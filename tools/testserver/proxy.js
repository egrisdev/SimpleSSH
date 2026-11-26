// Tiny multi-protocol proxy for exercising SimpleSSH's proxy support locally.
//   node proxy.js [port]          (default port 1080; 0 = OS-assigned)
//
// One listener; the protocol is sniffed from the first byte of each connection:
//   0x05       SOCKS5 (RFC 1928): CONNECT only; no-auth (0x00) or username/password
//              (0x02, RFC 1929). Credentials are optional, but if the client authenticates
//              with a non-empty user name or password they must be proxy / proxy.
//   0x04       SOCKS4 / SOCKS4a: CONNECT only; the user id is ignored.
//   otherwise  HTTP "CONNECT host:port HTTP/1.1". A Proxy-Authorization header is optional,
//              but if present it must be Basic proxy:proxy (otherwise 407).
// Targets may be IPv4 addresses or domain names (IPv6 also works for SOCKS5 and HTTP).
//
// Output (stdout):
//   proxy listening on <port>                 once, at startup
//   proxied <socks4|socks5|http> <host>:<port>  for each established tunnel
'use strict';

const net = require('net');

const PROXY_USER = 'proxy';
const PROXY_PASS = 'proxy';
const port = parseInt(process.argv[2] ?? '1080', 10);

/** Promise-based reader over a socket, used during the handshake only. */
class Reader {
  constructor(socket) {
    this.buf = Buffer.alloc(0);
    this.ended = false;
    this.waiter = null;
    this.onData = (d) => { this.buf = Buffer.concat([this.buf, d]); this.wake(); };
    this.onEnd = () => { this.ended = true; this.wake(); };
    socket.on('data', this.onData);
    socket.on('end', this.onEnd);
    socket.on('close', this.onEnd);
    this.socket = socket;
  }
  wake() { const w = this.waiter; this.waiter = null; if (w) w(); }
  async until(ready) {
    while (!ready()) {
      if (this.ended) throw new Error('connection closed during handshake');
      await new Promise((resolve) => { this.waiter = resolve; });
    }
  }
  async peek() { await this.until(() => this.buf.length > 0); return this.buf[0]; }
  async read(n) {
    await this.until(() => this.buf.length >= n);
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
  async byte() { return (await this.read(1))[0]; }
  /** Reads up to and including `delim`, returning the bytes before it. */
  async readUntil(delim, max = 64 * 1024) {
    await this.until(() => this.buf.includes(delim) || this.buf.length > max);
    const i = this.buf.indexOf(delim);
    if (i < 0) throw new Error('handshake too long');
    const out = this.buf.subarray(0, i);
    this.buf = this.buf.subarray(i + delim.length);
    return out;
  }
  /** Stops reading and returns any bytes received beyond the handshake. */
  detach() {
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('end', this.onEnd);
    this.socket.removeListener('close', this.onEnd);
    return this.buf;
  }
}

/** Connects to host:port; resolves with the socket or rejects on error. */
function connectTarget(host, targetPort) {
  return new Promise((resolve, reject) => {
    const target = net.connect(targetPort, host);
    target.once('connect', () => { target.removeListener('error', reject); resolve(target); });
    target.once('error', reject);
  });
}

/** Wires client and target together once the handshake reply has been sent. */
function tunnel(client, reader, target, protocol, host, targetPort) {
  console.log(`proxied ${protocol} ${host}:${targetPort}`);
  const leftover = reader.detach();
  if (leftover.length) target.write(leftover);
  target.on('error', () => client.destroy());
  client.on('error', () => target.destroy());
  client.on('close', () => target.destroy());
  target.on('close', () => client.destroy());
  client.pipe(target).pipe(client);
}

const ipv4 = (b) => Array.from(b).join('.');
function ipv6(b) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(i).toString(16));
  return parts.join(':');
}

async function handleSocks5(client, reader) {
  await reader.byte(); // version 5
  const methods = await reader.read(await reader.byte());
  // Prefer username/password when the client offers it, so offered credentials are checked
  // (empty credentials are accepted as "none", see below).
  const method = methods.includes(0x02) ? 0x02 : methods.includes(0x00) ? 0x00 : 0xff;
  client.write(Buffer.from([0x05, method]));
  if (method === 0xff) return client.end();

  if (method === 0x02) {
    await reader.byte(); // sub-negotiation version 1
    const user = (await reader.read(await reader.byte())).toString('utf8');
    const pass = (await reader.read(await reader.byte())).toString('utf8');
    // SSH.NET always offers both methods and sends empty credentials when it has none:
    // treat that as anonymous.
    const anonymous = user === '' && pass === '';
    const ok = anonymous || (user === PROXY_USER && pass === PROXY_PASS);
    client.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
    if (!ok) return client.end();
  }

  const [, cmd, , atyp] = await reader.read(4);
  const reply = (code) => Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  let host;
  if (atyp === 0x01) host = ipv4(await reader.read(4));
  else if (atyp === 0x03) host = (await reader.read(await reader.byte())).toString('utf8');
  else if (atyp === 0x04) host = ipv6(await reader.read(16));
  else return client.end(reply(0x08)); // address type not supported
  const targetPort = (await reader.read(2)).readUInt16BE(0);
  if (cmd !== 0x01) return client.end(reply(0x07)); // only CONNECT

  let target;
  try {
    target = await connectTarget(host, targetPort);
  } catch (err) {
    return client.end(reply(err.code === 'ECONNREFUSED' ? 0x05 : 0x04));
  }
  // Success reply with the bound address of our outgoing socket.
  const out = Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  const local = (target.localAddress || '').replace(/^::ffff:/, '');
  if (net.isIPv4(local)) Buffer.from(local.split('.').map(Number)).copy(out, 4);
  out.writeUInt16BE(target.localPort || 0, 8);
  client.write(out);
  tunnel(client, reader, target, 'socks5', host, targetPort);
}

async function handleSocks4(client, reader) {
  const head = await reader.read(8); // VN CD DSTPORT(2) DSTIP(4)
  const cmd = head[1];
  const targetPort = head.readUInt16BE(2);
  let host = ipv4(head.subarray(4, 8));
  await reader.readUntil(Buffer.from([0])); // user id (ignored)
  // SOCKS4a: IP 0.0.0.x (x != 0) means a domain name follows the user id.
  if (head[4] === 0 && head[5] === 0 && head[6] === 0 && head[7] !== 0) {
    host = (await reader.readUntil(Buffer.from([0]))).toString('utf8');
  }
  const reply = (code) => {
    const b = Buffer.alloc(8);
    b[1] = code;
    head.copy(b, 2, 2, 8);
    return b;
  };
  if (cmd !== 0x01) return client.end(reply(0x5b));
  let target;
  try {
    target = await connectTarget(host, targetPort);
  } catch {
    return client.end(reply(0x5b));
  }
  client.write(reply(0x5a));
  tunnel(client, reader, target, 'socks4', host, targetPort);
}

async function handleHttp(client, reader) {
  const head = (await reader.readUntil(Buffer.from('\r\n\r\n'))).toString('latin1');
  const [requestLine, ...headerLines] = head.split('\r\n');
  const respond = (status, extra = '') => client.end(`HTTP/1.1 ${status}\r\n${extra}Content-Length: 0\r\nConnection: close\r\n\r\n`);

  const m = /^CONNECT\s+(\S+)\s+HTTP\/1\.[01]$/i.exec(requestLine);
  if (!m) return respond('405 Method Not Allowed', 'Allow: CONNECT\r\n');
  const hp = /^\[([^\]]+)\]:(\d+)$/.exec(m[1]) || /^([^:]+):(\d+)$/.exec(m[1]);
  if (!hp) return respond('400 Bad Request');
  const host = hp[1];
  const targetPort = parseInt(hp[2], 10);

  const auth = headerLines.find((l) => /^proxy-authorization\s*:/i.test(l));
  if (auth) {
    const value = auth.slice(auth.indexOf(':') + 1).trim();
    const basic = /^Basic\s+(\S+)$/i.exec(value);
    const creds = basic ? Buffer.from(basic[1], 'base64').toString('utf8') : null;
    if (creds !== `${PROXY_USER}:${PROXY_PASS}`) {
      return respond('407 Proxy Authentication Required', 'Proxy-Authenticate: Basic realm="proxy"\r\n');
    }
  }

  let target;
  try {
    target = await connectTarget(host, targetPort);
  } catch {
    return respond('502 Bad Gateway');
  }
  client.write('HTTP/1.1 200 Connection established\r\n\r\n');
  tunnel(client, reader, target, 'http', host, targetPort);
}

const server = net.createServer((client) => {
  client.on('error', () => {});
  const reader = new Reader(client);
  (async () => {
    const first = await reader.peek();
    if (first === 0x05) await handleSocks5(client, reader);
    else if (first === 0x04) await handleSocks4(client, reader);
    else await handleHttp(client, reader);
  })().catch(() => client.destroy());
});

server.listen(port, '127.0.0.1', () => {
  console.log(`proxy listening on ${server.address().port}`);
});

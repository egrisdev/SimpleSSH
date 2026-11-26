// Minimal SSH server for exercising SimpleSSH locally.
//   node server.js [port] [sftpRoot]     (default port 2222)
//
// Users:
//   test / test   password or keyboard-interactive (one "Password: " prompt).
//   mfa  / test   password first; the server answers with *partial success* and
//                 then requires keyboard-interactive: "Verification code: " (echo) -> 123456.
//   otp           keyboard-interactive only, one round with two prompts:
//                 "Password: " (no echo) -> test, "Verification code: " (echo) -> 123456.
//   linux / test  a pretend Linux box for "Switch to key login": public keys from its own authorized_keys,
//                 password (until locked down). It understands SimpleSSH's install / lock-down / undo
//                 scripts (sudo password = test). User "test" can run `reset-linux-box [break-keys]`;
//                 break-keys makes the next lock-down also break key logins (to test the automatic undo).
//                 Also handles the "back to password login" scripts (remove key, turn passwords back on).
//
// Session features:
//   shell   fake interactive shell: help, size, color, echo <text>, whoami, flood, exit.
//   exec    echo <text>, whoami, hostname, fail (stderr "boom", exit 3),
//           scp -t / scp -f (classic SCP sink/source, files and -r directories),
//           anything else -> "<cmd>: command not found" on stderr, exit 127.
//   sftp    SFTP v3 subsystem serving a sandbox directory ("/" = sandbox root):
//           argv[3], else $SIMPLESSH_SFTP_ROOT, else tools/testserver/sftp-root
//           (created and seeded with readme.txt + configs/switch1.cfg when empty).
//           SCP uses the same sandbox.
//           Set SIMPLESSH_NO_SFTP=1 to refuse SFTP (imitates an SCP-only switch).
//
// Port forwarding:
//   direct-tcpip (local forwards) are connected to the requested host:port.
//   tcpip-forward / cancel-tcpip-forward (remote forwards) listen on 127.0.0.1.
//   A TCP echo service runs on 127.0.0.1 with an OS-assigned port for tests.
//
// Startup output (stdout), in this order:
//   echo service on <port>
//   sftp root <path>
//   SimpleSSH test server listening on 127.0.0.1:<port> (user: test / pass: test)
// The C# test fixture waits for the word "listening", so print everything else first.
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Server, utils } = require('ssh2');

const { OPEN_MODE, STATUS_CODE, flagsToString } = utils.sftp;

const port = parseInt(process.argv[2] || process.env.PORT || '2222', 10);
const keyPath = path.join(__dirname, 'host_rsa.pem');

if (!fs.existsSync(keyPath)) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  fs.writeFileSync(keyPath, privateKey);
}

const USER = 'test';
const PASS = 'test';
const OTP_CODE = '123456';

function safeEqual(a, b) {
  const ab = Buffer.from(a || '');
  const bb = Buffer.from(b || '');
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

// ---------------------------------------------------------------------------
// SFTP / SCP sandbox
// ---------------------------------------------------------------------------

const sftpRoot = path.resolve(
  process.argv[3] || process.env.SIMPLESSH_SFTP_ROOT || path.join(__dirname, 'sftp-root')
);

/** Creates the sandbox root and seeds it with a couple of files when it is empty. */
function prepareSftpRoot() {
  fs.mkdirSync(sftpRoot, { recursive: true });
  if (fs.readdirSync(sftpRoot).length === 0) {
    fs.writeFileSync(path.join(sftpRoot, 'readme.txt'), 'hello from sftp\n');
    fs.mkdirSync(path.join(sftpRoot, 'configs'));
    fs.writeFileSync(path.join(sftpRoot, 'configs', 'switch1.cfg'), 'hostname switch1\n');
  }
}

/**
 * Normalises a remote POSIX path to an absolute path inside the sandbox ("/" = root).
 * Relative paths (and "~") are relative to "/". Returns null if the path would escape
 * the root or contains components that are unsafe on Windows (backslashes, drive colons).
 */
function normalizeRemote(remotePath) {
  let p = String(remotePath || '');
  if (p === '~' || p.startsWith('~/')) p = p.slice(1);
  const parts = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (parts.length === 0) return null;
      parts.pop();
      continue;
    }
    if (seg.includes('\\') || seg.includes(':')) return null;
    parts.push(seg);
  }
  return '/' + parts.join('/');
}

/** Maps a remote path to a local filesystem path inside the sandbox, or null if refused. */
function toLocal(remotePath) {
  const norm = normalizeRemote(remotePath);
  return norm === null ? null : path.join(sftpRoot, ...norm.split('/').filter(Boolean));
}

const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;

/** SFTP attributes for an fs.Stats (synthesised permissions; Windows modes are meaningless). */
function attrsOf(st) {
  const dir = st.isDirectory();
  const writable = (st.mode & 0o200) !== 0;
  return {
    mode: dir ? S_IFDIR | 0o755 : S_IFREG | (writable ? 0o644 : 0o444),
    uid: 0,
    gid: 0,
    size: dir ? 0 : st.size,
    atime: Math.floor(st.atimeMs / 1000),
    mtime: Math.floor(st.mtimeMs / 1000),
  };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `ls -l` style line, formatted like OpenSSH's sftp-server. */
function longnameOf(name, attrs) {
  const dir = (attrs.mode & S_IFDIR) === S_IFDIR;
  let perms = dir ? 'd' : '-';
  for (let shift = 6; shift >= 0; shift -= 3) {
    const bits = (attrs.mode >> shift) & 7;
    perms += (bits & 4 ? 'r' : '-') + (bits & 2 ? 'w' : '-') + (bits & 1 ? 'x' : '-');
  }
  const d = new Date(attrs.mtime * 1000);
  const recent = Math.abs(Date.now() - d.getTime()) < 180 * 24 * 3600 * 1000;
  const when = recent
    ? `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
    : ` ${d.getFullYear()}`;
  return `${perms} ${String(dir ? 2 : 1).padStart(3)} ${'root'.padEnd(8)} ${'root'.padEnd(8)} `
    + `${String(attrs.size).padStart(8)} ${MONTHS[d.getMonth()]} ${String(d.getDate()).padStart(2)} ${when} ${name}`;
}

/** Translates SFTP open flags (OPEN_MODE bits) to something fs.openSync understands. */
function openFlags(pflags) {
  const str = flagsToString(pflags); // e.g. 'r', 'w', 'a+', or null for unusual combinations
  if (str) return str;
  const c = fs.constants;
  const read = (pflags & OPEN_MODE.READ) !== 0;
  const write = (pflags & OPEN_MODE.WRITE) !== 0;
  let flags = read && write ? c.O_RDWR : write ? c.O_WRONLY : c.O_RDONLY;
  if (pflags & OPEN_MODE.CREAT) flags |= c.O_CREAT;
  if (pflags & OPEN_MODE.TRUNC) flags |= c.O_TRUNC;
  if (pflags & OPEN_MODE.APPEND) flags |= c.O_APPEND;
  if (pflags & OPEN_MODE.EXCL) flags |= c.O_EXCL;
  return flags;
}

const MAX_READ = 256 * 1024;
const READDIR_BATCH = 64;

/** Serves one SFTP session. Uses synchronous fs calls: simple, and fine for a test server. */
function serveSftp(sftp) {
  const handles = new Map(); // hex(handle) -> { kind: 'file', fd, append } | { kind: 'dir', local, entries }
  let nextHandle = 0;

  const newHandle = (obj) => {
    const h = Buffer.alloc(4);
    h.writeUInt32BE(nextHandle++);
    handles.set(h.toString('hex'), obj);
    return h;
  };
  const getHandle = (h, kind) => {
    const obj = handles.get(Buffer.from(h).toString('hex'));
    return obj && obj.kind === kind ? obj : null;
  };
  const ok = (id) => sftp.status(id, STATUS_CODE.OK);
  const denied = (id) => sftp.status(id, STATUS_CODE.PERMISSION_DENIED, 'Path outside of sandbox');
  const badHandle = (id) => sftp.status(id, STATUS_CODE.FAILURE, 'Invalid handle');
  const fail = (id, err) => {
    const missing = err && (err.code === 'ENOENT' || err.code === 'ENOTDIR');
    sftp.status(id, missing ? STATUS_CODE.NO_SUCH_FILE : STATUS_CODE.FAILURE,
      missing ? 'No such file' : (err && err.code) || String(err));
  };

  /** Wraps a path-based request: resolves the path (refusing escapes) and reports thrown errors. */
  const withPath = (fn, { notRoot = false } = {}) => (id, remotePath, ...rest) => {
    const norm = normalizeRemote(remotePath);
    if (norm === null || (notRoot && norm === '/')) return denied(id);
    try {
      fn(id, toLocal(norm), ...rest);
    } catch (err) {
      fail(id, err);
    }
  };

  sftp.on('REALPATH', (id, remotePath) => {
    const norm = normalizeRemote(remotePath); // "." and "" -> "/"
    if (norm === null) return denied(id);
    sftp.name(id, [{ filename: norm, longname: norm, attrs: {} }]);
  });

  sftp.on('STAT', withPath((id, local) => sftp.attrs(id, attrsOf(fs.statSync(local)))));
  sftp.on('LSTAT', withPath((id, local) => sftp.attrs(id, attrsOf(fs.lstatSync(local)))));

  sftp.on('FSTAT', (id, h) => {
    const f = getHandle(h, 'file');
    if (!f) return badHandle(id);
    try { sftp.attrs(id, attrsOf(fs.fstatSync(f.fd))); } catch (err) { fail(id, err); }
  });

  sftp.on('OPEN', withPath((id, local, pflags) => {
    if (fs.existsSync(local) && fs.statSync(local).isDirectory()) {
      return sftp.status(id, STATUS_CODE.FAILURE, 'Is a directory');
    }
    const fd = fs.openSync(local, openFlags(pflags), 0o644);
    sftp.handle(id, newHandle({ kind: 'file', fd, append: (pflags & OPEN_MODE.APPEND) !== 0 }));
  }));

  sftp.on('READ', (id, h, offset, len) => {
    const f = getHandle(h, 'file');
    if (!f) return badHandle(id);
    try {
      const buf = Buffer.alloc(Math.min(len, MAX_READ));
      const n = fs.readSync(f.fd, buf, 0, buf.length, Number(offset));
      if (n === 0) return sftp.status(id, STATUS_CODE.EOF);
      sftp.data(id, buf.subarray(0, n));
    } catch (err) { fail(id, err); }
  });

  sftp.on('WRITE', (id, h, offset, data) => {
    const f = getHandle(h, 'file');
    if (!f) return badHandle(id);
    try {
      // APPEND handles ignore the offset and always write at the end of the file.
      let pos = f.append ? null : Number(offset);
      for (let done = 0; done < data.length;) {
        const n = fs.writeSync(f.fd, data, done, data.length - done, pos);
        done += n;
        if (pos !== null) pos += n;
      }
      ok(id);
    } catch (err) { fail(id, err); }
  });

  sftp.on('CLOSE', (id, h) => {
    const key = Buffer.from(h).toString('hex');
    const obj = handles.get(key);
    if (!obj) return badHandle(id);
    handles.delete(key);
    try {
      if (obj.kind === 'file') fs.closeSync(obj.fd);
      ok(id);
    } catch (err) { fail(id, err); }
  });

  sftp.on('OPENDIR', withPath((id, local) => {
    if (!fs.statSync(local).isDirectory()) return sftp.status(id, STATUS_CODE.FAILURE, 'Not a directory');
    sftp.handle(id, newHandle({ kind: 'dir', local, entries: null }));
  }));

  sftp.on('READDIR', (id, h) => {
    const d = getHandle(h, 'dir');
    if (!d) return badHandle(id);
    try {
      if (d.entries === null) {
        // Like OpenSSH, include "." and ".." (".." of the root is the root itself).
        const names = ['.', '..', ...fs.readdirSync(d.local)];
        d.entries = [];
        for (const name of names) {
          const local = name === '.' ? d.local
            : name === '..' ? (d.local === sftpRoot ? sftpRoot : path.dirname(d.local))
              : path.join(d.local, name);
          try {
            const attrs = attrsOf(fs.lstatSync(local));
            d.entries.push({ filename: name, longname: longnameOf(name, attrs), attrs });
          } catch { /* vanished or unreadable: skip */ }
        }
      }
      if (d.entries.length === 0) return sftp.status(id, STATUS_CODE.EOF);
      sftp.name(id, d.entries.splice(0, READDIR_BATCH));
    } catch (err) { fail(id, err); }
  });

  sftp.on('REMOVE', withPath((id, local) => {
    if (fs.statSync(local).isDirectory()) return sftp.status(id, STATUS_CODE.FAILURE, 'Is a directory');
    fs.unlinkSync(local);
    ok(id);
  }, { notRoot: true }));

  sftp.on('RMDIR', withPath((id, local) => { fs.rmdirSync(local); ok(id); }, { notRoot: true }));

  sftp.on('MKDIR', withPath((id, local) => { fs.mkdirSync(local); ok(id); }));

  sftp.on('RENAME', withPath((id, local, newRemote) => {
    const newNorm = normalizeRemote(newRemote);
    if (newNorm === null || newNorm === '/') return denied(id);
    const target = toLocal(newNorm);
    fs.statSync(local); // NO_SUCH_FILE if the source is missing
    // SFTP v3 rename must not overwrite (fs.renameSync would on Windows).
    if (fs.existsSync(target)) return sftp.status(id, STATUS_CODE.FAILURE, 'Target exists');
    fs.renameSync(local, target);
    ok(id);
  }, { notRoot: true }));

  // SETSTAT/FSETSTAT: only timestamps are applied (best effort); everything else is accepted as a no-op.
  sftp.on('SETSTAT', withPath((id, local, attrs) => {
    const st = fs.statSync(local);
    if (attrs && attrs.mtime !== undefined) {
      try { fs.utimesSync(local, attrs.atime ?? st.atimeMs / 1000, attrs.mtime); } catch { /* ignore */ }
    }
    ok(id);
  }));

  sftp.on('FSETSTAT', (id, h, attrs) => {
    const f = getHandle(h, 'file');
    if (!f) return badHandle(id);
    if (attrs && attrs.mtime !== undefined) {
      try { fs.futimesSync(f.fd, attrs.atime ?? attrs.mtime, attrs.mtime); } catch { /* ignore */ }
    }
    ok(id);
  });

  // Like OpenSSH's sftp-server, exit with status 0 and close the channel once the client sends EOF.
  // ssh2 does neither by itself: without the close OpenSSH's scp/sftp hang on exit, and without
  // the exit status scp (in its default SFTP mode) reports failure.
  sftp.on('end', () => {
    try {
      if (sftp.outgoing.state === 'open') sftp._protocol.exitStatus(sftp.outgoing.id, 0); // no public API
    } catch { /* ignore */ }
    sftp.end();
  });

  // Release file descriptors when the session goes away.
  sftp.on('close', () => {
    for (const obj of handles.values()) {
      if (obj.kind === 'file') { try { fs.closeSync(obj.fd); } catch { /* ignore */ } }
    }
    handles.clear();
  });
}

// ---------------------------------------------------------------------------
// Exec channel (including SCP)
// ---------------------------------------------------------------------------

/** Splits a command line like a POSIX shell: '...' literal, "..." with \" escapes, \x escapes. */
function shellSplit(cmd) {
  const words = [];
  let cur = '';
  let inWord = false;
  let quote = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote === "'") {
      if (c === "'") quote = null; else cur += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === '\\' && i + 1 < cmd.length && '"\\$`'.includes(cmd[i + 1])) cur += cmd[++i];
      else cur += c;
    } else if (c === "'" || c === '"') {
      quote = c; inWord = true;
    } else if (c === '\\' && i + 1 < cmd.length) {
      cur += cmd[++i]; inWord = true;
    } else if (/\s/.test(c)) {
      if (inWord) { words.push(cur); cur = ''; inWord = false; }
    } else {
      cur += c; inWord = true;
    }
  }
  if (inWord) words.push(cur);
  return words;
}

/** Sends the exit status and closes the channel (the client may already have closed it). */
function finish(stream, code) {
  try { stream.exit(code); stream.end(); } catch { /* channel already gone */ }
}

function runExec(stream, command, username) {
  if (username === 'linux' && command.startsWith("sh -c 'f=$(mktemp)")) return runLinuxScript(stream, command);
  if (command.startsWith('reset-linux-box')) {
    linuxBox.authorizedKeys.clear();
    linuxBox.passwordsOff = false;
    linuxBox.breakKeysOnLock = command.includes('break-keys');
    linuxBox.passwordsOff = command.includes('passwords-off'); // already locked down by someone else
    stream.write('reset\n');
    return finish(stream, 0);
  }
  // "Add a key by hand": the one-line command SimpleSSH shows, pasted into another session (any user here).
  const manual = /^k='([^']+)'; f="\$HOME\/\.ssh\/authorized_keys";/.exec(command);
  if (manual) {
    linuxBox.authorizedKeys.add(manual[1]);
    stream.write('Key added. Now test it in SimpleSSH.\n');
    return finish(stream, 0);
  }
  const argv = shellSplit(command);
  const name = argv[0] || '';
  switch (name) {
    case 'echo': stream.write(argv.slice(1).join(' ') + '\n'); return finish(stream, 0);
    case 'whoami': stream.write(username + '\n'); return finish(stream, 0);
    case 'hostname': stream.write('testserver\n'); return finish(stream, 0);
    case 'fail': stream.stderr.write('boom\n'); return finish(stream, 3);
    case 'scp':
      return runScp(stream, argv.slice(1)).then(
        (code) => finish(stream, code),
        (err) => { try { stream.stderr.write(`scp: ${err.message}\n`); } catch { /* ignore */ } finish(stream, 1); });
    default:
      stream.stderr.write(`${name}: command not found\n`);
      return finish(stream, 127);
  }
}

/** Promise-based reader over a channel's incoming data, for the byte-oriented SCP protocol. */
class ByteReader {
  constructor(stream) {
    this.buf = Buffer.alloc(0);
    this.ended = false;
    this.waiter = null;
    stream.on('data', (d) => { this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d; this.wake(); });
    const onEnd = () => { this.ended = true; this.wake(); };
    stream.on('end', onEnd);
    stream.on('close', onEnd);
  }
  wake() { const w = this.waiter; this.waiter = null; if (w) w(); }
  /** Resolves true once `ready()` holds, false if the stream ended first. */
  async until(ready) {
    while (!ready()) {
      if (this.ended) return false;
      await new Promise((resolve) => { this.waiter = resolve; });
    }
    return true;
  }
  take(n) { const out = this.buf.subarray(0, n); this.buf = this.buf.subarray(n); return out; }
  async readByte() { return (await this.until(() => this.buf.length > 0)) ? this.take(1)[0] : null; }
  async readLine() {
    if (!(await this.until(() => this.buf.includes(0x0a)))) return null;
    return this.take(this.buf.indexOf(0x0a) + 1).subarray(0, -1).toString('utf8');
  }
  /** Returns 1..max bytes, or null at end of stream. */
  async readChunk(max) {
    return (await this.until(() => this.buf.length > 0)) ? this.take(Math.min(max, this.buf.length)) : null;
  }
}

/** A file or directory name from an SCP C/D line must be a single, harmless path component. */
function safeScpName(name) {
  return name && name !== '.' && name !== '..' && !/[\\/:]/.test(name) ? name : null;
}

/**
 * `scp [-r] [-d] [-p] [-v] -t|-f <path>` - the remote half of the classic SCP protocol.
 * Resolves with the exit code.
 */
async function runScp(stream, args) {
  const opts = { t: false, f: false, r: false, d: false, p: false };
  let target = null;
  for (const arg of args) {
    if (arg.startsWith('-') && arg.length > 1 && target === null) {
      for (const ch of arg.slice(1)) if (ch in opts) opts[ch] = true;
    } else {
      target = arg;
    }
  }
  const reader = new ByteReader(stream);
  const local = target === null ? null : toLocal(target);
  if (opts.t === opts.f || target === null) {
    stream.write('\x02scp: usage: scp [-r] [-d] [-p] -t|-f <path>\n');
    return 1;
  }
  if (local === null) {
    stream.write(`\x02scp: ${target}: Permission denied\n`);
    return 1;
  }
  return opts.t ? scpSink(stream, reader, local, opts) : scpSource(stream, reader, target, local, opts);
}

const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

/** Receives files from the client ("scp -t"). */
async function scpSink(stream, reader, target, opts) {
  const ack = () => stream.write(Buffer.from([0]));
  let exitCode = 0;
  const warn = (msg) => { stream.write(`\x01scp: ${msg}\n`); exitCode = 1; };
  const dirs = []; // directories entered via D lines: { dest, times }
  let times = null; // pending T line (applied to the next C/D entry)
  const applyTimes = (p, t) => { if (t) { try { fs.utimesSync(p, t.atime, t.mtime); } catch { /* ignore */ } } };

  // Where does an incoming entry called `name` go? At top level: inside the target if it is an
  // existing directory, otherwise the target path itself. Inside D directories: always a child.
  const destFor = (name) => (dirs.length
    ? path.join(dirs[dirs.length - 1].dest, name)
    : (isDir(target) ? path.join(target, name) : target));

  ack(); // ready
  for (;;) {
    const line = await reader.readLine();
    if (line === null) break; // client closed: transfer complete
    const type = line[0];
    const rest = line.slice(1);
    if (type === 'T') {
      const m = /^(\d+) \d+ (\d+) \d+$/.exec(rest);
      if (!m) { warn('protocol error: bad T line'); break; }
      times = { mtime: Number(m[1]), atime: Number(m[2]) };
      ack();
    } else if (type === 'C') {
      const m = /^([0-7]{4}) (\d+) (.+)$/.exec(rest);
      if (!m) { warn('protocol error: bad C line'); break; }
      const size = Number(m[2]);
      const name = safeScpName(m[3]);
      let fd = null;
      let error = name ? null : `${m[3]}: invalid file name`;
      const dest = name ? destFor(name) : null;
      if (!error) {
        try { fd = fs.openSync(dest, 'w'); } catch (err) { error = `${m[3]}: ${err.code || err.message}`; }
      }
      ack(); // go ahead and send the content
      for (let left = size; left > 0;) {
        const chunk = await reader.readChunk(left);
        if (chunk === null) { if (fd !== null) fs.closeSync(fd); return 1; }
        if (fd !== null) fs.writeSync(fd, chunk);
        left -= chunk.length;
      }
      if (fd !== null) fs.closeSync(fd);
      await reader.readByte(); // trailing \0 after the content
      const fileTimes = times;
      times = null;
      if (error) { warn(error); continue; } // the error message replaces the final ack
      applyTimes(dest, fileTimes);
      ack();
    } else if (type === 'D') {
      const m = /^([0-7]{4}) \d+ (.+)$/.exec(rest);
      if (!m) { warn('protocol error: bad D line'); break; }
      if (!opts.r) { warn('received directory without -r'); break; }
      const name = safeScpName(m[2]);
      if (!name) { warn(`${m[2]}: invalid directory name`); break; }
      const dest = destFor(name);
      try { fs.mkdirSync(dest, { recursive: true }); } catch (err) { warn(`${m[2]}: ${err.code}`); break; }
      dirs.push({ dest, times }); // directory times are applied at E, after its contents are written
      times = null;
      ack();
    } else if (type === 'E') {
      const dir = dirs.pop();
      if (dir) applyTimes(dir.dest, dir.times);
      ack();
    } else if (type === '\x01' || type === '\x02') {
      exitCode = 1; // the client reported an error
      if (type === '\x02') break;
    } else {
      warn('protocol error: unexpected message');
      break;
    }
  }
  return exitCode;
}

/** Sends a file (or, with -r, a directory tree) to the client ("scp -f"). */
async function scpSource(stream, reader, remotePath, local, opts) {
  const write = async (data) => {
    if (!stream.write(data)) await new Promise((resolve) => stream.once('drain', resolve));
  };
  // Waits for the client's response: \0 = ok, \1/\2 + message = error.
  const expectAck = async () => {
    const b = await reader.readByte();
    if (b === 0) return true;
    if (b === 1 || b === 2) await reader.readLine();
    return false;
  };

  if (!(await expectAck())) return 1; // the sink starts by sending \0
  let st;
  try { st = fs.statSync(local); } catch {
    await write(`\x01scp: ${remotePath}: No such file or directory\n`);
    return 1;
  }
  if (st.isDirectory() && !opts.r) {
    await write(`\x01scp: ${remotePath}: not a regular file\n`);
    return 1;
  }

  const sendEntry = async (p, name) => {
    const s = fs.statSync(p);
    if (opts.p) {
      await write(`T${Math.floor(s.mtimeMs / 1000)} 0 ${Math.floor(s.atimeMs / 1000)} 0\n`);
      if (!(await expectAck())) return false;
    }
    if (s.isDirectory()) {
      await write(`D0755 0 ${name}\n`);
      if (!(await expectAck())) return false;
      for (const child of fs.readdirSync(p)) {
        if (!(await sendEntry(path.join(p, child), child))) return false;
      }
      await write('E\n');
      return expectAck();
    }
    await write(`C${(s.mode & 0o200) ? '0644' : '0444'} ${s.size} ${name}\n`);
    if (!(await expectAck())) return false;
    const fd = fs.openSync(p, 'r');
    try {
      const buf = Buffer.alloc(64 * 1024);
      for (let n; (n = fs.readSync(fd, buf, 0, buf.length, null)) > 0;) await write(Buffer.from(buf.subarray(0, n)));
    } finally {
      fs.closeSync(fd);
    }
    await write(Buffer.from([0]));
    return expectAck();
  };

  const name = local === sftpRoot ? 'sftp-root' : path.basename(local);
  return (await sendEntry(local, name)) ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/** User "test": password or keyboard-interactive (unchanged behaviour). */
// ---------------------------------------------------------------------------
// Pretend Linux box (user "linux")
// ---------------------------------------------------------------------------

const linuxBox = { authorizedKeys: new Set(), passwordsOff: false, breakKeysOnLock: false };

function linuxMethods() {
  return linuxBox.passwordsOff ? ['publickey'] : ['publickey', 'password', 'keyboard-interactive'];
}

function authLinux(ctx) {
  if (ctx.method === 'publickey') {
    for (const line of linuxBox.authorizedKeys) {
      const key = utils.parseKey(line);
      if (key instanceof Error) continue;
      if (ctx.key.algo !== key.type || !ctx.key.data.equals(key.getPublicSSH())) continue;
      if (!ctx.signature) return ctx.accept(); // "would this key do?"
      return key.verify(ctx.blob, ctx.signature, ctx.hashAlgo) === true ? ctx.accept() : ctx.reject(linuxMethods());
    }
    return ctx.reject(linuxMethods());
  }
  if (!linuxBox.passwordsOff) {
    if (ctx.method === 'password') return safeEqual(ctx.password, PASS) ? ctx.accept() : ctx.reject(linuxMethods());
    if (ctx.method === 'keyboard-interactive') {
      return ctx.prompt([{ prompt: 'Password: ', echo: false }], 'SimpleSSH test', '', (answers) => {
        safeEqual(answers[0], PASS) ? ctx.accept() : ctx.reject(linuxMethods());
      });
    }
  }
  ctx.reject(linuxMethods());
}

/** Runs one of SimpleSSH's base64-wrapped sh scripts (see KeyLoginSetup.ShellCommand) against the pretend box. */
function runLinuxScript(stream, command) {
  const outer = /echo ([A-Za-z0-9+\/=]+) \| base64 -d/.exec(command);
  if (!outer) { stream.stderr.write('sh: unexpected command\n'); return finish(stream, 2); }
  const script = Buffer.from(outer[1], 'base64').toString('utf8');

  if (script.includes('SIMPLESSH-KEY-REMOVED')) {
    const b = /b='([^']*)'/.exec(script);
    for (const line of [...linuxBox.authorizedKeys]) if (b && line.includes(b[1])) linuxBox.authorizedKeys.delete(line);
    stream.write('SIMPLESSH-KEY-REMOVED\n');
    return finish(stream, 0);
  }
  // "Turn passwords back on" checks for the lock-down file before asking sudo.
  if (script.includes('SIMPLESSH-NOT-LOCKED') && !linuxBox.passwordsOff) {
    stream.write('SIMPLESSH-NOT-LOCKED\n');
    return finish(stream, 0);
  }

  if (script.includes('SIMPLESSH-KEY-INSTALLED')) {
    const k = /k='([^']*)'/.exec(script);
    if (!k) { stream.stderr.write('no key\n'); return finish(stream, 1); }
    linuxBox.authorizedKeys.add(k[1]);
    stream.write('SIMPLESSH-KEY-INSTALLED\n');
    return finish(stream, 0);
  }

  const innerMatch = /s=\$\(echo ([A-Za-z0-9+\/=]+) \| base64 -d\)/.exec(script);
  if (!innerMatch) { stream.stderr.write('sh: unknown script\n'); return finish(stream, 2); }
  const inner = Buffer.from(innerMatch[1], 'base64').toString('utf8');

  // sudo -S: the password is the first line on stdin.
  let input = '';
  let done = false;
  const decide = () => {
    if (done) return;
    done = true;
    const password = input.split('\n')[0];
    if (!password) { stream.stderr.write('sudo: no password was provided\n'); return finish(stream, 1); }
    if (password !== PASS) { stream.stderr.write('Sorry, try again.\nsudo: 1 incorrect password attempt\n'); return finish(stream, 1); }
    if (inner.includes('SIMPLESSH-LOCKED')) {
      linuxBox.passwordsOff = true;
      if (linuxBox.breakKeysOnLock) linuxBox.authorizedKeys.clear();
      stream.write('SIMPLESSH-LOCKED\n');
    } else if (inner.includes('SIMPLESSH-UNLOCKED')) {
      linuxBox.passwordsOff = false;
      stream.write('SIMPLESSH-UNLOCKED\n');
    }
    finish(stream, 0);
  };
  stream.on('data', (d) => { input += d.toString('utf8'); if (input.includes('\n')) decide(); });
  stream.on('end', decide);
}

function authTest(ctx) {
  if (ctx.method === 'password') {
    return safeEqual(ctx.username, USER) && safeEqual(ctx.password, PASS) ? ctx.accept() : ctx.reject();
  }
  if (ctx.method === 'keyboard-interactive') {
    return ctx.prompt([{ prompt: 'Password: ', echo: false }], 'SimpleSSH test', '', (answers) => {
      safeEqual(ctx.username, USER) && safeEqual(answers[0], PASS) ? ctx.accept() : ctx.reject();
    });
  }
  ctx.reject(['password', 'keyboard-interactive']);
}

/**
 * User "mfa": password, then (partial success) a keyboard-interactive verification code.
 * Before the password step only "password" is advertised, so clients such as SSH.NET don't
 * burn their keyboard-interactive attempt first.
 */
function authMfa(ctx, state) {
  if (!state.passwordOk) {
    if (ctx.method === 'password' && safeEqual(ctx.password, PASS)) {
      state.passwordOk = true;
      return ctx.reject(['keyboard-interactive'], true); // partial success
    }
    return ctx.reject(['password']);
  }
  if (ctx.method === 'keyboard-interactive') {
    return ctx.prompt([{ prompt: 'Verification code: ', echo: true }], 'SimpleSSH test', '', (answers) => {
      safeEqual(answers[0], OTP_CODE) ? ctx.accept() : ctx.reject(['keyboard-interactive']);
    });
  }
  ctx.reject(['keyboard-interactive']);
}

/** User "otp": keyboard-interactive only, password and code asked in one round. */
function authOtp(ctx) {
  if (ctx.method !== 'keyboard-interactive') return ctx.reject(['keyboard-interactive']);
  ctx.prompt([
    { prompt: 'Password: ', echo: false },
    { prompt: 'Verification code: ', echo: true },
  ], 'SimpleSSH test', '', (answers) => {
    safeEqual(answers[0], PASS) && safeEqual(answers[1], OTP_CODE) ? ctx.accept() : ctx.reject(['keyboard-interactive']);
  });
}

// ---------------------------------------------------------------------------
// Port forwarding helpers
// ---------------------------------------------------------------------------

/** Pipes an SSH channel and a TCP socket into each other, tearing both down on errors. */
function pipeBoth(channel, socket) {
  socket.on('error', () => channel.destroy());
  channel.on('error', () => socket.destroy());
  channel.on('close', () => socket.destroy());
  channel.pipe(socket).pipe(channel);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new Server({ hostKeys: [fs.readFileSync(keyPath)] }, (client) => {
  let username = '';
  const mfaState = { passwordOk: false };
  client.on('authentication', (ctx) => {
    username = ctx.username;
    if (ctx.username === 'mfa') return authMfa(ctx, mfaState);
    if (ctx.username === 'otp') return authOtp(ctx);
    if (ctx.username === 'linux') return authLinux(ctx);
    authTest(ctx);
  });

  // Remote (reverse) forwards owned by this connection: "bindAddr:boundPort" -> net.Server.
  const remoteForwards = new Map();
  client.on('close', () => {
    for (const listener of remoteForwards.values()) listener.close();
    remoteForwards.clear();
  });

  client.on('ready', () => {
    // direct-tcpip: the client asks us to connect somewhere on its behalf (local forwarding).
    client.on('tcpip', (accept, reject, info) => {
      const socket = net.connect(info.destPort, info.destIP);
      const onConnectError = () => reject();
      socket.once('error', onConnectError);
      socket.once('connect', () => {
        socket.removeListener('error', onConnectError);
        const channel = accept();
        if (!channel) return socket.destroy();
        pipeBoth(channel, socket);
      });
    });

    // tcpip-forward / cancel-tcpip-forward: remote forwarding.
    client.on('request', (accept, reject, name, info) => {
      accept = accept || (() => {});
      reject = reject || (() => {});
      if (name === 'tcpip-forward') {
        let boundPort = info.bindPort;
        const listener = net.createServer((socket) => {
          socket.on('error', () => {});
          client.forwardOut(info.bindAddr, boundPort, socket.remoteAddress, socket.remotePort, (err, channel) => {
            if (err) return socket.destroy();
            pipeBoth(channel, socket);
          });
        });
        listener.once('error', () => reject());
        listener.listen(info.bindPort, '127.0.0.1', () => {
          boundPort = listener.address().port;
          remoteForwards.set(`${info.bindAddr}:${boundPort}`, listener);
          accept(boundPort); // ssh2 only sends the port back when 0 was requested
        });
      } else if (name === 'cancel-tcpip-forward') {
        const key = `${info.bindAddr}:${info.bindPort}`;
        const listener = remoteForwards.get(key);
        if (!listener) return reject();
        remoteForwards.delete(key);
        listener.close();
        accept();
      } else {
        reject();
      }
    });

    client.on('session', (accept) => {
      const session = accept();
      const term = { cols: 80, rows: 24, type: 'unknown' };

      session.on('pty', (acceptPty, _reject, info) => {
        term.cols = info.cols; term.rows = info.rows; term.type = info.term;
        acceptPty && acceptPty();
      });
      session.on('window-change', (acceptWc, _reject, info) => {
        term.cols = info.cols; term.rows = info.rows;
        acceptWc && acceptWc();
      });
      session.on('exec', (acceptExec, _reject, info) => {
        runExec(acceptExec(), info.command, username);
      });
      session.on('sftp', (acceptSftp, rejectSftp) => {
        // SIMPLESSH_NO_SFTP=1 imitates a network device that only speaks SCP.
        if (process.env.SIMPLESSH_NO_SFTP === '1') return rejectSftp();
        serveSftp(acceptSftp());
      });
      session.on('shell', (acceptShell) => {
        const stream = acceptShell();
        let line = '';
        const prompt = () => stream.write(`\x1b[32m${username}@testserver\x1b[0m:\x1b[34m~\x1b[0m$ `);
        stream.write(`Welcome to the SimpleSSH test server.\r\nTerminal: ${term.type} ${term.cols}x${term.rows}\r\nType 'help' for commands.\r\n`);
        prompt();
        stream.on('data', (data) => {
          for (const ch of data.toString('utf8')) {
            if (ch === '\r' || ch === '\n') {
              stream.write('\r\n');
              const cmd = line.trim();
              line = '';
              if (!run(cmd)) return;
              prompt();
            } else if (ch === '\x7f' || ch === '\b') {
              if (line.length > 0) { line = line.slice(0, -1); stream.write('\b \b'); }
            } else if (ch === '\x03') {
              stream.write('^C\r\n'); line = ''; prompt();
            } else if (ch === '\x04') {
              stream.write('logout\r\n'); stream.exit(0); stream.end(); return;
            } else if (ch >= ' ' || ch.length > 1 || ch.charCodeAt(0) > 127) {
              line += ch; stream.write(ch);
            }
          }
        });

        function run(cmd) {
          const [name, ...rest] = cmd.split(/\s+/);
          switch (name) {
            case '': break;
            case 'help': stream.write('Commands: help, size, color, echo <text>, whoami, flood, exit\r\n'); break;
            case 'size': stream.write(`${term.cols}x${term.rows}\r\n`); break;
            case 'whoami': stream.write(`${username}\r\n`); break;
            case 'echo': stream.write(rest.join(' ') + '\r\n'); break;
            case 'color':
              for (let i = 0; i < 8; i++) stream.write(`\x1b[3${i}m color${i} \x1b[0m`);
              stream.write('\r\nUnicode: \u2713 \u00e9\u00e8 \u65e5\u672c\u8a9e \u{1F600}\r\n');
              break;
            case 'flood':
              for (let i = 1; i <= 2000; i++) stream.write(`line ${i} ${'x'.repeat(60)}\r\n`);
              break;
            case 'exit': stream.write('logout\r\n'); stream.exit(0); stream.end(); return false;
            default: stream.write(`${name}: command not found\r\n`);
          }
          return true;
        }
      });
    });
  });
  client.on('error', () => {});
});

// TCP echo service used as a forwarding target by the tests.
const echoServer = net.createServer((socket) => {
  socket.on('error', () => {});
  socket.pipe(socket);
});

prepareSftpRoot();
echoServer.listen(0, '127.0.0.1', () => {
  console.log(`echo service on ${echoServer.address().port}`);
  console.log(`sftp root ${sftpRoot}`);
  server.listen(port, '127.0.0.1', () => {
    console.log(`SimpleSSH test server listening on 127.0.0.1:${server.address().port} (user: ${USER} / pass: ${PASS})`);
  });
});

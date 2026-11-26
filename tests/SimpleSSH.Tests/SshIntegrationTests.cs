using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Tests;

/// <summary>
/// Starts tools/testserver/server.js (Node + ssh2) on a free port for the integration tests.
/// Requires: node on PATH and `npm install` run in tools/testserver.
/// </summary>
public sealed class TestSshServer : IDisposable
{
    private readonly Process _process;

    public TestSshServer() : this(noSftp: false) { }

    /// <param name="noSftp">Refuse the SFTP subsystem, like an SCP-only switch.</param>
    internal TestSshServer(bool noSftp)
    {
        var root = FindRepoRoot();
        var script = Path.Combine(root, "tools", "testserver", "server.js");
        if (!Directory.Exists(Path.Combine(root, "tools", "testserver", "node_modules", "ssh2")))
            throw new InvalidOperationException("Run `npm install` in tools/testserver before running the integration tests.");

        Port = GetFreePort();
        SftpRoot = Path.Combine(Path.GetTempPath(), "simplessh-sftp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(SftpRoot);
        _process = Process.Start(new ProcessStartInfo("node", $"\"{script}\" {Port} \"{SftpRoot}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Environment = { ["SIMPLESSH_NO_SFTP"] = noSftp ? "1" : "0" },
        }) ?? throw new InvalidOperationException("Could not start node.");

        var ready = new TaskCompletionSource();
        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            var m = System.Text.RegularExpressions.Regex.Match(e.Data, @"echo service on (\d+)");
            if (m.Success) EchoPort = int.Parse(m.Groups[1].Value);
            if (e.Data.Contains("listening")) ready.TrySetResult();
        };
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
        if (!ready.Task.Wait(TimeSpan.FromSeconds(20)))
            throw new TimeoutException("Test SSH server did not start.");
    }

    public int Port { get; }

    /// <summary>Folder served as "/" over SFTP/SCP.</summary>
    public string SftpRoot { get; }

    /// <summary>A TCP echo service next to the SSH server (tunnel tests).</summary>
    public int EchoPort { get; private set; }

    internal static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimpleSSH.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repo root not found.");
    }

    public static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    public void Dispose()
    {
        try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); } catch { }
        _process.Dispose();
        try { Directory.Delete(SftpRoot, recursive: true); } catch { }
    }
}

[CollectionDefinition("ssh")]
public sealed class SshCollection : ICollectionFixture<TestSshServer> { }

[Collection("ssh")]
public sealed class SshIntegrationTests
{
    private readonly TestSshServer _server;

    public SshIntegrationTests(TestSshServer server) => _server = server;

    private SshConnectOptions Options(string user = "test", string? password = "test", int? port = null) => new()
    {
        Host = "127.0.0.1",
        Port = port ?? _server.Port,
        Credential = new ResolvedCredential(user, password, null, null),
        ConnectTimeout = TimeSpan.FromSeconds(10),
    };

    private sealed class OutputCollector
    {
        private readonly StringBuilder _sb = new();
        private readonly object _gate = new();

        public void Append(string s) { lock (_gate) _sb.Append(s); }
        public string Text { get { lock (_gate) return _sb.ToString(); } }

        public async Task WaitForAsync(string needle, int timeoutMs = 10000)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                if (Text.Contains(needle, StringComparison.Ordinal)) return;
                await Task.Delay(25);
            }
            throw new TimeoutException($"Did not see '{needle}'. Output so far:\n{Text}");
        }
    }

    [Fact]
    public async Task PasswordLogin_InteractiveShell_Resize_Unicode_Exit()
    {
        using var session = new SshTerminalSession(new AcceptAnyHostKeyVerifier());
        var output = new OutputCollector();
        var disconnected = new TaskCompletionSource<string>();
        session.Output += output.Append;
        session.Disconnected += r => disconnected.TrySetResult(r);

        await session.ConnectAsync(Options(), 100, 30);
        Assert.True(session.IsConnected);

        await output.WaitForAsync("Welcome to the SimpleSSH test server");
        await output.WaitForAsync("xterm-256color 100x30");

        session.Write("size\r");
        await output.WaitForAsync("100x30\r\n");

        session.Resize(132, 43);
        await Task.Delay(200);
        session.Write("size\r");
        await output.WaitForAsync("132x43");

        session.Write("color\r");
        await output.WaitForAsync("日本語 \U0001F600");

        session.Write("flood\r");
        await output.WaitForAsync("line 2000 ");

        session.Write("exit\r");
        var reason = await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains("closed", reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(session.EndedCleanly); // typing exit is a normal end -> the app closes the tab
        Assert.False(session.IsConnected);

        session.Write("ignored after disconnect\r"); // must not throw
    }

    [Fact]
    public async Task WrongPassword_FailsWithAuthenticationMessage()
    {
        using var session = new SshTerminalSession(new AcceptAnyHostKeyVerifier());
        var ex = await Assert.ThrowsAsync<SshSessionException>(() => session.ConnectAsync(Options(password: "wrong"), 80, 24));
        Assert.StartsWith("Authentication failed", ex.Message);
    }

    [Fact]
    public async Task RejectedHostKey_AbortsConnection()
    {
        var file = Path.Combine(Path.GetTempPath(), "simplessh-kh-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new KnownHostsStore(file);
            HostKeyInfo? seen = null;
            using var session = new SshTerminalSession(new KnownHostsVerifier(store, (k, _) => { seen = k; return HostKeyDecision.Reject; }));
            var ex = await Assert.ThrowsAsync<SshSessionException>(() => session.ConnectAsync(Options(), 80, 24));
            Assert.Contains("host key", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(seen);
            Assert.Contains("rsa", seen!.KeyType);          // test server uses an RSA host key
            Assert.Equal(43, seen.FingerprintSha256.Length); // unpadded base64 SHA-256
            Assert.Equal(_server.Port, seen.Port);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task KnownHosts_TrustOnFirstUse_ThenSilent()
    {
        var file = Path.Combine(Path.GetTempPath(), "simplessh-kh-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new KnownHostsStore(file);
            int asked = 0;
            var verifier = new KnownHostsVerifier(store, (_, check) =>
            {
                asked++;
                Assert.Equal(HostKeyStatus.Unknown, check.Status);
                return HostKeyDecision.AcceptAndSave;
            });

            using (var s1 = new SshTerminalSession(verifier)) await s1.ConnectAsync(Options(), 80, 24);
            using (var s2 = new SshTerminalSession(verifier)) await s2.ConnectAsync(Options(), 80, 24);
            Assert.Equal(1, asked);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task ClosedPort_ReportsConnectionRefused()
    {
        using var session = new SshTerminalSession(new AcceptAnyHostKeyVerifier());
        var ex = await Assert.ThrowsAsync<SshSessionException>(() =>
            session.ConnectAsync(Options(port: TestSshServer.GetFreePort()), 80, 24));
        Assert.Contains("refused", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Dispose_DoesNotRaiseDisconnected()
    {
        var session = new SshTerminalSession(new AcceptAnyHostKeyVerifier());
        bool raised = false;
        session.Disconnected += _ => raised = true;
        await session.ConnectAsync(Options(), 80, 24);
        session.Dispose();
        await Task.Delay(300);
        Assert.False(raised);
    }
}

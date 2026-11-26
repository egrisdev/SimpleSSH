using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Tests;

/// <summary>Starts tools/testserver/proxy.js (SOCKS4, SOCKS5 and HTTP CONNECT on one port).</summary>
public sealed class TestProxy : IDisposable
{
    private readonly Process _process;

    public TestProxy()
    {
        var script = Path.Combine(TestSshServer.FindRepoRoot(), "tools", "testserver", "proxy.js");
        _process = Process.Start(new ProcessStartInfo("node", $"\"{script}\" 0")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("Could not start node.");

        var ready = new TaskCompletionSource();
        _process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            Lines.Enqueue(e.Data);
            var m = Regex.Match(e.Data, @"proxy listening on (\d+)");
            if (m.Success)
            {
                Port = int.Parse(m.Groups[1].Value);
                ready.TrySetResult();
            }
        };
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
        if (!ready.Task.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("Test proxy did not start.");
    }

    public int Port { get; private set; }

    public ConcurrentQueue<string> Lines { get; } = new();

    public void Dispose()
    {
        try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); } catch { }
        _process.Dispose();
    }
}

[Collection("ssh")]
public sealed class FeatureIntegrationTests : IClassFixture<TestProxy>
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    private readonly TestSshServer _server;
    private readonly TestProxy _proxy;

    public FeatureIntegrationTests(TestSshServer server, TestProxy proxy)
    {
        _server = server;
        _proxy = proxy;
    }

    private SshConnectOptions Options(string user = "test", string? password = "test", AuthPromptHandler? prompt = null,
        ProxySettings? proxy = null, IReadOnlyList<TunnelSpec>? tunnels = null) => new()
    {
        Host = "127.0.0.1",
        Port = _server.Port,
        Credential = new ResolvedCredential(user, password, null, null),
        ConnectTimeout = TimeSpan.FromSeconds(10),
        Prompt = prompt,
        Proxy = proxy,
        Tunnels = tunnels ?? Array.Empty<TunnelSpec>(),
    };

    private static readonly IHostKeyVerifier Any = new AcceptAnyHostKeyVerifier();

    private static Task<CommandResult> Run(SshConnectOptions o, string command) =>
        SshCommandRunner.RunAsync(o, Any, command, TimeSpan.FromSeconds(15));

    // ------------------------------------------------------------------ Run command (exec)

    [Fact]
    public async Task RunCommand_ReturnsOutput_ExitCodes_AndStderr()
    {
        var ok = await Run(Options(), "echo hello world");
        Assert.Equal(0, ok.ExitStatus);
        Assert.Equal("hello world\n", ok.Output);
        Assert.True(ok.Succeeded);

        var fail = await Run(Options(), "fail");
        Assert.Equal(3, fail.ExitStatus);
        Assert.Equal("boom\n", fail.Error);
        Assert.False(fail.Succeeded);
        Assert.Contains("boom", fail.CombinedOutput);

        var missing = await Run(Options(), "nosuchcommand");
        Assert.Equal(127, missing.ExitStatus);
    }

    [Fact]
    public async Task RunCommand_ManyInParallel()
    {
        var results = await Task.WhenAll(Enumerable.Range(1, 8).Select(i => Run(Options(), $"echo n{i}")));
        for (int i = 1; i <= 8; i++) Assert.Equal($"n{i}\n", results[i - 1].Output);
    }

    [Fact]
    public async Task RunCommand_WrongPassword_IsAuthFailure()
    {
        var ex = await Assert.ThrowsAsync<SshSessionException>(() => Run(Options(password: "nope"), "whoami"));
        Assert.StartsWith("Authentication failed", ex.Message);
        Assert.True(SshConnector.IsAuthenticationFailure(ex));
    }

    // ------------------------------------------------------------------ MFA

    [Fact]
    public async Task Mfa_PasswordThenCode_PromptsOnlyForTheCode()
    {
        var asked = new List<AuthPromptRequest>();
        var result = await Run(Options("mfa", "test", r => { asked.Add(r); return new[] { "123456" }; }), "whoami");
        Assert.Equal("mfa\n", result.Output);
        var request = Assert.Single(asked);
        var field = Assert.Single(request.Fields);
        Assert.StartsWith("Verification code", field.Label);
        Assert.True(field.Echo);
    }

    [Fact]
    public async Task Otp_PasswordAndCodeInOnePrompt_PasswordAnsweredAutomatically()
    {
        var asked = new List<AuthPromptRequest>();
        var result = await Run(Options("otp", "test", r => { asked.Add(r); return new[] { "123456" }; }), "whoami");
        Assert.Equal("otp\n", result.Output);
        var field = Assert.Single(Assert.Single(asked).Fields);
        Assert.StartsWith("Verification code", field.Label);
    }

    [Fact]
    public async Task Mfa_WrongCode_Fails_CancelSaysCancelled()
    {
        var wrong = await Assert.ThrowsAsync<SshSessionException>(() => Run(Options("mfa", "test", _ => new[] { "000000" }), "whoami"));
        Assert.StartsWith("Authentication failed", wrong.Message);

        var cancelled = await Assert.ThrowsAsync<SshSessionException>(() => Run(Options("mfa", "test", _ => null), "whoami"));
        Assert.Equal("Login cancelled.", cancelled.Message);
    }

    [Fact]
    public async Task Otp_NoSavedPassword_AsksForEverything()
    {
        AuthPromptRequest? asked = null;
        var result = await Run(Options("otp", null, r => { asked = r; return new[] { "test", "123456" }; }), "whoami");
        Assert.Equal("otp\n", result.Output);
        Assert.Equal(2, asked!.Fields.Count);
        Assert.False(asked.Fields[0].Echo);
    }

    // ------------------------------------------------------------------ SFTP

    [Fact]
    public async Task Sftp_Browse_Upload_Download_Rename_Delete()
    {
        var work = Directory.CreateTempSubdirectory("simplessh-sftp-test-").FullName;
        try
        {
            using var sftp = await SftpSession.ConnectAsync(Options(), Any);
            Assert.Equal("/", sftp.HomeDirectory);

            var root = await sftp.ListAsync("/");
            Assert.Contains(root, e => e.Name == "readme.txt" && !e.IsDirectory && e.Size == "hello from sftp\n".Length);
            Assert.Contains(root, e => e.Name == "configs" && e.IsDirectory && e.Permissions.StartsWith('d'));
            Assert.True(root.TakeWhile(e => e.IsDirectory).Count() == root.Count(e => e.IsDirectory), "folders first");
            Assert.Equal("/configs", await sftp.ResolveDirectoryAsync("configs"));
            Assert.Equal("/configs", await sftp.ResolveDirectoryAsync("~/configs/../configs/"));

            // Upload a folder tree + a file.
            var tree = Path.Combine(work, "upload me");
            Directory.CreateDirectory(Path.Combine(tree, "sub"));
            File.WriteAllText(Path.Combine(tree, "a.txt"), "alpha");
            File.WriteAllBytes(Path.Combine(tree, "sub", "big.bin"), RandomBytes(3 * 1024 * 1024 + 17));
            var single = Path.Combine(work, "ünïcode name.txt");
            File.WriteAllText(single, "unicode ✓");
            var reports = new List<TransferProgress>();
            await sftp.UploadAsync(new[] { tree, single }, "/", new SyncProgress<TransferProgress>(reports.Add));
            Assert.NotEmpty(reports);
            Assert.Equal(reports[^1].BytesTotal, reports[^1].BytesDone);

            Assert.Equal("alpha", File.ReadAllText(Path.Combine(_server.SftpRoot, "upload me", "a.txt")));
            Assert.Equal(File.ReadAllBytes(Path.Combine(tree, "sub", "big.bin")), File.ReadAllBytes(Path.Combine(_server.SftpRoot, "upload me", "sub", "big.bin")));
            Assert.Equal("unicode ✓", File.ReadAllText(Path.Combine(_server.SftpRoot, "ünïcode name.txt")));

            // Download the folder back and one file to an exact path.
            var listing = await sftp.ListAsync("/");
            var folder = listing.Single(e => e.Name == "upload me");
            var back = Path.Combine(work, "back");
            Directory.CreateDirectory(back);
            await sftp.DownloadAsync(new[] { folder }, back, null);
            Assert.Equal(File.ReadAllBytes(Path.Combine(tree, "sub", "big.bin")), File.ReadAllBytes(Path.Combine(back, "upload me", "sub", "big.bin")));
            var readme = listing.Single(e => e.Name == "readme.txt");
            await sftp.DownloadFileAsync(readme, Path.Combine(work, "r.txt"), null);
            Assert.Equal("hello from sftp\n", File.ReadAllText(Path.Combine(work, "r.txt")));
            Assert.Empty(Directory.GetFiles(work, "*.part", SearchOption.AllDirectories));

            // Folder ops.
            await sftp.CreateDirectoryAsync("/new folder");
            await sftp.RenameAsync("/new folder", "/renamed");
            Assert.True(Directory.Exists(Path.Combine(_server.SftpRoot, "renamed")));
            await sftp.DeleteAsync(new RemoteEntry("renamed", "/renamed", true, false, 0, default, ""));
            await sftp.DeleteAsync(folder); // recursive
            Assert.False(Directory.Exists(Path.Combine(_server.SftpRoot, "upload me")));
            Assert.False(Directory.Exists(Path.Combine(_server.SftpRoot, "renamed")));

            var missing = await Assert.ThrowsAsync<SshSessionException>(() => sftp.ListAsync("/does-not-exist"));
            Assert.Contains("not found", missing.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    [Fact]
    public async Task Sftp_CancelledUpload_StopsAndSessionStaysUsable()
    {
        var work = Directory.CreateTempSubdirectory("simplessh-sftp-cancel-").FullName;
        try
        {
            var big = Path.Combine(work, "huge.bin");
            File.WriteAllBytes(big, RandomBytes(64 * 1024 * 1024));
            using var sftp = await SftpSession.ConnectAsync(Options(), Any);
            using var cts = new CancellationTokenSource();
            var progress = new SyncProgress<TransferProgress>(p => { if (p.BytesDone > 1024 * 1024) cts.Cancel(); });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sftp.UploadAsync(new[] { big }, "/", progress, cts.Token));

            var listing = await sftp.ListAsync("/");
            Assert.Contains(listing, e => e.Name == "readme.txt");
            Assert.DoesNotContain(listing, e => e.Name == "huge.bin"); // partial upload cleaned up
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    // ------------------------------------------------------------------ SCP

    [Fact]
    public async Task Scp_Upload_And_Download_WithAwkwardNames()
    {
        var work = Directory.CreateTempSubdirectory("simplessh-scp-").FullName;
        try
        {
            var local = Path.Combine(work, "it's a $file!.txt");
            File.WriteAllText(local, "scp payload");
            await ScpTransfer.UploadAsync(Options(), Any, local, "/configs/", null);
            Assert.Equal("scp payload", File.ReadAllText(Path.Combine(_server.SftpRoot, "configs", "it's a $file!.txt")));

            await ScpTransfer.UploadAsync(Options(), Any, local, "/configs/renamed.txt", null);
            Assert.Equal("scp payload", File.ReadAllText(Path.Combine(_server.SftpRoot, "configs", "renamed.txt")));

            var back = Path.Combine(work, "back.txt");
            await ScpTransfer.DownloadAsync(Options(), Any, "/configs/switch1.cfg", back, null);
            Assert.Equal("hostname switch1\n", File.ReadAllText(back));

            var ex = await Assert.ThrowsAsync<SshSessionException>(() => ScpTransfer.DownloadAsync(Options(), Any, "/nope.cfg", Path.Combine(work, "x"), null));
            Assert.StartsWith("SCP download failed", ex.Message);
            Assert.False(File.Exists(Path.Combine(work, "x.part")));
        }
        finally
        {
            Directory.Delete(work, recursive: true);
            foreach (var f in new[] { "it's a $file!.txt", "renamed.txt" })
                try { File.Delete(Path.Combine(_server.SftpRoot, "configs", f)); } catch { }
        }
    }

    // ------------------------------------------------------------------ Tunnels

    [Fact]
    public async Task Tunnels_Local_Remote_Dynamic_AllCarryTraffic()
    {
        Assert.True(_server.EchoPort > 0, "server did not report its echo port");
        int localPort = TestSshServer.GetFreePort(), socksPort = TestSshServer.GetFreePort(), remotePort = TestSshServer.GetFreePort();

        // Something on "this PC" for the remote forward to reach.
        using var localEcho = new TcpListener(IPAddress.Loopback, 0);
        localEcho.Start();
        var localEchoPort = ((IPEndPoint)localEcho.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await localEcho.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(async () => { using (c) { var s = c.GetStream(); var buf = new byte[256]; int n; while ((n = await s.ReadAsync(buf)) > 0) await s.WriteAsync(buf.AsMemory(0, n)); } });
            }
        });

        var tunnels = new[]
        {
            TunnelSpec.Parse($"L {localPort}:127.0.0.1:{_server.EchoPort}"),
            TunnelSpec.Parse($"D {socksPort}"),
            TunnelSpec.Parse($"R {remotePort}:127.0.0.1:{localEchoPort}"),
        };
        using var session = new SshTerminalSession(Any);
        await session.ConnectAsync(Options(tunnels: tunnels), 80, 24);
        Assert.All(session.TunnelStatus, s => Assert.StartsWith("Tunnel open", s));
        Assert.Equal(3, session.TunnelStatus.Count);

        Assert.Equal("via-local", await EchoAsync(localPort, "via-local"));
        Assert.Equal("via-socks", await EchoViaSocks5Async(socksPort, "127.0.0.1", _server.EchoPort, "via-socks"));
        Assert.Equal("via-remote", await EchoAsync(remotePort, "via-remote")); // server-side port -> back to this PC

        localEcho.Stop();
    }

    [Fact]
    public async Task Tunnel_PortInUse_IsReported_SessionStillWorks()
    {
        using var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        var busy = ((IPEndPoint)blocker.LocalEndpoint).Port;

        using var session = new SshTerminalSession(Any);
        await session.ConnectAsync(Options(tunnels: new[] { TunnelSpec.Parse($"L {busy}:127.0.0.1:{_server.EchoPort}") }), 80, 24);
        var status = Assert.Single(session.TunnelStatus);
        Assert.StartsWith("Tunnel failed", status);
        Assert.True(session.IsConnected);
    }

    // ------------------------------------------------------------------ Proxies

    [Theory]
    [InlineData("socks5")]
    [InlineData("socks4")]
    [InlineData("http")]
    public async Task Proxy_AllKinds_ReachTheServer(string scheme)
    {
        var proxy = ProxySettings.Parse($"{scheme}://127.0.0.1:{_proxy.Port}");
        var result = await Run(Options(proxy: proxy), "hostname");
        Assert.Equal("testserver\n", result.Output);
        Assert.Contains(_proxy.Lines, l => l.Contains($"proxied {scheme}") && l.Contains($":{_server.Port}"));
    }

    [Fact]
    public async Task Proxy_Socks5WithCredentials_AndBadCredentialsFail()
    {
        var good = await Run(Options(proxy: ProxySettings.Parse($"socks5://proxy:proxy@127.0.0.1:{_proxy.Port}")), "hostname");
        Assert.Equal("testserver\n", good.Output);

        await Assert.ThrowsAsync<SshSessionException>(() =>
            Run(Options(proxy: ProxySettings.Parse($"socks5://proxy:wrong@127.0.0.1:{_proxy.Port}")), "hostname"));
    }

    [Fact]
    public async Task Proxy_Unreachable_GivesReadableError()
    {
        var ex = await Assert.ThrowsAsync<SshSessionException>(() =>
            Run(Options(proxy: ProxySettings.Parse($"socks5://127.0.0.1:{TestSshServer.GetFreePort()}")), "hostname"));
        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static async Task<string> EchoAsync(int port, string text)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port).WaitAsync(Timeout);
        var s = client.GetStream();
        return await RoundTrip(s, text);
    }

    private static async Task<string> EchoViaSocks5Async(int socksPort, string host, int port, string text)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, socksPort).WaitAsync(Timeout);
        var s = client.GetStream();
        await s.WriteAsync(new byte[] { 5, 1, 0 });
        var reply = new byte[2];
        await s.ReadExactlyAsync(reply).AsTask().WaitAsync(Timeout);
        Assert.Equal(new byte[] { 5, 0 }, reply);
        var ip = IPAddress.Parse(host).GetAddressBytes();
        await s.WriteAsync(new byte[] { 5, 1, 0, 1 }.Concat(ip).Concat(new[] { (byte)(port >> 8), (byte)port }).ToArray());
        var connect = new byte[10];
        await s.ReadExactlyAsync(connect).AsTask().WaitAsync(Timeout);
        Assert.Equal(0, connect[1]);
        return await RoundTrip(s, text);
    }

    private static async Task<string> RoundTrip(NetworkStream s, string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        await s.WriteAsync(data);
        var buf = new byte[data.Length];
        await s.ReadExactlyAsync(buf).AsTask().WaitAsync(Timeout);
        return Encoding.UTF8.GetString(buf);
    }

    /// <summary>IProgress that reports synchronously (Progress&lt;T&gt; posts to the thread pool).</summary>
    private sealed class SyncProgress<T> : IProgress<T>
    {
        private readonly Action<T> _action;
        private readonly object _gate = new();
        public SyncProgress(Action<T> action) => _action = action;
        public void Report(T value) { lock (_gate) _action(value); }
    }
}

/// <summary>A server that refuses SFTP, like many switches: browsing fails clearly, SCP still works.</summary>
public sealed class ScpOnlyServerTests : IDisposable
{
    private readonly TestSshServer _server = new(noSftp: true);

    public void Dispose() => _server.Dispose();

    private SshConnectOptions Options() => new()
    {
        Host = "127.0.0.1",
        Port = _server.Port,
        Credential = new ResolvedCredential("test", "test", null, null),
        ConnectTimeout = TimeSpan.FromSeconds(10),
    };

    [Fact]
    public async Task Sftp_IsReportedAsUnavailable_ScpStillWorks()
    {
        var ex = await Assert.ThrowsAsync<SftpUnavailableException>(() => SftpSession.ConnectAsync(Options(), new AcceptAnyHostKeyVerifier()));
        Assert.Contains("SCP", ex.Message);

        var work = Directory.CreateTempSubdirectory("simplessh-scponly-").FullName;
        try
        {
            var back = Path.Combine(work, "readme.txt");
            await ScpTransfer.DownloadAsync(Options(), new AcceptAnyHostKeyVerifier(), "readme.txt", back, null);
            Assert.Equal("hello from sftp\n", File.ReadAllText(back));
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }
}

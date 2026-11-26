using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

public sealed class TunnelSpecTests
{
    [Theory]
    [InlineData("L 8080:db:5432", TunnelKind.Local, "127.0.0.1", 8080, "db", 5432)]
    [InlineData("-L 8080:db:5432", TunnelKind.Local, "127.0.0.1", 8080, "db", 5432)]
    [InlineData("l8080:db:5432", TunnelKind.Local, "127.0.0.1", 8080, "db", 5432)]
    [InlineData("L 0.0.0.0:8080:10.0.0.5:80", TunnelKind.Local, "0.0.0.0", 8080, "10.0.0.5", 80)]
    [InlineData("L *:8080:db:80", TunnelKind.Local, "0.0.0.0", 8080, "db", 80)]
    [InlineData("L 8080:[fe80::1]:80", TunnelKind.Local, "127.0.0.1", 8080, "fe80::1", 80)]
    [InlineData("R 9000:localhost:22", TunnelKind.Remote, "127.0.0.1", 9000, "localhost", 22)]
    [InlineData("D 1080", TunnelKind.Dynamic, "127.0.0.1", 1080, "", 0)]
    [InlineData("  d 0.0.0.0:1080 ", TunnelKind.Dynamic, "0.0.0.0", 1080, "", 0)]
    public void Parses(string text, TunnelKind kind, string bind, int bindPort, string host, int port)
    {
        Assert.True(TunnelSpec.TryParse(text, out var spec, out var error), error);
        Assert.Equal(new TunnelSpec(kind, bind, bindPort, host, port), spec);
    }

    [Theory]
    [InlineData("")]
    [InlineData("X 80:a:80")]
    [InlineData("L 8080")]
    [InlineData("L 8080:db")]
    [InlineData("L 99999:db:80")]
    [InlineData("L abc:db:80")]
    [InlineData("L 8080::80")]
    [InlineData("D 1080:a:b")]
    [InlineData("L 8080:[fe80::1:80")]
    public void Rejects(string text)
    {
        Assert.False(TunnelSpec.TryParse(text, out _, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void ParseAll_SkipsBlanksAndComments_AndRoundTrips()
    {
        Assert.True(TunnelSpec.TryParseAll(new[] { "L 8080:db:5432", "", "# note", "D 1080" }, out var specs, out _));
        Assert.Equal(2, specs.Count);
        Assert.Equal("L 8080:db:5432", specs[0].ToString());
        Assert.Equal("D 1080", specs[1].ToString());
        Assert.Equal("local 127.0.0.1:8080 → db:5432", specs[0].Describe());
        Assert.False(TunnelSpec.TryParseAll(new[] { "L 8080:db:5432", "bogus" }, out _, out var error));
        Assert.Contains("bogus", error);
    }
}

public sealed class ProxySettingsTests
{
    [Theory]
    [InlineData("socks5://proxy:1080", ProxyKind.Socks5, "proxy", 1080, null, null)]
    [InlineData("socks5://bastion", ProxyKind.Socks5, "bastion", 1080, null, null)]
    [InlineData("socks://u:p@10.0.0.1:9050", ProxyKind.Socks5, "10.0.0.1", 9050, "u", "p")]
    [InlineData("socks4://proxy:1081", ProxyKind.Socks4, "proxy", 1081, null, null)]
    [InlineData("http://proxy.corp:3128", ProxyKind.Http, "proxy.corp", 3128, null, null)]
    [InlineData("HTTP://proxy", ProxyKind.Http, "proxy", 8080, null, null)]
    [InlineData("http://me%40corp:p%3Ass@proxy:80", ProxyKind.Http, "proxy", 80, "me@corp", "p:ss")]
    [InlineData("socks5://[::1]:1080", ProxyKind.Socks5, "::1", 1080, null, null)]
    public void Parses(string text, ProxyKind kind, string host, int port, string? user, string? pass)
    {
        Assert.True(ProxySettings.TryParse(text, out var p, out var error), error);
        Assert.Equal(new ProxySettings(kind, host, port, user, pass), p);
    }

    [Theory]
    [InlineData("proxy:1080")]
    [InlineData("https://proxy:443")]
    [InlineData("ftp://x")]
    [InlineData("socks5://")]
    [InlineData("http://proxy:3128/path")]
    public void Rejects(string text) => Assert.False(ProxySettings.TryParse(text, out _, out _));

    [Fact]
    public void ToString_MasksPassword()
    {
        Assert.Equal("socks5://u:****@h:1080", ProxySettings.Parse("socks5://u:secret@h:1080").ToString());
        Assert.True(ProxySettings.HasPassword("socks5://u:secret@h"));
        Assert.False(ProxySettings.HasPassword("socks5://u@h"));
        Assert.False(ProxySettings.HasPassword("http://h:3128"));
    }
}

public sealed class LoginPromptTests
{
    [Theory]
    [InlineData("Password: ", 1, true)]
    [InlineData("user@host's password: ", 2, true)]
    [InlineData("Enter PASSCODE: ", 1, false)]
    [InlineData("Verification code: ", 1, false)]
    [InlineData("Duo two-factor login. Passcode or option (1-1): ", 1, false)]
    [InlineData("Token: ", 1, false)]
    [InlineData("Response: ", 1, true)]   // lone unnamed hidden prompt: most likely the password
    [InlineData("Response: ", 2, false)]
    public void ClassifiesPasswordPrompts(string request, int count, bool isPassword) =>
        Assert.Equal(isPassword, SshConnector.LooksLikePasswordPrompt(request, count));
}

public sealed class ProxyStorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-px-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void ProxyWithPassword_IsEncrypted_PlainProxyIsNot_TunnelsRoundTrip()
    {
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Add(new Connection { Name = "a", Host = "h1", Proxy = "socks5://u:hunter2@px:1080", Tunnels = new() { " L 8080:db:5432 ", "", "D 1080" } });
        store.Add(new Connection { Name = "b", Host = "h2", Proxy = "http://px:3128", Tunnels = new() { "  " } });

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("hunter2", json);
        Assert.Contains("\"proxy\": \"http://px:3128\"", json);   // nothing secret: stays readable
        Assert.Contains("\"L 8080:db:5432\"", json);

        var reloaded = new ConnectionStore(FilePath, new DpapiSecretProtector());
        reloaded.Load();
        Assert.Equal("socks5://u:hunter2@px:1080", reloaded.Connections[0].Proxy);
        Assert.Equal(new[] { "L 8080:db:5432", "D 1080" }, reloaded.Connections[0].Tunnels);
        Assert.Equal("http://px:3128", reloaded.Connections[1].Proxy);
        Assert.Null(reloaded.Connections[1].Tunnels);
    }

    [Fact]
    public void PlainProxyPassword_InFile_IsMigrated()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, """{ "connections": [ { "host": "h", "proxy": "socks5://u:pw123@px" } ] }""");
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Load();
        Assert.Equal(1, store.MigratedSecretCount);
        Assert.DoesNotContain("pw123", File.ReadAllText(FilePath));
        Assert.Equal("socks5://u:pw123@px", store.Connections[0].Proxy);
    }
}

public sealed class SshErrorTests
{
    [Fact]
    public async Task FailedLogin_IsMarked_SoOnlyItIsRetried()
    {
        // Nothing listens on port 1 here: the connect itself fails, before anything could run on a server.
        var options = new SshConnectOptions
        {
            Host = "127.0.0.1",
            Port = 1,
            Credential = new ResolvedCredential("u", "p", null, null),
            ConnectTimeout = TimeSpan.FromSeconds(5),
        };
        var ex = await Assert.ThrowsAsync<SshSessionException>(() => SshCommandRunner.RunAsync(options, new AcceptAnyHostKeyVerifier(), "true", TimeSpan.FromSeconds(5)));
        Assert.True(SshSessionException.FailedDuringLogin(ex));
        Assert.True(SshSessionException.FailedDuringLogin(new InvalidOperationException("wrapped", ex)));

        // A failure after logging in (e.g. the command timing out) is not.
        Assert.False(SshSessionException.FailedDuringLogin(new SshSessionException("The command did not finish within 120 seconds.")));
    }
}

public sealed class DownloadNameTests
{
    [Theory]
    [InlineData("report.pdf", "report.pdf")]
    [InlineData(@"a/b\c:d", "a_b_c_d")]
    [InlineData("..", "_")]
    [InlineData("name. . ", "name")]
    [InlineData("report\u202Efdp.exe", "reportfdp.exe")] // right-to-left override would show "reportexe.pdf"
    [InlineData("in\u200Bvisible\u2066.txt", "invisible.txt")]
    [InlineData("CON", "_CON")]
    [InlineData("con.txt", "_con.txt")]
    [InlineData("NUL .tar.gz", "_NUL .tar.gz")]
    [InlineData("COM1", "_COM1")]
    [InlineData("lpt9.log", "_lpt9.log")]
    [InlineData("CONSOLE.txt", "CONSOLE.txt")]
    [InlineData("COM10", "COM10")]
    public void SafeLocalName_Cleans(string remote, string expected) =>
        Assert.Equal(expected, SftpSession.SafeLocalName(remote));

    [Fact]
    public void MarkDownloaded_AddsTheMarkOfTheWeb()
    {
        var file = Path.Combine(Path.GetTempPath(), "simplessh-motw-" + Guid.NewGuid().ToString("N") + ".exe");
        try
        {
            File.WriteAllText(file, "x");
            SftpSession.MarkDownloaded(file, "srv1", "/home/u/tool.exe");
            var mark = File.ReadAllText(file + ":Zone.Identifier");
            Assert.Contains("[ZoneTransfer]", mark);
            Assert.Contains("ZoneId=3", mark);
            Assert.Contains("HostUrl=sftp://srv1/home/u/tool.exe", mark);
            Assert.Equal("x", File.ReadAllText(file));
        }
        finally
        {
            File.Delete(file);
        }
    }
}


public sealed class PasteTextTests
{
    [Fact]
    public void Clean_RemovesHiddenEscapes_KeepsLinesAndTabs()
    {
        Assert.Equal("echo hi[201~rm -rf ~" + "\r", PasteText.Clean("echo hi\u001b[201~rm -rf ~\r"));
        Assert.Equal("a\tb\r\nc\n", PasteText.Clean("a\tb\r\nc\n"));
        Assert.Equal("ab", PasteText.Clean("a\u009b201~b".Replace("201~", "")));
        Assert.Equal("x", PasteText.Clean("\u0000x\u007f\u0007"));
        Assert.Equal("", PasteText.Clean(""));
        var plain = "ls -la /tmp";
        Assert.Same(plain, PasteText.Clean(plain));
    }
}

public sealed class PrivateFolderTests
{
    [Fact]
    public void Secure_LimitsAFolderOthersCanWrite_ToThisUser()
    {
        var dir = Path.Combine(Path.GetTempPath(), "simplessh-acl-" + Guid.NewGuid().ToString("N"));
        try
        {
            var info = Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "connections.json"), "{}");
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);

            // %TEMP% is already private: nothing to change.
            Assert.False(SimpleSSH.Core.PrivateFolder.Secure(dir));

            // Like a folder made directly on C:\, where every user may add and change files.
            var open = info.GetAccessControl();
            open.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(users,
                System.Security.AccessControl.FileSystemRights.Modify,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
            info.SetAccessControl(open);
            Assert.True(SimpleSSH.Core.PrivateFolder.OthersCanWrite(info.GetAccessControl(), me));

            Assert.True(SimpleSSH.Core.PrivateFolder.Secure(dir));
            Assert.False(SimpleSSH.Core.PrivateFolder.OthersCanWrite(info.GetAccessControl(), me));
            var file = new FileInfo(Path.Combine(dir, "connections.json")).GetAccessControl();
            Assert.DoesNotContain(file.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
                .Cast<System.Security.AccessControl.FileSystemAccessRule>(), r => r.IdentityReference.Equals(users));
            Assert.Equal("{}", File.ReadAllText(Path.Combine(dir, "connections.json"))); // still readable by this user
            Assert.False(SimpleSSH.Core.PrivateFolder.Secure(dir)); // once is enough
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

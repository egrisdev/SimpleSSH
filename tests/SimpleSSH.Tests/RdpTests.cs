using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Rdp;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

public class RdpSettingsTests
{
    [Theory]
    [InlineData(@"CONTOSO\ann", "CONTOSO", "ann")]
    [InlineData("ann@contoso.com", "", "ann@contoso.com")]
    [InlineData("ann", "", "ann")]
    [InlineData(@"AzureAD\ann@contoso.com", "AzureAD", "ann@contoso.com")]
    [InlineData(@".\Administrator", ".", "Administrator")]
    [InlineData(@"  CONTOSO\ann  ", "CONTOSO", "ann")]
    [InlineData(@"\ann", "", @"\ann")]
    [InlineData(@"CONTOSO\", "", @"CONTOSO\")]
    [InlineData("", "", "")]
    [InlineData(null, "", "")]
    public void SplitUser(string? input, string domain, string user)
    {
        Assert.Equal((domain, user), RdpSettings.SplitUser(input));
    }

    [Theory]
    [InlineData("server1", 3389, "server1")]
    [InlineData("server1", 3390, "server1:3390")]
    [InlineData("10.0.0.5", 3389, "10.0.0.5")]
    [InlineData("fe80::1", 3389, "[fe80::1]")]
    [InlineData("fe80::1", 3390, "[fe80::1]:3390")]
    public void FullAddress(string host, int port, string expected)
    {
        Assert.Equal(expected, RdpSettings.FullAddress(new Connection { Protocol = ConnectionProtocol.Rdp, Host = host, Port = port }));
    }

    [Fact]
    public void RdpFile_HasAddressAndUser_NeverThePassword()
    {
        var c = new Connection { Protocol = ConnectionProtocol.Rdp, Host = "ts01", Port = 3390, Username = @"CONTOSO\ann", Password = "hunter2" };
        var file = RdpSettings.BuildRdpFile(c);
        var lines = file.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains("full address:s:ts01:3390", lines);
        Assert.Contains(@"username:s:CONTOSO\ann", lines);
        Assert.Contains("prompt for credentials:i:0", lines);
        Assert.DoesNotContain("hunter2", file);
        Assert.DoesNotContain("password", file, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RdpFile_StripsLineBreaksFromValues()
    {
        var c = new Connection { Protocol = ConnectionProtocol.Rdp, Host = "ts01", Port = 3389, Username = "ann\r\nalternate shell:s:cmd" };
        var lines = RdpSettings.BuildRdpFile(c).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.DoesNotContain(lines, l => l.StartsWith("alternate shell", StringComparison.Ordinal));
        Assert.DoesNotContain("username:s:", RdpSettings.BuildRdpFile(new Connection { Host = "x", Port = 3389, Username = "  " }));
    }

    [Fact]
    public void CredentialTarget_IsTermsrvHost()
    {
        Assert.Equal("TERMSRV/ts01.contoso.com", RdpSettings.CredentialTarget(new Connection { Host = " ts01.contoso.com " }));
    }

    [Theory]
    [InlineData(1.0, 100u, 100u)]
    [InlineData(1.25, 125u, 140u)]
    [InlineData(1.5, 150u, 140u)]
    [InlineData(1.75, 175u, 180u)]
    [InlineData(2.0, 200u, 180u)]
    [InlineData(1.1, 100u, 100u)]
    [InlineData(3.5, 300u, 180u)]
    public void ScaleFactors(double dpi, uint desktop, uint device)
    {
        Assert.Equal((desktop, device), RdpSettings.ScaleFactors(dpi));
    }

    [Theory]
    [InlineData(1921.4, 1080.2, 1920, 1080)]
    [InlineData(1001, 700, 1000, 700)]
    [InlineData(1427.6, 900.9, 1426, 900)]
    [InlineData(1439.999, 899.996, 1440, 900)]
    [InlineData(50, 20, 200, 200)]
    [InlineData(20000, 9000, 8192, 8192)]
    public void ClampDesktopSize(double w, double h, int ew, int eh)
    {
        Assert.Equal((ew, eh), RdpSettings.ClampDesktopSize(w, h));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(516, false)]
    [InlineData(2055, false)]
    public void IsNormalEnd(int reason, bool expected) => Assert.Equal(expected, RdpSettings.IsNormalEnd(reason));
}

public class ConnectionProtocolTests
{
    [Fact]
    public void Endpoint_HidesTheProtocolsDefaultPort()
    {
        Assert.Equal("ts01", new Connection { Protocol = ConnectionProtocol.Rdp, Host = "ts01", Port = 3389 }.Endpoint);
        Assert.Equal("ts01:22", new Connection { Protocol = ConnectionProtocol.Rdp, Host = "ts01", Port = 22 }.Endpoint);
        Assert.Equal("sw1", new Connection { Host = "sw1", Port = 22 }.Endpoint);
        Assert.Equal("sw1:3389", new Connection { Host = "sw1", Port = 3389 }.Endpoint);
    }

    [Fact]
    public void CloneAndCopyFrom_KeepTheProtocol()
    {
        var rdp = new Connection { Protocol = ConnectionProtocol.Rdp, Host = "ts01", Port = 3389 };
        Assert.True(rdp.Clone().IsRdp);
        var target = new Connection();
        target.CopyFrom(rdp);
        Assert.True(target.IsRdp);
    }
}

public sealed class RdpStorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-rdp-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void RdpIsSaved_SshIsTheDefaultAndNotWritten_PasswordEncrypted()
    {
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Add(new Connection { Name = "ts", Host = "ts01", Port = 3389, Protocol = ConnectionProtocol.Rdp, Username = @"CONTOSO\ann", Password = "hunter2" });
        store.Add(new Connection { Name = "sw", Host = "sw1" });

        var json = File.ReadAllText(FilePath);
        Assert.Contains("\"protocol\": \"Rdp\"", json);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(json, "\"protocol\""));
        Assert.DoesNotContain("hunter2", json);

        var reloaded = new ConnectionStore(FilePath, new DpapiSecretProtector());
        reloaded.Load();
        var ts = reloaded.Connections.Single(c => c.Name == "ts");
        Assert.True(ts.IsRdp);
        Assert.Equal("hunter2", ts.Password);
        Assert.False(reloaded.Connections.Single(c => c.Name == "sw").IsRdp);
    }

    [Theory]
    [InlineData("rdp")]
    [InlineData("RDP")]
    [InlineData("Rdp")]
    public void HandEditedProtocol_IsCaseInsensitive(string value)
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, $$"""{ "connections": [ { "name": "ts", "host": "ts01", "port": 3389, "protocol": "{{value}}" } ] }""");
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Load();
        Assert.True(store.Connections.Single().IsRdp);
    }
}

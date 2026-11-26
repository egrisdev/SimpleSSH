using SimpleSSH.Core;

namespace SimpleSSH.Tests;

public sealed class HostCheckTests
{
    [Theory]
    [InlineData("ds-app-01-ilo.corp.example")]
    [InlineData("core-sw-01")]
    [InlineData("DC01")]
    [InlineData("my_host.lan")]
    [InlineData("10.0.0.5")]
    [InlineData("255.255.255.255")]
    [InlineData("fe80::1")]
    [InlineData("fe80::1%12")]
    [InlineData("2001:db8::5")]
    [InlineData("bücher.example")]
    [InlineData("  core-sw-01  ")]
    public void GoodHosts_Pass(string host) => Assert.Null(HostCheck.Problem(host, out _));

    [Theory]
    [InlineData("ds-app-01-ilo.corp.example/", "ds-app-01-ilo.corp.example")]
    [InlineData("ilo-01.example.com/html/login.html", "ilo-01.example.com")]
    [InlineData("ilo-01\\", "ilo-01")]
    [InlineData("ssh://core-sw-01", "core-sw-01")]
    [InlineData("ilo-01.example.com.", "ilo-01.example.com")]
    [InlineData(".ilo-01", "ilo-01")]
    [InlineData("ilo-01..example.com", "ilo-01.example.com")]
    [InlineData("core-sw-01,", "core-sw-01")]
    [InlineData("<core-sw-01>", "core-sw-01")]
    [InlineData("\"core-sw-01\"", "core-sw-01")]
    [InlineData("core-sw-01:abc", "core-sw-01")]
    [InlineData("-core-sw-01", "core-sw-01")]
    [InlineData("10.0.0.5.", "10.0.0.5")]
    public void BadHosts_GetAFix(string host, string fix)
    {
        Assert.NotNull(HostCheck.Problem(host, out var suggestion));
        Assert.Equal(fix, suggestion);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ilo 01")]
    [InlineData("10.0.0.256")]
    [InlineData("10.0.0")]
    [InlineData("1234")]
    [InlineData("fe80::zz")]
    [InlineData("/")]
    public void BadHosts_WithoutAnObviousFix(string host)
    {
        Assert.NotNull(HostCheck.Problem(host, out var suggestion));
        Assert.Null(suggestion);
    }
}

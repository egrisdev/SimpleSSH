using System.Net;
using System.Text;
using System.Text.Json;
using SimpleSSH.Core.Bmc;
using SimpleSSH.Core.Models;

namespace SimpleSSH.Tests;

public sealed class WebAppTests
{
    // Trimmed from the start pages these apps serve at /.
    private const string PvePage = "<html><head><title>pve-01 - Proxmox Virtual Environment</title><script src=\"/pve2/js/pvemanagerlib.js\"></script>";
    private const string PbsPage = "<html><head><title>pbs-01 - Proxmox Backup Server</title><script src=\"/js/proxmox-backup-gui.js\"></script>";
    private const string VCenterPage = "<html><head><title>VMware vSphere</title></head><body><a href=\"/ui/\">Launch vSphere Client</a> vCenter Server</body>";
    private const string EsxiPage = "<html><head><meta http-equiv=\"refresh\" content=\"0;URL='/ui'\"/><title>VMware ESXi</title></head></html>";

    private static readonly Uri Home = new("https://pve-01.example.invalid:8006/");

    [Fact]
    public void StartPage_TellsTheAppApart()
    {
        Assert.Equal(WebAppKind.ProxmoxVe, WebApps.Detect(PvePage));
        Assert.Equal(WebAppKind.ProxmoxBackup, WebApps.Detect(PbsPage));
        Assert.Equal(WebAppKind.VCenter, WebApps.Detect(VCenterPage));
        Assert.Equal(WebAppKind.Esxi, WebApps.Detect(EsxiPage));
        Assert.Equal(WebAppKind.Other, WebApps.Detect("<html><title>TrueNAS</title></html>"));
        Assert.Equal(WebAppKind.Other, WebApps.Detect(""));
    }

    [Theory]
    [InlineData("root", "root@pam")]
    [InlineData("admin@pve", "admin@pve")]
    [InlineData("jdoe@ad.example", "jdoe@ad.example")]
    public void ProxmoxUser_GetsTheDefaultRealm(string user, string expected) => Assert.Equal(expected, WebApps.ProxmoxUser(user));

    [Fact]
    public void WebConnection_DefaultsToHttpsAndRoundTrips()
    {
        Assert.Equal(443, Connection.DefaultPortFor(ConnectionProtocol.Web));
        var c = new Connection { Protocol = ConnectionProtocol.Web, Host = "vc-01", Port = 443 };
        var back = JsonSerializer.Deserialize<Connection>(JsonSerializer.Serialize(c))!;
        Assert.True(back.IsWeb && back.IsWebPage && !back.IsConsole && !back.IsSsh);
        Assert.Equal("vc-01", back.Endpoint);
    }

    [Fact]
    public async Task Proxmox_SignsInWithATicketCookie()
    {
        var fake = new FakeApp()
            .On("GET /", 200, PvePage)
            .On("POST /api2/json/access/ticket", 200, """{"data":{"username":"root@pam","ticket":"PVE:root@pam:65A1B2C3::sig+/=","CSRFPreventionToken":"x"}}""");
        using var client = new ServerConsoleClient(Home, fake);

        var launch = await client.PrepareWebAppAsync("root", "pa&ss=word");

        Assert.Equal(Home, launch.Url);
        Assert.False(launch.WebPageOnly);
        Assert.False(launch.FillLogin);
        Assert.Equal("Proxmox VE", launch.Product);
        var cookie = Assert.Single(launch.Cookies);
        Assert.Equal("PVEAuthCookie", cookie.Key);
        Assert.Equal("PVE:root@pam:65A1B2C3::sig+/=", Uri.UnescapeDataString(cookie.Value));
        Assert.DoesNotContain(cookie.Value, c => "+/=:@".Contains(c)); // escaped, as Proxmox's own page does
        Assert.Equal("username=root%40pam&password=pa%26ss%3Dword", fake.Bodies["POST /api2/json/access/ticket"]);
    }

    [Fact]
    public async Task ProxmoxBackup_UsesItsOwnCookie()
    {
        var fake = new FakeApp()
            .On("GET /", 200, PbsPage)
            .On("POST /api2/json/access/ticket", 200, """{"data":{"ticket":"PBS:root@pam:65A1B2C3::sig"}}""");
        using var client = new ServerConsoleClient(Home, fake);

        var launch = await client.PrepareWebAppAsync("root@pam", "secret");

        Assert.Equal("PBSAuthCookie", Assert.Single(launch.Cookies).Key);
    }

    [Fact]
    public async Task Proxmox_WrongPassword_IsABadLogin()
    {
        var fake = new FakeApp().On("GET /", 200, PvePage).On("POST /api2/json/access/ticket", 401, "");
        using var client = new ServerConsoleClient(Home, fake);

        var ex = await Assert.ThrowsAsync<BmcException>(() => client.PrepareWebAppAsync("root", "wrong"));

        Assert.Equal(BmcFailure.BadLogin, ex.Failure);
        Assert.Contains("root@pam", ex.Message);
        Assert.Single(fake.Requests, r => r.StartsWith("POST")); // tried once, never again
    }

    [Fact]
    public async Task Proxmox_TwoFactor_OpensTheLoginPage()
    {
        var fake = new FakeApp()
            .On("GET /", 200, PvePage)
            .On("POST /api2/json/access/ticket", 200, """{"data":{"ticket":"PVE:!tfa!{\"totp\":true}:65A1B2C3::sig","NeedTFA":1}}""");
        using var client = new ServerConsoleClient(Home, fake);

        var launch = await client.PrepareWebAppAsync("root", "secret");

        Assert.True(launch.WebPageOnly);
        Assert.Empty(launch.Cookies);
        Assert.Contains("two-factor", launch.Notice);
    }

    [Theory]
    [InlineData(VCenterPage, "vCenter")]
    [InlineData(EsxiPage, "ESXi")]
    public async Task VSphere_OpensTheClientAndFillsTheLogin(string page, string product)
    {
        var fake = new FakeApp().On("GET /", 200, page);
        using var client = new ServerConsoleClient(new Uri("https://vc-01.example.invalid/"), fake);

        var launch = await client.PrepareWebAppAsync("administrator@vsphere.local", "secret");

        Assert.Equal("https://vc-01.example.invalid/ui/", launch.Url.AbsoluteUri);
        Assert.True(launch.FillLogin);
        Assert.Empty(launch.Cookies);
        Assert.Equal(product, launch.Product);
        Assert.DoesNotContain(fake.Requests, r => r.StartsWith("POST")); // the password only goes into the page's own form
    }

    [Fact]
    public async Task OtherApp_FollowsRedirectsOnTheSameServerOnly()
    {
        var fake = new FakeApp()
            .On("GET /", 302, "", r => r.Headers.Location = new Uri("/login", UriKind.Relative))
            .On("GET /login", 302, "", r => r.Headers.Location = new Uri("https://elsewhere.example.invalid/"));
        using var client = new ServerConsoleClient(new Uri("https://nas-01.example.invalid/"), fake);

        var launch = await client.PrepareWebAppAsync("admin", "secret");

        Assert.Equal(["GET /", "GET /login"], fake.Requests);
        Assert.Equal("https://nas-01.example.invalid/", launch.Url.AbsoluteUri);
        Assert.True(launch.FillLogin);
    }

    [Fact]
    public async Task Unreachable_OnPort443_MentionsProxmoxPort()
    {
        var fake = new FakeApp { Fail = new HttpRequestException("No connection could be made") };
        using var client = new ServerConsoleClient(new Uri("https://pve-01.example.invalid/"), fake);

        var ex = await Assert.ThrowsAsync<BmcException>(() => client.PrepareWebAppAsync("root", "secret"));

        Assert.Equal(BmcFailure.Unreachable, ex.Failure);
        Assert.Contains("8006", ex.Message);
    }

    [Theory]
    [InlineData("admin", "p\"ss'</script>\\n")]
    [InlineData("__LOGIN__", "x LINE-SEPARATOR `${x}`")]
    public void FillScript_CarriesTheLoginAsPlainStrings(string user, string password)
    {
        password = password.Replace("LINE-SEPARATOR", ((char)0x2028).ToString());
        var script = WebApps.FillLoginScript(user, password);
        var start = script.IndexOf("const [user, pass] = [", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var literal = script[(start + "const [user, pass] = ".Length)..(script.IndexOf("];", start, StringComparison.Ordinal) + 1)];
        // The array literal is plain JSON: it reads back as exactly the two values.
        Assert.Equal([user, password], JsonSerializer.Deserialize<string[]>(literal));
        Assert.DoesNotContain("</script>", script);
        Assert.DoesNotContain((char)0x2028, script); // a line break inside a JS string would end it
    }

    private sealed class FakeApp : HttpMessageHandler
    {
        private readonly Dictionary<string, (int Status, string Body, Action<HttpResponseMessage>? Adjust)> _routes = new();

        public List<string> Requests { get; } = new();
        public Dictionary<string, string> Bodies { get; } = new();
        public Exception? Fail { get; init; }

        public FakeApp On(string route, int status, string body, Action<HttpResponseMessage>? adjust = null)
        {
            _routes[route] = (status, body, adjust);
            return this;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Fail is not null) throw Fail;
            var key = $"{request.Method} {request.RequestUri!.PathAndQuery}";
            Requests.Add(key);
            if (request.Content is not null) Bodies[key] = await request.Content.ReadAsStringAsync(cancellationToken);
            if (!_routes.TryGetValue(key, out var route)) return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("") };
            var response = new HttpResponseMessage((HttpStatusCode)route.Status) { Content = new StringContent(route.Body, Encoding.UTF8, "text/html") };
            route.Adjust?.Invoke(response);
            return response;
        }
    }
}

using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SimpleSSH.Core.Bmc;
using SimpleSSH.Core.Models;

namespace SimpleSSH.Tests;

public class ServerConsoleTests
{
    // Trimmed from what real controllers return at /redfish/v1/ without logging in.
    private const string Ilo4Root = """
        {"@odata.id":"/redfish/v1/","RedfishVersion":"1.0.0","Name":"HP RESTful Root Service",
         "Oem":{"Hp":{"Manager":[{"ManagerFirmwareVersion":"2.82","ManagerType":"iLO 4"}]}},
         "SessionService":{"@odata.id":"/redfish/v1/SessionService/"}}
        """;

    private const string Ilo5Root = """
        {"@odata.id":"/redfish/v1/","RedfishVersion":"1.6.0","Vendor":"HPE",
         "Oem":{"Hpe":{"Manager":[{"ManagerFirmwareVersion":"3.10","ManagerType":"iLO 5"}]}},
         "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions/"}}}
        """;

    private const string IdracRoot = """
        {"@odata.id":"/redfish/v1","RedfishVersion":"1.17.0","Product":"Integrated Dell Remote Access Controller",
         "Oem":{"Dell":{"ServiceTag":"ABC1234"}},"Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}}}
        """;

    private const string OtherRoot = """{"@odata.id":"/redfish/v1/","RedfishVersion":"1.8.0","Vendor":"Supermicro","Product":"X12"}""";

    [Fact]
    public void ServiceRoot_TellsTheControllerApart()
    {
        Assert.Equal(new BmcInfo(BmcKind.Ilo, "iLO 4", "2.82"), BmcInfo.FromServiceRoot(Ilo4Root));
        Assert.Equal(new BmcInfo(BmcKind.Ilo, "iLO 5", "3.10"), BmcInfo.FromServiceRoot(Ilo5Root));
        Assert.Equal(BmcKind.Idrac, BmcInfo.FromServiceRoot(IdracRoot)!.Kind);
        Assert.Equal(BmcKind.Other, BmcInfo.FromServiceRoot(OtherRoot)!.Kind);
        Assert.Null(BmcInfo.FromServiceRoot("<html>login</html>"));
        Assert.Null(BmcInfo.FromServiceRoot("""{"hello":"world"}"""));
    }

    [Theory]
    [InlineData("iLO Advanced", false)]
    [InlineData("iLO Standard", true)]
    [InlineData("iLO Standard Blade Edition", true)]
    [InlineData("iLO Advanced Premium Security Edition", false)]
    public void IloStandardLicence_IsNoticed(string license, bool standard)
    {
        var json = new JsonObject { ["Oem"] = new JsonObject { ["Hpe"] = new JsonObject { ["License"] = new JsonObject { ["LicenseString"] = license } } } };
        Assert.Equal(standard, ServerConsoleClient.IloLicenseIsStandard(json.ToJsonString()));
        Assert.False(ServerConsoleClient.IloLicenseIsStandard("{}"));
    }

    [Theory]
    [InlineData("iDRAC9 Enterprise License", "14G Monolithic", false)]
    [InlineData("iDRAC9 Datacenter License", "15G Monolithic", false)]
    [InlineData("iDRAC9 Express License", "14G Monolithic", true)]
    [InlineData("iDRAC9 Basic License", "16G Monolithic", true)]
    [InlineData("iDRAC9 Express for Blades", "14G Modular", false)] // blades include the console
    public void IdracLicence_DecidesConsoleOrWebPage(string license, string model, bool lacks)
    {
        var licenses = JsonNode.Parse($$"""{"Members":[{"Description":"{{license}}","Id":"x"}]}""");
        Assert.Equal(lacks, ServerConsoleClient.IdracLacksConsoleLicense(licenses, model));
    }

    [Fact]
    public void IdracLicence_UnknownMeansTryTheConsole()
    {
        Assert.False(ServerConsoleClient.IdracLacksConsoleLicense(null, "14G Monolithic"));
        Assert.False(ServerConsoleClient.IdracLacksConsoleLicense(JsonNode.Parse("""{"Members":[]}"""), null));
    }

    [Theory]
    [InlineData("7.00.00.183", "iDRAC 9")]
    [InlineData("4.40.00.00", "iDRAC 9")]
    [InlineData("2.83.83.83", "iDRAC 8")]
    [InlineData(null, "iDRAC")]
    public void IdracGeneration_FromFirmware(string? firmware, string product) =>
        Assert.Equal(product, ServerConsoleClient.IdracProduct(null, firmware));

    [Fact]
    public void Addresses_AreBuiltSafely()
    {
        Assert.Equal("https://ilo.example.com/", ServerConsoleClient.BuildBaseUri(" ilo.example.com ", 443).AbsoluteUri);
        Assert.Equal("https://10.0.0.5:8443/", ServerConsoleClient.BuildBaseUri("10.0.0.5", 8443).AbsoluteUri);
        Assert.Equal("https://[fd00::5]/", ServerConsoleClient.BuildBaseUri("fd00::5", 443).AbsoluteUri);

        var url = ServerConsoleClient.IdracConsoleUrl(new Uri("https://10.0.0.6/"), "ad min", "t&u", "p=w%");
        Assert.Equal("https://10.0.0.6/console?username=ad%20min&tempUsername=t%26u&tempPassword=p%3Dw%25", url.AbsoluteUri);
    }

    [Fact]
    public void Fingerprint_IsSha256Base64LikeSsh()
    {
        var fp = ServerConsoleClient.Fingerprint(Encoding.ASCII.GetBytes("abc"));
        Assert.Equal("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0", fp);
    }

    // ------------------------------------------------------------------ whole flows against a fake controller

    [Fact]
    public async Task Ilo_OpensTheHtml5Console_WithTheSession()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, Ilo4Root)
            .On("POST /redfish/v1/SessionService/Sessions/", 201, "{}", r =>
            {
                r.Headers.Add("X-Auth-Token", "0123abcd");
                r.Headers.Location = new Uri("https://ilo.test/redfish/v1/SessionService/Sessions/admin0001/");
            })
            .On("GET /redfish/v1/Managers/1/", 200, """{"Oem":{"Hp":{"License":{"LicenseString":"iLO Advanced"}}}}""")
            .On("GET /irc.html", 200, "<html/>")
            .On("DELETE /redfish/v1/SessionService/Sessions/admin0001/", 200, "{}");
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);

        var launch = await client.PrepareAsync("Administrator", "pw");

        Assert.Equal("https://ilo.test/irc.html?token=0123abcd", launch.Url.AbsoluteUri);
        Assert.Equal(
            new Dictionary<string, string>
            {
                ["sessionKey"] = "0123abcd",
                ["ircSessionKey"] = "0123abcd",
                ["ircLocation"] = "https://ilo.test/redfish/v1/SessionService/Sessions/admin0001/",
            },
            launch.Cookies.ToDictionary(k => k.Key, k => k.Value));
        Assert.False(launch.WebPageOnly);
        Assert.Null(launch.Notice);
        Assert.Equal("iLO 4", launch.Product);
        var login = JsonNode.Parse(fake.Bodies["POST /redfish/v1/SessionService/Sessions/"])!;
        Assert.Equal("Administrator", (string?)login["UserName"]);
        Assert.Equal("0123abcd", fake.Headers["GET /irc.html"]["X-Auth-Token"]);

        await client.SignOutAsync();
        Assert.Contains("DELETE /redfish/v1/SessionService/Sessions/admin0001/", fake.Requests);
    }

    [Fact]
    public async Task Ilo_WrongPassword_IsABadLogin()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, Ilo5Root)
            .On("POST /redfish/v1/SessionService/Sessions/", 401, """{"error":{"code":"iLO.0.10.ExtendedInfo"}}""");
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);
        var ex = await Assert.ThrowsAsync<BmcException>(() => client.PrepareAsync("Administrator", "nope"));
        Assert.Equal(BmcFailure.BadLogin, ex.Failure);
    }

    [Fact]
    public async Task Ilo_OldFirmwareAndStandardLicence_OpenTheWebPageSignedIn()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, Ilo4Root)
            .On("POST /redfish/v1/SessionService/Sessions/", 201, "{}", r => r.Headers.Add("X-Auth-Token", "tok"))
            .On("GET /redfish/v1/Managers/1/", 200, """{"Oem":{"Hp":{"License":{"LicenseString":"iLO Standard"}}}}""")
            .On("GET /irc.html", 404, "");
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);
        var launch = await client.PrepareAsync("Administrator", "pw");
        Assert.True(launch.WebPageOnly);
        Assert.Equal("https://ilo.test/index.html", launch.Url.AbsoluteUri);
        Assert.Contains(new KeyValuePair<string, string>("sessionKey", "tok"), launch.Cookies);
        Assert.Contains("firmware", launch.Notice);
    }

    [Fact]
    public async Task Ilo_StandardLicence_StillOpensTheConsole_WithANote()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, Ilo5Root)
            .On("POST /redfish/v1/SessionService/Sessions/", 201, "{}", r => r.Headers.Add("X-Auth-Token", "tok"))
            .On("GET /redfish/v1/Managers/1/", 200, """{"Oem":{"Hpe":{"License":{"LicenseString":"iLO Standard"}}}}""")
            .On("GET /irc.html", 200, "<html/>");
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);
        var launch = await client.PrepareAsync("Administrator", "pw");
        Assert.False(launch.WebPageOnly);
        Assert.Contains("Standard licence", launch.Notice);
    }

    private const string CardService = "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService";

    [Fact]
    public async Task Idrac_OpensTheConsole_WithOneTimeLogin()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, IdracRoot)
            .On("GET " + CardService, 200, """{"Actions":{"#DelliDRACCardService.GetKVMSession":{"target":"x"}}}""")
            .On("GET /redfish/v1/Managers/iDRAC.Embedded.1", 200, """{"FirmwareVersion":"7.00.00.183","Model":"14G Monolithic"}""")
            .On("GET /redfish/v1/LicenseService/Licenses?$expand=*($levels=1)", 200, """{"Members":[{"Description":"iDRAC9 Enterprise License"}]}""")
            .On("POST " + CardService + "/Actions/DelliDRACCardService.GetKVMSession", 200, """{"TempUsername":"TU1","TempPassword":"TP2"}""");
        using var client = new ServerConsoleClient(new Uri("https://idrac.test/"), fake);

        var launch = await client.PrepareAsync("root", "calvin");

        Assert.Equal("https://idrac.test/console?username=root&tempUsername=TU1&tempPassword=TP2", launch.Url.AbsoluteUri);
        Assert.Equal("iDRAC 9", launch.Product);
        Assert.False(launch.WebPageOnly);
        Assert.Empty(launch.Cookies);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("root:calvin")), fake.Headers["GET " + CardService]["Authorization"]);
    }

    [Fact]
    public async Task Idrac_WrongPassword_IsABadLogin()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, IdracRoot)
            .On("GET " + CardService, 401, "");
        using var client = new ServerConsoleClient(new Uri("https://idrac.test/"), fake);
        var ex = await Assert.ThrowsAsync<BmcException>(() => client.PrepareAsync("root", "nope"));
        Assert.Equal(BmcFailure.BadLogin, ex.Failure);
    }

    [Fact]
    public async Task Idrac_WithoutTheAction_AsksToLogInOnItsConsolePage()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, IdracRoot)
            .On("GET " + CardService, 404, "")
            .On("GET /redfish/v1/Managers/iDRAC.Embedded.1", 200, """{"FirmwareVersion":"2.83.83.83"}""");
        using var client = new ServerConsoleClient(new Uri("https://idrac.test/"), fake);
        var launch = await client.PrepareAsync("root", "calvin");
        Assert.True(launch.WebPageOnly);
        Assert.Equal("https://idrac.test/console", launch.Url.AbsoluteUri);
        Assert.Equal("iDRAC 8", launch.Product);
    }

    [Fact]
    public async Task Idrac_WithoutConsoleLicence_OpensTheWebPage()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, IdracRoot)
            .On("GET " + CardService, 200, """{"Actions":{"#DelliDRACCardService.GetKVMSession":{}}}""")
            .On("GET /redfish/v1/Managers/iDRAC.Embedded.1", 200, """{"FirmwareVersion":"7.00.00.183","Model":"14G Monolithic"}""")
            .On("GET /redfish/v1/LicenseService/Licenses?$expand=*($levels=1)", 200, """{"Members":[{"Description":"iDRAC9 Express License"}]}""");
        using var client = new ServerConsoleClient(new Uri("https://idrac.test/"), fake);
        var launch = await client.PrepareAsync("root", "calvin");
        Assert.True(launch.WebPageOnly);
        Assert.Contains("licence", launch.Notice);
        Assert.DoesNotContain(fake.Requests, r => r.Contains("GetKVMSession", StringComparison.Ordinal) && r.StartsWith("POST", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Idrac_RefusedConsoleLogin_ExplainsWhy()
    {
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, IdracRoot)
            .On("GET " + CardService, 200, """{"Actions":{"#DelliDRACCardService.GetKVMSession":{}}}""")
            .On("POST " + CardService + "/Actions/DelliDRACCardService.GetKVMSession", 400,
                """{"error":{"@Message.ExtendedInfo":[{"Message":"Virtual Console is disabled."}]}}""");
        using var client = new ServerConsoleClient(new Uri("https://idrac.test/"), fake);
        var launch = await client.PrepareAsync("root", "calvin");
        Assert.True(launch.WebPageOnly);
        Assert.Contains("Virtual Console is disabled", launch.Notice);
    }

    [Fact]
    public async Task SomethingElse_OpensItsWebPage()
    {
        var fake = new FakeController().On("GET /redfish/v1/", 200, OtherRoot);
        using var client = new ServerConsoleClient(new Uri("https://bmc.test/"), fake);
        var launch = await client.PrepareAsync("u", "p");
        Assert.True(launch.WebPageOnly);
        Assert.Equal("https://bmc.test/", launch.Url.AbsoluteUri);

        var noRedfish = new FakeController().On("GET /redfish/v1/", 404, "");
        using var client2 = new ServerConsoleClient(new Uri("https://web.test/"), noRedfish);
        Assert.True((await client2.PrepareAsync("u", "p")).WebPageOnly);
    }

    [Fact]
    public async Task Unreachable_SaysSo()
    {
        var fake = new FakeController { Fail = new HttpRequestException("No such host is known.") };
        using var client = new ServerConsoleClient(new Uri("https://gone.test/"), fake);
        var ex = await Assert.ThrowsAsync<BmcException>(() => client.PrepareAsync("u", "p"));
        Assert.Equal(BmcFailure.Unreachable, ex.Failure);
        Assert.Contains("gone.test", ex.Message);
    }

    [Fact]
    public void ConsoleConnections_SaveTheirTypeAndUse443()
    {
        var c = new Connection { Protocol = ConnectionProtocol.Console, Host = "ilo-01", Port = 443 };
        var json = JsonSerializer.Serialize(c);
        Assert.Contains("\"Protocol\":\"Console\"", json);
        var back = JsonSerializer.Deserialize<Connection>(json)!;
        Assert.True(back.IsConsole);
        Assert.False(back.IsSsh);
        Assert.Equal("ilo-01", back.Endpoint);
        Assert.Equal(443, Connection.DefaultPortFor(ConnectionProtocol.Console));
        Assert.True(new Connection().IsSsh);
    }

    /// <summary>Answers "METHOD /path?query" with canned responses and records what was sent.</summary>
    [Fact]
    public async Task Ilo_NeverSendsThePasswordOrTokenToAnotherHost()
    {
        var root = Ilo5Root.Replace("\"/redfish/v1/SessionService/Sessions/\"}}}", "\"https://evil.test/collect/\"}}}");
        Assert.Contains("evil.test", root);
        var fake = new FakeController()
            .On("GET /redfish/v1/", 200, root)
            .On("POST /redfish/v1/SessionService/Sessions/", 201, "{}", r =>
            {
                r.Headers.Add("X-Auth-Token", "tok");
                r.Headers.Location = new Uri("https://evil.test:8443/redfish/v1/SessionService/Sessions/x/");
            })
            .On("GET /irc.html", 200, "<html/>");
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);

        var launch = await client.PrepareAsync("Administrator", "pw");
        await client.SignOutAsync();

        Assert.All(fake.Urls, u => Assert.Equal("ilo.test", u.Host));
        Assert.Contains("POST /redfish/v1/SessionService/Sessions/", fake.Requests); // the standard address on this iLO
        Assert.DoesNotContain(launch.Cookies, c => c.Key == "ircLocation");
        Assert.Equal("https://ilo.test/", launch.Url.GetLeftPart(UriPartial.Authority) + "/");
    }

    [Theory]
    [InlineData("/redfish/v1/x", true)]
    [InlineData("https://ilo.test/redfish/v1/x", true)]
    [InlineData("https://ILO.test:443/redfish/v1/x", true)]
    [InlineData("https://ilo.test:8443/redfish/v1/x", false)]
    [InlineData("http://ilo.test/redfish/v1/x", false)]
    [InlineData("https://other.test/redfish/v1/x", false)]
    [InlineData("//other.test/x", false)]
    [InlineData("", false)]
    public void OnController_AcceptsOnlyThisController(string address, bool accepted)
    {
        using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), new FakeController());
        Assert.Equal(accepted, client.OnController(address) is not null);
    }

    [Theory]
    [InlineData("https://ilo.test/js/iLO.js", true)]
    [InlineData("https://ilo.test/irc.html?token=abc", true)]
    [InlineData("https://ilo.test/font/x.WOFF", true)]
    [InlineData("https://ilo.test/redfish/v1/", false)]
    [InlineData("https://ilo.test/json/login_session", false)]
    [InlineData("https://ilo.test/lang/en/strings.json", false)]
    [InlineData("http://ilo.test/js/iLO.js", false)]
    public void PageFiles_OnlyStaticOnesAreKept(string url, bool kept) =>
        Assert.Equal(kept, ConsoleFileCache.IsStaticFile(new Uri(url)));

    [Fact]
    public void PageFiles_AreKeptPerControllerWithoutTheQuery()
    {
        var folder = Path.Combine(Path.GetTempPath(), "simplessh-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var cache = new ConsoleFileCache(folder);
            cache.Put(new Uri("https://ilo.test/irc.html?token=secret-session-key"), new CachedFile("\"e1\"", null, "Content-Type: text/html", "<html/>"u8.ToArray()));
            cache.Put(new Uri("https://ilo.test/nothing-to-check.js"), new CachedFile(null, null, "Content-Type: text/javascript", "x"u8.ToArray()));

            var kept = cache.Get(new Uri("https://ilo.test/irc.html?token=other"));
            Assert.NotNull(kept);
            Assert.Equal("\"e1\"", kept.ETag);
            Assert.Equal("<html/>", Encoding.UTF8.GetString(kept.Body));
            Assert.Null(cache.Get(new Uri("https://ilo.test:8443/irc.html")));
            Assert.Null(cache.Get(new Uri("https://other.test/irc.html")));
            Assert.Null(cache.Get(new Uri("https://ilo.test/nothing-to-check.js"))); // nothing to ask the controller with: not kept
            Assert.Single(Directory.GetFiles(folder));
            Assert.DoesNotContain("secret-session-key", File.ReadAllText(Directory.GetFiles(folder)[0]));
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, true);
        }
    }

    [Fact]
    public async Task PageFiles_ComeFromTheKeptCopyWhenUnchanged()
    {
        var folder = Path.Combine(Path.GetTempPath(), "simplessh-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var cache = new ConsoleFileCache(folder);
            var fake = new FakeController().On("GET /js/iLO.js", 200, "first", r =>
            {
                r.Headers.TryAddWithoutValidation("ETag", "W/\"v1\"");
                r.Headers.TryAddWithoutValidation("Content-Security-Policy", "script-src 'self'");
                r.Headers.TryAddWithoutValidation("Set-Cookie", "sessionKey=secret");
            });
            using var client = new ServerConsoleClient(new Uri("https://ilo.test/"), fake);
            var url = new Uri("https://ilo.test/js/iLO.js");

            var first = await client.GetPageFileAsync(url, cache);
            Assert.NotNull(first);
            Assert.Equal("first", Encoding.UTF8.GetString(first.Body));
            Assert.Contains("Content-Security-Policy: script-src 'self'", first.Headers);
            Assert.Contains("Content-Type: application/json", first.Headers);
            Assert.DoesNotContain("secret", first.Headers);
            Assert.False(fake.Headers["GET /js/iLO.js"].ContainsKey("If-None-Match"));

            fake.On("GET /js/iLO.js", 304, "");
            var second = await client.GetPageFileAsync(url, cache);
            Assert.Equal("W/\"v1\"", fake.Headers["GET /js/iLO.js"]["If-None-Match"]);
            Assert.Equal("first", Encoding.UTF8.GetString(second!.Body));
            Assert.Contains("Content-Security-Policy", second.Headers);

            fake.On("GET /js/iLO.js", 200, "changed", r => r.Headers.TryAddWithoutValidation("ETag", "\"v2\""));
            Assert.Equal("changed", Encoding.UTF8.GetString((await client.GetPageFileAsync(url, cache))!.Body));
            Assert.Equal("\"v2\"", cache.Get(url)!.ETag);

            var asked = fake.Requests.Count;
            Assert.Null(await client.GetPageFileAsync(new Uri("https://other.test/js/iLO.js"), cache)); // never another host
            Assert.Null(await client.GetPageFileAsync(new Uri("https://ilo.test/redfish/v1/"), cache)); // not a static file
            Assert.Equal(asked, fake.Requests.Count);
            Assert.Null(await client.GetPageFileAsync(new Uri("https://ilo.test/js/missing.js"), cache)); // 404: the browser asks itself
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, true);
        }
    }

    private sealed class FakeController : HttpMessageHandler
    {
        private readonly Dictionary<string, (int Status, string Body, Action<HttpResponseMessage>? Adjust)> _routes = new();

        public List<string> Requests { get; } = new();
        public List<Uri> Urls { get; } = new();
        public Dictionary<string, string> Bodies { get; } = new();
        public Dictionary<string, Dictionary<string, string>> Headers { get; } = new();
        public Exception? Fail { get; init; }

        public FakeController On(string route, int status, string body, Action<HttpResponseMessage>? adjust = null)
        {
            _routes[route] = (status, body, adjust);
            return this;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Fail is not null) throw Fail;
            var key = $"{request.Method} {Uri.UnescapeDataString(request.RequestUri!.PathAndQuery)}";
            Requests.Add(key);
            Urls.Add(request.RequestUri!);
            if (request.Content is not null) Bodies[key] = await request.Content.ReadAsStringAsync(cancellationToken);
            Headers[key] = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value));
            if (!_routes.TryGetValue(key, out var route)) return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("") };
            var response = new HttpResponseMessage((HttpStatusCode)route.Status) { Content = new StringContent(route.Body, Encoding.UTF8, "application/json") };
            route.Adjust?.Invoke(response);
            return response;
        }
    }
}

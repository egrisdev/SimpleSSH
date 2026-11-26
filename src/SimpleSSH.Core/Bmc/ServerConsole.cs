using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SimpleSSH.Core.Bmc;

/// <summary>Which kind of server management controller answered.</summary>
public enum BmcKind
{
    /// <summary>Something else (or a controller without the API SimpleSSH needs): only its web page is opened.</summary>
    Other,
    Ilo,
    Idrac,
}

/// <summary>What the Redfish service root (<c>/redfish/v1/</c>, readable without logging in) says about the controller.</summary>
public sealed record BmcInfo(BmcKind Kind, string Product, string? Firmware)
{
    /// <summary>Reads the service root JSON. Returns null when it isn't Redfish at all.</summary>
    public static BmcInfo? FromServiceRoot(string json)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(json); }
        catch (JsonException) { return null; }
        if (root is not JsonObject obj || obj["@odata.id"] is null && obj["RedfishVersion"] is null) return null;

        // HPE: Oem.Hp (iLO 4) or Oem.Hpe (iLO 5 and later) lists the manager type and firmware.
        var hpe = obj["Oem"]?["Hpe"] ?? obj["Oem"]?["Hp"];
        if (hpe is not null)
        {
            var manager = (hpe["Manager"] as JsonArray)?.FirstOrDefault();
            var type = Str(manager?["ManagerType"]);
            var firmware = Str(manager?["ManagerFirmwareVersion"]);
            return new BmcInfo(BmcKind.Ilo, string.IsNullOrWhiteSpace(type) ? "iLO" : type.Trim(), firmware);
        }

        var product = Str(obj["Product"]) ?? "";
        var vendor = Str(obj["Vendor"]) ?? "";
        if (obj["Oem"]?["Dell"] is not null || product.Contains("Dell Remote Access", StringComparison.OrdinalIgnoreCase) ||
            vendor.Equals("Dell", StringComparison.OrdinalIgnoreCase))
            return new BmcInfo(BmcKind.Idrac, "iDRAC", null);

        if (vendor.Contains("HPE", StringComparison.OrdinalIgnoreCase) || product.Contains("iLO", StringComparison.OrdinalIgnoreCase))
            return new BmcInfo(BmcKind.Ilo, "iLO", null);

        return new BmcInfo(BmcKind.Other, string.IsNullOrWhiteSpace(product) ? "Redfish" : product.Trim(), null);
    }

    internal static string? Str(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
}

/// <summary>What to open in the console tab.</summary>
public sealed class ConsoleLaunch
{
    public required Uri Url { get; init; }

    /// <summary>Cookies to set for <see cref="Url"/>'s host first (e.g. the iLO session).</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Cookies { get; init; } = Array.Empty<KeyValuePair<string, string>>();

    /// <summary>"iLO 4", "iDRAC"… for the tab header.</summary>
    public required string Product { get; init; }

    /// <summary>True when this is the controller's web page rather than its console (see <see cref="Notice"/>).</summary>
    public bool WebPageOnly { get; init; }

    /// <summary>A short note to show above the console, or null.</summary>
    public string? Notice { get; init; }

    /// <summary>Fill in and send the page's login form (once): for web apps SimpleSSH can't sign in to by itself.</summary>
    public bool FillLogin { get; init; }
}

public enum BmcFailure
{
    /// <summary>No answer, DNS failure, refused, timed out.</summary>
    Unreachable,
    /// <summary>Wrong username or password (or the account may not log in).</summary>
    BadLogin,
    /// <summary>The controller answered but refused for another reason (message says why).</summary>
    Refused,
}

public sealed class BmcException : Exception
{
    public BmcException(BmcFailure failure, string message, Exception? inner = null) : base(message, inner) => Failure = failure;

    public BmcFailure Failure { get; }
}

/// <summary>The controller's TLS certificate isn't trusted yet (self-signed, as most are): ask the user, then try again.</summary>
public sealed class BmcCertificateException : Exception
{
    public BmcCertificateException(string fingerprint, string subject, DateTime notAfter)
        : base("The controller's certificate isn't trusted yet.")
    {
        Fingerprint = fingerprint;
        Subject = subject;
        NotAfter = notAfter;
    }

    /// <summary>SHA-256 of the certificate, base64 without padding (like SSH fingerprints).</summary>
    public string Fingerprint { get; }

    public string Subject { get; }

    public DateTime NotAfter { get; }
}

/// <summary>
/// Opens an HPE iLO or Dell iDRAC straight into its remote console, the way HPE OneView or Dell OpenManage do:
/// logs in through the controller's Redfish API, then hands the browser a ready session.
/// <list type="bullet">
/// <item>iLO 4, 5, 6 (and later): a Redfish session; its key is also the web session key, so the standalone HTML5
/// console <c>/irc.html</c> opens with it (cookies <c>sessionKey</c>, <c>ircSessionKey</c> and <c>ircLocation</c>,
/// and <c>?token=</c> for the page).</item>
/// <item>iDRAC 9: the <c>DelliDRACCardService.GetKVMSession</c> action gives one-time console credentials for
/// <c>/console?username=&amp;tempUsername=&amp;tempPassword=</c> (as in Dell's own Redfish scripts).</item>
/// <item>Anything else, or a controller that can't do the above: its web page, with a plain explanation.</item>
/// </list>
/// Nothing is changed on the controller: no settings, power or media actions.
/// </summary>
public sealed partial class ServerConsoleClient : IDisposable
{
    public const string CertificateKeyType = "tls-certificate";
    private const string KvmAction = "#DelliDRACCardService.GetKVMSession";
    private const string DellCardService = "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService";

    private readonly HttpClient _http;
    private (string Fingerprint, string Subject, DateTime NotAfter)? _rejected;
    private string? _iloSession;
    private string? _iloToken;

    /// <param name="host">Host name or IP address.</param>
    /// <param name="port">HTTPS port (443).</param>
    /// <param name="isTrusted">Is a certificate with this SHA-256 fingerprint trusted for this host? Only asked when Windows doesn't trust it.</param>
    public ServerConsoleClient(string host, int port, Func<string, bool> isTrusted)
    {
        BaseUri = BuildBaseUri(host, port);
        var handler = new SocketsHttpHandler
        {
            UseCookies = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            // One connection, one request at a time: that's what iLOs answer fastest (a few milliseconds per file). Each
            // extra connection costs their slow processors a TLS handshake (0.2-0.7 s), and requests on two connections
            // at once each wait about 0.2 s.
            MaxConnectionsPerServer = 1,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    if (errors == SslPolicyErrors.None) return true;
                    if (cert is null) return false;
                    using var x509 = new X509Certificate2(cert);
                    var fingerprint = Fingerprint(x509);
                    if (isTrusted(fingerprint)) return true;
                    _rejected = (fingerprint, x509.Subject, x509.NotAfter);
                    return false;
                },
            },
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>For tests: talks to <paramref name="handler"/> instead of the network.</summary>
    public ServerConsoleClient(Uri baseUri, HttpMessageHandler handler)
    {
        BaseUri = baseUri;
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public Uri BaseUri { get; }

    public static Uri BuildBaseUri(string host, int port)
    {
        host = host.Trim();
        if (host.Contains(':') && !host.StartsWith('[')) host = $"[{host}]"; // IPv6
        return new UriBuilder(Uri.UriSchemeHttps, host, port == 443 ? -1 : port).Uri;
    }

    /// <summary>SHA-256 of the DER certificate, base64 without padding.</summary>
    public static string Fingerprint(X509Certificate2 cert) => Fingerprint(cert.RawData);

    public static string Fingerprint(byte[] der) => Convert.ToBase64String(SHA256.HashData(der)).TrimEnd('=');

    /// <summary>Logs in and works out the best thing to open. Throws <see cref="BmcException"/> or <see cref="BmcCertificateException"/>.</summary>
    public async Task<ConsoleLaunch> PrepareAsync(string username, string password, CancellationToken ct = default)
    {
        var (status, rootJson) = await SendAsync(HttpMethod.Get, "/redfish/v1/", null, ct);
        var info = status == HttpStatusCode.OK ? BmcInfo.FromServiceRoot(rootJson) : null;
        if (info is null || info.Kind == BmcKind.Other)
        {
            return WebPage(info?.Product ?? "Web",
                "Opened the web page: going straight to the console works with HPE iLO and Dell iDRAC.");
        }
        return info.Kind == BmcKind.Ilo
            ? await PrepareIloAsync(info, rootJson, username, password, ct)
            : await PrepareIdracAsync(username, password, ct);
    }

    // ------------------------------------------------------------------ HPE iLO

    private async Task<ConsoleLaunch> PrepareIloAsync(BmcInfo info, string rootJson, string username, string password, CancellationToken ct)
    {
        await SignOutAsync(); // a reconnect replaces the earlier session

        // The password only ever goes to this controller, whatever address its service root names.
        var sessions = OnController(BmcInfo.Str(JsonNode.Parse(rootJson)?["Links"]?["Sessions"]?["@odata.id"]))
                       ?? new Uri(BaseUri, "/redfish/v1/SessionService/Sessions/");
        var login = new JsonObject { ["UserName"] = username, ["Password"] = password }.ToJsonString();
        using var request = new HttpRequestMessage(HttpMethod.Post, sessions)
        {
            Content = new StringContent(login, Encoding.UTF8, "application/json"),
        };
        using var response = await SendRawAsync(request, ct);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.BadRequest)
            throw new BmcException(BmcFailure.BadLogin, "The iLO didn't accept the username or password.");
        var token = response.Headers.TryGetValues("X-Auth-Token", out var tokens) ? tokens.FirstOrDefault() : null;
        if (!response.IsSuccessStatusCode || string.IsNullOrEmpty(token))
            throw new BmcException(BmcFailure.Refused, $"The iLO didn't open a session ({(int)response.StatusCode} {response.ReasonPhrase}). {await ErrorTextAsync(response, ct)}".Trim());
        _iloToken = token;
        _iloSession = OnController(response.Headers.Location?.ToString()) is not null ? response.Headers.Location!.ToString() : null;

        // iLO 4 reads sessionKey; iLO 5's standalone console checks the session with ircSessionKey/ircLocation
        // (what its own web page sets before opening the console) and shows a login box without them.
        var cookie = new List<KeyValuePair<string, string>> { new("sessionKey", token), new("ircSessionKey", token) };
        if (_iloSession is not null) cookie.Add(new("ircLocation", _iloSession));
        var product = info.Product;

        string? notice = null;
        var (managerStatus, managerJson) = await SendAsync(HttpMethod.Get, "/redfish/v1/Managers/1/", token, ct, iloToken: true);
        if (managerStatus == HttpStatusCode.OK && IloLicenseIsStandard(managerJson))
            notice = "This iLO has a Standard licence, so its console may only show the server while it starts up (before the operating system loads). An iLO Advanced licence lifts that.";

        // iLO 4 firmware before the HTML5 console has no /irc.html: open its web page, signed in.
        var (ircStatus, _) = await SendAsync(HttpMethod.Get, "/irc.html", token, ct, iloToken: true);
        if (ircStatus == HttpStatusCode.NotFound)
        {
            return new ConsoleLaunch
            {
                Url = new Uri(BaseUri, "/index.html"),
                Cookies = cookie,
                Product = product,
                WebPageOnly = true,
                Notice = "This iLO's firmware has no HTML5 console, so its web page is open instead (signed in). Updating the iLO firmware adds it.",
            };
        }

        return new ConsoleLaunch
        {
            Url = new Uri(BaseUri, "/irc.html?token=" + Uri.EscapeDataString(token)),
            Cookies = cookie,
            Product = product,
            Notice = notice,
        };
    }

    /// <summary>"iLO Standard" (or "iLO Standard Blade Edition"); Advanced, Essentials, Scale-Out… include the console.</summary>
    public static bool IloLicenseIsStandard(string managerJson)
    {
        try
        {
            var oem = JsonNode.Parse(managerJson)?["Oem"];
            var license = BmcInfo.Str((oem?["Hpe"] ?? oem?["Hp"])?["License"]?["LicenseString"]);
            return license is not null && license.Contains("Standard", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Ends the iLO session opened for the console (when the tab closes). Never throws.</summary>
    /// <summary>An address from the controller, resolved against it; null if it points anywhere else (another host, port or scheme).</summary>
    internal Uri? OnController(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || !Uri.TryCreate(BaseUri, address, out var uri)) return null;
        return Uri.Compare(uri, BaseUri, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0 ? uri : null;
    }

    public async Task SignOutAsync()
    {
        var session = _iloSession;
        var token = _iloToken;
        _iloSession = _iloToken = null;
        if (session is null || token is null) return;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(BaseUri, session));
            request.Headers.Add("X-Auth-Token", token);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var _ = await _http.SendAsync(request, cts.Token);
        }
        catch
        {
            // The iLO ends idle sessions by itself.
        }
    }

    /// <summary>
    /// A static file of the console page (see <see cref="ConsoleFileCache"/>) over this client's connection, which is
    /// already open and checks the certificate the same way: the kept copy when the controller says it hasn't changed.
    /// Null when it isn't such a file or something else came back; the browser then asks for it itself.
    /// </summary>
    public async Task<CachedFile?> GetPageFileAsync(Uri url, ConsoleFileCache cache, CancellationToken ct = default)
    {
        if (!ConsoleFileCache.IsStaticFile(url) || OnController(url.AbsoluteUri) is null) return null;
        try
        {
            var kept = cache.Get(url);
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (kept?.ETag is { } etag) request.Headers.TryAddWithoutValidation("If-None-Match", etag);
            else if (kept?.LastModified is { } date) request.Headers.TryAddWithoutValidation("If-Modified-Since", date);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified) return kept;
            if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentEncoding.Count > 0 ||
                response.Content.Headers.ContentLength is { } length && !ConsoleFileCache.IsSmallEnough(length)) return null;
            var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var file = new CachedFile(Header(response, "ETag"), Header(response, "Last-Modified"), PageHeaders(response), body);
            if (response.Headers.CacheControl is not { NoStore: true }) cache.Put(url, file);
            return file;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or ObjectDisposedException)
        {
            return null;
        }
    }

    /// <summary>A response header as sent (embedded web servers don't always format ETags the way .NET parses them).</summary>
    private static string? Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) || response.Content.Headers.TryGetValues(name, out values)
            ? string.Join(", ", values).ReplaceLineEndings(" ")
            : null;

    private static string PageHeaders(HttpResponseMessage response)
    {
        var lines = ConsoleFileCache.KeptHeaders
            .Select(name => (Name: name, Value: Header(response, name)))
            .Where(h => !string.IsNullOrWhiteSpace(h.Value))
            .Select(h => $"{h.Name}: {h.Value}")
            .ToList();
        if (Header(response, "Content-Type") is null) lines.Insert(0, "Content-Type: application/octet-stream");
        return string.Join("\r\n", lines);
    }

    // ------------------------------------------------------------------ Dell iDRAC

    private async Task<ConsoleLaunch> PrepareIdracAsync(string username, string password, CancellationToken ct)
    {
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        var (status, serviceJson) = await SendAsync(HttpMethod.Get, DellCardService, basic, ct);
        if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new BmcException(BmcFailure.BadLogin, "The iDRAC didn't accept the username or password.");

        var manager = await GetJsonAsync("/redfish/v1/Managers/iDRAC.Embedded.1", basic, ct);
        var firmware = BmcInfo.Str(manager?["FirmwareVersion"]);
        var product = IdracProduct(BmcInfo.Str(manager?["Model"]), firmware);

        if (status != HttpStatusCode.OK || !HasAction(serviceJson, KvmAction))
            return LoginPage(product, "This iDRAC can't hand over a console login (that needs iDRAC 9 with current firmware), so it asks you to log in once here.");

        var licenses = await GetJsonAsync("/redfish/v1/LicenseService/Licenses?$expand=*($levels=1)", basic, ct);
        if (IdracLacksConsoleLicense(licenses, BmcInfo.Str(manager?["Model"])))
            return WebPage(product, "This iDRAC has no Enterprise or Datacenter licence, which rack and tower servers need for the virtual console. Its web page is open instead.");

        // The action wants a file name here (Dell's scripts pass this one); the certificate itself isn't needed.
        var body = new JsonObject { ["SessionTypeName"] = "idrac_cert_file.txt" }.ToJsonString();
        var (kvmStatus, kvmJson) = await SendAsync(HttpMethod.Post,
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession", basic, ct, body: body);
        if (kvmStatus is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new BmcException(BmcFailure.BadLogin, "This iDRAC account may not open the virtual console.");
        var kvm = TryParse(kvmJson);
        var tempUser = BmcInfo.Str(kvm?["TempUsername"]);
        var tempPassword = BmcInfo.Str(kvm?["TempPassword"]);
        if (kvmStatus != HttpStatusCode.OK || string.IsNullOrEmpty(tempUser) || string.IsNullOrEmpty(tempPassword))
            return LoginPage(product, "The iDRAC didn't hand over a console login" + Reason(RedfishMessage(kvmJson)) + ", so it asks you to log in once here.");

        return new ConsoleLaunch
        {
            Url = IdracConsoleUrl(BaseUri, username, tempUser, tempPassword),
            Product = product,
        };
    }

    public static Uri IdracConsoleUrl(Uri baseUri, string username, string tempUser, string tempPassword) =>
        new(baseUri, "/console?username=" + Uri.EscapeDataString(username) +
                     "&tempUsername=" + Uri.EscapeDataString(tempUser) +
                     "&tempPassword=" + Uri.EscapeDataString(tempPassword));

    /// <summary>"iDRAC 9" from firmware 3.x–7.x (14G–16G), "iDRAC 8" from 2.x; otherwise just "iDRAC".</summary>
    public static string IdracProduct(string? model, string? firmware)
    {
        var major = int.TryParse(firmware?.Split('.')[0], out var m) ? m : 0;
        return major switch
        {
            >= 3 and <= 7 => "iDRAC 9",
            2 => "iDRAC 8",
            >= 10 => "iDRAC 10",
            _ => "iDRAC",
        };
    }

    /// <summary>
    /// True only when the licence list is readable and has no Enterprise or Datacenter licence, on a server that
    /// isn't a blade (blades include the console).
    /// </summary>
    public static bool IdracLacksConsoleLicense(JsonNode? licenses, string? model)
    {
        if (model?.Contains("Modular", StringComparison.OrdinalIgnoreCase) == true) return false;
        if (licenses?["Members"] is not JsonArray members || members.Count == 0) return false;
        var names = members.Select(m => (BmcInfo.Str(m?["Description"]) ?? "") + " " + (BmcInfo.Str(m?["Id"]) ?? "")).ToList();
        if (names.All(string.IsNullOrWhiteSpace)) return false;
        return !names.Any(n => n.Contains("Enterprise", StringComparison.OrdinalIgnoreCase) ||
                               n.Contains("Datacenter", StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasAction(string json, string action)
    {
        var actions = TryParse(json)?["Actions"] as JsonObject;
        return actions?.ContainsKey(action) == true;
    }

    // ------------------------------------------------------------------ helpers

    private ConsoleLaunch WebPage(string product, string notice) =>
        new() { Url = BaseUri, Product = product, WebPageOnly = true, Notice = notice };

    private ConsoleLaunch LoginPage(string product, string notice) =>
        new() { Url = new Uri(BaseUri, "/console"), Product = product, WebPageOnly = true, Notice = notice };

    private static string Reason(string? message) => string.IsNullOrWhiteSpace(message) ? "" : $" ({message.Trim().TrimEnd('.')})";

    /// <summary>The first Redfish error message in a response body, if any.</summary>
    public static string? RedfishMessage(string json)
    {
        var node = TryParse(json);
        var info = (node?["error"]?["@Message.ExtendedInfo"] ?? node?["@Message.ExtendedInfo"]) as JsonArray;
        var message = BmcInfo.Str(info?.FirstOrDefault()?["Message"]) ?? BmcInfo.Str(node?["error"]?["message"]);
        return message;
    }

    private static JsonNode? TryParse(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonNode.Parse(json); }
        catch (JsonException) { return null; }
    }

    private async Task<JsonNode?> GetJsonAsync(string path, string basic, CancellationToken ct)
    {
        var (status, json) = await SendAsync(HttpMethod.Get, path, basic, ct);
        return status == HttpStatusCode.OK ? TryParse(json) : null;
    }

    private async Task<(HttpStatusCode Status, string Body)> SendAsync(HttpMethod method, string path, string? auth, CancellationToken ct,
        bool iloToken = false, string? body = null)
    {
        using var request = new HttpRequestMessage(method, new Uri(BaseUri, path));
        if (auth is not null)
        {
            if (iloToken)
            {
                request.Headers.Add("X-Auth-Token", auth);
                request.Headers.Add("Cookie", "sessionKey=" + auth);
            }
            else
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", auth);
            }
        }
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await SendRawAsync(request, ct);
        return (response.StatusCode, await response.Content.ReadAsStringAsync(ct));
    }

    private async Task<HttpResponseMessage> SendRawAsync(HttpRequestMessage request, CancellationToken ct, bool redfish = true)
    {
        if (redfish)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("OData-Version", "4.0");
        }
        _rejected = null;
        try
        {
            return await _http.SendAsync(request, ct);
        }
        catch (HttpRequestException) when (_rejected is { } cert)
        {
            throw new BmcCertificateException(cert.Fingerprint, cert.Subject, cert.NotAfter);
        }
        catch (HttpRequestException ex)
        {
            throw new BmcException(BmcFailure.Unreachable, $"Couldn't reach {BaseUri.Host}: {Plain(ex)}", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new BmcException(BmcFailure.Unreachable, $"{BaseUri.Host} didn't answer in time.", ex);
        }
    }

    private static string Plain(HttpRequestException ex)
    {
        var inner = ex.InnerException;
        while (inner?.InnerException is not null) inner = inner.InnerException;
        return (inner ?? ex).Message.TrimEnd('.') + ".";
    }

    private static async Task<string> ErrorTextAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try { return RedfishMessage(await response.Content.ReadAsStringAsync(ct)) ?? ""; }
        catch { return ""; }
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}

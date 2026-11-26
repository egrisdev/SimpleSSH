using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SimpleSSH.Core.Bmc;

/// <summary>Web apps SimpleSSH knows how to sign in to.</summary>
public enum WebAppKind
{
    /// <summary>Any other web app: its login form is filled in.</summary>
    Other,
    ProxmoxVe,
    ProxmoxBackup,
    VCenter,
    Esxi,
}

public static class WebApps
{
    public const int ProxmoxVePort = 8006;
    public const int ProxmoxBackupPort = 8007;

    /// <summary>Which web app a start page (the HTML at /) belongs to.</summary>
    public static WebAppKind Detect(string html)
    {
        bool Has(string text) => html.Contains(text, StringComparison.OrdinalIgnoreCase);
        if (Has("Proxmox Backup Server") || Has("proxmox-backup-gui")) return WebAppKind.ProxmoxBackup;
        if (Has("Proxmox Virtual Environment") || Has("pvemanagerlib")) return WebAppKind.ProxmoxVe;
        if (Has("ESXi")) return WebAppKind.Esxi;
        if (Has("vCenter") || Has("vSphere")) return WebAppKind.VCenter;
        return WebAppKind.Other;
    }

    public static string Product(WebAppKind kind) => kind switch
    {
        WebAppKind.ProxmoxVe => "Proxmox VE",
        WebAppKind.ProxmoxBackup => "Proxmox Backup Server",
        WebAppKind.VCenter => "vCenter",
        WebAppKind.Esxi => "ESXi",
        _ => "web app",
    };

    /// <summary>Proxmox user names name their realm (root@pam); its login page picks "Linux PAM" when none is given, and so does this.</summary>
    public static string ProxmoxUser(string username) => username.Contains('@') ? username : username + "@pam";

    /// <summary>
    /// A script for the page that fills in its login form (the user name box before the visible password box, then the
    /// password) and sends it, the way a person would. It waits up to 15 s for the form (pages often draw it late) and
    /// posts "filled" or "no-form" back. The values are JSON-encoded, so nothing in them can break out of the script.
    /// </summary>
    public static string FillLoginScript(string username, string password)
    {
        var user = JsonSerializer.Serialize(username);
        var pass = JsonSerializer.Serialize(password);
        return FillTemplate.Replace("__LOGIN__", user + ", " + pass); // one replacement: a value can't affect the other
    }

    private const string FillTemplate = """
        (() => {
          const [user, pass] = [__LOGIN__];
          const shown = e => !e.disabled && !e.readOnly && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          const type = (e, v) => {
            e.focus();
            setter.call(e, v);
            for (const name of ['input', 'change']) e.dispatchEvent(new Event(name, { bubbles: true }));
            e.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
          };
          const send = (pw, scope) => {
            const buttons = [...scope.querySelectorAll('button, input[type=submit], input[type=button], [role=button]')].filter(shown);
            const button = buttons.find(b => b.type === 'submit') ||
                           buttons.find(b => /log ?in|sign ?in|submit/i.test(b.innerText || b.value || b.id || ''));
            if (button) button.click();
            else if (pw.form) pw.form.requestSubmit();
            else for (const name of ['keydown', 'keypress', 'keyup'])
              pw.dispatchEvent(new KeyboardEvent(name, { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true }));
          };
          let tries = 0;
          const fill = () => {
            const pw = [...document.querySelectorAll('input[type=password]')].find(shown);
            if (!pw) {
              if (++tries < 60) setTimeout(fill, 250); else window.chrome.webview.postMessage('no-form');
              return;
            }
            const scope = pw.form || document;
            const inputs = [...scope.querySelectorAll('input')].filter(shown);
            const name = inputs.slice(0, inputs.indexOf(pw)).filter(e => e.type === 'text' || e.type === 'email').pop();
            if (name && user) type(name, user);
            type(pw, pass);
            window.chrome.webview.postMessage('filled');
            setTimeout(() => send(pw, scope), 200);
          };
          fill();
        })();
        """;
}

public sealed partial class ServerConsoleClient
{
    /// <summary>
    /// Works out which web app this is and signs in: Proxmox through its API (a login ticket, as its own page gets),
    /// anything else by filling in its login form. Throws <see cref="BmcException"/> or <see cref="BmcCertificateException"/>.
    /// </summary>
    public async Task<ConsoleLaunch> PrepareWebAppAsync(string username, string password, CancellationToken ct = default)
    {
        string html;
        try
        {
            html = await GetStartPageAsync(ct);
        }
        catch (BmcException ex) when (ex.Failure == BmcFailure.Unreachable && BaseUri.IsDefaultPort)
        {
            throw new BmcException(ex.Failure, ex.Message + $" Proxmox answers on port {WebApps.ProxmoxVePort}: Edit the connection to set it.", ex);
        }

        var kind = WebApps.Detect(html);
        var product = WebApps.Product(kind);
        return kind switch
        {
            WebAppKind.ProxmoxVe or WebAppKind.ProxmoxBackup => await PrepareProxmoxAsync(kind, username, password, ct),
            // The vSphere Client and the ESXi Host Client both live at /ui/ (the start page is a "launch" page).
            WebAppKind.VCenter or WebAppKind.Esxi => new ConsoleLaunch { Url = new Uri(BaseUri, "/ui/"), Product = product, FillLogin = true },
            _ => new ConsoleLaunch { Url = BaseUri, Product = product, FillLogin = true },
        };
    }

    /// <summary>The start page's HTML (following up to 3 redirects on this server), or "" when there is none.</summary>
    private async Task<string> GetStartPageAsync(CancellationToken ct)
    {
        var url = BaseUri;
        for (var hop = 0; hop < 4; hop++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("Accept", "text/html");
            using var response = await SendRawAsync(request, ct, redfish: false);
            if ((int)response.StatusCode is >= 300 and < 400 && OnController(response.Headers.Location?.ToString()) is { } next)
            {
                url = next;
                continue;
            }
            var body = await response.Content.ReadAsStringAsync(ct);
            return body.Length > 200_000 ? body[..200_000] : body;
        }
        return "";
    }

    private async Task<ConsoleLaunch> PrepareProxmoxAsync(WebAppKind kind, string username, string password, CancellationToken ct)
    {
        var product = WebApps.Product(kind);
        var user = WebApps.ProxmoxUser(username.Trim());
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BaseUri, "/api2/json/access/ticket"))
        {
            Content = new FormUrlEncodedContent([new("username", user), new("password", password)]),
        };
        using var response = await SendRawAsync(request, ct, redfish: false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new BmcException(BmcFailure.BadLogin, $"{product} didn't accept the username or password (user names name their realm, e.g. root@pam or admin@pve).");
        var json = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new BmcException(BmcFailure.Refused, $"{product} didn't sign in ({(int)response.StatusCode} {response.ReasonPhrase}).");

        var data = TryParse(json)?["data"];
        var ticket = BmcInfo.Str(data?["ticket"]);
        if (string.IsNullOrEmpty(ticket))
            throw new BmcException(BmcFailure.BadLogin, $"{product} didn't accept the username or password.");
        if (data?["NeedTFA"] is not null || ticket.Contains("!tfa!", StringComparison.Ordinal))
        {
            return new ConsoleLaunch
            {
                Url = BaseUri,
                Product = product,
                WebPageOnly = true,
                Notice = "This account also needs a second login step (two-factor), so log in here.",
            };
        }

        // The same cookie Proxmox's own login sets; its page then opens signed in.
        var cookie = kind == WebAppKind.ProxmoxBackup ? "PBSAuthCookie" : "PVEAuthCookie";
        return new ConsoleLaunch
        {
            Url = BaseUri,
            Product = product,
            Cookies = [new(cookie, Uri.EscapeDataString(ticket))],
        };
    }
}

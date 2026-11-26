using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Web.WebView2.Core;
using SimpleSSH.Core.Bmc;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Controls;

/// <summary>
/// One server console tab: logs in to an HPE iLO or Dell iDRAC with the saved password and shows its HTML5 remote
/// console straight away (no web UI, no "launch console" link), in a browser inside the tab.
/// Web app connections (vSphere, ESXi, Proxmox…) use the same tab: signed in by SimpleSSH (Proxmox), or with the
/// login form filled in and sent once.
/// </summary>
public partial class ConsoleView : UserControl, ISessionView
{
    private readonly SessionLogin _login;
    private readonly bool _web;
    /// <summary>The login to fill in on the page, until it has been (once per connect).</summary>
    private (string User, string Password)? _fill;
    private ServerConsoleClient? _client;
    private CancellationTokenSource? _connectCts;
    private bool _webReady;
    private Task<bool>? _webInit;
    private bool _disposed;
    private bool _navigating;
    /// <summary>Private profile numbers of the open console tabs (console-1, console-2…): each tab gets one no other open tab uses.</summary>
    private static readonly HashSet<int> ProfilesInUse = new();
    private int _profile;
    private readonly Stopwatch _clock = new();
    /// <summary>The certificate waiting for "Trust and connect".</summary>
    private BmcCertificateException? _pendingCertificate;

    public ConsoleView(Connection connection)
    {
        InitializeComponent();
        Connection = connection;
        _web = connection.IsWeb;
        _login = new SessionLogin(connection);
        ShowMessage($"Connecting to {connection.Endpoint}…", "", connecting: true);

        // Connect right away, also for tabs opened in the background.
        Dispatcher.BeginInvoke(() =>
        {
            if (!_disposed && State == SessionState.Idle) _ = ConnectAsync();
        }, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    public Connection Connection { get; }

    public string Kind => _web ? "Web" : "Console";

    /// <summary>"the console", or "the page" for a web app (in messages).</summary>
    private string Thing => _web ? "the page" : "the console";

    public SessionState State { get; private set; } = SessionState.Idle;

    public bool IsActive => State is SessionState.Connecting or SessionState.Connected;

    public event EventHandler? StateChanged;

    public event EventHandler? CloseRequested;

    private string Host => Connection.Host.Trim();

    // ------------------------------------------------------------------ connect

    public async Task ConnectAsync()
    {
        if (_disposed || State is SessionState.Connecting) return;
        SetState(SessionState.Connecting);
        _pendingCertificate = null;
        _fill = null;
        _clock.Restart();
        ShowMessage($"Connecting to {Connection.Endpoint}…", "", connecting: true);

        ResolvedCredential? credential;
        try
        {
            credential = await _login.ResolveCredentialAsync(Window.GetWindow(this));
        }
        catch (Exception ex)
        {
            Fail("Couldn't connect", ex.Message);
            return;
        }
        if (_disposed) return;
        if (credential is null)
        {
            Fail("Not connected", "Login cancelled.");
            return;
        }

        _connectCts?.Dispose();
        _connectCts = new CancellationTokenSource();
        _client ??= new ServerConsoleClient(Host, Connection.Port, IsTrusted);

        // The browser starts while SimpleSSH signs in.
        var browser = EnsureWebViewAsync();
        ConsoleLaunch launch;
        try
        {
            ShowMessage($"Signing in to {Connection.Endpoint}…", "", connecting: true);
            launch = _web
                ? await _client.PrepareWebAppAsync(credential.Username, credential.Password ?? "", _connectCts.Token)
                : await _client.PrepareAsync(credential.Username, credential.Password ?? "", _connectCts.Token);
        }
        catch (BmcCertificateException ex)
        {
            if (!_disposed) AskToTrust(ex);
            return;
        }
        catch (BmcException ex)
        {
            if (_disposed) return;
            Log.Info($"Console {Connection.Endpoint}: {ex.Failure}: {ex.Message}");
            if (ex.Failure == BmcFailure.BadLogin)
            {
                _login.ForgetPrompted();
                Fail("Couldn't log in", ex.Message + " Check the username and password (Edit the connection), then connect again.");
            }
            else
            {
                Fail("Couldn't connect", ex.Message);
            }
            return;
        }
        catch (OperationCanceledException)
        {
            if (!_disposed) Fail("Not connected", "Connection cancelled.");
            return;
        }
        catch (Exception ex)
        {
            Log.Error($"Console {Connection.Endpoint} failed", ex);
            if (!_disposed) Fail("Couldn't connect", ex.Message);
            return;
        }
        if (_disposed) return;
        if (!await browser)
        {
            _ = _client?.SignOutAsync(); // the browser couldn't start (its message is showing): don't hold an iLO session
            return;
        }
        if (_disposed) return;

        Log.Info($"{Kind} {Connection.Endpoint}: {launch.Product}, {(launch.WebPageOnly ? "web page" : launch.FillLogin ? "filling in its login" : _web ? "signed in" : "console")}" +
                 (launch.Notice is null ? "" : $" ({launch.Notice})"));
        // A filled-in form may still be refused (the page says so), so only a sign-in SimpleSSH saw succeed counts.
        if (!launch.WebPageOnly && !launch.FillLogin) _login.MarkSucceeded();
        _fill = launch.FillLogin ? (credential.Username, credential.Password ?? "") : null;
        ShowNotice(launch.Notice);
        Open(launch);
    }

    private void Open(ConsoleLaunch launch)
    {
        var core = WebView.CoreWebView2;
        foreach (var (name, value) in launch.Cookies)
        {
            var cookie = core.CookieManager.CreateCookie(name, value, launch.Url.Host, "/");
            cookie.IsSecure = true;
            core.CookieManager.AddOrUpdateCookie(cookie);
        }
        ShowMessage(_web ? $"Opening {Connection.Endpoint}…" : launch.WebPageOnly ? $"Opening {launch.Product}…" : $"Opening the {launch.Product} console…", "", connecting: true);
        _navigating = true;
        core.Navigate(launch.Url.AbsoluteUri);
    }

    private bool IsTrusted(string fingerprint) =>
        AppServices.KnownHosts.Check(Host, Connection.Port, ServerConsoleClient.CertificateKeyType, fingerprint).Status == HostKeyStatus.Trusted;

    private void AskToTrust(BmcCertificateException cert)
    {
        _pendingCertificate = cert;
        var check = AppServices.KnownHosts.Check(Host, Connection.Port, ServerConsoleClient.CertificateKeyType, cert.Fingerprint);
        SetState(SessionState.Disconnected);
        var changed = check.Status == HostKeyStatus.Changed;
        ShowMessage(
            changed ? $"{Connection.Endpoint} has a different certificate" : $"First connection to {Connection.Endpoint}",
            changed
                ? "Its certificate isn't the one you trusted before. That's expected after a firmware update, a reinstall or a new certificate; " +
                  "if none of those happened, someone may be in between. Trust the new one only if you expected the change."
                : "Its certificate isn't signed by an authority Windows knows, which is normal for iLO, iDRAC, ESXi and Proxmox. " +
                  "SimpleSSH will remember it and warn you if it ever changes.");
        // Some iLO 4 certificates carry a broken expiry date (shown as 1901): leave out dates that can't be right.
        FingerprintText.Text = $"{cert.Subject}\nSHA256:{cert.Fingerprint}" + (cert.NotAfter.Year >= 2000 ? $"\nValid until {cert.NotAfter:d}" : "");
        FingerprintText.Visibility = Visibility.Visible;
        TrustButton.Content = changed ? "Trust the new certificate" : "Trust and connect";
        TrustButton.Visibility = Visibility.Visible;
        ConnectButton.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = Visibility.Collapsed;
        TrustButton.Focus();
    }

    private void Trust_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingCertificate is not { } cert) return;
        _pendingCertificate = null;
        AppServices.KnownHosts.Trust(Host, Connection.Port, ServerConsoleClient.CertificateKeyType, cert.Fingerprint);
        Log.Info($"Console {Connection.Endpoint}: trusted certificate SHA256:{cert.Fingerprint}");
        _ = ConnectAsync();
    }

    // ------------------------------------------------------------------ browser

    /// <summary>Starts the browser once (again after a failed start); true when it's ready.</summary>
    private Task<bool> EnsureWebViewAsync()
    {
        if (_webInit is null || (_webInit.IsCompleted && !_webInit.Result)) _webInit = InitWebViewAsync();
        return _webInit;
    }

    private async Task<bool> InitWebViewAsync()
    {
        if (_webReady) return true;
        try
        {
            var env = await AppServices.GetWebViewEnvironmentAsync();
            if (_disposed) return false;
            // A private (InPrivate) profile that no other open console uses: the session cookies and the console address
            // (which holds the session key) stay in memory and are gone when the tab closes, and two consoles never share
            // cookies (cookies ignore the port, so two iLOs through tunnels on localhost:8443 and :8444 would otherwise
            // mix). Numbers are reused, so there are never more profile folders than consoles open at once.
            if (_profile == 0)
            {
                _profile = 1;
                while (ProfilesInUse.Contains(_profile)) _profile++;
                ProfilesInUse.Add(_profile);
            }
            var options = env.CreateCoreWebView2ControllerOptions();
            options.ProfileName = $"console-{_profile}";
            options.IsInPrivateModeEnabled = true;
            await WebView.EnsureCoreWebView2Async(env, options);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            Fail($"Couldn't open {Thing}", "The Microsoft Edge WebView2 Runtime is required but was not found. " +
                 "Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and restart SimpleSSH.");
            return false;
        }
        catch (Exception ex)
        {
            if (_disposed) return false;
            Log.Error("WebView2 initialisation failed (console)", ex);
            Fail($"Couldn't open {Thing}", ex.Message);
            return false;
        }
        if (_disposed) return false;

        var core = WebView.CoreWebView2;
        var settings = core.Settings;
        settings.AreBrowserAcceleratorKeysEnabled = false; // F5, Ctrl+F… belong to the server, not the page
        settings.IsStatusBarEnabled = false;
        settings.AreDevToolsEnabled = false;
        settings.IsPasswordAutosaveEnabled = false;
        settings.IsGeneralAutofillEnabled = false;
        core.ServerCertificateErrorDetected += OnCertificateError;
        core.NavigationStarting += OnNavigationStarting;
        core.NewWindowRequested += OnNewWindowRequested;
        core.NavigationCompleted += OnNavigationCompleted;
        if (_web)
        {
            core.DOMContentLoaded += OnDomContentLoaded;
            core.WebMessageReceived += OnWebMessageReceived;
        }
        else
        {
            // The page's own files come from the kept copies when the controller says they haven't changed (much faster).
            core.AddWebResourceRequestedFilter(ServerConsoleClient.BuildBaseUri(Host, Connection.Port).AbsoluteUri + "*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += OnWebResourceRequested;
        }
        // (Never log page titles or addresses: the first title is the address, which holds the session key.)
        core.WindowCloseRequested += (_, _) => CloseRequested?.Invoke(this, EventArgs.Empty);
        core.ProcessFailed += (_, e) =>
        {
            Log.Error($"WebView2 process failed (console): {e.ProcessFailedKind} ({e.Reason})", null);
            if (e.ProcessFailedKind is CoreWebView2ProcessFailedKind.BrowserProcessExited or CoreWebView2ProcessFailedKind.RenderProcessExited)
                Fail(_web ? "The page stopped" : "The console stopped", $"The browser inside this tab stopped. Connect again to reopen {Thing}.");
        };
        _webReady = true;
        return true;
    }

    /// <summary>Exactly the connection's address (scheme, host and port): the only place the login is ever filled in.</summary>
    private bool IsLoginOrigin(string? address)
    {
        var home = ServerConsoleClient.BuildBaseUri(Host, Connection.Port);
        return Uri.TryCreate(address, UriKind.Absolute, out var uri) &&
               Uri.Compare(uri, home, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0;
    }

    /// <summary>Each page of the web app, until the login has been filled in: fill it in if the page asks for it.</summary>
    private async void OnDomContentLoaded(object? sender, CoreWebView2DOMContentLoadedEventArgs e)
    {
        if (_disposed || _fill is not { } login || WebView.CoreWebView2 is not { } core || !IsLoginOrigin(core.Source)) return;
        try
        {
            await core.ExecuteScriptAsync(WebApps.FillLoginScript(login.User, login.Password));
        }
        catch (Exception ex)
        {
            Log.Info($"Web {Connection.Endpoint}: couldn't fill in the login: {ex.Message}");
        }
    }

    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (!IsLoginOrigin(e.Source)) return;
        string? message;
        try { message = e.TryGetWebMessageAsString(); }
        catch (ArgumentException) { return; }
        if (message != "filled" || _fill is null) return;
        // Once: if the page asks again, the login was refused, and sending it again won't help (and may lock the account).
        _fill = null;
        Log.Info($"Web {Connection.Endpoint}: filled in the login");
    }

    /// <summary>The console's own pages (any port on the same host, over https), or the blank page used when reconnecting.</summary>
    private bool IsConsolePage(string? address)
    {
        if (address == "about:blank") return true;
        // blob: addresses made by the page itself (e.g. a saved screenshot) carry its origin: blob:https://host/…
        if (address?.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) == true) address = address[5..];
        return Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
               string.Equals(uri.Host.Trim('[', ']'), Host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The tab only ever shows the controller: a page can't send it to another site.</summary>
    private void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (IsConsolePage(e.Uri)) return;
        e.Cancel = true;
        Log.Info($"Console {Connection.Endpoint}: blocked a page from opening another site");
    }

    /// <summary>The controller's own pop-ups (help, virtual media…) may open; anything else is blocked.</summary>
    private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        if (IsConsolePage(e.Uri) && e.Uri != "about:blank") return;
        e.Handled = true;
        Log.Info($"Console {Connection.Endpoint}: blocked a pop-up to another site");
    }

    private async void OnWebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        if (_disposed || _client is not { } client || e.Request.Method != "GET" ||
            !Uri.TryCreate(e.Request.Uri, UriKind.Absolute, out var url) || !ConsoleFileCache.IsStaticFile(url)) return;
        var deferral = e.GetDeferral();
        try
        {
            var file = await Task.Run(() => client.GetPageFileAsync(url, AppServices.ConsoleFiles));
            if (file is not null && !_disposed && WebView.CoreWebView2 is { } core)
            {
                e.Response = core.Environment.CreateWebResourceResponse(
                    new MemoryStream(file.Body, writable: false), 200, "OK", file.Headers);
            }
        }
        catch (Exception ex)
        {
            Log.Info($"Console {Connection.Endpoint}: page file from the controller: {ex.Message}");
        }
        finally
        {
            deferral.Complete(); // without a response the browser fetches the file itself
        }
    }

    /// <summary>The page uses the same certificate SimpleSSH checked (and the user trusted) while signing in.</summary>
    private void OnCertificateError(object? sender, CoreWebView2ServerCertificateErrorDetectedEventArgs e)
    {
        try
        {
            using var cert = e.ServerCertificate.ToX509Certificate2();
            var fingerprint = ServerConsoleClient.Fingerprint(cert);
            var sameHost = Uri.TryCreate(e.RequestUri, UriKind.Absolute, out var uri) &&
                           string.Equals(uri.Host.Trim('[', ']'), Host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase);
            if (sameHost && IsTrusted(fingerprint))
            {
                e.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
                return;
            }
            Log.Info($"Console {Connection.Endpoint}: refused certificate SHA256:{fingerprint} for {uri?.Host} ({e.ErrorStatus})");
        }
        catch (Exception ex)
        {
            Log.Error("Console certificate check failed", ex);
        }
        e.Action = CoreWebView2ServerCertificateErrorAction.Cancel;
    }

    private void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (_disposed || !_navigating) return;
        _navigating = false;
        if (!e.IsSuccess)
        {
            Log.Info($"Console {Connection.Endpoint}: page didn't open ({e.WebErrorStatus}, HTTP {e.HttpStatusCode})");
            Fail($"Couldn't open {Thing}", e.WebErrorStatus switch
            {
                CoreWebView2WebErrorStatus.CertificateCommonNameIsIncorrect or CoreWebView2WebErrorStatus.CertificateExpired or
                    CoreWebView2WebErrorStatus.ClientCertificateContainsErrors or CoreWebView2WebErrorStatus.CertificateRevoked or
                    CoreWebView2WebErrorStatus.CertificateIsInvalid =>
                    "The page came with a certificate SimpleSSH hadn't checked. Connect again to see it.",
                CoreWebView2WebErrorStatus.Timeout or CoreWebView2WebErrorStatus.ConnectionAborted or CoreWebView2WebErrorStatus.ConnectionReset or
                    CoreWebView2WebErrorStatus.Disconnected or CoreWebView2WebErrorStatus.CannotConnect or CoreWebView2WebErrorStatus.HostNameNotResolved =>
                    $"{Connection.Endpoint} stopped answering.",
                _ => $"The page didn't load ({e.WebErrorStatus}).",
            });
            return;
        }
        Log.Info($"Console {Connection.Endpoint}: open after {_clock.Elapsed.TotalSeconds:0.0} s");
        Overlay.Visibility = Visibility.Collapsed;
        WebView.Visibility = Visibility.Visible;
        SetState(SessionState.Connected);
        if (IsVisible) FocusContent();
    }

    // ------------------------------------------------------------------ UI

    private void ShowMessage(string title, string text, bool connecting = false)
    {
        WebView.Visibility = Visibility.Hidden;
        Overlay.Visibility = Visibility.Visible;
        OverlayTitle.Text = title;
        OverlayText.Text = text;
        OverlayText.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
        FingerprintText.Visibility = Visibility.Collapsed;
        TrustButton.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = connecting ? Visibility.Visible : Visibility.Collapsed;
        ConnectButton.Visibility = connecting ? Visibility.Collapsed : Visibility.Visible;
        BrowserButton.Visibility = connecting ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ShowNotice(string? text)
    {
        NoticeText.Text = text ?? "";
        NoticeBar.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
    }

    private void DismissNotice_Click(object sender, RoutedEventArgs e) => NoticeBar.Visibility = Visibility.Collapsed;

    private void Fail(string title, string text)
    {
        if (_disposed) return;
        _navigating = false;
        SetState(SessionState.Disconnected);
        ShowMessage(title, text);
    }

    private void SetState(SessionState state)
    {
        if (State == state) return;
        State = state;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public void FocusContent()
    {
        if (_disposed) return;
        if (State == SessionState.Connected) WebView.Focus();
        else if (TrustButton.IsVisible) TrustButton.Focus();
        else if (ConnectButton.IsVisible) ConnectButton.Focus();
    }

    /// <summary>Signs in again and reopens the console (a fresh session).</summary>
    public void Reconnect()
    {
        if (_disposed || State == SessionState.Connecting) return;
        if (WebView.CoreWebView2 is { } core)
        {
            try { core.Navigate("about:blank"); } catch (Exception ex) { Log.Info($"Console blank page: {ex.Message}"); }
        }
        SetState(SessionState.Disconnected);
        _ = ConnectAsync();
    }

    private void Connect_Click(object sender, RoutedEventArgs e) => Reconnect();

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (State != SessionState.Connecting) return;
        _connectCts?.Cancel();
        if (_navigating)
        {
            try { WebView.CoreWebView2?.Stop(); } catch { /* ignore */ }
            Fail("Not connected", "Connection cancelled.");
        }
    }

    private void Browser_Click(object sender, RoutedEventArgs e)
    {
        var url = ServerConsoleClient.BuildBaseUri(Host, Connection.Port).AbsoluteUri;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { Log.Error($"Could not open {url}", ex); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _fill = null;
        _connectCts?.Cancel();
        var client = _client;
        _client = null;
        if (client is not null)
        {
            // End the iLO session so it doesn't use up one of the controller's few slots.
            _ = client.SignOutAsync().ContinueWith(_ => client.Dispose(), TaskScheduler.Default);
        }
        try { WebView.Dispose(); }
        catch (Exception ex) { Log.Error("Disposing the console browser failed", ex); }
        if (_profile > 0) ProfilesInUse.Remove(_profile);
    }
}

using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Controls;

/// <summary>
/// One terminal tab: an xterm.js page in WebView2 wired to an <see cref="SshTerminalSession"/>.
/// </summary>
public partial class TerminalView : UserControl, ISessionView
{
    private const string VirtualHost = "simplessh.example";

    private const string AnsiReset = "\x1b[0m";
    private const string AnsiInfo = "\x1b[36m";
    private const string AnsiError = "\x1b[91m";
    private const string AnsiMuted = "\x1b[90m";

    private readonly StringBuilder _outBuffer = new();
    private readonly object _outGate = new();
    private readonly StringBuilder _pendingBeforeReady = new();
    private readonly SessionLogin _login;
    private bool _flushScheduled;

    private SshTerminalSession? _session;
    private CancellationTokenSource? _connectCts;
    private bool _webInitStarted;
    private bool _webReady;
    private bool _disposed;
    private uint _cols = 80;
    private uint _rows = 24;

    public TerminalView(Connection connection)
    {
        InitializeComponent();
        Connection = connection;
        _login = new SessionLogin(connection);
        WebView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(0x1E, 0x1E, 0x1E);
        Loaded += OnLoaded;

        // Connect right away, even if this tab starts in the background (e.g. "Open all in tag"):
        // the terminal page only loads once the tab is shown, and output is buffered until then.
        Dispatcher.BeginInvoke(() =>
        {
            if (!_disposed && State == SessionState.Idle) _ = ConnectAsync();
        }, DispatcherPriority.Loaded);
    }

    public Connection Connection { get; }

    private ShellLocation? _location;
    private bool _hasOsc7;
    private string? _shellHost;
    private string? _loginUser;

    /// <summary>
    /// The shell's current folder, as reported by its prompt (window title or OSC 7), for opening the file browser
    /// there. Null when the shell doesn't report it.
    /// </summary>
    public string? CurrentDirectory =>
        _location is null ? null : ShellDirectory.ForLogin(_location, _loginUser ?? Connection.Username);

    /// <summary>
    /// The shell's current folder: from its prompt when it reports one, otherwise asked from the server (Linux).
    /// Null when neither works; the file browser then opens the home folder.
    /// </summary>
    public async Task<string?> GetCurrentDirectoryAsync()
    {
        if (CurrentDirectory is { } here) return here;
        if (_session is not { } session) return null;
        var path = await session.QueryCurrentDirectoryAsync(TimeSpan.FromSeconds(4));
        Log.Info(path is null
            ? $"Current folder of {Connection.DisplayName}: the prompt doesn't report it and the server couldn't tell."
            : $"Current folder of {Connection.DisplayName}: asked the server ({path}).");
        return path;
    }

    private void OnTitle(string title)
    {
        // OSC 7 is exact; once the shell sends it, titles (which programs like vim also set) are ignored.
        if (_hasOsc7 || !ShellDirectory.TryParseTitle(title, out var location)) return;
        // The first prompt names this server; a different name means an ssh to another box from inside the terminal,
        // whose folders the file browser can't see.
        _shellHost ??= location.Host;
        if (string.Equals(location.Host, _shellHost, StringComparison.OrdinalIgnoreCase)) _location = location;
    }

    private void OnOsc7(string data)
    {
        if (!ShellDirectory.TryParseOsc7(data, out var location)) return;
        _hasOsc7 = true;
        _location = location;
    }

    public string Kind => "";

    public void FocusContent() => FocusTerminal();

    public SessionState State { get; private set; } = SessionState.Idle;

    public event EventHandler? StateChanged;

    /// <summary>Raised when the session ended normally and the tab should close itself.</summary>
    public event EventHandler? CloseRequested;

    public bool IsActive => State is SessionState.Connecting or SessionState.Connected;

    // ------------------------------------------------------------------ WebView setup

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_webInitStarted) return;
        _webInitStarted = true;
        await InitializeWebViewAsync();
    }

    private async Task InitializeWebViewAsync()
    {
        try
        {
            var env = await AppServices.GetWebViewEnvironmentAsync();
            if (_disposed) return;
            await WebView.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            ShowOverlay("The Microsoft Edge WebView2 Runtime is required but was not found.\n" +
                        "Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and restart SimpleSSH.");
            return;
        }
        catch (Exception ex)
        {
            if (_disposed) return;
            Log.Error("WebView2 initialisation failed", ex);
            ShowOverlay($"Could not start the terminal view:\n{ex.Message}");
            return;
        }
        if (_disposed) return;

        var core = WebView.CoreWebView2;
        _ = AppServices.ClearSharedHistoryOnceAsync(core);
        var settings = core.Settings;
        settings.AreDefaultContextMenusEnabled = false;
        settings.AreBrowserAcceleratorKeysEnabled = false;
        settings.IsStatusBarEnabled = false;
        settings.IsZoomControlEnabled = false;
        settings.IsPinchZoomEnabled = false;
        settings.IsSwipeNavigationEnabled = false;
        settings.IsGeneralAutofillEnabled = false;
        settings.IsPasswordAutosaveEnabled = false;
        settings.IsWebMessageEnabled = true;
#if DEBUG
        settings.AreDevToolsEnabled = true;
#else
        settings.AreDevToolsEnabled = false;
#endif

        var wwwroot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        core.SetVirtualHostNameToFolderMapping(VirtualHost, wwwroot, CoreWebView2HostResourceAccessKind.DenyCors);
        core.WebMessageReceived += OnWebMessageReceived;
        core.NavigationStarting += (_, args) =>
        {
            if (!args.Uri.StartsWith($"https://{VirtualHost}/", StringComparison.OrdinalIgnoreCase)) args.Cancel = true;
        };
        core.NewWindowRequested += (_, args) => args.Handled = true;
        core.ProcessFailed += OnProcessFailed;

        var s = AppServices.Settings;
        core.Navigate($"https://{VirtualHost}/terminal.html?fontSize={s.TerminalFontSize}&fontFamily={Uri.EscapeDataString(s.TerminalFontFamily)}" +
                      $"&copyOnSelect={(Connection.CopiesOnSelect ? 1 : 0)}");
    }

    /// <summary>Passes per-connection terminal options to the page again (after the connection was edited).</summary>
    public void ApplyConnectionOptions()
    {
        if (_webReady) Post(new { type = "options", copyOnSelect = Connection.CopiesOnSelect });
    }

    private void OnProcessFailed(object? sender, CoreWebView2ProcessFailedEventArgs e)
    {
        Log.Error($"WebView2 process failed: {e.ProcessFailedKind} ({e.Reason})", null);
        if (_disposed) return;
        _webReady = false;
        if (e.ProcessFailedKind == CoreWebView2ProcessFailedKind.BrowserProcessExited)
        {
            ShowOverlay("The terminal view crashed. Close this tab and open the connection again.");
            return;
        }
        try
        {
            AppendPending($"{AnsiError}[terminal view restarted]{AnsiReset}\r\n");
            WebView.CoreWebView2?.Reload();
        }
        catch (Exception ex)
        {
            Log.Error("Reload after process failure failed", ex);
        }
    }

    private void ShowOverlay(string text)
    {
        OverlayText.Text = text;
        OverlayText.Visibility = Visibility.Visible;
        WebView.Visibility = Visibility.Collapsed;
    }

    // ------------------------------------------------------------------ page -> host

    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (_disposed) return;
        try
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("type", out var typeProp)) return;

            switch (typeProp.GetString())
            {
                case "ready":
                    OnPageReady(GetUInt(root, "cols"), GetUInt(root, "rows"));
                    break;
                case "input":
                    HandleInput(root.GetProperty("data").GetString() ?? "");
                    break;
                case "binary":
                    if (State == SessionState.Connected)
                        _session?.Write(Encoding.Latin1.GetBytes(root.GetProperty("data").GetString() ?? ""));
                    break;
                case "resize":
                    _cols = Math.Max(1, GetUInt(root, "cols"));
                    _rows = Math.Max(1, GetUInt(root, "rows"));
                    _session?.Resize(_cols, _rows);
                    break;
                case "copy":
                    ClipboardHelper.SetText(root.GetProperty("text").GetString() ?? "");
                    break;
                case "paste":
                    var text = Core.Ssh.PasteText.Clean(ClipboardHelper.GetText()); // no hidden escape sequences
                    if (!string.IsNullOrEmpty(text)) Post(new { type = "paste", text });
                    break;
                case "title":
                    OnTitle(root.GetProperty("title").GetString() ?? "");
                    break;
                case "cwd":
                    OnOsc7(root.GetProperty("data").GetString() ?? "");
                    break;
                case "fontSize":
                    var size = (int)GetUInt(root, "size");
                    if (size is >= 6 and <= 40) AppServices.Settings.TerminalFontSize = size;
                    break;
            }
        }
        catch (Exception ex)
        {
            Log.Error("Bad message from terminal page", ex);
        }
    }

    private static uint GetUInt(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) && i > 0 ? (uint)i : 0;

    private void OnPageReady(uint cols, uint rows)
    {
        if (cols > 0) _cols = cols;
        if (rows > 0) _rows = rows;
        _webReady = true;
        OverlayText.Visibility = Visibility.Collapsed;

        if (_pendingBeforeReady.Length > 0)
        {
            Post(new { type = "output", data = _pendingBeforeReady.ToString() });
            _pendingBeforeReady.Clear();
        }

        if (State == SessionState.Idle) _ = ConnectAsync();
        else _session?.Resize(_cols, _rows);

        if (IsVisible) FocusTerminal();
    }

    private void HandleInput(string data)
    {
        switch (State)
        {
            case SessionState.Connected:
                _session?.Write(data);
                break;
            case SessionState.Disconnected when data.Contains('\r'):
                _ = ConnectAsync();
                break;
        }
    }

    // ------------------------------------------------------------------ host -> page

    private void Post(object message)
    {
        if (_disposed) return;
        var core = WebView.CoreWebView2;
        if (core is null) return;
        try
        {
            core.PostWebMessageAsJson(JsonSerializer.Serialize(message));
        }
        catch (Exception ex)
        {
            Log.Error("PostWebMessage failed", ex);
        }
    }

    private void AppendPending(string text)
    {
        if (_webReady) Post(new { type = "output", data = text });
        else _pendingBeforeReady.Append(text);
    }

    private void WriteLine(string color, string text) => AppendPending($"{color}{text}{AnsiReset}\r\n");

    /// <summary>Background thread: batch output and flush once per dispatcher turn.</summary>
    private void OnSessionOutput(string text)
    {
        bool schedule;
        lock (_outGate)
        {
            _outBuffer.Append(text);
            schedule = !_flushScheduled;
            _flushScheduled = true;
        }
        if (schedule) Dispatcher.BeginInvoke(FlushOutput, DispatcherPriority.Normal);
    }

    private void FlushOutput()
    {
        string text;
        lock (_outGate)
        {
            text = _outBuffer.ToString();
            _outBuffer.Clear();
            _flushScheduled = false;
        }
        if (text.Length > 0) AppendPending(text);
    }

    public void FocusTerminal()
    {
        if (_disposed) return;
        WebView.Focus();
        Post(new { type = "focus" });
    }

    public void ClearScreen() => Post(new { type = "clear" });

    // ------------------------------------------------------------------ SSH lifecycle

    public void Reconnect()
    {
        if (_disposed || State == SessionState.Connecting) return;
        if (State == SessionState.Connected)
        {
            DisposeSession();
            WriteLine(AnsiMuted, "\r\n[session closed – reconnecting]");
            SetState(SessionState.Disconnected);
        }
        _ = ConnectAsync();
    }

    public async Task ConnectAsync()
    {
        if (_disposed || State is SessionState.Connecting or SessionState.Connected) return;
        DisposeSession();
        SetState(SessionState.Connecting);
        _location = null; // a new shell starts in its home folder
        _shellHost = null;
        _hasOsc7 = false;

        var c = Connection;
        WriteLine(AnsiInfo, $"Connecting to {c.Endpoint}{(string.IsNullOrWhiteSpace(c.Proxy) ? "" : " via proxy")}…");

        SshConnectOptions? options;
        try
        {
            options = await _login.PrepareAsync(Window.GetWindow(this), includeTunnels: true);
        }
        catch (Exception ex)
        {
            if (!_disposed) Fail(SshConnector.DescribeError(ex));
            return;
        }
        if (_disposed) return;
        if (options is not null) _loginUser = options.Credential.Username;
        if (options is null)
        {
            WriteLine(AnsiMuted, "Login cancelled.");
            SetState(SessionState.Disconnected);
            WriteLine(AnsiMuted, "Press Enter to reconnect.");
            return;
        }

        SshTerminalSession session;
        try
        {
            session = await _login.ConnectAsync(options, async verifier =>
            {
                var s = new SshTerminalSession(verifier);
                s.Output += OnSessionOutput;
                s.Disconnected += reason => Dispatcher.BeginInvoke(() => OnSessionDisconnected(s, reason), DispatcherPriority.Normal);
                _session = s;
                _connectCts = new CancellationTokenSource();
                try
                {
                    await s.ConnectAsync(options, _cols, _rows, _connectCts.Token);
                    return s;
                }
                catch
                {
                    if (_disposed || !ReferenceEquals(_session, s)) throw new OperationCanceledException();
                    DisposeSession();
                    throw;
                }
            }, notice => WriteLine(AnsiMuted, notice));
        }
        catch (OperationCanceledException)
        {
            return; // tab closed or reconnect started meanwhile
        }
        catch (Exception ex)
        {
            if (_disposed) return;
            Log.Info($"Connect to {c.Endpoint} failed: {ex.Message}");
            Fail(SshConnector.DescribeError(ex));
            return;
        }

        if (_disposed || !ReferenceEquals(_session, session))
        {
            session.Dispose();
            return;
        }
        foreach (var line in session.TunnelStatus)
            WriteLine(line.StartsWith("Tunnel failed", StringComparison.Ordinal) ? AnsiError : AnsiMuted, line);
        SetState(SessionState.Connected);
        if (_webReady) session.Resize(_cols, _rows); // the page may have reported its real size while we were connecting
        if (IsVisible) FocusTerminal();
    }

    private void Fail(string message)
    {
        WriteLine(AnsiError, message);
        SetState(SessionState.Disconnected);
        WriteLine(AnsiMuted, "Press Enter to reconnect.");
    }

    private void OnSessionDisconnected(SshTerminalSession session, string reason)
    {
        if (_disposed || !ReferenceEquals(session, _session)) return;
        FlushOutput();
        if (session.EndedCleanly && State == SessionState.Connected && AppServices.Settings.CloseTabOnExit)
        {
            DisposeSession();
            SetState(SessionState.Disconnected);
            CloseRequested?.Invoke(this, EventArgs.Empty);
            return;
        }
        WriteLine(AnsiMuted, "");
        WriteLine(State == SessionState.Connected ? AnsiMuted : AnsiError, $"[{reason}]");
        DisposeSession();
        SetState(SessionState.Disconnected);
        WriteLine(AnsiMuted, "Press Enter to reconnect, or close the tab.");
    }

    private void SetState(SessionState state)
    {
        if (State == state) return;
        State = state;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private void DisposeSession()
    {
        _connectCts?.Cancel();
        _connectCts?.Dispose();
        _connectCts = null;

        var session = _session;
        _session = null;
        if (session is null) return;
        session.Output -= OnSessionOutput;
        // Disconnect can block briefly on the network; keep the UI responsive.
        Task.Run(session.Dispose);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        DisposeSession();
        try { WebView.Dispose(); } catch { /* ignore */ }
    }
}

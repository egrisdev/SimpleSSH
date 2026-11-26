using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Rdp;
using SimpleSSH.Services;

namespace SimpleSSH.Controls;

/// <summary>
/// One Remote Desktop tab: the Windows RDP control (the same engine as mstsc.exe) inside the tab, signed in with
/// the saved (DPAPI-encrypted) password. The remote desktop follows the tab's size.
/// </summary>
public partial class RdpView : UserControl, ISessionView
{
    private readonly SessionLogin _login;
    private readonly RdpClientHost _rdp;
    private readonly DispatcherTimer _resizeTimer;

    private bool _disposed;
    private bool _loggedIn;
    private bool _reconnectAfterDisconnect;
    private bool _cancelRequested;
    private bool _dynamicResize = true;
    /// <summary>The remote desktop's current resolution, as reported by the control.</summary>
    private (int Width, int Height) _remoteSize;
    /// <summary>The resolution last asked for, and how many times, so a request the server ignored is retried.</summary>
    private (int Width, int Height) _requestedSize;
    private int _resizeAttempts;
    private const int MaxResizeAttempts = 10; // about 25 s: the display channel can open late on a busy server
    private readonly DispatcherTimer _verifyResizeTimer;

    public RdpView(Connection connection)
    {
        InitializeComponent();
        Connection = connection;
        _login = new SessionLogin(connection);

        _rdp = new RdpClientHost();
        ((ISupportInitialize)_rdp).BeginInit();
        Host.Child = _rdp;
        ((ISupportInitialize)_rdp).EndInit();

        _rdp.Connected += OnConnected;
        _rdp.LoginComplete += OnLoginComplete;
        _rdp.Disconnected += OnDisconnected;
        _rdp.FatalError += code => Fail("Remote Desktop stopped working", $"The Remote Desktop control reported a fatal error (code {code}).");
        _rdp.LogonError += code => Log.Info($"RDP logon error {code} for {Connection.Endpoint}");
        _rdp.RequestMinimize += () => { if (Window.GetWindow(this) is { } w) w.WindowState = WindowState.Minimized; };
        _rdp.LeaveFullScreen += () => Dispatcher.BeginInvoke(FocusContent, DispatcherPriority.Input);

        _resizeTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(450) };
        _resizeTimer.Tick += (_, _) =>
        {
            _resizeTimer.Stop();
            ApplyDesktopSize();
        };
        SizeChanged += (_, _) =>
        {
            // Follow the tab at once (scaled to fit for a moment), then ask the server for the matching resolution.
            if (ActualWidth >= 100 && ActualHeight >= 100) FitHost(CurrentDesktopSize());
            if (!_loggedIn) return;
            _resizeTimer.Stop();
            _resizeTimer.Start();
        };

        // A resize request can be silently ignored (e.g. sent before the server's display channel is open right
        // after sign-in): check that the remote desktop really changed, and ask again if it didn't.
        _verifyResizeTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(1500) };
        _verifyResizeTimer.Tick += (_, _) =>
        {
            _verifyResizeTimer.Stop();
            ApplyDesktopSize();
        };
        _rdp.RemoteDesktopSizeChanged += (width, height) =>
        {
            _remoteSize = (width, height);
            Log.Info($"RDP {Connection.Endpoint}: remote desktop is now {width}x{height} (asked for {_requestedSize.Width}x{_requestedSize.Height}).");
            if (_remoteSize == _requestedSize) _verifyResizeTimer.Stop();
        };
        _rdp.AutoReconnected += () =>
        {
            // The session may come back at its old size.
            _resizeAttempts = 0;
            _resizeTimer.Stop();
            _resizeTimer.Start();
        };

        ShowMessage($"Connecting to {connection.Endpoint}…", "", connecting: true);

        // Connect right away, also for tabs opened in the background.
        Dispatcher.BeginInvoke(() =>
        {
            if (!_disposed && State == SessionState.Idle) _ = ConnectAsync();
        }, DispatcherPriority.Loaded);
    }

    public Connection Connection { get; }

    public string Kind => "";

    public SessionState State { get; private set; } = SessionState.Idle;

    public bool IsActive => State is SessionState.Connecting or SessionState.Connected;

    public event EventHandler? StateChanged;

    public event EventHandler? CloseRequested;

    // ------------------------------------------------------------------ connect

    public async Task ConnectAsync()
    {
        if (_disposed || State is SessionState.Connecting or SessionState.Connected) return;
        SetState(SessionState.Connecting);
        var c = Connection;
        ShowMessage($"Connecting to {c.Endpoint}…", "", connecting: true);

        ResolvedCredential? credential;
        try
        {
            credential = await _login.ResolveCredentialAsync(Window.GetWindow(this));
        }
        catch (Exception ex)
        {
            if (!_disposed) Fail("Couldn't connect", ex.Message);
            return;
        }
        if (_disposed) return;
        if (credential is null)
        {
            SetState(SessionState.Disconnected);
            ShowMessage("Not connected", "Login cancelled.");
            return;
        }

        if (!await EnsureControlAsync())
        {
            if (!_disposed) Fail("Couldn't start Remote Desktop", "The Windows Remote Desktop control (mstscax.dll) could not be loaded.");
            return;
        }

        try
        {
            Configure(credential);
            _loggedIn = false;
            _cancelRequested = false;
            _rdp.Ocx.Connect();
        }
        catch (Exception ex)
        {
            Log.Error($"RDP connect to {c.Endpoint} failed", ex);
            Fail("Couldn't connect", ex.Message);
        }
    }

    private void Configure(ResolvedCredential credential)
    {
        var c = Connection;
        var ocx = _rdp.Ocx;
        var (domain, user) = RdpSettings.SplitUser(credential.Username);
        var (width, height) = CurrentDesktopSize();
        var dpi = VisualTreeHelper.GetDpi(this);
        var (desktopScale, deviceScale) = RdpSettings.ScaleFactors(dpi.DpiScaleX);

        ocx.Server = c.Host.Trim();
        ocx.UserName = user;
        ocx.Domain = domain;
        ocx.DesktopWidth = width;
        ocx.DesktopHeight = height;
        FitHost((width, height));
        _remoteSize = _requestedSize = (width, height);
        _dynamicResize = true; // a new connection may reach a server that supports it
        _resizeAttempts = 0;
        Try(() => ocx.ColorDepth = 32, "ColorDepth");
        Try(() => ocx.FullScreenTitle = $"{c.DisplayName} – SimpleSSH", "FullScreenTitle");

        var adv = ocx.AdvancedSettings9;
        adv.RDPPort = c.Port;
        adv.ClearTextPassword = credential.Password ?? "";
        adv.EnableCredSspSupport = true;                    // Network Level Authentication
        Try(() => adv.AuthenticationLevel = 2u, "AuthenticationLevel");   // warn if the server's identity can't be verified
        Try(() => adv.RedirectClipboard = true, "RedirectClipboard");
        Try(() => adv.RedirectSmartCards = true, "RedirectSmartCards");
        Try(() => adv.RedirectPrinters = false, "RedirectPrinters");
        Try(() => adv.RedirectDrives = false, "RedirectDrives");
        Try(() => adv.EnableAutoReconnect = true, "EnableAutoReconnect");
        Try(() => adv.BitmapPersistence = 1, "BitmapPersistence");
        Try(() => adv.Compress = 1, "Compress");
        Try(() => adv.keepAliveInterval = 30000, "keepAliveInterval");
        Try(() => adv.NetworkConnectionType = 7u, "NetworkConnectionType");  // detect automatically
        Try(() => adv.BandwidthDetection = true, "BandwidthDetection");
        // Always on: whenever the remote resolution doesn't match the tab yet (or the server can't change it), the
        // picture is scaled to fit instead of showing scroll bars. At a matching size it is drawn 1:1.
        Try(() => adv.SmartSizing = true, "SmartSizing");
        Try(() => adv.GrabFocusOnConnect = IsVisible, "GrabFocusOnConnect");
        Try(() => adv.DisplayConnectionBar = true, "DisplayConnectionBar");

        _rdp.TrySetExtendedProperty("DesktopScaleFactor", desktopScale);
        _rdp.TrySetExtendedProperty("DeviceScaleFactor", deviceScale);
    }

    private static void Try(Action set, string name)
    {
        try { set(); }
        catch (Exception ex) { Log.Info($"RDP setting {name} not applied: {ex.Message}"); }
    }

    /// <summary>The ActiveX control is created with its window; wait for that if the tab hasn't been laid out yet.</summary>
    private async Task<bool> EnsureControlAsync()
    {
        if (_rdp.IsReady) return true;
        var created = new TaskCompletionSource();
        void OnCreated(object? s, EventArgs e) => created.TrySetResult();
        _rdp.HandleCreated += OnCreated;
        try
        {
            if (_rdp.IsReady) return true;
            await Task.WhenAny(created.Task, Task.Delay(TimeSpan.FromSeconds(10)));
            return !_disposed && _rdp.IsReady;
        }
        catch (Exception ex)
        {
            Log.Error("Remote Desktop control failed to load", ex);
            return false;
        }
        finally
        {
            _rdp.HandleCreated -= OnCreated;
        }
    }

    /// <summary>
    /// Makes the hosted control exactly <paramref name="size"/> device pixels. The remote resolution must have an
    /// even width; if the control were 1 px wider, smart sizing would stretch every frame and blur the text.
    /// </summary>
    private void FitHost((int Width, int Height) size)
    {
        var dpi = VisualTreeHelper.GetDpi(this);
        Host.Width = size.Width / dpi.DpiScaleX;
        Host.Height = size.Height / dpi.DpiScaleY;
    }

    /// <summary>Size of the tab in device pixels (falls back to the tab area when this tab is in the background).</summary>
    private (int Width, int Height) CurrentDesktopSize()
    {
        double w = ActualWidth, h = ActualHeight;
        if (w < 100 || h < 100)
        {
            var area = Parent as FrameworkElement ?? Window.GetWindow(this);
            w = area?.ActualWidth ?? 1280;
            h = area?.ActualHeight ?? 800;
        }
        var dpi = VisualTreeHelper.GetDpi(this);
        return RdpSettings.ClampDesktopSize(w * dpi.DpiScaleX, h * dpi.DpiScaleY);
    }

    /// <summary>
    /// Resizes the remote desktop to the tab (Windows 8.1 / Server 2012 R2 and later), checking that the server
    /// applied it. Until it has, or if the server can't, smart sizing scales the picture to fit the tab.
    /// </summary>
    private void ApplyDesktopSize()
    {
        _verifyResizeTimer.Stop();
        if (_disposed || !_loggedIn || !_dynamicResize || ActualWidth < 100 || ActualHeight < 100) return;
        var target = CurrentDesktopSize();
        if (target == _remoteSize)
        {
            _requestedSize = target;
            _resizeAttempts = 0;
            return;
        }
        if (target != _requestedSize)
        {
            _requestedSize = target;
            _resizeAttempts = 0;
        }
        if (_resizeAttempts >= MaxResizeAttempts)
        {
            if (_resizeAttempts++ == MaxResizeAttempts)
                Log.Info($"{Connection.Endpoint} kept {_remoteSize.Width}x{_remoteSize.Height} instead of {target.Width}x{target.Height}; scaling to fit.");
            return;
        }
        _resizeAttempts++;

        var dpi = VisualTreeHelper.GetDpi(this);
        var (desktopScale, deviceScale) = RdpSettings.ScaleFactors(dpi.DpiScaleX);
        uint Millimetres(int pixels, double scale) => (uint)Math.Round(pixels / (96.0 * scale) * 25.4);
        try
        {
            _rdp.Ocx.UpdateSessionDisplaySettings((uint)target.Width, (uint)target.Height,
                Millimetres(target.Width, dpi.DpiScaleX), Millimetres(target.Height, dpi.DpiScaleY), 0u, desktopScale, deviceScale);
            _verifyResizeTimer.Interval = TimeSpan.FromMilliseconds(_resizeAttempts <= 3 ? 1500 : 3000);
            _verifyResizeTimer.Start();
        }
        catch (Exception ex) when (_resizeAttempts < MaxResizeAttempts)
        {
            // Often "not ready yet" right after sign-in: try again shortly.
            Log.Info($"Resize of {Connection.Endpoint} to {target.Width}x{target.Height} not accepted yet: {ex.Message}");
            _verifyResizeTimer.Start();
        }
        catch (Exception ex)
        {
            Log.Info($"Dynamic resize not available for {Connection.Endpoint}, scaling to fit instead: {ex.Message}");
            _dynamicResize = false;
        }
    }

    // ------------------------------------------------------------------ control events

    private void OnConnected()
    {
        if (_disposed) return;
        Overlay.Visibility = Visibility.Collapsed;
        Host.Visibility = Visibility.Visible;
        SetState(SessionState.Connected);
        if (IsVisible) FocusContent();
    }

    private void OnLoginComplete()
    {
        if (_disposed) return;
        _loggedIn = true;
        _login.MarkSucceeded();
        var tab = CurrentDesktopSize();
        Log.Info($"RDP {Connection.Endpoint}: signed in at {_remoteSize.Width}x{_remoteSize.Height}; tab is {tab.Width}x{tab.Height}.");
        _resizeTimer.Stop();
        _resizeTimer.Start(); // the tab may have changed size while signing in
    }

    private void OnDisconnected(int reason)
    {
        if (_disposed) return;
        var wasConnected = State == SessionState.Connected;
        _loggedIn = false;
        _resizeTimer.Stop();
        _verifyResizeTimer.Stop();
        Host.Visibility = Visibility.Hidden;

        if (_reconnectAfterDisconnect)
        {
            _reconnectAfterDisconnect = false;
            SetState(SessionState.Disconnected);
            _ = ConnectAsync();
            return;
        }

        if (_cancelRequested && !wasConnected)
        {
            _cancelRequested = false;
            SetState(SessionState.Disconnected);
            ShowMessage("Not connected", "Connection cancelled.");
            return;
        }

        var description = DescribeDisconnect(reason);
        Log.Info($"RDP {Connection.Endpoint} disconnected: reason {reason} ({description})");
        SetState(SessionState.Disconnected);

        if (wasConnected && RdpSettings.IsNormalEnd(reason))
        {
            if (AppServices.Settings.CloseTabOnExit)
            {
                CloseRequested?.Invoke(this, EventArgs.Empty);
                return;
            }
            ShowMessage("Session ended", description);
            return;
        }

        if (!wasConnected) _login.ForgetPrompted();
        ShowMessage(wasConnected ? "Disconnected" : "Couldn't connect", description);
    }

    private string DescribeDisconnect(int reason)
    {
        string text = "";
        try
        {
            var ocx = _rdp.Ocx;
            uint extended = Convert.ToUInt32(ocx.ExtendedDisconnectReason);
            text = (string)ocx.GetErrorDescription((uint)reason, extended) ?? "";
        }
        catch (Exception ex)
        {
            Log.Info($"No RDP error description for {reason}: {ex.Message}");
        }
        text = text.Trim();
        return text.Length > 0 ? text : $"The connection ended (code {reason}).";
    }

    // ------------------------------------------------------------------ UI

    private void ShowMessage(string title, string text, bool connecting = false)
    {
        Host.Visibility = Visibility.Hidden;
        Overlay.Visibility = Visibility.Visible;
        OverlayTitle.Text = title;
        OverlayText.Text = text;
        OverlayText.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
        CancelButton.Visibility = connecting ? Visibility.Visible : Visibility.Collapsed;
        ConnectButton.Visibility = connecting ? Visibility.Collapsed : Visibility.Visible;
        ExternalButton.Visibility = connecting ? Visibility.Collapsed : Visibility.Visible;
    }

    private void Fail(string title, string text)
    {
        if (_disposed) return;
        _loggedIn = false;
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
        if (State == SessionState.Connected)
        {
            try
            {
                Host.Focus();
                _rdp.Focus();
            }
            catch (Exception ex)
            {
                Log.Info($"Could not focus the Remote Desktop control: {ex.Message}");
            }
        }
        else if (ConnectButton.IsVisible)
        {
            ConnectButton.Focus();
        }
    }

    /// <summary>Full screen with the standard Remote Desktop connection bar (Ctrl+Alt+Break also toggles it).</summary>
    public void EnterFullScreen()
    {
        if (_disposed || State != SessionState.Connected) return;
        try { _rdp.Ocx.FullScreen = true; }
        catch (Exception ex) { Log.Error("Full screen failed", ex); }
    }

    public void Reconnect()
    {
        if (_disposed) return;
        if (State == SessionState.Connected)
        {
            _reconnectAfterDisconnect = true;
            try { _rdp.Ocx.Disconnect(); }
            catch (Exception ex)
            {
                Log.Error("RDP disconnect failed", ex);
                _reconnectAfterDisconnect = false;
            }
            return;
        }
        if (State != SessionState.Connecting) _ = ConnectAsync();
    }

    private void Connect_Click(object sender, RoutedEventArgs e) => Reconnect();

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (State != SessionState.Connecting) return;
        try
        {
            if (_rdp.IsReady && Convert.ToInt32(_rdp.Ocx.Connected) != 0)
            {
                _cancelRequested = true;
                _rdp.Ocx.Disconnect(); // OnDisconnected shows the result
                return;
            }
        }
        catch (Exception ex)
        {
            Log.Info($"Cancel RDP connect: {ex.Message}");
        }
        Fail("Not connected", "Connection cancelled.");
    }

    private async void External_Click(object sender, RoutedEventArgs e) =>
        await RdpLauncher.OpenAsync(Window.GetWindow(this), Connection);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _resizeTimer.Stop();
        _verifyResizeTimer.Stop();
        try
        {
            if (_rdp.IsReady && Convert.ToInt32(_rdp.Ocx.Connected) != 0) _rdp.Ocx.Disconnect();
        }
        catch (Exception ex)
        {
            Log.Info($"RDP disconnect on close: {ex.Message}");
        }
        try
        {
            Host.Child = null;
            _rdp.Dispose();
            Host.Dispose();
        }
        catch (Exception ex)
        {
            Log.Error("Disposing the Remote Desktop control failed", ex);
        }
    }
}

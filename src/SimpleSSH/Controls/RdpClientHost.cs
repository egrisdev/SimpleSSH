using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SimpleSSH.Controls;

/// <summary>
/// The Windows Remote Desktop ActiveX control (mstscax.dll, part of Windows), hosted without generated interop
/// assemblies: properties and methods are called late-bound through IDispatch, events arrive through
/// <see cref="IMsTscAxEvents"/>.
/// </summary>
internal sealed class RdpClientHost : AxHost
{
    // MsRdpClient9NotSafeForScripting: Windows 8.1 / Server 2012 R2 and later. "Not safe for scripting" is the
    // variant that accepts a password from the host application.
    private const string ClassId = "8b918b82-7985-4c24-89df-c33ad2bbfbcd";

    private readonly EventSink _sink;
    private ConnectionPointCookie? _cookie;

    public RdpClientHost() : base(ClassId)
    {
        _sink = new EventSink(this);
    }

    /// <summary>The control's IMsRdpClient9 automation object. Only valid once the control has been created.</summary>
    public dynamic Ocx => GetOcx() ?? throw new InvalidOperationException("The Remote Desktop control isn't ready yet.");

    public bool IsReady => GetOcx() is not null;

    /// <summary>Sets an IMsRdpExtendedSettings value (e.g. "DesktopScaleFactor"). Returns false if it isn't supported.</summary>
    public bool TrySetExtendedProperty(string name, object value)
    {
        try
        {
            if (GetOcx() is not IMsRdpExtendedSettings settings) return false;
            settings.SetProperty(name, ref value);
            return true;
        }
        catch (COMException)
        {
            return false;
        }
    }

    public event Action? Connecting;
    public event Action? Connected;
    public event Action? LoginComplete;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;
    public event Action? EnterFullScreen;
    public event Action? LeaveFullScreen;
    public event Action? RequestMinimize;
    /// <summary>The remote desktop's resolution changed (after a resize request, or set by the server).</summary>
    public event Action<int, int>? RemoteDesktopSizeChanged;
    public event Action? AutoReconnected;

    protected override void CreateSink()
    {
        try
        {
            _cookie = new ConnectionPointCookie(GetOcx() ?? throw new InvalidOperationException("The Remote Desktop control has not been created."), _sink, typeof(IMsTscAxEvents));
        }
        catch (Exception ex)
        {
            Services.Log.Error("Could not subscribe to Remote Desktop events", ex);
        }
    }

    protected override void DetachSink()
    {
        try { _cookie?.Disconnect(); } catch { /* the control is going away anyway */ }
        _cookie = null;
    }

    /// <summary>Receives the control's events (IMsTscAxEvents dispinterface). Only the events we use are declared.</summary>
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    public sealed class EventSink : IMsTscAxEvents
    {
        private readonly RdpClientHost _owner;

        internal EventSink(RdpClientHost owner) => _owner = owner;

        public void OnConnecting() => _owner.Connecting?.Invoke();
        public void OnConnected() => _owner.Connected?.Invoke();
        public void OnLoginComplete() => _owner.LoginComplete?.Invoke();
        public void OnDisconnected(int discReason) => _owner.Disconnected?.Invoke(discReason);
        public void OnEnterFullScreenMode() => _owner.EnterFullScreen?.Invoke();
        public void OnLeaveFullScreenMode() => _owner.LeaveFullScreen?.Invoke();
        public void OnFatalError(int errorCode) => _owner.FatalError?.Invoke(errorCode);
        public void OnRequestContainerMinimize() => _owner.RequestMinimize?.Invoke();
        public void OnLogonError(int lError) => _owner.LogonError?.Invoke(lError);
        public void OnRemoteDesktopSizeChange(int width, int height) => _owner.RemoteDesktopSizeChanged?.Invoke(width, height);
        public void OnAutoReconnected() => _owner.AutoReconnected?.Invoke();
    }
}

/// <summary>Event interface of the Remote Desktop control (DISPIDs from mstscax.dll's type library).</summary>
[ComVisible(true)]
[Guid("336d5562-efa8-482e-8cb3-c5c0fc7a7db6")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
public interface IMsTscAxEvents
{
    [DispId(1)] void OnConnecting();
    [DispId(2)] void OnConnected();
    [DispId(3)] void OnLoginComplete();
    [DispId(4)] void OnDisconnected(int discReason);
    [DispId(5)] void OnEnterFullScreenMode();
    [DispId(6)] void OnLeaveFullScreenMode();
    [DispId(10)] void OnFatalError(int errorCode);
    [DispId(14)] void OnRequestContainerMinimize();
    [DispId(12)] void OnRemoteDesktopSizeChange(int width, int height);
    [DispId(22)] void OnLogonError(int lError);
    [DispId(33)] void OnAutoReconnected();
}

/// <summary>IMsRdpExtendedSettings (IUnknown-based, so it can't be reached through IDispatch).</summary>
[ComImport]
[Guid("302d8188-0052-4807-806a-362b628f9ac5")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMsRdpExtendedSettings
{
    void SetProperty([MarshalAs(UnmanagedType.BStr)] string name, [In] ref object value);

    [return: MarshalAs(UnmanagedType.Struct)]
    object GetProperty([MarshalAs(UnmanagedType.BStr)] string name);
}

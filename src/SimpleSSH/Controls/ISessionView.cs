using SimpleSSH.Core.Models;

namespace SimpleSSH.Controls;

public enum SessionState
{
    Idle,
    Connecting,
    Connected,
    Disconnected,
}

/// <summary>What the main window needs from a tab's content (a terminal or a file browser).</summary>
public interface ISessionView : IDisposable
{
    Connection Connection { get; }

    /// <summary>Shown after the connection name in the tab header, e.g. "Files". Empty for terminals.</summary>
    string Kind { get; }

    SessionState State { get; }

    bool IsActive { get; }

    event EventHandler? StateChanged;

    /// <summary>The tab asks to be closed (e.g. the shell exited normally).</summary>
    event EventHandler? CloseRequested;

    void Reconnect();

    void FocusContent();
}

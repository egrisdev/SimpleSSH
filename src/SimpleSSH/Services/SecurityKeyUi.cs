using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SimpleSSH.Core.Storage;
using SimpleSSH.Views;

namespace SimpleSSH.Services;

/// <summary>Unlocking and locking saved passwords that are protected with a security key.</summary>
internal static class SecurityKeyUi
{
    private static Task<bool>? _unlocking;

    private static ConnectionStore Store => AppServices.Connections;

    /// <summary>
    /// True if saved passwords can be read now (no security key, or already unlocked). Otherwise shows the unlock
    /// prompt; callers asking while it is open share it. Must be called on the UI thread.
    /// </summary>
    public static Task<bool> EnsureUnlockedAsync(Window? owner, string? reason = null)
    {
        if (!Store.IsLocked) return Task.FromResult(true);
        return _unlocking ??= ShowAsync();

        async Task<bool> ShowAsync()
        {
            try
            {
                await Task.Yield(); // let _unlocking be set before the dialog's nested message loop runs
                if (!Store.IsLocked) return true;
                var dlg = new UnlockDialog(reason) { Owner = VisibleOwner(owner) };
                dlg.ShowDialog();
                return !Store.IsLocked;
            }
            finally
            {
                _unlocking = null;
            }
        }
    }

    /// <summary>Asks a registered key for its secret (Windows Security prompt: touch + PIN) without blocking the UI.</summary>
    public static Task<WebAuthn.Secret> GetSecretAsync(Window owner, string relyingParty, IReadOnlyList<byte[]> allow, byte[] salt)
    {
        var hwnd = new WindowInteropHelper(owner).Handle;
        return Task.Run(() => WebAuthn.GetSecret(hwnd, relyingParty, allow, salt));
    }

    /// <summary>Registers a new key (Windows Security prompt: touch + PIN) without blocking the UI.</summary>
    public static Task<WebAuthn.Registration> RegisterAsync(Window owner, string relyingParty, IReadOnlyList<byte[]> exclude)
    {
        var hwnd = new WindowInteropHelper(owner).Handle;
        return Task.Run(() => WebAuthn.Register(hwnd, relyingParty, exclude));
    }

    public static void StartWatchingWindowsLock() => SystemEvents.SessionSwitch += OnSessionSwitch;

    public static void StopWatchingWindowsLock() => SystemEvents.SessionSwitch -= OnSessionSwitch;

    private static void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason != SessionSwitchReason.SessionLock) return;
        // Raised on a system thread.
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            if (!AppServices.Settings.LockWhenWindowsLocks || Store.Vault is not { IsUnlocked: true }) return;
            Store.Lock();
            Log.Info("Saved passwords locked (Windows locked).");
        });
    }

    private static Window? VisibleOwner(Window? owner)
    {
        owner ??= UiPrompts.Owner;
        return owner is { IsVisible: true } ? owner : Application.Current?.MainWindow is { IsVisible: true } main ? main : null;
    }
}

using System.Security.Cryptography;
using System.Windows;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Storage;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>
/// Unlocks passwords protected with a security key. The Windows Security prompt opens right away, so normally
/// this is one touch (plus the key's PIN). The recovery key is the fallback.
/// </summary>
public partial class UnlockDialog : Window
{
    private const string TouchPrompt = "Touch your security key and enter its PIN in the Windows Security window.";
    private const string OtherAccountText =
        "Your security key was set up under another Windows account or on another PC. " +
        "Unlock with your recovery key; SimpleSSH then offers to set up the key here too.";
    private const string RemoteText =
        "You're connected through Remote Desktop, and security keys can't reach SimpleSSH that way. " +
        "Enter your recovery key to unlock. Back at this PC, your security key works as usual.";

    private bool _busy;
    private bool _started;
    private bool _closed;
    /// <summary>Bumped to stop waiting for a key operation (Windows may keep its prompt open regardless).</summary>
    private int _operation;

    public UnlockDialog(string? reason)
    {
        InitializeComponent();
        if (!string.IsNullOrWhiteSpace(reason))
        {
            Reason.Text = reason;
            Reason.Visibility = Visibility.Visible;
        }
        Closing += (_, _) =>
        {
            if (_busy) Abandon();
        };
        Closed += (_, _) => _closed = true;
        ContentRendered += async (_, _) =>
        {
            if (_started) return;
            _started = true;
            if (Store.Vault is { } vault && vault.UsableCredentialIds.Count == 0) ShowRecovery(OtherAccountText);
            else if (RemoteSession.IsActive) ShowRemote();
            else await UnlockWithKeyAsync();
        };
    }

    private static ConnectionStore Store => AppServices.Connections;

    private async void Key_Click(object sender, RoutedEventArgs e) => await UnlockWithKeyAsync();

    private async Task UnlockWithKeyAsync()
    {
        if (Store.Vault is not { IsUnlocked: false } vault)
        {
            DialogResult = true;
            return;
        }
        var allow = vault.UsableCredentialIds;
        if (allow.Count == 0)
        {
            ShowRecovery(OtherAccountText);
            return;
        }

        bool unlocked = false;
        SetBusy(true, TouchPrompt);
        var op = ++_operation;
        try
        {
            var secret = await SecurityKeyUi.GetSecretAsync(this, vault.RelyingParty, allow, vault.Salt);
            try
            {
                // A touch after "Not now" still unlocks: the user did it on purpose. Only the dialog is gone.
                var result = Store.Unlock(secret.CredentialId, secret.Value);
                if (op != _operation) return;
                switch (result)
                {
                    case KeyUnlockResult.Unlocked:
                        unlocked = true;
                        break;
                    case KeyUnlockResult.OtherWindowsAccount:
                        ShowRecovery(OtherAccountText);
                        break;
                    default:
                        ShowRecovery("This security key could not open the saved passwords (was its PIN reset?). Use your recovery key.");
                        break;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret.Value);
            }
        }
        catch (WebAuthnException ex) when (ex.Cancelled)
        {
            if (op == _operation) ShowError("Not unlocked. Try again, or use your recovery key.");
        }
        catch (Exception ex)
        {
            Log.Error("Unlocking with the security key failed", ex);
            if (op == _operation)
            {
                if (RemoteSession.IsActive) ShowRecovery("Your security key couldn't be reached through Remote Desktop. Use your recovery key instead.");
                else ShowError(ex.Message);
            }
        }
        finally
        {
            if (op == _operation) SetBusy(false);
        }
        if (unlocked && !_closed) DialogResult = true;
    }

    /// <summary>
    /// Over Remote Desktop the security key is usually out of reach (Windows App on a Mac, iPad or Android doesn't pass
    /// it on to apps), so the recovery key comes first and the key stays one click away.
    /// </summary>
    private void ShowRemote()
    {
        var client = RemoteSession.ClientDescription();
        Log.Info($"Unlock requested over Remote Desktop{(client.Length > 0 ? $" ({client})" : "")}: asking for the recovery key.");
        StatusText.Text = RemoteText;
        ShowRecovery(null);
        KeyButtons.Visibility = Visibility.Collapsed;
        TryKeyLinkText.Visibility = Visibility.Visible;
    }

    private void ShowRecovery_Click(object sender, RoutedEventArgs e) => ShowRecovery(null);

    private void ShowRecovery(string? message)
    {
        if (message is not null) ShowError(message);
        RecoveryPanel.Visibility = Visibility.Visible;
        RecoveryLinkText.Visibility = Visibility.Collapsed;
        NotNowButton.Visibility = Visibility.Collapsed;
        KeyButton.IsDefault = false;
        KeyButton.Content = "Try security key again";
        RecoveryButton.IsDefault = true;
        if (Store.Vault?.UsableCredentialIds.Count == 0) KeyButtons.Visibility = Visibility.Collapsed;
        RecoveryBox.Focus();
    }

    private async void Recovery_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            Abandon(); // the Windows Security prompt may still be open; stop waiting for it
            StatusText.Text = "Enter the recovery key you saved in your password manager.";
        }
        if (string.IsNullOrWhiteSpace(RecoveryBox.Text))
        {
            RecoveryBox.Focus();
            return;
        }
        if (!SecurityKeyVault.TryParseRecoveryKey(RecoveryBox.Text, out _))
        {
            ShowError("That is not a recovery key. It has 32 letters and digits, like ABCD-EFGH-…");
            RecoveryBox.Focus();
            return;
        }
        if (!Store.UnlockWithRecoveryKey(RecoveryBox.Text))
        {
            ShowError("That recovery key does not match. Check for typos, or that it is the newest one you saved.");
            RecoveryBox.Focus();
            RecoveryBox.SelectAll();
            return;
        }
        RecoveryBox.Clear();
        Log.Info("Saved passwords unlocked with the recovery key.");

        if (!RemoteSession.IsActive && Store.Vault is { OtherAccountKeys.Count: > 0 } vault &&
            MessageBox.Show(this,
                "Unlocked.\n\nYour security key was set up under another Windows account or on another PC. " +
                "Touch it now so it unlocks SimpleSSH here too?",
                "Security key", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            await SetUpKeyHereAsync(vault);
        }
        DialogResult = true;
    }

    private async Task SetUpKeyHereAsync(SecurityKeyVault vault)
    {
        SetBusy(true, TouchPrompt);
        var op = ++_operation;
        try
        {
            var others = vault.OtherAccountKeys.Select(k => Convert.FromBase64String(k.CredentialId)).ToList();
            var secret = await SecurityKeyUi.GetSecretAsync(this, vault.RelyingParty, others, vault.Salt);
            try
            {
                vault.AddKey(secret.CredentialId, secret.Value, "");
                Store.SaveSecurityKeyChanges();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret.Value);
            }
        }
        catch (WebAuthnException ex) when (ex.Cancelled)
        {
            // Skipped; the next recovery-key unlock offers it again.
        }
        catch (Exception ex)
        {
            Log.Error("Setting up the security key for this account failed", ex);
            if (!_closed) MessageBox.Show(this, $"Could not set up the security key here:\n{ex.Message}", "Security key", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (op == _operation) SetBusy(false);
        }
    }

    private void NotNow_Click(object sender, RoutedEventArgs e) => Close();

    private void Abandon()
    {
        _operation++;
        WebAuthn.CancelCurrent();
        SetBusy(false);
    }

    private void SetBusy(bool busy, string? status = null)
    {
        _busy = busy;
        KeyButton.IsEnabled = !busy;
        if (status is not null) StatusText.Text = status;
        if (busy) ErrorText.Visibility = Visibility.Collapsed;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}

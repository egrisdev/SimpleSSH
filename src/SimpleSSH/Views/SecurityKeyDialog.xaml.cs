using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Storage;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>Turns security-key protection on or off, manages keys, the recovery key and when to lock.</summary>
public partial class SecurityKeyDialog : Window
{
    private const string FirstTouch = "Step 1 of 2: touch your security key and enter its PIN in the Windows Security window.";
    private const string SecondTouch = "Step 2 of 2: touch your security key again.";

    private bool _busy;
    private bool _loading;
    /// <summary>Bumped to abandon a running key operation: its late result is then ignored.</summary>
    private int _operation;

    public SecurityKeyDialog()
    {
        InitializeComponent();
        Closing += (_, _) =>
        {
            if (_busy) Abandon();
        };
        Store.LockChanged += Store_LockChanged;
        Closed += (_, _) => Store.LockChanged -= Store_LockChanged;
        Refresh();
    }

    private static ConnectionStore Store => AppServices.Connections;

    private void Store_LockChanged(object? sender, EventArgs e) => Refresh();

    private void Refresh()
    {
        var vault = Store.Vault;
        OffPanel.Visibility = vault is null ? Visibility.Visible : Visibility.Collapsed;
        OnPanel.Visibility = vault is null ? Visibility.Collapsed : Visibility.Visible;
        if (vault is null) return;

        StateText.Text = vault.IsUnlocked ? "Unlocked" : "Locked";
        StateText.Foreground = new SolidColorBrush(vault.IsUnlocked ? Color.FromRgb(0x16, 0x65, 0x34) : Color.FromRgb(0x92, 0x40, 0x0E));
        StateBadge.Background = new SolidColorBrush(vault.IsUnlocked ? Color.FromRgb(0xDC, 0xFC, 0xE7) : Color.FromRgb(0xFE, 0xF3, 0xC7));

        var selected = (KeyList.SelectedItem as ListBoxItem)?.Tag as string;
        var elsewhere = vault.OtherAccountKeys.Select(k => k.CredentialId).ToHashSet();
        KeyList.Items.Clear();
        foreach (var slot in vault.Header.Keys)
        {
            var name = string.IsNullOrWhiteSpace(slot.Name) ? "Security key" : slot.Name;
            var text = $"{name}   ·   added {slot.Added.LocalDateTime:d}";
            if (elsewhere.Contains(slot.CredentialId)) text += "   ·   set up on another PC or Windows account";
            var item = new ListBoxItem { Content = text, Tag = slot.CredentialId, Padding = new Thickness(4, 3, 4, 3) };
            KeyList.Items.Add(item);
            if (slot.CredentialId == selected) item.IsSelected = true;
        }
        RemoveKeyButton.IsEnabled = KeyList.SelectedItem is not null && vault.Header.Keys.Count > 1;

        _loading = true;
        LockOnWindowsLockRadio.IsChecked = AppServices.Settings.LockWhenWindowsLocks;
        LockOnCloseRadio.IsChecked = !AppServices.Settings.LockWhenWindowsLocks;
        _loading = false;
    }

    // ---- Turn on / off -------------------------------------------------------------------

    private async void TurnOn_Click(object sender, RoutedEventArgs e)
    {
        if (!WebAuthn.IsSupported(out var reason))
        {
            ShowError(reason);
            return;
        }

        SecurityKeyVault? vault = null;
        string? recoveryKey = null;
        SetBusy(true, FirstTouch);
        var op = ++_operation;
        try
        {
            var rp = SecurityKeyVault.DefaultRelyingParty;
            var registration = await SecurityKeyUi.RegisterAsync(this, rp, Array.Empty<byte[]>());
            if (op != _operation) return;
            ShowStatus(SecondTouch);
            var salt = SecurityKeyVault.NewSalt();
            var secret = await SecurityKeyUi.GetSecretAsync(this, rp, new[] { registration.CredentialId }, salt);
            try
            {
                if (op != _operation) return;
                vault = SecurityKeyVault.Create(salt, registration.CredentialId, secret.Value, "Security key",
                    AppServices.KeySlotProtector, out recoveryKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret.Value);
            }
        }
        catch (WebAuthnException ex) when (ex.Cancelled)
        {
            if (op == _operation) ShowError("Cancelled. Nothing was changed.");
        }
        catch (Exception ex)
        {
            Log.Error("Setting up the security key failed", ex);
            if (op == _operation) ShowError(KeyError(ex));
        }
        finally
        {
            if (op == _operation) SetBusy(false);
        }
        if (vault is null || recoveryKey is null || op != _operation || !IsVisible)
        {
            vault?.Lock();
            return;
        }

        if (new RecoveryKeyDialog(recoveryKey, replacing: false) { Owner = this }.ShowDialog() != true)
        {
            vault.Lock();
            ShowStatus("Not turned on. Nothing was changed.");
            return;
        }
        try
        {
            Store.EnableSecurityKey(vault);
            Log.Info("Security key protection turned on.");
            ShowStatus("Turned on. Saved passwords now need your security key.");
        }
        catch (Exception ex)
        {
            vault.Lock();
            Log.Error("Turning on security key protection failed", ex);
            ShowError($"Could not save the connections file: {ex.Message}");
        }
        Refresh();
    }

    private async void TurnOff_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this,
                "Turn off security key protection?\n\nSaved passwords will be encrypted with your Windows account only, " +
                "and no longer need the security key.",
                "Security key", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock first to turn off the security key.")) return;
        try
        {
            Store.DisableSecurityKey();
            Log.Info("Security key protection turned off.");
            ShowStatus("Turned off. Saved passwords are encrypted with your Windows account.");
        }
        catch (Exception ex)
        {
            Log.Error("Turning off security key protection failed", ex);
            ShowError($"Could not save the connections file: {ex.Message}");
        }
        Refresh();
    }

    // ---- Keys ----------------------------------------------------------------------------

    private void KeyList_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        RemoveKeyButton.IsEnabled = KeyList.SelectedItem is not null && Store.Vault?.Header.Keys.Count > 1;

    private async void AddKey_Click(object sender, RoutedEventArgs e)
    {
        if (!WebAuthn.IsSupported(out var reason))
        {
            ShowError(reason);
            return;
        }
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock first to add a key.")) return;
        if (Store.Vault is not { } vault) return;
        var name = InputDialog.Ask(this, "Add a security key", "Name for the new key (e.g. \"Spare YubiKey\"):", $"Security key {vault.Header.Keys.Count + 1}");
        if (name is null) return;

        SetBusy(true, "Step 1 of 2: insert the new key, touch it and enter its PIN in the Windows Security window.");
        var op = ++_operation;
        try
        {
            var registered = vault.Header.Keys.Select(k => Convert.FromBase64String(k.CredentialId)).ToList();
            var registration = await SecurityKeyUi.RegisterAsync(this, vault.RelyingParty, registered);
            if (op != _operation) return;
            ShowStatus("Step 2 of 2: touch the new key again.");
            var secret = await SecurityKeyUi.GetSecretAsync(this, vault.RelyingParty, new[] { registration.CredentialId }, vault.Salt);
            try
            {
                if (op != _operation) return;
                vault.AddKey(registration.CredentialId, secret.Value, name);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret.Value);
            }
            Store.SaveSecurityKeyChanges();
            Log.Info("Security key added.");
            ShowStatus($"Added \"{name}\". Either key now unlocks SimpleSSH.");
        }
        catch (WebAuthnException ex) when (ex.Cancelled)
        {
            if (op == _operation) ShowError("Cancelled. No key was added.");
        }
        catch (Exception ex)
        {
            Log.Error("Adding a security key failed", ex);
            if (op == _operation) ShowError(KeyError(ex));
        }
        finally
        {
            if (op == _operation) SetBusy(false);
        }
        Refresh();
    }

    private async void RemoveKey_Click(object sender, RoutedEventArgs e)
    {
        if (Store.Vault is not { } vault || (KeyList.SelectedItem as ListBoxItem)?.Tag is not string id) return;
        var slot = vault.Header.Keys.FirstOrDefault(k => k.CredentialId == id);
        if (slot is null) return;
        if (vault.Header.Keys.Count <= 1)
        {
            ShowError("This is the only key. To stop using a security key, choose Turn off.");
            return;
        }
        if (MessageBox.Show(this, $"Remove \"{slot.Name}\"? It will no longer unlock SimpleSSH." + Environment.NewLine + Environment.NewLine +
                "If the key was lost or stolen, choose New recovery key afterwards: that locks your saved passwords again " +
                "with a new key, which the removed key can't open even with an old copy of the file.", "Security key",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock first to remove a key.")) return;
        try
        {
            if (vault.RemoveKey(id)) Store.SaveSecurityKeyChanges();
            ShowStatus($"Removed \"{slot.Name}\".");
        }
        catch (Exception ex)
        {
            Log.Error("Removing a security key failed", ex);
            ShowError($"Could not save the connections file: {ex.Message}");
        }
        Refresh();
    }

    // ---- Recovery key and lock options ---------------------------------------------------

    /// <summary>
    /// A new recovery key, with everything locked again under a new data key: the old recovery key (and any key
    /// removed earlier) then can't open the passwords, even with an old copy of the file. Each key is touched once,
    /// because only the key itself can lock the new data key for it.
    /// </summary>
    private async void NewRecovery_Click(object sender, RoutedEventArgs e)
    {
        if (!WebAuthn.IsSupported(out var reason))
        {
            ShowError(reason);
            return;
        }
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock first to make a new recovery key.")) return;
        if (Store.Vault is not { } vault) return;

        var otherAccount = vault.OtherAccountKeys.ToHashSet();
        var keys = vault.Header.Keys.Where(k => !otherAccount.Contains(k)).ToList();
        var elsewhere = vault.Header.Keys.Count - keys.Count;
        if (keys.Count == 0)
        {
            ShowError("None of the keys was set up on this PC. Add your key here first (Add another key…).");
            return;
        }
        var text = "SimpleSSH locks your saved passwords again with a new recovery key. The previous recovery key will no " +
                   "longer open them, not even in older copies or backups of the connections file.\n\n" +
                   (keys.Count == 1 ? "Touch your security key when asked." : $"Touch each of your {keys.Count} security keys when asked.") +
                   (elsewhere > 0 ? $"\n\n{elsewhere} key(s) set up on another PC or Windows account will be removed. Add them again there." : "");
        if (MessageBox.Show(this, text, "New recovery key", MessageBoxButton.OKCancel, MessageBoxImage.Information, MessageBoxResult.OK) != MessageBoxResult.OK)
            return;

        var secrets = new List<(byte[] CredentialId, byte[] HmacSecret)>();
        SecurityKeyVault? next = null;
        string? recoveryKey = null;
        SetBusy(true);
        var op = ++_operation;
        try
        {
            for (int i = 0; i < keys.Count; i++)
            {
                var name = string.IsNullOrWhiteSpace(keys[i].Name) ? "your security key" : $"\"{keys[i].Name}\"";
                ShowStatus(keys.Count == 1
                    ? "Touch your security key and enter its PIN in the Windows Security window."
                    : $"Key {i + 1} of {keys.Count}: insert {name}, touch it and enter its PIN in the Windows Security window.");
                var id = Convert.FromBase64String(keys[i].CredentialId);
                var secret = await SecurityKeyUi.GetSecretAsync(this, vault.RelyingParty, new[] { id }, vault.Salt);
                secrets.Add((id, secret.Value));
                if (op != _operation) return;
            }
            next = vault.Rekey(secrets, out recoveryKey);
        }
        catch (WebAuthnException ex) when (ex.Cancelled)
        {
            if (op == _operation) ShowError("Cancelled. Nothing was changed; the previous recovery key still works.");
        }
        catch (Exception ex)
        {
            Log.Error("Making a new recovery key failed", ex);
            if (op == _operation) ShowError(KeyError(ex));
        }
        finally
        {
            foreach (var (_, secret) in secrets) CryptographicOperations.ZeroMemory(secret);
            if (op == _operation) SetBusy(false);
        }
        if (next is null || recoveryKey is null || op != _operation || !IsVisible)
        {
            next?.Lock();
            return;
        }

        if (new RecoveryKeyDialog(recoveryKey, replacing: true) { Owner = this }.ShowDialog() != true)
        {
            next.Lock();
            ShowStatus("Kept the previous recovery key.");
            return;
        }
        try
        {
            Store.EnableSecurityKey(next); // encrypts every saved password again with the new data key
            Log.Info("Recovery key replaced; saved passwords locked again with a new key.");
            ShowStatus("New recovery key saved. The previous one no longer opens your saved passwords.");
        }
        catch (Exception ex)
        {
            next.Lock();
            Log.Error("Saving the new recovery key failed", ex);
            ShowError($"Could not save the connections file: {ex.Message}. The previous recovery key still works.");
        }
        Refresh();
    }

    private void LockWhen_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        AppServices.Settings.LockWhenWindowsLocks = LockOnWindowsLockRadio.IsChecked == true;
        AppServices.SaveSettings();
    }

    // ---- Helpers -------------------------------------------------------------------------

    /// <summary>While the Windows Security prompt is open this is "Cancel": it closes the prompt, not the dialog.</summary>
    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy)
        {
            Close();
            return;
        }
        Abandon();
        ShowError("Cancelled. Nothing was changed. If the Windows Security window is still open, close it there.");
    }

    /// <summary>
    /// Stops waiting for the key. Windows is asked to close its prompt, but it may keep showing it until the user
    /// closes it; whatever it returns afterwards is ignored.
    /// </summary>
    private void Abandon()
    {
        _operation++;
        WebAuthn.CancelCurrent();
        SetBusy(false);
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != System.Windows.Input.Key.Escape) return;
        e.Handled = true;
        CloseButton_Click(sender, e);
    }

    private void SetBusy(bool busy, string? status = null)
    {
        _busy = busy;
        OffPanel.IsEnabled = OnPanel.IsEnabled = !busy;
        CloseButton.Content = busy ? "Cancel" : "Close";
        if (status is not null) ShowStatus(status);
    }

    private void ShowStatus(string text)
    {
        StatusText.Text = text;
        StatusText.Visibility = Visibility.Visible;
        ErrorText.Visibility = Visibility.Collapsed;
    }

    /// <summary>Over Remote Desktop the key usually can't be reached at all; say so instead of a Windows error code.</summary>
    private static string KeyError(Exception ex) => RemoteSession.IsActive
        ? "Security keys can't reach SimpleSSH through Remote Desktop. Set up your key while you're at this PC."
        : ex.Message;

    private void ShowError(string text)
    {
        ErrorText.Text = text;
        ErrorText.Visibility = Visibility.Visible;
        StatusText.Visibility = Visibility.Collapsed;
    }
}

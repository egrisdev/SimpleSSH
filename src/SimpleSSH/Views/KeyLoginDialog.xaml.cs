using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>
/// "Switch to key login": makes a key for one server, installs it over the login that works today, proves a key-only
/// login, saves the key in SimpleSSH, and then (optionally) turns off SSH password logins on the server.
/// </summary>
public partial class KeyLoginDialog : Window
{
    private enum StepState { Pending, Running, Done, Failed }

    private static readonly Brush Pending = new SolidColorBrush(Color.FromRgb(0x9C, 0xA3, 0xAF));
    private static readonly Brush Running = new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0xBD));
    private static readonly Brush Done = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A));
    private static readonly Brush Failed = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));

    private readonly Guid _id;
    private readonly SessionLogin _login;
    private SshConnectOptions? _options;
    private string? _privateKey;
    private string? _publicKey;
    private string? _password;
    private bool _keyReady;
    private bool _lockedDown;
    private bool _busy;

    public KeyLoginDialog(Connection connection)
    {
        InitializeComponent();
        _id = connection.Id;
        _login = new SessionLogin(connection);
        _privateKey = connection.PrivateKey;
        _publicKey = connection.PublicKey;

        Heading.Text = $"Switch {connection.DisplayName} to key login";
        SubHeading.Text = string.IsNullOrWhiteSpace(connection.Username) ? connection.Endpoint : $"{connection.Username}@{connection.Endpoint}";
        if (!string.IsNullOrEmpty(_privateKey))
        {
            // Already has a key in SimpleSSH: re-check it (adding it again is harmless) and offer the lock-down.
            Detail1.Text = "This connection already has a key in SimpleSSH" + Fingerprint() + ". It is reused.";
            StartButton.Content = "Check key login";
            Title = "Key login";
            Heading.Text = $"Key login for {connection.DisplayName}";
        }
        Closing += OnClosing;
    }

    private static Core.Storage.ConnectionStore Store => AppServices.Connections;

    /// <summary>Set when the person chose to add the key by hand (the server refuses passwords); the dialog has closed.</summary>
    public bool ByHandRequested { get; private set; }

    private void ByHand_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        ByHandRequested = true;
        Close();
    }

    private Connection? Current => Store.Find(_id);

    // ---- Steps 1-3 -----------------------------------------------------------------------------

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (Current is not { } connection) return;
        ErrorText.Visibility = Visibility.Collapsed;
        SetBusy(true);
        int step = 1;
        try
        {
            Mark(1, StepState.Running);
            if (string.IsNullOrEmpty(_privateKey))
            {
                var comment = $"SimpleSSH {Environment.UserName}@{Environment.MachineName}";
                var pair = await Task.Run(() => SshKeys.CreateEd25519(comment));
                (_privateKey, _publicKey) = (pair.PrivateKey, pair.PublicKey);
                Detail1.Text = "Created" + Fingerprint() + ". Kept encrypted inside SimpleSSH.";
            }
            else if (string.IsNullOrEmpty(_publicKey))
            {
                if (!SshKeys.TryGetPublicKey(_privateKey, connection.PrivateKeyPassphrase, "", out var pub, out var error))
                    throw new SshSessionException(error);
                _publicKey = pub;
            }
            Mark(1, StepState.Done);

            step = 2;
            Mark(2, StepState.Running);
            ShowBusy($"Logging in to {connection.DisplayName}…");
            _options = await _login.PrepareAsync(this, includeTunnels: false);
            if (_options is null)
            {
                Mark(2, StepState.Failed, "Login cancelled.");
                return;
            }
            _password = _options.Credential.Password;
            ShowBusy("Adding the key…");
            await KeyLoginSetup.InstallKeyAsync(_options, Verifier, _publicKey!);
            Mark(2, StepState.Done, "Added to ~/.ssh/authorized_keys.");

            step = 3;
            Mark(3, StepState.Running);
            ShowBusy("Logging in with the key alone…");
            await KeyLoginSetup.VerifyKeyLoginAsync(KeyOnly(), Verifier);
            Mark(3, StepState.Done, "The key works.");

            SaveKey();
            _keyReady = true;
            Log.Info($"Key login set up for {connection.Endpoint}.");
            ShowSuccess(connection);
        }
        catch (Exception ex)
        {
            if (ex is not SshSessionException) Log.Error("Switch to key login failed", ex);
            Mark(step, StepState.Failed);
            var message = SshConnector.DescribeError(ex);
            if (step == 2 && SshConnector.IsAuthenticationFailure(ex))
                message += "\n\nIf this server only takes keys, use Add the key by hand instead (link above).";
            ShowError(message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ShowSuccess(Connection connection)
    {
        SuccessText.Text = $"Key login works. SimpleSSH now logs in to {connection.DisplayName} with the key.";
        SuccessPanel.Visibility = Visibility.Visible;
        // Only offer to forget a password that is actually saved.
        ForgetPasswordBox.Visibility = string.IsNullOrEmpty(Current?.Password) ? Visibility.Collapsed : Visibility.Visible;
        LockPanel.Visibility = Visibility.Visible;
        UndoLinkText.Visibility = Visibility.Collapsed;
        ByHandLinkText.Visibility = Visibility.Collapsed;
        StartButton.Visibility = Visibility.Collapsed;
        CloseButton.Content = "Done";
        CloseButton.IsDefault = true;
    }

    /// <summary>Stores the key on the connection; the password stays until the dialog closes (it may be needed for sudo).</summary>
    private void SaveKey()
    {
        if (Current is not { } connection) return;
        var edited = connection.Clone();
        edited.PrivateKey = _privateKey;
        edited.PublicKey = _publicKey;
        edited.PrivateKeyPath = null;
        if (string.IsNullOrEmpty(connection.PrivateKey)) edited.PrivateKeyPassphrase = null; // a new key has no passphrase
        Store.Update(edited);
    }

    // ---- Lock down -----------------------------------------------------------------------------

    private async void LockDown_Click(object sender, RoutedEventArgs e)
    {
        if (!_keyReady || Current is not { } connection) return;
        var sudo = _password ?? PasswordPromptDialog.Ask(this, "Lock down", $"Password for sudo on {connection.DisplayName}:");
        if (sudo is null) return;

        SetBusy(true);
        ShowBusy("Turning off password logins and checking…");
        LockResult.Visibility = Visibility.Collapsed;
        try
        {
            LockDownResult result;
            while (true)
            {
                result = await KeyLoginSetup.LockDownAsync(KeyOnly(), PasswordOnly(sudo), sudo, Verifier);
                if (result.Status != LockDownStatus.WrongSudoPassword) break;
                var again = PasswordPromptDialog.Ask(this, "Lock down", $"sudo didn't accept that password. Password for sudo on {connection.DisplayName}:");
                if (again is null) break;
                sudo = again;
            }
            ShowLockResult(result, connection);
            Log.Info($"Lock down of {connection.Endpoint}: {result.Status}");
        }
        catch (Exception ex)
        {
            if (ex is not SshSessionException) Log.Error("Lock down failed", ex);
            ShowLock(false, $"Could not lock down: {SshConnector.DescribeError(ex)}");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ShowLockResult(LockDownResult result, Connection connection)
    {
        var name = connection.DisplayName;
        switch (result.Status)
        {
            case LockDownStatus.Locked:
                ShowLock(true, $"Done. {name} now refuses SSH password logins; SimpleSSH checked that a password is turned away and that the key " +
                               "still gets in. Console logins still take your password.");
                _lockedDown = true;
                UndoLinkText.Visibility = Visibility.Visible;
                break;
            case LockDownStatus.PasswordStillAccepted:
                ShowLock(false, "The setting was added, but the server still accepts a password. " + result.Output);
                UndoLinkText.Visibility = Visibility.Visible;
                break;
            case LockDownStatus.WrongSudoPassword:
                ShowLock(false, "sudo didn't accept the password, so nothing was changed.");
                break;
            case LockDownStatus.NotAllowed:
                ShowLock(false, "This account can't use sudo here, so nothing was changed. Ask an administrator, or use an account that can.");
                break;
            case LockDownStatus.Unsupported:
                ShowLock(false, "This server's SSH has no /etc/ssh/sshd_config.d folder (older than Ubuntu 20.04 or Debian 11?), so nothing was changed.");
                break;
            case LockDownStatus.ConfigRejected:
                ShowLock(false, "The SSH server rejected the setting, so it was removed again and nothing changed.\n" + result.Output);
                break;
            case LockDownStatus.RolledBack:
                ShowLock(false, "After the change a new key login didn't work, so SimpleSSH undid it. Password logins still work.\n" + result.Output);
                break;
            default:
                ShowLock(false, "Something unexpected happened; check the server.\n" + result.Output);
                break;
        }
    }

    private async void Undo_Click(object sender, RoutedEventArgs e)
    {
        if (Current is not { } connection) return;
        var sudo = _password ?? PasswordPromptDialog.Ask(this, "Turn password logins back on", $"Password for sudo on {connection.DisplayName}:");
        if (sudo is null) return;
        SetBusy(true);
        ShowBusy("Turning password logins back on…");
        try
        {
            var result = await KeyLoginSetup.UndoAsync(KeyOnly(), sudo, Verifier);
            if (result.Status == LockDownStatus.Undone)
            {
                ShowLock(true, $"{connection.DisplayName} accepts SSH passwords again. The key keeps working.");
                _lockedDown = false;
                UndoLinkText.Visibility = Visibility.Collapsed;
            }
            else
            {
                ShowLock(false, result.Status == LockDownStatus.WrongSudoPassword
                    ? "sudo didn't accept the password, so nothing was changed."
                    : "Could not undo it:\n" + result.Output + $"\n\nOn the server: {KeyLoginSetup.UndoHint}");
            }
        }
        catch (Exception ex)
        {
            ShowLock(false, $"Could not undo it: {SshConnector.DescribeError(ex)}\n\nOn the server: {KeyLoginSetup.UndoHint}");
        }
        finally
        {
            SetBusy(false);
        }
    }

    // ---- Helpers -------------------------------------------------------------------------------

    private IHostKeyVerifier Verifier => HostKeyPrompt.CreateVerifier(_login.HostKeys);

    private SshConnectOptions KeyOnly() => new()
    {
        Host = _options!.Host,
        Port = _options.Port,
        Proxy = _options.Proxy,
        ConnectTimeout = TimeSpan.FromSeconds(30),
        Credential = new ResolvedCredential(_options.Credential.Username, null, null,
            string.IsNullOrEmpty(Current?.PrivateKeyPassphrase) ? null : Current!.PrivateKeyPassphrase, _privateKey),
    };

    private SshConnectOptions PasswordOnly(string password) => new()
    {
        Host = _options!.Host,
        Port = _options.Port,
        Proxy = _options.Proxy,
        ConnectTimeout = TimeSpan.FromSeconds(30),
        Credential = new ResolvedCredential(_options.Credential.Username, password, null, null),
    };

    private string Fingerprint() => string.IsNullOrEmpty(_publicKey) ? "" : $" ({SshKeys.Fingerprint(_publicKey)})";

    private void Mark(int step, StepState state, string? detail = null)
    {
        var (icon, text) = step switch { 1 => (Icon1, Detail1), 2 => (Icon2, Detail2), _ => (Icon3, Detail3) };
        icon.Text = state switch { StepState.Running => "◌", StepState.Done => "✓", StepState.Failed => "✕", _ => "○" };
        icon.Foreground = state switch { StepState.Running => Running, StepState.Done => Done, StepState.Failed => Failed, _ => Pending };
        if (detail is not null) text.Text = detail;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        StartButton.IsEnabled = !busy;
        LockButton.IsEnabled = !busy && !_lockedDown;
        UndoLinkText.IsEnabled = !busy;
        CloseButton.IsEnabled = !busy;
        if (!busy) BusyText.Visibility = Visibility.Collapsed;
    }

    private void ShowBusy(string text)
    {
        BusyText.Text = text;
        BusyText.Visibility = Visibility.Visible;
    }

    private void ShowError(string text)
    {
        ErrorText.Text = text;
        ErrorText.Visibility = Visibility.Visible;
    }

    private void ShowLock(bool good, string text)
    {
        LockResult.Text = text.Trim();
        LockResult.Foreground = good ? new SolidColorBrush(Color.FromRgb(0x14, 0x53, 0x2D)) : Failed;
        LockResult.Visibility = Visibility.Visible;
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_busy)
        {
            e.Cancel = true; // let the server change finish; it undoes itself if it goes wrong
            return;
        }
        if (_keyReady && ForgetPasswordBox.IsChecked == true && ForgetPasswordBox.Visibility == Visibility.Visible && Current is { } c)
        {
            try
            {
                var edited = c.Clone();
                edited.Password = null;
                Store.Update(edited);
            }
            catch (Exception ex)
            {
                Log.Error("Could not forget the saved password", ex);
            }
        }
        _password = null;
    }
}

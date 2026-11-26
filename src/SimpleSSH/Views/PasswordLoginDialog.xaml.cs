using System.Windows;
using System.Windows.Media;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>
/// The way back from key login: turns SSH password logins on again (if SimpleSSH turned them off), proves a
/// password-only login, and only then removes the key from SimpleSSH (and optionally from the server).
/// </summary>
public partial class PasswordLoginDialog : Window
{
    private enum StepState { Running, Done, Skipped, Failed }

    private static readonly Brush Running = new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0xBD));
    private static readonly Brush Done = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A));
    private static readonly Brush Skipped = new SolidColorBrush(Color.FromRgb(0x9C, 0xA3, 0xAF));
    private static readonly Brush Failed = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));

    private readonly Guid _id;
    private readonly SessionLogin _login;
    private bool _busy;
    private bool _finished;

    public PasswordLoginDialog(Connection connection)
    {
        InitializeComponent();
        _id = connection.Id;
        _login = new SessionLogin(connection);
        Heading.Text = $"Switch {connection.DisplayName} back to password login";
        SubHeading.Text = string.IsNullOrWhiteSpace(connection.Username) ? connection.Endpoint : $"{connection.Username}@{connection.Endpoint}";
        if (!string.IsNullOrEmpty(connection.Password))
        {
            PasswordBox.Password = connection.Password;
            PasswordHint.Text = "Your saved password is filled in.";
        }
        else
        {
            PasswordHint.Text = $"The password of {(string.IsNullOrWhiteSpace(connection.Username) ? "your account" : connection.Username)} on the server. It is also used for sudo if needed.";
        }
        StartButton.IsEnabled = CurrentPassword.Length > 0;
        Loaded += (_, _) => PasswordBox.Focus();
        Closing += (_, e) => e.Cancel = _busy;
    }

    private static Core.Storage.ConnectionStore Store => AppServices.Connections;

    private Connection? Current => Store.Find(_id);

    private IHostKeyVerifier Verifier => HostKeyPrompt.CreateVerifier(_login.HostKeys);

    /// <summary>What is typed, from whichever box is showing (masked, or shown with "Show").</summary>
    private string CurrentPassword => ShowPassword?.IsChecked == true ? PasswordText.Text : PasswordBox?.Password ?? "";

    private void Password_Changed(object sender, RoutedEventArgs e) =>
        StartButton.IsEnabled = !_busy && !_finished && CurrentPassword.Length > 0;

    private void ShowPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (ShowPassword.IsChecked == true)
        {
            PasswordText.Text = PasswordBox.Password;
            PasswordText.Visibility = Visibility.Visible;
            PasswordBox.Visibility = Visibility.Collapsed;
            PasswordText.Focus();
            PasswordText.CaretIndex = PasswordText.Text.Length;
        }
        else
        {
            PasswordBox.Password = PasswordText.Text;
            PasswordText.Clear(); // don't leave the password in a plain text box
            PasswordBox.Visibility = Visibility.Visible;
            PasswordText.Visibility = Visibility.Collapsed;
            PasswordBox.Focus();
        }
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (Current is not { } connection || CurrentPassword.Length == 0) return;
        var password = CurrentPassword;
        ErrorText.Visibility = Visibility.Collapsed;
        SetBusy(true);
        int step = 1;
        try
        {
            ShowBusy($"Connecting to {connection.DisplayName}…");
            var options = await _login.PrepareAsync(this, includeTunnels: false);
            if (options is null)
            {
                ShowError("Login cancelled.");
                return;
            }
            var user = options.Credential.Username;
            SshConnectOptions With(ResolvedCredential credential, AuthPromptHandler? prompt) => new()
            {
                Host = options.Host,
                Port = options.Port,
                Proxy = options.Proxy,
                ConnectTimeout = TimeSpan.FromSeconds(30),
                Credential = credential,
                Prompt = prompt,
            };
            var passwordLogin = With(new ResolvedCredential(user, password, null, null), options.Prompt); // MFA codes still allowed

            // 1. Password logins back on, over the key.
            Mark(1, StepState.Running);
            ShowBusy("Checking whether SSH password logins are turned off…");
            if (string.IsNullOrEmpty(connection.PrivateKey))
            {
                Mark(1, StepState.Skipped, "Skipped: no key kept in SimpleSSH for this connection.");
            }
            else
            {
                var keyOnly = With(new ResolvedCredential(user, null, null,
                    string.IsNullOrEmpty(connection.PrivateKeyPassphrase) ? null : connection.PrivateKeyPassphrase, connection.PrivateKey), null);
                LockDownResult? result = null;
                bool keyRefused = false;
                try
                {
                    var sudo = password;
                    while (true)
                    {
                        result = await KeyLoginSetup.EnablePasswordsAsync(keyOnly, sudo, Verifier);
                        if (result?.Status != LockDownStatus.WrongSudoPassword) break;
                        var again = PasswordPromptDialog.Ask(this, "Turn password logins back on",
                            $"sudo didn't accept that password. Password for sudo on {connection.DisplayName}:");
                        if (again is null) break;
                        sudo = again;
                    }
                }
                catch (SshSessionException ex) when (SshConnector.IsAuthenticationFailure(ex))
                {
                    keyRefused = true; // the key no longer gets in: the password has to work on its own
                }

                if (keyRefused)
                    Mark(1, StepState.Skipped, "Skipped: the key no longer logs in, so the password has to work on its own.");
                else if (result is null)
                    Mark(1, StepState.Done, "Already on.");
                else if (result.Status == LockDownStatus.Undone)
                    Mark(1, StepState.Done, "Turned back on (removed SimpleSSH's file in /etc/ssh/sshd_config.d).");
                else
                {
                    Mark(1, StepState.Failed);
                    ShowError(result.Status switch
                    {
                        LockDownStatus.WrongSudoPassword => "sudo didn't accept the password, so nothing was changed.",
                        LockDownStatus.NotAllowed => "This account can't use sudo here, so password logins stay off. Nothing was changed.",
                        _ => "Could not turn password logins back on. Nothing else was changed.\n" + result.Output,
                    });
                    return;
                }
            }

            // 2. Prove the password.
            step = 2;
            Mark(2, StepState.Running);
            ShowBusy("Logging in with the password…");
            await KeyLoginSetup.VerifyPasswordLoginAsync(passwordLogin, Verifier);
            Mark(2, StepState.Done, "The password works.");

            // 3. Only now let go of the key.
            step = 3;
            Mark(3, StepState.Running);
            bool removedFromServer = false;
            var publicKey = connection.PublicKey;
            if (RemoveFromServerBox.IsChecked == true && !string.IsNullOrEmpty(publicKey))
            {
                ShowBusy("Removing the key from the server…");
                await KeyLoginSetup.RemoveKeyAsync(passwordLogin, Verifier, publicKey);
                removedFromServer = true;
            }
            SaveAsPasswordLogin(password);
            Mark(3, StepState.Done, removedFromServer
                ? "Removed from SimpleSSH and from the server."
                : "Removed from SimpleSSH. The server still lists it in ~/.ssh/authorized_keys.");

            Log.Info($"Switched {connection.Endpoint} back to password login.");
            _finished = true;
            SuccessText.Text = $"{connection.DisplayName} now uses password login" +
                               (SavePasswordBox.IsChecked == true ? ", with the password saved in SimpleSSH." : "; SimpleSSH asks for the password when connecting.");
            SuccessPanel.Visibility = Visibility.Visible;
            StartButton.Visibility = Visibility.Collapsed;
            RemoveFromServerBox.IsEnabled = SavePasswordBox.IsEnabled = PasswordBox.IsEnabled = PasswordText.IsEnabled = ShowPassword.IsEnabled = false;
            CloseButton.Content = "Done";
            CloseButton.IsDefault = true;
        }
        catch (Exception ex)
        {
            if (ex is not SshSessionException) Log.Error("Switch to password login failed", ex);
            Mark(step, StepState.Failed);
            ShowError(SshConnector.DescribeError(ex) + (step <= 2 ? "\nThe key still works; nothing was removed." : ""));
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SaveAsPasswordLogin(string password)
    {
        if (Current is not { } connection) return;
        var edited = connection.Clone();
        if (!string.IsNullOrEmpty(edited.PrivateKey)) edited.PrivateKeyPassphrase = null; // belonged to the stored key
        edited.PrivateKey = null;
        edited.PublicKey = null;
        edited.Password = SavePasswordBox.IsChecked == true ? password : null;
        Store.Update(edited);
    }

    private void Mark(int step, StepState state, string? detail = null)
    {
        var (icon, text) = step switch { 1 => (Icon1, Detail1), 2 => (Icon2, Detail2), _ => (Icon3, Detail3) };
        icon.Text = state switch { StepState.Running => "◌", StepState.Done => "✓", StepState.Skipped => "–", _ => "✕" };
        icon.Foreground = state switch { StepState.Running => Running, StepState.Done => Done, StepState.Skipped => Skipped, _ => Failed };
        if (detail is not null) text.Text = detail;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        StartButton.IsEnabled = !busy && !_finished && CurrentPassword.Length > 0;
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
}

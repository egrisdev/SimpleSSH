using System.Windows;
using System.Windows.Media;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>
/// Key login for a server that already refuses passwords: SimpleSSH makes a key, the person pastes a one-line command
/// into a session that already gets in (another SSH program, the console), and SimpleSSH proves a key-only login.
/// </summary>
public partial class AddKeyByHandDialog : Window
{
    private static readonly Brush Done = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A));
    private static readonly Brush Failed = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));
    private static readonly Brush Running = new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0xBD));

    private readonly string _host;
    private readonly int _port;
    private readonly string _username;
    private readonly ProxySettings? _proxy;
    private readonly string? _passphrase;
    private readonly HostKeyPromptState _hostKeys = new();
    private bool _busy;

    /// <param name="privateKey">A key the connection already keeps in SimpleSSH, to reuse; null makes a new one.</param>
    /// <param name="saveLabel">The main button, e.g. "Test and save".</param>
    internal AddKeyByHandDialog(string displayName, string host, int port, string username, ProxySettings? proxy,
                                string? privateKey, string? publicKey, string? passphrase, string saveLabel)
    {
        InitializeComponent();
        (_host, _port, _username, _proxy) = (host, port, username, proxy);
        _passphrase = string.IsNullOrEmpty(passphrase) ? null : passphrase;

        if (!string.IsNullOrEmpty(privateKey) &&
            (!string.IsNullOrEmpty(publicKey) || SshKeys.TryGetPublicKey(privateKey, _passphrase, "", out publicKey, out _)))
        {
            PrivateKey = privateKey;
            PublicKey = publicKey!;
        }
        else
        {
            var pair = SshKeys.CreateEd25519($"SimpleSSH {Environment.UserName}@{Environment.MachineName}");
            (PrivateKey, PublicKey) = (pair.PrivateKey, pair.PublicKey);
            _passphrase = null; // a new key has no passphrase
        }

        var endpoint = port == 22 ? host : $"{host}:{port}";
        Heading.Text = $"Add a key to {displayName} by hand";
        SubHeading.Text = $"{username}@{endpoint}";
        SubHeading.ToolTip = SshKeys.Fingerprint(PublicKey);
        Step1Title.Text = $"Run this on the server, logged in as {username}";
        CommandBox.Text = KeyLoginSetup.ManualInstallCommand(PublicKey);
        TestButton.Content = saveLabel;
        Closing += (_, e) => e.Cancel = _busy;
        Loaded += (_, _) => CopyCommandButton.Focus();
    }

    /// <summary>The key to keep (OpenSSH text, unencrypted; the store encrypts it).</summary>
    public string PrivateKey { get; }
    public string PublicKey { get; }
    /// <summary>The passphrase of a reused key; null for a new one.</summary>
    public string? Passphrase => _passphrase;
    /// <summary>True when a key-only login worked; false when the person kept the key without testing.</summary>
    public bool Tested { get; private set; }

    private void CopyCommand_Click(object sender, RoutedEventArgs e)
    {
        ClipboardHelper.SetText(CommandBox.Text);
        CopiedText.Text = "Copied. Paste it into the server and press Enter.";
        CopiedText.Visibility = Visibility.Visible;
        CommandBox.Focus();
        CommandBox.SelectAll();
    }

    private void CopyPublicKey_Click(object sender, RoutedEventArgs e)
    {
        ClipboardHelper.SetText(PublicKey);
        CopiedText.Text = "Public key copied. It goes on its own line in ~/.ssh/authorized_keys.";
        CopiedText.Visibility = Visibility.Visible;
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;
        SetBusy(true);
        Icon2.Text = "◌";
        Icon2.Foreground = Running;
        try
        {
            var keyOnly = new SshConnectOptions
            {
                Host = _host,
                Port = _port,
                Proxy = _proxy,
                ConnectTimeout = TimeSpan.FromSeconds(30),
                Credential = new ResolvedCredential(_username, null, null, _passphrase, PrivateKey),
            };
            await KeyLoginSetup.VerifyKeyLoginAsync(keyOnly, HostKeyPrompt.CreateVerifier(_hostKeys));
            Icon2.Text = "✓";
            Icon2.Foreground = Done;
            Tested = true;
            Log.Info($"Key added by hand and tested for {_username}@{_host}:{_port}.");
            _busy = false;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            Icon2.Text = "✕";
            Icon2.Foreground = Failed;
            bool refused = SshConnector.IsAuthenticationFailure(ex) ||
                           (ex.InnerException is { } inner && SshConnector.IsAuthenticationFailure(inner));
            ShowError(refused
                ? $"The server didn't accept the key yet. Check that the command ran without errors, logged in as {_username} " +
                  "(not root or another account), then test again."
                : SshConnector.DescribeError(ex));
            SkipTestLink.Visibility = Visibility.Visible;
            if (ex is not SshSessionException) Log.Error("Testing a key added by hand failed", ex);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SaveWithoutTest_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        Tested = false;
        DialogResult = true;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        TestButton.IsEnabled = CloseButton.IsEnabled = !busy;
        BusyText.Text = busy ? "Logging in with the key alone…" : "";
        BusyText.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowError(string text)
    {
        ErrorText.Text = text;
        ErrorText.Visibility = Visibility.Visible;
    }
}

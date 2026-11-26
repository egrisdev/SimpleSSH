using System.Windows;
using System.Windows.Media;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Views;

/// <summary>Takes a pasted private key, checks that SSH.NET can use it, and works out its public key.</summary>
public partial class PasteKeyDialog : Window
{
    private static readonly Brush Good = new SolidColorBrush(Color.FromRgb(0x16, 0x65, 0x34));
    private static readonly Brush Bad = new SolidColorBrush(Color.FromRgb(0xB4, 0x23, 0x18));

    public PasteKeyDialog()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            // Most people copy the key right before opening this.
            var clip = Services.ClipboardHelper.GetText();
            if (clip.Contains("PRIVATE KEY", StringComparison.Ordinal) || clip.StartsWith("PuTTY-User-Key-File", StringComparison.Ordinal))
                KeyBox.Text = clip.Trim();
            KeyBox.Focus();
        };
    }

    public string PrivateKey { get; private set; } = "";
    public string PublicKey { get; private set; } = "";
    public string Passphrase => PassphraseBox.Password;

    private void Key_Changed(object sender, RoutedEventArgs e)
    {
        OkButton.IsEnabled = false;
        if (string.IsNullOrWhiteSpace(KeyBox.Text))
        {
            StatusText.Text = "";
            return;
        }
        if (SshKeys.TryGetPublicKey(KeyBox.Text, PassphraseBox.Password, "", out var publicKey, out var error))
        {
            PrivateKey = KeyBox.Text.Replace("\r\n", "\n").Trim() + "\n";
            PublicKey = publicKey;
            StatusText.Foreground = Good;
            StatusText.Text = "Key recognized: " + SshKeys.Fingerprint(publicKey);
            OkButton.IsEnabled = true;
        }
        else
        {
            StatusText.Foreground = Bad;
            StatusText.Text = error;
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (OkButton.IsEnabled) DialogResult = true;
    }
}

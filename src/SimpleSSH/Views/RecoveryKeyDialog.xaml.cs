using System.Windows;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>Shows a new recovery key once. The caller applies it only if the user confirms it was saved.</summary>
public partial class RecoveryKeyDialog : Window
{
    private readonly string _key;

    public RecoveryKeyDialog(string recoveryKey, bool replacing)
    {
        InitializeComponent();
        _key = recoveryKey;
        KeyBox.Text = recoveryKey;
        if (replacing) ReplaceNote.Visibility = Visibility.Visible;
        Loaded += (_, _) => CopyButton.Focus();
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        CopiedText.Text = ClipboardHelper.SetSecret(_key, TimeSpan.FromMinutes(2))
            ? "Copied. Paste it into your password manager; the clipboard is cleared in 2 minutes."
            : "Could not use the clipboard. Select the key and press Ctrl+C.";
    }

    private void Saved_Changed(object sender, RoutedEventArgs e) => DoneButton.IsEnabled = SavedBox.IsChecked == true;

    private void Done_Click(object sender, RoutedEventArgs e)
    {
        if (SavedBox.IsChecked == true) DialogResult = true;
    }
}

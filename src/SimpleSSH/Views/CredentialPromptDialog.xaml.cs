using System.Windows;
using SimpleSSH.Core.Models;

namespace SimpleSSH.Views;

/// <summary>
/// Asks for credentials that were not saved with the connection (or could not be decrypted).
/// Nothing is persisted unless "Remember" is ticked, and then only after a successful login.
/// </summary>
public partial class CredentialPromptDialog : Window
{
    public CredentialPromptDialog(Connection connection, string? username, bool passwordOptional, string? reason = null, bool rememberByDefault = false)
    {
        InitializeComponent();
        Header.Text = $"Log in to {connection.DisplayName} ({connection.Endpoint})" +
                      (reason is null ? "" : $"\n{reason}") +
                      (passwordOptional ? "\nPassword is optional (a private key is configured)." : "");
        UserBox.Text = username ?? "";
        RememberBox.IsChecked = rememberByDefault;
        if (Services.AppServices.Connections.Vault is not null)
            RememberBox.ToolTip = "Saved encrypted with your security key and Windows account, and only after a successful login.";
        Loaded += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(UserBox.Text)) UserBox.Focus();
            else PasswordBox.Focus();
        };
    }

    public string Username => UserBox.Text.Trim();
    public string Password => PasswordBox.Password;
    public bool Remember => RememberBox.IsChecked == true;

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(UserBox.Text))
        {
            UserBox.Focus();
            return;
        }
        DialogResult = true;
    }
}

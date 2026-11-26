using System.Windows;

namespace SimpleSSH.Views;

/// <summary>Asks for one password that is used once and not saved (e.g. for sudo).</summary>
public partial class PasswordPromptDialog : Window
{
    private PasswordPromptDialog(string title, string prompt)
    {
        InitializeComponent();
        Title = title;
        Prompt.Text = prompt;
        Loaded += (_, _) => Box.Focus();
    }

    public static string? Ask(Window? owner, string title, string prompt)
    {
        var dlg = new PasswordPromptDialog(title, prompt) { Owner = owner };
        return dlg.ShowDialog() == true ? dlg.Typed : null;
    }

    private string Typed => ShowBox.IsChecked == true ? BoxText.Text : Box.Password;

    private void Show_Changed(object sender, RoutedEventArgs e)
    {
        if (ShowBox.IsChecked == true)
        {
            BoxText.Text = Box.Password;
            BoxText.Visibility = Visibility.Visible;
            Box.Visibility = Visibility.Collapsed;
            BoxText.Focus();
            BoxText.CaretIndex = BoxText.Text.Length;
        }
        else
        {
            Box.Password = BoxText.Text;
            BoxText.Clear();
            Box.Visibility = Visibility.Visible;
            BoxText.Visibility = Visibility.Collapsed;
            Box.Focus();
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (Typed.Length > 0) DialogResult = true;
        else if (ShowBox.IsChecked == true) BoxText.Focus();
        else Box.Focus();
    }
}

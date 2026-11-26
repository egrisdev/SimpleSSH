using System.Windows;

namespace SimpleSSH.Views;

/// <summary>A yes/cancel question with a "don't ask again" checkbox.</summary>
public partial class ConfirmDialog : Window
{
    public ConfirmDialog(string title, string heading, string detail, string okText, string dontAskText = "Don't ask again")
    {
        InitializeComponent();
        Title = title;
        Heading.Text = heading;
        Detail.Text = detail;
        Detail.Visibility = string.IsNullOrWhiteSpace(detail) ? Visibility.Collapsed : Visibility.Visible;
        OkButton.Content = okText;
        DontAskBox.Content = dontAskText;
        Loaded += (_, _) => OkButton.Focus();
    }

    /// <summary>Only meaningful when the dialog returned true: the user chose OK and ticked the box.</summary>
    public bool DontAskAgain => DontAskBox.IsChecked == true;

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}

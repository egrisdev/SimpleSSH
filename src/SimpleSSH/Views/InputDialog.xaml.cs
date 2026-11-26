using System.Windows;

namespace SimpleSSH.Views;

/// <summary>Asks for one line of text (new folder name, rename, remote path).</summary>
public partial class InputDialog : Window
{
    public InputDialog(string title, string prompt, string initial = "")
    {
        InitializeComponent();
        Title = title;
        Prompt.Text = prompt;
        ValueBox.Text = initial;
        Loaded += (_, _) =>
        {
            ValueBox.Focus();
            // Select the name without its extension, like Explorer.
            var dot = initial.LastIndexOf('.');
            if (dot > 0) ValueBox.Select(0, dot);
            else ValueBox.SelectAll();
        };
    }

    public string Value => ValueBox.Text.Trim();

    public static string? Ask(Window? owner, string title, string prompt, string initial = "")
    {
        var dlg = new InputDialog(title, prompt, initial) { Owner = owner };
        return dlg.ShowDialog() == true && dlg.Value.Length > 0 ? dlg.Value : null;
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}

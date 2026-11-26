using System.Windows;
using System.Windows.Controls;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Views;

/// <summary>Answers the server's own login questions, e.g. "Verification code:". Answers are never saved.</summary>
public partial class AuthPromptDialog : Window
{
    private readonly List<Func<string>> _readers = new();
    private Control? _first;

    public AuthPromptDialog(Connection connection, AuthPromptRequest request)
    {
        InitializeComponent();
        Header.Text = $"{connection.DisplayName} ({request.Endpoint}) asks:";
        if (request.Instruction is { } instruction)
        {
            Instruction.Text = instruction;
            Instruction.Visibility = Visibility.Visible;
        }

        foreach (var field in request.Fields)
        {
            var label = string.IsNullOrWhiteSpace(field.Label) ? "Response" : field.Label.TrimEnd(':', ' ');
            Fields.Children.Add(new TextBlock { Text = label, Margin = new Thickness(0, 6, 0, 3) });
            Control input;
            if (field.Echo)
            {
                var box = new TextBox { Style = (Style)FindResource("FieldBox") };
                _readers.Add(() => box.Text);
                input = box;
            }
            else
            {
                var box = new PasswordBox { Style = (Style)FindResource("FieldBox") };
                _readers.Add(() => box.Password);
                input = box;
            }
            System.Windows.Automation.AutomationProperties.SetName(input, label);
            Fields.Children.Add(input);
            _first ??= input;
        }

        Loaded += (_, _) => _first?.Focus();
    }

    public IReadOnlyList<string> Answers => _readers.Select(r => r()).ToList();

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}

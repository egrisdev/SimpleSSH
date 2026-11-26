using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;

namespace SimpleSSH.Views;

/// <summary>One connection's result card.</summary>
public sealed class CommandTarget : INotifyPropertyChanged
{
    private static readonly Brush Pending = Frozen(0x9C, 0xA3, 0xAF);
    private static readonly Brush Running = Frozen(0xF5, 0x9E, 0x0B);
    private static readonly Brush Ok = Frozen(0x16, 0xA3, 0x4A);
    private static readonly Brush Failed = Frozen(0xDC, 0x26, 0x26);

    private string _status = "";
    private string _output = "";
    private Brush _brush = Pending;

    internal CommandTarget(Connection connection)
    {
        Connection = connection;
        Login = new SessionLogin(connection);
    }

    public Connection Connection { get; }
    internal SessionLogin Login { get; }
    public string Name => Connection.DisplayName;
    public string Endpoint => string.IsNullOrEmpty(Connection.Username) ? Connection.Endpoint : $"{Connection.Username}@{Connection.Endpoint}";
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string Output { get => _output; private set { Set(ref _output, value); OnPropertyChanged(nameof(OutputVisibility)); } }
    public Brush StatusBrush { get => _brush; private set => Set(ref _brush, value); }
    public Visibility OutputVisibility => string.IsNullOrEmpty(Output) ? Visibility.Collapsed : Visibility.Visible;
    public bool? Succeeded { get; private set; }

    public void SetWaiting() { Succeeded = null; Status = "Waiting…"; StatusBrush = Pending; Output = ""; }
    public void SetRunning() { Status = "Running…"; StatusBrush = Running; }

    public void SetResult(CommandResult r)
    {
        Succeeded = r.Succeeded;
        Status = r.ExitStatus is { } code ? (code == 0 ? "Done" : $"Exit code {code}") : "Done";
        StatusBrush = r.Succeeded ? Ok : Failed;
        Output = r.CombinedOutput.TrimEnd('\r', '\n');
        if (Output.Length == 0) Output = "(no output)";
    }

    public void SetError(string message, string status = "Failed")
    {
        Succeeded = false;
        Status = status;
        StatusBrush = Failed;
        Output = message;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        OnPropertyChanged(name);
    }

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

/// <summary>Runs one command on one or many connections (a whole tag) and shows each device's output.</summary>
public partial class RunCommandWindow : Window
{
    private const int MaxParallel = 8;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(2);

    private readonly List<CommandTarget> _targets;
    private CancellationTokenSource? _cts;
    private bool _running;

    public RunCommandWindow(IReadOnlyList<Connection> connections, string scope)
    {
        InitializeComponent();
        connections = connections.OrderBy(c => c.DisplayName, SimpleSSH.Core.NaturalStringComparer.Instance).ToList();
        _targets = connections.Select(c => new CommandTarget(c)).ToList();
        Results.ItemsSource = _targets;
        Title = $"Run command – {scope}";
        var names = string.Join(", ", connections.Select(c => c.DisplayName));
        TargetsText.Text = connections.Count == 1 ? $"On {names}" : $"On {connections.Count} connections: {names}";
        TargetsText.ToolTip = names;
        SummaryText.Text = "Type a command and press Enter. Each device runs it on its own connection; nothing is typed into open terminals.";
        SummaryText.TextWrapping = TextWrapping.Wrap;
        RunButton.IsEnabled = false;
        Loaded += (_, _) => CommandBox.Focus();
    }

    private void CommandBox_TextChanged(object sender, TextChangedEventArgs e) =>
        RunButton.IsEnabled = !_running && !string.IsNullOrWhiteSpace(CommandBox.Text);

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (_running)
        {
            _cts?.Cancel();
            return;
        }
        var command = CommandBox.Text.Trim();
        if (command.Length == 0) return;

        _running = true;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        RunButton.Content = "Stop";
        RunButton.IsEnabled = true;
        CommandBox.IsReadOnly = true;
        CopyButton.IsEnabled = false;
        SummaryText.Text = $"Running on {_targets.Count} connection{(_targets.Count == 1 ? "" : "s")}…";
        foreach (var t in _targets) t.SetWaiting();

        try
        {
            // Ask for any missing passwords first, one at a time, then run everything in parallel.
            var ready = new List<(CommandTarget Target, SshConnectOptions Options)>();
            foreach (var t in _targets)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var options = await t.Login.PrepareAsync(this, includeTunnels: false);
                    if (options is null) t.SetError("Login cancelled.", "Skipped");
                    else ready.Add((t, options));
                }
                catch (Exception ex)
                {
                    t.SetError(SshConnector.DescribeError(ex));
                }
            }

            using var gate = new SemaphoreSlim(MaxParallel);
            await Task.WhenAll(ready.Select(async item =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(true);
                try
                {
                    item.Target.SetRunning();
                    var result = await item.Target.Login.ConnectAsync(item.Options,
                        verifier => SshCommandRunner.RunAsync(item.Options, verifier, command, CommandTimeout, ct));
                    item.Target.SetResult(result);
                }
                catch (OperationCanceledException)
                {
                    item.Target.SetError("Stopped.", "Stopped");
                }
                catch (Exception ex)
                {
                    item.Target.SetError(SshConnector.DescribeError(ex));
                }
                finally
                {
                    gate.Release();
                }
            }));
        }
        catch (OperationCanceledException)
        {
            // Stopped before everything started.
        }
        finally
        {
            foreach (var t in _targets.Where(t => t.Succeeded is null && t.Status == "Waiting…")) t.SetError("Stopped.", "Stopped");
            _running = false;
            _cts.Dispose();
            _cts = null;
            if (IsLoaded)
            {
                RunButton.Content = "Run";
                RunButton.IsEnabled = !string.IsNullOrWhiteSpace(CommandBox.Text);
                CommandBox.IsReadOnly = false;
                CopyButton.IsEnabled = true;
                var ok = _targets.Count(t => t.Succeeded == true);
                var skipped = _targets.Count(t => t.Status is "Skipped" or "Stopped");
                var failed = _targets.Count - ok - skipped;
                var parts = new List<string> { $"{ok} succeeded" };
                if (failed > 0) parts.Add($"{failed} failed");
                if (skipped > 0) parts.Add($"{skipped} skipped");
                SummaryText.Text = "Done: " + string.Join(", ", parts) + ".";
                CommandBox.Focus();
                CommandBox.SelectAll();
            }
        }
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        sb.Append("$ ").AppendLine(CommandBox.Text.Trim()).AppendLine();
        foreach (var t in _targets)
        {
            sb.Append("=== ").Append(t.Name).Append(" (").Append(t.Endpoint).Append(") – ").Append(t.Status).AppendLine(" ===");
            sb.AppendLine(t.Output).AppendLine();
        }
        ClipboardHelper.SetText(sb.ToString());
        SummaryText.Text = "Copied all output to the clipboard.";
    }

    private void Window_Closing(object? sender, CancelEventArgs e) => _cts?.Cancel();
}

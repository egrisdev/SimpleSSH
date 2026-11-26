using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Services;
using SimpleSSH.Views;

namespace SimpleSSH.Controls;

/// <summary>One row in the file list.</summary>
public sealed class RemoteItem
{
    public RemoteItem(RemoteEntry entry) => Entry = entry;

    /// <summary>The ".." row at the top of the list: opens the parent folder. Never downloaded, renamed or deleted.</summary>
    public static RemoteItem ParentOf(string path) =>
        new(new RemoteEntry("..", SftpSession.Parent(path), true, false, 0, default, "")) { IsParent = true };

    public RemoteEntry Entry { get; }
    public bool IsParent { get; private init; }
    public string Name => Entry.Name;
    public bool IsDirectory => Entry.IsDirectory;
    public string SizeText => Entry.IsDirectory ? "" : FilesView.FormatSize(Entry.Size);
    public string ModifiedText => Entry.Modified == default ? "" : Entry.Modified.ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture);

    /// <summary>Screen readers and UI automation see the file name.</summary>
    public override string ToString() => Name;
}

/// <summary>
/// A "Files" tab: browse the server over SFTP, upload by dragging files in, download, rename, delete.
/// Devices without SFTP get a simple SCP send/fetch panel instead.
/// </summary>
public partial class FilesView : UserControl, ISessionView
{
    private readonly SessionLogin _login;
    private SshConnectOptions? _options;
    private SftpSession? _sftp;
    private CancellationTokenSource? _opCts;
    private string _path = "/";
    private string? _startDirectory;
    private bool _busy;
    private bool _scpMode;
    private bool _started;
    private bool _disposed;

    /// <param name="startDirectory">Folder to open first (e.g. the terminal's current folder); home if null or unreadable.</param>
    public FilesView(Connection connection, string? startDirectory = null)
    {
        InitializeComponent();
        Connection = connection;
        _startDirectory = startDirectory;
        _login = new SessionLogin(connection);
        Loaded += (_, _) =>
        {
            if (_started) return;
            _started = true;
            _ = ConnectAsync();
        };
        UpdateButtons();
    }

    public Connection Connection { get; }

    public string Kind => "Files";

    public SessionState State { get; private set; } = SessionState.Idle;

    /// <summary>SCP mode has no open connection between transfers, so it doesn't count as an active session.</summary>
    public bool IsActive => State == SessionState.Connecting || (State == SessionState.Connected && !_scpMode);

    public event EventHandler? StateChanged;

    // A file browser never closes itself.
    public event EventHandler? CloseRequested { add { } remove { } }

    public void Reconnect() => _ = ConnectAsync();

    public void FocusContent()
    {
        if (_scpMode) ScpPathBox.Focus();
        else List.Focus();
    }

    // ------------------------------------------------------------------ connection

    private async Task ConnectAsync()
    {
        if (_disposed || State == SessionState.Connecting) return;
        CancelOperation();
        DisposeSftp();
        _scpMode = false;
        ScpPanel.Visibility = Visibility.Collapsed;
        SetState(SessionState.Connecting);
        ShowOverlay($"Connecting to {Connection.Endpoint}…", "");
        SetStatus("");

        SshConnectOptions? options;
        try
        {
            options = await _login.PrepareAsync(Window.GetWindow(this), includeTunnels: false);
        }
        catch (Exception ex)
        {
            if (!_disposed) Failed("Couldn't connect", SshConnector.DescribeError(ex));
            return;
        }
        if (_disposed) return;
        if (options is null)
        {
            Failed("Login cancelled", "");
            return;
        }

        try
        {
            var sftp = await _login.ConnectAsync(options, verifier => SftpSession.ConnectAsync(options, verifier));
            if (_disposed)
            {
                sftp.Dispose();
                return;
            }
            _options = options;
            _sftp = sftp;
            sftp.Disconnected += reason => Dispatcher.BeginInvoke(() =>
            {
                if (ReferenceEquals(_sftp, sftp)) Dropped(reason);
            });
            SetState(SessionState.Connected);
            HideOverlay();
            var start = _startDirectory;
            _startDirectory = null; // only for the first connect; a reconnect starts at home as before
            if (start is null || !await NavigateAsync(start))
            {
                await NavigateAsync(sftp.HomeDirectory);
                if (start is not null) SetStatus($"Couldn't open {start}; showing your home folder instead.", error: true);
            }
            if (IsVisible) FocusContent();
        }
        catch (SftpUnavailableException)
        {
            if (_disposed) return;
            _options = options;
            _scpMode = true;
            HideOverlay();
            ScpPanel.Visibility = Visibility.Visible;
            SetState(SessionState.Connected);
            SetStatus("SCP mode: this device has no SFTP.");
            UpdateButtons();
        }
        catch (Exception ex)
        {
            if (_disposed) return;
            Log.Info($"Files: connect to {Connection.Endpoint} failed: {ex.Message}");
            Failed("Couldn't connect", SshConnector.DescribeError(ex));
        }
    }

    private void Failed(string title, string detail)
    {
        SetState(SessionState.Disconnected);
        ShowOverlay(title, detail, retry: true);
        UpdateButtons();
    }

    private void Dropped(string reason)
    {
        if (_disposed || State != SessionState.Connected) return;
        CancelOperation();
        DisposeSftp();
        Failed("Disconnected", reason);
    }

    private void Retry_Click(object sender, RoutedEventArgs e) => _ = ConnectAsync();

    // ------------------------------------------------------------------ browsing

    private async Task<bool> NavigateAsync(string path, string? select = null)
    {
        if (_sftp is not { } sftp) return false;
        return await RunAsync("Loading…", async ct =>
        {
            var resolved = await sftp.ResolveDirectoryAsync(path, ct);
            var entries = await sftp.ListAsync(resolved, ct);
            _path = resolved;
            PathBox.Text = resolved;
            var items = entries.Select(e => new RemoteItem(e)).ToList();
            var rows = resolved == "/" ? items : items.Prepend(RemoteItem.ParentOf(resolved)).ToList();
            List.ItemsSource = rows;
            var toSelect = rows.FirstOrDefault(i => i.Name == select) ?? items.FirstOrDefault() ?? rows.FirstOrDefault();
            if (toSelect is not null)
            {
                List.SelectedItem = toSelect;
                List.ScrollIntoView(toSelect);
            }
            SetStatus(items.Count == 0 ? "This folder is empty. Drop files here to upload them." :
                $"{items.Count} item{(items.Count == 1 ? "" : "s")}");
        });
    }

    /// <summary>The selected files and folders, without the ".." row.</summary>
    private IReadOnlyList<RemoteItem> Selected => List.SelectedItems.OfType<RemoteItem>().Where(i => !i.IsParent).ToList();

    /// <summary>The one selected row, ".." included (for Open).</summary>
    private RemoteItem? SelectedRow => List.SelectedItems.Count == 1 ? List.SelectedItem as RemoteItem : null;

    private void Up_Click(object sender, RoutedEventArgs e) => GoUp();

    /// <summary>The mouse's back button goes up a folder.</summary>
    private void View_MouseUp(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.XButton1 || _scpMode || _busy || _sftp is null) return;
        GoUp();
        e.Handled = true;
    }

    private void GoUp()
    {
        if (_path == "/") return;
        var current = _path.TrimEnd('/');
        _ = NavigateAsync(SftpSession.Parent(_path), select: current[(current.LastIndexOf('/') + 1)..]);
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => Refresh();

    private void Refresh(string? select = null) => _ = RefreshAsync(select);

    private Task RefreshAsync(string? select = null)
    {
        if (_scpMode) return Task.CompletedTask;
        if (_sftp is null) return ConnectAsync();
        return NavigateAsync(_path, select ?? (List.SelectedItem as RemoteItem)?.Name);
    }

    private void PathBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            _ = NavigateAsync(PathBox.Text);
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            PathBox.Text = _path;
            List.Focus();
            e.Handled = true;
        }
    }

    private void List_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject d && ItemsControl.ContainerFromElement(List, d) is ListViewItem { DataContext: RemoteItem item })
            Open(item);
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedRow is { } item) Open(item);
    }

    private void Open(RemoteItem item)
    {
        if (item.IsParent) GoUp();
        else if (item.IsDirectory) _ = NavigateAsync(item.Entry.FullPath);
        else _ = DownloadAsync(new[] { item });
    }

    private void List_KeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Enter when SelectedRow is { } item:
                Open(item);
                break;
            case Key.Back:
            case Key.System when e.SystemKey == Key.Up && Keyboard.Modifiers == ModifierKeys.Alt: // Alt+Up, as in Explorer
                GoUp();
                break;
            case Key.Delete:
                Delete_Click(sender, e);
                break;
            case Key.F2:
                Rename_Click(sender, e);
                break;
            case Key.F5:
                Refresh();
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    private void ListMenu_Opened(object sender, RoutedEventArgs e)
    {
        var sel = Selected;
        CtxOpen.IsEnabled = SelectedRow is not null;
        CtxRename.IsEnabled = sel.Count == 1;
        CtxDownload.IsEnabled = CtxDelete.IsEnabled = sel.Count > 0;
    }

    // ------------------------------------------------------------------ actions

    private void Upload_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = $"Upload to {_path}", Multiselect = true };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) _ = UploadAsync(dlg.FileNames);
    }

    private void List_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !_busy && State == SessionState.Connected ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void List_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) _ = UploadAsync(files);
    }

    private async Task UploadAsync(IReadOnlyList<string> localPaths)
    {
        if (_sftp is not { } sftp) return;
        var target = _path;
        var label = localPaths.Count == 1 ? Path.GetFileName(localPaths[0]) : $"{localPaths.Count} items";
        if (await RunAsync($"Uploading {label}…", ct => sftp.UploadAsync(localPaths, target, ProgressReporter("Uploading"), ct), showProgress: true))
        {
            await RefreshAsync(select: Path.GetFileName(localPaths[0].TrimEnd('\\', '/')));
            SetStatus($"Uploaded {label} to {target}");
        }
    }

    private void Download_Click(object sender, RoutedEventArgs e)
    {
        var sel = Selected;
        if (sel.Count > 0) _ = DownloadAsync(sel);
    }

    private async Task DownloadAsync(IReadOnlyList<RemoteItem> items)
    {
        if (_sftp is not { } sftp) return;
        var owner = Window.GetWindow(this);

        if (items is [{ IsDirectory: false } file])
        {
            var save = new SaveFileDialog
            {
                Title = "Download",
                FileName = SftpSession.SafeLocalName(file.Name),
                InitialDirectory = DownloadsFolder(),
                Filter = "All files (*.*)|*.*",
            };
            if (save.ShowDialog(owner) != true) return;
            if (await RunAsync($"Downloading {file.Name}…", ct => sftp.DownloadFileAsync(file.Entry, save.FileName, ProgressReporter("Downloading"), ct), showProgress: true))
                SetStatus($"Downloaded {file.Name} to {save.FileName}");
            return;
        }

        var folder = new OpenFolderDialog { Title = "Download to folder", InitialDirectory = DownloadsFolder() };
        if (folder.ShowDialog(owner) != true) return;
        var label = items.Count == 1 ? items[0].Name : $"{items.Count} items";
        if (await RunAsync($"Downloading {label}…", ct => sftp.DownloadAsync(items.Select(i => i.Entry), folder.FolderName, ProgressReporter("Downloading"), ct), showProgress: true))
            SetStatus($"Downloaded {label} to {folder.FolderName}");
    }

    private void NewFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_sftp is not { } sftp) return;
        var name = InputDialog.Ask(Window.GetWindow(this), "New folder", $"New folder in {_path}:", "New folder");
        if (name is null) return;
        if (!ValidName(name)) return;
        _ = Do();

        async Task Do()
        {
            if (await RunAsync($"Creating {name}…", ct => sftp.CreateDirectoryAsync(SftpSession.Combine(_path, name), ct)))
                Refresh(select: name);
        }
    }

    private void Rename_Click(object sender, RoutedEventArgs e)
    {
        if (_sftp is not { } sftp || Selected is not [var item]) return;
        var name = InputDialog.Ask(Window.GetWindow(this), "Rename", $"New name for {item.Name}:", item.Name);
        if (name is null || name == item.Name || !ValidName(name)) return;
        _ = Do();

        async Task Do()
        {
            if (await RunAsync($"Renaming {item.Name}…", ct => sftp.RenameAsync(item.Entry.FullPath, SftpSession.Combine(_path, name), ct)))
                Refresh(select: name);
        }
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_sftp is not { } sftp) return;
        var items = Selected;
        if (items.Count == 0) return;
        var what = items.Count == 1 ? $"\"{items[0].Name}\"" : $"these {items.Count} items";
        var folders = items.Any(i => i.IsDirectory) ? "\n\nFolders are deleted with everything in them." : "";
        if (MessageBox.Show(Window.GetWindow(this), $"Delete {what} from {Connection.DisplayName}?{folders}\n\nThis can't be undone.",
                "Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        _ = Do();

        async Task Do()
        {
            var ok = await RunAsync($"Deleting {(items.Count == 1 ? items[0].Name : $"{items.Count} items")}…", async ct =>
            {
                foreach (var item in items) await sftp.DeleteAsync(item.Entry, ct);
            });
            if (ok) Refresh();
        }
    }

    private bool ValidName(string name)
    {
        if (name.Contains('/') || name is "." or "..")
        {
            SetStatus("A name can't contain \"/\".", error: true);
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------ SCP fallback

    private void ScpSend_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Send with SCP", Multiselect = true };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true) _ = ScpSendAsync(dlg.FileNames);
    }

    private void ScpPanel_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) _ = ScpSendAsync(files.Where(File.Exists).ToList());
    }

    private async Task ScpSendAsync(IReadOnlyList<string> files)
    {
        if (_options is not { } options || files.Count == 0) return;
        var remote = ScpPathBox.Text.Trim();
        if (files.Count > 1 && remote.Length > 0 && !remote.EndsWith('/') && !remote.EndsWith(':')) remote += "/";
        var label = files.Count == 1 ? Path.GetFileName(files[0]) : $"{files.Count} files";
        var ok = await RunAsync($"Sending {label}…", async ct =>
        {
            foreach (var f in files)
                await ScpTransfer.UploadAsync(options, HostKeyPrompt.CreateVerifier(_login.HostKeys), f, remote, ProgressReporter("Sending"), ct);
        }, showProgress: true);
        if (ok) SetStatus($"Sent {label}{(remote.Length > 0 ? " to " + remote : "")}.");
    }

    private void ScpFetch_Click(object sender, RoutedEventArgs e)
    {
        var remote = ScpPathBox.Text.Trim();
        if (remote.Length == 0 || remote.EndsWith('/'))
        {
            SetStatus("Enter the path of the file to fetch first.", error: true);
            ScpPathBox.Focus();
            return;
        }
        var name = remote[(Math.Max(remote.LastIndexOf('/'), remote.LastIndexOf(':')) + 1)..];
        var save = new SaveFileDialog { Title = "Fetch with SCP", FileName = SftpSession.SafeLocalName(name), InitialDirectory = DownloadsFolder() };
        if (save.ShowDialog(Window.GetWindow(this)) != true || _options is not { } options) return;
        _ = Do();

        async Task Do()
        {
            if (await RunAsync($"Fetching {name}…", ct => ScpTransfer.DownloadAsync(options, HostKeyPrompt.CreateVerifier(_login.HostKeys), remote, save.FileName, ProgressReporter("Fetching"), ct), showProgress: true))
                SetStatus($"Fetched {name} to {save.FileName}");
        }
    }

    // ------------------------------------------------------------------ plumbing

    /// <summary>Runs one operation at a time, with status, optional progress bar and Cancel.</summary>
    private async Task<bool> RunAsync(string busyText, Func<CancellationToken, Task> operation, bool showProgress = false)
    {
        if (_busy || _disposed) return false;
        _busy = true;
        _opCts = new CancellationTokenSource();
        SetStatus(busyText);
        Progress.Value = 0;
        Progress.IsIndeterminate = true;
        Progress.Visibility = showProgress ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = showProgress ? Visibility.Visible : Visibility.Collapsed;
        UpdateButtons();
        Mouse.OverrideCursor = showProgress ? null : Cursors.AppStarting;
        try
        {
            await operation(_opCts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            if (!_disposed) SetStatus("Cancelled.");
        }
        catch (Exception ex)
        {
            if (_disposed) return false;
            SetStatus(SshConnector.DescribeError(ex), error: true);
            if (_sftp is { IsConnected: false }) Dropped(SshConnector.DescribeError(ex));
        }
        finally
        {
            Mouse.OverrideCursor = null;
            _busy = false;
            _opCts?.Dispose();
            _opCts = null;
            if (!_disposed)
            {
                Progress.Visibility = Visibility.Collapsed;
                CancelButton.Visibility = Visibility.Collapsed;
                UpdateButtons();
            }
        }
        return false;
    }

    private IProgress<TransferProgress> ProgressReporter(string verb) => new Progress<TransferProgress>(p =>
    {
        if (_disposed || !_busy) return;
        if (p.BytesTotal > 0)
        {
            Progress.IsIndeterminate = false;
            Progress.Value = 100.0 * p.BytesDone / p.BytesTotal;
            SetStatus($"{verb} {p.CurrentFile} – {FormatSize(p.BytesDone)} of {FormatSize(p.BytesTotal)}");
        }
        else
        {
            SetStatus($"{verb} {p.CurrentFile} – {FormatSize(p.BytesDone)}");
        }
    });

    private void Cancel_Click(object sender, RoutedEventArgs e) => CancelOperation();

    private void CancelOperation()
    {
        try { _opCts?.Cancel(); } catch (ObjectDisposedException) { }
    }

    private void UpdateButtons()
    {
        bool ready = State == SessionState.Connected && !_busy && !_scpMode && _sftp is not null;
        UpButton.IsEnabled = ready && _path != "/";
        PathBox.IsEnabled = ready;
        UploadButton.IsEnabled = NewFolderButton.IsEnabled = ready;
        DownloadButton.IsEnabled = DeleteButton.IsEnabled = ready;
        RefreshButton.IsEnabled = !_busy && !_scpMode;
        List.IsEnabled = !_scpMode && _sftp is not null;
        ScpSendButton.IsEnabled = ScpFetchButton.IsEnabled = _scpMode && !_busy;
        Toolbar.Visibility = _scpMode ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ShowOverlay(string title, string text, bool retry = false)
    {
        OverlayTitle.Text = title;
        OverlayText.Text = text;
        OverlayText.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
        RetryButton.Visibility = retry ? Visibility.Visible : Visibility.Collapsed;
        Overlay.Visibility = Visibility.Visible;
        List.Visibility = Visibility.Hidden;
    }

    private void HideOverlay()
    {
        Overlay.Visibility = Visibility.Collapsed;
        List.Visibility = Visibility.Visible;
    }

    private void SetStatus(string text, bool error = false)
    {
        StatusText.Text = text;
        StatusText.ToolTip = string.IsNullOrEmpty(text) ? null : text;
        StatusText.Foreground = error ? (Brush)FindResource("ErrorBrush") : new SolidColorBrush(Color.FromRgb(0x37, 0x41, 0x51));
    }

    private void SetState(SessionState state)
    {
        if (State == state) return;
        State = state;
        StateChanged?.Invoke(this, EventArgs.Empty);
        UpdateButtons();
    }

    private static string DownloadsFolder()
    {
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return Directory.Exists(downloads) ? downloads : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    }

    public static string FormatSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{v:0.#} {units[u]}";
    }

    private void DisposeSftp()
    {
        var s = _sftp;
        _sftp = null;
        if (s is not null) Task.Run(s.Dispose);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CancelOperation();
        DisposeSftp();
    }
}

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media.Animation;
using AdornerLayer = System.Windows.Documents.AdornerLayer;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using SimpleSSH.Controls;
using SimpleSSH.Core;
using SimpleSSH.Core.Models;
using SimpleSSH.Services;
using SimpleSSH.ViewModels;
using SimpleSSH.Views;

namespace SimpleSSH;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<TagNode> _tagNodes = new();
    private readonly HashSet<string> _collapsedTags;
    private bool _suppressExpansionTracking;

    public MainWindow()
    {
        InitializeComponent();
        _collapsedTags = new HashSet<string>(AppServices.Settings.CollapsedTags, StringComparer.OrdinalIgnoreCase);
        Tree.ItemsSource = _tagNodes;
        DataPathText.Text = AppPaths.ConnectionsFile;
        MenuCloseTabOnExit.IsChecked = AppServices.Settings.CloseTabOnExit;
        MenuConfirmTagMoves.IsChecked = AppServices.Settings.ConfirmTagMoves;

        RestoreWindowPlacement();
        AppServices.Connections.Changed += (_, _) => RebuildTree();
        AppServices.Connections.LockChanged += (_, _) =>
        {
            UpdateLockUi();
            UpdateStatus();
        };
        UpdateLockUi();
        RebuildTree();
        UpdateTabUi();
    }

    // =====================================================================================
    // Tree
    // =====================================================================================

    private Connection? SelectedConnection => (Tree.SelectedItem as ConnectionNode)?.Connection;
    private TagNode? SelectedTag => Tree.SelectedItem switch
    {
        TagNode t => t,
        ConnectionNode c => c.Parent,
        _ => null,
    };

    private void RebuildTree(Guid? selectId = null, string? selectUnderTag = null)
    {
        var keepId = selectId ?? SelectedConnection?.Id;
        var keepTag = selectUnderTag ?? (SelectedConnection is null ? (Tree.SelectedItem as TagNode)?.StateKey : (Tree.SelectedItem as ConnectionNode)?.Parent.StateKey);
        var filter = SearchBox.Text;
        var filtering = !string.IsNullOrWhiteSpace(filter);

        _suppressExpansionTracking = true;
        try
        {
            foreach (var old in _tagNodes) old.PropertyChanged -= TagNode_PropertyChanged;
            _tagNodes.Clear();

            ConnectionNode? toSelect = null;
            TagNode? tagToSelect = null;
            foreach (var group in TagGrouping.Build(AppServices.Connections.Connections, filter))
            {
                var tagNode = new TagNode(group.Tag, group.IsUntagged);
                foreach (var c in group.Connections)
                {
                    var node = new ConnectionNode(c, tagNode);
                    tagNode.Children.Add(node);
                    // Prefer re-selecting under the same tag as before.
                    if (keepId == c.Id && (toSelect is null || tagNode.StateKey == keepTag)) toSelect = node;
                }
                tagNode.IsExpanded = filtering || !_collapsedTags.Contains(tagNode.StateKey);
                tagNode.PropertyChanged += TagNode_PropertyChanged;
                if (tagNode.StateKey == keepTag) tagToSelect = tagNode;
                _tagNodes.Add(tagNode);
            }

            if (toSelect is not null)
            {
                toSelect.Parent.IsExpanded = true;
                toSelect.IsSelected = true;
            }
            else if (tagToSelect is not null && selectId is null)
            {
                tagToSelect.IsSelected = true;
            }
        }
        finally
        {
            _suppressExpansionTracking = false;
        }

        var total = AppServices.Connections.Connections.Count;
        EmptyTreeHint.Visibility = total == 0 ? Visibility.Visible : Visibility.Collapsed;
        UpdateStatus();
        UpdateToolbar();
    }

    private void TagNode_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_suppressExpansionTracking || e.PropertyName != nameof(TreeNode.IsExpanded) || sender is not TagNode tag) return;
        if (!string.IsNullOrWhiteSpace(SearchBox.Text)) return; // filter expands everything temporarily
        if (tag.IsExpanded) _collapsedTags.Remove(tag.StateKey);
        else _collapsedTags.Add(tag.StateKey);
        AppServices.Settings.CollapsedTags = _collapsedTags.ToList();
    }

    private void Tree_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var item = FindAncestor<TreeViewItem>(e.OriginalSource as DependencyObject);
        if (item?.DataContext is ConnectionNode node)
        {
            e.Handled = true;
            OpenConnection(node.Connection);
        }
    }

    private void Tree_KeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Enter when SelectedConnection is { } c:
                OpenConnection(c);
                e.Handled = true;
                break;
            case Key.Delete when SelectedConnection is not null:
                Delete_Click(sender, e);
                e.Handled = true;
                break;
            case Key.F2 when SelectedConnection is not null:
                Edit_Click(sender, e);
                e.Handled = true;
                break;
        }
    }

    private void Tree_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var item = FindAncestor<TreeViewItem>(e.OriginalSource as DependencyObject);
        if (item is null) return;
        item.IsSelected = true;
        item.Focus();
    }

    private void Tree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e) => UpdateToolbar();

    private void TreeContextMenu_Opened(object sender, RoutedEventArgs e)
    {
        bool hasConnection = SelectedConnection is not null;
        CtxConnect.IsEnabled = CtxFiles.IsEnabled = CtxRun.IsEnabled = CtxEdit.IsEnabled = CtxDuplicate.IsEnabled = CtxDelete.IsEnabled = hasConnection;
        ShowProtocolItems(CtxFiles, CtxRun, CtxRdpWindow, CtxBrowser, CtxKeyLogin, CtxPasswordLogin);
        var tag = SelectedTag;
        CtxOpenAll.IsEnabled = tag is { Count: > 0 };
        CtxOpenAll.Header = tag is null ? "Open _all in this tag" : $"Open _all in \"{tag.Name.Replace("_", "__")}\" ({tag.Count})";
        CtxRunAll.IsEnabled = tag is not null && SshOnly(tag.Children.Select(n => n.Connection)).Count > 0;
        CtxRunAll.Header = tag is null ? "Run command on all in this tag…" : $"Run command on all in \"{tag.Name.Replace("_", "__")}\"…";
    }

    /// <summary>
    /// Files and Run command are SSH features; Remote Desktop connections get "Open in Remote Desktop window" and
    /// server consoles and web apps "Open in browser" instead.
    /// </summary>
    private void ShowProtocolItems(MenuItem files, MenuItem run, MenuItem rdpWindow, MenuItem browser, MenuItem keyLogin, MenuItem passwordLogin)
    {
        var c = SelectedConnection;
        bool ssh = c is null || c.IsSsh;
        files.Visibility = run.Visibility = keyLogin.Visibility = ssh ? Visibility.Visible : Visibility.Collapsed;
        // The public key is never locked away, so it shows which way the switch goes even while passwords are locked.
        bool usesKey = ssh && !string.IsNullOrEmpty(c?.PublicKey);
        keyLogin.Header = usesKey ? "_Lock down (key login)…" : "Switch to _key login…";
        passwordLogin.Visibility = usesKey ? Visibility.Visible : Visibility.Collapsed;
        rdpWindow.Visibility = c?.IsRdp == true ? Visibility.Visible : Visibility.Collapsed;
        browser.Visibility = c?.IsWebPage == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private static List<Connection> SshOnly(IEnumerable<Connection> connections) => connections.Where(c => c.IsSsh).ToList();

    private void UpdateToolbar()
    {
        bool hasConnection = SelectedConnection is not null;
        EditButton.IsEnabled = hasConnection;
        DeleteButton.IsEnabled = hasConnection;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        var empty = string.IsNullOrEmpty(SearchBox.Text);
        SearchPlaceholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        ClearSearchButton.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
        RebuildTree();
    }

    private void SearchBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            SearchBox.Clear();
            e.Handled = true;
        }
        else if (e.Key is Key.Down or Key.Enter)
        {
            // Jump into the results; Enter opens the first match.
            var first = _tagNodes.SelectMany(t => t.Children).FirstOrDefault();
            if (first is null) return;
            first.Parent.IsExpanded = true;
            first.IsSelected = true;
            if (e.Key == Key.Enter) OpenConnection(first.Connection);
            else FocusSelectedTreeItem();
            e.Handled = true;
        }
    }

    private void ClearSearch_Click(object sender, RoutedEventArgs e)
    {
        SearchBox.Clear();
        SearchBox.Focus();
    }

    private void FocusSelectedTreeItem()
    {
        Dispatcher.BeginInvoke(() =>
        {
            Tree.Focus();
            if (Tree.SelectedItem is ConnectionNode node &&
                Tree.ItemContainerGenerator.ContainerFromItem(node.Parent) is TreeViewItem parent &&
                parent.ItemContainerGenerator.ContainerFromItem(node) is TreeViewItem item)
            {
                item.Focus();
            }
        }, System.Windows.Threading.DispatcherPriority.Input);
    }

    private void ConfirmTagMoves_Click(object sender, RoutedEventArgs e)
    {
        AppServices.Settings.ConfirmTagMoves = MenuConfirmTagMoves.IsChecked;
        AppServices.SaveSettings();
    }

    // =====================================================================================
    // Drag a connection onto another tag
    // =====================================================================================

    private Point _dragStart;
    private ConnectionNode? _dragCandidate;
    private TagNode? _dropHighlight;

    private void Tree_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        _dragStart = e.GetPosition(Tree);
        _dragCandidate = FindAncestor<TreeViewItem>(e.OriginalSource as DependencyObject)?.DataContext as ConnectionNode;
        // Not from the expander arrow or the scroll bar.
        if (FindAncestor<System.Windows.Controls.Primitives.ToggleButton>(e.OriginalSource as DependencyObject) is not null ||
            FindAncestor<System.Windows.Controls.Primitives.ScrollBar>(e.OriginalSource as DependencyObject) is not null)
            _dragCandidate = null;
    }

    private void Tree_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (_dragCandidate is not { } node || e.LeftButton != MouseButtonState.Pressed) return;
        var delta = e.GetPosition(Tree) - _dragStart;
        if (Math.Abs(delta.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(delta.Y) < SystemParameters.MinimumVerticalDragDistance)
            return;
        _dragCandidate = null;
        try
        {
            DragDrop.DoDragDrop(Tree, new DataObject(typeof(ConnectionNode), node), DragDropEffects.Move | DragDropEffects.Copy);
        }
        finally
        {
            SetDropHighlight(null);
        }
    }

    /// <summary>The tag group under the pointer: a tag header, or the tag a connection row belongs to.</summary>
    private static TagNode? DropTargetAt(DragEventArgs e) =>
        FindAncestor<TreeViewItem>(e.OriginalSource as DependencyObject)?.DataContext switch
        {
            TagNode t => t,
            ConnectionNode c => c.Parent,
            _ => null,
        };

    private void Tree_DragOver(object sender, DragEventArgs e)
    {
        e.Handled = true;
        AutoScrollTree(e);
        var source = e.Data.GetData(typeof(ConnectionNode)) as ConnectionNode;
        var target = DropTargetAt(e);
        bool copy = (e.KeyStates & DragDropKeyStates.ControlKey) != 0;
        if (source is null || target is null || target.StateKey == source.Parent.StateKey ||
            TagGrouping.RetagForDrop(source.Connection.Tags, TagOf(source.Parent), TagOf(target), copy) is null)
        {
            e.Effects = DragDropEffects.None;
            SetDropHighlight(null);
            return;
        }
        e.Effects = copy ? DragDropEffects.Copy : DragDropEffects.Move;
        SetDropHighlight(target);
    }

    private void Tree_DragLeave(object sender, DragEventArgs e) => SetDropHighlight(null);

    private void Tree_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        SetDropHighlight(null);
        if (e.Data.GetData(typeof(ConnectionNode)) is not ConnectionNode source || DropTargetAt(e) is not { } target) return;
        bool copy = (e.KeyStates & DragDropKeyStates.ControlKey) != 0;
        // Let the drag finish (cursor, capture) before showing a dialog.
        Dispatcher.BeginInvoke(() => MoveToTag(source, target, copy), System.Windows.Threading.DispatcherPriority.Input);
    }

    private static string? TagOf(TagNode node) => node.IsUntagged ? null : node.Name;

    private void MoveToTag(ConnectionNode source, TagNode target, bool copy)
    {
        var c = AppServices.Connections.Find(source.Connection.Id);
        if (c is null || target.StateKey == source.Parent.StateKey) return;
        var newTags = TagGrouping.RetagForDrop(c.Tags, TagOf(source.Parent), TagOf(target), copy);
        if (newTags is null) return;

        if (AppServices.Settings.ConfirmTagMoves)
        {
            string heading, detail;
            if (target.IsUntagged)
            {
                heading = $"Remove all tags from \"{c.DisplayName}\"?";
                detail = $"It is tagged {Connection.FormatTags(c.Tags)}.";
            }
            else if (copy)
            {
                heading = $"Also tag \"{c.DisplayName}\" as {target.Name}?";
                detail = $"It stays under {source.Parent.Name} too.";
            }
            else
            {
                heading = source.Parent.IsUntagged
                    ? $"Tag \"{c.DisplayName}\" as {target.Name}?"
                    : $"Move \"{c.DisplayName}\" from {source.Parent.Name} to {target.Name}?";
                var others = newTags.Where(t => !string.Equals(t, target.Name, StringComparison.OrdinalIgnoreCase)).ToList();
                detail = others.Count > 0 ? $"It stays under {Connection.FormatTags(others)} too." : "";
            }
            var dlg = new ConfirmDialog(copy ? "Add tag" : "Move connection", heading, detail, copy ? "Add tag" : "Move")
            {
                Owner = this,
            };
            if (dlg.ShowDialog() != true) return;
            if (dlg.DontAskAgain)
            {
                AppServices.Settings.ConfirmTagMoves = false;
                MenuConfirmTagMoves.IsChecked = false;
                AppServices.SaveSettings();
                SetStatus("Moves between tags won't ask again. Turn it back on under View → Confirm before moving between tags.");
            }
        }

        var edited = c.Clone();
        edited.Tags = newTags;
        TrySave(() => AppServices.Connections.Update(edited), null);
        RebuildTree(c.Id, target.StateKey);
        RefreshTabHeaders();
    }

    private void SetDropHighlight(TagNode? node)
    {
        if (_dropHighlight == node) return;
        if (_dropHighlight is not null) _dropHighlight.IsDropTarget = false;
        _dropHighlight = node;
        if (node is not null) node.IsDropTarget = true;
    }

    /// <summary>Scrolls the tree while dragging near its top or bottom edge.</summary>
    private void AutoScrollTree(DragEventArgs e)
    {
        if (FindDescendant<ScrollViewer>(Tree) is not { } sv) return;
        var y = e.GetPosition(Tree).Y;
        const double edge = 24;
        if (y < edge) sv.LineUp();
        else if (y > Tree.ActualHeight - edge) sv.LineDown();
    }

    private static T? FindDescendant<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match) return match;
            if (FindDescendant<T>(child) is { } found) return found;
        }
        return null;
    }

    private void CloseTabOnExit_Click(object sender, RoutedEventArgs e)
    {
        AppServices.Settings.CloseTabOnExit = MenuCloseTabOnExit.IsChecked;
        AppServices.SaveSettings();
    }

    private void ExpandAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var t in _tagNodes) t.IsExpanded = true;
    }

    private void CollapseAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var t in _tagNodes) t.IsExpanded = false;
    }

    private void FocusSearch_Click(object sender, RoutedEventArgs e)
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
    }

    // =====================================================================================
    // Connection CRUD
    // =====================================================================================

    private async void NewConnection_Click(object sender, RoutedEventArgs e)
    {
        var tag = SelectedTag is { IsUntagged: false } t ? t.Name : null;
        var dlg = new ConnectionDialog(null, AppServices.Connections.AllTags(), tag) { Owner = this };
        if (dlg.ShowDialog() != true || !await UnlockToSave(dlg.Result)) return;
        TrySave(() => AppServices.Connections.Add(dlg.Result), dlg.Result.Id);
    }

    private async void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { } c) return;
        if (!await UnlockFor(c, "Unlock to edit the saved password.")) return;
        var dlg = new ConnectionDialog(c, AppServices.Connections.AllTags()) { Owner = this };
        if (dlg.ShowDialog() != true || !await UnlockToSave(dlg.Result)) return;
        TrySave(() => AppServices.Connections.Update(dlg.Result), c.Id);
        RefreshTabHeaders();
        foreach (var terminal in SessionViews().OfType<TerminalView>().Where(t => t.Connection.Id == c.Id)) terminal.ApplyConnectionOptions();
    }

    private async void Duplicate_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { } c) return;
        if (!await UnlockFor(c, "Unlock to copy the saved password.")) return;
        var copy = c.Clone();
        copy.Id = Guid.NewGuid();
        copy.Name = c.DisplayName + " (copy)";
        var dlg = new ConnectionDialog(copy, AppServices.Connections.AllTags()) { Owner = this, Title = "Duplicate connection" };
        if (dlg.ShowDialog() != true || !await UnlockToSave(dlg.Result)) return;
        TrySave(() => AppServices.Connections.Add(dlg.Result), dlg.Result.Id);
    }

    /// <summary>The dialogs show saved passwords, so locked ones must be unlocked first.</summary>
    private Task<bool> UnlockFor(Connection c, string reason) =>
        AppServices.Connections.HasLockedSecrets(c.Id) ? SecurityKeyUi.EnsureUnlockedAsync(this, reason) : Task.FromResult(true);

    /// <summary>
    /// A new password is only saved unlocked, so the security key protects it (not just Windows).
    /// False if the person didn't unlock: nothing is saved.
    /// </summary>
    private async Task<bool> UnlockToSave(Connection edited)
    {
        if (!AppServices.Connections.NeedsUnlockToSave(edited)) return true;
        if (await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock to save the password with your security key.")) return true;
        MessageBox.Show(this, "Not saved: saved passwords are locked with your security key. Unlock it to save a password.",
            "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Information);
        return false;
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { } c) return;
        var openTabs = SessionViews().Count(v => v.Connection.Id == c.Id);
        var msg = $"Remove the connection \"{c.DisplayName}\" ({c.Endpoint})?" +
                  (openTabs > 0 ? $"\n\n{openTabs} open tab(s) for it will stay open until you close them." : "");
        if (MessageBox.Show(this, msg, "Remove connection", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        TrySave(() => AppServices.Connections.Remove(c.Id), null);
    }

    private void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is { } c) OpenConnection(c);
    }

    private async void OpenFiles_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { } c) return;
        // From the connection's own terminal tab, start where the shell is.
        if (CurrentTerminal is { } t && t.Connection.Id == c.Id) await OpenFilesHere(t);
        else OpenFiles(c);
    }

    /// <summary>Opens the file browser in the folder the terminal's shell is in (home if that can't be found out).</summary>
    private async Task OpenFilesHere(TerminalView terminal)
    {
        var here = terminal.CurrentDirectory;
        if (here is null)
        {
            SetStatus("Finding the terminal's folder…");
            here = await terminal.GetCurrentDirectoryAsync();
            SetStatus("");
        }
        OpenFiles(terminal.Connection, here);
    }

    private void RunCommand_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is { } c) ShowRunCommand(new[] { c }, c.DisplayName);
    }

    private void RunCommandOnTag_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTag is { Count: > 0 } tag) ShowRunCommand(tag.Children.Select(n => n.Connection).ToList(), tag.Name);
    }

    /// <summary>Opens the Run command window for the SSH connections among <paramref name="connections"/>.</summary>
    public void ShowRunCommand(IReadOnlyList<Connection> connections, string scope)
    {
        var ssh = SshOnly(connections);
        if (ssh.Count == 0)
        {
            MessageBox.Show(this, "Run command works on SSH connections only.", "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        new RunCommandWindow(ssh, scope) { Owner = this }.Show();
    }

    private async void KeyLogin_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { IsSsh: true } c) return;
        // The dialog reads the saved password and key, and saves the new key: both need the security key unlocked.
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock to switch to key login.")) return;
        var dlg = new KeyLoginDialog(c) { Owner = this };
        dlg.ShowDialog();
        RebuildTree(c.Id);
        if (dlg.ByHandRequested) AddKeyByHand(c.Id);
    }

    /// <summary>Key login for a server that refuses passwords: the person adds the key from a session that gets in.</summary>
    private void AddKeyByHand(Guid id)
    {
        if (AppServices.Connections.Find(id) is not { } c) return;
        if (string.IsNullOrWhiteSpace(c.Username))
        {
            MessageBox.Show(this, $"Set the username for {c.DisplayName} first (Edit), so SimpleSSH knows whose account gets the key.",
                "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        Core.Ssh.ProxySettings? proxy = null;
        if (!string.IsNullOrWhiteSpace(c.Proxy) && !Core.Ssh.ProxySettings.TryParse(c.Proxy, out proxy, out var proxyError))
        {
            MessageBox.Show(this, proxyError + " (Edit the connection to fix it.)", "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var dlg = new AddKeyByHandDialog(c.DisplayName, c.Host, c.Port, c.Username, proxy,
            c.PrivateKey, c.PublicKey, c.PrivateKeyPassphrase, "Test and save") { Owner = this };
        if (dlg.ShowDialog() != true || AppServices.Connections.Find(id) is not { } current) return;
        try
        {
            var edited = current.Clone();
            edited.PrivateKey = dlg.PrivateKey;
            edited.PublicKey = dlg.PublicKey;
            edited.PrivateKeyPath = null;
            edited.PrivateKeyPassphrase = dlg.Passphrase;
            AppServices.Connections.Update(edited);
            SetStatus(dlg.Tested
                ? $"Key login works for {c.DisplayName}. SimpleSSH now logs in with the key."
                : $"Key kept for {c.DisplayName} without a test. Connect to try it.");
        }
        catch (Exception ex)
        {
            Log.Error("Could not save the key", ex);
            MessageBox.Show(this, "Could not save the key: " + ex.Message, "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void PasswordLogin_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is not { IsSsh: true } c || string.IsNullOrEmpty(c.PublicKey)) return;
        if (!await SecurityKeyUi.EnsureUnlockedAsync(this, "Unlock to switch to password login.")) return;
        new PasswordLoginDialog(c) { Owner = this }.ShowDialog();
        RebuildTree(c.Id);
    }

    private async void OpenRdpWindow_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is { IsRdp: true } c) await RdpLauncher.OpenAsync(this, c);
    }

    private void OpenInBrowser_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedConnection is { IsWebPage: true } c) OpenInBrowser(c);
    }

    /// <summary>The controller's or web app's own page in the default browser (the person logs in there).</summary>
    private void OpenInBrowser(Connection c)
    {
        var url = Core.Bmc.ServerConsoleClient.BuildBaseUri(c.Host, c.Port).AbsoluteUri;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { SetStatus($"Couldn't open {url}: {ex.Message}"); }
    }

    private void OpenAllInTag_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTag is not { } tag) return;
        if (tag.Count > 10 &&
            MessageBox.Show(this, $"Open {tag.Count} sessions?", "Open all", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        foreach (var node in tag.Children.ToList()) OpenConnection(node.Connection);
    }

    private void TrySave(Action action, Guid? selectId)
    {
        try
        {
            action();
            if (selectId is { } id) RebuildTree(id);
        }
        catch (Exception ex)
        {
            Log.Error("Saving connections failed", ex);
            MessageBox.Show(this, $"Could not save connections:\n{ex.Message}", "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Error);
            ReloadFromDisk(quiet: true);
        }
    }

    private void ReloadConnections_Click(object sender, RoutedEventArgs e) => ReloadFromDisk(quiet: false);

    private void ReloadFromDisk(bool quiet)
    {
        try
        {
            AppServices.Connections.Load();
            RebuildTree();
            if (!quiet) SetStatus($"Reloaded {AppServices.Connections.Connections.Count} connection(s) from disk.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Cannot reload connections", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // =====================================================================================
    // Tabs
    // =====================================================================================

    private IEnumerable<ISessionView> SessionViews() =>
        Tabs.Items.OfType<TabItem>().Select(t => (ISessionView)t.Tag);

    private TabItem? CurrentTab => Tabs.SelectedItem as TabItem;
    private ISessionView? CurrentView => CurrentTab?.Tag as ISessionView;
    private TerminalView? CurrentTerminal => CurrentView as TerminalView;

    /// <summary>Opens a terminal tab, a Remote Desktop tab, or a server console or web app tab.</summary>
    public void OpenConnection(Connection connection)
    {
        if (WithGoodHost(connection) is not { } c) return;
        OpenTab(c.Protocol switch
        {
            ConnectionProtocol.Rdp => new RdpView(c),
            ConnectionProtocol.Console or ConnectionProtocol.Web => new ConsoleView(c),
            _ => new TerminalView(c),
        });
    }

    /// <summary>
    /// A connection saved with a malformed host (e.g. "ilo-01.example.com/") can't connect: offer the fix, or say how to fix it.
    /// Returns the connection to open, or null to not open it.
    /// </summary>
    private Connection? WithGoodHost(Connection c)
    {
        if (HostCheck.Problem(c.Host, out var fix) is not { } problem) return c;
        if (fix is null)
        {
            MessageBox.Show(this, $"{c.DisplayName} can't connect: its host \"{c.Host}\" isn't valid. {problem}\n\nEdit the connection to fix it.",
                "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }
        if (MessageBox.Show(this, $"{c.DisplayName} can't connect: its host \"{c.Host}\" isn't valid. {problem}\n\nUse \"{fix}\" instead? It will be saved.",
                "SimpleSSH", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return null;

        var edited = (AppServices.Connections.Find(c.Id) ?? c).Clone();
        if (edited.Name == edited.Host) edited.Name = fix;
        edited.Host = fix;
        TrySave(() => AppServices.Connections.Update(edited), c.Id);
        RefreshTabHeaders();
        return AppServices.Connections.Find(c.Id) ?? edited;
    }

    /// <summary>Opens a file browser tab (SFTP, or SCP for devices without it). SSH connections only.</summary>
    public void OpenFiles(Connection connection, string? startDirectory = null)
    {
        if (!connection.IsSsh)
        {
            SetStatus($"{connection.DisplayName} is a {(connection.IsRdp ? "Remote Desktop" : "server console")} connection; it has no file browser.");
            return;
        }
        if (WithGoodHost(connection) is not { } c) return;
        OpenTab(new FilesView(c, startDirectory));
    }

    private void OpenTab(ISessionView view)
    {
        var element = (UIElement)view;
        element.Visibility = Visibility.Collapsed;
        var tab = new TabItem { Tag = view };
        tab.Header = BuildTabHeader(tab, view);
        tab.ContextMenu = BuildTabContextMenu(tab);
        tab.MouseUp += (_, e) =>
        {
            if (e.ChangedButton == MouseButton.Middle)
            {
                CloseTab(tab);
                e.Handled = true;
            }
        };
        view.StateChanged += (_, _) =>
        {
            UpdateTabHeader(tab);
            UpdateStatus();
        };
        view.CloseRequested += (_, _) => CloseTab(tab);

        TerminalHost.Children.Add(element);
        Tabs.Items.Add(tab);
        Tabs.SelectedItem = tab;
        UpdateTabUi();
    }

    private static object BuildTabHeader(TabItem tab, ISessionView view)
    {
        var dot = new Ellipse { Width = 8, Height = 8, Margin = new Thickness(0, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center };
        var title = new TextBlock { VerticalAlignment = VerticalAlignment.Center, MaxWidth = 220, TextTrimming = TextTrimming.CharacterEllipsis };
        var close = new Button { Style = (Style)Application.Current.Resources["TabCloseButton"] };
        close.Click += (_, _) => ((MainWindow)Window.GetWindow(tab)!).CloseTab(tab);

        var panel = new StackPanel { Orientation = Orientation.Horizontal, Background = Brushes.Transparent };
        panel.Children.Add(dot);
        panel.Children.Add(title);
        panel.Children.Add(close);
        panel.Tag = (dot, title);
        ApplyHeader(panel, view);
        return panel;
    }

    private static void ApplyHeader(StackPanel panel, ISessionView view)
    {
        var (dot, title) = ((Ellipse, TextBlock))panel.Tag;
        title.Text = view.Kind.Length == 0 ? view.Connection.DisplayName : $"{view.Connection.DisplayName} · {view.Kind}";
        var (brushKey, state) = view.State switch
        {
            SessionState.Connected => ("ConnectedBrush", "Connected"),
            SessionState.Connecting => ("ConnectingBrush", "Connecting…"),
            SessionState.Disconnected => ("DisconnectedBrush", "Disconnected"),
            _ => ("DisconnectedBrush", "Starting…"),
        };
        dot.Fill = (Brush)Application.Current.Resources[brushKey];
        panel.ToolTip = $"{view.Connection.DisplayName} – {view.Connection.Username}{(string.IsNullOrEmpty(view.Connection.Username) ? "" : "@")}{view.Connection.Endpoint}\n{state}";
    }

    private static void UpdateTabHeader(TabItem tab)
    {
        if (tab.Header is StackPanel panel && tab.Tag is ISessionView view) ApplyHeader(panel, view);
    }

    private void RefreshTabHeaders()
    {
        foreach (var tab in Tabs.Items.OfType<TabItem>()) UpdateTabHeader(tab);
    }

    private ContextMenu BuildTabContextMenu(TabItem tab)
    {
        var menu = new ContextMenu();
        MenuItem Item(string header, Action action, string? gesture = null)
        {
            var mi = new MenuItem { Header = header, InputGestureText = gesture ?? "" };
            mi.Click += (_, _) => action();
            menu.Items.Add(mi);
            return mi;
        }
        var view = (ISessionView)tab.Tag;
        Item("_Reconnect", () => view.Reconnect(), "Ctrl+Shift+R");
        // No "Duplicate" for Remote Desktop: a second tab with the same account would take over the first one's session.
        // Nor for a console: the controller would share (or hand over) the same screen.
        if (view is not (RdpView or ConsoleView)) Item("_Duplicate tab", () => DuplicateTab(view));
        if (view is RdpView rdp)
        {
            Item("_Full screen", () => rdp.EnterFullScreen(), "Ctrl+Alt+Break");
            Item("Open in Remote _Desktop window", () => _ = RdpLauncher.OpenAsync(this, view.Connection));
        }
        else if (view is ConsoleView)
        {
            Item("Open in _browser", () => OpenInBrowser(view.Connection));
        }
        else if (view is TerminalView terminal)
        {
            Item("C_lear screen", () => terminal.ClearScreen());
            var here = terminal.CurrentDirectory;
            Item(here is null ? "Open _files here" : $"Open _files in {here.Replace("_", "__")}", () => _ = OpenFilesHere(terminal));
        }
        else
        {
            Item("Open _terminal", () => OpenConnection(view.Connection));
        }
        menu.Items.Add(new Separator());
        Item("_Close", () => CloseTab(tab), "Ctrl+Shift+W");
        Item("Close _other tabs", () => CloseOtherTabs(tab));
        return menu;
    }

    // Drag a tab left or right to move it, like a browser: a see-through copy follows the mouse,
    // and the other tabs make room as it passes them.
    private TabItem? _dragTab;
    private Point _tabDragStart;
    private bool _dragging;
    private bool _movingTab;
    private double _grabX;
    private TabDragAdorner? _dragGhost;

    private static TabItem? TabAt(DependencyObject? d)
    {
        while (d is not null and not TabItem)
        {
            if (d is ButtonBase) return null; // the close button
            d = d is Visual ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);
        }
        return d as TabItem;
    }

    private void Tabs_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        _dragTab = TabAt(e.OriginalSource as DependencyObject);
        _tabDragStart = e.GetPosition(Tabs);
        _dragging = false;
    }

    private void Tabs_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (_dragTab is null) return;
        if (e.LeftButton != MouseButtonState.Pressed)
        {
            EndTabDrag();
            return;
        }
        var pos = e.GetPosition(Tabs);
        if (!_dragging)
        {
            if (Math.Abs(pos.X - _tabDragStart.X) < SystemParameters.MinimumHorizontalDragDistance &&
                Math.Abs(pos.Y - _tabDragStart.Y) < SystemParameters.MinimumVerticalDragDistance) return;
            _dragging = true;
            Tabs.CaptureMouse();
            _grabX = _tabDragStart.X - _dragTab.TranslatePoint(new Point(), Tabs).X;
            if (AdornerLayer.GetAdornerLayer(Tabs) is { } layer)
            {
                _dragGhost = new TabDragAdorner(Tabs, _dragTab);
                layer.Add(_dragGhost);
                _dragTab.Opacity = 0;
            }
        }
        _dragGhost?.MoveTo(pos.X - _grabX);

        if ((TabAt(Tabs.InputHitTest(pos) as DependencyObject) ?? EndTabAt(pos)) is not { } over || ReferenceEquals(over, _dragTab)) return;
        int from = Tabs.Items.IndexOf(_dragTab), to = Tabs.Items.IndexOf(over);
        if (from < 0 || to < 0) return;

        // Only move once the mouse would still be over the dragged tab afterwards, so tabs of different widths don't flip back and forth.
        double x = e.GetPosition(over).X;
        if (to > from ? x < over.ActualWidth - _dragTab.ActualWidth : x > _dragTab.ActualWidth) return;

        // Where every tab is on screen now (mid-slide included), so the ones that move can slide over instead of jumping.
        var others = Tabs.Items.OfType<TabItem>().Where(t => !ReferenceEquals(t, _dragTab)).ToList();
        var before = others.ToDictionary(t => t, t => t.TranslatePoint(new Point(), Tabs));

        _movingTab = true;
        try
        {
            Tabs.Items.Remove(_dragTab);
            Tabs.Items.Insert(to, _dragTab);
            Tabs.SelectedItem = _dragTab;
        }
        finally { _movingTab = false; }

        foreach (var t in others) SlideFrom(t, 0, 0);
        Tabs.UpdateLayout();
        foreach (var t in others)
        {
            var now = t.TranslatePoint(new Point(), Tabs);
            SlideFrom(t, before[t].X - now.X, before[t].Y - now.Y);
        }
        _dragGhost?.InvalidateVisual();
    }

    /// <summary>Past either end of the tab row (a quick flick can skip over the tabs): the tab at that end.</summary>
    private TabItem? EndTabAt(Point pos)
    {
        if (Tabs.Items.Count == 0 || Tabs.Items[0] is not TabItem first || Tabs.Items[^1] is not TabItem last) return null;
        if (pos.X >= last.TranslatePoint(new Point(last.ActualWidth, 0), Tabs).X) return last;
        if (pos.X <= first.TranslatePoint(new Point(), Tabs).X) return first;
        return null;
    }

    /// <summary>Shows a tab offset by (dx, dy) and glides it back into its place.</summary>
    private static void SlideFrom(TabItem tab, double dx, double dy)
    {
        if (tab.RenderTransform is not TranslateTransform move || move.IsFrozen)
            tab.RenderTransform = move = new TranslateTransform();
        move.BeginAnimation(TranslateTransform.XProperty, null);
        move.BeginAnimation(TranslateTransform.YProperty, null);
        move.X = move.Y = 0;
        if (Math.Abs(dx) < 0.5 && Math.Abs(dy) < 0.5) return;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        var time = TimeSpan.FromMilliseconds(170);
        move.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(dx, 0, time) { EasingFunction = ease });
        move.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(dy, 0, time) { EasingFunction = ease });
    }

    private void Tabs_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_dragging) e.Handled = true;
        EndTabDrag();
    }

    private void Tabs_LostMouseCapture(object sender, MouseEventArgs e)
    {
        if (_dragging) EndTabDrag();
    }

    private void EndTabDrag()
    {
        bool wasDragging = _dragging;
        if (_dragGhost is not null)
        {
            AdornerLayer.GetAdornerLayer(Tabs)?.Remove(_dragGhost);
            // Let go: the tab glides from where the copy was into its place.
            if (_dragTab is not null)
            {
                SlideFrom(_dragTab, 0, 0);
                SlideFrom(_dragTab, _dragGhost.Left - _dragTab.TranslatePoint(new Point(), Tabs).X, -2);
            }
            _dragGhost = null;
        }
        if (_dragTab is not null) _dragTab.Opacity = 1;
        _dragTab = null;
        _dragging = false;
        if (Tabs.IsMouseCaptured) Tabs.ReleaseMouseCapture();
        if (wasDragging && CurrentView is { } view)
            Dispatcher.BeginInvoke(view.FocusContent, System.Windows.Threading.DispatcherPriority.Input);
    }

    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, Tabs) || _movingTab) return;
        var current = CurrentView;
        foreach (var view in SessionViews())
            ((UIElement)view).Visibility = ReferenceEquals(view, current) ? Visibility.Visible : Visibility.Collapsed;
        if (current is not null)
        {
            Title = $"{current.Connection.DisplayName}{(current.Kind.Length == 0 ? "" : " · " + current.Kind)} – SimpleSSH";
            Dispatcher.BeginInvoke(current.FocusContent, System.Windows.Threading.DispatcherPriority.Input);
        }
        else
        {
            Title = "SimpleSSH";
        }
    }

    public void CloseTab(TabItem tab)
    {
        if (tab.Tag is not ISessionView view) return;
        if (ReferenceEquals(tab, _dragTab)) EndTabDrag(); // its session ended mid-drag
        int index = Tabs.Items.IndexOf(tab);
        bool wasSelected = ReferenceEquals(Tabs.SelectedItem, tab);

        Tabs.Items.Remove(tab);
        TerminalHost.Children.Remove((UIElement)view);
        view.Dispose();

        if (wasSelected && Tabs.Items.Count > 0)
            Tabs.SelectedIndex = Math.Min(index, Tabs.Items.Count - 1);
        UpdateTabUi();
    }

    private void CloseOtherTabs(TabItem keep)
    {
        foreach (var tab in Tabs.Items.OfType<TabItem>().Where(t => !ReferenceEquals(t, keep)).ToList()) CloseTab(tab);
        Tabs.SelectedItem = keep;
    }

    private void UpdateTabUi()
    {
        EmptyState.Visibility = Tabs.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (Tabs.Items.Count == 0) Title = "SimpleSSH";
        UpdateStatus();
    }

    private void CycleTab(int delta)
    {
        int n = Tabs.Items.Count;
        if (n < 2) return;
        Tabs.SelectedIndex = ((Tabs.SelectedIndex + delta) % n + n) % n;
    }

    private void TabMenu_Opened(object sender, RoutedEventArgs e)
    {
        bool has = CurrentTab is not null;
        MenuReconnect.IsEnabled = MenuCloseTab.IsEnabled = has;
        MenuDuplicateTab.IsEnabled = has && CurrentView is not (RdpView or ConsoleView);
        MenuClearTab.IsEnabled = CurrentTerminal is not null;
        MenuFullScreen.IsEnabled = CurrentView is RdpView { State: SessionState.Connected };
        MenuCloseOthers.IsEnabled = Tabs.Items.Count > 1;
        MenuNextTab.IsEnabled = MenuPrevTab.IsEnabled = Tabs.Items.Count > 1;
    }

    private void ConnectionMenu_Opened(object sender, RoutedEventArgs e)
    {
        bool has = SelectedConnection is not null;
        MenuConnect.IsEnabled = MenuFiles.IsEnabled = MenuRun.IsEnabled = MenuEdit.IsEnabled = MenuDuplicate.IsEnabled = MenuDelete.IsEnabled = has;
        ShowProtocolItems(MenuFiles, MenuRun, MenuRdpWindow, MenuBrowser, MenuKeyLogin, MenuPasswordLogin);
    }

    private void ReconnectTab_Click(object sender, RoutedEventArgs e) => CurrentView?.Reconnect();
    private void DuplicateTab_Click(object sender, RoutedEventArgs e) { if (CurrentView is { } v) DuplicateTab(v); }

    private void DuplicateTab(ISessionView view)
    {
        if (view is RdpView or ConsoleView) return;
        if (view is FilesView) OpenFiles(view.Connection);
        else OpenConnection(view.Connection);
    }
    private void ClearTab_Click(object sender, RoutedEventArgs e) => CurrentTerminal?.ClearScreen();
    private void FullScreen_Click(object sender, RoutedEventArgs e) => (CurrentView as RdpView)?.EnterFullScreen();
    private void NextTab_Click(object sender, RoutedEventArgs e) => CycleTab(1);
    private void PrevTab_Click(object sender, RoutedEventArgs e) => CycleTab(-1);
    private void CloseTab_Click(object sender, RoutedEventArgs e) { if (CurrentTab is { } t) CloseTab(t); }
    private void CloseOtherTabs_Click(object sender, RoutedEventArgs e) { if (CurrentTab is { } t) CloseOtherTabs(t); }

    // =====================================================================================
    // Keyboard (only chords that shells don't use, so the terminal keeps Ctrl+N, Ctrl+W, ...)
    // =====================================================================================

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var mods = Keyboard.Modifiers;
        bool ctrl = mods.HasFlag(ModifierKeys.Control) && !mods.HasFlag(ModifierKeys.Alt);
        bool shift = mods.HasFlag(ModifierKeys.Shift);
        if (!ctrl) return;

        switch (key)
        {
            case Key.Tab:
                CycleTab(shift ? -1 : 1);
                break;
            case Key.PageDown:
                CycleTab(1);
                break;
            case Key.PageUp:
                CycleTab(-1);
                break;
            case Key.W when shift:
                if (CurrentTab is { } t) CloseTab(t);
                break;
            case Key.R when shift:
                CurrentView?.Reconnect();
                break;
            case Key.N when shift:
                NewConnection_Click(this, e);
                break;
            case Key.F when shift:
                FocusSearch_Click(this, e);
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    // =====================================================================================
    // Misc
    // =====================================================================================

    private void UpdateStatus()
    {
        var total = AppServices.Connections.Connections.Count;
        var tags = AppServices.Connections.AllTags().Count;
        var views = SessionViews().ToList();
        var connected = views.Count(v => v.State == SessionState.Connected);
        StatusText.Text = $"{total} connection{(total == 1 ? "" : "s")} · {tags} tag{(tags == 1 ? "" : "s")} · " +
                          $"{views.Count} tab{(views.Count == 1 ? "" : "s")} open, {connected} connected";
        if (AppServices.Connections.IsLocked) StatusText.Text += " · saved passwords locked";
        var unreadable = AppServices.Connections.UnreadableSecretCount;
        if (unreadable > 0)
            StatusText.Text += $" · {unreadable} saved password{(unreadable == 1 ? "" : "s")} could not be decrypted for this Windows user (you will be asked when connecting)";
    }

    private void SetStatus(string text) => StatusText.Text = text;

    // =====================================================================================
    // Security key
    // =====================================================================================

    private void UpdateLockUi()
    {
        var vault = AppServices.Connections.Vault;
        LockStatus.Visibility = vault is null ? Visibility.Collapsed : Visibility.Visible;
        if (vault is not null)
        {
            LockLinkText.Text = vault.IsUnlocked ? "Passwords unlocked · Lock" : "Passwords locked · Unlock";
            LockLink.Foreground = (Brush)FindResource(vault.IsUnlocked ? "MutedTextBrush" : "AccentBrush");
            LockLink.ToolTip = vault.IsUnlocked
                ? "Saved passwords stay unlocked until SimpleSSH closes" + (AppServices.Settings.LockWhenWindowsLocks ? " or Windows locks" : "") + ". Click to lock now."
                : "Saved passwords need your security key. Click to unlock now (otherwise you are asked when connecting).";
        }
        DataPathText.ToolTip = vault is null
            ? "Connections are stored in this JSON file. Passwords in it are encrypted with your Windows account (DPAPI)."
            : "Connections are stored in this JSON file. Passwords in it are encrypted with your security key and your Windows account.";
    }

    private void FileMenu_Opened(object sender, RoutedEventArgs e)
    {
        var vault = AppServices.Connections.Vault;
        MenuLockPasswords.Visibility = vault is null ? Visibility.Collapsed : Visibility.Visible;
        MenuLockPasswords.IsEnabled = vault is { IsUnlocked: true };
    }

    private void SecurityKey_Click(object sender, RoutedEventArgs e)
    {
        new SecurityKeyDialog { Owner = this }.ShowDialog();
        UpdateLockUi(); // the lock option may have changed
    }

    private void LockPasswords_Click(object sender, RoutedEventArgs e) => LockPasswords();

    private void LockPasswords()
    {
        AppServices.Connections.Lock();
        SetStatus("Saved passwords locked. Open sessions stay connected.");
    }

    private async void LockLink_Click(object sender, RoutedEventArgs e)
    {
        if (AppServices.Connections.IsLocked) await SecurityKeyUi.EnsureUnlockedAsync(this);
        else LockPasswords();
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(AppPaths.DataDirectory);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppPaths.DataDirectory}\"") { UseShellExecute = true });
    }

    private void OpenJson_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(AppPaths.ConnectionsFile)) AppServices.Connections.Save();
        Process.Start(new ProcessStartInfo("notepad.exe", $"\"{AppPaths.ConnectionsFile}\"") { UseShellExecute = true });
        SetStatus("After editing the file by hand, use File → Reload connections from disk.");
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();

    private void Shortcuts_Click(object sender, RoutedEventArgs e) =>
        MessageBox.Show(this,
            "Connection list\n" +
            "  Double-click / Enter\tOpen in a new tab\n" +
            "  F2\t\t\tEdit\n" +
            "  Del\t\t\tRemove\n" +
            "  Ctrl+Shift+N\t\tNew connection\n" +
            "  Ctrl+Shift+F\t\tFilter connections\n\n" +
            "Tabs\n" +
            "  Ctrl+Tab / Ctrl+PgDn\tNext tab\n" +
            "  Ctrl+Shift+Tab / Ctrl+PgUp\tPrevious tab\n" +
            "  Ctrl+Shift+W\t\tClose tab (or middle-click the tab)\n" +
            "  Ctrl+Shift+R\t\tReconnect\n" +
            "  Drag a tab\t\tMove it left or right\n\n" +
            "Terminal\n" +
            "  Select text\t\tthen Ctrl+C, Ctrl+Shift+C or right-click to copy\n" +
            "  Ctrl+V / Shift+Ins\t\tPaste (right-click pastes when nothing is selected)\n" +
            "  Ctrl+ + / Ctrl+ - / Ctrl+0\tFont size (or Ctrl+mouse wheel)\n" +
            "  Enter (when disconnected)\tReconnect\n\n" +
            "Files tab (right-click a connection → Open files)\n" +
            "  Enter / double-click\tOpen folder or download file\n" +
            "  Backspace\t\tParent folder\n" +
            "  F2 / Del / F5\t\tRename / delete / refresh\n" +
            "  Drag files in\t\tUpload\n\n" +
            "Remote Desktop tab\n" +
            "  Ctrl+Alt+Break\t\tFull screen on / off\n" +
            "  While the remote desktop has focus, keys go to it: click a tab header to switch tabs.",
            "Keyboard shortcuts", MessageBoxButton.OK, MessageBoxImage.Information);

    private void About_Click(object sender, RoutedEventArgs e)
    {
        var version = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        MessageBox.Show(this,
            $"SimpleSSH {version}\n\nA tabbed SSH and Remote Desktop client with a tagged connection list.\n\n" +
            $"Connections: {AppPaths.ConnectionsFile}\nKnown hosts: {AppPaths.KnownHostsFile}\n\n" +
            "Built with SSH.NET, xterm.js, Microsoft Edge WebView2 and the Windows Remote Desktop control.\n\n" +
            "Free and open source under the MIT License. Provided \"as is\", without warranty of any kind; " +
            "use at your own risk. See LICENSE.txt and THIRD-PARTY-NOTICES.txt in the program folder.",
            "About SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        var active = SessionViews().Count(v => v.IsActive);
        if (active > 0 &&
            MessageBox.Show(this, $"{active} session{(active == 1 ? " is" : "s are")} still connected. Close SimpleSSH anyway?",
                "SimpleSSH", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            e.Cancel = true;
            return;
        }

        SaveWindowPlacement();
        foreach (var view in SessionViews().ToList()) view.Dispose();
    }

    private void RestoreWindowPlacement()
    {
        var s = AppServices.Settings;
        Width = Math.Max(MinWidth, s.WindowWidth);
        Height = Math.Max(MinHeight, s.WindowHeight);
        SidebarColumn.Width = new GridLength(Math.Clamp(s.SidebarWidth, 180, 900));

        if (s.WindowLeft is { } left && s.WindowTop is { } top &&
            left < SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - 100 &&
            top < SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - 100 &&
            left + Width > SystemParameters.VirtualScreenLeft + 100 &&
            top > SystemParameters.VirtualScreenTop - 20)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = left;
            Top = top;
        }
        else
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        if (s.WindowMaximized) WindowState = WindowState.Maximized;
    }

    private void SaveWindowPlacement()
    {
        var s = AppServices.Settings;
        var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
        if (!bounds.IsEmpty)
        {
            s.WindowLeft = bounds.Left;
            s.WindowTop = bounds.Top;
            s.WindowWidth = bounds.Width;
            s.WindowHeight = bounds.Height;
        }
        s.WindowMaximized = WindowState == WindowState.Maximized;
        s.SidebarWidth = SidebarColumn.ActualWidth;
        s.CollapsedTags = _collapsedTags.ToList();
        AppServices.SaveSettings();
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = current is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(current)
                : LogicalTreeHelper.GetParent(current);
        }
        return null;
    }
}

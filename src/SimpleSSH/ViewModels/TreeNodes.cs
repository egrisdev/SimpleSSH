using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using SimpleSSH.Core.Models;

namespace SimpleSSH.ViewModels;

public abstract class TreeNode : INotifyPropertyChanged
{
    private bool _isExpanded;
    private bool _isSelected;

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool IsExpanded
    {
        get => _isExpanded;
        set { if (_isExpanded != value) { _isExpanded = value; OnPropertyChanged(); } }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected != value) { _isSelected = value; OnPropertyChanged(); } }
    }

    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>A tag ("Switches", "Servers", ...) grouping connections.</summary>
public sealed class TagNode : TreeNode
{
    public TagNode(string name, bool isUntagged)
    {
        Name = name;
        IsUntagged = isUntagged;
    }

    private bool _isDropTarget;

    public string Name { get; }
    public bool IsUntagged { get; }
    public ObservableCollection<ConnectionNode> Children { get; } = new();

    /// <summary>A connection is being dragged over this tag (highlighted).</summary>
    public bool IsDropTarget
    {
        get => _isDropTarget;
        set { if (_isDropTarget != value) { _isDropTarget = value; OnPropertyChanged(); } }
    }
    public int Count => Children.Count;

    public override string ToString() => Name; // accessible name for screen readers / UI automation

    /// <summary>Key used to remember collapsed state across sessions.</summary>
    public string StateKey => IsUntagged ? "\u0000untagged" : Name.ToLowerInvariant();
}

public sealed class ConnectionNode : TreeNode
{
    public ConnectionNode(Connection connection, TagNode parent)
    {
        Connection = connection;
        Parent = parent;
    }

    public Connection Connection { get; }
    public TagNode Parent { get; }

    public string Name => Connection.DisplayName;

    public bool IsRdp => Connection.IsRdp;

    public bool IsConsole => Connection.IsConsole;

    public bool IsWeb => Connection.IsWeb;

    public override string ToString() => Name;

    public string Detail =>
        string.IsNullOrWhiteSpace(Connection.Username) ? Connection.Endpoint : $"{Connection.Username}@{Connection.Endpoint}";

    public string ToolTip
    {
        get
        {
            var lines = new List<string> { $"{Connection.DisplayName}", Detail };
            if (Connection.IsRdp) lines.Add("Remote Desktop");
            if (Connection.IsConsole) lines.Add("Server console (iLO / iDRAC)");
            if (Connection.IsWeb) lines.Add("Web app");
            if (Connection.Tags.Count > 0) lines.Add("Tags: " + Connection.FormatTags(Connection.Tags));
            if (!string.IsNullOrWhiteSpace(Connection.Notes)) lines.Add(Connection.Notes.Trim());
            return string.Join(Environment.NewLine, lines);
        }
    }
}

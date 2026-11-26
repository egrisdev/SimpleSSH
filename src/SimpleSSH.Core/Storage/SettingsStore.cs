namespace SimpleSSH.Core.Storage;

/// <summary>UI preferences (window placement, sidebar width, font size, collapsed tags).</summary>
public sealed class AppSettings
{
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public double WindowWidth { get; set; } = 1280;
    public double WindowHeight { get; set; } = 800;
    public bool WindowMaximized { get; set; }
    public double SidebarWidth { get; set; } = 280;
    public int TerminalFontSize { get; set; } = 14;
    public string TerminalFontFamily { get; set; } = "'Cascadia Mono', 'Cascadia Code', Consolas, 'Courier New', monospace";
    public List<string> CollapsedTags { get; set; } = new();
    /// <summary>Close a tab automatically when its session ends normally (exit/logout). Errors keep the tab open.</summary>
    public bool CloseTabOnExit { get; set; } = true;
    /// <summary>With a security key: also lock the saved passwords when Windows locks (they always lock when the app closes).</summary>
    public bool LockWhenWindowsLocks { get; set; }
    /// <summary>Ask before a connection dragged onto another tag is moved there.</summary>
    public bool ConfirmTagMoves { get; set; } = true;
}

public static class SettingsStore
{
    public static AppSettings Load(string path)
    {
        try
        {
            return JsonFile.Read<AppSettings>(path) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(string path, AppSettings settings)
    {
        try
        {
            JsonFile.Write(path, settings);
        }
        catch
        {
            // Preferences are not worth crashing over.
        }
    }
}

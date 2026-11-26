namespace SimpleSSH.Core;

/// <summary>
/// Locations of per-user data. Everything lives under %APPDATA%\SimpleSSH unless the
/// SIMPLESSH_DATA_DIR environment variable points somewhere else (handy for testing / portable use).
/// </summary>
public static class AppPaths
{
    public const string DataDirEnvironmentVariable = "SIMPLESSH_DATA_DIR";

    public static string DataDirectory
    {
        get
        {
            var overridden = Environment.GetEnvironmentVariable(DataDirEnvironmentVariable);
            return !string.IsNullOrWhiteSpace(overridden)
                ? Path.GetFullPath(overridden)
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SimpleSSH");
        }
    }

    /// <summary>Machine-local cache (WebView2 profile, logs). Never roams.</summary>
    public static string LocalDirectory
    {
        get
        {
            var overridden = Environment.GetEnvironmentVariable(DataDirEnvironmentVariable);
            return !string.IsNullOrWhiteSpace(overridden)
                ? Path.Combine(Path.GetFullPath(overridden), "local")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SimpleSSH");
        }
    }

    public static string ConnectionsFile => Path.Combine(DataDirectory, "connections.json");
    public static string KnownHostsFile => Path.Combine(DataDirectory, "known_hosts.json");
    public static string SettingsFile => Path.Combine(DataDirectory, "settings.json");
    public static string WebViewDataDirectory => Path.Combine(LocalDirectory, "WebView2");
    public static string LogFile => Path.Combine(LocalDirectory, "logs", "simplessh.log");
}

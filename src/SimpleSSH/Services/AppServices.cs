using Microsoft.Web.WebView2.Core;
using SimpleSSH.Core;
using SimpleSSH.Core.Bmc;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Services;

/// <summary>Application-wide singletons.</summary>
internal static class AppServices
{
    private static Task<CoreWebView2Environment>? _webViewEnvironment;

    public static ConnectionStore Connections { get; private set; } = null!;
    public static KnownHostsStore KnownHosts { get; private set; } = null!;
    public static AppSettings Settings { get; private set; } = new();

    /// <summary>DPAPI layer around security-key slots (separate entropy from the per-password one).</summary>
    public static ISecretProtector KeySlotProtector { get; } = new DpapiSecretProtector("SimpleSSH/security-key/v1");

    /// <summary>Swap this for a vault/API-backed provider when secure storage arrives.</summary>
    public static ICredentialProvider Credentials { get; private set; } = new StoredCredentialProvider();

    public static void Initialize(ConnectionStore store)
    {
        Connections = store;
        KnownHosts = new KnownHostsStore(AppPaths.KnownHostsFile);
        Settings = SettingsStore.Load(AppPaths.SettingsFile);
    }

    private static readonly Lazy<ConsoleFileCache> KeptConsoleFiles = new(() =>
    {
        var cache = new ConsoleFileCache(Path.Combine(AppPaths.LocalDirectory, "console-cache"));
        cache.TrimOld();
        return cache;
    });

    /// <summary>Server console pages' static files, kept between consoles and runs (old ones are removed at first use).</summary>
    public static ConsoleFileCache ConsoleFiles => KeptConsoleFiles.Value;

    public static void SaveSettings() => SettingsStore.Save(AppPaths.SettingsFile, Settings);

    /// <summary>
    /// One shared WebView2 environment for all terminal tabs. The user-data folder must be writable,
    /// so it lives in %LOCALAPPDATA% rather than next to the exe (Program Files is read-only).
    /// </summary>
    public static Task<CoreWebView2Environment> GetWebViewEnvironmentAsync() =>
        _webViewEnvironment ??= CreateWebViewEnvironmentAsync();

    private static Task<CoreWebView2Environment> CreateWebViewEnvironmentAsync() =>
        CoreWebView2Environment.CreateAsync(browserExecutableFolder: null, userDataFolder: AppPaths.WebViewDataDirectory);

    private static bool _historyCleared;

    /// <summary>
    /// Clears the shared profile's browsing history once per run. Terminal pages need none, and earlier builds
    /// opened server consoles in this profile, so its history may still hold console addresses with session keys.
    /// </summary>
    public static async Task ClearSharedHistoryOnceAsync(CoreWebView2 core)
    {
        if (_historyCleared) return;
        _historyCleared = true;
        try
        {
            await core.Profile.ClearBrowsingDataAsync(CoreWebView2BrowsingDataKinds.BrowsingHistory);
        }
        catch (Exception ex)
        {
            Log.Info($"Could not clear the browser history: {ex.Message}");
        }
    }
}

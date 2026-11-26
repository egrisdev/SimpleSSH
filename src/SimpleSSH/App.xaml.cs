using System.Windows;
using System.Windows.Threading;
using SimpleSSH.Core;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Storage;
using SimpleSSH.Services;

namespace SimpleSSH;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Escape hatch for remote desktop / broken GPU drivers (also makes PrintWindow screenshots work).
        if (Environment.GetEnvironmentVariable("SIMPLESSH_SOFTWARE_RENDER") == "1")
            System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => Log.Error("Unhandled exception", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Log.Error("Unobserved task exception", args.Exception);
            args.SetObserved();
        };

        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Cannot create the data folder:\n{AppPaths.DataDirectory}\n\n{ex.Message}", "SimpleSSH",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(AppPaths.DataDirEnvironmentVariable)))
        {
            // A folder chosen with SIMPLESSH_DATA_DIR gets %APPDATA%'s privacy: only this user (and the system) can change it.
            try
            {
                if (PrivateFolder.Secure(AppPaths.DataDirectory)) Log.Info($"Data folder limited to this Windows user: {AppPaths.DataDirectory}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PlatformNotSupportedException)
            {
                // FAT/exFAT drives and some network shares have no permissions to set.
                Log.Info($"Could not limit the data folder to this Windows user ({ex.Message}): {AppPaths.DataDirectory}");
            }
        }

        var store = new ConnectionStore(AppPaths.ConnectionsFile, new DpapiSecretProtector(), AppServices.KeySlotProtector);
        try
        {
            store.Load();
        }
        catch (ConnectionStoreException ex)
        {
            var answer = MessageBox.Show(
                $"{ex.Message}\n\nMove the broken file aside and start with an empty connection list?\n" +
                "(Choose No to exit and fix the file by hand.)",
                "SimpleSSH – cannot read connections", MessageBoxButton.YesNo, MessageBoxImage.Error);
            if (answer != MessageBoxResult.Yes)
            {
                Shutdown(1);
                return;
            }
            var backup = store.QuarantineCorruptFile();
            MessageBox.Show($"The old file was saved as:\n{backup}", "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        AppServices.Initialize(store);

        var window = new MainWindow();
        MainWindow = window;
        window.Show();

        // Passwords protected with a security key: ask for the key right away (one touch), not at the first connect.
        SecurityKeyUi.StartWatchingWindowsLock();
        if (store.IsLocked)
            window.ContentRendered += async (_, _) => await SecurityKeyUi.EnsureUnlockedAsync(window);

        // SimpleSSH.exe --connect "core-sw-01"   terminal tab   (name, host or id; repeatable)
        //               --files   "core-sw-01"   files tab
        //               --run     "Switches"     Run command window for a connection or every connection in a tag
        for (int i = 0; i + 1 < e.Args.Length; i++)
        {
            var arg = e.Args[i].TrimStart('-', '/').ToLowerInvariant();
            if (arg is not ("connect" or "c" or "files" or "run")) continue;
            var target = e.Args[++i];
            if (arg == "run")
            {
                var inTag = store.Connections.Where(c => c.Tags.Contains(target, StringComparer.OrdinalIgnoreCase)).ToList();
                if (inTag.Count > 0)
                {
                    window.ShowRunCommand(inTag, target);
                    continue;
                }
            }
            var match = store.Connections.FirstOrDefault(c => string.Equals(c.Id.ToString(), target, StringComparison.OrdinalIgnoreCase))
                        ?? store.Connections.FirstOrDefault(c => string.Equals(c.Name, target, StringComparison.OrdinalIgnoreCase))
                        ?? store.Connections.FirstOrDefault(c => string.Equals(c.Host, target, StringComparison.OrdinalIgnoreCase));
            if (match is null)
                MessageBox.Show(window, $"No saved connection{(arg == "run" ? " or tag" : "")} named \"{target}\".", "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Warning);
            else if (arg == "files") window.OpenFiles(match);
            else if (arg == "run") window.ShowRunCommand(new[] { match }, match.DisplayName);
            else window.OpenConnection(match);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SecurityKeyUi.StopWatchingWindowsLock();
        AppServices.Connections?.Vault?.Lock(); // wipe the data key now rather than whenever memory is reused
        AppServices.SaveSettings();
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error("Unhandled UI exception", e.Exception);
        MessageBox.Show($"An unexpected error occurred:\n\n{e.Exception.Message}\n\nDetails were written to:\n{AppPaths.LogFile}",
            "SimpleSSH", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}

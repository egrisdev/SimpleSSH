using System.Windows;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Views;

namespace SimpleSSH.Services;

/// <summary>Shows server login prompts (verification codes, extra factors) to the user. Safe to call from any thread.</summary>
internal static class AuthPromptUi
{
    public static AuthPromptHandler CreateHandler(Connection connection) => request =>
        UiPrompts.Run(() =>
        {
            var dlg = new AuthPromptDialog(connection, request) { Owner = UiPrompts.Owner };
            return dlg.ShowDialog() == true ? dlg.Answers : null;
        }, (IReadOnlyList<string>?)null);
}

/// <summary>Runs modal prompts raised from background threads one at a time on the UI thread.</summary>
internal static class UiPrompts
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static Window? Owner =>
        Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive) ?? Application.Current?.MainWindow;

    public static T Run<T>(Func<T> prompt, T fallback)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return fallback;
        if (dispatcher.CheckAccess()) return prompt();

        // Several background connections (e.g. "Run command" on a whole tag) may ask at once: queue them.
        Gate.Wait();
        try
        {
            return dispatcher.Invoke(prompt);
        }
        finally
        {
            Gate.Release();
        }
    }
}

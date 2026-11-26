using System.Windows;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Services;

/// <summary>Per-tab memory of host key prompts.</summary>
internal sealed class HostKeyPromptState
{
    /// <summary>Keys the user chose to "connect this time only" (remembered for the tab's lifetime).</summary>
    public HashSet<string> AcceptedOnce { get; } = new(StringComparer.Ordinal);

    /// <summary>Set when the user was asked during the current connection attempt.</summary>
    public HostKeyDecision? LastPromptDecision { get; set; }
}

/// <summary>Asks the user about unknown / changed host keys. Safe to call from any thread.</summary>
internal static class HostKeyPrompt
{
    public static IHostKeyVerifier CreateVerifier(HostKeyPromptState state) =>
        new KnownHostsVerifier(AppServices.KnownHosts, (key, check) =>
        {
            var id = $"{key.Host}|{key.Port}|{KnownHostsStore.NormalizeKeyType(key.KeyType)}|{key.FingerprintSha256}";
            if (state.AcceptedOnce.Contains(id)) return HostKeyDecision.AcceptOnce;

            var decision = Ask(key, check);
            state.LastPromptDecision = decision;
            if (decision == HostKeyDecision.AcceptOnce) state.AcceptedOnce.Add(id);
            return decision;
        });

    private static HostKeyDecision Ask(HostKeyInfo key, HostKeyCheck check) =>
        UiPrompts.Run(() => AskOnUiThread(key, check), HostKeyDecision.Reject);

    private static HostKeyDecision AskOnUiThread(HostKeyInfo key, HostKeyCheck check)
    {
        var owner = UiPrompts.Owner;
        var endpoint = key.Port == 22 ? key.Host : $"{key.Host}:{key.Port}";

        if (check.Status == HostKeyStatus.Changed)
        {
            var text =
                $"WARNING: THE HOST KEY FOR {endpoint} HAS CHANGED!\n\n" +
                "Someone could be eavesdropping on you (man-in-the-middle attack), or the device was " +
                "reinstalled / had its keys regenerated.\n\n" +
                $"Key type:  {key.KeyType}\n" +
                $"Saved:     SHA256:{check.KnownFingerprint}\n" +
                $"Presented: SHA256:{key.FingerprintSha256}\n\n" +
                "Yes = trust the NEW key and replace the saved one\n" +
                "No = abort the connection";
            var r = Show(owner, text, "SimpleSSH – host key changed", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            return r == MessageBoxResult.Yes ? HostKeyDecision.AcceptAndSave : HostKeyDecision.Reject;
        }

        if (check.Status == HostKeyStatus.OtherTypeKnown)
        {
            var text =
                $"WARNING: {endpoint} PRESENTED A DIFFERENT KIND OF HOST KEY!\n\n" +
                "SimpleSSH already trusts another key for this server, but the server didn't offer it. " +
                "Someone could be eavesdropping on you (man-in-the-middle attack), or the server's SSH keys were changed.\n\n" +
                $"Saved:     {check.KnownKeyType} SHA256:{check.KnownFingerprint}\n" +
                $"Presented: {key.KeyType} SHA256:{key.FingerprintSha256}\n\n" +
                "Yes = trust the new key as well and connect\n" +
                "No = abort the connection";
            var r = Show(owner, text, "SimpleSSH – unexpected host key", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            return r == MessageBoxResult.Yes ? HostKeyDecision.AcceptAndSave : HostKeyDecision.Reject;
        }

        var msg =
            $"The authenticity of host '{endpoint}' can't be established.\n\n" +
            $"Key type:    {key.KeyType} ({key.KeyLength} bits)\n" +
            $"Fingerprint: SHA256:{key.FingerprintSha256}\n\n" +
            "Do you trust this host?\n\n" +
            "Yes = trust and remember this key\n" +
            "No = connect this time only\n" +
            "Cancel = abort";
        var result = Show(owner, msg, "SimpleSSH – new host", MessageBoxButton.YesNoCancel, MessageBoxImage.Question, MessageBoxResult.Yes);
        return result switch
        {
            MessageBoxResult.Yes => HostKeyDecision.AcceptAndSave,
            MessageBoxResult.No => HostKeyDecision.AcceptOnce,
            _ => HostKeyDecision.Reject,
        };
    }

    private static MessageBoxResult Show(Window? owner, string text, string caption, MessageBoxButton buttons, MessageBoxImage icon, MessageBoxResult def) =>
        owner is { IsLoaded: true }
            ? MessageBox.Show(owner, text, caption, buttons, icon, def)
            : MessageBox.Show(text, caption, buttons, icon, def);
}

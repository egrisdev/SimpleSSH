using System.Text.RegularExpressions;

namespace SimpleSSH.Core.Ssh;

/// <summary>Where a remote shell is: its user (when known) and its folder, possibly starting with "~".</summary>
public sealed record ShellLocation(string? User, string Path, string? Host = null);

/// <summary>
/// Works out a terminal's current folder from what the shell already sends: the window title most Linux prompts set
/// (Ubuntu/Debian "user@host: ~/dir", Fedora/RHEL "user@host:~/dir") or an OSC 7 "file://host/path" report.
/// Nothing is typed into the shell.
/// </summary>
public static class ShellDirectory
{
    private static readonly Regex TitlePattern = new(
        @"^(?<user>[A-Za-z0-9._][A-Za-z0-9._-]*)@(?<host>[^\s:@]+): ?(?<path>(~|~/|/).*)$",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    /// <summary>Parses a terminal title such as "alex@syslog: /var/log" or "alex@syslog:~/notes".</summary>
    public static bool TryParseTitle(string? title, out ShellLocation location)
    {
        location = null!;
        var text = title?.Trim() ?? "";
        if (text.Length is 0 or > 4096) return false;
        Match m;
        try
        {
            m = TitlePattern.Match(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        if (!m.Success) return false;
        var path = m.Groups["path"].Value;
        if (path.StartsWith('~') && path.Length > 1 && path[1] != '/') return false; // "~bob" and the like
        location = new ShellLocation(m.Groups["user"].Value, path, m.Groups["host"].Value);
        return true;
    }

    /// <summary>Parses an OSC 7 report: "file://host/some%20dir" (percent-encoded, host may be empty).</summary>
    public static bool TryParseOsc7(string? data, out ShellLocation location)
    {
        location = null!;
        const string scheme = "file://";
        if (data is null || !data.StartsWith(scheme, StringComparison.OrdinalIgnoreCase)) return false;
        var slash = data.IndexOf('/', scheme.Length);
        if (slash < 0) return false;
        string path;
        try
        {
            path = Uri.UnescapeDataString(data[slash..]);
        }
        catch (UriFormatException)
        {
            return false;
        }
        if (path.Length == 0 || path.Contains('\0')) return false;
        location = new ShellLocation(null, path);
        return true;
    }

    /// <summary>
    /// For prompts that report nothing: run over the terminal's own SSH connection, this finds the newest process
    /// of this user on a terminal (/dev/pts) whose SSH_CONNECTION matches the exec channel's (so it's this tab's
    /// shell, or the program running in it, not another login) and prints its folder. Linux /proc only; prints
    /// nothing elsewhere. One line, no single quotes or "!", so any login shell (bash, zsh, fish, csh) passes it to sh.
    /// </summary>
    public const string ProbeCommand =
        "sh -c '" +
        "c=$SSH_CONNECTION; [ -n \"$c\" ] || exit 3; b=; bt=-1; " +
        "for d in /proc/[0-9]*; do " +
        "[ -O \"$d\" ] || continue; " +
        "case $(readlink \"$d/fd/0\" 2>/dev/null) in /dev/pts/*) ;; *) continue ;; esac; " +
        "tr \"\\000\" \"\\n\" < \"$d/environ\" 2>/dev/null | grep -qxF \"SSH_CONNECTION=$c\" || continue; " +
        "t=$(sed \"s/.*) //\" \"$d/stat\" 2>/dev/null | cut -d\" \" -f20); " +
        "[ -n \"$t\" ] && [ \"$t\" -gt \"$bt\" ] && { bt=$t; b=$d; }; " +
        "done; " +
        "[ -n \"$b\" ] && readlink \"$b/cwd\"'";

    /// <summary>Reads the output of <see cref="ProbeCommand"/>: one absolute path.</summary>
    public static bool TryParseProbe(string? output, out string path)
    {
        path = "";
        var text = (output ?? "").TrimEnd('\r', '\n');
        const string deleted = " (deleted)";
        if (text.EndsWith(deleted, StringComparison.Ordinal)) return false; // the folder was removed under the shell
        if (text.Length is 0 or > 4096 || text[0] != '/' || text.Any(char.IsControl)) return false;
        path = text;
        return true;
    }

    /// <summary>
    /// The folder as the file browser should open it. "~" belongs to the shell's user, which may not be the account
    /// the file browser logs in as (after <c>sudo -i</c>, for example), so it is spelled out for other users.
    /// </summary>
    public static string ForLogin(ShellLocation location, string? loginUser)
    {
        var path = location.Path;
        if (!path.StartsWith('~') || location.User is not { Length: > 0 } user ||
            string.IsNullOrEmpty(loginUser) || string.Equals(user, loginUser, StringComparison.Ordinal))
            return path;
        var home = user == "root" ? "/root" : "/home/" + user;
        return path.Length == 1 ? home : home + path[1..];
    }
}

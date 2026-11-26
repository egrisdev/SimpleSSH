using System.Text;
using Renci.SshNet;
using SimpleSSH.Core.Credentials;

namespace SimpleSSH.Core.Ssh;

public enum LockDownStatus
{
    /// <summary>Password logins are off, the key still works, and a password login was refused.</summary>
    Locked,
    /// <summary>The setting was applied and the key works, but the server still accepted a password (another rule overrides it).</summary>
    PasswordStillAccepted,
    WrongSudoPassword,
    NotAllowed,
    /// <summary>This SSH server has no drop-in config folder (sshd_config.d); nothing was changed.</summary>
    Unsupported,
    /// <summary>sshd rejected the new setting; it was removed again and nothing changed.</summary>
    ConfigRejected,
    /// <summary>The key stopped working after the change, so it was undone.</summary>
    RolledBack,
    /// <summary>Password logins were turned back on.</summary>
    Undone,
    Failed,
}

public sealed record LockDownResult(LockDownStatus Status, string Output)
{
    public bool Applied => Status is LockDownStatus.Locked or LockDownStatus.PasswordStillAccepted;
}

/// <summary>
/// Moves a Linux/Unix SSH login from password to key, safely: the public key is installed with the working password
/// login, a key-only login proves it, and only then can password logins be switched off. Switching off runs over a
/// key login that stays open, re-checks the key with a fresh login and undoes the change if that fails, so the
/// server can't be left without a way in over SSH.
/// </summary>
public static class KeyLoginSetup
{
    /// <summary>Drop-in file that turns SSH password logins off. Removing it (and restarting ssh) turns them back on.</summary>
    public const string DropInPath = "/etc/ssh/sshd_config.d/00-simplessh-keys-only.conf";

    public const string UndoHint = "sudo rm " + DropInPath + " && sudo systemctl restart ssh";

    private const string InstalledMarker = "SIMPLESSH-KEY-INSTALLED";
    private const string KeyLoginMarker = "SIMPLESSH-KEY-LOGIN";
    private const string LockedMarker = "SIMPLESSH-LOCKED";
    private const string UnlockedMarker = "SIMPLESSH-UNLOCKED";
    private const string NoDropInMarker = "SIMPLESSH-NO-DROPIN";
    private const string InvalidMarker = "SIMPLESSH-CONFIG-INVALID";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    // ---- Remote scripts -----------------------------------------------------------------------

    /// <summary>
    /// Runs <paramref name="script"/> with /bin/sh whatever the login shell is (bash, zsh, fish…): the script travels
    /// base64-encoded, so no quoting can break, and stdin stays free for sudo.
    /// </summary>
    public static string ShellCommand(string script)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(script.Replace("\r\n", "\n")));
        return "sh -c 'f=$(mktemp) || exit 99; echo " + b64 + " | base64 -d > \"$f\"; sh \"$f\"; r=$?; rm -f \"$f\"; exit $r'";
    }

    /// <summary>Adds the key to ~/.ssh/authorized_keys once, with the permissions sshd insists on.</summary>
    public static string InstallKeyScript(string publicKey)
    {
        var key = OneLine(publicKey);
        if (key.Contains('\'')) throw new ArgumentException("The public key must not contain quotes.", nameof(publicKey));
        return $$"""
            set -e
            umask 077
            k='{{key}}'
            mkdir -p "$HOME/.ssh"
            chmod 700 "$HOME/.ssh"
            f="$HOME/.ssh/authorized_keys"
            touch "$f"
            chmod 600 "$f"
            if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi
            grep -qxF "$k" "$f" || printf '%s\n' "$k" >> "$f"
            if command -v restorecon >/dev/null 2>&1; then restorecon -R "$HOME/.ssh" >/dev/null 2>&1 || true; fi
            echo {{InstalledMarker}}
            """.ReplaceLineEndings("\n"); // scripts run on Linux: LF even in a CRLF checkout
    }

    /// <summary>Printed by <see cref="ManualInstallCommand"/> once the key is in place.</summary>
    public const string ManualInstalledMessage = "Key added. Now test it in SimpleSSH.";

    /// <summary>
    /// A readable one-line command a person pastes into a session that already gets in (another SSH program, the
    /// console), for servers that refuse passwords. Does what <see cref="InstallKeyScript"/> does: adds the key once,
    /// fixes a missing final newline, and sets the permissions sshd insists on. POSIX sh, bash, zsh and dash.
    /// </summary>
    public static string ManualInstallCommand(string publicKey)
    {
        var key = OneLine(publicKey);
        if (key.Contains('\'')) throw new ArgumentException("The public key must not contain quotes.", nameof(publicKey));
        return $"k='{key}'; f=\"$HOME/.ssh/authorized_keys\"; " +
               "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\" && touch \"$f\" && chmod 600 \"$f\" && " +
               "{ grep -qxF \"$k\" \"$f\" || { [ -z \"$(tail -c 1 \"$f\")\" ] || echo >> \"$f\"; echo \"$k\" >> \"$f\"; }; } && " +
               $"echo '{ManualInstalledMessage}'";
    }

    /// <summary>
    /// The root part of the lock-down: write the drop-in, check it with sshd -t, restart ssh. It only turns password
    /// logins off: sshd keeps the first value it reads and this file is read first, so any other setting here
    /// (PermitRootLogin, AuthenticationMethods…) would silently override the admin's own, possibly stricter, one.
    /// </summary>
    public static string LockDownRootScript() => $$"""
        set -e
        d=/etc/ssh/sshd_config.d
        f={{DropInPath}}
        if [ ! -d "$d" ] || ! grep -qsE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' /etc/ssh/sshd_config; then echo {{NoDropInMarker}}; exit 20; fi
        cat > "$f.new" <<'EOF'
        # Added by SimpleSSH: SSH accepts keys only. Console and local logins still use passwords.
        # To undo: {{UndoHint}}
        PubkeyAuthentication yes
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        EOF
        chmod 644 "$f.new"
        mv "$f.new" "$f"
        mkdir -p /run/sshd
        s=$(command -v sshd || echo /usr/sbin/sshd)
        if ! "$s" -t 2>/dev/null; then
          # OpenSSH before 8.7 (Ubuntu 20.04) calls the keyboard-interactive switch ChallengeResponseAuthentication.
          sed -i 's/^KbdInteractiveAuthentication /ChallengeResponseAuthentication /' "$f"
          if ! "$s" -t; then rm -f "$f"; echo {{InvalidMarker}}; exit 22; fi
        fi
        {{RestartSsh}}
        echo {{LockedMarker}}
        """.ReplaceLineEndings("\n");

    public static string UndoRootScript() => $$"""
        rm -f {{DropInPath}}
        {{RestartSsh}}
        echo {{UnlockedMarker}}
        """.ReplaceLineEndings("\n");

    private const string RestartSsh =
        "if command -v systemctl >/dev/null 2>&1; then systemctl restart ssh 2>/dev/null || systemctl restart sshd; " +
        "else service ssh restart 2>/dev/null || service sshd restart; fi";

    /// <summary>Runs a root script with sudo (password read from stdin), or directly when already root.</summary>
    public static string AsRootScript(string rootScript)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(rootScript.Replace("\r\n", "\n")));
        return $$"""
            s=$(echo {{b64}} | base64 -d)
            if [ "$(id -u)" = 0 ]; then sh -c "$s"; else sudo -S -p '' sh -c "$s"; fi
            """.ReplaceLineEndings("\n");
    }

    public static LockDownStatus Classify(CommandResult result)
    {
        var all = result.CombinedOutput;
        if (all.Contains(LockedMarker, StringComparison.Ordinal)) return LockDownStatus.Locked;
        if (all.Contains(NoDropInMarker, StringComparison.Ordinal)) return LockDownStatus.Unsupported;
        if (all.Contains(InvalidMarker, StringComparison.Ordinal)) return LockDownStatus.ConfigRejected;
        if (all.Contains("incorrect password", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("Sorry, try again", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("no password was provided", StringComparison.OrdinalIgnoreCase))
            return LockDownStatus.WrongSudoPassword;
        if (all.Contains("not in the sudoers", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("not allowed to run sudo", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("sudo: not found", StringComparison.OrdinalIgnoreCase) ||
            all.Contains("sudo: command not found", StringComparison.OrdinalIgnoreCase))
            return LockDownStatus.NotAllowed;
        return LockDownStatus.Failed;
    }

    // ---- Steps ---------------------------------------------------------------------------------

    /// <summary>Step 1: installs <paramref name="publicKey"/> over a login that works today (normally the password).</summary>
    public static async Task InstallKeyAsync(SshConnectOptions currentLogin, IHostKeyVerifier verifier, string publicKey,
        CancellationToken cancellationToken = default)
    {
        using var connection = await ConnectAsync(currentLogin, verifier, cancellationToken).ConfigureAwait(false);
        var result = await RunAsync(connection.Client, ShellCommand(InstallKeyScript(publicKey)), null, cancellationToken).ConfigureAwait(false);
        if (!result.CombinedOutput.Contains(InstalledMarker, StringComparison.Ordinal))
            throw new SshSessionException("Could not add the key on the server. This works on Linux and other Unix servers, not on " +
                                          "network devices." + Detail(result));
    }

    /// <summary>Step 2: logs in with the key and nothing else (no password, no prompts).</summary>
    public static async Task VerifyKeyLoginAsync(SshConnectOptions keyOnly, IHostKeyVerifier verifier, CancellationToken cancellationToken = default)
    {
        RequireKeyOnly(keyOnly);
        try
        {
            using var connection = await ConnectAsync(keyOnly, verifier, cancellationToken).ConfigureAwait(false);
            var result = await RunAsync(connection.Client, "echo " + KeyLoginMarker, null, cancellationToken).ConfigureAwait(false);
            if (!result.Output.Contains(KeyLoginMarker, StringComparison.Ordinal))
                throw new SshSessionException("Logged in with the key, but the server didn't run a test command." + Detail(result));
        }
        catch (SshSessionException ex) when (SshConnector.IsAuthenticationFailure(ex))
        {
            throw new SshSessionException("The key was added, but the server didn't accept it for login. It may require other " +
                                          "settings (for example a different authorized_keys location).", ex);
        }
    }

    /// <summary>
    /// Step 3: turns off SSH password logins. Runs over a key login that stays open, then proves a fresh key login still
    /// works (undoing the change if not) and that a password login is now refused.
    /// </summary>
    public static async Task<LockDownResult> LockDownAsync(SshConnectOptions keyOnly, SshConnectOptions passwordOnly, string? sudoPassword,
        IHostKeyVerifier verifier, CancellationToken cancellationToken = default)
    {
        RequireKeyOnly(keyOnly);
        using var anchor = await ConnectAsync(keyOnly, verifier, cancellationToken).ConfigureAwait(false);
        var input = string.IsNullOrEmpty(sudoPassword) ? null : sudoPassword + "\n";

        var result = await RunAsync(anchor.Client, ShellCommand(AsRootScript(LockDownRootScript())), input, cancellationToken).ConfigureAwait(false);
        var status = Classify(result);
        if (status != LockDownStatus.Locked) return new LockDownResult(status, result.CombinedOutput.Trim());

        // The open session survives the restart. Make sure a new key login still gets in.
        try
        {
            await VerifyKeyLoginAsync(keyOnly, verifier, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var undo = await RunAsync(anchor.Client, ShellCommand(AsRootScript(UndoRootScript())), input, CancellationToken.None).ConfigureAwait(false);
            return new LockDownResult(LockDownStatus.RolledBack,
                $"{SshConnector.DescribeError(ex)}\n{(undo.CombinedOutput.Contains(UnlockedMarker) ? "The change was undone." : "Undo output:\n" + undo.CombinedOutput)}");
        }

        // And that a password is refused.
        try
        {
            using var _ = await ConnectAsync(passwordOnly, verifier, cancellationToken).ConfigureAwait(false);
            return new LockDownResult(LockDownStatus.PasswordStillAccepted,
                "The server still accepts the password. Another setting in /etc/ssh/sshd_config (a Match block, or an Include placed later) overrides SimpleSSH's file.");
        }
        catch (SshSessionException ex) when (SshConnector.IsAuthenticationFailure(ex))
        {
            return new LockDownResult(LockDownStatus.Locked, "");
        }
    }

    /// <summary>Turns SSH password logins back on (removes SimpleSSH's drop-in). Needs a working login.</summary>
    public static async Task<LockDownResult> UndoAsync(SshConnectOptions login, string? sudoPassword, IHostKeyVerifier verifier,
        CancellationToken cancellationToken = default)
    {
        using var connection = await ConnectAsync(login, verifier, cancellationToken).ConfigureAwait(false);
        var input = string.IsNullOrEmpty(sudoPassword) ? null : sudoPassword + "\n";
        var result = await RunAsync(connection.Client, ShellCommand(AsRootScript(UndoRootScript())), input, cancellationToken).ConfigureAwait(false);
        if (result.CombinedOutput.Contains(UnlockedMarker, StringComparison.Ordinal)) return new LockDownResult(LockDownStatus.Undone, "");
        var status = Classify(result);
        return new LockDownResult(status == LockDownStatus.Locked ? LockDownStatus.Failed : status, result.CombinedOutput.Trim());
    }

    // ---- Back to password login ----------------------------------------------------------------

    private const string NotLockedMarker = "SIMPLESSH-NOT-LOCKED";
    private const string RemovedMarker = "SIMPLESSH-KEY-REMOVED";
    private const string PasswordLoginMarker = "SIMPLESSH-PASSWORD-LOGIN";

    /// <summary>Removes SimpleSSH's lock-down file if it is there; needs sudo only then.</summary>
    public static string EnablePasswordsScript() => $$"""
        if [ ! -e {{DropInPath}} ]; then echo {{NotLockedMarker}}; exit 0; fi
        {{AsRootScript(UndoRootScript())}}
        """.ReplaceLineEndings("\n");

    /// <summary>Removes every authorized_keys line holding this key (whatever its comment or options), keeping the file's permissions.</summary>
    public static string RemoveKeyScript(string publicKey)
    {
        var parts = OneLine(publicKey).Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || parts[1].Length < 32 || parts[1].Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=')))
            throw new ArgumentException("Not an SSH public key.", nameof(publicKey));
        return $$"""
            set -e
            b='{{parts[1]}}'
            f="$HOME/.ssh/authorized_keys"
            if [ -f "$f" ] && grep -qF "$b" "$f"; then
              t=$(mktemp "$f.XXXXXX")
              grep -vF "$b" "$f" > "$t" || true
              chmod 600 "$t"
              mv "$t" "$f"
            fi
            echo {{RemovedMarker}}
            """.ReplaceLineEndings("\n");
    }

    /// <summary>Turns SSH password logins back on if SimpleSSH turned them off. Logs in with the key.</summary>
    /// <returns>
    /// <c>null</c> when SimpleSSH's lock-down file isn't there (nothing to do, no sudo used); <see cref="LockDownStatus.Undone"/>
    /// when it was removed; otherwise the problem (wrong sudo password, no sudo rights, …).
    /// </returns>
    public static async Task<LockDownResult?> EnablePasswordsAsync(SshConnectOptions keyOnly, string? sudoPassword, IHostKeyVerifier verifier,
        CancellationToken cancellationToken = default)
    {
        RequireKeyOnly(keyOnly);
        using var connection = await ConnectAsync(keyOnly, verifier, cancellationToken).ConfigureAwait(false);
        var input = string.IsNullOrEmpty(sudoPassword) ? null : sudoPassword + "\n";
        var result = await RunAsync(connection.Client, ShellCommand(EnablePasswordsScript()), input, cancellationToken).ConfigureAwait(false);
        var output = result.CombinedOutput;
        if (output.Contains(NotLockedMarker, StringComparison.Ordinal)) return null; // nothing to do
        if (output.Contains(UnlockedMarker, StringComparison.Ordinal)) return new LockDownResult(LockDownStatus.Undone, "");
        var status = Classify(result);
        return new LockDownResult(status == LockDownStatus.Locked ? LockDownStatus.Failed : status, output.Trim());
    }

    /// <summary>Logs in with the password (and any MFA prompts), proving password login works.</summary>
    public static async Task VerifyPasswordLoginAsync(SshConnectOptions passwordLogin, IHostKeyVerifier verifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(passwordLogin.Credential.Password) || passwordLogin.Credential.HasKey)
            throw new ArgumentException("The password check must use the password, without a key.", nameof(passwordLogin));
        try
        {
            using var connection = await ConnectAsync(passwordLogin, verifier, cancellationToken).ConfigureAwait(false);
            var result = await RunAsync(connection.Client, "echo " + PasswordLoginMarker, null, cancellationToken).ConfigureAwait(false);
            if (!result.Output.Contains(PasswordLoginMarker, StringComparison.Ordinal))
                throw new SshSessionException("Logged in with the password, but the server didn't run a test command." + Detail(result));
        }
        catch (SshSessionException ex) when (SshConnector.IsAuthenticationFailure(ex))
        {
            throw new SshSessionException("The server didn't accept the password. Check it, or whether another setting on the server " +
                                          "still turns off password logins (for example a file in /etc/ssh/sshd_config.d you added yourself).", ex);
        }
    }

    /// <summary>Removes <paramref name="publicKey"/> from ~/.ssh/authorized_keys, over any working login.</summary>
    public static async Task RemoveKeyAsync(SshConnectOptions login, IHostKeyVerifier verifier, string publicKey, CancellationToken cancellationToken = default)
    {
        using var connection = await ConnectAsync(login, verifier, cancellationToken).ConfigureAwait(false);
        var result = await RunAsync(connection.Client, ShellCommand(RemoveKeyScript(publicKey)), null, cancellationToken).ConfigureAwait(false);
        if (!result.CombinedOutput.Contains(RemovedMarker, StringComparison.Ordinal))
            throw new SshSessionException("Could not remove the key from ~/.ssh/authorized_keys." + Detail(result));
    }

    // ---- Plumbing ------------------------------------------------------------------------------

    private static void RequireKeyOnly(SshConnectOptions options)
    {
        var c = options.Credential;
        if (!c.HasKey || !string.IsNullOrEmpty(c.Password) || options.Prompt is not null)
            throw new ArgumentException("The key check must use the key alone: no password and no prompts.", nameof(options));
    }

    /// <remarks>
    /// Always off the caller's thread: SSH.NET does part of the handshake synchronously, and host-key or MFA prompts
    /// need the UI thread, so connecting from the UI thread would deadlock.
    /// </remarks>
    private static Task<SshConnection<SshClient>> ConnectAsync(SshConnectOptions options, IHostKeyVerifier verifier, CancellationToken ct) =>
        Task.Run(() => SshConnector.ConnectAsync(options, verifier, info => new SshClient(info), cancellationToken: ct), ct);

    /// <summary>Runs a command on an open connection, optionally feeding <paramref name="input"/> to its stdin.</summary>
    internal static Task<CommandResult> RunAsync(SshClient client, string command, string? input, CancellationToken cancellationToken) =>
        Task.Run(() => RunCoreAsync(client, command, input, cancellationToken), CancellationToken.None);

    private static async Task<CommandResult> RunCoreAsync(SshClient client, string command, string? input, CancellationToken cancellationToken)
    {
        using var cmd = client.CreateCommand(command);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CommandTimeout);
        try
        {
            var run = cmd.ExecuteAsync(timeout.Token);
            if (input is not null)
            {
                using var stdin = cmd.CreateInputStream(); // closing it sends EOF
                var bytes = Encoding.UTF8.GetBytes(input);
                await stdin.WriteAsync(bytes, timeout.Token).ConfigureAwait(false);
            }
            await run.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SshSessionException($"The server did not answer within {CommandTimeout.TotalSeconds:0} seconds.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not SshSessionException)
        {
            throw new SshSessionException(SshConnector.DescribeError(ex), ex);
        }
        return new CommandResult(cmd.ExitStatus, cmd.Result ?? "", cmd.Error ?? "");
    }

    private static string Detail(CommandResult result)
    {
        var text = result.CombinedOutput.Trim();
        if (text.Length == 0) return "";
        if (text.Length > 400) text = text[..400] + "…";
        return "\n\nServer said:\n" + text;
    }

    private static string OneLine(string s) => s.Replace('\r', ' ').Replace('\n', ' ').Trim();
}

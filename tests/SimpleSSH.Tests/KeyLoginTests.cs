using System.Diagnostics;
using System.Text.Json;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

public class SshKeysTests
{
    [Fact]
    public void Ed25519_LoadsInSshNet_AndMatchesItsPublicLine()
    {
        var pair = SshKeys.CreateEd25519("SimpleSSH alex@PC");
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n", pair.PrivateKey);
        Assert.Matches(@"^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]+=* SimpleSSH alex@PC$", pair.PublicKey);

        Assert.True(SshKeys.TryGetPublicKey(pair.PrivateKey, null, "SimpleSSH alex@PC", out var derived, out var error), error);
        Assert.Equal(pair.PublicKey, derived);
        Assert.NotEqual(pair.PublicKey, SshKeys.CreateEd25519("SimpleSSH alex@PC").PublicKey);
    }

    [Fact]
    public void PastedKey_ToleratesWindowsLineEndingsAndSpaces()
    {
        var pair = SshKeys.CreateEd25519("x");
        var pasted = "\r\n  " + pair.PrivateKey.Replace("\n", "\r\n") + "  \r\n";
        Assert.True(SshKeys.TryGetPublicKey(pasted, null, "x", out var pub, out _));
        Assert.Equal(pair.PublicKey, pub);
    }

    [Theory]
    [InlineData("", "Paste the private key")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI something", "public key")]
    [InlineData("hello world", "doesn't look like a private key")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64\n-----END OPENSSH PRIVATE KEY-----", "Could not load")]
    public void PastedKey_ExplainsWhatIsWrong(string text, string expected)
    {
        Assert.False(SshKeys.TryGetPublicKey(text, null, "", out _, out var error));
        Assert.Contains(expected, error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Comment_IsKeptOnOneLineWithoutQuotes()
    {
        var pair = SshKeys.CreateEd25519("bad'name\nhere");
        Assert.EndsWith(" bad name here", pair.PublicKey);
        Assert.DoesNotContain("'", pair.PublicKey);
    }

    [Fact]
    public void Fingerprint_LooksLikeSshKeygen()
    {
        var pair = SshKeys.CreateEd25519("x");
        Assert.Matches(@"^ED25519 SHA256:[A-Za-z0-9+/]{43}$", SshKeys.Fingerprint(pair.PublicKey));
    }
}

public class KeyLoginScriptTests
{
    private static string? Bash()
    {
        foreach (var p in new[] { @"C:\Program Files\Git\bin\bash.exe", @"C:\Program Files (x86)\Git\bin\bash.exe", "/bin/bash" })
            if (File.Exists(p)) return p;
        return null;
    }

    private static (int Code, string Output) RunBash(string bash, string command, string home)
    {
        var psi = new ProcessStartInfo(bash) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        psi.Environment["HOME"] = home;
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30_000);
        return (p.ExitCode, output);
    }

    [Theory]
    [InlineData("ssh-rsa AAAAexisting other@host")]   // no trailing newline
    [InlineData("ssh-rsa AAAAexisting other@host\n")]
    [InlineData(null)]                                  // no ~/.ssh yet
    public void ManualCommand_AddsTheKeyOnce(string? existing)
    {
        if (Bash() is not { } bash) return;
        var home = Path.Combine(Path.GetTempPath(), "simplessh-home-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        try
        {
            var file = Path.Combine(home, ".ssh", "authorized_keys");
            if (existing is not null)
            {
                Directory.CreateDirectory(Path.Combine(home, ".ssh"));
                File.WriteAllText(file, existing);
            }
            var key = SshKeys.CreateEd25519("SimpleSSH alex@PC").PublicKey;
            var command = KeyLoginSetup.ManualInstallCommand(key);
            Assert.DoesNotContain('\n', command);

            var first = RunBash(bash, command, home.Replace('\\', '/'));
            Assert.True(first.Code == 0, first.Output);
            Assert.Contains(KeyLoginSetup.ManualInstalledMessage, first.Output);
            var second = RunBash(bash, command, home.Replace('\\', '/'));
            Assert.True(second.Code == 0, second.Output);

            var expected = existing is null ? new[] { key } : new[] { "ssh-rsa AAAAexisting other@host", key };
            Assert.Equal(expected, File.ReadAllText(file).Split('\n', StringSplitOptions.RemoveEmptyEntries));
            Assert.EndsWith("\n", File.ReadAllText(file));
        }
        finally
        {
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void ManualCommand_ParsesInPlainSh()
    {
        if (Bash() is not { } bash) return;
        var command = KeyLoginSetup.ManualInstallCommand(SshKeys.CreateEd25519("x").PublicKey);
        var file = Path.Combine(Path.GetTempPath(), "simplessh-manual-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(file, command + "\n");
        try
        {
            var (code, output) = RunBash(bash, $"sh -n '{file.Replace('\\', '/')}'", Path.GetTempPath());
            Assert.True(code == 0, output);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void InstallScript_AddsTheKeyOnce_AndFixesAMissingNewline()
    {
        if (Bash() is not { } bash) return; // needs a POSIX shell (Git Bash on Windows)
        var home = Path.Combine(Path.GetTempPath(), "simplessh-home-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(home, ".ssh"));
        try
        {
            var file = Path.Combine(home, ".ssh", "authorized_keys");
            File.WriteAllText(file, "ssh-rsa AAAAexisting other@host"); // no trailing newline
            var key = SshKeys.CreateEd25519("SimpleSSH test").PublicKey;
            var command = KeyLoginSetup.ShellCommand(KeyLoginSetup.InstallKeyScript(key));

            var first = RunBash(bash, command, home.Replace('\\', '/'));
            Assert.True(first.Code == 0, first.Output);
            Assert.Contains("SIMPLESSH-KEY-INSTALLED", first.Output);
            var second = RunBash(bash, command, home.Replace('\\', '/'));
            Assert.True(second.Code == 0, second.Output);

            var lines = File.ReadAllText(file).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(new[] { "ssh-rsa AAAAexisting other@host", key }, lines);
            Assert.EndsWith("\n", File.ReadAllText(file));
        }
        finally
        {
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void RemoveScript_RemovesOnlyThatKey_WhateverItsCommentOrOptions()
    {
        if (Bash() is not { } bash) return;
        var home = Path.Combine(Path.GetTempPath(), "simplessh-home-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(home, ".ssh"));
        try
        {
            var key = SshKeys.CreateEd25519("SimpleSSH alex@PC").PublicKey;
            var blob = key.Split(' ')[1];
            var file = Path.Combine(home, ".ssh", "authorized_keys");
            File.WriteAllText(file, "ssh-rsa AAAAother one@x\n" + key + "\nfrom=\"10.0.0.0/8\" ssh-ed25519 " + blob + " renamed\nssh-ed25519 AAAAkeep two@y\n");
            var unixHome = home.Replace('\\', '/');
            var (code, output) = RunBash(bash, KeyLoginSetup.ShellCommand(KeyLoginSetup.RemoveKeyScript(key)), unixHome);
            Assert.True(code == 0, output);
            Assert.Contains("SIMPLESSH-KEY-REMOVED", output);
            Assert.Equal(new[] { "ssh-rsa AAAAother one@x", "ssh-ed25519 AAAAkeep two@y" },
                File.ReadAllText(file).Split('\n', StringSplitOptions.RemoveEmptyEntries));

            // Running it again (key already gone, or no file at all) is fine.
            Assert.Equal(0, RunBash(bash, KeyLoginSetup.ShellCommand(KeyLoginSetup.RemoveKeyScript(key)), unixHome).Code);
            File.Delete(file);
            Assert.Equal(0, RunBash(bash, KeyLoginSetup.ShellCommand(KeyLoginSetup.RemoveKeyScript(key)), unixHome).Code);
        }
        finally
        {
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Theory]
    [InlineData("ssh-ed25519")]
    [InlineData("ssh-ed25519 short")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc'; rm -rf ~ #")]
    public void RemoveScript_RejectsAnythingButAKey(string bad)
    {
        Assert.Throws<ArgumentException>(() => KeyLoginSetup.RemoveKeyScript(bad));
    }

    [Fact]
    public void RootScripts_AreValidShell()
    {
        if (Bash() is not { } bash) return;
        foreach (var script in new[]
                 {
                     KeyLoginSetup.LockDownRootScript(), KeyLoginSetup.UndoRootScript(),
                     KeyLoginSetup.AsRootScript(KeyLoginSetup.LockDownRootScript()),
                     KeyLoginSetup.InstallKeyScript("ssh-ed25519 AAAA x"),
                     KeyLoginSetup.EnablePasswordsScript(),
                     KeyLoginSetup.RemoveKeyScript(SshKeys.CreateEd25519("x").PublicKey),
                 })
        {
            var file = Path.Combine(Path.GetTempPath(), "simplessh-" + Guid.NewGuid().ToString("N") + ".sh");
            File.WriteAllText(file, script.Replace("\r\n", "\n"));
            try
            {
                var (code, output) = RunBash(bash, $"sh -n '{file.Replace('\\', '/')}'", Path.GetTempPath());
                Assert.True(code == 0, output + "\n---\n" + script);
            }
            finally
            {
                File.Delete(file);
            }
        }
    }

    [Fact]
    public void LockDownFile_TurnsOffPasswordsOnly()
    {
        var script = KeyLoginSetup.LockDownRootScript();
        Assert.Contains("\nPasswordAuthentication no\n", script);
        Assert.Contains("\nKbdInteractiveAuthentication no\n", script);
        // Nothing else: this file wins over the admin's own settings, so it must not loosen any of them.
        Assert.DoesNotContain("PermitRootLogin", script);
        Assert.DoesNotContain("AuthenticationMethods", script);
        var settings = script.Split('\n').SkipWhile(l => !l.StartsWith("cat > ")).Skip(1).TakeWhile(l => l != "EOF")
            .Where(l => l.Length > 0 && !l.StartsWith('#'));
        Assert.Equal(new[] { "PubkeyAuthentication yes", "PasswordAuthentication no", "KbdInteractiveAuthentication no" }, settings);
        Assert.Contains("sshd\" -t", script.Replace("\"$s\" -t", "sshd\" -t")); // checked before restarting
        Assert.Contains("\nEOF\n", script); // heredoc terminator at column 0
        Assert.StartsWith("/etc/ssh/sshd_config.d/00-", KeyLoginSetup.DropInPath);
    }

    [Theory]
    [InlineData("SIMPLESSH-LOCKED\n", "", LockDownStatus.Locked)]
    [InlineData("", "Sorry, try again.\nsudo: 1 incorrect password attempt", LockDownStatus.WrongSudoPassword)]
    [InlineData("", "sudo: no password was provided", LockDownStatus.WrongSudoPassword)]
    [InlineData("", "alex is not in the sudoers file.  This incident will be reported.", LockDownStatus.NotAllowed)]
    [InlineData("SIMPLESSH-NO-DROPIN\n", "", LockDownStatus.Unsupported)]
    [InlineData("SIMPLESSH-CONFIG-INVALID\n", "/etc/ssh/sshd_config line 3: Bad configuration option", LockDownStatus.ConfigRejected)]
    [InlineData("", "something else", LockDownStatus.Failed)]
    public void Classify(string stdout, string stderr, LockDownStatus expected)
    {
        Assert.Equal(expected, KeyLoginSetup.Classify(new CommandResult(1, stdout, stderr)));
    }

    [Fact]
    public void ShellCommand_HasNoQuotesThatCouldBreak()
    {
        var command = KeyLoginSetup.ShellCommand("echo 'it''s' \"quoted\" $HOME `x`");
        Assert.Equal(2, command.Count(c => c == '\''));
        Assert.StartsWith("sh -c '", command);
    }
}

public sealed class StoredKeyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-key-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public async Task PrivateKey_IsEncryptedOnDisk_AndResolvesToTheConnector()
    {
        var pair = SshKeys.CreateEd25519("x");
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Add(new Connection { Name = "web", Host = "web01", Username = "alex", PrivateKey = pair.PrivateKey, PublicKey = pair.PublicKey });

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("OPENSSH PRIVATE KEY", json);
        Assert.Contains("\"privateKey\": \"dpapi:", json);
        Assert.Contains(pair.PublicKey, json); // the public half is not secret

        var reloaded = new ConnectionStore(FilePath, new DpapiSecretProtector());
        reloaded.Load();
        var c = reloaded.Connections.Single();
        Assert.Equal(pair.PrivateKey, c.PrivateKey);
        var credential = await new StoredCredentialProvider().ResolveAsync(c);
        Assert.Equal(pair.PrivateKey, credential.PrivateKeyText);
        Assert.True(credential.HasKey);
        Assert.True(credential.HasSecret);
    }

    [Fact]
    public void PrivateKey_IsLockedWithThePasswords()
    {
        var key = new FakeSecurityKey();
        var salt = SecurityKeyVault.NewSalt();
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector());
        store.Add(new Connection { Host = "web01", PrivateKey = SshKeys.CreateEd25519("x").PrivateKey });
        store.EnableSecurityKey(SecurityKeyVault.Create(salt, key.CredentialId, key.Secret(salt), "k", null, out _));
        var c = store.Connections.Single();

        store.Lock();
        Assert.Null(c.PrivateKey);
        Assert.True(store.HasLockedSecrets(c.Id));
        Assert.Contains("\"privateKey\": \"sk:", File.ReadAllText(FilePath));
        store.Unlock(key.CredentialId, key.Secret(salt));
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----", c.PrivateKey);
    }

    [Fact]
    public async Task StoredKey_WinsOverAKeyFilePath()
    {
        var c = new Connection { Host = "x", PrivateKeyPath = @"C:\nope\id_rsa", PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----" };
        var credential = await new StoredCredentialProvider().ResolveAsync(c);
        Assert.Null(credential.PrivateKeyPath);
        Assert.NotNull(credential.PrivateKeyText);
    }
}

[Collection("ssh")]
public sealed class KeyLoginIntegrationTests
{
    private readonly TestSshServer _server;

    public KeyLoginIntegrationTests(TestSshServer server) => _server = server;

    private SshConnectOptions Login(string? password = "test", string? key = null, string user = "linux") => new()
    {
        Host = "127.0.0.1",
        Port = _server.Port,
        Credential = new ResolvedCredential(user, password, null, null, key),
        ConnectTimeout = TimeSpan.FromSeconds(10),
    };

    private async Task Reset(bool breakKeys = false)
    {
        var result = await SshCommandRunner.RunAsync(Login(user: "test"), new AcceptAnyHostKeyVerifier(),
            "reset-linux-box" + (breakKeys ? " break-keys" : ""), TimeSpan.FromSeconds(10));
        Assert.Contains("reset", result.Output);
    }

    [Fact]
    public async Task PasswordToKey_ThenLockDown_ThenUndo()
    {
        await Reset();
        var v = new AcceptAnyHostKeyVerifier();
        var pair = SshKeys.CreateEd25519("SimpleSSH test");

        // Before: the key is refused.
        await Assert.ThrowsAsync<ArgumentException>(() => KeyLoginSetup.VerifyKeyLoginAsync(Login(password: "test", key: pair.PrivateKey), v));
        var refused = await Assert.ThrowsAsync<SshSessionException>(() => KeyLoginSetup.VerifyKeyLoginAsync(Login(password: null, key: pair.PrivateKey), v));
        Assert.Contains("didn't accept it", refused.Message);

        await KeyLoginSetup.InstallKeyAsync(Login(), v, pair.PublicKey);
        await KeyLoginSetup.VerifyKeyLoginAsync(Login(password: null, key: pair.PrivateKey), v);

        // Wrong sudo password: nothing changes.
        var wrong = await KeyLoginSetup.LockDownAsync(Login(password: null, key: pair.PrivateKey), Login(), "nope", v);
        Assert.Equal(LockDownStatus.WrongSudoPassword, wrong.Status);
        Assert.Contains("still-open", (await SshCommandRunner.RunAsync(Login(), v, "echo still-open", TimeSpan.FromSeconds(10))).Output);

        var locked = await KeyLoginSetup.LockDownAsync(Login(password: null, key: pair.PrivateKey), Login(), "test", v);
        Assert.Equal(LockDownStatus.Locked, locked.Status);
        var pw = await Assert.ThrowsAsync<SshSessionException>(() => SshCommandRunner.RunAsync(Login(), v, "echo hi", TimeSpan.FromSeconds(10)));
        Assert.True(SshConnector.IsAuthenticationFailure(pw), pw.ToString());
        await KeyLoginSetup.VerifyKeyLoginAsync(Login(password: null, key: pair.PrivateKey), v);

        var undone = await KeyLoginSetup.UndoAsync(Login(password: null, key: pair.PrivateKey), "test", v);
        Assert.Equal(LockDownStatus.Undone, undone.Status);
        Assert.Contains("hi", (await SshCommandRunner.RunAsync(Login(), v, "echo hi", TimeSpan.FromSeconds(10))).Output);
    }

    [Fact]
    public async Task KeyLogin_BackToPassword_RoundTrip()
    {
        await Reset();
        var v = new AcceptAnyHostKeyVerifier();
        var pair = SshKeys.CreateEd25519("SimpleSSH test");
        var keyOnly = Login(password: null, key: pair.PrivateKey);
        await KeyLoginSetup.InstallKeyAsync(Login(), v, pair.PublicKey);
        Assert.Equal(LockDownStatus.Locked, (await KeyLoginSetup.LockDownAsync(keyOnly, Login(), "test", v)).Status);

        // Back: passwords on (sudo), password proven, key removed.
        var enabled = await KeyLoginSetup.EnablePasswordsAsync(keyOnly, "test", v);
        Assert.Equal(LockDownStatus.Undone, enabled!.Status);
        await KeyLoginSetup.VerifyPasswordLoginAsync(Login(), v);
        await KeyLoginSetup.RemoveKeyAsync(Login(), v, pair.PublicKey);
        await Assert.ThrowsAsync<SshSessionException>(() => KeyLoginSetup.VerifyKeyLoginAsync(keyOnly, v));

        // Not locked down: nothing to do, and no sudo password needed.
        await KeyLoginSetup.InstallKeyAsync(Login(), v, pair.PublicKey);
        Assert.Null(await KeyLoginSetup.EnablePasswordsAsync(keyOnly, null, v));
    }

    [Fact]
    public async Task WrongPassword_IsReportedBeforeAnythingIsRemoved()
    {
        await Reset();
        var v = new AcceptAnyHostKeyVerifier();
        var ex = await Assert.ThrowsAsync<SshSessionException>(() => KeyLoginSetup.VerifyPasswordLoginAsync(Login(password: "wrong"), v));
        Assert.Contains("didn't accept the password", ex.Message);
    }

    [Fact]
    public async Task LockDown_IsUndone_WhenTheKeyStopsWorking()
    {
        await Reset(breakKeys: true);
        var v = new AcceptAnyHostKeyVerifier();
        var pair = SshKeys.CreateEd25519("SimpleSSH test");
        await KeyLoginSetup.InstallKeyAsync(Login(), v, pair.PublicKey);

        var result = await KeyLoginSetup.LockDownAsync(Login(password: null, key: pair.PrivateKey), Login(), "test", v);
        Assert.Equal(LockDownStatus.RolledBack, result.Status);
        Assert.Contains("undone", result.Output);
        // Password logins work again, so the server is still reachable.
        Assert.Contains("hi", (await SshCommandRunner.RunAsync(Login(), v, "echo hi", TimeSpan.FromSeconds(10))).Output);
    }
}

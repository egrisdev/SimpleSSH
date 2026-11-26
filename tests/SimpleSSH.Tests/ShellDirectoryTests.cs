using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Tests;

public class ShellDirectoryTests
{
    [Theory]
    [InlineData("alex@syslog: ~", "alex", "~")]                       // Ubuntu / Debian
    [InlineData("alex@syslog: ~/logs/old", "alex", "~/logs/old")]
    [InlineData("alex@syslog: /var/log", "alex", "/var/log")]
    [InlineData("root@syslog: /etc/ssh", "root", "/etc/ssh")]
    [InlineData("alex@web01:~/site", "alex", "~/site")]               // Fedora / RHEL
    [InlineData("alex@web01.example.com: /srv/My Files ", "alex", "/srv/My Files")]
    [InlineData("svc-backup@nas: /", "svc-backup", "/")]
    public void Title_GivesTheFolder(string title, string user, string path)
    {
        Assert.True(ShellDirectory.TryParseTitle(title, out var location));
        Assert.Equal((user, path), (location.User, location.Path));
    }

    [Theory]
    [InlineData("")]
    [InlineData("vim notes.txt")]
    [InlineData("htop")]
    [InlineData("alex@syslog")]
    [InlineData("alex@syslog: ~bob/x")]
    [InlineData("alex@syslog: relative/path")]
    [InlineData("Windows PowerShell")]
    public void OtherTitles_AreIgnored(string title) => Assert.False(ShellDirectory.TryParseTitle(title, out _));

    [Theory]
    [InlineData("file://syslog/var/log", "/var/log")]
    [InlineData("file:///home/alex/My%20Files", "/home/alex/My Files")]
    [InlineData("file://syslog/", "/")]
    public void Osc7_GivesTheFolder(string data, string path)
    {
        Assert.True(ShellDirectory.TryParseOsc7(data, out var location));
        Assert.Equal(path, location.Path);
    }

    [Theory]
    [InlineData("http://x/y")]
    [InlineData("file://hostonly")]
    [InlineData("")]
    public void Osc7_RejectsOtherData(string data) => Assert.False(ShellDirectory.TryParseOsc7(data, out _));

    [Theory]
    [InlineData("/var/log\n", "/var/log")]
    [InlineData("/home/alex/My Files\r\n", "/home/alex/My Files")]
    [InlineData("/", "/")]
    public void Probe_GivesTheFolder(string output, string path)
    {
        Assert.True(ShellDirectory.TryParseProbe(output, out var parsed));
        Assert.Equal(path, parsed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative")]
    [InlineData("/tmp/gone (deleted)\n")]
    [InlineData("/a\nb\n")]
    public void Probe_RejectsOtherOutput(string output) => Assert.False(ShellDirectory.TryParseProbe(output, out _));

    [Fact]
    public void ProbeCommand_IsOneLineAnyShellCanPass()
    {
        var command = ShellDirectory.ProbeCommand;
        Assert.DoesNotContain('\n', command);
        Assert.DoesNotContain('!', command); // csh history expansion
        Assert.StartsWith("sh -c '", command);
        Assert.Equal(2, command.Count(ch => ch == '\''));
    }

    [Fact]
    public void ProbeCommand_RunsInPlainSh_AndFindsNothingWithoutASession()
    {
        var bash = new[] { @"C:\Program Files\Git\bin\bash.exe", @"C:\Program Files (x86)\Git\bin\bash.exe", "/bin/bash" }.FirstOrDefault(File.Exists);
        if (bash is null) return; // needs a POSIX shell (Git Bash on Windows)
        foreach (var (connection, expected) in new[] { ("", 3), ("203.0.113.9 50000 198.51.100.1 22", 1) })
        {
            var psi = new System.Diagnostics.ProcessStartInfo(bash) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(ShellDirectory.ProbeCommand);
            psi.Environment["SSH_CONNECTION"] = connection;
            using var p = System.Diagnostics.Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            Assert.True(p.WaitForExit(60_000));
            Assert.Equal("", output);
            Assert.Equal(expected, p.ExitCode);
        }
    }

    [Theory]
    [InlineData("alex", "~/logs", "alex", "~/logs")]          // same user: SFTP resolves ~ itself
    [InlineData("root", "~", "alex", "/root")]                // after sudo -i
    [InlineData("root", "~/x", "alex", "/root/x")]
    [InlineData("bob", "~/x", "alex", "/home/bob/x")]
    [InlineData("root", "/etc", "alex", "/etc")]
    [InlineData("alex", "~/x", "", "~/x")]                    // username not saved: assume it's the same account
    public void Tilde_BelongsToTheShellUser(string user, string path, string login, string expected) =>
        Assert.Equal(expected, ShellDirectory.ForLogin(new ShellLocation(user, path), login));
}

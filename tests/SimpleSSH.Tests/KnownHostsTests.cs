using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Tests;

public sealed class KnownHostsTests : IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), "simplessh-kh-" + Guid.NewGuid().ToString("N") + ".json");

    public void Dispose()
    {
        try { File.Delete(_file); } catch { }
    }

    [Fact]
    public void Check_Unknown_Trusted_Changed()
    {
        var store = new KnownHostsStore(_file);
        Assert.Equal(HostKeyStatus.Unknown, store.Check("Host", 22, "ssh-ed25519", "AAA").Status);

        store.Trust("Host", 22, "ssh-ed25519", "AAA");
        Assert.Equal(HostKeyStatus.Trusted, store.Check("host", 22, "ssh-ed25519", "AAA").Status);
        Assert.Equal(HostKeyStatus.Unknown, store.Check("host", 2222, "ssh-ed25519", "AAA").Status);
        var otherType = store.Check("host", 22, "ssh-rsa", "BBB");
        Assert.Equal(HostKeyStatus.OtherTypeKnown, otherType.Status);
        Assert.Equal(("ssh-ed25519", "AAA"), (otherType.KnownKeyType, otherType.KnownFingerprint));

        var changed = store.Check("host", 22, "ssh-ed25519", "ZZZ");
        Assert.Equal(HostKeyStatus.Changed, changed.Status);
        Assert.Equal("AAA", changed.KnownFingerprint);

        // Persisted
        var reloaded = new KnownHostsStore(_file);
        Assert.Equal(HostKeyStatus.Trusted, reloaded.Check("HOST", 22, "ssh-ed25519", "AAA").Status);
    }

    [Fact]
    public void Verifier_AsksOnlyWhenNotTrusted()
    {
        var store = new KnownHostsStore(_file);
        int asked = 0;
        var decision = HostKeyDecision.AcceptAndSave;
        var verifier = new KnownHostsVerifier(store, (_, _) => { asked++; return decision; });
        var key = new HostKeyInfo("h", 22, "ssh-rsa", "FP1", 2048);

        Assert.True(verifier.Verify(key));
        Assert.True(verifier.Verify(key));
        Assert.Equal(1, asked);

        decision = HostKeyDecision.Reject;
        Assert.False(verifier.Verify(key with { FingerprintSha256 = "FP2" }));
        Assert.Equal(2, asked);

        decision = HostKeyDecision.AcceptOnce;
        Assert.True(verifier.Verify(key with { Host = "other" }));
        Assert.Equal(HostKeyStatus.Unknown, store.Check("other", 22, "ssh-rsa", "FP1").Status);
    }

    [Fact]
    public void RsaSignatureVariants_AreTheSameKey()
    {
        var store = new KnownHostsStore(_file);
        store.Trust("sw1", 22, "rsa-sha2-512", "FP");
        Assert.Equal(HostKeyStatus.Trusted, store.Check("sw1", 22, "rsa-sha2-256", "FP").Status);
        Assert.Equal(HostKeyStatus.Trusted, store.Check("sw1", 22, "ssh-rsa", "FP").Status);
        Assert.Equal(HostKeyStatus.Changed, store.Check("sw1", 22, "ssh-rsa", "OTHER").Status);
    }

    [Fact]
    public void KnownKeyTypes_ArePreferredWhenConnecting()
    {
        var store = new KnownHostsStore(_file);
        store.Trust("sw1", 22, "rsa-sha2-512", "FP");
        Assert.Equal(new[] { "ssh-rsa" }, store.KnownKeyTypes("SW1", 22));
        Assert.Empty(store.KnownKeyTypes("sw1", 2222));

        var info = new Renci.SshNet.ConnectionInfo("sw1", "u", new Renci.SshNet.NoneAuthenticationMethod("u"));
        var before = info.HostKeyAlgorithms.Keys.ToList();
        SshConnector.PreferKnownHostKeyTypes(info, store.KnownKeyTypes("sw1", 22));
        var after = info.HostKeyAlgorithms.Keys.ToList();

        var rsa = before.Where(k => KnownHostsStore.NormalizeKeyType(k) == "ssh-rsa").ToList();
        Assert.NotEmpty(rsa);
        Assert.Equal(rsa, after.Take(rsa.Count)); // the RSA variants first, in their original order
        Assert.Equal(before.OrderBy(k => k), after.OrderBy(k => k)); // nothing lost
    }

    [Fact]
    public void CorruptFile_StartsFresh()
    {
        File.WriteAllText(_file, "garbage{");
        var store = new KnownHostsStore(_file);
        Assert.Equal(HostKeyStatus.Unknown, store.Check("h", 22, "t", "f").Status);
    }
}

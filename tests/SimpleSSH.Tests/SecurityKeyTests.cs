using System.Security.Cryptography;
using System.Text.Json;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

/// <summary>Stands in for a FIDO2 key: hmac-secret is HMAC-SHA256(per-credential secret, salt).</summary>
internal sealed class FakeSecurityKey
{
    private readonly byte[] _credRandom = RandomNumberGenerator.GetBytes(32);
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(48);
    public byte[] Secret(byte[] salt) => HMACSHA256.HashData(_credRandom, salt);
}

public class SecurityKeyVaultTests
{
    private static readonly byte[] Salt = SecurityKeyVault.NewSalt();

    private static SecurityKeyVault NewVault(FakeSecurityKey key, out string recovery, ISecretProtector? slots = null) =>
        SecurityKeyVault.Create(Salt, key.CredentialId, key.Secret(Salt), "Key 1", slots, out recovery);

    [Fact]
    public void Create_IsUnlocked_AndProtectsSecrets()
    {
        var vault = NewVault(new FakeSecurityKey(), out _);
        Assert.True(vault.IsUnlocked);
        var stored = vault.Protect("hunter2 日本");
        Assert.StartsWith(SecurityKeyVault.Prefix, stored);
        Assert.DoesNotContain("hunter2", stored);
        Assert.True(vault.TryUnprotect(stored, out var back));
        Assert.Equal("hunter2 日本", back);
        Assert.NotEqual(stored, vault.Protect("hunter2 日本"));
    }

    [Fact]
    public void Locked_CannotProtectOrUnprotect()
    {
        var vault = NewVault(new FakeSecurityKey(), out _);
        var stored = vault.Protect("x");
        vault.Lock();
        Assert.False(vault.IsUnlocked);
        Assert.False(vault.TryUnprotect(stored, out _));
        Assert.Throws<InvalidOperationException>(() => vault.Protect("y"));
    }

    [Fact]
    public void TheRegisteredKey_Unlocks_OthersDoNot()
    {
        var key = new FakeSecurityKey();
        var other = new FakeSecurityKey();
        var vault = NewVault(key, out _);
        var stored = vault.Protect("secret");
        var reopened = new SecurityKeyVault(vault.Header, null);

        Assert.Equal(KeyUnlockResult.UnknownKey, reopened.Unlock(other.CredentialId, other.Secret(Salt)));
        Assert.Equal(KeyUnlockResult.WrongSecret, reopened.Unlock(key.CredentialId, other.Secret(Salt)));
        Assert.Equal(KeyUnlockResult.WrongSecret, reopened.Unlock(key.CredentialId, key.Secret(SecurityKeyVault.NewSalt())));
        Assert.False(reopened.IsUnlocked);

        Assert.Equal(KeyUnlockResult.Unlocked, reopened.Unlock(key.CredentialId, key.Secret(Salt)));
        Assert.True(reopened.TryUnprotect(stored, out var back));
        Assert.Equal("secret", back);
    }

    [Fact]
    public void RecoveryKey_Unlocks_AndIsForgiving()
    {
        var vault = NewVault(new FakeSecurityKey(), out var recovery);
        var stored = vault.Protect("secret");
        Assert.Matches("^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$", recovery);

        var reopened = new SecurityKeyVault(vault.Header, null);
        Assert.False(reopened.UnlockWithRecoveryKey("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"));
        Assert.False(reopened.UnlockWithRecoveryKey(recovery[..^1]));
        Assert.False(reopened.UnlockWithRecoveryKey(""));
        Assert.True(reopened.UnlockWithRecoveryKey("  " + recovery.ToLowerInvariant().Replace("-", " ") + "\r\n"));
        Assert.True(reopened.TryUnprotect(stored, out _));
    }

    [Fact]
    public void RecoveryKey_ParsesLookAlikeDigits()
    {
        var raw = new byte[20];
        raw[0] = 0x73; // lets the text contain an O and an I
        var text = SecurityKeyVault.FormatRecoveryKey(raw);
        Assert.True(SecurityKeyVault.TryParseRecoveryKey(text.Replace('O', '0').Replace('I', '1').Replace('B', '8'), out var back));
        Assert.Equal(raw, back);
        Assert.False(SecurityKeyVault.TryParseRecoveryKey(text + "A", out _));
        Assert.False(SecurityKeyVault.TryParseRecoveryKey(text.Replace('A', '9'), out _));
    }

    [Fact]
    public void ResetRecoveryKey_RetiresTheOldOne()
    {
        var vault = NewVault(new FakeSecurityKey(), out var oldKey);
        var newKey = vault.ResetRecoveryKey();
        Assert.NotEqual(oldKey, newKey);
        Assert.False(new SecurityKeyVault(vault.Header, null).UnlockWithRecoveryKey(oldKey));
        Assert.True(new SecurityKeyVault(vault.Header, null).UnlockWithRecoveryKey(newKey));
    }

    [Fact]
    public void Rekey_RetiresTheOldRecoveryKey_EvenForOldCopies()
    {
        var first = new FakeSecurityKey();
        var second = new FakeSecurityKey();
        var vault = NewVault(first, out var oldRecovery);
        vault.AddKey(second.CredentialId, second.Secret(Salt), "Spare");
        var oldHeader = JsonSerializer.Serialize(vault.Header);
        var oldSecret = vault.Protect("pw");

        var next = vault.Rekey(new[] { (first.CredentialId, first.Secret(Salt)) }, out var newRecovery);

        Assert.NotEqual(oldRecovery, newRecovery);
        Assert.Equal(vault.Header.Salt, next.Header.Salt);
        Assert.Equal("Key 1", Assert.Single(next.Header.Keys).Name);
        Assert.Equal(KeyUnlockResult.Unlocked, new SecurityKeyVault(next.Header, null).Unlock(first.CredentialId, first.Secret(Salt)));
        Assert.Equal(KeyUnlockResult.UnknownKey, new SecurityKeyVault(next.Header, null).Unlock(second.CredentialId, second.Secret(Salt)));
        Assert.True(new SecurityKeyVault(next.Header, null).UnlockWithRecoveryKey(newRecovery));
        Assert.False(new SecurityKeyVault(next.Header, null).UnlockWithRecoveryKey(oldRecovery));

        // The old recovery key still opens an old copy of the file, but that data key opens nothing new.
        var oldCopy = new SecurityKeyVault(JsonSerializer.Deserialize<SecurityKeyLock>(oldHeader)!, null);
        Assert.True(oldCopy.UnlockWithRecoveryKey(oldRecovery));
        Assert.True(oldCopy.TryUnprotect(oldSecret, out _));
        Assert.False(oldCopy.TryUnprotect(next.Protect("pw"), out _));
        Assert.False(new SecurityKeyVault(next.Header, null).TryAdopt(oldCopy));
    }

    [Fact]
    public void Rekey_NeedsEachKeysOwnSecret()
    {
        var key = new FakeSecurityKey();
        var vault = NewVault(key, out _);
        Assert.Throws<ArgumentException>(() => vault.Rekey(Array.Empty<(byte[], byte[])>(), out _));
        Assert.Throws<ArgumentException>(() => vault.Rekey(new[] { (key.CredentialId, new FakeSecurityKey().Secret(Salt)) }, out _));
        var stranger = new FakeSecurityKey();
        Assert.Throws<ArgumentException>(() => vault.Rekey(new[] { (stranger.CredentialId, stranger.Secret(Salt)) }, out _));
        vault.Lock();
        Assert.Throws<InvalidOperationException>(() => vault.Rekey(new[] { (key.CredentialId, key.Secret(Salt)) }, out _));
    }

    [Fact]
    public void SecondKey_Unlocks_AndTheLastKeyCannotBeRemoved()
    {
        var first = new FakeSecurityKey();
        var second = new FakeSecurityKey();
        var vault = NewVault(first, out _);
        vault.AddKey(second.CredentialId, second.Secret(Salt), "Backup");
        Assert.Equal(2, vault.Header.Keys.Count);
        Assert.Equal(KeyUnlockResult.Unlocked, new SecurityKeyVault(vault.Header, null).Unlock(second.CredentialId, second.Secret(Salt)));

        Assert.True(vault.RemoveKey(Convert.ToBase64String(first.CredentialId)));
        Assert.False(vault.RemoveKey(Convert.ToBase64String(second.CredentialId)));
        Assert.Single(vault.Header.Keys);
        Assert.Equal(KeyUnlockResult.UnknownKey, new SecurityKeyVault(vault.Header, null).Unlock(first.CredentialId, first.Secret(Salt)));
    }

    [Fact]
    public void KeySlots_NeedThisWindowsAccount()
    {
        var key = new FakeSecurityKey();
        var vault = NewVault(key, out var recovery, new DpapiSecretProtector("slots-a"));
        Assert.StartsWith(DpapiSecretProtector.Prefix, vault.Header.Keys[0].DataKey);
        Assert.Equal(KeyUnlockResult.Unlocked, new SecurityKeyVault(vault.Header, new DpapiSecretProtector("slots-a")).Unlock(key.CredentialId, key.Secret(Salt)));

        // "Another Windows account": DPAPI cannot open the slot, but the recovery key still works, and re-adding fixes it.
        var elsewhere = new SecurityKeyVault(vault.Header, new DpapiSecretProtector("slots-b"));
        Assert.Empty(elsewhere.UsableCredentialIds);
        Assert.Single(elsewhere.OtherAccountKeys);
        Assert.Equal(KeyUnlockResult.OtherWindowsAccount, elsewhere.Unlock(key.CredentialId, key.Secret(Salt)));
        Assert.True(elsewhere.UnlockWithRecoveryKey(recovery));
        elsewhere.AddKey(key.CredentialId, key.Secret(Salt), "");
        Assert.Single(elsewhere.Header.Keys);
        Assert.Equal("Key 1", elsewhere.Header.Keys[0].Name);
        Assert.Empty(elsewhere.OtherAccountKeys);
    }

    [Fact]
    public void TryAdopt_TakesTheDataKeyOnlyForTheSameFile()
    {
        var key = new FakeSecurityKey();
        var vault = NewVault(key, out _);
        var sameFile = new SecurityKeyVault(JsonSerializer.Deserialize<SecurityKeyLock>(JsonSerializer.Serialize(vault.Header))!, null);
        Assert.True(sameFile.TryAdopt(vault));
        Assert.True(sameFile.IsUnlocked);

        var otherFile = new SecurityKeyVault(NewVault(key, out _).Header, null);
        Assert.False(otherFile.TryAdopt(vault));
        Assert.False(otherFile.IsUnlocked);
    }
}

public sealed class SecurityKeyStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-sk-" + Guid.NewGuid().ToString("N"));
    private readonly FakeSecurityKey _key = new();
    private readonly byte[] _salt = SecurityKeyVault.NewSalt();
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private ConnectionStore NewStore()
    {
        var store = new ConnectionStore(FilePath, new DpapiSecretProtector(), new DpapiSecretProtector("SimpleSSH/test-slots"));
        store.Load();
        return store;
    }

    private string EnableOn(ConnectionStore store)
    {
        var vault = SecurityKeyVault.Create(_salt, _key.CredentialId, _key.Secret(_salt), "Key", new DpapiSecretProtector("SimpleSSH/test-slots"), out var recovery);
        store.EnableSecurityKey(vault);
        return recovery;
    }

    private ConnectionStore StoreWithSecrets()
    {
        var store = NewStore();
        store.Add(new Connection { Name = "a", Host = "a", Username = "u", Password = "pw-a", PrivateKeyPassphrase = "pp-a", Proxy = "socks5://p:proxypw@px:1080" });
        store.Add(new Connection { Name = "b", Host = "b", Username = "u", Proxy = "socks5://px:1080" });
        return store;
    }

    [Fact]
    public void Enable_ReencryptsEverySecret_AndWritesTheHeader()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("pw-a", json);
        Assert.DoesNotContain("proxypw", json);
        Assert.DoesNotContain("\"dpapi:", json.Replace("\"dataKey\": \"dpapi:", ""));
        Assert.Contains("\"securityKey\"", json);
        Assert.Contains("\"password\": \"sk:", json);
        Assert.Contains("socks5://px:1080", json); // no password: not a secret
        Assert.False(store.IsLocked);
        Assert.Equal("pw-a", store.Connections[0].Password);
    }

    [Fact]
    public void Reload_IsLocked_UntilTheKeyIsUsed()
    {
        EnableOn(StoreWithSecrets());
        var store = NewStore();
        Assert.True(store.IsLocked);
        var a = store.Connections.Single(c => c.Name == "a");
        Assert.Null(a.Password);
        Assert.Null(a.PrivateKeyPassphrase);
        Assert.Null(a.Proxy);
        Assert.True(store.HasLockedSecrets(a.Id));
        Assert.False(store.HasLockedSecrets(store.Connections.Single(c => c.Name == "b").Id));
        Assert.False(store.HasUnreadablePassword(a.Id));
        Assert.Equal(0, store.UnreadableSecretCount);

        var other = new FakeSecurityKey();
        Assert.Equal(KeyUnlockResult.UnknownKey, store.Unlock(other.CredentialId, other.Secret(_salt)));
        Assert.True(store.IsLocked);

        Assert.Equal(KeyUnlockResult.Unlocked, store.Unlock(_key.CredentialId, _key.Secret(_salt)));
        Assert.False(store.IsLocked);
        Assert.Equal("pw-a", a.Password);
        Assert.Equal("pp-a", a.PrivateKeyPassphrase);
        Assert.Equal("socks5://p:proxypw@px:1080", a.Proxy);
        Assert.False(store.HasLockedSecrets(a.Id));
    }

    [Fact]
    public void Lock_ClearsMemory_AndSavingWhileLockedKeepsTheSecrets()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        var a = store.Connections.Single(c => c.Name == "a");
        var lockEvents = 0;
        store.LockChanged += (_, _) => lockEvents++;

        store.Lock();
        Assert.Equal(1, lockEvents);
        Assert.True(store.IsLocked);
        Assert.Null(a.Password);
        Assert.Null(a.Proxy);
        Assert.Equal("socks5://px:1080", store.Connections.Single(c => c.Name == "b").Proxy);

        // An edit that does not touch the secrets (rename) keeps them.
        var edited = a.Clone();
        edited.Name = "renamed";
        store.Update(edited);
        Assert.Contains("\"password\": \"sk:", File.ReadAllText(FilePath));

        Assert.True(store.Unlock(_key.CredentialId, _key.Secret(_salt)) == KeyUnlockResult.Unlocked);
        Assert.Equal("pw-a", a.Password);
        Assert.Equal("renamed", a.Name);
    }

    [Fact]
    public void NewSecretsWhileLocked_AreRefused_UntilUnlocked()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        store.Lock();
        var before = File.ReadAllText(FilePath);

        var b = store.Connections.Single(c => c.Name == "b").Clone();
        Assert.False(store.NeedsUnlockToSave(b)); // a proxy without a password is not a secret
        b.Password = "typed-while-locked";
        Assert.True(store.NeedsUnlockToSave(b));
        Assert.Throws<ConnectionStoreException>(() => store.Update(b));
        var added = new Connection { Name = "c", Host = "c", PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----" };
        Assert.Throws<ConnectionStoreException>(() => store.Add(added));
        var proxied = new Connection { Name = "d", Host = "d", Proxy = "socks5://u:pw@px:1080" };
        Assert.Throws<ConnectionStoreException>(() => store.Add(proxied));
        Assert.Equal(before, File.ReadAllText(FilePath)); // nothing written with DPAPI alone
        Assert.Null(store.Connections.Single(c => c.Name == "b").Password);

        store.Unlock(_key.CredentialId, _key.Secret(_salt));
        Assert.False(store.NeedsUnlockToSave(b));
        store.Update(b);
        var bJson = JsonDocument.Parse(File.ReadAllText(FilePath)).RootElement.GetProperty("connections")[1];
        Assert.StartsWith("sk:", bJson.GetProperty("password").GetString());
    }

    [Fact]
    public void Rekey_EncryptsEverySecretAgain()
    {
        var store = StoreWithSecrets();
        var oldRecovery = EnableOn(store);
        var oldFile = File.ReadAllText(FilePath);

        var next = store.Vault!.Rekey(new[] { (_key.CredentialId, _key.Secret(_salt)) }, out var newRecovery);
        store.EnableSecurityKey(next);

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("pw-a", json);
        var oldPassword = JsonDocument.Parse(oldFile).RootElement.GetProperty("connections")[0].GetProperty("password").GetString();
        var newPassword = JsonDocument.Parse(json).RootElement.GetProperty("connections")[0].GetProperty("password").GetString();
        Assert.StartsWith("sk:", newPassword);
        Assert.NotEqual(oldPassword, newPassword);

        var reloaded = NewStore();
        Assert.False(reloaded.UnlockWithRecoveryKey(oldRecovery));
        Assert.True(reloaded.UnlockWithRecoveryKey(newRecovery));
        Assert.Equal("pw-a", reloaded.Connections.Single(c => c.Name == "a").Password);
        Assert.Equal(0, reloaded.UnreadableSecretCount);
    }

    [Fact]
    public void RecoveryKey_UnlocksTheStore()
    {
        var recovery = EnableOn(StoreWithSecrets());
        var store = NewStore();
        Assert.False(store.UnlockWithRecoveryKey("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"));
        Assert.True(store.IsLocked);
        Assert.True(store.UnlockWithRecoveryKey(recovery));
        Assert.Equal("pw-a", store.Connections.Single(c => c.Name == "a").Password);
    }

    [Fact]
    public void Disable_GoesBackToDpapi()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        store.Lock();
        Assert.Throws<InvalidOperationException>(() => store.DisableSecurityKey());
        store.Unlock(_key.CredentialId, _key.Secret(_salt));
        store.DisableSecurityKey();

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("securityKey", json);
        Assert.DoesNotContain("\"sk:", json);
        Assert.Contains("\"password\": \"dpapi:", json);
        Assert.Equal("pw-a", NewStore().Connections.Single(c => c.Name == "a").Password);
    }

    [Fact]
    public void ReloadWhileUnlocked_StaysUnlocked_AndOldObjectsLoseTheirSecrets()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        var oldA = store.Connections.Single(c => c.Name == "a");
        store.Load();
        Assert.False(store.IsLocked);
        Assert.Null(oldA.Password);
        Assert.Equal("pw-a", store.Connections.Single(c => c.Name == "a").Password);
    }

    [Fact]
    public void DamagedVaultSecret_CountsAsUnreadable_OnceUnlocked()
    {
        var store = StoreWithSecrets();
        EnableOn(store);
        var text = File.ReadAllText(FilePath);
        var json = JsonDocument.Parse(text).RootElement.GetProperty("connections")[0].GetProperty("password").GetString()!;
        File.WriteAllText(FilePath, text.Replace(json, "sk:" + Convert.ToBase64String(new byte[40])));

        var reloaded = NewStore();
        reloaded.Unlock(_key.CredentialId, _key.Secret(_salt));
        var a = reloaded.Connections.Single(c => c.Name == "a");
        Assert.Null(a.Password);
        Assert.True(reloaded.HasUnreadablePassword(a.Id));
        Assert.Equal(1, reloaded.UnreadableSecretCount);
        Assert.Equal("pp-a", a.PrivateKeyPassphrase);
    }
}

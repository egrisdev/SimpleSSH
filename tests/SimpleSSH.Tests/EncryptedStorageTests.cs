using System.Text.Json;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

public sealed class EncryptedStorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-enc-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private ConnectionStore NewStore(ISecretProtector? protector = null)
    {
        var store = new ConnectionStore(FilePath, protector ?? new DpapiSecretProtector());
        store.Load();
        return store;
    }

    private JsonElement OnDisk(int index) =>
        JsonDocument.Parse(File.ReadAllText(FilePath)).RootElement.GetProperty("connections")[index];

    [Fact]
    public void Dpapi_RoundTrips_AndIsNotPlainText()
    {
        var p = new DpapiSecretProtector();
        var stored = p.Protect("s3cret!+<&>' 日本");
        Assert.StartsWith("dpapi:", stored);
        Assert.DoesNotContain("s3cret", stored);
        Assert.True(p.TryUnprotect(stored, out var back));
        Assert.Equal("s3cret!+<&>' 日本", back);
        Assert.NotEqual(stored, p.Protect("s3cret!+<&>' 日本")); // randomized
    }

    [Fact]
    public void Save_EncryptsSecrets_Load_DecryptsThem()
    {
        var store = NewStore();
        store.Add(new Connection { Name = "sw1", Host = "10.0.0.1", Username = "admin", Password = "hunter2", PrivateKeyPassphrase = "keypass" });

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain("hunter2", json);
        Assert.DoesNotContain("keypass", json);
        Assert.StartsWith("dpapi:", OnDisk(0).GetProperty("password").GetString());
        Assert.StartsWith("dpapi:", OnDisk(0).GetProperty("privateKeyPassphrase").GetString());
        Assert.Equal("admin", OnDisk(0).GetProperty("username").GetString()); // everything else stays readable

        Assert.Equal("hunter2", store.Connections[0].Password); // in memory: plain

        var reloaded = NewStore();
        Assert.Equal("hunter2", reloaded.Connections[0].Password);
        Assert.Equal("keypass", reloaded.Connections[0].PrivateKeyPassphrase);
        Assert.Equal(0, reloaded.UnreadableSecretCount);
    }

    [Fact]
    public void Load_MigratesPlainTextPasswords_OnTheSpot()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, """
            { "version": 1, "connections": [ { "name": "old", "host": "h", "username": "u", "password": "plain-old" } ] }
            """);

        var store = NewStore();
        Assert.Equal(1, store.MigratedSecretCount);
        Assert.Equal("plain-old", store.Connections[0].Password);
        Assert.DoesNotContain("plain-old", File.ReadAllText(FilePath)); // re-saved encrypted immediately

        var reloaded = NewStore();
        Assert.Equal(0, reloaded.MigratedSecretCount);
        Assert.Equal("plain-old", reloaded.Connections[0].Password);
    }

    [Fact]
    public void UnreadableSecret_IsKeptOnDisk_UntilReplaced()
    {
        // Encrypted "by someone else" (different entropy = different key as far as we're concerned).
        var foreign = new DpapiSecretProtector("another-user").Protect("theirs");
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(new
        {
            version = 1,
            connections = new[] { new { id = Guid.NewGuid(), name = "x", host = "h", password = foreign } },
        }));

        var store = NewStore();
        var c = store.Connections[0];
        Assert.Null(c.Password); // so the app asks at connect time
        Assert.Equal(1, store.UnreadableSecretCount);
        Assert.True(store.HasUnreadablePassword(c.Id));

        // Unrelated edits don't destroy the blob.
        var edited = c.Clone();
        edited.Notes = "edited";
        store.Update(edited);
        Assert.Equal(foreign, OnDisk(0).GetProperty("password").GetString());

        // A new password replaces it.
        edited.Password = "mine";
        store.Update(edited);
        Assert.Equal(0, store.UnreadableSecretCount);
        Assert.Equal("mine", NewStore().Connections[0].Password);
    }

    [Fact]
    public void GarbageEncryptedValue_IsUnreadable_NotACrash()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, """
            { "connections": [ { "host": "h", "password": "dpapi:not-base64!!" } ] }
            """);
        var store = NewStore();
        Assert.Null(store.Connections[0].Password);
        Assert.Equal(1, store.UnreadableSecretCount);
    }
}

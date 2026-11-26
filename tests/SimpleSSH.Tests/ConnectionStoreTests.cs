using System.Text.Json;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Tests;

public sealed class ConnectionStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "simplessh-tests-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "connections.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Load_MissingFile_GivesEmptyList()
    {
        var store = new ConnectionStore(FilePath);
        store.Load();
        Assert.Empty(store.Connections);
    }

    [Fact]
    public void Add_PersistsPlainTextJson_AndRoundTrips()
    {
        var store = new ConnectionStore(FilePath);
        store.Load();
        store.Add(new Connection
        {
            Name = "core-sw-01", Host = "10.0.0.1", Port = 22, Username = "admin", Password = "s3cret!+<&>'",
            Tags = new() { " Switches ", "switches", "", "Core" },
        });

        var json = File.ReadAllText(FilePath);
        Assert.Contains("\"password\": \"s3cret!+<&>'\"", json);   // no protector configured -> plain text
        Assert.Contains("\"connections\"", json);

        var reloaded = new ConnectionStore(FilePath);
        reloaded.Load();
        var c = Assert.Single(reloaded.Connections);
        Assert.Equal("core-sw-01", c.Name);
        Assert.Equal("admin", c.Username);
        Assert.Equal("s3cret!+<&>'", c.Password);
        Assert.Equal(new[] { "Switches", "Core" }, c.Tags);
    }

    [Fact]
    public void Update_And_Remove_Work()
    {
        var store = new ConnectionStore(FilePath);
        store.Load();
        var c = new Connection { Name = "a", Host = "h1" };
        store.Add(c);

        var edited = c.Clone();
        edited.Name = "b";
        edited.Port = 2200;
        store.Update(edited);
        Assert.Same(c, store.Find(c.Id));
        Assert.Equal("b", c.Name);
        Assert.Equal(2200, c.Port);

        Assert.True(store.Remove(c.Id));
        Assert.False(store.Remove(c.Id));

        var reloaded = new ConnectionStore(FilePath);
        reloaded.Load();
        Assert.Empty(reloaded.Connections);
    }

    [Fact]
    public void Add_RequiresHost_AndValidPort()
    {
        var store = new ConnectionStore(FilePath);
        Assert.Throws<ArgumentException>(() => store.Add(new Connection { Name = "x", Host = " " }));
        Assert.Throws<ArgumentException>(() => store.Add(new Connection { Name = "x", Host = "h", Port = 70000 }));
        Assert.False(File.Exists(FilePath));
    }

    [Fact]
    public void Load_CorruptFile_Throws_AndCanBeQuarantined()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, "{ not json");
        var store = new ConnectionStore(FilePath);
        Assert.Throws<ConnectionStoreException>(store.Load);
        var backup = store.QuarantineCorruptFile();
        Assert.True(File.Exists(backup));
        Assert.False(File.Exists(FilePath));
        store.Load();
        Assert.Empty(store.Connections);
    }

    [Fact]
    public void Load_FixesDuplicateIdsAndBadPorts()
    {
        Directory.CreateDirectory(_dir);
        var id = Guid.NewGuid();
        File.WriteAllText(FilePath, JsonSerializer.Serialize(new
        {
            version = 1,
            connections = new object[]
            {
                new { id, name = "a", host = "h", port = 0 },
                new { id, name = "b", host = "h2", port = 22 },
            },
        }));
        var store = new ConnectionStore(FilePath);
        store.Load();
        Assert.Equal(2, store.Connections.Count);
        Assert.NotEqual(store.Connections[0].Id, store.Connections[1].Id);
        Assert.Equal(22, store.Connections[0].Port);
    }

    [Fact]
    public void AllTags_DistinctAndSorted()
    {
        var store = new ConnectionStore(FilePath);
        store.Add(new Connection { Host = "a", Tags = new() { "Switches", "Core" } });
        store.Add(new Connection { Host = "b", Tags = new() { "servers", "switches" } });
        Assert.Equal(new[] { "Core", "servers", "Switches" }, store.AllTags());
    }

    [Fact]
    public void ParseTags_SplitsOnCommaAndSemicolon()
    {
        Assert.Equal(new[] { "a", "b c", "d" }, Connection.ParseTags(" a, b c ;d,, A "));
    }
}

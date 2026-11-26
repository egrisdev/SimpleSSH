using System.Text.Json.Serialization;

namespace SimpleSSH.Core.Models;

/// <summary>How a connection is opened.</summary>
public enum ConnectionProtocol
{
    Ssh,
    Rdp,
    /// <summary>A server management controller (HPE iLO, Dell iDRAC) opened straight into its remote console.</summary>
    Console,
    /// <summary>A web app (VMware vSphere or ESXi, Proxmox…) opened in a tab, signed in.</summary>
    Web,
}

/// <summary>
/// A saved connection (SSH, or Remote Desktop), persisted to connections.json.
/// </summary>
/// <remarks>
/// Password / PrivateKeyPassphrase / PrivateKey are plain text in memory only: <see cref="Storage.ConnectionStore"/> encrypts them
/// on disk (Windows DPAPI, current user).
/// They are only ever read through an <see cref="Credentials.ICredentialProvider"/>, so a
/// secure store (e.g. a vault API) can replace this later without touching the UI or SSH code.
/// </remarks>
public sealed class Connection
{
    public const int DefaultPort = 22;
    public const int RdpDefaultPort = 3389;
    public const int ConsoleDefaultPort = 443;
    public const int WebDefaultPort = 443;

    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>SSH (default, not written to the file) or Remote Desktop.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ConnectionProtocol Protocol { get; set; }

    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = DefaultPort;
    public string Username { get; set; } = "";

    /// <summary>Password (decrypted, in memory). Encrypted when saved.</summary>
    public string? Password { get; set; }

    /// <summary>Optional path to an OpenSSH/PEM/PuTTY private key file.</summary>
    public string? PrivateKeyPath { get; set; }

    /// <summary>Optional passphrase for <see cref="PrivateKeyPath"/> or <see cref="PrivateKey"/>.</summary>
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>
    /// A private key kept inside SimpleSSH (OpenSSH/PEM text; decrypted, in memory) instead of a file: made by
    /// "Switch to key login" or pasted in. Encrypted when saved. Takes precedence over <see cref="PrivateKeyPath"/>.
    /// </summary>
    public string? PrivateKey { get; set; }

    /// <summary>The public half of <see cref="PrivateKey"/> ("ssh-ed25519 AAAA… comment"), for display and copying.</summary>
    public string? PublicKey { get; set; }

    /// <summary>Optional proxy URL: socks5://host:1080, socks4://host:1080 or http://proxy:3128 (user:pass@ allowed; encrypted on disk).</summary>
    public string? Proxy { get; set; }

    /// <summary>Optional OpenSSH-style port forwards opened with the terminal: "L 8080:db:5432", "R 9000:localhost:22", "D 1080".</summary>
    public List<string>? Tunnels { get; set; }

    public List<string> Tags { get; set; } = new();

    public string? Notes { get; set; }

    /// <summary>Terminal: selecting text copies it (PuTTY style; right click then always pastes). On unless turned off.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CopyOnSelect { get; set; }

    [JsonIgnore]
    public bool CopiesOnSelect => CopyOnSelect != false;

    [JsonIgnore]
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Host : Name;

    [JsonIgnore]
    public bool IsRdp => Protocol == ConnectionProtocol.Rdp;

    [JsonIgnore]
    public bool IsConsole => Protocol == ConnectionProtocol.Console;

    [JsonIgnore]
    public bool IsWeb => Protocol == ConnectionProtocol.Web;

    /// <summary>Server consoles and web apps are web pages, so they can also open in the browser.</summary>
    [JsonIgnore]
    public bool IsWebPage => IsConsole || IsWeb;

    /// <summary>Terminal, files, run command, keys, tunnels: everything that needs an SSH login.</summary>
    [JsonIgnore]
    public bool IsSsh => Protocol == ConnectionProtocol.Ssh;

    [JsonIgnore]
    public string Endpoint => Port == DefaultPortFor(Protocol) ? Host : $"{Host}:{Port}";

    public static int DefaultPortFor(ConnectionProtocol protocol) => protocol switch
    {
        ConnectionProtocol.Rdp => RdpDefaultPort,
        ConnectionProtocol.Console => ConsoleDefaultPort,
        ConnectionProtocol.Web => WebDefaultPort,
        _ => DefaultPort,
    };

    public Connection Clone() => new()
    {
        Id = Id,
        Protocol = Protocol,
        Name = Name,
        Host = Host,
        Port = Port,
        Username = Username,
        Password = Password,
        PrivateKeyPath = PrivateKeyPath,
        PrivateKeyPassphrase = PrivateKeyPassphrase,
        PrivateKey = PrivateKey,
        PublicKey = PublicKey,
        Proxy = Proxy,
        Tunnels = Tunnels is null ? null : new List<string>(Tunnels),
        Tags = new List<string>(Tags),
        Notes = Notes,
        CopyOnSelect = CopyOnSelect,
    };

    /// <summary>Copies every field except <see cref="Id"/> from <paramref name="other"/>.</summary>
    public void CopyFrom(Connection other)
    {
        Protocol = other.Protocol;
        Name = other.Name;
        Host = other.Host;
        Port = other.Port;
        Username = other.Username;
        Password = other.Password;
        PrivateKeyPath = other.PrivateKeyPath;
        PrivateKeyPassphrase = other.PrivateKeyPassphrase;
        PrivateKey = other.PrivateKey;
        PublicKey = other.PublicKey;
        Proxy = other.Proxy;
        Tunnels = other.Tunnels is null ? null : new List<string>(other.Tunnels);
        Tags = new List<string>(other.Tags);
        Notes = other.Notes;
        CopyOnSelect = other.CopyOnSelect;
    }

    /// <summary>Trims, removes blanks and case-insensitive duplicates (first spelling wins).</summary>
    public static List<string> NormalizeTags(IEnumerable<string?>? tags)
    {
        var result = new List<string>();
        if (tags is null) return result;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in tags)
        {
            var t = raw?.Trim();
            if (string.IsNullOrEmpty(t)) continue;
            if (seen.Add(t)) result.Add(t);
        }
        return result;
    }

    /// <summary>Parses a comma/semicolon separated tag string.</summary>
    public static List<string> ParseTags(string? text) =>
        NormalizeTags((text ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries));

    public static string FormatTags(IEnumerable<string> tags) => string.Join(", ", tags);
}

using System.Text.Json;
using SimpleSSH.Core.Storage;

namespace SimpleSSH.Core.Ssh;

public enum HostKeyStatus
{
    Trusted,
    Unknown,
    Changed,

    /// <summary>The host is known, but with a key of another type: treat it like a changed key, not a new host.</summary>
    OtherTypeKnown,
}

/// <param name="KnownFingerprint">For Changed: the saved key of the same type. For OtherTypeKnown: a saved key of another type.</param>
/// <param name="KnownKeyType">The saved key's type.</param>
public sealed record HostKeyCheck(HostKeyStatus Status, string? KnownFingerprint, string? KnownKeyType = null);

/// <summary>
/// Trust-on-first-use store of server host keys (SHA256 fingerprints), keyed by host:port and key type.
/// </summary>
public sealed class KnownHostsStore
{
    public sealed class Entry
    {
        public string KeyType { get; set; } = "";
        public string Fingerprint { get; set; } = "";
        public DateTimeOffset Added { get; set; } = DateTimeOffset.Now;
    }

    private readonly object _gate = new();
    private Dictionary<string, List<Entry>> _hosts = new(StringComparer.OrdinalIgnoreCase);

    public KnownHostsStore(string filePath)
    {
        FilePath = filePath;
        Load();
    }

    public string FilePath { get; }

    public static string Key(string host, int port) => $"[{host.Trim().ToLowerInvariant()}]:{port}";

    /// <summary>rsa-sha2-256 / rsa-sha2-512 are signature algorithms over the same ssh-rsa key.</summary>
    public static string NormalizeKeyType(string keyType) =>
        keyType.StartsWith("rsa-sha2-", StringComparison.Ordinal) ? "ssh-rsa" : keyType;

    public HostKeyCheck Check(string host, int port, string keyType, string fingerprint)
    {
        keyType = NormalizeKeyType(keyType);
        lock (_gate)
        {
            if (!_hosts.TryGetValue(Key(host, port), out var entries))
                return new HostKeyCheck(HostKeyStatus.Unknown, null);

            var sameType = entries.FirstOrDefault(e => string.Equals(e.KeyType, keyType, StringComparison.Ordinal));
            if (sameType is null)
            {
                return entries.FirstOrDefault() is { } other
                    ? new HostKeyCheck(HostKeyStatus.OtherTypeKnown, other.Fingerprint, other.KeyType)
                    : new HostKeyCheck(HostKeyStatus.Unknown, null);
            }
            return string.Equals(sameType.Fingerprint, fingerprint, StringComparison.Ordinal)
                ? new HostKeyCheck(HostKeyStatus.Trusted, sameType.Fingerprint)
                : new HostKeyCheck(HostKeyStatus.Changed, sameType.Fingerprint);
        }
    }

    /// <summary>The key types saved for this host (ssh-rsa standing for its rsa-sha2-* signatures too).</summary>
    public IReadOnlyCollection<string> KnownKeyTypes(string host, int port)
    {
        lock (_gate)
        {
            return _hosts.TryGetValue(Key(host, port), out var entries)
                ? entries.Select(e => e.KeyType).ToArray()
                : Array.Empty<string>();
        }
    }

    public void Trust(string host, int port, string keyType, string fingerprint)
    {
        keyType = NormalizeKeyType(keyType);
        lock (_gate)
        {
            var key = Key(host, port);
            if (!_hosts.TryGetValue(key, out var entries))
            {
                entries = new List<Entry>();
                _hosts[key] = entries;
            }
            entries.RemoveAll(e => string.Equals(e.KeyType, keyType, StringComparison.Ordinal));
            entries.Add(new Entry { KeyType = keyType, Fingerprint = fingerprint, Added = DateTimeOffset.Now });
            JsonFile.Write(FilePath, _hosts);
        }
    }

    private void Load()
    {
        try
        {
            var loaded = JsonFile.Read<Dictionary<string, List<Entry>>>(FilePath);
            if (loaded is not null) _hosts = new Dictionary<string, List<Entry>>(loaded, StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            // A corrupt known-hosts file must not lock the user out; keep a copy and start fresh.
            try { File.Copy(FilePath, FilePath + ".corrupt", overwrite: true); } catch { /* ignore */ }
            _hosts = new Dictionary<string, List<Entry>>(StringComparer.OrdinalIgnoreCase);
        }
    }
}

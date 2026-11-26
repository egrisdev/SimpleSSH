using System.Text.Json;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Core.Storage;

public sealed class ConnectionStoreException : Exception
{
    public ConnectionStoreException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Loads/saves the list of connections from a JSON file.
/// </summary>
/// <remarks>
/// With an <see cref="ISecretProtector"/>, <see cref="Connection.Password"/> and
/// <see cref="Connection.PrivateKeyPassphrase"/> are encrypted on disk and plain text only in memory.
/// Plain-text secrets found in the file (old versions, hand edits) are encrypted on load.
/// Secrets that cannot be decrypted (another Windows user's file, lost profile keys) are left out of
/// memory but written back unchanged, so nothing is destroyed; setting a new password replaces them.
/// <para>
/// With a <see cref="SecurityKeyVault"/> (passwords locked with a security key) secrets are encrypted with the
/// vault's data key instead. While locked they stay out of memory the same way and come back on unlock.
/// A new secret can't be saved while locked (<see cref="Add"/> and <see cref="Update"/> refuse it; the app unlocks
/// first), so nothing ends up protected by DPAPI alone. Only a plain-text secret hand-edited into the file and
/// loaded while locked is written with DPAPI, and it moves into the vault at the next unlock.
/// </para>
/// </remarks>
public sealed class ConnectionStore
{
    public const int CurrentVersion = 1;

    private sealed class FileModel
    {
        public int Version { get; set; } = CurrentVersion;
        public SecurityKeyLock? SecurityKey { get; set; }
        public List<Connection> Connections { get; set; } = new();
    }

    private enum SecretField { Password, Passphrase, Proxy, PrivateKey }

    private readonly List<Connection> _connections = new();
    private readonly ISecretProtector? _protector;
    private readonly ISecretProtector? _keySlotProtector;
    /// <summary>Secrets held only in encrypted form: undecryptable, or locked in the vault.</summary>
    private readonly Dictionary<(Guid, SecretField), string> _sealed = new();

    /// <param name="protector">Encrypts secrets on disk. <c>null</c> stores them in plain text.</param>
    /// <param name="keySlotProtector">Protects security-key slots (DPAPI). Defaults to <paramref name="protector"/>.</param>
    public ConnectionStore(string filePath, ISecretProtector? protector = null, ISecretProtector? keySlotProtector = null)
    {
        FilePath = filePath;
        _protector = protector;
        _keySlotProtector = keySlotProtector ?? protector;
    }

    public string FilePath { get; }

    /// <summary>Set when saved passwords are protected with a security key.</summary>
    public SecurityKeyVault? Vault { get; private set; }

    /// <summary>True while a security key protects the passwords and they have not been unlocked.</summary>
    public bool IsLocked => Vault is { IsUnlocked: false };

    /// <summary>Raised after the passwords are locked or unlocked, or security-key protection changes.</summary>
    public event EventHandler? LockChanged;

    /// <summary>Number of saved secrets that could not be decrypted (not counting ones that are just locked).</summary>
    public int UnreadableSecretCount => _sealed.Values.Count(b => !IsLockedBlob(b));

    /// <summary>Number of plain-text secrets that the last <see cref="Load"/> encrypted.</summary>
    public int MigratedSecretCount { get; private set; }

    /// <summary>True if this connection has a saved password that could not be decrypted.</summary>
    public bool HasUnreadablePassword(Guid id) =>
        _sealed.TryGetValue((id, SecretField.Password), out var blob) && !IsLockedBlob(blob);

    /// <summary>True if this connection has a key kept in SimpleSSH that could not be decrypted.</summary>
    public bool HasUnreadablePrivateKey(Guid id) =>
        _sealed.TryGetValue((id, SecretField.PrivateKey), out var blob) && !IsLockedBlob(blob);

    /// <summary>True if this connection has a saved proxy (with a password) that could not be decrypted.</summary>
    public bool HasUnreadableProxy(Guid id) =>
        _sealed.TryGetValue((id, SecretField.Proxy), out var blob) && !IsLockedBlob(blob);

    /// <summary>True if this connection has saved secrets that need an unlock first.</summary>
    public bool HasLockedSecrets(Guid id) =>
        IsLocked && _sealed.Any(kv => kv.Key.Item1 == id && IsLockedBlob(kv.Value));

    /// <summary>
    /// True if saving <paramref name="c"/> would store a new secret while the security key is locked: unlock first.
    /// (While locked, saved secrets are out of memory, so any secret on the connection is a new one.)
    /// </summary>
    public bool NeedsUnlockToSave(Connection c) =>
        IsLocked && AllSecretFields.Any(field => GetSecret(c, field) is { Length: > 0 } value &&
                                                 (field != SecretField.Proxy || ProxySettings.HasPassword(value)));

    private void RefuseNewSecretsWhileLocked(Connection c)
    {
        if (NeedsUnlockToSave(c))
            throw new ConnectionStoreException("Unlock the saved passwords with your security key first, so the new password is protected by it.");
    }

    private bool IsLockedBlob(string blob) => Vault is { IsUnlocked: false } v && v.IsProtected(blob);

    public IReadOnlyList<Connection> Connections => _connections;

    /// <summary>Raised after any successful mutation + save.</summary>
    public event EventHandler? Changed;

    /// <summary>Loads the file. A missing file means "no connections yet".</summary>
    /// <exception cref="ConnectionStoreException">The file exists but cannot be parsed.</exception>
    public void Load()
    {
        FileModel? model;
        try
        {
            model = JsonFile.Read<FileModel>(FilePath);
        }
        catch (JsonException ex)
        {
            throw new ConnectionStoreException($"'{FilePath}' is not valid JSON: {ex.Message}", ex);
        }
        catch (IOException ex)
        {
            throw new ConnectionStoreException($"Could not read '{FilePath}': {ex.Message}", ex);
        }

        // Secrets on the replaced objects (open tabs may still hold them) must not outlive a lock.
        foreach (var old in _connections) ClearSecrets(old);
        _connections.Clear();
        _sealed.Clear();
        MigratedSecretCount = 0;

        var previousVault = Vault;
        Vault = model?.SecurityKey is { } header ? new SecurityKeyVault(header, _keySlotProtector) : null;
        if (previousVault is not null && Vault is not null) Vault.TryAdopt(previousVault);
        previousVault?.Lock();
        if (previousVault is not null || Vault is not null) LockChanged?.Invoke(this, EventArgs.Empty);
        if (model?.Connections is null) return;

        var ids = new HashSet<Guid>();
        foreach (var c in model.Connections)
        {
            if (c is null) continue;
            if (c.Id == Guid.Empty || !ids.Add(c.Id))
            {
                c.Id = Guid.NewGuid();
                ids.Add(c.Id);
            }
            c.Tags = Connection.NormalizeTags(c.Tags);
            if (c.Port is <= 0 or > 65535) c.Port = Connection.DefaultPort;
            c.Name ??= "";
            c.Host ??= "";
            c.Username ??= "";
            c.Password = ReadSecret(c.Id, SecretField.Password, c.Password);
            c.PrivateKeyPassphrase = ReadSecret(c.Id, SecretField.Passphrase, c.PrivateKeyPassphrase);
            c.Proxy = ReadSecret(c.Id, SecretField.Proxy, c.Proxy);
            c.PrivateKey = ReadSecret(c.Id, SecretField.PrivateKey, c.PrivateKey);
            NormalizeExtras(c);
            _connections.Add(c);
        }

        if (MigratedSecretCount > 0)
        {
            // Get plain text off the disk now rather than at the next edit.
            try { Save(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* retried on the next save */ }
        }
    }

    private string? ReadSecret(Guid id, SecretField field, string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        if (Vault is not null && Vault.IsProtected(stored))
        {
            if (Vault.TryUnprotect(stored, out var unlocked)) return unlocked;
            _sealed[(id, field)] = stored; // locked (or damaged)
            return null;
        }
        if (_protector is null) return stored;
        if (!_protector.IsProtected(stored))
        {
            // A proxy URL is only secret when it carries a password.
            if (field == SecretField.Proxy && !ProxySettings.HasPassword(stored)) return stored;
            MigratedSecretCount++;
            return stored;
        }
        if (_protector.TryUnprotect(stored, out var plaintext))
        {
            if (Vault is { IsUnlocked: true }) MigratedSecretCount++; // move it into the vault
            return plaintext;
        }
        _sealed[(id, field)] = stored;
        return null;
    }

    private string? WriteSecret(Guid id, SecretField field, string? plaintext)
    {
        if (!string.IsNullOrEmpty(plaintext))
        {
            _sealed.Remove((id, field)); // a new value replaces the undecryptable or locked one
            if (field == SecretField.Proxy && !ProxySettings.HasPassword(plaintext)) return plaintext;
            var protector = Vault is { IsUnlocked: true } ? Vault : _protector;
            return protector is null ? plaintext : protector.Protect(plaintext);
        }
        return _sealed.TryGetValue((id, field), out var blob) ? blob : null;
    }

    private static readonly SecretField[] AllSecretFields = { SecretField.Password, SecretField.Passphrase, SecretField.Proxy, SecretField.PrivateKey };

    private static string? GetSecret(Connection c, SecretField field) => field switch
    {
        SecretField.Password => c.Password,
        SecretField.Passphrase => c.PrivateKeyPassphrase,
        SecretField.PrivateKey => c.PrivateKey,
        _ => c.Proxy,
    };

    private static void SetSecret(Connection c, SecretField field, string? value)
    {
        switch (field)
        {
            case SecretField.Password: c.Password = value; break;
            case SecretField.Passphrase: c.PrivateKeyPassphrase = value; break;
            case SecretField.PrivateKey: c.PrivateKey = value; break;
            default: c.Proxy = value; break;
        }
    }

    private static void ClearSecrets(Connection c)
    {
        c.Password = null;
        c.PrivateKeyPassphrase = null;
        c.PrivateKey = null;
        if (c.Proxy is { } proxy && ProxySettings.HasPassword(proxy)) c.Proxy = null;
    }

    // =====================================================================================
    // Security key
    // =====================================================================================

    /// <summary>Protects all saved secrets with <paramref name="vault"/> (unlocked, from <see cref="SecurityKeyVault.Create"/>).</summary>
    public void EnableSecurityKey(SecurityKeyVault vault)
    {
        ArgumentNullException.ThrowIfNull(vault);
        if (!vault.IsUnlocked) throw new InvalidOperationException("The new vault must be unlocked.");
        if (IsLocked) throw new InvalidOperationException("Unlock the saved passwords first.");
        var previous = Vault;
        Vault = vault;
        try
        {
            Save();
        }
        catch
        {
            Vault = previous;
            throw;
        }
        if (previous != vault) previous?.Lock();
        LockChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Goes back to DPAPI-only protection. Requires the passwords to be unlocked.</summary>
    public void DisableSecurityKey()
    {
        if (Vault is not { } vault) return;
        if (IsLocked) throw new InvalidOperationException("Unlock the saved passwords first.");
        Vault = null;
        try
        {
            Save();
        }
        catch
        {
            Vault = vault;
            throw;
        }
        vault.Lock();
        LockChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Saves a change made to <see cref="Vault"/>'s keys or recovery key.</summary>
    public void SaveSecurityKeyChanges()
    {
        Save();
        LockChanged?.Invoke(this, EventArgs.Empty);
    }

    public KeyUnlockResult Unlock(byte[] credentialId, ReadOnlySpan<byte> hmacSecret)
    {
        if (Vault is not { IsUnlocked: false } vault) return KeyUnlockResult.Unlocked;
        var result = vault.Unlock(credentialId, hmacSecret);
        if (result == KeyUnlockResult.Unlocked) AfterUnlock(vault);
        return result;
    }

    public bool UnlockWithRecoveryKey(string recoveryKey)
    {
        if (Vault is not { } vault) return false;
        if (vault.IsUnlocked) return true;
        if (!vault.UnlockWithRecoveryKey(recoveryKey)) return false;
        AfterUnlock(vault);
        return true;
    }

    private void AfterUnlock(SecurityKeyVault vault)
    {
        foreach (var (key, blob) in _sealed.ToList())
        {
            if (!vault.IsProtected(blob) || !vault.TryUnprotect(blob, out var plaintext)) continue; // damaged: stays sealed
            _sealed.Remove(key);
            if (Find(key.Item1) is { } c) SetSecret(c, key.Item2, plaintext);
        }
        // Secrets still in DPAPI form (set while locked) move into the vault now.
        try { Save(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* retried on the next save */ }
        LockChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Forgets the data key and every decrypted secret. No-op without a security key.</summary>
    public void Lock()
    {
        if (Vault is not { IsUnlocked: true } vault) return;
        foreach (var c in _connections)
        {
            foreach (var field in AllSecretFields)
            {
                var value = GetSecret(c, field);
                if (string.IsNullOrEmpty(value)) continue;
                if (field == SecretField.Proxy && !ProxySettings.HasPassword(value)) continue;
                _sealed[(c.Id, field)] = vault.Protect(value);
                SetSecret(c, field, null);
            }
        }
        vault.Lock();
        LockChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Moves an unreadable file aside so the app can start with an empty list.</summary>
    public string QuarantineCorruptFile()
    {
        var backup = FilePath + $".corrupt-{DateTime.Now:yyyyMMdd-HHmmss}";
        File.Move(FilePath, backup);
        _connections.Clear();
        return backup;
    }

    public void Save()
    {
        var onDisk = _connections.Select(c =>
        {
            var copy = c.Clone();
            copy.Password = WriteSecret(c.Id, SecretField.Password, c.Password);
            copy.PrivateKeyPassphrase = WriteSecret(c.Id, SecretField.Passphrase, c.PrivateKeyPassphrase);
            copy.Proxy = WriteSecret(c.Id, SecretField.Proxy, c.Proxy);
            copy.PrivateKey = WriteSecret(c.Id, SecretField.PrivateKey, c.PrivateKey);
            return copy;
        }).ToList();
        JsonFile.Write(FilePath, new FileModel { Version = CurrentVersion, SecurityKey = Vault?.Header, Connections = onDisk });
    }

    public Connection? Find(Guid id) => _connections.FirstOrDefault(c => c.Id == id);

    public void Add(Connection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Validate(connection);
        RefuseNewSecretsWhileLocked(connection);
        if (connection.Id == Guid.Empty || Find(connection.Id) is not null) connection.Id = Guid.NewGuid();
        connection.Tags = Connection.NormalizeTags(connection.Tags);
        NormalizeExtras(connection);
        _connections.Add(connection);
        SaveAndNotify();
    }

    /// <summary>Copies the edited values into the stored instance with the same Id.</summary>
    public void Update(Connection edited)
    {
        ArgumentNullException.ThrowIfNull(edited);
        Validate(edited);
        RefuseNewSecretsWhileLocked(edited);
        var existing = Find(edited.Id) ?? throw new KeyNotFoundException($"Connection {edited.Id} not found.");
        existing.CopyFrom(edited);
        existing.Tags = Connection.NormalizeTags(existing.Tags);
        NormalizeExtras(existing);
        SaveAndNotify();
    }

    public bool Remove(Guid id)
    {
        var existing = Find(id);
        if (existing is null) return false;
        _connections.Remove(existing);
        foreach (var field in AllSecretFields) _sealed.Remove((id, field));
        SaveAndNotify();
        return true;
    }

    /// <summary>All distinct tags, naturally sorted.</summary>
    public IReadOnlyList<string> AllTags() =>
        _connections.SelectMany(c => c.Tags)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(t => t, NaturalStringComparer.Instance)
            .ToList();

    private static void NormalizeExtras(Connection c)
    {
        c.Proxy = string.IsNullOrWhiteSpace(c.Proxy) ? null : c.Proxy.Trim();
        var tunnels = c.Tunnels?.Select(t => t?.Trim() ?? "").Where(t => t.Length > 0).ToList();
        c.Tunnels = tunnels is { Count: > 0 } ? tunnels : null;
    }

    public static void Validate(Connection c)
    {
        if (string.IsNullOrWhiteSpace(c.Host)) throw new ArgumentException("Host is required.");
        if (c.Port is <= 0 or > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
    }

    private void SaveAndNotify()
    {
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
    }
}

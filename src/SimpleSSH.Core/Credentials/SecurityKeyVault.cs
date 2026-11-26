using System.Security.Cryptography;
using System.Text;

namespace SimpleSSH.Core.Credentials;

/// <summary>
/// Saved in connections.json (as <c>"securityKey"</c>) when passwords are locked with a FIDO2 security key.
/// Holds no secret in usable form: the data key is only stored encrypted, once per registered key and once
/// with the recovery key.
/// </summary>
public sealed class SecurityKeyLock
{
    public int Version { get; set; } = 1;

    /// <summary>WebAuthn relying party id the keys were registered for.</summary>
    public string RelyingParty { get; set; } = SecurityKeyVault.DefaultRelyingParty;

    /// <summary>hmac-secret salt (base64, 32 bytes). The same for every key; each key turns it into its own secret.</summary>
    public string Salt { get; set; } = "";

    /// <summary>A fixed value encrypted with the data key, to tell whether a data key belongs to this file.</summary>
    public string Check { get; set; } = "";

    public List<SecurityKeySlot> Keys { get; set; } = new();

    /// <summary>The data key, encrypted with the recovery key.</summary>
    public string Recovery { get; set; } = "";
}

/// <summary>One registered security key.</summary>
public sealed class SecurityKeySlot
{
    public string Name { get; set; } = "";

    /// <summary>WebAuthn credential id (base64).</summary>
    public string CredentialId { get; set; } = "";

    /// <summary>The data key, encrypted with this key's hmac-secret output and then with DPAPI.</summary>
    public string DataKey { get; set; } = "";

    public DateTimeOffset Added { get; set; }
}

public enum KeyUnlockResult
{
    Unlocked,
    /// <summary>The key is not registered here.</summary>
    UnknownKey,
    /// <summary>The key is registered, but under another Windows account or on another PC (DPAPI cannot open it).</summary>
    OtherWindowsAccount,
    /// <summary>The key's secret did not open the data key (another PIN state, damaged file).</summary>
    WrongSecret,
}

/// <summary>
/// Envelope encryption for saved secrets: a random 256-bit data key encrypts every password (AES-256-GCM),
/// and only lives in memory while unlocked. To unlock, a registered FIDO2 security key computes its
/// hmac-secret over <see cref="SecurityKeyLock.Salt"/> (a touch and the key's PIN); that output, plus this
/// Windows account (DPAPI), opens the data key. A recovery key (160 random bits, kept in a password manager)
/// opens it too, on any PC and without the security key.
/// </summary>
public sealed class SecurityKeyVault : ISecretProtector
{
    public const string Prefix = "sk:";
    public const string DefaultRelyingParty = "SimpleSSH";

    private const int DataKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int RecoveryKeyBytes = 20;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static readonly byte[] SecretAad = Encoding.ASCII.GetBytes("SimpleSSH/secret/v1");
    private static readonly byte[] SlotAad = Encoding.ASCII.GetBytes("SimpleSSH/security-key/v1");
    private static readonly byte[] RecoveryAad = Encoding.ASCII.GetBytes("SimpleSSH/recovery-key/v1");
    private static readonly byte[] CheckAad = Encoding.ASCII.GetBytes("SimpleSSH/check/v1");
    private static readonly byte[] CheckValue = Encoding.ASCII.GetBytes("SimpleSSH");

    private readonly ISecretProtector? _slotProtector;
    private byte[]? _dataKey;

    /// <param name="slotProtector">Second layer around each key slot (DPAPI). <c>null</c> only in tests.</param>
    public SecurityKeyVault(SecurityKeyLock header, ISecretProtector? slotProtector)
    {
        Header = header ?? throw new ArgumentNullException(nameof(header));
        _slotProtector = slotProtector;
    }

    public SecurityKeyLock Header { get; }

    public bool IsUnlocked => _dataKey is not null;

    public byte[] Salt => Convert.FromBase64String(Header.Salt);

    public string RelyingParty => string.IsNullOrWhiteSpace(Header.RelyingParty) ? DefaultRelyingParty : Header.RelyingParty;

    /// <summary>Credential ids of the keys this Windows account can use here.</summary>
    public IReadOnlyList<byte[]> UsableCredentialIds =>
        Header.Keys.Where(CanOpenHere).Select(k => Convert.FromBase64String(k.CredentialId)).ToList();

    /// <summary>Keys registered under another Windows account or PC. A recovery-key unlock can re-register them here.</summary>
    public IReadOnlyList<SecurityKeySlot> OtherAccountKeys => Header.Keys.Where(k => !CanOpenHere(k)).ToList();

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// A new, unlocked vault for a just-registered key. Nothing is saved until the caller hands it to the store.
    /// </summary>
    /// <param name="recoveryKey">Shown to the user once; never stored.</param>
    public static SecurityKeyVault Create(byte[] salt, byte[] credentialId, ReadOnlySpan<byte> hmacSecret, string keyName,
        ISecretProtector? slotProtector, out string recoveryKey)
    {
        var vault = new SecurityKeyVault(new SecurityKeyLock { Salt = Convert.ToBase64String(salt) }, slotProtector)
        {
            _dataKey = RandomNumberGenerator.GetBytes(DataKeySize),
        };
        vault.Header.Check = Convert.ToBase64String(Seal(vault._dataKey, CheckValue, CheckAad));
        vault.AddKey(credentialId, hmacSecret, keyName);
        recoveryKey = vault.ResetRecoveryKey();
        return vault;
    }

    public KeyUnlockResult Unlock(byte[] credentialId, ReadOnlySpan<byte> hmacSecret)
    {
        var slot = FindSlot(credentialId);
        if (slot is null) return KeyUnlockResult.UnknownKey;
        if (!TryOpenSlot(slot, out var sealedKey)) return KeyUnlockResult.OtherWindowsAccount;
        var kek = KeyFromSecret(hmacSecret, SlotAad);
        try
        {
            if (!TryOpen(kek, sealedKey, SlotAad, out var dataKey)) return KeyUnlockResult.WrongSecret;
            SetDataKey(dataKey);
            return KeyUnlockResult.Unlocked;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    public bool UnlockWithRecoveryKey(string recoveryKey)
    {
        if (!TryParseRecoveryKey(recoveryKey, out var raw)) return false;
        var kek = KeyFromSecret(raw, RecoveryAad);
        CryptographicOperations.ZeroMemory(raw);
        try
        {
            if (!TryDecode(Header.Recovery, out var blob) || !TryOpen(kek, blob, RecoveryAad, out var dataKey)) return false;
            SetDataKey(dataKey);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Takes over the data key of <paramref name="other"/> if it opens this file (reload from disk).</summary>
    public bool TryAdopt(SecurityKeyVault other)
    {
        if (other._dataKey is null || _dataKey is not null) return false;
        if (!TryDecode(Header.Check, out var check) || !TryOpen(other._dataKey, check, CheckAad, out var value)) return false;
        if (!value.AsSpan().SequenceEqual(CheckValue)) return false;
        _dataKey = (byte[])other._dataKey.Clone();
        return true;
    }

    /// <summary>Registers a key (or re-registers one for this Windows account). Requires the vault to be unlocked.</summary>
    public void AddKey(byte[] credentialId, ReadOnlySpan<byte> hmacSecret, string name)
    {
        var dataKey = RequireDataKey();
        var kek = KeyFromSecret(hmacSecret, SlotAad);
        try
        {
            var wrapped = Convert.ToBase64String(Seal(kek, dataKey, SlotAad));
            var slot = FindSlot(credentialId);
            if (slot is null)
            {
                slot = new SecurityKeySlot { CredentialId = Convert.ToBase64String(credentialId), Added = DateTimeOffset.Now };
                Header.Keys.Add(slot);
            }
            if (!string.IsNullOrWhiteSpace(name)) slot.Name = name.Trim();
            slot.DataKey = _slotProtector is null ? wrapped : _slotProtector.Protect(wrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Removes a key. The last key cannot be removed (turn the protection off instead).</summary>
    public bool RemoveKey(string credentialId)
    {
        if (Header.Keys.Count <= 1) return false;
        return Header.Keys.RemoveAll(k => k.CredentialId == credentialId) > 0;
    }

    /// <summary>
    /// A new vault with a new data key, for the given keys (each proven with its hmac-secret) and a new recovery key.
    /// Unlike <see cref="ResetRecoveryKey"/>, the old recovery key and any key left out can't open it, even with an old
    /// copy of the file. Its secrets still need encrypting again: hand it to <c>ConnectionStore.EnableSecurityKey</c>.
    /// Requires this vault to be unlocked.
    /// </summary>
    /// <exception cref="ArgumentException">No keys, or one that isn't registered here or doesn't open this vault.</exception>
    public SecurityKeyVault Rekey(IReadOnlyList<(byte[] CredentialId, byte[] HmacSecret)> keys, out string recoveryKey)
    {
        var current = RequireDataKey();
        if (keys.Count == 0) throw new ArgumentException("At least one security key is needed.", nameof(keys));
        var next = new SecurityKeyVault(new SecurityKeyLock { RelyingParty = Header.RelyingParty, Salt = Header.Salt }, _slotProtector)
        {
            _dataKey = RandomNumberGenerator.GetBytes(DataKeySize),
        };
        try
        {
            next.Header.Check = Convert.ToBase64String(Seal(next._dataKey, CheckValue, CheckAad));
            foreach (var (credentialId, secret) in keys)
            {
                var slot = FindSlot(credentialId) ?? throw new ArgumentException("That security key isn't registered here.", nameof(keys));
                if (!SlotOpensWith(slot, secret, current)) throw new ArgumentException($"\"{slot.Name}\" didn't unlock the saved passwords.", nameof(keys));
                next.AddKey(credentialId, secret, slot.Name);
                next.FindSlot(credentialId)!.Added = slot.Added;
            }
            recoveryKey = next.ResetRecoveryKey();
            return next;
        }
        catch
        {
            next.Lock();
            throw;
        }
    }

    private bool SlotOpensWith(SecurityKeySlot slot, ReadOnlySpan<byte> hmacSecret, byte[] dataKey)
    {
        if (!TryOpenSlot(slot, out var sealedKey)) return false;
        var kek = KeyFromSecret(hmacSecret, SlotAad);
        try
        {
            if (!TryOpen(kek, sealedKey, SlotAad, out var opened)) return false;
            var same = CryptographicOperations.FixedTimeEquals(opened, dataKey);
            CryptographicOperations.ZeroMemory(opened);
            return same;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Wraps the current data key for a new recovery key. The previous recovery key stops working on this file, but
    /// still opens older copies of it: to retire it completely use <see cref="Rekey"/>. Requires the vault to be unlocked.
    /// </summary>
    public string ResetRecoveryKey()
    {
        var dataKey = RequireDataKey();
        var raw = RandomNumberGenerator.GetBytes(RecoveryKeyBytes);
        var kek = KeyFromSecret(raw, RecoveryAad);
        try
        {
            Header.Recovery = Convert.ToBase64String(Seal(kek, dataKey, RecoveryAad));
            return FormatRecoveryKey(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Forgets the data key. Secrets already decrypted elsewhere are the caller's to clear.</summary>
    public void Lock()
    {
        if (_dataKey is null) return;
        CryptographicOperations.ZeroMemory(_dataKey);
        _dataKey = null;
    }

    // ---- ISecretProtector ----------------------------------------------------------------

    public bool IsProtected(string stored) => stored.StartsWith(Prefix, StringComparison.Ordinal);

    /// <exception cref="InvalidOperationException">The vault is locked.</exception>
    public string Protect(string plaintext)
    {
        var dataKey = RequireDataKey();
        var data = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            return Prefix + Convert.ToBase64String(Seal(dataKey, data, SecretAad));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public bool TryUnprotect(string stored, out string plaintext)
    {
        plaintext = "";
        if (_dataKey is null || !IsProtected(stored) || !TryDecode(stored[Prefix.Length..], out var blob)) return false;
        if (!TryOpen(_dataKey, blob, SecretAad, out var data)) return false;
        plaintext = Encoding.UTF8.GetString(data);
        CryptographicOperations.ZeroMemory(data);
        return true;
    }

    // ---- Recovery key text -----------------------------------------------------------------

    /// <summary>32 base32 characters in groups of four, e.g. <c>K7QM-…-3XWA</c>.</summary>
    public static string FormatRecoveryKey(ReadOnlySpan<byte> raw)
    {
        var chars = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in raw)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                chars.Append(Base32Alphabet[(buffer >> bits) & 31]);
            }
        }
        if (bits > 0) chars.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        var text = chars.ToString();
        return string.Join("-", Enumerable.Range(0, (text.Length + 3) / 4).Select(i => text.Substring(i * 4, Math.Min(4, text.Length - i * 4))));
    }

    /// <summary>Accepts any case, spaces and dashes, and the look-alikes 0/1/8 for O/I/B.</summary>
    public static bool TryParseRecoveryKey(string? text, out byte[] raw)
    {
        raw = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(text)) return false;
        var bytes = new List<byte>(RecoveryKeyBytes);
        int buffer = 0, bits = 0, count = 0;
        foreach (var ch in text.ToUpperInvariant())
        {
            if (ch is '-' or ' ' or '\t' or '\r' or '\n') continue;
            var c = ch switch { '0' => 'O', '1' => 'I', '8' => 'B', _ => ch };
            var value = Base32Alphabet.IndexOf(c);
            if (value < 0) return false;
            count++;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)(buffer >> bits));
            }
        }
        if (count != (RecoveryKeyBytes * 8 + 4) / 5 || bytes.Count != RecoveryKeyBytes) return false;
        raw = bytes.ToArray();
        return true;
    }

    // ---- Helpers ---------------------------------------------------------------------------

    private SecurityKeySlot? FindSlot(byte[] credentialId)
    {
        var id = Convert.ToBase64String(credentialId);
        return Header.Keys.FirstOrDefault(k => k.CredentialId == id);
    }

    private bool CanOpenHere(SecurityKeySlot slot) => TryOpenSlot(slot, out _);

    private bool TryOpenSlot(SecurityKeySlot slot, out byte[] sealedKey)
    {
        sealedKey = Array.Empty<byte>();
        var text = slot.DataKey;
        if (_slotProtector is not null)
        {
            if (!_slotProtector.TryUnprotect(text, out var inner)) return false;
            text = inner;
        }
        return TryDecode(text, out sealedKey);
    }

    private byte[] RequireDataKey() => _dataKey ?? throw new InvalidOperationException("Saved passwords are locked.");

    private void SetDataKey(byte[] dataKey)
    {
        Lock();
        _dataKey = dataKey;
    }

    private static byte[] KeyFromSecret(ReadOnlySpan<byte> secret, byte[] purpose)
    {
        if (secret.Length < 16) throw new ArgumentException("Secret is too short.", nameof(secret));
        var key = new byte[DataKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, key, ReadOnlySpan<byte>.Empty, purpose);
        return key;
    }

    private static byte[] Seal(byte[] key, ReadOnlySpan<byte> plaintext, byte[] aad)
    {
        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(NonceSize, plaintext.Length), output.AsSpan(NonceSize + plaintext.Length), aad);
        return output;
    }

    private static bool TryOpen(byte[] key, byte[] blob, byte[] aad, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();
        if (blob.Length < NonceSize + TagSize) return false;
        var data = new byte[blob.Length - NonceSize - TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize, data.Length), blob.AsSpan(NonceSize + data.Length), data, aad);
            plaintext = data;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryDecode(string? base64, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrEmpty(base64)) return false;
        try
        {
            bytes = Convert.FromBase64String(base64);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

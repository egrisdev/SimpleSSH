using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SimpleSSH.Core.Credentials;

/// <summary>Encrypts secrets (passwords, key passphrases) before they are written to disk.</summary>
public interface ISecretProtector
{
    /// <summary>True if <paramref name="stored"/> is an encrypted value produced by <see cref="Protect"/>.</summary>
    bool IsProtected(string stored);

    /// <summary>Returns the encrypted, self-describing form of <paramref name="plaintext"/> (safe to store in JSON).</summary>
    string Protect(string plaintext);

    /// <summary>Decrypts a value from <see cref="Protect"/>. Returns false if it cannot be decrypted here (other user, lost keys, tampered).</summary>
    bool TryUnprotect(string stored, out string plaintext);
}

/// <summary>
/// Windows DPAPI, current-user scope. The key is derived from the signed-in Windows account, so there is
/// no master password, and only that user (on any machine their profile/keys roam to) can decrypt.
/// Works for local, Active Directory, hybrid and Entra ID (Azure AD) accounts.
/// </summary>
/// <remarks>
/// Stored format: <c>dpapi:</c> + base64(DPAPI blob). The fixed entropy ties blobs to this app, so other
/// programs calling DPAPI for the same user cannot decrypt them just by passing the blob back.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    public const string Prefix = "dpapi:";

    private readonly byte[] _entropy;

    public DpapiSecretProtector() : this("SimpleSSH/connections/v1") { }

    /// <summary>Custom entropy (tests use this to simulate "encrypted by someone else").</summary>
    public DpapiSecretProtector(string entropy) => _entropy = Encoding.UTF8.GetBytes(entropy);

    public bool IsProtected(string stored) => stored.StartsWith(Prefix, StringComparison.Ordinal);

    public string Protect(string plaintext)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            return Prefix + Convert.ToBase64String(ProtectedData.Protect(data, _entropy, DataProtectionScope.CurrentUser));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public bool TryUnprotect(string stored, out string plaintext)
    {
        plaintext = "";
        if (!IsProtected(stored)) return false;
        try
        {
            var blob = Convert.FromBase64String(stored[Prefix.Length..]);
            var data = ProtectedData.Unprotect(blob, _entropy, DataProtectionScope.CurrentUser);
            plaintext = Encoding.UTF8.GetString(data);
            CryptographicOperations.ZeroMemory(data);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }
    }
}

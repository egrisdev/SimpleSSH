using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Renci.SshNet;

namespace SimpleSSH.Core.Ssh;

/// <summary>A key pair: OpenSSH private key text (unencrypted; SimpleSSH encrypts it at rest) and its public line.</summary>
public sealed record SshKeyPair(string PrivateKey, string PublicKey);

/// <summary>Creates and inspects SSH keys kept inside SimpleSSH.</summary>
public static class SshKeys
{
    /// <summary>A new Ed25519 key in OpenSSH format, as made by <c>ssh-keygen -t ed25519</c>.</summary>
    public static SshKeyPair CreateEd25519(string comment)
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();

        var blob = OpenSshPrivateKeyUtilities.EncodePrivateKey(pair.Private);
        try
        {
            var publicBlob = OpenSshPublicKeyUtilities.EncodePublicKey(pair.Public);
            return new SshKeyPair(ToPem(blob), PublicLine(publicBlob, comment));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    /// <summary>
    /// Checks pasted or saved private key text and returns its public line, or an error a person can act on.
    /// Works for OpenSSH, PEM (RSA/ECDSA/PKCS#8) and PuTTY keys that SSH.NET can load.
    /// </summary>
    public static bool TryGetPublicKey(string? privateKeyText, string? passphrase, string comment, out string publicKey, out string error)
    {
        publicKey = "";
        error = "";
        var text = privateKeyText?.Trim() ?? "";
        if (text.Length == 0)
        {
            error = "Paste the private key, including the BEGIN and END lines.";
            return false;
        }
        if (text.StartsWith("ssh-", StringComparison.Ordinal) || text.StartsWith("ecdsa-", StringComparison.Ordinal))
        {
            error = "That is a public key (one line starting with ssh-…). SimpleSSH needs the private key: the file without .pub.";
            return false;
        }
        if (!text.Contains("PRIVATE KEY", StringComparison.Ordinal) && !text.StartsWith("PuTTY-User-Key-File", StringComparison.Ordinal))
        {
            error = "This doesn't look like a private key. It should start with -----BEGIN … PRIVATE KEY-----.";
            return false;
        }
        try
        {
            using var key = SshConnector.LoadKeyText(text, passphrase);
            var data = key.HostKeyAlgorithms.First().Data;
            publicKey = PublicLine(data, comment);
            return true;
        }
        catch (SshSessionException ex)
        {
            error = ex.Message.Contains("encrypted", StringComparison.OrdinalIgnoreCase) || ex.InnerException is Renci.SshNet.Common.SshPassPhraseNullOrEmptyException
                ? "This key has a passphrase. Enter it below."
                : string.IsNullOrEmpty(passphrase) ? ex.Message : "The passphrase is wrong, or the key is damaged.";
            return false;
        }
    }

    /// <summary>"ssh-ed25519 AAAA… comment" from an SSH wire-format public key blob.</summary>
    public static string PublicLine(byte[] publicBlob, string comment)
    {
        var type = ReadSshString(publicBlob);
        var line = type + " " + Convert.ToBase64String(publicBlob);
        var c = (comment ?? "").Replace('\r', ' ').Replace('\n', ' ').Replace('\'', ' ').Trim();
        return c.Length > 0 ? line + " " + c : line;
    }

    /// <summary>Key type and SHA256 fingerprint, as <c>ssh-keygen -l</c> shows them (e.g. "ED25519 SHA256:abc…").</summary>
    public static string Fingerprint(string publicKeyLine)
    {
        var parts = publicKeyLine.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return "";
        try
        {
            var hash = SHA256.HashData(Convert.FromBase64String(parts[1]));
            var kind = parts[0] switch
            {
                "ssh-ed25519" => "ED25519",
                "ssh-rsa" => "RSA",
                var t when t.StartsWith("ecdsa-", StringComparison.Ordinal) => "ECDSA",
                var t => t,
            };
            return $"{kind} SHA256:{Convert.ToBase64String(hash).TrimEnd('=')}";
        }
        catch (FormatException)
        {
            return "";
        }
    }

    private static string ReadSshString(byte[] blob)
    {
        if (blob.Length < 4) throw new ArgumentException("Not an SSH public key.");
        int len = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
        if (len <= 0 || len > blob.Length - 4) throw new ArgumentException("Not an SSH public key.");
        return Encoding.ASCII.GetString(blob, 4, len);
    }

    private static string ToPem(byte[] blob)
    {
        var b64 = Convert.ToBase64String(blob);
        var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (int i = 0; i < b64.Length; i += 70) sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
        return sb.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
    }
}

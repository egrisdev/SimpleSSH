using SimpleSSH.Core.Models;

namespace SimpleSSH.Core.Credentials;

/// <summary>The credentials actually used to authenticate a session.</summary>
public sealed record ResolvedCredential(
    string Username,
    string? Password,
    string? PrivateKeyPath,
    string? PrivateKeyPassphrase,
    string? PrivateKeyText = null)
{
    public bool HasSecret => !string.IsNullOrEmpty(Password) || HasKey;

    public bool HasKey => !string.IsNullOrEmpty(PrivateKeyText) || !string.IsNullOrEmpty(PrivateKeyPath);
}

/// <summary>
/// Seam for credential storage. Today: <see cref="StoredCredentialProvider"/> reads the plain-text
/// values saved in connections.json. Later: a provider that pulls secrets from a vault/API.
/// </summary>
public interface ICredentialProvider
{
    Task<ResolvedCredential> ResolveAsync(Connection connection, CancellationToken cancellationToken = default);
}

/// <summary>Returns the credentials stored directly on the connection (plain text JSON).</summary>
public sealed class StoredCredentialProvider : ICredentialProvider
{
    public Task<ResolvedCredential> ResolveAsync(Connection connection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        return Task.FromResult(new ResolvedCredential(
            connection.Username ?? "",
            string.IsNullOrEmpty(connection.Password) ? null : connection.Password,
            string.IsNullOrWhiteSpace(connection.PrivateKeyPath) || !string.IsNullOrEmpty(connection.PrivateKey)
                ? null : Environment.ExpandEnvironmentVariables(connection.PrivateKeyPath.Trim()),
            string.IsNullOrEmpty(connection.PrivateKeyPassphrase) ? null : connection.PrivateKeyPassphrase,
            string.IsNullOrEmpty(connection.PrivateKey) ? null : connection.PrivateKey));
    }
}

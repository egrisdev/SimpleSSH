using System.Windows;
using SimpleSSH.Core.Credentials;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;
using SimpleSSH.Views;

namespace SimpleSSH.Services;

/// <summary>
/// Everything needed to log in to one connection from one tab or window: saved or prompted credentials,
/// MFA prompts, proxy, tunnels, host keys, and the "remember this password" follow-up.
/// </summary>
internal sealed class SessionLogin
{
    private (string User, string Password, bool Remember)? _prompted;
    private bool _neededUser;
    private bool _neededSecret;

    public SessionLogin(Connection connection) => Connection = connection;

    public Connection Connection { get; }

    /// <summary>
    /// The store's current copy of the connection: after a reload or an unlock the tab's object may be stale
    /// (its secrets are cleared when passwords lock).
    /// </summary>
    private Connection Current => AppServices.Connections.Find(Connection.Id) ?? Connection;

    public HostKeyPromptState HostKeys { get; } = new();

    /// <summary>
    /// Builds connect options, asking for a username/password first if none is saved.
    /// Returns null if the user cancelled. Must be called on the UI thread.
    /// </summary>
    /// <exception cref="SshSessionException">Bad proxy/tunnel settings or the credential source failed.</exception>
    public async Task<SshConnectOptions?> PrepareAsync(Window? owner, bool includeTunnels)
    {
        if (await ResolveCredentialAsync(owner) is not { } credential) return null;
        var c = Current;

        if (AppServices.Connections.HasUnreadablePrivateKey(c.Id))
            throw new SshSessionException("The saved private key could not be decrypted for this Windows user. Edit the connection and paste the key again, or use Switch to key login.");
        if (AppServices.Connections.HasUnreadableProxy(c.Id))
            throw new SshSessionException("The saved proxy password could not be decrypted for this Windows user. Edit the connection and enter the proxy again.");

        ProxySettings? proxy = null;
        if (!string.IsNullOrWhiteSpace(c.Proxy) && !ProxySettings.TryParse(c.Proxy, out proxy, out var proxyError))
            throw new SshSessionException(proxyError + " (Edit the connection to fix it.)");

        var tunnels = new List<TunnelSpec>();
        if (includeTunnels && !TunnelSpec.TryParseAll(c.Tunnels, out tunnels, out var tunnelError))
            throw new SshSessionException("Tunnel " + tunnelError + " (Edit the connection to fix it.)");

        return new SshConnectOptions
        {
            Host = c.Host,
            Port = c.Port,
            Credential = credential,
            Proxy = proxy,
            Tunnels = tunnels,
            Prompt = AuthPromptUi.CreateHandler(c),
        };
    }

    /// <summary>
    /// The saved credential, or one asked for now if the username or password is missing (a key file counts as a
    /// secret for SSH, not for Remote Desktop). Returns null if the user cancelled. Must be called on the UI thread.
    /// </summary>
    public async Task<ResolvedCredential?> ResolveCredentialAsync(Window? owner)
    {
        if (AppServices.Connections.HasLockedSecrets(Connection.Id) &&
            !await SecurityKeyUi.EnsureUnlockedAsync(owner, $"Unlock to connect to {Connection.DisplayName}."))
            return null;

        var c = Current;
        ResolvedCredential credential;
        try
        {
            credential = await AppServices.Credentials.ResolveAsync(c);
        }
        catch (Exception ex)
        {
            throw new SshSessionException($"Could not get credentials: {ex.Message}", ex);
        }

        _neededUser = string.IsNullOrWhiteSpace(credential.Username);
        _neededSecret = c.IsSsh ? !credential.HasSecret : string.IsNullOrEmpty(credential.Password);
        if (_neededUser || _neededSecret)
        {
            if (_prompted is null)
            {
                bool unreadable = AppServices.Connections.HasUnreadablePassword(c.Id);
                var dlg = new CredentialPromptDialog(c, credential.Username, passwordOptional: !_neededSecret,
                    reason: unreadable ? "The saved password could not be decrypted for this Windows user. Enter it again." : null,
                    rememberByDefault: unreadable)
                {
                    Owner = owner,
                };
                if (dlg.ShowDialog() != true) return null;
                _prompted = (dlg.Username, dlg.Password, dlg.Remember);
            }

            var p = _prompted.Value;
            credential = credential with
            {
                Username = _neededUser ? p.User : credential.Username,
                Password = _neededSecret ? p.Password : credential.Password,
            };
        }

        return credential;
    }

    /// <summary>Call after a successful login made without <see cref="ConnectAsync{T}"/> (Remote Desktop).</summary>
    public void MarkSucceeded() => OnSucceeded();

    /// <summary>Call after a failed login: a password typed into the prompt is asked for again next time.</summary>
    public void ForgetPrompted() => _prompted = null;

    /// <summary>
    /// Runs <paramref name="connect"/>; if the user had to accept a host key and the server gave up waiting
    /// meanwhile, tries once more (the key is trusted by then). Only a failed login is retried: once logged in,
    /// a command may already have run, and running it again could do harm.
    /// </summary>
    public async Task<T> ConnectAsync<T>(SshConnectOptions options, Func<IHostKeyVerifier, Task<T>> connect, Action<string>? notice = null)
    {
        for (int attempt = 1; ; attempt++)
        {
            HostKeys.LastPromptDecision = null;
            try
            {
                var result = await connect(HostKeyPrompt.CreateVerifier(HostKeys));
                OnSucceeded();
                return result;
            }
            catch (OperationCanceledException) { throw; }
            catch (SftpUnavailableException) { throw; } // logged in fine; nothing to retry
            catch (Exception ex)
            {
                if (attempt == 1 && HostKeys.LastPromptDecision is HostKeyDecision.AcceptAndSave or HostKeyDecision.AcceptOnce
                    && SshSessionException.FailedDuringLogin(ex) && !SshConnector.IsAuthenticationFailure(ex))
                {
                    notice?.Invoke("Host key accepted – connecting again…");
                    continue;
                }
                if (SshConnector.IsAuthenticationFailure(ex)) _prompted = null; // ask again next time
                throw;
            }
        }
    }

    /// <summary>Saves a prompted username/password (encrypted) once it has been proven to work.</summary>
    private void OnSucceeded()
    {
        if (_prompted is not { Remember: true } p) return;
        _prompted = p with { Remember = false }; // once is enough
        bool saveUser = _neededUser, savePassword = _neededSecret;
        // The unlock prompt needs the UI thread.
        Application.Current?.Dispatcher.InvokeAsync(() => SaveRememberedAsync(p.User, p.Password, saveUser, savePassword));
    }

    private async Task SaveRememberedAsync(string user, string password, bool saveUser, bool savePassword)
    {
        try
        {
            var store = AppServices.Connections;
            if (store.Find(Connection.Id) is null) return; // deleted meanwhile
            var edited = Current.Clone();
            if (saveUser) edited.Username = user;
            if (savePassword && !string.IsNullOrEmpty(password)) edited.Password = password;
            // With the security key locked, unlock first so it protects the password too (not just Windows).
            if (store.NeedsUnlockToSave(edited) &&
                !await SecurityKeyUi.EnsureUnlockedAsync(null, $"Unlock to save the password for {Connection.DisplayName}."))
            {
                Log.Info($"Password for {Connection.Endpoint} not saved: the security key stayed locked.");
                return;
            }
            edited = Current.Clone(); // unlocking reloads the saved secrets into the store's copy
            if (saveUser) edited.Username = user;
            if (savePassword && !string.IsNullOrEmpty(password)) edited.Password = password;
            store.Update(edited);
        }
        catch (Exception ex)
        {
            Log.Error("Could not save the remembered credential", ex);
        }
    }
}

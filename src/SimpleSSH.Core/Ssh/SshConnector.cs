using System.Net.Sockets;
using Renci.SshNet;
using Renci.SshNet.Common;
using SimpleSSH.Core.Credentials;

namespace SimpleSSH.Core.Ssh;

public sealed record HostKeyInfo(string Host, int Port, string KeyType, string FingerprintSha256, int KeyLength);

/// <summary>Decides whether a server host key is acceptable. Invoked on a background thread.</summary>
public interface IHostKeyVerifier
{
    bool Verify(HostKeyInfo hostKey);

    /// <summary>Key types already trusted for this host: offered to the server first, so it keeps using one of them.</summary>
    IReadOnlyCollection<string> KnownKeyTypes(string host, int port) => Array.Empty<string>();
}

/// <summary>Accepts every key. Only for tests.</summary>
public sealed class AcceptAnyHostKeyVerifier : IHostKeyVerifier
{
    public bool Verify(HostKeyInfo hostKey) => true;
}

/// <summary>One question from the server during keyboard-interactive login (e.g. "Verification code:").</summary>
public sealed record AuthPromptField(string Label, bool Echo);

public sealed record AuthPromptRequest(string Endpoint, string Username, string? Instruction, IReadOnlyList<AuthPromptField> Fields);

/// <summary>Asks the user to answer login prompts the app can't answer itself (one-time codes, extra factors).
/// Return one answer per field, or null to cancel. Called on a background thread.</summary>
public delegate IReadOnlyList<string>? AuthPromptHandler(AuthPromptRequest request);

public sealed class SshConnectOptions
{
    public required string Host { get; init; }
    public int Port { get; init; } = 22;
    public required ResolvedCredential Credential { get; init; }
    public string TerminalType { get; init; } = "xterm-256color";
    /// <summary>
    /// SSH.NET uses this for every wait during login, including while the user answers a host-key or MFA prompt
    /// (or approves a push notification), so it is generous. Unreachable hosts still fail at the OS TCP timeout (~21 s).
    /// </summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(90);
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional SOCKS4/SOCKS5/HTTP proxy to reach the server through.</summary>
    public ProxySettings? Proxy { get; init; }

    /// <summary>Port forwards opened with an interactive terminal session.</summary>
    public IReadOnlyList<TunnelSpec> Tunnels { get; init; } = Array.Empty<TunnelSpec>();

    /// <summary>Answers extra login prompts (MFA). Without it such prompts get an empty answer.</summary>
    public AuthPromptHandler? Prompt { get; init; }

    public string Endpoint => Port == 22 ? Host : $"{Host}:{Port}";
}

public sealed class SshSessionException : Exception
{
    public SshSessionException(string message, Exception? inner = null) : base(message, inner) { }

    /// <summary>Set when connecting or logging in failed, so nothing can have run on the server yet.</summary>
    public bool DuringLogin { get; internal set; }

    /// <summary>True if <paramref name="ex"/> (or one it wraps) failed while connecting or logging in.</summary>
    public static bool FailedDuringLogin(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
        {
            if (ex is SshSessionException { DuringLogin: true }) return true;
        }
        return false;
    }
}

/// <summary>A connected SSH.NET client plus everything it owns (key files, auth methods).</summary>
public sealed class SshConnection<T> : IDisposable where T : BaseClient
{
    private readonly List<IDisposable> _owned;
    private int _disposed;

    internal SshConnection(T client, List<IDisposable> owned)
    {
        Client = client;
        _owned = owned;
    }

    public T Client { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        SshConnector.DisposeQuietly(Client, _owned);
    }
}

/// <summary>Builds and connects SSH.NET clients the same way for terminals, file transfer and commands.</summary>
public static class SshConnector
{
    /// <summary>Connects a client created by <paramref name="create"/>. Errors become <see cref="SshSessionException"/> with a readable message.</summary>
    /// <param name="configure">Hook to attach events before connecting.</param>
    public static async Task<SshConnection<T>> ConnectAsync<T>(
        SshConnectOptions options,
        IHostKeyVerifier verifier,
        Func<ConnectionInfo, T> create,
        Action<T>? configure = null,
        CancellationToken cancellationToken = default) where T : BaseClient
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(verifier);

        var owned = new List<IDisposable>();
        var state = new LoginState();
        T? client = null;
        try
        {
            var info = BuildConnectionInfo(options, owned, state);
            PreferKnownHostKeyTypes(info, verifier.KnownKeyTypes(options.Host.Trim(), options.Port));
            client = create(info);
            client.KeepAliveInterval = options.KeepAliveInterval;
            client.HostKeyReceived += (_, e) =>
            {
                bool ok;
                try
                {
                    ok = verifier.Verify(new HostKeyInfo(options.Host.Trim(), options.Port, e.HostKeyName, e.FingerPrintSHA256, e.KeyLength));
                }
                catch
                {
                    ok = false;
                }
                state.HostKeyRejected = !ok;
                e.CanTrust = ok;
            };
            configure?.Invoke(client);

            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new SshConnection<T>(client, owned);
        }
        catch (Exception ex)
        {
            DisposeQuietly(client, owned);
            if (ex is SshSessionException session)
            {
                session.DuringLogin = true;
                throw;
            }
            var message = state.HostKeyRejected ? "The server's host key was not trusted. Connection aborted."
                : state.PromptCancelled ? "Login cancelled."
                : DescribeError(ex);
            throw new SshSessionException(message, ex) { DuringLogin = true };
        }
    }

    private sealed class LoginState
    {
        public volatile bool HostKeyRejected;
        public volatile bool PromptCancelled;
    }

    private static ConnectionInfo BuildConnectionInfo(SshConnectOptions options, List<IDisposable> owned, LoginState state)
    {
        var methods = BuildAuthenticationMethods(options, owned, state).ToArray();
        var host = options.Host.Trim();
        var user = options.Credential.Username;
        var info = options.Proxy is { } p
            ? new ConnectionInfo(host, options.Port, user,
                p.Kind switch { ProxyKind.Socks4 => ProxyTypes.Socks4, ProxyKind.Socks5 => ProxyTypes.Socks5, _ => ProxyTypes.Http },
                p.Host, p.Port, p.Username ?? "", p.Password ?? "", methods)
            : new ConnectionInfo(host, options.Port, user, methods);
        info.Timeout = options.ConnectTimeout;
        return info;
    }

    /// <summary>
    /// Moves the host key types already trusted for this host to the front (as OpenSSH does), so the server keeps
    /// presenting the saved key instead of one of another type, which would need asking about again.
    /// </summary>
    internal static void PreferKnownHostKeyTypes(ConnectionInfo info, IReadOnlyCollection<string> knownTypes)
    {
        if (knownTypes.Count == 0) return;
        var algorithms = info.HostKeyAlgorithms;
        var preferred = algorithms.Keys.Where(name => knownTypes.Contains(KnownHostsStore.NormalizeKeyType(name))).ToList();
        for (int i = 0; i < preferred.Count; i++)
        {
            if (algorithms.Remove(preferred[i], out var factory)) algorithms.Insert(i, preferred[i], factory);
        }
    }

    /// <summary>Loads a key kept in SimpleSSH (OpenSSH/PEM/PuTTY text).</summary>
    internal static PrivateKeyFile LoadKeyText(string text, string? passphrase, List<IDisposable>? owned = null)
    {
        try
        {
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n").Trim() + "\n"));
            var key = string.IsNullOrEmpty(passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, passphrase);
            owned?.Add(key);
            return key;
        }
        catch (SshPassPhraseNullOrEmptyException)
        {
            throw new SshSessionException("The saved private key is encrypted. Enter its passphrase in the connection settings.");
        }
        catch (Exception ex)
        {
            throw new SshSessionException($"Could not load the saved private key: {ex.Message}", ex);
        }
    }

    private static List<AuthenticationMethod> BuildAuthenticationMethods(SshConnectOptions options, List<IDisposable> owned, LoginState state)
    {
        var cred = options.Credential;
        var user = cred.Username;
        var methods = new List<AuthenticationMethod>();

        if (!string.IsNullOrEmpty(cred.PrivateKeyText))
        {
            methods.Add(new PrivateKeyAuthenticationMethod(user, LoadKeyText(cred.PrivateKeyText, cred.PrivateKeyPassphrase, owned)));
        }
        else if (!string.IsNullOrWhiteSpace(cred.PrivateKeyPath))
        {
            var path = Environment.ExpandEnvironmentVariables(cred.PrivateKeyPath.Trim().Trim('"'));
            PrivateKeyFile keyFile;
            try
            {
                keyFile = string.IsNullOrEmpty(cred.PrivateKeyPassphrase)
                    ? new PrivateKeyFile(path)
                    : new PrivateKeyFile(path, cred.PrivateKeyPassphrase);
            }
            catch (FileNotFoundException)
            {
                throw new SshSessionException($"Private key file not found: {path}");
            }
            catch (SshPassPhraseNullOrEmptyException)
            {
                throw new SshSessionException("The private key is encrypted. Enter its passphrase in the connection settings.");
            }
            catch (Exception ex)
            {
                throw new SshSessionException($"Could not load private key '{path}': {ex.Message}", ex);
            }
            owned.Add(keyFile);
            methods.Add(new PrivateKeyAuthenticationMethod(user, keyFile));
        }

        var password = string.IsNullOrEmpty(cred.Password) ? null : cred.Password;
        if (password is not null) methods.Add(new PasswordAuthenticationMethod(user, password));

        // Keyboard-interactive: network devices often only offer this, and it carries MFA prompts.
        // Password-looking prompts get the saved password (once); anything else goes to the user.
        if (password is not null || options.Prompt is not null)
        {
            var kbi = new KeyboardInteractiveAuthenticationMethod(user);
            int passwordAnswers = 0;
            kbi.AuthenticationPrompt += (_, e) =>
            {
                var ask = new List<AuthenticationPrompt>();
                foreach (var prompt in e.Prompts.OrderBy(p => p.Id))
                {
                    var request = prompt.Request ?? "";
                    if (prompt.IsEchoed && LooksLikeUsernamePrompt(request))
                        prompt.Response = user;
                    else if (password is not null && passwordAnswers == 0 && !prompt.IsEchoed && LooksLikePasswordPrompt(request, e.Prompts.Count()))
                    {
                        prompt.Response = password;
                        passwordAnswers++;
                    }
                    else
                        ask.Add(prompt);
                }
                if (ask.Count == 0) return;

                IReadOnlyList<string>? answers = null;
                if (options.Prompt is { } handler)
                {
                    var request = new AuthPromptRequest(options.Endpoint, user, NullIfBlank(e.Instruction),
                        ask.Select(p => new AuthPromptField((p.Request ?? "").Trim(), p.IsEchoed)).ToList());
                    try { answers = handler(request); }
                    catch { answers = null; }
                }
                if (answers is null && options.Prompt is not null) state.PromptCancelled = true;
                for (int i = 0; i < ask.Count; i++)
                    ask[i].Response = answers is not null && i < answers.Count ? answers[i] ?? "" : "";
            };
            methods.Add(kbi);
        }

        if (methods.Count == 0) methods.Add(new NoneAuthenticationMethod(user));

        foreach (var m in methods)
            if (m is IDisposable d) owned.Add(d);
        return methods;
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    internal static bool LooksLikeUsernamePrompt(string request) =>
        request.Contains("user", StringComparison.OrdinalIgnoreCase) || request.Contains("login", StringComparison.OrdinalIgnoreCase);

    internal static bool LooksLikePasswordPrompt(string request, int promptCount)
    {
        if (request.Contains("password", StringComparison.OrdinalIgnoreCase)) return true;
        // "PASSCODE", "Verification code", "Token", "OTP", "PIN" are second factors, not the password.
        string[] factorWords = { "code", "token", "otp", "pin", "verif", "one-time", "one time", "duo", "push" };
        if (factorWords.Any(w => request.Contains(w, StringComparison.OrdinalIgnoreCase))) return false;
        return promptCount == 1;
    }

    public static string DescribeError(Exception ex) => ex switch
    {
        SshSessionException s => s.Message,
        SshAuthenticationException a => $"Authentication failed: {a.Message}",
        SshOperationTimeoutException => "The connection timed out.",
        ProxyException p => $"Proxy error: {p.Message}",
        SocketException so => so.SocketErrorCode switch
        {
            SocketError.HostNotFound or SocketError.NoData => "Host not found (DNS lookup failed).",
            SocketError.ConnectionRefused => "Connection refused. Is an SSH server listening on that port?",
            SocketError.TimedOut => "The connection timed out.",
            SocketError.ConnectionReset => "The connection was reset by the remote host.",
            SocketError.AddressAlreadyInUse => "That local port is already in use.",
            _ => $"Network error: {so.Message}",
        },
        OperationCanceledException => "Cancelled.",
        SshConnectionException c => $"SSH connection error: {c.Message}",
        AggregateException { InnerException: { } inner } => DescribeError(inner),
        _ => ex.Message,
    };

    /// <summary>True if the failure was a rejected login (wrong password / code), as opposed to network or host key problems.</summary>
    public static bool IsAuthenticationFailure(Exception ex) =>
        ex is SshAuthenticationException || ex.InnerException is SshAuthenticationException ||
        (ex is AggregateException agg && agg.InnerExceptions.Any(IsAuthenticationFailure));

    internal static void DisposeQuietly(BaseClient? client, List<IDisposable> owned)
    {
        try { if (client?.IsConnected == true) client.Disconnect(); } catch { /* ignore */ }
        try { client?.Dispose(); } catch { /* ignore */ }
        foreach (var d in owned)
        {
            try { d.Dispose(); } catch { /* ignore */ }
        }
        owned.Clear();
    }
}

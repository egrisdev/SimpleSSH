using System.Net.Sockets;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace SimpleSSH.Core.Ssh;

/// <summary>
/// One interactive SSH shell. Output is decoded as UTF-8 (split multi-byte sequences are handled)
/// and raised on a background thread via <see cref="Output"/>. Tunnels in the options are opened with it.
/// </summary>
public sealed class SshTerminalSession : IDisposable
{
    private readonly IHostKeyVerifier _hostKeyVerifier;
    private SshConnection<SshClient>? _connection;
    private ShellStream? _shell;
    private Thread? _readThread;
    private volatile string? _lastError;
    private int _disconnectRaised;
    private int _disposed;
    private bool _started;

    public SshTerminalSession(IHostKeyVerifier hostKeyVerifier)
    {
        _hostKeyVerifier = hostKeyVerifier ?? throw new ArgumentNullException(nameof(hostKeyVerifier));
    }

    /// <summary>Decoded terminal output (background thread).</summary>
    public event Action<string>? Output;

    /// <summary>Raised once when the remote side closes or the connection drops (background thread).
    /// Not raised when the session is disposed locally.</summary>
    public event Action<string>? Disconnected;

    /// <summary>True when the remote side ended the shell normally (e.g. the user typed <c>exit</c>), as opposed to an error or dropped connection.</summary>
    public bool EndedCleanly { get; private set; }

    /// <summary>One line per tunnel after connecting, e.g. "Tunnel open: local 127.0.0.1:8080 → db:5432".</summary>
    public IReadOnlyList<string> TunnelStatus { get; private set; } = Array.Empty<string>();

    public bool IsConnected => _shell is not null && _connection?.Client.IsConnected == true && _disconnectRaised == 0 && _disposed == 0;

    public async Task ConnectAsync(SshConnectOptions options, uint columns, uint rows, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (_started) throw new InvalidOperationException("A session can only be connected once.");
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        _started = true;

        var connection = await SshConnector.ConnectAsync(options, _hostKeyVerifier, info => new SshClient(info),
            client => client.ErrorOccurred += (_, e) =>
            {
                _lastError = e.Exception?.Message;
                // Errors during the handshake surface as the ConnectAsync exception instead.
                if (_shell is not null) RaiseDisconnected(SshConnector.DescribeError(e.Exception ?? new Exception("Unknown error.")));
            },
            cancellationToken).ConfigureAwait(false);
        _connection = connection;

        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _shell = await Task.Run(
                () => connection.Client.CreateShellStream(options.TerminalType, Math.Max(columns, 1), Math.Max(rows, 1), 0, 0, 64 * 1024),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Teardown();
            throw new SshSessionException(SshConnector.DescribeError(ex), ex);
        }

        TunnelStatus = StartTunnels(connection.Client, options.Tunnels);

        _readThread = new Thread(ReadLoop) { IsBackground = true, Name = $"ssh-read {options.Host}" };
        _readThread.Start();
    }

    /// <summary>Opens each tunnel; a tunnel that can't open (port in use, refused by server) is reported, not fatal.</summary>
    private static List<string> StartTunnels(SshClient client, IReadOnlyList<TunnelSpec> tunnels)
    {
        var status = new List<string>();
        foreach (var t in tunnels)
        {
            ForwardedPort port = t.Kind switch
            {
                TunnelKind.Local => new ForwardedPortLocal(t.BindHost, (uint)t.BindPort, t.Host, (uint)t.Port),
                TunnelKind.Remote => new ForwardedPortRemote(t.BindHost, (uint)t.BindPort, t.Host, (uint)t.Port),
                _ => new ForwardedPortDynamic(t.BindHost, (uint)t.BindPort),
            };
            try
            {
                client.AddForwardedPort(port);
                port.Start();
                status.Add($"Tunnel open: {t.Describe()}");
            }
            catch (Exception ex)
            {
                try { client.RemoveForwardedPort(port); } catch { /* ignore */ }
                try { port.Dispose(); } catch { /* ignore */ }
                status.Add($"Tunnel failed: {t.Describe()}: {SshConnector.DescribeError(ex)}");
            }
        }
        return status;
    }

    /// <summary>
    /// Asks the server which folder this session's shell is in (see <see cref="ShellDirectory.ProbeCommand"/>), on
    /// this same connection so it finds this tab's shell. Null when the server can't tell (not Linux, timeout).
    /// </summary>
    public async Task<string?> QueryCurrentDirectoryAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var client = _connection?.Client;
        if (client is null || !IsConnected) return null;
        try
        {
            using var cmd = client.CreateCommand(ShellDirectory.ProbeCommand);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            await cmd.ExecuteAsync(cts.Token).ConfigureAwait(false);
            return cmd.ExitStatus == 0 && ShellDirectory.TryParseProbe(cmd.Result, out var path) ? path : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    public void Write(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        Write(Encoding.UTF8.GetBytes(text));
    }

    public void Write(byte[] data)
    {
        var shell = _shell;
        if (shell is null || data.Length == 0 || _disconnectRaised != 0 || _disposed != 0) return;
        try
        {
            shell.Write(data, 0, data.Length);
            shell.Flush();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or SshException or IOException or SocketException or InvalidOperationException)
        {
            RaiseDisconnected(SshConnector.DescribeError(ex));
        }
    }

    public void Resize(uint columns, uint rows)
    {
        var shell = _shell;
        if (shell is null || columns == 0 || rows == 0 || !IsConnected) return;
        try
        {
            shell.ChangeWindowSize(columns, rows, 0, 0);
        }
        catch (Exception ex) when (ex is ObjectDisposedException or SshException or IOException or SocketException or InvalidOperationException)
        {
            // The read loop will report the disconnect.
        }
    }

    private void ReadLoop()
    {
        var shell = _shell!;
        var buffer = new byte[32 * 1024];
        var decoder = new UTF8Encoding(false, false).GetDecoder();
        var chars = new char[Encoding.UTF8.GetMaxCharCount(buffer.Length)];
        string reason = "Connection closed by remote host.";

        while (true)
        {
            int read;
            try
            {
                read = shell.Read(buffer, 0, buffer.Length);
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                reason = SshConnector.DescribeError(ex);
                break;
            }

            if (read <= 0) break;

            int count = decoder.GetChars(buffer, 0, read, chars, 0, flush: false);
            if (count > 0)
            {
                try { Output?.Invoke(new string(chars, 0, count)); }
                catch { /* never let a UI handler kill the read loop */ }
            }
        }

        if (_lastError is { } err && reason.StartsWith("Connection closed", StringComparison.Ordinal))
            reason = $"Connection lost: {err}";
        else if (reason.StartsWith("Connection closed", StringComparison.Ordinal))
            EndedCleanly = true;
        RaiseDisconnected(reason);
    }

    private void RaiseDisconnected(string reason)
    {
        if (_disposed != 0) return;
        if (Interlocked.Exchange(ref _disconnectRaised, 1) != 0) return;
        try { Disconnected?.Invoke(reason); } catch { /* ignore */ }
    }

    /// <summary>Kept for callers of the old API.</summary>
    public static string DescribeError(Exception ex) => SshConnector.DescribeError(ex);

    private void Teardown()
    {
        var shell = Interlocked.Exchange(ref _shell, null);
        var connection = Interlocked.Exchange(ref _connection, null);
        try { shell?.Dispose(); } catch { /* ignore */ }
        if (connection is not null)
        {
            foreach (var port in connection.Client.ForwardedPorts.ToList())
            {
                try { port.Stop(); } catch { /* ignore */ }
                try { port.Dispose(); } catch { /* ignore */ }
            }
            connection.Dispose();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Teardown();
    }
}

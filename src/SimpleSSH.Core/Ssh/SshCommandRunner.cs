using Renci.SshNet;

namespace SimpleSSH.Core.Ssh;

public sealed record CommandResult(int? ExitStatus, string Output, string Error)
{
    public bool Succeeded => ExitStatus is null or 0;

    /// <summary>stdout followed by stderr, as a person would see it in a terminal.</summary>
    public string CombinedOutput =>
        string.IsNullOrEmpty(Error) ? Output
        : string.IsNullOrEmpty(Output) ? Error
        : Output.EndsWith('\n') ? Output + Error : Output + "\n" + Error;
}

/// <summary>Runs one non-interactive command over its own SSH connection (an "exec" channel).</summary>
public static class SshCommandRunner
{
    public static async Task<CommandResult> RunAsync(
        SshConnectOptions options, IHostKeyVerifier verifier, string command, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        using var connection = await SshConnector.ConnectAsync(options, verifier, info => new SshClient(info),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using var cmd = connection.Client.CreateCommand(command);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await cmd.ExecuteAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested &&
                                   (ex is OperationCanceledException || ex is Renci.SshNet.Common.SshOperationTimeoutException))
        {
            throw new SshSessionException($"The command did not finish within {timeout.TotalSeconds:0} seconds.", ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new SshSessionException(SshConnector.DescribeError(ex), ex);
        }
        return new CommandResult(cmd.ExitStatus, cmd.Result ?? "", cmd.Error ?? "");
    }
}

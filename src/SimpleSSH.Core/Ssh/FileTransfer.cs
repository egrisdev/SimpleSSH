using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace SimpleSSH.Core.Ssh;

public sealed record RemoteEntry(string Name, string FullPath, bool IsDirectory, bool IsSymbolicLink, long Size, DateTime Modified, string Permissions);

/// <summary>Progress of a transfer: the file being copied and total bytes done so far.</summary>
public readonly record struct TransferProgress(string CurrentFile, long BytesDone, long BytesTotal);

/// <summary>The server has no SFTP subsystem (common on network devices). SCP may still work.</summary>
public sealed class SftpUnavailableException : Exception
{
    public SftpUnavailableException(Exception inner)
        : base("This server doesn't offer SFTP, so its files can't be browsed. You can still copy files with SCP.", inner) { }
}

/// <summary>
/// A file-browsing session over SFTP. Operations are serialized; all are async and cancellable.
/// Paths are POSIX paths on the server.
/// </summary>
public sealed class SftpSession : IDisposable
{
    private readonly SshConnection<SftpClient> _connection;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private SftpSession(SshConnection<SftpClient> connection) => _connection = connection;

    /// <summary>Raised when the connection drops (background thread).</summary>
    public event Action<string>? Disconnected;

    public bool IsConnected => _connection.Client.IsConnected;

    /// <summary>The directory the server starts in (usually the user's home).</summary>
    public string HomeDirectory { get; private set; } = "/";

    public static async Task<SftpSession> ConnectAsync(SshConnectOptions options, IHostKeyVerifier verifier, CancellationToken cancellationToken = default)
    {
        SftpSession? session = null;
        SshConnection<SftpClient> connection;
        try
        {
            connection = await SshConnector.ConnectAsync(options, verifier, info => new SftpClient(info),
                client => client.ErrorOccurred += (_, e) => session?.Disconnected?.Invoke(SshConnector.DescribeError(e.Exception)),
                cancellationToken).ConfigureAwait(false);
        }
        catch (SshSessionException ex) when (IsSubsystemFailure(ex.InnerException))
        {
            throw new SftpUnavailableException(ex.InnerException!);
        }
        session = new SftpSession(connection);
        try
        {
            session.HomeDirectory = connection.Client.WorkingDirectory is { Length: > 0 } wd ? wd : "/";
        }
        catch
        {
            session.HomeDirectory = "/";
        }
        return session;
    }

    private static bool IsSubsystemFailure(Exception? ex) =>
        ex is SshException && ex.Message.Contains("subsystem", StringComparison.OrdinalIgnoreCase);

    public Task<IReadOnlyList<RemoteEntry>> ListAsync(string path, CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<RemoteEntry>>(client =>
        {
            var files = client.ListDirectory(path).Where(f => f.Name is not ("." or "..")).ToList();
            var linkToFolder = LinksToFolders(client, files.Where(f => f.IsSymbolicLink).ToList(), cancellationToken);
            return files
                .Select(f => ToEntry(f, f.IsSymbolicLink ? linkToFolder.Contains(f.FullName) : f.IsDirectory))
                .OrderByDescending(e => e.IsDirectory)
                .ThenBy(e => e.Name, NaturalStringComparer.Instance)
                .ToList();
        }, cancellationToken);

    /// <summary>
    /// Which of these links point at folders. The server is asked about all of them at once rather than one after
    /// another: a folder like /etc or /usr/lib holds dozens to hundreds of links, and each question is a round trip.
    /// </summary>
    private static HashSet<string> LinksToFolders(SftpClient client, IReadOnlyList<ISftpFile> links, CancellationToken cancellationToken)
    {
        var folders = new HashSet<string>(StringComparer.Ordinal);
        if (links.Count == 0) return folders;
        using var slots = new SemaphoreSlim(32); // plenty in flight, without flooding the server
        var checks = links.Select(async link =>
        {
            await slots.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return (link.FullName, IsFolder: (await client.GetAsync(link.FullName, cancellationToken).ConfigureAwait(false)).IsDirectory);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return (link.FullName, IsFolder: false); // dangling link
            }
            finally
            {
                slots.Release();
            }
        }).ToList();
        foreach (var (name, isFolder) in Task.WhenAll(checks).GetAwaiter().GetResult())
        {
            if (isFolder) folders.Add(name);
        }
        return folders;
    }

    /// <summary>Resolves a path the user typed (relative to home, "~", "..").</summary>
    public Task<string> ResolveDirectoryAsync(string path, CancellationToken cancellationToken = default) =>
        Run(client =>
        {
            var p = (path ?? "").Trim();
            if (p is "" or "~") p = HomeDirectory;
            else if (p.StartsWith("~/", StringComparison.Ordinal)) p = Combine(HomeDirectory, p[2..]);
            else if (!p.StartsWith('/')) p = Combine(HomeDirectory, p);
            p = Normalize(p);
            var attrs = client.GetAttributes(p);
            if (!attrs.IsDirectory) throw new SshSessionException($"{p} is not a folder.");
            return p;
        }, cancellationToken);

    public Task CreateDirectoryAsync(string path, CancellationToken cancellationToken = default) =>
        Run(client => { client.CreateDirectory(path); return true; }, cancellationToken);

    public Task RenameAsync(string from, string to, CancellationToken cancellationToken = default) =>
        Run(client => { client.RenameFile(from, to); return true; }, cancellationToken);

    /// <summary>Deletes a file, or a folder and everything in it.</summary>
    public Task DeleteAsync(RemoteEntry entry, CancellationToken cancellationToken = default) =>
        Run(client =>
        {
            DeleteRecursive(client, entry.FullPath, entry.IsDirectory && !entry.IsSymbolicLink, cancellationToken);
            return true;
        }, cancellationToken);

    private static void DeleteRecursive(SftpClient client, string path, bool isDirectory, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!isDirectory)
        {
            client.DeleteFile(path);
            return;
        }
        foreach (var f in client.ListDirectory(path))
        {
            if (f.Name is "." or "..") continue;
            DeleteRecursive(client, f.FullName, f.IsDirectory && !f.IsSymbolicLink, ct);
        }
        client.DeleteDirectory(path);
    }

    /// <summary>Uploads local files and folders (recursively) into <paramref name="remoteDirectory"/>.</summary>
    public Task UploadAsync(IEnumerable<string> localPaths, string remoteDirectory, IProgress<TransferProgress>? progress, CancellationToken cancellationToken = default)
    {
        var items = localPaths.ToList();
        return Run(client =>
        {
            long total = items.Sum(LocalSize), done = 0;
            foreach (var local in items) UploadItem(client, local, remoteDirectory, total, ref done, progress, cancellationToken);
            return true;
        }, cancellationToken);
    }

    private static void UploadItem(SftpClient client, string local, string remoteDir, long total, ref long done, IProgress<TransferProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var name = Path.GetFileName(local.TrimEnd('\\', '/'));
        var target = Combine(remoteDir, name);
        if (Directory.Exists(local))
        {
            if (!client.Exists(target)) client.CreateDirectory(target);
            foreach (var child in Directory.EnumerateFileSystemEntries(local))
                UploadItem(client, child, target, total, ref done, progress, ct);
            return;
        }

        using var source = new ProgressStream(File.OpenRead(local), name, total, done, progress, ct);
        try
        {
            client.UploadFile(source, target, canOverride: true);
        }
        catch (OperationCanceledException)
        {
            // Don't leave a half-written file behind.
            try { client.DeleteFile(target); } catch { /* best effort */ }
            throw;
        }
        done += source.Transferred;
    }

    /// <summary>Downloads remote files and folders (recursively) into <paramref name="localDirectory"/>.</summary>
    public Task DownloadAsync(IEnumerable<RemoteEntry> entries, string localDirectory, IProgress<TransferProgress>? progress, CancellationToken cancellationToken = default)
    {
        var items = entries.ToList();
        return Run(client =>
        {
            long total = items.Sum(e => RemoteSize(client, e, cancellationToken)), done = 0;
            foreach (var e in items) DownloadItem(client, e.FullPath, e.IsDirectory, Path.Combine(localDirectory, SafeLocalName(e.Name)), total, ref done, progress, cancellationToken);
            return true;
        }, cancellationToken);
    }

    /// <summary>Downloads one remote file to an exact local path.</summary>
    public Task DownloadFileAsync(RemoteEntry entry, string localPath, IProgress<TransferProgress>? progress, CancellationToken cancellationToken = default) =>
        Run(client =>
        {
            long done = 0;
            DownloadItem(client, entry.FullPath, false, localPath, entry.Size, ref done, progress, cancellationToken);
            return true;
        }, cancellationToken);

    private static void DownloadItem(SftpClient client, string remote, bool isDirectory, string local, long total, ref long done, IProgress<TransferProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (isDirectory)
        {
            Directory.CreateDirectory(local);
            foreach (var f in client.ListDirectory(remote))
            {
                if (f.Name is "." or "..") continue;
                DownloadItem(client, f.FullName, f.IsDirectory, Path.Combine(local, SafeLocalName(f.Name)), total, ref done, progress, ct);
            }
            return;
        }

        var temp = local + ".part";
        try
        {
            using (var target = new ProgressStream(File.Create(temp), Path.GetFileName(local), total, done, progress, ct))
            {
                client.DownloadFile(remote, target);
                done += target.Transferred;
            }
            File.Move(temp, local, overwrite: true);
            MarkDownloaded(local, client.ConnectionInfo.Host, remote);
        }
        finally
        {
            if (File.Exists(temp)) { try { File.Delete(temp); } catch { /* best effort */ } }
        }
    }

    /// <summary>
    /// Marks a downloaded file as coming from another computer (the "Mark of the Web"), as a browser does: Windows then
    /// asks before running it, SmartScreen checks it, and Office opens it in Protected View with macros blocked.
    /// </summary>
    public static void MarkDownloaded(string localPath, string host, string remotePath)
    {
        try
        {
            File.WriteAllText(localPath + ":Zone.Identifier",
                "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=sftp://" + host + remotePath + "\r\n");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // FAT/exFAT drives and some network shares have no room for the mark: nothing to do.
        }
    }

    private static long LocalSize(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            if (Directory.Exists(path))
                return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length);
        }
        catch { /* best effort */ }
        return 0;
    }

    private static long RemoteSize(SftpClient client, RemoteEntry e, CancellationToken ct)
    {
        if (!e.IsDirectory) return e.Size;
        long sum = 0;
        try
        {
            foreach (var f in client.ListDirectory(e.FullPath))
            {
                ct.ThrowIfCancellationRequested();
                if (f.Name is "." or "..") continue;
                sum += RemoteSize(client, ToEntry(f, f.IsDirectory), ct);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* best effort */ }
        return sum;
    }

    private async Task<T> Run<T>(Func<SftpClient, T> work, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => work(_connection.Client), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (SshSessionException) { throw; }
        catch (SftpPathNotFoundException ex) { throw new SshSessionException($"Not found: {ex.Message}", ex); }
        catch (SftpPermissionDeniedException ex) { throw new SshSessionException($"Permission denied: {ex.Message}", ex); }
        catch (Exception ex) { throw new SshSessionException(SshConnector.DescribeError(ex), ex); }
        finally
        {
            _gate.Release();
        }
    }

    private static RemoteEntry ToEntry(ISftpFile f, bool isDirectory) =>
        new(f.Name, f.FullName, isDirectory, f.IsSymbolicLink, isDirectory ? 0 : f.Length, f.LastWriteTime, PermissionString(f, isDirectory));

    private static string PermissionString(ISftpFile f, bool isDirectory)
    {
        char T(bool b, char c) => b ? c : '-';
        return (f.IsSymbolicLink ? 'l' : isDirectory ? 'd' : '-').ToString() +
               T(f.OwnerCanRead, 'r') + T(f.OwnerCanWrite, 'w') + T(f.OwnerCanExecute, 'x') +
               T(f.GroupCanRead, 'r') + T(f.GroupCanWrite, 'w') + T(f.GroupCanExecute, 'x') +
               T(f.OthersCanRead, 'r') + T(f.OthersCanWrite, 'w') + T(f.OthersCanExecute, 'x');
    }

    public static string Combine(string dir, string name) =>
        dir.EndsWith('/') ? dir + name : dir + "/" + name;

    public static string Parent(string path)
    {
        var p = path.TrimEnd('/');
        if (p.Length == 0) return "/";
        var i = p.LastIndexOf('/');
        return i <= 0 ? "/" : p[..i];
    }

    /// <summary>Collapses "." and ".." in an absolute POSIX path.</summary>
    public static string Normalize(string path)
    {
        var stack = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..") { if (stack.Count > 0) stack.RemoveAt(stack.Count - 1); continue; }
            stack.Add(part);
        }
        return "/" + string.Join('/', stack);
    }

    /// <summary>
    /// Makes a remote name safe as a Windows file name: no path characters, no invisible formatting characters (a
    /// right-to-left override can make <c>report[U+202E]fdp.exe</c> look like <c>reportexe.pdf</c>), and no device names
    /// such as CON or NUL.
    /// </summary>
    public static string SafeLocalName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var safe = new string(name
                .Where(c => char.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.Format)
                .Select(c => invalid.Contains(c) ? '_' : c).ToArray())
            .TrimEnd('.', ' ');
        if (safe.Length == 0) return "_";
        var stem = safe.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return ReservedNames.Contains(stem) ? "_" + safe : safe;
    }

    private static readonly HashSet<string> ReservedNames = new(
        new[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" }
            .Concat(Enumerable.Range(0, 10).SelectMany(i => new[] { "COM" + i, "LPT" + i }))
            .Concat(new[] { "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³" }));

    public void Dispose()
    {
        _connection.Dispose();
    }
}

/// <summary>SCP for servers without SFTP: copy one file each way. Each call uses its own connection.
/// Paths are shell-quoted so a file name can never inject a command on the server.</summary>
public static class ScpTransfer
{
    public static async Task UploadAsync(SshConnectOptions options, IHostKeyVerifier verifier, string localFile, string remotePath,
        IProgress<TransferProgress>? progress, CancellationToken cancellationToken = default)
    {
        using var connection = await SshConnector.ConnectAsync(options, verifier, info => new ScpClient(info, RemotePathTransformation.ShellQuote), cancellationToken: cancellationToken).ConfigureAwait(false);
        var name = Path.GetFileName(localFile);
        var target = string.IsNullOrWhiteSpace(remotePath) ? name
            : remotePath.EndsWith('/') ? remotePath + name
            : remotePath;
        await Task.Run(() =>
        {
            try
            {
                using var source = new ProgressStream(File.OpenRead(localFile), name, new FileInfo(localFile).Length, 0, progress, cancellationToken);
                connection.Client.Upload(source, target);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new SshSessionException($"SCP upload failed: {SshConnector.DescribeError(ex)}", ex);
            }
        }, cancellationToken).ConfigureAwait(false);
    }

    public static async Task DownloadAsync(SshConnectOptions options, IHostKeyVerifier verifier, string remotePath, string localFile,
        IProgress<TransferProgress>? progress, CancellationToken cancellationToken = default)
    {
        using var connection = await SshConnector.ConnectAsync(options, verifier, info => new ScpClient(info, RemotePathTransformation.ShellQuote), cancellationToken: cancellationToken).ConfigureAwait(false);
        var temp = localFile + ".part";
        await Task.Run(() =>
        {
            try
            {
                using (var target = new ProgressStream(File.Create(temp), Path.GetFileName(localFile), 0, 0, progress, cancellationToken))
                    connection.Client.Download(remotePath, target);
                File.Move(temp, localFile, overwrite: true);
                SftpSession.MarkDownloaded(localFile, options.Host.Trim(), remotePath);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new SshSessionException($"SCP download failed: {SshConnector.DescribeError(ex)}", ex);
            }
            finally
            {
                if (File.Exists(temp)) { try { File.Delete(temp); } catch { /* best effort */ } }
            }
        }, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Wraps a local stream to report progress and to abort a blocking SSH.NET transfer on cancellation.</summary>
internal sealed class ProgressStream : Stream
{
    private readonly Stream _inner;
    private readonly string _name;
    private readonly long _total;
    private readonly long _baseDone;
    private readonly IProgress<TransferProgress>? _progress;
    private readonly CancellationToken _ct;
    private long _lastReport = -1;

    public ProgressStream(Stream inner, string name, long total, long baseDone, IProgress<TransferProgress>? progress, CancellationToken ct)
    {
        _inner = inner;
        _name = name;
        _total = total;
        _baseDone = baseDone;
        _progress = progress;
        _ct = ct;
        Report(force: true);
    }

    public long Transferred { get; private set; }

    private void Advance(int count)
    {
        _ct.ThrowIfCancellationRequested();
        Transferred += count;
        Report(force: false);
    }

    private void Report(bool force)
    {
        if (_progress is null) return;
        var done = _baseDone + Transferred;
        // Throttle: report every 256 KB.
        if (!force && done - _lastReport < 256 * 1024) return;
        _lastReport = done;
        _progress.Report(new TransferProgress(_name, done, Math.Max(_total, done)));
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        _ct.ThrowIfCancellationRequested();
        var n = _inner.Read(buffer, offset, count);
        Advance(n);
        return n;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _ct.ThrowIfCancellationRequested();
        _inner.Write(buffer, offset, count);
        Advance(count);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Report(force: true);
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;
    public override long Position { get => _inner.Position; set => _inner.Position = value; }
    public override void Flush() => _inner.Flush();
    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override void SetLength(long value) => _inner.SetLength(value);
}

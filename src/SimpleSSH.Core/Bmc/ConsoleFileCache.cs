using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SimpleSSH.Core.Bmc;

/// <summary>A file of a console page, as the controller last sent it.</summary>
/// <param name="Headers">Its type and protections, one "Name: value" per line (see <see cref="ConsoleFileCache.KeptHeaders"/>).</param>
public sealed record CachedFile(string? ETag, string? LastModified, string Headers, byte[] Body);

/// <summary>
/// The console pages' own files (scripts, styles, fonts, pictures) kept on disk per controller, so a console opens
/// without downloading them again: iLO and iDRAC send them slowly (up to a second each) but answer "not changed" in a few
/// milliseconds. Every use still asks the controller first. Only static files are kept: never an address's query (an
/// iLO console address carries the session key), API answers, cookies or anything the page itself saves.
/// </summary>
public sealed class ConsoleFileCache
{
    private const int MaxFileBytes = 8 * 1024 * 1024;
    private static readonly TimeSpan KeepUnused = TimeSpan.FromDays(60);

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".html", ".htm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".svg", ".png", ".gif", ".jpg", ".jpeg", ".ico", ".bmp", ".webp",
    };

    /// <summary>The response headers given back with a file: its type and the page's protections. Never cookies.</summary>
    public static readonly IReadOnlyList<string> KeptHeaders = new[]
    {
        "Content-Type", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
        "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    };

    private readonly string _folder;

    public ConsoleFileCache(string folder) => _folder = folder;

    /// <summary>Is this address a static file worth keeping (by its file type)?</summary>
    public static bool IsStaticFile(Uri url) =>
        url.Scheme == Uri.UriSchemeHttps && StaticExtensions.Contains(Path.GetExtension(url.AbsolutePath));

    public static bool IsSmallEnough(long length) => length <= MaxFileBytes;

    /// <summary>The kept copy of this file (the query is ignored), or null.</summary>
    public CachedFile? Get(Uri url)
    {
        var path = PathFor(url);
        try
        {
            var data = File.ReadAllBytes(path);
            var newline = Array.IndexOf(data, (byte)'\n');
            if (newline < 0) return null;
            var meta = JsonSerializer.Deserialize<Meta>(data.AsSpan(0, newline));
            if (meta is null || meta.Path != url.AbsolutePath || string.IsNullOrEmpty(meta.Headers)) return null;
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow); // still in use: TrimOld keeps it
            return new CachedFile(meta.ETag, meta.LastModified, meta.Headers, data[(newline + 1)..]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>Keeps the file when the controller sent something to check it with later (an ETag or a date).</summary>
    public void Put(Uri url, CachedFile file)
    {
        if ((file.ETag is null && file.LastModified is null) || !IsSmallEnough(file.Body.Length)) return;
        var path = PathFor(url);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(_folder);
            var meta = JsonSerializer.SerializeToUtf8Bytes(new Meta(url.AbsolutePath, file.ETag, file.LastModified, file.Headers));
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write))
            {
                stream.Write(meta);
                stream.WriteByte((byte)'\n');
                stream.Write(file.Body);
            }
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temp); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Removes files no console has used for two months (e.g. from before a firmware update).</summary>
    public void TrimOld()
    {
        try
        {
            if (!Directory.Exists(_folder)) return;
            var cutoff = DateTime.UtcNow - KeepUnused;
            foreach (var file in new DirectoryInfo(_folder).EnumerateFiles())
            {
                if (file.LastWriteTimeUtc < cutoff) file.Delete();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>One file per controller (scheme, host, port) and path.</summary>
    private string PathFor(Uri url)
    {
        var key = $"{url.GetLeftPart(UriPartial.Authority).ToLowerInvariant()}{url.AbsolutePath}";
        return Path.Combine(_folder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant()[..40]);
    }

    private sealed record Meta(string Path, string? ETag, string? LastModified, string Headers);
}

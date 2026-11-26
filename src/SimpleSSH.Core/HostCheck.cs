using System.Net;
using System.Net.Sockets;

namespace SimpleSSH.Core;

/// <summary>
/// Checks a host name or IP address (without user@ or :port) and, when it is malformed, suggests a fix.
/// </summary>
public static class HostCheck
{
    /// <summary>What is wrong with the host, or null when it is fine. <paramref name="suggestion"/> is a fixed host, when there is an obvious one.</summary>
    public static string? Problem(string? host, out string? suggestion)
    {
        suggestion = null;
        var problem = Find(host?.Trim() ?? "");
        if (problem is null) return null;
        var fixedHost = Clean(host?.Trim() ?? "");
        if (fixedHost.Length > 0 && Find(fixedHost) is null) suggestion = fixedHost;
        return problem;
    }

    private static string? Find(string host)
    {
        if (host.Length == 0) return "Host is required.";
        if (host.Contains("://")) return "Leave out the " + host[..(host.IndexOf("://", StringComparison.Ordinal) + 3)] + " part.";
        if (host.Any(char.IsWhiteSpace)) return "Host can't contain spaces.";
        if (host.IndexOfAny(['/', '\\']) is var slash and >= 0) return $"Host can't contain \"{host[slash]}\".";

        // IPv6 (with an optional %zone)
        if (host.Contains(':'))
            return IPAddress.TryParse(host, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6 ? null
                : "That isn't a valid address. For a port, use the Port box.";

        if (host.FirstOrDefault(c => !IsHostChar(c)) is var bad and not '\0') return $"Host can't contain \"{bad}\".";
        if (host.StartsWith('.') || host.EndsWith('.') || host.Contains("..")) return "Host has a stray dot.";
        if (host.Length > 253) return "Host is too long.";

        var parts = host.Split('.');
        if (parts.All(p => p.All(char.IsAsciiDigit)))
            return parts.Length == 4 && parts.All(p => p.Length <= 3 && int.Parse(p) <= 255) ? null
                : "That isn't a valid IP address. It should be four numbers from 0 to 255, like 10.0.0.5.";
        if (parts.Any(p => p.StartsWith('-') || p.EndsWith('-'))) return "A part of the host name starts or ends with \"-\".";
        if (parts.Any(p => p.Length > 63)) return "A part of the host name is longer than 63 characters.";
        return null;
    }

    private static bool IsHostChar(char c) => char.IsLetterOrDigit(c) || c is '-' or '.' or '_';

    /// <summary>The likely intended host: no scheme, nothing from the first slash, no stray characters or dots.</summary>
    private static string Clean(string host)
    {
        var scheme = host.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) host = host[(scheme + 3)..];
        if (host.IndexOfAny(['/', '\\']) is var slash and >= 0) host = host[..slash];
        if (host.Any(char.IsWhiteSpace)) return ""; // "ilo 01": no safe guess
        if (host.Contains(':') && IPAddress.TryParse(host.Trim('[', ']'), out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
            return host.Trim('[', ']');
        if (host.Count(c => c == ':') > 1) return ""; // a broken IPv6 address: no safe guess
        if (host.IndexOf(':') is var colon and > 0) host = host[..colon]; // host:port typed with a bad port
        host = new string(host.Where(IsHostChar).ToArray());
        var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim('-')).Where(p => p.Length > 0);
        return string.Join('.', parts);
    }
}

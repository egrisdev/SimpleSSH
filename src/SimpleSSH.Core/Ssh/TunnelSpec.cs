using System.Globalization;

namespace SimpleSSH.Core.Ssh;

public enum TunnelKind
{
    /// <summary>-L: a port on this PC is forwarded through the server to Host:Port.</summary>
    Local,
    /// <summary>-R: a port on the server is forwarded back to Host:Port as seen from this PC.</summary>
    Remote,
    /// <summary>-D: a SOCKS proxy on this PC that connects out through the server.</summary>
    Dynamic,
}

/// <summary>
/// One port forward, written the OpenSSH way:
/// <c>L 8080:db:5432</c>, <c>L 0.0.0.0:8080:db:5432</c>, <c>R 9000:localhost:22</c>, <c>D 1080</c>.
/// A leading dash (<c>-L</c>) and a missing space (<c>L8080:db:5432</c>) are accepted too.
/// </summary>
public sealed record TunnelSpec(TunnelKind Kind, string BindHost, int BindPort, string Host, int Port)
{
    public const string DefaultBindHost = "127.0.0.1";

    public static bool TryParse(string? text, out TunnelSpec? spec, out string error)
    {
        spec = null;
        error = "";
        var s = (text ?? "").Trim();
        if (s.StartsWith('-')) s = s[1..];
        if (s.Length < 2)
        {
            error = "Expected something like \"L 8080:db:5432\", \"R 9000:localhost:22\" or \"D 1080\".";
            return false;
        }

        TunnelKind kind;
        switch (char.ToUpperInvariant(s[0]))
        {
            case 'L': kind = TunnelKind.Local; break;
            case 'R': kind = TunnelKind.Remote; break;
            case 'D': kind = TunnelKind.Dynamic; break;
            default:
                error = $"\"{text?.Trim()}\": start with L (local), R (remote) or D (SOCKS).";
                return false;
        }

        var parts = SplitHostParts(s[1..].Trim());
        if (parts is null)
        {
            error = $"\"{text?.Trim()}\": unbalanced [ ] around an IPv6 address.";
            return false;
        }

        string bind = DefaultBindHost, host = "";
        string bindPortText, portText = "0";
        if (kind == TunnelKind.Dynamic)
        {
            switch (parts.Count)
            {
                case 1: bindPortText = parts[0]; break;
                case 2: bind = parts[0]; bindPortText = parts[1]; break;
                default:
                    error = $"\"{text?.Trim()}\": SOCKS tunnels are \"D port\" or \"D address:port\".";
                    return false;
            }
        }
        else
        {
            switch (parts.Count)
            {
                case 3: bindPortText = parts[0]; host = parts[1]; portText = parts[2]; break;
                case 4: bind = parts[0]; bindPortText = parts[1]; host = parts[2]; portText = parts[3]; break;
                default:
                    error = $"\"{text?.Trim()}\": expected \"{s[0]} port:host:port\" (optionally \"address:port:host:port\").";
                    return false;
            }
            if (host.Length == 0)
            {
                error = $"\"{text?.Trim()}\": the destination host is missing.";
                return false;
            }
        }

        if (bind is "" or "*") bind = "0.0.0.0";
        if (!TryPort(bindPortText, out var bindPort) || !TryPort(portText, out var port, allowZero: kind == TunnelKind.Dynamic))
        {
            error = $"\"{text?.Trim()}\": ports must be numbers between 1 and 65535.";
            return false;
        }

        spec = new TunnelSpec(kind, bind, bindPort, host, port);
        return true;
    }

    public static TunnelSpec Parse(string text) =>
        TryParse(text, out var spec, out var error) ? spec! : throw new FormatException(error);

    /// <summary>Parses every non-blank line; returns the first error, if any.</summary>
    public static bool TryParseAll(IEnumerable<string>? lines, out List<TunnelSpec> specs, out string error)
    {
        specs = new List<TunnelSpec>();
        error = "";
        foreach (var line in lines ?? Enumerable.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) continue;
            if (!TryParse(line, out var spec, out error)) return false;
            specs.Add(spec!);
        }
        return true;
    }

    /// <summary>Short human description, e.g. "127.0.0.1:8080 → db:5432".</summary>
    public string Describe() => Kind switch
    {
        TunnelKind.Local => $"local {Fmt(BindHost)}:{BindPort} → {Fmt(Host)}:{Port}",
        TunnelKind.Remote => $"remote {Fmt(BindHost)}:{BindPort} (on server) → {Fmt(Host)}:{Port}",
        _ => $"SOCKS proxy on {Fmt(BindHost)}:{BindPort}",
    };

    public override string ToString() => Kind switch
    {
        TunnelKind.Dynamic => BindHost == DefaultBindHost ? $"D {BindPort}" : $"D {Fmt(BindHost)}:{BindPort}",
        _ => (Kind == TunnelKind.Local ? "L " : "R ") +
             (BindHost == DefaultBindHost ? "" : Fmt(BindHost) + ":") + $"{BindPort}:{Fmt(Host)}:{Port}",
    };

    private static string Fmt(string host) => host.Contains(':') ? $"[{host}]" : host;

    private static bool TryPort(string text, out int port, bool allowZero = false) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 0 and <= 65535 && (port > 0 || allowZero);

    /// <summary>Splits on ':' but keeps [IPv6] groups intact (brackets removed).</summary>
    private static List<string>? SplitHostParts(string s)
    {
        var parts = new List<string>();
        int i = 0;
        while (i <= s.Length)
        {
            if (i < s.Length && s[i] == '[')
            {
                var end = s.IndexOf(']', i);
                if (end < 0) return null;
                parts.Add(s[(i + 1)..end]);
                i = end + 1;
                if (i < s.Length && s[i] != ':') return null;
                i++;
                continue;
            }
            var next = s.IndexOf(':', i);
            if (next < 0)
            {
                parts.Add(s[i..].Trim());
                break;
            }
            parts.Add(s[i..next].Trim());
            i = next + 1;
        }
        return parts;
    }
}

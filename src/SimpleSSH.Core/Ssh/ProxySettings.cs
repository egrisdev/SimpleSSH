namespace SimpleSSH.Core.Ssh;

public enum ProxyKind
{
    Socks4,
    Socks5,
    Http,
}

/// <summary>
/// A proxy written as a URL: <c>socks5://host:1080</c>, <c>socks5://user:pass@host:1080</c>,
/// <c>socks4://host:1080</c> or <c>http://proxy:3128</c>.
/// </summary>
public sealed record ProxySettings(ProxyKind Kind, string Host, int Port, string? Username, string? Password)
{
    public static bool TryParse(string? text, out ProxySettings? proxy, out string error)
    {
        proxy = null;
        error = "";
        var s = (text ?? "").Trim();
        const string Example = "Use a URL such as socks5://host:1080 or http://proxy:3128.";

        var schemeEnd = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            error = "Proxy: " + Example;
            return false;
        }
        var kind = s[..schemeEnd].ToLowerInvariant() switch
        {
            "socks5" or "socks5h" or "socks" => ProxyKind.Socks5,
            "socks4" or "socks4a" => ProxyKind.Socks4,
            "http" => ProxyKind.Http,
            _ => (ProxyKind?)null,
        };
        if (kind is null)
        {
            error = $"Proxy: \"{s[..schemeEnd]}\" isn't supported (socks5, socks4 or http). {Example}";
            return false;
        }

        // Swap the scheme for one Uri understands so user info / IPv6 / ports parse uniformly.
        if (!Uri.TryCreate("http" + s[schemeEnd..], UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host) ||
            (uri.AbsolutePath != "/" && uri.AbsolutePath != ""))
        {
            error = "Proxy: " + Example;
            return false;
        }

        string? user = null, pass = null;
        if (uri.UserInfo.Length > 0)
        {
            var colon = uri.UserInfo.IndexOf(':');
            user = Uri.UnescapeDataString(colon < 0 ? uri.UserInfo : uri.UserInfo[..colon]);
            pass = colon < 0 ? null : Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]);
        }

        var port = HasExplicitPort(s[(schemeEnd + 3)..]) ? uri.Port : kind == ProxyKind.Http ? 8080 : 1080;
        var host = uri.Host.Trim('[', ']');
        proxy = new ProxySettings(kind.Value, host, port, user, pass);
        return true;
    }

    public static ProxySettings Parse(string text) =>
        TryParse(text, out var proxy, out var error) ? proxy! : throw new FormatException(error);

    /// <summary>True if the text parses and carries a password (it is then encrypted on disk).</summary>
    public static bool HasPassword(string? text) =>
        !string.IsNullOrWhiteSpace(text) && TryParse(text, out var p, out _) && !string.IsNullOrEmpty(p!.Password);

    /// <summary>The URL with the password masked, for display.</summary>
    public override string ToString()
    {
        var scheme = Kind switch { ProxyKind.Socks4 => "socks4", ProxyKind.Socks5 => "socks5", _ => "http" };
        var auth = Username is null ? "" : Username + (Password is null ? "" : ":****") + "@";
        var host = Host.Contains(':') ? $"[{Host}]" : Host;
        return $"{scheme}://{auth}{host}:{Port}";
    }

    private static bool HasExplicitPort(string authority)
    {
        var at = authority.LastIndexOf('@');
        var hostPart = at >= 0 ? authority[(at + 1)..] : authority;
        hostPart = hostPart.TrimEnd('/');
        if (hostPart.StartsWith('[')) return hostPart.Contains("]:");
        return hostPart.Contains(':');
    }
}

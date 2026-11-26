using System.Text;
using SimpleSSH.Core.Models;

namespace SimpleSSH.Core.Rdp;

/// <summary>Helpers for Remote Desktop connections that don't need Windows UI (and so can be unit tested).</summary>
public static class RdpSettings
{
    /// <summary>
    /// Splits a Windows sign-in name into domain and user: "CONTOSO\ann" gives ("CONTOSO", "ann").
    /// "ann@contoso.com" and "ann" have no domain part. "AzureAD\ann@contoso.com" gives ("AzureAD", "ann@contoso.com").
    /// </summary>
    public static (string Domain, string User) SplitUser(string? username)
    {
        var name = (username ?? "").Trim();
        var slash = name.IndexOf('\\');
        if (slash <= 0 || slash == name.Length - 1) return ("", name);
        return (name[..slash], name[(slash + 1)..]);
    }

    /// <summary>The "full address" for mstsc: host, [IPv6] and :port when it isn't 3389.</summary>
    public static string FullAddress(Connection connection)
    {
        var host = connection.Host.Trim();
        if (host.Contains(':') && !host.StartsWith('[')) host = $"[{host}]";
        return connection.Port == Connection.RdpDefaultPort ? host : $"{host}:{connection.Port}";
    }

    /// <summary>Builds a minimal .rdp file for the Windows Remote Desktop client (mstsc.exe). It never contains a password.</summary>
    public static string BuildRdpFile(Connection connection)
    {
        static string Clean(string value) => value.Replace("\r", "").Replace("\n", "");
        var sb = new StringBuilder();
        void Line(string text) => sb.Append(text).Append("\r\n");

        Line($"full address:s:{Clean(FullAddress(connection))}");
        if (!string.IsNullOrWhiteSpace(connection.Username)) Line($"username:s:{Clean(connection.Username.Trim())}");
        Line("screen mode id:i:1");          // a window, like the tab; Ctrl+Alt+Break toggles full screen
        Line("dynamic resolution:i:1");      // the remote desktop follows the window size
        Line("authentication level:i:2");    // warn about unverified server certificates
        Line("prompt for credentials:i:0");
        Line("redirectclipboard:i:1");
        Line("autoreconnection enabled:i:1");
        return sb.ToString();
    }

    /// <summary>Credential Manager target that mstsc.exe looks up for saved passwords.</summary>
    public static string CredentialTarget(Connection connection) => "TERMSRV/" + connection.Host.Trim();

    /// <summary>
    /// Desktop scale factors the RDP protocol accepts, picked from the monitor's DPI scale (1.0 = 100 %).
    /// The device scale factor is 100, 140 or 180.
    /// </summary>
    public static (uint Desktop, uint Device) ScaleFactors(double dpiScale)
    {
        uint[] allowed = { 100, 125, 150, 175, 200, 250, 300, 400, 500 };
        var percent = dpiScale * 100;
        var desktop = allowed.OrderBy(a => Math.Abs(a - percent)).First();
        uint device = desktop < 125 ? 100u : desktop < 175 ? 140u : 180u;
        return (desktop, device);
    }

    /// <summary>Clamps a desktop size to what the RDP client accepts (200-8192, even width).</summary>
    public static (int Width, int Height) ClampDesktopSize(double width, double height)
    {
        var w = (int)Math.Clamp(Math.Floor(width + 0.01), 200, 8192) & ~1; // never wider than the space; RDP needs an even width
        var h = (int)Math.Clamp(Math.Floor(height + 0.01), 200, 8192);
        return (w, h);
    }

    /// <summary>
    /// Disconnect reasons that mean the session ended on purpose: closed here (1), or the remote user
    /// signed out or chose Disconnect (2). Anything else is a dropped or refused connection.
    /// </summary>
    public static bool IsNormalEnd(int disconnectReason) => disconnectReason is 1 or 2;
}

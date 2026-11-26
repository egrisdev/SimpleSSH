using System.Runtime.InteropServices;
using System.Windows;

namespace SimpleSSH.Services;

/// <summary>
/// Whether SimpleSSH is shown through Remote Desktop. Security keys mostly can't reach a remote session: Windows App
/// on a Mac, iPad or Android doesn't pass them on for apps, so unlocking asks for the recovery key instead.
/// </summary>
internal static class RemoteSession
{
    private const int WtsClientBuildNumber = 9;
    private const int WtsClientName = 10;
    private static readonly IntPtr CurrentServer = IntPtr.Zero;
    private const int CurrentSession = -1;

    /// <summary>True in a Remote Desktop session. <c>SIMPLESSH_REMOTE_SESSION=1</c> pretends so, for testing.</summary>
    public static bool IsActive =>
        SystemParameters.IsRemoteSession || Environment.GetEnvironmentVariable("SIMPLESSH_REMOTE_SESSION") == "1";

    /// <summary>"client MACBOOK, build 1234" for the log, or "" when unknown.</summary>
    public static string ClientDescription()
    {
        try
        {
            var name = QueryString(WtsClientName);
            var build = QueryUInt(WtsClientBuildNumber);
            var parts = new List<string>();
            if (!string.IsNullOrEmpty(name)) parts.Add("client " + name);
            if (build is > 0) parts.Add("build " + build);
            return string.Join(", ", parts);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return "";
        }
    }

    private static string? QueryString(int infoClass)
    {
        if (!WTSQuerySessionInformationW(CurrentServer, CurrentSession, infoClass, out var buffer, out _)) return null;
        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static uint? QueryUInt(int infoClass)
    {
        if (!WTSQuerySessionInformationW(CurrentServer, CurrentSession, infoClass, out var buffer, out var bytes)) return null;
        try
        {
            return bytes >= sizeof(uint) ? (uint)Marshal.ReadInt32(buffer) : null;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    [DllImport("wtsapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll", ExactSpelling = true)]
    private static extern void WTSFreeMemory(IntPtr memory);
}

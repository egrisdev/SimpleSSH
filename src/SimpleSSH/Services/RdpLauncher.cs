using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Rdp;

namespace SimpleSSH.Services;

/// <summary>
/// Opens a connection in the Windows Remote Desktop app (mstsc.exe): multi-monitor, RD Gateway, drive redirection
/// and everything else it supports. The saved password is handed over through Windows Credential Manager for this
/// Windows sign-in only, and never written to the .rdp file.
/// </summary>
internal static class RdpLauncher
{
    private const string OurComment = "Added by SimpleSSH for this Windows sign-in";

    public static async Task OpenAsync(Window? owner, Connection connection)
    {
        var store = AppServices.Connections;
        if (store.HasLockedSecrets(connection.Id) &&
            !await SecurityKeyUi.EnsureUnlockedAsync(owner, $"Unlock to connect to {connection.DisplayName}."))
            return;
        connection = store.Find(connection.Id) ?? connection;
        try
        {
            var dir = Path.Combine(Path.GetTempPath(), "SimpleSSH");
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, SafeFileName(connection.DisplayName) + ".rdp");
            await File.WriteAllTextAsync(file, RdpSettings.BuildRdpFile(connection));

            var credential = await AppServices.Credentials.ResolveAsync(connection);
            if (!string.IsNullOrWhiteSpace(credential.Username) && !string.IsNullOrEmpty(credential.Password))
                ShareCredential(RdpSettings.CredentialTarget(connection), credential.Username.Trim(), credential.Password);

            Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "mstsc.exe"), $"\"{file}\"")
            {
                UseShellExecute = false,
            });
        }
        catch (Exception ex)
        {
            Log.Error("Opening Remote Desktop failed", ex);
            MessageBox.Show(owner ?? Application.Current.MainWindow, $"Could not open Remote Desktop:\n{ex.Message}", "SimpleSSH",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string SafeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var safe = new string(name.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray()).Trim();
        return safe.Length == 0 ? "connection" : safe;
    }

    /// <summary>
    /// Stores the password where mstsc looks for it (TERMSRV/host), for this sign-in only (cleared at sign-out).
    /// A credential the user saved themselves in Remote Desktop is left alone.
    /// </summary>
    private static void ShareCredential(string target, string user, string password)
    {
        if (HasForeignCredential(target, CredTypeDomainPassword) || HasForeignCredential(target, CredTypeGeneric)) return;

        var blob = Marshal.StringToCoTaskMemUni(password);
        try
        {
            var cred = new NativeCredential
            {
                Type = CredTypeGeneric,
                TargetName = target,
                Comment = OurComment,
                CredentialBlobSize = password.Length * 2,
                CredentialBlob = blob,
                Persist = CredPersistSession,
                UserName = user,
            };
            if (!CredWrite(ref cred, 0))
                Log.Info($"CredWrite for {target} failed: {Marshal.GetLastWin32Error()}");
        }
        finally
        {
            // Wipe the unmanaged copy of the password before freeing it.
            for (int i = 0; i < password.Length * 2; i++) Marshal.WriteByte(blob, i, 0);
            Marshal.FreeCoTaskMem(blob);
        }
    }

    private static bool HasForeignCredential(string target, int type)
    {
        if (!CredRead(target, type, 0, out var ptr)) return false;
        try
        {
            var existing = Marshal.PtrToStructure<NativeCredential>(ptr);
            return existing.Comment != OurComment;
        }
        finally
        {
            CredFree(ptr);
        }
    }

    private const int CredTypeGeneric = 1;
    private const int CredTypeDomainPassword = 2;
    private const int CredPersistSession = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref NativeCredential credential, int flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}

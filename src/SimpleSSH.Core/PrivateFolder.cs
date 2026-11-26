using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SimpleSSH.Core;

/// <summary>
/// Keeps a data folder chosen with SIMPLESSH_DATA_DIR as private as %APPDATA% is. A folder made elsewhere (directly
/// on C:\, a shared drive) usually lets every user add or change files: someone else could then edit known hosts to
/// trust their own server, or point a connection at it so the saved password goes there.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PrivateFolder
{
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>
    /// Creates the folder if needed and, if anyone besides this user, SYSTEM and Administrators can change it, limits it
    /// (and what's inside, by inheritance) to those three. Returns true if the permissions were changed.
    /// </summary>
    /// <exception cref="IOException">The folder can't be created.</exception>
    /// <exception cref="UnauthorizedAccessException">The folder's permissions can't be read or changed.</exception>
    public static bool Secure(string path)
    {
        var dir = Directory.CreateDirectory(path);
        var me = WindowsIdentity.GetCurrent().User ?? throw new UnauthorizedAccessException("No Windows user.");
        if (!OthersCanWrite(dir.GetAccessControl(), me)) return false;

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[]
                 {
                     me,
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        dir.SetAccessControl(security);
        return true;
    }

    /// <summary>True if a user or group other than <paramref name="me"/>, SYSTEM or Administrators may change the folder.</summary>
    public static bool OthersCanWrite(DirectorySecurity security, SecurityIdentifier me)
    {
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & WriteRights) == 0) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid == me || sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid))
                continue;
            return true;
        }
        return false;
    }
}

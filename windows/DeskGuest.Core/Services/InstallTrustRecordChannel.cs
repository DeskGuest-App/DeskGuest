using System.Security.AccessControl;
using System.Security.Principal;
using DeskGuest.Shared.Ipc;

namespace DeskGuest.Core.Services;

/// <summary>
/// W28: the Core side of the install trust record (see
/// InstallTrust in DeskGuest.Shared for the design + the round-6
/// break it closes).
///
/// PROVISIONING — who writes the record, and the fresh-install
/// race: the INSTALLER (elevated) creates the trust directory
/// %ProgramData%\DeskGuest\trust\ before the service first starts and
/// ACLs it SYSTEM + Administrators full / console users
/// read+execute with NO create right, so a console user cannot
/// pre-create the record or its directory. THIS channel is the
/// writer of the record itself: the Core — running as SYSTEM in
/// the shipped shape — writes it on first run and RE-ASSERTS it
/// every boot, deriving its contents from the Core's own
/// identity key, the service-configured Agent path
/// (DESKGUEST_AGENT_EXE, set by the installer under the service's HKLM
/// key) and the Core's own image path. Existing record content
/// is never read or trusted here: a planted record is simply
/// overwritten by the genuine Core, and before the genuine Core
/// has ever run the Agent refuses planted records whose store is
/// not provably protected (InstallTrust.ClassifyStore) and
/// refuses an absent record outright — fail closed, named in
/// the status/audit vocabulary as install_trust_record:*.
///
/// The record is PUBLIC material (a public key + two paths), so
/// unlike the token channel it needs no secret-first write
/// ordering; what it needs is the ACL: on Windows the file is
/// written, then the plan (SYSTEM + Administrators full, console
/// user READ ONLY) is applied and the owner set to the writer
/// when the writer is privileged. If the ACL cannot be applied,
/// the record is REMOVED rather than left under the wrong ACL —
/// an unprotected record is worse than an absent one (absent
/// fails closed by name; unprotected might be trusted by a
/// reader that skips the store check).
///
/// CONSOLE-HOST (Path B): the Core runs AS the console user, so
/// it writes the record under that user's ownership with no
/// privileged ACL available. The status names that shape
/// (provisioned-console-host-named-limit): the record is only as
/// trustworthy as the account, and same-user impersonation is
/// NOT excluded there — the W25 named limit, unchanged.
/// </summary>
public static class InstallTrustRecordChannel
{
    /// <summary>Provision (or re-assert) the install trust record
    /// for this boot. Returns a status string for the audit log —
    /// metadata only. Never blocks Core startup: a failure leaves
    /// the Agent fail-closed against this Core, which is the
    /// intended posture, and the status names why.</summary>
    public static string Provision(string dataDir, CoreIdentityKey identity, string? agentExePath, string? coreExePath)
    {
        if (string.IsNullOrWhiteSpace(agentExePath) || string.IsNullOrWhiteSpace(coreExePath))
            return "install_trust_record:provision-refused:image-path-unestablishable";
        var record = new InstallTrustRecord(identity.PublicKey, agentExePath, coreExePath);
        var consoleSid = OperatingSystem.IsWindows() ? IpcTokenFileChannel.ResolveConsoleUserSid() : null;
        var plan = InstallTrust.BuildRecordAclPlan(consoleSid);
        string? writerSid = null;
        if (OperatingSystem.IsWindows())
        {
            try { writerSid = WindowsIdentity.GetCurrent().User?.Value; } catch { }
        }
        var targets = new List<string> { InstallTrust.RecordPathForDataDir(dataDir) };
        var fixedPath = InstallTrust.FixedRecordPath();
        if (!targets.Contains(fixedPath, StringComparer.OrdinalIgnoreCase)) targets.Add(fixedPath);
        var published = 0;
        string? firstFailure = null;
        foreach (var target in targets)
        {
            var status = ProvisionTo(target, record, plan,
                OperatingSystem.IsWindows() ? ApplyRecordAcl : null, writerSid);
            if (status.StartsWith("install_trust_record:provisioned", StringComparison.Ordinal)) published++;
            else firstFailure ??= status;
        }
        if (published == 0) return firstFailure ?? "install_trust_record:provision-failed:Unknown";
        var shape = string.Equals(writerSid, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase)
            ? "provisioned-service"
            : OperatingSystem.IsWindows() ? "provisioned-console-host-named-limit" : "provisioned:acl-not-applicable-off-windows";
        return $"install_trust_record:{shape}:published:{published}/{targets.Count}";
    }

    /// <summary>One target's write sequence, factored out with
    /// the ACL applier as a seam (null applier = no ACL exists on
    /// this host; the harness drives the ordering, the ACL
    /// failure removal, and the writer-shape naming off-Windows).</summary>
    internal static string ProvisionTo(string recordPath, InstallTrustRecord record,
        IReadOnlyList<IpcTokenFileAclEntry> plan,
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>>? applyAcl,
        string? writerSid)
    {
        try
        {
            var dir = Path.GetDirectoryName(recordPath);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
            IpcTokenFile.WriteAtomic(recordPath, InstallTrust.SerializeRecord(record));
        }
        catch (Exception ex)
        {
            return $"install_trust_record:provision-failed:{ex.GetType().Name}";
        }
        if (applyAcl is not null)
        {
            try { applyAcl(recordPath, plan); }
            catch (Exception ex)
            {
                // Fail closed: never leave a record resting under
                // an unverified ACL (the token channel's precedent).
                try { File.Delete(recordPath); } catch { }
                return $"install_trust_record:acl-failed-removed:{ex.GetType().Name}";
            }
        }
        return string.Equals(writerSid, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase)
            ? "install_trust_record:provisioned-service"
            : "install_trust_record:provisioned-console-host-named-limit";
    }

    /// <summary>The record file's Windows ACL: the Shared plan
    /// (SYSTEM + Administrators full control, console user READ
    /// ONLY), inheritance broken, owner set to SYSTEM when the
    /// writer is SYSTEM so ClassifyStore's owner test reads the
    /// truth on the Agent side.</summary>
    private static void ApplyRecordAcl(string path, IReadOnlyList<IpcTokenFileAclEntry> plan)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        try
        {
            var writer = WindowsIdentity.GetCurrent().User;
            if (writer is not null && string.Equals(writer.Value, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase))
                security.SetOwner(writer);
        }
        catch { /* owner stays the writer's — SYSTEM by construction in the service shape */ }
        foreach (var entry in plan)
        {
            var rights = entry.Rights switch
            {
                "FullControl" => FileSystemRights.FullControl,
                "Read" => FileSystemRights.Read,
                _ => entry.IsSystem ? FileSystemRights.FullControl : FileSystemRights.Read,
            };
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(entry.Sid), rights,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        }
        new FileInfo(path).SetAccessControl(security);
    }
}

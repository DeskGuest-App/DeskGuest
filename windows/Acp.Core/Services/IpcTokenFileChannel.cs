using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Acp.Shared.Ipc;

namespace Acp.Core.Services;

/// <summary>
/// W20: the Core side of the token file channel (see IpcTokenFile
/// in Acp.Shared for the design defence). At startup the Core
/// publishes its per-boot IPC token to &lt;dataDir&gt;/ipc-token.txt
/// — this REPLACES the BD-WIN-CORE-1 F1 behaviour of deleting a
/// stale file at startup: the delete was the rotation's first half
/// with no second half. Now every boot writes a FRESH token
/// atomically and ACLs the file to SYSTEM + the console user only;
/// a clean Core shutdown deletes it.
///
/// The ACL is applied from the pure plan in IpcTokenFile.BuildAclPlan
/// (pinned by unit tests). On a non-Windows host there is no ACL to
/// apply — the file is still written (the Linux test suite exercises
/// the rotation/read mechanics) and the returned status names the
/// posture honestly.
///
/// Audit vocabulary note: the status strings say "ipc_file_", never
/// "ipc_token_file_". Audit outcomes surface inside host-state
/// snapshots, and the destruction suite's standing tripwire bans the
/// word for the credential itself from those snapshots
/// (WiringDestructionTests endpoint-section check). The labels are
/// metadata, not material — conforming the vocabulary keeps the
/// tripwire at full strength instead of arguing an exception into
/// it. Same for the Hello audit: "ipc_source:file".
/// </summary>
public static class IpcTokenFileChannel
{
    /// <summary>Publish (rotate) the token file for this boot.
    /// Returns a status string for the audit log — metadata only,
    /// never the token. A failure NEVER blocks Core startup and
    /// never widens anything: the env channel still works, and a
    /// task-launched agent simply stays RefuseNoToken, as before.
    ///
    /// W22 ORDER (round-4 — the pre-fix shape wrote the
    /// secret FIRST and resolved the ACL plan afterwards, so the
    /// null-plan return left the token on disk under inherited
    /// ACLs, and even the happy path held the secret in an
    /// inherited-ACL temp file before ApplyAcl ran):
    /// 1) the plan is resolved FIRST — on Windows a null plan
    ///    refuses by name and NOTHING is written;
    /// 2) the write is IpcTokenFile.WriteAtomicProtected: temp
    ///    created empty, plan ACL applied to the temp, secret bytes
    ///    land only into the already-protected temp, then the move;
    /// 3) every failure path deletes — the temp inside
    ///    WriteAtomicProtected, the target here whenever a step
    ///    after the move fails. The invariant is: no secret bytes
    ///    ever rest under a non-plan ACL.</summary>
    public static string Publish(string dataDir, string token)
    {
        var path = IpcTokenFile.DefaultPath(dataDir);
        var consoleSid = OperatingSystem.IsWindows() ? ResolveConsoleUserSid() : null;
        var plan = IpcTokenFile.BuildAclPlan(consoleSid);
        if (!OperatingSystem.IsWindows())
        {
            // No ACL exists to apply on this host — the file is
            // still written (the Linux test suite exercises the
            // rotation/read mechanics) and the status names the
            // posture honestly. Production is Windows-only.
            try { IpcTokenFile.WriteAtomic(path, token); }
            catch (Exception ex) { return $"ipc_file_write_failed:{ex.GetType().Name}"; }
            return "ipc_file_published:acl-not-applicable-off-windows";
        }
        string? writerSid = null;
        try { writerSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; } catch { }
        return PublishWindows(path, token, plan, consoleSid, ApplyAcl, writerSid);
    }

    /// <summary>The Windows publish sequence, factored out with the
    /// ACL applier as a seam so the harness can drive the ORDER and
    /// every failure injection off-Windows (the production applier
    /// is ApplyAcl; tests substitute recording/throwing appliers
    /// and inspect the directory afterwards — the destruction pin
    /// for the W22 invariant). The null-plan refusal lives HERE,
    /// ahead of any write, so the seam pins it too.</summary>
    internal static string PublishWindows(string path, string token,
        IReadOnlyList<IpcTokenFileAclEntry>? plan, string? consoleSid,
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>> applyAcl,
        string? writerSid = null)
    {
        if (plan is null)
            return "ipc_file_acl_refused:no-console-user-sid";
        try
        {
            WriteProtected(path, token, plan, applyAcl, writerSid);
        }
        catch (UnauthorizedAccessException) when (File.Exists(path))
        {
            // Self-healing rotation (W20 live finding): a previous
            // boot's file may carry an ACL the current writer cannot
            // replace (the console-host Core runs AS the console
            // user). The file's OWNER can always re-ACL it — repair
            // the ACL from the plan, then retry the protected write
            // exactly once.
            try
            {
                applyAcl(path, plan);
                WriteProtected(path, token, plan, applyAcl, writerSid);
            }
            catch (Exception ex)
            {
                return $"ipc_file_write_failed:{ex.GetType().Name}";
            }
        }
        catch (Exception ex)
        {
            return $"ipc_file_write_failed:{ex.GetType().Name}";
        }
        try
        {
            // The move already carried the temp's plan ACL onto the
            // target; this re-application is the verification step
            // that closes any filesystem quirk in that carry.
            applyAcl(path, plan);
            return $"ipc_file_published:acl=system+console-user:{consoleSid}";
        }
        catch (Exception ex)
        {
            // Remove the file rather than leave a secret whose ACL
            // could not be verified as the plan (the pipe-ACL
            // fail-closed precedent).
            IpcTokenFile.Delete(path);
            return $"ipc_file_acl_failed_removed:{ex.GetType().Name}";
        }
    }

    /// <summary>W25 item 5 — the console-host rotation break,
    /// VERIFIED REAL by construction: the plan grants the console
    /// SID Read|Delete only. In the console-host shape the Core
    /// runs AS that SID, so once WriteAtomicProtected applied the
    /// plan ACL to the temp file, the Core's own next step —
    /// writing the secret into that temp — was refused by its own
    /// ACL (the writer held no Write right on the file it had just
    /// protected). The service shape never saw it (SYSTEM holds
    /// FullControl under the plan); the console-host shape could
    /// not rotate at all. The W20 owner-repair retry could not save
    /// it either: the retry re-ran the same self-blocking write.
    ///
    /// The fix is the owner-based re-ACL around the Core's own
    /// write: when the WRITER is a non-SYSTEM identity (the
    /// console-host shape), the temp's first ACL is the plan PLUS
    /// a Write grant for the writer's own SID — the minimum the
    /// writer needs to land the secret into its own file. The
    /// instant the secret has landed, the STRICT plan is
    /// re-applied to the temp (WriteAtomicProtected's
    /// afterSecretWritten step), so the file that moves onto the
    /// target — and the target's verification re-application —
    /// carries exactly the plan, never the augmented grant. The
    /// augmented window exposes nothing new: the writer identity
    /// in this shape is the console user, who already holds Read
    /// on the token under the plan itself; Write adds no read
    /// capability, and the window is one temp file in the Core's
    /// data dir for the duration of one write.</summary>
    private static void WriteProtected(string path, string token, IReadOnlyList<IpcTokenFileAclEntry> plan,
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>> applyAcl, string? writerSid)
    {
        var writerNeedsSelfWrite = !string.IsNullOrWhiteSpace(writerSid) &&
            !string.Equals(writerSid, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase);
        if (!writerNeedsSelfWrite)
        {
            IpcTokenFile.WriteAtomicProtected(path, token, tmp => applyAcl(tmp, plan));
            return;
        }
        var augmented = plan.Concat(new[]
        {
            new IpcTokenFileAclEntry(writerSid!, "ReadAndDeleteWrite", IsSystem: false),
        }).ToArray();
        IpcTokenFile.WriteAtomicProtected(path, token,
            tmp => applyAcl(tmp, augmented),
            tmp => applyAcl(tmp, plan));
    }

    /// <summary>Clean-shutdown removal (best-effort).</summary>
    public static void Remove(string dataDir) => IpcTokenFile.Delete(IpcTokenFile.DefaultPath(dataDir));

    private static void ApplyAcl(string path, IReadOnlyList<IpcTokenFileAclEntry> plan)
    {
        var security = new FileSecurity();
        // Break inheritance: the plan is the WHOLE readership.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var entry in plan)
        {
            // W25: rights come from the plan entry's own vocabulary
            // (the W25 self-write grant needs Read|Delete|Write to
            // exist as a value); the pre-W25 IsSystem ternary could
            // only ever express FullControl vs Read|Delete.
            var rights = entry.Rights switch
            {
                "FullControl" => FileSystemRights.FullControl,
                "ReadAndDeleteWrite" => FileSystemRights.Read | FileSystemRights.Delete | FileSystemRights.Write,
                "Write" => FileSystemRights.Write,
                _ => entry.IsSystem ? FileSystemRights.FullControl : FileSystemRights.Read | FileSystemRights.Delete,
            };
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(entry.Sid), rights,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        }
        new FileInfo(path).SetAccessControl(security);
    }

    /// <summary>The console user's SID, from the OS: the active
    /// console session's user token (the same source the IPC
    /// identity check uses). When the Core runs as the console user
    /// itself (console-host shape) that IS the current identity.
    /// As SYSTEM (service shape) the current identity is SYSTEM —
    /// never granted as the "console user"; the session token is
    /// the only honest source, and ACP_LOGON_USER's account is the
    /// named fallback the installer already configures.</summary>
    public static string? ResolveConsoleUserSid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var session = Native.WTSGetActiveConsoleSessionId();
            if (session != 0xFFFFFFFF && Native.WTSQueryUserToken(session, out var token))
            {
                using (token)
                {
                    var sid = new WindowsIdentity(token.DangerousGetHandle()).User?.Value;
                    if (!string.IsNullOrWhiteSpace(sid)) return sid;
                }
            }
        }
        catch { /* fall through to the named fallbacks */ }
        try
        {
            var current = WindowsIdentity.GetCurrent().User?.Value;
            if (!string.IsNullOrWhiteSpace(current) &&
                !string.Equals(current, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase))
                return current;
        }
        catch { }
        try
        {
            var logonUser = Environment.GetEnvironmentVariable("ACP_LOGON_USER");
            if (!string.IsNullOrWhiteSpace(logonUser))
                return new NTAccount(logonUser).Translate(typeof(SecurityIdentifier)) is SecurityIdentifier sid
                    ? sid.Value : null;
        }
        catch { }
        return null;
    }

    private static class Native
    {
        [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSQueryUserToken(uint sessionId, out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token);
    }
}

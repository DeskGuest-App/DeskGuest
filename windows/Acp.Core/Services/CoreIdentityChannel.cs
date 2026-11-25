using System.Security.AccessControl;
using System.Security.Principal;
using Acp.Shared.Ipc;
using Acp.Shared.Security;

namespace Acp.Core.Services;

/// <summary>
/// W25: the Core side of the Core identity (see CoreIdentity in
/// Acp.Shared for the design + the named console-host limit).
///
/// Load-or-create: the identity seed persists in the Core data
/// dir as core-identity.key, wrapped by the runtime
/// ISecretProtector exactly like the device identity store — the
/// raw seed never touches disk. On Windows the key file carries
/// the BuildKeyFileAclPlan ACL (SYSTEM + Administrators only, NO
/// console-user principal): in the shipped service shape the
/// console user cannot read the seed, so a fake Core running as
/// that user cannot sign the handshake. A corrupt store mints a
/// fresh identity (and the pin is re-published) rather than
/// failing Core startup — a rotated identity is an owner-visible
/// re-pairing-class event, audited by the caller from the status
/// string, never silent.
///
/// The PUBLIC key is published as the Agent's install pin:
/// core-identity.pub beside the Agent's image (the install
/// record — the Core knows the agent's path from its options,
/// and in the co-located sanctioned shape that is also beside
/// the Core) and beside the Core's own image. Publishing the pin
/// is a Core act at startup; a console-user process cannot
/// rewrite the install-directory copy in the shipped shape.
///
/// CONSOLE-HOST LIMIT (named in CoreIdentity's doc, repeated here
/// because this is where the key is held): when the Core runs AS
/// the console user, that user can read this file whatever the
/// ACL says — the ACL grants their own account's administrators/
/// owner routes and the process itself runs as them. The ACL is
/// still applied (it excludes every OTHER non-admin principal),
/// but same-user impersonation is not excluded in that shape.
///
/// W43 (F1) — the console-host self-lockout, found live on the
/// v20 redeploy: the strict plan grants the console-host WRITER
/// nothing, and a non-elevated console process cannot use the
/// Administrators ACE, so the Core could neither READ its own
/// store (the read threw UnauthorizedAccessException and the
/// catch-all mislabelled a healthy DPAPI store "corrupt") nor
/// REPLACE it (the persist threw the same). The identity rotated
/// every boot. The fix follows the W25 token-channel discipline:
///   * the ACL plan is WRITER-AWARE (CoreIdentity.
///     BuildKeyFileAclPlan(writerSid)): the service shape keeps
///     the strict SYSTEM + Administrators plan exactly; the
///     console-host shape adds the writer's own SID — the one
///     principal the named limit already concedes — and no one
///     else;
///   * a read that fails with UnauthorizedAccessException is
///     named INACCESSIBLE, not corrupt, and first triggers an
///     owner repair: the file's owner can always re-ACL it
///     (WRITE_DAC is the owner's implicit right), so the plan is
///     re-applied to the existing file and the read retried ONCE.
///     A legitimately formatted older store then LOADS — it is
///     migrated in place, not rotated. The attempt-1-era live
///     store is exactly this case: same DPAPI CurrentUser format
///     this build writes, unreadable only because of the ACL;
///   * the persist itself is the token channel's protected
///     shape: owner repair of any existing file first, then
///     IpcTokenFile.WriteAtomicProtected — temp created empty,
///     plan ACL applied, secret lands, strict plan re-applied,
///     atomic move — and a final plan re-application on the
///     target as verification. A genuinely corrupt store is
///     therefore REPLACEABLE durably under the shipped posture,
///     and the same public key survives the next boot.
/// </summary>
public static class CoreIdentityChannel
{
    /// <summary>Load the persisted identity, or mint + persist a
    /// fresh one. Returns the key and a status string for the
    /// audit log (metadata only — never key material).</summary>
    public static (CoreIdentityKey Identity, string Status) LoadOrCreate(
        string dataDir, ISecretProtector protector, string? agentExePath)
    {
        if (!OperatingSystem.IsWindows())
            return LoadOrCreate(dataDir, protector, agentExePath, applyAcl: null, writerSid: null);
        string? writerSid = null;
        try { writerSid = WindowsIdentity.GetCurrent().User?.Value; } catch { }
        return LoadOrCreate(dataDir, protector, agentExePath, ApplyAclFromPlan, writerSid);
    }

    /// <summary>The seam form (the IpcTokenFileChannel.
    /// PublishWindows pattern): the ACL applier and the writer's
    /// SID are parameters so the harness can drive the ACL plan
    /// sequence and the file mechanics off-Windows. A null applier
    /// is the off-Windows shape: no ACL exists to apply and the
    /// persist is a plain protected-shape atomic write.</summary>
    internal static (CoreIdentityKey Identity, string Status) LoadOrCreate(
        string dataDir, ISecretProtector protector, string? agentExePath,
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>>? applyAcl, string? writerSid,
        Func<string, string>? readText = null)
    {
        readText ??= File.ReadAllText;
        var keyPath = Path.Combine(dataDir, CoreIdentity.PrivateKeyFileName);
        var plan = CoreIdentity.BuildKeyFileAclPlan(writerSid);
        CoreIdentityKey? restored = null;
        var existed = File.Exists(keyPath);
        string? loadFailure = null; // "corrupt" | "inaccessible"
        if (existed)
        {
            string? wrapped = null;
            try { wrapped = readText(keyPath).Trim(); }
            catch (UnauthorizedAccessException)
            {
                // W43: an access-denied read is NOT corruption.
                // Owner repair (the owner can always WRITE_DAC):
                // re-apply the writer-aware plan to the existing
                // file, then retry the read exactly once. A store
                // that then reads + unprotects LOADS — an older
                // legitimately formatted key migrates, it does not
                // rotate.
                if (applyAcl is not null)
                {
                    try
                    {
                        applyAcl(keyPath, plan);
                        wrapped = readText(keyPath).Trim();
                    }
                    catch { wrapped = null; }
                }
                if (wrapped is null) loadFailure = "inaccessible";
            }
            catch { loadFailure = "corrupt"; }
            if (wrapped is not null)
            {
                try
                {
                    var plain = protector.Unprotect(wrapped);
                    restored = CoreIdentityKey.ImportSeedBase64(plain.Trim());
                }
                catch { loadFailure = "corrupt"; }
            }
        }
        var identity = restored ?? CoreIdentityKey.Generate();
        var status = restored is not null
            ? "ipc_core_identity:loaded"
            : existed
                ? loadFailure == "inaccessible"
                    ? "ipc_core_identity:rotated-inaccessible-store"
                    : "ipc_core_identity:rotated-corrupt-store"
                : "ipc_core_identity:minted";
        if (restored is null)
        {
            try
            {
                PersistKeyFile(keyPath, protector.Protect(identity.ExportSeedBase64()), applyAcl, plan);
            }
            catch (Exception ex)
            {
                // The identity still works for THIS boot (the
                // Agent will refuse a Core whose pin it cannot
                // match after a restart — fail closed, named here).
                status += $":persist-failed:{ex.GetType().Name}";
            }
        }
        // Publish the pin: beside the Agent (its install record),
        // beside the Core's own image, and in the data dir for
        // operator inspection. A failed publish is named in the
        // status — the Agent fails closed against a Core whose
        // pin it does not hold, which is the intended posture.
        var pin = identity.PublicKeyBase64;
        var published = new List<string>();
        var pinTargets = new List<string>();
        if (!string.IsNullOrWhiteSpace(agentExePath) && Path.GetDirectoryName(agentExePath) is { } agentDir)
            pinTargets.Add(Path.Combine(agentDir, CoreIdentity.PinFileName));
        if (Environment.ProcessPath is { } ownExe && Path.GetDirectoryName(ownExe) is { } ownDir)
            pinTargets.Add(Path.Combine(ownDir, CoreIdentity.PinFileName));
        pinTargets.Add(Path.Combine(dataDir, CoreIdentity.PinFileName));
        foreach (var target in pinTargets.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try { File.WriteAllText(target, pin); published.Add(target); }
            catch { /* named below by omission */ }
        }
        status += published.Count > 0
            ? $":pin-published:{published.Count}"
            : ":pin-publish-failed";
        return (identity, status);
    }

    /// <summary>W43: persist the wrapped seed so a store the
    /// loader judged corrupt (or inaccessible) can be REPLACED
    /// durably under the shipped ACL posture — the token
    /// channel's W22/W25 discipline, in order:
    /// 1) owner repair: re-apply the writer-aware plan to any
    ///    EXISTING file first (the owner can always WRITE_DAC, so
    ///    this is the step that unlocks the replacement — its
    ///    failure is swallowed because the write below is the
    ///    verdict that gets named);
    /// 2) WriteAtomicProtected: temp created EMPTY, plan applied
    ///    to the temp, secret bytes land only into the protected
    ///    temp, plan re-applied, atomic move over the target;
    /// 3) the plan re-applied to the target as verification — a
    ///    throw here names the persist failed rather than leaving
    ///    a store whose ACL could not be verified as the plan.</summary>
    private static void PersistKeyFile(string keyPath, string protectedText,
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>>? applyAcl,
        IReadOnlyList<IpcTokenFileAclEntry> plan)
    {
        if (applyAcl is null)
        {
            // Off-Windows: no ACL to apply — the harness exercises
            // the persistence mechanics and the status names the
            // shape (as before).
            IpcTokenFile.WriteAtomicProtected(keyPath, protectedText, protectTempFile: null);
            return;
        }
        if (File.Exists(keyPath))
        {
            try { applyAcl(keyPath, plan); } catch { /* step 2 is the verdict */ }
        }
        IpcTokenFile.WriteAtomicProtected(keyPath, protectedText,
            tmp => applyAcl(tmp, plan),
            tmp => applyAcl(tmp, plan));
        applyAcl(keyPath, plan);
    }

    /// <summary>The key file's Windows ACL from a plan: every
    /// entry FullControl, inheritance broken, nothing else — no
    /// principal outside the plan can be granted here, by
    /// construction of the plan.</summary>
    private static void ApplyAclFromPlan(string path, IReadOnlyList<IpcTokenFileAclEntry> plan)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var entry in plan)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(entry.Sid), FileSystemRights.FullControl,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        }
        new FileInfo(path).SetAccessControl(security);
    }
}

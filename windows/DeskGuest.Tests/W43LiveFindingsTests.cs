using DeskGuest.Core;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>Wave 43 Lane A — the two live findings from the v20
/// redeploy (log-laneW42-v20retry §5).
///
/// F1: the Core identity store rotated every boot —
/// `ipc_core_identity:rotated-corrupt-store:persist-failed:
/// UnauthorizedAccessException:pin-published:2`. Diagnosis
/// (probed pre-fix in this lane): the key file's ACL plan
/// (SYSTEM + Administrators, FullControl) grants the console-host
/// WRITER nothing; a non-elevated console process cannot use the
/// Administrators ACE and ownership alone grants no read/write,
/// so (a) the attempt-1 store's READ was access-denied and the
/// catch-all mislabelled a healthy DPAPI store "corrupt", and
/// (b) the bare File.WriteAllText persist had no recovery — no
/// owner re-ACL, no temp+move — and threw the same exception.
/// The store's FORMAT never changed (DPAPI CurrentUser wrapped
/// seed, written by the same W25 code in attempt 1), so a
/// legitimately formatted older key must LOAD once readable
/// again (migrate), not rotate.
///
/// F2: boot 1's pointer_signing_posture append verified in
/// memory but never became durable (persisted chain ended at the
/// previous entry, zero "pointer" entries); boot 2's landed.
/// Diagnosis: EnterpriseService.SaveChain was unlocked, exported
/// outside any ordering, and wrote through ONE shared tmp path —
/// overlapping saves (composition appends racing the background
/// services composition started) could interleave, throw, or
/// move an older export over a newer one while both reported
/// "ok"; and the W35 landing check read only memory + the
/// last-save flag, so the loss was invisible in-process. The
/// concurrency probe in this file failed against the pre-fix
/// code (persistence state BROKEN / entries lost) and the
/// single-threaded path passed — the defect was ordering, not
/// the append itself.</summary>
public class W43LiveFindingsTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string OtherSid = "S-1-5-21-1000-1000-1000-1999";
    private static readonly DevOnlyPassThroughProtector Protector = new();

    private static Action<string, IReadOnlyList<IpcTokenFileAclEntry>> Recording(
        List<(string Path, IReadOnlyList<IpcTokenFileAclEntry> Plan)> sink) =>
        (p, pl) => { lock (sink) sink.Add((p, pl.ToArray())); };

    // ---- F1 ----------------------------------------------------

    [Fact]
    public void F1_CorruptStore_ConsoleWriter_PersistsDurably_SameKeyAcrossTwoBoots()
    {
        var dir = TestUtil.TempDir();
        var keyPath = Path.Combine(dir, CoreIdentity.PrivateKeyFileName);
        // (a) a key file the loader judges corrupt.
        File.WriteAllText(keyPath, "attempt-1-era garbage, not a wrapped seed");
        var applications = new List<(string Path, IReadOnlyList<IpcTokenFileAclEntry> Plan)>();
        var applier = Recording(applications);

        // (b) persist attempted under the data-dir ACL plan as
        // the console-host Core's identity (writer = ConsoleSid).
        var (first, status1) = CoreIdentityChannel.LoadOrCreate(
            dir, Protector, null, applier, ConsoleSid);
        Assert.StartsWith("ipc_core_identity:rotated-corrupt-store", status1);
        Assert.DoesNotContain("persist-failed", status1);
        Assert.Contains("pin-published", status1);
        // The replacement is on disk, protector-wrapped.
        Assert.True(File.Exists(keyPath));
        Assert.NotEqual("attempt-1-era garbage, not a wrapped seed", File.ReadAllText(keyPath));

        // The stability property: the SAME public key across the
        // next boot, loaded — not rotated again.
        var (second, status2) = CoreIdentityChannel.LoadOrCreate(
            dir, Protector, null, applier, ConsoleSid);
        Assert.StartsWith("ipc_core_identity:loaded", status2);
        Assert.Equal(first.PublicKeyBase64, second.PublicKeyBase64);

        // ACL sequence: owner repair of the existing file, plan
        // on the temp BEFORE the move, plan re-applied on the
        // target after it — and every plan is exactly the
        // writer-aware plan (SYSTEM + Administrators + the writer,
        // FullControl; no other principal ever appears).
        var expected = CoreIdentity.BuildKeyFileAclPlan(ConsoleSid);
        Assert.Equal(3, expected.Count);
        Assert.NotEmpty(applications);
        Assert.All(applications, a =>
        {
            Assert.Equal(expected.Count, a.Plan.Count);
            Assert.All(a.Plan, e => Assert.Equal("FullControl", e.Rights));
            Assert.DoesNotContain(a.Plan, e => e.Sid == OtherSid);
        });
        Assert.Contains(applications, a => a.Path == keyPath);
        Assert.Contains(applications, a => a.Path.Contains(".tmp-"));
        // Target's LAST application is the plan (verification).
        Assert.Equal(keyPath, applications.Last(a => a.Path == keyPath).Path);
    }

    [Fact]
    public void F1_InaccessibleStore_OwnerRepair_LoadsOriginalKey_NoRotation()
    {
        // A legitimately formatted store whose READ is
        // access-denied (the live attempt-1 file): the verdict
        // must not be "corrupt", the owner repair must run, and
        // the ORIGINAL key must load — migration, not rotation.
        var dir = TestUtil.TempDir();
        var (original, mintStatus) = CoreIdentityChannel.LoadOrCreate(dir, Protector, null);
        Assert.StartsWith("ipc_core_identity:minted", mintStatus);

        var order = new List<string>();
        var reads = 0;
        Func<string, string> readText = path =>
        {
            lock (order)
            {
                reads++;
                order.Add("read" + reads);
                if (reads == 1) throw new UnauthorizedAccessException("simulated ACL denial (W43 probe)");
            }
            return File.ReadAllText(path);
        };
        Action<string, IReadOnlyList<IpcTokenFileAclEntry>> applier = (p, pl) =>
        {
            lock (order) order.Add("acl:" + Path.GetFileName(p));
        };
        var (loaded, status) = CoreIdentityChannel.LoadOrCreate(
            dir, Protector, null, applier, ConsoleSid, readText);
        Assert.StartsWith("ipc_core_identity:loaded", status);
        Assert.Equal(original.PublicKeyBase64, loaded.PublicKeyBase64);
        // Repair happened BETWEEN the denied read and the retry.
        Assert.Equal(new[] { "read1", "acl:core-identity.key", "read2" }, order);
    }

    [Fact]
    public void F1_InaccessibleStore_RepairCannotHelp_NamedInaccessible_NotCorrupt()
    {
        var dir = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir, CoreIdentity.PrivateKeyFileName),
            Protector.Protect(CoreIdentityKey.Generate().ExportSeedBase64()));
        Func<string, string> alwaysDenied = _ => throw new UnauthorizedAccessException("denied");
        var applications = new List<(string Path, IReadOnlyList<IpcTokenFileAclEntry> Plan)>();
        var (_, status) = CoreIdentityChannel.LoadOrCreate(
            dir, Protector, null, Recording(applications), ConsoleSid, alwaysDenied);
        Assert.StartsWith("ipc_core_identity:rotated-inaccessible-store", status);
        Assert.DoesNotContain("corrupt", status);
    }

    [Fact]
    public void F1_FreshStore_Minted_Persists_LoadedNextBoot()
    {
        var dir = TestUtil.TempDir();
        var (first, s1) = CoreIdentityChannel.LoadOrCreate(dir, Protector, null);
        Assert.StartsWith("ipc_core_identity:minted", s1);
        Assert.DoesNotContain("persist-failed", s1);
        var (second, s2) = CoreIdentityChannel.LoadOrCreate(dir, Protector, null);
        Assert.StartsWith("ipc_core_identity:loaded", s2);
        Assert.Equal(first.PublicKeyBase64, second.PublicKeyBase64);
    }

    [Fact]
    public void F1_ServiceShape_WriterIsSystem_PlanStaysStrict_NoConsoleGrant()
    {
        var dir = TestUtil.TempDir();
        var applications = new List<(string Path, IReadOnlyList<IpcTokenFileAclEntry> Plan)>();
        var (_, status) = CoreIdentityChannel.LoadOrCreate(
            dir, Protector, null, Recording(applications), IpcTokenFile.SystemSid);
        Assert.StartsWith("ipc_core_identity:minted", status);
        Assert.DoesNotContain("persist-failed", status);
        var strict = CoreIdentity.BuildKeyFileAclPlan();
        Assert.Equal(2, strict.Count);
        Assert.NotEmpty(applications);
        Assert.All(applications, a =>
        {
            Assert.Equal(strict.Count, a.Plan.Count);
            Assert.DoesNotContain(a.Plan, e => e.Sid == ConsoleSid);
            Assert.DoesNotContain(a.Plan, e => e.Sid == OtherSid);
        });
    }

    [Fact]
    public void F1_WriterAwarePlan_OnlyTheWriterIsAdded()
    {
        var plan = CoreIdentity.BuildKeyFileAclPlan(ConsoleSid);
        Assert.Equal(3, plan.Count);
        Assert.Contains(plan, e => e.Sid == IpcTokenFile.SystemSid && e.Rights == "FullControl");
        Assert.Contains(plan, e => e.Sid == CoreIdentity.AdministratorsSid && e.Rights == "FullControl");
        Assert.Contains(plan, e => e.Sid == ConsoleSid && e.Rights == "FullControl");
        // Null / SYSTEM / Administrators writers keep the strict plan.
        Assert.Equal(2, CoreIdentity.BuildKeyFileAclPlan(null).Count);
        Assert.Equal(2, CoreIdentity.BuildKeyFileAclPlan(IpcTokenFile.SystemSid).Count);
        Assert.Equal(2, CoreIdentity.BuildKeyFileAclPlan(CoreIdentity.AdministratorsSid).Count);
    }

    // ---- F2 ----------------------------------------------------

    private static CoreRuntime Compose(string dir, int port)
    {
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install");
        Directory.CreateDirectory(install);
        return new CoreRuntime(new CoreOptions
        {
            DataDir = dataDir, Port = port, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
        });
    }

    [Fact]
    public void F2_PostureAppends_DurableAcrossImmediateRestart()
    {
        // Append during composition, simulate restart, find the
        // entries — read from the PERSISTED chain, not memory.
        var dir = TestUtil.TempDir();
        var runtime = Compose(dir, 18961);
        Assert.Equal("recorded:pointer_signing_posture", runtime.PointerSigningPostureAuditState);
        Assert.Equal("recorded:update_signing_posture", runtime.UpdateSigningPostureAuditState);
        Assert.True(runtime.Enterprise.ChainEntryIsDurable("pointer_signing_posture"));
        Assert.True(runtime.Enterprise.ChainEntryIsDurable("update_signing_posture"));

        var dataDir = Path.Combine(dir, "data");
        var restarted = new EnterpriseService(dataDir,
            new RosterService(new EnrollmentService()), protector: Protector);
        Assert.True(restarted.RestoreVerdict.Ok, restarted.RestoreVerdict.Summary);
        Assert.Contains(restarted.AuditLog.Entries, e => e.Kind == "pointer_signing_posture");
        Assert.Contains(restarted.AuditLog.Entries, e => e.Kind == "update_signing_posture");
    }

    [Fact]
    public void F2_ConcurrentAppends_PersistedChainMatchesMemory()
    {
        // The pre-fix race, as a standing regression: a large
        // chain (slow saves) + concurrent appenders — the shape
        // composition creates when background services append
        // while composition does. Post-fix ordering is explicit
        // (chain gate + export-at-save + unique tmp + fsync), so
        // the persisted chain must equal the in-memory chain.
        var dir = TestUtil.TempDir();
        var svc = new EnterpriseService(dir, new RosterService(new EnrollmentService()));
        var big = new string('x', 8192);
        for (var i = 0; i < 300; i++) svc.AppendServiceAudit("seed_kind", "SYSTEM", big + i);
        const int Threads = 8, PerThread = 25;
        var errors = new List<Exception>();
        var threads = Enumerable.Range(0, Threads).Select(t => new Thread(() =>
        {
            try
            {
                for (var i = 0; i < PerThread; i++)
                    svc.AppendServiceAudit("probe_kind", "SYSTEM", $"t{t}-{i}");
            }
            catch (Exception ex) { lock (errors) errors.Add(ex); }
        })).ToList();
        foreach (var th in threads) th.Start();
        foreach (var th in threads) th.Join();
        Assert.Empty(errors);
        Assert.Equal("ok", svc.ChainPersistenceState);
        var inMemory = svc.AuditLog.Entries.Count(e => e.Kind == "probe_kind");
        Assert.Equal(Threads * PerThread, inMemory);
        var restarted = new EnterpriseService(dir, new RosterService(new EnrollmentService()));
        Assert.True(restarted.RestoreVerdict.Ok, restarted.RestoreVerdict.Summary);
        Assert.Equal(inMemory, restarted.AuditLog.Entries.Count(e => e.Kind == "probe_kind"));
        Assert.Equal(svc.AuditLog.Entries.Count, restarted.AuditLog.Entries.Count);
        Assert.Equal(svc.AuditLog.HeadHash, restarted.AuditLog.HeadHash);
        // No stray tmp files survive any save.
        Assert.Empty(Directory.GetFiles(dir, "enterprise-audit.json.tmp-*"));
    }

    [Fact]
    public void F2_ChainEntryIsDurable_FalseForMissingKind_AndMissingStore()
    {
        var dir = TestUtil.TempDir();
        var svc = new EnterpriseService(dir, new RosterService(new EnrollmentService()));
        Assert.False(svc.ChainEntryIsDurable("pointer_signing_posture"));
        svc.AppendServiceAudit("pointer_signing_posture", "SYSTEM", "x");
        Assert.True(svc.ChainEntryIsDurable("pointer_signing_posture"));
        Assert.False(svc.ChainEntryIsDurable("never_appended_kind"));
    }

    [Fact]
    public void F2_PostureAuditStates_ObservableOnHostStateSurface()
    {
        var runtime = Compose(TestUtil.TempDir(), 18962);
        var json = runtime.BuildHostStateJson();
        Assert.Contains("\"pointerSigningPostureAudit\":\"recorded:pointer_signing_posture\"", json);
        Assert.Contains("\"updateSigningPostureAudit\":\"recorded:update_signing_posture\"", json);
    }

    [Fact]
    public void F2_HostStateSnapshot_FailedStatesRideTheEnterpriseSection()
    {
        // Pure shaping: a FAILED state supplied to the snapshot
        // appears verbatim in the enterprise section — the
        // surface carries the state, it does not recompute it.
        var json = HostStateSnapshot.Build(
            coreVersion: "0.0.0", machineName: "test", port: 1,
            runningLanes: Array.Empty<string>(), agentConnected: false,
            desktopUnlocked: false, userStopInForce: false,
            session: new HostStateSnapshot.SessionFacts(false, null, 0, 0, null),
            pairings: Array.Empty<DeskGuest.Shared.Security.Pairing>(),
            gatedClasses: Array.Empty<string>(), approvedGates: new HashSet<string>(),
            auditTail: Array.Empty<DeskGuest.Shared.Audit.AuditEntry>(),
            enterprise: new HostStateSnapshot.EnterpriseFact(
                PolicyState: "none", PolicyLoaded: false, ChainOk: true,
                ChainSummary: "OK", AlertCount: 0, BreakGlassRotationRequired: false,
                RealIdpBoundary: "n/a",
                PointerSigningPostureAuditState: "FAILED: pointer (probe)",
                UpdateSigningPostureAuditState: "FAILED: update (probe)"));
        Assert.Contains("\"pointerSigningPostureAudit\":\"FAILED: pointer (probe)\"", json);
        Assert.Contains("\"updateSigningPostureAudit\":\"FAILED: update (probe)\"", json);
    }
}

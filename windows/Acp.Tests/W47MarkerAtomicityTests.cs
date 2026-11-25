using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 47 Lane B — marker-advance ATOMICITY: the
/// DeepSeek round-10 Item 2 fix. Round 10 proved the W45 advance
/// was not part of the gated, verified append operation:
/// (1) the pack-compile advance sat outside the chain gate, so a
/// concurrent pointer stage could advance the marker to N+3 and
/// the pack's pending advance then REGRESSED it to N+2, after
/// which the round-9 staged rollback passed again;
/// (2) AppendServiceAudit advanced even when SaveChain swallowed
/// a persistence failure (marker-ahead-of-chain);
/// (3) keyed pack Compile advanced with no SaveChain at all.
/// The fix: advance INSIDE the gate, only after the append's
/// persist is VERIFIED durable (persisted store re-read and
/// matched); a monotonicity guard in the advance itself refuses
/// any regression by name; the pack path takes the same gate +
/// verified persist (wired by CoreRuntime, mirrored here).
/// These tests pin each leg.</summary>
public class W47MarkerAtomicityTests
{
    private sealed record EntRig(string Root, string DataDir, string Install, EnterpriseService Enterprise);

    private static EntRig NewEntRig(bool sabotageAuditStore = false)
    {
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        if (sabotageAuditStore)
            // A directory squatting on the audit store path: every
            // chain save fails (the move cannot land), exactly the
            // swallowed-failure shape round 10 named.
            Directory.CreateDirectory(Path.Combine(dataDir, PointerAuditAnchor.AuditFileName));
        var enterprise = new EnterpriseService(dataDir, new RosterService());
        enterprise.AnchorMarkerInstallRoot = install;
        return new EntRig(root, dataDir, install, enterprise);
    }

    private static PointerAnchorMarker.Marker InstallMarker(EntRig rig) =>
        Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));

    // ---------- (b) the monotonicity guard, directly ----------

    [Fact]
    public void MonotonicityGuard_StaleSnapshotAdvance_RefusedByName_MarkerUnchanged()
    {
        var rig = NewEntRig();
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "one");
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "two");
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "three");
        var entries = rig.Enterprise.AuditLog.Entries;
        var before = InstallMarker(rig);
        Assert.Equal(entries.Count, before.ChainEntries);

        // A caller outside the gate holding a STALE snapshot (the
        // round-10 pack shape) attempts to advance to N-1.
        var stale = entries.Take(entries.Count - 1).ToList();
        var (ok, state) = PointerAuditAnchor.AdvanceInstallRootMarker(rig.Install, stale);
        Assert.False(ok);
        Assert.Contains("monotonicity guard", state);
        Assert.Contains("BACKWARD", state);
        // The marker is byte-unchanged.
        var after = InstallMarker(rig);
        Assert.Equal(before.ChainEntries, after.ChainEntries);
        Assert.Equal(before.ChainHead, after.ChainHead);
    }

    [Fact]
    public void MonotonicityGuard_SameCountDifferentHead_RefusedByName()
    {
        var rig = NewEntRig();
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "alpha");
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "beta");
        var count = rig.Enterprise.AuditLog.Entries.Count;
        var before = InstallMarker(rig);

        // A different chain of the SAME length names a different
        // head at the marker's count — a same-count rewrite of
        // vouched freshness, refused by the same guard.
        var other = NewEntRig();
        other.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "gamma");
        other.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "delta");
        var otherEntries = other.Enterprise.AuditLog.Entries;
        Assert.Equal(count, otherEntries.Count);
        Assert.NotEqual(before.ChainHead, otherEntries[^1].Hash);

        var (ok, state) = PointerAuditAnchor.AdvanceInstallRootMarker(rig.Install, otherEntries);
        Assert.False(ok);
        Assert.Contains("monotonicity guard", state);
        Assert.Contains("same-count rewrite", state);
        Assert.Equal(before.ChainHead, InstallMarker(rig).ChainHead);
    }

    // ---------- (1) DeepSeek's interleave, verbatim shape ----------

    [Fact]
    public void DeepSeekInterleave_PendingPackAdvanceCannotRegress_Round9RollbackStillRefuses()
    {
        var rig = NewEntRig();
        var audit = rig.Enterprise.AuditLog;

        // Chain N with pointer P1 staged at N (marker at N).
        rig.Enterprise.AppendServiceAudit(PointerAuditAnchor.RecordKind, "SYSTEM", "stage P1");
        var n = audit.Entries.Count;
        Assert.Equal(n, InstallMarker(rig).ChainEntries);

        // Keyed pack compile appends N+1/N+2 (raw appends, as the
        // pre-fix pack path made them) and snapshots the entries
        // for its pending advance.
        audit.Append(PackAuditAnchor.CompiledKind, "admin", "pack compile record", DateTimeOffset.UtcNow);
        audit.Append(PackAuditAnchor.SignatureKind, "admin", "pack signature record", DateTimeOffset.UtcNow);
        var packSnapshot = audit.Entries;
        Assert.Equal(n + 2, packSnapshot.Count);

        // A concurrent pointer stage appends P2 at N+3 and — under
        // the gate, after verified persist — advances the marker
        // to N+3.
        rig.Enterprise.AppendServiceAudit(PointerAuditAnchor.RecordKind, "SYSTEM", "stage P2");
        Assert.Equal(n + 3, InstallMarker(rig).ChainEntries);

        // The pack's PENDING advance (its stale N+2 snapshot)
        // arrives now. Pre-fix it wrote N+2 and the marker
        // regressed. Now the guard refuses it BY NAME and the
        // marker stays at N+3.
        var (ok, state) = PointerAuditAnchor.AdvanceInstallRootMarker(rig.Install, packSnapshot);
        Assert.False(ok);
        Assert.Contains("monotonicity guard", state);
        Assert.Equal(n + 3, InstallMarker(rig).ChainEntries);

        // The round-9 staged rollback after the interleave:
        // truncate the chain to exactly N+2 (removes P2, keeps P1)
        // — the freshness leg still refuses, because the marker
        // never regressed.
        var truncated = new ChainedAuditLog();
        var prefixJson = JsonSerializer.Serialize(audit.Entries.Take(n + 2).ToList());
        Assert.True(truncated.ImportEntriesJson(prefixJson).Ok);
        var markers = PointerAnchorMarker.ReadAll(rig.Install);
        var refusal = PointerAuditAnchor.FreshnessRefusal(markers, truncated.Entries);
        Assert.NotNull(refusal);
        Assert.Contains("FEWER than", refusal);
    }

    // ---------- (2) persist failure: no advance, named state ----------

    [Fact]
    public void PersistFailure_ServiceAudit_DoesNotAdvance_NamedState()
    {
        // The audit store path is a directory: SaveChain fails and
        // (pre-fix) the failure was swallowed while the advance
        // still ran — marker-ahead-of-chain on restart.
        var rig = NewEntRig(sabotageAuditStore: true);
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "append under a broken store");
        Assert.StartsWith("BROKEN", rig.Enterprise.ChainPersistenceState);
        // NO advance happened: no marker exists in the install
        // root at all, and the state names the failure.
        Assert.False(File.Exists(PointerAnchorMarker.MarkerPath(rig.Install)));
        Assert.StartsWith("anchor marker advance FAILED", rig.Enterprise.AnchorMarkerState);
        Assert.Contains("could not be verified", rig.Enterprise.AnchorMarkerState);
        // The in-memory append is real (the failure is durability,
        // named — not a silent drop).
        Assert.True(rig.Enterprise.AuditLog.Entries.Any(e => e.Kind == "session_open"));
    }

    // ---------- (3) the pack path: gated + verified ----------

    private sealed class PackRig : IDisposable
    {
        public required EntRig Ent { get; init; }
        public required Rmm05Tests.Rig Vuln { get; init; }
        public required ComplianceService Service { get; init; }
        public required PointerSigningCustody Custody { get; init; }
        public void Dispose() { }
    }

    private static PackRig NewPackRig(bool sabotageAuditStore = false)
    {
        var ent = NewEntRig(sabotageAuditStore);
        var v = Rmm05Tests.NewRig();
        var custody = new PointerSigningCustody(ent.Install, ent.DataDir);
        custody.EnsureKeyForInstall();
        // CoreRuntime's W47 wiring, mirrored: the pack service
        // runs over the enterprise chain, under the enterprise
        // chain's gate, with its verified persist.
        var svc = new ComplianceService(ent.Enterprise.AuditLog, v.Policies, v.Inventory,
            v.Patches.Service, v.Service, v.Clock.UtcNow, custody,
            ent.Enterprise.ChainGate, ent.Enterprise.PersistChainVerified);
        svc.ContentPacks.SeedDefaults();
        v.Inventory.ApplyBaseline(
            Rmm05Tests.Record("dev1", software: new[] { ("Google Chrome", "130.0") }), Rmm09Tests.T0);
        svc.RegisterSecurityState(new DeviceSecurityState(
            "dev1", "scope1", true, true, true, Rmm09Tests.T0), "monitor");
        return new PackRig { Ent = ent, Vuln = v, Service = svc, Custody = custody };
    }

    [Fact]
    public void PackPath_HappyPath_AdvanceGatedAndVerified_MarkerAtChainHead_PackVerifies()
    {
        using var rig = NewPackRig();
        var result = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin");
        Assert.True(result.Ok, result.Reason);
        var count = rig.Ent.Enterprise.AuditLog.Entries.Count;
        // The advance landed under the gate at the chain's live
        // head, after the verified persist (the persisted store
        // is the enterprise chain file, written by the delegate).
        Assert.Equal(count, InstallMarker(rig.Ent).ChainEntries);
        Assert.Equal($"advanced:chain_entries={count}", rig.Service.AnchorMarkerState);
        Assert.True(rig.Ent.Enterprise.ChainEntryIsDurable(PackAuditAnchor.CompiledKind));
        Assert.True(rig.Service.VerifyStoredPack(result.Pack!.PackId, out var reason), reason);
    }

    [Fact]
    public void PackPath_PersistFailure_RefusesCompileByName_NoPackStored_NoAdvance()
    {
        // The enterprise chain's store is sabotaged, so the wired
        // verified persist genuinely fails — the exact swallowed-
        // failure shape, now on the pack path.
        using var rig = NewPackRig(sabotageAuditStore: true);
        var result = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin");
        Assert.False(result.Ok);
        Assert.Contains("could not be verified", result.Reason);
        Assert.Contains("not verified durable", result.Reason);
        Assert.Empty(rig.Service.PackHistory);
        // No advance: the install-root marker was never written
        // by this compile (custody writes its own files, never
        // the anchor marker).
        Assert.False(File.Exists(PointerAnchorMarker.MarkerPath(rig.Ent.Install)));
        Assert.StartsWith("anchor marker advance FAILED", rig.Service.AnchorMarkerState);
    }

    [Fact]
    public void ConcurrentPointerStagesAndPackCompiles_MarkerEndsAtChainHead_NeverRegresses()
    {
        using var rig = NewPackRig();
        // Warm-up compile: custody + caches settled before the
        // concurrent batch (the batch itself is the interleave
        // under test, not first-use initialization).
        Assert.True(rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Ok);

        var compileResults = new System.Collections.Concurrent.ConcurrentBag<bool>();
        var tasks = new List<Task>();
        for (var i = 0; i < 8; i++)
        {
            var n = i;
            tasks.Add(Task.Run(() =>
                rig.Ent.Enterprise.AppendServiceAudit(PointerAuditAnchor.RecordKind, "SYSTEM", $"concurrent stage {n}")));
        }
        for (var i = 0; i < 4; i++)
        {
            tasks.Add(Task.Run(() =>
                compileResults.Add(rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Ok)));
        }
        Task.WaitAll(tasks.ToArray());

        Assert.All(compileResults, ok => Assert.True(ok));
        // Every anchored append advanced under the one gate: the
        // marker ends exactly at the chain's head — never behind
        // a completed advance, never ahead of the chain.
        var entries = rig.Ent.Enterprise.AuditLog.Entries;
        var marker = InstallMarker(rig.Ent);
        Assert.Equal(entries.Count, marker.ChainEntries);
        Assert.Equal(entries[^1].Hash, marker.ChainHead);
    }
}

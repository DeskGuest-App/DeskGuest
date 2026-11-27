using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 45 Lane B — pointer PACK freshness: the DeepSeek
/// round-9 Item 3 fix (staged-pointer rollback) + the Item 4
/// parenthetical (whole-chain pack rollback).
///
/// Round 9 (log-laneW41-dsconfirm8.md, Item 3, probed against the
/// actual code): staging does not rotate the pointer-signing key,
/// so two genuine staged writes exist under the same key; the
/// install-root marker vouched only the FIRST position because it
/// was refreshed only on a LAUNCHER visit; restoring the older
/// staged pointer + its genuine sidecar and truncating the chain
/// to exactly the marker count/head passed every leg.
///
/// The fix: the marker is no longer launcher-visit-driven. The
/// Core advances the install-root marker on EVERY anchored append
/// (append → persist → advance), so the marker always names the
/// newest genuine chain state. These rigs wire UpdateManager to a
/// real file-backed EnterpriseService exactly as CoreRuntime does
/// (positioned seam → AppendServiceAuditReturningEntry), with
/// custody + pin in a separate install root. The attacker can
/// write everything under the data dir and nothing under the
/// install root.</summary>
public class W45PointerFreshnessTests
{
    private sealed record Rig(string Root, string DataDir, string Install, string Updates,
        EnterpriseService Enterprise, UpdateManager Manager, PointerSigningCustody Custody,
        RsaUpdateSignatureVerifier Signer);

    private Rig CoreRig()
    {
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "DeskGuest.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(dataDir, "updates");
        var enterprise = new EnterpriseService(dataDir, new RosterService());
        // CoreRuntime's W45 wiring: the Core advances the marker.
        enterprise.AnchorMarkerInstallRoot = install;
        var custody = new PointerSigningCustody(install, dataDir);
        var signer = new RsaUpdateSignatureVerifier();
        var manager = new UpdateManager(updates, signer, _ => Task.FromResult(true),
            pointerAudit: detail => enterprise.AppendServiceAudit(PointerAuditAnchor.RecordKind, "SYSTEM", detail),
            pointerSigning: custody,
            keyingAudit: detail => enterprise.AppendServiceAudit(PointerSigningCustody.KeyingRecordKind, "SYSTEM", detail),
            pointerAuditPositioned: detail =>
            {
                var e = enterprise.AppendServiceAuditReturningEntry(PointerAuditAnchor.RecordKind, "SYSTEM", detail);
                return (e.Seq, e.Hash);
            });
        foreach (var slot in new[] { "A", "B" })
        {
            var dir = Path.Combine(updates, "slots", slot); Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "DeskGuestCore.exe"), "slot core");
            File.WriteAllText(Path.Combine(dir, "DeskGuest.SessionAgent.exe"), "slot agent");
        }
        return new Rig(root, dataDir, install, updates, enterprise, manager, custody, signer);
    }

    private string AuditPath(Rig rig) => Path.Combine(rig.DataDir, PointerAuditAnchor.AuditFileName);
    private string PointerPath(Rig rig) => SlotPointer.PointerPath(rig.Updates);
    private string SigPath(Rig rig) => PointerSigningCustody.SignaturePathFor(PointerPath(rig));

    private static byte[] MakeZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var entry = zip.CreateEntry(name);
                using var w = new StreamWriter(entry.Open());
                w.Write(content);
            }
        }
        return ms.ToArray();
    }

    private void Stage(Rig rig, string version)
    {
        var pkg = MakeZip(("DeskGuestCore.exe", $"slot core {version}"), ("DeskGuest.SessionAgent.exe", $"slot agent {version}"));
        var (ok, msg) = rig.Manager.StagePackage(pkg, rig.Signer.Sign(pkg), version);
        Assert.True(ok, msg);
    }

    /// <summary>The attacker's chain truncation: rewrite the
    /// data-dir chain file to exactly its first
    /// <paramref name="count"/> entries (all genuine).</summary>
    private void TruncateChainFile(Rig rig, int count)
    {
        var prefix = rig.Enterprise.AuditLog.Entries.Take(count).ToList();
        File.WriteAllText(AuditPath(rig), JsonSerializer.Serialize(prefix));
    }

    private PointerAnchorMarker.Marker InstallMarker(Rig rig) =>
        Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));

    // ---------- (1) The round-9 staged rollback, verbatim ----------

    [Fact]
    public void Round9StagedRollback_Verbatim_RefusedByName_CoreAdvancedMarker()
    {
        var rig = CoreRig();

        // Step 1 (round-9): genuine staged pointer P1
        // (StagedVersion=1.0.0) is written and signed v2 under the
        // current install-root key; the launcher vouches it, so
        // the install-root marker sits at P1's chain position.
        Stage(rig, "1.0.0");
        var p1 = File.ReadAllBytes(PointerPath(rig));
        var sig1 = File.ReadAllText(SigPath(rig));
        Assert.True(PointerSigningCustody.TryParseSidecar(sig1, out _, out var bound) && bound);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var countAtP1 = rig.Enterprise.AuditLog.Entries.Count;
        Assert.Equal(countAtP1, InstallMarker(rig).ChainEntries);

        // Step 2 (round-9): a newer genuine stage writes P2
        // (StagedVersion=2.0.0) under the SAME key (staging does
        // not rotate). Pre-fix the marker remained at P1's count
        // until the next launcher check. THE FIX: with NO launcher
        // visit at all, the Core has already advanced the marker
        // past P1's position to the newest genuine state.
        Stage(rig, "2.0.0");
        var countAtP2 = rig.Enterprise.AuditLog.Entries.Count;
        Assert.True(countAtP2 > countAtP1);
        Assert.Equal(countAtP2, InstallMarker(rig).ChainEntries);
        Assert.Equal($"advanced:chain_entries={countAtP2}", rig.Enterprise.AnchorMarkerState);
        // The genuine P2 state verifies against the Core-advanced
        // marker (no launcher refresh was needed or used).
        var (okGenuine, noteGenuine) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(okGenuine, noteGenuine);

        // Step 3 (round-9): the data-dir-only attacker restores P1
        // and its genuine sidecar, and truncates the chain to
        // exactly the OLD marker count (P1's position). No
        // install-root file is touched.
        File.WriteAllBytes(PointerPath(rig), p1);
        File.WriteAllText(SigPath(rig), sig1);
        TruncateChainFile(rig, countAtP1);

        // Step 4: pre-fix every leg passed and the launcher
        // proceeded on 1.0.0. Now the chain is FEWER than the
        // Core-advanced marker — refused by name at the marker
        // leg, and the launcher falls back.
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("FEWER than", note!);
        Assert.Contains("truncated or rolled back", note!);
        var target = DeskGuest.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
    }

    // ---------- (2) Crash-window pins ----------

    [Fact]
    public void CrashWindow_MarkerBehindChain_IsAcceptedGrowth()
    {
        // Write order is append → persist → advance, so a crash
        // between persist and advance leaves the marker BEHIND the
        // chain. That state must be accepted: the prefix at the
        // marker's count still binds, and the chain's last pointer
        // record is the genuine newest write.
        var rig = CoreRig();
        Stage(rig, "1.0.0");
        var markerAtStage = InstallMarker(rig);
        // Genuine growth after the marker's position, in the
        // exact crash shape: the appends are made and their
        // persist is VERIFIED durable, but the advance never
        // runs (the Core crashed between persist and advance).
        // W49 note: this state can no longer be fabricated by
        // rewinding the marker — the guarded Write primitive
        // refuses a backward write by name — which is precisely
        // the point: marker-behind-chain now arises ONLY from
        // the crash window, never from a write. The raw appends
        // + verified persist below reproduce that window
        // faithfully, and the assertion is unchanged.
        rig.Enterprise.AuditLog.Append("session_open", "SYSTEM", "genuine activity 1", DateTimeOffset.UtcNow);
        rig.Enterprise.AuditLog.Append("session_close", "SYSTEM", "genuine activity 2", DateTimeOffset.UtcNow);
        Assert.True(rig.Enterprise.PersistChainVerified());
        Assert.True(rig.Enterprise.AuditLog.Entries.Count > markerAtStage.ChainEntries);
        Assert.Equal(markerAtStage.ChainEntries, InstallMarker(rig).ChainEntries);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
    }

    [Fact]
    public void CrashWindow_MarkerAheadOfChain_IsRefused()
    {
        // Marker AHEAD of the chain cannot arise from the Core's
        // write order (the marker is written only after the append
        // it names is durable), so its presence means the chain
        // was truncated or the marker was written outside the Core
        // — refused by the same leg either way.
        var rig = CoreRig();
        Stage(rig, "1.0.0");
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var marker = InstallMarker(rig);
        PointerAnchorMarker.Write(rig.Install, marker.PointerSha256,
            (marker.ChainEntries ?? 0) + 5, marker.ChainHead);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("FEWER than", note!);
    }

    // ---------- (3) Marker-write failure is a named state ----------

    [Fact]
    public void MarkerWriteFailure_IsNamedState_AppendStillLands_NeverSilent()
    {
        var rig = CoreRig();
        // Point ONLY the marker advance at an impossible install
        // root (a path under a regular file): custody/signing keep
        // working from the real install root, the advance cannot.
        var blocker = Path.Combine(rig.Root, "blocker");
        File.WriteAllText(blocker, "not a directory");
        rig.Enterprise.AnchorMarkerInstallRoot = Path.Combine(blocker, "install");
        rig.Enterprise.AppendServiceAudit("session_open", "SYSTEM", "append under a broken marker root");
        // The append itself landed and is durable (the W43 check)…
        Assert.True(rig.Enterprise.ChainEntryIsDurable("session_open"));
        // …and the marker failure is a NAMED state, not silence.
        Assert.StartsWith("anchor marker advance FAILED", rig.Enterprise.AnchorMarkerState);
        Assert.Contains("could not be written", rig.Enterprise.AnchorMarkerState);
    }

    [Fact]
    public void CoreRuntime_HostState_CarriesAnchorMarkerState()
    {
        var dir = TestUtil.TempDir();
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        var runtime = new DeskGuest.Core.CoreRuntime(new DeskGuest.Core.CoreOptions
        {
            DataDir = dataDir, Port = 18945, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
        });
        // The production composition advanced the marker during
        // its own composition appends, and the state rides the
        // host-state surface W43 wired.
        Assert.StartsWith("advanced:chain_entries=", runtime.Enterprise.AnchorMarkerState);
        var json = runtime.BuildHostStateJson();
        Assert.Contains("\"anchorMarker\":\"advanced:chain_entries=", json);
        // And the Core-advanced marker vouches the initial pointer
        // with no launcher visit having occurred.
        var updates = Path.Combine(dataDir, "updates");
        var (ok, note) = PointerAuditAnchor.Check(updates, install);
        Assert.True(ok, note);
    }

    // ---------- Apply path also advances (stage AND apply) ----------

    [Fact]
    public void ApplyFlip_AdvancesMarker_AndVerifies()
    {
        var rig = CoreRig();
        Stage(rig, "2.0.0");
        var countAtStage = rig.Enterprise.AuditLog.Entries.Count;
        var applied = rig.Manager.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(applied.Ok, applied.Message);
        var countAtApply = rig.Enterprise.AuditLog.Entries.Count;
        Assert.True(countAtApply > countAtStage);
        Assert.Equal(countAtApply, InstallMarker(rig).ChainEntries);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
    }
}

using System.IO.Compression;
using System.Security.Cryptography;
using Acp.Core;
using Acp.Core.Services;
using Acp.Launcher;
using Acp.Shared.Enterprise;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 17 Lane A — betterment items B-15 + B-16
/// (from log-laneW16-dsconfirm.md Part 2, verbatim there).
/// B-15: the CheckIntact→Process.Start DIRECTORY-swap race — the
/// W15 hold pinned the slot's FILES but not its directory, so the
/// verified directory could be renamed away and a different one
/// put at the slot path between the check and the exec. Closed on
/// Windows by deny-rename/delete directory handles in SlotHold
/// (slot dir + two ancestors) plus a post-start intact re-check
/// in the production starter (child killed on drift); off Windows
/// the swap is caught by CheckIntact, pinned as the portable half.
/// The mixed slot-core/base-agent case is pinned: both fall back.
/// B-16: the pointer audit anchor's downgrade-by-deletion —
/// deleting enterprise-audit.json, truncating it to "[]", or
/// truncating it to a record-less valid prefix used to return the
/// LEGACY posture for a rewritten pointer + slot. Closed via
/// anchor-presence markers (Core: updates root, on every anchored
/// pointer write; launcher: install root, on every vouched check,
/// carrying chain length + head so rollback refuses too) and the
/// main-vs-backup selection rule (hash the file ReadDetailed
/// selected). HONEST REMAINDER, pinned as such in
/// PointerAuditAnchor's doc: an attacker who can rewrite the
/// whole data dir AND the install root can delete every marker
/// and recompute the unkeyed chain — indistinguishable from a
/// genuine pre-anchor install without the production signing key
/// (named human item). No stronger claim is made.</summary>
public class W17WinBetterTests
{
    private static byte[] MakeZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = zip.CreateEntry(name);
                using var wr = new StreamWriter(e.Open());
                wr.Write(content);
            }
        }
        return ms.ToArray();
    }

    private static string SlotWithFiles(string root, params (string Name, string Content)[] files)
    {
        var slot = Path.Combine(root, "slot");
        Directory.CreateDirectory(slot);
        foreach (var (name, content) in files)
            File.WriteAllText(Path.Combine(slot, name), content);
        return slot;
    }

    // ---------- B-15: directory swap ----------

    [Fact]
    public void B15_Hold_DirectorySwapAttempt_NeverLeavesVerifiedPathToAttackerBytes()
    {
        var root = TestUtil.TempDir();
        var slot = SlotWithFiles(root, ("AcpCore.exe", "core"), ("sub.dll", "lib"));
        var hash = SlotIntegrity.ContentHash(slot);
        using var hold = SlotIntegrity.AcquireHold(slot, hash);
        if (OperatingSystem.IsWindows())
        {
            // The directory itself is held deny-rename/delete:
            // the swap cannot even move the verified directory.
            Assert.Contains(slot, hold.HeldDirectories);
            Assert.Throws<IOException>(() => Directory.Move(slot, slot + "-moved"));
            Assert.Null(hold.CheckIntact()); // untouched, still verified
        }
        else
        {
            // Portable half: the swap mechanically succeeds, and
            // the intact check refuses the attacker's bytes BY
            // NAME — the pre-exec (and post-start) gate the
            // production starter enforces.
            Assert.Empty(hold.HeldDirectories);
            Directory.Move(slot, slot + "-moved");
            Directory.CreateDirectory(slot);
            File.WriteAllText(Path.Combine(slot, "AcpCore.exe"), "attacker core");
            File.WriteAllText(Path.Combine(slot, "sub.dll"), "lib");
            var problem = hold.CheckIntact();
            Assert.NotNull(problem);
            Assert.Contains("start refused", problem);
            // And a fresh hold against the recorded anchor refuses
            // the swapped directory outright.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                SlotIntegrity.AcquireHold(slot, hash));
            Assert.Contains("does not match the recorded anchor", ex.Message);
        }
    }

    [Fact]
    public void B15_Hold_AncestorDirectoriesHeld_OnWindows()
    {
        var root = TestUtil.TempDir();
        var slot = SlotWithFiles(root, ("AcpCore.exe", "core"));
        var hash = SlotIntegrity.ContentHash(slot);
        using var hold = SlotIntegrity.AcquireHold(slot, hash);
        if (OperatingSystem.IsWindows())
        {
            // slot + parent + grandparent: renaming any level of
            // the path the starter resolves is denied while held.
            Assert.Equal(3, hold.HeldDirectories.Count);
            Assert.Equal(slot, hold.HeldDirectories[0]);
            Assert.Throws<IOException>(() =>
                Directory.Move(Path.GetDirectoryName(slot)!, Path.GetDirectoryName(slot) + "-moved"));
        }
        else
        {
            Assert.Empty(hold.HeldDirectories); // named off-Windows posture
        }
    }

    [Fact]
    public async Task B15_StartChild_ExecutesHeldSlotExe_AndRefusesWrongHash()
    {
        if (OperatingSystem.IsWindows())
            // The happy-path exec pin runs on the Linux harness
            // with /bin/true; the Windows-specific half (directory
            // handles) is pinned by the two tests above, which run
            // their Windows branches on a Windows host.
            return;
        var root = TestUtil.TempDir();
        var slot = SlotWithFiles(root, ("AcpCore.exe", "placeholder"));
        File.Copy("/bin/true", Path.Combine(slot, "AcpCore.exe"), overwrite: true);
        var hash = SlotIntegrity.ContentHash(slot);
        var code = await LauncherCore.StartChildProcessAsync(new LaunchRequest(
            Path.Combine(slot, "AcpCore.exe"), "",
            new Dictionary<string, string>(), HoldDirectory: slot, ExpectedSlotHash: hash));
        Assert.Equal(0, code);
        // A wrong anchor refuses BEFORE exec (no process starts).
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LauncherCore.StartChildProcessAsync(new LaunchRequest(
                Path.Combine(slot, "AcpCore.exe"), "",
                new Dictionary<string, string>(), HoldDirectory: slot,
                ExpectedSlotHash: new string('0', 64))));
        Assert.Contains("does not match the recorded anchor", ex.Message);
    }

    [Fact]
    public void B15_MixedCase_SlotCoreWithoutAgent_FallsBackBoth_ByName()
    {
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(root, "updates");
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core ONLY");
        var hash = SlotIntegrity.ContentHash(slotA);
        File.WriteAllText(SlotPointer.PointerPath(updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
        var target = LauncherCore.ResolveTarget(install, updates);
        Assert.True(target.FellBack);
        Assert.Contains("Core and Agent swap together", target.Reason);
        Assert.Equal(Path.Combine(install, "AcpCore.exe"), target.CoreExe);
        Assert.Equal(Path.Combine(install, "Acp.SessionAgent.exe"), target.AgentExe);
    }

    // ---------- B-16: anchor downgrade-by-deletion ----------

    private sealed record Rig(string Root, string Install, string Updates, string SlotA, UpdateManager Manager, ChainedAuditLog Audit);

    private Rig PointerRig()
    {
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(root, "updates");
        var manager = new UpdateManager(updates, new RsaUpdateSignatureVerifier(), _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
        return new Rig(root, install, updates, slotA, manager, audit);
    }

    private string AuditPath(Rig rig) => Path.Combine(rig.Root, PointerAuditAnchor.AuditFileName);
    private void PersistAudit(Rig rig) => File.WriteAllText(AuditPath(rig), rig.Audit.ExportEntriesJson());

    [Fact]
    public void B16_CorePointerWrite_ArmsUpdatesRootMarker()
    {
        var rig = PointerRig();
        // The manager's constructor wrote the initial pointer WITH
        // the audit seam wired — the presence witness exists even
        // before the launcher ever runs.
        Assert.True(File.Exists(PointerAnchorMarker.MarkerPath(rig.Updates)));
        var markers = PointerAnchorMarker.ReadAll(rig.Updates);
        Assert.Single(markers);
        Assert.NotNull(markers[0].PointerSha256);
    }

    [Fact]
    public void B16_HappyPath_VouchedCheck_ArmsInstallMarker_AndPasses()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
        Assert.Null(note);
        var marker = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(1, marker.ChainEntries);
        Assert.Equal(rig.Audit.HeadHash, marker.ChainHead);
        // The rig's pointer is the manager's INITIAL-install
        // pointer, which carries no slot hash anchor by design —
        // the launcher falls back for that named reason, not for
        // any anchor failure (the end-to-end flipped-slot resolve
        // is pinned in B16_StageApply_EndToEnd below).
        var target = LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
        Assert.Contains("no integrity anchor", target.Reason);
    }

    [Fact]
    public void B16_AuditDeletion_AfterAnchoring_Refuses_AndLauncherFallsBack()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // The B-16 attack: delete the chain, keep a rewritten
        // pointer + slot whose hash passes the slot check alone.
        File.Delete(AuditPath(rig));
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        File.WriteAllText(SlotPointer.PointerPath(rig.Updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":\"attacker\",\"ActiveSlotHash\":\"" + slotHash + "\"}");
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("MISSING", note!);
        Assert.Contains("refuses rather than downgrading", note!);
        var target = LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
        Assert.Contains("pointer audit anchor", target.Reason);
    }

    [Fact]
    public void B16_AuditDeletion_BeforeAnyLaunch_CoreMarkerAlone_Refuses()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        // No launcher run yet (no install marker): the Core-side
        // updates-root marker alone carries the refusal.
        Assert.Empty(PointerAnchorMarker.ReadAll(rig.Install));
        File.Delete(AuditPath(rig));
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("anchor marker survives", note!);
    }

    [Fact]
    public void B16_AuditTruncatedToEmptyArray_RefusesAfterAnchoring()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        File.WriteAllText(AuditPath(rig), "[]"); // parses fine, zero entries
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("NO pointer record", note!);
        Assert.Contains("truncated or replaced", note!);
    }

    [Fact]
    public void B16_AuditTruncatedToRecordlessPrefix_RefusesAfterAnchoring()
    {
        var rig = PointerRig();
        // A chain that verifies cleanly but predates any pointer
        // record (valid prefix shape), beside the real pointer.
        // The Core-side marker is already armed by the manager's
        // first pointer write — no launcher run is needed:
        var other = new ChainedAuditLog();
        other.Append("session_open", "SYSTEM", "unrelated", DateTimeOffset.UtcNow);
        File.WriteAllText(AuditPath(rig), other.ExportEntriesJson());
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("NO pointer record", note!);
    }

    [Fact]
    public void B16_AuditZeroByte_BrokenNotLegacy_Refuses()
    {
        var rig = PointerRig();
        File.WriteAllBytes(AuditPath(rig), Array.Empty<byte>());
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("BROKEN", note!);
    }

    [Fact]
    public void B16_ChainRollback_OldPointerPlusOldPrefix_RefusesByRegressionRule()
    {
        var rig = PointerRig();
        // Capture the INITIAL anchored state (pointer + 1-entry chain).
        var initialPointer = File.ReadAllBytes(SlotPointer.PointerPath(rig.Updates));
        PersistAudit(rig);
        var initialAudit = File.ReadAllText(AuditPath(rig));
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // Grow the chain with a second pointer record for the
        // SAME pointer state (the seam's exact shape — a re-write
        // of the current pointer, as a stage/apply cycle produces
        // more of): growth must be accepted and re-arm the marker.
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            "pointer_sha256=" + Convert.ToHexString(SHA256.HashData(initialPointer)).ToLowerInvariant() + " active=A version=0.1.0 staged=- activeSlotHash=-",
            DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok2, note2) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok2, note2); // growth accepted, marker refreshed to 2 entries
        // ATTACK: roll back chain AND pointer to the initial state.
        // Every hash is internally consistent — the W15 anchor
        // ACCEPTED this. The marker's chain-length record refuses.
        File.WriteAllText(AuditPath(rig), initialAudit);
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), initialPointer);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("FEWER than", note!);
        Assert.Contains("rolled back", note!);
    }

    [Fact]
    public void B16_LegitimateGrowth_AfterMarkerArmed_StillPasses()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // Unrelated audit activity grows the chain; the pointer
        // record is untouched and still vouches.
        rig.Audit.Append("session_open", "SYSTEM", "later activity", DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
        Assert.Null(note);
        Assert.Equal(2, Assert.Single(PointerAnchorMarker.ReadAll(rig.Install)).ChainEntries);
    }

    [Fact]
    public void B16_BackupSelection_MainCorrupt_BackupMatchesRecord_Passes()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        // Crash-recovery shape: main pointer torn, .bak holds the
        // exact recorded bytes (the Core writes both from one
        // serialization). ReadDetailed selects the .bak; the
        // anchor must hash THAT file — the pre-fix code hashed
        // the torn main and refused a legitimate recovery.
        File.WriteAllText(SlotPointer.PointerPath(rig.Updates), "{torn");
        var read = SlotPointer.ReadDetailed(rig.Updates);
        Assert.Equal(SlotPointer.PointerBackupPath(rig.Updates), read.SelectedPath);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
        Assert.Null(note);
    }

    [Fact]
    public void B16_BackupSelection_BackupRewritten_Refuses()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        File.Delete(SlotPointer.PointerPath(rig.Updates));
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        File.WriteAllText(SlotPointer.PointerBackupPath(rig.Updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":\"attacker\",\"ActiveSlotHash\":\"" + slotHash + "\"}");
        var read = SlotPointer.ReadDetailed(rig.Updates);
        Assert.Equal(SlotPointer.PointerBackupPath(rig.Updates), read.SelectedPath);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("does NOT match", note!);
        Assert.Contains(".bak", note!);
    }

    [Fact]
    public void B16_NoAuditNoMarker_GenuineLegacyPosture_Preserved()
    {
        // A pre-anchor install shape, built by hand (no manager,
        // no marker anywhere): the legacy posture is still the
        // named behaviour — W17 refuses only AFTER anchoring.
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        var updates = Path.Combine(root, "updates");
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
        var hash = SlotIntegrity.ContentHash(slotA);
        File.WriteAllText(SlotPointer.PointerPath(updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
        var (ok, note) = PointerAuditAnchor.Check(updates, install);
        Assert.True(ok);
        Assert.Contains("legacy posture", note!);
        Assert.Empty(PointerAnchorMarker.ReadAll(updates, install));
    }

    [Fact]
    public void B16_StageApply_EndToEnd_PointerRecordMarkerStayInStep()
    {
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        using var signer = new RsaUpdateSignatureVerifier();
        var updatesDir = Path.Combine(root, "updates");
        var manager = new UpdateManager(updatesDir, signer, _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var pkg = MakeZip(("AcpCore.exe", "slot core"), ("Acp.SessionAgent.exe", "slot agent"));
        Assert.True(manager.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        Assert.True(manager.ApplyStagedAsync(default).GetAwaiter().GetResult().Ok);
        File.WriteAllText(Path.Combine(root, PointerAuditAnchor.AuditFileName), audit.ExportEntriesJson());
        var (ok, note) = PointerAuditAnchor.Check(updatesDir, install);
        Assert.True(ok, note);
        Assert.Null(note);
        var target = LauncherCore.ResolveTarget(install, updatesDir);
        Assert.False(target.FellBack, target.Reason);
        Assert.EndsWith(Path.Combine("slots", "B", "AcpCore.exe"), target.CoreExe);
        // Now delete the chain: the flipped slot must REFUSE, not
        // downgrade — the end-to-end B-16 destruction case.
        File.Delete(Path.Combine(root, PointerAuditAnchor.AuditFileName));
        var (ok2, note2) = PointerAuditAnchor.Check(updatesDir, install);
        Assert.False(ok2);
        Assert.Contains("MISSING", note2!);
        var target2 = LauncherCore.ResolveTarget(install, updatesDir);
        Assert.True(target2.FellBack);
    }
}

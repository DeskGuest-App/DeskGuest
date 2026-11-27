using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DeskGuest.Core;
using DeskGuest.Core.Services;
using DeskGuest.Launcher;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 15 Lane A — round-2 FIX-INADEQUATE closures.
/// DS-P9-F6: the no-key-file / dev-ephemeral update path FAILS
/// CLOSED in production composition (named refusal; dev-ephemeral
/// only behind the explicit dev opt-in, labelled).
/// DS-P9-F18: (a) a file ADDED to the slot after verification is
/// named and refuses the start (whole-slot hash + hold + intact
/// check); (b) the unsigned pointer is cross-checked against the
/// Core's audit-chained pointer record — a pointer rewritten
/// together with the slot refuses by name. Full pointer closure
/// still requires the production signing key (named human item);
/// limb (b) is tamper-evidence, pinned as such, never a signature.</summary>
public class W15WinFixTests
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

    // ---------- P9-F6: fail closed on absent / ephemeral key ----------

    [Fact]
    public void P9F6_AbsentKeyManager_StageAndApply_RefuseByName()
    {
        var root = TestUtil.TempDir();
        const string reason = "no pinned product update key — update stage/apply FAIL CLOSED (DS-P9-F6) [test reason]";
        var updates = new UpdateManager(root, new AbsentKeyUpdateVerifier(), _ => Task.FromResult(true),
            pinnedKeyIds: new HashSet<string> { "product-pinned" }, failClosedReason: reason);
        Assert.Equal("no-pinned-product-key", updates.Status().SignatureKeyId);
        var pkg = MakeZip(("app.txt", "v2"));
        var staged = updates.StagePackage(pkg, new byte[] { 1, 2, 3 }, "2.0.0");
        Assert.False(staged.Ok);
        Assert.Equal(reason, staged.Message);
        var applied = updates.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.False(applied.Ok);
        Assert.Equal(reason, applied.Message);
        Assert.Null(updates.Status().StagedVersion); // nothing was staged
    }

    [Fact]
    public void P9F6_ProductionComposition_NoKeyFile_FailsClosedByName()
    {
        // CoreRuntime is the production composition root (Program.cs
        // never sets AllowDevEphemeralUpdateKey, and this test
        // process has no DESKGUEST_DEV_ALLOW_NO_TOKEN=1): with no
        // update-key.pub beside the test binary, staging refuses.
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = TestUtil.TempDir(), Port = 18915,
            Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
        });
        Assert.Equal("no-pinned-product-key", runtime.Updates.Status().SignatureKeyId);
        var staged = runtime.Updates.StagePackage(new byte[] { 1, 2, 3 }, new byte[] { 4 }, "9.9.9");
        Assert.False(staged.Ok);
        Assert.Contains("no pinned product update key", staged.Message);
        Assert.Contains("FAIL CLOSED", staged.Message);
        // The posture is an audit-chained fact:
        Assert.Contains(runtime.Enterprise.AuditLog.Entries,
            e => e.Kind == "update_signing_posture" && e.Detail.Contains("FAILS CLOSED"));
    }

    [Fact]
    public void P9F6_DevOptIn_LabelledEphemeral_StillStages()
    {
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = TestUtil.TempDir(), Port = 18916,
            Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            AllowDevEphemeralUpdateKey = true,
        });
        Assert.Equal("dev-ephemeral", runtime.Updates.Status().SignatureKeyId);
        Assert.Contains(runtime.Enterprise.AuditLog.Entries,
            e => e.Kind == "update_signing_posture" && e.Detail.Contains("DEV-Ephemeral"));
        // The runtime's own ephemeral verifier is not reachable for
        // signing from outside; staging an unsigned package still
        // fails SIGNATURE verification (a different, named refusal)
        // — the opt-in labels the posture, it does not disable checks.
        var staged = runtime.Updates.StagePackage(new byte[] { 1, 2, 3 }, new byte[] { 4 }, "9.9.9");
        Assert.False(staged.Ok);
        Assert.Contains("signature verification FAILED", staged.Message);
    }

    [Fact] // direct UpdateManager composition with an ephemeral key
           // and NO pinned set keeps working (embedder/test shape) —
           // the fail-closed rule binds PRODUCTION composition.
    public void P9F6_DirectManager_EphemeralUnpinned_Unchanged()
    {
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, signer, _ => Task.FromResult(true));
        var pkg = MakeZip(("app.txt", "v2"));
        Assert.True(updates.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
    }

    // ---------- P9-F18 limb (a): file added after verification ----------

    private static string SlotWithFiles(string root, params (string Name, string Content)[] files)
    {
        var slot = Path.Combine(root, "slot");
        Directory.CreateDirectory(slot);
        foreach (var (name, content) in files)
            File.WriteAllText(Path.Combine(slot, name), content);
        return slot;
    }

    [Fact]
    public void P9F18a_Hold_IntactSlot_CheckIntactNull_HoldsEveryFile()
    {
        var slot = SlotWithFiles(TestUtil.TempDir(), ("DeskGuestCore.exe", "core"), ("sub.dll", "lib"));
        var hash = SlotIntegrity.ContentHash(slot);
        using var hold = SlotIntegrity.AcquireHold(slot, hash);
        Assert.Equal(new[] { "DeskGuestCore.exe", "sub.dll" }, hold.HeldFiles);
        Assert.Null(hold.CheckIntact());
    }

    [Fact]
    public void P9F18a_Hold_FileAddedAfterVerification_RefusesByName()
    {
        var slot = SlotWithFiles(TestUtil.TempDir(), ("DeskGuestCore.exe", "core"));
        var hash = SlotIntegrity.ContentHash(slot);
        using var hold = SlotIntegrity.AcquireHold(slot, hash);
        File.WriteAllText(Path.Combine(slot, "evil.dll"), "attacker");
        var problem = hold.CheckIntact();
        Assert.NotNull(problem);
        Assert.Contains("ADDED after verification", problem);
        Assert.Contains("evil.dll", problem);
        Assert.Contains("start refused", problem);
    }

    [Fact]
    public void P9F18a_Hold_FileChangedOrRemoved_RefusesByName()
    {
        var slot = SlotWithFiles(TestUtil.TempDir(), ("DeskGuestCore.exe", "core"), ("gone.dll", "x"));
        var hash = SlotIntegrity.ContentHash(slot);
        using var hold = SlotIntegrity.AcquireHold(slot, hash);
        File.WriteAllText(Path.Combine(slot, "DeskGuestCore.exe"), "tampered");
        Assert.Contains("start refused", hold.CheckIntact()!);
        File.WriteAllText(Path.Combine(slot, "DeskGuestCore.exe"), "core");
        Assert.Null(hold.CheckIntact());
        File.Delete(Path.Combine(slot, "gone.dll"));
        var problem = hold.CheckIntact();
        Assert.Contains("gone.dll", problem!);
        Assert.Contains("start refused", problem);
    }

    [Fact]
    public void P9F18a_AcquireHold_WrongHash_Refuses()
    {
        var slot = SlotWithFiles(TestUtil.TempDir(), ("DeskGuestCore.exe", "core"));
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SlotIntegrity.AcquireHold(slot, new string('0', 64)));
        Assert.Contains("does not match the recorded anchor", ex.Message);
    }

    [Fact]
    public async Task P9F18a_RunAsync_CarriesExpectedSlotHash()
    {
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        var updates = Path.Combine(root, "updates"); Directory.CreateDirectory(updates);
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "DeskGuest.SessionAgent.exe"), "slot agent");
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        var hash = SlotIntegrity.ContentHash(slotA);
        File.WriteAllText(SlotPointer.PointerPath(updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
        string? seenHash = null; string? seenHold = null;
        var code = await LauncherCore.RunAsync(install, updates, "", req =>
        {
            seenHash = req.ExpectedSlotHash; seenHold = req.HoldDirectory; return Task.FromResult(0);
        }, new StringWriter());
        Assert.Equal(0, code);
        Assert.Equal(hash, seenHash);
        Assert.Equal(slotA, seenHold);
    }

    // ---------- P9-F18 limb (b): pointer vs audit-chained record ----------

    private sealed record Rig(string Root, string Install, string Updates, string SlotA, UpdateManager Manager);

    private Rig PointerRig(ChainedAuditLog audit)
    {
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "DeskGuest.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(root, "updates");
        var manager = new UpdateManager(updates, new RsaUpdateSignatureVerifier(), _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "DeskGuest.SessionAgent.exe"), "slot agent");
        return new Rig(root, install, updates, slotA, manager);
    }

    [Fact]
    public void P9F18b_PointerWrittenByCore_MatchesAuditRecord_CheckOk()
    {
        var audit = new ChainedAuditLog();
        var rig = PointerRig(audit);
        // The manager's constructor wrote the initial pointer AND
        // its audit record; persist the chain where the launcher
        // looks (data dir = parent of the updates root).
        File.WriteAllText(Path.Combine(rig.Root, PointerAuditAnchor.AuditFileName), audit.ExportEntriesJson());
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates);
        Assert.True(ok, note);
        Assert.Null(note); // vouched for — no legacy-posture note
    }

    [Fact]
    public void P9F18b_PointerRewrittenOutsideCore_RefusedByName_AndLauncherFallsBack()
    {
        var audit = new ChainedAuditLog();
        var rig = PointerRig(audit);
        File.WriteAllText(Path.Combine(rig.Root, PointerAuditAnchor.AuditFileName), audit.ExportEntriesJson());
        // Attacker rewrites the pointer (e.g. re-anchoring it to a
        // slot they also rewrote — the slot hash check alone would
        // pass against THEIR hash):
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        File.WriteAllText(SlotPointer.PointerPath(rig.Updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":\"attacker\",\"ActiveSlotHash\":\"" + slotHash + "\"}");
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates);
        Assert.False(ok);
        Assert.Contains("rewritten outside the Core", note!);
        var target = LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
        Assert.Contains("pointer audit anchor", target.Reason);
        Assert.Equal(Path.Combine(rig.Install, "DeskGuestCore.exe"), target.CoreExe);
    }

    [Fact]
    public void P9F18b_NoAuditChain_LegacyPostureNamed_SlotStillResolves()
    {
        var rig = PointerRig(new ChainedAuditLog()); // chain never persisted
        // W17 / DS-B-16 supersedes this pin's setup, not its
        // intent: with the audit seam wired, the manager's first
        // pointer write now arms an anchor marker in the updates
        // root, and a surviving marker + missing chain REFUSES
        // (see W17WinBetterTests). The genuine legacy posture —
        // a pre-anchor install — is chain absent AND marker
        // absent; remove the marker to stand in for it.
        File.Delete(PointerAnchorMarker.MarkerPath(rig.Updates));
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        File.WriteAllText(SlotPointer.PointerPath(rig.Updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + slotHash + "\"}");
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates);
        Assert.True(ok);
        Assert.Contains("legacy posture", note!);
        var target = LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.False(target.FellBack);
        Assert.Contains("legacy posture", target.Reason);
    }

    [Fact]
    public void P9F18b_BrokenAuditChain_RefusesSlot()
    {
        var audit = new ChainedAuditLog();
        var rig = PointerRig(audit);
        var json = audit.ExportEntriesJson();
        // Tamper with the persisted chain (flip a character inside
        // the first entry's detail): import must report BROKEN.
        var tampered = json.Replace("pointer_sha256=", "pointer_sha256=X");
        Assert.NotEqual(json, tampered);
        File.WriteAllText(Path.Combine(rig.Root, PointerAuditAnchor.AuditFileName), tampered);
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        File.WriteAllText(SlotPointer.PointerPath(rig.Updates),
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + slotHash + "\"}");
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates);
        Assert.False(ok);
        Assert.Contains("BROKEN", note!);
    }

    [Fact] // stage+apply through the manager keeps pointer + record in step
    public void P9F18b_StageApply_PointerRecordStaysInStep()
    {
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        using var signer = new RsaUpdateSignatureVerifier();
        var updatesDir = Path.Combine(root, "updates");
        var manager = new UpdateManager(updatesDir, signer, _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var pkg = MakeZip(("DeskGuestCore.exe", "slot core"), ("DeskGuest.SessionAgent.exe", "slot agent"));
        Assert.True(manager.StagePackage(pkg, signer.Sign(pkg), "2.0.0").Ok);
        Assert.True(manager.ApplyStagedAsync(default).GetAwaiter().GetResult().Ok);
        File.WriteAllText(Path.Combine(root, PointerAuditAnchor.AuditFileName), audit.ExportEntriesJson());
        var (ok, note) = PointerAuditAnchor.Check(updatesDir);
        Assert.True(ok, note);
        Assert.Null(note);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        var target = LauncherCore.ResolveTarget(install, updatesDir);
        Assert.False(target.FellBack, target.Reason);
        Assert.EndsWith(Path.Combine("slots", "B", "DeskGuestCore.exe"), target.CoreExe);
    }
}

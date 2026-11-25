using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Security;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 36 Lane B — pointer-signature POSITION binding
/// (the DeepSeek round-8 Item-2 fix) + Item 3 (update_signing_
/// posture named-state treatment).
///
/// PROBE (recorded in log-laneW36-pointerposition.md): before the
/// fix, the round-8 replay below was run verbatim against the W30
/// code and the launcher ACCEPTED the rolled-back pointer — the
/// W30 signature bound pointer bytes only, not chain position.
/// This suite asserts the opposite at every leg.
///
/// Layout mirrors W30: dataDir/updates is the updates root, the
/// audit chain lives in the data dir, custody + pin in a SEPARATE
/// install root. The attacker in every forgery test can write
/// everything under the data dir and nothing under the install
/// root.</summary>
public class W36PointerPositionTests
{
    private sealed record Rig(string Root, string DataDir, string Install, string Updates, string SlotA,
        UpdateManager Manager, ChainedAuditLog Audit, PointerSigningCustody Custody,
        RsaUpdateSignatureVerifier Signer);

    private Rig KeyedRig()
    {
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(dataDir, "updates");
        var custody = new PointerSigningCustody(install, dataDir);
        var signer = new RsaUpdateSignatureVerifier();
        var manager = new UpdateManager(updates, signer, _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow),
            pointerSigning: custody,
            pointerAuditPositioned: detail =>
            {
                var e = audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow);
                return (e.Seq, e.Hash);
            },
            keyingAudit: detail => audit.Append(PointerSigningCustody.KeyingRecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
        return new Rig(root, dataDir, install, updates, slotA, manager, audit, custody, signer);
    }

    private string AuditPath(Rig rig) => Path.Combine(rig.DataDir, PointerAuditAnchor.AuditFileName);
    private void PersistAudit(Rig rig) => File.WriteAllText(AuditPath(rig), rig.Audit.ExportEntriesJson());
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
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

    // ---------- The round-8 replay, verbatim → refused at the position leg ----------

    [Fact]
    public void Round8Replay_Verbatim_RefusedAtPositionLeg_MarkerNotRefreshed()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        // (1) Capture an old genuinely-signed pointer P0 + Sig(P0).
        var p0 = File.ReadAllBytes(PointerPath(rig));
        var sig0 = File.ReadAllText(SigPath(rig));
        var h0 = Sha(p0);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // The genuine sidecar is position-bound (v2) from the start.
        Assert.True(PointerSigningCustody.TryParseSidecar(sig0, out _, out var bound) && bound);

        // (2) The genuine chain grows to C1; the install-root
        // marker sits at (C1, h1).
        rig.Audit.Append("session_open", "SYSTEM", "genuine activity", DateTimeOffset.UtcNow);
        rig.Audit.Append("session_close", "SYSTEM", "more genuine activity", DateTimeOffset.UtcNow);
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var markerBefore = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(rig.Audit.Entries.Count, markerBefore.ChainEntries);

        // (3) Append ONE valid unkeyed chain record naming H(P0)
        // at C1+1 — in its STRONGEST form, carrying even the v2
        // scheme marker, so the hash leg and the scheme leg pass
        // and only the position commitment can refuse.
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            $"pointer_sha256={h0} active=A version=0.1.0 staged=- activeSlotHash=- pointer_sig_scheme=v2",
            DateTimeOffset.UtcNow);
        PersistAudit(rig);

        // (4) Restore active-slot.json = P0 and its genuine sidecar.
        File.WriteAllBytes(PointerPath(rig), p0);
        File.WriteAllText(SigPath(rig), sig0);

        // (5) REFUSED by name at the position leg: the restored
        // pointer's signature commits to its ORIGINAL record; the
        // chain's last pointer record is now the attacker's, at a
        // new index with a new hash.
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("POSITION-BOUND signature does NOT verify", note!);
        Assert.Contains("replay/rollback", note!);
        // The refused check did NOT refresh the launcher marker.
        var markerAfter = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(markerBefore.ChainEntries, markerAfter.ChainEntries);
        Assert.Equal(markerBefore.ChainHead, markerAfter.ChainHead);
        // And the launcher falls back rather than exec the slot.
        var target = Acp.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
    }

    // ---------- Genuine flow verifies at every step, incl. rotation ----------

    [Fact]
    public void GenuineFlow_InstallStageApplyFlipWithRotation_VerifiesAtEveryStep()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        var (ok0, note0) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok0, note0);
        var fpBefore = rig.Custody.Fingerprint;

        var pkg = MakeZip(("AcpCore.exe", "slot core v2"), ("Acp.SessionAgent.exe", "slot agent v2"));
        Assert.True(rig.Manager.StagePackage(pkg, rig.Signer.Sign(pkg), "2.0.0").Ok);
        PersistAudit(rig);
        var (ok1, note1) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok1, note1);

        var applied = rig.Manager.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(applied.Ok, applied.Message);
        // Rotation at apply re-signed under the NEW key, v2.
        Assert.NotEqual(fpBefore, rig.Custody.Fingerprint);
        Assert.True(PointerSigningCustody.TryParseSidecar(File.ReadAllText(SigPath(rig)), out _, out var bound) && bound);
        PersistAudit(rig);
        var (ok2, note2) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok2, note2);
        var target = Acp.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.False(target.FellBack, target.Reason);
        Assert.EndsWith(Path.Combine("slots", "B", "AcpCore.exe"), target.CoreExe);
    }

    [Fact]
    public void NonPointerGrowth_AfterPointerRecord_DoesNotInvalidate()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // Ordinary non-pointer chain growth after the pointer
        // record: the anchor is the last POINTER record, not the
        // chain head, so the position commitment still holds.
        for (var i = 0; i < 5; i++)
            rig.Audit.Append("session_open", "SYSTEM", $"activity {i}", DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
    }

    // ---------- Pure truncation/rollback (no appended record) → marker binding ----------

    [Fact]
    public void PureRollback_WithoutAppendedRecord_RefusedByMarkerBinding()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        var p0 = File.ReadAllBytes(PointerPath(rig));
        var sig0 = File.ReadAllText(SigPath(rig));
        var audit0 = File.ReadAllText(AuditPath(rig));
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        // Genuine advance: a stage grows the chain and re-arms
        // the install-root marker at the longer chain.
        var pkg = MakeZip(("AcpCore.exe", "slot core v2"), ("Acp.SessionAgent.exe", "slot agent v2"));
        Assert.True(rig.Manager.StagePackage(pkg, rig.Signer.Sign(pkg), "2.0.0").Ok);
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        // Pure rollback: restore ONLY the old pointer + sidecar +
        // old chain (all data-dir files); the install-root marker
        // still records the grown chain. No appended record.
        File.WriteAllText(AuditPath(rig), audit0);
        File.WriteAllBytes(PointerPath(rig), p0);
        File.WriteAllText(SigPath(rig), sig0);

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("FEWER than", note!);
        Assert.Contains("truncated or rolled back", note!);
    }

    // ---------- Tampered position commitment ----------

    [Fact]
    public void AppendedRecord_NamingCurrentPointer_RefusedAtPositionLeg()
    {
        // No pointer restore at all: the attacker appends a record
        // naming the CURRENT pointer's hash (with the v2 scheme
        // marker). The hash leg passes; the signature was made
        // over the ORIGINAL record's position, not this new one.
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var current = File.ReadAllBytes(PointerPath(rig));
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            $"pointer_sha256={Sha(current)} active=A version=0.1.0 staged=- activeSlotHash=- pointer_sig_scheme=v2",
            DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("POSITION-BOUND signature does NOT verify", note!);
    }

    [Fact]
    public void TamperedRecordDetail_RefusedAsBrokenChain()
    {
        // Editing the genuine record's detail in the chain file
        // (the only way to "move" its commitment in place) breaks
        // the record's own hash — the chain itself refuses.
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var json = File.ReadAllText(AuditPath(rig));
        Assert.Contains("pointer_sig_scheme=v2", json);
        File.WriteAllText(AuditPath(rig), json.Replace("pointer_sig_scheme=v2", "pointer_sig_scheme=v9"));
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("BROKEN", note!);
    }

    [Fact]
    public void V2Sidecar_WithPreV2LastRecord_RefusedByName()
    {
        // A v2 sidecar whose publishing record is a pre-W36 record
        // (no scheme marker): the record is not the one the
        // signature was made over — refused by name.
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var current = File.ReadAllBytes(PointerPath(rig));
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            $"pointer_sha256={Sha(current)} active=A version=0.1.0 staged=- activeSlotHash=-",
            DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("NO v2 scheme marker", note!);
    }

    // ---------- Migration: LEGACY-POSITIONLESS, named both ways ----------

    [Fact]
    public void LegacyV1_BeforePositionBegins_AcceptedUnderNamedPosture()
    {
        // A W30-era install shape, hand-built: the pointer is
        // signed over its BYTES ONLY (v1 bare sidecar) and its
        // chain record carries no scheme marker. No position
        // witness exists anywhere, so the named posture applies.
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(dataDir, "updates"); Directory.CreateDirectory(updates);
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
        var custody = new PointerSigningCustody(install, dataDir);
        custody.EnsureKeyForInstall();
        PointerSigningCustody.WriteKeyingMarker(updates, custody.Fingerprint!);

        var pointer = Encoding.UTF8.GetBytes("{\"Active\":0,\"Version\":\"1.0.0\",\"StagedVersion\":null,\"LastOutcome\":\"w30 era\"}");
        File.WriteAllBytes(SlotPointer.PointerPath(updates), pointer);
        File.WriteAllText(PointerSigningCustody.SignaturePathFor(SlotPointer.PointerPath(updates)),
            Convert.ToBase64String(custody.Sign(pointer))); // v1: bare base64 over bytes only
        audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            $"pointer_sha256={Sha(pointer)} active=A version=1.0.0 staged=- activeSlotHash=-", DateTimeOffset.UtcNow);
        File.WriteAllText(Path.Combine(dataDir, PointerAuditAnchor.AuditFileName), audit.ExportEntriesJson());

        var (ok, note) = PointerAuditAnchor.Check(updates, install);
        Assert.True(ok, note);
        Assert.Contains("LEGACY-POSITIONLESS", note!);
    }

    [Fact]
    public void LegacyV1_AfterPositionBegins_RefusedByName_EvenWithV2SidecarsDeleted()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        // The attacker builds a W30-style v1 pointer (they cannot
        // — but a genuine OLD v1 pointer captured pre-upgrade is
        // exactly this shape; here the custodied key signs it so
        // ONLY the migration leg can refuse), appends a matching
        // record, and deletes BOTH v2 sidecars so no sidecar
        // witness survives. The genuine v2 record in the chain
        // prefix is the witness that remains.
        var old = Encoding.UTF8.GetBytes("{\"Active\":0,\"Version\":\"1.0.0\",\"StagedVersion\":null,\"LastOutcome\":\"w30 era\"}");
        File.WriteAllBytes(PointerPath(rig), old);
        File.WriteAllText(SigPath(rig), Convert.ToBase64String(rig.Custody.Sign(old)));
        File.Delete(PointerSigningCustody.SignaturePathFor(SlotPointer.PointerBackupPath(rig.Updates)));
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            $"pointer_sha256={Sha(old)} active=A version=1.0.0 staged=- activeSlotHash=-", DateTimeOffset.UtcNow);
        PersistAudit(rig);

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("POSITION-LESS (v1, W30)", note!);
        Assert.Contains("LEGACY-POSITIONLESS posture no longer applies", note!);
    }

    // ---------- Composition discipline ----------

    [Fact]
    public void KeyedWrite_WithoutPositionedSeam_RefusesByName_NoPointerWritten()
    {
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        var updates = Path.Combine(dataDir, "updates");
        var custody = new PointerSigningCustody(install, dataDir);
        using var signer = new RsaUpdateSignatureVerifier();
        var refusal = Assert.Throws<InvalidOperationException>(() =>
            new UpdateManager(updates, signer, _ => Task.FromResult(true), pointerSigning: custody));
        Assert.Contains("POSITIONED pointer-audit seam", refusal.Message);
        Assert.False(File.Exists(SlotPointer.PointerPath(updates)));
    }

    // ---------- Production composition + Item 3 ----------

    [Fact]
    public void CoreRuntime_PositionedEndToEnd_LauncherCheckPasses()
    {
        var dir = TestUtil.TempDir();
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        var runtime = new Acp.Core.CoreRuntime(new Acp.Core.CoreOptions
        {
            DataDir = dataDir, Port = 18941, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
        });
        var updates = Path.Combine(dataDir, "updates");
        // The Core's initial pointer is v2 position-bound, and the
        // real production chain (persisted by EnterpriseService)
        // vouches for it end to end.
        Assert.True(PointerSigningCustody.TryParseSidecar(
            File.ReadAllText(PointerSigningCustody.SignaturePathFor(SlotPointer.PointerPath(updates))),
            out _, out var bound) && bound);
        var (ok, note) = PointerAuditAnchor.Check(updates, install);
        Assert.True(ok, note);
    }

    [Fact]
    public void CoreRuntime_UpdateSigningPosture_RecordedInChain()
    {
        var dir = TestUtil.TempDir();
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        var runtime = new Acp.Core.CoreRuntime(new Acp.Core.CoreOptions
        {
            DataDir = dataDir, Port = 18942, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
        });
        Assert.Equal("recorded:update_signing_posture", runtime.UpdateSigningPostureAuditState);
        Assert.Contains(runtime.Enterprise.AuditLog.Entries, e => e.Kind == "update_signing_posture");
    }

    [Fact]
    public void CoreRuntime_UpdateSigningPosture_ForcedAppendFailure_IsVisibleNamedError_NotSwallowed()
    {
        var dir = TestUtil.TempDir();
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        var runtime = new Acp.Core.CoreRuntime(new Acp.Core.CoreOptions
        {
            DataDir = dataDir, Port = 18943, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
            UpdateSigningPostureAuditSink = (_, _, _) => throw new InvalidOperationException("forced update posture failure (W36 regression)"),
        });
        Assert.StartsWith("FAILED: update_signing_posture audit append failed", runtime.UpdateSigningPostureAuditState);
        Assert.Contains("forced update posture failure (W36 regression)", runtime.UpdateSigningPostureAuditState);
    }
}

using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Security;
using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 30 Lane A — D-DEC-7 pointer signing IMPLEMENTATION
/// (W29-A Option 1, design in log-laneW29-pointersigning.md §3–§5).
/// The seven destruction tests the design specified, plus the
/// task's extras: genuine end-to-end verification, rotation at
/// apply, and a repin attempt outside install/update events.
/// Layout mirrors production: dataDir/updates is the updates
/// root, the audit chain lives in the data dir, and the runtime
/// key's custody + pin live in a SEPARATE install root — the
/// data-dir-only attacker in every forgery test can write
/// everything under the data dir and nothing under the install
/// root.
/// CLAIM (W21 precision): prefix-preserving growth forgery by a
/// data-dir-only attacker is CLOSED at the signature leg;
/// rollback with a writable install root remains open and is
/// pinned as a NAMED LIMIT (test 7), never as a success.</summary>
public class W30PointerSigningTests
{
    private sealed record Rig(string Root, string DataDir, string Install, string Updates, string SlotA,
        UpdateManager Manager, ChainedAuditLog Audit, PointerSigningCustody Custody,
        RsaUpdateSignatureVerifier Signer, List<string> KeyingRecords);

    private Rig KeyedRig()
    {
        var audit = new ChainedAuditLog();
        var keying = new List<string>();
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
            keyingAudit: detail =>
            {
                keying.Add(detail);
                audit.Append(PointerSigningCustody.KeyingRecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow);
            });
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
        return new Rig(root, dataDir, install, updates, slotA, manager, audit, custody, signer, keying);
    }

    private string AuditPath(Rig rig) => Path.Combine(rig.DataDir, PointerAuditAnchor.AuditFileName);
    private void PersistAudit(Rig rig) => File.WriteAllText(AuditPath(rig), rig.Audit.ExportEntriesJson());
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private string PointerPath(Rig rig) => SlotPointer.PointerPath(rig.Updates);
    private string SigPath(Rig rig) => PointerSigningCustody.SignaturePathFor(PointerPath(rig));

    private byte[] AttackerPointer(Rig rig)
    {
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        return Encoding.UTF8.GetBytes(
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":\"attacker\",\"ActiveSlotHash\":\"" + slotHash + "\"}");
    }

    private static string PointerRecord(byte[] pointer) =>
        "pointer_sha256=" + Sha(pointer) + " active=A version=9.9.9 staged=- activeSlotHash=-";

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

    // ---------- §5.3 + keying basics: genuine chain verifies ----------

    [Fact]
    public void Keyed_GenuineChain_Verifies_KeyCustodiedOutsideDataDir_KeyingBeganRecorded()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        // Custody red line, by construction: seed + pin are in the
        // install root; NOTHING key-shaped is in the data dir.
        Assert.True(File.Exists(rig.Custody.SeedPath));
        Assert.True(File.Exists(rig.Custody.PinPath));
        Assert.StartsWith(rig.Install, rig.Custody.SeedPath);
        Assert.False(File.Exists(Path.Combine(rig.DataDir, PointerSigningCustody.SeedFileName)));
        Assert.Empty(Directory.EnumerateFiles(rig.DataDir, "*" + PointerSigningCustody.SeedFileName, SearchOption.AllDirectories));
        // The pointer is signed and the transition is chain evidence.
        Assert.True(File.Exists(SigPath(rig)));
        Assert.True(PointerSigningCustody.KeyingMarkerExists(rig.Updates));
        Assert.Single(rig.KeyingRecords);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == PointerSigningCustody.KeyingRecordKind
            && e.Detail.Contains(rig.Custody.Fingerprint!));
        Assert.Equal(rig.Custody.Fingerprint, rig.Manager.PointerSigningFingerprint);

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);

        // Legitimate growth still vouches and re-arms (marker grows).
        rig.Audit.Append("session_open", "SYSTEM", "later activity", DateTimeOffset.UtcNow);
        rig.Audit.Append("session_close", "SYSTEM", "more activity", DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok2, note2) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok2, note2);
        Assert.Equal(4, Assert.Single(PointerAnchorMarker.ReadAll(rig.Install)).ChainEntries);
    }

    [Fact]
    public void Keyed_PointerFallbackToBak_SignedBackup_VouchesUnderKeyedPosture()
    {
        // §4: the .bak is judged under the posture in force — here
        // the keyed one: corrupt main falls back to the signed
        // backup, whose own sidecar verifies.
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        File.WriteAllText(PointerPath(rig), "{corrupt");
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
    }

    // ---------- §5.1: THE closure case — data-dir-only growth forgery ----------

    [Fact]
    public void GrowthForgery_DataDirOnly_PrefixPreserving_RefusedAtSignatureLeg_MarkerNotRefreshed()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var markerBefore = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));

        // The W19 named-limit attack, verbatim, by an attacker who
        // can write ONLY the data dir: genuine prefix preserved, a
        // validly-linked pointer record appended for their pointer,
        // the pointer rewritten to match. Every unkeyed leg passes.
        // They cannot sign: the seed is in the install root.
        var attacker = AttackerPointer(rig);
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", PointerRecord(attacker), DateTimeOffset.UtcNow);
        PersistAudit(rig);
        File.WriteAllBytes(PointerPath(rig), attacker);
        // (The genuine sidecar is left in place — it signs the OLD
        // bytes, so it cannot vouch for the attacker's.)

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        // W36: the appended record carries no v2 scheme marker, so
        // refusal lands at the position leg by name (previously the
        // W30 byte-signature wording — same leg family, stronger).
        Assert.Contains("W36/DS-round-8", note!);
        // The refused check did NOT refresh the launcher marker.
        var markerAfter = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(markerBefore.ChainEntries, markerAfter.ChainEntries);
        Assert.Equal(markerBefore.ChainHead, markerAfter.ChainHead);
        // And the launcher falls back rather than exec the forged slot.
        var target = Acp.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.True(target.FellBack);
        Assert.Contains("signature", target.Reason);
    }

    // ---------- §5.2: tampered pointer ----------

    [Fact]
    public void TamperedPointer_OneByteFlip_RefusedAtSignatureLeg()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        // Flip one byte of the pointer (version 0.1.0 → 0.1.7) and
        // give the chain a matching record, so ONLY the signature
        // leg can refuse: it does.
        var tampered = File.ReadAllBytes(PointerPath(rig));
        var text = Encoding.UTF8.GetString(tampered).Replace("0.1.0", "0.1.7");
        Assert.NotEqual(Encoding.UTF8.GetString(tampered), text);
        tampered = Encoding.UTF8.GetBytes(text);
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", PointerRecord(tampered), DateTimeOffset.UtcNow);
        PersistAudit(rig);
        File.WriteAllBytes(PointerPath(rig), tampered);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        // W36: the matching record the attacker appends carries no
        // v2 scheme marker — refusal at the position leg by name.
        Assert.Contains("W36/DS-round-8", note!);
    }

    [Fact]
    public void TamperedSidecar_RefusedAtSignatureLeg()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        Assert.True(PointerSigningCustody.TryParseSidecar(File.ReadAllText(SigPath(rig)), out var sig, out var wasBound));
        Assert.True(wasBound); // W36: genuine sidecars are v2 position-bound
        sig[0] ^= 0xFF;
        File.WriteAllText(SigPath(rig), PointerSigningCustody.FormatSidecar(sig, positionBound: true));
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("signature does NOT verify", note!);
    }

    // ---------- §5.4: stripped signature / deleted pin after keying ----------

    [Fact]
    public void SignatureStripped_AfterFirstKeying_RefusedByName_NoDowngrade()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        File.Delete(SigPath(rig));
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("NO signature sidecar", note!);
        Assert.Contains("never a downgrade", note!);
    }

    [Fact]
    public void PinDeleted_AfterFirstKeying_RefusedByName_NoDowngrade()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        // The keying marker in the updates root survives as witness.
        File.Delete(rig.Custody.PinPath);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("runtime public pin", note!);
        Assert.Contains("never a downgrade", note!);
    }

    // ---------- §5.5: migration — legacy, transition, then refusal ----------

    [Fact]
    public void PreKeying_LegacyUnkeyedNamed_FirstSignedWriteTransitions_PostTransitionUnsignedRefused()
    {
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "Acp.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(dataDir, "updates");
        var audit = new ChainedAuditLog();

        // Pre-keying install: an unkeyed manager (no custody, no
        // audit seam — the pre-anchor shape). The posture is named.
        using var legacySigner = new RsaUpdateSignatureVerifier();
        var legacy = new UpdateManager(updates, legacySigner, _ => Task.FromResult(true));
        Assert.Null(legacy.PointerSigningFingerprint);
        var (okLegacy, legacyNote) = PointerAuditAnchor.Check(updates, install);
        Assert.True(okLegacy, legacyNote);
        Assert.Contains("LEGACY-UNKEYED", legacyNote!);

        // First signed write transitions the install: a keyed
        // manager over the same updates root stages (a write),
        // keying begins, and the transition is recorded.
        var keying = new List<string>();
        var custody = new PointerSigningCustody(install, dataDir);
        var keyed = new UpdateManager(updates, legacySigner, _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow),
            pointerSigning: custody,
            pointerAuditPositioned: detail =>
            {
                var e = audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow);
                return (e.Seq, e.Hash);
            },
            keyingAudit: detail =>
            {
                keying.Add(detail);
                audit.Append(PointerSigningCustody.KeyingRecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow);
            });
        var pkg = MakeZip(("AcpCore.exe", "slot core"), ("Acp.SessionAgent.exe", "slot agent"));
        Assert.True(keyed.StagePackage(pkg, legacySigner.Sign(pkg), "2.0.0").Ok);
        Assert.Single(keying);
        Assert.True(PointerSigningCustody.KeyingMarkerExists(updates));
        File.WriteAllText(AuditPath(new Rig(root, dataDir, install, updates, "", null!, audit, custody, legacySigner, keying)), audit.ExportEntriesJson());
        var (okKeyed, keyedNote) = PointerAuditAnchor.Check(updates, install);
        Assert.True(okKeyed, keyedNote);

        // Post-transition, an unsigned pointer refuses by name —
        // the legacy posture is gone for good.
        File.Delete(PointerSigningCustody.SignaturePathFor(SlotPointer.PointerPath(updates)));
        var (okAfter, afterNote) = PointerAuditAnchor.Check(updates, install);
        Assert.False(okAfter);
        Assert.Contains("NO signature sidecar", afterNote!);
    }

    // ---------- §5.6: custody red line ----------

    [Fact]
    public void PrivateKey_InDataDir_SigningRefusesByName()
    {
        var root = TestUtil.TempDir();
        var dataDir = Path.Combine(root, "data"); Directory.CreateDirectory(dataDir);
        var updates = Path.Combine(dataDir, "updates");
        // Custody configured INTO the data dir: refused by name at
        // construction, at keying, and at sign — and a manager
        // composed over it cannot write its first pointer.
        var bad = new PointerSigningCustody(Path.Combine(dataDir, "keys"), dataDir);
        Assert.NotNull(bad.CustodyRefusal);
        Assert.Contains("INSIDE the data dir", bad.CustodyRefusal!);
        var signRefusal = Assert.Throws<InvalidOperationException>(() => bad.Sign(new byte[] { 1, 2, 3 }));
        Assert.Contains("INSIDE the data dir", signRefusal.Message);
        using var signer = new RsaUpdateSignatureVerifier();
        var managerRefusal = Assert.Throws<InvalidOperationException>(() =>
            new UpdateManager(updates, signer, _ => Task.FromResult(true), pointerSigning: bad));
        Assert.Contains("INSIDE the data dir", managerRefusal.Message);
        Assert.False(File.Exists(SlotPointer.PointerPath(updates)));
    }

    // ---------- §5.7: rollback with writable install root — NAMED LIMIT ----------

    [Fact]
    public void Rollback_WritableInstallRoot_PassesSignatureLeg_NAMED_LIMIT_W21Precision()
    {
        // This test is named for the LIMIT, not as a success: an
        // attacker who can ALSO write the install root restores the
        // old genuine signed pointer + sidecar + old chain and
        // deletes the launcher marker — every signature verifies,
        // because every restored byte IS genuine. W30 does not
        // close this; W21 named it, and it stays named (see
        // PointerSigningCustody's doc). The data-dir-only half of
        // the same attack IS closed (growth forgery test above).
        // W36 note: the data-dir-only replay variant (append one
        // record, restore ONLY pointer + sidecar, marker intact)
        // is now ALSO closed — see W36PointerPositionTests; this
        // test's restore includes the old CHAIN and the marker
        // deletion, which are the install-root acts that keep it
        // a named limit rather than a data-dir attack.
        var rig = KeyedRig();
        PersistAudit(rig);
        var pointer1 = File.ReadAllBytes(PointerPath(rig));
        var sig1 = File.ReadAllText(SigPath(rig));
        var audit1 = File.ReadAllText(AuditPath(rig));
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        // Genuine advance: another anchored write grows the chain.
        // W36: the advance must be a genuine Core write (a stage) —
        // a hand-appended record carries no v2 scheme marker and
        // is, correctly, no longer a vouched pointer state.
        var pkgAdvance = MakeZip(("AcpCore.exe", "slot core v2"), ("Acp.SessionAgent.exe", "slot agent v2"));
        Assert.True(rig.Manager.StagePackage(pkgAdvance, rig.Signer.Sign(pkgAdvance), "2.0.0").Ok);
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        Assert.Equal(3, Assert.Single(PointerAnchorMarker.ReadAll(rig.Install)).ChainEntries);

        // Rollback with a writable install root: restore the old
        // genuine set and delete the launcher-side marker (the
        // install-root act a data-dir-only attacker cannot do).
        File.WriteAllText(AuditPath(rig), audit1);
        File.WriteAllBytes(PointerPath(rig), pointer1);
        File.WriteAllText(SigPath(rig), sig1);
        File.Delete(PointerAnchorMarker.MarkerPath(rig.Install));
        File.Delete(PointerAnchorMarker.MarkerPath(rig.Updates));

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note); // PINNED LIMIT (W21), not a closure claim
    }

    // ---------- Rotation at apply + genuine end-to-end ----------

    [Fact]
    public void RotationAtApply_PinRotates_FlippedPointerVerifies_LauncherResolvesSlot()
    {
        var rig = KeyedRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var fpBefore = rig.Custody.Fingerprint;
        var pinBefore = File.ReadAllText(rig.Custody.PinPath);

        var pkg = MakeZip(("AcpCore.exe", "slot core v2"), ("Acp.SessionAgent.exe", "slot agent v2"));
        Assert.True(rig.Manager.StagePackage(pkg, rig.Signer.Sign(pkg), "2.0.0").Ok);
        var applied = rig.Manager.ApplyStagedAsync(default).GetAwaiter().GetResult();
        Assert.True(applied.Ok, applied.Message);

        // Rotation happened at the apply: new seed, new pin, new
        // fingerprint — and the flipped pointer is signed under
        // the NEW key, so verification stays green end to end.
        Assert.NotEqual(fpBefore, rig.Custody.Fingerprint);
        Assert.NotEqual(pinBefore, File.ReadAllText(rig.Custody.PinPath));
        Assert.Equal(rig.Custody.Fingerprint, rig.Manager.PointerSigningFingerprint);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
        var target = Acp.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates);
        Assert.False(target.FellBack, target.Reason);
        Assert.EndsWith(Path.Combine("slots", "B", "AcpCore.exe"), target.CoreExe);
    }

    // ---------- Repinning outside install/update events ----------

    [Fact]
    public void Repin_OutsideAuthorisedEvent_Refused_PinUnchanged()
    {
        var rig = KeyedRig();
        var pinBefore = File.ReadAllText(rig.Custody.PinPath);
        var (attackerSeed, attackerPub) = Ed25519.GenerateKeyPair();
        _ = attackerSeed;
        var (ok, reason) = rig.Custody.TryRepin(attackerPub, authorisedByProductionSignedEvent: false);
        Assert.False(ok);
        Assert.Contains("authorised ONLY", reason);
        Assert.Equal(pinBefore, File.ReadAllText(rig.Custody.PinPath));
        // Control: the same repin WITH a production-signed event
        // named is the authorised shape and takes effect.
        var (ok2, _) = rig.Custody.TryRepin(attackerPub, authorisedByProductionSignedEvent: true);
        Assert.True(ok2);
        Assert.NotEqual(pinBefore, File.ReadAllText(rig.Custody.PinPath));
    }

    // ---------- CoreRuntime composition ----------

    [Fact]
    public void CoreRuntime_WithInstallRoot_KeysPointerSigning_AndStatusNamesIt()
    {
        var dir = TestUtil.TempDir();
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        var runtime = new Acp.Core.CoreRuntime(new Acp.Core.CoreOptions
        {
            DataDir = dataDir, Port = 18931, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install,
        });
        Assert.Contains("pointer signing: runtime key keyed", runtime.PointerSigningStatus);
        Assert.True(File.Exists(Path.Combine(install, PointerSigningCustody.PinFileName)));
        Assert.NotNull(runtime.Updates.PointerSigningFingerprint);
        // The Core's initial pointer (written into <dataDir>/updates
        // by the manager's constructor) is signed under that key.
        Assert.True(File.Exists(PointerSigningCustody.SignaturePathFor(
            SlotPointer.PointerPath(Path.Combine(dataDir, "updates")))));
    }

    [Fact]
    public void CoreRuntime_InstallRootInsideDataDir_RefusesByName_NamedPosture()
    {
        var dir = TestUtil.TempDir();
        var runtime = new Acp.Core.CoreRuntime(new Acp.Core.CoreOptions
        {
            DataDir = dir, Port = 18932, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = Path.Combine(dir, "keys-inside-data"),
        });
        Assert.Contains("custody REFUSED", runtime.PointerSigningStatus);
        Assert.Contains("INSIDE the data dir", runtime.PointerSigningStatus);
        Assert.Null(runtime.Updates.PointerSigningFingerprint);
    }
}

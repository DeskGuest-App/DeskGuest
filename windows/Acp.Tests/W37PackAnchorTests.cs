using System.Reflection;
using Acp.Core.Services;
using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Update;

namespace Acp.Tests;

// W37 — compliance-pack KEYED anchoring (closing the append-replay
// sibling hole W36-B §3 named). The probe that opened this lane
// (temporary W37ProbeTests, deleted after the fix; output in the
// lane harness dir, probe.log) reproduced the attack verbatim
// against the pre-fix code: alter a stored pack, recompute its
// unkeyed hash, append a matching compliance_pack_compiled record
// — VerifyStoredPack PASSED. These tests are that attack and its
// siblings, now required to refuse at the position-bound
// signature leg, plus the genuine, restart, rotation and legacy
// postures, all named.
public class W37PackAnchorTests
{
    private sealed class KeyedRig : IDisposable
    {
        public required Rmm05Tests.Rig Vuln { get; init; }
        public required ComplianceService Service { get; init; }
        public required PointerSigningCustody Custody { get; init; }
        public required string InstallRoot { get; init; }
        public required string DataDir { get; init; }
        public void Dispose()
        {
            try { Directory.Delete(InstallRoot, recursive: true); } catch { }
            try { Directory.Delete(DataDir, recursive: true); } catch { }
        }
    }

    private static KeyedRig NewKeyedRig()
    {
        var v = Rmm05Tests.NewRig();
        var install = TestUtil.TempDir();
        var data = TestUtil.TempDir();
        var custody = new PointerSigningCustody(install, data);
        custody.EnsureKeyForInstall();
        var svc = new ComplianceService(v.Audit, v.Policies, v.Inventory,
            v.Patches.Service, v.Service, v.Clock.UtcNow, custody);
        svc.ContentPacks.SeedDefaults();
        return new KeyedRig { Vuln = v, Service = svc, Custody = custody, InstallRoot = install, DataDir = data };
    }

    // A rig whose service shares the Rmm09 helper shape (device +
    // security state registered through the SERVICE under test).
    private static void AddDevice(KeyedRig rig, ComplianceService svc)
    {
        rig.Vuln.Inventory.ApplyBaseline(
            Rmm05Tests.Record("dev1", software: new[] { ("Google Chrome", "130.0") }), Rmm09Tests.T0);
        svc.RegisterSecurityState(new DeviceSecurityState(
            "dev1", "scope1", true, true, true, Rmm09Tests.T0), "monitor");
    }

    private static void ReplaceStoredPack(ComplianceService svc, CompliancePack altered)
    {
        var t = typeof(ComplianceService);
        var byId = (System.Collections.IDictionary)t.GetField("_packsById", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(svc)!;
        byId[altered.PackId] = altered;
        var hist = (System.Collections.IList)t.GetField("_packHistory", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(svc)!;
        for (var i = 0; i < hist.Count; i++)
            if (((CompliancePack)hist[i]!).PackId == altered.PackId) hist[i] = altered;
    }

    private static CompliancePack Altered(CompliancePack pack) =>
        pack with { Verdicts = pack.Verdicts.Select(v => v with { Reason = "forged: all fine" }).ToList() };

    private static void AppendForgedAnchor(ChainedAuditLog audit, CompliancePack altered, bool schemeMarker = false) =>
        audit.Append("compliance_pack_compiled", "attacker",
            $"pack={altered.PackId} framework=hipaa scope=scope1 kind=evidence_pack satisfied={altered.SatisfiedCount} gaps={altered.GapCount} treated={altered.TreatedGapCount} contentHash={altered.ContentHash}{(schemeMarker ? " " + PackAuditAnchor.SchemeMarker : "")} headline={altered.Headline}",
            Rmm09Tests.T0.AddMinutes(5));

    // ---- the probed attack, verbatim -------------------------------

    [Fact]
    public void ProbedAttack_Verbatim_RefusedAtSignatureLeg()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(pack.PackId, out var okReason), okReason);
        Assert.Contains("position-bound signature verifies", okReason);
        // Attack: alter stored pack, recompute hash, append record.
        var altered = Altered(pack);
        Assert.NotEqual(pack.ContentHash, altered.ContentHash);
        ReplaceStoredPack(rig.Service, altered);
        AppendForgedAnchor(rig.Vuln.Audit, altered);
        Assert.False(rig.Service.VerifyStoredPack(pack.PackId, out var reason));
        // The verbatim forged record carries no scheme marker, so
        // it refuses at the position-less/legacy leg (keying has
        // begun); the scheme-forged form below reaches — and is
        // refused at — the signature leg itself.
        Assert.Contains("LEGACY-UNKEYED-PACK", reason);
        Assert.Contains("pack keying has begun", reason);
    }

    [Fact]
    public void ProbedAttack_StrongestForm_SchemeMarkerForged_StillRefusedAtSignatureLeg()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var altered = Altered(pack);
        ReplaceStoredPack(rig.Service, altered);
        // Strongest form: the forged record even carries the v1
        // scheme marker, so hash + scheme legs pass and only the
        // signature leg can refuse.
        AppendForgedAnchor(rig.Vuln.Audit, altered, schemeMarker: true);
        Assert.False(rig.Service.VerifyStoredPack(pack.PackId, out var reason));
        Assert.Contains("NO compliance_pack_signature record names its position", reason);
    }

    [Fact]
    public void ReplayedGenuineSignature_OntoAppendedRecord_RefusedAtPositionLeg()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        // Capture the genuine signature record, then replay BOTH
        // forged anchor and genuine signature record at new
        // positions (the attacker's best replay).
        var genuineSig = rig.Vuln.Audit.Entries.Last(e => e.Kind == PackAuditAnchor.SignatureKind);
        var altered = Altered(pack);
        ReplaceStoredPack(rig.Service, altered);
        AppendForgedAnchor(rig.Vuln.Audit, altered, schemeMarker: true);
        var forgedAnchor = rig.Vuln.Audit.Entries.Last(e => e.Kind == PackAuditAnchor.CompiledKind);
        // Replay the genuine sig bytes, re-pointed at the forged
        // record's seq in the detail (detail is attacker's to write;
        // the SIGNATURE still commits to the genuine position).
        var sigToken = genuineSig.Detail.Split("pack_sig=")[1].Split(' ')[0];
        var fpToken = genuineSig.Detail.Split("pack_key_fp=")[1].Split(' ')[0];
        rig.Vuln.Audit.Append(PackAuditAnchor.SignatureKind, "attacker",
            $"pack={pack.PackId} compiled_seq={forgedAnchor.Seq} pack_key_fp={fpToken} pack_sig={sigToken}",
            Rmm09Tests.T0.AddMinutes(6));
        Assert.False(rig.Service.VerifyStoredPack(pack.PackId, out var reason));
        Assert.Contains("POSITION-BOUND signature does NOT verify", reason);
    }

    // ---- genuine flow, restart, rotation ----------------------------

    [Fact]
    public void GenuineCompile_Store_Verify_Passes_AndSurvivesSimulatedRestart()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(pack.PackId, out var reason), reason);
        Assert.Contains("keyed anchor (W37)", reason);
        // Simulated Core restart: chain exported from the data dir
        // and re-imported into a fresh log; fresh service over the
        // SAME custody (install root untouched); pack restored.
        var json = rig.Vuln.Audit.ExportEntriesJson();
        var audit2 = new ChainedAuditLog();
        Assert.True(audit2.ImportEntriesJson(json).Ok);
        var svc2 = new ComplianceService(audit2, rig.Vuln.Policies, rig.Vuln.Inventory,
            rig.Vuln.Patches.Service, rig.Vuln.Service, rig.Vuln.Clock.UtcNow, rig.Custody);
        svc2.RestoreStoredPack(pack);
        Assert.True(svc2.VerifyStoredPack(pack.PackId, out var reason2), reason2);
        // And the probed attack still refuses after the restart:
        var altered = Altered(pack);
        svc2.RestoreStoredPack(altered);
        audit2.Append("compliance_pack_compiled", "attacker",
            $"pack={altered.PackId} framework=hipaa scope=scope1 kind=evidence_pack satisfied={altered.SatisfiedCount} gaps={altered.GapCount} treated={altered.TreatedGapCount} contentHash={altered.ContentHash} headline={altered.Headline}",
            Rmm09Tests.T0.AddMinutes(5));
        Assert.False(svc2.VerifyStoredPack(pack.PackId, out var reason3));
        Assert.Contains("LEGACY-UNKEYED-PACK", reason3);
    }

    [Fact]
    public void Rotation_PacksSignedBeforeRotation_StillVerify_NewPacksSignUnderRotatedKey()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var before = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var fpBefore = rig.Custody.Fingerprint;
        rig.Custody.RotateAuthorisedByProductionSignedUpdate();
        Assert.NotEqual(fpBefore, rig.Custody.Fingerprint);
        // Pre-rotation pack still verifies (archived pin, named fp).
        Assert.True(rig.Service.VerifyStoredPack(before.PackId, out var r1), r1);
        Assert.Contains(fpBefore!, r1);
        // New packs sign under the rotated key and verify.
        var after = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(after.PackId, out var r2), r2);
        Assert.Contains(rig.Custody.Fingerprint!, r2);
    }

    // ---- migration: LEGACY-UNKEYED-PACK, fail-closed and named ------

    [Fact]
    public void LegacyPack_BeforeKeyingBegins_AcceptedUnderNamedPosture()
    {
        var rig = Rmm09Tests.NewRig(); // unkeyed composition
        Rmm09Tests.AddDevice(rig);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(pack.PackId, out var reason), reason);
        Assert.Contains("LEGACY-UNKEYED-PACK posture", reason);
    }

    [Fact]
    public void LegacyPack_AfterKeyingBegins_RefusedByName()
    {
        using var rig = NewKeyedRig();
        // A genuine pre-W37 legacy pack + its unkeyed record,
        // hand-built on the same chain BEFORE any keyed compile.
        var legacySvc = new ComplianceService(rig.Vuln.Audit, rig.Vuln.Policies, rig.Vuln.Inventory,
            rig.Vuln.Patches.Service, rig.Vuln.Service, rig.Vuln.Clock.UtcNow);
        AddDevice(rig, legacySvc);
        var legacy = legacySvc.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        // Keying begins: a keyed compile on the same chain.
        AddDevice(rig, rig.Service);
        var keyed = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(keyed.PackId, out var ok), ok);
        // The legacy pack now refuses BY NAME under the keyed
        // service (witness: the scheme-marked record in the chain).
        rig.Service.RestoreStoredPack(legacy);
        Assert.False(rig.Service.VerifyStoredPack(legacy.PackId, out var reason));
        Assert.Contains("LEGACY-UNKEYED-PACK", reason);
        Assert.Contains("pack keying has begun", reason);
    }

    [Fact]
    public void KeyedRecord_JudgedByUnkeyedComposition_RefusesByName()
    {
        using var rig = NewKeyedRig();
        AddDevice(rig, rig.Service);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var unkeyed = new ComplianceService(rig.Vuln.Audit, rig.Vuln.Policies, rig.Vuln.Inventory,
            rig.Vuln.Patches.Service, rig.Vuln.Service, rig.Vuln.Clock.UtcNow);
        unkeyed.RestoreStoredPack(pack);
        Assert.False(unkeyed.VerifyStoredPack(pack.PackId, out var reason));
        Assert.Contains("no pack-signing custody", reason);
    }

    [Fact]
    public void CustodyInsideDataDir_KeyedCompile_RefusesByName_NoPackStored()
    {
        var v = Rmm05Tests.NewRig();
        var data = TestUtil.TempDir();
        var badCustody = new PointerSigningCustody(Path.Combine(data, "install"), data);
        Assert.NotNull(badCustody.CustodyRefusal);
        var svc = new ComplianceService(v.Audit, v.Policies, v.Inventory,
            v.Patches.Service, v.Service, v.Clock.UtcNow, badCustody);
        var result = svc.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin");
        Assert.False(result.Ok);
        Assert.Contains("custody REFUSED", result.Reason);
        Assert.Empty(svc.PackHistory);
        try { Directory.Delete(data, recursive: true); } catch { }
    }
}

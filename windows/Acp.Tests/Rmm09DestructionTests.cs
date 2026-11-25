using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;

namespace Acp.Tests;

// RMM-09 DESTRUCTION PASS — hostile attacks on the compliance
// evidence pack. Attacker models: a pack FORGER (satisfied without
// facts, tampered artefacts), a stale-fact LAUNDERER (old facts as
// current, replayed observations), a content-pack POISONER
// (always-pass controls, dropped hard controls, rollbacks), a
// treatment-plan GAMER (ownerless/expired/cross-scope plans), a
// movement FORGER (diffs that hide new gaps), and cross-scope
// evidence BLEED. Every test is a permanent regression: if it ever
// fails, the attack succeeded.
public class Rmm09DestructionTests
{
    private static readonly DateTimeOffset T0 = Rmm09Tests.T0;

    private static ComplianceFact Fact(string kind, string? deviceId, string scopeId,
        bool passing, DateTimeOffset observed, string detail = "fact") =>
        new(kind, deviceId, scopeId, passing, observed, detail,
            ComplianceHash.Sha256Hex($"{kind}|{deviceId}|{observed:O}|{detail}"));

    private static CompliancePack CompileDirect(ComplianceFactSet facts, TreatmentStore? treatments = null,
        ComplianceContentPack? content = null, DateTimeOffset? now = null) =>
        ComplianceCompiler.Compile(content ?? SeededPacks.Hipaa(), facts,
            treatments ?? new TreatmentStore(), ComplianceStalenessPolicy.Default,
            now ?? T0, "attacker-test");

    // ---- pack forgery ---------------------------------------------------

    [Fact]
    public void ATTACK_SatisfiedWithNoFact_Impossible()
    {
        // A fact set naming a real device but carrying NO facts:
        // every control must be a gap. There is no input to the
        // compiler that asserts satisfaction.
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0);
        var pack = CompileDirect(facts);
        Assert.Equal(0, pack.SatisfiedCount);
        Assert.All(pack.Verdicts, v => Assert.Equal(GapKinds.MissingFact, v.GapKind));
    }

    [Fact]
    public void ATTACK_VacuousScope_ZeroDevicesSatisfiesNothing()
    {
        // Even with passing scope-level facts, an EMPTY device
        // roster satisfies no device-scoped control.
        var facts = new ComplianceFactSet("scope1", Array.Empty<string>(), new[]
        {
            Fact(ComplianceFactKinds.AuditChain, null, "scope1", true, T0),
            Fact(ComplianceFactKinds.AuditHistory, null, "scope1", true, T0),
        }, T0);
        var pack = CompileDirect(facts);
        foreach (var id in new[] { "hipaa-encryption", "hipaa-security-updates", "hipaa-device-inventory", "hipaa-malware-protection" })
            Assert.Equal(GapKinds.MissingFact, pack.Verdicts.Single(v => v.ControlId == id).GapKind);
    }

    [Fact]
    public void ATTACK_TamperedPack_FailsContentHash()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig, encryption: false);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(pack.VerifyContentHash(pack.ContentHash));
        // The forger flips the encryption gap to satisfied:
        var forged = pack with
        {
            Verdicts = pack.Verdicts.Select(v => v.ControlId == "hipaa-encryption"
                ? v with { Outcome = ControlOutcomes.Satisfied, GapKind = null }
                : v).ToList(),
        };
        Assert.False(forged.VerifyContentHash(pack.ContentHash));
        Assert.NotEqual(pack.ContentHash, forged.ContentHash);
        Assert.Contains("GAPS PRESENT", pack.Headline); // the genuine pack never claimed otherwise
    }

    [Fact]
    public void ATTACK_BrokenAuditChain_FailsAuditControls()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        Rmm09Tests.CompleteScope(rig);
        var good = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied,
            good.Verdicts.Single(v => v.ControlId == "hipaa-audit-controls").Outcome);
        // Tamper with the stored chain: rewrite one entry's detail.
        var json = rig.Vuln.Audit.ExportEntriesJson();
        var tampered = json.Replace("routine session", "routine sessioN");
        Assert.NotEqual(json, tampered);
        var verification = rig.Vuln.Audit.ImportEntriesJson(tampered);
        Assert.False(verification.Ok);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = pack.Verdicts.Single(x => x.ControlId == "hipaa-audit-controls");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("BROKEN", v.Reason);
    }

    // ---- cross-device / cross-scope bleed ---------------------------------

    [Fact]
    public void ATTACK_CrossDeviceBleed_OneDevicesFactEvidencesNoOther()
    {
        var facts = new ComplianceFactSet("scope1", new[] { "dev1", "dev2" }, new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", true, T0), // only dev1 evidenced
        }, T0);
        var pack = CompileDirect(facts);
        var v = pack.Verdicts.Single(x => x.ControlId == "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.MissingFact, v.GapKind);
        Assert.Contains("dev2", v.FailingDevices);
    }

    [Fact]
    public void ATTACK_CrossScopeBleed_ForeignScopeFactsExcluded()
    {
        // Every fact a forger could want — all naming scope "evil".
        var foreign = new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "evil", true, T0),
            Fact(ComplianceFactKinds.PatchState, "dev1", "evil", true, T0),
            Fact(ComplianceFactKinds.InventoryPresence, "dev1", "evil", true, T0),
            Fact(ComplianceFactKinds.SecurityState, "dev1", "evil", true, T0),
            Fact(ComplianceFactKinds.AuditChain, null, "evil", true, T0),
            Fact(ComplianceFactKinds.AuditHistory, null, "evil", true, T0),
            Fact(ComplianceFactKinds.AccessReview, null, "evil", true, T0),
            Fact(ComplianceFactKinds.VulnerabilityState, null, "evil", true, T0, "open=0; overdue=0; kevOpen=0; closed=9"),
        };
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, foreign, T0);
        var pack = CompileDirect(facts);
        Assert.Equal(0, pack.SatisfiedCount);
        Assert.Contains(pack.ProvenanceNotes, n => n.Contains("EXCLUDED"));
    }

    // ---- stale-fact laundering ----------------------------------------------

    [Fact]
    public void ATTACK_StaleFactLaundering_OldObservationNeverPasses()
    {
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", true, T0.AddDays(-60)),
        }, T0);
        var pack = CompileDirect(facts);
        var v = pack.Verdicts.Single(x => x.ControlId == "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.StaleFact, v.GapKind);
        // And the pack's face carries the true observation instant:
        Assert.Equal(T0.AddDays(-60), v.FactObservedUtc);
    }

    [Fact]
    public void ATTACK_SecurityStateReplay_OlderObservationRefusedByStore()
    {
        var store = new SecurityStateStore();
        Assert.True(store.Record(new DeviceSecurityState("dev1", "scope1", true, true, false, T0))); // encryption OFF, current
        // Replay last week's "encryption on" over it:
        Assert.False(store.Record(new DeviceSecurityState("dev1", "scope1", true, true, true, T0.AddDays(-7))));
        Assert.False(store.Record(new DeviceSecurityState("dev1", "scope1", true, true, true, T0))); // same instant, different value
        Assert.Equal(false, store.Get("dev1")!.EncryptionEnabled);
    }

    [Fact]
    public void ATTACK_UpstreamStaleFlag_CannotBeLaunderedByFreshTimestamp()
    {
        // A vulnerability fact with a FRESH observation instant whose
        // source names itself stale (the RMM-05 feed verdict):
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            new ComplianceFact(ComplianceFactKinds.VulnerabilityState, null, "scope1",
                Passing: true, T0, "open=0; overdue=0; kevOpen=0; closed=3",
                ComplianceHash.Sha256Hex("vuln"), UpstreamStale: true,
                UpstreamStaleNote: "STALE FEED: published 30 days ago"),
        }, T0);
        var pack = CompileDirect(facts);
        var v = pack.Verdicts.Single(x => x.ControlId == "hipaa-risk-analysis");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.StaleFact, v.GapKind);
    }

    // ---- content-pack poisoning ------------------------------------------------

    [Fact]
    public void ATTACK_PoisonedPack_AlwaysPassRule_AndUnknownFactKind_Refused()
    {
        var store = new ComplianceContentPackStore();
        var alwaysPass = new ComplianceContentPack("evil", "evil-fw", 1, new[]
        {
            new ComplianceControl("c1", "X.1", "Everything is fine", ComplianceFactKinds.PatchState, "always_pass"),
        });
        var r1 = store.Admit(alwaysPass);
        Assert.False(r1.Accepted);
        Assert.Contains("always-pass", r1.Reason);

        var unknownFact = new ComplianceContentPack("evil2", "evil-fw2", 1, new[]
        {
            new ComplianceControl("c1", "X.1", "Trust us", "management_assertion", ComplianceRules.FactPassing),
        });
        var r2 = store.Admit(unknownFact);
        Assert.False(r2.Accepted);
        Assert.Contains("unknown fact kind", r2.Reason);

        var empty = new ComplianceContentPack("evil3", "evil-fw3", 1, Array.Empty<ComplianceControl>());
        Assert.False(store.Admit(empty).Accepted); // an empty checklist would "pass" vacuously
        Assert.Null(store.Get("evil-fw"));
    }

    [Fact]
    public void ATTACK_PackDropsHardControls_RemovalIsLoud()
    {
        var rig = Rmm09Tests.NewRig();
        // D38-F11: this test previously claimed "the movement diff
        // names the removals too" but only compiled an untouched
        // gdpr pack and asserted NotNull. It now does what it says:
        // compile hipaa BEFORE and AFTER the weakening revision
        // and diff those two packs.
        var before = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var weakened = SeededPacks.Hipaa() with
        {
            Revision = 2,
            Controls = SeededPacks.Hipaa().Controls
                .Where(c => c.ControlId != "hipaa-encryption" && c.ControlId != "hipaa-audit-controls")
                .ToList(),
        };
        var admission = rig.Service.AdmitContentPack(weakened, "attacker-admin");
        Assert.True(admission.Accepted); // a revision MAY retire controls…
        Assert.Contains("hipaa-encryption", admission.RemovedControlIds); // …but never silently
        Assert.Contains("hipaa-audit-controls", admission.RemovedControlIds);
        Assert.Contains(rig.Vuln.Audit.Entries, e =>
            e.Kind == "compliance_pack_controls_removed" &&
            e.Detail.Contains("hipaa-encryption") && e.Detail.Contains("hipaa-audit-controls"));
        // And the movement diff names the removals too (the clock
        // advances so the second compile is a distinct pack):
        rig.Clock.Now = T0.AddHours(1);
        var after = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.NotEqual(before.PackId, after.PackId);
        var diff = rig.Service.DiffPacks(before.PackId, after.PackId, "auditor");
        Assert.Contains(diff.Removed, m => m.ControlId == "hipaa-encryption");
        Assert.Contains(diff.Removed, m => m.ControlId == "hipaa-audit-controls");
        Assert.Equal(0, diff.UnaccountedCount);
        Assert.Equal(before.Verdicts.Count, diff.Movements.Count); // union of both checklists
    }

    [Fact]
    public void ATTACK_PackRollback_AndSameRevisionSwap_Refused()
    {
        var store = new ComplianceContentPackStore();
        Assert.True(store.Admit(SeededPacks.Hipaa() with { Revision = 3 }).Accepted);
        var rollback = store.Admit(SeededPacks.Hipaa() with { Revision = 2 });
        Assert.False(rollback.Accepted);
        Assert.Contains("stale", rollback.Reason);
        var swap = store.Admit(SeededPacks.Hipaa() with
        {
            Revision = 3,
            Controls = SeededPacks.Hipaa().Controls.Take(3).ToList(),
        });
        Assert.False(swap.Accepted);
        Assert.Contains("conflicts", swap.Reason);
        Assert.Equal(3, store.Get("hipaa")!.Revision);
        Assert.Equal(SeededPacks.Hipaa().Controls.Count, store.Get("hipaa")!.Controls.Count);
    }

    // ---- treatment-plan games ------------------------------------------------------

    [Fact]
    public void ATTACK_TreatmentGames_OwnerlessExpiredAndCrossScope_NeverCloseAGap()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig, encryption: false);
        // Ownerless: refused at the store.
        Assert.False(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "  ", "we will fix it", T0.AddDays(30), "attacker").Ok);
        // Cross-scope: a plan for scope2 must not treat scope1's gap.
        Assert.True(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope2",
            "alice", "other site's plan", T0.AddDays(30), "admin").Ok);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Gap,
            pack.Verdicts.Single(v => v.ControlId == "hipaa-encryption").Outcome);
        // Expired: recorded live, then the clock passes its target
        // while the fact stays fresh and failing — gap reopens.
        Assert.True(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "real plan", T0.AddDays(5), "admin").Ok);
        rig.Clock.Now = T0.AddDays(6);
        Rmm09Tests.AddDevice(rig, encryption: false, observed: T0.AddDays(6));
        var pack2 = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = pack2.Verdicts.Single(x => x.ControlId == "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Contains("EXPIRED", v.Reason);
    }

    [Fact]
    public void ATTACK_TreatmentOnSatisfiedControl_DoesNothing()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig, encryption: true);
        Assert.True(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "belt and braces", T0.AddDays(30), "admin").Ok);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = pack.Verdicts.Single(x => x.ControlId == "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Satisfied, v.Outcome);
        Assert.Null(v.TreatmentId); // satisfaction comes from the fact, never the plan
    }

    // ---- movement forgery -------------------------------------------------------------

    [Fact]
    public void ATTACK_MovementForgery_NewlyOpenedGap_CannotBeHidden()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig, encryption: true);
        Rmm09Tests.CompleteScope(rig);
        var p1 = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied,
            p1.Verdicts.Single(v => v.ControlId == "hipaa-encryption").Outcome);

        // D38-F3: clock first, then the report at that instant
        // (future-dated reports refuse now — see Rmm09D38FixTests).
        rig.Clock.Now = T0.AddHours(3);
        Rmm09Tests.AddDevice(rig, encryption: false, observed: T0.AddHours(3));
        var p2 = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var diff = rig.Service.DiffPacks(p1.PackId, p2.PackId, "auditor");
        Assert.Contains(diff.Opened, m => m.ControlId == "hipaa-encryption");
        Assert.Equal(0, diff.UnaccountedCount);
        Assert.Equal(diff.Movements.Count,
            diff.Closed.Count + diff.Opened.Count + diff.StillOpen.Count +
            diff.Movements.Count(m => m.Category == MovementCategories.StillSatisfied) +
            diff.Movements.Count(m => m.Category == MovementCategories.NewSatisfied) +
            diff.Movements.Count(m => m.Category == MovementCategories.TreatmentChanged) +
            diff.Removed.Count);
        var text = CompliancePackRenderer.RenderDiffPlainText(diff);
        Assert.Contains("hipaa-encryption", text);
        Assert.Contains("opened", text);
    }

    [Fact]
    public void ATTACK_MovementDiff_ControlRemoved_IsNamedNotDropped()
    {
        var e = CompileDirect(new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", true, T0),
        }, T0));
        var laterContent = SeededPacks.Hipaa() with
        {
            Revision = 2,
            Controls = SeededPacks.Hipaa().Controls.Where(c => c.ControlId != "hipaa-encryption").ToList(),
        };
        var l = CompileDirect(new ComplianceFactSet("scope1", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0),
            content: laterContent, now: T0.AddDays(1));
        var diff = CompliancePackDiffer.Compare(e, l);
        Assert.Contains(diff.Removed, m => m.ControlId == "hipaa-encryption");
        Assert.Equal(0, diff.UnaccountedCount);
    }

    // ---- service-level refusal ---------------------------------------------------------

    [Fact]
    public void ATTACK_SecurityStateForUnknownDevice_MintsNoEvidence()
    {
        var rig = Rmm09Tests.NewRig();
        // A glowing security report for a device that has no
        // inventory record: the roster comes from RMM-04, so the
        // phantom device is not in scope and evidences nothing.
        rig.Service.RegisterSecurityState(new DeviceSecurityState(
            "phantom", "scope1", true, true, true, T0), "attacker");
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        // No DEVICE-scoped control may be satisfied by the phantom's
        // report (the scope-level audit controls are legitimately
        // evidenced by the chained audit itself — the intake call
        // above is one of its entries — and are not the attack).
        foreach (var id in new[] { "hipaa-encryption", "hipaa-malware-protection", "hipaa-security-updates", "hipaa-device-inventory" })
        {
            var v = pack.Verdicts.Single(x => x.ControlId == id);
            Assert.Equal(ControlOutcomes.Gap, v.Outcome);
            Assert.Equal(GapKinds.MissingFact, v.GapKind);
        }
        Assert.DoesNotContain(pack.Verdicts, v => v.FailingDevices.Contains("phantom"));
    }
}

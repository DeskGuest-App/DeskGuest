using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Hub;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;

namespace Acp.Tests;

// RMM-09 D38 FIX — regression tests for the 12 findings of packet
// 9b61590c. Every test here pins one finding's fix: if it fails,
// that attack works again. Attacker models as in the destruction
// pass: pack FORGER, stale-fact LAUNDERER, content-pack POISONER,
// treatment-plan GAMER, movement FORGER, cross-scope BLEEDER.
public class Rmm09D38FixTests
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
            now ?? T0, "d38-fix-test");

    private static ControlVerdict Verdict(CompliancePack pack, string controlId) =>
        pack.Verdicts.Single(v => v.ControlId == controlId);

    private static DeviceInventoryRecord SiteRecord(string deviceId, string scopeId,
        params (string Name, string Version)[] software) => new(
            deviceId, scopeId, "host-" + deviceId,
            new HardwareSnapshot("Contoso", "Model", null, "CPU", 4, 16L << 30,
                "Windows 11 Pro", "22631.1000", "22631.1000", null,
                Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
            software.Select(s => new SoftwareItem(s.Name, s.Version, null, null, null)).ToList(),
            new Dictionary<string, string>(), new HashSet<string>(),
            T0, T0, T0, 1);

    // ---- F1: access review -------------------------------------------

    [Fact]
    public void F1_UnansweredCampaign_TimesOutToDefaulted_DoesNotPass()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        var campaign = new AccessReviewCampaign(new[] { "alice", "bob" }, T0.AddDays(14));
        rig.Service.RegisterAccessReview("camp-silent", campaign, "scope1", "admin"); // nobody answers
        rig.Clock.Now = T0.AddDays(15); // past the deadline: DIR-54 defaults fire
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-access-review");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome); // timing out is NOT completing
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("defaulted_suspend=2", v.Reason);
        Assert.Contains("pending=0", v.Reason); // the old code passed on exactly this
    }

    [Fact]
    public void F1_ForeignScopeCampaign_EvidencesNothingHere()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        var campaign = new AccessReviewCampaign(new[] { "alice" }, T0.AddDays(14));
        campaign.Attest("alice");
        rig.Service.RegisterAccessReview("camp-site2", campaign, "site2", "admin"); // a DIFFERENT site's review
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-access-review");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.MissingFact, v.GapKind); // scope1 has no campaign of its own
    }

    [Fact]
    public void F1_CompletedCampaign_GoesStaleAfterItsDeadline()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        var campaign = new AccessReviewCampaign(new[] { "alice" }, T0.AddDays(14));
        campaign.Attest("alice");
        rig.Service.RegisterAccessReview("camp-old", campaign, "scope1", "admin");
        rig.Clock.Now = T0.AddDays(30); // the review closed 16 days ago
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-access-review");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.StaleFact, v.GapKind); // not re-stamped fresh at compile time
        Assert.Equal(T0.AddDays(14), v.FactObservedUtc);
    }

    // ---- F2: audit history ---------------------------------------------

    [Fact]
    public void F2_BrokenChain_AuditHistoryControlsFailToo()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        Rmm09Tests.CompleteScope(rig);
        var good = rig.Service.CompilePack(Rmm09Tests.Facts(), "gdpr", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(good, "gdpr-accountability").Outcome);
        var json = rig.Vuln.Audit.ExportEntriesJson();
        var tampered = json.Replace("routine session", "routine sessioN");
        Assert.False(rig.Vuln.Audit.ImportEntriesJson(tampered).Ok);
        var gdpr = rig.Service.CompilePack(Rmm09Tests.Facts(), "gdpr", "admin").Pack!;
        var v = Verdict(gdpr, "gdpr-accountability");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome); // history does NOT pass on a broken chain
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("BROKEN", v.Reason);
        var cmmc = rig.Service.CompilePack(Rmm09Tests.Facts(), "cmmc", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Gap, Verdict(cmmc, "cmmc-au-audit-records").Outcome);
    }

    [Fact]
    public void F2_ScopeWithNoInventory_GetsNoAuditFacts()
    {
        var rig = Rmm09Tests.NewRig();
        rig.Vuln.Audit.Append("session", "tech", "someone did something", T0); // the hub chain exists…
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!; // …but scope1 holds no devices
        Assert.Equal(GapKinds.MissingFact, Verdict(pack, "hipaa-audit-controls").GapKind);
        Assert.Equal(GapKinds.MissingFact, Verdict(pack, "hipaa-access-review").GapKind);
    }

    // ---- F3: future-dated observations -----------------------------------

    [Fact]
    public void F3_FutureSecurityState_Refused_AndDoesNotPoisonTheStore()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig); // dev1 baselined at T0
        // A report from next year: refused, and the real report after it still lands.
        Assert.False(rig.Service.RegisterSecurityState(
            new DeviceSecurityState("dev1", "scope1", true, true, true, T0.AddYears(1)), "attacker"));
        rig.Clock.Now = T0.AddHours(1); // the real report is made at its own instant
        Assert.True(rig.Service.RegisterSecurityState(
            new DeviceSecurityState("dev1", "scope1", true, true, true, T0.AddHours(1)), "monitor"));
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-encryption").Outcome);
        // The store itself, on its own clock, refuses the future too:
        var store = new SecurityStateStore(() => T0);
        Assert.False(store.Record(new DeviceSecurityState("d", "s", true, true, true, T0.AddDays(30))));
        Assert.True(store.Record(new DeviceSecurityState("d", "s", true, true, true, T0.AddMinutes(4)))); // within skew
    }

    [Fact]
    public void F3_FutureHandBuiltFacts_JudgedStale_NeverPass()
    {
        var deviceFacts = new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", true, T0.AddYears(1)),
        }, T0);
        var pack = CompileDirect(deviceFacts);
        var v = Verdict(pack, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.StaleFact, v.GapKind); // negative age is not freshness

        var scopeFacts = new ComplianceFactSet("scope1", Array.Empty<string>(), new[]
        {
            Fact(ComplianceFactKinds.AccessReview, null, "scope1", true, T0.AddYears(1)),
        }, T0);
        var pack2 = CompileDirect(scopeFacts);
        var v2 = Verdict(pack2, "hipaa-access-review");
        Assert.Equal(ControlOutcomes.Gap, v2.Outcome);
        Assert.Equal(GapKinds.StaleFact, v2.GapKind);
        Assert.Contains("FUTURE", v2.Reason);
    }

    // ---- F4: site assessment scope confusion ------------------------------

    [Fact]
    public void F4_SiteAssessment_TargetScopePolicyGoverns_NotTheCallers()
    {
        var rig = Rmm09Tests.NewRig();
        var off = rig.Vuln.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-compliance-off-site2", PolicyLevels.Org, "site2",
            new Dictionary<string, string> { ["rmm.compliance.enabled"] = "false" }, 1), "test");
        Assert.True(off.Allowed, off.Reason);
        // The caller sits in enabled scope1; the SITE has compliance disabled:
        var refused = rig.Service.CompileSiteAssessment(Rmm09Tests.Facts(), "hipaa", "site2", "admin");
        Assert.False(refused.Ok);
        Assert.Contains("disabled by policy", refused.Reason);
        // …while the caller's own scope still compiles:
        Assert.True(rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Ok);
    }

    [Fact]
    public void F4_SiteAssessment_VulnDataComesFromTheSite_NotTheCaller()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig); // scope1: clean device
        // site2: a device carrying the vulnerable Acrobat:
        rig.Vuln.Inventory.ApplyBaseline(SiteRecord("site2-dev", "site2", ("Adobe Acrobat", "23.0.5")), T0);
        rig.Service.RegisterSecurityState(new DeviceSecurityState("site2-dev", "site2", true, true, true, T0), "monitor");
        rig.Vuln.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Vuln.Service.RunCorrelation(StaticDeviceFacts.Of("site2-dev", "site2"));
        rig.Clock.Now = T0.AddDays(4); // past the critical SLA; feed still fresh
        // Compile site2's assessment HOLDING scope1 facts: before the
        // fix, scope1's clean report was stamped as site2's posture.
        var site2 = rig.Service.CompileSiteAssessment(Rmm09Tests.Facts(), "hipaa", "site2", "admin").Pack!;
        var v = Verdict(site2, "hipaa-risk-analysis");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
    }

    // ---- F5: control remapping ----------------------------------------------

    [Fact]
    public void F5_RemappedControl_AdmissionNamesIt_AndAuditsIt()
    {
        var rig = Rmm09Tests.NewRig();
        var hollowed = SeededPacks.Hipaa() with
        {
            Revision = 2,
            Controls = SeededPacks.Hipaa().Controls.Select(c => c.ControlId == "hipaa-encryption"
                ? c with { RequiredFactKind = ComplianceFactKinds.InventoryPresence, Title = "Encryption (trust us)" }
                : c).ToList(),
        };
        var admission = rig.Service.AdmitContentPack(hollowed, "poisoner");
        Assert.True(admission.Accepted); // a revision MAY re-point a control…
        Assert.Empty(admission.RemovedControlIds); // …nothing was removed…
        Assert.Contains("hipaa-encryption", admission.RemappedControlIds); // …but the remap is NAMED
        Assert.Contains(rig.Vuln.Audit.Entries, e =>
            e.Kind == "compliance_pack_controls_remapped" && e.Detail.Contains("hipaa-encryption"));
    }

    [Fact]
    public void F5_RemappedControl_DiffNamesRemap_NeverClosed()
    {
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", false, T0), // encryption OFF: a gap
            Fact(ComplianceFactKinds.InventoryPresence, "dev1", "scope1", true, T0),
        }, T0);
        var before = CompileDirect(facts);
        Assert.Equal(ControlOutcomes.Gap, Verdict(before, "hipaa-encryption").Outcome);
        var hollowed = SeededPacks.Hipaa() with
        {
            Revision = 2,
            Controls = SeededPacks.Hipaa().Controls.Select(c => c.ControlId == "hipaa-encryption"
                ? c with { RequiredFactKind = ComplianceFactKinds.InventoryPresence }
                : c).ToList(),
        };
        var after = CompileDirect(facts, content: hollowed, now: T0.AddDays(1));
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(after, "hipaa-encryption").Outcome); // passes under the remap
        var diff = CompliancePackDiffer.Compare(before, after);
        var movement = diff.Movements.Single(m => m.ControlId == "hipaa-encryption");
        Assert.Equal(MovementCategories.ControlRemapped, movement.Category); // named as a remap…
        Assert.DoesNotContain(diff.Closed, m => m.ControlId == "hipaa-encryption"); // …never as a closed gap
        Assert.Equal(0, diff.UnaccountedCount);
    }

    // ---- F6: artefact integrity ----------------------------------------------

    [Fact]
    public void F6_HashBindsTitleFactKindReasonAndProvenanceNotes()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig, encryption: false);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(pack.VerifyContentHash(pack.ContentHash));
        // Relabel a satisfied inventory verdict as the encryption requirement:
        var relabelled = pack with
        {
            Verdicts = pack.Verdicts.Select(v => v.ControlId == "hipaa-device-inventory"
                ? v with { ControlId = "hipaa-encryption", Title = "Encryption and decryption", RequiredFactKind = ComplianceFactKinds.EncryptionState }
                : v).ToList(),
        };
        Assert.False(relabelled.VerifyContentHash(pack.ContentHash));
        // Soften a gap's reason prose:
        var softened = pack with
        {
            Verdicts = pack.Verdicts.Select(v => v.ControlId == "hipaa-encryption"
                ? v with { Reason = "basically fine" } : v).ToList(),
        };
        Assert.False(softened.VerifyContentHash(pack.ContentHash));
        // Strip the provenance notes:
        var stripped = pack with { ProvenanceNotes = Array.Empty<string>() };
        Assert.False(stripped.VerifyContentHash(pack.ContentHash));
    }

    [Fact]
    public void F6_VerifyStoredPack_AnchorsInTheAuditChain()
    {
        var rig = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.True(rig.Service.VerifyStoredPack(pack.PackId, out var reason), reason);
        // Break the chain (rewrite the compile event's kind in the
        // exported entries, re-import): now NO pack can be
        // anchored, and the service says so.
        var json = rig.Vuln.Audit.ExportEntriesJson();
        Assert.Contains("compliance_pack_compiled", json);
        rig.Vuln.Audit.ImportEntriesJson(json.Replace("compliance_pack_compiled", "compliance_pack_compileX"));
        Assert.False(rig.Vuln.Audit.Verify().Ok);
        Assert.False(rig.Service.VerifyStoredPack(pack.PackId, out var brokenReason));
        Assert.Contains("does not verify", brokenReason);
    }

    // ---- F7: staleness windows on the face -------------------------------------

    [Fact]
    public void F7_StalenessWindows_RecordedOnThePack_AndInItsHash()
    {
        var rig = Rmm09Tests.NewRig();
        var doc = rig.Vuln.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-compliance-windows", PolicyLevels.Org, "scope1",
            new Dictionary<string, string> { ["rmm.compliance.fact_stale_days"] = "30" }, 1), "test");
        Assert.True(doc.Allowed, doc.Reason);
        Rmm09Tests.AddDevice(rig);
        var pack = rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(30, pack.StalenessDefaultDays);
        Assert.Equal(7, pack.StalenessInventoryDays);
        Assert.Contains("staleDefaultDays=30", pack.CanonicalContent()); // hash-bound
        Assert.Contains(pack.ProvenanceNotes, n => n.Contains("freshness windows applied: facts 30d"));
        var text = CompliancePackRenderer.RenderPlainText(pack);
        Assert.Contains("freshness windows: facts 30d, inventory 7d", text);
        // A pack judged under the default windows is a different artefact:
        var rig2 = Rmm09Tests.NewRig();
        Rmm09Tests.AddDevice(rig2);
        var pack2 = rig2.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(7, pack2.StalenessDefaultDays);
        Assert.NotEqual(pack.ContentHash, pack2.ContentHash);
    }

    // ---- F8: differ scope/framework discipline -----------------------------------

    [Fact]
    public void F8_Differ_CrossScopeOrFramework_RefusesByName()
    {
        var a = CompileDirect(new ComplianceFactSet("scope1", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0));
        var b = CompileDirect(new ComplianceFactSet("site2", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0), now: T0.AddDays(1));
        var ex = Assert.Throws<ArgumentException>(() => CompliancePackDiffer.Compare(a, b));
        Assert.Contains("scope", ex.Message);
        var g = CompileDirect(new ComplianceFactSet("scope1", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0),
            content: SeededPacks.Gdpr(), now: T0.AddDays(1));
        var ex2 = Assert.Throws<ArgumentException>(() => CompliancePackDiffer.Compare(a, g));
        Assert.Contains("framework", ex2.Message);
    }

    [Fact]
    public void F8_Differ_DuplicateControlIds_RefusesNamingTheControl()
    {
        var a = CompileDirect(new ComplianceFactSet("scope1", new[] { "dev1" }, Array.Empty<ComplianceFact>(), T0));
        var dup = a with { Verdicts = a.Verdicts.Concat(new[] { a.Verdicts[0] }).ToList() };
        var ex = Assert.Throws<ArgumentException>(() => CompliancePackDiffer.Compare(a, dup));
        Assert.Contains("more than once", ex.Message);
        Assert.Contains(a.Verdicts[0].ControlId, ex.Message);
    }

    // ---- F9: treatments -------------------------------------------------------------

    private static string TreatmentJson(params ComplianceTreatment[] treatments) =>
        HubPersistence.Wrap("acp-compliance-treatments-v1",
            System.Text.Json.JsonSerializer.Serialize(treatments.ToList()));

    [Fact]
    public void F9_ImportJson_Revalidates_ForgedPlansRestoreNothing()
    {
        var legit = new ComplianceTreatment(
            ComplianceTreatment.IdFor("hipaa", "hipaa-encryption", "scope1", "alice", T0.AddDays(30)),
            "hipaa", "hipaa-encryption", "scope1", "alice", "rollout", "admin", T0, T0.AddDays(30));
        var store = new TreatmentStore();
        Assert.Equal(1, store.ImportJson(TreatmentJson(legit), T0)); // a genuine plan restores

        // Target in year 9999 with a correctly recomputed id — Record would refuse it:
        var forever = new ComplianceTreatment(
            ComplianceTreatment.IdFor("hipaa", "hipaa-encryption", "scope1", "alice", new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero)),
            "hipaa", "hipaa-encryption", "scope1", "alice", "rollout", "admin", T0,
            new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(0, new TreatmentStore().ImportJson(TreatmentJson(forever), T0));
        // Ownerless, with a matching id:
        var ownerless = new ComplianceTreatment(
            ComplianceTreatment.IdFor("hipaa", "hipaa-encryption", "scope1", "", T0.AddDays(30)),
            "hipaa", "hipaa-encryption", "scope1", "", "rollout", "admin", T0, T0.AddDays(30));
        Assert.Equal(0, new TreatmentStore().ImportJson(TreatmentJson(ownerless), T0));
        // Owner swapped, id left stale (the id binds the owner):
        var ownerSwapped = legit with { Owner = "mallory" };
        Assert.Equal(0, new TreatmentStore().ImportJson(TreatmentJson(ownerSwapped), T0));
        // Text blanked — Record refuses a plan with no treatment stated:
        var blanked = legit with { Treatment = "" };
        Assert.Equal(0, new TreatmentStore().ImportJson(TreatmentJson(blanked), T0));
        // Expired while persisted:
        Assert.Equal(0, new TreatmentStore().ImportJson(TreatmentJson(legit), T0.AddDays(31)));
    }

    [Fact]
    public void F9_RecordTreatment_NonexistentOrSatisfiedControl_Refused()
    {
        var rig = Rmm09Tests.NewRig();
        var ghost = rig.Service.RecordTreatment("hipaa", "hipaa-no-such-control", "scope1",
            "alice", "plan", T0.AddDays(30), "admin");
        Assert.False(ghost.Ok);
        Assert.Contains("does not exist", ghost.Reason);
        // A satisfied control has no gap to treat:
        Rmm09Tests.AddDevice(rig, encryption: true);
        rig.Service.CompilePack(Rmm09Tests.Facts(), "hipaa", "admin");
        var preArmed = rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "pre-armed plan", T0.AddDays(30), "admin");
        Assert.False(preArmed.Ok);
        Assert.Contains("SATISFIED", preArmed.Reason);
        Assert.Null(rig.Service.Treatments.Get("hipaa", "hipaa-encryption", "scope1"));
    }

    // ---- F10: vulnerability detail parsing ---------------------------------------------

    [Fact]
    public void F10_TryReadVulnCounts_StrictParsing()
    {
        Assert.False(ComplianceRules.TryReadVulnCounts("overdue=0", out _, out _)); // kevOpen missing ≠ 0
        Assert.False(ComplianceRules.TryReadVulnCounts("kevOpen=5; kevOpen=0; overdue=0", out _, out _)); // duplicate: last must not win
        Assert.False(ComplianceRules.TryReadVulnCounts("overdue=-1; kevOpen=0", out _, out _)); // negative
        Assert.False(ComplianceRules.TryReadVulnCounts("overdue=0; kevOpen", out _, out _)); // malformed part
        Assert.True(ComplianceRules.TryReadVulnCounts("open=3; overdue=0; kevOpen=0; closed=9", out var od, out var kev));
        Assert.Equal(0, od); Assert.Equal(0, kev);
        Assert.True(ComplianceRules.TryReadVulnCounts("kevOpen=2; overdue=1", out var od2, out var kev2));
        Assert.Equal(1, od2); Assert.Equal(2, kev2);
    }

    [Fact]
    public void F10_MissingKevKey_CannotPassTheKevControl()
    {
        var facts = new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
        {
            Fact(ComplianceFactKinds.VulnerabilityState, null, "scope1", true, T0, "open=0; overdue=0; closed=3"),
        }, T0);
        var pack = CompileDirect(facts, content: SeededPacks.NistCsf());
        var v = Verdict(pack, "nist-prip-kev");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome); // unparseable detail is a failing gap, never a pass
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("cannot be evaluated", v.Reason);
    }

    // ---- F11: treatment boundaries ---------------------------------------------------------

    [Fact]
    public void F11_TreatmentExpiryBoundary_AtTargetStillLive_OneTickPastReopened()
    {
        var treatments = new TreatmentStore();
        var target = T0.AddDays(10);
        Assert.True(treatments.Record("hipaa", "hipaa-encryption", "scope1",
            "alice", "rollout", "admin", target, T0).Ok);
        CompliancePack At(DateTimeOffset now) => CompileDirect(
            new ComplianceFactSet("scope1", new[] { "dev1" }, new[]
            {
                Fact(ComplianceFactKinds.EncryptionState, "dev1", "scope1", false, now),
            }, now), treatments: treatments, now: now);
        var atTarget = At(target);
        Assert.Equal(ControlOutcomes.GapTreated, Verdict(atTarget, "hipaa-encryption").Outcome); // IsExpired is now > target
        var pastTarget = At(target.AddTicks(1));
        var v = Verdict(pastTarget, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Contains("EXPIRED", v.Reason);
    }

    [Fact]
    public void F11_TreatmentCapBoundary_Exactly365DaysAccepted_OneTickMoreRefused()
    {
        var store = new TreatmentStore();
        Assert.True(store.Record("hipaa", "hipaa-encryption", "scope1",
            "alice", "plan", "admin", T0.AddDays(365), T0).Ok);
        var over = store.Record("hipaa", "hipaa-audit-controls", "scope1",
            "alice", "plan", "admin", T0.AddDays(365).AddTicks(1), T0);
        Assert.False(over.Ok);
        Assert.Contains("365", over.Reason);
    }

    // ---- F12: indexed evaluation stays exact -------------------------------------------------

    [Fact]
    public void F12_ManyDevices_IndexedEvaluationNamesExactlyTheBadDevices()
    {
        var facts = new List<ComplianceFact>();
        var devices = new List<string>();
        for (var i = 0; i < 50; i++)
        {
            var id = $"dev{i:00}";
            devices.Add(id);
            if (i % 5 == 0) continue; // every 5th device: no fact (missing)
            facts.Add(Fact(ComplianceFactKinds.EncryptionState, id, "scope1", i % 5 != 1, T0)); // every (5k+1)th: failing
        }
        var pack = CompileDirect(new ComplianceFactSet("scope1", devices, facts, T0));
        var v = Verdict(pack, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Equal(20, v.FailingDevices.Count); // 10 missing + 10 failing, no more, no fewer
        Assert.Contains("dev01", v.FailingDevices);
        Assert.Contains("dev45", v.FailingDevices);
        Assert.DoesNotContain("dev02", v.FailingDevices);
    }
}

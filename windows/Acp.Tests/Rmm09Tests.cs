using Acp.Core.Services;
using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;

namespace Acp.Tests;

// RMM-09 — Compliance evidence packs: content packs, fact-mapped
// compilation, the three gap kinds, treatment plans, movement
// diffs, site assessments. The honesty rule is the suite's spine:
// nothing in here may ever assert a satisfied control that a fresh,
// passing, in-scope ACP-collected fact does not back.
public class Rmm09Tests
{
    internal static readonly DateTimeOffset T0 = Rmm05Tests.T0;

    internal sealed record Rig(
        Rmm05Tests.Rig Vuln,
        ComplianceService Service,
        Rmm05Tests.MutableClock Clock);

    internal static Rig NewRig()
    {
        var v = Rmm05Tests.NewRig();
        var svc = new ComplianceService(v.Audit, v.Policies, v.Inventory,
            v.Patches.Service, v.Service, v.Clock.UtcNow);
        return new Rig(v, svc, v.Clock);
    }

    internal static IDeviceFacts Facts(string deviceId = "dev1", string scopeId = "scope1") =>
        StaticDeviceFacts.Of(deviceId, scopeId);

    /// <summary>One fully-evidenced device: fresh inventory, fresh
    /// security state (encryption/AV/firewall on), plus the scope
    /// facts (audit entries + completed access review) added by
    /// <see cref="CompleteScope"/>.</summary>
    internal static void AddDevice(Rig rig, string deviceId = "dev1", bool encryption = true,
        bool av = true, bool firewall = true, DateTimeOffset? observed = null)
    {
        var at = observed ?? T0;
        rig.Vuln.Inventory.ApplyBaseline(
            Rmm05Tests.Record(deviceId, software: new[] { ("Google Chrome", "130.0") }), at);
        rig.Service.RegisterSecurityState(new DeviceSecurityState(
            deviceId, "scope1", av, firewall, encryption, at), "monitor");
    }

    internal static void CompleteScope(Rig rig)
    {
        rig.Vuln.Audit.Append("session", "tech", "routine session", T0);
        rig.Vuln.Audit.Append("system", "core", "self check ok", T0);
        var campaign = new AccessReviewCampaign(new[] { "alice", "bob" }, T0.AddDays(14));
        campaign.Attest("alice");
        campaign.Attest("bob");
        rig.Service.RegisterAccessReview("camp-2026-q4", campaign, "scope1", "admin");
    }

    internal static ControlVerdict Verdict(CompliancePack pack, string controlId) =>
        pack.Verdicts.Single(v => v.ControlId == controlId);

    // ---- content packs ---------------------------------------------

    [Fact]
    public void RMM09_SeededPacks_AllFourFrameworks_Admitted()
    {
        var rig = NewRig();
        Assert.Equal(4, rig.Service.ContentPacks.All.Count);
        foreach (var fw in new[] { "hipaa", "gdpr", "nist-csf", "cmmc" })
        {
            var pack = rig.Service.ContentPacks.Get(fw);
            Assert.NotNull(pack);
            Assert.Null(pack!.Validate());
            Assert.True(pack.Controls.Count >= 7);
            // every seeded control maps to a fact ACP collects:
            Assert.All(pack.Controls, c => Assert.Contains(c.RequiredFactKind, ComplianceFactKinds.All));
        }
    }

    [Fact]
    public void RMM09_ContentPack_CanonicalRoundTrip_SameHash()
    {
        var pack = SeededPacks.Hipaa();
        var parsed = ComplianceContentPack.FromCanonicalJson(pack.ToCanonicalJson());
        Assert.NotNull(parsed);
        Assert.Equal(pack.ContentHash, parsed!.ContentHash);
    }

    // ---- compilation: the honesty rule ------------------------------

    [Fact]
    public void RMM09_Compile_EmptyScope_NothingSatisfied_AllMissingFactGaps()
    {
        var rig = NewRig();
        var result = rig.Service.CompilePack(Facts(), "hipaa", "admin");
        Assert.True(result.Ok, result.Reason);
        var pack = result.Pack!;
        Assert.Equal(0, pack.SatisfiedCount);
        Assert.Equal(pack.Verdicts.Count, pack.GapCount);
        Assert.All(pack.Verdicts, v =>
        {
            Assert.Equal(GapKinds.MissingFact, v.GapKind);
            Assert.True(v.IsGap);
        });
        Assert.Contains("GAPS PRESENT", pack.Headline);
        Assert.Contains("does NOT attest", pack.Headline);
    }

    [Fact]
    public void RMM09_Compile_FullyEvidenced_SatisfiesBackedControls_VulnStaysGapWithoutFeed()
    {
        var rig = NewRig();
        AddDevice(rig);
        CompleteScope(rig);
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-encryption").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-malware-protection").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-security-updates").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-device-inventory").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-audit-controls").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "hipaa-access-review").Outcome);
        // No vulnerability feed was imported: the risk-analysis
        // control has NO backing fact and must say so.
        var vuln = Verdict(pack, "hipaa-risk-analysis");
        Assert.Equal(ControlOutcomes.Gap, vuln.Outcome);
        Assert.Equal(GapKinds.MissingFact, vuln.GapKind);
        Assert.Contains("GAPS PRESENT", pack.Headline);
        Assert.Contains(rig.Vuln.Audit.Entries, e => e.Kind == "compliance_pack_compiled");
        Assert.True(rig.Vuln.Audit.Verify().Ok);
    }

    [Fact]
    public void RMM09_Compile_MissingPatch_IsFailingFactGap()
    {
        var rig = NewRig();
        Assert.True(rig.Vuln.Patches.Service.Catalogue.AddOrReplace(Rmm02Tests.ThirdParty()).Accepted);
        rig.Vuln.Inventory.ApplyBaseline(
            Rmm05Tests.Record("dev1", software: new[] { ("Contoso App", "1.5") }), T0);
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-security-updates");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("dev1", v.FailingDevices);
    }

    [Fact]
    public void RMM09_Compile_StaleFacts_AreStaleFactGaps_NotPasses()
    {
        var rig = NewRig();
        AddDevice(rig);
        CompleteScope(rig);
        rig.Clock.Now = T0.AddDays(30); // every observation is now a month old
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        foreach (var id in new[] { "hipaa-encryption", "hipaa-device-inventory", "hipaa-security-updates", "hipaa-audit-controls" })
        {
            var v = Verdict(pack, id);
            Assert.Equal(ControlOutcomes.Gap, v.Outcome);
            Assert.Equal(GapKinds.StaleFact, v.GapKind);
        }
        Assert.Equal(0, pack.SatisfiedCount - pack.Verdicts.Count(v =>
            v.Outcome == ControlOutcomes.Satisfied && v.ControlId == "hipaa-access-review")); // only the state-read review may stand
    }

    [Fact]
    public void RMM09_GapKinds_AreNamedDifferently_AndReasonNamesAll()
    {
        var rig = NewRig();
        // dev1: no security state at all (missing). dev2: encryption OFF (failing).
        rig.Vuln.Inventory.ApplyBaseline(Rmm05Tests.Record("dev1"), T0);
        AddDevice(rig, "dev2", encryption: false);
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-encryption");
        Assert.Equal(GapKinds.FailingFact, v.GapKind); // a known-bad state outranks an unknown
        Assert.Contains("dev2", v.Reason);
        Assert.Contains("missing for: dev1", v.Reason);
        Assert.Contains("dev1", v.FailingDevices);
        Assert.Contains("dev2", v.FailingDevices);
    }

    // ---- vulnerability facts (RMM-05 seam) ----------------------------

    [Fact]
    public void RMM09_VulnFacts_OverdueExposure_FailsVulnControls()
    {
        var rig = NewRig();
        AddDevice(rig);
        rig.Vuln.Inventory.ApplyBaseline(
            Rmm05Tests.Record("dev9", software: new[] { ("Adobe Acrobat", "23.0.5") }), T0);
        rig.Service.RegisterSecurityState(new DeviceSecurityState("dev9", "scope1", true, true, true, T0), "monitor");
        rig.Vuln.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Vuln.Service.RunCorrelation(Facts());
        rig.Clock.Now = T0.AddDays(4); // past the 72h critical SLA; feed (5d old) still fresh at 7d
        var pack = rig.Service.CompilePack(Facts(), "nist-csf", "admin").Pack!;
        var overdue = Verdict(pack, "nist-prip-improvement");
        Assert.Equal(ControlOutcomes.Gap, overdue.Outcome);
        Assert.Equal(GapKinds.FailingFact, overdue.GapKind);
        var kev = Verdict(pack, "nist-prip-kev");
        Assert.Equal(ControlOutcomes.Gap, kev.Outcome);
        Assert.Equal(GapKinds.FailingFact, kev.GapKind);
    }

    [Fact]
    public void RMM09_VulnFacts_StaleFeed_MakesStaleGaps_NeverPasses()
    {
        var rig = NewRig();
        AddDevice(rig);
        rig.Vuln.Service.ImportFeed(Rmm05Tests.Feed(published: T0.AddDays(-30)), "admin");
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-risk-analysis");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.StaleFact, v.GapKind);
        Assert.Contains("STALE", v.Reason);
    }

    [Fact]
    public void RMM09_VulnFacts_CleanFeedAndFleet_SatisfiesVulnControls()
    {
        var rig = NewRig();
        AddDevice(rig);
        rig.Vuln.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Vuln.Service.RunCorrelation(Facts());
        var pack = rig.Service.CompilePack(Facts(), "nist-csf", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "nist-prip-improvement").Outcome);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack, "nist-prip-kev").Outcome);
    }

    // ---- access review + audit facts -----------------------------------

    [Fact]
    public void RMM09_AccessReview_PendingIsFailing_CompleteSatisfies()
    {
        var rig = NewRig();
        AddDevice(rig);
        var campaign = new AccessReviewCampaign(new[] { "alice", "bob" }, T0.AddDays(14));
        campaign.Attest("alice"); // bob still pending, deadline ahead
        rig.Service.RegisterAccessReview("camp-x", campaign, "scope1", "admin");
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-access-review");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Equal(GapKinds.FailingFact, v.GapKind);
        Assert.Contains("pending=1", v.Reason);

        campaign.Attest("bob");
        var pack2 = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(pack2, "hipaa-access-review").Outcome);
    }

    // ---- treatments -------------------------------------------------------

    [Fact]
    public void RMM09_Treatment_MarksGapTreated_NeverSatisfied()
    {
        var rig = NewRig();
        AddDevice(rig, encryption: false);
        var before = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Gap, Verdict(before, "hipaa-encryption").Outcome);

        var (ok, reason, _) = rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "owner-alice", "Enable BitLocker via RMM-18 rollout, ticket 441", T0.AddDays(30), "admin");
        Assert.True(ok, reason);
        var after = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(after, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.GapTreated, v.Outcome);
        Assert.True(v.IsGap); // treated is still a gap — the pack cannot attest
        Assert.NotNull(v.TreatmentId);
        Assert.Contains("GAPS PRESENT", after.Headline);
        Assert.Equal(1, after.TreatedGapCount);
    }

    [Fact]
    public void RMM09_Treatment_ValidationRefusals()
    {
        var rig = NewRig();
        Assert.False(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "", "plan", T0.AddDays(30), "admin").Ok); // ownerless
        Assert.False(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "", T0.AddDays(30), "admin").Ok); // no treatment stated
        Assert.False(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "plan", T0.AddDays(-1), "admin").Ok); // already expired
        Assert.False(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "plan", T0.AddDays(400), "admin").Ok); // never comes due
        Assert.Contains(rig.Vuln.Audit.Entries, e => e.Kind == "compliance_treatment_refused");
    }

    [Fact]
    public void RMM09_Treatment_Expiry_ReopensGap()
    {
        var rig = NewRig();
        AddDevice(rig, encryption: false);
        Assert.True(rig.Service.RecordTreatment("hipaa", "hipaa-encryption", "scope1",
            "alice", "rollout planned", T0.AddDays(10), "admin").Ok);
        // Keep the underlying facts fresh so ONLY the treatment moves:
        rig.Clock.Now = T0.AddDays(11);
        AddDevice(rig, encryption: false, observed: T0.AddDays(11));
        var pack = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var v = Verdict(pack, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Contains("EXPIRED", v.Reason);
        Assert.Contains("reopened", v.Reason);
    }

    // ---- movement ------------------------------------------------------------

    [Fact]
    public void RMM09_Movement_ShowsClosedThenOpened_AndAccountsForEveryControl()
    {
        var rig = NewRig();
        AddDevice(rig, encryption: false);
        CompleteScope(rig);
        var p1 = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        Assert.Equal(ControlOutcomes.Gap, Verdict(p1, "hipaa-encryption").Outcome);

        // D38-F3: the clock advances BEFORE the newer observation
        // is reported — a report dated ahead of the hub's clock is
        // future-dated and now refuses, so the fixture reports in
        // chronological order like a real monitor does.
        rig.Clock.Now = T0.AddHours(1);
        AddDevice(rig, encryption: true, observed: T0.AddHours(1));
        var p2 = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var diff = rig.Service.DiffPacks(p1.PackId, p2.PackId, "admin");
        Assert.Contains(diff.Closed, m => m.ControlId == "hipaa-encryption");
        Assert.Equal(0, diff.UnaccountedCount);
        Assert.Equal(p1.Verdicts.Count, diff.Movements.Count); // same checklist both times

        rig.Clock.Now = T0.AddHours(2);
        AddDevice(rig, encryption: false, observed: T0.AddHours(2));
        var p3 = rig.Service.CompilePack(Facts(), "hipaa", "admin").Pack!;
        var diff2 = rig.Service.DiffPacks(p2.PackId, p3.PackId, "admin");
        Assert.Contains(diff2.Opened, m => m.ControlId == "hipaa-encryption");
        Assert.Equal(0, diff2.UnaccountedCount);
        var text = CompliancePackRenderer.RenderDiffPlainText(diff2);
        Assert.Contains("opened", text);
    }

    // ---- site assessment --------------------------------------------------------

    [Fact]
    public void RMM09_SiteAssessment_RestrictsToTheSiteScope()
    {
        var rig = NewRig();
        AddDevice(rig, "dev1", encryption: true);
        // A second site with a failing device:
        rig.Vuln.Inventory.ApplyBaseline(new DeviceInventoryRecord(
            "site2-dev", "site2", "host-site2",
            new HardwareSnapshot("Contoso", "Model", null, "CPU", 4, 16L << 30,
                "Windows 11 Pro", "22631.1000", "22631.1000", null,
                Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
            Array.Empty<SoftwareItem>(), new Dictionary<string, string>(), new HashSet<string>(),
            T0, T0, T0, 1), T0);
        rig.Service.RegisterSecurityState(new DeviceSecurityState("site2-dev", "site2", true, true, false, T0), "monitor");

        var site1 = rig.Service.CompileSiteAssessment(Facts(), "hipaa", "scope1", "admin").Pack!;
        Assert.Equal(PackKinds.SiteAssessment, site1.Kind);
        Assert.Equal("scope1", site1.ScopeId);
        Assert.Equal(ControlOutcomes.Satisfied, Verdict(site1, "hipaa-encryption").Outcome);

        var site2 = rig.Service.CompileSiteAssessment(Facts(), "hipaa", "site2", "admin").Pack!;
        var v = Verdict(site2, "hipaa-encryption");
        Assert.Equal(ControlOutcomes.Gap, v.Outcome);
        Assert.Contains("site2-dev", v.FailingDevices);
        Assert.DoesNotContain("dev1", v.FailingDevices);
    }

    // ---- policy + rendering -------------------------------------------------------

    [Fact]
    public void RMM09_PolicyToggle_Disabled_RefusesCompile()
    {
        var rig = NewRig();
        var verdict = rig.Vuln.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-compliance-off", PolicyLevels.Org, "scope1",
            new Dictionary<string, string> { ["rmm.compliance.enabled"] = "false" }, 1), "test");
        Assert.True(verdict.Allowed, verdict.Reason);
        var result = rig.Service.CompilePack(Facts(), "hipaa", "admin");
        Assert.False(result.Ok);
        Assert.Contains("disabled by policy", result.Reason);
        Assert.Contains(rig.Vuln.Audit.Entries, e => e.Kind == "compliance_pack_refused");
    }

    [Fact]
    public void RMM09_Rendering_CarriesGapsAndStalenessOnItsFace()
    {
        var rig = NewRig();
        AddDevice(rig, encryption: false);
        var pack = rig.Service.CompilePack(Facts(), "gdpr", "admin").Pack!;
        var text = CompliancePackRenderer.RenderPlainText(pack);
        Assert.Contains("GAPS PRESENT", text);
        Assert.Contains("GAP ANALYSIS", text);
        Assert.Contains("gdpr-encryption", text);
        Assert.Contains("failing_fact", text);
        Assert.Contains(pack.ContentHash, text);
        Assert.True(pack.VerifyContentHash(pack.ContentHash));
    }

    [Fact]
    public void RMM09_UnknownFramework_RefusesByName()
    {
        var rig = NewRig();
        var result = rig.Service.CompilePack(Facts(), "pci-dss", "admin");
        Assert.False(result.Ok);
        Assert.Contains("pci-dss", result.Reason);
    }
}

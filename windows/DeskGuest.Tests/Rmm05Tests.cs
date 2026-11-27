using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Vulnerability;

namespace DeskGuest.Tests;

// RMM-05 — Vulnerability management loop: feed import + provenance,
// correlation over RMM-04 inventory + RMM-02 patch state, exposure
// work items, patch remediation requests (RMM-02 hand-off),
// compensating controls, evidence-bound closure, SLA tracking.
// No live feed, scanner or network is touched: fixtures only.
public class Rmm05Tests
{
    internal static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    internal sealed class MutableClock
    {
        public DateTimeOffset Now = T0;
        public DateTimeOffset UtcNow() => Now;
    }

    internal sealed record Rig(
        Rmm02Tests.Rig Patches,
        MutableClock Clock,
        InventoryStore Inventory,
        VulnerabilityService Service,
        ChainedAuditLog Audit,
        ManagementPolicyService Policies);

    internal static Rig NewRig()
    {
        var patches = Rmm02Tests.NewRig();
        var clock = new MutableClock();
        // Rebuild the policy + patch services over the MUTABLE clock
        // so SLA/expiry tests can move time. (Rmm02Tests.NewRig pins
        // its own T0; the vulnerability rig needs a travelling clock
        // for the PatchService approvals it verifies against.)
        var audit = new ChainedAuditLog();
        var gate = new SignedCommandGate(new SignedCommandVerifier(patches.Ring), audit);
        var policies = new ManagementPolicyService(audit, gate, now: clock.UtcNow);
        var endpoint = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var patchSvc = new PatchService(TestUtil.TempDir(), audit, policies, gate, endpoint, patches.Ring, now: clock.UtcNow);
        var inventory = new InventoryStore();
        var svc = new VulnerabilityService(audit, policies, patchSvc, inventory, clock.UtcNow);
        var rig2 = patches with { Service = patchSvc };
        return new Rig(rig2, clock, inventory, svc, audit, policies);
    }

    internal static IDeviceFacts Facts(string deviceId = "dev1", string scopeId = "scope1") =>
        StaticDeviceFacts.Of(deviceId, scopeId);

    internal static DeviceInventoryRecord Record(string deviceId, string osName = "Windows 11 Pro",
        string osBuild = "22631.1000", params (string Name, string Version)[] software) =>
        Rmm02Tests.Record(deviceId, osName, osBuild, software);

    internal static VulnerabilityFeedEntry AcrobatCve(double cvss = 9.8, string severity = "critical",
        bool kev = true, string? fixedIn = "24.0") => new(
            CveId: "CVE-2024-12345", ProductName: "Adobe Acrobat",
            FixedInVersion: fixedIn, TargetOs: null, FixedInOsBuild: null,
            CvssScore: cvss, Severity: severity, IsKev: kev,
            KevDateAddedUtc: kev ? T0.AddDays(-30) : null,
            PublishedUtc: T0.AddDays(-2), Description: "Acrobat RCE");

    internal static VulnerabilityFeed Feed(long seq = 1, DateTimeOffset? published = null,
        params VulnerabilityFeedEntry[] entries) => new(
            FeedId: "nvd-mirror", Source: "admin-imported NVD mirror (local file)",
            Sequence: seq, PublishedUtc: published ?? T0.AddDays(-1),
            Entries: entries.Length > 0 ? entries : new[] { AcrobatCve() });

    internal static Rig RigWithFleet()
    {
        var rig = NewRig();
        rig.Inventory.ApplyBaseline(Record("dev1", software: new[] { ("Adobe Acrobat", "23.0.5") }), T0);
        rig.Inventory.ApplyBaseline(Record("dev2", software: new[] { ("Adobe Acrobat", "25.2.0") }), T0);
        rig.Inventory.ApplyBaseline(Record("dev3", software: new[] { ("Google Chrome", "130.0") }), T0);
        return rig;
    }

    // ---- feed import ------------------------------------------------

    [Fact]
    public void RMM05_FeedImport_ValidatesShape_AndRecordsProvenance()
    {
        var rig = NewRig();
        var ok = rig.Service.ImportFeed(Feed(), "admin-1");
        Assert.True(ok.Accepted, ok.Reason);
        Assert.NotNull(ok.ContentHash);
        var prov = rig.Service.ProvenanceFor(Facts());
        Assert.Equal("nvd-mirror", prov.FeedId);
        Assert.False(prov.IsStale);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_feed_imported");
        Assert.True(rig.Audit.Verify().Ok);
        // malformed CVE / bad CVSS / empty feed all refuse atomically:
        Assert.False(rig.Service.ImportFeed(Feed(2, entries: new[] { AcrobatCve() with { CveId = "CVE-24-1" } }), "admin").Accepted);
        Assert.False(rig.Service.ImportFeed(Feed(2, entries: new[] { AcrobatCve() with { CvssScore = 11.0 } }), "admin").Accepted);
        Assert.False(rig.Service.ImportFeed(new VulnerabilityFeed("f", "s", 2, T0, Array.Empty<VulnerabilityFeedEntry>()), "admin").Accepted);
        Assert.Equal(1, rig.Service.Feeds.Current!.Sequence); // refusals changed nothing
    }

    [Fact]
    public void RMM05_FeedProvenance_StaleIsNamedStale()
    {
        var rig = NewRig();
        rig.Service.ImportFeed(Feed(published: T0.AddDays(-30)), "admin");
        var prov = rig.Service.ProvenanceFor(Facts());
        Assert.True(prov.IsStale);
        Assert.Contains("STALE FEED", prov.StalenessNote);
        // correlation outputs carry the same verdict on their face:
        var run = rig.Service.RunCorrelation(Facts());
        Assert.True(run.Ok);
        Assert.True(run.Provenance!.IsStale);
        Assert.Contains("STALE", run.Result!.Summary);
    }

    // ---- correlation --------------------------------------------------

    [Fact]
    public void RMM05_Correlation_FeedAgainstInventory_OnlyVulnerableDevicesExposed()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        var run = rig.Service.RunCorrelation(Facts());
        Assert.True(run.Ok, run.Reason);
        Assert.Equal(1, run.Created);
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal("dev1", item.DeviceId);           // 23.0.5 < fixed 24.0
        Assert.Equal("CVE-2024-12345", item.CveId);
        Assert.True(item.IsKev);
        Assert.Equal(9.8, item.CvssScore);
        // dev2 runs the fixed version; dev3 never had the product:
        Assert.DoesNotContain(rig.Service.Exposures.Items, i => i.DeviceId is "dev2" or "dev3");
    }

    [Fact]
    public void RMM05_Correlation_MultiInstall_AnyInstallCounts()
    {
        var rig = NewRig();
        // Side-by-side installs: a fixed 64-bit copy AND a vulnerable
        // 32-bit copy. The RMM-04 multi-install lesson: ANY counts.
        rig.Inventory.ApplyBaseline(Record("dev1", software: new[]
        {
            ("Adobe Acrobat", "25.2.0"), ("Adobe Acrobat", "23.0.5"),
        }), T0);
        rig.Service.ImportFeed(Feed(), "admin");
        var run = rig.Service.RunCorrelation(Facts());
        Assert.Equal(1, run.Created);
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Contains("23.0.5", item.VulnerableVersions);
        Assert.DoesNotContain("25.2.0", item.VulnerableVersions);
    }

    [Fact]
    public void RMM05_Correlation_OsBuildEntry_MatchesByBuild()
    {
        var rig = NewRig();
        rig.Inventory.ApplyBaseline(Record("dev1", osBuild: "22631.1000"), T0);
        rig.Inventory.ApplyBaseline(Record("dev2", osBuild: "22631.4000"), T0);
        var osCve = new VulnerabilityFeedEntry("CVE-2024-99999", "Windows OS", null, "windows", "22631.3000",
            9.1, "critical", false, null, T0.AddDays(-2), "OS flaw");
        rig.Service.ImportFeed(Feed(entries: new[] { osCve }), "admin");
        var run = rig.Service.RunCorrelation(Facts());
        Assert.Equal(1, run.Created);
        Assert.Equal("dev1", Assert.Single(rig.Service.Exposures.OpenItems()).DeviceId);
    }

    [Fact]
    public void RMM05_Correlation_Idempotent_FirstSeenAndSlaNeverMove()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var first = Assert.Single(rig.Service.Exposures.OpenItems());
        rig.Clock.Now = T0.AddDays(5);
        var run2 = rig.Service.RunCorrelation(Facts());
        Assert.Equal(0, run2.Created);
        Assert.Equal(1, run2.Refreshed);
        var again = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal(first.Id, again.Id);
        Assert.Equal(T0, again.FirstSeenUtc);       // the SLA clock did not reset
        Assert.Equal(first.SlaDueUtc, again.SlaDueUtc);
        Assert.Equal(T0.AddDays(5), again.LastSeenUtc);
    }

    [Fact]
    public void RMM05_Prioritisation_KevFirstThenCvss()
    {
        var rig = NewRig();
        rig.Inventory.ApplyBaseline(Record("dev1", software: new[]
        {
            ("Adobe Acrobat", "23.0.5"), ("Google Chrome", "120.0"), ("Widget", "1.0"),
        }), T0);
        var chrome = new VulnerabilityFeedEntry("CVE-2024-22222", "Google Chrome", "131.0", null, null,
            8.0, "high", false, null, T0.AddDays(-2), null);
        var widget = new VulnerabilityFeedEntry("CVE-2024-33333", "Widget", "2.0", null, null,
            7.0, "high", true, T0.AddDays(-9), T0.AddDays(-2), null);
        rig.Service.ImportFeed(Feed(entries: new[] { chrome, widget, AcrobatCve() }), "admin");
        rig.Service.RunCorrelation(Facts());
        var open = rig.Service.Exposures.OpenItems();
        Assert.Equal(3, open.Count);
        Assert.Equal("CVE-2024-12345", open[0].CveId); // KEV + CVSS 9.8
        Assert.Equal("CVE-2024-33333", open[1].CveId); // KEV beats higher non-KEV CVSS
        Assert.Equal("CVE-2024-22222", open[2].CveId);
    }

    // ---- SLA ------------------------------------------------------------

    [Fact]
    public void RMM05_Sla_BySeverity_WithKevCap_AndOverdueComputation()
    {
        var sla = VulnerabilitySlaPolicy.Default;
        Assert.Equal(T0.AddHours(72), sla.DueUtc(T0, "critical", false));
        Assert.Equal(T0.AddHours(336), sla.DueUtc(T0, "high", false));
        // KEV caps a LOW severity at the KEV cap (14d < 90d):
        Assert.Equal(T0.AddHours(336), sla.DueUtc(T0, "low", true));
        // KEV does not EXTEND a critical (72h < cap):
        Assert.Equal(T0.AddHours(72), sla.DueUtc(T0, "critical", true));

        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin"); // critical + KEV → due T0+72h
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal(T0.AddHours(72), item.SlaDueUtc);
        Assert.Empty(rig.Service.Exposures.Overdue(T0.AddHours(71)));
        Assert.Single(rig.Service.Exposures.Overdue(T0.AddHours(73)));
        rig.Clock.Now = T0.AddHours(73); // the report is computed at the service clock
        var report = rig.Service.BuildReport(Facts());
        Assert.Single(report.Overdue);
        Assert.False(report.Provenance.IsStale);
    }

    [Fact]
    public void RMM05_Sla_PolicyContentOverridesDefaults()
    {
        var rig = RigWithFleet();
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "sla-doc", PolicyLevels.Org, "scope1",
            new Dictionary<string, string> { [VulnerabilityPolicyKeys.SlaHoursCritical] = "24" }, 1), "test");
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal(T0.AddHours(24), item.SlaDueUtc); // policy said 24h, not the 72h default
    }

    // ---- scanner import ---------------------------------------------------

    [Fact]
    public void RMM05_ScannerImport_ThreeVendorShapes_ConfirmAndRaise()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        var tenable = """{"findings":[{"id":"t-1","host_id":"dev1","host_name":"host-dev1","software":"Adobe Acrobat","version":"23.0.5","cve":"CVE-2024-12345","cvss":9.8}]}""";
        var parsed = rig.Service.ImportScannerResults("tenable", tenable, "admin");
        Assert.True(parsed.Ok, parsed.Reason);
        var run = rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal(ExposureSources.FeedAndScanner, item.Source); // scanner CONFIRMED the feed exposure

        var rapid7 = """{"assets":[{"id":"dev3","hostName":"host-dev3","vulnerabilities":[{"id":"r-1","cve":"CVE-2024-77777","product":"Google Chrome","version":"130.0","cvss":7.5}]}]}""";
        Assert.True(rig.Service.ImportScannerResults("rapid7", rapid7, "admin").Ok);
        var run2 = rig.Service.RunCorrelation(Facts());
        Assert.Contains(rig.Service.Exposures.OpenItems(),
            i => i.DeviceId == "dev3" && i.Source == ExposureSources.Scanner);

        var qualys = """{"detections":[{"qid":"q-1","hostId":"dev1","hostname":"host-dev1","software":"Adobe Acrobat","version":"23.0.5","cve":"CVE-2024-12345","cvss":9.8}]}""";
        Assert.True(rig.Service.ImportScannerResults("qualys", qualys, "admin").Ok);
        // unknown vendor + malformed shapes refuse atomically:
        Assert.False(rig.Service.ImportScannerResults("nessus-legacy", tenable, "admin").Ok);
        Assert.False(rig.Service.ImportScannerResults("tenable", """{"findings":[{"id":"t-2","cve":"bogus"}]}""", "admin").Ok);
    }

    // ---- remediation request (patch path) --------------------------------

    [Fact]
    public void RMM05_RemediationRequest_BindsCatalogueContent_DeploysNothing()
    {
        var rig = RigWithFleet();
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "test");
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal(entry.Id, item.PatchEntryId);
        var (ok, reason, request) = rig.Service.RequestPatchRemediation(Facts(), item.Id, "tech-1");
        Assert.True(ok, reason);
        Assert.Equal(entry.ContentHash, request!.EntryContentHash);
        Assert.Equal(ExposureStates.RemediationRequested, rig.Service.Exposures.Get(item.Id)!.State);
        // REQUEST ONLY: no job exists, nothing deployed:
        Assert.Empty(rig.Patches.Service.Journal.ListJobs());
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_remediation_requested");
    }

    [Fact]
    public void RMM05_RemediationRequest_NoCatalogueFix_RefusesTowardControlPath()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        var (ok, reason, _) = rig.Service.RequestPatchRemediation(Facts(), item.Id, "tech");
        Assert.False(ok);
        Assert.Contains("compensating control", reason);
    }

    // ---- compensating controls --------------------------------------------

    [Fact]
    public void RMM05_CompensatingControl_RecordValidateCloseWithEvidence()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        var (ok, reason, control) = rig.Service.RecordCompensatingControl(item.Id,
            "Acrobat isolated to a no-internet VLAN; PDFs opened in a sandbox viewer only.",
            "owner-contact", T0.AddDays(30), "CONTROL DOC: vlan isolation + sandbox policy v1", "tech-1");
        Assert.True(ok, reason);
        var compensated = rig.Service.Exposures.Get(item.Id)!;
        Assert.Equal(ExposureStates.Compensated, compensated.State);
        Assert.Equal("owner-contact", compensated.Owner);
        var closed = rig.Service.CloseWithControlEvidence(item.Id, "tech-1");
        Assert.True(closed.Ok, closed.Reason);
        var done = rig.Service.Exposures.Get(item.Id)!;
        Assert.True(done.IsClosed);
        Assert.Equal(ClosureKinds.CompensatingControl, done.Closure!.Kind);
        Assert.Equal(control!.DocumentHash,
            VulnerabilityHash.Sha256Hex("CONTROL DOC: vlan isolation + sandbox policy v1"));
    }

    [Fact]
    public void RMM05_CompensatingControl_ExpiredReview_ReopensExposure()
    {
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.True(rig.Service.RecordCompensatingControl(item.Id,
            "Isolated VLAN control for the unpatchable BAS host.",
            "owner-a", T0.AddDays(7), "doc v1", "tech").Ok);
        Assert.Equal(ExposureStates.Compensated, rig.Service.Exposures.Get(item.Id)!.State);
        rig.Clock.Now = T0.AddDays(8); // review date passed
        var reopened = rig.Service.Exposures.EvaluateExpirations(rig.Clock.Now);
        Assert.Single(reopened);
        var back = rig.Service.Exposures.Get(item.Id)!;
        Assert.Equal(ExposureStates.Open, back.State);
        Assert.Null(back.Owner);
        Assert.Equal(T0, back.FirstSeenUtc); // reopening never resets the SLA clock
    }

    // ---- patch closure (prove) ----------------------------------------------

    [Fact]
    public void RMM05_PatchClosure_RequiresApprovalAndInventoryConvergence()
    {
        var rig = RigWithFleet();
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "test");
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.True(rig.Service.RequestPatchRemediation(Facts(), item.Id, "tech").Ok);
        // Not approved yet, still vulnerable: closure refuses twice over.
        Assert.False(rig.Service.CloseWithPatchEvidence(item.Id, "tech").Ok);
        // Approve in RMM-02 — STILL refuses: the device still runs 23.0.5.
        Assert.True(rig.Patches.Service.Decide(Facts(), entry.Id, "dev1", approve: true, decidedBy: "admin-1").Ok);
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("still", refused.Reason);
        // The fleet record converges (the patch actually landed):
        var stored = rig.Inventory.Get("dev1")!;
        var next = Record("dev1", software: new[] { ("Adobe Acrobat", "24.0.1") });
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(2));
        Assert.True(rig.Inventory.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(2)).Accepted);
        var closed = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.True(closed.Ok, closed.Reason);
        var done = rig.Service.Exposures.Get(item.Id)!;
        Assert.True(done.IsClosed);
        Assert.Equal(ClosureKinds.Patch, done.Closure!.Kind);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- policy toggle -------------------------------------------------------

    [Fact]
    public void RMM05_PolicyToggleOff_CorrelationAndRequestsRefuse()
    {
        var rig = RigWithFleet();
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "vuln-off", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { [VulnerabilityPolicyKeys.Enabled] = "false" }, 1), "test");
        rig.Service.ImportFeed(Feed(), "admin");
        var run = rig.Service.RunCorrelation(Facts("dev1"));
        Assert.False(run.Ok);
        Assert.Contains("rmm.vulnerability.enabled", run.Reason);
        Assert.Empty(rig.Service.Exposures.Items);
    }

    [Fact]
    public void RMM05_NoFeed_CorrelationNamesAbsenceOfData()
    {
        var rig = RigWithFleet();
        var run = rig.Service.RunCorrelation(Facts());
        Assert.True(run.Ok);
        Assert.Equal(0, run.Created);
        Assert.Contains("absence of data", run.Result!.Summary);
        Assert.True(run.Provenance!.IsStale);
    }

    [Fact]
    public void RMM05_ClosedEpisode_ReappearanceMintsNewEpisode_OldClosureStands()
    {
        // AMENDED by the D38 fix lane (F1): this test originally
        // enshrined the condemned behaviour — a compensating-control
        // closure minting episode #2 with a FRESH SLA clock on the
        // next correlation, making the control a permanent
        // exception that also reset the SLA. Corrected semantics:
        // while the control is live, re-correlation mints NOTHING
        // (the risk acceptance stands); when the review date
        // passes, the SAME episode reopens with its ORIGINAL
        // FirstSeen/SlaDue. (Patch closures still mint episode #2
        // on reappearance — see Rmm05D38FixTests.)
        var rig = RigWithFleet();
        rig.Service.ImportFeed(Feed(), "admin");
        rig.Service.RunCorrelation(Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        rig.Service.RecordCompensatingControl(item.Id, "Temporary isolation control.",
            "owner-a", T0.AddDays(30), "doc", "tech");
        Assert.True(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
        // The device is STILL vulnerable (the control accepted the
        // risk, it did not fix the CVE) — but the acceptance is
        // live, so the next correlation mints no new episode:
        rig.Clock.Now = T0.AddDays(1);
        var run = rig.Service.RunCorrelation(Facts());
        Assert.Equal(0, run.Created);
        Assert.Single(rig.Service.Exposures.Items);
        Assert.True(rig.Service.Exposures.Get(item.Id)!.IsClosed);
        // The review date passes: the SAME episode reopens, clock
        // untouched — the acceptance was bounded, never permanent.
        rig.Clock.Now = T0.AddDays(31);
        var run2 = rig.Service.RunCorrelation(Facts());
        Assert.Single(run2.Reopened);
        var back = rig.Service.Exposures.Get(item.Id)!;
        Assert.Equal(ExposureStates.Open, back.State);
        Assert.Equal(T0, back.FirstSeenUtc);
        Assert.Equal(item.SlaDueUtc, back.SlaDueUtc);
        Assert.Single(rig.Service.Exposures.Items); // still no episode #2
    }
}

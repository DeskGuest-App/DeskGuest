using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.SoftwareMetering;

namespace DeskGuest.Tests;

// RMM-26 — Software metering + licence-compliance reporting (local).
// Entitlements are admin-asserted claims (labelled, snapshotted);
// install position comes from RMM-04 inventory only; usage is
// reported only where a named-source usage fact exists.
public class Rmm26Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Admin = "it-admin";

    private static HardwareSnapshot Hw() => new(
        "Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16, 16_000_000_000,
        "Windows 11 Pro", "26100.1", "10.0.26100", "1.0",
        Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0);

    private static DeviceInventoryRecord Record(string deviceId, IReadOnlyList<SoftwareItem> software,
        DateTimeOffset? lastSeen = null, long revision = 1) => new(
        deviceId, Scope, "WS-" + deviceId, Hw(), software,
        new Dictionary<string, string>(), new HashSet<string>(),
        T0, lastSeen ?? T0, T0, revision);

    private static SoftwareItem Sw(string name, string version) => new(name, version, "Pub", null, "winget");

    private static LicenceEntitlement Ent(string id, string product, string? edition, int seats,
        DateTimeOffset? expires = null, long revision = 1) => new(
        id, Scope, product, edition, seats, expires, "PO-2026-114 on file", Admin, T0, revision);

    private static EditionClassifier ClassifierWithOffice()
    {
        var c = new EditionClassifier();
        Assert.True(c.AddRule(new EditionRule("Microsoft Office", "ProPlus", "2021.0", "2024.0")).Ok);
        Assert.True(c.AddRule(new EditionRule("Microsoft Office", "Standard", "2019.0", "2021.0")).Ok);
        return c;
    }

    private static LicencePositionReport Build(
        IReadOnlyList<LicenceEntitlement> ents, IReadOnlyList<DeviceInventoryRecord> inv,
        EditionClassifier? classifier = null, IReadOnlyList<SoftwareUsageFact>? usage = null,
        DateTimeOffset? now = null) =>
        LicencePositionBuilder.Build(ents, inv, classifier ?? new EditionClassifier(), usage, Scope, now ?? T0);

    // ---- entitlements ------------------------------------------------

    [Fact]
    public void Entitlement_Add_AdmittedAndLabelledAsAdminAsserted()
    {
        var store = new EntitlementStore();
        var (ok, _) = store.Add(Ent("lic-1", "Microsoft Office", "ProPlus", 50));
        Assert.True(ok);
        var cur = Assert.Single(store.Current(Scope));
        Assert.Equal(50, cur.Seats);
        Assert.Contains("admin-asserted", LicenceEntitlement.ProvenanceLabel);
    }

    [Fact]
    public void Entitlement_InvalidSeatCounts_RefusedByName()
    {
        var store = new EntitlementStore();
        Assert.False(store.Add(Ent("lic-0", "App", null, 0)).Ok);
        Assert.False(store.Add(Ent("lic-neg", "App", null, -5)).Ok);
        var absurd = store.Add(Ent("lic-absurd", "App", null, MeteringLimits.MaxSeatsPerEntitlement + 1));
        Assert.False(absurd.Ok);
        Assert.Contains("absurdity bound", absurd.Reason);
        Assert.Empty(store.Current());
    }

    [Fact]
    public void Entitlement_UnattributedOrIdRecycled_Refused()
    {
        var store = new EntitlementStore();
        Assert.False(store.Add(Ent("lic-1", "App", null, 5) with { EnteredBy = " " }).Ok);
        Assert.True(store.Add(Ent("lic-1", "App", null, 5)).Ok);
        Assert.False(store.Add(Ent("lic-1", "App", null, 5)).Ok); // id never recycled
    }

    [Fact]
    public void Entitlement_Update_RequiresExpectedRevision_AndKeepsHistory()
    {
        var store = new EntitlementStore();
        store.Add(Ent("lic-1", "App", null, 10));
        Assert.False(store.Update(Ent("lic-1", "App", null, 20, revision: 2), expectedRevision: 99).Ok);
        var (ok, _) = store.Update(Ent("lic-1", "App", null, 20, revision: 2), expectedRevision: 1);
        Assert.True(ok);
        Assert.Equal(20, Assert.Single(store.Current()).Seats);
        Assert.Equal(2, store.History("lic-1").Count); // r1 retained
    }

    // ---- edition classification ---------------------------------------

    [Fact]
    public void Classifier_VersionBandsDetermineEdition_NoRuleMeansUnknown()
    {
        var c = ClassifierWithOffice();
        Assert.Equal("ProPlus", c.Classify("Microsoft Office", "2021.5"));
        Assert.Equal("Standard", c.Classify("Microsoft Office", "2019.2"));
        Assert.Null(c.Classify("Microsoft Office", "2030.0"));
        Assert.Null(c.Classify("Other App", "2021.5"));
    }

    [Fact]
    public void Classifier_ReservedUnknownLabel_RefusedAsRuleEdition()
    {
        var c = new EditionClassifier();
        Assert.False(c.AddRule(new EditionRule("App", "UNKNOWN")).Ok);
    }

    // ---- position ------------------------------------------------------

    [Fact]
    public void Position_CompliantEdition_DeltaZero()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 2) }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(LicenceStates.Compliant, line.State);
        Assert.Equal(0, line.Delta);
        Assert.Equal(2, line.InstalledCount);
        Assert.Equal(2, line.DeviceCount);
        Assert.Equal(new[] { "lic-1@r1" }, line.EntitlementRefs);
    }

    [Fact]
    public void Position_OverLicensed_FindingAndDeltaNegative()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-3", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 2) }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(LicenceStates.OverLicensed, line.State);
        Assert.Equal(-1, line.Delta);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindOverLicensed && f.Severity == LicenceFinding.SeverityCritical);
    }

    [Fact]
    public void Position_UnderLicensed_SurplusNamed()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 10) }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(LicenceStates.UnderLicensed, line.State);
        Assert.Equal(9, line.Delta);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUnderLicensed);
    }

    [Fact]
    public void Position_NoEntitlement_UnlicensedUnknown_NoDelta()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Mystery App", "1.0") }) };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv);
        // No entitlement AND no classifier rule: the product's only
        // line is the unknown-edition line, its delta is null (never
        // zero), and the report names the missing entitlement.
        var line = Assert.Single(report.Lines);
        Assert.True(line.IsUnknownEditionLine);
        Assert.Null(line.EntitledSeats);
        Assert.Null(line.Delta);
        Assert.Contains(report.Notes, n => n.Contains("UNLICENSED-UNKNOWN"));
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUnknownEdition);
    }

    [Fact]
    public void Position_KnownEditionNoEntitlement_UnlicensedUnknownLine()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(LicenceStates.UnlicensedUnknown, line.State);
        Assert.Null(line.EntitledSeats);
        Assert.Null(line.Delta);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUnlicensedUnknown);
    }

    [Fact]
    public void Position_ProductWideEntitlement_CoversUnknownEditionInstalls_ButNamesIt()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2030.0") }), // no rule -> unknown edition
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }), // ProPlus, no edition entitlement
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", null, 5) }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.False(line.IsUnknownEditionLine);
        Assert.Equal(2, line.InstalledCount);
        Assert.Equal(3, line.Delta);
        Assert.Contains(report.Notes, n => n.Contains("edition-agnostic"));
    }

    [Fact]
    public void Position_ExpiredEntitlement_ContributesZeroEffectiveSeats()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var expired = Ent("lic-1", "Microsoft Office", "ProPlus", 10, expires: T0.AddDays(-1));
        var report = Build(new[] { expired }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(10, line.EntitledSeats);       // as asserted
        Assert.Equal(0, line.EffectiveEntitledSeats); // as effective
        Assert.Equal(LicenceStates.OverLicensed, line.State);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindEntitlementExpired);
    }

    [Fact]
    public void Position_EntitledNotInstalled_StateNamed()
    {
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 5) },
            Array.Empty<DeviceInventoryRecord>(), ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(LicenceStates.EntitledNotInstalled, line.State);
        Assert.Equal(5, line.Delta);
    }

    // ---- staleness -------------------------------------------------------

    [Fact]
    public void Staleness_PerDeviceAndAggregate_OldestDeviceGovernsHeader()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("App", "1.0") }, lastSeen: T0.AddHours(-1)),
            Record("dev-2", new[] { Sw("App", "1.0") }, lastSeen: T0.AddHours(-72)),
        };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv, now: T0);
        Assert.Equal(1, report.StaleDeviceCount);
        Assert.True(report.HasStaleInventory);
        Assert.True(report.Header.HasStaleInputs(T0));
        var stale = Assert.Single(report.Devices, d => d.IsStale);
        Assert.Equal("dev-2", stale.DeviceId);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindStaleInventory && f.Detail.Contains("dev-2"));
    }

    [Fact]
    public void Staleness_FreshFleet_HeaderClean()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }) };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv);
        Assert.False(report.HasStaleInventory);
    }

    // ---- usage -------------------------------------------------------------

    [Fact]
    public void Usage_NoFacts_ReportSaysUsageNotMeasured_NeverFromInstalls()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 5) }, inv, ClassifierWithOffice());
        var line = Assert.Single(report.Lines);
        Assert.Equal(UsageSummary.StateNotMeasured, line.Usage.State);
        Assert.Contains("usage not measured", line.Usage.Note);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUsageNotMeasured);
    }

    [Fact]
    public void Usage_WithNamedSourceFacts_MeasuredAndUnusedCounted()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var usage = new[]
        {
            new SoftwareUsageFact("dev-1", "Microsoft Office", "windows-userassist", T0.AddDays(-200), T0),
            new SoftwareUsageFact("dev-2", "Microsoft Office", "windows-userassist", T0.AddDays(-1), T0),
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 5) }, inv, ClassifierWithOffice(), usage);
        var line = Assert.Single(report.Lines);
        Assert.Equal(UsageSummary.StateMeasured, line.Usage.State);
        Assert.Equal(2, line.Usage.MeasuredInstalls);
        Assert.Equal(1, line.Usage.UnusedMeasuredInstalls);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUnusedSoftware);
    }

    [Fact]
    public void Usage_InvalidFacts_DroppedAndCounted()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var usage = new[]
        {
            new SoftwareUsageFact("dev-1", "Microsoft Office", "", T0.AddDays(-1), T0),       // unnamed source
            new SoftwareUsageFact("dev-1", "Microsoft Office", "src", T0.AddDays(1), T0),      // future last-used
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 5) }, inv, ClassifierWithOffice(), usage);
        var line = Assert.Single(report.Lines);
        Assert.Equal(UsageSummary.StateNotMeasured, line.Usage.State);
        Assert.Contains(report.Notes, n => n.Contains("usage facts dropped as invalid: 2"));
    }

    // ---- report integrity / export ------------------------------------------

    [Fact]
    public void Report_ContentHashVerifies_AndHubExportCarriesProvenance()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }, lastSeen: T0.AddHours(-72)) };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 5) }, inv, ClassifierWithOffice());
        Assert.True(report.VerifyContentHash());
        var hub = report.ToHubReport();
        var text = ReportExporter.ToText(hub, T0);
        Assert.Contains("STALE INPUTS", text);
        Assert.Contains("admin-asserted", text);
        var csv = ReportExporter.ToCsv(hub, T0);
        Assert.Contains("licence_position", csv);
    }

    [Fact]
    public void Findings_EmittedToSink_ExcludingInfo()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 1) }, inv, ClassifierWithOffice());
        var sink = new RecordingLicenceFindingSink();
        var emitted = LicencePositionBuilder.EmitFindings(report, sink, T0);
        Assert.True(emitted >= 1);
        Assert.Contains(sink.Alerts, a => a.Kind == LicenceFinding.KindOverLicensed);
        Assert.All(sink.Alerts, a => Assert.NotEqual(LicenceFinding.SeverityInfo, a.Severity));
    }

    // ---- Core service ---------------------------------------------------------

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public ManagementPolicyService PolicySvc;
        public InventoryStore Inventory = new();
        public SoftwareMeteringService Svc;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of("hub", Scope);

        public Rig()
        {
            PolicySvc = new ManagementPolicyService(Audit, null, Policy, () => Now);
            Svc = new SoftwareMeteringService(Audit, PolicySvc, Inventory, () => Now);
        }

        public void SetPolicy(string key, string value) =>
            Policy.AddDocument(new ManagementPolicyDocument("doc-" + key, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, 1));
    }

    [Fact]
    public void Service_GeneratesReportOverInventoryStore_AndAudits()
    {
        var rig = new Rig();
        rig.Inventory.ApplyBaseline(Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }), T0);
        Assert.True(rig.Svc.AddEditionRule(rig.Facts, new EditionRule("Microsoft Office", "ProPlus", "2021.0", "2024.0"), Admin).Ok);
        Assert.True(rig.Svc.AddEntitlement(rig.Facts, Ent("lic-1", "Microsoft Office", "ProPlus", 1)).Ok);
        var (ok, _, report) = rig.Svc.GenerateReport(rig.Facts);
        Assert.True(ok);
        Assert.NotNull(report);
        Assert.Equal(LicenceStates.Compliant, Assert.Single(report!.Lines).State);
        Assert.NotNull(rig.Svc.GetStoredReport(rig.Facts, report.Header.ReportId)); // FL-26 F1: stores are private; reads go through the gated service
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "licence_report_generated");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "entitlement_entered");
    }

    [Fact]
    public void Service_PolicyDisabled_RefusesGenerationAndEntitlementEntry()
    {
        var rig = new Rig();
        rig.SetPolicy(MeteringPolicyKeys.RegistryToggle, "false");
        Assert.False(rig.Svc.IsEnabled(rig.Facts));
        Assert.False(rig.Svc.GenerateReport(rig.Facts).Ok);
        Assert.False(rig.Svc.AddEntitlement(rig.Facts, Ent("lic-1", "App", null, 5)).Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "metering_refused");
    }

    [Fact]
    public void Service_DirectiveNamedKeyFalse_AlsoDisables()
    {
        var rig = new Rig();
        rig.SetPolicy(MeteringPolicyKeys.SoftwareMeteringEnabled, "false");
        Assert.False(rig.Svc.IsEnabled(rig.Facts));
    }

    [Fact]
    public void Service_ExportStored_RidesRmm13Exporter()
    {
        var rig = new Rig();
        var (ok, _, report) = rig.Svc.GenerateReport(rig.Facts);
        Assert.True(ok);
        var json = rig.Svc.ExportStored(rig.Facts, report!.Header.ReportId, "json", Admin); // FL-26 F1: export is gated + audited, names its actor
        Assert.NotNull(json);
        Assert.Contains("licence_position", json!);
        Assert.Null(rig.Svc.ExportStored(rig.Facts, "no-such-report", "json", Admin));
    }
}

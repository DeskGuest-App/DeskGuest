using System.Reflection;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Reporting;
using Acp.Shared.SoftwareMetering;

namespace Acp.Tests;

// RMM-26 FIX LANE (FL-26a/b) — permanent regression tests for the
// reconciled review (verdict abf3c933, FAIL, 12 findings,
// all confirmed). One or more tests per finding; F12b/F12c were
// re-verified against source by this lane before fixing (both
// confirmed — see log-fix26.md).
public class Rmm26FixTests
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
        long revision = 1) => new(
        id, Scope, product, edition, seats, null, "PO-2026-114 on file", Admin, T0, revision);

    private static LicencePositionReport Build(
        IReadOnlyList<LicenceEntitlement> ents, IReadOnlyList<DeviceInventoryRecord> inv,
        EditionClassifier? classifier = null, IReadOnlyList<SoftwareUsageFact>? usage = null) =>
        LicencePositionBuilder.Build(ents, inv, classifier ?? new EditionClassifier(), usage, Scope, T0);

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

    // ---- F1: stores behind the gate -----------------------------------

    [Fact]
    public void F1_Service_ExposesNoPublicStoreSurface()
    {
        var exposed = typeof(SoftwareMeteringService)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.PropertyType).Concat(
                typeof(SoftwareMeteringService).GetFields(BindingFlags.Public | BindingFlags.Instance)
                    .Select(f => f.FieldType))
            .ToList();
        Assert.DoesNotContain(typeof(EntitlementStore), exposed);
        Assert.DoesNotContain(typeof(EditionClassifier), exposed);
        Assert.DoesNotContain(typeof(LicenceReportStore), exposed);
    }

    [Fact]
    public void F1_ExportStored_GatedAndAudited_UnknownIdLedgered()
    {
        var rig = new Rig();
        var (ok, _, report) = rig.Svc.GenerateReport(rig.Facts);
        Assert.True(ok);

        var json = rig.Svc.ExportStored(rig.Facts, report!.Header.ReportId, "json", Admin);
        Assert.NotNull(json);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "licence_report_exported" && e.Actor == Admin);

        Assert.Null(rig.Svc.ExportStored(rig.Facts, "no-such-report", "json", Admin));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "licence_report_export_refused");

        rig.SetPolicy(MeteringPolicyKeys.RegistryToggle, "false");
        Assert.Null(rig.Svc.ExportStored(rig.Facts, report.Header.ReportId, "json", Admin));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "metering_refused");
    }

    [Fact]
    public void F1_ImportExportEntitlements_GatedAndAudited()
    {
        var src = new EntitlementStore();
        Assert.True(src.Add(Ent("lic-1", "App", null, 5)).Ok);

        var rig = new Rig();
        var imp = rig.Svc.ImportEntitlements(rig.Facts, src.ExportJson(), Admin);
        Assert.True(imp.Ok);
        Assert.Equal(1, imp.Result!.Restored);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "entitlements_imported" && e.Detail.Contains("restored=1"));
        Assert.Single(rig.Svc.CurrentEntitlements(rig.Facts, Scope));

        var exp = rig.Svc.ExportEntitlements(rig.Facts, Admin);
        Assert.True(exp.Ok);
        Assert.Contains("lic-1", exp.Json!);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "entitlements_exported" && e.Actor == Admin);

        var rig2 = new Rig();
        rig2.SetPolicy(MeteringPolicyKeys.RegistryToggle, "false");
        Assert.False(rig2.Svc.ImportEntitlements(rig2.Facts, src.ExportJson(), Admin).Ok);
        Assert.False(rig2.Svc.ExportEntitlements(rig2.Facts, Admin).Ok);
        Assert.Empty(rig2.Svc.CurrentEntitlements(rig2.Facts, Scope));
    }

    // ---- F2: report store integrity -------------------------------------

    [Fact]
    public void F2_Store_SameIdRefused_OriginalKept_TamperedRefused()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }) };
        var report = Build(new[] { Ent("lic-1", "App", null, 1) }, inv);
        var store = new LicenceReportStore();

        Assert.True(store.Store(report).Ok);
        var again = store.Store(report);
        Assert.False(again.Ok);
        Assert.Contains("already stored", again.Reason);
        Assert.Same(report, store.Get(report.Header.ReportId));

        var tampered = report with
        {
            Lines = new[] { Assert.Single(report.Lines) with { InstalledCount = 0 } },
        };
        var refused = store.Store(tampered with { Header = tampered.Header with { ReportId = "rpt-other" } });
        Assert.False(refused.Ok);
        Assert.Contains("checksum", refused.Reason);
        Assert.Null(store.Get("rpt-other"));
    }

    // ---- F3: future-dated usage ------------------------------------------

    [Fact]
    public void F3_FutureDatedUsageFact_Refused_WithinSkewAdmitted()
    {
        var futureCollected = new SoftwareUsageFact("dev-1", "App", "windows-userassist", T0.AddHours(-1), T0.AddHours(1));
        Assert.NotNull(futureCollected.Validate(T0));
        var futureUsed = new SoftwareUsageFact("dev-1", "App", "windows-userassist", T0.AddHours(1), T0.AddHours(1));
        Assert.NotNull(futureUsed.Validate(T0)); // last-used == collected passes the old check; both are future
        var withinSkew = new SoftwareUsageFact("dev-1", "App", "windows-userassist", T0.AddMinutes(4), T0.AddMinutes(4));
        Assert.Null(withinSkew.Validate(T0));

        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }) };
        var report = Build(new[] { Ent("lic-1", "App", null, 5) }, inv, usage: new[] { futureUsed });
        Assert.Equal(UsageSummary.StateNotMeasured, Assert.Single(report.Lines).Usage.State);
        Assert.Contains(report.Notes, n => n.Contains("usage facts dropped as invalid: 1"));
    }

    [Fact]
    public void F3_GenerationAudit_NamesUsageSources_AndAnchorsHash()
    {
        var rig = new Rig();
        rig.Inventory.ApplyBaseline(Record("dev-1", new[] { Sw("App", "1.0") }), T0);
        var usage = new[] { new SoftwareUsageFact("dev-1", "App", "windows-userassist", T0.AddDays(-1), T0) };
        var (ok, _, report) = rig.Svc.GenerateReport(rig.Facts, usage);
        Assert.True(ok);
        var entry = Assert.Single(rig.Audit.Entries, e => e.Kind == "licence_report_generated");
        Assert.Contains("usageSources=windows-userassist", entry.Detail);
        Assert.Contains($"hash={report!.ContentHash}", entry.Detail);
    }

    // ---- F4: import chain integrity ---------------------------------------

    private static string DtoJson(string id, long revision, int seats = 5) =>
        $"{{\"Id\":\"{id}\",\"ScopeId\":\"{Scope}\",\"Product\":\"App\",\"Edition\":null,\"Seats\":{seats}," +
        $"\"ExpiresUtc\":null,\"EvidenceNote\":\"e\",\"EnteredBy\":\"{Admin}\"," +
        $"\"EnteredUtc\":\"2026-11-21T12:00:00+00:00\",\"Revision\":{revision},\"Deleted\":false}}";

    [Fact]
    public void F4_ImportJson_GappedChain_RefusedWhole_AndCounted()
    {
        var store = new EntitlementStore();
        var result = store.ImportJson($"[{DtoJson("lic-g", 1)},{DtoJson("lic-g", 3)}]");
        Assert.Equal(0, result.Restored);
        Assert.Equal(2, result.Skipped);
        Assert.Empty(store.Current());
        Assert.Empty(store.FullHistory);
    }

    [Fact]
    public void F4_ImportJson_DuplicateRevision_RefusedWhole_AndCounted()
    {
        var store = new EntitlementStore();
        var result = store.ImportJson($"[{DtoJson("lic-d", 1)},{DtoJson("lic-d", 1, seats: 999)}]");
        Assert.Equal(0, result.Restored);
        Assert.Equal(2, result.Skipped);
        Assert.Empty(store.Current());
    }

    [Fact]
    public void F4_ImportJson_ValidChainRestores_InvalidEntriesCountedNotSilent()
    {
        var store = new EntitlementStore();
        var json = $"[{DtoJson("lic-ok", 1)},{DtoJson("lic-ok", 2, seats: 9)},{DtoJson("lic-bad", 1, seats: 0)}]";
        var result = store.ImportJson(json);
        Assert.Equal(2, result.Restored);
        Assert.Equal(1, result.Skipped);
        Assert.Contains("skipped", result.Reason);
        Assert.Equal(9, Assert.Single(store.Current()).Seats);
        Assert.Equal(2, store.History("lic-ok").Count);
    }

    // ---- F5: reserved UNKNOWN edition --------------------------------------

    [Fact]
    public void F5_EntitlementEditionUnknown_Reserved_Refused()
    {
        var store = new EntitlementStore();
        Assert.False(store.Add(Ent("lic-1", "App", "UNKNOWN", 5)).Ok);
        Assert.False(store.Add(Ent("lic-2", "App", "unknown", 5)).Ok);
        Assert.NotNull(EntitlementValidation.Validate(Ent("lic-3", "App", " Unknown ", 5)));
        Assert.Empty(store.Current());
    }

    // ---- F6: versionless classification --------------------------------------

    [Fact]
    public void F6_VersionlessOrUnparsable_NeverClassified()
    {
        var c = new EditionClassifier();
        Assert.True(c.AddRule(new EditionRule("App", "AnyEdition", null, "2024.0")).Ok); // max-only rule
        Assert.Null(c.Classify("App", null));
        Assert.Null(c.Classify("App", ""));
        Assert.Null(c.Classify("App", "   "));
        Assert.Null(c.Classify("App", "not-a-version"));
        Assert.Equal("AnyEdition", c.Classify("App", "2020.5")); // real versions still classify

        var inv = new[] { Record("dev-1", new[] { Sw("App", "") }) };
        var report = Build(new[] { Ent("lic-1", "App", "AnyEdition", 5) }, inv, c);
        var unknown = Assert.Single(report.Lines, l => l.IsUnknownEditionLine);
        Assert.Equal(1, unknown.InstalledCount); // the versionless install did NOT join the entitled edition's line
    }

    // ---- F7: unlicensed masked by unknown-edition line ------------------------

    [Fact]
    public void F7_NoEntitlementProduct_RaisesUnlicensedUnknown_EvenWithEntitledNeighbours()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Mystery App", "1.0"), Sw("Entitled App", "2.0") }),
        };
        var report = Build(new[] { Ent("lic-1", "Entitled App", null, 5) }, inv);
        Assert.Contains(report.Findings, f =>
            f.Kind == LicenceFinding.KindUnlicensedUnknown && f.Product == "Mystery App");
        Assert.Contains(report.Findings, f =>
            f.Kind == LicenceFinding.KindUnknownEdition && f.Product == "Mystery App");
    }

    // ---- F8: content hash coverage ----------------------------------------------

    [Fact]
    public void F8_HashCoversHeaderInputs_AgeHours_AndUsageNote()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }, lastSeen: T0.AddHours(-3)) };
        var report = Build(new[] { Ent("lic-1", "App", null, 5) }, inv);
        Assert.True(report.VerifyContentHash());

        var inputsTampered = report with
        {
            Header = report.Header with
            {
                Inputs = new[] { new ReportInputProvenance("rmm04.inventory", T0, TimeSpan.FromHours(1), true) },
            },
        };
        Assert.False(inputsTampered.VerifyContentHash());

        var ageTampered = report with
        {
            Devices = new[] { Assert.Single(report.Devices) with { AgeHours = 0 } },
        };
        Assert.False(ageTampered.VerifyContentHash());

        var noteTampered = report with
        {
            Lines = new[]
            {
                Assert.Single(report.Lines) with
                {
                    Usage = Assert.Single(report.Lines).Usage with { Note = "usage measured everywhere, trust me" },
                },
            },
        };
        Assert.False(noteTampered.VerifyContentHash());
    }

    // ---- F9: dedup identity + seat basis -------------------------------------------

    [Fact]
    public void F9_SameInstallReportedByTwoSources_CountsOnce()
    {
        var inv = new[]
        {
            Record("dev-1", new[]
            {
                new SoftwareItem("App", "1.0", "Pub", null, "winget"),
                new SoftwareItem("App", "1.0", "Pub", null, "registry"),   // same install, second source
                new SoftwareItem("App", "1.0", "Pub ", null, "winget"),    // publisher differs only by padding
                new SoftwareItem("App", "2.0", "Pub", null, "winget"),     // distinct version: kept
            }),
        };
        var report = Build(new[] { Ent("lic-1", "App", null, 5) }, inv);
        Assert.Equal(2, Assert.Single(report.Lines).InstalledCount);
        Assert.Contains(report.Notes, n => n.Contains("exact-duplicate installs"));
    }

    [Fact]
    public void F9_ReportStatesSeatBasis()
    {
        var report = Build(Array.Empty<LicenceEntitlement>(), Array.Empty<DeviceInventoryRecord>());
        Assert.Contains(report.Notes, n => n.Contains("seat basis:") && n.Contains("per INSTALL"));
    }

    // ---- F10: per-line usage ---------------------------------------------------------

    [Fact]
    public void F10_UsageSummary_ComputedPerLine_NotPerProduct()
    {
        var c = new EditionClassifier();
        c.AddRule(new EditionRule("Microsoft Office", "ProPlus", "2021.0", "2024.0"));
        c.AddRule(new EditionRule("Microsoft Office", "Standard", "2019.0", "2021.0"));
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2019.2") }),
        };
        var ents = new[]
        {
            Ent("lic-1", "Microsoft Office", "ProPlus", 5),
            Ent("lic-2", "Microsoft Office", "Standard", 5),
        };
        var usage = new[]
        {
            new SoftwareUsageFact("dev-1", "Microsoft Office", "windows-userassist", T0.AddDays(-1), T0),
        };
        var report = Build(ents, inv, c, usage);
        var proPlus = Assert.Single(report.Lines, l => l.Edition == "ProPlus");
        var standard = Assert.Single(report.Lines, l => l.Edition == "Standard");
        Assert.Equal(UsageSummary.StateMeasured, proPlus.Usage.State);
        Assert.Equal(1, proPlus.Usage.MeasuredInstalls);
        Assert.Equal(UsageSummary.StateNotMeasured, standard.Usage.State);
        Assert.Equal(0, standard.Usage.MeasuredInstalls);
    }

    // ---- F11: durability named ---------------------------------------------------------

    [Fact]
    public void F11_ReportNamesInMemoryOnlyDurability()
    {
        // REPAIRED (Wave 2 Lane B, 2026-11-22) for bd-shared-rmm-3/F12:
        // the stores behind the report now round-trip through the
        // HubPersistence envelope, so the old "IN-MEMORY ONLY" note
        // would be a false claim. The F11 invariant — the report
        // NAMES its durability honestly — is preserved against the
        // new note text.
        var report = Build(Array.Empty<LicenceEntitlement>(), Array.Empty<DeviceInventoryRecord>());
        Assert.Contains(report.Notes, n => n.Contains("HubPersistence envelope"));
        Assert.Contains(report.ToHubReport().Notes, n => n.Contains("HubPersistence envelope"));
    }

    // ---- F12a: effective seats render -----------------------------------------------------

    [Fact]
    public void F12a_EffectiveSeats_OnUnlicensedRow_IsNoRecord_NotZero()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Mystery App", "1.0") }) };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv);
        var hub = report.ToHubReport();
        var col = Array.IndexOf(hub.Columns.ToArray(), "effective_entitled");
        Assert.True(col >= 0);
        var row = Assert.Single(hub.Rows);
        Assert.Equal("(no entitlement record)", row[col]);
    }

    // ---- F12b: blank device id --------------------------------------------------------------

    [Fact]
    public void F12b_BlankDeviceId_NamedInvalid_NotCountedAsDuplicate()
    {
        var inv = new[]
        {
            Record(" ", new[] { Sw("App", "1.0") }),
            Record("dev-1", new[] { Sw("App", "1.0") }, revision: 1),
            Record("dev-1", new[] { Sw("App", "1.0") }, revision: 2),
        };
        var report = Build(new[] { Ent("lic-1", "App", null, 5) }, inv);
        Assert.Contains(report.Notes, n => n.Contains("blank device id dropped as INVALID: 1"));
        Assert.Contains(report.Notes, n => n.Contains("collapsed by device identity: 1 record(s)"));
        Assert.Single(report.Devices);
        Assert.Equal(1, report.Lines.Sum(l => l.InstalledCount));
    }

    // ---- F12c: future last-seen -----------------------------------------------------------------

    [Fact]
    public void F12c_FutureLastSeen_ClockSkewFinding_NotFresh()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }, lastSeen: T0.AddHours(2)) };
        var report = Build(new[] { Ent("lic-1", "App", null, 5) }, inv);
        var device = Assert.Single(report.Devices);
        Assert.True(device.IsStale); // freshness unverifiable — NOT presented as fresh
        Assert.Contains(report.Findings, f =>
            f.Kind == LicenceFinding.KindClockSkew && f.Detail.Contains("dev-1"));
        Assert.DoesNotContain(report.Findings, f => f.Kind == LicenceFinding.KindStaleInventory);
    }
}

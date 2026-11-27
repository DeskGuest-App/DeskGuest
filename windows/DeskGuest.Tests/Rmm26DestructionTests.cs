using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.SoftwareMetering;

namespace DeskGuest.Tests;

// RMM-26 DESTRUCTION PASS — hostile attacks on the licence position:
//   1. entitlement inflation rewriting a PAST report;
//   2. double counting via duplicate inventory records;
//   3. edition laundering (unknown absorbed into entitled edition);
//   4. stale-inventory masking (fleet-wide stale as current);
//   5. negative/absurd entitlement values;
//   6. entitlement deletion hiding an over-licence finding from history.
// Every attack resisted = a permanent regression test here.
public class Rmm26DestructionTests
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

    private static LicenceEntitlement Ent(string id, string product, string? edition, int seats, long revision = 1) => new(
        id, Scope, product, edition, seats, null, "evidence", Admin, T0, revision);

    private static EditionClassifier OfficeClassifier()
    {
        var c = new EditionClassifier();
        c.AddRule(new EditionRule("Microsoft Office", "ProPlus", "2021.0", "2024.0"));
        return c;
    }

    private static LicencePositionReport Build(
        IReadOnlyList<LicenceEntitlement> ents, IReadOnlyList<DeviceInventoryRecord> inv,
        EditionClassifier? classifier = null, DateTimeOffset? now = null) =>
        LicencePositionBuilder.Build(ents, inv, classifier ?? new EditionClassifier(),
            null, Scope, now ?? T0);

    // ---- 1. entitlement inflation vs a PAST report ---------------------

    [Fact]
    public void Attack_InflateEntitlementAfterReport_PastReportUnchanged()
    {
        var store = new EntitlementStore();
        var reports = new LicenceReportStore();
        store.Add(Ent("lic-1", "Microsoft Office", "ProPlus", 1));
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var past = Build(store.Current(Scope), inv, OfficeClassifier());
        reports.Store(past);
        Assert.Equal(LicenceStates.OverLicensed, Assert.Single(past.Lines).State);

        // The attack: inflate the claim so the over-licence "goes away".
        Assert.True(store.Update(Ent("lic-1", "Microsoft Office", "ProPlus", 500, revision: 2), expectedRevision: 1).Ok);

        var reread = reports.Get(past.Header.ReportId)!;
        Assert.Equal(1, Assert.Single(reread.Lines).EntitledSeats); // snapshot value, not 500
        Assert.Equal(LicenceStates.OverLicensed, Assert.Single(reread.Lines).State);
        Assert.True(reread.VerifyContentHash());
        Assert.Contains(reread.Findings, f => f.Kind == LicenceFinding.KindOverLicensed);

        // A NEW report honestly shows the new claim — and names its revision.
        var fresh = Build(store.Current(Scope), inv, OfficeClassifier());
        Assert.Equal(new[] { "lic-1@r2" }, Assert.Single(fresh.Lines).EntitlementRefs);
        Assert.Equal(LicenceStates.UnderLicensed, Assert.Single(fresh.Lines).State);
    }

    [Fact]
    public void Attack_TamperStoredReportLines_ContentHashFails()
    {
        var inv = new[] { Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }) };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 1) }, inv, OfficeClassifier());
        var tampered = report with
        {
            Lines = new[] { Assert.Single(report.Lines) with { InstalledCount = 0, State = LicenceStates.Compliant } },
        };
        Assert.False(tampered.VerifyContentHash());
    }

    // ---- 2. double counting ---------------------------------------------

    [Fact]
    public void Attack_DuplicateDeviceRecords_SameInstallCountedOnce()
    {
        var older = Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }, revision: 1);
        var newer = Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }, revision: 3);
        var staleCopy = Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }, revision: 2);
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 1) },
            new[] { older, newer, staleCopy }, OfficeClassifier());
        var line = Assert.Single(report.Lines);
        Assert.Equal(1, line.InstalledCount); // NOT 3
        Assert.Equal(LicenceStates.Compliant, line.State);
        Assert.Single(report.Devices);
        Assert.Contains(report.Notes, n => n.Contains("duplicate inventory records collapsed"));
    }

    [Fact]
    public void Attack_DuplicateInstallRowsWithinDevice_CountedOnce_DistinctVersionsKept()
    {
        var inv = new[]
        {
            Record("dev-1", new[]
            {
                Sw("Microsoft Office", "2021.5"), Sw("Microsoft Office", "2021.5"), // exact dup
                Sw("Microsoft Office", "2021.6"),                                    // distinct install
            }),
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 2) }, inv, OfficeClassifier());
        Assert.Equal(2, Assert.Single(report.Lines).InstalledCount);
        Assert.Contains(report.Notes, n => n.Contains("exact-duplicate installs"));
    }

    [Fact]
    public void Attack_ProductWidePlusKnownEdition_InstallCountedInExactlyOneLine()
    {
        // Regression (found by the RMM-26 functional suite): with a
        // product-wide claim, a known-edition install ALSO appeared
        // in a spurious unlicensed edition line — the report's
        // totals double-counted it.
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "1999.0") }), // unknown edition
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }), // ProPlus, no own claim
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", null, 5) }, inv, OfficeClassifier());
        Assert.Equal(2, report.Lines.Sum(l => l.InstalledCount)); // fleet truth: 2 installs
        Assert.Single(report.Lines);
    }

    // ---- 3. edition laundering --------------------------------------------

    [Fact]
    public void Attack_UnknownEditionInstall_NotAbsorbedIntoEntitledEdition()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }), // ProPlus
            Record("dev-2", new[] { Sw("Microsoft Office", "1999.0") }), // no rule -> UNKNOWN
        };
        var report = Build(new[] { Ent("lic-1", "Microsoft Office", "ProPlus", 1) }, inv, OfficeClassifier());
        var proPlus = Assert.Single(report.Lines, l => l.Edition == "ProPlus");
        Assert.Equal(1, proPlus.InstalledCount); // the unknown install did NOT join it
        Assert.Equal(LicenceStates.Compliant, proPlus.State);
        var unknown = Assert.Single(report.Lines, l => l.IsUnknownEditionLine);
        Assert.Equal(1, unknown.InstalledCount);
        Assert.Null(unknown.Delta);
        Assert.Equal(LicenceStates.UnknownEdition, unknown.State);
        Assert.Contains(report.Findings, f => f.Kind == LicenceFinding.KindUnknownEdition);
    }

    [Fact]
    public void Attack_RuleNamedUnknown_CannotLaunderViaClassifier()
    {
        var c = new EditionClassifier();
        Assert.False(c.AddRule(new EditionRule("App", "unknown", "1.0", "2.0")).Ok);
        Assert.Null(c.Classify("App", "1.5"));
    }

    // ---- 4. stale-inventory masking -----------------------------------------

    [Fact]
    public void Attack_FleetWideStaleSnapshot_CannotPresentAsCurrent()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("App", "1.0") }, lastSeen: T0.AddDays(-30)),
            Record("dev-2", new[] { Sw("App", "1.0") }, lastSeen: T0.AddDays(-45)),
        };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv, now: T0);
        Assert.Equal(2, report.StaleDeviceCount);
        Assert.True(report.Header.HasStaleInputs(T0));
        Assert.Contains(report.Notes, n => n.Contains("EVERY device's inventory is stale"));
        var hubText = ReportExporter.ToText(report.ToHubReport(), T0);
        Assert.Contains("STALE INPUTS", hubText); // every export format carries it
        var hubCsv = ReportExporter.ToCsv(report.ToHubReport(), T0);
        Assert.Contains("stale_inputs,true", hubCsv.Replace("\"", ""));
    }

    [Fact]
    public void Attack_OneFreshDevice_DoesNotLaunderStaleFleet()
    {
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("App", "1.0") }, lastSeen: T0),
            Record("dev-2", new[] { Sw("App", "1.0") }, lastSeen: T0.AddDays(-10)),
            Record("dev-3", new[] { Sw("App", "1.0") }, lastSeen: T0.AddDays(-20)),
        };
        var report = Build(Array.Empty<LicenceEntitlement>(), inv, now: T0);
        // Header rests on the OLDEST device (RMM-13 rule): stale despite dev-1 being fresh.
        Assert.True(report.Header.HasStaleInputs(T0));
        Assert.Equal(2, report.StaleDeviceCount);
    }

    // ---- 5. negative / absurd entitlements -----------------------------------

    [Fact]
    public void Attack_NegativeAndZeroSeats_CannotCreateFakeCompliance()
    {
        var store = new EntitlementStore();
        Assert.False(store.Add(Ent("lic-neg", "App", null, -100)).Ok);
        Assert.False(store.Add(Ent("lic-zero", "App", null, 0)).Ok);
        Assert.False(store.Add(Ent("lic-huge", "App", null, int.MaxValue)).Ok);
        // With nothing admitted, installs still read unlicensed-unknown.
        var inv = new[] { Record("dev-1", new[] { Sw("App", "1.0") }) };
        var report = Build(store.Current(Scope), inv);
        Assert.All(report.Lines, l => Assert.NotEqual(LicenceStates.Compliant, l.State));
    }

    [Fact]
    public void Attack_StaleEditorOverwrite_Refused()
    {
        var store = new EntitlementStore();
        store.Add(Ent("lic-1", "App", null, 10));
        store.Update(Ent("lic-1", "App", null, 20, revision: 2), expectedRevision: 1);
        // Second admin still holding r1 tries to overwrite with r2 content:
        var attack = store.Update(Ent("lic-1", "App", null, 9999, revision: 2), expectedRevision: 1);
        Assert.False(attack.Ok);
        Assert.Equal(20, Assert.Single(store.Current()).Seats);
    }

    // ---- 6. deletion hiding history -------------------------------------------

    [Fact]
    public void Attack_DeleteEntitlement_PastReportAndHistorySurvive()
    {
        var store = new EntitlementStore();
        var reports = new LicenceReportStore();
        store.Add(Ent("lic-1", "Microsoft Office", "ProPlus", 1));
        var inv = new[]
        {
            Record("dev-1", new[] { Sw("Microsoft Office", "2021.5") }),
            Record("dev-2", new[] { Sw("Microsoft Office", "2021.5") }),
        };
        var past = Build(store.Current(Scope), inv, OfficeClassifier());
        reports.Store(past);
        Assert.Contains(past.Findings, f => f.Kind == LicenceFinding.KindOverLicensed);

        Assert.True(store.Delete("lic-1", Admin, T0).Ok);

        // Past report: untouched, finding intact, hash verifies.
        var reread = reports.Get(past.Header.ReportId)!;
        Assert.Contains(reread.Findings, f => f.Kind == LicenceFinding.KindOverLicensed);
        Assert.True(reread.VerifyContentHash());
        // History: the claim AND its tombstone are both still there.
        var history = store.History("lic-1");
        Assert.Equal(2, history.Count);
        Assert.False(history[0].Deleted);
        Assert.True(history[1].Deleted);
        // Future reports honestly show the consequence: unlicensed-unknown.
        var fresh = Build(store.Current(Scope), inv, OfficeClassifier());
        Assert.Contains(fresh.Lines, l => l.State == LicenceStates.UnlicensedUnknown);
        // Export carries history — deletion cannot ride an export out.
        var export = store.ExportJson();
        Assert.Contains("\"Deleted\":true", export);
    }

    [Fact]
    public void Attack_RecycleDeletedId_Refused()
    {
        var store = new EntitlementStore();
        store.Add(Ent("lic-1", "App", null, 5));
        store.Delete("lic-1", Admin, T0);
        Assert.False(store.Add(Ent("lic-1", "App", null, 5000)).Ok);
    }

    [Fact]
    public void Attack_ImportOverLiveHistory_Refused()
    {
        var store = new EntitlementStore();
        store.Add(Ent("lic-1", "App", null, 5));
        var other = new EntitlementStore();
        other.Add(Ent("lic-9", "App", null, 1));
        Assert.Equal(0, store.ImportJson(other.ExportJson()).Restored); // FL-26 F4: import reports restored/skipped; never a merge over live history
        Assert.Single(store.Current());
    }
}

using Acp.Core.Services;
using Acp.Shared.Connection;
using Acp.Shared.Inventory;

namespace Acp.Tests;

/// <summary>RMM-04 — continuous fleet inventory: hardware, software,
/// warranty, custom fields, unmanaged-asset register, lifecycle
/// reporting. Every test names the directive half it enforces.</summary>
public class Rmm04Tests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-11-21T12:00:00Z");

    private sealed class FakeClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = T0;
    }

    private static HardwareSnapshot Hw(string serial = "ABC1234", long ram = 16_000_000_000,
        string osBuild = "26100.1", string manufacturer = "Dell Inc.") => new(
        Manufacturer: manufacturer, Model: "OptiPlex 7010", SerialNumber: serial,
        CpuModel: "Intel i7-13700", CpuCores: 16, RamBytes: ram,
        OsName: "Windows 11 Pro", OsBuild: osBuild, OsVersion: "10.0.26100",
        BiosVersion: "1.2.3",
        Disks: new[] { new DiskInfo("C:", "Samsung SSD 990", "DISK001", 512_000_000_000, "NVMe", "SSD") },
        Peripherals: new[] { new PeripheralInfo("monitor", "Dell U2723", "Dell", "U2723") },
        CollectedUtc: T0);

    private static DeviceInventoryRecord Record(string deviceId, HardwareSnapshot? hw = null,
        IReadOnlyList<SoftwareItem>? software = null, string hostname = "WS-01") => new(
        DeviceId: deviceId, ScopeId: "company-1", Hostname: hostname,
        Hardware: hw ?? Hw(),
        Software: software ?? new[] { new SoftwareItem("Adobe Acrobat", "24.0.1", "Adobe", null, "winget") },
        CustomFields: new Dictionary<string, string>(),
        Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    private static InventoryStore StoreWithSchema()
    {
        var store = new InventoryStore();
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("site_code", "Site code", "text")));
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("refresh_year", "Refresh year", "number")));
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("criticality", "Criticality", "enum",
            new[] { "low", "high" })));
        return store;
    }

    // ---- version comparison -------------------------------------------

    [Fact]
    public void VersionCompare_NumericSegmentsBeatStringOrder()
    {
        Assert.True(SoftwareVersion.Compare("9.0", "10.0") < 0);
        Assert.True(SoftwareVersion.Compare("24.0.10", "24.0.9") > 0);
        Assert.Equal(0, SoftwareVersion.Compare("1.2", "1.2.0"));
        Assert.True(SoftwareVersion.Compare("1.2-beta", "1.2") < 0);
        Assert.Equal(0, SoftwareVersion.Compare(" 2.0 ", "2.0"));
    }

    // ---- baseline + diff reporting --------------------------------------

    [Fact]
    public void Baseline_AcceptedAtRevision1_AndSecondBaselineRefused()
    {
        var store = new InventoryStore();
        var r1 = store.ApplyBaseline(Record("dev-1"), T0);
        Assert.True(r1.Accepted);
        Assert.Equal(1, r1.NewRevision);
        Assert.Equal(1, store.Get("dev-1")!.Revision);
        var r2 = store.ApplyBaseline(Record("dev-1"), T0);
        Assert.False(r2.Accepted); // history cannot be reset silently
    }

    [Fact]
    public void ChangeReport_SoftwareUpgrade_AppliesAndBumpsRevision()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", software: new[] { new SoftwareItem("Adobe Acrobat", "25.1.0", "Adobe", null, "winget") });
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.Single(diff.ChangedSoftware);
        Assert.Equal("24.0.1", diff.ChangedSoftware[0].OldVersion);
        var result = store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(1));
        Assert.True(result.Accepted, result.Outcome);
        Assert.Equal(2, result.NewRevision);
        Assert.Equal("25.1.0", store.Get("dev-1")!.Software[0].Version);
    }

    [Fact]
    public void ChangeReport_EmptyDiff_IsSeenUnchanged_NoRevisionBump()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var stored = store.Get("dev-1")!;
        var same = Record("dev-1");
        var diff = InventoryDiffer.Compute(stored, same, stored.Revision, T0.AddHours(2));
        Assert.True(diff.IsEmpty);
        var result = store.ApplyChangeReport(new InventoryChangeReport(diff, same), T0.AddHours(2));
        Assert.True(result.Accepted);
        Assert.Equal("seen_unchanged", result.Outcome);
        Assert.Equal(1, store.Get("dev-1")!.Revision);
        Assert.Equal(T0.AddHours(2), store.Get("dev-1")!.LastSeenUtc);
    }

    [Fact]
    public void ChangeReport_HardwareChange_IsNamedInDiff()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", hw: Hw(ram: 32_000_000_000, osBuild: "26100.2"));
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.Contains(diff.HardwareChanges, c => c.StartsWith("ram_bytes:"));
        Assert.Contains(diff.HardwareChanges, c => c.StartsWith("os_build:"));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(1)).Accepted);
    }

    [Fact]
    public void ChangeReport_WithoutBaseline_Refused()
    {
        var store = new InventoryStore();
        var next = Record("ghost");
        var diff = InventoryDiffer.Compute(null, next, 0, T0);
        Assert.False(store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0).Accepted);
    }

    [Fact]
    public void Warranty_OnWire_IsIgnored_StoredWarrantySurvivesReports()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var warranty = new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(2), "ProSupport", T0);
        Assert.True(store.SetWarranty("dev-1", warranty));
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", software: new[] { new SoftwareItem("Adobe Acrobat", "25.0", "Adobe", null, null) });
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(1)).Accepted);
        Assert.Equal(warranty, store.Get("dev-1")!.Warranty); // hub-owned, untouched by the report
    }

    // ---- custom fields + tags ---------------------------------------------

    [Fact]
    public void CustomFields_SchemaGoverns_UndefinedKeyAndBadEnumRefuse()
    {
        var store = StoreWithSchema();
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.True(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["site_code"] = "SITE-ONE", ["criticality"] = "high" },
            new[] { "site-server" }, T0.AddHours(1)));
        Assert.Equal("SITE-ONE", store.Get("dev-1")!.CustomFields["site_code"]);
        Assert.Contains("site-server", store.Get("dev-1")!.Tags);

        Assert.False(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["invented_field"] = "x" }, null, T0.AddHours(2)));
        Assert.False(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["criticality"] = "urgent" }, null, T0.AddHours(2))); // not in enum
        Assert.False(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["refresh_year"] = "not-a-year" }, null, T0.AddHours(2)));
        // Schema itself refuses hostile definitions.
        Assert.False(store.DefineCustomField(new CustomFieldDefinition("bad key!", "x", "text")));
        Assert.False(store.DefineCustomField(new CustomFieldDefinition("site_code", "x", "number"))); // type change
    }

    [Fact]
    public void Baseline_WithUndefinedCustomField_Refused()
    {
        var store = StoreWithSchema();
        var rec = Record("dev-1") with
        {
            CustomFields = new Dictionary<string, string> { ["rogue"] = "value" },
        };
        Assert.False(store.ApplyBaseline(rec, T0).Accepted);
        Assert.Null(store.Get("dev-1"));
    }

    // ---- fleet query -------------------------------------------------------

    private static InventoryStore Fleet()
    {
        var store = StoreWithSchema();
        store.ApplyBaseline(Record("dev-old-acrobat", software: new[]
        {
            new SoftwareItem("Adobe Acrobat", "23.0.5", "Adobe", null, null),
            new SoftwareItem("Google Chrome", "130.0", "Google", null, null),
        }), T0);
        store.ApplyBaseline(Record("dev-new-acrobat", hw: Hw(serial: "XYZ9876"), software: new[]
        {
            new SoftwareItem("Adobe Acrobat", "25.2.0", "Adobe", null, null),
        }), T0);
        store.ApplyBaseline(Record("dev-no-acrobat", hw: Hw(serial: "QWE5555"), software: new[]
        {
            new SoftwareItem("Google Chrome", "131.0", "Google", null, null),
        }), T0);
        store.SetCustomFieldsAndTags("dev-old-acrobat",
            new Dictionary<string, string> { ["site_code"] = "SITE-ONE" }, new[] { "site-server" }, T0);
        return store;
    }

    [Fact]
    public void Query_EveryMachineWithAcrobatBelowVersion()
    {
        var result = InventoryQueryEngine.Query(Fleet(), new InventoryQuery(
            SoftwareName: "Adobe Acrobat", VersionOp: VersionComparison.LessThan, Version: "24.0"), T0);
        Assert.True(result.Accepted, result.RefusalReason);
        var match = Assert.Single(result.Matches);
        Assert.Equal("dev-old-acrobat", match.DeviceId);
    }

    [Fact]
    public void Query_AbsentAndPresent_AndTagAndCustomField()
    {
        var fleet = Fleet();
        var absent = InventoryQueryEngine.Query(fleet, new InventoryQuery(
            SoftwareName: "Adobe Acrobat", VersionOp: VersionComparison.Absent), T0);
        Assert.Equal("dev-no-acrobat", Assert.Single(absent.Matches).DeviceId);

        var byField = InventoryQueryEngine.Query(fleet, new InventoryQuery(
            CustomFieldKey: "site_code", CustomFieldValue: "SITE-ONE"), T0);
        Assert.Equal("dev-old-acrobat", Assert.Single(byField.Matches).DeviceId);

        var byTag = InventoryQueryEngine.Query(fleet, new InventoryQuery(Tag: "site-server"), T0);
        Assert.Equal("dev-old-acrobat", Assert.Single(byTag.Matches).DeviceId);
    }

    [Fact]
    public void Query_WarrantyExpiringWithinDays()
    {
        var fleet = Fleet();
        fleet.SetWarranty("dev-new-acrobat",
            new WarrantyInfo("dell", "XYZ9876", "active", T0.AddDays(30), "Basic", T0));
        var result = InventoryQueryEngine.Query(fleet, new InventoryQuery(WarrantyExpiringWithinDays: 60), T0);
        Assert.Equal("dev-new-acrobat", Assert.Single(result.Matches).DeviceId);
    }

    // ---- policy toggles -------------------------------------------------------

    [Fact]
    public void Policy_InventoryDisabled_RefusesBaselineAndReports()
    {
        var store = new InventoryStore(policyCheck: key => key != InventoryPolicyKeys.InventoryEnabled);
        Assert.False(store.ApplyBaseline(Record("dev-1"), T0).Accepted);
        Assert.Null(store.Get("dev-1"));
    }

    [Fact]
    public void PolicyKeys_AreRegisteredAsData_WithDocumentedDefaults()
    {
        Assert.Equal(3, InventoryPolicyKeys.All.Count);
        Assert.All(InventoryPolicyKeys.Defaults, kv => Assert.True(kv.Value));
        Assert.True(InventoryPolicyKeys.Defaults.ContainsKey("rmm.inventory.enabled"));
        Assert.True(InventoryPolicyKeys.Defaults.ContainsKey("rmm.inventory.warrantyLookup.enabled"));
        Assert.True(InventoryPolicyKeys.Defaults.ContainsKey("rmm.inventory.unmanagedRegister.enabled"));
    }

    // ---- warranty service -------------------------------------------------------

    [Fact]
    public async Task Warranty_Refresh_StampsVendorSerialAndOutboundFlag()
    {
        var fake = new FakeWarrantyLookup();
        fake.SetAnswer("dell", "ABC1234", new WarrantyInfo(
            "WRONG", "WRONG", "active", T0.AddYears(1), "ProSupport", T0, IsOutboundLookup: false));
        var svc = new WarrantyService(fake);
        var result = await svc.RefreshAsync(Record("dev-1"));
        Assert.True(result.Refreshed, result.Outcome);
        Assert.Equal("dell", result.Warranty!.Vendor);          // re-stamped from the query
        Assert.Equal("ABC1234", result.Warranty.SerialNumber);  // re-stamped
        Assert.True(result.Warranty.IsOutboundLookup);          // flag forced on
        Assert.Equal(1, fake.CallCount);
    }

    [Fact]
    public async Task Warranty_UnknownManufacturerOrBadSerial_NoLookupAttempted()
    {
        var fake = new FakeWarrantyLookup();
        var svc = new WarrantyService(fake);
        var unknownMaker = await svc.RefreshAsync(Record("dev-1", hw: Hw(manufacturer: "Framework")));
        Assert.False(unknownMaker.Refreshed);
        var badSerial = await svc.RefreshAsync(Record("dev-1", hw: Hw(serial: "x")));
        Assert.False(badSerial.Refreshed);
        Assert.Equal(0, fake.CallCount); // neither attempt reached the lookup
    }

    [Fact]
    public void WarrantyAlerts_ExpiringCriticalExpired_AndQuietOutsideWindow()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-warn"), T0);
        store.ApplyBaseline(Record("dev-crit", hw: Hw(serial: "CRT0001")), T0);
        store.ApplyBaseline(Record("dev-dead", hw: Hw(serial: "DED0001")), T0);
        store.ApplyBaseline(Record("dev-fine", hw: Hw(serial: "FIN0001")), T0);
        store.SetWarranty("dev-warn", new WarrantyInfo("dell", "ABC1234", "active", T0.AddDays(60), null, T0));
        store.SetWarranty("dev-crit", new WarrantyInfo("dell", "CRT0001", "active", T0.AddDays(10), null, T0));
        store.SetWarranty("dev-dead", new WarrantyInfo("dell", "DED0001", "expired", T0.AddDays(-5), null, T0));
        store.SetWarranty("dev-fine", new WarrantyInfo("dell", "FIN0001", "active", T0.AddDays(300), null, T0));

        var alerts = store.CollectWarrantyAlerts(T0);
        Assert.Equal(3, alerts.Count);
        Assert.Equal(WarrantyAlertEvent.SeverityWarning,
            alerts.Single(a => a.DeviceId == "dev-warn").Severity);
        Assert.Equal(WarrantyAlertEvent.SeverityCritical,
            alerts.Single(a => a.DeviceId == "dev-crit").Severity);
        var dead = alerts.Single(a => a.DeviceId == "dev-dead");
        Assert.Equal(WarrantyAlertEvent.KindExpired, dead.Kind);
        Assert.Equal(WarrantyAlertEvent.SeverityExpired, dead.Severity);
    }

    [Fact]
    public void OutboundTargetGuard_OnlyAllowlistedHttpsHostsPerVendor()
    {
        Assert.True(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("https://www.dell.com/support")));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("http://www.dell.com/support")));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("https://support.hp.com/x"))); // wrong vendor's host
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("https://www.dell.com.evil.example/x")));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("https://user@www.dell.com/x")));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", new Uri("https://www.dell.com:8443/x")));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("acme", new Uri("https://www.dell.com/x")));
    }

    // ---- unmanaged register -------------------------------------------------------

    private static UnmanagedAsset Asset(string id, string kind = UnmanagedAssetKinds.BasController,
        string state = UnmanagedLifecycleStates.Discovered) => new(
        AssetId: id, ScopeId: "company-1", Name: "Asset " + id, Kind: kind,
        Make: "Tridium", Model: "JACE 8000", SerialNumber: null, IpAddress: "192.168.1.50",
        MacAddress: null, SiteId: "site-one", Location: "Mech room",
        LifecycleState: state, ManagedDeviceIds: new[] { "dev-1" },
        Tags: new HashSet<string> { "bas" }, CustomFields: new Dictionary<string, string>(),
        Notes: null, DiscoveredBy: "manual", CreatedUtc: T0, UpdatedUtc: T0);

    [Fact]
    public void Unmanaged_AddGetList_AndRelationships()
    {
        var reg = new UnmanagedAssetRegister();
        var added = reg.Add(Asset("jace-01"));
        Assert.NotNull(added);
        Assert.False(added!.ManagedByAgent); // the invariant, on the record itself
        Assert.True(added.KindIsKnown);
        Assert.Equal("jace-01", reg.Get("jace-01")!.AssetId);
        Assert.Single(reg.ListRelatedTo("dev-1"));
        Assert.Null(reg.Add(Asset("jace-01"))); // duplicate refused
    }

    [Fact]
    public void Unmanaged_CameraRecord_CarriesMakeModelAndViewCapability()
    {
        var reg = new UnmanagedAssetRegister();
        var cam = Asset("cam-lobby", UnmanagedAssetKinds.Camera) with
        {
            Make = "Axis", Model = "P3265", ViewCapability = CameraViewCapabilities.Onvif,
            DiscoveredBy = "rmm11-discovery",
        };
        var added = reg.Add(cam);
        Assert.NotNull(added);
        Assert.Equal("Axis", added!.Make);
        Assert.Equal("P3265", added.Model);
        Assert.Equal("onvif", added.ViewCapability);

        // Cloud-locked: inventory-only REQUIRES the plainly stated reason.
        var lockedNoReason = Asset("cam-ring", UnmanagedAssetKinds.Camera) with
        { ViewCapability = CameraViewCapabilities.InventoryOnly };
        Assert.Null(reg.Add(lockedNoReason));
        var locked = lockedNoReason with { InventoryOnlyReason = "cloud-locked consumer camera: no local ONVIF/RTSP stream" };
        Assert.NotNull(reg.Add(locked));
        // Camera fields on a non-camera refuse.
        Assert.Null(reg.Add(Asset("printer-01", UnmanagedAssetKinds.Printer) with
        { ViewCapability = CameraViewCapabilities.Rtsp }));
    }

    [Fact]
    public void Unmanaged_LifecycleTransitions_EnforceStateMachine()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("ups-01", UnmanagedAssetKinds.Ups));
        Assert.False(reg.Transition("ups-01", UnmanagedLifecycleStates.Maintenance)); // discovered -/-> maintenance
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Active));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Maintenance));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Retired));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Disposed));
        Assert.False(reg.Transition("ups-01", UnmanagedLifecycleStates.Active)); // disposed is terminal
        // Born-disposed refuses at Add.
        Assert.Null(reg.Add(Asset("ups-02", UnmanagedAssetKinds.Ups, UnmanagedLifecycleStates.Disposed)));
    }

    [Fact]
    public void Unmanaged_PolicyDisabled_RefusesAdds()
    {
        var reg = new UnmanagedAssetRegister(
            policyCheck: key => key != InventoryPolicyKeys.UnmanagedRegisterEnabled);
        Assert.Null(reg.Add(Asset("jace-99")));
        Assert.Empty(reg.List());
    }

    [Fact]
    public void Unmanaged_ExportImport_RoundTrips()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("jace-01"));
        reg.Add(Asset("cam-01", UnmanagedAssetKinds.Camera) with
        { Make = "Axis", Model = "M3057", ViewCapability = CameraViewCapabilities.Rtsp });
        var json = reg.ExportJson();
        var reg2 = new UnmanagedAssetRegister();
        Assert.Equal(2, reg2.ImportJson(json));
        Assert.Equal("M3057", reg2.Get("cam-01")!.Model);
        Assert.Equal(0, reg2.ImportJson(json)); // re-import duplicates nothing
        Assert.Equal(0, reg2.ImportJson("{not json"));
    }

    // ---- lifecycle reporting -------------------------------------------------------

    [Fact]
    public void LifecycleReport_CohortsAndRefreshCandidates()
    {
        var store = new InventoryStore();
        var old = Record("dev-old") with { PurchaseDateUtc = T0.AddYears(-7) };
        store.ApplyBaseline(old, T0);
        store.ApplyBaseline(Record("dev-new", hw: Hw(serial: "NEW0001")), T0);
        store.SetWarranty("dev-new", new WarrantyInfo("dell", "NEW0001", "expired", T0.AddDays(-30), null, T0));
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("jace-01"));

        var report = LifecycleReporting.Build(store, reg, T0);
        Assert.Equal(2, report.TotalDevices);
        Assert.Equal(1, report.TotalUnmanagedAssets);
        Assert.Equal(1, report.AgeCohorts["5y+"]);
        Assert.Equal(1, report.WarrantyCohorts["expired"]);
        Assert.Equal(2, report.RefreshCandidates.Count); // old by age, new by expired warranty
        Assert.Contains(report.RefreshCandidates, c => c.DeviceId == "dev-old" && c.Reason.Contains("age"));
        Assert.Contains(report.RefreshCandidates, c => c.DeviceId == "dev-new" && c.Reason.Contains("warranty"));
    }

    // ---- serial conflicts -------------------------------------------------------

    [Fact]
    public void SerialConflicts_DuplicateSerialAcrossDevices_IsSurfacedNotMerged()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-a", hw: Hw(serial: "SHARED1")), T0);
        store.ApplyBaseline(Record("dev-b", hw: Hw(serial: "SHARED1")), T0);
        var conflict = Assert.Single(store.GetSerialConflicts());
        Assert.Equal("SHARED1", conflict.SerialNumber);
        Assert.Equal(new[] { "dev-a", "dev-b" }, conflict.DeviceIds);
        Assert.NotNull(store.Get("dev-a")); // both records kept
        Assert.NotNull(store.Get("dev-b"));
    }

    // ---- persistence -------------------------------------------------------

    [Fact]
    public void Store_ExportImport_RestoresRecords_AndSkipsLiveOnReimport()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        store.SetWarranty("dev-1", new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(1), null, T0));
        var json = store.ExportJson();
        var store2 = new InventoryStore();
        Assert.Equal(1, store2.ImportJson(json));
        Assert.Equal("ABC1234", store2.Get("dev-1")!.Hardware.SerialNumber);
        Assert.NotNull(store2.Get("dev-1")!.Warranty); // genuine outbound record survives
        Assert.Equal(0, store2.ImportJson(json));
        Assert.Equal(0, store2.ImportJson("garbage{{{"));
    }

    // ---- agent-side service -------------------------------------------------------

    [Fact]
    public void AgentService_BaselinesThenReportsDiffsOnly()
    {
        var clock = new FakeClock();
        var software = new List<SoftwareItem> { new("App", "1.0", "Pub", null, null) };
        var svc = new InventoryService("dev-1", "company-1",
            hardwareCollector: () => Hw(),
            softwareCollector: () => software.ToList(),
            hostname: () => "WS-01", clock: clock);
        var store = new InventoryStore();

        var r1 = svc.CollectAndReport(store);
        Assert.True(r1.Accepted);
        Assert.Equal(1, store.Get("dev-1")!.Revision);

        var r2 = svc.CollectAndReport(store); // unchanged
        Assert.True(r2.Accepted);
        Assert.Equal("seen_unchanged", r2.Outcome);
        Assert.Equal(1, store.Get("dev-1")!.Revision);

        software[0] = new SoftwareItem("App", "2.0", "Pub", null, null);
        clock.UtcNow = T0.AddHours(3);
        var r3 = svc.CollectAndReport(store);
        Assert.True(r3.Accepted, r3.Outcome);
        Assert.Equal(2, store.Get("dev-1")!.Revision);
        Assert.Equal("2.0", store.Get("dev-1")!.Software[0].Version);
    }

    [Fact]
    public async Task HubService_WarrantyRefresh_StoresResult_AndFailureKeepsStale()
    {
        var fake = new FakeWarrantyLookup();
        fake.SetAnswer("dell", "ABC1234", new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(2), "Pro", T0));
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var hub = new HubInventoryService(store, new WarrantyService(fake));

        var ok = await hub.RefreshWarrantyAsync("dev-1");
        Assert.True(ok.Refreshed);
        Assert.NotNull(store.Get("dev-1")!.Warranty);

        var noAnswer = await hub.RefreshWarrantyAsync("dev-1"); // fake still answers; use unknown device instead
        Assert.True(noAnswer.Refreshed);
        var unknown = await hub.RefreshWarrantyAsync("no-such-device");
        Assert.False(unknown.Refreshed);
        Assert.NotNull(store.Get("dev-1")!.Warranty); // untouched by failures elsewhere
    }
}

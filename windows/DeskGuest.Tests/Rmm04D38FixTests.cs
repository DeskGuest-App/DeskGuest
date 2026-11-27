using System.Net;
using System.Text.Json;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Inventory;

namespace DeskGuest.Tests;

/// <summary>D38 reconciliation regression tests for RMM-04 (Block R).
/// One or more tests per review finding F1–F12, named
/// D38F&lt;n&gt;_*. Each test pins the FIXED behaviour; several also
/// re-attack the fixed surface (destruction discipline).</summary>
public class Rmm04D38FixTests
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
        IReadOnlyList<SoftwareItem>? software = null, string scope = "company-1") => new(
        DeviceId: deviceId, ScopeId: scope, Hostname: "WS-01",
        Hardware: hw ?? Hw(),
        Software: software ?? new[] { new SoftwareItem("Adobe Acrobat", "24.0.1", "Adobe", null, "winget") },
        CustomFields: new Dictionary<string, string>(),
        Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    private static InventoryStore StoreWithSchema()
    {
        var store = new InventoryStore();
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("site_code", "Site code", "text")));
        return store;
    }

    private static UnmanagedAsset Asset(string id, string kind = UnmanagedAssetKinds.Printer,
        string state = UnmanagedLifecycleStates.Discovered, string? ip = "192.168.1.50") => new(
        AssetId: id, ScopeId: "company-1", Name: "Asset " + id, Kind: kind,
        Make: "HP", Model: "LaserJet", SerialNumber: null, IpAddress: ip,
        MacAddress: null, SiteId: "site-1", Location: "Mech room",
        LifecycleState: state, ManagedDeviceIds: Array.Empty<string>(),
        Tags: new HashSet<string>(), CustomFields: new Dictionary<string, string>(),
        Notes: null, DiscoveredBy: "manual", CreatedUtc: T0, UpdatedUtc: T0);

    // ---- F1: admin edits cannot deadlock or be erased ---------------

    [Fact]
    public void D38F1_AdminEdit_DoesNotBumpDeviceRevision_AndAgentKeepsReporting()
    {
        var store = StoreWithSchema();
        var software = new List<SoftwareItem> { new("App", "1.0", "Pub", null, null) };
        var svc = new InventoryService("dev-1", "company-1",
            hardwareCollector: () => Hw(), softwareCollector: () => software.ToList(),
            hostname: () => "WS-01", clock: new FakeClock());
        Assert.True(svc.CollectAndReport(store).Accepted);
        Assert.Equal(1, store.Get("dev-1")!.Revision);

        Assert.True(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["site_code"] = "X" }, new[] { "t" }, T0.AddHours(1)));
        Assert.Equal(1, store.Get("dev-1")!.Revision); // admin domain: no device-revision bump

        software[0] = new SoftwareItem("App", "2.0", "Pub", null, null);
        var r = svc.CollectAndReport(store);
        Assert.True(r.Accepted, r.Outcome); // previously: permanent stale-refusal deadlock
        Assert.Equal(2, store.Get("dev-1")!.Revision);
        Assert.Equal("X", store.Get("dev-1")!.CustomFields["site_code"]); // not erased
        Assert.Contains("t", store.Get("dev-1")!.Tags);
    }

    [Fact]
    public void D38F1_SnapshotWithEmptyAdminFields_DoesNotEraseAdminMetadata()
    {
        var store = StoreWithSchema();
        store.ApplyBaseline(Record("dev-1"), T0);
        store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["site_code"] = "SITE-ONE" }, new[] { "site-server" }, T0);
        var stored = store.Get("dev-1")!;
        // Snapshot as a resynced agent with adminFields=null would send:
        var next = Record("dev-1", hw: Hw(ram: 32_000_000_000));
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(1)).Accepted);
        Assert.Equal("SITE-ONE", store.Get("dev-1")!.CustomFields["site_code"]);
        Assert.Contains("site-server", store.Get("dev-1")!.Tags);
    }

    [Fact]
    public void D38F1_Reattack_ForgedDiffClaimingAdminFieldChange_Refused()
    {
        var store = StoreWithSchema();
        store.ApplyBaseline(Record("dev-1"), T0);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", hw: Hw(ram: 32_000_000_000));
        var real = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        var forged = real with
        {
            CustomFieldChanges = new[] { new CustomFieldChange("site_code", null, "hacked") },
        };
        Assert.False(store.ApplyChangeReport(new InventoryChangeReport(forged, next), T0.AddHours(1)).Accepted);
        Assert.False(store.Get("dev-1")!.CustomFields.ContainsKey("site_code"));
    }

    // ---- F2: one canonical normalization point ------------------------

    [Fact]
    public void D38F2_AgentWithUnnormalizedCollectorOutput_ReportsEveryCycle()
    {
        var store = new InventoryStore();
        var software = new List<SoftwareItem>
        {
            new("App", "1.0", "Pub", null, null),
            new("App", "2.0", "Pub", null, null), // duplicate uninstall entries
        };
        var svc = new InventoryService("dev-1", "company-1",
            hardwareCollector: () => Hw(serial: "abc1234"), // lowercase serial
            softwareCollector: () => software.ToList(),
            hostname: () => "  WS-01  ", // padded hostname
            adminFields: () => (new Dictionary<string, string>(), new HashSet<string> { "SITE-SERVER" }),
            clock: new FakeClock());
        var r1 = svc.CollectAndReport(store);
        Assert.True(r1.Accepted, r1.Outcome);
        Assert.Equal("ABC1234", store.Get("dev-1")!.Hardware.SerialNumber);
        Assert.Equal("WS-01", store.Get("dev-1")!.Hostname);
        Assert.Contains("site-server", store.Get("dev-1")!.Tags);

        var r2 = svc.CollectAndReport(store); // previously: "diff spoofing" forever
        Assert.True(r2.Accepted, r2.Outcome);
        Assert.Equal("seen_unchanged", r2.Outcome);

        software[1] = new SoftwareItem("App", "3.0", "Pub", null, null);
        var r3 = svc.CollectAndReport(store);
        Assert.True(r3.Accepted, r3.Outcome);
        Assert.Equal(2, store.Get("dev-1")!.Revision);
    }

    [Fact]
    public void D38F2_Normalizer_IsIdempotent()
    {
        var raw = Record("dev-1", hw: Hw(serial: "abc1234")) with
        {
            Hostname = "  WS-01 ",
            Tags = new HashSet<string> { "UPPER" },
        };
        var once = InventoryNormalizer.Normalize(raw).Record;
        var twice = InventoryNormalizer.Normalize(once).Record;
        Assert.Equal(once.Hardware.SerialNumber, twice.Hardware.SerialNumber);
        Assert.Equal(once.Hostname, twice.Hostname);
        Assert.Equal(once.Software, twice.Software);
        Assert.Equal(once.Tags.OrderBy(t => t), twice.Tags.OrderBy(t => t));
    }

    // ---- F3: fields outside the diff are hub-pinned / diff-covered ----

    [Fact]
    public void D38F3_DeviceCannotMoveScopeOrBackdatePurchase_BehindCheckedDiff()
    {
        var store = new InventoryStore();
        var baseline = Record("dev-1") with { PurchaseDateUtc = T0.AddYears(-1) };
        store.ApplyBaseline(baseline, T0);
        var stored = store.Get("dev-1")!;
        var evil = Record("dev-1", hw: Hw(ram: 32_000_000_000), scope: "company-2") with
        { PurchaseDateUtc = T0.AddYears(-9) };
        var diff = InventoryDiffer.Compute(stored, evil, stored.Revision, T0.AddHours(1));
        var result = store.ApplyChangeReport(new InventoryChangeReport(diff, evil), T0.AddHours(1));
        Assert.True(result.Accepted, result.Outcome); // the ram change itself is legitimate
        Assert.Equal("company-1", store.Get("dev-1")!.ScopeId); // pinned
        Assert.Equal(T0.AddYears(-1), store.Get("dev-1")!.PurchaseDateUtc); // pinned
        Assert.Empty(store.List("company-2"));
        Assert.Single(store.List("company-1"));
    }

    [Fact]
    public void D38F3_DiskInterfaceAndSoftwareSourceChanges_AreDiffCovered()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        var stored = store.Get("dev-1")!;
        var hw2 = Hw() with
        {
            Disks = new[] { new DiskInfo("C:", "Samsung SSD 990", "DISK001", 512_000_000_000, "SATA", "SSD") },
        };
        var next = Record("dev-1", hw: hw2);
        // A forged empty diff hiding the interface change refuses…
        var forgedEmpty = new InventoryDiff("dev-1", stored.Revision, T0.AddHours(1),
            Array.Empty<SoftwareItem>(), Array.Empty<string>(), Array.Empty<SoftwareChange>(),
            Array.Empty<string>(), Array.Empty<CustomFieldChange>(), Array.Empty<string>(),
            Array.Empty<string>(), HostnameChanged: false);
        Assert.False(store.ApplyChangeReport(new InventoryChangeReport(forgedEmpty, next), T0.AddHours(1)).Accepted);
        // …and the honest diff (which now names it) applies.
        var honest = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.Contains(honest.HardwareChanges, c => c.StartsWith("disk_"));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(honest, next), T0.AddHours(1)).Accepted);

        var stored2 = store.Get("dev-1")!;
        var next2 = Record("dev-1", hw: hw2, software: new[]
        { new SoftwareItem("Adobe Acrobat", "24.0.1", "Adobe", null, "msi") }); // Source winget->msi
        var diff2 = InventoryDiffer.Compute(stored2, next2, stored2.Revision, T0.AddHours(2));
        Assert.Single(diff2.ChangedSoftware);
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff2, next2), T0.AddHours(2)).Accepted);
    }

    // ---- F5: warranty write paths --------------------------------------

    [Fact]
    public void D38F5_SetWarranty_MismatchedSerialUnknownVendorBadStatusUnflagged_AllRefused()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.False(store.SetWarranty("dev-1",
            new WarrantyInfo("dell", "ZZZ9999", "active", T0.AddYears(9), "X", T0, IsOutboundLookup: true)));
        Assert.False(store.SetWarranty("dev-1",
            new WarrantyInfo("acme", "ABC1234", "active", T0.AddYears(1), null, T0)));
        Assert.False(store.SetWarranty("dev-1",
            new WarrantyInfo("dell", "ABC1234", "gold-tier", T0.AddYears(1), null, T0)));
        Assert.False(store.SetWarranty("dev-1",
            new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(1), null, T0, IsOutboundLookup: false)));
        Assert.Null(store.Get("dev-1")!.Warranty);
        Assert.True(store.SetWarranty("dev-1",
            new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(1), null, T0)));
        Assert.NotNull(store.Get("dev-1")!.Warranty);
    }

    [Fact]
    public void D38F5_Import_FlaggedButMismatchedWarranty_DroppedNotHonored()
    {
        var planted = new DeviceInventoryRecord(
            "dev-x", "company-1", "WS", Hw(serial: "AAA1111"), Array.Empty<SoftwareItem>(),
            new Dictionary<string, string>(), new HashSet<string>(), T0, T0, T0, 3,
            Warranty: new WarrantyInfo("dell", "ZZZ9999", "active", T0.AddYears(99), "Planted", T0,
                IsOutboundLookup: true));
        var json = JsonSerializer.Serialize(new[] { planted });
        var store = new InventoryStore();
        Assert.Equal(1, store.ImportJson(json)); // the record restores…
        Assert.Null(store.Get("dev-x")!.Warranty); // …the planted warranty does not
        Assert.Empty(store.CollectWarrantyAlerts(T0)); // and suppresses no expiry alert
    }

    [Fact]
    public void D38F5_SerialChange_ClearsWarrantyFromOldSerial()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.True(store.SetWarranty("dev-1",
            new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(2), null, T0)));
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", hw: Hw(serial: "SER9999"));
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff, next), T0.AddHours(1)).Accepted);
        Assert.Equal("SER9999", store.Get("dev-1")!.Hardware.SerialNumber);
        Assert.Null(store.Get("dev-1")!.Warranty); // old serial's warranty detached
    }

    [Fact]
    public void D38F5_SerialConflicts_ExposedAsAlertEventsForRmm01()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-a", hw: Hw(serial: "SHARED1")), T0);
        store.ApplyBaseline(Record("dev-b", hw: Hw(serial: "SHARED1")), T0);
        var ev = Assert.Single(store.CollectSerialConflictAlerts(T0));
        Assert.Equal(SerialConflictAlertEvent.KindSerialConflict, ev.Kind);
        Assert.Equal("SHARED1", ev.SerialNumber);
        Assert.Equal(new[] { "dev-a", "dev-b" }, ev.DeviceIds);
    }

    // ---- F6: hardware validation + fail-fast bounds ---------------------

    [Fact]
    public void D38F6_NullOrOversizeHardwareFields_RefuseTheRecord()
    {
        var store = new InventoryStore();
        var nullBuild = Hw() with { OsBuild = null! };
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: nullBuild), T0).Accepted);
        var nullMaker = Hw() with { Manufacturer = null! };
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: nullMaker), T0).Accepted);
        var hugeMaker = Hw(manufacturer: new string('M', InventoryLimits.MaxHardwareStringLength + 1));
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: hugeMaker), T0).Accepted);
        var nullDisk = Hw() with { Disks = new DiskInfo[] { null! } };
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: nullDisk), T0).Accepted);
        var nullPeripheral = Hw() with { Peripherals = new PeripheralInfo[] { null! } };
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: nullPeripheral), T0).Accepted);
        Assert.Null(store.Get("dev-1"));
        // …and a clean record still flows + reports without crashing.
        Assert.True(store.ApplyBaseline(Record("dev-1"), T0).Accepted);
        var report = LifecycleReporting.Build(store, null, T0);
        Assert.Equal(1, report.TotalDevices);
    }

    [Fact]
    public void D38F6_RawListsBeyondFailFastWall_RefusedBeforeWork()
    {
        var store = new InventoryStore();
        var hugeSoftware = Enumerable.Range(0, InventoryLimits.RawSoftwareFailFast + 1)
            .Select(i => new SoftwareItem($"App-{i}", "1.0", null, null, null)).ToList();
        Assert.False(store.ApplyBaseline(Record("dev-1", software: hugeSoftware), T0).Accepted);
        var hugeTags = Record("dev-1") with
        {
            Tags = Enumerable.Range(0, InventoryLimits.RawTagsFailFast + 1)
                .Select(i => $"tag-{i}").ToHashSet(),
        };
        Assert.False(store.ApplyBaseline(hugeTags, T0).Accepted);
        Assert.Null(store.Get("dev-1"));
    }

    // ---- F7: drop-vs-refuse honesty --------------------------------------

    [Fact]
    public void D38F7_SideBySideInstalls_BothKept_AndVulnerableCopyQueryable()
    {
        var store = new InventoryStore();
        var sw = new[]
        {
            new SoftwareItem("Adobe Acrobat", "23.0.5", "Adobe", null, "x86"),
            new SoftwareItem("Adobe Acrobat", "25.2.0", "Adobe", null, "x64"),
        };
        Assert.True(store.ApplyBaseline(Record("dev-1", software: sw), T0).Accepted);
        Assert.Equal(2, store.Get("dev-1")!.Software.Count); // previously: only 25.2.0 survived
        var result = InventoryQueryEngine.Query(store, new InventoryQuery(
            SoftwareName: "Adobe Acrobat", VersionOp: VersionComparison.LessThan, Version: "24.0"), T0);
        Assert.True(result.Accepted, result.RefusalReason);
        Assert.Single(result.Matches); // the vulnerable 32-bit install is visible
    }

    [Fact]
    public void D38F7_OversizeVersionItem_KeptAsUnknownVersion_AndAccountingPersisted()
    {
        var store = new InventoryStore();
        var sw = new[]
        {
            new SoftwareItem("LongVer App", new string('9', 100), "Pub", null, null),
            new SoftwareItem("Bad\nName", "1.0", null, null, null),
            new SoftwareItem("Good App", "1.0", "Pub", null, null),
        };
        var result = store.ApplyBaseline(Record("dev-1", software: sw), T0);
        Assert.True(result.Accepted, result.Outcome);
        var stored = store.Get("dev-1")!;
        var longVer = Assert.Single(stored.Software, s => s.Name == "LongVer App");
        Assert.Equal("", longVer.Version); // kept, version marked unknown — not vanished
        Assert.Equal(1, stored.UnknownVersionSoftwareCount);
        Assert.Equal(1, stored.DroppedSoftwareCount);
        var present = InventoryQueryEngine.Query(store, new InventoryQuery(
            SoftwareName: "LongVer App", VersionOp: VersionComparison.Present), T0);
        Assert.Single(present.Matches);
        // Persisted accounting survives export/import.
        var store2 = new InventoryStore();
        Assert.Equal(1, store2.ImportJson(store.ExportJson()));
        Assert.Equal(1, store2.Get("dev-1")!.DroppedSoftwareCount);
        Assert.Equal(1, store2.Get("dev-1")!.UnknownVersionSoftwareCount);
    }

    // ---- F8: disposed unmanaged assets survive export/import --------------

    [Fact]
    public void D38F8_DisposedAsset_RoundTripsThroughExportImport()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("ups-01", UnmanagedAssetKinds.Ups));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Active));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Retired));
        Assert.True(reg.Transition("ups-01", UnmanagedLifecycleStates.Disposed));
        var reg2 = new UnmanagedAssetRegister();
        Assert.Equal(1, reg2.ImportJson(reg.ExportJson())); // previously: 0 — history dropped
        Assert.Equal(UnmanagedLifecycleStates.Disposed, reg2.Get("ups-01")!.LifecycleState);
        // Add still refuses a born-disposed asset (creation rule intact).
        Assert.Null(reg2.Add(Asset("ups-02", UnmanagedAssetKinds.Ups, UnmanagedLifecycleStates.Disposed)));
    }

    [Fact]
    public void D38F8_AllLifecycleStates_RoundTrip()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("a-disc"));
        reg.Add(Asset("a-act")); reg.Transition("a-act", UnmanagedLifecycleStates.Active);
        reg.Add(Asset("a-mnt")); reg.Transition("a-mnt", UnmanagedLifecycleStates.Active);
        reg.Transition("a-mnt", UnmanagedLifecycleStates.Maintenance);
        reg.Add(Asset("a-ret")); reg.Transition("a-ret", UnmanagedLifecycleStates.Active);
        reg.Transition("a-ret", UnmanagedLifecycleStates.Retired);
        reg.Add(Asset("a-dis")); reg.Transition("a-dis", UnmanagedLifecycleStates.Disposed);
        var reg2 = new UnmanagedAssetRegister();
        Assert.Equal(5, reg2.ImportJson(reg.ExportJson()));
        Assert.Equal(UnmanagedLifecycleStates.Discovered, reg2.Get("a-disc")!.LifecycleState);
        Assert.Equal(UnmanagedLifecycleStates.Active, reg2.Get("a-act")!.LifecycleState);
        Assert.Equal(UnmanagedLifecycleStates.Maintenance, reg2.Get("a-mnt")!.LifecycleState);
        Assert.Equal(UnmanagedLifecycleStates.Retired, reg2.Get("a-ret")!.LifecycleState);
        Assert.Equal(UnmanagedLifecycleStates.Disposed, reg2.Get("a-dis")!.LifecycleState);
    }

    // ---- F9: camera / unmanaged field bounds -------------------------------

    [Fact]
    public void D38F9_CameraAddressAndCapabilityInvariants()
    {
        var reg = new UnmanagedAssetRegister();
        var cam = Asset("cam-1", UnmanagedAssetKinds.Camera) with { ViewCapability = CameraViewCapabilities.Onvif };
        Assert.NotNull(reg.Add(cam)); // RFC1918 viewable camera: legitimate
        // SSRF-shaped registrations refuse:
        Assert.Null(reg.Add(cam with { AssetId = "cam-meta", IpAddress = "169.254.169.254" }));
        Assert.Null(reg.Add(cam with { AssetId = "cam-loop", IpAddress = "127.0.0.1" }));
        Assert.Null(reg.Add(cam with { AssetId = "cam-bad", IpAddress = "not-an-ip" }));
        // Capability is REQUIRED on cameras:
        Assert.Null(reg.Add(Asset("cam-none", UnmanagedAssetKinds.Camera)));
        // A reason alongside a viewable capability is self-contradictory:
        Assert.Null(reg.Add(cam with
        { AssetId = "cam-contra", InventoryOnlyReason = "cloud-locked" }));
        // Inventory-only with a stated reason is the honest shape:
        Assert.NotNull(reg.Add(Asset("cam-locked", UnmanagedAssetKinds.Camera) with
        {
            ViewCapability = CameraViewCapabilities.InventoryOnly,
            InventoryOnlyReason = "cloud-locked consumer camera",
        }));
    }

    [Fact]
    public void D38F9_MacAndTextBounds_EnforcedAndMacNormalized()
    {
        var reg = new UnmanagedAssetRegister();
        Assert.Null(reg.Add(Asset("p-1") with { MacAddress = "zz:zz:zz:zz:zz:zz" }));
        Assert.Null(reg.Add(Asset("p-1") with { Notes = new string('n', 2000) }));
        Assert.Null(reg.Add(Asset("p-1") with { Make = "bad\nmake" }));
        var ok = reg.Add(Asset("p-1") with { MacAddress = "aa-bb-cc-dd-ee-ff" });
        Assert.NotNull(ok);
        Assert.Equal("AA:BB:CC:DD:EE:FF", ok!.MacAddress);
    }

    // ---- F10: malformed queries refuse, never widen -------------------------

    [Fact]
    public void D38F10_OrphanAndEmptyCriteria_RefuseNeverWiden()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.False(InventoryQueryEngine.Query(store, new InventoryQuery(
            CustomFieldValue: "SITE-ONE"), T0).Accepted); // value without key
        Assert.False(InventoryQueryEngine.Query(store, new InventoryQuery(
            SoftwareName: "Adobe Acrobat", Version: "24.0"), T0).Accepted); // version without op
        Assert.False(InventoryQueryEngine.Query(store, new InventoryQuery(
            Manufacturer: ""), T0).Accepted); // "" previously matched everything
        Assert.False(InventoryQueryEngine.Query(store, new InventoryQuery(
            Manufacturer: "   "), T0).Accepted);
        Assert.False(InventoryQueryEngine.Query(store, new InventoryQuery(
            OsBuild: ""), T0).Accepted);
        // A well-formed query still works.
        Assert.True(InventoryQueryEngine.Query(store, new InventoryQuery(
            Manufacturer: "Dell"), T0).Accepted);
    }

    // ---- F11: SSRF guard contract -------------------------------------------

    [Fact]
    public void D38F11_RelativeUri_ReturnsFalseNeverThrows()
    {
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell",
            new Uri("/support", UriKind.Relative)));
        Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell",
            new Uri("support/page", UriKind.RelativeOrAbsolute)));
    }

    [Fact]
    public void D38F11_ResolvedAddresses_PrivateOrLoopbackAnswersRefused()
    {
        Assert.True(OemWarrantyEndpoints.ValidateResolvedAddresses(
            new[] { IPAddress.Parse("93.184.216.34") }));
        Assert.False(OemWarrantyEndpoints.ValidateResolvedAddresses(
            new[] { IPAddress.Parse("10.0.0.5") }));
        Assert.False(OemWarrantyEndpoints.ValidateResolvedAddresses(
            new[] { IPAddress.Parse("93.184.216.34"), IPAddress.Parse("169.254.169.254") }));
        Assert.False(OemWarrantyEndpoints.ValidateResolvedAddresses(
            new[] { IPAddress.Loopback }));
        Assert.False(OemWarrantyEndpoints.ValidateResolvedAddresses(Array.Empty<IPAddress>()));
        Assert.False(OemWarrantyEndpoints.ValidateResolvedAddresses(null));
    }

    // ---- F12: register gaps ---------------------------------------------------

    [Fact]
    public void D38F12_DefaultCheck_ReadsDefaults_UnknownKeysRefused()
    {
        Assert.True(InventoryPolicyKeys.DefaultCheck(InventoryPolicyKeys.InventoryEnabled));
        Assert.True(InventoryPolicyKeys.DefaultCheck(InventoryPolicyKeys.WarrantyLookupEnabled));
        Assert.False(InventoryPolicyKeys.DefaultCheck("rmm.inventory.no-such-key"));
        Assert.False(InventoryPolicyKeys.DefaultCheck(""));
    }

    [Fact]
    public void D38F12_ManagedCollision_CaseSensitivePredicateStillCatches()
    {
        // Enrollment lookup that only matches the ORIGINAL case:
        var reg = new UnmanagedAssetRegister(isManagedDeviceId: id => id == "PC-01");
        Assert.True(reg.ManagedCheckWired);
        Assert.Null(reg.Add(Asset("PC-01"))); // previously: predicate got "pc-01" and missed
        Assert.NotNull(reg.Add(Asset("printer-01")));
        var unwired = new UnmanagedAssetRegister();
        Assert.False(unwired.ManagedCheckWired); // honestly surfaced, not silent
    }

    [Fact]
    public void D38F12_RegisterSchema_DuplicatesAndInvalidDefs_NeverThrow()
    {
        var reg = new UnmanagedAssetRegister(customFieldSchema: new[]
        {
            new CustomFieldDefinition("site_code", "Site", "text"),
            new CustomFieldDefinition("site_code", "Site", "number"), // conflicting duplicate: skipped
            new CustomFieldDefinition("bad key!", "Bad", "text"),     // invalid: skipped
            new CustomFieldDefinition("kind_e", "E", "enum"),         // enum without values: skipped
        });
        var withField = Asset("p-9") with
        {
            CustomFields = new Dictionary<string, string> { ["site_code"] = "SITE-ONE" },
        };
        Assert.NotNull(reg.Add(withField)); // first (text) definition governs
    }

    [Fact]
    public void D38F12_EventLog_IsBounded()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("ups-ev", UnmanagedAssetKinds.Ups));
        reg.Transition("ups-ev", UnmanagedLifecycleStates.Active);
        for (var i = 0; i < UnmanagedAssetRegister.MaxEvents + 10; i++)
        {
            reg.Transition("ups-ev", UnmanagedLifecycleStates.Maintenance);
            reg.Transition("ups-ev", UnmanagedLifecycleStates.Active);
        }
        Assert.True(reg.Events.Count <= UnmanagedAssetRegister.MaxEvents,
            $"events={reg.Events.Count}");
    }

    // ---- Re-attack: fixes must not open new holes ------------------------------

    [Fact]
    public void D38Reattack_ResyncPath_CannotForceBaselineOrOverwrite()
    {
        // The service resync retries ONCE against the stored record;
        // a second baseline is still refused and a replayed report
        // still refuses (the resync recomputes, it never forces).
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.False(store.ApplyBaseline(Record("dev-1"), T0).Accepted);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", software: new[] { new SoftwareItem("App", "2.0", null, null, null) });
        var report = new InventoryChangeReport(
            InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1)), next);
        Assert.True(store.ApplyChangeReport(report, T0.AddHours(1)).Accepted);
        Assert.False(store.ApplyChangeReport(report, T0.AddHours(2)).Accepted); // replay still dead
        Assert.Equal(2, store.Get("dev-1")!.Revision);
    }
}

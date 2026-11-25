using System.Text.Json;
using Acp.Shared.Inventory;

namespace Acp.Tests;

/// <summary>RMM-04 destruction pass: forged/duplicate serials, diff
/// spoofing + replay, custom-field injection into queries, unmanaged
/// records claiming managed status, warranty-lookup redirect/SSRF
/// shapes, huge/poisoned software lists. Every attack either holds
/// against the shipped check or names the fix it forced (ledger
/// DG-R04-* in the lane's ledger file).</summary>
public class Rmm04DestructionTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-11-21T12:00:00Z");

    private static HardwareSnapshot Hw(string? serial = "ABC1234", string manufacturer = "Dell Inc.") => new(
        Manufacturer: manufacturer, Model: "OptiPlex 7010", SerialNumber: serial,
        CpuModel: "Intel i7", CpuCores: 8, RamBytes: 16_000_000_000,
        OsName: "Windows 11", OsBuild: "26100.1", OsVersion: "10.0",
        BiosVersion: null, Disks: Array.Empty<DiskInfo>(), Peripherals: Array.Empty<PeripheralInfo>(),
        CollectedUtc: T0);

    private static DeviceInventoryRecord Record(string deviceId, HardwareSnapshot? hw = null,
        IReadOnlyList<SoftwareItem>? software = null) => new(
        DeviceId: deviceId, ScopeId: "company-1", Hostname: "WS",
        Hardware: hw ?? Hw(),
        Software: software ?? Array.Empty<SoftwareItem>(),
        CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    private static UnmanagedAsset Asset(string id) => new(
        AssetId: id, ScopeId: "company-1", Name: "A", Kind: UnmanagedAssetKinds.Printer,
        Make: "HP", Model: "LaserJet", SerialNumber: null, IpAddress: null, MacAddress: null,
        SiteId: null, Location: null, LifecycleState: UnmanagedLifecycleStates.Active,
        ManagedDeviceIds: Array.Empty<string>(), Tags: new HashSet<string>(),
        CustomFields: new Dictionary<string, string>(), Notes: null, DiscoveredBy: "manual",
        CreatedUtc: T0, UpdatedUtc: T0);

    // ---- DG-R04-01: diff spoofing --------------------------------------
    // A forged diff claims "nothing changed" while its own snapshot
    // swaps the software list. The hub recomputes the diff from
    // (stored, snapshot) and refuses on mismatch.

    [Fact]
    public void Attack_ForgedDiff_ClaimsNoChangeWhileSnapshotSwapsSoftware_Refused()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1", software: new[] { new SoftwareItem("Good", "1.0", null, null, null) }), T0);
        var stored = store.Get("dev-1")!;
        var evilSnapshot = Record("dev-1", software: new[] { new SoftwareItem("Evil", "9.9", null, null, null) });
        var forgedEmptyDiff = new InventoryDiff("dev-1", stored.Revision, T0.AddHours(1),
            Array.Empty<SoftwareItem>(), Array.Empty<string>(), Array.Empty<SoftwareChange>(),
            Array.Empty<string>(), Array.Empty<CustomFieldChange>(), Array.Empty<string>(),
            Array.Empty<string>(), HostnameChanged: false);
        var result = store.ApplyChangeReport(new InventoryChangeReport(forgedEmptyDiff, evilSnapshot), T0.AddHours(1));
        Assert.False(result.Accepted);
        Assert.Contains("spoofing", result.Outcome);
        Assert.Equal("Good", store.Get("dev-1")!.Software[0].Name); // stored record untouched
        Assert.Equal(1, store.Get("dev-1")!.Revision);
    }

    [Fact]
    public void Attack_ForgedDiff_UnderstatesAVersionChange_Refused()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1", software: new[] { new SoftwareItem("App", "1.0", null, null, null) }), T0);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", software: new[] { new SoftwareItem("App", "3.0", null, null, null) });
        var realDiff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1));
        // Attacker rewrites the claimed change as 1.0 -> 2.0 (hiding 3.0).
        var forged = realDiff with
        {
            ChangedSoftware = new[] { new SoftwareChange("App", "1.0", "2.0") },
        };
        Assert.False(store.ApplyChangeReport(new InventoryChangeReport(forged, next), T0.AddHours(1)).Accepted);
        Assert.Equal("1.0", store.Get("dev-1")!.Software[0].Version);
    }

    // ---- DG-R04-02: replay ----------------------------------------------
    // The same valid change report delivered twice: the second copy's
    // base revision is stale after the first applied.

    [Fact]
    public void Attack_ReplayedChangeReport_SecondCopyRefused()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1", software: new[] { new SoftwareItem("App", "1.0", null, null, null) }), T0);
        var stored = store.Get("dev-1")!;
        var next = Record("dev-1", software: new[] { new SoftwareItem("App", "2.0", null, null, null) });
        var report = new InventoryChangeReport(
            InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(1)), next);
        Assert.True(store.ApplyChangeReport(report, T0.AddHours(1)).Accepted);
        var replay = store.ApplyChangeReport(report, T0.AddHours(2));
        Assert.False(replay.Accepted);
        Assert.Contains("replayed", replay.Outcome);
        Assert.Equal(2, store.Get("dev-1")!.Revision); // applied exactly once
    }

    // ---- DG-R04-03: forged / duplicate serials ---------------------------

    [Fact]
    public void Attack_PoisonedSerialShapes_RefuseTheRecord()
    {
        var store = new InventoryStore();
        // URL-as-serial (a lookup redirect attempt smuggled as data).
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: Hw(serial: "https://evil.example/x")), T0).Accepted);
        // Path / prose / too short / control characters.
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: Hw(serial: "../../etc/passwd")), T0).Accepted);
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: Hw(serial: "AB")), T0).Accepted);
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: Hw(serial: "ABC\n1234")), T0).Accepted);
        Assert.Null(store.Get("dev-1"));
    }

    [Fact]
    public async Task Attack_SerialIsUrl_NeverReachesTheLookup()
    {
        var fake = new FakeWarrantyLookup();
        var svc = new WarrantyService(fake);
        var result = await svc.RefreshAsync(Record("dev-1", hw: Hw(serial: "https://evil.example/steal")));
        Assert.False(result.Refreshed);
        Assert.Equal(0, fake.CallCount);
        Assert.Null(fake.LastSerial);
    }

    // ---- DG-R04-04: custom-field injection into queries -------------------
    // Queries are structured data — there is no query string. Hostile
    // keys refuse the query outright (never widen to a wildcard), and
    // hostile values simply match nothing.

    [Fact]
    public void Attack_QueryInjectionKeys_RefusedNeverWildcarded()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1"), T0);
        foreach (var hostileKey in new[] { "site_code' OR '1'='1", "*", "", "Site Code", "a b", "key;DROP" })
        {
            var result = InventoryQueryEngine.Query(store,
                new InventoryQuery(CustomFieldKey: hostileKey), T0);
            Assert.False(result.Accepted, $"key '{hostileKey}' must refuse");
            Assert.Empty(result.Matches);
        }
        var hostileTag = InventoryQueryEngine.Query(store, new InventoryQuery(Tag: "*"), T0);
        Assert.False(hostileTag.Accepted);
    }

    [Fact]
    public void Attack_QueryInjectionValue_MatchesNothing()
    {
        var store = new InventoryStore();
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("site_code", "Site", "text")));
        store.ApplyBaseline(Record("dev-1"), T0);
        store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["site_code"] = "SITE-ONE" }, null, T0);
        var result = InventoryQueryEngine.Query(store, new InventoryQuery(
            CustomFieldKey: "site_code", CustomFieldValue: "' OR '1'='1"), T0);
        Assert.True(result.Accepted); // the value is data; it just isn't any device's value
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Attack_CustomFieldValueInjection_ControlCharsAndOversize_Refused()
    {
        var store = new InventoryStore();
        Assert.True(store.DefineCustomField(new CustomFieldDefinition("note", "Note", "text")));
        store.ApplyBaseline(Record("dev-1"), T0);
        Assert.False(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["note"] = "line1\nline2" }, null, T0));
        Assert.False(store.SetCustomFieldsAndTags("dev-1",
            new Dictionary<string, string> { ["note"] = new string('x', InventoryLimits.MaxCustomFieldValueLength + 1) }, null, T0));
    }

    // ---- DG-R04-05: unmanaged assets claiming managed status ---------------

    [Fact]
    public void Attack_UnmanagedAsset_WithManagedDeviceId_CollisionRefused()
    {
        var reg = new UnmanagedAssetRegister(isManagedDeviceId: id => id == "dev-real-1");
        Assert.Null(reg.Add(Asset("dev-real-1"))); // an enrolled device's id cannot be re-registered as unmanaged
        Assert.NotNull(reg.Add(Asset("printer-01")));
    }

    [Fact]
    public void Attack_UnmanagedImport_ClaimingManagedStatus_Skipped()
    {
        var reg = new UnmanagedAssetRegister();
        reg.Add(Asset("printer-ok"));
        var planted = JsonSerializer.Serialize(new[]
        {
            new
            {
                AssetId = "planted-1", ScopeId = "company-1", Name = "Planted", Kind = "printer",
                Make = (string?)null, Model = (string?)null, SerialNumber = (string?)null,
                IpAddress = (string?)null, MacAddress = (string?)null, SiteId = (string?)null,
                Location = (string?)null, LifecycleState = "active",
                ManagedDeviceIds = Array.Empty<string>(), Tags = Array.Empty<string>(),
                CustomFields = new Dictionary<string, string>(), Notes = (string?)null,
                DiscoveredBy = "manual", CreatedUtc = T0, UpdatedUtc = T0,
                PurchaseDateUtc = (DateTimeOffset?)null, ViewCapability = (string?)null,
                InventoryOnlyReason = (string?)null,
                ManagedByAgent = (bool?)true, // <-- the claim
            },
        });
        Assert.Equal(0, reg.ImportJson(planted));
        Assert.Null(reg.Get("planted-1"));
        Assert.NotNull(reg.Get("printer-ok"));
    }

    [Fact]
    public void Attack_UnmanagedRecord_HasNoManagedPath_AtModelLevel()
    {
        // The record type carries no settable managed flag: the only
        // member is the computed constant. Pin it so a future field
        // addition cannot quietly reopen the hole.
        var prop = typeof(UnmanagedAsset).GetProperty("ManagedByAgent");
        Assert.NotNull(prop);
        Assert.False(prop!.CanWrite);
        Assert.False(Asset("x-1").ManagedByAgent);
    }

    // ---- DG-R04-06: warranty SSRF / redirect shapes --------------------------

    [Fact]
    public void Attack_WarrantyTargets_OffAllowlistShapes_AllRefused()
    {
        var attacks = new[]
        {
            new Uri("https://dell.com@evil.example/"),            // userinfo host confusion
            new Uri("https://www.dell.com@evil.example/"),
            new Uri("https://evil.example/?u=www.dell.com"),      // dell in the query, not the host
            new Uri("https://www.dell.com.evil.example/"),        // suffix host
            new Uri("https://sub.www.dell.com/"),                 // subdomain not on the list
            new Uri("https://127.0.0.1/"),                        // loopback
            new Uri("https://169.254.169.254/latest/meta-data/"), // cloud metadata
            new Uri("file:///etc/passwd"),
            new Uri("gopher://www.dell.com/"),
        };
        foreach (var uri in attacks)
            Assert.False(OemWarrantyEndpoints.ValidateOutboundTarget("dell", uri), uri.ToString());
    }

    [Fact]
    public async Task Attack_WarrantyLookupDisabled_LookupNeverInvoked()
    {
        var fake = new FakeWarrantyLookup();
        fake.SetAnswer("dell", "ABC1234",
            new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(1), null, T0));
        var svc = new WarrantyService(fake,
            policyCheck: key => key != InventoryPolicyKeys.WarrantyLookupEnabled);
        var result = await svc.RefreshAsync(Record("dev-1"));
        Assert.False(result.Refreshed);
        Assert.Contains("disabled by policy", result.Outcome);
        Assert.Equal(0, fake.CallCount); // the policy check runs BEFORE the lookup
    }

    // ---- DG-R04-07: huge / poisoned software lists ---------------------------

    [Fact]
    public void Attack_HugeSoftwareList_OverCap_RefusedWhole()
    {
        var store = new InventoryStore();
        var huge = Enumerable.Range(0, InventoryLimits.MaxSoftwareItems + 1)
            .Select(i => new SoftwareItem($"App-{i}", "1.0", null, null, null)).ToList();
        var result = store.ApplyBaseline(Record("dev-1", software: huge), T0);
        Assert.False(result.Accepted);
        Assert.Null(store.Get("dev-1"));
    }

    [Fact]
    public void Attack_PoisonedSoftwareItems_DroppedAndCounted_DuplicatesKeepHighest()
    {
        // D38-F7 SUPERSEDES the keep-highest half of this test's
        // original assertion: keeping only the highest duplicate hid
        // side-by-side vulnerable installs from patch queries, so
        // distinct (name, version) installs are now ALL kept. The
        // poison half is unchanged: invalid items drop and count.
        var store = new InventoryStore();
        var poisoned = new[]
        {
            new SoftwareItem("Real App", "1.0", "Pub", null, null),
            new SoftwareItem("Real App", "2.0", "Pub", null, null),   // distinct install: kept
            new SoftwareItem("Real App", "1.5", "Pub", null, null),   // distinct install: kept
            new SoftwareItem("Bad\nName", "1.0", null, null, null),   // control char: dropped
            new SoftwareItem("", "1.0", null, null, null),            // empty name: dropped
            new SoftwareItem(new string('A', 300), "1.0", null, null, null), // oversize name: dropped
        };
        var result = store.ApplyBaseline(Record("dev-1", software: poisoned), T0);
        Assert.True(result.Accepted, result.Outcome);
        var stored = store.Get("dev-1")!;
        Assert.Equal(3, stored.Software.Count);
        Assert.Contains(stored.Software, s => s.Version == "2.0");
        Assert.Contains(stored.Software, s => s.Version == "1.0"); // vulnerable copy stays visible
        Assert.Equal(3, stored.DroppedSoftwareCount); // persisted, not warning-only
        Assert.Contains(result.Warnings, w => w.StartsWith("software_items_dropped:"));
    }

    [Fact]
    public void Attack_OversizedHardwareLists_Refused()
    {
        var store = new InventoryStore();
        var hw = Hw() with
        {
            Disks = Enumerable.Range(0, InventoryLimits.MaxDisks + 1)
                .Select(i => new DiskInfo($"D{i}", null, null, 1, null, null)).ToList(),
        };
        Assert.False(store.ApplyBaseline(Record("dev-1", hw: hw), T0).Accepted);
    }

    // ---- DG-R04-08: planted store import --------------------------------------

    [Fact]
    public void Attack_StoreImport_UnflaggedWarranty_DroppedNotHonored()
    {
        // A hand-edited store file plants a warranty that did NOT come
        // from the outbound lookup (flag false). Import drops it.
        var planted = new DeviceInventoryRecord(
            "dev-planted", "company-1", "WS", Hw(), Array.Empty<SoftwareItem>(),
            new Dictionary<string, string>(), new HashSet<string>(), T0, T0, T0, 7,
            Warranty: new WarrantyInfo("dell", "ABC1234", "active", T0.AddYears(9), "PlantedPlan", T0,
                IsOutboundLookup: false));
        var json = JsonSerializer.Serialize(new[] { planted });
        var store = new InventoryStore();
        Assert.Equal(1, store.ImportJson(json));
        Assert.Null(store.Get("dev-planted")!.Warranty);
    }

    [Fact]
    public void Attack_StoreImport_CannotOverwriteLiveRecord()
    {
        var store = new InventoryStore();
        store.ApplyBaseline(Record("dev-1", software: new[] { new SoftwareItem("Live", "1.0", null, null, null) }), T0);
        var stale = Record("dev-1", software: new[] { new SoftwareItem("Stale", "0.1", null, null, null) });
        var json = JsonSerializer.Serialize(new[] { stale });
        Assert.Equal(0, store.ImportJson(json));
        Assert.Equal("Live", store.Get("dev-1")!.Software[0].Name);
    }
}

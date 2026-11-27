using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Inventory;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-04 agent-side collection + hub-side orchestration.
// Agent side: InventoryService builds the device's inventory record
// from injectable collectors, baselines once, and afterwards reports
// ONLY diffs (InventoryChangeReport) — the continuous, on-change
// reporting the directive requires. Collectors are delegates so tests
// drive the whole pipeline with fakes; the production defaults read
// what this sandbox can read honestly (Environment + DriveInfo) and
// the software collector defaults to EMPTY: real installed-software
// enumeration is registry/WMI work that only exists on the Windows
// host, and an honest empty beats an invented list (never fake data).
// Hub side: HubInventoryService owns the warranty refresh flow and
// the alert collection RMM-01 will consume.
// =====================================================================

/// <summary>Agent-side continuous inventory reporter for ONE device.</summary>
public sealed class InventoryService
{
    private readonly string _deviceId;
    private readonly string _scopeId;
    private readonly Func<string> _hostname;
    private readonly Func<HardwareSnapshot> _hardwareCollector;
    private readonly Func<IReadOnlyList<SoftwareItem>> _softwareCollector;
    private readonly Func<(IReadOnlyDictionary<string, string> Fields, IReadOnlySet<string> Tags)>? _adminFields;
    private readonly IClock _clock;
    private readonly IAuditLog? _audit;
    private readonly object _gate = new();
    private DeviceInventoryRecord? _lastReported;

    public InventoryService(
        string deviceId,
        string scopeId,
        Func<HardwareSnapshot> hardwareCollector,
        Func<IReadOnlyList<SoftwareItem>> softwareCollector,
        Func<string>? hostname = null,
        Func<(IReadOnlyDictionary<string, string> Fields, IReadOnlySet<string> Tags)>? adminFields = null,
        IClock? clock = null,
        IAuditLog? audit = null)
    {
        _deviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        _scopeId = scopeId ?? throw new ArgumentNullException(nameof(scopeId));
        _hardwareCollector = hardwareCollector ?? throw new ArgumentNullException(nameof(hardwareCollector));
        _softwareCollector = softwareCollector ?? throw new ArgumentNullException(nameof(softwareCollector));
        _hostname = hostname ?? (() => Environment.MachineName);
        _adminFields = adminFields;
        _clock = clock ?? new SystemClock();
        _audit = audit;
    }

    /// <summary>The record this agent last successfully reported —
    /// the base the next diff is computed against.</summary>
    public DeviceInventoryRecord? LastReported
    {
        get { lock (_gate) return _lastReported; }
    }

    /// <summary>Build the device's current inventory candidate from
    /// the collectors. D38-F2: the candidate is run through the ONE
    /// canonical normalizer (InventoryNormalizer — the same function
    /// the hub runs) before it is diffed or sent, so normalization
    /// can never read as diff spoofing. Note (D38-F1/F4): fields/tags
    /// supplied here are baseline-provisioning data only — after the
    /// baseline they are admin-owned hub metadata and a change
    /// report cannot alter them.</summary>
    public DeviceInventoryRecord BuildCurrentRecord()
    {
        var now = _clock.UtcNow;
        var (fields, tags) = _adminFields?.Invoke()
            ?? (new Dictionary<string, string>(), new HashSet<string>());
        var raw = new DeviceInventoryRecord(
            DeviceId: _deviceId,
            ScopeId: _scopeId,
            Hostname: _hostname(),
            Hardware: _hardwareCollector(),
            Software: _softwareCollector(),
            CustomFields: fields,
            Tags: tags,
            FirstSeenUtc: now,
            LastSeenUtc: now,
            LastChangedUtc: now,
            Revision: 0);
        return InventoryNormalizer.Normalize(raw).Record;
    }

    /// <summary>One collection cycle against the hub store: baseline
    /// on first contact, a consistency-checked change report
    /// afterwards (D38-F4: consistency, not device authentication —
    /// that is the transport/pairing layer's job). An
    /// unchanged cycle produces an empty diff (the store records
    /// "seen, unchanged" without bumping the revision).</summary>
    public InventoryApplyResult CollectAndReport(InventoryStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        var now = _clock.UtcNow;
        var current = BuildCurrentRecord();
        lock (_gate)
        {
            InventoryApplyResult result;
            if (_lastReported is null)
            {
                result = store.ApplyBaseline(current, now);
                if (result.Accepted) _lastReported = store.Get(_deviceId);
            }
            else
            {
                var diff = InventoryDiffer.Compute(_lastReported, current, _lastReported.Revision, now);
                result = store.ApplyChangeReport(new InventoryChangeReport(diff, current), now);
                if (result.Accepted) _lastReported = store.Get(_deviceId);
                else if (result.OutcomeKind == InventoryOutcomeKinds.StaleOrReplayed)
                {
                    // D38-F1 re-baseline path (defence in depth — the
                    // revision-domain separation means admin edits no
                    // longer cause this): on a stale refusal, resync
                    // ONCE from the hub's stored record and recompute
                    // against the fresh revision. Never loops, never
                    // forces a baseline over an existing record.
                    var fresh = store.Get(_deviceId);
                    if (fresh is not null)
                    {
                        var retryDiff = InventoryDiffer.Compute(fresh, current, fresh.Revision, now);
                        var retry = store.ApplyChangeReport(new InventoryChangeReport(retryDiff, current), now);
                        if (retry.Accepted)
                        {
                            result = retry;
                            _lastReported = store.Get(_deviceId);
                        }
                    }
                }
            }
            _audit?.Append(new AuditEntry(now, "inventory", null, null, null,
                result.Accepted ? "inventory_report" : "inventory_report_refused",
                null, result.Outcome, "SYSTEM", null));
            return result;
        }
    }

    // ---- production default collectors --------------------------------

    /// <summary>Hardware from what the runtime can state truthfully
    /// on any OS: machine identity, CPU count, GC-visible memory,
    /// ready drives. Serial / manufacturer / model are NOT knowable
    /// here — they arrive from the Windows host's WMI/CIM feed in
    /// production wiring; this default leaves them empty rather than
    /// inventing values.</summary>
    public static HardwareSnapshot DefaultHardwareCollector()
    {
        var gc = GC.GetGCMemoryInfo();
        var disks = DriveInfo.GetDrives().Where(d => d.IsReady)
            .Select(d => new DiskInfo(d.Name, null, null, d.TotalSize, null, d.DriveType.ToString()))
            .ToList();
        return new HardwareSnapshot(
            Manufacturer: "",
            Model: Environment.MachineName,
            SerialNumber: null,
            CpuModel: "",
            CpuCores: Environment.ProcessorCount,
            RamBytes: gc.TotalAvailableMemoryBytes,
            OsName: Environment.OSVersion.VersionString,
            OsBuild: Environment.OSVersion.Version.ToString(),
            OsVersion: Environment.OSVersion.Version.ToString(),
            BiosVersion: null,
            Disks: disks,
            Peripherals: Array.Empty<PeripheralInfo>(),
            CollectedUtc: DateTimeOffset.UtcNow);
    }

    /// <summary>Installed-software enumeration is Windows-host work
    /// (registry uninstall keys / CIM). Off that host there is no
    /// honest list, so the default is empty — never fabricated.</summary>
    public static IReadOnlyList<SoftwareItem> DefaultSoftwareCollector() =>
        Array.Empty<SoftwareItem>();

    public static InventoryService CreateDefault(string deviceId, string scopeId, IClock? clock = null, IAuditLog? audit = null) =>
        new(deviceId, scopeId, DefaultHardwareCollector, DefaultSoftwareCollector, clock: clock, audit: audit);
}

/// <summary>Hub-side RMM-04 orchestration: warranty refresh (the one
/// outbound lookup, policy-gated inside WarrantyService) and the
/// fleet alert collection the RMM-01 lane consumes.</summary>
public sealed class HubInventoryService
{
    private readonly InventoryStore _store;
    private readonly WarrantyService _warranty;
    private readonly IAuditLog? _audit;

    public HubInventoryService(InventoryStore store, WarrantyService warranty, IAuditLog? audit = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _warranty = warranty ?? throw new ArgumentNullException(nameof(warranty));
        _audit = audit;
    }

    public InventoryStore Store => _store;

    /// <summary>Refresh one device's warranty from the OEM lookup
    /// and store the result. A refused/no-answer refresh changes
    /// nothing on the record — a stale warranty is never overwritten
    /// by a failure.</summary>
    public async Task<WarrantyRefreshResult> RefreshWarrantyAsync(string deviceId, CancellationToken ct = default)
    {
        var record = _store.Get(deviceId);
        if (record is null)
            return new WarrantyRefreshResult(false, "refused: unknown device", null);
        var result = await _warranty.RefreshAsync(record, ct);
        if (result.Refreshed && result.Warranty is not null)
            _store.SetWarranty(record.DeviceId, result.Warranty);
        _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "inventory", null, null, null,
            "warranty_refresh", null, result.Outcome, "SYSTEM", null));
        return result;
    }

    /// <summary>Fleet warranty alerts at `now` — the exact event
    /// shape RMM-01's alert centre consumes.</summary>
    public IReadOnlyList<WarrantyAlertEvent> CollectWarrantyAlerts(DateTimeOffset now) =>
        _store.CollectWarrantyAlerts(now);

    public FleetLifecycleReport BuildLifecycleReport(UnmanagedAssetRegister? unmanaged, DateTimeOffset now) =>
        LifecycleReporting.Build(_store, unmanaged, now);
}

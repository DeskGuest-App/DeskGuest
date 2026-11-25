namespace Acp.Shared.Inventory;

// =====================================================================
// RMM-04 warranty surface. Warranty status by serial (Dell / Lenovo /
// HP / Microsoft) via public OEM lookups FROM THE HUB. This is the
// ONE outbound lookup in RMM-04, and the model says so in the open:
//   * WarrantyInfo.IsOutboundLookup is always true — the fact is
//     flagged in the data itself, not just in docs.
//   * The lookup sits behind IWarrantyLookup; callers pass a vendor
//     + a serial, NEVER a URL. There is no URL parameter anywhere in
//     this surface, so a redirect/SSRF target cannot be expressed.
//   * WarrantyService checks the policy toggle
//     (rmm.inventory.warrantyLookup.enabled) BEFORE invoking the
//     inner lookup — the lookup itself refuses when disabled.
//   * No live OEM client ships in this lane. Tests use
//     FakeWarrantyLookup; production HTTP wiring is hub integration
//     work, and OemWarrantyEndpoints + ValidateOutboundTarget below
//     are the allowlist guard that wiring must pass through.
// =====================================================================

/// <summary>OEMs the warranty lookup knows. Unknown is a refusal,
/// never a guess at some other vendor's endpoint.</summary>
public static class WarrantyVendors
{
    public const string Dell = "dell";
    public const string Lenovo = "lenovo";
    public const string Hp = "hp";
    public const string Microsoft = "microsoft";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Dell, Lenovo, Hp, Microsoft };

    public static string? Normalize(string? vendor)
    {
        var v = (vendor ?? "").Trim().ToLowerInvariant();
        return All.Contains(v) ? v : null;
    }

    /// <summary>Best-effort vendor inference from the hardware
    /// manufacturer string the agent reported. Null when the maker
    /// is not one of the four — no lookup is attempted.</summary>
    public static string? InferFromManufacturer(string? manufacturer)
    {
        var m = (manufacturer ?? "").Trim().ToLowerInvariant();
        if (m.Length == 0) return null;
        if (m.Contains("dell")) return Dell;
        if (m.Contains("lenovo")) return Lenovo;
        if (m.Contains("hewlett") || m.Contains("hp inc") || m == "hp") return Hp;
        if (m.Contains("microsoft")) return Microsoft;
        return null;
    }
}

/// <summary>The public OEM endpoints the hub-side lookup may contact,
/// as DATA: vendor → the only hostnames a lookup for that vendor may
/// ever reach. Any other host is refused by ValidateOutboundTarget.</summary>
public static class OemWarrantyEndpoints
{
    public static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> AllowedHosts =
        new Dictionary<string, IReadOnlySet<string>>
        {
            [WarrantyVendors.Dell] = new HashSet<string> { "www.dell.com", "www.delltechnologies.com" },
            [WarrantyVendors.Lenovo] = new HashSet<string> { "support.lenovo.com", "pcsupport.lenovo.com" },
            [WarrantyVendors.Hp] = new HashSet<string> { "support.hp.com" },
            [WarrantyVendors.Microsoft] = new HashSet<string> { "support.microsoft.com", "mybusinessservice.surface.com" },
        };

    /// <summary>SSRF/redirect guard for the future HTTP wiring: only
    /// https, only an allowlisted host FOR THAT VENDOR, no userinfo,
    /// no non-default port tricks beyond 443.
    /// D38-F11 CONTRACT — named requirements on the future HTTP
    /// client (no client ships in this lane; these are obligations,
    /// not comments-as-decoration):
    /// (1) The client MUST be built with AllowAutoRedirect=false and
    ///     MUST re-run ValidateOutboundTarget on EVERY redirect hop
    ///     before following it — a validated first hop never vouches
    ///     for the second.
    /// (2) The client MUST run ValidateResolvedAddresses on the DNS
    ///     answers for the target host at connect time and refuse if
    ///     ANY answer is non-public (DNS-rebinding defence).
    /// (3) Any non-absolute or unparseable target is a refusal
    ///     (false), never an exception.</summary>
    public static bool ValidateOutboundTarget(string? vendor, Uri? target)
    {
        var v = WarrantyVendors.Normalize(vendor);
        if (v is null || target is null) return false;
        if (!target.IsAbsoluteUri) return false; // D38-F11: relative Uri refused, not thrown on
        if (!string.Equals(target.Scheme, "https", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(target.UserInfo)) return false;
        if (target.Port != 443) return false;
        return AllowedHosts.TryGetValue(v, out var hosts) &&
               hosts.Contains(target.Host.ToLowerInvariant());
    }

    /// <summary>D38-F11: DNS-rebinding half of the guard, executable
    /// now so the future client has a check to call (contract item 2
    /// above). False when there are no answers or ANY answer is
    /// loopback, link-local, private, multicast or unspecified —
    /// an allowlisted OEM host never legitimately resolves there.</summary>
    public static bool ValidateResolvedAddresses(IEnumerable<System.Net.IPAddress>? addresses)
    {
        if (addresses is null) return false;
        var any = false;
        foreach (var ip in addresses)
        {
            if (ip is null) return false;
            any = true;
            if (System.Net.IPAddress.IsLoopback(ip)) return false;
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] == 10) return false;                                  // 10/8 private
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false; // 172.16/12
                if (bytes[0] == 192 && bytes[1] == 168) return false;              // 192.168/16
                if (bytes[0] == 169 && bytes[1] == 254) return false;              // link-local / metadata
                if (bytes[0] >= 224) return false;                                 // multicast/reserved
                if (bytes[0] == 0) return false;                                   // unspecified source block
            }
            else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
                if (ip.Equals(System.Net.IPAddress.IPv6Any)) return false;
            }
        }
        return any;
    }
}

/// <summary>Warranty state for one device, as stored on its inventory
/// record. IsOutboundLookup is permanently true: this data exists
/// ONLY because the hub made the one flagged outbound lookup (serial
/// → OEM), and the record carries that fact so no surface can present
/// it as locally-known data.</summary>
public sealed record WarrantyInfo(
    string Vendor,
    string SerialNumber,
    string Status,               // "active" | "expired" | "unknown"
    DateTimeOffset? ExpiresUtc,
    string? PlanName,
    DateTimeOffset RetrievedUtc,
    bool IsOutboundLookup = true,
    string Source = "oem-public-lookup")
{
    public const string StatusActive = "active";
    public const string StatusExpired = "expired";
    public const string StatusUnknown = "unknown";
}

/// <summary>The warranty lookup contract. Implementations receive a
/// normalized vendor + a validated serial — never a URL, never raw
/// device data beyond the serial (the register's privacy shape: no
/// device data leaves except the serial, to the OEM).
/// D38-F11: any HTTP implementation of this contract MUST be built
/// on OemWarrantyEndpoints.ValidateOutboundTarget +
/// ValidateResolvedAddresses per the contract stated there
/// (AllowAutoRedirect=false, every hop re-validated, resolved IPs
/// checked). An implementation that skips the guard does not
/// satisfy this interface's contract even if it compiles.</summary>
public interface IWarrantyLookup
{
    Task<WarrantyInfo?> LookupAsync(string vendor, string serialNumber, CancellationToken ct);
}

/// <summary>Test double: canned answers, call-counted, never any
/// network. A serial with no canned answer returns null (the OEM
/// "unknown serial" outcome).</summary>
public sealed class FakeWarrantyLookup : IWarrantyLookup
{
    private readonly Dictionary<string, WarrantyInfo> _answers = new(StringComparer.OrdinalIgnoreCase);
    public int CallCount { get; private set; }
    public string? LastVendor { get; private set; }
    public string? LastSerial { get; private set; }

    public void SetAnswer(string vendor, string serial, WarrantyInfo info) =>
        _answers[Key(vendor, serial)] = info;

    private static string Key(string vendor, string serial) => vendor + "|" + serial;

    public Task<WarrantyInfo?> LookupAsync(string vendor, string serialNumber, CancellationToken ct)
    {
        CallCount++;
        LastVendor = vendor;
        LastSerial = serialNumber;
        return Task.FromResult(_answers.TryGetValue(Key(vendor, serialNumber), out var info) ? info : null);
    }
}

/// <summary>Outcome of a warranty refresh attempt. Refusals are
/// values, not exceptions: policy-disabled, missing/invalid serial,
/// unknown vendor, and OEM-no-answer are all named outcomes the hub
/// can log and display honestly.</summary>
public sealed record WarrantyRefreshResult(
    bool Refreshed,
    string Outcome,
    WarrantyInfo? Warranty);

/// <summary>Policy-gated warranty service (hub-side). The policy
/// check runs INSIDE this service, before the inner lookup is
/// touched — disabling rmm.inventory.warrantyLookup.enabled stops
/// the outbound call itself, not just its display.</summary>
public sealed class WarrantyService
{
    private readonly IWarrantyLookup _lookup;
    private readonly Func<string, bool> _policyCheck;

    public WarrantyService(IWarrantyLookup lookup, Func<string, bool>? policyCheck = null)
    {
        _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));
        _policyCheck = policyCheck ?? InventoryPolicyKeys.DefaultCheck;
    }

    public bool LookupEnabled => _policyCheck(InventoryPolicyKeys.WarrantyLookupEnabled);

    public async Task<WarrantyRefreshResult> RefreshAsync(
        DeviceInventoryRecord record, CancellationToken ct = default)
    {
        if (!_policyCheck(InventoryPolicyKeys.WarrantyLookupEnabled))
            return new WarrantyRefreshResult(false,
                "refused: warranty lookup disabled by policy (rmm.inventory.warrantyLookup.enabled)", null);

        var serial = InventoryValidation.NormalizeSerial(record.Hardware.SerialNumber);
        if (serial is null)
            return new WarrantyRefreshResult(false,
                "refused: device serial is missing or not a plausible OEM serial — no lookup attempted", null);

        var vendor = WarrantyVendors.InferFromManufacturer(record.Hardware.Manufacturer);
        if (vendor is null)
            return new WarrantyRefreshResult(false,
                $"refused: manufacturer '{record.Hardware.Manufacturer}' is not one of dell/lenovo/hp/microsoft — no lookup attempted", null);

        var info = await _lookup.LookupAsync(vendor, serial, ct);
        if (info is null)
            return new WarrantyRefreshResult(false,
                "no_answer: OEM returned no warranty record for this serial", null);

        // The answer is re-stamped with the facts of THIS lookup: the
        // vendor/serial actually queried and the outbound flag forced
        // true — an implementation cannot smuggle a mismatched serial
        // or an unflagged record into the store through this service.
        var stamped = info with
        {
            Vendor = vendor,
            SerialNumber = serial,
            IsOutboundLookup = true,
            Source = string.IsNullOrWhiteSpace(info.Source) ? "oem-public-lookup" : info.Source,
        };
        return new WarrantyRefreshResult(true, "refreshed", stamped);
    }
}

// ---- expiry alerts: the event shape RMM-01 consumes -----------------

/// <summary>A warranty expiry alert event (RMM-04 → RMM-01 hook).
/// RMM-01's condition system consumes this shape: Kind is
/// "warranty_expiring" (inside the warning window) or
/// "warranty_expired"; Severity is "warning" | "critical" |
/// "expired". Raised from hub-stored warranty data only — evaluating
/// alerts never triggers a lookup.</summary>
public sealed record WarrantyAlertEvent(
    string DeviceId,
    string SerialNumber,
    string Vendor,
    string Kind,
    string Severity,
    DateTimeOffset ExpiresUtc,
    int DaysRemaining,
    DateTimeOffset RaisedUtc)
{
    public const string KindExpiring = "warranty_expiring";
    public const string KindExpired = "warranty_expired";
    public const string SeverityWarning = "warning";
    public const string SeverityCritical = "critical";
    public const string SeverityExpired = "expired";
}

public static class WarrantyAlertEvaluator
{
    public const int DefaultWarningWindowDays = 90;
    public const int DefaultCriticalWindowDays = 30;

    /// <summary>Evaluate one record's stored warranty at `now`.
    /// Null when there is nothing to alert on: no warranty, unknown
    /// status/expiry, or expiry comfortably outside the window.</summary>
    public static WarrantyAlertEvent? Evaluate(
        DeviceInventoryRecord record, DateTimeOffset now,
        int warningWindowDays = DefaultWarningWindowDays,
        int criticalWindowDays = DefaultCriticalWindowDays)
    {
        var w = record.Warranty;
        if (w is null || w.ExpiresUtc is not { } expires) return null;
        if (w.Status is not (WarrantyInfo.StatusActive or WarrantyInfo.StatusExpired)) return null;
        var days = (int)Math.Floor((expires - now).TotalDays);
        if (days < 0 || w.Status == WarrantyInfo.StatusExpired)
            return new WarrantyAlertEvent(record.DeviceId, w.SerialNumber, w.Vendor,
                WarrantyAlertEvent.KindExpired, WarrantyAlertEvent.SeverityExpired,
                expires, Math.Min(days, -1), now);
        if (days > warningWindowDays) return null;
        var severity = days <= criticalWindowDays
            ? WarrantyAlertEvent.SeverityCritical
            : WarrantyAlertEvent.SeverityWarning;
        return new WarrantyAlertEvent(record.DeviceId, w.SerialNumber, w.Vendor,
            WarrantyAlertEvent.KindExpiring, severity, expires, days, now);
    }
}

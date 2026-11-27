using System.Text.Json;
using System.Text.RegularExpressions;

namespace DeskGuest.Shared.Inventory;

// =====================================================================
// RMM-04 — the unmanaged-asset register: devices that will NEVER run
// an agent (printers, cameras, BAS controllers, switches, UPSs) with
// lifecycle state and relationships to managed devices / sites. This
// register is also where RMM-11 discovery results and camera records
// land, so the model is built for extension:
//   * Kind is an open slug with well-known constants — RMM-11 can
//     register new kinds without a schema change (KindIsKnown says
//     whether the kind is one this build recognizes).
//   * Camera records carry make/model (the shared Make/Model slots)
//     plus the camera-viewing extension's fields (ViewCapability,
//     InventoryOnlyReason) — the 2026-11-20 camera adoption depends
//     on those slots existing here.
//   * DiscoveredBy records provenance ("manual", "rmm11-discovery").
//
// THE core invariant: an unmanaged asset is NOT a managed device and
// can never become one by editing this register. The record has no
// settable managed/agent flag at all — ManagedByAgent is a computed
// constant false — enrollment lives in the enrollment store, and the
// register additionally REFUSES an asset id that collides with a
// managed device id (via the injectable predicate) and REFUSES import
// entries that claim agent enrollment.
// =====================================================================

public static class UnmanagedAssetKinds
{
    public const string Printer = "printer";
    public const string Camera = "camera";
    public const string BasController = "bas-controller";
    public const string NetworkSwitch = "network-switch";
    public const string Ups = "ups";
    public const string AccessPoint = "access-point";
    public const string Phone = "phone";
    public const string Other = "other";

    public static readonly IReadOnlySet<string> Known = new HashSet<string>
    {
        Printer, Camera, BasController, NetworkSwitch, Ups, AccessPoint, Phone, Other,
    };
}

public static class UnmanagedLifecycleStates
{
    public const string Discovered = "discovered";
    public const string Active = "active";
    public const string Maintenance = "maintenance";
    public const string Retired = "retired";
    public const string Disposed = "disposed";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        Discovered, Active, Maintenance, Retired, Disposed,
    };

    /// <summary>Legal lifecycle transitions. Disposed is terminal;
    /// retired may be recommissioned to active; everything else
    /// follows the working life of a physical asset.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> Transitions =
        new Dictionary<string, IReadOnlySet<string>>
        {
            [Discovered] = new HashSet<string> { Active, Retired, Disposed },
            [Active] = new HashSet<string> { Maintenance, Retired, Disposed },
            [Maintenance] = new HashSet<string> { Active, Retired, Disposed },
            [Retired] = new HashSet<string> { Active, Disposed },
            [Disposed] = new HashSet<string>(),
        };

    public static bool CanTransition(string from, string to) =>
        Transitions.TryGetValue(from ?? "", out var set) && set.Contains(to ?? "");
}

/// <summary>Camera view capability (RMM-11 camera extension bounds):
/// open protocols only. A cloud-locked camera is "inventory-only"
/// with the reason stated in the record — never a silent failure.</summary>
public static class CameraViewCapabilities
{
    public const string Onvif = "onvif";
    public const string Rtsp = "rtsp";
    public const string InventoryOnly = "inventory-only";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Onvif, Rtsp, InventoryOnly };
}

/// <summary>One unmanaged asset. Make/Model are the shared identity
/// slots every kind uses (cameras included). Relationships are by id:
/// ManagedDeviceIds names enrolled devices this asset relates to
/// (e.g. the JACE a controller hangs off, the switch a camera plugs
/// into); SiteId names the site record in whatever site model the
/// hub keeps — this register stores the reference, not the site.</summary>
public sealed record UnmanagedAsset(
    string AssetId,
    string ScopeId,
    string Name,
    string Kind,
    string? Make,
    string? Model,
    string? SerialNumber,
    string? IpAddress,
    string? MacAddress,
    string? SiteId,
    string? Location,
    string LifecycleState,
    IReadOnlyList<string> ManagedDeviceIds,
    IReadOnlySet<string> Tags,
    IReadOnlyDictionary<string, string> CustomFields,
    string? Notes,
    string DiscoveredBy,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    DateTimeOffset? PurchaseDateUtc = null,
    string? ViewCapability = null,
    string? InventoryOnlyReason = null)
{
    /// <summary>THE invariant, computed — there is no constructor
    /// path, property setter, or import field that can make this
    /// true. Managed status comes only from enrollment.</summary>
    public bool ManagedByAgent => false;

    /// <summary>True when Kind is one this build recognizes; RMM-11
    /// discovery may land kinds this build predates, and they are
    /// stored (flagged unknown), never dropped or misfiled.</summary>
    public bool KindIsKnown => UnmanagedAssetKinds.Known.Contains(Kind);
}

public sealed record UnmanagedAssetEvent(
    DateTimeOffset Utc, string Kind, string AssetId, string Detail);

public sealed partial class UnmanagedAssetRegister
{
    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-_]{0,63}$")]
    private static partial Regex KindPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-_]{0,127}$")]
    private static partial Regex AssetIdPattern();

    public const int MaxAssets = 10000;
    public const int MaxRelationshipsPerAsset = 64;
    // D38-F12: the event log is bounded — oldest entries roll off.
    public const int MaxEvents = 10000;

    private readonly Dictionary<string, UnmanagedAsset> _assets = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<UnmanagedAssetEvent> _events = new();
    private readonly object _gate = new();
    private readonly Func<string, bool> _policyCheck;
    private readonly Func<string, bool>? _isManagedDeviceId;
    private readonly IReadOnlyDictionary<string, CustomFieldDefinition> _customFieldSchema;

    /// <param name="policyCheck">TOTAL POLICY CONTROL delegate;
    /// the register consults rmm.inventory.unmanagedRegister.enabled.</param>
    /// <param name="isManagedDeviceId">Predicate over the enrollment
    /// store: an asset id that IS a managed device id is refused —
    /// one identity cannot live in both registers. D38-F12: hub
    /// wiring MUST supply this predicate in production (it is the
    /// enrollment store's lookup); the register stays constructible
    /// without it for unit use, and <see cref="ManagedCheckWired"/>
    /// exposes honestly whether the check is live. The predicate is
    /// invoked with BOTH the as-supplied id and its normalized
    /// (lowercased) form, and the enrollment lookup itself must
    /// compare case-insensitively — "PC-01" and "pc-01" are one
    /// identity. The reverse direction (an enrollment attempt under
    /// an id that already exists as an unmanaged asset) is the
    /// ENROLLMENT store's job at hub wiring: it must consult this
    /// register's Get/List before enrolling — named here because no
    /// code in this file can enforce it.</param>
    /// <param name="customFieldSchema">Admin-defined field
    /// definitions shared with the managed inventory; values for
    /// undefined keys are refused.</param>
    public UnmanagedAssetRegister(
        Func<string, bool>? policyCheck = null,
        Func<string, bool>? isManagedDeviceId = null,
        IEnumerable<CustomFieldDefinition>? customFieldSchema = null)
    {
        _policyCheck = policyCheck ?? InventoryPolicyKeys.DefaultCheck;
        _isManagedDeviceId = isManagedDeviceId;
        // D38-F12: schema entries are validated with the SAME rules
        // as InventoryStore.DefineCustomField (clean key, closed
        // type set, enum needs values, non-empty label); invalid or
        // conflicting duplicates are skipped, never thrown on, so
        // the register's schema cannot drift or crash construction.
        var schema = new Dictionary<string, CustomFieldDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var def in customFieldSchema ?? Array.Empty<CustomFieldDefinition>())
        {
            if (def is null) continue;
            if (!InventoryValidation.IsValidCustomFieldKey(def.Key)) continue;
            if (!CustomFieldTypes.All.Contains(def.Type ?? "")) continue;
            if (def.Type == "enum" && def.AllowedValues.Count == 0) continue;
            if (string.IsNullOrWhiteSpace(def.Label)) continue;
            if (schema.TryGetValue(def.Key, out var existing))
            {
                if (existing.Type != def.Type) continue; // type conflict: first wins, no throw
                continue;
            }
            if (schema.Count >= InventoryLimits.MaxCustomFields) break;
            schema[def.Key] = def;
        }
        _customFieldSchema = schema;
    }

    /// <summary>D38-F12: true when hub wiring supplied the managed-id
    /// collision predicate. False means the collision check is NOT
    /// live — surfaced honestly instead of silently defaulting to
    /// "no check" (production wiring must make this true).</summary>
    public bool ManagedCheckWired => _isManagedDeviceId is not null;

    /// <summary>Collision check honoring D38-F12: the predicate sees
    /// the id as supplied (original case) AND normalized, so a
    /// case-sensitive enrollment lookup cannot miss PC-01/pc-01.</summary>
    private bool IsManagedCollision(string? rawId, string normalizedId)
    {
        if (_isManagedDeviceId is null) return false;
        if (rawId is not null && _isManagedDeviceId(rawId.Trim())) return true;
        return _isManagedDeviceId(normalizedId);
    }

    public event Action? Changed;

    public bool RegisterEnabled => _policyCheck(InventoryPolicyKeys.UnmanagedRegisterEnabled);

    public IReadOnlyList<UnmanagedAssetEvent> Events
    {
        get { lock (_gate) return _events.ToList(); }
    }

    private void RecordEvent(string kind, string assetId, string detail)
    {
        _events.Add(new UnmanagedAssetEvent(DateTimeOffset.UtcNow, kind, assetId, detail));
        // D38-F12: bounded log — roll the oldest off past the cap.
        while (_events.Count > MaxEvents) _events.RemoveAt(0);
    }

    /// <summary>Add an asset. Null on refusal: register disabled by
    /// policy, malformed id/kind/name, duplicate id, id colliding
    /// with a managed device, unknown lifecycle state, a camera
    /// field on a non-camera, an inventory-only camera with no
    /// stated reason, too many relationships, or a custom field
    /// that fails its definition.</summary>
    public UnmanagedAsset? Add(UnmanagedAsset candidate)
    {
        if (!RegisterEnabled) return null;
        if (candidate is null) return null;
        var asset = ValidateAndNormalize(candidate, isNew: true);
        if (asset is null) return null;
        lock (_gate)
        {
            if (_assets.Count >= MaxAssets) return null;
            if (_assets.ContainsKey(asset.AssetId)) return null;
            if (IsManagedCollision(candidate.AssetId, asset.AssetId)) return null;
            _assets[asset.AssetId] = asset;
            RecordEvent("asset_added", asset.AssetId, $"kind={asset.Kind} state={asset.LifecycleState}");
            Changed?.Invoke();
            return asset;
        }
    }

    /// <summary>D38-F8: restore insert used ONLY by ImportJson.
    /// Validates with isNew:false so an asset exported in ANY
    /// lifecycle state — including disposed — round-trips with its
    /// disposal history intact (Add's born-disposed refusal is a
    /// creation rule, not a restore rule). Still refuses: disabled
    /// register, id collisions with live assets, managed-id
    /// collisions, and (in ImportJson) managed-status claims.</summary>
    private UnmanagedAsset? AddForRestore(UnmanagedAsset candidate)
    {
        if (!RegisterEnabled) return null;
        if (candidate is null) return null;
        var asset = ValidateAndNormalize(candidate, isNew: false);
        if (asset is null) return null;
        lock (_gate)
        {
            if (_assets.Count >= MaxAssets) return null;
            if (_assets.ContainsKey(asset.AssetId)) return null;
            if (IsManagedCollision(candidate.AssetId, asset.AssetId)) return null;
            _assets[asset.AssetId] = asset;
            RecordEvent("asset_restored", asset.AssetId, $"kind={asset.Kind} state={asset.LifecycleState}");
            Changed?.Invoke();
            return asset;
        }
    }

    /// <summary>Replace an asset's mutable facts (identity, kind and
    /// creation time are immutable — a kind change is a new asset).
    /// Lifecycle changes must go through Transition so the state
    /// machine is honored; a direct state jump here is refused.</summary>
    public bool Update(UnmanagedAsset candidate)
    {
        if (!RegisterEnabled || candidate is null) return false;
        lock (_gate)
        {
            if (!_assets.TryGetValue(candidate.AssetId ?? "", out var existing)) return false;
            if (!string.Equals(existing.Kind, candidate.Kind, StringComparison.OrdinalIgnoreCase)) return false;
            if (existing.CreatedUtc != candidate.CreatedUtc) return false;
            if (!string.Equals(existing.LifecycleState, candidate.LifecycleState, StringComparison.Ordinal))
                return false; // state moves only via Transition
            var normalized = ValidateAndNormalize(candidate with
            {
                ScopeId = existing.ScopeId,
                CreatedUtc = existing.CreatedUtc,
                UpdatedUtc = DateTimeOffset.UtcNow,
            }, isNew: false);
            if (normalized is null) return false;
            if (IsManagedCollision(candidate.AssetId, normalized.AssetId)) return false;
            _assets[existing.AssetId] = normalized;
            RecordEvent("asset_updated", existing.AssetId, $"kind={normalized.Kind}");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Move an asset through its lifecycle. False for an
    /// unknown asset, an unknown state, or a transition the state
    /// machine does not allow (disposed is terminal).</summary>
    public bool Transition(string assetId, string toState)
    {
        var to = (toState ?? "").Trim().ToLowerInvariant();
        if (!UnmanagedLifecycleStates.All.Contains(to)) return false;
        lock (_gate)
        {
            if (!_assets.TryGetValue(assetId ?? "", out var asset)) return false;
            if (!UnmanagedLifecycleStates.CanTransition(asset.LifecycleState, to)) return false;
            _assets[asset.AssetId] = asset with
            {
                LifecycleState = to,
                UpdatedUtc = DateTimeOffset.UtcNow,
            };
            RecordEvent("asset_transition", asset.AssetId, $"{asset.LifecycleState}->{to}");
            Changed?.Invoke();
            return true;
        }
    }

    public bool Remove(string assetId)
    {
        lock (_gate)
        {
            if (!_assets.Remove(assetId ?? "")) return false;
            RecordEvent("asset_removed", assetId, "removed by admin");
            Changed?.Invoke();
            return true;
        }
    }

    public UnmanagedAsset? Get(string? assetId)
    {
        lock (_gate) return assetId is not null && _assets.TryGetValue(assetId, out var a) ? a : null;
    }

    public IReadOnlyList<UnmanagedAsset> List(string? scopeId = null, string? kind = null)
    {
        lock (_gate)
            return _assets.Values
                .Where(a => scopeId is null || string.Equals(a.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .Where(a => kind is null || string.Equals(a.Kind, kind, StringComparison.OrdinalIgnoreCase))
                .OrderBy(a => a.AssetId, StringComparer.Ordinal)
                .ToList();
    }

    /// <summary>Assets related to one managed device (the reverse
    /// relationship lookup RMM-11/site views need).</summary>
    public IReadOnlyList<UnmanagedAsset> ListRelatedTo(string managedDeviceId)
    {
        lock (_gate)
            return _assets.Values
                .Where(a => a.ManagedDeviceIds.Contains(managedDeviceId ?? "", StringComparer.OrdinalIgnoreCase))
                .OrderBy(a => a.AssetId, StringComparer.Ordinal)
                .ToList();
    }

    // D38-F9 helpers: every free-text field is length-bounded and
    // control-char free; a violation refuses the asset.
    private static bool IsBoundedText(string? s, int max) =>
        s is null || (s.Trim().Length <= max && !InventoryValidation.HasControlChars(s));

    [GeneratedRegex(@"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$")]
    private static partial Regex MacPattern();

    /// <summary>D38-F9 address rule — DECISION, defended: an asset
    /// IpAddress must parse, and loopback / link-local (incl. the
    /// 169.254.169.254 cloud-metadata address) / unspecified /
    /// multicast addresses are REFUSED at registration for every
    /// kind. Defence: this register is a fleet LAN inventory —
    /// RFC1918 addresses are its legitimate content and stay
    /// allowed — but no physical printer/camera/controller IS the
    /// hub itself (loopback) or a link-local/metadata endpoint, and
    /// IpAddress is exactly what a future RMM-11 viewer connects
    /// to, so registering one is an SSRF-shaped registration with
    /// no legitimate use. RMM-11's connect-time guard remains a
    /// second, independent line (its contract, not replaced here).</summary>
    private static string? NormalizeIpAddress(string? raw)
    {
        if (raw is null) return null;
        var s = raw.Trim();
        if (s.Length == 0) return null;
        if (!System.Net.IPAddress.TryParse(s, out var ip)) return null;
        if (System.Net.IPAddress.IsLoopback(ip)) return null;
        if (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)) return null;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (bytes[0] == 169 && bytes[1] == 254) return null; // link-local + cloud metadata
            if (bytes[0] >= 224) return null;                    // multicast/reserved
        }
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
            (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast)) return null;
        return ip.ToString();
    }

    private static string? NormalizeMacAddress(string? raw)
    {
        if (raw is null) return null;
        var s = raw.Trim();
        if (!MacPattern().IsMatch(s)) return null;
        var hex = new string(s.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    private UnmanagedAsset? ValidateAndNormalize(UnmanagedAsset c, bool isNew)
    {
        if (string.IsNullOrWhiteSpace(c.AssetId) || !AssetIdPattern().IsMatch(c.AssetId.Trim().ToLowerInvariant()))
            return null;
        if (string.IsNullOrWhiteSpace(c.ScopeId) || string.IsNullOrWhiteSpace(c.Name)) return null;
        if (InventoryValidation.HasControlChars(c.Name) || c.Name.Trim().Length > 128) return null;
        // D38-F9: bound/control-check every free-text field.
        if (!IsBoundedText(c.ScopeId, 128) || !IsBoundedText(c.Make, 128) ||
            !IsBoundedText(c.Model, 128) || !IsBoundedText(c.Location, 256) ||
            !IsBoundedText(c.Notes, 1024) || !IsBoundedText(c.SiteId, 128) ||
            !IsBoundedText(c.DiscoveredBy, 128) || !IsBoundedText(c.InventoryOnlyReason, 512))
            return null;
        string? ip = null;
        if (c.IpAddress is not null)
        {
            ip = NormalizeIpAddress(c.IpAddress);
            if (ip is null) return null;
        }
        string? mac = null;
        if (c.MacAddress is not null)
        {
            mac = NormalizeMacAddress(c.MacAddress);
            if (mac is null) return null;
        }
        var kind = (c.Kind ?? "").Trim().ToLowerInvariant();
        if (!KindPattern().IsMatch(kind)) return null;
        var state = (c.LifecycleState ?? "").Trim().ToLowerInvariant();
        if (!UnmanagedLifecycleStates.All.Contains(state)) return null;
        if (isNew && state == UnmanagedLifecycleStates.Disposed) return null; // cannot be born disposed

        // Camera fields belong to cameras only (extension bounds).
        var isCamera = kind == UnmanagedAssetKinds.Camera;
        if (!isCamera && (c.ViewCapability is not null || c.InventoryOnlyReason is not null)) return null;
        string? viewCap = null;
        string? inventoryOnlyReason = null;
        if (isCamera)
        {
            // D38-F9: a camera MUST declare its capability — it is
            // either viewable (onvif/rtsp) or explicitly inventory-
            // only; "neither" is no longer representable.
            if (c.ViewCapability is null) return null;
            viewCap = c.ViewCapability.Trim().ToLowerInvariant();
            if (!CameraViewCapabilities.All.Contains(viewCap)) return null;
            if (viewCap == CameraViewCapabilities.InventoryOnly)
            {
                // Inventory-only REQUIRES the reason stated plainly.
                if (string.IsNullOrWhiteSpace(c.InventoryOnlyReason)) return null;
                inventoryOnlyReason = c.InventoryOnlyReason.Trim();
            }
            else if (c.InventoryOnlyReason is not null)
            {
                return null; // D38-F9: a reason alongside onvif/rtsp is self-contradictory
            }
        }

        var rels = (c.ManagedDeviceIds ?? Array.Empty<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (rels.Count > MaxRelationshipsPerAsset) return null;

        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in c.Tags ?? new HashSet<string>())
        {
            var t = InventoryValidation.NormalizeTag(raw);
            if (t is not null) tags.Add(t);
        }
        if (tags.Count > InventoryLimits.MaxTags) return null;

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in c.CustomFields ?? new Dictionary<string, string>())
        {
            if (!_customFieldSchema.TryGetValue(key ?? "", out var def)) return null;
            var v = InventoryValidation.ValidateCustomFieldValue(def, value);
            if (v is null) return null;
            fields[def.Key] = v;
        }

        var serial = c.SerialNumber is null ? null : InventoryValidation.NormalizeSerial(c.SerialNumber);
        if (c.SerialNumber is not null && serial is null) return null;

        return c with
        {
            AssetId = c.AssetId.Trim().ToLowerInvariant(),
            ScopeId = c.ScopeId.Trim(),
            Name = c.Name.Trim(),
            Kind = kind,
            Make = c.Make?.Trim(),
            Model = c.Model?.Trim(),
            IpAddress = ip,
            MacAddress = mac,
            SiteId = c.SiteId?.Trim(),
            Location = c.Location?.Trim(),
            Notes = c.Notes?.Trim(),
            LifecycleState = state,
            ManagedDeviceIds = rels,
            Tags = tags,
            CustomFields = fields,
            SerialNumber = serial,
            ViewCapability = viewCap,
            InventoryOnlyReason = inventoryOnlyReason,
            DiscoveredBy = string.IsNullOrWhiteSpace(c.DiscoveredBy) ? "manual" : c.DiscoveredBy.Trim(),
        };
    }

    // ---- persistence (Roster discipline: malformed skipped, never
    // fatal; an import NEVER overwrites a live record, and an entry
    // claiming agent enrollment is refused outright) ---------------

    private sealed record AssetDto(
        string AssetId, string ScopeId, string Name, string Kind, string? Make, string? Model,
        string? SerialNumber, string? IpAddress, string? MacAddress, string? SiteId, string? Location,
        string LifecycleState, string[] ManagedDeviceIds, string[] Tags,
        Dictionary<string, string> CustomFields, string? Notes, string DiscoveredBy,
        DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc, DateTimeOffset? PurchaseDateUtc,
        string? ViewCapability, string? InventoryOnlyReason,
        // Hostile-import witnesses: a planted file may carry these.
        // They are read ONLY to refuse the entry — never honored.
        bool? ManagedByAgent = null, bool? IsManaged = null, bool? AgentEnrolled = null);

    public string ExportJson()
    {
        lock (_gate)
        {
            var dtos = _assets.Values.Select(a => new AssetDto(
                a.AssetId, a.ScopeId, a.Name, a.Kind, a.Make, a.Model, a.SerialNumber,
                a.IpAddress, a.MacAddress, a.SiteId, a.Location, a.LifecycleState,
                a.ManagedDeviceIds.ToArray(), a.Tags.ToArray(),
                new Dictionary<string, string>(a.CustomFields), a.Notes, a.DiscoveredBy,
                a.CreatedUtc, a.UpdatedUtc, a.PurchaseDateUtc, a.ViewCapability, a.InventoryOnlyReason)).ToArray();
            return JsonSerializer.Serialize(dtos);
        }
    }

    /// <summary>Restore assets from ExportJson output. Returns the
    /// number restored. Entries that already exist live, fail
    /// validation, collide with a managed device id, or CLAIM managed
    /// status (managedByAgent / isManaged / agentEnrolled in the
    /// file) are skipped — a hand-edited register file can never
    /// mint a managed device.</summary>
    public int ImportJson(string json)
    {
        AssetDto[]? dtos;
        try { dtos = JsonSerializer.Deserialize<AssetDto[]>(json); }
        catch { return 0; }
        if (dtos is null) return 0;
        var restored = 0;
        foreach (var dto in dtos)
        {
            if (dto is null) continue;
            if (dto.ManagedByAgent == true || dto.IsManaged == true || dto.AgentEnrolled == true)
                continue; // claims managed status: refused, never imported
            var candidate = new UnmanagedAsset(
                dto.AssetId ?? "", dto.ScopeId ?? "", dto.Name ?? "", dto.Kind ?? "",
                dto.Make, dto.Model, dto.SerialNumber, dto.IpAddress, dto.MacAddress,
                dto.SiteId, dto.Location, dto.LifecycleState ?? "",
                dto.ManagedDeviceIds ?? Array.Empty<string>(),
                new HashSet<string>(dto.Tags ?? Array.Empty<string>()),
                dto.CustomFields ?? new Dictionary<string, string>(),
                dto.Notes, dto.DiscoveredBy ?? "manual", dto.CreatedUtc, dto.UpdatedUtc,
                dto.PurchaseDateUtc, dto.ViewCapability, dto.InventoryOnlyReason);
            lock (_gate)
            {
                if (dto.AssetId is not null && _assets.ContainsKey(dto.AssetId)) continue;
            }
            // D38-F8: restore path (not Add) so disposed assets keep
            // their lifecycle state/history on a backup restore.
            if (AddForRestore(candidate) is not null) restored++;
        }
        return restored;
    }
}

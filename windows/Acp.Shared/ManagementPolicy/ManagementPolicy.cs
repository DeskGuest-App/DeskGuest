using System.Text.Json;
using Acp.Shared.Enterprise;

namespace Acp.Shared.ManagementPolicy;

// =====================================================================
// RMM-07 — Management-policy inheritance + Effective Policy view.
//
// Generalises the enterprise signed-bundle machinery (org ceiling →
// group → device, signed content, fail-closed) from transports to
// ALL management policy. A policy document is a settings tree
// (feature keys → values) assigned at org, group or device level:
//
//   * a child INHERITS every setting it does not set;
//   * a child may OVERRIDE an inherited setting;
//   * a child may REVERT to inherited (the InheritMarker value, or
//     simply not setting the key) — the inherited value and its
//     provenance show through again.
//
// Group membership can be DYNAMIC: a group may carry attribute
// rules evaluated against IDeviceFacts ("all devices with X
// installed", "all site servers"). RMM-04 inventory will implement
// IDeviceFacts against real collection; the engine depends only on
// the interface.
//
// Effective Policy is a computed, queryable model: for every
// setting, its effective value AND its provenance (which level and
// which document set it). This file is the model + engine; the Core
// service (ManagementPolicyService) is the data surface.
//
// TOTAL POLICY CONTROL contract: every feature registers a toggle
// key in FeatureToggleRegistry and asks IsEnabled(facts, key).
// Seeded below for RMM-01..32 (+ the RMM-11 camera extension).
//
// THE §7.10 CONSENT FLOOR IS NEVER A SETTING. ConsentFloorGuard
// refuses — at document admission AND at registry admission — any
// key that would toggle presence, STOP, the audit chain, or the
// consent floor itself. The floor is the floor; toggles govern
// features only.
// =====================================================================

public static class PolicyLevels
{
    public const string Org = "org";
    public const string Group = "group";
    public const string Device = "device";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Org, Group, Device };
}

/// <summary>One signed management-policy document: a settings tree
/// fragment assigned to one target at one level. Content travels
/// inside an RMM-03 signed-command envelope (class policy_delivery);
/// this record is the payload model. Revision is monotonic per Id:
/// a stale or conflicting re-delivery refuses.</summary>
public sealed record ManagementPolicyDocument(
    string Id,
    string Level,          // PolicyLevels.*
    string TargetId,       // org: scope id | group: group id | device: device id
    IReadOnlyDictionary<string, string> Settings,
    long Revision)
{
    /// <summary>The value a document sets to say "revert to
    /// inherited": the engine treats it as not setting the key, so
    /// the inherited value (and provenance) shows through.</summary>
    public const string InheritMarker = "__inherit__";

    /// <summary>Deterministic canonical JSON (settings keys sorted
    /// ordinal) — the exact bytes the RMM-03 envelope payload carries
    /// and hashes.</summary>
    public string ToCanonicalJson()
    {
        var sorted = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in Settings) sorted[k] = v;
        return JsonSerializer.Serialize(new
        {
            id = Id, level = Level, targetId = TargetId, revision = Revision, settings = sorted,
        });
    }

    public static ManagementPolicyDocument? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var settings = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var p in root.GetProperty("settings").EnumerateObject())
                settings[p.Name] = p.Value.GetString() ?? "";
            return new ManagementPolicyDocument(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("level").GetString() ?? "",
                root.GetProperty("targetId").GetString() ?? "",
                settings,
                root.GetProperty("revision").GetInt64());
        }
        catch { return null; }
    }
}

/// <summary>The §7.10 consent-floor denylist. A key is denied when
/// it names presence, STOP, the audit chain, or the consent floor —
/// as a whole key or as a dotted namespace. Denial is by NAME, so a
/// feature key can never be crafted to reach the floor through this
/// engine; and the engine refuses a whole document that carries one
/// denied key rather than silently dropping it (a dropped key would
/// let a document look applied while its floor-attack vanished).</summary>
public static class ConsentFloorGuard
{
    private static readonly IReadOnlySet<string> DeniedExact = new HashSet<string>(StringComparer.Ordinal)
    {
        "presence", "stop", "audit", "consent", "consent_floor", "consent.floor",
        "presence.enabled", "presence.visible", "presence.hide", "presence_indicator",
        "stop.enabled", "stop.disabled", "stop_button", "kill_switch",
        "audit.enabled", "audit.editable", "audit.deletable", "audit_chain",
    };

    private static readonly string[] DeniedPrefixes = { "presence.", "stop.", "audit.", "consent.", "consent_floor." };

    // D38 F4: the floor-naming SEGMENTS — checked against every
    // segment of the key, however the key is glued together. The
    // compound floor names (kill_switch, audit_chain, stop_button,
    // presence_indicator) are segments too: "rmm.kill_switch" is a
    // kill-switch toggle wherever it hides, exactly like
    // "rmm.presence.enabled".
    private static readonly IReadOnlySet<string> DeniedSegments = new HashSet<string>(StringComparer.Ordinal)
    {
        "presence", "stop", "audit", "consent", "consent_floor", "consentfloor",
        "kill_switch", "killswitch", "audit_chain", "auditchain",
        "stop_button", "stopbutton", "presence_indicator", "presenceindicator",
    };

    // Segment separators an attacker can glue a disguise with —
    // the guard splits on ALL of them, not just '.'.
    private static readonly char[] SegmentSeparators = { '.', '-', '/', '_', ' ', '\t' };

    // Common Cyrillic/Greek homoglyphs folded to their Latin
    // look-alikes before matching (defence in depth alongside
    // format-character stripping and FormKC normalization).
    private static readonly Dictionary<char, char> HomoglyphFold = new()
    {
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c',
        ['у'] = 'y', ['х'] = 'x', ['і'] = 'i', ['ј'] = 'j', ['ѕ'] = 's',
        ['һ'] = 'h', ['ԁ'] = 'd', ['ο'] = 'o', ['ρ'] = 'p', ['τ'] = 't',
        ['υ'] = 'u', ['χ'] = 'x', ['α'] = 'a', ['ε'] = 'e', ['ι'] = 'i', ['κ'] = 'k',
    };

    /// <summary>Canonicalize a key for the floor check ONLY (the
    /// engine's stored keys keep their own normalization): strip
    /// zero-width / format characters (Unicode category Cf — a
    /// zero-width space inside "pres\u200Bence" must not smuggle
    /// the segment past the matcher), fold homoglyphs, apply
    /// FormKC, trim, lowercase.</summary>
    public static string NormalizeForFloorCheck(string? key)
    {
        var raw = key ?? "";
        var sb = new System.Text.StringBuilder(raw.Length);
        foreach (var c in raw.Normalize(System.Text.NormalizationForm.FormKC))
        {
            if (System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c)
                == System.Globalization.UnicodeCategory.Format) continue;
            sb.Append(HomoglyphFold.TryGetValue(c, out var folded) ? folded : c);
        }
        return sb.ToString().Trim().ToLowerInvariant();
    }

    public static bool IsDenied(string? key)
    {
        var k = NormalizeForFloorCheck(key);
        if (k.Length == 0) return false;
        if (DeniedExact.Contains(k)) return true;
        foreach (var p in DeniedPrefixes)
            if (k.StartsWith(p, StringComparison.Ordinal)) return true;
        // bd-shared-sec-2/F11: the previous shape split on '_' too
        // and denied ANY segment equal to a floor word, so
        // legitimate keys were refused -- "rmm.compliance.audit_pack
        // .enabled" (segment "audit") and "rmm.backup.stop_on_
        // battery" (segment "stop") are not consent-floor keys.
        // The matcher now works on COMPONENTS (split on '.', '-',
        // '/', whitespace -- never '_', so compound floor names
        // like "kill_switch" stay whole):
        //   * a component that IS a floor name denies
        //     ("rmm/stop", "rmm-presence-enabled", "kill_switch");
        //   * a component of the form <floor-head>_<floor-suffix>
        //     denies ("stop_enabled", "presence_hide",
        //     "audit_deletable") -- the disguise shape;
        //   * a component that merely CONTAINS a floor word as one
        //     of several name tokens ("audit_pack",
        //     "stop_on_battery") does NOT deny.
        foreach (var seg in k.Split(new[] { '.', '-', '/', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var component = seg.Trim();
            if (DeniedSegments.Contains(component)) return true;
            var tokens = component.Split('_', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length >= 2 && FloorHeads.Contains(tokens[0]) &&
                tokens.Skip(1).All(t => FloorSuffixes.Contains(t)))
                return true;
            // A floor head buried in a glued name denies when it
            // ENDS the component or is followed only by floor
            // suffixes ("rmm_stop_enabled", "x_stop") -- but not
            // when ordinary name tokens follow it
            // ("stop_on_battery": "battery" follows "on").
            for (var i = 0; i < tokens.Length; i++)
                if (FloorHeads.Contains(tokens[i]) &&
                    tokens.Skip(i + 1).All(t => FloorSuffixes.Contains(t)))
                    return true;
        }
        // W12 / DS-P7-F22: the hyphenated/space compound forms —
        // "kill-switch" and "kill switch" are the kill_switch floor
        // name with a different glue. Re-join each dotted component's
        // '-'/' ' glue to '_' and test the compound segment directly.
        // (SegmentSeparators above was dead; the live split list and
        // this check now cover every glue the field names.)
        foreach (var seg in k.Split(new[] { '.', '/' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var compound = seg.Trim().Replace('-', '_').Replace(' ', '_');
            if (DeniedSegments.Contains(compound) || DeniedExact.Contains(compound)) return true;
        }
        return false;
    }

    // bd-shared-sec-2/F11: floor heads and the suffix vocabulary
    // that turns a head into a floor toggle ("stop_enabled").
    // A component like "stop_on_battery" survives because
    // "battery" is not floor vocabulary; "audit_pack" survives
    // because "pack" is not either.
    private static readonly IReadOnlySet<string> FloorHeads = new HashSet<string>(StringComparer.Ordinal)
        { "presence", "stop", "audit", "consent" };
    private static readonly IReadOnlySet<string> FloorSuffixes = new HashSet<string>(StringComparer.Ordinal)
        { "enabled", "disabled", "visible", "hide", "hidden", "editable", "deletable",
          "button", "indicator", "chain", "floor", "on", "off", "required", "enforced" };

    /// <summary>Null when the document is clean; otherwise the
    /// refusal reason naming the first denied key.</summary>
    public static string? CheckDocument(ManagementPolicyDocument doc)
    {
        foreach (var key in doc.Settings.Keys)
            if (IsDenied(key))
                return $"policy document '{doc.Id}' carries consent-floor key '{key}' — REFUSED: the §7.10 consent floor is never a setting (presence, STOP and the audit chain have no toggle)";
        return null;
    }
}

/// <summary>One registered feature toggle (TOTAL POLICY CONTROL).
/// Other Block R lanes consume the registry; they never invent keys.</summary>
public sealed record FeatureToggle(string Key, string Directive, bool DefaultEnabled, string Description);

/// <summary>The feature-toggle registry, seeded with the RMM-01..32
/// toggles (names + defaults from the Block R register; RMM-10
/// Backstage defaults OFF per its directive, the RMM-11 camera
/// extension defaults OFF per its bounds, RMM-31/32 default OFF —
/// MDM's push transit is a named platform caveat and DLP is
/// programme-scale). Registering a consent-floor key throws: the
/// registry itself refuses to carry one.
/// W13 / DS-P7-F1 adjudication note (precision, replacing the W12
/// log's looser summary): the seed set is 40 toggles — 35 default
/// ON, 5 default OFF (RMM-10 backstage, RMM-10 background_tools,
/// RMM-11-EXT camera_viewing, RMM-31 mdm, RMM-32 dlp), each OFF
/// carrying its reason in its seed line above. The ON defaults are
/// the Block R register's commissioned posture — every RMM feature
/// the owner commissioned is ON unless its own directive said OFF —
/// recorded per key by its Directive field, not a fail-open
/// accident: IsEnabled fail-closes for unregistered keys, for
/// consent-floor keys, and for unparsable explicit values (see
/// IsEnabled's doc). Whether any individual ON default should
/// flip is a per-key product decision for the trio, not a code
/// defect this registry hides.</summary>
public sealed class FeatureToggleRegistry
{
    private readonly Dictionary<string, FeatureToggle> _toggles = new(StringComparer.Ordinal);
    private readonly object _gate = new(); // W12 / DS-P7-F18: the registry is shared across lanes — every access locks

    public FeatureToggleRegistry() { }

    public void Register(FeatureToggle toggle)
    {
        var key = (toggle.Key ?? "").Trim().ToLowerInvariant();
        if (key.Length == 0) throw new ArgumentException("feature toggle key is empty", nameof(toggle));
        if (ConsentFloorGuard.IsDenied(key))
            throw new InvalidOperationException($"feature key '{key}' names the §7.10 consent floor — the registry REFUSES to carry it: presence, STOP and audit are never settings");
        lock (_gate) _toggles[key] = toggle with { Key = key };
    }

    public bool TryGet(string key, out FeatureToggle? toggle)
    {
        lock (_gate) return _toggles.TryGetValue((key ?? "").Trim().ToLowerInvariant(), out toggle);
    }

    public IReadOnlyList<FeatureToggle> All
    {
        get { lock (_gate) return _toggles.Values.OrderBy(t => t.Key, StringComparer.Ordinal).ToList(); }
    }

    public static FeatureToggleRegistry Seeded()
    {
        var r = new FeatureToggleRegistry();
        void Add(string directive, string key, bool def, string desc) => r.Register(new FeatureToggle(key, directive, def, desc));
        Add("RMM-01", "rmm.monitoring.enabled", true, "Continuous endpoint health monitoring + threshold alerting");
        Add("RMM-02", "rmm.patch.enabled", true, "Patch management (OS + third-party, approvals, rings)");
        Add("RMM-03", "rmm.signed_commands.enabled", true, "Endpoint Takeover Prevention: signed commands, endpoint-verified");
        Add("RMM-04", "rmm.inventory.enabled", true, "Continuous fleet inventory");
        Add("RMM-04", "rmm.inventory.warrantyLookup.enabled", true, "Warranty lookup by serial (the one outbound lookup; hub-side, OEM hosts only)");
        Add("RMM-04", "rmm.inventory.unmanagedRegister.enabled", true, "Unmanaged-asset register (printers, cameras, BAS controllers)");
        Add("RMM-05", "rmm.vulnerability.enabled", true, "Vulnerability management loop");
        Add("RMM-06", "rmm.backup.enabled", true, "Endpoint backup to user-owned storage");
        Add("RMM-07", "rmm.policy.enabled", true, "Management-policy inheritance + Effective Policy");
        Add("RMM-08", "rmm.remediation.enabled", true, "Auto-remediation engine");
        Add("RMM-09", "rmm.compliance.enabled", true, "Compliance evidence packs");
        Add("RMM-10", "rmm.backstage.enabled", false, "Background tools / Backstage — default OFF per the RMM-10 directive (presence tension recorded)");
        Add("RMM-10", "rmm.background_tools.enabled", false, "Background toolset (process/service/file/registry without a visible session) — default OFF, separate scope required (coordinator seeding of the RMM-10 lane's policy key, 2026-11-21)");
        Add("RMM-11", "rmm.network_discovery.enabled", true, "Network discovery + agentless monitoring");
        Add("RMM-11-EXT", "rmm.camera_viewing.enabled", false, "Camera viewing (ONVIF/RTSP only; viewing is not recording; audio off by default)");
        Add("RMM-12", "rmm.work_items.enabled", true, "Work items (ticket-lite)");
        Add("RMM-13", "rmm.reporting.enabled", true, "Local reporting + hub API/webhooks");
        Add("RMM-14", "rmm.p2p_distribution.enabled", true, "P2P LAN distribution + patch caching");
        Add("RMM-15", "rmm.job_resume.enabled", true, "Job resume-on-reconnect");
        Add("RMM-16", "rmm.software_deployment.enabled", true, "Software deployment: package repository + content packs");
        Add("RMM-17", "rmm.endpoint_security.enabled", true, "Endpoint security posture: ransomware isolation + AV/EDR management");
        Add("RMM-18", "rmm.encryption_enforcement.enabled", true, "Disk-encryption enforcement + recovery-key escrow");
        Add("RMM-19", "rmm.baselines.enabled", true, "Desired-state baselines + drift detection");
        Add("RMM-20", "rmm.runbooks.enabled", true, "Runbooks: approval-gated SOP execution chains");
        Add("RMM-21", "rmm.site_documentation.enabled", true, "Site documentation + credential vault, surfaced in-session");
        Add("RMM-22", "rmm.camera_share.enabled", true, "Camera-share sessions");
        Add("RMM-23", "rmm.vendor_passes.enabled", true, "Privileged access passes for vendors + browser hardening policy");
        Add("RMM-23", "rmm.browser_hardening.enabled", true, "Browser hardening policy (extension inventory + allow/block + settings) — D38 F9: its own toggle, decoupled from the vendor-pass kill switch so a vendor incident response cannot blind browser enforcement");
        Add("RMM-24", "rmm.enrollment_push.enabled", true, "Directory-driven enrollment push");
        Add("RMM-24", "rmm.mobile_operator.enabled", true, "Mobile operator client (bd-shared-plat-2/F4: its own toggle — decoupled from push enrollment so neither silently controls the other)");
        Add("RMM-25", "rmm.app_control.enabled", true, "Application control (allow/blocklisting)");
        Add("RMM-26", "rmm.metering.enabled", true, "Software metering + licence-compliance reporting");
        Add("RMM-27", "rmm.anomaly_baselining.enabled", true, "Local anomaly baselining for alert quality");
        Add("RMM-28", "rmm.health_scoring.enabled", true, "Endpoint health scoring (DEX-style), locally computed");
        Add("RMM-29", "rmm.imaging.enabled", true, "OS imaging / provisioning + profile migration");
        Add("RMM-30", "rmm.usb_control.enabled", true, "USB/peripheral control + removable-media tracing");
        Add("RMM-31", "rmm.mdm.enabled", false, "MDM subset for site devices — default OFF (APNs/FCM push transit is a named platform caveat)");
        Add("RMM-32", "rmm.dlp.enabled", false, "Endpoint DLP + sensitive-data discovery — programme-scale, default OFF");
        Add("U4", "rmm.session_budget.enabled", true, "Per-session agent budgets + tripwires (U4): per-class caps counted per session at the MCP choke point; a breach or a SCAM sensitive context PAUSES the session. Caps themselves are plain settings keys session_budget.cap.<class> (total/input/deletions/sending/egress_calls/egress_bytes) resolved by SessionBudgetCaps.FromEffective");
        Add("U1", "rmm.clipboard_policy.enabled", true, "Clipboard direction policy (U1): clipboard transfer direction is policy-controlled — plain settings keys clipboard.direction (both|host_to_agent|agent_to_host|off) and clipboard.sensitive_skip (default on: a sensitive-class clip is refused by name, never returned), resolved by ClipboardPolicy.FromEffective and enforced at the MCP choke point and again at the desktop engine's clipboard path");
        Add("A2", "rmm.tor_provisioning.enabled", true, "Tor component provisioning (A2, W19-C wiring): the owner-initiated Tor setup act from the host window — downloads ONLY the pinned Tor expert bundle from the Tor Project's own distribution directory, verifies bundle + per-file hashes against the pins before any launch, and writes tor.json only once the local SOCKS listener answers. Disabling this toggle refuses the setup act by name; status stays readable and stop/unconfigure stays available (a stop is never policy-gated)");
        Add("FR-120", "rmm.takeover_modes.enabled", true, "Tunable takeover fleet defaults (FR-120, W73): the signed-policy channel may set the DEFAULT takeover modes a device starts from — plain settings keys session.takeover.mouse_mode / session.takeover.keyboard_mode (TakeOver | Share | HotkeyOnly) resolved by TakeoverFleetDefaults.FromEffective and pushed to the session agent as defaults only. The modes are NOT §7.10 consent floor (presence/STOP/audit have no toggle and these keys name none of them); the device's own DeskGuest UI stays the live settings home and a local choice outranks the fleet default; the agent channel can never set them");
        Add("FR-143", "connections.https_only.enabled", true, "Require HTTPS for agent connections (default ON). Agent connections arrive on this device's mesh listener (its private-mesh or company-hub address) and its home-network listener. The home-network listener is HTTPS-only by construction, on or off. With this setting ON, the mesh listener is also served over HTTPS with this device's own certificate — an agent receives the certificate's fingerprint (the pin) at pairing and checks it on every connection, and a plain-HTTP attempt is refused by name and logged. With it OFF, the mesh listener accepts plain HTTP (still inside the mesh's encrypted tunnel, but readable to anything that can see inside the tunnel), for older agents. NOT changed by this setting: connections between devices themselves (mesh, hub, direct, sealed relay, Tor) are sealed end to end with the devices' own keys and never travel as readable HTTP. Exempt by name: connections from this same computer (loopback), which never leave the machine");
        Add("A3", "rmm.aipack_download.enabled", true, "Local AI pack download (D25/A3, W19-C wiring): the owner-initiated download of the UI-TARS-1.5-7B pack from the author's official source ONLY, licence acceptance required first, every file verified against the hashes pinned in the product before it lands in the pack home; refuses on any mismatch with no override. Disabling this toggle refuses the download act by name; status/verify stay readable and cancel stays available");
        return r;
    }
}

/// <summary>The device-facts interface dynamic targeting evaluates
/// against. RMM-04 (continuous inventory) implements this against
/// real collection later; the engine and its tests use only this
/// surface. Attributes are free-form string facts (site, role, OS
/// build, tags as a comma-joined "tags" attribute, …).</summary>
public interface IDeviceFacts
{
    string DeviceId { get; }
    string ScopeId { get; }
    IReadOnlySet<string> DirectGroupIds { get; }
    IReadOnlyDictionary<string, string> Attributes { get; }
    IReadOnlySet<string> InstalledSoftware { get; }
}

/// <summary>Plain facts carrier — the shape RMM-04's collector will
/// produce, and the engine's test double.</summary>
public sealed record StaticDeviceFacts(
    string DeviceId,
    string ScopeId,
    IReadOnlySet<string> DirectGroupIds,
    IReadOnlyDictionary<string, string> Attributes,
    IReadOnlySet<string> InstalledSoftware) : IDeviceFacts
{
    public static StaticDeviceFacts Of(string deviceId, string scopeId,
        IEnumerable<string>? groups = null, IDictionary<string, string>? attributes = null,
        IEnumerable<string>? software = null) => new(
            deviceId, scopeId,
            new HashSet<string>(groups ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase),
            new Dictionary<string, string>(attributes ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(software ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase));
}

/// <summary>One dynamic-membership rule. Kinds:
/// attribute_equals / attribute_contains (Attribute + Value),
/// software_installed (Value = software name), tag (Value = tag in
/// the comma-joined "tags" attribute).</summary>
public sealed record GroupRule(string Kind, string? Attribute, string? Value)
{
    public bool Matches(IDeviceFacts facts)
    {
        switch ((Kind ?? "").Trim().ToLowerInvariant())
        {
            case "attribute_equals":
                return Attribute is not null && facts.Attributes.TryGetValue(Attribute, out var eq)
                    && string.Equals(eq, Value ?? "", StringComparison.OrdinalIgnoreCase);
            case "attribute_contains":
                // D38 F3: an empty/whitespace contains-value matches
                // EVERY device that merely has the attribute
                // ("".Contains is trivially true) — that is a
                // fleet-wide group wearing a rule's clothes, so it
                // matches NOTHING (fail closed).
                return Attribute is not null && !string.IsNullOrWhiteSpace(Value)
                    && facts.Attributes.TryGetValue(Attribute, out var co)
                    && co.Contains(Value, StringComparison.OrdinalIgnoreCase);
            case "software_installed":
                return Value is not null && facts.InstalledSoftware.Contains(Value);
            case "tag":
                return facts.Attributes.TryGetValue("tags", out var tags)
                    && tags.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                           .Contains(Value ?? "", StringComparer.OrdinalIgnoreCase);
            default:
                return false; // an unknown rule kind matches NOTHING (fail closed)
        }
    }
}

/// <summary>A targeting group: static membership via the device's
/// DirectGroupIds, dynamic membership via rules (ANY rule matching
/// admits the device — rules are alternatives, documented here so
/// Effective Policy provenance stays explainable).</summary>
public sealed record GroupDefinition(string Id, string Name, IReadOnlyList<GroupRule> Rules)
{
    public bool IsMember(IDeviceFacts facts) =>
        facts.DirectGroupIds.Contains(Id) || Rules.Any(r => r.Matches(facts));
}

/// <summary>One setting's effective value + provenance.</summary>
public sealed record EffectiveSetting(string Key, string Value, string SourceLevel, string SourceTargetId, string SourceDocumentId);

/// <summary>The computed Effective Policy for one device: every
/// setting that applies, with where it came from. This is the model
/// behind the Effective Policy view (a data surface, per the
/// programme: functional surfaces only, product design is last).</summary>
public sealed record EffectivePolicy(string DeviceId, string ScopeId,
    IReadOnlyDictionary<string, EffectiveSetting> Settings,
    IReadOnlyList<string> MemberGroupIds)
{
    /// <summary>bd-shared-sec-2/F4: keys an ORG document locked
    /// (via a "policy.lock.<key>" = "true" setting in an org
    /// document). Group and device documents could not override
    /// these keys in this computation -- the org value stands.
    /// Provenance of a locked key is the org setting itself.</summary>
    public IReadOnlySet<string> LockedKeys { get; init; } =
        new HashSet<string>(StringComparer.Ordinal);

    public EffectiveSetting? Get(string key) =>
        Settings.TryGetValue((key ?? "").Trim().ToLowerInvariant(), out var s) ? s : null;
}

/// <summary>The management-policy engine: document admission
/// (consent-floor refusal, level/revision discipline), dynamic
/// group membership, Effective Policy computation, and the TOTAL
/// POLICY CONTROL IsEnabled query.</summary>
public sealed class ManagementPolicyEngine
{
    private readonly Dictionary<string, ManagementPolicyDocument> _docsById = new(StringComparer.Ordinal);
    private readonly Dictionary<string, GroupDefinition> _groups = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ManagementPolicyEngine(FeatureToggleRegistry? registry = null) =>
        Registry = registry ?? FeatureToggleRegistry.Seeded();

    public FeatureToggleRegistry Registry { get; }

    public IReadOnlyList<ManagementPolicyDocument> Documents
    {
        // W12 / DS-P7-F17: callers get COPIES — the internal documents'
        // Settings dictionaries are mutable behind IReadOnlyDictionary,
        // and handing them out let any caller edit live policy with
        // no revision, signature or audit.
        get
        {
            lock (_gate)
                return _docsById.Values.OrderBy(d => d.Id, StringComparer.Ordinal)
                    .Select(d => d with { Settings = new Dictionary<string, string>(d.Settings, StringComparer.Ordinal) })
                    .ToList();
        }
    }

    /// <summary>Define a group. Group definitions decide where
    /// signed group-level policy lands, so they carry admission
    /// discipline of their own (D38 F3): a group id, once defined,
    /// CANNOT be silently redefined — re-adding the identical
    /// definition is idempotent, a DIFFERENT definition under the
    /// same id refuses (an attacker who can reach any group-
    /// definition path must not be able to widen a narrow group
    /// into a fleet-wide one). Rules that would match everything
    /// by construction (attribute_contains with an empty value)
    /// refuse at admission too, and match nothing if they ever
    /// reach evaluation. Refusals are returned, never thrown.</summary>
    public PolicyVerdict AddGroup(GroupDefinition group)
    {
        if (group is null) return new PolicyVerdict(false, "no group definition — refused");
        if (string.IsNullOrWhiteSpace(group.Id))
            return new PolicyVerdict(false, "group definition needs an id — refused");
        // W12 / DS-P7-F11: refusals are returned, never thrown — a
        // null Rules list refused here, not dereferenced below.
        if (group.Rules is null)
            return new PolicyVerdict(false, "group definition needs a rules list — refused");
        foreach (var rule in group.Rules ?? Array.Empty<GroupRule>())
            if (string.Equals((rule.Kind ?? "").Trim(), "attribute_contains", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrWhiteSpace(rule.Value))
                return new PolicyVerdict(false,
                    $"group '{group.Id}' carries an attribute_contains rule with an empty value — that matches every device with the attribute; refused (D38 F3: a fleet-wide group must be defined as one, not smuggled as a rule)");
        lock (_gate)
        {
            if (_groups.TryGetValue(group.Id, out var existing))
            {
                if (existing.Name == group.Name && existing.Rules.Count == group.Rules.Count
                    && existing.Rules.Zip(group.Rules).All(p => p.First == p.Second))
                    return new PolicyVerdict(true, $"group '{group.Id}' already defined identically (idempotent)");
                return new PolicyVerdict(false,
                    $"group '{group.Id}' is already defined and group definitions cannot be redefined in place — refused (define a new group id; D38 F3)");
            }
            // Defensive copy of the rules list, same discipline as
            // documents: post-admission mutation must not widen it.
            _groups[group.Id] = group with { Rules = group.Rules.ToList() };
            return new PolicyVerdict(true, $"group '{group.Id}' defined ({group.Rules.Count} rule(s))");
        }
    }

    public IReadOnlyList<GroupDefinition> Groups
    {
        get { lock (_gate) return _groups.Values.OrderBy(g => g.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Admit a policy document. Refusals (returned, never
    /// thrown): consent-floor keys, unknown level, empty identity,
    /// stale revision, or a same-revision document whose content
    /// differs from the admitted one (a conflicting re-delivery —
    /// two documents cannot share an id+revision and disagree).</summary>
    public PolicyVerdict AddDocument(ManagementPolicyDocument doc)
    {
        if (doc is null) return new PolicyVerdict(false, "no policy document — refused");
        if (string.IsNullOrWhiteSpace(doc.Id) || string.IsNullOrWhiteSpace(doc.TargetId))
            return new PolicyVerdict(false, "policy document needs an id and a target — refused");
        if (!PolicyLevels.All.Contains(doc.Level ?? ""))
            return new PolicyVerdict(false, $"unknown policy level '{doc.Level}' — refused");
        if (ConsentFloorGuard.CheckDocument(doc) is { } floorRefusal)
            return new PolicyVerdict(false, floorRefusal);
        foreach (var key in doc.Settings.Keys)
            if (string.IsNullOrWhiteSpace(key))
                return new PolicyVerdict(false, $"policy document '{doc.Id}' carries an empty setting key — refused");
        lock (_gate)
        {
            if (_docsById.TryGetValue(doc.Id, out var existing))
            {
                if (doc.Revision < existing.Revision)
                    return new PolicyVerdict(false, $"policy document '{doc.Id}' revision {doc.Revision} is stale (current {existing.Revision}) — refused");
                if (doc.Revision == existing.Revision && doc.ToCanonicalJson() != existing.ToCanonicalJson())
                    return new PolicyVerdict(false, $"policy document '{doc.Id}' revision {doc.Revision} conflicts with the admitted document of the same id+revision — refused");
                if (doc.Revision == existing.Revision)
                    return new PolicyVerdict(true, $"policy document '{doc.Id}' r{doc.Revision} already admitted (idempotent)");
            }
            // Defensive copy: the admitted document is frozen at
            // admission. Without this, a caller holding the original
            // settings dictionary could mutate live policy after the
            // fact — no revision, no signature, no audit (found by
            // the RMM-07 destruction pass; regression-tested there).
            _docsById[doc.Id] = doc with
            {
                Settings = new Dictionary<string, string>(doc.Settings, StringComparer.Ordinal),
            };
            return new PolicyVerdict(true, $"policy document '{doc.Id}' r{doc.Revision} admitted at {doc.Level} level for '{doc.TargetId}'");
        }
    }

    public IReadOnlyList<string> MemberGroupIds(IDeviceFacts facts)
    {
        lock (_gate)
            return _groups.Values.Where(g => g.IsMember(facts))
                .Select(g => g.Id).OrderBy(id => id, StringComparer.Ordinal).ToList();
    }

    /// <summary>Compute the Effective Policy: org documents for the
    /// device's scope, then group documents for every group the
    /// device belongs to (groups applied in ordinal group-id order —
    /// deterministic, so provenance never depends on insertion
    /// order), then device documents. Later levels override; the
    /// InheritMarker leaves the inherited value (and provenance) in
    /// place. Keys are normalized to lowercase.</summary>
    public EffectivePolicy ComputeEffective(IDeviceFacts facts)
    {
        var memberGroups = MemberGroupIds(facts);
        var memberSet = new HashSet<string>(memberGroups, StringComparer.OrdinalIgnoreCase);
        List<ManagementPolicyDocument> docs;
        lock (_gate) docs = _docsById.Values.ToList();

        var acc = new Dictionary<string, EffectiveSetting>(StringComparer.Ordinal);
        // bd-shared-sec-2/F4: ORG LOCKS. The engine was plain
        // last-writer-wins: any group/device document could loosen
        // an org security setting (mode=audit, direction=both, cap
        // upward, the whole peripheral rules string). An org
        // document now LOCKS a key by carrying
        // "policy.lock.<key>" = "true"; once locked at org level,
        // group/device settings for that key are IGNORED in this
        // computation (the org value -- or its absence -- stands).
        // Locks are gathered from every org document applying to
        // this device BEFORE any level applies, so lock order
        // never depends on document order. Only org documents can
        // lock: a "policy.lock.*" setting in a group/device
        // document is inert (it lands as an ordinary setting and
        // locks nothing).
        const string LockPrefix = "policy.lock.";
        var orgDocs = docs.Where(d => d.Level == PolicyLevels.Org &&
            (d.TargetId == facts.ScopeId || d.TargetId == "*")).ToList();
        var locked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var doc in orgDocs)
            foreach (var (rawKey, value) in doc.Settings)
            {
                var key = rawKey.Trim().ToLowerInvariant();
                if (key.StartsWith(LockPrefix, StringComparison.Ordinal) &&
                    bool.TryParse(value, out var on) && on)
                    locked.Add(key[LockPrefix.Length..]);
            }

        void Apply(IEnumerable<ManagementPolicyDocument> levelDocs, bool honourLocks)
        {
            // Order: target, then id, then REVISION ascending — so
            // within a target, a higher revision always wins over a
            // lower one even when document ids sort the other way
            // (D38 F9: '…:v10' sorts before '…:v9' ordinally; the
            // revision, not the name, is the authority).
            // W12 / DS-P7-F8: revision BEFORE id — with id second, a
            // stale document whose id sorts later beat a newer
            // revision for the same target; revision is the authority.
            foreach (var doc in levelDocs.OrderBy(d => d.TargetId, StringComparer.Ordinal).ThenBy(d => d.Revision).ThenBy(d => d.Id, StringComparer.Ordinal))
                foreach (var (rawKey, value) in doc.Settings)
                {
                    var key = rawKey.Trim().ToLowerInvariant();
                    if (value == ManagementPolicyDocument.InheritMarker) continue; // revert-to-inherited: inherited value stands
                    if (honourLocks && locked.Contains(key)) continue; // bd-sec-2/F4: org-locked — lower levels cannot move this key
                    acc[key] = new EffectiveSetting(key, value, doc.Level, doc.TargetId, doc.Id);
                }
        }

        Apply(orgDocs, honourLocks: false);
        Apply(docs.Where(d => d.Level == PolicyLevels.Group && memberSet.Contains(d.TargetId)), honourLocks: true);
        Apply(docs.Where(d => d.Level == PolicyLevels.Device && d.TargetId == facts.DeviceId), honourLocks: true);
        return new EffectivePolicy(facts.DeviceId, facts.ScopeId, acc, memberGroups)
            { LockedKeys = locked };
    }

    /// <summary>THE TOTAL POLICY CONTROL query other features call.
    /// Resolution (D38 F12 — the doc now states what the code does):
    /// consent-floor key → false (always; the floor is not a
    /// setting); a key a document explicitly sets → its value wins
    /// ("true"/"false" parse; an unparsable explicit value refuses
    /// — false — rather than guessing), whether or not the key is
    /// registered (documents may carry plain settings keys, not
    /// only feature toggles); a key no document sets → the registry
    /// default for registered keys; an unregistered key no document
    /// sets → false (fail closed).</summary>
    public bool IsEnabled(IDeviceFacts facts, string featureKey)
    {
        var key = (featureKey ?? "").Trim().ToLowerInvariant();
        if (ConsentFloorGuard.IsDenied(key)) return false;
        var effective = ComputeEffective(facts).Get(key);
        if (effective is not null)
        {
            if (bool.TryParse(effective.Value, out var v)) return v;
            return false; // an unparsable toggle value never enables anything
        }
        return Registry.TryGet(key, out var toggle) && toggle!.DefaultEnabled;
    }
}

/// <summary>Bridge: the existing enterprise PolicyBundle (Block E)
/// as the new engine's first real org-level policy document. The
/// bundle's settings (transport ceiling/mode, update pin/defer,
/// enterprise flags) and its TOTAL POLICY CONTROL feature toggles
/// (PolicyFeatures keys) map into the settings tree; the bundle
/// itself remains the transport/update authority — this document is
/// its projection into the management-policy engine, so Effective
/// Policy can answer for those settings too.</summary>
public static class EnterpriseBundleBridge
{
    public static ManagementPolicyDocument FromBundle(PolicyBundle bundle)
    {
        var s = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["transport.ceiling"] = string.Join(",", bundle.TransportCeiling),
            ["transport.mode"] = bundle.TransportMode,
            ["enterprise.forbid_ai_pairings"] = bundle.ForbidAiPairings.ToString().ToLowerInvariant(),
            ["enterprise.disable_recording"] = bundle.DisableRecording.ToString().ToLowerInvariant(),
            ["enterprise.unattended_tier"] = bundle.UnattendedTier,
        };
        if (bundle.PinnedVersion is not null) s["update.pinned_version"] = bundle.PinnedVersion;
        if (bundle.UpdateDeferUntil is not null) s["update.defer_until"] = bundle.UpdateDeferUntil.Value.ToString("O");
        foreach (var key in PolicyFeatures.All)
        {
            s[$"feature.{key}"] = bundle.Disabled.Contains(key) ? "false" : "true";
            if (bundle.Required.Contains(key)) s[$"feature.{key}.required"] = "true";
        }
        // D38 F9: the document id is STABLE per scope and the
        // bundle version rides as the document REVISION — so the
        // engine's monotonic-revision discipline applies BETWEEN
        // bundle versions: a stale bundle (v9 after v10) refuses as
        // stale instead of coexisting with the newer document and
        // winning on an ordinal id sort.
        return new ManagementPolicyDocument(
            Id: $"enterprise-bundle:{bundle.ScopeId}",
            Level: PolicyLevels.Org, TargetId: bundle.ScopeId,
            Settings: s, Revision: bundle.Version);
    }
}

using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Shared.PeripheralControl;

// =====================================================================
// RMM-30 — USB / peripheral control + removable-media tracing.
//
//   (a) PERIPHERAL POLICY: allow/block by device CLASS (storage,
//       HID, network adapters, Bluetooth radios, cameras, printers,
//       serial) and by specific device identity (VID/PID + serial
//       where the device offers one), delivered as RMM-07 signed
//       policy content. Modes audit vs enforce, AUDIT the default,
//       following RMM-25's pattern exactly: every surface carries
//       the EFFECTIVE mode label, and an audit verdict never claims
//       a block happened.
//   (b) IDENTITY STRENGTH IS LABELLED, never smoothed: a rule bound
//       to VID/PID + SERIAL is strong; a rule bound to VID/PID
//       alone is CLONEABLE — VID/PID are unauthenticated values a
//       spoofing device can copy, and the model says so wherever
//       the rule appears. A display name NEVER binds policy.
//       Two different serials claiming one VID/PID identity on one
//       machine is an identity COLLISION and is itself an alert.
//   (c) STORAGE MEDIA TRACING: a writable storage medium's connect
//       is recorded with device identity + machine + time; where
//       the OS watcher provides visibility, transfers TO removable
//       media are logged by file NAME + size + SHA-256 (metadata
//       tracing — this model has NO content field by construction;
//       content inspection is RMM-32's separate gated territory).
//       Trace records are hash-chained and verifiable. The model
//       ENUMERATES the transfer paths it can see and NAMES the ones
//       it cannot — honesty over coverage claims.
//   (d) EXCEPTIONS: a blocked device can be excepted via the
//       approval workflow (RMM-25's request pattern, composed with
//       RMM-12 work items by the Core service). An exception binds
//       the EXACT device identity + the requesting MACHINE + an
//       EXPIRY. There is no parameter by which an approval widens
//       to a class, to another machine, or to permanence.
//
// ENFORCEMENT is host machinery (Windows device-installation
// restrictions / removable-storage access policy): this file is
// model + policy + evaluation + workflow + tracing; the applier is
// an interface with fakes, per the RMM-23/RMM-25 pattern — the
// honest unavailable applier reports NOT applied.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-30. The RMM-07 seeded
/// toggle spelling is rmm.usb_control.enabled (default ON); the
/// register spelling rmm.peripheral_control.enabled is honoured as
/// the primary key here — either spelling gates the feature, the
/// primary spelling wins when both are set (RMM-25 alias pattern).</summary>
public static class PeripheralKeys
{
    public const string FeatureEnabled = "rmm.peripheral_control.enabled";
    public const string FeatureEnabledSeeded = "rmm.usb_control.enabled";
    /// <summary>"audit" | "enforce". Unset/unparsable → audit, named.</summary>
    public const string Mode = "rmm.peripheral_control.mode";
    /// <summary>Rule list, one rule per '|' entry, fields
    /// comma-separated: effect,kind,scopeKind,scopeId,expiresIsoOrDash,
    /// ruleId,anchor. Anchor: class kind → the class slug; device
    /// kind → vid:pid or vid:pid:serial (hex vid/pid, colon-joined).</summary>
    public const string Rules = "rmm.peripheral_control.rules";
    /// <summary>Media tracing on/off ("true"/"false"); unset → ON
    /// when the feature is enabled (tracing is the evidence half of
    /// the directive; disabling it is an explicit, audited act).</summary>
    public const string Tracing = "rmm.peripheral_control.tracing";
}

public static class PeripheralModes
{
    public const string Audit = "audit";
    public const string Enforce = "enforce";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Audit, Enforce };
    public static string Label(string mode) => mode == Enforce
        ? "ENFORCE (blocks are real)"
        : "AUDIT-ONLY (nothing is blocked; would-block events are logged)";
}

public static class DeviceClasses
{
    public const string Storage = "storage";
    public const string Hid = "hid";
    public const string Network = "network";
    public const string Bluetooth = "bluetooth";
    public const string Camera = "camera";
    public const string Printer = "printer";
    public const string Serial = "serial";
    /// <summary>A device whose class cannot be determined. Class
    /// rules never match it by name; in ENFORCE mode an unknown-class
    /// device is would-be/blocked by the unknown-class guard (a
    /// device that hides its class does not get a free pass), and
    /// that guard is named in the decision.</summary>
    public const string Unknown = "unknown";
    public static readonly IReadOnlySet<string> All = new HashSet<string>
        { Storage, Hid, Network, Bluetooth, Camera, Printer, Serial, Unknown };
    public static readonly IReadOnlySet<string> Ruleable = new HashSet<string>
        { Storage, Hid, Network, Bluetooth, Camera, Printer, Serial };
}

public static class PeripheralEffects
{
    public const string Allow = "allow";
    public const string Block = "block";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Allow, Block };
}

public static class PeripheralRuleKinds
{
    public const string Class = "class";
    public const string Device = "device";
    /// <summary>Approval-minted exception rules: kind=device anchors
    /// + SourceRequestId set + expiry mandatory + machine scope.</summary>
    public const string Exception = "exception";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Class, Device, Exception };

    /// <summary>Precedence: an APPROVED exception beats a plain
    /// device rule (D38-F5: the exception IS the human decision
    /// about that exact device — at equal rank the device block
    /// always won and the approval minted a rule that changed
    /// nothing); a specific-device rule beats a class rule.</summary>
    public static int Rank(string kind) => kind switch
    {
        Exception => 3,
        Device => 2,
        Class => 1,
        _ => 0,
    };
}

public static class PeripheralScopes
{
    public const string Org = "org";
    public const string Group = "group";
    public const string Device = "device";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Org, Group, Device };
}

public static class PeripheralLimits
{
    public const int MaxSerialLength = 128;
    public const int MaxDisplayNameLength = 256;
    public const int MaxRulesPerPolicy = 1024;
    public const int MaxReasonLength = 2048;
    public const int MaxActorLength = 128;
    public const int MaxFileNameLength = 512;
    public static readonly TimeSpan MaxExceptionDuration = TimeSpan.FromDays(90);
    public const int MaxPendingRequestsPerMachine = 20;
    public const int MaxRequestsPerRequesterPerHour = 10;
    /// <summary>Bound on the in-memory seen registry (D38-F11a):
    /// oldest identities are evicted FIFO past this count, so a
    /// hostile device population cannot grow the registry without
    /// limit. Eviction re-arms first-seen for the evicted identity —
    /// a named trade, never silent growth.</summary>
    public const int MaxSeenIdentities = 100_000;
}

/// <summary>One peripheral's identity as presented at connect time.
/// VendorId/ProductId are the USB VID/PID (4 hex each) where the
/// bus offers them; Serial is the device serial where offered.
/// DisplayName is presentation ONLY and never binds policy.</summary>
public sealed record DeviceIdentity(
    string MachineId,
    string Class,
    string? VendorId,
    string? ProductId,
    string? Serial,
    string? DisplayName)
{
    public string NormalizedClass => (Class ?? "").Trim().ToLowerInvariant();
    public string NormalizedVid => (VendorId ?? "").Trim().ToLowerInvariant();
    public string NormalizedPid => (ProductId ?? "").Trim().ToLowerInvariant();
    public string NormalizedSerial => (Serial ?? "").Trim();
    public bool HasSerial => NormalizedSerial.Length > 0;
    public bool HasVidPid => NormalizedVid.Length > 0 && NormalizedPid.Length > 0;

    /// <summary>THE identity-strength label, carried on every
    /// surface that names this identity or a rule bound to it.</summary>
    public string StrengthLabel => HasVidPid && HasSerial
        ? "strong (serial-bound: VID/PID + device serial)"
        : HasSerial
            ? "WEAK (serial only — NO VID/PID offered, so nothing binds the serial to a vendor/product identity; a serial alone is unauthenticated and just as spoofable as VID/PID)"
            : HasVidPid
                ? "CLONEABLE (VID/PID only — no serial offered; VID/PID are unauthenticated and a spoofing device can copy them; labelled as such wherever this identity appears)"
                : "WEAKEST (no VID/PID, no serial — class + display only; display names are spoofable)";

    /// <summary>The cloneable-identity key: what a VID/PID-only
    /// spoof would collide on. Two different serials under one
    /// KeyBase on one machine = an identity collision.</summary>
    public string KeyBase => $"{NormalizedClass}|{NormalizedVid}:{NormalizedPid}";
    public string Key => $"{MachineId}|{KeyBase}|{NormalizedSerial}";

    public static bool IsVidPid(string s) =>
        s.Length == 4 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(MachineId)) return "device identity needs a machine id — refused";
        if (!DeviceClasses.All.Contains(NormalizedClass))
            return $"device identity carries unknown class '{Class}' — refused (classes: {string.Join(", ", DeviceClasses.All.OrderBy(c => c, StringComparer.Ordinal))})";
        if (VendorId is not null && !IsVidPid(NormalizedVid))
            return "vendor id is not a 4-hex-digit USB VID — refused (a malformed VID binds nothing)";
        if (ProductId is not null && !IsVidPid(NormalizedPid))
            return "product id is not a 4-hex-digit USB PID — refused (a malformed PID binds nothing)";
        if ((VendorId is null) != (ProductId is null))
            return "device identity carries only half a VID/PID pair — refused (VID and PID bind together or not at all)";
        if (Serial is { Length: > PeripheralLimits.MaxSerialLength }) return "device serial over bounds — refused";
        if (DisplayName is { Length: > PeripheralLimits.MaxDisplayNameLength }) return "device display name over bounds — refused";
        if (!HasVidPid && !HasSerial)
            return "device identity carries no VID/PID and no serial — too thin to bind policy to; refused (a class plus a spoofable display name is not an identity)";
        return null;
    }
}

/// <summary>One allow/block rule. Class rules bind a class slug.
/// Device rules bind VID/PID and — when Serial is set — the serial
/// too (the conjunction is the strong form). Exception rules are
/// approval-minted device rules: expiry mandatory, scope pinned to
/// the requesting machine by the store, never class kind.</summary>
public sealed record PeripheralRule(
    string Id,
    string Effect,                 // PeripheralEffects.*
    string Kind,                   // PeripheralRuleKinds.*
    string? Class,                 // kind=class anchor
    string? VendorId,              // kind=device/exception anchor
    string? ProductId,
    string? Serial,                // optional strong anchor
    string ScopeKind,              // PeripheralScopes.*
    string ScopeId,
    DateTimeOffset? ExpiresUtc,    // REQUIRED for exception rules
    string? SourceRequestId)       // set exactly for exception rules
{
    public bool IsException => SourceRequestId is not null;
    public int Rank => PeripheralRuleKinds.Rank(Kind);
    public string StrengthLabel => Kind == PeripheralRuleKinds.Class
        ? "class-wide (every device of this class)"
        : Serial is not null && VendorId is not null && ProductId is not null
            ? "strong (serial-bound: VID/PID + device serial)"
            : Serial is not null
                ? "WEAK (serial only — no VID/PID anchor; a serial alone is unauthenticated and spoofable)"
                : "CLONEABLE (VID/PID only — a spoofing device can copy VID/PID; labelled as such wherever this rule appears)";

    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(Id)) return "a rule needs an id — refused";
        if (!PeripheralEffects.All.Contains(Effect ?? "")) return $"unknown rule effect '{Effect}' — refused";
        if (!PeripheralRuleKinds.All.Contains(Kind ?? "")) return $"unknown rule kind '{Kind}' — refused";
        if (!PeripheralScopes.All.Contains(ScopeKind ?? "")) return $"unknown rule scope '{ScopeKind}' — refused";
        if (string.IsNullOrWhiteSpace(ScopeId)) return "a rule needs a scope id — refused";
        switch (Kind)
        {
            case PeripheralRuleKinds.Class:
                if (Class is null || !DeviceClasses.Ruleable.Contains(Class.Trim().ToLowerInvariant()))
                    return $"class rule '{Id}' names no ruleable device class — refused (the unknown-class guard is a model behaviour, not an authorable class rule)";
                break;
            case PeripheralRuleKinds.Device:
            case PeripheralRuleKinds.Exception:
                // D38-F10: a PRESENT but malformed VID or PID refuses
                // at admission (named) — it must never pass Validate
                // and then silently match nothing, failing a block
                // rule open on a typo. Empty anchors count as absent:
                // a serial-only anchor is a legitimate (weak) form.
                var hasVidText = !string.IsNullOrWhiteSpace(VendorId);
                var hasPidText = !string.IsNullOrWhiteSpace(ProductId);
                if (hasVidText != hasPidText)
                    return $"device rule '{Id}' carries only half a VID/PID pair — refused";
                if (hasVidText && !DeviceIdentity.IsVidPid(VendorId!.Trim()))
                    return $"device rule '{Id}' carries a malformed VID '{VendorId}' (not 4 hex digits) — refused at admission, never silently inert";
                if (hasPidText && !DeviceIdentity.IsVidPid(ProductId!.Trim()))
                    return $"device rule '{Id}' carries a malformed PID '{ProductId}' (not 4 hex digits) — refused at admission, never silently inert";
                var hasVidPid = hasVidText && hasPidText;
                var hasSerialAnchor = !string.IsNullOrWhiteSpace(Serial);
                if (!hasVidPid && !hasSerialAnchor)
                    return $"device rule '{Id}' carries no valid VID/PID anchor and no serial anchor — refused";
                if (Serial is { Length: > PeripheralLimits.MaxSerialLength })
                    return $"device rule '{Id}' serial over bounds — refused";
                break;
        }
        if (Kind == PeripheralRuleKinds.Exception && !IsException)
            return $"exception rule '{Id}' names no source request — refused";
        if (IsException)
        {
            if (Kind == PeripheralRuleKinds.Class)
                return $"exception rule '{Id}' is CLASS-wide — refused: an exception binds one device identity on one machine, never a class-wide hole";
            if (string.IsNullOrWhiteSpace(Class))
                return $"exception rule '{Id}' binds NO class — refused: every exception carries the class it was approved for (D38-F5)";
            if (ExpiresUtc is null)
                return $"exception rule '{Id}' carries NO expiry — refused: exceptions are timed by construction and never permanent";
            if (ExpiresUtc.Value <= now)
                return $"exception rule '{Id}' is already expired at admission — refused";
            if (ExpiresUtc.Value - now > PeripheralLimits.MaxExceptionDuration)
                return $"exception rule '{Id}' exceeds the maximum exception lifetime ({PeripheralLimits.MaxExceptionDuration.TotalDays:0} days) — refused at admission, never clamped (D38-F5)";
            if (ScopeKind != PeripheralScopes.Device)
                return $"exception rule '{Id}' is scoped '{ScopeKind}' — refused: an exception binds the requesting machine (device scope) only";
        }
        return null;
    }

    public bool IsExpired(DateTimeOffset now) => ExpiresUtc is { } exp && now >= exp;

    public bool ScopeApplies(DeviceIdentity identity, string scopeId, IReadOnlySet<string> groupIds) =>
        ScopeKind switch
        {
            PeripheralScopes.Device => string.Equals(ScopeId, identity.MachineId, StringComparison.OrdinalIgnoreCase),
            PeripheralScopes.Group => groupIds.Contains(ScopeId),
            PeripheralScopes.Org => ScopeId == "*" || string.Equals(ScopeId, scopeId, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };

    /// <summary>Anchor match. Expired rules never match; an
    /// exception rule with no expiry matches NOTHING even if one
    /// reached an evaluator without admission (defence in depth,
    /// RMM-25 B2 pattern). A serial-bound rule requires the serial;
    /// a VID/PID rule matches any serial under that VID/PID — that
    /// is exactly the cloneability the label names.</summary>
    public bool Matches(DeviceIdentity identity, DateTimeOffset now)
    {
        if (IsExpired(now)) return false;
        if (IsException && ExpiresUtc is null) return false;
        switch (Kind)
        {
            case PeripheralRuleKinds.Class:
                return string.Equals(identity.NormalizedClass, (Class ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal);
            case PeripheralRuleKinds.Device:
            case PeripheralRuleKinds.Exception:
                // Only a REAL VID/PID anchor constrains: an empty
                // anchor text is no anchor (D38-F10 — a serial-only
                // rule must be able to match a serial-only device).
                if (!string.IsNullOrWhiteSpace(VendorId) || !string.IsNullOrWhiteSpace(ProductId))
                {
                    if (!identity.HasVidPid) return false;
                    if (!string.Equals(identity.NormalizedVid, (VendorId ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal)) return false;
                    if (!string.Equals(identity.NormalizedPid, (ProductId ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal)) return false;
                }
                if (Serial is not null && !string.Equals(identity.NormalizedSerial, Serial.Trim(), StringComparison.Ordinal)) return false;
                // An exception binds the class AS APPROVED too: the
                // same VID/PID re-presented in another class (a
                // storage stick returning as an HID) must NOT
                // inherit the exception. An exception with NO class
                // recorded matches NOTHING (defence in depth, D38-F5).
                if (IsException &&
                    (Class is null || !string.Equals(identity.NormalizedClass, Class.Trim().ToLowerInvariant(), StringComparison.Ordinal))) return false;
                return true;
            default:
                return false;
        }
    }

    public string Describe() =>
        $"{Effect}/{Kind} rule '{Id}' [{StrengthLabel}] scope={ScopeKind}:{ScopeId}" +
        (ExpiresUtc is { } e ? $" expires={e:O}" : " no-expiry") +
        (SourceRequestId is not null ? $" source-request={SourceRequestId}" : "");
}

/// <summary>The resolved peripheral policy for one machine.</summary>
public sealed record ResolvedPeripheralPolicy(
    bool FeatureEnabled,
    string Mode,
    bool TracingEnabled,
    IReadOnlyList<PeripheralRule> Rules,
    IReadOnlyList<string> Notes)
{
    public string EffectiveModeLabel => PeripheralModes.Label(Mode);
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public static class PeripheralResolver
{
    public static ResolvedPeripheralPolicy Resolve(
        ManagementPolicyEngine engine, IDeviceFacts facts,
        IEnumerable<PeripheralRule>? exceptionRules = null, DateTimeOffset now = default)
    {
        if (now == default) now = DateTimeOffset.UtcNow;
        var eff = engine.ComputeEffective(facts);
        var notes = new List<string>();

        var enabledSetting = eff.Get(PeripheralKeys.FeatureEnabled) ?? eff.Get(PeripheralKeys.FeatureEnabledSeeded);
        var enabled = enabledSetting is not null
            ? bool.TryParse(enabledSetting.Value, out var v) && v
            : engine.Registry.TryGet(PeripheralKeys.FeatureEnabledSeeded, out var t) && t!.DefaultEnabled;
        if (!enabled)
            return new ResolvedPeripheralPolicy(false, PeripheralModes.Audit, false,
                Array.Empty<PeripheralRule>(), new[] { $"peripheral control is disabled by policy for machine '{facts.DeviceId}' ({PeripheralKeys.FeatureEnabled})" });

        var mode = PeripheralModes.Audit;
        if (eff.Get(PeripheralKeys.Mode) is { } m)
        {
            var candidate = m.Value.Trim().ToLowerInvariant();
            if (PeripheralModes.All.Contains(candidate)) mode = candidate;
            else notes.Add($"peripheral control mode '{m.Value}' is not a known mode — AUDIT-ONLY applies (an unparsable mode never enforces)");
        }
        else notes.Add("no peripheral control mode set by policy — AUDIT-ONLY (the safe default; switching to enforce is an explicit, audited policy act)");

        var tracing = true;
        if (eff.Get(PeripheralKeys.Tracing) is { } tr)
        {
            if (bool.TryParse(tr.Value, out var tv)) tracing = tv;
            else notes.Add($"media tracing setting '{tr.Value}' is unparsable — tracing stays ON (an unparsable value never silently disables the evidence trail)");
        }

        var groups = new HashSet<string>(engine.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        var rules = new List<PeripheralRule>();
        if (eff.Get(PeripheralKeys.Rules) is { } raw && !string.IsNullOrWhiteSpace(raw.Value))
        {
            var droppedOverCap = 0;
            foreach (var entry in raw.Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                // D38-F11f: the cap is enforced DURING accumulation —
                // the resolved list never grows past it; entries past
                // the cap are counted and named, not parsed-then-cut.
                if (rules.Count >= PeripheralLimits.MaxRulesPerPolicy) { droppedOverCap++; continue; }
                var rule = ParseRuleEntry(entry, out var refusal);
                if (rule is null) { notes.Add(refusal!); continue; }
                if (rule.Validate(now) is { } invalid) { notes.Add(invalid + " (dropped from policy, named)"); continue; }
                var probe = new DeviceIdentity(facts.DeviceId, DeviceClasses.Storage, null, null, null, null);
                if (!rule.ScopeApplies(probe, facts.ScopeId, groups)) continue;
                rules.Add(rule);
            }
            if (droppedOverCap > 0)
                notes.Add($"policy carries more rules than the cap {PeripheralLimits.MaxRulesPerPolicy} — {droppedOverCap} excess entr{(droppedOverCap == 1 ? "y" : "ies")} dropped (named, never silently applied; rule ORDER decides what survives a cap, so keep block rules early)");
        }
        foreach (var rule in exceptionRules ?? Array.Empty<PeripheralRule>())
        {
            if (rule.Validate(now) is { } invalid) { notes.Add(invalid + " (exception rule dropped at resolution, named)"); continue; }
            if (rule.IsExpired(now)) { notes.Add($"exception rule '{rule.Id}' (request {rule.SourceRequestId}) is expired — it no longer allows anything"); continue; }
            var probe = new DeviceIdentity(facts.DeviceId, DeviceClasses.Storage, null, null, null, null);
            if (!rule.ScopeApplies(probe, facts.ScopeId, groups)) continue;
            // Machine pinning, defence in depth: an exception only
            // ever joins the resolution of ITS machine.
            if (!string.Equals(rule.ScopeId, facts.DeviceId, StringComparison.OrdinalIgnoreCase)) continue;
            rules.Add(rule);
        }
        return new ResolvedPeripheralPolicy(true, mode, tracing, rules, notes);
    }

    private static PeripheralRule? ParseRuleEntry(string entry, out string? refusal)
    {
        refusal = null;
        var parts = entry.Split(',');
        if (parts.Length < 7)
        {
            refusal = $"malformed rule entry '{entry}' — dropped (named): expected effect,kind,scopeKind,scopeId,expires,ruleId,anchor";
            return null;
        }
        var effect = parts[0].Trim().ToLowerInvariant();
        var kind = parts[1].Trim().ToLowerInvariant();
        var scopeKind = parts[2].Trim().ToLowerInvariant();
        var scopeId = parts[3].Trim();
        var expiresRaw = parts[4].Trim();
        var ruleId = parts[5].Trim();
        var anchor = string.Join(",", parts.Skip(6)).Trim();
        DateTimeOffset? expires = null;
        if (expiresRaw != "-" && expiresRaw.Length > 0)
        {
            if (!DateTimeOffset.TryParse(expiresRaw, out var parsed))
            {
                refusal = $"rule entry '{entry}' carries an unparsable expiry — dropped (named)";
                return null;
            }
            expires = parsed;
        }
        // D38-F5: policy text can NEVER author an exception.
        // Exceptions are minted only by the approval workflow
        // (PeripheralExceptionStore.Approve) — a kind=exception entry
        // in policy text bypassed the approval, the class binding
        // and the 90-day cap, so it is dropped here, named.
        if (kind == PeripheralRuleKinds.Exception)
        {
            refusal = $"rule entry '{entry}' authors kind=exception from policy text — dropped (named): exceptions are minted by the approval workflow only, never written into policy";
            return null;
        }
        string? cls = null, vid = null, pid = null, serial = null;
        if (kind == PeripheralRuleKinds.Class) cls = anchor.ToLowerInvariant();
        else if (kind == PeripheralRuleKinds.Device)
        {
            var seg = anchor.Split(':');
            if (seg.Length is 2 or 3)
            {
                // Empty segments are ABSENT anchors (serial-only
                // form "::SN"), not empty-string anchors (D38-F10).
                vid = seg[0].Trim() is { Length: > 0 } v ? v : null;
                pid = seg[1].Trim() is { Length: > 0 } p ? p : null;
                if (seg.Length == 3 && seg[2].Trim() is { Length: > 0 } s) serial = s;
            }
            else { vid = ""; pid = ""; } // invalid anchor → Validate refuses, named in notes
        }
        return new PeripheralRule(ruleId, effect, kind, cls, vid, pid, serial,
            scopeKind, scopeId, expires, null);
    }
}

public static class PeripheralDispositions
{
    public const string Allowed = "allowed";
    public const string Blocked = "blocked";
    public const string WouldBlock = "would_block";
    public const string NotControlled = "not_controlled";
}

public sealed record PeripheralDecision(
    DeviceIdentity Identity, string Disposition, PeripheralRule? MatchedRule,
    string EffectiveMode, string Reason)
{
    public string EffectiveModeLabel => PeripheralModes.Label(EffectiveMode);
    public bool ActuallyBlocked => Disposition == PeripheralDispositions.Blocked;
    public bool IsStoppedOrWouldStop =>
        Disposition is PeripheralDispositions.Blocked or PeripheralDispositions.WouldBlock;
}

/// <summary>The pure evaluator. Precedence: device/exception rank
/// beats class rank; within a rank BLOCK beats ALLOW and the
/// conflict is named. No matching rule → ALLOWED (peripherals are
/// default-allow: a machine's built-in keyboard must not die
/// because policy forgot it — the control surface is the explicit
/// block list plus exceptions). EXCEPTION: an unknown-class device
/// in ENFORCE mode is blocked by the named unknown-class guard
/// (would-block in audit) — a device hiding its class gets no pass.</summary>
public static class PeripheralEvaluator
{
    public static PeripheralDecision Evaluate(DeviceIdentity identity, ResolvedPeripheralPolicy policy, DateTimeOffset now)
    {
        if (!policy.FeatureEnabled)
            return new PeripheralDecision(identity, PeripheralDispositions.NotControlled, null, policy.Mode,
                $"peripheral control is disabled by policy — device [{identity.StrengthLabel}] is not controlled (mode label: {policy.EffectiveModeLabel})");
        var matching = policy.Rules.Where(r => r.Matches(identity, now)).ToList();
        if (matching.Count > 0)
        {
            // bd-shared-sec-2/F10: a CLONEABLE exception (VID/PID
            // only -- no serial binds the identity, and VID/PID
            // are unauthenticated values any spoofing device can
            // copy) must not override an ORG-scope block. The
            // exception rank (3) exists so a human decision about
            // an EXACT device beats a device-level block (D38-F5);
            // an org block is the fleet authority, and a
            // cloneable identity is not exact. Serial-bound
            // exceptions keep their rank against org blocks.
            if (!identity.HasSerial)
            {
                var orgBlock = matching.FirstOrDefault(r =>
                    r.Effect == PeripheralEffects.Block && r.ScopeKind == PeripheralScopes.Org);
                if (orgBlock is not null)
                    matching = matching.Where(r =>
                        !(r.Kind == PeripheralRuleKinds.Exception && r.Effect == PeripheralEffects.Allow)).ToList();
            }
            var topRank = matching.Max(r => r.Rank);
            var top = matching.Where(r => r.Rank == topRank).ToList();
            var block = top.FirstOrDefault(r => r.Effect == PeripheralEffects.Block);
            var winner = block ?? top[0];
            var conflict = block is not null && top.Any(r => r.Effect == PeripheralEffects.Allow)
                ? " (an allow rule of the SAME precedence also matched — block wins within a rank; the conflict is named, never silently resolved)"
                : "";
            if (winner.Effect == PeripheralEffects.Block)
                return policy.Mode == PeripheralModes.Enforce
                    ? new PeripheralDecision(identity, PeripheralDispositions.Blocked, winner, policy.Mode,
                        $"device [{identity.StrengthLabel}] BLOCKED by {winner.Describe()}{conflict}")
                    : new PeripheralDecision(identity, PeripheralDispositions.WouldBlock, winner, policy.Mode,
                        $"device [{identity.StrengthLabel}] WOULD be blocked by {winner.Describe()} — AUDIT-ONLY mode: the device was NOT blocked{conflict}");
            return new PeripheralDecision(identity, PeripheralDispositions.Allowed, winner, policy.Mode,
                $"device [{identity.StrengthLabel}] allowed by {winner.Describe()}");
        }
        if (identity.NormalizedClass == DeviceClasses.Unknown)
            return policy.Mode == PeripheralModes.Enforce
                ? new PeripheralDecision(identity, PeripheralDispositions.Blocked, null, policy.Mode,
                    $"device [{identity.StrengthLabel}] BLOCKED by the unknown-class guard: a device that presents no determinable class is not admitted in ENFORCE mode")
                : new PeripheralDecision(identity, PeripheralDispositions.WouldBlock, null, policy.Mode,
                    $"device [{identity.StrengthLabel}] WOULD be blocked by the unknown-class guard — AUDIT-ONLY mode: the device was NOT blocked");
        return new PeripheralDecision(identity, PeripheralDispositions.Allowed, null, policy.Mode,
            $"device [{identity.StrengthLabel}] allowed: no block rule matches (peripheral policy is default-allow; the block list is the control)");
    }
}

// ---- first-seen registry: collisions + new-HID detection -------------

public sealed record SeenOutcome(
    bool IsFirstSeen,
    bool IsIdentityCollision,
    string Detail);

/// <summary>Per-machine first-seen registry. Feeds two named
/// detections: (1) identity collision — one VID/PID identity base
/// presenting two different serials on one machine (a clone, or a
/// fleet of same-model devices — either way it is NAMED, because a
/// serial-bound rule silently covering both would be a lie);
/// (2) first-seen HID — a keyboard-class device never seen on this
/// machine before (the BadUSB shape: class rules say "HID allowed"
/// and the attack arrives AS an HID).</summary>
public sealed class PeripheralSeenRegistry
{
    private readonly Dictionary<string, HashSet<string>> _serialsByBase = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _seenKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _seenOrder = new();
    private readonly object _gate = new();

    public SeenOutcome Observe(DeviceIdentity identity)
    {
        lock (_gate)
        {
            var first = _seenKeys.Add(identity.Key);
            if (first)
            {
                _seenOrder.Enqueue(identity.Key);
                // Bounded growth (D38-F11a): FIFO eviction past the cap.
                while (_seenKeys.Count > PeripheralLimits.MaxSeenIdentities && _seenOrder.Count > 0)
                    _seenKeys.Remove(_seenOrder.Dequeue());
            }
            // D38-F9: the collision base is CLASS-INDEPENDENT
            // (machine|VID:PID) — the same VID/PID identity moving
            // between classes (storage → HID, the BadUSB transition)
            // with a different serial IS a collision and must raise.
            var baseKey = $"{identity.MachineId}|{identity.NormalizedVid}:{identity.NormalizedPid}";
            var collision = false;
            if (identity.HasSerial && identity.HasVidPid)
            {
                if (!_serialsByBase.TryGetValue(baseKey, out var serials))
                    _serialsByBase[baseKey] = serials = new HashSet<string>(StringComparer.Ordinal);
                if (serials.Count > 0 && !serials.Contains(identity.NormalizedSerial)) collision = true;
                serials.Add(identity.NormalizedSerial);
            }
            var detail = collision
                ? $"IDENTITY COLLISION on machine '{identity.MachineId}': identity base {identity.NormalizedVid}:{identity.NormalizedPid} (any class) now presents serial '{identity.NormalizedSerial}' alongside different serial(s) [{string.Join(", ", _serialsByBase[baseKey].Where(s => s != identity.NormalizedSerial))}] — two physical devices claim one VID/PID identity; serial-bound rules distinguish them, VID/PID-only rules CANNOT (cloneability, named)"
                : first
                    ? $"first-seen device on machine '{identity.MachineId}': {identity.KeyBase} [{identity.StrengthLabel}]"
                    : $"previously seen device on machine '{identity.MachineId}': {identity.KeyBase}";
            return new SeenOutcome(first, collision, detail);
        }
    }

    public bool IsFirstSeen(DeviceIdentity identity)
    {
        lock (_gate) return !_seenKeys.Contains(identity.Key);
    }
}

// ---- media tracing ----------------------------------------------------

/// <summary>Which transfer paths the tracing model can and cannot
/// see. This enumeration IS the coverage claim — nothing outside it
/// is claimed, and the cannot-see list ships in every surface.</summary>
public static class TransferPathVisibility
{
    public static readonly IReadOnlyList<string> Visible = new[]
    {
        "file copies to a mounted removable volume observed by the endpoint watcher (shell copy, xcopy/robocopy and application saves all land as filesystem events on the volume)",
        "new files appearing on a mounted removable volume between watcher polls (poll-diff catch-up, marked as inferred)",
    };
    public static readonly IReadOnlyList<string> NotVisible = new[]
    {
        "raw disk / sector-level writes below the filesystem (imaging tools writing a device directly)",
        "transfers performed while the endpoint agent is stopped or the machine is off (media written elsewhere)",
        "the CONTENTS of encrypted containers or archives written to the media (the container file itself is traced by name+size+hash; its inner files are not visible)",
        "transfers over other channels entirely (network shares, Bluetooth file transfer, cloud sync) — those are other features' surfaces, not removable-media tracing",
        "files written by a process that deletes them before the watcher poll on a poll-only volume (event-driven volumes do not have this gap; the record names which watcher mode produced it)",
    };
    public static string CoverageStatement =>
        "TRACED: " + string.Join("; ", Visible) + " || NOT TRACED (named, never claimed): " + string.Join("; ", NotVisible);
}

/// <summary>One traced record in the hash chain. Kind:
/// media_connected | media_disconnected | file_transferred.
/// A file_transferred record carries file NAME + size + SHA-256
/// ONLY — there is no content field in this model by construction
/// (content inspection is RMM-32, separately gated).</summary>
public sealed record MediaTraceRecord(
    long Seq,
    string Kind,
    string MachineId,
    string DeviceKey,
    string DeviceStrengthLabel,
    string? FileName,
    long? FileSizeBytes,
    string? FileSha256,
    string WatcherMode,
    DateTimeOffset AtUtc,
    string PrevHash,
    string Hash);

public static class MediaTraceKinds
{
    public const string Connected = "media_connected";
    public const string Disconnected = "media_disconnected";
    public const string FileTransferred = "file_transferred";
}

/// <summary>The watcher modes a trace record may claim (D38-F7:
/// the mode was unvalidated free text even though the cannot-see
/// list's honesty rests on it). event = OS filesystem events;
/// poll = watcher poll-diff; inferred = poll-diff catch-up where
/// the write itself was not observed.</summary>
public static class MediaWatcherModes
{
    public const string Event = "event";
    public const string Poll = "poll";
    public const string Inferred = "inferred";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Event, Poll, Inferred };
    public static string? Normalize(string? mode, out string normalized)
    {
        normalized = (mode ?? "").Trim().ToLowerInvariant();
        if (normalized.Length == 0) { normalized = Event; return null; }
        return All.Contains(normalized) ? null
            : $"watcher mode '{mode}' is not a known watcher mode ({string.Join(", ", All.OrderBy(m => m, StringComparer.Ordinal))}) — refused: a trace record must name honestly how it was produced";
    }
}

/// <summary>The audit-chained trace store: append-only, hash-linked,
/// verifiable. A transfer record REFUSES unless a live connection
/// for that exact device identity + machine stands in the chain —
/// a transfer trace with no connect event would be a coverage lie.</summary>
public sealed class MediaTraceStore
{
    private readonly List<MediaTraceRecord> _records = new();
    // D38-F11b: the live-connection index — RecordTransfer must not
    // rescan the whole chain per transfer (O(n) each, O(n²) overall).
    private readonly Dictionary<string, MediaTraceRecord> _liveByDevice = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    public const string GenesisHash = "GENESIS";

    public IReadOnlyList<MediaTraceRecord> Records { get { lock (_gate) return _records.ToList(); } }
    public string HeadHash { get { lock (_gate) return _records.Count == 0 ? GenesisHash : _records[^1].Hash; } }
    private static string LiveKey(DeviceIdentity device) => $"{device.MachineId}|{device.Key}";

    // D38-F7: the hash binds EVERY field the record asserts —
    // including WatcherMode and DeviceStrengthLabel, whose alteration
    // previously left VerifyChain green.
    private static string ComputeHash(long seq, string kind, string machine, string deviceKey,
        string strengthLabel, string? fileName, long? size, string? sha, string watcherMode,
        DateTimeOffset at, string prev) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{seq}|{kind}|{machine}|{deviceKey}|{strengthLabel}|{fileName}|{size}|{sha}|{watcherMode}|{at:O}|{prev}"))).ToLowerInvariant();

    private MediaTraceRecord Append(string kind, DeviceIdentity device, string? fileName,
        long? size, string? sha, string watcherMode, DateTimeOffset now)
    {
        lock (_gate)
        {
            var seq = _records.Count + 1L;
            var prev = _records.Count == 0 ? GenesisHash : _records[^1].Hash;
            var hash = ComputeHash(seq, kind, device.MachineId, device.Key, device.StrengthLabel, fileName, size, sha, watcherMode, now, prev);
            var rec = new MediaTraceRecord(seq, kind, device.MachineId, device.Key, device.StrengthLabel,
                fileName, size, sha, watcherMode, now, prev, hash);
            _records.Add(rec);
            if (kind == MediaTraceKinds.Connected) _liveByDevice[LiveKey(device)] = rec;
            else if (kind == MediaTraceKinds.Disconnected) _liveByDevice.Remove(LiveKey(device));
            return rec;
        }
    }

    public (MediaTraceRecord? Record, string Reason) RecordConnection(DeviceIdentity device, string watcherMode, DateTimeOffset now)
    {
        if (device.Validate() is { } invalid) return (null, invalid);
        if (device.NormalizedClass != DeviceClasses.Storage)
            return (null, $"media connection tracing covers storage-class devices; class '{device.NormalizedClass}' is not storage — refused (named, not silently recorded as media)");
        if (MediaWatcherModes.Normalize(watcherMode, out var mode) is { } badMode) return (null, badMode);
        var rec = Append(MediaTraceKinds.Connected, device, null, null, null, mode, now);
        return (rec, $"media connected traced at seq {rec.Seq}: {device.Key} [{device.StrengthLabel}] on machine '{device.MachineId}'");
    }

    public (MediaTraceRecord? Record, string Reason) RecordDisconnection(DeviceIdentity device, DateTimeOffset now, string watcherMode = MediaWatcherModes.Event)
    {
        // D38-F6: a disconnect is validated like every other record —
        // a valid storage identity with a LIVE connection must stand,
        // otherwise the disconnect is refused and nothing is appended.
        if (device.Validate() is { } invalid) return (null, invalid);
        if (device.NormalizedClass != DeviceClasses.Storage)
            return (null, $"media disconnection tracing covers storage-class devices; class '{device.NormalizedClass}' is not storage — refused");
        if (MediaWatcherModes.Normalize(watcherMode, out var mode) is { } badMode) return (null, badMode);
        lock (_gate)
        {
            if (!_liveByDevice.ContainsKey(LiveKey(device)))
                return (null, $"no live media connection for {device.Key} on machine '{device.MachineId}' stands in the trace chain — disconnect refused: a disconnect trace without its connect event would be a coverage lie");
        }
        var rec = Append(MediaTraceKinds.Disconnected, device, null, null, null, mode, now);
        return (rec, $"media disconnected traced at seq {rec.Seq}: {device.Key}");
    }

    /// <summary>Trace one transfer TO removable media. Metadata
    /// only: name + size + hash. The hash must be a real SHA-256 —
    /// a trace record claiming a file it cannot fingerprint is
    /// refused rather than recorded weakly.</summary>
    public (MediaTraceRecord? Record, string Reason) RecordTransfer(
        DeviceIdentity device, string? fileName, long sizeBytes, string? sha256, string watcherMode, DateTimeOffset now)
    {
        if (device.Validate() is { } invalid) return (null, invalid);
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Trim().Length > PeripheralLimits.MaxFileNameLength)
            return (null, $"a transfer trace needs a file name within {PeripheralLimits.MaxFileNameLength} characters — refused");
        if (fileName.Contains('/') || fileName.Contains('\\'))
            return (null, "a transfer trace records the file NAME, not a path — a path-bearing name is refused (the trace is metadata about the file, not a map of the user's folders)");
        if (sizeBytes < 0) return (null, "a transfer trace needs a non-negative file size — refused");
        var sha = (sha256 ?? "").Trim().ToLowerInvariant();
        if (sha.Length != 64 || !sha.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            return (null, "a transfer trace needs the file's SHA-256 (64 hex) — refused: an unfingerprinted transfer record would claim evidence it does not hold");
        if (MediaWatcherModes.Normalize(watcherMode, out var mode) is { } badMode) return (null, badMode);
        lock (_gate)
        {
            if (!_liveByDevice.ContainsKey(LiveKey(device)))
                return (null, $"no live media connection for {device.Key} on machine '{device.MachineId}' stands in the trace chain — transfer refused: a transfer trace without its connect event would be a coverage lie (the connect is traced first, or the gap is named)");
        }
        var rec = Append(MediaTraceKinds.FileTransferred, device, fileName.Trim(), sizeBytes, sha, mode, now);
        return (rec, $"transfer traced at seq {rec.Seq}: '{fileName.Trim()}' ({sizeBytes} bytes, sha256 {sha[..12]}…) to {device.Key} — metadata only, no content recorded");
    }

    public (bool Ok, string Summary) VerifyChain()
    {
        lock (_gate)
        {
            var prev = GenesisHash;
            foreach (var r in _records)
            {
                if (r.PrevHash != prev) return (false, $"BROKEN at seq {r.Seq}: prev-hash link mismatch");
                var expect = ComputeHash(r.Seq, r.Kind, r.MachineId, r.DeviceKey, r.DeviceStrengthLabel, r.FileName, r.FileSizeBytes, r.FileSha256, r.WatcherMode, r.AtUtc, r.PrevHash);
                if (r.Hash != expect) return (false, $"BROKEN at seq {r.Seq}: record hash mismatch (content altered)");
                prev = r.Hash;
            }
            return (true, $"OK: {_records.Count} trace records, chain intact, head {prev}");
        }
    }
}

// ---- block / detection events (RMM-01 sink shapes) ---------------------

public static class PeripheralAlertKind
{
    public const string Blocked = "peripheral_blocked";
    public const string IdentityCollision = "peripheral_identity_collision";
    public const string NewHid = "peripheral_new_hid";
    public static string ConditionIdFor(string kind, DeviceIdentity identity) =>
        "peripheral:" + kind + ":" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(identity.Key))).ToLowerInvariant()[..16];
}

public sealed record PeripheralEvent(
    string Kind, string MachineId, DeviceIdentity Identity, string? MatchedRuleDescription,
    string EffectiveMode, bool ActuallyBlocked, DateTimeOffset OccurredUtc, string Detail)
{
    public string EffectiveModeLabel => PeripheralModes.Label(EffectiveMode);
}

public interface IPeripheralAlertSink
{
    void Raise(PeripheralEvent peripheralEvent);
}

public sealed class RecordingPeripheralAlertSink : IPeripheralAlertSink
{
    public List<PeripheralEvent> Events { get; } = new();
    public void Raise(PeripheralEvent peripheralEvent) => Events.Add(peripheralEvent);
}

/// <summary>Production-shaped adapter into RMM-01's HealthAlertCentre.
/// Real blocks raise at warning; audit would-blocks, collisions and
/// new-HID detections at info/warning as named — severity itself
/// names whether anything was actually stopped.</summary>
public sealed class HealthAlertCentrePeripheralSink : IPeripheralAlertSink
{
    private readonly HealthAlertCentre _centre;
    public HealthAlertCentrePeripheralSink(HealthAlertCentre centre) =>
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));

    public void Raise(PeripheralEvent e)
    {
        var severity = e.Kind switch
        {
            PeripheralAlertKind.IdentityCollision => AlertSeverities.Warning,
            PeripheralAlertKind.NewHid => AlertSeverities.Warning,
            _ => e.ActuallyBlocked ? AlertSeverities.Warning : AlertSeverities.Info,
        };
        _centre.Raise(e.MachineId, PeripheralAlertKind.ConditionIdFor(e.Kind, e.Identity), e.Kind,
            severity, e.Detail, "peripheral-control", TimeSpan.Zero, e.OccurredUtc);
    }
}

// ---- enforcement seam (host wiring) ------------------------------------

public sealed record PeripheralEnforcementPlan(
    string MachineId, string EffectiveMode, IReadOnlyList<PeripheralRule> Rules, DateTimeOffset PlannedUtc)
{
    public string EffectiveModeLabel => PeripheralModes.Label(EffectiveMode);
}

public sealed record PeripheralApplyResult(bool Applied, string Detail);

/// <summary>The OS-enforcement applier seam (Windows device
/// installation restrictions + removable-storage access policy).
/// Honest by contract: an applier that cannot write OS policy
/// reports Applied=false with the reason.</summary>
public interface IPeripheralControlApplier
{
    PeripheralApplyResult Apply(PeripheralEnforcementPlan plan);
}

public sealed class UnavailablePeripheralControlApplier : IPeripheralControlApplier
{
    public PeripheralApplyResult Apply(PeripheralEnforcementPlan plan) =>
        new(false, $"no Windows device-installation-restriction / storage-access policy writer is wired on this host — plan for machine '{plan.MachineId}' ({plan.Rules.Count} rules, mode {plan.EffectiveModeLabel}) was computed but NOT applied (named remainder: host wiring)");
}

public sealed class RecordingPeripheralControlApplier : IPeripheralControlApplier
{
    public List<PeripheralEnforcementPlan> Plans { get; } = new();
    public PeripheralApplyResult Apply(PeripheralEnforcementPlan plan)
    {
        Plans.Add(plan);
        return new PeripheralApplyResult(true, $"applied {plan.Rules.Count} rules to machine {plan.MachineId} (mode {plan.EffectiveModeLabel})");
    }
}

// ---- the exception (access-request) workflow ---------------------------

public static class PeripheralRequestStates
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
}

public sealed record PeripheralAccessRequest(
    string Id,
    string MachineId,
    string Requester,
    DeviceIdentity Identity,
    string BusinessReason,
    string State,
    DateTimeOffset CreatedUtc,
    string? DecidedBy,
    DateTimeOffset? DecidedUtc,
    string? DecisionReason,
    string? MintedRuleId,
    // bd-shared-sec-2/F10: the filer's AUTHENTICATED principal
    // id, stamped at filing when the channel supplies one (the
    // sec-1/F4 AppControl pattern). Decisions compare the
    // approver's principal against THIS -- previously Approve
    // compared a registered principal id against the free-text
    // display name in Requester, two different kinds of
    // identifier, so the self-approval check could never fire
    // on the principal axis.
    string? RequesterPrincipal = null);

/// <summary>The exception store: RMM-25's filing/decision discipline
/// narrowed to this lane's contract — an approval mints an ALLOW
/// rule binding the EXACT requested identity (VID/PID + serial when
/// offered) on the REQUESTING MACHINE ONLY, with a mandatory
/// bounded expiry. Class scope, org scope, group scope and
/// other-machine scope all refuse at decision time: there is no
/// widening parameter.</summary>
public sealed class PeripheralExceptionStore
{
    private readonly Dictionary<string, PeripheralAccessRequest> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, PeripheralRule> _rulesById = new(StringComparer.Ordinal);
    private readonly HashSet<string> _approverPrincipals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>Register an approver PRINCIPAL (D38-F4, FL-25b
    /// pattern): decisions are made by a principal id carrying an
    /// approver role, never by any caller-supplied free-text name.
    /// With NO principals registered, every decision refuses —
    /// fail closed.</summary>
    public void RegisterApproverPrincipal(string principalId)
    {
        if (string.IsNullOrWhiteSpace(principalId)) return;
        lock (_gate) _approverPrincipals.Add(principalId.Trim());
    }

    public IReadOnlyList<string> ApproverPrincipals
    {
        get { lock (_gate) return _approverPrincipals.OrderBy(p => p, StringComparer.Ordinal).ToList(); }
    }

    private string? PrincipalRefusal(string? actor, string verb)
    {
        if (_approverPrincipals.Count == 0)
            return $"no approver principals are registered — {verb} refused (fail closed: a decision must come from a registered approver principal, never a free-text name)";
        if (string.IsNullOrWhiteSpace(actor) || !_approverPrincipals.Contains(actor.Trim()))
            return $"'{actor}' is not a registered approver principal — {verb} refused (decisions are made by principal id with an approver role, not by any caller-supplied name)";
        return null;
    }

    public IReadOnlyList<PeripheralAccessRequest> Requests
    {
        get { lock (_gate) return _byId.Values.OrderBy(r => r.CreatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal).ToList(); }
    }

    public PeripheralAccessRequest? Get(string? id)
    {
        lock (_gate) return id is not null && _byId.TryGetValue(id, out var r) ? r : null;
    }

    public (PeripheralAccessRequest? Request, bool Created, string Reason) File(
        string? authenticatedMachineId, string? claimedMachineId, string requestId,
        string? requester, DeviceIdentity? identity, string? businessReason, DateTimeOffset now,
        string? authenticatedRequesterPrincipal = null)
    {
        // bd-shared-sec-2/F10: stamp the authenticated requester
        // principal when the channel supplies one (validated like
        // any principal id); decisions refuse self-approval on it.
        if (authenticatedRequesterPrincipal is not null &&
            (string.IsNullOrWhiteSpace(authenticatedRequesterPrincipal) ||
             authenticatedRequesterPrincipal.Trim().Length > PeripheralLimits.MaxActorLength))
            return (null, false, "the authenticated requester principal is out of bounds — refused");
        if (string.IsNullOrWhiteSpace(authenticatedMachineId))
            return (null, false, "the request arrived on no authenticated machine channel — refused");
        if (string.IsNullOrWhiteSpace(requestId)) return (null, false, "the request carries no request id — refused");
        if (identity is null) return (null, false, "the request names no device identity — refused");
        if (identity.Validate() is { } invalid) return (null, false, invalid);
        if (!string.Equals((claimedMachineId ?? "").Trim(), authenticatedMachineId.Trim(), StringComparison.OrdinalIgnoreCase))
            return (null, false, $"the request claims machine '{claimedMachineId}' but arrived on the authenticated channel of '{authenticatedMachineId}' — refused as a spoofed machine context; no request recorded");
        if (!string.Equals(identity.MachineId, authenticatedMachineId.Trim(), StringComparison.OrdinalIgnoreCase))
            return (null, false, $"the device identity names machine '{identity.MachineId}' inside a request for '{authenticatedMachineId}' — refused (a request speaks for its own machine only)");
        if (string.IsNullOrWhiteSpace(requester) || requester.Trim().Length > PeripheralLimits.MaxActorLength)
            return (null, false, "a request needs a requester name within bounds — refused");
        if (string.IsNullOrWhiteSpace(businessReason) || businessReason.Trim().Length > PeripheralLimits.MaxReasonLength)
            return (null, false, $"a request needs a business reason within {PeripheralLimits.MaxReasonLength} characters — refused (no reason, no request)");
        lock (_gate)
        {
            if (_byId.TryGetValue(requestId, out var existing))
            {
                // D38-F3: request IDs are caller-supplied, so the
                // namespace must not leak across machines — another
                // machine's filing under a taken ID is REFUSED and
                // gets NOTHING of the standing request back (no
                // identity, requester or reason crosses the boundary).
                if (!string.Equals(existing.MachineId, authenticatedMachineId.Trim(), StringComparison.OrdinalIgnoreCase))
                    return (null, false, $"request id '{requestId}' is already in use on another machine — refused: request ids do not cross machine boundaries and no detail of the standing request is disclosed");
                return (existing, false, $"request '{requestId}' already stands (idempotent filing)");
            }
            var standing = _byId.Values.FirstOrDefault(r =>
                r.State == PeripheralRequestStates.Pending &&
                string.Equals(r.MachineId, authenticatedMachineId, StringComparison.OrdinalIgnoreCase) &&
                r.Identity.Key == identity.Key);
            if (standing is not null)
                return (standing, false, $"a pending request '{standing.Id}' already covers this device on machine '{authenticatedMachineId}' — the standing request is returned, no duplicate minted");
            var pendingForMachine = _byId.Values.Count(r => r.State == PeripheralRequestStates.Pending &&
                string.Equals(r.MachineId, authenticatedMachineId, StringComparison.OrdinalIgnoreCase));
            if (pendingForMachine >= PeripheralLimits.MaxPendingRequestsPerMachine)
                return (null, false, $"pending-request cap ({PeripheralLimits.MaxPendingRequestsPerMachine}) reached for machine '{authenticatedMachineId}' — request refused (flood discipline, counted not silent)");
            var recentByRequester = _byId.Values.Count(r =>
                string.Equals(r.Requester, requester.Trim(), StringComparison.OrdinalIgnoreCase) &&
                now - r.CreatedUtc < TimeSpan.FromHours(1));
            if (recentByRequester >= PeripheralLimits.MaxRequestsPerRequesterPerHour)
                return (null, false, $"requester '{requester.Trim()}' has filed {recentByRequester} requests in the last hour (cap {PeripheralLimits.MaxRequestsPerRequesterPerHour}) — request refused (flood discipline)");
            var request = new PeripheralAccessRequest(
                requestId, authenticatedMachineId.Trim(), requester.Trim(), identity,
                businessReason.Trim(), PeripheralRequestStates.Pending, now,
                null, null, null, null,
                authenticatedRequesterPrincipal?.Trim());
            _byId[requestId] = request;
            return (request, true, $"request '{requestId}' filed for device [{identity.StrengthLabel}] {identity.KeyBase} on machine '{authenticatedMachineId}'");
        }
    }

    /// <summary>Approve, minting the machine-pinned exception rule.
    /// THE ANTI-WIDENING CONTRACT: scope is not a parameter — the
    /// rule's scope is ALWAYS device-scope on the requesting
    /// machine; its anchors are ALWAYS the requested identity's
    /// VID/PID (+ serial when offered, + the class recorded on the
    /// rule's Class field, which PeripheralRule.Matches enforces so
    /// a class-re-presentation does not inherit the exception).
    /// Expiry mandatory, ≤ 90 days. The approver must be a
    /// REGISTERED approver principal (D38-F4). Self-approval
    /// refuses.</summary>
    public (PeripheralAccessRequest? Request, PeripheralRule? Rule, string Reason) Approve(
        string requestId, string? approver, DateTimeOffset? expiresUtc, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(approver) || approver.Trim().Length > PeripheralLimits.MaxActorLength)
            return (null, null, "an approval needs an approver name within bounds — refused");
        lock (_gate)
        {
            if (!_byId.TryGetValue(requestId ?? "", out var request))
                return (null, null, $"unknown request '{requestId}' — approval refused");
            if (request.State != PeripheralRequestStates.Pending)
                return (null, null, $"request '{requestId}' is already {request.State} — decisions are terminal and singular");
            if (string.Equals(approver.Trim(), request.Requester, StringComparison.OrdinalIgnoreCase))
                return (null, null, $"request '{requestId}' cannot be approved by its own requester '{request.Requester}' — a request can never self-approve");
            // bd-shared-sec-2/F10: principal-axis self-approval --
            // the approver IS a registered principal (checked next),
            // so compare principal to principal: the filer's
            // stamped authenticated principal.
            if (request.RequesterPrincipal is { } requesterPrincipal &&
                string.Equals(approver.Trim(), requesterPrincipal, StringComparison.OrdinalIgnoreCase))
                return (null, null, $"request '{requestId}' cannot be approved by its own requester principal '{requesterPrincipal}' — a request can never self-approve (the filing display name is not the identity; the stamped principal is)");
            if (PrincipalRefusal(approver, "approval") is { } principalRefusal)
                return (null, null, principalRefusal);
            if (expiresUtc is null)
                return (null, null, "an approval MUST carry an expiry — refused: exceptions are not permanent");
            if (expiresUtc.Value <= now)
                return (null, null, "the approval expiry is not in the future — refused");
            if (expiresUtc.Value - now > PeripheralLimits.MaxExceptionDuration)
                return (null, null, $"the approval expiry exceeds the maximum exception lifetime ({PeripheralLimits.MaxExceptionDuration.TotalDays:0} days) — refused, never clamped");
            var identity = request.Identity;
            var rule = new PeripheralRule(
                Id: "exception-" + request.Id,
                Effect: PeripheralEffects.Allow,
                Kind: PeripheralRuleKinds.Exception,
                Class: identity.NormalizedClass,
                VendorId: identity.NormalizedVid.Length > 0 ? identity.NormalizedVid : null,
                ProductId: identity.NormalizedPid.Length > 0 ? identity.NormalizedPid : null,
                Serial: identity.HasSerial ? identity.NormalizedSerial : null,
                ScopeKind: PeripheralScopes.Device, ScopeId: request.MachineId,
                ExpiresUtc: expiresUtc.Value,
                SourceRequestId: request.Id);
            if (rule.Validate(now) is { } invalid) return (null, null, invalid);
            _rulesById[rule.Id] = rule;
            var decided = request with
            {
                State = PeripheralRequestStates.Approved,
                DecidedBy = approver.Trim(), DecidedUtc = now,
                DecisionReason = $"approved; machine-pinned exception minted as rule '{rule.Id}' ({rule.StrengthLabel}) for class '{identity.NormalizedClass}'",
                MintedRuleId = rule.Id,
            };
            _byId[request.Id] = decided;
            return (decided, rule, $"request '{requestId}' approved by {approver.Trim()}; exception rule '{rule.Id}' minted for the exact requested identity on machine '{request.MachineId}' ONLY, expiring {expiresUtc.Value:O} — it cannot bless another device, another machine, another class presentation, or outlive its expiry");
        }
    }

    public (PeripheralAccessRequest? Request, string Reason) Deny(
        string requestId, string? denier, string? reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(denier)) return (null, "a denial needs a named decider — refused");
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length > PeripheralLimits.MaxReasonLength)
            return (null, $"a denial must record its reason within {PeripheralLimits.MaxReasonLength} characters — refused (denial is recorded WITH reason, never silently)");
        lock (_gate)
        {
            if (PrincipalRefusal(denier, "denial") is { } principalRefusal)
                return (null, principalRefusal);
            if (!_byId.TryGetValue(requestId ?? "", out var request))
                return (null, $"unknown request '{requestId}' — denial refused");
            if (request.State != PeripheralRequestStates.Pending)
                return (null, $"request '{requestId}' is already {request.State} — decisions are terminal and singular");
            if (string.Equals(denier.Trim(), request.Requester, StringComparison.OrdinalIgnoreCase))
                return (null, $"request '{requestId}' cannot be decided by its own requester '{request.Requester}' — refused");
            if (request.RequesterPrincipal is { } denierPrincipal &&
                string.Equals(denier.Trim(), denierPrincipal, StringComparison.OrdinalIgnoreCase))
                return (null, $"request '{requestId}' cannot be decided by its own requester principal '{denierPrincipal}' — refused (bd-shared-sec-2/F10)");
            var decided = request with
            {
                State = PeripheralRequestStates.Denied,
                DecidedBy = denier.Trim(), DecidedUtc = now,
                DecisionReason = reason.Trim(),
            };
            _byId[request.Id] = decided;
            return (decided, $"request '{requestId}' denied by {denier.Trim()}: {reason.Trim()}");
        }
    }

    public IReadOnlyList<PeripheralRule> LiveExceptionRules(DateTimeOffset now)
    {
        lock (_gate) return _rulesById.Values.Where(r => !r.IsExpired(now))
            .OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
    }

    public IReadOnlyList<PeripheralRule> AllExceptionRules
    {
        get { lock (_gate) return _rulesById.Values.OrderBy(r => r.Id, StringComparer.Ordinal).ToList(); }
    }
}

// D38-F12: the former ExceptionMatch.MatchesWithClass helper was
// dead code duplicating the class check inside PeripheralRule.Matches
// (with different null-Class handling). It is removed — the class
// binding for exception rules lives ONLY in PeripheralRule.Matches.

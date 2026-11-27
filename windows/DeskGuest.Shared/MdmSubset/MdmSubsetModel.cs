namespace DeskGuest.Shared.MdmSubset;

// =====================================================================
// RMM-31 — MDM subset for DeskGuest-enrolled phones/tablets.
//
// HONEST SUBSET. The phone/tablet is ALREADY an DeskGuest endpoint (existing
// enrollment — no second MDM enrollment is built here). This layers
// management facts, policy restrictions and bounded actions onto it.
//
// THREE-TIER HONESTY (structural, per restriction): every restriction
// is labelled for THIS device's ownership as
//   enforce    — platform can apply it without the user's cooperation
//   detect     — platform can only CHECK and report non-compliance
//   impossible — platform cannot do it at all in this ownership shape
// DeskGuest's direct-distribution shape means most phones are NOT
// device-owner, so most restrictions are detect/impossible there.
// The model never upgrades a tier: compliance output preserves the
// tier verbatim (detection is not enforcement — RMM-09 honesty).
//
// LOCATE READING (stated for D38): the register says "No location
// tracking (that's §5)" and class-(c) excludes "Continuous location
// tracking / geofencing". It does NOT exclude a one-shot locate.
// Maximum built: one-shot locate on explicit admin request, with
// device-side notice BEFORE the fix, audit, a minimum interval and
// a daily cap. D38 FIX (F2): those limits have HARD CEILINGS in
// MdmLimits that policy cannot move — the interval can never go
// below the floor and the daily cap can never exceed the ceiling,
// and the cap counts a ROLLING 24 hours, so policy alone cannot
// turn this into de-facto tracking. Continuous tracking /
// geofencing: no API at all. NO LOCATION RESULT IS MODELLED OR
// RETAINED HERE (D38 F3): there is no coordinate type, no fix
// store, no retention — a locate outcome carries only the
// executor's detail string; whatever the on-device executor does
// with a fix stays on the device side of that seam.
//
// PUSH TRANSIT named honestly: platform-push shape transits APNs/FCM
// (platform fact, named in-product); self-hosted shape rides DeskGuest's
// own transports and a sleeping phone may not receive a command
// until it wakes — stated, never smoothed.
//
// ACTIONS ride RMM-03 signed commands (class background_action,
// payload-bound), require a device-side notice record created BEFORE
// execution, and are audited. Wipe has two scopes that never blur:
// DeskGuest-data wipe (always available) vs full-device wipe (device-owner
// only; impossible otherwise — refused, not downgraded silently:
// the refusal names that only an DeskGuest-data wipe is available).
// =====================================================================

public static class MdmKeys
{
    /// <summary>RMM-07 seeded toggle. NOTE: the registry seeds it
    /// DEFAULT OFF (push-transit caveat) — this lane follows the
    /// registry as built, not any summary of it.</summary>
    public const string FeatureEnabled = "rmm.mdm.enabled";
    /// <summary>Comma-separated desired restriction ids.</summary>
    public const string Restrictions = "rmm.mdm.restrictions";
    public const string LocateMinIntervalMinutes = "rmm.mdm.locate_min_interval_minutes";
    public const string LocateMaxPerDay = "rmm.mdm.locate_max_per_day";
}

public static class MdmPlatforms
{
    public const string Android = "android";
    public const string Ios = "ios";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Android, Ios };
}

public static class MdmOwnership
{
    public const string DeviceOwner = "device_owner";
    public const string ProfileOwner = "profile_owner";
    public const string Personal = "personal_no_owner";
    public const string Unknown = "unknown";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { DeviceOwner, ProfileOwner, Personal, Unknown };
}

public static class MdmTiers
{
    public const string Enforce = "enforce";
    public const string Detect = "detect";
    public const string Impossible = "impossible";
    public static string Label(string tier) => tier switch
    {
        Enforce => "ENFORCE (the platform applies this on this device)",
        Detect => "DETECT-ONLY (non-compliance can be checked and reported; the platform does NOT apply this on this device)",
        _ => "IMPOSSIBLE on this device (the platform cannot do this in this ownership shape — not offered as a capability)",
    };
}

public static class ScreenLockStrengths
{
    public const string None = "none";
    public const string Swipe = "swipe";
    public const string PinPattern = "pin_pattern";
    public const string Password = "password";
    public const string BiometricStrong = "biometric_strong";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { None, Swipe, PinPattern, Password, BiometricStrong };
    public static int Rank(string s) => s switch { None => 0, Swipe => 1, PinPattern => 2, Password => 3, BiometricStrong => 4, _ => -1 };
}

/// <summary>One mobile device's management-relevant facts, reported
/// by the enrolled DeskGuest endpoint itself (RMM-04 inventory shape).
/// Encryption uses RMM-18's tri-state honesty: Encrypted is true
/// only when the platform reports encryption ON; null = not known.</summary>
public sealed record MdmDeviceState(
    string DeviceId,
    string ScopeId,
    string Platform,
    string Ownership,
    string OsVersion,
    bool? EncryptionOn,
    string ScreenLock,
    string DeskGuestAppVersion,
    IReadOnlyList<string> ManagedApps,
    IReadOnlyList<string> AppliedRestrictions,
    DateTimeOffset ReportedUtc)
{
    public IReadOnlyList<string> ManagedApps { get; init; } = ManagedApps ?? Array.Empty<string>();
    public IReadOnlyList<string> AppliedRestrictions { get; init; } = AppliedRestrictions ?? Array.Empty<string>();
    // D38 FIX (F6): ownership is normalised EVERYWHERE it is compared
    // — a raw comparison here disagreed with the lowercased tier
    // lookup, so 'Device_Owner' was refused full wipe yet allowed
    // passcode reset.
    public bool IsDeviceOwner => string.Equals((Ownership ?? "").Trim(), MdmOwnership.DeviceOwner, StringComparison.OrdinalIgnoreCase);

    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(DeviceId)) return "MDM device state needs a device id — refused";
        if (string.IsNullOrWhiteSpace(ScopeId)) return "MDM device state needs a scope id — refused";
        if (!MdmPlatforms.All.Contains((Platform ?? "").Trim().ToLowerInvariant())) return $"unknown MDM platform '{Platform}' — refused";
        if (!MdmOwnership.All.Contains((Ownership ?? "").Trim().ToLowerInvariant())) return $"unknown MDM ownership '{Ownership}' — refused";
        if (!ScreenLockStrengths.All.Contains((ScreenLock ?? "").Trim().ToLowerInvariant())) return $"unknown screen-lock strength '{ScreenLock}' — refused";
        if (ReportedUtc > now.AddMinutes(5)) return "MDM device state is future-dated — refused (a future report cannot prove present compliance)";
        // NOTE (D38 FIX F11): an earlier comment here claimed kiosk /
        // full-wipe-capable markers are "hard-refused" in this method.
        // They are not — the capability-inflation wall is the SERVICE's
        // per-restriction tier check in ReportState. This method only
        // validates the report's own shape.
        return null;
    }

    public bool IsStale(DateTimeOffset now) => now - ReportedUtc > MdmLimits.StateFreshness;
}

public static class MdmLimits
{
    public static readonly TimeSpan StateFreshness = TimeSpan.FromHours(24);
    public static readonly TimeSpan MaxCommandTtl = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan DefaultLocateMinInterval = TimeSpan.FromMinutes(15);
    public const int DefaultLocateMaxPerDay = 6;
    // D38 FIX (F2) — HARD ANTI-TRACKING CEILINGS. Policy may tighten
    // locate limits but can NEVER loosen them past these: the minimum
    // interval has a floor and the per-24h cap has a ceiling, enforced
    // in the limiter itself (not only where policy is read), so no
    // caller can turn one-shot locate into polling-as-tracking.
    public static readonly TimeSpan LocateMinIntervalFloor = TimeSpan.FromMinutes(15);
    public const int LocateMaxPer24hCeiling = 6;
    public static readonly TimeSpan LocateWindow = TimeSpan.FromHours(24);
    /// <summary>D38 FIX (F4): a command issued further in the future
    /// than this skew is refused — it must never run before its
    /// issue time.</summary>
    public static readonly TimeSpan MaxCommandFutureSkew = TimeSpan.FromMinutes(5);
    /// <summary>D38 FIX (F9): a device-side notice must SAY something
    /// a person on the device can read — a token like "." is not a
    /// notice.</summary>
    public const int MinNoticeLength = 10;
    // D38 FIX (F12) — growth bounds: retained notices, tracked device
    // states. Nothing in this lane grows without bound any more.
    public const int MaxRetainedNotices = 256;
    public const int MaxTrackedStates = 4096;
    public const int MaxManagedApps = 512;
}

/// <summary>One restriction definition with its per-ownership tier.
/// The tier table IS the honesty surface — D38's attack surface.</summary>
public sealed record MdmRestrictionDef(
    string Id, string Name, string Description,
    string TierDeviceOwner, string TierProfileOwner, string TierPersonal)
{
    // D38 FIX (F6): the ownership argument is normalised here so
    // EVERY caller compares tiers the same way.
    public string TierFor(string ownership) => (ownership ?? "").Trim().ToLowerInvariant() switch
    {
        MdmOwnership.DeviceOwner => TierDeviceOwner,
        MdmOwnership.ProfileOwner => TierProfileOwner,
        MdmOwnership.Personal => TierPersonal,
        _ => MdmTiers.Impossible, // unknown ownership claims nothing
    };
}

public static class MdmRestrictions
{
    public static readonly IReadOnlyList<MdmRestrictionDef> All = new[]
    {
        new MdmRestrictionDef("require_encryption", "Require device encryption",
            "Device storage encryption must be on",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Detect),
        new MdmRestrictionDef("require_screen_lock", "Require screen lock (PIN/pattern or stronger)",
            "A screen lock of at least PIN/pattern strength must be set",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Detect),
        new MdmRestrictionDef("prevent_deskguest_removal", "Prevent removal of the DeskGuest app",
            "The DeskGuest endpoint app cannot be uninstalled by the device user",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Impossible),
        new MdmRestrictionDef("managed_app_install", "Install managed apps silently",
            "Push app installs without a per-install user prompt",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Impossible),
        new MdmRestrictionDef("managed_app_remove", "Remove managed apps silently",
            "Remove managed apps without a per-removal user prompt",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Impossible),
        new MdmRestrictionDef("kiosk_mode", "Kiosk mode (single-app / locked task)",
            "Pin the device to a managed app set (site tablets)",
            MdmTiers.Enforce, MdmTiers.Impossible, MdmTiers.Impossible),
        new MdmRestrictionDef("wifi_vpn_profile", "Push Wi-Fi / VPN profiles",
            "Deliver network profiles as managed configuration",
            MdmTiers.Enforce, MdmTiers.Enforce, MdmTiers.Impossible),
        new MdmRestrictionDef("passcode_reset", "Reset device passcode",
            "Admin-initiated passcode reset",
            MdmTiers.Enforce, MdmTiers.Impossible, MdmTiers.Impossible),
    };

    public static MdmRestrictionDef? For(string id) =>
        All.FirstOrDefault(r => string.Equals(r.Id, (id ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal));
}

/// <summary>Compliance verdicts — wording preserves the tier:
/// a detect-tier pass/fail is DETECTED, never "enforced".</summary>
public static class MdmComplianceOutcomes
{
    public const string EnforcedCompliant = "enforced_compliant";
    public const string EnforcementMissing = "enforcement_missing";
    public const string DetectedCompliant = "detected_compliant";
    public const string DetectedNonCompliant = "detected_noncompliant";
    public const string ImpossibleNotApplicable = "impossible_not_applicable";
    public const string UnknownStaleState = "unknown_stale_state";
    /// <summary>D38 FIX (F8): the reported facts cannot tell (e.g.
    /// tri-state encryption is null) on FRESH state. This is not
    /// staleness and is never labelled as such.</summary>
    public const string UnknownFactsMissing = "unknown_facts_missing";
}

public sealed record MdmComplianceVerdict(
    string RestrictionId, string Tier, string Outcome, string Detail)
{
    public string TierLabel => MdmTiers.Label(Tier);
    /// <summary>True only for a genuinely satisfied restriction.
    /// An impossible restriction is NEVER satisfied-by-absence.</summary>
    public bool IsSatisfied => Outcome is MdmComplianceOutcomes.EnforcedCompliant or MdmComplianceOutcomes.DetectedCompliant;
}

public static class MdmComplianceEvaluator
{
    /// <summary>Does the reported state satisfy this restriction's
    /// SUBSTANCE (independent of tier)? Null = cannot tell.</summary>
    public static bool? SubstanceHolds(MdmRestrictionDef def, MdmDeviceState state) => def.Id switch
    {
        "require_encryption" => state.EncryptionOn,
        "require_screen_lock" => ScreenLockStrengths.Rank((state.ScreenLock ?? "").Trim().ToLowerInvariant()) >= ScreenLockStrengths.Rank(ScreenLockStrengths.PinPattern),
        // For enforce-tier restrictions substance = the platform reports it applied.
        _ => state.AppliedRestrictions.Contains(def.Id, StringComparer.OrdinalIgnoreCase) ? true : false,
    };

    public static MdmComplianceVerdict Evaluate(MdmRestrictionDef def, MdmDeviceState state, DateTimeOffset now)
    {
        var tier = def.TierFor((state.Ownership ?? "").Trim().ToLowerInvariant());
        if (state.IsStale(now))
            return new(def.Id, tier, MdmComplianceOutcomes.UnknownStaleState,
                $"device state for '{state.DeviceId}' is stale (reported {state.ReportedUtc:O}) — compliance UNKNOWN, never inferred from old facts [{MdmTiers.Label(tier)}]");
        if (tier == MdmTiers.Impossible)
            return new(def.Id, tier, MdmComplianceOutcomes.ImpossibleNotApplicable,
                $"restriction '{def.Id}' is IMPOSSIBLE on device '{state.DeviceId}' (ownership {state.Ownership}) — it is not applied, not detected, and not counted as satisfied");
        var holds = SubstanceHolds(def, state);
        if (tier == MdmTiers.Enforce)
        {
            if (def.Id is "require_encryption" or "require_screen_lock")
            {
                // D38 FIX (F8): tri-state facts can be UNKNOWN (null) —
                // that is unknown, not "enforcement missing".
                if (holds is null)
                    return new(def.Id, tier, MdmComplianceOutcomes.UnknownFactsMissing, $"restriction '{def.Id}' on '{state.DeviceId}': the reported facts cannot tell (unknown) — compliance UNKNOWN, never guessed");
                return holds == true
                    ? new(def.Id, tier, MdmComplianceOutcomes.EnforcedCompliant, $"restriction '{def.Id}' ENFORCED and the reported state satisfies it on '{state.DeviceId}'")
                    : new(def.Id, tier, MdmComplianceOutcomes.EnforcementMissing, $"restriction '{def.Id}' is enforce-tier on '{state.DeviceId}' but the reported state does NOT satisfy it — enforcement missing/failed, named (not reported as compliant)");
            }
            return state.AppliedRestrictions.Contains(def.Id, StringComparer.OrdinalIgnoreCase)
                ? new(def.Id, tier, MdmComplianceOutcomes.EnforcedCompliant, $"restriction '{def.Id}' ENFORCED: the platform reports it applied on '{state.DeviceId}'")
                : new(def.Id, tier, MdmComplianceOutcomes.EnforcementMissing, $"restriction '{def.Id}' is enforce-tier on '{state.DeviceId}' but the platform does NOT report it applied — enforcement missing, named");
        }
        // detect tier
        return holds switch
        {
            true => new(def.Id, tier, MdmComplianceOutcomes.DetectedCompliant, $"restriction '{def.Id}' DETECTED compliant on '{state.DeviceId}' — detection only: DeskGuest did not apply this and does not claim enforcement"),
            false => new(def.Id, tier, MdmComplianceOutcomes.DetectedNonCompliant, $"restriction '{def.Id}' DETECTED NON-COMPLIANT on '{state.DeviceId}' — detection only: DeskGuest cannot apply this on a {state.Ownership} device; the finding is a report, not an enforcement"),
            null => new(def.Id, tier, MdmComplianceOutcomes.UnknownFactsMissing, $"restriction '{def.Id}' on '{state.DeviceId}': the reported facts cannot tell (unknown) — compliance UNKNOWN, never guessed"),
        };
    }
}

// ---- push transit ------------------------------------------------------

public sealed record MdmTransport(string Id, string Label, bool AllowedInSelfHosted, bool AllowedInPlatformShape, string HonestNote);

public static class MdmTransports
{
    public static readonly MdmTransport PlatformPush = new(
        "platform_push_apns_fcm", "Platform push (Apple APNs / Google FCM)",
        false, true,
        "PLATFORM FACT, named in-product: in the platform-push shape, commands transit Apple APNs / Google FCM by OS design. Command metadata transits Apple/Google. This is the register's recorded caveat for RMM-31.");
    public static readonly MdmTransport DeskGuestDirect = new(
        "deskguest_direct", "DeskGuest direct (the endpoint's own DeskGuest transport to the user's hub)",
        true, true,
        "No third party transits the command. LATENCY HONESTY: a sleeping or offline phone may not receive the command until it wakes / reconnects — delivery is not instant and the model never claims it is.");
    public static readonly MdmTransport UserRelay = new(
        "user_owned_relay", "User-owned relay",
        true, true, "The relay is the user's own infrastructure; DeskGuest ships no relay of its own.");

    public static readonly IReadOnlyList<MdmTransport> All = new[] { PlatformPush, DeskGuestDirect, UserRelay };
    public static MdmTransport? For(string id) => All.FirstOrDefault(t => string.Equals(t.Id, id ?? "", StringComparison.OrdinalIgnoreCase));
}

// ---- actions -----------------------------------------------------------

public static class MdmActionKinds
{
    public const string Lock = "lock_device";
    public const string LocateOnce = "locate_once";
    public const string WipeDeskGuestData = "wipe_deskguest_data";
    public const string WipeFullDevice = "wipe_full_device";
    public const string PasscodeReset = "passcode_reset";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Lock, LocateOnce, WipeDeskGuestData, WipeFullDevice, PasscodeReset };
    // Deliberately ABSENT: locate_continuous / geofence / track — no
    // constant, no API. Their absence is the exclusion, structural.
}

/// <summary>The ONLY data an DeskGuest-data wipe may touch. Any target
/// outside this set is scope creep and refuses at construction of
/// the command payload (service-enforced, tested).</summary>
public static class DeskGuestWipeTargets
{
    public const string AppData = "deskguest_app_data";
    public const string Credentials = "deskguest_credentials";
    public const string Cache = "deskguest_cache";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { AppData, Credentials, Cache };
}

public sealed record MdmActionRequest(
    string CommandId, string DeviceId, string Kind,
    IReadOnlyList<string> WipeTargets,
    string NoticeText,
    DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc)
{
    public IReadOnlyList<string> WipeTargets { get; init; } = WipeTargets ?? Array.Empty<string>();

    // D38 FIX (F6): ONE normalisation for kind and targets, used by
    // validation, the canonical payload and (via the service) the
    // executor — previously kind was lowercased for membership but
    // compared RAW for the wipe rules, so 'WIPE_DESKGUEST_DATA' skipped
    // the target rules entirely, and a null target threw.
    public string NormalizedKind => (Kind ?? "").Trim().ToLowerInvariant();
    public IReadOnlyList<string> NormalizedTargets =>
        WipeTargets.Select(t => (t ?? "").Trim().ToLowerInvariant()).ToList();

    /// <summary>Canonical signed payload bytes: the RMM-03 envelope
    /// binds exactly this string, so any field change breaks the hash.</summary>
    public string CanonicalPayload() =>
        string.Join("|", "deskguest-mdm-action-v1", CommandId, DeviceId, NormalizedKind,
            string.Join(",", NormalizedTargets.OrderBy(t => t, StringComparer.Ordinal)),
            NoticeText, IssuedUtc.ToString("O"), ExpiresUtc.ToString("O"));

    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(CommandId)) return "an MDM action needs a command id — refused";
        if (string.IsNullOrWhiteSpace(DeviceId)) return "an MDM action needs a device id — refused";
        var kind = NormalizedKind;
        if (!MdmActionKinds.All.Contains(kind))
            return $"unknown MDM action kind '{Kind}' — refused (continuous location tracking has no kind here by design)";
        if (string.IsNullOrWhiteSpace(NoticeText))
            return "an MDM action needs device-side notice text — refused: a lock/wipe/locate with no on-device trace violates the no-hidden-operation law";
        // D38 FIX (F9): whitespace was the only bar — "." passed as a
        // 'notice'. A notice must be readable text of substance.
        if (NoticeText.Trim().Length < MdmLimits.MinNoticeLength)
            return $"an MDM action notice must be readable text of at least {MdmLimits.MinNoticeLength} characters — refused: a token mark is not a device-side notice";
        if (ExpiresUtc <= IssuedUtc) return "an MDM action expiry must follow its issuance — refused";
        if (ExpiresUtc - IssuedUtc > MdmLimits.MaxCommandTtl)
            return $"an MDM action TTL exceeds the freshness cap ({MdmLimits.MaxCommandTtl.TotalMinutes:0} minutes) — refused: a stale lock/wipe must never execute late";
        if (ExpiresUtc <= now) return "this MDM action has EXPIRED — refused: stale commands do not execute";
        // D38 FIX (F4): a command issued in the future (beyond clock
        // skew) must never execute before its issue time.
        if (IssuedUtc > now.Add(MdmLimits.MaxCommandFutureSkew))
            return "this MDM action is issued in the FUTURE — refused: a command never executes before its issue time";
        var targets = NormalizedTargets;
        if (kind == MdmActionKinds.WipeDeskGuestData)
        {
            if (targets.Count == 0) return "an DeskGuest-data wipe needs at least one DeskGuest wipe target — refused";
            foreach (var t in WipeTargets)
            {
                if (t is null) return "a wipe target is null — refused (a malformed target list proves nothing)";
                if (!DeskGuestWipeTargets.All.Contains(t.Trim().ToLowerInvariant()))
                    return $"wipe target '{t}' is NOT DeskGuest data — refused: an DeskGuest-data wipe reaches DeskGuest's own data only (scope creep is refused, never widened)";
            }
        }
        if (kind != MdmActionKinds.WipeDeskGuestData && targets.Count > 0)
            return $"action '{kind}' carries wipe targets — refused (targets belong to the DeskGuest-data wipe only)";
        return null;
    }
}

/// <summary>Device-side notice record: created BEFORE any execution.
/// HONESTY (D38 FIX F9): this record is created HOST-side, in the
/// service, before the executor runs — it proves the order was
/// noticed before execution was attempted. DELIVERY of the notice
/// to the device screen happens through the on-device executor
/// seam; until the Android executor is wired that delivery is NOT
/// proven, and nothing here claims the device displayed it.</summary>
public sealed record MdmDeviceNotice(
    string CommandId, string DeviceId, string Kind, string NoticeText, DateTimeOffset RecordedUtc);

public sealed record MdmActionOutcome(
    string CommandId, string DeviceId, string Kind, bool Executed,
    string Detail, MdmDeviceNotice? Notice, DateTimeOffset AtUtc);

/// <summary>The on-device executor seam. The Android endpoint side is
/// model/contract + integration points (Gradle environment-blocked,
/// banked) — the honest unavailable executor reports NOT executed.</summary>
public interface IMdmActionExecutor
{
    (bool Executed, string Detail) Execute(MdmActionRequest request, MdmDeviceState state, DateTimeOffset now);
}

public sealed class UnavailableMdmActionExecutor : IMdmActionExecutor
{
    public (bool, string) Execute(MdmActionRequest request, MdmDeviceState state, DateTimeOffset now) =>
        (false, $"no on-device MDM executor is wired on this host for device '{state.DeviceId}' — action '{request.Kind}' was validated and noticed but NOT executed (named remainder: Android endpoint wiring, Gradle environment-blocked)");
}

public sealed class RecordingMdmActionExecutor : IMdmActionExecutor
{
    public List<MdmActionRequest> Executed { get; } = new();
    public (bool, string) Execute(MdmActionRequest request, MdmDeviceState state, DateTimeOffset now)
    {
        Executed.Add(request);
        return (true, $"action '{request.Kind}' executed on device '{state.DeviceId}' (recording executor)");
    }
}

/// <summary>One-shot locate bookkeeping: the anti-tracking defence.
/// Enforces a minimum interval and a per-24h cap per device; every
/// allowed AND refused attempt is counted by the service's audit.
/// D38 FIX (F2): the limits passed in are CLAMPED to the hard
/// ceilings in MdmLimits inside this method — no caller (policy
/// included) can loosen them. The cap counts a ROLLING 24-hour
/// window, not a calendar day, so the midnight boundary buys no
/// extra locates. D38 FIX (F12): entries older than the window are
/// pruned on every call — the lists no longer grow forever.
/// PERSISTENCE: Snapshot/Restore let a host persist the counters
/// across restarts; MdmSubsetService exports/imports them
/// (integrity-wrapped) and raises LocateLimiterChanged on every
/// acquired slot so the host writes through (bd-shared-plat-2/F8).</summary>
public sealed class LocateRateLimiter
{
    private readonly Dictionary<string, List<DateTimeOffset>> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public (bool Ok, string Reason) TryAcquire(string deviceId, DateTimeOffset now, TimeSpan minInterval, int maxPerDay)
    {
        // Hard ceilings first: policy/callers may only tighten.
        if (minInterval < MdmLimits.LocateMinIntervalFloor) minInterval = MdmLimits.LocateMinIntervalFloor;
        if (maxPerDay < 1) maxPerDay = 1;
        if (maxPerDay > MdmLimits.LocateMaxPer24hCeiling) maxPerDay = MdmLimits.LocateMaxPer24hCeiling;
        lock (_gate)
        {
            if (!_byDevice.TryGetValue(deviceId ?? "", out var list))
                _byDevice[deviceId ?? ""] = list = new List<DateTimeOffset>();
            list.RemoveAll(t => now - t >= MdmLimits.LocateWindow);
            var last = list.Count == 0 ? (DateTimeOffset?)null : list.Max();
            if (last is { } l && now - l < minInterval)
                return (false, $"one-shot locate for '{deviceId}' refused: the minimum interval ({minInterval.TotalMinutes:0} min) has not elapsed since the last locate — repeated locates becoming de-facto tracking is refused by construction");
            if (list.Count >= maxPerDay)
                return (false, $"one-shot locate for '{deviceId}' refused: the daily cap ({maxPerDay} per rolling 24 hours) is reached — a locate facility that can be polled all day is tracking by another name");
            list.Add(now);
            return (true, "locate slot acquired");
        }
    }

    public int CountFor(string deviceId)
    {
        lock (_gate) return _byDevice.TryGetValue(deviceId ?? "", out var l) ? l.Count : 0;
    }

    /// <summary>Export the counters so a host CAN persist them
    /// across restarts (device id → locate timestamps).</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<DateTimeOffset>> Snapshot()
    {
        lock (_gate) return _byDevice.ToDictionary(
            kv => kv.Key, kv => (IReadOnlyList<DateTimeOffset>)kv.Value.ToList(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Restore counters exported by Snapshot (e.g. after a
    /// restart). Entries already outside the rolling window at
    /// restore time are dropped.</summary>
    public void Restore(IReadOnlyDictionary<string, IReadOnlyList<DateTimeOffset>> snapshot, DateTimeOffset now)
    {
        if (snapshot is null) return;
        lock (_gate)
        {
            foreach (var (deviceId, stamps) in snapshot)
            {
                var kept = (stamps ?? Array.Empty<DateTimeOffset>())
                    .Where(t => now - t < MdmLimits.LocateWindow).OrderBy(t => t).ToList();
                if (kept.Count > 0) _byDevice[deviceId ?? ""] = kept;
            }
        }
    }
}

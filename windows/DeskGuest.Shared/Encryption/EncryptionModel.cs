using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Encryption;

// =====================================================================
// RMM-18 — Disk-encryption enforcement + recovery-key escrow
// (ADOPTED 2026-11-20). MODEL LAYER: per-volume encryption state,
// the OS-driver seam, the policy requirement (with the RMM-07
// ceiling discipline), the compliance evaluation, the user-impact
// enable flow, and the recovery-key escrow vault.
//
// Doctrine carried from the register + gate law:
//   * State is reported CONTINUOUSLY and per volume. The states are
//     a closed set; UNKNOWN is a state, never silently "encrypted".
//     BitLocker protection-OFF (suspended) is NOT encrypted, and a
//     volume mid-encryption is NOT encrypted — the compliance
//     verdict and the RMM-01 security sample both say so.
//   * Recovery keys are ESCROWED into the hub vault machinery: at
//     rest they exist only as ISecretProtector-protected text (the
//     existing vault discipline — DPAPI in production, the named
//     dev pass-through in tests). Key material NEVER appears in
//     listings, audit entries, or error messages: listings are a
//     separate metadata type with no key field by construction.
//   * A key REVEAL is dual-controlled and audited: one admin alone
//     cannot reveal. Request → distinct-approver approval →
//     single-use reveal by the requester, every step chained-audit
//     with metadata only (who, which device, when — never the key).
//   * Key↔device binding is verified at ESCROW and at REVEAL: an
//     entry is bound to (device, volume) and its key hash; a reveal
//     naming any other device refuses.
//   * The requirement is policy CONTENT under the ceiling
//     discipline: an org/group requirement cannot be weakened by a
//     device-level document. A device may tighten (require where
//     nobody else does); it may never loosen.
//   * Enabling encryption is DISRUPTIVE and is never silent: the
//     enable flow models user notice + deferral, and the driver is
//     called only from a flow state that proves notice happened and
//     (acknowledgement OR deferral expiry) holds.
//   * The OS tooling (BitLocker / FileVault) sits behind
//     IEncryptionDriver. Tests drive fakes; the production host
//     driver is WINDOWS/MAC HOST WIRING — the unavailable driver
//     below is the honest placeholder (all states unknown, enable
//     refuses by name). NOTHING in this lane enables or alters
//     encryption on any real machine.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-18. The feature toggle
/// (rmm.encryption_enforcement.enabled, seeded ON) lives in the
/// RMM-07 registry; the keys below are POLICY CONTENT read through
/// Effective Policy / the requirement resolver.</summary>
public static class EncryptionPolicyKeys
{
    public const string Enabled = "rmm.encryption_enforcement.enabled";
    /// <summary>Policy content: "true" at org/group/device level
    /// requires encryption. Ceiling discipline applies (see
    /// EncryptionRequirementResolver): a device-level "false" never
    /// weakens an org/group "true".</summary>
    public const string Required = "rmm.encryption_enforcement.required";
    /// <summary>Policy content: the longest a user may defer an
    /// enable, in hours. Default 72; clamped 0..720 — an absurd
    /// value falls back to the default rather than minting an
    /// infinite deferral.</summary>
    public const string MaxDeferHours = "rmm.encryption_enforcement.max_defer_hours";
    public const int DefaultMaxDeferHours = 72;
    public const int MaxMaxDeferHours = 720;
}

/// <summary>The closed set of per-volume encryption states. A state
/// outside this set refuses at report admission — an unknown string
/// is a field that changes meaning (house fail-closed rule).</summary>
public static class VolumeEncryptionStates
{
    public const string Encrypted = "encrypted";         // fully encrypted AND protection on
    public const string Encrypting = "encrypting";       // conversion in progress — NOT compliant
    public const string Decrypting = "decrypting";       // conversion back — NOT compliant
    public const string NotEncrypted = "not_encrypted";
    public const string Suspended = "suspended";         // encrypted bytes, protection OFF — NOT compliant
    public const string Unknown = "unknown";             // not read / unreadable — a state, never "encrypted"

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    { Encrypted, Encrypting, Decrypting, NotEncrypted, Suspended, Unknown };

    public static bool IsValid(string? s) => s is not null && All.Contains(s);
}

/// <summary>One volume's encryption state as the driver read it.
/// ProtectionOn is tri-state: null = not read. A volume counts as
/// encrypted ONLY when State == encrypted AND ProtectionOn == true:
/// BitLocker "conversion complete, protection suspended" is the
/// classic state-lying trap and this model refuses to call it
/// encrypted.</summary>
public sealed record VolumeEncryptionState(
    string VolumeId,
    string State,
    bool? ProtectionOn,
    double? PercentEncrypted,
    string? KeyProtectorType)   // "recovery_password" | "tpm" | "filevault_prk" | ... (a label, never key material)
{
    /// <summary>Encrypted means FULLY encrypted: an "encrypted"
    /// state reporting less than 100% encrypted is internally
    /// inconsistent and never counts as encrypted (D38 F10).</summary>
    public bool IsEncrypted => State == VolumeEncryptionStates.Encrypted && ProtectionOn == true
        && (PercentEncrypted is null || PercentEncrypted >= 100);
    /// <summary>Definitively NOT compliant: a state that proves the
    /// volume is not protected right now (as opposed to unknown).</summary>
    public bool IsDefinitivelyUnprotected =>
        State is VolumeEncryptionStates.NotEncrypted or VolumeEncryptionStates.Suspended
            or VolumeEncryptionStates.Decrypting or VolumeEncryptionStates.Encrypting
        || (State == VolumeEncryptionStates.Encrypted && ProtectionOn == false);
}

/// <summary>One device's continuous encryption report: every volume
/// the driver read, at the instant it read them. ObservedUtc is the
/// observation instant (freshness + stale-replay discipline run
/// from it, never from arrival time).</summary>
public sealed record DeviceEncryptionReport(
    string DeviceId,
    string ScopeId,
    IReadOnlyList<VolumeEncryptionState> Volumes,
    DateTimeOffset ObservedUtc)
{
    public IReadOnlyList<VolumeEncryptionState> Volumes { get; init; } = Volumes ?? Array.Empty<VolumeEncryptionState>();

    /// <summary>True only when the report names at least one volume
    /// and EVERY volume IsEncrypted. An empty report is not
    /// compliance — it is no evidence (vacuous truth forbidden).</summary>
    public bool AllEncrypted => Volumes.Count > 0 && Volumes.All(v => v.IsEncrypted);

    public bool AnyDefinitivelyUnprotected => Volumes.Any(v => v.IsDefinitivelyUnprotected);
    /// <summary>Unknown includes the not-read shapes D38 F10 named:
    /// state=encrypted with protection NOT READ (null), and an
    /// encrypted state whose percentage contradicts it (&lt;100).</summary>
    public bool AnyUnknown => Volumes.Any(v => v.State == VolumeEncryptionStates.Unknown || !VolumeEncryptionStates.IsValid(v.State)
        || (v.State == VolumeEncryptionStates.Encrypted && v.ProtectionOn is null)
        || (v.State == VolumeEncryptionStates.Encrypted && v.PercentEncrypted is < 100));

    /// <summary>The RMM-01 security-state shape (EncryptionEnabled
    /// is bool?): true ONLY when all volumes are encrypted; false
    /// when any volume is definitively unprotected or still
    /// converting; null when the honest answer is "not known"
    /// (no volumes read, or an unknown volume and nothing
    /// definitively bad). Unknown NEVER reads as true.</summary>
    public bool? ToMonitorEncryptionEnabled()
    {
        if (AllEncrypted) return true;
        if (AnyDefinitivelyUnprotected) return false;
        return null;
    }

    public SecurityStateSample ToSecuritySample(bool? avEnabled, bool? firewallEnabled) =>
        new(avEnabled, firewallEnabled, ToMonitorEncryptionEnabled());

    /// <summary>The RMM-09 hub landing shape (DeviceSecurityState).
    /// EncryptionEnabled carries the same tri-state honesty.</summary>
    public DeviceSecurityState ToDeviceSecurityState(bool? avEnabled, bool? firewallEnabled) =>
        new(DeviceId, ScopeId, avEnabled, firewallEnabled, ToMonitorEncryptionEnabled(), ObservedUtc);
}

// ---- the OS driver seam ---------------------------------------------------

/// <summary>The OS-native tooling seam (BitLocker / FileVault driven
/// by the agent). ReadVolumes must not fabricate: an unreadable
/// volume is State=unknown with a note in the state itself, never a
/// guessed state. ReadRecoveryKey is ENDPOINT-side only — the key
/// travels to the hub escrow over the agent channel and is never
/// logged by the driver. BeginEnable is the disruptive act: callers
/// (the enforcement service) may call it ONLY through the enable
/// flow's notice/deferral discipline.</summary>
public interface IEncryptionDriver
{
    string Name { get; }
    IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now);
    (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now);
    string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now);
}

/// <summary>The honest placeholder where no OS driver is wired:
/// every volume unknown, enable refuses by name, no key exists.
/// Host wiring (manage-bde / fdesetup readers) is a named remainder
/// — this type exists so an unwired host reports UNKNOWN, never a
/// fabricated "encrypted".</summary>
public sealed class UnavailableEncryptionDriver : IEncryptionDriver
{
    public string Name => "unavailable";
    public IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now) =>
        new[] { new VolumeEncryptionState("OS", VolumeEncryptionStates.Unknown, null, null, null) };
    public (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now) =>
        (false, "no OS encryption driver is wired on this host — enable refuses (host wiring remainder, RMM-18)");
    public string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now) => null;
}

/// <summary>Test double: scripted volume states + keys, call-counted.
/// BeginEnable flips the volume to encrypting (the honest in-progress
/// state — never straight to encrypted).</summary>
public sealed class FakeEncryptionDriver : IEncryptionDriver
{
    private readonly Dictionary<string, VolumeEncryptionState> _volumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _keys = new(StringComparer.OrdinalIgnoreCase);

    public string Name => "fake";
    public int BeginEnableCalls { get; private set; }
    public int ReadKeyCalls { get; private set; }

    public FakeEncryptionDriver(params VolumeEncryptionState[] volumes)
    {
        foreach (var v in volumes) _volumes[v.VolumeId] = v;
    }

    public void SetVolume(VolumeEncryptionState v) => _volumes[v.VolumeId] = v;
    public void SetKey(string volumeId, string key) => _keys[volumeId] = key;

    public IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now) =>
        _volumes.Values.OrderBy(v => v.VolumeId, StringComparer.Ordinal).ToList();

    public (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now)
    {
        BeginEnableCalls++;
        if (!_volumes.TryGetValue(volumeId, out var v))
            return (false, $"volume '{volumeId}' not present on this endpoint — enable refuses");
        _volumes[volumeId] = v with
        {
            State = VolumeEncryptionStates.Encrypting,
            ProtectionOn = false,
            PercentEncrypted = v.PercentEncrypted ?? 0,
        };
        return (true, $"encryption enable started for volume '{volumeId}' (state: encrypting)");
    }

    public string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now)
    {
        ReadKeyCalls++;
        return _keys.TryGetValue(volumeId, out var k) ? k : null;
    }
}

// ---- the requirement (policy content + ceiling discipline) -----------------

/// <summary>One device's encryption requirement, resolved from
/// policy content with provenance. RequiredHere names the level +
/// document that imposed it; DeviceAttemptedWeaken records that a
/// device-level document tried to switch an org/group requirement
/// off — the attempt is VISIBLE, and it does not work.</summary>
public sealed record EncryptionRequirement(
    bool Required,
    string? RequiredByLevel,
    string? RequiredByDocumentId,
    bool DeviceAttemptedWeaken,
    string Summary);

/// <summary>Resolves the encryption requirement from the admitted
/// policy documents directly (Effective Policy collapses provenance
/// to the winning level, which is exactly what the ceiling
/// discipline must NOT do for a requirement: org OR group "true"
/// binds, whatever a device document says). A device-level "true"
/// tightens (requires where nobody else does). A device-level
/// "false" against an org/group "true" is recorded as an attempted
/// weaken and ignored.</summary>
public static class EncryptionRequirementResolver
{
    public static EncryptionRequirement Resolve(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var memberGroups = new HashSet<string>(engine.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        var docs = engine.Documents;
        string? orgDoc = null, groupDoc = null;
        var deviceRequires = false; string? deviceDoc = null;
        var deviceWeakens = false;

        bool? Read(ManagementPolicyDocument d) =>
            d.Settings.TryGetValue(EncryptionPolicyKeys.Required, out var v) && bool.TryParse(v, out var b) ? b : null;

        foreach (var d in docs.Where(d => d.Level == PolicyLevels.Org &&
                     (d.TargetId == facts.ScopeId || d.TargetId == "*")).OrderBy(d => d.Id, StringComparer.Ordinal))
            if (Read(d) == true) orgDoc ??= d.Id;
        foreach (var d in docs.Where(d => d.Level == PolicyLevels.Group && memberGroups.Contains(d.TargetId))
                     .OrderBy(d => d.Id, StringComparer.Ordinal))
            if (Read(d) == true) groupDoc ??= d.Id;
        foreach (var d in docs.Where(d => d.Level == PolicyLevels.Device && d.TargetId == facts.DeviceId))
        {
            if (Read(d) == true) { deviceRequires = true; deviceDoc ??= d.Id; }
            if (Read(d) == false) deviceWeakens = true;
        }

        if (orgDoc is not null || groupDoc is not null)
        {
            var level = orgDoc is not null ? PolicyLevels.Org : PolicyLevels.Group;
            var docId = orgDoc ?? groupDoc!;
            return new EncryptionRequirement(true, level, docId, deviceWeakens,
                deviceWeakens
                    ? $"encryption REQUIRED by {level} policy '{docId}'; a device-level document attempted to weaken it — refused by the ceiling discipline (the attempt is recorded, the requirement stands)"
                    : $"encryption REQUIRED by {level} policy '{docId}'");
        }
        if (deviceRequires)
            return new EncryptionRequirement(true, PolicyLevels.Device, deviceDoc, false,
                $"encryption REQUIRED by device policy '{deviceDoc}' (a device may tighten its own requirement)");
        return new EncryptionRequirement(false, null, null, false,
            "no policy level requires encryption for this device");
    }

    /// <summary>The deferral cap from policy content, under a
    /// CEILING discipline (D38 F9): the cap limits how long
    /// enforcement may be postponed, so a lower level may only
    /// TIGHTEN it. The org/group cap (the smallest such value)
    /// binds; a device value may reduce it further but never raise
    /// it. A value outside 1..720 (including 0 — a zero cap made
    /// "defer" a silent no-op) is invalid and ignored; when no
    /// valid value exists the default applies.</summary>
    public static int MaxDeferHours(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var memberGroups = new HashSet<string>(engine.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        int? ReadCap(ManagementPolicyDocument d) =>
            d.Settings.TryGetValue(EncryptionPolicyKeys.MaxDeferHours, out var s)
                && int.TryParse(s, out var v) && v is >= 1 and <= EncryptionPolicyKeys.MaxMaxDeferHours ? v : null;
        var higher = engine.Documents
            .Where(d => (d.Level == PolicyLevels.Org && (d.TargetId == facts.ScopeId || d.TargetId == "*"))
                     || (d.Level == PolicyLevels.Group && memberGroups.Contains(d.TargetId)))
            .Select(ReadCap).Where(v => v is not null).Select(v => v!.Value).ToList();
        var device = engine.Documents
            .Where(d => d.Level == PolicyLevels.Device && d.TargetId == facts.DeviceId)
            .Select(ReadCap).Where(v => v is not null).Select(v => v!.Value).ToList();
        int? cap = higher.Count > 0 ? higher.Min() : null;
        if (device.Count > 0) cap = cap is null ? device.Min() : Math.Min(cap.Value, device.Min());
        return cap ?? EncryptionPolicyKeys.DefaultMaxDeferHours;
    }
}

/// <summary>The feature toggle under the CEILING discipline
/// (D38 F6): rmm.encryption_enforcement.enabled is resolved from
/// admitted documents directly, NOT through Effective Policy —
/// Effective Policy collapses to the winning (device) level, which
/// let a device-level document switch off its own enforcement,
/// reporting and escrow while the org requirement stood. Here an
/// org value binds over a group value; a DEVICE-level value is
/// ignored entirely (a device can neither disable nor enable its
/// own enforcement feature); with no org/group value the seeded
/// registry default applies. Within the binding level, any "false"
/// wins (fail closed on conflicting documents).</summary>
public static class EncryptionToggleResolver
{
    public static bool IsEnabled(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var memberGroups = new HashSet<string>(engine.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        bool? Read(ManagementPolicyDocument d) =>
            d.Settings.TryGetValue(EncryptionPolicyKeys.Enabled, out var v) && bool.TryParse(v, out var b) ? b : null;
        bool? Level(IEnumerable<ManagementPolicyDocument> docs)
        {
            var values = docs.Select(Read).Where(v => v is not null).Select(v => v!.Value).ToList();
            return values.Count == 0 ? null : values.All(v => v);
        }
        var org = Level(engine.Documents.Where(d => d.Level == PolicyLevels.Org &&
            (d.TargetId == facts.ScopeId || d.TargetId == "*")));
        if (org is not null) return org.Value;
        var group = Level(engine.Documents.Where(d => d.Level == PolicyLevels.Group && memberGroups.Contains(d.TargetId)));
        if (group is not null) return group.Value;
        return engine.Registry.TryGet(EncryptionPolicyKeys.Enabled, out var t) && t!.DefaultEnabled;
    }

    /// <summary>True when a device-level document tries to set the
    /// toggle at all — visible for audit, never effective.</summary>
    public static bool DeviceAttemptedToggle(ManagementPolicyEngine engine, IDeviceFacts facts) =>
        engine.Documents.Any(d => d.Level == PolicyLevels.Device && d.TargetId == facts.DeviceId
            && d.Settings.ContainsKey(EncryptionPolicyKeys.Enabled));
}

/// <summary>Audit-detail escaping (D38 F11): caller free text
/// (reasons, device/volume ids, refs) is percent-escaped before it
/// is spliced into space-separated key=value audit details, so a
/// reason like "x approvedBy=admin-b" can never mint spoofed
/// fields for anyone parsing the exports. The hash chain was never
/// the issue; the MEANING was.</summary>
public static class EncryptionAuditText
{
    // bd-shared-sec-1/F12: the canonical implementation now lives
    // in the Audit lane (DeskGuest.Shared.Audit.AuditText); this delegates
    // so every lane escapes identically.
    public static string Escape(string? s) => DeskGuest.Shared.Audit.AuditText.Escape(s);
}

// ---- compliance evaluation ---------------------------------------------------

public static class EncryptionComplianceOutcomes
{
    public const string Compliant = "compliant";
    public const string NonCompliant = "non_compliant";
    /// <summary>The state cannot be judged (unknown volumes, no
    /// report): NOT compliant, and not proven non-compliant either —
    /// a third state, never folded into either.</summary>
    public const string Unknown = "unknown";
    public const string NotRequired = "not_required";
}

public sealed record EncryptionComplianceVerdict(
    string DeviceId,
    string Outcome,               // EncryptionComplianceOutcomes.*
    bool RequirementApplies,
    IReadOnlyList<string> OffendingVolumes,
    string Reason)
{
    public IReadOnlyList<string> OffendingVolumes { get; init; } = OffendingVolumes ?? Array.Empty<string>();
    public bool IsCompliant => Outcome == EncryptionComplianceOutcomes.Compliant;
}

public static class EncryptionComplianceEvaluator
{
    /// <summary>Pure verdict. Compliant requires: requirement
    /// applies, a report exists, and EVERY volume IsEncrypted.
    /// Unknown volumes under a requirement yield Unknown (evidence
    /// missing), never Compliant. Without a requirement the outcome
    /// is NotRequired — but a definitively-unprotected report is
    /// still NAMED in the reason (visibility without enforcement).</summary>
    public static EncryptionComplianceVerdict Evaluate(
        DeviceEncryptionReport? report, EncryptionRequirement requirement, string deviceId)
    {
        if (!requirement.Required)
        {
            var note = report is not null && report.AnyDefinitivelyUnprotected
                ? " (note: volumes are definitively unprotected — visible, not enforced, because no requirement applies)"
                : "";
            return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.NotRequired, false,
                Array.Empty<string>(), "no encryption requirement applies to this device" + note);
        }
        if (report is null)
            return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.Unknown, true,
                Array.Empty<string>(), "encryption is required but no state report exists for this device — compliance is UNKNOWN, never assumed");
        var offending = report.Volumes
            .Where(v => v.IsDefinitivelyUnprotected)
            .Select(v => $"{v.VolumeId}({v.State}{(v.State == VolumeEncryptionStates.Encrypted && v.ProtectionOn == false ? ",protection_off" : "")})")
            .ToList();
        if (offending.Count > 0)
            return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.NonCompliant, true,
                offending, $"encryption required by {requirement.RequiredByLevel} policy '{requirement.RequiredByDocumentId}'; unprotected volume(s): {string.Join(", ", offending)}");
        if (report.Volumes.Count == 0 || report.AnyUnknown)
            return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.Unknown, true,
                Array.Empty<string>(), "encryption is required but at least one volume's state is unknown — compliance is UNKNOWN, never assumed encrypted");
        if (report.AllEncrypted)
            return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.Compliant, true,
                Array.Empty<string>(), $"all {report.Volumes.Count} volume(s) encrypted with protection on");
        // Defensive fallback (D38 F10 corrected wording): with the
        // AnyUnknown definition above this is not expected to be
        // reachable from the current state set, but if a future
        // state shape ever lands here the evaluator still refuses
        // to guess — Unknown, never Compliant.
        return new EncryptionComplianceVerdict(deviceId, EncryptionComplianceOutcomes.Unknown, true,
            Array.Empty<string>(), "volume states do not resolve to a verdict — compliance is UNKNOWN");
    }
}

// ---- the enable flow (user-impact honesty) ------------------------------------

public static class EnableFlowStates
{
    public const string NoticePending = "notice_pending";   // created; user notice not yet issued
    public const string Noticed = "noticed";                // user notice issued; awaiting ack or deferral
    public const string Deferred = "deferred";              // user deferred until DeferredUntilUtc
    public const string Ready = "ready";                    // acked, or deferral expired after notice — driver may be called
    public const string EnableStarted = "enable_started";   // driver called; volume converting
    public const string Failed = "failed";
}

/// <summary>One volume's enable flow. The flow is the ONLY path to
/// the driver: Proceed refuses unless the state proves notice was
/// issued AND (the user acknowledged OR a recorded deferral has
/// expired). There is no silent-encrypt state and no transition
/// that skips notice.</summary>
public sealed record EncryptionEnableFlow(
    string FlowId,
    string DeviceId,
    string ScopeId,
    string VolumeId,
    string State,
    string RequestedBy,
    DateTimeOffset RequestedUtc,
    DateTimeOffset? NoticeIssuedUtc,
    DateTimeOffset? AcknowledgedUtc,
    DateTimeOffset? DeferredUntilUtc,
    string Detail,
    string? NoticeEvidence = null,      // D38 F5: HOW the notice reached the device (e.g. the endpoint dialog channel) — a bare assertion is not evidence
    string? AcknowledgedBy = null)      // D38 F5: WHO acknowledged, recorded so it can be checked distinct from the requester
{
    public static string IdFor(string deviceId, string volumeId, DateTimeOffset requestedUtc) =>
        "encflow-" + EncryptionHash.Sha256Hex($"{deviceId}|{volumeId}|{requestedUtc:O}")[..20];

    public bool MayProceed(DateTimeOffset now) =>
        State == EnableFlowStates.Ready ||
        (State == EnableFlowStates.Noticed && AcknowledgedUtc is not null) ||
        (State == EnableFlowStates.Deferred && DeferredUntilUtc is { } until && now >= until);
}

/// <summary>SHA-256 helpers (house shape).</summary>
public static class EncryptionHash
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
}

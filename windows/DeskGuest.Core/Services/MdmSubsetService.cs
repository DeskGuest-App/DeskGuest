using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.MdmSubset;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-31 — MDM subset service: Core surface over the Shared model.
// Policy gate (rmm.mdm.enabled) on state intake, compliance
// evaluation, state reads and actions; compliance evaluation
// preserving the enforce/detect/impossible tier; actions only
// through the RMM-03 signed-command gate with payload binding,
// freshness, device-side notice BEFORE execution, locate
// rate-limiting, and audit.
//
// D38 FIXES (packet 045c9412):
//  F1  state intake binds DeviceId + ScopeId to the enrolled
//      device facts, refuses out-of-order reports, audits ownership
//      escalation, and names ownership as SELF-REPORTED in every
//      surface that relies on it. There is no cryptographic
//      attestation in this layer — endpoint authentication is the
//      enrollment transport seam (Android wiring, unwired); the
//      residual is named, not smoothed.
//  F2  locate policy values are clamped to the model's hard
//      anti-tracking ceilings (the limiter clamps again itself).
//  F4  freshness is re-validated at the moment of execution, not
//      only when the request first arrives.
//  F5  device-owner-power actions refuse on STALE state.
//  F6  the executor receives the NORMALISED request (kind/targets).
//  F7  EVERY intake refusal is audited, capability inflation first.
//  F8  compliance headline separates enforced from detected;
//      unknown policy restriction ids are named, never silently
//      dropped from the denominator.
//  F9  notice text is escaped before it enters an audit line, so
//      notice text cannot fake audit fields.
//  F10 the deployment shape is construction-time configuration of
//      THIS service (default: self-hosted, fail-closed). A per-call
//      caller claim can only make the effective shape MORE
//      restrictive — a caller on a self-hosted install cannot talk
//      its way onto APNs/FCM by passing selfHostedShape=false.
//  F11 the locate limiter is private (a count accessor remains);
//      StateFor is policy-gated like the other device operations.
//  F12 notices and the state map are bounded (caps in MdmLimits).
// =====================================================================
public sealed class MdmSubsetService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly SignedCommandGate _signedGate;
    private readonly IMdmActionExecutor _executor;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly Func<DateTimeOffset> _now;
    private readonly bool _deploymentSelfHostedShape;
    private readonly Dictionary<string, MdmDeviceState> _states = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<MdmDeviceNotice> _notices = new();
    private readonly object _gate = new();
    private readonly LocateRateLimiter _locateLimiter = new();

    public IReadOnlyList<MdmDeviceNotice> Notices { get { lock (_gate) return _notices.ToList(); } }

    /// <summary>Read-only locate counter for a device (D38 FIX F11:
    /// the limiter itself is no longer public — holding the service
    /// must not let arbitrary code spend a device's locate slots).</summary>
    public int LocateCountFor(string deviceId) => _locateLimiter.CountFor(deviceId);

    /// <summary>bd-shared-plat-2/F8: the locate limiter's counters
    /// PERSIST through this service — the host writes the export
    /// through on <see cref="LocateLimiterChanged"/> and restores
    /// it at startup, so a restart no longer resets the 24-hour
    /// anti-tracking cap. The export is integrity-wrapped.</summary>
    public event Action? LocateLimiterChanged;

    public string ExportLocateLimiterJson() =>
        DeskGuest.Shared.Hub.HubPersistence.Wrap("deskguest-mdm-locate-limiter-v1",
            System.Text.Json.JsonSerializer.Serialize(_locateLimiter.Snapshot()));

    public bool ImportLocateLimiterJson(string json, DateTimeOffset now)
    {
        var payload = DeskGuest.Shared.Hub.HubPersistence.Unwrap(json, "deskguest-mdm-locate-limiter-v1");
        if (payload is null) return false;
        Dictionary<string, List<DateTimeOffset>>? snap;
        try { snap = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, List<DateTimeOffset>>>(payload); }
        catch { return false; }
        if (snap is null) return false;
        _locateLimiter.Restore(
            snap.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<DateTimeOffset>)kv.Value), now);
        return true;
    }

    public MdmSubsetService(
        ChainedAuditLog audit, ManagementPolicyEngine policy, SignedCommandGate signedGate,
        IMdmActionExecutor executor, Func<string, IDeviceFacts?> factsByDevice,
        Func<DateTimeOffset>? now = null, bool deploymentSelfHostedShape = true)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _signedGate = signedGate ?? throw new ArgumentNullException(nameof(signedGate));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _deploymentSelfHostedShape = deploymentSelfHostedShape;
    }

    /// <summary>D38 FIX (F10): the effective shape can only be MORE
    /// restrictive than the deployment's configured shape.</summary>
    private bool EffectiveSelfHosted(bool callerClaim) => _deploymentSelfHostedShape || callerClaim;

    /// <summary>D38 FIX (F9): free text (notice text especially) is
    /// escaped before entering an audit line — brackets, pipes and
    /// line breaks are flattened so text cannot fake audit fields.</summary>
    private static string AuditSafe(string? text) =>
        (text ?? "").Replace('[', '(').Replace(']', ')').Replace('|', '/')
            .Replace('\r', ' ').Replace('\n', ' ');

    private (IDeviceFacts? Facts, string Reason) Gate(string deviceId, string op)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null) return (null, $"no device facts for '{deviceId}' — {op} refuses (policy cannot be evaluated; fail closed)");
        // D38 FIX (F1): the facts must BE for the device asked about —
        // a facts record for another device never gates this one.
        if (!string.Equals(facts.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            return (null, $"device facts returned for '{deviceId}' belong to '{facts.DeviceId}' — {op} refuses (device binding mismatch; fail closed)");
        if (!_policy.IsEnabled(facts, MdmKeys.FeatureEnabled))
            return (null, $"the MDM subset is disabled by policy for device '{deviceId}' ({MdmKeys.FeatureEnabled}) — {op} refuses");
        return (facts, "ok");
    }

    /// <summary>Latest recorded state for a device. Policy-gated
    /// (D38 FIX F11): when the subset is disabled by policy, stored
    /// state is not served either.</summary>
    public MdmDeviceState? StateFor(string deviceId)
    {
        var (facts, _) = Gate(deviceId, "state read");
        if (facts is null) return null;
        lock (_gate) return _states.TryGetValue(deviceId ?? "", out var s) ? s : null;
    }

    private MdmDeviceState? StoredState(string deviceId)
    {
        lock (_gate) return _states.TryGetValue(deviceId ?? "", out var s) ? s : null;
    }

    /// <summary>Intake one device-state report. Capability-inflation
    /// wall: a non-device-owner report claiming an enforce-tier
    /// restriction as APPLIED where its tier is detect/impossible
    /// refuses the whole report — a lying report is not stored
    /// partially. EVERY refusal is audited (D38 FIX F7).</summary>
    public (MdmDeviceState? State, string Reason) ReportState(MdmDeviceState? state, string actor)
    {
        var now = _now();
        if (state is null) return (null, "no MDM device state presented — refused");
        (MdmDeviceState?, string) Refuse(string reason)
        {
            _audit.Append("mdm_state_refused", actor ?? "mdm-service", $"device={state.DeviceId} reason={AuditSafe(reason)}", now);
            return (null, reason);
        }
        var (facts, gateReason) = Gate(state.DeviceId, "state reporting");
        if (facts is null) return Refuse(gateReason);
        // D38 FIX (F1): the report's scope must be the enrolled
        // scope of THIS device — a report carrying another scope's
        // id is not this device's report.
        if (!string.Equals((state.ScopeId ?? "").Trim(), facts.ScopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"MDM state scope '{state.ScopeId}' does not match the enrolled scope '{facts.ScopeId}' for device '{state.DeviceId}' — refused (a state report is bound to the device's enrolled scope)");
        if (state.Validate(now) is { } invalid) return Refuse(invalid);
        if (state.ManagedApps.Count > MdmLimits.MaxManagedApps)
            return Refuse($"managed-app list over bounds ({MdmLimits.MaxManagedApps}) — refused");
        var ownership = (state.Ownership ?? "").Trim().ToLowerInvariant();
        foreach (var appliedId in state.AppliedRestrictions)
        {
            var def = MdmRestrictions.For(appliedId);
            if (def is null)
                return Refuse($"device '{state.DeviceId}' claims unknown restriction '{appliedId}' as applied — refused (an invented restriction proves nothing)");
            var tier = def.TierFor(ownership);
            if (tier != MdmTiers.Enforce)
                return Refuse($"CAPABILITY INFLATION refused: device '{state.DeviceId}' (ownership {ownership}) claims restriction '{appliedId}' as APPLIED, but its tier on this device is {tier.ToUpperInvariant()} — a non-enforce install cannot apply it; the report is refused whole");
        }
        // D38 FIX (F1): reports are monotonic — an older (or equal)
        // report never overwrites a newer stored one.
        var existing = StoredState(state.DeviceId);
        if (existing is not null && state.ReportedUtc <= existing.ReportedUtc)
            return Refuse($"MDM state for '{state.DeviceId}' reported at {state.ReportedUtc:O} does not advance the stored report ({existing.ReportedUtc:O}) — refused (out-of-order reports never overwrite newer state)");
        // D38 FIX (F1): an ownership ESCALATION claim is the highest-
        // value lie this intake can carry — it is accepted as a claim
        // (re-provisioning is real) but always audited by name, and
        // ownership remains labelled self-reported wherever it is used.
        if (existing is not null && OwnershipRank(ownership) > OwnershipRank((existing.Ownership ?? "").Trim().ToLowerInvariant()))
            _audit.Append("mdm_state_ownership_escalation", actor ?? "mdm-service",
                $"device={state.DeviceId} ownershipClaim {existing.Ownership} -> {state.Ownership} (SELF-REPORTED, unattested at this layer — named for review)", now);
        lock (_gate)
        {
            // D38 FIX (F12): the state map is bounded — at capacity a
            // NEW device evicts the oldest-reported state.
            if (!_states.ContainsKey(state.DeviceId) && _states.Count >= MdmLimits.MaxTrackedStates)
            {
                var oldest = _states.Values.OrderBy(s => s.ReportedUtc).First();
                _states.Remove(oldest.DeviceId);
            }
            _states[state.DeviceId] = state;
        }
        _audit.Append("mdm_state_reported", actor ?? "mdm-service",
            $"device={state.DeviceId} platform={state.Platform} ownership={state.Ownership} ownershipProvenance=self-reported scope={state.ScopeId} os={state.OsVersion} encryption={(state.EncryptionOn?.ToString() ?? "unknown")} lock={state.ScreenLock} managedApps={state.ManagedApps.Count} applied=[{string.Join(",", state.AppliedRestrictions)}]", now);
        return (state, $"MDM state recorded for '{state.DeviceId}' (ownership {state.Ownership}, SELF-REPORTED by the endpoint — attestation is the enrollment transport seam, not this layer; tiers are computed per restriction, never assumed)");
    }

    private static int OwnershipRank(string ownership) => ownership switch
    {
        MdmOwnership.DeviceOwner => 3,
        MdmOwnership.ProfileOwner => 2,
        MdmOwnership.Personal => 1,
        _ => 0,
    };

    /// <summary>Desired restrictions from policy + compliance verdicts
    /// for the device's latest state. Tier wording is preserved in
    /// every verdict (RMM-09: detection is not enforcement).</summary>
    public (IReadOnlyList<MdmComplianceVerdict>? Verdicts, string Reason) EvaluateCompliance(string deviceId, string actor)
    {
        var now = _now();
        var (facts, gateReason) = Gate(deviceId, "compliance evaluation");
        if (facts is null) return (null, gateReason);
        var state = StoredState(deviceId);
        if (state is null) return (null, $"no MDM state reported for '{deviceId}' — compliance is UNKNOWN (no report, no verdict; absence of evidence is never compliance)");
        var eff = _policy.ComputeEffective(facts);
        var desired = new List<MdmRestrictionDef>();
        var unknownIds = new List<string>();
        if (eff.Get(MdmKeys.Restrictions) is { } raw)
            foreach (var id in raw.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var def = MdmRestrictions.For(id);
                // D38 FIX (F8): an unrecognised policy id is NAMED in
                // the result and the audit — never silently dropped,
                // which used to shrink the denominator invisibly.
                if (def is null) { if (!unknownIds.Contains(id, StringComparer.OrdinalIgnoreCase)) unknownIds.Add(id); }
                else if (!desired.Contains(def)) desired.Add(def);
            }
        var verdicts = desired.Select(d => MdmComplianceEvaluator.Evaluate(d, state, now)).ToList();
        _audit.Append("mdm_compliance_evaluated", actor ?? "mdm-service",
            $"device={deviceId} verdicts=[{string.Join("; ", verdicts.Select(v => $"{v.RestrictionId}:{v.Tier}:{v.Outcome}"))}] unknownPolicyIds=[{string.Join(",", unknownIds)}]", now);
        // D38 FIX (F8): enforced and detected satisfaction are
        // counted SEPARATELY — one blended 'satisfied' number let
        // '2/2 satisfied' hide that both were only detected.
        var enforcedOk = verdicts.Count(v => v.Outcome == MdmComplianceOutcomes.EnforcedCompliant);
        var detectedOk = verdicts.Count(v => v.Outcome == MdmComplianceOutcomes.DetectedCompliant);
        var unknownNote = unknownIds.Count > 0
            ? $" — WARNING: policy names {unknownIds.Count} unrecognised restriction id(s) [{string.Join(", ", unknownIds)}] which match NO restriction and are counted NOWHERE (fix the policy; a typo must not silently shrink compliance)"
            : "";
        return (verdicts, $"compliance for '{deviceId}': {enforcedOk} enforced-satisfied, {detectedOk} detected-satisfied, of {verdicts.Count} desired restrictions (detected is NOT enforced; impossible-tier restrictions are never counted satisfied){unknownNote}");
    }

    /// <summary>Describe a command's transit for a deployment shape —
    /// the in-product honesty surface for push. The deployment shape
    /// is THIS service's construction-time configuration (D38 FIX
    /// F10); the caller-supplied shape can only tighten it.</summary>
    public (MdmTransport? Transport, string Reason) DescribeTransit(string transportId, bool selfHostedShape)
    {
        var t = MdmTransports.For(transportId);
        if (t is null) return (null, $"unknown MDM transport '{transportId}' — refused");
        var effectiveSelfHosted = EffectiveSelfHosted(selfHostedShape);
        if (effectiveSelfHosted && !t.AllowedInSelfHosted)
            return (null, $"transport '{t.Id}' is NOT part of the self-hosted shape — refused: {t.HonestNote}");
        if (!effectiveSelfHosted && !t.AllowedInPlatformShape)
            return (null, $"transport '{t.Id}' is not part of the platform shape — refused");
        return (t, t.HonestNote);
    }

    /// <summary>Execute one MDM action. The full wall, in order:
    /// policy gate → request validity (freshness, notice text, wipe
    /// scope) → RMM-03 signed gate with payload binding → device
    /// state present → ownership powers (full wipe / passcode reset
    /// are device-owner-tier only, and refuse on STALE state) →
    /// locate rate limit → freshness RE-validated at execution →
    /// device-side notice recorded → executor (which receives the
    /// NORMALISED request). Every refusal audits.</summary>
    public (MdmActionOutcome? Outcome, string Reason) ExecuteAction(
        MdmActionRequest? request, SignedCommandEnvelope? envelope, string transportId, bool selfHostedShape, string actor)
    {
        var now = _now();
        (MdmActionOutcome?, string) Refuse(string reason)
        {
            _audit.Append("mdm_action_refused", actor ?? "mdm-service",
                $"command={request?.CommandId} device={request?.DeviceId} kind={request?.Kind} reason={AuditSafe(reason)}", now);
            return (null, reason);
        }
        if (request is null) return Refuse("no MDM action request — refused");
        var (facts, gateReason) = Gate(request.DeviceId, "MDM action");
        if (facts is null) return Refuse(gateReason);
        if (request.Validate(now) is { } invalid) return Refuse(invalid);
        var (transport, transitReason) = DescribeTransit(transportId, selfHostedShape);
        if (transport is null) return Refuse(transitReason);

        // Signed-command discipline: envelope must verify AND its
        // payload must be exactly this request's canonical payload.
        var verdict = _signedGate.Authorize(envelope, now, SignedCommandClasses.BackgroundAction);
        if (!verdict.Allowed) return Refuse($"signed-command gate refused: {verdict.Reason}");
        var payloadText = Encoding.UTF8.GetString(verdict.Payload ?? Array.Empty<byte>());
        if (!string.Equals(payloadText, request.CanonicalPayload(), StringComparison.Ordinal))
            return Refuse("the signed payload does not match this MDM action request — refused (a signature over one action never authorizes another)");

        var state = StoredState(request.DeviceId);
        if (state is null) return Refuse($"no MDM state for '{request.DeviceId}' — action refuses (ownership powers cannot be judged without a state report)");

        // Ownership powers: never claim device-owner powers not held.
        // D38 FIX (F6): the kind is the normalised kind, and the
        // executor below receives a normalised request.
        var kind = request.NormalizedKind;
        var normalized = request with { Kind = kind, WipeTargets = request.NormalizedTargets };
        // D38 FIX (F5): powers are judged from state — state that is
        // STALE cannot confer them. Compliance already treated old
        // state as UNKNOWN; actions now do the same.
        if (kind == MdmActionKinds.WipeFullDevice)
        {
            if (state.IsStale(now))
                return Refuse($"full-device wipe for '{request.DeviceId}' refuses: the device state is STALE (reported {state.ReportedUtc:O}) — device-owner powers are never judged from old facts; a fresh state report is required");
            if (!state.IsDeviceOwner)
                return Refuse($"full-device wipe is IMPOSSIBLE on '{request.DeviceId}' (ownership {state.Ownership}, self-reported) — refused: DeskGuest is not device-owner on this device. An DeskGuest-data wipe (wipe_deskguest_data) IS available and is a different command; it is never silently substituted");
        }
        if (kind == MdmActionKinds.PasscodeReset)
        {
            if (state.IsStale(now))
                return Refuse($"passcode reset for '{request.DeviceId}' refuses: the device state is STALE (reported {state.ReportedUtc:O}) — passcode powers are never judged from old facts; a fresh state report is required");
            var tier = MdmRestrictions.For("passcode_reset")!.TierFor(state.Ownership);
            if (tier != MdmTiers.Enforce)
                return Refuse($"passcode reset is {tier.ToUpperInvariant()} on '{request.DeviceId}' (ownership {state.Ownership}) — refused: only a device-owner install can reset the passcode");
        }
        if (kind == MdmActionKinds.LocateOnce)
        {
            var eff = _policy.ComputeEffective(facts);
            // D38 FIX (F2): policy values are clamped to the hard
            // ceilings here AND in the limiter — policy can tighten
            // locate, never loosen it into tracking.
            var minInterval = MdmLimits.DefaultLocateMinInterval;
            if (eff.Get(MdmKeys.LocateMinIntervalMinutes) is { } mi && int.TryParse(mi.Value, out var miv) && miv > 0)
                minInterval = TimeSpan.FromMinutes(Math.Max(miv, (int)MdmLimits.LocateMinIntervalFloor.TotalMinutes));
            var maxPerDay = MdmLimits.DefaultLocateMaxPerDay;
            if (eff.Get(MdmKeys.LocateMaxPerDay) is { } md && int.TryParse(md.Value, out var mdv) && mdv > 0)
                maxPerDay = Math.Min(mdv, MdmLimits.LocateMaxPer24hCeiling);
            var (ok, why) = _locateLimiter.TryAcquire(request.DeviceId, now, minInterval, maxPerDay);
            if (!ok) return Refuse(why);
            LocateLimiterChanged?.Invoke();
        }

        // D38 FIX (F4): freshness is re-validated at the moment of
        // execution — a command that expired (or was future-issued)
        // while it waited in transit or in the gate never executes.
        var execNow = _now();
        if (request.Validate(execNow) is { } staleAtExecution)
            return Refuse($"freshness re-check at execution refused: {staleAtExecution}");

        // Device-side notice BEFORE execution — the no-hidden-operation law.
        var notice = new MdmDeviceNotice(request.CommandId, request.DeviceId, kind, request.NoticeText, execNow);
        lock (_gate)
        {
            _notices.Add(notice);
            // D38 FIX (F12): retained notices are bounded.
            if (_notices.Count > MdmLimits.MaxRetainedNotices)
                _notices.RemoveRange(0, _notices.Count - MdmLimits.MaxRetainedNotices);
        }
        _audit.Append("mdm_action_notice_recorded", actor ?? "mdm-service",
            $"command={request.CommandId} device={request.DeviceId} kind={kind} notice=[{AuditSafe(request.NoticeText)}] transport={transport.Id} transitNote=[{AuditSafe(transport.HonestNote)}]", execNow);

        var (executed, detail) = _executor.Execute(normalized, state, execNow);
        var outcome = new MdmActionOutcome(request.CommandId, request.DeviceId, kind, executed, detail, notice, execNow);
        _audit.Append(executed ? "mdm_action_executed" : "mdm_action_not_executed", actor ?? "mdm-service",
            $"command={request.CommandId} device={request.DeviceId} kind={kind} transport={transport.Id} detail={AuditSafe(detail)}", execNow);
        return (outcome, executed
            ? $"MDM action '{kind}' executed on '{request.DeviceId}' via {transport.Id} (device-side notice recorded first)"
            : $"MDM action '{kind}' for '{request.DeviceId}' was validated, signed and noticed but NOT executed: {detail}");
    }
}

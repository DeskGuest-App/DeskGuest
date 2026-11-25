using Acp.Shared.Compliance;
using Acp.Shared.Encryption;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Core.Services;

// =====================================================================
// RMM-18 — EncryptionEnforcementService: the Core wiring for disk-
// encryption enforcement + recovery-key escrow.
//
//   * State: the agent driver reads per-volume state; reports land
//     here with stale-replay discipline (an older observation never
//     overwrites a newer one — last week's "encrypted" cannot
//     launder today's "suspended").
//   * Feeds: a report projects into RMM-01's SecurityStateSample
//     (the security_encryption_off condition reads it unchanged)
//     and into RMM-09's landing shapes (DeviceSecurityState for the
//     SecurityStateStore + a ComplianceFact of kind
//     encryption_state). This service consumes those public shapes;
//     it edits none of their files.
//   * Enforcement: the requirement resolves from policy content
//     under the ceiling discipline; a non-compliant required device
//     is a chained-audit event and its monitor sample reads
//     EncryptionEnabled=false (or null when honestly unknown) —
//     the RMM-01 condition does the alerting, this service does
//     the judging.
//   * Enable: ONLY through the flow. Notice → (acknowledge |
//     defer) → proceed. The driver is never called from any other
//     path, and never silently.
//   * Escrow: keys read by the endpoint driver escrow into
//     RecoveryKeyEscrow (ISecretProtector vault discipline);
//     reveals are that vault's dual-control path, surfaced here.
//
// Every operation is gated by the TOTAL POLICY CONTROL toggle
// rmm.encryption_enforcement.enabled for the device's facts.
// =====================================================================
public sealed class EncryptionEnforcementService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly IEncryptionDriver _driver;
    private readonly Func<string, IDeviceFacts?> _factsFor;
    private readonly Func<DateTimeOffset> _now;
    private readonly Dictionary<string, DeviceEncryptionReport> _latestByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, EncryptionEnableFlow> _flows = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public RecoveryKeyEscrow Escrow { get; }

    public EncryptionEnforcementService(ChainedAuditLog audit, ManagementPolicyService policies,
        IEncryptionDriver driver, ISecretProtector protector,
        Func<string, IDeviceFacts?> factsFor, Func<DateTimeOffset>? now = null,
        Func<string, bool>? escrowAdminAuthorizer = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _driver = driver ?? throw new ArgumentNullException(nameof(driver));
        _factsFor = factsFor ?? throw new ArgumentNullException(nameof(factsFor));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        // D38 F1/F2/F12: the escrow runs on THIS service's clock
        // (never caller-supplied times), on the host's admin
        // authorizer when one is supplied, and behind this
        // service's policy gate — the raw `Escrow` surface can no
        // longer bypass the toggle.
        Escrow = new RecoveryKeyEscrow(protector, audit, () => _now(), escrowAdminAuthorizer,
            (deviceId, actor, op) => PolicyGate(deviceId, actor, op).Ok);
    }

    private IDeviceFacts? Facts(string deviceId) => _factsFor(deviceId);

    /// <summary>D38 F6: the toggle resolves under the CEILING
    /// discipline (org/group bind; a device-level document can
    /// neither disable nor enable its own enforcement), NOT through
    /// Effective-Policy precedence.</summary>
    private bool Enabled(IDeviceFacts facts) => EncryptionToggleResolver.IsEnabled(_policies.Engine, facts);

    private static string E(string? s) => EncryptionAuditText.Escape(s);

    private (bool Ok, string Reason) PolicyGate(string deviceId, string actor, string op)
    {
        var facts = Facts(deviceId);
        if (facts is null)
            return (false, $"unknown device '{deviceId}' — {op} refuses (no facts, no action)");
        if (!Enabled(facts))
        {
            var reason = $"disk-encryption enforcement is disabled by policy for device '{deviceId}' (rmm.encryption_enforcement.enabled) — {op} refuses (fail closed)";
            _audit.Append("encryption_refusal", actor, $"device={E(deviceId)} op={E(op)} reason={E(reason)}", _now());
            return (false, reason);
        }
        return (true, "ok");
    }

    // ---- continuous state reporting -------------------------------------------

    /// <summary>D38 F4: how long a report stays servable. Past this
    /// horizon the last report is STALE EVIDENCE, not a current
    /// fact: the feeds stop serving it (sample reads unknown, no
    /// compliance fact, verdict Unknown) instead of passing a dead
    /// agent's last "encrypted" forever.</summary>
    public static readonly TimeSpan ReportMaxAge = TimeSpan.FromHours(24);

    /// <summary>D38 F7: the largest future skew an agent-supplied
    /// observation instant may carry against the hub clock.</summary>
    public static readonly TimeSpan MaxObservationSkew = TimeSpan.FromMinutes(5);

    /// <summary>Read the driver and record the report. The
    /// observation instant for a driver read is the read instant
    /// itself (the driver runs endpoint-side); agent-supplied
    /// observations go through ReportObservedState, which binds and
    /// verifies the supplied instant.</summary>
    public (bool Ok, string Reason, DeviceEncryptionReport? Report) ReportState(string deviceId, string reportedBy)
    {
        var now = _now();
        var gate = PolicyGate(deviceId, reportedBy, "state report");
        if (!gate.Ok) return (false, gate.Reason, null);
        IReadOnlyList<VolumeEncryptionState> volumes;
        try { volumes = _driver.ReadVolumes(deviceId, now); }
        catch (Exception ex)
        {
            var reason = $"encryption driver '{_driver.Name}' failed to read device '{deviceId}' ({ex.GetType().Name}) — state is UNKNOWN, no report recorded";
            _audit.Append("encryption_state_report_failed", reportedBy, $"device={E(deviceId)} reason={E(reason)}", now);
            return (false, reason, null);
        }
        return AdmitReport(deviceId, reportedBy, volumes, now);
    }

    /// <summary>D38 F7: admit a report whose observation instant
    /// the AGENT supplies. The instant is bound and verified: a
    /// future-dated observation (beyond the named skew) refuses,
    /// and an observation not strictly newer than the stored one
    /// refuses (stale replay). A volume carrying an invalid state
    /// string refuses the WHOLE report — a state the model does
    /// not know is never coerced into one it does.</summary>
    public (bool Ok, string Reason, DeviceEncryptionReport? Report) ReportObservedState(
        string deviceId, string reportedBy, IReadOnlyList<VolumeEncryptionState> volumes, DateTimeOffset observedUtc)
    {
        var gate = PolicyGate(deviceId, reportedBy, "state report");
        if (!gate.Ok) return (false, gate.Reason, null);
        var now = _now();
        if (observedUtc > now.Add(MaxObservationSkew))
        {
            var reason = $"agent-supplied observation {observedUtc:O} is future-dated beyond the {MaxObservationSkew.TotalMinutes:F0}-minute skew against the hub clock — report refused (an unverifiable timestamp binds nothing)";
            _audit.Append("encryption_state_report_refused", reportedBy, $"device={E(deviceId)} reason={E(reason)}", now);
            return (false, reason, null);
        }
        return AdmitReport(deviceId, reportedBy, volumes, observedUtc);
    }

    private (bool Ok, string Reason, DeviceEncryptionReport? Report) AdmitReport(
        string deviceId, string reportedBy, IReadOnlyList<VolumeEncryptionState> volumes, DateTimeOffset observedUtc)
    {
        var now = _now();
        var facts = Facts(deviceId)!;
        var bad = volumes.FirstOrDefault(v => !VolumeEncryptionStates.IsValid(v.State));
        if (bad is not null)
        {
            var reason = $"driver reported state '{bad.State}' for volume '{bad.VolumeId}' — not a known encryption state; report refused whole (an unknown string is never coerced)";
            _audit.Append("encryption_state_report_refused", reportedBy, $"device={E(deviceId)} reason={E(reason)}", now);
            return (false, reason, null);
        }
        var report = new DeviceEncryptionReport(deviceId, facts.ScopeId, volumes, observedUtc);
        lock (_gate)
        {
            if (_latestByDevice.TryGetValue(deviceId, out var existing) && report.ObservedUtc <= existing.ObservedUtc)
            {
                _audit.Append("encryption_state_report_refused", reportedBy,
                    $"device={E(deviceId)} reason=observation {report.ObservedUtc:O} is not newer than the stored {existing.ObservedUtc:O} (stale replay refused)", now);
                return (false, "stale report refused: a stored newer observation already exists for this device", existing);
            }
            _latestByDevice[deviceId] = report;
        }
        _audit.Append("encryption_state_reported", reportedBy,
            $"device={E(deviceId)} volumes={string.Join(",", volumes.Select(v => $"{E(v.VolumeId)}:{v.State}:protection={(v.ProtectionOn?.ToString() ?? "not_read")}"))} monitorEncryption={(report.ToMonitorEncryptionEnabled()?.ToString() ?? "unknown")}", now);
        return (true, $"encryption state recorded for '{deviceId}': {volumes.Count} volume(s), monitor encryption = {(report.ToMonitorEncryptionEnabled()?.ToString() ?? "unknown")}", report);
    }

    public DeviceEncryptionReport? LatestReport(string deviceId)
    {
        lock (_gate) return deviceId is not null && _latestByDevice.TryGetValue(deviceId, out var r) ? r : null;
    }

    /// <summary>True when a stored report exists AND is within the
    /// freshness horizon (D38 F4).</summary>
    public bool HasFreshReport(string deviceId)
    {
        var r = LatestReport(deviceId);
        return r is not null && _now() - r.ObservedUtc <= ReportMaxAge;
    }

    /// <summary>The report the feeds may serve: the latest report
    /// only when it is FRESH and the feature is enabled for the
    /// device (D38 F4/F6). A stale report, or a report frozen by a
    /// toggle-off, serves as UNKNOWN — never as a passing fact.</summary>
    private DeviceEncryptionReport? ServingReport(string deviceId)
    {
        var report = LatestReport(deviceId);
        if (report is null) return null;
        if (_now() - report.ObservedUtc > ReportMaxAge) return null;
        var facts = Facts(deviceId);
        if (facts is null || !Enabled(facts)) return null;
        return report;
    }

    // ---- RMM-01 / RMM-09 feeds ---------------------------------------------------

    /// <summary>The RMM-01 feed: the latest report as a security
    /// sample. AV/firewall pass through from the caller's own
    /// readings (this service does not read them); encryption is
    /// the tri-state honesty projection. No report → encryption
    /// null (not read), never true.</summary>
    public SecurityStateSample SecuritySampleFor(string deviceId, bool? avEnabled = null, bool? firewallEnabled = null)
    {
        var report = ServingReport(deviceId);
        return report is null
            ? new SecurityStateSample(avEnabled, firewallEnabled, null)
            : report.ToSecuritySample(avEnabled, firewallEnabled);
    }

    /// <summary>The RMM-09 hub landing shape for the
    /// SecurityStateStore seam. Null when no report exists — the
    /// caller records nothing rather than a fabricated state.</summary>
    public DeviceSecurityState? SecurityStateFor(string deviceId, bool? avEnabled = null, bool? firewallEnabled = null)
    {
        var report = ServingReport(deviceId);
        return report?.ToDeviceSecurityState(avEnabled, firewallEnabled);
    }

    /// <summary>The RMM-09 compliance fact (kind encryption_state)
    /// for this device: passing ONLY when a requirement applies and
    /// every volume is encrypted, OR when the device is encrypted
    /// regardless of requirement. A device that is unencrypted
    /// without a requirement produces a FAILING fact too — the fact
    /// states the device's encryption truth; whether a control
    /// requires it is the compiler's question. Null when there is
    /// no report (RMM-09 emits missing_fact, never a guess).</summary>
    public ComplianceFact? BuildComplianceFact(string deviceId)
    {
        var report = ServingReport(deviceId);
        if (report is null) return null;
        var enc = report.ToMonitorEncryptionEnabled();
        if (enc is null) return null; // honestly unknown → no fact; the compiler's missing_fact gap is the truthful outcome
        return new ComplianceFact(
            ComplianceFactKinds.EncryptionState, report.DeviceId, report.ScopeId,
            Passing: enc.Value, report.ObservedUtc,
            enc.Value
                ? $"all {report.Volumes.Count} volume(s) encrypted with protection on, as observed by the endpoint driver"
                : $"unprotected volume(s): {string.Join(", ", report.Volumes.Where(v => !v.IsEncrypted).Select(v => $"{v.VolumeId}({v.State})"))}",
            EncryptionHash.Sha256Hex($"enc18|{report.DeviceId}|{report.ObservedUtc:O}|{enc.Value}|{string.Join(",", report.Volumes.Select(v => $"{v.VolumeId}:{v.State}:{v.ProtectionOn}"))}"));
    }

    // ---- enforcement -----------------------------------------------------------

    public EncryptionRequirement RequirementFor(string deviceId)
    {
        var facts = Facts(deviceId);
        return facts is null
            ? new EncryptionRequirement(false, null, null, false, $"unknown device '{deviceId}' — no requirement can be resolved")
            : EncryptionRequirementResolver.Resolve(_policies.Engine, facts);
    }

    /// <summary>Judge the device against its requirement. A
    /// non-compliant verdict under a requirement is a chained-audit
    /// event (encryption_noncompliant) — the enforcement signal
    /// RMM-01's condition and RMM-09's fact both corroborate.</summary>
    // D38 F12: the last outcome audited per device — periodic
    // evaluation audits TRANSITIONS, not every poll, so the chain
    // does not grow without bound for a steady state.
    private readonly Dictionary<string, string> _lastAuditedOutcome = new(StringComparer.OrdinalIgnoreCase);

    public EncryptionComplianceVerdict EvaluateCompliance(string deviceId, string evaluatedBy)
    {
        // D38 F12: the requirement is resolved ONCE per evaluation.
        var requirement = RequirementFor(deviceId);
        // D38 F4: a stale (or toggle-frozen) report judges as NO
        // report — Unknown under a requirement, never Compliant.
        var verdict = EncryptionComplianceEvaluator.Evaluate(ServingReport(deviceId), requirement, deviceId);
        bool transition;
        lock (_gate)
        {
            transition = !_lastAuditedOutcome.TryGetValue(deviceId, out var last) || last != verdict.Outcome;
            _lastAuditedOutcome[deviceId] = verdict.Outcome;
        }
        if (transition && verdict.Outcome == EncryptionComplianceOutcomes.NonCompliant)
            _audit.Append("encryption_noncompliant", evaluatedBy,
                $"device={E(deviceId)} volumes={E(string.Join(",", verdict.OffendingVolumes))} reason={E(verdict.Reason)}", _now());
        if (transition && verdict.RequirementApplies && requirement.DeviceAttemptedWeaken)
            _audit.Append("encryption_policy_weaken_attempt", evaluatedBy,
                $"device={E(deviceId)} detail=a device-level policy document attempted to weaken an org/group encryption requirement — refused by the ceiling discipline", _now());
        return verdict;
    }

    // ---- escrow ------------------------------------------------------------------

    /// <summary>Escrow the recovery keys the driver reads for every
    /// volume that HAS one. A volume with no readable key is named
    /// in the result — never silently skipped, never escrowed on a
    /// guess. Keys pass straight from driver to vault; this method
    /// never logs, returns, or audits them.</summary>
    public (bool Ok, string Reason, IReadOnlyList<EscrowedKeyMetadata> Escrowed, IReadOnlyList<string> VolumesWithoutKey)
        EscrowRecoveryKeys(string deviceId, string escrowedBy)
    {
        var now = _now();
        var gate = PolicyGate(deviceId, escrowedBy, "key escrow");
        if (!gate.Ok) return (false, gate.Reason, Array.Empty<EscrowedKeyMetadata>(), Array.Empty<string>());
        var report = ServingReport(deviceId);
        if (report is null)
            return (false, $"no encryption state report for device '{deviceId}' (or the stored report is stale) — escrow refuses (keys are escrowed against a known, current volume set, never blind or stale)", Array.Empty<EscrowedKeyMetadata>(), Array.Empty<string>());
        var escrowed = new List<EscrowedKeyMetadata>();
        var without = new List<string>();
        foreach (var volume in report.Volumes)
        {
            string? key;
            try { key = _driver.ReadRecoveryKey(deviceId, volume.VolumeId, now); }
            catch { key = null; }
            if (key is null) { without.Add(volume.VolumeId); continue; }
            var (ok, _, meta) = Escrow.Escrow(deviceId, volume.VolumeId, report.ScopeId, key,
                volume.KeyProtectorType ?? "", escrowedBy, now);
            if (ok && meta is not null) escrowed.Add(meta); else without.Add(volume.VolumeId);
        }
        return (true,
            $"escrowed {escrowed.Count} recovery key(s) for device '{deviceId}'" +
            (without.Count > 0 ? $"; NO key could be read for volume(s): {string.Join(", ", without)} — named, not hidden" : ""),
            escrowed, without);
    }

    // ---- the enable flow ------------------------------------------------------------

    /// <summary>Open an enable flow for one unprotected volume. The
    /// flow starts at notice_pending: nothing has been shown to the
    /// user yet, and the driver cannot be reached from here.</summary>
    public (bool Ok, string Reason, EncryptionEnableFlow? Flow) RequestEnable(
        string deviceId, string volumeId, string requestedBy)
    {
        var now = _now();
        var gate = PolicyGate(deviceId, requestedBy, "enable request");
        if (!gate.Ok) return (false, gate.Reason, null);
        var report = ServingReport(deviceId);
        var volume = report?.Volumes.FirstOrDefault(v =>
            string.Equals(v.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase));
        if (volume is null)
            return (false, $"no state report names volume '{volumeId}' on device '{deviceId}' — enable refuses (the flow acts on reported state, not on a guess)", null);
        if (volume.IsEncrypted)
            return (false, $"volume '{volumeId}' on device '{deviceId}' is already encrypted with protection on — nothing to enable", null);
        var flow = new EncryptionEnableFlow(
            EncryptionEnableFlow.IdFor(deviceId, volumeId, now), deviceId, Facts(deviceId)!.ScopeId, volumeId,
            EnableFlowStates.NoticePending, requestedBy, now, null, null, null,
            "enable requested; user notice has NOT yet been issued — encryption will not start silently");
        lock (_gate)
        {
            // D38 F12: one OPEN flow per (device, volume) — a second
            // request names the existing flow instead of minting a
            // duplicate; terminal flows are pruned (the audit chain
            // is their permanent record).
            var open = _flows.Values.FirstOrDefault(f =>
                string.Equals(f.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(f.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase) &&
                f.State is EnableFlowStates.NoticePending or EnableFlowStates.Noticed
                    or EnableFlowStates.Deferred or EnableFlowStates.Ready);
            if (open is not null)
                return (false, $"an open enable flow '{open.FlowId}' already exists for device '{deviceId}' volume '{volumeId}' (state '{open.State}') — duplicate flow refused", open);
            foreach (var kv in _flows.Where(kv => kv.Value.State is EnableFlowStates.EnableStarted or EnableFlowStates.Failed).ToList())
                _flows.Remove(kv.Key);
            _flows[flow.FlowId] = flow;
        }
        _audit.Append("encryption_enable_requested", requestedBy,
            $"flow={E(flow.FlowId)} device={E(deviceId)} volume={E(volumeId)} state={volume.State}", now);
        return (true, $"enable flow '{flow.FlowId}' opened for device '{deviceId}' volume '{volumeId}' — user notice is the next step; the driver has NOT been called", flow);
    }

    /// <summary>Record that the user notice was issued. D38 F5:
    /// the caller must supply DELIVERY EVIDENCE (how the notice
    /// reached the device — e.g. the endpoint dialog channel that
    /// displayed it); a bare assertion that "the user was told" is
    /// not a notice. The evidence is recorded on the flow and in
    /// the audit. Only from notice_pending; policy-gated (F12).</summary>
    public (bool Ok, string Reason, EncryptionEnableFlow? Flow) IssueUserNotice(string flowId, string issuedBy, string deliveryEvidence)
    {
        var now = _now();
        var flow = GetFlow(flowId);
        if (flow is null) return (false, $"unknown enable flow '{flowId}' — refused", null);
        var gate = PolicyGate(flow.DeviceId, issuedBy, "enable notice");
        if (!gate.Ok) return (false, gate.Reason, flow);
        if (string.IsNullOrWhiteSpace(deliveryEvidence))
            return (false, "a user notice needs delivery evidence (the channel that actually displayed it at the device) — a bare assertion is not a notice; refused", flow);
        if (flow.State != EnableFlowStates.NoticePending)
            return (false, $"flow '{flowId}' is '{flow.State}' — notice can only be issued from notice_pending; refused", flow);
        var next = flow with
        {
            State = EnableFlowStates.Noticed,
            NoticeIssuedUtc = now,
            NoticeEvidence = deliveryEvidence.Trim(),
            Detail = $"user notice issued with delivery evidence '{deliveryEvidence.Trim()}': the notice states encryption will start and what it means (restart, recovery key escrowed, performance during conversion)",
        };
        lock (_gate) _flows[flowId] = next;
        _audit.Append("encryption_enable_notice_issued", issuedBy,
            $"flow={E(flowId)} device={E(flow.DeviceId)} volume={E(flow.VolumeId)} evidence={E(deliveryEvidence)}", now);
        return (true, "user notice recorded with its delivery evidence — the user may acknowledge, or defer within the policy cap", next);
    }

    /// <summary>The user acknowledges: proceed as soon as the flow
    /// is next advanced. Only from noticed.</summary>
    public (bool Ok, string Reason, EncryptionEnableFlow? Flow) AcknowledgeEnable(string flowId, string acknowledgedBy)
    {
        var now = _now();
        var flow = GetFlow(flowId);
        if (flow is null) return (false, $"unknown enable flow '{flowId}' — refused", null);
        var gate = PolicyGate(flow.DeviceId, acknowledgedBy, "enable acknowledgement");
        if (!gate.Ok) return (false, gate.Reason, flow);
        if (flow.State != EnableFlowStates.Noticed)
            return (false, $"flow '{flowId}' is '{flow.State}' — acknowledgement requires an issued notice first; refused", flow);
        // D38 F5: the acknowledgement must come from a DISTINCT
        // actor from the admin who requested the enable (names
        // normalised — trailing spaces are not a second person).
        // One admin requesting + self-acknowledging back to back
        // was a silent encrypt in practice.
        acknowledgedBy = RecoveryKeyEscrow.NormalizeActor(acknowledgedBy);
        if (string.IsNullOrWhiteSpace(acknowledgedBy))
            return (false, "an acknowledgement needs a named device user — refused", flow);
        if (string.Equals(acknowledgedBy, RecoveryKeyEscrow.NormalizeActor(flow.RequestedBy), StringComparison.OrdinalIgnoreCase))
            return (false, "the admin who requested this enable cannot acknowledge it themselves — the acknowledgement must come from the device user, a distinct actor; refused (silent-encrypt defense)", flow);
        var next = flow with
        {
            State = EnableFlowStates.Ready,
            AcknowledgedUtc = now,
            AcknowledgedBy = acknowledgedBy,
            Detail = $"user '{acknowledgedBy}' acknowledged after notice — enable may proceed",
        };
        lock (_gate) _flows[flowId] = next;
        _audit.Append("encryption_enable_acknowledged", acknowledgedBy,
            $"flow={E(flowId)} device={E(flow.DeviceId)} volume={E(flow.VolumeId)}", now);
        return (true, "acknowledgement recorded — the flow is ready to proceed", next);
    }

    /// <summary>The user defers. The deferral is capped by policy
    /// content (max_defer_hours): a longer ask is CLAMPED to the cap
    /// and the clamp is stated, never silently granted. Only from
    /// noticed.</summary>
    public (bool Ok, string Reason, EncryptionEnableFlow? Flow) DeferEnable(string flowId, string deferredBy, TimeSpan deferFor)
    {
        var now = _now();
        var flow = GetFlow(flowId);
        if (flow is null) return (false, $"unknown enable flow '{flowId}' — refused", null);
        var gate = PolicyGate(flow.DeviceId, deferredBy, "enable deferral");
        if (!gate.Ok) return (false, gate.Reason, flow);
        if (flow.State != EnableFlowStates.Noticed)
            return (false, $"flow '{flowId}' is '{flow.State}' — deferral requires an issued notice first; refused", flow);
        if (deferFor <= TimeSpan.Zero)
            return (false, "a deferral must be a positive duration — refused", flow);
        var facts = Facts(flow.DeviceId);
        var cap = TimeSpan.FromHours(facts is null
            ? EncryptionPolicyKeys.DefaultMaxDeferHours
            : EncryptionRequirementResolver.MaxDeferHours(_policies.Engine, facts));
        var clamped = deferFor > cap;
        var until = now.Add(clamped ? cap : deferFor);
        var next = flow with
        {
            State = EnableFlowStates.Deferred,
            DeferredUntilUtc = until,
            Detail = clamped
                ? $"user deferred; the ask exceeded the policy cap of {cap.TotalHours:F0}h and was CLAMPED to it — deferral expires {until:O}, after which enable may proceed on the notice already given"
                : $"user deferred until {until:O} — enable may proceed after that instant on the notice already given",
        };
        lock (_gate) _flows[flowId] = next;
        _audit.Append("encryption_enable_deferred", deferredBy,
            $"flow={E(flowId)} device={E(flow.DeviceId)} volume={E(flow.VolumeId)} until={until:O} clamped={clamped} capHours={cap.TotalHours:F0}", now);
        return (true, next.Detail, next);
    }

    /// <summary>Advance a ready flow: THE ONLY call site of
    /// driver.BeginEnable in the service. Refuses unless the flow
    /// proves notice + (acknowledgement OR expired deferral). A
    /// driver refusal lands the flow in Failed with the driver's
    /// own reason — named, never retried silently.</summary>
    public (bool Ok, string Reason, EncryptionEnableFlow? Flow) ProceedEnable(string flowId, string proceededBy)
    {
        var now = _now();
        var probe = GetFlow(flowId);
        if (probe is null) return (false, $"unknown enable flow '{flowId}' — refused", null);
        var gate = PolicyGate(probe.DeviceId, proceededBy, "enable proceed");
        if (!gate.Ok) return (false, gate.Reason, probe);
        // D38 F3: ATOMIC — the flow read, the MayProceed check, the
        // driver call and the state store happen inside the one
        // lock, so two concurrent proceeds cannot both reach the
        // driver.
        lock (_gate)
        {
            if (!_flows.TryGetValue(flowId ?? "", out var flow) || flow is null)
                return (false, $"unknown enable flow '{flowId}' — refused", null);
            if (!flow.MayProceed(now))
            {
                var reason = flow.State switch
                {
                    EnableFlowStates.NoticePending => "user notice has not been issued — encryption NEVER starts silently; refused",
                    EnableFlowStates.Noticed => "the user has neither acknowledged nor deferred — refused (notice alone is not consent to proceed immediately)",
                    EnableFlowStates.Deferred => $"the user's deferral runs until {flow.DeferredUntilUtc:O} — proceeding earlier would break the deferral promise; refused",
                    _ => $"flow '{flowId}' is '{flow.State}' — it cannot proceed; refused",
                };
                _audit.Append("encryption_enable_refused", proceededBy,
                    $"flow={E(flowId)} device={E(flow.DeviceId)} volume={E(flow.VolumeId)} reason={E(reason)}", now);
                return (false, reason, flow);
            }
            var (ok, driverReason) = _driver.BeginEnable(flow.DeviceId, flow.VolumeId, now);
            var next = flow with
            {
                State = ok ? EnableFlowStates.EnableStarted : EnableFlowStates.Failed,
                Detail = driverReason,
            };
            _flows[flowId] = next;
            _audit.Append(ok ? "encryption_enable_started" : "encryption_enable_failed", proceededBy,
                $"flow={E(flowId)} device={E(flow.DeviceId)} volume={E(flow.VolumeId)} driver={E(_driver.Name)} reason={E(driverReason)}", now);
            return (ok, driverReason, next);
        }
    }

    public EncryptionEnableFlow? GetFlow(string flowId)
    {
        lock (_gate) return flowId is not null && _flows.TryGetValue(flowId, out var f) ? f : null;
    }

    public IReadOnlyList<EncryptionEnableFlow> Flows
    {
        get { lock (_gate) return _flows.Values.OrderBy(f => f.FlowId, StringComparer.Ordinal).ToList(); }
    }
}

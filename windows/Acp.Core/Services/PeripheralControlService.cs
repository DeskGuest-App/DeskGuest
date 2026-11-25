using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.PeripheralControl;
using Acp.Shared.WorkItems;

namespace Acp.Core.Services;

// =====================================================================
// RMM-30 — Peripheral control service: the Core surface over the
// Shared model. Policy gate per machine on every operation;
// connection evaluation raising block / collision / new-HID events
// into the RMM-01 alert centre and the chained audit; media tracing
// through the hash-chained trace store; the exception workflow
// composed with RMM-12 work items; evaluate-and-apply reporting the
// applier's outcome EXACTLY (host wiring is a named remainder).
// =====================================================================
public sealed class PeripheralControlService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly IPeripheralControlApplier _applier;
    private readonly IPeripheralAlertSink _alertSink;
    private readonly WorkItemStore _workItems;
    private readonly Func<string, IDeviceFacts?> _factsByMachine;
    private readonly Func<DateTimeOffset> _now;

    public PeripheralExceptionStore Exceptions { get; } = new();
    public PeripheralSeenRegistry Seen { get; } = new();
    public MediaTraceStore Trace { get; } = new();

    public PeripheralControlService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        IPeripheralControlApplier applier,
        IPeripheralAlertSink alertSink,
        WorkItemStore workItems,
        Func<string, IDeviceFacts?> factsByMachine,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _applier = applier ?? throw new ArgumentNullException(nameof(applier));
        _alertSink = alertSink ?? throw new ArgumentNullException(nameof(alertSink));
        _workItems = workItems ?? throw new ArgumentNullException(nameof(workItems));
        _factsByMachine = factsByMachine ?? throw new ArgumentNullException(nameof(factsByMachine));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    // ONE resolution per operation (D38-F11d/F12): the gate and the
    // policy resolution share a single Resolve over the LIVE
    // exception rules (D38-F11e: expired exceptions are not re-fed
    // to the resolver on every call, so resolver notes and audits
    // stop growing with dead rules).
    private (IDeviceFacts? Facts, ResolvedPeripheralPolicy? Resolved, string Reason) GateCore(string machineId, string op)
    {
        var facts = _factsByMachine(machineId);
        if (facts is null)
            return (null, null, $"no device facts for '{machineId}' — {op} refuses (policy cannot be evaluated; fail closed)");
        var resolved = PeripheralResolver.Resolve(_policy, facts, Exceptions.LiveExceptionRules(_now()), _now());
        if (!resolved.FeatureEnabled)
            return (facts, null, $"peripheral control is disabled by policy for machine '{machineId}' ({PeripheralKeys.FeatureEnabled}) — {op} refuses");
        return (facts, resolved, "ok");
    }

    private (IDeviceFacts? Facts, string Reason) Gate(string machineId, string op)
    {
        var (facts, _, reason) = GateCore(machineId, op);
        return (facts is null || reason != "ok" ? null : facts, reason);
    }

    public (ResolvedPeripheralPolicy? Policy, string Reason) ResolvePolicy(string machineId)
    {
        var (_, resolved, reason) = GateCore(machineId, "policy resolution");
        if (resolved is null) return (null, reason);
        return (resolved, $"resolved peripheral control for machine '{machineId}': mode {resolved.EffectiveModeLabel}, tracing {(resolved.TracingEnabled ? "ON" : "OFF")}, {resolved.Rules.Count} applicable rules");
    }

    /// <summary>Evaluate one device connection. Order matters: the
    /// seen-registry observes FIRST (collision + first-seen facts
    /// exist even for allowed devices), then the policy decision.
    /// Collisions always raise an alert + audit entry; a first-seen
    /// HID in ENFORCE mode raises the named new-HID event (BadUSB
    /// shape) even when class policy allows HIDs; a block/would-block
    /// raises the block event with the full identity + matched rule.</summary>
    public (PeripheralDecision? Decision, SeenOutcome? Seen, string Reason) EvaluateConnection(string machineId, DeviceIdentity? identity, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(machineId);
        if (resolved is null)
        {
            _audit.Append("peripheral_connect_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} reason={reason}", now);
            return (null, null, reason);
        }
        if (identity is null) return (null, null, "no device identity presented — connection decision refused");
        if (!string.Equals(identity.MachineId, machineId, StringComparison.OrdinalIgnoreCase))
            return (null, null, $"the identity names machine '{identity.MachineId}' inside a connection decision for '{machineId}' — refused");
        if (identity.Validate() is { } invalid)
        {
            // D38-F1: an identity that FAILS validation (unrecognised
            // class string, no VID/PID and no serial, malformed
            // VID/PID) is the MOST suspicious presentation, not the
            // least — it gets a real guard decision (blocked in
            // enforce, would-block in audit) AND the block alert,
            // exactly like the unknown-class guard. It never falls
            // through to a silent audit-only refusal.
            var disposition = resolved.Mode == PeripheralModes.Enforce
                ? PeripheralDispositions.Blocked : PeripheralDispositions.WouldBlock;
            var guardDecision = new PeripheralDecision(identity, disposition, null, resolved.Mode,
                $"device [{identity.StrengthLabel}] {(disposition == PeripheralDispositions.Blocked ? "BLOCKED" : "WOULD be blocked")} by the unidentifiable-device guard: the presented identity failed validation ({invalid}) — a device that cannot be identified does not get a free pass ({(disposition == PeripheralDispositions.Blocked ? "ENFORCE mode" : "AUDIT-ONLY mode: the device was NOT blocked")})");
            var ev = new PeripheralEvent(PeripheralAlertKind.Blocked, machineId, identity,
                "unidentifiable-device guard (identity failed validation; no rule matched)", resolved.Mode,
                guardDecision.ActuallyBlocked, now,
                $"{guardDecision.Reason} | identity class={identity.Class} vid={identity.VendorId} pid={identity.ProductId} serial={identity.Serial} display={identity.DisplayName}");
            _alertSink.Raise(ev);
            _audit.Append(guardDecision.ActuallyBlocked ? "peripheral_blocked" : "peripheral_would_block",
                actor ?? "peripheral-control-service",
                $"machine={machineId} class={identity.Class} vid={identity.VendorId} pid={identity.ProductId} serial={identity.Serial} rule=unidentifiable-device guard reason={invalid} mode={guardDecision.EffectiveModeLabel} actuallyBlocked={guardDecision.ActuallyBlocked}", now);
            return (guardDecision, null, guardDecision.Reason);
        }

        var seen = Seen.Observe(identity);
        if (seen.IsIdentityCollision)
        {
            var ev = new PeripheralEvent(PeripheralAlertKind.IdentityCollision, machineId, identity,
                null, resolved.Mode, false, now,
                $"{seen.Detail} | identity class={identity.NormalizedClass} vid={identity.NormalizedVid} pid={identity.NormalizedPid} serial={identity.NormalizedSerial} [{identity.StrengthLabel}]");
            _alertSink.Raise(ev);
            _audit.Append("peripheral_identity_collision", actor ?? "peripheral-control-service",
                $"machine={machineId} detail={seen.Detail}", now);
        }

        var decision = PeripheralEvaluator.Evaluate(identity, resolved, now);

        // D38-F9: first-seen HID detection fires in EVERY mode —
        // the event blocks nothing by itself, so gating it on
        // enforce left the default (audit) fleet with NO BadUSB
        // detection at all.
        if (identity.NormalizedClass == DeviceClasses.Hid && seen.IsFirstSeen)
        {
            var ev = new PeripheralEvent(PeripheralAlertKind.NewHid, machineId, identity,
                decision.MatchedRule?.Describe(), resolved.Mode, decision.ActuallyBlocked, now,
                $"NEW HID first seen on machine '{machineId}' in {resolved.Mode.ToUpperInvariant()} mode: {identity.KeyBase} serial={identity.NormalizedSerial} [{identity.StrengthLabel}] — a never-before-seen keyboard-class device is the BadUSB shape; the connection decision was {decision.Disposition} ({decision.Reason}). Named as an event whether allowed or blocked.");
            _alertSink.Raise(ev);
            _audit.Append("peripheral_new_hid", actor ?? "peripheral-control-service",
                $"machine={machineId} identity={identity.Key} disposition={decision.Disposition} mode={decision.EffectiveModeLabel}", now);
        }

        if (decision.IsStoppedOrWouldStop)
        {
            var ruleDescription = decision.MatchedRule?.Describe() ?? "unknown-class guard (no rule matched)";
            var ev = new PeripheralEvent(PeripheralAlertKind.Blocked, machineId, identity,
                ruleDescription, decision.EffectiveMode, decision.ActuallyBlocked, now,
                $"{decision.Reason} | identity class={identity.NormalizedClass} vid={identity.NormalizedVid} pid={identity.NormalizedPid} serial={identity.NormalizedSerial} display={identity.DisplayName} [{identity.StrengthLabel}] rule={ruleDescription}");
            _alertSink.Raise(ev);
            _audit.Append(decision.ActuallyBlocked ? "peripheral_blocked" : "peripheral_would_block",
                actor ?? "peripheral-control-service",
                $"machine={machineId} class={identity.NormalizedClass} vid={identity.NormalizedVid} pid={identity.NormalizedPid} serial={identity.NormalizedSerial} rule={ruleDescription} mode={decision.EffectiveModeLabel} actuallyBlocked={decision.ActuallyBlocked}", now);
        }
        else if (decision.Disposition == PeripheralDispositions.Allowed)
        {
            _audit.Append("peripheral_allowed", actor ?? "peripheral-control-service",
                $"machine={machineId} class={identity.NormalizedClass} vid={identity.NormalizedVid} pid={identity.NormalizedPid} serial={identity.NormalizedSerial} rule={decision.MatchedRule?.Describe() ?? "none"} mode={decision.EffectiveModeLabel} firstSeen={seen.IsFirstSeen}", now);
        }
        return (decision, seen, decision.Reason);
    }

    /// <summary>Trace a storage medium's connection. Tracing has its
    /// own policy switch: with tracing OFF the refusal is named and
    /// audited — a silent gap in the evidence trail is
    /// unrepresentable.</summary>
    public (MediaTraceRecord? Record, string Reason) TraceMediaConnection(string machineId, DeviceIdentity? identity, string watcherMode, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(machineId);
        if (resolved is null) return (null, reason);
        if (!resolved.TracingEnabled)
        {
            _audit.Append("media_trace_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} reason=media tracing is disabled by policy ({PeripheralKeys.Tracing}) — the connect is NOT traced and that gap is named, never silent", now);
            return (null, $"media tracing is disabled by policy for machine '{machineId}' ({PeripheralKeys.Tracing}) — connect NOT traced (named gap)");
        }
        if (identity is null) return (null, "no device identity presented — media trace refused");
        // D38-F2: the identity must name the machine whose policy
        // was resolved — the same check TraceTransfer always had.
        if (!string.Equals(identity.MachineId, machineId, StringComparison.OrdinalIgnoreCase))
            return (null, $"the identity names machine '{identity.MachineId}' inside a media connection trace for '{machineId}' — refused");
        var (rec, traceReason) = Trace.RecordConnection(identity, watcherMode, now);
        if (rec is not null)
            _audit.Append("media_connected_traced", actor ?? "peripheral-control-service",
                $"machine={machineId} seq={rec.Seq} device={rec.DeviceKey} hash={rec.Hash}", now);
        return (rec, traceReason);
    }

    /// <summary>Trace a storage medium's disconnection (D38-F6:
    /// the service previously had NO disconnect path, so a traced
    /// connection stayed 'live' forever and every later transfer
    /// was accepted). Same gates as the connect: policy, tracing
    /// switch (refusal named + audited), machine pinning.</summary>
    public (MediaTraceRecord? Record, string Reason) TraceMediaDisconnection(string machineId, DeviceIdentity? identity, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(machineId);
        if (resolved is null) return (null, reason);
        if (!resolved.TracingEnabled)
        {
            _audit.Append("media_trace_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} reason=media tracing is disabled by policy ({PeripheralKeys.Tracing}) — the disconnect is NOT traced and that gap is named, never silent", now);
            return (null, $"media tracing is disabled by policy for machine '{machineId}' ({PeripheralKeys.Tracing}) — disconnect NOT traced (named gap)");
        }
        if (identity is null) return (null, "no device identity presented — media disconnect trace refused");
        if (!string.Equals(identity.MachineId, machineId, StringComparison.OrdinalIgnoreCase))
            return (null, $"the identity names machine '{identity.MachineId}' inside a media disconnection trace for '{machineId}' — refused");
        var (rec, traceReason) = Trace.RecordDisconnection(identity, now);
        _audit.Append(rec is not null ? "media_disconnected_traced" : "media_trace_refused",
            actor ?? "peripheral-control-service",
            rec is not null
                ? $"machine={machineId} seq={rec.Seq} device={rec.DeviceKey} hash={rec.Hash}"
                : $"machine={machineId} reason={traceReason}", now);
        return (rec, traceReason);
    }

    public (MediaTraceRecord? Record, string Reason) TraceTransfer(string machineId, DeviceIdentity? identity,
        string? fileName, long sizeBytes, string? sha256, string watcherMode, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(machineId);
        if (resolved is null) return (null, reason);
        if (!resolved.TracingEnabled)
        {
            _audit.Append("media_trace_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} file={fileName} reason=media tracing is disabled by policy — the transfer is NOT traced and that gap is named, never silent", now);
            return (null, $"media tracing is disabled by policy for machine '{machineId}' ({PeripheralKeys.Tracing}) — transfer NOT traced (named gap)");
        }
        if (identity is null) return (null, "no device identity presented — transfer trace refused");
        if (!string.Equals(identity.MachineId, machineId, StringComparison.OrdinalIgnoreCase))
            return (null, $"the identity names machine '{identity.MachineId}' inside a transfer trace for '{machineId}' — refused");
        var (rec, traceReason) = Trace.RecordTransfer(identity, fileName, sizeBytes, sha256, watcherMode, now);
        if (rec is not null)
            // D38-F11c: the ~1 KB coverage statement is NOT embedded
            // in every transfer audit entry — it lives in
            // TransferPathVisibility.CoverageStatement, referenced here.
            _audit.Append("media_transfer_traced", actor ?? "peripheral-control-service",
                $"machine={machineId} seq={rec.Seq} file={rec.FileName} size={rec.FileSizeBytes} sha256={rec.FileSha256} device={rec.DeviceKey} watcher={rec.WatcherMode} coverage=TransferPathVisibility.CoverageStatement", now);
        else
            // D38-F6: a refused transfer still leaves its evidence —
            // file name + size + SHA-256 — in the chained audit, even
            // though no trace-chain record is minted for a transfer
            // the chain cannot witness.
            _audit.Append("media_trace_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} file={fileName} size={sizeBytes} sha256={sha256} reason={traceReason}", now);
        return (rec, traceReason);
    }

    public (PeripheralApplyResult? Result, string Reason) EvaluateAndApply(string machineId, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(machineId);
        if (resolved is null)
        {
            _audit.Append("peripheral_apply_refused", actor ?? "peripheral-control-service",
                $"machine={machineId} reason={reason}", now);
            return (null, reason);
        }
        var plan = new PeripheralEnforcementPlan(machineId, resolved.Mode, resolved.Rules, now);
        var result = _applier.Apply(plan);
        _audit.Append(result.Applied ? "peripheral_applied" : "peripheral_not_applied",
            actor ?? "peripheral-control-service",
            $"machine={machineId} mode={resolved.EffectiveModeLabel} rules={resolved.Rules.Count} notes=[{string.Join("; ", resolved.Notes)}] applier={result.Detail}", now);
        return (result, result.Applied
            ? $"peripheral control applied to machine '{machineId}': {result.Detail}"
            : $"peripheral control for machine '{machineId}' was computed but NOT applied: {result.Detail}");
    }

    // ---- exception workflow ----------------------------------------------

    public (PeripheralAccessRequest? Request, bool Created, string Reason) FileExceptionRequest(
        string authenticatedMachineId, string? claimedMachineId, string requestId,
        string? requester, DeviceIdentity? identity, string? businessReason, string actor)
    {
        var now = _now();
        var (facts, gateReason) = Gate(authenticatedMachineId, "exception filing");
        if (facts is null)
        {
            _audit.Append("peripheral_request_refused", actor ?? "peripheral-control-service",
                $"machine={authenticatedMachineId} request={requestId} reason={gateReason}", now);
            return (null, false, gateReason);
        }
        var (request, created, reason) = Exceptions.File(
            authenticatedMachineId, claimedMachineId, requestId, requester, identity, businessReason, now);
        if (request is null)
        {
            _audit.Append("peripheral_request_refused", actor ?? "peripheral-control-service",
                $"machine={authenticatedMachineId} request={requestId} reason={reason}", now);
            return (null, false, reason);
        }
        if (created)
        {
            var text = $"Peripheral exception request: {request.Identity.NormalizedClass} device vid={request.Identity.NormalizedVid} pid={request.Identity.NormalizedPid} serial={request.Identity.NormalizedSerial} [{request.Identity.StrengthLabel}] — {request.BusinessReason}";
            var (item, _, wiReason) = _workItems.IntakeRequest(authenticatedMachineId, facts.ScopeId,
                new UserWorkRequest(request.Id, authenticatedMachineId, request.Requester, text, null), now);
            _audit.Append("peripheral_request_filed", actor ?? "peripheral-control-service",
                $"machine={authenticatedMachineId} request={request.Id} requester={request.Requester} device={request.Identity.Key} workItem={item?.Id} workItemReason={wiReason}", now);
        }
        return (request, created, reason);
    }

    public (PeripheralAccessRequest? Request, PeripheralRule? Rule, string Reason) ApproveExceptionRequest(
        string requestId, string? approver, DateTimeOffset? expiresUtc, string actor)
    {
        var now = _now();
        var standing = Exceptions.Get(requestId);
        if (standing is null) return (null, null, $"unknown request '{requestId}' — approval refused");
        // Approval MINTS policy power → gated on the toggle for the
        // request's machine (RMM-25 R25R-F5 discipline). Denial is
        // deliberately NOT gated: it mints nothing. ONE gate lookup
        // (D38-F12: no second facts fetch on top of the gate).
        var (_, _, gateReason) = GateCore(standing.MachineId, "exception approval");
        if (gateReason != "ok")
        {
            _audit.Append("peripheral_request_approval_refused", actor ?? "peripheral-control-service",
                $"request={requestId} approver={approver} reason={gateReason}", now);
            return (null, null, gateReason);
        }
        var (request, rule, reason) = Exceptions.Approve(requestId, approver, expiresUtc, now);
        _audit.Append(request is not null ? "peripheral_request_approved" : "peripheral_request_approval_refused",
            actor ?? "peripheral-control-service",
            $"request={requestId} approver={approver} rule={rule?.Id} reason={reason}", now);
        return (request, rule, reason);
    }

    public (PeripheralAccessRequest? Request, string Reason) DenyExceptionRequest(
        string requestId, string? denier, string? reason, string actor)
    {
        var now = _now();
        var (request, denyReason) = Exceptions.Deny(requestId, denier, reason, now);
        _audit.Append(request is not null ? "peripheral_request_denied" : "peripheral_request_denial_refused",
            actor ?? "peripheral-control-service",
            $"request={requestId} denier={denier} reason={denyReason}", now);
        return (request, denyReason);
    }
}

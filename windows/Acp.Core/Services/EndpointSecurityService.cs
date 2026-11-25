using System.Text;
using Acp.Shared.EndpointSecurity;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Core.Services;

// =====================================================================
// RMM-17 — the endpoint security service for ONE device: wires the
// Shared model (detector, isolation manager, AV posture) to the
// RMM-07 policy engine, the RMM-01 alert centre and the hash-chained
// audit. Consumes, through public surfaces only:
//   * RMM-07: rmm.endpoint_security.enabled (TOTAL POLICY CONTROL)
//     + the RMM-17 policy content (thresholds, required AV) through
//     Effective Policy. Policy clamps (attempts to weaken the bar)
//     are audited on first sight per policy revision of the values.
//   * RMM-01: HealthAlertCentre — the isolation CRITICAL alert and
//     the AV findings (security_av_off kind, never suppressible)
//     surface there; this service owns no second alert surface.
//   * RMM-03: SignedCommandGate — un-isolation and AV management
//     commands verify through it; unsigned/wrong-class/altered
//     commands refuse at the gate and the refusal is chained there.
// Host wiring remainders (named, never faked): the real file
// watcher + entropy sampler behind IFileActivitySource, the OS
// firewall/NIC actuation behind IEndpointNetworkControl, the
// SecurityCenter2 reader behind IAvStatusSource, and the vendor
// installer run behind an AV management intent.
// =====================================================================

public sealed record SecurityCycleResult(
    bool FeatureEnabled,
    DetectionVerdict? Verdict,
    bool IsolationApplied,
    string? AlertOutcome,
    string Detail);

public sealed class EndpointSecurityService
{
    private readonly string _deviceId;
    private readonly IDeviceFacts _facts;
    private readonly ManagementPolicyEngine _policy;
    private readonly RansomwareDetector _detector;
    private readonly IFileActivitySource _fileActivity;
    private readonly EndpointIsolationManager _isolation;
    private readonly IsolationPlan _isolationPlan;
    private readonly IAvStatusSource _avSource;
    private readonly HealthAlertCentre _centre;
    private readonly ChainedAuditLog _audit;
    private readonly SignedCommandGate? _gate;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private DetectionVerdict? _lastVerdict;
    private AvPostureReport? _lastPosture;
    private string? _clampsAuditedFor;
    private bool _disabledAudited;

    public EndpointSecurityService(
        string deviceId,
        IDeviceFacts facts,
        ManagementPolicyEngine policy,
        RansomwareDetector detector,
        IFileActivitySource fileActivity,
        EndpointIsolationManager isolation,
        IsolationPlan isolationPlan,
        IAvStatusSource avSource,
        HealthAlertCentre centre,
        ChainedAuditLog audit,
        SignedCommandGate? gate = null,
        Func<DateTimeOffset>? now = null)
    {
        _deviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        _facts = facts ?? throw new ArgumentNullException(nameof(facts));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _detector = detector ?? throw new ArgumentNullException(nameof(detector));
        _fileActivity = fileActivity ?? throw new ArgumentNullException(nameof(fileActivity));
        _isolation = isolation ?? throw new ArgumentNullException(nameof(isolation));
        _isolationPlan = isolationPlan ?? throw new ArgumentNullException(nameof(isolationPlan));
        _avSource = avSource ?? throw new ArgumentNullException(nameof(avSource));
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _gate = gate;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public bool FeatureEnabled => _policy.IsEnabled(_facts, EndpointSecurityPolicyKeys.Enabled);
    public IsolationStatus IsolationStatus => _isolation.Status;
    public DetectionVerdict? LastVerdict { get { lock (_lock) return _lastVerdict; } }
    public AvPostureReport? LastPosture { get { lock (_lock) return _lastPosture; } }

    /// <summary>Effective RMM-17 policy for this device, with any
    /// bar-weakening clamps audited once per distinct clamp set.</summary>
    public EndpointSecurityPolicy CurrentPolicy(DateTimeOffset now)
    {
        var p = EndpointSecurityPolicy.FromEffective(_policy.ComputeEffective(_facts));
        if (p.ClampNotes.Count > 0)
        {
            var key = string.Join(";", p.ClampNotes);
            lock (_lock)
            {
                if (_clampsAuditedFor != key)
                {
                    _clampsAuditedFor = key;
                    _audit.Append("endpoint_security_policy_clamped", "endpoint-security",
                        $"device={_deviceId} clamps={key}", now);
                }
            }
        }
        return p;
    }

    /// <summary>One detection cycle: drain the file-activity seam,
    /// evaluate the window, and — when the bar is met, policy allows
    /// auto-isolation and the feature is on — isolate + raise the
    /// CRITICAL alert. While already isolated, a still-firing
    /// verdict refreshes the alert (dedup) so a maintenance window
    /// can never permanently swallow it.</summary>
    public SecurityCycleResult RunDetectionCycle()
    {
        var now = _now();
        if (!FeatureEnabled)
        {
            // BD-WIN-CORE-3/F10: the isolation obligation is checked
            // BEFORE the feature gate. An isolated (or
            // isolation_failed) device KEEPS alerting / retrying even
            // when policy turns the feature off — the D38-F2 "never
            // quiet" rule does not end with a policy flip, and a
            // failed isolation is retried (actuation is a safety
            // act, not a detection act).
            var st = _isolation.Status;
            if (st.IsIsolated || st.State == IsolationStates.IsolationFailed)
            {
                // BD-SHARED-TRANSPORT lane build-unblock (no
                // behaviour change): these locals were named
                // verdict/outcome/detail, colliding with the
                // method-level declarations below (CS0136) — the
                // tree did not compile. Renamed in this block only.
                var standingVerdict = LastVerdict ?? new DetectionVerdict(false,
                    Array.Empty<string>(), 0, 0, 0, 0, false, false,
                    "feature disabled by policy while isolation state stands");
                var standingOutcome = RaiseIsolationAlert(standingVerdict, now);
                var retried = false;
                if (st.State == IsolationStates.IsolationFailed)
                {
                    var (ok, retryDetail) = _isolation.Isolate(_isolationPlan,
                        "retry of failed isolation while feature disabled by policy (BD-WIN-CORE-3/F10: the never-quiet obligation outlives the feature gate)", now);
                    retried = ok;
                    if (!ok)
                        _audit.Append("ransomware_isolation_actuation_failed", "endpoint-security",
                            $"device={_deviceId} retry-while-disabled detail={retryDetail}", now);
                }
                _audit.Append("endpoint_security_disabled_while_isolated", "endpoint-security",
                    $"device={_deviceId} state={st.State} — feature is OFF by policy but the isolation alert obligation continues (D38-F2/BD-WIN-CORE-3/F10)", now);
                _fileActivity.Drain();
                return new SecurityCycleResult(false, standingVerdict, retried, standingOutcome,
                    $"feature disabled by policy, but device is {st.State} — isolation alert re-raised{(retried ? "; isolation retry applied" : "")}");
            }
            lock (_lock)
            {
                if (!_disabledAudited)
                {
                    _disabledAudited = true;
                    _audit.Append("endpoint_security_disabled", "endpoint-security",
                        $"device={_deviceId} — rmm.endpoint_security.enabled is off; detector and AV posture are inert", now);
                }
            }
            // Drain even while disabled so stale activity cannot
            // accumulate and fire the moment the feature re-enables.
            _fileActivity.Drain();
            return new SecurityCycleResult(false, null, false, null,
                "feature disabled by policy (rmm.endpoint_security.enabled)");
        }
        lock (_lock) _disabledAudited = false;

        var policy = CurrentPolicy(now);
        _detector.Ingest(_fileActivity.Drain());
        var verdict = _detector.Evaluate(policy.Thresholds, now);
        lock (_lock) _lastVerdict = verdict;

        if (!verdict.ShouldIsolate)
        {
            // D38-F2: the alert / retry obligation does NOT end when
            // the burst ages out of the window. While ISOLATED, the
            // CRITICAL alert re-raises every cycle (the centre dedups
            // it into a refresh) — a maintenance window that met the
            // first raise can never leave an isolated device with no
            // alert landed. While ISOLATION_FAILED, actuation is
            // RETRIED every cycle until it lands — a failed cut that
            // is never retried once activity stops is a silent
            // un-isolated machine under attack.
            var st = _isolation.Status;
            if (st.IsIsolated)
            {
                var reOutcome = RaiseIsolationAlert(verdict, now);
                return new SecurityCycleResult(true, verdict, true, reOutcome,
                    $"still isolated (since {st.SinceUtc:O}); alert re-raised this cycle: {verdict.Detail}");
            }
            if (st.State == IsolationStates.IsolationFailed)
            {
                if (!policy.AutoIsolation)
                {
                    var alertOnly2 = RaiseIsolationAlert(verdict, now);
                    return new SecurityCycleResult(true, verdict, false, alertOnly2,
                        "isolation previously FAILED and auto-isolation is now OFF by policy — alert re-raised, actuation not retried");
                }
                var (retried, retryDetail) = _isolation.Isolate(_isolationPlan,
                    $"retry of failed isolation actuation (device has been in isolation_failed since {st.SinceUtc:O}; original verdict in the audit chain)", now);
                var retryOutcome = RaiseIsolationAlert(verdict, now);
                if (!retried)
                    _audit.Append("ransomware_isolation_actuation_failed", "endpoint-security",
                        $"device={_deviceId} retry detail={retryDetail}", now);
                return new SecurityCycleResult(true, verdict, retried, retryOutcome,
                    retried ? $"isolation retry applied: {retryDetail}"
                            : $"isolation retry NOT applied: {retryDetail}");
            }
            return new SecurityCycleResult(true, verdict, false, null, verdict.Detail);
        }

        if (!policy.AutoIsolation)
        {
            _audit.Append("ransomware_detected_no_auto_isolation", "endpoint-security",
                $"device={_deviceId} verdict={verdict.Detail} — auto-isolation is OFF by policy; alerting only", now);
            var alertOnly = RaiseIsolationAlert(verdict, now);
            return new SecurityCycleResult(true, verdict, false, alertOnly,
                "ransomware bar met but auto-isolation disabled by policy — alert raised, endpoint NOT isolated");
        }

        var (applied, detail) = _isolation.Isolate(_isolationPlan,
            $"suspected ransomware behaviour ({verdict.Detail})", now);
        var outcome = RaiseIsolationAlert(verdict, now);
        if (!applied && _isolation.Status.State == IsolationStates.IsolationFailed)
        {
            // Actuation failed: the CRITICAL alert still goes out —
            // an un-isolated machine under active encryption is the
            // worst case and it is never quiet.
            _audit.Append("ransomware_isolation_actuation_failed", "endpoint-security",
                $"device={_deviceId} verdict={verdict.Detail} detail={detail}", now);
        }
        return new SecurityCycleResult(true, verdict, applied, outcome,
            applied ? $"isolated: {detail}" : $"isolation NOT applied: {detail}");
    }

    private string RaiseIsolationAlert(DetectionVerdict verdict, DateTimeOffset now)
    {
        var outcome = _centre.Raise(_deviceId, Rmm17AlertKinds.IsolationConditionId,
            Rmm17AlertKinds.RansomwareIsolation, AlertSeverities.Critical,
            $"suspected ransomware: {verdict.Detail}", "endpoint-security",
            TimeSpan.Zero, now);
        if (outcome.Outcome == RaiseOutcome.Suppressed)
            _audit.Append("ransomware_alert_suppressed_by_window", "endpoint-security",
                $"device={_deviceId} — the alert was suppressed by a maintenance window (unexpected: ransomware_isolation is in RMM-01's NeverSuppressible set since RES-3, so this branch is defence-in-depth only); the ISOLATION, audit chain and user banner are NOT suppressed, and the alert re-raises every cycle while isolated or isolation_failed (D38-F2)", now);
        return outcome.Outcome;
    }

    /// <summary>Refresh AV posture from the security-centre seam and
    /// feed RMM-01: every non-protected finding raises (or refreshes)
    /// a security_av_off alert under its rmm17 condition id; a
    /// finding that clears auto-resets its alert. Returns the
    /// report (null when the feature is policy-disabled).</summary>
    public AvPostureReport? RefreshAvPosture()
    {
        var now = _now();
        if (!FeatureEnabled)
        {
            // BD-WIN-CORE-3/F10: turning the feature off must not
            // strand never-suppressible rmm17-av-* alerts active
            // forever with no code path that can reset them. Reset
            // them explicitly, with the reason on the record.
            foreach (var active in _centre.ActiveAlerts.Where(a =>
                         a.DeviceId == _deviceId && a.ConditionId.StartsWith("rmm17-av-", StringComparison.Ordinal)).ToList())
                _centre.Reset(active.AlertId, "endpoint-security",
                    "feature disabled by policy (BD-WIN-CORE-3/F10)", now);
            return null;
        }
        var policy = CurrentPolicy(now);
        var report = AvPostureEvaluator.Evaluate(_deviceId, _avSource.Read(now), policy, now);
        lock (_lock) _lastPosture = report;

        var gapConditions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in report.Findings.Where(f => f.State != AvPostureStates.Protected))
        {
            // D38-F9 (remainder): an UNREGISTERED tool's "unknown"
            // finding is not an AV-off alert when a registered
            // product IS protected — an extra harmless agent beside
            // a healthy required product must not pin a permanent
            // never-suppressible security_av_off alert. The finding
            // stays in the report; it raises only when it is part of
            // an actual gap (nothing protected), and auto-resets
            // when protection appears (it is not in gapConditions).
            if (f.State == AvPostureStates.Unknown && report.AnyProtected)
                continue;
            gapConditions.Add(f.ConditionId);
            var severity = f.State is AvPostureStates.Missing or AvPostureStates.Disabled
                ? AlertSeverities.Critical : AlertSeverities.Warning;
            _centre.Raise(_deviceId, f.ConditionId, f.ConditionKind, severity,
                $"[{f.State}] {f.Detail}", "endpoint-security", TimeSpan.FromMinutes(30), now);
        }
        // Clear alerts whose gap closed.
        foreach (var active in _centre.ActiveAlerts.Where(a =>
                     a.DeviceId == _deviceId && a.ConditionId.StartsWith("rmm17-av-", StringComparison.Ordinal)
                     && !gapConditions.Contains(a.ConditionId)).ToList())
            _centre.Reset(active.AlertId, "endpoint-security",
                "auto-reset: AV posture gap closed", now);
        return report;
    }

    /// <summary>Hub-issued release: the ONLY un-isolate path. The
    /// envelope verifies through the RMM-03 gate (class automation)
    /// and binds to this device in the isolation manager.</summary>
    public (bool Applied, string Detail) HandleSignedUnisolate(SignedCommandEnvelope? envelope)
    {
        if (_gate is null)
            return (false, "un-isolate refused: no signed-command gate is wired on this endpoint (RMM-03)");
        var result = _isolation.HandleSignedUnisolate(envelope, _gate, _now());
        if (result.Applied) _detector.Reset();
        return result;
    }

    /// <summary>Local release attempt — refused by construction (see
    /// EndpointIsolationManager.TryLocalUnisolate).</summary>
    public (bool Applied, string Detail) TryLocalUnisolate(string actor) =>
        _isolation.TryLocalUnisolate(actor, _now());

    /// <summary>Build an AV management intent (deploy/configure the
    /// org's chosen tool) and return the payload bytes for the hub
    /// to sign under the intent's RMM-03 class. Creation is audited;
    /// the intent itself executes nothing.</summary>
    public (AvManagementIntent? Intent, string? Refusal) CreateAvManagementIntent(
        string productId, string action, IReadOnlyDictionary<string, string>? settings = null)
    {
        var now = _now();
        if (!FeatureEnabled)
            return (null, "AV management refused: rmm.endpoint_security.enabled is off for this device");
        var (intent, refusal) = AvManagementIntent.Build(productId, action, _deviceId, settings);
        if (intent is null) return (null, refusal);
        _audit.Append("av_management_intent_created", "endpoint-security",
            $"device={_deviceId} product={intent.ProductId} action={intent.Action} class={intent.CommandClass}", now);
        return (intent, null);
    }

    /// <summary>Endpoint side of an AV management command: verify
    /// the signed envelope through the RMM-03 gate under the
    /// intent's class and bind its payload (product + action + THIS
    /// device). Verification is ACP's deliverable; the vendor
    /// installer's actual run is host wiring and is reported as
    /// such — never as done.</summary>
    public (bool Verified, string Detail) ApplyAvManagementCommand(
        AvManagementIntent intent, SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
            return (false, "AV management command refused: no signed-command gate is wired on this endpoint (RMM-03)");
        // D38-F5: the intent is CALLER-SUPPLIED, so it proves
        // nothing until it is itself bound: (a) its device must be
        // THIS device; (b) its payload must parse and its fields
        // (product + action + device) must equal the intent's own
        // fields — an intent wrapping another intent's payload, or
        // another device's payload, refuses; (c) the command class
        // is RECOMPUTED from the parsed action, never taken from
        // the caller — a deploy intent re-labelled "automation"
        // refuses. All binding checks run BEFORE the gate, so a
        // mis-bound command does not burn its nonce at the gate.
        if (intent is null)
            return (false, "AV management command refused: no intent supplied");
        string Refuse(string why)
        {
            _audit.Append("av_management_intent_binding_refused", "endpoint-security",
                $"device={_deviceId} product={intent.ProductId} action={intent.Action} — {why}", now);
            return $"AV management command refused: {why}";
        }
        if (!string.Equals(intent.DeviceId, _deviceId, StringComparison.OrdinalIgnoreCase))
            return (false, Refuse($"intent targets device '{intent.DeviceId}', not this device '{_deviceId}'"));
        string pAction, pProduct, pDevice;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(intent.PayloadJson ?? "");
            pAction = doc.RootElement.GetProperty("action").GetString() ?? "";
            pProduct = doc.RootElement.GetProperty("productId").GetString() ?? "";
            pDevice = doc.RootElement.GetProperty("deviceId").GetString() ?? "";
        }
        catch
        {
            return (false, Refuse("intent payload is not the expected JSON shape"));
        }
        if (!string.Equals(pDevice, _deviceId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(pProduct, intent.ProductId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(pAction, $"rmm17.av.{intent.Action}", StringComparison.Ordinal))
            return (false, Refuse($"intent payload (product={pProduct} action={pAction} device={pDevice}) does not match the intent's own fields (product={intent.ProductId} action={intent.Action} device={intent.DeviceId})"));
        var expectedClass = AvManagementActions.CommandClassFor(intent.Action);
        if (!string.Equals(intent.CommandClass, expectedClass, StringComparison.Ordinal))
            return (false, Refuse($"intent command class '{intent.CommandClass}' is not the class recomputed from its action ('{expectedClass}') — a re-labelled intent proves nothing"));
        var verdict = _gate.Authorize(envelope, now, expectedClass);
        if (!verdict.Allowed)
            return (false, $"AV management command refused: {verdict.Reason}");
        var payloadText = Encoding.UTF8.GetString(verdict.Payload!);
        if (payloadText != intent.PayloadJson)
        {
            _audit.Append("av_management_payload_mismatch", "endpoint-security",
                $"device={_deviceId} product={intent.ProductId} action={intent.Action} — signed payload does not match the admitted intent", now);
            return (false, "AV management command refused: signed payload does not match the admitted intent");
        }
        _audit.Append("av_management_command_verified", "endpoint-security",
            $"device={_deviceId} product={intent.ProductId} action={intent.Action} — signature verified; host execution (vendor installer) is host wiring, NOT performed by this build", now);
        return (true, "signed AV management command verified — host execution is host wiring (named remainder)");
    }

    public EndpointSecurityReport BuildReport()
    {
        lock (_lock)
            return new EndpointSecurityReport(_deviceId, _now(), FeatureEnabled,
                _isolation.Status, _lastVerdict, _lastPosture);
    }
}

using DeskGuest.Shared.ApplicationControl;
using DeskGuest.Shared.Deployment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-25 — AppControlService: the Core wiring for application
// control.
//
// Flow: policy resolves from RMM-07 Effective Policy + the live
// approval rules → the pure evaluator decides a launch → a stopped
// or would-be-stopped launch raises a block event into the alert
// centre (RMM-01 sink) with the full identity + matched rule → the
// enforcement plan goes to the applier seam (AppLocker/WDAC, host
// wiring). The request workflow files an RMM-12 work item for every
// request; approvals mint scoped rules in the request store (which
// resolution then joins) and may offer the RMM-16 packaged install
// path when a package covers the requested application.
//
// Every step is policy-gated by rmm.app_control.enabled and joined
// to the hash-chained ledger, including refusals and the honest
// NOT-applied outcome of the unavailable applier. Every audit
// detail for a decision carries the EFFECTIVE MODE LABEL — the
// record can never leave the mode ambiguous.
// =====================================================================

public sealed class AppControlService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly IAppControlApplier _applier;
    private readonly IAppBlockAlertSink _alertSink;
    private readonly WorkItemStore _workItems;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly Func<string, DeploymentPackage?>? _packageById;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<IReadOnlyList<string>>? _approverPrincipalSource;
    private readonly List<string> _constructorPrincipals = new();

    private void RefreshApproverPrincipals()
    {
        if (_approverPrincipalSource is null) return;
        // FL-25b/DF9: the refreshed set is the UNION of the
        // constructor-registered ids and the live source's ids.
        // The FL-25 refresh REPLACED the set from the source alone,
        // so the first decision after wiring a source silently
        // discarded every statically registered principal.
        try { Requests.SetApproverPrincipals(_constructorPrincipals.Concat(_approverPrincipalSource())); }
        catch { Requests.SetApproverPrincipals(_constructorPrincipals); } // source failure: statically registered ids only, source-granted power lapses
    }

    public AppAccessRequestStore Requests { get; } = new();

    public AppControlService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        IAppControlApplier applier,
        IAppBlockAlertSink alertSink,
        WorkItemStore workItems,
        Func<string, IDeviceFacts?> factsByDevice,
        Func<string, DeploymentPackage?>? packageById = null,
        Func<DateTimeOffset>? now = null,
        IEnumerable<string>? approverPrincipalIds = null,
        Func<IReadOnlyList<string>>? approverPrincipalSource = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _applier = applier ?? throw new ArgumentNullException(nameof(applier));
        _alertSink = alertSink ?? throw new ArgumentNullException(nameof(alertSink));
        _workItems = workItems ?? throw new ArgumentNullException(nameof(workItems));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _packageById = packageById;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        // FL-25a/F1: wire the store's group authority from the
        // RMM-07 engine — a group exists iff the engine knows it,
        // and membership is the engine's own membership answer for
        // the requesting device's facts.
        Requests.GroupExistenceCheck = groupId =>
            _policy.Groups.Any(g => string.Equals(g.Id, groupId, StringComparison.OrdinalIgnoreCase));
        Requests.GroupMembershipCheck = (deviceId, groupId) =>
        {
            var facts = _factsByDevice(deviceId);
            return facts is not null && _policy.MemberGroupIds(facts)
                .Contains(groupId, StringComparer.OrdinalIgnoreCase);
        };
        // FL-25b/F3: register the approver principals whose ids may
        // decide requests. None registered → decisions fail closed
        // at the store.
        foreach (var principal in approverPrincipalIds ?? Array.Empty<string>())
        {
            Requests.RegisterApproverPrincipal(principal);
            if (!string.IsNullOrWhiteSpace(principal)) _constructorPrincipals.Add(principal.Trim());
        }
        // Lane A (item 4) + FL-25b/DF9: a live source IS wired in
        // production — CoreRuntime passes the roster's
        // ApproverPrincipalIds (CoreRuntime.cs, AppControl
        // construction). At every decision the set is refreshed as
        // the UNION of the constructor ids above and the source's
        // current ids: a principal the source drops (suspended /
        // offboarded) loses decision power at the next decision, a
        // newly seated admin gains it without a restart, and
        // statically registered ids are never silently discarded
        // by the refresh. Still fail-closed: no ids from either
        // source means every decision refuses.
        _approverPrincipalSource = approverPrincipalSource;
    }

    /// <summary>Ledger-safe encoding for identity/actor strings
    /// interpolated into structured audit details (FL-25c/F5):
    /// percent-encodes the characters that could plant a fake
    /// field or marker (space, '=', '|', '%', controls) so the
    /// REAL mode=/actuallyBlocked= markers later in the detail are
    /// the only ones a reader or parser can find.</summary>
    private static string Esc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c == '%' || c == ' ' || c == '=' || c == '|' || char.IsControl(c))
                sb.Append('%').Append(((int)c).ToString("X2"));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private (IDeviceFacts? Facts, string Reason) Gate(string deviceId, string op, bool aliasAware = false)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return (null, $"no device facts for '{deviceId}' — {op} refuses (policy cannot be evaluated; fail closed)");
        if (!aliasAware)
        {
            if (!_policy.IsEnabled(facts, AppControlKeys.FeatureEnabled))
                return (null, $"application control is disabled by policy for device '{deviceId}' ({AppControlKeys.FeatureEnabled}) — {op} refuses");
            return (facts, "ok");
        }
        // FL-25c/F12 (gate-alias parity): the DECISION gate must
        // honour the same toggle resolution as the resolver —
        // seeded spelling first, alias as fallback — otherwise an
        // approval could mint while resolution reported the
        // feature disabled via the alias spelling. (Evaluation and
        // resolution keep the plain gate: the resolver itself
        // reports NotControlled for the alias-off state, the
        // surface R25R-07 pins.)
        var eff = _policy.ComputeEffective(facts);
        var setting = eff.Get(AppControlKeys.FeatureEnabled) ?? eff.Get(AppControlKeys.FeatureEnabledAlias);
        var enabled = setting is not null
            ? bool.TryParse(setting.Value, out var v) && v
            : _policy.IsEnabled(facts, AppControlKeys.FeatureEnabled);
        if (!enabled)
            return (null, $"application control is disabled by policy for device '{deviceId}' ({AppControlKeys.FeatureEnabled}) — {op} refuses");
        return (facts, "ok");
    }

    /// <summary>Resolve the device's effective application-control
    /// policy: RMM-07 content + live approval rules.</summary>
    public (ResolvedAppControlPolicy? Policy, string Reason) ResolvePolicy(string deviceId)
    {
        var (facts, reason) = Gate(deviceId, "policy resolution");
        if (facts is null) return (null, reason);
        // FL-25b/DF6: only THIS device's approval rules go to the
        // resolver — its own live ones (which decide) and its own
        // expired ones (which the resolver names in its notes,
        // recovery fix R25R-F4). The FL-25 code handed over EVERY
        // approval rule in the fleet: other devices' expired rules
        // were named in this device's notes, those notes are
        // ledgered by EvaluateAndApply (leaking other devices'
        // request ids), and the eviction below then removed rules
        // whose owning device may never have seen them named.
        var probe = new AppIdentity(facts.DeviceId, "probe", null, null, null, null, null);
        var memberGroups = new HashSet<string>(_policy.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        var deviceApprovalRules = Requests.ApprovalRulesFor(probe, facts.ScopeId, memberGroups);
        var resolved = AppControlResolver.Resolve(_policy, facts, deviceApprovalRules, _now());
        // Expired rules are evicted AFTER the resolver has named
        // them — and only the ones named HERE (this device's). A
        // rule owned by another device is evicted when THAT device
        // resolves (or when its own expiry is observed there); it
        // is never silently removed by a stranger's resolution.
        if (deviceApprovalRules.Any(r => r.IsExpired(_now())))
        {
            var expiredHere = new HashSet<string>(
                deviceApprovalRules.Where(r => r.IsExpired(_now())).Select(r => r.Id), StringComparer.Ordinal);
            Requests.EvictExpiredApprovalRules(_now(), r => expiredHere.Contains(r.Id));
        }
        return (resolved, $"resolved application control for device '{deviceId}': mode {resolved.EffectiveModeLabel}, {resolved.Rules.Count} applicable rules");
    }

    /// <summary>Decide one launch. A blocked (enforce) or
    /// would-block (audit) verdict raises the block event into the
    /// alert centre with the full identity + matched rule, and is
    /// ledgered with the effective mode label.</summary>
    public (AppDecision? Decision, string Reason) EvaluateLaunch(string deviceId, AppIdentity? identity, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(deviceId);
        if (resolved is null)
        {
            _audit.Append("app_control_launch_refused", actor ?? "app-control-service",
                $"device={deviceId} reason={reason}", now);
            return (null, reason);
        }
        // FL-25c/F10: EVERY refusal is ledgered — the null-identity
        // and device-mismatch refusals previously returned silently.
        if (identity is null)
        {
            _audit.Append("app_control_launch_refused", actor ?? "app-control-service",
                $"device={deviceId} reason=no application identity presented", now);
            return (null, "no application identity presented — launch decision refused");
        }
        if (identity.Validate() is { } invalid)
        {
            _audit.Append("app_control_launch_refused", actor ?? "app-control-service",
                $"device={deviceId} reason={invalid}", now);
            return (null, invalid);
        }
        if (!string.Equals(identity.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
        {
            var mismatch = $"the identity names device '{identity.DeviceId}' inside a launch decision for '{deviceId}' — refused";
            // FL-25b/DF1: identity.DeviceId is caller-supplied and
            // was interpolated RAW into the ledger on this path
            // (the FL-25 F5 fix escaped the block path only). The
            // ledger copy encodes both device ids; the returned
            // reason stays human-readable.
            _audit.Append("app_control_launch_refused", actor ?? "app-control-service",
                $"device={Esc(deviceId)} reason=the identity names device '{Esc(identity.DeviceId)}' inside a launch decision for '{Esc(deviceId)}' — refused", now);
            return (null, mismatch);
        }
        var decision = AppControlEvaluator.Evaluate(identity, resolved, now);
        if (decision.IsStoppedOrWouldStop)
        {
            var ruleDescription = decision.MatchedRule?.Describe() ?? "default-deny (no allow rule matched)";
            var blockEvent = new AppBlockEvent(
                deviceId, identity, ruleDescription,
                decision.EffectiveMode, decision.ActuallyBlocked, now,
                $"{decision.Reason} | identity product={Esc(identity.NormalizedProduct)} version={Esc(identity.Version)} publisher={Esc(identity.PublisherName)} signer={identity.NormalizedSigner} hash={identity.NormalizedHash} path={Esc(identity.NormalizedPath)} rule={ruleDescription}");
            _alertSink.Raise(blockEvent);
            _audit.Append(decision.ActuallyBlocked ? "app_control_blocked" : "app_control_would_block",
                actor ?? "app-control-service",
                $"device={deviceId} product={Esc(identity.NormalizedProduct)} version={Esc(identity.Version)} publisher={Esc(identity.PublisherName)} signer={identity.NormalizedSigner} hash={identity.NormalizedHash} path={Esc(identity.NormalizedPath)} rule={blockEvent.MatchedRuleDescription} mode={decision.EffectiveModeLabel} actuallyBlocked={decision.ActuallyBlocked}", now);
        }
        else
        {
            _audit.Append("app_control_allowed", actor ?? "app-control-service",
                $"device={deviceId} product={Esc(identity.NormalizedProduct)} rule={decision.MatchedRule?.Describe() ?? "none"} mode={decision.EffectiveModeLabel}", now);
        }
        return (decision, decision.Reason);
    }

    /// <summary>Resolve and hand the enforcement plan to the
    /// applier seam. The outcome is returned and ledgered EXACTLY
    /// as the applier reports it.</summary>
    public (AppApplyResult? Result, string Reason) EvaluateAndApply(string deviceId, string actor)
    {
        var now = _now();
        var (resolved, reason) = ResolvePolicy(deviceId);
        if (resolved is null)
        {
            _audit.Append("app_control_apply_refused", actor ?? "app-control-service",
                $"device={deviceId} reason={reason}", now);
            return (null, reason);
        }
        var plan = new AppEnforcementPlan(deviceId, resolved.Mode, resolved.Rules, now);
        var result = _applier.Apply(plan);
        _audit.Append(result.Applied ? "app_control_applied" : "app_control_not_applied",
            actor ?? "app-control-service",
            $"device={deviceId} mode={resolved.EffectiveModeLabel} rules={resolved.Rules.Count} notes=[{string.Join("; ", resolved.Notes)}] applier={result.Detail}", now);
        return (result, result.Applied
            ? $"application control applied to device '{deviceId}': {result.Detail}"
            : $"application control for device '{deviceId}' was computed but NOT applied: {result.Detail}");
    }

    // ---- the request workflow -------------------------------------------

    /// <summary>File a user's request to run blocked software. On
    /// acceptance the request ALSO becomes an RMM-12 work item
    /// (kind=request) naming the application identity + business
    /// reason — the console's queue is the work-item trail, not a
    /// side channel.</summary>
    public (AppAccessRequest? Request, bool Created, string Reason) FileRequest(
        string authenticatedDeviceId, string? claimedDeviceId, string requestId,
        string? requester, AppIdentity? identity, string? businessReason, string actor)
    {
        var now = _now();
        // FL-25b/DF10: the filing gate uses the SAME alias-aware
        // toggle resolution as the approval gate and the resolver.
        // The FL-25 code applied alias parity to approval only, so
        // with rmm.application_control.enabled=false (seeded key
        // unset) requests were still accepted and work items still
        // created while resolution reported the feature disabled.
        var (facts, gateReason) = Gate(authenticatedDeviceId, "request filing", aliasAware: true);
        if (facts is null)
        {
            _audit.Append("app_request_refused", actor ?? "app-control-service",
                $"device={Esc(authenticatedDeviceId)} request={Esc(requestId)} reason={gateReason}", now);
            return (null, false, gateReason);
        }
        var (request, created, reason) = Requests.File(
            authenticatedDeviceId, claimedDeviceId, requestId, requester, identity, businessReason, now);
        if (request is null)
        {
            _audit.Append("app_request_refused", actor ?? "app-control-service",
                $"device={Esc(authenticatedDeviceId)} request={Esc(requestId)} reason={reason}", now);
            return (null, false, reason);
        }
        if (created)
        {
            var text = $"Application access request: {request.Identity.NormalizedProduct}" +
                (request.Identity.Version is not null ? $" v{request.Identity.Version}" : "") +
                $" (publisher {request.Identity.PublisherName ?? "unknown"}, signer {request.Identity.NormalizedSigner}, hash {request.Identity.NormalizedHash}, path {request.Identity.NormalizedPath}) — {request.BusinessReason}";
            // FL-25b/DF3: the work item is keyed by the
            // DEVICE-SCOPED request key, not the bare request id —
            // WorkItem.IdForRequest is a global keyspace, so two
            // devices filing the same id shared one work item and
            // closing one device's request closed the other's.
            var (item, _, wiReason) = _workItems.IntakeRequest(authenticatedDeviceId, facts.ScopeId,
                new UserWorkRequest(WorkRequestKey(request), authenticatedDeviceId, request.Requester, text, null), now);
            if (item is null)
            {
                // FL-25c/F10: the work item is the request's queue
                // presence — if intake yields no item, the request
                // must NOT stand (previously it stayed filed with
                // an empty workItem= in the ledger and no queue
                // presence). Roll the filing back, ledgered.
                Requests.Remove(authenticatedDeviceId, request.Id);
                var rollback = $"work-item intake created no item for request '{request.Id}' ({wiReason}) — the filing is rolled back; no request stands";
                _audit.Append("app_request_refused", actor ?? "app-control-service",
                    $"device={Esc(authenticatedDeviceId)} request={Esc(request.Id)} reason={rollback}", now);
                return (null, false, rollback);
            }
            _audit.Append("app_request_filed", actor ?? "app-control-service",
                $"device={Esc(authenticatedDeviceId)} request={Esc(request.Id)} requester={Esc(request.Requester)} product={Esc(request.Identity.NormalizedProduct)} workItem={item.Id} workItemReason={wiReason}", now);
        }
        return (request, created, reason);
    }

    /// <summary>Approve a request. The package offer (RMM-16) is
    /// validated BEFORE the decision lands: the package must exist,
    /// be enabled, and its installed-software name must be the
    /// requested application — an approval cannot smuggle a
    /// different application's packaged install.</summary>
    public (AppAccessRequest? Request, AppRule? Rule, string Reason) ApproveRequest(
        string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, string actor) =>
        ApproveRequestCore(null, requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, actor);

    /// <summary>Device-scoped approval (FL-25b/DF3): decides ONE
    /// device's request when the bare id stands on several devices
    /// — the bare overload's ambiguity refusal must not freeze a
    /// victim's request when a rogue device files a colliding id.</summary>
    public (AppAccessRequest? Request, AppRule? Rule, string Reason) ApproveRequest(
        string deviceId, string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, string actor) =>
        ApproveRequestCore(deviceId, requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, actor);

    private (AppAccessRequest? Request, AppRule? Rule, string Reason) ApproveRequestCore(
        string? deviceId, string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, string actor)
    {
        RefreshApproverPrincipals();
        var now = _now();
        var standing = deviceId is not null ? Requests.Get(deviceId, requestId) : Requests.Get(requestId);
        if (standing is null)
        {
            // FL-25c/F10: an unknown-request approval attempt is a
            // refusal and is ledgered like every other refusal.
            // FL-25b/F4: an id held by several devices is AMBIGUOUS,
            // named as such — never silently resolved to one device.
            var unknown = deviceId is null && Requests.CountById(requestId) > 1
                ? $"request id '{requestId}' exists on multiple devices — approval refused (request ids are scoped per device; an ambiguous id decides nothing — use the device-scoped approval)"
                : deviceId is not null
                    ? $"unknown request '{requestId}' on device '{deviceId}' — approval refused"
                    : $"unknown request '{requestId}' — approval refused";
            _audit.Append("app_request_approval_refused", actor ?? "app-control-service",
                $"request={Esc(requestId)} approver={Esc(approver)} reason={unknown}", now);
            return (null, null, unknown);
        }
        // Recovery fix R25R-F5: approval MINTS policy power, so it
        // is gated on the feature toggle for the request's device,
        // exactly like filing and evaluation. Before this fix an
        // approval landed while the feature was disabled and its
        // rule silently went live when the toggle came back on —
        // D25-15's kill-switch claim did not cover decisions.
        // (Denial is deliberately NOT gated: it mints nothing and
        // must stay available to clean a queue while disabled.)
        var (gateFacts, gateReason) = Gate(standing.DeviceId, "request approval", aliasAware: true);
        if (gateFacts is null)
        {
            _audit.Append("app_request_approval_refused", actor ?? "app-control-service",
                $"request={Esc(requestId)} approver={Esc(approver)} reason={gateReason}", now);
            return (null, null, gateReason);
        }
        if (offeredPackageId is not null)
        {
            // FL-25c/F10: every package-offer refusal is ledgered —
            // these returns previously left no audit trace.
            string? offerRefusal = null;
            if (_packageById is null)
                offerRefusal = "a packaged install was offered but no package repository is wired — approval refused (the offer cannot be verified)";
            else
            {
                var package = _packageById(offeredPackageId);
                if (package is null)
                    offerRefusal = $"offered package '{offeredPackageId}' does not exist in the repository — approval refused";
                else if (!package.Enabled)
                    offerRefusal = $"offered package '{offeredPackageId}' is not enabled — approval refused";
                else if (string.IsNullOrWhiteSpace(package.InstalledSoftwareName) ||
                    !string.Equals(package.InstalledSoftwareName.Trim(), standing.Identity.NormalizedProduct, StringComparison.OrdinalIgnoreCase))
                    offerRefusal = $"offered package '{offeredPackageId}' installs '{package.InstalledSoftwareName}', not the requested application '{standing.Identity.NormalizedProduct}' — approval refused (an approval cannot offer a different application)";
            }
            if (offerRefusal is not null)
            {
                _audit.Append("app_request_approval_refused", actor ?? "app-control-service",
                    $"request={Esc(requestId)} approver={Esc(approver)} reason={offerRefusal}", now);
                return (null, null, offerRefusal);
            }
        }
        var (request, rule, reason) = deviceId is not null
            ? Requests.Approve(deviceId, requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, now)
            : Requests.Approve(requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, now);
        if (request is null || rule is null)
        {
            _audit.Append("app_request_approval_refused", actor ?? "app-control-service",
                $"request={Esc(requestId)} approver={Esc(approver)} reason={reason}", now);
            return (null, null, reason);
        }
        CloseWorkItem(request, WorkItemOutcomes.Resolved,
            $"approved by {request.DecidedBy}; rule {rule.Id}; package offer {offeredPackageId ?? "none"}", now);
        _audit.Append("app_request_approved", actor ?? "app-control-service",
            $"device={Esc(request.DeviceId)} request={Esc(requestId)} approver={Esc(request.DecidedBy)} rule={rule.Describe()} packageOffer={Esc(offeredPackageId ?? "none")}", now);
        return (request, rule, reason);
    }

    /// <summary>Deny a request: recorded with reason on the request,
    /// in the ledger, and on the linked work item.</summary>
    public (AppAccessRequest? Request, string Reason) DenyRequest(
        string requestId, string? denier, string? reason, string actor) =>
        DenyRequestCore(null, requestId, denier, reason, actor);

    /// <summary>Device-scoped denial (FL-25b/DF3): decides ONE
    /// device's request when the bare id is ambiguous across
    /// devices.</summary>
    public (AppAccessRequest? Request, string Reason) DenyRequest(
        string deviceId, string requestId, string? denier, string? reason, string actor) =>
        DenyRequestCore(deviceId, requestId, denier, reason, actor);

    private (AppAccessRequest? Request, string Reason) DenyRequestCore(
        string? deviceId, string requestId, string? denier, string? reason, string actor)
    {
        RefreshApproverPrincipals();
        var now = _now();
        var (request, outcome) = deviceId is not null
            ? Requests.Deny(deviceId, requestId, denier, reason, now)
            : Requests.Deny(requestId, denier, reason, now);
        if (request is null)
        {
            // FL-25b/DF1: denier and the refusal outcome (which can
            // embed caller-supplied text) are percent-encoded in
            // the ledger, exactly like the identity fields — the
            // FL-25 F5 fix left the denial path raw.
            _audit.Append("app_request_denial_refused", actor ?? "app-control-service",
                $"request={Esc(requestId)} denier={Esc(denier)} reason={outcome}", now);
            return (null, outcome);
        }
        CloseWorkItem(request, WorkItemOutcomes.Resolved, $"denied by {request.DecidedBy}: {request.DecisionReason}", now);
        _audit.Append("app_request_denied", actor ?? "app-control-service",
            $"device={Esc(request.DeviceId)} request={Esc(requestId)} denier={Esc(request.DecidedBy)} reason={Esc(request.DecisionReason)}", now);
        return (request, outcome);
    }

    /// <summary>The device-scoped key under which a request's
    /// RMM-12 work item stands (FL-25b/DF3): bare request ids are
    /// per-device, so every derived keyspace — work items here,
    /// approval rule ids in the store — carries the device too.</summary>
    private static string WorkRequestKey(AppAccessRequest request) =>
        request.Id + "@" + AppRequestIds.Segment(request.DeviceId);

    private void CloseWorkItem(AppAccessRequest request, string outcome, string note, DateTimeOffset now)
    {
        var itemId = WorkItem.IdForRequest(WorkRequestKey(request));
        var item = _workItems.Get(itemId);
        if (item is not null && !item.IsClosed)
            _workItems.Close(itemId, outcome, request.DecidedBy ?? "app-control-service", note, now);
    }
}

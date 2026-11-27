using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Vulnerability;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-12 — WorkItemService: the hub-side wiring for the work-item
// layer (alert→work→session→audit trail; ticket-lite, not a PSA).
//
// Owns the WorkItemStore (which implements RMM-01's IWorkItemSink)
// and the outbound PSA bridge. Consumes, through public surfaces
// only:
//   * RMM-01: the IWorkItemSink contract — EndpointMonitorService
//     calls OpenWorkItem on a new alert whose condition actions say
//     so (policy-gated there by rmm.work_items.enabled) and
//     CloseWorkItem when the alert auto-resets. This service IS
//     that sink (it delegates to the store).
//   * RMM-05: ExposureWorkItem adoption by composition —
//     AdoptExposure projects an exposure onto the trail; the
//     exposure record and ExposureStore are never edited here.
//   * Sessions: attachment validation reads the EXISTING session
//     record through a lookup delegate (CoreRuntime passes
//     HumanSessions.GetSession). A session attaches only to a work
//     item FOR THE SESSION'S OWN DEVICE — the poisoning line.
//   * RMM-07: ManagementPolicyService — rmm.work_items.enabled
//     gates every tech action (TOTAL POLICY CONTROL); the bridge
//     and request-channel keys are policy content read through
//     Effective Policy (bridge defaults OFF, request channel ON).
//   * the enterprise ChainedAuditLog: the store chains every item
//     mutation; this service chains attachment refusals, bridge
//     configuration, and every bridge delivery transition.
//
// Billing / contracts / invoicing: OUT, by directive. No such
// surface exists here and none is reachable through the bridge
// (the bridge forwards item events; it takes nothing back).
// =====================================================================
public sealed class WorkItemService : IWorkItemSink
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly Func<string, Session?> _sessionLookup;
    private readonly IWebhookTransport? _transport;
    private readonly Func<DateTimeOffset> _now;

    public WorkItemStore Store { get; }
    public WorkItemBridge Bridge { get; }

    public WorkItemService(ChainedAuditLog audit, ManagementPolicyService policies,
        Func<string, Session?> sessionLookup, IWebhookTransport? transport = null,
        Func<DateTimeOffset>? now = null,
        Func<string, string?>? scopeLookup = null,
        Func<string, System.Net.IPAddress[]>? bridgeResolver = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _sessionLookup = sessionLookup ?? throw new ArgumentNullException(nameof(sessionLookup));
        _transport = transport;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        // W3 host wiring (Wave-2 Lane B remainders):
        //  (2) scopeLookup threads into the store, so alert-open
        //      resolves the device's enterprise scope (and refuses
        //      by name when it resolves to none) instead of the
        //      legacy unscoped shape -- BD-SHARED-RMM-3/F5.
        //  (3) bridgeResolver threads into the PSA bridge, so a
        //      send re-validates the webhook host's DNS answers at
        //      send time (rebinding defense) instead of trusting
        //      admission-time resolution -- BD-SHARED-RMM-3/F3/F8.
        Store = new WorkItemStore(audit, scopeLookup);
        Bridge = new WorkItemBridge(bridgeResolver);
    }

    public bool IsEnabled(IDeviceFacts facts) =>
        _policies.IsEnabled(facts, WorkItemPolicyKeys.Enabled);

    /// <summary>Policy-content boolean: effective value wins, else
    /// the named default. Unparsable values fall back to the default
    /// (never to "on" for the outbound bridge).</summary>
    private bool PolicyContentBool(IDeviceFacts facts, string key, bool defaultValue)
    {
        var s = _policies.ComputeEffective(facts).Get(key);
        return s is not null && bool.TryParse(s.Value, out var v) ? v : defaultValue;
    }

    public bool BridgeEnabledFor(IDeviceFacts facts) =>
        PolicyContentBool(facts, WorkItemPolicyKeys.BridgeEnabled, false);

    public bool RequestChannelEnabledFor(IDeviceFacts facts) =>
        PolicyContentBool(facts, WorkItemPolicyKeys.RequestChannelEnabled, true);

    private (bool, string) Gate(IDeviceFacts facts)
    {
        if (IsEnabled(facts)) return (true, "");
        return (false, "work items are disabled by policy for this scope (rmm.work_items.enabled) — refused (fail closed)");
    }

    /// <summary>D38-F4: the policy gate alone is not authorisation
    /// — the caller's facts must be FOR THE ITEM'S OWN DEVICE.
    /// Previously only Assign compared them, so facts for a
    /// policy-ON device could attach/close work belonging to a
    /// policy-OFF device. Every item-bound action checks here.</summary>
    private string? ItemDeviceMismatch(IDeviceFacts facts, WorkItem item)
    {
        if (string.Equals(item.DeviceId, facts.DeviceId, StringComparison.OrdinalIgnoreCase)) return null;
        return $"work item '{item.Id}' belongs to device '{item.DeviceId}', not '{facts.DeviceId}' — refused";
    }

    // ---- RMM-01 sink (delegates to the store) ---------------------------

    // D38-F6: sink events previously reached NEITHER the bridge
    // NOR the audit chain as a skip — they were bridged only if
    // some other code happened to forward them. The sink contract
    // carries no device facts, so per-device bridge policy cannot
    // be evaluated here; that fact is now CHAINED as a named bridge
    // skip for every item the sink actually opens/closes, and the
    // hub wiring can still forward explicitly via BridgeOpened /
    // BridgeAutoClosed with real facts.
    public void OpenWorkItem(HealthAlertEvent alert, DateTimeOffset now)
    {
        var (item, created, _) = Store.OpenFromAlert(alert, now);
        if (created && item is not null)
            _audit.Append("work_bridge_skipped", "work-items",
                $"item={item.Id} event={BridgeEventKinds.Opened} reason=alert sink carries no device facts — per-device bridge policy cannot be evaluated on the sink path; hub wiring forwards via BridgeOpened with facts", now);
    }

    public void CloseWorkItem(HealthAlertEvent alert, string reason, DateTimeOffset now)
    {
        var (closed, _) = Store.AutoCloseFromAlert(alert, reason, now);
        if (closed)
        {
            var item = Store.Get(WorkItem.IdForAlert(alert.AlertId));
            if (item is not null)
                _audit.Append("work_bridge_skipped", "work-items",
                    $"item={item.Id} event={BridgeEventKinds.AutoClosed} reason=alert sink carries no device facts — per-device bridge policy cannot be evaluated on the sink path; hub wiring forwards via BridgeAutoClosed with facts", now);
        }
    }

    // ---- tech actions -----------------------------------------------------

    public (WorkItem? Item, string Reason) OpenManual(IDeviceFacts facts, string title, string openedBy)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (null, refusal);
        var (item, reason) = Store.OpenManual(facts.DeviceId, facts.ScopeId, title, openedBy, _now());
        if (item is not null) BridgeEvent(facts, BridgeEventKinds.Opened, item);
        return (item, reason);
    }

    public (bool Ok, string Reason) Assign(IDeviceFacts facts, string itemId, string owner, string actor)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (false, refusal);
        var item = Store.Get(itemId);
        if (item is not null && ItemDeviceMismatch(facts, item) is { } mismatch) return (false, mismatch);
        return Store.Assign(itemId, owner, actor, _now());
    }

    /// <summary>Attach a session BY ID. The session record is read
    /// from the session layer and must belong to the SAME device as
    /// the work item — a session from another device attached here
    /// would poison this item's trail with another machine's work,
    /// so the mismatch refuses AND is chained as its own event.</summary>
    public (bool Ok, string Reason) AttachSession(IDeviceFacts facts, string itemId, string sessionId, string actor)
    {
        var now = _now();
        var (ok, refusal) = Gate(facts);
        if (!ok) return (false, refusal);
        var item = Store.Get(itemId);
        if (item is null) return (false, $"unknown work item '{itemId}' — refused");
        if (ItemDeviceMismatch(facts, item) is { } mismatch) return (false, mismatch);
        var session = _sessionLookup(sessionId);
        if (session is null)
        {
            _audit.Append("work_item_attach_refused", actor,
                $"item={itemId} attachment=session:{sessionId} reason=no such session in the session record", now);
            return (false, $"session '{sessionId}' does not exist in the session record — refused (attachments link to real records)");
        }
        if (!string.Equals(session.HostDeviceId, item.DeviceId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("work_item_attach_refused", actor,
                $"item={itemId} attachment=session:{sessionId} reason=session belongs to device '{session.HostDeviceId}' but the work item is for '{item.DeviceId}' — cross-device attachment refused", now);
            return (false, $"session '{sessionId}' belongs to device '{session.HostDeviceId}' but work item '{itemId}' is for '{item.DeviceId}' — a session attaches only to its own device's work");
        }
        return Store.Attach(itemId, new WorkItemAttachment(AttachmentKinds.Session, sessionId, null, actor, now), now);
    }

    public (bool Ok, string Reason) AttachScript(IDeviceFacts facts, string itemId, string scriptId, string actor)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (false, refusal);
        var item = Store.Get(itemId);
        if (item is not null && ItemDeviceMismatch(facts, item) is { } mismatch) return (false, mismatch);
        return Store.Attach(itemId, new WorkItemAttachment(AttachmentKinds.Script, scriptId, null, actor, _now()), _now());
    }

    public (bool Ok, string Reason) AddNote(IDeviceFacts facts, string itemId, string noteId, string text, string actor)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (false, refusal);
        var item = Store.Get(itemId);
        if (item is not null && ItemDeviceMismatch(facts, item) is { } mismatch) return (false, mismatch);
        return Store.Attach(itemId, new WorkItemAttachment(AttachmentKinds.Note, noteId, text, actor, _now()), _now());
    }

    public (bool Ok, string Reason) Close(IDeviceFacts facts, string itemId, string outcome, string? note, string closedBy)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (false, refusal);
        var existing = Store.Get(itemId);
        if (existing is not null && ItemDeviceMismatch(facts, existing) is { } mismatch) return (false, mismatch);
        var (closed, reason) = Store.Close(itemId, outcome, closedBy, note, _now());
        if (closed)
        {
            var item = Store.Get(itemId)!;
            BridgeEvent(facts, BridgeEventKinds.Closed, item);
        }
        return (closed, reason);
    }

    // ---- request channel ----------------------------------------------------

    /// <summary>Intake one end-user request. The authenticated
    /// device id comes from the channel (the caller passes the
    /// identity its transport authenticated); the request body's
    /// claimed device is checked against it by the store. The
    /// request channel itself is policy content (default ON).</summary>
    public (WorkItem? Item, bool Created, string Reason) IntakeRequest(
        IDeviceFacts facts, string authenticatedDeviceId, UserWorkRequest request)
    {
        var (ok, refusal) = Gate(facts);
        if (!ok) return (null, false, refusal);
        // D38-F4: the gate and the stamped ScopeId come from
        // `facts` — they must be facts FOR the channel's device.
        // Previously facts for any device could authorise (and
        // scope-stamp) an item created for another device.
        if (!string.Equals(facts.DeviceId, authenticatedDeviceId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("work_request_spoof_refused", "work-items",
                $"request={request?.RequestId} channelDevice={authenticatedDeviceId} factsDevice={facts.DeviceId} — the policy facts presented are not for the channel's device; refused, no item created", _now());
            return (null, false, $"the policy facts are for device '{facts.DeviceId}' but the request arrived on the authenticated channel of '{authenticatedDeviceId}' — refused; no work item created");
        }
        if (!RequestChannelEnabledFor(facts))
            return (null, false, "the end-user request channel is disabled by policy for this scope (rmm.work_items.request_channel.enabled) — refused");
        var (item, created, reason) = Store.IntakeRequest(authenticatedDeviceId, facts.ScopeId, request, _now());
        if (item is not null && created) BridgeEvent(facts, BridgeEventKinds.Opened, item);
        return (item, created, reason);
    }

    // ---- RMM-05 adoption ------------------------------------------------------

    /// <summary>Project an RMM-05 exposure onto the work-item trail.
    /// The exposure is consumed read-only; ExposureStore remains
    /// its authority.</summary>
    public (WorkItem? Item, bool Created, string Reason) AdoptExposure(IDeviceFacts facts, ExposureWorkItem exposure)
    {
        // D38-F4: adoption was the one service action with NO
        // policy gate at all. It is gated like every other action
        // (TOTAL POLICY CONTROL), and the facts must be for the
        // exposure's own device. A refused adoption creates and
        // changes nothing; the refusal is chained.
        var (ok, refusal) = Gate(facts);
        if (!ok)
        {
            _audit.Append("work_item_adopt_refused", "work-items",
                $"exposure={exposure.Id} device={exposure.DeviceId} reason={refusal}", _now());
            return (null, false, refusal);
        }
        if (!string.Equals(facts.DeviceId, exposure.DeviceId, StringComparison.OrdinalIgnoreCase))
        {
            var mismatch = $"exposure '{exposure.Id}' belongs to device '{exposure.DeviceId}', not '{facts.DeviceId}' — adoption refused";
            _audit.Append("work_item_adopt_refused", "work-items",
                $"exposure={exposure.Id} device={exposure.DeviceId} reason={mismatch}", _now());
            return (null, false, mismatch);
        }
        var wasClosed = Store.Get(WorkItem.IdForExposure(exposure.Id))?.IsClosed ?? false;
        var (item, created) = Store.AdoptExposure(exposure, _now());
        if (created) BridgeEvent(facts, BridgeEventKinds.Opened, item);
        // D38-F6: a re-adoption that CLOSES the projection is an
        // item event like any other — it reaches the bridge (or
        // the chained skip), never neither.
        if (item.IsClosed && !wasClosed) BridgeEvent(facts, BridgeEventKinds.Closed, item);
        return (item, created, created
            ? $"exposure '{exposure.Id}' adopted as work item '{item.Id}'"
            : $"exposure '{exposure.Id}' re-synced as work item '{item.Id}'");
    }

    // ---- bridge ---------------------------------------------------------------

    public (bool Ok, string Reason) ConfigureBridge(IDeviceFacts facts, string targetUrl, string signingSecret, string configuredBy)
    {
        var now = _now();
        // D38-F4: ConfigureBridge took `facts` and never used it —
        // the bridge is part of the work-items feature and is
        // gated by the same policy toggle as every other action.
        var (gateOk, refusal) = Gate(facts);
        if (!gateOk)
        {
            _audit.Append("work_bridge_refused", configuredBy,
                $"target={targetUrl} reason={refusal}", now);
            return (false, refusal);
        }
        var (ok, reason) = Bridge.Configure(targetUrl, signingSecret, configuredBy, now);
        // The audit names the target and the outcome — never the secret.
        _audit.Append(ok ? "work_bridge_configured" : "work_bridge_refused", configuredBy,
            $"target={targetUrl} reason={reason}", now);
        return (ok, reason);
    }

    /// <summary>Forward one item event to the bridge when policy
    /// enables it for this device. Every outcome is chained: a
    /// disabled bridge, an unconfigured bridge, and an enqueued
    /// delivery are each named facts — an event is never just
    /// dropped.</summary>
    private void BridgeEvent(IDeviceFacts facts, string eventKind, WorkItem item)
    {
        var now = _now();
        if (!BridgeEnabledFor(facts))
        {
            _audit.Append("work_bridge_skipped", "work-items",
                $"item={item.Id} event={eventKind} reason=bridge disabled by policy ({WorkItemPolicyKeys.BridgeEnabled})", now);
            return;
        }
        var (delivery, reason) = Bridge.Enqueue(eventKind, item, now);
        _audit.Append(delivery is not null ? "work_bridge_enqueued" : "work_bridge_skipped", "work-items",
            $"item={item.Id} event={eventKind} delivery={delivery?.DeliveryId} reason={reason}", now);
    }

    /// <summary>Bridge an auto-close for an item the sink closed.
    /// Called by the hub wiring that observes sink closes (the sink
    /// contract itself carries no facts, so bridging an auto-close
    /// is an explicit step, audited like every other bridge act).</summary>
    public void BridgeAutoClosed(IDeviceFacts facts, WorkItem item) =>
        BridgeEvent(facts, BridgeEventKinds.AutoClosed, item);

    /// <summary>Bridge an alert-opened item the sink created.
    /// Symmetric with BridgeAutoClosed (D38-F6): the sink path
    /// chains a named skip because it has no facts; hub wiring
    /// that observes the open calls this with real facts to
    /// forward the event under the device's bridge policy.</summary>
    public void BridgeOpened(IDeviceFacts facts, WorkItem item) =>
        BridgeEvent(facts, BridgeEventKinds.Opened, item);

    /// <summary>One delivery pump pass over the bridge. Delivery
    /// state changes are chained per delivery: delivered, failed
    /// (with the error), and dead are all on the record.</summary>
    private bool _pumpSkipChained;

    public IReadOnlyList<BridgeDelivery> PumpBridge()
    {
        var now = _now();
        if (_transport is null)
        {
            // D38-F10: the no-transport skip is chained ONCE per
            // service instance, not once per pump — a timer-driven
            // pump would otherwise grow the chain forever with the
            // same entry. The state stays named; it stops repeating.
            if (!_pumpSkipChained)
            {
                _pumpSkipChained = true;
                _audit.Append("work_bridge_pump_skipped", "work-items",
                    "reason=no webhook transport wired — deliveries remain in their current visible state (this skip is chained once per service instance, not per pump)", now);
            }
            return Array.Empty<BridgeDelivery>();
        }
        var changed = Bridge.Pump(_transport, now);
        foreach (var d in changed)
            _audit.Append(
                d.State == BridgeDeliveryStates.Delivered ? "work_bridge_delivered" : "work_bridge_delivery_failed",
                "work-items",
                $"item={d.ItemId} delivery={d.DeliveryId} event={d.EventKind} state={d.State} attempts={d.Attempts} error={d.LastError}", now);
        return changed;
    }
}

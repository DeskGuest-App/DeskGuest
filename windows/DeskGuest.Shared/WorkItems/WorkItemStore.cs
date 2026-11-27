using System.Text.Json;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Vulnerability;

namespace DeskGuest.Shared.WorkItems;

// =====================================================================
// RMM-12 — the work-item store + the RMM-01 sink implementation.
//
// Invariants the store enforces structurally (the destruction pass
// attacks each by name):
//   * ALERT OPENS ARE IDEMPOTENT per alert id: the item id derives
//     from the alert id, so a re-delivered open returns the standing
//     item — alert→item duplication floods mint nothing twice, and
//     the per-device open caps bound what a flapping condition can
//     create at all.
//   * AUTO-CLOSE IS BOUND TO THE OPENING ALERT: the only auto-close
//     path looks the item up BY THE ALERT ID that opened it and
//     checks SourceAlertId. A fabricated alert, a different alert
//     episode for the same condition, or a human calling the manual
//     path with the reserved outcome closes nothing.
//   * CLOSURE NEEDS AN OUTCOME: the manual path accepts only the
//     named human outcomes + an attributed closer; the reserved
//     auto-close outcome is refused there. There is no close call
//     without an outcome parameter — it is not optional.
//   * CLOSED IS TERMINAL: a closed item takes no assignment, no
//     attachment, no second closure.
//   * EVERY MUTATION IS A CHAINED AUDIT EVENT and the item records
//     the entry's sequence number. History is reconstructable from
//     the chain (WorkItemHistory) and the store can verify its own
//     state against the chain — state that disagrees is named.
// =====================================================================

public sealed class WorkItemStore : IWorkItemSink
{
    /// <summary>The actor name the alert lifecycle closes under.
    /// Reserved: the manual close path refuses it as a closer, so
    /// no human action can be recorded as a lifecycle auto-close.</summary>
    public const string LifecycleActor = "alert-lifecycle";

    private readonly ChainedAuditLog _audit;
    private readonly Dictionary<string, WorkItem> _items = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _floodRefusals = new(StringComparer.OrdinalIgnoreCase);
    // D38-F10: open counts are maintained incrementally at the
    // create/close transitions instead of counting across every
    // item (incl. all closed history) under the lock on each open.
    private readonly Dictionary<string, int> _openByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _openAlertsByDevice = new(StringComparer.OrdinalIgnoreCase);
    // D38-F9: a flood EPISODE is chained once; the chain entry is
    // re-armed when the device next opens successfully (the cap
    // cleared), so a second flood after a drain is chained too —
    // the counter alone was "first flood ever only".
    private readonly HashSet<string> _floodAuditSuppressed = new(StringComparer.OrdinalIgnoreCase);
    // D38-F10: spoof refusals are counted per channel device and
    // chained on the first occurrence only — a spoof loop cannot
    // grow the chain one entry per attempt, and the count stays
    // visible here (counted, not silent).
    private readonly Dictionary<string, int> _spoofRefusals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private void CountOpen(WorkItem item)
    {
        if (item.IsClosed) return;
        _openByDevice[item.DeviceId] = _openByDevice.GetValueOrDefault(item.DeviceId) + 1;
        if (item.Kind == WorkItemKinds.Alert)
            _openAlertsByDevice[item.DeviceId] = _openAlertsByDevice.GetValueOrDefault(item.DeviceId) + 1;
    }

    private void CountClosed(WorkItem item)
    {
        _openByDevice[item.DeviceId] = Math.Max(0, _openByDevice.GetValueOrDefault(item.DeviceId) - 1);
        if (item.Kind == WorkItemKinds.Alert)
            _openAlertsByDevice[item.DeviceId] = Math.Max(0, _openAlertsByDevice.GetValueOrDefault(item.DeviceId) - 1);
    }

    /// <summary>Register one cap refusal (D38-F9): EVERY refused
    /// path counts — alert, manual and request alike — and the
    /// first refusal of each flood episode is chained. Returns the
    /// device's running refusal count.</summary>
    private int RegisterFloodRefusal(string deviceId, string path, string detail, DateTimeOffset now)
    {
        var count = _floodRefusals[deviceId] = _floodRefusals.GetValueOrDefault(deviceId) + 1;
        if (_floodAuditSuppressed.Add(deviceId))
            _audit.Append("work_item_flood_capped", "work-items",
                $"device={deviceId} path={path} {detail} — open-item cap reached; further opens for this device are counted, not created", now);
        return count;
    }

    private readonly Func<string, string?>? _scopeLookup;

    /// <param name="scopeLookup">BD-SHARED-RMM-3/F5: resolves a
    /// device's enterprise scope at alert-open time. When wired, an
    /// alert whose device resolves to NO scope is refused by name —
    /// alert items previously carried ScopeId "" unconditionally, so
    /// they fell out of every scoped view (or leaked into a global
    /// one) and the PSA bridge sent scopeId "" for them. When not
    /// wired, the legacy unscoped shape stands (named here, not
    /// hidden).</param>
    public WorkItemStore(ChainedAuditLog audit, Func<string, string?>? scopeLookup = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _scopeLookup = scopeLookup;
    }

    /// <summary>BD-SHARED-RMM-3/F7: device ids are audit-detail
    /// TOKENS — whitespace or '=' in one lets it mint spoofed fields
    /// (the D38-F3 class) for anyone parsing the chain.</summary>
    internal static bool IsValidDeviceId(string? deviceId) =>
        !string.IsNullOrWhiteSpace(deviceId) && deviceId.Trim() == deviceId &&
        !deviceId.Any(c => char.IsWhiteSpace(c) || c == '=');

    /// <summary>Lane A: raised after every committed mutation so
    /// CoreRuntime can write the store through to disk.</summary>
    public event Action? Changed;

    public IReadOnlyList<WorkItem> Items
    {
        get { lock (_gate) return _items.Values.OrderBy(i => i.CreatedUtc).ThenBy(i => i.Id, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<WorkItem> OpenItems
    {
        get { lock (_gate) return _items.Values.Where(i => !i.IsClosed).OrderBy(i => i.CreatedUtc).ToList(); }
    }

    public WorkItem? Get(string? id)
    {
        lock (_gate) return id is not null && _items.TryGetValue(id, out var item) ? item : null;
    }

    /// <summary>Alert-open refusals swallowed by the flood caps, per
    /// device — visible, never silent.</summary>
    public IReadOnlyDictionary<string, int> FloodRefusals
    {
        get { lock (_gate) return new Dictionary<string, int>(_floodRefusals); }
    }

    /// <summary>Spoofed-request refusals per channel device —
    /// counted even where the chain entry is deduped (D38-F10).</summary>
    public IReadOnlyDictionary<string, int> SpoofRefusals
    {
        get { lock (_gate) return new Dictionary<string, int>(_spoofRefusals); }
    }

    private WorkItem Commit(WorkItem item, string kind, string actor, string detail, DateTimeOffset now)
    {
        var entry = _audit.Append(kind, actor, $"item={item.Id} {detail}", now);
        var withSeq = item with { AuditSeqs = item.AuditSeqs.Append(entry.Seq).ToList() };
        _items[item.Id] = withSeq;
        Changed?.Invoke();
        return withSeq;
    }

    private static string? ValidateActor(string? actor, string role)
    {
        if (string.IsNullOrWhiteSpace(actor)) return $"a work item needs a {role} — refused (unattributed work is not recorded)";
        if (actor.Trim().Length > WorkItemLimits.MaxActorLength) return $"the {role} name exceeds {WorkItemLimits.MaxActorLength} characters — refused";
        return null;
    }

    // ---- (a) alert-driven lifecycle (the IWorkItemSink contract) ----

    /// <summary>RMM-01 sink: a condition's alert raised → open the
    /// item for that alert. Idempotent per alert id.</summary>
    public void OpenWorkItem(HealthAlertEvent alert, DateTimeOffset now) =>
        OpenFromAlert(alert, now);

    /// <summary>RMM-01 sink: the alert auto-reset because its
    /// condition cleared → auto-close the item THAT ALERT opened.</summary>
    public void CloseWorkItem(HealthAlertEvent alert, string reason, DateTimeOffset now) =>
        AutoCloseFromAlert(alert, reason, now);

    public (WorkItem? Item, bool Created, string Reason) OpenFromAlert(HealthAlertEvent? alert, DateTimeOffset now)
    {
        if (alert is null) return (null, false, "no alert presented — refused");
        // D38-F9: a null/blank device id must refuse cleanly — it
        // previously reached the flood dictionary as a null key and
        // threw out of the sink.
        if (string.IsNullOrWhiteSpace(alert.DeviceId))
            return (null, false, "the alert carries no device id — refused");
        if (!IsValidDeviceId(alert.DeviceId))
            return (null, false, $"the alert's device id '{alert.DeviceId}' contains whitespace or '=' — refused (device ids are audit tokens)");
        string? resolvedScope = null;
        if (_scopeLookup is not null)
        {
            resolvedScope = _scopeLookup(alert.DeviceId);
            if (string.IsNullOrWhiteSpace(resolvedScope))
                return (null, false, $"device '{alert.DeviceId}' resolves to no enterprise scope — alert work item refused by name rather than opened unscoped (BD-SHARED-RMM-3/F5)");
        }
        lock (_gate)
        {
            var id = WorkItem.IdForAlert(alert.AlertId);
            if (_items.TryGetValue(id, out var existing))
                return (existing, false, $"work item '{id}' already stands for alert '{alert.AlertId}' (idempotent open)");
            var openForDevice = _openByDevice.GetValueOrDefault(alert.DeviceId);
            var openAlertForDevice = _openAlertsByDevice.GetValueOrDefault(alert.DeviceId);
            if (openAlertForDevice >= WorkItemLimits.MaxOpenAlertItemsPerDevice ||
                openForDevice >= WorkItemLimits.MaxOpenItemsPerDevice)
            {
                RegisterFloodRefusal(alert.DeviceId, "alert",
                    $"alert={alert.AlertId} condition={alert.ConditionId}", now);
                return (null, false, $"open-item cap reached for device '{alert.DeviceId}' — alert work item refused (counted, not silent)");
            }
            var item = new WorkItem(
                Id: id,
                Title: $"[{alert.Severity}] {alert.Kind} on {alert.DeviceId} ({alert.ConditionId})",
                DeviceId: alert.DeviceId,
                ScopeId: resolvedScope ?? "",
                State: WorkItemStates.Open,
                Owner: null,
                CreatedUtc: now, UpdatedUtc: now, ClosedUtc: null,
                Kind: WorkItemKinds.Alert,
                SourceAlertId: alert.AlertId,
                SourceConditionId: alert.ConditionId,
                ExposureId: null, RequestId: null, RequesterName: null, HealthSummary: null,
                Attachments: Array.Empty<WorkItemAttachment>(), Closure: null,
                AuditSeqs: Array.Empty<long>());
            // BD-SHARED-RMM-3/F7: alert detail is free text — it is
            // REDACTED, BOUNDED and AuditText-escaped before it enters
            // the chain (RemediationRunner.CaptureOutput's pattern).
            var safeDetail = AuditText.Escape(Redactor.RedactText(alert.Detail ?? ""));
            if (safeDetail.Length > WorkItemLimits.MaxNoteLength) safeDetail = safeDetail[..WorkItemLimits.MaxNoteLength];
            var committed = Commit(item, "work_item_opened", "work-items",
                $"device={alert.DeviceId} kind=alert alert={alert.AlertId} condition={alert.ConditionId} severity={alert.Severity} detail={safeDetail}", now);
            CountOpen(committed);
            _floodAuditSuppressed.Remove(alert.DeviceId); // cap cleared — re-arm the flood chain entry
            return (committed, true, $"work item '{id}' opened for alert '{alert.AlertId}'");
        }
    }

    /// <summary>The auto-close. Bound three ways: the item is found
    /// BY the alert id, its SourceAlertId must equal that id, and it
    /// must be an alert-kind item still open. Anything else — a
    /// forged alert, a later episode's alert, an already-human-closed
    /// item — closes nothing (a human closure is never overwritten
    /// by the lifecycle).</summary>
    public (bool Closed, string Reason) AutoCloseFromAlert(HealthAlertEvent? alert, string reason, DateTimeOffset now)
    {
        if (alert is null) return (false, "no alert presented — auto-close refused");
        lock (_gate)
        {
            var id = WorkItem.IdForAlert(alert.AlertId);
            if (!_items.TryGetValue(id, out var item))
                return (false, $"no work item stands for alert '{alert.AlertId}' — auto-close closes nothing");
            if (item.Kind != WorkItemKinds.Alert || item.SourceAlertId != alert.AlertId)
                return (false, $"work item '{id}' is not bound to alert '{alert.AlertId}' — auto-close refused (the close must come from the alert that opened it)");
            if (item.IsClosed)
                return (false, $"work item '{id}' is already closed ({item.Closure?.Outcome} by {item.Closure?.ClosedBy}) — the lifecycle never overwrites a closure");
            var closed = item with
            {
                State = WorkItemStates.Closed,
                ClosedUtc = now,
                UpdatedUtc = now,
                Closure = new WorkItemClosure(WorkItemOutcomes.AutoClosedConditionReset,
                    LifecycleActor, now, true, reason),
            };
            Commit(closed, "work_item_auto_closed", LifecycleActor,
                $"device={item.DeviceId} alert={alert.AlertId} condition={item.SourceConditionId} reason={reason}", now);
            CountClosed(item);
            return (true, $"work item '{id}' auto-closed: condition reset (alert '{alert.AlertId}')");
        }
    }

    // ---- (b) manual items ----------------------------------------------

    public (WorkItem? Item, string Reason) OpenManual(
        string deviceId, string scopeId, string title, string openedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return (null, "a work item needs a device — refused");
        if (!IsValidDeviceId(deviceId)) return (null, $"device id '{deviceId}' contains whitespace or '=' — refused (device ids are audit tokens)");
        if (string.IsNullOrWhiteSpace(title) || title.Trim().Length > WorkItemLimits.MaxTitleLength)
            return (null, $"a work item needs a title within {WorkItemLimits.MaxTitleLength} characters — refused");
        if (ValidateActor(openedBy, "opener") is { } actorRefusal) return (null, actorRefusal);
        lock (_gate)
        {
            var openForDevice = _openByDevice.GetValueOrDefault(deviceId);
            if (openForDevice >= WorkItemLimits.MaxOpenItemsPerDevice)
            {
                // D38-F9: this path SAID "counted, not silent" but
                // counted nothing. It counts (and chains the flood
                // episode) exactly like the alert path.
                RegisterFloodRefusal(deviceId, "manual", $"title={title.Trim()}", now);
                return (null, $"open-item cap reached for device '{deviceId}' — manual open refused (counted, not silent)");
            }
            var item = new WorkItem(
                Id: "wi-" + WorkItemHash.Sha256Hex($"manual|{deviceId.Trim()}|{Guid.NewGuid():N}")[..20],
                Title: title.Trim(),
                DeviceId: deviceId, ScopeId: scopeId ?? "",
                State: WorkItemStates.Open, Owner: null,
                CreatedUtc: now, UpdatedUtc: now, ClosedUtc: null,
                Kind: WorkItemKinds.Manual,
                SourceAlertId: null, SourceConditionId: null,
                ExposureId: null, RequestId: null, RequesterName: null, HealthSummary: null,
                Attachments: Array.Empty<WorkItemAttachment>(), Closure: null,
                AuditSeqs: Array.Empty<long>());
            var committed = Commit(item, "work_item_opened", openedBy.Trim(),
                $"device={deviceId} kind=manual title={item.Title}", now);
            CountOpen(committed);
            _floodAuditSuppressed.Remove(deviceId);
            return (committed, $"work item '{committed.Id}' opened manually by {openedBy.Trim()}");
        }
    }

    public (bool Ok, string Reason) Assign(string itemId, string? owner, string actor, DateTimeOffset now)
    {
        if (ValidateActor(actor, "actor") is { } a) return (false, a);
        if (string.IsNullOrWhiteSpace(owner)) return (false, "assignment needs an owner — refused (unassigned is a state, not an assignment to nobody)");
        lock (_gate)
        {
            if (!_items.TryGetValue(itemId ?? "", out var item)) return (false, $"unknown work item '{itemId}' — refused");
            if (item.IsClosed) return (false, $"work item '{item.Id}' is closed — closed work takes no assignment");
            var updated = item with
            {
                Owner = owner.Trim(),
                State = item.State == WorkItemStates.Open ? WorkItemStates.InProgress : item.State,
                UpdatedUtc = now,
            };
            Commit(updated, "work_item_assigned", actor.Trim(), $"device={item.DeviceId} owner={owner.Trim()}", now);
            return (true, $"work item '{item.Id}' assigned to {owner.Trim()}");
        }
    }

    /// <summary>Attach a session / script / note. The store checks
    /// shape, caps and item state; DEVICE BINDING for sessions (the
    /// session must belong to the item's device) is verified by the
    /// service against the session record before this is called —
    /// the store has no session surface of its own, by design: it
    /// links by id, it does not reach into another record.</summary>
    public (bool Ok, string Reason) Attach(string itemId, WorkItemAttachment? attachment, DateTimeOffset now)
    {
        if (attachment is null) return (false, "no attachment presented — refused");
        if (!AttachmentKinds.All.Contains(attachment.Kind ?? ""))
            return (false, $"unknown attachment kind '{attachment.Kind}' — refused");
        if (string.IsNullOrWhiteSpace(attachment.RefId))
            return (false, "an attachment needs a reference id — refused (a link that names nothing links nothing)");
        if (ValidateActor(attachment.AddedBy, "attacher") is { } a) return (false, a);
        if (attachment.Kind == AttachmentKinds.Note &&
            (string.IsNullOrWhiteSpace(attachment.Text) || attachment.Text.Length > WorkItemLimits.MaxNoteLength))
            return (false, $"a note attachment needs text within {WorkItemLimits.MaxNoteLength} characters — refused");
        if (attachment.Kind != AttachmentKinds.Note && attachment.Text is not null)
            return (false, "only note attachments carry text — refused (session/script attachments are links by id)");
        lock (_gate)
        {
            if (!_items.TryGetValue(itemId ?? "", out var item)) return (false, $"unknown work item '{itemId}' — refused");
            if (item.IsClosed) return (false, $"work item '{item.Id}' is closed — closed work takes no attachments");
            if (item.Attachments.Count >= WorkItemLimits.MaxAttachmentsPerItem)
                return (false, $"work item '{item.Id}' already carries {WorkItemLimits.MaxAttachmentsPerItem} attachments — refused");
            if (item.Attachments.Any(x => x.Kind == attachment.Kind &&
                    string.Equals(x.RefId, attachment.RefId, StringComparison.OrdinalIgnoreCase)))
                return (false, $"work item '{item.Id}' already carries {attachment.Kind} '{attachment.RefId}' — duplicate attachment refused");
            var updated = item with
            {
                Attachments = item.Attachments.Append(attachment).ToList(),
                UpdatedUtc = now,
            };
            Commit(updated, "work_item_attached", attachment.AddedBy.Trim(),
                $"device={item.DeviceId} attachment={attachment.Kind}:{attachment.RefId}", now);
            return (true, $"{attachment.Kind} '{attachment.RefId}' attached to work item '{item.Id}'");
        }
    }

    /// <summary>Manual closure. OUTCOME IS MANDATORY and must be a
    /// human outcome: the reserved auto-close outcome refuses here,
    /// an unknown outcome refuses, a missing closer refuses, and the
    /// lifecycle actor name refuses — a human closure and a
    /// lifecycle auto-close can never be confused in the record.</summary>
    public (bool Ok, string Reason) Close(string itemId, string? outcome, string? closedBy,
        string? note, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(outcome))
            return (false, "closure without an outcome is refused — work closes WITH a verdict or it does not close");
        if (outcome == WorkItemOutcomes.AutoClosedConditionReset)
            return (false, "the auto-close outcome is reserved to the alert lifecycle — a manual closure must name a human outcome (resolved / no_fault_found / duplicate / superseded)");
        if (!WorkItemOutcomes.HumanOutcomes.Contains(outcome))
            return (false, $"unknown closure outcome '{outcome}' — refused");
        if (ValidateActor(closedBy, "closer") is { } a) return (false, a);
        if ((note?.Length ?? 0) > WorkItemLimits.MaxNoteLength)
            return (false, $"closure note exceeds {WorkItemLimits.MaxNoteLength} characters — refused (free text entering the audit chain is bounded)");
        if (string.Equals(closedBy!.Trim(), LifecycleActor, StringComparison.OrdinalIgnoreCase))
            return (false, $"'{LifecycleActor}' is the lifecycle's reserved actor name — a manual closure must name the human who closed it");
        lock (_gate)
        {
            if (!_items.TryGetValue(itemId ?? "", out var item)) return (false, $"unknown work item '{itemId}' — refused");
            if (item.IsClosed) return (false, $"work item '{item.Id}' is already closed ({item.Closure?.Outcome}) — closure is terminal and singular");
            var closed = item with
            {
                State = WorkItemStates.Closed,
                ClosedUtc = now,
                UpdatedUtc = now,
                Closure = new WorkItemClosure(outcome, closedBy.Trim(), now, false, note),
            };
            // BD-SHARED-RMM-3/F7: the outcome token sits at the FIXED
            // position immediately after Commit's item= prefix, and
            // the note is redacted + AuditText-escaped — a device id
            // or note can no longer inject an earlier outcome= token
            // for ReconstructedHistory to misread.
            Commit(closed, "work_item_closed", closedBy.Trim(),
                $"outcome={outcome} device={item.DeviceId} kind={item.Kind} note={AuditText.Escape(Redactor.RedactText(note ?? ""))}", now);
            CountClosed(item);
            return (true, $"work item '{item.Id}' closed ({outcome}) by {closedBy.Trim()}");
        }
    }

    // ---- (c) the request channel intake ---------------------------------

    /// <summary>Intake one end-user request. `authenticatedDeviceId`
    /// is the device identity OF THE CHANNEL the request arrived on
    /// (the agent's own authenticated identity) — the ONLY identity
    /// the item ever carries. A body claiming a different device is
    /// a spoof attempt: refused, audited, and NO item is created.
    /// Idempotent per request id.</summary>
    public (WorkItem? Item, bool Created, string Reason) IntakeRequest(
        string? authenticatedDeviceId, string scopeId, UserWorkRequest? request, DateTimeOffset now)
    {
        if (request is null) return (null, false, "no request presented — refused");
        if (string.IsNullOrWhiteSpace(authenticatedDeviceId))
            return (null, false, "the request arrived on no authenticated device channel — refused (an unattributed request carries no device context)");
        if (string.IsNullOrWhiteSpace(request.RequestId))
            return (null, false, "the request carries no request id — refused");
        lock (_gate)
        {
            if (!string.Equals(request.ClaimedDeviceId?.Trim(), authenticatedDeviceId.Trim(),
                    StringComparison.OrdinalIgnoreCase))
            {
                // D38-F10: chained on the FIRST spoof per channel
                // device and counted thereafter — a spoof loop
                // cannot grow the chain one entry per attempt.
                var spoofs = _spoofRefusals[authenticatedDeviceId] =
                    _spoofRefusals.GetValueOrDefault(authenticatedDeviceId) + 1;
                if (spoofs == 1)
                    _audit.Append("work_request_spoof_refused", "work-items",
                        $"request={request.RequestId} claimedDevice={request.ClaimedDeviceId} channelDevice={authenticatedDeviceId} — the request body claimed a device the channel does not authenticate; refused, no item created (further spoofs on this channel are counted in SpoofRefusals, not chained per attempt)", now);
                return (null, false, $"the request claims device '{request.ClaimedDeviceId}' but arrived on the authenticated channel of '{authenticatedDeviceId}' — refused as a spoofed device context; no work item created");
            }
            if (string.IsNullOrWhiteSpace(request.Text) ||
                request.Text.Trim().Length > WorkItemLimits.MaxRequestTextLength)
                return (null, false, $"a request needs text within {WorkItemLimits.MaxRequestTextLength} characters — refused");
            if (string.IsNullOrWhiteSpace(request.RequesterName))
                return (null, false, "a request needs a requester name — refused");
            var id = WorkItem.IdForRequest(request.RequestId);
            if (_items.TryGetValue(id, out var existing))
                return (existing, false, $"request '{request.RequestId}' already stands as work item '{id}' (idempotent intake)");
            var openForDevice = _openByDevice.GetValueOrDefault(authenticatedDeviceId);
            if (openForDevice >= WorkItemLimits.MaxOpenItemsPerDevice)
            {
                // D38-F9: counted + chained like every cap path.
                RegisterFloodRefusal(authenticatedDeviceId, "request", $"request={request.RequestId}", now);
                return (null, false, $"open-item cap reached for device '{authenticatedDeviceId}' — request refused (counted, not silent)");
            }
            var item = new WorkItem(
                Id: id,
                Title: request.Text.Trim().Length <= 120 ? request.Text.Trim() : request.Text.Trim()[..120],
                DeviceId: authenticatedDeviceId,
                ScopeId: scopeId ?? "",
                State: WorkItemStates.Open, Owner: null,
                CreatedUtc: now, UpdatedUtc: now, ClosedUtc: null,
                Kind: WorkItemKinds.Request,
                SourceAlertId: null, SourceConditionId: null, ExposureId: null,
                RequestId: request.RequestId,
                RequesterName: request.RequesterName.Trim(),
                HealthSummary: request.HealthSummary,
                Attachments: Array.Empty<WorkItemAttachment>(), Closure: null,
                AuditSeqs: Array.Empty<long>());
            var committed = Commit(item, "work_item_opened", "work-items",
                $"device={authenticatedDeviceId} kind=request request={request.RequestId} requester={item.RequesterName} healthState={request.HealthSummary?.HealthState} firing={string.Join(",", request.HealthSummary?.FiringConditionIds ?? Array.Empty<string>())}", now);
            CountOpen(committed);
            _floodAuditSuppressed.Remove(authenticatedDeviceId);
            return (committed, true, $"request '{request.RequestId}' accepted as work item '{id}' for device '{authenticatedDeviceId}'");
        }
    }

    // ---- RMM-05 adoption --------------------------------------------------

    /// <summary>Adopt (or re-sync) an RMM-05 exposure as a work item.
    /// Composition, not a fork: the exposure record is untouched and
    /// remains the lifecycle authority for its payload; this item is
    /// its projection onto the shared trail. Re-sync refreshes the
    /// spine (owner, updated) and follows the exposure's closure —
    /// a closed exposure closes its projection with the exposure's
    /// own closer named; a projection already closed by a human is
    /// never overwritten.</summary>
    public (WorkItem Item, bool Created) AdoptExposure(ExposureWorkItem exposure, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(exposure);
        lock (_gate)
        {
            var projection = WorkItem.FromExposure(exposure);
            if (!_items.TryGetValue(projection.Id, out var existing))
            {
                var committed = Commit(projection, "work_item_opened", "work-items",
                    $"device={exposure.DeviceId} kind=vulnerability exposure={exposure.Id} cve={exposure.CveId} severity={exposure.Severity}", now);
                CountOpen(committed);
                if (committed.IsClosed && exposure.Closure is not null)
                    // Adopted already-closed: the closure joins the
                    // chain as its own event so reconstruction agrees.
                    // D38-F2: the outcome token is the projection's
                    // OWN closure outcome (kind-mapped), never a
                    // hardcoded label.
                    committed = Commit(committed, "work_item_closed", exposure.Closure.ClosedBy,
                        $"outcome={committed.Closure!.Outcome} device={exposure.DeviceId} kind=vulnerability exposure={exposure.Id} exposureClosure={exposure.Closure.Kind} note=adopted closed from RMM-05", now);
                return (committed, true);
            }
            if (existing.IsClosed) return (existing, false);
            var refreshed = existing with
            {
                Owner = exposure.Owner ?? existing.Owner,
                UpdatedUtc = now,
                State = exposure.IsClosed ? WorkItemStates.Closed : existing.State,
                ClosedUtc = exposure.IsClosed ? exposure.ClosedUtc : existing.ClosedUtc,
                Closure = exposure.IsClosed && exposure.Closure is not null
                    ? new WorkItemClosure(WorkItemOutcomes.ForExposureClosure(exposure.Closure.Kind), exposure.Closure.ClosedBy,
                        exposure.Closure.ClosedUtc, false,
                        $"vulnerability closure ({exposure.Closure.Kind}) evidence {exposure.Closure.EvidenceHash}")
                    : existing.Closure,
            };
            if (refreshed.State == existing.State && refreshed.Owner == existing.Owner)
                return (existing, false);
            var kind = refreshed.IsClosed ? "work_item_closed" : "work_item_synced";
            // D38-F2: the re-sync closure event MUST carry the
            // outcome= token (before any free-text field) — without
            // it reconstruction found no closure outcome and
            // VerifyAgainstChain reported a false disagreement for
            // every exposure closed by re-adoption.
            var detail = refreshed.IsClosed && exposure.Closure is not null
                ? $"outcome={refreshed.Closure!.Outcome} device={exposure.DeviceId} kind=vulnerability exposure={exposure.Id} exposureClosure={exposure.Closure.Kind} exposureState={exposure.State}"
                : $"device={exposure.DeviceId} kind=vulnerability exposure={exposure.Id} exposureState={exposure.State}";
            var committed2 = Commit(refreshed, kind, "work-items", detail, now);
            if (refreshed.IsClosed) CountClosed(existing);
            return (committed2, false);
        }
    }

    // ---- history verification ---------------------------------------------

    /// <summary>Verify the store's state for one item AGAINST the
    /// chain: every audit seq the item references must exist and
    /// name this item, and the state reconstructed from the chain
    /// must equal the item's stored state (incl. closure outcome).
    /// A divergence is named — item state that disagrees with the
    /// audit chain is exactly the history-rewriting failure.</summary>
    public (bool Ok, string Reason) VerifyAgainstChain(string itemId)
    {
        WorkItem? item;
        lock (_gate) item = itemId is not null && _items.TryGetValue(itemId, out var i) ? i : null;
        if (item is null) return (false, $"unknown work item '{itemId}'");
        var entries = _audit.Entries;
        var bySeq = entries.ToDictionary(e => e.Seq);
        foreach (var seq in item.AuditSeqs)
        {
            if (!bySeq.TryGetValue(seq, out var e))
                return (false, $"work item '{item.Id}' references audit seq {seq} which is not in the chain — history does not reconstruct");
            if (!ReconstructedHistory.NamesItem(e, item.Id))
                return (false, $"audit seq {seq} does not name work item '{item.Id}' — the item's references do not match the chain");
        }
        var rebuilt = ReconstructedHistory.Reconstruct(entries, item.Id);
        if (!rebuilt.Found) return (false, $"the chain carries no events for work item '{item.Id}' — history does not reconstruct");
        if (rebuilt.FinalState != item.State)
            return (false, $"chain reconstructs state '{rebuilt.FinalState}' but the item says '{item.State}' — state disagrees with the audit chain");
        if (item.IsClosed && rebuilt.ClosureOutcome != item.Closure?.Outcome)
            return (false, $"chain reconstructs closure outcome '{rebuilt.ClosureOutcome}' but the item says '{item.Closure?.Outcome}' — state disagrees with the audit chain");
        var chainOk = _audit.Verify();
        if (!chainOk.Ok) return (false, $"the audit chain itself does not verify: {chainOk.Summary}");
        return (true, $"work item '{item.Id}' history reconstructs from the chain ({rebuilt.EventKinds.Count} events, state {item.State})");
    }

    // ---- hub persistence (Lane A: RMM-04 pattern + integrity envelope) ----

    private sealed record StoreDto(List<WorkItem> Items, Dictionary<string, int> FloodRefusals,
        Dictionary<string, int>? SpoofRefusals = null);

    /// <summary>BD-SHARED-RMM-3/F6: items refused by the last
    /// ImportJson validation, by count — named, never silent.</summary>
    public int LastImportRefusedCount { get; private set; }

    public string ExportJson()
    {
        lock (_gate)
        {
            var dto = new StoreDto(
                _items.Values.OrderBy(i => i.Id, StringComparer.Ordinal).ToList(),
                new Dictionary<string, int>(_floodRefusals),
                new Dictionary<string, int>(_spoofRefusals));
            return HubPersistence.Wrap("deskguest-work-items-v1", JsonSerializer.Serialize(dto));
        }
    }

    /// <summary>Restore items whose id does not already stand.
    /// BD-SHARED-RMM-3/F6: every restored item is VALIDATED first
    /// (known kind, valid device token, attachment cap, closure
    /// outcome in the closed set, positive audit seqs, per-device
    /// open caps) — the old shape restored anything the envelope
    /// carried, including the reserved auto-close outcome on a
    /// manual item and AuditSeqs pointing nowhere. Refusals are
    /// counted by name (LastImportRefusedCount), and ONE
    /// 'work_items_restored' chain entry records the restore with
    /// its counts (item AuditSeqs still refer to their birth chain;
    /// the restore entry is the store's own act, not an item event).
    /// A payload failing the integrity envelope restores nothing.</summary>
    public int ImportJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "deskguest-work-items-v1");
        if (payload is null) return 0;
        StoreDto? dto;
        try { dto = JsonSerializer.Deserialize<StoreDto>(payload); } catch { return 0; }
        if (dto is null) return 0;
        var restored = 0;
        var refused = 0;
        lock (_gate)
        {
            foreach (var item in dto.Items ?? new List<WorkItem>())
            {
                if (item is null || _items.ContainsKey(item.Id)) continue;
                if (!IsRestorable(item)) { refused++; continue; }
                if (!item.IsClosed && _openByDevice.GetValueOrDefault(item.DeviceId) >= WorkItemLimits.MaxOpenItemsPerDevice)
                { refused++; continue; }
                _items[item.Id] = item;
                CountOpen(item);
                restored++;
            }
            foreach (var (device, count) in dto.FloodRefusals ?? new Dictionary<string, int>())
                if (!_floodRefusals.ContainsKey(device)) _floodRefusals[device] = count;
            foreach (var (device, count) in dto.SpoofRefusals ?? new Dictionary<string, int>())
                if (!_spoofRefusals.ContainsKey(device)) _spoofRefusals[device] = count;
            LastImportRefusedCount = refused;
            if (restored > 0 || refused > 0)
                _audit.Append("work_items_restored", "work-items",
                    $"restored={restored} refused={refused} — restore validated every item (kind/device/caps/outcomes/seqs) before admission", DateTimeOffset.UtcNow);
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }

    private static bool IsRestorable(WorkItem item)
    {
        if (string.IsNullOrWhiteSpace(item.Id)) return false;
        if (!WorkItemKinds.All.Contains(item.Kind ?? "")) return false;
        if (!IsValidDeviceId(item.DeviceId)) return false;
        if (item.Attachments.Count > WorkItemLimits.MaxAttachmentsPerItem) return false;
        if (item.AuditSeqs.Any(s => s <= 0)) return false;
        if (item.IsClosed && (item.Closure is null || !WorkItemOutcomes.All.Contains(item.Closure.Outcome ?? ""))) return false;
        if (!item.IsClosed && item.Closure is not null) return false;
        return true;
    }
}

/// <summary>Reconstruction of one item's history from the chain
/// alone: the event kinds in order, the final state they imply, and
/// the closure outcome they record. Pure over the entry list.</summary>
public sealed record ReconstructedHistory(
    bool Found, IReadOnlyList<string> EventKinds, string? FinalState, string? ClosureOutcome)
{
    /// <summary>D38-F3: an entry names an item ONLY through the
    /// leading `item=&lt;id&gt;` token Commit stamps at the START
    /// of the detail. The old substring check let any user text
    /// pasted later in a detail (a title, a note, a requester name
    /// containing "item=wi-…") attribute that event to another
    /// item — an audit-attribution injection that could reset a
    /// closed item's rebuilt state to open. Anchored at the
    /// prefix, injected tokens are inert.</summary>
    public static bool NamesItem(ChainedAuditEntry entry, string itemId)
    {
        var prefix = $"item={itemId}";
        return entry.Detail.StartsWith(prefix, StringComparison.Ordinal) &&
            (entry.Detail.Length == prefix.Length || entry.Detail[prefix.Length] == ' ');
    }

    public static ReconstructedHistory Reconstruct(IReadOnlyList<ChainedAuditEntry> entries, string itemId)
    {
        var kinds = new List<string>();
        string? state = null;
        string? outcome = null;
        foreach (var e in entries.OrderBy(e => e.Seq))
        {
            if (!e.Kind.StartsWith("work_item_", StringComparison.Ordinal)) continue;
            if (!NamesItem(e, itemId)) continue;
            kinds.Add(e.Kind);
            switch (e.Kind)
            {
                case "work_item_opened": state = WorkItemStates.Open; break;
                case "work_item_assigned": state = WorkItemStates.InProgress; break;
                case "work_item_closed":
                    state = WorkItemStates.Closed;
                    outcome = ExtractLeadingOutcome(e.Detail, itemId);
                    break;
                case "work_item_auto_closed":
                    state = WorkItemStates.Closed;
                    outcome = WorkItemOutcomes.AutoClosedConditionReset;
                    break;
            }
        }
        return new ReconstructedHistory(kinds.Count > 0, kinds, state, outcome);
    }

    /// <summary>BD-SHARED-RMM-3/F7: the closure outcome is read ONLY
    /// from the fixed position immediately after the leading
    /// item= token. The old IndexOf("outcome=") read the FIRST
    /// occurrence anywhere in the detail, so a device id like
    /// "pc outcome=duplicate" rebuilt a false outcome and
    /// VerifyAgainstChain reported a phantom disagreement.</summary>
    private static string? ExtractLeadingOutcome(string detail, string itemId)
    {
        var prefix = $"item={itemId} outcome=";
        if (!detail.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var rest = detail[prefix.Length..];
        var end = rest.IndexOf(' ');
        return end < 0 ? rest : rest[..end];
    }

    private static string? Extract(string detail, string key)
    {
        var i = detail.IndexOf(key, StringComparison.Ordinal);
        if (i < 0) return null;
        var rest = detail[(i + key.Length)..];
        var end = rest.IndexOf(' ');
        return end < 0 ? rest : rest[..end];
    }

}

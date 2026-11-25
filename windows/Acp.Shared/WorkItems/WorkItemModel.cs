using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Vulnerability;

namespace Acp.Shared.WorkItems;

// =====================================================================
// RMM-12 — Work items: the alert→work→session→audit trail
// (ticket-lite, deliberately NOT a PSA).
//
// A local work-item layer over ACP's hash-chained record:
//   * RMM-01 alerts auto-create work items that AUTO-CLOSE when the
//     condition resets — the close is driven by the alert lifecycle
//     (the IWorkItemSink contract in MonitoringAlerts), never by a
//     human remembering, and never by anything else: the auto-close
//     path is bound to the alert id that opened the item.
//   * A tech can open one manually, attach sessions / scripts /
//     notes, assign it, and close it WITH AN OUTCOME. Closure
//     without an outcome is unrepresentable through the store.
//   * End users get a REQUEST CHANNEL: a request arrives carrying
//     the device's identity + recent health summary. The device
//     identity is stamped from the AUTHENTICATED channel, never
//     taken from the request body — a request claiming another
//     device's context is refused and audited as a spoof attempt.
//   * An outbound BRIDGE (signed webhook) forwards item events to
//     whatever PSA the org already runs. ACP's side only: delivery
//     failures are visible states (pending / failed / dead), never
//     silent drops, and the bridge target passes the RMM-04
//     outbound-guard discipline before anything is sent.
//
// BILLING / CONTRACTS / INVOICING ARE EXPLICITLY OUT. There is no
// money field, no contract field, no invoice shape anywhere in this
// model — the work log is the part with ACP-shaped value; the PSA
// stays the org's existing system, reached only through the bridge.
//
// ADOPTION OF RMM-05: ExposureWorkItem (Acp.Shared.Vulnerability)
// was shaped for this lane as a generic work-item spine + a
// vulnerability payload. The spine is GENERALISED here: WorkItem
// carries (Id, Title, DeviceId, ScopeId, State, Owner, CreatedUtc,
// UpdatedUtc, ClosedUtc) exactly as the exposure item does, and an
// exposure becomes a work item of Kind=vulnerability whose payload
// reference is the exposure's own id (WorkItem.FromExposure). The
// exposure item itself is NOT forked or edited: ExposureStore stays
// its home and its lifecycle authority; the work item is the
// cross-kind operational view that links it into the same
// alert→work→session→audit trail as every other kind.
//
// AUDIT DISCIPLINE: creation / assignment / attachment / closure
// are chained-audit events (kind prefix "work_"). The item record
// REFERENCES audit entries by sequence number (AuditSeqs) — it
// never copies their content — and an item's history is
// reconstructable from the chain alone (ReconstructedHistory).
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-12. The feature
/// toggle itself is seeded in the RMM-07 registry
/// (rmm.work_items.enabled, default ON). The bridge and request
/// channel keys are POLICY CONTENT read through the same engine's
/// Effective Policy view: the bridge is an outbound surface, so it
/// defaults OFF until an admin both configures a target and
/// enables it by policy.</summary>
public static class WorkItemPolicyKeys
{
    public const string Enabled = "rmm.work_items.enabled";
    public const string BridgeEnabled = "rmm.work_items.bridge.enabled";
    public const string RequestChannelEnabled = "rmm.work_items.request_channel.enabled";
}

public static class WorkItemKinds
{
    public const string Alert = "alert";
    public const string Manual = "manual";
    public const string Request = "request";
    public const string Vulnerability = "vulnerability";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Alert, Manual, Request, Vulnerability };
}

public static class WorkItemStates
{
    public const string Open = "open";
    public const string InProgress = "in_progress";
    public const string Closed = "closed";
}

/// <summary>Closure outcomes. A manual closure MUST name one of
/// the human outcomes; the auto-close outcome is RESERVED to the
/// alert lifecycle — the store refuses it from any manual path, so
/// "the condition reset" can never be forged as a human verdict,
/// and a human verdict can never masquerade as an auto-close.</summary>
public static class WorkItemOutcomes
{
    public const string Resolved = "resolved";
    public const string NoFaultFound = "no_fault_found";
    public const string Duplicate = "duplicate";
    public const string Superseded = "superseded";
    public const string AutoClosedConditionReset = "auto_closed_condition_reset";
    /// <summary>Reserved to the RMM-05 adoption path: an exposure
    /// closed by a COMPENSATING CONTROL is mitigated, not resolved —
    /// the vulnerability is still present behind the control, so
    /// projecting it as "resolved" would mislabel the closure
    /// (D38-F2). Like the auto-close outcome it is NOT a human
    /// outcome: the manual close path refuses it.</summary>
    public const string MitigatedCompensatingControl = "mitigated_compensating_control";

    public static readonly IReadOnlySet<string> HumanOutcomes =
        new HashSet<string> { Resolved, NoFaultFound, Duplicate, Superseded };
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Resolved, NoFaultFound, Duplicate, Superseded, AutoClosedConditionReset, MitigatedCompensatingControl };

    /// <summary>Map an RMM-05 exposure closure kind onto the
    /// work-item outcome that HONESTLY names it: a patch closure
    /// resolved the exposure; a compensating-control closure
    /// mitigated it. The exposure's own kind travels in the closure
    /// note and the chain detail alongside the outcome, so nothing
    /// about the original closure is lost in projection.</summary>
    public static string ForExposureClosure(string? exposureClosureKind) =>
        exposureClosureKind == ClosureKinds.CompensatingControl
            ? MitigatedCompensatingControl
            : Resolved;
}

public static class WorkItemLimits
{
    public const int MaxTitleLength = 256;
    public const int MaxNoteLength = 4096;
    public const int MaxRequestTextLength = 2048;
    public const int MaxActorLength = 128;
    /// <summary>Flood discipline for alert-driven creation: at most
    /// this many OPEN alert-kind items per device. Beyond it, opens
    /// refuse (audited, counted) — a flapping condition cannot mint
    /// unbounded work, mirroring RMM-01's own flood cap.</summary>
    public const int MaxOpenAlertItemsPerDevice = 100;
    /// <summary>Absolute cap on open items of any kind per device.</summary>
    public const int MaxOpenItemsPerDevice = 500;
    public const int MaxAttachmentsPerItem = 200;
    /// <summary>Cap on the firing-condition ids a request's health
    /// summary may carry (D38-F10): the list is end-user supplied
    /// and is joined into audit detail, so it is bounded at the
    /// model door, never pasted unbounded into the chain.</summary>
    public const int MaxFiringConditionIds = 32;
    /// <summary>Bridge retention bound (D38-F10): at most this many
    /// delivery records are retained; beyond it the oldest
    /// DELIVERED records are evicted (pending / failed / dead are
    /// never evicted — undelivered and terminal-failure states stay
    /// visible).</summary>
    public const int MaxRetainedDeliveries = 1000;
    /// <summary>Bridge delivery: attempts before a delivery is
    /// pronounced DEAD (a visible terminal state, never a drop).</summary>
    public const int MaxBridgeAttempts = 3;
}

public static class WorkItemHash
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
}

/// <summary>What kind of thing is attached to a work item. A
/// session attachment is a LINK BY SESSION ID into the existing
/// session record (Acp.Shared.Sessions.Session) — the work item
/// never copies session content. A script attachment references a
/// remediation/script id. A note is the tech's own text.</summary>
public static class AttachmentKinds
{
    public const string Session = "session";
    public const string Script = "script";
    public const string Note = "note";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Session, Script, Note };
}

public sealed record WorkItemAttachment(
    string Kind,          // AttachmentKinds.*
    string RefId,         // session id | script id | note id
    string? Text,         // note body (notes only)
    string AddedBy,
    DateTimeOffset AddedUtc);

/// <summary>How an item closed. Present exactly when State=closed.</summary>
public sealed record WorkItemClosure(
    string Outcome,       // WorkItemOutcomes.*
    string ClosedBy,
    DateTimeOffset ClosedUtc,
    bool AutoClosed,      // true only via the alert-lifecycle path
    string? Note);

/// <summary>The recent-health summary a user request carries: the
/// device's own facts at request time (health state, firing
/// conditions, monitor status), supplied by the device's agent over
/// its authenticated channel. It is CONTEXT, not identity — the
/// identity is stamped by the intake from the channel.</summary>
public sealed record DeviceHealthSummary(
    string HealthState,
    IReadOnlyList<string> FiringConditionIds,
    string MonitorStatus,
    DateTimeOffset SampledUtc)
{
    public IReadOnlyList<string> FiringConditionIds { get; init; } =
        (FiringConditionIds ?? Array.Empty<string>())
            .Take(WorkItemLimits.MaxFiringConditionIds).ToList();
}

/// <summary>An end-user request as it arrives at the intake. The
/// ClaimedDeviceId is what the request BODY asserts; the intake
/// compares it against the authenticated device id and refuses on
/// mismatch — the body's claim never becomes the item's device.</summary>
public sealed record UserWorkRequest(
    string RequestId,
    string ClaimedDeviceId,
    string RequesterName,
    string Text,
    DeviceHealthSummary? HealthSummary);

/// <summary>
/// THE WORK ITEM — the generalised spine. The first nine fields are
/// the ExposureWorkItem spine verbatim in shape (Id, Title,
/// DeviceId, ScopeId, State, Owner, CreatedUtc, UpdatedUtc,
/// ClosedUtc); Kind discriminates the specialisation and the
/// kind-specific references (SourceAlertId, ExposureId, RequestId)
/// are the typed payload links — ids into the owning records, never
/// copies of them.
/// </summary>
public sealed record WorkItem(
    string Id,
    string Title,
    string DeviceId,
    string ScopeId,
    string State,
    string? Owner,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    DateTimeOffset? ClosedUtc,
    // --- specialisation ---
    string Kind,                       // WorkItemKinds.*
    string? SourceAlertId,             // alert kind: the RMM-01 alert that opened it
    string? SourceConditionId,         // alert kind: the condition behind the alert
    string? ExposureId,                // vulnerability kind: the ExposureWorkItem id
    string? RequestId,                 // request kind: the intake request id
    string? RequesterName,             // request kind: who asked
    DeviceHealthSummary? HealthSummary, // request kind: device context at intake
    IReadOnlyList<WorkItemAttachment> Attachments,
    WorkItemClosure? Closure,
    IReadOnlyList<long> AuditSeqs)     // references into the chain, never copies
{
    public IReadOnlyList<WorkItemAttachment> Attachments { get; init; } =
        Attachments ?? Array.Empty<WorkItemAttachment>();
    public IReadOnlyList<long> AuditSeqs { get; init; } =
        AuditSeqs ?? Array.Empty<long>();

    public bool IsClosed => State == WorkItemStates.Closed;

    /// <summary>Deterministic id for one alert episode's work item:
    /// re-delivery of the same alert open finds THIS item — the
    /// sink is idempotent per alert, so a retried open can never
    /// mint a duplicate.</summary>
    public static string IdForAlert(string alertId) =>
        "wi-" + WorkItemHash.Sha256Hex($"alert|{(alertId ?? "").Trim()}")[..20];

    public static string IdForExposure(string exposureId) =>
        "wi-" + WorkItemHash.Sha256Hex($"exposure|{(exposureId ?? "").Trim()}")[..20];

    public static string IdForRequest(string requestId) =>
        "wi-" + WorkItemHash.Sha256Hex($"request|{(requestId ?? "").Trim()}")[..20];

    /// <summary>ADOPT an RMM-05 exposure as a work item (projection,
    /// not a fork): the spine fields map field-for-field; the
    /// vulnerability payload stays in the ExposureWorkItem, linked
    /// by ExposureId. State maps open-family → open, closed →
    /// closed with the exposure's own closure outcome named in the
    /// closure note (the evidence itself stays in RMM-05's record).</summary>
    public static WorkItem FromExposure(ExposureWorkItem exposure)
    {
        ArgumentNullException.ThrowIfNull(exposure);
        var closed = exposure.IsClosed;
        return new WorkItem(
            Id: IdForExposure(exposure.Id),
            Title: exposure.Title,
            DeviceId: exposure.DeviceId,
            ScopeId: exposure.ScopeId,
            State: closed ? WorkItemStates.Closed : WorkItemStates.Open,
            Owner: exposure.Owner,
            CreatedUtc: exposure.CreatedUtc,
            UpdatedUtc: exposure.UpdatedUtc,
            ClosedUtc: exposure.ClosedUtc,
            Kind: WorkItemKinds.Vulnerability,
            SourceAlertId: null,
            SourceConditionId: null,
            ExposureId: exposure.Id,
            RequestId: null,
            RequesterName: null,
            HealthSummary: null,
            Attachments: Array.Empty<WorkItemAttachment>(),
            Closure: closed && exposure.Closure is not null
                ? new WorkItemClosure(WorkItemOutcomes.ForExposureClosure(exposure.Closure.Kind), exposure.Closure.ClosedBy,
                    exposure.Closure.ClosedUtc, false,
                    $"vulnerability closure ({exposure.Closure.Kind}) evidence {exposure.Closure.EvidenceHash}")
                : null,
            AuditSeqs: Array.Empty<long>());
    }
}

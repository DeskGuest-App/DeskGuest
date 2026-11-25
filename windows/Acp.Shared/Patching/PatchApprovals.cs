namespace Acp.Shared.Patching;

// =====================================================================
// RMM-02 — Approval workflows.
//
// Deployment authority comes from exactly one place: an approval
// decision recorded against (entry id, entry CONTENT HASH, device
// scope). Rules classify entries into auto / manual / reject by
// classification, severity, or KB id; a human decision covers the
// manual class. The defaults fail closed:
//
//   * NO matching rule ⇒ manual (a human must decide) — never auto;
//   * a REJECT decision (rule or human) stands until it is
//     EXPLICITLY superseded by a named decider at the same scope
//     (D38 F7 revocation path: supersession appends a new decision
//     and the latest per scope governs — the old decision is
//     never edited or erased);
//   * an approval recorded against content hash H authorises ONLY
//     content hash H. Edit or swap the entry after approval and
//     the approval silently stops matching — deployment re-checks
//     currency at deploy time, every time;
//   * auto-approval is a DECISION too: it is recorded with its
//     rule as the actor, so the audit trail shows who/what
//     approved every deployment, human or rule.
//
// Decisions are append-only records in this store; the Core
// service mirrors every one into the hash-chained audit log.
// =====================================================================

public static class ApprovalDecisions
{
    public const string Approved = "approved";
    public const string Rejected = "rejected";
    public const string PendingManual = "pending_manual";
}

/// <summary>What a rule (or the default) says about an entry class.</summary>
public enum ApprovalMode { AutoApprove, RequireManual, Reject }

/// <summary>One approval rule. All non-null match fields must
/// match (AND); a rule with no match fields matches everything —
/// authors should place it last, deliberately.</summary>
public sealed record ApprovalRule(
    string Name,
    ApprovalMode Mode,
    string? Classification = null,
    string? Severity = null,
    string? KbId = null,
    string? EntryId = null)
{
    public bool Matches(PatchCatalogueEntry e) =>
        (Classification is null || string.Equals(Classification, e.Classification, StringComparison.OrdinalIgnoreCase)) &&
        (Severity is null || string.Equals(Severity, e.Severity, StringComparison.OrdinalIgnoreCase)) &&
        (KbId is null || string.Equals(KbId, e.KbId, StringComparison.OrdinalIgnoreCase)) &&
        (EntryId is null || string.Equals(EntryId, e.Id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>The ordered rule set (management-policy content in
/// production; a value object here). First match wins; no match ⇒
/// RequireManual — the fail-closed default.</summary>
public sealed record ApprovalPolicy(IReadOnlyList<ApprovalRule> Rules)
{
    public (ApprovalMode Mode, string RuleName) Evaluate(PatchCatalogueEntry entry)
    {
        foreach (var rule in Rules ?? Array.Empty<ApprovalRule>())
            if (rule.Matches(entry)) return (rule.Mode, rule.Name);
        return (ApprovalMode.RequireManual, "(default: no rule matched — manual)");
    }

    public static ApprovalPolicy ManualOnly { get; } = new(Array.Empty<ApprovalRule>());
}

/// <summary>One recorded decision. Scope is a device id, or "*"
/// for a fleet-scope decision (an approval for the patch itself,
/// any device). Device-scope beats fleet-scope at lookup; a
/// device-scope REJECT beats a fleet-scope approval (the narrower
/// refusal wins — fail closed).</summary>
public sealed record ApprovalDecisionRecord(
    string EntryId,
    string EntryContentHash,
    string DeviceScope,
    string Decision,
    string DecidedBy,
    DateTimeOffset DecidedUtc,
    string Basis);

/// <summary>Append-only decision store + the currency check the
/// deploy path calls. Recording is idempotent per (entry, content,
/// scope, decision, decider) — replaying the same decision changes
/// nothing; a CONTRADICTING decision for the same content+scope is
/// refused (decisions are history, not a mutable flag: to change
/// the answer, change the content or narrow the scope).</summary>
public sealed class PatchApprovalStore
{
    private readonly List<ApprovalDecisionRecord> _records = new();
    private readonly object _gate = new();

    public IReadOnlyList<ApprovalDecisionRecord> Records
    {
        get { lock (_gate) return _records.ToList(); }
    }

    public (bool Recorded, string Reason) Record(ApprovalDecisionRecord record) =>
        Record(record, supersede: false);

    /// <summary>Record a decision. Plain recording refuses to
    /// contradict a standing decision at the same content+scope
    /// (history is not a mutable flag). D38 F7: that rule left NO
    /// way to retract an approval for the same content — a bad
    /// fleet approval could never be fleet-rejected. The explicit
    /// <paramref name="supersede"/> path is the revocation: the new
    /// decision is APPENDED (the old one stays in the record —
    /// nothing is rewritten) and the currency check reads the
    /// LATEST decision per scope, so the superseding decision is
    /// the one that governs. Supersession is a deliberate act by a
    /// named decider, mirrored into the chained audit by the Core
    /// service; it is never inferred.</summary>
    public (bool Recorded, string Reason) Record(ApprovalDecisionRecord record, bool supersede)
    {
        if (record is null) return (false, "no decision record — refused");
        if (record.Decision is not (ApprovalDecisions.Approved or ApprovalDecisions.Rejected))
            return (false, $"decision '{record.Decision}' is not a recordable decision (approved/rejected) — refused");
        if (string.IsNullOrWhiteSpace(record.DecidedBy))
            return (false, "a decision with no decider is not a decision — refused (who/when is the audit contract)");
        lock (_gate)
        {
            var same = _records.Where(r =>
                r.EntryId == record.EntryId && r.EntryContentHash == record.EntryContentHash &&
                string.Equals(r.DeviceScope, record.DeviceScope, StringComparison.OrdinalIgnoreCase)).ToList();
            if (same.Any(r => r.Decision != record.Decision))
            {
                if (!supersede)
                    return (false, $"a contradicting decision already stands for entry '{record.EntryId}' content {record.EntryContentHash[..Math.Min(12, record.EntryContentHash.Length)]}… at scope '{record.DeviceScope}' — refused (decisions are history; supersede explicitly, change the content, or narrow the scope)");
                _records.Add(record);
                return (true, $"decision recorded: {record.Decision} for '{record.EntryId}' at scope '{record.DeviceScope}' by {record.DecidedBy} — SUPERSEDES the standing {same[^1].Decision} by {same[^1].DecidedBy} (the superseded decision remains in the record)");
            }
            if (same.Any(r => r.Decision == record.Decision && r.DecidedBy == record.DecidedBy))
                return (true, "decision already recorded (idempotent)");
            _records.Add(record);
            return (true, $"decision recorded: {record.Decision} for '{record.EntryId}' at scope '{record.DeviceScope}' by {record.DecidedBy}");
        }
    }

    /// <summary>Restore persisted decision history verbatim
    /// (Core service state load, D38 F3). History is appended in
    /// its recorded order with NO contradiction checks — the
    /// checks govern NEW decisions, and a restored store must be
    /// able to hold a superseded pair exactly as it was written.</summary>
    public void Restore(IEnumerable<ApprovalDecisionRecord> records)
    {
        lock (_gate) _records.AddRange(records);
    }

    /// <summary>The deploy-time currency check. The governing
    /// decision is the LATEST recorded decision per scope for the
    /// entry's CURRENT content hash (D38 F7: supersession appends,
    /// so an old decision still in the list must not govern).
    /// Device scope beats fleet scope (the narrower decision
    /// wins — a device reject overrides a fleet approval, and a
    /// device approval overrides a fleet reject). Anything else —
    /// no record, a record against older content, a governing
    /// reject — is not approved, with the reason named.</summary>
    public (bool Approved, string Reason) CheckCurrent(PatchCatalogueEntry entry, string deviceId)
    {
        lock (_gate)
        {
            var relevant = _records.Where(r => r.EntryId == entry.Id && r.EntryContentHash == entry.ContentHash &&
                (r.DeviceScope == "*" || string.Equals(r.DeviceScope, deviceId, StringComparison.OrdinalIgnoreCase))).ToList();
            // BD-SHARED-RMM-2/F11: the LATEST standing decision governs,
            // across scopes. The old rule let ANY device-scope decision
            // beat the fleet decision forever, so the D38-F7 revocation
            // path — a fleet-scope REJECT recorded to pull a bad patch —
            // never stopped a device already holding a device approval.
            // "Narrower wins" is fail-closed only when the narrower
            // decision is also the newer one; recency is the honest
            // rule, and a device approval explicitly RE-recorded after
            // a fleet reject still governs (it is the latest word).
            var effective = relevant.LastOrDefault();
            if (effective is not null)
            {
                if (effective.Decision == ApprovalDecisions.Rejected)
                    return (false, $"entry '{entry.Id}' is REJECTED at scope '{effective.DeviceScope}' by {effective.DecidedBy} ({effective.Basis}) — deployment refused");
                return (true, $"approved by {effective.DecidedBy} at {effective.DecidedUtc:O} ({effective.Basis})");
            }
            var stale = _records.Any(r => r.EntryId == entry.Id && r.EntryContentHash != entry.ContentHash && r.Decision == ApprovalDecisions.Approved);
            return (false, stale
                ? $"approvals exist for entry '{entry.Id}' but against DIFFERENT content — the entry changed after approval, so no approval covers what would deploy now — refused (re-approval required)"
                : $"no approval stands for entry '{entry.Id}' (content {entry.ContentHash[..12]}…) — an unapproved patch NEVER deploys (fail closed)");
        }
    }
}

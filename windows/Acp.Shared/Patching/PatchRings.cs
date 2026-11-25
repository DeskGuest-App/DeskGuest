using System.Security.Cryptography;
using System.Text;

namespace Acp.Shared.Patching;

// =====================================================================
// RMM-02 — Rollout rings (test → pilot → fleet).
//
// A rollout advances ring by ring. Each ring carries a SUCCESS
// THRESHOLD: the minimum fraction of its devices that must report
// success for the ring to complete. Breach HALTS the rollout
// automatically — the halt is a STATE carrying its evidence (the
// exact counts that breached), not a log line:
//
//   * outcomes are recorded once per device per ring. A device
//     cannot be counted twice (double-counted success is how
//     thresholds get gamed), and a recorded failure cannot be
//     overwritten by a later "success" for the same device (hidden
//     failures are the other half of gaming);
//   * a halt can trigger EARLY: once failures make the threshold
//     mathematically unreachable, the ring halts immediately
//     rather than burning the rest of the ring to learn the same
//     fact;
//   * a HALTED ring resumes ONLY on a new signed decision: the
//     resume decision binds (plan, ring, halt-evidence hash) — it
//     is recorded as an approval decision by a named decider
//     through the PatchService, which verifies the RMM-03 envelope
//     before calling here. There is deliberately NO parameterless
//     resume: this class cannot move a halted ring on its own
//     authority;
//   * the next ring cannot start while an earlier ring is
//     incomplete or halted — order is enforced by state, not by
//     caller discipline.
// =====================================================================

public static class RingStates
{
    public const string NotStarted = "not_started";
    public const string InProgress = "in_progress";
    public const string Halted = "halted";
    public const string Complete = "complete";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { NotStarted, InProgress, Halted, Complete };
}

public sealed record RingDefinition(string Name, int Order, double SuccessThreshold, IReadOnlyList<string> DeviceIds)
{
    public IReadOnlyList<string> DeviceIds { get; init; } = DeviceIds ?? Array.Empty<string>();
}

/// <summary>The evidence that halted a ring: the counts at halt
/// time and the threshold they breached. Hashed into the resume
/// decision's binding, so a resume decision made against one
/// halt's evidence cannot be replayed against a different halt.</summary>
public sealed record RingHaltEvidence(string RingName, int Succeeded, int Failed, int TotalDevices,
    double SuccessThreshold, string Reason, DateTimeOffset HaltedUtc)
{
    // BD-SHARED-RMM-2/F12: the threshold is formatted with the
    // INVARIANT culture ('R') — the old interpolation used the host's
    // current culture, so a resume basis built on a de-DE host never
    // matched one built on an en-US host.
    public string EvidenceHash => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"acp-ring-halt-v1|{RingName}|{Succeeded}|{Failed}|{TotalDevices}|{SuccessThreshold.ToString("R", System.Globalization.CultureInfo.InvariantCulture)}|{Reason}|{HaltedUtc:O}"))).ToLowerInvariant();
}

public sealed record RingStatus(string Name, int Order, string State, int Succeeded, int Failed,
    int TotalDevices, double SuccessThreshold, RingHaltEvidence? HaltEvidence);

public sealed class RolloutPlan
{
    private readonly Dictionary<string, Dictionary<string, bool>> _outcomes = new(StringComparer.OrdinalIgnoreCase); // ring -> device -> success
    private readonly Dictionary<string, string> _states = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RingHaltEvidence> _halts = new(StringComparer.OrdinalIgnoreCase);
    // D38 F11(b): resume baselines — (outcomes recorded, successes)
    // at the moment a halted ring was resumed under a signed
    // decision. Threshold arithmetic after a resume is judged on
    // the POST-resume cohort only: the recorded failures stay in
    // the record (StatusOf counts never shrink), but a signed
    // resume decision is precisely a human accepting those known
    // failures and judging the ring on its remaining devices.
    // Without this, bestPossible was already below threshold at
    // resume time and the very next outcome re-halted the ring —
    // a resumed ring could NEVER complete.
    private readonly Dictionary<string, (int Count, int Succeeded)> _resumeBaseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public RolloutPlan(string id, string entryId, string entryContentHash, IReadOnlyList<RingDefinition> rings)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        EntryId = entryId ?? throw new ArgumentNullException(nameof(entryId));
        EntryContentHash = entryContentHash ?? throw new ArgumentNullException(nameof(entryContentHash));
        Rings = (rings ?? throw new ArgumentNullException(nameof(rings))).OrderBy(r => r.Order).ToList();
        if (Rings.Count == 0) throw new ArgumentException("a rollout plan needs at least one ring", nameof(rings));
        if (Rings.Select(r => r.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Rings.Count)
            throw new ArgumentException("ring names must be distinct within a plan", nameof(rings));
        foreach (var ring in Rings)
        {
            // D38 F11(c): a threshold of exactly 0.0 completes a
            // ring in which EVERY device failed — a threshold must
            // demand at least some success, so the valid range is
            // (0.0, 1.0].
            if (ring.SuccessThreshold is <= 0.0 or > 1.0)
                throw new ArgumentException($"ring '{ring.Name}' success threshold {ring.SuccessThreshold} is outside (0.0–1.0] — a 0.0 threshold would complete a ring where every device failed", nameof(rings));
            if (ring.DeviceIds.Count == 0)
                throw new ArgumentException($"ring '{ring.Name}' has no devices — an empty ring would complete vacuously and prove nothing", nameof(rings));
            if (ring.DeviceIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() != ring.DeviceIds.Count)
                throw new ArgumentException($"ring '{ring.Name}' lists a device twice — refused (double membership is double counting)", nameof(rings));
            _outcomes[ring.Name] = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            _states[ring.Name] = RingStates.NotStarted;
        }
        // D38 F11(a): a device in TWO rings breaks both rings'
        // arithmetic — RingOf resolves it to the earlier ring, so
        // the later ring's denominator counts a device that can
        // never report there (its deploy gate resolves to the
        // earlier ring). Membership is exclusive by construction.
        var duplicated = Rings.SelectMany(r => r.DeviceIds)
            .GroupBy(d => d, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1);
        if (duplicated is not null)
            throw new ArgumentException($"device '{duplicated.Key}' appears in more than one ring of plan '{id}' — refused (ring membership is exclusive: a device in two rings corrupts both rings' thresholds)", nameof(rings));
    }

    public string Id { get; }
    public string EntryId { get; }
    public string EntryContentHash { get; }
    public IReadOnlyList<RingDefinition> Rings { get; }

    public RingStatus StatusOf(string ringName)
    {
        lock (_gate)
        {
            var ring = Rings.FirstOrDefault(r => string.Equals(r.Name, ringName, StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException($"unknown ring '{ringName}'", nameof(ringName));
            var outcomes = _outcomes[ring.Name];
            return new RingStatus(ring.Name, ring.Order, _states[ring.Name],
                outcomes.Values.Count(v => v), outcomes.Values.Count(v => !v),
                ring.DeviceIds.Count, ring.SuccessThreshold,
                _halts.TryGetValue(ring.Name, out var h) ? h : null);
        }
    }

    public IReadOnlyList<RingStatus> Statuses
    {
        get { lock (_gate) return Rings.Select(r => StatusOf(r.Name)).ToList(); }
    }

    /// <summary>Which ring a device belongs to in this plan (null
    /// when the device is in no ring — such a device is outside
    /// this rollout entirely).</summary>
    public string? RingOf(string deviceId)
    {
        lock (_gate)
            return Rings.FirstOrDefault(r => r.DeviceIds.Contains(deviceId ?? "", StringComparer.OrdinalIgnoreCase))?.Name;
    }

    /// <summary>Start a ring. Only the FIRST incomplete ring in
    /// order may start, and only from NotStarted: an earlier ring
    /// that is in progress, halted, or skipped-over blocks every
    /// later ring.</summary>
    public (bool Ok, string Reason) StartRing(string ringName)
    {
        lock (_gate)
        {
            var ring = Rings.FirstOrDefault(r => string.Equals(r.Name, ringName, StringComparison.OrdinalIgnoreCase));
            if (ring is null) return (false, $"unknown ring '{ringName}' — refused");
            if (_states[ring.Name] != RingStates.NotStarted)
                return (false, $"ring '{ring.Name}' is {_states[ring.Name]} — only a not-started ring can start (a halted ring needs a signed resume decision, never a restart)");
            foreach (var earlier in Rings.Where(r => r.Order < ring.Order))
                if (_states[earlier.Name] != RingStates.Complete)
                    return (false, $"ring '{earlier.Name}' is {_states[earlier.Name]}, not complete — ring '{ring.Name}' cannot start out of order");
            _states[ring.Name] = RingStates.InProgress;
            return (true, $"ring '{ring.Name}' started ({ring.DeviceIds.Count} device(s), success threshold {ring.SuccessThreshold:P0})");
        }
    }

    /// <summary>Record one device's outcome in the active ring.
    /// Once-only per device: a second report for the same device —
    /// in either direction — refuses, so successes cannot be
    /// double-counted and failures cannot be hidden. After each
    /// outcome the threshold is re-evaluated: unreachable ⇒ HALT
    /// now; all devices in and threshold met ⇒ Complete; all in
    /// and threshold missed ⇒ HALT.</summary>
    public (bool Ok, string Reason) RecordOutcome(string ringName, string deviceId, bool success, DateTimeOffset now)
    {
        lock (_gate)
        {
            var ring = Rings.FirstOrDefault(r => string.Equals(r.Name, ringName, StringComparison.OrdinalIgnoreCase));
            if (ring is null) return (false, $"unknown ring '{ringName}' — refused");
            if (_states[ring.Name] != RingStates.InProgress)
                return (false, $"ring '{ring.Name}' is {_states[ring.Name]} — outcomes record only while a ring is in progress");
            if (!ring.DeviceIds.Contains(deviceId ?? "", StringComparer.OrdinalIgnoreCase))
                return (false, $"device '{deviceId}' is not a member of ring '{ring.Name}' — outcome refused (a non-member cannot move a ring's numbers)");
            var outcomes = _outcomes[ring.Name];
            if (outcomes.ContainsKey(deviceId))
                return (false, $"device '{deviceId}' already has a recorded outcome in ring '{ring.Name}' — refused (outcomes are once-only: no double-counted success, no hidden failure)");
            outcomes[deviceId] = success;
            var succeeded = outcomes.Values.Count(v => v);
            var failed = outcomes.Values.Count(v => !v);
            var total = ring.DeviceIds.Count;
            // Threshold arithmetic is judged on the cohort since
            // the last signed resume (the whole ring before any
            // resume): baseline outcomes are the known failures a
            // named decider already accepted (D38 F11(b)).
            var (baseCount, baseSucceeded) = _resumeBaseline.GetValueOrDefault(ring.Name, (0, 0));
            var judgedTotal = total - baseCount;
            var judgedSucceeded = succeeded - baseSucceeded;
            var judgedReported = outcomes.Count - baseCount;
            // Early halt: even if every remaining device succeeds,
            // the threshold is unreachable.
            var bestPossible = (double)(judgedSucceeded + (judgedTotal - judgedReported)) / judgedTotal;
            if (bestPossible < ring.SuccessThreshold)
            {
                var evidence = new RingHaltEvidence(ring.Name, succeeded, failed, total, ring.SuccessThreshold,
                    $"success threshold {ring.SuccessThreshold:P0} is mathematically unreachable: {failed} failure(s) cap the ring at {bestPossible:P0}", now);
                _states[ring.Name] = RingStates.Halted;
                _halts[ring.Name] = evidence;
                return (true, $"outcome recorded; ring '{ring.Name}' HALTED — {evidence.Reason}");
            }
            if (outcomes.Count == total)
            {
                var rate = (double)judgedSucceeded / judgedTotal;
                if (rate >= ring.SuccessThreshold)
                {
                    _states[ring.Name] = RingStates.Complete;
                    return (true, $"outcome recorded; ring '{ring.Name}' COMPLETE at {rate:P0} success (threshold {ring.SuccessThreshold:P0})");
                }
                var evidence = new RingHaltEvidence(ring.Name, succeeded, failed, total, ring.SuccessThreshold,
                    $"ring finished at {rate:P0} success, below the {ring.SuccessThreshold:P0} threshold", now);
                _states[ring.Name] = RingStates.Halted;
                _halts[ring.Name] = evidence;
                return (true, $"outcome recorded; ring '{ring.Name}' HALTED — {evidence.Reason}");
            }
            return (true, $"outcome recorded for '{deviceId}' in ring '{ring.Name}' ({succeeded} ok / {failed} failed / {total - outcomes.Count} outstanding)");
        }
    }

    /// <summary>Resume a halted ring. The ONLY caller is the Core
    /// service after it has verified a fresh RMM-03 signed decision
    /// whose recorded basis binds this plan, this ring, and the
    /// halt evidence hash — this method re-checks that binding
    /// against the CURRENT halt evidence, so a decision recorded
    /// against an earlier (or different) halt cannot move this
    /// one. Resuming clears NO outcomes: the devices that failed
    /// stay failed in the record; the ring re-enters InProgress
    /// for its outstanding devices only.</summary>
    public (bool Ok, string Reason) ResumeHalted(string ringName, ApprovalDecisionRecord resumeDecision)
    {
        lock (_gate)
        {
            var ring = Rings.FirstOrDefault(r => string.Equals(r.Name, ringName, StringComparison.OrdinalIgnoreCase));
            if (ring is null) return (false, $"unknown ring '{ringName}' — refused");
            if (_states[ring.Name] != RingStates.Halted)
                return (false, $"ring '{ring.Name}' is {_states[ring.Name]} — only a halted ring can be resumed");
            if (resumeDecision is null) return (false, "no resume decision presented — refused (resuming a halted ring is a new signed decision, never automatic)");
            if (resumeDecision.Decision != ApprovalDecisions.Approved)
                return (false, "the presented decision is not an approval — refused");
            var halt = _halts[ring.Name];
            var expectedBasis = $"ring_resume:{Id}:{ring.Name}:{halt.EvidenceHash}";
            if (!string.Equals(resumeDecision.Basis, expectedBasis, StringComparison.Ordinal))
                return (false, "the resume decision does not bind THIS halt (plan/ring/evidence mismatch) — refused (a decision made against different evidence cannot resume this halt)");
            if (resumeDecision.EntryId != EntryId || resumeDecision.EntryContentHash != EntryContentHash)
                return (false, "the resume decision names different patch content than this plan deploys — refused");
            var outcomes = _outcomes[ring.Name];
            _halts.Remove(ring.Name);
            // D38 F11(b): if every device has already reported,
            // there is no outstanding cohort to judge — the signed
            // decision itself completes the ring (the decider has
            // seen the full evidence in the halt record). Otherwise
            // the ring re-enters InProgress and its threshold is
            // judged on the post-resume cohort (see RecordOutcome).
            if (outcomes.Count == ring.DeviceIds.Count)
            {
                _states[ring.Name] = RingStates.Complete;
                return (true, $"ring '{ring.Name}' resumed by decision of {resumeDecision.DecidedBy} against halt evidence {halt.EvidenceHash[..12]}… — every device had already reported, so the signed decision completes the ring; recorded outcomes stand");
            }
            _resumeBaseline[ring.Name] = (outcomes.Count, outcomes.Values.Count(v => v));
            _states[ring.Name] = RingStates.InProgress;
            return (true, $"ring '{ring.Name}' resumed by decision of {resumeDecision.DecidedBy} against halt evidence {halt.EvidenceHash[..12]}… — recorded outcomes stand; the threshold is judged on the {ring.DeviceIds.Count - outcomes.Count} outstanding device(s)");
        }
    }

    // ---- persistence (D38 F3) -------------------------------------
    // A plan's states, outcomes, halts and resume baselines are
    // deployment evidence: a halt that evaporates on restart is a
    // halt that never happened. The Core service persists this DTO
    // beside the journal and restores it at construction.

    public sealed record RingStateDto(string Name, string State,
        List<KeyValuePair<string, bool>> Outcomes, RingHaltEvidence? Halt,
        int ResumeBaselineCount, int ResumeBaselineSucceeded);

    public sealed record Dto(string Id, string EntryId, string EntryContentHash,
        List<RingDefinition> Rings, List<RingStateDto> RingStates);

    public Dto Export()
    {
        lock (_gate)
        {
            var states = Rings.Select(r =>
            {
                var (bc, bs) = _resumeBaseline.GetValueOrDefault(r.Name, (0, 0));
                return new RingStateDto(r.Name, _states[r.Name],
                    _outcomes[r.Name].ToList(),
                    _halts.TryGetValue(r.Name, out var h) ? h : null, bc, bs);
            }).ToList();
            return new Dto(Id, EntryId, EntryContentHash, Rings.ToList(), states);
        }
    }

    public static RolloutPlan Restore(Dto dto)
    {
        var plan = new RolloutPlan(dto.Id, dto.EntryId, dto.EntryContentHash, dto.Rings);
        lock (plan._gate)
        {
            foreach (var rs in dto.RingStates)
            {
                var ring = plan.Rings.FirstOrDefault(r => string.Equals(r.Name, rs.Name, StringComparison.OrdinalIgnoreCase))
                    ?? throw new ArgumentException($"persisted plan '{dto.Id}' carries state for unknown ring '{rs.Name}' — refused (corrupt plan state is not silently dropped)");
                if (!RingStates.All.Contains(rs.State))
                    throw new ArgumentException($"persisted plan '{dto.Id}' ring '{rs.Name}' carries unknown state '{rs.State}' — refused");
                plan._states[ring.Name] = rs.State;
                foreach (var (device, success) in rs.Outcomes) plan._outcomes[ring.Name][device] = success;
                if (rs.Halt is not null) plan._halts[ring.Name] = rs.Halt;
                if (rs.ResumeBaselineCount > 0) plan._resumeBaseline[ring.Name] = (rs.ResumeBaselineCount, rs.ResumeBaselineSucceeded);
            }
        }
        return plan;
    }
}

/// <summary>The rollout-plan store: plans are looked up by id and
/// by (entry, device) for the deploy-time ring gate.</summary>
public sealed class RolloutPlanStore
{
    private readonly Dictionary<string, RolloutPlan> _plans = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public (bool Ok, string Reason) Add(RolloutPlan plan)
    {
        if (plan is null) return (false, "no plan — refused");
        lock (_gate)
        {
            if (_plans.ContainsKey(plan.Id)) return (false, $"rollout plan '{plan.Id}' already exists — refused (plans are not silently replaced)");
            _plans[plan.Id] = plan;
            return (true, $"rollout plan '{plan.Id}' registered for entry '{plan.EntryId}' with {plan.Rings.Count} ring(s)");
        }
    }

    public RolloutPlan? Get(string? planId)
    {
        lock (_gate) return planId is not null && _plans.TryGetValue(planId, out var p) ? p : null;
    }

    /// <summary>Every plan for an entry that includes this device —
    /// the deploy gate consults these: if ANY plan covers the
    /// device for this patch, the device's ring in that plan must
    /// be InProgress for a deployment to proceed.</summary>
    public IReadOnlyList<RolloutPlan> PlansFor(string entryId, string entryContentHash, string deviceId)
    {
        lock (_gate)
            return _plans.Values.Where(p => p.EntryId == entryId && p.EntryContentHash == entryContentHash
                && p.RingOf(deviceId) is not null).ToList();
    }

    /// <summary>D38 F4: plans for the same ENTRY (any content
    /// revision) in which this device sits in a HALTED ring. The
    /// deploy gate consults these separately from PlansFor: a halt
    /// is a decision about a DEVICE cohort's observed failures,
    /// and re-hashing the content (a cosmetic catalogue edit, a
    /// re-pin) must not launder it away — the device stays gated
    /// until the halted plan is resumed by its own signed decision
    /// or the plan's halt is otherwise discharged. Without this,
    /// PlansFor's current-hash match made every halt optional.</summary>
    public IReadOnlyList<RolloutPlan> HaltedForEntry(string entryId, string deviceId)
    {
        lock (_gate)
            return _plans.Values.Where(p => p.EntryId == entryId
                && p.RingOf(deviceId) is { } ring
                && p.StatusOf(ring).State == RingStates.Halted).ToList();
    }

    public IReadOnlyList<RolloutPlan> All
    {
        get { lock (_gate) return _plans.Values.ToList(); }
    }
}

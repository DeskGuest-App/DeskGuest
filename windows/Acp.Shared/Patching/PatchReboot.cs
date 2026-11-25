namespace Acp.Shared.Patching;

// =====================================================================
// RMM-02 — Reboot handling (policy-driven state, modelled + gated).
//
// Reboot behaviour is part of the DEPLOYMENT PLAN, decided by
// policy before anything deploys:
//   * reboot WINDOWS: a reboot may only be enforced inside an
//     admin-defined window (days + time-of-day range, device-local
//     as carried by the evaluation instant's offset);
//   * user DEFERRALS: the person at the machine may defer a
//     pending reboot up to a policy limit; the limit is a hard
//     count, not a suggestion — deferral N+1 refuses;
//   * ENFORCED reboot for critical patches: when a patch is
//     critical (severity critical, or classification security with
//     CVSS ≥ 9) and policy arms enforcement, the reboot becomes due
//     at the earlier of (window, deferral exhaustion) and is then
//     enforced — still never silently: the decision record names
//     why (window reached / deferrals exhausted / critical
//     enforcement deadline passed).
//
// This file MODELS and GATES the decision. It executes nothing:
// the actual reboot rides the existing ACP power machinery under
// its own rules, invoked by host wiring with this decision as its
// gate. Live reboot proof is therefore PENDING by construction.
// =====================================================================

/// <summary>Reboot policy (management-policy content in
/// production). EnforcementDeadlineHours bounds how long a
/// critical patch's reboot may be pushed out in total, window or
/// no window.</summary>
public sealed record RebootPolicy(
    IReadOnlySet<DayOfWeek> WindowDays,
    TimeOnly WindowStart,
    TimeOnly WindowEnd,
    int MaxDeferrals,
    bool EnforceCritical,
    int EnforcementDeadlineHours)
{
    public bool IsInWindow(DateTimeOffset now)
    {
        if (WindowDays is null || WindowDays.Count == 0) return false;
        if (!WindowDays.Contains(now.DayOfWeek)) return false;
        var t = TimeOnly.FromTimeSpan(now.TimeOfDay);
        return WindowStart <= WindowEnd
            ? t >= WindowStart && t < WindowEnd
            : t >= WindowStart || t < WindowEnd; // overnight window
    }

    /// <summary>A conservative default: weekday nights 01:00–04:00,
    /// two deferrals, critical enforcement armed at 72 h.</summary>
    public static RebootPolicy Default { get; } = new(
        new HashSet<DayOfWeek> { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday },
        new TimeOnly(1, 0), new TimeOnly(4, 0),
        MaxDeferrals: 2, EnforceCritical: true, EnforcementDeadlineHours: 72);
}

public static class RebootStates
{
    public const string NotRequired = "not_required";
    public const string PendingWindow = "pending_window";       // due, waiting for the window
    public const string DueInWindow = "due_in_window";           // may reboot now, inside window
    public const string Deferred = "deferred";                   // user deferred, count < limit
    public const string Enforced = "enforced";                   // reboot now, reason named
}

/// <summary>The gate's verdict for one pending reboot.</summary>
public sealed record RebootDecision(string State, bool RebootPermittedNow, string Reason);

public static class RebootGate
{
    public static bool IsCritical(PatchCatalogueEntry entry) =>
        entry.Severity == PatchSeverities.Critical ||
        (entry.Classification == PatchClassifications.Security && entry.CvssScore is >= 9.0);

    /// <summary>Decide the state of a pending reboot.
    /// <paramref name="patchAppliedUtc"/> anchors the enforcement
    /// deadline; <paramref name="deferralsUsed"/> is the recorded
    /// deferral count (the caller persists it; this gate never
    /// trusts a count it cannot see exceeded — a count at/over the
    /// limit enforces).</summary>
    public static RebootDecision Evaluate(PatchCatalogueEntry entry, RebootPolicy policy,
        DateTimeOffset patchAppliedUtc, int deferralsUsed, DateTimeOffset now)
    {
        if (!entry.RequiresReboot)
            return new RebootDecision(RebootStates.NotRequired, false, "this patch does not require a reboot");
        var critical = IsCritical(entry);
        if (deferralsUsed > policy.MaxDeferrals)
            deferralsUsed = policy.MaxDeferrals; // counts beyond the limit read as the limit (defensive; RecordDeferral refuses them first)
        var deadlinePassed = critical && policy.EnforceCritical &&
            now >= patchAppliedUtc.AddHours(Math.Max(1, policy.EnforcementDeadlineHours));
        if (deadlinePassed)
            return new RebootDecision(RebootStates.Enforced, true,
                $"critical-patch enforcement deadline passed ({policy.EnforcementDeadlineHours}h since apply) — reboot is enforced now, window or no window");
        if (policy.IsInWindow(now))
            return new RebootDecision(RebootStates.DueInWindow, true,
                deferralsUsed >= policy.MaxDeferrals
                    ? $"inside the reboot window and user deferrals are exhausted ({deferralsUsed}/{policy.MaxDeferrals}) — reboot permitted now, no further deferral"
                    : "inside the reboot window — reboot permitted now");
        if (deferralsUsed >= policy.MaxDeferrals)
            return new RebootDecision(RebootStates.Enforced, false,
                $"user deferrals exhausted ({deferralsUsed}/{policy.MaxDeferrals}) — the reboot WILL be enforced at the next window; outside the window it is not permitted now (only a passed critical enforcement deadline enforces outside a window)");
        if (deferralsUsed > 0)
            return new RebootDecision(RebootStates.Deferred, false,
                $"deferred by the user ({deferralsUsed}/{policy.MaxDeferrals} used); next window enforces if deferrals run out");
        return new RebootDecision(RebootStates.PendingWindow, false,
            "reboot pending the next policy window (outside window, deferrals remain)");
    }

    /// <summary>May the user defer once more? The limit is hard:
    /// at the limit the answer is no, for every patch class —
    /// "defer forever" is the abuse this gate exists to refuse.</summary>
    public static (bool Allowed, string Reason) CanDefer(RebootPolicy policy, int deferralsUsed)
    {
        if (deferralsUsed < 0) return (false, "a negative deferral count is not a state this gate recognises — refused");
        if (deferralsUsed >= policy.MaxDeferrals)
            return (false, $"deferral limit reached ({deferralsUsed}/{policy.MaxDeferrals}) — no further deferral is permitted");
        return (true, $"deferral permitted ({deferralsUsed + 1}/{policy.MaxDeferrals})");
    }
}

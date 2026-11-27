using DeskGuest.Shared.BrowserPolicy;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-23 (item 2) — BrowserPolicyService: the Core wiring for
// browser hardening policy.
//
// Flow: collectors report extension inventory (facts) → the store
// keeps the current snapshot per (device, browser) → policy
// resolves from RMM-07 Effective Policy for the device → the pure
// evaluator decides every extension → the enforcement plan goes
// to the applier seam (OS/browser policy mechanism, host wiring).
//
// BOUNDARY: this service has NO history surface. Nothing here
// reads, stores or reports browsing history, visited URLs or visit
// times — that half of vendor "browser management" is class-(c)
// excluded (§5) and is unrepresentable in these types.
//
// Every step is policy-gated by rmm.browser_hardening.enabled —
// browser hardening's OWN toggle (D38 F9: it no longer rides the
// vendor-pass kill switch, so a vendor incident response cannot
// blind browser enforcement, and vice versa) — and ledgered:
// inventory reports (with dropped-fact refusals named),
// evaluations (per-disposition counts + resolver notes), and
// apply outcomes — including the honest NOT-applied outcome of
// the unavailable applier. Ledger joins are CAPPED (D38 F12): a
// report carrying hundreds of refusals must not mint one
// unbounded ledger entry — the first few are named and the rest
// are counted.
// =====================================================================

public sealed class BrowserPolicyService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly IBrowserPolicyApplier _applier;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly Func<DateTimeOffset> _now;

    public BrowserInventoryStore Inventory { get; } = new();

    public BrowserPolicyService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        IBrowserPolicyApplier applier,
        Func<string, IDeviceFacts?> factsByDevice,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _applier = applier ?? throw new ArgumentNullException(nameof(applier));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>D38 F12: cap a list joined into ONE ledger entry —
    /// name the first few, count the remainder.</summary>
    private static string JoinCapped(IReadOnlyList<string> items, int max = 8) =>
        items.Count <= max ? string.Join("; ", items)
            : string.Join("; ", items.Take(max)) + $"; … +{items.Count - max} more (counted, not joined)";

    private (IDeviceFacts? Facts, string Reason) Gate(string deviceId, string op)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return (null, $"no device facts for '{deviceId}' — {op} refuses (policy cannot be evaluated; fail closed)");
        if (!_policy.IsEnabled(facts, BrowserPolicyKeys.FeatureEnabled))
            return (null, $"browser hardening is disabled by policy for device '{deviceId}' ({BrowserPolicyKeys.FeatureEnabled}) — {op} refuses");
        return (facts, "ok");
    }

    /// <summary>Ingest one browser's extension inventory for a
    /// device. Dropped facts are named in the result AND the
    /// ledger — inventory that silently loses facts produces
    /// policy that silently misjudges, so losses are loud.</summary>
    public (int Accepted, IReadOnlyList<string> Refusals) ReportInventory(
        string deviceId, string browser, IEnumerable<BrowserExtensionFact> facts, string reportedBy)
    {
        var now = _now();
        var (deviceFacts, reason) = Gate(deviceId, "inventory report");
        if (deviceFacts is null)
        {
            _audit.Append("browser_inventory_refused", reportedBy ?? "browser-policy-service",
                $"device={deviceId} browser={browser} reason={reason}", now);
            return (0, new[] { reason });
        }
        var (accepted, refusals) = Inventory.Report(deviceId, browser, facts, now);
        _audit.Append("browser_inventory_reported", reportedBy ?? "browser-policy-service",
            $"device={deviceId} browser={browser} accepted={accepted} dropped={refusals.Count}" +
            (refusals.Count > 0 ? $" refusals=[{JoinCapped(refusals)}]" : ""), now);
        return (accepted, refusals);
    }

    /// <summary>Resolve policy + evaluate the device's current
    /// inventory. Returns null (with the refusal reason) when the
    /// feature is policy-off or facts do not resolve.</summary>
    public (IReadOnlyList<ExtensionDecision>? Decisions, ResolvedBrowserPolicy? Policy, string Reason) EvaluateDevice(string deviceId)
    {
        var (facts, reason) = Gate(deviceId, "evaluation");
        if (facts is null) return (null, null, reason);
        var resolved = BrowserPolicyResolver.Resolve(_policy, facts);
        var decisions = BrowserPolicyEvaluator.EvaluateAll(Inventory.FactsFor(deviceId), resolved);
        return (decisions, resolved, $"evaluated {decisions.Count} extension(s) for device '{deviceId}' under mode {resolved.Mode}");
    }

    /// <summary>Evaluate and hand the enforcement plan to the
    /// applier seam. The apply outcome is returned and ledgered
    /// EXACTLY as the applier reports it — a computed plan is never
    /// reported as enforced.</summary>
    public (BrowserApplyResult? Result, string Reason) EvaluateAndApply(string deviceId, string actor)
    {
        var now = _now();
        var (decisions, resolved, reason) = EvaluateDevice(deviceId);
        if (decisions is null || resolved is null)
        {
            _audit.Append("browser_policy_apply_refused", actor ?? "browser-policy-service",
                $"device={deviceId} reason={reason}", now);
            return (null, reason);
        }
        var plan = new BrowserEnforcementPlan(deviceId, decisions, resolved.Settings, now);
        var result = _applier.Apply(plan);
        var counts = decisions.GroupBy(d => d.Disposition)
            .Select(g => $"{g.Key}={g.Count()}").OrderBy(x => x, StringComparer.Ordinal);
        _audit.Append(result.Applied ? "browser_policy_applied" : "browser_policy_not_applied",
            actor ?? "browser-policy-service",
            $"device={deviceId} mode={resolved.Mode} decisions=[{string.Join(",", counts)}] settings={resolved.Settings.Count} notes=[{JoinCapped(resolved.Notes.ToList())}] applier={result.Detail}", now);
        return (result, result.Applied
            ? $"browser policy applied to device '{deviceId}': {result.Detail}"
            : $"browser policy for device '{deviceId}' was computed but NOT applied: {result.Detail}");
    }
}

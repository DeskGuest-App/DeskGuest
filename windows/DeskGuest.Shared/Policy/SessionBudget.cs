using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Shared.Policy;

// =====================================================================
// U4 — Per-session agent budgets + tripwires (UNION BUILD lane U4).
//
// Until this lane, the only volume limit in DeskGuest was PolicyEngine's
// global 240 calls/minute PER PAIRING — not per session, not per
// class, not policy-settable — and the SCAM sensitive-context pause
// (ScamFriction.SensitiveContextPauses) was an unwired model: nothing
// at the MCP choke point consulted it, so it paused no live session.
//
// This file is the budget layer:
//   * caps per ACTION CLASS, counted per SESSION (keyed by session
//     id; a new session starts from zero — budgets never leak across
//     sessions);
//   * caps are TOTAL POLICY CONTROL settings (RMM-07 pattern): the
//     feature toggle is registered in FeatureToggleRegistry
//     ("rmm.session_budget.enabled", default ON) and each cap is a
//     plain settings key ("session_budget.cap.<class>") an admitted
//     management-policy document may set; unset keys fall back to
//     the named defaults below;
//   * verdicts are Allow / Deny / TripPause. A cap breach is a
//     TRIPWIRE: the choke point pauses the session (presence-visible
//     reason + audit entry) — the session never silently continues,
//     and it is never hard-killed by a budget: pause is a state the
//     owner clears, not an ending.
//   * the SCAM sensitive-context verdict is computed here from the
//     foreground feed and consulted at the same choke point.
//
// Egress is counted WHERE MEASURABLE: calls in the egress class are
// counted pre-execution, and the byte size of what a successful
// egress-class call actually returned is counted post-execution by
// the choke point. A byte-cap breach discovered post-execution trips
// the pause for everything that follows (the call that crossed has
// already returned its payload — the audit entry says exactly that).
// =====================================================================

/// <summary>The budget action classes. Every counted call counts
/// toward Total; a call additionally counts toward each class its
/// tool belongs to.</summary>
public static class BudgetClasses
{
    public const string Total = "total";
    public const string Input = "input";
    public const string Deletions = "deletions";
    public const string Sending = "sending";
    public const string EgressCalls = "egress_calls";
    public const string EgressBytes = "egress_bytes";

    public static readonly IReadOnlyList<string> All =
        new[] { Total, Input, Deletions, Sending, EgressCalls, EgressBytes };
}

/// <summary>Per-class caps for one session. A cap of 0 means the
/// class is forbidden outright in-session (the first such call
/// trips); caps are counts, except EgressBytes which is bytes.</summary>
public sealed record SessionBudgetCaps(
    long Total = SessionBudgetCaps.DefaultTotal,
    long Input = SessionBudgetCaps.DefaultInput,
    long Deletions = SessionBudgetCaps.DefaultDeletions,
    long Sending = SessionBudgetCaps.DefaultSending,
    long EgressCalls = SessionBudgetCaps.DefaultEgressCalls,
    long EgressBytes = SessionBudgetCaps.DefaultEgressBytes)
{
    // Named sane defaults: generous for real work, finite so a
    // runaway or hostile agent meets a wall inside one session.
    public const long DefaultTotal = 1000;
    public const long DefaultInput = 600;
    public const long DefaultDeletions = 25;
    public const long DefaultSending = 20;
    public const long DefaultEgressCalls = 200;
    public const long DefaultEgressBytes = 256L * 1024 * 1024; // 256 MiB

    /// <summary>The TOTAL POLICY CONTROL settings key carrying this
    /// class's cap in a management-policy document.</summary>
    public static string PolicyKeyFor(string budgetClass) => $"session_budget.cap.{budgetClass}";

    public long CapFor(string budgetClass) => budgetClass switch
    {
        BudgetClasses.Total => Total,
        BudgetClasses.Input => Input,
        BudgetClasses.Deletions => Deletions,
        BudgetClasses.Sending => Sending,
        BudgetClasses.EgressCalls => EgressCalls,
        BudgetClasses.EgressBytes => EgressBytes,
        _ => long.MaxValue, // an unknown class is never capped by accident
    };

    public SessionBudgetCaps With(string budgetClass, long value) => budgetClass switch
    {
        BudgetClasses.Total => this with { Total = value },
        BudgetClasses.Input => this with { Input = value },
        BudgetClasses.Deletions => this with { Deletions = value },
        BudgetClasses.Sending => this with { Sending = value },
        BudgetClasses.EgressCalls => this with { EgressCalls = value },
        BudgetClasses.EgressBytes => this with { EgressBytes = value },
        _ => this,
    };

    /// <summary>Resolve caps from an Effective Policy: each
    /// "session_budget.cap.&lt;class&gt;" setting overrides the named
    /// default. An unparsable or negative value is IGNORED (the
    /// default stands) — a malformed policy value must neither
    /// disable a budget nor zero it by accident.</summary>
    public static SessionBudgetCaps FromEffective(EffectivePolicy? effective)
    {
        var caps = new SessionBudgetCaps();
        if (effective is null) return caps;
        foreach (var cls in BudgetClasses.All)
        {
            var setting = effective.Get(PolicyKeyFor(cls));
            if (setting is not null && long.TryParse(setting.Value, out var v) && v >= 0)
                caps = caps.With(cls, v);
        }
        return caps;
    }
}

/// <summary>How a tool call classifies for budget counting.</summary>
public static class BudgetClassifier
{
    // Drive-plane input acts (synthetic input into the owner's
    // desktop). batch_actions is input-class too: it is an ordered
    // run of desktop steps through the same channel.
    private static readonly IReadOnlySet<string> InputTools = new HashSet<string>(StringComparer.Ordinal)
    {
        "click", "double_click", "type_text", "key_press", "shortcut", "scroll", "mouse_move",
        "drag", "multi_select", "multi_edit", "input_primitives", "uia_pattern_action",
        "window_state", "ui_menu_dialog", "batch_actions",
    };

    private static readonly IReadOnlySet<string> DeletionTools = new HashSet<string>(StringComparer.Ordinal)
    {
        "file_delete", "registry_delete",
    };

    // Calls whose RESULT carries host data out to the agent — the
    // measurable egress surface at the MCP choke point.
    private static readonly IReadOnlySet<string> EgressTools = new HashSet<string>(StringComparer.Ordinal)
    {
        "file_read", "clipboard_get", "screenshot", "screenshot_region", "screenshot_annotated",
        "ocr_text", "diagnostics_bundle", "audit_log_read", "event_log_read", "scrape", "snapshot",
    };

    /// <summary>The classes one call counts toward (always Total).
    /// Gate-classed tools classify by their gate class first — the
    /// gate class is the descriptor's own declaration of what the
    /// tool DOES (deletions, sending, payments…).</summary>
    public static IReadOnlyList<string> ClassesFor(ToolDescriptor tool)
    {
        var classes = new List<string> { BudgetClasses.Total };
        if (tool.GateClass == BudgetClasses.Deletions || DeletionTools.Contains(tool.Name))
            classes.Add(BudgetClasses.Deletions);
        if (tool.GateClass == BudgetClasses.Sending)
            classes.Add(BudgetClasses.Sending);
        if (InputTools.Contains(tool.Name))
            classes.Add(BudgetClasses.Input);
        if (EgressTools.Contains(tool.Name))
            classes.Add(BudgetClasses.EgressCalls);
        return classes;
    }

    public static bool IsEgress(ToolDescriptor tool) => EgressTools.Contains(tool.Name);
}

/// <summary>Maps the foreground feed (window title + owning process,
/// the same feed PolicyEngine's protected-targets check consumes)
/// onto the SCAM sensitive-context vocabulary
/// (banking / password_field / password_manager / otp_prompt).
/// Keyword match on either field; null when nothing sensitive is
/// recognised — an unrecognised foreground never pauses.</summary>
public static class SensitiveContextClassifier
{
    private static readonly string[] PasswordManagerTerms =
        { "1password", "bitwarden", "keepass", "lastpass", "dashlane", "password manager" };
    private static readonly string[] PasswordFieldTerms =
        { "password", "passcode", "enter pin", "sign-in", "sign in" };
    private static readonly string[] OtpTerms =
        { "one-time code", "verification code", "authenticator", "two-factor", "2fa", "otp" };
    private static readonly string[] BankingTerms =
        { "bank", "banking", "chase", "wells fargo", "bank of america", "credit union",
          "fidelity", "vanguard", "schwab", "paypal", "venmo", "cash app" };

    public static string? ContextFor(string? foregroundTitle, string? foregroundProcess)
    {
        var hay = $"{foregroundTitle}\n{foregroundProcess}";
        if (hay.Trim().Length == 0) return null;
        bool Has(string[] terms) => terms.Any(t => hay.Contains(t, StringComparison.OrdinalIgnoreCase));
        if (Has(PasswordManagerTerms)) return "password_manager";
        if (Has(OtpTerms)) return "otp_prompt";
        if (Has(PasswordFieldTerms)) return "password_field";
        if (Has(BankingTerms)) return "banking";
        return null;
    }

    /// <summary>The wired SCAM verdict: the sensitive-context model
    /// (SCAM-09) consulted with the operator history DeskGuest can honestly
    /// claim. DeskGuest keeps no per-pairing earned-trust store, so NO
    /// operator is "established" here — the SCAM-15 fast path is
    /// earned only through the model's own history, and inventing one
    /// would defeat the pause. Non-established + sensitive context =
    /// pause.</summary>
    public static bool Pauses(string? foregroundTitle, string? foregroundProcess) =>
        ContextFor(foregroundTitle, foregroundProcess) is { } ctx
        && ScamFriction.SensitiveContextPauses(ctx, new OperatorHistory(0, 0, 0, null, false));
}

public enum BudgetVerdictKind { Allow, Deny, TripPause }

/// <summary>One budget decision. TripPause carries the class, the
/// count that tripped, and the cap — the numbers the pause reason
/// and the audit entry are built from.</summary>
public sealed record BudgetVerdict(BudgetVerdictKind Kind, string? Class, long Count, long Cap, string Reason)
{
    public static BudgetVerdict Allow() => new(BudgetVerdictKind.Allow, null, 0, 0, "");
    public static BudgetVerdict Deny(string reason) => new(BudgetVerdictKind.Deny, null, 0, 0, reason);
    public static BudgetVerdict Trip(string cls, long count, long cap) => new(
        BudgetVerdictKind.TripPause, cls, count, cap,
        $"budget tripwire: session cap for '{cls}' reached ({count} > {cap}) — session paused; the owner resumes it from the host");
}

/// <summary>An immutable owner-visible snapshot of one session's
/// budget state: caps, counts so far, and the pause state.</summary>
public sealed record SessionBudgetSnapshot(
    string SessionId,
    IReadOnlyDictionary<string, long> Caps,
    IReadOnlyDictionary<string, long> Counts,
    bool Paused,
    string? PauseReason);

/// <summary>Per-session budget counters. One instance serves the
/// Core; counters are keyed by session id and created fresh at
/// session start, so budgets reset per session by construction.
/// Thread-safe: every public act takes the gate.</summary>
public sealed class SessionBudget
{
    private sealed class Counters
    {
        public SessionBudgetCaps Caps = new();
        public readonly Dictionary<string, long> Counts = new(StringComparer.Ordinal);
        public bool Tripped;
        public string? TripReason;
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, Counters> _bySession = new(StringComparer.Ordinal);

    /// <summary>Start counting a session under the given caps.
    /// Re-beginning an id starts it from zero.</summary>
    public void BeginSession(string sessionId, SessionBudgetCaps caps)
    {
        lock (_gate) _bySession[sessionId] = new Counters { Caps = caps };
    }

    public void EndSession(string sessionId)
    {
        lock (_gate) _bySession.Remove(sessionId);
    }

    public bool HasSession(string sessionId)
    {
        lock (_gate) return _bySession.ContainsKey(sessionId);
    }

    /// <summary>Pre-execution check-and-count for one call. Counts
    /// the call toward each of its classes; if any class would pass
    /// its cap, the verdict is TripPause and the session is marked
    /// tripped (the choke point performs the actual pause). Once
    /// tripped, every further check Denies as paused until the
    /// session ends or the owner resumes (Resume clears the trip —
    /// counts stand, so a class still over its cap trips again on
    /// the next call of that class; the owner resumes knowing the
    /// numbers, which session_status shows).</summary>
    public BudgetVerdict CheckAndCount(string sessionId, IReadOnlyList<string> classes)
    {
        lock (_gate)
        {
            if (!_bySession.TryGetValue(sessionId, out var c))
                return BudgetVerdict.Deny($"budget: no budget counters for session '{sessionId}' — call session_start first");
            if (c.Tripped)
                return BudgetVerdict.Deny($"session_paused: {c.TripReason}");
            foreach (var cls in classes)
            {
                var next = CountOf(c, cls) + 1;
                var cap = c.Caps.CapFor(cls);
                if (next > cap)
                {
                    c.Tripped = true;
                    c.TripReason = BudgetVerdict.Trip(cls, next, cap).Reason;
                    return BudgetVerdict.Trip(cls, next, cap);
                }
            }
            foreach (var cls in classes) c.Counts[cls] = CountOf(c, cls) + 1;
            return BudgetVerdict.Allow();
        }
    }

    /// <summary>Post-execution egress accounting: add the bytes a
    /// successful egress-class call actually returned. Returns a
    /// TripPause verdict when the cumulative bytes pass the cap
    /// (the pause applies from the NEXT call; this call's payload
    /// already returned), otherwise Allow.</summary>
    public BudgetVerdict NoteEgressBytes(string sessionId, long bytes)
    {
        if (bytes <= 0) return BudgetVerdict.Allow();
        lock (_gate)
        {
            if (!_bySession.TryGetValue(sessionId, out var c) || c.Tripped) return BudgetVerdict.Allow();
            var next = CountOf(c, BudgetClasses.EgressBytes) + bytes;
            c.Counts[BudgetClasses.EgressBytes] = next;
            var cap = c.Caps.CapFor(BudgetClasses.EgressBytes);
            if (next > cap)
            {
                c.Tripped = true;
                var trip = BudgetVerdict.Trip(BudgetClasses.EgressBytes, next, cap);
                c.TripReason = trip.Reason + " (the call that crossed the byte cap had already returned its payload; the pause applies from the next call)";
                return trip with { Reason = c.TripReason };
            }
            return BudgetVerdict.Allow();
        }
    }

    /// <summary>Owner resume: clear the trip so the session may act
    /// again. Counts are NOT reset — the budget is per session, and
    /// resuming is the owner accepting the state shown, not a fresh
    /// allowance.</summary>
    public void Resume(string sessionId)
    {
        lock (_gate)
        {
            if (_bySession.TryGetValue(sessionId, out var c))
            {
                c.Tripped = false;
                c.TripReason = null;
            }
        }
    }

    public SessionBudgetSnapshot? Snapshot(string sessionId, bool paused, string? pauseReason)
    {
        lock (_gate)
        {
            if (!_bySession.TryGetValue(sessionId, out var c)) return null;
            var caps = new Dictionary<string, long>(StringComparer.Ordinal);
            var counts = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var cls in BudgetClasses.All)
            {
                caps[cls] = c.Caps.CapFor(cls);
                counts[cls] = CountOf(c, cls);
            }
            return new SessionBudgetSnapshot(sessionId, caps, counts, paused, pauseReason);
        }
    }

    private static long CountOf(Counters c, string cls) =>
        c.Counts.TryGetValue(cls, out var v) ? v : 0;
}

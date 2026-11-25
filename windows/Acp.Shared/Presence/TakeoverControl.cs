namespace Acp.Shared.Presence;

/// <summary>
/// FR-120 (W73) — the tunable-takeover BEHAVIOUR model: one pure
/// state machine both input classes feed, the session-record
/// entry vocabulary, and the actor vocabulary the record uses to
/// distinguish HOW a change arrived (Jacob's ownership rule,
/// 2026-11-23 22:49 CT: a change made at the machine outside a
/// session is the owner's local act; a change made through the
/// device UI while a session is live rode that session and is
/// recorded like any session action).
///
/// The machine knows nothing about STOP: STOP never consults a
/// mode and never passes through here — it ends the session from
/// any state, including owner-driving and SHARE, by its own path
/// (PresenceLayer.StopPressed / the STOP hotkey / the Core).
/// </summary>
public enum TakeoverInputClass { Mouse, Keyboard }

/// <summary>What a local-input signal did.</summary>
public enum TakeoverInputOutcome
{
    /// <summary>TakeOver mode: driving yielded to the owner.</summary>
    Yielded,
    /// <summary>Share mode: input observed; the agent keeps driving.</summary>
    ObservedShare,
    /// <summary>HotkeyOnly mode: input ignored for control purposes.</summary>
    IgnoredHotkeyOnly,
    /// <summary>The owner already drives; nothing changed.</summary>
    AlreadyOwnerDriving,
}

/// <summary>How a recorded takeover fact arrived (the record's
/// actor distinction, FR-120 ownership rule).</summary>
public static class TakeoverActors
{
    /// <summary>The owner at the machine, no session live.</summary>
    public const string OwnerLocal = "owner-local";
    /// <summary>Through the device's own UI while a session was
    /// live — the change rode the session (an in-session helper,
    /// or the owner at the machine mid-session; the record states
    /// the arrival path, which is what the rule distinguishes).</summary>
    public const string InSession = "in-session";
    /// <summary>The owner's own hand-back control on the Box.</summary>
    public const string OwnerHandBackControl = "owner-handback-control";
    /// <summary>Hand-back approved by the owner on the gate card
    /// after the agent asked for control back through the gate.</summary>
    public const string OwnerGateApproval = "owner-gate-approval";
    /// <summary>The person at the machine pressed the takeover chord.</summary>
    public const string OwnerHotkey = "owner-hotkey";
    /// <summary>Local input itself (content is never captured —
    /// the class only).</summary>
    public const string LocalInput = "local-input";
    /// <summary>FR-130: the presence layer's own session-boundary
    /// reconciliation — a stale owner-driving flag cleared itself
    /// at a session start. Not a person's act: the record says so.</summary>
    public const string PresenceReconciliation = "presence-reconciliation";
}

/// <summary>The session-record entry kinds for FR-120 facts.
/// These strings are the record vocabulary: the SessionService
/// event list and the Core audit chain both carry them.</summary>
public static class TakeoverRecordKinds
{
    /// <summary>Recorded at session start: the active modes.</summary>
    public const string ModesAtStart = "takeover_modes";
    /// <summary>A mid-session (or any) mode change.</summary>
    public const string ModeChanged = "takeover_mode_changed";
    /// <summary>Driving yielded to the owner.</summary>
    public const string Yield = "takeover_yield";
    /// <summary>Driving handed back to the agent.</summary>
    public const string HandBack = "takeover_handback";
    /// <summary>The takeover hotkey yielded driving.</summary>
    public const string Hotkey = "takeover_hotkey";
    /// <summary>FR-130: a stale owner-driving flag left over from
    /// an earlier session was cleared at a session boundary —
    /// the pill had latched "paused" with no takeover in the
    /// session that was actually starting.</summary>
    public const string Reconciled = "takeover_reconciled";
}

/// <summary>Canonical detail strings for takeover record entries —
/// one formatter home so the agent, the Core and the tests can
/// never drift on the record's shape. Values only ever carry mode
/// NAMES and input-class names: never input content.</summary>
public static class TakeoverRecordDetail
{
    public static string Modes(TakeoverMode mouse, TakeoverMode keyboard) =>
        $"mouse={mouse} keyboard={keyboard}";

    public static string ModeChange(TakeoverInputClass inputClass, TakeoverMode from, TakeoverMode to) =>
        $"{inputClass.ToString().ToLowerInvariant()} mode {from} -> {to}";

    public static string Yield(TakeoverInputClass inputClass) =>
        $"local {inputClass.ToString().ToLowerInvariant()} input yielded driving to the owner";

    public static string HandBack(string actor) =>
        actor == TakeoverActors.OwnerGateApproval
            ? "owner approved the agent's request for control back on the gate card"
            : "owner handed control back from the presence box";

    public static string Reconciled() =>
        "stale owner-driving state from a previous session cleared at session start; the pill follows the new session";
}

/// <summary>The FR-120 hand-back gate identity: an agent asking
/// for control back raises a per-action gate request carrying
/// this tool name; the owner's approval on the gate card is the
/// hand-back. It is a REQUEST through the existing gate — the
/// agent can never take control back by any direct path.</summary>
public static class TakeoverGate
{
    public const string HandBackTool = "takeover_handback";
    public const string HandBackGateClass = "takeover_handback";
}

/// <summary>
/// The driving-ownership state machine. One instance per live
/// session presence. Both input classes feed the SAME ownership
/// state (there is one driver at a time) but consult their OWN
/// class mode for the yield decision:
///
///  * TakeOver    — local input of that class yields.
///  * Share       — local input of that class is observed only;
///                  the agent keeps driving (the system cursor is
///                  the owner's; the ghost stays the agent's).
///  * HotkeyOnly  — local input of that class is ignored for
///                  control; the takeover chord (or STOP, which
///                  is not this machine's business) still works.
///
/// The chord yields in EVERY mode — it is the deliberate act the
/// HotkeyOnly mode waits for, and it stays live under TakeOver
/// and Share too (PresenceComposition teaches it as the takeover
/// path). Hand-back is explicit only: the owner's Box control,
/// or the owner's gate approval of the agent's request.
/// </summary>
public sealed class TakeoverStateMachine
{
    public bool OwnerDriving { get; private set; }

    /// <summary>A local-input signal of one class, decided by that
    /// class's own mode.</summary>
    public TakeoverInputOutcome LocalInput(TakeoverInputClass inputClass, TakeoverMode mouseMode, TakeoverMode keyboardMode)
    {
        if (OwnerDriving) return TakeoverInputOutcome.AlreadyOwnerDriving;
        var mode = inputClass == TakeoverInputClass.Mouse ? mouseMode : keyboardMode;
        if (TakeoverModes.LocalInputYields(mode))
        {
            OwnerDriving = true;
            return TakeoverInputOutcome.Yielded;
        }
        return mode == TakeoverMode.Share
            ? TakeoverInputOutcome.ObservedShare
            : TakeoverInputOutcome.IgnoredHotkeyOnly;
    }

    /// <summary>The takeover chord (Ctrl+Alt+Shift+Backspace):
    /// yields from any mode. True when this press changed state.</summary>
    public bool TakeoverHotkey()
    {
        if (OwnerDriving) return false;
        OwnerDriving = true;
        return true;
    }

    /// <summary>Explicit hand-back (Box control or gate approval).
    /// True when this call changed state.</summary>
    public bool HandBack()
    {
        if (!OwnerDriving) return false;
        OwnerDriving = false;
        return true;
    }

    /// <summary>Session end: ownership resets with the session.
    /// (STOP ends the session through its own path and lands
    /// here only as part of teardown — the mode never gated it.)</summary>
    public void Reset() => OwnerDriving = false;

    /// <summary>FR-130: session-boundary reconciliation. Driving
    /// ownership belongs to ONE session: a session that ends
    /// leaves none behind, and a session that starts always
    /// starts with the agent driving (the rule HideSession's
    /// reset was written for — but the live lifecycle runs
    /// through Core directives, which never called it, so a flag
    /// set in one session latched the pill "paused" through
    /// every later session while the Core reported no takeover).
    /// Returns true when a stale owner-driving flag was cleared,
    /// so the caller can record the correction.</summary>
    public bool ReconcileAtSessionBoundary()
    {
        if (!OwnerDriving) return false;
        OwnerDriving = false;
        return true;
    }
}

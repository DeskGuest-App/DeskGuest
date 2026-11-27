namespace DeskGuest.Shared.Presence;

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
    /// <summary>FR-145 (owner ruling, 2026-11-25 23:31–23:33 CT):
    /// ordinary local input was observed and the owner coexists —
    /// the agent keeps driving in EVERY mode. This is now the
    /// only outcome LocalInput can produce for a session the
    /// agent is driving: input is never a floor event.</summary>
    ObservedCoexist,
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
/// state (there is one driver at a time).
///
/// FR-145 (owner ruling, 2026-11-25 23:31–23:33 CT, restating
/// the settled 2026-11-25 13:47–14:09 floor design): input is
/// NEVER a floor event. Ordinary local input of either class —
/// physical or injected, from any process — never yields
/// driving, in ANY takeover mode: the owner pops in, moves the
/// mouse, types, and the agent carries on like normal; the
/// local pointer is permanently the owner's and the agent has
/// its own. The Give/Take mechanism is the SOLE floor
/// mechanism:
///
///  * The takeover chord yields in EVERY mode — it is the
///    deliberate Take control act (TakeoverHotkey below).
///  * Hand-back is explicit only: the owner's Box control
///    (Give control), or the owner's gate approval of the
///    agent's request.
///
/// The mode arguments to LocalInput remain in the signature as
/// record vocabulary (the session record still carries the
/// device's chosen modes); they no longer decide anything.
/// STOP is untouched: it never passes through here.
/// </summary>
public sealed class TakeoverStateMachine
{
    public bool OwnerDriving { get; private set; }

    /// <summary>A local-input signal of one class. FR-145: this
    /// NEVER yields, for any class, in any mode — the owner
    /// coexists and the agent keeps driving. The outcome is
    /// ObservedCoexist, or AlreadyOwnerDriving when a deliberate
    /// Take control (the chord) already handed the floor over.</summary>
    public TakeoverInputOutcome LocalInput(TakeoverInputClass inputClass, TakeoverMode mouseMode, TakeoverMode keyboardMode)
    {
        _ = inputClass; _ = mouseMode; _ = keyboardMode; // record vocabulary only (FR-145)
        if (OwnerDriving) return TakeoverInputOutcome.AlreadyOwnerDriving;
        return TakeoverInputOutcome.ObservedCoexist;
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

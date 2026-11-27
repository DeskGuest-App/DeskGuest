namespace DeskGuest.Shared.Presence;

/// <summary>What the presence layer should be showing, as a pure
/// function of session + STOP truth. One vocabulary shared by the
/// Core (which computes directives) and the Session Agent (which
/// renders them), so the two can never disagree about what a state
/// means (M1, 2026-11-17: the banner previously derived its state
/// from whichever IPC field happened to be populated, and the
/// blocked state had no exit at all).</summary>
public enum PresenceMode
{
    /// <summary>Nothing on screen. No session, no STOP.</summary>
    Off,
    /// <summary>Session live: glow, named banner with STOP, ghost cursor.</summary>
    Active,
    /// <summary>STOP in force: named blocked banner with working
    /// CLEAR STOP and DISMISS controls. No glow, no ghost — nothing
    /// is being controlled, and the banner must not pretend otherwise.</summary>
    Blocked,
    /// <summary>STOP still in force, but the owner dismissed the notice.
    /// The block itself is untouched (it lives in the Core); only the
    /// on-screen notice is gone. Any new STOP engagement or session
    /// transition re-surfaces state truthfully.</summary>
    BlockedDismissed,
}

/// <summary>The Core-side decision: given the session/STOP truth,
/// what presence mode should the agent be rendering?</summary>
public static class PresenceDirective
{
    public static PresenceMode Decide(bool sessionActive, bool stopInForce)
    {
        if (stopInForce) return PresenceMode.Blocked;
        if (sessionActive) return PresenceMode.Active;
        return PresenceMode.Off;
    }

    /// <summary>BD-SHARED-SESSION F8: the full session-truth input
    /// the presence layer actually renders from — recording, blank,
    /// input-block, watermark, and whether the driver is an AI —
    /// carried as typed fields, not squeezed into two bools. The
    /// two-bool Decide above remains for the mode itself; this
    /// record is what the banner text and indicators derive from.</summary>
    public sealed record Inputs(
        bool SessionActive,
        bool StopInForce,
        bool Recording = false,
        bool Blanked = false,
        bool InputBlocked = false,
        bool Watermarked = false,
        bool DriverIsAi = false,
        long StopEpoch = 0);

    public static PresenceMode Decide(Inputs inputs) => Decide(inputs.SessionActive, inputs.StopInForce);

    /// <summary>The indicator lines a renderer must show for these
    /// inputs — recording/blank/input-block/AI-driver are named on
    /// screen, never silent (SPEC §7.10: presence must say what is
    /// happening, including who/what is driving).</summary>
    public static IReadOnlyList<string> IndicatorLines(Inputs inputs)
    {
        var lines = new List<string>();
        if (inputs.Recording) lines.Add("recording");
        if (inputs.Blanked) lines.Add("screen_blanked");
        if (inputs.InputBlocked) lines.Add("input_blocked");
        if (inputs.Watermarked) lines.Add("watermarked");
        if (inputs.SessionActive && inputs.DriverIsAi) lines.Add("ai_driving");
        if (inputs.SessionActive && !inputs.DriverIsAi) lines.Add("human_driving");
        return lines;
    }
}

/// <summary>The Agent-side presence state machine. Every transition
/// is total: from any state, session end lands in a state with zero
/// presence windows unless STOP is in force, and STOP always has a
/// clear path (ClearStop) plus a notice-only dismiss. There is no
/// state in which a rendered button does nothing: the STOP button
/// exists only in Active (pressing it engages the block), and the
/// blocked banner offers CLEAR STOP and DISMISS, both wired.</summary>
public sealed class PresenceStateMachine
{
    public PresenceMode Mode { get; private set; } = PresenceMode.Off;
    public bool SessionActive { get; private set; }
    public bool StopInForce { get; private set; }
    public string? AgentName { get; private set; }

    // BD-SHARED-SESSION F8: full session truth + STOP epoch.
    public bool Recording { get; private set; }
    public bool Blanked { get; private set; }
    public bool InputBlocked { get; private set; }
    public bool Watermarked { get; private set; }
    public bool DriverIsAi { get; private set; }
    /// <summary>Monotonically increasing STOP engagement counter.
    /// A dismiss is bound to the epoch it dismissed: a NEW block
    /// (higher epoch) always re-surfaces, even across a reconnect
    /// where the boolean alone looks unchanged.</summary>
    public long StopEpoch { get; private set; }
    private long _dismissedEpoch = -1;

    /// <summary>BD-SHARED-SESSION F8: while a session is active
    /// there is ALWAYS a minimal non-dismissable indicator — the
    /// dismiss path exists only for the blocked NOTICE, never for
    /// session presence itself.</summary>
    public bool MinimalIndicatorVisible => SessionActive;

    /// <summary>True only when a SPECIFIC driver name is held.
    /// The presence law (the Box names the SPECIFIC driver) makes
    /// this the gate every session rendering must pass.</summary>
    public bool HasDriverName => !string.IsNullOrWhiteSpace(AgentName);

    /// <summary>FR-121 (W76) — the named defect state: a session is
    /// (or was) live but no specific driver name is held. This is
    /// a wiring bug, never a product state: surfaces must REFUSE /
    /// FLAG the session (the Agent's IPC path refuses an unnamed
    /// session start exactly like a failed presence self-test) and
    /// must never render presence for it under a generic name.</summary>
    public bool DriverNameMissing => SessionActive && !HasDriverName;

    /// <summary>The name the banner shows — the specific driver's
    /// name, or EMPTY when none was ever supplied. FR-121 (W76)
    /// abolished the former last-resort generic fallback ("An
    /// agent"): it was reachable (SessionStarted / ApplyDirective
    /// with a blank name on a fresh machine set SessionActive with
    /// no name, and the Box then rendered the generic form), and a
    /// generic rendering silently converts a wiring bug into a
    /// product state the presence law forbids. Callers must check
    /// <see cref="HasDriverName"/> / <see cref="DriverNameMissing"/>
    /// and take the defect path instead of rendering an empty or
    /// generic name.</summary>
    public string DisplayName => HasDriverName ? AgentName! : "";

    public void SessionStarted(string? agentName)
    {
        SessionActive = true;
        if (!string.IsNullOrWhiteSpace(agentName)) AgentName = agentName;
        Mode = StopInForce ? PresenceMode.Blocked : PresenceMode.Active;
    }

    public void SessionEnded()
    {
        SessionActive = false;
        if (!StopInForce) Mode = PresenceMode.Off;
        else if (Mode != PresenceMode.BlockedDismissed) Mode = PresenceMode.Blocked;
    }

    /// <summary>STOP engaged (banner STOP, host-window STOP, tray,
    /// panic_stop, STOP file — the Core reports them all the same
    /// way). A fresh engagement always re-surfaces the notice, even
    /// if a previous block's notice was dismissed: a new deliberate
    /// stop is new information.</summary>
    public void StopEngaged()
    {
        if (StopInForce) return;
        StopInForce = true;
        StopEpoch++;
        Mode = PresenceMode.Blocked;
    }

    /// <summary>The owner cleared STOP (banner CLEAR STOP or the host
    /// window's clear control, confirmed by the Core). The mode
    /// returns to whatever the session truth is.</summary>
    public void StopCleared()
    {
        StopInForce = false;
        Mode = SessionActive ? PresenceMode.Active : PresenceMode.Off;
    }

    /// <summary>Reconcile with a full directive from the Core (the
    /// supervisor pushes complete truth on every change and on agent
    /// reconnect, so a restarted agent converges instead of guessing).</summary>
    public void ApplyDirective(bool sessionActive, string? agentName, bool stopInForce) =>
        ApplyDirective(new PresenceDirective.Inputs(sessionActive, stopInForce, StopEpoch: StopEpoch),
            agentName);

    /// <summary>BD-SHARED-SESSION F8: reconcile with the FULL
    /// directive (recording/blank/input-block/watermark/AI-driver +
    /// stop epoch). A directive whose epoch exceeds the dismissed
    /// epoch is a new block and re-surfaces even if this machine
    /// never saw the intervening clear (the reconnect case).</summary>
    public void ApplyDirective(PresenceDirective.Inputs inputs, string? agentName = null)
    {
        if (!string.IsNullOrWhiteSpace(agentName)) AgentName = agentName;
        SessionActive = inputs.SessionActive;
        Recording = inputs.Recording;
        Blanked = inputs.Blanked;
        InputBlocked = inputs.InputBlocked;
        Watermarked = inputs.Watermarked;
        DriverIsAi = inputs.DriverIsAi;
        var wasInForce = StopInForce;
        if (inputs.StopInForce && !wasInForce) StopEpoch = Math.Max(StopEpoch + 1, inputs.StopEpoch);
        else if (inputs.StopEpoch > StopEpoch) StopEpoch = inputs.StopEpoch;
        StopInForce = inputs.StopInForce;
        var sameBlockDismissed = Mode == PresenceMode.BlockedDismissed && _dismissedEpoch == StopEpoch;
        Mode = PresenceDirective.Decide(inputs) switch
        {
            PresenceMode.Blocked when wasInForce && sameBlockDismissed
                => PresenceMode.BlockedDismissed,
            PresenceMode.Blocked when !wasInForce && _dismissedEpoch == StopEpoch && StopEpoch > 0
                => PresenceMode.BlockedDismissed,
            var m => m,
        };
        // A block re-engaged under a NEW epoch never stays dismissed:
        if (Mode == PresenceMode.BlockedDismissed && _dismissedEpoch != StopEpoch && StopInForce)
            Mode = PresenceMode.Blocked;
    }

    /// <summary>Dismiss the blocked notice. Valid only in Blocked;
    /// anywhere else it is a no-op returning false, so a dismiss
    /// control can never exist in a state where it does nothing —
    /// the renderer only shows it in Blocked.</summary>
    public bool Dismiss()
    {
        if (Mode != PresenceMode.Blocked) return false;
        // BD-SHARED-SESSION F8: dismiss is refused while a session is
        // ACTIVE — DISMISS may hide the blocked notice only; it can
        // never remove every on-screen indicator from a live session
        // (MinimalIndicatorVisible stays true regardless).
        if (SessionActive) return false;
        _dismissedEpoch = StopEpoch;
        Mode = PresenceMode.BlockedDismissed;
        return true;
    }
}

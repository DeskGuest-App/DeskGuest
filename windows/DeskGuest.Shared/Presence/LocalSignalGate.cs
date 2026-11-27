namespace DeskGuest.Shared.Presence;

/// <summary>
/// FR-141 — the local-input watcher's yield decision for one
/// poll, kept pure so it is harness-pinned: given what the poll
/// observed, should the signal yield driving to the owner?
///
/// FR-145 SCOPE (owner ruling, 2026-11-25 23:31–23:33 CT):
/// ordinary local input is never a floor event, so this gate's
/// ONLY remaining use is the takeover-CHORD decision — the one
/// deliberate Take control act. The watcher's ordinary
/// mouse/keyboard signals no longer pass through here at all
/// (they are consumed as baseline evidence and never signalled;
/// see LocalInputWatcher). The gate's semantics are unchanged
/// from FR-141; only its call sites narrowed.
///
/// The inputs:
///   * physicalPending — the watcher's low-level hooks saw at
///     least one NON-INJECTED event of this class since the last
///     poll. A low-level hook event carries the one fact the
///     pollable state can never provide: whether the event was
///     synthesised (LLKHF_INJECTED / LLMHF_INJECTED) or came
///     from a real device. A physically pressed chord is the
///     owner's deliberate act; it is NEVER suppressed, not even
///     mid-operation.
///   * signalObserved — the poll's classified signal (for the
///     chord: the chord's own edge from the keyboard sample).
///   * selfCovered — the evidence falls inside the agent's own
///     injection window (SelfInputWindow: an open operation, or
///     the tail after the last noted send). Evidence the agent's
///     own injection explains is suppressed — the agent must not
///     take control from itself by synthesising the chord.
///
/// The rule: physical evidence yields on its own evidence
/// alone; classified evidence yields unless the agent's own
/// injection window covers it. A chord injected by OTHER
/// processes (the bridge) sets neither physicalPending nor
/// selfCovered, so it yields exactly as it did before FR-141.
/// </summary>
public static class LocalSignalGate
{
    public static bool ShouldYield(bool physicalPending, bool signalObserved, bool selfCovered) =>
        physicalPending || (signalObserved && !selfCovered);
}

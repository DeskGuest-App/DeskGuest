namespace Acp.Shared.Presence;

/// <summary>
/// FR-141 — the local-input watcher's yield decision for one
/// poll, kept pure so it is harness-pinned: given what the poll
/// observed, should the class signal yield driving to the owner?
///
/// The inputs:
///   * physicalPending — the watcher's low-level hooks saw at
///     least one NON-INJECTED event of this class since the last
///     poll. A low-level hook event carries the one fact the
///     pollable state can never provide: whether the event was
///     synthesised (LLKHF_INJECTED / LLMHF_INJECTED) or came
///     from a real device. Physical input is the owner's hand;
///     it is NEVER suppressed, not even mid-operation — the
///     FR-141 fix must not weaken real owner take-over, so a
///     genuine keystroke during the agent's own typing still
///     yields immediately.
///   * signalObserved — the poll's classified signal (the
///     GetAsyncKeyState / cursor evidence through
///     LocalInputClassification's latches).
///   * selfCovered — the evidence falls inside the agent's own
///     injection window (SelfInputWindow: an open operation, or
///     the tail after the last noted send). Evidence the agent's
///     own injection explains is suppressed — the agent must not
///     yield driving to itself.
///
/// The rule: physical input yields on its own evidence alone;
/// classified evidence yields unless the agent's own injection
/// window covers it. Input injected by OTHER processes (the
/// bridge) sets neither physicalPending nor selfCovered, so it
/// yields exactly as it did before FR-141 — the W73 by-design
/// behaviour is preserved.
/// </summary>
public static class LocalSignalGate
{
    public static bool ShouldYield(bool physicalPending, bool signalObserved, bool selfCovered) =>
        physicalPending || (signalObserved && !selfCovered);
}

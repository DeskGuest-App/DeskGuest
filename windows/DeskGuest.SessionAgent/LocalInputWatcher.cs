using DeskGuest.Shared.Input;
using DeskGuest.Shared.Presence;

namespace DeskGuest.SessionAgent;

/// <summary>
/// FR-145 (owner ruling, 2026-11-25 23:31–23:33 CT) — input is
/// NEVER a floor event. This watcher no longer signals ordinary
/// local input as a takeover at all: mouse movement, clicks,
/// wheel and keyboard input — physical or injected, from any
/// process — are consumed as baseline evidence only, and the
/// agent carries on while the owner pops in and out. The ONE
/// signal this watcher still raises is the takeover chord
/// (Ctrl+Alt+Shift+Backspace), the deliberate Take control act,
/// which yields in every mode through
/// PresenceLayer.TakeoverHotkeyPressed.
///
/// History (why the machinery below still exists): FR-120/W73
/// built this watcher as the touch-to-yield signal source;
/// FR-130 added the SelfInputWindow distinction for the agent's
/// own injections; FR-141 added operation-scope coverage and
/// the hooks' physical-vs-injected evidence after sustained
/// agent typing yielded to itself mid-operation. FR-145
/// removes the defect class at the root — ordinary input
/// cannot yield, so there is nothing left for self-input to
/// falsely trigger — and the evidence machinery is retained
/// for the one decision that still needs it: the chord must
/// NOT be triggerable by the agent's own injected input, so
/// the chord decision keeps its SelfInputWindow coverage and
/// the hooks' physical evidence (LocalSignalGate).
///
/// What a poll still does, every 60 ms while a session is live:
///   * samples the keyboard ONCE (KeyboardState) — the sample
///     consumes pressed-since bits and advances baselines, and
///     derives the chord from the same sample's down bits;
///   * on the chord's rising edge, decides through
///     LocalSignalGate (physical chord evidence is never
///     suppressed; evidence inside the agent's own injection
///     window is) and raises TakeoverHotkeyPressed on a pass;
///   * runs the mouse/keyboard classifiers through their edge
///     latches and consumes the wheel count, cursor position,
///     last-input tick and hook pending flags — baselining
///     only, so no evidence is ever replayed as a fresh signal
///     and the classification pins (W107/W111/W113) keep
///     exercising the real path.
///
/// The watcher reports SIGNALS, never content: no key identity
/// leaves this class (the chord is a fixed, published constant,
/// PresenceComposition.TakeoverChordText), no cursor path is
/// recorded.
///
/// DEVICE-PROOF CLASS: the physical-chord half of this (a real
/// hand pressing the chord at the laptop) can only be proven
/// with a person at the laptop; the state machine it feeds is
/// harness-proven, and this class's classification logic is
/// harness-pinned in DeskGuest.Shared (LocalInputClassification).
/// </summary>
public sealed class LocalInputWatcher : IDisposable
{
    private readonly PresenceLayer _presence;
    private CancellationTokenSource? _cts;
    private uint _lastInputTick;
    private int _lastCursorX, _lastCursorY;
    private bool _chordWasDown;
    private readonly LocalInputClassification.MouseButtonLatch _buttonLatch = new();
    private readonly LocalInputClassification.KeyboardLatch _keyboardLatch = new();
    // W107: wheel pulses counted by the hook thread, consumed by
    // the poll. A count (not a flag) so a pulse arriving mid-poll
    // is never lost between read and reset.
    private int _wheelPulses;
    // FR-141: physical (non-injected) input observed by the
    // low-level hooks, as sticky pending flags consumed by the
    // poll. A flag, not a count: the poll needs to know only
    // THAT the owner's hand moved, and one pending gesture must
    // survive until a poll acts on it (LocalSignalGate).
    // FR-145: only the KEYBOARD flag still decides anything —
    // it is the chord gate's physical evidence; the mouse flag
    // is consumed for baselining only.
    private int _physKeyPending;
    private int _physMousePending;
    private Thread? _hookThread;
    private IntPtr _hookHandle;
    private IntPtr _keyboardHookHandle;
    private uint _hookThreadId;
    private NativeMethods.LowLevelMouseProc? _hookProc; // rooted: the GC must not collect the callback
    private NativeMethods.LowLevelKeyboardProc? _keyboardHookProc; // rooted, same reason

    public LocalInputWatcher(PresenceLayer presence) => _presence = presence;

    public bool Running => _cts is not null;

    public void Start()
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();
        // Baseline at start: input that predates the session is
        // not a takeover signal.
        _lastInputTick = LastInputTick();
        if (NativeMethods.GetCursorPos(out var pos)) { _lastCursorX = pos.X; _lastCursorY = pos.Y; }
        // Baseline the input state: this sample clears any
        // pressed-since bits accumulated before the session and
        // records the chord's starting state, so pre-session
        // input is never signalled as a takeover.
        var baseline = KeyboardState();
        _chordWasDown = baseline.ChordDown;
        _ = MouseButtonState();
        // FR-141: physical input observed before the session is
        // not a takeover signal either.
        Interlocked.Exchange(ref _physKeyPending, 0);
        Interlocked.Exchange(ref _physMousePending, 0);
        StartHooks();
        _ = Task.Run(() => PollAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        StopHooks();
    }

    // ---- W107 + FR-141: the low-level hooks (best-effort) ----
    // A dedicated thread installs the hooks and pumps messages
    // (the hook contract requires a message loop). The mouse
    // hook carries the wheel (W107: no pollable state exists)
    // and, since FR-141, the physical-vs-injected distinction
    // for BOTH classes: a hook event's flags mark synthesised
    // events (any process's SendInput, SetCursorPos) as injected
    // and leave real device input unmarked — the one place that
    // fact exists. Physical events set the pending flags the
    // poll's gate (LocalSignalGate) never suppresses.
    // If a hook cannot be installed, the rest of the watcher
    // still works — that class simply falls back to the pre-fix
    // evidence (pollable state + the self-input window), never a
    // watcher failure.
    private void StartHooks()
    {
        try
        {
            _hookProc = (nCode, wParam, lParam) =>
            {
                try
                {
                    if (nCode >= 0)
                    {
                        if (wParam == (IntPtr)NativeMethods.WM_MOUSEWHEEL ||
                            wParam == (IntPtr)NativeMethods.WM_MOUSEHWHEEL)
                            Interlocked.Increment(ref _wheelPulses);
                        var info = System.Runtime.InteropServices.Marshal.PtrToStructure<NativeMethods.MSLLHOOKSTRUCT>(lParam);
                        if ((info.flags & NativeMethods.LLMHF_INJECTED) == 0)
                            Interlocked.Exchange(ref _physMousePending, 1);
                    }
                }
                catch { /* the hook must never throw across the boundary */ }
                return NativeMethods.CallNextHookEx(_hookHandle, nCode, wParam, lParam);
            };
            _keyboardHookProc = (nCode, wParam, lParam) =>
            {
                try
                {
                    if (nCode >= 0 && (wParam == (IntPtr)NativeMethods.WM_KEYDOWN ||
                                       wParam == (IntPtr)NativeMethods.WM_SYSKEYDOWN))
                    {
                        var info = System.Runtime.InteropServices.Marshal.PtrToStructure<NativeMethods.KBDLLHOOKSTRUCT>(lParam);
                        if ((info.flags & NativeMethods.LLKHF_INJECTED) == 0)
                            Interlocked.Exchange(ref _physKeyPending, 1);
                    }
                }
                catch { /* the hook must never throw across the boundary */ }
                return NativeMethods.CallNextHookEx(_keyboardHookHandle, nCode, wParam, lParam);
            };
            _hookThread = new Thread(() =>
            {
                try
                {
                    _hookThreadId = NativeMethods.GetCurrentThreadId();
                    try
                    {
                        _hookHandle = NativeMethods.SetWindowsHookEx(
                            NativeMethods.WH_MOUSE_LL, _hookProc!, IntPtr.Zero, 0);
                    }
                    catch { /* mouse hook is best-effort, as above */ }
                    try
                    {
                        _keyboardHookHandle = NativeMethods.SetWindowsHookEx(
                            NativeMethods.WH_KEYBOARD_LL, _keyboardHookProc!, IntPtr.Zero, 0);
                    }
                    catch { /* keyboard hook is best-effort, as above */ }
                    // Pump until WM_QUIT (StopHooks posts it).
                    while (NativeMethods.GetMessage(out _, IntPtr.Zero, 0, 0) > 0) { }
                }
                catch { /* no hook: named best-effort above */ }
                finally
                {
                    try { if (_hookHandle != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(_hookHandle); } catch { }
                    try { if (_keyboardHookHandle != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(_keyboardHookHandle); } catch { }
                    _hookHandle = IntPtr.Zero;
                    _keyboardHookHandle = IntPtr.Zero;
                }
            })
            { IsBackground = true, Name = "DeskGuestInputHooks" };
            _hookThread.Start();
        }
        catch { /* no hook thread: same best-effort rule */ }
    }

    private void StopHooks()
    {
        try
        {
            if (_hookThreadId != 0)
                NativeMethods.PostThreadMessage(_hookThreadId, NativeMethods.WM_QUIT, IntPtr.Zero, IntPtr.Zero);
        }
        catch { }
        _hookThread = null;
        _hookThreadId = 0;
    }

    private static uint LastInputTick()
    {
        var info = new NativeMethods.LASTINPUTINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.LASTINPUTINFO>() };
        return NativeMethods.GetLastInputInfo(ref info) ? info.dwTime : 0;
    }

    /// <summary>W111: the keyboard's raw state this poll,
    /// sampled ONCE across the classifier's keyboard VK set
    /// (VK_CANCEL 0x03 explicitly + the 0x08..0xFE scan range —
    /// printable + function + navigation; modifiers alone count
    /// too, a bare Ctrl press is the owner touching the
    /// keyboard). One sample serves both consumers: the chord
    /// (derived from the SAME down bits — Ctrl/Alt/Shift/Back
    /// are all in the scan range) and the class signal (down bit
    /// OR the pressed-since-last-call low bit, which is what
    /// keeps a press-and-release inside one 60 ms poll window
    /// from being lost). Sampling once matters: a separate chord
    /// probe would consume the chord keys' pressed-since bits
    /// before the class sample could see them. Mouse-button VKs
    /// (0x01..0x06) are never in this set — a click is not
    /// keyboard input (W107).</summary>
    private static (bool AnyDown, bool AnyPressedSince, bool ChordDown) KeyboardState()
    {
        var down = false;
        var pressedSince = false;
        var ctrl = false; var alt = false; var shift = false; var back = false;
        foreach (var vk in LocalInputClassification.KeyboardVirtualKeys)
        {
            var state = NativeMethods.GetAsyncKeyState(vk);
            // The pressed-since bit is read for EVERY key, down
            // or not: a sub-poll tap is already up at sample time
            // and only this bit remembers it.
            if ((state & 0x0001) != 0) pressedSince = true;
            if ((state & 0x8000) == 0) continue;
            down = true;
            if (vk == NativeMethods.VK_CONTROL) ctrl = true;
            else if (vk == NativeMethods.VK_MENU) alt = true;
            else if (vk == NativeMethods.VK_SHIFT) shift = true;
            else if (vk == NativeMethods.VK_BACK) back = true;
        }
        return (down, pressedSince, ctrl && alt && shift && back);
    }

    /// <summary>W107: the mouse buttons' raw state this poll —
    /// any currently down (0x8000), and any pressed since the
    /// previous GetAsyncKeyState call for that VK (the low-order
    /// 0x0001 bit), which is what keeps a press-and-release inside
    /// one 60 ms poll window from being lost.</summary>
    private static (bool AnyDown, bool AnyPressedSince) MouseButtonState()
    {
        var down = false;
        var pressedSince = false;
        foreach (var vk in LocalInputClassification.MouseButtonVirtualKeys)
        {
            var state = NativeMethods.GetAsyncKeyState(vk);
            if ((state & 0x8000) != 0) down = true;
            if ((state & 0x0001) != 0) pressedSince = true;
        }
        return (down, pressedSince);
    }

    private async Task PollAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(60, ct); } catch (TaskCanceledException) { return; }
            try { PollOnce(); } catch { /* a failed poll must never kill the watch */ }
        }
    }

    private void PollOnce()
    {
        // FR-141: the hooks' physical-input evidence for this
        // poll, consumed up front. A physical event is the
        // owner's own hand (the hook flags separate it from any
        // injected event). FR-145: this evidence now feeds ONLY
        // the chord decision below — ordinary input of either
        // class is never signalled, physical or not.
        var physKeys = Interlocked.Exchange(ref _physKeyPending, 0) != 0;
        var physMouse = Interlocked.Exchange(ref _physMousePending, 0) != 0;

        // W111: ONE keyboard sample per poll serves the chord
        // (see KeyboardState). Sampling runs whether or not
        // anything will be signalled: it consumes the
        // pressed-since bits and advances the baselines, so
        // evidence is never replayed as a fresh signal on a
        // later poll.
        var (keysDown, keysPressedSince, chord) = KeyboardState();

        // FR-130/FR-141: is this poll's evidence covered by the
        // agent's OWN injection window? Sampled at DECISION time,
        // after the state sample — the pre-FR-141 code sampled it
        // before the sample, so an operation opening during the
        // sample had its first keys judged against the stale
        // reading. Coverage now means an open injection operation
        // (FR-141) or the tail after the last noted send. FR-145:
        // coverage guards ONLY the chord — the agent must not
        // take control from itself by synthesising it.
        var selfCovered = SelfInputWindow.Shared.Covers(DateTime.UtcNow);

        // The chord is checked on its own edge, independent of
        // the tick: it is the deliberate Take control act and
        // yields in EVERY mode (FR-145: it is the sole input-path
        // floor event there is).
        if (chord && !_chordWasDown && LocalSignalGate.ShouldYield(physKeys, signalObserved: true, selfCovered))
            _presence.TakeoverHotkeyPressed();
        _chordWasDown = chord;
        // FR-145: the keyboard class signal is still classified
        // and latched from the sample — consuming the evidence
        // and keeping the W111/W113 latch path exercised — but
        // it is NEVER signalled to the presence layer: ordinary
        // keyboard input does not yield, in any mode, from any
        // process.
        _ = LocalInputClassification.IsKeyboardSignal(
            new LocalInputClassification.KeyboardPoll(
                AnyKeyDown: keysDown,
                AnyKeyPressedSinceLastPoll: keysPressedSince),
            _keyboardLatch);

        // Wheel pulses are consumed on every poll, tick or not:
        // the hook observed real activity; the classifier runs
        // it as mouse class below (through the same latch call)
        // for baselining only.
        var wheel = Interlocked.Exchange(ref _wheelPulses, 0) > 0;

        var tick = LastInputTick();
        var tickAdvanced = tick != _lastInputTick;
        if (tickAdvanced) _lastInputTick = tick;
        if (!tickAdvanced && !wheel && !physMouse) return;

        var mouseMoved = false;
        if (NativeMethods.GetCursorPos(out var pos))
        {
            mouseMoved = pos.X != _lastCursorX || pos.Y != _lastCursorY;
            _lastCursorX = pos.X; _lastCursorY = pos.Y;
        }
        var (buttonsDown, buttonsPressedSince) = MouseButtonState();
        // FR-145: classified + latched for baselining only —
        // never signalled (see the keyboard path above).
        _ = LocalInputClassification.IsMouseSignal(
            new LocalInputClassification.MousePoll(
                CursorMoved: mouseMoved,
                AnyButtonDown: buttonsDown,
                AnyButtonPressedSinceLastPoll: buttonsPressedSince,
                WheelActivity: wheel),
            _buttonLatch);
    }

    public void Dispose() => Stop();
}

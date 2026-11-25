using Acp.Shared.Input;
using Acp.Shared.Presence;

namespace Acp.SessionAgent;

/// <summary>
/// FR-120 (W73) — the local-input signal source touch-to-yield
/// never had: before this lane, PresenceLayer.SetOwnerDriving
/// existed with NO caller, so no local input could ever yield.
///
/// The watcher polls while a session is live and reports local
/// input signals. Its gate is GetLastInputInfo: when the tick
/// advances, input arrived in the window and the poll classifies
/// it (LocalInputClassification is the pinned classifier):
///   * the takeover chord (Ctrl+Alt+Shift+Backspace) currently
///     down → the hotkey signal (checked FIRST, on its own edge —
///     in HotkeyOnly the chord is the one keyboard act that must
///     yield);
///   * the cursor moved since the previous poll → mouse class;
///   * a mouse BUTTON state change (VK 0x01/0x02/0x04/0x05/0x06,
///     down or pressed-since-last-call bit) → mouse class, edge-
///     latched: one signal per press, a held button never
///     re-fires (W107 — pre-W107 these VKs sat below the keyboard
///     scan's floor and a stationary click was silently dropped);
///   * wheel activity (observed via a low-level mouse hook; the
///     wheel has no pollable state) → mouse class;
///   * any key down, or the pressed-since bit for any keyboard
///     VK (VK_CANCEL 0x03 explicitly, plus the 0x08..0xFE scan)
///     → keyboard class, edge-latched: one signal per press, a
///     held key never re-fires (W111 — pre-W111 this path sampled
///     instantaneous state only and a sub-poll tap was dropped).
/// Both class signals may fire for one window (a person can move
/// and type at once); the presence state machine decides each
/// class by its own mode.
///
/// HONEST LIMIT — the SendInput premise (W107, W106-verified
/// C1): this watcher does NOT claim that injected input never
/// advances the tick. W73's live record shows the windows-mcp
/// bridge's injected input DID advance this laptop's tick and
/// the watcher fired on it exactly as designed — and still
/// does: input injected by any OTHER process classifies by
/// class (mouse/keyboard) only, from the signals actually
/// available.
///
/// FR-130 amendment: the one distinction that now exists is
/// this process's OWN injections. The desktop engine notes
/// every raw send it makes in the shared SelfInputWindow
/// (Acp.Shared.Input); evidence inside that window is consumed
/// (baselines and pressed-since bits advance as usual) but
/// never signalled — the agent must not yield driving to
/// itself, and with FR-136 the engine moves the real cursor on
/// every click, so unbracketed it would yield on its own first
/// action of every session.
///
/// FR-141 amendment (battery run 6 + this lane's repro): the
/// note-and-tail window alone did not hold for SUSTAINED
/// injection — a long paced type_text yielded to itself
/// mid-operation, repeatedly, at random depths. The window now
/// also covers whole OPERATIONS (the engine brackets each
/// injection operation; coverage no longer depends on note
/// timing while one is open), coverage is sampled at decision
/// time, and the low-level hooks contribute the complementary
/// half: physical (non-injected) input of either class is
/// observed directly and is NEVER suppressed (LocalSignalGate),
/// so a genuine owner keystroke or mouse act mid-operation
/// still yields immediately. Other processes' injected input
/// (the bridge) sets neither flag and classifies exactly as
/// before.
///
/// The watcher reports SIGNALS, never content: no key identity
/// leaves this class (the chord is a fixed, published constant,
/// PresenceComposition.TakeoverChordText), no cursor path is
/// recorded. Poll cadence 60 ms — yield latency is bounded by
/// one poll plus the presence render.
///
/// DEVICE-PROOF CLASS: the physical-input half of this (a real
/// hand on a real mouse advancing the tick) can only be proven
/// with a person at the laptop; the state machine it feeds is
/// harness-proven, and this class's classification logic is
/// harness-pinned in Acp.Shared (LocalInputClassification).
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
            { IsBackground = true, Name = "AcpInputHooks" };
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
        // injected event); the gate below never suppresses it.
        var physKeys = Interlocked.Exchange(ref _physKeyPending, 0) != 0;
        var physMouse = Interlocked.Exchange(ref _physMousePending, 0) != 0;

        // W111: ONE keyboard sample per poll serves the chord and
        // the keyboard class (see KeyboardState). Sampling runs
        // whether or not anything will be signalled: it consumes
        // the pressed-since bits and advances the baselines, so
        // self-evidence is never replayed as a fresh signal on a
        // later poll.
        var (keysDown, keysPressedSince, chord) = KeyboardState();

        // FR-130/FR-141: is this poll's evidence covered by the
        // agent's OWN injection window? Sampled at DECISION time,
        // after the state sample — the pre-FR-141 code sampled it
        // before the sample, so an operation opening during the
        // sample had its first keys judged against the stale
        // reading. Coverage now means an open injection operation
        // (FR-141) or the tail after the last noted send.
        var selfCovered = SelfInputWindow.Shared.Covers(DateTime.UtcNow);

        // The chord is checked on its own edge, independent of
        // the tick: it must yield even in HotkeyOnly, where
        // ordinary keyboard input is ignored for control.
        if (chord && !_chordWasDown && LocalSignalGate.ShouldYield(physKeys, signalObserved: true, selfCovered))
            _presence.TakeoverHotkeyPressed();
        _chordWasDown = chord;
        // The keyboard signal is latched from the sample whether
        // or not the tick advanced: the pressed-since bit IS the
        // evidence of a sub-poll tap, and gating it on the tick
        // would re-drop exactly the tap W111 exists to keep. The
        // chord itself never ALSO fires the ordinary keyboard
        // signal (pre-W111 discipline).
        var keyboardSignal = LocalInputClassification.IsKeyboardSignal(
            new LocalInputClassification.KeyboardPoll(
                AnyKeyDown: keysDown,
                AnyKeyPressedSinceLastPoll: keysPressedSince),
            _keyboardLatch);
        if (!chord && LocalSignalGate.ShouldYield(physKeys, keyboardSignal, selfCovered))
            _presence.SetOwnerDrivingFromKeyboard(true);

        // Wheel pulses are consumed on every poll, tick or not:
        // the hook observed real activity; the classifier decides
        // it as mouse class below (through the same latch call —
        // a wheel pulse is its own signal, never latched away).
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
        var mouseSignal = LocalInputClassification.IsMouseSignal(
            new LocalInputClassification.MousePoll(
                CursorMoved: mouseMoved,
                AnyButtonDown: buttonsDown,
                AnyButtonPressedSinceLastPoll: buttonsPressedSince,
                WheelActivity: wheel),
            _buttonLatch);
        if (LocalSignalGate.ShouldYield(physMouse, mouseSignal, selfCovered))
            _presence.SetOwnerDriving(true);
    }

    public void Dispose() => Stop();
}

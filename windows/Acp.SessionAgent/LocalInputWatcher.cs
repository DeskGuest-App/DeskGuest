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
/// the watcher fired on it exactly as designed; the agent's own
/// SendInput path has not been separately proven either way. So
/// no injected-vs-physical distinction is made anywhere here:
/// signals are classified by class (mouse/keyboard) only, from
/// the signals actually available. A distinction, if ever
/// needed, must be built from an available signal (e.g. the
/// hook's injected flag) and proven per injection path.
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
    private Thread? _hookThread;
    private IntPtr _hookHandle;
    private uint _hookThreadId;
    private NativeMethods.LowLevelMouseProc? _hookProc; // rooted: the GC must not collect the callback

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
        StartWheelHook();
        _ = Task.Run(() => PollAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        StopWheelHook();
    }

    // ---- W107: the wheel hook (best-effort) ----
    // A dedicated thread installs WH_MOUSE_LL and pumps messages
    // (the hook contract requires a message loop). If the hook
    // cannot be installed, button + movement classification still
    // works — the wheel simply has no signal, the pre-W107 state
    // for that one input, never a watcher failure.
    private void StartWheelHook()
    {
        try
        {
            _hookProc = (nCode, wParam, lParam) =>
            {
                try
                {
                    if (nCode >= 0 && (wParam == (IntPtr)NativeMethods.WM_MOUSEWHEEL ||
                                       wParam == (IntPtr)NativeMethods.WM_MOUSEHWHEEL))
                        Interlocked.Increment(ref _wheelPulses);
                }
                catch { /* the hook must never throw across the boundary */ }
                return NativeMethods.CallNextHookEx(_hookHandle, nCode, wParam, lParam);
            };
            _hookThread = new Thread(() =>
            {
                try
                {
                    _hookThreadId = NativeMethods.GetCurrentThreadId();
                    _hookHandle = NativeMethods.SetWindowsHookEx(
                        NativeMethods.WH_MOUSE_LL, _hookProc!, IntPtr.Zero, 0);
                    // Pump until WM_QUIT (StopWheelHook posts it).
                    while (NativeMethods.GetMessage(out _, IntPtr.Zero, 0, 0) > 0) { }
                }
                catch { /* no hook: named best-effort above */ }
                finally
                {
                    try { if (_hookHandle != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(_hookHandle); } catch { }
                    _hookHandle = IntPtr.Zero;
                }
            })
            { IsBackground = true, Name = "AcpWheelHook" };
            _hookThread.Start();
        }
        catch { /* no hook thread: same best-effort rule */ }
    }

    private void StopWheelHook()
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
        // W111: ONE keyboard sample per poll serves the chord and
        // the keyboard class (see KeyboardState). The chord is
        // checked on its own edge, independent of the tick: it
        // must yield even in HotkeyOnly, where ordinary keyboard
        // input is ignored for control.
        var (keysDown, keysPressedSince, chord) = KeyboardState();
        if (chord && !_chordWasDown) _presence.TakeoverHotkeyPressed();
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
        if (keyboardSignal && !chord) _presence.SetOwnerDrivingFromKeyboard(true);

        // Wheel pulses are consumed on every poll, tick or not:
        // the hook observed real activity; the classifier decides
        // it as mouse class below (through the same latch call —
        // a wheel pulse is its own signal, never latched away).
        var wheel = Interlocked.Exchange(ref _wheelPulses, 0) > 0;

        var tick = LastInputTick();
        var tickAdvanced = tick != _lastInputTick;
        if (tickAdvanced) _lastInputTick = tick;
        if (!tickAdvanced && !wheel) return;

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
        if (mouseSignal) _presence.SetOwnerDriving(true);
    }

    public void Dispose() => Stop();
}

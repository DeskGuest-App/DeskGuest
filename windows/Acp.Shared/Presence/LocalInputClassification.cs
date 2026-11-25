namespace Acp.Shared.Presence;

/// <summary>
/// W107 (W106-verified C1) — the local-input classification the
/// takeover watcher (Acp.SessionAgent/LocalInputWatcher) applies
/// to its raw poll signals, kept here in the shared tree so the
/// classification itself is harness-pinned, not source-described.
///
/// The defect this fixes: the pre-W107 watcher fired the MOUSE
/// class only on cursor delta and the KEYBOARD class only via a
/// VK scan whose floor (0x08) sits ABOVE every mouse-button VK
/// (0x01/0x02/0x04/0x05/0x06) — so a click or wheel turn with a
/// stationary pointer produced NO signal of either class and was
/// silently dropped: under mouse-TakeOver the owner clicked and
/// the agent kept the pointer.
///
/// The classification, per poll window:
///   * cursor moved → mouse class;
///   * a mouse BUTTON state change (any of VK_LBUTTON 0x01,
///     VK_RBUTTON 0x02, VK_MBUTTON 0x04, VK_XBUTTON1 0x05,
///     VK_XBUTTON2 0x06 going down, or the pressed-since-last-call
///     bit for one of them) → mouse class, through the edge latch
///     below: ONE signal per press, however long the button is
///     held — a held button must not re-fire every poll, and a
///     click is exactly one yield event;
///   * wheel activity → mouse class (the wheel has no held state
///     to latch; each observed wheel pulse is one signal);
///   * any key down (the watcher's existing scan) → keyboard
///     class (W107). W111 (W110-C1): the keyboard class now has
///     the SAME pressed-since edge latch as the mouse class —
///     pre-W111 it sampled instantaneous key state only, so a
///     sub-poll tap was dropped exactly as the mouse tap had
///     been. VK_CANCEL (0x03, Ctrl+Break) is assigned to the
///     keyboard class explicitly: it sits below the 0x08 scan
///     floor and was previously in NEITHER class, so even a
///     held Ctrl+Break produced no signal.
/// Mouse buttons are NEVER keyboard-class input: they are not in
/// the keyboard scan's range, and this classifier is the one
/// place that decides it.
///
/// HONEST LIMIT (the SendInput premise): nothing here — and
/// nothing in the watcher — may claim that injected input never
/// advances the GetLastInputInfo tick the watcher gates on.
/// W73's own live record shows the windows-mcp bridge's injected
/// input DID advance this laptop's tick and the watcher fired on
/// it exactly as designed; whether the agent's own SendInput path
/// advances it was stated from the API contract and never
/// separately proven. This classifier therefore makes no
/// injected-vs-physical distinction: it classifies whatever the
/// poll observed. If a future lane needs that distinction, it
/// must build it from signals actually available (e.g. the
/// low-level hook's injected flag) and prove it per path — the
/// limit is named here rather than the premise asserted.
/// </summary>
public static class LocalInputClassification
{
    /// <summary>The mouse-button virtual-key codes, in the order
    /// the watcher samples them. All sit below the keyboard
    /// scan's 0x08 floor — the C1 gap.</summary>
    public static readonly int[] MouseButtonVirtualKeys = { 0x01, 0x02, 0x04, 0x05, 0x06 };

    /// <summary>One poll's raw mouse observations.</summary>
    public sealed record MousePoll(
        bool CursorMoved,
        bool AnyButtonDown,
        bool AnyButtonPressedSinceLastPoll,
        bool WheelActivity);

    /// <summary>The edge latch for mouse buttons: converts a
    /// level (button currently down / pressed-since bit set) into
    /// one signal per press. State: latched while a press has
    /// been signalled and no fully-released poll has been seen
    /// since; a poll with no button down and no pressed-since bit
    /// releases the latch, so the NEXT press signals again.</summary>
    public sealed class MouseButtonLatch
    {
        private bool _latched;

        /// <summary>Observe one poll. Returns true exactly once
        /// per press — on the first poll that sees the press —
        /// and never again until the button has been seen fully
        /// released.</summary>
        public bool Observe(bool anyButtonDown, bool anyPressedSinceLastPoll)
        {
            if (!anyButtonDown && !anyPressedSinceLastPoll)
            {
                _latched = false;
                return false;
            }
            if (_latched) return false;
            _latched = true;
            return true;
        }

        public bool Latched => _latched;
    }

    /// <summary>Does this poll carry a MOUSE-class signal?
    /// Movement, a latched button-press edge, or wheel activity —
    /// each is mouse-class local input, decided by the mouse
    /// class's own takeover mode downstream.</summary>
    public static bool IsMouseSignal(MousePoll poll, MouseButtonLatch latch) =>
        poll.CursorMoved
        || poll.WheelActivity
        || latch.Observe(poll.AnyButtonDown, poll.AnyButtonPressedSinceLastPoll);

    // ---- W111 (W110-C1): the keyboard class ----

    /// <summary>VK_CANCEL (Ctrl+Break): a keyboard event below
    /// the keyboard scan's floor, assigned to the keyboard class
    /// explicitly. It is NOT a mouse button.</summary>
    public const int VkCancel = 0x03;

    /// <summary>The keyboard scan's floor and ceiling (the
    /// watcher's long-standing range).</summary>
    public const int KeyboardScanFloor = 0x08;
    public const int KeyboardScanCeiling = 0xFE;

    /// <summary>Every virtual-key code the watcher samples for
    /// the KEYBOARD class: VK_CANCEL explicitly, then the scan
    /// range 0x08..0xFE. No mouse-button VK appears here.</summary>
    public static readonly int[] KeyboardVirtualKeys =
        new[] { VkCancel }
            .Concat(Enumerable.Range(KeyboardScanFloor, KeyboardScanCeiling - KeyboardScanFloor + 1))
            .ToArray();

    /// <summary>Is this VK keyboard-class? VK_CANCEL explicitly,
    /// plus the scan range; mouse buttons never are.</summary>
    public static bool IsKeyboardVirtualKey(int vk) =>
        vk == VkCancel || (vk >= KeyboardScanFloor && vk <= KeyboardScanCeiling);

    /// <summary>One poll's raw keyboard observations.</summary>
    public sealed record KeyboardPoll(
        bool AnyKeyDown,
        bool AnyKeyPressedSinceLastPoll);

    /// <summary>The edge latch for the keyboard class — parity
    /// with <see cref="MouseButtonLatch"/>: one signal per press,
    /// a held key never re-fires per poll, a fully-released poll
    /// re-arms, and the pressed-since bit keeps a press-and-
    /// release that happened entirely inside one poll window.
    ///
    /// W113 (the W112 held-modifier edge, DeepSeek's residual
    /// note): the latch must not be a single aggregate gate. The
    /// edge, precisely: a modifier (say Shift) is held across
    /// polls — it latched on its first poll — and while it is
    /// STILL held the owner taps another key. Under a pure
    /// aggregate latch that tap's poll reads "latched" and the
    /// tap is swallowed, even though it is a new press and its
    /// pressed-since bit is consumed by that very poll (the bit
    /// is read-to-clear), so no later poll can ever recover it.
    /// The rule that pins both halves: a pressed-since bit on a
    /// poll is ALWAYS a new press and always signals — a held
    /// key produces that bit only on the poll that first sees
    /// its press, so it cannot re-fire from this arm; and a
    /// down-only poll (no pressed-since bit) signals only on
    /// the rising edge into the latched state, so a modifier
    /// held across polls never re-fires. The chord path cannot
    /// consume the tap's bit either: the watcher derives the
    /// chord from the SAME single sample's down bits (W111),
    /// never from a second probe.</summary>
    public sealed class KeyboardLatch
    {
        private bool _latched;

        public bool Observe(bool anyKeyDown, bool anyPressedSinceLastPoll)
        {
            if (!anyKeyDown && !anyPressedSinceLastPoll)
            {
                _latched = false;
                return false;
            }
            if (anyPressedSinceLastPoll)
            {
                // A new press happened inside this poll window —
                // signal it even when another key (a held
                // modifier) already latched the class: the press
                // is a new gesture, and its bit is consumed by
                // this read, so deferring would lose it forever.
                _latched = true;
                return true;
            }
            if (_latched) return false;
            _latched = true;
            return true;
        }

        public bool Latched => _latched;
    }

    /// <summary>Does this poll carry a KEYBOARD-class signal?
    /// Exactly one per press, through the edge latch.</summary>
    public static bool IsKeyboardSignal(KeyboardPoll poll, KeyboardLatch latch) =>
        latch.Observe(poll.AnyKeyDown, poll.AnyKeyPressedSinceLastPoll);
}

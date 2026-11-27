namespace DeskGuest.Shared.Input;

/// <summary>
/// U7 link-loss fail-safe (2026-11-22): the held-input release leg.
///
/// The desktop engine injects key/button DOWN and UP as separate
/// acts (input_primitives key_down/key_up, mouse_down/mouse_up,
/// button_here down/up). If the link dies — or the session ends, or
/// STOP engages — between a down and its up, the physical key or
/// button stays down on the controlled machine: a stuck Ctrl/Shift
/// corrupts everything the person at the keyboard types next, and a
/// stuck mouse button drags whatever it touches. That is a safety
/// hazard, not a cosmetic bug, so the release built on this tracker
/// is CONSENT-FLOOR class: it is not a tool, it is not policy-gated,
/// and no setting, pairing scope, or policy verdict can disable it.
/// Every caller fires it unconditionally on its trigger.
///
/// This tracker is the mechanism; the OS send lives behind
/// <see cref="IInputReleaseSink"/> (the Session Agent's SendInput
/// path on Windows, a recording fake in tests). The tracker owns
/// only the bookkeeping: which keys/buttons are currently held, in
/// the order they went down.
///
/// BD-SUPP-HELDINPUT (Wave 7): F1 — the tracker now SEALS when
/// ReleaseAll fires. A press is recorded BEFORE its send, under the
/// same gate ReleaseAll snapshots under (PressKey/PressButton), so
/// there is no window where a key is physically down but untracked,
/// and a press that arrives after the seal is refused and answered
/// with an immediate up instead of a down. F3 — ReleaseAll reports
/// released and FAILED separately; failed items go back into the
/// tracker so a later trigger retries them, instead of being
/// reported as released and forgotten.
/// </summary>
public interface IInputReleaseSink
{
    /// <summary>Send the key-up event for one held virtual key.</summary>
    void ReleaseKey(ushort virtualKey);

    /// <summary>Send the button-up event for one held mouse button
    /// ("left" / "right" / "middle", already normalised).</summary>
    void ReleaseMouseButton(string button);
}

/// <summary>Optional sink extension: cancel an in-progress drag
/// (an Esc press) BEFORE the button-up lands, so an interrupted
/// Ctrl/Shift-drag is cancelled instead of committing as a
/// modifier-drop (BD-SUPP-HELDINPUT F11). Sinks that implement it
/// get the cancel; the tracker calls it once per ReleaseAll that
/// releases at least one button.</summary>
public interface IInputDragCancelSink
{
    void CancelDrag();
}

/// <summary>The honest outcome of a ReleaseAll: what actually got
/// its up sent, and what FAILED (send threw) and is therefore still
/// held and still tracked for a retry. The pre-fix API returned one
/// list that named failed items as released (F3).</summary>
public sealed record HeldReleaseResult(
    IReadOnlyList<string> Released,
    IReadOnlyList<string> Failed);

/// <summary>Thread-safe record of injected input currently held down.
/// Every down the engine sends is noted; every up removes its entry.
/// A snapshot that is non-empty when a fail-safe trigger fires is
/// exactly the set of physical inputs stuck on the host.</summary>
public sealed class HeldInputTracker
{
    private readonly object _gate = new();
    private readonly List<ushort> _keys = new();       // acquisition order
    private readonly List<string> _buttons = new();    // acquisition order
    private bool _sealed;                              // F1: latched by ReleaseAll, cleared by Rearm

    /// <summary>Normalise a button name the same way the engine's
    /// send path does: anything that is not right/middle is the left
    /// button (the engine's SendInput fallback maps unknown names to
    /// LEFTDOWN, so tracking them as anything else would strand the
    /// real hold). F8 note: the engine's raw send switch folds X1/X2
    /// to LEFTDOWN too, and its key sends are VK-only (no scan code,
    /// no extended-key flag — see DesktopEngine.SendKeyRaw), so a
    /// VK-only release replays the exact inverse of the down the
    /// engine actually sent. If the engine ever sends extended or
    /// scan-code downs, this tracker must grow the flags with it.</summary>
    public static string NormaliseButton(string? button) =>
        button?.Trim().ToLowerInvariant() switch
        {
            "right" => "right",
            "middle" => "middle",
            _ => "left",
        };

    /// <summary>True once ReleaseAll has fired and before Rearm:
    /// presses are refused (and answered with an up) while sealed.</summary>
    public bool IsSealed { get { lock (_gate) return _sealed; } }

    /// <summary>Re-arm the tracker for a NEW session/presence
    /// period after a fail-safe release. Only the agent's
    /// session-start path calls this; a release never re-arms
    /// itself, so input held at a trigger stays refused until a
    /// genuinely new session begins.</summary>
    public void Rearm() { lock (_gate) _sealed = false; }

    /// <summary>F1: the atomic press. The hold is RECORDED under
    /// the gate first, then <paramref name="sendDown"/> runs — a
    /// racing ReleaseAll therefore either snapshots this key (and
    /// releases it) or has already sealed, in which case no down is
    /// sent at all and <paramref name="sendUp"/> fires immediately
    /// as belt-and-braces. Returns true when the down was sent.
    /// The send runs outside the gate so a slow send never blocks a
    /// fail-safe snapshot; the record-before-send order is what
    /// closes the race, and ReleaseAll's seal covers the rest.</summary>
    public bool PressKey(ushort virtualKey, Action sendDown, Action sendUp)
    {
        if (virtualKey == 0) return false; // engine's "unknown key" sentinel — nothing to send
        bool wasSealed;
        lock (_gate)
        {
            wasSealed = _sealed;
            if (!wasSealed && !_keys.Contains(virtualKey)) _keys.Add(virtualKey);
        }
        if (wasSealed) { try { sendUp(); } catch { } return false; }
        sendDown();
        // W12 / DS-P6-F1: the post-send recheck. A ReleaseAll that ran
        // ENTIRELY in the gap between the record above and sendDown
        // sealed the tracker, snapshotted this key and sent its up —
        // BEFORE the down landed. Without this recheck the key would
        // sit physically down, sealed and untracked. If the seal is
        // latched or the hold is no longer tracked, the down lost the
        // race: send the up NOW and report the press refused.
        var lostRace = false;
        lock (_gate) { lostRace = _sealed || !_keys.Contains(virtualKey); }
        if (lostRace) { try { sendUp(); } catch { } return false; }
        return true;
    }

    /// <summary>F1: the atomic button press — same contract as
    /// <see cref="PressKey"/>.</summary>
    public bool PressButton(string? button, Action sendDown, Action sendUp)
    {
        var b = NormaliseButton(button);
        bool wasSealed;
        lock (_gate)
        {
            wasSealed = _sealed;
            if (!wasSealed && !_buttons.Contains(b)) _buttons.Add(b);
        }
        if (wasSealed) { try { sendUp(); } catch { } return false; }
        sendDown();
        // W12 / DS-P6-F1: same post-send race recheck as PressKey.
        var lostRace = false;
        lock (_gate) { lostRace = _sealed || !_buttons.Contains(b); }
        if (lostRace) { try { sendUp(); } catch { } return false; }
        return true;
    }

    /// <summary>W12 / DS-P6-F10: NOTE-ONLY legacy surface. This records
    /// a hold the CALLER already sent; it cannot send the compensating
    /// up a sealed press needs, so new code must use
    /// <see cref="PressKey"/>/<see cref="PressButton"/> (the atomic
    /// pair). Retained for the engine's key_down/key_up tool legs,
    /// whose callers check the returned bool before sending.</summary>
    public bool NoteKeyDown(ushort virtualKey)
    {
        if (virtualKey == 0) return false; // 0 is the engine's "unknown key" sentinel — nothing was sent
        lock (_gate)
        {
            if (_sealed) return false; // F1: a sealed tracker accepts no new holds
            if (!_keys.Contains(virtualKey)) _keys.Add(virtualKey);
            return true;
        }
    }

    public void NoteKeyUp(ushort virtualKey)
    {
        lock (_gate) _keys.Remove(virtualKey);
    }

    public bool NoteMouseDown(string? button)
    {
        var b = NormaliseButton(button);
        lock (_gate)
        {
            if (_sealed) return false;
            if (!_buttons.Contains(b)) _buttons.Add(b);
            return true;
        }
    }

    public void NoteMouseUp(string? button)
    {
        lock (_gate) _buttons.Remove(NormaliseButton(button));
    }

    public bool HasHeldInput { get { lock (_gate) return _keys.Count > 0 || _buttons.Count > 0; } }

    /// <summary>Snapshot of the virtual keys currently held, in
    /// acquisition order. BD-WIN-AGENT F7: the input guard tests a
    /// prospective key_down against this set, so a forbidden combo
    /// assembled one key at a time is refused at the completing key.</summary>
    public IReadOnlyList<ushort> HeldKeys() { lock (_gate) return _keys.ToList(); }

    /// <summary>Snapshot of what is held right now, in acquisition
    /// order, as audit-friendly descriptors ("key:0x11",
    /// "button:left").</summary>
    public IReadOnlyList<string> HeldSnapshot()
    {
        lock (_gate)
        {
            var held = new List<string>(_buttons.Count + _keys.Count);
            foreach (var b in _buttons) held.Add($"button:{b}");
            foreach (var k in _keys) held.Add($"key:0x{k:X2}");
            return held;
        }
    }

    /// <summary>
    /// Release EVERYTHING held: drag-cancel first (F11: an Esc so an
    /// interrupted drag is cancelled, not committed), then buttons
    /// (a held button must not drag across whatever the key release
    /// changes), then keys in REVERSE acquisition order (modifiers
    /// that went down first come up last — the mirror of how a chord
    /// is pressed). F11 trade-off, stated plainly: the ups are sent
    /// unconditionally; if the person at the keyboard is physically
    /// holding the same key, this up also ends their hold's injected
    /// twin — the fail-safe errs toward letting go, because a stuck
    /// injected modifier corrupts everything typed next, while a
    /// person's own hold re-asserts on their next keystroke.
    ///
    /// The tracker SEALS and clears BEFORE any send (F1): presses
    /// after this call are refused until Rearm. Each send is
    /// attempted independently — one bad send never strands the
    /// rest — but a FAILED send is no longer forgotten (F3): the
    /// item goes back into the tracker and is named in
    /// <see cref="HeldReleaseResult.Failed"/>, so the next trigger
    /// retries it and the audit can tell the truth. Idempotent — a
    /// second call with nothing held (and nothing failed) sends
    /// nothing.
    /// </summary>
    public HeldReleaseResult ReleaseAll(IInputReleaseSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        List<ushort> keys;
        List<string> buttons;
        lock (_gate)
        {
            _sealed = true;
            keys = new List<ushort>(_keys);
            buttons = new List<string>(_buttons);
            _keys.Clear();
            _buttons.Clear();
        }
        var released = new List<string>(buttons.Count + keys.Count);
        var failed = new List<string>();
        if (buttons.Count > 0 && sink is IInputDragCancelSink cancel)
        {
            try { cancel.CancelDrag(); } catch { /* the ups still go out */ }
        }
        // W12 / DS-P6-F20: failed items are re-tracked in their
        // ORIGINAL acquisition order (collected first, reinserted
        // once), so the next ReleaseAll still releases in reverse
        // acquisition order — appending in failure order mirrored it.
        var failedButtons = new List<string>();
        var failedKeys = new List<ushort>();
        foreach (var b in buttons)
        {
            try { sink.ReleaseMouseButton(b); released.Add($"button:{b}"); }
            catch { failed.Add($"button:{b}"); failedButtons.Add(b); }
        }
        for (var i = keys.Count - 1; i >= 0; i--)
        {
            try { sink.ReleaseKey(keys[i]); released.Add($"key:0x{keys[i]:X2}"); }
            catch { failed.Add($"key:0x{keys[i]:X2}"); failedKeys.Add(keys[i]); }
        }
        if (failedButtons.Count > 0 || failedKeys.Count > 0)
        {
            lock (_gate)
            {
                foreach (var b in failedButtons) if (!_buttons.Contains(b)) _buttons.Add(b);
                failedKeys.Reverse(); // collected newest-first; restore acquisition order
                foreach (var k in failedKeys) if (!_keys.Contains(k)) _keys.Add(k);
            }
        }
        return new HeldReleaseResult(released, failed);
    }

    /// <summary>F2 mitigation — the startup sweep. A process that is
    /// KILLED mid-hold cannot run any release code (no finally, no
    /// handler survives TerminateProcess), and Windows does not undo
    /// injected SendInput downs when the injector dies. What CAN be
    /// done: the next agent start sends an up for every mouse
    /// button and EVERY virtual key, whether or not its (fresh,
    /// empty) tracker believes anything is held — an up for a key
    /// that is not down is a no-op. The window between the crash and
    /// the restart is a named residual: during it, the Core has
    /// already ended the session on link loss, and the watchdog
    /// restarts the agent, which runs this sweep before serving any
    /// tool. Returns the descriptors swept, for the narration/audit.
    ///
    /// W11 / R-32: the sweep previously covered only modifiers, the
    /// Win keys and Esc — but the tracker can hold ANY key (a held
    /// letter from a drag chord, a held F-key, a held space), and a
    /// sweep named "all possible" that leaves those down was a
    /// partial mitigation wearing a complete name. The sweep now
    /// covers the full virtual-key range the input path can press
    /// (0x08–0xFE), excluding only: the mouse-button VKs 0x01–0x06
    /// (buttons are swept as buttons), 0x00/0xFF (undefined /
    /// reserved), and VK_PACKET 0xE7 (a Unicode-injection pseudo-
    /// key that is never held as a physical-style down). The
    /// crash→restart WINDOW itself remains, named in the W7
    /// ledger: closing it needs a session-resident supervisor that
    /// survives the agent — a new component, not a sweep change.</summary>
    public static IReadOnlyList<string> SweepAllPossible(IInputReleaseSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        var swept = new List<string>();
        foreach (var b in new[] { "left", "right", "middle" })
        {
            try { sink.ReleaseMouseButton(b); swept.Add($"button:{b}"); } catch { }
        }
        foreach (var vk in SweepKeys)
        {
            try { sink.ReleaseKey(vk); swept.Add($"key:0x{vk:X2}"); } catch { }
        }
        return swept;
    }

    private static readonly ushort[] SweepKeys = BuildSweepKeys();

    private static ushort[] BuildSweepKeys()
    {
        var keys = new List<ushort>();
        for (var vk = 0x08; vk <= 0xFE; vk++)
        {
            if (vk == 0xE7) continue; // VK_PACKET — never a held down
            keys.Add((ushort)vk);
        }
        return keys.ToArray();
    }
}

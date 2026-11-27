namespace DeskGuest.Shared.Presence;

/// <summary>
/// FR-120 (Jacob, 2026-11-23) — TUNABLE TAKEOVER vocabulary,
/// as amended by FR-145 (owner ruling, 2026-11-25 23:31–23:33
/// CT). The mode VALUES (independent mouse / keyboard choices)
/// remain the device's recorded preference and session-record
/// vocabulary, with exactly one settings home: the DEVICE'S
/// OWN DeskGuest instance state (the SessionAgent's
/// PresencePalette / presence.json), changed through that
/// instance's UI — by the owner at the machine, or by a helper
/// remoted into the device in a live, presence-visible session
/// using that UI like any other action. There is NO
/// API/back-channel write path and none may be added: no
/// out-of-band edits, no silent flips (Jacob's corrected
/// ownership rule, 2026-11-23 22:49 CT).
///
/// FR-145 LAW: no mode makes ordinary local input yield. Input
/// is never a floor event — moving the mouse, clicking, typing
/// or remoting in never takes driving from the agent, in any
/// mode; the owner coexists and the agent carries on. The
/// Give/Take mechanism is the sole floor mechanism: the
/// takeover chord (Ctrl+Alt+Shift+Backspace) is the deliberate
/// Take control act in every mode, and hand-back (Give
/// control) is explicit. STOP is unaffected in every mode.
/// </summary>
public enum TakeoverMode { TakeOver, Share, HotkeyOnly }

public static class TakeoverModes
{
    /// <summary>The default for a device that has never chosen.
    /// Kept as the record-vocabulary default; under FR-145 the
    /// choice no longer changes what ordinary input does.</summary>
    public const TakeoverMode Default = TakeoverMode.TakeOver;

    /// <summary>Does local input of this mode yield driving to
    /// the owner? FR-145: NO mode yields — this returns false
    /// for every mode. It remains as the one named decision
    /// point so no caller can quietly reintroduce a
    /// touch-to-yield branch; the chord, not input, is the take
    /// path. (STOP is not a mode question at all and is never
    /// gated by this.)</summary>
    public static bool LocalInputYields(TakeoverMode mode) => false;
}

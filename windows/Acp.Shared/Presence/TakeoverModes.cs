namespace Acp.Shared.Presence;

/// <summary>
/// FR-120 (owner directive, 2026-11-23) — TUNABLE TAKEOVER vocabulary.
/// How a session is taken back is a setting, with INDEPENDENT
/// modes for local mouse and keyboard input:
///
///  * TakeOver    — local input yields driving to the owner;
///                  the agent observes. (Default for mouse.)
///  * Share       — local input never interrupts; the owner
///                  points freely while the agent drives.
///  * HotkeyOnly  — local input is ignored until the takeover
///                  hotkey or STOP.
///
/// STOP is unaffected in every mode. The mode VALUES live in
/// exactly one settings home: the DEVICE'S OWN DeskGuest
/// instance state (the SessionAgent's PresencePalette /
/// presence.json), changed through that instance's UI — by the
/// owner at the machine, or by a helper remoted into the device
/// in a live, presence-visible session using that UI like any
/// other action. There is NO API/back-channel write path and
/// none may be added: no out-of-band edits, no silent flips
/// (the owner's corrected ownership rule, 2026-11-23 22:49 CT).
/// Behaviour consults the values through LocalInputYields and
/// never hard-codes today's touch-to-yield. W72 ships the read
/// point with TakeOver as the only behaviour wired; the full
/// modes, the session-record field and the settings UI are
/// W73 / the customization-page build.
/// </summary>
public enum TakeoverMode { TakeOver, Share, HotkeyOnly }

public static class TakeoverModes
{
    /// <summary>The default for a device that has never chosen:
    /// local input takes over (today's touch-to-yield).</summary>
    public const TakeoverMode Default = TakeoverMode.TakeOver;

    /// <summary>Does local input of this mode yield driving to
    /// the owner? Only TakeOver yields. Share never interrupts;
    /// HotkeyOnly waits for the hotkey (or STOP, which is not a
    /// mode question at all and is never gated by this).</summary>
    public static bool LocalInputYields(TakeoverMode mode) => mode == TakeoverMode.TakeOver;
}

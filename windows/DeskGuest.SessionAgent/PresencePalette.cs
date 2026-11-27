using System.IO;
using System.Text.Json;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Presence;

namespace DeskGuest.SessionAgent;

/// <summary>
/// Presence settings home (W8, extended by W85 / FR-105). W8
/// replaced the old palette editor with comfort-only settings on
/// the reasoning that presence hues are meanings fixed by
/// PresenceLaw. Jacob's 2026-11-23 PRESENCE CUSTOMIZATION
/// DIRECTIVE supersedes that posture: appearance is the owner's
/// — size, brightness, detail level, per-state colors, pointer
/// style, and the Background Work Only indicator's appearance —
/// customized on the Presence page and persisted HERE, through
/// this one store (the FR-105 scheme fields below, written only
/// by SetScheme from this device's own UI). What the directive
/// keeps as law, this store enforces: state remains readable by
/// word and icon whatever colors are chosen (triple-coding lives
/// in the composition, PresenceCustomization), and the scheme is
/// CLAMPED on load and on save so presence can never be persisted
/// invisible, unnamed, or STOP-less.
///
/// The comfort settings stand as they were:
///   * Glow intensity — never below the 40% legibility floor.
///   * Glow breath — off by default (the Glow is static by
///     default, OI-04); when on, the 6.4 s / 82–100% breath.
/// The consent floor itself is not a setting.
///
/// Migration: a legacy presence.json written by the picker (colour
/// keys, ShowIntent, GlowAllMonitors) loads as comfort defaults —
/// the legacy keys are dropped on the next save and are never
/// consumed by any surface. A malformed file falls back to the
/// defaults whole: presence must never fail to paint because a
/// settings file is corrupt. Agent-local: how THIS screen looks,
/// never a host policy, never travels the IPC channel.
/// </summary>
public sealed class PresencePalette
{
    /// <summary>Glow intensity, percent — clamped to
    /// [GlowIntensityFloorPct, 100] on load and on set.</summary>
    public int GlowIntensityPct { get; set; } = 100;

    /// <summary>Comfort only: the 6.4 s breath. Default false —
    /// the Glow is static by default (OI-04).</summary>
    public bool BreathEnabled { get; set; } = false;

    // ---- FR-105 (W85): the customization scheme, persisted ----
    // Written ONLY by SetScheme (this device's own Presence page);
    // read through the clamped Scheme property. Defaults are the
    // law scheme (PresenceScheme.Default) so a file written before
    // W85 — or no file at all — renders exactly the W72 pill.
    public int BoxSizePct { get; set; } = 100;
    public int AppearanceBrightnessPct { get; set; } = 100;
    public string DetailLevel { get; set; } = nameof(PresenceDetail.Full);
    public int AiColorArgb { get; set; } = PresenceLaw.HueAi;
    public int HumanColorArgb { get; set; } = PresenceLaw.HueHuman;
    public int WaitingColorArgb { get; set; } = PresenceLaw.HueIdle;
    public int StopColorArgb { get; set; } = PresenceLaw.PillStopRed;
    public string PointerStyleId { get; set; } = PointerStyles.DefaultId;
    public int BgColorArgb { get; set; } = PresenceLaw.HueAi;
    public int BgSizePct { get; set; } = 100;
    public int BgBrightnessPct { get; set; } = 100;

    /// <summary>The owner's scheme, floor-clamped: whatever the
    /// file holds, what renders is inside the never-invisible
    /// bounds (PresenceScheme.Clamp).</summary>
    public PresenceScheme Scheme => new PresenceScheme(
        BoxSizePct, AppearanceBrightnessPct,
        Enum.TryParse<PresenceDetail>(DetailLevel, ignoreCase: true, out var d) ? d : PresenceDetail.Full,
        AiColorArgb, HumanColorArgb, WaitingColorArgb, StopColorArgb,
        PointerStyleId, BgColorArgb, BgSizePct, BgBrightnessPct).Clamp();

    /// <summary>FR-105: THE appearance write path — called ONLY by
    /// this device's own DeskGuest UI (the Presence page's Save).
    /// The scheme is clamped before it is stored, so the file can
    /// never hold an invisible scheme even if a caller skipped
    /// validation. Mirrors SetTakeoverModes' discipline: no IPC
    /// kind, MCP tool, or Core message reaches this method.</summary>
    public void SetScheme(PresenceScheme scheme)
    {
        var s = scheme.Clamp();
        BoxSizePct = s.SizePct;
        AppearanceBrightnessPct = s.BrightnessPct;
        DetailLevel = s.Detail.ToString();
        AiColorArgb = s.AiArgb;
        HumanColorArgb = s.HumanArgb;
        WaitingColorArgb = s.WaitingArgb;
        StopColorArgb = s.StopArgb;
        PointerStyleId = s.PointerStyleId;
        BgColorArgb = s.BgArgb;
        BgSizePct = s.BgSizePct;
        BgBrightnessPct = s.BgBrightnessPct;
        // One brightness, one value: the page's brightness control
        // drives the Glow's intensity too (the acting display's
        // intensity), so the preview and the real Glow agree.
        GlowIntensityPct = s.BrightnessPct;
        Save();
    }

    /// <summary>FR-120 — the ONE settings home for the tunable
    /// takeover modes (this device's own DeskGuest instance
    /// state — changed through this instance's UI only; there is
    /// no API/back-channel write path, FR-120 as corrected
    /// 2026-11-23 22:49 CT). Independent
    /// modes for local mouse and keyboard input; both default to
    /// TakeOver (the owner's stated default for mouse, and
    /// the FR-120-era behaviour for keyboard). FR-145 (owner
    /// ruling, 2026-11-25): these values are now record
    /// vocabulary only — TakeoverModes.LocalInputYields is
    /// false for every mode, ordinary input never yields, and
    /// the chord is the sole take path. Serialized by name so
    /// the file stays human-readable; an unknown name loads as
    /// TakeOver. The settings UI for these is W73, not the
    /// palette.</summary>
    public string MouseTakeoverMode { get; set; } = nameof(TakeoverMode.TakeOver);
    public string KeyboardTakeoverMode { get; set; } = nameof(TakeoverMode.TakeOver);

    /// <summary>FR-120 (W73): true once the device itself has
    /// chosen its takeover modes through this instance's UI. A
    /// fleet default (signed policy, TakeoverFleetDefaults)
    /// supplies the starting modes ONLY while this is false; the
    /// moment the UI saves a choice, the device's own choice is
    /// the whole story. Legacy files (written before the flag)
    /// load as not-chosen unless their mode values differ from
    /// the defaults — a device that picked Share under W72 keeps
    /// it (Load promotes the flag in that case).</summary>
    public bool TakeoverModesChosen { get; set; } = false;

    /// <summary>The fleet defaults most recently pushed by the
    /// Core (IpcKinds.TakeoverDefaults). IN MEMORY ONLY — policy
    /// never writes presence.json; this is a starting point for a
    /// device that has not chosen, never an override.</summary>
    public static DeskGuest.Shared.Policy.TakeoverFleetDefaults FleetDefaults { get; set; } =
        DeskGuest.Shared.Policy.TakeoverFleetDefaults.None;

    /// <summary>The active mouse takeover mode: the device's own
    /// choice when it has chosen; otherwise the fleet default if
    /// policy supplied one; otherwise TakeOver. The stored value
    /// parses fail-safe: anything unrecognized is TakeOver
    /// (yield — the safe side).</summary>
    public TakeoverMode ActiveMouseTakeoverMode =>
        TakeoverModesChosen
            ? (Enum.TryParse<TakeoverMode>(MouseTakeoverMode, ignoreCase: true, out var m) ? m : TakeoverMode.TakeOver)
            : FleetDefaults.DefaultFor(TakeoverInputClass.Mouse);

    /// <summary>The active keyboard takeover mode, same rule.</summary>
    public TakeoverMode ActiveKeyboardTakeoverMode =>
        TakeoverModesChosen
            ? (Enum.TryParse<TakeoverMode>(KeyboardTakeoverMode, ignoreCase: true, out var m) ? m : TakeoverMode.TakeOver)
            : FleetDefaults.DefaultFor(TakeoverInputClass.Keyboard);

    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DeskGuest", "presence.json");

    /// <summary>Raised after a save so the live layer repaints.</summary>
    public static event Action? Changed;

    /// <summary>True when a loaded file carried any legacy picker
    /// key — the migration fact, for the harness.</summary>
    public static bool LastLoadHadLegacyKeys { get; private set; }

    private static readonly string[] LegacyKeys =
        { "Glow", "Cursor", "Ripple", "Highlight", "Accent", "Stop", "ShowIntent", "GlowAllMonitors" };

    public static PresencePalette Load()
    {
        LastLoadHadLegacyKeys = false;
        try
        {
            if (File.Exists(FilePath))
            {
                var text = File.ReadAllText(FilePath);
                LastLoadHadLegacyKeys = LegacyKeys.Any(k =>
                    text.Contains($"\"{k}\"", StringComparison.Ordinal));
                var loaded = JsonSerializer.Deserialize<PresencePalette>(text);
                if (loaded is not null)
                {
                    loaded.GlowIntensityPct = Math.Clamp(loaded.GlowIntensityPct,
                        PresenceLaw.GlowIntensityFloorPct, 100);
                    // FR-120 chosen-flag migration: a pre-flag file
                    // whose stored modes differ from the defaults
                    // records a choice the owner already made —
                    // promote it, so a fleet default can never
                    // silently move a device that already chose.
                    if (!loaded.TakeoverModesChosen &&
                        (loaded.MouseTakeoverMode != nameof(TakeoverMode.TakeOver) ||
                         loaded.KeyboardTakeoverMode != nameof(TakeoverMode.TakeOver)))
                        loaded.TakeoverModesChosen = true;
                    // Normalize the STORED strings by their own
                    // parse (never via the fleet-aware Active*
                    // properties — the file carries the device's
                    // values only, policy is not persisted here).
                    loaded.MouseTakeoverMode =
                        (Enum.TryParse<TakeoverMode>(loaded.MouseTakeoverMode, ignoreCase: true, out var mm) ? mm : TakeoverMode.TakeOver).ToString();
                    loaded.KeyboardTakeoverMode =
                        (Enum.TryParse<TakeoverMode>(loaded.KeyboardTakeoverMode, ignoreCase: true, out var mk) ? mk : TakeoverMode.TakeOver).ToString();
                    return loaded;
                }
            }
        }
        catch { /* fall through to defaults */ }
        return new PresencePalette();
    }

    /// <summary>FR-120: THE settings write for the takeover modes
    /// — called ONLY by this device's own DeskGuest UI (the
    /// Presence page's "Taking back control" group). Marks the
    /// device as having chosen, so fleet defaults stop applying,
    /// and saves through the one home. There is no other caller
    /// shape: no IPC kind, MCP tool, or Core message reaches this
    /// method (pinned by the W73 no-API-write tests).</summary>
    public void SetTakeoverModes(TakeoverMode mouse, TakeoverMode keyboard)
    {
        MouseTakeoverMode = mouse.ToString();
        KeyboardTakeoverMode = keyboard.ToString();
        TakeoverModesChosen = true;
        Save();
    }

    public void Save()
    {
        GlowIntensityPct = Math.Clamp(GlowIntensityPct, PresenceLaw.GlowIntensityFloorPct, 100);
        // FR-105: the stored scheme is normalized to its clamped
        // form on every save — the file never holds an invisible
        // scheme, whoever the caller was.
        var s = Scheme;
        BoxSizePct = s.SizePct; AppearanceBrightnessPct = s.BrightnessPct;
        DetailLevel = s.Detail.ToString();
        AiColorArgb = s.AiArgb; HumanColorArgb = s.HumanArgb;
        WaitingColorArgb = s.WaitingArgb; StopColorArgb = s.StopArgb;
        PointerStyleId = s.PointerStyleId;
        BgColorArgb = s.BgArgb; BgSizePct = s.BgSizePct; BgBrightnessPct = s.BgBrightnessPct;
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        Changed?.Invoke();
    }

    public static void ResetToDefaults() => new PresencePalette().Save();

    /// <summary>The effective intensity for a display: the acting
    /// display runs at the owner's comfort intensity; every other
    /// display runs at the 40% legibility floor — never unlit
    /// (record §2).</summary>
    public int IntensityForDisplay(bool actingDisplay) =>
        actingDisplay ? GlowIntensityPct : PresenceLaw.GlowLegibilityFloorPct;
}

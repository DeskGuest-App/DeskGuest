using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Shared.Policy;

// =====================================================================
// FR-120 (W73) — the tunable takeover modes as FLEET-SETTABLE
// DEFAULTS, wired exactly the way sibling plain settings map
// (U1 clipboard.direction / U4 session_budget.cap.*): a feature
// toggle in FeatureToggleRegistry ("rmm.takeover_modes.enabled",
// directive FR-120) plus plain settings keys an admitted signed
// management-policy document may set:
//
//   session.takeover.mouse_mode     TakeOver | Share | HotkeyOnly
//   session.takeover.keyboard_mode  TakeOver | Share | HotkeyOnly
//
// The modes are NOT part of the §7.10 consent floor — presence,
// STOP and the audit chain have no toggle and these keys name
// none of them (ConsentFloorGuard admits them; a test pins that).
// A fleet may set the DEFAULT a device starts from; the device's
// own DeskGuest UI remains the live settings home
// (PresencePalette / presence.json) and the owner's local choice
// is what a session actually runs — policy supplies the default
// only where the device has not chosen (TakeoverModes.Default
// stands when neither has spoken). An unparsable policy value is
// IGNORED (no default supplied) — a malformed fleet value can
// neither widen nor break takeover behaviour by accident.
//
// The AGENT channel may never set these: there is no MCP tool,
// IPC kind, or mesh route that writes them (pinned by test). The
// only write paths are (a) the signed policy channel into this
// resolver's inputs, and (b) the device UI into presence.json.
//
// FR-145 NOTE (owner ruling, 2026-11-25): the modes no longer
// decide any input behaviour — ordinary local input never
// yields in any mode, and the chord is the sole take path.
// These keys survive as fleet-settable record vocabulary (the
// session record still carries the modes a session ran under);
// a fleet default can no longer widen or narrow who holds the
// floor, because input is never a floor event.
// =====================================================================

/// <summary>The TOTAL POLICY CONTROL keys for the takeover modes.</summary>
public static class TakeoverPolicyKeys
{
    /// <summary>Feature toggle registered in FeatureToggleRegistry
    /// (directive FR-120, default ON). OFF stands the fleet-default
    /// layer down: devices run purely on their local choice.</summary>
    public const string FeatureToggle = "rmm.takeover_modes.enabled";

    /// <summary>The fleet default for local MOUSE input:
    /// TakeOver | Share | HotkeyOnly. Unset/unparsable → no fleet
    /// default (the device's own choice / TakeoverModes.Default).</summary>
    public const string MouseMode = "session.takeover.mouse_mode";

    /// <summary>The fleet default for local KEYBOARD input. Same
    /// vocabulary and same fail-safe as the mouse key.</summary>
    public const string KeyboardMode = "session.takeover.keyboard_mode";
}

/// <summary>The fleet defaults resolved from one device's
/// Effective Policy. A null mode means policy supplied no usable
/// default for that class.</summary>
public sealed record TakeoverFleetDefaults(TakeoverMode? Mouse, TakeoverMode? Keyboard)
{
    public static readonly TakeoverFleetDefaults None = new(null, null);

    /// <summary>Resolve from an Effective Policy (null policy →
    /// no defaults). Parse is fail-safe in the palette's sense:
    /// only an exact mode name counts; anything else is ignored,
    /// never coerced.</summary>
    public static TakeoverFleetDefaults FromEffective(EffectivePolicy? effective)
    {
        if (effective is null) return None;
        return new TakeoverFleetDefaults(
            Parse(effective.Get(TakeoverPolicyKeys.MouseMode)?.Value),
            Parse(effective.Get(TakeoverPolicyKeys.KeyboardMode)?.Value));
    }

    private static TakeoverMode? Parse(string? value) =>
        value is not null && Enum.TryParse<TakeoverMode>(value.Trim(), ignoreCase: true, out var m)
            ? m : null;

    /// <summary>The starting mode for a class on a device that
    /// has not chosen: the fleet default if policy supplied one,
    /// else TakeoverModes.Default. A device-local choice, once
    /// made in the DeskGuest UI, outranks this — the palette is
    /// the live home; this supplies only the never-chosen starting
    /// point. The Core pushes these defaults to the Session Agent
    /// (IpcKinds.TakeoverDefaults, the U1 clipboard-policy push
    /// pattern); the agent applies them in memory only — policy
    /// never writes presence.json.</summary>
    public TakeoverMode DefaultFor(TakeoverInputClass inputClass) =>
        (inputClass == TakeoverInputClass.Mouse ? Mouse : Keyboard) ?? TakeoverModes.Default;

    /// <summary>The IPC payload the Core pushes (state only: mode
    /// names, nothing else). A class with no fleet default is
    /// simply absent from the payload.</summary>
    public string ToIpcJson()
    {
        var parts = new List<string>();
        if (Mouse is not null) parts.Add($"\"mouse\": \"{Mouse}\"");
        if (Keyboard is not null) parts.Add($"\"keyboard\": \"{Keyboard}\"");
        return "{ " + string.Join(", ", parts) + " }";
    }

    /// <summary>Parse a TakeoverDefaults payload agent-side.
    /// Malformed input resolves to no defaults — a garbled push
    /// can never move a mode.</summary>
    public static TakeoverFleetDefaults FromIpcJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return None;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            return new TakeoverFleetDefaults(
                root.TryGetProperty("mouse", out var m) ? Parse(m.GetString()) : null,
                root.TryGetProperty("keyboard", out var k) ? Parse(k.GetString()) : null);
        }
        catch { return None; }
    }
}

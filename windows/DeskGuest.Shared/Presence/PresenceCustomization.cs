using DeskGuest.Shared.Design;

namespace DeskGuest.Shared.Presence;

/// <summary>
/// FR-105 (W85) — the presence CUSTOMIZATION model. Jacob's
/// 2026-11-23 directive supersedes the fixed-palette posture:
/// appearance is the owner's — size, brightness, detail, per-state
/// colors, pointer style, and the Background Work Only indicator's
/// appearance — as a real settings surface, persisted through
/// PresencePalette (the device's own settings home; this model is
/// the pure shape + floor math, no storage).
///
/// THE FLOOR (never customizable away, enforced here so no caller
/// can save around it):
///  * Presence can never be made invisible: size is clamped to
///    [60, 160]%, brightness to [40, 100]% (the legibility floor —
///    the same 40 the Glow has always had), and every state color's
///    alpha is clamped to at least 0xCC, so a scheme persisted
///    through Clamp is always plainly visible.
///  * The Box always names the driver and always carries STOP —
///    that is composition law (PresenceComposition.BoxLines),
///    not a field here; Validate re-checks it so a future edit
///    that broke the composition fails the floor tests, not a user.
///  * State stays readable by WORD and ICON whatever colors are
///    chosen (triple-coding): the sentence and the state word are
///    text, the face/glyph is an icon, the color is the third
///    channel. Validate WARNS (never blocks) when two state colors
///    are close enough to confuse — the words still tell them
///    apart, exactly as the revision draft's S21 row prescribes.
/// </summary>
public enum PresenceDetail { Full, CompactPill }

/// <summary>One pointer-gallery style: a base geometry in a
/// colorway. The gallery is 10 bases × 3 colorways = 30 styles.
/// Every style is drawn with the agent HALO in the current state's
/// color around it — the halo is what keeps the ghost instantly
/// distinguishable from the owner's own system cursor, whatever
/// shape or colorway is picked.</summary>
public sealed record PointerStyle(string Id, string Base, string Colorway, string DisplayName)
{
    /// <summary>The halo color for a state: always the scheme's
    /// state color (triple-coding — the halo is a state channel,
    /// never a fixed brand color).</summary>
    public int HaloArgb(PresenceScheme scheme, PresenceLaw.Actor actor) => scheme.ColorFor(actor);
}

public static class PointerStyles
{
    public static readonly IReadOnlyList<string> Bases = new[]
    {
        "RingInitial", "RingDot", "Arrow", "Hand", "Crosshair",
        "Diamond", "Star", "Heart", "Chevron", "Wand",
    };

    public static readonly IReadOnlyList<string> Colorways = new[] { "Classic", "Inverted", "Accent" };

    private static readonly IReadOnlyDictionary<string, string> BaseNames = new Dictionary<string, string>
    {
        ["RingInitial"] = "Ring with initial",
        ["RingDot"] = "Ring and dot",
        ["Arrow"] = "Arrow",
        ["Hand"] = "Hand",
        ["Crosshair"] = "Crosshair",
        ["Diamond"] = "Diamond",
        ["Star"] = "Star",
        ["Heart"] = "Heart",
        ["Chevron"] = "Chevron",
        ["Wand"] = "Wand",
    };

    /// <summary>The full gallery: 30 styles, stable ids
    /// ("arrow-inverted"), unique by construction.</summary>
    public static readonly IReadOnlyList<PointerStyle> All =
        Bases.SelectMany(b => Colorways.Select(c => new PointerStyle(
            $"{b.ToLowerInvariant()}-{c.ToLowerInvariant()}", b, c,
            $"{BaseNames[b]} · {c}"))).ToList();

    public const string DefaultId = "ringinitial-classic";

    public static PointerStyle ById(string? id) =>
        All.FirstOrDefault(s => s.Id == id) ?? All.First(s => s.Id == DefaultId);

    public static bool IsKnownId(string? id) => id is not null && All.Any(s => s.Id == id);
}

/// <summary>The owner's presence scheme — one record for the whole
/// presence system (the consolidation directive: ONE page, and the
/// background-mode indicator is customized from the same page under
/// the same floor, so its appearance fields live here too).
/// Background Work Only MODE itself is a V2 build item; only its
/// indicator's appearance is modeled/saved here.</summary>
public sealed record PresenceScheme(
    int SizePct,
    int BrightnessPct,
    PresenceDetail Detail,
    int AiArgb,
    int HumanArgb,
    int WaitingArgb,
    int StopArgb,
    string PointerStyleId,
    int BgArgb,
    int BgSizePct,
    int BgBrightnessPct)
{
    /// <summary>The defaults ARE the law's functional family:
    /// violet AI / green person / amber waiting / red STOP (the
    /// pill's emergency-red token), full detail, the ring-with-
    /// initial ghost the product already draws.</summary>
    public static PresenceScheme Default => new(
        SizePct: 100,
        BrightnessPct: 100,
        Detail: PresenceDetail.Full,
        AiArgb: PresenceLaw.HueAi,
        HumanArgb: PresenceLaw.HueHuman,
        WaitingArgb: PresenceLaw.HueIdle,
        StopArgb: PresenceLaw.PillStopRed,
        PointerStyleId: PointerStyles.DefaultId,
        BgArgb: PresenceLaw.HueAi,
        BgSizePct: 100,
        BgBrightnessPct: 100);

    // Floor bounds — the never-invisible clamps.
    public const int SizeMinPct = 60;
    public const int SizeMaxPct = 160;
    public const int BrightnessFloorPct = 40;
    public const int MinColorAlpha = 0xCC;

    /// <summary>True when any appearance field differs from the
    /// default scheme (the renderer's cue that the owner has a
    /// scheme of their own — e.g. the pill STOP takes the scheme's
    /// STOP color; at defaults it takes the reference token, which
    /// is the same value, so the default rendering is unchanged).</summary>
    public bool IsCustomized => this != Default;

    public int ColorFor(PresenceLaw.Actor actor) => actor switch
    {
        PresenceLaw.Actor.Ai => AiArgb,
        PresenceLaw.Actor.Human => HumanArgb,
        _ => WaitingArgb,
    };

    /// <summary>Force a color's alpha to at least the visibility
    /// floor — a translucent state color is presence trying to
    /// disappear, and the floor refuses it.</summary>
    public static int ForceVisible(int argb) =>
        ((argb >> 24) & 0xFF) >= MinColorAlpha
            ? argb
            : (MinColorAlpha << 24) | (argb & 0x00FFFFFF);

    /// <summary>The clamped form of this scheme: every field inside
    /// its floor bounds, every color visibly opaque, the pointer
    /// style a known gallery id. Persistence goes through Clamp —
    /// an invisible or unknown scheme can never be what is saved
    /// or loaded.</summary>
    public PresenceScheme Clamp() => new(
        SizePct: Math.Clamp(SizePct, SizeMinPct, SizeMaxPct),
        BrightnessPct: Math.Clamp(BrightnessPct, BrightnessFloorPct, 100),
        Detail: Detail,
        AiArgb: ForceVisible(AiArgb),
        HumanArgb: ForceVisible(HumanArgb),
        WaitingArgb: ForceVisible(WaitingArgb),
        StopArgb: ForceVisible(StopArgb),
        PointerStyleId: PointerStyles.IsKnownId(PointerStyleId) ? PointerStyleId : PointerStyles.DefaultId,
        BgArgb: ForceVisible(BgArgb),
        BgSizePct: Math.Clamp(BgSizePct, SizeMinPct, SizeMaxPct),
        BgBrightnessPct: Math.Clamp(BgBrightnessPct, BrightnessFloorPct, 100));

    /// <summary>Floor validation of an UNclamped scheme (the page
    /// validates the owner's working copy before save so a floor
    /// breach is said out loud, not silently clamped): Errors are
    /// the breaches that would make presence invisible, unnamed,
    /// or STOP-less; Warnings are the alike-color notices the S21
    /// row prescribes (words still tell the states apart).</summary>
    public static (IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings) Validate(PresenceScheme s)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        if (s.SizePct < SizeMinPct) errors.Add("size below the smallest readable presence");
        if (s.BrightnessPct < BrightnessFloorPct) errors.Add("brightness below the legibility floor");
        if (s.BgBrightnessPct < BrightnessFloorPct) errors.Add("background indicator brightness below the legibility floor");
        foreach (var (name, argb) in new[]
        {
            ("AI driving", s.AiArgb), ("person driving", s.HumanArgb),
            ("waiting", s.WaitingArgb), ("STOP", s.StopArgb), ("background indicator", s.BgArgb),
        })
            if (((argb >> 24) & 0xFF) < MinColorAlpha)
                errors.Add($"{name} color is too faint to see");
        if (!PointerStyles.IsKnownId(s.PointerStyleId))
            errors.Add("pointer style is not in the gallery");
        // The composition floor, re-checked: the Box at this
        // scheme's detail level must still carry name + state + STOP.
        var lines = PresenceComposition.BoxLines(
            s.Detail == PresenceDetail.CompactPill ? BoxDetailLevel.CompactMinimum : BoxDetailLevel.Full,
            hasRoster: false);
        if (!lines.Contains(BoxLineKind.DriverName)) errors.Add("the indicator would not name the driver");
        if (!lines.Contains(BoxLineKind.StateSentence)) errors.Add("the indicator would not say the state in words");
        if (!lines.Contains(BoxLineKind.Stop)) errors.Add("the indicator would not carry STOP");
        // Alike warnings (never blocks): two state colors within a
        // small RGB distance are hard to tell apart by color alone.
        var states = new[] { ("AI driving", s.AiArgb), ("person driving", s.HumanArgb), ("waiting", s.WaitingArgb) };
        for (var i = 0; i < states.Length; i++)
            for (var j = i + 1; j < states.Length; j++)
                if (ColorDistance(states[i].Item2, states[j].Item2) < 40)
                    warnings.Add($"«{states[i].Item1}» and «{states[j].Item1}» look very alike — the words will still tell them apart");
        return (errors, warnings);
    }

    private static double ColorDistance(int a, int b)
    {
        var dr = ((a >> 16) & 0xFF) - ((b >> 16) & 0xFF);
        var dg = ((a >> 8) & 0xFF) - ((b >> 8) & 0xFF);
        var db = (a & 0xFF) - (b & 0xFF);
        return Math.Sqrt(dr * dr + dg * dg + db * db);
    }
}

/// <summary>FR-107 (W85): the driver name for a human-session LIST
/// ROW. The detail view already names the participants and their
/// floor; the row resolves the same truth: the floor holder's
/// NAME (matched from the participant list by user id, or a
/// participant whose floor marks them holder), else the session's
/// initiator — a session row never renders without a driver name
/// when the record carries one.</summary>
public static class SessionDriverName
{
    public static string Resolve(
        string initiatorName,
        string? floorHolder,
        IReadOnlyList<(string UserId, string Name, string Floor)> participants)
    {
        if (!string.IsNullOrWhiteSpace(floorHolder))
        {
            var byId = participants.FirstOrDefault(p =>
                string.Equals(p.UserId, floorHolder, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(p.Name));
            if (!string.IsNullOrWhiteSpace(byId.Name)) return byId.Name;
            var byName = participants.FirstOrDefault(p =>
                string.Equals(p.Name, floorHolder, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(p.Name));
            if (!string.IsNullOrWhiteSpace(byName.Name)) return byName.Name;
        }
        var holder = participants.FirstOrDefault(p =>
            !string.IsNullOrWhiteSpace(p.Floor) &&
            p.Floor.Contains("hold", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(p.Name));
        if (!string.IsNullOrWhiteSpace(holder.Name)) return holder.Name;
        return initiatorName ?? "";
    }
}

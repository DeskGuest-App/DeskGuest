namespace DeskGuest.Shared.Presence;

/// <summary>
/// W117 / F1 — the pill must NEVER clip its sentence. W115 proved
/// the defect live: at the 10-char pairing name "W115 Proof" the
/// board sentence wraps to THREE lines inside the fixed-height
/// 94-DIP pill and line 3 ("everything") is severed mid-glyph
/// (glyph rows 85–92, cut at row 93).
///
/// THE GROWTH RULE (stated, not implied): the reference name
/// "Axle" — bold segment "Axle (AI Agent)" — stays PIXEL-TRUE at
/// the floor's 640×94. Growth is HEIGHT-ONLY and happens only
/// beyond the reference fit: the width never leaves 640 (the
/// floor's composition discipline), the height grows by whole
/// text lines. Two independent guarantees carry it:
///  (a) the renderer (PresenceLayer.BoxShell, pill form) no
///      longer fixes the height at all — the window is
///      SizeToContent.WidthAndHeight, so WPF's own measurement
///      of the wrapped sentence sizes the Border;
///  (b) this estimator sets the pill's MINIMUM height from a
///      greedy word-wrap simulation of the actual sentence, so
///      even a measurement surprise starts from a height that
///      already fits. The estimator is deliberately
///      CONSERVATIVE: its per-glyph widths run wide (it sizes
///      the 9-char "W69 Proof" for 3 lines though live WPF fit
///      it in 2). Over-estimating costs a few empty DIPs;
///      under-estimating costs a severed glyph — the trade is
///      one-directional by design.
///
/// The token geometry is untouched: fill #0F2537, trim #E5A93B,
/// STOP #DC2626, the circle mark, exactly three elements
/// (face + sentence + STOP) — only the height is a function of
/// the sentence now.
/// </summary>
public static class PillLayout
{
    /// <summary>The floor's pill width — never grows.</summary>
    public const double BaseWidth = 640;
    /// <summary>The floor's pill height at the reference fit.</summary>
    public const double BaseHeight = 94;
    /// <summary>The compact pill's base height (W85).</summary>
    public const double CompactBaseHeight = 64;
    /// <summary>The sentence column's max width at scale 1 (the
    /// W72/W85 TextBlock MaxWidth the renderer draws with).</summary>
    public const double TextMaxWidth = 350;
    /// <summary>Full-pill sentence size at scale 1.</summary>
    public const double FontSize = 21;
    /// <summary>Compact-pill sentence size at scale 1.</summary>
    public const double CompactFontSize = 17;
    /// <summary>Line height as a multiple of font size (the
    /// renderer's font stack measures ≈1.3; the estimator uses
    /// it as the per-line step).</summary>
    public const double LineHeightFactor = 1.3;
    /// <summary>Vertical padding inside the pill Border at
    /// scale 1 (9 top + 9 bottom — W128, measured from the
    /// Board 4 crop: with the 2-DIP trim the stack
    /// 2+9+72+9+2 lands the pill at exactly 94 total; the
    /// W72-era 11+11 stacked to 98 live).</summary>
    public const double VerticalPadding = 18;
    /// <summary>The pill Border's total vertical thickness at
    /// scale 1 (2 top + 2 bottom). W128: the estimator's
    /// heights are TOTAL pill heights including this border —
    /// the content minimum subtracts it alongside the padding
    /// (its omission is what rendered the pill 98 tall against
    /// the 94 spec, measured live by window rect).</summary>
    public const double ShellBorderVertical = 4;

    private static double GlyphWidth(char c, bool bold, double fontSize)
    {
        var f = c switch
        {
            ' ' => 0.30,
            'i' or 'l' or 'j' or '.' or '\'' or '|' => 0.28,
            'f' or 't' => 0.36,
            'm' or 'w' => 0.86,
            'W' => 0.94,
            '—' => 0.90,
            '-' or '(' or ')' or ',' => 0.34,
            _ when char.IsUpper(c) => 0.68,
            _ when char.IsDigit(c) => 0.56,
            _ => 0.54,
        };
        return f * fontSize * (bold ? 1.06 : 1.0);
    }

    /// <summary>Greedy word-wrap simulation: how many lines the
    /// sentence (bold segment + regular segment) needs in a
    /// column of <paramref name="maxWidth"/> at
    /// <paramref name="fontSize"/>. Words are never split (the
    /// renderer's Wrap does not split them either); a single
    /// word wider than the column still counts as one line —
    /// the column, not the word, is what the height must fit,
    /// and WPF places such a word on its own line.</summary>
    public static int WrapLines(string boldSegment, string regularSegment,
        double maxWidth, double fontSize)
    {
        var boldWords = boldSegment.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var words = (boldSegment + regularSegment)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var space = GlyphWidth(' ', false, fontSize);
        var lines = 1;
        var cur = 0.0;
        for (var i = 0; i < words.Length; i++)
        {
            var bold = i < boldWords.Length;
            var w = words[i].Sum(c => GlyphWidth(c, bold, fontSize));
            var next = cur == 0 ? w : cur + space + w;
            if (next > maxWidth && cur > 0) { lines++; cur = w; }
            else cur = next;
        }
        return lines;
    }

    /// <summary>The rendered text bounds' height for a sentence:
    /// lines × line height, at the scheme's scale.</summary>
    public static double TextHeight(int lines, double fontSize) =>
        lines * fontSize * LineHeightFactor;

    /// <summary>The height the pill must have so the sentence
    /// renders WHOLE: the floor base height, or the text height
    /// plus the pill's vertical padding when the wrap needs
    /// more — whichever is taller. At the reference name this
    /// returns exactly the base height (94 full / 64 compact):
    /// the reference fit is pixel-true and growth happens only
    /// beyond it.</summary>
    public static double RequiredHeight(PresenceScheme scheme,
        string boldSegment, string regularSegment)
    {
        var compact = scheme.Detail == PresenceDetail.CompactPill;
        var scale = scheme.SizePct / 100.0;
        var fontSize = (compact ? CompactFontSize : FontSize) * scale;
        var lines = WrapLines(boldSegment, regularSegment,
            TextMaxWidth * scale, fontSize);
        var needed = TextHeight(lines, fontSize) + VerticalPadding * scale;
        var baseH = (compact ? CompactBaseHeight : BaseHeight) * scale;
        return Math.Max(baseH, Math.Ceiling(needed));
    }

    /// <summary>Convenience for the controlling branch: the
    /// board sentence (PillSentence) for this pairing name.</summary>
    public static double RequiredHeightForName(PresenceScheme scheme, string agentName)
    {
        var (bold, rest) = PresenceComposition.PillSentence(agentName);
        return RequiredHeight(scheme, bold, rest);
    }
}

/// <summary>
/// W117 / F4 — the parked Ghost's dimming step. The signed
/// revision (REVISION-DRAFT S11) says the Ghost "parks dimmed";
/// W115's live capture read the parked ring at FULL saturation
/// (#7C4DFF) — no dimmed parked state existed. This is a STATE
/// BEHAVIOR in the renderer, not a user color change: the
/// owner's scheme (W85) is never read or written differently —
/// the same scheme color is drawn through this named step while
/// the Ghost sits at its park position, and at full strength
/// the moment it drives. Dimming is two-channel (opacity AND
/// saturation) so it reads as dimmed on any wallpaper, light or
/// dark, and never as a different agent (the initial and the
/// ring geometry do not change).
/// </summary>
public static class GhostDimming
{
    /// <summary>Window opacity while parked (active = 1.0).</summary>
    public const double ParkedOpacity = 0.55;
    /// <summary>Window opacity while driving / dwelling.</summary>
    public const double ActiveOpacity = 1.0;
    /// <summary>How much of the halo color's saturation survives
    /// parked: the parked color keeps 45% of its distance from
    /// its own luminance gray.</summary>
    public const double ParkedSaturationScale = 0.45;

    /// <summary>The parked form of a color: same hue direction,
    /// pulled toward its own luminance gray by the saturation
    /// scale; alpha untouched (visibility floor is the scheme's
    /// business, already clamped there).</summary>
    public static int DimmedArgb(int argb)
    {
        var a = (argb >> 24) & 0xFF;
        var r = (argb >> 16) & 0xFF;
        var g = (argb >> 8) & 0xFF;
        var b = argb & 0xFF;
        var gray = (int)Math.Round(0.2126 * r + 0.7152 * g + 0.0722 * b);
        int Pull(int c) => (int)Math.Round(gray + (c - gray) * ParkedSaturationScale);
        return (a << 24) | (Pull(r) << 16) | (Pull(g) << 8) | Pull(b);
    }

    /// <summary>The opacity a Ghost window carries in a state.</summary>
    public static double OpacityFor(bool parked) => parked ? ParkedOpacity : ActiveOpacity;
}

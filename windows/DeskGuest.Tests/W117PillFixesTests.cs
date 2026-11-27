using DeskGuest.Shared.Design;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Tests;

/// <summary>
/// W117 — presence pill fixes, from W115's live evidence:
///  F1 the pill sentence CLIPPED at a 10-char pairing name
///     (3-line wrap in the fixed-height pill, line 3 severed
///     mid-glyph). The pill now grows HEIGHT-ONLY beyond the
///     reference fit: "Axle" stays pixel-true at 640×94, and
///     PillLayout's conservative wrap estimator + the shell's
///     content-sized height guarantee the whole sentence at
///     any plausible name length (pinned at 1/10/20/30 chars,
///     measuring estimated text bounds vs pill bounds the way
///     W115 measured glyph rows: text height must fit inside
///     the pill height minus its padding, with lines to spare
///     accounted exactly).
///  F2 the owner-driving branch named NO agent ("Paused —
///     you're driving" only). Every presence branch now renders
///     the pairing's name through the one home
///     (PresenceComposition.BranchSentence) — the FR-121 rule
///     extended to all branches.
///  F4 the parked Ghost read FULL saturation live; the signed
///     revision says it "parks dimmed". GhostDimming is the
///     named step (opacity 0.55, saturation ×0.45), applied as
///     a renderer state behavior — never a scheme change.
/// </summary>
public class W117PillFixesTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    private static string NameOfLength(int n)
    {
        // Plausible pairing names at exact lengths (letters,
        // digits and a space — the W115 name's own alphabet).
        var pool = "W115 Proof Agent Seven Three Nine";
        return pool[..n];
    }

    // ---------- F1: no clipped line at any plausible length ----------

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    public void Pill_FitsItsWholeSentence_AtNameLength(int length)
    {
        var scheme = PresenceScheme.Default;
        var name = NameOfLength(length);
        Assert.Equal(length, name.Length);
        var (bold, rest) = PresenceComposition.PillSentence(name);
        var lines = PillLayout.WrapLines(bold, rest,
            PillLayout.TextMaxWidth, PillLayout.FontSize);
        var textHeight = PillLayout.TextHeight(lines, PillLayout.FontSize);
        var pillHeight = PillLayout.RequiredHeight(scheme, bold, rest);
        // The W115 measurement, as a pin: the rendered text
        // bounds (lines × line height) must fit INSIDE the pill
        // bounds (height minus the pill's own vertical padding).
        Assert.True(textHeight <= pillHeight - PillLayout.VerticalPadding,
            $"len {length}: text {textHeight} in {lines} lines vs pill {pillHeight}");
        // Width never grows: the floor's 640 holds at every length.
        Assert.Equal(640, PillLayout.BaseWidth);
    }

    [Fact]
    public void Pill_ReferenceName_StaysPixelTrue_AndGrowthIsBeyondItOnly()
    {
        var scheme = PresenceScheme.Default;
        // The reference name: exactly the floor's 640×94.
        Assert.Equal(PillLayout.BaseHeight,
            PillLayout.RequiredHeightForName(scheme, "Axle"));
        Assert.Equal(94, PillLayout.BaseHeight);
        // The W115 defect case (10 chars) grows past it.
        Assert.True(PillLayout.RequiredHeightForName(scheme, NameOfLength(10))
            > PillLayout.BaseHeight);
        // Growth is monotonic in name length — a longer name
        // never gets a shorter pill.
        var heights = new[] { 1, 10, 20, 30 }
            .Select(n => PillLayout.RequiredHeightForName(scheme, NameOfLength(n))).ToList();
        Assert.Equal(heights.OrderBy(h => h), heights);
        // Token geometry untouched by the growth rule.
        Assert.Equal(unchecked((int)0xFF0F2537), PresenceLaw.PillBackground);
        Assert.Equal(unchecked((int)0xFFE5A93B), PresenceLaw.PillTrimGold);
        Assert.Equal(unchecked((int)0xFFDC2626), PresenceLaw.PillStopRed);
    }

    [Fact]
    public void Pill_ShellNeverFixesTheHeight_AndContentCarriesTheMinimum()
    {
        var presence = SrcFile("DeskGuest.SessionAgent", "Presence.cs");
        var pill = SrcFile("DeskGuest.SessionAgent", "PillVisual.cs");
        // The shell sizes to content in BOTH axes for the pill
        // and floors at the base height — no fixed pill height
        // survives anywhere in the shell.
        Assert.Contains("SizeToContent = SizeToContent.WidthAndHeight", presence);
        Assert.Contains("MinHeight = pill ? PillVisual.HeightFor(Scheme)", presence);
        Assert.Contains("Height = double.NaN,", presence);
        Assert.DoesNotContain("pill ? SizeToContent.Width : SizeToContent.WidthAndHeight", presence);
        // The content grid carries the estimator's minimum.
        Assert.Contains("PillLayout.RequiredHeight", pill);
        Assert.Contains("grid.MinHeight", pill);
        Assert.Contains("PillLayout.RequiredHeightForName", pill);
    }

    // ---------- F2: every branch names the driver ----------

    [Theory]
    [InlineData(PresenceComposition.PresenceBranch.Driving)]
    [InlineData(PresenceComposition.PresenceBranch.OwnerDriving)]
    [InlineData(PresenceComposition.PresenceBranch.Waiting)]
    [InlineData(PresenceComposition.PresenceBranch.Gate)]
    [InlineData(PresenceComposition.PresenceBranch.Blocked)]
    public void EveryBranch_RendersThePairingsName(PresenceComposition.PresenceBranch branch)
    {
        var sentence = PresenceComposition.BranchSentence(branch, "W115 Proof");
        Assert.Contains("W115 Proof", sentence);
        Assert.DoesNotContain(PresenceComposition.GenericHeaderText, sentence);
    }

    [Fact]
    public void OwnerDriving_KeepsTheCopyRegister_AndNamesTheAgent()
    {
        var s = PresenceComposition.BranchSentence(
            PresenceComposition.PresenceBranch.OwnerDriving, "W115 Proof");
        Assert.Equal("W115 Proof is paused — you're driving", s);
        Assert.Contains("you're driving", s);
    }

    [Fact]
    public void BlockedBranch_EqualsTheAgentsBlockedFormatString()
    {
        // The two homes (shared composition + the SessionAgent's
        // Strings table) cannot drift apart.
        var strings = SrcFile("DeskGuest.SessionAgent", "Strings.cs");
        Assert.Contains("[\"PresenceBlockedFormat\"] = \"{0} is blocked — STOP is in force\"", strings);
        Assert.Equal("W115 Proof is blocked — STOP is in force",
            PresenceComposition.BranchSentence(
                PresenceComposition.PresenceBranch.Blocked, "W115 Proof"));
    }

    [Fact]
    public void Renderer_StateSentence_ReadsTheBranchHome_ForEveryBranch()
    {
        var presence = SrcFile("DeskGuest.SessionAgent", "Presence.cs");
        Assert.Contains("PresenceBranch.OwnerDriving", presence);
        Assert.Contains("PresenceBranch.Waiting", presence);
        Assert.Contains("PresenceBranch.Gate", presence);
        Assert.Contains("PresenceComposition.BranchSentence", presence);
        // The preview reads the same home (shared builders law).
        var pages = SrcFile("DeskGuest.SessionAgent", "MainWindow.Pages.cs");
        Assert.Contains("PresenceComposition.BranchSentence", pages);
        // The nameless owner-driving copy is no longer a pill
        // sentence source: StateSentence never returns the bare
        // PresenceYoureDriving string on its own.
        Assert.DoesNotContain("_ownerDriving ? Strings.Get(\"PresenceYoureDriving\")", presence);
    }

    // ---------- F4: parked Ghost dims ----------

    private static double Saturation(int argb)
    {
        var r = ((argb >> 16) & 0xFF) / 255.0;
        var g = ((argb >> 8) & 0xFF) / 255.0;
        var b = (argb & 0xFF) / 255.0;
        var (mx, mn) = (Math.Max(r, Math.Max(g, b)), Math.Min(r, Math.Min(g, b)));
        return mx == 0 ? 0 : (mx - mn) / mx;
    }

    [Fact]
    public void ParkedDimming_IsANamedStep_ThatDropsSaturationAndOpacity()
    {
        Assert.Equal(0.55, GhostDimming.ParkedOpacity);
        Assert.Equal(1.0, GhostDimming.ActiveOpacity);
        Assert.Equal(0.45, GhostDimming.ParkedSaturationScale);
        Assert.True(GhostDimming.OpacityFor(parked: true) < GhostDimming.OpacityFor(parked: false));
        var violet = PresenceLaw.HueAi; // the W115-sampled #7C4DFF family
        var dimmed = GhostDimming.DimmedArgb(violet);
        Assert.True(Saturation(dimmed) < Saturation(violet) * 0.75,
            $"parked saturation {Saturation(dimmed)} vs active {Saturation(violet)}");
        // Chroma (max-min channel spread) drops to the named
        // scale of the active color's spread, by construction.
        static int Spread(int argb)
        {
            var r = (argb >> 16) & 0xFF; var g = (argb >> 8) & 0xFF; var b = argb & 0xFF;
            return Math.Max(r, Math.Max(g, b)) - Math.Min(r, Math.Min(g, b));
        }
        Assert.True(Spread(dimmed) <= Spread(violet) * 0.5,
            $"parked spread {Spread(dimmed)} vs active {Spread(violet)}");
        // Alpha untouched: dimming never makes presence faint
        // past the scheme's own visibility floor.
        Assert.Equal((violet >> 24) & 0xFF, (dimmed >> 24) & 0xFF);
        // The scheme itself is untouched by the behavior.
        Assert.Equal(PresenceLaw.HueAi, PresenceScheme.Default.AiArgb);
    }

    [Fact]
    public void Ghost_RendererAppliesParkedDimming_AndDrivingUndims()
    {
        var ghost = SrcFile("DeskGuest.SessionAgent", "GhostVisual.cs");
        var presence = SrcFile("DeskGuest.SessionAgent", "Presence.cs");
        Assert.Contains("GhostDimming.DimmedArgb", ghost);
        Assert.Contains("GhostDimming.OpacityFor(parked)", ghost);
        Assert.Contains("parked: _ghostParked", presence);
        Assert.Contains("_ghostParked = false", presence); // first glide un-dims
        Assert.Contains("_ghostParked = true", presence);  // session end re-parks
        // The gallery preview draws ACTIVE ghosts (default) —
        // dimming is the live parked state, not a style.
        var pages = SrcFile("DeskGuest.SessionAgent", "MainWindow.Pages.cs");
        Assert.DoesNotContain("parked: true", pages);
    }

    // ---------- the laws the fixes must not break ----------

    [Fact]
    public void ExactlyThreeElements_AndCompositionLines_Survive()
    {
        Assert.Equal(3, PresenceComposition.SessionElements(ghostDrawn: true).Count);
        Assert.Equal(
            new[] { BoxLineKind.DriverName, BoxLineKind.StateSentence, BoxLineKind.Stop },
            PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: false));
    }
}

using System.Text.Json;
using Acp.Shared.Design;
using Acp.Shared.Presence;

namespace Acp.Tests;

/// <summary>
/// W85 / FR-105 + FR-107 + S04 residual — the Presence Customizer.
///
/// Floor invariants (pure, Acp.Shared): a scheme that would make
/// presence invisible, unnamed or STOP-less FAILS validation and
/// is neutralized by Clamp — persistence can only ever carry a
/// clamped scheme. The defaults ARE the law's functional family.
/// The compact pill still carries name + state word + STOP.
/// Alike state colors warn, never block (the words tell them
/// apart). The pointer catalogue is 30 styles (10 bases × 3
/// colorways) and every style's halo IS the scheme's state color.
///
/// Wiring pins (source): the page preview and the real Box render
/// through the SAME composition (PillVisual.BuildPillContent);
/// the gallery and the real Ghost render through the SAME drawing
/// code (GhostVisual.Build); the page saves through
/// PresencePalette.SetScheme, the palette's only appearance write
/// path; the FR-105 comfort-only copy is gone from both string
/// homes and the page; FR-107's list row names the driver via
/// SessionDriverName; Home's Ready card is back at the
/// reference's 334 so the floor sentence fits 768.
/// </summary>
public class W85PresenceCustomizerTests
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

    // ---------- the floor: invisible / unnamed / STOP-less ----------

    [Fact]
    public void Validate_RefusesAnInvisibleScheme()
    {
        var invisible = PresenceScheme.Default with
        {
            SizePct = 10, BrightnessPct = 5,
            AiArgb = 0x107C4DFF, PointerStyleId = "not-a-style",
        };
        var (errors, _) = PresenceScheme.Validate(invisible);
        Assert.True(errors.Count >= 4, string.Join("; ", errors));
    }

    [Fact]
    public void Clamp_NeutralizesAnInvisibleScheme()
    {
        var invisible = PresenceScheme.Default with
        {
            SizePct = 10, BrightnessPct = 5, BgBrightnessPct = 0,
            AiArgb = 0x107C4DFF, HumanArgb = 0x002FA84F,
            PointerStyleId = "not-a-style",
        };
        var clamped = invisible.Clamp();
        Assert.InRange(clamped.SizePct, PresenceScheme.SizeMinPct, PresenceScheme.SizeMaxPct);
        Assert.True(clamped.BrightnessPct >= PresenceScheme.BrightnessFloorPct);
        Assert.True(clamped.BgBrightnessPct >= PresenceScheme.BrightnessFloorPct);
        Assert.True(((clamped.AiArgb >> 24) & 0xFF) >= PresenceScheme.MinColorAlpha);
        Assert.True(((clamped.HumanArgb >> 24) & 0xFF) >= PresenceScheme.MinColorAlpha);
        Assert.Equal(PointerStyles.DefaultId, clamped.PointerStyleId);
        var (errors, _) = PresenceScheme.Validate(clamped);
        Assert.Empty(errors);
    }

    [Fact]
    public void Composition_AlwaysCarriesNameStateAndStop_AtBothDetailLevels()
    {
        foreach (var detail in new[] { PresenceDetail.Full, PresenceDetail.CompactPill })
        {
            var scheme = PresenceScheme.Default with { Detail = detail };
            var (errors, _) = PresenceScheme.Validate(scheme);
            Assert.Empty(errors);
            var lines = PresenceComposition.BoxLines(
                detail == PresenceDetail.CompactPill ? BoxDetailLevel.CompactMinimum : BoxDetailLevel.Full,
                hasRoster: false);
            Assert.Contains(BoxLineKind.DriverName, lines);
            Assert.Contains(BoxLineKind.StateSentence, lines);
            Assert.Contains(BoxLineKind.Stop, lines);
        }
    }

    [Fact]
    public void CompactLine_CarriesNameStateWordAndStop()
    {
        var (name, word, stop) = PresenceComposition.CompactPillLine("Axle", "Controlling");
        Assert.Equal("Axle", name);
        Assert.Equal("Controlling", word);
        Assert.Contains("STOP", stop);
    }

    [Fact]
    public void Defaults_AreTheLawFamily()
    {
        var d = PresenceScheme.Default;
        Assert.Equal(PresenceLaw.HueAi, d.AiArgb);
        Assert.Equal(PresenceLaw.HueHuman, d.HumanArgb);
        Assert.Equal(PresenceLaw.HueIdle, d.WaitingArgb);
        Assert.Equal(PresenceLaw.PillStopRed, d.StopArgb);
        Assert.False(d.IsCustomized);
        var (errors, warnings) = PresenceScheme.Validate(d);
        Assert.Empty(errors);
        Assert.Empty(warnings);
    }

    [Fact]
    public void AlikeColors_WarnButNeverBlock()
    {
        var alike = PresenceScheme.Default with { HumanArgb = PresenceScheme.Default.AiArgb };
        var (errors, warnings) = PresenceScheme.Validate(alike);
        Assert.Empty(errors);
        Assert.Contains(warnings, w => w.Contains("look very alike"));
    }

    // ---------- pointer gallery ----------

    [Fact]
    public void PointerCatalogue_IsThirtyStylesFromTenBases()
    {
        Assert.Equal(30, PointerStyles.All.Count);
        Assert.Equal(30, PointerStyles.All.Select(s => s.Id).Distinct().Count());
        Assert.Equal(10, PointerStyles.All.Select(s => s.Base).Distinct().Count());
        Assert.Equal(3, PointerStyles.All.Select(s => s.Colorway).Distinct().Count());
        Assert.True(PointerStyles.IsKnownId(PointerStyles.DefaultId));
        Assert.False(PointerStyles.IsKnownId("not-a-style"));
    }

    [Fact]
    public void PointerHalo_FollowsTheSchemeStateColor()
    {
        var scheme = PresenceScheme.Default with
        {
            AiArgb = unchecked((int)0xFF112233),
            HumanArgb = unchecked((int)0xFF445556),
        };
        foreach (var style in PointerStyles.All)
        {
            Assert.Equal(scheme.AiArgb, style.HaloArgb(scheme, PresenceLaw.Actor.Ai));
            Assert.Equal(scheme.HumanArgb, style.HaloArgb(scheme, PresenceLaw.Actor.Human));
            Assert.Equal(scheme.WaitingArgb, style.HaloArgb(scheme, PresenceLaw.Actor.Idle));
        }
    }

    [Fact]
    public void Scheme_SurvivesJsonRoundTrip()
    {
        var scheme = (PresenceScheme.Default with
        {
            SizePct = 130, Detail = PresenceDetail.CompactPill,
            AiArgb = unchecked((int)0xFF2F8BC9), PointerStyleId = "star-accent",
        }).Clamp();
        var json = JsonSerializer.Serialize(scheme);
        var back = JsonSerializer.Deserialize<PresenceScheme>(json);
        Assert.Equal(scheme, back);
    }

    // ---------- FR-107: the list row's driver name ----------

    [Fact]
    public void DriverName_ResolvesFloorHolderThenInitiator()
    {
        var parts = new List<(string UserId, string Name, string Floor)>
        {
            ("u1", "Priya", ""), ("u2", "Tom", "holder"),
        };
        Assert.Equal("Tom", SessionDriverName.Resolve("Priya", "u2", parts));
        Assert.Equal("Tom", SessionDriverName.Resolve("Priya", "Tom", parts));
        Assert.Equal("Tom", SessionDriverName.Resolve("Priya", null, parts));
        Assert.Equal("Priya", SessionDriverName.Resolve("Priya", null,
            new List<(string UserId, string Name, string Floor)> { ("u1", "Priya", "") }));
    }

    // ---------- wiring pins ----------

    [Fact]
    public void PreviewAndRealBox_ShareOneComposition()
    {
        var presence = SrcFile("Acp.SessionAgent", "Presence.cs");
        var pages = SrcFile("Acp.SessionAgent", "MainWindow.Pages.cs");
        Assert.Contains("PillVisual.BuildPillContent", presence);
        Assert.Contains("PillVisual.BuildPillContent", pages);
        Assert.Contains("PillVisual.CreateStopButton", presence);
        Assert.Contains("PillVisual.CreateStopButton", pages);
    }

    [Fact]
    public void GalleryAndRealGhost_ShareOneDrawingCode()
    {
        var presence = SrcFile("Acp.SessionAgent", "Presence.cs");
        var pages = SrcFile("Acp.SessionAgent", "MainWindow.Pages.cs");
        Assert.Contains("GhostVisual.Build", presence);
        Assert.Contains("GhostVisual.Build", pages);
        Assert.Contains("PointerStyles.ById(Scheme.PointerStyleId)", presence);
    }

    [Fact]
    public void Page_SavesThroughThePalettesOnlyAppearanceWritePath()
    {
        var pages = SrcFile("Acp.SessionAgent", "MainWindow.Pages.cs");
        var palette = SrcFile("Acp.SessionAgent", "PresencePalette.cs");
        Assert.Contains("PresencePalette.Load().SetScheme(_w85Working)", pages);
        Assert.Contains("public void SetScheme(PresenceScheme scheme)", palette);
        Assert.Contains("public PresenceScheme Scheme", palette);
        // The mode toggle + the plain not-in-this-version line.
        Assert.Contains("Strings.Get(\"PresenceModeBackground\")", pages);
        Assert.Contains("Strings.Get(\"PresenceBgNote\")", pages);
        // The W73 section is integrated, not duplicated or dropped.
        Assert.Contains("p.SetTakeoverModes(", pages);
    }

    [Fact]
    public void Fr105Copy_IsGoneFromBothStringHomesAndThePage()
    {
        var stringsCs = SrcFile("Acp.SessionAgent", "Strings.cs");
        var stringsResx = SrcFile("Acp.SessionAgent", "Strings.resx");
        var pages = SrcFile("Acp.SessionAgent", "MainWindow.Pages.cs");
        Assert.DoesNotContain("PresenceComfortOnly", stringsCs);
        Assert.DoesNotContain("PresenceComfortOnly", stringsResx);
        Assert.DoesNotContain("They are not a setting", stringsCs);
        Assert.DoesNotContain("They are not a setting", stringsResx);
        Assert.DoesNotContain("Get(\"PresenceComfortOnly\")", pages);
        // The floor sentence of record is what the page leads with.
        Assert.Contains("PresenceFloorSentence", stringsCs);
        Assert.Contains("PresenceFloorSentence", stringsResx);
    }

    [Fact]
    public void Page_ResourceKeys_AllExistInTheTheme()
    {
        // Regression pin for the W85 first-deploy crash: the page
        // asked FindResource for "AccentBrush"/"BorderBrush",
        // which do not exist (the theme's keys are DgBlueBrush /
        // DgBorderBrush) — an unhandled
        // ResourceReferenceKeyNotFoundException killed the agent
        // on first render of the page. Every key the page's W85
        // code requests must exist as an x:Key in the app XAML.
        var pages = SrcFile("Acp.SessionAgent", "MainWindow.Pages.cs");
        Assert.DoesNotContain("\"AccentBrush\"", pages);
        Assert.DoesNotContain("\"BorderBrush\"", pages);
        var theme = SrcFile("Acp.SessionAgent", "DeskGuestTheme.xaml");
        var window = SrcFile("Acp.SessionAgent", "MainWindow.xaml");
        foreach (var key in new[]
        {
            "DgBlueBrush", "DgBorderBrush", "DgSurfaceBrush", "DgTextBrush",
            "DgMutedBrush", "DgRedBrush",
        })
            Assert.Contains($"x:Key=\"{key}\"", theme);
        foreach (var key in new[] { "SectionLabel", "PrimaryButton", "GhostButton", "Card" })
            Assert.Contains($"x:Key=\"{key}\"", window);
    }

    [Fact]
    public void SessionListRow_NamesTheDriver()
    {
        var roster = SrcFile("Acp.SessionAgent", "MainWindow.RosterSessions.cs");
        Assert.Contains("SessionDriverName.Resolve", roster);
        Assert.Contains("driven by", roster);
    }

    [Fact]
    public void Home_ReadyCardIsBackAtTheReferenceHeight()
    {
        var home = SrcFile("Acp.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("readyCard.Height = 334", home);
        Assert.DoesNotContain("readyCard.Height = 343", home);
    }
}

using System.Text.RegularExpressions;
using System.Xml.Linq;
using Acp.Shared.Design;
using Acp.Shared.Ipc;
using Acp.Shared.Presence;

namespace Acp.Tests;

/// <summary>
/// W60-A (FR-111 / FR-114) — ONE presence system, pinned.
/// W72 AMENDMENT (2026-11-23, micro-decision under delegation,
/// W71 BUILD-SPEC §1): the Box's live form is the Screen 11
/// PILL. The takeover hint no longer prints on the Box at any
/// detail level (STOP (ESC) is the visible control path;
/// touch-to-yield still functions and is taught in setup/help),
/// roster/elapsed no longer print, and Full == CompactMinimum
/// == [name, state, STOP]. The five pins this forced are
/// re-named decision-driven tests below, each marked W72.
/// (1) A session composes exactly Box + Glow + Ghost; the
/// takeover hint is never an element or a window, and (W72)
/// never a Box line either. (2) At the FR-105 compact minimum
/// the Box is exactly name + state + STOP — and (W72) so is
/// Full: the pill form itself satisfies the floor. (3) The gate
/// is a card within the system: no presence header of its own,
/// the generic header sentence absent from the whole session
/// presence path. (4) FR-114 lifecycle: a gate prompt whose gate
/// times out, is decided, or loses its session dismisses itself
/// and its exits are inert — a dead gate never presents a live
/// Approve. (5) Gate exit contrast: the system's colour pairs
/// meet WCAG AA with margin, bound through an explicit template.
/// </summary>
public class W60PresenceCompositionTests
{
    private static string SessionAgentDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var rel in new[]
            {
                Path.Combine("src", "Acp.SessionAgent"),
                Path.Combine("windows-agent", "src", "Acp.SessionAgent"),
            })
            {
                var candidate = Path.Combine(dir.FullName, rel);
                if (Directory.Exists(candidate)) return candidate;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Acp.SessionAgent source dir not found above " + AppContext.BaseDirectory);
    }

    private static string ReadAgent(string file) =>
        File.ReadAllText(Path.Combine(SessionAgentDir(), file));

    // ---------- (1) composition: exactly three elements ----------

    [Fact]
    public void Session_composes_exactly_box_glow_ghost()
    {
        Assert.Equal(
            new[] { PresenceElementKind.Box, PresenceElementKind.Glow, PresenceElementKind.Ghost },
            PresenceComposition.SessionElements(ghostDrawn: true).ToArray());
        Assert.Equal(3, PresenceComposition.SessionElements(ghostDrawn: true).Distinct().Count());
        Assert.Equal(PresenceLaw.Elements.Count, PresenceComposition.SessionElements(ghostDrawn: true).Count);
        // Ghost withdrawn (gate up / owner driving): still the
        // same system, one element fewer — never a fourth kind.
        Assert.Equal(
            new[] { PresenceElementKind.Box, PresenceElementKind.Glow },
            PresenceComposition.SessionElements(ghostDrawn: false).ToArray());
    }

    [Fact]
    public void Gate_up_composition_is_box_and_glow_and_the_card_is_not_an_element()
    {
        Assert.Equal(
            new[] { PresenceElementKind.Box, PresenceElementKind.Glow },
            PresenceComposition.GateElements().ToArray());
        Assert.DoesNotContain(PresenceComposition.GateCardKind, PresenceLaw.Elements);
        Assert.DoesNotContain(PresenceElementKind.Ghost, PresenceComposition.GateElements());
    }

    // ---------- (2) the pill's lines (W72 decision-driven) ----------

    [Fact]
    public void Box_lines_full_is_name_state_stop_pill_form()
    {
        // W72 pin change 1 (decision-driven, ex
        // Box_lines_full_order_hint_is_the_bottom_line_below_stop):
        // the pill prints exactly name + state + STOP; the hint
        // is not a Box line at any level.
        var lines = PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: false);
        Assert.Equal(
            new[] { BoxLineKind.DriverName, BoxLineKind.StateSentence, BoxLineKind.Stop },
            lines.ToArray());
        Assert.Equal(BoxLineKind.Stop, lines[^1]);
        Assert.DoesNotContain(BoxLineKind.TakeoverHint, lines);
    }

    [Fact]
    public void Box_lines_full_with_roster_prints_no_roster_line()
    {
        // W72 pin change 2 (decision-driven, ex
        // Box_lines_full_with_roster_folds_roster_before_stop):
        // roster no longer prints on the Box; hasRoster is kept
        // for signature stability and changes nothing.
        Assert.Equal(
            new[] { BoxLineKind.DriverName, BoxLineKind.StateSentence, BoxLineKind.Stop },
            PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: true).ToArray());
        Assert.DoesNotContain(BoxLineKind.Roster,
            PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: true));
    }

    [Fact]
    public void Box_lines_compact_minimum_is_name_state_stop_and_full_equals_compact()
    {
        // W72 pin change 3 (decision-driven): the FR-105 floor
        // stands — at minimum detail the Box carries exactly
        // agent name + state word + STOP — and the pill form
        // satisfies it at Full too: Full == CompactMinimum.
        var lines = PresenceComposition.BoxLines(BoxDetailLevel.CompactMinimum, hasRoster: true);
        Assert.Equal(
            new[] { BoxLineKind.DriverName, BoxLineKind.StateSentence, BoxLineKind.Stop },
            lines.ToArray());
        Assert.DoesNotContain(BoxLineKind.TakeoverHint, lines);
        Assert.DoesNotContain(BoxLineKind.Roster, lines);
        Assert.Equal(lines.ToArray(),
            PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: true).ToArray());
        Assert.Equal(lines.ToArray(),
            PresenceComposition.BoxLines(BoxDetailLevel.Full, hasRoster: false).ToArray());
    }

    [Fact]
    public void Pill_sentence_is_the_board_sentence_with_the_live_name_bold()
    {
        // W72: one home for the pill sentence — Board 4 Screen 11
        // verbatim, with the LIVE pairing name in the bold segment.
        var (bold, rest) = PresenceComposition.PillSentence("Axle");
        Assert.Equal("Axle (AI Agent)", bold);
        Assert.Equal(" is controlling your computer — You see everything", rest);
        var (bold2, rest2) = PresenceComposition.PillSentence("W69 Proof");
        Assert.Equal("W69 Proof (AI Agent)", bold2);
        Assert.Equal(rest, rest2);
    }

    [Fact]
    public void Takeover_hint_text_is_exact_and_agrees_across_every_table()
    {
        const string expected = "Press Ctrl + Alt + Shift + Backspace to take over";
        Assert.Equal(expected, PresenceComposition.TakeoverHintText);
        Assert.Contains(PresenceComposition.TakeoverChordText, PresenceComposition.TakeoverHintText);
        // The shared design table (the Android-mirrored door).
        Assert.Equal(expected, DesignStrings.Get("presence_takeover_hint"));
        // The SessionAgent U8 table: built-in default AND resx.
        var cs = ReadAgent("Strings.cs");
        var m = Regex.Match(cs, "\\[\"PresenceTakeoverHint\"\\] = \"((?:[^\"\\\\]|\\\\.)*)\"");
        Assert.True(m.Success, "Strings.cs carries PresenceTakeoverHint");
        Assert.Equal(expected, Regex.Unescape(m.Groups[1].Value));
        var resx = XDocument.Load(Path.Combine(SessionAgentDir(), "Strings.resx"));
        var value = resx.Root!.Elements("data")
            .Single(d => d.Attribute("name")!.Value == "PresenceTakeoverHint")
            .Element("value")!.Value;
        Assert.Equal(expected, value);
    }

    [Fact]
    public void Renderer_composes_the_pill_from_the_model_and_never_renders_the_hint()
    {
        // W72 pin change 4 (decision-driven, ex
        // Renderer_composes_the_box_from_the_model_and_the_hint_from_the_strings_door):
        // the renderer consumes the composition model AND the
        // pill sentence home AND the pill STOP key — and the
        // takeover hint is NOT rendered by the Box.
        // W85 pin change (decision-driven): FR-105 requires the
        // Presence page's live preview to render through the SAME
        // composition code as the real Box, so the composition
        // moved from Presence.cs into PillVisual.cs — the shared
        // builder PresenceLayer.BoxContent delegates to (pinned
        // in W85PresenceCustomizerTests). The three consumptions
        // are therefore asserted across the layer + its builder;
        // the hint bans stay on Presence.cs itself.
        var code = ReadAgent("Presence.cs") + ReadAgent("PillVisual.cs");
        Assert.Contains("PresenceComposition.BoxLines", code);
        Assert.Contains("PresenceComposition.PillSentence", code);
        Assert.Contains("Strings.Get(\"StopEsc\")", code);
        code = ReadAgent("Presence.cs");
        Assert.DoesNotContain("BoxLineKind.TakeoverHint", code);
        Assert.DoesNotContain("PresenceTakeoverHint", code);
        Assert.DoesNotContain("TakeoverHintTextBlock", code);
    }

    [Fact]
    public void Pill_colours_are_the_reference_tokens_and_gold_is_controlling_only_in_the_renderer()
    {
        // FR-117 / Q1 reconciliation: pill navy + gold trim +
        // emergency red are the reference's own token values;
        // the renderer applies gold only in the controlling
        // (Actor.Ai) state.
        Assert.Equal(unchecked((int)0xFF0F2537), PresenceLaw.PillBackground);
        Assert.Equal(unchecked((int)0xFFE5A93B), PresenceLaw.PillTrimGold);
        Assert.Equal(unchecked((int)0xFFDC2626), PresenceLaw.PillStopRed);
        var code = ReadAgent("Presence.cs");
        Assert.Contains("PresenceLaw.Actor.Ai ? PillGold : CurrentHue", code);
        Assert.Contains("PresenceLaw.Actor.Ai ? PillGold : CurrentHue", code);
    }

    [Fact]
    public void Presence_layer_builds_only_the_known_windows_no_hint_window_exists()
    {
        var code = ReadAgent("Presence.cs");
        Assert.DoesNotContain("BuildHint", code);
        Assert.DoesNotContain("HintWindow", code);
        Assert.DoesNotContain("HintBar", code);
        // Every window the layer constructs: BoxShell (Box +
        // mirrors), the blocked Box, one Glow per display, the
        // Ghost. Three `new Window` sites + BoxShell's target-typed
        // construction — and no other window builder methods.
        Assert.Equal(3, Regex.Matches(code, @"new Window\b").Count);
        var builders = Regex.Matches(code, @"private (?:static )?(?:Window|UIElement) (\w+)\(")
            .Select(m => m.Groups[1].Value).ToHashSet();
        Assert.Equal(
            new HashSet<string> { "BoxShell", "BoxContent", "BuildGlowWindow", "BuildGhostWindow" },
            builders);
        var voidBuilders = Regex.Matches(code, @"private void (Build\w+)\(")
            .Select(m => m.Groups[1].Value).ToHashSet();
        // W76 (FR-121) decision-driven addition: BuildDefectBox is
        // a fourth Box builder — the refusal surface an unnamed
        // session gets INSTEAD of presence. It builds through
        // BoxShell (no new `new Window` site — the count above
        // still pins 3), draws no glow/ghost/pill, and exists only
        // in the defect state, so the composition law (exactly
        // Box + Glow + Ghost for a session) is untouched.
        Assert.Equal(
            new HashSet<string> { "BuildActiveBox", "BuildBlockedBox", "BuildNoticeBox", "BuildDefectBox" },
            voidBuilders);
    }

    // ---------- (3) the gate is a card, no generic header ----------

    [Fact]
    public void Generic_header_is_absent_from_the_whole_session_presence_path()
    {
        var dir = SessionAgentDir();
        foreach (var file in Directory.EnumerateFiles(dir, "*.cs").Concat(Directory.EnumerateFiles(dir, "*.xaml")))
        {
            var code = File.ReadAllText(file);
            Assert.False(code.Contains(PresenceComposition.GenericHeaderText, StringComparison.OrdinalIgnoreCase),
                $"{Path.GetFileName(file)} renders the generic presence header");
            // W74 precision fix: the law bans the GENERIC form — a
            // controlling-line with no driver name. A plain string
            // literal that IS a controlling-line (no interpolation,
            // ends at "computer") is unnamed by construction and is
            // banned; the NAMED form built from the pairing name
            // ($"{name} is controlling this computer", the Home
            // session card heading) is what the presence law
            // REQUIRES and is pinned positively below.
            Assert.False(Regex.IsMatch(code, "\"[^\"{]*is controlling this computer\"", RegexOptions.IgnoreCase),
                $"{Path.GetFileName(file)} renders an unnamed controlling-this-computer line");
            Assert.False(code.Contains("An agent is controlling", StringComparison.OrdinalIgnoreCase),
                $"{Path.GetFileName(file)} renders the fallback-labelled controlling line as copy");
        }
    }

    [Fact]
    public void Home_session_heading_is_built_from_the_pairing_name()
    {
        // W74: the Home session card heading is the named form —
        // interpolated from `name`, destructured out of the
        // presence layer's ViewState in RenderOverview, whose
        // DisplayName is the state machine's AgentName (the
        // pairing's name, carried over IPC). It is never a
        // literal and never the generic header.
        var main = ReadAgent("MainWindow.xaml.cs");
        Assert.Contains("$\"{name} is controlling this computer\"", main);
        Assert.Contains("sessionActive, name, seconds, actions", main);
        Assert.Contains("_presence.ViewState", main);
        var presence = ReadAgent("Presence.cs");
        Assert.Contains("_machine.DisplayName", presence);
    }

    [Fact]
    public void Gate_sheet_carries_no_presence_header_and_binds_its_lifecycle_at_the_caller()
    {
        var gate = ReadAgent("GateSheet.cs");
        Assert.DoesNotContain("ControllingThisPc", gate);
        Assert.DoesNotContain("ControllingYourPc", gate);
        Assert.Contains("GatePromptLifecycle", gate);
        Assert.Contains("PresenceComposition.GateCardColors", gate);
        var app = ReadAgent("App.xaml.cs");
        Assert.Contains("expiresUtc: request.ExpiresUtc", app);
        Assert.Contains("sessionLive:", app);
        Assert.Contains("presence.ViewState.SessionActive", app);
    }

    // ---------- (5) gate exit contrast ----------

    [Fact]
    public void Gate_exit_colour_pairs_meet_wcag_aa_with_margin()
    {
        var approve = PresenceComposition.ContrastRatio(
            PresenceComposition.GateCardColors.ApproveBackground,
            PresenceComposition.GateCardColors.ApproveForeground);
        var deny = PresenceComposition.ContrastRatio(
            PresenceComposition.GateCardColors.DenyBackground,
            PresenceComposition.GateCardColors.DenyForeground);
        Assert.True(approve >= 7.0, $"Approve pair contrast {approve:F2} < 7.0 (WCAG AAA)");
        Assert.True(deny >= 7.0, $"Deny pair contrast {deny:F2} < 7.0 (WCAG AAA)");
        // The Deny label also stays legible against the card fill
        // itself, so no fill failure can strand it.
        var denyOnCard = PresenceComposition.ContrastRatio(
            PresenceComposition.GateCardColors.CardBackground,
            PresenceComposition.GateCardColors.DenyForeground);
        Assert.True(denyOnCard >= 7.0, $"Deny-on-card contrast {denyOnCard:F2} < 7.0");
    }

    [Fact]
    public void Gate_exits_are_bound_through_an_explicit_template()
    {
        var gate = ReadAgent("GateSheet.cs");
        Assert.Contains("ControlTemplate", gate);
        Assert.Contains("ExitTemplate", gate);
        Assert.Contains("RelativeSourceMode.TemplatedParent", gate);
    }

    // ---------- (4) FR-114 prompt lifecycle ----------

    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Prompt_shown_then_gate_times_out_prompt_dismisses_and_exits_go_inert()
    {
        var expiry = T0 + GateRequestBroker.DefaultTimeout;
        Assert.Equal(GatePromptState.Live,
            GatePromptLifecycle.Evaluate(T0 + TimeSpan.FromSeconds(29), expiry, sessionLive: true, decided: false));
        var dead = GatePromptLifecycle.Evaluate(T0 + TimeSpan.FromSeconds(30), expiry, sessionLive: true, decided: false);
        Assert.Equal(GatePromptState.Expired, dead);
        Assert.True(GatePromptLifecycle.ShouldDismiss(dead));
        Assert.False(GatePromptLifecycle.ExitsLive(dead, armed: true));
    }

    [Fact]
    public void Prompt_shown_then_session_ends_prompt_dismisses_and_exits_go_inert()
    {
        var expiry = T0 + GateRequestBroker.DefaultTimeout;
        var dead = GatePromptLifecycle.Evaluate(T0 + TimeSpan.FromSeconds(5), expiry, sessionLive: false, decided: false);
        Assert.Equal(GatePromptState.SessionEnded, dead);
        Assert.True(GatePromptLifecycle.ShouldDismiss(dead));
        Assert.False(GatePromptLifecycle.ExitsLive(dead, armed: true));
    }

    [Fact]
    public void Prompt_exits_are_live_only_when_live_and_armed_and_a_decision_closes_via_its_own_path()
    {
        var expiry = T0 + GateRequestBroker.DefaultTimeout;
        Assert.False(GatePromptLifecycle.ExitsLive(GatePromptState.Live, armed: false));
        Assert.True(GatePromptLifecycle.ExitsLive(GatePromptState.Live, armed: true));
        var decided = GatePromptLifecycle.Evaluate(T0 + TimeSpan.FromSeconds(5), expiry, sessionLive: true, decided: true);
        Assert.Equal(GatePromptState.Decided, decided);
        Assert.False(GatePromptLifecycle.ShouldDismiss(decided));
        Assert.False(GatePromptLifecycle.ExitsLive(decided, armed: true));
    }

    [Fact]
    public void Prompt_expiry_resolution_is_always_finite_and_the_wire_expiry_wins()
    {
        var wire = T0 + TimeSpan.FromSeconds(30);
        Assert.Equal(wire, GatePromptLifecycle.ResolveExpiry(T0, wire, T0 + TimeSpan.FromSeconds(1)));
        Assert.Equal(T0 + GateRequestBroker.DefaultTimeout,
            GatePromptLifecycle.ResolveExpiry(T0, default, T0 + TimeSpan.FromSeconds(1)));
        var shownOnly = GatePromptLifecycle.ResolveExpiry(default, default, T0);
        Assert.Equal(T0 + GateRequestBroker.DefaultTimeout, shownOnly);
        Assert.True(shownOnly > DateTimeOffset.MinValue);
    }

    [Fact]
    public void Broker_refuses_answers_for_the_dead_gates_the_prompt_mirrors()
    {
        var broker = new GateRequestBroker();
        var req = broker.Register("pair1", "sess1", "file_delete", "file_delete",
            new byte[] { 1, 2, 3 }, fromChat: false, T0);
        // After the 30 s window the broker itself refuses — the
        // prompt retiring at the same instant is a mirror, not a
        // second policy.
        Assert.Equal(GateResolution.Expired,
            broker.TryAnswer(req.Id, GateAnswers.Allow, "sess1", T0 + TimeSpan.FromSeconds(31), out _, out var accepted));
        Assert.Null(accepted);
        // Session end kills a fresh gate's answer the same way.
        var req2 = broker.Register("pair1", "sess1", "file_delete", "file_delete",
            new byte[] { 4 }, fromChat: false, T0);
        Assert.Equal(GateResolution.SessionEnded,
            broker.TryAnswer(req2.Id, GateAnswers.Allow, "sess2", T0 + TimeSpan.FromSeconds(2), out _, out accepted));
        Assert.Null(accepted);
        var req3 = broker.Register("pair1", "sess1", "file_delete", "file_delete",
            new byte[] { 5 }, fromChat: false, T0);
        Assert.Equal(1, broker.InvalidateSession("sess1"));
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(req3.Id, GateAnswers.Allow, "sess1", T0 + TimeSpan.FromSeconds(2), out _, out accepted));
        Assert.Null(accepted);
    }
}

/// <summary>W60-A destruction pass: hostile readings of the
/// composition + lifecycle models — every way a fourth element,
/// a stray hint window, or a live Approve for a dead gate could
/// sneak back in.</summary>
public class W60PresenceCompositionDestructionTests
{
    [Fact]
    public void Destruction_no_ghost_state_and_no_detail_level_ever_yields_a_fourth_element()
    {
        foreach (var ghost in new[] { false, true })
        {
            var elements = PresenceComposition.SessionElements(ghost);
            Assert.True(elements.Count <= 3);
            Assert.Equal(elements.Count, elements.Distinct().Count());
        }
        foreach (var detail in Enum.GetValues<BoxDetailLevel>())
            foreach (var roster in new[] { false, true })
            {
                var lines = PresenceComposition.BoxLines(detail, roster);
                Assert.Equal(lines.Count, lines.Distinct().Count());
                Assert.Equal(BoxLineKind.DriverName, lines[0]);
                Assert.Contains(BoxLineKind.Stop, lines);
            }
    }

    [Fact]
    public void Destruction_a_dead_gate_never_presents_a_live_approve_in_any_combination()
    {
        foreach (var state in Enum.GetValues<GatePromptState>())
            foreach (var armed in new[] { false, true })
                Assert.Equal(state == GatePromptState.Live && armed,
                    GatePromptLifecycle.ExitsLive(state, armed));
    }

    [Fact]
    public void Destruction_expiry_boundary_is_dead_at_the_exact_instant()
    {
        var expiry = DateTimeOffset.UtcNow;
        Assert.Equal(GatePromptState.Expired,
            GatePromptLifecycle.Evaluate(expiry, expiry, sessionLive: true, decided: false));
    }

    [Fact]
    public void Destruction_session_flicker_kills_the_prompt_even_with_time_remaining()
    {
        var expiry = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5);
        Assert.Equal(GatePromptState.SessionEnded,
            GatePromptLifecycle.Evaluate(DateTimeOffset.UtcNow, expiry, sessionLive: false, decided: false));
    }

    [Fact]
    public void Destruction_decision_wins_over_expiry_and_session_end()
    {
        var past = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5);
        Assert.Equal(GatePromptState.Decided,
            GatePromptLifecycle.Evaluate(DateTimeOffset.UtcNow, past, sessionLive: false, decided: true));
    }

    [Fact]
    public void Destruction_contrast_ratio_is_symmetric_and_bounded()
    {
        var a = PresenceComposition.GateCardColors.DenyBackground;
        var b = PresenceComposition.GateCardColors.DenyForeground;
        Assert.Equal(PresenceComposition.ContrastRatio(a, b), PresenceComposition.ContrastRatio(b, a), precision: 10);
        Assert.Equal(1.0, PresenceComposition.ContrastRatio(a, a), precision: 10);
        Assert.True(PresenceComposition.ContrastRatio(a, b) <= 21.0);
    }
}

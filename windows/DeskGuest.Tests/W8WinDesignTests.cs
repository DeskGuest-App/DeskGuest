using System.Text;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

/// <summary>W8 — Windows design-of-record implementation fixtures.
/// Pins: (1) PresenceLaw byte/value equality with Android's landed
/// PresenceLaw (HeroDesign.kt — the values are read from the
/// Android source in the tree, not re-typed from memory);
/// (2) gate three-exit parity + arming + OI-12 payload fidelity;
/// (3) ledger counting — Read/Sent/Changed separate labelled
/// numbers, off-device chat = Sent, frames counted only on
/// delivery; (4) comfort-only presence settings law (floor, static
/// default); (5) host-home / fleet / setup model rules;
/// (6) EventWatchLines renders ListAll completely.</summary>
public class W8WinDesignTests
{
    private static string AndroidHeroDesign()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "agent-control-app", "android", "app", "src",
                "main", "java", "io", "deskguest", "app", "design", "HeroDesign.kt");
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("HeroDesign.kt not found above " + AppContext.BaseDirectory);
    }

    private static int AndroidInt(string kt, string name)
    {
        var m = Regex.Match(kt, name + @":\s*(?:Int|Long)\s*=\s*(0x[0-9A-Fa-f]+|[\d_]+)");
        if (!m.Success) m = Regex.Match(kt, name + @"\s*=\s*(0x[0-9A-Fa-f]+)");
        Assert.True(m.Success, name);
        var raw = m.Groups[1].Value.Replace("_", "");
        return raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? Convert.ToInt32(raw[2..], 16) : int.Parse(raw);
    }

    // ---------- (1) PresenceLaw parity with Android ----------

    [Fact]
    public void PresenceLaw_hues_match_android_byte_for_byte()
    {
        var kt = AndroidHeroDesign();
        Assert.Equal(AndroidInt(kt, "HUE_HUMAN"), PresenceLaw.HueHuman);
        Assert.Equal(AndroidInt(kt, "HUE_AI"), PresenceLaw.HueAi);
        Assert.Equal(AndroidInt(kt, "HUE_IDLE"), PresenceLaw.HueIdle);
        Assert.Equal(AndroidInt(kt, "HUE_STOP"), PresenceLaw.HueStop);
        Assert.Equal(AndroidInt(kt, "BOX_BACKGROUND"), PresenceLaw.BoxBackground);
        Assert.Equal(AndroidInt(kt, "BOX_ON_BACKGROUND"), PresenceLaw.BoxOnBackground);
    }

    [Fact]
    public void PresenceLaw_constants_match_android()
    {
        var kt = AndroidHeroDesign();
        Assert.Equal(AndroidInt(kt, "DWELL_MS"), (int)PresenceLaw.DwellMs);
        Assert.Equal(AndroidInt(kt, "SETTLE_MS"), (int)PresenceLaw.SettleMs);
        Assert.Equal(AndroidInt(kt, "GATE_ARM_MS"), (int)PresenceLaw.GateArmMs);
        Assert.Equal(AndroidInt(kt, "BOX_IN_MS"), (int)PresenceLaw.BoxInMs);
        Assert.Equal(AndroidInt(kt, "BOX_OUT_MS"), (int)PresenceLaw.BoxOutMs);
        Assert.Equal(AndroidInt(kt, "GLOW_FADE_MS"), (int)PresenceLaw.GlowFadeMs);
        Assert.Equal(AndroidInt(kt, "GATE_SHEET_MS"), (int)PresenceLaw.GateSheetMs);
        Assert.Equal(AndroidInt(kt, "GLOW_BREATH_PERIOD_MS"), (int)PresenceLaw.GlowBreathPeriodMs);
        Assert.Equal(AndroidInt(kt, "GLOW_BREATH_MIN_PCT"), PresenceLaw.GlowBreathMinPct);
    }

    [Fact]
    public void PresenceLaw_glide_formula_matches_android()
    {
        // Android: (180 + 0.25*px).toLong().coerceIn(220, 600)
        Assert.Equal(220, PresenceLaw.GlideMs(0));
        Assert.Equal(220, PresenceLaw.GlideMs(100));
        Assert.Equal(280, PresenceLaw.GlideMs(400));
        Assert.Equal(430, PresenceLaw.GlideMs(1000));
        Assert.Equal(600, PresenceLaw.GlideMs(100000));
    }

    [Fact]
    public void PresenceLaw_three_elements_and_hue_surfaces()
    {
        Assert.Equal(new[] { "BOX", "GHOST", "GLOW" }, PresenceLaw.Elements.ToArray());
        Assert.True(PresenceLaw.HueLegalOn("BOX"));
        Assert.True(PresenceLaw.HueLegalOn("TRAY_MIRROR"));
        Assert.False(PresenceLaw.HueLegalOn("HEALTH"));
        Assert.False(PresenceLaw.HueLegalOn("PRIMARY_BUTTON"));
        Assert.Equal("A", PresenceLaw.GhostInitial("Agent A"));
        Assert.Equal("?", PresenceLaw.GhostInitial("  "));
        Assert.False(PresenceLaw.GhostDrawn(gateUp: true, ownerDriving: false));
        Assert.False(PresenceLaw.GhostDrawn(gateUp: false, ownerDriving: true));
        Assert.True(PresenceLaw.GhostDrawn(gateUp: false, ownerDriving: false));
        Assert.Equal(40, PresenceLaw.GlowLegibilityFloorPct);
    }

    [Fact]
    public void PresenceSelfTest_requires_all_three_and_stop()
    {
        Assert.True(PresenceSelfTest.Evaluate(true, true, true, true).Passed);
        Assert.False(PresenceSelfTest.Evaluate(true, true, true, false).Passed);
        Assert.False(PresenceSelfTest.Evaluate(false, true, true, true).Passed);
        Assert.False(PresenceSelfTest.Evaluate(true, false, true, true).Passed);
        Assert.False(PresenceSelfTest.Evaluate(true, true, false, true).Passed);
        Assert.Contains("STOP", PresenceSelfTest.Evaluate(true, true, true, false).Failures[0]);
    }

    // ---------- (2) Gate parity ----------

    [Fact]
    public void Gate_exits_are_exactly_three_and_exactly_equal()
    {
        var exits = GateSheetModel.Exits();
        Assert.Equal(3, exits.Count);
        Assert.Equal(new[] { "Approve", "Deny", "Deny and end session" },
            exits.Select(e => e.Label).ToArray());
        Assert.All(exits, e => Assert.Equal(600, e.Weight));
        Assert.All(exits, e => Assert.Equal(1, e.BorderContrast));
        Assert.False(GateSheetModel.HasSessionAllow());
        Assert.False(GateSheetModel.CredentialTypingApprovable());
    }

    [Fact]
    public void Gate_arming_needs_600ms_AND_human_activation()
    {
        Assert.False(GateSheetModel.ControlsArmed(1000, 1599, humanActivated: true));
        Assert.True(GateSheetModel.ControlsArmed(1000, 1600, humanActivated: true));
        Assert.False(GateSheetModel.ControlsArmed(1000, 99999, humanActivated: false));
    }

    [Fact]
    public void Gate_payload_fidelity_is_byte_for_byte()
    {
        var payload = Encoding.UTF8.GetBytes("To: a@b.c\r\nSubject: x\r\n\r\nBody — exact  ");
        Assert.True(GateSheetModel.PayloadMatches(payload, payload.ToArray()));
        var trimmed = Encoding.UTF8.GetBytes("To: a@b.c\r\nSubject: x\r\n\r\nBody — exact");
        Assert.False(GateSheetModel.PayloadMatches(payload, trimmed));
        var reencoded = Encoding.UTF8.GetBytes("To: a@b.c\nSubject: x\n\nBody — exact  ");
        Assert.False(GateSheetModel.PayloadMatches(payload, reencoded));
    }

    [Fact]
    public void Gate_agent_input_on_deskguest_windows_refused_on_every_path()
    {
        foreach (var path in Enum.GetValues<GateSheetModel.InjectionPath>())
            Assert.True(GateSheetModel.AgentActionOnDeskGuestWindowRefused(path, targetIsDeskGuestWindow: true));
        Assert.False(GateSheetModel.AgentActionOnDeskGuestWindowRefused(
            GateSheetModel.InjectionPath.SendInput, targetIsDeskGuestWindow: false));
    }

    [Fact]
    public void Gate_deny_and_end_audits_before_teardown()
    {
        Assert.Equal(new[] { "audit:approval_deny_and_end", "teardown:end_session" },
            GateSheetModel.DenyAndEndSteps.ToArray());
        Assert.Equal("DRAFT · NOT SENT", GateSheetModel.DraftMarker());
        Assert.Equal("Asked from Agent chat", GateSheetModel.ChatOriginLine());
    }

    // ---------- (3) Ledger counting ----------

    [Fact]
    public void Ledger_chat_counts_as_sent_off_device()
    {
        var ledger = new DataFlowLedger();
        var t0 = new DateTimeOffset(2026, 11, 23, 9, 41, 0, TimeSpan.Zero);
        ledger.NoteChatMessage("pair-1", "Agent A", "HOST-LAPTOP", t0);
        ledger.NoteChatMessage("pair-1", "Agent A", "HOST-LAPTOP", t0);
        var report = DataFlowReport.Build(ledger.Records(), Array.Empty<DeskGuest.Shared.Audit.AuditEntry>());
        var agent = Assert.Single(report.Agents);
        var counts = SessionLedgerModel.CountsFor(agent);
        Assert.Equal(0, counts.Read);
        Assert.Equal(2, counts.Sent);
        Assert.Equal(0, counts.Changed);
        Assert.Contains("HOST-LAPTOP", agent.Destinations);
        // The chat record is a standing per-pairing record, never a session.
        Assert.All(ledger.Records(), r => Assert.True(r.OutsideSession));
    }

    [Fact]
    public void Ledger_counts_render_as_separate_labelled_numbers()
    {
        var line = SessionLedgerModel.CountsLine(new SessionLedgerModel.Counts(3, 5, 2), live: false);
        Assert.Equal("Read 3 · Sent 5 · Changed 2", line);
        Assert.DoesNotContain("=", line);
        Assert.DoesNotContain("+", line);
        var liveLine = SessionLedgerModel.CountsLine(new SessionLedgerModel.Counts(3, 5, 2), live: true);
        Assert.EndsWith("so far", liveLine);
    }

    [Fact]
    public void Ledger_frames_count_only_on_delivery()
    {
        Assert.True(SessionLedgerModel.FrameDelivered("screenshot", resultIsError: false));
        Assert.False(SessionLedgerModel.FrameDelivered("screenshot", resultIsError: true));
        Assert.False(SessionLedgerModel.FrameDelivered("shell_run", resultIsError: false));
        Assert.Equal("12 screens seen so far in this session", SessionLedgerModel.SeenSoFarLine(12));
    }

    [Fact]
    public void Ledger_model_carries_provider_vendor_gaps_and_presence_lines()
    {
        var model = SessionLedgerModel.Build("verdict", new SessionLedgerModel.Counts(1, 2, 3),
            live: true, agentName: "Agent A", destinations: new[] { "Agent A on HOST-LAPTOP" },
            gaps: new[] { "camera frames" });
        Assert.Equal("What Agent A's provider does with what it sees is outside this app.", model.ProviderLine);
        Assert.Equal("Nowhere else — DeskGuest sends nothing to anyone.", model.VendorLine);
        Assert.Equal("Not seen: camera frames", model.GapsLine);
        Assert.Contains("never hidden from the agent", model.PresenceOnFramesLine);
        var noGaps = SessionLedgerModel.Build("v", new SessionLedgerModel.Counts(0, 0, 0),
            live: false, agentName: "Agent A", destinations: Array.Empty<string>(), gaps: Array.Empty<string>());
        Assert.Null(noGaps.GapsLine);
    }

    // ---------- (4)/(5) model rules ----------

    [Fact]
    public void HostHome_order_pages_and_floor()
    {
        Assert.Equal(new[] { "Overview", "Presence", "Guardrails", "Audit Log", "Updates", "Settings", "About" },
            HostHomeModel.Pages.ToArray());
        var model = HostHomeModel.Build("STUDIO-PC", null,
            new[]
            {
                new HostHomeModel.ReadinessRow("Core", "ok", IsProblem: false),
                new HostHomeModel.ReadinessRow("Desktop locked", "unlock to drive", IsProblem: true),
            },
            Array.Empty<HostHomeModel.AgentRow>(), Array.Empty<string>());
        Assert.Equal("No one is in control of this PC right now.", model.StateSentence);
        Assert.Equal("Desktop locked", model.Readiness[0].Label); // problem promoted
        Assert.Equal(4, HostHomeModel.ConsentFloorItems.Count);
        Assert.False(FleetRegisterModel.ConsentFloorAttributedToSetter());
    }

    [Fact]
    public void Fleet_rules_name_setter_and_order_by_exception()
    {
        var rules = new[]
        {
            new FleetRegisterModel.Rule("Sessions end after 5 minutes idle", "Northwind IT", NeedsAttention: false),
            new FleetRegisterModel.Rule("3 devices need patches", "Northwind IT", NeedsAttention: true),
            new FleetRegisterModel.Rule("Local fact", null, NeedsAttention: false),
        };
        var ordered = FleetRegisterModel.OrderByException(rules);
        Assert.Equal("3 devices need patches", ordered[0].Sentence);
        Assert.Equal("Sessions end after 5 minutes idle · set by Northwind IT",
            FleetRegisterModel.RuleLine(ordered[1]));
        Assert.Equal("Local fact", FleetRegisterModel.RuleLine(ordered[2]));
        Assert.Equal(32, FleetRegisterModel.GridRowHeightPx);
        Assert.Equal(40, FleetRegisterModel.OwnerRowHeightPx);
    }

    [Fact]
    public void Setup_role_first_sas_and_reachability()
    {
        Assert.Equal(4, SetupWizardModel.Roles.Count);
        Assert.Equal("endpoint", SetupWizardModel.Roles[0].Id);
        Assert.Contains("no roster", SetupWizardModel.Roles[0].Consequence);
        Assert.False(SetupWizardModel.RoleCreatesComponents());
        Assert.False(SetupWizardModel.EndpointHasRoster());
        Assert.Equal("Step 1 of 5", SetupWizardModel.StepLabel(0));
        Assert.False(SetupWizardModel.PairStepShowsNameAndPhrase(redeemed: false));
        Assert.True(SetupWizardModel.PairStepShowsNameAndPhrase(redeemed: true));
        Assert.False(SetupWizardModel.MayMintCode(null));
        Assert.False(SetupWizardModel.MayMintCode("  "));
        Assert.True(SetupWizardModel.MayMintCode("100.64.0.1"));
        Assert.True(SetupWizardModel.FirstWordsDiffer("amber", "birch"));
        Assert.False(SetupWizardModel.FirstWordsDiffer("amber", "Amber"));
        Assert.Contains("clicks", SetupWizardModel.PersonalAutoBudget);
        Assert.DoesNotContain("taps", SetupWizardModel.PersonalAutoBudget);
    }

    [Fact]
    public void Chat_is_not_a_session_and_not_a_window()
    {
        Assert.False(AgentChatModel.ChatStartsSession());
        Assert.False(AgentChatModel.ChatGrantsCapability());
        Assert.False(AgentChatModel.IsTopLevelNavItem());
        Assert.False(AgentChatModel.IsStandaloneWindow());
        Assert.Empty(AgentChatModel.PresenceElementsInChat);
        Assert.Equal("Messaging does not use this access. It applies only while a session runs.",
            AgentChatModel.CapabilityLine());
    }

    [Fact]
    public void EventWatchLines_render_listall_completely_and_sorted()
    {
        var watches = new[]
        {
            new EventWatch("pair-b", new HashSet<string> { "session_ended", "agent_connected" }, DateTimeOffset.UtcNow),
            new EventWatch("pair-a", new HashSet<string> { "session_started" }, DateTimeOffset.UtcNow),
        };
        Assert.Equal(new[]
        {
            "pair-a · session_started",
            "pair-b · agent_connected",
            "pair-b · session_ended",
        }, EventWatchLines.Lines(watches).ToArray());
        Assert.Empty(EventWatchLines.Lines(Array.Empty<EventWatch>()));
    }

    /// <summary>The shared design strings and the SessionAgent U8
    /// table carry the same wording for every shared key — the two
    /// doors can never drift apart.</summary>
    [Fact]
    public void DesignStrings_match_sessionagent_u8_table_for_shared_keys()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? csPath = null;
        while (dir is not null)
        {
            foreach (var rel in new[]
            {
                Path.Combine("src", "DeskGuest.SessionAgent", "Strings.cs"),
                Path.Combine("windows-agent", "src", "DeskGuest.SessionAgent", "Strings.cs"),
            })
            {
                var candidate = Path.Combine(dir.FullName, rel);
                if (File.Exists(candidate)) { csPath = candidate; break; }
            }
            if (csPath is not null) break;
            dir = dir.Parent;
        }
        Assert.NotNull(csPath);
        var cs = File.ReadAllText(csPath!);
        var map = new Dictionary<string, string>();
        foreach (Match m in Regex.Matches(cs, "\\[\"(\\w+)\"\\] = \"((?:[^\"\\\\]|\\\\.)*)\""))
            map[m.Groups[1].Value] = Regex.Unescape(m.Groups[2].Value);
        (string Design, string U8)[] pairs =
        {
            ("presence_stop_is_in_force", "StopIsInForce"),
            ("presence_youre_driving", "PresenceYoureDriving"),
            ("presence_watchdog_line", "PresenceWatchdogLine"),
            ("gate_deny_and_end", "GateDenyAndEnd"),
            ("gate_draft_not_sent", "GateDraftNotSent"),
            ("gate_asked_from_chat", "GateAskedFromChat"),
            ("gate_no_session_allow", "GateNoSessionAllow"),
            ("session_vendor_line", "SessionVendorLine"),
            ("session_presence_on_frames", "SessionPresenceOnFrames"),
            ("chat_capability_line", "ChatCapabilityLine"),
            ("host_this_pc_only", "HostThisPcOnly"),
            ("policy_consent_floor_title", "FloorBoxTitle"),
            ("wizard_waiting_for_ai", "WizardWaitingForAi"),
        };
        foreach (var (design, u8) in pairs)
        {
            Assert.True(map.TryGetValue(u8, out var u8Value), u8);
            // The U8 table uses {0}-style format placeholders where
            // the design table uses the same ones — compare after
            // normalising only the format-key spelling.
            Assert.Equal(DesignStrings.Get(design), u8Value);
        }
    }
}

/// <summary>W8 destruction pass on the gate/presence paths:
/// hostile inputs against the new law surfaces.</summary>
public class W8WinDesignDestructionTests
{
    [Fact]
    public void Destruction_gate_cannot_arm_on_agent_activation_alone()
    {
        // Time passing is not consent: without a human activation
        // the controls never arm, however long the sheet sits open.
        Assert.False(GateSheetModel.ControlsArmed(0, long.MaxValue / 2, humanActivated: false));
        // A negative clock skew never arms early either.
        Assert.False(GateSheetModel.ControlsArmed(5000, 100, humanActivated: true));
    }

    [Fact]
    public void Destruction_ledger_refuses_cross_pairing_chat_merge()
    {
        var ledger = new DataFlowLedger();
        var t0 = new DateTimeOffset(2026, 11, 23, 9, 41, 0, TimeSpan.Zero);
        ledger.BeginSession("s1", "pair-a", "Agent A", t0);
        // A chat note for a DIFFERENT pairing under pair-a's session
        // record id must not fold into pair-a's totals (the ledger's
        // own isolation refusal): chat uses its own standing record.
        ledger.NoteChatMessage("pair-b", "Other", "ELSEWHERE", t0);
        var report = DataFlowReport.Build(ledger.Records(), Array.Empty<DeskGuest.Shared.Audit.AuditEntry>());
        var a = report.Agents.Single(x => x.PairingId == "pair-a");
        Assert.Equal(0, SessionLedgerModel.CountsFor(a).Sent);
        var b = report.Agents.Single(x => x.PairingId == "pair-b");
        Assert.Equal(1, SessionLedgerModel.CountsFor(b).Sent);
    }

    [Fact]
    public void Destruction_selftest_fails_closed_on_any_missing_element()
    {
        for (var mask = 0; mask < 16; mask++)
        {
            var r = PresenceSelfTest.Evaluate(
                boxDrawn: (mask & 1) != 0, ghostDrawn: (mask & 2) != 0,
                glowDrawn: (mask & 4) != 0, stopPresent: (mask & 8) != 0);
            Assert.Equal(mask == 15, r.Passed);
        }
    }

    [Fact]
    public void Destruction_hues_never_legal_on_health_or_fault_surfaces()
    {
        // Record §1/[R6]: health is not a presence state; no hue is
        // spent on faults.
        Assert.False(PresenceLaw.HueLegalOn("HEALTH_GLYPH"));
        Assert.False(PresenceLaw.HueLegalOn("FAULT_NOTCH"));
        Assert.False(PresenceLaw.HueLegalOn("TRAY_HEALTH"));
    }
}

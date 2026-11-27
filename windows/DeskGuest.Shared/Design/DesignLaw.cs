using DeskGuest.Shared.Sessions;

namespace DeskGuest.Shared.Design;

// =====================================================================
// W8 — the Windows design of record (TRIO-SIGNED, merged
// windows-design-of-record.md incl. [R1]/[R4]/[R5]/[R6]) as code.
// The Android implementation (W6-B/W7-B) landed the same laws in
// HeroDesign.kt / Part2Design.kt; this file mirrors those semantics
// for the Windows surfaces, whose forms are their own per the
// Windows record. Where the record and older Windows code conflict,
// the record wins; where the record is silent, Android's landed
// semantics are mirrored and the mirror is noted in the member doc.
// =====================================================================

/// <summary>The owner-visible sentences the design models render.
/// Wording mirrors Android's ConsentStrings.DEFAULTS (the U8 table)
/// with the Windows record's own substitutions (PC for phone, the
/// §2 watchdog sentence verbatim). The SessionAgent reads the same
/// values through its Strings.resx door; W8WinDesignTests pins the
/// two tables equal for every shared key.</summary>
public static class DesignStrings
{
    public static readonly IReadOnlyDictionary<string, string> Defaults =
        new Dictionary<string, string>
        {
            ["presence_stop"] = "STOP",
            ["presence_stop_is_in_force"] = "STOP is in force",
            ["presence_youre_driving"] = "Paused — you're driving",
            ["presence_watchdog_line"] = "This app can't reach the host. It can't confirm whether anything is controlling this PC.",
            ["presence_idle"] = "Session open — idle",
            ["presence_takeover_hint"] = "Press Ctrl + Alt + Shift + Backspace to take over",
            ["presence_acting_on_display"] = "{0} is acting on Display {1}",
            ["presence_gate_on_display"] = "{0} is asking on Display {1}",
            ["approval_approve"] = "Approve",
            ["approval_deny"] = "Deny",
            ["gate_deny_and_end"] = "Deny and end session",
            ["gate_draft_not_sent"] = "DRAFT · NOT SENT",
            ["gate_asked_from_chat"] = "Asked from Agent chat",
            ["gate_no_session_allow"] = "There is no allow-for-this-session. Every gated action asks on its own.",
            ["session_provider_line"] = "What {0}'s provider does with what it sees is outside this app.",
            ["session_vendor_line"] = "Nowhere else — DeskGuest sends nothing to anyone.",
            ["session_not_seen"] = "Not seen: {0}",
            ["session_seen_so_far"] = "{0} screens seen so far in this session",
            ["session_presence_on_frames"] = "The presence layer is part of the screens the agent receives — it is never hidden from the agent.",
            ["session_frames_sent"] = "{0} screens sent to {1}",
            ["session_frames_uncounted"] = "Screens could not be counted where they were captured, so no screen count is shown for them.",
            ["session_so_far"] = "so far",
            ["chat_sent_count"] = "{0} messages sent from chat",
            ["chat_destination"] = "Messages go to {0} on {1}",
            ["chat_capability_line"] = "Messaging does not use this access. It applies only while a session runs.",
            ["wizard_step_of"] = "Step {0} of {1}",
            ["wizard_waiting_for_ai"] = "Waiting for your AI",
            ["wizard_sas_check"] = "Is this {0}? Check the words — they must match what your AI shows.",
            ["policy_consent_floor_title"] = "Always on — no one can change this",
            ["home_no_one_in_control"] = "No one is in control of this PC right now.",
            ["home_agent_in_control"] = "{0} is in control of this PC right now.",
            ["home_connected_not_session"] = "Connected — not in a session",
            ["host_this_pc_only"] = "You're looking at this PC only.",
            ["fleet_consent_floor_unattributed"] = "The consent floor is set by DeskGuest itself. No policy can change it.",
        };

    public static string Get(string key) =>
        Defaults.TryGetValue(key, out var v) ? v : key;

    public static string Format(string key, params object?[] args) =>
        string.Format(System.Globalization.CultureInfo.CurrentCulture, Get(key), args);
}

/// <summary>§1/§2 presence law — hues are MEANINGS, fixed. The
/// values are byte-identical to Android's PresenceLaw
/// (HeroDesign.kt): the fixture in W8WinDesignTests pins every one.
/// Presence hues may paint ONLY the three elements (Box, Ghost,
/// Glow) and their mirrors — never health, brand, or chrome.</summary>
public static class PresenceLaw
{
    // ARGB, identical to Android HUE_* values.
    public const int HueHuman = unchecked((int)0xFF2FA84F); // green — a human is acting
    public const int HueAi = unchecked((int)0xFF7C4DFF);    // violet — an AI is acting
    public const int HueIdle = unchecked((int)0xFFF2A900);  // amber — session open, idle
    // W90: aligned to the STOP red of record, #DC2626 — the token
    // the shipped Windows pill's STOP fill was measured at in W72
    // and that Android's HUE_STOP carries since W84 (FR-117). The
    // old #C62828 was the lone divergence in the presence family;
    // HueStop and PillStopRed are now the same token, as they are
    // on Android (HUE_STOP == the pill's stopRed).
    public const int HueStop = unchecked((int)0xFFDC2626);  // red — STOP / destructive only

    /// <summary>The Box is theme-invariant: always dark, on any
    /// desktop, in either theme (Android BOX_BACKGROUND). W90:
    /// aligned to the Android value, the Gemini token navy
    /// #0F2537 — the same navy PillBackground already carried for
    /// the pill form. The gate card is a different surface and
    /// keeps its own fill (PresenceComposition.GateCardColors.
    /// CardBackground, #14141C); it is not the Box and is outside
    /// the cross-platform Box pin.</summary>
    public const int BoxBackground = unchecked((int)0xFF0F2537);
    public const int BoxOnBackground = unchecked((int)0xFFF4F4F6);

    // FR-117 (W72, Screen 11 pill): the pill form of the Box is
    // built to the reference's own colours — Gemini token sheet
    // v2.0.0: deepTrustNavy is the "presence overlay surface",
    // alertGold is designated "Presence banner border", and
    // emergencyRed is STOP-only. PillBackground and BoxBackground
    // are the same navy since W90 (see above); the blocked and
    // notice Boxes render on BoxBackground through the same
    // BoxShell, and the gate card keeps its own CardBackground.
    public const int PillBackground = unchecked((int)0xFF0F2537);
    public const int PillTrimGold = unchecked((int)0xFFE5A93B);
    public const int PillStopRed = unchecked((int)0xFFDC2626);
    public const int PillStopHoverRed = unchecked((int)0xFFB91C1C);
    public const int PillFaceCream = unchecked((int)0xFFF2EEDF);

    public enum Actor { Human, Ai, Idle }

    public static int HueFor(Actor actor) => actor switch
    {
        Actor.Human => HueHuman,
        Actor.Ai => HueAi,
        _ => HueIdle,
    };

    /// <summary>§2: presence is EXACTLY three elements.</summary>
    public static readonly IReadOnlyList<string> Elements = new[] { "BOX", "GHOST", "GLOW" };

    /// <summary>The fold: every §7 item lives in exactly one element
    /// or is a mirror of one (identical to Android's FOLD).</summary>
    public static readonly IReadOnlyDictionary<string, string> Fold =
        new Dictionary<string, string>
        {
            ["banner"] = "BOX",
            ["live narration"] = "BOX",
            ["virtual finger"] = "GHOST",
            ["session sounds and haptics"] = "BOX",
            ["persistent notification"] = "BOX (mirror)",
            ["quick settings tile"] = "BOX (mirror)",
            ["flag secure moment"] = "BOX",
            // Windows record §1: the tray is the Box's smallest mirror.
            ["tray"] = "BOX (mirror)",
        };

    /// <summary>Surfaces a presence hue may legally paint: the three
    /// elements and their mirrors only.</summary>
    public static readonly IReadOnlySet<string> HueLegalSurfaces = new HashSet<string>
    {
        "BOX", "GHOST", "GLOW", "TRAY_MIRROR", "QS_TILE_MIRROR", "NOTIFICATION_MIRROR",
    };

    public static bool HueLegalOn(string surface) => HueLegalSurfaces.Contains(surface);

    // §1.3/§2/§6 consent + motion constants — platform-invariant,
    // identical to Android's.
    public const long DwellMs = 650;
    public const long SettleMs = 90;
    public const int BoxMinHeightDp = 110;
    public const long GateArmMs = 600;
    public const long BoxInMs = 220;
    public const long BoxOutMs = 400;
    public const long GlowFadeMs = 600;
    public const long GateSheetMs = 240;
    public const long StateChangeMs = 180;
    public const long ChromeFastMs = 167;
    public const long ChromeMidMs = 250;
    public const long ChromeSlowMs = 333;

    /// <summary>Ghost glide: clamp(220 ms, 180 + 0.25 ms/px, 600 ms)
    /// — the same formula as Android's glideMs.</summary>
    public static long GlideMs(int distancePx) =>
        Math.Clamp((long)(180.0 + 0.25 * Math.Max(0, distancePx)), 220, 600);

    /// <summary>The Glow is static by default; the 6.4 s / 82–100%
    /// breath is a comfort setting only (OI-04).</summary>
    public const long GlowBreathPeriodMs = 6_400;
    public const int GlowBreathMinPct = 82;
    public const int GlowBreathMaxPct = 100;

    /// <summary>§2 multi-display: displays the agent is not acting
    /// on run at the legibility floor — 40% intensity, never unlit.
    /// The same 40 is the comfort intensity floor (Android
    /// PresenceSettings.GLOW_INTENSITY_FLOOR_PCT).</summary>
    public const int GlowLegibilityFloorPct = 40;
    public const int GlowIntensityFloorPct = 40;

    /// <summary>Ghost: ring with the actor's initial inside — one
    /// geometry, both platforms.</summary>
    public static string GhostInitial(string actorName)
    {
        var t = (actorName ?? "").Trim();
        return t.Length == 0 ? "?" : char.ToUpperInvariant(t[0]).ToString();
    }

    /// <summary>The Ghost withdraws while a gate is up or the owner
    /// is driving; only the floor holder's Ghost shows a dwell ring.</summary>
    public static bool GhostDrawn(bool gateUp, bool ownerDriving) => !gateUp && !ownerDriving;
    public static bool DwellShown(bool isFloorHolder) => isFloorHolder;

    public static string TakeoverSentence() => DesignStrings.Get("presence_youre_driving");
    public static string WatchdogSentence() => DesignStrings.Get("presence_watchdog_line");
}

/// <summary>§2 presence self-test: all three elements are drawn and
/// verified before a session is accepted; a failed draw blocks it.
/// The renderer reports what it actually drew (per element); this
/// model is the verdict — it never passes an element the renderer
/// did not confirm, and STOP must be present on the Box.</summary>
public static class PresenceSelfTest
{
    public sealed record Result(bool BoxDrawn, bool GhostDrawn, bool GlowDrawn, bool StopPresent)
    {
        public bool Passed => BoxDrawn && GhostDrawn && GlowDrawn && StopPresent;
        public IReadOnlyList<string> Failures
        {
            get
            {
                var f = new List<string>();
                if (!BoxDrawn) f.Add("BOX did not draw");
                if (!GhostDrawn) f.Add("GHOST did not draw");
                if (!GlowDrawn) f.Add("GLOW did not draw");
                if (!StopPresent) f.Add("STOP missing from the Box");
                return f;
            }
        }
    }

    public static Result Evaluate(bool boxDrawn, bool ghostDrawn, bool glowDrawn, bool stopPresent) =>
        new(boxDrawn, ghostDrawn, glowDrawn, stopPresent);
}

/// <summary>§3 the gate: a dialog-class sheet over the dimmed
/// desktop, the Box held above it. Exits exactly three, at exactly
/// equal weight; no default button; Esc and outside-click do
/// nothing; no session-wide allow for any class, in any mode.
/// Gate-fidelity law (OI-12): the gate quotes the payload the tool
/// call will submit, byte-for-byte. Agent-input exclusion (OI-13):
/// controls arm only after 600 ms AND a human activation.</summary>
public static class GateSheetModel
{
    public sealed record Exit(string Label, int Weight, int BorderContrast);

    /// <summary>Approve / Deny / Deny-and-end — all weight 600, same
    /// border, in each theme (Android GateModel parity). Approve is
    /// achromatic; Deny sits directly beneath at equal weight.</summary>
    public static IReadOnlyList<Exit> Exits() => new[]
    {
        new Exit(DesignStrings.Get("approval_approve"), 600, 1),
        new Exit(DesignStrings.Get("approval_deny"), 600, 1),
        new Exit(DesignStrings.Get("gate_deny_and_end"), 600, 1),
    };

    public static bool HasSessionAllow() => false;
    public static string NoSessionAllowLine() => DesignStrings.Get("gate_no_session_allow");
    public static string DraftMarker() => DesignStrings.Get("gate_draft_not_sent");
    public static string ChatOriginLine() => DesignStrings.Get("gate_asked_from_chat");

    /// <summary>OI-12 fixture comparison: gate bytes == submitted
    /// bytes — same length, same bytes, no re-encoding, no trim.</summary>
    public static bool PayloadMatches(byte[] gateShown, byte[] submitted) =>
        gateShown.AsSpan().SequenceEqual(submitted);

    /// <summary>OI-13 arming: at least GateArmMs elapsed AND a human
    /// activation (a human input event, or a Narrator/UIA activation
    /// from a non-agent source).</summary>
    public static bool ControlsArmed(long shownAtMs, long nowMs, bool humanActivated) =>
        humanActivated && nowMs - shownAtMs >= PresenceLaw.GateArmMs;

    /// <summary>W118 — the activating event ITSELF completes the
    /// arming, synchronously, when the GateArmMs delay has already
    /// elapsed by the time it lands. Before W118 the activation
    /// only latched a flag and a 50 ms timer armed the exits
    /// afterwards — but the press that carried the activation had
    /// landed on a still-DISABLED exit, and a press on a disabled
    /// button captures nothing, so its release could never raise
    /// the exit's Click: the owner's first click on a gate card
    /// was consumed by the arming transition and answered nothing
    /// (W115 live: one dead-centre Approve click produced the
    /// FR-120 yield but no gate answer; the gate failed closed on
    /// timeout). The rule: an activation at or after the delay
    /// arms the exits inside the activation event's own tunnel
    /// phase, BEFORE the target exit processes the press — so the
    /// one act both arms and answers, against the gate that was
    /// up when the click landed. An activation INSIDE the delay
    /// arms nothing: OI-13's 600 ms stands exactly, and only a
    /// later press answers. This is a property of the activation
    /// event, not of any input path — physical and injected owner
    /// input take the same rule, no special case.</summary>
    public static bool ArmsOnActivation(long shownAtMs, long activationAtMs) =>
        activationAtMs - shownAtMs >= PresenceLaw.GateArmMs;

    /// <summary>W118, second layer — live proof (gate 1 of the
    /// W118 lane) showed synchronous arming alone is NOT enough:
    /// a press whose target exit is DISABLED at press start is
    /// routed by WPF to the element beneath the exit, so even
    /// with the exit enabled during the event's tunnel phase,
    /// that press never becomes the exit's own press — it
    /// captures nothing and its release raises no Click. The
    /// window therefore completes such a press itself: when a
    /// press lands on an exit that THIS press's activation just
    /// armed (disabled at press start, armed by the press), and
    /// the release lands on the SAME exit, the press counts as
    /// that exit's click — the one act answers. A press that
    /// starts off the exit, or releases off the exit it started
    /// on, counts for nothing (a real click's shape); a press on
    /// an exit that was already enabled takes WPF's own path and
    /// never consults this rule.</summary>
    public static bool WindowPressAnswers(bool exitEnabledAtPressStart, bool armedByThisPress,
        bool pressOnExit, bool releaseOnSameExit) =>
        !exitEnabledAtPressStart && armedByThisPress && pressOnExit && releaseOnSameExit;

    public enum InjectionPath { SendInput, UiAutomation, WindowMessage }

    /// <summary>OI-13: the host refuses every agent action whose
    /// target is an DeskGuest window, on every injection path.</summary>
    public static bool AgentActionOnDeskGuestWindowRefused(InjectionPath path, bool targetIsDeskGuestWindow) =>
        targetIsDeskGuestWindow;

    /// <summary>No approval can enable credential typing — refused
    /// outright, no toggle, for every class.</summary>
    public static bool CredentialTypingApprovable() => false;

    /// <summary>Deny-and-end ordering (Android GateDenyAndEnd
    /// parity): the audit record is written FIRST, then the session
    /// teardown runs. The two steps, in order, are the contract the
    /// wiring is tested against.</summary>
    public static readonly IReadOnlyList<string> DenyAndEndSteps =
        new[] { "audit:approval_deny_and_end", "teardown:end_session" };
}

/// <summary>§4 sessions detail — the Windows witness surface, the
/// same accounting as Android A4: verdict sentence first, then
/// Read / Sent / Changed as separate labelled numbers (never an
/// arithmetic equation), destinations named, the fixed provider
/// line, the vendor line, gaps named as what was not seen, and the
/// presence-on-frames note. [R4] frames delivered to an off-device
/// agent count as Sent to that destination; chat messages to an
/// off-device agent likewise count as Sent. A live session's counts
/// are quoted "so far" [R6].</summary>
public static class SessionLedgerModel
{
    public sealed record Counts(long Read, long Sent, long Changed)
    {
        /// <summary>Separate labelled numbers — never "r + s + c".</summary>
        public IReadOnlyList<(string Label, long Value)> Labelled() => new[]
        {
            ("Read", Read), ("Sent", Sent), ("Changed", Changed),
        };
    }

    public sealed record Model(
        string Verdict,
        Counts Counts,
        bool Live,
        IReadOnlyList<string> Destinations,
        string ProviderLine,
        string VendorLine,
        string? GapsLine,
        string PresenceOnFramesLine);

    /// <summary>Frame accounting (Android FrameAccounting parity):
    /// a frame counts ONLY when a frame tool returns a delivered
    /// (non-error) result.</summary>
    public static readonly IReadOnlySet<string> FrameTools = new HashSet<string>
    {
        "screenshot", "annotated_screenshot", "snapshot", "camera_capture",
    };

    public static bool FrameDelivered(string tool, bool resultIsError) =>
        FrameTools.Contains(tool) && !resultIsError;

    /// <summary>Counts from a DataFlow agent aggregate: the class
    /// totals ARE the ledger. Frames and chat are already folded
    /// into Sent by the choke points (McpHandler frame results and
    /// DataFlowLedger.NoteChatMessage both record class Sent for an
    /// off-device pairing).</summary>
    public static Counts CountsFor(AgentFlow agent) => new(
        agent.ByClass.TryGetValue(DataFlowClasses.Read, out var r) ? r.Calls : 0,
        agent.ByClass.TryGetValue(DataFlowClasses.Sent, out var s) ? s.Calls : 0,
        agent.ByClass.TryGetValue(DataFlowClasses.Changed, out var c) ? c.Calls : 0);

    public static Model Build(
        string verdict, Counts counts, bool live,
        string agentName, IReadOnlyList<string> destinations,
        IReadOnlyList<string> gaps) => new(
            Verdict: verdict,
            Counts: counts,
            Live: live,
            Destinations: destinations,
            ProviderLine: DesignStrings.Format("session_provider_line", agentName),
            VendorLine: DesignStrings.Get("session_vendor_line"),
            GapsLine: gaps.Count == 0 ? null
                : DesignStrings.Format("session_not_seen", string.Join(", ", gaps)),
            PresenceOnFramesLine: DesignStrings.Get("session_presence_on_frames"));

    /// <summary>The counts header: labelled numbers, with "so far"
    /// appended while the session is live — never presented as an
    /// end-of-session total mid-session.</summary>
    public static string CountsLine(Counts counts, bool live)
    {
        var parts = counts.Labelled().Select(p => $"{p.Label} {p.Value}");
        var line = string.Join(" · ", parts);
        return live ? $"{line} · {DesignStrings.Get("session_so_far")}" : line;
    }

    public static string SeenSoFarLine(long screens) =>
        DesignStrings.Format("session_seen_so_far", screens);

    public static string ChatSentLine(long count) =>
        DesignStrings.Format("chat_sent_count", count);
}

/// <summary>§4 host window Overview — an instrument in the record's
/// order: (1) state sentence, (2) readiness (a problem promotes to
/// the top; a non-decision does not appear), (3) who may connect,
/// (4) recent sessions, (5) standing sections, and the locked
/// "What no setting changes" floor box. The census "nothing else"
/// rule does not apply here — it applies to the operator device
/// home. The host window has NO fleet (§4: the sidebar's MESH
/// DEVICES block is replaced — there is none).</summary>
public static class HostHomeModel
{
    public sealed record ReadinessRow(string Label, string Consequence, bool IsProblem);
    public sealed record AgentRow(string Name, string AccessLabel, long ChatSentCount);

    public sealed record Model(
        string Title,
        string StateSentence,
        bool SessionRunning,
        IReadOnlyList<ReadinessRow> Readiness,
        IReadOnlyList<AgentRow> Agents,
        IReadOnlyList<string> RecentSessions,
        IReadOnlyList<string> StandingSections);

    /// <summary>The host window's pages, §4 — nothing else.</summary>
    public static readonly IReadOnlyList<string> Pages = new[]
    {
        "Overview", "Presence", "Guardrails", "Audit Log", "Updates", "Settings", "About",
    };

    /// <summary>The standing sections Overview carries, in order.</summary>
    public static readonly IReadOnlyList<string> StandingSections = new[]
    {
        "Recovery", "Audit", "Approvals", "Updates",
    };

    /// <summary>The locked floor box: what no setting changes.</summary>
    public static readonly IReadOnlyList<string> ConsentFloorItems = new[]
    {
        "you always see who is in control",
        "STOP always works, even offline",
        "your passwords are never typed by an agent",
        "the record of a session can't be edited",
    };

    public static string NoSessionSentence() => DesignStrings.Get("home_no_one_in_control");
    public static string SessionSentence(string agentName) =>
        DesignStrings.Format("home_agent_in_control", agentName);
    public static string ThisPcOnlyLine() => DesignStrings.Get("host_this_pc_only");

    public static Model Build(
        string machineName, string? sessionAgent,
        IReadOnlyList<ReadinessRow> readiness,
        IReadOnlyList<AgentRow> agents,
        IReadOnlyList<string> recentSessions)
    {
        var ordered = readiness.Where(r => r.IsProblem)
            .Concat(readiness.Where(r => !r.IsProblem)).ToList();
        return new Model(
            Title: machineName,
            StateSentence: sessionAgent is null ? NoSessionSentence() : SessionSentence(sessionAgent),
            SessionRunning: sessionAgent is not null,
            Readiness: ordered,
            Agents: agents,
            RecentSessions: recentSessions,
            StandingSections: StandingSections);
    }
}

/// <summary>§6 RMM/enterprise (OI-17): fleet register in the
/// operator surfaces — status by exception (what needs attention
/// leads, in words), and EffectivePolicy sentences each naming
/// their setter ("… · set by Northwind IT"). The consent floor is
/// NEVER attributed to a setter. Mirrors Android
/// EffectivePolicyModel.</summary>
public static class FleetRegisterModel
{
    public sealed record Rule(string Sentence, string? Setter, bool NeedsAttention);

    public static string RuleLine(Rule rule) =>
        string.IsNullOrWhiteSpace(rule.Setter)
            ? rule.Sentence
            : $"{rule.Sentence} · set by {rule.Setter}";

    public static string ConsentFloorTitle() => DesignStrings.Get("policy_consent_floor_title");
    public static bool ConsentFloorAttributedToSetter() => false;
    public static string ConsentFloorLine() => DesignStrings.Get("fleet_consent_floor_unattributed");

    /// <summary>Status by exception: attention rows first, stable
    /// order otherwise; nothing is dropped.</summary>
    public static IReadOnlyList<Rule> OrderByException(IReadOnlyList<Rule> rules) =>
        rules.Where(r => r.NeedsAttention).Concat(rules.Where(r => !r.NeedsAttention)).ToList();

    /// <summary>Fleet grid law (§1): 32 px rows, 13 px text,
    /// sortable, severity as words — never a presence hue.</summary>
    public const int GridRowHeightPx = 32;
    public const int GridFontPx = 13;
    public const int OwnerRowHeightPx = 40;
    public const int OwnerFontPx = 14;
    public const int SessionBarHeightPx = 36;
}

/// <summary>§5 setup — role first. "What is this PC for?" is step
/// 1; each card states its consequence. Windows wizard steps
/// (mirroring Android's 7-step shape with the Windows record's own
/// steps): role → transport → pairing → access level → presence
/// self-test / self-check. Pairing: the agent's name appears only
/// after the code is redeemed, with the three-word SAS check;
/// phrase derivation differs in the first word across identities.
/// The reachability gate refuses to mint a code when no remote
/// address is reachable (W4-B F8 rule, Android parity).</summary>
public static class SetupWizardModel
{
    public sealed record RoleCard(string Id, string Title, string Consequence);

    public static readonly IReadOnlyList<RoleCard> Roles = new[]
    {
        new RoleCard("endpoint", "People connect to this PC",
            "This PC is an endpoint. This install holds no roster data, no operator keys, and no entry point to either — and it never grows a roster later."),
        new RoleCard("operator", "I connect to other PCs",
            "This PC is an operator workspace. It holds the roster and your operator keys; it is not itself an endpoint."),
        new RoleCard("both", "Both",
            "This PC is an endpoint and an operator workspace. On a STOP hotkey press, this PC's hosted session stops first."),
        new RoleCard("for_other", "Someone else's PC — I'm setting it up for them",
            "Setup chooses this PC's role for its owner. A silent deployment carries its role in the deployment package and leaves zero endpoint residue."),
    };

    /// <summary>Which components exist is decided at installer /
    /// deployment-package level — role-first setup chooses defaults
    /// only and creates nothing (§4, OI-02).</summary>
    public static bool RoleCreatesComponents() => false;
    public static bool EndpointHasRoster() => false;

    public static readonly IReadOnlyList<string> Steps = new[]
    {
        "role", "transport", "pairing", "access level", "self-check",
    };

    public const int StepCount = 5;

    public static string StepLabel(int stepIndexZeroBased) =>
        DesignStrings.Format("wizard_step_of", stepIndexZeroBased + 1, StepCount);

    /// <summary>Click budget, stated on the self-check screen in
    /// clicks and steps — never Android "taps" [R4].</summary>
    public const string PersonalAutoBudget = "about 6 clicks and 5 steps";

    public static string WaitingLine() => DesignStrings.Get("wizard_waiting_for_ai");

    /// <summary>The SAS confirmation line, shown only after
    /// redemption — the agent's name is never shown before the code
    /// is redeemed.</summary>
    public static string SasCheckLine(string agentName) =>
        DesignStrings.Format("wizard_sas_check", agentName);

    public static bool PairStepShowsNameAndPhrase(bool redeemed) => redeemed;

    /// <summary>Reachability gate: no reachable remote address →
    /// no pairing code is minted.</summary>
    public static bool MayMintCode(string? reachableRemoteAddress) =>
        !string.IsNullOrWhiteSpace(reachableRemoteAddress);

    /// <summary>Phrase derivation differs in the first word across
    /// identities (no shared-prefix phrases).</summary>
    public static bool FirstWordsDiffer(string firstWordA, string firstWordB) =>
        !string.IsNullOrWhiteSpace(firstWordA) && !string.IsNullOrWhiteSpace(firstWordB)
        && !string.Equals(firstWordA, firstWordB, StringComparison.OrdinalIgnoreCase);
}

/// <summary>§4 Agent chat (Addendum A): on the host side the thread
/// lives on the agent's row in Overview — never a top-level nav
/// item, never a standalone window. Not a session: no presence, no
/// capability. An ask from chat opens the ordinary gate and names
/// its origin. Off-device messages count as Sent in the data-flow
/// ledger; audit keeps metadata, not text. Unpairing ends the
/// thread.</summary>
public static class AgentChatModel
{
    public static readonly IReadOnlyList<string> PresenceElementsInChat = Array.Empty<string>();
    public static bool ChatStartsSession() => false;
    public static bool ChatGrantsCapability() => false;
    public static bool IsTopLevelNavItem() => false;
    public static bool IsStandaloneWindow() => false;

    public static string DestinationLine(string agentName, string agentDevice) =>
        DesignStrings.Format("chat_destination", agentName, agentDevice);
    public static string CapabilityLine() => DesignStrings.Get("chat_capability_line");
}

/// <summary>W7-A named remainder, closed here: the presence-UI
/// rendering of EventSubscriptions.ListAll(). Groups (pairings)
/// sorted by name, event kinds sorted inside each group — a
/// stable, complete rendering; nothing is sampled or truncated.
/// Mirrors Android MdmSurfaceModel.eventLines over the Windows
/// store's EventWatch shape.</summary>
public static class EventWatchLines
{
    public static IReadOnlyList<string> Lines(IReadOnlyList<EventWatch> watches) =>
        watches.OrderBy(w => w.PairingId, StringComparer.Ordinal)
            .SelectMany(w => w.Kinds.OrderBy(k => k, StringComparer.Ordinal)
                .Select(kind => $"{w.PairingId} · {kind}"))
            .ToList();

    public static string EmptyLine() => "No event watches are live.";
}

import io.agenticcontrol.app.design.GateModel
import io.agenticcontrol.app.design.HeroThemes
import io.agenticcontrol.app.design.HomeModel
import io.agenticcontrol.app.design.PresenceLaw
import io.agenticcontrol.app.design.SessionDetailModel
import io.agenticcontrol.app.mesh.MeshAuth
import java.io.File

/**
 * W6 Lane B — mesh Authorization (Task 0) + design-of-record hero
 * surfaces part 1 (Task 1). Pins:
 *  - MeshAuth header presence/shape + absence when unpaired +
 *    injection-guard refusals; MeshClient applies authorize() on
 *    every request path (source lint, since MeshClient is
 *    Android-bound and cannot run on the JVM).
 *  - Presence law: exactly 3 elements, fold table, hues-as-meanings
 *    legality, 650ms dwell, glide formula, Ghost rules, talk levels.
 *  - Themes: light is a first-class peer (not an inversion), Box
 *    always dark in both, Follow system resolves both ways.
 *  - Home: state sentence first/exact, problem promotion, standing
 *    sections incl. the not-in-this-build row, Look-only default.
 *  - Session detail: counts as separate labelled numbers, off-device
 *    frames count as Sent (R4), "so far" gate counts (R6), provider
 *    + vendor lines, gaps, replay honesty.
 *  - Gate (OI-12 fixture): the gate payload equals the submitted
 *    payload BYTE FOR BYTE; exits exactly 3 at equal weight; no
 *    session allow; 600ms + human arming (OI-13); agent actions on
 *    ACP windows refused on all three injection paths.
 *
 * Args: [0] = android project dir.
 */
object W6DesignTest {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])

        // ---- Task 0: MeshAuth ----
        check("mesh header shape", MeshAuth.headerValue("tok-abc_123") == "Bearer tok-abc_123")
        check("mesh header name", MeshAuth.HEADER_NAME == "Authorization")
        check("mesh no token -> no header (null)", MeshAuth.headerValue(null) == null)
        check("mesh no token -> no header (empty)", MeshAuth.headerValue("") == null)
        check("mesh no token -> no header (blank)", MeshAuth.headerValue("   ") == null)
        check("mesh token never invented", !MeshAuth.hasToken(null) && !MeshAuth.hasToken(""))
        check("mesh whitespace token refused", MeshAuth.headerValue("a b") == null)
        check("mesh padded token refused", MeshAuth.headerValue(" tok") == null)
        check("mesh newline token refused", MeshAuth.headerValue("to\nk") == null)
        check("mesh CRLF injection refused", MeshAuth.headerValue("tok\r\nX-Evil: 1") == null)
        // MeshClient applies the header on every request path.
        val meshClient = File(root,
            "app/src/main/java/io/agenticcontrol/app/mesh/MeshClient.kt").readText()
        check("meshclient defines authorize", meshClient.contains("fun HttpURLConnection.authorize()"))
        check("meshclient authorize call sites >= 4",
            meshClient.split("authorize()").size - 1 >= 5) // def + 4 paths
        check("meshclient token is a provider", meshClient.contains("bearerToken: () -> String?"))
        check("meshclient default provider sends nothing",
            meshClient.contains("bearerToken: () -> String? = { null }"))
        val winAct = File(root,
            "app/src/main/java/io/agenticcontrol/app/WindowsDeviceActivity.kt").readText()
        check("windows page supplies pairing token",
            winAct.contains("MeshStore.bearerToken") && winAct.contains("sharedPairingStore"))

        // ---- Presence law (§1–§2) ----
        check("presence exactly 3 elements",
            PresenceLaw.ELEMENTS == listOf("BOX", "GHOST", "GLOW"))
        check("fold banner is box", PresenceLaw.FOLD["banner"] == "BOX")
        check("fold narration is box", PresenceLaw.FOLD["live narration"] == "BOX")
        check("fold finger is ghost", PresenceLaw.FOLD["virtual finger"] == "GHOST")
        check("fold has 7 items", PresenceLaw.FOLD.size == 7)
        check("fold targets are elements/mirrors only",
            PresenceLaw.FOLD.values.all { it.startsWith("BOX") || it.startsWith("GHOST") || it.startsWith("GLOW") })
        check("hue human green", PresenceLaw.hueFor(PresenceLaw.Actor.HUMAN) == PresenceLaw.HUE_HUMAN)
        check("hue ai violet", PresenceLaw.hueFor(PresenceLaw.Actor.AI) == PresenceLaw.HUE_AI)
        check("hue idle amber", PresenceLaw.hueFor(PresenceLaw.Actor.IDLE) == PresenceLaw.HUE_IDLE)
        check("hues distinct", setOf(PresenceLaw.HUE_HUMAN, PresenceLaw.HUE_AI,
            PresenceLaw.HUE_IDLE, PresenceLaw.HUE_STOP).size == 4)
        check("hue illegal on brand", !PresenceLaw.hueLegalOn("BRAND"))
        check("hue illegal on avatar", !PresenceLaw.hueLegalOn("AVATAR"))
        check("hue illegal on primary button", !PresenceLaw.hueLegalOn("PRIMARY_BUTTON"))
        check("hue illegal on device card", !PresenceLaw.hueLegalOn("DEVICE_CARD"))
        check("hue legal on box/ghost/glow",
            PresenceLaw.hueLegalOn("BOX") && PresenceLaw.hueLegalOn("GHOST") && PresenceLaw.hueLegalOn("GLOW"))
        check("hue legal on mirrors",
            PresenceLaw.hueLegalOn("QS_TILE_MIRROR") && PresenceLaw.hueLegalOn("NOTIFICATION_MIRROR"))
        check("dwell is 650ms", PresenceLaw.DWELL_MS == 650L)
        check("gate arm is 600ms", PresenceLaw.GATE_ARM_MS == 600L)
        check("box min height 110dp", PresenceLaw.BOX_MIN_HEIGHT_DP == 110)
        check("glide floor 220", PresenceLaw.glideMs(0) == 220L)
        check("glide mid", PresenceLaw.glideMs(800) == 380L)
        check("glide cap 600", PresenceLaw.glideMs(100000) == 600L)
        check("ghost initial", PresenceLaw.ghostInitial("Agent A") == "A")
        check("ghost initial blank", PresenceLaw.ghostInitial("") == "?")
        check("ghost withdrawn at gate", !PresenceLaw.ghostDrawn(gateUp = true, ownerDriving = false))
        check("ghost withdrawn on takeover", !PresenceLaw.ghostDrawn(gateUp = false, ownerDriving = true))
        check("ghost drawn while driving", PresenceLaw.ghostDrawn(gateUp = false, ownerDriving = false))
        check("dwell only floor holder", PresenceLaw.dwellShown(true) && !PresenceLaw.dwellShown(false))
        check("takeover sentence", PresenceLaw.takeoverSentence() == "Paused — you're driving")
        check("watchdog sentence honest",
            PresenceLaw.watchdogSentence() ==
                "This app can't confirm whether anything is controlling this phone.")
        check("glow breath period", PresenceLaw.GLOW_BREATH_PERIOD_MS == 6400L &&
            PresenceLaw.GLOW_BREATH_MIN_PCT == 82 && PresenceLaw.GLOW_BREATH_MAX_PCT == 100)
        // Talk-through levels (OI-15)
        check("quiet: gate only class",
            PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.QUIET, false, true, false, false, false) &&
            !PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.QUIET, true, false, false, false, true))
        check("main: four triggers",
            PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.MAIN, true, false, false, false, false) &&
            PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.MAIN, false, false, false, true, false) &&
            !PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.MAIN, false, false, false, false, true))
        check("every: every step",
            PresenceLaw.narrationChanges(PresenceLaw.TalkLevel.EVERY, false, false, false, false, true))

        // ---- Themes (§5) ----
        check("follow system light", HeroThemes.resolve(HeroThemes.Mode.FOLLOW_SYSTEM, false) == HeroThemes.LIGHT)
        check("follow system dark", HeroThemes.resolve(HeroThemes.Mode.FOLLOW_SYSTEM, true) == HeroThemes.DARK)
        check("explicit light wins over system dark",
            HeroThemes.resolve(HeroThemes.Mode.LIGHT, true) == HeroThemes.LIGHT)
        check("box always dark both themes",
            HeroThemes.LIGHT.boxBackground == HeroThemes.DARK.boxBackground &&
            HeroThemes.LIGHT.boxBackground == HeroThemes.BOX_BACKGROUND)
        check("light not an inversion of dark",
            HeroThemes.LIGHT.surface != HeroThemes.DARK.surface &&
            HeroThemes.LIGHT.cardSurface != HeroThemes.DARK.cardSurface &&
            HeroThemes.LIGHT.border != HeroThemes.DARK.border &&
            HeroThemes.LIGHT.onSurface != HeroThemes.DARK.onSurface)
        check("approve achromatic both themes",
            HeroThemes.LIGHT.approveFill == HeroThemes.LIGHT.onSurface &&
            HeroThemes.DARK.approveFill == HeroThemes.DARK.onSurface)
        check("stop red both themes",
            HeroThemes.LIGHT.stopRed == PresenceLaw.HUE_STOP &&
            HeroThemes.DARK.stopRed == PresenceLaw.HUE_STOP)

        // ---- Home (§4 A1) ----
        val home = HomeModel.build(
            deviceName = "Pixel 9",
            sessionAgent = null,
            readiness = listOf(
                HomeModel.ReadinessRow("Battery", "fine", false),
                HomeModel.ReadinessRow("Accessibility", "off — the agent cannot drive", true),
                HomeModel.ReadinessRow("Overlay", "fine", false)
            ),
            agents = listOf(HomeModel.AgentRow("Agent A", "Full control", 3)),
            recentSessions = listOf("9:41 session")
        )
        check("home title is device name", home.title == "Pixel 9")
        check("home no-session sentence exact",
            home.stateSentence == "No one is in your phone right now." && !home.sessionRunning)
        check("home problem promotes to top", home.readiness.first().label == "Accessibility")
        check("home promotion never deletes",
            home.readiness.size == 3 && home.readiness.map { it.label }.toSet().size == 3)
        check("home standing sections complete", home.standingSections.size == 8)
        check("home invisible apps says not in this build",
            home.standingSections.last() == "Invisible apps — not in this build")
        val homeLive = HomeModel.build("Pixel 9", "Agent A", emptyList(), emptyList(), emptyList())
        check("home session sentence names agent",
            homeLive.stateSentence == "Agent A is in your phone right now." && homeLive.sessionRunning)
        check("new pairing defaults look only", HomeModel.NEW_PAIRING_ACCESS == "Look only")
        check("connected-not-session label",
            HomeModel.connectedNotInSessionLabel() == "Connected — not in a session")

        // ---- Session detail (§4 A4) ----
        val countsOff = SessionDetailModel.countsFor(
            framesDelivered = 24, agentOffDevice = true, sentOther = 3, changed = 5, readOther = 2)
        check("off-device frames count as Sent (R4)",
            countsOff.sent == 27 && countsOff.read == 2 && countsOff.changed == 5)
        val countsOn = SessionDetailModel.countsFor(
            framesDelivered = 24, agentOffDevice = false, sentOther = 3, changed = 5, readOther = 2)
        check("on-device frames count as Read only",
            countsOn.read == 26 && countsOn.sent == 3)
        check("counts labelled separately, no equation",
            countsOff.labelled() == listOf("Read" to 2, "Sent" to 27, "Changed" to 5))
        val detail = SessionDetailModel.build(
            verdict = "v", counts = countsOff, agentName = "Agent A",
            agentDevice = "HOST-LAPTOP", screens = 24,
            gaps = listOf("2 secure screens", "1 refused field"))
        check("detail destination line", detail.destinationLine == "24 screens → Agent A on HOST-LAPTOP")
        check("detail provider line",
            detail.providerLine == "What Agent A's provider does with what it sees is outside this app.")
        check("detail vendor line",
            detail.vendorLine == "Nowhere else — DeskGuest sends nothing to anyone.")
        check("detail gaps line", detail.gapsLine == "Not seen: 2 secure screens, 1 refused field")
        check("detail replay honesty", detail.replayLine == "Replay isn't in this build")
        check("banned nothing-sent copy absent",
            !detail.vendorLine.contains("Nothing was sent") && !detail.providerLine.contains("Nothing was sent"))
        check("so-far gate counts (R6)",
            SessionDetailModel.seenSoFarLine(18) == "18 screens seen so far in this session")
        check("chat sent line", SessionDetailModel.chatSentLine(3) == "3 messages sent from chat")

        // ---- Gate (§3, OI-12 fixture, OI-13) ----
        val exits = GateModel.exits()
        check("gate exits exactly 3", exits.size == 3)
        check("gate exit labels",
            exits.map { it.label } == listOf("Approve", "Deny", "Deny and end session"))
        check("gate exits exactly equal weight",
            exits.all { it.weight == 600 } && exits.map { it.weight }.toSet().size == 1)
        check("gate exits equal border contrast",
            exits.map { it.borderContrast }.toSet().size == 1)
        check("gate has no session allow", !GateModel.hasSessionAllow())
        check("gate draft marker", GateModel.draftMarker() == "DRAFT · NOT SENT")
        check("gate chat origin line", GateModel.chatOriginLine() == "Asked from Agent chat")
        // OI-12 build fixture: gate payload == submitted payload, byte for byte.
        val submitted = "Send the battery report to Marta — café ☕ 100%\nSecond line."
            .toByteArray(Charsets.UTF_8)
        val gateShown = String(submitted, Charsets.UTF_8).toByteArray(Charsets.UTF_8)
        check("OI-12 fixture: payload byte-for-byte", GateModel.payloadMatches(gateShown, submitted))
        check("OI-12 fixture: altered byte fails",
            !GateModel.payloadMatches(
                submitted.copyOf().also { it[0] = (it[0] + 1).toByte() }, submitted))
        check("OI-12 fixture: truncated payload fails",
            !GateModel.payloadMatches(submitted.copyOf(submitted.size - 1), submitted))
        check("OI-12 fixture: re-encoded payload fails",
            !GateModel.payloadMatches(
                String(submitted, Charsets.UTF_8).toByteArray(Charsets.ISO_8859_1), submitted))
        // OI-13 arming + refusal paths.
        check("gate not armed before 600ms",
            !GateModel.controlsArmed(1000, 1599, humanActivated = true))
        check("gate armed at 600ms + human",
            GateModel.controlsArmed(1000, 1600, humanActivated = true))
        check("gate never armed without human activation",
            !GateModel.controlsArmed(1000, 999999, humanActivated = false))
        check("agent action on ACP window refused: gesture",
            GateModel.agentActionOnAcpWindowRefused(GateModel.InjectionPath.GESTURE, true))
        check("agent action on ACP window refused: node action",
            GateModel.agentActionOnAcpWindowRefused(GateModel.InjectionPath.NODE_ACTION, true))
        check("agent action on ACP window refused: shell input",
            GateModel.agentActionOnAcpWindowRefused(GateModel.InjectionPath.SHELL_INPUT, true))
        check("agent action elsewhere not refused by this rule",
            !GateModel.agentActionOnAcpWindowRefused(GateModel.InjectionPath.GESTURE, false))
        // Gate surface source pins: full-screen sheet, payload quote,
        // deny-and-end wired, Box not covered by this window.
        val overlay = File(root,
            "app/src/main/java/io/agenticcontrol/app/server/ApprovalOverlay.kt").readText()
        check("gate sheet is full-screen",
            overlay.contains("WindowManager.LayoutParams.MATCH_PARENT,\n            WindowManager.LayoutParams.MATCH_PARENT"))
        // W10 (V3-F1): the payload renders through the escaping
        // that keeps shown == submitted byte-exact (OI-12), and
        // the gate starts DISARMED in effect — exits visible but
        // dimmed, decision clicks ignored until 600 ms + a human
        // activation (clicks must stay enabled-able for TalkBack,
        // the defect behind the old isEnabled=false shape).
        check("gate renders submitted payload verbatim (escaped, byte-exact)",
            overlay.contains("text = GateModel.escapePayload(payload)"))
        check("gate wires deny-and-end", overlay.contains("onDenyAndEnd"))
        // W13 superseded pin (cause: P1-F12 — armed-click shape
        // is now if (armedNow()) { onDecision() } else { feedback };
        // disarmed-at-start is unchanged).
        check("gate starts disarmed", overlay.contains("alpha = 0.45f") &&
            overlay.contains("if (armedNow())"))

        println("W6DesignTest: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

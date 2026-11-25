package io.agenticcontrol.app.design

import io.agenticcontrol.app.strings.ConsentStrings

/**
 * W6 — TRIO-SIGNED merged Android design of record, hero surfaces
 * part 1 (design-trio/merged/android-design-of-record.md). Pure
 * model layer: presence law (§1–§2), themes (§5), Home (§4 A1),
 * session detail (§4 A4) and the approval gate (§3). The Android
 * views render from these models; the JVM suite pins the record's
 * normative rules here so a view cannot drift from the record
 * silently. All user-facing wording comes from the U8-externalised
 * ConsentStrings defaults — no consent/presence literals live here.
 */
object PresenceLaw {

    /** §1.1 hues are meanings, fixed. ARGB. */
    val HUE_HUMAN: Int = 0xFF2FA84F.toInt()   // green — a human is acting
    val HUE_AI: Int = 0xFF7C4DFF.toInt()      // violet — an AI is acting
    val HUE_IDLE: Int = 0xFFF2A900.toInt()    // amber — session open, idle
    val HUE_STOP: Int = 0xFFDC2626.toInt()    // red — STOP/destructive only (FR-117: token STOP red, aligned cross-platform with the Windows pill's measured #DC2626 in W72)

    enum class Actor { HUMAN, AI, IDLE }

    fun hueFor(actor: Actor): Int = when (actor) {
        Actor.HUMAN -> HUE_HUMAN
        Actor.AI -> HUE_AI
        Actor.IDLE -> HUE_IDLE
    }

    /** §2: presence is EXACTLY three elements. Nothing else may be
     *  added — no badges, toasts, tray pop-ups or watermarks. */
    val ELEMENTS: List<String> = listOf("BOX", "GHOST", "GLOW")

    /** §2 fold table (normative): every §7 item lives in exactly
     *  one element or is a mirror of one. */
    val FOLD: Map<String, String> = mapOf(
        "banner" to "BOX",
        "live narration" to "BOX",
        "virtual finger" to "GHOST",
        "session sounds and haptics" to "BOX",
        "persistent notification" to "BOX (mirror)",
        "quick settings tile" to "BOX (mirror)",
        "flag secure moment" to "BOX"
    )

    /** Surfaces a presence hue may legally paint (§1.1): the three
     *  elements and their OS mirrors only — never brand, avatar,
     *  primary button, scope, selection, focus or health colour. */
    val HUE_LEGAL_SURFACES: Set<String> = setOf(
        // W12-DS P1-F17: "BOX (mirror)" — the exact string FOLD
        // returns for the notification/QS mirrors — is legal too;
        // the two tables now agree.
        "BOX", "BOX (mirror)", "GHOST", "GLOW", "TRAY_MIRROR", "QS_TILE_MIRROR",
        "NOTIFICATION_MIRROR"
    )

    fun hueLegalOn(surface: String): Boolean = surface in HUE_LEGAL_SURFACES

    /** §1.3 / §2 consent constants — identical on both platforms. */
    const val DWELL_MS: Long = 650
    const val SETTLE_MS: Long = 90
    const val BOX_MIN_HEIGHT_DP: Int = 110
    const val GATE_ARM_MS: Long = 600
    const val BOX_IN_MS: Long = 220
    const val BOX_OUT_MS: Long = 400
    const val GLOW_FADE_MS: Long = 600
    const val GATE_SHEET_MS: Long = 240
    const val STATE_CHANGE_MS: Long = 180

    /** §2 Ghost glide: clamp(220ms, 180 + 0.25ms/px, 600ms). */
    fun glideMs(distancePx: Int): Long =
        (180.0 + 0.25 * distancePx.coerceAtLeast(0)).toLong().coerceIn(220, 600)

    /** §2/§5: the Glow is static by default; the 6.4s / 82–100%
     *  breath exists only as a comfort setting (OI-04). */
    const val GLOW_BREATH_PERIOD_MS: Long = 6_400
    const val GLOW_BREATH_MIN_PCT: Int = 82
    const val GLOW_BREATH_MAX_PCT: Int = 100

    /** §2 Ghost: ring with the actor's initial inside — one
     *  geometry, initial carries identity. */
    fun ghostInitial(actorName: String): String =
        actorName.trim().firstOrNull()?.uppercase() ?: "?"

    /** §2: the Ghost withdraws while a gate is up and during owner
     *  takeover; only the floor holder's Ghost shows a dwell ring. */
    fun ghostDrawn(gateUp: Boolean, ownerDriving: Boolean): Boolean =
        !gateUp && !ownerDriving

    fun dwellShown(isFloorHolder: Boolean): Boolean = isFloorHolder

    /** §2 Box invariants: always dark (theme-invariant), full
     *  opacity, never minimises/dismisses/compacts while driving,
     *  STOP full-width in the same place in every state. */
    data class BoxModel(
        val actorName: String,
        val stateSentence: String,
        val elapsedText: String,
        val hueEdge: Int,
        val alwaysDark: Boolean = true,
        val fullOpacity: Boolean = true,
        val stopFullWidth: Boolean = true,
        val stopLabel: String = ConsentStrings.DEFAULTS.getValue("presence_stop")
    ) {
        // W12-DS P1-F16: the §2 invariants are INVARIANTS, not
        // overridable defaults — a BoxModel with any of them false
        // cannot be constructed.
        init {
            require(alwaysDark && fullOpacity && stopFullWidth) {
                "Box invariants are not optional: always dark, full opacity, STOP full-width"
            }
        }
    }

    /** §4 takeover: owner driving → green Glow + the driving
     *  sentence + Ghost withdrawn, so the three elements agree. */
    fun takeoverSentence(): String =
        ConsentStrings.DEFAULTS.getValue("presence_youre_driving")

    /** §2 watchdog honesty line (neutral fault treatment). */
    fun watchdogSentence(): String =
        ConsentStrings.DEFAULTS.getValue("presence_watchdog_line")

    /** §1.4 talk-through levels (OI-15). The sentence row itself is
     *  never removed at any level. */
    enum class TalkLevel { QUIET, MAIN, EVERY }

    fun narrationChanges(
        level: TalkLevel,
        isFirstAction: Boolean,
        isGate: Boolean,
        isIrreversible: Boolean,
        isFirstAfterIdle30s: Boolean,
        isAnyStep: Boolean
    ): Boolean = when (level) {
        TalkLevel.QUIET -> isGate || isIrreversible
        TalkLevel.MAIN -> isFirstAction || isGate || isIrreversible || isFirstAfterIdle30s
        TalkLevel.EVERY -> isAnyStep || isGate || isIrreversible
    }
}

/** §5 themes (D11): Follow system / Light / Dark. Both themes are
 *  first-class, hand-tuned designs — the light peer is NOT an
 *  inversion of dark (its surface, card and border values are its
 *  own). The Box is always dark in both. */
object HeroThemes {

    enum class Mode { FOLLOW_SYSTEM, LIGHT, DARK }

    data class Theme(
        val dark: Boolean,
        val surface: Int,
        val cardSurface: Int,
        val onSurface: Int,
        val muted: Int,
        val border: Int,
        val boxBackground: Int,
        val boxOnBackground: Int,
        val stopRed: Int,
        /** §3: Approve is achromatic — ink on surface. */
        val approveFill: Int,
        val approveText: Int
    )

    /** FR-117: the Box fill is the Gemini token navy #0F2537 — the
     *  cross-platform design of record, aligned with the Windows
     *  pill (W72, live-capture verified). */
    val BOX_BACKGROUND: Int = 0xFF0F2537.toInt()
    val BOX_ON_BACKGROUND: Int = 0xFFF4F4F6.toInt()

    val LIGHT = Theme(
        dark = false,
        surface = 0xFFFAF8F4.toInt(),
        cardSurface = 0xFFFFFFFF.toInt(),
        onSurface = 0xFF1B1B1F.toInt(),
        muted = 0xFF5C5C66.toInt(),
        border = 0xFFD8D4CC.toInt(),
        boxBackground = BOX_BACKGROUND,
        boxOnBackground = BOX_ON_BACKGROUND,
        stopRed = PresenceLaw.HUE_STOP,
        approveFill = 0xFF1B1B1F.toInt(),
        approveText = 0xFFFAF8F4.toInt()
    )

    val DARK = Theme(
        dark = true,
        surface = 0xFF101016.toInt(),
        cardSurface = 0xFF1B1B24.toInt(),
        onSurface = 0xFFF0F0F3.toInt(),
        muted = 0xFFA6A6B0.toInt(),
        border = 0xFF33333F.toInt(),
        boxBackground = BOX_BACKGROUND,
        boxOnBackground = BOX_ON_BACKGROUND,
        stopRed = PresenceLaw.HUE_STOP,
        approveFill = 0xFFF0F0F3.toInt(),
        approveText = 0xFF101016.toInt()
    )

    fun resolve(mode: Mode, systemDark: Boolean): Theme = when (mode) {
        Mode.LIGHT -> LIGHT
        Mode.DARK -> DARK
        Mode.FOLLOW_SYSTEM -> if (systemDark) DARK else LIGHT
    }
}

/** §4 A1 Home — order is law (OI-11): (1) state sentence, (2) This
 *  phone readiness ledger (a problem promotes to the top; a
 *  non-decision does not appear), (3) Who may connect, (4) Recent
 *  sessions, (5) standing sections. The promotion rule orders the
 *  list; it never deletes a section. Home's title is the device's
 *  name, never the product name. */
object HomeModel {

    data class ReadinessRow(val label: String, val consequence: String, val isProblem: Boolean)
    data class AgentRow(val name: String, val accessLabel: String, val chatSentCount: Int)
    data class Model(
        val title: String,
        val stateSentence: String,
        val sessionRunning: Boolean,
        val readiness: List<ReadinessRow>,
        val agents: List<AgentRow>,
        val recentSessions: List<String>,
        val standingSections: List<String>
    )

    /** The standing sections the A1 inventory names; where a named
     *  capability is not in this build, its row says so. */
    val STANDING_SECTIONS: List<String> = listOf(
        "Recovery", "Platform", "Boot and restart health", "Audit",
        "Approvals", "Shell", "Devices",
        ConsentStrings.DEFAULTS.getValue("home_invisible_apps_not_built")
    )

    fun noSessionSentence(): String =
        ConsentStrings.DEFAULTS.getValue("home_no_one_in_phone")

    fun sessionSentence(agentName: String): String =
        ConsentStrings.DEFAULTS.getValue("home_agent_in_phone")
            .replace("%1\$s", agentName)

    fun build(
        deviceName: String,
        sessionAgent: String?,
        readiness: List<ReadinessRow>,
        agents: List<AgentRow>,
        recentSessions: List<String>
    ): Model {
        // Promotion rule: problems first, stable order otherwise.
        val ordered = readiness.filter { it.isProblem } + readiness.filter { !it.isProblem }
        return Model(
            title = deviceName,
            stateSentence = if (sessionAgent == null) noSessionSentence()
                else sessionSentence(sessionAgent),
            sessionRunning = sessionAgent != null,
            readiness = ordered,
            agents = agents,
            recentSessions = recentSessions,
            standingSections = STANDING_SECTIONS
        )
    }

    /** §4 A1 [R1]: new pairings default to observe only. */
    const val NEW_PAIRING_ACCESS: String = "Look only"

    /** "Connected — not in a session" carries a neutral dot and a
     *  word, never green (no presence hue off the elements). */
    fun connectedNotInSessionLabel(): String =
        ConsentStrings.DEFAULTS.getValue("home_connected_not_session")
}

/** §4 A4 session detail: verdict sentence first, then the three
 *  counts as separate labelled numbers (never an arithmetic
 *  equation), then destinations, the fixed provider line, the
 *  vendor line, gaps named as what was not seen, then the feed.
 *  [R1/R4 ledger rule] frames delivered to an off-device agent
 *  count as Sent to that named destination; chat messages to an
 *  off-device agent likewise count as Sent. */
object SessionDetailModel {

    data class Counts(val read: Int, val sent: Int, val changed: Int) {
        /** Separate labelled numbers — never "r + s + c = n". */
        fun labelled(): List<Pair<String, Int>> = listOf(
            "Read" to read, "Sent" to sent, "Changed" to changed
        )
    }

    data class Model(
        val verdict: String,
        val counts: Counts,
        val destinationLine: String,
        val providerLine: String,
        val vendorLine: String,
        val gapsLine: String?,
        val presenceOnFramesLine: String,
        val replayLine: String
    )

    /** Off-device frames are Sent; on-device frames are Read only.
     *  [R4] every canonical board draws the off-device case. */
    fun countsFor(
        framesDelivered: Int,
        agentOffDevice: Boolean,
        sentOther: Int,
        changed: Int,
        readOther: Int
    ): Counts = if (agentOffDevice) {
        Counts(read = readOther, sent = sentOther + framesDelivered, changed = changed)
    } else {
        Counts(read = readOther + framesDelivered, sent = sentOther, changed = changed)
    }

    fun build(
        verdict: String,
        counts: Counts,
        agentName: String,
        agentDevice: String,
        screens: Int,
        gaps: List<String>
    ): Model = Model(
        verdict = verdict,
        counts = counts,
        destinationLine = "$screens screens → $agentName on $agentDevice",
        providerLine = ConsentStrings.DEFAULTS.getValue("session_provider_line")
            .replace("%1\$s", agentName),
        vendorLine = ConsentStrings.DEFAULTS.getValue("session_vendor_line"),
        gapsLine = if (gaps.isEmpty()) null else
            ConsentStrings.DEFAULTS.getValue("session_not_seen")
                .replace("%1\$s", gaps.joinToString(", ")),
        presenceOnFramesLine =
            ConsentStrings.DEFAULTS.getValue("session_presence_on_frames"),
        replayLine = ConsentStrings.DEFAULTS.getValue("session_replay_not_built")
    )

    /** [R6] a gate mid-session quotes counts "so far", never the
     *  end-of-session total. */
    fun seenSoFarLine(screensSeenSoFar: Int): String =
        ConsentStrings.DEFAULTS.getValue("session_seen_so_far")
            .replace("%1\$d", screensSeenSoFar.toString())

    /** A4: chat Sent entries surface on the agent card. */
    fun chatSentLine(count: Int): String =
        ConsentStrings.DEFAULTS.getValue("chat_sent_count")
            .replace("%1\$d", count.toString())
}

/** §3 the gate: full-screen sheet with the amber Box held above it
 *  (STOP included; the sheet never replaces or covers the Box).
 *  Exits exactly three, at exactly equal weight. Gate-fidelity law
 *  (OI-12): the gate quotes the payload the tool call will actually
 *  submit, byte for byte — [payloadMatches] is the build fixture's
 *  comparison. Agent-input exclusion (OI-13): ACP windows are not
 *  valid agent targets; gate controls arm only after 600 ms AND a
 *  human activation. */
object GateModel {

    data class Exit(val label: String, val weight: Int, val borderContrast: Int)

    /** [R6 fold] Approve and Deny both 600 weight, same border, in
     *  each theme. Deny-and-end carries the same equal treatment. */
    fun exits(): List<Exit> {
        val approve = ConsentStrings.DEFAULTS.getValue("approval_approve")
        val deny = ConsentStrings.DEFAULTS.getValue("approval_deny")
        val denyEnd = ConsentStrings.DEFAULTS.getValue("gate_deny_and_end")
        return listOf(
            Exit(approve, 600, 1),
            Exit(deny, 600, 1),
            Exit(denyEnd, 600, 1)
        )
    }

    /** W10 (V3-F1): the RENDERED style of one exit. All three
     *  exits carry exactly this style — same fill, same text
     *  colour, same border — so no exit outweighs another and
     *  none is the brightest thing on the sheet except STOP
     *  (which is not on the sheet; it lives on the Box above it).
     *  The weight and border contrast come from [exits], so the
     *  model values are what the overlay actually reads. */
    data class ExitStyle(
        val label: String,
        val fill: Int,
        val textColor: Int,
        val borderColor: Int,
        val weight: Int,
        val borderContrast: Int
    )

    /** The three exits styled for [theme]: identical treatment
     *  for Approve, Deny and Deny-and-end — the neutral card
     *  surface with the theme border, never the solid ink fill
     *  (a solid near-white Approve in the dark theme broke §3:
     *  only STOP may be the brightest thing present). */
    fun exitStyles(theme: HeroThemes.Theme): List<ExitStyle> =
        exits().map { exit ->
            ExitStyle(
                label = exit.label,
                fill = theme.cardSurface,
                textColor = theme.onSurface,
                borderColor = theme.border,
                weight = exit.weight,
                borderContrast = exit.borderContrast
            )
        }

    /** OI-13 second wall (W10, V3-F6): the gate card and every
     *  exit set filterTouchesWhenObscured, so a third-party
     *  overlay drawn over the gate cannot pass taps through to
     *  it. The overlay reads this pin; the fixture asserts both. */
    const val FILTER_TOUCHES_WHEN_OBSCURED: Boolean = true

    /** OI-12 display escaping (W10, V3-F1): the payload the owner
     *  reads must be the payload that will be submitted — bidi
     *  controls and other invisible characters are made VISIBLE
     *  as escapes, never silently rendered, so a payload cannot
     *  look different from its bytes. [unescapePayload] is the
     *  exact inverse for printable text. */
    fun escapePayload(payload: String): String {
        val sb = StringBuilder()
        for (ch in payload) {
            when (ch.code) {
                // Bidi controls / isolates / BOM: invisible
                // characters that can make shown text differ
                // from its bytes — rendered as visible escapes.
                0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF ->
                    sb.append("\\u%04X".format(ch.code))
                else -> when {
                    ch.code < 0x20 && ch != '\n' && ch != '\t' ->
                        sb.append("\\u%04X".format(ch.code))
                    ch.code == 0x7F -> sb.append("\\u007F")
                    else -> sb.append(ch)
                }
            }
        }
        return sb.toString()
    }

    fun unescapePayload(shown: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < shown.length) {
            if (shown[i] == '\\' && i + 6 <= shown.length && shown[i + 1] == 'u') {
                val hex = shown.substring(i + 2, i + 6)
                val code = hex.toIntOrNull(16)
                if (code != null) {
                    sb.append(code.toChar())
                    i += 6
                    continue
                }
            }
            sb.append(shown[i])
            i++
        }
        return sb.toString()
    }

    /** OI-12, the overlay-level fixture (W10, V3-F1): the string
     *  the overlay DISPLAYED (after escaping) must decode back to
     *  exactly the bytes the tool call submits. This is the
     *  comparison the real call site is pinned to — not two
     *  arrays a caller happens to supply. */
    fun overlayPayloadMatches(shownText: String, submitted: String): Boolean =
        unescapePayload(shownText) == submitted &&
            payloadMatches(
                unescapePayload(shownText).toByteArray(Charsets.UTF_8),
                submitted.toByteArray(Charsets.UTF_8)
            )

    /** No "Allow for this session" anywhere, for any class. */
    fun hasSessionAllow(): Boolean = false

    fun noSessionAllowLine(): String =
        ConsentStrings.DEFAULTS.getValue("gate_no_session_allow")

    /** OI-12 fixture comparison: the bytes the gate renders must be
     *  exactly the bytes the tool call submits — same length, same
     *  bytes, no re-encoding, no trimming. */
    fun payloadMatches(gateShown: ByteArray, submitted: ByteArray): Boolean =
        gateShown.contentEquals(submitted)

    fun draftMarker(): String =
        ConsentStrings.DEFAULTS.getValue("gate_draft_not_sent")

    fun chatOriginLine(): String =
        ConsentStrings.DEFAULTS.getValue("gate_asked_from_chat")

    /** OI-13 arming: at least [PresenceLaw.GATE_ARM_MS] elapsed AND
     *  a human activation (touch or the owner's own TalkBack
     *  activation — never the agent's service). */
    fun controlsArmed(shownAtMs: Long, nowMs: Long, humanActivated: Boolean): Boolean =
        humanActivated && nowMs - shownAtMs >= PresenceLaw.GATE_ARM_MS

    /** W13 P1-F12: the activation is carried IN the model — when it
     *  happened and what source produced it — not as a bare caller
     *  boolean. An activation stamped before the sheet was shown,
     *  or from a source that is not the owner's own touch/click,
     *  never arms the controls. */
    data class Activation(val atMs: Long, val source: String)

    val ACTIVATION_SOURCES: Set<String> = setOf("touch", "click", "talkback")

    fun controlsArmed(shownAtMs: Long, nowMs: Long, activation: Activation?): Boolean {
        val a = activation ?: return false
        if (a.source !in ACTIVATION_SOURCES) return false
        if (a.atMs < shownAtMs) return false
        return nowMs - shownAtMs >= PresenceLaw.GATE_ARM_MS
    }

    /** OI-13: an agent action whose target is an ACP window is
     *  refused at ACP's own action layer, on every injection path. */
    enum class InjectionPath { GESTURE, NODE_ACTION, SHELL_INPUT }

    fun agentActionOnAcpWindowRefused(path: InjectionPath, targetIsAcpWindow: Boolean): Boolean =
        targetIsAcpWindow // refused on all three paths when the target is ours

    // ---- W8 item 5: OI-13 injection-path fixtures, real paths ----
    // The W6 pins above proved the MODEL. These are the decision
    // functions the real injection paths consult, so the fixtures
    // exercise the same code the paths run:
    //  - GESTURE / NODE_ACTION: ControlAccessibilityService asks
    //    [targetIsAcpWindow] with the live target's package (node
    //    package for performAction, foreground package for raw
    //    coordinate gestures) before dispatching anything.
    //  - SHELL_INPUT: ShellToolHost asks [shellInputRefused]
    //    before the gate. A shell `input …` command's coordinate
    //    target cannot be resolved to a package from the command
    //    text, so synthetic-input verbs are refused outright on
    //    this path (their target cannot be proven NOT to be an
    //    ACP window), as is any shell command that launches or
    //    drives ACP's own package.

    /** True when [targetPackage] is ACP's own package. A null or
     *  blank target is NOT ACP as a CLASSIFICATION (observation of
     *  other apps is the product's purpose). Classification is not
     *  an action decision: the action paths must not treat
     *  "not proven ACP" as "proven safe" — see
     *  [nodeTargetRefused] / [coordinateTargetRefused]. */
    fun targetIsAcpWindow(targetPackage: String?, ownPackage: String): Boolean =
        !targetPackage.isNullOrBlank() && targetPackage == ownPackage

    /** W13 P1-F2 (coordinate-path remainder, closed): raw-coordinate
     *  gestures resolve their target from the FOREGROUND package,
     *  which is null mid-transition (no active window). On this
     *  path an unknown target is REFUSED — the gesture cannot prove
     *  it does not land on an ACP window, and OI-13 is fail-closed. */
    fun coordinateTargetRefused(targetPackage: String?, ownPackage: String): Boolean =
        targetPackage.isNullOrBlank() || targetIsAcpWindow(targetPackage, ownPackage)

    /** W15 P1-F2 (GENUINELY OVERTURNED by round-2, closed):
     *  the W13 node-path rebuttal claimed a null package means no
     *  node exists, hence no action. That does not hold: a NON-NULL
     *  live node can still expose a null packageName, and that node
     *  reaches performAction (tapByRef's clickable branch, typeText's
     *  SET_TEXT) with the null consulted and waved through. The node
     *  ACTION decision is therefore fail-closed, exactly like the
     *  coordinate decision: a null/blank target package REFUSES, an
     *  own-package target REFUSES, and only a non-null, non-blank,
     *  non-own package may proceed. Every action path that consults
     *  a node's (or a launch request's) package — tap, type, launch —
     *  asks THIS function, via the service's targetIsOwnWindow. */
    fun nodeTargetRefused(targetPackage: String?, ownPackage: String): Boolean =
        targetPackage.isNullOrBlank() || targetIsAcpWindow(targetPackage, ownPackage)

    // W12-DS P1-F1 fix: the old literal-substring filter was
    // bypassable by path prefixes (/system/bin/input), TAB
    // separators, quoting, $() substitution, flags before the verb
    // (input -d 0 tap), and unlisted verbs (draganddrop/press/
    // roll/keycombination); pm clear / am force-stop on ACP itself
    // were not refused at all. The filter now TOKENISES: quotes,
    // backslashes and shell separators (; & | $ ( ) `) are stripped
    // or split, and decisions are made on executable basenames.
    // ANY invocation of the `input` binary is refused (it is a
    // synthetic-input tool with no non-injection use), `monkey` is
    // refused outright, and any am/pm command that names ACP's own
    // package as a token is refused whatever the subcommand.
    //
    // W15 P1-F1 (FIX-INADEQUATE per round-2, completed):
    // `cmd` equivalents (cmd input / cmd activity / cmd package),
    // $VAR references naming a dangerous verb, assignments carrying
    // a dangerous value, quote/backslash JOINING, and an
    // unresolvable $VAR command word in an input-verb / self
    // context were all added — see W15AndFixTest.
    //
    // W17 P1-F1 STRUCTURAL FIX (round-2 + W16
    // confirmation: two list-fix rounds each closed the named
    // forms and the next round found the same class again —
    // expansion-boundary joins: in${X}put, a${X}m, in$(true)put,
    // cmd $SUB start-activity <own>, $X $Y). The fix is therefore
    // structural, not another list extension:
    //  1. EXPANSION NORMALISATION. [normaliseExpansions] produces
    //     a normalised stream in which every expansion construct
    //     — $VAR, ${...}, $(...), $((...)), backtick spans — is
    //     REMOVED in a way that JOINS the surrounding literal text
    //     (in${X}put -> input, in$(true)put -> input, a${X}m ->
    //     am), with quote/backslash joins applied the same way.
    //     Denied-verb matching ([refusedOnTokens]) runs against
    //     BOTH the legacy raw token stream (every refusal it
    //     earned still fires) AND the normalised stream, so a verb
    //     spelled across an expansion boundary is seen whole in
    //     one stream or the other. Substitution bodies ($(...)
    //     and backtick contents) are also re-checked as commands
    //     in their own right, recursively.
    //  2. VERB-POSITION EXPANSION RULE. An aligned scan
    //     ([scanSegments]) keeps, per token, its literal
    //     (normalised) text, whether it contained an expansion,
    //     and which variables it named. Where the COMMAND WORD,
    //     or the verb slot following cmd/am/pm/monkey, contained
    //     an expansion whose resolution is not provably a benign
    //     literal, the input-verb / self-target context refuses —
    //     fail-closed on an unresolvable verb position:
    //     cmd $SUB start-activity <own> refuses ($SUB unresolvable
    //     in the cmd verb slot, the tail names the own package in
    //     an activity context); $X $Y refuses (command word AND
    //     its verb both expansions); $X tap refuses (unresolvable
    //     command word, literal input verb). A command word whose
    //     expansions are all ordinary environment names (HOME,
    //     PATH, …) AND which still resolves to a literal path
    //     ($HOME/bin/tool) is provably a benign literal and stays
    //     allowed, as do ordinary expansions in argument position
    //     (echo $HOME, ls ${HOME}/docs) — the ordinary-shell floor
    //     does not move.
    //     W19 COMPLETION (round-3): the slot branch of
    //     that rule only failed closed when the slot expansion
    //     normalised to empty; a non-empty expansion contributing
    //     the missing character (cmd ${X}ctivity, X=a) skipped
    //     it. The verb slots are now PURE LITERALS: the slot
    //     following cmd/am/pm/monkey refuses on ANY expansion
    //     construct in its raw token, whatever it might produce
    //     and whatever the context. Argument positions keep the
    //     W17 posture exactly.
    //  3. The own-package self-target guarantee is evaluated on
    //     the normalised stream as well as the raw one, for
    //     am/pm/cmd-activity/cmd-package forms, so a package name
    //     spelled across an expansion boundary is still recognised
    //     as ACP's own.
    //
    // W22 GRAMMAR AWARENESS (round-4, W21 confirmation):
    // the W19 pure-literal slot rule fired only when the
    // scanner's recognised command word was the shell's. Two
    // desync classes closed here, in [scanSegments] +
    // [verbPositionRefused] (full model + stated limits there):
    //  (a) REDIRECTIONS — `cmd >/dev/null ${X}ctivity …` made
    //     the scanner take /dev/null as the verb slot while the
    //     shell consumed it as a redirection target. Redirection
    //     operators (incl. digit-prefixed and attached forms)
    //     now consume their target token; targets are never
    //     command words, verb slots, or self-target arguments,
    //     wherever the redirection sits.
    //  (b) RESERVED-WORD PREFIXES — `if cmd ${X}ctivity …`
    //     made the scanner stop at `if`. Grammar/transparent
    //     prefixes (if/then/else/elif/while/until/do/!/{/}/
    //     exec/command/time/builtin/xargs and the closing
    //     words) are now unwrapped recursively per segment
    //     before the command position is located.
    // Fail-closed boundary: an unparseable COMMAND POSITION
    // refuses only in an input-verb / self-target context;
    // redirections alone never refuse (benign redirected
    // commands stay allowed).
    //
    // W25 ASSEMBLED-WORD RULE (round-5, W23
    // confirmation): the boundary above was evaded inside a
    // CASE arm — `case x in x) "$(printf %s a)m" start -n
    // "io.agenticcontrol.ap$(printf %s p)/.MainActivity";; esac`
    // — because neither the verb nor the package ever appears
    // literally and the whole arm sits in the unparseable
    // `case` segment. Structural closure, in [verbPositionRefused]:
    //  (a) ASSEMBLED WORDS inside an unparseable segment (and
    //     inside an if/while/until/elif CONDITION segment, whose
    //     command is reached only by unwrapping) refuse
    //     unconditionally: a word carrying an expansion joined
    //     with literal text, or more than one expansion, is
    //     assembled at expansion time and cannot be proven not
    //     to spell a denied verb or the own package. A PURE
    //     word — exactly one expansion and no literal text
    //     (`echo $(date)` in an arm) — stays allowed.
    //  (b) CASE-ARM PARSING: `)` now leaves a marker token, and
    //     each arm body after a marker is re-scanned as its own
    //     command (normal verb-position + slot rules, plus, in
    //     arm context, a pure-substitution command word or a
    //     substitution-bearing tail after a literal slot parent
    //     refuses — inside an arm nothing substitution-carried
    //     in a verb position is provable).
    //  (c) OUTSIDE any construct (proven reachable by probe,
    //     W25): a literal cmd/am/pm/monkey command word with a
    //     SUBSTITUTION-ASSEMBLED word anywhere in its tail
    //     refuses — `am start -n "io.agenticcontrol.ap$(printf
    //     %s p)/.MainActivity"` assembled the own package past
    //     every view. Variable-assembled tails keep the W17
    //     posture ($PKG/.Main stays allowed): a named variable
    //     is joined optimistically by normalisation, a command
    //     substitution's output is arbitrary.
    // Stated residual (W25): a pure single substitution in
    // ARGUMENT position outside an arm/condition (e.g.
    // `am start -n $(cat f)`) was not resolvable and stayed
    // allowed — CLOSED in W28, see below.
    //
    // W28 ROUND-6 CLOSURES (round-6, W27 confirmation):
    //  (a) SECOND-SHELL RE-PARSE. The W25 rules scan ONE shell's
    //     grammar; a quoted payload handed to a SECOND shell was
    //     never re-checked — `sh -c 'a$(printf %s m) start -n
    //     "io.agenticcontrol.ap$(printf %s p)/.MainActivity"'`
    //     assembled `am` + the own package inside the inner
    //     shell and escaped every view. [payloadInvocationRefused]
    //     now locates payload invocations at the corrected
    //     command position — a shell interpreter (sh/bash/dash/
    //     ash/zsh/ksh/mksh, or `busybox <applet>`) with a `-c`
    //     flag, `eval` (its arguments joined as the shell joins
    //     them), `su -c` (direct payload), transparent wrappers
    //     leading to one of those (env/nohup/setsid/timeout/
    //     stdbuf/doas/nice, plus the W22 grammar prefixes incl.
    //     xargs), and `find -exec`/`-execdir` nested commands —
    //     extracts the payload argument as a literal string and
    //     runs the FULL filter over it as its own command line,
    //     recursively, depth-capped at 3 (a payload invocation
    //     at the cap refuses: deeper is unscannable). A payload
    //     argument that cannot be extracted verbatim (an
    //     expansion or backtick in an UNQUOTED position of the
    //     payload token — its value/splitting is the outer
    //     shell's expansion result, not a string this filter
    //     can read) REFUSES: an unscannable payload is an
    //     unknown payload. Expansions inside quotes extract
    //     verbatim, because the inner shell is what expands
    //     them — the recursion then judges exactly the string
    //     the inner shell parses. The recursion closes the
    //     verbatim string only together with one new pair rule
    //     in [segRefused]: a non-provably-benign ASSEMBLED
    //     command word paired with a SUBSTITUTION-ASSEMBLED
    //     tail word refuses — inside the payload BOTH the verb
    //     and the package are substitution-assembled, so no
    //     literal slot-parent rule and no token view can see
    //     either one whole (probed: the extracted payload alone
    //     was ALLOWED by every pre-W28 rule).
    //  (b) SLOT-PARENT SUBSTITUTION CLOSURE (the W25 named
    //     residual, rejected by round-6): when the
    //     command word is a literal slot parent (cmd/am/pm/
    //     monkey), ANY command-substitution token anywhere in
    //     its tail refuses — pure or assembled. The slot value
    //     a substitution produces is unknown, and unknown in a
    //     denied verb's argument fails closed. Parameter
    //     expansion ($PKG, ${PKG}) is NOT a command
    //     substitution and keeps the W17 posture exactly.
    // Stated limits (W28): an interpreter reading a script FILE
    // (`sh /sdcard/x`) is not a payload invocation — the file's
    // contents are not in the command string and cannot be
    // scanned; expansions in a wrapper's own flag positions
    // (env/timeout/…) leave the nested command unlocatable by
    // this pass and keep the prior rules' posture.
    //
    // W32 ROUND-7 CLOSURES (round-7, W31 confirmation;
    // every claim probed against pre-W32 code first —
    // see the W32 lane log for probe outcomes, including the
    // one claim NOT reproduced as stated):
    //  (1) ASSEMBLED COMMAND WORD. An assembled word (an
    //     expansion joined with literal text, or several
    //     expansions in one word) in COMMAND position refuses
    //     in every context, whatever its tail: the command
    //     word must be assessable, and an assembled word's
    //     expansion-time value is not. Carve-outs, both pinned:
    //     the W17 variable-only path form (`$HOME/bin/tool` —
    //     no substitution, literal final component), and the
    //     PURE single-expansion command word (`$(echo ls)
    //     -la` stays allowed: its body is re-checked as a
    //     command, and every tail that would make an unknown
    //     verb dangerous is literal and judged). Assembled
    //     words in ARGUMENT position are untouched.
    //  (2) INTERPRETER SCRIPT FILES REFUSE (coordinator
    //     decision): a shell interpreter (sh/bash/dash/ash/
    //     zsh/ksh/mksh, incl. via busybox/toybox applet
    //     dispatch and wrappers) invoked with a script-file
    //     operand refuses — inline -c payloads remain
    //     available and are scanned; an unscannable file is
    //     an unknown payload. The stdin forms of the same
    //     unknown payload refuse too (-s, a bare -, and an
    //     input redirection with no -c payload). Enumeration
    //     of this Android shell environment (the shell channel
    //     is the phone's own /system/bin/sh — mksh — plus
    //     stock toybox; no other interpreter is stock):
    //     toybox awk's unambiguous -f file forms refuse the
    //     same way; toybox sed -f is NOT closed (toybox sed
    //     has no command-execution primitive — residual);
    //     non-stock interpreters (python/perl/lua/node/…)
    //     are not invocable in the stock environment
    //     (residual if one is ever installed).
    //  (3) EXPANSION IN WRAPPER POSITION. Inside a wrapper
    //     chain (env/nohup/setsid/timeout/stdbuf/doas/nice/
    //     xargs/find -exec/busybox/toybox/exec/command/time/
    //     builtin), any expansion in a position the unwrapping
    //     must step over — flag, flag argument, assignment
    //     value, duration, applet name, or the nested command
    //     word itself — refuses: the final command cannot be
    //     determined, and unknown fails closed. This closes
    //     the W28 stated limit (2) above. Literal chains stay
    //     allowed.
    //  (4) su TRAILING COMMAND. `su` without -c: tokens after
    //     the user operand (and flags) are joined and recursed
    //     as a payload, exactly like eval's arguments;
    //     ambiguous shapes (an expansion where a flag, the
    //     user, or the command start should be) refuse. This
    //     closes the W28 stated limit on su. Semantics note in
    //     [invocationRefused]: stock Android ships no su; the
    //     general su contract passes post-user arguments to
    //     the shell, and no Android su binary exists in this
    //     environment to test against, so the fail-closed
    //     reading is implemented.
    //
    // W40 ROUND-8 CLOSURES (round-8, W33 confirmation;
    // every DeepSeek claim probed against pre-W40 code
    // first — see the W40 lane log for probe outcomes; all
    // four claims reproduced as stated):
    //  (1) CARVE-OUT HOLE. The W17 variable-path carve-out
    //     required only norm.contains('/') — never a literal
    //     final component — so `$HOME/bin/$PATH` (PATH set
    //     by an earlier assignment to a traversal ending in
    //     an assembled `input`) was "provably benign" and
    //     its tail was never judged. The carve-out now
    //     covers variable DIRECTORY components only:
    //     [finalCompLiteral] requires the final component
    //     (the program name) to be literal text with no
    //     expansion inside it, in both the assembled-word
    //     carve-out and the provablyBenign test. Composition
    //     pinned: with a literal final component the tail
    //     checks still judge the NAME — a literal
    //     input/monkey final component refuses outright,
    //     and slot-parent names keep the slot block, which
    //     runs on the corrected basename regardless of the
    //     directory expansions.
    //  (2) PURE-SUBSTITUTION COMMAND WORD (residual A).
    //     [invocationRefused] returned on hadExpansion
    //     before the shells branch, so `$(echo sh) -c '…'`
    //     never had its payload scanned. A pure substitution
    //     whose body is a simple literal-producing form
    //     (echo/printf of literals — [resolvePureSubst]) is
    //     now resolved and the full invocation rules apply
    //     to the resolved word, payload recursion included;
    //     variable-assembled command words inside the
    //     payload (`${i}put`) then refuse under the existing
    //     W32 assembled-word rule, as they already did in
    //     directly scanned payloads. An unresolvable pure
    //     substitution with a -c-shaped tail or any
    //     substitution in its tail refuses. The pinned
    //     benign pure-substitution uses stay allowed
    //     ($(echo ls) -la resolves to a benign verb with a
    //     judged literal tail; $(echo sh) -c 'echo hi'
    //     resolves and its payload scans benign).
    //  (3) ANSI-C QUOTING. $'...' segments are DECODED
    //     during tokenisation ([decodeAnsiC]: \xHH, octal,
    //     \n, \t, \\, \', \u/\U, \cX, the C one-letter set),
    //     in both the normalised stream and the aligned
    //     scan, so every view sees the decoded word
    //     ($'in\x70ut' is `input`). An undecodable segment
    //     in command position (or verb-slot / payload
    //     position) refuses.
    //  (4) AWK (residual B). Flag handling is now
    //     CASE-SENSITIVE where case survives (top level):
    //     [ScanTok.caseNorm] carries each token's
    //     original-case literal text, and the awk flag
    //     walker refuses the -f script-file flag in all
    //     its forms while -F keeps its separator. Inline
    //     awk program text is scanned for embedded command
    //     strings (system() arguments and pipe-position
    //     string literals), each run through the full
    //     filter; an unextractable system() argument
    //     refuses. Residual: inside a re-parsed payload the
    //     text arrives case-folded, so a plain-name -f
    //     there keeps the W32 posture (path/.awk/--file
    //     forms still refuse). [W45: that residual is
    //     CLOSED — see (2) below.]
    //
    // W45 ROUND-9 CLOSURES (round-9, W41 confirmation;
    // every DeepSeek claim probed against pre-W45 code
    // first — see the W45 lane log for probe outcomes; all
    // four claims reproduced as stated):
    //  (1) RESOLVED-NAME RULE. The round-9 counter-example
    //     was the carve-out class again, one step over:
    //     `$HOME/bin/sh` has a literal final component, so
    //     the carve-out accepted it, and [invocationRefused]
    //     returned on hadExpansion before the shells branch
    //     — the `-c` payload (verb variable-assembled as
    //     `${i}put`) was never scanned. Now, when a command
    //     word's final component is literal (written
    //     literally or reached through the variable-
    //     directory carve-out) and names a program the
    //     invocation pass dispatches on (sh/bash/dash/ash/
    //     zsh/ksh/mksh, busybox/toybox, su, the command-
    //     running wrappers, awk, eval, find), the RESOLVED
    //     name takes its rules in full — payload extraction
    //     and recursion included. (Denied verbs and slot
    //     parents under a variable path were already judged
    //     by name in [verbPositionRefused]: `$HOME/bin/input`
    //     refused pre-W45 and still refuses.) A literal
    //     final component naming nothing dispatched keeps
    //     the carve-out's benign treatment
    //     (`$HOME/bin/tool run` stays allowed). Inside a
    //     wrapper chain the W32 posture stands (an expansion
    //     in the nested command position refuses).
    //  (2) PAYLOAD CASE PRESERVATION (residual (i)).
    //     Payload extraction worked on the case-folded scan,
    //     so `sh -c 'awk -f prog'` was allowed at depth 1:
    //     the recursion could not tell -f from -F. The
    //     scanner now carries each token's original-case raw
    //     text ([ScanTok.caseRaw], mirrored from the
    //     original-case twin), extraction extracts from it,
    //     substitution bodies are recorded from the
    //     original-case string, and ANSI-C segments decode
    //     from the original-case segment when the span
    //     matches. The awk flag walker is therefore
    //     case-sensitive at EVERY depth: depth-1 and
    //     depth-2 `awk -f` refuse, depth-1 `awk -F:`
    //     controls stay allowed.
    //  (3) UNRESOLVABLE COMMAND WORDS FAIL CLOSED
    //     (residual (ii)). A PURE-substitution command word
    //     whose producer does not resolve to a literal word
    //     through [resolvePureSubst] now REFUSES whatever
    //     its tail: the executed word is the substitution's
    //     output (e.g. file content), which is unknowable,
    //     and unknowable in command position fails closed.
    //     This deliberately flips the W40 pin
    //     `$(cat /sdcard/c) -la` from allowed to refused —
    //     the named cost of the rule. Resolved forms keep
    //     working: `$(echo ls) -la` allowed; `$(echo sh)
    //     -c 'echo hi'` allowed with its payload scanned.
    //  (4) AWK ADJACENT-LITERAL CONCATENATION (residual
    //     (iv)). Awk concatenates whitespace-separated
    //     adjacent string literals; the embedded-command
    //     scan now joins them ([joinAwkAdjacentLiterals])
    //     before judging system() arguments and
    //     pipe-position literals, and checks every system()
    //     call, not only the first. Benign adjacent-literal
    //     programs without embedded commands stay allowed.
    //
    // W47 ROUND-10 CLOSURES (round-10, W46 confirmation;
    // every DeepSeek claim probed against pre-W47 code
    // first — see the W47 lane log for probe outcomes):
    //  (1) RESOLVED-NAME COMPLETENESS. The W45 set omitted
    //     every name dispatched by the command-position
    //     LOCATOR rather than the unwrap loop — `xargs` (the
    //     round-10 counter-example: `HOME=/system;
    //     $HOME/bin/xargs sh -c "$(echo in)put tap 1 1"` was
    //     ALLOWED) and, probed with it, `exec`, `command`,
    //     `time`, `builtin`. Root fix, not a name patch: the
    //     filter's name tables are hoisted to ONE GateModel-
    //     level source ([grammarPrefixWords],
    //     [prefixFlagArgWords], [chainPrefixWords],
    //     [shellNames], [multicallNames],
    //     [wrapperFlagArgWords], [slotParentNames],
    //     [deniedVerbNames]) read by every pass, and
    //     [dispatchedNames] is DERIVED from them; the
    //     resolved-name replacement now also runs in the
    //     locator, before it decides a token is not a prefix.
    //     The W47 suite's source cross-check enumerates the
    //     dispatch branches/tables from this file and fails
    //     if any recognised name is outside the derived set.
    //  (2) AWK NON-LITERAL system() ARGUMENTS (residual
    //     R3). The W45 count check was satisfied by a literal
    //     PREFIX: `system("in" x)` and `system("in"
    //     substr("put tap 1 1",1))` were ALLOWED, the
    //     variable/function suffix never judged. Now each
    //     system() argument is PARSED: after adjacent-literal
    //     joining it must be one PURE string literal followed
    //     by `)` — anything else (variable concatenation,
    //     function calls, variable references) refuses as
    //     unextractable. The same purity rule applies to a
    //     string literal that is only part of a pipe command
    //     expression ([awkCompoundPipeLiteralRefused]).
    //     Pure-literal arguments keep the exact prior
    //     treatment (joined, then shell-filtered); programs
    //     with no system() and no compound pipe literal are
    //     untouched.
    //
    // W49 ROUND-11 CLOSURE (round-11, W48 confirmation;
    // DeepSeek's counter-example probed against pre-W49
    // code first — see the W49 lane log): PURITY AT EVERY
    // AWK COMMAND SINK. The W47 rule judged system() and
    // literals that were PART of a pipe expression, but a
    // pipe command carried ENTIRELY by a variable has no
    // literal for it to judge: `awk 'BEGIN{c="in" "put
    // tap 1 1"; c | getline}'` was ALLOWED — the joined
    // literals assemble the command inside `c` and the
    // pipe executes it. The rule now runs at the sink
    // itself ([awkCommandSinkRefused]): at system(), at
    // print/printf pipes, at `expr | getline` and at the
    // gawk coprocess `|&`, the command operand must be a
    // PURE string literal at the sink (after the W45
    // joining); a variable, a field, a function call, a
    // parenthesised expression, or any concatenation
    // involving a non-literal REFUSES as unextractable —
    // no data-flow tracking, the filter's consistent
    // posture. Pure-literal sink commands keep the exact
    // prior treatment (joined, then shell-filtered).
    // File redirection is NOT a command sink: `print …
    // > expr`, `print … >> expr` and `getline … < expr`
    // keep their prior treatment whatever the filename
    // expression is, distinguished from pipes by awk's
    // own grammar (`>`/`>>`/`<` vs `|`/`|&`).
    //
    // W51 ROUND-12 CLOSURE (round-12, W50 confirmation;
    // DeepSeek's counter-example probed against pre-W51
    // code first — see the W51 lane log): ESCAPE-DECODING
    // FIDELITY. The sink rule was sound but the DECODER
    // feeding it was not: [unescapeAwkString] collapsed
    // backslash pairs, so `system("\151nput tap 1 1")`
    // was judged as `151nput…` while awk's octal escape
    // made the executed command `input tap 1 1`. The
    // decoder now reproduces awk's decoding EXACTLY
    // (one-letter set, octal \ooo, hex \xhh — see its doc
    // for the dialect table and why \x is decoded) and
    // returns null for forms the variants decode
    // differently (\x with no digit, \u/\U, \e/\E); every
    // caller treats null as unextractable and refuses.
    // The decoded text is what flows into payload
    // recursion at system(), at every pipe sink and in
    // the pipe-position scan. SAME-CLASS AUDIT, shell
    // side: [decodeAnsiC] was re-checked against mksh/
    // bash $'...' — faithful on the one-letter set,
    // octal, \xhh, \u/\U and unknown escapes (backslash
    // kept), with ONE divergence found and fixed (\c?
    // is DEL, not 0x1F). The payload extractor's
    // double-quote backslash handling is POSIX-faithful
    // (backslash collapses only before $ ` " \ newline;
    // [extractPayloadLiteral]). The aligned scan's own
    // quote handling was NOT faithful — it collapsed
    // backslash pairs inside single quotes, where the
    // shell keeps the backslash, mangling the awk
    // program's escapes before the awk decoder ran;
    // [scanSegments] now applies each quote kind's own
    // backslash rule, so a token's literal text is the
    // text the shell delivers. The remaining token
    // views (legacy strip, expansion normalisation) are
    // judgement views only — they never feed payload
    // extraction, and they strip/collapse a SUPERSET of
    // the shell's removals, so they cannot hide a verb
    // the shell would form.
    //
    // W53 ROUND-13 CLOSURES (round-13, W52 confirmation;
    // DeepSeek's two counter-examples probed against
    // pre-W53 code first — see the W53 lane log):
    //  (1) BACKSLASH-LF LINE CONTINUATION. POSIX/mksh
    //     delete a backslash immediately followed by a
    //     newline in unquoted and double-quoted contexts
    //     (line continuation), so `sh -c "in\<LF>put tap
    //     1 1"` executes `input tap 1 1`; pre-W53 every
    //     text-assembly path kept the LF, the recursion
    //     split at it, and no verb was judged. The rule
    //     now is per-context fidelity, applied at every
    //     place command/literal text is assembled or
    //     split: the pair is DELETED where the shell
    //     deletes it — [scanSegments]' unquoted and
    //     double-quoted branches, [normaliseExpansions]
    //     outside single quotes, the legacy view via
    //     [deleteLineContinuations], and
    //     [extractPayloadLiteral]'s unquoted and
    //     double-quoted branches — and KEPT where the
    //     shell keeps it: single-quoted spans in all of
    //     the above (the literal is carried verbatim into
    //     payload recursion / the awk decoder, which judge
    //     it in the inner context), and ANSI-C $'...'
    //     segments ([decodeAnsiC] keeps the pair — probed
    //     against bash: $'ec\<LF>ho' is a literal word,
    //     not `echo`). Substitution and backtick bodies
    //     are recorded verbatim and re-parsed by the
    //     recursion, whose own contexts apply the same
    //     rule. AWK path: a backslash-LF inside an awk
    //     string literal is deleted by
    //     [unescapeAwkString] (probed against BWK awk and
    //     mawk: system("ec\<LF>ho …") executes `echo …` —
    //     whether the awk source continuation or the
    //     inner shell's deletion does the joining, the
    //     executed command is the joined text, and judging
    //     the joined text can only over-refuse a dialect
    //     that would pass a bare LF through, never
    //     under-refuse), and [awkProgramTextRefused]
    //     deletes the pair in program text outside the
    //     decoder's reach the same way. A benign command
    //     split across lines stays allowed; only the
    //     joined text is judged.
    //  (2) \x IN AWK STRING LITERALS IS UNEXTRACTABLE.
    //     The W51 dialect argument for decoding \xhh as
    //     hex is REJECTED (round-13 residual R2): under a
    //     BWK reading \x27 is the literal text `x27`, so
    //     the semicolons it was meant to quote stay active
    //     in the executed command while the hex reading
    //     makes them inert — a dangerous-direction
    //     divergence — and which awk binary PATH
    //     resolution selects on the device is unknowable
    //     (BWK builds themselves disagree: the Debian
    //     BWK build probed in the W53 lane log DECODES
    //     \x). [unescapeAwkString] therefore returns null
    //     for \x in any form, joining \u/\U and \e/\E in
    //     the divergent set; every caller refuses. Cost,
    //     named in the W53 lane log per case: benign
    //     hex-decoded sink commands pinned allowed in W51
    //     (e.g. system("\x65cho hi")) now refuse. OCTAL
    //     stays decoded: the byte value of \ooo is agreed
    //     by BWK, mawk, gawk and busybox awk (probed for
    //     BWK/mawk in the W53 lane log: \777 is one byte
    //     everywhere; \400 is the NUL byte everywhere —
    //     the only divergence is whether a string's
    //     length counts that NUL, which cannot form a
    //     verb the byte reading lacks).
    fun shellInputRefused(command: String, ownPackage: String): Boolean =
        shellInputRefused(command, ownPackage, 0)

    private fun shellInputRefused(command: String, ownPackage: String, depth: Int): Boolean {
        val own = ownPackage.trim().lowercase()
        val raw = command.lowercase()
        val dangerousVerbs = setOf("input", "monkey", "am", "pm", "cmd")
        // A variable REFERENCE naming a dangerous verb itself
        // refuses — the expansion names the verb, so the command
        // cannot be proven not to invoke it.
        val varNames = Regex("""\$\{?([a-z_][a-z0-9_]*)""").findAll(raw)
            .map { it.groupValues[1] }.toList()
        if (varNames.any { it in dangerousVerbs }) return true

        // View 1 — the legacy (W12/W15) token stream, kept intact
        // so every refusal it earned still fires. W53: the raw
        // text is first passed through [deleteLineContinuations]
        // so a verb split by a backslash-LF the shell deletes
        // (unquoted / double-quoted) is joined in this view too,
        // while a backslash-LF inside single quotes — literal
        // text the shell keeps — is left for the chain below,
        // whose backslash strip leaves the LF as a separator
        // (the literal is judged as the literal it is).
        val cleaned = deleteLineContinuations(raw)
            .replace("\\", "").replace("\"", "").replace("'", "")
            .replace('`', ' ').replace('$', ' ')
        val legacyTokens = cleaned.split(Regex("[\\s;|&()<>={}]+")).filter { it.isNotBlank() }
        if (refusedOnTokens(legacyTokens, own)) return true

        // View 2 — the expansion-normalised token stream (joins
        // across expansion boundaries; see the header note).
        val inners = mutableListOf<String>()
        val normalised = normaliseExpansions(raw, inners, command)
        val normTokens = normalised.split(Regex("[\\s;|&()<>={}]+")).filter { it.isNotBlank() }
        if (refusedOnTokens(normTokens, own)) return true

        // Verb-position expansion rule over the aligned scan.
        val segments = scanSegments(raw, inners, command)
        if (verbPositionRefused(segments, own)) return true

        // W28 (a): second-shell payload re-parse — a payload
        // argument handed to another shell (or eval, or a
        // find -exec nested command) is a command line in its
        // own right and is judged by the full filter,
        // recursively (see the W28 header note).
        if (payloadInvocationRefused(segments, own, ownPackage, depth)) return true

        // Substitution bodies are commands in their own right.
        if (depth < 3) {
            for (inner in inners.distinct()) {
                if (inner.isNotBlank() && shellInputRefused(inner, ownPackage, depth + 1)) return true
            }
        }
        return false
    }

    // W47 (round-10, point 1): the shell filter's program-name
    // tables live HERE, once, at GateModel level — every pass
    // that recognises a program name reads these same vals, and
    // [dispatchedNames] is DERIVED from them, so a name added to
    // any dispatch table is covered by the resolved-name rule by
    // construction. (Pre-W47 the tables were re-declared inside
    // each pass and [dispatchedNames] was a hand-maintained
    // list: it omitted `xargs` — and `exec` / `command` /
    // `time` / `builtin` — which the prefix pass dispatches on,
    // so `$HOME/bin/xargs sh -c '…'` never took xargs' rules
    // and its payload was never scanned. The W47 suite carries
    // a source cross-check that fails if a dispatch branch or
    // table names a program the derived set does not cover.)
    /** Grammar prefix words recognised by the command-position
     *  locators (both passes): shell grammar keywords plus the
     *  command-running prefixes. Literal tokens only. */
    private val grammarPrefixWords = setOf(
        "if", "then", "else", "elif", "while", "until", "do",
        "fi", "done", "esac", "!", "{", "}",
        "exec", "command", "time", "builtin", "xargs"
    )

    /** Flags of the grammar prefixes that consume the following
     *  token as their argument. */
    private val prefixFlagArgWords: Map<String, Set<String>> = mapOf(
        "exec" to setOf("-a"),
        "xargs" to setOf("-I", "-L", "-n", "-P", "-d", "-E", "-e", "-s", "-a", "-J"),
        "time" to setOf("-o", "-f")
    )

    /** The prefix words that RUN a following command (the
     *  grammar keywords in [grammarPrefixWords] do not): being
     *  consumed by one puts the scan inside a wrapper chain. */
    private val chainPrefixWords = setOf("xargs", "exec", "command", "time", "builtin")

    /** The shell interpreters the invocation pass dispatches on. */
    private val shellNames = setOf("sh", "bash", "dash", "ash", "zsh", "ksh", "mksh")

    /** The multicall binaries: the applet name after one is the
     *  nested command word. */
    private val multicallNames = setOf("busybox", "toybox")

    /** Command-running wrappers and the flags of each that
     *  consume the following token as their argument. */
    private val wrapperFlagArgWords: Map<String, Set<String>> = mapOf(
        "env" to setOf("-u", "-C", "--unset", "--chdir"),
        "setsid" to emptySet(),
        "timeout" to setOf("-k", "-s", "--kill-after", "--signal"),
        "stdbuf" to setOf("-i", "-o", "-e", "--input", "--output", "--error"),
        "doas" to setOf("-u", "-C"),
        "nice" to setOf("-n", "--adjustment")
    )

    /** Slot parents judged by name in [verbPositionRefused]. */
    private val slotParentNames = setOf("cmd", "am", "pm", "monkey")

    /** Denied verbs judged by name regardless of expansion
     *  ([verbPositionRefused] / [refusedOnTokens]). */
    private val deniedVerbNames = setOf("input", "monkey")

    /** W47: every program name the filter treats specially
     *  ANYWHERE — DERIVED from the dispatch tables above plus
     *  the invocation pass's remaining branch names (su, nohup,
     *  awk, eval, find, whose branches the W47 source
     *  cross-check enumerates from the dispatch code itself).
     *  The resolved-name rule ([invocationRefused]) judges a
     *  variable-directory command word against this set: a
     *  literal final component naming one of these takes the
     *  resolved name's rules in full. */
    private val dispatchedNames = shellNames + multicallNames +
        setOf("su", "nohup", "awk", "eval", "find") +
        wrapperFlagArgWords.keys + chainPrefixWords +
        prefixFlagArgWords.keys + slotParentNames + deniedVerbNames

    /** Denied-verb matching over ONE token stream: any `input` /
     *  `monkey` basename refuses outright; any am/pm form naming
     *  the own package refuses; `cmd input` refuses outright and
     *  `cmd activity` / `cmd package` refuse when the own package
     *  is named. Run against both the raw and the normalised
     *  streams by [shellInputRefused]. */
    private fun refusedOnTokens(tokens: List<String>, own: String): Boolean {
        if (tokens.isEmpty()) return false
        val basenames = tokens.map { it.substringAfterLast('/') }
        if (basenames.any { it == "input" || it == "monkey" }) return true
        val namesOwn = own.isNotEmpty() && tokens.any { tok ->
            tok == own || tok.startsWith("$own/") || tok.startsWith("$own:")
        }
        if (namesOwn && basenames.any { it == "am" || it == "pm" }) return true
        for (i in basenames.indices) {
            if (basenames[i] != "cmd") continue
            // Subcommand = first non-flag token after `cmd`.
            var j = i + 1
            while (j < basenames.size && basenames[j].startsWith("-")) j++
            if (j >= basenames.size) break
            when (basenames[j]) {
                "input" -> return true
                "activity", "package" -> if (namesOwn) return true
            }
        }
        return false
    }

    /** W53: [s] with every shell line continuation — a
     *  backslash immediately followed by a newline —
     *  DELETED in the contexts where the shell deletes
     *  it (unquoted and double-quoted text) and KEPT in
     *  single-quoted spans, where backslash and newline
     *  are both literal. Quote state is tracked with the
     *  shell's own rules (a backslash outside single
     *  quotes escapes the next character, so an escaped
     *  quote never toggles state). Used by the legacy
     *  judgement view in [shellInputRefused]; the
     *  faithful paths ([scanSegments],
     *  [extractPayloadLiteral]) apply the same rule in
     *  their own quote branches. */
    private fun deleteLineContinuations(s: String): String {
        val out = StringBuilder()
        var i = 0
        var inSingle = false
        var inDouble = false
        while (i < s.length) {
            val c = s[i]
            when {
                inSingle -> {
                    out.append(c)
                    if (c == '\'') inSingle = false
                    i++
                }
                c == '\\' && i + 1 < s.length && s[i + 1] == '\n' -> i += 2
                c == '\\' && i + 1 < s.length -> {
                    out.append(c); out.append(s[i + 1]); i += 2
                }
                c == '\'' && !inDouble -> { inSingle = true; out.append(c); i++ }
                c == '"' -> { inDouble = !inDouble; out.append(c); i++ }
                else -> { out.append(c); i++ }
            }
        }
        return out.toString()
    }

    /** Index of the closing [close] matching the [open] at
     *  [openIdx], or the last index when unbalanced. */
    private fun findBalanced(s: String, openIdx: Int, open: Char, close: Char): Int {
        var depth = 0
        var i = openIdx
        while (i < s.length) {
            val c = s[i]
            if (c == '\\') { i += 2; continue }
            if (c == open) depth++
            else if (c == close) { depth--; if (depth == 0) return i }
            i++
        }
        return s.length - 1
    }

    /** If an expansion construct starts at [i] (s[i] == '$'),
     *  returns the index just past it and records any command
     *  substitution body in [inners]; -1 when the '$' is a lone
     *  literal. The construct contributes NOTHING to the output —
     *  that removal is what joins the surrounding literal text. */
    /** W40: decodes the ANSI-C quoted segment starting at
     *  [start] (s[start] == '$', s[start+1] == '\''). Returns
     *  the decoded text and the index just past the closing
     *  quote, or null when the segment is undecodable or
     *  unterminated. Escapes: the C one-letter set, \xHH (1–2
     *  hex digits), octal (up to 3 digits), \uHHHH, \UHHHHHHHH
     *  and \cX. An unknown escape keeps its backslash (the
     *  mksh/bash posture for unrecognised escapes), so the
     *  decoded word is exactly the word the shell would use. */
    private fun decodeAnsiC(s: String, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var j = start + 2
        fun hexAt(pos: Int, count: Int): Int? {
            if (pos + count > s.length) return null
            val h = s.substring(pos, pos + count)
            if (!h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            return h.toInt(16)
        }
        while (j < s.length) {
            val c = s[j]
            when {
                c == '\'' -> return sb.toString() to (j + 1)
                c == '\\' -> {
                    if (j + 1 >= s.length) return null
                    val e = s[j + 1]
                    when {
                        e == 'a' -> { sb.append('\u0007'); j += 2 }
                        e == 'b' -> { sb.append('\b'); j += 2 }
                        e == 'e' || e == 'E' -> { sb.append('\u001B'); j += 2 }
                        e == 'f' -> { sb.append('\u000C'); j += 2 }
                        e == 'n' -> { sb.append('\n'); j += 2 }
                        e == 'r' -> { sb.append('\r'); j += 2 }
                        e == 't' -> { sb.append('\t'); j += 2 }
                        e == 'v' -> { sb.append('\u000B'); j += 2 }
                        e == '\\' -> { sb.append('\\'); j += 2 }
                        e == '\'' -> { sb.append('\''); j += 2 }
                        e == '"' -> { sb.append('"'); j += 2 }
                        e == '?' -> { sb.append('?'); j += 2 }
                        e == 'x' -> {
                            var k = j + 2
                            var digits = ""
                            while (k < s.length && digits.length < 2 &&
                                (s[k] in '0'..'9' || s[k] in 'a'..'f' || s[k] in 'A'..'F')) {
                                digits += s[k]; k++
                            }
                            if (digits.isEmpty()) return null
                            sb.append(digits.toInt(16).toChar()); j = k
                        }
                        e == 'u' -> {
                            val v = hexAt(j + 2, 4) ?: return null
                            sb.append(v.toChar()); j += 6
                        }
                        e == 'U' -> {
                            val v = hexAt(j + 2, 8) ?: return null
                            if (v > 0x10FFFF) return null
                            sb.append(String(Character.toChars(v))); j += 10
                        }
                        e == 'c' -> {
                            if (j + 2 >= s.length) return null
                            // W51 audit fix: \c? is DEL (0x7F)
                            // in bash/mksh, not 0x1F — the old
                            // mask mis-decoded exactly that one
                            // control char. Other \cX keep the
                            // mask (letters fold to their
                            // control value under it).
                            val cx = s[j + 2]
                            sb.append(if (cx == '?') '\u007F'
                                else (cx.code and 0x1F).toChar()); j += 3
                        }
                        e in '0'..'7' -> {
                            var k = j + 1
                            var digits = ""
                            while (k < s.length && digits.length < 3 && s[k] in '0'..'7') {
                                digits += s[k]; k++
                            }
                            sb.append((digits.toInt(8) and 0xFF).toChar()); j = k
                        }
                        else -> { sb.append('\\'); sb.append(e); j += 2 }
                    }
                }
                else -> { sb.append(c); j++ }
            }
        }
        return null
    }

    /** W40: true when the FINAL component (the program name)
     *  of the word [raw] contains an expansion construct —
     *  walked over the raw token with quote/expansion spans
     *  consumed atomically, so a '/' inside a quoted span or
     *  an ANSI-C segment counts as the literal separator it
     *  is, and an expansion after the last literal '/'
     *  marks the final component as expansion-carried. */
    private fun finalComponentHasExpansion(raw: String): Boolean {
        var exp = false
        var i = 0
        val scratch = mutableListOf<String>()
        while (i < raw.length) {
            val c = raw[i]
            when {
                c == '\\' -> {
                    if (i + 1 < raw.length && raw[i + 1] == '/') exp = false
                    i += 2
                }
                c == '\'' -> {
                    i++
                    while (i < raw.length && raw[i] != '\'') {
                        if (raw[i] == '/') exp = false
                        i++
                    }
                    i++
                }
                c == '"' -> {
                    i++
                    while (i < raw.length && raw[i] != '"') {
                        when {
                            raw[i] == '\\' -> i += 2
                            raw[i] == '/' -> { exp = false; i++ }
                            raw[i] == '$' && i + 1 < raw.length && raw[i + 1] == '\'' -> {
                                val dec = decodeAnsiC(raw, i)
                                if (dec == null) { exp = true; i = raw.length }
                                else {
                                    if (dec.first.contains('/')) exp = false
                                    i = dec.second
                                }
                            }
                            raw[i] == '$' -> {
                                val end = dollarEnd(raw, i, scratch)
                                if (end < 0) i++ else { exp = true; i = end }
                            }
                            raw[i] == '`' -> {
                                exp = true
                                i++
                                while (i < raw.length && raw[i] != '`') { if (raw[i] == '\\') i++; i++ }
                                i++
                            }
                            else -> i++
                        }
                    }
                    i++
                }
                c == '$' && i + 1 < raw.length && raw[i + 1] == '\'' -> {
                    val dec = decodeAnsiC(raw, i)
                    if (dec == null) { exp = true; i = raw.length }
                    else {
                        if (dec.first.contains('/')) exp = false
                        i = dec.second
                    }
                }
                c == '$' -> {
                    val end = dollarEnd(raw, i, scratch)
                    if (end < 0) i++ else { exp = true; i = end }
                }
                c == '`' -> {
                    exp = true
                    i++
                    while (i < raw.length && raw[i] != '`') { if (raw[i] == '\\') i++; i++ }
                    i++
                }
                c == '/' -> { exp = false; i++ }
                else -> i++
            }
        }
        return exp
    }

    /** W40: the command word's final component is LITERAL
     *  text — a non-empty normalised final component with no
     *  expansion anywhere inside it. Only then is the executed
     *  program name known whatever the variables hold. */
    private fun finalCompLiteral(tok: ScanTok): Boolean =
        tok.norm.substringAfterLast('/').isNotEmpty() &&
            !finalComponentHasExpansion(tok.raw)

    /** W40: a PURE substitution command word — exactly one
     *  command substitution and no literal text. */
    private fun isPureSubst(tok: ScanTok): Boolean =
        tok.expCount == 1 && tok.hadSubst && tok.norm.isEmpty()

    /** W40: resolves a PURE substitution command word whose
     *  body is a simple literal-producing form — `echo` of
     *  literal words, or `printf` of a literal format with
     *  literal arguments — to the word it produces, or null
     *  when the body is anything else (an expansion inside,
     *  several commands, a non-literal producer, or a result
     *  that is not a single word). */
    private fun resolvePureSubst(tok: ScanTok): String? {
        if (!isPureSubst(tok)) return null
        val raw = tok.raw.trim()
        val body: String = when {
            raw.startsWith("\$(") -> {
                val end = findBalanced(raw, 1, '(', ')')
                if (end + 1 != raw.length) return null
                raw.substring(2, end)
            }
            raw.length >= 2 && raw.startsWith("`") && raw.endsWith("`") ->
                raw.substring(1, raw.length - 1)
            else -> return null
        }
        if (body.isBlank()) return null
        val scratch = mutableListOf<String>()
        val segs = scanSegments(body, scratch)
        if (segs.size != 1 || segs[0].danglingRedir) return null
        val toks = segs[0].toks.filter { !it.redirTarget && !it.parenClose }
        if (toks.isEmpty() || toks.any { it.hadExpansion || it.ansiBad }) return null
        val producer = toks[0].norm.substringAfterLast('/')
        val args = toks.drop(1).map { it.norm }
        val result: String = when (producer) {
            "echo" -> args.dropWhile { it == "-n" || it == "-e" || it == "-E" }
                .joinToString(" ")
            "printf" -> {
                if (args.isEmpty()) return null
                val format = args[0]
                val sb = StringBuilder()
                var ai = 1
                var fi = 0
                var hadSpecifier = false
                var ok = true
                while (fi < format.length && ok) {
                    val ch = format[fi]
                    if (ch == '%') {
                        if (fi + 1 >= format.length) { ok = false; break }
                        when (format[fi + 1]) {
                            '%' -> { sb.append('%'); fi += 2 }
                            's', 'd', 'i', 'c' -> {
                                hadSpecifier = true
                                if (ai >= args.size) { ok = false; break }
                                sb.append(args[ai]); ai++; fi += 2
                            }
                            else -> { ok = false }
                        }
                    } else { sb.append(ch); fi++ }
                }
                if (!ok) return null
                if (hadSpecifier && ai != args.size) return null
                sb.toString()
            }
            else -> return null
        }
        if (result.isEmpty() || result.any { it.isWhitespace() }) return null
        return result
    }

    private fun dollarEnd(s: String, i: Int, inners: MutableList<String>, orig: String = s): Int {
        if (i + 1 >= s.length) return -1
        val c1 = s[i + 1]
        return when {
            c1 == '{' -> findBalanced(s, i + 1, '{', '}') + 1
            c1 == '(' -> {
                val end = findBalanced(s, i + 1, '(', ')')
                // W45: the recorded body comes from [orig] (the
                // original-case twin) so a substitution body
                // re-scanned as its own command keeps its case.
                val inner = orig.substring(i + 2, maxOf(i + 2, minOf(end, orig.length)))
                if (inner.isNotBlank()) inners += inner
                end + 1
            }
            c1.isLetter() || c1 == '_' -> {
                var j = i + 1
                while (j < s.length && (s[j].isLetterOrDigit() || s[j] == '_')) j++
                j
            }
            c1 in "?$#@*!-" || c1.isDigit() -> i + 2
            else -> -1
        }
    }

    /** The expansion-normalised form of [s]: quotes dropped,
     *  backslash joins applied, every expansion construct removed
     *  joining the surrounding literal text, backtick spans
     *  removed joining (their bodies recorded in [inners], as are
     *  $(...) bodies). */
    private fun normaliseExpansions(s: String, inners: MutableList<String>, orig: String = s): String {
        val out = StringBuilder()
        var i = 0
        // W53: quote state, tracked only so the backslash-LF
        // rule below can be per-context (see the W53 header
        // note on [shellInputRefused]); every other collapse
        // in this judgement view keeps its prior posture.
        var inSingle = false
        var inDouble = false
        while (i < s.length) {
            val c = s[i]
            when {
                c == '\\' -> {
                    // W53: a backslash-LF pair is a line
                    // continuation the shell DELETES outside
                    // single quotes — appending the LF would
                    // split a joined verb back into fragments
                    // in this stream. Inside single quotes the
                    // pair is literal text and the LF is kept
                    // (it separates, exactly as the literal
                    // separates in the delivered string).
                    if (i + 1 < s.length && s[i + 1] == '\n' && !inSingle) i += 2
                    else if (i + 1 < s.length) { out.append(s[i + 1]); i += 2 } else i++
                }
                c == '`' -> {
                    var j = i + 1
                    while (j < s.length && s[j] != '`') { if (s[j] == '\\') j++; j++ }
                    // W45: body recorded from [orig] (case kept).
                    val inner = orig.substring(i + 1, minOf(j, orig.length))
                    if (inner.isNotBlank()) inners += inner
                    i = if (j < s.length) j + 1 else s.length
                }
                // W40: an ANSI-C quoted segment contributes its
                // DECODED text to the normalised stream, so the
                // token views see the word the shell will run
                // ($'in\x70ut' -> input). An undecodable segment
                // contributes nothing here; the aligned scan
                // marks it and command position fails closed.
                c == '$' && i + 1 < s.length && s[i + 1] == '\'' -> {
                    val dec = decodeAnsiC(s, i)
                    if (dec != null) { out.append(dec.first); i = dec.second } else {
                        var j = i + 2
                        while (j < s.length && s[j] != '\'') { if (s[j] == '\\') j++; j++ }
                        i = if (j < s.length) j + 1 else s.length
                    }
                }
                c == '$' -> {
                    val end = dollarEnd(s, i, inners, orig)
                    if (end < 0) { out.append('$'); i++ } else i = end
                }
                c == '\'' || c == '"' -> {
                    // W53: track quote state for the
                    // backslash-LF rule above (an ANSI-C
                    // segment's quotes are consumed by the
                    // $'...' branch and never reach here).
                    if (c == '\'' && !inDouble) inSingle = !inSingle
                    if (c == '"' && !inSingle) inDouble = !inDouble
                    i++
                }
                else -> { out.append(c); i++ }
            }
        }
        return out.toString()
    }

    /** One scanned token: [raw] as written, [norm] its literal
     *  text after quote/backslash joining and expansion removal,
     *  [hadExpansion] whether it contained any expansion or
     *  substitution construct, [vars] the variable names it
     *  referenced. [redirTarget] (W22): this token is the target
     *  of a redirection operator — the shell consumes it as a
     *  file/fd name, so in the grammar-aware scan it is NEVER
     *  a command word or a verb slot and never counts as a
     *  self-target argument. (The legacy token-stream views
     *  in [shellInputRefused] are not position-aware and may
     *  still over-refuse a target that literally spells a
     *  denied word or the own package exactly — fail-closed
     *  over-refusal, retained so every refusal they earned
     *  still fires.) */
    private data class ScanTok(
        val raw: String,
        val norm: String,
        val hadExpansion: Boolean,
        val vars: List<String>,
        val redirTarget: Boolean = false,
        // W32: the redirection that produced this target was an
        // INPUT redirection (`<`, `<<`, `<>`): its target feeds
        // the command's stdin, so a shell interpreter with no
        // -c payload and an input redirection is reading its
        // script from that target (see the W32 header note).
        val redirInput: Boolean = false,
        // W25: number of expansion constructs in the token and
        // whether any was a COMMAND SUBSTITUTION ($(...) with a
        // non-arithmetic body, or a backtick span). Together with
        // [norm] these define an ASSEMBLED word: an expansion
        // joined with literal text (norm non-empty) or several
        // expansions in one word — its expansion-time value
        // cannot be proven from the literal text. A token with
        // exactly one expansion and empty [norm] is PURE.
        val expCount: Int = 0,
        val hadSubst: Boolean = false,
        // W40: this token contained a $'...' ANSI-C quoted
        // segment the decoder could not decode — its literal
        // text is unknown, so command position fails closed.
        val ansiBad: Boolean = false,
        // W40: [norm] as it appeared in the ORIGINAL-case
        // command string (the scanner runs on a case-folded
        // copy; [caseNorm] preserves case for the one consumer
        // that is case-sensitive by nature: awk flag letters,
        // where -f and -F are different flags).
        val caseNorm: String = norm,
        // W45: [raw] as it appeared in the ORIGINAL-case
        // command string. Payload extraction walks the raw
        // token, so without this the payload text handed to
        // the recursion was case-folded and every depth below
        // the top lost case-sensitive flag discipline (the
        // round-9 residual (i): `sh -c 'awk -f prog'`).
        val caseRaw: String = raw,
        // W25: this token is the `)` marker [scanSegments] emits
        // so case-arm bodies can be re-scanned as commands. It
        // carries no literal text any rule may match on.
        val parenClose: Boolean = false
    )

    /** One scanned command segment (W22 grammar model).
     *  [danglingRedir]: a redirection operator in this segment
     *  had no target token before the segment ended. A dangling
     *  redirection is a shell SYNTAX ERROR — the shell runs
     *  nothing — so it never refuses on its own (see the
     *  fail-closed boundary in [verbPositionRefused]). */
    private data class ScanSeg(
        val toks: List<ScanTok>,
        val danglingRedir: Boolean
    )

    /** Aligned scan of [s] into command segments (split on
     *  ; | & and newlines). Quoted spans, backtick spans and
     *  $(...)/${...} constructs are consumed atomically so their
     *  contents never split a token; substitution bodies are
     *  recorded in [inners]. */
    private fun scanSegments(s: String, inners: MutableList<String>, orig: String = s): List<ScanSeg> {
        // W40: [orig] is the original-case twin of the (case-
        // folded) [s]; [caseB] mirrors [normB] append for
        // append so each token also carries its original-case
        // literal text. Falls back to [s] when lengths differ.
        val origS = if (orig.length == s.length) orig else s
        val segments = mutableListOf<ScanSeg>()
        var seg = mutableListOf<ScanTok>()
        val rawB = StringBuilder()
        // W45: mirrors [rawB] append for append from [origS],
        // so each token also carries its raw text in original
        // case ([ScanTok.caseRaw]) for payload extraction.
        val rawCaseB = StringBuilder()
        val normB = StringBuilder()
        val caseB = StringBuilder()
        var hadExp = false
        var expCount = 0
        var hadSubst = false
        var ansiBad = false
        val vars = mutableListOf<String>()
        // W22: true while the NEXT token flushed is the target
        // of a redirection operator just consumed. Persists
        // across whitespace (detached form `> /dev/null`) and
        // clears the moment a real token is flushed as target.
        var pendingRedir = false
        var pendingRedirInput = false
        fun tokenPresent() = rawB.isNotEmpty() || normB.isNotEmpty() || hadExp
        fun flushTok() {
            if (tokenPresent()) {
                seg += ScanTok(rawB.toString(), normB.toString(), hadExp, vars.toList(), pendingRedir, redirInput = pendingRedirInput, expCount = expCount, hadSubst = hadSubst, ansiBad = ansiBad, caseNorm = caseB.toString().ifEmpty { normB.toString() }, caseRaw = rawCaseB.toString().ifEmpty { rawB.toString() })
                pendingRedir = false
                pendingRedirInput = false
            }
            rawB.clear(); rawCaseB.clear(); normB.clear(); caseB.clear(); hadExp = false; expCount = 0; hadSubst = false; ansiBad = false; vars.clear()
        }
        fun flushSeg() {
            flushTok()
            val dangling = pendingRedir
            pendingRedir = false
            pendingRedirInput = false
            if (seg.isNotEmpty() || dangling) segments += ScanSeg(seg, dangling)
            seg = mutableListOf()
        }
        // Consumes the expansion at s[i] == '$' into the current
        // token (nothing joins normB — the removal IS the join).
        fun dollar(i: Int): Int {
            if (i + 1 >= s.length) { rawB.append('$'); rawCaseB.append(origS[i]); normB.append('$'); caseB.append(origS[i]); return i + 1 }
            val c1 = s[i + 1]
            return when {
                c1 == '{' -> {
                    val end = findBalanced(s, i + 1, '{', '}')
                    val inside = s.substring(i + 2, maxOf(i + 2, minOf(end, s.length)))
                    val name = inside.takeWhile { it.isLetterOrDigit() || it == '_' }
                    if (name.isNotEmpty()) vars += name
                    // A ${...} whose default/alternate text runs a
                    // command substitution is substitution-bearing.
                    if (inside.contains("\$(") || inside.contains('`')) hadSubst = true
                    hadExp = true; expCount++
                    rawB.append(s.substring(i, minOf(end + 1, s.length)))
                    rawCaseB.append(origS.substring(i, minOf(end + 1, origS.length)))
                    end + 1
                }
                c1 == '(' -> {
                    val end = dollarEnd(s, i, inners, origS)
                    // $((...)) is arithmetic, not a command
                    // substitution; every other $(...) is one.
                    if (!(i + 2 < s.length && s[i + 2] == '(')) hadSubst = true
                    hadExp = true; expCount++
                    rawB.append(s.substring(i, minOf(end, s.length)))
                    rawCaseB.append(origS.substring(i, minOf(end, origS.length)))
                    end
                }
                c1.isLetter() || c1 == '_' -> {
                    var j = i + 1
                    while (j < s.length && (s[j].isLetterOrDigit() || s[j] == '_')) j++
                    vars += s.substring(i + 1, j)
                    hadExp = true; expCount++; rawB.append(s.substring(i, j))
                    rawCaseB.append(origS.substring(i, j))
                    j
                }
                c1 in "?$#@*!-" || c1.isDigit() -> {
                    vars += c1.toString()
                    hadExp = true; expCount++; rawB.append(s.substring(i, i + 2))
                    rawCaseB.append(origS.substring(i, i + 2))
                    i + 2
                }
                else -> { rawB.append('$'); rawCaseB.append(origS[i]); normB.append('$'); caseB.append(origS[i]); i + 1 }
            }
        }
        // W22: consumes a redirection operator starting at
        // s[i] ('>', '<', or '&' of '&>'/'&>>'). A digit-only
        // token directly attached before the operator is its
        // fd prefix (`2>`), never a word; any other attached
        // token is a word and is flushed first (`hi>file`).
        // The operator itself produces NO token: it arms
        // [pendingRedir] so the next token — attached
        // (`2>/dev/null`) or detached (`> /dev/null`) — is
        // marked as the redirection target. A `<(` / `>(`
        // process substitution is not a redirection: it is a
        // word (an fd path) and its body is re-checked via
        // [inners] like any substitution.
        fun redir(i: Int): Int {
            if (tokenPresent()) {
                val isFdPrefix = !hadExp && vars.isEmpty() &&
                    normB.isNotEmpty() && normB.all { it.isDigit() } && rawB.toString() == normB.toString()
                if (isFdPrefix) {
                    rawB.clear(); rawCaseB.clear(); normB.clear(); caseB.clear()
                } else flushTok()
            }
            var j = i
            // Operator characters: the lead char plus a doubled
            // char, a trailing '&' (`>&`, `<&`), the second char
            // of `<>`, or the `>` run of `&>` / `&>>`.
            j++
            if (j < s.length && (s[j] == s[i] || s[j] == '&' ||
                    (s[i] == '<' && s[j] == '>') || (s[i] == '&' && s[j] == '>'))) {
                val second = s[j]
                j++
                if (second == '&' && j < s.length && s[j] == '>') j++
                else if (s[i] == '&' && second == '>' && j < s.length && s[j] == '>') j++
            }
            if ((s[i] == '<' || s[i] == '>') && j < s.length && s[j] == '(' && j == i + 1) {
                // Process substitution `<(...)` / `>(...)`: a
                // word, not an operator + target pair.
                val end = findBalanced(s, j, '(', ')')
                val inner = origS.substring(j + 1, maxOf(j + 1, minOf(end, origS.length)))
                if (inner.isNotBlank()) inners += inner
                hadExp = true; expCount++; hadSubst = true
                rawB.append(s.substring(i, minOf(end + 1, s.length)))
                rawCaseB.append(origS.substring(i, minOf(end + 1, origS.length)))
                return end + 1
            }
            pendingRedir = true
            pendingRedirInput = s[i] == '<'
            return j
        }
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '\\' -> {
                    // W53: backslash-LF unquoted is a line
                    // continuation — the shell deletes BOTH
                    // characters, joining the surrounding
                    // text, so [norm]/[caseNorm] append
                    // nothing. A continuation with nothing
                    // else in the token appends nothing at
                    // all (no phantom empty token where the
                    // shell has no word). Every other escaped
                    // char keeps the prior join.
                    if (i + 1 < s.length && s[i + 1] == '\n') {
                        if (rawB.isNotEmpty() || normB.isNotEmpty() || hadExp) {
                            rawB.append(c); rawB.append(s[i + 1]); rawCaseB.append(origS[i]); rawCaseB.append(origS[i + 1])
                        }
                        i += 2
                    }
                    else if (i + 1 < s.length) { rawB.append(c); rawB.append(s[i + 1]); rawCaseB.append(origS[i]); rawCaseB.append(origS[i + 1]); normB.append(s[i + 1]); caseB.append(origS[i + 1]); i += 2 }
                    else i++
                }
                c == '`' -> {
                    var j = i + 1
                    while (j < s.length && s[j] != '`') { if (s[j] == '\\') j++; j++ }
                    val inner = origS.substring(i + 1, minOf(j, origS.length))
                    if (inner.isNotBlank()) inners += inner
                    hadExp = true; expCount++; hadSubst = true
                    val btEnd = if (j < s.length) j + 1 else s.length
                    rawB.append(s.substring(i, btEnd))
                    rawCaseB.append(origS.substring(i, btEnd))
                    i = btEnd
                }
                // W40: ANSI-C quoting — the segment contributes
                // its DECODED text to the token, so every view
                // downstream sees the word mksh will run. An
                // undecodable segment marks the token [ansiBad];
                // command position then fails closed.
                c == '$' && i + 1 < s.length && s[i + 1] == '\'' -> {
                    val dec = decodeAnsiC(s, i)
                    if (dec != null) {
                        rawB.append(s.substring(i, dec.second))
                        rawCaseB.append(origS.substring(i, dec.second))
                        normB.append(dec.first)
                        // W45: caseNorm decodes the ORIGINAL-case
                        // segment when it spans the same extent, so
                        // case survives ANSI-C quoting too; a span
                        // mismatch keeps the folded decode (the
                        // fail-closed direction for case-sensitive
                        // consumers).
                        val decOrig = decodeAnsiC(origS, i)
                        caseB.append(if (decOrig != null && decOrig.second == dec.second) decOrig.first else dec.first)
                        i = dec.second
                    } else {
                        var j = i + 2
                        while (j < s.length && s[j] != '\'') { if (s[j] == '\\') j++; j++ }
                        val end = if (j < s.length) j + 1 else s.length
                        rawB.append(s.substring(i, end))
                        rawCaseB.append(origS.substring(i, end))
                        ansiBad = true
                        i = end
                    }
                }
                c == '$' -> i = dollar(i)
                c == '\'' || c == '"' -> {
                    rawB.append(c); rawCaseB.append(origS[i])
                    var j = i + 1
                    while (j < s.length && s[j] != c) {
                        when {
                            s[j] == '\\' && j + 1 < s.length -> {
                                rawB.append(s[j]); rawB.append(s[j + 1]); rawCaseB.append(origS[j]); rawCaseB.append(origS[j + 1])
                                // W51: quote-faithful backslash
                                // handling. Pre-W51 the pair
                                // collapsed to the escaped char
                                // in BOTH quote kinds — but in
                                // single quotes the shell keeps
                                // the backslash literally, and
                                // in double quotes it collapses
                                // only before $ ` " \ or a
                                // newline. The collapse mangled
                                // an awk program's escapes
                                // (\151 -> 151) before the awk
                                // decoder ever saw them — the
                                // round-12 hole's other half.
                                // Now [norm]/[caseNorm] carry
                                // exactly the text the quoted
                                // span delivers.
                                when {
                                    c == '\'' -> {
                                        normB.append(s[j]); normB.append(s[j + 1]); caseB.append(origS[j]); caseB.append(origS[j + 1])
                                    }
                                    // W53: inside double quotes a
                                    // backslash-LF pair is a line
                                    // continuation — the shell
                                    // deletes BOTH characters, so
                                    // nothing is appended (pre-W53
                                    // the LF was appended and split
                                    // the joined verb in this view:
                                    // the round-13 counter-example).
                                    s[j + 1] == '\n' -> {
                                    }
                                    s[j + 1] in "\$`\"\\" -> {
                                        normB.append(s[j + 1]); caseB.append(origS[j + 1])
                                    }
                                    else -> {
                                        normB.append(s[j]); normB.append(s[j + 1]); caseB.append(origS[j]); caseB.append(origS[j + 1])
                                    }
                                }
                                j += 2
                            }
                            s[j] == '$' -> j = dollar(j)
                            s[j] == '`' -> {
                                var k = j + 1
                                while (k < s.length && s[k] != '`') { if (s[k] == '\\') k++; k++ }
                                val inner = origS.substring(j + 1, minOf(k, origS.length))
                                if (inner.isNotBlank()) inners += inner
                                hadExp = true; expCount++; hadSubst = true
                                val btEnd = if (k < s.length) k + 1 else s.length
                                rawB.append(s.substring(j, btEnd))
                                rawCaseB.append(origS.substring(j, btEnd))
                                j = btEnd
                            }
                            else -> { rawB.append(s[j]); rawCaseB.append(origS[j]); normB.append(s[j]); caseB.append(origS[j]); j++ }
                        }
                    }
                    if (j < s.length) { rawB.append(s[j]); rawCaseB.append(origS[j]); j++ }
                    i = j
                }
                c == '&' && i + 1 < s.length && s[i + 1] == '>' -> i = redir(i)
                c == '<' || c == '>' -> i = redir(i)
                c == ';' || c == '|' || c == '&' || c == '\n' -> { flushSeg(); i++ }
                c == '(' || c == ')' -> {
                    flushTok()
                    // W25: a bare `)` leaves a marker so a case
                    // arm's body (or a `name()` function's body
                    // introducer) can be re-scanned as its own
                    // command by [verbPositionRefused]. `(` needs
                    // no marker: a subshell/group body is scanned
                    // as the segment's own command already.
                    if (c == ')') seg += ScanTok(")", ")", false, emptyList(), false, expCount = 0, hadSubst = false, parenClose = true)
                    i++
                }
                c.isWhitespace() -> { flushTok(); i++ }
                else -> { rawB.append(c); rawCaseB.append(origS[i]); normB.append(c); caseB.append(origS[i]); i++ }
            }
        }
        flushSeg()
        return segments
    }

    /** The verb-position rule over the aligned scan, W22
     *  grammar-aware form.
     *
     *  GRAMMAR MODEL (as built). Per segment (split on
     *  ; | & — `&>`/`&>>` are redirections, not separators —
     *  and newlines), the COMMAND POSITION is located by
     *  skipping, in any order and recursively:
     *   - assignment tokens (`X=a`),
     *   - redirection targets (marked by [scanSegments]; an
     *     operator may sit before the command word, between
     *     it and its verb slot, or anywhere else — its target
     *     is never a command word, a verb slot, or a
     *     self-target argument),
     *   - grammar/transparent prefix words: the reserved
     *     words if / then / else / elif / while / until / do,
     *     the closing words fi / done / esac / }, the negation
     *     !, the brace {, and the transparent command words
     *     exec / command / time / builtin / xargs (their
     *     literal flags are skipped too; `command -v`/`-V`
     *     is a lookup, not an execution, and ends the
     *     segment's command search).
     *  The token at the corrected position is the command
     *  word; for cmd/am/pm/monkey the verb slot is the first
     *  following token that is neither a literal flag nor a
     *  redirection target. All W17/W19 rules then apply on
     *  the corrected positions, plus the literal form of the
     *  cmd slot rule on those positions (`cmd` + literal
     *  `input` refuses; `cmd` + literal `activity`/`package`
     *  naming the own package refuses; am/pm naming the own
     *  package refuses) — the token-stream views cannot see
     *  these when a redirection sits between `cmd` and its
     *  slot, because they take the target as the slot.
     *
     *  FAIL-CLOSED BOUNDARY (stated rule). A construct in
     *  COMMAND POSITION that this grammar model cannot parse
     *  — a starter whose following words are not a simple
     *  command (for / case / select / function / [[ / ((),
     *  or a transparent prefix whose flag carries an
     *  expansion — refuses ONLY when its segment carries an
     *  input-verb or self-target context (a literal input
     *  verb, a cmd/am/pm/monkey/input word, or the own
     *  package as a non-target token). Redirections alone
     *  are NEVER a refusal: a benign command with any
     *  redirection placement stays allowed, and a dangling
     *  redirection is a shell syntax error (the shell runs
     *  nothing), so it does not refuse either. The refusal
     *  is for an unparseable COMMAND POSITION in a sensitive
     *  context, nothing else.
     *
     *  W25 EXTENSIONS (round-5). The boundary above now has
     *  three structural additions (full statement in the W25
     *  header note on [shellInputRefused]): assembled words
     *  refuse inside unparseable and condition segments;
     *  case-arm bodies after a `)` marker are re-scanned as
     *  their own commands in arm context; and a literal slot
     *  parent with a substitution-assembled tail word refuses
     *  on any segment.
     *
     *  STATED LIMITS. `for` BODIES are reached through their
     *  `do`-separated segments in the ordinary scan where the
     *  shell's separators expose them; `case` bodies are
     *  reached through the W25 arm re-scan. A denied command
     *  hidden inside a case pattern list with no separator
     *  before it is covered by the assembled-word rule, the
     *  sensitive-context starter refusal above and the
     *  token-stream views. (W28: the W25 named residual — a
     *  PURE single substitution in argument position, e.g.
     *  `am start -n $(cat f)` — is CLOSED: any substitution in
     *  a literal slot parent's tail refuses; see the W28
     *  header note on [shellInputRefused].) Prefix words are recognised as
     *  literal tokens only (a quoted or expansion-carried
     *  "if" is a command word, as in the shell). xargs flag
     *  handling covers the common argument-taking flags;
     *  an expansion in an xargs flag is unparseable command
     *  position under the boundary rule. */
    private fun verbPositionRefused(segments: List<ScanSeg>, own: String): Boolean {
        val inputVerbs = setOf(
            "tap", "swipe", "text", "keyevent", "keyevents", "press",
            "roll", "draganddrop", "keycombination", "motionevent",
            "longpress", "scroll"
        )
        val benignVars = setOf(
            "home", "path", "tmpdir", "user", "shell", "lang", "term",
            "pwd", "oldpwd", "ifs"
        )
        val specialVars = setOf("?", "$", "#", "@", "*", "!", "-")
        val assignment = Regex("""^[a-z_][a-z0-9_]*=""")
        // W47: the name tables are the shared GateModel-level
        // vals (see [dispatchedNames]) — one source for every
        // pass, so the resolved-name set cannot drift from the
        // names this pass dispatches on.
        val prefixWords = grammarPrefixWords
        val unparseableStarters = setOf("for", "case", "select", "function", "[[", "((", "coproc")
        val slotParents = slotParentNames
        // Flags of the transparent words that consume the
        // following token as their argument.
        val flagArgWords = prefixFlagArgWords
        fun tokNamesOwn(tok: ScanTok): Boolean {
            if (tok.redirTarget || own.isEmpty()) return false
            val candidates = listOf(
                tok.norm,
                tok.raw.removePrefix("$").trim('{', '}', '"', '\''),
                tok.raw
            )
            return candidates.any { cand ->
                cand == own || cand.startsWith("$own/") || cand.startsWith("$own:")
            }
        }
        // W25 assembled-word predicates (see the W25 header
        // note on [shellInputRefused]). A word is ASSEMBLED when
        // an expansion is joined with literal text or several
        // expansions share the word; it is SUBSTITUTION-ASSEMBLED
        // when a command substitution takes part in that join.
        // Exactly one expansion and no literal text is PURE.
        fun isAssembled(t: ScanTok): Boolean =
            t.hadExpansion && (t.norm.isNotEmpty() || t.expCount > 1)
        fun isSubstAssembled(t: ScanTok): Boolean =
            t.hadSubst && (t.norm.isNotEmpty() || t.expCount > 1)
        fun segRefused(segIn: List<ScanTok>, armContext: Boolean): Boolean {
            val seg = segIn
            if (seg.isEmpty()) return false
            val segNamesOwn = seg.any { tokNamesOwn(it) }
            fun sensitiveContext(): Boolean =
                segNamesOwn || seg.any { tok ->
                    !tok.redirTarget && tok.norm.substringAfterLast('/') in
                        (inputVerbs + slotParents + setOf("input", "activity", "package"))
                }
            // W25: an ARM token list is by construction inside
            // an unparseable construct (a case arm, a function
            // body introducer) even when its segment carries no
            // starter token of its own — a SECOND arm is its own
            // segment (`a) echo hi;; x) <arm>`), so the
            // assembled-word rule applies to it directly.
            if (armContext && seg.any { !it.redirTarget && !it.parenClose && isAssembled(it) }) return true
            // W25: a CONDITION segment (if/while/until/elif …)
            // is a grammar construct whose command this scanner
            // reaches only by unwrapping the starter — an
            // assembled word anywhere in it is unprovable in
            // exactly the way an assembled word inside an
            // unparseable starter's segment is, so it refuses
            // unconditionally (redirection targets excluded:
            // they are file names, never words the shell runs).
            run {
                var k = 0
                while (k < seg.size && (seg[k].redirTarget || seg[k].parenClose ||
                        assignment.containsMatchIn(seg[k].norm))) k++
                if (k < seg.size && !seg[k].hadExpansion &&
                    seg[k].norm.substringAfterLast('/') in setOf("if", "while", "until", "elif") &&
                    seg.any { !it.redirTarget && !it.parenClose && isAssembled(it) }) return true
            }
            // ---- locate the command position ----
            var idx = 0
            var noCommand = false
            var unparseable = false
            while (idx < seg.size) {
                val t = seg[idx]
                if (t.redirTarget) { idx++; continue }
                if (t.parenClose) { idx++; continue }
                if (assignment.containsMatchIn(t.norm)) { idx++; continue }
                val base = t.norm.substringAfterLast('/')
                if (!t.hadExpansion && base in unparseableStarters) { unparseable = true; break }
                if (!t.hadExpansion && base in prefixWords) {
                    idx++
                    if (base in flagArgWords.keys || base == "command") {
                        // Skip this transparent word's literal
                        // flags (and flag arguments).
                        var lookupOnly = false
                        while (idx < seg.size) {
                            val f = seg[idx]
                            if (f.redirTarget) { idx++; continue }
                            if (f.hadExpansion || !f.norm.startsWith("-")) break
                            if (base == "command" && (f.norm == "-v" || f.norm == "-V")) {
                                lookupOnly = true; idx++; break
                            }
                            idx++
                            val flagName = f.norm.substringBefore('=')
                            if (!f.norm.contains('=') && flagName in (flagArgWords[base] ?: emptySet())) {
                                // The flag's argument is the
                                // next non-target token.
                                while (idx < seg.size && seg[idx].redirTarget) idx++
                                if (idx < seg.size) {
                                    if (seg[idx].hadExpansion) unparseable = true
                                    idx++
                                }
                            }
                        }
                        if (lookupOnly) { noCommand = true }
                    }
                    if (noCommand || unparseable) break
                    continue
                }
                break
            }
            if (unparseable) {
                // W25 ASSEMBLED-WORD RULE: inside a construct
                // the grammar model cannot parse, an assembled
                // word (expansion joined with literal text, or
                // several expansions in one word) refuses
                // unconditionally — its expansion-time value
                // cannot be proven not to spell a denied verb
                // or the own package, which is exactly how the
                // round-5 case-arm evasion assembled both.
                // Pure words (one expansion, no literal join)
                // keep the W22 boundary below.
                if (seg.any { !it.redirTarget && !it.parenClose && isAssembled(it) }) return true
                if (sensitiveContext()) return true
                return false
            }
            if (noCommand || idx >= seg.size) return false
            val cw = seg[idx]
            // A leading `!` may attach to the command word
            // itself (`!cmd …` in interactive spelling).
            val cwBase = cw.norm.substringAfterLast('/').removePrefix("!")
            val rest = seg.drop(idx + 1).filter { !it.redirTarget && !it.parenClose }
            // W32 ASSEMBLED COMMAND WORD (round-7,
            // W31 confirmation): an ASSEMBLED word in COMMAND
            // position refuses in EVERY context — plain tail,
            // benign tail, any tail. The pre-W32 rules judged an
            // assembled command word only against its tail
            // (input verb present / own package named /
            // substitution-assembled tail word), so an assembled
            // slot parent or interpreter with an innocuous tail
            // escaped: `a$(echo m) start -n com.other/.Main`,
            // `mon$(echo key) -p com.other 1`, `s$(echo h) -c
            // 'echo hi'` (all probed ALLOWED pre-W32). The
            // command word must be assessable, and an assembled
            // word's expansion-time value is not: it can spell
            // any verb, including a denied one, and the tail
            // cannot clear it. ONE carve-out, the pinned W17
            // floor: a VARIABLE-ONLY path form whose variables
            // are all ordinary environment names and whose
            // literal path survives (`$HOME/bin/tool`) — no
            // substitution takes part, the executed basename is
            // the literal final component whatever the
            // variables hold, so the word IS assessable.
            // A PURE command word (exactly one expansion, no
            // literal join — `$(echo ls) -la`) is NOT assembled
            // and keeps its existing posture, DECISION PINNED:
            // its body is re-checked as a command in its own
            // right by the inners pass, and any tail that would
            // make an unknown verb dangerous (an input verb,
            // the own package) is literal and is judged by the
            // branches below; inside an arm a pure-substitution
            // command word already refuses. Assembled words in
            // ARGUMENT position are untouched by this rule
            // (`echo in$(echo put)` stays allowed).
            if (isAssembled(cw)) {
                // W40 (round-8): the carve-out covers variable
                // DIRECTORY components only — the FINAL
                // component (the program name) must be literal
                // text. Pre-W40 the check was only
                // norm.contains('/'), so `$HOME/bin/$PATH`
                // passed with its program name carried entirely
                // by a variable (the round-8 counter-example:
                // PATH set to a traversal ending in an assembled
                // `input`, run as `$HOME/bin/$PATH tap 1 1`).
                val benignVarPath = !cw.hadSubst && cw.vars.all {
                    it in benignVars || it in specialVars || it.all { ch -> ch.isDigit() }
                } && cw.norm.contains('/') && finalCompLiteral(cw)
                if (!benignVarPath) return true
            }
            // W40: an undecodable ANSI-C segment in command
            // position — the program name is unknown text.
            if (cw.ansiBad) return true
            // Verb slot following cmd / am / pm / monkey, on
            // the corrected position: flags and redirection
            // targets are skipped, in any interleaving.
            if (cwBase in slotParents) {
                var j = idx + 1
                while (j < seg.size &&
                    (seg[j].redirTarget || seg[j].parenClose ||
                        (seg[j].norm.startsWith("-") && !seg[j].hadExpansion))) j++
                if (j < seg.size) {
                    val slot = seg[j]
                    // W19 VERB-SLOT LITERAL RULE (round-3,
                    // W18 confirmation): the W17 branch below only
                    // failed closed when the slot's expansion
                    // normalised to EMPTY. A NON-empty expansion
                    // contributing a character evaded it —
                    // `cmd ${X}ctivity …` (X=a) normalises to
                    // `ctivity`, the slot branch was skipped, and
                    // the shell ran `cmd activity …`. Verb slots
                    // are a closed literal set in practice; an
                    // expansion there is never a legitimate shell
                    // need. So: ANY expansion construct in the raw
                    // slot token refuses, regardless of what the
                    // expansion might produce and regardless of
                    // context (own-naming, sensitive tail, …).
                    // Argument positions are untouched — they keep
                    // the W17 normalisation + ordinary floor.
                    if (slot.hadExpansion) return true
                    if (slot.ansiBad) return true
                    // W22: the literal slot rule on the corrected
                    // position (a redirection between the parent
                    // and its slot hid these from the token
                    // views, which took the target as the slot).
                    val slotBase = slot.norm.substringAfterLast('/')
                    if (cwBase == "cmd") {
                        if (slotBase == "input") return true
                        if ((slotBase == "activity" || slotBase == "package") && segNamesOwn) return true
                    }
                    if ((cwBase == "am" || cwBase == "pm") && segNamesOwn) return true
                } else if (cwBase == "am" || cwBase == "pm") {
                    if (segNamesOwn) return true
                }
            }
            // W25 (c) SUBSTITUTION-ASSEMBLED TAIL after a literal
            // slot parent, on ANY segment (proven reachable by
            // probe outside every construct): the tail word's
            // expansion-time value is arbitrary, so a joined
            // substitution there cannot be proven not to spell
            // the own package — `am start -n "io.agenticcontrol
            // .ap$(printf %s p)/.MainActivity"` escaped every
            // view pre-W25.
            // W28 (b) CLOSURE (round-6, residual
            // rejected): the rule now covers ANY command
            // substitution in the tail — pure or assembled, in
            // or out of arm context. `am start -n $(cat f)` was
            // the W25 named residual: the substitution's output
            // IS the slot value, it is unknown, and unknown in
            // a slot parent's tail fails closed. Parameter
            // expansion is not a substitution (hadSubst is
            // false for $PKG/${PKG}) and is untouched.
            if (cwBase in slotParents && !cw.hadExpansion) {
                if (rest.any { it.hadSubst }) return true
            }
            // W25 (b) ARM CONTEXT: a pure-substitution COMMAND
            // WORD inside a case arm / function body is an
            // unresolvable verb in an unparseable construct —
            // it refuses even though the same word in argument
            // position (`echo $(date)`) stays allowed.
            if (armContext && cw.hadSubst && cw.norm.isEmpty()) return true
            // Command word itself held an expansion.
            if (cw.hadExpansion) {
                // W40 composition: a variable DIRECTORY path
                // does not exempt the program name. When the
                // final component is literal, it is judged by
                // name like any literal command word — a
                // literal `input`/`monkey` final component
                // reached via `$HOME/bin/…` is the denied verb
                // itself, whatever directory the variables
                // supplied. (The slot-parent names are judged
                // by the slot block above, which already runs
                // on cwBase regardless of expansions.)
                if (finalCompLiteral(cw) && cwBase in setOf("input", "monkey")) return true
                // W45 (round-9, point 3): a PURE substitution
                // command word the scanner cannot resolve
                // REFUSES, whatever its tail — the executed
                // word is the substitution's unknowable output,
                // and unknowable in command position fails
                // closed. This replaces the W40 tail-shape rule
                // (refuse only with a -c-shaped or substitution
                // tail) and flips the W40 pin
                // `$(cat /sdcard/c) -la` to refused (named in
                // the W45 lane log). (The resolvable case is
                // unwrapped in [invocationRefused], which scans
                // the payload under the resolved name.)
                if (isPureSubst(cw) && resolvePureSubst(cw) == null) return true
                val allBenign = cw.vars.all {
                    it in benignVars || it in specialVars || it.all { ch -> ch.isDigit() }
                }
                // Provably a benign literal: ordinary environment
                // names only, a literal path survives the
                // removal ($HOME/bin/tool -> /bin/tool), AND
                // (W40) the final component is literal text.
                val provablyBenign = allBenign && cw.norm.contains('/') && finalCompLiteral(cw)
                if (!provablyBenign) {
                    if (rest.any { it.norm.substringAfterLast('/') in inputVerbs }) return true
                    if (segNamesOwn) return true
                    // $X $Y: the verb after the command word is
                    // itself an expansion — nothing is resolvable.
                    if (rest.firstOrNull()?.hadExpansion == true) return true
                    // W28: an assembled COMMAND WORD paired with
                    // a SUBSTITUTION-ASSEMBLED tail word — the
                    // round-6 inner payload's exact shape
                    // (`a$(printf %s m) start -n "io.agentic
                    // control.ap$(printf %s p)/…"`): the verb is
                    // assembled so no slot-parent rule can see
                    // it, and the tail word is assembled so no
                    // view can see the own package either. Two
                    // substitution assemblies in one command,
                    // one of them in verb position, cannot be
                    // proven not to be a denied verb driving at
                    // an assembled target.
                    if (rest.any { isSubstAssembled(it) }) return true
                }
            }
            return false
        }
        for (segment in segments) {
            if (segRefused(segment.toks, armContext = false)) return true
            // W25 (b) CASE-ARM PARSING: re-scan each body after
            // a `)` marker as its own command, in arm context.
            // The header part (before the first marker) was
            // already judged as part of the whole segment above;
            // arm bodies get the corrected verb positions the
            // whole-segment scan cannot give them (the round-5
            // arm's verb sat mid-segment, behind the `case`
            // starter, where no position rule could reach it).
            if (segment.toks.any { it.parenClose }) {
                var arm = mutableListOf<ScanTok>()
                var inArm = false
                fun flushArm(): Boolean {
                    val r = inArm && segRefused(arm, armContext = true)
                    arm = mutableListOf()
                    return r
                }
                for (t in segment.toks) {
                    if (t.parenClose) {
                        if (flushArm()) return true
                        inArm = true
                    } else if (inArm) arm += t
                }
                if (flushArm()) return true
            }
        }
        return false
    }

    // ---- W28 (a): second-shell payload re-parse ----

    /** Scans every segment (and every case-arm body inside it)
     *  for a payload invocation and judges the payload by the
     *  full filter. See the W28 header note on
     *  [shellInputRefused] for the rule and its stated limits. */
    private fun payloadInvocationRefused(
        segments: List<ScanSeg>, own: String, ownPackage: String, depth: Int
    ): Boolean {
        for (segment in segments) {
            if (invocationRefused(segment.toks, own, ownPackage, depth)) return true
            if (segment.toks.any { it.parenClose }) {
                var arm = mutableListOf<ScanTok>()
                var inArm = false
                fun flushArm(): Boolean {
                    val r = inArm && invocationRefused(arm, own, ownPackage, depth)
                    arm = mutableListOf()
                    return r
                }
                for (t in segment.toks) {
                    if (t.parenClose) {
                        if (flushArm()) return true
                        inArm = true
                    } else if (inArm) arm += t
                }
                if (flushArm()) return true
            }
        }
        return false
    }

    /** Judges ONE command invocation (a token list whose first
     *  real word is the invocation's command position, after
     *  grammar-prefix unwrapping) for a payload it hands to a
     *  second shell. Only the command position is an invocation:
     *  the same words in argument position (`echo sh -c '…'`)
     *  are text, not a re-parse. */
    private fun invocationRefused(
        toksIn: List<ScanTok>, own: String, ownPackage: String, depth: Int,
        wrapped: Boolean = false
    ): Boolean {
        // W32: an INPUT redirection feeding this invocation —
        // for an interpreter with no -c payload it is the
        // script source (see the shells branch below).
        val inputRedir = toksIn.any { it.redirTarget && it.redirInput }
        val toks = toksIn.filter { !it.redirTarget && !it.parenClose }.toMutableList()
        if (toks.isEmpty()) return false
        val assignment = Regex("""^[a-z_][a-z0-9_]*=""")
        // W47: shared GateModel-level name tables (see
        // [dispatchedNames]) — one source for every pass.
        val prefixWords = grammarPrefixWords
        val flagArgWords = prefixFlagArgWords
        val shells = shellNames
        // W32 (point 3): true once a command-running wrapper or
        // transparent prefix has been consumed on the way to the
        // command word. Inside a wrapper chain, ANY expansion in
        // a position the unwrapping must step over — a flag, a
        // flag argument, an env assignment value, a duration, an
        // applet name, or the nested command word itself —
        // refuses: an unquoted expansion word-splits before the
        // wrapper ever runs, so it can shift which word ends up
        // as the command, and a quoted one still hides a value
        // this filter cannot read. Either way the final command
        // cannot be determined, and unknown fails closed — the
        // slot-parent closure's principle, one level up. Literal
        // chains are untouched.
        var chain = wrapped
        val chainPrefixes = chainPrefixWords
        // Wrappers that run the following tokens as a command:
        // their literal flags (and flag arguments) are skipped
        // to reach the nested command word.
        val wrapperFlagArgs = wrapperFlagArgWords
        // ---- locate the command position (mirrors segRefused) ----
        var idx = 0
        while (idx < toks.size) {
            val t = toks[idx]
            if (assignment.containsMatchIn(t.norm)) { idx++; continue }
            // W47 (round-10, point 1): the RESOLVED-NAME RULE
            // applies HERE, in the locator, not only in the
            // unwrap loop below: the grammar prefixes (xargs,
            // exec, command, time, builtin) are dispatched by
            // THIS loop, so a variable-directory command word
            // naming one of them must be resolved before the
            // locator decides it is not a prefix and stops.
            // Pre-W47 the rule lived only in the unwrap loop
            // and [dispatchedNames] omitted the prefix names
            // entirely, so `$HOME/bin/xargs sh -c '…'` stopped
            // the locator at the expansion token, the unwrap
            // loop returned on hadExpansion, and the nested
            // payload was never scanned (the round-10
            // counter-example; exec/command/time/builtin had
            // the same hole, probed). Resolution replaces the
            // token with its literal resolved form and the
            // locator re-reads it: a prefix name is consumed as
            // a prefix, any other dispatched name falls through
            // to the unwrap/dispatch below.
            if (t.hadExpansion && finalCompLiteral(t)) {
                val resolvedBase = t.norm.substringAfterLast('/').removePrefix("!")
                if (resolvedBase in dispatchedNames) {
                    toks[idx] = ScanTok(t.norm, t.norm, false, emptyList(),
                        caseNorm = t.caseNorm, caseRaw = t.caseRaw)
                    continue
                }
            }
            val base = t.norm.substringAfterLast('/')
            if (!t.hadExpansion && base in prefixWords) {
                idx++
                if (base in chainPrefixes) chain = true
                if (base in flagArgWords.keys || base == "command") {
                    var lookupOnly = false
                    while (idx < toks.size) {
                        val f = toks[idx]
                        if (f.hadExpansion || !f.norm.startsWith("-")) break
                        if (base == "command" && (f.norm == "-v" || f.norm == "-V")) {
                            lookupOnly = true; idx++; break
                        }
                        idx++
                        val flagName = f.norm.substringBefore('=')
                        if (!f.norm.contains('=') && flagName in (flagArgWords[base] ?: emptySet())) {
                            if (idx < toks.size) idx++
                        }
                    }
                    if (lookupOnly) return false
                }
                continue
            }
            break
        }
        if (idx >= toks.size) return false
        // W45 (round-9, point 1) / W47 (round-10, point 1):
        // the resolved-name set is the GateModel-level
        // [dispatchedNames], DERIVED from every dispatch table
        // (see its declaration) — the locator above has already
        // resolved a dispatched name at the command position,
        // and the unwrap loop below re-checks after each
        // wrapper it consumes.
        // ---- unwrap command-running wrappers ----
        var guard = 0
        while (guard++ < 8) {
            val cwTok = toks[idx]
            if (cwTok.ansiBad) return true
            // W40 (round-8 residual A): a PURE substitution
            // command word is RESOLVED when its body is a
            // simple literal-producing form (echo/printf of
            // literals — see [resolvePureSubst]): the resolved
            // word takes the command position and the full
            // invocation rules apply to it, including the -c
            // payload recursion — pre-W40 this branch returned
            // on hadExpansion before the shells branch, so
            // `$(echo sh) -c '…'` never had its payload scanned
            // at all. W45 (round-9, point 3): when it cannot
            // be resolved it now REFUSES outright (see the
            // branch) — the W40 tail-shape distinction is
            // retired.
            if (cwTok.hadExpansion && isPureSubst(cwTok)) {
                val resolved = resolvePureSubst(cwTok)
                if (resolved != null) {
                    toks[idx] = ScanTok(resolved, resolved, false, emptyList(), caseNorm = resolved)
                    continue
                }
                // W45 (round-9, point 3): an UNRESOLVABLE pure
                // substitution in command position REFUSES,
                // whatever its tail — the executed word is the
                // substitution's output (file content, another
                // program's stdout), which is unknowable, and
                // unknowable in command position fails closed.
                // This flips the W40 pin `$(cat /sdcard/c) -la`
                // from allowed to refused (named in the W45
                // lane log as this rule's cost). Resolvable
                // producers (echo/printf of literals) keep the
                // resolution path above.
                return true
            }
            // W45 (round-9, point 1) RESOLVED-NAME RULE (W47:
            // the primary site is now the locator above, which
            // also covers the grammar-prefix names; this site
            // remains for a command word reached after wrapper
            // consumption in a not-yet-chained position): a
            // command word carried by variable DIRECTORY
            // components whose final component is LITERAL text
            // ([finalCompLiteral]) names a known program —
            // when that name is one this pass dispatches on
            // (an interpreter, a multicall binary, a wrapper,
            // awk/eval/find/su), the resolved name takes its
            // rules in full: the token is replaced by its
            // literal resolved form and the dispatch below
            // applies, payload extraction and recursion
            // included. Pre-W45 this branch returned on
            // hadExpansion before the shells branch, so
            // `$HOME/bin/sh -c '${i}put tap 1 1'` never had
            // its payload scanned. A literal final component
            // naming nothing dispatched keeps the carve-out's
            // benign treatment (the return below). Inside a
            // wrapper chain the W32 posture stands: the
            // expansion there refuses via [chain].
            if (cwTok.hadExpansion && !chain && finalCompLiteral(cwTok)) {
                val resolvedBase = cwTok.norm.substringAfterLast('/').removePrefix("!")
                if (resolvedBase in dispatchedNames) {
                    toks[idx] = ScanTok(cwTok.norm, cwTok.norm, false, emptyList(),
                        caseNorm = cwTok.caseNorm, caseRaw = cwTok.caseRaw)
                    continue
                }
            }
            // W32 (point 3): an expansion where the nested
            // command word should be, after a wrapper was
            // consumed, refuses — the chain cannot be unwrapped
            // to a determinable command. With no wrapper
            // consumed it keeps the prior posture (the verb-
            // position rules judge the word itself).
            if (cwTok.hadExpansion) return chain
            val cwBase = cwTok.norm.substringAfterLast('/').removePrefix("!")
            when {
                cwBase in multicallNames -> {
                    // The applet name is the nested command word.
                    // W32: toybox is stock Android's multicall
                    // binary (busybox is the third-party twin);
                    // both dispatch identically here. An expansion
                    // applet name is a wrapper-position expansion:
                    // it determines what runs and cannot be read.
                    if (idx + 1 >= toks.size) return false
                    if (toks[idx + 1].hadExpansion) return true
                    chain = true
                    idx++
                }
                cwBase == "su" -> {
                    // `su -c <payload>`: the payload is a shell
                    // command string directly, no interpreter
                    // token in between.
                    // W32 (point 4): the TRAILING command is a
                    // payload too. Semantics, as far as this
                    // environment allows verification: stock
                    // Android ships no su at all (it exists only
                    // via a root solution — Magisk / KernelSU /
                    // SuperSU — whose grammar is
                    // `su [flags] [user [command...]]`), and the
                    // general su contract (util-linux / shadow
                    // man pages) is that arguments after the user
                    // are passed to the shell, which runs them as
                    // a command. No Android su binary exists in
                    // this build environment to test against, so
                    // the fail-closed reading is implemented:
                    // tokens after the user operand (and flags)
                    // are joined and recursed exactly like a -c
                    // payload, and ambiguous shapes — an expansion
                    // where a flag, the user, or the command start
                    // should be — refuse, since which token is the
                    // user and which the command cannot be told.
                    val rest = toks.drop(idx + 1)
                    val suArgFlags = setOf("-s", "--shell", "-g", "-G", "--group", "--supp-group")
                    var userSeen = false
                    var afterDashDash = false
                    val trailing = mutableListOf<ScanTok>()
                    var k = 0
                    while (k < rest.size) {
                        val t = rest[k]
                        if (trailing.isNotEmpty()) { trailing += t; k++; continue }
                        if (!afterDashDash && t.norm == "--") { afterDashDash = true; k++; continue }
                        if (!afterDashDash && !t.hadExpansion && t.norm == "-c") {
                            val p = rest.getOrNull(k + 1) ?: return false
                            return payloadTokenRefused(p, ownPackage, depth)
                        }
                        if (!afterDashDash && !t.hadExpansion && t.norm.startsWith("--command=")) {
                            // W45: payload text keeps its case.
                            return recursePayload(t.caseNorm.substringAfter('='), ownPackage, depth)
                        }
                        if (t.hadExpansion) return true
                        if (!afterDashDash && !userSeen && t.norm.startsWith("-") && t.norm.length >= 1 && t.norm != "-c") {
                            // A literal su flag; the argument-
                            // taking ones consume the next token.
                            val flagName = t.norm.substringBefore('=')
                            k++
                            if (!t.norm.contains('=') && flagName in suArgFlags) {
                                if (k < rest.size && rest[k].hadExpansion) return true
                                if (k < rest.size) k++
                            }
                            continue
                        }
                        if (!userSeen) { userSeen = true; k++; continue }
                        trailing += t; k++
                    }
                    if (trailing.isEmpty()) {
                        // No command: an interactive su shell —
                        // unless its stdin is redirected, in which
                        // case the redirect target IS the script
                        // and is unscanned (W32 point 2 principle).
                        return inputRedir
                    }
                    val parts = mutableListOf<String>()
                    for (t in trailing) {
                        val part = extractPayloadLiteral(t) ?: return true
                        parts += part
                    }
                    return recursePayload(parts.joinToString(" "), ownPackage, depth)
                }
                cwBase == "nohup" -> {
                    chain = true
                    if (idx + 1 >= toks.size) return false
                    idx++
                }
                cwBase in wrapperFlagArgs.keys -> {
                    chain = true
                    var j = idx + 1
                    while (j < toks.size) {
                        val t = toks[j]
                        // W32 (point 3): any expansion token the
                        // unwrapping must step over refuses —
                        // env assignments included (an unquoted
                        // value word-splits and its later words
                        // become env's command candidate).
                        if (t.hadExpansion) return true
                        if (cwBase == "env" && !t.norm.startsWith("-") &&
                            assignment.containsMatchIn(t.norm)) { j++; continue }
                        if (t.norm.startsWith("-")) {
                            val flagName = t.norm.substringBefore('=')
                            j++
                            if (!t.norm.contains('=') &&
                                flagName in (wrapperFlagArgs[cwBase] ?: emptySet())) {
                                if (j < toks.size && toks[j].hadExpansion) return true
                                if (j < toks.size) j++
                            }
                            continue
                        }
                        break
                    }
                    // timeout's first non-flag token is its
                    // DURATION, not the nested command — an
                    // expansion there word-splits and shifts the
                    // command position, so it refuses too.
                    if (cwBase == "timeout" && j < toks.size) {
                        if (toks[j].hadExpansion) return true
                        j++
                    }
                    if (j >= toks.size) return false
                    idx = j
                }
                else -> break
            }
        }
        if (idx >= toks.size) return false
        val cw = toks[idx]
        if (cw.ansiBad) return true
        if (cw.hadExpansion) return chain
        val cwBase = cw.norm.substringAfterLast('/').removePrefix("!")
        val rest = toks.drop(idx + 1)
        return when {
            cwBase in shells -> {
                // The payload is the argument of -c (alone or in
                // a combined flag group), extracted and scanned.
                // W32 (point 2, coordinator decision): a script-
                // FILE operand REFUSES — `sh /sdcard/x` executes
                // content that is not in the command string and
                // cannot be scanned; an unscannable file is an
                // unknown payload, and unknown fails closed.
                // Inline -c payloads remain available and are
                // scanned, so no legitimate scanned use is lost.
                // The same closure covers the stdin forms of the
                // same unknown payload: `-s` / a bare `-` (script
                // read from stdin) and, when there is no -c
                // payload, an input redirection feeding the
                // interpreter. An expansion token before the -c
                // flag is resolved also refuses: whether it is a
                // flag, the payload, or the script operand cannot
                // be determined. `-o` consumes its option-name
                // argument, which is neither flag nor operand.
                var k = 0
                var result = false
                var sawDashDash = false
                while (k < rest.size) {
                    val t = rest[k]
                    if (t.hadExpansion) return true
                    val n = t.norm
                    if (!sawDashDash && n.matches(Regex("-[a-z]*c[a-z]*"))) {
                        val p = rest.getOrNull(k + 1)
                        if (p != null) result = payloadTokenRefused(p, ownPackage, depth)
                        break
                    }
                    if (!sawDashDash && n == "--") { sawDashDash = true; k++; continue }
                    if (!sawDashDash && n.startsWith("-")) {
                        if (n == "-" || (n.matches(Regex("-[a-z]+")) && n.contains('s'))) return true
                        k++
                        if (n.matches(Regex("-[a-z]*o"))) {
                            if (k < rest.size && rest[k].hadExpansion) return true
                            if (k < rest.size) k++
                        }
                        continue
                    }
                    // First non-flag token: a script-file operand.
                    return true
                }
                // No -c payload and no operand: the interpreter
                // reads its script from stdin when one is fed to
                // it — an input redirection is exactly that.
                if (k >= rest.size && inputRedir) true else result
            }
            cwBase == "awk" -> {
                // W32 (point 2 enumeration): toybox awk is stock
                // on Android and `-f <file>` runs a program FILE
                // whose text is not in the command string — the
                // same unscanned-payload shape as a shell script
                // file, and awk's system() can run shell commands
                // from it.
                // W40 (round-8 residual B): the W32 layer could
                // not tell `-f` from `-F` because the command
                // string is case-folded before scanning. The
                // scanner now carries each token's original-case
                // text ([ScanTok.caseNorm]), and awk flag
                // handling is CASE-SENSITIVE: a flag walker
                // reads the flag letters in order — `f` is the
                // script-file flag and REFUSES like any
                // interpreter file operand, `F` consumes its
                // separator (attached or as the next token) and
                // stays allowed, `v` consumes its assignment
                // the same way. W45: extraction preserves case
                // ([ScanTok.caseRaw]; substitution bodies are
                // recorded from the original-case string), so
                // the walker now runs at every depth — the W40
                // depth>0 folded posture is retired and
                // `sh -c 'awk -f prog'` refuses like the top
                // level (round-9 residual (i) closed).
                // W40 (b): an INLINE awk program is payload text
                // for its embedded command strings — a system()
                // call's string argument and any string literal
                // in pipe position (`"cmd" | getline`,
                // `print … | "cmd"`) are extracted and run
                // through the full filter; a system() whose
                // argument is not a readable string literal
                // refuses (unextractable embedded command).
                var refused = false
                var programTok: ScanTok? = null
                var programText: String? = null
                var k = 0
                while (k < rest.size && !refused && programTok == null && programText == null) {
                    val t = rest[k]
                    // W45: payload extraction now preserves case
                    // end-to-end ([ScanTok.caseRaw]), so the
                    // case-sensitive walker runs at EVERY depth
                    // — the W40 depth>0 folded posture (plain
                    // -f allowed in a payload) is retired.
                    val flagText = t.caseNorm
                    when {
                        !t.hadExpansion && flagText.startsWith("--") -> {
                            when {
                                flagText.startsWith("--file") -> refused = true
                                flagText == "--source" ->
                                    programTok = rest.getOrNull(k + 1).also { k++ }
                                flagText.startsWith("--source=") ->
                                    programText = t.caseNorm.substringAfter('=')
                                else -> {}
                            }
                            k++
                        }
                        !t.hadExpansion && flagText.startsWith("-") && flagText.length > 1 -> {
                            var j = 1
                            var stopWalk = false
                            var consumeNext = false
                            while (j < flagText.length && !stopWalk) {
                                when (flagText[j]) {
                                    'f' -> { refused = true; stopWalk = true }
                                    'F', 'v' -> {
                                        if (j == flagText.length - 1) consumeNext = true
                                        stopWalk = true
                                    }
                                    else -> j++
                                }
                            }
                            if (consumeNext) k++
                            k++
                        }
                        else -> { programTok = t; k++ }
                    }
                }
                if (!refused) {
                    val text = programText ?: programTok?.let {
                        extractPayloadLiteral(it) ?: it.norm
                    }
                    if (text != null && awkProgramTextRefused(text, ownPackage, depth)) refused = true
                }
                refused
            }
            cwBase == "eval" -> {
                // eval joins its arguments with spaces and hands
                // the result to THIS shell as a command line. An
                // argument that cannot be extracted verbatim
                // makes the joined payload unscannable: refuse.
                if (rest.isEmpty()) false
                else {
                    val parts = mutableListOf<String>()
                    var unscannable = false
                    for (t in rest) {
                        val part = extractPayloadLiteral(t)
                        if (part == null) { unscannable = true; break }
                        parts += part
                    }
                    unscannable || recursePayload(parts.joinToString(" "), ownPackage, depth)
                }
            }
            cwBase == "find" -> {
                // -exec / -execdir run the tokens up to `;`/`+`
                // as a nested command invocation.
                var refused = false
                var k = 0
                while (k < rest.size && !refused) {
                    val t = rest[k]
                    if (!t.hadExpansion && (t.norm == "-exec" || t.norm == "-execdir")) {
                        val sub = mutableListOf<ScanTok>()
                        var m = k + 1
                        while (m < rest.size &&
                            (rest[m].hadExpansion || (rest[m].norm != ";" && rest[m].norm != "+"))) {
                            sub += rest[m]; m++
                        }
                        if (sub.isNotEmpty() && invocationRefused(sub, own, ownPackage, depth, wrapped = true)) refused = true
                        k = m
                    }
                    k++
                }
                refused
            }
            else -> false
        }
    }

    /** W45: joins awk's adjacent string literals: in awk,
     *  two string literals separated only by whitespace are
     *  ONE string (concatenation), so `"in" "put tap 1 1"`
     *  is the command `input tap 1 1` to system(). The join
     *  repeats until stable (three or more literals). Raw
     *  literal contents are concatenated inside one literal —
     *  escape pairs are self-contained per literal, so the
     *  joined literal unescapes to exactly the value awk
     *  builds. */
    private fun joinAwkAdjacentLiterals(text: String): String {
        val pat = Regex(""""((?:\\.|[^"\\])*)"\s+"((?:\\.|[^"\\])*)"""")
        var cur = text
        while (true) {
            val next = pat.replace(cur) { m ->
                "\"" + m.groupValues[1] + m.groupValues[2] + "\""
            }
            if (next == cur) return cur
            cur = next
        }
    }

    /** W40: judges the text of an INLINE awk program for the
     *  shell commands embedded in it: the string argument of
     *  every system() call, and every string literal in pipe
     *  position (before or after a `|` that is not `||`).
     *  Each extracted command string runs through the full
     *  filter via [recursePayload]. A system() call whose
     *  argument is not a readable string literal refuses —
     *  the embedded command is unextractable. W45: adjacent
     *  string literals are joined first ([joinAwkAdjacentLiterals])
     *  so a concatenated command string is judged whole, in
     *  system() and pipe positions alike, and EVERY system()
     *  call is checked, not only the first. W47 (round-10,
     *  residual R3): a system() argument is now PARSED, not
     *  prefix-matched — after joining it must be ONE pure
     *  string literal immediately followed by `)`. The W45
     *  count check was satisfied by a literal prefix, so
     *  `system("in" x)` and `system("in" substr("…",1))`
     *  passed with their variable/function suffix never
     *  judged; any argument whose full text the scanner
     *  cannot read (variable concatenation, function calls,
     *  variable references, parenthesised expressions)
     *  refuses as unextractable. Pure-literal arguments keep
     *  the exact prior treatment. W49 (round-11): the same
     *  purity rule now runs at EVERY awk command sink, not
     *  only system() and compound literals —
     *  [awkCommandSinkRefused] tokenises the program and,
     *  at every single `|` and coprocess `|&`, requires the
     *  command operand (the expression after a print pipe,
     *  the expression before a getline pipe) to be one pure
     *  string literal at the sink; anything else refuses as
     *  unextractable. File redirection (`>`, `>>`, `<`) is
     *  not a command sink and is untouched. */
    private fun awkProgramTextRefused(textIn: String, ownPackage: String, depth: Int): Boolean {
        // W53: a backslash-LF pair anywhere in the program
        // text is deleted before scanning. Inside a string
        // literal this matches [unescapeAwkString]'s own
        // rule (the executed command is the joined text —
        // see the W53 header note); in program text proper
        // it matches the gawk-style source continuation, and
        // the scans below are comment-unaware in the
        // fail-closed direction, so a continuation pulled
        // into a comment line cannot hide a system() call
        // from them.
        val text = joinAwkAdjacentLiterals(textIn.replace("\\\n", ""))
        for (m in Regex("""system\s*\(""").findAll(text)) {
            var i = m.range.last + 1
            while (i < text.length && text[i].isWhitespace()) i++
            if (i >= text.length || text[i] != '"') return true
            val sb = StringBuilder()
            i++
            var closed = false
            while (i < text.length) {
                when {
                    text[i] == '\\' && i + 1 < text.length -> {
                        sb.append(text[i]); sb.append(text[i + 1]); i += 2
                    }
                    text[i] == '"' -> { closed = true; i++; break }
                    else -> { sb.append(text[i]); i++ }
                }
            }
            if (!closed) return true
            var j = i
            while (j < text.length && text[j].isWhitespace()) j++
            if (j >= text.length || text[j] != ')') return true
            // W51: an undecodable literal is unextractable.
            val decSys = unescapeAwkString(sb.toString()) ?: return true
            if (recursePayload(decSys, ownPackage, depth)) return true
        }
        // W47: a string literal that is only PART of a pipe
        // command expression is an unextractable pipe
        // argument — refuse (see the helper).
        if (awkCompoundPipeLiteralRefused(text)) return true
        // W49: purity at EVERY awk command sink — a pipe
        // command with NO literal at the sink (variable,
        // field, function call) is unextractable and
        // refuses (see the helper).
        if (awkCommandSinkRefused(text, ownPackage, depth)) return true
        // String literals in pipe position.
        var i = 0
        while (i < text.length) {
            if (text[i] != '"') { i++; continue }
            val start = i
            val sb = StringBuilder()
            i++
            var closed = false
            while (i < text.length) {
                when {
                    text[i] == '\\' && i + 1 < text.length -> { sb.append(text[i]); sb.append(text[i + 1]); i += 2 }
                    text[i] == '"' -> { closed = true; i++; break }
                    else -> { sb.append(text[i]); i++ }
                }
            }
            if (!closed) break
            val after = text.substring(i).trimStart()
            val before = text.substring(0, start).trimEnd()
            val pipeAfter = after.startsWith("|") && !after.startsWith("||")
            val pipeBefore = before.endsWith("|") && !before.endsWith("||")
            if (pipeAfter || pipeBefore) {
                // W51: an undecodable literal is unextractable.
                val decPipe = unescapeAwkString(sb.toString()) ?: return true
                if (recursePayload(decPipe, ownPackage, depth)) return true
            }
        }
        return false
    }

    /** W47: true when a string literal in an awk program is
     *  part of a LARGER expression (concatenated with a
     *  variable, a field, a function call — anything whose
     *  value the scanner cannot read) AND that expression is
     *  a pipe command: either it stands before a single `|`
     *  in its own statement (`"in" x | getline`) or it
     *  follows one (`print x | "in" y`, `print x | y "in"`).
     *  The pipe command's full text is then unextractable and
     *  refuses, exactly like a non-literal system() argument.
     *  A compound literal that is a print/printf ARGUMENT is
     *  exempt from the forward check: in `print "a" $1 |
     *  "sort"` the pipe command is the pure literal after the
     *  pipe, and `"a"` is data. Pure literals are untouched —
     *  the pipe scan in [awkProgramTextRefused] judges them. */
    private fun awkCompoundPipeLiteralRefused(text: String): Boolean {
        var i = 0
        while (i < text.length) {
            if (text[i] != '"') { i++; continue }
            val start = i
            i++
            var closed = false
            while (i < text.length) {
                when {
                    text[i] == '\\' && i + 1 < text.length -> i += 2
                    text[i] == '"' -> { closed = true; i++; break }
                    else -> i++
                }
            }
            if (!closed) break
            // Compound-after: the next non-whitespace char
            // continues the expression past this literal.
            var j = i
            while (j < text.length && text[j].isWhitespace()) j++
            val afterChar = if (j < text.length) text[j] else null
            val compoundAfter = afterChar != null &&
                (afterChar.isLetterOrDigit() || afterChar == '_' ||
                    afterChar == '$' || afterChar == '(')
            // Compound-before: the previous non-whitespace
            // char continues an expression into this literal.
            var b = start - 1
            while (b >= 0 && text[b].isWhitespace()) b--
            val beforeChar = if (b >= 0) text[b] else null
            val compoundBefore = beforeChar != null &&
                (beforeChar.isLetterOrDigit() || beforeChar == '_' ||
                    beforeChar == '$' || beforeChar == ')')
            if (!compoundAfter && !compoundBefore) continue
            if (compoundAfter) {
                // Forward: a single `|` before the statement
                // ends makes this expression the pipe command
                // — unless the literal is a print argument.
                var k = j
                var parenDepth = 0
                var pipe = false
                while (k < text.length) {
                    val c = text[k]
                    when {
                        c == '(' -> parenDepth++
                        c == ')' -> { if (parenDepth == 0) break; parenDepth-- }
                        c == ';' || c == '{' || c == '}' -> break
                        c == '|' -> {
                            if (k + 1 < text.length && text[k + 1] == '|') { k += 2; continue }
                            pipe = true; break
                        }
                        else -> k++
                    }
                    if (c == '(' || c == ')') k++
                }
                if (pipe && !awkLiteralUnderPrint(text, start)) return true
            }
            // Backward: scan over this expression's own
            // continuation tokens only; a single `|` reached
            // that way governs this expression as the pipe
            // command on its right.
            var k = b
            var pipe = false
            while (k >= 0) {
                val c = text[k]
                when {
                    c == '|' -> {
                        if (k - 1 >= 0 && text[k - 1] == '|') { k -= 2; continue }
                        pipe = true; break
                    }
                    c.isLetterOrDigit() || c == '_' || c == '$' || c == ')' ||
                        c == '"' || c.isWhitespace() -> k--
                    else -> break
                }
            }
            if (pipe) return true
        }
        return false
    }

    // W49: token kinds for the awk command-sink scan.
    private val AWK_TOK_STR = 0
    private val AWK_TOK_WORD = 1
    private val AWK_TOK_NUM = 2
    private val AWK_TOK_REGEX = 3
    private val AWK_TOK_FIELD = 4
    private val AWK_TOK_SYM = 5

    /** One token of an awk program for the sink scan:
     *  [sym] carries a word's text or an operator symbol;
     *  [strVal] carries a string literal's raw (still
     *  escaped) contents. Regex literals, numbers and field
     *  references carry neither — only their kind matters:
     *  none of them is a pure string literal. */
    private class AwkTok(val kind: Int, val sym: String, val strVal: String?)

    /** Words after which a `/` opens a regex literal rather
     *  than dividing: statement keywords and functions whose
     *  argument position takes a pattern. Any other word is
     *  a value, so a following `/` is division. */
    private val awkRegexLeadWords = setOf(
        "if", "else", "while", "for", "in", "do", "return",
        "print", "printf", "getline", "system", "next",
        "nextfile", "exit", "delete", "function", "switch",
        "case", "default", "BEGIN", "END", "begin", "end")

    private val awkTwoCharSyms = setOf(
        "|&", "||", "&&", ">>", ">=", "<=", "==", "!=", "!~",
        "++", "--", "+=", "-=", "*=", "/=", "%=", "^=", "**")

    /** W49: tokenises an awk program for the sink scan.
     *  String literals, regex literals and `#` comments are
     *  consumed whole, so a `|` inside data (a pattern
     *  alternation, a split separator, a printed string) is
     *  never mistaken for a pipe. A `/` is read as a regex
     *  opener only where awk's grammar allows a pattern
     *  (after an operator, a delimiter, or a keyword from
     *  [awkRegexLeadWords]); after a value it is division. */
    private fun tokenizeAwk(text: String): List<AwkTok> {
        val toks = ArrayList<AwkTok>()
        var i = 0
        fun regexAllowed(): Boolean {
            val p = toks.lastOrNull() ?: return true
            return when (p.kind) {
                AWK_TOK_WORD -> p.sym in awkRegexLeadWords
                AWK_TOK_SYM -> p.sym !in setOf(")", "]", "++", "--")
                else -> false
            }
        }
        while (i < text.length) {
            val c = text[i]
            when {
                c.isWhitespace() -> i++
                c == '#' -> {
                    while (i < text.length && text[i] != '\n') i++
                }
                c == '"' -> {
                    val sb = StringBuilder()
                    i++
                    var closed = false
                    while (i < text.length && !closed) {
                        when {
                            text[i] == '\\' && i + 1 < text.length -> {
                                sb.append(text[i]); sb.append(text[i + 1]); i += 2
                            }
                            text[i] == '"' -> { closed = true; i++ }
                            else -> { sb.append(text[i]); i++ }
                        }
                    }
                    toks.add(AwkTok(AWK_TOK_STR, "", sb.toString()))
                }
                c == '/' && regexAllowed() -> {
                    i++
                    var inClass = false
                    var done = false
                    while (i < text.length && !done) {
                        val d = text[i]
                        when {
                            d == '\\' && i + 1 < text.length -> i += 2
                            d == '[' -> { inClass = true; i++ }
                            d == ']' -> { inClass = false; i++ }
                            d == '/' && !inClass -> { done = true; i++ }
                            d == '\n' -> done = true
                            else -> i++
                        }
                    }
                    toks.add(AwkTok(AWK_TOK_REGEX, "", null))
                }
                c == '$' -> {
                    i++
                    while (i < text.length &&
                        (text[i].isLetterOrDigit() || text[i] == '_')) i++
                    toks.add(AwkTok(AWK_TOK_FIELD, "", null))
                }
                c.isLetter() || c == '_' -> {
                    val s = i
                    while (i < text.length &&
                        (text[i].isLetterOrDigit() || text[i] == '_')) i++
                    toks.add(AwkTok(AWK_TOK_WORD, text.substring(s, i), null))
                }
                c.isDigit() -> {
                    while (i < text.length &&
                        (text[i].isLetterOrDigit() || text[i] == '.' ||
                            text[i] == '_')) i++
                    toks.add(AwkTok(AWK_TOK_NUM, "", null))
                }
                else -> {
                    val two = if (i + 1 < text.length)
                        text.substring(i, i + 2) else ""
                    if (two in awkTwoCharSyms) {
                        toks.add(AwkTok(AWK_TOK_SYM, two, null)); i += 2
                    } else {
                        toks.add(AwkTok(AWK_TOK_SYM, c.toString(), null)); i++
                    }
                }
            }
        }
        return toks
    }

    /** W49: purity at EVERY awk command sink. In awk a
     *  command executes at exactly the pipe forms: the
     *  expression after a print/printf pipe (`print … |
     *  expr`, coprocess `print … |& expr`) and the
     *  expression before a getline pipe (`expr | getline`,
     *  `expr |& getline`) — system() is parsed separately
     *  in [awkProgramTextRefused] under the same rule. At
     *  each such sink the command operand must be ONE pure
     *  string literal at the sink itself (the text arrives
     *  after [joinAwkAdjacentLiterals], so a joined literal
     *  is one token): a variable, field, number, regex,
     *  function call, parenthesised expression, or a
     *  literal concatenated with anything non-literal (or
     *  with an unjoined literal) REFUSES as unextractable —
     *  the filter does no data-flow tracking, so what
     *  cannot be read at the point of execution is refused.
     *  A pure literal is extracted and shell-filtered
     *  exactly like the W40 pipe scan. Redirection to a
     *  file (`>`, `>>`, `<`) never reaches this scan: those
     *  operators are not pipes, and their operands are
     *  filenames, not commands. */
    private fun awkCommandSinkRefused(
        text: String, ownPackage: String, depth: Int): Boolean {
        val toks = tokenizeAwk(text)
        // Tokens that may stand immediately BEFORE a pure
        // getline command operand: expression boundaries
        // and statement keywords — anything else continues
        // an expression into the literal (concatenation).
        val lhsBoundary = setOf(
            "(", ";", "{", "}", ",", "=", "==", "!=", "<", ">",
            "<=", ">=", "~", "!~", "&&", "||", "!", "?", ":",
            "+", "-", "*", "/", "%", "^", "|", "|&")
        // Tokens that may stand immediately AFTER a pure
        // print-pipe command operand: statement/expression
        // terminators — anything else continues the command
        // expression past the literal.
        val rhsEnd = setOf(
            ";", "}", ")", ",", "==", "!=", "<", ">", "<=",
            ">=", "&&", "||", "?", ":", "|", "|&", ">>")
        for (idx in toks.indices) {
            val t = toks[idx]
            if (t.kind != AWK_TOK_SYM || (t.sym != "|" && t.sym != "|&")) continue
            val next = toks.getOrNull(idx + 1)
            if (next != null && next.kind == AWK_TOK_WORD &&
                next.sym == "getline") {
                // `expr | getline`: the command is on the LEFT.
                val prev = toks.getOrNull(idx - 1) ?: return true
                if (prev.kind != AWK_TOK_STR) return true
                val before = toks.getOrNull(idx - 2)
                val pure = before == null ||
                    (before.kind == AWK_TOK_SYM && before.sym in lhsBoundary) ||
                    (before.kind == AWK_TOK_WORD && before.sym in awkRegexLeadWords)
                if (!pure) return true
                // W51: an undecodable literal is unextractable.
                val decL = unescapeAwkString(prev.strVal ?: "") ?: return true
                if (recursePayload(decL, ownPackage, depth)) return true
            } else {
                // `print … | expr`: the command is on the RIGHT.
                val rhs = next ?: return true
                if (rhs.kind != AWK_TOK_STR) return true
                val after = toks.getOrNull(idx + 2)
                val pure = after == null ||
                    (after.kind == AWK_TOK_SYM && after.sym in rhsEnd)
                if (!pure) return true
                // W51: an undecodable literal is unextractable.
                val decR = unescapeAwkString(rhs.strVal ?: "") ?: return true
                if (recursePayload(decR, ownPackage, depth)) return true
            }
        }
        return false
    }

    /** W47: true when the awk string literal at [litStart] is
     *  an argument of a print/printf statement: scanning back
     *  over the statement's own expression tokens (commas
     *  included) reaches the print/printf keyword before any
     *  statement boundary or operator. */
    private fun awkLiteralUnderPrint(text: String, litStart: Int): Boolean {
        var k = litStart - 1
        while (k >= 0) {
            val c = text[k]
            when {
                c.isLetterOrDigit() || c == '_' -> {
                    var s = k
                    while (s >= 0 && (text[s].isLetterOrDigit() || text[s] == '_')) s--
                    val word = text.substring(s + 1, k + 1)
                    if (word == "print" || word == "printf") return true
                    k = s
                }
                c == '$' || c == ')' || c == '"' || c == ',' || c.isWhitespace() -> k--
                else -> return false
            }
        }
        return false
    }

    /** W51 (round-12): FAITHFUL awk string decoding for an
     *  extracted command string, or null when the literal is
     *  UNEXTRACTABLE (a form the implemented dialect table
     *  cannot decode exactly — the caller refuses). The
     *  pre-W51 pair-collapse rule decoded `\151` as `151`,
     *  so `system("\151nput tap 1 1")` was judged as the
     *  benign unknown verb `151nput` while awk executed
     *  `input tap 1 1` — the round-12 counter-example. The
     *  principle: any decoding the scanner applies to a
     *  literal must reproduce the target interpreter's
     *  decoding EXACTLY; where it cannot, refuse.
     *
     *  DIALECT TABLE IMPLEMENTED (and why). Android's stock
     *  awk (Android P and later, /system/bin/awk) is Brian
     *  Kernighan's "one true" awk (BWK), a POSIX awk; but
     *  `awk` here is PATH-resolved and the filter also
     *  dispatches `busybox awk`, whose awk (like gawk)
     *  decodes `\xHH`. The table is therefore only the
     *  decodings every resolvable variant agrees on:
     *   - the one-letter set \a \b \f \n \r \t \v \\ \"
     *     (POSIX/BWK/gawk/busybox all agree);
     *   - OCTAL \ooo, one to three digits 0-7, value taken
     *     as a byte (all agree; `\151` is `i`; values above
     *     \377 truncate to the byte — probed for BWK/mawk
     *     in the W53 lane log, documented for gawk/busybox);
     *   - a backslash-LF pair is DELETED (W53): the
     *     executed command is the joined text under every
     *     probed dialect (see the W53 header note);
     *   - backslash + any OTHER character decodes to that
     *     character — awk's own literal-char rule (`\c`
     *     in the gawk table, BWK's default), covering
     *     \/, \', \i, \8, \9 and the rest, on which the
     *     variants agree.
     *  REFUSED as unextractable (variants DIVERGE, so no
     *  single decoding is faithful): `\x` in ANY form
     *  (W53, round-13 residual R2: gawk/busybox decode
     *  \xhh as hex, a BWK literal-char reading keeps
     *  `xhh` as text — under that reading \x27 does NOT
     *  produce a quote, so syntax the hex reading makes
     *  inert stays active in the executed command, a
     *  dangerous-direction divergence; BWK builds
     *  themselves disagree on \x, and which awk PATH
     *  resolution selects is unknowable, so the W51
     *  hex decoding is withdrawn), `\u` / `\U` (a gawk
     *  Unicode extension BWK reads literally), `\e` /
     *  `\E` (ESC in newer gawk, a literal `e` in BWK),
     *  and a trailing lone backslash. */
    private fun unescapeAwkString(s: String): String? {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            if (s[i] != '\\') { sb.append(s[i]); i++; continue }
            if (i + 1 >= s.length) return null
            val e = s[i + 1]
            when {
                e == 'a' -> { sb.append('\u0007'); i += 2 }
                e == 'b' -> { sb.append('\b'); i += 2 }
                e == 'f' -> { sb.append('\u000C'); i += 2 }
                e == 'n' -> { sb.append('\n'); i += 2 }
                e == 'r' -> { sb.append('\r'); i += 2 }
                e == 't' -> { sb.append('\t'); i += 2 }
                e == 'v' -> { sb.append('\u000B'); i += 2 }
                e == '\\' -> { sb.append('\\'); i += 2 }
                e == '"' -> { sb.append('"'); i += 2 }
                e == 'e' || e == 'E' || e == 'u' || e == 'U' -> return null
                // W53: \x is dialect-divergent (see the doc
                // above) — unextractable in every form.
                e == 'x' -> return null
                // W53: backslash-LF inside the literal is a
                // continuation — the pair is deleted and the
                // surrounding text joins, which is the text
                // the executed command is judged on.
                e == '\n' -> { i += 2 }
                e in '0'..'7' -> {
                    var k = i + 1
                    var digits = ""
                    while (k < s.length && digits.length < 3 && s[k] in '0'..'7') {
                        digits += s[k]; k++
                    }
                    sb.append((digits.toInt(8) and 0xFF).toChar()); i = k
                }
                else -> { sb.append(e); i += 2 }
            }
        }
        return sb.toString()
    }

    /** A located payload argument: extract it verbatim and run
     *  the full filter over it. Extraction failure REFUSES —
     *  an unscannable payload is an unknown payload. */
    private fun payloadTokenRefused(tok: ScanTok, ownPackage: String, depth: Int): Boolean {
        if (tok.ansiBad) return true
        val template = extractPayloadLiteral(tok) ?: return true
        return recursePayload(template, ownPackage, depth)
    }

    /** Recursion into a payload string, depth-capped: a payload
     *  invocation found at the cap is deeper than the filter
     *  scans, so it refuses rather than passing unscanned. */
    private fun recursePayload(payload: String, ownPackage: String, depth: Int): Boolean {
        if (payload.isBlank()) return false
        if (depth >= 3) return true
        return shellInputRefused(payload, ownPackage, depth + 1)
    }

    /** The literal string a token hands to the next shell, or
     *  null when the token's value is not a readable string: an
     *  expansion or backtick in an UNQUOTED position means the
     *  outer shell's expansion — not this text — decides the
     *  value (and may split it), so no verbatim payload exists.
     *  Quoted spans extract verbatim (single quotes literally;
     *  double quotes with their backslash rules applied), plain
     *  and backslash-joined literals extract as their joined
     *  text. A token with no expansion at all IS its literal
     *  text ([ScanTok.norm]). */
    private fun extractPayloadLiteral(tok: ScanTok): String? {
        // W45: extraction works on the ORIGINAL-case text
        // ([ScanTok.caseNorm] / [ScanTok.caseRaw]) so the
        // payload handed to the recursion keeps its case and
        // case-sensitive flag discipline (awk -f vs -F) is
        // the same at every depth as at the top level.
        if (!tok.hadExpansion) return tok.caseNorm
        val raw = tok.caseRaw
        val sb = StringBuilder()
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            when {
                c == '\'' -> {
                    val j = raw.indexOf('\'', i + 1)
                    if (j < 0) { sb.append(raw.substring(i + 1)); i = raw.length }
                    else { sb.append(raw.substring(i + 1, j)); i = j + 1 }
                }
                c == '"' -> {
                    var j = i + 1
                    while (j < raw.length && raw[j] != '"') {
                        // W53: a backslash-LF pair inside
                        // double quotes is a line continuation
                        // the shell deletes — append nothing
                        // (pre-W53 the pair was carried into
                        // the payload and the recursion split
                        // at the LF: the round-13 hole).
                        if (raw[j] == '\\' && j + 1 < raw.length && raw[j + 1] == '\n') {
                            j += 2
                        } else if (raw[j] == '\\' && j + 1 < raw.length && raw[j + 1] in "\$`\"\\") {
                            sb.append(raw[j + 1]); j += 2
                        } else { sb.append(raw[j]); j++ }
                    }
                    i = if (j < raw.length) j + 1 else raw.length
                }
                c == '\\' -> {
                    // W53: unquoted backslash-LF is the same
                    // line continuation — deleted, joining the
                    // surrounding text; any other escaped char
                    // extracts as that char, as before.
                    if (i + 1 < raw.length && raw[i + 1] == '\n') i += 2
                    else if (i + 1 < raw.length) { sb.append(raw[i + 1]); i += 2 } else i++
                }
                c == '$' || c == '`' -> return null
                else -> { sb.append(c); i++ }
            }
        }
        return sb.toString()
    }

    /** The refusal text every path shares, so the fixture pins
     *  one wording. */
    fun injectionRefusalLine(path: InjectionPath): String = when (path) {
        InjectionPath.GESTURE ->
            "Refused: that gesture targets DeskGuest's own window — an agent cannot act on the app that hosts it (OI-13)."
        InjectionPath.NODE_ACTION ->
            "Refused: that element belongs to DeskGuest's own window — an agent cannot act on the app that hosts it (OI-13)."
        InjectionPath.SHELL_INPUT ->
            "Refused: shell synthetic input cannot prove its target is not DeskGuest's own window — refused on the shell path (OI-13)."
    }
}

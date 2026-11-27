package io.deskguest.app.design

import io.deskguest.app.strings.ConsentStrings

/**
 * W7 — TRIO-SIGNED merged Android design of record, part 2
 * (design-trio/merged/android-design-of-record.md): the presence
 * self-test (§2), frame accounting (§4 A4), the setup wizard
 * (§4 A2), Agent chat (§4 A17 / Addendum A), the access editor
 * (§4 A1 [R1]), Effective Policy (§4 A8 / OI-17) and the
 * MDM-notice / event / backup key-sheet surfaces (§5 RMM).
 * Pure model layer, same discipline as HeroDesign.kt: the views
 * render from these models and the JVM suite pins the record's
 * normative rules here. All wording comes from ConsentStrings.
 */

/** §2 presence self-test (merged law): before a session is
 *  accepted, the host draws all three elements and verifies the
 *  draw; a failed draw blocks the session. The Android overlay
 *  performs the real draw (PresenceOverlay.selfTestDraw) and
 *  reports the three booleans; this model is the verdict rule —
 *  ALL three must have drawn, and the STOP control must be part
 *  of the Box draw, or the session is refused. */
object PresenceSelfTest {

    data class DrawReport(
        val boxDrawn: Boolean,
        val boxStopDrawn: Boolean,
        val ghostDrawn: Boolean,
        val glowDrawn: Boolean
    )

    fun passes(report: DrawReport): Boolean =
        report.boxDrawn && report.boxStopDrawn && report.ghostDrawn && report.glowDrawn

    fun resultLine(passed: Boolean): String = ConsentStrings.DEFAULTS.getValue(
        if (passed) "presence_selftest_pass" else "presence_selftest_fail"
    )

    /** The session-accept gate: no verified presence, no session. */
    fun sessionMayStart(report: DrawReport): Boolean = passes(report)
}

/** §4 A4 frame accounting, honest form (W7 item 4): Sent counts
 *  DELIVERED frames, never tool calls. A frame counts only when
 *  the stream/preview path confirms delivery to the agent's
 *  endpoint. Where a source cannot count its frames, the detail
 *  says so (the uncounted line) instead of estimating. */
object FrameAccounting {

    /** Tools whose successful result IS one delivered frame. */
    val FRAME_TOOLS: Set<String> = setOf(
        "screenshot", "annotated_screenshot", "snapshot", "camera_capture"
    )

    fun isFrameTool(tool: String): Boolean = tool in FRAME_TOOLS

    /** A frame is counted only on a delivered (non-error) result. */
    fun frameDelivered(tool: String, resultIsError: Boolean): Boolean =
        isFrameTool(tool) && !resultIsError

    fun framesSentLine(frames: Long, agentName: String): String =
        ConsentStrings.DEFAULTS.getValue("session_frames_sent")
            .replace("%1\$d", frames.toString())
            .replace("%2\$s", agentName)

    fun uncountedLine(): String =
        ConsentStrings.DEFAULTS.getValue("session_frames_uncounted")

    /** The detail line for a pairing: the counted line when at
     *  least one frame was counted at its source; the honesty
     *  line when frames flowed from a source that cannot count. */
    fun detailLine(frames: Long, agentName: String, hadUncountableSource: Boolean): String =
        when {
            frames > 0 -> framesSentLine(frames, agentName)
            hadUncountableSource -> uncountedLine()
            else -> framesSentLine(0, agentName)
        }
}

/** §4 A2 setup wizard: seven labelled steps — role → transport →
 *  battery/OEM survival → accessibility → pair → access level →
 *  self-check. One step per screen, "Step N of 7", segments never
 *  unlabelled dots. Role first (OI-02) chooses the starting view
 *  only; it creates nothing. The pair step is the hero surface:
 *  before the code is redeemed the screen says "Waiting for your
 *  AI"; the agent's name and the safety phrase appear only AFTER
 *  redemption. The reachability gate (W4-B F8) refuses to mint a
 *  code when no remote address is reachable. */
object SetupWizardModel {

    val STEPS: List<String> = listOf(
        "role", "transport", "battery", "accessibility",
        "pair", "access level", "self-check"
    )

    const val STEP_COUNT: Int = 7

    fun stepLabel(stepIndexZeroBased: Int): String =
        ConsentStrings.DEFAULTS.getValue("wizard_step_of")
            .replace("%1\$d", (stepIndexZeroBased + 1).toString())
            .replace("%2\$d", STEP_COUNT.toString())

    /** The labelled segment for one step: "Step 5 of 7 · pair".
     *  Segments are NEVER unlabelled dots (§4 A2). */
    fun stepSegmentLabel(stepIndexZeroBased: Int): String =
        stepLabel(stepIndexZeroBased) + " · " + STEPS[stepIndexZeroBased]

    /** W8 item 3: the SAS phrase line itself — rendered ONLY
     *  where a real phrase exists. The phrase is derived in the
     *  enrollment flow (PairingSas.compute over both devices'
     *  keys, stored on the EnrolledDevice record); the MCP
     *  PairingStore holds no key material, so an MCP-only pairing
     *  can never produce one here — the wizard renders this line
     *  when an enrollment record carries a phrase, and the
     *  name-only check line otherwise. Never fabricated. */
    fun sasPhraseLine(sasDisplay: String): String =
        ConsentStrings.DEFAULTS.getValue("wizard_sas_phrase")
            .replace("%1\$s", sasDisplay)

    /** W10 (V3-F3a): the SAS phrase shown on the pair step must
     *  belong to THE pairing just redeemed — selected by that
     *  pairing's own id, never "the first enrollment record that
     *  has any SAS" (an operator enrollment record for a different
     *  identity showed the wrong words). [enrolled] is a list of
     *  (recordId, sas) pairs; the phrase is the one whose record
     *  id equals [redeemedPairingId], or null when none matches —
     *  no match means no phrase is shown, never another
     *  identity's words. */
    fun sasForPairing(
        redeemedPairingId: String?,
        enrolled: List<Pair<String, String>>
    ): String? {
        if (redeemedPairingId.isNullOrBlank()) return null
        return enrolled.firstOrNull { (id, sas) ->
            id == redeemedPairingId && sas.isNotBlank()
        }?.second
    }

    /** W10 (V3-F3f): the QR pairing offer (§4 A2 "Pairing offers
     *  QR + code") — the same endpoint + one-time code the copy
     *  prompt carries, in a short machine-readable form the AI's
     *  side can scan. The code in the QR is the code on screen:
     *  one offer, two renderings. */
    fun pairingOffer(endpoint: String, code: String): String =
        "deskguest://pair?endpoint=" +
            java.net.URLEncoder.encode(endpoint, "UTF-8") +
            "&code=" + code

    /** W10 (V3-F3f): the click budget, stated on the self-check
     *  screen (§4 A2 [R2F]). */
    fun clickBudgetLine(): String =
        ConsentStrings.DEFAULTS.getValue("wizard_click_budget")

    fun waitingLine(): String =
        ConsentStrings.DEFAULTS.getValue("wizard_waiting_for_ai")

    /** The SAS confirmation line, shown only after redemption —
     *  the agent's name is never shown before authentication. */
    fun sasCheckLine(agentName: String): String =
        ConsentStrings.DEFAULTS.getValue("wizard_sas_check")
            .replace("%1\$s", agentName)

    /** What the pair step may show: before redemption, ONLY the
     *  waiting line (no name, no phrase); after redemption, the
     *  name + phrase check. */
    fun pairStepShowsNameAndPhrase(redeemed: Boolean): Boolean = redeemed

    /** W4-B F8 reachability gate: no reachable remote address →
     *  no pairing code is minted. */
    fun mayMintCode(reachableRemoteAddress: String?): Boolean =
        !reachableRemoteAddress.isNullOrBlank()

    /** [A2] phrase derivation must differ in the first word across
     *  identities (no shared-prefix phrases): two different
     *  identities must not render the same first word. */
    fun firstWordsDiffer(firstWordA: String, firstWordB: String): Boolean =
        firstWordA.isNotBlank() && firstWordB.isNotBlank() &&
            !firstWordA.equals(firstWordB, ignoreCase = true)
}

/** §4 A17 Agent chat (Addendum A): the thread lives on the agent
 *  card, one thread per pairing. It is NOT a session: no Box, no
 *  Ghost, no Glow, no capability. Action requests from chat route
 *  through the ordinary approval gate and carry the chat origin.
 *  Off-device messages count as Sent in the data-flow ledger;
 *  unpairing ends the thread. Audit keeps message METADATA, not
 *  text — this model never carries message bodies into any
 *  accounting structure. */
object AgentChatModel {

    /** Chat confers no presence and no capability, ever. */
    val PRESENCE_ELEMENTS_IN_CHAT: List<String> = emptyList()
    fun chatStartsSession(): Boolean = false
    fun chatGrantsCapability(): Boolean = false

    fun destinationLine(agentName: String, agentDevice: String): String =
        ConsentStrings.DEFAULTS.getValue("chat_destination")
            .replace("%1\$s", agentName)
            .replace("%2\$s", agentDevice)

    fun gateNoteLine(): String =
        ConsentStrings.DEFAULTS.getValue("chat_gate_note")

    fun threadEndedLine(): String =
        ConsentStrings.DEFAULTS.getValue("chat_thread_ended")

    /** [R4] every canonical chat is the off-device case: a message
     *  to a paired (off-device) agent counts Sent. A co-located
     *  agent's messages stay on the device and do NOT count Sent. */
    fun countsAsSent(agentOffDevice: Boolean): Boolean = agentOffDevice

    /** An action ask from chat goes through the gate with the
     *  chat origin flag set — chat itself can never approve. */
    fun askRoutesThroughGate(): Boolean = true
    fun askFromChatFlag(): Boolean = true

    /** W10 (V3-F7): thread bound — a pairing's thread keeps at
     *  most this many messages; older ones are dropped at append
     *  time (their sequence numbers are never reused). */
    const val MAX_THREAD_MESSAGES: Int = 500

    /** W10 (V3-F7): agent post rate cap — at most this many
     *  chat_post calls per pairing inside the window, so a
     *  runaway or hostile agent cannot flood the owner's thread. */
    const val CHAT_POST_RATE_MAX: Int = 30
    const val CHAT_POST_RATE_WINDOW_MS: Long = 60_000

    /** The A17 ask-card line, carried by the chat ask path
     *  itself: asking opens the gate; chat cannot approve. */
    fun askCardLine(): String =
        ConsentStrings.DEFAULTS.getValue("chat_gate_note")
}

/** §4 A1 [R1] access editor: new pairings default to Look only;
 *  tightening takes effect on the next tool call. Escalating to
 *  Full control is a one-tap choice behind an explicit
 *  confirmation that names the agent and the consequence.
 *  Pairing.scopeIds (W2-A) is owner-edited here: the pairing may
 *  act only inside its scopes; an empty scope set means the
 *  pairing holds no scoped access. */
object AccessEditorModel {

    const val ACCESS_LOOK_ONLY: String = "observe"
    const val ACCESS_FULL: String = "full"
    const val ACCESS_CUSTOM: String = "custom"

    fun lookOnlyCopy(): String =
        ConsentStrings.DEFAULTS.getValue("access_look_only_copy")

    fun fullControlConfirmLine(agentName: String): String =
        ConsentStrings.DEFAULTS.getValue("access_full_control_confirm")
            .replace("%1\$s", agentName)

    /** Escalation requires the confirmation; de-escalation never
     *  does (tightening is always one tap, effective next call). */
    fun requiresConfirmation(fromAccess: String?, toAccess: String): Boolean =
        toAccess == ACCESS_FULL && fromAccess != ACCESS_FULL

    /** Scope editing: blank ids are dropped, duplicates collapse,
     *  order is stable — the same normalisation PairingStore
     *  applies at persistence. */
    fun normaliseScopeIds(ids: Collection<String>): Set<String> =
        ids.map { it.trim() }.filter { it.isNotBlank() }.toSet()

    fun pairingMayActInScope(scopeIds: Set<String>, scopeId: String): Boolean =
        scopeId in scopeIds
}

/** §4 A8 / §5 RMM: Effective Policy in owner words — one sentence
 *  per rule, each naming who set it ("… · set by Northwind IT").
 *  Status by exception: the surface leads with what needs
 *  attention. [R4 fold] the consent floor is NEVER a "set by …"
 *  row: it sits in its own "Always on — no one can change this"
 *  box, unattributed to any setter. */
object EffectivePolicyModel {

    data class Rule(val sentence: String, val setter: String?, val needsAttention: Boolean)

    /** A rule line names its setter; a rule with no setter is a
     *  local fact and carries no attribution suffix. */
    fun ruleLine(rule: Rule): String =
        if (rule.setter.isNullOrBlank()) rule.sentence
        else "${rule.sentence} · set by ${rule.setter}"

    /** The consent floor box: fixed title, fixed content, and —
     *  normatively — NO setter, ever. */
    fun consentFloorTitle(): String =
        ConsentStrings.DEFAULTS.getValue("policy_consent_floor_title")

    val CONSENT_FLOOR_ITEMS: List<String> = listOf(
        "you always see who is in control",
        "STOP always works, even offline",
        "your passwords are never typed by an agent",
        "the record of a session can't be edited"
    )

    fun consentFloorAttributedToSetter(): Boolean = false

    /** Status by exception: attention rows first, stable order
     *  otherwise; nothing is dropped. */
    fun orderByException(rules: List<Rule>): List<Rule> =
        rules.filter { it.needsAttention } + rules.filter { !it.needsAttention }
}

/** §5 RMM surfaces (W7 item 9): the MDM device notice, the event
 *  list (EventSubscriptions.listAll rendering) and the backup
 *  passphrase/key-sheet path for the W5-B encryption. The service
 *  paths exist (MdmService.notices, EventSubscriptions.listAll,
 *  BackupCrypto); these models are the rendering rules. */
object MdmSurfaceModel {

    fun noticeTitle(): String =
        ConsentStrings.DEFAULTS.getValue("mdm_notice_title")

    /** A notice renders kind + outcome in owner words; a notice
     *  whose action was refused says so — never silent. */
    fun noticeLine(kind: String, outcome: String): String = "$kind — $outcome"

    /** Event list rendering: groups sorted by name, event kinds
     *  sorted inside each group — a stable, complete rendering of
     *  listAll(); nothing is sampled or truncated. */
    fun eventLines(listAll: Map<String, Set<String>>): List<String> =
        listAll.entries.sortedBy { it.key }.flatMap { (group, kinds) ->
            kinds.sorted().map { kind -> "$group · $kind" }
        }
}

object BackupKeySheetModel {

    fun title(): String =
        ConsentStrings.DEFAULTS.getValue("backup_keysheet_title")

    fun body(): String =
        ConsentStrings.DEFAULTS.getValue("backup_keysheet_body")

    /** The key sheet is shown ONCE, at key creation, and the key
     *  is never stored in plain form by the surface: the sheet is
     *  a hand-off to the owner's own keeping. */
    fun keyStoredBySurface(): Boolean = false
    fun shownOnceAtCreation(): Boolean = true
}

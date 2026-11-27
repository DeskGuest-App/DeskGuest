import io.deskguest.app.chat.AgentChatStore
import io.deskguest.app.design.AccessEditorModel
import io.deskguest.app.design.AgentChatModel
import io.deskguest.app.design.BackupKeySheetModel
import io.deskguest.app.design.EffectivePolicyModel
import io.deskguest.app.design.FrameAccounting
import io.deskguest.app.design.MdmSurfaceModel
import io.deskguest.app.design.PresenceSelfTest
import io.deskguest.app.design.SetupWizardModel
import io.deskguest.app.server.ApprovalGate
import io.deskguest.app.server.DataFlows
import io.deskguest.app.server.GateDenyAndEnd
import java.io.File

/**
 * W7 — Android design implementation part 2 (TRIO-SIGNED record).
 * Pins Phases 1+2: presence self-test verdict, gate caller wiring
 * (source pins over the three hosts + the deny-and-end order
 * fixture), Home A1 order helpers, frame accounting (functional,
 * at DataFlows), wizard/SAS model, Agent chat (functional store +
 * ledger counting fixture), access editor, EffectivePolicy floor,
 * MDM/event/backup surfaces.
 * Args: [0] = android project dir.
 */
object W7Design2Test {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val src = File(root, "app/src/main/java/io/deskguest/app")
        fun text(rel: String) = File(src, rel).readText()

        // ---- Item 1: presence self-test + palette removal ----
        check("selftest: all drawn passes", PresenceSelfTest.passes(
            PresenceSelfTest.DrawReport(true, true, true, true)))
        check("selftest: missing glow blocks", !PresenceSelfTest.sessionMayStart(
            PresenceSelfTest.DrawReport(true, true, true, false)))
        check("selftest: missing STOP blocks", !PresenceSelfTest.sessionMayStart(
            PresenceSelfTest.DrawReport(true, false, true, true)))
        check("selftest: missing ghost blocks", !PresenceSelfTest.sessionMayStart(
            PresenceSelfTest.DrawReport(true, true, false, true)))
        val overlay = text("presence/PresenceOverlay.kt")
        check("overlay: no palette consumption", !overlay.contains("PresencePalette.Config") &&
            !overlay.contains("palette."))
        check("overlay: paints from PresenceLaw", overlay.contains("PresenceLaw.HUE_AI") &&
            overlay.contains("PresenceLaw.HUE_HUMAN"))
        check("overlay: ghost is ring+initial", overlay.contains("GhostDrawable") &&
            !overlay.contains("FingerDrawable"))
        check("overlay: static glow default (breath gated)",
            overlay.contains("if (comfort.breathEnabled) startGlowPulse"))
        check("overlay: self-test draw exists", overlay.contains("fun selfTestDraw"))
        check("overlay: STOP full width", overlay.contains("buttons.addView(boxStop, LinearLayout.LayoutParams(-1, -2))"))
        val presAct = text("PresenceActivity.kt")
        check("presence settings: no picker", !presAct.contains("PresencePalette") &&
            !presAct.contains("PRESETS") && !presAct.contains("parseHex"))
        check("presence settings: comfort only", presAct.contains("saveGlowIntensity") &&
            presAct.contains("saveBreath"))
        val presSettings = text("presence/PresenceSettings.kt")
        check("presence settings: legacy colour keys deleted, never read",
            presSettings.contains("LEGACY_COLOR_KEYS") && presSettings.contains("edit.remove"))
        val sm = text("server/SessionManager.kt")
        check("session gate: self-test provider refuses drive",
            sm.contains("presenceSelfTestPassed") && sm.contains("Presence failed its self-test"))

        // ---- Item 2: gate caller wiring ----
        for ((rel, payloadPin) in listOf(
            "server/AccessToolHost.kt" to "payload = value",
            "server/ShellToolHost.kt" to "payload = command",
            "server/OwedToolHost.kt" to "payload = encoded"
        )) {
            val host = text(rel)
            check("$rel: passes payload", host.contains(payloadPin))
            check("$rel: passes onDenyAndEnd", host.contains("GateDenyAndEnd.handler"))
            check("$rel: passes fromChat", host.contains("fromChat = fromChat"))
        }
        // Deny-and-end fixture — W10 (V3-F1) contract supersedes
        // the W7 audit-first pin: the handler performs the
        // TEARDOWN ONLY, and ApprovalOverlay writes the audit
        // event exactly once, after the handler returns; a
        // throwing handler propagates (the overlay then writes
        // approval_deny_and_end_failed, never a false success).
        val order = mutableListOf<String>()
        val handler = GateDenyAndEnd.handler(
            ApprovalGate.ActionClass.SHELL,
            endSession = { order += "end" }
        )
        handler()
        check("deny-and-end: handler runs the teardown only (overlay owns the single audit write)",
            order == listOf("end"), "$order")
        var propagated = false
        try {
            GateDenyAndEnd.handler(
                ApprovalGate.ActionClass.SHELL,
                endSession = { throw IllegalStateException("teardown failed") }
            )()
        } catch (_: IllegalStateException) {
            propagated = true
        }
        check("deny-and-end: a throwing teardown propagates (no swallowed failure)",
            propagated)
        val overlayText = text("server/ApprovalOverlay.kt")
        val denyEndText = text("server/GateDenyAndEnd.kt")
        check("deny-and-end: overlay emits approval_deny_and_end exactly once, handler never emits",
            overlayText.split("approval_deny_and_end\"").size - 1 == 1 &&
                !denyEndText.contains("SessionEvents.emit"))
        check("deny-and-end: overlay writes the failure event on the exception path",
            overlayText.contains("approval_deny_and_end_failed"))

        // ---- Item 3: Home A1 ----
        val main = text("MainActivity.kt")
        val iState = main.indexOf("section(\"home state\")")
        val iReady = main.indexOf("section(\"readiness\")")
        val iPair = main.indexOf("section(\"pairings\")")
        val iRecent = main.indexOf("section(\"recent\")")
        val iStanding = main.indexOf("section(\"standing\")")
        check("home order: state < readiness < pairings < recent < standing",
            iState in 0 until iReady && iReady < iPair && iPair < iRecent && iRecent < iStanding,
            "$iState $iReady $iPair $iRecent $iStanding")
        check("home: readiness rendered from HomeModel",
            main.contains("HomeModel.build") && main.contains("HomeModel.ReadinessRow"))
        check("home: standing from HomeModel", main.contains("HomeModel.STANDING_SECTIONS"))

        // ---- Item 4: frame accounting (functional) ----
        DataFlows.resetForTest()
        check("frames: screenshot delivered counts", FrameAccounting.frameDelivered("screenshot", false))
        check("frames: error result does not count", !FrameAccounting.frameDelivered("screenshot", true))
        check("frames: non-frame tool does not count", !FrameAccounting.frameDelivered("tap", false))
        DataFlows.noteDeliveredFrame("pair-1")
        DataFlows.noteDeliveredFrame("pair-1")
        check("frames: DataFlows counts delivered frames", DataFlows.framesDelivered("pair-1") == 2L)
        check("frames: blank pairing refused", run {
            DataFlows.noteDeliveredFrame(""); DataFlows.totalFramesDelivered() == 2L
        })
        val mcp = text("server/McpCore.kt")
        check("frames: McpCore wires delivery at dispatch",
            mcp.contains("FrameAccounting") && mcp.contains("noteDeliveredFrame"))
        val sess = text("SessionsActivity.kt")
        check("frames: session detail Sent comes from frames",
            sess.contains("totalFramesDelivered") && sess.contains("totalChatSent"))
        check("frames: uncounted honesty line exists",
            FrameAccounting.uncountedLine().contains("could not be counted"))

        // ---- Item 5: wizard + SAS ----
        check("wizard: seven steps", SetupWizardModel.STEPS.size == 7 &&
            SetupWizardModel.STEP_COUNT == 7)
        check("wizard: step label", SetupWizardModel.stepLabel(4) == "Step 5 of 7")
        check("wizard: waiting line", SetupWizardModel.waitingLine() == "Waiting for your AI")
        check("wizard: name/phrase only after redemption",
            !SetupWizardModel.pairStepShowsNameAndPhrase(false) &&
                SetupWizardModel.pairStepShowsNameAndPhrase(true))
        check("wizard: reachability gate refuses blank address",
            !SetupWizardModel.mayMintCode(null) && !SetupWizardModel.mayMintCode("") &&
                SetupWizardModel.mayMintCode("100.64.0.2"))
        check("wizard: first words must differ across identities",
            SetupWizardModel.firstWordsDiffer("tat", "vav") &&
                !SetupWizardModel.firstWordsDiffer("tat", "TAT"))
        val wiz = text("WizardActivity.kt")
        check("wizard: waiting + SAS lines rendered",
            wiz.contains("SetupWizardModel.waitingLine") && wiz.contains("SetupWizardModel.sasCheckLine"))

        // ---- Item 6: Agent chat (functional) ----
        check("chat: not a session, no capability, no presence",
            !AgentChatModel.chatStartsSession() && !AgentChatModel.chatGrantsCapability() &&
                AgentChatModel.PRESENCE_ELEMENTS_IN_CHAT.isEmpty())
        check("chat: off-device counts Sent, on-device does not",
            AgentChatModel.countsAsSent(true) && !AgentChatModel.countsAsSent(false))
        check("chat: ask routes through gate with chat flag",
            AgentChatModel.askRoutesThroughGate() && AgentChatModel.askFromChatFlag())
        DataFlows.resetForTest()
        val chatDir = File(System.getProperty("java.io.tmpdir"), "deskguest-w7-chat-${System.nanoTime()}")
        val ev = AgentChatStore.append(chatDir, "pair-9", AgentChatStore.DIR_OWNER, "hello agent", 1000L)
        check("chat: owner message counted Sent in ledger", DataFlows.chatSentCount("pair-9") == 1L)
        check("chat: audit event is metadata only",
            ev.keys == setOf("pairing", "direction", "chars", "atMs") &&
                ev["chars"] == 11 && !ev.values.any { it.toString().contains("hello") })
        AgentChatStore.append(chatDir, "pair-9", AgentChatStore.DIR_AGENT, "hi owner", 1001L)
        check("chat: agent reply does not count Sent", DataFlows.chatSentCount("pair-9") == 1L)
        check("chat: thread loads both directions",
            AgentChatStore.load(chatDir, "pair-9").size == 2)
        AgentChatStore.endThread(chatDir, "pair-9")
        check("chat: unpair ends thread", !AgentChatStore.threadExists(chatDir, "pair-9") &&
            AgentChatStore.load(chatDir, "pair-9").isEmpty())
        chatDir.deleteRecursively()
        val chatAct = text("AgentChatActivity.kt")
        check("chat activity: destination line + gate note + fromChat gate",
            chatAct.contains("AgentChatModel.destinationLine") &&
                chatAct.contains("AgentChatModel.gateNoteLine") &&
                chatAct.contains("fromChat = true"))
        check("chat: agent card entry + unpair ends thread in MainActivity",
            main.contains("AgentChatActivity") && main.contains("AgentChatStore.endThread"))

        // ---- Item 7: access editor ----
        check("access: full control needs confirmation, tightening does not",
            AccessEditorModel.requiresConfirmation("observe", "full") &&
                !AccessEditorModel.requiresConfirmation("full", "full") &&
                !AccessEditorModel.requiresConfirmation("full", "observe"))
        check("access: scope ids normalised",
            AccessEditorModel.normaliseScopeIds(listOf(" a ", "", "a", "b")) == setOf("a", "b"))
        check("access: scope gate", AccessEditorModel.pairingMayActInScope(setOf("s1"), "s1") &&
            !AccessEditorModel.pairingMayActInScope(setOf("s1"), "s2") &&
            !AccessEditorModel.pairingMayActInScope(emptySet(), "s1"))
        check("access: MainActivity wires confirmation + scopeIds UI",
            main.contains("AccessEditorModel.fullControlConfirmLine") &&
                main.contains("setScopeIds") && main.contains("normaliseScopeIds"))
        val uikit = text("ui/UiKit.kt")
        check("access: Look only copy corrected via externalised string",
            uikit.contains("R.string.access_look_only_copy"))

        // ---- Item 8: EffectivePolicy ----
        val rule = EffectivePolicyModel.Rule("Widgets may run at night", "Northwind IT", false)
        check("policy: rule line names setter",
            EffectivePolicyModel.ruleLine(rule) == "Widgets may run at night · set by Northwind IT")
        check("policy: consent floor NEVER attributed",
            !EffectivePolicyModel.consentFloorAttributedToSetter() &&
                EffectivePolicyModel.consentFloorTitle() == "Always on — no one can change this")
        val ordered = EffectivePolicyModel.orderByException(listOf(
            EffectivePolicyModel.Rule("ok rule", "Northwind IT", false),
            EffectivePolicyModel.Rule("bad rule", "Northwind IT", true)
        ))
        check("policy: status by exception orders attention first",
            ordered.first().sentence == "bad rule" && ordered.size == 2)
        val effAct = text("rmmspine/EffectivePolicyActivity.kt")
        check("policy activity: floor box rendered from the single floor source (W10 V3-F4)",
            effAct.contains("EffectivePolicyView.floorText()"))

        // ---- Item 9: MDM / events / backup key sheet ----
        check("mdm: notice line", MdmSurfaceModel.noticeLine("lock", "done") == "lock — done")
        val eventLines = MdmSurfaceModel.eventLines(
            mapOf("pair-b" to setOf("session_started"), "pair-a" to setOf("gate", "chat"))
        )
        check("mdm: event listAll rendered completely + sorted",
            eventLines == listOf("pair-a · chat", "pair-a · gate", "pair-b · session_started"),
            "$eventLines")
        check("backup: key sheet shown once, never stored by surface",
            BackupKeySheetModel.shownOnceAtCreation() && !BackupKeySheetModel.keyStoredBySurface())
        val rmmAct = text("RmmNoticesActivity.kt")
        check("rmm activity: notices + listAll + key sheet rendered",
            rmmAct.contains("MdmSurfaceModel.noticeLine") &&
                rmmAct.contains("EventSubscriptions.listAll") &&
                rmmAct.contains("BackupCrypto.deriveKey") &&
                rmmAct.contains("BackupKeySheetModel.title"))

        DataFlows.resetForTest()
        println("W7Design2Test: $passes PASS, $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

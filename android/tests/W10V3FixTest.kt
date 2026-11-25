import io.agenticcontrol.app.chat.AgentChatStore
import io.agenticcontrol.app.design.AgentChatModel
import io.agenticcontrol.app.design.EffectivePolicyModel
import io.agenticcontrol.app.design.GateModel
import io.agenticcontrol.app.design.HeroThemes
import io.agenticcontrol.app.design.QrCode
import io.agenticcontrol.app.design.QrReferenceFixtures
import io.agenticcontrol.app.design.SetupWizardModel
import io.agenticcontrol.app.rmmspine.EffectivePolicyView
import io.agenticcontrol.app.rmmspine.ManagementPolicyDocument
import io.agenticcontrol.app.rmmspine.ManagementPolicyEngine
import io.agenticcontrol.app.rmmspine.PolicyLevels
import io.agenticcontrol.app.rmmspine.StaticDeviceFacts
import io.agenticcontrol.app.server.ApprovalGate
import io.agenticcontrol.app.server.ChatToolHost
import io.agenticcontrol.app.server.GateDenyAndEnd
import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.PairingStore
import org.json.JSONObject
import java.io.File

/**
 * W10 — V3 verification fixes (packet 129ca200). Every V3
 * claim was verified against the tree first (lane log); this
 * suite pins the FIXES:
 *  F5 gate/Box: PresenceOverlay.raiseBoxAboveGate exists and the
 *     overlay calls it after addView (source pins; on-device
 *     hit-test is a named human-reserved remainder).
 *  F1 gate parity: exitStyles equal in both themes and read
 *     GateModel.exits() weight/borderContrast; arming accepts a
 *     click (TalkBack) as human activation; onDenyAndEnd
 *     non-null (signature pin); single audit write (overlay pin,
 *     also in W7Design2Test); payload scroll + escaping +
 *     overlayPayloadMatches round-trip.
 *  F3 wizard: lastRedeemedPairing is this-run only; sasForPairing
 *     binds by pairing id; source pins (no name field, 11sp,
 *     record role wording, QR rendered, click budget, vendor
 *     line, no banned copy, neutral chips/expiry).
 *  F2 chat→gate: chat_ask through the real McpCore dispatch with
 *     an injected gateAsker proves fromChat routing exists on the
 *     agent side; scope "none" on all chat tools; owner-side
 *     caller pin in AgentChatActivity.
 *  F4 policy: default-OFF→ON needs attention; owner-words
 *     sentences/setters; floor once.
 *  F6: filterTouchesWhenObscured pins.
 *  F7 chat store: explicit seq survives a torn legacy line,
 *     single-snapshot cursor, thread bound, post rate cap.
 *  QR: QrCode matrices equal the segno reference matrices,
 *     module for module, at forced masks (V1/V5/V7).
 * Args: [0] = android project dir.
 */
object W10V3FixTest {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    private fun call(core: McpCore, token: String?, id: Int, tool: String, args: String): JSONObject {
        val reply = core.handle(
            """{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"$tool","arguments":$args}}""",
            token
        )
        return JSONObject(reply.body!!)
    }

    private fun resultText(json: JSONObject): String =
        json.getJSONObject("result").getJSONArray("content").getJSONObject(0).getString("text")

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val src = File(root, "app/src/main/java/io/agenticcontrol/app")
        fun text(rel: String) = File(src, rel).readText()

        // ================= F1: gate parity =================
        for ((themeName, theme) in listOf("LIGHT" to HeroThemes.LIGHT, "DARK" to HeroThemes.DARK)) {
            val styles = GateModel.exitStyles(theme)
            check("gate parity ($themeName): exactly three exits", styles.size == 3)
            check(
                "gate parity ($themeName): all exits identical fill/text/border",
                styles.map { Triple(it.fill, it.textColor, it.borderColor) }.distinct().size == 1,
                "$styles"
            )
            check(
                "gate parity ($themeName): no exit uses the solid approve fill",
                styles.none { it.fill == theme.approveFill }
            )
            check(
                "gate parity ($themeName): weight + borderContrast read from GateModel.exits()",
                styles.map { it.weight } == GateModel.exits().map { it.weight } &&
                    styles.map { it.borderContrast } == GateModel.exits().map { it.borderContrast } &&
                    styles.all { it.weight == 600 }
            )
        }
        // Arming: a click (the TalkBack activation path) is a human
        // activation; time alone is not; activation alone is not.
        check(
            "gate arming: 600ms + human activation required, click counts as activation",
            GateModel.controlsArmed(1000, 1600, true) &&
                !GateModel.controlsArmed(1000, 1599, true) &&
                !GateModel.controlsArmed(1000, 5000, false)
        )
        val overlay = text("server/ApprovalOverlay.kt")
        check(
            "gate arming: overlay treats an exit click as activation and only an armed click decides",
            // W13 superseded pin (cause: P1-F12/P2-F19 — the
            // activation is now a GateModel.Activation RECORD on
            // the monotonic clock, recorded via recordActivation;
            // the pinned behaviour — a click activates, only an
            // armed click decides — is unchanged).
            overlay.contains("recordActivation(\"click\")") &&
                overlay.contains("if (armedNow())")
        )
        check(
            "gate parity: overlay renders exits from GateModel.exitStyles with the semibold (600) face",
            overlay.contains("GateModel.exitStyles(theme)") && overlay.contains("Fonts.semibold")
        )
        check(
            "gate: onDenyAndEnd is a required (non-null) handler",
            overlay.contains("onDenyAndEnd: () -> Unit") &&
                !overlay.contains("onDenyAndEnd?.invoke()")
        )
        check(
            "gate payload: bounded ScrollView with exits outside it",
            overlay.contains("ScrollView(context)") &&
                overlay.indexOf("ScrollView(context)") < overlay.indexOf("exitButtons +=")
        )
        check(
            "gate payload: rendered through GateModel.escapePayload",
            overlay.contains("GateModel.escapePayload(payload)")
        )
        // Payload escaping: bidi/control characters become visible
        // escapes, and the shown string decodes back to the exact
        // submitted bytes.
        val sneaky = "Pay 100\u202E txt.exe \u0007done"
        val shown = GateModel.escapePayload(sneaky)
        check(
            "gate payload: bidi + control characters are escaped visibly",
            !shown.contains('\u202E') && !shown.contains('\u0007') &&
                shown.contains("\\u202E") && shown.contains("\\u0007"),
            shown
        )
        check(
            "gate payload (OI-12): overlay string decodes to the submitted bytes exactly",
            GateModel.overlayPayloadMatches(shown, sneaky) &&
                GateModel.overlayPayloadMatches(GateModel.escapePayload("plain text"), "plain text") &&
                !GateModel.overlayPayloadMatches(shown, "$sneaky ")
        )
        check(
            "gate payload: plain payloads render unmodified",
            GateModel.escapePayload("Send the report to Alex") == "Send the report to Alex"
        )

        // ================= F6: obscured-touch second wall =================
        check(
            "OI-13 second wall: card + exits set filterTouchesWhenObscured from the model pin",
            GateModel.FILTER_TOUCHES_WHEN_OBSCURED &&
                overlay.split("filterTouchesWhenObscured = GateModel.FILTER_TOUCHES_WHEN_OBSCURED").size - 1 == 2
        )

        // ================= F5: Box stays above the gate =================
        val presence = text("presence/PresenceOverlay.kt")
        check(
            "OI-01: PresenceOverlay can re-raise the Box (re-attach its window)",
            presence.contains("fun raiseBoxAboveGate()") &&
                presence.contains("wm.removeViewImmediate(box)") &&
                presence.contains("wm.addView(box, params)")
        )
        check(
            "OI-01: the gate re-raises the Box after adding its own sheet",
            overlay.indexOf("wm.addView(card, params)") in 0 until
                overlay.indexOf("PresenceOverlay.raiseBoxAboveGate()")
        )

        // ================= F3: wizard binding =================
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-w10-" + System.nanoTime())
        dir.mkdirs()
        val storeFile = File(dir, "pairings.tsv")
        val storeA = PairingStore(storeFile)
        check(
            "wizard: a fresh store has redeemed nothing this run",
            storeA.lastRedeemedPairing() == null
        )
        val codeA = storeA.beginPairing("")
        val redeemedA = storeA.redeem(codeA, setOf("observe"))
        check(
            "wizard: lastRedeemedPairing is the pairing this run redeemed",
            redeemedA != null && storeA.lastRedeemedPairing()?.token == redeemedA.token
        )
        val storeB = PairingStore(storeFile)
        check(
            "wizard: a reloaded store (earlier pairings on disk) has redeemed NOTHING this run",
            storeB.all().isNotEmpty() && storeB.lastRedeemedPairing() == null
        )
        check(
            "wizard SAS: phrase binds to THE redeemed pairing's record only",
            SetupWizardModel.sasForPairing(
                "pair-2",
                listOf("pair-1" to "apple berry cherry", "pair-2" to "delta echo foxtrot")
            ) == "delta echo foxtrot" &&
                SetupWizardModel.sasForPairing("pair-3", listOf("pair-1" to "apple berry cherry")) == null &&
                SetupWizardModel.sasForPairing(null, listOf("pair-1" to "apple berry cherry")) == null
        )
        val wiz = text("WizardActivity.kt")
        check(
            "wizard: no owner-typed AI name field remains",
            !wiz.contains("EditText") && !wiz.contains("Your AI's name") &&
                // W98 amendment (recorded, W97 precedent): the mint call
                // gained its second argument — the connection-path
                // setting bound at mint (S09(b)). The nameless rule this
                // pin guards is the FIRST argument, still exactly "".
                wiz.contains("store.beginPairing(\"\", mintConnection)")
        )
        check(
            "wizard: pair step binds name/phrase/continue to this run's redemption",
            wiz.contains("store?.lastRedeemedPairing()") &&
                wiz.contains("sasForPairing(target.id, enrolledPairs)") &&
                wiz.contains("redeemed != null || paired.isNotEmpty()")
        )
        check(
            "wizard: step segment labels meet the 11sp floor",
            wiz.contains("textSize = 11f") && !wiz.contains("textSize = 9f")
        )
        check(
            "wizard: role options carry the record's wording",
            wiz.contains("\"This is my phone\"") &&
                wiz.contains("\"I'm setting this phone up for someone else\"") &&
                !wiz.contains("\"Just me\"")
        )
        check(
            "wizard: QR option rendered from the pairing offer",
            wiz.contains("SetupWizardModel") && wiz.contains("pairingOffer(endpoint, pairingCode!!)") &&
                wiz.contains("QrCode.encode(offer)") && wiz.contains("qrImage(symbol)")
        )
        check(
            "wizard: click budget stated on the self-check screen",
            wiz.contains("SetupWizardModel.clickBudgetLine()") &&
                SetupWizardModel.clickBudgetLine().contains("5–8 taps") &&
                SetupWizardModel.clickBudgetLine().contains("10–14")
        )
        check(
            "wizard welcome: vendor line verbatim, no banned 'nothing is sent' form, Box is the banner",
            wiz.contains("Nowhere else — DeskGuest sends nothing to anyone.") &&
                !wiz.contains("Nothing is sent anywhere else") &&
                !wiz.contains("a banner naming the AI") &&
                !wiz.contains("the glow, banner, and STOP") &&
                !wiz.contains("the Glow, banner, and STOP")
        )
        check(
            "wizard hues: expiry in neutral ink, state chips neutral (no presence hues as status)",
            !wiz.contains("UiKit.WARNING") && !wiz.contains("ChipKind.GOOD") &&
                !wiz.contains("ChipKind.WARN") && wiz.contains("ChipKind.NEUTRAL")
        )
        check(
            "wizard: pairing offer is the endpoint + code, one offer two renderings",
            SetupWizardModel.pairingOffer("http://100.64.0.1:8931/mcp", "123456") ==
                "acp://pair?endpoint=http%3A%2F%2F100.64.0.1%3A8931%2Fmcp&code=123456"
        )

        // ================= QR vs external reference =================
        fun qrCheck(name: String, payload: String, mask: Int, expected: List<String>) {
            val sym = QrCode.encode(payload, forceMask = mask)
            check(
                "QR reference ($name): matrix equals segno reference at mask $mask",
                sym != null && sym.rowStrings() == expected,
                if (sym == null) "null symbol" else "version ${sym.version} size ${sym.size}"
            )
        }
        qrCheck("V1 HELLO", "HELLO", 0, QrReferenceFixtures.HELLO_mask0)
        qrCheck(
            "V5 offer", "acp://pair?endpoint=http%3A%2F%2F100.64.0.1%3A8931%2Fmcp&code=123456",
            6, QrReferenceFixtures.OFFER_mask6
        )
        qrCheck(
            "V7 long",
            "ACP pairing offer: connect to http://100.64.0.1:8931/mcp and redeem code 123456 within 10 minutes. The code works once.",
            3, QrReferenceFixtures.LONG_mask3
        )
        check(
            "QR: auto version picks the smallest fitting symbol",
            QrCode.encode("HELLO")?.version == 1 &&
                QrCode.encode("x".repeat(200)) == null
        )

        // ================= F2: chat → gate =================
        val chatDir = File(dir, "agent-chat")
        var gateCalls = 0
        var gateSawPayload: String? = null
        var gateSawSummary: String? = null
        val host = ChatToolHost(chatDir, storeB) { summary, payload, _ ->
            gateCalls++; gateSawSummary = summary; gateSawPayload = payload; true
        }
        val core = McpCore(storeB, host)
        val code2 = storeB.beginPairing("")
        val pairReply = core.handle(
            """{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code2"}}""", null
        )
        val token = JSONObject(pairReply.body!!).getJSONObject("result").getString("token")
        val list = core.handle("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", token)
        check(
            "chat: tools/list offers chat_read + chat_post + chat_ask",
            list.body!!.contains("chat_read") && list.body!!.contains("chat_post") &&
                list.body!!.contains("chat_ask"),
            list.body ?: ""
        )
        check(
            "chat: ask card carries the A17 line (chat cannot approve)",
            list.body!!.contains("Opens the approval gate. Chat cannot approve.")
        )
        val askReply = JSONObject(
            resultText(call(core, token, 3, "chat_ask", """{"request":"Open the files app and share the battery report"}"""))
        )
        check(
            "chat→gate: chat_ask actually calls the gate and reports its answer",
            gateCalls == 1 && askReply.getBoolean("approved") &&
                gateSawPayload == "Open the files app and share the battery report" &&
                (gateSawSummary ?: "").contains("Agent chat"),
            "calls=$gateCalls reply=$askReply"
        )
        val hostTools = ChatToolHost(chatDir, storeB).tools()
        check(
            "chat: all chat tools declare the capability-free scope (none)",
            hostTools.all { it.scope == "none" } && hostTools.map { it.name }.toSet() ==
                setOf("chat_read", "chat_post", "chat_ask"),
            hostTools.map { "${it.name}:${it.scope}" }.toString()
        )
        val svc = text("server/ControlService.kt")
        check(
            "chat→gate: ControlService wires chat_ask to ApprovalOverlay with fromChat = true",
            svc.contains("ApprovalOverlay.requestApproval") &&
                svc.contains("fromChat = true") &&
                svc.contains("ApprovalGate.ActionClass.CHAT_REQUEST")
        )
        val chatAct = text("AgentChatActivity.kt")
        check(
            "chat→gate: owner-side ask-to-act keeps its fromChat gate AND acts on approval",
            chatAct.contains("fromChat = true") &&
                chatAct.contains("if (approved)") &&
                chatAct.contains("AgentChatStore.append")
        )
        // Denied ask: gate answer false is reported, nothing approved.
        val hostDeny = ChatToolHost(chatDir, storeB) { _, _, _ -> false }
        val coreDeny = McpCore(storeB, hostDeny)
        val askDeny = JSONObject(
            resultText(call(coreDeny, token, 4, "chat_ask", """{"request":"Do a thing"}"""))
        )
        check(
            "chat→gate: a denied ask reports approved=false",
            !askDeny.getBoolean("approved")
        )

        // ================= F7: chat store race / bound =================
        val raceDir = File(dir, "race-chat")
        val pid = "pair-race"
        AgentChatStore.append(raceDir, pid, AgentChatStore.DIR_OWNER, "one", 1000L)
        AgentChatStore.append(raceDir, pid, AgentChatStore.DIR_AGENT, "two", 1001L)
        // A torn legacy line in the middle must not shift seqs.
        // W12-DS P1-F11: thread filenames are now injective
        // (Base64url of the pairing id) — locate the actual file.
        val threadFile = raceDir.listFiles()!!.single { it.name.endsWith(".thread") }
        val lines = threadFile.readLines().toMutableList()
        lines.add(1, "garbage-line-without-fields")
        threadFile.writeText(lines.joinToString("\n") + "\n")
        val third = AgentChatStore.appendSequenced(raceDir, pid, AgentChatStore.DIR_OWNER, "three", 1002L)
        check(
            "chat store: explicit persisted seq — a torn line never shifts sequence numbers",
            third.seq == 3L &&
                AgentChatStore.loadSequenced(raceDir, pid).map { it.seq } == listOf(1L, 2L, 3L),
            "${AgentChatStore.loadSequenced(raceDir, pid).map { it.seq }}"
        )
        val (snapMsgs, snapCursor) = AgentChatStore.snapshotAfter(raceDir, pid, 1L)
        check(
            "chat store: single-snapshot read — messages and cursor from one load",
            snapMsgs.map { it.seq } == listOf(2L, 3L) && snapCursor == 3L &&
                AgentChatStore.nextCursor(raceDir, pid) == snapCursor
        )
        // Bound: appends past the cap drop the oldest, seqs preserved.
        val boundDir = File(dir, "bound-chat")
        repeat(AgentChatModel.MAX_THREAD_MESSAGES + 5) { i ->
            AgentChatStore.append(boundDir, pid, AgentChatStore.DIR_AGENT, "m$i", 2000L + i)
        }
        val bound = AgentChatStore.loadSequenced(boundDir, pid)
        check(
            "chat store: thread is bounded, oldest dropped, seqs never renumbered",
            bound.size == AgentChatModel.MAX_THREAD_MESSAGES &&
                bound.first().seq == 6L &&
                bound.last().seq == (AgentChatModel.MAX_THREAD_MESSAGES + 5).toLong(),
            "size=${bound.size} first=${bound.firstOrNull()?.seq} last=${bound.lastOrNull()?.seq}"
        )
        // Rate cap: CHAT_POST_RATE_MAX posts pass, the next refuses.
        val rateDir = File(dir, "rate-chat")
        val rateHost = ChatToolHost(rateDir, storeB)
        val rateCore = McpCore(storeB, rateHost)
        var lastPost = ""
        repeat(AgentChatModel.CHAT_POST_RATE_MAX) { i ->
            lastPost = resultText(call(rateCore, token, 100 + i, "chat_post", """{"body":"post $i"}"""))
        }
        val overPost = resultText(
            call(rateCore, token, 999, "chat_post", """{"body":"one too many"}""")
        )
        check(
            "chat store: chat_post rate cap refuses past the per-minute limit",
            JSONObject(lastPost).getBoolean("posted") && overPost.contains("refused"),
            overPost
        )

        // ================= F4: effective policy =================
        val engine = ManagementPolicyEngine()
        val facts = StaticDeviceFacts("phone-1", "scope-1")
        engine.addDocument(
            ManagementPolicyDocument(
                "org-doc", PolicyLevels.ORG, "scope-1",
                mapOf(
                    "rmm.camera_viewing.enabled" to "true",
                    "rmm.monitoring.enabled" to "false"
                ), 1
            )
        )
        val rules = EffectivePolicyView.rules(engine, facts)
        val cameraRule = rules.first { it.sentence.contains("Camera viewing") }
        val monitoringRule = rules.first { it.sentence.contains("Continuous endpoint health monitoring") }
        check(
            "policy: default-OFF turned ON needs attention (presence/privacy weight surfaces)",
            cameraRule.needsAttention && cameraRule.sentence.contains("on"),
            cameraRule.toString()
        )
        check(
            "policy: default-ON turned OFF still needs attention",
            monitoringRule.needsAttention && monitoringRule.sentence.contains("off")
        )
        check(
            "policy: an untouched default does NOT need attention",
            !rules.first { it.sentence.contains("Patch management") }.needsAttention
        )
        check(
            "policy: sentences are owner words — no raw keys in registry rule sentences",
            rules.none { it.sentence.contains("rmm.") },
            rules.firstOrNull { it.sentence.contains("rmm.") }?.sentence ?: ""
        )
        check(
            "policy: setter is owner words (org → '<org> IT'), never a doc id",
            cameraRule.setter == "scope-1 IT" &&
                rules.none { (it.setter ?: "").contains("org-doc") },
            "${cameraRule.setter}"
        )
        val ordered = EffectivePolicyModel.orderByException(rules)
        check(
            "policy: exception ordering leads with BOTH deviation directions",
            ordered.take(2).map { it.sentence }.toSet() ==
                setOf(cameraRule.sentence, monitoringRule.sentence),
            ordered.take(2).toString()
        )
        val rendered = EffectivePolicyView.render(engine, facts)
        check(
            "policy: floor listed once — only in floorText, all four items, unattributed",
            !rendered.contains("Always on") && !rendered.contains("Consent floor") &&
                EffectivePolicyModel.CONSENT_FLOOR_ITEMS.size == 4 &&
                EffectivePolicyModel.CONSENT_FLOOR_ITEMS.all {
                    EffectivePolicyView.floorText().contains(it)
                } &&
                EffectivePolicyView.floorText().contains("passwords") &&
                !EffectivePolicyView.floorText().contains("set by")
        )
        val effAct = text("rmmspine/EffectivePolicyActivity.kt")
        check(
            "policy: Activity renders the floor from the single floorText source",
            effAct.contains("EffectivePolicyView.floorText()")
        )

        // ================= deny-and-end handler (functional) =================
        var ended = false
        GateDenyAndEnd.handler(ApprovalGate.ActionClass.CHAT_REQUEST) { ended = true }()
        check("deny-and-end: handler performs the teardown", ended)

        println("W10V3FIX: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

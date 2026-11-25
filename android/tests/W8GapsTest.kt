import io.agenticcontrol.app.chat.AgentChatStore
import io.agenticcontrol.app.design.EffectivePolicyModel
import io.agenticcontrol.app.design.GateModel
import io.agenticcontrol.app.design.SetupWizardModel
import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.rmmspine.EffectivePolicyView
import io.agenticcontrol.app.rmmspine.ManagementPolicyDocument
import io.agenticcontrol.app.rmmspine.ManagementPolicyEngine
import io.agenticcontrol.app.rmmspine.MdmDeviceNotice
import io.agenticcontrol.app.rmmspine.MdmWiring
import io.agenticcontrol.app.rmmspine.PolicyLevels
import io.agenticcontrol.app.rmmspine.StaticDeviceFacts
import io.agenticcontrol.app.server.ChatToolHost
import io.agenticcontrol.app.server.DataFlows
import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.PairingStore
import org.json.JSONObject
import java.io.File

/**
 * W8 — Android named-gap closures. Per item:
 *  1. Agent chat TRANSPORT: chat_read/chat_post through the real
 *     McpCore dispatch (pair → tools/list → tools/call), cursor
 *     sync semantics, own-pairing isolation, metadata-only audit,
 *     unpair ends both legs.
 *  2. Live MdmService wiring: MdmWiring.build constructs a real
 *     service whose notices are live AND backed by the same file
 *     the surface reads; absent-source honesty (no facts ⇒ the
 *     policy gate refuses closed; no notices ⇒ empty list).
 *  3. Wizard: 7 labelled steps rendered from SetupWizardModel
 *     (source pins over WizardActivity) + SAS phrase line renders
 *     a real enrollment-derived phrase and is never fabricated
 *     for an MCP-only pairing.
 *  4. Effective Policy receipts: rules regenerated through
 *     EffectivePolicyModel.ruleLine on-device (functional, from
 *     a live engine), setter attribution + exception ordering.
 *  5. OI-13 injection-path fixtures: the REAL decision functions
 *     the gesture/node/shell paths consult (GateModel), plus
 *     source pins that the paths call them.
 * Args: [0] = android project dir.
 */
object W8GapsTest {
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

        // ================= Item 1: chat transport =================
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-w8-" + System.nanoTime())
        dir.mkdirs()
        val chatDir = File(dir, "agent-chat")
        val store = PairingStore(File(dir, "pairings.tsv"))
        val core = McpCore(store, ChatToolHost(chatDir, store))
        val code = store.beginPairing("Chat AI")
        val paired = core.handle(
            """{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null
        )
        val token = JSONObject(paired.body!!).getJSONObject("result").getString("token")
        val pairingId = store.all().single().id

        val list = core.handle("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", token)
        check("chat: tools/list offers chat_read + chat_post to the paired agent",
            list.body!!.contains("chat_read") && list.body!!.contains("chat_post"), list.body ?: "")

        // Owner writes in the app surface's store; the agent reads
        // it over the channel — the owner→agent delivery leg.
        DataFlows.resetForTest()
        AgentChatStore.append(chatDir, pairingId, AgentChatStore.DIR_OWNER, "hello from owner", 1000L)
        AgentChatStore.append(chatDir, pairingId, AgentChatStore.DIR_OWNER, "second note", 1001L)
        val read1 = JSONObject(resultText(call(core, token, 3, "chat_read", "{}")))
        check("chat transport: agent reads owner messages via chat_read",
            read1.getJSONArray("messages").length() == 2 &&
                read1.getJSONArray("messages").getJSONObject(0).getString("body") == "hello from owner",
            read1.toString())
        check("chat transport: cursor advances to last seq", read1.getLong("next_cursor") == 2L)
        val read2 = JSONObject(resultText(call(core, token, 4, "chat_read", """{"after_seq":2}""")))
        check("chat transport: cursor read returns nothing new (no duplicates)",
            read2.getJSONArray("messages").length() == 0 && read2.getLong("next_cursor") == 2L)
        AgentChatStore.append(chatDir, pairingId, AgentChatStore.DIR_OWNER, "third", 1002L)
        val read3 = JSONObject(resultText(call(core, token, 5, "chat_read", """{"after_seq":2}""")))
        check("chat transport: resume after cursor returns only the new message",
            read3.getJSONArray("messages").length() == 1 &&
                read3.getJSONArray("messages").getJSONObject(0).getLong("seq") == 3L)

        // Agent→device leg: chat_post lands in the owner's thread.
        val post = JSONObject(resultText(call(core, token, 6, "chat_post", """{"body":"hi owner, on it"}""")))
        check("chat transport: chat_post accepted with seq", post.getBoolean("posted") && post.getLong("seq") == 4L)
        val thread = AgentChatStore.load(chatDir, pairingId)
        check("chat transport: posted message is in the owner's thread as agent direction",
            thread.size == 4 && thread.last().direction == AgentChatStore.DIR_AGENT &&
                thread.last().body == "hi owner, on it")
        check("chat transport: agent post does not count Sent (owner messages do)",
            DataFlows.chatSentCount(pairingId) == 3L, "${DataFlows.chatSentCount(pairingId)}")
        val postBlank = resultText(call(core, token, 7, "chat_post", """{"body":"  "}"""))
        check("chat transport: blank post refused", postBlank.contains("refused"))
        val postLong = resultText(call(core, token, 8, "chat_post",
            """{"body":"${"x".repeat(ChatToolHost.MAX_BODY_CHARS + 1)}"}"""))
        check("chat transport: over-limit post refused", postLong.contains("refused"))

        // Isolation: a second pairing cannot read the first thread.
        val code2 = store.beginPairing("Other AI")
        val paired2 = core.handle(
            """{"jsonrpc":"2.0","id":9,"method":"pair","params":{"code":"$code2"}}""", null
        )
        val token2 = JSONObject(paired2.body!!).getJSONObject("result").getString("token")
        val readOther = JSONObject(resultText(call(core, token2, 10, "chat_read", "{}")))
        check("chat transport: another pairing reads only its own (empty) thread",
            readOther.getJSONArray("messages").length() == 0)

        // Unpair ends the thread: token dies AND the file is removed
        // (MainActivity's unpair path), so both legs close.
        AgentChatStore.endThread(chatDir, pairingId)
        store.revoke(token)
        val afterRevoke = core.handle("""{"jsonrpc":"2.0","id":11,"method":"tools/list"}""", token)
        check("chat transport: unpair kills the token (401)", afterRevoke.httpStatus == 401)
        check("chat transport: unpair removed the thread", !AgentChatStore.threadExists(chatDir, pairingId))
        val svc = text("server/ControlService.kt")
        check("chat transport: ControlService wires ChatToolHost on the agent-chat dir",
            svc.contains("ChatToolHost(File(filesDir, \"agent-chat\"), store)"))
        val mcp = text("server/McpCore.kt")
        check("chat transport: chat tools need no capability and are budget/session exempt",
            mcp.contains("\"chat_read\", \"chat_post\", \"chat_ask\" -> null") &&
                mcp.contains("\"chat_read\", \"chat_post\", \"chat_ask\""))

        // ================= Item 2: live MdmService =================
        val noticeFile = File(dir, MdmWiring.NOTICE_FILE_NAME)
        val audit = ChainedAuditLog()
        val service = MdmWiring.build(dir, audit)
        check("mdm wiring: live service starts with no notices (honest empty)",
            service.notices().isEmpty())
        // A notice recorded through the live service is visible
        // live AND persisted to the file the surface falls back to.
        // (Notices enter the list inside executeAction before
        // execution; here we prove the wiring's file binding by
        // round-tripping a second service over the same dir after
        // a direct persist-path exercise via executeAction refusal
        // is impossible without a gate — so instead we verify the
        // notice store file path is the shared one and a fresh
        // service over a pre-written store loads it live.)
        noticeFile.writeText("cmd-1|phone-1|lock_device|Your admin locked this phone|5000\n")
        val service2 = MdmWiring.build(dir, audit)
        check("mdm wiring: service loads the durable notice store live",
            service2.notices() == listOf(
                MdmDeviceNotice("cmd-1", "phone-1", "lock_device", "Your admin locked this phone", 5000L)
            ), "${service2.notices()}")
        check("mdm wiring: live rows render in the surface shape",
            MdmWiring.liveNoticeRows(service2).single()[2] == "lock_device")
        // Absent-source honesty: no facts ⇒ executeAction refuses
        // closed at the policy gate, nothing is executed silently.
        val (outcome, why) = service2.executeAction(
            io.agenticcontrol.app.rmmspine.MdmActionRequest(
                "cmd-2", "phone-1", io.agenticcontrol.app.rmmspine.MdmActionKinds.LOCK,
                noticeText = "locking", issuedMs = 1000L, expiresMs = 2000L
            ), null, "hub", 1500L
        )
        check("mdm wiring: no device facts ⇒ action refuses closed, not executed",
            outcome?.executed == false && why.contains("no device facts"), why)
        val rmmAct = text("RmmNoticesActivity.kt")
        check("mdm wiring: surface prefers the live service, store is fallback",
            rmmAct.contains("ControlService.sharedMdmService") &&
                rmmAct.contains("MdmWiring.liveNoticeRows"))
        check("mdm wiring: ControlService constructs + publishes the live service",
            svc.contains("sharedMdmService = io.agenticcontrol.app.rmmspine.MdmWiring.build") &&
                svc.contains("var sharedMdmService"))

        // ================= Item 3: wizard =================
        check("wizard: model still carries exactly 7 steps",
            SetupWizardModel.STEPS == listOf(
                "role", "transport", "battery", "accessibility", "pair", "access level", "self-check"))
        check("wizard: every segment is labelled (Step N of 7 · name)",
            (0 until 7).all { i ->
                SetupWizardModel.stepSegmentLabel(i) ==
                    "Step ${i + 1} of 7 · ${SetupWizardModel.STEPS[i]}"
            })
        val wiz = text("WizardActivity.kt")
        check("wizard UI: seven step screens exist",
            listOf("renderRole", "renderTransport", "renderBattery", "renderAccessibility",
                "renderPairing", "renderAccess", "renderSelfCheck")
                .all { wiz.contains("fun $it") })
        check("wizard UI: progress renders all 7 labelled segments from the model",
            wiz.contains("SetupWizardModel.STEP_COUNT") && wiz.contains("SetupWizardModel.STEPS[i]") &&
                wiz.contains("SetupWizardModel.stepLabel(active)"))
        check("wizard UI: step order role→transport→battery→accessibility→pair→access→self-check",
            wiz.indexOf("step = Step.TRANSPORT") < wiz.indexOf("step = Step.BATTERY") &&
                wiz.indexOf("step = Step.BATTERY") < wiz.indexOf("step = Step.ACCESSIBILITY") &&
                wiz.indexOf("step = Step.ACCESSIBILITY") < wiz.indexOf("step = Step.PAIR") &&
                wiz.indexOf("step = Step.ACCESS") < wiz.indexOf("step = Step.SELFCHECK"))
        // SAS: a real enrollment-derived phrase renders through the
        // model; the line is bound to the enrollment record.
        val sas = io.agenticcontrol.app.enrollment.PairingSas.compute(
            ByteArray(32) { it.toByte() }, ByteArray(32) { (it + 7).toByte() }, "code-123"
        )!!
        check("wizard SAS: phrase line renders the real derived phrase",
            SetupWizardModel.sasPhraseLine(sas.display).contains(sas.display) &&
                SetupWizardModel.sasPhraseLine(sas.display).startsWith("Safety words:"))
        check("wizard SAS: wizard binds the phrase to THIS pairing's enrollment record (W10 V3-F3a)",
            wiz.contains("PlatformRuntime.peek()") && wiz.contains("enrollment?.all()") &&
                wiz.contains("sasForPairing(target.id, enrolledPairs)") &&
                wiz.contains("SetupWizardModel.sasPhraseLine(boundSas)"))
        check("wizard SAS: name-only check line kept for MCP pairings (no fabricated phrase)",
            wiz.contains("SetupWizardModel.sasCheckLine(displayName(target))"))

        // ================= Item 4: Effective Policy receipts =================
        val engine = ManagementPolicyEngine()
        val facts = StaticDeviceFacts("phone-1", "scope-1")
        engine.addDocument(
            ManagementPolicyDocument(
                "org-doc", PolicyLevels.ORG, "scope-1",
                mapOf("rmm.mdm.enabled" to "true", "custom.key" to "on"), 1
            )
        )
        val rules = EffectivePolicyView.rules(engine, facts)
        // W10 (V3-F4): owner-words sentences + setters supersede
        // the W8 raw-provenance pins. The MDM rule is found by its
        // owner-words sentence (the registry description), never
        // by raw key.
        val mdmRule = rules.first { it.sentence.contains("MDM subset") }
        check("policy receipts: explicit toggle carries its setter in owner words",
            mdmRule.setter == "scope-1 IT", "${mdmRule.setter}")
        check("policy receipts: ruleLine renders the owner-words setter suffix",
            EffectivePolicyModel.ruleLine(mdmRule) ==
                "${mdmRule.sentence} · set by scope-1 IT")
        check("policy receipts: default-OFF toggle turned ON needs attention (W10 V3-F4)",
            mdmRule.needsAttention)
        val defaultRule = rules.first { it.sentence.startsWith("Continuous endpoint health monitoring") }
        check("policy receipts: registry-default rule has NO setter attribution",
            defaultRule.setter == null &&
                !EffectivePolicyModel.ruleLine(defaultRule).contains("set by"))
        val otherRule = rules.first { it.sentence.startsWith("custom.key") }
        check("policy receipts: non-registry setting carries the same owner-words setter",
            otherRule.setter == "scope-1 IT", "${otherRule.setter}")
        val rendered = EffectivePolicyView.render(engine, facts)
        check("policy receipts: render regenerates every rule through ruleLine",
            rules.all { r -> rendered.contains(EffectivePolicyModel.ruleLine(r)) })
        check("policy receipts: floor listed once — in floorText with all 4 items, never in the render body (W10 V3-F4)",
            !rendered.contains("Consent floor") &&
                !rendered.contains("Always on — no one can change this") &&
                EffectivePolicyModel.CONSENT_FLOOR_ITEMS.all {
                    EffectivePolicyView.floorText().contains(it)
                } &&
                !EffectivePolicyView.floorText().contains("set by"))
        // Exception ordering: a default-on toggle set OFF by a doc
        // leads the rendered rules.
        val engine2 = ManagementPolicyEngine()
        engine2.addDocument(
            ManagementPolicyDocument(
                "org-off", PolicyLevels.ORG, "scope-1",
                mapOf("rmm.monitoring.enabled" to "false"), 1
            )
        )
        val rendered2 = EffectivePolicyView.render(engine2, facts)
        val firstRuleLine = rendered2.lines()
            .dropWhile { !it.startsWith("— Rules") }.drop(1).first()
        check("policy receipts: status-by-exception — the switched-off rule leads",
            firstRuleLine.contains("Continuous endpoint health monitoring") &&
                firstRuleLine.contains("off"), firstRuleLine)
        val effAct = text("rmmspine/EffectivePolicyActivity.kt")
        check("policy receipts: Activity regenerates from the bound engine on-device",
            effAct.contains("PolicyGate.engine") && effAct.contains("EffectivePolicyView.render(boundEngine, boundFacts)"))

        // ================= Item 5: OI-13 injection fixtures =================
        val own = "io.agenticcontrol.app"
        check("OI-13 fixture: own package is an ACP window target",
            GateModel.targetIsAcpWindow(own, own))
        check("OI-13 fixture: another package is not refused by this rule",
            !GateModel.targetIsAcpWindow("com.example.other", own))
        check("OI-13 fixture: unknown (null) target is not treated as ACP",
            !GateModel.targetIsAcpWindow(null, own) && !GateModel.targetIsAcpWindow("", own))
        check("OI-13 fixture: gesture path decision refuses ACP target",
            GateModel.agentActionOnAcpWindowRefused(
                GateModel.InjectionPath.GESTURE, GateModel.targetIsAcpWindow(own, own)))
        check("OI-13 fixture: node-action path decision refuses ACP target",
            GateModel.agentActionOnAcpWindowRefused(
                GateModel.InjectionPath.NODE_ACTION, GateModel.targetIsAcpWindow(own, own)))
        check("OI-13 fixture: shell 'input tap' refused (unresolvable target)",
            GateModel.shellInputRefused("input tap 500 500", own))
        check("OI-13 fixture: shell chained input refused",
            GateModel.shellInputRefused("settings get global x; input text hello", own))
        check("OI-13 fixture: shell input swipe/keyevent refused",
            GateModel.shellInputRefused("input swipe 1 2 3 4", own) &&
                GateModel.shellInputRefused("input keyevent 66", own))
        check("OI-13 fixture: shell launch of ACP itself refused",
            GateModel.shellInputRefused("am start -n $own/.MainActivity", own))
        check("OI-13 fixture: ordinary shell work is NOT refused",
            !GateModel.shellInputRefused("settings get global device_name", own) &&
                !GateModel.shellInputRefused("dumpsys battery", own) &&
                !GateModel.shellInputRefused("am start -n com.example.other/.Main", own) &&
                !GateModel.shellInputRefused("logcat -d", own))
        val a11y = text("access/ControlAccessibilityService.kt")
        check("OI-13 fixture: accessibility service consults the guard on gesture + node paths",
            // W15 superseded pin (cause: P1-F2 genuinely overturned
                // — a non-null node can expose a null packageName, so
                // the node/launch action decision is the fail-closed
                // GateModel.nodeTargetRefused, not the bare
                // targetIsAcpWindow classification).
                a11y.contains("GateModel.nodeTargetRefused") &&
                a11y.contains("targetIsOwnWindow(live.packageName") &&
                // W13 superseded pin (cause: P1-F2 — the gesture
                // paths now consult the fail-closed coordinate
                // guard, which refuses an UNKNOWN foreground too;
                // the node paths keep targetIsOwnWindow).
                a11y.contains("GateModel.coordinateTargetRefused(currentAppPackage(), packageName)") &&
                a11y.contains("targetIsOwnWindow(node.packageName"))
        check("OI-13 fixture: service refuses launch of its own package",
            a11y.contains("if (targetIsOwnWindow(packageName)) return false"))
        val shell = text("server/ShellToolHost.kt")
        check("OI-13 fixture: shell host refuses before the gate via the same decision",
            shell.contains("GateModel.shellInputRefused(command, OWN_PACKAGE)") &&
                shell.indexOf("GateModel.shellInputRefused") < shell.indexOf("gate(ApprovalGate.ActionClass.SHELL"))
        check("OI-13 fixture: refusal lines are path-specific and name OI-13",
            GateModel.InjectionPath.values().all {
                GateModel.injectionRefusalLine(it).contains("OI-13")
            })

        DataFlows.resetForTest()
        dir.deleteRecursively()
        println("W8GapsTest: $passes PASS, $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

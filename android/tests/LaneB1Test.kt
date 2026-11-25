import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.rmmspine.*
import io.agenticcontrol.app.server.ApprovalGate
import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.PairingStore
import org.json.JSONObject
import java.io.File

/** Lane B1 (Android security spine): RMM-03 / 15 / 31 / 07 / 08 / 20
 *  JVM suite incl. destruction batteries. Counts from this output. */
private var failures = 0
private var passes = 0
private fun check(n: String, c: Boolean, detail: String = "") {
    if (c) { println("PASS  $n"); passes++ } else { println("FAIL  $n  $detail"); failures++ }
}

private val T0 = 1_800_000_000_000L // fixed clock
private fun identity(seedByte: Int): DeviceIdentity =
    DeviceIdentity.fromSeed(ByteArray(32) { seedByte.toByte() })

private class Fixture {
    val customer = identity(7)
    val attacker = identity(99)
    val ring = CustomerCommandKeyRing().apply { addCurrent(customer.publicKey) }
    val signer = SignedCommandSigner(customer)
    val audit = ChainedAuditLog()
    val nonceFile: File
    val store: PersistedNonceStore
    val gate: SignedCommandGate
    val facts = StaticDeviceFacts("phone-1", "scope-1")
    val engine = ManagementPolicyEngine()
    init {
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-b1-" + System.nanoTime()); dir.mkdirs()
        nonceFile = File(dir, "nonces.json")
        store = PersistedNonceStore(nonceFile)
        gate = SignedCommandGate(SignedCommandVerifier(ring, store), audit)
    }
    fun env(cls: String, payload: String, now: Long = T0, ttl: Long = 600_000, nonce: String, signer: SignedCommandSigner = this.signer) =
        signer.sign(cls, payload.toByteArray(Charsets.UTF_8), now, ttl, nonce)
}

fun main() {
    // ================= RMM-03 =================
    run {
        val f = Fixture()
        val e = f.env(SignedCommandClasses.SHELL_EXEC, "echo hi", nonce = "n1")
        val v = f.gate.authorize(e, T0, SignedCommandClasses.SHELL_EXEC)
        check("R03 valid envelope verifies", v.allowed && String(v.payload!!) == "echo hi")
        check("R03 acceptance audited (chained)", f.audit.entries().any { it.kind == "signed_command_accepted" } && f.audit.verify().first)
        // Destruction: unsigned
        val v2 = f.gate.authorize(null, T0, SignedCommandClasses.SHELL_EXEC)
        check("R03 unsigned refuses + audited", !v2.allowed && f.audit.entries().any { it.kind == "signed_command_refused" })
        // Forged (attacker key, relabelled with customer key id)
        val atkSigner = SignedCommandSigner(f.attacker)
        val forged = atkSigner.sign(SignedCommandClasses.SHELL_EXEC, "rm -rf".toByteArray(), T0, 600_000, "a1")
            .copy(keyId = f.signer.keyId)
        check("R03 forged signature (relabeled key id) refuses", !f.gate.authorize(forged, T0, SignedCommandClasses.SHELL_EXEC).allowed)
        // Payload altered after signing
        val altered = e.copy(payloadBase64 = java.util.Base64.getEncoder().encodeToString("echo pwned".toByteArray()))
        check("R03 payload alteration refuses", !f.gate.authorize(altered, T0, SignedCommandClasses.SHELL_EXEC).allowed)
        // Signature splice: valid sig from another envelope
        val other = f.env(SignedCommandClasses.SHELL_EXEC, "echo other", nonce = "n2")
        val spliced = e.copy(signatureBase64 = other.signatureBase64)
        check("R03 signature splice refuses", !f.gate.authorize(spliced, T0, SignedCommandClasses.SHELL_EXEC).allowed)
        // Class confusion: shell envelope at policy path
        check("R03 cross-path class confusion refuses", !f.gate.authorize(
            f.env(SignedCommandClasses.SHELL_EXEC, "x", nonce = "n3"), T0, SignedCommandClasses.POLICY_DELIVERY).allowed)
        check("R03 unknown class refuses", try {
            SignedCommandSigner(f.customer).sign("wipe_everything", "x".toByteArray(), T0, 1000, "z"); false
        } catch (ex: IllegalArgumentException) { true })
        // Expiry / future / zero lifetime
        check("R03 expired refuses", !f.gate.authorize(f.env(SignedCommandClasses.SHELL_EXEC, "x", now = T0 - 700_000, nonce = "n4"), T0, SignedCommandClasses.SHELL_EXEC).allowed)
        check("R03 future-dated refuses", !f.gate.authorize(f.env(SignedCommandClasses.SHELL_EXEC, "x", now = T0 + 400_000, nonce = "n5"), T0, SignedCommandClasses.SHELL_EXEC).allowed)
        // Replay (same envelope twice)
        val r = f.env(SignedCommandClasses.SHELL_EXEC, "echo once", nonce = "n6")
        val first = f.gate.authorize(r, T0, SignedCommandClasses.SHELL_EXEC)
        val second = f.gate.authorize(r, T0, SignedCommandClasses.SHELL_EXEC)
        check("R03 replay refuses", first.allowed && !second.allowed && second.reason.contains("replay"))
        // Replay ACROSS RESTART (persisted store rebuilt over same file)
        val store2 = PersistedNonceStore(f.nonceFile)
        val gate2 = SignedCommandGate(SignedCommandVerifier(f.ring, store2), ChainedAuditLog())
        check("R03 replay across restart refuses (persisted nonce store)", !gate2.authorize(r, T0, SignedCommandClasses.SHELL_EXEC).allowed)
        check("R03 persisted store loaded state named", store2.state.startsWith("loaded"))
        // Corrupt store = fail closed for EVERY registration
        f.nonceFile.writeText("garbage{{{")
        val broken = PersistedNonceStore(f.nonceFile)
        val gateB = SignedCommandGate(SignedCommandVerifier(f.ring, broken), ChainedAuditLog())
        check("R03 corrupt nonce store refuses even fresh valid commands (fail closed)",
            broken.broken && !gateB.authorize(f.env(SignedCommandClasses.SHELL_EXEC, "x", nonce = "n7"), T0, SignedCommandClasses.SHELL_EXEC).allowed)
        // Payload binding (background_action names the tool)
        val bg = f.env(SignedCommandClasses.BACKGROUND_ACTION, "tool=tap", nonce = "n8")
        check("R03 payload binding: wrong payload refuses", !f.gate.authorize(bg, T0, SignedCommandClasses.BACKGROUND_ACTION, "tool=swipe".toByteArray()).allowed)
        check("R03 payload binding: right payload verifies", f.gate.authorize(
            f.env(SignedCommandClasses.BACKGROUND_ACTION, "tool=tap", nonce = "n9"), T0, SignedCommandClasses.BACKGROUND_ACTION, "tool=tap".toByteArray()).allowed)
        // Retired key past grace
        val f2 = Fixture()
        val oldEnv = f2.env(SignedCommandClasses.SHELL_EXEC, "x", nonce = "r1")
        f2.ring.rotate(f2.attacker.publicKey, T0, 60_000)
        check("R03 retired key verifies within grace", f2.gate.authorize(oldEnv, T0 + 30_000, SignedCommandClasses.SHELL_EXEC).allowed)
        val oldEnv2 = f2.env(SignedCommandClasses.SHELL_EXEC, "x", nonce = "r2")
        check("R03 retired key past grace refuses", !f2.gate.authorize(oldEnv2, T0 + 120_000, SignedCommandClasses.SHELL_EXEC).allowed)
        // Key-id derivation binds id to material
        check("R03 key id derived from key material", CustomerCommandKeyRing.keyIdFor(f.customer.publicKey) == f.signer.keyId &&
            CustomerCommandKeyRing.keyIdFor(f.attacker.publicKey) != f.signer.keyId)
    }
    // McpCore wiring: gate in front of tool execution
    run {
        val f = Fixture()
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-b1-mcp-" + System.nanoTime()); dir.mkdirs()
        val store = PairingStore(File(dir, "pairings.tsv"))
        var shellRan: String? = null
        val host = object : McpCore.ToolHost {
            override fun tools(): List<McpCore.ToolDef> = listOf(
                McpCore.ToolDef("shell_exec", "fake shell", "drive", JSONObject().put("type", "object"),
                    run = { a -> shellRan = a.optString("command", ""); "ran: ${a.optString("command", "")}" }),
                McpCore.ToolDef("device_info", "fake info", "observe", JSONObject().put("type", "object"),
                    run = { "{\"model\":\"TestPhone\"}" })
            )
        }
        val core = McpCore(store, host, "test", f.gate) { T0 }
        check("R03 McpCore gate state names WIRED", core.commandGateState.startsWith("WIRED"))
        check("R03 McpCore unwired state named honestly", McpCore(store, host).commandGateState.startsWith("UNWIRED"))
        val code = store.beginPairing("tester")
        val pairReply = core.handle("""{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null)
        val token = JSONObject(pairReply.body!!).getJSONObject("result").getString("token")
        store.setAccess(token, PairingStore.ACCESS_FULL, emptySet()) // owner raises access (SPEC §5.3) — shell cap included
        fun call(tool: String, args: JSONObject, id: Int): Pair<Boolean, String> {
            val body = JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", "tools/call")
                .put("params", JSONObject().put("name", tool).put("arguments", args)).toString()
            val reply = core.handle(body, token)
            val result = JSONObject(reply.body!!).getJSONObject("result")
            return result.getBoolean("isError") to result.getJSONArray("content").getJSONObject(0).getString("text")
        }
        // REPAIRED by laneW2-andfix1 (bd-and-core F1, 2026-11-22),
        // disclosed: the old assertion pinned the pre-fix scope in
        // which EVERY tools/call needed an envelope — the behaviour
        // the breakdown proved made locally paired control
        // dead on arrival. New law (McpCore KDoc): the gate governs
        // calls that PRESENT an envelope; an envelope-less call from
        // a code-paired full-access token runs under pairing +
        // capability + approval-gate authority. The envelope checks
        // below (payload runs instead of the arg, replay refuses,
        // cross-tool binding refuses) are unchanged and still pin
        // the gate where it applies.
        val (errUnsigned, _) = call("shell_exec", JSONObject().put("command", "echo unsigned"), 2)
        check("R03 McpCore: envelope-less locally-paired call runs under pairing authority (bd-and-core F1 scope)",
            !errUnsigned && shellRan == "echo unsigned")
        val env = f.env(SignedCommandClasses.SHELL_EXEC, "echo signed", nonce = "m1")
        val (errSigned, text) = call("shell_exec",
            JSONObject().put("command", "echo UNSIGNED-ARG").put("_signed_command", env.toJson()), 3)
        check("R03 McpCore: signed shell executes the ENVELOPE payload, never the unsigned arg",
            !errSigned && shellRan == "echo signed" && text.contains("echo signed"))
        val (errReplay, _) = call("shell_exec", JSONObject().put("_signed_command", env.toJson()), 4)
        check("R03 McpCore: replayed envelope refuses", errReplay)
        val bgEnv = f.env(SignedCommandClasses.BACKGROUND_ACTION, "tool=device_info", nonce = "m2")
        val (errBg, _) = call("device_info", JSONObject().put("_signed_command", bgEnv.toJson()), 5)
        check("R03 McpCore: background_action envelope executes named tool", !errBg)
        val bgWrong = f.env(SignedCommandClasses.BACKGROUND_ACTION, "tool=shell_exec", nonce = "m3")
        val (errWrong, _) = call("device_info", JSONObject().put("_signed_command", bgWrong.toJson()), 6)
        check("R03 McpCore: envelope minted for another tool refuses (payload binding)", errWrong)
    }

    // ================= RMM-15 =================
    run {
        val f = Fixture()
        val journal = JobJournal(identity(42), identity(42).publicKey)
        val env = f.env(SignedCommandClasses.SCRIPT_EXEC, "chain", nonce = "j1")
        val steps = listOf(JobStepDefinition("s1", "one", true), JobStepDefinition("s2", "two", false), JobStepDefinition("s3", "three", true))
        val job = journal.createJob("job1", JobKinds.SCRIPT_CHAIN, "phone-1", steps, env, T0)
        check("R15 job created under signed envelope", job != null && job.state == JobStates.PENDING)
        check("R15 unsigned signed-kind job refuses", journal.createJob("jobX", JobKinds.SCRIPT_CHAIN, "phone-1", steps, null, T0) == null)
        check("R15 wrong-class envelope refuses", journal.createJob("jobY", JobKinds.PATCH_RUN, "phone-1", steps, env, T0) == null)
        check("R15 duplicate steps refuse", journal.createJob("jobZ", JobKinds.FILE_TRANSFER, "phone-1",
            listOf(JobStepDefinition("s", "a", true), JobStepDefinition("s", "b", true)), null, T0) == null)
        journal.startJob("job1", T0); journal.beginStep("job1", "s1", T0); journal.completeStep("job1", "s1", T0)
        journal.beginStep("job1", "s2", T0) // non-idempotent mid-flight at "crash"
        val exported = journal.exportJson()
        val restored = JobJournal(null, identity(42).publicKey)
        val ver = restored.importJson(exported)
        check("R15 export/import chain verifies (signed entries)", ver.ok)
        val rep = restored.resumeAll(T0 + 1000, true, f.ring)
        val parked = restored.getJob("job1")
        check("R15 non-idempotent crashed step PARKS for a human", parked?.state == JobStates.PARKED &&
            parked.steps.first { it.stepId == "s2" }.state == StepStates.UNCERTAIN)
        check("R15 parked job cannot be force-started", !restored.startJob("job1", T0 + 2000))
        check("R15 human retry decision resumes parked job", restored.resolveParked("job1", ParkedDecision.RETRY_STEP, "tech-1", T0 + 3000) &&
            restored.getJob("job1")?.state == JobStates.RESUMED)
        check("R15 unattributed human decision refuses", !restored.resolveParked("job1", ParkedDecision.SKIP_STEP, "", T0 + 3000))
        // Idempotent crash resets
        val j2 = JobJournal()
        j2.createJob("job2", JobKinds.FILE_TRANSFER, "phone-1", listOf(JobStepDefinition("a", "a", true)), null, T0)
        j2.startJob("job2", T0); j2.beginStep("job2", "a", T0)
        val rep2 = j2.resumeAll(T0 + 1000, true)
        check("R15 idempotent crashed step resets to pending + resumed",
            j2.getJob("job2")?.state == JobStates.RESUMED && j2.getJob("job2")!!.steps[0].state == StepStates.PENDING &&
            rep2.outcomes.any { it.outcome == "resumed" })
        // Toggle OFF
        val j3 = JobJournal()
        j3.createJob("job3", JobKinds.FILE_TRANSFER, "phone-1", listOf(JobStepDefinition("a", "a", true)), null, T0)
        j3.resumeAll(T0, false)
        check("R15 resume toggle OFF fails resume_disabled", j3.getJob("job3")?.failureReason == JobFailureReasons.RESUME_DISABLED)
        // Expired envelope mid-outage
        val j4 = JobJournal()
        val shortEnv = f.env(SignedCommandClasses.SCRIPT_EXEC, "chain", ttl = 60_000, nonce = "j2")
        j4.createJob("job4", JobKinds.SCRIPT_CHAIN, "phone-1", listOf(JobStepDefinition("a", "a", true)), shortEnv, T0)
        j4.startJob("job4", T0)
        j4.resumeAll(T0 + 120_000, true, f.ring)
        check("R15 envelope expired mid-outage fails authority_expired", j4.getJob("job4")?.failureReason == JobFailureReasons.AUTHORITY_EXPIRED)
        // Tamper: single edit breaks chain; resume fails everything journal_tampered
        val j5 = JobJournal()
        j5.createJob("job5", JobKinds.FILE_TRANSFER, "phone-1", listOf(JobStepDefinition("a", "a", true)), null, T0)
        val tampered = j5.exportJson().replace("job_created", "job_hacked!")
        val j5b = JobJournal(); val v5 = j5b.importJson(tampered)
        j5b.resumeAll(T0, true)
        check("R15 tampered journal: import names BROKEN, resume resumes nothing",
            !v5.ok && j5b.getJob("job5")?.state != JobStates.RESUMED)
        // Forged job_done over unfinished steps (recomputed chain, unsigned journal) — replay guard:
        // with a SIGNED journal the recompute fails signature check:
        val j6 = JobJournal(identity(43), identity(43).publicKey)
        j6.createJob("job6", JobKinds.FILE_TRANSFER, "phone-1", listOf(JobStepDefinition("a", "a", true)), null, T0)
        val forgedExport = JSONObject(j6.exportJson()).also { root ->
            val entries = root.getJSONArray("entries")
            entries.put(JSONObject().put("seq", 2L).put("jobId", "job6").put("atMs", T0).put("kind", "job_done")
                .put("detail", "all steps done/skipped").put("prevHash", entries.getJSONObject(0).getString("hash"))
                .put("hash", "deadbeef").put("signatureBase64", JSONObject.NULL))
        }.toString()
        val j6b = JobJournal(null, identity(43).publicKey)
        check("R15 forged appended job_done on signed journal refuses at import", !j6b.importJson(forgedExport).ok)
        // Persistence round-trip via file
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-b1-j-" + System.nanoTime()); dir.mkdirs()
        val jf = File(dir, "journal.json"); j2.saveToFile(jf)
        val j7 = JobJournal(); val v7 = j7.loadFromFile(jf)
        check("R15 file persistence round-trip", v7.ok && j7.getJob("job2") != null)
        check("R15 state report carries head + toggle", j2.buildStateReport("phone-1", true, T0).let {
            it.journalHeadHash == j2.headHash && it.resumeEnabled && it.jobs.size == 1 })
        check("R15 never-started job stays honestly pending on resume", run {
            val j8 = JobJournal(); j8.createJob("job8", JobKinds.FILE_TRANSFER, "phone-1", listOf(JobStepDefinition("a", "a", true)), null, T0)
            val r = j8.resumeAll(T0, true); r.outcomes.any { it.outcome == "pending" } && j8.getJob("job8")?.state == JobStates.PENDING })
    }

    // ================= RMM-07 =================
    run {
        val f = Fixture()
        val engine = ManagementPolicyEngine()
        check("R07 registry seeded with the rmm.* catalogue (44 toggles, W12-DS P7-F6 added browser_hardening + mobile_operator; W20 mirror added tor_provisioning + aipack_download)", engine.registry.all().size == 44, // 36 catalogue + U4's session-budget toggle + U1's clipboard-policy toggle (UNION BUILD lanes U4/U1, 2026-11-22) + bd-and-rmm F2's rmm.probes.enabled + rmm.vault_surfacing.enabled (laneW2-andfix1, 2026-11-22 — keys the module code always named but the registry never carried; updated per the same registry-growth precedent) + W19-C's rmm.tor_provisioning.enabled + rmm.aipack_download.enabled mirrored from the Windows catalogue in W20 (laneW20-andmirror, 2026-11-23 — Windows reached 42 with those two; Android's 44 is the full Windows catalogue PLUS the two Android F2 keys Windows does not carry)
            "got ${engine.registry.all().size}")
        check("R07 W20 mirror: tor_provisioning + aipack_download registered, both default ON as on Windows",
            engine.registry.get("rmm.tor_provisioning.enabled")?.defaultEnabled == true &&
                engine.registry.get("rmm.aipack_download.enabled")?.defaultEnabled == true)
        check("R07 rmm.mdm.enabled defaults OFF per registry", engine.registry.get("rmm.mdm.enabled")?.defaultEnabled == false)
        check("R07 consent-floor key cannot be registered", try {
            FeatureToggleRegistry().register(FeatureToggle("rmm.presence.enabled", "X", true, "x")); false
        } catch (ex: IllegalStateException) { true })
        // Inheritance + provenance + revert
        engine.addGroup(GroupDefinition("g1", "Group 1", emptyList()))
        engine.addDocument(ManagementPolicyDocument("org1", PolicyLevels.ORG, "scope-1",
            mapOf("rmm.remediation.enabled" to "true", "feature.x" to "org"), 1))
        engine.addDocument(ManagementPolicyDocument("grp1", PolicyLevels.GROUP, "g1", mapOf("feature.x" to "group"), 1))
        engine.addDocument(ManagementPolicyDocument("dev1", PolicyLevels.DEVICE, "phone-1", mapOf("feature.x" to "device"), 1))
        val factsG = StaticDeviceFacts("phone-1", "scope-1", directGroupIds = setOf("g1"))
        check("R07 device overrides group overrides org, provenance kept",
            engine.computeEffective(factsG).get("feature.x")?.let { it.value == "device" && it.sourceDocumentId == "dev1" } == true)
        engine.addDocument(ManagementPolicyDocument("dev1", PolicyLevels.DEVICE, "phone-1",
            mapOf("feature.x" to ManagementPolicyDocument.INHERIT_MARKER), 2))
        check("R07 revert-to-inherited shows group value + provenance",
            engine.computeEffective(factsG).get("feature.x")?.let { it.value == "group" && it.sourceDocumentId == "grp1" } == true)
        check("R07 cross-device doc does not leak", engine.computeEffective(StaticDeviceFacts("phone-2", "scope-1")).get("feature.x")?.value == "org")
        // Dynamic targeting
        engine.addGroup(GroupDefinition("dyn", "dyn", listOf(GroupRule("attribute_equals", "site", "site-one"))))
        engine.addDocument(ManagementPolicyDocument("dyn1", PolicyLevels.GROUP, "dyn", mapOf("feature.y" to "yes"), 1))
        val factsDyn = StaticDeviceFacts("phone-9", "scope-1", attributes = mapOf("site" to "site-one"))
        check("R07 dynamic group membership by attribute", engine.computeEffective(factsDyn).get("feature.y")?.value == "yes")
        engine.addGroup(GroupDefinition("bad", "bad", listOf(GroupRule("teleport", null, "x"))))
        check("R07 unknown rule kind matches nothing (fail closed)", !engine.memberGroupIds(factsDyn).contains("bad"))
        // IsEnabled semantics
        check("R07 IsEnabled: unknown key false", !engine.isEnabled(factsG, "rmm.nope.enabled"))
        check("R07 IsEnabled: floor key false always", !engine.isEnabled(factsG, "presence.enabled") && !engine.isEnabled(factsG, "rmm.stop.enabled"))
        engine.addDocument(ManagementPolicyDocument("org2", PolicyLevels.ORG, "scope-1", mapOf("rmm.runbooks.enabled" to "banana"), 1))
        check("R07 IsEnabled: unparsable explicit value refuses (false)", !engine.isEnabled(factsG, "rmm.runbooks.enabled"))
        // Consent-floor document refuses WHOLE, incl. segment smuggling
        val floorDoc = ManagementPolicyDocument("evil", PolicyLevels.ORG, "scope-1",
            mapOf("rmm.ok.enabled" to "true", "x.audit.y" to "false"), 1)
        check("R07 floor segment smuggling refuses whole document", !engine.addDocument(floorDoc).allowed &&
            engine.documents().none { it.id == "evil" })
        // Post-admission mutation (the Windows BREAK 1 regression)
        val mutable = mutableMapOf("feature.z" to "before")
        engine.addDocument(ManagementPolicyDocument("mut", PolicyLevels.ORG, "scope-1", mutable, 1))
        mutable["feature.z"] = "after"; mutable["presence.enabled"] = "false"
        check("R07 post-admission mutation cannot change live policy",
            engine.computeEffective(factsG).get("feature.z")?.value == "before" && engine.computeEffective(factsG).get("presence.enabled") == null)
        // Revision discipline
        check("R07 stale revision refuses", !engine.addDocument(
            ManagementPolicyDocument("org1", PolicyLevels.ORG, "scope-1", mapOf("a" to "b"), 0)).allowed)
        check("R07 same-revision conflict refuses", !engine.addDocument(
            ManagementPolicyDocument("org1", PolicyLevels.ORG, "scope-1", mapOf("different" to "content"), 1)).allowed)
        // Signed receipt path: verified BEFORE parse; floor doc signed still refuses
        val receipt = ManagementPolicyReceipt(engine, f.gate, f.audit)
        val doc = ManagementPolicyDocument("signed1", PolicyLevels.ORG, "scope-1", mapOf("rmm.camera_viewing.enabled" to "true"), 1)
        val envOk = f.env(SignedCommandClasses.POLICY_DELIVERY, doc.toCanonicalJson(), nonce = "p1")
        check("R07 signed policy delivery applies", receipt.applySignedDocument(envOk, "hub", T0).allowed &&
            engine.isEnabled(factsG, "rmm.camera_viewing.enabled"))
        val floorSigned = ManagementPolicyDocument("signedfloor", PolicyLevels.ORG, "scope-1", mapOf("stop.enabled" to "false"), 1)
        val envFloor = f.env(SignedCommandClasses.POLICY_DELIVERY, floorSigned.toCanonicalJson(), nonce = "p2")
        check("R07 validly SIGNED floor document still refuses (signature ≠ permission)",
            !receipt.applySignedDocument(envFloor, "hub", T0).allowed)
        val receiptNoGate = ManagementPolicyReceipt(engine, null, f.audit)
        check("R07 no-gate receipt refuses by name", !receiptNoGate.applySignedDocument(envOk, "hub", T0).allowed)
        // Effective Policy view — W10 (V3-F4) supersedes the raw
        // rendering pin: owner-words toggle sentences, provenance
        // in owner words, and the floor listed ONCE via floorText
        // (all four items), never inside the render body.
        val view = EffectivePolicyView.render(engine, factsG)
        check("R07 Effective Policy view: owner-words toggles + provenance, floor separate",
            view.contains("MDM subset") && view.contains("set by scope-1 IT") &&
                !view.contains("Consent floor") &&
                io.agenticcontrol.app.design.EffectivePolicyModel.CONSENT_FLOOR_ITEMS.all {
                    EffectivePolicyView.floorText().contains(it)
                })
        val dir = File(System.getProperty("java.io.tmpdir"), "acp-b1-ep-" + System.nanoTime()); dir.mkdirs()
        val epStore = EffectivePolicyStore(File(dir, "effective-policy.txt"))
        epStore.save(view)
        check("R07 Effective Policy store round-trip for the on-device view", epStore.load() == view)
    }

    // ================= RMM-31 =================
    run {
        val f = Fixture()
        // Enable MDM via policy for the fixture device
        f.engine.addDocument(ManagementPolicyDocument("mdm-on", PolicyLevels.ORG, "scope-1", mapOf("rmm.mdm.enabled" to "true"), 1))
        val factsFor = { id: String -> if (id == "phone-1") f.facts else null }
        val exec = RecordingMdmActionExecutor()
        val limiterFile = File(System.getProperty("java.io.tmpdir"), "acp-b1-loc-" + System.nanoTime() + ".txt")
        val svc = MdmService(f.engine, f.gate, exec, f.audit, factsFor, LocateRateLimiter(limiterFile))
        val personal = MdmDeviceState("phone-1", "scope-1", "android", MdmOwnership.PERSONAL, "16", true, "pin_pattern", "0.4.9", reportedMs = T0)
        check("R31 state report accepted (personal, honest tiers)", svc.reportState(personal, "endpoint", T0).first != null)
        val verdicts = svc.evaluateCompliance("phone-1", "hub", T0).first!!
        check("R31 personal encryption reads DETECTED compliant, never enforced",
            verdicts.first { it.restrictionId == "require_encryption" }.outcome == MdmComplianceOutcomes.DETECTED_COMPLIANT)
        check("R31 personal kiosk reads IMPOSSIBLE, never satisfied",
            verdicts.first { it.restrictionId == "kiosk_mode" }.let { it.outcome == MdmComplianceOutcomes.IMPOSSIBLE_NOT_APPLICABLE && !it.isSatisfied })
        // Capability inflation: personal device claiming kiosk applied refuses whole
        val inflated = personal.copy(appliedRestrictions = listOf("kiosk_mode"))
        val svc2 = MdmService(f.engine, f.gate, exec, f.audit, factsFor, LocateRateLimiter())
        check("R31 capability inflation refuses whole report, nothing stored",
            svc2.reportState(inflated, "endpoint", T0).first == null && svc2.stateFor("phone-1") == null)
        // Stale state → UNKNOWN
        val stale = personal.copy(reportedMs = T0 - 25 * 3600_000L)
        check("R31 stale state compliance is UNKNOWN", MdmComplianceEvaluator.evaluate(
            MdmRestrictions.forId("require_encryption")!!, stale, T0).outcome == MdmComplianceOutcomes.UNKNOWN_STALE_STATE)
        // Action wall: lock happy path (notice BEFORE execution)
        fun mdmEnv(req: MdmActionRequest, nonce: String) =
            f.env(SignedCommandClasses.BACKGROUND_ACTION, req.canonicalPayload(), nonce = nonce)
        val lock = MdmActionRequest("c1", "phone-1", MdmActionKinds.LOCK, noticeText = "Locked by your IT admin", issuedMs = T0, expiresMs = T0 + 600_000)
        val (out1, _) = svc.executeAction(lock, mdmEnv(lock, "d1"), "hub", T0)
        check("R31 lock executes under signed command; notice recorded", out1?.executed == true && svc.notices().any { it.commandId == "c1" })
        // Silent action (no notice) refuses, no execution
        val silent = lock.copy(commandId = "c2", noticeText = "")
        val execCountBefore = exec.executed.size
        check("R31 silent action (empty notice) refuses, nothing executes",
            svc.executeAction(silent, mdmEnv(silent, "d2"), "hub", T0).first?.executed == false && exec.executed.size == execCountBefore)
        // Unsigned refuses
        check("R31 unsigned action refuses", svc.executeAction(lock.copy(commandId = "c3"), null, "hub", T0).first?.executed == false)
        // Signature swap: lock signature presented for a wipe
        val wipe = MdmActionRequest("c4", "phone-1", MdmActionKinds.WIPE_ACP_DATA, listOf(AcpWipeTargets.CACHE), "Wiping ACP cache", T0, T0 + 600_000)
        check("R31 signature swap (lock sig for wipe) refuses via payload binding",
            svc.executeAction(wipe, mdmEnv(lock, "d3"), "hub", T0).first?.executed == false)
        // Wipe scope creep
        val creep = wipe.copy(commandId = "c5", wipeTargets = listOf("user_photos"))
        check("R31 wipe scope creep refuses at validation", svc.executeAction(creep, mdmEnv(creep, "d4"), "hub", T0).first?.executed == false)
        check("R31 wipe targets on a lock refuse", svc.executeAction(
            lock.copy(commandId = "c6", wipeTargets = listOf(AcpWipeTargets.CACHE)), null, "hub", T0).first?.executed == false)
        // Full wipe on personal: refused, never substituted
        val fullWipe = MdmActionRequest("c7", "phone-1", MdmActionKinds.WIPE_FULL_DEVICE, noticeText = "Full wipe ordered", issuedMs = T0, expiresMs = T0 + 600_000)
        val (outFw, fwReason) = svc.executeAction(fullWipe, mdmEnv(fullWipe, "d5"), "hub", T0)
        check("R31 full wipe on personal device refuses, never substituted",
            outFw?.executed == false && fwReason.contains("never substituted") && exec.executed.none { it.kind == MdmActionKinds.WIPE_FULL_DEVICE })
        // Passcode reset on personal (impossible tier) refuses
        val pwr = MdmActionRequest("c8", "phone-1", MdmActionKinds.PASSCODE_RESET, noticeText = "Passcode reset ordered", issuedMs = T0, expiresMs = T0 + 600_000)
        check("R31 passcode reset on personal refuses (enforce-tier only)",
            svc.executeAction(pwr, mdmEnv(pwr, "d6"), "hub", T0).first?.executed == false)
        // Over-long TTL refuses (freshness cap)
        val stale_cmd = lock.copy(commandId = "c9", expiresMs = T0 + 3600_000)
        check("R31 over-long TTL refuses (15-min freshness cap)",
            svc.executeAction(stale_cmd, mdmEnv(stale_cmd, "d7"), "hub", T0).first?.executed == false)
        // Replay of the same MDM envelope refuses
        check("R31 replayed MDM envelope refuses", svc.executeAction(lock, mdmEnv(lock, "d1"), "hub", T0).first?.executed == false)
        // Locate-once: rate limit + daily cap; no continuous kind exists
        check("R31 continuous tracking has NO kind (structural)", MdmActionKinds.ALL.none { it.contains("track") || it.contains("continuous") || it.contains("geofence") })
        val limiter = LocateRateLimiter()
        var allowedCount = 0
        for (i in 0 until 10) { if (limiter.tryAcquire("phone-1", T0 + i * 16 * 60_000L, 15 * 60_000L, 6).first) allowedCount++ }
        check("R31 locate daily cap holds at 6", allowedCount == 6, "allowed=$allowedCount")
        val limiter2 = LocateRateLimiter()
        limiter2.tryAcquire("phone-1", T0, 15 * 60_000L, 6)
        check("R31 locate minimum interval holds", !limiter2.tryAcquire("phone-1", T0 + 60_000, 15 * 60_000L, 6).first)
        // Policy OFF refuses everything
        val fOff = Fixture()
        val svcOff = MdmService(fOff.engine, fOff.gate, exec, fOff.audit, { fOff.facts }, LocateRateLimiter())
        check("R31 policy OFF (registry default) refuses state + actions",
            svcOff.reportState(personal, "endpoint", T0).first == null)
        // Unavailable executor: validated + noticed, NOT executed
        val svcUn = MdmService(f.engine, f.gate, UnavailableMdmActionExecutor(), f.audit, factsFor, LocateRateLimiter())
        svcUn.reportState(personal, "endpoint", T0)
        val lockU = lock.copy(commandId = "cU")
        val (outU, _) = svcUn.executeAction(lockU, f.env(SignedCommandClasses.BACKGROUND_ACTION, lockU.canonicalPayload(), nonce = "dU"), "hub", T0)
        check("R31 unavailable executor reports NOT executed while notice still records",
            outU?.executed == false && svcUn.notices().any { it.commandId == "cU" })
    }

    // ================= RMM-08 =================
    run {
        val f = Fixture()
        val journal = JobJournal()
        val exec = RecordingRemediationExecutor()
        val svc = RemediationService(f.engine, f.gate, exec, journal, f.audit)
        fun remEnv(action: String, runId: String, nonce: String) =
            f.env(SignedCommandClasses.AUTOMATION, RemediationActions.canonicalPayload(action, "phone-1", runId), nonce = nonce)
        val out = svc.execute(RemediationActions.CLEAR_ACP_CACHE, "phone-1", "run1", "", remEnv(RemediationActions.CLEAR_ACP_CACHE, "run1", "e1"), f.facts, "hub", T0)
        check("R08 signed remediation executes + journal job done", out.executed &&
            journal.getJob("remediation-run1")?.state == JobStates.DONE)
        check("R08 unknown action refuses (closed catalogue)", !svc.execute("wipe_everything", "phone-1", "run2", "", null, f.facts, "hub", T0).executed)
        check("R08 unsigned remediation refuses, nothing performs", run {
            val before = exec.performed.size
            !svc.execute(RemediationActions.CLEAR_ACP_CACHE, "phone-1", "run3", "", null, f.facts, "hub", T0).executed && exec.performed.size == before })
        check("R08 envelope minted for another action refuses (payload binding)",
            !svc.execute(RemediationActions.RESTART_ACP_COMPONENTS, "phone-1", "run4", "",
                remEnv(RemediationActions.CLEAR_ACP_CACHE, "run4", "e2"), f.facts, "hub", T0).executed)
        // Policy kill switch
        f.engine.addDocument(ManagementPolicyDocument("rem-off", PolicyLevels.ORG, "scope-1", mapOf("rmm.remediation.enabled" to "false"), 1))
        check("R08 policy OFF refuses (kill switch)", !svc.execute(RemediationActions.CLEAR_ACP_CACHE, "phone-1", "run5", "",
            remEnv(RemediationActions.CLEAR_ACP_CACHE, "run5", "e3"), f.facts, "hub", T0).executed)
        // Failed action journals FAILED honestly
        val f2 = Fixture(); val j2 = JobJournal(); val ex2 = RecordingRemediationExecutor().apply { failActions = setOf(RemediationActions.CLEAR_ACP_CACHE) }
        val svc2 = RemediationService(f2.engine, f2.gate, ex2, j2, f2.audit)
        val out2 = svc2.execute(RemediationActions.CLEAR_ACP_CACHE, "phone-1", "runF", "",
            f2.env(SignedCommandClasses.AUTOMATION, RemediationActions.canonicalPayload(RemediationActions.CLEAR_ACP_CACHE, "phone-1", "runF"), nonce = "e4"), f2.facts, "hub", T0)
        check("R08 executor failure journals FAILED, outcome honest", !out2.executed && j2.getJob("remediation-runF")?.state == JobStates.FAILED)
        check("R08 rerun_failed_acp_job is the non-idempotent catalogue entry", !RemediationActions.isIdempotent(RemediationActions.RERUN_FAILED_ACP_JOB))
    }

    // ================= RMM-20 =================
    run {
        val f = Fixture()
        val journal = JobJournal()
        val remExec = RecordingRemediationExecutor()
        val remSvc = RemediationService(f.engine, f.gate, remExec, journal, f.audit)
        val checks = RecordingRunbookCheckEvaluator(mapOf(RunbookChecks.ACP_RUNNING to true))
        val tools = RecordingRunbookToolExecutor()
        val svc = RunbookService(f.engine, f.gate, checks, tools, journal, f.audit,
            approvalPolicyFor = { ApprovalGate.Policy.AUTO })
        svc.setRemediationStepExecutor { action, device, _, _ -> remExec.perform(action, device, "") }
        val def = RunbookDefinition("monthly-maintenance-android", "Monthly maintenance (Android)", 1, listOf(
            RunbookStep("chk", RunbookStepKinds.CHECK, RunbookChecks.ACP_RUNNING),
            RunbookStep("cache", RunbookStepKinds.REMEDIATION, RemediationActions.CLEAR_ACP_CACHE),
            RunbookStep("sign", RunbookStepKinds.HUMAN_CONFIRMATION, "", prompt = "Confirm the site paperwork matches", requireDistinctAttester = true)
        ))
        check("R20 runbook admits", svc.admit(def).first)
        check("R20 step outside Android catalogue refuses at admission", !svc.admit(
            RunbookDefinition("bad", "bad", 1, listOf(RunbookStep("s", RunbookStepKinds.REMEDIATION, "restart_windows_service")))).first)
        check("R20 script-carrying step is unrepresentable (closed kinds)", !svc.admit(
            RunbookDefinition("bad2", "bad2", 1, listOf(RunbookStep("s", "run_script", "rm -rf")))).first)
        fun rbEnv(runId: String, nonce: String) = f.env(SignedCommandClasses.BACKGROUND_ACTION,
            RunbookDefinition.canonicalPayload(def.id, "phone-1", runId), nonce = nonce)
        val (run1, _) = svc.startRun(def.id, "phone-1", "rb1", "tech-1", f.facts, rbEnv("rb1", "f1"), T0)
        check("R20 run pauses at human confirmation after automated steps", run1?.status == "paused_awaiting_attestation" &&
            svc.getRun("rb1")!!.records.first { it.stepId == "cache" }.state == StepStates.DONE)
        check("R20 self-attestation refused (distinct attester)", !svc.attest("rb1", "sign", "tech-1", T0).first)
        val (attOk, _) = svc.attest("rb1", "sign", "tech-2", T0)
        check("R20 distinct attestation completes the run", attOk && svc.getRun("rb1")?.status == "succeeded")
        check("R20 unsigned run refuses", svc.startRun(def.id, "phone-1", "rb2", "tech-1", f.facts, null, T0).first == null)
        // Approval gate: ASK with no decision parks; self-approval refuses; named approver completes
        val svcAsk = RunbookService(f.engine, f.gate, checks, tools, journal, f.audit,
            approvalPolicyFor = { ApprovalGate.Policy.ASK_FIRST }, approvalDecision = { _, _ -> false })
        svcAsk.setRemediationStepExecutor { a, d, _, _ -> remExec.perform(a, d, "") }
        val defGated = RunbookDefinition("gated", "Gated", 1, listOf(
            RunbookStep("rst", RunbookStepKinds.REMEDIATION, RemediationActions.RESTART_ACP_COMPONENTS, requiresApproval = true)))
        svcAsk.admit(defGated)
        val (runG, _) = svcAsk.startRun("gated", "phone-1", "rbG", "tech-1", f.facts,
            f.env(SignedCommandClasses.BACKGROUND_ACTION, RunbookDefinition.canonicalPayload("gated", "phone-1", "rbG"), nonce = "f2"), T0)
        check("R20 approval gate parks the run (ApprovalGate ASK)", runG?.status == "paused_awaiting_approval")
        check("R20 resume does NOT skip the approval gate", svcAsk.resumeRun("rbG", "tech-1", T0).second.contains("STILL paused"))
        check("R20 self-approval refuses", !svcAsk.approveStep("rbG", "rst", "tech-1", T0).first)
        check("R20 second-human approval executes the step", svcAsk.approveStep("rbG", "rst", "tech-2", T0).first &&
            svcAsk.getRun("rbG")?.status == "succeeded")
        // ApprovalGate BLOCKED policy fails the step, executes nothing
        val svcBlock = RunbookService(f.engine, f.gate, checks, tools, journal, f.audit,
            approvalPolicyFor = { ApprovalGate.Policy.BLOCKED })
        svcBlock.setRemediationStepExecutor { a, d, _, _ -> remExec.perform(a, d, "") }
        svcBlock.admit(defGated)
        val beforeBlock = remExec.performed.size
        val (runB, _) = svcBlock.startRun("gated", "phone-1", "rbB", "tech-1", f.facts,
            f.env(SignedCommandClasses.BACKGROUND_ACTION, RunbookDefinition.canonicalPayload("gated", "phone-1", "rbB"), nonce = "f3"), T0)
        check("R20 ApprovalGate BLOCKED fails run, nothing executes", runB?.status == "failed" && remExec.performed.size == beforeBlock)
        // Check halt + recorded skip preserves the failure; run never reads succeeded
        val checksFail = RecordingRunbookCheckEvaluator(mapOf(RunbookChecks.ACP_RUNNING to false))
        val svcHalt = RunbookService(f.engine, f.gate, checksFail, tools, journal, f.audit,
            approvalPolicyFor = { ApprovalGate.Policy.AUTO })
        val defHalt = RunbookDefinition("halt-rb", "Halt", 1, listOf(
            RunbookStep("chk", RunbookStepKinds.CHECK, RunbookChecks.ACP_RUNNING, failurePolicy = "halt"),
            RunbookStep("tool", RunbookStepKinds.BACKGROUND_TOOL, "device_info")))
        svcHalt.admit(defHalt)
        val (runH, _) = svcHalt.startRun("halt-rb", "phone-1", "rbH", "tech-1", f.facts,
            f.env(SignedCommandClasses.BACKGROUND_ACTION, RunbookDefinition.canonicalPayload("halt-rb", "phone-1", "rbH"), nonce = "f4"), T0)
        check("R20 failed check halts; unrun step renders 'not yet known'",
            runH?.status == "halted_check_failed" && runH.renderCheck("tool") == "not yet known" && runH.renderCheck("chk") == "FAILED")
        check("R20 initiator cannot skip their own halted check", !svcHalt.skipStep("rbH", "chk", "tech-1", "just skip", T0).first)
        check("R20 unreasoned skip refuses", !svcHalt.skipStep("rbH", "chk", "tech-2", "", T0).first)
        val (skipOk, _) = svcHalt.skipStep("rbH", "chk", "tech-2", "ACP service confirmed running by hand", T0)
        check("R20 recorded skip completes as partial_failure, failure preserved",
            skipOk && svcHalt.getRun("rbH")?.status == "partial_failure" &&
            svcHalt.getRun("rbH")!!.records.first { it.stepId == "chk" }.checkPassed == false)
        // Unobserved check never passes (shipped evaluator)
        check("R20 shipped check evaluator fails every check by name",
            !HostWiringRunbookCheckEvaluator().observe(RunbookChecks.ACP_RUNNING, "", "phone-1").first)
        // Policy OFF at start refuses
        val fOff = Fixture()
        fOff.engine.addDocument(ManagementPolicyDocument("rb-off", PolicyLevels.ORG, "scope-1", mapOf("rmm.runbooks.enabled" to "false"), 1))
        val svcOff = RunbookService(fOff.engine, fOff.gate, checks, tools, JobJournal(), fOff.audit,
            approvalPolicyFor = { ApprovalGate.Policy.AUTO })
        svcOff.admit(def)
        check("R20 policy OFF refuses run start", svcOff.startRun(def.id, "phone-1", "rbOff", "tech-1", fOff.facts,
            fOff.env(SignedCommandClasses.BACKGROUND_ACTION, RunbookDefinition.canonicalPayload(def.id, "phone-1", "rbOff"), nonce = "f5"), T0).first == null)
        // Mid-run definition substitution: pinned snapshot wins
        val svcSub = RunbookService(f.engine, f.gate, checks, tools, journal, f.audit,
            approvalPolicyFor = { ApprovalGate.Policy.AUTO })
        svcSub.setRemediationStepExecutor { a, d, _, _ -> remExec.perform(a, d, "") }
        svcSub.admit(def)
        val (runS, _) = svcSub.startRun(def.id, "phone-1", "rbS", "tech-1", f.facts,
            f.env(SignedCommandClasses.BACKGROUND_ACTION, RunbookDefinition.canonicalPayload(def.id, "phone-1", "rbS"), nonce = "f6"), T0)
        svcSub.admit(RunbookDefinition(def.id, def.name, 2, listOf(RunbookStep("only", RunbookStepKinds.BACKGROUND_TOOL, "device_info"))))
        svcSub.attest("rbS", "sign", "tech-2", T0)
        check("R20 mid-run library swap cannot substitute the pinned definition",
            svcSub.getRun("rbS")?.status == "succeeded" && svcSub.getRun("rbS")!!.records.size == 3)
    }

    println("LANEB1 passes=$passes failures=$failures")
    println(if (failures == 0) "LANEB1 ALL PASS" else "LANEB1 FAILURES=$failures")
    if (failures > 0) kotlin.system.exitProcess(1)
}

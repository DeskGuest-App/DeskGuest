import io.deskguest.app.bgtools.BgToolExecutor
import io.deskguest.app.bgtools.BgToolService
import io.deskguest.app.bgtools.BgToolsPolicy
import io.deskguest.app.bgtools.SignedCommandVerifier as BgVerifier
import io.deskguest.app.bgtools.SignedEnvelope
import io.deskguest.app.camerashare.DeskGuestfValidator
import io.deskguest.app.camerashare.AiShareGrant
import io.deskguest.app.camerashare.CameraSharePolicy
import io.deskguest.app.camerashare.CameraShareService
import io.deskguest.app.camerashare.CameraShareSink
import io.deskguest.app.camerashare.PartyDirectory
import io.deskguest.app.cameraview.CameraRecord
import io.deskguest.app.cameraview.CameraViewPolicy
import io.deskguest.app.cameraview.CameraViewService
import io.deskguest.app.cameraview.ChainedAudit
import io.deskguest.app.cameraview.ViewRights
import io.deskguest.app.crypto.AtRestCipher
import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.enterprise.ChainedAuditLog
import io.deskguest.app.enterprise.ScamFriction
import io.deskguest.app.rmm.RmmToggles
import io.deskguest.app.rmmspine.CustomerCommandKeyRing
import io.deskguest.app.rmmspine.EffectivePolicyStore
import io.deskguest.app.rmmspine.InMemoryReplayGuard
import io.deskguest.app.rmmspine.JobJournal
import io.deskguest.app.rmmspine.JobKinds
import io.deskguest.app.rmmspine.JobStates
import io.deskguest.app.rmmspine.JobStepDefinition
import io.deskguest.app.rmmspine.LocateRateLimiter
import io.deskguest.app.rmmspine.ManagementPolicyDocument
import io.deskguest.app.rmmspine.ManagementPolicyEngine
import io.deskguest.app.rmmspine.ManagementPolicyReceipt
import io.deskguest.app.rmmspine.MdmLimits
import io.deskguest.app.rmmspine.PolicyGate
import io.deskguest.app.rmmspine.RecordingRemediationExecutor
import io.deskguest.app.rmmspine.RemediationActions
import io.deskguest.app.rmmspine.RunbookDefinition
import io.deskguest.app.rmmspine.RunbookService
import io.deskguest.app.rmmspine.RunbookStep
import io.deskguest.app.rmmspine.SignedCommandClasses
import io.deskguest.app.rmmspine.SignedCommandEnvelope
import io.deskguest.app.rmmspine.SignedCommandGate
import io.deskguest.app.rmmspine.SignedCommandSigner
import io.deskguest.app.rmmspine.SignedCommandVerifier
import io.deskguest.app.rmmspine.StaticDeviceFacts
import io.deskguest.app.rmmspine.StepStates
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.server.ApprovalPending
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import io.deskguest.app.server.SessionManager
import io.deskguest.app.session.SessionStore
import io.deskguest.app.probes.ProbeService
import io.deskguest.app.probes.ProbesPolicy
import io.deskguest.app.probes.SnmpCodec
import io.deskguest.app.probes.TargetGuard
import io.deskguest.app.probes.UdpTransport
import io.deskguest.app.wiring.PlatformStores
import io.deskguest.app.wiring.PlatformToolHost
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/**
 * Lane W2-andfix1 regression suite (2026-11-22): every fix for the
 * bd-and-core + bd-and-rmm breakdown findings lands here as a
 * permanent check. Names cite the finding they pin.
 */
private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { println("PASS  $name"); passes++ } else { println("FAIL  $name"); failures++ }
}

private val T0 = 1_800_000_000_000L
private fun tmpDir(tag: String): File =
    File(System.getProperty("java.io.tmpdir"), "deskguest-bdfix-$tag-" + System.nanoTime()).apply { mkdirs() }

private fun berTlv(tag: Int, v: ByteArray): ByteArray {
    val len = when {
        v.size < 0x80 -> byteArrayOf(v.size.toByte())
        v.size <= 0xFF -> byteArrayOf(0x81.toByte(), v.size.toByte())
        else -> byteArrayOf(0x82.toByte(), (v.size ushr 8).toByte(), v.size.toByte())
    }
    return byteArrayOf(tag.toByte()) + len + v
}
private fun berInt(v: Int): ByteArray {
    var bytes = ByteArray(4) { i -> (v ushr (24 - 8 * i)).toByte() }
    var start = 0
    while (start < 3) {
        val b0 = bytes[start].toInt() and 0xFF; val b1 = bytes[start + 1].toInt() and 0xFF
        val red = (b0 == 0x00 && b1 and 0x80 == 0) || (b0 == 0xFF && b1 and 0x80 != 0)
        if (!red) break
        start++
    }
    return berTlv(0x02, bytes.copyOfRange(start, 4))
}
private fun snmpResponse(rid: Int, valueTag: Int, valueBytes: ByteArray, errStatus: Int = 0): ByteArray {
    val oid = SnmpCodec.encodeOidBody(intArrayOf(1, 3, 6, 1, 2, 1, 1, 3, 0))
    val vb = berTlv(0x30, berTlv(0x06, oid) + berTlv(valueTag, valueBytes))
    val pdu = berTlv(0xA2, berInt(rid) + berInt(errStatus) + berInt(0) + berTlv(0x30, vb))
    return berTlv(0x30, berInt(1) + berTlv(0x04, "public".toByteArray()) + pdu)
}

fun main() {
    // ================= bd-and-core F1/F2/F4: McpCore =================
    run {
        val dir = tmpDir("core")
        val store = PairingStore(File(dir, "pairings.tsv"))
        var shellRan: String? = null
        val host = object : McpCore.ToolHost {
            override fun tools(): List<McpCore.ToolDef> = listOf(
                McpCore.ToolDef("shell_exec", "fake shell", "drive", JSONObject().put("type", "object"),
                    run = { a -> shellRan = a.optString("command", ""); "ran: ${a.optString("command", "")}" }),
                McpCore.ToolDef("device_info", "fake info", "observe", JSONObject().put("type", "object"),
                    run = { "{\"model\":\"TestPhone\"}" }),
                // Mirrors AccessToolHost's end_session (the fixture
                // host stands in for the composite production host).
                McpCore.ToolDef("end_session", "close session", "drive", JSONObject().put("type", "object"),
                    run = { SessionManager.end()?.let { "Session closed." } ?: "No session is open." })
            )
        }
        val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
        val ring = CustomerCommandKeyRing()
        ring.addCurrent(customer.publicKey)
        val gate = SignedCommandGate(SignedCommandVerifier(ring, InMemoryReplayGuard()), ChainedAuditLog())
        val signer = SignedCommandSigner(customer)
        val core = McpCore(store, host, "test", gate) { T0 }
        fun pair(name: String, access: String): String {
            val code = store.beginPairing(name)
            val reply = core.handle("""{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null)
            val token = JSONObject(reply.body!!).getJSONObject("result").getString("token")
            store.setAccess(token, access, emptySet())
            return token
        }
        fun call(token: String, tool: String, args: JSONObject, id: Int): Pair<Boolean, String> {
            val body = JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", "tools/call")
                .put("params", JSONObject().put("name", tool).put("arguments", args)).toString()
            val reply = core.handle(body, token)
            val result = JSONObject(reply.body!!).getJSONObject("result")
            return result.getBoolean("isError") to result.getJSONArray("content").getJSONObject(0).getString("text")
        }
        val owner = pair("owner", PairingStore.ACCESS_FULL)
        val guest = pair("guest", PairingStore.ACCESS_FULL)

        // F1: envelope-less locally paired call runs under pairing authority.
        val (e1, _) = call(owner, "shell_exec", JSONObject().put("command", "echo local"), 2)
        check("W2 F1 envelope-less locally-paired call executes (gate governs presented envelopes only)", !e1 && shellRan == "echo local")
        // F1: a presented envelope still binds (payload runs, arg does not).
        val env = signer.sign(SignedCommandClasses.SHELL_EXEC, "echo signed".toByteArray(), T0, 600_000, "w2-1")
        val (e2, _) = call(owner, "shell_exec",
            JSONObject().put("command", "echo ARG").put("_signed_command", env.toJson()), 3)
        check("W2 F1 presented envelope verified; envelope payload runs", !e2 && shellRan == "echo signed")
        // F1 destruction: envelope minted for device_info presented to shell_exec refuses.
        val bgEnv = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, "tool=device_info".toByteArray(), T0, 600_000, "w2-2")
        val (e3, _) = call(owner, "shell_exec",
            JSONObject().put("command", "echo x").put("_signed_command", bgEnv.toJson()), 4)
        check("W2 F1 cross-tool envelope refuses at shell_exec", e3 && shellRan == "echo signed")
        // F1: end_session is exempt from the gate even with a garbage envelope attached.
        val (e4, t4) = call(owner, "end_session", JSONObject().put("_signed_command", JSONObject()), 5)
        check("W2 F1 end_session never gate-refused", !t4.contains("Signed command refused"))

        // F2: approval-pending choke point.
        ApprovalPending.begin()
        val (e5, t5) = call(owner, "device_info", JSONObject(), 6)
        check("W2 F2 while an approval prompt is pending, tools refuse at the choke point", e5 && t5.contains("approval", ignoreCase = true))
        val (e6, t6) = call(owner, "end_session", JSONObject(), 7)
        check("W2 F2 end_session still allowed while approval pending", !t6.contains("approval prompt", ignoreCase = true) || !e6)
        ApprovalPending.end()
        check("W2 F2 tap-guard: a tap within 1500ms of the agent's last gesture is not an approval",
            !ApprovalPending.approveTapAllowed(10_000, 9_000) && ApprovalPending.approveTapAllowed(11_000, 9_000))

        // F4: session binding.
        SessionManager.start("owner-agent", pairingKey = owner)
        val (e7, t7) = call(guest, "shell_exec", JSONObject().put("command", "echo hijack"), 8)
        check("W2 F4 another pairing cannot drive inside the owner's session", e7 && t7.contains("another pairing") && shellRan == "echo signed")
        val (e8, _) = call(guest, "device_info", JSONObject(), 9)
        check("W2 F4 another pairing may still read status tools", !e8)
        val (e9, _) = call(guest, "end_session", JSONObject(), 10)
        check("W2 F4 another pairing cannot end the owner's session over the channel", e9 && SessionManager.isOpen)
        val (e10, _) = call(owner, "end_session", JSONObject(), 11)
        check("W2 F4 the owning pairing can end its session", !e10 && !SessionManager.isOpen)
        // F4: revocation ends the owned session. The hook is
        // wiring (ControlService installs exactly this); install
        // the same hook here so the store-level contract is what
        // is pinned.
        store.onRevoke = { token -> SessionManager.endIfOwnedBy(token) }
        SessionManager.start("owner-agent", pairingKey = owner)
        store.revoke(owner)
        check("W2 F4 revoking the pairing ends its live session", !SessionManager.isOpen)
        dir.deleteRecursively()
    }

    // ================= bd-and-core F3: generation revalidation =================
    run {
        val s = SessionManager.start("gen-agent")
        check("W2 F3 session starts", s != null)
        val gen = SessionManager.generation.get()
        check("W2 F3 same generation revalidates clean", SessionManager.refusalIfChangedSince(gen, null) == null)
        SessionManager.end()
        SessionManager.start("gen-agent-2")
        check("W2 F3 a STOP/new session invalidates the captured generation",
            SessionManager.refusalIfChangedSince(gen, null) != null)
        SessionManager.end()
    }

    // ================= bd-and-core F5: presence precondition =================
    run {
        SessionManager.presenceStopAttached = { false }
        SessionManager.start("presence-agent")
        check("W2 F5 drive refuses while the STOP surface is not attached",
            SessionManager.driveRefusal()?.contains("presence", ignoreCase = true) == true)
        SessionManager.presenceStopAttached = { true }
        check("W2 F5 drive allowed once STOP is attached", SessionManager.driveRefusal() == null)
        SessionManager.presenceStopAttached = null
        SessionManager.end()
    }

    // ================= bd-and-core F6: at-rest cipher verdict =================
    run {
        val dir = tmpDir("cipher")
        val wrapping = object : LineCipher {
            override fun encrypt(plain: String) = "v1:WRAPPED"
            override fun decrypt(wrapped: String): String? = if (wrapped.startsWith("v1:")) "plain" else wrapped
        }
        check("W2 F6 no verdict recorded -> identity cipher (named posture)",
            AtRestCipher.select(dir) { wrapping } === IdentityLineCipher)
        AtRestCipher.recordVerdict(dir, true)
        check("W2 F6 probe_ok verdict -> wrapping cipher selected",
            AtRestCipher.select(dir) { wrapping } === wrapping)
        AtRestCipher.recordVerdict(dir, false)
        check("W2 F6 probe failure verdict -> identity cipher",
            AtRestCipher.select(dir) { wrapping } === IdentityLineCipher)
        // PlatformRuntime guard: a plaintext identity seed must not be wrapped under.
        val filesDir = tmpDir("cipher2"); val platformDir = tmpDir("cipher3")
        File(platformDir, "device-identity.txt").writeText("plain-seed-bytes")
        AtRestCipher.recordVerdict(filesDir, true)
        check("W2 F6 verdict ok + plaintext seed -> identity cipher (seed guard: no silent identity rotation)",
            AtRestCipher.selectGuarded(filesDir, platformDir, "device-identity.txt") { wrapping } === IdentityLineCipher)
        File(platformDir, "device-identity.txt").writeText("v1:already-wrapped")
        check("W2 F6 verdict ok + wrapped seed -> wrapping cipher",
            AtRestCipher.selectGuarded(filesDir, platformDir, "device-identity.txt") { wrapping } === wrapping)
        dir.deleteRecursively(); filesDir.deleteRecursively(); platformDir.deleteRecursively()
    }

    // ================= bd-and-core F8/F10/F11: PairingStore + McpCore identity =================
    run {
        val dir = tmpDir("pairing")
        val store = PairingStore(File(dir, "pairings.tsv"))
        val code = store.beginPairing("agent-x")
        val p = store.redeem(code, emptySet())
        check("W2 F11 scopeIds set on the pairing record", p != null && store.setScopeIds(p.token, setOf("co")))
        val reloaded = PairingStore(File(dir, "pairings.tsv"))
        check("W2 F11 scopeIds survive reload", reloaded.pairingForToken(p!!.token)?.scopeIds == setOf("co"))
        // F10: pair-time identity comes from the session binding, not a stale fallback.
        val core = McpCore(store, object : McpCore.ToolHost {
            override fun tools(): List<McpCore.ToolDef> = emptyList()
        }, "test") { T0 }
        val code2 = store.beginPairing("agent-y")
        // The real flow: initialize presents clientInfo and issues
        // a session id; pair binds THAT session's identity.
        val initReply = core.handle(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"Evil|Name","version":"9.9"}}}""", null)
        val reply = core.handle(
            """{"jsonrpc":"2.0","id":2,"method":"pair","params":{"code":"$code2"}}""", null, initReply.sessionId)
        val token2 = JSONObject(reply.body!!).getJSONObject("result").getString("token")
        val paired = store.pairingForToken(token2)
        check("W2 F10 paired identity recorded from the pairing session itself",
            paired?.agentName == "Evil|Name" || paired?.agentName?.contains("Evil") == true)
        check("W2 F10 identity fields sanitised (no control chars, capped)",
            (paired?.agentName ?: "").none { it.code < 0x20 } && (paired?.agentName?.length ?: 0) <= 40)
        dir.deleteRecursively()
    }

    // ================= bd-and-core F11: platform session scope wall =================
    run {
        val dir = tmpDir("scopewall")
        val stores = PlatformStores(dir)
        val roster = stores.roster
        roster.addScope(RosterStore.Scope("co", "company", "Co"))
        roster.addScope(RosterStore.Scope("home", "personal", "Home"))
        roster.addUser(RosterStore.User("admin", "co", "Admin", "human"))
        roster.addCompanyAdmin("co", "admin")
        roster.addUser(RosterStore.User("host1", "co", "Host", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug", "co", "G", memberUserIds = setOf("user1")), "admin")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg", "co", "Fleet", listOf("lan")), "admin")
        roster.addGrant(RosterStore.Grant("co", "ug", "dg", setOf("use")), "admin")
        val ident = DeviceIdentity.generate()
        val code = stores.enrollment.mint("company", "dg", "Fleet")
        stores.enrollment.redeem(code, EnrollmentStore.EnrollingDevice(ident.deviceId, ident.publicKeyBase64, "Host Dev"))
        stores.sessions.createSession(
            SessionStore.Session(id = "sess-co", scopeId = "co", hostDeviceId = ident.deviceId,
                initiatorUserId = "user1", kind = "attended", transportRung = "lan"), "host1")
        // Drive the host through McpCore exactly as the service
        // does: the resolver sees the calling pairing's key; only
        // the token in boundToken resolves to the company scope.
        var boundToken: String? = null
        val hostFiltered = PlatformToolHost(callerScopes = { key ->
            if (key != null && key == boundToken) setOf("co") else emptySet()
        }, storesProvider = { stores })
        val pairStore = PairingStore(File(dir, "p2.tsv"))
        val core = McpCore(pairStore, hostFiltered, "test") { T0 }
        val codeP = pairStore.beginPairing("wall-tester")
        val pairReply = core.handle("""{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$codeP"}}""", null)
        val token = JSONObject(pairReply.body!!).getJSONObject("result").getString("token")
        pairStore.setAccess(token, PairingStore.ACCESS_FULL, emptySet())
        fun callTool(tool: String, args: JSONObject, id: Int): String {
            val body = JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", "tools/call")
                .put("params", JSONObject().put("name", tool).put("arguments", args)).toString()
            val reply = core.handle(body, token)
            return JSONObject(reply.body!!).getJSONObject("result").getJSONArray("content").getJSONObject(0).getString("text")
        }
        check("W2 F11 unbound pairing sees NO company sessions (absent, not redacted)",
            !callTool("platform_sessions", JSONObject(), 2).contains("sess-co"))
        check("W2 F11 status of an out-of-scope session reads as no-such-session",
            callTool("platform_session_status", JSONObject().put("session_id", "sess-co"), 3).contains("no such session"))
        boundToken = token
        check("W2 F11 the bound pairing sees its scope's sessions",
            callTool("platform_sessions", JSONObject(), 4).contains("sess-co"))
        dir.deleteRecursively()
    }

    // ================= bd-and-core F12: SessionStore compaction + badges =================
    run {
        val dir = tmpDir("sessions")
        val stores = PlatformStores(dir)
        val roster = stores.roster
        roster.addScope(RosterStore.Scope("co", "company", "Co"))
        roster.addUser(RosterStore.User("admin", "co", "Admin", "human"))
        roster.addCompanyAdmin("co", "admin")
        roster.addUser(RosterStore.User("host1", "co", "Host", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug", "co", "G", memberUserIds = setOf("user1")), "admin")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg", "co", "Fleet", listOf("lan")), "admin")
        roster.addGrant(RosterStore.Grant("co", "ug", "dg", setOf("use")), "admin")
        val ident = DeviceIdentity.generate()
        val code = stores.enrollment.mint("company", "dg", "Fleet")
        stores.enrollment.redeem(code, EnrollmentStore.EnrollingDevice(ident.deviceId, ident.publicKeyBase64, "Host Dev"))
        val created = stores.sessions.createSession(
            SessionStore.Session(id = "sess-x", scopeId = "co", hostDeviceId = ident.deviceId,
                initiatorUserId = "user1", kind = "attended", transportRung = "lan",
                recording = SessionStore.RECORDING_VIDEO, recordingRef = "recordings/rec1.mp4"), "host1")
        check("W2 F12 session created for compaction test", created)
        stores.sessions.acceptSession("sess-x", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI)
        stores.sessions.startSession("sess-x", "user1")
        repeat(620) { stores.sessions.appendEvent("sess-x", "transport_note", "user1", "note $it") }
        val events = stores.sessions.events("sess-x")
        check("W2 F12 event list is capped per session", events.size <= SessionStore.MAX_EVENTS_PER_SESSION)
        check("W2 F12 compaction is visible via a marker naming the dropped count",
            events.any { it.type == SessionStore.EVENT_EVENTS_COMPACTED && it.detail.contains("dropped=") })
        check("W2 F12 presence badges derive from the record (recording badge)",
            stores.liveSessionBadges().contains("Recording"))
        dir.deleteRecursively()
    }

    // ================= bd-and-rmm F1/F3: background tools =================
    run {
        BgToolsPolicy.enabled = true
        var now = T0
        val clock = { now }
        val verifier = BgVerifier { env, payload -> env.signature == "good" && env.payloadHash == BgToolService.payloadHashHex(payload) }
        fun env(tool: String, args: Map<String, String>, nonce: String, sig: String = "good") = SignedEnvelope(
            "background_tool", nonce, now + 60_000,
            BgToolService.payloadHashHex(BgToolService.canonicalPayload(tool, args)), sig)
        val ranArgs = mutableListOf<Map<String, String>>()
        val svc = BgToolService(verifier, BgToolExecutor { _, a -> ranArgs += a; "ok" }, ChainedAudit(clock), clock)
        val args = mapOf("path" to "/deskguest")
        check("W2 F1 bgtool runs when the envelope binds tool+args",
            svc.invoke("storage_report", args, env("storage_report", args, "b1"), byteArrayOf()).isSuccess)
        check("W2 F1 destruction: envelope minted for other args refuses",
            svc.invoke("storage_report", mapOf("path" to "/etc"), env("storage_report", args, "b2"), byteArrayOf()).isFailure)
        check("W2 F1 destruction: envelope minted for another tool refuses",
            svc.invoke("device_info", emptyMap(), env("storage_report", args, "b3"), byteArrayOf()).isFailure)
        check("W2 F1 destruction: caller payload that is not the canonical payload refuses",
            svc.invoke("storage_report", args, env("storage_report", args, "b4"), byteArrayOf(9, 9, 9)).isFailure)
        check("W2 F3 a device-visible notice precedes execution",
            svc.notices().any { it.contains("storage_report") } &&
                svc.audit.entries().any { it.type == "bgtool_notice" })
        // Resume: non-mutating replays the ORIGINAL args; mutating parks.
        val flaky = BgToolService(verifier, BgToolExecutor { t, a ->
            ranArgs += a; if (t == "storage_report") throw RuntimeException("boom") else "ok"
        }, ChainedAudit(clock), clock)
        val job = flaky.invoke("storage_report", args, env("storage_report", args, "b5"), byteArrayOf()).getOrThrow()
        check("W2 F3 failed job checkpoints", job.state == "failed_checkpointed")
        val resumed = flaky.resume(job.id, env("storage_report", args, "b6"), byteArrayOf())
        check("W2 F1 resume replays the job's ORIGINAL args (never emptyMap)",
            resumed.isSuccess && ranArgs.last() == args)
        val mutSvc = BgToolService(verifier, BgToolExecutor { _, _ -> throw RuntimeException("boom") }, ChainedAudit(clock), clock)
        val mjob = mutSvc.invoke("service_restart", emptyMap(), env("service_restart", emptyMap(), "b7"), byteArrayOf()).getOrThrow()
        val mres = mutSvc.resume(mjob.id, env("service_restart", emptyMap(), "b8"), byteArrayOf())
        check("W2 F3 resume of a MUTATING tool parks instead of re-executing",
            mres.getOrThrow().state == "parked_non_idempotent")
        // Durability: jobs survive a fresh service over the same store file.
        val jobFile = File(tmpDir("bgjobs"), "jobs.json")
        val durable = BgToolService(verifier, BgToolExecutor { _, _ -> "ok" }, ChainedAudit(clock), clock, jobStoreFile = jobFile)
        val djob = durable.invoke("device_info", emptyMap(), env("device_info", emptyMap(), "b9"), byteArrayOf()).getOrThrow()
        val reloaded = BgToolService(verifier, BgToolExecutor { _, _ -> "ok" }, ChainedAudit(clock), clock, jobStoreFile = jobFile)
        check("W2 F3 jobs persist across process restart", reloaded.job(djob.id)?.state == "succeeded")
        BgToolsPolicy.enabled = false
    }

    // ================= bd-and-rmm F2: policy wiring =================
    run {
        val engine = ManagementPolicyEngine()
        check("W2 F2 registry carries rmm.probes.enabled + rmm.vault_surfacing.enabled (44 keys, W12-DS P7-F6 added browser_hardening + mobile_operator; W20 mirror added W19-C's tor_provisioning + aipack_download)",
            engine.registry.all().size == 44 && engine.registry.get("rmm.probes.enabled") != null &&
                engine.registry.get("rmm.vault_surfacing.enabled") != null &&
                engine.registry.get("rmm.tor_provisioning.enabled") != null &&
                engine.registry.get("rmm.aipack_download.enabled") != null)
        check("W2 F2 BgToolsPolicy default now matches the registry (OFF)",
            io.deskguest.app.bgtools.BgToolsPolicy.enabled == false)
        check("W2 F2 RmmToggles keys are registry keys; unknown fails closed",
            RmmToggles.KEYS.all { engine.registry.get(it) != null } && !RmmToggles.enabled(emptyMap(), "rmm.nope"))
        // Receipt binds PolicyGate + persists the Effective Policy view.
        val dir = tmpDir("receipt")
        val store = EffectivePolicyStore(File(dir, "effective.txt"))
        val facts = StaticDeviceFacts("phone-1", "co")
        val receipt = ManagementPolicyReceipt(engine, null, ChainedAuditLog(),
            factsProvider = { facts }, effectiveStore = store)
        val doc = ManagementPolicyDocument("d1", "org", "co",
            mapOf("rmm.background_tools.enabled" to "true"), 1)
        receipt.admitLocalDocument(doc, "admin", T0)
        check("W2 F2 receipt persists the Effective Policy view (no more eternal 'no policy received')",
            // W10 (V3-F4): the persisted view renders owner-words
            // sentences, not raw keys.
            store.load()?.contains("Background toolset") == true &&
                store.load()?.contains("set by co IT") == true)
        check("W2 F2 PolicyGate follows the engine after a receipt",
            PolicyGate.enabledFor("rmm.background_tools.enabled", false))
        PolicyGate.unbind()
        check("W2 F2 unbound PolicyGate falls back to the local var",
            !PolicyGate.enabledFor("rmm.background_tools.enabled", false) &&
                PolicyGate.enabledFor("rmm.background_tools.enabled", true))
        dir.deleteRecursively()
    }

    // ================= bd-and-rmm F4/F5: probes =================
    run {
        ProbesPolicy.enabled = true; ProbesPolicy.snmpEnabled = true; ProbesPolicy.topologyEnabled = true
        check("W2 F5 public internet target refused", TargetGuard.refusal("8.8.8.8") != null)
        check("W2 F5 CGNAT/shared space refused", TargetGuard.refusal("100.64.1.1") != null)
        check("W2 F5 172.32 (outside RFC1918) refused", TargetGuard.refusal("172.32.0.1") != null)
        check("W2 F5 RFC1918 targets allowed",
            TargetGuard.refusal("10.0.0.5") == null && TargetGuard.refusal("172.16.0.5") == null &&
                TargetGuard.refusal("192.168.1.20") == null)
        // BER: TimeTicks decode, request-id verification, error-status, big OID arcs.
        val ticks = SnmpCodec.decodeResponse(snmpResponse(7, 0x43, byteArrayOf(0x01, 0xE2.toByte(), 0x40)), 7)
        check("W2 F4 TimeTicks (0x43) decodes to a value", ticks.first == "123456" && ticks.second == null)
        val spoof = SnmpCodec.decodeResponse(snmpResponse(9, 0x43, byteArrayOf(1)), 7)
        check("W2 F4 destruction: response with the wrong request-id refuses (spoof/stale)",
            spoof.first == null && spoof.second?.contains("request-id") == true)
        val errd = SnmpCodec.decodeResponse(snmpResponse(7, 0x04, "x".toByteArray(), errStatus = 2), 7)
        check("W2 F4 error-status is honoured by name", errd.first == null && errd.second?.contains("error-status 2") == true)
        val bigOid = intArrayOf(1, 3, 6, 1, 4, 1, 99999, 200000)
        check("W2 F4 OID sub-identifiers >= 16384 round-trip (base-128)",
            SnmpCodec.decodeOidBody(SnmpCodec.encodeOidBody(bigOid))?.toList() == bigOid.toList())
        val longCommunity = "c".repeat(200)
        val enc = SnmpCodec.encodeGet(longCommunity, 300, intArrayOf(1, 3, 6, 1, 2, 1, 1, 1, 0))
        check("W2 F4 long-form lengths + request-id > 127 encode without corruption", enc.size > 200)
        // Service: actor named in audit; policy-off reads unavailable, not fail.
        val svc = ProbeService(UdpTransport { _, _, _, _ -> snmpResponse(1, 0x43, byteArrayOf(0x10)) }, ChainedAudit { T0 })
        val r = svc.snmpGet("192.168.1.20", "public", intArrayOf(1, 3, 6, 1, 2, 1, 1, 3, 0), "sysUpTime", actor = "hub-alice")
        check("W2 F5 probe audit names the actor", r.value == "16" &&
            svc.audit.entries().any { it.detail.contains("actor=hub-alice") })
        ProbesPolicy.enabled = false
        check("W2 F4 policy OFF agentless check is unavailable, not a device fail",
            svc.agentlessCheck("192.168.1.20", "snmp_uptime", "public").outcome == "unavailable:policy OFF")
        ProbesPolicy.enabled = true
        val deadSvc = ProbeService(UdpTransport { _, _, _, _ -> null }, ChainedAudit { T0 })
        check("W2 F4 timeout agentless check is unavailable, not a device fail",
            deadSvc.agentlessCheck("192.168.1.21", "snmp_uptime", "public").outcome.startsWith("unavailable:"))
        check("W2 F5 topology sweep is bounded at the cap",
            ProbeService.MAX_TOPOLOGY_TARGETS == 64)
    }

    // ================= bd-and-rmm F6: camera share =================
    run {
        CameraSharePolicy.enabled = true
        var ownerLive = true; var watcherLive = true
        val parties = object : PartyDirectory {
            override fun isLiveHuman(s: String, u: String) = (u == "owner" && ownerLive) || (u == "watcher" && watcherLive)
            override fun isLiveAi(s: String, u: String) = u == "aiw"
            override fun displayName(u: String) = u
            override fun phoneFiled(s: String, p: String) = p == "phone1"
            override fun isPhoneOwner(s: String, o: String, p: String) = o == "owner" && p == "phone1"
        }
        val sink = object : CameraShareSink {
            override fun open(s: String, w: String) {}
            override fun deliverFrame(s: String, w: String, f: ByteArray) {}
            override fun deliverAnnotation(s: String, x: Int, y: Int) {}
            override fun setTorch(s: String, on: Boolean) {}
            override fun close(s: String, c: String) {}
        }
        var now = T0
        val svc = CameraShareService(parties, sink, DeskGuestfValidator { true }, ChainedAudit { now }, { now })
        check("W2 F6 destruction: a live human who does NOT own the phone cannot start its share",
            svc.initiateShare("co", "watcher", "phone1", "owner").isFailure)
        val share = svc.initiateShare("co", "owner", "phone1", "watcher").getOrThrow()
        watcherLive = false
        svc.tick()
        check("W2 F6 tick ends the share when the watcher stops being live", svc.share(share.id)?.state == "ended")
        watcherLive = true
        // AI watcher whose grant expires mid-share.
        svc.grantAiWatcher("owner", "co", "aiw", "phone1", 30)
        val aiShare = svc.initiateShare("co", "owner", "phone1", "aiw").getOrThrow()
        now += 31 * 60_000
        svc.tick()
        check("W2 F6 tick ends an AI-watched share when the grant expires", svc.share(aiShare.id)?.state == "ended")
        now -= 31 * 60_000
        // Owner ceases to be a live human.
        val s3 = svc.initiateShare("co", "owner", "phone1", "watcher").getOrThrow()
        ownerLive = false
        svc.tick()
        check("W2 F6 tick ends the share when the owner is no longer a live human", svc.share(s3.id)?.state == "ended")
        ownerLive = true
    }

    // ================= bd-and-rmm F7/F10: JobJournal =================
    run {
        val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
        val ring = CustomerCommandKeyRing(); ring.addCurrent(customer.publicKey)
        val signer = SignedCommandSigner(customer)
        val env = signer.sign(SignedCommandClasses.SCRIPT_EXEC, "chain".toByteArray(), T0, 600_000, "jj-1")
        val steps = listOf(JobStepDefinition("s1", "one", true), JobStepDefinition("s2", "two", false))
        val j = JobJournal()
        j.createJob("job1", JobKinds.SCRIPT_CHAIN, "phone-1", steps, env, T0)
        j.startJob("job1", T0); j.beginStep("job1", "s1", T0); j.completeStep("job1", "s1", T0)
        val exported = j.exportJson()
        val honest = JobJournal()
        check("W2 F7 honest export imports clean", honest.importJson(exported).ok)
        // Destruction: flip s2's idempotency in the defs only (chain untouched).
        val tampered = JSONObject(exported)
        tampered.getJSONArray("jobs").getJSONObject(0).getJSONArray("steps").getJSONObject(1).put("idempotent", true)
        val victim = JobJournal()
        val v = victim.importJson(tampered.toString())
        check("W2 F7 destruction: idempotency flipped in defs (chain intact) is caught by the def/chain cross-check",
            !v.ok && victim.getJob("job1") == null)
        // Destruction: swap the envelope for a different valid one (hash recomputed in def).
        val otherEnv = signer.sign(SignedCommandClasses.SCRIPT_EXEC, "other".toByteArray(), T0, 600_000, "jj-2")
        val swapped = JSONObject(exported)
        val defObj = swapped.getJSONArray("jobs").getJSONObject(0)
        defObj.put("envelopeJson", otherEnv.toJson().toString())
        defObj.put("envelopeHash", io.deskguest.app.enterprise.sha256Hex(otherEnv.toJson().toString()))
        val victim2 = JobJournal()
        check("W2 F7 destruction: envelope swapped in defs (self-consistent hash) is caught against the chained envHash",
            !victim2.importJson(swapped.toString()).ok && victim2.getJob("job1") == null)
        // F7: resume of an envelope job without a key ring fails AUTHORITY_INVALID.
        val j2 = JobJournal()
        j2.createJob("job2", JobKinds.SCRIPT_CHAIN, "phone-1", steps, env, T0)
        j2.startJob("job2", T0)
        val rep = j2.resumeAll(T0 + 1000, true, null)
        check("W2 F7 resume without a key ring refuses envelope jobs (no self-referential hash trust)",
            j2.getJob("job2")?.failureReason == "authority_invalid" && rep.outcomes.any { it.outcome == "failed" })
        val rep2 = run {
            val j3 = JobJournal()
            j3.createJob("job3", JobKinds.SCRIPT_CHAIN, "phone-1", steps, env, T0)
            j3.startJob("job3", T0)
            j3.resumeAll(T0 + 1000, true, ring)
        }
        check("W2 F7 resume WITH the ring re-verifies and resumes", rep2.outcomes.any { it.outcome == "resumed" })
        // F10 journal verbs.
        val j4 = JobJournal()
        j4.createJob("job4", JobKinds.FILE_TRANSFER, "phone-1", steps, null, T0)
        j4.startJob("job4", T0); j4.beginStep("job4", "s1", T0)
        check("W2 F10 failStepContinue fails the step but keeps the job continuable",
            j4.failStepContinue("job4", "s1", "check failed", T0) &&
                j4.getJob("job4")?.state == JobStates.RESUMED &&
                j4.beginStep("job4", "s2", T0))
        check("W2 F10 skipStep + recordHalt are journalled",
            j4.skipStep("job4", "s2", T0) && j4.recordHalt("job4", "halted by operator", T0) &&
                j4.entries().any { it.kind == "step_skipped" } && j4.entries().any { it.kind == "job_halted" })
    }

    // ================= bd-and-rmm F8/F10: runbooks =================
    run {
        val engine = ManagementPolicyEngine()
        val facts = StaticDeviceFacts("phone-1", "co")
        val backward = RunbookDefinition("rb-bad", "bad", 1, listOf(
            RunbookStep("a", "check", "deskguest_running", failurePolicy = "route", routeTo = "b"),
            RunbookStep("b", "check", "deskguest_running", failurePolicy = "route", routeTo = "a")))
        check("W2 F8 backward route refuses at validate (infinite-loop construction)",
            backward.validate()?.contains("not a LATER step") == true)
        val selfRoute = RunbookDefinition("rb-bad2", "bad", 1, listOf(
            RunbookStep("a", "check", "deskguest_running", failurePolicy = "route", routeTo = "a")))
        check("W2 F8 self route refuses at validate", selfRoute.validate() != null)
        val forward = RunbookDefinition("rb-ok", "ok", 1, listOf(
            RunbookStep("a", "check", "deskguest_running", failurePolicy = "route", routeTo = "b"),
            RunbookStep("b", "check", "deskguest_running")))
        check("W2 F8 forward route validates", forward.validate() == null)
        // skipStep: only the failed check; remediation policy pre-check inside runs.
        val journal = JobJournal()
        val audit = ChainedAuditLog()
        val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
        val ring = CustomerCommandKeyRing(); ring.addCurrent(customer.publicKey)
        val gate = SignedCommandGate(SignedCommandVerifier(ring, InMemoryReplayGuard()), audit)
        val signer = SignedCommandSigner(customer)
        val checks = io.deskguest.app.rmmspine.RecordingRunbookCheckEvaluator(mapOf("deskguest_running" to false))
        val svc = RunbookService(engine, gate, checks,
            io.deskguest.app.rmmspine.RecordingRunbookToolExecutor(), journal, audit)
        val def = RunbookDefinition("rb-halt", "halt", 1, listOf(
            RunbookStep("chk", "check", "deskguest_running", failurePolicy = "halt"),
            RunbookStep("later", "check", "deskguest_running", failurePolicy = "halt")))
        svc.admit(def)
        val env = signer.sign(SignedCommandClasses.BACKGROUND_ACTION,
            RunbookDefinition.canonicalPayload("rb-halt", "phone-1", "run1").toByteArray(), T0, 600_000, "rb-1")
        val (runStarted, _) = svc.startRun("rb-halt", "phone-1", "run1", "tech-1", facts, env, T0)
        check("W2 F8 run halts on the failed check", runStarted?.status == "halted_check_failed")
        check("W2 F8 destruction: skipping a step that never failed refuses",
            !svc.skipStep("run1", "later", "tech-2", "reason", T0).first)
        check("W2 F10 the halt itself is journalled", journal.entries().any { it.kind == "job_halted" })
        val (skipOk, _) = svc.skipStep("run1", "chk", "tech-2", "verified by hand", T0)
        check("W2 F8/F10 skipping the failed check works and is journalled",
            skipOk && journal.entries().any { it.kind == "step_skipped" })
        // Remediation step inside a runbook honours the per-action policy disable.
        val engine2 = ManagementPolicyEngine()
        engine2.addDocument(ManagementPolicyDocument("p1", "org", "co",
            mapOf("rmm.remediation.${RemediationActions.CLEAR_DESKGUEST_CACHE}.enabled" to "false"), 1))
        val svc2 = RunbookService(engine2, gate, checks,
            io.deskguest.app.rmmspine.RecordingRunbookToolExecutor(), JobJournal(), audit)
        val recording = RecordingRemediationExecutor()
        svc2.setRemediationStepExecutor { a, d, r, _ -> recording.perform(a, d, r) }
        val def2 = RunbookDefinition("rb-rem", "rem", 1, listOf(
            RunbookStep("fix", "remediation", RemediationActions.CLEAR_DESKGUEST_CACHE)))
        svc2.admit(def2)
        val env2 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION,
            RunbookDefinition.canonicalPayload("rb-rem", "phone-1", "run2").toByteArray(), T0, 600_000, "rb-2")
        val (run2, _) = svc2.startRun("rb-rem", "phone-1", "run2", "tech-1", facts, env2, T0)
        check("W2 F10 remediation step inside a runbook honours the per-action policy disable (executor untouched)",
            run2?.status == "failed" && recording.performed.isEmpty())
    }

    // ================= bd-and-rmm F9: MDM locate defence =================
    run {
        val lim = LocateRateLimiter()
        check("W2 F9 first locate acquires", lim.tryAcquire("dev", T0, MdmLimits.DEFAULT_LOCATE_MIN_INTERVAL_MS, MdmLimits.DEFAULT_LOCATE_MAX_PER_DAY).first)
        check("W2 F9 second locate inside the interval refuses",
            !lim.tryAcquire("dev", T0 + 60_000, MdmLimits.DEFAULT_LOCATE_MIN_INTERVAL_MS, MdmLimits.DEFAULT_LOCATE_MAX_PER_DAY).first)
        val dir = tmpDir("limiter")
        val badFile = File(dir, "lim.tsv"); badFile.writeText("garbage-line-no-pipe")
        val broken = LocateRateLimiter(badFile)
        check("W2 F9 destruction: corrupt limiter store fails CLOSED (counts never silently reset)",
            broken.broken && !broken.tryAcquire("dev", T0, 0, 10000).first)
        dir.deleteRecursively()
    }

    // ================= bd-and-rmm F9: MDM policy cannot disarm the locate defence =================
    run {
        val engine = ManagementPolicyEngine()
        engine.addDocument(ManagementPolicyDocument("mdm-on", "org", "scope-1",
            mapOf("rmm.mdm.enabled" to "true"), 1))
        // Destruction: policy tries to switch the anti-tracking
        // defence off — interval 0, cap 10000/day.
        engine.addDocument(ManagementPolicyDocument("mdm-lax", "org", "scope-1",
            mapOf("rmm.mdm.locate_min_interval_minutes" to "0", "rmm.mdm.locate_max_per_day" to "10000"), 2))
        val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
        val ring = CustomerCommandKeyRing(); ring.addCurrent(customer.publicKey)
        val gate = SignedCommandGate(SignedCommandVerifier(ring, InMemoryReplayGuard()), ChainedAuditLog())
        val signer = SignedCommandSigner(customer)
        val facts = StaticDeviceFacts("phone-1", "scope-1")
        val noticeFile = File(tmpDir("mdmnotices"), "notices.tsv")
        val svc = io.deskguest.app.rmmspine.MdmService(engine, gate,
            io.deskguest.app.rmmspine.RecordingMdmActionExecutor(), ChainedAuditLog(),
            { id -> if (id == "phone-1") facts else null }, LocateRateLimiter(),
            noticeStoreFile = noticeFile)
        val state = io.deskguest.app.rmmspine.MdmDeviceState("phone-1", "scope-1", "android",
            io.deskguest.app.rmmspine.MdmOwnership.PERSONAL, "16", true, "pin_pattern", "0.4.9", reportedMs = T0)
        svc.reportState(state, "endpoint", T0)
        fun locate(id: String, nonce: String, at: Long): Boolean {
            val req = io.deskguest.app.rmmspine.MdmActionRequest(id, "phone-1",
                io.deskguest.app.rmmspine.MdmActionKinds.LOCATE_ONCE,
                noticeText = "Locate ordered by IT", issuedMs = at, expiresMs = at + 600_000)
            val env = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, req.canonicalPayload().toByteArray(), at, 600_000, nonce)
            return svc.executeAction(req, env, "hub", at).first?.executed == true
        }
        check("W2 F9 first locate executes", locate("L1", "m1", T0))
        check("W2 F9 destruction: policy interval=0 does NOT disarm the 15-minute minimum (clamped)",
            !locate("L2", "m2", T0 + 60_000))
        val svcReloaded = io.deskguest.app.rmmspine.MdmService(engine, gate,
            io.deskguest.app.rmmspine.RecordingMdmActionExecutor(), ChainedAuditLog(),
            { id -> if (id == "phone-1") facts else null }, LocateRateLimiter(),
            noticeStoreFile = noticeFile)
        check("W2 F9 device notices persist across service restart (the user-visible trace survives)",
            svcReloaded.notices().any { it.commandId == "L1" })
    }

    // ================= bd-and-rmm F11: camera view re-gating =================
    run {
        CameraViewPolicy.enabled = true; CameraViewPolicy.audioEnabled = false
        var grant = true
        val svc = CameraViewService(ViewRights { _, _, _ -> grant }, ChainedAudit { T0 }, { T0 })
        val cam = CameraRecord("cam1", "co", "dg", "192.168.1.50", viewCapability = "rtsp",
            streamUri = "rtsp://192.168.1.50:554/s")
        val view = svc.requestView(cam, "co", "op").getOrThrow()
        grant = false
        svc.tick()
        check("W2 F11 tick ends a live view whose right was revoked mid-view",
            svc.liveViews().isEmpty() && svc.audit.entries().any { it.type == "camera_view_ended" && it.detail.contains("cause=right_revoked") })
        CameraViewPolicy.enabled = false
    }

    // ================= bd-and-rmm F12: audit chains + scam friction =================
    run {
        val log = ChainedAuditLog()
        log.append("kind", "actor", "detail with | pipe and \\ backslash", T0)
        check("W2 F12 enterprise chain verifies with delimiter-bearing fields (canonical escaping)",
            log.verify().first)
        val csv = log.exportCsv("admin", T0 + 1)
        check("W2 F12 CSV export quotes every text field", csv.contains("\"kind\"") && csv.contains("\"actor\""))
        val log2 = ChainedAuditLog()
        log2.append("=cmd|evil", "mallory", "x", T0)
        val csv2 = log2.exportCsv("admin", T0 + 1)
        check("W2 F12 CSV formula injection is neutralised", csv2.contains("\"'=cmd|evil\"") || csv2.contains("'=cmd"))
        val dir = tmpDir("chain")
        val chainFile = File(dir, "chain.json")
        log.saveToFile(chainFile)
        val restored = ChainedAuditLog()
        val (okLoad, _) = restored.loadFromFile(chainFile)
        check("W2 F12 audit chain persists + restores + verifies", okLoad && restored.verify().first &&
            restored.headHash() == log.headHash())
        check("W2 F12 scam terms match on word boundaries ('Kirsten'/'First' are not 'irs')",
            !ScamFriction.hasImpersonationTerm("Kirsten First") &&
                ScamFriction.hasImpersonationTerm("Microsoft Support"))
        val est = io.deskguest.app.enterprise.OperatorHistory(5, 0, 0, null, false)
        check("W2 F12 an active call blocks the established fast path (SCAM-14)",
            ScamFriction.evaluate("op", "Helper", est, T0 - 30L * 24 * 3600 * 1000, T0, callActive = true).level == "high_friction" &&
                ScamFriction.evaluate("op", "Helper", est, T0 - 30L * 24 * 3600 * 1000, T0, callActive = false).level == "established")
        dir.deleteRecursively()
    }

    println("BDANDFIX $passes passed, $failures failed")
    println(if (failures == 0) "BDANDFIX ALL PASS" else "BDANDFIX FAILURES PRESENT")
    if (failures > 0) kotlin.system.exitProcess(1)
}

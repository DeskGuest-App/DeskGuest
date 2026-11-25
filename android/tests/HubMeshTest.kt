import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.session.SessionStore
import io.agenticcontrol.app.transport.AclBuilder
import io.agenticcontrol.app.transport.ApiResult
import io.agenticcontrol.app.transport.ClientVersionGate
import io.agenticcontrol.app.transport.EndpointAuthKeyRules
import io.agenticcontrol.app.transport.HubMembership
import io.agenticcontrol.app.transport.HubRung
import io.agenticcontrol.app.transport.LanProtocol
import io.agenticcontrol.app.transport.MeshAddress
import io.agenticcontrol.app.transport.MeshPlatform
import io.agenticcontrol.app.transport.MeshRole
import io.agenticcontrol.app.transport.MeshRung
import io.agenticcontrol.app.transport.MeshSetupFlow
import io.agenticcontrol.app.transport.PolicyGuard
import io.agenticcontrol.app.transport.SocketStreams
import io.agenticcontrol.app.transport.StreamConnector
import io.agenticcontrol.app.transport.StubRung
import io.agenticcontrol.app.transport.TailnetGrant
import io.agenticcontrol.app.transport.TailnetMapping
import io.agenticcontrol.app.transport.TailscaleApi
import io.agenticcontrol.app.transport.TailscaleCredentialGuard
import io.agenticcontrol.app.transport.TailscaleHonesty
import io.agenticcontrol.app.transport.TransportSessionManager
import io.agenticcontrol.app.transport.TransportTarget
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files

/**
 * JVM tests for Block C part 3 (Android half): the `hub` rung
 * (membership gate, tailnet-address gate, enrollment handshake —
 * mesh membership never equals ACP admission), the live lan→hub
 * failover hop at engine level, and the in-app Tailscale setup
 * (D4) with its T2 conditions: client floor, the TS-03 mobile
 * carve-out, scoped-OAuth-only credentials, guarded policy writes,
 * D12 ACL generation, single-use endpoint keys.
 *
 * Socket note (same as TransportTest): JVM loopback connects are
 * reset in this sandbox, so rung connects run over in-memory pipes
 * through the rungs' connector seam — the gate and handshake code
 * is the production code; the Windows half proves the same rungs
 * over real sockets, and the laptop proof ran them on the real
 * hub. The live-account leg of the mesh setup is UNPROVEN by
 * design (no account may be created); the API here is a mock.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private var clockNow = 1_700_200_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private class HubWorld(dir: File, val tag: String, groupSet: List<String> = listOf("lan", "hub", "mesh")) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    val hostDeviceId: String
    val hostIdentity: DeviceIdentity
    val operatorIdentity: DeviceIdentity

    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", groupSet), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        hostIdentity = DeviceIdentity.generate()
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(hostIdentity.deviceId, hostIdentity.publicKeyBase64, "Host Device"))
        hostDeviceId = hostIdentity.deviceId
        operatorIdentity = DeviceIdentity.generate()
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(operatorIdentity.deviceId, operatorIdentity.publicKeyBase64, "Operator Device"))
    }

    fun manager(vararg rungs: io.agenticcontrol.app.transport.TransportRung, identity: DeviceIdentity? = null): TransportSessionManager {
        var n = 0
        // W3 lane B sibling repair (disclosed): manager takes the
        // enrollment store (transport v2).
        return TransportSessionManager(roster, sessions, rungs.toList(), identity, enrollment) { "hm-$tag-${n++}" }
    }
}

/** A connector that wires rung connects to a LanProtocol host
 *  handshake over pipes (the sandbox's socket substitute). */
private class PipeConnector(val enrollments: EnrollmentStore, val hostIdentity: DeviceIdentity) : StreamConnector {
    @Volatile var opens: Int = 0
    @Volatile var accepted: Int = 0
    @Volatile var refused: Int = 0

    override fun open(host: String, port: Int): SocketStreams {
        opens++
        val c2hOut = PipedOutputStream(); val c2hIn = PipedInputStream(c2hOut)
        val h2cOut = PipedOutputStream(); val h2cIn = PipedInputStream(h2cOut)
        val hostStreams = SocketStreams(c2hIn, h2cOut)
        Thread {
            try {
                // W3 lane B sibling repair (disclosed): v2 returns
                // the AEAD channel; the echo loop runs over it.
                val established = LanProtocol.hostHandshake(hostStreams, enrollments, hostIdentity)
                if (established == null) { refused++; return@Thread }
                accepted++
                val channel = established.second
                while (true) {
                    val line = LanProtocol.readLine(channel.input) ?: return@Thread
                    LanProtocol.writeLine(channel.output, if (line == "PING") "PONG" else "ERR unknown")
                }
            } catch (_: Exception) { /* peer gone */ }
        }.apply { isDaemon = true }.start()
        return SocketStreams(h2cIn, c2hOut)
    }
}

private class MockApi : TailscaleApi {
    var policy: String = "{\"groups\":{}}"
    var exchanges: Int = 0
    var applies: Int = 0
    var failApplyOnce: Boolean = false

    override fun exchangeToken(clientId: String, clientSecret: String, scopes: Set<String>): ApiResult<String> {
        exchanges++; return ApiResult.success("tok-1")
    }
    override fun getPolicy(accessToken: String): ApiResult<String> = ApiResult.success(policy)
    override fun validatePolicy(accessToken: String, policyJson: String): ApiResult<Unit> =
        if (policyJson.contains("\"bad\"")) ApiResult.failure("invalid") else ApiResult.success(Unit)
    override fun applyPolicy(accessToken: String, policyJson: String): ApiResult<Unit> {
        applies++
        if (failApplyOnce) { failApplyOnce = false; return ApiResult.failure("boom") }
        policy = policyJson
        return ApiResult.success(Unit)
    }
}

fun main() {
    val dir = Files.createTempDirectory("acp-hubmesh-test").toFile()

    // ---- tailnet address shape ----
    check("100.64.0.0/10 admitted (0.1, 0.127 edges)",
        MeshAddress.isTailnetAddress("100.64.0.1") && MeshAddress.isTailnetAddress("100.127.255.254"))
    check("non-tailnet refused (LAN, public, 100.63/100.128 edges, garbage, null)",
        !MeshAddress.isTailnetAddress("192.168.1.2") && !MeshAddress.isTailnetAddress("8.8.8.8") &&
        !MeshAddress.isTailnetAddress("100.63.0.1") && !MeshAddress.isTailnetAddress("100.128.0.1") &&
        !MeshAddress.isTailnetAddress("hello") && !MeshAddress.isTailnetAddress(null))
    check("host:port form parses to its host", MeshAddress.isTailnetAddress("100.64.0.7:47621"))

    // ---- client version floor (T2) ----
    check("floor admits 1.104.4 / 1.104.7 / 1.105.0",
        ClientVersionGate.meetsFloor("1.104.4") && ClientVersionGate.meetsFloor("1.104.7") && ClientVersionGate.meetsFloor("1.105.0"))
    check("floor refuses the Tailworm range + garbage + null",
        !ClientVersionGate.meetsFloor("1.104.3") && !ClientVersionGate.meetsFloor("1.90.0") &&
        !ClientVersionGate.meetsFloor("soon") && !ClientVersionGate.meetsFloor(null))

    // ---- hub membership ----
    run {
        val m = HubMembership()
        check("DESTRUCTION downgrade client cannot join the hub",
            m.join("dev-a", "1.90.0", 1L) == null && m.lastJoinRefusal?.contains("floor") == true && !m.isLiveMember("dev-a"))
        val node = m.join("dev-a", "1.104.7", 2L)
        check("join at the pinned version admitted", node != null && m.isLiveMember("dev-a"))
        m.decommission("dev-a")
        check("decommissioned node is not a live member", !m.isLiveMember("dev-a"))
    }

    // ---- hub rung gates + session (over pipes) ----
    run {
        val w = HubWorld(dir, "hub1")
        val membership = HubMembership()
        val pipes = PipeConnector(w.enrollment, w.hostIdentity)
        val hub = HubRung(membership, pipes)
        val target = TransportTarget(w.hostDeviceId, "100.64.0.7")

        val neverJoined = hub.connectSession(target, w.operatorIdentity, w.enrollment)
        check("hub rung refuses a device that never joined (before any socket)",
            !neverJoined.ok && pipes.opens == 0 && neverJoined.detail.contains("not a live member"))

        membership.join(w.hostDeviceId, "1.104.7", tick())
        val lanTarget = hub.connectSession(TransportTarget(w.hostDeviceId, "192.168.1.2"), w.operatorIdentity, w.enrollment)
        check("DESTRUCTION hub rung refuses a LAN address — never a silent downgrade",
            !lanTarget.ok && pipes.opens == 0 && lanTarget.detail.contains("not a tailnet address"))

        val connected = hub.connectSession(target, w.operatorIdentity, w.enrollment)
        check("hub session connects for a joined member (handshake over the mesh path)",
            connected.ok && connected.stream != null)
        LanProtocol.writeLine(connected.stream!!.output, "PING")
        check("hub session channel answers PING with PONG", LanProtocol.readLine(connected.stream.input) == "PONG")
        connected.stream.close()

        membership.decommission(w.hostDeviceId)
        val afterDecom = hub.connectSession(target, w.operatorIdentity, w.enrollment)
        check("decommissioned node cannot start a hub session", !afterDecom.ok)
    }

    // ---- destruction: hub member, unenrolled in ACP → refused at the handshake ----
    run {
        val w = HubWorld(dir, "hub2")
        val membership = HubMembership()
        val pipes = PipeConnector(w.enrollment, w.hostIdentity)
        val hub = HubRung(membership, pipes)
        val stranger = DeviceIdentity.generate() // hub member, never enrolled in ACP
        membership.join(stranger.deviceId, "1.104.7", tick())
        val attempt = hub.connectSession(TransportTarget(stranger.deviceId, "100.64.0.9"), stranger, w.enrollment)
        Thread.sleep(300)
        check("DESTRUCTION hub member unenrolled in ACP is refused at the handshake (membership != admission)",
            !attempt.ok && pipes.refused == 1 && pipes.accepted == 0)
    }

    // ---- engine: live lan→hub failover hop ----
    run {
        val w = HubWorld(dir, "hop", listOf("lan", "hub", "mesh"))
        val membership = HubMembership()
        membership.join(w.hostDeviceId, "1.104.7", tick())
        val pipes = PipeConnector(w.enrollment, w.hostIdentity)
        val mgr = w.manager(StubRung.succeeding("lan"), HubRung(membership, pipes), identity = w.operatorIdentity)
        val s1 = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())
        check("hop setup: session starts on lan", s1 != null && s1.transportRung == "lan" && s1.state == "active")
        val s2 = mgr.reestablish(s1!!.id, mapOf("hub" to TransportTarget(w.hostDeviceId, "100.64.0.7")))
        check("LIVE lan-to-hub failover hop: new session active on hub",
            s2 != null && s2.transportRung == "hub" && s2.state == "active")
        val old = w.sessions.session(s1.id)
        check("hop honesty: old session ended with transport_failover",
            old != null && old.state == SessionStore.STATE_ENDED && old.endReason == SessionStore.REASON_TRANSPORT_FAILOVER)
        check("hop linkage: session_reestablished event links old to new",
            mgr.events().any { it.kind == "session_reestablished" && it.fromSessionId == s1.id && it.toSessionId == s2!!.id })
    }

    // ---- credential guard (T2: scoped OAuth only) ----
    check("DESTRUCTION personal API token refused by shape",
        TailscaleCredentialGuard.classify("tskey-api-kAAA123") == TailscaleCredentialGuard.KIND_PERSONAL_API_TOKEN &&
        TailscaleCredentialGuard.acceptForStorage("tskey-api-kAAA123", setOf("policy_file"))?.contains("personal API token") == true)
    check("scoped OAuth accepted only with scopes named",
        TailscaleCredentialGuard.acceptForStorage("tskey-client-kBBB", setOf("policy_file")) == null &&
        TailscaleCredentialGuard.acceptForStorage("tskey-client-kBBB", emptySet()) != null &&
        TailscaleCredentialGuard.acceptForStorage("hunter2", setOf("policy_file")) != null)

    // ---- honesty labels (D15/D16) ----
    check("honesty label names the vendor + free-tier metering",
        TailscaleHonesty.VENDOR_LABEL.contains("Tailscale Inc.") &&
        TailscaleHonesty.VENDOR_LABEL.contains("6 users") && TailscaleHonesty.VENDOR_LABEL.contains("50 tagged resources"))
    check("carve-out label states the mobile log limit plainly",
        TailscaleHonesty.MOBILE_CARVE_OUT_LABEL.contains("cannot turn off") &&
        TailscaleHonesty.MOBILE_CARVE_OUT_LABEL.contains("operator's own personal device only"))

    // ---- setup flow: carve-out + endpoint + floor (TS-03 / D3 / T2) ----
    run {
        val flow = MeshSetupFlow()
        val endpoint = flow.runPreSignIn(MeshPlatform.ANDROID, MeshRole.ENDPOINT, carveOutAcknowledged = true, clientVersion = "1.104.7")
        check("DESTRUCTION endpoint setup refused on Android (D3)", endpoint.stage == MeshSetupFlow.STAGE_REFUSED)
        val noAck = flow.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = false, clientVersion = "1.104.7")
        check("Android operator without the carve-out acknowledgment is refused", noAck.stage == MeshSetupFlow.STAGE_REFUSED)
        val old = flow.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.90.0")
        check("Android operator on a below-floor client is refused", old.stage == MeshSetupFlow.STAGE_REFUSED)
        val okState = flow.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.104.7")
        check("Android operator + carve-out acknowledged → awaiting sign-in, carve-out carried",
            okState.stage == MeshSetupFlow.STAGE_AWAITING_SIGN_IN && okState.carveOut)
        val desktopNoKill = MeshSetupFlow().runPreSignIn(MeshPlatform.DESKTOP, MeshRole.OPERATOR, carveOutAcknowledged = false, clientVersion = "1.104.7", desktopKillSwitchVerified = false)
        check("DESTRUCTION desktop setup refuses when the kill switch cannot be verified",
            desktopNoKill.stage == MeshSetupFlow.STAGE_REFUSED && desktopNoKill.detail.contains("kill switch"))
    }

    // ---- setup completion: sign-in boundary, credential, policy guard ----
    run {
        val mapping = TailnetMapping(
            userGroups = mapOf("techs" to listOf("alice@example.com")),
            deviceGroups = mapOf("fleet" to "acp-fleet"),
            grants = listOf(TailnetGrant("techs", "fleet", setOf("use", "enroll"))))

        val flowA = MeshSetupFlow()
        flowA.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.104.7")
        val apiA = MockApi()
        val notSigned = flowA.completeAfterSignIn(false, "cid", "tskey-client-x", setOf("policy_file"), mapping, 47621, apiA)
        check("sign-in not completed → nothing configured (no token exchange, no apply)",
            notSigned.stage == MeshSetupFlow.STAGE_REFUSED && apiA.exchanges == 0 && apiA.applies == 0)

        val flowB = MeshSetupFlow()
        flowB.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.104.7")
        val personal = flowB.completeAfterSignIn(true, "cid", "tskey-api-personal", setOf("policy_file"), mapping, 47621, MockApi())
        check("DESTRUCTION personal-token-shaped credential stops the setup", personal.stage == MeshSetupFlow.STAGE_REFUSED)

        val flowC = MeshSetupFlow()
        flowC.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.104.7")
        val apiC = MockApi()
        val ready = flowC.completeAfterSignIn(true, "cid", "tskey-client-x", setOf("policy_file", "auth_keys"), mapping, 47621, apiC)
        check("full mock flow reaches Ready; policy applied through the guard",
            ready.stage == MeshSetupFlow.STAGE_READY && apiC.policy.contains("tag:acp-fleet"))
    }

    // ---- ACL builder: D12 shape + injection refusals ----
    run {
        val mapping = TailnetMapping(
            userGroups = mapOf("techs" to listOf("alice@example.com")),
            deviceGroups = mapOf("fleet" to "acp-fleet"),
            grants = listOf(TailnetGrant("techs", "fleet", setOf("use", "enroll"))))
        val json = AclBuilder.build(mapping, 47621)
        check("D12 mapping lands (groups, tags, tagOwners from enroll, accept on the session port)",
            json.contains("\"group:techs\"") && json.contains("\"tag:acp-fleet\"") &&
            json.contains("\"tagOwners\"") && json.contains("tag:acp-fleet:47621"))
        check("policy never carries ssh or a wildcard grant", !json.contains("\"ssh\"") && !json.contains("\"*\""))
        val hostileName = try { AclBuilder.build(mapping.copy(userGroups = mapOf("ops\",\"ssh\":[{\"src\":[\"*\"]}" to listOf("a@b.c"))), 47621); false } catch (_: IllegalArgumentException) { true }
        check("DESTRUCTION hostile group name refused (config injection)", hostileName)
        val hostileMember = try { AclBuilder.build(mapping.copy(userGroups = mapOf("techs" to listOf("x\"],\"evil\":[\"*"))), 47621); false } catch (_: IllegalArgumentException) { true }
        check("DESTRUCTION hostile member value refused (config injection)", hostileMember)
    }

    // ---- policy guard rollback ----
    run {
        val api = MockApi()
        val before = api.policy
        api.failApplyOnce = true
        val outcome = PolicyGuard(api).apply("tok", "{\"groups\":{\"group:techs\":[]}}")
        check("failed apply rolls back to the previous policy",
            !outcome.applied && api.policy == before && outcome.detail.contains("restored"))
    }

    // ---- endpoint auth key rules (D3) ----
    check("endpoint keys: single-use + tagged + ≤90d enforced",
        EndpointAuthKeyRules.refusal(reusable = true, tags = listOf("tag:acp-fleet"), expiryDays = 7) != null &&
        EndpointAuthKeyRules.refusal(reusable = false, tags = emptyList(), expiryDays = 7) != null &&
        EndpointAuthKeyRules.refusal(reusable = false, tags = listOf("tag:acp-fleet"), expiryDays = 91) != null &&
        EndpointAuthKeyRules.refusal(reusable = false, tags = listOf("tag:acp-fleet"), expiryDays = 7) == null)

    // ---- mesh rung gating ----
    run {
        val w = HubWorld(dir, "mesh1")
        val flow = MeshSetupFlow()
        val pipes = PipeConnector(w.enrollment, w.hostIdentity)
        val mesh = MeshRung({ flow.state }, pipes)
        val target = TransportTarget(w.hostDeviceId, "100.64.0.11")
        val tooEarly = mesh.connectSession(target, w.operatorIdentity, w.enrollment)
        check("mesh rung refuses every connect before setup completes", !tooEarly.ok && pipes.opens == 0)
        flow.runPreSignIn(MeshPlatform.ANDROID, MeshRole.OPERATOR, carveOutAcknowledged = true, clientVersion = "1.104.7")
        val mapping = TailnetMapping(
            userGroups = mapOf("techs" to listOf("alice@example.com")),
            deviceGroups = mapOf("fleet" to "acp-fleet"),
            grants = listOf(TailnetGrant("techs", "fleet", setOf("use", "enroll"))))
        flow.completeAfterSignIn(true, "cid", "tskey-client-x", setOf("policy_file"), mapping, 47621, MockApi())
        val connected = mesh.connectSession(target, w.operatorIdentity, w.enrollment)
        check("mesh rung connects once setup is Ready (carve-out path)", connected.ok)
        connected.stream?.close()
        val lanOnMesh = mesh.connectSession(TransportTarget(w.hostDeviceId, "192.168.1.2"), w.operatorIdentity, w.enrollment)
        check("mesh rung refuses a LAN address", !lanOnMesh.ok && lanOnMesh.detail.contains("not a tailnet address"))
    }

    println(if (failures == 0) "HUBMESH: ALL PASS" else "HUBMESH: $failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}

import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import io.deskguest.app.session.SessionStore
import io.deskguest.app.wiring.PlatformStores
import io.deskguest.app.wiring.PlatformToolHost
import java.io.File
import java.nio.file.Files
import java.util.Base64
import org.json.JSONObject

/**
 * JVM tests for the Slice 1–3 WIRING layer (Block A, Android half):
 * PlatformStores (the facade every live surface uses), the three
 * activities' source-level guarantees, and PlatformToolHost (the
 * MCP surface). Includes the focused destruction battery for the
 * new wiring:
 *  - endpoint-view leakage through the endpoint surface's only read
 *  - channel-origin accept attempts through the wiring layer
 *  - cross-scope reads/writes through the UI-layer facade
 *  - STOP from every state through the UI-layer (facade) path
 *  - corrupt-store / corrupt-identity boot behaviour
 * Checks cite the decision they enforce (D2/D7/D8/D14/D31/D32/D36,
 * RULING 2026-11-19) like the other suites.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

private fun sourceFile(rel: String): String {
    val a = File("app/src/main/java/io/deskguest/app/$rel")
    val b = File("android/app/src/main/java/io/deskguest/app/$rel")
    val f = if (a.exists()) a else b
    return if (f.exists()) f.readText() else ""
}

/** Enroll an arbitrary identity into [stores]' enrollment store via
 *  a freshly minted code (test-side device, not the stores' own). */
private fun enrollDevice(
    stores: PlatformStores, seedByte: Int, scope: String, groupId: String, groupName: String, displayName: String
): EnrollmentStore.EnrolledDevice {
    val identity = DeviceIdentity.fromSeed(ByteArray(32) { seedByte.toByte() })
    val code = stores.mintEnrollment(scope, groupId, groupName)
    return stores.enrollment.redeem(
        code, EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, displayName)
    )!!
}

/** A populated personal scope: owner (admin) + tech, a device group,
 *  an enrolled host device, a user group with a use+admin grant. */
private class WiringWorld(val stores: PlatformStores, val hostDeviceId: String)

private fun personalWorld(dir: File, cipher: AesGcmLineCipher): WiringWorld {
    val stores = PlatformStores(dir, cipher)
    check("world: personal scope created", stores.addScope("home", "personal", "Home"))
    check("world: owner added", stores.addUser("home", "owner", "Owner", "human"))
    check("world: tech added", stores.addUser("home", "tech", "Tech", "human"))
    check("world: owner seated as first admin", stores.addCompanyAdmin("home", "owner", null))
    check(
        "world: device group created",
        stores.addDeviceGroup("home", "phones", "Phones", listOf("lan", "hub"), "owner")
    )
    val host = enrollDevice(stores, 7, "personal", "phones", "Phones", "Host Phone")
    check("world: user group created", stores.addUserGroup("home", "ops", "Ops", "owner"))
    check("world: tech joins ops", stores.addUserToGroup("home", "ops", "tech", "owner"))
    check("world: owner joins ops", stores.addUserToGroup("home", "ops", "owner", "owner"))
    check(
        "world: grant use+admin saved",
        stores.addGrant("home", "ops", "phones", setOf("use", "admin"), "owner")
    )
    return WiringWorld(stores, host.deviceId)
}

fun main() {
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())

    // ================= identity: lazy, wrapped, stable =================
    val dir1 = Files.createTempDirectory("deskguest-wiring-id").toFile()
    val s1 = PlatformStores(dir1, cipher)
    check("identity is NOT loaded by opening the stores (lazy, off the startup path)", !s1.identityLoaded())
    check("identity file does NOT exist before first use", !File(dir1, PlatformStores.IDENTITY_FILE).exists())
    val id1 = s1.ownIdentity()
    check("identity loads on first explicit use", s1.identityLoaded())
    check("identity file exists after first use", File(dir1, PlatformStores.IDENTITY_FILE).exists())
    val onDisk = File(dir1, PlatformStores.IDENTITY_FILE).readText().trim()
    check("identity on disk is in wrapped form (LineCipher contract)", cipher.isWrapped(onDisk))
    check("identity on disk holds no plaintext seed", !onDisk.contains(b64(id1.seedCopy())))
    val s1Again = PlatformStores(dir1, cipher)
    check("identity is stable across reopening the stores", s1Again.ownDeviceId() == id1.deviceId)

    // ================= mint → redeem own → endpoint snapshot =================
    val dir2 = Files.createTempDirectory("deskguest-wiring-own").toFile()
    val own = PlatformStores(dir2, cipher)
    own.addScope("home", "personal", "Home")
    own.addUser("home", "owner", "Owner", "human")
    own.addCompanyAdmin("home", "owner", null)
    own.addDeviceGroup("home", "phones", "Phones", listOf("lan", "hub"), "owner")
    // Another device enrolls into the same group FIRST, so the store
    // is populated with a foreign record before our own redemption.
    val other = enrollDevice(own, 9, "personal", "phones", "Phones", "Someone Elses Phone")
    val mintCode = own.mintEnrollment("personal", "phones", "Phones")
    val redeemed = own.redeemOwn(mintCode, "My Phone", "Operator Olivia", "operator-device-1")
    check("redeemOwn succeeds with a minted code", redeemed != null)
    check("redeemOwn files THIS device (own DeviceId)", redeemed?.deviceId == own.ownDeviceId())
    check("redeemOwn files into the MINT's group", redeemed?.groupId == "phones")
    check("redeemOwn files into the MINT's scope", redeemed?.scope == "personal")
    val snap = own.endpointSnapshot()
    check("D2: snapshot's record is the device's OWN record", snap.ownRecord?.deviceId == own.ownDeviceId())
    check("D2: snapshot carries the enrollment receipt", snap.receipts.any { it.enrollerName == "Operator Olivia" })
    check(
        "D2: allowed operators derive from the receipt",
        snap.allowedOperators.any { it.enrollerDeviceId == "operator-device-1" && it.enrollerName == "Operator Olivia" }
    )
    val snapText = snap.toString()
    check(
        "DESTRUCTION D2: endpoint snapshot contains NO other device's id",
        !snapText.contains(other.deviceId)
    )
    check(
        "DESTRUCTION D2: endpoint snapshot contains NO other device's name",
        !snapText.contains("Someone Elses Phone")
    )
    check("redeemOwn refuses a replayed (single-use) code", own.redeemOwn(mintCode, "My Phone", "Operator Olivia", "operator-device-1") == null)

    // Unenrolled endpoint: the view is empty, never widened.
    val dir2b = Files.createTempDirectory("deskguest-wiring-unenrolled").toFile()
    val fresh = PlatformStores(dir2b, cipher)
    val freshSnap = fresh.endpointSnapshot()
    check("D2: unenrolled endpoint snapshot has no record", freshSnap.ownRecord == null)
    check("D2: unenrolled endpoint snapshot has no receipts", freshSnap.receipts.isEmpty())
    check("D2: unenrolled endpoint snapshot has no operators", freshSnap.allowedOperators.isEmpty())
    check("D2: unenrolled snapshot still shows the device's own id", freshSnap.deviceId == fresh.ownDeviceId())

    // ================= sessions through the facade =================
    val dir3 = Files.createTempDirectory("deskguest-wiring-sessions").toFile()
    val world = personalWorld(dir3, cipher)
    val st = world.stores
    check(
        "session create (attended) via facade",
        st.createSession("sess-1", "home", world.hostDeviceId, "tech", "owner", "attended", "lan", "video")
    )
    check("session list sees the new session", st.allSessions().any { it.id == "sess-1" })
    check("D36: requested session with recording set is NOT yet recording (derived, active-only)", st.sessionDetail("sess-1")?.isRecording == false)

    // DESTRUCTION — channel-origin accept through the wiring layer.
    check(
        "RULING 2026-11-19: acceptFromChannel REFUSES",
        !st.acceptFromChannel("sess-1", "owner")
    )
    check(
        "RULING 2026-11-19: refused channel accept leaves the session unaccepted",
        st.sessionDetail("sess-1")?.session?.acceptBy == null
    )
    check(
        "RULING 2026-11-19: refused channel accept is evented as accept_refused",
        st.sessionDetail("sess-1")?.events?.any { it.type == SessionStore.EVENT_ACCEPT_REFUSED } == true
    )
    check(
        "RULING 2026-11-19: start still refused after a channel accept attempt",
        !st.startSession("sess-1", "owner")
    )
    check(
        "RULING 2026-11-19: an arbitrary non-local origin also refuses (store level)",
        !st.sessions.acceptSession("sess-1", "owner", "smoke-signal")
    )
    // The local path — the one the sessions screen calls.
    check("RULING 2026-11-19: acceptLocal (the screen's origin) succeeds", st.acceptLocal("sess-1", "owner"))
    check(
        "RULING 2026-11-19: local accept records the local origin",
        st.sessionDetail("sess-1")?.session?.acceptOrigin == SessionStore.ACCEPT_ORIGIN_LOCAL_UI
    )
    check(
        "RULING 2026-11-19: local accept event names the device, locally",
        st.sessionDetail("sess-1")?.events?.any {
            it.type == SessionStore.EVENT_ACCEPTED && it.detail.contains("locally")
        } == true
    )
    check("start after local accept", st.startSession("sess-1", "owner"))
    check("D36: active session with recording=video IS recording (derived)", st.sessionDetail("sess-1")?.isRecording == true)
    check("floor grant via facade", st.grantFloor("sess-1", "owner", "tech"))
    check("floor holder is tech after grant", st.sessionDetail("sess-1")?.floorHolderUserId == "tech")
    check("floor take-back via facade", st.takeFloorBack("sess-1", "owner"))
    check("floor holder is owner after take-back", st.sessionDetail("sess-1")?.floorHolderUserId == "owner")

    // DESTRUCTION — STOP from every state, through the facade (the
    // exact call the sessions screen's STOP button makes).
    fun sessionIn(state: String, id: String): Boolean {
        if (!st.createSession(id, "home", world.hostDeviceId, "tech", "owner", "attended", "lan")) return false
        when (state) {
            "requested" -> {}
            "active", "paused", "blocked" -> {
                if (!st.acceptLocal(id, "owner")) return false
                if (!st.startSession(id, "owner")) return false
                if (state == "paused" && !st.pauseSession(id, "owner")) return false
                if (state == "blocked" && !st.blockSession(id, "owner")) return false
            }
        }
        return st.sessionDetail(id)?.session?.state == state
    }
    for (state in listOf("requested", "active", "paused", "blocked")) {
        val id = "stop-$state"
        check("STOP setup: session reaches $state", sessionIn(state, id))
        check("DESTRUCTION STOP: STOP from $state terminates", st.stopSession(id, "owner"))
        val after = st.sessionDetail(id)?.session
        check(
            "DESTRUCTION STOP: $state session is ended with host_stop",
            after?.state == SessionStore.STATE_ENDED && after?.endReason == SessionStore.REASON_HOST_STOP
        )
    }
    check("STOP of the live session via facade", st.stopSession("sess-1", "owner"))
    check("D36: a stopped session no longer reports recording", st.sessionDetail("sess-1")?.isRecording == false)
    check("STOP on an ended session refuses (nothing to stop)", !st.stopSession("sess-1", "owner"))
    // STOP by a non-host, non-admin participant refuses and the
    // session survives — STOP is powerful, not public.
    check("setup: second live session", sessionIn("active", "stop-guard"))
    check("DESTRUCTION STOP: controller (non-host, non-admin) cannot STOP", !st.stopSession("stop-guard", "tech"))
    check("DESTRUCTION STOP: session survives a refused STOP", st.sessionDetail("stop-guard")?.session?.state == SessionStore.STATE_ACTIVE)
    check("STOP by host ends the guarded session", st.stopSession("stop-guard", "owner"))

    // ================= MCP surface truthfulness =================
    val host = PlatformToolHost { st }
    val toolNames = host.tools().map { it.name }
    check("MCP: platform tools are exactly the two read-only session tools", toolNames == listOf("platform_sessions", "platform_session_status"))
    check("MCP: NO accept tool exists on the channel surface", toolNames.none { it.contains("accept") })
    check("MCP: NO stop/transition tool exists on the channel surface", toolNames.none { it.contains("stop") || it.contains("start") || it.contains("end") })
    val listText = host.tools().first { it.name == "platform_sessions" }.run(JSONObject())
    val listJson = JSONObject(listText)
    val listed = listJson.getJSONArray("sessions")
    var listedStopActive: JSONObject? = null
    for (i in 0 until listed.length()) {
        val entry = listed.getJSONObject(i)
        if (entry.getString("id") == "sess-1") listedStopActive = entry
    }
    check("MCP: the agent sees the same session the app sees", listedStopActive != null)
    check(
        "MCP: agent-visible state matches the store (ended/host_stop)",
        listedStopActive?.getString("state") == "ended" && listedStopActive?.getString("endReason") == "host_stop"
    )
    check(
        "MCP: agent-visible recording state is the derived one (false once ended)",
        listedStopActive?.getBoolean("isRecording") == false
    )
    val statusText = host.tools().first { it.name == "platform_session_status" }
        .run(JSONObject().put("session_id", "sess-1"))
    val statusJson = JSONObject(statusText)
    check("MCP: session status carries participants", statusJson.getJSONArray("participants").length() == 2)
    check("MCP: session status carries the event history", statusJson.getJSONArray("events").length() > 0)
    check(
        "MCP: unknown session is an honest error, not a fabricated record",
        JSONObject(host.tools().first { it.name == "platform_session_status" }.run(JSONObject().put("session_id", "nope"))).has("error")
    )
    // Through the real McpCore protocol path, with a real pairing.
    val pairDir = Files.createTempDirectory("deskguest-wiring-mcp").toFile()
    val pairingStore = PairingStore(File(pairDir, "pairings.tsv"), IdentityLineCipher)
    val core = McpCore(pairingStore, PlatformToolHost { st }, "wiring-test")
    val code = pairingStore.beginPairing("Wire Agent")
    val pairReply = core.handle(
        """{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null
    )
    val token = JSONObject(pairReply.body!!).getJSONObject("result").getString("token")
    val toolsList = core.handle("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", token)
    check("MCP: tools/list over the protocol includes platform_sessions", toolsList.body!!.contains("platform_sessions"))
    val callReply = core.handle(
        """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"platform_sessions","arguments":{}}}""",
        token
    )
    check("MCP: tools/call platform_sessions answers with the app's sessions", callReply.body!!.contains("sess-1"))
    val acceptCall = core.handle(
        """{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"platform_accept_session","arguments":{"session_id":"sess-1"}}}""",
        token
    )
    check(
        "DESTRUCTION MCP: there is no channel accept tool to call (unknown tool, in-band error)",
        acceptCall.body!!.contains("Unknown tool")
    )

    // ================= cross-scope through the facade (D8 wall) =================
    val dir4 = Files.createTempDirectory("deskguest-wiring-scopes").toFile()
    val multi = personalWorld(dir4, cipher).stores
    check("company scope created beside personal (D8)", multi.addScope("acme", "company", "Acme"))
    check("company user added", multi.addUser("acme", "carol", "Carol", "human"))
    check("company second admin added", multi.addUser("acme", "dave", "Dave", "human"))
    check("carol seated as company admin", multi.addCompanyAdmin("acme", "carol", null))
    check("dave seated as company admin", multi.addCompanyAdmin("acme", "dave", "carol"))
    check("company device group created", multi.addDeviceGroup("acme", "servers", "Servers", listOf("lan"), "carol"))
    val acmeRoster = multi.operatorRoster("acme")
    val homeRoster = multi.operatorRoster("home")
    check(
        "D8: company roster contains ONLY company users",
        acmeRoster?.users?.map { it.id }?.toSet() == setOf("carol", "dave")
    )
    check(
        "D8: personal roster contains ONLY personal users",
        homeRoster?.users?.map { it.id }?.toSet() == setOf("owner", "tech")
    )
    check(
        "DESTRUCTION D8: company admin cannot delete a PERSONAL device through the facade",
        !multi.deleteDevice("acme", personalWorldHost(multi), "carol")
    )
    check(
        "DESTRUCTION D8: the personal device survives the cross-scope delete attempt",
        multi.enrollment.byId(personalWorldHost(multi))?.revoked == false
    )
    check(
        "DESTRUCTION D8: offboarding a personal user FROM the company scope refuses",
        !multi.offboard("acme", "owner", "carol", true).fired
    )
    check("D8: the personal user survives the cross-scope offboarding", multi.roster.user("owner") != null)
    check(
        "DESTRUCTION D8: adding a personal user to a company group refuses",
        !multi.addUserToGroup("acme", "servers", "owner", "carol")
    )
    // Suspended admins hold no power through the facade (D38 F4).
    check("suspend carol by dave (step-up)", multi.setUserSuspended("acme", "carol", true, "dave", true))
    check(
        "DESTRUCTION D38/F4: a suspended company admin cannot delete a group through the facade",
        !multi.deleteDeviceGroup("acme", "servers", "carol")
    )
    check(
        "DESTRUCTION D38/F4: a suspended company admin cannot suspend others through the facade",
        !multi.setUserSuspended("acme", "dave", true, "carol", true)
    )
    check("unsuspend carol by dave", multi.setUserSuspended("acme", "carol", false, "dave", true))
    check("carol's authority returns on unsuspension", multi.deleteDeviceGroup("acme", "servers", "carol"))

    // ================= offboarding: blast BEFORE fire (D14) =================
    val dir5 = Files.createTempDirectory("deskguest-wiring-offboard").toFile()
    val off = PlatformStores(dir5, cipher)
    off.addScope("acme", "company", "Acme")
    off.addUser("acme", "carol", "Carol", "human")
    off.addUser("acme", "dave", "Dave", "human")
    off.addCompanyAdmin("acme", "carol", null)
    off.addCompanyAdmin("acme", "dave", "carol")
    off.addDeviceGroup("acme", "servers", "Servers", listOf("lan"), "carol")
    off.addUserGroup("acme", "ops", "Ops", "carol")
    off.addUserToGroup("acme", "ops", "carol", "carol")
    off.addGrant("acme", "ops", "servers", setOf("use"), "carol")
    val carolDevice = enrollDevice(off, 21, "company", "servers", "Servers", "Carol Minted Server")
    check(
        "mint attribution recorded (test setup via store)",
        off.roster.recordEnrollmentMint("acme", carolDevice.deviceId, "carol")
    )
    check("carol's AI pairing added", off.addUser("acme", "carol-ai", "Carol AI", "ai", "carol"))
    check(
        "session setup: dave-hosted session with carol participating",
        off.createSession("off-sess", "acme", carolDevice.deviceId, "carol", "dave", "attended", "lan")
    )
    val blast = off.offboardPreview("acme", "carol")
    check("D14: blast list names the minted enrollment", blast?.mintedEnrollmentDeviceIds?.contains(carolDevice.deviceId) == true)
    check("D14: blast list names the owned AI", blast?.ownedAiUserIds?.contains("carol-ai") == true)
    check("D14: blast list names the company-admin seat", blast?.isCompanyAdmin == true)
    check("D14: blast list names the live-session requirement", blast?.requiresLiveSessionKill == true)
    check(
        "D14: PREVIEW DOES NOT FIRE — user still present",
        off.roster.user("carol") != null
    )
    check(
        "D14: PREVIEW DOES NOT FIRE — minted device not revoked",
        off.enrollment.byId(carolDevice.deviceId)?.revoked == false
    )
    check(
        "D14: PREVIEW DOES NOT FIRE — AI not suspended",
        off.roster.user("carol-ai")?.suspended == false
    )
    check(
        "D14: PREVIEW DOES NOT FIRE — session still live",
        off.sessionDetail("off-sess")?.session?.state == SessionStore.STATE_REQUESTED
    )
    val outcome = off.offboard("acme", "carol", "dave", true)
    check("D14: offboarding fires with step-up by a peer admin", outcome.fired)
    check("D14: fired — minted enrollment revoked", off.enrollment.byId(carolDevice.deviceId)?.revoked == true)
    check("D14: fired — owned AI suspended, not deleted", off.roster.user("carol-ai")?.suspended == true)
    check("D14: fired — the session hook ends the removed user's session", off.enforceOffboarding("off-sess"))
    check(
        "D14: fired — session ended as participant_removed",
        off.sessionDetail("off-sess")?.session?.endReason == SessionStore.REASON_PARTICIPANT_REMOVED
    )

    // ================= corrupt-store boot (destruction) =================
    val dir6 = Files.createTempDirectory("deskguest-wiring-corrupt").toFile()
    File(dir6, PlatformStores.ENROLLMENT_FILE).writeText("garbage\tline\n\u0000\u0001 binary junk\npartial")
    File(dir6, PlatformStores.ROSTER_FILE).writeText("not\ta\troster\nscope\tbroken")
    File(dir6, PlatformStores.SESSIONS_FILE).writeText("session\tbroken\tline\n%%%")
    val corrupt = PlatformStores(dir6, cipher)
    check("DESTRUCTION corrupt boot: stores open over garbage without throwing", corrupt.scopes().isEmpty())
    check("DESTRUCTION corrupt boot: session list is empty, not a crash", corrupt.allSessions().isEmpty())
    val corruptSnap = corrupt.endpointSnapshot()
    check("DESTRUCTION corrupt boot: endpoint snapshot still answers (own identity only)", corruptSnap.ownRecord == null && corruptSnap.deviceId.isNotBlank())
    // Corrupt identity file: preserved, never overwritten in place.
    val dir7 = Files.createTempDirectory("deskguest-wiring-corrupt-id").toFile()
    File(dir7, PlatformStores.IDENTITY_FILE).writeText("planted-not-a-seed")
    val corruptId = PlatformStores(dir7, cipher)
    val minted = corruptId.ownIdentity()
    check("DESTRUCTION corrupt identity: a fresh identity is minted, the plant is not used", minted.deviceId.isNotBlank())
    check(
        "DESTRUCTION corrupt identity: the corrupt file is preserved beside the new one",
        dir7.listFiles()?.any { it.name.startsWith(PlatformStores.IDENTITY_FILE + ".corrupt-") } == true
    )
    check(
        "DESTRUCTION corrupt identity: the preserved bytes are the planted ones",
        dir7.listFiles()?.firstOrNull { it.name.startsWith(PlatformStores.IDENTITY_FILE + ".corrupt-") }
            ?.readText() == "planted-not-a-seed"
    )
    val reopened = PlatformStores(dir7, cipher)
    check("DESTRUCTION corrupt identity: the replacement identity is stable", reopened.ownDeviceId() == minted.deviceId)

    // ================= source-level guarantees =================
    val endpointSrc = sourceFile("EndpointActivity.kt")
    check("source: endpoint screen exists", endpointSrc.isNotEmpty())
    check("source: endpoint screen reads through endpointSnapshot", endpointSrc.contains("endpointSnapshot"))
    for (forbidden in listOf("operatorRoster", "allSessions", "sessionsInScope", ".all()", "byGroup", "blastList", "removeUser", "operatorRoster")) {
        check("DESTRUCTION source: endpoint screen has NO '$forbidden' path", !endpointSrc.contains(forbidden))
    }
    val sessionsSrc = sourceFile("SessionsActivity.kt")
    check("source: sessions screen accepts through acceptLocal only", sessionsSrc.contains("acceptLocal"))
    check("DESTRUCTION source: sessions screen has NO channel accept path", !sessionsSrc.contains("acceptFromChannel"))
    check("DESTRUCTION source: sessions screen never names the channel origin", !sessionsSrc.contains("INITIATING"))
    check("DESTRUCTION source: sessions screen never mentions the channel at all", !sessionsSrc.lowercase().contains("channel"))
    val serviceSrc = sourceFile("server/ControlService.kt")
    check("source: ControlService hosts the platform tool host", serviceSrc.contains("PlatformToolHost"))
    check(
        "DESTRUCTION source: ControlService startup never loads the identity (0.4.3 lesson)",
        !serviceSrc.contains("ownIdentity") && !serviceSrc.contains("DeviceIdentity.load")
    )
    check(
        "DESTRUCTION source: ControlService never constructs the platform stores on startup",
        !serviceSrc.contains("PlatformStores(")
    )
    val mainSrc = sourceFile("MainActivity.kt")
    check(
        "source: home screen routes to all three platform screens",
        mainSrc.contains("EndpointActivity") && mainSrc.contains("RosterActivity") && mainSrc.contains("SessionsActivity")
    )

    if (failures > 0) {
        println("WIRING SUITE: $failures FAILURE(S)")
        kotlin.system.exitProcess(1)
    }
    println("WIRING SUITE DONE")
}

/** The personal world's host device id, re-derived after the fact. */
private fun personalWorldHost(stores: PlatformStores): String =
    stores.enrollment.all().first { it.displayName == "Host Phone" }.deviceId

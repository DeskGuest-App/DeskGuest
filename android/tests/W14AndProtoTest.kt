// Wave 14 Lane C — Android protocol items regression pins.
//  P3-F14b: STOPLOCAL wire verb removed (refused by name, no stop).
//  P3-F2:   ownerUserId trailing field (mint/redeem-carried,
//           persisted, parse-tolerant) + host binding owner check.
//  R-10:    MainActivity beginPairing is nameless (clientInfo rule).
// Args: [0] = android project dir (source pins, W10-style).
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import io.deskguest.app.transport.HostSessionBinding
import io.deskguest.app.transport.LanProtocol
import io.deskguest.app.transport.SocketStreams
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}
private var clockNow = 1_700_400_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private class W14World(dir: File, tag: String, operatorOwner: String = "") {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    val hostIdentity = DeviceIdentity.generate()
    val operatorIdentity = DeviceIdentity.generate()
    val hostDeviceId get() = hostIdentity.deviceId
    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "tor")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        enrollment.redeem(enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(hostIdentity.deviceId, hostIdentity.publicKeyBase64, "Host Device"))
        enrollment.redeem(enrollment.mint("company", "dg1", "Fleet", ownerUserId = operatorOwner),
            EnrollmentStore.EnrollingDevice(operatorIdentity.deviceId, operatorIdentity.publicKeyBase64, "Operator Device"))
    }
}

private class PipeBinding(w: W14World, id: String) {
    val binding = HostSessionBinding(w.sessions, w.enrollment,
        ownDeviceId = { w.hostDeviceId }, idFactory = { id })
    val c2hOut = PipedOutputStream(); val c2hIn = PipedInputStream(c2hOut)
    val h2cOut = PipedOutputStream(); val h2cIn = PipedInputStream(h2cOut)
    val client = SocketStreams(h2cIn, c2hOut)
    val host = SocketStreams(c2hIn, h2cOut)
    lateinit var thread: Thread
    fun start(peer: String) {
        thread = Thread { binding.serve(peer, host) }.apply { isDaemon = true; start() }
    }
    fun close() { try { c2hOut.close() } catch (_: Exception) {} }
}

object W14AndProtoTest {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val dir = Files.createTempDirectory("deskguest-w14-test").toFile()

        // ---- P3-F2: ownerUserId mint/redeem/persist/legacy ----
        run {
            val f = File(dir, "owner-enroll.tsv")
            val store = EnrollmentStore(f)
            val dev = DeviceIdentity.generate()
            val rec = store.redeem(store.mint("company", "dg1", "Fleet", ownerUserId = "user1"),
                EnrollmentStore.EnrollingDevice(dev.deviceId, dev.publicKeyBase64, "Owned Dev"))
            check("W14 P3-F2 ownerUserId is mint/redeem-carried onto the record",
                rec?.ownerUserId == "user1" && store.byId(dev.deviceId)?.ownerUserId == "user1")
            check("W14 P3-F2 ownerUserId persists across reload (trailing TSV field)",
                EnrollmentStore(f).byId(dev.deviceId)?.ownerUserId == "user1")
            val dev2 = DeviceIdentity.generate()
            val rec2 = store.redeem(store.mint("company", "dg1", "Fleet"),
                EnrollmentStore.EnrollingDevice(dev2.deviceId, dev2.publicKeyBase64, "Unowned Dev"))
            check("W14 P3-F2 a mint without owner yields an unbound (empty) owner",
                rec2?.ownerUserId == "")
            // Parse-tolerant: truncate the owned line to the pre-W14
            // 14-field shape — it must still load, owner empty.
            val lines = f.readLines().toMutableList()
            val idx = lines.indexOfFirst { it.contains(dev.deviceId) }
            val parts = lines[idx].split('\t')
            check("W14 P3-F2 setup: saved line carries owner as field 15", parts.size == 15 && parts[14] == "user1")
            lines[idx] = parts.take(14).joinToString("\t")
            f.writeText(lines.joinToString("\n"))
            val legacy = EnrollmentStore(f)
            check("W14 P3-F2 a pre-W14 line without the trailing field loads, owner empty",
                legacy.byId(dev.deviceId) != null && legacy.byId(dev.deviceId)?.ownerUserId == "")
        }

        // ---- P3-F2: host binding refuses a non-owner initiator ----
        run {
            val w = W14World(dir, "ownbind", operatorOwner = "user1")
            check("W14 P3-F2 setup: peer record carries its owner",
                w.enrollment.byId(w.operatorIdentity.deviceId)?.ownerUserId == "user1")
            val bad = PipeBinding(w, "hs-bad")
            bad.start(w.operatorIdentity.deviceId)
            LanProtocol.writeLine(bad.client.output, "SESSION co host1 host1 attended")
            check("W14 P3-F2 SESSION by a non-owner initiator is refused by name (owner_mismatch)",
                LanProtocol.readLine(bad.client.input) == "REFUSED owner_mismatch")
            bad.thread.join(3_000)
            check("W14 P3-F2 the refused SESSION created no record",
                w.sessions.session("hs-bad") == null && !bad.thread.isAlive)
            val good = PipeBinding(w, "hs-good")
            good.start(w.operatorIdentity.deviceId)
            LanProtocol.writeLine(good.client.output, "SESSION co user1 host1 attended")
            check("W14 P3-F2 SESSION by the bound owner proceeds to PENDING",
                LanProtocol.readLine(good.client.input) == "PENDING hs-good")
            good.close(); good.thread.join(3_000)
        }
        run {
            // Unbound (legacy) peer: no owner check — existing flow intact.
            val w = W14World(dir, "unbound")
            val p = PipeBinding(w, "hs-legacy")
            p.start(w.operatorIdentity.deviceId)
            LanProtocol.writeLine(p.client.output, "SESSION co user1 host1 attended")
            check("W14 P3-F2 an unbound peer's SESSION is not owner-refused (legacy tolerant)",
                LanProtocol.readLine(p.client.input) == "PENDING hs-legacy")
            p.close(); p.thread.join(3_000)
        }

        // ---- P3-F14b: STOPLOCAL removed ----
        run {
            val w = W14World(dir, "stoplocal")
            val p = PipeBinding(w, "hs-sl")
            p.start(w.operatorIdentity.deviceId)
            LanProtocol.writeLine(p.client.output, "SESSION co user1 host1 attended")
            check("W14 P3-F14b setup: PENDING", LanProtocol.readLine(p.client.input) == "PENDING hs-sl")
            check("W14 P3-F14b setup: local accept + start",
                w.sessions.acceptSession("hs-sl", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                    w.sessions.startSession("hs-sl", "host1"))
            LanProtocol.writeLine(p.client.output, "STOPLOCAL")
            check("W14 P3-F14b STOPLOCAL is refused with the named reason stoplocal_removed",
                LanProtocol.readLine(p.client.input) == "REFUSED stoplocal_removed")
            check("W14 P3-F14b STOPLOCAL did NOT stop the session",
                w.sessions.session("hs-sl")?.state == SessionStore.STATE_ACTIVE)
            LanProtocol.writeLine(p.client.output, "PING")
            check("W14 P3-F14b the channel stays open after the refused verb",
                LanProtocol.readLine(p.client.input) == "PONG")
            LanProtocol.writeLine(p.client.output, "STOP host1")
            check("W14 P3-F14b the host-gated STOP verb still works",
                LanProtocol.readLine(p.client.input) == "STOPPED" &&
                    w.sessions.session("hs-sl")?.state == SessionStore.STATE_ENDED)
            p.thread.join(3_000)
            val src = File(root, "app/src/main/java/io/deskguest/app/transport/HostListenerBinding.kt").readText()
            check("W14 P3-F14b source: no wire path calls stopLocalSession from STOPLOCAL",
                !src.contains("val ok = sessions.stopLocalSession(sessionId)\n                    LanProtocol.writeLine(channel.output, if (ok) \"STOPPED\"") &&
                    src.contains("REFUSED stoplocal_removed"))
        }

        // ---- R-10: MainActivity name path ----
        run {
            val main = File(root, "app/src/main/java/io/deskguest/app/MainActivity.kt").readText()
            check("W14 R-10 MainActivity pairing begins nameless (clientInfo rule, as the wizard)",
                // W98 amendment (recorded, W97 precedent): the mint call
                // gained its second argument — the connection-path
                // setting bound at mint (S09(b)). The nameless rule this
                // pin guards is the FIRST argument, still exactly "".
                main.contains("store.beginPairing(\"\", mintConnection)"))
            check("W14 R-10 MainActivity no longer reads KEY_AGENT_NAME as a pairing name",
                !main.contains("getString(WizardActivity.KEY_AGENT_NAME") && !main.contains("?: \"My AI\""))
            check("W14 R-10 (FR-123) MainActivity display falls back to the unnamed-pairing label, never a typed or generic one",
                main.contains("R.string.pairing_unnamed_label") && !main.contains("?: \"Your AI\"") &&
                    !main.contains(".ifBlank { \"Your AI\" }"))
            val wiz = File(root, "app/src/main/java/io/deskguest/app/WizardActivity.kt").readText()
            check("W14 R-10 the KEY_AGENT_NAME constant is preserved as W10-B left it",
                wiz.contains("const val KEY_AGENT_NAME = \"agent_name\""))
        }

        dir.deleteRecursively()
        println("W14AndProtoTest: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

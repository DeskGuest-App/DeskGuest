import io.deskguest.app.server.ConnectionPath
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/**
 * W98 / S09(b) Android parity pins: the per-pairing connection-path
 * control — policy semantics over Android's real arrival paths
 * (mesh + loopback), mint binding, the ONE store apply path with
 * audit-on-change-and-refusal, persistence (pre-W98 stores restore
 * AUTO; corrupt stored records restore FAIL-CLOSED — amended by
 * W108, see the corrupt pin below), and CHOKE-POINT proofs at the
 * real McpCore: an arrival over an excluded path is refused (401,
 * audited, label unmoved), never widened; the pair door refuses
 * before consuming the code.
 * The Android mirror of the Windows W97 pins.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private fun fakeHost(): McpCore.ToolHost = object : McpCore.ToolHost {
    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "device_info", "fake device info", "observe",
            JSONObject().put("type", "object"),
            run = { "{\"model\":\"TestPhone\"}" }
        )
    )
}

private fun call(core: McpCore, body: String, token: String?, arrival: String?): McpCore.Reply =
    core.handle(body, token, null, arrival)

private const val PING = """{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"""
private const val LIST = """{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"""

fun main(args: Array<String>) {
    val cp = ConnectionPath
    val auto = ConnectionPath.Setting.AUTO
    val meshOnly = ConnectionPath.Setting(cp.MODE_RESTRICTED, setOf(cp.PATH_MESH))
    val loopOnly = ConnectionPath.Setting(cp.MODE_RESTRICTED, setOf(cp.PATH_LOOPBACK))
    val pinMesh = ConnectionPath.Setting(cp.MODE_MANUAL, pin = cp.PATH_MESH)
    val pinLoop = ConnectionPath.Setting(cp.MODE_MANUAL, pin = cp.PATH_LOOPBACK)

    // ---- The catalogue is Android's real pairing paths, no imports ----
    check("catalogue: exactly mesh + loopback, in that order",
        cp.PATHS.map { it.id } == listOf("mesh", "loopback"))
    check("catalogue: real plain names",
        cp.PATHS[0].name == "Private mesh (Tailscale)" &&
            cp.PATHS[1].name == "This phone only (loopback)")
    check("catalogue: no Windows-only rungs (lan/hub/ipv6/ownpath/tor have no Android pairing listener)",
        listOf("lan", "hub", "ipv6", "ownpath", "tor").none { it in cp.PATH_IDS })

    // ---- Allows matrix ----
    check("allows: AUTO allows both real paths",
        cp.allows(auto, "mesh") && cp.allows(auto, "loopback"))
    check("allows: restricted allows exactly its subset",
        cp.allows(meshOnly, "mesh") && !cp.allows(meshOnly, "loopback") &&
            cp.allows(loopOnly, "loopback") && !cp.allows(loopOnly, "mesh"))
    check("allows: manual pin binds exactly",
        cp.allows(pinMesh, "mesh") && !cp.allows(pinMesh, "loopback") &&
            cp.allows(pinLoop, "loopback") && !cp.allows(pinLoop, "mesh"))
    check("allows: an empty or unknown arrival claim is never allowed, in any mode",
        !cp.allows(auto, null) && !cp.allows(auto, "") && !cp.allows(auto, "lan") &&
            !cp.allows(meshOnly, "tor") && !cp.allows(pinMesh, null))
    check("allows: arrival spelling is case-insensitive",
        cp.allows(meshOnly, "MESH") && cp.allows(pinLoop, " Loopback "))

    // ---- Validate: invalid values refused, never honored ----
    check("validate: the three honest forms pass",
        cp.validate(auto) == null && cp.validate(meshOnly) == null && cp.validate(pinMesh) == null)
    check("validate: unknown mode refused",
        cp.validate(ConnectionPath.Setting("sometimes")) != null)
    check("validate: unknown path in a subset refused (a Windows rung name is not honored)",
        cp.validate(ConnectionPath.Setting(cp.MODE_RESTRICTED, setOf("mesh", "lan"))) != null)
    check("validate: empty restricted subset refused",
        cp.validate(ConnectionPath.Setting(cp.MODE_RESTRICTED, emptySet())) != null)
    check("validate: manual without a pin refused",
        cp.validate(ConnectionPath.Setting(cp.MODE_MANUAL)) != null)
    check("validate: manual with an unknown pin refused",
        cp.validate(ConnectionPath.Setting(cp.MODE_MANUAL, pin = "hub")) != null)

    // ---- Describe / normalize ----
    check("describe: plain forms for all three modes",
        cp.describe(auto) == "Auto — any working path" &&
            cp.describe(loopOnly) == "Auto, restricted to This phone only (loopback)" &&
            cp.describe(pinMesh) == "Manual — pinned to Private mesh (Tailscale)")
    check("normalize: case + catalogue order, unknown ids survive to be refused",
        cp.normalize(ConnectionPath.Setting("RESTRICTED", setOf("LOOPBACK", "mesh"))).let {
            it.mode == "restricted" && it.rungs.toList() == listOf("mesh", "loopback")
        } && cp.normalize(ConnectionPath.Setting("restricted", setOf("zzz"))).rungs == setOf("zzz"))

    // ---- Store: mint binding, the ONE apply path, audit ----
    val dir = Files.createTempDirectory("deskguest-w98-test").toFile()
    val file = File(dir, "pairings.tsv")
    val store = PairingStore(file)
    val audits = mutableListOf<Triple<String, Boolean, String>>()
    store.onConnectionAudit = { name, ok, detail -> audits.add(Triple(name, ok, detail)) }

    val plain = store.redeem(store.beginPairing("Plain"), setOf("observe"))!!
    check("store: a pairing minted with no choice carries AUTO",
        plain.connection == ConnectionPath.Setting.AUTO)

    val bound = store.redeem(
        store.beginPairing("Bound", loopOnly), setOf("observe")
    )!!
    check("store: the mint-bound setting is stamped at redemption",
        bound.connection == loopOnly)
    check("store: the pending binding resets after redemption (next mint is AUTO again)",
        store.pendingConnectionSetting() == ConnectionPath.Setting.AUTO)

    var mintThrew = false
    try {
        store.beginPairing("Bad", ConnectionPath.Setting(cp.MODE_RESTRICTED, emptySet()))
    } catch (e: IllegalArgumentException) {
        mintThrew = e.message?.contains("refused") == true
    }
    check("store: an invalid mint setting refuses the mint, never widens to AUTO",
        mintThrew && store.currentCode() == null)

    val applied = store.updateConnectionPath(plain.token, pinLoop)
    check("store: updateConnectionPath applies a valid setting",
        applied.pairing?.connection == pinLoop && applied.refusal == null &&
            store.pairingForToken(plain.token)?.connection == pinLoop)
    check("store: the apply is audited with old -> new settings described",
        audits.any {
            it.second && it.third.contains("Auto — any working path") &&
                it.third.contains("Manual — pinned to This phone only (loopback)")
        })
    val refused = store.updateConnectionPath(
        plain.token, ConnectionPath.Setting(cp.MODE_MANUAL)
    )
    check("store: a pin-less manual proposal is refused and state is untouched",
        refused.pairing == null && refused.refusal != null &&
            store.pairingForToken(plain.token)?.connection == pinLoop)
    check("store: the refusal itself is audited (ok=false, reason named)",
        audits.any { !it.second && it.third.contains("refused") })
    val miss = store.updateConnectionPath("deadbeef", auto)
    check("store: unknown token is a clean miss (no pairing, no refusal)",
        miss.pairing == null && miss.refusal == null)

    // Persistence: the setting survives reload.
    val reloaded = PairingStore(file)
    check("store: applied connection setting survives reload",
        reloaded.pairingForToken(plain.token)?.connection == pinLoop &&
            reloaded.pairingForToken(bound.token)?.connection == loopOnly)

    // Pre-W98 store (9 fields): restores as AUTO.
    val legacyFile = File(dir, "legacy.tsv")
    legacyFile.writeText(
        listOf(
            "Legacy", "legacytoken123", "observe", "1700000000000", "Agent", "1.0",
            "observe", "see", ""
        ).joinToString("\t")
    )
    check("store: a pre-W98 (9-field) record restores as AUTO",
        PairingStore(legacyFile).pairingForToken("legacytoken123")?.connection ==
            ConnectionPath.Setting.AUTO)

    // Corrupt stored restriction (restricted with an empty subset).
    // PIN AMENDED by W108 (2026-11-24, W105-C5 verified real in
    // W106): this pin previously asserted the corrupt record
    // restores as AUTO — the fail-OPEN defect itself (a corrupt
    // RESTRICTED/MANUAL record silently became the widest mode and
    // was then overwritten on the next save). The amended pin
    // asserts the fail-CLOSED restore: Setting.FAIL_CLOSED
    // (needs-attention, no path allowed) until the owner re-sets
    // it. The missing-record migration to AUTO above is unchanged.
    val corruptFile = File(dir, "corrupt.tsv")
    corruptFile.writeText(
        listOf(
            "Corrupt", "corrupttoken123", "observe", "1700000000000", "Agent", "1.0",
            "observe", "see", "", "restricted", "", ""
        ).joinToString("\t")
    )
    check("store: a corrupt stored restriction restores FAIL-CLOSED (needs attention, no path), never AUTO [pin amended by W108: was AUTO]",
        PairingStore(corruptFile).pairingForToken("corrupttoken123")?.connection ==
            ConnectionPath.Setting.FAIL_CLOSED)

    // Last-connection label state: allowed arrivals only.
    check("label: nothing noted before any connection",
        store.lastConnection(plain.token) == null)
    store.noteConnection(plain.token, "mesh")
    check("label: a noted arrival reads back with its path",
        store.lastConnection(plain.token)?.first == "mesh")
    store.noteConnection(plain.token, "carrier-pigeon")
    check("label: an unknown path claim is never noted",
        store.lastConnection(plain.token)?.first == "mesh")
    store.noteConnection("deadbeef", "mesh")
    check("label: noting for an unknown token is a no-op",
        store.lastConnection("deadbeef") == null)

    // ---- Choke point: the real McpCore, real arrivals ----
    val coreDir = Files.createTempDirectory("deskguest-w98-core").toFile()
    val coreStore = PairingStore(File(coreDir, "pairings.tsv"))
    val core = McpCore(coreStore, fakeHost())
    val coreAudits = mutableListOf<Triple<String, Boolean, String>>()
    core.connectionAuditSink = { name, ok, detail -> coreAudits.add(Triple(name, ok, detail)) }

    fun pairOver(setting: ConnectionPath.Setting, arrival: String?): PairingStore.Pairing {
        val code = coreStore.beginPairing("Choke", setting)
        val reply = call(
            core,
            """{"jsonrpc":"2.0","id":9,"method":"pair","params":{"code":"$code"}}""",
            null, arrival
        )
        val token = JSONObject(reply.body!!).getJSONObject("result").getString("token")
        return coreStore.pairingForToken(token)!!
    }

    // AUTO pairing: every real path works; arrivals move the label.
    val autoPairing = pairOver(auto, "mesh")
    check("choke: AUTO pairing lists tools over mesh and loopback",
        call(core, LIST, autoPairing.token, "mesh").httpStatus == 200 &&
            call(core, LIST, autoPairing.token, "loopback").httpStatus == 200)
    check("choke: an allowed arrival notes the label",
        coreStore.lastConnection(autoPairing.token)?.first == "loopback")
    check("choke: a null arrival (in-process) is not policed",
        call(core, LIST, autoPairing.token, null).httpStatus == 200)

    // Restricted pairing: excluded arrival refused at the choke point.
    val loopPairing = pairOver(loopOnly, "loopback")
    val refusedReply = call(core, LIST, loopPairing.token, "mesh")
    check("choke: restricted pairing over its excluded path gets the 401 refusal surface",
        refusedReply.httpStatus == 401 &&
            (refusedReply.body ?: "").contains("this pairing may not connect over this path"))
    check("choke: the refusal is audited, naming the arrival and the setting",
        coreAudits.any {
            !it.second && it.third.contains("Private mesh (Tailscale)") &&
                it.third.contains("restricted to This phone only (loopback)")
        })
    check("choke: a refused arrival does NOT move the current-path label",
        coreStore.lastConnection(loopPairing.token)?.first == "loopback")
    check("choke: the same token over its allowed path works (no widening needed, none done)",
        call(core, LIST, loopPairing.token, "loopback").httpStatus == 200)
    check("choke: ping bearing the token is gated the same way",
        call(core, PING, loopPairing.token, "mesh").httpStatus == 401 &&
            call(core, PING, loopPairing.token, "loopback").httpStatus == 200)
    check("choke: the SSE leg's path check refuses excluded and allows included",
        !core.isPathAllowed(loopPairing.token, "mesh") &&
            core.isPathAllowed(loopPairing.token, "loopback") &&
            core.isPathAllowed(loopPairing.token, null))

    // Manual pin binds exactly.
    val pinned = pairOver(pinMesh, "mesh")
    check("choke: manual pin allows exactly its path",
        call(core, LIST, pinned.token, "mesh").httpStatus == 200 &&
            call(core, LIST, pinned.token, "loopback").httpStatus == 401)

    // A restriction applied later bites the EXISTING token — no re-pairing.
    coreStore.updateConnectionPath(autoPairing.token, loopOnly)
    check("choke: a restriction applied later bites the existing token's next request",
        call(core, LIST, autoPairing.token, "mesh").httpStatus == 401 &&
            call(core, LIST, autoPairing.token, "loopback").httpStatus == 200)

    // ---- Pair door: refused before consumption, code stays alive ----
    val doorCode = coreStore.beginPairing("Door", loopOnly)
    val doorReply = call(
        core,
        """{"jsonrpc":"2.0","id":10,"method":"pair","params":{"code":"$doorCode"}}""",
        null, "mesh"
    )
    check("door: an excluded-path redemption is refused with the path error",
        JSONObject(doorReply.body!!).getJSONObject("error").getInt("code") == -32003 &&
            JSONObject(doorReply.body!!).getJSONObject("error").getString("message")
                .contains("may not connect over this path"))
    check("door: the refusal is audited as a pair-door refusal",
        coreAudits.any { !it.second && it.third.contains("pairing_exchange_refused_by_path") })
    check("door: the code is NOT consumed by the refusal",
        coreStore.currentCode() == doorCode)
    // Six more refused attempts must not burn the code (no brake counting).
    repeat(6) {
        call(
            core,
            """{"jsonrpc":"2.0","id":11,"method":"pair","params":{"code":"$doorCode"}}""",
            null, "mesh"
        )
    }
    val doorOk = call(
        core,
        """{"jsonrpc":"2.0","id":12,"method":"pair","params":{"code":"$doorCode"}}""",
        null, "loopback"
    )
    check("door: after 7 refused attempts the code still redeems over its allowed path",
        JSONObject(doorOk.body!!).has("result") &&
            coreStore.pairingForToken(
                JSONObject(doorOk.body!!).getJSONObject("result").getString("token")
            )?.connection == loopOnly)
    check("door: the redemption notes the arrival on the label",
        coreStore.lastConnection(
            JSONObject(doorOk.body!!).getJSONObject("result").getString("token")
        )?.first == "loopback")

    // ---- Source pins: enforcement and surface wired as built ----
    val root = args.getOrElse(0) { "." }
    fun src(path: String) = File(root, path).readText()
    val http = src("app/src/main/java/io/deskguest/app/server/McpHttpServer.kt")
    val coreSrc = src("app/src/main/java/io/deskguest/app/server/McpCore.kt")
    val uikit = src("app/src/main/java/io/deskguest/app/ui/UiKit.kt")
    val main = src("app/src/main/java/io/deskguest/app/MainActivity.kt")
    val wizard = src("app/src/main/java/io/deskguest/app/WizardActivity.kt")
    val service = src("app/src/main/java/io/deskguest/app/server/ControlService.kt")
    check("wiring: the HTTP server classifies arrival by listener and hands it to the core",
        http.contains("ConnectionPath.PATH_LOOPBACK") && http.contains("ConnectionPath.PATH_MESH") &&
            http.contains("core.handle(body, token, sessionHeader, arrivalPath)"))
    check("wiring: the SSE leg enforces the path before opening",
        http.contains("core.isPathAllowed(token, arrivalPath)"))
    check("wiring: the core audits pair-door refusals under the named kind detail",
        coreSrc.contains("pairing_exchange_refused_by_path"))
    check("wiring: audit hooks land in the AuditStore as pairing_connection",
        service.contains("onConnectionAudit") && service.contains("connectionAuditSink") &&
            service.contains("\"pairing_connection\""))
    check("surface: the editor + mint picker exist with the never-widen line",
        uikit.contains("fun connectionPathEditor") && uikit.contains("fun connectionPathMintPicker") &&
            uikit.contains("NEVER_WIDEN_LINE") && uikit.contains("Path setting now:"))
    check("surface: both homes apply only through updateConnectionPath",
        main.contains("updateConnectionPath") && wizard.contains("updateConnectionPath"))
    check("surface: both mint flows bind the choice at beginPairing (default AUTO field)",
        main.contains("beginPairing(\"\", mintConnection)") &&
            wizard.contains("beginWizardPairing") &&
            main.contains("ConnectionPath.Setting.AUTO") &&
            wizard.contains("ConnectionPath.Setting.AUTO"))
    check("surface: the current-path label reads live last-arrival state in both homes",
        main.contains("lastConnection(pairing.token)") &&
            wizard.contains("lastConnection(pairing.token)"))

    if (failures > 0) {
        println("W98: $failures FAILURES")
        kotlin.system.exitProcess(1)
    }
    println("W98: ALL CHECKS PASS")
}

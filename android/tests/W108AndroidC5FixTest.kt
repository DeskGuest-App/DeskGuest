import io.deskguest.app.server.ConnectionPath
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/**
 * W108 / W105-C5 (verified real in W106) Android fix pins:
 *
 * 1. FAIL-CLOSED CORRUPT RESTORE — the missing/corrupt cases are
 *    split: a record with NO connection fields (genuine pre-W98)
 *    still migrates to AUTO; a PRESENT-BUT-CORRUPT record
 *    (restricted / manual / auto, or truncated) restores as
 *    Setting.FAIL_CLOSED — no path allowed, surface says the
 *    setting needs attention, the restore is audited, and the
 *    original corrupt fields are QUARANTINED: a later save/export
 *    writes them back verbatim instead of overwriting them. The
 *    owner's re-set through updateConnectionPath is the repair.
 *    (This amends W98's pinned-in corrupt-restore-to-AUTO rule;
 *    the amendment is recorded at the W98 pin itself.)
 *
 * 2. MID-STREAM RE-CHECK — McpHttpServer's SSE loop re-checks
 *    McpCore.isPathAllowed on its heartbeat cadence and breaks
 *    (closing the stream) when the arrival path has become
 *    excluded; the refusal is audited by the same
 *    pairing_connection refusal family as attach-time refusals.
 *    The loop itself needs a live socket (JVM loopback connects
 *    are reset in this sandbox), so the loop is pinned by source
 *    and the re-check predicate — the exact call the heartbeat
 *    makes — is proven functionally at the real McpCore.
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

private const val LIST = """{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"""

private fun record(
    name: String, token: String, connectionFields: List<String>?
): String {
    val base = listOf(
        name, token, "observe", "1700000000000", "Agent", "1.0",
        "observe", "see", ""
    )
    return (if (connectionFields == null) base else base + connectionFields)
        .joinToString("\t")
}

private fun loadSetting(dir: File, fileName: String, line: String, token: String):
    Pair<ConnectionPath.Setting?, PairingStore> {
    val file = File(dir, fileName)
    file.writeText(line)
    val store = PairingStore(file)
    return store.pairingForToken(token)?.connection to store
}

fun main(args: Array<String>) {
    val cp = ConnectionPath
    val dir = Files.createTempDirectory("deskguest-w108-test").toFile()
    val failClosed = ConnectionPath.Setting.FAIL_CLOSED

    // ---- Corrupt cases: every present-but-corrupt shape fails closed ----
    val corruptCases = listOf(
        Triple("restricted with an empty subset", listOf("restricted", "", ""), "tok-corrupt-a"),
        Triple("restricted with an unknown rung", listOf("restricted", "mesh,lan", ""), "tok-corrupt-b"),
        Triple("manual with no pin", listOf("manual", "", ""), "tok-corrupt-c"),
        Triple("manual with an unknown pin", listOf("manual", "", "hub"), "tok-corrupt-d"),
        Triple("unknown mode string (corrupt auto record)", listOf("autoo", "", ""), "tok-corrupt-e"),
        Triple("auto with an unknown stored rung", listOf("auto", "zzz", ""), "tok-corrupt-f"),
        Triple("truncated record (mode field only)", listOf("restricted"), "tok-corrupt-g")
    )
    corruptCases.forEachIndexed { i, (label, fields, token) ->
        val (setting, _) = loadSetting(
            dir, "corrupt-$i.tsv", record("Corrupt$i", token, fields), token
        )
        check("corrupt restore: $label restores FAIL-CLOSED (needs attention)",
            setting == failClosed && setting?.needsAttention == true)
        check("corrupt restore: $label allows NO path (mesh and loopback both refused)",
            setting != null && !cp.allows(setting, "mesh") && !cp.allows(setting, "loopback"))
    }
    check("corrupt restore: the surface description says needs attention, never a chosen mode",
        cp.describe(failClosed).contains("needs attention") &&
            !cp.describe(failClosed).contains("Auto — any working path"))
    check("corrupt restore: the fail-closed marker is not a valid proposal",
        cp.validate(failClosed) != null)

    // ---- Missing cases: genuine pre-W98 records still migrate to AUTO ----
    val (missingSetting, _) = loadSetting(
        dir, "missing.tsv", record("Legacy", "tok-missing", null), "tok-missing"
    )
    check("missing restore: a record with no connection fields still migrates to AUTO",
        missingSetting == ConnectionPath.Setting.AUTO)
    check("missing restore: the migrated AUTO allows both real paths",
        missingSetting != null && cp.allows(missingSetting, "mesh") &&
            cp.allows(missingSetting, "loopback"))
    val legacyFile = File(dir, "legacy4.tsv")
    legacyFile.writeText(
        listOf("Old", "tok-legacy4", "observe", "1700000000000").joinToString("\t")
    )
    check("missing restore: a legacy 4-field record restores as AUTO",
        PairingStore(legacyFile).pairingForToken("tok-legacy4")?.connection ==
            ConnectionPath.Setting.AUTO)

    // ---- The restore is audited (queued at load, flushed when the hook lands) ----
    val auditFile = File(dir, "audit.tsv")
    auditFile.writeText(record("Audited", "tok-audited", listOf("manual", "", "hub")))
    val auditStore = PairingStore(auditFile)
    val restoreAudits = mutableListOf<Triple<String, Boolean, String>>()
    auditStore.onConnectionAudit = { name, ok, detail -> restoreAudits.add(Triple(name, ok, detail)) }
    check("corrupt restore: the restore is audited (ok=false, corruption + fail-closed named)",
        restoreAudits.any {
            !it.second && it.first == "Audited" &&
                it.third.contains("corrupt connection setting restored fail-closed") &&
                it.third.contains("needs attention")
        })

    // ---- Quarantine: a save/export does NOT overwrite the corrupt fields ----
    val qFile = File(dir, "quarantine.tsv")
    qFile.writeText(record("Quarantined", "tok-quarantine", listOf("manual", "", "hub")))
    val qStore = PairingStore(qFile)
    check("quarantine: the original corrupt fields are held by the store",
        qStore.quarantinedConnection("tok-quarantine") == Triple("manual", "", "hub"))
    // Any ordinary save (here: an agent-info bind) re-exports the store.
    qStore.bindAgentInfo("tok-quarantine", "Agent2", "1.1")
    val exportedFields = qFile.readText().trim().split('\t')
    check("quarantine: a save does NOT overwrite the corrupt record (original fields written back)",
        exportedFields.size >= 12 && exportedFields[9] == "manual" &&
            exportedFields[10] == "" && exportedFields[11] == "hub")
    check("quarantine: reloading the exported store still restores FAIL-CLOSED",
        PairingStore(qFile).pairingForToken("tok-quarantine")?.connection == failClosed)

    // ---- Repair: the owner re-setting the value is the repair path ----
    val loopOnly = ConnectionPath.Setting(cp.MODE_RESTRICTED, setOf(cp.PATH_LOOPBACK))
    val repaired = qStore.updateConnectionPath("tok-quarantine", loopOnly)
    check("repair: updateConnectionPath applies over a fail-closed restore and clears quarantine",
        repaired.pairing?.connection == loopOnly && repaired.refusal == null &&
            qStore.quarantinedConnection("tok-quarantine") == null)
    val repairedFields = qFile.readText().trim().split('\t')
    check("repair: the repaired setting is what the store now exports (and reloads)",
        repairedFields[9] == "restricted" && repairedFields[10] == "loopback" &&
            PairingStore(qFile).pairingForToken("tok-quarantine")?.connection == loopOnly)

    // ---- Choke point: a corrupt-restricted pairing stays refused over mesh ----
    val coreDir = Files.createTempDirectory("deskguest-w108-core").toFile()
    val coreFile = File(coreDir, "pairings.tsv")
    coreFile.writeText(record("Stuck", "tok-stuck", listOf("restricted", "mesh,lan", "")))
    val coreStore = PairingStore(coreFile)
    val core = McpCore(coreStore, fakeHost())
    val coreAudits = mutableListOf<Triple<String, Boolean, String>>()
    core.connectionAuditSink = { name, ok, detail -> coreAudits.add(Triple(name, ok, detail)) }
    check("choke: corrupt-restricted pairing is refused over mesh (401)",
        core.handle(LIST, "tok-stuck", null, "mesh").httpStatus == 401)
    check("choke: corrupt-restricted pairing is refused over loopback too (no path allowed)",
        core.handle(LIST, "tok-stuck", null, "loopback").httpStatus == 401)
    check("choke: the refusal is audited in the pairing_connection refusal family, naming needs attention",
        coreAudits.any {
            !it.second && it.third.contains("arrived over") &&
                it.third.contains("needs attention")
        })

    // ---- Mid-stream: the heartbeat re-check predicate flips and audits ----
    val streamStore = PairingStore(File(coreDir, "stream.tsv"))
    val streamCore = McpCore(streamStore, fakeHost())
    val streamAudits = mutableListOf<Triple<String, Boolean, String>>()
    streamCore.connectionAuditSink = { name, ok, detail -> streamAudits.add(Triple(name, ok, detail)) }
    val streamPairing = streamStore.redeem(
        streamStore.beginPairing("Streamer", ConnectionPath.Setting.AUTO), setOf("observe")
    )!!
    check("stream: at attach the AUTO pairing is path-allowed over mesh",
        streamCore.isPathAllowed(streamPairing.token, "mesh"))
    // The owner tightens the setting while the stream is open.
    streamStore.updateConnectionPath(streamPairing.token, loopOnly)
    check("stream: the heartbeat re-check (isPathAllowed) now refuses the open stream's mesh arrival",
        !streamCore.isPathAllowed(streamPairing.token, "mesh"))
    check("stream: the mid-stream refusal is audited with the attach-time refusal detail family",
        streamAudits.any {
            !it.second && it.third.contains("arrived over Private mesh (Tailscale)") &&
                it.third.contains("restricted to This phone only (loopback)")
        })
    check("stream: the same stream's arrival over the still-allowed path remains allowed",
        streamCore.isPathAllowed(streamPairing.token, "loopback"))

    // ---- Source pins: the SSE loop actually re-checks per heartbeat ----
    val root = args.getOrElse(0) { "." }
    val http = File(root, "app/src/main/java/io/deskguest/app/server/McpHttpServer.kt").readText()
    val occurrences = http.split("core.isPathAllowed(token, arrivalPath)").size - 1
    check("stream wiring: isPathAllowed is consulted at attach AND again in the stream loop (>=2 calls)",
        occurrences >= 2)
    check("stream wiring: the loop's re-check is on the heartbeat cadence and breaks the loop",
        http.contains("per-heartbeat connection-path") &&
            http.contains("if (arrivalPath != null && !core.isPathAllowed(token, arrivalPath))"))
    val uikit = File(root, "app/src/main/java/io/deskguest/app/ui/UiKit.kt").readText()
    check("surface: the editor carries the needs-attention line for a fail-closed restore",
        uikit.contains("needsAttention") &&
            uikit.contains("could not be read, so no path is") &&
            uikit.contains("allowed until you choose a setting and apply it"))

    if (failures > 0) {
        println("W108: $failures FAILURES")
        kotlin.system.exitProcess(1)
    }
    println("W108: ALL CHECKS PASS")
}

import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.rmmspine.SignedCommandClasses
import io.agenticcontrol.app.rmmspine.SignedCommandSigner
import io.agenticcontrol.app.server.CommandGateWiring
import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.PairingStore
import org.json.JSONObject
import java.io.File
import java.util.Base64

/** Lane INT task 6 (2026-11-21) — ControlService's RMM-03 gate
 *  wiring, proven through the exact factory the service calls
 *  (CommandGateWiring.build over a files dir):
 *  (a) no customer key registered -> gate present, state names
 *      fail-closed, every hub command envelope refuses;
 *  (b) registered customer key -> a correctly signed envelope
 *      verifies through the service-constructed gate and executes
 *      its payload; forged / attacker envelopes refuse;
 *  (c) broken key file -> fail-closed, state names the breakage. */
private var gateFailures = 0
private var gatePasses = 0
private fun gcheck(name: String, cond: Boolean) {
    if (cond) { println("PASS  $name"); gatePasses++ } else { println("FAIL  $name"); gateFailures++ }
}

private val GT0 = 1_800_000_000_000L

private class GateFixture(val dir: File) {
    var shellRan: String? = null
    val store = PairingStore(File(dir, "pairings.tsv"))
    val host = object : McpCore.ToolHost {
        override fun tools(): List<McpCore.ToolDef> = listOf(
            McpCore.ToolDef("shell_exec", "fake shell", "drive", JSONObject().put("type", "object"),
                run = { a -> shellRan = a.optString("command", ""); "ran: ${a.optString("command", "")}" }),
            McpCore.ToolDef("device_info", "fake info", "observe", JSONObject().put("type", "object"),
                run = { "{\"model\":\"TestPhone\"}" })
        )
    }
    fun core(wiring: CommandGateWiring.Wired): McpCore = McpCore(
        pairingStore = store, toolHost = host, serverVersion = "test",
        commandGate = wiring.gate, commandGateStateDetail = wiring.stateDetail, clockMs = { GT0 }
    )
    fun pairedToken(core: McpCore): String {
        val code = store.beginPairing("tester")
        val reply = core.handle("""{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null)
        val token = JSONObject(reply.body!!).getJSONObject("result").getString("token")
        store.setAccess(token, PairingStore.ACCESS_FULL, emptySet())
        return token
    }
    fun call(core: McpCore, token: String, tool: String, args: JSONObject, id: Int): Boolean {
        val body = JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", "tools/call")
            .put("params", JSONObject().put("name", tool).put("arguments", args)).toString()
        val reply = core.handle(body, token)
        return JSONObject(reply.body!!).getJSONObject("result").getBoolean("isError")
    }
}

private fun freshDir(tag: String): File =
    File(System.getProperty("java.io.tmpdir"), "acp-int-gate-$tag-" + System.nanoTime()).apply { mkdirs() }

fun main() {
    val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
    val attacker = DeviceIdentity.fromSeed(ByteArray(32) { 99 })
    val customerSigner = SignedCommandSigner(customer)
    val attackerSigner = SignedCommandSigner(attacker)

    // ---------- (a) no key registered: present-but-refusing ----------
    run {
        val dir = freshDir("nokey")
        val wiring = CommandGateWiring.build(dir, ChainedAuditLog())
        val f = GateFixture(dir)
        val core = f.core(wiring)
        gcheck("INT-GATE gate is present with no key registered (state is WIRED, not UNWIRED)",
            core.commandGateState.startsWith("WIRED"))
        gcheck("INT-GATE no-key state honestly names fail-closed + no registered key",
            core.commandGateState.contains("fail-closed") && core.commandGateState.contains("no customer command key is registered"))
        val token = f.pairedToken(core)
        val env = customerSigner.sign(SignedCommandClasses.SHELL_EXEC, "echo signed".toByteArray(), GT0, 600_000, "g-a1")
        val errSigned = f.call(core, token, "shell_exec",
            JSONObject().put("command", "echo unsigned").put("_signed_command", env.toJson()), 2)
        gcheck("INT-GATE (a) validly-signed envelope from an UNREGISTERED key refuses", errSigned && f.shellRan == null)
        // REPAIRED by laneW2-andfix1 (bd-and-core F1, 2026-11-22),
        // disclosed: the gate's scope changed by design. The old
        // assertion ("unsigned hub command refuses") pinned the
        // pre-fix behaviour the breakdown proved broken —
        // McpCore could not distinguish a hub-originated call from
        // a locally paired one, so envelope-less local control was
        // dead. New law: the gate governs calls that PRESENT an
        // envelope (above: an unregistered key still refuses);
        // an envelope-less call from a code-paired full-access
        // token runs under pairing + capability + approval-gate
        // authority, exactly like the local transports.
        val errUnsigned = f.call(core, token, "shell_exec", JSONObject().put("command", "echo unsigned"), 3)
        gcheck("INT-GATE (a) envelope-less locally-paired call runs under pairing authority (bd-and-core F1 scope)",
            !errUnsigned && f.shellRan == "echo unsigned")
        dir.deleteRecursively()
    }

    // ---------- (b) registered key: verifies; forged refuses ----------
    run {
        val dir = freshDir("key")
        File(dir, CommandGateWiring.KEYS_FILE_NAME)
            .writeText("current ${Base64.getEncoder().encodeToString(customer.publicKey)}\n")
        val wiring = CommandGateWiring.build(dir, ChainedAuditLog())
        val f = GateFixture(dir)
        val core = f.core(wiring)
        gcheck("INT-GATE registered-key state names WIRED + the key id",
            core.commandGateState.startsWith("WIRED:") && core.commandGateState.contains(customerSigner.keyId))
        val token = f.pairedToken(core)
        val env = customerSigner.sign(SignedCommandClasses.SHELL_EXEC, "echo signed".toByteArray(), GT0, 600_000, "g-b1")
        val errSigned = f.call(core, token, "shell_exec",
            JSONObject().put("command", "echo UNSIGNED-ARG").put("_signed_command", env.toJson()), 2)
        gcheck("INT-GATE (b) correctly signed envelope verifies through the service-constructed gate (envelope payload runs)",
            !errSigned && f.shellRan == "echo signed")
        val forged = attackerSigner.sign(SignedCommandClasses.SHELL_EXEC, "echo forged".toByteArray(), GT0, 600_000, "g-b2")
        val errForged = f.call(core, token, "shell_exec",
            JSONObject().put("_signed_command", forged.toJson()), 3)
        gcheck("INT-GATE (b) attacker-signed (forged) envelope refuses", errForged && f.shellRan == "echo signed")
        val tampered = customerSigner.sign(SignedCommandClasses.SHELL_EXEC, "echo signed".toByteArray(), GT0, 600_000, "g-b3")
            .copy(signatureBase64 = Base64.getEncoder().encodeToString(ByteArray(64) { 1 }))
        val errTampered = f.call(core, token, "shell_exec",
            JSONObject().put("_signed_command", tampered.toJson()), 4)
        gcheck("INT-GATE (b) tampered-signature envelope refuses", errTampered && f.shellRan == "echo signed")
        dir.deleteRecursively()
    }

    // ---------- (c) broken key file: fail-closed, named ----------
    run {
        val dir = freshDir("broken")
        File(dir, CommandGateWiring.KEYS_FILE_NAME).writeText("current not-base64!!\n")
        val wiring = CommandGateWiring.build(dir, ChainedAuditLog())
        val f = GateFixture(dir)
        val core = f.core(wiring)
        gcheck("INT-GATE broken key file state names fail-closed + broken file",
            core.commandGateState.contains("fail-closed") && core.commandGateState.contains("broken"))
        val token = f.pairedToken(core)
        val env = customerSigner.sign(SignedCommandClasses.SHELL_EXEC, "echo signed".toByteArray(), GT0, 600_000, "g-c1")
        val err = f.call(core, token, "shell_exec", JSONObject().put("_signed_command", env.toJson()), 2)
        gcheck("INT-GATE (c) broken key file refuses every envelope", err && f.shellRan == null)
        dir.deleteRecursively()
    }

    println("LANEINTGATE $gatePasses passed, $gateFailures failed")
    println(if (gateFailures == 0) "LANEINTGATE ALL PASS" else "LANEINTGATE FAILURES PRESENT")
    if (gateFailures > 0) kotlin.system.exitProcess(1)
}

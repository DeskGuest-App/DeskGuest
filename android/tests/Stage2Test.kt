import io.deskguest.app.access.WaitCondition
import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.server.ApprovalGate
import io.deskguest.app.server.AuditLog
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/**
 * JVM tests for the 0.4.0 stage-2 additions: the audit log's
 * redaction and encoding, the approval policy mapping, wait_for's
 * matcher, and McpCore's audit hook + capability map for the new
 * tools.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

fun main() {
    // ---- AuditLog redaction: secrets never reach a summary ----
    val typeArgs = JSONObject().put("text", "my secret message")
    val typeSummary = AuditLog.summarize("type_text", typeArgs)
    check("type_text summary is a length, never the text",
        typeSummary == "typed 17 chars" && !typeSummary.contains("secret"))

    val clipSummary = AuditLog.summarize(
        "clipboard_set", JSONObject().put("text", "tok-123456")
    )
    check("clipboard summary is a length", clipSummary.contains("10 chars") && !clipSummary.contains("tok-"))

    val shellSummary = AuditLog.summarize(
        "shell_exec", JSONObject().put("command", "settings put global x 1 --token abc")
    )
    check("shell summary is program + length",
        shellSummary.startsWith("ran settings (") && !shellSummary.contains("abc"))

    val generic = AuditLog.summarize(
        "some_tool", JSONObject().put("token", "abc").put("ref", "e3")
    )
    check("generic summary drops forbidden keys",
        !generic.contains("token") && generic.contains("ref"))

    // ---- AuditLog encode/decode round-trip + tamper ----
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    val record = AuditLog.record(123L, "tool", "tap", "Agent A", true, "tap e3")
    val line = AuditLog.encode(record, cipher)
    check("audit line is wrapped", line.startsWith("v1:"))
    val decoded = AuditLog.decode(line, cipher)
    check("audit line round-trips",
        decoded?.optString("name") == "tap" && decoded?.optLong("at") == 123L)
    check("tampered audit line refused",
        AuditLog.decode(line.dropLast(4) + "AAAA", cipher) == null)
    val longDetail = AuditLog.record(1L, "tool", "x", "A", false, "y".repeat(1000))
    check("detail is length-capped", longDetail.optString("detail").length == 300)

    // ---- ApprovalGate policy mapping + defaults ----
    check("AUTO allows", ApprovalGate.decide(ApprovalGate.Policy.AUTO) == ApprovalGate.Decision.ALLOW)
    check("ASK_FIRST asks", ApprovalGate.decide(ApprovalGate.Policy.ASK_FIRST) == ApprovalGate.Decision.ASK)
    check("BLOCKED denies", ApprovalGate.decide(ApprovalGate.Policy.BLOCKED) == ApprovalGate.Decision.DENY)
    check("launch defaults to AUTO",
        ApprovalGate.defaultPolicy(ApprovalGate.ActionClass.LAUNCH_APP) == ApprovalGate.Policy.AUTO)
    check("shell defaults to ASK_FIRST",
        ApprovalGate.defaultPolicy(ApprovalGate.ActionClass.SHELL) == ApprovalGate.Policy.ASK_FIRST)
    check("clipboard defaults to ASK_FIRST",
        ApprovalGate.defaultPolicy(ApprovalGate.ActionClass.CLIPBOARD) == ApprovalGate.Policy.ASK_FIRST)
    check("every class has a default",
        ApprovalGate.ActionClass.values().all { ApprovalGate.DEFAULTS.containsKey(it) })
    check("approval timeout is 30s", ApprovalGate.TIMEOUT_MS == 30_000L)

    // ---- WaitCondition matcher ----
    val byText = WaitCondition(text = "Settings")
    check("text match is substring + case-insensitive",
        byText.matches("com.android.settings", listOf("Open Settings now")))
    check("text mismatch", !byText.matches("com.android.settings", listOf("Home")))
    val byPackage = WaitCondition(packageName = "com.android.settings")
    check("package match", byPackage.matches("com.android.settings", emptyList()))
    check("package mismatch", !byPackage.matches("com.other", emptyList()))
    val both = WaitCondition(text = "Wi-Fi", packageName = "com.android.settings")
    check("both parts must match (package wrong)",
        !both.matches("com.other", listOf("Wi-Fi")))
    check("both parts must match (both right)",
        both.matches("com.android.settings", listOf("Wi-Fi")))
    check("empty condition never matches",
        !WaitCondition().matches("com.android.settings", listOf("anything")))

    // ---- McpCore: audit hook fires; new tools are capability-gated ----
    val dir = Files.createTempDirectory("deskguest-stage2").toFile()
    val store = PairingStore(File(dir, "pairings.tsv"))
    val host = object : McpCore.ToolHost {
        override fun tools(): List<McpCore.ToolDef> = listOf(
            McpCore.ToolDef(
                "launch_app", "fake", "drive",
                JSONObject().put("type", "object"),
                run = { "launched" }
            ),
            McpCore.ToolDef(
                "clipboard_get", "fake", "observe",
                JSONObject().put("type", "object"),
                run = { "clip" }
            )
        )
    }
    val core = McpCore(store, host)
    val events = mutableListOf<String>()
    core.auditSink = { agent, tool, ok, detail -> events.add("$agent|$tool|$ok|$detail") }
    core.handle("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}""", null)
    val code = store.beginPairing("Stage2 Agent")
    val pairReply = core.handle(
        """{"jsonrpc":"2.0","id":2,"method":"pair","params":{"code":"$code","agentName":"Agent A","scopes":["mcp"]}}""",
        null
    )
    val token = JSONObject(pairReply.body!!).getJSONObject("result").getString("token")

    // Observe-level pairing (default): launch_app needs the apps cap.
    val refused = core.handle(
        """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"launch_app","arguments":{"package":"com.x"}}}""",
        token
    )
    check("launch_app refused without the apps cap",
        JSONObject(refused.body!!).getJSONObject("result").getBoolean("isError"))
    check("refusal was audited", events.any { it.contains("launch_app|false") })

    // Raise to full: the call runs and is audited as a success.
    store.setAccess(token, "full", setOf("see", "tap", "type", "apps", "shell", "settings"))
    val okReply = core.handle(
        """{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"launch_app","arguments":{"package":"com.x"}}}""",
        token
    )
    check("launch_app runs with the apps cap",
        !JSONObject(okReply.body!!).getJSONObject("result").getBoolean("isError"))
    check("success was audited with the redacted summary",
        events.any { it.contains("launch_app|true") && it.contains("com.x") })

    dir.deleteRecursively()
    println(if (failures == 0) "ALL STAGE-2 TESTS PASSED" else "$failures STAGE-2 TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

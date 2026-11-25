import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.PairingStore
import org.json.JSONObject
import java.io.File

/**
 * JVM test suite for the MCP core + pairing store (SPEC §10: VM-side
 * tests before device tests). Run via test-jvm.sh. Every check prints
 * PASS/FAIL; any FAIL exits nonzero.
 */
private var failures = 0

private fun check(name: String, condition: Boolean, detail: String = "") {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name  $detail")
        failures++
    }
}

private fun fakeHost(): McpCore.ToolHost = object : McpCore.ToolHost {
    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "device_info", "fake device info", "observe",
            JSONObject().put("type", "object"),
            run = { "{\"model\":\"TestPhone\"}" }
        ),
        McpCore.ToolDef(
            "tap", "fake drive tool", "drive",
            JSONObject().put("type", "object"),
            run = { "tapped" }
        )
    )
}

private fun richHost(): McpCore.ToolHost = object : McpCore.ToolHost {
    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "device_info", "fake device info", "observe",
            JSONObject().put("type", "object"),
            run = { "{\"model\":\"TestPhone\"}" }
        ),
        McpCore.ToolDef(
            "session_status", "fake session status", "observe",
            JSONObject().put("type", "object"),
            run = { "{\"sessionActive\":false}" }
        ),
        McpCore.ToolDef(
            "snapshot", "fake snapshot", "observe",
            JSONObject().put("type", "object"),
            run = { "snapshot text" }
        ),
        McpCore.ToolDef(
            "tap", "fake drive tool", "drive",
            JSONObject().put("type", "object"),
            run = { "tapped" }
        ),
        McpCore.ToolDef(
            "type_text", "fake type tool", "drive",
            JSONObject().put("type", "object"),
            run = { "typed" }
        ),
        McpCore.ToolDef(
            "start_session", "fake session start", "drive",
            JSONObject().put("type", "object"),
            run = { "session open" }
        )
    )
}

private fun callText(core: McpCore, token: String, tool: String, id: Int): Pair<Boolean, String> {
    val reply = core.handle(
        """{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"$tool","arguments":{}}}""",
        token
    )
    val result = JSONObject(reply.body!!).getJSONObject("result")
    val text = result.getJSONArray("content").getJSONObject(0).getString("text")
    return result.getBoolean("isError") to text
}

fun main() {
    val dir = File(System.getProperty("java.io.tmpdir"), "acp-test-" + System.nanoTime())
    dir.mkdirs()
    val store = PairingStore(File(dir, "pairings.tsv"))
    val core = McpCore(store, fakeHost())

    // initialize answers with protocol version + a session id
    val init = core.handle(
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}""", null
    )
    check("initialize status 200", init.httpStatus == 200, init.toString())
    check("initialize has session", !init.sessionId.isNullOrBlank())
    val initJson = JSONObject(init.body!!)
    check(
        "initialize protocol version",
        initJson.getJSONObject("result").getString("protocolVersion") == McpCore.PROTOCOL_VERSION
    )

    // notifications get 202 and no body
    val notif = core.handle(
        """{"jsonrpc":"2.0","method":"notifications/initialized"}""", null
    )
    check("notification 202 empty", notif.httpStatus == 202)

    // tools/list without a token is refused at the HTTP layer
    val unauth = core.handle(
        """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", null
    )
    check("tools/list unauthenticated -> 401", unauth.httpStatus == 401, unauth.toString())

    // pairing: wrong code rejected, right code issues a token
    val code = store.beginPairing("Test AI")
    check("code is 6 digits", code.length == 6 && code.all { it.isDigit() }, code)
    val wrong = core.handle(
        """{"jsonrpc":"2.0","id":3,"method":"pair","params":{"code":"000000"}}""", null
    )
    val wrongJson = JSONObject(wrong.body!!)
    check(
        "wrong code rejected",
        wrongJson.has("error") && wrongJson.getJSONObject("error").getInt("code") == -32002,
        wrong.body ?: ""
    )
    check("attempt survives a wrong code", store.currentCode() == code)

    val paired = core.handle(
        """{"jsonrpc":"2.0","id":4,"method":"pair","params":{"code":"$code"}}""", null
    )
    val pairedJson = JSONObject(paired.body!!)
    check("pair succeeds", pairedJson.has("result"), paired.body ?: "")
    val token = pairedJson.getJSONObject("result").getString("token")
    check("token issued (64 hex)", token.length == 64, token)
    check("code burned after use", store.currentCode() == null)

    // the same code cannot be redeemed twice
    val replay = core.handle(
        """{"jsonrpc":"2.0","id":5,"method":"pair","params":{"code":"$code"}}""", null
    )
    check("code replay rejected", JSONObject(replay.body!!).has("error"))

    // brute-force guard: a live code burns after MAX_REDEEM_ATTEMPTS
    // wrong guesses, so spraying the pair endpoint buys an attacker
    // that many tries per code — not the whole 10-minute window.
    val codeB = store.beginPairing("Brute Force Bait")
    val wrongB = "%06d".format((codeB.toInt() + 1) % 1_000_000)
    repeat(PairingStore.MAX_REDEEM_ATTEMPTS - 1) { i ->
        val attempt = core.handle(
            """{"jsonrpc":"2.0","id":90,"method":"pair","params":{"code":"$wrongB"}}""", null
        )
        check("wrong guess ${i + 1} rejected", JSONObject(attempt.body!!).has("error"))
    }
    check("code alive below the attempt limit", store.currentCode() == codeB)
    val lastGuess = core.handle(
        """{"jsonrpc":"2.0","id":91,"method":"pair","params":{"code":"$wrongB"}}""", null
    )
    check("limit-th wrong guess rejected", JSONObject(lastGuess.body!!).has("error"))
    check("code burned at the attempt limit", store.currentCode() == null)
    val correctButBurned = core.handle(
        """{"jsonrpc":"2.0","id":92,"method":"pair","params":{"code":"$codeB"}}""", null
    )
    check(
        "burned code rejects even the right code",
        JSONObject(correctButBurned.body!!).has("error")
    )
    // the owner just makes a fresh code; pairing works again at once
    val codeC = store.beginPairing("Owner Retry")
    val rePaired = core.handle(
        """{"jsonrpc":"2.0","id":93,"method":"pair","params":{"code":"$codeC"}}""", null
    )
    check("fresh code pairs after a burn", JSONObject(rePaired.body!!).has("result"), rePaired.body ?: "")

    // tools/list with the token shows observe tools only (default scopes)
    val list = core.handle("""{"jsonrpc":"2.0","id":6,"method":"tools/list"}""", token)
    val tools = JSONObject(list.body!!).getJSONObject("result").getJSONArray("tools")
    check("tools/list returns tools", tools.length() == 1, list.body ?: "")
    check(
        "drive tool hidden from observe pairing",
        tools.getJSONObject(0).getString("name") == "device_info"
    )

    // tools/call runs the observe tool
    val call = core.handle(
        """{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"device_info","arguments":{}}}""",
        token
    )
    val callJson = JSONObject(call.body!!)
    check(
        "device_info call answers",
        callJson.getJSONObject("result").getJSONArray("content").getJSONObject(0)
            .getString("text").contains("TestPhone"),
        call.body ?: ""
    )

    // tools/call on a drive tool is scope-refused, in-band (isError), not a crash
    val gated = core.handle(
        """{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"tap","arguments":{}}}""",
        token
    )
    val gatedJson = JSONObject(gated.body!!)
    check(
        "drive call scope-refused",
        gatedJson.getJSONObject("result").getBoolean("isError"),
        gated.body ?: ""
    )

    // revocation takes effect immediately
    val pairing = store.pairingForToken(token)
    check("token resolves before revoke", pairing != null)
    store.revoke(token)
    val after = core.handle("""{"jsonrpc":"2.0","id":9,"method":"tools/list"}""", token)
    check("revoked token -> 401", after.httpStatus == 401)

    // pairings persist across store instances (same file)
    val code2 = store.beginPairing("Second AI")
    val paired2 = core.handle(
        """{"jsonrpc":"2.0","id":10,"method":"pair","params":{"code":"$code2"}}""", null
    )
    val token2 = JSONObject(paired2.body!!).getJSONObject("result").getString("token")
    val storeReloaded = PairingStore(File(dir, "pairings.tsv"))
    check("pairing persists on disk", storeReloaded.pairingForToken(token2) != null)

    // garbage body is a parse error, unknown method is -32601
    val garbage = core.handle("not json", null)
    check("garbage body -> parse error", JSONObject(garbage.body!!).getJSONObject("error").getInt("code") == -32700)
    val unknown = core.handle("""{"jsonrpc":"2.0","id":11,"method":"nope"}""", token2)
    check("unknown method -> -32601", JSONObject(unknown.body!!).getJSONObject("error").getInt("code") == -32601)

    // ---- v0.3: clientInfo binding, access levels, capability gating ----
    val store2 = PairingStore(File(dir, "pairings2.tsv"))
    val core2 = McpCore(store2, richHost())

    // initialize presents a clientInfo; pair binds it to the pairing
    val init2 = core2.handle(
        """{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"clientInfo":{"name":"Muse","version":"9.9"}}}""",
        null
    )
    check("v0.3 initialize has session", !init2.sessionId.isNullOrBlank())
    val code3 = store2.beginPairing("My AI")
    val paired3 = core2.handle(
        """{"jsonrpc":"2.0","id":21,"method":"pair","params":{"code":"$code3"}}""",
        null, init2.sessionId
    )
    val paired3Json = JSONObject(paired3.body!!)
    check(
        "pair result carries the agent name",
        paired3Json.getJSONObject("result").optString("agentName") == "Muse",
        paired3.body ?: ""
    )
    val token3 = paired3Json.getJSONObject("result").getString("token")
    val pairing3 = store2.byToken(token3)
    check("clientInfo name bound at pair", pairing3?.agentName == "Muse", pairing3.toString())
    check("clientInfo version bound at pair", pairing3?.agentVersion == "9.9")
    check("latest() is the newest pairing", store2.latest()?.token == token3)

    // a new pairing defaults to observe / see-only
    check("default access is observe", pairing3?.access == "observe")
    check("default caps are see-only", pairing3?.caps == setOf("see"), pairing3?.caps.toString())
    check("default scopes are observe-only", pairing3?.scopes == setOf("observe"))

    // status results name the connected agent
    val (_, infoText) = callText(core2, token3, "device_info", 22)
    check("device_info names the agent", infoText.contains("\"agentName\"") && infoText.contains("Muse"), infoText)
    val (_, statusText) = callText(core2, token3, "session_status", 23)
    check("session_status names the agent", statusText.contains("Muse"), statusText)

    // see-only pairing: see tools run, drive tools are refused by capability
    val (snapError, _) = callText(core2, token3, "snapshot", 24)
    check("see-only pairing can snapshot", !snapError)
    val (tapError, tapReason) = callText(core2, token3, "tap", 25)
    check("see-only pairing refused tap", tapError, tapReason)
    check("tap refusal names the tap capability", tapReason.contains("'tap'"), tapReason)
    val (sessionError, _) = callText(core2, token3, "start_session", 26)
    check("see-only pairing cannot start a session", sessionError)

    // setAccess to full: caps and scopes open up, tap now runs
    val full = store2.setAccess(token3, "full", emptySet())
    check("full access recorded", full?.access == "full")
    check(
        "full caps are all six",
        full?.caps == PairingStore.ALL_CAPS, full?.caps.toString()
    )
    check(
        "full scopes are all four",
        full?.scopes == PairingStore.ALL_SCOPES, full?.scopes.toString()
    )
    val (tapAfterFull, tapText) = callText(core2, token3, "tap", 27)
    check("full pairing can tap", !tapAfterFull && tapText == "tapped", tapText)

    // custom access: caps gate each tool on their own
    val code4 = store2.beginPairing("Custom AI")
    val paired4 = core2.handle(
        """{"jsonrpc":"2.0","id":28,"method":"pair","params":{"code":"$code4"}}""", null
    )
    val token4 = JSONObject(paired4.body!!).getJSONObject("result").getString("token")
    val custom = store2.setAccess(token4, "custom", setOf("see", "type"))
    check("custom access recorded", custom?.access == "custom")
    check("custom caps kept as given", custom?.caps == setOf("see", "type"), custom?.caps.toString())
    check(
        "custom scopes gain observe + drive",
        custom?.scopes == setOf("observe", "drive"), custom?.scopes.toString()
    )
    val (typeError, typeTextOut) = callText(core2, token4, "type_text", 29)
    check("custom pairing with type cap can type", !typeError && typeTextOut == "typed", typeTextOut)
    val (customTapError, customTapReason) = callText(core2, token4, "tap", 30)
    check("custom pairing without tap cap refused tap", customTapError, customTapReason)
    check("custom tap refusal names the tap capability", customTapReason.contains("'tap'"), customTapReason)

    // setAccess on an unknown token is a clean miss, not a crash
    check("setAccess unknown token -> null", store2.setAccess("deadbeef", "full", emptySet()) == null)

    // access levels and agent identity persist across store instances
    val store2Reloaded = PairingStore(File(dir, "pairings2.tsv"))
    val reloaded4 = store2Reloaded.byToken(token4)
    check("custom access persists", reloaded4?.access == "custom" && reloaded4?.caps == setOf("see", "type"))
    check("agent identity persists", store2Reloaded.byToken(token3)?.agentName == "Muse")

    // a legacy 4-field store file loads with safe defaults, no crash
    val legacyFile = File(dir, "legacy.tsv")
    legacyFile.writeText("Old AI\t${"a".repeat(64)}\tobserve\t12345")
    val legacyStore = PairingStore(legacyFile)
    val legacy = legacyStore.pairingForToken("a".repeat(64))
    check("legacy pairing loads", legacy != null)
    check(
        "legacy pairing gets observe/see defaults",
        legacy?.access == "observe" && legacy?.caps == setOf("see") && legacy?.agentName == ""
    )

    println(if (failures == 0) "ALL TESTS PASSED" else "$failures TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

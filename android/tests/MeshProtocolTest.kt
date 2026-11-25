import io.agenticcontrol.app.mesh.MeshProtocol
import org.json.JSONObject

/**
 * JVM tests for the stage-4 mesh protocol shapes: heartbeat parsing
 * (including degraded/unknown heartbeats) and the input event
 * builders the device page emits.
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
    val full = MeshProtocol.CompanionState.parse(
        JSONObject(
            """{"state":"AI_DRIVING","device":"HOST-LAPTOP","agent":"Agent A",""" +
                """"sessionSeconds":125,"actions":42,"intent":"Checking the router",""" +
                """"preview":true}"""
        )
    )
    check("heartbeat parses AI_DRIVING", full.state == MeshProtocol.State.AI_DRIVING)
    check("heartbeat parses agent", full.agentName == "Agent A")
    check("heartbeat parses counters",
        full.sessionSeconds == 125L && full.actions == 42)
    check("heartbeat parses intent + preview",
        full.intent == "Checking the router" && full.previewAvailable)

    val idle = MeshProtocol.CompanionState.parse(JSONObject("""{"state":"IDLE"}"""))
    check("idle heartbeat defaults the rest",
        idle.state == MeshProtocol.State.IDLE && idle.agentName.isEmpty() &&
            !idle.previewAvailable)

    val manual = MeshProtocol.CompanionState.parse(JSONObject("""{"state":"human_manual"}"""))
    check("state names parse case-insensitively",
        manual.state == MeshProtocol.State.HUMAN_MANUAL)

    val garbage = MeshProtocol.CompanionState.parse(JSONObject("""{"state":"WAT"}"""))
    check("unknown state degrades to UNKNOWN, never invented",
        garbage.state == MeshProtocol.State.UNKNOWN)

    val empty = MeshProtocol.CompanionState.parse(JSONObject())
    check("empty heartbeat is UNKNOWN with defaults",
        empty.state == MeshProtocol.State.UNKNOWN && empty.sessionSeconds == 0L)

    val pointer = MeshProtocol.inputPointer(0.5, -0.25)
    check("pointer event shape",
        pointer.getString("type") == "pointer" &&
            pointer.getDouble("dx") == 0.5 && pointer.getDouble("dy") == -0.25)

    val button = MeshProtocol.inputButton("right", "click")
    check("button event shape",
        button.getString("type") == "button" &&
            button.getString("button") == "right" &&
            button.getString("action") == "click")

    val key = MeshProtocol.inputKey("alt_tab")
    check("key event shape",
        key.getString("type") == "key" && key.getString("key") == "alt_tab")

    val text = MeshProtocol.inputText("hello")
    check("text event shape",
        text.getString("type") == "text" && text.getString("text") == "hello")

    val heartbeat = MeshProtocol.heartbeat("Pixel", watching = true)
    check("phone heartbeat shape",
        heartbeat.getString("from") == "Pixel" && heartbeat.getBoolean("watching"))

    // ---- Block D: session stream (mesh contract v2) ----

    check("session states parse HUMAN_SESSION + PAUSED_BY_USER",
        MeshProtocol.CompanionState.parse(JSONObject("""{"state":"HUMAN_SESSION"}""")).state ==
            MeshProtocol.State.HUMAN_SESSION &&
            MeshProtocol.CompanionState.parse(JSONObject("""{"state":"PAUSED_BY_USER"}""")).state ==
            MeshProtocol.State.PAUSED_BY_USER)

    fun nal(type: Int, vararg payload: Byte): ByteArray =
        byteArrayOf(0, 0, 0, 1, type.toByte()) + payload

    val sps = nal(7, 0x64, 0x00)
    val pps = nal(8, 0xEE.toByte())
    val idr = nal(5, 0x88.toByte())
    val slice = nal(1, 0x22)
    val keyAu = sps + pps + idr
    val deltaAu = slice

    fun envelope(headerJson: String, au: ByteArray): ByteArray {
        val header = headerJson.toByteArray(Charsets.UTF_8)
        val out = ByteArray(8 + header.size + au.size)
        out[0] = 'A'.code.toByte(); out[1] = 'C'.code.toByte()
        out[2] = 'P'.code.toByte(); out[3] = 'F'.code.toByte()
        out[4] = 1; out[5] = 0
        out[6] = (header.size and 0xFF).toByte(); out[7] = ((header.size shr 8) and 0xFF).toByte()
        header.copyInto(out, 8)
        au.copyInto(out, 8 + header.size)
        return out
    }

    val keyHeader = """{"seq":7,"ptsMs":100,"captureMs":1700000000000,"keyframe":true,"width":1920,"height":1080,"monitor":0,"codec":"h264","encoder":"Test MFT","hardware":true,"capture":"dxgi","cursorX":10,"cursorY":20}"""
    val parsedKey = MeshProtocol.StreamFrames.parse(envelope(keyHeader, keyAu))
    check("ACPF keyframe parses with derived flag + cursor",
        parsedKey != null && parsedKey.keyframe && parsedKey.seq == 7L &&
            parsedKey.width == 1920 && parsedKey.cursorX == 10 && parsedKey.cursorY == 20 &&
            parsedKey.accessUnit.contentEquals(keyAu))

    val deltaHeader = keyHeader.replace("\"seq\":7", "\"seq\":8").replace("\"keyframe\":true", "\"keyframe\":false")
    val parsedDelta = MeshProtocol.StreamFrames.parse(envelope(deltaHeader, deltaAu))
    check("ACPF delta frame parses", parsedDelta != null && !parsedDelta.keyframe)

    check("ACPF rejects bad magic",
        MeshProtocol.StreamFrames.parse(
            envelope(keyHeader, keyAu).also { it[0] = 'X'.code.toByte() }) == null)
    check("ACPF rejects a keyframe claim without IDR",
        MeshProtocol.StreamFrames.parse(envelope(keyHeader, deltaAu)) == null)
    check("ACPF rejects SPS after IDR (config after picture)",
        MeshProtocol.StreamFrames.parse(envelope(keyHeader, idr + sps + pps)) == null)
    check("ACPF rejects forbidden_zero_bit set",
        MeshProtocol.StreamFrames.parse(envelope(keyHeader,
            byteArrayOf(0, 0, 0, 1, (0x80 or 5).toByte(), 0x11))) == null)
    check("ACPF rejects non-Annex-B payload",
        MeshProtocol.StreamFrames.parse(envelope(deltaHeader,
            byteArrayOf(0x11, 0x22, 0x33, 0x44))) == null)
    check("ACPF rejects absurd dimensions",
        MeshProtocol.StreamFrames.parse(envelope(
            keyHeader.replace("\"width\":1920", "\"width\":99999"), keyAu)) == null)
    check("ACPF rejects a truncated envelope",
        MeshProtocol.StreamFrames.parse(envelope(keyHeader, keyAu).copyOf(10)) == null)
    check("ACPF rejects wrong codec",
        MeshProtocol.StreamFrames.parse(envelope(
            keyHeader.replace("\"h264\"", "\"vp9\""), keyAu)) == null)

    val infoJson = JSONObject(
        """{"ok":true,"streaming":true,"sessionState":"active",""" +
            """"floor":{"userId":"u-host","name":"Owner One"},""" +
            """"width":1920,"height":1080,"monitor":0,"capture":"dxgi",""" +
            """"encoder":"NVIDIA H.264 Encoder MFT","hardware":true,"framesEncoded":123,""" +
            """"roster":[{"userId":"u-host","name":"Owner One","role":"host","floor":"holds"},""" +
            """{"userId":"u-phone","name":"Phone","role":"watcher","floor":"watching"}]}"""
    )
    val info = MeshProtocol.StreamInfo.parse(infoJson)
    check("stream info parses floor + roster + encoder truth",
        info.ok && info.streaming && info.floorHolderId == "u-host" &&
            info.roster.size == 2 && info.roster[1].floor == "watching" &&
            info.hardware && info.framesEncoded == 123L)
    val refusedInfo = MeshProtocol.StreamInfo.parse(JSONObject("""{"ok":false,"error":"nope"}"""))
    check("stream info refusal degrades honestly", !refusedInfo.ok && refusedInfo.error == "nope")

    val startBody = MeshProtocol.streamStart("s1", "u1", 2)
    check("stream start body shape",
        startBody.getString("sessionId") == "s1" && startBody.getString("userId") == "u1" &&
            startBody.getInt("monitor") == 2)
    val inputBody = MeshProtocol.streamInput("s1", "u1", MeshProtocol.inputPointerAbs(40, 50))
    check("stream input wraps the event with identity",
        inputBody.getString("sessionId") == "s1" &&
            inputBody.getJSONObject("event").getString("type") == "pointer_abs" &&
            inputBody.getJSONObject("event").getInt("x") == 40)

    println(if (failures == 0) "ALL MESH TESTS PASSED" else "$failures MESH TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

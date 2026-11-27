import io.deskguest.app.server.McpCore
import io.deskguest.app.server.McpHttpServer
import io.deskguest.app.server.PairingStore
import org.json.JSONObject
import java.io.File

/**
 * Hosts the real McpHttpServer on the JVM for the Python-driven HTTP
 * flow test (tests/http_flow.py). Why Python drives: in this VM's
 * sandbox, JVM-originated loopback connects are reset while native
 * clients connect cleanly (see BUILD-LOG.md) — the same quirk that
 * breaks Gradle's daemon. The server code under test is identical to
 * what ships in the app.
 *
 * Writes <workdir>/code.txt (the live pairing code) and
 * <workdir>/ready.txt when listening.
 */
fun main(args: Array<String>) {
    val port = 18723
    val workdir = File(args.getOrElse(0) { "/tmp/deskguest-http" })
    workdir.mkdirs()
    val store = PairingStore(File(workdir, "pairings.tsv"))
    val host = object : McpCore.ToolHost {
        override fun tools(): List<McpCore.ToolDef> = listOf(
            McpCore.ToolDef(
                "device_info", "fake device info", "observe",
                JSONObject().put("type", "object"),
                run = { "{\"model\":\"HttpTestPhone\"}" }
            )
        )
    }
    val server = McpHttpServer(McpCore(store, host), port)
    server.start()
    val code = store.beginPairing("Http AI")
    File(workdir, "code.txt").writeText(code)
    File(workdir, "ready.txt").writeText("ready")
    println("HTTP test server listening on $port, pairing code in ${workdir}/code.txt")
    Thread.sleep(120_000)
    server.stop()
}

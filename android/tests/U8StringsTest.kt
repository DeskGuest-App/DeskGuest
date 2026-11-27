import io.deskguest.app.strings.ConsentStrings
import java.io.File

/**
 * U8 gate — consent / presence / STOP string externalisation (Android).
 *
 * Proves, from the tree itself:
 *  1. Every consent key exists in res/values/strings.xml with EXACTLY
 *     the built-in default value (wording is law — externalised,
 *     never reworded).
 *  2. The fallback resolver: a missing (null) or blank resource value
 *     resolves to the built-in default — in particular the STOP and
 *     presence strings can never resolve blank (destruction leg).
 *  3. Lint leg: the named consent surfaces contain no hardcoded
 *     consent literals in code (comments stripped) and do read their
 *     strings through consentString(R.string.…).
 *
 * Args: [0] = android project dir (the dir containing app/ and tests/).
 */
object U8StringsTest {
    private var failures = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) println("PASS $name") else { failures++; println("FAIL $name $detail") }
    }

    private fun unescapeXml(s: String): String =
        s.replace("\\'", "'").replace("\\n", "\n").replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val xmlFile = File(root, "app/src/main/res/values/strings.xml")
        check("strings.xml exists", xmlFile.isFile)
        val xml = xmlFile.readText()
        val entries = Regex("""<string name="([a-z0-9_]+)">(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(xml).associate { it.groupValues[1] to unescapeXml(it.groupValues[2]) }

        // 1. Resource values == built-in defaults, verbatim, for every key.
        for ((key, def) in ConsentStrings.DEFAULTS) {
            check("resource present: $key", entries.containsKey(key))
            check("resource verbatim: $key", entries[key] == def,
                "xml=${entries[key]} default=$def")
            check("resource non-blank: $key", !entries[key].isNullOrBlank())
        }

        // 2. Fallback / destruction leg: missing or blank never blanks.
        for ((key, def) in ConsentStrings.DEFAULTS) {
            check("fallback missing: $key", ConsentStrings.resolve(key, null) == def)
            check("fallback empty: $key", ConsentStrings.resolve(key, "") == def)
            check("fallback blank: $key", ConsentStrings.resolve(key, "   ") == def)
            check("fallback non-blank: $key", ConsentStrings.resolve(key, null).isNotBlank())
        }
        check("STOP fallback is STOP", ConsentStrings.resolve("presence_stop", null) == "STOP")
        check("STOP fallback on blank is STOP", ConsentStrings.resolve("presence_stop", "") == "STOP")
        check("present resource wins", ConsentStrings.resolve("presence_stop", "HALTE") == "HALTE")

        // 3. Lint leg: no hardcoded consent literals in the named surfaces.
        val forbidden = listOf(
            "\"STOP\"", "\"Resume\"", "\"Paused — you have the phone\"",
            "is controlling your phone", "\"Approval requested\"",
            "\"Deny\"", "\"Approve\"", "\"Paused\"", "\"STOP session\"",
            "\"Channel open\"", "\"Channel stopped\"",
            "\"No active session\"", "\"ACTIVE SESSION\"", "\"Resume the session\"",
            "\"Session stopped.\"", "You took over — tap to end",
        )
        val surfaces = mapOf(
            "presence/PresenceOverlay.kt" to "R.string.presence_stop",
            "server/ApprovalOverlay.kt" to "R.string.approval_title",
            "tile/DeskGuestTileService.kt" to "R.string.tile_stop_label",
            "MainActivity.kt" to "R.string.session_none_title",
            "ui/UiKit.kt" to "R.string.presence_stop",
        )
        val srcRoot = File(root, "app/src/main/java/io/deskguest/app")
        for ((rel, marker) in surfaces) {
            val f = File(srcRoot, rel)
            check("surface exists: $rel", f.isFile)
            val code = f.readText()
                .replace(Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL), "")
                .lines().filter { !it.trimStart().startsWith("//") && !it.trimStart().startsWith("*") }
                .joinToString("\n")
            for (bad in forbidden) {
                check("no hardcoded $bad in $rel", !code.contains(bad))
            }
            check("surface reads resources: $rel", code.contains(marker),
                "expected $marker")
        }

        if (failures > 0) { println("U8 FAILURES: $failures"); kotlin.system.exitProcess(1) }
        println("U8StringsTest: ALL PASS")
    }
}

import io.deskguest.app.strings.ConsentStrings
import java.io.File

/**
 * W81 / FR-123 — generic-name fallback cleanup (Android).
 *
 * W80/FR-122 abolished generic names on the live-session presence
 * surfaces. FR-123 covers the remaining generic-name surfaces that
 * do NOT render live-session presence:
 *  (a) the pairing-list label displayName(pairing) in MainActivity
 *      and WizardActivity fell back to the fabricated "Your AI";
 *  (b) approval-gate prompts in AccessToolHost / ShellToolHost /
 *      OwedToolHost fell back to "Your AI" for a session-less
 *      caller, and the chat gate paths (ChatToolHost.ask,
 *      AgentChatActivity) could pass a blank caller name;
 *  (c) WindowsDeviceActivity rendered a blank companion agent
 *      name as the generic stand-in "The agent";
 *  (d) the dead tile_default_agent ("AI") string resource — its
 *      only call site was removed by W80 — is removed outright.
 *
 * Rule proven here: a pairing with no name is labelled truthfully
 * ("Unnamed pairing"), a gate caller with no name is presented
 * plainly as unnamed ("An unnamed caller"), and no code path in
 * the tree falls back to a generic stand-in name. All wording
 * goes through the U8 strings door (strings.xml + ConsentStrings
 * parity is proven by U8StringsTest over the new keys).
 *
 * Args: [0] = android project dir.
 */
object W81Fr123Test {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    /** Source with block comments and //-comment lines stripped, so
     *  pins judge code, not the historical notes that name the old
     *  generic strings while explaining their removal. */
    private fun codeOf(f: File): String = f.readText()
        .replace(Regex("""(?s)/\*.*?\*/"""), "")
        .lines().filter { !it.trimStart().startsWith("//") }
        .joinToString("\n")

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val src = File(root, "app/src/main/java/io/deskguest/app")
        fun code(rel: String) = codeOf(File(src, rel))

        // ---- The U8 wording itself: truthful, non-generic, non-blank ----
        check("unnamed pairing label wording",
            ConsentStrings.unnamedPairingLabel() == "Unnamed pairing")
        check("unnamed caller label wording",
            ConsentStrings.unnamedCallerLabel() == "An unnamed caller")
        check("unnamed labels are not generic stand-ins",
            ConsentStrings.unnamedPairingLabel() !in listOf("Your AI", "My AI", "Agent", "AI") &&
                ConsentStrings.unnamedCallerLabel() !in listOf("Your AI", "My AI", "Agent", "AI"))
        check("mesh unnamed driving wording",
            ConsentStrings.resolve("mesh_unnamed_agent_driving", null) ==
                "An unnamed agent is driving")
        check("dead generic tile_default_agent string abolished",
            !ConsentStrings.DEFAULTS.containsKey("tile_default_agent"))

        // ---- (a) pairing-list labels ----
        val main = code("MainActivity.kt")
        check("MainActivity displayName: no generic Your AI fallback",
            !main.contains("\"Your AI\""))
        check("MainActivity displayName: unnamed label via the strings door",
            main.contains("R.string.pairing_unnamed_label"))
        val wiz = code("WizardActivity.kt")
        check("WizardActivity displayName: no generic Your AI fallback",
            !wiz.contains("\"Your AI\""))
        check("WizardActivity displayName: unnamed label via the strings door",
            wiz.contains("R.string.pairing_unnamed_label"))

        // ---- (b) approval-gate prompts ----
        for ((rel, label) in listOf(
            "server/AccessToolHost.kt" to "AccessToolHost",
            "server/ShellToolHost.kt" to "ShellToolHost",
            "server/OwedToolHost.kt" to "OwedToolHost",
        )) {
            val host = code(rel)
            check("$label gate: no generic Your AI fallback",
                !host.contains("\"Your AI\""))
            check("$label gate: session-less caller named unnamed via the strings door",
                host.contains("R.string.gate_unnamed_caller"))
            check("$label gate: blank session name also falls to the unnamed label",
                host.contains("takeIf { it.isNotBlank() }"))
        }
        val chat = code("server/ChatToolHost.kt")
        check("ChatToolHost chat_ask: caller name never blank at the gate",
            chat.contains("ConsentStrings.unnamedCallerLabel()"))
        val chatAct = code("AgentChatActivity.kt")
        check("AgentChatActivity: unnamed pairing labelled via the strings door",
            chatAct.contains("R.string.pairing_unnamed_label"))

        // ---- (c) mesh companion driving label ----
        val winDev = code("WindowsDeviceActivity.kt")
        check("WindowsDeviceActivity: no generic The agent stand-in",
            !winDev.contains("\"The agent\""))
        check("WindowsDeviceActivity: blank driver stated unnamed via the strings door",
            winDev.contains("R.string.mesh_unnamed_agent_driving"))

        // ---- Whole-tree sweep: no generic stand-in name fallback remains ----
        val genericPatterns = listOf(
            "?: \"Your AI\"", ".ifBlank { \"Your AI\" }",
            "?: \"My AI\"", ".ifBlank { \"My AI\" }",
            ".ifBlank { \"The agent\" }", "\"tile_default_agent\"",
        )
        val offenders = mutableListOf<String>()
        src.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val c = codeOf(f)
            for (p in genericPatterns) {
                if (c.contains(p)) offenders.add("${f.name}: $p")
            }
        }
        check("whole tree: no generic stand-in name fallback in any Kotlin source",
            offenders.isEmpty(), offenders.joinToString("; "))

        println("W81Fr123Test: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

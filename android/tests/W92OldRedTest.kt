import io.agenticcontrol.app.design.PresenceLaw
import io.agenticcontrol.app.presence.PresencePalette
import java.io.File

/**
 * W92 — Android old-red leftovers: every C62828 (and off-token red
 * in a STOP/danger role) dispositioned against the STOP token of
 * record #DC2626 (W72 live-measured; W84 aligned HeroDesign;
 * W90 aligned Windows + the hues-parity pin).
 *
 * Consumer traces behind these pins (lane log W92):
 *  - UiKit.DANGER is LIVE: it fills UiKit.stopButton (home STOP,
 *    session STOP, destructive "Remove …"), colours the access
 *    editor's refusal line, and backs BAD_TEXT. Aligned to the
 *    token; its companion DANGER_DEEP was already the token's
 *    darken step #B91C1C and is pinned as such.
 *  - PresencePalette.DEFAULT_STOP paints NOTHING (picker abolished
 *    in W7; PresenceSettings deletes the legacy colour keys
 *    unread; PresenceOverlay paints STOP only from
 *    PresenceLaw.HUE_STOP and uses PresencePalette solely for the
 *    pure withAlpha). Aligned anyway — a stale pre-token red in a
 *    STOP-named default is how the W84/W90 divergence happened.
 *  - PresencePalette.LEGACY_DEFAULTS.stop KEEPS the old red: it
 *    is the migration record of the pre-0.4.0 defaults; its value
 *    is the historical fact and paints nothing.
 *  - StreamViewer's "Stop stream" control is a live STOP surface;
 *    its off-token Material red was aligned in hue to the token
 *    at its pre-existing 0xCC alpha.
 *  - PresenceOverlay's syncBadge (#E69B1B1B) is a justified keep:
 *    a record-derived session-state badge (Recording / blanked /
 *    input-blocked), not STOP/destructive chrome (W84 item 8).
 *
 * Args: [0] = android project dir.
 */
object W92OldRedTest {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    /** Source with block comments and //-comment lines stripped,
     *  so pins judge code, not the historical notes. */
    private fun codeOf(f: File): String {
        var s = f.readText()
        s = s.replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        return s.lines().filter { !it.trimStart().startsWith("//") }
            .joinToString("\n")
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args.getOrElse(0) { "." })
        val src = File(root, "app/src/main/java")

        // ---- PresencePalette values (JVM-pure model) ----
        check("W92: palette STOP default is the token red #DC2626",
            PresencePalette.DEFAULT_STOP == 0xFFDC2626.toInt(),
            "was ${"%08X".format(PresencePalette.DEFAULT_STOP)}")
        check("W92: palette STOP default equals PresenceLaw.HUE_STOP",
            PresencePalette.DEFAULT_STOP == PresenceLaw.HUE_STOP)
        check("W92: DEFAULTS.stop carries the token",
            PresencePalette.DEFAULTS.stop == 0xFFDC2626.toInt())
        check("W92: STOP item default carries the token",
            PresencePalette.ITEMS.first { it.key == PresencePalette.KEY_STOP }.default
                == 0xFFDC2626.toInt())
        check("W92: 'Red' preset is the token red",
            PresencePalette.PRESETS.first { it.first == "Red" }.second
                == 0xFFDC2626.toInt())
        check("W92: LEGACY record keeps the historical pre-token red",
            PresencePalette.LEGACY_DEFAULTS.stop == 0xFFC62828.toInt(),
            "was ${"%08X".format(PresencePalette.LEGACY_DEFAULTS.stop)}")

        // ---- UiKit source pins (UiKit is android.*) ----
        val uikit = codeOf(File(src, "io/agenticcontrol/app/ui/UiKit.kt"))
        check("W92: UiKit.DANGER is the token red",
            uikit.contains("val DANGER = 0xFFDC2626.toInt()"))
        check("W92: UiKit.DANGER_DEEP is the token darken step #B91C1C",
            uikit.contains("val DANGER_DEEP = 0xFFB91C1C.toInt()"))
        check("W92: stopButton fills from DANGER",
            uikit.contains("setColor(DANGER)"))
        check("W92: BAD_TEXT still aliases DANGER",
            uikit.contains("val BAD_TEXT = DANGER"))
        check("W92: no old red left in UiKit code",
            !uikit.contains("C62828"))

        // ---- StreamViewer source pins (android.*) ----
        val viewer = codeOf(File(src, "io/agenticcontrol/app/StreamViewer.kt"))
        check("W92: Stop-stream control paints the token hue at 0xCC",
            viewer.contains("0xCCDC2626"))
        check("W92: no Material error red left in StreamViewer",
            !viewer.contains("B3261E"))

        // ---- PresenceOverlay justified keep ----
        val overlay = codeOf(File(src,
            "io/agenticcontrol/app/presence/PresenceOverlay.kt"))
        check("W92: syncBadge keeps its justified status-badge red",
            overlay.contains("#E69B1B1B"))

        // ---- Whole-tree sweep pin: the old red survives ONLY as
        // the single LEGACY_DEFAULTS migration record ----
        var c62828Total = 0
        var c62828Files = mutableListOf<String>()
        var b3261eTotal = 0
        src.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .forEach { f ->
                val code = codeOf(f)
                val n = code.split("C62828").size - 1
                if (n > 0) { c62828Total += n; c62828Files.add(f.name) }
                b3261eTotal += code.split("B3261E").size - 1
            }
        check("W92: exactly one C62828 remains in app code (the LEGACY record)",
            c62828Total == 1 && c62828Files == listOf("PresencePalette.kt"),
            "found $c62828Total in $c62828Files")
        check("W92: no B3261E remains anywhere in app code",
            b3261eTotal == 0, "found $b3261eTotal")

        println("W92OldRedTest: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

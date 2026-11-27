import io.deskguest.app.design.HeroThemes
import io.deskguest.app.design.PresenceLaw
import java.io.File

/**
 * W84 / FR-117 — Android presence Box alignment to the Gemini
 * token family (cross-platform design of record; Windows aligned
 * in W72, live-capture verified there):
 *  - Box/pill fill  = navy  #0F2537
 *  - STOP red       =       #DC2626
 *  - trim           = gold #E5A93B WHERE THE DESIGN USES TRIM —
 *    the Android design of record uses no gold trim: the Box edge
 *    is the actor hue edge (BoxModel.hueEdge), part of the state
 *    family. The state hues (violet AI / green person / amber
 *    waiting) are NOT re-themed by FR-117 and are pinned
 *    unchanged here.
 *
 * Pins: the token values on the pure model (HeroDesign is
 * JVM-compiled), the relational theme pins (both themes carry the
 * token fill and the token STOP), and source pins on the
 * android.* renderer (PresenceOverlay) proving the named Box, the
 * FR-122 defect Box and both STOP buttons paint from those model
 * values — and that no stale pre-alignment hex survives in the
 * presence renderer.
 *
 * Args: [0] = android project dir.
 */
object W84Fr117Test {
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

        // ---- Token values on the model ----
        check("FR-117: Box fill is the Gemini token navy #0F2537",
            HeroThemes.BOX_BACKGROUND == 0xFF0F2537.toInt(),
            "was ${"%08X".format(HeroThemes.BOX_BACKGROUND)}")
        check("FR-117: STOP hue is the token red #DC2626",
            PresenceLaw.HUE_STOP == 0xFFDC2626.toInt(),
            "was ${"%08X".format(PresenceLaw.HUE_STOP)}")

        // ---- Both themes carry the tokens (Box always dark) ----
        check("FR-117: light theme Box fill is the token navy",
            HeroThemes.LIGHT.boxBackground == 0xFF0F2537.toInt())
        check("FR-117: dark theme Box fill is the token navy",
            HeroThemes.DARK.boxBackground == 0xFF0F2537.toInt())
        check("FR-117: light theme stopRed is the token red",
            HeroThemes.LIGHT.stopRed == 0xFFDC2626.toInt())
        check("FR-117: dark theme stopRed is the token red",
            HeroThemes.DARK.stopRed == 0xFFDC2626.toInt())

        // ---- State family NOT re-themed ----
        check("FR-117: AI state hue unchanged (violet #7C4DFF)",
            PresenceLaw.HUE_AI == 0xFF7C4DFF.toInt())
        check("FR-117: person state hue unchanged (green #2FA84F)",
            PresenceLaw.HUE_HUMAN == 0xFF2FA84F.toInt())
        check("FR-117: waiting state hue unchanged (amber #F2A900)",
            PresenceLaw.HUE_IDLE == 0xFFF2A900.toInt())
        check("FR-117: four hues still distinct",
            setOf(PresenceLaw.HUE_HUMAN, PresenceLaw.HUE_AI,
                PresenceLaw.HUE_IDLE, PresenceLaw.HUE_STOP).size == 4)
        check("FR-117: Box text colour unchanged (#F4F4F6)",
            HeroThemes.BOX_ON_BACKGROUND == 0xFFF4F4F6.toInt())

        // ---- Renderer source pins (PresenceOverlay is android.*) ----
        val overlay = codeOf(File(src,
            "io/deskguest/app/presence/PresenceOverlay.kt"))
        check("renderer: Box fill paints from HeroThemes.BOX_BACKGROUND",
            overlay.contains("io.deskguest.app.design.HeroThemes.BOX_BACKGROUND"))
        check("renderer: STOP paints from PresenceLaw.HUE_STOP",
            overlay.contains("io.deskguest.app.design.PresenceLaw.HUE_STOP"))
        check("renderer: no stale pre-alignment Box hex #14141C",
            !overlay.contains("14141C"))
        check("renderer: no stale pre-alignment STOP hex #C62828",
            !overlay.contains("C62828"))
        check("renderer: no hard-coded token hex bypassing the model",
            !overlay.contains("0F2537") && !overlay.contains("DC2626"))

        // ---- Model source pins: the old values are gone ----
        val hero = codeOf(File(src,
            "io/deskguest/app/design/HeroDesign.kt"))
        check("model: token navy literal at BOX_BACKGROUND",
            hero.contains("BOX_BACKGROUND: Int = 0xFF0F2537.toInt()"))
        check("model: token red literal at HUE_STOP",
            hero.contains("HUE_STOP: Int = 0xFFDC2626.toInt()"))
        check("model: no stale #14141C anywhere",
            !hero.contains("14141C"))
        check("model: no stale #C62828 anywhere",
            !hero.contains("C62828"))

        println("W84Fr117Test: $passes PASS / $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}

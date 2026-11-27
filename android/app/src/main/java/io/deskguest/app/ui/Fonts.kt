package io.deskguest.app.ui

import android.content.Context
import android.graphics.Typeface

/**
 * Bundled type (0.4.0): Inter for UI text and JetBrains Mono for
 * codes and addresses, shipped as assets under the SIL Open Font
 * License 1.1 (assets/fonts/OFL.txt). Loaded once; if an asset is
 * ever missing the platform sans/mono takes over so text never
 * breaks. Bold is synthesized from the regular face by the platform
 * (Typeface.create with a style), which variable fonts handle well.
 */
object Fonts {

    @Volatile
    private var sans: Typeface? = null
    @Volatile
    private var mono: Typeface? = null

    private fun loadSans(context: Context): Typeface {
        sans?.let { return it }
        val loaded = try {
            Typeface.createFromAsset(context.assets, "fonts/Inter.ttf")
        } catch (e: Exception) {
            null
        } ?: Typeface.SANS_SERIF
        sans = loaded
        return loaded
    }

    private fun loadMono(context: Context): Typeface {
        mono?.let { return it }
        val loaded = try {
            Typeface.createFromAsset(context.assets, "fonts/JetBrainsMono.ttf")
        } catch (e: Exception) {
            null
        } ?: Typeface.MONOSPACE
        mono = loaded
        return loaded
    }

    fun regular(context: Context): Typeface = loadSans(context)

    fun medium(context: Context): Typeface {
        // bd-and-ui F12 fix: "medium" was synthesized from BOLD —
        // every medium label rendered a weight heavier than
        // designed. On API 28+ ask the variable font for a true
        // 500 weight; older devices keep the bold synthesis.
        val base = loadSans(context)
        return if (android.os.Build.VERSION.SDK_INT >= 28) {
            Typeface.create(base, 500, false)
        } else {
            Typeface.create(base, Typeface.BOLD)
        }
    }

    /** W10 (V3-F1): a true 600 weight — the gate exits carry
     *  GateModel's 600 weight, and "medium" (500) is not it. */
    fun semibold(context: Context): Typeface {
        val base = loadSans(context)
        return if (android.os.Build.VERSION.SDK_INT >= 28) {
            Typeface.create(base, 600, false)
        } else {
            Typeface.create(base, Typeface.BOLD)
        }
    }

    fun mono(context: Context): Typeface = loadMono(context)

    fun monoBold(context: Context): Typeface =
        Typeface.create(loadMono(context), Typeface.BOLD)
}

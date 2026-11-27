package io.deskguest.app.presence

/**
 * The presence color scheme (0.3.8): which color paints which part of
 * the on-screen presence layer — edge glow, cursor, tap ripple, target
 * highlight, banner accent, STOP button. Pure logic, no Android
 * imports: the defaults, the preset palette offered in the app, and
 * the hex parsing/formatting the settings UI uses. Persistence lives
 * in PresenceSettings; painting lives in PresenceOverlay.
 *
 * Defaults are the light-blue family of the approved 0.4.0 design
 * set (sky glow, lighter sky cursor, deep-sky banner accent); STOP
 * defaults to the token red (#DC2626, aligned in W92). The pre-0.4.0 violet
 * family is preserved as [LEGACY_DEFAULTS] so stored preferences
 * can be migrated: a stored value equal to the old default was
 * never a deliberate choice and follows the new default, while a
 * deliberately customized color is kept (see PresenceSettings).
 */
object PresencePalette {

    data class Config(
        val glow: Int,
        val cursor: Int,
        val ripple: Int,
        val highlight: Int,
        val bannerAccent: Int,
        val stop: Int
    ) {
        fun get(key: String): Int = when (key) {
            KEY_CURSOR -> cursor
            KEY_RIPPLE -> ripple
            KEY_HIGHLIGHT -> highlight
            KEY_BANNER -> bannerAccent
            KEY_STOP -> stop
            else -> glow
        }

        fun with(key: String, value: Int): Config = when (key) {
            KEY_CURSOR -> copy(cursor = value)
            KEY_RIPPLE -> copy(ripple = value)
            KEY_HIGHLIGHT -> copy(highlight = value)
            KEY_BANNER -> copy(bannerAccent = value)
            KEY_STOP -> copy(stop = value)
            else -> copy(glow = value)
        }
    }

    data class Item(val key: String, val label: String, val default: Int)

    const val KEY_GLOW = "glow"
    const val KEY_CURSOR = "cursor"
    const val KEY_RIPPLE = "ripple"
    const val KEY_HIGHLIGHT = "highlight"
    const val KEY_BANNER = "banner"
    const val KEY_STOP = "stop"

    val DEFAULT_GLOW = 0xFF38BDF8.toInt()
    val DEFAULT_CURSOR = 0xFF7DD3FC.toInt()
    val DEFAULT_RIPPLE = 0xFF38BDF8.toInt()
    val DEFAULT_HIGHLIGHT = 0xFF38BDF8.toInt()
    val DEFAULT_BANNER = 0xFF0284C7.toInt()
    /*
     * W92: aligned to the STOP token of record (#DC2626). This
     * default paints nothing today — the picker was abolished in
     * W7, PresenceSettings deletes the legacy colour keys unread,
     * and PresenceOverlay paints STOP solely from
     * PresenceLaw.HUE_STOP (which carries this same token). The
     * value is aligned anyway: a stale pre-token red sitting in a
     * STOP-named default is exactly how the W84/W90 divergence
     * happened, and if this palette is ever revived its STOP
     * default must be the token, not a second red.
     */
    val DEFAULT_STOP = 0xFFDC2626.toInt()

    val DEFAULTS = Config(
        glow = DEFAULT_GLOW,
        cursor = DEFAULT_CURSOR,
        ripple = DEFAULT_RIPPLE,
        highlight = DEFAULT_HIGHLIGHT,
        bannerAccent = DEFAULT_BANNER,
        stop = DEFAULT_STOP
    )

    /**
     * The pre-0.4.0 (violet) defaults, kept for migration only.
     * W92: LEGACY stop intentionally keeps its historical value —
     * this Config is a RECORD of what the old defaults were, so
     * its stop value is the pre-token red by definition. It paints
     * nothing and must never be "aligned": changing it would
     * falsify the migration record. The live STOP token is
     * PresenceLaw.HUE_STOP (#DC2626); the current default above
     * carries it.
     */
    val LEGACY_DEFAULTS = Config(
        glow = 0xFF7C4DFF.toInt(),
        cursor = 0xFF7C4DFF.toInt(),
        ripple = 0xFF9D7BFF.toInt(),
        highlight = 0xFF7C4DFF.toInt(),
        bannerAccent = 0xFF7C4DFF.toInt(),
        stop = 0xFFC62828.toInt()
    )

    /** The six customizable items, in settings display order. */
    val ITEMS: List<Item> = listOf(
        Item(KEY_GLOW, "Screen edge glow", DEFAULT_GLOW),
        Item(KEY_CURSOR, "Cursor", DEFAULT_CURSOR),
        Item(KEY_RIPPLE, "Tap ripple", DEFAULT_RIPPLE),
        Item(KEY_HIGHLIGHT, "Target highlight", DEFAULT_HIGHLIGHT),
        Item(KEY_BANNER, "Banner accent", DEFAULT_BANNER),
        Item(KEY_STOP, "STOP button", DEFAULT_STOP)
    )

    /** Preset swatches offered for every item, in display order. */
    val PRESETS: List<Pair<String, Int>> = listOf(
        "Violet" to 0xFF7C4DFF.toInt(),
        "Lavender" to 0xFF9D7BFF.toInt(),
        "Blue" to 0xFF2979FF.toInt(),
        "Cyan" to 0xFF00B0FF.toInt(),
        "Teal" to 0xFF00BFA5.toInt(),
        "Green" to 0xFF43A047.toInt(),
        "Amber" to 0xFFFFB300.toInt(),
        "Orange" to 0xFFFB8C00.toInt(),
        "Pink" to 0xFFEC407A.toInt(),
        "Red" to 0xFFDC2626.toInt(),
        "White" to 0xFFEEEEEE.toInt(),
        "Graphite" to 0xFF424242.toInt()
    )

    /**
     * Parse a hex color as typed in the settings UI: "#RRGGBB" or
     * "RRGGBB" (an "0x" prefix is also accepted). Returns an opaque
     * ARGB int, or null when the text is not exactly six hex digits.
     */
    fun parseHex(text: String): Int? {
        var t = text.trim()
        if (t.startsWith("#")) t = t.substring(1)
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2)
        if (t.length != 6) return null
        val value = t.toIntOrNull(16) ?: return null
        return (0xFF shl 24) or value
    }

    /** Format an ARGB int the way the settings UI shows it: "#RRGGBB". */
    fun formatHex(argb: Int): String =
        "#%06X".format(argb and 0xFFFFFF)

    /** The same color at a different opacity (alpha 0–255). */
    fun withAlpha(argb: Int, alpha: Int): Int =
        (alpha.coerceIn(0, 255) shl 24) or (argb and 0xFFFFFF)
}

package io.agenticcontrol.app.presence

import android.content.Context

/**
 * Presence settings — W7 re-skin to the design record (§1.1, §4
 * A3). Presence hues are MEANINGS, fixed by PresenceLaw; there is
 * NO colour picker and no per-part colour choice anywhere. The
 * only owner settings are COMFORT settings: the Glow's intensity
 * (never below its floor) and whether the Glow breathes (static
 * by default, OI-04). The consent floor itself is not a setting.
 *
 * Migration: the legacy colour keys written by the pre-W7 picker
 * (PresencePalette items in this same "presence" prefs file) are
 * DELETED on first load — persisted picker state is no longer
 * consumed by any surface.
 */
object PresenceSettings {

    private const val PREFS = "presence"
    private const val KEY_GLOW_INTENSITY = "comfort_glow_intensity_pct"
    private const val KEY_BREATH = "comfort_glow_breath"

    /** The Glow intensity floor (§4 A3: intensity above its floor). */
    const val GLOW_INTENSITY_FLOOR_PCT = 40

    data class Comfort(
        val glowIntensityPct: Int = 100,
        val breathEnabled: Boolean = false
    )

    /** Legacy picker keys (PresencePalette item keys) — removed,
     *  never read. */
    private val LEGACY_COLOR_KEYS = listOf(
        "glow", "cursor", "ripple", "highlight", "banner", "stop"
    )

    fun load(context: Context): Comfort {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        // One-time migration: drop every legacy colour key so no
        // surface can ever consume picker state again.
        if (LEGACY_COLOR_KEYS.any { prefs.contains(it) }) {
            val edit = prefs.edit()
            LEGACY_COLOR_KEYS.forEach { edit.remove(it) }
            edit.apply()
        }
        return Comfort(
            glowIntensityPct = prefs.getInt(KEY_GLOW_INTENSITY, 100)
                .coerceIn(GLOW_INTENSITY_FLOOR_PCT, 100),
            breathEnabled = prefs.getBoolean(KEY_BREATH, false)
        )
    }

    fun saveGlowIntensity(context: Context, pct: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt(
                KEY_GLOW_INTENSITY,
                pct.coerceIn(GLOW_INTENSITY_FLOOR_PCT, 100)
            ).apply()
    }

    fun saveBreath(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_BREATH, enabled).apply()
    }
}

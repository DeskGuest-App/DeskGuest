import io.agenticcontrol.app.presence.PresencePalette

/**
 * JVM tests for the presence color palette (0.3.8): defaults, hex
 * parsing/formatting as the settings UI uses it, and the Config
 * get/with round-trips the settings editor relies on.
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
    // Defaults (0.4.0): the approved light-blue family, STOP red.
    check("default glow is sky", PresencePalette.DEFAULTS.glow == 0xFF38BDF8.toInt())
    check("default cursor is light sky", PresencePalette.DEFAULTS.cursor == 0xFF7DD3FC.toInt())
    check("default ripple is sky", PresencePalette.DEFAULTS.ripple == 0xFF38BDF8.toInt())
    check("default highlight is sky", PresencePalette.DEFAULTS.highlight == 0xFF38BDF8.toInt())
    check("default banner accent is deep sky", PresencePalette.DEFAULTS.bannerAccent == 0xFF0284C7.toInt())
    check("default stop is the token red", PresencePalette.DEFAULTS.stop == 0xFFDC2626.toInt())
    // The legacy (violet) family is preserved for migration checks.
    check("legacy glow is violet", PresencePalette.LEGACY_DEFAULTS.glow == 0xFF7C4DFF.toInt())
    check("legacy ripple is light violet", PresencePalette.LEGACY_DEFAULTS.ripple == 0xFF9D7BFF.toInt())
    check("legacy stop is red", PresencePalette.LEGACY_DEFAULTS.stop == 0xFFC62828.toInt())
    check(
        "legacy and new defaults differ (migration is meaningful)",
        PresencePalette.ITEMS.any {
            PresencePalette.LEGACY_DEFAULTS.get(it.key) != PresencePalette.DEFAULTS.get(it.key)
        }
    )
    check("six customizable items", PresencePalette.ITEMS.size == 6)
    check(
        "item defaults match DEFAULTS",
        PresencePalette.ITEMS.all { it.default == PresencePalette.DEFAULTS.get(it.key) }
    )
    check("twelve presets", PresencePalette.PRESETS.size == 12)

    // Hex parsing: the forms the settings UI accepts.
    check("parse #RRGGBB", PresencePalette.parseHex("#7C4DFF") == 0xFF7C4DFF.toInt())
    check("parse bare RRGGBB", PresencePalette.parseHex("DC2626") == 0xFFDC2626.toInt())
    check("parse lowercase", PresencePalette.parseHex("#00b0ff") == 0xFF00B0FF.toInt())
    check("parse trims space", PresencePalette.parseHex("  #43A047 ") == 0xFF43A047.toInt())
    check("parse 0x prefix", PresencePalette.parseHex("0xEC407A") == 0xFFEC407A.toInt())
    check("parsed colors are opaque", (PresencePalette.parseHex("#123456")!! ushr 24) == 0xFF)

    // Hex parsing: refused, never guessed.
    check("empty refused", PresencePalette.parseHex("") == null)
    check("short refused", PresencePalette.parseHex("#12345") == null)
    check("long refused", PresencePalette.parseHex("#1234567") == null)
    check("non-hex refused", PresencePalette.parseHex("#GGGGGG") == null)
    check("words refused", PresencePalette.parseHex("violet") == null)

    // Formatting round-trips.
    check("format", PresencePalette.formatHex(0xFF7C4DFF.toInt()) == "#7C4DFF")
    check(
        "format/parse round-trip",
        PresencePalette.PRESETS.all { (_, c) -> PresencePalette.parseHex(PresencePalette.formatHex(c)) == c }
    )

    // Config get/with per key.
    val changed = PresencePalette.DEFAULTS.with(PresencePalette.KEY_STOP, 0xFF2979FF.toInt())
    check("with sets the one key", changed.stop == 0xFF2979FF.toInt())
    check("with leaves the others", changed.glow == PresencePalette.DEFAULTS.glow)
    check(
        "get reads back every key",
        PresencePalette.ITEMS.all { item ->
            PresencePalette.DEFAULTS.with(item.key, 0xFF101010.toInt()).get(item.key) == 0xFF101010.toInt()
        }
    )

    // Alpha helper.
    check(
        "withAlpha replaces alpha only",
        PresencePalette.withAlpha(0xFF7C4DFF.toInt(), 46) == 0x2E7C4DFF.toInt()
    )
    check(
        "withAlpha clamps",
        (PresencePalette.withAlpha(0xFF7C4DFF.toInt(), 300) ushr 24) == 0xFF
    )

    println(if (failures == 0) "ALL PRESENCE PALETTE TESTS PASSED" else "$failures PRESENCE PALETTE TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

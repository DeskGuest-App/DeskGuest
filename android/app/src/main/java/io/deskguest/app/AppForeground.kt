package io.deskguest.app

/**
 * Whether the app's own UI is in the foreground (0.4.0). MainActivity
 * maintains it; the clipboard_get tool consults it because Android
 * only lets the foreground app read the clipboard — the tool reports
 * UNAVAILABLE instead of pretending otherwise.
 */
object AppForeground {
    @Volatile
    var isForeground: Boolean = false
}

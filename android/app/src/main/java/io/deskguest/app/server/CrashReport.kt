package io.deskguest.app.server

/**
 * Crash-report parsing (FEATURES §1 "Crash reports", surfacing leg
 * built 2026-11-23, Wave 11 Lane B).
 *
 * CrashTrap (Android layer) has recorded this app's own failures
 * to a file since 0.4.1 and MainActivity shows that file to the
 * owner on next open. What was missing was the MCP surfacing the
 * FEATURES entry claims: a paired agent diagnosing a broken
 * session had no way to read the report. [parse] turns the file's
 * text into the structured shape the `crash_report_read` tool
 * returns: when it happened, where it was caught, the top
 * exception line, and how many stack frames follow.
 *
 * Scope honesty: this is THIS app's crash record — the most recent
 * report only, because CrashTrap keeps only the most recent. It is
 * not a device-wide crash log and never claims to be; other apps'
 * crashes are not readable by a normal app and none are offered.
 *
 * Pure JVM — runs in the JVM suite.
 */
object CrashReport {

    data class Parsed(
        val recordedAt: String,
        val where: String,
        val exceptionLine: String,
        val frameCount: Int,
        val raw: String
    )

    /** CrashTrap's header: "DeskGuest failure report\n
     *  <yyyy-MM-dd HH:mm:ss> — <where>\n\n<stack>". A text that
     *  does not carry the header parses to null — the tool reports
     *  "no readable report" rather than guessing at a shape. */
    fun parse(text: String?): Parsed? {
        if (text.isNullOrBlank()) return null
        val lines = text.lines()
        if (lines.size < 2 || !lines[0].startsWith("DeskGuest failure report")) return null
        val header = lines[1]
        val sep = header.indexOf(" — ")
        if (sep < 0) return null
        val recordedAt = header.substring(0, sep).trim()
        val where = header.substring(sep + 3).trim()
        val body = lines.drop(2)
        val exceptionLine = body.firstOrNull { it.isNotBlank() }?.trim() ?: ""
        val frames = body.count { it.trimStart().startsWith("at ") }
        return Parsed(recordedAt, where, exceptionLine, frames, text)
    }
}

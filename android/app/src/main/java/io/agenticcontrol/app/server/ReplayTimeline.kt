package io.agenticcontrol.app.server

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Session-replay timeline rendering (FEATURES §7, in-app surface
 * leg built 2026-11-23, Wave 11 Lane B).
 *
 * The replay DATA source (ReplayLog) and the `session_replay_data`
 * tool were built 2026-11-22; what was missing was the surface the
 * FEATURES entry actually promises — "replay any session IN-APP:
 * timeline, cursor path, actions, gate events". This formatter is
 * the surface's whole rendering logic: the recorded events in
 * order, each with its wall-clock time and its offset from the
 * first event, in plain words. ReplayActivity displays exactly
 * these lines and adds nothing of its own.
 *
 * Honest limits, stated on the surface itself (the activity shows
 * the same note): the record covers this process's lifetime (the
 * durable evidence store is the audit log, owner-exported only),
 * and entries the bound dropped are counted in the header line,
 * never silently missing.
 *
 * Pure JVM — runs in the JVM suite.
 */
object ReplayTimeline {

    fun render(entries: List<ReplayLog.Entry>, dropped: Int): List<String> {
        if (entries.isEmpty()) {
            return listOf(
                "No session events recorded yet in this process.",
                "Sessions record here as they run; the durable evidence " +
                    "store is the audit log, which only you can export."
            )
        }
        val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        val first = entries.first().atMs
        val lines = mutableListOf<String>()
        lines.add(
            "${entries.size} session event(s)" +
                if (dropped > 0) " — $dropped oldest entr(ies) fell off the record's bound and are not shown" else ""
        )
        for (e in entries) {
            val offsetSec = (e.atMs - first) / 1000
            val detail = e.detail.entries
                .filter { it.value.isNotEmpty() }
                .joinToString(", ") { "${it.key}=${it.value}" }
            lines.add(
                "+${offsetSec}s  ${fmt.format(Date(e.atMs))}  ${e.state}" +
                    if (detail.isNotEmpty()) " — $detail" else ""
            )
        }
        return lines
    }
}

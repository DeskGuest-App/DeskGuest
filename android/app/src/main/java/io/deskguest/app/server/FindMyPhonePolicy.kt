package io.deskguest.app.server

/**
 * Find-my-phone policy (FEATURES §9, built 2026-11-23, Wave 11
 * Lane B): the pure rules behind the `find_my_phone` tool — an
 * owner request, relayed through a paired agent, to ring this
 * phone at full volume even on silent and to show owner text.
 *
 * The policy exists so the act stays an owner's act, never an
 * agent's toy:
 * - the ring is capped ([MAX_RING_SECONDS]) and rate-limited
 *   ([MIN_INTERVAL_MS]) — no loop, no flood;
 * - the owner text is capped and flattened to one line — it is
 *   shown on a notification, never executed, never a URL handler;
 * - an empty text is fine: the default "This phone was rung from
 *   DeskGuest" wording stands instead, so the surface always
 *   says whose act it was.
 *
 * Pure JVM — runs in the JVM suite. The Android leg (ringtone at
 * alarm volume + the visible notification) lives in OwedToolHost.
 */
object FindMyPhonePolicy {

    const val MAX_RING_SECONDS = 30
    const val DEFAULT_RING_SECONDS = 20
    const val MIN_INTERVAL_MS = 60_000L
    const val MAX_TEXT_CHARS = 120
    const val DEFAULT_TEXT = "This phone was rung from DeskGuest (find-my-phone)."

    /** The text to show, or null when the supplied text is over
     *  the cap (refused, never truncated silently). */
    fun ownerText(raw: String?): String? {
        val flat = raw?.replace(Regex("\\s+"), " ")?.trim().orEmpty()
        if (flat.length > MAX_TEXT_CHARS) return null
        return flat.ifEmpty { DEFAULT_TEXT }
    }

    fun ringSeconds(requested: Int): Int =
        if (requested <= 0) DEFAULT_RING_SECONDS else requested.coerceAtMost(MAX_RING_SECONDS)

    fun allowedNow(lastRingAtMs: Long, nowMs: Long): Boolean =
        lastRingAtMs <= 0L || nowMs - lastRingAtMs >= MIN_INTERVAL_MS
}

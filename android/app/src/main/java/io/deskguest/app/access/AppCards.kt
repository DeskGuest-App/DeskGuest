package io.deskguest.app.access

import io.deskguest.app.safety.InvisibleAppRules
import org.json.JSONObject

/**
 * App cards (FEATURES §2, built 2026-11-23, Wave 11 Lane B):
 * per-app guidance notes — known quirks, preferred flows — that an
 * agent consults before driving an unfamiliar app, and records
 * after learning one.
 *
 * The store is deliberately small and honest:
 * - keyed by normalized package name (same normalization the
 *   invisible-apps blocklist uses: lower-cased, trimmed, at least
 *   two segments — a junk key is refused, never stored);
 * - one note per app, capped in length; a write replaces the note
 *   whole, so a card can never accrete contradictory halves;
 * - the whole store is capped; writing beyond the cap refuses and
 *   names the cap instead of evicting another app's card silently;
 * - cards for invisible apps (§7.5) are refused at the tool layer:
 *   an app the owner marked unseeable gets no guidance file either.
 *
 * Persistence is the tool layer's job (one JSON file in the app's
 * own files folder); [encode]/[decode] here are the whole format.
 * A corrupt file decodes to an empty store and says so via
 * [decode]'s null — the caller reports it, never guesses.
 *
 * Pure JVM — runs in the JVM suite.
 */
class AppCards private constructor(private val notes: LinkedHashMap<String, String>) {

    constructor() : this(LinkedHashMap())

    /** Store a note for [packageName]; returns the normalized key,
     *  or null when the key is invalid, the note is blank/over the
     *  cap, or the store is full of other apps' cards. */
    fun put(packageName: String, note: String): String? {
        val key = InvisibleAppRules.normalize(packageName) ?: return null
        val trimmed = note.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_NOTE_CHARS) return null
        if (!notes.containsKey(key) && notes.size >= MAX_CARDS) return null
        notes[key] = trimmed
        return key
    }

    fun get(packageName: String): String? {
        val key = InvisibleAppRules.normalize(packageName) ?: return null
        return notes[key]
    }

    fun remove(packageName: String): Boolean {
        val key = InvisibleAppRules.normalize(packageName) ?: return false
        return notes.remove(key) != null
    }

    fun packages(): List<String> = notes.keys.toList()

    fun size(): Int = notes.size

    fun encode(): String {
        val obj = JSONObject()
        for ((k, v) in notes) obj.put(k, v)
        return obj.toString()
    }

    companion object {
        const val MAX_CARDS = 100
        const val MAX_NOTE_CHARS = 2_000

        /** Null on any corruption — the caller reports an unreadable
         *  store rather than treating it as an empty one. */
        fun decode(text: String?): AppCards? {
            if (text == null) return AppCards()
            return try {
                val obj = JSONObject(text)
                val cards = AppCards()
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = obj.optString(k, "")
                    if (cards.put(k, v) == null) return null
                }
                cards
            } catch (_: Exception) {
                null
            }
        }
    }
}

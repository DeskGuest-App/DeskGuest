package io.agenticcontrol.app.safety

import android.content.Context

/**
 * Android storage for the invisible-apps blocklist (SPEC §7.5):
 * a SharedPreferences string owned by the app, edited only from
 * the app's own UI (MainActivity's Invisible apps section). Tool
 * hosts read through [blocklist], which reloads when the stored
 * value changes so an owner's edit takes effect on the next tool
 * call, never at some later restart.
 */
object InvisibleAppStore {

    private const val PREFS = "invisible_apps"
    private const val KEY = "packages"

    @Volatile
    private var cached: InvisibleAppBlocklist = InvisibleAppBlocklist()

    @Volatile
    private var cachedEncoded: String? = null

    @Synchronized
    fun blocklist(context: Context): InvisibleAppBlocklist {
        val stored = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, "") ?: ""
        if (stored != cachedEncoded) {
            cached = InvisibleAppBlocklist.decode(stored)
            cachedEncoded = stored
        }
        return cached
    }

    fun isBlocked(context: Context, packageName: String?): Boolean =
        blocklist(context).isBlocked(packageName)

    /** Owner-side edit (app UI only — never a tool). */
    fun mark(context: Context, raw: String?): String? {
        val list = blocklist(context)
        val normalized = list.mark(raw) ?: return null
        persist(context, list)
        return normalized
    }

    /** Owner-side edit (app UI only — never a tool). */
    fun unmark(context: Context, raw: String?): Boolean {
        val list = blocklist(context)
        val removed = list.unmark(raw)
        if (removed) persist(context, list)
        return removed
    }

    private fun persist(context: Context, list: InvisibleAppBlocklist) {
        val encoded = list.encode()
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY, encoded).apply()
        cachedEncoded = encoded
    }
}

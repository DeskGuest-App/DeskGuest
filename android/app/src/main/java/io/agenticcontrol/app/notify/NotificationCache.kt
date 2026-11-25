package io.agenticcontrol.app.notify

/**
 * The active-notification cache behind `notifications_read`
 * (SPEC §6, FEATURES §1) — BD-XCHECK owed item, built 2026-11-22.
 *
 * Platform law: a normal Android app can read notifications only
 * through a NotificationListenerService the USER enables in system
 * Settings (BIND_NOTIFICATION_LISTENER_SERVICE). There is no other
 * route and this product uses no other route: AcpNotificationListener
 * (Android layer) feeds this cache while the grant is live, and the
 * tool reports UNAVAILABLE with the fix when the grant is absent.
 * The cache holds only currently-active notifications (a removal
 * removes the entry), is bounded, and is memory-only — nothing is
 * persisted, and the tool additionally requires a live control
 * session (FEATURES §6: no ambient capture outside a session).
 *
 * Pure JVM — runs in the JVM suite.
 */
object NotificationCache {

    data class Entry(
        val key: String,
        val packageName: String,
        val title: String,
        val text: String,
        val postedAtMs: Long
    )

    const val MAX_ENTRIES = 50
    const val MAX_TEXT_CHARS = 500

    private val lock = Any()
    private val byKey = linkedMapOf<String, Entry>()

    fun posted(key: String, packageName: String, title: String, text: String, postedAtMs: Long) {
        synchronized(lock) {
            byKey.remove(key)
            byKey[key] = Entry(
                key, packageName,
                title.take(MAX_TEXT_CHARS), text.take(MAX_TEXT_CHARS), postedAtMs
            )
            while (byKey.size > MAX_ENTRIES) {
                byKey.remove(byKey.keys.first())
            }
        }
    }

    fun removed(key: String) {
        synchronized(lock) { byKey.remove(key) }
    }

    fun clear() {
        synchronized(lock) { byKey.clear() }
    }

    /** Active notifications, most recent last. */
    fun active(): List<Entry> = synchronized(lock) { byKey.values.toList() }
}

package io.agenticcontrol.app.notify

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * The notification-listener behind `notifications_read` (SPEC §6) —
 * BD-XCHECK owed item, built 2026-11-22. Android only delivers
 * notifications to a listener the USER enables in system Settings
 * (Settings → Notifications → Device & app notifications); the
 * system binds this service only while that grant is live, and
 * revoking it unbinds the service and empties the feed. The service
 * does nothing but mirror the currently-active set into
 * NotificationCache (memory-only, bounded); it never posts, never
 * dismisses, and never acts on a notification.
 */
class AcpNotificationListener : NotificationListenerService() {

    override fun onListenerConnected() {
        super.onListenerConnected()
        connected = true
        try {
            activeNotifications?.forEach { sbn -> feed(sbn) }
        } catch (_: Exception) {
        }
    }

    override fun onListenerDisconnected() {
        connected = false
        NotificationCache.clear()
        super.onListenerDisconnected()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn?.let { feed(it) }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        sbn?.let { NotificationCache.removed(it.key) }
    }

    private fun feed(sbn: StatusBarNotification) {
        val extras = sbn.notification?.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            ?: extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        NotificationCache.posted(
            key = sbn.key,
            packageName = sbn.packageName ?: "",
            title = title,
            text = text,
            postedAtMs = sbn.postTime
        )
    }

    companion object {
        /** True only while the system has this listener bound —
         *  i.e. only while the user's grant is live. */
        @Volatile
        var connected: Boolean = false
    }
}

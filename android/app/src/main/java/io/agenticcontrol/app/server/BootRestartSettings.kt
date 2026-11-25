package io.agenticcontrol.app.server

import android.content.Context

/**
 * C19 — persistence for the boot-restart setting and the
 * opened-once marker, following the ApprovalSettings pattern:
 * one small SharedPreferences file, plain values only.
 *
 * Nothing here touches the Keystore, an identity, or any store —
 * these are exactly the facts the boot path is allowed to read
 * (see BootRestartPolicy's startup-path discipline).
 */
object BootRestartSettings {

    private const val PREFS = "boot_restart"
    private const val KEY_ENABLED = "restart_after_reboot"
    private const val KEY_OPENED_ONCE = "opened_once"

    /** "Restart the control channel after reboot" — default ON
     *  (BootRestartPolicy.DEFAULT_ENABLED). */
    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, BootRestartPolicy.DEFAULT_ENABLED)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    /** True once the owner has opened the app at least once. An
     *  app that has never been opened is in Android's stopped
     *  state and receives no boot broadcast; this marker is the
     *  same boundary, recorded from the UI side. */
    fun hasOpenedAppBefore(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_OPENED_ONCE, false)

    /** Called from the app's UI entry (MainActivity) — the one
     *  place that proves a human opened the app. Never called
     *  from the boot path itself. */
    fun markOpened(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_OPENED_ONCE, true).apply()
    }
}

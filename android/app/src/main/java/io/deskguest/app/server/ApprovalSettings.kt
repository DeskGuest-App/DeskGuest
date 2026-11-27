package io.deskguest.app.server

import android.content.Context

/**
 * Persistence for the approval policies (0.4.0): one SharedPreferences
 * entry per action class. Missing entries take ApprovalGate's
 * defaults, so a fresh install asks first for everything sensitive.
 */
object ApprovalSettings {

    private const val PREFS = "approvals"

    fun load(context: Context, actionClass: ApprovalGate.ActionClass): ApprovalGate.Policy {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(actionClass.name, null) ?: return ApprovalGate.defaultPolicy(actionClass)
        return try {
            ApprovalGate.Policy.valueOf(raw)
        } catch (e: Exception) {
            ApprovalGate.defaultPolicy(actionClass)
        }
    }

    fun save(context: Context, actionClass: ApprovalGate.ActionClass, policy: ApprovalGate.Policy) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(actionClass.name, policy.name).apply()
    }
}

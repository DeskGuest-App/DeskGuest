package io.agenticcontrol.app.strings

import android.content.Context
import android.content.res.Resources
import io.agenticcontrol.app.R

/**
 * U8: the one door the consent / presence / STOP surfaces use to read
 * their strings. Reads the (localisable) resource; on a missing or
 * blank resource it falls back to the built-in default in
 * [ConsentStrings] — the surface is never blanked by a resource
 * failure. Formatting goes through the same fallback: if the resource
 * template is blank, the default template is formatted instead.
 */
fun Context.consentString(resId: Int): String {
    val key = try {
        resources.getResourceEntryName(resId)
    } catch (_: Resources.NotFoundException) {
        ""
    }
    val value = try {
        getString(resId)
    } catch (_: Resources.NotFoundException) {
        null
    }
    return ConsentStrings.resolve(key, value)
}

fun Context.consentString(resId: Int, vararg args: Any): String {
    val key = try {
        resources.getResourceEntryName(resId)
    } catch (_: Resources.NotFoundException) {
        ""
    }
    val template = try {
        getString(resId)
    } catch (_: Resources.NotFoundException) {
        null
    }
    val resolved = ConsentStrings.resolve(key, template)
    return if (args.isEmpty()) resolved else String.format(resolved, *args)
}

/** The R ids of every U8 consent string, for the lint-style test. */
val CONSENT_STRING_IDS: List<Int> = listOf(
    R.string.presence_stop,
    R.string.presence_resume,
    R.string.presence_paused_title,
    R.string.presence_paused_agent,
    R.string.consent_session_active,
    R.string.presence_driver_name_missing,
    R.string.presence_driver_name_missing_hint,
    R.string.approval_title,
    R.string.approval_wants_to,
    R.string.approval_deny,
    R.string.approval_approve,
    R.string.tile_paused_label,
    R.string.tile_paused_subtitle,
    R.string.tile_stop_label,
    R.string.tile_controlling_subtitle,
    R.string.pairing_unnamed_label,
    R.string.gate_unnamed_caller,
    R.string.mesh_unnamed_agent_driving,
    R.string.tile_channel_open_label,
    R.string.tile_channel_open_subtitle,
    R.string.tile_channel_stopped_label,
    R.string.tile_channel_stopped_subtitle,
    R.string.session_none_title,
    R.string.session_none_body,
    R.string.session_paused_chip,
    R.string.session_active_chip,
    R.string.session_paused_body,
    R.string.session_resume,
    R.string.session_stopped_toast,
    R.string.session_actions,
    R.string.home_no_one_in_phone,
    R.string.home_agent_in_phone,
    R.string.home_connected_not_session,
    R.string.home_invisible_apps_not_built,
    R.string.gate_deny_and_end,
    R.string.gate_draft_not_sent,
    R.string.gate_asked_from_chat,
    R.string.gate_no_session_allow,
    R.string.session_provider_line,
    R.string.session_vendor_line,
    R.string.session_replay_not_built,
    R.string.session_not_seen,
    R.string.session_seen_so_far,
    R.string.session_presence_on_frames,
    R.string.presence_youre_driving,
    R.string.presence_watchdog_line,
    R.string.presence_screen_not_shown,
    R.string.chat_sent_count,
    R.string.wizard_click_budget,
)

package io.deskguest.app.strings

/**
 * U8: built-in default values for the consent / presence / STOP
 * surface strings, plus the pure fallback resolver.
 *
 * The surfaces render from `res/values/strings.xml` (so the consent
 * surface can be localised). This map is the safety net: if a resource
 * is ever missing or blank — a bad locale overlay, a stripped build —
 * the resolver returns the built-in English default instead of an
 * empty string, so the STOP button and the presence banner can never
 * be blanked by a resource failure. The values here are the exact
 * English wording the surfaces shipped with; wording is law.
 *
 * Pure Kotlin (no Android imports) so the JVM suite can prove the
 * fallback behaviour directly.
 */
object ConsentStrings {

    val DEFAULTS: Map<String, String> = mapOf(
        "presence_stop" to "STOP",
        "presence_resume" to "Resume",
        "presence_paused_title" to "Paused — you have the phone",
        "presence_paused_agent" to "%1\$s is paused",
        "consent_session_active" to "%1\$s is controlling your phone",
        "presence_driver_name_missing" to "Session defect — the driver has no name",
        "presence_driver_name_missing_hint" to "Presence must name the specific driver. End this session and pair again so the agent has a name.",
        "approval_title" to "Approval requested",
        "approval_wants_to" to "%1\$s wants to: %2\$s\n%3\$s",
        "approval_deny" to "Deny",
        "approval_approve" to "Approve",
        "tile_paused_label" to "Paused",
        "tile_paused_subtitle" to "You took over — tap to end",
        "tile_stop_label" to "STOP session",
        "tile_controlling_subtitle" to "%1\$s is controlling",
        "pairing_unnamed_label" to "Unnamed pairing",
        "gate_unnamed_caller" to "An unnamed caller",
        "mesh_unnamed_agent_driving" to "An unnamed agent is driving",
        "tile_channel_open_label" to "Channel open",
        "tile_channel_open_subtitle" to "Tap to stop the server",
        "tile_channel_stopped_label" to "Channel stopped",
        "tile_channel_stopped_subtitle" to "Tap to start the server",
        "session_none_title" to "No active session",
        "session_none_body" to "When your AI is working, this card shows it live — and the STOP here, on the banner, and in Quick Settings all end it at once.",
        "session_paused_chip" to "PAUSED",
        "session_active_chip" to "ACTIVE SESSION",
        "session_paused_body" to "%1\$s is paused — you have the phone",
        "session_resume" to "Resume the session",
        "session_stopped_toast" to "Session stopped.",
        "session_actions" to "%1\$d actions",
        // W6 design-of-record strings (hero surfaces, part 1).
        "home_no_one_in_phone" to "No one is in your phone right now.",
        "home_agent_in_phone" to "%1\$s is in your phone right now.",
        "home_connected_not_session" to "Connected — not in a session",
        "home_invisible_apps_not_built" to "Invisible apps — not in this build",
        "gate_deny_and_end" to "Deny and end session",
        "gate_draft_not_sent" to "DRAFT · NOT SENT",
        "gate_asked_from_chat" to "Asked from Agent chat",
        "gate_no_session_allow" to "There is no allow-for-this-session. Every gated action asks on its own.",
        "session_provider_line" to "What %1\$s's provider does with what it sees is outside this app.",
        "session_vendor_line" to "Nowhere else — DeskGuest sends nothing to anyone.",
        "session_replay_not_built" to "Replay isn't in this build",
        "session_not_seen" to "Not seen: %1\$s",
        "session_seen_so_far" to "%1\$d screens seen so far in this session",
        "session_presence_on_frames" to "The presence layer is part of the screens the agent receives — it is never hidden from the agent.",
        "presence_youre_driving" to "Paused — you're driving",
        "presence_watchdog_line" to "This app can't confirm whether anything is controlling this phone.",
        "presence_screen_not_shown" to "This screen can't be shown to %1\$s",
        "chat_sent_count" to "%1\$d messages sent from chat",
        // W7 design-of-record strings (part 2 surfaces).
        "wizard_waiting_for_ai" to "Waiting for your AI",
        "wizard_sas_check" to "Is this %1\$s? Check the words — they must match what your AI shows.",
        "wizard_sas_phrase" to "Safety words: %1\$s — they must match what your AI shows.",
        "wizard_step_of" to "Step %1\$d of %2\$d",
        "wizard_click_budget" to "Setup takes about 5–8 taps on your own phone. An Android endpoint takes about 10–14 taps, including the steps Android reserves for itself.",
        "chat_destination" to "Messages go to %1\$s on %2\$s",
        "chat_gate_note" to "Opens the approval gate. Chat cannot approve.",
        "chat_thread_ended" to "This pairing ended, so this thread is closed.",
        "chat_ask_to_act" to "Ask to act",
        "access_full_control_confirm" to "Give %1\$s full control of this phone? From then on it can act on everything you allow here, without asking each time.",
        "access_look_only_copy" to "Look only — it can see the screen and read phone info, but it cannot tap, type, or change anything.",
        "presence_selftest_pass" to "Presence check passed — the box, the ring, and the glow all drew.",
        "presence_selftest_fail" to "Presence check failed — a session can't start until presence can be shown.",
        "session_frames_sent" to "%1\$d screens sent to %2\$s",
        "session_frames_uncounted" to "Screens could not be counted where they were captured, so no screen count is shown for them.",
        "policy_consent_floor_title" to "Always on — no one can change this",
        "mdm_notice_title" to "Your organisation changed this phone",
        "backup_keysheet_title" to "Your backup key",
        "backup_keysheet_body" to "Write this key down and keep it somewhere safe. Without it, an encrypted backup cannot be opened — not by this app, and not by anyone else.",
        "home_readiness_title" to "This phone",
        "home_who_may_connect" to "Who may connect",
        "home_recent_title" to "Recent sessions",
        "home_standing_title" to "Standing",
    )

    /**
     * The fallback rule: a present, non-blank resource value wins;
     * a missing (null) or blank one falls back to the built-in
     * default for [key]. Unknown keys resolve to "" — every consent
     * key is in [DEFAULTS], so a consent surface never resolves blank.
     */
    fun resolve(key: String, resourceValue: String?): String =
        if (!resourceValue.isNullOrBlank()) resourceValue else DEFAULTS[key] ?: ""

    /**
     * FR-123: the plain unnamed-caller label for an approval-gate
     * prompt whose caller has no name. Pure (no Android Context) so
     * the JVM-compiled gate callers (ChatToolHost) read the same U8
     * wording the Android callers read through consentString —
     * never a fabricated generic name like "Your AI".
     */
    fun unnamedCallerLabel(): String = DEFAULTS.getValue("gate_unnamed_caller")

    /** FR-123: the truthful label for a pairing record with no name. */
    fun unnamedPairingLabel(): String = DEFAULTS.getValue("pairing_unnamed_label")
}

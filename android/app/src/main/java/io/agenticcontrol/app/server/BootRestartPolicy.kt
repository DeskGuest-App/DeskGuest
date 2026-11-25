package io.agenticcontrol.app.server

/**
 * C19 — Android channel self-healing: the DECISION logic for
 * restarting the control channel after a reboot, as a pure JVM
 * unit (no Android imports) so the whole decision table runs in
 * the JVM suite (tests/BootRestartTest.kt). The Android glue —
 * BootReceiver, BootRestartSettings — only gathers the facts,
 * calls [decide], and acts on the verdict; it contains no policy
 * of its own.
 *
 * Platform facts this logic is built on (Android Developers,
 * "Restrictions on starting a foreground service from the
 * background", verified 2026-11-22):
 * - Android 12 (API 31)+ forbids starting a foreground service
 *   from the background and throws
 *   ForegroundServiceStartNotAllowedException — EXCEPT, among
 *   others, when the app receives ACTION_BOOT_COMPLETED in a
 *   broadcast receiver, when the user has turned off battery
 *   optimizations for the app, or when the app holds
 *   SYSTEM_ALERT_WINDOW. A boot receiver is therefore a LAWFUL
 *   start path, not a workaround.
 * - An app in the stopped state (never launched, or force-stopped
 *   by the user) receives NO broadcasts at all until the user
 *   launches it again. No code in the app can detect or repair
 *   that state from inside — the receiver simply never runs.
 *   [Facts.hasOpenedAppBefore] mirrors that boundary for the
 *   (rare) paths where a broadcast does arrive first: a channel
 *   the owner never set up is never started silently.
 * - ACTION_BOOT_COMPLETED is delivered only after the device is
 *   first unlocked after reboot (credential-protected storage —
 *   this app's files and preferences — is unavailable before
 *   that). There is deliberately no LOCKED_BOOT_COMPLETED leg.
 * - OEM battery managers (several vendors) additionally suppress
 *   autostart on their own rules, which the app cannot query.
 *   That is why every outcome — started, skipped, refused — is
 *   written to the on-disk breadcrumb: the NEXT time the owner
 *   opens the app, the diagnostics line shows what the boot
 *   attempt actually did, instead of the app pretending the
 *   restart is guaranteed.
 *
 * Startup-path discipline (0.4.3 lesson, binding here): the boot
 * path reads plain SharedPreferences facts only. It performs NO
 * Keystore work, loads NO identity, and builds NO stores — it
 * hands off to the existing guarded [ControlService.start],
 * whose own startup path is already at least that conservative.
 */
object BootRestartPolicy {

    /** The setting's default: ON (spec C19). */
    const val DEFAULT_ENABLED = true

    /** The only broadcast action this policy acts on. The literal
     *  is pinned here so the JVM suite can assert the receiver and
     *  the manifest name exactly this action. */
    const val ACTION_BOOT_COMPLETED = "android.intent.action.BOOT_COMPLETED"

    /** Facts the Android glue gathers. Every field is a plain
     *  preference/system query — none touches the Keystore. */
    data class Facts(
        /** The owner's "Restart the control channel after reboot" setting. */
        val settingEnabled: Boolean,
        /** The broadcast action received (null when not a broadcast). */
        val action: String?,
        /** True once the owner has opened the app at least once —
         *  i.e. the app is not in the never-launched stopped state
         *  and a channel setup exists to restart. */
        val hasOpenedAppBefore: Boolean,
        /** Build.VERSION.SDK_INT of the device. */
        val sdkInt: Int,
        /** PowerManager.isIgnoringBatteryOptimizations for this app. */
        val batteryOptimizationExempt: Boolean,
        /** Settings.canDrawOverlays for this app. */
        val systemAlertWindowGranted: Boolean
    )

    enum class Decision {
        /** Call ControlService.start. */
        START_CHANNEL,

        /** The owner turned the setting off — the receiver no-ops. */
        SKIP_SETTING_OFF,

        /** Not a boot broadcast — nothing to do. */
        SKIP_WRONG_ACTION,

        /** The app has never been opened: no setup exists, and a
         *  stopped-state app would not have received the broadcast
         *  anyway. Never start a channel silently. */
        SKIP_NEVER_OPENED
    }

    /**
     * The decision table. Note what is NOT here: on API 31+ the
     * boot broadcast itself is a named exemption from the
     * background FGS-start ban, so [Facts.sdkInt],
     * [Facts.batteryOptimizationExempt] and
     * [Facts.systemAlertWindowGranted] never gate the attempt —
     * they are recorded in the breadcrumb (see [attemptNote]) so
     * a later refusal can be read in context. Gating the attempt
     * on them would break the lawful path on stock Android, where
     * neither extra exemption is normally held. A platform/OEM
     * refusal is handled where it can actually be known: at the
     * start call, as an [Outcome].
     */
    fun decide(facts: Facts): Decision = when {
        facts.action != ACTION_BOOT_COMPLETED -> Decision.SKIP_WRONG_ACTION
        !facts.settingEnabled -> Decision.SKIP_SETTING_OFF
        !facts.hasOpenedAppBefore -> Decision.SKIP_NEVER_OPENED
        else -> Decision.START_CHANNEL
    }

    /** The outcome of an attempted start, as reported by the
     *  guarded ControlService.start call. A returned start request
     *  is NOT proof the channel came up — the service's own
     *  breadcrumbs (svc_create_start …) are that proof — so the
     *  started outcome is named "requested", never "running". */
    enum class Outcome {
        START_REQUESTED,
        REFUSED_BY_PLATFORM,
        FAILED_OTHER
    }

    /** Classify a start failure by its exception type name: the
     *  API 31+ ForegroundServiceStartNotAllowedException (and its
     *  IllegalStateException base on some OEM builds) is a
     *  PLATFORM refusal — the honest state to record is "Android
     *  blocked the automatic restart; open the app to start the
     *  channel", not a crash. Matched by name so this pure unit
     *  needs no Android classes. */
    fun classifyFailure(exceptionClassName: String?): Outcome = when (exceptionClassName) {
        "android.app.ForegroundServiceStartNotAllowedException",
        "java.lang.IllegalStateException" -> Outcome.REFUSED_BY_PLATFORM
        else -> Outcome.FAILED_OTHER
    }

    /** Breadcrumb tag for a decision — written before any start
     *  is attempted, so a process killed mid-start still leaves
     *  the decision on disk. */
    fun breadcrumbFor(decision: Decision): String = when (decision) {
        Decision.START_CHANNEL -> "boot_restart_starting"
        Decision.SKIP_SETTING_OFF -> "boot_restart_skipped_setting_off"
        Decision.SKIP_WRONG_ACTION -> "boot_restart_skipped_wrong_action"
        Decision.SKIP_NEVER_OPENED -> "boot_restart_skipped_never_opened"
    }

    /** Breadcrumb tag for a start outcome. */
    fun breadcrumbFor(outcome: Outcome): String = when (outcome) {
        Outcome.START_REQUESTED -> "boot_restart_start_requested"
        Outcome.REFUSED_BY_PLATFORM -> "boot_restart_refused_by_platform"
        Outcome.FAILED_OTHER -> "boot_restart_start_failed"
    }

    /** Context recorded alongside a start attempt: which of the
     *  API 31+ exemption legs this device holds, so a refusal can
     *  be told apart from an OEM suppression after the fact.
     *  "boot" (the broadcast exemption) is always present on this
     *  path; the other two are the additional named exemptions. */
    fun attemptNote(facts: Facts): String {
        val legs = mutableListOf("boot")
        if (facts.batteryOptimizationExempt) legs.add("battery_exempt")
        if (facts.systemAlertWindowGranted) legs.add("overlay")
        return "boot_restart_exemptions_" + legs.joinToString("_")
    }
}

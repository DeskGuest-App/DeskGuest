package io.deskguest.app.server

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import io.deskguest.app.Breadcrumb
import io.deskguest.app.CrashTrap

/**
 * C19 — restarts the control channel after a reboot.
 *
 * Declared exported=false on ACTION_BOOT_COMPLETED in the
 * manifest (with RECEIVE_BOOT_COMPLETED). All policy lives in
 * the pure [BootRestartPolicy]; this receiver only gathers its
 * facts (plain preferences + two system queries — NO Keystore,
 * NO identity, NO stores), records the decision on the
 * breadcrumb BEFORE acting, and hands a START verdict to the
 * existing guarded [ControlService.start].
 *
 * Honest limits, by construction:
 * - A refusal by the platform/OEM at the start call is caught by
 *   ControlService.start (which records it via CrashTrap) and is
 *   ALSO written here as boot_restart_refused_by_platform /
 *   boot_restart_start_failed, so the next app open shows the
 *   automatic restart was blocked — the app never claims the
 *   channel is back until the service's own breadcrumbs say so.
 * - A force-stopped or never-opened app receives no broadcast at
 *   all; nothing in the app can observe that state, and this
 *   receiver does not pretend otherwise.
 * - Nothing in this receiver can throw out of onReceive: every
 *   step is guarded, because a crashing receiver helps no one.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        try {
            val facts = gatherFacts(context, intent?.action)
            val decision = BootRestartPolicy.decide(facts)
            Breadcrumb.mark(context, BootRestartPolicy.breadcrumbFor(decision))
            if (decision != BootRestartPolicy.Decision.START_CHANNEL) return
            Breadcrumb.mark(context, BootRestartPolicy.attemptNote(facts))
            val started = ControlService.start(context)
            Breadcrumb.mark(
                context,
                BootRestartPolicy.breadcrumbFor(
                    if (started) {
                        BootRestartPolicy.Outcome.START_REQUESTED
                    } else {
                        // ControlService.start already recorded the
                        // failure in CrashTrap; classify from its
                        // recorded report is not readable back as a
                        // type, so a refused start is recorded with
                        // the platform-refusal tag only when the
                        // recorded report names that exception —
                        // otherwise the generic failure tag.
                        classifyRecordedRefusal(context)
                    }
                )
            )
        } catch (t: Throwable) {
            CrashTrap.record(context, "BootReceiver.onReceive", t)
            Breadcrumb.mark(context, BootRestartPolicy.breadcrumbFor(BootRestartPolicy.Outcome.FAILED_OTHER))
        }
    }

    private fun gatherFacts(context: Context, action: String?): BootRestartPolicy.Facts {
        val batteryExempt = try {
            val pm = context.getSystemService(PowerManager::class.java)
            pm?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        } catch (_: Throwable) {
            false
        }
        val overlayGranted = try {
            Settings.canDrawOverlays(context)
        } catch (_: Throwable) {
            false
        }
        return BootRestartPolicy.Facts(
            settingEnabled = BootRestartSettings.isEnabled(context),
            action = action,
            hasOpenedAppBefore = BootRestartSettings.hasOpenedAppBefore(context),
            sdkInt = Build.VERSION.SDK_INT,
            batteryOptimizationExempt = batteryExempt,
            systemAlertWindowGranted = overlayGranted
        )
    }

    /** The CrashTrap report ControlService.start just wrote names
     *  the exception class in its stack trace; the platform's
     *  background-start refusal is the expected failure on this
     *  path, everything else stays a generic failure. */
    private fun classifyRecordedRefusal(context: Context): BootRestartPolicy.Outcome {
        val report = CrashTrap.read(context) ?: return BootRestartPolicy.Outcome.FAILED_OTHER
        return when {
            report.contains("ForegroundServiceStartNotAllowedException") ->
                BootRestartPolicy.Outcome.REFUSED_BY_PLATFORM
            report.contains("IllegalStateException") ->
                BootRestartPolicy.Outcome.REFUSED_BY_PLATFORM
            else -> BootRestartPolicy.Outcome.FAILED_OTHER
        }
    }
}

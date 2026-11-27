package io.deskguest.app.safety

/**
 * Driving lockout (SPEC §7.7, FEATURES §6) — BD-XCHECK owed item,
 * built 2026-11-22. When the device is in a vehicle, screen DRIVING
 * is refused; voice-grade interactions (notify_user, read-aloud via
 * the agent's own channel) remain available — they are not drive
 * tools and never pass through SessionManager.driveRefusal.
 *
 * Detection scope, honestly stated: this product detects driving
 * only from signals Android exposes to a normal app without a
 * vehicle integration —
 *   - the system car mode (UiModeManager car mode / Android Auto
 *     projection state as the OS reports it), or
 *   - a car Bluetooth profile (A2DP / headset) currently connected.
 * There is NO motion/activity-recognition claim: without Google
 * Play services' Activity Recognition (not a dependency of this
 * local-first product) the app cannot prove the user is driving
 * from movement, and it does not pretend to. When neither signal is
 * present the state is NOT_DRIVING *as far as these signals can
 * tell* — the lockout is a guard for the detectable case, not a
 * promise that every drive is detected. The state and its basis are
 * surfaced verbatim by the detector adapter.
 *
 * Pure JVM core: signal evaluation + the refusal text. The Android
 * adapter (DrivingDetector) queries the OS signals on demand at
 * each drive check — there is no background monitoring.
 */
object DrivingLockout {

    enum class State { NOT_DRIVING, DRIVING }

    data class Signals(
        val carMode: Boolean = false,
        val carBluetoothConnected: Boolean = false
    ) {
        /** Which signal fired, for honest reporting; null when none. */
        fun basis(): String? = when {
            carMode && carBluetoothConnected -> "car mode and car Bluetooth are both active"
            carMode -> "the system is in car mode"
            carBluetoothConnected -> "a car Bluetooth profile is connected"
            else -> null
        }
    }

    fun evaluate(signals: Signals): State =
        if (signals.carMode || signals.carBluetoothConnected) State.DRIVING else State.NOT_DRIVING

    /** Why a drive tool must refuse in this state, or null. */
    fun driveRefusal(state: State, signals: Signals): String? {
        if (state != State.DRIVING) return null
        val basis = signals.basis() ?: "a driving signal is active"
        return "DRIVING LOCKOUT: $basis, so screen driving is refused while the " +
            "device appears to be in a vehicle. Voice-grade interactions " +
            "(notify_user) remain available. Do not retry drive tools until " +
            "the driving state clears."
    }
}

/**
 * The live driving-state provider, installed by the Android layer
 * (ControlService installs DrivingDetector). SessionManager consults
 * it inside driveRefusal; with no provider installed (JVM suite,
 * detector failure) the lockout reports NOT_DRIVING — the detector
 * is an on-demand query, and a failed query must not wedge every
 * drive tool behind an error it cannot explain. The detector's own
 * honesty about its limits lives in DrivingLockout's header.
 */
object DrivingStateHolder {

    @Volatile
    var provider: (() -> Pair<DrivingLockout.State, DrivingLockout.Signals>)? = null

    fun currentRefusal(): String? {
        val p = provider ?: return null
        val (state, signals) = try {
            p()
        } catch (_: Exception) {
            return null
        }
        return DrivingLockout.driveRefusal(state, signals)
    }
}

package io.deskguest.app.safety

import android.app.UiModeManager
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.content.res.Configuration

/**
 * Android adapter for the driving lockout (SPEC §7.7): queries the
 * two OS signals the pure core (DrivingLockout) evaluates, ON
 * DEMAND at each drive check. No listeners, no background sampling,
 * no location, no motion sensing — see DrivingLockout's header for
 * the honest detection limits. A signal the OS refuses (e.g.
 * BLUETOOTH_CONNECT not granted) reads as absent, never as driving:
 * the lockout guards the detectable case and says so.
 */
object DrivingDetector {

    fun signals(context: Context): DrivingLockout.Signals {
        val carMode = try {
            val uiMode = context.getSystemService(Context.UI_MODE_SERVICE) as? UiModeManager
            uiMode?.currentModeType == Configuration.UI_MODE_TYPE_CAR
        } catch (_: Exception) {
            false
        }
        val carBluetooth = try {
            val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            val adapter = manager?.adapter
            adapter != null && (
                adapter.getProfileConnectionState(BluetoothProfile.A2DP) == BluetoothProfile.STATE_CONNECTED ||
                    adapter.getProfileConnectionState(BluetoothProfile.HEADSET) == BluetoothProfile.STATE_CONNECTED
                )
        } catch (_: SecurityException) {
            false
        } catch (_: Exception) {
            false
        }
        return DrivingLockout.Signals(carMode = carMode, carBluetoothConnected = carBluetooth)
    }

    fun state(context: Context): Pair<DrivingLockout.State, DrivingLockout.Signals> {
        val signals = signals(context)
        return DrivingLockout.evaluate(signals) to signals
    }
}

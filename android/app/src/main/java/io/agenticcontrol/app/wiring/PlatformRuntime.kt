package io.agenticcontrol.app.wiring

import android.content.Context
import io.agenticcontrol.app.crypto.AtRestCipher
import io.agenticcontrol.app.crypto.IdentityLineCipher
import io.agenticcontrol.app.crypto.LineCipher
import java.io.File

/**
 * The Android-side singleton for the Slice 1–3 wiring layer.
 *
 * Created LAZILY, on first actual use — a platform screen opening,
 * or the first platform MCP tool call (an HTTP-handler thread).
 * It is never created from ControlService.onCreate / the channel
 * startup path, and creating it does not touch the device identity
 * (PlatformStores loads that lazily itself): the 0.4.3 lesson —
 * nothing identity- or Keystore-shaped on the startup path — holds
 * for this layer by construction.
 *
 * The identity cipher (bd-and-core F6, 2026-11-22): the
 * Keystore-backed wrap returns here on a recorded probe_ok verdict
 * — but ONLY when the stored identity seed is already wrapped or
 * does not exist yet. A plaintext seed written by the plain era is
 * NEVER silently re-read under a wrapping cipher: DeviceIdentity
 * refuses plaintext under a wrapping cipher by design, and
 * switching would mint a fresh device identity behind the owner's
 * back. Such a device keeps the plain cipher until the owner
 * re-enrolls — named here, not hidden.
 */
object PlatformRuntime {

    @Volatile
    private var instance: PlatformStores? = null

    /** The cipher a fresh PlatformStores should open with, given
     *  the recorded probe verdict and the seed already on disk.
     *  Pure logic, unit-testable (the JVM suite pins it). */
    fun selectCipher(filesDir: File, platformDir: File, keystoreCipher: () -> LineCipher): LineCipher =
        // The guard itself lives in AtRestCipher.selectGuarded so
        // the JVM suites exercise the exact production logic (this
        // file is Android-side and cannot load on the JVM).
        AtRestCipher.selectGuarded(filesDir, platformDir, PlatformStores.IDENTITY_FILE, keystoreCipher)

    fun get(context: Context): PlatformStores {
        instance?.let { return it }
        return synchronized(this) {
            instance ?: PlatformStores(
                File(context.applicationContext.filesDir, "platform"),
                selectCipher(context.applicationContext.filesDir,
                    File(context.applicationContext.filesDir, "platform")) {
                    io.agenticcontrol.app.crypto.AesGcmLineCipher(
                        io.agenticcontrol.app.server.KeystoreKeys.getOrCreate("platform-identity-key")
                    )
                }
            ).also { instance = it }
        }
    }

    /** The open stores, or null when no surface has opened them yet.
     *  Never creates them — status readers must not force the open. */
    fun peek(): PlatformStores? = instance
}

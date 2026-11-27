package io.deskguest.app.crypto

import java.io.File

/**
 * bd-and-core F6 fix (2026-11-22): the at-rest wrap decision, in
 * one place, honestly. The Android Keystore probe (ControlService)
 * records its verdict to [VERDICT_FILE_NAME] in the app-private
 * files dir — "ok" only after a full encrypt/decrypt round-trip
 * through a Keystore-held key succeeded on this device. Store
 * construction then selects the AES-GCM cipher ONLY on a recorded
 * ok verdict; anything else (no verdict yet, a failed verdict, a
 * cipher that throws at construction) selects the plain
 * IdentityLineCipher and the surfaces say so. The probe never sits
 * on the startup path (the 0.4.3 lesson): the verdict is read from
 * the file the previous run's background probe left behind, and a
 * first-ever run starts plain and earns the wrap for the next run.
 */
object AtRestCipher {
    const val VERDICT_FILE_NAME = "keystore-verdict.txt"

    fun verdictOk(dir: File): Boolean = try {
        File(dir, VERDICT_FILE_NAME).readText(Charsets.UTF_8).trim() == "ok"
    } catch (_: Exception) {
        false
    }

    /** Record a probe verdict (temp + rename; never throws). */
    fun recordVerdict(dir: File, ok: Boolean) {
        try {
            val tmp = File(dir, VERDICT_FILE_NAME + ".tmp")
            tmp.writeText(if (ok) "ok" else "failed")
            if (!tmp.renameTo(File(dir, VERDICT_FILE_NAME))) tmp.delete()
        } catch (_: Exception) {
        }
    }

    /**
     * The cipher for a store in [dir]: the Keystore-backed cipher
     * from [keystoreCipher] when the recorded verdict is ok and
     * construction succeeds; IdentityLineCipher otherwise.
     */
    fun select(dir: File, keystoreCipher: () -> LineCipher): LineCipher {
        if (!verdictOk(dir)) return IdentityLineCipher
        return try {
            keystoreCipher()
        } catch (_: Exception) {
            IdentityLineCipher
        }
    }

    /** True when [cipher] actually wraps (for honest state text). */
    fun wraps(cipher: LineCipher): Boolean = cipher !is IdentityLineCipher

    /**
     * The platform-identity selection (extracted from
     * PlatformRuntime.selectCipher so the guard is JVM-provable —
     * BdAndFixTest exercises THIS function): verdict first, then
     * the seed guard — a device-identity seed file that exists and
     * does not already carry the wrapped prefix stays under the
     * identity cipher, because DeviceIdentity.load refuses a
     * plaintext seed under a wrapping cipher and selecting the
     * wrapper would silently mint a fresh device identity.
     */
    fun selectGuarded(
        filesDir: File, platformDir: File, identityFileName: String,
        keystoreCipher: () -> LineCipher
    ): LineCipher {
        if (!verdictOk(filesDir)) return IdentityLineCipher
        val seed = File(platformDir, identityFileName)
        if (seed.exists()) {
            val first = try {
                seed.readText(Charsets.UTF_8).trim().lineSequence().firstOrNull() ?: ""
            } catch (_: Exception) {
                ""
            }
            if (!first.startsWith(LineCipher.WRAP_PREFIX)) return IdentityLineCipher
        }
        return select(filesDir, keystoreCipher)
    }
}

package io.agenticcontrol.app.update

import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * Pure input-handling guards for the update download step
 * (bd-and-ui F8 fix, 2026-11-22). Everything here is free of
 * Android types so the JVM suite pins the shapes; UpdateChecker
 * routes its manifest-supplied values through these before any
 * of them touches the filesystem or the network.
 */
object UpdateGuards {

    /** The APK always lands under ONE fixed name. The old code
     *  used the manifest's fileName as a path — a "../" in a
     *  (signed but hostile or corrupted) manifest escaped the
     *  updates directory. A manifest name is now accepted only
     *  when it is a bare file name ending in .apk; anything else
     *  falls back to the fixed name. */
    const val FIXED_APK_NAME = "update.apk"

    fun safeApkFileName(manifestName: String?): String {
        val name = manifestName?.trim().orEmpty()
        if (name.isEmpty()) return FIXED_APK_NAME
        if (name != File(name).name) return FIXED_APK_NAME // any path separator / traversal
        if (name.contains('/') || name.contains('\\') || name.contains('\u0000')) return FIXED_APK_NAME
        if (!name.lowercase().endsWith(".apk")) return FIXED_APK_NAME
        // W12-DS P8-F16: the KDoc guarantee is ONE fixed name —
        // now the code keeps it (a manifest-supplied bare name no
        // longer chooses the staged path).
        return FIXED_APK_NAME
    }

    /** Downloads happen over HTTPS only (F8: URL(info.apkUrl)
     *  accepted http, so the "signed manifest" could point the
     *  APK fetch at a cleartext host). */
    fun isHttpsUrl(url: String?): Boolean = url?.trim()?.startsWith("https://", ignoreCase = true) == true

    /** Copy with a hard byte cap (F8: downloads had no size
     *  limit). Returns the bytes written, or -1 when the cap was
     *  exceeded (the caller deletes the partial). */
    fun copyCapped(input: InputStream, output: OutputStream, capBytes: Long): Long {
        val buffer = ByteArray(64 * 1024)
        var written = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            written += n
            if (written > capBytes) return -1
            output.write(buffer, 0, n)
        }
        return written
    }

    /** The download cap for an update: the manifest's declared
     *  size plus a small margin. An undeclared size (<= 0) earns
     *  NO download — the manifest must commit to a size. */
    fun downloadCapBytes(declaredSizeBytes: Long): Long =
        if (declaredSizeBytes <= 0) -1 else declaredSizeBytes + 64 * 1024

    /** Signer comparison (F8): the archive's signer SET must
     *  EQUAL this app's signer set. The old `.any {}` passed when
     *  a single archive signer matched, so an APK co-signed by a
     *  stranger's key alongside ours was accepted. Certificate
     *  comparison is by encoded bytes, supplied by the caller. */
    fun signerSetsEqual(ownCerts: List<ByteArray>, archiveCerts: List<ByteArray>): Boolean {
        if (ownCerts.isEmpty() || archiveCerts.isEmpty()) return false
        if (ownCerts.size != archiveCerts.size) return false
        val own = ownCerts.map { it.toList() }.toSet()
        val archive = archiveCerts.map { it.toList() }.toSet()
        return own == archive
    }
}

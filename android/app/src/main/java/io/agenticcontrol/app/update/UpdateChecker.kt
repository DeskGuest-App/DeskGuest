package io.agenticcontrol.app.update

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The in-app updater (platform/update-channel-plan.md): fetch the
 * signed manifest, verify it against this app's own signing
 * certificate, compare versions, download the APK, check its hash and
 * its signer, and hand it to the system installer. Every step fails
 * closed and reports its reason — an update that cannot be verified
 * is an update that does not happen.
 */
class UpdateChecker(private val context: Context) {

    data class UpdateInfo(
        val versionName: String,
        val versionCode: Long,
        val notes: String,
        val sizeBytes: Long,
        val apkUrl: String,
        val apkFileName: String,
        val apkSha256: String
    )

    sealed class CheckResult {
        data class Available(val info: UpdateInfo) : CheckResult()
        object UpToDate : CheckResult()
        data class Failed(val reason: String) : CheckResult()
    }

    fun check(): CheckResult {
        val manifest = try {
            JSONObject(fetchText(MANIFEST_URL))
        } catch (e: Exception) {
            return CheckResult.Failed("Could not read the update list (${e.message}).")
        }
        val keys = ownSignerPublicKeys()
        if (keys.isEmpty()) {
            return CheckResult.Failed("This app cannot read its own signing key, so no update can be trusted.")
        }
        val key = keys.first()
        // bd-and-ui F10 fix: ONE gate decides — signature, Long
        // version monotonicity, package binding and expiry. (The
        // old code verified the signature twice and compared the
        // version three times, twice Int-narrowed.) A failed
        // signature and a not-newer manifest both land on
        // UpToDate's refusal path here EXCEPT the signature case,
        // which keeps its own plainly-worded failure:
        if (!ManifestVerifier.verify(manifest, keys)) {
            return CheckResult.Failed("The update list failed its signature check. Nothing was downloaded.")
        }
        val remoteCode = manifest.optLong("versionCode", -1L)
        val localCode = localVersionCode()
        if (remoteCode < 0) return CheckResult.Failed("The update list is missing its version.")
        if (!ManifestVerifier.verifyNewer(manifest, keys, localCode, expectedPackage = context.packageName)) {
            // W13 P8-F10 remainder closed: verifyNewer=false is no
            // longer flattened to UpToDate — only a genuinely
            // not-newer manifest is "up to date"; a package
            // mismatch or an expired manifest is a FAILURE with
            // its reason named.
            return when {
                remoteCode <= localCode -> CheckResult.UpToDate
                manifest.has("packageName") && manifest.optString("packageName") != context.packageName ->
                    CheckResult.Failed("The update list names a different app package. Nothing was downloaded.")
                manifest.has("expiresAt") && manifest.optLong("expiresAt", 0L) <= System.currentTimeMillis() ->
                    CheckResult.Failed("The update list has expired. Nothing was downloaded.")
                else -> CheckResult.UpToDate
            }
        }
        val apk = manifest.optJSONObject("apk")
            ?: return CheckResult.Failed("The update list names no file to install.")
        val apkUrl = apk.optString("url", "")
        if (!UpdateGuards.isHttpsUrl(apkUrl)) {
            return CheckResult.Failed("The update list's download address is not https. Nothing was downloaded.")
        }
        val issued = UpdateInfo(
                versionName = manifest.optString("versionName", ""),
                versionCode = remoteCode,
                notes = manifest.optString("notes", ""),
                sizeBytes = apk.optLong("sizeBytes", 0),
                apkUrl = apk.optString("url", ""),
                apkFileName = apk.optString("fileName", "update.apk"),
                apkSha256 = apk.optString("sha256", "")
            )
        issuedInfos.add(issued)
        return CheckResult.Available(issued)
    }

    /** Download the APK and verify hash + signer. Returns the file, or null with [error] set. */
    fun download(info: UpdateInfo, error: (String) -> Unit): File? {
        // W13 P8-F13: provenance — download() only serves an
        // UpdateInfo that check() issued from a VERIFIED manifest
        // in this process. A hand-built info (even with plausible
        // fields) is refused before any network or file work; the
        // hash/signer/package/version checks below still run on
        // whatever is actually fetched.
        if (!issuedInfos.contains(info)) {
            error("That update was not produced by a verified update check in this session. Run the update check again.")
            return null
        }
        // Staged in the app's private cache (0700 by the sandbox);
        // the installer receives it through the FileProvider's
        // read-only grant, never a world-readable path (0.4.0).
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        // bd-and-ui F8 fixes: the manifest's file name is never a
        // path (UpdateGuards.safeApkFileName), the transfer is
        // https-only and byte-capped at the manifest's declared
        // size, and failures include Errors, not only Exceptions.
        if (!UpdateGuards.isHttpsUrl(info.apkUrl)) {
            error("The download address is not https. Nothing was downloaded.")
            return null
        }
        val cap = UpdateGuards.downloadCapBytes(info.sizeBytes)
        if (cap < 0) {
            error("The update list does not declare the file's size. Nothing was downloaded.")
            return null
        }
        val out = File(dir, UpdateGuards.safeApkFileName(info.apkFileName))
        try {
            // W13 P8-F15: the connection comes from openHttps —
            // status checked, redirects revalidated, always
            // disconnected (see below).
            val conn = openHttps(info.apkUrl)
            val written = conn.inputStream.use { input ->
                out.outputStream().use { output -> UpdateGuards.copyCapped(input, output, cap) }
            }
            conn.disconnect()
            if (written < 0) {
                out.delete()
                error("The download grew past the size the update list declared. It was deleted.")
                return null
            }
        } catch (e: Throwable) {
            out.delete()
            error("The download failed (${e.message}).")
            return null
        }
        if (sha256(out) != info.apkSha256.lowercase()) {
            out.delete()
            error("The downloaded file does not match the update list's hash. It was deleted.")
            return null
        }
        val signerOk = apkSignerMatchesOwn(out)
        if (!signerOk) {
            out.delete()
            error("The downloaded file is signed by a different key. It was deleted.")
            return null
        }
        // W12-DS P8-F8: bind the ARTIFACT to the verified manifest —
        // the downloaded APK's own package name and versionCode
        // must equal the manifest's, or an older same-key release
        // could be substituted under a newer manifest.
        val archiveInfo = try {
            context.packageManager.getPackageArchiveInfo(out.absolutePath, 0)
        } catch (_: Throwable) { null }
        val archiveCode = archiveInfo?.let {
            if (android.os.Build.VERSION.SDK_INT >= 28) it.longVersionCode
            else @Suppress("DEPRECATION") it.versionCode.toLong()
        }
        if (archiveInfo == null || archiveInfo.packageName != context.packageName || archiveCode != info.versionCode) {
            out.delete()
            error("The downloaded file is not the package/version the update list named. It was deleted.")
            return null
        }
        return out
    }

    // ---------- internals ----------

    private fun fetchText(url: String): String {
        val conn = openHttps(url)
        return conn.inputStream.bufferedReader().readText()
    }

    /** W13 P8-F15: HTTP hygiene for every update-channel fetch —
     *  automatic redirects are OFF; each redirect hop is followed
     *  manually (max 3) and its Location must stay https (a signed
     *  manifest must not be able to bounce the fetch — or the APK
     *  download — onto plain http or an unbounded chain); the
     *  response status must be 200 before any byte is read; the
     *  caller owns the returned connection and disconnects it. */
    private fun openHttps(url: String): HttpURLConnection {
        var current = url
        var hops = 0
        while (true) {
            if (!UpdateGuards.isHttpsUrl(current)) {
                throw java.io.IOException("update channel left https (refused)")
            }
            val conn = URL(current).openConnection() as HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 60_000
            conn.instanceFollowRedirects = false
            val code = conn.responseCode
            if (code in 300..399) {
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                if (location.isNullOrBlank() || ++hops > 3) {
                    throw java.io.IOException("update channel redirect chain refused")
                }
                current = URL(URL(current), location).toString()
                continue
            }
            if (code != 200) {
                conn.disconnect()
                throw java.io.IOException("update channel answered HTTP $code")
            }
            return conn
        }
    }

    private fun localVersionCode(): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        // F10: Long end to end — the old toInt() truncated codes
        // above 2^31-1.
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode
        else @Suppress("DEPRECATION") info.versionCode.toLong()
    }

    private fun ownSignerPublicKey(): java.security.PublicKey? = try {
        ownSignerCertificate()?.publicKey
    } catch (e: Exception) {
        null
    }

    /** W13 P8-F3: ALL own signer public keys — the manifest side
     *  now verifies against the set, matching the APK side's
     *  set-equality rule. */
    private fun ownSignerPublicKeys(): Set<java.security.PublicKey> {
        val cf = CertificateFactory.getInstance("X.509")
        return ownSignerCertBytes().mapNotNull { bytes ->
            try {
                (cf.generateCertificate(bytes.inputStream()) as X509Certificate).publicKey
            } catch (e: Exception) { null }
        }.toSet()
    }

    /** All of this app's signer certificates (encoded bytes).
     *  F8 fix: SigningInfo needs API 28 — below that the
     *  deprecated GET_SIGNATURES path is used instead of
     *  throwing NoSuchMethodError past the guards. */
    private fun ownSignerCertBytes(): List<ByteArray> {
        val pm = context.packageManager
        return try {
            if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                info.signingInfo?.apkContentsSigners?.map { sig ->
                    val cf = CertificateFactory.getInstance("X.509")
                    (cf.generateCertificate(sig.toByteArray().inputStream()) as X509Certificate).encoded
                } ?: emptyList()
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures?.map { sig ->
                    val cf = CertificateFactory.getInstance("X.509")
                    (cf.generateCertificate(sig.toByteArray().inputStream()) as X509Certificate).encoded
                } ?: emptyList()
            }
        } catch (e: Throwable) {
            emptyList()
        }
    }

    private fun ownSignerCertificate(): X509Certificate? {
        val bytes = ownSignerCertBytes().firstOrNull() ?: return null
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(bytes.inputStream()) as X509Certificate
    }

    private fun apkSignerMatchesOwn(file: File): Boolean {
        return try {
            val pm = context.packageManager
            // W12-DS P8-F9: API < 28 has no signingInfo — mirror
            // ownSignerCertBytes()' deprecated GET_SIGNATURES path
            // or every update is refused on Android 8.x.
            val archiveCerts: List<ByteArray> = if (android.os.Build.VERSION.SDK_INT >= 28) {
                val archive = pm.getPackageArchiveInfo(
                    file.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES
                ) ?: return false
                val archiveSigners = archive.signingInfo?.apkContentsSigners ?: return false
                archiveSigners.map { sig ->
                    val cf = CertificateFactory.getInstance("X.509")
                    (cf.generateCertificate(sig.toByteArray().inputStream()) as X509Certificate).encoded
                }
            } else {
                @Suppress("DEPRECATION")
                val archive = pm.getPackageArchiveInfo(
                    file.absolutePath, PackageManager.GET_SIGNATURES
                ) ?: return false
                @Suppress("DEPRECATION")
                val sigs = archive.signatures ?: return false
                sigs.map { sig ->
                    val cf = CertificateFactory.getInstance("X.509")
                    (cf.generateCertificate(sig.toByteArray().inputStream()) as X509Certificate).encoded
                }
            }
            // F8 fix: signer SET equality — the old .any {} let an
            // APK co-signed by a stranger's key pass.
            UpdateGuards.signerSetsEqual(ownSignerCertBytes(), archiveCerts)
        } catch (e: Throwable) {
            false
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        /** W13 P8-F13: infos issued by check() in this process. */
        private val issuedInfos: MutableSet<UpdateInfo> =
            java.util.Collections.synchronizedSet(mutableSetOf())
        const val MANIFEST_URL =
            "https://github.com/DeskGuest-App/DeskGuest/releases/latest/download/update-manifest.json"
    }
}

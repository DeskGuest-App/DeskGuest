package io.deskguest.app.update

import org.json.JSONArray
import org.json.JSONObject
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/**
 * Verifies update manifests (platform/update-channel-plan.md). The
 * signed content is the manifest without its `signature` field,
 * serialized with sorted keys and compact separators — byte for byte
 * the rule the publish script signs with. The two implementations are
 * pinned to each other by a cross-test in the JVM suite.
 */
object ManifestVerifier {

    fun canonicalBytes(manifest: JSONObject): ByteArray {
        val sb = StringBuilder()
        writeObject(sb, manifest, excludeTopSignature = true)
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /** W13 P8-F3: SET-based verification — the manifest verifies
     *  when ANY of the app's own signer keys verifies it. The APK
     *  side already compared signer SETS; the manifest side pinned
     *  only the FIRST own certificate, so a legitimately rotated /
     *  multi-signer build refused its own update channel. */
    fun verify(manifest: JSONObject, keys: Set<PublicKey>): Boolean =
        keys.any { verify(manifest, it) }

    fun verify(manifest: JSONObject, key: PublicKey): Boolean {
        val signatureB64 = manifest.optString("signature", "")
        if (signatureB64.isBlank()) return false
        return try {
            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(key)
            sig.update(canonicalBytes(manifest))
            sig.verify(Base64.getDecoder().decode(signatureB64))
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Signature AND monotonicity (0.4.0): a manifest is acceptable
     * only when it verifies AND its versionCode is strictly greater
     * than the running app's. Enforced here, inside the verifier, so
     * no caller can forget the downgrade check — a signed-but-older
     * manifest (a replayed release) is refused like a forged one.
     */
    /** W13 P8-F3: set-based [verifyNewer] (see [verify] set form). */
    fun verifyNewer(
        manifest: JSONObject, keys: Set<PublicKey>, currentVersionCode: Long,
        expectedPackage: String? = null, nowMs: Long = System.currentTimeMillis()
    ): Boolean {
        if (!verify(manifest, keys)) return false
        val remoteCode = manifest.optLong("versionCode", -1L)
        if (remoteCode <= currentVersionCode) return false
        if (expectedPackage != null &&
            (!manifest.has("packageName") || manifest.optString("packageName") != expectedPackage)) return false
        if (manifest.has("expiresAt") && manifest.optLong("expiresAt", 0L) <= nowMs) return false
        return true
    }

    fun verifyNewer(
        manifest: JSONObject, key: PublicKey, currentVersionCode: Long,
        expectedPackage: String? = null, nowMs: Long = System.currentTimeMillis()
    ): Boolean {
        if (!verify(manifest, key)) return false
        // bd-and-ui F10: Long-wide comparison (the Int optInt
        // truncated versionCodes above 2^31-1); a carried
        // packageName must be THIS app's package, and a carried
        // expiresAt (epoch ms) must still be in the future — a
        // signed manifest was previously replayable forever.
        val remoteCode = manifest.optLong("versionCode", -1L)
        if (remoteCode <= currentVersionCode) return false
        // W12-DS P8-F10: when a package is expected, the field
        // must be PRESENT and equal — an omitted field no longer
        // passes silently.
        if (expectedPackage != null &&
            (!manifest.has("packageName") || manifest.optString("packageName") != expectedPackage)) return false
        if (manifest.has("expiresAt") && manifest.optLong("expiresAt", 0L) <= nowMs) return false
        return true
    }

    private fun writeObject(sb: StringBuilder, obj: JSONObject, excludeTopSignature: Boolean = false) {
        sb.append('{')
        val keys = mutableListOf<String>()
        val it = obj.keys()
        while (it.hasNext()) {
            val k = it.next()
            if (excludeTopSignature && k == "signature") continue
            keys.add(k)
        }
        keys.sort()
        keys.forEachIndexed { i, k ->
            if (i > 0) sb.append(',')
            writeString(sb, k)
            sb.append(':')
            writeValue(sb, obj.get(k))
        }
        sb.append('}')
    }

    private fun writeValue(sb: StringBuilder, value: Any?) {
        when (value) {
            null, JSONObject.NULL -> sb.append("null")
            is JSONObject -> writeObject(sb, value)
            is JSONArray -> {
                sb.append('[')
                for (i in 0 until value.length()) {
                    if (i > 0) sb.append(',')
                    writeValue(sb, value.get(i))
                }
                sb.append(']')
            }
            is String -> writeString(sb, value)
            is Boolean -> sb.append(if (value) "true" else "false")
            is Int, is Long -> sb.append(value.toString())
            is Double -> {
                // Match the publisher: integral doubles print without a fraction.
                if (value == value.toLong().toDouble()) sb.append(value.toLong().toString())
                else sb.append(value.toString())
            }
            else -> writeString(sb, value.toString())
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        // Matches the publisher's serializer exactly (Python json with
        // ensure_ascii): short escapes for the usual control chars,
        // \uXXXX for everything outside printable ASCII — including
        // non-ASCII, which arrives as UTF-16 units, so astral chars
        // come out as surrogate pairs on both sides.
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '' -> sb.append("\\f")
                else -> {
                    if (c.code < 0x20 || c.code >= 0x7F) {
                        sb.append(String.format("\\u%04x", c.code))
                    } else {
                        sb.append(c)
                    }
                }
            }
        }
        sb.append('"')
    }
}

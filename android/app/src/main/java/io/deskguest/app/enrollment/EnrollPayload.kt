package io.deskguest.app.enrollment

import java.net.URLDecoder
import java.net.URLEncoder

/**
 * QR enrollment payload (Slice 1):
 *   deskguest://enroll/1?c=<CODE>&s=<scope>&g=<groupId>
 *
 * Carries the same enrollment code as the manual flow and nothing
 * else secret — scope and group id are the mint's binding, shown so
 * the enrolling side can display what it is joining. The parser
 * never throws on hostile input: wrong scheme, wrong version,
 * missing/blank code, missing scope/group, or garbage all parse to
 * null.
 */
object EnrollPayload {

    data class Parsed(
        val code: String,
        val scope: String,
        val groupId: String,
        /** bd-and-rest F11 fix: the MINTER's identity, carried in
         *  the payload (params m/k) when the minting side supplies
         *  it — the enrollee verifies the key fingerprints to the
         *  device id (DeviceIdentity.deviceIdFor) before trusting
         *  either, and derives the receipt + SAS from them instead
         *  of free-text fields typed at redeem time. Null on legacy
         *  payloads, which keep the honest no-SAS receipt state. */
        val minterDeviceId: String? = null,
        val minterPublicKeyBase64: String? = null
    ) {
        /** Display form XXXXX-XXXXX of the carried code. */
        val displayCode: String get() = EnrollmentStore.formatCode(code)

        /** True when the carried minter key actually fingerprints
         *  to the carried minter device id — the only shape an
         *  enrollee may derive an operator record from. */
        val minterVerified: Boolean
            get() {
                val id = minterDeviceId ?: return false
                val key = try {
                    java.util.Base64.getDecoder().decode(minterPublicKeyBase64 ?: return false)
                } catch (_: Exception) { return false }
                return key.size == DeviceIdentity.PUBLIC_KEY_SIZE &&
                    DeviceIdentity.deviceIdFor(key).equals(id, ignoreCase = true)
            }
    }

    const val SCHEME_PREFIX = "deskguest://enroll/1"

    fun build(
        code: String, scope: String, groupId: String,
        minterDeviceId: String? = null, minterPublicKeyBase64: String? = null
    ): String {
        val rawCode = EnrollmentStore.normalizeCode(code)
            ?: throw IllegalArgumentException("not a valid enrollment code")
        val normalizedScope = scope.trim().lowercase()
        require(normalizedScope in EnrollmentStore.SCOPES) { "unknown enrollment scope: $scope" }
        require(groupId.isNotBlank()) { "groupId must not be blank" }
        var out = SCHEME_PREFIX +
            "?c=" + encode(rawCode) +
            "&s=" + encode(normalizedScope) +
            "&g=" + encode(groupId)
        // F11: bind the minter when supplied — and only as a
        // consistent pair (an id without its key, or a key that
        // does not fingerprint to the id, is a programmer error).
        if (minterDeviceId != null || minterPublicKeyBase64 != null) {
            val key = try {
                java.util.Base64.getDecoder().decode(minterPublicKeyBase64 ?: "")
            } catch (_: Exception) { ByteArray(0) }
            require(minterDeviceId != null && key.size == DeviceIdentity.PUBLIC_KEY_SIZE &&
                DeviceIdentity.deviceIdFor(key).equals(minterDeviceId, ignoreCase = true)) {
                "minter id/key pair is inconsistent — the key must fingerprint to the device id"
            }
            out += "&m=" + encode(minterDeviceId!!) + "&k=" + encode(minterPublicKeyBase64!!)
        }
        return out
    }

    fun parse(payload: String?): Parsed? {
        return try {
            if (payload == null) return null
            val text = payload.trim()
            if (!text.startsWith("$SCHEME_PREFIX?")) return null
            val query = text.substring(SCHEME_PREFIX.length + 1)
            if (query.isEmpty()) return null
            val params = mutableMapOf<String, String>()
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                if (eq < 0) continue
                val key = decode(pair.substring(0, eq)) ?: return null
                val value = decode(pair.substring(eq + 1)) ?: return null
                params[key] = value
            }
            val code = EnrollmentStore.normalizeCode(params["c"]) ?: return null
            val scope = params["s"]?.trim()?.lowercase() ?: return null
            if (scope !in EnrollmentStore.SCOPES) return null
            val groupId = params["g"]?.takeIf { it.isNotBlank() } ?: return null
            // F11: a payload carrying a minter id WITHOUT its key
            // (or with a key that does not fingerprint to it) is
            // malformed — refuse rather than half-trust it. A
            // payload with neither is the legacy shape and parses.
            val minterId = params["m"]?.takeIf { it.isNotBlank() }
            val minterKey = params["k"]?.takeIf { it.isNotBlank() }
            if ((minterId == null) != (minterKey == null)) return null
            val parsed = Parsed(code, scope, groupId, minterId, minterKey)
            if (minterId != null && !parsed.minterVerified) return null
            parsed
        } catch (_: Exception) {
            null
        }
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8.name())

    private fun decode(value: String): String? = try {
        URLDecoder.decode(value, Charsets.UTF_8.name())
    } catch (_: Exception) {
        null
    }
}

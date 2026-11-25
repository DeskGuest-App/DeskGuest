package io.agenticcontrol.app.crypto

import io.agenticcontrol.app.enterprise.PolicyFeatures
import io.agenticcontrol.app.roster.RosterStore
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

/**
 * G-06 — Local second factor, Android mirror of the Windows
 * Acp.Shared SecondFactorService. Same rules, same RFC vectors:
 * TOTP (RFC 6238 / HOTP RFC 4226, HMAC-SHA1) fully built; passkeys
 * by ASSERTION VERIFICATION (challenge, rpId hash, UP flag,
 * counter monotonicity) — the capture legs (Credential Manager /
 * Windows Hello) are platform surfaces for the device gates.
 * Replay discipline is identical: an accepted TOTP step can never
 * be accepted again; acceptance is monotonic in the step counter.
 */

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(ALPHABET[(buffer shr bits) and 0x1F])
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }

    /** Tolerant decode: case-insensitive, spaces/padding ignored.
     * Null on any foreign character — never a partial secret. */
    fun decode(text: String?): ByteArray? {
        if (text == null) return null
        val clean = text.filter { !it.isWhitespace() && it != '=' }.uppercase()
        if (clean.isEmpty()) return null
        val out = ArrayList<Byte>()
        var buffer = 0
        var bits = 0
        for (c in clean) {
            val v = ALPHABET.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.add(((buffer shr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}

object Totp {
    const val STEP_SECONDS = 30L
    const val DIGITS = 6

    fun counterFor(atMillis: Long, stepSeconds: Long = STEP_SECONDS): Long =
        (atMillis / 1000) / stepSeconds

    fun hotp(secret: ByteArray, counter: Long, digits: Int = DIGITS): String {
        val counterBytes = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) { counterBytes[i] = (c and 0xFF).toByte(); c = c shr 8 }
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(secret, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        var mod = 1
        repeat(digits) { mod *= 10 }
        return (binary % mod).toString().padStart(digits, '0')
    }

    fun at(secret: ByteArray, atMillis: Long, digits: Int = DIGITS): String =
        hotp(secret, counterFor(atMillis), digits)

    /** The matched step within ±windowSteps, or null. Constant-time
     * comparison over the code bytes (MessageDigest.isEqual). */
    fun matchStep(secret: ByteArray, code: String?, atMillis: Long, windowSteps: Long = 1): Long? {
        if (code.isNullOrBlank()) return null
        val presented = code.trim().toByteArray(Charsets.US_ASCII)
        val center = counterFor(atMillis)
        for (step in center - windowSteps..center + windowSteps) {
            val candidate = hotp(secret, step).toByteArray(Charsets.US_ASCII)
            if (MessageDigest.isEqual(candidate, presented)) return step
        }
        return null
    }
}

/** Seals factor secrets at rest. Production wiring seals with the
 * app key (AesGcm); the model never stores a plaintext secret. */
interface SecretSealer {
    fun seal(plain: String): String
    fun unseal(sealed: String): String
}

data class TotpEnrollment(
    val scopeId: String, val userId: String, val sealedSecretBase64: String,
    val state: String, // "pending" | "active"
    val createdMillis: Long, val lastAcceptedStep: Long
)

data class PasskeyCredential(
    val scopeId: String, val userId: String, val credentialIdBase64: String,
    val publicKeyXBase64: String, val publicKeyYBase64: String,
    val signCount: Long, val createdMillis: Long
)

data class SecondFactorEvent(
    val atMillis: Long, val kind: String, val scopeId: String, val userId: String, val detail: String
)

class SecondFactorStore(
    private val roster: RosterStore,
    private val sealer: SecretSealer,
    private val featureGate: ((String, String) -> Boolean)? = null,
    /** Change hook for wiring write-through persistence (AF10).
     *  The persisted form carries sealed secrets only. NOT the
     *  last parameter: the clock stays last so every existing
     *  trailing-lambda call site keeps binding to it. */
    private val onChanged: (() -> Unit)? = null,
    private val nowMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val totp = LinkedHashMap<String, TotpEnrollment>()
    private val pending = LinkedHashMap<String, TotpEnrollment>()
    private val passkeys = LinkedHashMap<String, PasskeyCredential>()
    private val _events = ArrayList<SecondFactorEvent>()
    val events: List<SecondFactorEvent> get() = _events.toList()

    // ---- Block H (design 1): attempt throttling ----
    // ONE throttle per (scopeId, userId) shared by EVERY verify
    // path (TOTP verify, TOTP confirm, the re-enrollment
    // current-code check, passkey verify): an attacker spraying
    // one path cannot launder attempts through another.
    // THROTTLE_MAX_FAILURES consecutive material failures engage
    // a THROTTLE_LOCKOUT_MS lockout; during lockout every verify
    // path refuses WITHOUT checking material. A success on any
    // path resets the consecutive-failure counter. The state
    // persists (export/import below) and an import can only ever
    // RAISE it (max-merge): a rolled-back file never unlocks a
    // live lockout.
    private data class ThrottleState(var failures: Int = 0, var lockoutUntilMillis: Long = 0L)
    private val throttle = LinkedHashMap<String, ThrottleState>()

    /** D38 Block H review F1: the lockout is judged against the
     *  STORE's own clock, never a caller-supplied timestamp — a
     *  caller passing a future time must not walk past a live
     *  lockout (the passkey path already did this; the TOTP paths
     *  now match it). The `atMillis` parameters on the public
     *  verify calls remain only as the TOTP code's time window. */
    private fun throttled(scopeId: String, userId: String): Boolean {
        val st = throttle[key(scopeId, userId)] ?: return false
        return nowMillis() < st.lockoutUntilMillis
    }

    /** One material failure on a verify path. Engaging the
     *  lockout is recorded (the engagement is an auditable act);
     *  the counter resets as the lockout engages, so after the
     *  lockout expires a fresh run of failures is needed to
     *  re-engage it. Callers hold the monitor. */
    private fun noteVerifyFailure(scopeId: String, userId: String) {
        val st = throttle.getOrPut(key(scopeId, userId)) { ThrottleState() }
        st.failures += 1
        if (st.failures >= THROTTLE_MAX_FAILURES) {
            st.failures = 0
            // F1: the lockout is measured from the store clock too.
            st.lockoutUntilMillis = nowMillis() + THROTTLE_LOCKOUT_MS
            record("factor_throttled", scopeId, userId,
                "Five consecutive failed factor attempts — verification locked for 300 seconds.")
        } else {
            onChanged?.invoke() // the raised counter is persisted state too
        }
    }

    /** A success on any verify path resets the failure counter.
     *  Callers hold the monitor. */
    private fun noteVerifySuccess(scopeId: String, userId: String) {
        val st = throttle[key(scopeId, userId)] ?: return
        if (st.failures != 0) {
            st.failures = 0
            onChanged?.invoke()
        }
    }

    // ---- Block H (design 2): passkey challenge issuance ----
    // Challenges are EPHEMERAL by design: export/import does NOT
    // carry them, so a restart invalidates every outstanding
    // ceremony (mirrors the C# side's choice). ONE outstanding
    // challenge per (scope, user); issuing replaces.
    private data class IssuedChallenge(val challenge: String, val expiresMillis: Long)
    private val passkeyChallenges = LinkedHashMap<String, IssuedChallenge>()

    /** Issue the challenge a passkey ceremony must answer:
     *  base64url (unpadded) 32 random bytes, 300 s to live. */
    @Synchronized
    fun issuePasskeyChallenge(scopeId: String, userId: String): String? {
        if (!featureAllowed(scopeId)) return null
        if (!liveHuman(scopeId, userId)) return null
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        passkeyChallenges[key(scopeId, userId)] =
            IssuedChallenge(challenge, nowMillis() + PASSKEY_CHALLENGE_TTL_MS)
        return challenge
    }

    private fun key(scopeId: String, userId: String) = "$scopeId\n$userId"
    private fun key(scopeId: String, userId: String, credentialId: String) = "$scopeId\n$userId\n$credentialId"

    private fun liveHuman(scopeId: String, userId: String?): Boolean {
        if (userId.isNullOrBlank()) return false
        val user = roster.user(userId) ?: return false
        return user.scopeId == scopeId && user.kind == RosterStore.USER_HUMAN && !user.suspended
    }

    /** SCOPE-AWARE gate (scopeId, featureKey) — D38-G review F2. */
    private fun featureAllowed(scopeId: String): Boolean =
        featureGate?.invoke(scopeId, PolicyFeatures.LOCAL_SECOND_FACTOR) ?: true

    private fun record(kind: String, scopeId: String, userId: String, detail: String) {
        _events.add(SecondFactorEvent(nowMillis(), kind, scopeId, userId, detail))
        onChanged?.invoke()
    }

    private fun secretOf(e: TotpEnrollment): ByteArray? =
        try { Base32.decode(sealer.unseal(e.sealedSecretBase64)) } catch (ex: Exception) { null }

    // ---- TOTP ----

    /** Begin enrollment: fresh 160-bit secret, stored sealed +
     * PENDING (in the pending store, apart from any active
     * factor); the base32 secret + otpauth URI are returned for
     * the user's authenticator app — the only moment the secret
     * shows.
     *
     * Re-enrollment over an ACTIVE factor (D38-G review F4 /
     * Android packet F1 — the packet's blocker) is a
     * possession-gated act: the caller must present a currently
     * valid code for the EXISTING factor (verified, its step
     * consumed). Without it, begin refuses — no caller can
     * replace a victim's factor with an attacker-known secret,
     * and registerPasskey is bound to the roster's live-human
     * check for the same reason. The old factor stays ACTIVE
     * until the new one confirms (no factor-less window). The
     * code-free recovery path is the admin's (removeTotpByAdmin,
     * then begin). */
    @Synchronized
    fun beginTotpEnrollment(scopeId: String, userId: String,
                            currentCode: String? = null, atMillis: Long = nowMillis()): Pair<String, String>? {
        if (!featureAllowed(scopeId)) return null
        if (!liveHuman(scopeId, userId)) return null
        val k = key(scopeId, userId)
        val active = totp[k]
        if (active != null) {
            // Design 1: the re-enrollment current-code check is a
            // verify path — during lockout it refuses WITHOUT
            // checking the presented code.
            if (throttled(scopeId, userId)) {
                record("totp_reenrollment_refused", scopeId, userId,
                    "Re-enrollment refused: factor verification is throttled (lockout).")
                return null
            }
            val activeSecret = secretOf(active)
            val step = if (activeSecret == null || currentCode == null) null
                else Totp.matchStep(activeSecret, currentCode, atMillis)
            if (step == null || step <= active.lastAcceptedStep) {
                // A PRESENTED code that fails counts toward the
                // throttle; presenting no code checks no material
                // and counts nothing.
                if (currentCode != null && activeSecret != null)
                    noteVerifyFailure(scopeId, userId)
                record("totp_reenrollment_refused", scopeId, userId,
                    "Re-enrollment over an active factor refused: no valid current code presented.")
                return null
            }
            noteVerifySuccess(scopeId, userId)
            totp[k] = active.copy(lastAcceptedStep = step)
            record("totp_reenrollment_authorized", scopeId, userId,
                "Re-enrollment authorized by a current code from the existing factor (step consumed).")
        }
        val secret = ByteArray(20).also { SecureRandom().nextBytes(it) }
        val base32 = Base32.encode(secret)
        pending[k] = TotpEnrollment(
            scopeId, userId, sealer.seal(base32), "pending", nowMillis(), -1)
        record("totp_enrollment_begun", scopeId, userId, "TOTP enrollment begun (pending possession proof).")
        val uri = "otpauth://totp/ACP%3A$userId?secret=$base32&issuer=ACP&digits=${Totp.DIGITS}&period=${Totp.STEP_SECONDS}"
        return base32 to uri
    }

    @Synchronized
    fun confirmTotpEnrollment(scopeId: String, userId: String, code: String, atMillis: Long): Boolean {
        if (!featureAllowed(scopeId)) return false
        if (!liveHuman(scopeId, userId)) return false
        if (throttled(scopeId, userId)) return false // design 1: no material checked
        val e = pending[key(scopeId, userId)] ?: return false
        val secret = secretOf(e) ?: return false
        val step = Totp.matchStep(secret, code, atMillis)
        if (step == null) {
            noteVerifyFailure(scopeId, userId)
            return false
        }
        pending.remove(key(scopeId, userId))
        totp[key(scopeId, userId)] = e.copy(state = "active", lastAcceptedStep = step)
        noteVerifySuccess(scopeId, userId)
        record("totp_enrollment_confirmed", scopeId, userId, "TOTP enrollment confirmed and active.")
        return true
    }

    /** Verify a step-up code: active enrollments only; the matched
     * step must be NEWER than every previously accepted step
     * (replay + out-of-order refusal) and is consumed on success. */
    @Synchronized
    fun verifyTotp(scopeId: String, userId: String, code: String, atMillis: Long): Boolean {
        if (!featureAllowed(scopeId)) return false
        if (!liveHuman(scopeId, userId)) return false
        if (throttled(scopeId, userId)) return false // design 1: no material checked
        val e = totp[key(scopeId, userId)] ?: return false
        if (e.state != "active") return false
        val secret = secretOf(e) ?: return false
        val step = Totp.matchStep(secret, code, atMillis)
        if (step == null || step <= e.lastAcceptedStep) {
            // A wrong code AND a replayed/out-of-order step both
            // count: both are presented material that failed.
            noteVerifyFailure(scopeId, userId)
            return false
        }
        totp[key(scopeId, userId)] = e.copy(lastAcceptedStep = step)
        noteVerifySuccess(scopeId, userId)
        record("totp_verified", scopeId, userId, "TOTP step-up verified.")
        return true
    }

    @Synchronized
    fun removeTotp(scopeId: String, userId: String, code: String, atMillis: Long): Boolean {
        if (!totp.containsKey(key(scopeId, userId))) return false
        if (!verifyTotp(scopeId, userId, code, atMillis)) return false
        totp.remove(key(scopeId, userId))
        record("totp_removed", scopeId, userId, "TOTP factor removed by its owner (code-verified).")
        return true
    }

    /** Admin removal (lost-device recovery): a live company admin
     * may remove another user's factor without a code; the act is
     * recorded with the admin named — possible, never silent. */
    @Synchronized
    fun removeTotpByAdmin(scopeId: String, targetUserId: String, adminUserId: String): Boolean {
        if (!roster.isCompanyAdmin(scopeId, adminUserId) || !liveHuman(scopeId, adminUserId)) return false
        val k = key(scopeId, targetUserId)
        val hadFactor = totp.remove(k) != null
        // D38 Block H review F3: admin recovery also CLEARS the
        // target's throttle state — recovery that leaves a lockout
        // standing is no recovery (re-enrollment's confirm step
        // would still refuse). The clear is part of this recorded
        // act, never a silent side path.
        val hadThrottle = throttle.remove(k) != null
        if (!hadFactor && !hadThrottle) return false
        record("totp_removed_by_admin", scopeId, targetUserId,
            "TOTP factor removed by company admin $adminUserId (recovery path); throttle state cleared.")
        return true
    }

    @Synchronized
    fun hasActiveTotp(scopeId: String, userId: String): Boolean =
        totp[key(scopeId, userId)]?.state == "active"

    /** Active factor counts (a snapshot fact; counts only,
     *  mirrors the Windows SecondFactorService.Counts). */
    @Synchronized
    fun counts(): Pair<Int, Int> =
        Pair(totp.values.count { it.state == "active" }, passkeys.size)

    // ---- Passkeys (assertion verification) ----

    @Synchronized
    fun registerPasskey(scopeId: String, userId: String, credentialIdBase64: String,
                        publicKeyXBase64: String, publicKeyYBase64: String): Boolean {
        if (!featureAllowed(scopeId)) return false
        if (!liveHuman(scopeId, userId)) return false
        val x: ByteArray
        val y: ByteArray
        try {
            if (credentialIdBase64.isBlank()) return false
            Base64.getDecoder().decode(credentialIdBase64)
            x = Base64.getDecoder().decode(publicKeyXBase64)
            y = Base64.getDecoder().decode(publicKeyYBase64)
        } catch (ex: Exception) { return false }
        if (x.size != 32 || y.size != 32) return false
        if (!isOnCurve(x, y)) return false
        passkeys[key(scopeId, userId, credentialIdBase64)] = PasskeyCredential(
            scopeId, userId, credentialIdBase64, publicKeyXBase64, publicKeyYBase64, 0, nowMillis())
        record("passkey_registered", scopeId, userId, "Passkey credential registered (platform attestation leg).")
        return true
    }

    /** Verify a passkey assertion. Design 1: this is a verify
     *  path — during lockout it refuses WITHOUT checking material
     *  (the challenge is not even burned: the challenge check is
     *  never reached), and its outcome feeds the shared throttle
     *  (a failure against a REGISTERED credential counts; an
     *  unknown credential checks nothing and counts nothing). */
    @Synchronized
    fun verifyPasskeyAssertion(scopeId: String, userId: String, credentialIdBase64: String,
                               authenticatorData: ByteArray, clientDataJson: String, signature: ByteArray,
                               expectedChallengeBase64Url: String, rpId: String): Boolean {
        if (!featureAllowed(scopeId)) return false
        if (!liveHuman(scopeId, userId)) return false
        val now = nowMillis()
        if (throttled(scopeId, userId)) return false
        val credExists = passkeys.containsKey(key(scopeId, userId, credentialIdBase64))
        val ok = verifyPasskeyAssertionChecked(scopeId, userId, credentialIdBase64,
            authenticatorData, clientDataJson, signature, expectedChallengeBase64Url, rpId)
        if (ok) noteVerifySuccess(scopeId, userId)
        else if (credExists) noteVerifyFailure(scopeId, userId)
        return ok
    }

    private fun verifyPasskeyAssertionChecked(scopeId: String, userId: String, credentialIdBase64: String,
                               authenticatorData: ByteArray, clientDataJson: String, signature: ByteArray,
                               expectedChallengeBase64Url: String, rpId: String): Boolean {
        val cred = passkeys[key(scopeId, userId, credentialIdBase64)] ?: return false
        if (authenticatorData.size < 37) return false
        try {
            val root = JSONObject(clientDataJson)
            if (root.getString("type") != "webauthn.get") return false
            // Design 2 — challenge binding: the presented challenge
            // must equal an outstanding UNEXPIRED challenge this
            // store issued for (scope, user). Reaching this check
            // CONSUMES the issued challenge (burn-on-attempt):
            // success or failure from here on, it cannot be
            // presented again — a captured ceremony is not
            // replayable, and a failed attempt cannot be retried
            // against the same challenge.
            val presented = root.getString("challenge")
            val issued = passkeyChallenges.remove(key(scopeId, userId))
            if (issued == null || nowMillis() > issued.expiresMillis) return false
            if (!MessageDigest.isEqual(
                    issued.challenge.toByteArray(Charsets.US_ASCII),
                    presented.toByteArray(Charsets.US_ASCII))) return false
            if (presented != expectedChallengeBase64Url) return false
            val origin = root.getString("origin")
            val host = try { java.net.URI(origin).host } catch (ex: Exception) { null } ?: return false
            if (!host.equals(rpId, ignoreCase = true)) return false
        } catch (ex: Exception) { return false }

        val expectedRpHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
        if (!MessageDigest.isEqual(expectedRpHash, authenticatorData.copyOfRange(0, 32))) return false
        val flags = authenticatorData[32].toInt()
        if (flags and 0x01 == 0) return false // user-presence bit required
        val signCount = ((authenticatorData[33].toLong() and 0xFF) shl 24) or
            ((authenticatorData[34].toLong() and 0xFF) shl 16) or
            ((authenticatorData[35].toLong() and 0xFF) shl 8) or
            (authenticatorData[36].toLong() and 0xFF)
        if ((cred.signCount > 0 || signCount > 0) && signCount <= cred.signCount) {
            record("passkey_counter_refused", scopeId, userId,
                "Passkey signature counter did not advance — possible cloned authenticator; refused.")
            return false
        }
        val clientHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson.toByteArray(Charsets.UTF_8))
        val signed = authenticatorData + clientHash
        val ok = try {
            val pub = ecPublicKey(
                Base64.getDecoder().decode(cred.publicKeyXBase64),
                Base64.getDecoder().decode(cred.publicKeyYBase64))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(pub)
            verifier.update(signed)
            verifier.verify(signature)
        } catch (ex: Exception) { return false }
        if (!ok) return false
        passkeys[key(scopeId, userId, credentialIdBase64)] = cred.copy(signCount = signCount)
        record("passkey_verified", scopeId, userId, "Passkey assertion verified.")
        return true
    }

    @Synchronized
    fun removePasskey(scopeId: String, userId: String, credentialIdBase64: String, actorUserId: String): Boolean {
        val self = actorUserId == userId && liveHuman(scopeId, actorUserId)
        val admin = roster.isCompanyAdmin(scopeId, actorUserId) && liveHuman(scopeId, actorUserId)
        if (!self && !admin) return false
        if (passkeys.remove(key(scopeId, userId, credentialIdBase64)) == null) return false
        record("passkey_removed", scopeId, userId, "Passkey removed by $actorUserId.")
        return true
    }

    companion object {
        /** Design 1: consecutive material failures that engage
         *  the lockout, and the lockout's length. */
        const val THROTTLE_MAX_FAILURES = 5
        const val THROTTLE_LOCKOUT_MS = 300_000L
        /** Design 2: an issued passkey challenge's lifetime. */
        const val PASSKEY_CHALLENGE_TTL_MS = 300_000L
    }

    private fun ecParameterSpec(): ECParameterSpec {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        return params.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun ecPublicKey(x: ByteArray, y: ByteArray): ECPublicKey {
        val spec = ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), ecParameterSpec())
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    private fun isOnCurve(x: ByteArray, y: ByteArray): Boolean =
        try { ecPublicKey(x, y); true } catch (ex: Exception) { false }

    // ---- persistence ----

    /** Serialize the factor store. TOTP secrets travel ONLY sealed. */
    @Synchronized
    fun exportJson(): String {
        val root = JSONObject()
        val totpArr = JSONArray()
        for (e in totp.values + pending.values) totpArr.put(JSONObject()
            .put("scopeId", e.scopeId).put("userId", e.userId)
            .put("sealedSecretBase64", e.sealedSecretBase64).put("state", e.state)
            .put("createdMillis", e.createdMillis).put("lastAcceptedStep", e.lastAcceptedStep))
        val passArr = JSONArray()
        for (c in passkeys.values) passArr.put(JSONObject()
            .put("scopeId", c.scopeId).put("userId", c.userId)
            .put("credentialIdBase64", c.credentialIdBase64)
            .put("publicKeyXBase64", c.publicKeyXBase64).put("publicKeyYBase64", c.publicKeyYBase64)
            .put("signCount", c.signCount).put("createdMillis", c.createdMillis))
        root.put("totp", totpArr)
        root.put("passkeys", passArr)
        // Design 1: throttle state persists with the factors.
        // Passkey CHALLENGES deliberately do NOT (design 2: they
        // are ephemeral; a restart invalidates ceremonies).
        val thArr = JSONArray()
        for ((k, st) in throttle) {
            val parts = k.split("\n", limit = 2)
            if (parts.size != 2) continue
            thArr.put(JSONObject()
                .put("scopeId", parts[0]).put("userId", parts[1])
                .put("failures", st.failures).put("lockoutUntilMillis", st.lockoutUntilMillis))
        }
        root.put("throttle", thArr)
        // The event history travels too (D38-G review F1).
        val evArr = JSONArray()
        for (e in _events) evArr.put(JSONObject()
            .put("atMillis", e.atMillis).put("kind", e.kind).put("scopeId", e.scopeId)
            .put("userId", e.userId).put("detail", e.detail))
        root.put("events", evArr)
        return root.toString()
    }

    /** Restore, re-validated like the Windows store: dead users,
     * unknown states, unsealable secrets, and malformed key
     * material are all dropped, never fatal. */
    @Synchronized
    fun importJson(json: String): Int {
        val root = try { JSONObject(json) } catch (ex: Exception) { return 0 }
        var restored = 0
        // Design 1: throttle state merges by MAX — an import must
        // never clear (or lower) an existing in-memory lockout or
        // failure count, so a rolled-back factors file cannot
        // unlock a live throttle. Malformed rows drop.
        val thArr = root.optJSONArray("throttle")
        if (thArr != null) {
            for (i in 0 until thArr.length()) {
                val dto = thArr.optJSONObject(i) ?: continue
                val scopeId = dto.optString("scopeId")
                val userId = dto.optString("userId")
                if (scopeId.isBlank() || userId.isBlank()) continue
                // F3: imported throttle state is BOUNDED — the
                // failure count clamps to the engagement threshold
                // and a lockout may extend at most one lockout
                // period past the importing store's clock, so a
                // hand-edited factors file cannot lock a user out
                // for years (the max-merge rule below still applies
                // within those bounds).
                val failures = dto.optInt("failures", 0).coerceIn(0, THROTTLE_MAX_FAILURES)
                val lockoutUntil = dto.optLong("lockoutUntilMillis", 0)
                    .coerceIn(0, nowMillis() + THROTTLE_LOCKOUT_MS)
                val k = key(scopeId, userId)
                val existing = throttle[k]
                if (existing == null) {
                    throttle[k] = ThrottleState(failures, lockoutUntil)
                } else {
                    existing.failures = maxOf(existing.failures, failures)
                    existing.lockoutUntilMillis = maxOf(existing.lockoutUntilMillis, lockoutUntil)
                }
            }
        }
        val evArr = root.optJSONArray("events")
        if (evArr != null) {
            for (i in 0 until evArr.length()) {
                val dto = evArr.optJSONObject(i) ?: continue
                val kind = dto.optString("kind")
                if (kind.isBlank()) continue
                _events.add(SecondFactorEvent(dto.optLong("atMillis"), kind,
                    dto.optString("scopeId"), dto.optString("userId"), dto.optString("detail")))
            }
        }
        val totpArr = root.optJSONArray("totp") ?: JSONArray()
        for (i in 0 until totpArr.length()) {
            val dto = totpArr.optJSONObject(i) ?: continue
            val scopeId = dto.optString("scopeId")
            val userId = dto.optString("userId")
            val state = dto.optString("state")
            if (!liveHuman(scopeId, userId)) continue
            if (state !in setOf("pending", "active")) continue
            val target = if (state == "active") totp else pending
            if (target.containsKey(key(scopeId, userId))) continue
            // D38-G review F10: the stored replay counter is
            // UNTRUSTED — an imported ACTIVE enrollment's floor is
            // the CURRENT step, so a rolled-back counter cannot
            // resurrect used codes; only future codes verify.
            val lastStep = if (state == "active")
                maxOf(dto.optLong("lastAcceptedStep", -1), Totp.counterFor(nowMillis()))
            else dto.optLong("lastAcceptedStep", -1)
            val e = TotpEnrollment(scopeId, userId, dto.optString("sealedSecretBase64"),
                state, dto.optLong("createdMillis"), lastStep)
            if (secretOf(e) == null) continue
            target[key(scopeId, userId)] = e
            restored++
        }
        val passArr = root.optJSONArray("passkeys") ?: JSONArray()
        for (i in 0 until passArr.length()) {
            val dto = passArr.optJSONObject(i) ?: continue
            val scopeId = dto.optString("scopeId")
            val userId = dto.optString("userId")
            val credId = dto.optString("credentialIdBase64")
            if (!liveHuman(scopeId, userId)) continue
            if (passkeys.containsKey(key(scopeId, userId, credId))) continue
            val x: ByteArray
            val y: ByteArray
            try {
                Base64.getDecoder().decode(credId)
                x = Base64.getDecoder().decode(dto.optString("publicKeyXBase64"))
                y = Base64.getDecoder().decode(dto.optString("publicKeyYBase64"))
            } catch (ex: Exception) { continue }
            if (x.size != 32 || y.size != 32) continue
            if (!isOnCurve(x, y)) continue // F10: import runs registerPasskey's probe too
            passkeys[key(scopeId, userId, credId)] = PasskeyCredential(
                scopeId, userId, credId, dto.optString("publicKeyXBase64"),
                dto.optString("publicKeyYBase64"), dto.optLong("signCount"), dto.optLong("createdMillis"))
            restored++
        }
        return restored
    }
}

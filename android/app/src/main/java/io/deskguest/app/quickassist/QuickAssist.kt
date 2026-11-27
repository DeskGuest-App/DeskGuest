package io.deskguest.app.quickassist

import io.deskguest.app.transport.sha256Hex
import java.security.SecureRandom

/**
 * Quick-assist session codes (Block F, D24 — Android mirror of the
 * Windows QuickAssistService): a one-time, view-only rendezvous.
 * Only the SHA-256 of a code is ever stored; failed redeems count
 * toward an attempt burn that locks the whole mint; a grant answers
 * only to the client binding that redeemed it (helper-impersonation
 * defense); closing kills code + grant together.
 */
data class QuickAssistGrant(
    val grantId: String,
    val codeId: String,
    val scopeId: String,
    val hostDeviceId: String,
    val viewOnly: Boolean,
    val expiresUtcMs: Long
)

class QuickAssistService {
    companion object {
        const val ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        const val DEFAULT_TTL_MS = 10 * 60 * 1000L
        const val MAX_FAILED_ATTEMPTS = 5
        const val LOCKOUT_MS = 10 * 60 * 1000L
        const val GRANT_VIEW_ONLY = true
        /** bd-and-remote F11(b): a grant's own session TTL, counted
         *  from REDEEM — never inherited from the code's remaining
         *  life (a code redeemed at 9:59 used to yield a ~1-second
         *  session). */
        const val GRANT_TTL_MS = 10 * 60 * 1000L
        /** F11(a): failures tolerated per (code-hash) before that
         *  CODE locks; the global lockout survives only as a last
         *  resort at a much higher threshold, so one guesser can
         *  no longer lock out every legitimate helper. */
        const val MAX_FAILED_ATTEMPTS_PER_CODE = 5
        // Unknown-code guessing keeps the ORIGINAL global brake
        // (5, pinned by BlockHTest DG-H-A13): blind brute force is
        // exactly what the global lock exists for. The F11(a) fix
        // is narrower — failures against a KNOWN code burn only
        // that code (MAX_FAILED_ATTEMPTS_PER_CODE) and no longer
        // feed this counter.
        const val GLOBAL_FAILED_ATTEMPTS = MAX_FAILED_ATTEMPTS

        fun normalize(code: String?): String =
            (code ?: "").uppercase().filter { it in ALPHABET }

        fun isWellFormed(code: String?): Boolean = normalize(code).length == 8
    }

    private class CodeState(
        val id: String,
        val codeHash: String,
        val scopeId: String,
        val hostDeviceId: String,
        val initiatorUserId: String,
        val expiresUtcMs: Long,
        var used: Boolean = false,
        var closed: Boolean = false,
        var grantId: String? = null,
        var failedAttempts: Int = 0,
        var lockedUntilMs: Long = 0L
    )

    private class GrantState(
        val grant: QuickAssistGrant,
        val tokenHash: String,
        val clientBindingHash: String,
        var closed: Boolean = false
    )

    private val codes = LinkedHashMap<String, CodeState>()
    private val grants = LinkedHashMap<String, GrantState>()
    private var failedAttempts = 0
    private var lockedUntilMs = 0L
    private var counter = 0

    /** F11(d): evict expired-and-closed / expired-and-used entries
     *  so the maps cannot grow without limit. Callers hold the
     *  monitor. Live (unexpired, unclosed) entries are never
     *  evicted. */
    fun prune(nowMs: Long) {
        // Terminal entries only: a code that is closed or past its
        // expiry can never redeem again; a grant that is closed or
        // past its expiry can never validate again. Live entries
        // (unused unexpired code, open unexpired grant) stay.
        val deadCodes = codes.values.filter { it.closed || nowMs > it.expiresUtcMs }.map { it.codeHash }
        deadCodes.forEach { codes.remove(it) }
        val deadGrants = grants.values.filter { it.closed || nowMs > it.grant.expiresUtcMs }.map { it.grant.grantId }
        deadGrants.forEach { grants.remove(it) }
    }

    /** Test/diagnostic visibility into the retained entry counts. */
    @Synchronized fun retainedCounts(): Pair<Int, Int> = codes.size to grants.size

    private fun hash(text: String): String = sha256Hex(text.toByteArray(Charsets.UTF_8))

    @Synchronized
    fun mint(scopeId: String, hostDeviceId: String, initiatorUserId: String, nowMs: Long, ttlMs: Long = DEFAULT_TTL_MS): String {
        prune(nowMs)
        val random = SecureRandom()
        val chars = CharArray(8) { ALPHABET[random.nextInt(ALPHABET.length)] }
        val code = String(chars)
        val state = CodeState("qa-${++counter}", hash(code), scopeId, hostDeviceId, initiatorUserId, nowMs + ttlMs)
        codes[state.codeHash] = state
        return code.substring(0, 4) + "-" + code.substring(4)
    }

    @Synchronized
    fun redeem(code: String?, clientBinding: String, nowMs: Long): Triple<Boolean, String, Pair<QuickAssistGrant, String>?> {
        prune(nowMs)
        if (nowMs < lockedUntilMs)
            return Triple(false, "quick assist is locked after too many failed attempts — try again later", null)
        val normalized = normalize(code)
        val state = if (normalized.length == 8) codes[hash(normalized)] else null
        // F11(a): a guess against a KNOWN code counts against that
        // code only; unknown-code guesses count toward the global
        // last-resort lockout at the higher threshold.
        if (state != null && nowMs < state.lockedUntilMs)
            return Triple(false, "this code is locked after too many failed attempts against it — mint a new code", null)
        if (state == null || state.closed || state.used || nowMs > state.expiresUtcMs) {
            failedAttempts++
            if (failedAttempts >= GLOBAL_FAILED_ATTEMPTS) lockedUntilMs = nowMs + LOCKOUT_MS
            if (state != null && !state.used && !state.closed) {
                state.failedAttempts++
                if (state.failedAttempts >= MAX_FAILED_ATTEMPTS_PER_CODE) state.lockedUntilMs = nowMs + LOCKOUT_MS
            }
            return Triple(false, "code refused (unknown, used, closed, or expired)", null)
        }
        state.used = true
        val tokenBytes = ByteArray(24).also { SecureRandom().nextBytes(it) }
        val token = tokenBytes.joinToString("") { "%02x".format(it) }
        val grant = QuickAssistGrant(
            grantId = "qag-${++counter}", codeId = state.id, scopeId = state.scopeId,
            hostDeviceId = state.hostDeviceId, viewOnly = GRANT_VIEW_ONLY,
            expiresUtcMs = nowMs + GRANT_TTL_MS)
        state.grantId = grant.grantId
        grants[grant.grantId] = GrantState(grant, hash(token), hash(clientBinding))
        failedAttempts = 0
        return Triple(true, "view-only grant issued", grant to token)
    }

    /**
     * F11(c): the consented step up from view-only to control. A
     * grant starts view-only ([GRANT_VIEW_ONLY]); it becomes a
     * control grant ONLY when the HOST confirms by calling this
     * (the host-side consent act — this service never upgrades a
     * grant on the redeeming client's say-so). False for unknown,
     * closed or expired grants.
     */
    @Synchronized
    fun allowControl(grantId: String, nowMs: Long): Boolean {
        val state = grants[grantId] ?: return false
        if (state.closed || nowMs > state.grant.expiresUtcMs) return false
        grants[grantId] = GrantState(
            state.grant.copy(viewOnly = false), state.tokenHash, state.clientBindingHash, state.closed)
        return true
    }

    @Synchronized
    fun validate(grantId: String?, grantToken: String?, clientBinding: String, nowMs: Long): Pair<Boolean, String> {
        val state = grants[grantId] ?: return false to "no such grant"
        if (state.closed) return false to "grant is closed"
        if (nowMs > state.grant.expiresUtcMs) return false to "grant expired"
        if (!constantTimeEquals(state.tokenHash, hash(grantToken ?: ""))) return false to "grant token mismatch"
        if (!constantTimeEquals(state.clientBindingHash, hash(clientBinding))) return false to "client binding mismatch — this grant answers only to the browser that redeemed it"
        return true to if (state.grant.viewOnly) "grant valid (view-only)" else "grant valid (control — host-confirmed step up)"
    }

    @Synchronized
    fun close(codeIdOrGrantId: String): Boolean {
        var closed = false
        for (c in codes.values) if (c.id == codeIdOrGrantId || c.grantId == codeIdOrGrantId) { c.closed = true; closed = true }
        for (g in grants.values) if (g.grant.grantId == codeIdOrGrantId || g.grant.codeId == codeIdOrGrantId) { g.closed = true; closed = true }
        return closed
    }

    @Synchronized
    fun closeCode(displayCode: String?): Boolean {
        val codeHash = hash(normalize(displayCode))
        var closed = false
        for (c in codes.values) if (c.codeHash == codeHash) {
            c.closed = true; closed = true
            for (g in grants.values) if (g.grant.codeId == c.id) g.closed = true
        }
        return closed
    }

    @Synchronized
    fun isLocked(nowMs: Long): Boolean = nowMs < lockedUntilMs

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }
}

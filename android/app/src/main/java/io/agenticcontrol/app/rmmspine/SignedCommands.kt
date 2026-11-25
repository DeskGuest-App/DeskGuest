package io.agenticcontrol.app.rmmspine

import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.enterprise.sha256Hex
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Base64

/**
 * RMM-03 — Endpoint Takeover Prevention, Android mirror.
 * Mirrors Windows Acp.Shared/Security/SignedCommand.cs +
 * PersistedNonceStore.cs semantics: every hub instruction that
 * CHANGES the phone verifies against a customer-held Ed25519 key
 * BEFORE executing; unsigned/altered/expired/replayed commands
 * refuse, audited. Canonical body covers version, class, key id,
 * issued/expiry, nonce and payload hash — altering any breaks the
 * signature or the hash check. The persisted nonce store closes
 * the Windows lane's own residual: replay refuses ACROSS restarts.
 */
object SignedCommandClasses {
    const val SHELL_EXEC = "shell_exec"
    const val SCRIPT_EXEC = "script_exec"
    const val AUTOMATION = "automation"
    const val PACKAGE_DEPLOY = "package_deploy"
    const val PATCH_DEPLOY = "patch_deploy"
    const val POLICY_DELIVERY = "policy_delivery"
    const val SESSION_INITIATION = "session_initiation"
    const val UPDATE_STAGING = "update_staging"
    const val BACKGROUND_ACTION = "background_action"
    const val PROVISIONING = "provisioning"
    val ALL = setOf(SHELL_EXEC, SCRIPT_EXEC, AUTOMATION, PACKAGE_DEPLOY, PATCH_DEPLOY,
        POLICY_DELIVERY, SESSION_INITIATION, UPDATE_STAGING, BACKGROUND_ACTION, PROVISIONING)
}

/** ISO rendering for canonical bodies: the string stored in the
 *  envelope IS the signed string, so signer and verifier agree by
 *  construction; parsing accepts ISO instant or offset forms. */
object IsoTime {
    fun format(epochMs: Long): String = Instant.ofEpochMilli(epochMs).toString()
    fun parse(s: String?): Long? {
        if (s.isNullOrBlank()) return null
        return try { Instant.parse(s).toEpochMilli() }
        catch (_: Exception) {
            try { OffsetDateTime.parse(s).toInstant().toEpochMilli() } catch (_: Exception) { null }
        }
    }
}

data class SignedCommandEnvelope(
    val version: Int, val commandClass: String, val keyId: String,
    val issuedUtc: String, val expiresUtc: String, val nonce: String,
    val payloadHash: String, val payloadBase64: String, val signatureBase64: String
) {
    fun canonicalBody(): String = listOf(
        "acp-signed-command-v1", version.toString(), commandClass, keyId,
        issuedUtc, expiresUtc, nonce, payloadHash
    ).joinToString("|")

    fun payloadBytes(): ByteArray? = try {
        Base64.getDecoder().decode(payloadBase64)
    } catch (_: Exception) { null }

    fun toJson(): JSONObject = JSONObject()
        .put("version", version).put("commandClass", commandClass).put("keyId", keyId)
        .put("issuedUtc", issuedUtc).put("expiresUtc", expiresUtc).put("nonce", nonce)
        .put("payloadHash", payloadHash).put("payloadBase64", payloadBase64)
        .put("signatureBase64", signatureBase64)

    companion object {
        fun hashPayload(payload: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(payload)
                .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        fun fromJson(o: JSONObject?): SignedCommandEnvelope? {
            if (o == null) return null
            return try {
                SignedCommandEnvelope(
                    o.optInt("version", -1), o.optString("commandClass", ""), o.optString("keyId", ""),
                    o.optString("issuedUtc", ""), o.optString("expiresUtc", ""), o.optString("nonce", ""),
                    o.optString("payloadHash", ""), o.optString("payloadBase64", ""), o.optString("signatureBase64", "")
                )
            } catch (_: Exception) { null }
        }
    }
}

data class CustomerCommandKey(val keyId: String, val publicKey: ByteArray, val retiredUntilMs: Long?) {
    fun isRetired(nowMs: Long): Boolean = retiredUntilMs != null && nowMs > retiredUntilMs
}

/** Endpoint-side PUBLIC key ring. Key ids derive from key material
 *  ("cust-" + first 16 hex of SHA-256(pubkey)) — an id cannot be
 *  detached from its key. Rotation retires with a bounded grace. */
class CustomerCommandKeyRing {
    private val keys = mutableMapOf<String, CustomerCommandKey>()
    var currentKeyId: String? = null
        private set

    companion object {
        fun keyIdFor(publicKey: ByteArray): String =
            "cust-" + DeviceIdentity.deviceIdFor(publicKey).substring(0, 16)
    }

    @Synchronized
    fun addCurrent(publicKey: ByteArray): CustomerCommandKey {
        require(publicKey.size == 32) { "customer command public key must be 32 bytes" }
        val k = CustomerCommandKey(keyIdFor(publicKey), publicKey.copyOf(), null)
        // W12-DS P7-F21: installing a new current key RETIRES the
        // previous current key (bounded 24h grace) — the old key
        // must not verify forever just because a caller used
        // addCurrent instead of rotate.
        val prev = currentKeyId
        if (prev != null && prev != k.keyId) {
            keys[prev]?.let { old -> if (old.retiredUntilMs == null)
                keys[prev] = old.copy(retiredUntilMs = System.currentTimeMillis() + 24 * 3_600_000L) }
        }
        keys[k.keyId] = k; currentKeyId = k.keyId; return k
    }

    @Synchronized
    fun addRetired(publicKey: ByteArray, retiredUntilMs: Long): CustomerCommandKey {
        require(publicKey.size == 32) { "customer command public key must be 32 bytes" }
        val k = CustomerCommandKey(keyIdFor(publicKey), publicKey.copyOf(), retiredUntilMs)
        keys[k.keyId] = k; return k
    }

    @Synchronized
    fun rotate(newPublicKey: ByteArray, nowMs: Long, graceMs: Long): CustomerCommandKey {
        currentKeyId?.let { cur ->
            keys[cur]?.let { old -> if (old.retiredUntilMs == null) keys[cur] = old.copy(retiredUntilMs = nowMs + graceMs) }
        }
        return addCurrent(newPublicKey)
    }

    @Synchronized
    fun get(keyId: String?): CustomerCommandKey? = keys[keyId ?: ""]

    @Synchronized
    fun all(): List<CustomerCommandKey> = keys.values.sortedBy { it.keyId }
}

/** Hub-side signer (tests / hub composition): the seed never leaves
 *  the DeviceIdentity; this is the only place envelopes are minted. */
class SignedCommandSigner(private val customerKey: DeviceIdentity) {
    val keyId: String = CustomerCommandKeyRing.keyIdFor(customerKey.publicKey)

    fun sign(commandClass: String, payload: ByteArray, nowMs: Long, ttlMs: Long, nonce: String): SignedCommandEnvelope {
        require(commandClass in SignedCommandClasses.ALL) { "unknown signed-command class '$commandClass'" }
        require(ttlMs > 0) { "envelope ttl must be positive" }
        val unsigned = SignedCommandEnvelope(
            1, commandClass, keyId, IsoTime.format(nowMs), IsoTime.format(nowMs + ttlMs),
            nonce, SignedCommandEnvelope.hashPayload(payload),
            Base64.getEncoder().encodeToString(payload), ""
        )
        val sig = customerKey.sign(unsigned.canonicalBody().toByteArray(Charsets.UTF_8))
        return unsigned.copy(signatureBase64 = Base64.getEncoder().encodeToString(sig))
    }
}

interface ReplayGuard {
    fun tryRegister(e: SignedCommandEnvelope, nowMs: Long): Boolean
    val trackedCount: Int
}

/** In-memory guard (tests / unwired hosts). */
class InMemoryReplayGuard : ReplayGuard {
    private val seen = mutableMapOf<String, Long>()
    @Synchronized
    override fun tryRegister(e: SignedCommandEnvelope, nowMs: Long): Boolean {
        seen.entries.removeIf { it.value < nowMs }
        val id = e.keyId + "|" + e.nonce
        if (id in seen) return false
        seen[id] = (IsoTime.parse(e.expiresUtc) ?: nowMs) + 5 * 60_000L
        return true
    }
    override val trackedCount: Int get() = synchronized(this) { seen.size }
}

/**
 * Persisted nonce store (the Windows precondition fix): seen nonces
 * live in a file, flushed temp+replace BEFORE an acceptance returns,
 * pruned only after expiry+5min. A store file that exists but does
 * not parse is BROKEN and refuses EVERY registration — an unreadable
 * replay history is never treated as an empty one (fail closed).
 */
class PersistedNonceStore(private val file: File) : ReplayGuard {
    private val seen = mutableMapOf<String, Long>()
    var broken: Boolean = false
        private set
    var state: String = ""
        private set

    init {
        synchronized(this) {
            if (!file.exists()) {
                state = "fresh: no nonce store file yet (first boot)"
            } else {
                try {
                    val arr = JSONArray(file.readText())
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        val kid = o.optString("keyId", ""); val nonce = o.optString("nonce", "")
                        if (kid.isBlank() || nonce.isBlank()) throw IllegalStateException("empty key id or nonce")
                        seen["$kid|$nonce"] = o.getLong("keepUntilMs")
                    }
                    state = "loaded: ${seen.size} seen nonce(s) restored from disk"
                } catch (ex: Exception) {
                    broken = true; seen.clear()
                    state = "BROKEN: nonce store at '${file.name}' did not load (${ex.javaClass.simpleName}) — every registration refuses until repaired (fail closed)"
                }
            }
        }
    }

    @Synchronized
    override fun tryRegister(e: SignedCommandEnvelope, nowMs: Long): Boolean {
        if (broken) return false
        seen.entries.removeIf { it.value < nowMs }
        val id = e.keyId + "|" + e.nonce
        if (id in seen) return false
        seen[id] = (IsoTime.parse(e.expiresUtc) ?: nowMs) + 5 * 60_000L
        try { flush() } catch (_: Exception) {
            seen.remove(id); broken = true
            state = "BROKEN: nonce store flush failed — registrations refuse (fail closed)"
            return false
        }
        return true
    }

    override val trackedCount: Int get() = synchronized(this) { seen.size }

    private fun flush() {
        file.parentFile?.mkdirs()
        val arr = JSONArray()
        for ((id, keep) in seen.entries.sortedBy { it.key }) {
            val sep = id.indexOf('|')
            arr.put(JSONObject().put("keyId", id.substring(0, sep)).put("nonce", id.substring(sep + 1)).put("keepUntilMs", keep))
        }
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(arr.toString())
        if (!tmp.renameTo(file)) { tmp.delete(); throw IllegalStateException("nonce store rename failed") }
    }
}

data class SignedVerdict(val allowed: Boolean, val reason: String, val payload: ByteArray? = null)

/** Endpoint verifier. Pure and fail-closed: nothing throws. */
class SignedCommandVerifier(
    private val ring: CustomerCommandKeyRing,
    private val replay: ReplayGuard = InMemoryReplayGuard()
) {
    fun verify(e: SignedCommandEnvelope?, nowMs: Long, expectedClass: String? = null, expectedPayload: ByteArray? = null): SignedVerdict {
        if (e == null) return SignedVerdict(false, "no signed-command envelope presented — refused (RMM-03: unsigned commands never execute)")
        if (e.version != 1) return SignedVerdict(false, "unknown envelope version ${e.version} — refused")
        if (e.commandClass !in SignedCommandClasses.ALL) return SignedVerdict(false, "unknown command class '${e.commandClass}' — refused")
        if (expectedClass != null && e.commandClass != expectedClass)
            return SignedVerdict(false, "command class '${e.commandClass}' does not match the '$expectedClass' this path executes — refused")
        if (e.nonce.isBlank()) return SignedVerdict(false, "envelope carries no nonce — refused (replay protection is not optional)")
        val issued = IsoTime.parse(e.issuedUtc) ?: return SignedVerdict(false, "envelope issued time unparseable — refused")
        val expires = IsoTime.parse(e.expiresUtc) ?: return SignedVerdict(false, "envelope expiry unparseable — refused")
        if (expires <= nowMs) return SignedVerdict(false, "signed command expired — refused")
        if (issued > nowMs + 5 * 60_000L) return SignedVerdict(false, "signed command issued in the future — refused")
        if (expires <= issued) return SignedVerdict(false, "envelope expiry precedes its issuance — refused")
        val payload = e.payloadBytes() ?: return SignedVerdict(false, "payload is not valid base64 — refused")
        if (SignedCommandEnvelope.hashPayload(payload) != e.payloadHash.lowercase())
            return SignedVerdict(false, "payload hash mismatch — the command was altered after signing — refused")
        val key = ring.get(e.keyId) ?: return SignedVerdict(false, "unknown signer key id '${e.keyId}' — refused (key-id confusion never widens trust)")
        if (key.isRetired(nowMs)) return SignedVerdict(false, "signer key '${e.keyId}' is retired past its grace deadline — refused")
        val sig = try { Base64.getDecoder().decode(e.signatureBase64) } catch (_: Exception) { return SignedVerdict(false, "signature undecodable — refused") }
        if (!DeviceIdentity.verify(key.publicKey, e.canonicalBody().toByteArray(Charsets.UTF_8), sig))
            return SignedVerdict(false, "signature invalid — refused (fail closed; a compromised hub cannot forge the customer's key)")
        if (expectedPayload != null && !payload.contentEquals(expectedPayload))
            return SignedVerdict(false, "payload does not match the payload this path executes — refused (payload binding)")
        if (!replay.tryRegister(e, nowMs)) return SignedVerdict(false, "nonce already seen — replayed command refused")
        return SignedVerdict(true, "signed command verified (class ${e.commandClass}, key ${e.keyId})", payload)
    }

    /** Signature/expiry recheck WITHOUT consuming the nonce — the
     *  RMM-15 resume path: resume is a continuation of an already
     *  consumed presentation, not a new one.
     *  W13 P7-F14: [expectedClass] binds the recheck to the class
     *  the resume path is resuming — an envelope of any other class
     *  (or, when a payload is supplied via the full [verify], any
     *  other payload) does not recheck as authority for it. */
    fun verifySignatureOnly(e: SignedCommandEnvelope?, nowMs: Long, expectedClass: String? = null): SignedVerdict {
        if (e == null) return SignedVerdict(false, "no envelope to recheck — authority invalid")
        if (e.commandClass !in SignedCommandClasses.ALL) return SignedVerdict(false, "unknown command class on recheck — authority invalid")
        if (expectedClass != null && e.commandClass != expectedClass)
            return SignedVerdict(false, "envelope class '${e.commandClass}' is not the class this path resumes ('$expectedClass') — authority invalid")
        val expires = IsoTime.parse(e.expiresUtc) ?: return SignedVerdict(false, "envelope expiry unparseable — authority invalid")
        if (expires <= nowMs) return SignedVerdict(false, "authority_expired")
        val payload = e.payloadBytes() ?: return SignedVerdict(false, "payload undecodable — authority invalid")
        if (SignedCommandEnvelope.hashPayload(payload) != e.payloadHash.lowercase())
            return SignedVerdict(false, "payload hash mismatch on recheck — authority invalid")
        val key = ring.get(e.keyId) ?: return SignedVerdict(false, "signer key no longer in ring — authority invalid")
        if (key.isRetired(nowMs)) return SignedVerdict(false, "signer key retired past grace — authority invalid")
        val sig = try { Base64.getDecoder().decode(e.signatureBase64) } catch (_: Exception) { return SignedVerdict(false, "signature undecodable — authority invalid") }
        if (!DeviceIdentity.verify(key.publicKey, e.canonicalBody().toByteArray(Charsets.UTF_8), sig))
            return SignedVerdict(false, "signature invalid on recheck — authority invalid")
        return SignedVerdict(true, "authority rechecked", payload)
    }
}

/** The gate wired in front of tool execution: every acceptance AND
 *  refusal is a hash-chained audit event, never silent. */
class SignedCommandGate(
    private val verifier: SignedCommandVerifier,
    private val audit: ChainedAuditLog
) {
    fun authorize(e: SignedCommandEnvelope?, nowMs: Long, expectedClass: String? = null, expectedPayload: ByteArray? = null): SignedVerdict {
        val v = verifier.verify(e, nowMs, expectedClass, expectedPayload)
        val cls = e?.commandClass ?: "(none)"; val kid = e?.keyId ?: "(none)"
        if (v.allowed) audit.append("signed_command_accepted", "signed-command-gate", "class=$cls key=$kid nonce=${e!!.nonce}", nowMs)
        else audit.append("signed_command_refused", "signed-command-gate", "class=$cls key=$kid reason=${v.reason}", nowMs)
        return v
    }
}

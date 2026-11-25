package io.agenticcontrol.app.recovery

import io.agenticcontrol.app.adb.Ed25519
import io.agenticcontrol.app.adb.Hkdf
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/**
 * C20 — Recovery blob (Android mirror of Acp.Shared/Security/
 * RecoveryBlob.cs; the envelope format is BYTE-COMPATIBLE across the
 * two platforms and the JVM suite proves cross-platform restore in
 * both directions against the C# harness fixture).
 *
 * The artefact is USER-HELD: the user exports a single encrypted file
 * and keeps it where they choose. NO cloud default, NO ACP account,
 * NO server-side recovery — there is no server (D-series law).
 * Optional sealed copies go to user-named recovery contacts, encrypted
 * to the contact's enrolled Ed25519 key; the holder cannot read them,
 * and the named contact cannot use one alone (unsealing yields a
 * recovery-key-wrapped blob key — the key sheet is also required).
 *
 * Keystore seam (spec): the phone's identity seed is stored wrapped
 * by an Android Keystore key (server/KeystoreKeys.kt via a
 * LineCipher). Export RE-WRAPS that material under the recovery key:
 * the caller unwraps the identity with the keystore cipher
 * (DeviceIdentity.load(...).seedCopy()) and hands the seed here; the
 * blob carries it inside the encrypted payload. Keystore keys
 * themselves never leave the device. On restore the caller re-wraps
 * the returned seed under the (new) device's keystore cipher via
 * DeviceIdentity.fromSeed(seed).save(file, cipher, overwrite = true)
 * (W13 P4-F19: overwrite is explicit — restore re-wraps over the
 * placeholder the restore flow created; save()'s default is false).
 *
 * Restore discipline mirrors the C# service exactly: parse → recover
 * the blob key through the presented credential → AES-256-GCM-decrypt
 * (tag failure = refuse) → validate payload + device binding → only
 * then check the target is empty (live identity / non-empty stores
 * refuse) → apply. A refused import never touches live state.
 */
class RecoveryBlobException(message: String) : Exception(message)

data class RecoveryContact(val name: String, val ed25519PublicKey: ByteArray)

data class RecoveryExportResult(
    val primaryBlob: ByteArray,
    val contactBlobs: List<Pair<RecoveryContact, ByteArray>>,
    val keySheet: String,
    val deviceId: String
)

data class RecoveryPayloadData(
    val deviceId: String,
    val identitySeed: ByteArray,
    val pairingsExport: String,
    val rosterExport: String
)

data class RecoveryBlobInfo(
    val kind: String,
    val deviceId: String,
    val createdUtc: String,
    val contactName: String?
)

object RecoveryBlob {

    const val FORMAT_TAG = "acp-recovery-blob"
    const val FORMAT_VERSION = 1
    const val KIND_PRIMARY = "primary"
    const val KIND_CONTACT = "contact"
    const val PASSPHRASE_ITERATIONS = 600_000
    const val MIN_PASSPHRASE_LENGTH = 10

    private const val PAYLOAD_FORMAT_TAG = "acp-recovery-payload"
    private const val SEAL_INFO = "acp-recovery-seal-v1"

    private val random = SecureRandom()
    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun unb64(text: String): ByteArray = try {
        Base64.getDecoder().decode(text)
    } catch (e: Exception) {
        throw RecoveryBlobException("the blob carries malformed base64 — corrupt; nothing was restored")
    }

    // ---- key sheet (pinned SAS word list, generated from the pattern) ----

    val KEY_SHEET_WORDS: List<String> = run {
        val onsets = listOf("b", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z")
        val suffixes = listOf("ab", "ad", "ag", "ak", "al", "am", "an", "ap", "ar", "as", "at", "av", "eb", "ed", "eg", "ek")
        onsets.flatMap { onset -> suffixes.map { suffix -> onset + suffix } }
    }

    /** 32 key words + 2 checksum words (SHA-256 of the key), 34 total. */
    fun keySheetEncode(recoveryKey: ByteArray): String {
        if (recoveryKey.size != 32) throw RecoveryBlobException("a recovery key is exactly 32 bytes")
        val words = ArrayList<String>(34)
        for (b in recoveryKey) words.add(KEY_SHEET_WORDS[b.toInt() and 0xFF])
        val check = MessageDigest.getInstance("SHA-256").digest(recoveryKey)
        words.add(KEY_SHEET_WORDS[check[0].toInt() and 0xFF])
        words.add(KEY_SHEET_WORDS[check[1].toInt() and 0xFF])
        return words.joinToString(" ")
    }

    fun keySheetDecode(keySheet: String): ByteArray {
        if (keySheet.isBlank()) throw RecoveryBlobException("the recovery key sheet is empty")
        val tokens = keySheet.lowercase().split(' ', '\t', '\r', '\n', '-').filter { it.isNotEmpty() }
        if (tokens.size != 34)
            throw RecoveryBlobException("a recovery key sheet is 34 words — this one has ${tokens.size}")
        val bytes = ByteArray(34)
        for ((i, token) in tokens.withIndex()) {
            val idx = KEY_SHEET_WORDS.indexOf(token)
            if (idx < 0) throw RecoveryBlobException("key sheet word '$token' is not a recovery word")
            bytes[i] = idx.toByte()
        }
        val key = bytes.copyOf(32)
        val check = MessageDigest.getInstance("SHA-256").digest(key)
        if (check[0] != bytes[32] || check[1] != bytes[33])
            throw RecoveryBlobException("key sheet checksum mismatch — a word is wrong or mistyped; refused before any decryption")
        return key
    }

    // ---- export ------------------------------------------------------------

    /**
     * Export the artefact set. [identitySeed] is the device's raw
     * 32-byte Ed25519 seed, obtained by the caller through the
     * Keystore unwrapping seam described in the class doc.
     * [pairingsExport]/[rosterExport] are the stores' own export
     * strings, carried opaquely inside the encrypted payload.
     * [createdUtc] is an ISO-8601 timestamp from the caller's clock.
     */
    fun export(
        identitySeed: ByteArray,
        deviceId: String,
        pairingsExport: String,
        rosterExport: String,
        passphrase: String,
        contacts: List<RecoveryContact> = emptyList(),
        createdUtc: String
    ): RecoveryExportResult {
        if (identitySeed.size != 32) throw RecoveryBlobException("the identity seed is not 32 bytes — export refused")
        // W12-DS P4-F7: the deviceId is DERIVED from the seed, never
        // trusted from the caller — a mismatched id would emit a
        // blob openVerified can never open.
        val derivedDeviceId = io.agenticcontrol.app.enrollment.DeviceIdentity.deviceIdFor(
            io.agenticcontrol.app.enrollment.DeviceIdentity.derivePublicKey(identitySeed))
        if (deviceId != derivedDeviceId)
            throw RecoveryBlobException("the supplied deviceId does not match the identity seed — export refused (the blob would be unopenable)")
        if (passphrase.length < MIN_PASSPHRASE_LENGTH)
            throw RecoveryBlobException("the export passphrase must be at least $MIN_PASSPHRASE_LENGTH characters — it is the only thing standing between a found blob and this device's identity")
        for (contact in contacts) {
            if (contact.name.isBlank()) throw RecoveryBlobException("a recovery contact needs a name")
            if (contact.ed25519PublicKey.size != 32)
                throw RecoveryBlobException("recovery contact '${contact.name}' does not carry a 32-byte Ed25519 public key")
            val point = Ed25519.decode(contact.ed25519PublicKey)
                ?: throw RecoveryBlobException("recovery contact '${contact.name}' public key does not decode — refused")
            if (Ed25519.isSmallOrder(point))
                throw RecoveryBlobException("recovery contact '${contact.name}' public key is a small-order point — sealing to it would produce a predictable shared secret; refused")
        }

        val payload = JSONObject()
            .put("format", PAYLOAD_FORMAT_TAG)
            .put("version", FORMAT_VERSION)
            .put("deviceId", deviceId)
            .put("createdUtc", createdUtc)
            .put("identitySeed", b64(identitySeed))
            .put("pairings", pairingsExport)
            .put("roster", rosterExport)
            .toString().toByteArray(Charsets.UTF_8)

        val blobKey = ByteArray(32).also { random.nextBytes(it) }
        val recoveryKey = ByteArray(32).also { random.nextBytes(it) }
        try {
            val (nonce, ciphertext) = aesGcmEncrypt(blobKey, payload, aad(deviceId))

            val salt = ByteArray(16).also { random.nextBytes(it) }
            val kek = pbkdf2Sha256(passphrase.toByteArray(Charsets.UTF_8), salt, PASSPHRASE_ITERATIONS, 32)
            val wrappedByPassphrase = try {
                wrapKey(kek, blobKey, "passphrase")
            } finally {
                kek.fill(0)
            }
            val wrappedByRecovery = wrapKey(recoveryKey, blobKey, "recovery-key")

            val primary = JSONObject()
                .put("format", FORMAT_TAG)
                .put("version", FORMAT_VERSION)
                .put("kind", KIND_PRIMARY)
                .put("deviceId", deviceId)
                .put("createdUtc", createdUtc)
                .put("payloadNonce", b64(nonce))
                .put("payloadCiphertext", b64(ciphertext))
                .put("passphrase", JSONObject()
                    .put("salt", b64(salt))
                    .put("iterations", PASSPHRASE_ITERATIONS)
                    .put("wrappedKey", b64(wrappedByPassphrase)))
                .put("recoveryKey", JSONObject().put("wrappedKey", b64(wrappedByRecovery)))
                .put("sealed", JSONObject.NULL)

            val contactBlobs = contacts.map { contact ->
                val recoveryWrapped = wrapKey(recoveryKey, blobKey, "recovery-key")
                val sealedSlot = sealToContact(contact, recoveryWrapped)
                val envelope = JSONObject()
                    .put("format", FORMAT_TAG)
                    .put("version", FORMAT_VERSION)
                    .put("kind", KIND_CONTACT)
                    .put("deviceId", deviceId)
                    .put("createdUtc", createdUtc)
                    .put("payloadNonce", b64(nonce))
                    .put("payloadCiphertext", b64(ciphertext))
                    .put("passphrase", JSONObject.NULL)
                    .put("recoveryKey", JSONObject.NULL)
                    .put("sealed", sealedSlot)
                contact to envelope.toString().toByteArray(Charsets.UTF_8)
            }

            return RecoveryExportResult(
                primary.toString().toByteArray(Charsets.UTF_8),
                contactBlobs,
                keySheetEncode(recoveryKey),
                deviceId
            )
        } finally {
            blobKey.fill(0)
            recoveryKey.fill(0)
        }
    }

    // ---- inspect -------------------------------------------------------------

    fun inspect(blob: ByteArray): RecoveryBlobInfo {
        val env = parseEnvelope(blob)
        val sealed = if (env.isNull("sealed")) null else env.getJSONObject("sealed")
        return RecoveryBlobInfo(
            env.getString("kind"),
            env.getString("deviceId"),
            env.getString("createdUtc"),
            sealed?.getString("contactName")
        )
    }

    // ---- restore ---------------------------------------------------------------

    /** Verify + open a PRIMARY blob (passphrase wins when both are
     *  given). Touches NO live state — see [restorePrimary]. */
    fun openPrimary(blob: ByteArray, passphrase: String?, keySheet: String?): RecoveryPayloadData {
        val env = parseEnvelope(blob)
        if (env.getString("kind") != KIND_PRIMARY)
            throw RecoveryBlobException("this is a sealed contact copy, not the primary blob — restore it with the named contact's key and the recovery key sheet")
        val blobKey: ByteArray = when {
            !passphrase.isNullOrEmpty() -> {
                if (env.isNull("passphrase")) throw RecoveryBlobException("this blob carries no passphrase slot")
                unwrapWithPassphrase(env.getJSONObject("passphrase"), passphrase)
            }
            !keySheet.isNullOrBlank() -> {
                if (env.isNull("recoveryKey")) throw RecoveryBlobException("this blob carries no recovery-key slot")
                val recoveryKey = keySheetDecode(keySheet)
                try {
                    unwrapKey(recoveryKey, unb64(env.getJSONObject("recoveryKey").getString("wrappedKey")), "recovery-key")
                } catch (e: RecoveryBlobException) {
                    throw RecoveryBlobException("the recovery key sheet does not open this blob — wrong sheet, or the blob is corrupt; nothing was restored")
                } finally {
                    recoveryKey.fill(0)
                }
            }
            else -> throw RecoveryBlobException("a restore needs the export passphrase or the recovery key sheet")
        }
        try {
            return openVerified(env, blobKey)
        } finally {
            blobKey.fill(0)
        }
    }

    /** Verify + open a SEALED CONTACT copy: needs BOTH the named
     *  contact's identity seed AND the recovery key sheet. */
    fun openContactCopy(blob: ByteArray, contactSeed: ByteArray, keySheet: String): RecoveryPayloadData {
        val env = parseEnvelope(blob)
        if (env.getString("kind") != KIND_CONTACT || env.isNull("sealed"))
            throw RecoveryBlobException("this is not a sealed contact copy")
        if (contactSeed.size != 32) throw RecoveryBlobException("the contact's identity seed must be 32 bytes")
        if (keySheet.isBlank())
            throw RecoveryBlobException("a contact-copy restore also needs the recovery key sheet — the contact's key alone is not enough, by design")
        val recoveryWrapped = unsealFromContact(env.getJSONObject("sealed"), contactSeed)
        val recoveryKey = keySheetDecode(keySheet)
        val blobKey = try {
            unwrapKey(recoveryKey, recoveryWrapped, "recovery-key")
        } catch (e: RecoveryBlobException) {
            throw RecoveryBlobException("the recovery key sheet does not match this contact copy — wrong sheet, or the copy is corrupt; nothing was restored")
        } finally {
            recoveryKey.fill(0)
        }
        try {
            return openVerified(env, blobKey)
        } finally {
            blobKey.fill(0)
        }
    }

    /**
     * Full restore of a primary blob into EMPTY stores: verification
     * completes first; [liveIdentityExists] / [targetStoresEmpty] are
     * consulted after verification and before [apply] runs, so a
     * refused import leaves live state byte-identical.
     */
    fun restorePrimary(
        blob: ByteArray,
        passphrase: String?,
        keySheet: String?,
        liveIdentityExists: () -> Boolean,
        targetStoresEmpty: () -> Boolean,
        apply: (RecoveryPayloadData) -> Unit
    ): RecoveryPayloadData {
        val payload = openPrimary(blob, passphrase, keySheet)
        refuseIfNotEmpty(liveIdentityExists, targetStoresEmpty)
        apply(payload)
        return payload
    }

    /** Full restore of a sealed contact copy into EMPTY stores. */
    fun restoreFromContactCopy(
        blob: ByteArray,
        contactSeed: ByteArray,
        keySheet: String,
        liveIdentityExists: () -> Boolean,
        targetStoresEmpty: () -> Boolean,
        apply: (RecoveryPayloadData) -> Unit
    ): RecoveryPayloadData {
        val payload = openContactCopy(blob, contactSeed, keySheet)
        refuseIfNotEmpty(liveIdentityExists, targetStoresEmpty)
        apply(payload)
        return payload
    }

    private fun refuseIfNotEmpty(liveIdentityExists: () -> Boolean, targetStoresEmpty: () -> Boolean) {
        if (liveIdentityExists())
            throw RecoveryBlobException("a live identity already exists on this device — restore refused (a recovery import never overwrites a live identity)")
        if (!targetStoresEmpty())
            throw RecoveryBlobException("the target stores are not empty — restore refused (a recovery import lands in empty stores only)")
    }

    /** Decrypt + validate the payload. Pure: touches no state. */
    private fun openVerified(env: JSONObject, blobKey: ByteArray): RecoveryPayloadData {
        val payloadBytes = try {
            aesGcmDecrypt(blobKey, unb64(env.getString("payloadNonce")), unb64(env.getString("payloadCiphertext")), aad(env.getString("deviceId")))
        } catch (e: RecoveryBlobException) {
            throw e
        } catch (e: Exception) {
            throw RecoveryBlobException("the blob failed its integrity check — it is corrupt or tampered with; nothing was restored")
        }
        val payload = try {
            JSONObject(String(payloadBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            throw RecoveryBlobException("the blob's payload is malformed; nothing was restored")
        }
        // W13 P4-F13 remainder closed: EVERY field extraction in
        // this verification is inside the translation boundary —
        // a missing/wrong-typed field (JSONException) becomes a
        // RecoveryBlobException, never a raw org.json escape.
        try {
            if (payload.optString("format") != PAYLOAD_FORMAT_TAG || payload.optInt("version") != FORMAT_VERSION)
                throw RecoveryBlobException("the blob's payload is not a recovery payload; nothing was restored")
            if (payload.getString("deviceId") != env.getString("deviceId"))
                throw RecoveryBlobException("the blob's payload does not match its envelope device binding — substituted or tampered; nothing was restored")
            val seed = unb64(payload.getString("identitySeed"))
            if (seed.size != 32) throw RecoveryBlobException("the blob's identity seed is not 32 bytes; nothing was restored")
            // The seed must reproduce the bound device id (SHA-256 of the
            // derived public key) — a substituted seed refuses here.
            val derivedId = io.agenticcontrol.app.enrollment.DeviceIdentity.deviceIdFor(
                io.agenticcontrol.app.enrollment.DeviceIdentity.derivePublicKey(seed)
            )
            if (derivedId != env.getString("deviceId"))
                throw RecoveryBlobException("the blob's identity seed does not reproduce its device id — tampered; nothing was restored")
            return RecoveryPayloadData(
                payload.getString("deviceId"),
                seed,
                payload.getString("pairings"),
                payload.getString("roster")
            )
        } catch (e: RecoveryBlobException) {
            throw e
        } catch (e: Exception) {
            throw RecoveryBlobException("the blob's payload is malformed; nothing was restored")
        }
    }

    // ---- envelope ----------------------------------------------------------------

    private fun parseEnvelope(blob: ByteArray): JSONObject {
        if (blob.isEmpty()) throw RecoveryBlobException("the blob is empty")
        val env = try {
            JSONObject(String(blob, Charsets.UTF_8))
        } catch (e: Exception) {
            throw RecoveryBlobException("this file is not a recovery blob (unparseable)")
        }
        if (env.optString("format") != FORMAT_TAG) throw RecoveryBlobException("this file is not a recovery blob")
        if (env.optInt("version") != FORMAT_VERSION)
            throw RecoveryBlobException("recovery blob version ${env.optInt("version")} is not supported by this build (expected $FORMAT_VERSION)")
        val kind = env.optString("kind")
        if (kind != KIND_PRIMARY && kind != KIND_CONTACT) throw RecoveryBlobException("unknown recovery blob kind '$kind'")
        if (env.optString("deviceId").isBlank() || env.optString("payloadNonce").isBlank() || env.optString("payloadCiphertext").isBlank())
            throw RecoveryBlobException("the recovery blob envelope is incomplete")
        return env
    }

    // ---- sealing (Ed25519 → X25519 sealed box) --------------------------------------

    private fun sealToContact(contact: RecoveryContact, recoveryWrappedKey: ByteArray): JSONObject {
        val ephemeralSeed = ByteArray(32).also { random.nextBytes(it) }
        try {
            val ephemeralScalar = X25519Recovery.scalarFromEd25519Seed(ephemeralSeed)
            val ephemeralPublic = X25519Recovery.raw(ephemeralScalar, X25519Recovery.BASE_POINT_U)
            val contactU = X25519Recovery.publicFromEd25519(contact.ed25519PublicKey)
            val shared = X25519Recovery.raw(ephemeralScalar, contactU)
            rejectZeroShared(shared)
            val sealKey = Hkdf.sha256(shared, ephemeralPublic, SEAL_INFO.toByteArray(Charsets.UTF_8), 32)
            try {
                // W13 P4-F17: new seals bind the contact NAME into
                // the AAD (sealAadV2) and say so (sealAadV=2) — a
                // renamed slot no longer opens. Pre-W13 seals carry
                // no marker and open under the legacy AAD only.
                val (nonce, ct) = aesGcmEncrypt(sealKey, recoveryWrappedKey, sealAadV2(contact.ed25519PublicKey, contact.name))
                return JSONObject()
                    .put("contactName", contact.name)
                    .put("sealAadV", 2)
                    .put("contactPublicKey", b64(contact.ed25519PublicKey))
                    .put("ephemeralPublicKey", b64(ephemeralPublic))
                    .put("sealedWrappedKey", b64(nonce + ct))
            } finally {
                sealKey.fill(0)
            }
        } finally {
            ephemeralSeed.fill(0)
        }
    }

    private fun unsealFromContact(slot: JSONObject, contactSeed: ByteArray): ByteArray {
        val contactPublic: ByteArray
        val ephemeralPublic: ByteArray
        val sealedBytes: ByteArray
        try {
            contactPublic = unb64(slot.getString("contactPublicKey"))
            ephemeralPublic = unb64(slot.getString("ephemeralPublicKey"))
            sealedBytes = unb64(slot.getString("sealedWrappedKey"))
        } catch (e: RecoveryBlobException) {
            throw RecoveryBlobException("the sealed slot is malformed; nothing was restored")
        } catch (e: Exception) {
            // W13 P4-F13: JSONException translates too.
            throw RecoveryBlobException("the sealed slot is malformed; nothing was restored")
        }
        if (contactPublic.size != 32 || ephemeralPublic.size != 32 || sealedBytes.size <= 12 + 16)
            throw RecoveryBlobException("the sealed slot is malformed; nothing was restored")
        // The presented seed must belong to the NAMED contact.
        val presentedPublic = io.agenticcontrol.app.enrollment.DeviceIdentity.derivePublicKey(contactSeed)
        if (!MessageDigest.isEqual(presentedPublic, contactPublic))
            throw RecoveryBlobException("this copy is sealed to '${slot.optString("contactName")}' — the presented key is not theirs; refused")
        val scalar = X25519Recovery.scalarFromEd25519Seed(contactSeed)
        val shared = X25519Recovery.raw(scalar, ephemeralPublic)
        rejectZeroShared(shared)
        val sealKey = Hkdf.sha256(shared, ephemeralPublic, SEAL_INFO.toByteArray(Charsets.UTF_8), 32)
        try {
            // W13 P4-F17: v2 slots verify against the name-bound
            // AAD (the slot's own contactName — renaming it breaks
            // the seal); unmarked slots are pre-W13 and verify
            // against the legacy AAD.
            val aad = if (slot.optInt("sealAadV", 1) >= 2)
                sealAadV2(contactPublic, slot.optString("contactName"))
            else sealAad(contactPublic)
            return aesGcmDecrypt(sealKey, sealedBytes.copyOfRange(0, 12), sealedBytes.copyOfRange(12, sealedBytes.size), aad)
        } catch (e: Exception) {
            throw RecoveryBlobException("the sealed copy failed its integrity check — corrupt or tampered; nothing was restored")
        } finally {
            sealKey.fill(0)
        }
    }

    private fun rejectZeroShared(shared: ByteArray) {
        if (shared.all { it == 0.toByte() })
            throw RecoveryBlobException("the key agreement produced a degenerate shared secret — refused (small-order peer key)")
    }

    private fun sealAad(contactPublicKey: ByteArray): ByteArray =
        ("acp-recovery-seal|" + b64(contactPublicKey)).toByteArray(Charsets.UTF_8)

    /** W13 P4-F17: v2 seal AAD — the contact's display name is
     *  bound into the seal, so editing the slot's contactName
     *  (e.g. to redirect a restore) breaks verification. */
    private fun sealAadV2(contactPublicKey: ByteArray, contactName: String): ByteArray =
        ("acp-recovery-seal-v2|" + b64(contactPublicKey) + "|" + contactName).toByteArray(Charsets.UTF_8)

    // ---- primitive helpers ------------------------------------------------------------

    /** Payload AAD: format + device — deliberately NOT the envelope
     *  kind (primary and contact envelopes share one ciphertext). */
    private fun aad(deviceId: String): ByteArray =
        "$FORMAT_TAG|$FORMAT_VERSION|$deviceId".toByteArray(Charsets.UTF_8)

    private fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        // JCE output is ciphertext || tag(16) — the same layout the
        // C# service produces by concatenating ciphertext + tag.
        return nonce to cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        if (nonce.size != 12 || ciphertextWithTag.size < 16) throw RecoveryBlobException("ciphertext too short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextWithTag)
    }

    private fun wrapKey(wrappingKey: ByteArray, key: ByteArray, slotName: String): ByteArray {
        val (nonce, ct) = aesGcmEncrypt(wrappingKey, key, "acp-recovery-wrap|$slotName".toByteArray(Charsets.UTF_8))
        return nonce + ct
    }

    private fun unwrapKey(wrappingKey: ByteArray, wrapped: ByteArray, slotName: String): ByteArray {
        if (wrapped.size != 12 + 32 + 16) throw RecoveryBlobException("a wrapped key slot is malformed; nothing was restored")
        try {
            return aesGcmDecrypt(wrappingKey, wrapped.copyOfRange(0, 12), wrapped.copyOfRange(12, wrapped.size),
                "acp-recovery-wrap|$slotName".toByteArray(Charsets.UTF_8))
        } catch (e: RecoveryBlobException) {
            throw e
        } catch (e: Exception) {
            throw RecoveryBlobException("a key slot failed its integrity check — wrong credential or corrupt blob; nothing was restored")
        }
    }

    private fun unwrapWithPassphrase(slot: JSONObject, passphrase: String): ByteArray {
        val salt: ByteArray
        val wrapped: ByteArray
        val iterations: Int
        try {
            salt = unb64(slot.getString("salt"))
            wrapped = unb64(slot.getString("wrappedKey"))
            iterations = slot.getInt("iterations")
        } catch (e: Exception) {
            // W12-DS P4-F13: JSONException (wrong-typed fields) is
            // translated too — no raw org.json escapes.
            throw RecoveryBlobException("the passphrase slot is malformed; nothing was restored")
        }
        // W12-DS P4-F11: the 600k floor is enforced on import.
        if (iterations < PASSPHRASE_ITERATIONS || iterations > 10_000_000)
            throw RecoveryBlobException("the passphrase slot names an out-of-range iteration count — tampered; nothing was restored")
        val kek = pbkdf2Sha256(passphrase.toByteArray(Charsets.UTF_8), salt, iterations, 32)
        try {
            return unwrapKey(kek, wrapped, "passphrase")
        } catch (e: RecoveryBlobException) {
            throw RecoveryBlobException("the passphrase does not open this blob — wrong passphrase, or the blob is corrupt; nothing was restored")
        } finally {
            kek.fill(0)
        }
    }

    /** PBKDF2-HMAC-SHA256 over the passphrase's UTF-8 bytes — the
     *  exact input .NET's Rfc2898DeriveBytes.Pbkdf2(string, ...) uses,
     *  so passphrases open blobs on both platforms (SecretKeyFactory's
     *  PBEKeySpec char conversion is NOT UTF-8 and is avoided). */
    fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val out = ByteArray(dkLen)
        var produced = 0
        var block = 1
        while (produced < dkLen) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (i in 1 until iterations) {
                u = mac.doFinal(u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val take = minOf(t.size, dkLen - produced)
            System.arraycopy(t, 0, out, produced, take)
            produced += take
            block++
        }
        return out
    }
}

/**
 * X25519 (RFC 7748) via the birational map from Ed25519 —
 * BigInteger Montgomery ladder, mirroring X25519 in
 * Acp.Shared/Security/RecoveryBlob.cs step for step. Pinned against
 * the RFC 7748 §5.2 vectors in the JVM suite (expected outputs
 * verified against an independent implementation during the C20
 * build).
 */
object X25519Recovery {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24: BigInteger = BigInteger.valueOf(121665)
    val BASE_POINT_U: ByteArray = ByteArray(32).also { it[0] = 9 }

    fun raw(scalar: ByteArray, uCoordinate: ByteArray): ByteArray {
        require(scalar.size == 32 && uCoordinate.size == 32) { "X25519 inputs are 32 bytes" }
        val k = decodeLittleEndian(scalar)
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = (k[31].toInt() and 127).toByte()
        k[31] = (k[31].toInt() or 64).toByte()
        val scalarInt = Ed25519.littleEndianToInt(k)
        val x1 = Ed25519.littleEndianToInt(decodeLittleEndian(uCoordinate))
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0
        for (t in 254 downTo 0) {
            val bit = scalarInt.shiftRight(t).and(BigInteger.ONE).toInt()
            swap = swap xor bit
            if (swap == 1) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = bit
            val a = mod(x2.add(z2)); val aa = mod(a.multiply(a))
            val b = mod(x2.subtract(z2)); val bb = mod(b.multiply(b))
            val e = mod(aa.subtract(bb))
            val c = mod(x3.add(z3)); val d = mod(x3.subtract(z3))
            val da = mod(d.multiply(a)); val cb = mod(c.multiply(b))
            x3 = mod(da.add(cb).multiply(da.add(cb)))
            z3 = mod(x1.multiply(mod(da.subtract(cb).multiply(da.subtract(cb)))))
            x2 = mod(aa.multiply(bb))
            z2 = mod(e.multiply(mod(aa.add(mod(A24.multiply(e))))))
        }
        if (swap == 1) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }
        val result = mod(x2.multiply(z2.modPow(P.subtract(BigInteger.TWO), P)))
        return Ed25519.intToLittleEndian(result, 32)
    }

    /** The X25519 scalar for an Ed25519 seed: first half of
     *  SHA-512(seed), unclamped (raw() clamps). */
    fun scalarFromEd25519Seed(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        return MessageDigest.getInstance("SHA-512").digest(seed).copyOf(32)
    }

    /** Ed25519 public key → Montgomery u = (1+y)·(1−y)⁻¹ mod p. */
    fun publicFromEd25519(edPublicKey: ByteArray): ByteArray {
        require(edPublicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        val y = Ed25519.littleEndianToInt(decodeLittleEndian(edPublicKey))
        val numerator = mod(BigInteger.ONE.add(y))
        val denominator = mod(BigInteger.ONE.subtract(y))
        val u = mod(numerator.multiply(denominator.modInverse(P)))
        return Ed25519.intToLittleEndian(u, 32)
    }

    private fun mod(value: BigInteger): BigInteger {
        val r = value.mod(P)
        return if (r.signum() < 0) r.add(P) else r
    }

    private fun decodeLittleEndian(bytes: ByteArray): ByteArray {
        val copy = bytes.copyOf()
        copy[31] = (copy[31].toInt() and 127).toByte()
        return copy
    }
}

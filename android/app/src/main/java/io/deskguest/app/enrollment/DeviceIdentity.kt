package io.deskguest.app.enrollment

import io.deskguest.app.adb.Ed25519
import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * This device's Ed25519 identity (Slice 1: enrollment + identity
 * foundation).
 *
 * Seed = 32 random bytes. Public key derived per RFC 8032 §5.1.5:
 * SHA-512 of the seed, clamp the first half, scalarmult base — built
 * on the existing vector-tested group operations in adb/Ed25519.kt
 * (extended-coordinate add/double/scalarmult, encode/decode,
 * scReduce). Sign/verify follow RFC 8032 §5.1.6/§5.1.7 and fail
 * closed on any malformed input.
 *
 * DeviceId = lowercase hex SHA-256 of the 32-byte public key.
 *
 * Persistence: the seed is stored Base64-encoded and then wrapped
 * with the injected [LineCipher] (the same pattern PairingStore uses
 * for tokens), as a single line in its own identity file — separate
 * from the enrollment roster file. Loading is explicit and lazy:
 * nothing in this file is constructed on any startup path; callers
 * decide when (if ever) to call [load].
 */
class DeviceIdentity private constructor(seed: ByteArray) {

    private val seedBytes: ByteArray = seed.copyOf()

    init {
        require(seedBytes.size == SEED_SIZE) { "Ed25519 seed must be 32 bytes" }
    }

    /** The 32-byte public key. */
    val publicKey: ByteArray by lazy { derivePublicKey(seedBytes) }

    val publicKeyBase64: String
        get() = Base64.getEncoder().encodeToString(publicKey)

    /** Lowercase hex SHA-256 of the 32-byte public key. */
    val deviceId: String by lazy { deviceIdFor(publicKey) }

    // D38 S1-AND F10: the expanded secret (clamped scalar + nonce
    // prefix) is derived ONCE per instance — sign() previously
    // recomputed the public key with a full scalarmultBase on every
    // signature even though the instance caches it.
    private val expandedScalar: BigInteger by lazy {
        Ed25519.littleEndianToInt(clamp(sha512(seedBytes).copyOf(32)))
    }
    private val noncePrefix: ByteArray by lazy { sha512(seedBytes).copyOfRange(32, 64) }

    /** A defensive copy of the seed (for persistence/tests only). */
    fun seedCopy(): ByteArray = seedBytes.copyOf()

    /** RFC 8032 sign: returns the 64-byte signature, deterministic. */
    fun sign(message: ByteArray): ByteArray =
        signCore(expandedScalar, noncePrefix, publicKey, message)

    /** Verify a signature under this identity's public key. */
    fun verify(message: ByteArray, signature: ByteArray): Boolean =
        verify(publicKey, message, signature)

    /**
     * Save the seed wrapped via [cipher] to [file] (tmp + fsync +
     * rename, PairingStore style). The plaintext seed (raw, hex, or
     * Base64) never touches disk when a real cipher is injected.
     *
     * D38 S1-AND F11: overwriting an EXISTING identity file is
     * refused unless [overwrite] is explicitly true — silently
     * replacing a device's root identity is never a side effect.
     * D38 F4: the write is atomic (no direct-write fallback that a
     * crash could leave truncated), and owner-only permissions are
     * applied best-effort.
     */
    fun save(
        file: File, cipher: LineCipher, overwrite: Boolean = false,
        /** W13 P4-F6 remainder closed: saving the root identity
         *  under the PLAINTEXT (identity) cipher is refused unless
         *  the caller explicitly opts in — the decision to store a
         *  seed unwrapped is made at the call site, in the open,
         *  never silently inside save(). Production passes this
         *  only where AtRestCipher's probe fell back AND the
         *  surfaces report the unwrapped state (AtRestCipher.wraps). */
        allowPlaintext: Boolean = false
    ) {
        if (cipher === IdentityLineCipher && !allowPlaintext) {
            throw IllegalStateException(
                "identity save refused: the identity (plaintext) cipher would store the root seed unwrapped — pass allowPlaintext=true only where that fallback is a surfaced, deliberate choice")
        }
        if (file.exists() && !overwrite) {
            throw IllegalStateException("identity file already exists: ${file.name} (pass overwrite=true to replace the root identity)")
        }
        val encoded = Base64.getEncoder().encodeToString(seedBytes)
        val wrapped = cipher.encrypt(encoded)
        val bytes = wrapped.toByteArray(Charsets.UTF_8)
        val parent = file.parentFile
        if (parent != null) {
            val tmp = File(parent, file.name + ".tmp")
            java.io.FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            if (!tmp.renameTo(file)) {
                tmp.delete()
                throw IllegalStateException("identity save: atomic rename failed for ${file.name}")
            }
        } else {
            java.io.FileOutputStream(file).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
        }
        // Best-effort owner-only permissions (a no-op where the
        // platform ignores them, e.g. some test filesystems).
        try {
            file.setReadable(false, false); file.setReadable(true, true)
            file.setWritable(false, false); file.setWritable(true, true)
            file.setExecutable(false, false)
        } catch (_: Exception) {
            // permissions are best-effort; the wrapped form is the protection
        }
    }

    companion object {
        const val SEED_SIZE = 32
        const val PUBLIC_KEY_SIZE = 32
        const val SIGNATURE_SIZE = 64

        fun generate(random: SecureRandom = SecureRandom()): DeviceIdentity {
            val seed = ByteArray(SEED_SIZE).also { random.nextBytes(it) }
            return DeviceIdentity(seed)
        }

        fun fromSeed(seed: ByteArray): DeviceIdentity {
            require(seed.size == SEED_SIZE) { "Ed25519 seed must be 32 bytes" }
            return DeviceIdentity(seed.copyOf())
        }

        /**
         * Load a previously [save]d identity. Returns null on a
         * missing file, a decrypt failure, or malformed content —
         * fail closed, never throws on corrupt/hostile file content.
         */
        fun load(file: File, cipher: LineCipher): DeviceIdentity? {
            return try {
                if (!file.exists()) return null
                val raw = file.readText().trim()
                if (raw.isEmpty()) return null
                // First field if a TSV-style line ever appears; the
                // canonical form is a single wrapped value.
                val field = raw.lineSequence().firstOrNull()?.split('\t')?.firstOrNull() ?: return null
                // D38 S1-AND F3: a field that is not in wrapped form
                // is REFUSED when a wrapping cipher is injected —
                // quietly accepting a plaintext Base64 seed would
                // let anything that can write this file plant a
                // known identity, and would keep a plaintext file
                // from a bug or migration working with no warning.
                // (With IdentityLineCipher, plaintext IS the stored
                // form — that cipher means "no wrapping" by design.)
                val plain = if (cipher.isWrapped(field)) {
                    cipher.decrypt(field) ?: return null
                } else if (cipher === IdentityLineCipher) {
                    field
                } else {
                    return null
                }
                val seed = try {
                    Base64.getDecoder().decode(plain)
                } catch (_: Exception) {
                    return null
                }
                if (seed.size != SEED_SIZE) return null
                DeviceIdentity(seed)
            } catch (_: Exception) {
                null
            }
        }

        /** Lowercase hex SHA-256 of the 32-byte public key. */
        fun deviceIdFor(publicKey: ByteArray): String {
            require(publicKey.size == PUBLIC_KEY_SIZE) { "public key must be 32 bytes" }
            val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
            return digest.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }

        fun derivePublicKey(seed: ByteArray): ByteArray {
            require(seed.size == SEED_SIZE) { "Ed25519 seed must be 32 bytes" }
            val h = sha512(seed)
            val aBytes = clamp(h.copyOf(32))
            val a = Ed25519.littleEndianToInt(aBytes)
            return Ed25519.encode(Ed25519.scalarmultBase(a))
        }

        fun signWithSeed(seed: ByteArray, message: ByteArray): ByteArray {
            require(seed.size == SEED_SIZE) { "Ed25519 seed must be 32 bytes" }
            val h = sha512(seed)
            val a = Ed25519.littleEndianToInt(clamp(h.copyOf(32)))
            val prefix = h.copyOfRange(32, 64)
            val publicKey = Ed25519.encode(Ed25519.scalarmultBase(a))
            return signCore(a, prefix, publicKey, message)
        }

        /** Shared RFC 8032 signing core over an expanded scalar. */
        private fun signCore(a: BigInteger, prefix: ByteArray, publicKey: ByteArray, message: ByteArray): ByteArray {
            val rHash = sha512(prefix + message)
            val r = Ed25519.littleEndianToInt(Ed25519.scReduce(rHash))
            val rEncoded = Ed25519.encode(Ed25519.scalarmultBase(r))
            val kHash = sha512(rEncoded + publicKey + message)
            val k = Ed25519.littleEndianToInt(Ed25519.scReduce(kHash))
            val s = r.add(k.multiply(a)).mod(Ed25519.L)
            return rEncoded + Ed25519.intToLittleEndian(s, 32)
        }

        /**
         * RFC 8032 verify. Fail-closed: false for wrong sizes,
         * non-canonical S (>= L), undecodable points, small-order
         * A or R (D38 S1-AND F5), or any internal error — never
         * throws on malformed input.
         */
        fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            return try {
                if (publicKey.size != PUBLIC_KEY_SIZE) return false
                if (signature.size != SIGNATURE_SIZE) return false
                val rEncoded = signature.copyOfRange(0, 32)
                val sBytes = signature.copyOfRange(32, 64)
                val s = Ed25519.littleEndianToInt(sBytes)
                if (s >= Ed25519.L) return false // (s < 0 is impossible: unsigned decode)
                val aPoint = Ed25519.decode(publicKey) ?: return false
                if (Ed25519.isSmallOrder(aPoint)) return false // D38 F5
                val rPoint = Ed25519.decode(rEncoded) ?: return false
                if (Ed25519.isSmallOrder(rPoint)) return false // D38 F5
                val kHash = sha512(rEncoded + publicKey + message)
                val k = Ed25519.littleEndianToInt(Ed25519.scReduce(kHash))
                val left = Ed25519.encode(Ed25519.scalarmultBase(s))
                val right = Ed25519.encode(
                    Ed25519.addPoints(rPoint, Ed25519.scalarmult(aPoint, k))
                )
                MessageDigest.isEqual(left, right)
            } catch (_: Exception) {
                false
            }
        }

        private fun sha512(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-512").digest(data)

        private fun clamp(aBytes: ByteArray): ByteArray {
            val out = aBytes.copyOf()
            out[0] = (out[0].toInt() and 248).toByte()
            out[31] = (out[31].toInt() and 63).toByte()
            out[31] = (out[31].toInt() or 64).toByte()
            return out
        }
    }
}

package io.agenticcontrol.app.adb

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The pairing channel's cipher (0.4.0), transcribed from AOSP
 * pairing_auth/aes_128_gcm.cpp: AES-128-GCM whose key is
 * HKDF-SHA256(SPAKE2 key material, empty salt,
 * info "adb pairing_auth aes-128-gcm key", 16 bytes). Nonces are 12
 * bytes: a little-endian uint64 sequence number (separate counters
 * for encrypt and decrypt, both starting at 0) followed by 4 zero
 * bytes. Sealed output is ciphertext || 16-byte tag, as EVP_AEAD
 * produces. Validated against a Wycheproof AES-128-GCM vector (via
 * [encryptWithNonce]) and the HKDF RFC 5869 vector in the JVM suite.
 */
class PairingCipher(keyMaterial: ByteArray) {

    private val key: SecretKeySpec = SecretKeySpec(
        Hkdf.sha256(keyMaterial, ByteArray(0), INFO, 16), "AES"
    )
    private var encSequence: Long = 0
    private var decSequence: Long = 0

    fun encrypt(plain: ByteArray): ByteArray {
        val nonce = nonce(encSequence++)
        return gcm(Cipher.ENCRYPT_MODE, key, nonce, plain)
    }

    fun decrypt(sealed: ByteArray): ByteArray? {
        val nonce = nonce(decSequence)
        return try {
            val out = gcm(Cipher.DECRYPT_MODE, key, nonce, sealed)
            decSequence++
            out
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        val INFO: ByteArray = "adb pairing_auth aes-128-gcm key".toByteArray(Charsets.UTF_8)

        fun nonce(sequence: Long): ByteArray {
            val out = ByteArray(12)
            var v = sequence
            for (i in 0 until 8) {
                out[i] = (v and 0xFF).toByte()
                v = v shr 8
            }
            return out
        }

        /** Raw AES-128-GCM seal with an explicit key + nonce (the
         *  JVM suite's vector entry point). */
        fun encryptWithNonce(keyBytes: ByteArray, nonce: ByteArray, plain: ByteArray): ByteArray =
            gcm(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                nonce,
                plain
            )

        private fun gcm(mode: Int, key: SecretKeySpec, nonce: ByteArray, input: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(mode, key, GCMParameterSpec(128, nonce))
            return cipher.doFinal(input)
        }
    }
}

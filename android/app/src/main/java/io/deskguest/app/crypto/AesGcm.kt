package io.deskguest.app.crypto

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * String-at-rest encryption (0.4.0): AES-256-GCM behind a tiny
 * interface so the stores that use it (pairing tokens, the audit log)
 * stay pure and JVM-testable. The Android side supplies a key from the
 * Android Keystore (server/KeystoreKeys.kt); the JVM suite supplies a
 * generated key. The wire form is "v1:" + Base64(iv || ciphertext) —
 * the prefix lets loaders recognise wrapped values and migrate
 * plaintext ones written by older versions.
 */
interface LineCipher {
    fun encrypt(plain: String): String
    fun decrypt(wrapped: String): String?

    /** True when [value] carries the wrapped-form prefix. */
    fun isWrapped(value: String): Boolean = value.startsWith(WRAP_PREFIX)

    companion object {
        const val WRAP_PREFIX = "v1:"
    }
}

/** No encryption: values pass through unchanged. JVM default only. */
object IdentityLineCipher : LineCipher {
    override fun encrypt(plain: String): String = plain
    override fun decrypt(wrapped: String): String? = wrapped
    override fun isWrapped(value: String): Boolean = false
}

class AesGcmLineCipher(private val key: SecretKey) : LineCipher {

    private val random = SecureRandom()

    override fun encrypt(plain: String): String {
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val sealed = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return LineCipher.WRAP_PREFIX +
            Base64.getEncoder().encodeToString(iv + sealed)
    }

    override fun decrypt(wrapped: String): String? {
        if (!isWrapped(wrapped)) return null
        return try {
            val raw = Base64.getDecoder().decode(wrapped.substring(LineCipher.WRAP_PREFIX.length))
            if (raw.size <= 12) return null
            val iv = raw.copyOfRange(0, 12)
            val sealed = raw.copyOfRange(12, raw.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            String(cipher.doFinal(sealed), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        /** A fresh AES-256 key (the JVM suite's stand-in for the Keystore). */
        fun generateKey(): SecretKey =
            KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }
}

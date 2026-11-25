package io.agenticcontrol.app.adb

import java.math.BigInteger
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * The ADB RSA identity encoding (0.4.0), from AOSP adb_auth.h /
 * crypto/rsa_2048_key.cpp: the public key travels as a base64 string
 * of the little-endian struct
 *
 *   uint32 modulus_size_words   (64 for RSA-2048)
 *   uint32 n0inv                (-(n^-1) mod 2^32)
 *   uint8  modulus[256]         (little-endian)
 *   uint8  rr[256]              (R^2 mod n, R = 2^2048, little-endian)
 *   uint32 exponent
 *
 * 524 bytes total for a 2048-bit key. The AUTH signature is
 * RSA PKCS#1 v1.5 with SHA-1 over the 20-byte token (AOSP's
 * RSA_sign(NID_sha1, ...)), i.e. JCA "SHA1withRSA".
 *
 * The JVM suite cross-checks the struct: n0inv * n = -1 (mod 2^32),
 * rr = (2^2048)^2 mod n recomputed independently, and a sign/verify
 * round-trip with the platform provider.
 */
object AdbKey {

    const val RSA_2048_WORDS = 64
    const val RSA_2048_BYTES = 256

    /** The struct bytes for an RSA public key. */
    fun encodePublicKeyStruct(key: RSAPublicKey): ByteArray {
        val n = key.modulus
        val byteCount = (n.bitLength() + 7) / 8
        require(byteCount <= RSA_2048_BYTES) { "modulus too large for the ADB struct" }
        val n0inv = n.modInverse(BigInteger.ONE.shiftLeft(32)).negate()
            .mod(BigInteger.ONE.shiftLeft(32))
        val r = BigInteger.ONE.shiftLeft(32 * RSA_2048_WORDS)
        val rr = r.multiply(r).mod(n)

        val out = ByteArray(4 + 4 + RSA_2048_BYTES + RSA_2048_BYTES + 4)
        writeInt32(out, 0, RSA_2048_WORDS)
        writeInt32(out, 4, n0inv.toInt())
        writeLittleEndian(out, 8, n, RSA_2048_BYTES)
        writeLittleEndian(out, 8 + RSA_2048_BYTES, rr, RSA_2048_BYTES)
        writeInt32(out, 8 + 2 * RSA_2048_BYTES, key.publicExponent.toInt())
        return out
    }

    /** The base64 public-key string the AUTH flow and the pairing
     *  PeerInfo carry. */
    fun publicKeyString(key: RSAPublicKey): String =
        Base64.getEncoder().encodeToString(encodePublicKeyStruct(key))

    /** Sign an AUTH token (20 bytes) with SHA1withRSA. */
    fun signToken(privateKey: PrivateKey, token: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA1withRSA")
        signature.initSign(privateKey)
        signature.update(token)
        return signature.sign()
    }

    private fun writeInt32(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = (value shr 8 and 0xFF).toByte()
        out[offset + 2] = (value shr 16 and 0xFF).toByte()
        out[offset + 3] = (value shr 24 and 0xFF).toByte()
    }

    private fun writeLittleEndian(out: ByteArray, offset: Int, value: BigInteger, length: Int) {
        var v = value
        for (i in 0 until length) {
            out[offset + i] = v.and(BigInteger.valueOf(0xFF)).toByte()
            v = v.shiftRight(8)
        }
    }
}

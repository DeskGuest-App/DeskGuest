package io.deskguest.app.adb

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869): extract with the given salt (an empty salt
 * means HashLen zeros, per the RFC), expand with the given info.
 * Used for the pairing cipher's key derivation (AOSP aes_128_gcm.cpp:
 * HKDF over the SPAKE2 key material, empty salt, info
 * "adb pairing_auth aes-128-gcm key", 16-byte output). Validated
 * against RFC 5869 test case 1 in the JVM suite.
 */
object Hkdf {

    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        val prk = extract.doFinal(ikm)

        val out = ByteArray(length)
        var produced = 0
        var counter = 1
        var previous = ByteArray(0)
        val expand = Mac.getInstance("HmacSHA256")
        while (produced < length) {
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(previous)
            expand.update(info)
            expand.update(counter.toByte())
            previous = expand.doFinal()
            val take = minOf(previous.size, length - produced)
            System.arraycopy(previous, 0, out, produced, take)
            produced += take
            counter++
        }
        return out
    }
}

package io.deskguest.app.adb

import java.security.interfaces.RSAPublicKey
import javax.net.ssl.SSLContext

/**
 * The device's ADB identity (0.4.0): one RSA-2048 keypair whose
 * public half (in the ADB struct encoding) is what pairing hands to
 * the phone's adbd and what the AUTH flow signs with. The Android
 * implementation keeps the private key in the Android Keystore,
 * where it can never be exported.
 */
interface AdbIdentity {
    val rsaPublicKey: RSAPublicKey

    /** The base64 ADB struct encoding of the public key. */
    fun publicKeyString(): String = AdbKey.publicKeyString(rsaPublicKey)

    /** Sign a 20-byte AUTH token (SHA1withRSA). */
    fun signToken(token: ByteArray): ByteArray

    /**
     * A TLS client context presenting this identity's certificate
     * and accepting the peer's certificate as-is. That mirrors the
     * ADB trust model: authorization is decided by the device from
     * the key, not by a CA chain.
     */
    fun sslContext(): SSLContext
}

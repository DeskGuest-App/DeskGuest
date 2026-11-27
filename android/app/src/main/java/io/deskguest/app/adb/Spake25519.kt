package io.deskguest.app.adb

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * SPAKE2 over Edwards25519 exactly as BoringSSL implements it
 * (crypto/curve25519/spake25519.cc) and as Android's pairing uses it
 * (pairing_auth.cpp): the client is Alice, the device is Bob; the
 * password is the pairing-code bytes with the TLS exported keying
 * material appended (that augmentation happens in AdbPairing — this
 * class takes the final password bytes).
 *
 * Protocol, transcribed from the BoringSSL source:
 * - ephemeral scalar: 64 random bytes -> sc_reduce -> x8.
 * - password scalar: SHA-512(password) -> sc_reduce, then the
 *   "password scalar hack": for each set bit among the low 3 bits,
 *   add that multiple of the group order L (making the scalar a
 *   multiple of 8 without changing it mod L).
 * - my message: encode(ephemeral*B + passwordScalar*(M for Alice,
 *   N for Bob)).
 * - shared: ephemeral * (theirMsg - passwordScalar*(N for Alice,
 *   M for Bob)), encoded.
 * - key (64 bytes): SHA-512 over length-prefixed (uint64 LE)
 *   aliceName, bobName, aliceMsg, bobMsg, sharedEncoded,
 *   SHA-512(password).
 *
 * Identity names for ADB pairing include the trailing NUL
 * (pairing_auth.cpp passes sizeof of the C strings): see
 * [ADB_CLIENT_NAME] / [ADB_SERVER_NAME].
 */
class Spake25519(
    val isAlice: Boolean,
    private val myName: ByteArray,
    private val theirName: ByteArray,
    private val randomBytes: (Int) -> ByteArray = { n ->
        ByteArray(n).also { SecureRandom().nextBytes(it) }
    },
    /** Test-only: BoringSSL's ctx flag of the same name. Mixed
     *  hack/no-hack peers must still agree (the hack only adds
     *  multiples of L) — its test matrix checks exactly that. */
    private val disablePasswordScalarHack: Boolean = false
) {
    private var privateScalar: BigInteger? = null
    private var passwordScalar: BigInteger? = null
    private var passwordHash: ByteArray? = null
    private var myMsg: ByteArray? = null
    private var processed = false

    /** Generate our 32-byte message for [password]. */
    fun generateMsg(password: ByteArray): ByteArray {
        check(myMsg == null) { "message already generated" }
        val privateTmp = randomBytes(64)
        val reduced = Ed25519.scReduce(privateTmp)
        val ephemeral = Ed25519.littleEndianToInt(reduced).multiply(BigInteger.valueOf(8))
        privateScalar = ephemeral

        val digest = MessageDigest.getInstance("SHA-512").digest(password)
        passwordHash = digest
        var pwScalar = Ed25519.littleEndianToInt(Ed25519.scReduce(digest))
        // The password-scalar hack (BoringSSL, verbatim logic): add
        // 1x/2x/4x the group order for each set low bit — each check
        // reads the running value, exactly as the C does — so the
        // scalar ends up a multiple of 8 while staying equal mod L.
        if (!disablePasswordScalarHack) {
            if (pwScalar.testBit(0)) pwScalar = pwScalar.add(Ed25519.L)
            if (pwScalar.testBit(1)) pwScalar = pwScalar.add(Ed25519.L.multiply(BigInteger.TWO))
            if (pwScalar.testBit(2)) pwScalar = pwScalar.add(Ed25519.L.multiply(BigInteger.valueOf(4)))
        }
        passwordScalar = pwScalar

        val maskPoint = if (isAlice) Ed25519.POINT_M else Ed25519.POINT_N
        val mask = Ed25519.scalarmult(maskPoint, pwScalar)
        val pub = Ed25519.scalarmultBase(ephemeral)
        val msg = Ed25519.encode(Ed25519.addPoints(pub, mask))
        myMsg = msg
        return msg
    }

    /**
     * Process the peer's 32-byte message and derive the 64-byte key
     * material. Null when the message is not a valid point. One-shot:
     * a context processes exactly one message, like BoringSSL's.
     */
    fun processMsg(theirMsg: ByteArray): ByteArray? {
        val mine = myMsg ?: return null
        if (processed || theirMsg.size != 32) return null
        processed = true
        val qStar = Ed25519.decode(theirMsg) ?: return null
        val peerMaskPoint = if (isAlice) Ed25519.POINT_N else Ed25519.POINT_M
        val peerMask = Ed25519.scalarmult(peerMaskPoint, passwordScalar!!)
        val q = Ed25519.subtract(qStar, peerMask)
        val dh = Ed25519.scalarmult(q, privateScalar!!)
        val dhEncoded = Ed25519.encode(dh)

        val sha = MessageDigest.getInstance("SHA-512")
        fun updateLengthPrefixed(data: ByteArray) {
            val len = ByteArray(8)
            var l = data.size.toLong()
            for (i in 0 until 8) {
                len[i] = (l and 0xFF).toByte()
                l = l shr 8
            }
            sha.update(len)
            sha.update(data)
        }
        // Transcript order is always Alice's name, Bob's name,
        // Alice's message, Bob's message — regardless of our role.
        if (isAlice) {
            updateLengthPrefixed(myName)
            updateLengthPrefixed(theirName)
            updateLengthPrefixed(mine)
            updateLengthPrefixed(theirMsg)
        } else {
            updateLengthPrefixed(theirName)
            updateLengthPrefixed(myName)
            updateLengthPrefixed(theirMsg)
            updateLengthPrefixed(mine)
        }
        updateLengthPrefixed(dhEncoded)
        updateLengthPrefixed(passwordHash!!)
        return sha.digest()
    }

    companion object {
        /** ADB pairing identity names, trailing NUL included
         *  (pairing_auth.cpp uses sizeof of the C strings). */
        val ADB_CLIENT_NAME: ByteArray = "adb pair client".toByteArray(Charsets.UTF_8) + 0.toByte()
        val ADB_SERVER_NAME: ByteArray = "adb pair server".toByteArray(Charsets.UTF_8) + 0.toByte()

        /** A client (Alice) context with the ADB pairing names. */
        fun adbClient(randomBytes: ((Int) -> ByteArray)? = null): Spake25519 =
            if (randomBytes == null) {
                Spake25519(true, ADB_CLIENT_NAME, ADB_SERVER_NAME)
            } else {
                Spake25519(true, ADB_CLIENT_NAME, ADB_SERVER_NAME, randomBytes)
            }

        /** A server (Bob) context with the ADB pairing names. */
        fun adbServer(randomBytes: ((Int) -> ByteArray)? = null): Spake25519 =
            if (randomBytes == null) {
                Spake25519(false, ADB_SERVER_NAME, ADB_CLIENT_NAME)
            } else {
                Spake25519(false, ADB_SERVER_NAME, ADB_CLIENT_NAME, randomBytes)
            }
    }
}

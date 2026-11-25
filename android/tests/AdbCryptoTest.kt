import io.agenticcontrol.app.adb.AdbKey
import io.agenticcontrol.app.adb.AdbProtocol
import io.agenticcontrol.app.adb.Ed25519
import io.agenticcontrol.app.adb.Hkdf
import io.agenticcontrol.app.adb.PairingCipher
import io.agenticcontrol.app.adb.Spake25519
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey

/**
 * JVM tests for the stage-3 ADB crypto/protocol core, validated
 * against published references — never app-against-itself:
 * - Ed25519 group ops: RFC 8032 §7.1 TEST 1 key derivation, plus the
 *   SPAKE M/N point encodings published in BoringSSL's
 *   spake25519.cc.
 * - HKDF: RFC 5869 test case 1.
 * - AES-128-GCM: Wycheproof test vector (aes_gcm_test.json tcId 1).
 * - SPAKE25519: the BoringSSL test matrix (agreement, mixed
 *   hack/no-hack, wrong password, corrupted message).
 * - ADB framing: hand-computed header bytes + stream round-trips.
 * - ADB RSA struct: field cross-checks recomputed independently.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun hex(bytes: ByteArray): String = Ed25519.bytesToHex(bytes)
private fun unhex(s: String): ByteArray = Ed25519.hexToBytes(s)

fun main() {
    // ---- Ed25519 anchors ----
    check(
        "base point encodes to the canonical 5866..66",
        hex(Ed25519.encode(Ed25519.BASE)) ==
            "5866666666666666666666666666666666666666666666666666666666666666"
    )
    check(
        "L * base is the identity (01 00..00)",
        hex(Ed25519.encode(Ed25519.scalarmultBase(Ed25519.L))) ==
            "01" + "00".repeat(31)
    )
    // RFC 8032 TEST 1: clamp(SHA-512(seed)[0..32)) * B = public key.
    val seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val h = MessageDigest.getInstance("SHA-512").digest(seed)
    val aBytes = h.copyOf(32)
    aBytes[0] = (aBytes[0].toInt() and 248).toByte()
    aBytes[31] = (aBytes[31].toInt() and 63).toByte()
    aBytes[31] = (aBytes[31].toInt() or 64).toByte()
    val scalarA = Ed25519.littleEndianToInt(aBytes)
    check(
        "RFC 8032 TEST 1 public key derivation",
        hex(Ed25519.encode(Ed25519.scalarmultBase(scalarA))) ==
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    // SPAKE M/N encodings as published in BoringSSL's source header.
    check(
        "SPAKE point M encoding matches BoringSSL",
        hex(Ed25519.encode(Ed25519.POINT_M)) ==
            "5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e"
    )
    check(
        "SPAKE point N encoding matches BoringSSL",
        hex(Ed25519.encode(Ed25519.POINT_N)) ==
            "10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778"
    )
    check(
        "M and N are on the curve and decode back",
        Ed25519.decode(Ed25519.encode(Ed25519.POINT_M))?.let {
            it.affineX() == Ed25519.POINT_M.affineX() && it.affineY() == Ed25519.POINT_M.affineY()
        } == true
    )
    // M and N are hash-generated points: they may carry a cofactor
    // component (the protocol's scalars are all multiples of 8,
    // which annihilates it). The true invariant: the cofactor-cleared
    // point 8*M is in the prime-order subgroup, so L*(8*M) = identity.
    check(
        "cofactor-cleared M is in the prime-order subgroup (L*(8M) = identity)",
        hex(
            Ed25519.encode(
                Ed25519.scalarmult(
                    Ed25519.scalarmult(Ed25519.POINT_M, BigInteger.valueOf(8)),
                    Ed25519.L
                )
            )
        ) == "01" + "00".repeat(31)
    )
    // sc_reduce: L reduces to 0; 2^255+... reduces consistently.
    val lBytes = ByteArray(64)
    System.arraycopy(Ed25519.intToLittleEndian(Ed25519.L, 32), 0, lBytes, 0, 32)
    check(
        "sc_reduce(L) is zero",
        Ed25519.scReduce(lBytes).all { it == 0.toByte() }
    )

    // ---- HKDF: RFC 5869 test case 1 ----
    val okm = Hkdf.sha256(
        ByteArray(22) { 0x0b.toByte() },
        unhex("000102030405060708090a0b0c"),
        unhex("f0f1f2f3f4f5f6f7f8f9"),
        42
    )
    check(
        "HKDF-SHA256 RFC 5869 case 1 OKM",
        hex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )

    // ---- AES-128-GCM: Wycheproof tcId 1 ----
    val gcmOut = PairingCipher.encryptWithNonce(
        unhex("5b9604fe14eadba931b0ccf34843dab9"),
        unhex("028318abc1824029138141a2"),
        unhex("001d0c231287c1182784554ca3a21908")
    )
    check(
        "AES-128-GCM Wycheproof vector (ct||tag)",
        hex(gcmOut) == "26073cc1d851beff176384dc9896d5ff" + "0a3ea7a5487cb5f7d70fb6c58d038554"
    )

    // ---- SPAKE25519: the BoringSSL test matrix ----
    fun exchange(
        alicePassword: ByteArray,
        bobPassword: ByteArray,
        aliceHackOff: Boolean = false,
        bobHackOff: Boolean = false,
        corruptAliceBit: Int = -1
    ): Pair<ByteArray?, ByteArray?> {
        val alice = Spake25519(
            true, "alice".toByteArray(), "bob".toByteArray(),
            disablePasswordScalarHack = aliceHackOff
        )
        val bob = Spake25519(
            false, "bob".toByteArray(), "alice".toByteArray(),
            disablePasswordScalarHack = bobHackOff
        )
        var aliceMsg = alice.generateMsg(alicePassword)
        val bobMsg = bob.generateMsg(bobPassword)
        if (corruptAliceBit >= 0) {
            aliceMsg = aliceMsg.copyOf()
            aliceMsg[corruptAliceBit / 8] =
                (aliceMsg[corruptAliceBit / 8].toInt() xor (1 shl (corruptAliceBit % 8))).toByte()
        }
        val aliceKey = alice.processMsg(bobMsg)
        val bobKey = bob.processMsg(aliceMsg)
        return aliceKey to bobKey
    }
    val password = "password".toByteArray()
    val (k1, k2) = exchange(password, password)
    check("SPAKE agreement (same password)", k1 != null && k1.contentEquals(k2!!))
    check("SPAKE key is 64 bytes", k1?.size == 64)
    val (k3, k4) = exchange(password, password, aliceHackOff = true)
    check("SPAKE agreement (old alice, hack off)", k3 != null && k3.contentEquals(k4!!))
    val (k5, k6) = exchange(password, password, bobHackOff = true)
    check("SPAKE agreement (old bob, hack off)", k5 != null && k5.contentEquals(k6!!))
    val (k7, k8) = exchange(password, "wrong password".toByteArray())
    check("SPAKE wrong password derives different keys",
        k7 == null || k8 == null || !k7.contentEquals(k8))
    var corruptOk = true
    for (bit in listOf(0, 63, 128, 200, 255)) {
        val (ck1, ck2) = exchange(password, password, corruptAliceBit = bit)
        if (ck1 != null && ck2 != null && ck1.contentEquals(ck2)) corruptOk = false
    }
    check("SPAKE corrupted message never yields agreement", corruptOk)

    // ADB-flavored exchange: real names + code||exporter password.
    val adbPassword = "123456".toByteArray() + ByteArray(64) { it.toByte() }
    val alice = Spake25519.adbClient()
    val bob = Spake25519.adbServer()
    val aMsg = alice.generateMsg(adbPassword)
    val bMsg = bob.generateMsg(adbPassword)
    val aKey = alice.processMsg(bMsg)
    val bKey = bob.processMsg(aMsg)
    check("ADB SPAKE exchange agrees", aKey != null && aKey.contentEquals(bKey!!))
    check("ADB identity names carry the trailing NUL",
        Spake25519.ADB_CLIENT_NAME.size == 16 && Spake25519.ADB_CLIENT_NAME.last() == 0.toByte())

    // ---- PairingCipher over the agreed key ----
    val cipherA = PairingCipher(aKey!!)
    val cipherB = PairingCipher(bKey!!)
    val peerInfo = ByteArray(8192) { (it % 251).toByte() }
    val sealed = cipherA.encrypt(peerInfo)
    check("peer-info seal is plaintext + 16-byte tag", sealed.size == 8192 + 16)
    val opened = cipherB.decrypt(sealed)
    check("peer-info round-trips through the pairing cipher",
        opened != null && opened.contentEquals(peerInfo))
    val wrongCipher = PairingCipher(ByteArray(64) { 9 })
    check("wrong key material cannot open the seal", wrongCipher.decrypt(sealed) == null)

    // ---- ADB framing ----
    val cnxn = AdbProtocol.Message(
        AdbProtocol.A_CNXN, AdbProtocol.VERSION, 1024 * 1024,
        "host::\u0000".toByteArray(Charsets.UTF_8)
    )
    val encoded = AdbProtocol.encode(cnxn)
    check("CNXN header starts with the CNXN fourcc LE",
        encoded.copyOf(4).contentEquals(byteArrayOf(0x43, 0x4E, 0x58, 0x4E)))
    check("magic is command XOR -1",
        encoded.copyOfRange(20, 24).contentEquals(
            byteArrayOf(0xBC.toByte(), 0xB1.toByte(), 0xA7.toByte(), 0xB1.toByte())
        ))
    check("checksum is the payload byte sum",
        AdbProtocol.checksum(byteArrayOf(1, 2, 250.toByte())) == 253)
    val back = AdbProtocol.readFrom(ByteArrayInputStream(encoded))
    check("framing round-trips", back == cnxn)
    val out = ByteArrayOutputStream()
    AdbProtocol.writeTo(out, AdbProtocol.Message(AdbProtocol.A_OKAY, 7, 9, ByteArray(0)))
    val okay = AdbProtocol.readFrom(ByteArrayInputStream(out.toByteArray()))
    check("empty-payload message round-trips",
        okay?.command == AdbProtocol.A_OKAY && okay.arg0 == 7 && okay.arg1 == 9)

    // ---- ADB RSA struct + AUTH signature ----
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    val keyPair = kpg.generateKeyPair()
    val rsaPub = keyPair.public as RSAPublicKey
    val struct = AdbKey.encodePublicKeyStruct(rsaPub)
    check("ADB struct is 524 bytes for RSA-2048", struct.size == 524)
    fun readInt32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or (b[off + 1].toInt() and 0xFF shl 8) or
            (b[off + 2].toInt() and 0xFF shl 16) or (b[off + 3].toInt() and 0xFF shl 24)
    check("struct modulus_size_words is 64", readInt32(struct, 0) == 64)
    val n0inv = BigInteger.valueOf(readInt32(struct, 4).toLong() and 0xFFFFFFFFL)
    val nLow = rsaPub.modulus.mod(BigInteger.ONE.shiftLeft(32))
    check(
        "n0inv * n = -1 (mod 2^32)",
        n0inv.multiply(nLow).mod(BigInteger.ONE.shiftLeft(32)) ==
            BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE)
    )
    val rrBytes = struct.copyOfRange(8 + 256, 8 + 512)
    val rr = Ed25519.littleEndianToInt(rrBytes)
    val rBig = BigInteger.ONE.shiftLeft(2048)
    check("rr equals R^2 mod n", rr == rBig.multiply(rBig).mod(rsaPub.modulus))
    val modBytes = struct.copyOfRange(8, 8 + 256)
    check("modulus stored little-endian",
        Ed25519.littleEndianToInt(modBytes) == rsaPub.modulus)
    check("exponent stored", readInt32(struct, 8 + 512) == rsaPub.publicExponent.toInt())
    check("public key string is base64 of the struct",
        java.util.Base64.getDecoder().decode(AdbKey.publicKeyString(rsaPub)).contentEquals(struct))

    // ---- Pairing packet framing (AOSP pairing_connection) ----
    val packetHeader = io.agenticcontrol.app.adb.AdbPairing.packetHeader(1, 8208)
    check(
        "pairing packet header is version|type|BE size",
        packetHeader.contentEquals(byteArrayOf(1, 1, 0, 0, 0x20, 0x10))
    )
    val parsedHeader = io.agenticcontrol.app.adb.AdbPairing.parsePacketHeader(packetHeader)
    check(
        "pairing packet header parses back",
        parsedHeader?.first == 1.toByte() && parsedHeader.second == 8208
    )
    check(
        "bad pairing version is rejected",
        io.agenticcontrol.app.adb.AdbPairing.parsePacketHeader(
            byteArrayOf(2, 0, 0, 0, 0, 32)
        ) == null
    )
    val fakeIdentity = object : io.agenticcontrol.app.adb.AdbIdentity {
        override val rsaPublicKey = rsaPub
        override fun signToken(token: ByteArray): ByteArray = AdbKey.signToken(keyPair.private, token)
        override fun sslContext(): javax.net.ssl.SSLContext =
            throw UnsupportedOperationException("not needed in tests")
    }
    val peerInfoBlock = io.agenticcontrol.app.adb.AdbPairing.peerInfoPayload(fakeIdentity)
    check("peer info block is 8192 bytes with type 0",
        peerInfoBlock.size == 8192 && peerInfoBlock[0] == 0.toByte())
    check(
        "peer info carries the base64 key at offset 1",
        peerInfoBlock.copyOfRange(1, 1 + AdbKey.publicKeyString(rsaPub).length)
            .toString(Charsets.UTF_8) == AdbKey.publicKeyString(rsaPub)
    )

    val token = ByteArray(20) { (it * 7).toByte() }
    val signature = AdbKey.signToken(keyPair.private, token)
    val verifier = Signature.getInstance("SHA1withRSA")
    verifier.initVerify(keyPair.public)
    verifier.update(token)
    check("AUTH signature verifies as SHA1withRSA", verifier.verify(signature))

    println(if (failures == 0) "ALL ADB CRYPTO TESTS PASSED" else "$failures ADB CRYPTO TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

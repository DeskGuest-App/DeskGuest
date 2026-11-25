package io.agenticcontrol.app.adb

import java.io.InputStream
import java.io.OutputStream
import javax.net.ssl.SSLSocket

/**
 * The wireless-debugging pairing exchange (0.4.0), transcribed from
 * AOSP's pairing_connection.cpp and pairing_auth.cpp:
 *
 *   1. TLS 1.3 to the pairing endpoint; both sides present
 *      self-signed certificates, either is accepted.
 *   2. Export 64 bytes of keying material, label "adb-label\0".
 *   3. SPAKE2 (BoringSSL variant) with password =
 *      code bytes || exported material. Packets carry a 6-byte
 *      header: version(1) byte, type byte, payload size as a
 *      big-endian uint32. Type 0 = SPAKE2 message, type 1 = peer
 *      info.
 *   4. Peer info is an 8192-byte block: type byte 0 (RSA public
 *      key) + the base64 ADB public key, zero-padded — sealed with
 *      the pairing cipher. The device answers with its own sealed
 *      peer info; a successful open proves the code was right.
 */
object AdbPairing {

    data class Result(
        val success: Boolean,
        val message: String,
        /** bd-and-ui F3 fix: the device's ADB public key, parsed
         *  out of its peer-info block. Before this fix the block
         *  was decrypted, size-checked, and THROWN AWAY — nothing
         *  bound the pairing to the device that later connects.
         *  Callers can now persist this and compare it at shell
         *  connect time. Null when the block is not an RSA-key
         *  peer info. */
        val devicePublicKey: String? = null
    )

    /** Parse the device's key out of a decrypted peer-info block:
     *  type byte 0 (RSA public key) + base64 key text, NUL- or
     *  zero-padded. Null for any other shape. */
    fun parsePeerInfoKey(theirs: ByteArray): String? {
        if (theirs.size != PEER_INFO_SIZE || theirs[0] != 0.toByte()) return null
        val text = theirs.copyOfRange(1, theirs.size)
            .toString(Charsets.UTF_8)
            .trimEnd('\u0000', ' ')
        if (text.isBlank() || text.any { it.isISOControl() }) return null
        return text
    }

    const val PACKET_VERSION: Byte = 1
    const val TYPE_SPAKE2_MSG: Byte = 0
    const val TYPE_PEER_INFO: Byte = 1
    const val PEER_INFO_SIZE = 8192

    fun packetHeader(type: Byte, payloadSize: Int): ByteArray = byteArrayOf(
        PACKET_VERSION,
        type,
        (payloadSize shr 24 and 0xFF).toByte(),
        (payloadSize shr 16 and 0xFF).toByte(),
        (payloadSize shr 8 and 0xFF).toByte(),
        (payloadSize and 0xFF).toByte()
    )

    /** Parse a 6-byte packet header: (type, payloadSize) or null. */
    fun parsePacketHeader(header: ByteArray): Pair<Byte, Int>? {
        if (header.size != 6 || header[0] != PACKET_VERSION) return null
        val size = (header[2].toInt() and 0xFF shl 24) or
            (header[3].toInt() and 0xFF shl 16) or
            (header[4].toInt() and 0xFF shl 8) or
            (header[5].toInt() and 0xFF)
        return header[1] to size
    }

    /** The PeerInfo block carrying our RSA public key. */
    fun peerInfoPayload(identity: AdbIdentity): ByteArray {
        val block = ByteArray(PEER_INFO_SIZE)
        block[0] = 0 // ADB_RSA_PUB_KEY
        val keyBytes = identity.publicKeyString().toByteArray(Charsets.UTF_8)
        System.arraycopy(keyBytes, 0, block, 1, minOf(keyBytes.size, PEER_INFO_SIZE - 1))
        return block
    }

    fun pair(
        host: String,
        pairingPort: Int,
        code: String,
        identity: AdbIdentity,
        exporter: TlsExporter = AndroidTlsExporter,
        timeoutMs: Int = 15_000
    ): Result {
        var socket: SSLSocket? = null
        return try {
            val ssl = identity.sslContext().socketFactory
                .createSocket(host, pairingPort) as SSLSocket
            socket = ssl
            ssl.soTimeout = timeoutMs
            ssl.startHandshake()

            val exported = exporter.export(ssl, AndroidTlsExporter.ADB_LABEL, 64)
                ?: return Result(
                    false,
                    "Pairing cannot run on this Android build: the TLS exporter " +
                        "(keying-material export) is not reachable from the app, and " +
                        "the pairing exchange requires it. Nothing was paired."
                )
            val password = code.toByteArray(Charsets.UTF_8) + exported

            val out = ssl.getOutputStream()
            val inp = ssl.getInputStream()
            val spake = Spake25519.adbClient()
            val myMsg = spake.generateMsg(password)
            writePacket(out, TYPE_SPAKE2_MSG, myMsg)

            val (type, payload) = readPacket(inp)
                ?: return Result(false, "The pairing endpoint closed the connection.")
            if (type != TYPE_SPAKE2_MSG || payload.size != 32) {
                return Result(false, "Unexpected pairing response from the device.")
            }
            val keyMaterial = spake.processMsg(payload)
                ?: return Result(false, "The device's pairing message was not a valid point.")
            val cipher = PairingCipher(keyMaterial)

            writePacket(out, TYPE_PEER_INFO, cipher.encrypt(peerInfoPayload(identity)))

            val (infoType, sealed) = readPacket(inp)
                ?: return Result(false, "The device did not answer with its peer info.")
            if (infoType != TYPE_PEER_INFO) {
                return Result(false, "Unexpected pairing response from the device.")
            }
            val theirs = cipher.decrypt(sealed)
                ?: return Result(
                    false,
                    "The device could not open our peer info — the pairing code " +
                        "did not match. Check the code and try again."
                )
            if (theirs.size != PEER_INFO_SIZE) {
                return Result(false, "The device's peer info had an unexpected size.")
            }
            Result(true, "Paired. The device now trusts this app's ADB key.",
                devicePublicKey = parsePeerInfoKey(theirs))
        } catch (e: Exception) {
            Result(false, "Pairing failed: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun writePacket(out: OutputStream, type: Byte, payload: ByteArray) {
        out.write(packetHeader(type, payload.size))
        out.write(payload)
        out.flush()
    }

    private fun readPacket(inp: InputStream): Pair<Byte, ByteArray>? {
        val header = readFully(inp, 6) ?: return null
        val (type, size) = parsePacketHeader(header) ?: return null
        if (size < 0 || size > 64 * 1024) return null
        val payload = readFully(inp, size) ?: return null
        return type to payload
    }

    private fun readFully(inp: InputStream, count: Int): ByteArray? {
        val out = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = inp.read(out, read, count - read)
            if (n < 0) return null
            read += n
        }
        return out
    }
}

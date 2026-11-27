package io.deskguest.app.adb

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * The ADB wire protocol (0.4.0), from AOSP's adb.h and protocol.txt:
 * a 24-byte header of six little-endian uint32s — command, arg0,
 * arg1, payload length, payload checksum (the simple sum of payload
 * bytes), and magic (command XOR 0xFFFFFFFF) — followed by the
 * payload. Command constants are the ASCII fourccs as uint32 LE.
 *
 * Pure byte logic: the JVM suite round-trips messages and checks the
 * header against hand-computed bytes.
 */
object AdbProtocol {

    const val A_SYNC = 0x434e5953
    const val A_CNXN = 0x4e584e43
    const val A_STLS = 0x534C5453 // bd-and-ui F1: "STLS" — the TLS-upgrade command
    const val A_AUTH = 0x48545541
    const val A_OPEN = 0x4e45504f
    const val A_OKAY = 0x59414b4f
    const val A_CLSE = 0x45534c43
    const val A_WRTE = 0x45545257

    /** Protocol version both sides advertise in CNXN (A_VERSION). */
    const val VERSION = 0x01000001

    /** Payload ceiling: v2 devices allow 1 MiB; never send more. */
    const val MAX_PAYLOAD = 1024 * 1024

    const val AUTH_TOKEN = 1
    const val AUTH_SIGNATURE = 2
    const val AUTH_RSAPUBLICKEY = 3

    const val HEADER_SIZE = 24

    data class Message(
        val command: Int,
        val arg0: Int,
        val arg1: Int,
        val payload: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Message) return false
            return command == other.command && arg0 == other.arg0 &&
                arg1 == other.arg1 && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            var result = command
            result = 31 * result + arg0
            result = 31 * result + arg1
            result = 31 * result + payload.contentHashCode()
            return result
        }
    }

    fun checksum(payload: ByteArray): Int {
        var sum = 0
        for (b in payload) sum += b.toInt() and 0xFF
        return sum
    }

    fun encode(message: Message): ByteArray {
        val out = ByteArray(HEADER_SIZE + message.payload.size)
        writeInt(out, 0, message.command)
        writeInt(out, 4, message.arg0)
        writeInt(out, 8, message.arg1)
        writeInt(out, 12, message.payload.size)
        writeInt(out, 16, checksum(message.payload))
        writeInt(out, 20, message.command xor -1)
        System.arraycopy(message.payload, 0, out, HEADER_SIZE, message.payload.size)
        return out
    }

    fun writeTo(out: OutputStream, message: Message) {
        out.write(encode(message))
        out.flush()
    }

    /** Read one message; null on a clean EOF before the header. */
    fun readFrom(input: InputStream): Message? {
        val header = ByteArray(HEADER_SIZE)
        var read = 0
        while (read < HEADER_SIZE) {
            val n = input.read(header, read, HEADER_SIZE - read)
            if (n < 0) {
                if (read == 0) return null
                throw EOFException("EOF inside ADB header")
            }
            read += n
        }
        val command = readInt(header, 0)
        val arg0 = readInt(header, 4)
        val arg1 = readInt(header, 8)
        val length = readInt(header, 12)
        val check = readInt(header, 16)
        val magic = readInt(header, 20)
        if (magic != (command xor -1)) {
            throw IllegalStateException("ADB magic mismatch")
        }
        if (length < 0 || length > MAX_PAYLOAD) {
            throw IllegalStateException("ADB payload length out of range: $length")
        }
        val payload = ByteArray(length)
        var got = 0
        while (got < length) {
            val n = input.read(payload, got, length - got)
            if (n < 0) throw EOFException("EOF inside ADB payload")
            got += n
        }
        if (checksum(payload) != check) {
            throw IllegalStateException("ADB checksum mismatch")
        }
        return Message(command, arg0, arg1, payload)
    }

    private fun writeInt(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = (value shr 8 and 0xFF).toByte()
        out[offset + 2] = (value shr 16 and 0xFF).toByte()
        out[offset + 3] = (value shr 24 and 0xFF).toByte()
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            (bytes[offset + 1].toInt() and 0xFF shl 8) or
            (bytes[offset + 2].toInt() and 0xFF shl 16) or
            (bytes[offset + 3].toInt() and 0xFF shl 24)
}

package io.deskguest.app.adb

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

/**
 * A minimal ADB client: connects to the phone's adbd and runs
 * `shell:` streams to completion. One stream at a time — exec,
 * connect and close are @Synchronized (bd-and-ui F9: the old
 * "the tool layer serializes calls" doc was not enforced here).
 *
 * bd-and-ui F1 fix (2026-11-22): the connect sequence now follows
 * real adbd. The connect port starts in PLAINTEXT: the client
 * sends CNXN, adbd answers A_STLS, the client replies A_STLS,
 * and only then is TLS layered over the SAME socket
 * (SSLSocketFactory.createSocket(raw, host, port, true)) and
 * CNXN re-sent inside the tunnel. The old code wrapped the raw
 * socket in TLS before any CNXN (adbd received a ClientHello
 * where it expected an ADB header) and threw on STLS in the
 * plain path — both connect modes failed against a real device.
 * There is no fake-adbd transcript test in the old suite; the
 * JVM suite now replays a scripted STLS transcript through the
 * [transportFactory] seam.
 *
 * bd-and-ui F3 (partial): the plain (non-TLS-upgrading) path is
 * refused for non-loopback hosts — a cleartext shell channel
 * over the LAN is not offered. (Device-certificate pinning for
 * the TLS leg is a named remainder: adbd's TLS certificate is
 * not the peer-info key, and this build extracts + returns the
 * peer-info key at pairing time as the first step.)
 *
 * Stream rules follow protocol.txt: OPEN waits for OKAY (which
 * carries the peer's stream id), WRTE must be answered with OKAY,
 * and the stream ends when the peer sends CLSE, which we echo.
 */
class AdbClient(private val identity: AdbIdentity) {

    class AdbException(message: String) : Exception(message)

    /** One connection leg: byte streams plus the TLS upgrade.
     *  The production leg wraps a Socket; the JVM suite wraps
     *  in-memory pipes and records that the upgrade happened. */
    interface Transport {
        val input: InputStream
        val output: OutputStream
        var readTimeoutMs: Int
        /** Layer TLS over the existing connection (post-STLS). */
        fun upgradeToTls(): Transport
        fun close()
    }

    private class SocketTransport(
        private val socket: Socket,
        private val identity: AdbIdentity,
        private val host: String,
        private val port: Int
    ) : Transport {
        override val input: InputStream get() = socket.getInputStream()
        override val output: OutputStream get() = socket.getOutputStream()
        override var readTimeoutMs: Int
            get() = socket.soTimeout
            set(value) { socket.soTimeout = value }
        override fun upgradeToTls(): Transport {
            val ssl = identity.sslContext().socketFactory
                .createSocket(socket, host, port, true) as SSLSocket
            ssl.soTimeout = socket.soTimeout
            ssl.startHandshake()
            return SocketTransport(ssl, identity, host, port)
        }
        override fun close() { try { socket.close() } catch (_: Exception) {} }
    }

    /** Test seam: replaces the socket leg. Null in production. */
    var transportFactory: ((String, Int) -> Transport)? = null

    private var transport: Transport? = null

    @Volatile
    var deviceBanner: String = ""
        private set

    val isConnected: Boolean
        get() = transport != null

    @Synchronized
    fun connect(host: String, port: Int, useTls: Boolean, timeoutMs: Int = 12_000) {
        close()
        if (!useTls && !isLoopbackHost(host)) {
            throw AdbException(
                "refused: a plain (non-TLS) ADB connect is only allowed to loopback — " +
                    "'$host' would carry a cleartext shell channel over the network")
        }
        val leg = transportFactory?.invoke(host, port) ?: run {
            val raw = Socket(host, port)
            raw.soTimeout = timeoutMs
            SocketTransport(raw, identity, host, port)
        }
        transport = leg
        try {
            handshake(timeoutMs)
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    private fun isLoopbackHost(host: String): Boolean = try {
        InetAddress.getByName(host).isLoopbackAddress
    } catch (_: Exception) { host == "localhost" }

    private fun handshake(timeoutMs: Int) {
        sendCnxn()
        val deadline = System.currentTimeMillis() + timeoutMs
        // bd-and-ui F4 fix: adbd answers EVERY rejected signature
        // with another AUTH TOKEN — the old code signed every
        // TOKEN, so the RSAPUBLICKEY branch was unreachable and an
        // unauthorised key looped until "handshake timed out".
        // The state machine is: 1st TOKEN → signature; 2nd TOKEN →
        // public key (the device then shows "Allow debugging?");
        // 3rd TOKEN → fail with that instruction.
        var sentSignature = false
        var sentPublicKey = false
        var upgraded = false
        while (System.currentTimeMillis() < deadline) {
            val msg = read() ?: throw AdbException("connection closed during handshake")
            when (msg.command) {
                AdbProtocol.A_CNXN -> {
                    deviceBanner = msg.payload.toString(Charsets.UTF_8).trimEnd('\u0000')
                    return
                }
                AdbProtocol.A_STLS -> {
                    if (upgraded) throw AdbException("device asked for a second TLS upgrade")
                    upgraded = true
                    send(AdbProtocol.Message(AdbProtocol.A_STLS, AdbProtocol.VERSION, 0, ByteArray(0)))
                    val current = transport ?: throw AdbException("not connected")
                    val tls = current.upgradeToTls()
                    transport = tls
                    sendCnxn() // CNXN is re-sent inside the tunnel
                }
                AdbProtocol.A_AUTH -> {
                    if (msg.arg0 == AdbProtocol.AUTH_TOKEN) {
                        when {
                            !sentSignature -> {
                                sentSignature = true
                                val signature = identity.signToken(msg.payload)
                                send(AdbProtocol.Message(AdbProtocol.A_AUTH, AdbProtocol.AUTH_SIGNATURE, 0, signature))
                            }
                            !sentPublicKey -> {
                                sentPublicKey = true
                                send(AdbProtocol.Message(
                                    AdbProtocol.A_AUTH, AdbProtocol.AUTH_RSAPUBLICKEY, 0,
                                    (identity.publicKeyString() + "\u0000").toByteArray(Charsets.UTF_8)))
                            }
                            else -> throw AdbException(
                                "the device keeps asking for authentication — if a prompt appeared, " +
                                    "approve this app's key on the device (\"Allow debugging?\") and reconnect")
                        }
                    } else if (!sentPublicKey) {
                        sentPublicKey = true
                        send(AdbProtocol.Message(
                            AdbProtocol.A_AUTH, AdbProtocol.AUTH_RSAPUBLICKEY, 0,
                            (identity.publicKeyString() + "\u0000").toByteArray(Charsets.UTF_8)))
                    } else {
                        throw AdbException("device rejected the ADB identity key")
                    }
                }
                else -> throw AdbException("unexpected handshake message ${msg.command}")
            }
        }
        throw AdbException("handshake timed out")
    }

    private fun sendCnxn() {
        send(
            AdbProtocol.Message(
                AdbProtocol.A_CNXN, AdbProtocol.VERSION, AdbProtocol.MAX_PAYLOAD,
                "host::features=shell_v2\u0000".toByteArray(Charsets.UTF_8)
            )
        )
    }

    /** Run one shell stream to completion and return its output.
     *  Output is capped at [MAX_OUTPUT_BYTES] (bd-and-ui F9): the
     *  bytes accumulate raw and decode ONCE at the end, so a
     *  multibyte UTF-8 character split across WRTE frames is no
     *  longer mangled; past the cap the stream is drained (the
     *  protocol stays in sync) and the result is marked
     *  truncated. On timeout the stream is CLSEd before throwing. */
    @Synchronized
    fun exec(command: String, timeoutMs: Long = 20_000): String {
        val leg = transport ?: throw AdbException("not connected")
        val previousTimeout = leg.readTimeoutMs
        leg.readTimeoutMs = 5_000
        val localId = (System.nanoTime() and 0x3FFFFFFF).toInt().coerceAtLeast(1)
        var remoteId = -1
        try {
            send(
                AdbProtocol.Message(
                    AdbProtocol.A_OPEN, localId, 0,
                    "shell:$command\u0000".toByteArray(Charsets.UTF_8)
                )
            )
            val deadline = System.currentTimeMillis() + timeoutMs
            val acc = ByteArrayOutputStream()
            var truncated = false
            while (System.currentTimeMillis() < deadline) {
                val msg = try {
                    AdbProtocol.readFrom(leg.input)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                } ?: throw AdbException("connection closed during shell stream")
                when {
                    msg.command == AdbProtocol.A_OKAY && msg.arg1 == localId && remoteId < 0 -> {
                        remoteId = msg.arg0
                    }
                    msg.command == AdbProtocol.A_WRTE && msg.arg1 == localId -> {
                        if (acc.size() + msg.payload.size <= MAX_OUTPUT_BYTES) {
                            acc.write(msg.payload)
                        } else {
                            truncated = true // drain without storing
                        }
                        send(AdbProtocol.Message(AdbProtocol.A_OKAY, localId, msg.arg0, ByteArray(0)))
                    }
                    msg.command == AdbProtocol.A_CLSE && msg.arg1 == localId -> {
                        send(AdbProtocol.Message(AdbProtocol.A_CLSE, localId, msg.arg0, ByteArray(0)))
                        val text = acc.toByteArray().toString(Charsets.UTF_8)
                        return if (truncated) text + "\n[output truncated at $MAX_OUTPUT_BYTES bytes]" else text
                    }
                    msg.command == AdbProtocol.A_CLSE -> {
                        // A stream we do not own: echo its close.
                        send(AdbProtocol.Message(AdbProtocol.A_CLSE, msg.arg1, msg.arg0, ByteArray(0)))
                    }
                    else -> {
                        // Ignore anything else (SYNC, stray OKAYs).
                    }
                }
            }
            // Timeout: close the stream before throwing (F9 — the
            // old code left it open on the device).
            try {
                send(AdbProtocol.Message(AdbProtocol.A_CLSE, localId, if (remoteId >= 0) remoteId else 0, ByteArray(0)))
            } catch (_: Exception) { /* the channel may already be dead */ }
            throw AdbException("shell command timed out after ${timeoutMs}ms")
        } finally {
            try { leg.readTimeoutMs = previousTimeout } catch (_: Exception) {}
        }
    }

    private fun send(message: AdbProtocol.Message) {
        val leg = transport ?: throw AdbException("not connected")
        AdbProtocol.writeTo(leg.output, message)
    }

    private fun read(): AdbProtocol.Message? {
        val leg = transport ?: throw AdbException("not connected")
        return AdbProtocol.readFrom(leg.input)
    }

    @Synchronized
    fun close() {
        try {
            transport?.close()
        } catch (_: Exception) {
        }
        transport = null
        deviceBanner = ""
    }

    companion object {
        const val MAX_OUTPUT_BYTES = 4 * 1024 * 1024
    }
}

/** Endpoint-candidate rule for discovery (bd-and-ui F3): an
 *  address may be offered as a wireless-debugging endpoint only
 *  when it is loopback or one of this device's own interface
 *  addresses — the adbd endpoints live on this device. Pure, so
 *  the JVM suite pins it; AdbDiscovery delegates here. */
object AdbEndpoints {
    fun isOwnAddress(address: String, ownAddresses: Set<String>): Boolean =
        address == "127.0.0.1" || address == "::1" || address in ownAddresses
}

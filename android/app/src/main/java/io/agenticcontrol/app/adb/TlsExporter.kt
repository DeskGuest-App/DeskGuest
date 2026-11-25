package io.agenticcontrol.app.adb

import javax.net.ssl.SSLSocket

/**
 * TLS exported keying material (RFC 5705): the pairing exchange
 * appends 64 exported bytes (label "adb-label" with its trailing
 * NUL, per AOSP tls_connection.cpp) to the pairing code before
 * SPAKE2. The standard JSSE API does not expose the exporter;
 * Conscrypt sockets do, through a method the platform does not put
 * in the SDK. [AndroidTlsExporter] reaches it reflectively and
 * returns null when the platform refuses — pairing then reports
 * that honestly instead of pretending to pair.
 */
interface TlsExporter {
    fun export(socket: SSLSocket, label: String, length: Int): ByteArray?
}

object AndroidTlsExporter : TlsExporter {

    /** The AOSP exporter label, trailing NUL included. */
    const val ADB_LABEL: String = "adb-label\u0000"

    override fun export(socket: SSLSocket, label: String, length: Int): ByteArray? {
        // Direct socket method (Conscrypt's OpenSSLSocketImpl).
        try {
            val method = socket.javaClass.getMethod(
                "exportKeyingMaterial",
                String::class.java,
                ByteArray::class.java,
                Int::class.javaPrimitiveType
            )
            (method.invoke(socket, label, null, length) as? ByteArray)?.let { return it }
        } catch (_: Exception) {
        }
        // Session-based variant some builds expose.
        try {
            val session = socket.session
            val method = session.javaClass.getMethod(
                "exportKeyingMaterial",
                String::class.java,
                ByteArray::class.java,
                Int::class.javaPrimitiveType
            )
            (method.invoke(session, label, null, length) as? ByteArray)?.let { return it }
        } catch (_: Exception) {
        }
        return null
    }
}

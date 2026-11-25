package io.agenticcontrol.app.server

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Minimal HTTP transport for [McpCore] (SPEC §4.3): one fixed port,
 * POST /mcp for JSON-RPC, GET /health for the wizard's self-check,
 * and GET /mcp with an SSE Accept header for session-state events.
 * Hand-rolled on ServerSocket — no external server library, nothing
 * to audit beyond this file. Request bodies are capped; connections
 * are handled on a small fixed pool.
 *
 * 0.4.0 hardening: the server binds ONLY the loopback and the
 * phone's Tailscale addresses (100.64.0.0/10) — never 0.0.0.0, so
 * the control channel is not offered to the whole LAN. Any request
 * carrying an Origin header is refused (browsers send Origin;
 * MCP clients do not — this kills drive-by CSRF / DNS-rebinding
 * from a web page), and the Host header must name loopback or one
 * of the bound addresses. [rebind] re-evaluates the address set
 * when the network changes (ControlService's NetworkCallback).
 */
class McpHttpServer(
    private val core: McpCore,
    private val port: Int = PORT,
    private val addressProvider: () -> List<InetAddress> = { defaultBindAddresses() }
) {
    /** Drives the accept loops. Set before listeners open, cleared
     *  before they close — but on its own it is NOT the truth about
     *  the server: see [isRunning]. */
    @Volatile
    private var accepting = false
    /** W98 / S09(b): each listener carries the connection-path id
     *  a connection accepted on it ARRIVED over (classified from
     *  the address it binds — see [openListeners]), handed to
     *  McpCore on every request so the per-pairing connection-path
     *  setting is enforced at the choke point with the real
     *  arrival, never a client claim. */
    private val listeners = mutableListOf<Pair<ServerSocket, String?>>()
    private val pool = Executors.newFixedThreadPool(8) { r ->
        Thread(r, "acp-http").apply { isDaemon = true }
    }
    private val sseStreams = ConcurrentHashMap<String, (SessionEvents.Event) -> Unit>()

    /** bd-and-core F8: live SSE streams per pairing key — capped,
     *  so event streams cannot exhaust the request pool or the
     *  device one unauthenticated initialize at a time. */
    private val sseByPairing = ConcurrentHashMap<String, Int>()

    /**
     * The server's real state, derived — never latched (0.4.4): the
     * server is running only while it is accepting AND at least one
     * listener socket is actually bound. The old flag was set before
     * openListeners() ran, so the status card could claim Running
     * with zero sockets bound — and, read too early, claim Starting
     * forever (the stuck-"Starting" card defect).
     */
    val isRunning: Boolean get() = accepting && boundAddresses.isNotEmpty()

    /** Addresses the server is currently bound to (for status). */
    @Volatile
    var boundAddresses: List<String> = emptyList()
        private set

    @Synchronized
    fun start() {
        if (accepting) return
        accepting = true
        openListeners()
    }

    @Synchronized
    fun stop() {
        accepting = false
        closeListeners()
    }

    /** Re-evaluate the bind set after a network change: sockets for
     *  addresses that vanished are closed, new ones are opened. */
    @Synchronized
    fun rebind() {
        if (!accepting) return
        val wanted = addressProvider().map { it.hostAddress }.toSet()
        if (wanted == boundAddresses.toSet()) return
        closeListeners()
        openListeners()
    }

    private fun openListeners() {
        val addresses = addressProvider()
        val opened = mutableListOf<String>()
        for (address in addresses) {
            try {
                val server = ServerSocket(port, 16, address)
                // W98: the arrival path is a fact of the LISTENER,
                // classified here where the bind policy lives:
                // loopback binds are the loopback path, Tailscale
                // CGNAT binds are the mesh path. (defaultBindAddresses
                // binds nothing else; an unclassifiable address
                // would carry null = unpoliced, so the bind set and
                // this classification must stay in step.)
                val arrivalPath = when {
                    address.isLoopbackAddress -> ConnectionPath.PATH_LOOPBACK
                    isTailnetAddress(address) -> ConnectionPath.PATH_MESH
                    else -> null
                }
                listeners.add(server to arrivalPath)
                opened.add(address.hostAddress ?: address.toString())
                Thread({ acceptLoop(server, arrivalPath) }, "acp-accept").apply { isDaemon = true }.start()
            } catch (_: Exception) {
                // One bad address must not take the rest down.
            }
        }
        boundAddresses = opened
    }

    private fun closeListeners() {
        listeners.forEach { try { it.first.close() } catch (_: Exception) {} }
        listeners.clear()
        boundAddresses = emptyList()
    }

    private fun acceptLoop(server: ServerSocket, arrivalPath: String? = null) {
        while (accepting) {
            val client = try {
                server.accept()
            } catch (e: Exception) {
                if (accepting && !server.isClosed) continue else return
            }
            pool.execute { handleClient(client, arrivalPath) }
        }
    }

    /**
     * Read one CRLF-terminated line from the raw stream as BYTES
     * (bd-and-core F7): header lines are ASCII; reading them
     * byte-wise keeps the stream positioned exactly at the body,
     * whose Content-Length counts bytes — the old BufferedReader
     * read that many CHARS, so any non-ASCII body (accented, emoji
     * or CJK type_text) stalled until the socket timeout and the
     * request died with no response.
     */
    private fun readLineBytes(input: InputStream): String? {
        val buf = ByteArrayOutputStream()
        var prev = -1
        while (true) {
            val b = input.read()
            if (b < 0) return if (buf.size() == 0) null else String(buf.toByteArray(), Charsets.UTF_8)
            if (prev == '\r'.code && b == '\n'.code) {
                val bytes = buf.toByteArray()
                return String(bytes, 0, bytes.size - 1, Charsets.UTF_8)
            }
            buf.write(b)
            prev = b
            if (buf.size() > MAX_HEADER_LINE_BYTES) return String(buf.toByteArray(), Charsets.UTF_8)
        }
    }

    private fun handleClient(client: Socket, arrivalPath: String? = null) {
        var keepOpen = false
        try {
            client.soTimeout = SOCKET_TIMEOUT_MS
            val input = client.getInputStream()
            val requestLine = readLineBytes(input) ?: return
            val parts = requestLine.split(' ')
            if (parts.size < 2) return respond(client.getOutputStream(), 400, "Bad request")
            val method = parts[0]
            val path = parts[1]

            var contentLength = 0
            var authorization: String? = null
            var sessionHeader: String? = null
            var hostHeader: String? = null
            var originHeader: String? = null
            var acceptHeader: String? = null
            var lastEventId: Long? = null
            while (true) {
                val line = readLineBytes(input) ?: break
                if (line.isEmpty()) break
                val colon = line.indexOf(':')
                if (colon > 0) {
                    val name = line.substring(0, colon).trim().lowercase()
                    val value = line.substring(colon + 1).trim()
                    when (name) {
                        "content-length" -> contentLength = value.toIntOrNull() ?: 0
                        "authorization" -> authorization = value
                        "mcp-session-id" -> sessionHeader = value
                        "host" -> hostHeader = value
                        "origin" -> originHeader = value
                        "accept" -> acceptHeader = value
                        "last-event-id" -> lastEventId = value.toLongOrNull()
                    }
                }
            }

            // Browser-originated requests are refused outright: a web
            // page must never be able to reach this server, even on
            // the tailnet (CSRF / DNS-rebinding defense).
            if (originHeader != null) {
                return respond(client.getOutputStream(), 403, "Forbidden: browser origin")
            }
            // The Host must be loopback or a bound address — a
            // rebinding hostname fails here.
            if (!hostAllowed(hostHeader)) {
                return respond(client.getOutputStream(), 403, "Forbidden: host")
            }

            val token = authorization
                ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
                ?.substring(7)?.trim()

            when {
                method == "GET" && path == "/health" -> {
                    respond(client.getOutputStream(), 200, "{\"status\":\"ok\",\"server\":\"agentic-control-platform\"}", "application/json")
                }
                method == "GET" && path == "/mcp" &&
                    acceptHeader?.contains("text/event-stream") == true -> {
                    // bd-and-core F8: SSE lives on its OWN thread,
                    // never on one of the 8 request-pool threads —
                    // a handful of streams used to be able to starve
                    // every tool call. The stream thread owns the
                    // socket from here (keepOpen stops this handler
                    // closing it).
                    keepOpen = true
                    Thread({ openEventStream(client, token, sessionHeader, lastEventId, arrivalPath) }, "acp-sse")
                        .apply { isDaemon = true }.start()
                }
                method == "POST" && path == "/mcp" -> {
                    if (contentLength <= 0 || contentLength > MAX_BODY_BYTES) {
                        return respond(client.getOutputStream(), 413, "Body missing or too large")
                    }
                    // bd-and-core F7: read exactly contentLength
                    // BYTES from the raw stream, then decode UTF-8.
                    val buffer = ByteArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = input.read(buffer, read, contentLength - read)
                        if (n < 0) break
                        read += n
                    }
                    val body = String(buffer, 0, read, Charsets.UTF_8)
                    val reply = core.handle(body, token, sessionHeader, arrivalPath)
                    val headers = mutableMapOf<String, String>()
                    reply.sessionId?.let { headers["Mcp-Session-Id"] = it }
                    respond(client.getOutputStream(), reply.httpStatus, reply.body ?: "", "application/json", headers)
                }
                else -> respond(client.getOutputStream(), 404, "Not found")
            }
        } catch (_: Exception) {
            // A dropped client is not an error worth logging a stack for.
        } finally {
            if (!keepOpen) {
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    /** Host header check: the host part must be "localhost", a
     *  loopback literal, or one of the currently bound addresses. */
    private fun hostAllowed(hostHeader: String?): Boolean {
        if (hostHeader.isNullOrBlank()) return true // HTTP/1.0 style: no Host to check
        val host = hostHeader.substringBefore(':').trim().trim('[', ']')
        if (host.equals("localhost", ignoreCase = true)) return true
        val address = try {
            InetAddress.getByName(host)
        } catch (e: Exception) {
            return false
        }
        if (address.isLoopbackAddress) return true
        return boundAddresses.contains(address.hostAddress)
    }

    /**
     * Open an SSE stream for session-state notifications
     * (notifications/session_state). Requires the bearer token and
     * the session id issued at initialize. The stream lives until
     * the client disconnects; a comment heartbeat keeps it warm.
     * Returns true when the socket stays open under stream care.
     */
    private fun openEventStream(client: Socket, token: String?, sessionHeader: String?, lastEventId: Long? = null, arrivalPath: String? = null): Boolean {
        val out = client.getOutputStream()
        if (sessionHeader.isNullOrBlank() || !core.isAuthorized(token)) {
            respond(out, 401, "Unauthorized: event stream needs a paired token and session id")
            try { client.close() } catch (_: Exception) {}
            return false
        }
        // W98 / S09(b): the event-stream leg enforces the pairing's
        // connection-path setting identically, before any byte of
        // the stream is written (W97 parity).
        if (!core.isPathAllowed(token, arrivalPath)) {
            respond(out, 401, "Unauthorized: this pairing may not connect over this path")
            try { client.close() } catch (_: Exception) {}
            return false
        }
        // bd-and-core F8: per-pairing stream cap.
        val pairingCountKey = token!!
        val active = sseByPairing.merge(pairingCountKey, 1) { a, b -> a + b } ?: 1
        if (active > MAX_SSE_PER_PAIRING) {
            sseByPairing.merge(pairingCountKey, -1) { a, b -> a + b }
            respond(out, 429, "Too many event streams for this pairing")
            try { client.close() } catch (_: Exception) {}
            return false
        }
        // U2: the stream is filtered by THIS pairing's subscription
        // (EventSubscriptions, keyed by its token): kinds it never
        // subscribed to are not written to its socket. STOP kills
        // the stream: a stopped_by_user event is delivered, then
        // the loop below closes the socket.
        val pairingKey = token
        val stopSeen = java.util.concurrent.atomic.AtomicBoolean(false)
        val head = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/event-stream\r\n" +
            "Cache-Control: no-cache\r\n" +
            "Connection: keep-alive\r\n\r\n"
        out.write(head.toByteArray(Charsets.UTF_8))
        out.flush()
        client.soTimeout = 0
        val writeLock = Any()
        fun writeFrame(frame: String) {
            synchronized(writeLock) {
                out.write(frame.toByteArray(Charsets.UTF_8))
                out.flush()
            }
        }
        // W5 (bd-supp-eventsub F1): delivery is scoped LIVE — the
        // pairing must still resolve AND still hold Observe at the
        // moment of the event. Revocation or scope loss stops
        // delivery immediately; there is no fail-open path.
        fun holdsObserveNow(): Boolean {
            val p = core.pairingForToken(pairingKey) ?: return false
            return "observe" in p.scopes
        }
        // W5 (F3): the bus listener NEVER touches the socket. It
        // only offers the event to this stream's bounded queue
        // (drop-oldest on full); a dedicated writer thread drains
        // the queue to the socket. A stalled or half-open client
        // therefore blocks only its own writer thread — never the
        // producer, never another stream.
        val queue = java.util.concurrent.ArrayBlockingQueue<SessionEvents.Event>(SSE_QUEUE_CAPACITY)
        fun enqueue(event: SessionEvents.Event) {
            if (!queue.offer(event)) {
                queue.poll() // drop the oldest — the sequence jump shows the gap (F7)
                queue.offer(event)
            }
        }
        val listener: (SessionEvents.Event) -> Unit = { event ->
            if (event.state == "stopped_by_user") stopSeen.set(true)
            if (pairingKey != null &&
                EventSubscriptions.shouldDeliverScoped(pairingKey, event) { holdsObserveNow() }
            ) {
                enqueue(event)
            }
        }
        sseStreams[sessionHeader] = listener
        SessionEvents.addListener(listener)
        // W5 (F7): Last-Event-ID resume — replay what the bus ring
        // still holds for this pairing before live events flow.
        if (lastEventId != null && pairingKey != null) {
            for (event in SessionEvents.eventsSince(lastEventId)) {
                if (EventSubscriptions.shouldDeliverScoped(pairingKey, event) { holdsObserveNow() }) {
                    enqueue(event)
                }
            }
        }
        val writer = Thread({
            try {
                while (accepting && !client.isClosed) {
                    val event = queue.poll(500, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                    try {
                        writeFrame("id: " + event.seq + "\ndata: " + SessionEvents.toJson(event) + "\n\n")
                    } catch (_: Exception) {
                        break // dead socket — the read loop finishes the teardown
                    }
                    if (event.state == "stopped_by_user") break
                }
            } catch (_: InterruptedException) {
            }
        }, "acp-sse-writer").apply { isDaemon = true }
        writer.start()
        try {
            val input = client.getInputStream()
            val buffer = ByteArray(1024)
            var lastBeat = System.currentTimeMillis()
            // W5 (F4): the stream also ends when the pairing stops
            // resolving (revoked) — a revoked pairing is told by the
            // close itself, not left holding a silent open stream.
            while (accepting && !client.isClosed && !stopSeen.get() && core.isAuthorized(token)) {
                if (input.available() > 0) {
                    if (input.read(buffer) < 0) break
                }
                if (System.currentTimeMillis() - lastBeat > 15_000) {
                    // W108 / W105-C5: per-heartbeat connection-path
                    // RE-CHECK — the attach-time check alone let a
                    // restriction applied mid-stream never bite the
                    // open stream. Re-checking here (the stream's
                    // heartbeat cadence) closes the stream when its
                    // arrival path has become excluded; the refusal
                    // is audited by McpCore.isPathAllowed under the
                    // same pairing_connection refusal family as
                    // attach-time refusals.
                    if (arrivalPath != null && !core.isPathAllowed(token, arrivalPath)) {
                        break
                    }
                    try {
                        writeFrame(": heartbeat\n\n")
                    } catch (_: Exception) {
                        break
                    }
                    lastBeat = System.currentTimeMillis()
                }
                Thread.sleep(250)
            }
        } catch (_: Exception) {
        } finally {
            SessionEvents.removeListener(listener)
            writer.interrupt()
            sseStreams.remove(sessionHeader)
            sseByPairing.merge(pairingCountKey, -1) { a, b -> a + b }
            try { client.close() } catch (_: Exception) {}
        }
        return true
    }

    private fun respond(
        out: OutputStream,
        status: Int,
        body: String,
        contentType: String = "text/plain",
        extraHeaders: Map<String, String> = emptyMap()
    ) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val reason = when (status) {
            200 -> "OK"; 202 -> "Accepted"; 400 -> "Bad Request"; 401 -> "Unauthorized"
            403 -> "Forbidden"; 404 -> "Not Found"; 413 -> "Payload Too Large"; else -> "Status"
        }
        val head = StringBuilder()
            .append("HTTP/1.1 $status $reason\r\n")
            .append("Content-Type: $contentType\r\n")
            .append("Content-Length: ${bytes.size}\r\n")
            .append("Connection: close\r\n")
        extraHeaders.forEach { (k, v) -> head.append("$k: $v\r\n") }
        head.append("\r\n")
        out.write(head.toString().toByteArray(Charsets.UTF_8))
        out.write(bytes)
        out.flush()
    }

    companion object {
        /** The product's fixed MCP port (SPEC §4.3). */
        const val PORT = 8723
        const val MAX_BODY_BYTES = 256 * 1024
        const val SOCKET_TIMEOUT_MS = 5_000
        const val MAX_HEADER_LINE_BYTES = 16 * 1024
        /** bd-and-core F8: event streams one pairing may hold. */
        const val MAX_SSE_PER_PAIRING = 2
        /** W5 (bd-supp-eventsub F3): per-stream outbound queue cap. */
        const val SSE_QUEUE_CAPACITY = 128

        /**
         * The addresses this server may bind: loopback, plus every
         * up non-loopback interface address inside the Tailscale
         * CGNAT range (100.64.0.0/10). LAN addresses are deliberately
         * NOT bound (0.4.0 hardening) — the wizard's Wi-Fi route now
         * rides the same tailnet/loopback set, and the app says so.
         */
        fun defaultBindAddresses(): List<InetAddress> {
            val out = mutableListOf<InetAddress>()
            out.add(InetAddress.getByName("127.0.0.1"))
            try {
                val interfaces = NetworkInterface.getNetworkInterfaces()
                while (interfaces != null && interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    if (!iface.isUp || iface.isLoopback) continue
                    val addrs = iface.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (addr is Inet4Address && isTailnetAddress(addr)) out.add(addr)
                    }
                }
            } catch (_: Exception) {
            }
            return out
        }

        /** 100.64.0.0/10: first octet 100, second 64–127. */
        fun isTailnetAddress(addr: InetAddress): Boolean {
            val bytes = addr.address
            if (bytes.size != 4) return false
            val second = bytes[1].toInt() and 0xFF
            return (bytes[0].toInt() and 0xFF) == 100 && second in 64..127
        }
    }
}

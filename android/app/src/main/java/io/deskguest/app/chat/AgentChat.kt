package io.deskguest.app.chat

import io.deskguest.app.design.AgentChatModel
import io.deskguest.app.server.DataFlows
import java.io.File

/**
 * W7 item 6 — Agent chat store (§4 A17 / Addendum A). One thread
 * per pairing, keyed by the pairing's unique id (never a display
 * name — the DataFlows keying rule). The thread is NOT a session:
 * sending a message starts nothing, grants nothing, and shows no
 * presence. Off-device messages are counted Sent in the data-flow
 * ledger at send time. Unpairing ENDS the thread: it is closed
 * and its messages are removed with the pairing.
 *
 * Audit keeps message METADATA, not text: [auditEvent] carries
 * only the pairing id, direction, length and timestamp — the
 * message body never enters an audit/accounting structure.
 *
 * Persistence: one file per pairing under the chat dir. W10
 * (V3-F7) line format v2: `seq|atMs|direction|base64(body)` —
 * every message carries an EXPLICIT, persisted sequence number.
 * Legacy v1 lines (`atMs|direction|base64`) still load, taking
 * sequence numbers from their position among loadable lines.
 * Bodies live ONLY in the thread file the owner reads in the
 * chat surface.
 *
 * Concurrency (W10, V3-F7): appends are serialised on this
 * store — the owner UI thread and the agent tool threads both
 * append, and interleaved appendText calls could previously tear
 * lines (a torn line was dropped by load(), silently losing the
 * message AND shifting every later sequence number). Sequence
 * numbers are assigned inside the same lock from the persisted
 * maximum, so they are monotone and never reused. Reads that
 * return messages together with a cursor take BOTH from a single
 * load ([snapshotAfter]): the old two-load read could skip a
 * message appended between the loads while the cursor advanced
 * past it.
 *
 * Bound (W10, V3-F7): a thread keeps at most
 * [AgentChatModel.MAX_THREAD_MESSAGES] messages; at append time
 * the oldest are dropped (sequence numbers are preserved, never
 * renumbered).
 */
object AgentChatStore {

    const val DIR_OWNER = "owner"
    const val DIR_AGENT = "agent"

    data class Message(val atMs: Long, val direction: String, val body: String)

    /** One message with its thread sequence number (1-based,
     *  persisted, never reused). */
    data class Sequenced(val seq: Long, val message: Message)

    /** W13 P1-F7: pairings whose thread has been ENDED (unpair).
     *  Appends and deletes already serialise on this object's
     *  monitor, but an append that arrives AFTER an unpair (a tool
     *  call racing the owner's unpair tap) would silently recreate
     *  the thread file. The tombstone makes the end durable for
     *  the process lifetime: appends to an ended pairing are
     *  dropped, never written. Pairing ids are unique per pairing,
     *  so a tombstone can never block a different, live pairing. */
    private val endedPairings = mutableSetOf<String>()

    fun threadEnded(pairingId: String): Boolean =
        synchronized(this) { pairingId in endedPairings }

    // W12-DS P1-F11: INJECTIVE filename — the old sanitizer mapped
    // "a:b", "a/b" and "a b" to the same file, so two pairings
    // could share (and delete) one thread. Base64url of the full
    // id is one-to-one.
    private fun threadFile(chatDir: File, pairingId: String): File =
        File(chatDir, java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(pairingId.toByteArray(Charsets.UTF_8)) + ".thread")

    private fun decodeBody(encoded: String): String? = try {
        String(java.util.Base64.getDecoder().decode(encoded), Charsets.UTF_8)
    } catch (_: Exception) {
        null
    }

    /** Load the whole thread WITH sequence numbers, in order.
     *  Malformed lines are dropped and never occupy a sequence
     *  slot a reader could wait on. */
    @Synchronized
    fun loadSequenced(chatDir: File, pairingId: String): List<Sequenced> {
        val f = threadFile(chatDir, pairingId)
        if (!f.isFile) return emptyList()
        val out = mutableListOf<Sequenced>()
        var legacySeq = 0L
        for (line in f.readLines()) {
            val parts = line.split("|", limit = 4)
            if (parts.size == 4) {
                // v2: seq|atMs|direction|base64
                val seq = parts[0].toLongOrNull() ?: continue
                val at = parts[1].toLongOrNull() ?: continue
                val body = decodeBody(parts[3]) ?: continue
                out += Sequenced(seq, Message(at, parts[2], body))
                legacySeq = maxOf(legacySeq, seq)
            } else if (parts.size == 3) {
                // v1 legacy: atMs|direction|base64 — seq is the
                // position among loadable lines (the old rule),
                // kept only so old threads still read.
                val at = parts[0].toLongOrNull() ?: continue
                val body = decodeBody(parts[2]) ?: continue
                legacySeq += 1
                out += Sequenced(legacySeq, Message(at, parts[1], body))
            }
        }
        return out
    }

    fun load(chatDir: File, pairingId: String): List<Message> =
        loadSequenced(chatDir, pairingId).map { it.message }

    /**
     * Append one message, serialised against every other append
     * and read-modify-write of the same store. When the message
     * goes to an off-device agent ([AgentChatModel.countsAsSent])
     * it is counted Sent in the ledger. Returns the metadata-only
     * audit event for the caller to emit — the body is never in
     * it. The assigned sequence number is available from
     * [appendSequenced].
     */
    @Synchronized
    fun append(
        chatDir: File,
        pairingId: String,
        direction: String,
        body: String,
        atMs: Long,
        agentOffDevice: Boolean = true
    ): Map<String, Any> {
        if (pairingId in endedPairings) {
            return auditEvent(pairingId, direction, body.length, atMs) + ("threadEnded" to true)
        }
        appendSequencedLocked(chatDir, pairingId, direction, body, atMs)
        if (direction == DIR_OWNER && AgentChatModel.countsAsSent(agentOffDevice)) {
            DataFlows.noteChatMessageSent(pairingId)
        }
        return auditEvent(pairingId, direction, body.length, atMs)
    }

    /** Append and return the stored message with its assigned
     *  sequence number. */
    @Synchronized
    fun appendSequenced(
        chatDir: File,
        pairingId: String,
        direction: String,
        body: String,
        atMs: Long,
        agentOffDevice: Boolean = true
    ): Sequenced {
        // W13 P1-F7: an ended pairing's thread stays ended — the
        // append is dropped and the caller sees seq -1 (no slot).
        if (pairingId in endedPairings) return Sequenced(-1L, Message(atMs, direction, body))
        val stored = appendSequencedLocked(chatDir, pairingId, direction, body, atMs)
        if (direction == DIR_OWNER && AgentChatModel.countsAsSent(agentOffDevice)) {
            DataFlows.noteChatMessageSent(pairingId)
        }
        return stored
    }

    /** The append itself. Caller must hold the store lock (all
     *  public entry points are @Synchronized on this object). */
    private fun appendSequencedLocked(
        chatDir: File,
        pairingId: String,
        direction: String,
        body: String,
        atMs: Long
    ): Sequenced {
        chatDir.mkdirs()
        val existing = loadSequenced(chatDir, pairingId)
        val nextSeq = (existing.maxOfOrNull { it.seq } ?: 0L) + 1L
        val encoded = java.util.Base64.getEncoder()
            .encodeToString(body.toByteArray(Charsets.UTF_8))
        val message = Message(atMs, direction, body)
        val withNew = existing + Sequenced(nextSeq, message)
        if (withNew.size > AgentChatModel.MAX_THREAD_MESSAGES) {
            // Bound: rewrite the file with only the newest
            // messages, sequence numbers preserved.
            val kept = withNew.takeLast(AgentChatModel.MAX_THREAD_MESSAGES)
            val sb = StringBuilder()
            for (s in kept) {
                val enc = java.util.Base64.getEncoder()
                    .encodeToString(s.message.body.toByteArray(Charsets.UTF_8))
                sb.append("${s.seq}|${s.message.atMs}|${s.message.direction}|$enc\n")
            }
            threadFile(chatDir, pairingId).writeText(sb.toString(), Charsets.UTF_8)
        } else {
            threadFile(chatDir, pairingId)
                .appendText("$nextSeq|$atMs|$direction|$encoded\n", Charsets.UTF_8)
        }
        return Sequenced(nextSeq, message)
    }

    /** Metadata only — pairing, direction, length, time. No text. */
    fun auditEvent(
        pairingId: String, direction: String, bodyLength: Int, atMs: Long
    ): Map<String, Any> = mapOf(
        "pairing" to pairingId,
        "direction" to direction,
        "chars" to bodyLength,
        "atMs" to atMs
    )

    /** Unpairing ends the thread (§4 A17): the file is removed and
     *  the surface renders the thread-ended line thereafter. */
    @Synchronized
    // W12-DS P1-F20: the delete result is CHECKED and retried
    // once; the return says whether the thread is actually gone.
    fun endThread(chatDir: File, pairingId: String): Boolean {
        endedPairings.add(pairingId)
        val f = threadFile(chatDir, pairingId)
        if (!f.exists()) return true
        if (f.delete()) return true
        return !f.exists() || f.delete()
    }

    fun threadExists(chatDir: File, pairingId: String): Boolean =
        threadFile(chatDir, pairingId).isFile

    fun sentCount(pairingId: String): Long = DataFlows.chatSentCount(pairingId)

    // ---- W8 item 1: agent-side transport sync semantics ----
    // The pairing's established channel is the MCP server: the
    // agent already connects agent→device to call tools. Chat
    // rides that same channel in both directions — the owner→agent
    // leg is DELIVERY BY READ: owner messages appended here are
    // returned to the paired agent by the chat_read tool (its own
    // app context, its own bearer token, its own pairing only);
    // the agent→device leg is chat_post, which appends an agent
    // message the owner reads in AgentChatActivity. Sync is a
    // monotone cursor: every message carries its persisted
    // sequence number; chat_read(afterSeq) returns exactly the
    // messages after the cursor plus the next cursor, so a
    // reconnecting agent resumes without loss or duplication.
    // There is NO server-initiated push leg for chat on this
    // architecture (McpCore serves request/response; the SSE event
    // stream carries event kinds, not message bodies) — delivery
    // is pull-based and is named as such wherever it is described.

    /** W13 P1-F10 remainder closed: STREAMING parse of one line
     *  (same v1/v2 rules as [loadSequenced]); [legacySeq] carries
     *  the running legacy position. Returns null for malformed
     *  lines and the new legacy counter with the parsed entry. */
    private fun parseLine(line: String, legacySeq: Long): Pair<Sequenced?, Long> {
        val parts = line.split("|", limit = 4)
        if (parts.size == 4) {
            val seq = parts[0].toLongOrNull() ?: return null to legacySeq
            val at = parts[1].toLongOrNull() ?: return null to legacySeq
            val body = decodeBody(parts[3]) ?: return null to legacySeq
            return Sequenced(seq, Message(at, parts[2], body)) to maxOf(legacySeq, seq)
        }
        if (parts.size == 3) {
            val at = parts[0].toLongOrNull() ?: return null to legacySeq
            val body = decodeBody(parts[2]) ?: return null to legacySeq
            val seq = legacySeq + 1
            return Sequenced(seq, Message(at, parts[1], body)) to seq
        }
        return null to legacySeq
    }

    /** Stream the thread file once, collecting only entries after
     *  [afterSeq] and the maximum sequence seen — memory is
     *  proportional to the RESULT, not the whole thread (the old
     *  loadAfter materialised every message to return a tail). */
    @Synchronized
    fun streamAfter(
        chatDir: File, pairingId: String, afterSeq: Long
    ): Pair<List<Sequenced>, Long> {
        val f = threadFile(chatDir, pairingId)
        if (!f.isFile) return emptyList<Sequenced>() to 0L
        val out = mutableListOf<Sequenced>()
        var legacySeq = 0L
        var cursor = 0L
        f.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                val (entry, nextLegacy) = parseLine(line, legacySeq)
                legacySeq = nextLegacy
                if (entry != null) {
                    if (entry.seq > cursor) cursor = entry.seq
                    if (entry.seq > afterSeq) out += entry
                }
            }
        }
        return out to cursor
    }

    /** All messages after [afterSeq] (0 = from the start), each
     *  with its sequence number. */
    fun loadAfter(chatDir: File, pairingId: String, afterSeq: Long): List<Sequenced> =
        streamAfter(chatDir, pairingId, afterSeq).first

    /** The cursor an agent stores after reading: the sequence of
     *  the last message in the thread (0 when empty). */
    fun nextCursor(chatDir: File, pairingId: String): Long =
        streamAfter(chatDir, pairingId, Long.MAX_VALUE).second

    /** W10 (V3-F7): messages after [afterSeq] AND the next cursor,
     *  taken from ONE load — a message appended concurrently can
     *  never be skipped by a cursor that advanced past it (the
     *  old read() loaded twice and could do exactly that). W13:
     *  the one pass is now streaming (see [streamAfter]). */
    fun snapshotAfter(
        chatDir: File, pairingId: String, afterSeq: Long
    ): Pair<List<Sequenced>, Long> = streamAfter(chatDir, pairingId, afterSeq)
}

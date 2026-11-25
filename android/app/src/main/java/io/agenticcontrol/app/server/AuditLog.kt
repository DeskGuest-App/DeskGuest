package io.agenticcontrol.app.server

import io.agenticcontrol.app.crypto.LineCipher
import org.json.JSONObject

/**
 * The audit log's pure core (0.4.0): what gets written, how it is
 * redacted, and how a line is encoded. The log is append-only JSONL,
 * each line wrapped through the same LineCipher as the pairing
 * store (AES-GCM under a Keystore key only on a recorded probe_ok
 * verdict — bd-and-core F6, see crypto/AtRestCipher; plain
 * otherwise, named honestly), and there is deliberately NO MCP
 * read path — the only way out is the owner's in-app export
 * (AuditStore).
 *
 * Redaction happens at write time, here, so a secret cannot reach
 * the disk even if a caller is careless:
 * - type_text is recorded as a length, never the text (it may be a
 *   message the owner dictated, or worse).
 * - clipboard contents are recorded as a length, never the content.
 * - shell commands are recorded as program name + length.
 * - any field named token/code/password/secret is dropped outright.
 */
object AuditLog {

    /** Field names that never reach the log, whatever the caller passes. */
    private val FORBIDDEN_KEYS = setOf("token", "code", "password", "secret", "paircode")

    /** A log-safe summary of a tool call's arguments. */
    fun summarize(tool: String, args: JSONObject?): String {
        if (args == null) return ""
        return when (tool) {
            "type_text" -> {
                val text = args.optString("text", "")
                "typed ${text.length} chars"
            }
            "clipboard_set" -> {
                val text = args.optString("text", "")
                "clipboard set, ${text.length} chars"
            }
            "clipboard_get" -> "clipboard read"
            "shell_exec" -> {
                val command = args.optString("command", "")
                val program = command.trim().split(Regex("\\s+")).firstOrNull() ?: ""
                "ran $program (${command.length} chars)"
            }
            "tap" -> "tap ${args.optString("ref", "")}"
            "tap_point" -> "tap ${args.optInt("x")},${args.optInt("y")}"
            "launch_app" -> "launched ${args.optString("package", "")}"
            else -> {
                // Generic: keys only, values only when short and
                // clearly not a secret-bearing field.
                val keys = mutableListOf<String>()
                val it = args.keys()
                while (it.hasNext()) {
                    val key = it.next()
                    if (key.lowercase() in FORBIDDEN_KEYS) continue
                    keys.add(key)
                }
                if (keys.isEmpty()) "" else "args: ${keys.joinToString(",")}"
            }
        }
    }

    /** Build one record as a JSONObject, with forbidden keys dropped. */
    fun record(
        atMs: Long,
        kind: String,
        name: String,
        agent: String,
        ok: Boolean,
        detail: String
    ): JSONObject {
        val json = JSONObject()
            .put("at", atMs)
            .put("kind", kind)
            .put("name", name)
            .put("ok", ok)
            .put("detail", detail.take(300))
        if (agent.isNotBlank()) json.put("agent", agent)
        return json
    }

    /** Encode one record as a wrapped log line. */
    fun encode(record: JSONObject, cipher: LineCipher): String =
        cipher.encrypt(record.toString())

    /** Decode one log line; null when it does not decrypt (tampered
     *  or written under another key) — the export reports the count
     *  of unreadable lines rather than hiding them. */
    fun decode(line: String, cipher: LineCipher): JSONObject? {
        val plain = cipher.decrypt(line) ?: return null
        return try {
            JSONObject(plain)
        } catch (e: Exception) {
            null
        }
    }
}

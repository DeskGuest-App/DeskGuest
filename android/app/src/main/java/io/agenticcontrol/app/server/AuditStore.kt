package io.agenticcontrol.app.server

import android.content.Context
import io.agenticcontrol.app.crypto.LineCipher
import org.json.JSONObject
import java.io.File

/**
 * The audit log's Android side (0.4.0): an append-only file of
 * wrapped JSONL records in the app's private directory. Writes are
 * synchronized appends; the count and the export read the file back
 * through the cipher. There is no MCP read path — export is a
 * user-only, in-app action (MainActivity).
 */
class AuditStore(context: Context, private val cipher: LineCipher) {

    private val file = File(context.filesDir, "audit.log")
    private val lock = Any()

    fun record(kind: String, name: String, agent: String, ok: Boolean, detail: String) {
        val line = AuditLog.encode(
            AuditLog.record(System.currentTimeMillis(), kind, name, agent, ok, detail),
            cipher
        )
        synchronized(lock) {
            try {
                file.appendText(line + "\n")
            } catch (_: Exception) {
                // A failed audit write must never break the tool call
                // it was recording.
            }
        }
    }

    /** Number of records currently in the log. */
    fun count(): Int = synchronized(lock) {
        try {
            if (!file.exists()) 0 else file.readLines().count { it.isNotBlank() }
        } catch (e: Exception) {
            0
        }
    }

    data class Export(val text: String, val records: Int, val unreadable: Int)

    /** Decrypt the whole log to plain JSONL for the owner's export. */
    fun export(): Export = synchronized(lock) {
        if (!file.exists()) return Export("", 0, 0)
        val out = StringBuilder()
        var records = 0
        var unreadable = 0
        try {
            file.readLines().forEach { line ->
                if (line.isBlank()) return@forEach
                // bd-and-core F6: lines written in the plain era
                // decode under the identity cipher, so a probe_ok
                // switch to the Keystore wrap does not make the
                // owner's audit history unreadable. A line that
                // decodes under neither counts unreadable, honestly.
                val decoded: JSONObject? = AuditLog.decode(line, cipher)
                    ?: AuditLog.decode(line, io.agenticcontrol.app.crypto.IdentityLineCipher)
                if (decoded == null) {
                    unreadable++
                } else {
                    out.append(decoded.toString()).append('\n')
                    records++
                }
            }
        } catch (e: Exception) {
            // Partial export beats none; the counts say what happened.
        }
        Export(out.toString(), records, unreadable)
    }

    /** The wrapped file itself (for the share sheet's stream). */
    fun rawFile(): File = file
}

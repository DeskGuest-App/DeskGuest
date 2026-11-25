package io.agenticcontrol.app.server

import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.rmmspine.CustomerCommandKeyRing
import io.agenticcontrol.app.rmmspine.PersistedNonceStore
import io.agenticcontrol.app.rmmspine.SignedCommandGate
import io.agenticcontrol.app.rmmspine.SignedCommandVerifier
import java.io.File
import java.util.Base64

/**
 * RMM-03 service wiring (Lane INT, 2026-11-21) — the composition
 * ControlService uses to instantiate McpCore's signed-command gate.
 * Pure JVM (files + rmmspine + the chained audit log), so the exact
 * construction the service runs is exercised by the JVM suite.
 *
 * The customer command key ring is sourced from the device's
 * app-private provisioning state: [KEYS_FILE_NAME] in the same
 * files directory that holds the pairing store and the enrollment
 * store. Provisioning (the pairing/enrollment flow, or the owner
 * placing the file) registers the CUSTOMER's hub signing public
 * key there; nothing else can mint trust — key ids derive from key
 * material inside CustomerCommandKeyRing, so a file can only name
 * keys, never invent an id for different material.
 *
 * File format (UTF-8, one entry per line, '#' comments):
 *   current <base64-encoded 32-byte Ed25519 public key>
 *   retired <base64-encoded 32-byte Ed25519 public key> <retiredUntilMs>
 *
 * Fail-closed posture, by construction:
 *  - No file / no entries: the gate is STILL built, over an empty
 *    ring — every envelope refuses (unknown key id). The gate is
 *    never absent once this wiring runs.
 *  - Any malformed line: the WHOLE file is distrusted (empty ring)
 *    and the state names the breakage — a partially trusted key
 *    file is never loaded.
 *  - A broken persisted nonce store refuses every registration
 *    (PersistedNonceStore's own posture) and the state names it.
 * [build] never throws and never returns a null gate.
 *
 * Scope of the gate (bd-and-core F1, 2026-11-22): McpCore applies
 * this gate to calls that CARRY an envelope (hub/RMM-originated
 * calls) — every such envelope must verify here, over an empty
 * ring none can. Calls carrying no envelope are locally
 * code-paired calls and run under the pairing + capability +
 * approval gates; the gate's fail-closed posture governs
 * envelopes, not the owner's own local pairing.
 */
object CommandGateWiring {
    const val KEYS_FILE_NAME = "customer-command-keys.tsv"
    const val NONCE_FILE_NAME = "signed-command-nonces.json"

    class Wired(
        val gate: SignedCommandGate,
        val ring: CustomerCommandKeyRing,
        val stateDetail: String,
        val loadError: String?
    )

    /** Load the ring from [keysFile]. Returns ring + error text;
     *  on ANY error the ring is empty (fail closed). */
    fun loadRing(keysFile: File): Pair<CustomerCommandKeyRing, String?> {
        val ring = CustomerCommandKeyRing()
        if (!keysFile.exists()) return ring to null
        val lines = try {
            keysFile.readLines(Charsets.UTF_8)
        } catch (e: Exception) {
            return CustomerCommandKeyRing() to "key file unreadable (${e.javaClass.simpleName})"
        }
        var sawCurrent = false
        for ((idx, raw) in lines.withIndex()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parts = line.split(Regex("\\s+"))
            val where = "line ${idx + 1}"
            try {
                when (parts[0]) {
                    "current" -> {
                        if (parts.size != 2) return CustomerCommandKeyRing() to "$where: 'current' takes exactly one key"
                        if (sawCurrent) return CustomerCommandKeyRing() to "$where: second 'current' key — file distrusted"
                        val key = Base64.getDecoder().decode(parts[1])
                        if (key.size != 32) return CustomerCommandKeyRing() to "$where: customer key must be 32 bytes"
                        ring.addCurrent(key); sawCurrent = true
                    }
                    "retired" -> {
                        if (parts.size != 3) return CustomerCommandKeyRing() to "$where: 'retired' takes a key and a retired-until time"
                        val key = Base64.getDecoder().decode(parts[1])
                        if (key.size != 32) return CustomerCommandKeyRing() to "$where: customer key must be 32 bytes"
                        val until = parts[2].toLongOrNull()
                            ?: return CustomerCommandKeyRing() to "$where: retired-until is not a number"
                        ring.addRetired(key, until)
                    }
                    else -> return CustomerCommandKeyRing() to "$where: unknown entry kind '${parts[0]}'"
                }
            } catch (e: Exception) {
                return CustomerCommandKeyRing() to "$where: ${e.javaClass.simpleName}"
            }
        }
        return ring to null
    }

    /** The honest one-line state for a built gate. */
    fun stateFor(ring: CustomerCommandKeyRing, loadError: String?, nonceBroken: Boolean): String = when {
        loadError != null ->
            "WIRED (fail-closed): the customer command key file is broken ($loadError) — every hub command envelope refuses until the key file is repaired (RMM-03)"
        nonceBroken ->
            "WIRED (fail-closed): the signed-command nonce store is broken — every hub command envelope refuses until it is repaired (RMM-03)"
        ring.currentKeyId == null ->
            "WIRED (fail-closed for envelopes): no customer command key is registered on this device — every signed-command envelope refuses until a customer key is provisioned; locally code-paired calls run under pairing + capability + approval gates (RMM-03, bd-and-core F1)"
        else ->
            "WIRED: calls carrying a signed-command envelope verify against the registered customer key ${ring.currentKeyId} before executing; locally code-paired calls run under pairing + capability + approval gates (RMM-03, bd-and-core F1)"
    }

    /**
     * Build the gate ControlService hands to McpCore, from the
     * app-private [dir] (the service's filesDir). Never throws,
     * never returns a null gate.
     */
    fun build(dir: File, audit: ChainedAuditLog): Wired {
        var loadError: String? = null
        val ring = try {
            val (r, err) = loadRing(File(dir, KEYS_FILE_NAME)); loadError = err; r
        } catch (e: Exception) {
            loadError = "key load failed (${e.javaClass.simpleName})"; CustomerCommandKeyRing()
        }
        val nonceStore = try {
            PersistedNonceStore(File(dir, NONCE_FILE_NAME))
        } catch (e: Exception) {
            if (loadError == null) loadError = "nonce store construction failed (${e.javaClass.simpleName})"
            null
        }
        val gate = try {
            if (nonceStore != null) SignedCommandGate(SignedCommandVerifier(ring, nonceStore), audit)
            else SignedCommandGate(SignedCommandVerifier(ring), audit)
        } catch (e: Exception) {
            if (loadError == null) loadError = "gate construction failed (${e.javaClass.simpleName})"
            SignedCommandGate(SignedCommandVerifier(CustomerCommandKeyRing()), audit)
        }
        return Wired(gate, ring, stateFor(ring, loadError, nonceStore?.broken == true), loadError)
    }
}

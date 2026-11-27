package io.deskguest.app.server

import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Pairing state for the control server (SPEC §5.2, §5.3).
 *
 * The app shows a one-time 6-digit code; an agent presents it once and
 * receives a bearer token bound to a named pairing. Codes are
 * single-use, expire, and burn after a bounded number of wrong guesses
 * ([MAX_REDEEM_ATTEMPTS]) so the pair endpoint cannot be brute-forced
 * inside the code's lifetime. Tokens are stored in the app's private files
 * directory (never logged, never in preferences). At-rest wrapping
 * rides the injected [cipher]: AES-GCM under an Android Keystore key
 * when the wiring layer supplies it (bd-and-core F6: ControlService
 * supplies it only on a recorded probe_ok Keystore verdict — see
 * AtRestCipher); the plain IdentityLineCipher otherwise, which this
 * file names honestly rather than claiming a wrap that is not in
 * force. The JVM suite runs the same code with a generated key. Token
 * comparisons are constant-time (MessageDigest.isEqual), and a failed
 * redemption imposes a [FAILURE_BACKOFF_MS] delay on the next attempt —
 * the redeem path is serialized by this store's monitor, so concurrent
 * guesses cannot race the burn counter.
 *
 * Each pairing also carries:
 * - [Pairing.agentName] / [Pairing.agentVersion]: the name the agent
 *   gave in its MCP initialize (clientInfo), bound at pair time. It is
 *   self-reported, but only a client that completed the handshake can
 *   present one, so it proves a real connection happened.
 * - [Pairing.access]: the access level — "observe", "full", or
 *   "custom" (SPEC §5.3).
 * - [Pairing.caps]: the capability set the level resolves to. Tool
 *   calls are gated on these in McpCore; scopes are derived from the
 *   level here so the two never drift apart.
 */
class PairingStore(
    private val storeFile: File,
    private val cipher: LineCipher = IdentityLineCipher
) {

    data class Pairing(
        val name: String,
        val token: String,
        val scopes: Set<String>,
        val createdAtMs: Long,
        val agentName: String = "",
        val agentVersion: String = "",
        val access: String = ACCESS_OBSERVE,
        val caps: Set<String> = OBSERVE_CAPS,
        /**
         * bd-and-core F11 fix (2026-11-22): the roster scope ids
         * this pairing may SEE through the platform session tools.
         * Empty = unbound: the platform surface then shows only
         * personal-scope sessions (the scope wall's default), never
         * every scope's records. Set via [setScopeIds] by the
         * host-side roster/pairing wiring.
         */
        val scopeIds: Set<String> = emptySet(),
        /**
         * W98 / S09(b): the per-pairing connection-path setting
         * (AUTO / restricted subset / manual pin over Android's
         * real arrival paths — see [ConnectionPath]). Defaulted:
         * a pre-W98 record carries AUTO, exactly as a pre-W97
         * Windows record does. Changed only via
         * [updateConnectionPath]; bound at mint via [beginPairing].
         */
        val connection: ConnectionPath.Setting = ConnectionPath.Setting.AUTO
    ) {
        /**
         * Stable, unique identity for THIS pairing — the only key
         * per-pairing accounting (DataFlows) may use. [name] is a
         * display label the owner typed at pair time and is NOT
         * unique: two pairings can carry the same name (and the same
         * self-reported agent name), so keying anything by name
         * folds two pairings' records into one (the Android mirror
         * of the Windows ledger session-id collision, caught by the
         * Android DataFlows destruction pass 2026-11-22). Derived
         * one-way from the token (SHA-256, first 32 hex chars):
         * unique because tokens are unique, stable across reloads
         * because the token is, and safe to show or log because the
         * token cannot be recovered from it.
         */
        val id: String
            get() = MessageDigest.getInstance("SHA-256")
                .digest(token.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
                .take(32)
    }

    private val random = SecureRandom()
    private val pairings = mutableListOf<Pairing>()

    private var pendingCode: String? = null
    private var pendingCodeExpiresAtMs: Long = 0
    // FR-122: no generic default name ("Agent" abolished) — a
    // pairing carries only the name beginPairing was actually
    // given; an unnamed pairing is the driver_name_missing defect
    // at session start, never a generic presence name.
    private var pendingName: String = ""

    /** W98 / S09(b): the connection-path setting bound to the live
     *  pairing code at mint (beginPairing), stamped onto the
     *  pairing at redemption — the mint binding, mirroring W97's
     *  CreatePairingCode. AUTO unless the mint surface chose
     *  otherwise. */
    private var pendingConnection: ConnectionPath.Setting = ConnectionPath.Setting.AUTO

    /** W98 / S09(b): the last AUTHENTICATED arrival per pairing
     *  token (path id → time), in memory only — live state of this
     *  run. Never persisted: a stored "current path" claim would
     *  be a lie after a restart (W97's LastConnection discipline). */
    private val lastConnections = mutableMapOf<String, Pair<String, Long>>()

    /**
     * W108 / W105-C5: audit events queued at load time. The store
     * loads in init — before the wiring layer installs
     * onConnectionAudit — so a corrupt-restore event raised during
     * load is queued here and flushed the moment the hook is
     * installed, instead of being lost. Declared BEFORE the init
     * block so load() can use it.
     */
    private val pendingConnectionAudits = mutableListOf<Triple<String, Boolean, String>>()

    /**
     * W108 / W105-C5 quarantine: the ORIGINAL stored connection
     * fields (mode, subset csv, pin) of a present-but-corrupt
     * record, keyed by pairing token. While a pairing's setting
     * carries the fail-closed needs-attention marker, save()
     * writes these original fields back verbatim instead of the
     * marker's fields — a store export can never silently
     * overwrite (and destroy) the owner's corrupt-but-recoverable
     * intent. The entry is dropped only when the owner re-sets the
     * setting through updateConnectionPath (the repair path).
     * Declared BEFORE the init block so load() can use it.
     */
    private val quarantinedConnectionFields =
        mutableMapOf<String, Triple<String, String, String>>()

    /** W10 (V3-F3b): the pairing redeemed in THIS process run, by
     *  this store instance — the wizard's pair step binds its
     *  "redeemed" state, the agent's name and the safety phrase to
     *  THIS pairing only. A store loaded from disk with earlier
     *  pairings has redeemed nothing this run: [lastRedeemedPairing]
     *  stays null until a code is actually redeemed here, so a
     *  re-run or a second AI never inherits an old pairing's
     *  identity or unlock. */
    @Volatile
    private var lastRedeemed: Pairing? = null

    /** The pairing this run's code redemption created, or null
     *  when this run has redeemed nothing yet. */
    fun lastRedeemedPairing(): Pairing? {
        val redeemed = lastRedeemed ?: return null
        // Reflect later binds (clientInfo name) / access changes:
        // return the live record for the same token.
        return synchronized(this) {
            pairings.firstOrNull { it.token == redeemed.token } ?: redeemed
        }
    }
    private var pendingFailedAttempts: Int = 0
    private var lastFailureAtMs: Long = 0

    init {
        load()
    }

    /** Begin a pairing attempt: returns the code to show the user. */
    @Synchronized
    fun beginPairing(agentName: String): String =
        beginPairing(agentName, ConnectionPath.Setting.AUTO)

    /**
     * W98 / S09(b): begin a pairing attempt with the connection-path
     * setting chosen on the mint surface bound to the code. An
     * invalid supplied setting REFUSES the mint (throws) — it is
     * never silently widened to AUTO (W97's mint discipline).
     */
    @Synchronized
    fun beginPairing(agentName: String, connection: ConnectionPath.Setting): String {
        val refusal = ConnectionPath.validate(connection)
        if (refusal != null) {
            throw IllegalArgumentException("pairing mint refused: $refusal")
        }
        pendingConnection = ConnectionPath.normalize(connection)
        pendingName = agentName
        val code = "%06d".format(random.nextInt(1_000_000))
        pendingCode = code
        pendingCodeExpiresAtMs = System.currentTimeMillis() + CODE_TTL_MS
        pendingFailedAttempts = 0
        return code
    }

    /** Milliseconds until the live pairing code expires (0 when no
     *  code is live). The wizard's countdown reads this (0.4.0). */
    val pendingCodeRemainingMs: Long
        @Synchronized get() {
            if (pendingCode == null) return 0L
            return (pendingCodeExpiresAtMs - System.currentTimeMillis()).coerceAtLeast(0L)
        }

    /** W98 / S09(b): the connection setting bound to the live code
     *  (AUTO when no code is live or none was chosen). The pair
     *  door (McpCore) checks an arrival against this BEFORE the
     *  code is redeemed, without consuming it. */
    @Synchronized
    fun pendingConnectionSetting(): ConnectionPath.Setting = pendingConnection

    /** The name the live pairing attempt was begun with ("" when
     *  nameless — the Android norm; the pair door's audit uses it). */
    @Synchronized
    fun pendingPairingName(): String = pendingName

    /** W98 / S09(b): record that [token]'s pairing authenticated
     *  over [pathId] just now — the live current-path label's only
     *  source. Called by the choke points on ALLOWED arrivals
     *  only; a refused arrival never moves the label. */
    @Synchronized
    fun noteConnection(token: String, pathId: String) {
        if (pathId !in ConnectionPath.PATH_IDS) return
        if (pairings.none { constantTimeEquals(it.token, token) }) return
        lastConnections[token] = pathId to System.currentTimeMillis()
    }

    /** The pairing's last authenticated arrival (path id, time ms),
     *  or null when it has not connected since this process started. */
    @Synchronized
    fun lastConnection(token: String): Pair<String, Long>? = lastConnections[token]

    /** The live code, or null when no attempt is open or it expired. */
    @Synchronized
    fun currentCode(): String? {
        val code = pendingCode ?: return null
        if (System.currentTimeMillis() > pendingCodeExpiresAtMs) {
            pendingCode = null
            return null
        }
        return code
    }

    /**
     * Redeem a code. On success returns the new pairing (code is burned).
     * On failure returns null. A few mistyped codes are tolerated so the
     * user is not forced to restart, but the failure budget is bounded:
     * after [MAX_REDEEM_ATTEMPTS] wrong guesses the code is burned, so
     * an attacker spraying the pair endpoint gets that many tries per
     * code — not the whole 10-minute window to brute-force 6 digits.
     * The owner re-initiates pairing from the app (one tap) for a fresh
     * code. Failures against no live code count for nothing: there is
     * nothing to guess at until the owner opens a pairing window.
     *
     * New pairings start at the safe default (SPEC §5.3): access
     * "observe", caps {see}. The wizard's access step upgrades from
     * there via [setAccess].
     */
    fun redeem(code: String, scopes: Set<String>): Pairing? {
        // Failure backoff (0.4.0): after a wrong guess, the next
        // attempt waits out the remainder of the backoff window.
        // bd-and-core F8 fix (2026-11-22): the wait happens OUTSIDE
        // the store monitor — the old shape slept while holding it,
        // so unauthenticated pair spam stalled pairingForToken for
        // every authorized call behind the same lock. The burn
        // counter still cannot be raced: the check-and-burn below
        // runs inside the monitor; only the waiting moved out.
        val waitMs = synchronized(this) {
            if (lastFailureAtMs > 0) {
                lastFailureAtMs + FAILURE_BACKOFF_MS - System.currentTimeMillis()
            } else {
                0L
            }
        }
        if (waitMs > 0) {
            try {
                Thread.sleep(waitMs)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }
        }
        return synchronized(this) { redeemLocked(code, scopes) }
    }

    private fun redeemLocked(code: String, scopes: Set<String>): Pairing? {
        val live = currentCode() ?: return null
        if (!constantTimeEquals(live, code)) {
            pendingFailedAttempts++
            lastFailureAtMs = System.currentTimeMillis()
            if (pendingFailedAttempts >= MAX_REDEEM_ATTEMPTS) {
                pendingCode = null
                pendingFailedAttempts = 0
            }
            return null
        }
        lastFailureAtMs = 0
        pendingCode = null
        pendingFailedAttempts = 0
        val mintedConnection = pendingConnection
        pendingConnection = ConnectionPath.Setting.AUTO
        val tokenBytes = ByteArray(32).also { random.nextBytes(it) }
        val token = tokenBytes.joinToString("") { "%02x".format(it) }
        val pairing = Pairing(
            name = pendingName,
            token = token,
            // D38 Block H review F7: redeem validates scopes the
            // same way load does — live state and reloaded state
            // can never differ on what a pairing holds.
            scopes = scopes.filter { it in ALL_SCOPES }.toSet().ifEmpty { DEFAULT_SCOPES },
            createdAtMs = System.currentTimeMillis(),
            access = ACCESS_OBSERVE,
            caps = OBSERVE_CAPS,
            // W98 / S09(b): the mint-bound connection setting is
            // stamped at redemption (W97's ExchangeCode shape).
            connection = mintedConnection
        )
        pairings.add(pairing)
        lastRedeemed = pairing
        save()
        return pairing
    }

    /**
     * Bind the agent's self-reported identity (MCP clientInfo) to a
     * pairing. Called by McpCore right after a successful pair.
     * Returns the updated pairing, or null if the token is unknown.
     */
    @Synchronized
    fun bindAgentInfo(token: String, agentName: String, agentVersion: String): Pairing? {
        val index = pairings.indexOfFirst { constantTimeEquals(it.token, token) }
        if (index < 0) return null
        val updated = pairings[index].copy(agentName = agentName, agentVersion = agentVersion)
        pairings[index] = updated
        save()
        return updated
    }

    /**
     * Set a pairing's access level (SPEC §5.3). [access] is "observe",
     * "full", or "custom" (anything else is treated as "custom").
     *
     * The presets resolve caps and scopes here, in one place:
     * - observe → caps {see}, scopes {observe}
     * - full    → caps all six, scopes {observe, drive, shell, admin}
     * - custom  → caps as given; scopes keep what the pairing holds,
     *             with "observe" always present and "drive" added when
     *             caps include any of tap/type/apps.
     *
     * Returns the updated pairing, or null if the token is unknown.
     */
    @Synchronized
    fun setAccess(token: String, access: String, caps: Set<String>): Pairing? {
        val index = pairings.indexOfFirst { constantTimeEquals(it.token, token) }
        if (index < 0) return null
        val current = pairings[index]
        val level = when (access.trim().lowercase()) {
            ACCESS_OBSERVE -> ACCESS_OBSERVE
            ACCESS_FULL -> ACCESS_FULL
            else -> ACCESS_CUSTOM
        }
        val newCaps = when (level) {
            ACCESS_OBSERVE -> OBSERVE_CAPS
            ACCESS_FULL -> ALL_CAPS
            else -> caps.filter { it in ALL_CAPS }.toSet()
        }
        val newScopes = when (level) {
            ACCESS_OBSERVE -> setOf("observe")
            ACCESS_FULL -> ALL_SCOPES
            else -> {
                val derived = current.scopes.toMutableSet()
                derived.add("observe")
                if (newCaps.any { it in DRIVE_CAPS }) derived.add("drive")
                derived.toSet()
            }
        }
        val updated = current.copy(access = level, caps = newCaps, scopes = newScopes)
        pairings[index] = updated
        save()
        // W89: the legacy path audits too — every grant change
        // through this store is recorded, whichever surface made it.
        fireAccessAudit(
            current.name, true,
            AccessControl.auditDetail(current.scopes, newScopes)
        )
        try {
            onAccessChanged?.invoke(updated)
        } catch (_: Exception) {
        }
        return updated
    }

    @Synchronized
    fun pairingForToken(token: String?): Pairing? {
        if (token.isNullOrBlank()) return null
        return pairings.firstOrNull { constantTimeEquals(it.token, token) }
    }

    /** Alias of [pairingForToken] (the name the wizard/UI contract uses). */
    fun byToken(token: String): Pairing? = pairingForToken(token)

    /** The most recently created pairing, or null when there are none. */
    @Synchronized
    fun latest(): Pairing? = pairings.lastOrNull()

    /**
     * bd-and-core F4 hooks: the wiring layer (ControlService)
     * installs these so a revoke or an access downgrade ends a live
     * drive session owned by the affected pairing. Null in tests:
     * revocation then only removes the pairing (the session-binding
     * checks in McpCore/SessionManager still refuse the revoked
     * token at the channel, since pairingForToken no longer
     * resolves it).
     */
    @Volatile
    var onRevoke: ((token: String) -> Unit)? = null

    @Volatile
    var onAccessChanged: ((pairing: Pairing) -> Unit)? = null

    /**
     * W89 / S08: the audit hook for access changes. The wiring
     * layer (ControlService.wireAudit) installs this so EVERY
     * grant change — and every refused proposal — lands in the
     * AuditStore as kind "pairing_access": (pairing name, applied?,
     * detail naming the old → new scope sets, or the refusal).
     * Null in tests: changes then only mutate the store.
     */
    @Volatile
    var onAccessAudit: ((name: String, ok: Boolean, detail: String) -> Unit)? = null

    private fun fireAccessAudit(name: String, ok: Boolean, detail: String) {
        try {
            onAccessAudit?.invoke(name, ok, detail)
        } catch (_: Exception) {
        }
    }

    /**
     * W98 / S09(b): the audit hook for connection-path changes and
     * enforcement refusals. The wiring layer (ControlService
     * .wireAudit) installs this so EVERY change — and every refused
     * proposal — lands in the AuditStore as kind
     * "pairing_connection" (the W97 audit kind): (pairing name,
     * applied?, detail naming the old → new setting, or the
     * refusal). Null in tests: changes then only mutate the store.
     */
    @Volatile
    var onConnectionAudit: ((name: String, ok: Boolean, detail: String) -> Unit)? = null
        set(value) {
            field = value
            if (value != null) {
                val queued = synchronized(this) {
                    val copy = pendingConnectionAudits.toList()
                    pendingConnectionAudits.clear()
                    copy
                }
                queued.forEach { (name, ok, detail) ->
                    try {
                        value.invoke(name, ok, detail)
                    } catch (_: Exception) {
                    }
                }
            }
        }

    private fun fireConnectionAudit(name: String, ok: Boolean, detail: String) {
        val hook = onConnectionAudit
        if (hook == null) {
            // No wiring yet (e.g. during load): queue, never drop.
            synchronized(this) { pendingConnectionAudits.add(Triple(name, ok, detail)) }
            return
        }
        try {
            hook.invoke(name, ok, detail)
        } catch (_: Exception) {
        }
    }

    /** W108: the quarantined original stored connection fields for
     *  [token] (mode, subset csv, pin), or null when its record was
     *  not a corrupt restore. */
    @Synchronized
    fun quarantinedConnection(token: String): Triple<String, String, String>? =
        quarantinedConnectionFields[token]

    /** The outcome of an [updateConnectionPath] proposal: the
     *  updated pairing when applied, or the refusal reason when not. */
    data class ConnectionUpdate(val pairing: Pairing?, val refusal: String?)

    /**
     * W98 / S09(b): apply a proposed connection-path setting from
     * the pairing surface — the ONE connection write, mirroring
     * [updateScopes] and W97's UpdateConnectionPath.
     * [ConnectionPath.validate] runs first, at the store: unknown
     * modes/paths, an empty restricted subset, and a pin-less
     * manual setting are all refused, never honored. Every apply
     * and every refusal is reported through [onConnectionAudit].
     * Unknown token: a clean miss (null pairing, no refusal).
     */
    @Synchronized
    fun updateConnectionPath(
        token: String,
        proposed: ConnectionPath.Setting
    ): ConnectionUpdate {
        val index = pairings.indexOfFirst { constantTimeEquals(it.token, token) }
        if (index < 0) return ConnectionUpdate(null, null)
        val current = pairings[index]
        val refusal = ConnectionPath.validate(proposed)
        if (refusal != null) {
            fireConnectionAudit(current.name, false, refusal)
            return ConnectionUpdate(null, refusal)
        }
        val normalized = ConnectionPath.normalize(proposed)
        val updated = current.copy(connection = normalized)
        pairings[index] = updated
        // W108: the owner's re-set IS the repair path for a
        // fail-closed corrupt restore — applying a valid setting
        // clears the needs-attention marker and drops the
        // quarantine, so this save writes the new honest fields.
        quarantinedConnectionFields.remove(current.token)
        save()
        fireConnectionAudit(
            current.name, true,
            ConnectionPath.auditDetail(current.connection, normalized)
        )
        return ConnectionUpdate(updated, null)
    }

    /** The outcome of an [updateScopes] proposal: the updated
     *  pairing when applied, or the refusal reason when not. */
    data class ScopeUpdate(val pairing: Pairing?, val refusal: String?)

    /**
     * W89 / S08: apply a proposed scope set from the access-control
     * surface (the ONE apply path for the slider + Fine-tune).
     * [AccessControl.validateProposal] runs first, at the store:
     * unknown scopes are refused, and a proposal ADDING the admin
     * (elevation) scope without [elevationConfirmed] is refused —
     * elevation is default-refused for AI pairings, exactly as on
     * Windows (W79). On apply, caps and the access label are
     * derived from the scopes ([AccessControl.capsForScopes] /
     * [AccessControl.accessLabelForScopes]) so the layers McpCore
     * gates on can never drift from the grant state. Every apply
     * and every refusal is reported through [onAccessAudit].
     * Unknown token: a clean miss (null pairing, no refusal).
     */
    @Synchronized
    fun updateScopes(
        token: String,
        proposed: Set<String>,
        elevationConfirmed: Boolean
    ): ScopeUpdate {
        val index = pairings.indexOfFirst { constantTimeEquals(it.token, token) }
        if (index < 0) return ScopeUpdate(null, null)
        val current = pairings[index]
        val refusal = AccessControl.validateProposal(current.scopes, proposed, elevationConfirmed)
        if (refusal != null) {
            fireAccessAudit(current.name, false, refusal)
            return ScopeUpdate(null, refusal)
        }
        val updated = current.copy(
            scopes = proposed.toSet(),
            caps = AccessControl.capsForScopes(proposed),
            access = AccessControl.accessLabelForScopes(proposed)
        )
        pairings[index] = updated
        save()
        fireAccessAudit(
            current.name, true,
            AccessControl.auditDetail(current.scopes, proposed)
        )
        try {
            onAccessChanged?.invoke(updated)
        } catch (_: Exception) {
        }
        return ScopeUpdate(updated, null)
    }

    @Synchronized
    fun revoke(token: String): Boolean {
        val removed = pairings.removeAll { constantTimeEquals(it.token, token) }
        if (removed) {
            // W5 (bd-supp-eventsub F4/F5/F10): revocation clears the
            // pairing's event subscription and tombstones its key —
            // before this, clearPairing existed but nothing called
            // it, so a revoked pairing's watch survived in the store.
            EventSubscriptions.revokePairing(token)
            save()
            try {
                onRevoke?.invoke(token)
            } catch (_: Exception) {
            }
        }
        return removed
    }

    /** Bind a pairing to roster scopes (bd-and-core F11). Unknown
     *  token: no-op false. Scope ids are stored as given; the
     *  platform surface intersects them with real scopes. */
    @Synchronized
    fun setScopeIds(token: String, scopeIds: Set<String>): Boolean {
        val index = pairings.indexOfFirst { constantTimeEquals(it.token, token) }
        if (index < 0) return false
        pairings[index] = pairings[index].copy(scopeIds = scopeIds.filter { it.isNotBlank() }.toSet())
        save()
        return true
    }

    @Synchronized
    fun all(): List<Pairing> = pairings.toList()

    /**
     * W108 / W105-C5: restore one record's connection setting from
     * its stored fields — see the split at the call site in [load].
     * [parts] is the full TSV line; [token] is the already-decrypted
     * pairing token (the quarantine key).
     */
    private fun restoreConnection(
        parts: List<String>,
        token: String
    ): ConnectionPath.Setting {
        // No connection fields at all: genuine pre-W98 migration.
        if (parts.size < 10) return ConnectionPath.Setting.AUTO
        val stored = ConnectionPath.Setting(
            mode = parts[9],
            rungs = if (parts.size >= 11) parts[10].csvSet() else emptySet(),
            pin = if (parts.size >= 12) parts[11].ifBlank { null } else null
        )
        val refusal = if (parts.size >= 12) {
            ConnectionPath.validateStored(stored)
        } else {
            // A truncated record (some connection fields present,
            // some missing) is present-but-corrupt, never a
            // migration: it cannot be read as an honest setting.
            "stored connection setting is truncated (${parts.size} fields) — refused"
        }
        if (refusal == null) return ConnectionPath.normalize(stored)
        // Present-but-corrupt: fail closed, quarantine the original
        // fields verbatim, and audit the restore.
        quarantinedConnectionFields[token] = Triple(
            parts[9],
            if (parts.size >= 11) parts[10] else "",
            if (parts.size >= 12) parts[11] else ""
        )
        fireConnectionAudit(
            parts[0], false,
            "corrupt connection setting restored fail-closed (needs attention): " +
                "stored mode='${parts[9]}' failed validation ($refusal); " +
                "no path is allowed until the owner sets the connection setting again; " +
                "the original stored fields are preserved, not overwritten"
        )
        return ConnectionPath.Setting.FAIL_CLOSED
    }

    private fun load() {
        if (!storeFile.exists()) return
        var sawPlaintextToken = false
        storeFile.readLines().forEach { line ->
            if (line.isBlank()) return@forEach
            val parts = line.split('\t')
            // The token field is wrapped at rest (0.4.0). Plaintext
            // tokens written by older versions are read once and
            // migrated by the re-save below; a wrapped token that
            // fails to decrypt (key lost) drops its pairing — fail
            // closed, the owner simply pairs again.
            val tokenField = parts.getOrNull(1) ?: return@forEach
            val token = if (cipher.isWrapped(tokenField)) {
                cipher.decrypt(tokenField) ?: return@forEach
            } else {
                sawPlaintextToken = true
                tokenField
            }
            when {
                // Current format: 12 fields (8-field and 9-field
                // lines from earlier versions still load; the
                // later fields take their defaults). Scopes and caps are
                // re-validated against the known sets (Block H
                // destruction DG-H-A09): setAccess filters what it
                // writes, so a value outside the sets on disk came
                // from a hand edit — unknown scopes/caps are
                // dropped, never honored. Caps are NOT widened
                // on load (F7): an empty saved cap set reloads
                // empty — the observe floor applies to scopes
                // only, where an empty set would otherwise strand
                // the pairing's own record.
                parts.size >= 8 -> pairings.add(
                    Pairing(
                        name = parts[0],
                        token = token,
                        scopes = parts[2].csvSet().filter { it in ALL_SCOPES }.toSet()
                            .ifEmpty { DEFAULT_SCOPES },
                        createdAtMs = parts[3].toLongOrNull() ?: 0L,
                        agentName = parts[4],
                        agentVersion = parts[5],
                        // F7: the access field is validated on
                        // load like every other field — an unknown
                        // level reads as the observe floor, never
                        // as a caller-invented level.
                        access = parts[6].trim().lowercase().takeIf {
                            it in setOf(ACCESS_OBSERVE, ACCESS_FULL, ACCESS_CUSTOM)
                        } ?: ACCESS_OBSERVE,
                        // F7: NO ifEmpty widening — a custom
                        // pairing legitimately saved with zero
                        // caps reloads with zero caps; load must
                        // never grant what save did not hold.
                        caps = parts[7].csvSet().filter { it in ALL_CAPS }.toSet(),
                        // bd-and-core F11: 9th field, roster scope
                        // binding. 8-field lines (pre-fix) load
                        // unbound — the personal-scope default.
                        scopeIds = if (parts.size >= 9) parts[8].csvSet() else emptySet(),
                        // W98 / S09(b): fields 10–12, the
                        // connection-path setting (mode, subset,
                        // pin). W108 / W105-C5 (amends W98's
                        // corrupt-restore rule, per W106's verified
                        // finding): the cases are SPLIT —
                        //  * NO connection fields at all (fewer
                        //    than 10 fields: a genuine pre-W98
                        //    record) restores as AUTO — the
                        //    legitimate migration.
                        //  * Connection fields PRESENT but failing
                        //    validation (a corrupt restricted /
                        //    manual / auto record, or a truncated
                        //    10–11-field record) restores FAIL
                        //    CLOSED as Setting.FAIL_CLOSED — no
                        //    path allowed until the owner re-sets
                        //    it — the original fields are
                        //    quarantined (never overwritten by a
                        //    later save) and the restore is
                        //    audited. The old rule restored AUTO:
                        //    a corrupt restriction silently became
                        //    the widest mode.
                        connection = restoreConnection(parts, token)
                    )
                )
                // Legacy S1 format: 4 fields. New fields take defaults.
                parts.size == 4 -> pairings.add(
                    Pairing(
                        name = parts[0],
                        token = token,
                        scopes = parts[2].csvSet().filter { it in ALL_SCOPES }.toSet()
                            .ifEmpty { DEFAULT_SCOPES },
                        createdAtMs = parts[3].toLongOrNull() ?: 0L
                    )
                )
                // Anything else is a corrupt line; skip it, never crash.
                else -> Unit
            }
        }
        // Migration: re-write the store with every token wrapped, so
        // an upgrade leaves no plaintext bearer tokens on disk.
        if (sawPlaintextToken && cipher !is IdentityLineCipher) save()
    }

    private fun save() {
        val tmp = File(storeFile.parentFile, storeFile.name + ".tmp")
        tmp.writeText(pairings.joinToString("\n") { p ->
            // W98 / S09(b): fields 10–12 — connection mode,
            // restricted subset, manual pin ("" = none).
            // W108 / W105-C5: a fail-closed (needs-attention)
            // pairing writes its QUARANTINED original fields back
            // verbatim — an export/save must never overwrite the
            // corrupt record with the marker (or with AUTO, the
            // old destructive shape).
            val connectionFields = quarantinedConnectionFields[p.token]
                ?.takeIf { p.connection.needsAttention }
                ?.let { listOf(it.first, it.second, it.third) }
                ?: listOf(
                    p.connection.mode,
                    p.connection.rungs.joinToString(","),
                    p.connection.pin ?: ""
                )
            (listOf(
                p.name.tsvSafe(),
                cipher.encrypt(p.token),
                p.scopes.joinToString(","),
                p.createdAtMs.toString(),
                p.agentName.tsvSafe(),
                p.agentVersion.tsvSafe(),
                p.access,
                p.caps.joinToString(","),
                p.scopeIds.joinToString(",")
            ) + connectionFields).joinToString("\t")
        })
        tmp.renameTo(storeFile)
    }

    private fun String.csvSet(): Set<String> =
        split(',').filter { it.isNotBlank() }.toSet()

    /** Field values ride a TSV line, so tabs and newlines cannot survive. */
    private fun String.tsvSafe(): String = replace('\t', ' ').replace('\n', ' ')

    /** Constant-time comparison (0.4.0): MessageDigest.isEqual over
     *  the UTF-8 bytes, so token/code checks do not leak a prefix
     *  through timing. */
    private fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(
            a.toByteArray(Charsets.UTF_8),
            b.toByteArray(Charsets.UTF_8)
        )

    companion object {
        const val CODE_TTL_MS = 10 * 60 * 1000L
        /** Wrong guesses a live code tolerates before it burns. */
        const val MAX_REDEEM_ATTEMPTS = 5
        /** Delay a failed redemption imposes on the next attempt. */
        const val FAILURE_BACKOFF_MS = 500L
        /** Scopes a fresh pairing receives (SPEC §5.2: observe by default). */
        val DEFAULT_SCOPES = setOf("observe")

        // Access levels (SPEC §5.3).
        const val ACCESS_OBSERVE = "observe"
        const val ACCESS_FULL = "full"
        const val ACCESS_CUSTOM = "custom"

        // Capability keys (SPEC §5.3).
        const val CAP_SEE = "see"
        const val CAP_TAP = "tap"
        const val CAP_TYPE = "type"
        const val CAP_APPS = "apps"
        const val CAP_SHELL = "shell"
        const val CAP_SETTINGS = "settings"

        val ALL_CAPS = setOf(CAP_SEE, CAP_TAP, CAP_TYPE, CAP_APPS, CAP_SHELL, CAP_SETTINGS)
        val OBSERVE_CAPS = setOf(CAP_SEE)
        /** Caps that imply hands-on driving, for scope derivation. */
        val DRIVE_CAPS = setOf(CAP_TAP, CAP_TYPE, CAP_APPS)
        val ALL_SCOPES = setOf("observe", "drive", "shell", "admin")
    }
}

package io.deskguest.app.wiring

import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import io.deskguest.app.crypto.SecondFactorStore
import io.deskguest.app.crypto.SecretSealer
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.enterprise.PolicyEnforcer
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import io.deskguest.app.session.SessionTunnelStore
import io.deskguest.app.session.StandaloneTransferStore
import io.deskguest.app.wake.UdpWakeSender
import io.deskguest.app.wake.WakeStore
import io.deskguest.app.transport.DiscoveredDevice
import io.deskguest.app.transport.DiscoveryAnnouncement
import io.deskguest.app.transport.DiscoveryService
import io.deskguest.app.transport.HubMembership
import io.deskguest.app.transport.HubRung
import io.deskguest.app.transport.LanRung
import io.deskguest.app.transport.MeshRung
import io.deskguest.app.transport.MeshSetupFlow
import io.deskguest.app.transport.TransportEvent
import io.deskguest.app.transport.TransportSessionManager
import io.deskguest.app.transport.TransportTarget
import io.deskguest.app.recovery.RecoveryBlob
import io.deskguest.app.recovery.RecoveryBlobInfo
import io.deskguest.app.recovery.RecoveryContact
import io.deskguest.app.recovery.RecoveryExportResult
import io.deskguest.app.recovery.RecoveryPayloadData
import java.io.File
import java.time.Instant

/**
 * Wiring layer for Slices 1–3 (Block A, Android half): the ONE
 * holder through which every live surface — the app screens and the
 * MCP tool host — reaches the enrollment, roster, and session
 * stores, so a session (or device, or group) seen in the app is the
 * same record an agent sees over the channel. Pure JVM (no Android
 * imports) so the whole layer runs in the JVM suite; the Android
 * singleton lives in PlatformRuntime.
 *
 * Lifecycle discipline (standing lessons, do not regress):
 * - Construction opens the three TSV stores ONLY. The device
 *   identity seed is NOT loaded or created here: it loads lazily on
 *   the first [ownIdentity] call, through the injected [LineCipher]
 *   wrapping (the DeviceIdentity.save/load contract), and this
 *   holder is itself only ever created off the ControlService
 *   startup path (see PlatformRuntime) — the 0.4.3 Keystore-park
 *   lesson: nothing identity-shaped may sit on service startup.
 * - A corrupt identity file is never overwritten in place: it is
 *   preserved beside the new file as `device-identity.corrupt-<ts>`
 *   (the Windows F3 pattern) and a fresh identity is minted.
 * - Store files follow the PairingStore TSV persistence patterns
 *   (the stores' own atomic tmp+fsync+rename saves; corrupt lines
 *   skipped on load, never fatal — a corrupt store boots empty,
 *   it does not crash the surface).
 *
 * Consent discipline:
 * - [acceptLocal] is the ONLY honoured accept path in this layer:
 *   it calls the store with ACCEPT_ORIGIN_LOCAL_UI, the origin the
 *   endpoint's own UI generates. [acceptFromChannel] exists so any
 *   channel-shaped caller routes through the store's refusal (and
 *   its `accept_refused` event) instead of around it; it can never
 *   succeed — the store refuses every non-local origin, in every
 *   scope (RULING 2026-11-19).
 * - The endpoint surface reads roster data ONLY through
 *   [endpointSnapshot], which is built exclusively from
 *   RosterStore.endpointView(ownDeviceId) — the D2 shape in which
 *   other devices' records are ABSENT, not hidden. No other method
 *   in this class is called by the endpoint screen.
 */
class PlatformStores(
    private val dir: File,
    private val identityCipher: LineCipher = IdentityLineCipher,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {

    init {
        dir.mkdirs()
    }

    val enrollment: EnrollmentStore =
        // bd-and-core F6 fix (2026-11-22): the enrollment store now
        // receives the SAME injected cipher as the device identity
        // seed instead of a hardcoded IdentityLineCipher — when the
        // wiring layer supplies the Keystore-backed cipher (on a
        // recorded probe_ok verdict), enrollment records wrap too.
        EnrollmentStore(File(dir, ENROLLMENT_FILE), identityCipher, clockMs)

    init {
        // U9: the SAS responder key is this device's own identity
        // key (loaded lazily at redeem time, never at startup).
        enrollment.localPublicKeyProvider = { ownIdentity().publicKey }
    }

    val roster: RosterStore =
        RosterStore(File(dir, ROSTER_FILE), enrollment, clockMs)

    // TOTAL POLICY CONTROL gate (Block G): the layer that loads a
    // signed policy bundle installs its enforcer here; every
    // Block G store below consults it through these delegates.
    // Until then — and whenever no bundle is loaded — features
    // are not policy-gated (the owner's own device; the same
    // posture as the Windows EnterpriseService.CheckFeature).
    /** D38 Block H review F10: enforcer installs are serialized
     *  on this lock — two racing installs can no longer sweep
     *  under a bundle that is no longer current. */
    private val enforcerLock = Any()

    @Volatile
    var policyEnforcer: PolicyEnforcer? = null
        set(value) {
            synchronized(enforcerLock) {
                field = value
                // Block H (design 5) — policy-change teardown: when a
                // new enforcer is installed/replaced, everything its
                // bundle DISABLES is torn down in its scope on the
                // spot (live calls ended, blank/input/watermark
                // cleared, tunnels closed, standalone jobs cancelled)
                // instead of lingering until each surface's next act.
                // The consent floor is not a policy feature and no
                // sweep touches it.
                if (value != null) {
                    val scopeId = value.scopeId
                    // F10: the teardown predicate IS the gate
                    // predicate — checkFeature(scopeId, key), the
                    // exact call every feature gate makes — so a
                    // feature the gates refuse is torn down and a
                    // feature they permit is not, by construction
                    // (featureState was a second, divergent source
                    // of truth and is no longer consulted here).
                    val disabled: (String) -> Boolean =
                        { key -> !value.checkFeature(scopeId, key).first }
                    sessions.sweepPolicyTeardown(scopeId, disabled)
                    sessionTunnels.sweepPolicyTeardown(scopeId, disabled)
                    standaloneTransfers.sweepPolicyTeardown(scopeId, disabled)
                }
            }
        }

    // SCOPE-AWARE delegates (D38-G review F2): the enforcer's
    // bundle governs only its own scope; other scopes read the
    // not-policy-gated posture.
    private val featureGate: (String, String) -> Boolean = { scopeId, key ->
        policyEnforcer?.checkFeature(scopeId, key)?.first ?: true
    }
    private val featureRequired: (String, String) -> Boolean = { scopeId, key ->
        policyEnforcer?.featureRequired(scopeId, key) ?: false
    }

    val sessions: SessionStore =
        SessionStore(File(dir, SESSIONS_FILE), roster, enrollment, featureGate, featureRequired, clockMs)

    // Block G stores (2026-11-20): wake registry (G-01),
    // standalone transfers (G-04), local second factor (G-06 —
    // composed here for the first time; its TOTP secrets are
    // sealed with an AES-GCM cipher whose key the platform layer
    // supplies via [secondFactorSealer]), session tunnels (G-08).
    val wake: WakeStore = WakeStore(roster, enrollment, UdpWakeSender(), featureGate,
        localDeviceId = { try { ownDeviceId() } catch (_: Exception) { null } },
        onChanged = { persistWake() }, nowMillis = clockMs)

    val standaloneTransfers: StandaloneTransferStore =
        StandaloneTransferStore(roster, enrollment, featureGate,
            onChanged = { persistStandalone() }, nowMillis = clockMs)

    val sessionTunnels: SessionTunnelStore =
        SessionTunnelStore(sessions, roster, featureGate,
            // Block H (design 3): no host-config source exists on
            // Android yet, so the destination allowlist is NOT
            // configured here (null) — the pivot blocklist inside
            // the store remains the tunnel destination control.
            allowedTargets = null,
            onChanged = { persistTunnels() }, nowMillis = clockMs)

    // AF10: the Block G stores PERSIST through this layer — each
    // store's recorded acts write its JSON file through
    // (tmp + rename), and construction restores what a previous
    // run left. Before this wiring the four stores were
    // memory-only: wake targets, factors, and the TOTP replay
    // counter died with the process.
    init {
        readStoreFile(WAKE_FILE)?.let { try { wake.importJson(it) } catch (_: Exception) { } }
        readStoreFile(STANDALONE_FILE)?.let { try { standaloneTransfers.importJson(it) } catch (_: Exception) { } }
        readStoreFile(TUNNELS_FILE)?.let { try { sessionTunnels.importJson(it) } catch (_: Exception) { } }
    }

    private fun writeStoreFile(name: String, content: String) {
        try {
            val tmp = File(dir, "$name.tmp")
            tmp.writeText(content)
            if (!tmp.renameTo(File(dir, name))) {
                File(dir, name).writeText(content)
                tmp.delete()
            }
        } catch (_: Exception) { }
    }

    private fun readStoreFile(name: String): String? =
        try { File(dir, name).takeIf { it.exists() }?.readText() } catch (_: Exception) { null }

    private fun persistWake() = writeStoreFile(WAKE_FILE, wake.exportJson())
    private fun persistStandalone() = writeStoreFile(STANDALONE_FILE, standaloneTransfers.exportJson())
    private fun persistTunnels() = writeStoreFile(TUNNELS_FILE, sessionTunnels.exportJson())
    private fun persistFactors() {
        val store = secondFactorsRef ?: return
        writeStoreFile(FACTORS_FILE, store.exportJson())
    }

    /** The second-factor store, composed lazily: sealing needs a
     *  platform key (Android Keystore), and nothing key-shaped
     *  may sit on a service startup path (the 0.4.3 lesson). The
     *  platform layer passes its Keystore-backed sealer on first
     *  use. */
    @Volatile
    private var secondFactorsRef: SecondFactorStore? = null

    @Synchronized
    fun secondFactors(sealer: SecretSealer): SecondFactorStore =
        secondFactorsRef ?: SecondFactorStore(roster, sealer, featureGate,
            onChanged = { persistFactors() }, nowMillis = clockMs)
            .also {
                secondFactorsRef = it
                readStoreFile(FACTORS_FILE)?.let { json ->
                    try { it.importJson(json) } catch (_: Exception) { }
                }
            }

    private val identityFile: File = File(dir, IDENTITY_FILE)

    @Volatile
    private var identity: DeviceIdentity? = null

    // ---- identity (lazy) ----

    /**
     * This device's identity, loaded (or first created) on first
     * use — never at holder construction, never on any service
     * startup path. A file that exists but does not load (corrupt,
     * wrong key, planted plaintext under a wrapping cipher) is
     * preserved as a `.corrupt-<ts>` sibling and a fresh identity
     * takes its place; the corrupt bytes are never silently
     * overwritten and never used.
     */
    @Synchronized
    fun ownIdentity(): DeviceIdentity {
        identity?.let { return it }
        DeviceIdentity.load(identityFile, identityCipher)?.let {
            identity = it
            return it
        }
        if (identityFile.exists()) {
            val preserved = File(dir, "$IDENTITY_FILE.corrupt-${clockMs()}")
            try {
                identityFile.renameTo(preserved)
            } catch (_: Exception) {
                // Preservation is best-effort; minting must not be
                // blocked by a rename failure on a hostile file.
            }
        }
        val fresh = DeviceIdentity.generate()
        // W13 P4-F6: plaintext storage only when the at-rest
        // probe actually fell back — stated here, at the call site.
        fresh.save(identityFile, identityCipher, allowPlaintext = identityCipher === IdentityLineCipher)
        identity = fresh
        return fresh
    }

    /** True once the identity has been loaded/created in this process. */
    fun identityLoaded(): Boolean = identity != null

    fun ownDeviceId(): String = ownIdentity().deviceId

    // ---- endpoint view (D2) — the endpoint screen's only roster read ----

    /** Everything the endpoint screen may show about roster state:
     *  its own identity, its own enrolled record, its own receipts,
     *  and the allowed-operators list derived from them. Built ONLY
     *  from endpointView(ownDeviceId); when this device is not
     *  enrolled, the record/receipts/operators are empty — there is
     *  no fallback that widens the view. */
    data class EndpointSnapshot(
        val deviceId: String,
        val publicKeyBase64: String,
        val ownRecord: EnrollmentStore.EnrolledDevice?,
        val receipts: List<EnrollmentStore.EnrollmentReceipt>,
        val allowedOperators: List<RosterStore.AllowedOperator>
    )

    fun endpointSnapshot(): EndpointSnapshot {
        val id = ownIdentity()
        val view = roster.endpointView(id.deviceId)
        return EndpointSnapshot(
            deviceId = id.deviceId,
            publicKeyBase64 = id.publicKeyBase64,
            ownRecord = view?.device,
            receipts = view?.receipts ?: emptyList(),
            allowedOperators = view?.allowedOperators ?: emptyList()
        )
    }

    // ---- enrollment flows ----

    /** Mint a one-time enrollment code; scope/group (and transport)
     *  are bound HERE, at mint — redemption can never widen them. */
    fun mintEnrollment(
        scope: String,
        groupId: String,
        groupName: String,
        transportMode: String = EnrollmentStore.TRANSPORT_MODE_INHERIT,
        allowedTransports: Set<String> = emptySet(),
        ownerUserId: String = ""
    ): String = enrollment.mint(scope, groupId, groupName, EnrollmentStore.CODE_TTL_MS, transportMode, allowedTransports, ownerUserId)

    fun currentEnrollmentCode(): String? = enrollment.currentCode()

    /**
     * Redeem [code] for THIS device: the presented DeviceId and key
     * are always this device's own identity (the store verifies the
     * DeviceId↔key binding and refuses a mismatch, a revoked record,
     * or a key swap). On success the endpoint records its receipt —
     * who enrolled it — from the enroller fields the person at this
     * device entered from the operator who handed them the code.
     */
    fun redeemOwn(
        code: String,
        deviceDisplayName: String,
        enrollerName: String,
        enrollerDeviceId: String
    ): EnrollmentStore.EnrolledDevice? {
        val id = ownIdentity()
        val enrolled = enrollment.redeem(
            code,
            EnrollmentStore.EnrollingDevice(id.deviceId, id.publicKeyBase64, deviceDisplayName)
        ) ?: return null
        enrollment.recordReceipt(
            EnrollmentStore.EnrollmentReceipt(
                enrollerName = enrollerName,
                enrollerDeviceId = enrollerDeviceId,
                scope = enrolled.scope,
                groupName = enrolled.groupName,
                enrolledAtMs = enrolled.enrolledAtMs
            )
        )
        return enrolled
    }

    // ---- roster (operator side) — the store enforces every gate;
    // this layer passes the actor through unchanged and never
    // substitutes, widens, or retries with a different actor. ----

    fun scopes(): List<RosterStore.Scope> = roster.allScopes()

    fun addScope(id: String, kind: String, name: String): Boolean =
        roster.addScope(RosterStore.Scope(id, kind, name))

    fun addUser(scopeId: String, userId: String, displayName: String, kind: String, pairedByUserId: String? = null): Boolean =
        roster.addUser(RosterStore.User(userId, scopeId, displayName, kind, pairedByUserId))

    fun addCompanyAdmin(scopeId: String, userId: String, actorUserId: String? = null): Boolean =
        roster.addCompanyAdmin(scopeId, userId, actorUserId)

    fun removeCompanyAdmin(scopeId: String, userId: String, actorUserId: String, stepUp: Boolean): Boolean =
        roster.removeCompanyAdmin(scopeId, userId, actorUserId, stepUp)

    fun setUserSuspended(scopeId: String, userId: String, suspended: Boolean, actorUserId: String, stepUp: Boolean = false): Boolean {
        val ok = roster.setUserSuspended(scopeId, userId, suspended, actorUserId, stepUp)
        if (ok && suspended) {
            // AF2: suspension lands on the user's live transfers now,
            // not at their next act.
            standaloneTransfers.cancelJobsFor(initiatorUserId = userId, actorUserId = actorUserId)
        }
        return ok
    }

    fun addUserGroup(scopeId: String, groupId: String, name: String, actorUserId: String): Boolean =
        roster.addUserGroup(RosterStore.UserGroup(groupId, scopeId, name), actorUserId)

    fun addUserToGroup(scopeId: String, groupId: String, userId: String, actorUserId: String): Boolean =
        roster.addUserToGroup(scopeId, groupId, userId, actorUserId)

    fun removeUserFromGroup(scopeId: String, groupId: String, userId: String, actorUserId: String): Boolean =
        roster.removeUserFromGroup(scopeId, groupId, userId, actorUserId)

    fun addDeviceGroup(scopeId: String, groupId: String, name: String, transportSet: List<String>, actorUserId: String): Boolean =
        roster.addDeviceGroup(RosterStore.DeviceGroup(groupId, scopeId, name, transportSet), actorUserId)

    fun setGroupTransports(scopeId: String, groupId: String, transports: List<String>, actorUserId: String): Boolean =
        roster.setGroupTransports(scopeId, groupId, transports, actorUserId)

    fun addGrant(scopeId: String, userGroupId: String, deviceGroupId: String, rights: Set<String>, actorUserId: String): Boolean =
        roster.addGrant(RosterStore.Grant(scopeId, userGroupId, deviceGroupId, rights), actorUserId)

    /** Structural acts — gated exactly as the store enforces (D7). */
    fun deleteUserGroup(scopeId: String, groupId: String, actorUserId: String): Boolean =
        roster.deleteUserGroup(scopeId, groupId, actorUserId)

    fun deleteDeviceGroup(scopeId: String, groupId: String, actorUserId: String): Boolean =
        roster.deleteDeviceGroup(scopeId, groupId, actorUserId)

    fun deleteDevice(scopeId: String, deviceId: String, actorUserId: String): Boolean {
        val ok = roster.deleteDevice(scopeId, deviceId, actorUserId)
        if (ok) {
            // AF2: a deleted device's transfers cancel and its
            // sessions' tunnels close, eagerly.
            standaloneTransfers.cancelJobsFor(deviceId = deviceId, actorUserId = actorUserId)
            for (s in sessions.sessionsInScope(scopeId)) {
                if (s.hostDeviceId == deviceId) sessionTunnels.closeForSession(s.id, actorUserId)
            }
        }
        return ok
    }

    fun operatorRoster(scopeId: String): RosterStore.OperatorRoster? = roster.operatorRoster(scopeId)

    /** D14: the blast list, computed WITHOUT firing. The UI shows
     *  this before [offboard] can be called. */
    fun offboardPreview(scopeId: String, userId: String): RosterStore.BlastList? =
        roster.blastList(scopeId, userId)

    /** D14: fire an offboarding whose blast list was previewed. */
    fun offboard(scopeId: String, userId: String, actorUserId: String, stepUp: Boolean): RosterStore.RemoveOutcome {
        val outcome = roster.removeUser(scopeId, userId, actorUserId, stepUp)
        if (outcome.fired) {
            // AF2: offboarding lands on the user's live standalone
            // transfers in the same act (their sessions end through
            // the session store's own offboarding re-reads, and the
            // tunnel reads sweep what those endings leave behind).
            standaloneTransfers.cancelJobsFor(initiatorUserId = userId, actorUserId = actorUserId)
        }
        return outcome
    }

    fun effectiveTransportsFor(scopeId: String, deviceId: String): List<String>? =
        roster.effectiveTransportsFor(scopeId, deviceId)

    // ---- sessions ----

    data class SessionDetail(
        val session: SessionStore.Session,
        val participants: List<SessionStore.Participant>,
        val events: List<SessionStore.SessionEvent>,
        val floorHolderUserId: String?,
        val isRecording: Boolean
    )

    /** Every session in every scope this device holds — the session
     *  screen's list and the MCP surface's list are this same call. */
    fun allSessions(): List<SessionStore.Session> =
        roster.allScopes().flatMap { sessions.sessionsInScope(it.id) }
            .distinctBy { it.id }
            .sortedBy { it.startedUtc }

    /**
     * bd-and-core F12 fix (2026-11-22): the presence badges the
     * SessionStore record derives — for every non-ended session:
     * "Recording" while its recording flag is live, "Screen blanked
     * for remote viewer" while blanked, "Input blocked" while
     * input-blocked. PresenceOverlay renders these non-hideably
     * (ControlService installs this as its badge provider), which
     * makes the model's G-02/G-03/G-07 claim true on the phone.
     */
    fun liveSessionBadges(): List<String> {
        val out = mutableListOf<String>()
        for (s in allSessions()) {
            if (s.state == SessionStore.STATE_ENDED) continue
            if (s.isRecording) out += "Recording"
            if (s.blanked) out += "Screen blanked for remote viewer"
            if (s.inputBlocked) out += "Input blocked"
        }
        return out.distinct()
    }

    fun sessionDetail(sessionId: String): SessionDetail? {
        val session = sessions.session(sessionId) ?: return null
        val parts = sessions.participants(sessionId)
        return SessionDetail(
            session = session,
            participants = parts,
            events = sessions.events(sessionId),
            floorHolderUserId = parts.firstOrNull { it.floor == SessionStore.FLOOR_HOLDS }?.userId,
            isRecording = session.isRecording
        )
    }

    fun createSession(
        sessionId: String,
        scopeId: String,
        hostDeviceId: String,
        initiatorUserId: String,
        hostUserId: String,
        kind: String,
        transportRung: String,
        recording: String = SessionStore.RECORDING_NONE,
        recordingRef: String? = null
    ): Boolean = sessions.createSession(
        SessionStore.Session(
            id = sessionId,
            scopeId = scopeId,
            hostDeviceId = hostDeviceId,
            initiatorUserId = initiatorUserId,
            kind = kind,
            transportRung = transportRung,
            recording = recording,
            recordingRef = recordingRef
        ),
        hostUserId
    )

    /** The ONLY honoured accept: the endpoint-local UI origin. The
     *  sessions screen is this origin — a person at this device
     *  tapping Accept. */
    fun acceptLocal(sessionId: String, acceptByUserId: String): Boolean =
        sessions.acceptSession(sessionId, acceptByUserId, SessionStore.ACCEPT_ORIGIN_LOCAL_UI)

    /** The channel path: routed through the store so the refusal
     *  (and its accept_refused event) is the store's own. It can
     *  never succeed — no scope, no caller, no state (RULING
     *  2026-11-19). No live surface calls this; it exists so a
     *  channel-shaped accept attempt has exactly one door, and the
     *  door is shut. */
    fun acceptFromChannel(sessionId: String, acceptByUserId: String): Boolean =
        sessions.acceptSession(sessionId, acceptByUserId, SessionStore.ACCEPT_ORIGIN_INITIATING_CHANNEL)

    fun startSession(sessionId: String, actorUserId: String): Boolean =
        sessions.startSession(sessionId, actorUserId)

    fun pauseSession(sessionId: String, actorUserId: String): Boolean =
        sessions.pauseSession(sessionId, actorUserId)

    fun blockSession(sessionId: String, actorUserId: String): Boolean {
        val ok = sessions.blockSession(sessionId, actorUserId)
        if (ok) sessionTunnels.closeForSession(sessionId, actorUserId) // AF2 sweep
        return ok
    }

    fun endSession(sessionId: String, actorUserId: String): Boolean {
        val ok = sessions.endSession(sessionId, actorUserId)
        if (ok) sessionTunnels.closeForSession(sessionId, actorUserId) // AF2 sweep
        return ok
    }

    /** STOP: terminates from every non-ended state (host actor or
     *  company admin, as the store enforces). */
    fun stopSession(sessionId: String, actorUserId: String): Boolean {
        val ok = sessions.stopSession(sessionId, actorUserId)
        if (ok) sessionTunnels.closeForSession(sessionId, actorUserId) // AF2: STOP leaves no tunnel standing
        return ok
    }

    /** bd-and-rest F2: the endpoint-local STOP — the person at this
     *  device pressing STOP on its own screen. Needs no actor and
     *  can never be refused over a typed actor value (see
     *  SessionStore.stopLocalSession); tunnels close as with any
     *  STOP, under the resolved host actor. */
    fun stopSessionLocal(sessionId: String): Boolean {
        val hostUserId = sessions.participants(sessionId)
            .firstOrNull { it.role == SessionStore.ROLE_HOST }?.userId
        val ok = sessions.stopLocalSession(sessionId)
        if (ok && hostUserId != null) sessionTunnels.closeForSession(sessionId, hostUserId)
        return ok
    }

    fun grantFloor(sessionId: String, actorUserId: String, targetUserId: String): Boolean =
        sessions.grantFloor(sessionId, actorUserId, targetUserId)

    fun takeFloorBack(sessionId: String, actorUserId: String): Boolean =
        sessions.takeFloorBack(sessionId, actorUserId)

    fun setWatchOnly(sessionId: String, actorUserId: String, targetUserId: String): Boolean =
        sessions.setWatchOnly(sessionId, actorUserId, targetUserId)

    fun removeParticipant(sessionId: String, actorUserId: String, userId: String): Boolean =
        sessions.removeParticipant(sessionId, actorUserId, userId)

    fun enforceOffboarding(sessionId: String): Boolean = sessions.enforceOffboarding(sessionId)

    // ---- Block C transport core (D19/D29/D32) ----
    // The failover engine over the live stores. Built lazily: it
    // holds the device identity, which loads only on first use
    // (never on the ControlService startup path — the same lazy
    // rule as [ownIdentity]). Registered rungs: `lan` (part 1),
    // `hub` and `mesh` (part 3). The hub rung gates on
    // [hubMembership]; the mesh rung admits nothing until
    // [meshSetupFlow] completes — on Android that is the TS-03
    // operator-personal carve-out path only.

    /** DeskGuest's hub-node registry for this install (part 3).
     *  W4 F6-remainder wiring: constructed WITH its persistence
     *  file, so joins/decommissions/reconciliations survive the
     *  process (the W3 seam was built but never wired). */
    val hubMembership = HubMembership(File(dir, HUB_FILE))

    /** The in-app Tailscale setup state machine (part 3, D4).
     *  W4 F6-remainder wiring: the state sink persists every
     *  transition and a persisted state restores at construction,
     *  so a completed setup (Ready) survives a restart instead of
     *  silently reverting to NotStarted. */
    val meshSetupFlow: MeshSetupFlow = MeshSetupFlow(
        stateSink = { state ->
            writeStoreFile(MESH_FILE, org.json.JSONObject()
                .put("stage", state.stage).put("detail", state.detail)
                .put("carveOut", state.carveOut).toString())
        },
        restored = readStoreFile(MESH_FILE)?.let { text ->
            try {
                val o = org.json.JSONObject(text)
                val stage = o.optString("stage")
                if (stage.isBlank()) null else io.deskguest.app.transport.MeshSetupState(
                    stage, o.optString("detail"), o.optBoolean("carveOut", false))
            } catch (_: Exception) { null }
        }
    )

    private var transportManager: TransportSessionManager? = null

    private fun transport(): TransportSessionManager =
        transportManager ?: TransportSessionManager(
            roster, sessions,
            listOf(LanRung(), HubRung(hubMembership), MeshRung({ meshSetupFlow.state })),
            ownIdentity(), enrollment
        ).also { transportManager = it }

    /** Start a session over the transport layer: the engine walks
     *  the device's resolved transport set in order; the session
     *  record's rung is the rung that actually carried it. An
     *  [address] (host or host:port) is the connect-by-address path
     *  on the `lan` rung (D19). Returns the new session id, or null
     *  when every rung failed / the start was refused — the engine
     *  events ([transportEvents]) carry the reasons. */
    fun startTransportSession(
        scopeId: String,
        hostDeviceId: String,
        initiatorUserId: String,
        hostUserId: String,
        kind: String,
        address: String? = null,
        hubAddress: String? = null,
        meshAddress: String? = null,
        recording: String = SessionStore.RECORDING_NONE,
        manualPins: List<String>? = null
    ): String? {
        val targets = mutableMapOf<String, TransportTarget>()
        if (!address.isNullOrBlank()) targets["lan"] = TransportTarget(hostDeviceId, address.trim())
        if (!hubAddress.isNullOrBlank()) targets["hub"] = TransportTarget(hostDeviceId, hubAddress.trim())
        if (!meshAddress.isNullOrBlank()) targets["mesh"] = TransportTarget(hostDeviceId, meshAddress.trim())
        return transport().startSession(
            scopeId, hostDeviceId, initiatorUserId, hostUserId, kind, targets, recording, manualPins
        )?.id
    }

    /** Re-establish a transport-carried session on the next rung
     *  of its resolved set (the old session ends with reason
     *  transport_failover — a reconnect, honestly). Returns the
     *  NEW session id, or null when there is no next rung. */
    fun reestablishTransportSession(
        sessionId: String,
        address: String? = null,
        hubAddress: String? = null,
        meshAddress: String? = null
    ): String? {
        val hostDeviceId = sessions.session(sessionId)?.hostDeviceId ?: ""
        val targets = mutableMapOf<String, TransportTarget>()
        if (!address.isNullOrBlank()) targets["lan"] = TransportTarget(hostDeviceId, address.trim())
        if (!hubAddress.isNullOrBlank()) targets["hub"] = TransportTarget(hostDeviceId, hubAddress.trim())
        if (!meshAddress.isNullOrBlank()) targets["mesh"] = TransportTarget(hostDeviceId, meshAddress.trim())
        return transport().reestablish(sessionId, targets)?.id
    }

    fun transportEvents(): List<TransportEvent> =
        transportManager?.events() ?: emptyList()

    // ---- host listener production binding (W4) -------------------
    // The Android host listener, owned here so ControlService can
    // start/stop it with the control channel. Built lazily like
    // the transport manager: it holds the device identity, which
    // loads only on first use. Presence hooks are installed by
    // ControlService (the Android layer); unset, attach/detach are
    // no-ops and the SessionStore record + its events remain the
    // presence source of truth (liveSessionBadges).

    /** (sessionId, peerDeviceId) — fired when a network session
     *  record is created, before the peer learns its id. */
    @Volatile
    var hostPresenceAttach: ((String, String) -> Unit)? = null

    /** (sessionId) — fired exactly once per network session end. */
    @Volatile
    var hostPresenceDetach: ((String) -> Unit)? = null

    private var hostListenerRef: io.deskguest.app.transport.HostListenerService? = null

    @Synchronized
    fun hostListener(): io.deskguest.app.transport.HostListenerService =
        hostListenerRef ?: io.deskguest.app.transport.HostListenerService(
            io.deskguest.app.transport.HostSessionBinding(
                sessions, enrollment,
                ownDeviceId = { ownDeviceId() },
                enrollerName = { "" },
                presenceAttach = { sid, peer -> hostPresenceAttach?.invoke(sid, peer) },
                presenceDetach = { sid -> hostPresenceDetach?.invoke(sid) }
            ),
            enrollment, ownIdentity()
        ).also { hostListenerRef = it }

    /** Start listening for enrolled peers. The bind address is the
     *  caller's explicit choice (the listener refuses wildcards);
     *  ControlService passes the tailnet address. False when the
     *  bind failed — the service records it, never hides it. */
    fun startHostListener(bindAddress: java.net.InetAddress, port: Int = io.deskguest.app.transport.LanProtocol.DEFAULT_PORT): Boolean =
        hostListener().start(bindAddress, port)

    fun stopHostListener() {
        hostListenerRef?.stop()
    }

    val hostListenerRunning: Boolean get() = hostListenerRef?.isRunning == true

    // ---- RMM services composition (bd-and-rest F5 wiring) --------
    // Backup / Deploy / VendorPass / MobileOperator were standalone
    // classes nothing composed. They are composed HERE, over the
    // live stores: roster rights are the real roster's, parties are
    // the real roster's users, backup sources are this layer's own
    // store files (ids/names/state only — D22: no secrets in these
    // files), content packs persist through this layer's files, and
    // every service's ChainedAudit forwards to [rmmAuditSink] (the
    // app's shared AuditStore, installed by MainActivity) through
    // SharedAuditBridge.

    /** (kind, detail) — installed by the Android layer to the
     *  shared encrypted AuditStore. Installing it also arms the
     *  SharedAuditBridge every RMM ChainedAudit forwards through. */
    @Volatile
    var rmmAuditSink: ((String, String) -> Unit)? = null
        set(value) {
            field = value
            io.deskguest.app.cameraview.SharedAuditBridge.sink =
                value?.let { sink -> { type, detail -> sink(type, detail) } }
        }

    fun backupService(): io.deskguest.app.backup.BackupService =
        io.deskguest.app.backup.BackupService(
            stores = io.deskguest.app.backup.StoreSource {
                listOf(ENROLLMENT_FILE, ROSTER_FILE, SESSIONS_FILE, WAKE_FILE, STANDALONE_FILE, TUNNELS_FILE)
                    .mapNotNull { name ->
                        val f = File(dir, name)
                        if (f.exists()) name to f.readBytes() else null
                    }.toMap()
            },
            clockMs = clockMs,
            // The manifest HMAC key is this device's identity seed:
            // device-held, never stored beside the backup.
            manifestKey = ownIdentity().seedCopy(),
            // W5 payload encryption at rest: the payload key is
            // HKDF-derived from the same identity seed — the one
            // user-controlled secret in-tree. The seed lives wrapped
            // by the Android Keystore line cipher and moves between
            // devices only through the user's C20 recovery export /
            // restore (passphrase or key sheet), so an encrypted
            // backup opens exactly where the user's identity has
            // been recovered, and nowhere else.
            payloadKey = io.deskguest.app.adb.Hkdf.sha256(
                ownIdentity().seedCopy(),
                "deskguest-backup-v2".toByteArray(Charsets.UTF_8),
                "deskguest-backup-payload-key-v2".toByteArray(Charsets.UTF_8),
                32
            )
        )

    fun deployService(
        verifier: io.deskguest.app.deploy.SignatureVerifier,
        installer: io.deskguest.app.deploy.InstallerHandoff,
        payloadInstaller: io.deskguest.app.deploy.PayloadInstallerHandoff? = null
    ): io.deskguest.app.deploy.DeployService {
        val service = io.deskguest.app.deploy.DeployService(
            verifier, installer,
            payloadInstaller = payloadInstaller,
            packSink = { pack ->
                val packs = readContentPacks().toMutableList()
                packs.removeAll { it.id == pack.id }
                packs.add(pack)
                writeStoreFile(PACKS_FILE, org.json.JSONArray().apply {
                    for (p in packs) put(org.json.JSONObject()
                        .put("id", p.id).put("title", p.title).put("hash", p.hash)
                        .put("entries", org.json.JSONArray(p.entries)))
                }.toString())
            }
        )
        readContentPacks().forEach { service.restorePack(it) }
        return service
    }

    private fun readContentPacks(): List<io.deskguest.app.deploy.ContentPack> {
        val text = readStoreFile(PACKS_FILE) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(text)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val entriesArr = o.optJSONArray("entries")
                val entries = if (entriesArr == null) emptyList()
                    else (0 until entriesArr.length()).map { entriesArr.optString(it) }
                io.deskguest.app.deploy.ContentPack(
                    o.optString("id"), o.optString("title"), entries, o.optString("hash"))
            }
        } catch (_: Exception) { emptyList() }
    }

    fun vendorPassService(): io.deskguest.app.vendorpass.VendorPassService =
        io.deskguest.app.vendorpass.VendorPassService(
            rights = io.deskguest.app.vendorpass.PassRights { scopeId, userId, deviceGroupId, right ->
                roster.userHasRight(scopeId, userId, deviceGroupId, right)
            },
            parties = io.deskguest.app.vendorpass.LiveParty { scopeId, userId ->
                roster.user(userId)?.let { it.scopeId == scopeId && !it.suspended } == true
            },
            clockMs = clockMs
        )

    fun mobileOperatorClient(
        scopeId: String, userId: String,
        hubKeys: io.deskguest.app.mobileop.HubKeyVerifier,
        clientKeys: io.deskguest.app.mobileop.ClientKeySigner,
        alerts: io.deskguest.app.mobileop.AlertLookup
    ): io.deskguest.app.mobileop.MobileOperatorClient =
        io.deskguest.app.mobileop.MobileOperatorClient(
            scopeId, userId,
            io.deskguest.app.mobileop.RosterRights { s, u, g -> roster.rightsFor(s, u, g) },
            hubKeys, clientKeys, alerts
        )

    // ---- local discovery (D19/D20) ----
    // Announcement + browse, formalized: an announcement carries
    // ONLY a hash of the device id, a display name, and an
    // enrollment state. Browse classifies what it hears against
    // this install's enrolled devices (matched by hash). Discovery
    // grants NO trust — a discovered device is never controllable
    // from discovery; control requires enrollment and the
    // proof-of-possession handshake. Browse is a bounded window,
    // never a background scan (D20: DeskGuest never scans).

    /** A discovery service whose known peers are this install's
     *  enrolled devices. */
    fun discoveryService(): DiscoveryService =
        DiscoveryService(enrollment.all().map { it.deviceId })

    /** This device's own announcement, or null when its name is
     *  not announceable. Enrollment state is this device's real
     *  state: enrolled (unrevoked record of its own id) or
     *  available. */
    fun ownAnnouncement(displayName: String): DiscoveryAnnouncement? {
        val own = enrollment.byId(ownDeviceId())
        return DiscoveryAnnouncement.forDevice(
            ownDeviceId(), displayName, enrolled = own != null && !own.revoked
        )
    }

    /** Announce this device once on the local network. False when
     *  the announcement could not be built or sent. */
    fun announceDiscovery(displayName: String): Boolean {
        val announcement = ownAnnouncement(displayName) ?: return false
        return try {
            discoveryService().announce(announcement)
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Listen for announcements for one bounded window and return
     *  the unique devices heard, classified. Blocks the calling
     *  thread for the window — UI callers run it off the main
     *  thread. */
    fun browseDiscovery(windowMs: Long = 3_000): List<DiscoveredDevice> =
        discoveryService().browse(windowMs)

    // ---- C20 recovery blob wiring (2026-11-22) --------------------
    // Owner-local acts ONLY: these methods are called from the app's
    // own home-screen recovery section (MainActivity) — there is no
    // MCP/tool path into them (the tool host never references this
    // section), mirroring the Windows owner_takeover discipline.
    //
    // Keystore seam (per the C20 record): the identity seed is
    // unwrapped through the identity LineCipher by [ownIdentity]
    // (DeviceIdentity.load under the cipher) and handed to the blob
    // as raw seed; the blob re-wraps it under the recovery key.
    // Keystore keys never leave the device. On restore the returned
    // seed is re-wrapped under this device's cipher via
    // DeviceIdentity.fromSeed(seed).save(file, cipher, overwrite = true) — W13 P4-F19: the documented form names the overwrite explicitly; save()'s default remains false.
    //
    // Store exports are the stores' own TSV files, carried opaquely
    // (the C20 design): the enrollment file rides the payload's
    // pairings slot, the roster file its roster slot.
    //
    // Audit: export/restore acts (and refusals) are reported through
    // [recoveryAudit] with FIXED outcome strings + the device id
    // only. A refusal's exception message can quote a mistyped
    // key-sheet word, so messages are returned to the owner surface
    // but NEVER passed to the audit hook — the sheet cannot leak
    // into the log through this layer.

    /** (kind, ok, detail) — wired by MainActivity to the AuditStore.
     *  Detail carries a device id or a fixed outcome word, never a
     *  credential, never exception text. */
    @Volatile
    var recoveryAudit: ((String, Boolean, String) -> Unit)? = null

    @Volatile
    var lastRecoveryExportMs: Long? = null
        private set

    /** Presence-visible record of the last restore on this endpoint:
     *  the home screen renders it, so a restore is a visible event,
     *  not a silent state swap. */
    data class RecoveryRestoreRecord(val deviceId: String, val atMs: Long)

    @Volatile
    var lastRecoveryRestore: RecoveryRestoreRecord? = null
        private set

    private val enrollmentFile: File = File(dir, ENROLLMENT_FILE)
    private val rosterFile: File = File(dir, ROSTER_FILE)

    private fun readStoreText(file: File): String =
        try { if (file.exists()) file.readText() else "" } catch (_: Exception) { "" }

    private fun writeStoreTextAtomic(file: File, content: String) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(content)
        if (!tmp.renameTo(file)) {
            file.writeText(content)
            tmp.delete()
        }
    }

    /** Export the recovery artefact set for this device. The result
     *  carries the key sheet — the caller (the home screen) shows it
     *  ONCE and drops it; nothing here persists it. */
    @Synchronized
    fun exportRecoveryBlob(
        passphrase: String,
        contacts: List<RecoveryContact> = emptyList()
    ): RecoveryExportResult {
        try {
            val id = ownIdentity()
            val result = RecoveryBlob.export(
                identitySeed = id.seedCopy(),
                deviceId = id.deviceId,
                pairingsExport = readStoreText(enrollmentFile),
                rosterExport = readStoreText(rosterFile),
                passphrase = passphrase,
                contacts = contacts,
                createdUtc = Instant.ofEpochMilli(clockMs()).toString()
            )
            lastRecoveryExportMs = clockMs()
            recoveryAudit?.invoke("recovery_exported", true, result.deviceId)
            return result
        } catch (e: Exception) {
            recoveryAudit?.invoke("recovery_export_refused", false, "recovery")
            throw e
        }
    }

    /** Public metadata of a blob the owner picked. Not audited:
     *  inspecting a held file is not an act on this device's state. */
    fun inspectRecoveryBlob(blob: ByteArray): RecoveryBlobInfo = RecoveryBlob.inspect(blob)

    /** An identity counts as LIVE (restore-blocking) when it is in
     *  use: an unrevoked enrollment record exists, or any roster
     *  scope exists. A lazily minted identity on a fresh install —
     *  file present, stores empty, never enrolled — is replaceable,
     *  exactly the replacement-device case recovery exists for. */
    private fun recoveryLiveIdentityExists(): Boolean =
        enrollment.all().any { !it.revoked } || roster.allScopes().isNotEmpty()

    private fun recoveryTargetStoresEmpty(): Boolean =
        enrollment.all().isEmpty() && roster.allScopes().isEmpty() && allSessions().isEmpty()

    private fun applyRecovery(payload: RecoveryPayloadData) {
        // Stores first (files, then reload the live stores from
        // them), identity last: the seed was already verified to
        // reproduce the payload's device id inside RecoveryBlob.
        writeStoreTextAtomic(enrollmentFile, payload.pairingsExport)
        writeStoreTextAtomic(rosterFile, payload.rosterExport)
        enrollment.reloadForRecovery()
        roster.reloadForRecovery()
        val restored = DeviceIdentity.fromSeed(payload.identitySeed)
        restored.save(identityFile, identityCipher, overwrite = true,
            allowPlaintext = identityCipher === IdentityLineCipher)
        identity = restored
    }

    private fun finishRecoveryRestore(payload: RecoveryPayloadData): RecoveryPayloadData {
        lastRecoveryRestore = RecoveryRestoreRecord(payload.deviceId, clockMs())
        recoveryAudit?.invoke("recovery_restored", true, payload.deviceId)
        return payload
    }

    /** Restore from a PRIMARY blob (passphrase or key sheet) into
     *  empty stores. Every refusal is the C20 layer's loud exception;
     *  refusals are audited with a fixed string (see class note). */
    @Synchronized
    fun restoreRecoveryBlobPrimary(
        blob: ByteArray,
        passphrase: String?,
        keySheet: String?
    ): RecoveryPayloadData {
        try {
            return finishRecoveryRestore(RecoveryBlob.restorePrimary(
                blob, passphrase, keySheet,
                liveIdentityExists = { recoveryLiveIdentityExists() },
                targetStoresEmpty = { recoveryTargetStoresEmpty() },
                apply = { applyRecovery(it) }
            ))
        } catch (e: Exception) {
            recoveryAudit?.invoke("recovery_restore_refused", false, "recovery")
            throw e
        }
    }

    /** Restore from a SEALED CONTACT copy (contact seed + key sheet). */
    @Synchronized
    fun restoreRecoveryBlobFromContactCopy(
        blob: ByteArray,
        contactSeed: ByteArray,
        keySheet: String
    ): RecoveryPayloadData {
        try {
            return finishRecoveryRestore(RecoveryBlob.restoreFromContactCopy(
                blob, contactSeed, keySheet,
                liveIdentityExists = { recoveryLiveIdentityExists() },
                targetStoresEmpty = { recoveryTargetStoresEmpty() },
                apply = { applyRecovery(it) }
            ))
        } catch (e: Exception) {
            recoveryAudit?.invoke("recovery_restore_refused", false, "recovery")
            throw e
        }
    }

    companion object {
        const val IDENTITY_FILE = "device-identity.txt"
        const val ENROLLMENT_FILE = "enrollment.tsv"
        const val ROSTER_FILE = "roster.tsv"
        const val SESSIONS_FILE = "sessions.tsv"
        const val WAKE_FILE = "wake-targets.json"
        const val STANDALONE_FILE = "standalone-transfers.json"
        const val TUNNELS_FILE = "session-tunnels.json"
        const val FACTORS_FILE = "second-factors.json"
        const val HUB_FILE = "hub-membership.json"
        const val MESH_FILE = "mesh-setup.json"
        const val PACKS_FILE = "content-packs.json"
    }
}

/** SecretSealer over the AES-GCM line cipher (G-06): the
 *  platform layer supplies a Keystore-held key
 *  (KeystoreKeys.getOrCreate) on device; the JVM suite supplies
 *  a generated one. An unseal failure yields an empty string,
 *  which the factor store's decode rejects — a corrupted seal
 *  verifies nothing, never something. */
class AesGcmSecretSealer(key: javax.crypto.SecretKey) : SecretSealer {
    private val cipher = AesGcmLineCipher(key)
    override fun seal(plain: String): String = cipher.encrypt(plain)
    override fun unseal(sealed: String): String = cipher.decrypt(sealed) ?: ""
}

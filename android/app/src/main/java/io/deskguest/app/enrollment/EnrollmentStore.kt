package io.deskguest.app.enrollment

import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Enrollment state (Slice 1): one-time enrollment codes, the roster
 * of enrolled devices, and receipts — in the PairingStore style.
 *
 * Codes: 10 chars from [CODE_ALPHABET], displayed XXXXX-XXXXX,
 * stored/compared without the dash, case-insensitive. Default TTL
 * 10 minutes, single-use, burned after [MAX_REDEEM_ATTEMPTS] wrong
 * attempts against a live code. Redemption is serialized by this
 * store's monitor (same discipline as PairingStore). (D38 S1-AND
 * F6: there is deliberately NO sleep-based backoff — the old
 * implementation slept while holding the monitor, stalling
 * revoke/verify behind every wrong guess. The burn counter is the
 * throttle.)
 *
 * Minting binds scope + device group id + device group name + the
 * D31 transport fields. The redeeming side presents only its code
 * and its own device identity (deviceId / publicKeyBase64 /
 * displayName); it cannot choose or widen scope, group, or
 * transport — those are copied from the mint (D38 S1-AND F7).
 * The presented deviceId must equal the DeviceId derived from the
 * presented public key (SHA-256, see [DeviceIdentity.deviceIdFor])
 * — an id that does not match its key is refused, and a revoked
 * device can never be resurrected by redeeming again (D38 F1).
 *
 * Persistence: one TSV roster file (separate from the identity
 * file). Lines are type-tagged ("device" / "receipt"); corrupt lines
 * are skipped, never fatal. String fields are TSV-sanitised.
 *
 * The [cipher] parameter is accepted for parity with PairingStore
 * construction (and future at-rest wrapping of sensitive roster
 * fields); public keys, device ids, scopes and names are not secret
 * and are stored in the clear in this slice, so the roster does not
 * currently wrap fields with it.
 */
class EnrollmentStore(
    private val storeFile: File,
    @Suppress("unused") private val cipher: LineCipher = IdentityLineCipher,
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    /** W13 P4-F15: MONOTONIC clock for the pending-code TTL — a
     *  wall-clock jump (NTP correction, user changing the time)
     *  must not extend or resurrect a code's life. System.nanoTime
     *  is CLOCK_MONOTONIC on Android and the JVM alike; the wall
     *  clock still stamps records. */
    private val monotonicMs: () -> Long = { System.nanoTime() / 1_000_000L }
) {

    data class EnrollingDevice(
        val deviceId: String,
        val publicKeyBase64: String,
        val displayName: String
    )

    data class EnrolledDevice(
        val deviceId: String,
        val displayName: String,
        val publicKeyBase64: String,
        val scope: String,
        val groupId: String,
        val groupName: String,
        val enrolledAtMs: Long,
        val revoked: Boolean = false,
        /** U9: the SAS computed at redeem (both keys + the code as
         *  transcript), display form; empty when the minting side's
         *  local key was not wired — honestly unconfirmed either way
         *  until [EnrollmentStore.confirmSas]. */
        val sas: String = "",
        /** U9: true ONLY after the endpoint-local human confirm. */
        val sasConfirmed: Boolean = false,
        /** bd-and-remote F3 fix (2026-11-22): a reported SAS
         *  mismatch QUARANTINES the device — admission
         *  ([verifyEnrolledSignature], and with it the v2 host
         *  handshake) refuses it until a human re-confirms a
         *  matching SAS ([confirmSas] clears the flag). The record
         *  is NOT revoked or removed: the standing U9 design (and
         *  SasTest) pin "mismatch does not revoke the pairing" —
         *  but before this fix a mismatch changed nothing about
         *  admission at all, which made the report decorative. */
        val sasMismatchReported: Boolean = false,
        /** D31: transport mode decided at enrollment — "inherit" |
         *  "auto" | "manual". Data model only in this slice; no
         *  precedence/policy resolution here. */
        val transportMode: String = TRANSPORT_MODE_INHERIT,
        /** Transport-rung ids chosen for this device; empty =
         *  inherit / none chosen. Per D32 this is the device's
         *  within-group-set narrowing/pin: it narrows/pins from the
         *  group's own ordered transport set, which is a Slice 2
         *  record — not a Slice 1 record, and not stored here. */
        val allowedTransports: Set<String> = emptySet(),
        /** W14 P3-F2 (W13-P3-F2 spec): the user id that OWNS this
         *  device — mint/redeem-carried, persisted as a trailing
         *  TSV field (index 14). Empty = unbound (legacy records
         *  load empty, parse-tolerant when absent). When non-empty,
         *  HostSessionBinding refuses a SESSION whose initiator
         *  is not this owner for the handshake-proven peer device. */
        val ownerUserId: String = ""
    ) {
        /** U9 SAS state, honestly reported. W13 P4-F5: a blank SAS
         *  is ABSENT (never computed), not UNCONFIRMED. */
        val sasState: String
            get() = when {
                sasConfirmed -> PairingSas.STATE_CONFIRMED
                sas.isBlank() -> PairingSas.STATE_ABSENT
                else -> PairingSas.STATE_UNCONFIRMED
            }
    }

    data class EnrollmentReceipt(
        val enrollerName: String,
        val enrollerDeviceId: String,
        val scope: String,
        val groupName: String,
        val enrolledAtMs: Long,
        /** U9: SAS for this enrollment when the enrollee side could
         *  compute it (enroller key known); empty otherwise. */
        val sas: String = "",
        val sasConfirmed: Boolean = false,
        /** W13 P4-F14: a mismatch was reported against this
         *  receipt — durable (persisted), mirroring the device
         *  record's flag, so the enrollee side's warning survives
         *  a restart instead of living only in the audit trail. */
        val sasMismatchReported: Boolean = false
    ) {
        val sasState: String
            get() = when {
                sasConfirmed -> PairingSas.STATE_CONFIRMED
                sas.isBlank() -> PairingSas.STATE_ABSENT
                else -> PairingSas.STATE_UNCONFIRMED
            }

        /** True when this receipt carries a computed SAS. False is
         *  the honest legacy state: the enroller sent no public key
         *  in its enrollment response (U9 follow-up) — absent,
         *  never faked. */
        val hasSas: Boolean
            get() = sas.isNotBlank()
    }

    /** U9: one SAS audit-trail entry (redeem / confirm / mismatch). */
    data class SasAuditEntry(val deviceId: String, val action: String, val atMs: Long)

    /**
     * U9 follow-up — the enrollment RESPONSE: the post-redeem
     * payload the ENROLLER returns to the enrollee, carrying the
     * enroller's 32-byte public key (base64) so the enrollee can
     * compute the identical SAS at redeem, enrollee-side.
     *
     * The key is a REVEAL, not a trust root: the enrollee already
     * holds the enroller's DeviceId — the SHA-256 fingerprint of
     * this key — from the code/QR transcript, and verifies the
     * transmitted key against that committed fingerprint BEFORE
     * any use ([recordReceiptFromResponse]). A key that does not
     * fingerprint to the committed DeviceId is refused + audited.
     *
     * LEGACY: an old enroller sends no key
     * ([enrollerPublicKeyBase64] null). The enrollee keeps the
     * honest pre-follow-up state — receipt with an empty SAS,
     * audited as [PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY].
     */
    data class EnrollmentResponse(
        val enrollerDeviceId: String,
        val enrollerName: String,
        val enrollerPublicKeyBase64: String?,
        val enrolledDeviceId: String,
        val scope: String,
        val groupId: String,
        val groupName: String,
        val enrolledAtMs: Long
    )

    /** Outcome of an enrollee ingesting an [EnrollmentResponse]. */
    enum class EnrollmentResponseOutcome {
        /** Key verified; SAS computed enrollee-side, unconfirmed. */
        APPLIED,
        /** Legacy enroller sent no key: receipt stored, SAS absent. */
        LEGACY_NO_KEY,
        /** Key does not fingerprint to the committed DeviceId:
         *  refused, audited, NO receipt and NO SAS produced. */
        REFUSED_KEY_MISMATCH,
        /** Response/key malformed: refused, NO receipt produced. */
        REFUSED_MALFORMED
    }

    /** Result of [recordReceiptFromResponse]. */
    data class EnrollmentResponseResult(
        val outcome: EnrollmentResponseOutcome,
        val receipt: EnrollmentReceipt?,
        val detail: String
    )

    /** U9: supplies THIS (minting/responder) device's 32-byte
     *  public key so redeem can compute the SAS binding both keys.
     *  Wired by PlatformStores to the device identity. Unset =
     *  redeem still succeeds with an empty, unconfirmed SAS. */
    var localPublicKeyProvider: (() -> ByteArray?)? = null

    private val sasAuditList = mutableListOf<SasAuditEntry>()

    @Synchronized
    fun sasAudit(): List<SasAuditEntry> = sasAuditList.toList()

    private fun appendSasAudit(deviceId: String, action: String) {
        sasAuditList.add(SasAuditEntry(deviceId, action, clockMs()))
        // W13 P4-F12: the audit trail is CAPPED — it was unbounded
        // in memory and on disk (every redeem/confirm/mismatch
        // appended forever). Oldest entries drop past the cap;
        // the cap is generous against any real enrollment history.
        while (sasAuditList.size > MAX_SAS_AUDIT_ENTRIES) sasAuditList.removeAt(0)
    }

    private val random = SecureRandom()
    private val devices = mutableListOf<EnrolledDevice>()
    private val receiptList = mutableListOf<EnrollmentReceipt>()

    private var pendingCode: String? = null
    private var pendingScope: String? = null
    private var pendingGroupId: String = ""
    private var pendingGroupName: String = ""
    private var pendingExpiresAtMs: Long = 0
    /** W13 P4-F15: monotonic deadline twin of [pendingExpiresAtMs]
     *  (0 = not set, e.g. a pending record restored from disk whose
     *  remaining life is re-derived at load). */
    private var pendingExpiresMonoMs: Long = 0
    private var pendingFailedAttempts: Int = 0
    private var pendingTransportMode: String = TRANSPORT_MODE_INHERIT
    private var pendingAllowedTransports: Set<String> = emptySet()
    /** W14 P3-F2: owner bound at mint, carried to the redeemed record. */
    private var pendingOwnerUserId: String = ""

    init {
        load()
    }

    /**
     * C20 wiring: re-read the store file after a recovery restore
     * rewrote it (the restore's apply step writes the blob's store
     * export, then this reloads so the live store and the file agree
     * — without it, the next in-process save would overwrite the
     * restored file with the pre-restore empty state). Any pending
     * (unredeemed) code is dropped: it was minted under the
     * pre-restore identity's watch and does not survive a restore.
     */
    @Synchronized
    fun reloadForRecovery() {
        devices.clear()
        receiptList.clear()
        sasAuditList.clear()
        pendingCode = null
        pendingScope = null
        pendingGroupId = ""
        pendingGroupName = ""
        pendingExpiresAtMs = 0
        pendingExpiresMonoMs = 0
        pendingFailedAttempts = 0
        pendingTransportMode = TRANSPORT_MODE_INHERIT
        pendingAllowedTransports = emptySet()
        pendingOwnerUserId = ""
        load()
    }

    /**
     * Mint a live enrollment code bound to [scope], [groupId],
     * [groupName] and the D31 transport fields ([transportMode] /
     * [allowedTransports] — D38 S1-AND F7: transport is decided by
     * the MINTING side, exactly like scope and group; the redeeming
     * side cannot supply it). Returns the display form XXXXX-XXXXX.
     * [scope] must be "local", "personal", or "company";
     * [transportMode] must be a known mode (an unknown mode is a
     * programmer error and throws, as an unknown scope does).
     */
    @Synchronized
    fun mint(
        scope: String,
        groupId: String,
        groupName: String,
        ttlMs: Long = CODE_TTL_MS,
        transportMode: String = TRANSPORT_MODE_INHERIT,
        allowedTransports: Set<String> = emptySet(),
        ownerUserId: String = ""
    ): String {
        val normalizedScope = scope.trim().lowercase()
        require(normalizedScope in SCOPES) { "unknown enrollment scope: $scope" }
        val normalizedMode = transportMode.trim().lowercase()
        require(normalizedMode in TRANSPORT_MODES) { "unknown transport mode: $transportMode" }
        val raw = buildString {
            repeat(CODE_LENGTH) { append(CODE_ALPHABET[random.nextInt(CODE_ALPHABET.length)]) }
        }
        pendingCode = raw
        pendingScope = normalizedScope
        pendingGroupId = groupId.tsvSafe()
        pendingGroupName = groupName.tsvSafe()
        pendingExpiresAtMs = clockMs() + ttlMs
        pendingExpiresMonoMs = monotonicMs() + ttlMs
        pendingFailedAttempts = 0
        pendingTransportMode = normalizedMode
        pendingAllowedTransports = sanitizeTransports(allowedTransports)
        pendingOwnerUserId = ownerUserId.trim().tsvSafe()
        return formatCode(raw)
    }

    /** Alias following the PairingStore naming. */
    fun mintCode(
        scope: String, groupId: String, groupName: String, ttlMs: Long = CODE_TTL_MS,
        transportMode: String = TRANSPORT_MODE_INHERIT,
        allowedTransports: Set<String> = emptySet(),
        ownerUserId: String = ""
    ): String = mint(scope, groupId, groupName, ttlMs, transportMode, allowedTransports, ownerUserId)

    /** D38 F7/F8: transport ids are bounded, TSV-safe strings. */
    private fun sanitizeTransports(transports: Set<String>): Set<String> =
        transports.map { it.trim().tsvSafe() }.filter { it.isNotBlank() && it.length <= 64 }
            .take(16).toSet()

    /** The live code in display form, or null when none/expired. */
    @Synchronized
    fun currentCode(): String? {
        val raw = liveRawCode() ?: return null
        return formatCode(raw)
    }

    @Synchronized
    fun redeem(
        code: String,
        device: EnrollingDevice
    ): EnrolledDevice? {
        // Wrong guesses count toward the burn; there is NO sleep
        // here (D38 S1-AND F6 — sleeping under this monitor stalled
        // revoke/verify behind every bad guess).
        val live = liveRawCode() ?: return null
        val presented = normalizeCode(code)
        if (presented == null || !constantTimeEquals(live, presented)) {
            pendingFailedAttempts++
            if (pendingFailedAttempts >= MAX_REDEEM_ATTEMPTS) {
                clearPending()
            }
            return null
        }
        // Validate the enrolling device before burning the code on a
        // malformed record? No: a correct code presented with a bad
        // public key is a failed enrollment — fail closed and do not
        // create a roster entry. The code stays live in that case so
        // a legitimate retry is not punished for a formatting bug.
        val publicKey = try {
            Base64.getDecoder().decode(device.publicKeyBase64)
        } catch (_: Exception) {
            return null
        }
        if (publicKey.size != DeviceIdentity.PUBLIC_KEY_SIZE) return null
        if (device.deviceId.isBlank()) return null
        // D38 S1-AND F1: the DeviceId IS the SHA-256 of the public
        // key (Slice 1 spec) — a presented id that does not match
        // its key is refused. Without this, anyone holding a code
        // could enroll under a VICTIM's deviceId with their own key
        // and every later signature check would trust the attacker.
        if (DeviceIdentity.deviceIdFor(publicKey) != device.deviceId) return null
        // D38 S1-AND F5: the key must decode as a curve point and
        // must not be a small-order point (the identity point would
        // accept universal signature forgeries under verify).
        val point = io.deskguest.app.adb.Ed25519.decode(publicKey) ?: return null
        if (io.deskguest.app.adb.Ed25519.isSmallOrder(point)) return null
        // D38 S1-AND F1: re-enrollment rules — a REVOKED record is
        // never resurrected by redeeming again, and an existing
        // record's key can never be swapped under its id.
        val existing = devices.firstOrNull { it.deviceId == device.deviceId }
        if (existing != null) {
            if (existing.revoked) return null
            if (existing.publicKeyBase64 != Base64.getEncoder().encodeToString(publicKey)) return null
        }

        val scope = pendingScope ?: return null
        // U9: SAS binds BOTH keys + the transcript (the raw code both
        // sides held), computed at redeem because the code is
        // consumed by this act. Initiator = redeeming device,
        // responder = this minting device. Pairing completes
        // regardless — no responder key leaves sas empty/unconfirmed.
        val sasDisplay = try {
            PairingSas.compute(publicKey, localPublicKeyProvider?.invoke(), live)?.display ?: ""
        } catch (_: Exception) { "" }
        val enrolled = EnrolledDevice(
            deviceId = device.deviceId,
            displayName = device.displayName.tsvSafe(),
            publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey),
            scope = scope,
            sas = sasDisplay,
            sasConfirmed = false,
            groupId = pendingGroupId,
            groupName = pendingGroupName,
            enrolledAtMs = clockMs(),
            revoked = false,
            // D38 F7: transport comes from the MINT, never the redeemer.
            transportMode = pendingTransportMode,
            allowedTransports = pendingAllowedTransports,
            // W14 P3-F2: owner likewise comes from the MINT only.
            ownerUserId = pendingOwnerUserId
        )
        // D38 S1-AND F4: mutate + persist with rollback — if the
        // save fails, neither the roster nor the (single-use) code
        // is consumed by an enrollment that never became durable.
        val devicesBefore = devices.toList()
        val pendingBefore = PendingSnapshot()
        val auditBefore = sasAuditList.size
        clearPending()
        devices.removeAll { it.deviceId == enrolled.deviceId }
        devices.add(enrolled)
        appendSasAudit(enrolled.deviceId, PairingSas.STATE_UNCONFIRMED)
        try {
            save()
        } catch (e: Exception) {
            devices.clear(); devices.addAll(devicesBefore)
            while (sasAuditList.size > auditBefore) sasAuditList.removeAt(sasAuditList.size - 1)
            pendingBefore.restore()
            return null
        }
        return enrolled
    }

    @Synchronized
    fun redeem(
        code: String,
        deviceId: String,
        publicKeyBase64: String,
        displayName: String
    ): EnrolledDevice? = redeem(
        code, EnrollingDevice(deviceId, publicKeyBase64, displayName)
    )

    // ---- U9 follow-up: enrollment response (enroller key reveal) ----

    /**
     * Build the post-redeem [EnrollmentResponse] for an enrolled
     * device (ENROLLER side). The response carries THIS device's
     * public key — from [localPublicKeyProvider] — so the enrollee
     * can compute the identical SAS. With no local key wired, the
     * response is the LEGACY shape: no key, and the enrollee will
     * honestly record an absent SAS.
     */
    @Synchronized
    fun buildEnrollmentResponse(enrolled: EnrolledDevice?, enrollerName: String): EnrollmentResponse? {
        if (enrolled == null) return null
        val key = try { localPublicKeyProvider?.invoke() } catch (_: Exception) { null }
        return if (key != null && key.size == DeviceIdentity.PUBLIC_KEY_SIZE) {
            EnrollmentResponse(
                enrollerDeviceId = DeviceIdentity.deviceIdFor(key),
                enrollerName = enrollerName,
                enrollerPublicKeyBase64 = Base64.getEncoder().encodeToString(key),
                enrolledDeviceId = enrolled.deviceId,
                scope = enrolled.scope,
                groupId = enrolled.groupId,
                groupName = enrolled.groupName,
                enrolledAtMs = enrolled.enrolledAtMs
            )
        } else {
            EnrollmentResponse(
                enrollerDeviceId = "",
                enrollerName = enrollerName,
                enrollerPublicKeyBase64 = null,
                enrolledDeviceId = enrolled.deviceId,
                scope = enrolled.scope,
                groupId = enrolled.groupId,
                groupName = enrolled.groupName,
                enrolledAtMs = enrolled.enrolledAtMs
            )
        }
    }

    /**
     * Redeem + build the enrollment response in one act (ENROLLER
     * side). Null enrolled (and null response) when the redeem
     * itself is refused.
     */
    @Synchronized
    fun redeemWithResponse(
        code: String,
        device: EnrollingDevice,
        enrollerName: String
    ): Pair<EnrolledDevice?, EnrollmentResponse?> {
        val enrolled = redeem(code, device) ?: return Pair(null, null)
        return Pair(enrolled, buildEnrollmentResponse(enrolled, enrollerName))
    }

    /** Snapshot of the pending-code state, for redeem rollback. */
    private inner class PendingSnapshot {
        private val code = pendingCode
        private val scope = pendingScope
        private val groupId = pendingGroupId
        private val groupName = pendingGroupName
        private val expiresAtMs = pendingExpiresAtMs
        private val failedAttempts = pendingFailedAttempts
        private val transportMode = pendingTransportMode
        private val allowedTransports = pendingAllowedTransports
        private val ownerUserId = pendingOwnerUserId
        fun restore() {
            pendingCode = code; pendingScope = scope; pendingGroupId = groupId
            pendingGroupName = groupName; pendingExpiresAtMs = expiresAtMs
            pendingOwnerUserId = ownerUserId
            // W13 P4-F15: a restored pending record re-derives its
            // monotonic deadline from the wall time REMAINING, so
            // the monotonic rule applies to it from here on.
            pendingExpiresMonoMs = monotonicMs() + maxOf(0L, expiresAtMs - clockMs())
            pendingFailedAttempts = failedAttempts; pendingTransportMode = transportMode
            pendingAllowedTransports = allowedTransports
        }
    }

    /**
     * D31 data-model update: set a device's transport mode / allowed
     * transports and persist immediately. No policy resolution —
     * that is a later slice. False for unknown devices or an
     * unknown mode.
     */
    @Synchronized
    fun setTransport(deviceId: String, transportMode: String, allowedTransports: Set<String>): Boolean {
        val normalized = transportMode.trim().lowercase()
        if (normalized !in TRANSPORT_MODES) return false
        val index = devices.indexOfFirst { it.deviceId == deviceId }
        if (index < 0) return false
        val before = devices[index]
        devices[index] = devices[index].copy(
            transportMode = normalized,
            allowedTransports = sanitizeTransports(allowedTransports)
        )
        // D38 F4: report only durable changes — roll back on failure.
        try {
            save()
        } catch (e: Exception) {
            devices[index] = before
            return false
        }
        return true
    }

    @Synchronized
    fun all(): List<EnrolledDevice> = devices.toList()

    @Synchronized
    fun byGroup(groupId: String): List<EnrolledDevice> =
        devices.filter { it.groupId == groupId }

    @Synchronized
    fun byId(deviceId: String): EnrolledDevice? =
        devices.firstOrNull { it.deviceId == deviceId }

    /**
     * Revoke a device: immediate effect, persisted. D38 S1-AND F4:
     * returns true only when the revocation is DURABLE — if the
     * save fails, the in-memory flag is rolled back and false is
     * returned, so a caller never believes a revocation happened
     * that a restart would silently undo.
     */
    @Synchronized
    fun revoke(deviceId: String): Boolean {
        val index = devices.indexOfFirst { it.deviceId == deviceId }
        if (index < 0) return false
        if (!devices[index].revoked) {
            val before = devices[index]
            devices[index] = devices[index].copy(revoked = true)
            try {
                save()
            } catch (e: Exception) {
                devices[index] = before
                return false
            }
        }
        return true
    }

    /**
     * U9: the endpoint-local human confirm — the person at THIS
     * endpoint compared the SAS on both surfaces and they matched.
     * The ONLY path that sets sasConfirmed. False for unknown
     * devices or a device with no computed SAS (never faked).
     * Persisted with the same rollback discipline as [revoke].
     */
    @Synchronized
    fun confirmSas(deviceId: String): Boolean {
        val index = devices.indexOfFirst { it.deviceId == deviceId }
        if (index < 0) return false
        if (devices[index].sas.isBlank()) return false
        if (devices[index].sasConfirmed && !devices[index].sasMismatchReported) return true
        val before = devices[index]
        // A successful re-confirm also lifts the F3 quarantine.
        devices[index] = devices[index].copy(sasConfirmed = true, sasMismatchReported = false)
        appendSasAudit(deviceId, PairingSas.STATE_CONFIRMED)
        try {
            save()
        } catch (e: Exception) {
            devices[index] = before
            sasAuditList.removeAt(sasAuditList.size - 1)
            return false
        }
        return true
    }

    /**
     * U9: the endpoint-local mismatch report — compared strings did
     * NOT match. Record stays honestly unconfirmed; pairing is NOT
     * torn down or revoked (SAS never blocks the consent floor) —
     * but bd-and-remote F3: the device IS quarantined from
     * admission ([verifyEnrolledSignature] refuses it) until a
     * human re-confirms a matching SAS. A mismatch is direct
     * evidence an attacker's key may have been enrolled; admitting
     * the device unchanged made the report decorative.
     */
    @Synchronized
    fun reportSasMismatch(deviceId: String): Boolean {
        val index = devices.indexOfFirst { it.deviceId == deviceId }
        if (index < 0) return false
        val before = devices[index]
        devices[index] = devices[index].copy(sasConfirmed = false, sasMismatchReported = true)
        appendSasAudit(deviceId, "sas_mismatch_reported")
        try {
            save()
        } catch (e: Exception) {
            devices[index] = before
            sasAuditList.removeAt(sasAuditList.size - 1)
            return false
        }
        return true
    }

    /**
     * Verify [signature] over [message] under the enrolled public
     * key for [deviceId]. False for unknown, revoked, or malformed
     * anything — never throws.
     */
    @Synchronized
    fun verifyEnrolledSignature(deviceId: String, message: ByteArray, signature: ByteArray): Boolean {
        val device = devices.firstOrNull { it.deviceId == deviceId } ?: return false
        if (device.revoked) return false
        // bd-and-remote F3: a SAS-mismatch-quarantined device is
        // refused admission until a human re-confirms the SAS.
        if (device.sasMismatchReported) return false
        val publicKey = try {
            Base64.getDecoder().decode(device.publicKeyBase64)
        } catch (_: Exception) {
            return false
        }
        return DeviceIdentity.verify(publicKey, message, signature)
    }

    @Synchronized
    fun recordReceipt(receipt: EnrollmentReceipt) {
        // W12-DS P4-F4: a caller-supplied receipt can NEVER arrive
        // pre-confirmed — confirmation is confirmReceiptSas's alone
        // (a confirmed blank-SAS receipt is refused outright, the
        // same combination the disk loader rejects).
        if (receipt.sasConfirmed && receipt.sas.isBlank())
            throw IllegalArgumentException("a confirmed receipt must carry a SAS — refused")
        receiptList.add(receipt.copy(sasConfirmed = false, sasMismatchReported = false))
        try {
            save()
        } catch (e: Exception) {
            receiptList.removeAt(receiptList.size - 1) // D38 F4 rollback
            throw e
        }
    }

    @Synchronized
    fun recordReceipt(
        enrollerName: String,
        enrollerDeviceId: String,
        scope: String,
        groupName: String,
        enrolledAtMs: Long = clockMs()
    ) {
        recordReceipt(EnrollmentReceipt(enrollerName, enrollerDeviceId, scope, groupName, enrolledAtMs))
    }

    @Synchronized
    fun receipts(): List<EnrollmentReceipt> = receiptList.toList()

    /**
     * ENROLLEE side of the U9 follow-up: ingest an
     * [EnrollmentResponse] and record this device's receipt,
     * computing the SAS enrollee-side.
     *
     * Verification BEFORE use (the MITM leg): the transmitted
     * enroller key is fingerprinted (SHA-256, the DeviceId
     * derivation) and compared against [expectedEnrollerDeviceId]
     * — the commitment the enrollee already holds from the code/QR
     * transcript — and against the response's own claimed enroller
     * id when present. Any mismatch refuses the response: no
     * receipt, no SAS, and a
     * [PairingSas.AUDIT_ENROLLER_KEY_MISMATCH] audit entry.
     *
     * SAS derivation is the pinned U9 algorithm with the enrollee's
     * OWN key as initiator, the verified enroller key as responder,
     * and the enrollee's locally held code (normalized) as the
     * transcript — never a transcript taken from the response. The
     * resulting string is identical to the enroller-side record.
     *
     * LEGACY: a response with no key stores the receipt with an
     * empty SAS and a [PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY]
     * audit entry — the downgrade to the no-SAS state is VISIBLE,
     * never silent, and the absent SAS is never faked.
     *
     * REPLAY: re-ingesting the identical response is idempotent —
     * the already-recorded receipt is returned, no duplicate
     * receipt or audit entry is stored, and a human-confirmed
     * state is never shadowed by a fresh unconfirmed copy
     * (recovery-verification fix, 2026-11-22).
     *
     * Persistence follows the D38 F4 discipline: a failed save
     * rolls the receipt + audit back and reports REFUSED_MALFORMED.
     */
    @Synchronized
    fun recordReceiptFromResponse(
        response: EnrollmentResponse?,
        expectedEnrollerDeviceId: String?,
        ownPublicKeyBase64: String?,
        transcriptCode: String?
    ): EnrollmentResponseResult {
        if (response == null) {
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null, "no enrollment response")
        }
        val enrollerId = response.enrollerDeviceId.trim()
            .ifBlank { (expectedEnrollerDeviceId ?: "").trim() }
        if (enrollerId.isBlank()) {
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "response carries no enroller identity and no committed fingerprint was held")
        }
        val scope = response.scope.trim().lowercase()
        if (scope !in SCOPES) {
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "response carries an unknown scope")
        }

        // W12-DS P4-F3: the response binds the ENROLLEE device id —
        // a response issued for another device is refused before
        // anything is stored, in both legs. The own id derives
        // from the caller's own key; an undecodable/absent own key
        // cannot prove the binding, so it refuses too when the
        // response names an enrolled device.
        if (response.enrolledDeviceId.isNotBlank()) {
            val ownKeyForBinding = try {
                Base64.getDecoder().decode(ownPublicKeyBase64 ?: "")
            } catch (_: Exception) { ByteArray(0) }
            val ownId = if (ownKeyForBinding.size == DeviceIdentity.PUBLIC_KEY_SIZE)
                DeviceIdentity.deviceIdFor(ownKeyForBinding) else null
            if (ownId == null || !ownId.equals(response.enrolledDeviceId.trim(), ignoreCase = true)) {
                return EnrollmentResponseResult(
                    EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                    "response was issued for a different device (enrolledDeviceId does not match this device's key) — refused, nothing stored")
            }
        }

        // LEGACY leg: no key in the response — honest absent SAS.
        if (response.enrollerPublicKeyBase64.isNullOrBlank()) {
            // W12-DS P4-F2: when a committed enroller id is held,
            // the legacy leg must match it — a stripped key must
            // not let a MITM substitute the enroller identity.
            val committedLegacy = (expectedEnrollerDeviceId ?: "").trim()
            if (committedLegacy.isNotBlank() &&
                !enrollerId.equals(committedLegacy, ignoreCase = true)) {
                appendSasAuditDurable(enrollerId, PairingSas.AUDIT_ENROLLER_KEY_MISMATCH)
                return EnrollmentResponseResult(
                    EnrollmentResponseOutcome.REFUSED_KEY_MISMATCH, null,
                    "legacy response's enroller id does not match the committed fingerprint — refused and audited")
            }
            val legacyReceipt = EnrollmentReceipt(
                enrollerName = response.enrollerName,
                enrollerDeviceId = enrollerId,
                scope = scope,
                groupName = response.groupName,
                enrolledAtMs = response.enrolledAtMs,
                sas = "",
                sasConfirmed = false
            )
            // Replay guard: the identical receipt is already
            // recorded — a re-sent response stores no duplicate
            // and appends no second absent-SAS audit entry.
            findIdenticalReceipt(legacyReceipt)?.let { existingLegacy ->
                return EnrollmentResponseResult(
                    EnrollmentResponseOutcome.LEGACY_NO_KEY, existingLegacy,
                    "replayed response — receipt already recorded; no duplicate stored")
            }
            receiptList.add(legacyReceipt)
            appendSasAudit(enrollerId, PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY)
            try {
                save()
            } catch (e: Exception) {
                receiptList.removeAt(receiptList.size - 1)
                sasAuditList.removeAt(sasAuditList.size - 1)
                return EnrollmentResponseResult(
                    EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                    "legacy receipt could not be persisted (${e.javaClass.simpleName}) — rolled back")
            }
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.LEGACY_NO_KEY, legacyReceipt,
                "legacy enroller sent no public key — SAS absent (audited), not faked")
        }

        // Decode + shape-check the revealed key BEFORE any use.
        val enrollerKey = try {
            Base64.getDecoder().decode(response.enrollerPublicKeyBase64)
        } catch (_: Exception) {
            appendSasAuditDurable(enrollerId, PairingSas.AUDIT_ENROLLER_KEY_MALFORMED)
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "enroller public key is not valid base64 — refused")
        }
        val keyPoint = if (enrollerKey.size == DeviceIdentity.PUBLIC_KEY_SIZE)
            io.deskguest.app.adb.Ed25519.decode(enrollerKey) else null
        if (enrollerKey.size != DeviceIdentity.PUBLIC_KEY_SIZE || keyPoint == null ||
            io.deskguest.app.adb.Ed25519.isSmallOrder(keyPoint)
        ) {
            appendSasAuditDurable(enrollerId, PairingSas.AUDIT_ENROLLER_KEY_MALFORMED)
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "enroller public key is malformed (length or small-order) — refused")
        }

        // THE COMMITMENT CHECK: fingerprint(revealed key) must
        // equal the committed enroller DeviceId held from the
        // code/QR, and the response's own claimed id when present.
        val fingerprint = DeviceIdentity.deviceIdFor(enrollerKey)
        val committed = (expectedEnrollerDeviceId ?: "").trim()
        if (committed.isBlank() ||
            !fingerprint.equals(committed, ignoreCase = true) ||
            (response.enrollerDeviceId.isNotBlank() &&
                !fingerprint.equals(response.enrollerDeviceId.trim(), ignoreCase = true))
        ) {
            appendSasAuditDurable(enrollerId, PairingSas.AUDIT_ENROLLER_KEY_MISMATCH)
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_KEY_MISMATCH, null,
                "enroller public key does not match the committed fingerprint — refused and audited")
        }

        // Derive the SAS enrollee-side: own key (initiator) + the
        // VERIFIED enroller key (responder) + locally held code.
        val transcript = normalizeCode(transcriptCode)
        val ownKey = try {
            Base64.getDecoder().decode(ownPublicKeyBase64 ?: "")
        } catch (_: Exception) {
            ByteArray(0)
        }
        val sas = if (transcript == null) null
            else PairingSas.compute(ownKey, enrollerKey, transcript)
        if (sas == null) {
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "could not derive SAS enrollee-side (own key or transcript invalid) — no receipt recorded")
        }

        val receipt = EnrollmentReceipt(
            enrollerName = response.enrollerName,
            enrollerDeviceId = enrollerId,
            scope = scope,
            groupName = response.groupName,
            enrolledAtMs = response.enrolledAtMs,
            sas = sas.display,
            sasConfirmed = false
        )
        // Replay guard (see the legacy leg): no duplicate
        // receipt/audit, and a replay must never shadow a
        // human-confirmed receipt with a fresh unconfirmed copy.
        findIdenticalReceipt(receipt)?.let { existing ->
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.APPLIED, existing,
                "replayed response — receipt already recorded; no duplicate stored, confirmation state untouched")
        }
        receiptList.add(receipt)
        appendSasAudit(enrollerId, PairingSas.STATE_UNCONFIRMED)
        try {
            save()
        } catch (e: Exception) {
            receiptList.removeAt(receiptList.size - 1)
            sasAuditList.removeAt(sasAuditList.size - 1)
            return EnrollmentResponseResult(
                EnrollmentResponseOutcome.REFUSED_MALFORMED, null,
                "receipt could not be persisted (${e.javaClass.simpleName}) — rolled back")
        }
        return EnrollmentResponseResult(
            EnrollmentResponseOutcome.APPLIED, receipt,
            "enroller key verified against the committed fingerprint; SAS computed enrollee-side, unconfirmed")
    }

    /** Replay guard for [recordReceiptFromResponse]: a receipt
     *  for the SAME enrollment (enroller, enrolled instant, scope,
     *  group, enroller name and SAS — the confirmation flag
     *  deliberately excluded) is already recorded. Callers hold
     *  the monitor (@Synchronized). */
    private fun findIdenticalReceipt(candidate: EnrollmentReceipt): EnrollmentReceipt? =
        receiptList.firstOrNull {
            it.enrollerDeviceId == candidate.enrollerDeviceId &&
                it.enrolledAtMs == candidate.enrolledAtMs &&
                it.scope == candidate.scope &&
                it.groupName == candidate.groupName &&
                it.enrollerName == candidate.enrollerName &&
                it.sas == candidate.sas
        }

    /** Append a refusal audit entry and persist it best-effort
     *  (callers hold the monitor; a failed save never masks the
     *  refusal itself). */
    private fun appendSasAuditDurable(deviceId: String, action: String) {
        appendSasAudit(deviceId, action)
        try {
            save()
        } catch (_: Exception) {
            // The refusal stands either way; the in-memory audit
            // entry remains for this process's trail.
        }
    }

    /**
     * The endpoint-local human confirm for a RECEIPT (enrollee
     * side, U9 follow-up): the person at THIS device compared the
     * receipt's SAS against the string on the enroller and they
     * matched. The ONLY path that confirms a receipt SAS. False
     * when no receipt exists for the enroller or the receipt
     * carries no SAS (legacy/absent is never confirmable).
     * Persisted with the same rollback discipline as [confirmSas].
     */
    @Synchronized
    fun confirmReceiptSas(enrollerDeviceId: String): Boolean {
        val index = receiptList.indexOfLast {
            it.enrollerDeviceId.equals(enrollerDeviceId, ignoreCase = true)
        }
        if (index < 0) return false
        if (receiptList[index].sas.isBlank()) return false
        if (receiptList[index].sasConfirmed) return true
        val before = receiptList[index]
        receiptList[index] = receiptList[index].copy(sasConfirmed = true, sasMismatchReported = false)
        appendSasAudit(before.enrollerDeviceId, PairingSas.STATE_CONFIRMED)
        try {
            save()
        } catch (e: Exception) {
            receiptList[index] = before
            sasAuditList.removeAt(sasAuditList.size - 1)
            return false
        }
        return true
    }

    /**
     * The endpoint-local mismatch report for a RECEIPT (enrollee
     * side, U9 follow-up): the compared strings did NOT match. The
     * receipt stays honestly unconfirmed and the report is
     * audit-trailed; pairing is NOT torn down.
     */
    @Synchronized
    fun reportReceiptSasMismatch(enrollerDeviceId: String): Boolean {
        val index = receiptList.indexOfLast {
            it.enrollerDeviceId.equals(enrollerDeviceId, ignoreCase = true)
        }
        if (index < 0) return false
        val before = receiptList[index]
        // W13 P4-F14: the mismatch is a durable flag on the
        // receipt itself (persisted below), not only an audit line.
        receiptList[index] = receiptList[index].copy(sasConfirmed = false, sasMismatchReported = true)
        appendSasAudit(before.enrollerDeviceId, "sas_mismatch_reported")
        try {
            save()
        } catch (e: Exception) {
            receiptList[index] = before
            sasAuditList.removeAt(sasAuditList.size - 1)
            return false
        }
        return true
    }

    // ---- internals (callers hold the monitor) ----

    private fun liveRawCode(): String? {
        val code = pendingCode ?: return null
        // W13 P4-F15: expiry is judged on the MONOTONIC clock when
        // a monotonic deadline exists — wall-clock jumps neither
        // extend nor shorten a live code. The wall deadline is the
        // fallback for a record restored from disk.
        val expired = if (pendingExpiresMonoMs > 0) monotonicMs() > pendingExpiresMonoMs
                      else clockMs() > pendingExpiresAtMs
        if (expired) {
            clearPending()
            return null
        }
        return code
    }

    /** W12-DS P4-F8: the decline/withdraw path the intention
     *  names — declining an enrollment REVOKES the pending code
     *  immediately instead of leaving it live for its TTL.
     *  Returns true when a pending code was actually revoked. */
    @Synchronized
    fun declinePending(): Boolean {
        if (pendingCode == null) return false
        clearPending()
        try { save() } catch (_: Exception) {}
        return true
    }

    private fun clearPending() {
        pendingCode = null
        pendingScope = null
        pendingGroupId = ""
        pendingGroupName = ""
        pendingExpiresAtMs = 0
        pendingExpiresMonoMs = 0
        pendingFailedAttempts = 0
        pendingTransportMode = TRANSPORT_MODE_INHERIT
        pendingAllowedTransports = emptySet()
        pendingOwnerUserId = ""
    }

    private fun load() {
        if (!storeFile.exists()) return
        try {
            storeFile.readLines().forEach { line ->
                if (line.isBlank()) return@forEach
                val parts = line.split('\t')
                try {
                    when (parts.getOrNull(0)) {
                        "device" -> {
                            if (parts.size < 9) return@forEach
                            // D38 S1-AND F1/F8: a roster line is
                            // trusted only if it is internally
                            // consistent — known scope, a decodable
                            // non-small-order key, and a deviceId
                            // that IS that key's fingerprint. A line
                            // failing any check is corrupt: skipped.
                            val scope = parts[4].trim().lowercase()
                            if (scope !in SCOPES) return@forEach
                            val keyBytes = try {
                                Base64.getDecoder().decode(parts[3])
                            } catch (_: Exception) {
                                return@forEach
                            }
                            if (keyBytes.size != DeviceIdentity.PUBLIC_KEY_SIZE) return@forEach
                            if (DeviceIdentity.deviceIdFor(keyBytes) != parts[1]) return@forEach
                            val keyPoint = io.deskguest.app.adb.Ed25519.decode(keyBytes)
                                ?: return@forEach
                            if (io.deskguest.app.adb.Ed25519.isSmallOrder(keyPoint)) return@forEach
                            val loaded = EnrolledDevice(
                                deviceId = parts[1],
                                displayName = parts[2],
                                publicKeyBase64 = parts[3],
                                scope = scope,
                                groupId = parts[5],
                                groupName = parts[6],
                                enrolledAtMs = parts[7].toLongOrNull() ?: return@forEach,
                                revoked = parts[8] == "1" || parts[8].equals("true", ignoreCase = true),
                                // D31 trailing fields: older/shorter
                                // lines (9 fields) load with defaults.
                                transportMode = parts.getOrNull(9)
                                    ?.let { normalizeTransportMode(it) }
                                    ?: TRANSPORT_MODE_INHERIT,
                                allowedTransports = parts.getOrNull(10)
                                    ?.split(',')?.filter { it.isNotBlank() }?.toSet()
                                    ?: emptySet(),
                                // U9 trailing fields: older lines
                                // load empty + unconfirmed. A stored
                                // confirmation with NO sas is dropped
                                // to unconfirmed — never faked.
                                sas = parts.getOrNull(11)?.takeIf { it.length <= 64 } ?: "",
                                sasConfirmed = !parts.getOrNull(11).isNullOrBlank() &&
                                    (parts.getOrNull(12) == "1" || parts.getOrNull(12).equals("true", ignoreCase = true)),
                                // F3 trailing field: older lines load un-quarantined.
                                sasMismatchReported = parts.getOrNull(13) == "1" ||
                                    parts.getOrNull(13).equals("true", ignoreCase = true),
                                // W14 P3-F2 trailing field: older/shorter
                                // lines load unbound (empty owner).
                                ownerUserId = parts.getOrNull(14) ?: ""
                            )
                            // D38 F8: duplicate ids resolve in
                            // favour of REVOKED — an active line can
                            // never outrank a revocation by ordering.
                            val existingIdx = devices.indexOfFirst { it.deviceId == loaded.deviceId }
                            if (existingIdx < 0) {
                                devices.add(loaded)
                            } else if (loaded.revoked && !devices[existingIdx].revoked) {
                                devices[existingIdx] = loaded
                            }
                        }
                        "receipt" -> {
                            if (parts.size < 6) return@forEach
                            receiptList.add(
                                EnrollmentReceipt(
                                    enrollerName = parts[1],
                                    enrollerDeviceId = parts[2],
                                    scope = parts[3],
                                    groupName = parts[4],
                                    enrolledAtMs = parts[5].toLongOrNull() ?: return@forEach,
                                    sas = parts.getOrNull(6)?.takeIf { it.length <= 64 } ?: "",
                                    sasConfirmed = !parts.getOrNull(6).isNullOrBlank() &&
                                        (parts.getOrNull(7) == "1" || parts.getOrNull(7).equals("true", ignoreCase = true)),
                                    // W13 P4-F14 trailing field: older
                                    // lines load un-flagged.
                                    sasMismatchReported = parts.getOrNull(8) == "1" ||
                                        parts.getOrNull(8).equals("true", ignoreCase = true)
                                )
                            )
                        }
                        "sas" -> {
                            if (parts.size < 4) return@forEach
                            sasAuditList.add(
                                SasAuditEntry(
                                    deviceId = parts[1],
                                    action = parts[2],
                                    atMs = parts[3].toLongOrNull() ?: return@forEach
                                )
                            )
                        }
                        else -> Unit // corrupt/unknown line: skip, never fatal
                    }
                } catch (_: Exception) {
                    // corrupt line: skip, never fatal
                }
            }
        } catch (_: Exception) {
            // unreadable store: start empty, never fatal
        }
    }

    private fun save() {
        val lines = mutableListOf<String>()
        devices.forEach { d ->
            lines.add(
                listOf(
                    "device",
                    d.deviceId.tsvSafe(),
                    d.displayName.tsvSafe(),
                    d.publicKeyBase64.tsvSafe(),
                    d.scope.tsvSafe(),
                    d.groupId.tsvSafe(),
                    d.groupName.tsvSafe(),
                    d.enrolledAtMs.toString(),
                    if (d.revoked) "1" else "0",
                    d.transportMode.tsvSafe(),
                    d.allowedTransports.joinToString(",") { it.tsvSafe().replace(',', ' ') },
                    d.sas.tsvSafe(),
                    if (d.sasConfirmed) "1" else "0",
                    if (d.sasMismatchReported) "1" else "0",
                    d.ownerUserId.tsvSafe()
                ).joinToString("\t")
            )
        }
        receiptList.forEach { r ->
            lines.add(
                listOf(
                    "receipt",
                    r.enrollerName.tsvSafe(),
                    r.enrollerDeviceId.tsvSafe(),
                    r.scope.tsvSafe(),
                    r.groupName.tsvSafe(),
                    r.enrolledAtMs.toString(),
                    r.sas.tsvSafe(),
                    if (r.sasConfirmed) "1" else "0",
                    if (r.sasMismatchReported) "1" else "0"
                ).joinToString("\t")
            )
        }
        sasAuditList.forEach { e ->
            lines.add(
                listOf(
                    "sas",
                    e.deviceId.tsvSafe(),
                    e.action.tsvSafe(),
                    e.atMs.toString()
                ).joinToString("\t")
            )
        }
        // D38 S1-AND F4: atomic replace only — tmp, fsync, rename.
        // The old direct-write fallback could truncate the roster
        // on a crash mid-write; a failed rename now throws and the
        // mutating callers roll back.
        val parent = storeFile.parentFile
        val bytes = lines.joinToString("\n").toByteArray(Charsets.UTF_8)
        if (parent != null) {
            val tmp = File(parent, storeFile.name + ".tmp")
            java.io.FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            if (!tmp.renameTo(storeFile)) {
                tmp.delete()
                throw IllegalStateException("enrollment store: atomic rename failed for ${storeFile.name}")
            }
        } else {
            java.io.FileOutputStream(storeFile).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
        }
    }

    private fun String.tsvSafe(): String = replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')

    private fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

    companion object {
        const val CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        const val CODE_LENGTH = 10
        const val CODE_TTL_MS = 10 * 60 * 1000L
        const val MAX_SAS_AUDIT_ENTRIES = 512
        const val MAX_REDEEM_ATTEMPTS = 5

        const val SCOPE_LOCAL = "local"
        const val SCOPE_PERSONAL = "personal"
        const val SCOPE_COMPANY = "company"
        val SCOPES = setOf(SCOPE_LOCAL, SCOPE_PERSONAL, SCOPE_COMPANY)

        // D31 transport modes (data model only).
        const val TRANSPORT_MODE_INHERIT = "inherit"
        const val TRANSPORT_MODE_AUTO = "auto"
        const val TRANSPORT_MODE_MANUAL = "manual"
        val TRANSPORT_MODES = setOf(TRANSPORT_MODE_INHERIT, TRANSPORT_MODE_AUTO, TRANSPORT_MODE_MANUAL)

        /** Unknown modes degrade to "inherit" — never persisted raw. */
        fun normalizeTransportMode(mode: String?): String {
            val normalized = mode?.trim()?.lowercase() ?: return TRANSPORT_MODE_INHERIT
            return if (normalized in TRANSPORT_MODES) normalized else TRANSPORT_MODE_INHERIT
        }

        /** Display form XXXXX-XXXXX of a raw/normalized code. */
        fun formatCode(code: String): String {
            val raw = normalizeCode(code) ?: return code
            return raw.substring(0, 5) + "-" + raw.substring(5, 10)
        }

        /** Strip the dash, uppercase; null when not a plausible code. */
        fun normalizeCode(code: String?): String? {
            if (code == null) return null
            val raw = code.replace("-", "").trim().uppercase()
            if (raw.length != CODE_LENGTH) return null
            if (!raw.all { it in CODE_ALPHABET }) return null
            return raw
        }
    }
}

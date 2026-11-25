package io.agenticcontrol.app.session

import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.enterprise.PolicyFeatures
import io.agenticcontrol.app.roster.RosterStore
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Standalone file transfer (Block G, G-04) — the Android mirror
 * of the Windows StandaloneTransferService. A "send a file to my
 * PC" job that is NOT bound to a session: the Slice 3 FileJob is
 * session-bound by construction (its jobs die with their
 * session), so the outside-session form carries the same
 * invariants — monotonic progress, "done" requires full bytes,
 * the same closed transition set — without a SessionId.
 *
 * Authorization is the standing Slice 2 "use" grant on the
 * target device's group: the same basis on which an unattended
 * session may be started against that device. There is no new
 * authority here — a standalone transfer is exactly as powerful
 * as the session its initiator could have opened, minus the
 * session. The authorization is RE-READ before every act: a job
 * whose device was revoked, whose scope filing moved, or whose
 * initiator lost the grant mid-flight is cancelled on the spot,
 * recorded, and the act refuses.
 *
 * The model carries job state only; the byte-moving leg rides
 * the transports like any other transfer and is not claimed
 * here. The whole store is policy-toggleable (TOTAL POLICY
 * CONTROL, key `standalone_file_transfer`).
 */
data class StandaloneJob(
    val id: String,
    val scopeId: String,
    val deviceId: String,
    val initiatorUserId: String,
    val direction: String,
    val name: String,
    val sizeBytes: Long,
    val transferredBytes: Long = 0L,
    val state: String = JOB_QUEUED
) {
    companion object {
        const val JOB_QUEUED = "queued"
        const val JOB_ACTIVE = "active"
        const val JOB_PAUSED = "paused"
        const val JOB_DONE = "done"
        const val JOB_FAILED = "failed"
        const val JOB_CANCELLED = "cancelled"
        val STATES = setOf(JOB_QUEUED, JOB_ACTIVE, JOB_PAUSED, JOB_DONE, JOB_FAILED, JOB_CANCELLED)
        val TERMINAL = setOf(JOB_DONE, JOB_FAILED, JOB_CANCELLED)

        /** The closed transition set — shared with the session
         *  file jobs (one transfer discipline for the product).
         *  Terminal states have no outgoing edges; "done"
         *  additionally requires full bytes (enforced by the
         *  store, not expressible in this table). */
        fun isLegalTransition(from: String?, to: String?): Boolean =
            when ((from ?: "").trim().lowercase() to (to ?: "").trim().lowercase()) {
                JOB_QUEUED to JOB_ACTIVE, JOB_QUEUED to JOB_PAUSED,
                JOB_QUEUED to JOB_FAILED, JOB_QUEUED to JOB_CANCELLED,
                JOB_ACTIVE to JOB_PAUSED, JOB_ACTIVE to JOB_DONE,
                JOB_ACTIVE to JOB_FAILED, JOB_ACTIVE to JOB_CANCELLED,
                JOB_PAUSED to JOB_ACTIVE, JOB_PAUSED to JOB_DONE,
                JOB_PAUSED to JOB_FAILED, JOB_PAUSED to JOB_CANCELLED -> true
                else -> false
            }
    }
}

data class StandaloneEvent(
    val atMs: Long,
    val kind: String,
    val jobId: String,
    val actorUserId: String?,
    val detail: String
)

class StandaloneTransferStore(
    private val roster: RosterStore,
    private val enrollment: EnrollmentStore,
    private val featureGate: ((String, String) -> Boolean)? = null,
    /** Change hook for wiring write-through persistence (AF10).
     *  NOT the last parameter: the clock stays last so existing
     *  trailing-lambda call sites keep binding to it. */
    private val onChanged: (() -> Unit)? = null,
    private val nowMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val jobs = LinkedHashMap<String, StandaloneJob>()
    private val _events = ArrayList<StandaloneEvent>()
    val events: List<StandaloneEvent> get() = synchronized(this) { _events.toList() }

    /** SCOPE-AWARE gate (scopeId, featureKey) — D38-G review F2. */
    private fun featureAllowed(scopeId: String): Boolean =
        featureGate?.invoke(scopeId, PolicyFeatures.STANDALONE_FILE_TRANSFER) ?: true

    private fun device(deviceId: String?) = enrollment.byId(deviceId ?: "")

    @Synchronized
    private fun record(kind: String, job: StandaloneJob, actor: String?, detail: String) {
        _events.add(StandaloneEvent(nowMillis(), kind, job.id, actor, detail))
        onChanged?.invoke()
    }

    /** The standing authorization re-read, run before every act
     *  (the F4 discipline applied to a session-less surface). */
    private fun authorizationIntact(job: StandaloneJob): Boolean {
        val device = device(job.deviceId) ?: return false
        if (device.revoked) return false
        val group = roster.deviceGroup(device.groupId) ?: return false
        if (group.scopeId != job.scopeId) return false
        val initiator = roster.user(job.initiatorUserId) ?: return false
        if (initiator.scopeId != job.scopeId || initiator.suspended) return false
        return roster.canUse(job.scopeId, job.initiatorUserId, device.groupId)
    }

    /** Returns true when the job was just cancelled by the
     *  re-read (the caller must refuse its act). */
    @Synchronized
    private fun enforceAuthorization(job: StandaloneJob): Boolean {
        if (job.state in StandaloneJob.TERMINAL) return false
        if (authorizationIntact(job)) return false
        val cancelled = job.copy(state = StandaloneJob.JOB_CANCELLED)
        jobs[job.id] = cancelled
        record("job_cancelled_authorization_lost", cancelled, null,
            "Transfer cancelled: its authorization (device enrollment or initiator grant) no longer holds.")
        return true
    }

    /**
     * Create a standalone job in "queued". Null on refusal:
     * policy-disabled feature, unknown scope, unknown/revoked
     * device, a device not filed in the named scope (D8), an
     * initiator who is not a live user of the scope or holds no
     * "use" grant on the device's group, an unknown direction, an
     * empty name, or a negative size.
     */
    @Synchronized
    fun createJob(scopeId: String, deviceId: String, initiatorUserId: String,
                  direction: String, name: String, sizeBytes: Long): StandaloneJob? {
        if (!featureAllowed(scopeId)) return null
        val normalizedDirection = direction.trim().lowercase()
        if (normalizedDirection !in SessionStore.DIRECTIONS) return null
        if (name.isBlank() || sizeBytes < 0) return null
        val scope = roster.scope(scopeId) ?: return null
        val device = device(deviceId) ?: return null
        if (device.revoked) return null
        val group = roster.deviceGroup(device.groupId) ?: return null
        if (group.scopeId != scope.id) return null
        val initiator = roster.user(initiatorUserId) ?: return null
        if (initiator.scopeId != scope.id || initiator.suspended) return null
        if (!roster.canUse(scope.id, initiator.id, device.groupId)) return null
        val job = StandaloneJob(
            UUID.randomUUID().toString().replace("-", ""), scope.id, device.deviceId,
            initiator.id, normalizedDirection, name.trim(), sizeBytes)
        jobs[job.id] = job
        record("job_created", job, initiator.id,
            "Standalone transfer '${job.name}' ($normalizedDirection, $sizeBytes bytes) queued for ${device.deviceId}.")
        return job
    }

    @Synchronized
    fun job(jobId: String?): StandaloneJob? =
        if (jobId.isNullOrBlank()) null else jobs[jobId]

    /** Jobs for one scope, or one device within it (D8 isolation
     *  on the read too). */
    @Synchronized
    fun jobs(scopeId: String, deviceId: String? = null): List<StandaloneJob> =
        jobs.values.filter {
            it.scopeId.equals(scopeId, ignoreCase = true) &&
                (deviceId == null || it.deviceId.equals(deviceId, ignoreCase = true))
        }

    /** Live (non-terminal) job count across all scopes — a
     *  snapshot fact; counts only, never job contents. */
    @Synchronized
    fun liveJobCount(): Int = jobs.values.count { it.state !in StandaloneJob.TERMINAL }

    /**
     * Report progress. Monotonic (a lower value refuses, an
     * over-size value refuses), terminal jobs refuse, and the
     * authorization re-read runs first. Only the initiator
     * reports progress: the bytes are theirs.
     */
    @Synchronized
    fun updateProgress(jobId: String, transferredBytes: Long, actorUserId: String): Boolean {
        val job = jobs[jobId] ?: return false
        if (enforceAuthorization(job)) return false
        val current = jobs[job.id] ?: return false
        if (!featureAllowed(current.scopeId)) return false // F6/F7: disable lands on running jobs
        if (actorUserId != current.initiatorUserId) return false
        if (current.state in StandaloneJob.TERMINAL) return false
        if (transferredBytes < current.transferredBytes) return false
        if (transferredBytes > current.sizeBytes) return false
        if (transferredBytes == current.transferredBytes) return true
        jobs[job.id] = current.copy(transferredBytes = transferredBytes)
        // U5: the bytes that just moved count toward this target
        // device's data flow (delta only — progress is monotonic,
        // so the delta is exactly what moved since the last report).
        io.agenticcontrol.app.server.DataFlows.noteTransfer(
            current.deviceId, current.direction, transferredBytes - current.transferredBytes)
        record("job_progress", jobs[job.id]!!, actorUserId,
            "Transfer '${current.name}' at $transferredBytes/${current.sizeBytes} bytes.")
        return true
    }

    /**
     * Move a job along the closed transition set. "done"
     * requires full bytes. Only the initiator moves their job;
     * the authorization re-read runs first.
     */
    @Synchronized
    fun setJobState(jobId: String, state: String, actorUserId: String): Boolean {
        val normalized = state.trim().lowercase()
        if (normalized !in StandaloneJob.STATES) return false
        val job = jobs[jobId] ?: return false
        if (enforceAuthorization(job)) return false
        val current = jobs[job.id] ?: return false
        if (!featureAllowed(current.scopeId)) return false // F6/F7
        if (actorUserId != current.initiatorUserId) return false
        if (!StandaloneJob.isLegalTransition(current.state, normalized)) return false
        if (normalized == StandaloneJob.JOB_DONE && current.transferredBytes != current.sizeBytes) return false
        jobs[job.id] = current.copy(state = normalized)
        record("job_state", jobs[job.id]!!, actorUserId, "Transfer '${current.name}' → $normalized.")
        return true
    }

    /**
     * Cancel one live job (D38-G review F7). The initiator can
     * always stop their own transfer; a live company admin of
     * the job's scope can stop anyone's — the device-side house
     * must be able to halt an incoming push without the
     * initiator's cooperation (the §7.10 STOP principle on a
     * session-less surface). Recorded with its actor.
     */
    @Synchronized
    fun cancelJob(jobId: String, actorUserId: String): Boolean {
        val job = jobs[jobId] ?: return false
        if (job.state in StandaloneJob.TERMINAL) return false
        val isInitiator = actorUserId == job.initiatorUserId
        val adminUser = roster.user(actorUserId)
        val isAdmin = roster.isCompanyAdmin(job.scopeId, actorUserId) &&
            adminUser != null && adminUser.kind == RosterStore.USER_HUMAN && !adminUser.suspended
        if (!isInitiator && !isAdmin) return false
        val cancelled = job.copy(state = StandaloneJob.JOB_CANCELLED)
        jobs[job.id] = cancelled
        record("job_cancelled", cancelled, actorUserId,
            if (isInitiator) "Transfer cancelled by its initiator."
            else "Transfer cancelled by a company admin (device-side stop).")
        return true
    }

    /**
     * Cancel every live job touching a device or a user — the
     * offboarding/revocation sweep the wiring layer calls when
     * the roster changes. (Per-act re-reads already cancel
     * lazily; this is the eager form.) Returns the number
     * cancelled; the sweep's actor is recorded when named.
     */
    @Synchronized
    fun cancelJobsFor(deviceId: String? = null, initiatorUserId: String? = null,
                      actorUserId: String? = null): Int {
        var count = 0
        for (job in jobs.values.toList()) {
            if (job.state in StandaloneJob.TERMINAL) continue
            val hit = (deviceId != null && job.deviceId.equals(deviceId, ignoreCase = true)) ||
                (initiatorUserId != null && job.initiatorUserId.equals(initiatorUserId, ignoreCase = true))
            if (!hit) continue
            val cancelled = job.copy(state = StandaloneJob.JOB_CANCELLED)
            jobs[job.id] = cancelled
            record("job_cancelled_sweep", cancelled, actorUserId,
                "Transfer cancelled by an offboarding/revocation sweep.")
            count++
        }
        return count
    }

    /**
     * Block H (design 5) — policy-change teardown sweep: when
     * policy disables `standalone_file_transfer`, cancel every
     * live (non-terminal) job in [scopeId] on the spot, actor
     * `policy`. The wiring layer runs this when a new
     * PolicyEnforcer is installed/replaced. Returns the number
     * cancelled.
     */
    @Synchronized
    fun sweepPolicyTeardown(scopeId: String, featureDisabled: (String) -> Boolean): Int {
        if (!featureDisabled(PolicyFeatures.STANDALONE_FILE_TRANSFER)) return 0
        var count = 0
        for (job in jobs.values.toList()) {
            if (!job.scopeId.equals(scopeId, ignoreCase = true)) continue
            if (job.state in StandaloneJob.TERMINAL) continue
            val cancelled = job.copy(state = StandaloneJob.JOB_CANCELLED)
            jobs[job.id] = cancelled
            record("job_cancelled_policy_teardown", cancelled, "policy",
                "Transfer cancelled by policy teardown (standalone_file_transfer disabled).")
            count++
        }
        return count
    }

    // ---- persistence ----

    /** The event history exports WITH the jobs (D38-G review
     *  F1). Root {jobs, events}; import accepts the bare array. */
    @Synchronized
    fun exportJson(): String {
        val arr = JSONArray()
        for (j in jobs.values) arr.put(JSONObject()
            .put("id", j.id).put("scopeId", j.scopeId).put("deviceId", j.deviceId)
            .put("initiatorUserId", j.initiatorUserId).put("direction", j.direction)
            .put("name", j.name).put("sizeBytes", j.sizeBytes)
            .put("transferredBytes", j.transferredBytes).put("state", j.state))
        val evArr = JSONArray()
        synchronized(this) {
            for (e in _events) evArr.put(JSONObject()
                .put("atMs", e.atMs).put("kind", e.kind).put("jobId", e.jobId)
                .put("actorUserId", e.actorUserId ?: JSONObject.NULL).put("detail", e.detail))
        }
        return JSONObject().put("jobs", arr).put("events", evArr).toString()
    }

    /** Restore, re-validated with the session FileJob import
     *  discipline: unknown directions/states, negative or
     *  over-size progress, a "done" without full bytes, and
     *  duplicate ids all drop at the entry that carries them. */
    @Synchronized
    fun importJson(json: String): Int {
        val arr: JSONArray
        val evArr: JSONArray?
        try {
            val trimmed = json.trim()
            if (trimmed.startsWith("{")) {
                val root = JSONObject(trimmed)
                arr = root.optJSONArray("jobs") ?: JSONArray()
                evArr = root.optJSONArray("events")
            } else {
                arr = JSONArray(trimmed)
                evArr = null
            }
        } catch (ex: Exception) { return 0 }
        if (evArr != null) {
            for (i in 0 until evArr.length()) {
                val dto = evArr.optJSONObject(i) ?: continue
                val kind = dto.optString("kind")
                val jobId = dto.optString("jobId")
                if (kind.isBlank() || jobId.isBlank()) continue
                _events.add(StandaloneEvent(dto.optLong("atMs"), kind, jobId,
                    if (dto.isNull("actorUserId")) null else dto.optString("actorUserId"),
                    dto.optString("detail")))
            }
        }
        var restored = 0
        for (i in 0 until arr.length()) {
            val dto = arr.optJSONObject(i) ?: continue
            val id = dto.optString("id")
            if (id.isBlank() || jobs.containsKey(id)) continue
            val direction = dto.optString("direction").trim().lowercase()
            if (direction !in SessionStore.DIRECTIONS) continue
            var state = dto.optString("state").trim().lowercase()
            if (state !in StandaloneJob.STATES) continue
            val name = dto.optString("name")
            if (name.isBlank()) continue
            // F7: rows missing any identity field drop — terminal
            // rows included; a record without its scope, device
            // or initiator is not evidence, it is a hole.
            val scopeId = dto.optString("scopeId")
            val deviceId = dto.optString("deviceId")
            val initiator = dto.optString("initiatorUserId")
            if (scopeId.isBlank() || deviceId.isBlank() || initiator.isBlank()) continue
            val size = dto.optLong("sizeBytes", -1)
            val done = dto.optLong("transferredBytes", -1)
            if (size < 0 || done < 0 || done > size) continue
            if (state == StandaloneJob.JOB_DONE && done != size) continue
            // F7: a job stored "active" restores FAILED — its
            // byte leg did not survive the restart.
            if (state == StandaloneJob.JOB_ACTIVE) state = StandaloneJob.JOB_FAILED
            var job = StandaloneJob(id, scopeId, deviceId, initiator, direction, name, size, done, state)
            // AF10: live jobs re-read their authorization at the
            // door; a job whose grant died while the app was off
            // restores CANCELLED, never live.
            if (state !in StandaloneJob.TERMINAL && !authorizationIntact(job))
                job = job.copy(state = StandaloneJob.JOB_CANCELLED)
            jobs[id] = job
            restored++
        }
        return restored
    }
}

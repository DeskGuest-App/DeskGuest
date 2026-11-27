package io.deskguest.app.rmmspine

import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enterprise.sha256Hex
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Base64

/**
 * RMM-15 — Job checkpoint journal, Android mirror. Mirrors Windows
 * DeskGuest.Shared/Jobs/JobJournal.cs: multi-step jobs are checkpointed
 * on-device in a durable, hash-chained journal (entries optionally
 * Ed25519-signed by the endpoint identity) and resume after reboot
 * or connection loss. State is DERIVED by replaying entries — there
 * is no snapshot to tamper with. Resume RE-VALIDATES before any
 * non-idempotent step: broken chain fails every non-terminal job
 * journal_tampered; toggle OFF fails resume_disabled; envelope
 * expiry/signature recheck fails authority_expired /
 * authority_invalid; a non-idempotent step caught mid-flight parks
 * the job for a journalled human decision — the journal never
 * guesses. Composed from the session/transfer persistence
 * discipline (temp+replace file writes, monotonic forward state).
 */
object JobKinds {
    const val FILE_TRANSFER = "file_transfer"
    const val UPDATE_STAGING = "update_staging"
    const val SCRIPT_CHAIN = "script_chain"
    const val PATCH_RUN = "patch_run"
    const val DEPLOYMENT = "deployment"
    const val BACKUP = "backup"
    /** Classes that may authorise each kind. script_chain also
     *  accepts automation on Android: the RMM-08 mirror's verified
     *  automation envelope IS the chain's authority (named Android
     *  composition; Windows binds script_chain to script_exec). */
    val SIGNED_CLASSES: Map<String, Set<String>> = mapOf(
        UPDATE_STAGING to setOf(SignedCommandClasses.UPDATE_STAGING),
        SCRIPT_CHAIN to setOf(SignedCommandClasses.SCRIPT_EXEC, SignedCommandClasses.AUTOMATION, SignedCommandClasses.BACKGROUND_ACTION),
        PATCH_RUN to setOf(SignedCommandClasses.PATCH_DEPLOY),
        DEPLOYMENT to setOf(SignedCommandClasses.PACKAGE_DEPLOY),
        BACKUP to setOf(SignedCommandClasses.AUTOMATION)
    )
    val ALL = setOf(FILE_TRANSFER, UPDATE_STAGING, SCRIPT_CHAIN, PATCH_RUN, DEPLOYMENT, BACKUP)
    fun isKnown(k: String?) = k in ALL
}

object JobStates {
    const val PENDING = "pending"; const val RUNNING = "running"; const val RESUMED = "resumed"
    const val PARKED = "parked"; const val DONE = "done"; const val FAILED = "failed"
    fun isTerminal(s: String?) = s == DONE || s == FAILED
}
object StepStates {
    const val PENDING = "pending"; const val RUNNING = "running"; const val DONE = "done"
    const val FAILED = "failed"; const val UNCERTAIN = "uncertain"; const val SKIPPED = "skipped"
}
object JobFailureReasons {
    const val AUTHORITY_EXPIRED = "authority_expired"; const val AUTHORITY_INVALID = "authority_invalid"
    const val JOURNAL_TAMPERED = "journal_tampered"; const val RESUME_DISABLED = "resume_disabled"
    const val NON_IDEMPOTENT_UNCERTAIN = "non_idempotent_uncertain"; const val HUMAN_DECISION_FAIL = "human_decision_fail"
}
enum class ParkedDecision { RETRY_STEP, SKIP_STEP, FAIL_JOB }

data class JobStepDefinition(val stepId: String, val name: String, val idempotent: Boolean)
data class JobStepState(val stepId: String, val name: String, val idempotent: Boolean, val state: String)
data class ResumableJob(
    val id: String, val kind: String, val deviceId: String,
    val state: String, val failureReason: String?, val steps: List<JobStepState>,
    val resumeCount: Int, val envelopeJson: String?, val envelopeHash: String?
) {
    val completedSteps: Int get() = steps.count { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }
    val isTerminal: Boolean get() = JobStates.isTerminal(state)
}
data class JournalEntry(
    val seq: Long, val jobId: String, val atMs: Long, val kind: String,
    val detail: String, val prevHash: String, val hash: String, val signatureBase64: String?
)
data class JournalVerification(val ok: Boolean, val brokenAtSeq: Long?, val summary: String)
data class ResumeOutcome(val jobId: String, val outcome: String, val detail: String)
data class ResumeReport(val outcomes: List<ResumeOutcome>, val chainOk: Boolean, val authorityRechecked: Boolean) {
    val resumedCount: Int get() = outcomes.count { it.outcome == "resumed" }
}
data class JobStateSummary(val jobId: String, val kind: String, val state: String, val failureReason: String?,
    val completedSteps: Int, val totalSteps: Int, val resumeCount: Int)
data class JobStateReport(val deviceId: String, val generatedMs: Long, val resumeEnabled: Boolean,
    val journalHeadHash: String, val chainOk: Boolean, val jobs: List<JobStateSummary>)

class JobJournal(
    private val endpointIdentity: DeviceIdentity? = null,
    private val endpointPublicKey: ByteArray? = null
) {
    private val entries = mutableListOf<JournalEntry>()
    private val jobs = LinkedHashMap<String, ResumableJob>()
    private var chainOk = true
    private var brokenAtSeq: Long? = null
    private var chainSummary = "OK: empty journal"
    var importError: String? = null
        private set

    companion object { const val GENESIS = "GENESIS" }

    val headHash: String get() = synchronized(this) { if (entries.isEmpty()) GENESIS else entries.last().hash }
    fun verification(): JournalVerification = synchronized(this) { JournalVerification(chainOk, brokenAtSeq, chainSummary) }
    fun entries(): List<JournalEntry> = synchronized(this) { entries.toList() }
    fun getJob(id: String?): ResumableJob? = synchronized(this) { jobs[id ?: ""] }
    fun listJobs(deviceId: String? = null): List<ResumableJob> =
        synchronized(this) { jobs.values.filter { deviceId == null || it.deviceId.equals(deviceId, true) } }

    @Synchronized
    private fun appendLocked(jobId: String, kind: String, detail: String, atMs: Long): JournalEntry {
        val seq = entries.size + 1L
        val prev = if (entries.isEmpty()) GENESIS else entries.last().hash
        val hash = sha256Hex("$seq|$jobId|$atMs|$kind|$detail|$prev")
        val sig = endpointIdentity?.let { Base64.getEncoder().encodeToString(it.sign(hash.toByteArray(Charsets.UTF_8))) }
        val e = JournalEntry(seq, jobId, atMs, kind, detail, prev, hash, sig)
        entries.add(e); return e
    }

    /** Create a job. Signed kinds REQUIRE an envelope of a matching
     *  class whose hash is bound into the genesis entry; unknown
     *  kinds, wrong-class/expired envelopes, empty or duplicate
     *  steps refuse (null + reason in [lastRefusal]). */
    var lastRefusal: String? = null
        private set

    @Synchronized
    fun createJob(jobId: String, kind: String, deviceId: String,
                  steps: List<JobStepDefinition>, envelope: SignedCommandEnvelope?, nowMs: Long): ResumableJob? {
        fun refuse(r: String): ResumableJob? { lastRefusal = r; return null }
        if (!JobKinds.isKnown(kind)) return refuse("unknown job kind '$kind' — refused")
        if (jobId.isBlank() || deviceId.isBlank()) return refuse("job needs an id and a device id — refused")
        if (jobId in jobs) return refuse("job id '$jobId' already exists — refused")
        if (steps.isEmpty()) return refuse("job needs at least one step — refused")
        if (steps.map { it.stepId }.distinct().size != steps.size) return refuse("duplicate step ids — refused")
        if (steps.any { it.stepId.isBlank() }) return refuse("empty step id — refused")
        var envHash: String? = null; var envJson: String? = null
        val required = JobKinds.SIGNED_CLASSES[kind]
        if (required != null) {
            if (envelope == null) return refuse("job kind '$kind' requires a signed-command envelope — refused")
            if (envelope.commandClass !in required) return refuse("envelope class '${envelope.commandClass}' does not authorise job kind '$kind' — refused")
            val exp = IsoTime.parse(envelope.expiresUtc)
            if (exp == null || exp <= nowMs) return refuse("authorising envelope expired — refused")
            envHash = sha256Hex(envelope.toJson().toString())
            envJson = envelope.toJson().toString()
        } else if (envelope != null) {
            return refuse("job kind '$kind' takes no envelope (standing grant is its authority) — refused")
        }
        val job = ResumableJob(jobId, kind, deviceId, JobStates.PENDING, null,
            steps.map { JobStepState(it.stepId, it.name, it.idempotent, StepStates.PENDING) }, 0, envJson, envHash)
        jobs[jobId] = job
        appendLocked(jobId, "job_created",
            "kind=$kind device=$deviceId steps=${steps.joinToString(",") { it.stepId + if (it.idempotent) "(i)" else "(n)" }} envHash=${envHash ?: "-"}", nowMs)
        lastRefusal = null; return job
    }

    @Synchronized
    fun startJob(jobId: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        if (j.state != JobStates.PENDING && j.state != JobStates.RESUMED) return false
        jobs[jobId] = j.copy(state = JobStates.RUNNING)
        appendLocked(jobId, "job_started", "state=${j.state}", nowMs); return true
    }

    @Synchronized
    fun beginStep(jobId: String, stepId: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        if (j.state != JobStates.RUNNING && j.state != JobStates.RESUMED) return false
        val idx = j.steps.indexOfFirst { it.stepId == stepId }
        if (idx < 0 || j.steps[idx].state != StepStates.PENDING) return false
        // Ordered: prior steps must be done/skipped — EXCEPT a
        // prior FAILED step when the job itself was continued past
        // it (failStepContinue leaves the job RESUMED; bd-and-rmm
        // F10). A plain failStep fails the whole job, so this
        // relaxation can never smuggle a run past a job failure.
        if (j.steps.take(idx).any {
                it.state != StepStates.DONE && it.state != StepStates.SKIPPED &&
                    !(it.state == StepStates.FAILED && j.state == JobStates.RESUMED)
            }) return false // ordered
        val steps = j.steps.toMutableList(); steps[idx] = steps[idx].copy(state = StepStates.RUNNING)
        jobs[jobId] = j.copy(state = JobStates.RUNNING, steps = steps)
        appendLocked(jobId, "step_started", "step=$stepId", nowMs); return true
    }

    @Synchronized
    fun completeStep(jobId: String, stepId: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        val idx = j.steps.indexOfFirst { it.stepId == stepId }
        if (idx < 0 || j.steps[idx].state != StepStates.RUNNING) return false
        val steps = j.steps.toMutableList(); steps[idx] = steps[idx].copy(state = StepStates.DONE)
        val allDone = steps.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }
        jobs[jobId] = j.copy(steps = steps, state = if (allDone) JobStates.DONE else j.state)
        appendLocked(jobId, "step_completed", "step=$stepId", nowMs)
        if (allDone) appendLocked(jobId, "job_done", "all steps done/skipped", nowMs)
        return true
    }

    @Synchronized
    fun failStep(jobId: String, stepId: String, reason: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        val idx = j.steps.indexOfFirst { it.stepId == stepId }
        if (idx < 0 || j.isTerminal) return false
        val steps = j.steps.toMutableList()
        if (steps[idx].state == StepStates.RUNNING || steps[idx].state == StepStates.PENDING)
            steps[idx] = steps[idx].copy(state = StepStates.FAILED)
        jobs[jobId] = j.copy(steps = steps, state = JobStates.FAILED, failureReason = reason)
        appendLocked(jobId, "step_failed", "step=$stepId reason=$reason", nowMs); return true
    }

    /**
     * bd-and-rmm F10: fail ONE step and CONTINUE the job (the
     * runbook 'continue' path). The old composition called
     * [failStep] for 'continue', which marks the whole job FAILED —
     * every later beginStep then refused and the runbook silently
     * ignored the refusal. Here the step is FAILED, the job moves
     * to RESUMED (continuable), and the continuation is chained.
     */
    @Synchronized
    fun failStepContinue(jobId: String, stepId: String, reason: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        val idx = j.steps.indexOfFirst { it.stepId == stepId }
        if (idx < 0 || j.isTerminal) return false
        if (j.steps[idx].state != StepStates.RUNNING && j.steps[idx].state != StepStates.PENDING) return false
        val steps = j.steps.toMutableList(); steps[idx] = steps[idx].copy(state = StepStates.FAILED)
        jobs[jobId] = j.copy(steps = steps, state = JobStates.RESUMED)
        appendLocked(jobId, "step_failed_continue", "step=$stepId reason=$reason", nowMs); return true
    }

    /** bd-and-rmm F10: journal a step skip (the runbook skip path
     *  previously changed no journal state at all). */
    @Synchronized
    fun skipStep(jobId: String, stepId: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        val idx = j.steps.indexOfFirst { it.stepId == stepId }
        if (idx < 0 || j.isTerminal) return false
        if (j.steps[idx].state != StepStates.FAILED && j.steps[idx].state != StepStates.RUNNING && j.steps[idx].state != StepStates.PENDING) return false
        val steps = j.steps.toMutableList(); steps[idx] = steps[idx].copy(state = StepStates.SKIPPED)
        val allDone = steps.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }
        jobs[jobId] = j.copy(steps = steps, state = if (allDone) JobStates.DONE else j.state)
        appendLocked(jobId, "step_skipped", "step=$stepId", nowMs)
        if (allDone) appendLocked(jobId, "job_done", "all steps done/skipped", nowMs)
        return true
    }

    /** bd-and-rmm F10: journal a halt (previously unrecorded). */
    @Synchronized
    fun recordHalt(jobId: String, detail: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        if (j.isTerminal) return false
        appendLocked(jobId, "job_halted", detail, nowMs); return true
    }

    @Synchronized
    fun failJob(jobId: String, reason: String, nowMs: Long): Boolean {
        val j = jobs[jobId] ?: return false
        if (j.isTerminal) return false
        jobs[jobId] = j.copy(state = JobStates.FAILED, failureReason = reason)
        appendLocked(jobId, "job_failed", "reason=$reason", nowMs); return true
    }

    /**
     * Resume every non-terminal job after a restart/reconnect.
     * Re-validates FIRST: chain, toggle, envelope (hash + signature
     * recheck when [ring] is supplied, expiry always). Idempotent
     * crashed steps reset to pending (job resumed); non-idempotent
     * crashed steps become uncertain and the job PARKS.
     */
    @Synchronized
    fun resumeAll(nowMs: Long, resumeEnabled: Boolean, ring: CustomerCommandKeyRing? = null): ResumeReport {
        val outcomes = mutableListOf<ResumeOutcome>()
        var rechecked = false
        if (!chainOk) {
            for (j in jobs.values.filter { !it.isTerminal }) {
                jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.JOURNAL_TAMPERED)
                outcomes += ResumeOutcome(j.id, "failed", "journal chain broken — ${JobFailureReasons.JOURNAL_TAMPERED}")
            }
            return ResumeReport(outcomes, false, false)
        }
        for (j in jobs.values.filter { !it.isTerminal }.toList()) {
            if (j.state == JobStates.PARKED) { outcomes += ResumeOutcome(j.id, "parked", "awaiting human decision"); continue }
            if (!resumeEnabled) {
                jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.RESUME_DISABLED)
                appendLocked(j.id, "job_failed", "reason=${JobFailureReasons.RESUME_DISABLED}", nowMs)
                outcomes += ResumeOutcome(j.id, "failed", JobFailureReasons.RESUME_DISABLED); continue
            }
            // Authority recheck before ANY step moves.
            if (j.envelopeJson != null) {
                val env = SignedCommandEnvelope.fromJson(try { JSONObject(j.envelopeJson) } catch (_: Exception) { null })
                if (env == null || sha256Hex(j.envelopeJson) != j.envelopeHash) {
                    jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.AUTHORITY_INVALID)
                    appendLocked(j.id, "job_failed", "reason=${JobFailureReasons.AUTHORITY_INVALID} (envelope hash mismatch)", nowMs)
                    outcomes += ResumeOutcome(j.id, "failed", JobFailureReasons.AUTHORITY_INVALID); continue
                }
                // bd-and-rmm F7 fix: the signature recheck is
                // MANDATORY for envelope-carrying jobs. The old
                // code compared sha256(envelopeJson) to the stored
                // envelopeHash — both read from the same imported
                // record — so a re-signed-by-nobody envelope passed
                // whenever no ring was supplied. No ring, no resume.
                if (ring == null) {
                    jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.AUTHORITY_INVALID)
                    appendLocked(j.id, "job_failed", "reason=${JobFailureReasons.AUTHORITY_INVALID} (no key ring supplied — signature recheck is mandatory for envelope jobs)", nowMs)
                    outcomes += ResumeOutcome(j.id, "failed", JobFailureReasons.AUTHORITY_INVALID); continue
                }
                val exp = IsoTime.parse(env.expiresUtc)
                if (exp == null || exp <= nowMs) {
                    jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.AUTHORITY_EXPIRED)
                    appendLocked(j.id, "job_failed", "reason=${JobFailureReasons.AUTHORITY_EXPIRED}", nowMs)
                    outcomes += ResumeOutcome(j.id, "failed", JobFailureReasons.AUTHORITY_EXPIRED); continue
                }
                if (ring != null) {
                    val v = SignedCommandVerifier(ring, InMemoryReplayGuard()).verifySignatureOnly(env, nowMs)
                    rechecked = true
                    if (!v.allowed) {
                        jobs[j.id] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.AUTHORITY_INVALID)
                        appendLocked(j.id, "job_failed", "reason=${JobFailureReasons.AUTHORITY_INVALID} (${v.reason})", nowMs)
                        outcomes += ResumeOutcome(j.id, "failed", JobFailureReasons.AUTHORITY_INVALID); continue
                    }
                }
            }
            val running = j.steps.firstOrNull { it.state == StepStates.RUNNING }
            when {
                j.state == JobStates.PENDING -> outcomes += ResumeOutcome(j.id, "pending", "never started — stays honestly pending")
                running == null -> {
                    jobs[j.id] = j.copy(state = JobStates.RESUMED, resumeCount = j.resumeCount + 1)
                    appendLocked(j.id, "job_resumed", "no step mid-flight", nowMs)
                    outcomes += ResumeOutcome(j.id, "resumed", "crash between steps — safe to continue")
                }
                running.idempotent -> {
                    val steps = j.steps.map { if (it.stepId == running.stepId) it.copy(state = StepStates.PENDING) else it }
                    jobs[j.id] = j.copy(state = JobStates.RESUMED, steps = steps, resumeCount = j.resumeCount + 1)
                    appendLocked(j.id, "job_resumed", "idempotent step ${running.stepId} reset to pending", nowMs)
                    outcomes += ResumeOutcome(j.id, "resumed", "idempotent step ${running.stepId} reset")
                }
                else -> {
                    val steps = j.steps.map { if (it.stepId == running.stepId) it.copy(state = StepStates.UNCERTAIN) else it }
                    jobs[j.id] = j.copy(state = JobStates.PARKED, steps = steps, failureReason = JobFailureReasons.NON_IDEMPOTENT_UNCERTAIN)
                    appendLocked(j.id, "job_parked", "step=${running.stepId} reason=${JobFailureReasons.NON_IDEMPOTENT_UNCERTAIN}", nowMs)
                    outcomes += ResumeOutcome(j.id, "parked", "non-idempotent step ${running.stepId} uncertain — human decision required")
                }
            }
        }
        return ResumeReport(outcomes, true, rechecked)
    }

    /** The ONLY way a parked job moves: a journalled human decision. */
    @Synchronized
    fun resolveParked(jobId: String, decision: ParkedDecision, decidedBy: String, nowMs: Long): Boolean {
        if (decidedBy.isBlank()) return false
        val j = jobs[jobId] ?: return false
        if (j.state != JobStates.PARKED) return false
        val idx = j.steps.indexOfFirst { it.state == StepStates.UNCERTAIN }
        if (idx < 0) return false
        val steps = j.steps.toMutableList()
        when (decision) {
            ParkedDecision.RETRY_STEP -> {
                steps[idx] = steps[idx].copy(state = StepStates.PENDING)
                jobs[jobId] = j.copy(state = JobStates.RESUMED, steps = steps, failureReason = null, resumeCount = j.resumeCount + 1)
            }
            ParkedDecision.SKIP_STEP -> {
                steps[idx] = steps[idx].copy(state = StepStates.SKIPPED)
                val allDone = steps.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }
                jobs[jobId] = j.copy(state = if (allDone) JobStates.DONE else JobStates.RESUMED, steps = steps, failureReason = null)
            }
            ParkedDecision.FAIL_JOB -> {
                steps[idx] = steps[idx].copy(state = StepStates.FAILED)
                jobs[jobId] = j.copy(state = JobStates.FAILED, steps = steps, failureReason = JobFailureReasons.HUMAN_DECISION_FAIL)
            }
        }
        appendLocked(jobId, "human_decision", "by=$decidedBy decision=$decision step=${j.steps[idx].stepId}", nowMs)
        return true
    }

    fun buildStateReport(deviceId: String, resumeEnabled: Boolean, nowMs: Long): JobStateReport = synchronized(this) {
        JobStateReport(deviceId, nowMs, resumeEnabled, headHash, chainOk,
            jobs.values.filter { it.deviceId.equals(deviceId, true) }
                .map { JobStateSummary(it.id, it.kind, it.state, it.failureReason, it.completedSteps, it.steps.size, it.resumeCount) })
    }

    // ---- persistence: entries ONLY, replay on import ----

    @Synchronized
    fun exportJson(): String {
        val arr = JSONArray()
        for (e in entries) arr.put(JSONObject()
            .put("seq", e.seq).put("jobId", e.jobId).put("atMs", e.atMs).put("kind", e.kind)
            .put("detail", e.detail).put("prevHash", e.prevHash).put("hash", e.hash)
            .put("signatureBase64", e.signatureBase64 ?: JSONObject.NULL))
        // Job definitions (steps + envelope) ride as data; STATE never does.
        val defs = JSONArray()
        for (j in jobs.values) {
            val steps = JSONArray()
            for (s in j.steps) steps.put(JSONObject().put("stepId", s.stepId).put("name", s.name).put("idempotent", s.idempotent))
            defs.put(JSONObject().put("id", j.id).put("kind", j.kind).put("deviceId", j.deviceId)
                .put("steps", steps).put("envelopeJson", j.envelopeJson ?: JSONObject.NULL)
                .put("envelopeHash", j.envelopeHash ?: JSONObject.NULL))
        }
        return JSONObject().put("entries", arr).put("jobs", defs).toString()
    }

    @Synchronized
    fun importJson(json: String): JournalVerification {
        entries.clear(); jobs.clear(); chainOk = true; brokenAtSeq = null; importError = null
        try {
            val root = JSONObject(json)
            val defs = root.getJSONArray("jobs")
            for (i in 0 until defs.length()) {
                val d = defs.getJSONObject(i)
                val stepsArr = d.getJSONArray("steps")
                val steps = (0 until stepsArr.length()).map {
                    val s = stepsArr.getJSONObject(it)
                    JobStepState(s.getString("stepId"), s.optString("name", ""), s.optBoolean("idempotent"), StepStates.PENDING)
                }
                val envJson = if (d.isNull("envelopeJson")) null else d.getString("envelopeJson")
                val envHash = if (d.isNull("envelopeHash")) null else d.getString("envelopeHash")
                jobs[d.getString("id")] = ResumableJob(d.getString("id"), d.getString("kind"), d.getString("deviceId"),
                    JobStates.PENDING, null, steps, 0, envJson, envHash)
            }
            val arr = root.getJSONArray("entries")
            var prev = GENESIS
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val e = JournalEntry(o.getLong("seq"), o.getString("jobId"), o.getLong("atMs"), o.getString("kind"),
                    o.getString("detail"), o.getString("prevHash"), o.getString("hash"),
                    if (o.isNull("signatureBase64")) null else o.getString("signatureBase64"))
                val expect = sha256Hex("${e.seq}|${e.jobId}|${e.atMs}|${e.kind}|${e.detail}|${e.prevHash}")
                var bad = e.prevHash != prev || e.hash != expect
                if (!bad && endpointPublicKey != null) {
                    if (e.signatureBase64 == null) bad = true
                    else {
                        val sig = try { Base64.getDecoder().decode(e.signatureBase64) } catch (_: Exception) { null }
                        if (sig == null || !DeviceIdentity.verify(endpointPublicKey, e.hash.toByteArray(Charsets.UTF_8), sig)) bad = true
                    }
                }
                if (bad) {
                    // Stop replay at the break: entries at/after it are
                    // untrusted and never change job state.
                    chainOk = false; brokenAtSeq = e.seq
                    chainSummary = "BROKEN at seq ${e.seq}: chain or signature invalid — replay stopped, later entries untrusted"
                    importError = chainSummary
                    return JournalVerification(false, e.seq, chainSummary)
                }
                entries.add(e); prev = e.hash; replayLocked(e)
            }
            // bd-and-rmm F7 fix: definitions are now CROSS-CHECKED
            // against the chain. The old import built jobs from the
            // unchained "jobs" array first and never compared them
            // to the chained job_created entries — a tampered
            // definition (idempotency flipped, envelope swapped)
            // imported cleanly under an intact chain. Every def
            // must match its job_created entry: same step ids, same
            // idempotency flags, and the entry's envHash must equal
            // sha256(def.envelopeJson) and the def's envelopeHash.
            // A def with no job_created entry, or any mismatch, is
            // DROPPED and the import is flagged not-ok.
            val defProblems = mutableListOf<String>()
            for ((jobId, job) in jobs.toMap()) {
                val created = entries.firstOrNull { it.jobId == jobId && it.kind == "job_created" }
                if (created == null) {
                    defProblems += "job '$jobId' has no chained job_created entry — definition dropped"
                    jobs.remove(jobId); continue
                }
                val stepsSeg = created.detail.split(" ").firstOrNull { it.startsWith("steps=") }?.removePrefix("steps=") ?: ""
                val entrySteps = if (stepsSeg.isBlank()) emptyList()
                    else stepsSeg.split(",").map {
                        val idem = it.endsWith("(i)")
                        it.removeSuffix("(i)").removeSuffix("(n)") to idem
                    }
                val defSteps = job.steps.map { it.stepId to it.idempotent }
                if (entrySteps != defSteps) {
                    defProblems += "job '$jobId' definition steps/idempotency do not match its chained job_created entry — definition dropped"
                    jobs.remove(jobId); continue
                }
                val entryEnvHash = created.detail.split(" ").firstOrNull { it.startsWith("envHash=") }?.removePrefix("envHash=") ?: "-"
                if (job.envelopeJson != null) {
                    val recomputed = sha256Hex(job.envelopeJson)
                    if (entryEnvHash != recomputed || job.envelopeHash != recomputed) {
                        defProblems += "job '$jobId' envelope does not match its chained job_created envHash — definition dropped"
                        jobs.remove(jobId); continue
                    }
                } else if (entryEnvHash != "-") {
                    defProblems += "job '$jobId' carries no envelope but its chained job_created entry binds one — definition dropped"
                    jobs.remove(jobId); continue
                }
            }
            if (defProblems.isNotEmpty()) {
                chainOk = false
                importError = "journal import: definition/chain mismatch — " + defProblems.joinToString("; ")
                chainSummary = importError!!
                return JournalVerification(false, null, chainSummary)
            }
            chainSummary = "OK: ${entries.size} entries, chain intact, head $prev"
            return JournalVerification(true, null, chainSummary)
        } catch (ex: Exception) {
            chainOk = false; importError = "journal import failed: ${ex.message}"
            return JournalVerification(false, null, importError!!)
        }
    }

    private fun replayLocked(e: JournalEntry) {
        val j = jobs[e.jobId] ?: return
        fun stepsWith(stepId: String, st: String): List<JobStepState> =
            j.steps.map { if (it.stepId == stepId) it.copy(state = st) else it }
        fun stepId(): String = e.detail.split(" ").firstOrNull { it.startsWith("step=") }?.removePrefix("step=") ?: ""
        when (e.kind) {
            "job_started" -> jobs[e.jobId] = j.copy(state = JobStates.RUNNING)
            "step_started" -> jobs[e.jobId] = j.copy(state = JobStates.RUNNING, steps = stepsWith(stepId(), StepStates.RUNNING))
            "step_completed" -> {
                val ns = stepsWith(stepId(), StepStates.DONE)
                jobs[e.jobId] = j.copy(steps = ns)
            }
            "job_done" -> {
                // Replay requires every step done/skipped — a forged
                // job_done over unfinished steps changes nothing.
                if (j.steps.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED })
                    jobs[e.jobId] = j.copy(state = JobStates.DONE)
            }
            "step_failed" -> jobs[e.jobId] = j.copy(state = JobStates.FAILED,
                failureReason = e.detail.substringAfter("reason=", "step_failed"),
                steps = if (stepId().isNotBlank()) stepsWith(stepId(), StepStates.FAILED) else j.steps)
            "job_failed" -> jobs[e.jobId] = j.copy(state = JobStates.FAILED,
                failureReason = e.detail.removePrefix("reason=").substringBefore(" "))
            "step_failed_continue" -> jobs[e.jobId] = j.copy(state = JobStates.RESUMED,
                steps = if (stepId().isNotBlank()) stepsWith(stepId(), StepStates.FAILED) else j.steps)
            "step_skipped" -> {
                val ns = stepsWith(stepId(), StepStates.SKIPPED)
                jobs[e.jobId] = j.copy(steps = ns,
                    state = if (ns.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }) JobStates.DONE else j.state)
            }
            "job_halted" -> Unit // recorded; changes no state
            "job_resumed" -> jobs[e.jobId] = j.copy(state = JobStates.RESUMED, resumeCount = j.resumeCount + 1,
                steps = j.steps.map { if (it.state == StepStates.RUNNING && it.idempotent) it.copy(state = StepStates.PENDING) else it })
            "job_parked" -> jobs[e.jobId] = j.copy(state = JobStates.PARKED,
                failureReason = JobFailureReasons.NON_IDEMPOTENT_UNCERTAIN,
                steps = j.steps.map { if (it.stepId == stepId() && it.state == StepStates.RUNNING) it.copy(state = StepStates.UNCERTAIN) else it })
            "human_decision" -> {
                val dec = e.detail.split(" ").firstOrNull { it.startsWith("decision=") }?.removePrefix("decision=") ?: ""
                val sid = stepId()
                when (dec) {
                    "RETRY_STEP" -> jobs[e.jobId] = j.copy(state = JobStates.RESUMED, failureReason = null, steps = stepsWith(sid, StepStates.PENDING))
                    "SKIP_STEP" -> {
                        val ns = stepsWith(sid, StepStates.SKIPPED)
                        jobs[e.jobId] = j.copy(state = if (ns.all { it.state == StepStates.DONE || it.state == StepStates.SKIPPED }) JobStates.DONE else JobStates.RESUMED, steps = ns, failureReason = null)
                    }
                    "FAIL_JOB" -> jobs[e.jobId] = j.copy(state = JobStates.FAILED, failureReason = JobFailureReasons.HUMAN_DECISION_FAIL, steps = stepsWith(sid, StepStates.FAILED))
                }
            }
        }
    }

    fun saveToFile(file: File) {
        val text = synchronized(this) { exportJson() }
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) { tmp.delete(); throw IllegalStateException("journal save rename failed") }
    }

    fun loadFromFile(file: File): JournalVerification {
        if (!file.exists()) return JournalVerification(false, null, "journal file absent — nothing loaded (named, not an empty journal)")
        return importJson(file.readText())
    }
}

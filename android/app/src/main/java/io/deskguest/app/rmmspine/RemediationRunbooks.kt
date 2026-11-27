package io.deskguest.app.rmmspine

import io.deskguest.app.enterprise.ChainedAuditLog
import io.deskguest.app.enterprise.sha256Hex
import io.deskguest.app.server.ApprovalGate

/**
 * RMM-08 (Android) + RMM-20 (Android target-side) mirrors.
 *
 * RMM-08 Android catalogue is the small platform-bounded set from
 * BUILD-PROGRAMME.md's completion-phase decisions — re-apply
 * policy, clear DeskGuest cache, restart DeskGuest components, re-run a failed
 * DeskGuest job. No general device remediation is claimed on a personal
 * phone. Every execution rides the RMM-03 gate (class automation,
 * payload-bound) and checkpoints into the RMM-15 journal.
 *
 * RMM-20 Android step catalogue is bounded to steps executable via
 * the RMM-08 mirror (remediation steps), the background-tool seam
 * (tool steps), checks over honestly observable facts, and human
 * confirmations. Approval gates ride the existing ApprovalGate
 * machinery (owner-set policy per action class). Execution rides
 * RMM-03 + RMM-15 exactly as RMM-08 does.
 */
object RemediationActions {
    const val REAPPLY_POLICY = "reapply_policy"
    const val CLEAR_DESKGUEST_CACHE = "clear_deskguest_cache"
    const val RESTART_DESKGUEST_COMPONENTS = "restart_deskguest_components"
    const val RERUN_FAILED_DESKGUEST_JOB = "rerun_failed_deskguest_job"
    val ALL = setOf(REAPPLY_POLICY, CLEAR_DESKGUEST_CACHE, RESTART_DESKGUEST_COMPONENTS, RERUN_FAILED_DESKGUEST_JOB)
    /** Idempotency per action: re-running a failed job can double
     *  its effects, so it is NON-idempotent (journal parks it). */
    fun isIdempotent(action: String): Boolean = action != RERUN_FAILED_DESKGUEST_JOB
    fun canonicalPayload(action: String, deviceId: String, runId: String): String =
        listOf("deskguest-remediation-v1", action, deviceId, runId).joinToString("|")
}

/** The platform seam: the Android binding (RemediationPlatform.kt
 *  hooks) performs the real acts; tests use the recording fake.
 *  An executor that cannot perform an act says so — never fakes. */
interface RemediationExecutor {
    fun perform(action: String, deviceId: String, detail: String): Pair<Boolean, String>
}
class RecordingRemediationExecutor : RemediationExecutor {
    val performed = mutableListOf<String>()
    var failActions: Set<String> = emptySet()
    override fun perform(action: String, deviceId: String, detail: String): Pair<Boolean, String> {
        performed += action
        return if (action in failActions) false to "action '$action' failed (recording executor, injected failure)"
        else true to "action '$action' performed on '$deviceId' (recording executor)"
    }
}
class UnavailableRemediationExecutor : RemediationExecutor {
    override fun perform(action: String, deviceId: String, detail: String): Pair<Boolean, String> =
        false to "no remediation executor is wired on this host — action '$action' NOT performed (named, never faked)"
}

data class RemediationOutcome(val runId: String, val action: String, val deviceId: String,
    val executed: Boolean, val detail: String, val journalJobId: String?)

class RemediationService(
    private val engine: ManagementPolicyEngine,
    private val gate: SignedCommandGate?,
    private val executor: RemediationExecutor,
    private val journal: JobJournal,
    private val audit: ChainedAuditLog
) {
    fun execute(action: String?, deviceId: String, runId: String, detail: String,
                envelope: SignedCommandEnvelope?, facts: DeviceFacts?, actor: String, nowMs: Long): RemediationOutcome {
        fun refuse(reason: String): RemediationOutcome {
            audit.append("remediation_refused", actor, "action=${action ?: "(none)"} device=$deviceId reason=$reason", nowMs)
            return RemediationOutcome(runId, action ?: "", deviceId, false, reason, null)
        }
        if (action == null || action !in RemediationActions.ALL)
            return refuse("unknown remediation action '${action ?: "(none)"}' — refused (the Android catalogue is closed: ${RemediationActions.ALL.sorted().joinToString(",")})")
        if (facts == null) return refuse("no device facts for '$deviceId' — remediation refuses (policy cannot be evaluated)")
        if (!engine.isEnabled(facts, "rmm.remediation.enabled"))
            return refuse("auto-remediation is disabled by policy for device '$deviceId' (rmm.remediation.enabled) — refused")
        engine.computeEffective(facts).get("rmm.remediation.$action.enabled")?.let {
            if (it.value.toBooleanStrictOrNull() == false) return refuse("remediation action '$action' is disabled by policy — refused")
        }
        if (gate == null) return refuse("no signed-command gate configured — remediation refuses (RMM-03 coverage is not claimed)")
        val expected = RemediationActions.canonicalPayload(action, deviceId, runId).toByteArray(Charsets.UTF_8)
        val v = gate.authorize(envelope, nowMs, SignedCommandClasses.AUTOMATION, expected)
        if (!v.allowed) return refuse("signed-command verification failed: ${v.reason}")
        // Checkpoint into the RMM-15 journal BEFORE performing.
        val jobId = "remediation-$runId"
        val job = journal.createJob(jobId, JobKinds.SCRIPT_CHAIN, deviceId,
            listOf(JobStepDefinition(action, action, RemediationActions.isIdempotent(action))), envelope, nowMs)
            ?: return refuse("journal refused the remediation job: ${journal.lastRefusal}")
        journal.startJob(jobId, nowMs)
        if (!journal.beginStep(jobId, action, nowMs)) return refuse("journal could not begin the remediation step")
        val (ok, why) = try { executor.perform(action, deviceId, detail) }
            catch (ex: Exception) { false to "executor threw (${ex.javaClass.simpleName}) — action NOT performed" }
        if (ok) journal.completeStep(jobId, action, nowMs) else journal.failStep(jobId, action, why, nowMs)
        audit.append(if (ok) "remediation_executed" else "remediation_failed", actor,
            "action=$action device=$deviceId job=$jobId detail=$why", nowMs)
        return RemediationOutcome(runId, action, deviceId, ok, why, jobId)
    }
}

// ---------------- RMM-20 runbooks (Android target-side) ----------------

object RunbookStepKinds {
    const val REMEDIATION = "remediation"       // names an RMM-08 Android action
    const val BACKGROUND_TOOL = "background_tool" // names a tool on the background seam
    const val CHECK = "check"                   // closed check vocabulary below
    const val HUMAN_CONFIRMATION = "human_confirmation"
    val ALL = setOf(REMEDIATION, BACKGROUND_TOOL, CHECK, HUMAN_CONFIRMATION)
}
object RunbookChecks {
    const val POLICY_ENABLED = "policy_enabled"       // arg: policy key — observed via the engine
    const val DESKGUEST_RUNNING = "deskguest_running"             // observed via the check seam
    const val JOB_STATE = "job_state"                 // arg: job id — observed via the journal
    val ALL = setOf(POLICY_ENABLED, DESKGUEST_RUNNING, JOB_STATE)
}

data class RunbookStep(
    val stepId: String, val kind: String, val ref: String,
    val failurePolicy: String = "halt", // halt | continue | route (route target in routeTo)
    val routeTo: String? = null,
    val requiresApproval: Boolean = false,
    val requiredApproverId: String? = null,
    val requiredAttesterId: String? = null,
    val requireDistinctAttester: Boolean = false,
    val prompt: String = ""
)
data class RunbookDefinition(val id: String, val name: String, val revision: Long, val steps: List<RunbookStep>) {
    fun contentHash(): String = sha256Hex(steps.joinToString(";") {
        "${it.stepId}:${it.kind}:${it.ref}:${it.failurePolicy}:${it.routeTo ?: ""}:${it.requiresApproval}:${it.requiredApproverId ?: ""}:${it.requiredAttesterId ?: ""}:${it.requireDistinctAttester}:${it.prompt}"
    } + "|$id|$revision")
    fun validate(): String? {
        if (id.isBlank()) return "runbook needs an id — refused"
        if (steps.isEmpty()) return "runbook '$id' needs at least one step — refused"
        if (steps.map { it.stepId }.distinct().size != steps.size) return "runbook '$id' has duplicate step ids — refused"
        val ids = steps.map { it.stepId }.toSet()
        for (s in steps) {
            if (s.kind !in RunbookStepKinds.ALL) return "runbook step '${s.stepId}' has unknown kind '${s.kind}' — refused (catalogue is closed)"
            when (s.kind) {
                RunbookStepKinds.REMEDIATION ->
                    if (s.ref !in RemediationActions.ALL) return "runbook step '${s.stepId}' names remediation action '${s.ref}' outside the Android catalogue — refused"
                RunbookStepKinds.CHECK ->
                    if (s.ref !in RunbookChecks.ALL) return "runbook step '${s.stepId}' names check '${s.ref}' outside the closed vocabulary — refused"
                RunbookStepKinds.BACKGROUND_TOOL ->
                    if (s.ref.isBlank()) return "runbook step '${s.stepId}' names no background tool — refused"
                RunbookStepKinds.HUMAN_CONFIRMATION ->
                    if (s.prompt.isBlank()) return "runbook step '${s.stepId}' is a human confirmation with no prompt — refused"
            }
            if (s.failurePolicy !in setOf("halt", "continue", "route")) return "runbook step '${s.stepId}' has unknown failure policy '${s.failurePolicy}' — refused"
            if (s.failurePolicy == "route" && (s.routeTo == null || s.routeTo !in ids)) return "runbook step '${s.stepId}' routes to unknown step '${s.routeTo}' — refused"
            // bd-and-rmm F8 fix: a route must go strictly FORWARD.
            // The old check accepted self-routes and backward
            // routes; advance() executes the first PENDING record,
            // so a backward/self route re-pends an earlier step and
            // the run loops forever. Route target index must exceed
            // the source step's index.
            if (s.failurePolicy == "route") {
                val fromIdx = steps.indexOfFirst { it.stepId == s.stepId }
                val toIdx = steps.indexOfFirst { it.stepId == s.routeTo }
                if (toIdx <= fromIdx) return "runbook step '${s.stepId}' routes to '${s.routeTo}', which is not a LATER step — backward/self routes loop forever and are refused"
            }
        }
        return null
    }
    companion object {
        fun canonicalPayload(runbookId: String, deviceId: String, runId: String): String =
            listOf("deskguest-runbook-v1", runbookId, deviceId, runId).joinToString("|")
    }
}

data class RunbookStepRecord(val stepId: String, val kind: String, val state: String,
    val detail: String, val checkPassed: Boolean?, val actor: String?)
data class RunbookRun(
    val runId: String, val runbookId: String, val deviceId: String, val initiatedBy: String,
    val status: String, // running | paused_awaiting_attestation | paused_awaiting_approval | halted_check_failed | succeeded | partial_failure | failed | aborted_policy_disabled
    val records: List<RunbookStepRecord>, val definitionHash: String, val journalJobId: String?
) {
    fun renderCheck(stepId: String): String {
        val r = records.firstOrNull { it.stepId == stepId } ?: return "not yet known"
        return when (r.checkPassed) { true -> "passed"; false -> "FAILED"; null -> "not yet known" }
    }
}

/** Check observation seam: an unobserved check NEVER passes. The
 *  shipped evaluator fails every check by name (host probes are
 *  the wiring's step); tests inject observations. */
interface RunbookCheckEvaluator {
    fun observe(check: String, arg: String, deviceId: String): Pair<Boolean, String>
}
class HostWiringRunbookCheckEvaluator : RunbookCheckEvaluator {
    override fun observe(check: String, arg: String, deviceId: String): Pair<Boolean, String> =
        false to "check '$check' not observed — host wiring pending (an unobserved check never passes)"
}
class RecordingRunbookCheckEvaluator(var results: Map<String, Boolean> = emptyMap()) : RunbookCheckEvaluator {
    override fun observe(check: String, arg: String, deviceId: String): Pair<Boolean, String> {
        val key = if (arg.isBlank()) check else "$check:$arg"
        val v = results[key] ?: results[check] ?: return false to "check '$check' has no recorded observation — fails by name"
        return v to "check '$check' observed ${if (v) "pass" else "FAIL"} (recording evaluator)"
    }
}

/** Background-tool seam for runbook tool steps. */
interface RunbookToolExecutor { fun runTool(tool: String, deviceId: String): Pair<Boolean, String> }
class RecordingRunbookToolExecutor : RunbookToolExecutor {
    val ran = mutableListOf<String>()
    var failTools: Set<String> = emptySet()
    override fun runTool(tool: String, deviceId: String): Pair<Boolean, String> {
        ran += tool
        return if (tool in failTools) false to "tool '$tool' failed (recording executor)" else true to "tool '$tool' ran on '$deviceId' (recording executor)"
    }
}

class RunbookService(
    private val engine: ManagementPolicyEngine,
    private val gate: SignedCommandGate?,
    private val checks: RunbookCheckEvaluator,
    private val tools: RunbookToolExecutor,
    private val journal: JobJournal,
    private val audit: ChainedAuditLog,
    /** Owner-set ApprovalGate policy per action class (existing
     *  machinery: ApprovalSettings on-device, injected map here). */
    private val approvalPolicyFor: (String) -> ApprovalGate.Policy = { ApprovalGate.Policy.ASK_FIRST },
    private val approvalDecision: (String, String) -> Boolean = { _, _ -> false },
    /** bd-and-rmm F8: rights hook — (scopeId, actorId, right) with
     *  right in {approve, attest, skip}. Approver/attester used to
     *  be free strings any caller could type. When wired, the hook
     *  decides; when null, the named-actor rules above are the only
     *  gate (legacy compositions, named here). */
    private val actorRights: ((scopeId: String, actorId: String, right: String) -> Boolean)? = null,
    /** bd-and-rmm F10: the real RMM-08 service + per-step envelope
     *  provider. When wired, remediation steps execute THROUGH
     *  RemediationService (its own RMM-03 gate, payload binding and
     *  per-action policy keys) instead of the bare executor seam. */
    private val remediationService: RemediationService? = null,
    private val stepEnvelopeProvider: ((stepId: String) -> SignedCommandEnvelope?)? = null
) {
    private fun rightsRefusal(runId: String, actor: String, right: String): String? {
        val hook = actorRights ?: return null
        val scope = runFacts[runId]?.scopeId ?: ""
        return if (hook(scope, actor, right)) null
        else "actor '$actor' does not hold the '$right' right for this run — refused"
    }
    private val runbooks = mutableMapOf<String, RunbookDefinition>()
    private val runs = mutableMapOf<String, RunbookRun>()
    private val runDefs = mutableMapOf<String, RunbookDefinition>()
    private val runFacts = mutableMapOf<String, DeviceFacts>()

    var lastRefusal: String? = null
        private set

    fun admit(def: RunbookDefinition): Pair<Boolean, String> {
        def.validate()?.let { return false to it }
        synchronized(this) {
            runbooks[def.id]?.let { existing ->
                if (def.revision < existing.revision) return false to "runbook '${def.id}' revision ${def.revision} is stale — refused"
                if (def.revision == existing.revision && def.contentHash() != existing.contentHash())
                    return false to "runbook '${def.id}' revision ${def.revision} conflicts with the admitted content — refused"
            }
            runbooks[def.id] = def.copy(steps = def.steps.toList()) // defensive copy
        }
        return true to "runbook '${def.id}' r${def.revision} admitted"
    }

    fun getRun(runId: String): RunbookRun? = synchronized(this) { runs[runId] }

    /** Start a run: policy → library → RMM-03 gate (payload-bound)
     *  → definition SNAPSHOTTED + pinned by hash → RMM-15 journal
     *  job created → steps execute until a gate/failure/end. */
    fun startRun(runbookId: String, deviceId: String, runId: String, initiatedBy: String,
                 facts: DeviceFacts?, envelope: SignedCommandEnvelope?, nowMs: Long): Pair<RunbookRun?, String> {
        fun refuse(r: String): Pair<RunbookRun?, String> {
            audit.append("runbook_refused", initiatedBy, "runbook=$runbookId device=$deviceId reason=$r", nowMs)
            lastRefusal = r; return null to r
        }
        if (initiatedBy.isBlank()) return refuse("a runbook run needs a named initiator — refused")
        if (facts == null) return refuse("no device facts for '$deviceId' — run refuses (policy cannot be evaluated)")
        if (!engine.isEnabled(facts, "rmm.runbooks.enabled")) return refuse("runbooks are disabled by policy (rmm.runbooks.enabled) — refused")
        engine.computeEffective(facts).get("rmm.runbooks.$runbookId.enabled")?.let {
            if (it.value.toBooleanStrictOrNull() == false) return refuse("runbook '$runbookId' is disabled by policy — refused")
        }
        val def = synchronized(this) { runbooks[runbookId] } ?: return refuse("unknown runbook '$runbookId' — refused")
        if (gate == null) return refuse("no signed-command gate configured — runbook runs refuse (RMM-03 coverage is not claimed)")
        val expected = RunbookDefinition.canonicalPayload(runbookId, deviceId, runId).toByteArray(Charsets.UTF_8)
        val v = gate.authorize(envelope, nowMs, SignedCommandClasses.BACKGROUND_ACTION, expected)
        if (!v.allowed) return refuse("signed-command verification failed: ${v.reason}")
        val jobId = "runbook-$runId"
        val job = journal.createJob(jobId, JobKinds.SCRIPT_CHAIN, deviceId,
            def.steps.map { JobStepDefinition(it.stepId, it.stepId, it.kind != RunbookStepKinds.REMEDIATION || RemediationActions.isIdempotent(it.ref)) },
            envelope, nowMs)
            ?: return refuse("journal refused the runbook job: ${journal.lastRefusal}")
        val run = RunbookRun(runId, runbookId, deviceId, initiatedBy, "running",
            def.steps.map { RunbookStepRecord(it.stepId, it.kind, StepStates.PENDING, "", null, null) },
            def.contentHash(), jobId)
        synchronized(this) { runs[runId] = run; runDefs[runId] = def; runFacts[runId] = facts }
        journal.startJob(jobId, nowMs)
        audit.append("runbook_started", initiatedBy, "runbook=$runbookId run=$runId device=$deviceId hash=${def.contentHash()}", nowMs)
        return advance(runId, initiatedBy, nowMs) to "run started"
    }

    /** Attest a human-confirmation step (attributed; distinctness
     *  and named-attester rules enforced). */
    fun attest(runId: String, stepId: String, attestedBy: String, nowMs: Long): Pair<Boolean, String> {
        val run = synchronized(this) { runs[runId] } ?: return false to "unknown run '$runId' — refused"
        if (run.status != "paused_awaiting_attestation") return false to "run '$runId' is not awaiting attestation — refused"
        val def = runDefs[runId]!!; val step = def.steps.firstOrNull { it.stepId == stepId }
            ?: return false to "unknown step '$stepId' — refused"
        if (step.kind != RunbookStepKinds.HUMAN_CONFIRMATION) return false to "step '$stepId' is not a human confirmation — refused"
        if (attestedBy.isBlank()) return false to "attestation needs a named attester — refused"
        if (step.requiredAttesterId != null && attestedBy != step.requiredAttesterId)
            return false to "step '$stepId' is reserved for attester '${step.requiredAttesterId}' — refused"
        if (step.requireDistinctAttester && attestedBy == run.initiatedBy)
            return false to "step '$stepId' requires a distinct attester (not the initiator) — self-attestation refused"
        rightsRefusal(runId, attestedBy, "attest")?.let { return false to it }
        // bd-and-rmm F10: the journal's verdict is CHECKED — the
        // old code ignored both return values, so a journal refusal
        // left run and journal permanently desynchronised.
        if (!journal.beginStep(run.journalJobId!!, stepId, nowMs))
            return false to "journal refused to begin the attested step '$stepId' — attestation NOT recorded (run unchanged)"
        if (!journal.completeStep(run.journalJobId, stepId, nowMs))
            return false to "journal refused to complete the attested step '$stepId' — attestation NOT recorded (run unchanged)"
        val recs = run.records.map { if (it.stepId == stepId) it.copy(state = StepStates.DONE, detail = "attested", actor = attestedBy) else it }
        synchronized(this) { runs[runId] = run.copy(status = "running", records = recs) }
        audit.append("runbook_attested", attestedBy, "run=$runId step=$stepId", nowMs)
        advance(runId, attestedBy, nowMs)
        return true to "attested"
    }

    /** Approve a gated step. The owner-set ApprovalGate policy
     *  decides ASK/DENY first; self-approval and wrong-approver
     *  refuse; a human decision is required when policy says ASK. */
    fun approveStep(runId: String, stepId: String, approvedBy: String, nowMs: Long): Pair<Boolean, String> {
        val run = synchronized(this) { runs[runId] } ?: return false to "unknown run '$runId' — refused"
        if (run.status != "paused_awaiting_approval") return false to "run '$runId' is not awaiting approval — refused"
        val def = runDefs[runId]!!; val step = def.steps.firstOrNull { it.stepId == stepId }
            ?: return false to "unknown step '$stepId' — refused"
        if (approvedBy.isBlank()) return false to "approval needs a named approver — refused"
        if (approvedBy == run.initiatedBy) return false to "self-approval refused (the initiator cannot approve their own gated step)"
        if (step.requiredApproverId != null && approvedBy != step.requiredApproverId)
            return false to "step '$stepId' requires approver '${step.requiredApproverId}' — refused"
        rightsRefusal(runId, approvedBy, "approve")?.let { return false to it }
        val recs = run.records.map { if (it.stepId == stepId) it.copy(detail = "approved by $approvedBy", actor = approvedBy) else it }
        synchronized(this) { runs[runId] = run.copy(status = "running", records = recs) }
        audit.append("runbook_approved", approvedBy, "run=$runId step=$stepId", nowMs)
        advance(runId, approvedBy, nowMs)
        return true to "approved"
    }

    /** Recorded skip of a HALTED check by an authorised actor —
     *  the failed CheckPassed=false stays in the record and the
     *  run can never read succeeded afterwards. */
    fun skipStep(runId: String, stepId: String, skippedBy: String, reason: String, nowMs: Long): Pair<Boolean, String> {
        val run = synchronized(this) { runs[runId] } ?: return false to "unknown run '$runId' — refused"
        if (run.status != "halted_check_failed") return false to "only a halted check can be skipped — refused"
        if (skippedBy.isBlank() || reason.isBlank()) return false to "a recorded skip needs an actor and a reason — refused"
        if (skippedBy == run.initiatedBy) return false to "the executing initiator cannot skip their own halted check — refused"
        // bd-and-rmm F8 fix: only the step whose check actually
        // FAILED (checkPassed == false) may be skipped — the old
        // code accepted any stepId while halted, silently skipping
        // steps that never ran.
        val target = run.records.firstOrNull { it.stepId == stepId }
            ?: return false to "unknown step '$stepId' — refused"
        if (target.checkPassed != false)
            return false to "step '$stepId' cannot be skipped — only the halted step whose check FAILED may be skipped (this step's check did not fail)"
        rightsRefusal(runId, skippedBy, "skip")?.let { return false to it }
        // bd-and-rmm F10: the skip is journalled (it never was).
        if (!journal.skipStep(run.journalJobId!!, stepId, nowMs))
            return false to "journal refused the skip of step '$stepId' — skip NOT recorded (run unchanged)"
        val recs = run.records.map { if (it.stepId == stepId) it.copy(state = StepStates.SKIPPED, detail = "skipped by $skippedBy: $reason (check FAILED, preserved)", actor = skippedBy) else it }
        synchronized(this) { runs[runId] = run.copy(status = "running", records = recs) }
        audit.append("runbook_step_skipped", skippedBy, "run=$runId step=$stepId reason=$reason", nowMs)
        advance(runId, skippedBy, nowMs)
        return true to "skipped (recorded)"
    }

    /** Resume a parked/paused run: re-checks policy, NEVER skips
     *  the human step it paused on, re-runs a halted check. */
    fun resumeRun(runId: String, actor: String, nowMs: Long): Pair<RunbookRun?, String> {
        val run = synchronized(this) { runs[runId] } ?: return null to "unknown run '$runId' — refused"
        if (run.status in setOf("succeeded", "partial_failure", "failed", "aborted_policy_disabled"))
            return null to "run '$runId' is terminal (${run.status}) — resume refused"
        val facts = runFacts[runId]!!
        if (!engine.isEnabled(facts, "rmm.runbooks.enabled")) {
            synchronized(this) { runs[runId] = run.copy(status = "aborted_policy_disabled") }
            audit.append("runbook_aborted", actor, "run=$runId reason=policy disabled at resume", nowMs)
            return runs[runId] to "aborted: policy disabled"
        }
        if (run.status == "paused_awaiting_attestation" || run.status == "paused_awaiting_approval")
            return run to "run '$runId' is STILL paused at its human gate — resume does not skip it"
        if (run.status == "halted_check_failed") {
            // Re-run the halted check from its pending state.
            val recs = run.records.map { if (it.state == StepStates.FAILED) it.copy(state = StepStates.PENDING, checkPassed = null, detail = "re-check on resume") else it }
            synchronized(this) { runs[runId] = run.copy(status = "running", records = recs) }
            advance(runId, actor, nowMs)
            return runs[runId] to "halted check re-run"
        }
        advance(runId, actor, nowMs)
        return runs[runId] to "resumed"
    }

    private fun advance(runId: String, actor: String, nowMs: Long): RunbookRun {
        while (true) {
            val run = synchronized(this) { runs[runId] } ?: error("run vanished")
            if (run.status != "running") return run
            val facts = runFacts[runId]!!
            // Policy re-checked before EVERY step.
            if (!engine.isEnabled(facts, "rmm.runbooks.enabled")) {
                val done = run.copy(status = "aborted_policy_disabled")
                synchronized(this) { runs[runId] = done }
                audit.append("runbook_aborted", actor, "run=$runId reason=policy disabled mid-run", nowMs)
                return done
            }
            val def = runDefs[runId]!!
            val idx = run.records.indexOfFirst { it.state == StepStates.PENDING }
            if (idx < 0) {
                val anyFailed = run.records.any { it.checkPassed == false || it.state == StepStates.FAILED }
                val anySkippedFailed = run.records.any { it.state == StepStates.SKIPPED && it.checkPassed == false }
                val status = if (anyFailed || anySkippedFailed) "partial_failure" else "succeeded"
                val done = run.copy(status = status)
                synchronized(this) { runs[runId] = done }
                audit.append("runbook_finished", actor, "run=$runId status=$status", nowMs)
                return done
            }
            val step = def.steps.first { it.stepId == run.records[idx].stepId }
            // Approval gate (existing ApprovalGate machinery).
            if (step.requiresApproval && !run.records[idx].detail.startsWith("approved by")) {
                val policy = approvalPolicyFor(step.kind)
                when (ApprovalGate.decide(policy)) {
                    ApprovalGate.Decision.DENY -> {
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.FAILED, detail = "approval policy BLOCKED this step") else r }
                        synchronized(this) { runs[runId] = run.copy(status = "failed", records = recs) }
                        audit.append("runbook_refused", actor, "run=$runId step=${step.stepId} approval policy blocked", nowMs)
                        return runs[runId]!!
                    }
                    ApprovalGate.Decision.ASK -> {
                        if (!approvalDecision(runId, step.stepId)) {
                            synchronized(this) { runs[runId] = run.copy(status = "paused_awaiting_approval") }
                            return runs[runId]!!
                        }
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(detail = "approved by gate-prompt", actor = actor) else r }
                        synchronized(this) { runs[runId] = run.copy(records = recs) }
                        continue
                    }
                    ApprovalGate.Decision.ALLOW -> Unit
                }
            }
            when (step.kind) {
                RunbookStepKinds.HUMAN_CONFIRMATION -> {
                    synchronized(this) { runs[runId] = run.copy(status = "paused_awaiting_attestation") }
                    return runs[runId]!!
                }
                RunbookStepKinds.CHECK -> {
                    journal.beginStep(run.journalJobId!!, step.stepId, nowMs)
                    val (passed, why) = try {
                        if (step.ref == RunbookChecks.POLICY_ENABLED) {
                            val key = step.prompt // check arg carried in prompt for policy checks
                            (engine.isEnabled(facts, key)) to "policy key '$key' enabled=${engine.isEnabled(facts, key)} (engine-observed)"
                        } else checks.observe(step.ref, step.prompt, run.deviceId)
                    } catch (ex: Exception) { false to "check evaluator threw (${ex.javaClass.simpleName}) — check FAILED, named" }
                    if (passed) {
                        journal.completeStep(run.journalJobId, step.stepId, nowMs)
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.DONE, detail = why, checkPassed = true) else r }
                        synchronized(this) { runs[runId] = run.copy(records = recs) }
                    } else {
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.FAILED, detail = why, checkPassed = false) else r }
                        when (step.failurePolicy) {
                            // bd-and-rmm F10: a halt is JOURNALLED
                            // (recordHalt) — the journal previously
                            // kept the step RUNNING with no entry.
                            "halt" -> { journal.recordHalt(run.journalJobId!!, "step=${step.stepId} check failed: $why — run halted", nowMs)
                                synchronized(this) { runs[runId] = run.copy(status = "halted_check_failed", records = recs) }; return runs[runId]!! }
                            // bd-and-rmm F10: 'continue' fails the
                            // STEP, not the job (failStepContinue),
                            // and a journal refusal fails the run
                            // loudly instead of being ignored.
                            "continue" -> { if (!journal.failStepContinue(run.journalJobId!!, step.stepId, why, nowMs)) {
                                    val failed = run.copy(status = "failed", records = recs)
                                    synchronized(this) { runs[runId] = failed }
                                    audit.append("runbook_failed", actor, "run=$runId step=${step.stepId} journal refused the continue — run failed rather than desynchronised", nowMs)
                                    return failed
                                }
                                synchronized(this) { runs[runId] = run.copy(records = recs) } }
                            "route" -> {
                                val target = step.routeTo!!
                                val routed = recs.map { if (it.stepId == target) it.copy(state = StepStates.PENDING) else it }
                                    .mapIndexed { i, r -> if (i > idx && r.state == StepStates.PENDING && r.stepId != target) r.copy(state = StepStates.SKIPPED, detail = "routed past by ${step.stepId}") else r }
                                synchronized(this) { runs[runId] = run.copy(records = routed) }
                            }
                        }
                    }
                }
                RunbookStepKinds.REMEDIATION -> {
                    // Compose RMM-08: its own gate + journal step run
                    // under a per-step signed envelope is the hub's
                    // composition; here the step executes through the
                    // remediation executor seam via a nested service
                    // call keyed by the run's already-verified
                    // authority (recorded in the step record).
                    journal.beginStep(run.journalJobId!!, step.stepId, nowMs)
                    val innerRunId = "$runId-${step.stepId}"
                    val outcome = remediationStep(runId, step.ref, run.deviceId, innerRunId, step.stepId, actor, nowMs)
                    if (outcome.first) {
                        journal.completeStep(run.journalJobId, step.stepId, nowMs)
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.DONE, detail = outcome.second) else r }
                        synchronized(this) { runs[runId] = run.copy(records = recs) }
                    } else {
                        journal.failStep(run.journalJobId, step.stepId, outcome.second, nowMs)
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.FAILED, detail = outcome.second) else r }
                        synchronized(this) { runs[runId] = run.copy(status = "failed", records = recs) }
                        return runs[runId]!!
                    }
                }
                RunbookStepKinds.BACKGROUND_TOOL -> {
                    journal.beginStep(run.journalJobId!!, step.stepId, nowMs)
                    val (ok, why) = try { tools.runTool(step.ref, run.deviceId) }
                        catch (ex: Exception) { false to "tool executor threw (${ex.javaClass.simpleName}) — step FAILED, named" }
                    if (ok) {
                        journal.completeStep(run.journalJobId, step.stepId, nowMs)
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.DONE, detail = why) else r }
                        synchronized(this) { runs[runId] = run.copy(records = recs) }
                    } else {
                        journal.failStep(run.journalJobId, step.stepId, why, nowMs)
                        val recs = run.records.mapIndexed { i, r -> if (i == idx) r.copy(state = StepStates.FAILED, detail = why) else r }
                        synchronized(this) { runs[runId] = run.copy(status = "failed", records = recs) }
                        return runs[runId]!!
                    }
                }
            }
        }
    }

    /** Remediation steps inside a runbook.
     *  bd-and-rmm F10 fix: BOTH paths now pass the RMM-08 policy
     *  checks first (rmm.remediation.enabled + the per-action key
     *  rmm.remediation.<action>.enabled) — the old seam skipped
     *  RemediationService entirely, so neither the master switch
     *  nor per-action disables applied inside runbooks. When a
     *  RemediationService is wired, the step executes THROUGH it
     *  (RMM-03 gate + payload binding + its own journal job) under
     *  a per-step envelope from [stepEnvelopeProvider]; without an
     *  envelope the step refuses by name. The legacy executor seam
     *  remains for compositions that wire it explicitly, under the
     *  same policy pre-checks. */
    private var remediationStepOverride: ((String, String, String, Long) -> Pair<Boolean, String>)? = null
    fun setRemediationStepExecutor(f: (String, String, String, Long) -> Pair<Boolean, String>) { remediationStepOverride = f }
    private fun remediationStep(runId: String, action: String, deviceId: String, innerRunId: String, stepId: String, actor: String, nowMs: Long): Pair<Boolean, String> {
        val facts = runFacts[runId] ?: return false to "remediation step '$action' has no run facts — NOT performed"
        if (!engine.isEnabled(facts, "rmm.remediation.enabled"))
            return false to "remediation step '$action' refused: auto-remediation is disabled by policy (rmm.remediation.enabled)"
        engine.computeEffective(facts).get("rmm.remediation.$action.enabled")?.let {
            if (it.value.toBooleanStrictOrNull() == false)
                return false to "remediation step '$action' refused: the action is disabled by policy (rmm.remediation.$action.enabled)"
        }
        val svc = remediationService
        if (svc != null) {
            val env = stepEnvelopeProvider?.invoke(stepId)
                ?: return false to "remediation step '$action' has no per-step signed envelope in this composition — NOT performed (named, never faked)"
            val out = svc.execute(action, deviceId, innerRunId, "runbook step (run $runId)", env, facts, actor, nowMs)
            return out.executed to out.detail
        }
        return remediationStepOverride?.invoke(action, deviceId, innerRunId, nowMs)
            ?: (false to "remediation step '$action' has no wired executor in this composition — NOT performed (named, never faked)")
    }
}

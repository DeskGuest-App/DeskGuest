using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Security;

namespace Acp.Shared.Jobs;

// =====================================================================
// RMM-15 — Job resume-on-reconnect.
//
// Every multi-step job (patch run, deployment, script chain, backup,
// file transfer, update staging) is checkpointed ON THE ENDPOINT in a
// durable job journal and RESUMES after reboot or connection loss
// instead of dying half-applied. This generalises the session layer's
// monotonic file-job discipline (FileJob / StandaloneJob: monotonic
// progress, a closed transition set, terminal states with no outgoing
// edges) from byte counts to ordered steps:
//
//   * steps run in order; a step's state only moves forward
//     (pending → running → done/failed/skipped; a crashed "running"
//     step becomes "uncertain" if it is non-idempotent);
//   * every mutation appends a hash-chained journal entry — the same
//     chain discipline as the enterprise ChainedAuditLog — and, when
//     the journal is constructed with the endpoint's DeviceIdentity,
//     each entry is additionally SIGNED by the endpoint key, so a
//     tamperer who rewrites history and recomputes the hash chain
//     still cannot forge entries (they hold no endpoint seed);
//   * job state on import is DERIVED by replaying journal entries,
//     never trusted from a stored snapshot: editing a snapshot's
//     "done" flags changes nothing;
//   * a job's authority is its RMM-03 signed-command envelope,
//     bound into the journal at creation by hash. Resume re-checks
//     the envelope: expiry still applies after resume (an envelope
//     that expired mid-outage parks the job as failed-with-reason
//     "authority_expired"), and when the customer key ring is
//     supplied the signature is re-verified WITHOUT the replay
//     guard (the nonce was legitimately consumed at first
//     execution; resume is a continuation, not a new presentation —
//     what resume must prove is that the envelope is the genuine,
//     unaltered, unexpired one the journal was created under);
//   * idempotency is explicit per step: a step that may have run
//     before the crash is safe to re-run ONLY when marked
//     idempotent. A non-idempotent step caught mid-flight parks the
//     job for a human decision — the journal never guesses.
//
// Toggle: rmm.job_resume.enabled (TOTAL POLICY CONTROL). When OFF,
// ResumeAll refuses to resume anything: interrupted jobs fail with
// reason "resume_disabled" — the pre-RMM-15 behaviour, named in
// state rather than silent. ResumeAll and BuildStateReport read the
// toggle from ONE caller-supplied source per pass (the Func<bool>
// overloads), so behaviour and the hub report can never disagree
// (D38 F6).
//
// D38 reconciliation fixes (cross-review, packet 1877a640):
//   F1  A job in state Resumed is NO LONGER short-circuited by
//       ResumeAll: Resumed and Running jobs run the FULL check gauntlet
//       (chain, toggle, envelope expiry/signature, running-step rule)
//       on every post-restart pass, so a second crash after a resume
//       or after a human RetryStep decision parks an uncertain
//       non-idempotent step again instead of letting it complete with
//       no human decision. Replay of job_resumed applies the same
//       step reset as the live path, and BeginStep's Resumed→Running
//       transition is JOURNALLED (a job_started entry) — never a
//       memory-only flip — and BeginStep validates the step BEFORE
//       mutating anything, so a refused call changes no state.
//   F2  Import STOPS replaying at the first broken/unsigned entry:
//       entries at or after the break are dropped as untrusted and
//       never change job state, so a forged appended job_done cannot
//       fake a terminal state. Replay of job_done additionally
//       requires every step done/skipped. JobStateReport carries
//       ChainOk / BrokenAtSeq / ChainSummary / JournalSeq, and the
//       hub reconciler refuses reports from a broken journal.
//   F3  Rollback/truncation is DETECTED: SaveToFile anchors the head
//       (hash + seq) in a sidecar anchor file written after the
//       journal; LoadFromFile verifies the journal still CONTAINS
//       that anchored head. A journal shorter than the anchor, or
//       whose entry at the anchored seq has a different hash, imports
//       as BROKEN (rollback detected) — ResumeAll then fails every
//       non-terminal job rather than silently running an older
//       history. NAMED RESIDUAL: the anchor file is co-located, so a
//       rollback that restores journal + anchor + audit log together
//       is only caught hub-side (the reconciler's forward-only
//       JournalSeq/head discipline over accepted reports) or by an
//       externally held anchor (the chained-audit sink receives the
//       head at every checkpoint when wired).
//   F4  A verify-only journal (ForVerification) NEVER appends: it
//       holds no signer, so any entry it wrote would be unsigned and
//       would poison the next restart's verification. Execution
//       mutations on a verify-only journal refuse (false/null), and
//       ResumeAll on one runs the pass IN MEMORY ONLY (state changes
//       are reported, nothing is journalled). Durable resume requires
//       a journal constructed with the endpoint DeviceIdentity.
//   F5  The journal is WRITE-AHEAD when attached to a file (via
//       LoadFromFile / SaveToFile / AttachPersistence): every append
//       is written to a per-entry WAL sidecar and flushed to disk
//       (Flush(true)) BEFORE the mutating call returns, so a crash
//       after a step's effect but before a compacting SaveToFile
//       still replays the step_started and the park rule fires.
//       SaveToFile fsyncs before the atomic rename. A journal store
//       that does not parse (torn/empty after power loss) imports as
//       the NAMED failure "journal_lost" (chain broken, summary
//       names it, the hub report carries ChainOk=false) — interrupted
//       jobs never silently vanish into an empty journal; when the
//       WAL alone forms a valid chain it is recovered from the WAL.
//   F11 Crash vs reconnect are DISTINGUISHED: ResumeAll's full pass
//       is the post-restart pass (journal freshly imported, nothing
//       executing in this process). Once execution has begun in this
//       process (StartJob/BeginStep succeeded), the journal is LIVE
//       and ResumeAll runs in live mode: jobs with a step still
//       executing are reported "executing" and are NOT reset, NOT
//       parked, NOT failed by the toggle — a transport reconnect can
//       never double-run or falsely park an in-flight step. A job
//       already resumed earlier in the same process is likewise
//       left settled ("already_resumed"): a reconnect never
//       re-adjudicates it, recounts it, or fails it on an envelope
//       that expired after its legitimate resume (recovery-lane
//       re-attack). A caller that knows better may pass
//       allowLiveJournal: true to force the full pass on a live
//       journal.
//   F12 CreateJob verifies the envelope when the customer ring is
//       supplied (signature + payload hash + expiry, no nonce
//       consumption — creation-time genuineness, the gate remains
//       the nonce consumer); without a ring it trusts the caller's
//       gate exactly as PatchService wires it (gate authorizes
//       BEFORE CreateJob) — named here so the trust is explicit.
//       An envelope presented for a FileTransfer job must still name
//       a KNOWN signed-command class. Replay re-checks the genesis
//       kind↔envelopeClass binding against JobKinds.SignedClassByKind:
//       a recomputed journal that rebinds kind→class creates no job.
//       KEY ROTATION, NAMED: if the customer key that signed a job's
//       envelope is rotated and its grace deadline passes mid-job,
//       resume fails that job "authority_key_rotated" — deliberate:
//       a retired key verifies nothing, and a job whose authority
//       can no longer be proven does not continue on trust.
//
// The hub side is JobStateReconciler: it consumes per-device
// JobStateReports and keeps the hub's true per-device view
// (pending / running / resumed / parked / done / failed-with-
// reason). See its doc for the forward-only discipline (D38 F9).
// =====================================================================

/// <summary>The registered job kinds. Kinds are registered types,
/// not free text: an unknown kind refuses at creation. Each kind
/// names the RMM-03 signed-command class that authorises it (null
/// for file transfer, whose authorisation is the standing "use"
/// grant, as with StandaloneTransferService).</summary>
public static class JobKinds
{
    public const string FileTransfer = "file_transfer";
    public const string UpdateStaging = "update_staging";
    public const string ScriptChain = "script_chain";
    public const string PatchRun = "patch_run";
    public const string Deployment = "deployment";
    public const string Backup = "backup";
    /// <summary>BD-SHARED-RMM-2/F8: a multi-step remediation run IS a
    /// journal job — an interrupted kill_process / uninstall_app run
    /// must park under RMM-15 exactly as RemediationStepKinds'
    /// idempotency flags promise. Bound to the automation class: the
    /// same class that signs the automation definition itself.</summary>
    public const string Remediation = "remediation";
    /// <summary>RMM-29: an OS imaging / provisioning run — a journal
    /// job (resumable, staged, never half-applied silently),
    /// authorised by the RMM-03 `provisioning` signed-command class.</summary>
    public const string Provisioning = "provisioning";

    public static readonly IReadOnlyDictionary<string, string?> SignedClassByKind =
        new Dictionary<string, string?>
        {
            [FileTransfer] = null,
            [UpdateStaging] = SignedCommandClasses.UpdateStaging,
            [ScriptChain] = SignedCommandClasses.ScriptExec,
            [PatchRun] = SignedCommandClasses.PatchDeploy,
            [Deployment] = SignedCommandClasses.PackageDeploy,
            [Backup] = SignedCommandClasses.Automation,
            [Remediation] = SignedCommandClasses.Automation,
            [Provisioning] = SignedCommandClasses.Provisioning,
        };

    public static bool IsKnown(string? kind) =>
        kind is not null && SignedClassByKind.ContainsKey(kind.Trim().ToLowerInvariant());
}

public static class JobStates
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Resumed = "resumed";
    public const string Parked = "parked";
    public const string Done = "done";
    public const string Failed = "failed";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Pending, Running, Resumed, Parked, Done, Failed };
    public static bool IsTerminal(string? s) => s is Done or Failed;
}

public static class StepStates
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Done = "done";
    public const string Failed = "failed";
    public const string Uncertain = "uncertain";
    public const string Skipped = "skipped";
}

public static class JobFailureReasons
{
    public const string AuthorityExpired = "authority_expired";
    public const string AuthorityInvalid = "authority_invalid";
    /// <summary>D38 F12, named: the signing customer key was rotated
    /// and its grace deadline passed mid-job, so the envelope's
    /// authority can no longer be proven. Deliberate fail-closed.</summary>
    public const string AuthorityKeyRotated = "authority_key_rotated";
    public const string JournalTampered = "journal_tampered";
    /// <summary>D38 F5, named: the journal store itself was lost or
    /// unreadable (torn/empty/deleted while an anchor survives) —
    /// surfaced in the chain summary and the hub report, never a
    /// silent empty journal.</summary>
    public const string JournalLost = "journal_lost";
    public const string ResumeDisabled = "resume_disabled";
    public const string NonIdempotentUncertain = "non_idempotent_uncertain";
    public const string HumanDecisionFail = "human_decision_fail";
}

/// <summary>Whether a step is safe to re-run after a crash that may
/// have interrupted it mid-effect. The default for a step definition
/// built without thought must be the SAFE answer for correctness,
/// which is NonIdempotent (park, never guess) — callers opt INTO
/// idempotency explicitly.</summary>
public enum StepIdempotency { NonIdempotent = 0, Idempotent = 1 }

public sealed record JobStepDefinition(string StepId, string Name, StepIdempotency Idempotency);

public sealed record JobStepState(string StepId, string Name, StepIdempotency Idempotency,
    string State, int Attempts, string? LastError);

public sealed record ResumableJob(
    string Id, string Kind, string DeviceId, string State, string? FailureReason,
    IReadOnlyList<JobStepState> Steps,
    string? EnvelopeJson, string? EnvelopeHash, string? EnvelopeClass, DateTimeOffset? EnvelopeExpiresUtc,
    DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc, int ResumeCount)
{
    public int CompletedSteps => Steps.Count(s => s.State is StepStates.Done or StepStates.Skipped);
    public bool IsTerminal => JobStates.IsTerminal(State);
}

/// <summary>One hash-chained (and optionally endpoint-signed)
/// journal entry. The Detail of the genesis entry carries the full
/// job definition (kind, device, ordered steps, envelope hash), so
/// replay can rebuild the job from entries alone.</summary>
public sealed record JobJournalEntry(
    long Seq, string JobId, DateTimeOffset AtUtc, string Kind, string Detail,
    string PrevHash, string Hash, string? SignatureBase64);

public sealed record JournalVerification(bool Ok, long? BrokenAtSeq, string Summary);

public sealed record ResumeOutcome(string JobId, string Outcome, string Detail);
public sealed record ResumeReport(IReadOnlyList<ResumeOutcome> Outcomes, bool ChainOk, bool AuthorityRechecked)
{
    public int ResumedCount => Outcomes.Count(o => o.Outcome == "resumed");
}

/// <summary>The hub-facing per-device job state (RMM-15 directive:
/// pending / running / resumed / done / failed-with-reason; parked
/// is the human-decision state the directive's non-idempotent rule
/// requires, surfaced honestly rather than folded into failed).
/// D38 F2/F9: the report also carries the journal's chain status
/// (ChainOk / BrokenAtSeq / ChainSummary) and the journal sequence
/// (JournalSeq) so the hub can refuse state derived from a broken
/// journal and detect head/sequence regression. AUTHENTICATION
/// SEAM, NAMED: reports are NOT signed at this layer and DeviceId
/// is self-asserted IN THE REPORT VALUE; authenticity comes from
/// the transport/pairing layer — a report is only ever accepted
/// over the device's authenticated paired session, which is bound
/// to the enrolled device. This layer's job is forward-only state
/// discipline, not identity.</summary>
public sealed record JobStateSummary(string JobId, string Kind, string State, string? FailureReason,
    int CompletedSteps, int TotalSteps, int ResumeCount);
public sealed record JobStateReport(string DeviceId, DateTimeOffset GeneratedUtc, bool ResumeEnabled,
    string JournalHeadHash, IReadOnlyList<JobStateSummary> Jobs,
    bool ChainOk = true, long? BrokenAtSeq = null, string ChainSummary = "", long JournalSeq = 0,
    // BD-SHARED-RMM-2/F10: whether the journal behind this report is
    // endpoint-SIGNED. An unsigned journal's history is recomputable
    // by anyone who can write the store; the hub must be able to tell
    // the two apart instead of accepting both alike.
    bool Signed = false);

public enum ParkedDecision { RetryStep, SkipStep, FailJob }

/// <summary>The endpoint job journal. Thread-safe; every public
/// mutation is journal-append + state change under one lock, so a
/// crash between the two cannot happen inside this process — and a
/// crash of the process leaves the last exported/persisted journal,
/// from which state is rebuilt by replay.</summary>
public sealed class JobJournal
{
    public const string GenesisHash = "GENESIS";

    private readonly List<JobJournalEntry> _entries = new();
    private readonly Dictionary<string, ResumableJob> _jobs = new(StringComparer.Ordinal);
    private readonly DeviceIdentity? _signer;
    private readonly byte[]? _verifyKey;
    private readonly bool _verifyOnly;
    private readonly Action<string, string?, string>? _auditSink;
    private readonly object _gate = new();
    private bool _chainOk = true;
    private long? _brokenAtSeq;
    private string _chainSummary = "OK: empty journal";
    private string? _importError;
    private string? _persistPath;
    private string? _persistenceError;
    // True once execution has begun in THIS process (a step may be
    // in flight). Import clears it: a freshly imported journal has
    // nothing executing. Drives the F11 crash-vs-reconnect split.
    private bool _liveExecution;

    /// <param name="endpointIdentity">When supplied, entries are
    /// signed with the endpoint key and import verifies signatures
    /// as well as the hash chain (the recompute-attack defence).</param>
    /// <param name="auditSink">Optional chained-audit sink
    /// (kind, actor, detail): job lifecycle events AND the journal
    /// head hash at every checkpoint are anchored into the
    /// enterprise audit chain when wired.</param>
    public JobJournal(DeviceIdentity? endpointIdentity = null,
        Action<string, string?, string>? auditSink = null)
    {
        _signer = endpointIdentity;
        _verifyKey = endpointIdentity?.PublicKey;
        _auditSink = auditSink;
    }

    private JobJournal(byte[] verifyKey, Action<string, string?, string>? auditSink)
    {
        _verifyKey = verifyKey;
        _verifyOnly = true;
        _auditSink = auditSink;
    }

    /// <summary>A verify-only journal (hub-side verification, or a
    /// read-only post-restart inspection). D38 F4: it holds NO
    /// signer, so it NEVER appends — execution mutations refuse and
    /// ResumeAll runs in memory only. A durable resume pass must use
    /// a journal constructed with the endpoint DeviceIdentity.</summary>
    public static JobJournal ForVerification(byte[] endpointPublicKey,
        Action<string, string?, string>? auditSink = null) => new(endpointPublicKey, auditSink);

    public bool IsVerifyOnly => _verifyOnly;
    /// <summary>True when this journal's entries are endpoint-signed
    /// (constructed with a DeviceIdentity) or signature-verified
    /// (ForVerification) — BD-SHARED-RMM-2/F10.</summary>
    public bool IsSigned => _signer is not null || _verifyKey is not null;
    /// <summary>The named import failure (journal_lost) when the
    /// store could not be read at all; null on a readable import.</summary>
    public string? ImportError { get { lock (_gate) return _importError; } }
    /// <summary>The last write-ahead persistence failure, if any.
    /// Persistence errors are recorded, never thrown into execution
    /// callers and never silent.</summary>
    public string? PersistenceError { get { lock (_gate) return _persistenceError; } }
    /// <summary>The current rollback anchor: (head hash, entry
    /// count). Anchor this externally (chained audit / hub) for the
    /// strongest rollback detection; SaveToFile also writes it to a
    /// sidecar anchor file that LoadFromFile verifies (D38 F3).</summary>
    public (string HeadHash, long Seq) CurrentAnchor
    {
        get { lock (_gate) return (_entries.Count == 0 ? GenesisHash : _entries[^1].Hash, _entries.Count); }
    }

    public IReadOnlyList<JobJournalEntry> Entries { get { lock (_gate) return _entries.ToList(); } }
    public string HeadHash { get { lock (_gate) return _entries.Count == 0 ? GenesisHash : _entries[^1].Hash; } }
    public JournalVerification Verification { get { lock (_gate) return new JournalVerification(_chainOk, _brokenAtSeq, _chainSummary); } }

    private static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static string ComputeHash(JobJournalEntry e) =>
        Sha256Hex($"{e.Seq}|{e.JobId}|{e.AtUtc:O}|{e.Kind}|{e.Detail}|{e.PrevHash}");

    /// <summary>Attach write-ahead persistence to a journal file
    /// path: from now on every append is WAL-persisted (fsync)
    /// before the mutating call returns (D38 F5). LoadFromFile and
    /// SaveToFile attach automatically.</summary>
    public void AttachPersistence(string path)
    {
        lock (_gate) _persistPath = path;
    }

    private JobJournalEntry? AppendLocked(string jobId, string kind, string detail, DateTimeOffset now)
    {
        if (_verifyOnly)
            throw new InvalidOperationException(
                "a verify-only journal never appends (it holds no signer; an unsigned entry would poison the next verification) — construct the journal with the endpoint DeviceIdentity for a mutating pass (D38 F4)");
        var seq = _entries.Count + 1L;
        var prev = _entries.Count == 0 ? GenesisHash : _entries[^1].Hash;
        var draft = new JobJournalEntry(seq, jobId, now, kind, detail, prev, "", null);
        var hash = ComputeHash(draft);
        string? sig = null;
        if (_signer is not null)
            sig = Convert.ToBase64String(_signer.Sign(Encoding.UTF8.GetBytes("acp-job-journal-v1|" + hash)));
        var entry = draft with { Hash = hash, SignatureBase64 = sig };
        // BD-SHARED-RMM-2/F2: the F5 header promises the WAL append is
        // durable BEFORE the mutating call returns. A failed WAL write
        // therefore ROLLS THE APPEND BACK — the entry never enters the
        // in-memory chain, callers observe the refusal through their
        // own return values (BeginStep/StartJob/CreateJob re-check
        // below), and a non-idempotent step's step_started can never
        // exist only in memory while the step itself runs.
        if (!PersistWalLocked(entry))
            return null;
        _entries.Add(entry);
        _auditSink?.Invoke("job_journal_checkpoint", null,
            $"job={jobId} entry={kind} seq={seq} head={hash}");
        return entry;
    }

    /// <summary>Append-if-writable: the verify-only ResumeAll pass
    /// (in-memory only, D38 F4) uses this so its state changes are
    /// reported without ever writing an unsigned entry.</summary>
    private void AppendIfWritableLocked(string jobId, string kind, string detail, DateTimeOffset now)
    {
        if (_verifyOnly) return;
        AppendLocked(jobId, kind, detail, now);
    }

    // Write-ahead log: one JSON line per entry, flushed to disk
    // before the append returns. SaveToFile compacts the main file
    // but RETAINS the WAL as the torn-main recovery source.
    private bool PersistWalLocked(JobJournalEntry entry)
    {
        if (_persistPath is null) return true;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_persistPath))!);
            var line = JsonSerializer.Serialize(new EntryDto(entry.Seq, entry.JobId, entry.AtUtc,
                entry.Kind, entry.Detail, entry.PrevHash, entry.Hash, entry.SignatureBase64)) + "\n";
            var bytes = Encoding.UTF8.GetBytes(line);
            using var fs = new FileStream(_persistPath + ".wal", FileMode.Append, FileAccess.Write, FileShare.Read);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
            return true;
        }
        catch (Exception ex) { _persistenceError = $"write-ahead persist failed at seq {entry.Seq}: {ex.Message}"; return false; }
    }

    // ---- creation -------------------------------------------------

    /// <summary>Create a job in "pending". Refusals (null): unknown
    /// kind, no steps, duplicate/blank step ids, an envelope whose
    /// class does not match the kind's authorising class, an
    /// envelope already expired, or a kind that requires an envelope
    /// presented without one. The envelope is bound by SHA-256 of
    /// its canonical JSON; the genesis journal entry carries that
    /// hash, so no later edit can swap the authority.
    /// D38 F12: when <paramref name="ring"/> is supplied the envelope
    /// is fully re-verified (signature + payload hash + expiry)
    /// before the job exists; without a ring the caller is trusted
    /// to have run the RMM-03 gate first (PatchService does exactly
    /// that) — the trust is named, not hidden.</summary>
    public ResumableJob? CreateJob(string kind, string deviceId,
        IReadOnlyList<JobStepDefinition> steps, SignedCommandEnvelope? envelope, DateTimeOffset now,
        CustomerCommandKeyRing? ring = null)
    {
        if (_verifyOnly) return null;
        var k = (kind ?? "").Trim().ToLowerInvariant();
        if (!JobKinds.IsKnown(k)) return null;
        if (string.IsNullOrWhiteSpace(deviceId)) return null;
        if (steps is null || steps.Count == 0) return null;
        if (steps.Any(s => string.IsNullOrWhiteSpace(s.StepId)) ||
            steps.Select(s => s.StepId).Distinct(StringComparer.Ordinal).Count() != steps.Count) return null;

        var requiredClass = JobKinds.SignedClassByKind[k];
        string? envelopeJson = null, envelopeHash = null;
        DateTimeOffset? envelopeExpires = null;
        if (envelope is not null)
        {
            if (requiredClass is not null && envelope.CommandClass != requiredClass) return null;
            // D38 F12: even a FileTransfer job (no required class)
            // may not carry an envelope naming an UNKNOWN class.
            if (requiredClass is null && !SignedCommandClasses.All.Contains(envelope.CommandClass ?? "")) return null;
            if (envelope.ExpiresUtc <= now) return null;
            if (ring is not null)
            {
                var (ok, _) = RecheckEnvelope(envelope, ring, now);
                if (!ok) return null;
            }
            envelopeJson = envelope.ToJson();
            envelopeHash = Sha256Hex(envelopeJson);
            envelopeExpires = envelope.ExpiresUtc;
        }
        else if (requiredClass is not null) return null;

        lock (_gate)
        {
            var id = Guid.NewGuid().ToString("N");
            var stepStates = steps.Select(s =>
                new JobStepState(s.StepId, s.Name ?? s.StepId, s.Idempotency, StepStates.Pending, 0, null)).ToList();
            var job = new ResumableJob(id, k, deviceId.Trim(), JobStates.Pending, null,
                stepStates, envelopeJson, envelopeHash, envelope?.CommandClass, envelopeExpires, now, now, 0);
            _jobs[id] = job;
            var def = JsonSerializer.Serialize(new
            {
                kind = k, deviceId = job.DeviceId, createdUtc = now,
                envelopeHash, envelopeClass = envelope?.CommandClass, envelopeExpiresUtc = envelopeExpires,
                envelopeJson,
                steps = steps.Select(s => new { stepId = s.StepId, name = s.Name, idempotency = s.Idempotency.ToString() }).ToArray(),
            });
            if (AppendLocked(id, "job_created", def, now) is null)
            {
                // BD-SHARED-RMM-2/F2: the genesis entry could not be
                // made durable — the job must not exist.
                _jobs.Remove(id);
                return null;
            }
            _auditSink?.Invoke("job_created", null, $"job={id} kind={k} device={job.DeviceId} steps={steps.Count}");
            return job;
        }
    }

    public ResumableJob? GetJob(string? jobId)
    {
        lock (_gate) return jobId is not null && _jobs.TryGetValue(jobId, out var j) ? j : null;
    }

    public IReadOnlyList<ResumableJob> ListJobs(string? deviceId = null)
    {
        lock (_gate) return _jobs.Values
            .Where(j => deviceId is null || string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(j => j.CreatedUtc).ToList();
    }

    // ---- execution ------------------------------------------------

    private ResumableJob? MutableLocked(string jobId) =>
        _jobs.TryGetValue(jobId ?? "", out var j) ? j : null;

    private void SaveLocked(ResumableJob job, DateTimeOffset now) =>
        _jobs[job.Id] = job with { UpdatedUtc = now };

    /// <summary>pending/resumed → running. Terminal and parked jobs
    /// refuse; a parked job needs a human decision first.</summary>
    public bool StartJob(string jobId, DateTimeOffset now)
    {
        if (_verifyOnly) return false;
        lock (_gate)
        {
            var job = MutableLocked(jobId);
            if (job is null || job.State is not (JobStates.Pending or JobStates.Resumed)) return false;
            SaveLocked(job with { State = JobStates.Running }, now);
            if (AppendLocked(job.Id, "job_started", $"resumeCount={job.ResumeCount}", now) is null)
            {
                SaveLocked(job, now); // BD-SHARED-RMM-2/F2 rollback
                return false;
            }
            _liveExecution = true;
            return true;
        }
    }

    /// <summary>Begin the next step. Order is enforced: every prior
    /// step must be done/skipped — the monotonic discipline,
    /// generalised from FileJob byte counts to step order. The job
    /// must be running (a resumed job re-enters running here).
    /// D38 F1: the Resumed→Running transition is JOURNALLED (a
    /// job_started entry precedes the step_started entry), and the
    /// step is fully validated BEFORE any state changes — a refused
    /// BeginStep mutates nothing, in memory or in the journal.</summary>
    public bool BeginStep(string jobId, string stepId, DateTimeOffset now)
    {
        if (_verifyOnly) return false;
        lock (_gate)
        {
            var job = MutableLocked(jobId);
            if (job is null) return false;
            if (job.State is not (JobStates.Running or JobStates.Resumed)) return false;
            var idx = job.Steps.ToList().FindIndex(s => s.StepId == stepId);
            if (idx < 0) return false;
            if (job.Steps.Take(idx).Any(s => s.State is not (StepStates.Done or StepStates.Skipped))) return false;
            var step = job.Steps[idx];
            if (step.State != StepStates.Pending) return false;
            // All checks passed — now mutate, journal first-class.
            var original = job;
            if (job.State == JobStates.Resumed)
            {
                job = job with { State = JobStates.Running };
                SaveLocked(job, now);
                if (AppendLocked(job.Id, "job_started", $"resumeCount={job.ResumeCount} via=begin_step", now) is null)
                {
                    SaveLocked(original, now); // BD-SHARED-RMM-2/F2 rollback
                    return false;
                }
            }
            var steps = job.Steps.ToList();
            steps[idx] = step with { State = StepStates.Running, Attempts = step.Attempts + 1, LastError = null };
            SaveLocked(job with { Steps = steps }, now);
            if (AppendLocked(job.Id, "step_started", $"step={stepId} attempt={steps[idx].Attempts}", now) is null)
            {
                // BD-SHARED-RMM-2/F2: step_started was never made
                // durable — the step must NOT run. State rolls back
                // whole, so a crash-replay can never see this step as
                // running, and the caller sees the refusal.
                SaveLocked(original, now);
                return false;
            }
            _liveExecution = true;
            return true;
        }
    }

    /// <summary>running step → done. When every step is done or
    /// skipped the job itself becomes done — "done" requires ALL
    /// steps, exactly as FileJob's done requires full bytes.</summary>
    public bool CompleteStep(string jobId, string stepId, DateTimeOffset now)
    {
        if (_verifyOnly) return false;
        lock (_gate)
        {
            var job = MutableLocked(jobId);
            if (job is null || job.State != JobStates.Running) return false;
            var steps = job.Steps.ToList();
            var idx = steps.FindIndex(s => s.StepId == stepId);
            if (idx < 0 || steps[idx].State != StepStates.Running) return false;
            var original = job;
            steps[idx] = steps[idx] with { State = StepStates.Done };
            var allDone = steps.All(s => s.State is StepStates.Done or StepStates.Skipped);
            SaveLocked(job with { Steps = steps, State = allDone ? JobStates.Done : job.State }, now);
            if (AppendLocked(job.Id, "step_completed", $"step={stepId}", now) is null)
            {
                SaveLocked(original, now); // BD-SHARED-RMM-2/F2 rollback
                return false;
            }
            if (allDone)
            {
                AppendLocked(job.Id, "job_done", "all steps complete", now);
                _auditSink?.Invoke("job_done", null, $"job={job.Id} kind={job.Kind}");
            }
            return true;
        }
    }

    /// <summary>A step's own failure fails the job with the reason
    /// carried in state (failed-with-reason, per the directive).</summary>
    public bool FailStep(string jobId, string stepId, string reason, DateTimeOffset now)
    {
        if (_verifyOnly) return false;
        lock (_gate)
        {
            var job = MutableLocked(jobId);
            if (job is null || job.IsTerminal || job.State == JobStates.Parked) return false;
            var steps = job.Steps.ToList();
            var idx = steps.FindIndex(s => s.StepId == stepId);
            if (idx < 0 || steps[idx].State is StepStates.Done or StepStates.Skipped) return false;
            steps[idx] = steps[idx] with { State = StepStates.Failed, LastError = reason };
            var failure = $"step_failed:{stepId}:{reason}";
            SaveLocked(job with { Steps = steps, State = JobStates.Failed, FailureReason = failure }, now);
            AppendLocked(job.Id, "step_failed", $"step={stepId} reason={reason}", now);
            AppendLocked(job.Id, "job_failed", failure, now);
            _auditSink?.Invoke("job_failed", null, $"job={job.Id} reason={failure}");
            return true;
        }
    }

    // ---- resume ---------------------------------------------------

    /// <summary>Re-verify an envelope's signature + payload hash +
    /// expiry against the customer ring WITHOUT consuming its nonce
    /// (see the file header: resume is continuation, not replay).
    /// D38 F12: a key that exists but is retired past its grace
    /// deadline reports the NAMED reason authority_key_rotated,
    /// distinct from a merely invalid envelope.</summary>
    public static (bool Ok, string Reason) RecheckEnvelope(SignedCommandEnvelope e,
        CustomerCommandKeyRing ring, DateTimeOffset now)
    {
        if (e.ExpiresUtc <= now) return (false, JobFailureReasons.AuthorityExpired);
        byte[] payload;
        try { payload = Convert.FromBase64String(e.PayloadBase64 ?? ""); }
        catch { return (false, JobFailureReasons.AuthorityInvalid); }
        if (SignedCommandEnvelope.HashPayload(payload) != (e.PayloadHash ?? "").ToLowerInvariant())
            return (false, JobFailureReasons.AuthorityInvalid);
        if (!ring.TryGet(e.KeyId ?? "", out var key) || key is null)
            return (false, JobFailureReasons.AuthorityInvalid);
        if (key.IsRetired(now)) return (false, JobFailureReasons.AuthorityKeyRotated);
        try
        {
            var ok = Ed25519.Verify(key.PublicKey,
                Encoding.UTF8.GetBytes(SignedCommandEnvelope.CanonicalBody(e)),
                Convert.FromBase64String(e.SignatureBase64 ?? ""));
            return ok ? (true, "ok") : (false, JobFailureReasons.AuthorityInvalid);
        }
        catch { return (false, JobFailureReasons.AuthorityInvalid); }
    }

    /// <summary>The reconnect/reboot pass, toggle read from ONE
    /// source for the whole pass (D38 F6). Post-restart rules, in
    /// order: broken chain ⇒ every non-terminal job fails
    /// journal_tampered and NOTHING resumes; a step still executing
    /// in THIS process (live journal, D38 F11) ⇒ the job is reported
    /// "executing" and left completely alone; resume toggle OFF ⇒
    /// interrupted (running/resumed) jobs fail resume_disabled —
    /// parked jobs stay parked (a human decision is still owed and
    /// ResolveParked enforces the toggle) and never-started jobs stay
    /// pending; envelope expired/invalid/rotated ⇒ failed with the
    /// named authority reason; a step caught running ⇒ idempotent
    /// steps reset to pending (job resumed), non-idempotent steps
    /// become uncertain and the job PARKS for a human; otherwise the
    /// job is resumed at its next step. Resumed jobs run the SAME
    /// gauntlet as Running jobs on every pass (D38 F1) — there is no
    /// "already resumed" short-circuit.</summary>
    public ResumeReport ResumeAll(DateTimeOffset now, Func<bool> resumeEnabled,
        CustomerCommandKeyRing? ring = null, bool allowLiveJournal = false)
    {
        ArgumentNullException.ThrowIfNull(resumeEnabled);
        lock (_gate)
        {
            var enabled = resumeEnabled(); // read ONCE per pass (F6)
            var live = _liveExecution && !allowLiveJournal;
            var outcomes = new List<ResumeOutcome>();
            var rechecked = ring is not null;
            foreach (var job in _jobs.Values.Where(j => !j.IsTerminal).ToList())
            {
                if (!_chainOk)
                {
                    SaveLocked(job with { State = JobStates.Failed, FailureReason = JobFailureReasons.JournalTampered }, now);
                    outcomes.Add(new ResumeOutcome(job.Id, "failed", JobFailureReasons.JournalTampered));
                    continue;
                }
                // D38 F11: on a LIVE journal a job with a step in
                // flight in this process is executing, not crashed.
                // Resume must not reset, park or fail it.
                if (live && (job.State == JobStates.Running ||
                        job.Steps.Any(s => s.State == StepStates.Running)))
                {
                    outcomes.Add(new ResumeOutcome(job.Id, "executing",
                        "step still executing in this process (live journal / reconnect) — untouched by this pass"));
                    continue;
                }
                // Recovery-lane re-attack (F11): on a LIVE journal a
                // job already Resumed EARLIER IN THIS PROCESS is not
                // re-adjudicated by a reconnect pass — the first cut
                // ran it through the full gauntlet again, so a mere
                // reconnect could FAIL it when its envelope expired
                // after the legitimate resume, and every reconnect
                // inflated ResumeCount and appended another
                // job_resumed entry. Already-resumed is a settled
                // state for this process; the gauntlet belongs to
                // the post-restart pass.
                if (live && job.State == JobStates.Resumed)
                {
                    outcomes.Add(new ResumeOutcome(job.Id, "already_resumed",
                        "resumed earlier in this process — a reconnect pass does not re-adjudicate it"));
                    continue;
                }
                if (job.State == JobStates.Parked)
                {
                    outcomes.Add(new ResumeOutcome(job.Id, "parked", "awaiting human decision (unchanged by this pass)"));
                    continue;
                }
                if (job.State == JobStates.Pending)
                {
                    // Never started before the interruption: nothing
                    // to resume — it simply remains pending, honestly
                    // NOT labelled "resumed".
                    outcomes.Add(new ResumeOutcome(job.Id, "pending", "never started; remains pending"));
                    continue;
                }
                // Running or Resumed: the full gauntlet, every pass.
                if (!enabled)
                {
                    SaveLocked(job with { State = JobStates.Failed, FailureReason = JobFailureReasons.ResumeDisabled }, now);
                    AppendIfWritableLocked(job.Id, "job_failed", JobFailureReasons.ResumeDisabled, now);
                    outcomes.Add(new ResumeOutcome(job.Id, "failed", JobFailureReasons.ResumeDisabled));
                    continue;
                }
                // Authority: the envelope bound at creation governs.
                if (job.EnvelopeJson is not null)
                {
                    var env = SignedCommandEnvelope.FromJson(job.EnvelopeJson);
                    if (env is null || Sha256Hex(job.EnvelopeJson) != job.EnvelopeHash)
                    {
                        SaveLocked(job with { State = JobStates.Failed, FailureReason = JobFailureReasons.AuthorityInvalid }, now);
                        AppendIfWritableLocked(job.Id, "job_failed", JobFailureReasons.AuthorityInvalid, now);
                        outcomes.Add(new ResumeOutcome(job.Id, "failed", JobFailureReasons.AuthorityInvalid));
                        continue;
                    }
                    if (env.ExpiresUtc <= now)
                    {
                        SaveLocked(job with { State = JobStates.Failed, FailureReason = JobFailureReasons.AuthorityExpired }, now);
                        AppendIfWritableLocked(job.Id, "job_failed", JobFailureReasons.AuthorityExpired, now);
                        outcomes.Add(new ResumeOutcome(job.Id, "failed", JobFailureReasons.AuthorityExpired));
                        continue;
                    }
                    if (ring is not null)
                    {
                        var (ok, reason) = RecheckEnvelope(env, ring, now);
                        if (!ok)
                        {
                            SaveLocked(job with { State = JobStates.Failed, FailureReason = reason }, now);
                            AppendIfWritableLocked(job.Id, "job_failed", reason, now);
                            outcomes.Add(new ResumeOutcome(job.Id, "failed", reason));
                            continue;
                        }
                    }
                }
                // The crashed-step question.
                var steps = job.Steps.ToList();
                var runningIdx = steps.FindIndex(s => s.State == StepStates.Running);
                if (runningIdx >= 0 && steps[runningIdx].Idempotency == StepIdempotency.NonIdempotent)
                {
                    steps[runningIdx] = steps[runningIdx] with { State = StepStates.Uncertain };
                    SaveLocked(job with { Steps = steps, State = JobStates.Parked, FailureReason = JobFailureReasons.NonIdempotentUncertain }, now);
                    AppendIfWritableLocked(job.Id, "job_parked",
                        $"step={steps[runningIdx].StepId} was mid-flight at interruption and is non-idempotent", now);
                    _auditSink?.Invoke("job_parked", null, $"job={job.Id} step={steps[runningIdx].StepId}");
                    outcomes.Add(new ResumeOutcome(job.Id, "parked", JobFailureReasons.NonIdempotentUncertain));
                    continue;
                }
                if (runningIdx >= 0)
                    steps[runningIdx] = steps[runningIdx] with { State = StepStates.Pending };
                var resumed = job with
                {
                    Steps = steps, State = JobStates.Resumed, FailureReason = null,
                    ResumeCount = job.ResumeCount + 1,
                };
                SaveLocked(resumed, now);
                AppendIfWritableLocked(job.Id, "job_resumed",
                    $"resumeCount={resumed.ResumeCount} nextStep={(steps.FirstOrDefault(s => s.State == StepStates.Pending)?.StepId ?? "(none)")}", now);
                _auditSink?.Invoke("job_resumed", null, $"job={job.Id} resumeCount={resumed.ResumeCount}");
                outcomes.Add(new ResumeOutcome(job.Id, "resumed", $"resume #{resumed.ResumeCount}"));
            }
            return new ResumeReport(outcomes, _chainOk, rechecked);
        }
    }

    /// <summary>Compatibility overload: a fixed toggle value for the
    /// pass. Prefer the Func&lt;bool&gt; overload so ResumeAll and
    /// BuildStateReport read the SAME policy source (D38 F6).</summary>
    public ResumeReport ResumeAll(DateTimeOffset now, bool resumeEnabled,
        CustomerCommandKeyRing? ring = null)
        => ResumeAll(now, () => resumeEnabled, ring);

    /// <summary>The human decision for a parked job. RetryStep puts
    /// the uncertain step back to pending (the human asserts
    /// re-running it is right); SkipStep marks it skipped (the
    /// human asserts its effect already happened or is not needed);
    /// FailJob ends the job. Only parked jobs accept a decision,
    /// and the decision itself is journalled.
    /// D38 F6: when a resume-toggle source is supplied and it reads
    /// OFF, Retry/Skip decisions refuse (they would resume the job
    /// against policy); FailJob — which resumes nothing — is always
    /// allowed.</summary>
    public bool ResolveParked(string jobId, ParkedDecision decision, string decidedBy, DateTimeOffset now,
        Func<bool>? resumeEnabled = null)
    {
        if (_verifyOnly) return false;
        lock (_gate)
        {
            var job = MutableLocked(jobId);
            if (job is null || job.State != JobStates.Parked) return false;
            if (decision != ParkedDecision.FailJob && resumeEnabled is not null && !resumeEnabled())
                return false;
            var steps = job.Steps.ToList();
            var idx = steps.FindIndex(s => s.State == StepStates.Uncertain);
            if (decision == ParkedDecision.FailJob || idx < 0)
            {
                SaveLocked(job with { State = JobStates.Failed, FailureReason = JobFailureReasons.HumanDecisionFail }, now);
                AppendLocked(job.Id, "human_decision", $"by={decidedBy} decision=fail_job", now);
                return true;
            }
            steps[idx] = steps[idx] with
            {
                State = decision == ParkedDecision.RetryStep ? StepStates.Pending : StepStates.Skipped,
            };
            var allDone = steps.All(s => s.State is StepStates.Done or StepStates.Skipped);
            SaveLocked(job with
            {
                Steps = steps, FailureReason = null,
                State = allDone ? JobStates.Done : JobStates.Resumed,
                ResumeCount = job.ResumeCount + 1,
            }, now);
            AppendLocked(job.Id, "human_decision",
                $"by={decidedBy} decision={decision} step={steps[idx].StepId}", now);
            return true;
        }
    }

    // ---- reporting --------------------------------------------------

    /// <summary>Build the hub report, reading the resume toggle from
    /// the caller's single policy source (D38 F6) and carrying the
    /// journal's chain status + sequence (D38 F2/F9).</summary>
    public JobStateReport BuildStateReport(string deviceId, Func<bool> resumeEnabled, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(resumeEnabled);
        lock (_gate)
            return new JobStateReport(deviceId, now, resumeEnabled(), HeadHash,
                _jobs.Values.Where(j => string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(j => j.CreatedUtc)
                    .Select(j => new JobStateSummary(j.Id, j.Kind, j.State, j.FailureReason,
                        j.CompletedSteps, j.Steps.Count, j.ResumeCount)).ToList(),
                _chainOk, _brokenAtSeq, _chainSummary, _entries.Count, IsSigned);
    }

    /// <summary>Compatibility overload with a fixed toggle value.</summary>
    public JobStateReport BuildStateReport(string deviceId, bool resumeEnabled, DateTimeOffset now)
        => BuildStateReport(deviceId, () => resumeEnabled, now);

    // ---- persistence: export / replay-import ------------------------

    private sealed record EntryDto(long Seq, string JobId, DateTimeOffset AtUtc, string Kind,
        string Detail, string PrevHash, string Hash, string? SignatureBase64);

    /// <summary>Export is ENTRIES ONLY. There is no job snapshot to
    /// tamper with: state is rebuilt by replay on import.</summary>
    public string ExportJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(_entries.Select(e => new EntryDto(
                e.Seq, e.JobId, e.AtUtc, e.Kind, e.Detail, e.PrevHash, e.Hash, e.SignatureBase64)).ToArray());
    }

    /// <summary>Import + verify + replay. Chain verification checks
    /// sequence, prev-hash links, entry hashes, and (when a verify
    /// key is held) entry signatures. D38 F2: replay STOPS at the
    /// first broken entry — entries at/after the break are dropped
    /// as untrusted and never change job state. A broken chain
    /// imports as BROKEN (visible, named) and ResumeAll will fail
    /// every non-terminal job rather than trust fabricated progress.
    /// An unparseable store imports as the NAMED journal_lost
    /// failure (D38 F5), never as a silent empty journal.</summary>
    public JournalVerification ImportJson(string json) => ImportJson(json, null, null);

    /// <summary>Import with a rollback anchor (D38 F3): the last
    /// externally anchored (head hash, seq). A journal that no
    /// longer CONTAINS that head — truncated, rolled back, or
    /// rewritten below the anchor — imports as BROKEN even when its
    /// internal chain and signatures verify.</summary>
    public JournalVerification ImportJson(string json, string? expectedHeadHash, long? expectedSeq)
    {
        List<JobJournalEntry> restored;
        try
        {
            var dtos = JsonSerializer.Deserialize<List<EntryDto>>(json) ?? new List<EntryDto>();
            restored = dtos.Select(d => new JobJournalEntry(d.Seq, d.JobId, d.AtUtc, d.Kind,
                d.Detail, d.PrevHash, d.Hash, d.SignatureBase64)).ToList();
        }
        catch
        {
            lock (_gate)
            {
                _entries.Clear(); _jobs.Clear();
                _chainOk = false; _brokenAtSeq = null;
                _importError = JobFailureReasons.JournalLost;
                _chainSummary = $"{JobFailureReasons.JournalLost}: journal store did not parse — NOT trusted (torn or empty store after power loss is a named failure, never a silent empty journal)";
                _liveExecution = false;
            }
            return Verification;
        }
        lock (_gate)
        {
            _importError = null;
            _entries.Clear(); _jobs.Clear();
            _entries.AddRange(restored.OrderBy(e => e.Seq));
            _chainOk = true; _brokenAtSeq = null;
            _chainSummary = $"OK: {_entries.Count} entries, chain intact";
            var prev = GenesisHash;
            long expectSeq = 1;
            var trusted = 0;
            foreach (var e in _entries)
            {
                if (e.Seq != expectSeq || e.PrevHash != prev || e.Hash != ComputeHash(e))
                {
                    _chainOk = false; _brokenAtSeq = e.Seq;
                    _chainSummary = $"BROKEN at seq {e.Seq}: hash-chain mismatch (content altered or reordered); entries at/after the break are untrusted and were dropped";
                    break;
                }
                if (_verifyKey is not null)
                {
                    bool sigOk = false;
                    try
                    {
                        sigOk = e.SignatureBase64 is not null && Ed25519.Verify(_verifyKey,
                            Encoding.UTF8.GetBytes("acp-job-journal-v1|" + e.Hash),
                            Convert.FromBase64String(e.SignatureBase64));
                    }
                    catch { sigOk = false; }
                    if (!sigOk)
                    {
                        _chainOk = false; _brokenAtSeq = e.Seq;
                        _chainSummary = $"BROKEN at seq {e.Seq}: entry signature invalid (forged or recomputed history); entries at/after the break are untrusted and were dropped";
                        break;
                    }
                }
                prev = e.Hash; expectSeq++; trusted++;
            }
            var anchorFailed = false;
            if (_chainOk && expectedSeq.HasValue && expectedSeq.Value > 0 && expectedHeadHash is not null)
            {
                var es = expectedSeq.Value;
                if (_entries.Count < es)
                {
                    _chainOk = false; anchorFailed = true; _brokenAtSeq = es;
                    _chainSummary = $"BROKEN: rollback/truncation detected — journal holds {_entries.Count} entries but the anchored head is at seq {es} (head {expectedHeadHash}); the journal on disk is OLDER than the last anchored state and is NOT trusted";
                }
                else if (!string.Equals(_entries[(int)es - 1].Hash, expectedHeadHash, StringComparison.OrdinalIgnoreCase))
                {
                    _chainOk = false; anchorFailed = true; _brokenAtSeq = es;
                    _chainSummary = $"BROKEN: anchored head mismatch at seq {es} — history at or below the anchor was rewritten; journal NOT trusted";
                }
            }
            if (!_chainOk && !anchorFailed)
            {
                // D38 F2: drop the untrusted tail so it can never be
                // re-exported or chained onto; replay only the
                // verified prefix.
                _entries.RemoveRange(trusted, _entries.Count - trusted);
                for (var i = 0; i < trusted; i++) ReplayLocked(_entries[i]);
            }
            else
            {
                // Chain intact, or anchor-failed: replay what is
                // there FOR NAMING/REPORTING — trust is governed by
                // _chainOk (ResumeAll fails non-terminal jobs and the
                // hub refuses ChainOk=false reports), never by the
                // replayed states alone.
                foreach (var e in _entries) ReplayLocked(e);
            }
            _liveExecution = false;
            return Verification;
        }
    }

    private void ReplayLocked(JobJournalEntry e)
    {
        switch (e.Kind)
        {
            case "job_created":
            {
                try
                {
                    using var doc = JsonDocument.Parse(e.Detail);
                    var root = doc.RootElement;
                    var kind = root.GetProperty("kind").GetString() ?? "";
                    string? envClass = root.TryGetProperty("envelopeClass", out var ec) && ec.ValueKind == JsonValueKind.String ? ec.GetString() : null;
                    // D38 F12: the genesis kind↔envelopeClass binding
                    // is re-checked on replay — a recomputed journal
                    // that rebinds kind→class creates no job. The
                    // check MIRRORS CreateJob exactly (recovery-lane
                    // re-attack: the first cut demanded strict
                    // equality, which silently VANISHED a FileTransfer
                    // job carrying a known-class envelope — a shape
                    // CreateJob legitimately accepts): a kind with a
                    // required class demands that class; a kind with
                    // none (file transfer) accepts no envelope or an
                    // envelope of any KNOWN class, and nothing else.
                    if (!JobKinds.SignedClassByKind.TryGetValue(kind, out var requiredClass))
                        break;
                    if (requiredClass is not null &&
                        !string.Equals(requiredClass, envClass, StringComparison.Ordinal))
                        break;
                    if (requiredClass is null && envClass is not null &&
                        !SignedCommandClasses.All.Contains(envClass))
                        break;
                    var steps = root.GetProperty("steps").EnumerateArray().Select(s =>
                        new JobStepState(s.GetProperty("stepId").GetString() ?? "",
                            s.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                            Enum.TryParse<StepIdempotency>(s.GetProperty("idempotency").GetString(), out var idem)
                                ? idem : StepIdempotency.NonIdempotent,
                            StepStates.Pending, 0, null)).ToList();
                    string? envJson = root.TryGetProperty("envelopeJson", out var ej) && ej.ValueKind == JsonValueKind.String ? ej.GetString() : null;
                    string? envHash = root.TryGetProperty("envelopeHash", out var eh) && eh.ValueKind == JsonValueKind.String ? eh.GetString() : null;
                    DateTimeOffset? envExp = root.TryGetProperty("envelopeExpiresUtc", out var ex) && ex.ValueKind == JsonValueKind.String
                        ? ex.GetDateTimeOffset() : null;
                    _jobs[e.JobId] = new ResumableJob(e.JobId,
                        kind,
                        root.GetProperty("deviceId").GetString() ?? "",
                        JobStates.Pending, null, steps, envJson, envHash, envClass, envExp,
                        e.AtUtc, e.AtUtc, 0);
                }
                catch { /* a genesis entry that does not parse creates no job; chain state already speaks */ }
                break;
            }
            case "job_started":
                if (_jobs.TryGetValue(e.JobId, out var js)) _jobs[e.JobId] = js with { State = JobStates.Running, UpdatedUtc = e.AtUtc };
                break;
            case "step_started":
                MutateStepLocked(e, (s, detail) => s with
                {
                    State = StepStates.Running,
                    Attempts = ParseAttempt(detail) ?? s.Attempts + 1,
                });
                break;
            case "step_completed":
                MutateStepLocked(e, (s, _) => s with { State = StepStates.Done });
                break;
            case "step_failed":
                MutateStepLocked(e, (s, detail) => s with { State = StepStates.Failed, LastError = DetailValue(detail, "reason") });
                break;
            case "job_done":
                // D38 F2 defence in depth: "done" requires ALL steps
                // done/skipped — a job_done entry that arrives while
                // steps are outstanding changes nothing.
                if (_jobs.TryGetValue(e.JobId, out var jd) &&
                    jd.Steps.All(s => s.State is StepStates.Done or StepStates.Skipped))
                    _jobs[e.JobId] = jd with { State = JobStates.Done, UpdatedUtc = e.AtUtc };
                break;
            case "job_failed":
                if (_jobs.TryGetValue(e.JobId, out var jf))
                    _jobs[e.JobId] = jf with { State = JobStates.Failed, FailureReason = ReasonOf(jf, e.Detail), UpdatedUtc = e.AtUtc };
                break;
            case "job_resumed":
                if (_jobs.TryGetValue(e.JobId, out var jr))
                {
                    // D38 F1: replay applies the SAME step reset as
                    // the live resume path — a step left "running"
                    // at this point in history is the step the crash
                    // interrupted: idempotent → pending; non-
                    // idempotent → uncertain and the job PARKS (an
                    // honest journal only writes job_resumed for the
                    // idempotent/no-running case; anything else fails
                    // safe to parked, never silently onward).
                    var steps = jr.Steps.ToList();
                    var idx = steps.FindIndex(s => s.State == StepStates.Running);
                    var state = JobStates.Resumed;
                    string? failure = null;
                    if (idx >= 0 && steps[idx].Idempotency == StepIdempotency.NonIdempotent)
                    {
                        steps[idx] = steps[idx] with { State = StepStates.Uncertain };
                        state = JobStates.Parked;
                        failure = JobFailureReasons.NonIdempotentUncertain;
                    }
                    else if (idx >= 0)
                    {
                        steps[idx] = steps[idx] with { State = StepStates.Pending };
                    }
                    _jobs[e.JobId] = jr with
                    {
                        Steps = steps, State = state, FailureReason = failure,
                        ResumeCount = jr.ResumeCount + 1, UpdatedUtc = e.AtUtc,
                    };
                }
                break;
            case "job_parked":
                if (_jobs.TryGetValue(e.JobId, out var jp))
                {
                    var steps = jp.Steps.ToList();
                    var idx = steps.FindIndex(s => s.State == StepStates.Running);
                    if (idx >= 0) steps[idx] = steps[idx] with { State = StepStates.Uncertain };
                    _jobs[e.JobId] = jp with { Steps = steps, State = JobStates.Parked, FailureReason = JobFailureReasons.NonIdempotentUncertain, UpdatedUtc = e.AtUtc };
                }
                break;
            case "human_decision":
            {
                if (_jobs.TryGetValue(e.JobId, out var jh))
                {
                    var decision = DetailValue(e.Detail, "decision");
                    var stepId = DetailValue(e.Detail, "step");
                    if (decision == "fail_job")
                        _jobs[e.JobId] = jh with { State = JobStates.Failed, FailureReason = JobFailureReasons.HumanDecisionFail, UpdatedUtc = e.AtUtc };
                    else if (stepId is not null)
                    {
                        var steps = jh.Steps.ToList();
                        var idx = steps.FindIndex(s => s.StepId == stepId);
                        if (idx >= 0)
                            steps[idx] = steps[idx] with { State = decision == "SkipStep" ? StepStates.Skipped : StepStates.Pending };
                        var allDone = steps.All(s => s.State is StepStates.Done or StepStates.Skipped);
                        _jobs[e.JobId] = jh with
                        {
                            Steps = steps, FailureReason = null, UpdatedUtc = e.AtUtc,
                            State = allDone ? JobStates.Done : JobStates.Resumed,
                            ResumeCount = jh.ResumeCount + 1,
                        };
                    }
                }
                break;
            }
        }
    }

    private static string ReasonOf(ResumableJob job, string detail)
    {
        // job_failed details written by this journal are either a
        // bare reason token or "step_failed:<step>:<reason>".
        if (detail.StartsWith("step_failed:", StringComparison.Ordinal)) return detail;
        return detail.Trim();
    }

    private void MutateStepLocked(JobJournalEntry e, Func<JobStepState, string, JobStepState> mutate)
    {
        if (!_jobs.TryGetValue(e.JobId, out var job)) return;
        var stepId = DetailValue(e.Detail, "step");
        if (stepId is null) return;
        var steps = job.Steps.ToList();
        var idx = steps.FindIndex(s => s.StepId == stepId);
        if (idx < 0) return;
        steps[idx] = mutate(steps[idx], e.Detail);
        _jobs[e.JobId] = job with { Steps = steps, UpdatedUtc = e.AtUtc };
    }

    private static string? DetailValue(string detail, string key)
    {
        foreach (var part in (detail ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            if (part.StartsWith(key + "=", StringComparison.Ordinal)) return part[(key.Length + 1)..];
        return null;
    }

    private static int? ParseAttempt(string detail)
    {
        var v = DetailValue(detail, "attempt");
        return int.TryParse(v, out var n) ? n : null;
    }

    private sealed record AnchorDto(string HeadHash, long Seq);

    private static void WriteFileFsync(string path, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        fs.Write(bytes, 0, bytes.Length);
        fs.Flush(true);
    }

    /// <summary>Compacting persistence (D38 F5): the full journal is
    /// written to a temp file, FLUSHED TO DISK, then atomically
    /// renamed over the target — a crash mid-save leaves the OLD
    /// journal, never a torn one. The rollback anchor (D38 F3) is
    /// written after the rename. The write-ahead log is RETAINED
    /// (it is the recovery source if the main file is later torn;
    /// LoadFromFile ignores WAL entries already folded into the
    /// main file by sequence). NAMED RESIDUAL: the WAL therefore
    /// grows with the journal — WAL compaction (rewriting it from
    /// an externally anchored snapshot) is maintenance tooling, not
    /// built here.</summary>
    public void SaveToFile(string path)
    {
        // BD-SHARED-RMM-2/F3: the exported entries and the anchor are
        // taken under ONE lock acquisition, from the SAME snapshot.
        // The old shape released the lock between ExportJson and
        // CurrentAnchor, so a concurrent append made the anchor newer
        // than the file — and the next load read that as a rollback
        // and broke the whole journal.
        string json; (string HeadHash, long Seq) snapshotAnchor;
        lock (_gate)
        {
            json = ExportJson();
            snapshotAnchor = (_entries.Count == 0 ? GenesisHash : _entries[^1].Hash, _entries.Count);
        }
        var (head, seq) = snapshotAnchor;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        WriteFileFsync(tmp, json);
        File.Move(tmp, path, overwrite: true);
        WriteFileFsync(path + ".anchor.tmp", JsonSerializer.Serialize(new AnchorDto(head, seq)));
        File.Move(path + ".anchor.tmp", path + ".anchor", overwrite: true);
        lock (_gate) _persistPath = path;
    }

    /// <summary>Load the persisted journal: main file (verified
    /// against its rollback anchor), then any write-ahead entries
    /// appended since the last compaction. A missing main file with
    /// a surviving anchor is journal_lost (D38 F3/F5); a torn main
    /// file whose WAL alone forms a valid chain is recovered from
    /// the WAL; a torn main file with no recoverable WAL is
    /// journal_lost — named, never silently empty.</summary>
    public JournalVerification LoadFromFile(string path)
    {
        lock (_gate) _persistPath = path;
        (string Head, long Seq)? anchor = null;
        try
        {
            if (File.Exists(path + ".anchor"))
            {
                var dto = JsonSerializer.Deserialize<AnchorDto>(File.ReadAllText(path + ".anchor"));
                if (dto is not null) anchor = (dto.HeadHash, dto.Seq);
            }
        }
        catch { /* an unreadable anchor is no anchor; the chain itself still speaks */ }

        var walEntries = ReadWal(path);
        if (!File.Exists(path))
        {
            if (walEntries is { Count: > 0 } && TryImportWalOnly(walEntries, anchor))
                return Verification;
            if (anchor is not null)
            {
                lock (_gate)
                {
                    _entries.Clear(); _jobs.Clear();
                    _chainOk = false; _brokenAtSeq = anchor.Value.Seq; _importError = JobFailureReasons.JournalLost;
                    _chainSummary = $"{JobFailureReasons.JournalLost}: journal file is missing but its anchor survives (seq {anchor.Value.Seq}, head {anchor.Value.Head}) — the store was deleted or rolled back; NOT treated as an empty journal";
                    _liveExecution = false;
                }
                return Verification;
            }
            return Verification; // genuinely fresh: no file, no anchor, no WAL
        }

        var v = ImportJson(File.ReadAllText(path), anchor?.Head, anchor?.Seq);
        if (!_chainOk && _importError == JobFailureReasons.JournalLost && walEntries is { Count: > 0 })
        {
            // Torn main file: the WAL is the recovery source.
            // BD-SHARED-RMM-2/F3 note: this recovery deliberately does
            // NOT extend to an anchor-stale main file. A main file
            // whose chain is internally intact but older than its
            // anchor is a ROLLBACK (D38-F3), and resurrecting it from
            // the WAL would defeat the anchor — the claim's
            // "judge the anchor against main+WAL" limb is therefore
            // not taken; the race it cited is closed at the source by
            // SaveToFile's single-snapshot anchor above.
            if (TryImportWalOnly(walEntries, anchor)) return Verification;
        }
        if (walEntries is { Count: > 0 }) ApplyWalTail(walEntries);
        return Verification;
    }

    private static List<JobJournalEntry>? ReadWal(string path)
    {
        try
        {
            var walPath = path + ".wal";
            if (!File.Exists(walPath)) return null;
            var list = new List<JobJournalEntry>();
            foreach (var line in File.ReadLines(walPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var d = JsonSerializer.Deserialize<EntryDto>(line);
                    if (d is null) break; // torn tail line: stop, earlier lines stand
                    list.Add(new JobJournalEntry(d.Seq, d.JobId, d.AtUtc, d.Kind, d.Detail, d.PrevHash, d.Hash, d.SignatureBase64));
                }
                catch { break; } // torn tail line (crash mid-append): the append never returned, so dropping it is exact
            }
            return list;
        }
        catch { return null; }
    }

    private bool TryImportWalOnly(List<JobJournalEntry> walEntries, (string Head, long Seq)? anchor)
    {
        var json = JsonSerializer.Serialize(walEntries.Select(e => new EntryDto(
            e.Seq, e.JobId, e.AtUtc, e.Kind, e.Detail, e.PrevHash, e.Hash, e.SignatureBase64)).ToArray());
        // Recovery-lane re-attack (F3/F5): the WAL path must honour
        // the rollback anchor too — a WAL truncated BELOW the anchor
        // is a rollback, not a recovery, and must never verify OK.
        var v = ImportJson(json, anchor?.Head, anchor?.Seq);
        if (v.Ok)
        {
            lock (_gate)
                _chainSummary = $"OK: recovered {_entries.Count} entries from the write-ahead log (main store was lost/torn)";
            return true;
        }
        return false;
    }

    /// <summary>Apply WAL entries that extend the imported chain
    /// (appends since the last compaction). Each must link exactly
    /// (seq, prev-hash, hash, signature); the first that does not is
    /// a torn tail and stops the tail — never trusted, never fatal.</summary>
    private void ApplyWalTail(List<JobJournalEntry> walEntries)
    {
        lock (_gate)
        {
            if (!_chainOk) return;
            foreach (var e in walEntries.OrderBy(x => x.Seq))
            {
                if (e.Seq <= _entries.Count) continue; // already folded into the main file
                var prev = _entries.Count == 0 ? GenesisHash : _entries[^1].Hash;
                if (e.Seq != _entries.Count + 1 || e.PrevHash != prev || e.Hash != ComputeHash(e)) break;
                if (_verifyKey is not null)
                {
                    bool sigOk = false;
                    try
                    {
                        sigOk = e.SignatureBase64 is not null && Ed25519.Verify(_verifyKey,
                            Encoding.UTF8.GetBytes("acp-job-journal-v1|" + e.Hash),
                            Convert.FromBase64String(e.SignatureBase64));
                    }
                    catch { sigOk = false; }
                    if (!sigOk) break;
                }
                _entries.Add(e);
                ReplayLocked(e);
            }
            _chainSummary = $"OK: {_entries.Count} entries, chain intact (incl. write-ahead tail)";
        }
    }
}

/// <summary>Hub-side reconciliation of per-device job reports. The
/// hub's view only moves FORWARD (D38 F9, full discipline):
///   * a report from a BROKEN journal (ChainOk=false) is refused —
///     state derived from untrusted entries never enters the hub
///     view, so a forged terminal state cannot lock in;
///   * a report dated beyond now + a small skew is refused (a
///     future-dated report must not freeze the device forever);
///   * stale reports (older generation time than the last accepted)
///     refuse, and an equal-time or equal-sequence report whose
///     journal head DIFFERS from the accepted one refuses;
///   * the journal sequence never regresses;
///   * per job: terminal states never exit or flip; CompletedSteps
///     and ResumeCount never regress; non-terminal state moves only
///     along the forward edges (pending→running/resumed/parked/
///     done/failed, running→resumed/parked/done/failed, resumed→
///     running/parked/done/failed, parked→resumed/done/failed) —
///     resumed→pending, parked→running and friends refuse.
/// AUTHENTICATION SEAM, NAMED: report.DeviceId is self-asserted in
/// the report value and reports are unsigned at this layer; the
/// reconciler must only be fed reports that arrived over the
/// device's authenticated paired transport (the pairing layer binds
/// the session to the enrolled device). An optional enrolled-device
/// gate can be supplied for defence in depth.</summary>
public sealed class JobStateReconciler
{
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(5);

    private readonly Dictionary<string, JobStateReport> _latestByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, JobStateSummary>> _jobsByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<DateTimeOffset>? _clock;
    private readonly Func<string, bool>? _isEnrolledDevice;
    private readonly bool _requireSigned;
    private readonly Dictionary<string, (DateTimeOffset AtUtc, string Reason)> _untrustedByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>BD-SHARED-RMM-2/F10: devices whose latest report was
    /// refused as journal-untrusted (broken chain), by name, with the
    /// refusal reason — tampering surfaces as a NAMED state here,
    /// never as a silently frozen hub view.</summary>
    public IReadOnlyDictionary<string, (DateTimeOffset AtUtc, string Reason)> UntrustedDevices
    {
        get { lock (_gate) return new Dictionary<string, (DateTimeOffset, string)>(_untrustedByDevice); }
    }

    /// <param name="clock">The hub's clock. The future-dating bound
    /// (D38 F9) is enforced when a clock is supplied — the hub host
    /// MUST supply it in production; without one this layer cannot
    /// know "now" for a device report and skips that one check
    /// (every other discipline applies unconditionally).</param>
    public JobStateReconciler(Func<DateTimeOffset>? clock = null, Func<string, bool>? isEnrolledDevice = null,
        bool requireSigned = false)
    {
        _clock = clock;
        _isEnrolledDevice = isEnrolledDevice;
        _requireSigned = requireSigned;
    }

    private static bool ForwardStateOk(string from, string to)
    {
        if (from == to) return true;
        if (JobStates.IsTerminal(from)) return false; // terminal exits/flips handled by caller with named reasons
        return from switch
        {
            JobStates.Pending => to is JobStates.Running or JobStates.Resumed or JobStates.Parked or JobStates.Done or JobStates.Failed,
            JobStates.Running => to is JobStates.Resumed or JobStates.Parked or JobStates.Done or JobStates.Failed,
            JobStates.Resumed => to is JobStates.Running or JobStates.Parked or JobStates.Done or JobStates.Failed,
            JobStates.Parked => to is JobStates.Resumed or JobStates.Done or JobStates.Failed,
            _ => false,
        };
    }

    public (bool Accepted, string Reason) Accept(JobStateReport report)
    {
        if (report is null || string.IsNullOrWhiteSpace(report.DeviceId))
            return (false, "report carries no device id — refused");
        if (_isEnrolledDevice is not null && !_isEnrolledDevice(report.DeviceId))
            return (false, $"report for unenrolled device '{report.DeviceId}' — refused (device identity is established by the pairing/transport layer; this report did not arrive over it)");
        if (!report.ChainOk)
        {
            // BD-SHARED-RMM-2/F10: the refusal stands (untrusted state
            // never enters the hub view), but the device is RECORDED
            // as journal_untrusted by name — the old shape dropped the
            // report whole, so the hub view froze at the last good
            // state (e.g. 'running') and the tamper was silence.
            lock (_gate) _untrustedByDevice[report.DeviceId] =
                (report.GeneratedUtc, $"journal_tampered: broken chain at seq {report.BrokenAtSeq}: {report.ChainSummary}");
            return (false, $"report for '{report.DeviceId}' derives from a BROKEN journal (break at seq {report.BrokenAtSeq}: {report.ChainSummary}) — refused and recorded as journal_untrusted: untrusted state never enters the hub view, so a forged terminal state cannot lock in");
        }
        if (_requireSigned && !report.Signed)
            return (false, $"report for '{report.DeviceId}' is UNSIGNED and this hub requires signed journals in enterprise scope — refused (an unsigned journal's history is recomputable by whoever can write the store)");
        if (_clock is not null && report.GeneratedUtc > _clock().Add(MaxFutureSkew))
            return (false, $"report for '{report.DeviceId}' is dated {report.GeneratedUtc:O}, beyond now + {MaxFutureSkew.TotalMinutes:0} min skew — refused (a future-dated report must not freeze the device's view)");
        lock (_gate)
        {
            if (_latestByDevice.TryGetValue(report.DeviceId, out var latest))
            {
                if (report.GeneratedUtc < latest.GeneratedUtc)
                    return (false, $"stale report for '{report.DeviceId}' (older than the last accepted) — refused");
                if (report.GeneratedUtc == latest.GeneratedUtc && report.JournalHeadHash != latest.JournalHeadHash)
                    return (false, $"conflicting reports for '{report.DeviceId}' at the same generation time — refused");
                if (report.JournalSeq > 0 && latest.JournalSeq > 0)
                {
                    if (report.JournalSeq < latest.JournalSeq)
                        return (false, $"journal sequence for '{report.DeviceId}' regresses ({report.JournalSeq} < {latest.JournalSeq}) — refused (rollback is not rewritable history)");
                    if (report.JournalSeq == latest.JournalSeq && report.JournalHeadHash != latest.JournalHeadHash)
                        return (false, $"conflicting reports for '{report.DeviceId}' at journal seq {report.JournalSeq} with different heads — refused");
                }
            }
            var known = _jobsByDevice.TryGetValue(report.DeviceId, out var existing)
                ? existing : new Dictionary<string, JobStateSummary>(StringComparer.Ordinal);
            foreach (var job in report.Jobs)
            {
                if (!known.TryGetValue(job.JobId, out var prior)) continue;
                if (JobStates.IsTerminal(prior.State) && !JobStates.IsTerminal(job.State))
                    return (false, $"job '{job.JobId}' on '{report.DeviceId}' regresses out of terminal state '{prior.State}' to '{job.State}' — refused (history is not rewritable)");
                if (JobStates.IsTerminal(prior.State) && job.State != prior.State)
                    return (false, $"job '{job.JobId}' on '{report.DeviceId}' flips terminal state '{prior.State}' to '{job.State}' — refused");
                if (job.CompletedSteps < prior.CompletedSteps)
                    return (false, $"job '{job.JobId}' on '{report.DeviceId}' regresses completed steps {prior.CompletedSteps}→{job.CompletedSteps} — refused (progress only moves forward)");
                if (job.ResumeCount < prior.ResumeCount)
                    return (false, $"job '{job.JobId}' on '{report.DeviceId}' regresses resume count {prior.ResumeCount}→{job.ResumeCount} — refused");
                if (!ForwardStateOk(prior.State, job.State))
                    return (false, $"job '{job.JobId}' on '{report.DeviceId}' moves state '{prior.State}'→'{job.State}', which is not a forward edge — refused");
            }
            var merged = new Dictionary<string, JobStateSummary>(known, StringComparer.Ordinal);
            foreach (var job in report.Jobs) merged[job.JobId] = job;
            _jobsByDevice[report.DeviceId] = merged;
            _latestByDevice[report.DeviceId] = report;
            _untrustedByDevice.Remove(report.DeviceId); // a verified report clears the untrusted mark
            return (true, $"report for '{report.DeviceId}' accepted: {report.Jobs.Count} job(s), head {report.JournalHeadHash}");
        }
    }

    public IReadOnlyList<JobStateSummary> JobsFor(string deviceId)
    {
        lock (_gate)
            return _jobsByDevice.TryGetValue(deviceId ?? "", out var m)
                ? m.Values.OrderBy(j => j.JobId, StringComparer.Ordinal).ToList()
                : Array.Empty<JobStateSummary>();
    }

    public JobStateSummary? GetJob(string deviceId, string jobId)
    {
        lock (_gate)
            return _jobsByDevice.TryGetValue(deviceId ?? "", out var m) &&
                   m.TryGetValue(jobId ?? "", out var j) ? j : null;
    }
}

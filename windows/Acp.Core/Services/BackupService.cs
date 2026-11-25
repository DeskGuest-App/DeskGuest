using System.Text;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Core.Services;

/// <summary>
/// RMM-06 data surface in the Core: endpoint backup to user-owned
/// storage. Jobs, schedules, selections, retentions and targets are
/// POLICY CONTENT (RMM-07): this service computes the device's
/// Effective Policy, parses the backup content out of it
/// (BackupPolicyContent — refusals named, never silent), and runs
/// what is due. The TOTAL POLICY CONTROL toggle
/// `rmm.backup.enabled` gates runs and restores; when it is OFF,
/// both refuse by name.
///
/// Hub-issued backup/restore commands arrive as RMM-03 signed
/// commands (class automation): the gate verifies BEFORE anything
/// is parsed or executed, and the engine re-verifies the restore
/// binding (envelope payload must name this snapshot + device).
/// A delete command under a perfectly valid signature is still
/// refused by the snapshot store — immutability does not care who
/// signed the request.
///
/// Host wiring (W11 / R-15, LANDED): BackupHostWiring constructs
/// the per-target BackupSnapshotStore over DirectoryBackupStorage
/// at each policy target's locator, with the target's at-rest key
/// loaded via BackupAtRest.LoadOrCreateKeyFile under the Core's
/// DPAPI protector (key files live in the Core data dir, NEVER at
/// the target), reloads each target's persisted catalogue, and
/// hands this service one BackupEngine per target. This service
/// routes every act by the job's / snapshot's target. Still owed
/// and named, not hidden: the VSS-backed capture source (the host
/// wires FileBackupCaptureSource — real file capture, honestly
/// NOT snapshot-consistent; image jobs refuse by name until VSS
/// lands) and feeding BackupHealthFacts into the endpoint monitor
/// cycle (no production monitor-cycle caller exists yet).
///
/// W10 / V2-C1: the store seals chunks + manifests at rest
/// (BackupAtRest, AES-256-GCM, AAD bound to the storage key, key
/// fingerprint bound into the catalogue chain). A store
/// constructed without a key is the legacy plaintext shape,
/// retained for tests and deliberate recovery of pre-encryption
/// backups, never a silent fallback — production wiring always
/// passes a key.
/// </summary>
public sealed class BackupService : IBackupHealthFactsProvider
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly IReadOnlyDictionary<string, BackupEngine> _enginesByTarget;
    private readonly SignedCommandGate? _gate;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<RestoreRequester, bool>? _requesterAuthenticator;
    private readonly Action<string>? _catalogueDirty;
    private readonly Dictionary<string, IBackupCaptureSource> _captureByDevice = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="gate">The RMM-03 verify-gate for hub-issued
    /// commands. When null, hub-command entry points refuse —
    /// named, never silent; policy-scheduled local runs and
    /// scope-checked self-restore still work.</param>
    /// <param name="requesterAuthenticator">D38 F7: the host's proof
    /// that a self-restore requester IS the authenticated session
    /// user on that device. Host wiring supplies it from the
    /// session; when wired, SelfRestore refuses an unauthenticated
    /// claim before the engine is reached. When not wired, the
    /// engine's scope check compares the claimed identity only —
    /// that host-wiring dependency is named, not silent. W11 /
    /// R-09 remainder: CoreRuntime still wires NO authenticator —
    /// no standing authenticated-session-user provider is exposed
    /// to Core services (the console SID exists only inside
    /// AgentChannel's per-connection verify path), so this stays
    /// unwired until that provider exists; it is NOT faked.</param>
    public BackupService(ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice, BackupEngine engine,
        SignedCommandGate? gate, Func<DateTimeOffset>? now = null,
        Func<RestoreRequester, bool>? requesterAuthenticator = null)
        : this(audit, policy, factsByDevice,
            new Dictionary<string, BackupEngine>(StringComparer.OrdinalIgnoreCase)
                { [engine?.Store.TargetId ?? throw new ArgumentNullException(nameof(engine))] = engine },
            gate, now, requesterAuthenticator)
    {
    }

    /// <summary>W11 / R-15: the multi-target shape production host
    /// wiring constructs — one engine per policy storage target,
    /// routed by target id. An EMPTY map is a legitimate wiring
    /// outcome (policy names no targets): every run/restore then
    /// refuses BY NAME instead of falling back to an in-memory
    /// fake, which is what the pre-W11 host construction did.</summary>
    /// <param name="catalogueDirty">Host hook invoked with a target
    /// id after any act that may have changed that target's
    /// catalogue, so the host can persist it (SaveCatalogueToFile).
    /// Null in tests / single-process rigs.</param>
    public BackupService(ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        IReadOnlyDictionary<string, BackupEngine> enginesByTarget,
        SignedCommandGate? gate, Func<DateTimeOffset>? now = null,
        Func<RestoreRequester, bool>? requesterAuthenticator = null,
        Action<string>? catalogueDirty = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _enginesByTarget = enginesByTarget ?? throw new ArgumentNullException(nameof(enginesByTarget));
        _gate = gate;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _requesterAuthenticator = requesterAuthenticator;
        _catalogueDirty = catalogueDirty;
    }

    /// <summary>The single wired engine when exactly one target is
    /// wired; otherwise the first target's engine (routing callers
    /// should use EnginesByTarget). Throws when no target is wired
    /// — a caller asking for THE engine of a target-less service
    /// has no honest answer.</summary>
    public BackupEngine Engine => _enginesByTarget.Count == 1
        ? _enginesByTarget.Values.First()
        : _enginesByTarget.Values.FirstOrDefault()
            ?? throw new InvalidOperationException("no backup target is wired on this host — there is no backup engine");

    /// <summary>Every wired per-target engine, keyed by target id.</summary>
    public IReadOnlyDictionary<string, BackupEngine> EnginesByTarget => _enginesByTarget;

    public IReadOnlyList<string> WiredTargetIds => _enginesByTarget.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();

    private BackupEngine? EngineForTarget(string targetId) =>
        _enginesByTarget.TryGetValue(targetId ?? "", out var engine) ? engine : null;

    private BackupEngine? EngineForSnapshot(string snapshotId)
    {
        foreach (var engine in _enginesByTarget.Values)
            if (engine.Store.GetSnapshot(snapshotId) is not null) return engine;
        return null;
    }

    private void NoteCatalogueDirty(string targetId)
    {
        try { _catalogueDirty?.Invoke(targetId); } catch { /* persistence must never break the act it follows */ }
    }

    /// <summary>The device's backup policy content, computed from
    /// its Effective Policy. Parse refusals are returned with the
    /// content — a malformed job is visible, never dropped.</summary>
    public BackupPolicyContent.ParseResult PolicyFor(string deviceId)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return new BackupPolicyContent.ParseResult(
                Array.Empty<BackupJobDefinition>(), Array.Empty<BackupStorageTarget>(),
                new[] { $"no device facts for '{deviceId}' — no backup policy can be computed" });
        var parsed = BackupPolicyContent.Parse(_policy.ComputeEffective(facts));
        return new BackupPolicyContent.ParseResult(
            parsed.Jobs.Where(j => string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToList(),
            parsed.Targets, parsed.Refusals);
    }

    public bool IsBackupEnabled(string deviceId)
    {
        var facts = _factsByDevice(deviceId);
        return facts is not null && _policy.IsEnabled(facts, BackupPolicyKeys.BackupEnabled);
    }

    /// <summary>Run every due job for a device. Each run needs its
    /// RMM-15 authority: the caller supplies the automation envelope
    /// the hub minted for this run cycle (the scheduler's signed
    /// dispatch); without a journal wired in the engine the envelope
    /// is unused, with one it is mandatory — the engine names the
    /// refusal either way.</summary>
    public IReadOnlyList<BackupRunOutcome> RunDueJobs(string deviceId, SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (!IsBackupEnabled(deviceId))
        {
            _audit.Append("backup_refused", "backup-service",
                $"device={deviceId} reason=rmm.backup.enabled is OFF by policy", now);
            return new[] { new BackupRunOutcome(false, "refused: rmm.backup.enabled is OFF by policy", null, null, 0, 0) };
        }
        var content = PolicyFor(deviceId);
        var outcomes = new List<BackupRunOutcome>();
        var jobsByTarget = content.Jobs.GroupBy(j => j.TargetId, StringComparer.OrdinalIgnoreCase);
        foreach (var group in jobsByTarget)
        {
            var engine = EngineForTarget(group.Key);
            if (engine is null)
            {
                // W11 / R-15: a due job whose target has no wired
                // store refuses BY NAME — the pre-W11 host silently
                // ran every job against an in-memory fake store.
                foreach (var job in group.Where(j => j.Enabled &&
                    string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                    j.Schedule.IsDue(null, now)))
                {
                    var reason = $"no backup store is wired on this host for target '{group.Key}' — job '{job.Id}' refused, nothing written (the target is not constructible here, or policy named it after this host started)";
                    _audit.Append("backup_refused", "backup-service", $"device={deviceId} job={job.Id} reason={reason}", now);
                    outcomes.Add(new BackupRunOutcome(false, reason, null, job.Id, 0, 0));
                }
                continue;
            }
            foreach (var job in engine.DueJobs(group, deviceId, now))
            {
                outcomes.Add(engine.RunBackup(job, envelope, now));
                NoteCatalogueDirty(group.Key);
            }
        }
        return outcomes;
    }

    /// <summary>Execute one hub-issued backup command. The envelope
    /// (class automation) is verified by the RMM-03 gate first; its
    /// payload names the job id to run ("acp-backup-run-v1|&lt;jobId&gt;").
    /// The SAME envelope then authorises the RMM-15 job in the
    /// engine — one signature, bound twice.</summary>
    public BackupRunOutcome RunBackupCommand(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured on this endpoint — hub backup commands refuse (RMM-03)";
            _audit.Append("backup_refused", "backup-service", reason, now);
            return new BackupRunOutcome(false, reason, null, null, 0, 0);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.Automation);
        if (!verdict.Allowed) return new BackupRunOutcome(false, $"signed backup command refused: {verdict.Reason}", null, null, 0, 0);
        // D38 F12: an allowed verdict with no payload is a refusal,
        // not a NullReferenceException from a null-forgiving bang.
        if (verdict.Payload is null)
        {
            const string reason = "signed backup command carried no payload — refused";
            _audit.Append("backup_refused", "backup-service", reason, now);
            return new BackupRunOutcome(false, reason, null, null, 0, 0);
        }
        var payload = Encoding.UTF8.GetString(verdict.Payload);
        var parts = payload.Split('|');
        if (parts.Length != 2 || parts[0] != "acp-backup-run-v1" || string.IsNullOrWhiteSpace(parts[1]))
        {
            const string reason = "signed backup command payload does not name a job (expected acp-backup-run-v1|<jobId>) — refused";
            _audit.Append("backup_refused", "backup-service", reason, now);
            return new BackupRunOutcome(false, reason, null, null, 0, 0);
        }
        var jobId = parts[1];
        // Find the job across the fleet's policy content: the job id
        // is the address; its device comes from the job itself.
        foreach (var candidateDevice in CandidateDevices())
        {
            var job = PolicyFor(candidateDevice).Jobs.FirstOrDefault(j => j.Id == jobId);
            if (job is not null)
            {
                var engine = EngineForTarget(job.TargetId);
                if (engine is null)
                {
                    var unwired = $"backup job '{jobId}' names target '{job.TargetId}', for which no backup store is wired on this host — refused, nothing written";
                    _audit.Append("backup_refused", "backup-service", unwired, now);
                    return new BackupRunOutcome(false, unwired, null, job.Id, 0, 0);
                }
                var outcome = engine.RunBackup(job, envelope, now);
                NoteCatalogueDirty(job.TargetId);
                return outcome;
            }
        }
        var notFound = $"backup job '{jobId}' is not in any device's effective policy — refused";
        _audit.Append("backup_refused", "backup-service", notFound, now);
        return new BackupRunOutcome(false, notFound, null, null, 0, 0);
    }

    private IEnumerable<string> CandidateDevices()
    {
        // Devices this service can see facts for are enumerated by
        // the caller-provided facts function over the policy
        // engine's documents' device targets — plus any device with
        // a backup job in its effective policy. Kept deliberately
        // simple: device-level policy documents name their device.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var doc in _policy.Documents.Where(d => d.Level == PolicyLevels.Device))
            if (seen.Add(doc.TargetId)) yield return doc.TargetId;
    }

    /// <summary>Self-restore entry point (the end user's own files,
    /// own device — scope enforced in the engine, audited either
    /// way).</summary>
    public RestoreOutcome SelfRestore(string snapshotId, IReadOnlyList<string>? paths,
        IRestoreTarget target, RestoreRequester requester)
    {
        if (_requesterAuthenticator is not null && !_requesterAuthenticator(requester))
        {
            var reason = $"self-restore refused: the requester's claimed identity ('{requester.UserId}' on '{requester.DeviceId}') could not be authenticated by the host";
            _audit.Append("self_restore_refused", requester.UserId, $"snapshot={snapshotId} reason={reason}", _now());
            return new RestoreOutcome(false, reason, 0, 0);
        }
        var engine = EngineForSnapshot(snapshotId);
        if (engine is null)
        {
            var reason = $"snapshot '{snapshotId}' is not in any wired backup target's catalogue — self-restore refused";
            _audit.Append("self_restore_refused", requester.UserId, $"snapshot={snapshotId} reason={reason}", _now());
            return new RestoreOutcome(false, reason, 0, 0);
        }
        return engine.RestoreFiles(snapshotId, paths, target, requester, envelope: null, _now());
    }

    /// <summary>Hub/admin restore entry point: the envelope is
    /// verified inside the engine against the snapshot binding.</summary>
    public RestoreOutcome AdminRestore(string snapshotId, IReadOnlyList<string>? paths,
        IRestoreTarget target, RestoreRequester admin, SignedCommandEnvelope? envelope,
        bool allowSystemPaths = false)
    {
        var engine = EngineForSnapshot(snapshotId);
        if (engine is null)
            return new RestoreOutcome(false,
                $"snapshot '{snapshotId}' is not in any wired backup target's catalogue — restore refused", 0, 0);
        return engine.RestoreFiles(snapshotId, paths, target, admin, envelope, _now(), allowSystemPaths);
    }

    /// <summary>A delete request, whoever sent it and however it
    /// was signed, meets the store's refusal — surfaced here so the
    /// attempt lands in the audit chain.</summary>
    public DeleteOutcome RequestDelete(string snapshotId, string actor, bool underSignedCommand)
    {
        var engine = EngineForSnapshot(snapshotId);
        if (engine is null)
            return new DeleteOutcome(false,
                $"snapshot '{snapshotId}' is not in any wired backup target's catalogue — delete refused");
        var outcome = engine.RequestDelete(snapshotId, actor, underSignedCommand, _now());
        NoteCatalogueDirty(engine.Store.TargetId);
        return outcome;
    }

    /// <summary>The device's backup health facts — the RMM-01 seam
    /// (see BackupEngine's header for the exact consumption shape).
    /// W11 / R-15: with several targets wired the facts MERGE —
    /// latest attempt/success win, failures and locked snapshots
    /// sum, storage reads reachable only when every wired target
    /// is reachable, and a tampered catalogue anywhere taints the
    /// whole report. With NO target wired the facts say so
    /// (never ran, storage unreachable) rather than borrowing a
    /// fake engine's numbers.</summary>
    public BackupHealthFacts HealthFacts(string deviceId) => HealthFactsAt(deviceId, _now());

    /// <summary>IBackupHealthFactsProvider leg (W11 / R-15):
    /// Reporting + HealthScoring consume backup facts through this
    /// provider — with per-target wiring the provider is THIS
    /// service (merged across targets), not any single engine.</summary>
    public BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now) => HealthFactsAt(deviceId, now);

    private BackupHealthFacts HealthFactsAt(string deviceId, DateTimeOffset now)
    {
        if (_enginesByTarget.Count == 0)
            return new BackupHealthFacts(deviceId, null, null, null, 0, 0, 0, false, null, false, now);
        if (_enginesByTarget.Count == 1)
            return _enginesByTarget.Values.First().GetFacts(deviceId, now);
        var all = _enginesByTarget.Values.Select(e => e.GetFacts(deviceId, now)).ToList();
        var latest = all.Where(f => f.LastAttemptUtc is not null).OrderByDescending(f => f.LastAttemptUtc).FirstOrDefault();
        return new BackupHealthFacts(
            deviceId,
            all.Select(f => f.LastAttemptUtc).Max(),
            all.Select(f => f.LastSuccessUtc).Max(),
            latest?.LastOutcome ?? all.Select(f => f.LastOutcome).FirstOrDefault(o => o is not null),
            all.Sum(f => f.ConsecutiveFailures),
            all.Sum(f => f.LockedSnapshots),
            all.Sum(f => f.LockedBytes),
            all.All(f => f.StorageReachable),
            all.Select(f => f.StorageFreePercent).Where(p => p is not null).Min(),
            all.Any(f => f.CatalogueTampered),
            now);
    }

    /// <summary>Usage across every wired target. The single-target
    /// shape is the engine's own report, unchanged; multi-target
    /// reports sum under an honest aggregate target id.</summary>
    public BackupUsageReport Usage()
    {
        var now = _now();
        if (_enginesByTarget.Count == 0)
            return new BackupUsageReport("no backup target wired on this host", 0, 0, 0, 0, 0, null, null, null);
        if (_enginesByTarget.Count == 1)
            return _enginesByTarget.Values.First().Usage(now);
        var all = _enginesByTarget.Values.Select(e => e.Usage(now)).ToList();
        return new BackupUsageReport(
            $"all wired targets ({all.Count})",
            all.Sum(r => r.SealedSnapshots), all.Sum(r => r.LockedSnapshots),
            all.Sum(r => r.LogicalBytes), all.Sum(r => r.StoredBytes), all.Sum(r => r.LockedBytes),
            all.Select(r => r.OldestSealedUtc).Min(), all.Select(r => r.NewestSealedUtc).Max(),
            all.All(r => r.StorageFreeBytes is not null) ? all.Sum(r => r.StorageFreeBytes ?? 0) : null);
    }
}

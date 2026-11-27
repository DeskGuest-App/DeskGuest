using System.Text.Json;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.Sessions;

// =====================================================================
// G-04 — File transfer OUTSIDE a session (census §3 row; §6
// differentiator, graded Core in §21): the standalone "send a file
// to my PC" verb. Slice 3's FileJob is session-bound by
// construction — a job carries a SessionId and dies with its
// session — so the standalone form is its own service with the
// same discipline (monotonic progress, closed transitions, done
// requires full bytes) and a different consent basis: there is no
// host-side accept for a machine-to-machine act, so authorization
// is the Slice 2 "use" grant on the target device's group —
// exactly the grant that authorizes an unattended session. A user
// who could not start an unattended session on the device cannot
// push files at it either.
//
// What a standalone job is NOT: it is not a back door around
// session consent for interactive work. It moves named files
// between the initiator and one enrolled device, every act is
// recorded, and the whole service is policy-toggleable (TOTAL
// POLICY CONTROL, key "standalone_file_transfer").
// =====================================================================

/// <summary>A standalone transfer job. Deliberately mirrors
/// FileJob's invariants (monotonic progress; "done" requires
/// TransferredBytes == SizeBytes) without a SessionId.</summary>
public sealed record StandaloneJob(
    string Id,
    string ScopeId,
    string DeviceId,
    string InitiatorUserId,
    string Direction,           // "to_host" | "from_host" (SessionService.ValidDirections)
    string Name,
    long SizeBytes,
    long TransferredBytes,
    string State);              // SessionService.ValidFileJobStates

public sealed record StandaloneEvent(
    DateTimeOffset Utc, string Kind, string JobId, string? ActorUserId, string Detail);

public sealed class StandaloneTransferService
{
    private readonly RosterService _roster;
    private readonly EnrollmentService _enrollments;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly Action<string, string?, string>? _auditSink;
    private readonly Dictionary<string, StandaloneJob> _jobs = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<StandaloneEvent> _events = new();
    private readonly object _gate = new();

    /// <param name="featureGate">TOTAL POLICY CONTROL gate,
    /// SCOPE-AWARE (scopeId, featureKey) — D38 review F2.</param>
    /// <param name="auditSink">Optional chained-audit sink
    /// (kind, actor, detail) — D38 review F1.</param>
    public StandaloneTransferService(RosterService roster, EnrollmentService enrollments,
        Func<string, string, PolicyVerdict>? featureGate = null,
        Action<string, string?, string>? auditSink = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _featureGate = featureGate;
        _auditSink = auditSink;
    }

    public event Action? Changed;
    public IReadOnlyList<StandaloneEvent> Events { get { lock (_gate) return _events.ToList(); } }

    private bool FeatureAllowed(string scopeId) =>
        _featureGate?.Invoke(scopeId, PolicyFeatures.StandaloneFileTransfer).Allowed ?? true;

    private EnrolledDevice? Device(string? deviceId) =>
        _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId ?? "", StringComparison.OrdinalIgnoreCase));

    private void RecordLocked(string kind, StandaloneJob job, string? actor, string detail)
    {
        _events.Add(new StandaloneEvent(DateTimeOffset.UtcNow, kind, job.Id, actor, detail));
        _auditSink?.Invoke(kind, actor, detail);
        Changed?.Invoke();
    }

    /// <summary>The standing authorization re-read, run before
    /// every act (the F4 discipline applied to a session-less
    /// surface): the device must still be enrolled, unrevoked, and
    /// filed in the job's scope, and the initiator must still be a
    /// live user holding the "use" grant. When the re-read fails
    /// on a live job, the job is cancelled on the spot — a transfer
    /// whose authorization evaporated mid-flight does not get to
    /// finish quietly.</summary>
    private bool AuthorizationIntactLocked(StandaloneJob job)
    {
        var device = Device(job.DeviceId);
        if (device is null || device.Revoked) return false;
        var group = _roster.FindDeviceGroup(device.GroupId);
        if (group is null || !string.Equals(group.ScopeId, job.ScopeId, StringComparison.OrdinalIgnoreCase))
            return false;
        var initiator = _roster.GetUser(job.ScopeId, job.InitiatorUserId);
        if (initiator is null || initiator.Suspended) return false;
        return _roster.UserHasRight(job.ScopeId, job.InitiatorUserId, device.GroupId, "use");
    }

    private bool EnforceAuthorizationLocked(StandaloneJob job)
    {
        if (job.State is "done" or "failed" or "cancelled") return false;
        if (AuthorizationIntactLocked(job)) return false;
        _jobs[job.Id] = job with { State = "cancelled" };
        RecordLocked("job_cancelled_authorization_lost", _jobs[job.Id], null,
            "Transfer cancelled: its authorization (device enrollment or initiator grant) no longer holds.");
        return true;
    }

    /// <summary>Create a standalone job in "queued". Null on
    /// refusal: policy-disabled feature, unknown/revoked device, a
    /// device not filed in the named scope (D8), an initiator who
    /// is not a live user of the scope or holds no "use" grant on
    /// the device's group, an unknown direction, an empty name, or
    /// a negative size.</summary>
    public StandaloneJob? CreateJob(string scopeId, string deviceId, string initiatorUserId,
        string direction, string name, long sizeBytes)
    {
        var normalizedDirection = (direction ?? "").Trim().ToLowerInvariant();
        if (!SessionService.ValidDirections.Contains(normalizedDirection)) return null;
        if (string.IsNullOrWhiteSpace(name) || sizeBytes < 0) return null;
        lock (_gate)
        {
            if (_roster.GetScope(scopeId) is not { } scope) return null;
            if (!FeatureAllowed(scope.Id)) return null;
            var device = Device(deviceId);
            if (device is null || device.Revoked) return null;
            var group = _roster.FindDeviceGroup(device.GroupId);
            if (group is null || !string.Equals(group.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase))
                return null;
            var initiator = _roster.GetUser(scope.Id, initiatorUserId);
            if (initiator is null || initiator.Suspended) return null;
            if (!_roster.UserHasRight(scope.Id, initiator.Id, device.GroupId, "use")) return null;
            var job = new StandaloneJob(Guid.NewGuid().ToString("N"), scope.Id, device.DeviceId,
                initiator.Id, normalizedDirection, name.Trim(), sizeBytes, 0, "queued");
            _jobs[job.Id] = job;
            RecordLocked("job_created", job, initiator.Id,
                $"Standalone transfer '{job.Name}' ({normalizedDirection}, {sizeBytes} bytes) queued for {device.DeviceId}.");
            return job;
        }
    }

    public StandaloneJob? GetJob(string? jobId)
    {
        if (string.IsNullOrWhiteSpace(jobId)) return null;
        lock (_gate) return _jobs.TryGetValue(jobId, out var j) ? j : null;
    }

    /// <summary>Live (non-terminal) job count across all scopes —
    /// a snapshot fact; counts only, never job contents.</summary>
    public int LiveJobCount()
    {
        lock (_gate) return _jobs.Values.Count(j => j.State is not ("done" or "failed" or "cancelled"));
    }

    /// <summary>Jobs for one device (operator-side read), or one
    /// scope when deviceId is null (D8 isolation on the read too).</summary>
    public IReadOnlyList<StandaloneJob> ListJobs(string scopeId, string? deviceId = null)
    {
        lock (_gate)
            return _jobs.Values
                .Where(j => string.Equals(j.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                            (deviceId is null || string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)))
                .ToList();
    }

    /// <summary>Report progress. Monotonic (a lower value refuses,
    /// an over-size value refuses), terminal jobs refuse, and the
    /// authorization re-read runs first — progress on a job whose
    /// grant died cancels the job and refuses. The policy gate is
    /// re-consulted on continuing acts too (D38 review F6: a
    /// disable lands on running jobs, not just new ones). Only
    /// the initiator reports progress: the bytes are theirs.</summary>
    public bool UpdateProgress(string jobId, long transferredBytes, string actorUserId)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (EnforceAuthorizationLocked(job)) return false;
            job = _jobs[job.Id];
            if (!FeatureAllowed(job.ScopeId)) return false;
            if (!string.Equals(actorUserId, job.InitiatorUserId, StringComparison.OrdinalIgnoreCase)) return false;
            if (job.State is "done" or "failed" or "cancelled") return false;
            if (transferredBytes < job.TransferredBytes) return false;
            if (transferredBytes > job.SizeBytes) return false;
            if (transferredBytes == job.TransferredBytes) return true;
            _jobs[job.Id] = job with { TransferredBytes = transferredBytes };
            RecordLocked("job_progress", _jobs[job.Id], actorUserId,
                $"Transfer '{job.Name}' at {transferredBytes}/{job.SizeBytes} bytes.");
            return true;
        }
    }

    /// <summary>Move a job along FileJob's closed transition set
    /// (shared with the session jobs — one transfer discipline for
    /// the product). "done" requires full bytes. Only the
    /// initiator moves their job; the authorization re-read and
    /// the policy gate (F6) run first. The one exception to
    /// initiator-only is CANCEL via <see cref="CancelJob"/>: a
    /// job must always be stoppable from the device's side of the
    /// house (D38 review F7).</summary>
    public bool SetJobState(string jobId, string state, string actorUserId)
    {
        var normalized = (state ?? "").Trim().ToLowerInvariant();
        if (!SessionService.ValidFileJobStates.Contains(normalized)) return false;
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (EnforceAuthorizationLocked(job)) return false;
            job = _jobs[job.Id];
            if (!FeatureAllowed(job.ScopeId)) return false;
            if (!string.Equals(actorUserId, job.InitiatorUserId, StringComparison.OrdinalIgnoreCase)) return false;
            if (!SessionService.IsLegalFileJobTransition(job.State, normalized)) return false;
            if (normalized == "done" && job.TransferredBytes != job.SizeBytes) return false;
            _jobs[job.Id] = job with { State = normalized };
            RecordLocked("job_state", _jobs[job.Id], actorUserId,
                $"Transfer '{job.Name}' → {normalized}.");
            return true;
        }
    }

    /// <summary>Cancel one live job (D38 review F7). The
    /// initiator can always stop their own transfer; a live
    /// company admin of the job's scope can stop anyone's — the
    /// device-side house must be able to halt an incoming push
    /// without the initiator's cooperation (the §7.10 STOP
    /// principle applied to a session-less surface). Anyone else
    /// refuses. The cancel is recorded with its actor.</summary>
    public bool CancelJob(string jobId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (job.State is "done" or "failed" or "cancelled") return false;
            var isInitiator = string.Equals(actorUserId, job.InitiatorUserId, StringComparison.OrdinalIgnoreCase);
            var isAdmin = _roster.IsCompanyAdmin(job.ScopeId, actorUserId) &&
                _roster.GetUser(job.ScopeId, actorUserId) is { Kind: "human", Suspended: false };
            if (!isInitiator && !isAdmin) return false;
            _jobs[job.Id] = job with { State = "cancelled" };
            RecordLocked("job_cancelled", _jobs[job.Id], actorUserId,
                isInitiator
                    ? "Transfer cancelled by its initiator."
                    : "Transfer cancelled by a company admin (device-side stop).");
            return true;
        }
    }

    /// <summary>The device-presence stop (Block H D38 fix F10):
    /// the person physically at this machine can stop ANY live
    /// job, whoever started it — the panel's promise, made true
    /// in the service instead of depending on a typed roster id.
    /// This is a STOP-only power (the §7.10 fail-safe direction):
    /// it starts nothing, moves nothing, and grants nothing. The
    /// act is recorded under the reserved actor "device-console"
    /// — never under a roster identity the person at the keyboard
    /// merely typed into a box, which is how the chained audit
    /// used to come to attribute a stop to an admin who was never
    /// there. Reachable only from inside the host process (the
    /// Core's laptop-UI IPC channel); it is not an MCP surface.</summary>
    public const string DeviceConsoleActor = "device-console";

    public bool CancelJobFromDevice(string jobId)
    {
        lock (_gate)
        {
            if (!_jobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (job.State is "done" or "failed" or "cancelled") return false;
            _jobs[job.Id] = job with { State = "cancelled" };
            RecordLocked("job_cancelled", _jobs[job.Id], DeviceConsoleActor,
                "Transfer stopped from the device console by the person at this machine (device-presence stop, §7.10).");
            return true;
        }
    }

    /// <summary>Cancel every live job touching a device or a user —
    /// the offboarding/revocation sweep the wiring layer calls when
    /// the roster changes. (Per-act re-reads already cancel lazily;
    /// this is the eager form.) Returns the number cancelled; the
    /// sweep's actor is recorded when the wiring names one.</summary>
    public int CancelJobsFor(string? deviceId = null, string? initiatorUserId = null, string? actorUserId = null)
    {
        lock (_gate)
        {
            var count = 0;
            foreach (var job in _jobs.Values.Where(j =>
                         j.State is not ("done" or "failed" or "cancelled") &&
                         (deviceId is not null && string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                          initiatorUserId is not null && string.Equals(j.InitiatorUserId, initiatorUserId, StringComparison.OrdinalIgnoreCase)))
                     .ToList())
            {
                _jobs[job.Id] = job with { State = "cancelled" };
                RecordLocked("job_cancelled_sweep", _jobs[job.Id], actorUserId,
                    "Transfer cancelled by an offboarding/revocation sweep.");
                count++;
            }
            return count;
        }
    }

    /// <summary>Policy-change TEARDOWN sweep (Block H — the D38
    /// F6 remainder): when a policy reload disables
    /// standalone_file_transfer, every live job in that scope is
    /// cancelled on the spot under the actor "policy" (the F6
    /// per-act gate re-check already refuses progress on a
    /// disabled feature; this ends the job itself instead of
    /// leaving a zombie record the byte leg might resume).
    /// Returns the number cancelled.</summary>
    public int SweepPolicyTeardown(string scopeId, Func<string, bool> featureDisabled)
    {
        if (!featureDisabled(PolicyFeatures.StandaloneFileTransfer)) return 0;
        lock (_gate)
        {
            var count = 0;
            foreach (var job in _jobs.Values.Where(j =>
                         j.State is not ("done" or "failed" or "cancelled") &&
                         string.Equals(j.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase)).ToList())
            {
                _jobs[job.Id] = job with { State = "cancelled" };
                RecordLocked("job_cancelled_policy", _jobs[job.Id], "policy",
                    "Transfer cancelled: a policy change disabled standalone_file_transfer for this scope.");
                count++;
            }
            return count;
        }
    }

    // ---- persistence ------------------------------------------------------

    private sealed record JobDto(string Id, string ScopeId, string DeviceId, string InitiatorUserId,
        string Direction, string Name, long SizeBytes, long TransferredBytes, string State);

    private sealed record EventDto(DateTimeOffset Utc, string Kind, string JobId,
        string? ActorUserId, string Detail);

    private sealed record StoreDto(JobDto[] Jobs, EventDto[]? Events);

    public string ExportJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new StoreDto(
                _jobs.Values.Select(j => new JobDto(j.Id, j.ScopeId,
                    j.DeviceId, j.InitiatorUserId, j.Direction, j.Name, j.SizeBytes,
                    j.TransferredBytes, j.State)).ToArray(),
                _events.Select(e => new EventDto(e.Utc, e.Kind, e.JobId, e.ActorUserId, e.Detail)).ToArray()));
    }

    /// <summary>Restore, re-validated like every DeskGuest store: rows
    /// missing any identity field (scope/device/initiator) drop —
    /// including terminal rows (D38 review F7); jobs whose device
    /// or initiator authorization no longer holds are restored
    /// CANCELLED (their history is evidence, not a live
    /// capability); a job stored "active" restores FAILED — its
    /// byte leg did not survive the restart, and a record must
    /// not claim a transfer is moving when nothing is moving it;
    /// non-monotonic or over-size progress, unknown
    /// directions/states, and "done" without full bytes are
    /// dropped at the entry. The pre-F1 bare-array shape is still
    /// accepted.</summary>
    public int ImportJson(string json)
    {
        JobDto[]? dtos;
        EventDto[]? eventDtos = null;
        try
        {
            var store = JsonSerializer.Deserialize<StoreDto>(json);
            dtos = store?.Jobs;
            eventDtos = store?.Events;
        }
        catch { dtos = null; }
        if (dtos is null)
        {
            try { dtos = JsonSerializer.Deserialize<JobDto[]>(json); }
            catch { return 0; }
        }
        if (dtos is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in eventDtos ?? Array.Empty<EventDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Kind) ||
                    string.IsNullOrWhiteSpace(dto.JobId)) continue;
                _events.Add(new StandaloneEvent(dto.Utc, dto.Kind, dto.JobId, dto.ActorUserId, dto.Detail ?? ""));
            }
            foreach (var dto in dtos)
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    string.IsNullOrWhiteSpace(dto.ScopeId) ||
                    string.IsNullOrWhiteSpace(dto.DeviceId) ||
                    string.IsNullOrWhiteSpace(dto.InitiatorUserId) ||
                    string.IsNullOrWhiteSpace(dto.Name)) continue;
                var direction = (dto.Direction ?? "").Trim().ToLowerInvariant();
                var state = (dto.State ?? "").Trim().ToLowerInvariant();
                if (!SessionService.ValidDirections.Contains(direction)) continue;
                if (!SessionService.ValidFileJobStates.Contains(state)) continue;
                if (dto.SizeBytes < 0 || dto.TransferredBytes < 0 || dto.TransferredBytes > dto.SizeBytes) continue;
                if (state == "done" && dto.TransferredBytes != dto.SizeBytes) continue;
                if (_jobs.ContainsKey(dto.Id)) continue;
                if (state == "active") state = "failed"; // interrupted by restart (F7)
                var job = new StandaloneJob(dto.Id, dto.ScopeId, dto.DeviceId, dto.InitiatorUserId,
                    direction, dto.Name, dto.SizeBytes, dto.TransferredBytes, state);
                if (state is not ("done" or "failed" or "cancelled") && !AuthorizationIntactLocked(job))
                    job = job with { State = "cancelled" };
                _jobs[job.Id] = job;
                restored++;
            }
        }
        return restored;
    }
}

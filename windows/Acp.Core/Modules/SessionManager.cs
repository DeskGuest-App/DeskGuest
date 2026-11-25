using System.Text.Json;
using Acp.Shared.Policy;
using Acp.Shared.Tools;
using Acp.Shared.Security;

namespace Acp.Core.Modules;

/// <summary>Desktop-work session bookkeeping (DESIGN §7.4, SPEC §7.8a):
/// a session binds a pairing, a presence state, and a time box. The
/// agent ends its session as the final action of a completed task;
/// connection drop and idle timeout are the backstops.</summary>
public sealed record SessionRecord(
    string Id,
    string PairingId,
    string ActorAgentName,
    IReadOnlySet<string> ScopesInForce,
    DateTimeOffset StartedUtc,
    DateTimeOffset LastActionUtc,
    DateTimeOffset? TimeBoxEndsUtc,
    bool AgentUnlockedThisSession);

public sealed class SessionManager
{
    private readonly object _gate = new();
    private SessionRecord? _current;
    private int _actionCount;
    private string? _pauseReason;

    public SessionRecord? Current { get { lock (_gate) return _current; } }

    /// <summary>U4 tripwire pause state. A paused session is NOT
    /// ended: presence stays up, the reason is visible, and the
    /// owner resumes it (Resume) — a budget/SCAM tripwire never
    /// hard-kills a session and never silently lets it continue.
    /// The MCP choke point denies every call while paused (except
    /// session_stop / session_status) with this reason.</summary>
    public bool IsPaused { get { lock (_gate) return _current is not null && _pauseReason is not null; } }
    public string? PauseReason { get { lock (_gate) return _pauseReason; } }

    /// <summary>Pause the live session with a presence-visible
    /// reason. Returns false when there is no live session or it is
    /// already paused (the first reason stands).</summary>
    public bool Pause(string reason)
    {
        lock (_gate)
        {
            if (_current is null || _pauseReason is not null) return false;
            _pauseReason = reason;
            return true;
        }
    }

    /// <summary>Owner resume: clear the pause. Returns the reason
    /// that was cleared, or null when the session was not paused.
    /// W12 / DS-P6-F19: resume also Touches, so the idle clock restarts
    /// from the resume, not from the last pre-pause action.</summary>
    public string? Resume()
    {
        lock (_gate)
        {
            var reason = _pauseReason;
            _pauseReason = null;
            if (reason is not null && _current is not null)
                _current = _current with { LastActionUtc = DateTimeOffset.UtcNow };
            return reason;
        }
    }

    /// <summary>U1 TOTAL POLICY CONTROL seam: CoreRuntime wires this
    /// to the RMM-07 engine — it returns the effective clipboard
    /// policy for this device, or null when policy disables the
    /// clipboard layer ("rmm.clipboard_policy.enabled" = false).
    /// Unset (unit tests, embedders) = the named defaults. Resolved
    /// per call by the MCP choke point and by the Core's IPC push,
    /// so an admitted policy document takes effect without a
    /// restart and the session never carries a stale copy.</summary>
    public Func<ClipboardPolicy?>? ClipboardPolicyProvider { get; set; }

    public ClipboardPolicy? ResolveClipboardPolicy() =>
        ClipboardPolicyProvider is null ? ClipboardPolicy.Default : ClipboardPolicyProvider();

    /// <summary>Successful tool executions in the current session —
    /// the mesh heartbeat's "actions" field (M2). Reset at session
    /// start/stop; counted by the MCP choke point, nowhere else.</summary>
    public int ActionCount => Volatile.Read(ref _actionCount);
    public void NoteAction() => Interlocked.Increment(ref _actionCount);
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Start a session. W12 / DS-P6-F6: returns null when a
    /// session is already live — the check and the start are ONE lock
    /// acquisition, so two concurrent starts cannot both observe
    /// "no session" and clobber each other.</summary>
    public SessionRecord? Start(Pairing pairing, bool agentUnlocked = false)
    {
        lock (_gate)
        {
            if (_current is not null) return null;
            var now = DateTimeOffset.UtcNow;
            _current = new SessionRecord(
                Guid.NewGuid().ToString("N"), pairing.Id, pairing.AgentName,
                pairing.Scopes, now, now,
                pairing.SessionTimeBox is { } box ? now + box : null,
                agentUnlocked);
            Volatile.Write(ref _actionCount, 0);
            _pauseReason = null;
            return _current;
        }
    }

    public void Touch()
    {
        lock (_gate)
        {
            if (_current is not null) _current = _current with { LastActionUtc = DateTimeOffset.UtcNow };
        }
    }

    /// <summary>End the session. Returns the record that ended, or null.</summary>
    public SessionRecord? Stop()
    {
        lock (_gate)
        {
            var ended = _current;
            _current = null;
            _pauseReason = null;
            Volatile.Write(ref _actionCount, 0);
            return ended;
        }
    }

    /// <summary>W12 / DS-P6-F7: ownership-checked stop — ends the
    /// live session ONLY when it belongs to <paramref name="pairingId"/>.
    /// Returns false (and stops nothing) when there is no session or
    /// the live session is another pairing's.</summary>
    public bool TryStopForPairing(string pairingId, out SessionRecord? ended)
    {
        lock (_gate)
        {
            ended = null;
            if (_current is null) return false;
            if (!string.Equals(_current.PairingId, pairingId, StringComparison.Ordinal)) return false;
            ended = _current;
            _current = null;
            _pauseReason = null;
            Volatile.Write(ref _actionCount, 0);
            return true;
        }
    }

    /// <summary>Backstop checks (idle timeout / time box). Returns the
    /// reason the live session must end, or null if it may continue.</summary>
    public string? ExpiryReason(DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_current is null) return null;
            if (_current.TimeBoxEndsUtc is { } end && now > end) return "time_box_expired";
            // W12 / DS-P6-F19: a PAUSED session is not ended by the
            // idle backstop — pause means the owner froze it on
            // purpose; the time box still applies (it is a hard cap,
            // not an activity clock).
            if (_pauseReason is not null) return null;
            if (now - _current.LastActionUtc > IdleTimeout) return "idle_timeout";
            return null;
        }
    }
}

/// <summary>Census row 1: session_start — binds the pairing to a presence
/// session. Presence comes up WITH the session; there is no silent session.</summary>
public sealed class SessionStartModule : IToolModule
{
    private readonly SessionManager _sessions;
    private readonly CoreState _state;
    private readonly Shared.Security.SignedCommandGate? _commandGate;

    /// <param name="commandGate">RMM-03 verify-gate. When wired,
    /// session initiation requires a verified signed-command
    /// envelope (class session_initiation, payload
    /// "session_start|&lt;pairing id&gt;") — a compromised hub
    /// cannot open sessions the customer never signed for. When
    /// null, no customer command key is configured and the
    /// pre-RMM-03 posture stands (named in CoreRuntime).</param>
    public SessionStartModule(SessionManager sessions, CoreState state, Shared.Security.SignedCommandGate? commandGate = null)
    { _sessions = sessions; _state = state; _commandGate = commandGate; }

    public ToolDescriptor Descriptor { get; } = new(
        "session_start", "Start a control session: presence on, narration live, time box in force.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"signed_command":{"type":"string","description":"RMM-03 signed-command envelope JSON; required when a customer command key is configured on this endpoint"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (_commandGate is not null)
        {
            // W12 / DS-P6-F17: GetString() throws on a non-string
            // signed_command; a malformed argument is a refusal, not
            // a crash out of ExecuteAsync. A null payload on an Allowed
            // verdict refuses the same way.
            var envelope = Shared.Security.SignedCommandEnvelope.FromJson(
                arguments.ValueKind == JsonValueKind.Object && arguments.TryGetProperty("signed_command", out var sc)
                    && sc.ValueKind == JsonValueKind.String ? sc.GetString() : null);
            var verdict = _commandGate.Authorize(envelope, DateTimeOffset.UtcNow, Shared.Security.SignedCommandClasses.SessionInitiation);
            if (!verdict.Allowed)
                return Task.FromResult(ToolResult.Error("signed_command_refused", verdict.Reason));
            if (verdict.Payload is null)
                return Task.FromResult(ToolResult.Error("signed_command_refused", "signed verdict carried no payload — refused"));
            var expected = System.Text.Encoding.UTF8.GetBytes($"session_start|{ctx.Pairing.Id}");
            if (!verdict.Payload.AsSpan().SequenceEqual(expected))
                return Task.FromResult(ToolResult.Error("signed_command_refused",
                    "signed session-initiation payload does not name this pairing — refused (an envelope minted for another pairing/session opens nothing here)"));
        }
        var record = _sessions.Start(ctx.Pairing);
        if (record is null)
            return Task.FromResult(ToolResult.Error("session_active", "a session is already active; stop it before starting another"));
        _state.UpdateSession(s => s with { ActingAgentName = ctx.Pairing.AgentName, SessionStartedUtc = record.StartedUtc });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { session_id = record.Id, started_utc = record.StartedUtc, time_box_ends_utc = record.TimeBoxEndsUtc })));
    }
}

/// <summary>Census row 1: session_stop — the agent's final action of a
/// completed task (SPEC §7.8a). Presence clearing is the done signal.</summary>
public sealed class SessionStopModule : IToolModule
{
    private readonly SessionManager _sessions;
    private readonly CoreState _state;
    private readonly Ipc.AgentIpcServer? _ipc;

    /// <param name="ipc">U7: when wired, session end immediately
    /// orders the session agent to release any held key/button
    /// (the supervisor's presence push says the same thing a tick
    /// later; this is the immediate path). The release is
    /// consent-floor — it is not gated by this call's policy
    /// outcome, and a failed send never fails the stop.</param>
    public SessionStopModule(SessionManager sessions, CoreState state, Ipc.AgentIpcServer? ipc = null)
    { _sessions = sessions; _state = state; _ipc = ipc; }

    public ToolDescriptor Descriptor { get; } = new(
        "session_stop", "End the current session. Presence clears; if the agent unlocked this machine, it relocks (Phase 2 rule, DESIGN §5.4).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        // W12 / DS-P6-F7: session_stop is ownership-checked — a pairing
        // may end only its OWN session, never another pairing's.
        var live = _sessions.Current;
        if (live is null) return ToolResult.Success("no session was active");
        if (!string.Equals(live.PairingId, ctx.Pairing.Id, StringComparison.Ordinal))
            return ToolResult.Error("not_your_session", "the live session belongs to a different pairing — session_stop refuses (DS-P6-F7)");
        if (!_sessions.TryStopForPairing(ctx.Pairing.Id, out var ended) || ended is null)
            return ToolResult.Success("no session was active");
        _state.UpdateSession(s => s with { ActingAgentName = null, SessionStartedUtc = null });
        var relocked = false;
        if (_ipc is not null)
        {
            try
            {
                await _ipc.NotifyAgentAsync(new Shared.Ipc.IpcMessage(Shared.Ipc.IpcKinds.ReleaseInputs, null, null, null, null, null, null, null, null, null), ct);
            }
            catch { /* the stop stands; the presence push + the agent's own triggers remain as backstops */ }
            // W12 / DS-P6-F3: the Phase 2 rule this tool's own
            // descriptor states — a session that unlocked this machine
            // relocks it when it ends. The unlock path binds the flag
            // (UnlockService starts the session agentUnlocked: true);
            // session_stop now honours it instead of leaving the
            // workstation unlocked until someone calls session_relock.
            if (ended.AgentUnlockedThisSession)
            {
                try { await _ipc.CallDesktopToolAsync("session_lock", "{}", ct); relocked = true; }
                catch { /* the stop stands; session_relock remains as the manual path */ }
            }
        }
        return ToolResult.Success($"session {ended.Id} ended after {(DateTimeOffset.UtcNow - ended.StartedUtc).TotalSeconds:F0}s" +
            (ended.AgentUnlockedThisSession ? (relocked ? "; workstation relocked (this session unlocked it)" : "; relock ordered but unconfirmed — session_relock remains available") : ""));
    }
}

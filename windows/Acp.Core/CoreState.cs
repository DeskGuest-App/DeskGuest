using System.Threading;
using Acp.Shared.Connection;
using Acp.Shared.Heartbeat;
using Acp.Shared.State;

namespace Acp.Core;

/// <summary>
/// The Core's central state store: component health, session facts, lane
/// states, and the §4.1 endpoint state computed from them. Every answer
/// the endpoint gives about itself comes from here, so state can never
/// disagree between tools, heartbeat, and self-check.
/// </summary>
public sealed class CoreState
{
    private readonly object _gate = new();
    private SessionFacts _session = SessionFactsExtensions.None;
    private bool _stopFilePresent;
    private bool _userStop;
    private bool _coreHealthy = true;
    private string? _lastWord;
    private PreviousRunInfo? _previousRun;
    private int _coreCrashCount;
    private int _agentCrashCount;
    private bool _pendingReboot;

    // The version is the ASSEMBLY's, never a hand-typed literal
    // (Block H: this field defaulted to "0.1.0" forever, so MCP
    // serverInfo, system info, and the self-check all reported a
    // version the product had long outgrown).
    public string CoreVersion { get; set; } =
        typeof(CoreState).Assembly.GetName().Version?.ToString() ?? "unknown";
    public string AgentVersion { get; set; } = "unknown";
    public LaneSupervisor? Lanes { get; set; }

    public SessionFacts Session { get { lock (_gate) return _session; } }

    public void UpdateSession(Func<SessionFacts, SessionFacts> mutate)
    {
        lock (_gate) _session = mutate(_session) with { StopInForce = _stopFilePresent || _session.StopInForce };
    }

    /// <summary>Apply a session-state report from the session agent
    /// (IPC session_state / hello): lock state, takeover, and the
    /// protected-targets foreground feed (M5). Null fields keep the
    /// current fact — an agent report can only refine what it knows.</summary>
    public void ApplyAgentSessionReport(bool? desktopUnlocked, bool? takeoverActive, string? foregroundTitle, string? foregroundProcess)
    {
        UpdateSession(s => s with
        {
            SessionExists = true,
            DesktopUnlocked = desktopUnlocked ?? s.DesktopUnlocked,
            TakeoverActive = takeoverActive ?? s.TakeoverActive,
            ForegroundTitle = foregroundTitle ?? s.ForegroundTitle,
            ForegroundProcess = foregroundProcess ?? s.ForegroundProcess
        });
    }

    public void SetStopFilePresent(bool present)
    {
        lock (_gate)
        {
            _stopFilePresent = present;
            _session = _session with { StopInForce = present || _userStop };
        }
    }

    /// <summary>The owner pressed STOP on the laptop itself (DESIGN §6.6, switch 1).</summary>
    public void SetUserStop(bool stopped)
    {
        lock (_gate)
        {
            _userStop = stopped;
            _session = _session with { StopInForce = stopped || _stopFilePresent };
        }
    }

    private string? _lastNarration;

    /// <summary>The last narration line an agent set through
    /// presence_control — the mesh heartbeat's "intent" field (M2).
    /// The Core is the only side both the narration and the phone
    /// poll can reach.</summary>
    public string? LastNarration
    {
        get { lock (_gate) return _lastNarration; }
        set { lock (_gate) _lastNarration = value; }
    }

    public bool StopInForce { get { lock (_gate) return _session.StopInForce; } }
    public void SetLastWord(string? word) { lock (_gate) _lastWord = word; }
    public void SetPreviousRun(PreviousRunInfo? info) { lock (_gate) _previousRun = info; }
    public void RecordAgentCrash() { lock (_gate) _agentCrashCount++; }

    private long _auditWriteFailures;
    public long AuditWriteFailures => Interlocked.Read(ref _auditWriteFailures);
    public void NoteAuditWriteFailure() => Interlocked.Increment(ref _auditWriteFailures);
    public void SetPendingReboot(bool value) { lock (_gate) _pendingReboot = value; }

    /// <summary>Compute the §4.1 state from current facts. Order matters:
    /// deliberate stop outranks everything; then component death; then the
    /// tailnet characterization; then session states.</summary>
    public EndpointState ComputeState()
    {
        lock (_gate)
        {
            if (_stopFilePresent || _userStop) return EndpointState.StoppedByUser;
            if (!_coreHealthy) return EndpointState.CoreDead;
            var s = _session;
            if (s.SessionExists && !s.AgentConnected) return EndpointState.AgentDead;
            if (Lanes is not null && Lanes.TailscaleUnavailable && !s.SessionExists)
                return EndpointState.TailscaleDown;
            if (!s.SessionExists) return EndpointState.BootNoLogon;
            if (!s.DesktopUnlocked) return EndpointState.LogonLocked;
            return EndpointState.LogonUnlocked;
        }
    }

    public EndpointStateReport BuildReport(IReadOnlyList<SubsystemHealth> subsystems)
    {
        lock (_gate)
        {
            return new EndpointStateReport(
                ComputeState(), DateTimeOffset.UtcNow, CoreVersion, subsystems, _session, _lastWord, _previousRun);
        }
    }

    public HeartbeatReport BuildHeartbeat()
    {
        lock (_gate)
        {
            return new HeartbeatReport(
                DateTimeOffset.UtcNow, ComputeState(), CoreVersion, AgentVersion,
                TailscaleBound: Lanes?.Status(LaneKind.Tailscale).Phase == LanePhase.Bound,
                LanBound: Lanes?.Status(LaneKind.Lan).Phase == LanePhase.Bound,
                AgentConnected: _session.AgentConnected,
                PendingReboot: _pendingReboot,
                CoreCrashCount: _coreCrashCount,
                AgentCrashCount: _agentCrashCount,
                PreviousRun: _previousRun);
        }
    }
}

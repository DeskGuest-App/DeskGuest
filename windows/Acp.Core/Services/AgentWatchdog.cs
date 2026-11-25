using Acp.Shared.Audit;
using Acp.Core.Platform;

namespace Acp.Core.Services;

/// <summary>Liveness facts the watchdog decides on (the IPC server implements this).</summary>
public interface IAgentLiveness
{
    bool AgentConnected { get; }
    DateTimeOffset LastAgentHeartbeatUtc { get; }
}

/// <summary>
/// Core → Agent half of the mutual watchdog (DESIGN §3.4): if the
/// Agent's heartbeat goes stale, the Core relaunches it with
/// backoff. Repeated failure is reported as AGENT_DEAD, never
/// retried forever in silence. The Agent → Core half is the installer's
/// service ACL + SCM recovery (the Agent can restart a hung Core);
/// that half is Windows-runtime behaviour, UNPROVEN-ON-WINDOWS here.
///
/// W20 (W19 diagnosis, Defect B deadlock): the pre-fix Tick returned
/// early whenever NO session existed — but SessionExists is set only
/// by an authenticated agent's report, and the watchdog's relaunch
/// was the one path that could deliver the IPC token to an agent.
/// No session ⟹ no relaunch ⟹ no token ⟹ no session. The gate is
/// REMOVED, not merely bypassed by the W20 token file: the file
/// channel makes a task-launched agent able to authenticate, but a
/// crashed agent in a not-yet-reported session still needs a
/// relaunch path that does not depend on the state the relaunch
/// itself creates. Pre-session launch failures (there may be no
/// console session to launch INTO yet) do not count toward
/// exhaustion — the books reset when a session first appears, as
/// they always did for a new session.
/// </summary>
public sealed class AgentWatchdog
{
    private readonly CoreState _state;
    private readonly IAgentLiveness _liveness;
    private readonly IAgentLauncher _launcher;
    private readonly IAuditLog _audit;
    private readonly string _agentExePath;

    public TimeSpan StaleAfter { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan BaseBackoff { get; set; } = TimeSpan.FromSeconds(15);
    public int MaxConsecutiveFailures { get; set; } = 5;

    private DateTimeOffset _lastLaunchAttemptUtc = DateTimeOffset.MinValue;
    private int _launchAttempts;
    private bool _sawSession;
    private int _consecutiveFailures;
    private bool _wasConnected;

    public AgentWatchdog(CoreState state, IAgentLiveness liveness, IAgentLauncher launcher, IAuditLog audit, string agentExePath)
    {
        _state = state;
        _liveness = liveness;
        _launcher = launcher;
        _audit = audit;
        _agentExePath = agentExePath;
    }

    public int ConsecutiveFailures => _consecutiveFailures;
    public bool Exhausted => _consecutiveFailures >= MaxConsecutiveFailures;

    /// <summary>One supervision decision. Returns a description when it acted.</summary>
    public string? Tick(DateTimeOffset now)
    {
        var connected = _liveness.AgentConnected;
        if (connected)
        {
            if (!_wasConnected && _consecutiveFailures > 0)
            {
                _audit.Append(new AuditEntry(now, "supervision", null, null, null, null, null, "agent_recovered", null, null));
                _consecutiveFailures = 0;
            }
            _launchAttempts = 0;
            _wasConnected = true;
            return null;
        }

        var session = _state.Session;
        // W20: NO SessionExists gate (see class summary — the gate
        // was one half of the AgentConnected deadlock). The new-
        // session book reset still happens on the session's first
        // appearance; without a session the watchdog still attempts
        // launches under the same backoff, but pre-session failures
        // never exhaust it (below).
        if (!session.SessionExists) { _wasConnected = false; _sawSession = false; }
        else if (!_sawSession)
        {
            // A NEW logon session resets the books (M2): failures from a
            // previous session must not leave this one un-watched.
            _sawSession = true;
            _consecutiveFailures = 0;
            _launchAttempts = 0;
        }

        var stale = _liveness.LastAgentHeartbeatUtc == DateTimeOffset.MinValue ||
                    now - _liveness.LastAgentHeartbeatUtc > StaleAfter;
        if (!stale) return null;

        if (_wasConnected)
        {
            _wasConnected = false;
            _state.RecordAgentCrash();
            _audit.Append(new AuditEntry(now, "supervision", null, null, null, null, null, "agent_died", null, null));
        }

        if (Exhausted)
            return null; // AGENT_DEAD is reported via state; no silent infinite retry.

        var backoff = TimeSpan.FromSeconds(BaseBackoff.TotalSeconds * Math.Pow(2, Math.Min(_launchAttempts, 4)));
        if (now - _lastLaunchAttemptUtc < backoff) return null;

        _lastLaunchAttemptUtc = now;
        _launchAttempts++;
        bool launched;
        try { launched = _launcher.Launch(_agentExePath); }
        catch { launched = false; } // a throwing launcher is a failed launch, not a supervisor error (M2)
        // Only FAILED launches count toward exhaustion (M2): a launch
        // that succeeded but whose agent is slow to connect must not
        // march the watchdog to AGENT_DEAD while the agent is coming up.
        // W20: a failed launch while NO session exists does not count
        // either — there may be no console session to launch into
        // yet, and that absence must not spend the exhaustion budget
        // the real session will need.
        if (!launched && session.SessionExists) _consecutiveFailures++;
        _audit.Append(new AuditEntry(now, "supervision", null, null, null, null, null,
            launched ? "agent_relaunch_attempted" : "agent_relaunch_failed", null, null));
        return launched ? "agent_relaunch_attempted" : "agent_relaunch_failed";
    }
}

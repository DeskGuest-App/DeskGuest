namespace DeskGuest.Shared.State;

/// <summary>
/// The DESIGN §4.1 endpoint state vocabulary. The endpoint is always in
/// exactly one named state; every tool response and heartbeat carries it.
/// This replaces "down" forever.
/// </summary>
public enum EndpointState
{
    BootNoLogon,      // Windows up, nobody logged on. Command plane up.
    LogonUnlocked,    // Session exists, desktop open. Both planes up.
    LogonLocked,      // Session exists, secure desktop showing. Command plane up.
    Unlocking,        // An approved unlock is in flight (Phase 2 module).
    Asleep,           // Last-word state before suspend.
    TailscaleDown,    // Machine fine; the tailnet path is not (yet).
    CoreDead,         // Core failed; supervision is working on it.
    AgentDead,        // Session Agent failed; supervision is working on it.
    StoppedByUser,    // A kill switch is in force. Deliberate.
    Off               // No heartbeat, no last word: power/network-loss class.
}

/// <summary>Health of one subsystem, report-card style (DESIGN §4.5).</summary>
public enum HealthLevel { Green, Amber, Red }

public sealed record SubsystemHealth(string Name, HealthLevel Level, string Reason);

/// <summary>Session-plane facts the policy engine and state model need.
/// ForegroundTitle/ForegroundProcess are the protected-targets feed
/// (DESIGN §6.5, inspector M5): the session agent reports the current
/// foreground window's title and owning process; the policy engine
/// matches them against the owner's protected-targets set.</summary>
public sealed record SessionFacts(
    bool SessionExists,
    bool DesktopUnlocked,
    bool AgentConnected,
    bool AgentElevated,
    string? ActingAgentName,
    DateTimeOffset? SessionStartedUtc,
    bool StopInForce,
    bool TakeoverActive,
    string? ForegroundTitle = null,
    string? ForegroundProcess = null);

public static class SessionFactsExtensions
{
    public static readonly SessionFacts None = new(false, false, false, false, null, null, false, false);
}

/// <summary>A full endpoint state report: the §4.1 state plus its evidence.</summary>
public sealed record EndpointStateReport(
    EndpointState State,
    DateTimeOffset AtUtc,
    string CoreVersion,
    IReadOnlyList<SubsystemHealth> Subsystems,
    SessionFacts Session,
    string? LastWord,
    PreviousRunInfo? PreviousRun);

/// <summary>Post-mortem characterization of the previous Core run (DESIGN §4.4).</summary>
public sealed record PreviousRunInfo(
    bool EndedCleanly,
    EndpointState? LastState,
    DateTimeOffset? LastSeenUtc,
    string Characterization);

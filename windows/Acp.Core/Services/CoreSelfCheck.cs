using Acp.Core.Ipc;
using Acp.Core.Platform;
using Acp.Shared.Audit;
using Acp.Shared.Connection;
using Acp.Shared.Security;
using Acp.Shared.State;

namespace Acp.Core.Services;

/// <summary>Builds the §4.5 report card from observed subsystem state.</summary>
public sealed class CoreSelfCheck
{
    private readonly CoreState _state;
    private readonly FileAuditLog _audit;
    private readonly PairingService _pairings;
    private readonly IFactChecks _factChecks;
    private readonly IAgentChannel _agentChannel;

    public CoreSelfCheck(CoreState state, FileAuditLog audit, PairingService pairings, IFactChecks factChecks, IAgentChannel agentChannel)
    {
        _state = state;
        _audit = audit;
        _pairings = pairings;
        _factChecks = factChecks;
        _agentChannel = agentChannel;
    }

    public async Task<IReadOnlyList<SubsystemHealth>> BuildAsync(CancellationToken ct)
    {
        var list = new List<SubsystemHealth>
        {
            new("core", HealthLevel.Green, $"ACP Core {_state.CoreVersion} running; endpoint state {_state.ComputeState()}")
        };

        // Audit log: proven by a write test, not assumed.
        list.Add(_audit.WriteTest()
            ? new SubsystemHealth("audit_log", HealthLevel.Green, "host-side audit log append + read-back verified")
            : new SubsystemHealth("audit_log", HealthLevel.Red, "audit log write test FAILED"));

        // Token store protection.
        var protector = _pairings.Protector;
        if (protector.IsRealProtection)
            list.Add(new("token_store", HealthLevel.Green, $"pairing tokens protected at rest ({protector.Name})"));
        else if (OperatingSystem.IsWindows())
            list.Add(new("token_store", HealthLevel.Red, $"token store is NOT protected ({protector.Name}) on a Windows host — release blocker"));
        else
            list.Add(new("token_store", HealthLevel.Amber, $"dev protector ({protector.Name}) on a non-Windows build host; DPAPI engages on Windows"));

        // Lanes.
        if (_state.Lanes is { } lanes)
        {
            foreach (var lane in new[] { LaneKind.Tailscale, LaneKind.Lan })
            {
                var s = lanes.Status(lane);
                list.Add(new SubsystemHealth($"listener_{lane.ToString().ToLowerInvariant()}",
                    s.Phase == LanePhase.Bound ? HealthLevel.Green : HealthLevel.Amber,
                    s.Phase == LanePhase.Bound ? $"bound on {s.Address}" : $"phase {s.Phase} — a missing address is a state, retried forever, never an exit (DESIGN §4.2)"));
            }
        }

        // Session agent.
        var session = _state.Session;
        if (_agentChannel.AgentConnected)
            list.Add(new("session_agent", HealthLevel.Green, $"connected (v{_state.AgentVersion}); desktop {(session.DesktopUnlocked ? "unlocked" : "locked — desktop tools report unavailable")}"));
        else if (session.SessionExists)
            list.Add(new("session_agent", HealthLevel.Red, "a session exists but the agent is not connected; the watchdog is on it"));
        else
            list.Add(new("session_agent", HealthLevel.Amber, "no interactive session (BOOT_NO_LOGON): command plane only, by design"));

        // Kill switch state, said out loud.
        list.Add(_state.StopInForce
            ? new SubsystemHealth("kill_switches", HealthLevel.Amber, "STOP is in force: all sessions blocked until the owner clears it")
            : new SubsystemHealth("kill_switches", HealthLevel.Green, "no kill switch in force"));

        // Pairings.
        list.Add(new("pairings", HealthLevel.Green, $"{_pairings.List().Count(p => !p.Revoked)} active pairing(s)"));

        // Fact checks (edition / BitLocker / Hello-only).
        var facts = await _factChecks.RunAsync(ct);
        list.Add(facts.WindowsEdition);
        list.Add(facts.BitLocker);
        list.Add(facts.HelloOnlyMode);

        return list;
    }
}

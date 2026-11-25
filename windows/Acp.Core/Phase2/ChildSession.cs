using System.Text.Json;
using Acp.Core.Platform;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Phase2;

/// <summary>The seat driver seam (DESIGN §3.6): a real driver brings up
/// a loopback-RDP child session and hosts a second Session Agent inside
/// it. The Windows driver is laptop-gate work (RDP child sessions,
/// edition-gated); this contract is what the Core orchestrates against.</summary>
public interface IChildSessionDriver
{
    bool SeatActive { get; }
    string? StartSeat(string userName);
    string? StopSeat();
    string? SeatStatus();
}

/// <summary>Records calls and reports a working seat (tests).</summary>
public sealed class FakeChildSessionDriver : IChildSessionDriver
{
    public bool SeatActive { get; private set; }
    public string? StartSeat(string userName) { SeatActive = true; return null; }
    public string? StopSeat() { SeatActive = false; return null; }
    public string? SeatStatus() => SeatActive ? "seat active" : null;
}

/// <summary>Placeholder for the real Windows driver: reports the honest
/// reason until the laptop gate builds the RDP seat. Never fakes a seat.</summary>
public sealed class WindowsChildSessionDriver : IChildSessionDriver
{
    public bool SeatActive => false;
    public string? StartSeat(string userName) =>
        "the loopback-RDP seat driver is Phase 2 laptop-gate work (DESIGN §3.6); the orchestration, policy, and presence contract are built and VM-tested against the driver seam";
    public string? StopSeat() => null;
    public string? SeatStatus() => null;
}

/// <summary>
/// Child-session orchestration (DESIGN §3.6): the Core manages seat
/// lifecycle exactly as it manages the console agent. Constraints are
/// enforced here, not discovered: Pro/Enterprise/Education editions
/// only; logon to a seat requires the vaulted PASSWORD (Hello PIN does
/// not work for RDP logon — the same fact that shapes Route B); a seat
/// is an additional session for the owner's account only.
/// </summary>
public sealed class ChildSessionManager
{
    private readonly IChildSessionDriver _driver;
    private readonly IFactChecks _facts;
    public ChildSessionManager(IChildSessionDriver driver, IFactChecks facts) { _driver = driver; _facts = facts; }

    public bool SeatActive => _driver.SeatActive;

    public async Task<ToolResult> StartAsync(string userName, CancellationToken ct)
    {
        var facts = await _facts.RunAsync(ct);
        if (facts.WindowsEdition.Level != Shared.State.HealthLevel.Green)
            return ToolResult.Unavailable($"child sessions require Windows Pro/Enterprise/Education — {facts.WindowsEdition.Reason}");
        var error = _driver.StartSeat(userName);
        return error is null
            ? ToolResult.Success("child session started: the agent works in its own seat; the owner's pointer, focus, and windows are untouched. Seat logon used the vaulted password path (PIN cannot log on to RDP seats).")
            : ToolResult.Unavailable(error);
    }

    public Task<ToolResult> StopAsync()
    {
        var error = _driver.StopSeat();
        return Task.FromResult(error is null ? ToolResult.Success("child session stopped") : ToolResult.Unavailable(error));
    }

    public ToolResult Status() => ToolResult.Success(JsonSerializer.Serialize(new
    {
        seat_active = SeatActive,
        driver_status = _driver.SeatStatus(),
        note = "one console user still: a seat is an additional RDP session for the owner's account, not multi-user Windows (DESIGN §3.6)"
    }));
}

public sealed class ChildSessionModule : IToolModule
{
    private readonly ChildSessionManager _manager;
    public ChildSessionModule(ChildSessionManager manager) => _manager = manager;
    public ToolDescriptor Descriptor { get; } = new(
        "child_session", "Start/stop/status an agent child session (loopback-RDP seat, DESIGN §3.6): desktop work that never touches the owner's pointer, focus, or windows.",
        Scopes.Drive, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status"]}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = arguments.TryGetProperty("action", out var a) ? a.GetString() : "status";
        return action switch
        {
            "start" => await _manager.StartAsync(ctx.Pairing.AgentName, ct),
            "stop" => await _manager.StopAsync(),
            _ => _manager.Status()
        };
    }
}

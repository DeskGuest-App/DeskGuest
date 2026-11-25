using Acp.Core;
using Acp.Core.Platform;
using Acp.Core.Services;
using Acp.Shared.Audit;
using Acp.Shared.Connection;
using Acp.Shared.Security;
using Acp.Shared.State;

namespace Acp.Tests;

public sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
    public void Advance(TimeSpan by) => UtcNow += by;
}

public sealed class FakeProbe : ILaneAddressProbe
{
    public Func<LaneKind, string?> Handler { get; set; } = _ => null;
    public string? ProbeAddress(LaneKind lane) => Handler(lane);
}

public sealed class FakeRunner : IProcessRunner
{
    public List<(string File, string Args)> Calls { get; } = new();
    public Func<string, string, ProcessResult> Handler { get; set; } = (_, _) => new ProcessResult(0, "", "", false);
    public Task<ProcessResult> RunAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
    {
        Calls.Add((fileName, arguments));
        return Task.FromResult(Handler(fileName, arguments));
    }
}

public sealed class FakeFactChecks : IFactChecks
{
    public FactCheckReport Report { get; set; } = new(
        new SubsystemHealth("edition", HealthLevel.Green, "Windows 11 Pro"),
        new SubsystemHealth("bitlocker", HealthLevel.Green, "on, TPM"),
        new SubsystemHealth("hello", HealthLevel.Green, "Hello-only sign-in mode is OFF"));
    public Task<FactCheckReport> RunAsync(CancellationToken ct) => Task.FromResult(Report);
}

public sealed class FakeLiveness : IAgentLiveness
{
    public bool AgentConnected { get; set; }
    public DateTimeOffset LastAgentHeartbeatUtc { get; set; } = DateTimeOffset.MinValue;
}

public sealed class RecordingLauncher : IAgentLauncher
{
    public int Launches { get; private set; }
    public bool Result { get; set; } = true;
    public bool Launch(string agentExePath) { Launches++; return Result; }
}

public static class TestUtil
{
    public static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "acp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static (PairingService Service, Pairing Pairing, string Token) MakePairing(IReadOnlySet<string> scopes)
    {
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("test-agent", TimeSpan.FromMinutes(5), scopes);
        var exchange = svc.ExchangeCode(code, "test-agent");
        Assert.NotNull(exchange);
        var pairing = svc.List().Single(p => p.Id == exchange!.PairingId);
        return (svc, pairing, exchange.BearerToken);
    }

    public static Pairing BarePairing(IReadOnlySet<string> scopes, string id = "p1") =>
        new(id, "test-agent", scopes, DateTimeOffset.UtcNow, null, null, false);

    public static SessionFacts Session(bool exists = true, bool unlocked = true, bool agent = true, bool stop = false, bool takeover = false) =>
        new(exists, unlocked, agent, false, "test-agent", DateTimeOffset.UtcNow, stop, takeover);

    public static EndpointState State() => new CoreState().ComputeState();

    public static FileAuditLog AuditLog(string dir) => new(Path.Combine(dir, "audit.jsonl"));
}

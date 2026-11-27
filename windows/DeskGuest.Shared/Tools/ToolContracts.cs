using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.State;

namespace DeskGuest.Shared.Tools;

/// <summary>A tool module's declaration (DESIGN §7.1): operations, required
/// scope, session requirement, risk tier, gate class. The capability report
/// is computed from (modules present × pairing scopes × endpoint state).</summary>
public sealed record ToolDescriptor(
    string Name,
    string Description,
    string RequiredScope,
    SessionRequirement Session,
    RiskTier Risk,
    string? GateClass = null,
    string ExecutionContext = "Core",
    string InputSchemaJson = """{"type":"object","properties":{}}""");

/// <summary>What a tool returns. Unavailable is a first-class, honest result:
/// a host never fakes a capability (SPEC §6, FEATURES §13).</summary>
public sealed record ToolResult(bool Ok, string? Text, string? UnavailableReason = null, string? ErrorClass = null)
{
    public static ToolResult Success(string text) => new(true, text);
    public static ToolResult Unavailable(string reason) => new(false, null, UnavailableReason: reason);
    public static ToolResult Error(string errorClass, string message) => new(false, message, ErrorClass: errorClass);
}

/// <summary>Everything an execution needs, assembled by the policy choke point.</summary>
public sealed record ToolExecutionContext(
    Pairing Pairing,
    SessionFacts Session,
    EndpointState EndpointState,
    IReadOnlySet<string> ApprovedGateClasses,
    string DataDir);

public interface IToolModule
{
    ToolDescriptor Descriptor { get; }
    Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct);
}

/// <summary>Registry of tool modules. Registration order is stable so
/// tools/list output is deterministic.</summary>
public sealed class ToolRegistry
{
    private readonly Dictionary<string, IToolModule> _modules = new();
    private readonly List<string> _order = new();

    public void Register(IToolModule module)
    {
        if (_modules.ContainsKey(module.Descriptor.Name))
            throw new InvalidOperationException($"Duplicate tool module: {module.Descriptor.Name}");
        _modules[module.Descriptor.Name] = module;
        _order.Add(module.Descriptor.Name);
    }

    public IToolModule? Find(string name) => _modules.GetValueOrDefault(name);
    public IReadOnlyList<ToolDescriptor> Descriptors =>
        _order.Select(n => _modules[n].Descriptor).ToList();

    /// <summary>The per-agent capability report (SPEC §6): for every tool,
    /// whether THIS pairing may call it right now, and why not if not.</summary>
    public IReadOnlyList<CapabilityLine> CapabilityReport(Pairing pairing, SessionFacts session, EndpointState state)
    {
        var lines = new List<CapabilityLine>();
        foreach (var d in Descriptors)
        {
            string? whyNot = null;
            // BD-SHARED-SESSION F10: the report claims "right now" —
            // STOP in force and a user-stopped endpoint make EVERY
            // tool unavailable, whatever the scopes say.
            if (session.StopInForce)
                whyNot = "STOP is in force — no tool is available until the person at the machine clears it";
            else if (state == EndpointState.StoppedByUser)
                whyNot = "endpoint is stopped by the user (kill switch in force)";
            else if (!pairing.Scopes.Contains(d.RequiredScope))
                whyNot = $"pairing lacks scope '{d.RequiredScope}'";
            else if (d.GateClass is not null)
                whyNot = $"gate class '{d.GateClass}' requires approval at call time — availability is decided by the gate, not pre-granted";
            else if (d.Session == SessionRequirement.Agent && !session.AgentConnected)
                whyNot = "session agent not connected (no interactive session)";
            else if (d.Session == SessionRequirement.Agent && session.SessionExists && !session.DesktopUnlocked)
                whyNot = "desktop is locked (secure desktop); reported, never faked";
            lines.Add(new CapabilityLine(d.Name, whyNot is null, whyNot, state.ToString()));
        }
        return lines;
    }
}

public sealed record CapabilityLine(string Tool, bool Available, string? WhyNot, string EndpointState);

using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.State;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>Census row 2: the §4.1 state model as a queryable report.</summary>
public sealed class EndpointStateModule : IToolModule
{
    private readonly CoreState _state;
    private readonly Func<CancellationToken, Task<IReadOnlyList<SubsystemHealth>>> _selfCheck;

    public EndpointStateModule(CoreState state, Func<CancellationToken, Task<IReadOnlyList<SubsystemHealth>>> selfCheck)
    {
        _state = state;
        _selfCheck = selfCheck;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "endpoint_state", "The endpoint's current state (DESIGN §4.1 vocabulary), component health, and session facts.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var subsystems = await _selfCheck(ct);
        var report = _state.BuildReport(subsystems);
        return ToolResult.Success(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>Census row 58: the report card — every subsystem green/amber/red
/// with plain-language reasons. Nothing is claimed working that the
/// self-check did not observe working (DESIGN §4.5).</summary>
public sealed class SelfCheckModule : IToolModule
{
    private readonly Func<CancellationToken, Task<IReadOnlyList<SubsystemHealth>>> _selfCheck;
    public SelfCheckModule(Func<CancellationToken, Task<IReadOnlyList<SubsystemHealth>>> selfCheck) => _selfCheck = selfCheck;

    public ToolDescriptor Descriptor { get; } = new(
        "self_check", "Report card for every subsystem: green/amber/red with plain-language reasons.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var subsystems = await _selfCheck(ct);
        return ToolResult.Success(JsonSerializer.Serialize(subsystems, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>Census row 85 (partial, Phase 0): component versions.</summary>
public sealed class AgentVersionModule : IToolModule
{
    private readonly CoreState _state;
    public AgentVersionModule(CoreState state) => _state = state;

    public ToolDescriptor Descriptor { get; } = new(
        "agent_version", "Component versions of the DeskGuest-Windows host.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            core = _state.CoreVersion,
            agent = _state.AgentVersion,
            contract = "DeskGuest shared contract (SPEC §2/§6)"
        })));
}

/// <summary>Census row 1 (status half): session state for the calling pairing.</summary>
public sealed class SessionStatusModule : IToolModule
{
    private readonly SessionManager _sessions;
    private readonly Func<IReadOnlyList<Services.HumanSessionFact>>? _humanSessions;
    private readonly Func<SessionBudgetSnapshot?>? _budget;
    private readonly Func<DataFlowReport?>? _dataFlows;

    public SessionStatusModule(SessionManager sessions,
        Func<IReadOnlyList<Services.HumanSessionFact>>? humanSessions = null,
        Func<SessionBudgetSnapshot?>? budget = null,
        Func<DataFlowReport?>? dataFlows = null)
    {
        _sessions = sessions;
        _humanSessions = humanSessions;
        _budget = budget;
        _dataFlows = dataFlows;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "session_status", "Presence state, elapsed time, acting agent, and scope in force for the current session. Agent (MCP) sessions and Slice 3 human sessions are reported in one picture.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var session = _sessions.Current;
        var humans = _humanSessions?.Invoke() ?? Array.Empty<Services.HumanSessionFact>();
        var humanLive = humans.FirstOrDefault(h => h.State is "active" or "paused" or "blocked");
        var humanShape = humans.Select(h => new
        {
            id = h.Id, initiator = h.InitiatorName, kind = h.Kind, state = h.State,
            seconds = h.Seconds, recording = h.Recording, isRecording = h.IsRecording,
            floorHolder = h.FloorHolderName, participants = h.ParticipantCount,
            // U5: file bytes moved in this session + their target devices.
            bytesIn = h.BytesIn, bytesOut = h.BytesOut,
            destinations = (h.Destinations ?? Array.Empty<string>()).ToArray(),
        }).ToArray();
        // U5: the per-agent data-flow view — flows by agent, class
        // and volume, cross-checked against the audit; gaps are
        // reported as gaps inside the report itself. DESTRUCTION
        // BOUNDARY: this tool is callable by ANY paired agent, so
        // it only ever shows the CALLING pairing's own flows (and
        // the gaps that name it) — one pairing's volumes and
        // destinations never leak to another through this surface.
        // The full multi-agent view is owner-only: it rides the
        // host-state snapshot the owner's own window reads.
        var flowReport = _dataFlows?.Invoke();
        var flowShape = flowReport is null ? null : new
        {
            scope = "calling pairing only",
            agents = flowReport.Agents
                .Where(a => string.Equals(a.PairingId, ctx.Pairing.Id, StringComparison.Ordinal))
                .Select(a => new
                {
                    pairingId = a.PairingId, agentName = a.AgentName, sessions = a.SessionCount,
                    bytesIn = a.BytesIn, bytesOut = a.BytesOut, byClass = a.ByClass,
                    tools = a.Tools, destinations = a.Destinations,
                }).ToArray(),
            humanFlows = flowReport.HumanFlows.Select(h => new
            {
                sessionId = h.SessionId, bytesIn = h.BytesIn, bytesOut = h.BytesOut,
                destinations = h.Destinations,
            }).ToArray(),
            gaps = flowReport.Gaps
                .Where(g => g.Contains(ctx.Pairing.Id, StringComparison.Ordinal))
                .ToArray(),
        };
        if (session is null && humanLive is null)
            return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
            {
                active = false,
                humanSessions = humanShape,
                dataFlows = flowShape,
            })));
        if (session is null)
            return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
            {
                active = true,
                source = "human",
                ActorAgentName = humanLive!.InitiatorName,
                startedUtc = humanLive.StartedUtc,
                elapsedSeconds = (double)humanLive.Seconds,
                humanSessions = humanShape,
                dataFlows = flowShape,
            })));
        // U4: owner-visible budget state — caps, counts, and the
        // tripwire pause state ride the existing status surface.
        var budgetSnap = _budget?.Invoke();
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            active = true,
            source = "agent",
            session.ActorAgentName,
            startedUtc = session.StartedUtc,
            elapsedSeconds = (DateTimeOffset.UtcNow - session.StartedUtc).TotalSeconds,
            scopesInForce = session.ScopesInForce.ToArray(),
            paused = _sessions.IsPaused,
            pauseReason = _sessions.PauseReason,
            budget = budgetSnap is null ? null : new
            {
                caps = budgetSnap.Caps,
                counts = budgetSnap.Counts,
            },
            humanSessions = humanShape,
            dataFlows = flowShape,
        })));
    }
}

/// <summary>Census row 83: read the host audit log (admin scope). There is
/// no agent path to alter or delete entries — this module only reads.</summary>
public sealed class AuditLogReadModule : IToolModule
{
    private readonly IAuditLog _audit;
    public AuditLogReadModule(IAuditLog audit) => _audit = audit;

    public ToolDescriptor Descriptor { get; } = new(
        "audit_log_read", "Read the tail of the host-side audit log. Read-only by construction.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"max_entries":{"type":"integer","default":100}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var max = arguments.ValueKind == JsonValueKind.Object && arguments.TryGetProperty("max_entries", out var m)
            ? Math.Clamp(m.GetInt32(), 1, 1000) : 100;
        var entries = _audit.ReadTail(max);
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true })));
    }
}

/// <summary>Census row 88: list/revoke pairings (admin scope). Creation and
/// scope grants happen in the laptop UI only, never remotely.</summary>
public sealed class PairingAdminModule : IToolModule
{
    private readonly PairingService _pairings;
    private readonly SessionManager? _sessions;
    private readonly Action<SessionRecord>? _sessionEnded;

    /// <param name="sessions">U7: when wired, revoking the pairing
    /// that owns the live session ends that session in the same
    /// act — a revoked agent keeps neither the session nor any
    /// input it is holding.</param>
    /// <param name="sessionEnded">Called with the ended record so
    /// the runtime can audit, tear down forwards, and order the
    /// held-input release.</param>
    public PairingAdminModule(PairingService pairings, SessionManager? sessions = null, Action<SessionRecord>? sessionEnded = null,
        Action<string>? pairingRevoked = null)
    { _pairings = pairings; _sessions = sessions; _sessionEnded = sessionEnded; _pairingRevoked = pairingRevoked; }

    // BD-SUPP-EVENTSUB F4: fired on EVERY successful revoke, session
    // or not — the pre-fix wiring only cleared event subscriptions
    // when the revoked pairing owned the live session (the
    // sessionEnded callback), so an idle pairing's watch survived
    // its own revocation.
    private readonly Action<string>? _pairingRevoked;

    public ToolDescriptor Descriptor { get; } = new(
        "pairing_admin", "List pairings, or revoke one by id. Pairings are created on the laptop only.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","revoke"]},"pairing_id":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = arguments.ValueKind == JsonValueKind.Object && arguments.TryGetProperty("action", out var a) ? a.GetString() : "list";
        if (action == "revoke")
        {
            var id = arguments.TryGetProperty("pairing_id", out var p) ? p.GetString() : null;
            var ok = id is not null && _pairings.Revoke(id);
            if (ok) _pairingRevoked?.Invoke(id!);
            if (ok && _sessions?.Current is { } live && live.PairingId == id)
            {
                // U7: revocation mid-session ends the session NOW —
                // not "effective on its next call".
                var ended = _sessions.Stop();
                if (ended is not null) _sessionEnded?.Invoke(ended);
                return Task.FromResult(ToolResult.Success("pairing revoked; its live session was ended and held input released"));
            }
            return Task.FromResult(ok ? ToolResult.Success("pairing revoked; effective on its next call") : ToolResult.Error("not_found", "no such pairing"));
        }
        var list = _pairings.List().Select(p => new
        {
            p.Id, p.AgentName, Scopes = p.Scopes.ToArray(), p.CreatedUtc, p.ExpiresUtc, p.Revoked
        });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true })));
    }
}

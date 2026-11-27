using System.Text.Json;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;
using DeskGuest.Shared.Wake;

namespace DeskGuest.Core.Modules;

// =====================================================================
// Block G services — MCP exposure (Block H; the F7/G remainder:
// the services were Core-composed and snapshot-visible but no tool,
// IPC action, or panel could reach them).
//
// The adapter is THIN on purpose: every authorization rule lives
// in the services (roster liveness, "use" grants, policy toggles,
// the AI tunnel refusal) and is enforced there, per act. What the
// adapter adds is the ACTOR: an MCP caller's roster identity is
// the live AI user enrolled under the pairing's agent name in the
// named scope (D9 — a paired AI is a member with a leash). No
// matching roster member = refusal: a pairing alone is not a
// roster membership, and no tool here lets a caller name someone
// else's user id.
//
// Deliberately NOT exposed to MCP: tunnel open/close. A session
// tunnel is a human-session act whose service refuses AI actors
// outright (D38 F9) — shipping an MCP tool that can only ever
// refuse would be a dishonest surface. Tunnels are listed here
// (read) and closed from the host panel (device-side act).
// =====================================================================

internal static class BlockGActors
{
    /// <summary>Resolve the pairing's roster identity. The
    /// pairing's AgentName is host-bound at mint (PairingService,
    /// D38 fix F3), so matching it against roster AI users is
    /// matching a HOST-issued identity, not a client claim. The
    /// match must be UNIQUE (D38 fix F3, second half): duplicate
    /// display names resolve to NOBODY — a FirstOrDefault over
    /// duplicates would hand the caller an arbitrary user's
    /// grants.</summary>
    public static User? ResolveAiUser(RosterService roster, Pairing pairing, string scopeId)
    {
        var matches = roster.ListUsers(scopeId).Where(u =>
            string.Equals(u.Kind, "ai", StringComparison.OrdinalIgnoreCase) && !u.Suspended &&
            string.Equals(u.DisplayName, pairing.AgentName, StringComparison.OrdinalIgnoreCase)).ToList();
        return matches.Count == 1 ? matches[0] : null;
    }

    public static ToolResult NoMember(Pairing pairing, string scopeId) =>
        ToolResult.Error("no_roster_member",
            $"no live AI roster user named '{pairing.AgentName}' in scope '{scopeId}' — " +
            "an admin must enroll this agent as a roster member of the scope before it can act on the Block G services (D9)");
}

public sealed class WakeTargetsModule : IToolModule
{
    private readonly WakeService _wake;
    public WakeTargetsModule(WakeService wake) => _wake = wake;
    public ToolDescriptor Descriptor { get; } = new(
        "wake_targets", "List this host's registered Wake-on-LAN targets (device, MAC, broadcast). The registry is written only by company admins or the host itself — this tool only reads it.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var targets = _wake.ListTargets();
        if (targets.Count == 0) return Task.FromResult(ToolResult.Success("no wake targets registered on this host"));
        var lines = targets.Select(t => $"{t.DeviceId} · {t.MacAddress} · via {t.BroadcastAddress}" +
            (t.LastWakeUtc is { } w ? $" · last wake {w:u}" : ""));
        return Task.FromResult(ToolResult.Success(string.Join("\n", lines)));
    }
}

public sealed class WakeSendModule : IToolModule
{
    private readonly WakeService _wake;
    private readonly RosterService _roster;
    public WakeSendModule(WakeService wake, RosterService roster) { _wake = wake; _roster = roster; }
    public ToolDescriptor Descriptor { get; } = new(
        "wake_send", "Wake a device over the LAN (Wake-on-LAN). The target must be registered on this host; the caller must be a roster member of the scope holding the 'use' grant on the device's group, and policy must allow wake_on_lan for the scope.",
        Scopes.Drive, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"scopeId":{"type":"string"},"deviceId":{"type":"string"}},"required":["scopeId","deviceId"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var scopeId = FileArgs.Str(arguments, "scopeId") ?? "";
        var deviceId = FileArgs.Str(arguments, "deviceId") ?? "";
        var actor = BlockGActors.ResolveAiUser(_roster, ctx.Pairing, scopeId);
        if (actor is null) return Task.FromResult(BlockGActors.NoMember(ctx.Pairing, scopeId));
        var (sent, detail) = _wake.SendWake(deviceId, actor.Id);
        return Task.FromResult(sent ? ToolResult.Success(detail) : ToolResult.Error("refused", detail));
    }
}

public sealed class TransferStartModule : IToolModule
{
    private readonly StandaloneTransferService _transfers;
    private readonly RosterService _roster;
    public TransferStartModule(StandaloneTransferService transfers, RosterService roster) { _transfers = transfers; _roster = roster; }
    public ToolDescriptor Descriptor { get; } = new(
        "transfer_start", "Queue a standalone (session-less) file transfer job for a device. The job is a governed record: the service re-reads the caller's 'use' grant on every act, and the person at the device can stop it from the host panel at any time.",
        Scopes.Drive, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"scopeId":{"type":"string"},"deviceId":{"type":"string"},"direction":{"type":"string","enum":["to_host","from_host"]},"name":{"type":"string"},"sizeBytes":{"type":"integer"}},"required":["scopeId","deviceId","direction","name","sizeBytes"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var scopeId = FileArgs.Str(arguments, "scopeId") ?? "";
        var actor = BlockGActors.ResolveAiUser(_roster, ctx.Pairing, scopeId);
        if (actor is null) return Task.FromResult(BlockGActors.NoMember(ctx.Pairing, scopeId));
        var size = arguments.TryGetProperty("sizeBytes", out var s) && s.ValueKind == JsonValueKind.Number
            ? s.GetInt64() : -1;
        var job = _transfers.CreateJob(scopeId, FileArgs.Str(arguments, "deviceId") ?? "", actor.Id,
            FileArgs.Str(arguments, "direction") ?? "", FileArgs.Str(arguments, "name") ?? "", size);
        return Task.FromResult(job is null
            ? ToolResult.Error("refused", "transfer refused (policy, device, or grant check failed — the service's rules, re-read at create)")
            : ToolResult.Success($"transfer job {job.Id} queued: '{job.Name}' ({job.Direction}, {job.SizeBytes} bytes) for {job.DeviceId}"));
    }
}

public sealed class TransferListModule : IToolModule
{
    private readonly StandaloneTransferService _transfers;
    private readonly RosterService _roster;
    public TransferListModule(StandaloneTransferService transfers, RosterService roster) { _transfers = transfers; _roster = roster; }
    public ToolDescriptor Descriptor { get; } = new(
        "transfer_list", "List this caller's own standalone transfer jobs in a scope (id, name, direction, state, bytes).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"scopeId":{"type":"string"}},"required":["scopeId"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var scopeId = FileArgs.Str(arguments, "scopeId") ?? "";
        var actor = BlockGActors.ResolveAiUser(_roster, ctx.Pairing, scopeId);
        if (actor is null) return Task.FromResult(BlockGActors.NoMember(ctx.Pairing, scopeId));
        var jobs = _transfers.ListJobs(scopeId)
            .Where(j => string.Equals(j.InitiatorUserId, actor.Id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (jobs.Count == 0) return Task.FromResult(ToolResult.Success("no standalone transfer jobs for this caller in the scope"));
        var lines = jobs.Select(j => $"{j.Id} · '{j.Name}' · {j.Direction} · {j.State} · {j.TransferredBytes}/{j.SizeBytes} bytes · device {j.DeviceId}");
        return Task.FromResult(ToolResult.Success(string.Join("\n", lines)));
    }
}

public sealed class TransferCancelModule : IToolModule
{
    private readonly StandaloneTransferService _transfers;
    private readonly RosterService _roster;
    public TransferCancelModule(StandaloneTransferService transfers, RosterService roster) { _transfers = transfers; _roster = roster; }
    public ToolDescriptor Descriptor { get; } = new(
        "transfer_cancel", "Cancel a live standalone transfer job. The initiator can always stop their own job; a company admin of the job's scope can stop anyone's (the service enforces both).",
        Scopes.Drive, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"jobId":{"type":"string"}},"required":["jobId"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var jobId = FileArgs.Str(arguments, "jobId") ?? "";
        var job = _transfers.GetJob(jobId);
        if (job is null) return Task.FromResult(ToolResult.Error("not_found", jobId));
        var actor = BlockGActors.ResolveAiUser(_roster, ctx.Pairing, job.ScopeId);
        if (actor is null) return Task.FromResult(BlockGActors.NoMember(ctx.Pairing, job.ScopeId));
        return Task.FromResult(_transfers.CancelJob(jobId, actor.Id)
            ? ToolResult.Success($"transfer job {jobId} cancelled")
            : ToolResult.Error("refused", "cancel refused (job already terminal, or the caller is neither its initiator nor a company admin of its scope)"));
    }
}

public sealed class FactorStatusModule : IToolModule
{
    private readonly DeskGuest.Shared.Security.SecondFactorService _factors;
    public FactorStatusModule(DeskGuest.Shared.Security.SecondFactorService factors) => _factors = factors;
    public ToolDescriptor Descriptor { get; } = new(
        "factor_status", "Local second-factor posture on this host: counts of active TOTP enrollments and registered passkeys. Counts only — never which users, never any factor material.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var (totp, passkeys) = _factors.Counts();
        return Task.FromResult(ToolResult.Success($"active TOTP enrollments: {totp} · registered passkeys: {passkeys}"));
    }
}

public sealed class TunnelListModule : IToolModule
{
    private readonly SessionTunnelService _tunnels;
    private readonly SessionService _sessions;
    private readonly RosterService _roster;
    public TunnelListModule(SessionTunnelService tunnels, SessionService sessions, RosterService roster)
    { _tunnels = tunnels; _sessions = sessions; _roster = roster ?? throw new ArgumentNullException(nameof(roster)); }
    public ToolDescriptor Descriptor { get; } = new(
        "tunnel_list", "List open session TCP tunnels in a scope (id, session, target, listen port, opener). Read-only: tunnels open and close inside human sessions and from the host panel — an AI actor is refused tunnel control by the service itself (D38 F9).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"scopeId":{"type":"string"}},"required":["scopeId"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var scopeId = FileArgs.Str(arguments, "scopeId") ?? "";
        // Membership check (Block H D38 fix F3): listing tunnels
        // discloses targets and opener ids, so — like every other
        // Block G tool — the caller must resolve to a live AI
        // roster member OF THIS SCOPE. Before the fix any Observe
        // pairing could enumerate any scope's tunnels.
        var actor = BlockGActors.ResolveAiUser(_roster, ctx.Pairing, scopeId);
        if (actor is null) return Task.FromResult(BlockGActors.NoMember(ctx.Pairing, scopeId));
        var open = _tunnels.ListOpen().Where(t =>
        {
            var s = _sessions.GetSession(t.SessionId);
            return s is not null && string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase);
        }).ToList();
        if (open.Count == 0) return Task.FromResult(ToolResult.Success("no open session tunnels in the scope"));
        var lines = open.Select(t => $"{t.Id} · session {t.SessionId} · :{t.ListenPort} → {t.TargetHost}:{t.TargetPort} · opened by {t.OpenedByUserId}");
        return Task.FromResult(ToolResult.Success(string.Join("\n", lines)));
    }
}

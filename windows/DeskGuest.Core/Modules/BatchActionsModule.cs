using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>Census row 21: an action sequence executed as one session
/// flow. Each step is a desktop tool call through the same IPC channel;
/// the sequence stops at the first failure and reports which step —
/// never silently continues past an error.
///
/// U3: every step is re-run through PolicyEngine BEFORE its IPC call
/// (the batch call itself being policy-checked once at the choke point
/// never covered a step naming a tool outside the pairing's scopes or
/// gates), and an optional dryRun mode validates the whole sequence —
/// per-step verdicts, nothing executed.
/// Dry-run purity law: a dry run makes ZERO channel calls, records NO
/// rate-limit call (PolicyEngine.EvaluateDryRun peeks only), touches
/// no session, file or counter. Its one sanctioned side effect is the
/// audit entry that records the dry run itself.</summary>
public sealed class BatchActionsModule : IToolModule
{
    private readonly IAgentChannel _channel;
    private readonly PolicyEngine? _policy;
    private readonly ToolRegistry? _tools;
    private readonly IAuditLog? _audit;

    /// <param name="policy">Per-step policy evaluation. Null only in
    /// legacy/test construction: live steps then run as they always
    /// did, but dryRun REFUSES (it cannot validate, and a dry run
    /// that claims verdicts it never computed would be a fake).</param>
    /// <param name="tools">Registry the step descriptors resolve
    /// from. Held by reference and read at call time, so tools
    /// registered after this module are still seen.</param>
    /// <param name="audit">When present, every dry run appends a
    /// `batch_dry_run` entry before its result returns.</param>
    public BatchActionsModule(IAgentChannel channel, PolicyEngine? policy = null, ToolRegistry? tools = null, IAuditLog? audit = null)
    {
        _channel = channel;
        _policy = policy;
        _tools = tools;
        _audit = audit;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "batch_actions", "Execute a sequence of desktop actions as one visible flow; stops at the first failure and names it. With dryRun=true it executes nothing: each step is validated against policy and reported as would_execute or blocked, with the reason.",
        Scopes.Drive, SessionRequirement.Agent, RiskTier.High, ExecutionContext: "Agent",
        InputSchemaJson: """{"type":"object","properties":{"steps":{"type":"array","items":{"type":"object","properties":{"tool":{"type":"string"},"arguments":{"type":"object"}},"required":["tool"]}},"dryRun":{"type":"boolean","default":false}},"required":["steps"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!arguments.TryGetProperty("steps", out var steps) || steps.ValueKind != JsonValueKind.Array)
            return ToolResult.Error("bad_arguments", "batch_actions requires {steps:[...]}");
        // A present-but-non-boolean dryRun ("true", 1, null) refuses:
        // silently treating it as false would EXECUTE a batch the
        // caller may have meant to only validate.
        var dryRun = false;
        if (arguments.TryGetProperty("dryRun", out var dr))
        {
            if (dr.ValueKind == JsonValueKind.True) dryRun = true;
            else if (dr.ValueKind != JsonValueKind.False)
                return ToolResult.Error("bad_arguments", "batch_actions dryRun must be a boolean when present; the batch was not executed");
        }
        if (dryRun) return DryRun(steps, arguments, ctx);

        var results = new List<object>();
        var i = 0;
        foreach (var step in steps.EnumerateArray())
        {
            i++;
            var tool = step.ValueKind == JsonValueKind.Object && step.TryGetProperty("tool", out var t) ? t.GetString() ?? "" : "";
            var stepArgs = step.ValueKind == JsonValueKind.Object && step.TryGetProperty("arguments", out var a) ? a.GetRawText() : "{}";
            // U3 live leg: the per-step verdict gates the IPC call —
            // a step policy refuses stops the batch BEFORE it runs,
            // naming the policy reason, not after it has acted.
            var verdict = EvaluateStep(i, step, ctx, dry: false);
            if (verdict is { Blocked: true })
            {
                results.Add(new { step = i, tool, ok = false, text = $"refused before execution: {verdict.Reason}" });
                return ToolResult.Error("step_failed", JsonSerializer.Serialize(new { failed_step = i, tool, reason = verdict.Reason, results }));
            }
            var r = await _channel.CallDesktopToolAsync(tool, stepArgs, ct);
            results.Add(new { step = i, tool, ok = r.Ok, text = r.Text ?? r.UnavailableReason });
            if (!r.Ok)
                return ToolResult.Error("step_failed", JsonSerializer.Serialize(new { failed_step = i, tool, results }));
        }
        return ToolResult.Success(JsonSerializer.Serialize(new { completed = i, results }));
    }

    /// <summary>One step's pre-execution verdict. Null when no policy
    /// wiring exists (live legacy path only — DryRun refuses earlier
    /// in that case, so a null verdict is never reported as a pass).</summary>
    private sealed record StepVerdict(bool Blocked, string? Reason, ToolDescriptor? Descriptor);

    private StepVerdict? EvaluateStep(int index, JsonElement step, ToolExecutionContext ctx, bool dry)
    {
        if (_policy is null || _tools is null) return null;
        if (step.ValueKind != JsonValueKind.Object)
            return new StepVerdict(true, "malformed_step: each step must be an object {tool, arguments}", null);
        var tool = step.TryGetProperty("tool", out var t) ? t.GetString() ?? "" : "";
        if (tool.Length == 0)
            return new StepVerdict(true, "malformed_step: step has no tool name", null);
        var descriptor = _tools.Find(tool)?.Descriptor;
        if (descriptor is null)
            return new StepVerdict(true, $"unknown_tool: no tool named '{tool}' is registered on this host", null);
        // batch_actions itself is executed by the Core, never by
        // the desktop engine — and its descriptor carries the
        // "Agent" context of the plane it drives, so the generic
        // check below would wave a nested batch through. Refuse
        // nesting by name.
        if (string.Equals(tool, Descriptor.Name, StringComparison.Ordinal))
            return new StepVerdict(true, "not_a_desktop_step: 'batch_actions' is executed by the Core, not the desktop engine; a batch cannot nest inside itself", descriptor);
        // The batch channel reaches only the desktop plane. A Core /
        // SYSTEM tool (session_start, file_read, shell hosts…) can
        // never be a batch step.
        if (!string.Equals(descriptor.ExecutionContext, "Agent", StringComparison.Ordinal))
            return new StepVerdict(true, $"not_a_desktop_step: '{tool}' does not run on the desktop plane (execution context '{descriptor.ExecutionContext}'); batch steps can only be desktop tools", descriptor);
        JsonElement stepArgs;
        if (step.TryGetProperty("arguments", out var a))
        {
            if (a.ValueKind != JsonValueKind.Object)
                return new StepVerdict(true, "invalid_arguments: step arguments must be an object", descriptor);
            stepArgs = a;
        }
        else
        {
            using var empty = JsonDocument.Parse("{}");
            stepArgs = empty.RootElement.Clone();
        }
        // Required-argument presence from the descriptor's own schema
        // — the one argument check that needs no execution.
        var missing = MissingRequired(descriptor, stepArgs);
        if (missing.Count > 0)
            return new StepVerdict(true, $"invalid_arguments: '{tool}' requires argument(s) the step does not supply: {string.Join(", ", missing)}", descriptor);
        var decision = dry
            ? _policy.EvaluateDryRun(ctx.Pairing, descriptor, stepArgs, ctx.Session, ctx.EndpointState, ctx.ApprovedGateClasses, ctx.Session.ForegroundTitle, ctx.Session.ForegroundProcess)
            : _policy.Evaluate(ctx.Pairing, descriptor, stepArgs, ctx.Session, ctx.EndpointState, ctx.ApprovedGateClasses, ctx.Session.ForegroundTitle, ctx.Session.ForegroundProcess);
        return decision.Allowed
            ? new StepVerdict(false, null, descriptor)
            : new StepVerdict(true, decision.DenyReason, descriptor);
    }

    private static List<string> MissingRequired(ToolDescriptor descriptor, JsonElement args)
    {
        var missing = new List<string>();
        try
        {
            using var schema = JsonDocument.Parse(descriptor.InputSchemaJson);
            if (schema.RootElement.TryGetProperty("required", out var req) && req.ValueKind == JsonValueKind.Array)
                foreach (var r in req.EnumerateArray())
                    if (r.GetString() is { } name && !args.TryGetProperty(name, out _))
                        missing.Add(name);
        }
        catch (JsonException) { /* an unparseable schema claims no required args; policy still gates the step */ }
        return missing;
    }

    /// <summary>U3 dry run: validate every step, execute none of
    /// them. Every step is reported (validation does not stop at the
    /// first blocker — the caller wants the whole picture), and the
    /// result states plainly what validation cannot know.</summary>
    private ToolResult DryRun(JsonElement steps, JsonElement arguments, ToolExecutionContext ctx)
    {
        if (_policy is null || _tools is null)
            return ToolResult.Error("dry_run_unavailable",
                "batch_actions dryRun cannot validate on this host: the policy engine / tool registry are not wired into the batch module. Nothing was executed and no verdict is claimed.");

        var verdicts = new List<object>();
        var i = 0;
        var blocked = 0;
        string? firstBlocker = null;
        foreach (var step in steps.EnumerateArray())
        {
            i++;
            var tool = step.ValueKind == JsonValueKind.Object && step.TryGetProperty("tool", out var t) ? t.GetString() ?? "" : "";
            var v = EvaluateStep(i, step, ctx, dry: true)!; // non-null: wiring checked above
            if (v.Blocked) { blocked++; firstBlocker ??= $"step {i} ({tool}): {v.Reason}"; }
            verdicts.Add(new
            {
                step = i,
                tool,
                verdict = v.Blocked ? "blocked" : "would_execute",
                reason = v.Reason,
                required_scope = v.Descriptor?.RequiredScope,
                gate_class = v.Descriptor?.GateClass,
                session_requirement = v.Descriptor?.Session.ToString(),
                risk = v.Descriptor?.Risk.ToString(),
                effect_validated = false // a step's on-screen effect is never knowable without running it
            });
        }
        var allPass = blocked == 0;
        // The dry run itself is audited — the one sanctioned side
        // effect. Appended before the result returns; if the append
        // throws, the dry run fails closed rather than passing
        // unrecorded (McpHandler turns the throw into an error).
        _audit?.Append(new AuditEntry(
            DateTimeOffset.UtcNow, "batch_dry_run", ctx.Pairing.Id, ctx.Pairing.AgentName, "batch_actions", null,
            Redactor.RedactJson(arguments).GetRawText(),
            allPass ? $"dry_run:all_{i}_steps_would_execute" : $"dry_run:{blocked}_of_{i}_steps_blocked; first: {firstBlocker}",
            "Agent", null));
        return ToolResult.Success(JsonSerializer.Serialize(new
        {
            dry_run = true,
            executed = 0,
            steps_checked = i,
            all_steps_would_pass = allPass,
            verdicts,
            not_validated = new[]
            {
                "each step's actual effect on the desktop (element existence, app state, timing, what the previous step leaves behind) — knowable only by executing",
                "rate capacity is peeked, not reserved: a live run re-evaluates policy at each step against the facts as they then stand",
                "gate approvals are read as they stand now; an approval granted or revoked before the live run changes its verdicts"
            }
        }));
    }
}

/// <summary>Census row 3 (Core half): presence is driven by session
/// state. This module lets a session announce narration text; the
/// glow/banner themselves are owned by the Agent's presence layer and
/// follow session start/stop — they are never agent-optional.</summary>
public sealed class PresenceControlModule : IToolModule
{
    private readonly AgentIpcServer _ipc;
    private readonly CoreState _state;
    private readonly SessionManager? _sessions;
    public PresenceControlModule(AgentIpcServer ipc, CoreState state, SessionManager? sessions = null)
    { _ipc = ipc; _state = state; _sessions = sessions; }

    /// <summary>BD-WIN-CORE-1 F10 narration cap.</summary>
    public const int MaxNarrationChars = 200;

    public ToolDescriptor Descriptor { get; } = new(
        "presence_control", "Set the session narration line (what the banner says the agent is doing). Presence itself is never optional.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"narration":{"type":"string"}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        // BD-WIN-CORE-1 F10: the banner is the owner's consent
        // surface — an agent may only narrate inside its OWN live
        // session. Without one there is nothing to narrate, and an
        // Observe-only caller can no longer paint arbitrary text
        // ("Windows Update in progress") over the banner.
        if (_sessions is not null)
        {
            var live = _sessions.Current;
            if (live is null) return ToolResult.Error("no_session", "presence narration requires a live session owned by the calling pairing");
            if (!string.Equals(live.PairingId, ctx.Pairing.Id, StringComparison.Ordinal))
                return ToolResult.Error("session_owned_by_other_pairing", "the live session belongs to another pairing");
        }
        var narration = arguments.TryGetProperty("narration", out var n) ? n.GetString() ?? "" : "";
        if (narration.Length > MaxNarrationChars) narration = narration[..MaxNarrationChars];
        _state.LastNarration = narration; // mesh "intent" line (M2)
        // Same directive shape as the supervisor's push (M1): the
        // agent reconciles from complete truth — including the real
        // STOP flag, so a narration update can never paint over a
        // block the Core is enforcing.
        var payload = JsonSerializer.Serialize(new { active = true, agent = ctx.Pairing.AgentName, stopInForce = _state.StopInForce });
        await _ipc.NotifyAgentAsync(new Shared.Ipc.IpcMessage(Shared.Ipc.IpcKinds.Presence, null, null, payload, null, "on", null, null, null, narration,
            AgentName: ctx.Pairing.AgentName), ct);
        return ToolResult.Success("narration updated");
    }
}

/// <summary>Census row 4: takeover status — the owner has the desktop;
/// capture is suspended and the log records that a takeover occurred,
/// never its content.</summary>
public sealed class TakeoverStatusModule : IToolModule
{
    private readonly CoreState _state;
    public TakeoverStatusModule(CoreState state) => _state = state;
    public ToolDescriptor Descriptor { get; } = new(
        "takeover_status", "Whether the owner has taken over the desktop (capture suspended while they have it).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { takeover_active = _state.Session.TakeoverActive })));
}

/// <summary>Census row 5: notify the owner — toast/banner via the Agent
/// when a session exists; otherwise queued to the data dir where the
/// Agent surfaces it at next logon. Never silent.</summary>
public sealed class NotifyUserModule : IToolModule
{
    private readonly AgentIpcServer _ipc;
    private readonly string _dataDir;
    private readonly Shared.Sessions.AgentEventBus? _events;
    public NotifyUserModule(AgentIpcServer ipc, string dataDir, Shared.Sessions.AgentEventBus? events = null)
    { _ipc = ipc; _dataDir = dataDir; _events = events; }

    public ToolDescriptor Descriptor { get; } = new(
        "notify_user", "Show the owner a message (question, completion, warning) on the laptop.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}""");

    private readonly object _rateGate = new();
    private readonly Dictionary<string, List<DateTimeOffset>> _recentByPairing = new();
    /// <summary>BD-WIN-CORE-1 F10 caps.</summary>
    public const int MaxMessageChars = 500;
    public const int MaxNotificationsPerMinute = 5;
    public const long MaxQueueBytes = 256 * 1024;

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var message = arguments.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
        if (message.Length > MaxMessageChars) message = message[..MaxMessageChars];
        // Rate limit per pairing: the notification surface is not a
        // spam channel onto the owner's screen / disk queue.
        lock (_rateGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (!_recentByPairing.TryGetValue(ctx.Pairing.Id, out var times))
                _recentByPairing[ctx.Pairing.Id] = times = new List<DateTimeOffset>();
            times.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
            if (times.Count >= MaxNotificationsPerMinute)
                return ToolResult.Error("rate_limited", "notify_user is capped at 5 messages per minute per pairing");
            times.Add(now);
        }
        // U2: a posted notification is an event for the posting
        // pairing's own subscribers (origin-scoped; the event
        // detail names that a notification was posted, never its
        // text — message content is not event data).
        _events?.Publish(Shared.Sessions.AgentEventKinds.NotificationPosted,
            $"notification_posted: by {ctx.Pairing.AgentName}", ctx.Pairing.Id);
        if (_ipc.AgentConnected)
        {
            await _ipc.NotifyAgentAsync(new Shared.Ipc.IpcMessage(Shared.Ipc.IpcKinds.Notify, null, null, null, null, message, null, null, null, message), ct);
            return ToolResult.Success("shown on the laptop");
        }
        var path = Path.Combine(_dataDir, "pending-notifications.jsonl");
        // Queue cap: an unbounded append-only file under an
        // Observe-scope tool is a disk-fill path.
        if (File.Exists(path) && new FileInfo(path).Length > MaxQueueBytes)
            return ToolResult.Error("queue_full", "the pending-notification queue is full (256 KB); the message was not queued");
        await File.AppendAllTextAsync(path, JsonSerializer.Serialize(new { at = DateTimeOffset.UtcNow, from = ctx.Pairing.AgentName, message }) + Environment.NewLine, ct);
        return ToolResult.Success("queued: no session agent is connected; the owner will see it at next logon");
    }
}

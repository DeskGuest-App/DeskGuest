using System.Text.Json;
using DeskGuest.Shared.BackgroundTools;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

// =====================================================================
// RMM-10 — the background toolset as MCP tool modules. Each module
// requires the dedicated `background_tools` scope (Scopes
// .BackgroundTools) — NOT shell/admin: background rights are a
// separate grant from session rights in both directions. The
// modules are thin: every gate (policy, scope re-check, protected
// targets, signed command, audit, session history) lives in
// BackgroundToolsService, so a module can never become an
// unaudited side door around it.
//
// SURFACE LAW: CoreRuntime registers these modules ONLY when the
// toolset is policy-enabled for the endpoint (the coordinator's
// wiring step) — policy OFF means the tools do not exist in
// tools/list at all. If a module IS registered while policy is off
// (policy flipped after startup), the service refuses and the
// module reports Unavailable honestly, never a fake success.
//
// WIRING (BD-WIN-CORE-1 F4): CoreRuntime registers these modules
// when the BackgroundToolSurface policy check enables the toolset
// for the device, passing deviceId: () => Identity.DeviceId.
// WIRING REMAINDER (named): production executor bindings (real
// process/service/registry primitives in SYSTEM context) — the
// service still runs over the recording executor in CoreRuntime.
// =====================================================================

public abstract class BackgroundToolModuleBase : IToolModule
{
    protected readonly BackgroundToolsService Service;
    private readonly Func<string> _deviceId;
    /// <param name="deviceId">The endpoint's own device id, bound by
    /// CoreRuntime wiring. Until wiring supplies it the default is
    /// empty — facts resolve to null and every call fails closed,
    /// never to a borrowed identifier.</param>
    protected BackgroundToolModuleBase(BackgroundToolsService service, Func<string>? deviceId = null)
    {
        Service = service;
        _deviceId = deviceId ?? (() => "");
    }
    public abstract ToolDescriptor Descriptor { get; }
    public abstract Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct);

    protected BackgroundCallContext CallContext(ToolExecutionContext ctx, JsonElement arguments) => new(
        ctx.Pairing.Id, ctx.Pairing.AgentName, ctx.Pairing.Scopes,
        DeviceId: _deviceId(),
        // D38 F11: a non-string signed_command must not throw out of
        // the module — only a JSON string is an envelope; anything
        // else is treated as absent and the service's gates decide.
        SignedCommandJson: arguments.ValueKind == JsonValueKind.Object &&
            arguments.TryGetProperty("signed_command", out var sc) && sc.ValueKind == JsonValueKind.String
            ? sc.GetString() : null);

    protected static ToolResult Map(BackgroundActionResult r) =>
        r.Ok ? ToolResult.Success(r.Output ?? r.Detail)
             : ToolResult.Error("background_refused", r.Detail);

    // D38 F11: typed accessors never throw on a wrong-typed value —
    // a non-string is "absent" (the caller then refuses by name for
    // a missing required argument), a non-integer number likewise.
    protected static string? Str(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

    protected static int? Int(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number &&
        v.TryGetInt32(out var n) ? n : null;
}

public sealed class BackgroundProcessKillModule : BackgroundToolModuleBase
{
    public BackgroundProcessKillModule(BackgroundToolsService s, Func<string>? deviceId = null) : base(s, deviceId) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "background_process_kill", "RMM-10 background tools: kill one process by pid, without opening a session. DeskGuest's own processes refuse.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"pid":{"type":"integer"},"signed_command":{"type":"string"}},"required":["pid"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var pid = Int(arguments, "pid");
        if (pid is null) return Task.FromResult(ToolResult.Error("bad_arguments", "background_process_kill requires {pid}"));
        return Task.FromResult(Map(Service.KillProcess(CallContext(ctx, arguments), pid.Value)));
    }
}

public sealed class BackgroundProcessKillTreeModule : BackgroundToolModuleBase
{
    public BackgroundProcessKillTreeModule(BackgroundToolsService s, Func<string>? deviceId = null) : base(s, deviceId) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "background_process_kill_tree", "RMM-10 background tools: kill a process and all its descendants. A tree containing an DeskGuest process refuses whole.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"pid":{"type":"integer"},"signed_command":{"type":"string"}},"required":["pid"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var pid = Int(arguments, "pid");
        if (pid is null) return Task.FromResult(ToolResult.Error("bad_arguments", "background_process_kill_tree requires {pid}"));
        return Task.FromResult(Map(Service.KillProcessTree(CallContext(ctx, arguments), pid.Value)));
    }
}

public sealed class BackgroundServiceControlModule : BackgroundToolModuleBase
{
    private readonly string _action;
    public BackgroundServiceControlModule(BackgroundToolsService s, string action, Func<string>? deviceId = null) : base(s, deviceId) => _action = action;
    public override ToolDescriptor Descriptor => new(
        $"background_service_{_action}", $"RMM-10 background tools: {_action} a Windows service, without opening a session. DeskGuest's own services refuse.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"name":{"type":"string"},"signed_command":{"type":"string"}},"required":["name"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var name = Str(arguments, "name");
        if (name is null) return Task.FromResult(ToolResult.Error("bad_arguments", $"background_service_{_action} requires {{name}}"));
        var call = CallContext(ctx, arguments);
        var result = _action switch
        {
            "start" => Service.StartService(call, name),
            "stop" => Service.StopService(call, name),
            _ => Service.RestartService(call, name),
        };
        return Task.FromResult(Map(result));
    }
}

public sealed class BackgroundFileListModule : BackgroundToolModuleBase
{
    public BackgroundFileListModule(BackgroundToolsService s, Func<string>? deviceId = null) : base(s, deviceId) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "background_file_list", "RMM-10 background tools: browse a directory, without opening a session.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = Str(arguments, "path");
        if (path is null) return Task.FromResult(ToolResult.Error("bad_arguments", "background_file_list requires {path}"));
        return Task.FromResult(Map(Service.ListFiles(CallContext(ctx, arguments), path)));
    }
}

public sealed class BackgroundRegistrySetModule : BackgroundToolModuleBase
{
    public BackgroundRegistrySetModule(BackgroundToolsService s, Func<string>? deviceId = null) : base(s, deviceId) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "background_registry_set", "RMM-10 background tools: set a registry value (Windows), without opening a session. DeskGuest's own protected keys refuse.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"key":{"type":"string"},"value_name":{"type":"string"},"value":{"type":"string"},"signed_command":{"type":"string"}},"required":["key","value_name","value"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var key = Str(arguments, "key"); var vn = Str(arguments, "value_name"); var val = Str(arguments, "value");
        if (key is null || vn is null || val is null)
            return Task.FromResult(ToolResult.Error("bad_arguments", "background_registry_set requires {key, value_name, value}"));
        return Task.FromResult(Map(Service.RegistrySet(CallContext(ctx, arguments), key, vn, val)));
    }
}

public sealed class BackgroundKitRunModule : BackgroundToolModuleBase
{
    public BackgroundKitRunModule(BackgroundToolsService s, Func<string>? deviceId = null) : base(s, deviceId) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "background_kit_run", "RMM-10 governed toolbox: run one tool from an admitted, hash-pinned kit (personal or shared). Bytes that do not match the pin never run.",
        Scopes.BackgroundTools, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"kit_id":{"type":"string"},"tool":{"type":"string"},"arguments":{"type":"string"},"signed_command":{"type":"string"}},"required":["kit_id","tool"]}""");
    public override Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var kit = Str(arguments, "kit_id"); var tool = Str(arguments, "tool");
        if (kit is null || tool is null)
            return Task.FromResult(ToolResult.Error("bad_arguments", "background_kit_run requires {kit_id, tool}"));
        return Task.FromResult(Map(Service.RunKitTool(CallContext(ctx, arguments), kit, tool, Str(arguments, "arguments") ?? "")));
    }
}

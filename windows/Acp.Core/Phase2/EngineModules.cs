using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Acp.Core.Ipc;
using Acp.Core.Modules;
using Acp.Core.Services;
using Acp.Core.Platform;
using Acp.Shared.Audit;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Phase2;

/// <summary>Store-name discipline for every module that turns a
/// caller-supplied name into a file path (2026-11-15 blocker fix):
/// the macro store interpolated the name straight into Path.Combine,
/// so name = "..\pairings" wrote over the pairing store — a
/// Drive-scope caller could grant itself every scope at next start.
/// Names are now a strict allowlist shape, and mission ids (same
/// pattern, same hole) are validated identically.</summary>
internal static class SafeStoreName
{
    private static readonly System.Text.RegularExpressions.Regex Pattern =
        new("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", System.Text.RegularExpressions.RegexOptions.Compiled);
    public static bool IsValid(string? name) => name is not null && Pattern.IsMatch(name);
}

/// <summary>Census row 103: durable missions — ordered tool-call steps
/// with checkpoints persisted to disk, resumable after a Core restart,
/// running under the pairing that created them (a revoked pairing halts
/// its missions). The step runner is injected by the runtime to avoid a
/// construction cycle with the MCP handler.</summary>
public sealed class MissionEngine
{
    public sealed class MissionStep { public string Tool { get; set; } = ""; public JsonObject Args { get; set; } = new(); }
    public sealed class Mission
    {
        public string Id { get; set; } = "";
        public string PairingId { get; set; } = "";
        public string Title { get; set; } = "";
        public List<MissionStep> Steps { get; set; } = new();
        public int CompletedSteps { get; set; }
        public string State { get; set; } = "queued"; // queued|running|paused|complete|failed|halted
        public string? LastError { get; set; }
    }

    private readonly string _dir;
    private readonly object _lock = new();
    private readonly HashSet<string> _running = new();
    public Func<string, string, JsonObject, CancellationToken, Task<ToolResult>>? StepRunner { get; set; }

    /// <summary>Re-checked before EVERY step (BD-WIN-CORE-2/F4): the
    /// host wires this to the pairing store; a mission whose creating
    /// pairing was revoked / expired mid-run HALTS (the declared
    /// 'halted' state, previously never assigned) instead of running
    /// on under a dead pairing's authority.</summary>
    public Func<string, bool>? PairingStillValid { get; set; }

    public MissionEngine(string dataDir)
    {
        _dir = Path.Combine(dataDir, "missions");
        Directory.CreateDirectory(_dir);
    }

    private string PathFor(string id) => Path.Combine(_dir, $"{id}.json");
    private void Save(Mission m) { lock (_lock) File.WriteAllText(PathFor(m.Id), JsonSerializer.Serialize(m, new JsonSerializerOptions { WriteIndented = true })); }
    public Mission? Load(string id) => SafeStoreName.IsValid(id) && File.Exists(PathFor(id)) ? JsonSerializer.Deserialize<Mission>(File.ReadAllText(PathFor(id))) : null;
    public IReadOnlyList<Mission> List() => Directory.EnumerateFiles(_dir, "*.json").Select(f => JsonSerializer.Deserialize<Mission>(File.ReadAllText(f))).Where(m => m is not null).Cast<Mission>().ToList();

    public Mission Create(string pairingId, string title, List<MissionStep> steps)
    {
        var m = new Mission { Id = Guid.NewGuid().ToString("N")[..12], PairingId = pairingId, Title = title, Steps = steps };
        Save(m);
        return m;
    }

    /// <summary>Restart recovery (BD-WIN-CORE-2/F4): a mission left in
    /// 'running' by a Core that died mid-run is moved to 'paused' —
    /// its checkpoints stand, so an explicit run resumes where it
    /// stopped. Nothing auto-executes steps at boot: resumption is
    /// the creating pairing's explicit act, under its live authority.
    /// Returns how many missions were recovered.</summary>
    public int RecoverStaleRuns()
    {
        var recovered = 0;
        foreach (var m in List())
        {
            if (m.State != "running") continue;
            bool inFlight;
            lock (_lock) inFlight = _running.Contains(m.Id);
            if (inFlight) continue;
            m.State = "paused"; m.LastError = "Core restarted mid-run; checkpoints stand — resume explicitly";
            Save(m); recovered++;
        }
        return recovered;
    }

    public async Task<Mission> RunAsync(string id, CancellationToken ct)
    {
        var m = Load(id) ?? throw new InvalidOperationException($"no mission {id}");
        // Per-id run lock (F4): two concurrent runs of the same id
        // would execute every remaining step twice.
        lock (_lock)
        {
            if (!_running.Add(id))
                throw new InvalidOperationException($"mission {id} is already running; concurrent runs of one mission are refused");
        }
        try
        {
            if (StepRunner is null) { m.State = "failed"; m.LastError = "step runner not wired"; Save(m); return m; }
            m.State = "running"; Save(m);
            try
            {
                while (m.CompletedSteps < m.Steps.Count)
                {
                    ct.ThrowIfCancellationRequested();
                    if (PairingStillValid is not null && !PairingStillValid(m.PairingId))
                    { m.State = "halted"; m.LastError = "the creating pairing is revoked, expired, or unknown; the mission halts rather than run under dead authority"; Save(m); return m; }
                    var step = m.Steps[m.CompletedSteps];
                    var result = await StepRunner(m.PairingId, step.Tool, step.Args, ct);
                    if (!result.Ok) { m.State = "failed"; m.LastError = $"{step.Tool}: {result.Text}"; Save(m); return m; }
                    m.CompletedSteps++;
                    Save(m); // checkpoint after every step — a crash resumes here
                }
                m.State = "complete"; Save(m);
                return m;
            }
            catch (OperationCanceledException) { m.State = "paused"; Save(m); return m; }
        }
        finally { lock (_lock) _running.Remove(id); }
    }
}

public sealed class MissionEngineModule : IToolModule
{
    private readonly MissionEngine _engine;
    public MissionEngineModule(MissionEngine engine) => _engine = engine;
    public ToolDescriptor Descriptor { get; } = new(
        "mission_engine", "Durable multi-step missions: create / run / status / list. Steps checkpoint after each success; missions run under the creating pairing.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["create","run","status","list"]},"id":{"type":"string"},"title":{"type":"string"},"steps":{"type":"array","items":{"type":"object","properties":{"tool":{"type":"string"},"args":{"type":"object"}}}}}}""");

    /// <summary>BD-WIN-CORE-2/F4: missions run under the creating
    /// pairing, so ownership is checked HERE, at the tool surface —
    /// run/status refuse any pairing but the creator, and list shows
    /// a pairing only its own missions. Previously any Shell-scope
    /// pairing could list, inspect and RUN another pairing's mission,
    /// and the steps executed with the CREATOR's PairingId through
    /// the MCP choke point (a confused deputy up to the creator's
    /// scopes). A foreign id answers 'not_found': another pairing's
    /// mission ids are not disclosed either.</summary>
    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        switch (action)
        {
            case "create":
            {
                var steps = new List<MissionEngine.MissionStep>();
                if (arguments.TryGetProperty("steps", out var arr))
                    foreach (var s in arr.EnumerateArray())
                        steps.Add(new MissionEngine.MissionStep
                        {
                            Tool = s.TryGetProperty("tool", out var t) ? t.GetString() ?? "" : "",
                            Args = s.TryGetProperty("args", out var a) ? JsonNode.Parse(a.GetRawText()) as JsonObject ?? new JsonObject() : new JsonObject()
                        });
                // Create-time validation (F4): step tool names and the
                // step count are checked NOW, not discovered mid-run.
                if (steps.Count == 0) return ToolResult.Error("bad_arguments", "a mission needs at least one step");
                if (steps.Count > 100) return ToolResult.Error("bad_arguments", "a mission is capped at 100 steps");
                if (steps.Any(s => string.IsNullOrWhiteSpace(s.Tool)))
                    return ToolResult.Error("bad_arguments", "every step must name a tool");
                var m = _engine.Create(ctx.Pairing.Id, FileArgs.Str(arguments, "title") ?? "mission", steps);
                return ToolResult.Success(JsonSerializer.Serialize(new { m.Id, m.State, steps = m.Steps.Count }));
            }
            case "run":
            {
                var id = FileArgs.Str(arguments, "id") ?? "";
                var owned = _engine.Load(id);
                if (owned is null || owned.PairingId != ctx.Pairing.Id)
                    return ToolResult.Error("not_found", "no such mission for this pairing");
                try
                {
                    var m = await _engine.RunAsync(id, ct);
                    return ToolResult.Success(JsonSerializer.Serialize(new { m.Id, m.State, m.CompletedSteps, m.LastError }));
                }
                catch (InvalidOperationException ex) { return ToolResult.Error("run_refused", ex.Message); }
            }
            case "status":
            {
                var m = _engine.Load(FileArgs.Str(arguments, "id") ?? "");
                return m is null || m.PairingId != ctx.Pairing.Id
                    ? ToolResult.Error("not_found", "no such mission for this pairing")
                    : ToolResult.Success(JsonSerializer.Serialize(new { m.Id, m.State, m.CompletedSteps, total = m.Steps.Count, m.LastError }));
            }
            default:
                _engine.RecoverStaleRuns();
                return ToolResult.Success(JsonSerializer.Serialize(_engine.List()
                    .Where(m => m.PairingId == ctx.Pairing.Id)
                    .Select(m => new { m.Id, m.Title, m.State })));
        }
    }
}

/// <summary>Census row 104: macro record/replay — named sequences of
/// desktop actions stored in the staging store, replayed through the
/// session agent. Recording captures actions the CALLER performs via
/// tools; there is no background input hooking (consent floor).</summary>
public sealed class MacroModule : IToolModule
{
    private readonly string _dir;
    public MacroModule(string dataDir, IAgentChannel agent)
    {
        _dir = Path.Combine(dataDir, "macros");
        Directory.CreateDirectory(_dir);
        // The agent channel parameter is retained for construction
        // compatibility, but replay deliberately NO LONGER uses the
        // raw channel (F9): steps go through PolicyStepRunner, i.e.
        // the MCP choke point, or replay refuses.
        _ = agent;
    }

    /// <summary>Replay path (BD-WIN-CORE-2/F9): the host wires this
    /// to the MCP choke point (McpHandler.ExecuteForPairingAsync —
    /// the same runner missions use), so EVERY replayed step is
    /// re-checked as its real tool: descriptor scope, gate class,
    /// takeover and STOP, under the REPLAYING pairing. The previous
    /// implementation forwarded each step's engine name straight to
    /// the session agent, so a Drive-scope caller could replay any
    /// desktop engine (shell_exec included) with none of those
    /// checks. When the runner is not wired, replay of a non-empty
    /// macro REFUSES — it never falls back to the raw channel.</summary>
    public Func<string, string, JsonObject, CancellationToken, Task<ToolResult>>? PolicyStepRunner { get; set; }

    public ToolDescriptor Descriptor { get; } = new(
        "macro_record_replay", "Save/list/replay named desktop-action macros (action=save|list|replay). 'Save' stores a caller-supplied step list — there is no live recording and no background input hooking (consent floor); replay runs every step back through the policy choke point as its real tool.",
        Scopes.Drive, SessionRequirement.Agent, RiskTier.High, ExecutionContext: "SessionAgent",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["save","list","replay"]},"name":{"type":"string"},"steps":{"type":"array"}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        var name = FileArgs.Str(arguments, "name") ?? "";
        if (action != "list" && !SafeStoreName.IsValid(name))
            return ToolResult.Error("bad_arguments", "macro name must be 1-64 characters of letters, digits, '-' or '_' (no path separators or dots)");
        var path = Path.Combine(_dir, $"{name}.json");
        switch (action)
        {
            case "save":
                await File.WriteAllTextAsync(path, arguments.TryGetProperty("steps", out var s) ? s.GetRawText() : "[]", ct);
                return ToolResult.Success($"macro '{name}' saved");
            case "list":
                return ToolResult.Success(JsonSerializer.Serialize(Directory.EnumerateFiles(_dir, "*.json").Select(Path.GetFileNameWithoutExtension)));
            case "replay":
            {
                if (!File.Exists(path)) return ToolResult.Error("not_found", $"no macro '{name}'");
                using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path, ct));
                var steps = doc.RootElement.EnumerateArray().ToList();
                if (steps.Count > 0 && PolicyStepRunner is null)
                    return ToolResult.Error("replay_unavailable", "macro replay is not wired to the policy choke point in this host; refusing rather than replaying around scope, gate, takeover and STOP checks");
                var played = 0;
                foreach (var step in steps)
                {
                    var engine = step.TryGetProperty("engine", out var e) ? e.GetString() ?? "" : "";
                    var argsObj = step.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Object
                        ? JsonNode.Parse(a.GetRawText()) as JsonObject ?? new JsonObject()
                        : new JsonObject();
                    var r = await PolicyStepRunner!(ctx.Pairing.Id, engine, argsObj, ct);
                    if (!r.Ok) return ToolResult.Error("replay_failed", $"step {played} ({engine}): {r.Text}");
                    played++;
                }
                return ToolResult.Success($"replayed {played} steps of '{name}' (each step re-checked through the policy choke point)");
            }
            default:
                return ToolResult.Error("bad_arguments", action);
        }
    }
}

/// <summary>Census row 107: the signature policy for scripts and plugin
/// modules. Policy state lives in the data dir; when "signed_only" is
/// on, unsigned script files are refused by script_engines and unsigned
/// assemblies by tool_module_install.
/// DEFAULT IS ON (2026-11-15 blocker fix): the original getter failed
/// OPEN — no policy file meant unsigned code ran as SYSTEM. Now an
/// absent or unreadable policy file means signed-only; turning it off
/// requires an explicit recorded policy write by an Admin-scope
/// caller through script_signature_policy.</summary>
public sealed class ScriptSignaturePolicy
{
    private readonly string _path;
    public ScriptSignaturePolicy(string dataDir) => _path = Path.Combine(dataDir, "script-policy.json");
    public bool SignedOnly
    {
        get
        {
            try
            {
                if (!File.Exists(_path)) return true; // fail closed
                return JsonDocument.Parse(File.ReadAllText(_path)).RootElement.TryGetProperty("signed_only", out var v) && v.GetBoolean();
            }
            catch { return true; } // unreadable policy: fail closed
        }
        set => File.WriteAllText(_path, JsonSerializer.Serialize(new { signed_only = value }));
    }
}

public sealed class ScriptSignaturePolicyModule : IToolModule
{
    private readonly ScriptSignaturePolicy _policy;
    private readonly IAuditLog? _audit;
    public ScriptSignaturePolicyModule(ScriptSignaturePolicy policy, IAuditLog? audit = null) { _policy = policy; _audit = audit; }
    public ToolDescriptor Descriptor { get; } = new(
        "script_signature_policy", "Read or set the signed-only policy for scripts and plugin modules. Every 'set' is audit-recorded with its actor (BD-WIN-CORE-2/F7: the policy header always claimed 'an explicit recorded policy write'; the write is now actually recorded).",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["get","set"]},"signed_only":{"type":"boolean"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "get";
        if (action == "set" && arguments.TryGetProperty("signed_only", out var v))
        {
            _policy.SignedOnly = v.GetBoolean();
            _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", ctx.Pairing.Id, ctx.Pairing.AgentName,
                "script_signature_policy", "set", JsonSerializer.Serialize(new { signed_only = _policy.SignedOnly }),
                "policy_write", "SYSTEM", null));
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { signed_only = _policy.SignedOnly })));
    }
}

/// <summary>Census row 106: script engines — PowerShell / Python / Node
/// script FILES from inside the file scope, executed with the same
/// timeout discipline as shell. Under signed-only policy, a script
/// needs a detached .sig that verifies against the update key.</summary>
public sealed class ScriptEnginesModule : IToolModule
{
    private readonly IProcessRunner _runner;
    private readonly FileScope _scope;
    private readonly ScriptSignaturePolicy _policy;
    private readonly IUpdateSignatureVerifier _verifier;
    public ScriptEnginesModule(IProcessRunner runner, FileScope scope, ScriptSignaturePolicy policy, IUpdateSignatureVerifier verifier)
    { _runner = runner; _scope = scope; _policy = policy; _verifier = verifier; }

    public ToolDescriptor Descriptor { get; } = new(
        "script_engines", "Run a script file (powershell/python/node) from inside the file scope, honouring the signature policy.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"engine":{"type":"string","enum":["powershell","python","node"]},"path":{"type":"string"},"args":{"type":"string"},"timeout_seconds":{"type":"integer"}}}""");

    /// <summary>Hard cap for timeout_seconds (BD-WIN-CORE-2/F7: the
    /// caller previously set an unbounded timeout).</summary>
    public const int MaxTimeoutSeconds = 3600;

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var engine = FileArgs.Str(arguments, "engine") ?? "";
        var path = FileArgs.Path(arguments, "path");
        var full = path is null ? null : _scope.ResolveInScope(path);
        if (full is null || !File.Exists(full)) return ToolResult.Error("out_of_scope", "script must be an existing file inside the scope");
        // TOCTOU (F7): read the script ONCE, verify THOSE bytes, and
        // execute a snapshot of exactly those bytes from a Core-owned
        // staging file — the interpreter never re-opens the caller's
        // path, so swapping the file between verify and run gains
        // nothing. Python runs isolated (-I: no user site, the
        // script's own directory is not added to sys.path) and Node's
        // working directory is the snapshot directory, which contains
        // ONLY the snapshot — unsigned sibling modules next to the
        // original script are no longer silently imported.
        var scriptBytes = File.ReadAllBytes(full);
        if (_policy.SignedOnly)
        {
            var sigPath = full + ".sig";
            if (!File.Exists(sigPath)) return ToolResult.Error("unsigned_refused", "signed-only policy is on and this script has no detached signature");
            byte[] sigBytes;
            try { sigBytes = Convert.FromBase64String(File.ReadAllText(sigPath).Trim()); }
            catch { return ToolResult.Error("bad_signature", "script .sig file is not base64"); }
            if (!_verifier.Verify(scriptBytes, sigBytes))
                return ToolResult.Error("bad_signature", "script signature does not verify");
        }
        var callerArgs = FileArgs.Str(arguments, "args") ?? "";
        // The args string rides a command line; a quote in it would
        // break out of the snapshot-path quoting — refused, not escaped.
        if (callerArgs.Contains('"')) return ToolResult.Error("bad_arguments", "args must not contain double-quote characters");
        var timeout = arguments.TryGetProperty("timeout_seconds", out var ts) ? ts.GetInt32() : 300;
        if (timeout <= 0 || timeout > MaxTimeoutSeconds)
            return ToolResult.Error("bad_arguments", $"timeout_seconds must be between 1 and {MaxTimeoutSeconds}");
        var ext = engine switch { "powershell" => ".ps1", "python" => ".py", "node" => ".js", _ => "" };
        if (ext == "") return ToolResult.Error("bad_arguments", engine);
        var snapshotDir = Path.Combine(ctx.DataDir, "script-snapshots");
        Directory.CreateDirectory(snapshotDir);
        var snapshot = Path.Combine(snapshotDir, Guid.NewGuid().ToString("N") + ext);
        File.WriteAllBytes(snapshot, scriptBytes);
        try
        {
            var (file, args) = engine switch
            {
                // PowerShell by absolute System32 path, never PATH-resolved.
                "powershell" => (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                    $"-NoProfile -NonInteractive -File \"{snapshot}\" {callerArgs}"),
                "python" => ("python", $"-I \"{snapshot}\" {callerArgs}"),
                "node" => ("node", $"\"{snapshot}\" {callerArgs}"),
                _ => ("", "")
            };
            var r = await _runner.RunAsync(file, args, TimeSpan.FromSeconds(timeout), ct);
            return r.ExitCode == 0 ? ToolResult.Success(r.StdOut) : ToolResult.Error("script_failed", r.StdErr + r.StdOut);
        }
        finally { try { File.Delete(snapshot); } catch { } }
    }
}

/// <summary>Census row 125: remote shell to OTHER hosts (ssh) with a
/// per-target allowlist. The agent never originates unauthenticated
/// sessions; credentials ride ssh's own agent/key files on the host.</summary>
public sealed class RemoteShellModule : IToolModule
{
    private readonly IProcessRunner _runner;
    private readonly IReadOnlySet<string> _targets;
    public RemoteShellModule(IProcessRunner runner, IReadOnlySet<string> targets) { _runner = runner; _targets = targets; }
    public ToolDescriptor Descriptor { get; } = new(
        "remote_shell", "Run a command on an allowlisted remote host over ssh (BatchMode; host keys/keys are the host's own).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"target":{"type":"string"},"command":{"type":"string"}},"required":["target","command"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var target = FileArgs.Str(arguments, "target") ?? "";
        if (!_targets.Contains(target)) return ToolResult.Error("not_allowlisted", $"target '{target}' is not on this host's remote-shell allowlist");
        var r = await _runner.RunAsync("ssh", $"-o BatchMode=yes -o ConnectTimeout=10 {target} \"{(FileArgs.Str(arguments, "command") ?? "").Replace("\"", "\\\"")}\"", TimeSpan.FromSeconds(120), ct);
        return r.ExitCode == 0 ? ToolResult.Success(r.StdOut) : ToolResult.Error("ssh_failed", r.StdErr);
    }
}

/// <summary>Census row 102: the plugin slot — install a signed tool
/// module assembly; it registers after signature verification and a
/// restart of Core (hot-loading arbitrary code mid-process is a
/// reliability and audit hazard this design declines).</summary>
public sealed class ToolModuleInstallModule : IToolModule
{
    private readonly string _pluginDir;
    private readonly IUpdateSignatureVerifier _verifier;
    private readonly ScriptSignaturePolicy _policy;
    public ToolModuleInstallModule(string dataDir, IUpdateSignatureVerifier verifier, ScriptSignaturePolicy policy)
    {
        _pluginDir = Path.Combine(dataDir, "plugins");
        Directory.CreateDirectory(_pluginDir);
        _verifier = verifier;
        _policy = policy;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "tool_module_install", "Install/list signed plugin tool-module assemblies. Modules activate at the next Core start.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","install"]},"assembly_path":{"type":"string"},"signature":{"type":"string"}}}""");

    /// <summary>Loads installed plugins at Core start; a module that
    /// fails to load is skipped and named in the result — never fatal.
    /// When signed-only is in force (the default), every DLL must
    /// carry the detached .sig written at install time and re-verify
    /// against the update key HERE, at load (2026-11-15 blocker fix:
    /// the original loader never re-verified, so anything dropped
    /// into the plugins dir ran as SYSTEM at next start).</summary>
    public static (IReadOnlyList<IToolModule> Modules, IReadOnlyList<string> Errors) LoadInstalled(string pluginDir, IUpdateSignatureVerifier? verifier = null, bool signedOnly = true)
    {
        var modules = new List<IToolModule>();
        var errors = new List<string>();
        if (!Directory.Exists(pluginDir)) return (modules, errors);
        foreach (var dll in Directory.EnumerateFiles(pluginDir, "*.dll"))
        {
            // TOCTOU (BD-WIN-CORE-2/F7): read the bytes ONCE; the same
            // snapshot is verified and loaded (Assembly.Load(bytes)),
            // never re-read from the path after the check.
            var dllBytes = File.ReadAllBytes(dll);
            if (signedOnly)
            {
                var sigPath = dll + ".sig";
                if (verifier is null) { errors.Add($"{Path.GetFileName(dll)}: signed-only is on but no signature verifier is configured — refused"); continue; }
                if (!File.Exists(sigPath)) { errors.Add($"{Path.GetFileName(dll)}: no detached signature — refused under signed-only policy"); continue; }
                byte[] sigBytes;
                try { sigBytes = Convert.FromBase64String(File.ReadAllText(sigPath).Trim()); }
                catch { errors.Add($"{Path.GetFileName(dll)}: detached signature is not base64 — refused"); continue; }
                if (!verifier.Verify(dllBytes, sigBytes)) { errors.Add($"{Path.GetFileName(dll)}: signature does not verify — refused"); continue; }
            }
            try
            {
                var asm = Assembly.Load(dllBytes);
                foreach (var type in asm.GetTypes().Where(t => typeof(IToolModule).IsAssignableFrom(t) && !t.IsAbstract))
                {
                    if (Activator.CreateInstance(type) is IToolModule m) modules.Add(m);
                    else errors.Add($"{Path.GetFileName(dll)}: {type.Name} has no parameterless constructor");
                }
            }
            catch (Exception ex) { errors.Add($"{Path.GetFileName(dll)}: {ex.GetType().Name}"); }
        }
        return (modules, errors);
    }

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        if (action == "list")
            return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(Directory.EnumerateFiles(_pluginDir, "*.dll").Select(Path.GetFileName))));
        var source = FileArgs.Path(arguments, "assembly_path");
        if (source is null || !File.Exists(source)) return Task.FromResult(ToolResult.Error("not_found", "assembly_path must be an existing file"));
        var sig = FileArgs.Str(arguments, "signature");
        // TOCTOU (F7): verify one byte snapshot and install THAT
        // snapshot — File.Copy would re-read the path after the check.
        var sourceBytes = File.ReadAllBytes(source);
        if (_policy.SignedOnly || sig is not null)
        {
            byte[] sigBytes;
            try { sigBytes = Convert.FromBase64String(sig ?? ""); }
            catch { return Task.FromResult(ToolResult.Error("bad_signature", "signature is not base64")); }
            if (!_verifier.Verify(sourceBytes, sigBytes))
                return Task.FromResult(ToolResult.Error("bad_signature", "plugin signature does not verify against the update key"));
        }
        var dest = Path.Combine(_pluginDir, Path.GetFileName(source));
        File.WriteAllBytes(dest, sourceBytes);
        // Persist the verified signature beside the DLL so the loader
        // can re-verify at Core start (LoadInstalled). A stale .sig
        // from a previous install of the same filename is removed when
        // this install carried none, so it can never bless new bytes.
        var sigDest = dest + ".sig";
        if (sig is not null) File.WriteAllText(sigDest, sig);
        else if (File.Exists(sigDest)) File.Delete(sigDest);
        return Task.FromResult(ToolResult.Success($"installed {Path.GetFileName(source)}; it activates at the next Core start"));
    }
}

/// <summary>Census row 90: browser control via Chrome DevTools Protocol
/// against a browser started with a debugging port. Target listing is
/// real; page automation rides the same CDP channel and grows at the
/// laptop gate — no fake DOM claims here.</summary>
public sealed class BrowserControlModule : IToolModule
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly IReadOnlySet<int> _allowedPorts;
    /// <summary>BD-WIN-CORE-2/F11: the port argument previously let a
    /// Drive-scope caller GET /json/list on ANY local port (a probe of
    /// whatever local service lived there). Ports are clamped to a
    /// configured allowlist — the CDP default plus host-configured
    /// debugging ports.</summary>
    public BrowserControlModule(IEnumerable<int>? allowedPorts = null) =>
        _allowedPorts = (allowedPorts ?? new[] { 9222 }).ToHashSet();
    public ToolDescriptor Descriptor { get; } = new(
        "browser_control", "CDP browser inspection: list debuggable targets of a browser running with --remote-debugging-port (targets ONLY — no page automation: no navigate/evaluate/screenshot over CDP). The port must be on the host's CDP allowlist.",
        Scopes.Drive, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["targets"]},"port":{"type":"integer","default":9222}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var port = arguments.TryGetProperty("port", out var p) ? p.GetInt32() : 9222;
        if (!_allowedPorts.Contains(port))
            return ToolResult.Error("port_not_allowlisted", $"port {port} is not on this host's CDP allowlist ({string.Join(", ", _allowedPorts.OrderBy(x => x))}); the port argument is not a general local-service probe");
        try
        {
            var json = await Http.GetStringAsync($"http://127.0.0.1:{port}/json/list", ct);
            return ToolResult.Success(json);
        }
        catch (Exception ex)
        {
            return ToolResult.Unavailable($"no CDP endpoint on 127.0.0.1:{port} ({ex.GetType().Name}) — the browser must be launched with --remote-debugging-port={port}");
        }
    }
}

/// <summary>Census row 101: protocol-layer credential use — NARROWED
/// at reconciliation and further constrained by the built vault: the
/// logon vault (ICredentialVault) is write/use-via-CP/wipe ONLY, with
/// no read path by construction (X4). Protocol-layer presentation
/// (cmdkey/net use) requires reading the secret back out, which this
/// host refuses to be able to do. The module therefore ships as an
/// honest refusal naming the conflict; the sanctioned paths are (1)
/// the credential-provider courier for logon, and (2) Credential
/// Manager entries the owner creates himself in Windows, which net use
/// then consumes without any agent ever holding the secret. Recorded
/// as a design-vs-code conflict in BUILD-REPORT.md.</summary>
public sealed class CredentialInjectServiceModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "credential_inject_service", "Protocol-layer credential use. UNAVAILABLE by construction: the vault has no read path (X4), so the agent cannot present stored secrets to protocols; use the CP courier for logon or self-created Credential Manager entries for shares.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, GateClass: "credential_inject", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"protocol":{"type":"string"},"target":{"type":"string"},"username":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Unavailable("refused by construction (X4): the vault exposes no read path, so no stored secret can be presented at a protocol layer. Logon uses the credential-provider courier; shares use Credential Manager entries created by the owner in Windows."));
}

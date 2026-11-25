using System.Text.Json;
using Acp.Core.Platform;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Modules;

/// <summary>
/// Census row 28: one-shot command as SYSTEM (machine context). The Core
/// runs as LocalSystem on Windows, so commands execute with machine
/// authority — no desktop, no user profile, no UAC layer above it
/// (DESIGN §1A.2). On the Linux build VM this runs under the dev user
/// and says so in its result; the context label is never faked.
/// </summary>
public sealed class ShellExecSystemModule : IToolModule
{
    private readonly IProcessRunner _runner;
    private readonly SignedCommandGate? _commandGate;

    /// <param name="commandGate">RMM-03 verify-gate. When wired
    /// (a customer command key is configured on this endpoint), a
    /// shell command executes ONLY as the payload of a verified
    /// signed-command envelope (class shell_exec) — an unsigned or
    /// altered command refuses even if the hub is compromised.
    /// When null, no customer key is configured and the module
    /// keeps its pre-RMM-03 posture (pairing scope + policy engine
    /// remain the gates); that state is named in CoreRuntime, never
    /// implied to be signed-command coverage.</param>
    public ShellExecSystemModule(IProcessRunner runner, SignedCommandGate? commandGate = null)
    {
        _runner = runner;
        _commandGate = commandGate;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "shell_exec_system", "Run one command in the SYSTEM (machine) context and return its output. No desktop, no user profile.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Critical, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"command":{"type":"string"},"timeout_seconds":{"type":"integer","default":60},"signed_command":{"type":"string","description":"RMM-03 signed-command envelope JSON; required when a customer command key is configured on this endpoint"}},"required":["command"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (arguments.ValueKind != JsonValueKind.Object || !arguments.TryGetProperty("command", out var cmdEl))
            return ToolResult.Error("bad_arguments", "shell_exec_system requires {command}");
        var command = cmdEl.GetString() ?? "";
        if (string.IsNullOrWhiteSpace(command)) return ToolResult.Error("bad_arguments", "command is empty");
        if (_commandGate is not null)
        {
            var envelope = SignedCommandEnvelope.FromJson(
                arguments.TryGetProperty("signed_command", out var sc) ? sc.GetString() : null);
            var verdict = _commandGate.Authorize(envelope, DateTimeOffset.UtcNow, SignedCommandClasses.ShellExec);
            if (!verdict.Allowed)
                return ToolResult.Error("signed_command_refused", verdict.Reason);
            // The executed command is the SIGNED payload, never the
            // unsigned argument: what runs is exactly what the
            // customer's key signed.
            command = System.Text.Encoding.UTF8.GetString(verdict.Payload!);
            if (string.IsNullOrWhiteSpace(command)) return ToolResult.Error("bad_arguments", "signed command payload is empty");
        }
        var timeout = arguments.TryGetProperty("timeout_seconds", out var t) ? Math.Clamp(t.GetInt32(), 1, 600) : 60;

        string file, args;
        if (OperatingSystem.IsWindows())
        {
            file = "powershell.exe";
            args = $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"";
        }
        else
        {
            file = "/bin/bash";
            args = $"-c \"{command.Replace("\"", "\\\"")}\"";
        }

        var result = await _runner.RunAsync(file, args, TimeSpan.FromSeconds(timeout), ct);
        var context = OperatingSystem.IsWindows() ? "SYSTEM" : $"dev-user ({Environment.UserName}) — NOT Windows SYSTEM; context parity is proven at the laptop gate";
        return ToolResult.Success(JsonSerializer.Serialize(new
        {
            exit_code = result.ExitCode,
            timed_out = result.TimedOut,
            execution_context = context,
            stdout = result.StdOut,
            stderr = result.StdErr
        }));
    }
}

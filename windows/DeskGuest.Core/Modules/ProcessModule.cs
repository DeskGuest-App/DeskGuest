using System.Diagnostics;
using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>Census row 44: process list with owning session (Core context).</summary>
public sealed class ProcessListModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "process_list", "List processes: name, PID, session id, memory.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"name_filter":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var filter = arguments.ValueKind == JsonValueKind.Object && arguments.TryGetProperty("name_filter", out var f) ? f.GetString() : null;
        var rows = new List<object>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (filter is not null && !p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
                rows.Add(new { name = p.ProcessName, pid = p.Id, session_id = p.SessionId, working_set_mb = Math.Round(p.WorkingSet64 / 1048576.0, 1) });
            }
            catch { /* processes vanish mid-enumeration; the list reports what it saw */ }
            finally { p.Dispose(); }
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(rows.OrderBy(r => r.ToString()), new JsonSerializerOptions { WriteIndented = true })));
    }
}

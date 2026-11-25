using System.Text.Json;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Modules;

/// <summary>
/// Scoped filesystem access (census rows 31/32/35). Every path is
/// resolved to a full path and must live under one of the configured
/// roots — the Phase 0 form of operation-granular file capabilities
/// (DESIGN §6.3). Path escapes are refused, never "helpfully" followed.
/// </summary>
public sealed class FileScope
{
    private readonly string[] _roots;
    public FileScope(IEnumerable<string> roots) =>
        _roots = roots.Select(r => Path.TrimEndingDirectorySeparator(Path.GetFullPath(r))).ToArray();

    public IReadOnlyList<string> Roots => _roots;

    public string? ResolveInScope(string path)
    {
        var full = Path.GetFullPath(path);
        if (!IsInScope(full)) return null;
        // BD-WIN-CORE-1 F7: reparse points (symlinks/junctions) are
        // RESOLVED before the scope verdict — a link inside a root
        // that points outside it no longer smuggles the target into
        // scope. The deepest existing component is resolved to its
        // final target; the non-existent remainder is re-appended
        // and the whole path is re-checked.
        var resolved = ResolveReparsePoints(full);
        return resolved is not null && IsInScope(resolved) ? resolved : null;
    }

    private bool IsInScope(string full)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var root in _roots)
        {
            if (full.Equals(root, comparison) || full.StartsWith(root + Path.DirectorySeparatorChar, comparison))
                return true;
        }
        return false;
    }

    private static string? ResolveReparsePoints(string full)
    {
        var current = full;
        for (var depth = 0; depth < 16; depth++)
        {
            // Find the deepest existing ancestor-or-self.
            var probe = current;
            var remainder = "";
            while (!File.Exists(probe) && !Directory.Exists(probe))
            {
                var parent = Path.GetDirectoryName(probe);
                if (parent is null) return current; // nothing exists: lexical path stands
                remainder = Path.Combine(Path.GetFileName(probe), remainder);
                probe = parent;
            }
            FileSystemInfo info = Directory.Exists(probe) ? new DirectoryInfo(probe) : new FileInfo(probe);
            var target = info.ResolveLinkTarget(returnFinalTarget: true);
            if (target is null) return current; // not a link (or final target is itself)
            current = Path.GetFullPath(Path.Combine(target.FullName, remainder));
        }
        return null; // link chain too deep: refuse
    }
}

public sealed class FileReadModule : IToolModule
{
    private readonly FileScope _scope;
    public FileReadModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_read", "Read a text file under a configured root.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = arguments.TryGetProperty("path", out var p) ? p.GetString() : null;
        if (path is null) return ToolResult.Error("bad_arguments", "file_read requires {path}");
        var full = _scope.ResolveInScope(path);
        if (full is null) return ToolResult.Error("out_of_scope", $"path is outside the configured roots ({string.Join(", ", _scope.Roots)})");
        if (!File.Exists(full)) return ToolResult.Error("not_found", $"no file at {full}");
        var info = new FileInfo(full);
        if (info.Length > 1024 * 1024) return ToolResult.Error("too_large", "file exceeds the 1 MB Phase 0 read cap; use file_transfer (Phase 1)");
        return ToolResult.Success(await File.ReadAllTextAsync(full, ct));
    }
}

public sealed class FileWriteModule : IToolModule
{
    private readonly FileScope _scope;
    public FileWriteModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_write", "Create, overwrite, or append a text file under a configured root.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"mode":{"type":"string","enum":["create","overwrite","append"],"default":"overwrite"}},"required":["path","content"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = arguments.TryGetProperty("path", out var p) ? p.GetString() : null;
        var content = arguments.TryGetProperty("content", out var c) ? c.GetString() : null;
        if (path is null || content is null) return ToolResult.Error("bad_arguments", "file_write requires {path, content}");
        var full = _scope.ResolveInScope(path);
        if (full is null) return ToolResult.Error("out_of_scope", "path is outside the configured roots");
        var mode = arguments.TryGetProperty("mode", out var m) ? m.GetString() : "overwrite";
        // BD-WIN-CORE-1 F7: overwriting an existing file destroys
        // its previous content — the deletions gate applies.
        if (mode is not "append" and not "create" && File.Exists(full) && !ctx.ApprovedGateClasses.Contains("deletions"))
            return ToolResult.Error("gated:deletions", "overwriting an existing file replaces it; the deletions gate class must be approved (use mode=append or mode=create where they fit)");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        switch (mode)
        {
            case "create" when File.Exists(full):
                return ToolResult.Error("exists", "mode=create but the file exists");
            case "append":
                await File.AppendAllTextAsync(full, content, ct);
                break;
            default:
                await File.WriteAllTextAsync(full, content, ct);
                break;
        }
        return ToolResult.Success($"wrote {content.Length} chars to {full} (mode={mode})");
    }
}

public sealed class FileListModule : IToolModule
{
    private readonly FileScope _scope;
    public FileListModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_list", "List a directory under a configured root.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = arguments.TryGetProperty("path", out var p) ? p.GetString() : null;
        if (path is null) return Task.FromResult(ToolResult.Error("bad_arguments", "file_list requires {path}"));
        var full = _scope.ResolveInScope(path);
        if (full is null) return Task.FromResult(ToolResult.Error("out_of_scope", "path is outside the configured roots"));
        if (!Directory.Exists(full)) return Task.FromResult(ToolResult.Error("not_found", $"no directory at {full}"));
        var entries = Directory.EnumerateFileSystemEntries(full).Select(e =>
        {
            var fi = new FileInfo(e);
            return new { name = Path.GetFileName(e), is_dir = Directory.Exists(e), size = Directory.Exists(e) ? (long?)null : fi.Length };
        });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true })));
    }
}

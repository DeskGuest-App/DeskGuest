using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>Shared argument/path plumbing for the file modules.</summary>
internal static class FileArgs
{
    public static string? Path(JsonElement args, string name = "path") =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var p) ? p.GetString() : null;
    public static string? Str(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var p) ? p.GetString() : null;
}

public sealed class FileSearchModule : IToolModule
{
    private readonly FileScope _scope;
    public FileSearchModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_search", "Search by name (and optionally content) under a root.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"root":{"type":"string"},"name_contains":{"type":"string"},"content_contains":{"type":"string"},"max_results":{"type":"integer","default":100}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var rootArg = FileArgs.Path(arguments, "root") ?? _scope.Roots[0];
        var root = _scope.ResolveInScope(rootArg);
        if (root is null) return Task.FromResult(ToolResult.Error("out_of_scope", "root is outside the configured roots"));
        var nameContains = FileArgs.Str(arguments, "name_contains");
        var contentContains = FileArgs.Str(arguments, "content_contains");
        var max = arguments.TryGetProperty("max_results", out var m) ? Math.Clamp(m.GetInt32(), 1, 1000) : 100;
        var hits = new List<string>();
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (hits.Count >= max) break;
            if (nameContains is not null && !Path.GetFileName(file).Contains(nameContains, StringComparison.OrdinalIgnoreCase)) continue;
            if (contentContains is not null)
            {
                try { if (!File.ReadAllText(file).Contains(contentContains, StringComparison.Ordinal)) continue; }
                catch { continue; }
            }
            hits.Add(file);
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(hits, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class FileInfoModule : IToolModule
{
    private readonly FileScope _scope;
    public FileInfoModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_info", "Size, times, and attributes for a path in scope.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = FileArgs.Path(arguments);
        var full = path is null ? null : _scope.ResolveInScope(path);
        if (full is null) return Task.FromResult(ToolResult.Error("out_of_scope", "path is outside the configured roots"));
        if (!File.Exists(full) && !Directory.Exists(full)) return Task.FromResult(ToolResult.Error("not_found", full));
        var fi = new FileInfo(full);
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            path = full, is_dir = Directory.Exists(full),
            size = Directory.Exists(full) ? (long?)null : fi.Length,
            created_utc = fi.CreationTimeUtc, modified_utc = fi.LastWriteTimeUtc,
            attributes = fi.Attributes.ToString()
        }, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class FileCopyMoveModule : IToolModule
{
    private readonly FileScope _scope;
    private readonly bool _move;
    public FileCopyMoveModule(FileScope scope, bool move) { _scope = scope; _move = move; }
    public ToolDescriptor Descriptor => new(
        _move ? "file_move" : "file_copy", _move ? "Move a file within scope." : "Copy a file within scope.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"source":{"type":"string"},"destination":{"type":"string"}},"required":["source","destination"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var src = FileArgs.Path(arguments, "source");
        var dst = FileArgs.Path(arguments, "destination");
        var s = src is null ? null : _scope.ResolveInScope(src);
        var d = dst is null ? null : _scope.ResolveInScope(dst);
        if (s is null || d is null) return Task.FromResult(ToolResult.Error("out_of_scope", "both paths must be inside the configured roots"));
        if (!File.Exists(s)) return Task.FromResult(ToolResult.Error("not_found", s));
        // BD-WIN-CORE-1 F7: overwriting an existing destination is a
        // deletion of its previous content — the deletions gate
        // applies, checked here where the overwrite is known.
        if (File.Exists(d) && !ctx.ApprovedGateClasses.Contains("deletions"))
            return Task.FromResult(ToolResult.Error("gated:deletions", "overwriting an existing file replaces it; the deletions gate class must be approved"));
        Directory.CreateDirectory(Path.GetDirectoryName(d)!);
        if (_move) File.Move(s, d, overwrite: true); else File.Copy(s, d, overwrite: true);
        return Task.FromResult(ToolResult.Success($"{(_move ? "moved" : "copied")} {s} → {d}"));
    }
}

/// <summary>Census row 37: deletions are a gated class in every
/// approval mode. Recursive delete only as an explicit flag.</summary>
public sealed class FileDeleteModule : IToolModule
{
    private readonly FileScope _scope;
    public FileDeleteModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_delete", "Delete a file (or, with recursive=true, a directory) in scope. Gated class: deletions.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Critical, GateClass: "deletions", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"path":{"type":"string"},"recursive":{"type":"boolean","default":false}},"required":["path"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var path = FileArgs.Path(arguments);
        var full = path is null ? null : _scope.ResolveInScope(path);
        if (full is null) return Task.FromResult(ToolResult.Error("out_of_scope", "path is outside the configured roots"));
        var recursive = arguments.TryGetProperty("recursive", out var r) && r.ValueKind == JsonValueKind.True;
        if (Directory.Exists(full))
        {
            if (!recursive) return Task.FromResult(ToolResult.Error("is_directory", "path is a directory; pass recursive=true to delete it"));
            Directory.Delete(full, recursive: true);
            return Task.FromResult(ToolResult.Success($"deleted directory {full}"));
        }
        if (!File.Exists(full)) return Task.FromResult(ToolResult.Error("not_found", full));
        File.Delete(full);
        return Task.FromResult(ToolResult.Success($"deleted {full}"));
    }
}

/// <summary>Census row 39: chunked transfer with hash verification.
/// begin → write_chunk(s) → commit verifies SHA-256 of the assembled
/// file against the declared hash; a mismatch deletes the partial and
/// reports — a transfer is never silently half-right.</summary>
public sealed class FileTransferModule : IToolModule
{
    private readonly FileScope _scope;
    private readonly string _transferDir;
    // BD-WIN-CORE-1 F5: transfer state is concurrent (MCP calls are
    // concurrent), capped, and expiring — a transfer may assemble at
    // most MaxTransferBytes and must commit within TransferLifetime.
    public const long MaxTransferBytes = 64L * 1024 * 1024;
    public static readonly TimeSpan TransferLifetime = TimeSpan.FromMinutes(30);
    private readonly ConcurrentDictionary<string, (string Target, string ExpectedHash, long Bytes, DateTimeOffset CreatedUtc)> _open = new();

    public FileTransferModule(FileScope scope, string dataDir)
    {
        _scope = scope;
        _transferDir = Path.Combine(dataDir, "transfers");
        Directory.CreateDirectory(_transferDir);
    }

    public ToolDescriptor Descriptor { get; } = new(
        "file_transfer", "Chunked upload with SHA-256 verification: {action: begin|chunk|commit|abort}.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string"},"transfer_id":{"type":"string"},"destination":{"type":"string"},"sha256":{"type":"string"},"data_base64":{"type":"string"}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "";
        switch (action)
        {
            case "begin":
            {
                var dest = FileArgs.Path(arguments, "destination");
                var full = dest is null ? null : _scope.ResolveInScope(dest);
                if (full is null) return ToolResult.Error("out_of_scope", "destination is outside the configured roots");
                var hash = FileArgs.Str(arguments, "sha256");
                if (hash is null) return ToolResult.Error("bad_arguments", "begin requires the declared sha256 of the complete file");
                SweepExpired();
                var id = Guid.NewGuid().ToString("N");
                await File.WriteAllBytesAsync(PartPath(id), Array.Empty<byte>(), ct);
                _open[id] = (full, hash, 0, DateTimeOffset.UtcNow);
                return ToolResult.Success(JsonSerializer.Serialize(new { transfer_id = id }));
            }
            case "chunk":
            {
                var id = FileArgs.Str(arguments, "transfer_id") ?? "";
                if (!_open.TryGetValue(id, out var t)) return ToolResult.Error("unknown_transfer", id);
                var data = FileArgs.Str(arguments, "data_base64");
                if (data is null) return ToolResult.Error("bad_arguments", "chunk requires data_base64");
                var bytes = Convert.FromBase64String(data);
                // BD-WIN-CORE-1 F5: byte quota — an endless chunk
                // stream can no longer fill the disk under SYSTEM.
                if (t.Bytes + bytes.Length > MaxTransferBytes)
                {
                    _open.TryRemove(id, out _);
                    try { File.Delete(PartPath(id)); } catch { }
                    return ToolResult.Error("quota_exceeded", $"transfer exceeds the {MaxTransferBytes}-byte cap; aborted and partial deleted");
                }
                using (var fs = new FileStream(PartPath(id), FileMode.Append, FileAccess.Write))
                    await fs.WriteAsync(bytes, ct);
                _open[id] = (t.Target, t.ExpectedHash, t.Bytes + bytes.Length, t.CreatedUtc);
                return ToolResult.Success($"chunk accepted ({t.Bytes + bytes.Length} bytes so far)");
            }
            case "commit":
            {
                var id = FileArgs.Str(arguments, "transfer_id") ?? "";
                if (!_open.TryRemove(id, out var t)) return ToolResult.Error("unknown_transfer", id);
                // BD-WIN-CORE-1 F5: the hash stream is DISPOSED before
                // the move/delete — on Windows an open FileShare.Read
                // handle blocks both, so every commit used to fail.
                string actual;
                await using (var fs = File.OpenRead(PartPath(id)))
                    actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct));
                if (!actual.Equals(t.ExpectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(PartPath(id));
                    return ToolResult.Error("hash_mismatch", $"assembled file hashes to {actual}, declared {t.ExpectedHash}; partial deleted, nothing written");
                }
                // BD-WIN-CORE-1 F7: committing over an existing file
                // replaces it — the deletions gate applies.
                if (File.Exists(t.Target) && !ctx.ApprovedGateClasses.Contains("deletions"))
                {
                    try { File.Delete(PartPath(id)); } catch { }
                    return ToolResult.Error("gated:deletions", "committing over an existing file replaces it; the deletions gate class must be approved (transfer discarded)");
                }
                Directory.CreateDirectory(Path.GetDirectoryName(t.Target)!);
                File.Move(PartPath(id), t.Target, overwrite: true);
                return ToolResult.Success($"transfer committed: {t.Bytes} bytes → {t.Target} (sha256 verified)");
            }
            case "abort":
            {
                var id = FileArgs.Str(arguments, "transfer_id") ?? "";
                if (_open.TryRemove(id, out _)) { try { File.Delete(PartPath(id)); } catch { } }
                return ToolResult.Success("transfer aborted");
            }
            default:
                return ToolResult.Error("bad_arguments", $"unknown transfer action '{action}'");
        }
    }

    private string PartPath(string id) => Path.Combine(_transferDir, id + ".part");

    /// <summary>BD-WIN-CORE-1 F5: expired transfers lose their state
    /// AND their .part files — a restart or an abandoned begin no
    /// longer orphans partials in the data dir forever. (State is
    /// still in-memory; the sweep bounds the on-disk residue to one
    /// lifetime window after the last begin.)</summary>
    private void SweepExpired()
    {
        var cutoff = DateTimeOffset.UtcNow - TransferLifetime;
        foreach (var (id, t) in _open)
            if (t.CreatedUtc < cutoff && _open.TryRemove(id, out _))
                try { File.Delete(PartPath(id)); } catch { }
        try
        {
            foreach (var f in Directory.EnumerateFiles(_transferDir, "*.part"))
                if (File.GetLastWriteTimeUtc(f) < cutoff.UtcDateTime)
                    try { File.Delete(f); } catch { }
        }
        catch { /* the dir was just created in the ctor; enumeration failure is not fatal */ }
    }
}

/// <summary>Census row 40: the managed staging store — hand-off
/// folders (incl. the bridge queue) with retention rules.</summary>
public sealed class StagingStoreModule : IToolModule
{
    private readonly FileScope _scope;
    public StagingStoreModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "staging_store", "List the managed staging store and enforce its retention rule (default 30 days).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","prune"]},"retention_days":{"type":"integer","default":30}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var root = _scope.Roots[0];
        var action = FileArgs.Str(arguments, "action") ?? "list";
        if (action == "prune")
        {
            // BD-WIN-CORE-1 F7: prune DELETES files — the deletions
            // gate applies (it previously ran ungated for any
            // retention, including 0/negative = delete everything).
            if (!ctx.ApprovedGateClasses.Contains("deletions"))
                return Task.FromResult(ToolResult.Error("gated:deletions", "staging prune deletes files; the deletions gate class must be approved"));
            var days = arguments.TryGetProperty("retention_days", out var d) ? d.GetInt32() : 30;
            if (days < 1) return Task.FromResult(ToolResult.Error("bad_arguments", "retention_days must be at least 1"));
            var cutoff = DateTime.UtcNow - TimeSpan.FromDays(days);
            var pruned = 0;
            foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                if (File.GetLastWriteTimeUtc(f) < cutoff) { File.Delete(f); pruned++; }
            return Task.FromResult(ToolResult.Success($"pruned {pruned} file(s) older than {days} days from {root}"));
        }
        var entries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
            .Select(e => new { path = e, size = Directory.Exists(e) ? (long?)null : new FileInfo(e).Length, modified_utc = File.GetLastWriteTimeUtc(e) });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true })));
    }
}

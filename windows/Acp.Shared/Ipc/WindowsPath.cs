namespace Acp.Shared.Ipc;

/// <summary>
/// String-based WINDOWS path semantics for the IPC trust decisions
/// (W10 / V2-C3). These decisions are always about Windows paths —
/// OS-reported image paths from the Windows pipe APIs — but the
/// pure decision functions are pinned by tests running on the Linux
/// build VM, where System.IO.Path treats "C:\…" as a relative
/// Unix path. Normalizing here keeps the decision identical on
/// every host: slashes unified, trailing separators trimmed,
/// fully-qualified means a drive-letter root (C:\…) or a UNC root
/// (\\server\share\…). Deliberately minimal: no dot-segment
/// resolution (OS-reported image paths are canonical already).
/// </summary>
public static class WindowsPath
{
    public static string Normalize(string path) =>
        path.Replace('/', '\\').TrimEnd('\\');

    public static bool IsFullyQualified(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Replace('/', '\\');
        if (p.StartsWith(@"\\", StringComparison.Ordinal)) return p.Length > 2; // UNC
        return p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\';
    }

    public static string FileName(string path)
    {
        var p = Normalize(path);
        var idx = p.LastIndexOf('\\');
        return idx >= 0 ? p[(idx + 1)..] : p;
    }

    /// <summary>Full-path equality under Windows semantics
    /// (case-insensitive, slash-unified).</summary>
    public static bool EqualsFull(string? a, string? b) =>
        a is not null && b is not null &&
        string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>W28: LEXICAL canonicalisation — slash unification
    /// plus dot-segment resolution ("." dropped, ".." pops the
    /// previous segment, never above the root) and duplicate-
    /// separator collapse. This is the string half of canonical
    /// comparison; the filesystem half (symlink / junction
    /// resolution) lives in InstallTrust.CanonicalizeImagePath,
    /// which feeds each path through a link resolver BEFORE this
    /// lexical pass. Two spellings of one image must compare equal
    /// here, and a spelling that escapes its directory with ".."
    /// must land on the path it actually names.</summary>
    public static string Canonicalize(string path)
    {
        var p = path.Replace('/', '\\');
        string root;
        string rest;
        if (p.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // UNC: \\server\share is the root; segments follow it.
            var parts = p.Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return @"\\" + string.Join('\\', parts);
            root = @"\\" + parts[0] + "\\" + parts[1];
            rest = string.Join('\\', parts.Skip(2));
        }
        else if (p.Length >= 2 && p[1] == ':')
        {
            root = p[..2] + "\\";
            rest = p.Length > 3 ? p[3..] : "";
        }
        else
        {
            root = "";
            rest = p;
        }
        var segments = new List<string>();
        foreach (var seg in rest.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..") { if (segments.Count > 0) segments.RemoveAt(segments.Count - 1); continue; }
            segments.Add(seg);
        }
        return root + string.Join('\\', segments);
    }

    /// <summary>Canonical full-path equality (W28): lexical
    /// canonicalisation, then the usual case-insensitive compare.</summary>
    public static bool EqualsCanonical(string? a, string? b) =>
        a is not null && b is not null &&
        string.Equals(Canonicalize(a), Canonicalize(b), StringComparison.OrdinalIgnoreCase);
}

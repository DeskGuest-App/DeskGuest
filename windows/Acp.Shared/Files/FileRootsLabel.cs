namespace Acp.Shared.Files;

/// <summary>
/// FR-113 (W65): the Guardrails page's FileSystem label is GENERATED
/// from the Core's effective configured roots — never a hard-coded
/// claim. The Core reports its effective roots (the configured
/// ACP_FILE_ROOTS, or the staging-only fallback when none are
/// configured) in the host-state snapshot; the window renders
/// exactly this text. The word "unscoped" is never produced here:
/// the scope is always stated as the concrete folder list, and the
/// staging-only fallback says so plainly.
/// </summary>
public static class FileRootsLabel
{
    /// <summary>Chip text + detail line for the Guardrails
    /// FileSystem row, generated from the effective roots.</summary>
    public static (string Chip, string Detail) Generate(IReadOnlyList<string>? effectiveRoots)
    {
        if (effectiveRoots is null || effectiveRoots.Count == 0)
            return ("Not reported",
                "The Core has not reported its file scope yet — the label appears when it does. Nothing is claimed here until then.");
        var roots = effectiveRoots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (roots.Length == 0)
            return ("Not reported",
                "The Core has not reported its file scope yet — the label appears when it does. Nothing is claimed here until then.");
        var stagingOnly = roots.Length == 1 && roots[0].Replace('/', '\\').TrimEnd('\\').EndsWith("staging", StringComparison.OrdinalIgnoreCase);
        if (stagingOnly)
            return ("Staging folder only",
                $"File tools are confined to the staging folder: {roots[0]}. No other folder on this PC is in scope.");
        return ($"Allowed in {roots.Length} folder{(roots.Length == 1 ? "" : "s")}",
            "File tools may only work inside these folders: " + string.Join(" · ", roots));
    }
}

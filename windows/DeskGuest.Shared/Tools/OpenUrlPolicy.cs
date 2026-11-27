namespace DeskGuest.Shared.Tools;

/// <summary>
/// BD-WIN-AGENT F10: open_url's scope contract. Before this, any
/// string went to ShellExecute — local paths, .exe/.lnk/.bat files,
/// file:// links and protocol handlers (ms-settings:, search-ms:) —
/// making open_url an unrestricted app_launch under a lighter name.
/// open_url is a BROWSER act: only http, https and mailto are
/// allowed; everything else is refused with a pointer to app_launch,
/// which carries the heavier scope.
/// </summary>
public static class OpenUrlPolicy
{
    public static readonly IReadOnlySet<string> AllowedSchemes =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https", "mailto" };

    /// <summary>Null when the value may be opened as a URL; otherwise
    /// the refusal text (which names app_launch as the right tool).</summary>
    public static string? RefusalFor(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return "open_url requires {url}";
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return $"refused: '{url}' is not an absolute URL; open_url opens http/https/mailto only — use app_launch for programs and files";
        if (!AllowedSchemes.Contains(uri.Scheme))
            return $"refused: open_url does not open '{uri.Scheme}:' targets (files, programs and protocol handlers belong to app_launch, which carries that scope)";
        if ((uri.Scheme == "http" || uri.Scheme == "https") && string.IsNullOrEmpty(uri.Host))
            return "refused: the URL has no host";
        return null;
    }

    public static bool IsAllowed(string? url) => RefusalFor(url) is null;
}

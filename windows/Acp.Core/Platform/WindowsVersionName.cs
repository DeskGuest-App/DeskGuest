using System.Text.RegularExpressions;

namespace Acp.Core.Platform;

/// <summary>
/// FR-129: the registry's ProductName is NOT a version source —
/// Microsoft never updated it for Windows 11, so a Windows 11
/// machine (build 22000+) still reports "Windows 10 Home" there,
/// and endpoint_state repeated the lie (a build 26300 machine
/// reported as Windows 10). The version NAME is derived from the
/// build number, which is the field Windows actually advances:
/// the ProductName contributes only the edition suffix (Home /
/// Pro / Enterprise / …), never the version.
///
/// Derivation (build-derived, not a string swap — the next
/// version boundary is a new build range, and a name carrying no
/// 10/11 token, e.g. a Server SKU, passes through untouched):
///   build >= 22000          -> Windows 11
///   10240 <= build < 22000  -> Windows 10
///   build < 10240 / unknown -> ProductName verbatim (pre-10
///                              naming was honest; an unreadable
///                              build must not invent a version)
/// </summary>
public static class WindowsVersionName
{
    public const int Windows10FirstBuild = 10240;
    public const int Windows11FirstBuild = 22000;

    private static readonly Regex VersionToken = new(
        @"^Windows (?:10|11)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <param name="productName">The registry ProductName (the
    /// edition source; its version token is NOT trusted).</param>
    /// <param name="currentBuild">The registry CurrentBuildNumber,
    /// or a value &lt;= 0 when it could not be read.</param>
    public static string FromProductName(string? productName, int currentBuild)
    {
        if (string.IsNullOrWhiteSpace(productName)) return "unknown";
        var name = productName.Trim();
        var derived = currentBuild >= Windows11FirstBuild ? "Windows 11"
            : currentBuild >= Windows10FirstBuild ? "Windows 10"
            : null;
        if (derived is null) return name;
        // Replace the (possibly stale) version token; a name with
        // no 10/11 token keeps its own naming entirely.
        return VersionToken.IsMatch(name)
            ? VersionToken.Replace(name, derived, 1)
            : name;
    }
}

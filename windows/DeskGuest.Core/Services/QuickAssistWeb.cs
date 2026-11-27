using System.Security.Cryptography;

namespace DeskGuest.Core.Services;

/// <summary>
/// C18 — the quick-assist front door, SERVED by the endpoint.
///
/// The page itself (agent-control-app/quick-assist-web/: index.html +
/// app.js) is embedded into DeskGuest.Core as manifest resources at build
/// time, straight from the repo files (see DeskGuest.Core.csproj), so the
/// served copy can never drift from the repo copy. Serving is an
/// exact-path allowlist of those two assets — there is NO static-file
/// middleware and NO directory surface: a path is answered only if it
/// is one of the known door paths, after one percent-decode, and any
/// traversal/separator trick fails the match and gets a bare 404.
///
/// The door is a door, not a hole. The page holds no secrets, no
/// roster, no session state, and grants nothing by being served: the
/// one-time code redemption (POST /mesh/quickassist/redeem, in
/// LaneHostManager.MapMesh) remains the only gate, exactly as before.
/// An unauthenticated visitor receives these two public files and
/// nothing else. If the embedded resources are somehow absent, the
/// door fails closed (404), never open.
/// </summary>
public static class QuickAssistWeb
{
    /// <summary>One servable asset: content type, exact bytes, and the
    /// SHA-256 of those bytes (hex, lowercase) for hash-equality proofs.</summary>
    public sealed record Asset(string ContentType, byte[] Body, string Sha256Hex);

    private const string IndexResource = "DeskGuest.Core.QuickAssist.index.html";
    private const string AppJsResource = "DeskGuest.Core.QuickAssist.app.js";

    private static readonly Lazy<Asset?> IndexAsset = new(() => Load(IndexResource, "text/html; charset=utf-8"));
    private static readonly Lazy<Asset?> AppJsAsset = new(() => Load(AppJsResource, "text/javascript; charset=utf-8"));

    /// <summary>The complete list of paths the door answers. Anything
    /// not listed here — including every other repo file in
    /// quick-assist-web/ (e.g. README.md) — is not served.</summary>
    public static IReadOnlyList<string> ServedPaths { get; } = new[]
    {
        "/quickassist",
        "/quickassist/",
        "/quickassist/index.html",
        "/quickassist/app.js",
    };

    /// <summary>Headers set on every served response. Deliberately no
    /// Server / X-Powered-By style fingerprinting headers are ever
    /// added here.</summary>
    public static IReadOnlyDictionary<string, string> ResponseHeaders { get; } =
        new Dictionary<string, string>
        {
            ["Cache-Control"] = "no-store",
            ["X-Content-Type-Options"] = "nosniff",
            ["Referrer-Policy"] = "no-referrer",
        };

    /// <summary>
    /// The whole routing decision for the front door, as a pure
    /// function so it is provable at the handler level without a
    /// socket. Returns true with status 200 and the asset for a known
    /// door path on GET/HEAD; otherwise false with the status the
    /// caller should answer (404 unknown path, 405 wrong method) and
    /// a null asset — the caller writes an empty body, leaking
    /// nothing about what exists.
    /// </summary>
    public static bool TryServe(string method, string? rawPath, out int status, out Asset? asset)
    {
        status = 404;
        asset = null;
        if (!string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            status = 405;
            return false;
        }
        if (string.IsNullOrEmpty(rawPath)) return false;

        string path;
        try { path = Uri.UnescapeDataString(rawPath); }
        catch { return false; }

        // Separator/traversal tricks never reach the allowlist. The
        // allowlist match below is exact and ordinal, so these would
        // fail anyway — refusing them here keeps the intent explicit
        // and auditable.
        if (path.Contains('\\') || path.Contains("..") || path.Contains("//") || path.Contains('\0'))
            return false;

        switch (path)
        {
            case "/quickassist":
            case "/quickassist/":
            case "/quickassist/index.html":
                asset = IndexAsset.Value;
                break;
            case "/quickassist/app.js":
                asset = AppJsAsset.Value;
                break;
            default:
                return false;
        }
        if (asset is null) return false; // embedded resource missing: fail closed
        status = 200;
        return true;
    }

    private static Asset? Load(string logicalName, string contentType)
    {
        using var stream = typeof(QuickAssistWeb).Assembly.GetManifestResourceStream(logicalName);
        if (stream is null) return null;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var body = ms.ToArray();
        return new Asset(contentType, body,
            Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant());
    }
}

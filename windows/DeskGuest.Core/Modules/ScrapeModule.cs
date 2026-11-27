using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>
/// Census row 30: fetch a URL FROM the laptop as text/markdown, with
/// the incumbent's SSRF guard discipline adopted (AUDIT): http/https
/// only, DNS resolved and checked, private/loopback/link-local and
/// cloud-metadata addresses refused unless the host config explicitly
/// allowlists them. Redirects are re-checked hop by hop.
/// </summary>
public sealed partial class ScrapeModule : IToolModule
{
    private readonly IReadOnlySet<string> _allowlist;
    private readonly HttpClient _http;

    public ScrapeModule(IReadOnlySet<string>? allowlist = null)
    {
        _allowlist = allowlist ?? new HashSet<string>();
        // BD-WIN-CORE-1 F8: the SSRF guard is enforced at CONNECT
        // time on the address actually dialed (ConnectCallback) —
        // the pre-flight DNS check alone left a DNS-rebinding window
        // between resolution and connect. The callback resolves,
        // classifies, and connects to a checked address itself.
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = async (context, ct) =>
            {
                var host = context.DnsEndPoint.Host;
                var addresses = await Dns.GetHostAddressesAsync(host, ct);
                if (!_allowlist.Contains(host))
                    foreach (var addr in addresses)
                        if (IsPrivateOrSpecial(addr))
                            throw new HttpRequestException($"host '{host}' resolves to {addr}, a private/special address — refused at connect (SSRF guard)");
                foreach (var addr in addresses)
                {
                    var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try { await socket.ConnectAsync(addr, context.DnsEndPoint.Port, ct); return new NetworkStream(socket, ownsSocket: true); }
                    catch { socket.Dispose(); }
                }
                throw new HttpRequestException($"host '{host}' could not be connected on any resolved address");
            }
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>Load the host-config allowlist (BD-WIN-CORE-1 F8:
    /// scrape-allowlist.txt in the data dir, one host per line,
    /// #-comments). Absent file = empty allowlist.</summary>
    public static IReadOnlySet<string> LoadAllowlist(string dataDir)
    {
        try
        {
            var path = Path.Combine(dataDir, "scrape-allowlist.txt");
            if (!File.Exists(path)) return new HashSet<string>();
            return File.ReadAllLines(path).Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('#'))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch { return new HashSet<string>(); }
    }

    public ToolDescriptor Descriptor { get; } = new(
        "scrape", "Fetch a URL from the laptop and return readable text. SSRF-guarded: private/metadata addresses refused unless allowlisted.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}""");

    /// <summary>The guard, separated so it is unit-testable without network.</summary>
    public async Task<string?> GuardErrorAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return "url is not absolute";
        if (uri.Scheme is not ("http" or "https")) return $"scheme '{uri.Scheme}' is not fetchable";
        if (_allowlist.Contains(uri.Host)) return null;
        IPAddress[] addresses;
        try { addresses = await Dns.GetHostAddressesAsync(uri.Host, ct); }
        catch (SocketException) { return $"host '{uri.Host}' does not resolve"; }
        foreach (var addr in addresses)
        {
            if (IsPrivateOrSpecial(addr))
                return $"host '{uri.Host}' resolves to {addr}, a private/special address — refused (SSRF guard). Allowlist it in host config if this is deliberate.";
        }
        return null;
    }

    public static bool IsPrivateOrSpecial(IPAddress addr)
    {
        // BD-WIN-CORE-1 F8: IPv4-mapped IPv6 is classified as the
        // IPv4 it carries (::ffff:10.0.0.1 is 10.0.0.1).
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        if (IPAddress.IsLoopback(addr)) return true;
        if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any)) return true;
        if (addr.IsIPv6Multicast) return true;
        var b = addr.GetAddressBytes();
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if ((b[0] & 0xFE) == 0xFC) return true; // fc00::/7 unique-local
        }
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true; // link-local incl. cloud metadata 169.254.169.254
            if (b[0] == 100 && (b[1] & 0xC0) == 0x40) return true; // tailnet CGNAT: the laptop's own mesh is not a scrape target
            if (b[0] == 0) return true;
            if (b[0] >= 224) return true; // multicast (224/4) + broadcast 255.255.255.255
        }
        if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return true;
        return false;
    }

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var url = FileArgs.Str(arguments, "url") ?? "";
        var current = url;
        for (var hop = 0; hop <= 5; hop++)
        {
            if (await GuardErrorAsync(current, ct) is { } error)
                return ToolResult.Error("ssrf_guard", error);
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            req.Headers.UserAgent.ParseAdd("DeskGuest-Windows scrape (agent tool, host-side fetch)");
            // BD-WIN-CORE-1 F8: headers-first + a hard byte cap —
            // the body is no longer buffered whole before the cut.
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
            {
                current = new Uri(new Uri(current), loc).ToString();
                continue;
            }
            await using var stream = await resp.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[256 * 1024];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
                if (n == 0) break;
                read += n;
            }
            var html = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
            return ToolResult.Success(HtmlToText(html));
        }
        return ToolResult.Error("too_many_redirects", "more than 5 redirects");
    }

    [GeneratedRegex("<script[\\s\\S]*?</script>|<style[\\s\\S]*?</style>", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptStyle();
    [GeneratedRegex("<[^>]+>")]
    private static partial Regex Tags();
    [GeneratedRegex("\\s+")]
    private static partial Regex Whitespace();

    public static string HtmlToText(string html)
    {
        var noScripts = ScriptStyle().Replace(html, " ");
        var noTags = Tags().Replace(noScripts, " ");
        var decoded = WebUtility.HtmlDecode(noTags);
        var text = Whitespace().Replace(decoded, " ").Trim();
        return text.Length <= 100_000 ? text : text[..100_000] + "\n[truncated at 100k chars]";
    }
}

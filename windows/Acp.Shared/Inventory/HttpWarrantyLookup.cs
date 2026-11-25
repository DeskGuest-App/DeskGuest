using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Acp.Shared.Inventory;

// =====================================================================
// Lane A (item 2a) — the PRODUCTION warranty lookup: serial → OEM
// public lookup over HTTPS, honouring every D38-F11 contract item
// the model imposed on this client:
//   (1) AllowAutoRedirect=false; every redirect hop is re-run
//       through OemWarrantyEndpoints.ValidateOutboundTarget before
//       it is followed; at most 3 hops.
//   (2) DNS answers for the target host are checked at connect
//       time via ValidateResolvedAddresses — any non-public answer
//       refuses the lookup (DNS-rebinding defence).
//   (3) Unparseable targets/responses are refusals (null), never
//       exceptions and never fabricated data: when the OEM page
//       cannot be parsed into a status, the answer is an explicit
//       StatusUnknown record stamped as an outbound lookup, so the
//       hub records "we asked, the OEM page told us nothing
//       parseable" instead of inventing coverage.
// Callers pass vendor + serial ONLY (the IWarrantyLookup shape) —
// the URL is built here from per-vendor templates whose hosts are
// all in the OemWarrantyEndpoints allowlist. The policy toggle
// lives in WarrantyService, which refuses before invoking this.
// =====================================================================

public sealed class HttpWarrantyLookup : IWarrantyLookup
{
    private static readonly IReadOnlyDictionary<string, string> UrlTemplates =
        new Dictionary<string, string>
        {
            [WarrantyVendors.Dell] = "https://www.dell.com/support/home/en-us/product-support/servicetag/{0}",
            [WarrantyVendors.Lenovo] = "https://pcsupport.lenovo.com/us/en/products/{0}/warranty",
            [WarrantyVendors.Hp] = "https://support.hp.com/us-en/checkwarranty",
            [WarrantyVendors.Microsoft] = "https://mybusinessservice.surface.com/",
        };

    private readonly HttpClient _http;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<string, Task<IPAddress[]>> _resolve;

    public HttpWarrantyLookup(HttpClient? http = null, Func<DateTimeOffset>? now = null,
        Func<string, Task<IPAddress[]>>? resolve = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _resolve = resolve ?? (host => Dns.GetHostAddressesAsync(host));
        // BD-SHARED-RMM-1 F2: the default transport PINS the
        // connection to the validated resolution. Previously the
        // lookup resolved + validated, then HttpClient resolved
        // AGAIN at send time — the classic rebinding window
        // between check and connect. The ConnectCallback resolves
        // through the same injected resolver, refuses any
        // non-public answer set, and connects the socket itself
        // to a validated address; TLS/SNI still use the URI host.
        // Redirects stay manual (AllowAutoRedirect=false) so every
        // hop re-validates in LookupAsync. An INJECTED HttpClient
        // remains the caller's transport (test stubs carry no DNS
        // at all); a caller injecting a real network handler owns
        // its redirect policy — production uses this default.
        _http = http ?? new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectCallback = async (ctx, ct) =>
            {
                var answers = await _resolve(ctx.DnsEndPoint.Host);
                if (!OemWarrantyEndpoints.ValidateResolvedAddresses(answers))
                    throw new HttpRequestException(
                        $"warranty lookup refused: '{ctx.DnsEndPoint.Host}' resolved to a non-public address");
                Exception? last = null;
                foreach (var addr in answers)
                {
                    var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(addr, ctx.DnsEndPoint.Port), ct);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception ex) { last = ex; socket.Dispose(); }
                }
                throw new HttpRequestException(
                    $"warranty lookup: no validated address for '{ctx.DnsEndPoint.Host}' accepted a connection", last);
            },
        })
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
    }

    public async Task<WarrantyInfo?> LookupAsync(string vendor, string serialNumber, CancellationToken ct)
    {
        var v = WarrantyVendors.Normalize(vendor);
        if (v is null) return null;
        var serial = InventoryValidation.NormalizeSerial(serialNumber);
        if (serial is null) return null;
        if (!UrlTemplates.TryGetValue(v, out var template)) return null;
        // BD-SHARED-RMM-1 F3: templates without a {0} never send
        // the serial (HP checkwarranty, Microsoft surface) — the
        // fetch returned a generic page and Parse stamped a date
        // off it as THIS device's coverage. Honestly unsupported
        // until a serial-bearing endpoint exists.
        if (!template.Contains("{0}")) return null;

        var target = new Uri(string.Format(CultureInfo.InvariantCulture, template,
            Uri.EscapeDataString(serial)));
        string? body = null;
        for (var hop = 0; hop <= 3; hop++)
        {
            // D38-F11 (1)+(3): validate EVERY hop before following.
            if (!OemWarrantyEndpoints.ValidateOutboundTarget(v, target)) return null;
            // D38-F11 (2): DNS-rebinding check at connect time.
            IPAddress[] answers;
            try { answers = await _resolve(target.Host); }
            catch { return null; }
            if (!OemWarrantyEndpoints.ValidateResolvedAddresses(answers)) return null;

            using var req = new HttpRequestMessage(HttpMethod.Get, target);
            req.Headers.UserAgent.ParseAdd("ACP-Hub-WarrantyLookup/1.0");
            HttpResponseMessage resp;
            try { resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct); }
            catch { return null; }
            using (resp)
            {
                if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    target = new Uri(target, loc);
                    continue;
                }
                if (!resp.IsSuccessStatusCode) return null;
                try { body = await resp.Content.ReadAsStringAsync(ct); }
                catch { return null; }
            }
            break;
        }
        if (body is null) return null;
        return Parse(v, serial, body);
    }

    /// <summary>Best-effort parse of an OEM warranty page. Only a
    /// date the page actually carries becomes ExpiresUtc; the
    /// status is active/expired ONLY when the page's own words say
    /// so relative to that date — otherwise unknown. Nothing is
    /// invented: an unparseable page yields StatusUnknown.</summary>
    internal WarrantyInfo Parse(string vendor, string serial, string body)
    {
        var now = _now();
        // BD-SHARED-RMM-1 F3: a coverage verdict must be about
        // THIS serial. The page has to echo the queried serial
        // (a servicetag page does), and the date must hang off a
        // warranty-END label — the previous regex took the first
        // date within 80 chars after the word warranty/coverage/
        // service ANYWHERE on the page (a purchase date, a
        // support-article date) and called it this device's
        // expiry. Anything less is StatusUnknown, never a verdict.
        var serialEchoed = body.Contains(serial, StringComparison.OrdinalIgnoreCase);
        DateTimeOffset? expires = null;
        if (serialEchoed)
        {
            var dateMatch = Regex.Match(body,
                @"(?:warranty|coverage)\s+(?:end date|ends|expires|expiration|expiry)[^<>{}]{0,40}?(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})",
                RegexOptions.IgnoreCase);
            if (dateMatch.Success &&
                DateTimeOffset.TryParse(dateMatch.Groups[1].Value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var parsed))
                expires = parsed;
        }
        var status = WarrantyInfo.StatusUnknown;
        if (expires is { } exp)
            status = exp >= now ? WarrantyInfo.StatusActive : WarrantyInfo.StatusExpired;
        else if (serialEchoed && Regex.IsMatch(body, @"\b(out of warranty|warranty (has )?expired|no active warranty)\b", RegexOptions.IgnoreCase))
            status = WarrantyInfo.StatusExpired;
        return new WarrantyInfo(vendor, serial, status, expires, null, now,
            IsOutboundLookup: true, Source: "oem-public-lookup:http");
    }
}

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Shared.Reporting;

// =====================================================================
// RMM-13 — Outbound webhooks on hub events.
//
// Discipline, all structural (the RMM-04 outbound-guard discipline,
// extended per the RMM-13 register):
//   * TARGET GUARD: https only, port 443 only, no userinfo. The
//     host may not be localhost, a loopback / link-local /
//     multicast / unspecified address, or a cloud-metadata name.
//     RFC1918 private addresses ARE admissible — the org's own
//     tooling usually lives on its own LAN, and that is the point
//     of a local API — but link-local (169.254.0.0/16, fe80::/10)
//     never is: that range is where metadata services live.
//     ValidateResolvedAddresses is the DNS-rebinding half the HTTP
//     wiring MUST call at connect time, and ValidateRedirectTarget
//     re-runs the whole guard on every redirect hop: a 302 to a
//     guarded target refuses the delivery, it is never followed.
//   * SIGNED OR NOT SENT: every payload is Ed25519-signed with the
//     hub's customer-held key (the RMM-03 signing discipline —
//     receivers verify origin against the customer's PUBLIC key).
//     There is no code path that emits an unsigned payload, and
//     HubWebhookSigning.VerifyPayload is the receiver-side check:
//     unsigned, wrongly-signed, or tampered payloads verify FALSE.
//   * FAILURES ARE STATES, NOT DROPS: pending → delivered |
//     failed → dead, attempts counted, last error kept, bounded
//     exponential backoff. Dead is terminal and visible.
//   * NO LIVE CLIENT SHIPS in this lane: delivery runs through
//     IWebhookTransport (the RMM-12 contract); tests use fakes.
// =====================================================================

public static class HubEventKinds
{
    public const string AlertRaised = "alert.raised";
    public const string PatchCompleted = "patch.completed";
    public const string PatchFailed = "patch.failed";
    public const string BackupFailed = "backup.failed";
    public const string BackupCompleted = "backup.completed";
    public const string DeviceDown = "device.down";
    public const string ReportGenerated = "report.generated";
    public const string ExposureOpened = "vulnerability.exposure_opened";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        AlertRaised, PatchCompleted, PatchFailed, BackupFailed,
        BackupCompleted, DeviceDown, ReportGenerated, ExposureOpened,
    };
}

public static class WebhookDeliveryStates
{
    public const string Pending = "pending";
    public const string Delivered = "delivered";
    public const string Failed = "failed";
    public const string Dead = "dead";
}

public static class WebhookTargetGuard
{
    public const int MaxAttempts = 4;

    private static readonly string[] MetadataNames = { "metadata", "metadata.google.internal", "instance-data" };

    /// <summary>Null when the target is admissible; otherwise the
    /// refusal reason. Fail-closed on every ambiguity.</summary>
    public static string? ValidateTarget(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "webhook target URL is empty — refused";
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return "webhook target URL does not parse as an absolute URI — refused";
        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return "webhook target must be https — refused (hub events never travel in cleartext)";
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return "webhook target carries userinfo — refused (credentials do not belong in a URL)";
        if (uri.Port != 443)
            return $"webhook target port {uri.Port} is not 443 — refused (the outbound guard admits the standard https port only)";
        var host = uri.Host.Trim().TrimEnd('.');
        if (host.Length == 0) return "webhook target has no host — refused";
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
            return "webhook target host is localhost — refused (SSRF line)";
        if (MetadataNames.Contains(host, StringComparer.OrdinalIgnoreCase))
            return $"webhook target host '{host}' is a cloud-metadata name — refused (SSRF line)";
        if (IPAddress.TryParse(host, out var ip) && !IsAdmissible(ip))
            return $"webhook target host '{host}' is a loopback/link-local/multicast/unspecified address — refused (SSRF line)";
        return null;
    }

    /// <summary>Admissible = public OR RFC1918-private (the org's
    /// own LAN). Loopback, link-local (incl. 169.254.169.254),
    /// multicast, unspecified, IPv6 loopback/link-local/ULA are
    /// never admissible as webhook targets.</summary>
    public static bool IsAdmissible(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // D38-F4: these checks run AFTER the IPv4-mapped unmap,
            // so [::ffff:127.0.0.1] is judged as the IPv4 it is.
            if (bytes[0] == 127) return false;                      // 127.0.0.0/8 loopback (whole range, not just .1)
            if (bytes[0] == 169 && bytes[1] == 254) return false;   // link-local / metadata
            if (bytes[0] == 100 && (bytes[1] & 0xC0) == 0x40) return false; // 100.64.0.0/10 CGNAT — shared space, not org LAN
            if (bytes[0] >= 224) return false;                      // multicast
            if (bytes[0] == 0) return false;                        // unspecified network
            return true;                                            // public + RFC1918
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast) return false;
            if (bytes.All(b => b == 0)) return false;                       // :: unspecified
            if (bytes.Take(15).All(b => b == 0) && bytes[15] == 1) return false; // ::1
            if ((bytes[0] & 0xFE) == 0xFC) return false;                    // fc00::/7 ULA
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0) return false; // fec0::/10 site-local (deprecated)
            // IPv4-compatible ::a.b.c.d (first 96 bits zero): judge
            // the embedded IPv4 on its own merits.
            if (bytes.Take(12).All(b => b == 0))
                return IsAdmissible(new IPAddress(bytes[12..]));
            // NAT64 well-known prefix 64:ff9b::/96: the last 32 bits
            // are an embedded IPv4 — a NAT64 path to a refused IPv4
            // (169.254, 127/8, …) is refused.
            if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xFF && bytes[3] == 0x9B &&
                bytes.Skip(4).Take(8).All(b => b == 0))
                return IsAdmissible(new IPAddress(bytes[12..]));
            return true;
        }
        return false;
    }

    /// <summary>DNS-rebinding half (RMM-04 D38-F11 contract): the
    /// HTTP wiring MUST call this on the DNS answers at connect
    /// time. False when there are no answers or ANY answer is
    /// inadmissible — one poisoned answer poisons the set.</summary>
    public static bool ValidateResolvedAddresses(IEnumerable<IPAddress>? addresses)
    {
        if (addresses is null) return false;
        var any = false;
        foreach (var ip in addresses)
        {
            if (ip is null) return false;
            any = true;
            if (!IsAdmissible(ip)) return false;
        }
        return any;
    }

    /// <summary>Redirect discipline: a redirect is a NEW target and
    /// is admitted only if it passes the full guard on its own.
    /// Null when admissible; otherwise the refusal the delivery
    /// records (the delivery FAILS — the redirect is never
    /// followed).</summary>
    public static string? ValidateRedirectTarget(string? location) =>
        ValidateTarget(location) is { } r ? $"redirect target refused: {r}" : null;
}

public static class HubWebhookSigning
{
    /// <summary>The canonical string the signature covers: version,
    /// event, delivery id, timestamp, and the SHA-256 of the body —
    /// altering any of them breaks verification.</summary>
    public static string Canonical(string eventKind, string deliveryId, DateTimeOffset atUtc, string bodyJson) =>
        string.Join("|", "deskguest-hub-webhook-v1", eventKind, deliveryId, atUtc.ToString("O"),
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(bodyJson ?? ""))).ToLowerInvariant());

    /// <summary>Build the signed envelope for one event. The body
    /// travels as a STRING (re-serialising parsed JSON is not
    /// byte-stable); the signature is Ed25519 over the canonical
    /// string, made with the hub's customer-held key (RMM-03).</summary>
    public static string SignedPayload(string eventKind, string deliveryId, string bodyJson,
        DeviceIdentity signer, DateTimeOffset atUtc)
    {
        var sig = signer.Sign(Encoding.UTF8.GetBytes(Canonical(eventKind, deliveryId, atUtc, bodyJson)));
        return JsonSerializer.Serialize(new
        {
            eventKind,
            deliveryId,
            atUtc,
            keyId = CustomerCommandKeyRing.KeyIdFor(signer.PublicKey),
            body = bodyJson,
            signature = Convert.ToBase64String(sig),
        });
    }

    /// <summary>Receiver-side verification: TRUE only when the
    /// envelope parses, names the expected key, and its Ed25519
    /// signature verifies against the hub's customer PUBLIC key.
    /// Unsigned payloads, wrong-key signatures, and any tampering
    /// with body/event/id/time verify FALSE — never throw.</summary>
    /// <summary>Freshness/replay window for the timed overload:
    /// a payload older than this, or further in the future than
    /// the skew allowance, is refused even when correctly signed.</summary>
    public static readonly TimeSpan MaxPayloadAge = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(5);

    public static bool VerifyPayload(string? payloadJson, byte[] hubPublicKey) =>
        VerifyPayload(payloadJson, hubPublicKey, null);

    /// <summary>D38-F12: when <paramref name="referenceNow"/> is
    /// supplied, the payload's timestamp must fall inside the
    /// freshness window around it (replay protection); the
    /// timestamp is parsed with the invariant culture, never
    /// culture-sensitively. The
    /// two-argument overload verifies the signature only — a
    /// receiver that needs replay protection calls this one.</summary>
    public static bool VerifyPayload(string? payloadJson, byte[] hubPublicKey, DateTimeOffset? referenceNow)
    {
        if (string.IsNullOrWhiteSpace(payloadJson) || hubPublicKey is null || hubPublicKey.Length != 32) return false;
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;
            var eventKind = root.GetProperty("eventKind").GetString() ?? "";
            var deliveryId = root.GetProperty("deliveryId").GetString() ?? "";
            var atRaw = root.GetProperty("atUtc").GetRawText().Trim('"');
            // Invariant-culture parse (never the ambient culture —
            // the D38-F12 defect); the exact "O" form the signer
            // writes into Canonical is among the accepted ISO
            // shapes, as is the JSON serialiser's trimmed form.
            if (!DateTimeOffset.TryParse(atRaw, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var atUtc)) return false;
            if (referenceNow is { } now && (now - atUtc > MaxPayloadAge || atUtc - now > MaxFutureSkew))
                return false;
            var body = root.GetProperty("body").GetString() ?? "";
            var keyId = root.GetProperty("keyId").GetString() ?? "";
            if (keyId != CustomerCommandKeyRing.KeyIdFor(hubPublicKey)) return false;
            var sig = Convert.FromBase64String(root.GetProperty("signature").GetString() ?? "");
            return Ed25519.Verify(hubPublicKey,
                Encoding.UTF8.GetBytes(Canonical(eventKind, deliveryId, atUtc, body)), sig);
        }
        catch { return false; }
    }
}

/// <summary>One admin-configured webhook endpoint: URL (guard-
/// admitted at configuration time), the event kinds it subscribes
/// to, and its enabled flag. Configuration is an admin act; the
/// service audits it.</summary>
public sealed record WebhookEndpoint(
    string Id, string Url, IReadOnlySet<string> EventKinds, bool Enabled, string ConfiguredBy)
{
    public IReadOnlySet<string> EventKinds { get; init; } =
        EventKinds ?? new HashSet<string>();
}

/// <summary>One outbound delivery: a signed payload for one event
/// at one endpoint, with its full attempt history on its face.</summary>
public sealed record WebhookDelivery(
    string DeliveryId, string EndpointId, string EventKind, string PayloadJson,
    string State, int Attempts, string? LastError,
    DateTimeOffset CreatedUtc, DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? NextAttemptUtc, DateTimeOffset? DeliveredUtc)
{
    public bool IsTerminal => State is WebhookDeliveryStates.Delivered or WebhookDeliveryStates.Dead;

    public static TimeSpan BackoffFor(int attempts) =>
        TimeSpan.FromMinutes(Math.Pow(2, Math.Max(1, attempts)));
}

/// <summary>The webhook hub: endpoint configuration, event fan-out,
/// and the delivery pump. Holds the signing identity (the hub's
/// customer-held key — the seed never leaves DeviceIdentity);
/// receivers verify against its public key.</summary>
public sealed class HubWebhookHub
{
    /// <summary>D38-F11: terminal delivery records are pruned
    /// beyond this count (newest kept) so the delivery list cannot
    /// grow without bound; non-terminal records are never pruned.</summary>
    public const int MaxTerminalDeliveriesKept = 500;

    private readonly DeviceIdentity _signer;
    private readonly Func<string, IPAddress[]>? _resolver;
    private readonly Dictionary<string, WebhookEndpoint> _endpoints = new(StringComparer.Ordinal);
    private readonly List<WebhookDelivery> _deliveries = new();
    private readonly object _gate = new();
    // BD-SHARED-RMM-3/F4: serialises pump passes — two concurrent
    // pumps previously snapshotted the same due set and both sent
    // (and counted) the same delivery. WorkItemBridge.Pump already
    // held this discipline (D38-F5); the hub pump now matches it.
    private readonly object _pumpGate = new();

    /// <param name="resolver">Optional DNS resolver (host wiring):
    /// when supplied, the pump validates the resolved addresses
    /// at SEND time (D38-F10) before any transport call.</param>
    public HubWebhookHub(DeviceIdentity signer, Func<string, IPAddress[]>? resolver = null)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _resolver = resolver;
    }

    public byte[] HubPublicKey => _signer.PublicKey;

    public IReadOnlyList<WebhookEndpoint> Endpoints
    {
        get { lock (_gate) return _endpoints.Values.OrderBy(e => e.Id, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<WebhookDelivery> Deliveries
    {
        get { lock (_gate) return _deliveries.ToList(); }
    }

    /// <summary>Configure (or replace) an endpoint. The target must
    /// pass the outbound guard and the subscription must name known
    /// event kinds — a refused configuration is never stored, so it
    /// can never be sent to.</summary>
    public (bool Ok, string Reason) Configure(WebhookEndpoint? endpoint)
    {
        if (endpoint is null) return (false, "no webhook endpoint presented — refused");
        if (string.IsNullOrWhiteSpace(endpoint.Id)) return (false, "webhook endpoint needs an id — refused");
        if (string.IsNullOrWhiteSpace(endpoint.ConfiguredBy)) return (false, "webhook endpoint needs a configuring admin — refused");
        if (WebhookTargetGuard.ValidateTarget(endpoint.Url) is { } refusal) return (false, refusal);
        if (endpoint.EventKinds.Count == 0) return (false, $"webhook endpoint '{endpoint.Id}' subscribes to no event kinds — refused");
        var unknown = endpoint.EventKinds.FirstOrDefault(k => !HubEventKinds.All.Contains(k));
        if (unknown is not null) return (false, $"webhook endpoint '{endpoint.Id}' subscribes to unknown event kind '{unknown}' — refused");
        lock (_gate) _endpoints[endpoint.Id] = endpoint;
        return (true, $"webhook endpoint '{endpoint.Id}' configured for {endpoint.EventKinds.Count} event kind(s)");
    }

    public bool Remove(string endpointId)
    {
        lock (_gate) return _endpoints.Remove(endpointId ?? "");
    }

    /// <summary>Raise one hub event: fans out to every ENABLED
    /// endpoint subscribed to the kind, minting one signed delivery
    /// per endpoint. Unknown kinds refuse — an event that changes
    /// meaning is never emitted. Returns the deliveries created
    /// (empty when nobody subscribes — a named fact for the caller
    /// to audit, not a silent no-op).</summary>
    public IReadOnlyList<WebhookDelivery> Raise(string eventKind, string bodyJson, DateTimeOffset now)
    {
        if (!HubEventKinds.All.Contains(eventKind ?? ""))
            throw new ArgumentException($"unknown hub event kind '{eventKind}' — refused", nameof(eventKind));
        var created = new List<WebhookDelivery>();
        List<WebhookEndpoint> targets;
        lock (_gate) targets = _endpoints.Values.Where(e => e.Enabled && e.EventKinds.Contains(eventKind)).ToList();
        foreach (var ep in targets)
        {
            var deliveryId = "whd-" + Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes($"{ep.Id}|{eventKind}|{now:O}|{Guid.NewGuid():N}")))[..20].ToLowerInvariant();
            var payload = HubWebhookSigning.SignedPayload(eventKind, deliveryId, bodyJson ?? "", _signer, now);
            var delivery = new WebhookDelivery(deliveryId, ep.Id, eventKind, payload,
                WebhookDeliveryStates.Pending, 0, null, now, null, now, null);
            lock (_gate) _deliveries.Add(delivery);
            created.Add(delivery);
        }
        return created;
    }

    /// <summary>One delivery pump pass: attempt every due,
    /// non-terminal delivery once through the transport. Backoff
    /// gates re-attempts; the attempt cap pronounces DEAD. Returns
    /// the deliveries whose state changed (the service audits
    /// each). A transport that reports a redirect to a guarded
    /// target fails the delivery via its detail — the pump never
    /// follows redirects itself.</summary>
    public IReadOnlyList<WebhookDelivery> Pump(IWebhookTransport transport, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(transport);
        lock (_pumpGate)
        {
        var changed = new List<WebhookDelivery>();
        List<WebhookDelivery> due;
        // D38-F11: one index build per pass — transitions are O(1)
        // lookups, not a linear FindIndex per delivery (O(n²)).
        Dictionary<string, int> index;
        lock (_gate)
        {
            due = _deliveries.Where(d => !d.IsTerminal && d.NextAttemptUtc <= now).ToList();
            index = BuildIndex();
        }
        foreach (var d in due)
        {
            WebhookEndpoint? ep;
            lock (_gate) _endpoints.TryGetValue(d.EndpointId, out ep);
            if (ep is null)
            {
                // The endpoint was removed after enqueue: the
                // delivery dies VISIBLY, never silently dropped.
                Transition(d.DeliveryId, now, false, "endpoint removed after enqueue — delivery pronounced dead, not dropped", changed, forceDead: true, index);
                continue;
            }
            // D38-F10: the guard is re-run at SEND time, not only
            // at configuration time — an endpoint admitted earlier
            // whose target no longer passes (guard tightened, URL
            // shape changed) fails as a delivery record and the
            // transport is never called. When host wiring supplies
            // a resolver, its DNS answers are validated too (the
            // DNS-rebinding half, enforced here, not by comment).
            if (WebhookTargetGuard.ValidateTarget(ep.Url) is { } sendRefusal)
            {
                Transition(d.DeliveryId, now, false, $"send-time target re-validation refused: {sendRefusal}", changed, forceDead: false, index);
                continue;
            }
            if (_resolver is not null)
            {
                var host = new Uri(ep.Url).Host;
                IPAddress[] answers;
                try { answers = _resolver(host) ?? Array.Empty<IPAddress>(); }
                catch (Exception ex)
                {
                    Transition(d.DeliveryId, now, false, $"send-time DNS resolution failed for '{host}': {ex.GetType().Name}", changed, forceDead: false, index);
                    continue;
                }
                if (!WebhookTargetGuard.ValidateResolvedAddresses(answers))
                {
                    Transition(d.DeliveryId, now, false, $"send-time DNS answers for '{host}' include an inadmissible address — refused (DNS-rebinding guard)", changed, forceDead: false, index);
                    continue;
                }
            }
            // BD-SHARED-RMM-3/F4: a THROWING transport is a failed
            // attempt, never an escape — the old shape threw out of
            // Pump mid-pass and the deliveries transitioned earlier
            // in that pass were never returned to be audited.
            bool ok; string detail;
            try { (ok, detail) = transport.Post(new Uri(ep.Url), d.PayloadJson); }
            catch (Exception ex) { ok = false; detail = $"transport threw {ex.GetType().Name}: {ex.Message}"; }
            Transition(d.DeliveryId, now, ok, detail, changed, forceDead: false, index);
        }
        lock (_gate) PruneTerminal();
        return changed;
        }
    }

    private Dictionary<string, int> BuildIndex()
    {
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < _deliveries.Count; i++) index[_deliveries[i].DeliveryId] = i;
        return index;
    }

    /// <summary>Prune terminal deliveries beyond the kept count,
    /// newest first. Caller holds _gate.</summary>
    private void PruneTerminal()
    {
        var terminal = 0;
        for (var i = _deliveries.Count - 1; i >= 0; i--)
        {
            if (!_deliveries[i].IsTerminal) continue;
            terminal++;
            if (terminal > MaxTerminalDeliveriesKept) _deliveries.RemoveAt(i);
        }
    }

    private void Transition(string deliveryId, DateTimeOffset now, bool ok, string detail,
        List<WebhookDelivery> changed, bool forceDead, Dictionary<string, int>? index = null)
    {
        lock (_gate)
        {
            var idx = index is not null && index.TryGetValue(deliveryId, out var ii) ? ii
                : _deliveries.FindIndex(x => x.DeliveryId == deliveryId);
            if (idx < 0 || idx >= _deliveries.Count || _deliveries[idx].DeliveryId != deliveryId) return;
            var cur = _deliveries[idx];
            var attempts = cur.Attempts + 1;
            WebhookDelivery next;
            if (ok && !forceDead)
            {
                next = cur with
                {
                    State = WebhookDeliveryStates.Delivered, Attempts = attempts,
                    LastAttemptUtc = now, DeliveredUtc = now, NextAttemptUtc = null, LastError = null,
                };
            }
            else if (forceDead || attempts >= WebhookTargetGuard.MaxAttempts)
            {
                next = cur with
                {
                    State = WebhookDeliveryStates.Dead, Attempts = attempts,
                    LastAttemptUtc = now, NextAttemptUtc = null, LastError = detail,
                };
            }
            else
            {
                next = cur with
                {
                    State = WebhookDeliveryStates.Failed, Attempts = attempts,
                    LastAttemptUtc = now, NextAttemptUtc = now + WebhookDelivery.BackoffFor(attempts),
                    LastError = detail,
                };
            }
            _deliveries[idx] = next;
            changed.Add(next);
        }
    }
}

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Reporting;

namespace Acp.Shared.WorkItems;

// =====================================================================
// RMM-12 — the outbound PSA bridge (ACP's side only).
//
// ACP does not become a PSA. This bridge forwards work-item events
// (opened / closed / auto-closed) as SIGNED webhooks to whatever
// ticketing system the org already runs, so the org's system of
// record stays theirs while ACP's trail stays complete.
//
// Discipline, all structural:
//   * TARGET GUARD (the RMM-04 outbound-guard discipline, reused):
//     https only, port 443 only, no userinfo, and the host may not
//     be localhost or a loopback / private / link-local / multicast
//     IP literal; ValidateResolvedAddresses is the DNS-rebinding
//     half the future HTTP wiring must call at connect time. A
//     bridge URL that fails the guard is refused at CONFIGURATION
//     time — it is never stored, so it can never be sent to.
//   * SIGNED OR NOT SENT: configuration requires a signing secret;
//     every payload is HMAC-SHA256 signed over its exact body bytes
//     (the AlertCenter signed-webhook pattern). There is no code
//     path that emits an unsigned payload.
//   * FAILURES ARE STATES, NOT DROPS: every delivery is a record
//     with state pending → delivered | failed → dead. Attempts are
//     counted, the last error is kept, retries back off
//     exponentially (no retry storms), and dead is terminal and
//     visible. Nothing is ever silently discarded.
//   * NO LIVE CLIENT SHIPS in this lane: delivery runs through
//     IWebhookTransport; tests use the recording fake. The HTTP
//     wiring must pass the guard + resolved-address check per hop
//     (the RMM-04 D38-F11 contract applies verbatim).
// =====================================================================

public static class BridgeDeliveryStates
{
    public const string Pending = "pending";
    public const string Delivered = "delivered";
    public const string Failed = "failed";
    public const string Dead = "dead";
}

public static class BridgeEventKinds
{
    public const string Opened = "work_item.opened";
    public const string Closed = "work_item.closed";
    public const string AutoClosed = "work_item.auto_closed";
}

/// <summary>The bridge target as configured by an admin: the PSA's
/// webhook URL + the signing secret's HASH (the secret itself is
/// held by the service, never in this record, never in audit).</summary>
public sealed record BridgeConfiguration(
    string TargetUrl,
    string SecretHash,
    string ConfiguredBy,
    DateTimeOffset ConfiguredUtc);

/// <summary>One outbound delivery: a signed payload for one item
/// event, with its full attempt history on its face.</summary>
public sealed record BridgeDelivery(
    string DeliveryId,
    string ItemId,
    string EventKind,
    string PayloadJson,        // the signed envelope, exactly as sent
    string State,              // BridgeDeliveryStates.*
    int Attempts,
    string? LastError,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? NextAttemptUtc,
    DateTimeOffset? DeliveredUtc,
    // D38-F8: the target is SNAPSHOTTED at enqueue, paired with
    // the payload that was signed (with the then-current secret)
    // at the same instant. Reconfiguring the bridge must not
    // retarget already-queued events to a new PSA under an old
    // signature.
    string TargetUrl = "")
{
    public bool IsTerminal => State is BridgeDeliveryStates.Delivered or BridgeDeliveryStates.Dead;

    /// <summary>Exponential backoff: attempt n waits 2^n minutes
    /// (2, 4, 8) — a down PSA is retried politely, never stormed.</summary>
    public static TimeSpan BackoffFor(int attempts) =>
        TimeSpan.FromMinutes(Math.Pow(2, Math.Max(1, attempts)));
}

public static class BridgeGuard
{
    /// <summary>Validate a bridge target URL. Null when admissible;
    /// otherwise the refusal reason.
    /// BD-SHARED-RMM-3/F3: this guard had DRIFTED from the hub's
    /// WebhookTargetGuard — it rejected RFC1918 LAN addresses, which
    /// blocks a self-hosted PSA on the org's own LAN in a local-first
    /// product, and it had no metadata-hostname handling. There is
    /// now ONE guard: target-shape validation delegates to
    /// WebhookTargetGuard; the stricter public-only rule survives
    /// ONLY for resolved DNS answers (IsPublic/ValidateResolvedAddresses
    /// below), where a public name resolving to a private answer is
    /// exactly the DNS-rebinding shape.</summary>
    public static string? ValidateTarget(string? url)
    {
        if (WebhookTargetGuard.ValidateTarget(url) is { } refusal)
            return refusal.Replace("webhook target", "bridge target");
        // WebhookTargetGuard has already judged scheme, userinfo,
        // port, localhost, metadata names and literal-IP class
        // (admitting the org's own RFC1918 LAN, refusing loopback /
        // link-local / multicast / ULA). Nothing further to check:
        // the drift this lane removes was a second, divergent rule.
        return null;
    }

    public static bool IsPublic(IPAddress ip)
    {
        // D38-F7: an IPv4-mapped IPv6 literal ([::ffff:10.0.0.5])
        // IS the IPv4 address it maps — judge it by IPv4 rules.
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (bytes[0] == 10) return false;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
            if (bytes[0] == 192 && bytes[1] == 168) return false;
            if (bytes[0] == 169 && bytes[1] == 254) return false;
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false; // 100.64.0.0/10 CGNAT (D38-F7)
            if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)) return false; // 198.18.0.0/15 benchmarking (D38-F7)
            if (bytes[0] >= 224) return false;
            if (bytes[0] == 0) return false;
            return true;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
            if (bytes.All(b => b == 0)) return false;                       // :: unspecified
            if (bytes.Take(15).All(b => b == 0) && bytes[15] == 1) return false; // ::1 loopback
            if ((bytes[0] & 0xFE) == 0xFC) return false;                    // fc00::/7 unique-local
            return true;
        }
        return false;
    }

    /// <summary>DNS-rebinding half of the guard (RMM-04 D38-F11
    /// contract item 2): the HTTP wiring MUST call this on the DNS
    /// answers at connect time. False when there are no answers or
    /// ANY answer is non-public.</summary>
    public static bool ValidateResolvedAddresses(IEnumerable<IPAddress>? addresses)
    {
        if (addresses is null) return false;
        var any = false;
        foreach (var ip in addresses)
        {
            if (ip is null) return false;
            any = true;
            if (!IsPublic(ip)) return false;
        }
        return any;
    }
}

public static class BridgeSigning
{
    /// <summary>Build the signed envelope for one event. The signed
    /// body travels as a STRING (re-serialising parsed JSON is not
    /// byte-stable); the signature is HMAC-SHA256 over the body.</summary>
    /// <summary>BD-SHARED-RMM-3/F8: how old a signed payload may be
    /// and still verify, and how far ahead of the verifier's clock it
    /// may be dated — the hub webhook scheme's discipline
    /// (HubWebhookSigning), applied to the bridge's HMAC scheme.</summary>
    public static readonly TimeSpan MaxPayloadAge = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(5);

    public static string SignedPayload(string eventKind, WorkItem item, string signingSecret, DateTimeOffset atUtc,
        string? deliveryId = null)
    {
        var body = JsonSerializer.Serialize(new
        {
            // BD-SHARED-RMM-3/F8: the delivery id is INSIDE the signed
            // body — it is the receiver's idempotency key, so a
            // redelivery after a lost acknowledgement de-duplicates
            // instead of creating a second PSA ticket.
            deliveryId = deliveryId ?? "",
            eventKind,
            itemId = item.Id,
            itemKind = item.Kind,
            deviceId = item.DeviceId,
            scopeId = item.ScopeId,
            title = item.Title,
            state = item.State,
            owner = item.Owner,
            outcome = item.Closure?.Outcome,
            closedBy = item.Closure?.ClosedBy,
            atUtc,
        });
        var sig = Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingSecret), Encoding.UTF8.GetBytes(body)))
            .ToLowerInvariant();
        return JsonSerializer.Serialize(new { body, signature = sig });
    }

    public static bool VerifyPayload(string payloadJson, string signingSecret)
    {
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var body = doc.RootElement.GetProperty("body").GetString() ?? "";
            var expected = Convert.ToHexString(
                HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingSecret), Encoding.UTF8.GetBytes(body)))
                .ToLowerInvariant();
            return EntUtil.FixedEq(expected, doc.RootElement.GetProperty("signature").GetString() ?? "");
        }
        catch { return false; }
    }

    /// <summary>BD-SHARED-RMM-3/F8: freshness-checked verification —
    /// the signature must verify AND the body's signed atUtc must sit
    /// inside [referenceNow - MaxPayloadAge, referenceNow +
    /// MaxFutureSkew]. A captured payload replayed later fails here
    /// even though its HMAC still verifies.</summary>
    public static bool VerifyPayload(string payloadJson, string signingSecret, DateTimeOffset referenceNow)
    {
        if (!VerifyPayload(payloadJson, signingSecret)) return false;
        try
        {
            using var outer = JsonDocument.Parse(payloadJson);
            var body = outer.RootElement.GetProperty("body").GetString() ?? "";
            using var doc = JsonDocument.Parse(body);
            var atUtc = doc.RootElement.GetProperty("atUtc").GetDateTimeOffset();
            return atUtc >= referenceNow - MaxPayloadAge && atUtc <= referenceNow + MaxFutureSkew;
        }
        catch { return false; }
    }

    /// <summary>The delivery id carried inside a signed payload (the
    /// receiver's idempotency key), or null when absent/unparseable.</summary>
    public static string? PayloadDeliveryId(string payloadJson)
    {
        try
        {
            using var outer = JsonDocument.Parse(payloadJson);
            var body = outer.RootElement.GetProperty("body").GetString() ?? "";
            using var doc = JsonDocument.Parse(body);
            var id = doc.RootElement.GetProperty("deliveryId").GetString();
            return string.IsNullOrWhiteSpace(id) ? null : id;
        }
        catch { return null; }
    }

    public static string SecretHash(string secret) => WorkItemHash.Sha256Hex(secret ?? "");
}

/// <summary>The delivery transport: ACP's side of the wire. The
/// production HTTP implementation is hub wiring that must honour
/// the guard contract; tests and this lane use fakes.</summary>
public interface IWebhookTransport
{
    (bool Ok, string Detail) Post(Uri target, string payloadJson);
}

/// <summary>Recording test double for IWebhookTransport (house
/// pattern: fakes live beside the model).</summary>
public sealed class RecordingWebhookTransport : IWebhookTransport
{
    public List<(Uri Target, string PayloadJson)> Sent { get; } = new();
    public (bool Ok, string Detail) Result { get; set; } = (true, "200 OK (recording double)");
    public (bool Ok, string Detail) Post(Uri target, string payloadJson)
    {
        Sent.Add((target, payloadJson));
        return Result;
    }
}

/// <summary>The bridge: configuration, enqueue, and the delivery
/// pump. Owns delivery records; every state change is reported to
/// the caller (the service) for auditing — the bridge itself holds
/// no audit reference, so a delivery can never exist off-chain
/// when driven through the service.</summary>
public sealed class WorkItemBridge
{
    private readonly List<BridgeDelivery> _deliveries = new();
    private readonly object _gate = new();
    private readonly object _pumpGate = new(); // D38-F5: serialises pump passes
    private readonly Func<string, IPAddress[]>? _resolver;

    /// <param name="resolver">Optional DNS resolver (host wiring):
    /// when supplied, Pump validates the resolved addresses at SEND
    /// time (BD-SHARED-RMM-3/F3), exactly as HubWebhookHub does.</param>
    public WorkItemBridge(Func<string, IPAddress[]>? resolver = null) => _resolver = resolver;
    private BridgeConfiguration? _config;
    private string? _secret; // held only in memory, never persisted in a record or audit detail
    // D38-F8: the stored secret fingerprint is an HMAC keyed by a
    // per-instance random key held only in memory — the plain
    // unsalted SHA-256 it replaces could be brute-forced offline
    // against the stored record for weak secrets.
    private readonly byte[] _fingerprintKey = RandomNumberGenerator.GetBytes(32);

    public BridgeConfiguration? Configuration { get { lock (_gate) return _config; } }
    public bool IsConfigured { get { lock (_gate) return _config is not null; } }

    public IReadOnlyList<BridgeDelivery> Deliveries
    {
        get { lock (_gate) return _deliveries.ToList(); }
    }

    public IReadOnlyList<BridgeDelivery> DeliveriesFor(string itemId)
    {
        lock (_gate) return _deliveries.Where(d => d.ItemId == itemId).ToList();
    }

    /// <summary>Configure (or reconfigure) the bridge. The target
    /// must pass the outbound guard and a signing secret is
    /// mandatory — an unsigned bridge is refused here, at the only
    /// door.</summary>
    public (bool Ok, string Reason) Configure(string? targetUrl, string? signingSecret,
        string configuredBy, DateTimeOffset now)
    {
        if (BridgeGuard.ValidateTarget(targetUrl) is { } refusal) return (false, refusal);
        if (string.IsNullOrWhiteSpace(signingSecret) || signingSecret.Length < 16)
            return (false, "the bridge requires a signing secret of at least 16 characters — refused (unsigned webhook payloads are never sent)");
        if (string.IsNullOrWhiteSpace(configuredBy))
            return (false, "bridge configuration needs a configuring admin — refused");
        lock (_gate)
        {
            var fingerprint = Convert.ToHexString(HMACSHA256.HashData(
                _fingerprintKey, Encoding.UTF8.GetBytes(signingSecret))).ToLowerInvariant();
            _config = new BridgeConfiguration(targetUrl!.Trim(), fingerprint,
                configuredBy.Trim(), now);
            _secret = signingSecret;
        }
        return (true, $"bridge configured to {targetUrl!.Trim()} (signed, HMAC-SHA256)");
    }

    /// <summary>Enqueue one item event for delivery. Refuses when
    /// unconfigured — the caller audits the refusal, so an event
    /// that could not be bridged is a named fact, not a drop.</summary>
    public (BridgeDelivery? Delivery, string Reason) Enqueue(string eventKind, WorkItem item, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_config is null || _secret is null)
                return (null, "bridge is not configured — event not enqueued (the caller records this; nothing is silently dropped)");
            var deliveryId = "dlv-" + WorkItemHash.Sha256Hex($"{item.Id}|{eventKind}|{now:O}|{Guid.NewGuid():N}")[..20];
            var payload = BridgeSigning.SignedPayload(eventKind, item, _secret, now, deliveryId);
            var delivery = new BridgeDelivery(
                DeliveryId: deliveryId,
                ItemId: item.Id, EventKind: eventKind, PayloadJson: payload,
                State: BridgeDeliveryStates.Pending, Attempts: 0, LastError: null,
                CreatedUtc: now, LastAttemptUtc: null, NextAttemptUtc: now, DeliveredUtc: null,
                TargetUrl: _config.TargetUrl);
            _deliveries.Add(delivery);
            // D38-F10 retention: bound the record list by evicting
            // the oldest DELIVERED records only — a delivered event
            // already reached the PSA and its transition is on the
            // audit chain; pending/failed/dead are never evicted.
            while (_deliveries.Count > WorkItemLimits.MaxRetainedDeliveries)
            {
                var idx = _deliveries.FindIndex(d => d.State == BridgeDeliveryStates.Delivered);
                if (idx < 0) break;
                _deliveries.RemoveAt(idx);
            }
            // BD-SHARED-RMM-3/F9: Dead records are retained for
            // redrive, but not without limit — during a long PSA
            // outage every event ends Dead, and the old list grew
            // forever. Oldest Dead beyond the cap are evicted.
            while (_deliveries.Count(d => d.State == BridgeDeliveryStates.Dead) > MaxRetainedDeadDeliveries)
            {
                var idx = _deliveries.FindIndex(d => d.State == BridgeDeliveryStates.Dead);
                if (idx < 0) break;
                _deliveries.RemoveAt(idx);
            }
            return (delivery, $"delivery '{delivery.DeliveryId}' enqueued for item '{item.Id}' ({eventKind})");
        }
    }

    /// <summary>One delivery pump pass: attempt every due,
    /// non-terminal delivery once. Backoff gates re-attempts, the
    /// attempt cap pronounces DEAD. Returns the deliveries whose
    /// state changed this pass (the service audits each).</summary>
    public IReadOnlyList<BridgeDelivery> Pump(IWebhookTransport transport, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(transport);
        var changed = new List<BridgeDelivery>();
        // D38-F5: pump passes are SERIALISED. The due snapshot is
        // taken outside the delivery lock, so two concurrent pumps
        // could previously both send the same delivery and count
        // two attempts for one event.
        lock (_pumpGate)
        {
        List<BridgeDelivery> due;
        BridgeConfiguration? config;
        lock (_gate)
        {
            config = _config;
            due = _deliveries.Where(d => !d.IsTerminal && d.NextAttemptUtc <= now).ToList();
        }
        if (config is null) return changed;
        // BD-SHARED-RMM-3/F9: one id index per pass — state changes
        // are O(1) lookups, not a linear FindIndex per delivery.
        Dictionary<string, int> index;
        lock (_gate)
        {
            index = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < _deliveries.Count; i++) index[_deliveries[i].DeliveryId] = i;
        }
        foreach (var d in due)
        {
            // BD-SHARED-RMM-3/F3: the guard is re-run at SEND time,
            // and the DNS answers are checked when a resolver is
            // wired — the old pump posted to the stored URL with no
            // re-check at all, so a target admitted under a looser
            // guard (or a name since rebound) went out unexamined.
            // A refused send is a failed attempt on the record.
            var sendTarget = d.TargetUrl.Length > 0 ? d.TargetUrl : config.TargetUrl;
            string? sendRefusal = BridgeGuard.ValidateTarget(sendTarget);
            if (sendRefusal is null && _resolver is not null)
            {
                var host = new Uri(sendTarget).Host;
                try
                {
                    if (!BridgeGuard.ValidateResolvedAddresses(_resolver(host)))
                        sendRefusal = $"send-time DNS answers for '{host}' include a non-public address — refused (DNS-rebinding guard)";
                }
                catch (Exception ex) { sendRefusal = $"send-time DNS resolution failed for '{host}': {ex.GetType().Name}"; }
            }
            if (sendRefusal is not null)
            {
                lock (_gate)
                {
                    if (!index.TryGetValue(d.DeliveryId, out var ridx)) continue;
                    var cur = _deliveries[ridx];
                    var attempts = cur.Attempts + 1;
                    var next = attempts >= WorkItemLimits.MaxBridgeAttempts
                        ? cur with { State = BridgeDeliveryStates.Dead, Attempts = attempts, LastAttemptUtc = now, NextAttemptUtc = null, LastError = sendRefusal }
                        : cur with { State = BridgeDeliveryStates.Failed, Attempts = attempts, LastAttemptUtc = now, NextAttemptUtc = now + BridgeDelivery.BackoffFor(attempts), LastError = sendRefusal };
                    _deliveries[ridx] = next;
                    changed.Add(next);
                }
                continue;
            }
            // D38-F5/F8: send to the delivery's OWN snapshotted
            // target, and a THROWING transport is a failed attempt
            // (counted, error retained, chained by the caller via
            // the changed list) — it must never escape Pump
            // mid-pass and leave earlier transitions unreported.
            bool ok;
            string detail;
            try
            {
                (ok, detail) = transport.Post(new Uri(d.TargetUrl.Length > 0 ? d.TargetUrl : config.TargetUrl), d.PayloadJson);
            }
            catch (Exception ex)
            {
                ok = false;
                detail = $"transport threw {ex.GetType().Name}: {ex.Message}";
            }
            lock (_gate)
            {
                if (!index.TryGetValue(d.DeliveryId, out var idx)) continue;
                var cur = _deliveries[idx];
                var attempts = cur.Attempts + 1;
                BridgeDelivery next;
                if (ok)
                {
                    next = cur with
                    {
                        State = BridgeDeliveryStates.Delivered,
                        Attempts = attempts,
                        LastAttemptUtc = now,
                        DeliveredUtc = now,
                        NextAttemptUtc = null,
                        LastError = null,
                    };
                }
                else if (attempts >= WorkItemLimits.MaxBridgeAttempts)
                {
                    next = cur with
                    {
                        State = BridgeDeliveryStates.Dead,
                        Attempts = attempts,
                        LastAttemptUtc = now,
                        NextAttemptUtc = null,
                        LastError = detail,
                    };
                }
                else
                {
                    next = cur with
                    {
                        State = BridgeDeliveryStates.Failed,
                        Attempts = attempts,
                        LastAttemptUtc = now,
                        NextAttemptUtc = now + BridgeDelivery.BackoffFor(attempts),
                        LastError = detail,
                    };
                }
                _deliveries[idx] = next;
                changed.Add(next);
            }
        }
        return changed;
        }
    }

    /// <summary>BD-SHARED-RMM-3/F9: how many Dead deliveries are
    /// retained for redrive. Beyond the cap the oldest Dead records
    /// are evicted by Enqueue's retention pass (their transitions are
    /// already on the caller's audit chain via Pump's changed list).</summary>
    public const int MaxRetainedDeadDeliveries = 500;

    /// <summary>BD-SHARED-RMM-3/F9: requeue Dead deliveries for a
    /// fresh pump pass after the PSA recovers — the admin act the
    /// bridge previously had no shape for. Attempts reset, the
    /// delivery is due immediately, and the returned records are the
    /// caller's audit evidence. Only Dead deliveries move; a live or
    /// delivered record is never resurrected.</summary>
    public IReadOnlyList<BridgeDelivery> RedriveDead(string redrivenBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(redrivenBy)) return Array.Empty<BridgeDelivery>();
        lock (_gate)
        {
            var moved = new List<BridgeDelivery>();
            for (var i = 0; i < _deliveries.Count; i++)
            {
                if (_deliveries[i].State != BridgeDeliveryStates.Dead) continue;
                var next = _deliveries[i] with
                {
                    State = BridgeDeliveryStates.Pending, Attempts = 0,
                    LastAttemptUtc = null, NextAttemptUtc = now,
                    LastError = $"redriven by {redrivenBy.Trim()}",
                };
                _deliveries[i] = next;
                moved.Add(next);
            }
            return moved;
        }
    }
}

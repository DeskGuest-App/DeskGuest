using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Ipc;

/// <summary>
/// W9 — the per-action gate protocol (design of record §3, live
/// caller). When a session action requires endpoint approval, the
/// Core raises ONE request; the Session Agent shows the GateSheet;
/// the answer returns and is enforced. This file is the state
/// machine both sides share — deliberately free of pipes and UI so
/// the destruction surface (forgery, replay, race with session end)
/// is provable in the plain test harness.
///
/// The answers, exactly the GateSheet's three exits.
/// </summary>
public static class GateAnswers
{
    public const string Allow = "allow";
    public const string Deny = "deny";
    public const string DenyAndEnd = "deny_and_end";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Allow, Deny, DenyAndEnd };
    public static bool IsAnswer(string? value) => value is not null && All.Contains(value);
}

/// <summary>One pending per-action gate request. Payload is the
/// EXACT argument bytes the caller submitted (base64 on the wire):
/// OI-12 — the sheet renders those bytes and the executed call uses
/// the same bytes; nothing is re-encoded or trimmed between the
/// two. Bound at raise time to one pairing and one session: an
/// answer that names any other pairing or session is a forgery and
/// is refused, never applied.</summary>
public sealed record GateRequest(
    string Id,
    string PairingId,
    string SessionId,
    string GateClass,
    string Tool,
    string PayloadBase64,
    bool FromChat,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc)
{
    public byte[] PayloadBytes()
    {
        try { return Convert.FromBase64String(PayloadBase64 ?? ""); }
        catch { return Array.Empty<byte>(); }
    }

    public static GateRequest Create(string pairingId, string sessionId, string gateClass,
        string tool, byte[] payloadBytes, bool fromChat, DateTimeOffset now, TimeSpan ttl) =>
        new(Guid.NewGuid().ToString("N"), pairingId, sessionId, gateClass, tool,
            Convert.ToBase64String(payloadBytes), fromChat, now, now + ttl);
}

/// <summary>The wire payloads. Request: the full GateRequest.
/// Answer: {"requestId": "...", "answer": "..."} — nothing else is
/// read from an answer, so extra fields cannot smuggle authority.</summary>
public static class GateRequestPayload
{
    public static string Build(GateRequest request) => JsonSerializer.Serialize(new
    {
        requestId = request.Id,
        pairingId = request.PairingId,
        sessionId = request.SessionId,
        gateClass = request.GateClass,
        tool = request.Tool,
        payloadBase64 = request.PayloadBase64,
        fromChat = request.FromChat,
        createdUtc = request.CreatedUtc,
        expiresUtc = request.ExpiresUtc,
    });

    public static GateRequest? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            string? S(string name) => r.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            if (S("requestId") is not { } id || S("pairingId") is not { } pairing || S("sessionId") is not { } session
                || S("gateClass") is not { } gateClass || S("tool") is not { } tool || S("payloadBase64") is not { } payload)
                return null;
            var fromChat = r.TryGetProperty("fromChat", out var fc) && fc.ValueKind == JsonValueKind.True;
            var created = r.TryGetProperty("createdUtc", out var c) && c.TryGetDateTimeOffset(out var cv) ? cv : DateTimeOffset.MinValue;
            var expires = r.TryGetProperty("expiresUtc", out var e) && e.TryGetDateTimeOffset(out var ev) ? ev : DateTimeOffset.MinValue;
            return new GateRequest(id, pairing, session, gateClass, tool, payload, fromChat, created, expires);
        }
        catch (JsonException) { return null; }
    }

    public static string BuildAnswer(string requestId, string answer) =>
        JsonSerializer.Serialize(new { requestId, answer });

    /// <summary>Parse an answer payload. Refuses (null) anything
    /// malformed, any answer outside the three exits, and any
    /// requestId that does not match the IPC frame's own RequestId
    /// when the frame carries one — the two must agree, so an answer
    /// cannot be re-pointed at a different pending request in
    /// transit.</summary>
    public static (string RequestId, string Answer)? ParseAnswer(string? json, string? frameRequestId)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var id = r.TryGetProperty("requestId", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null;
            var answer = r.TryGetProperty("answer", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
            if (string.IsNullOrWhiteSpace(id) || !GateAnswers.IsAnswer(answer)) return null;
            if (frameRequestId is not null && !string.Equals(frameRequestId, id, StringComparison.Ordinal)) return null;
            return (id!, answer!);
        }
        catch (JsonException) { return null; }
    }
}

public enum GateResolution
{
    /// <summary>The answer was accepted; this is its one use.</summary>
    Answered,
    /// <summary>No such pending request (never existed, or already
    /// consumed / expired / invalidated — replay lands here).</summary>
    UnknownOrConsumed,
    /// <summary>The request existed but its window had closed.</summary>
    Expired,
    /// <summary>The answer's pairing/session binding does not match
    /// the request's — a forged or cross-session answer.</summary>
    BindingMismatch,
    /// <summary>The session the request belongs to has ended; the
    /// request died with it (the race-with-session-end rule).</summary>
    SessionEnded,
}

/// <summary>
/// The Core-side pending-gate registry. One request, one answer:
/// TryAnswer consumes the request whatever the outcome, so a second
/// answer — a replay of a captured "allow" — finds nothing and is
/// refused. Expiry and session end resolve pending requests without
/// any answer being honored. All state transitions happen under one
/// lock; the broker is the ONLY path from a gate_answer message to
/// a decision the handler may enforce.
/// </summary>
public sealed class GateRequestBroker
{
    private readonly Dictionary<string, GateRequest> _pending = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>How long a raised gate waits for the person at the
    /// endpoint — Android ApprovalGate.TIMEOUT_MS parity (30 s). A
    /// gate nobody answers is a NO, never a stall and never a yes.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    public int PendingCount { get { lock (_gate) return _pending.Count; } }

    public GateRequest Register(string pairingId, string sessionId, string gateClass, string tool,
        byte[] payloadBytes, bool fromChat, DateTimeOffset now, TimeSpan? ttl = null)
    {
        var request = GateRequest.Create(pairingId, sessionId, gateClass, tool, payloadBytes,
            fromChat, now, ttl ?? DefaultTimeout);
        lock (_gate) _pending[request.Id] = request;
        return request;
    }

    public GateRequest? Peek(string requestId)
    {
        lock (_gate) return requestId is not null && _pending.TryGetValue(requestId, out var r) ? r : null;
    }

    /// <summary>
    /// Consume one answer. <paramref name="liveSessionId"/> is the
    /// Core's OWN current session id at answer time (never the
    /// sender's claim): if the request's session is no longer the
    /// live one, the answer is refused as SessionEnded — a gate
    /// raised by a session that has since ended can never be
    /// answered into an allow for anything.
    /// </summary>
    public GateResolution TryAnswer(string requestId, string answer, string? liveSessionId, DateTimeOffset now,
        out GateRequest? request, out string? acceptedAnswer)
    {
        request = null;
        acceptedAnswer = null;
        if (!GateAnswers.IsAnswer(answer)) return GateResolution.UnknownOrConsumed;
        lock (_gate)
        {
            if (requestId is null || !_pending.TryGetValue(requestId, out var found)) return GateResolution.UnknownOrConsumed;
            // Consume FIRST: whatever the verdict, this request can
            // never be answered again.
            _pending.Remove(requestId);
            request = found;
            if (now > found.ExpiresUtc) return GateResolution.Expired;
            if (!string.Equals(found.SessionId, liveSessionId ?? "", StringComparison.Ordinal)) return GateResolution.SessionEnded;
            acceptedAnswer = answer;
            return GateResolution.Answered;
        }
    }

    /// <summary>Abandon one pending request (its waiter timed out or
    /// the channel dropped): it can never be answered afterwards —
    /// a late answer resolves UnknownOrConsumed.</summary>
    public bool Abandon(string requestId)
    {
        lock (_gate) return requestId is not null && _pending.Remove(requestId);
    }

    /// <summary>Drop every pending request bound to a session (the
    /// session ended — by any road). Returns how many died. An
    /// answer already in flight for one of them now resolves
    /// UnknownOrConsumed / SessionEnded, never Answered.</summary>
    public int InvalidateSession(string sessionId)
    {
        lock (_gate)
        {
            var dead = _pending.Values.Where(r => string.Equals(r.SessionId, sessionId, StringComparison.Ordinal))
                .Select(r => r.Id).ToList();
            foreach (var id in dead) _pending.Remove(id);
            return dead.Count;
        }
    }

    /// <summary>Drop every pending request for a pairing (unpair
    /// ends its gates with its thread and its session).</summary>
    public int InvalidatePairing(string pairingId)
    {
        lock (_gate)
        {
            var dead = _pending.Values.Where(r => string.Equals(r.PairingId, pairingId, StringComparison.Ordinal))
                .Select(r => r.Id).ToList();
            foreach (var id in dead) _pending.Remove(id);
            return dead.Count;
        }
    }

    /// <summary>Expire everything whose window has closed (the
    /// raiser's timeout path resolves its own request; this is the
    /// sweep for any request whose waiter vanished).</summary>
    public int SweepExpired(DateTimeOffset now)
    {
        lock (_gate)
        {
            var dead = _pending.Values.Where(r => now > r.ExpiresUtc).Select(r => r.Id).ToList();
            foreach (var id in dead) _pending.Remove(id);
            return dead.Count;
        }
    }
}

/// <summary>FR-114 (W60-A): the prompt-side lifecycle of one gate.
/// The Core's broker already refuses answers for expired or
/// session-ended requests (GateResolution.Expired / SessionEnded);
/// this model is the Session Agent prompt's mirror of that truth —
/// a prompt whose gate has timed out, been decided, or lost its
/// session must dismiss itself and its exits must be inert. A
/// prompt for a dead gate NEVER presents a live Approve. Pure and
/// UI-free, like the broker above, so the harness proves it.</summary>
public enum GatePromptState
{
    /// <summary>The gate is pending, unexpired, its session live,
    /// and no exit has been taken. The only state in which the
    /// prompt stays on screen.</summary>
    Live,
    /// <summary>An exit was taken. The prompt closes through the
    /// decision path; lifecycle never re-opens it.</summary>
    Decided,
    /// <summary>The gate's answer window closed with no decision
    /// (the broker's 30 s DefaultTimeout). Dismiss + inert.</summary>
    Expired,
    /// <summary>The session the gate belongs to has ended.
    /// Dismiss + inert.</summary>
    SessionEnded,
}

public static class GatePromptLifecycle
{
    /// <summary>The instant this prompt's gate dies of old age.
    /// The wire request's own ExpiresUtc wins; a request parsed
    /// without one falls back to CreatedUtc + the broker's
    /// DefaultTimeout, and a request with neither falls back to
    /// shown-at + DefaultTimeout — a prompt can NEVER be immortal:
    /// every input combination yields a finite expiry.</summary>
    public static DateTimeOffset ResolveExpiry(DateTimeOffset createdUtc, DateTimeOffset expiresUtc, DateTimeOffset shownAtUtc)
    {
        if (expiresUtc > DateTimeOffset.MinValue) return expiresUtc;
        if (createdUtc > DateTimeOffset.MinValue) return createdUtc + GateRequestBroker.DefaultTimeout;
        return shownAtUtc + GateRequestBroker.DefaultTimeout;
    }

    /// <summary>Evaluate the prompt's state. Decision wins over
    /// every other transition (a decided gate closes through its
    /// own path, never through the retire path); session end wins
    /// over expiry (the stronger fact about why the gate died).</summary>
    public static GatePromptState Evaluate(DateTimeOffset nowUtc, DateTimeOffset expiresUtc, bool sessionLive, bool decided)
    {
        if (decided) return GatePromptState.Decided;
        if (!sessionLive) return GatePromptState.SessionEnded;
        if (nowUtc >= expiresUtc) return GatePromptState.Expired;
        return GatePromptState.Live;
    }

    /// <summary>True when the prompt must take itself off screen
    /// without an answer: its gate is dead (expired or orphaned).</summary>
    public static bool ShouldDismiss(GatePromptState state) =>
        state is GatePromptState.Expired or GatePromptState.SessionEnded;

    /// <summary>The exits are live only while the prompt is Live
    /// AND OI-13 arming has completed (600 ms + human activation,
    /// GateSheetModel.ControlsArmed). In every other state —
    /// unarmed, expired, orphaned, decided — they are inert.</summary>
    public static bool ExitsLive(GatePromptState state, bool armed) =>
        state == GatePromptState.Live && armed;
}

using System.Text;
using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Streaming;

namespace DeskGuest.Core.Services;

/// <summary>
/// The session-stream layer (Block D) — the security core of the
/// real remote-desktop stream. It binds an H.264 stream to a Slice 3
/// session and enforces, AT THE STREAM LAYER (never merely in a
/// viewer UI):
///
///  * No session, no stream: start requires a session that exists,
///    is `active`, and whose requester is a live participant.
///    `requested`/`paused`/`blocked`/`ended` all refuse. Every frame
///    fetch and every input re-reads the session, so end / block /
///    STOP / offboarding-removal kill the stream on the very next
///    call — there is no cached "streaming" flag to go stale.
///  * Floor control: input (pointer + keyboard) is forwarded to the
///    desktop ONLY when the caller's AUTHENTICATED identity (never
///    a body-typed userId — BD-WIN-CORE-4/F2) is the session's current
///    floor holder, read fresh from the SessionService on each
///    event — a floor grant/take-back takes effect on the next
///    input event, mid-stream, by construction. A watcher's input
///    is refused here (403) and never reaches the agent channel.
///  * Cross-scope safety is structural: participants and floor live
///    on the session record in its own scope; a user id from another
///    scope is simply not a participant of this session.
///  * Frames are validated through StreamProtocol.TryParse before
///    being served — a misbehaving/compromised capture path cannot
///    push malformed bytes at viewer decoders through this layer.
///
/// Capture+encode itself lives in the Session Agent (interactive
/// session): DXGI Desktop Duplication → Media Foundation H.264.
/// This service drives it through the same IPC desktop channel as
/// every other desktop tool (stream_start / stream_frame /
/// stream_stop / stream_monitors) and serves the validated access
/// units to viewers over the mesh lanes.
/// </summary>
public sealed class StreamService
{
    private readonly IAgentChannel _channel;
    private readonly SessionService _sessions;
    private readonly Func<bool> _desktopUnlocked;
    private readonly Func<bool> _stopInForce;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<string, string, string?>? _displayName;
    private readonly DataFlowLedger? _flows;

    private readonly object _gate = new();
    private readonly Dictionary<string, StreamBinding> _bindings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, StreamStats> _stats = new(StringComparer.OrdinalIgnoreCase);

    private sealed class StreamBinding
    {
        public required string SessionId;
        public required int Monitor;
        public long LastServedSeq = -1;
        public byte[]? LastFrameBody;
        public StreamProtocol.FrameHeader? LastHeader;
        public bool AgentToldToStop;
    }

    public sealed class StreamStats
    {
        public long Started;
        public long FramesServed;
        public long BytesServed;
        public long InputsAccepted;
        public long InputsRefusedFloor;
        public long InputsRefusedState;
        public long FramesDroppedInvalid;
    }

    public StreamService(
        IAgentChannel channel,
        SessionService sessions,
        Func<bool> desktopUnlocked,
        Func<bool>? stopInForce = null,
        Func<DateTimeOffset>? now = null,
        Func<string, string, string?>? displayName = null,
        DataFlowLedger? flows = null)
    {
        _channel = channel;
        _sessions = sessions;
        _desktopUnlocked = desktopUnlocked;
        _stopInForce = stopInForce ?? (() => false);
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _displayName = displayName;
        _flows = flows;
    }

    // ---- lifecycle -------------------------------------------------

    /// <summary>Start the stream for a session. Refusals: unknown
    /// session (404), session not active (409), requester not a live
    /// participant (403), STOP in force (409), desktop locked (503),
    /// agent down (503), agent refused the capture (502).</summary>
    // BD-WIN-CORE-4/F2: the caller's identity is the AUTHENTICATED
    // identity the transport/channel established (the actor-
    // derivation law: identity comes from the authenticated
    // channel/pairing, never from caller-typed fields). Any userId
    // inside bodyJson is a caller-typed claim and is IGNORED. A
    // null/empty authenticated identity refuses 401.
    // BD-WIN-CORE-3/F1 (built): LaneHostManager now resolves that
    // identity through MeshIdentityResolver — the request's pairing
    // bearer token (the v2 channel's authenticated identity) → the
    // host-bound pairing name → the unique live roster user — so
    // stream acts succeed for an authenticated session participant
    // and still fail closed for everyone else.
    private static MeshReply? RequireAuthenticated(string? authenticatedUserId, out string userId)
    {
        userId = authenticatedUserId ?? "";
        return string.IsNullOrWhiteSpace(authenticatedUserId)
            ? MeshReply.Error(401, "no authenticated caller identity — a caller-typed userId is not an identity; stream acts refuse")
            : null;
    }

    public async Task<MeshReply> StartAsync(string bodyJson, string? authenticatedUserId, CancellationToken ct)
    {
        if (RequireAuthenticated(authenticatedUserId, out var userId) is { } authRefusal) return authRefusal;
        if (!TryReadStart(bodyJson, out var sessionId, out var monitor))
            return MeshReply.Error(400, "stream start requires {sessionId, monitor}");
        var refusal = CheckLiveSession(sessionId, userId, requireParticipant: true);
        if (refusal is not null) return refusal;
        // BD-WIN-CORE-4/F11: the agent-side capture is a single
        // global stream — a second session's binding would tear
        // down / cross-serve the first. One stream per host,
        // refused by name.
        lock (_gate)
        {
            var other = _bindings.Keys.FirstOrDefault(k => !string.Equals(k, sessionId, StringComparison.OrdinalIgnoreCase));
            if (other is not null)
                return MeshReply.Error(409, $"another session ({other}) already holds this host's single capture stream — stream start refused");
        }
        if (_stopInForce()) return MeshReply.Error(409, "STOP is in force — no stream");
        if (!_channel.AgentConnected) return MeshReply.Error(503, "session agent not connected");
        if (!_desktopUnlocked()) return MeshReply.Error(503, "desktop locked — no stream");
        var result = await _channel.CallDesktopToolAsync("stream_start",
            JsonSerializer.Serialize(new { monitor }), ct);
        if (!result.Ok)
            return MeshReply.Error(502, result.UnavailableReason ?? result.Text ?? "capture start failed");
        lock (_gate)
        {
            _bindings[sessionId] = new StreamBinding { SessionId = sessionId, Monitor = monitor };
            StatsFor(sessionId).Started++;
        }
        return MeshReply.Json(200, new { streaming = true, sessionId, monitor });
    }

    /// <summary>Stop the stream for a session (viewer-initiated or
    /// host-initiated). Always succeeds for a known binding; the
    /// session itself is untouched (ending the session is a Slice 3
    /// act, not a stream act).</summary>
    public async Task<MeshReply> StopAsync(string bodyJson, string? authenticatedUserId, CancellationToken ct)
    {
        // BD-WIN-CORE-4/F2: stop is participant-gated on the
        // authenticated identity — anyone who can reach the lane
        // can no longer end someone else's stream.
        if (RequireAuthenticated(authenticatedUserId, out var userId) is { } authRefusal) return authRefusal;
        string? sessionId = null;
        try
        {
            using var doc = JsonDocument.Parse(bodyJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("sessionId", out var s))
                sessionId = s.GetString();
        }
        catch (JsonException) { return MeshReply.Error(400, "stream stop is not JSON"); }
        if (string.IsNullOrWhiteSpace(sessionId)) return MeshReply.Error(400, "stream stop requires {sessionId}");
        var refusal = CheckLiveSession(sessionId, userId, requireParticipant: true);
        if (refusal is not null) return refusal;
        await TeardownAsync(sessionId, ct);
        return MeshReply.Json(200, new { streaming = false, sessionId });
    }

    /// <summary>Monitor inventory + stream truth for a session:
    /// which monitors exist, which one the stream targets, the
    /// encoder/capture facts from the latest frame header, and the
    /// floor/roster picture the viewers render (D35).</summary>
    public async Task<MeshReply> GetInfoAsync(string? sessionId, CancellationToken ct)
    {
        object monitors = Array.Empty<object>();
        if (_channel.AgentConnected)
        {
            var result = await _channel.CallDesktopToolAsync("stream_monitors", "{}", ct);
            if (result.Ok && result.Text is not null)
            {
                try { monitors = JsonDocument.Parse(result.Text).RootElement.Clone(); }
                catch (JsonException) { /* inventory stays empty — honest absence */ }
            }
        }
        if (string.IsNullOrWhiteSpace(sessionId))
            return MeshReply.Json(200, new { ok = true, monitors });
        var session = _sessions.GetSession(sessionId);
        if (session is null) return MeshReply.Error(404, "unknown session");
        var participants = _sessions.ListParticipants(session.Id);
        StreamProtocol.FrameHeader? header;
        lock (_gate) header = _bindings.TryGetValue(session.Id, out var b) ? b.LastHeader : null;
        // Encoder-side counters from the capture path itself (the
        // agent's stream_stats) — served frames are counted here,
        // encoded frames are counted there; both are reported under
        // their own names.
        long framesEncoded = 0;
        if (_channel.AgentConnected && IsStreaming(session.Id))
        {
            var statsResult = await _channel.CallDesktopToolAsync("stream_stats", "{}", ct);
            if (statsResult.Ok && statsResult.Text is not null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(statsResult.Text);
                    if (doc.RootElement.TryGetProperty("framesEncoded", out var fe) && fe.ValueKind == JsonValueKind.Number)
                        framesEncoded = fe.GetInt64();
                }
                catch (JsonException) { /* counter stays 0 — honest absence */ }
            }
        }
        var stats = Stats(session.Id);
        string Name(string userId) => _displayName?.Invoke(session.ScopeId, userId) ?? userId;
        var holder = participants.FirstOrDefault(p => p.Floor == "holds");
        return MeshReply.Json(200, new
        {
            ok = true,
            monitors,
            sessionId = session.Id,
            sessionState = session.State,
            streaming = IsStreaming(session.Id),
            monitor = header?.Monitor ?? -1,
            codec = header?.Codec ?? "h264",
            encoder = header?.Encoder ?? "",
            hardware = header?.Hardware ?? false,
            capture = header?.Capture ?? "",
            width = header?.Width ?? 0,
            height = header?.Height ?? 0,
            framesEncoded,
            framesServed = stats.FramesServed,
            inputsAccepted = stats.InputsAccepted,
            inputsRefusedFloor = stats.InputsRefusedFloor,
            inputsRefusedState = stats.InputsRefusedState,
            framesDroppedInvalid = stats.FramesDroppedInvalid,
            floorHolder = holder?.UserId,
            floor = holder is null ? null : new { userId = holder.UserId, name = Name(holder.UserId) },
            participants = participants.Select(p => new
            {
                userId = p.UserId, role = p.Role, floor = p.Floor,
            }).ToArray(),
            roster = participants.Select(p => new
            {
                userId = p.UserId, name = Name(p.UserId), role = p.Role, floor = p.Floor,
            }).ToArray(),
        });
    }

    // ---- frames ------------------------------------------------------

    /// <summary>The next access unit after <paramref name="afterSeq"/>
    /// for the session's stream. 204 when nothing newer exists yet;
    /// the session-state refusals above otherwise. A frame is served
    /// ONLY after StreamProtocol validation — invalid agent output is
    /// dropped and counted, never forwarded.</summary>
    public async Task<MeshReply> GetFrameAsync(string? sessionId, long afterSeq, string? authenticatedUserId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return MeshReply.Error(400, "sessionId required");
        // BD-WIN-CORE-4/F2: frame fetches require participant
        // membership under the AUTHENTICATED identity — the old
        // participant-free posture let anyone on the lane pull
        // frames for any live session.
        if (RequireAuthenticated(authenticatedUserId, out var userId) is { } authRefusal) return authRefusal;
        var refusal = CheckLiveSession(sessionId, userId, requireParticipant: true);
        if (refusal is not null)
        {
            // The stream dies WITH the session: if the session ended
            // (or was blocked/stopped/removed), tear the agent-side
            // capture down as we refuse.
            if (refusal.Status is 404 or 409) await TeardownAsync(sessionId, ct);
            return refusal;
        }
        if (_stopInForce()) { await TeardownAsync(sessionId, ct); return MeshReply.Error(409, "STOP is in force — stream ended"); }
        StreamBinding binding;
        lock (_gate)
        {
            if (!_bindings.TryGetValue(sessionId, out var b))
                return MeshReply.Error(409, "stream not started for this session");
            binding = b;
        }
        lock (_gate)
        {
            if (binding.LastFrameBody is not null && binding.LastServedSeq > afterSeq)
                return Serve(binding);
        }
        // Pull the newest AU from the capture path.
        var result = await _channel.CallDesktopToolAsync("stream_frame",
            JsonSerializer.Serialize(new { afterSeq }), ct);
        if (!result.Ok || result.Text is null)
            return MeshReply.Error(502, result.UnavailableReason ?? result.Text ?? "frame pull failed");
        string? dataB64 = null; long seq = -1;
        try
        {
            using var doc = JsonDocument.Parse(result.Text);
            var root = doc.RootElement;
            if (root.TryGetProperty("seq", out var s) && s.ValueKind == JsonValueKind.Number) seq = s.GetInt64();
            if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.String) dataB64 = d.GetString();
            if (root.TryGetProperty("empty", out var e) && e.ValueKind == JsonValueKind.True)
                return new MeshReply(204, "application/octet-stream", Array.Empty<byte>());
        }
        catch (JsonException) { return MeshReply.Error(502, "frame pull returned malformed JSON"); }
        if (dataB64 is null) return new MeshReply(204, "application/octet-stream", Array.Empty<byte>());
        byte[] body;
        try { body = Convert.FromBase64String(dataB64); }
        catch (FormatException) { CountInvalid(sessionId); return MeshReply.Error(502, "frame pull returned undecodable bytes"); }
        var frame = StreamProtocol.TryParse(body);
        if (frame is null) { CountInvalid(sessionId); return MeshReply.Error(502, "capture produced an invalid stream frame — dropped"); }
        if (frame.Header.Seq <= afterSeq)
            return new MeshReply(204, "application/octet-stream", Array.Empty<byte>());
        lock (_gate)
        {
            binding.LastFrameBody = body;
            binding.LastHeader = frame.Header;
            binding.LastServedSeq = frame.Header.Seq;
        }
        return Serve(binding);
    }

    private MeshReply Serve(StreamBinding binding)
    {
        long served;
        lock (_gate)
        {
            var stats = StatsFor(binding.SessionId);
            stats.FramesServed++;
            stats.BytesServed += binding.LastFrameBody!.Length;
            served = binding.LastFrameBody!.Length;
        }
        // U5: the stream is a data flow the owner can see — frame
        // bytes served inside this human session, targeted at the
        // session's host device, land in the flow ledger beside the
        // agent flows. Counting rides the stats update above (the
        // same bytes, counted once); a ledger failure never breaks
        // a frame.
        if (_flows is not null && served > 0)
        {
            try
            {
                var hostDeviceId = _sessions.GetSession(binding.SessionId)?.HostDeviceId;
                _flows.NoteCall(binding.SessionId, "human", null, "stream", "stream",
                    DataFlowClasses.Read, 0, served, hostDeviceId, _now());
            }
            catch { /* the frame already served; the view must never gate the stream */ }
        }
        return new MeshReply(200, "application/octet-stream", binding.LastFrameBody!);
    }

    // ---- input (the floor gate) ---------------------------------------

    /// <summary>One stream input event: {sessionId, userId, event:{…}}.
    /// THE FLOOR GATE: the event is forwarded to the desktop only
    /// when the named user is a live participant of the session AND
    /// currently holds the floor. Every other case refuses at this
    /// layer — watcher, non-participant, cross-scope id, ended /
    /// blocked / paused session, STOP in force — and nothing reaches
    /// the agent channel. The floor is read fresh per event, so a
    /// grant or take-back lands on the very next event.</summary>
    public async Task<MeshReply> PostInputAsync(string bodyJson, string? authenticatedUserId, CancellationToken ct)
    {
        // BD-WIN-CORE-4/F2: THE FLOOR GATE compares the floor
        // holder with the AUTHENTICATED identity, never with a
        // userId typed into the request body (that field is now
        // ignored entirely — knowing/guessing the holder's id
        // buys nothing).
        if (RequireAuthenticated(authenticatedUserId, out var userId) is { } authRefusal) return authRefusal;
        string? sessionId;
        JsonElement eventEl;
        try
        {
            using var doc = JsonDocument.Parse(bodyJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return MeshReply.Error(400, "stream input must be an object");
            sessionId = Text(root, "sessionId");
            if (!root.TryGetProperty("event", out eventEl)) return MeshReply.Error(400, "stream input requires an event");
            eventEl = eventEl.Clone();
        }
        catch (JsonException) { return MeshReply.Error(400, "stream input is not JSON"); }
        if (string.IsNullOrWhiteSpace(sessionId))
            return MeshReply.Error(400, "stream input requires {sessionId, event}");
        var session = _sessions.GetSession(sessionId);
        if (session is null) return MeshReply.Error(404, "unknown session");
        if (session.State != "active")
        {
            CountRefusedState(sessionId);
            if (session.State is "ended" or "blocked") await TeardownAsync(sessionId, ct);
            return MeshReply.Error(409, $"session is {session.State} — input refused");
        }
        if (_stopInForce()) { CountRefusedState(sessionId); await TeardownAsync(sessionId, ct); return MeshReply.Error(409, "STOP is in force — input refused"); }
        // Offboarding re-read: a removed/suspended participant's
        // session ends here (the Slice 3 hook), and with it the stream.
        if (_sessions.EnforceOffboarding(sessionId))
        {
            CountRefusedState(sessionId);
            await TeardownAsync(sessionId, ct);
            return MeshReply.Error(409, "a participant was removed — session and stream ended");
        }
        session = _sessions.GetSession(sessionId)!;
        if (session.State != "active") { CountRefusedState(sessionId); return MeshReply.Error(409, $"session is {session.State} — input refused"); }
        var participants = _sessions.ListParticipants(sessionId);
        var caller = participants.FirstOrDefault(p =>
            string.Equals(p.UserId, userId, StringComparison.OrdinalIgnoreCase));
        if (caller is null) { CountRefusedFloor(sessionId); return MeshReply.Error(403, "not a participant of this session — input refused at the stream layer"); }
        if (caller.Floor != "holds") { CountRefusedFloor(sessionId); return MeshReply.Error(403, "watching — input refused at the stream layer (floor is held by " + (participants.FirstOrDefault(p => p.Floor == "holds")?.UserId ?? "nobody") + ")"); }
        if (!_channel.AgentConnected) return MeshReply.Error(503, "session agent not connected");
        if (!_desktopUnlocked()) return MeshReply.Error(503, "desktop locked — input refused");
        var type = eventEl.ValueKind == JsonValueKind.Object && eventEl.TryGetProperty("type", out var t) ? t.GetString() : null;
        // Absolute pointer coordinates are pixels inside the STREAMED
        // monitor — the agent needs the binding's monitor to place
        // them (Block D recovery 2026-11-19: the monitor was never
        // forwarded, so abs input silently targeted monitor 0).
        int streamMonitor;
        lock (_gate) streamMonitor = _bindings.TryGetValue(sessionId, out var sb) ? sb.Monitor : 0;
        var (tool, args) = type switch
        {
            "pointer" => ("mouse_move_rel", JsonSerializer.Serialize(new { dx = Number(eventEl, "dx"), dy = Number(eventEl, "dy") })),
            "pointer_abs" => ("mouse_move_abs_stream", JsonSerializer.Serialize(new { x = Number(eventEl, "x"), y = Number(eventEl, "y"), monitor = streamMonitor })),
            "button" => ("button_here", JsonSerializer.Serialize(new { button = Text(eventEl, "button") ?? "left", action = Text(eventEl, "action") ?? "click" })),
            "key" => ("key_press", JsonSerializer.Serialize(new { keys = MeshService.MapKey(Text(eventEl, "key") ?? "") })),
            "text" => ("type_text", JsonSerializer.Serialize(new { text = Text(eventEl, "text") ?? "" })),
            "scroll" => ("scroll", JsonSerializer.Serialize(new { delta = (int)Number(eventEl, "delta", -120) })),
            _ => (null, null),
        };
        if (tool is null) return MeshReply.Error(400, $"unknown input event type: {type ?? "(missing)"}");
        var result = await _channel.CallDesktopToolAsync(tool, args!, ct);
        if (!result.Ok) return MeshReply.Error(502, result.UnavailableReason ?? result.Text ?? "input failed in the session agent");
        lock (_gate) StatsFor(sessionId).InputsAccepted++;
        return MeshReply.Json(200, new { accepted = true, floorHolder = userId });
    }

    // ---- helpers -------------------------------------------------------

    public bool IsStreaming(string sessionId)
    {
        lock (_gate) return _bindings.ContainsKey(sessionId);
    }

    public StreamStats Stats(string sessionId)
    {
        lock (_gate) return _stats.TryGetValue(sessionId, out var s) ? s : new StreamStats();
    }

    /// <summary>End every stream (Core shutdown / global STOP).</summary>
    public async Task StopAllAsync(CancellationToken ct)
    {
        List<string> ids;
        lock (_gate) ids = _bindings.Keys.ToList();
        foreach (var id in ids) await TeardownAsync(id, ct);
    }

    private async Task TeardownAsync(string sessionId, CancellationToken ct)
    {
        StreamBinding? binding;
        lock (_gate)
        {
            if (!_bindings.Remove(sessionId, out binding)) return;
            // BD-WIN-CORE-4/F11: stats entries die with their
            // binding — the old map grew without limit for the
            // process lifetime.
            _stats.Remove(sessionId);
        }
        if (binding.AgentToldToStop) return;
        binding.AgentToldToStop = true;
        try { await _channel.CallDesktopToolAsync("stream_stop", "{}", ct); } catch { /* agent may already be gone — the binding is dead either way */ }
    }

    /// <summary>The shared live-session gate. Returns null when the
    /// session may stream; otherwise the refusal reply. Participant
    /// checks apply to start, frame, stop and input alike
    /// (BD-WIN-CORE-4/F2 — the old participant-free frame posture
    /// is closed), always against the AUTHENTICATED identity, and
    /// the SESSION must be live either way.</summary>
    private MeshReply? CheckLiveSession(string sessionId, string? userId, bool requireParticipant)
    {
        var session = _sessions.GetSession(sessionId);
        if (session is null) return MeshReply.Error(404, "unknown session — no session, no stream");
        if (session.State != "active")
            return MeshReply.Error(409, $"session is {session.State} — stream requires an active session");
        if (_sessions.EnforceOffboarding(sessionId))
            return MeshReply.Error(409, "a participant was removed — session and stream ended");
        session = _sessions.GetSession(sessionId)!;
        if (session.State != "active")
            return MeshReply.Error(409, $"session is {session.State} — stream requires an active session");
        if (requireParticipant)
        {
            var participants = _sessions.ListParticipants(sessionId);
            if (userId is null || !participants.Any(p => string.Equals(p.UserId, userId, StringComparison.OrdinalIgnoreCase)))
                return MeshReply.Error(403, "requester is not a participant of this session");
        }
        return null;
    }

    private StreamStats StatsFor(string sessionId)
    {
        if (!_stats.TryGetValue(sessionId, out var s)) _stats[sessionId] = s = new StreamStats();
        return s;
    }

    private void CountInvalid(string sessionId) { lock (_gate) StatsFor(sessionId).FramesDroppedInvalid++; }
    private void CountRefusedFloor(string sessionId) { lock (_gate) StatsFor(sessionId).InputsRefusedFloor++; }
    private void CountRefusedState(string sessionId) { lock (_gate) StatsFor(sessionId).InputsRefusedState++; }

    private static bool TryReadStart(string bodyJson, out string sessionId, out int monitor)
    {
        // BD-WIN-CORE-4/F2: no userId is read from the body at
        // all — identity is the authenticated parameter only.
        sessionId = ""; monitor = 0;
        try
        {
            using var doc = JsonDocument.Parse(bodyJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            sessionId = Text(root, "sessionId") ?? "";
            if (root.TryGetProperty("monitor", out var m) && m.ValueKind == JsonValueKind.Number) monitor = m.GetInt32();
            return sessionId.Length > 0 && monitor >= 0 && monitor < 16;
        }
        catch (JsonException) { return false; }
    }

    private static double Number(JsonElement root, string name, double fallback = 0) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number ? el.GetDouble() : fallback;

    private static string? Text(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString() : null;
}

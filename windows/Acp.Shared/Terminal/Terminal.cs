using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Sessions;

namespace Acp.Shared.Terminal;

// =====================================================================
// Terminal channel (Block F, Slice 6). A session-scoped shell:
//
//  * A terminal exists ONLY inside a live session. It is opened by
//    a session act, it dies with the session, and there is no API
//    by which a terminal can exist outside one — the record is
//    keyed by session and every operation re-reads the session's
//    state fresh, so an ended/blocked session's terminal refuses
//    on the very next call.
//  * Only the floor holder's keystrokes reach it. The floor is
//    read fresh from the session model per write — a watcher, a
//    former floor holder, and a non-participant are all refused
//    identically, at this layer, never merely in a UI.
//  * It is participant-visible: the session's event list carries
//    terminal_opened / terminal_closed markers (so the roster and
//    the replay show a terminal was open), and its OUTPUT lines
//    are part of the session record — the replay source. Input is
//    recorded as a redacted marker only (keystrokes can carry
//    secrets; the replay never stores them).
//  * AI leash (D9): `terminal` is a NAMED capability in the pairing
//    scope, default OFF for AIs. An AI participant reaches a
//    terminal only when the capability delegate the composition
//    root supplies (reading the pairing's scope) says so — the
//    model itself grants an AI nothing.
// The actual shell process is a platform component behind
// ITerminalSink (ConPTY on the Windows host); this service is the
// authority every keystroke and output line passes.
// =====================================================================

public sealed record TerminalInfo(
    string Id, string SessionId, string OpenedByUserId,
    DateTimeOffset OpenedUtc, bool IsOpen, int OutputLines);

public interface ITerminalSink
{
    /// <summary>Start the platform shell for a terminal the service
    /// has just opened (gates already passed).</summary>
    void Start(string terminalId);
    /// <summary>Deliver keystrokes to the platform shell. Called
    /// ONLY after TerminalService's gates pass.</summary>
    void Write(string terminalId, string text);
    /// <summary>Tear the platform shell down (session end / close).</summary>
    void Close(string terminalId);
}

public sealed class TerminalService
{
    private sealed class TerminalState
    {
        public required string Id;
        public required string SessionId;
        public required string OpenedBy;
        public required DateTimeOffset OpenedUtc;
        public bool Closed;
        public List<string> Output { get; } = new();
    }

    /// <summary>BD-SHARED-SESSION F7: output is a bounded ring —
    /// the newest MaxOutputLines lines are the replay source; older
    /// lines are dropped, never an unbounded in-memory list.</summary>
    public const int MaxOutputLines = 2000;

    private readonly SessionService _sessions;
    private readonly RosterService _roster;
    private readonly Func<string, string, bool> _aiTerminalCapability;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly ITerminalSink? _sink;
    private readonly Dictionary<string, TerminalState> _terminals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <param name="aiTerminalCapability">(scopeId, aiUserId) → the
    /// pairing scope for that AI names the `terminal` capability.
    /// Null (the default posture) = no AI may use a terminal.</param>
    /// <param name="featureGate">BD-SHARED-SESSION F2: TOTAL POLICY
    /// CONTROL gate (scopeId, featureKey "terminal"), the same
    /// scope-aware shape the tunnel service takes. Null = no policy
    /// loaded.</param>
    public TerminalService(SessionService sessions, RosterService roster,
        Func<string, string, bool>? aiTerminalCapability = null, ITerminalSink? sink = null,
        Func<string, string, PolicyVerdict>? featureGate = null)
    {
        _sessions = sessions; _roster = roster;
        _aiTerminalCapability = aiTerminalCapability ?? ((_, _) => false);
        _sink = sink;
        _featureGate = featureGate;
    }

    /// <summary>The policy feature key the terminal consults.</summary>
    public const string FeatureKey = "terminal";

    private bool FeatureAllowed(Session session) =>
        _featureGate?.Invoke(session.ScopeId, FeatureKey).Allowed ?? true;

    /// <summary>BD-SHARED-SESSION F2 — the fresh gating every Open
    /// and Write now runs, identical in shape to every other session
    /// surface: the offboarding re-read (a suspended/removed
    /// participant ends the session on the spot), the policy feature
    /// gate, and — inside CapabilityGate — the suspended check and
    /// the AF3 "use"-grant re-read for non-host actors.</summary>
    private bool FreshGate(Session session, string actorUserId, Participant? actor, out string reason)
    {
        reason = "";
        if (_sessions.EnforceOffboarding(session.Id)) { reason = "a participant was removed or suspended — the session ended (D14)"; return false; }
        if (!FeatureAllowed(session)) { reason = "policy no longer allows the terminal feature for this scope"; return false; }
        if (!CapabilityGate(session, actorUserId, out reason)) return false;
        if (actor is not null && actor.Role != "host" && !_sessions.HoldsUseGrant(session.Id, actorUserId))
        { reason = "the 'use' grant on the host device's group is no longer held — terminal refused"; return false; }
        return true;
    }

    /// <summary>Policy-change teardown sweep (BD-SHARED-SESSION F2):
    /// when a policy reload disables the terminal feature, every
    /// open terminal on a session of that scope closes on the spot.
    /// Returns the number closed.</summary>
    public int SweepPolicyTeardown(string scopeId, Func<string, bool> featureDisabled)
    {
        if (!featureDisabled(FeatureKey)) return 0;
        var closed = 0;
        lock (_gate)
        {
            foreach (var t in _terminals.Values.Where(x => !x.Closed).ToList())
            {
                var s = _sessions.GetSession(t.SessionId);
                if (s is null || !string.Equals(s.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase)) continue;
                CloseInternal(t, "policy");
                _sessions.AppendEvent(t.SessionId, "terminal_closed", "policy", t.Id,
                    "Terminal closed: a policy change disabled the terminal feature for this scope.");
                closed++;
            }
        }
        return closed;
    }

    public (bool Ok, string Detail, TerminalInfo? Terminal) Open(string sessionId, string actorUserId, DateTimeOffset now)
    {
        var session = _sessions.GetSession(sessionId);
        if (session is null) return (false, "unknown session — a terminal exists only inside a session", null);
        if (session.State != "active") return (false, $"session is {session.State} — a terminal opens only in an active session", null);
        var participants = _sessions.ListParticipants(sessionId);
        var actor = participants.FirstOrDefault(p => string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (actor is null) return (false, "not a participant of this session — terminal refused", null);
        if (!FreshGate(session, actorUserId, actor, out var capReason)) return (false, capReason, null);
        var isHost = actor.Role == "host";
        var holdsFloor = actor.Floor == "holds";
        if (!isHost && !holdsFloor)
            return (false, "only the host or the floor holder may open the session terminal", null);
        lock (_gate)
        {
            var existing = _terminals.Values.FirstOrDefault(t => t.SessionId == sessionId && !t.Closed);
            if (existing is not null)
                return (true, "terminal already open for this session", Shape(existing, session));
            var t = new TerminalState
            {
                Id = Guid.NewGuid().ToString("N"),
                SessionId = sessionId,
                OpenedBy = actorUserId,
                OpenedUtc = now,
            };
            _terminals[t.Id] = t;
            try { _sink?.Start(t.Id); } catch { /* a shell that cannot start leaves the record; writes will surface it */ }
            _sessions.AppendEvent(sessionId, "terminal_opened", actorUserId, t.Id,
                $"Terminal opened by {actorUserId} (session act; keystrokes reach it only from the floor holder)");
            return (true, "terminal open", Shape(t, session));
        }
    }

    /// <summary>One keystroke batch. THE gate: fresh session state,
    /// fresh floor, fresh capability — every call, no caching.</summary>
    public (bool Ok, string Detail) Write(string terminalId, string actorUserId, string text)
    {
        TerminalState? t;
        lock (_gate) _terminals.TryGetValue(terminalId ?? "", out t);
        if (t is null || t.Closed) return (false, "no such open terminal");
        var session = _sessions.GetSession(t.SessionId);
        if (session is null || session.State is "ended" or "blocked")
        { CloseInternal(t, "session_ended"); return (false, "the session has ended — the terminal died with it"); }
        // BD-SHARED-SESSION F7: a PAUSED session refuses the write
        // WITHOUT closing — pause is not death (tunnels already
        // survive pause; the terminal now matches).
        if (session.State != "active") return (false, $"session is {session.State} — keystrokes refused while paused, terminal kept open");
        var actor = _sessions.ListParticipants(t.SessionId)
            .FirstOrDefault(p => string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (actor is null) return (false, "not a participant of this session — keystrokes refused");
        if (!FreshGate(session, actorUserId, actor, out var capReason)) return (false, capReason);
        if (actor.Floor != "holds")
            return (false, "watching — only the floor holder's keystrokes reach the terminal");
        _sink?.Write(t.Id, text ?? "");
        _sessions.AppendEvent(t.SessionId, "terminal_input", actorUserId, t.Id,
            $"keystrokes delivered ({(text ?? "").Length} chars; content never recorded)");
        return (true, "delivered");
    }

    /// <summary>Output from the platform shell. Output IS part of
    /// the session record (the replay source), so it is kept on the
    /// terminal record and counted on the session picture.</summary>
    public bool AppendOutput(string terminalId, string line)
    {
        lock (_gate)
        {
            if (!_terminals.TryGetValue(terminalId ?? "", out var t) || t.Closed) return false;
            var session = _sessions.GetSession(t.SessionId);
            if (session is null || session.State is "ended" or "blocked") { CloseInternal(t, "session_ended"); return false; }
            t.Output.Add(line ?? "");
            if (t.Output.Count > MaxOutputLines) t.Output.RemoveRange(0, t.Output.Count - MaxOutputLines);
            return true;
        }
    }

    public IReadOnlyList<string> Output(string terminalId)
    {
        lock (_gate)
            return _terminals.TryGetValue(terminalId ?? "", out var t) ? t.Output.ToList() : new List<string>();
    }

    public (bool Ok, string Detail) Close(string terminalId, string actorUserId)
    {
        TerminalState? t;
        lock (_gate) _terminals.TryGetValue(terminalId ?? "", out t);
        if (t is null || t.Closed) return (false, "no such open terminal");
        var session = _sessions.GetSession(t.SessionId);
        var actor = session is null ? null : _sessions.ListParticipants(t.SessionId)
            .FirstOrDefault(p => string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        var isHostSide = actor is not null && actor.Role == "host";
        if (!isHostSide && !string.Equals(t.OpenedBy, actorUserId, StringComparison.OrdinalIgnoreCase) &&
            !(session is not null && string.Equals(session.AcceptedByUserId, actorUserId, StringComparison.OrdinalIgnoreCase)))
            return (false, "only the opener or the host side may close the terminal");
        CloseInternal(t, "closed");
        if (session is not null)
            _sessions.AppendEvent(t.SessionId, "terminal_closed", actorUserId, t.Id, "Terminal closed");
        return (true, "terminal closed");
    }

    /// <summary>Roster visibility: the open terminal for a session,
    /// or null. A terminal on an ended session is never reported
    /// open — it died with the session.</summary>
    public TerminalInfo? OpenTerminalFor(string sessionId)
    {
        var session = _sessions.GetSession(sessionId);
        lock (_gate)
        {
            var t = _terminals.Values.FirstOrDefault(x => x.SessionId == sessionId && !x.Closed);
            if (t is null) return null;
            if (session is null || session.State is "ended" or "blocked") { CloseInternal(t, "session_ended"); return null; }
            return Shape(t, session);
        }
    }

    /// <summary>Sweep: close every terminal whose session has ended
    /// (the supervisor calls this on session end / STOP; per-call
    /// re-reads are the backstop that makes the sweep non-load-bearing).</summary>
    public int ReapEnded()
    {
        var closed = 0;
        lock (_gate)
        {
            foreach (var t in _terminals.Values.Where(x => !x.Closed).ToList())
            {
                var s = _sessions.GetSession(t.SessionId);
                if (s is null || s.State == "ended" || s.State == "blocked") { CloseInternal(t, "session_ended"); closed++; }
            }
        }
        return closed;
    }

    private bool CapabilityGate(Session session, string userId, out string reason)
    {
        reason = "";
        var user = _roster.GetUser(session.ScopeId, userId);
        if (user is not null && user.Suspended)
        {
            reason = "suspended users hold no terminal authority — refused";
            return false;
        }
        if (user is not null && user.Kind == "ai" && !_aiTerminalCapability(session.ScopeId, userId))
        {
            reason = "AI participants need the pairing scope's named `terminal` capability (default OFF, D9) — refused";
            return false;
        }
        return true;
    }

    private void CloseInternal(TerminalState t, string why)
    {
        if (t.Closed) return;
        t.Closed = true;
        try { _sink?.Close(t.Id); } catch { /* the record is closed either way */ }
    }

    private static TerminalInfo Shape(TerminalState t, Session session) =>
        new(t.Id, t.SessionId, t.OpenedBy, t.OpenedUtc,
            !t.Closed && session.State is "active" or "paused", t.Output.Count);

    // ---- persistence (BD-SHARED-SESSION F7) ----------------------
    // Output was claimed as "part of the session record (the replay
    // source)" but lived only in memory. It now exports/imports with
    // the terminal record (bounded by the ring cap). Import restores
    // a terminal CLOSED: a restart leaves nothing live behind a
    // record — its output survives for replay, its shell does not.

    private sealed record TerminalDto(string Id, string SessionId, string OpenedBy,
        DateTimeOffset OpenedUtc, string[] Output);

    public string ExportJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(_terminals.Values.Select(t => new TerminalDto(
                t.Id, t.SessionId, t.OpenedBy, t.OpenedUtc, t.Output.ToArray())).ToArray());
    }

    public int ImportJson(string json)
    {
        TerminalDto[]? dtos;
        try { dtos = JsonSerializer.Deserialize<TerminalDto[]>(json); } catch { return 0; }
        if (dtos is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in dtos)
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    string.IsNullOrWhiteSpace(dto.SessionId) || _terminals.ContainsKey(dto.Id)) continue;
                var t = new TerminalState { Id = dto.Id, SessionId = dto.SessionId,
                    OpenedBy = dto.OpenedBy ?? "", OpenedUtc = dto.OpenedUtc, Closed = true };
                foreach (var line in (dto.Output ?? Array.Empty<string>()).TakeLast(MaxOutputLines))
                    t.Output.Add(line ?? "");
                _terminals[t.Id] = t;
                restored++;
            }
        }
        return restored;
    }
}

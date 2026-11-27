using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Core.Services;

/// <summary>One Slice 3 human session, shaped for operator-side
/// readers (host-state snapshot, mesh state, session_status,
/// presence). Facts only: ids, names resolved from the roster,
/// states, counts. No key material, no chat bodies, no recording
/// references — a recording's existence is a state, its path is not
/// an operator-surface fact.</summary>
public sealed record HumanSessionFact(
    string Id,
    string ScopeId,
    string HostDeviceId,
    string InitiatorUserId,
    string InitiatorName,
    string Kind,
    string State,
    DateTimeOffset? StartedUtc,
    long Seconds,
    string Recording,
    bool IsRecording,
    string? AcceptedByUserId,
    string? AcceptOrigin,
    string? FloorHolderUserId,
    string? FloorHolderName,
    int ParticipantCount,
    int Actions,
    IReadOnlyList<ParticipantFact> Participants,
    IReadOnlyList<SessionEventFact> RecentEvents,
    // Block F (D35): a terminal open on this session is a roster
    // fact — participant-visible by design. Enriched by the Core
    // (the picture itself stays a pure shaping over the stores).
    bool TerminalOpen = false,
    // Block G (G-02/G-03/G-07/G-05): the session-surface flags and
    // the live call are presence facts — the presence payload reads
    // this picture, so a blanked screen, a blocked input, a
    // watermark, or a live call is visible in exactly the same
    // shape on every surface, never a hidden state.
    bool Blanked = false,
    bool InputBlocked = false,
    bool Watermarked = false,
    string? LiveCallKind = null,
    string? LiveCallState = null,
    // U5 data-flow transparency: file bytes that moved inside this
    // session, derived at shaping time from the FileJob records the
    // store already keeps (to_host = in, from_host = out) — no new
    // collection. Destinations names the device ids those bytes
    // targeted (the host device for to_host jobs; a from_host job's
    // target device is not in the existing records, so it is not
    // invented here). Stream bytes ride the U5 flow ledger instead
    // (StreamService is their choke point) and surface in the
    // data-flow report, not in this picture.
    long BytesIn = 0,
    long BytesOut = 0,
    IReadOnlyList<string>? Destinations = null);

/// <summary>One participant (D35): role, floor state, and the
/// transport the session runs on (the session's rung — every
/// participant's traffic rides it).</summary>
public sealed record ParticipantFact(string UserId, string Name, string Role, string Floor, string Transport = "");
public sealed record SessionEventFact(DateTimeOffset Utc, string Kind, string? ActorUserId, string Detail);

/// <summary>
/// The ONE session picture (Block A wiring, 2026-11-19): every
/// operator-side surface — the host window's snapshot, the mesh
/// state the phone reads, the MCP session_status tool, and the
/// presence payload — derives its Slice 3 facts here, from the live
/// SessionService + RosterService stores, so a human session started
/// from the host window appears in all of them identically. Pure
/// shaping over the stores; unit-testable without a runtime.
/// </summary>
public static class SessionPicture
{
    /// <summary>States in which a human session is LIVE for presence
    /// and mesh purposes: it has started (or is stoppable mid-flight)
    /// and has not ended. "requested" is not live — nothing is being
    /// controlled yet, and presence must not pretend otherwise.</summary>
    public static bool IsLive(Session session) =>
        session.State is "active" or "paused" or "blocked";

    public static HumanSessionFact Shape(SessionService sessions, RosterService roster, Session session, DateTimeOffset now)
    {
        string Name(string? userId) =>
            userId is null ? "" : roster.GetUser(session.ScopeId, userId)?.DisplayName ?? userId;
        var participants = sessions.ListParticipants(session.Id)
            .Select(p => new ParticipantFact(p.UserId, Name(p.UserId), p.Role, p.Floor, session.TransportRung))
            .ToList();
        var floor = participants.FirstOrDefault(p => p.Floor == "holds");
        var events = sessions.ListEvents(session.Id);
        var fileJobs = sessions.ListFileJobs(session.Id);
        var actions = sessions.ListChat(session.Id).Count + fileJobs.Count;
        // U5: flow totals from the file-job records themselves —
        // transferred bytes only (a job's declared size is a claim;
        // its transferred count is the record of what moved).
        long bytesIn = 0, bytesOut = 0;
        var destinations = new List<string>();
        foreach (var job in fileJobs)
        {
            if (job.Direction == "to_host")
            {
                bytesIn += job.TransferredBytes;
                if (!destinations.Contains(session.HostDeviceId)) destinations.Add(session.HostDeviceId);
            }
            else if (job.Direction == "from_host")
            {
                bytesOut += job.TransferredBytes;
            }
        }
        var liveCall = sessions.GetLiveCall(session.Id);
        return new HumanSessionFact(
            Id: session.Id,
            ScopeId: session.ScopeId,
            HostDeviceId: session.HostDeviceId,
            InitiatorUserId: session.InitiatorUserId,
            InitiatorName: Name(session.InitiatorUserId),
            Kind: session.Kind,
            State: session.State,
            StartedUtc: session.StartedUtc,
            Seconds: session.StartedUtc is { } started && session.State != "ended"
                ? Math.Max(0, (long)(now - started).TotalSeconds)
                : session.StartedUtc is { } st && session.EndedUtc is { } en
                    ? Math.Max(0, (long)(en - st).TotalSeconds)
                    : 0,
            Recording: session.Recording,
            IsRecording: session.IsRecording,
            AcceptedByUserId: session.AcceptedByUserId,
            AcceptOrigin: session.AcceptOrigin,
            FloorHolderUserId: floor?.UserId,
            FloorHolderName: floor?.Name,
            ParticipantCount: participants.Count,
            Actions: actions,
            Participants: participants,
            RecentEvents: events.TakeLast(20)
                .Select(e => new SessionEventFact(e.Utc, e.Kind, e.ActorUserId, e.Detail))
                .ToList(),
            Blanked: session.Blanked,
            InputBlocked: session.InputBlocked,
            Watermarked: session.Watermarked,
            LiveCallKind: liveCall?.Kind,
            LiveCallState: liveCall?.State,
            BytesIn: bytesIn,
            BytesOut: bytesOut,
            Destinations: destinations);
    }

    /// <summary>All human sessions (every state), newest first by
    /// start/creation — the operator list shape.</summary>
    public static IReadOnlyList<HumanSessionFact> All(SessionService sessions, RosterService roster, DateTimeOffset now) =>
        sessions.ListSessions()
            .Select(s => Shape(sessions, roster, s, now))
            .OrderByDescending(f => f.StartedUtc ?? DateTimeOffset.MinValue)
            .ToList();

    /// <summary>The primary LIVE human session for presence/mesh:
    /// an active one wins over paused, paused over blocked; ties
    /// break to the most recently started. Null when none is live.</summary>
    public static HumanSessionFact? PrimaryLive(SessionService sessions, RosterService roster, DateTimeOffset now)
    {
        var live = sessions.ListSessions().Where(IsLive).ToList();
        if (live.Count == 0) return null;
        var rank = new Dictionary<string, int> { ["active"] = 0, ["paused"] = 1, ["blocked"] = 2 };
        var chosen = live
            .OrderBy(s => rank.TryGetValue(s.State, out var r) ? r : 3)
            .ThenByDescending(s => s.StartedUtc ?? DateTimeOffset.MinValue)
            .First();
        return Shape(sessions, roster, chosen, now);
    }
}

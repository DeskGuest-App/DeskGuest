using System.Text.Json;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Presence;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.Sessions;

/// <summary>A human remote session, first-class (Slice 3). State is
/// one of requested|active|paused|blocked|ended and moves ONLY along
/// the closed transition set enforced by SessionService (blocked →
/// ended is the only edge out of blocked, so the 2026-11-17 STOP
/// trap — a live session the host cannot clear — is structurally
/// impossible). Recording is a flag ON this record: there is no
/// second, hidden recording state anywhere, so IsRecording is always
/// derivable from the record itself and covert recording is
/// unrepresentable (D36 / SPEC §7.10).</summary>
public sealed record Session(
    string Id,
    string ScopeId,
    string HostDeviceId,
    string InitiatorUserId,
    string Kind,
    string State,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? EndedUtc,
    string TransportRung,
    string Recording,
    string? RecordingRef = null,
    string? AcceptedByUserId = null,
    string? EndReason = null,
    string? AcceptOrigin = null,
    // Block G session-surface flags (G-02/G-03/G-07). Each is a
    // flag ON this record for the same reason Recording is: the
    // state must be derivable from the record itself, so there is
    // no way for the host screen to be blanked, local input to be
    // blocked, or the stream to be watermarked without the record
    // — and therefore the presence layer, which reads this record —
    // saying so. All three clear on session end (EndLocked).
    bool Blanked = false,
    bool InputBlocked = false,
    bool Watermarked = false,
    // FR-120 (W73): THE ACTIVE TAKEOVER MODES ARE PART OF THE
    // SESSION RECORD — the mouse/keyboard modes in force when
    // this session was created, by name. Null on records created
    // before FR-120 (or by callers that do not carry modes);
    // mid-session changes and takeover events land in the event
    // list (TakeoverRecordKinds), never by rewriting these.
    string? MouseTakeoverMode = null,
    string? KeyboardTakeoverMode = null)
{
    /// <summary>True while this session is capturing, derived ONLY
    /// from this record (D36): a non-ended, started session whose
    /// Recording flag is not "none" is recording, and the presence
    /// layer reads exactly this — there is no state in which a
    /// session records without this being true.</summary>
    public bool IsRecording =>
        Recording != "none" && State is "active" or "paused" or "blocked";
}

/// <summary>A session participant (D35, model half). Floor is
/// "holds" | "watching"; at most ONE participant per session holds
/// the floor at any moment — granting the floor revokes it from the
/// previous holder in the same atomic store update.</summary>
public sealed record Participant(
    string SessionId,
    string UserId,
    string Role,
    string Floor);

/// <summary>One entry in a session's append-only event list. The
/// list is the structured replay's data source (D36 form 2): every
/// lifecycle transition, consent act, floor act, and chat/file
/// marker lands here with its timestamp and actor.</summary>
public sealed record SessionEvent(
    DateTimeOffset Utc,
    string Kind,
    string? ActorUserId,
    string? SubjectId,
    string Detail);

/// <summary>A session chat message (Slice 3, model half). Senders
/// must be participants of the session; an ended session refuses.</summary>
public sealed record ChatMessage(
    string SessionId,
    string SenderUserId,
    DateTimeOffset Utc,
    string Text);

/// <summary>A file-transfer job (Slice 3, model half). Progress is
/// monotonic — TransferredBytes never decreases — and "done"
/// requires TransferredBytes == SizeBytes. Jobs on an ended session
/// are forced "cancelled" by the session-end cascade.</summary>
public sealed record FileJob(
    string Id,
    string SessionId,
    string Direction,
    string Name,
    long SizeBytes,
    long TransferredBytes,
    string State);

/// <summary>An in-session voice/video call (Block G, G-05; the
/// chat third of the census row was Slice 3). The model carries
/// the call's signaling state only — ringing | active | ended —
/// between participants of ONE session; the media leg itself is a
/// platform surface (capture/encode/transport), labeled as such
/// wherever it is surfaced, never claimed by this record. A call
/// is not a session: it lives and dies inside one, and the
/// session-end cascade ends it like every other session content.</summary>
public sealed record SessionCall(
    string Id,
    string SessionId,
    string Kind,
    string State,
    string InitiatorUserId,
    DateTimeOffset StartedUtc,
    DateTimeOffset? AnsweredUtc,
    DateTimeOffset? EndedUtc);

/// <summary>G-07 — the watermark text, DERIVED, never supplied.
/// The stream layer renders this into the picture; it is computed
/// from the session record and the roster so the name stamped into
/// a stream or recording is the name of the person actually
/// driving (the floor holder, else the initiator) — a caller can
/// never stamp someone else's name, and an unknown user stamps
/// their bare id rather than an invented name.</summary>
public static class WatermarkSpec
{
    public sealed record Spec(string Text, string OperatorUserId);

    // W12 / DS-P5-F11: internal — the only caller is
    // SessionService.GetWatermark, which passes the session's OWN
    // live participants. A public Derive trusted any caller-supplied
    // participant list, so a fabricated floor holder could stamp
    // someone else's name into a recording.
    internal static Spec Derive(Session session, RosterService roster, IEnumerable<Participant> participants)
    {
        var holder = participants?.FirstOrDefault(p =>
            p.Floor == "holds" && string.Equals(p.SessionId, session.Id, StringComparison.OrdinalIgnoreCase));
        var operatorId = holder?.UserId ?? session.InitiatorUserId;
        var user = roster.GetUser(session.ScopeId, operatorId);
        var name = user is not null && !string.IsNullOrWhiteSpace(user.DisplayName)
            ? user.DisplayName.Trim() : operatorId;
        var shortId = session.Id.Length > 8 ? session.Id[..8] : session.Id;
        return new Spec($"{name} ({operatorId}) · session {shortId} · {session.ScopeId}", operatorId);
    }
}

/// <summary>Where an accept act originated (RULINGS — 2026-11-19,
/// resolving DG-FIND-05). Acceptance is an ENDPOINT-LOCAL act, not a
/// second-person act: only an accept event the endpoint host's own
/// software generates from a local interaction at the controlled
/// machine counts as consent. An accept arriving over the channel
/// that initiated the session is the requester approving their own
/// request and NEVER counts, in any scope.</summary>
public enum SessionAcceptOrigin
{
    /// <summary>Generated by the endpoint host's local UI from a
    /// local interaction at the controlled machine.</summary>
    EndpointLocal,

    /// <summary>Arrived over the initiating channel (the requester's
    /// side). Always refused as an accept.</summary>
    InitiatingChannel,
}

/// <summary>
/// The human session-model store (Slice 3), mirroring the
/// PairingService / EnrollmentService / RosterService discipline:
/// ExportJson/ImportJson + Changed, malformed entries skipped on
/// import, never fatal. Guard refusals (illegal transition, missing
/// consent, missing grant, non-host actor, removed participant,
/// remote recording ref, non-monotonic progress) return false/null —
/// fail-closed, never an exception and never a partial mutation:
/// an illegal transition changes NOTHING (state, timestamps, and
/// the event list are all untouched).
///
/// Consent lives IN the model (SPEC §7.10 — automation never covers
/// consent): an attended session cannot leave "requested" without a
/// recorded host-side accept; an unattended session cannot start
/// unless the initiator holds the Slice 2 "use" grant on the host's
/// device group; StopSession terminates from every non-ended state.
/// </summary>
public sealed class SessionService
{
    /// <summary>Valid session kinds (Slice 3 spec; "camera_share"
    /// added by RMM-22 — a camera-share is a session KIND in this
    /// model, not a parallel system. Its lifecycle is owned by
    /// CameraShareService, the phone-owner-initiated path: the
    /// generic CreateSession/StartSession below REFUSE the kind,
    /// so no caller of this service can mint or start one — above
    /// all not the watcher side).</summary>
    public static readonly IReadOnlySet<string> ValidKinds =
        new HashSet<string> { "attended", "unattended", "camera_share" };

    /// <summary>Valid session states (Slice 3 spec).</summary>
    public static readonly IReadOnlySet<string> ValidStates =
        new HashSet<string> { "requested", "active", "paused", "blocked", "ended" };

    /// <summary>Valid participant roles (D35).</summary>
    public static readonly IReadOnlySet<string> ValidRoles =
        new HashSet<string> { "host", "controller", "watcher" };

    /// <summary>Valid recording modes (D36): "none", video form,
    /// replay form, or both.</summary>
    public static readonly IReadOnlySet<string> ValidRecordings =
        new HashSet<string> { "none", "video", "replay", "both" };

    /// <summary>Valid file-job directions (Slice 3 spec).</summary>
    public static readonly IReadOnlySet<string> ValidDirections =
        new HashSet<string> { "to_host", "from_host" };

    /// <summary>Valid in-session call kinds (G-05).</summary>
    public static readonly IReadOnlySet<string> ValidCallKinds =
        new HashSet<string> { "audio", "video" };

    /// <summary>Valid in-session call states (G-05): ringing →
    /// active → ended, or ringing → ended (declined/unanswered).</summary>
    public static readonly IReadOnlySet<string> ValidCallStates =
        new HashSet<string> { "ringing", "active", "ended" };

    /// <summary>Valid file-job states (Slice 3 spec).</summary>
    public static readonly IReadOnlySet<string> ValidFileJobStates =
        new HashSet<string> { "queued", "active", "paused", "done", "failed", "cancelled" };

    /// <summary>End reason recorded when the host stops a session.</summary>
    public const string EndReasonHostStop = "host_stop";

    /// <summary>End reason recorded when the offboarding hook ends a
    /// session (a participant was removed or suspended, D14).</summary>
    public const string EndReasonParticipantRemoved = "participant_removed";

    /// <summary>End reason for an ordinary EndSession.</summary>
    public const string EndReasonEnded = "ended";

    /// <summary>End reason applied by ImportJson when a stored
    /// session fails consent/offboarding re-validation (D38 F7): a
    /// hand-edited store can never produce a live session whose
    /// consent was never recorded.</summary>
    public const string EndReasonImportRepair = "import_repair";

    /// <summary>End reason applied by ReconcileAfterRestart (D38
    /// F11): a Core restart leaves nothing live behind a restored
    /// session record.</summary>
    public const string EndReasonCoreRestart = "core_restart";

    /// <summary>End reason applied by the transport failover engine
    /// (D29/D32): the rung carrying a live session died; the session
    /// ends honestly and a NEW session re-establishes on the next
    /// rung — a reconnect, never a pretend-seamless stream.</summary>
    public const string EndReasonTransportFailover = "transport_failover";

    /// <summary>End reason applied by EndSessionsForDevice (W12 /
    /// DS-P5-F2): the host device's enrollment was revoked.</summary>
    public const string EndReasonDeviceRevoked = "device_revoked";

    /// <summary>Stored form of <see cref="SessionAcceptOrigin.EndpointLocal"/>
    /// on the session record (Session.AcceptOrigin).</summary>
    public const string AcceptOriginEndpointLocal = "endpoint_local";

    /// <summary>Stored form of <see cref="SessionAcceptOrigin.InitiatingChannel"/>.
    /// Never written by AcceptSession (channel accepts refuse); it can
    /// only arrive via a hand-edited/imported store, where import
    /// treats it as no consent at all.</summary>
    public const string AcceptOriginInitiatingChannel = "initiating_channel";

    /// <summary>The closed state-transition set (Slice 3 spec):
    /// requested→active|ended; active→paused|blocked|ended;
    /// paused→active|blocked|ended; blocked→ended ONLY; ended is
    /// terminal. Anything else is illegal and refuses.</summary>
    public static bool IsLegalTransition(string? from, string? to)
    {
        var f = (from ?? "").Trim().ToLowerInvariant();
        var t = (to ?? "").Trim().ToLowerInvariant();
        return (f, t) switch
        {
            ("requested", "active") => true,
            ("requested", "ended") => true,
            ("active", "paused") => true,
            ("active", "blocked") => true,
            ("active", "ended") => true,
            ("paused", "active") => true,
            ("paused", "blocked") => true,
            ("paused", "ended") => true,
            ("blocked", "ended") => true,
            _ => false,
        };
    }

    /// <summary>The closed file-job transition set. Terminal states
    /// (done/failed/cancelled) have no outgoing edges; "done"
    /// additionally requires full bytes (enforced in SetFileJobState,
    /// not expressible in this table).</summary>
    public static bool IsLegalFileJobTransition(string? from, string? to)
    {
        var f = (from ?? "").Trim().ToLowerInvariant();
        var t = (to ?? "").Trim().ToLowerInvariant();
        return (f, t) switch
        {
            ("queued", "active") => true,
            ("queued", "paused") => true,
            ("queued", "failed") => true,
            ("queued", "cancelled") => true,
            ("active", "paused") => true,
            ("active", "done") => true,
            ("active", "failed") => true,
            ("active", "cancelled") => true,
            ("paused", "active") => true,
            ("paused", "done") => true,
            ("paused", "failed") => true,
            ("paused", "cancelled") => true,
            _ => false,
        };
    }

    /// <summary>True when a recording reference points at a remote
    /// location (D36: recording storage is local to the user's own
    /// devices — never a cloud/remote reference). Any absolute URI
    /// whose scheme is not "file", any UNC/network path, and any
    /// protocol-relative "//host" path is remote. Plain local paths
    /// (POSIX, Windows drive, relative) and file:// URIs are local.</summary>
    public static bool IsRemoteRecordingRef(string? recordingRef)
    {
        if (string.IsNullOrWhiteSpace(recordingRef)) return false;
        var t = recordingRef.Trim();
        if (t.StartsWith("//", StringComparison.Ordinal) || t.StartsWith("\\\\", StringComparison.Ordinal) ||
            t.StartsWith("\\/", StringComparison.Ordinal) || t.StartsWith("/\\", StringComparison.Ordinal))
            return true; // protocol-relative or UNC network path, incl. mixed separators (D38 F6)
        if (t.Length >= 3 && char.IsLetter(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/'))
            return false; // Windows drive path — local
        if (Uri.TryCreate(t, UriKind.Absolute, out var uri))
        {
            if (!string.Equals(uri.Scheme, "file", StringComparison.OrdinalIgnoreCase))
                return true; // http/https/ftp/s3/... — remote
            // A file URI with a non-localhost host is a UNC network
            // location (file://server/share), not local storage (F6).
            if (!string.IsNullOrEmpty(uri.Host) &&
                !string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private readonly RosterService _roster;
    private readonly EnrollmentService _enrollments;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly Func<string, string, bool>? _featureRequired;
    private readonly Func<string, string, bool>? _aiSurfaceCapability;
    private readonly Dictionary<string, Session> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Participant>> _participants = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<SessionEvent>> _events = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<ChatMessage>> _chat = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FileJob> _fileJobs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SessionCall> _calls = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _surfaceSetters = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>W12 / DS-P5-F1: the endpoint-local accept capability.
    /// One instance per SessionService, handed ONLY to the host
    /// process's composition (the Core), which presents it on the
    /// laptop-UI accept path. A caller that merely knows the enum
    /// value cannot mint this object — reference equality is the
    /// proof of locality the enum alone could not carry.</summary>
    public sealed class EndpointLocalAcceptCapability { internal EndpointLocalAcceptCapability() { } }
    public EndpointLocalAcceptCapability LocalAcceptCapability { get; } = new();

    /// <summary>Record a gate refusal in the session's replay
    /// (W12 / DS-P5-F5): every guarded path that refuses records the
    /// action, the actor and the gate, so the audit shows the gate
    /// doing its job — a refusal is an event, not a silence. Caller
    /// holds the gate and the session exists.</summary>
    private void RecordRefusalLocked(Session session, string action, string? actorUserId, string gate)
    {
        RecordEventLocked(session, "refused", actorUserId, session.HostDeviceId,
            $"{action} refused by gate '{gate}'.");
        // W13 / DS-P5-F5 (closure): the refusal is a durable mutation
        // of the replay — raise Changed here so EVERY recording site
        // persists it, not only the sites that remembered to.
        Changed?.Invoke();
    }

    /// <summary>W13 / DS-P5-F5 (closure): record a refusal for a
    /// guard that fires BEFORE the session lock is taken (the
    /// capability check, the channel-origin check, the host-role
    /// check). No-ops when the session is unknown or already ended
    /// (an ended session's replay is closed). SCOPE of the F5 rule,
    /// stated once: a refusal is recorded on every GUARD decision —
    /// authority, consent, liveness, policy, grant, capability —
    /// on a live session. Pure state-machine mismatches (pausing a
    /// requested session), value refusals (backwards file progress),
    /// and refusals before a session exists (CreateSession) or for
    /// an unknown session record nothing: there is either no guard
    /// decision or no replay to attach it to, and the pinned
    /// "illegal transition changes nothing" contract governs those.</summary>
    private void RecordRefusalIfKnown(string? sessionId, string action, string? actorUserId, string gate)
    {
        lock (_gate)
        {
            if (sessionId is not null && _sessions.TryGetValue(sessionId, out var session) &&
                session.State != "ended")
                RecordRefusalLocked(session, action, actorUserId, gate);
        }
    }

    /// <param name="featureGate">TOTAL POLICY CONTROL gate for the
    /// Block G session surfaces (blank_screen / input_block /
    /// watermark / voice_video), consulted before a surface is
    /// ENABLED. The delegate is SCOPE-AWARE (scopeId, featureKey):
    /// a policy bundle governs only its own scope (D38 review
    /// F2). Null = no policy loaded (the owner's own device —
    /// the EnterpriseService.CheckFeature posture).</param>
    /// <param name="featureRequired">TOTAL POLICY CONTROL
    /// required-posture lookup (scopeId, featureKey): a required
    /// watermark may not be cleared and a session may not start
    /// unwatermarked. Null = nothing required.</param>
    /// <param name="aiSurfaceCapability">BD-SHARED-SESSION F5:
    /// (scopeId, aiUserId) → the pairing scope names the capability
    /// that lets an AI ENABLE the lockout surfaces (blank/input
    /// block). Null (default) = no AI may ever enable them.</param>
    public SessionService(RosterService roster, EnrollmentService enrollments,
        Func<string, string, PolicyVerdict>? featureGate = null,
        Func<string, string, bool>? featureRequired = null,
        Func<string, string, bool>? aiSurfaceCapability = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _featureGate = featureGate;
        _featureRequired = featureRequired;
        _aiSurfaceCapability = aiSurfaceCapability;
    }

    private bool FeatureAllowed(Session session, string featureKey) =>
        _featureGate?.Invoke(session.ScopeId, featureKey).Allowed ?? true;

    private bool FeatureIsRequired(Session session, string featureKey) =>
        _featureRequired?.Invoke(session.ScopeId, featureKey) ?? false;

    /// <summary>Raised after any durable mutation so the host can
    /// persist the store (PairingService pattern).</summary>
    public event Action? Changed;

    // ---- creation -----------------------------------------------------------

    /// <summary>Create a session in "requested". Null on refusal:
    /// unknown scope, unknown/revoked host device, a host device
    /// whose enrollment group is not a device group of THIS scope
    /// (D8 wall), an initiator who is not a live user of the scope
    /// (a removed user can NEVER initiate; a suspended user — human
    /// or AI — cannot initiate either, D14/D9), an unknown kind or
    /// recording mode, a transport rung outside the six (D32), or a
    /// remote-looking RecordingRef (D36). The initiator joins as a
    /// "controller" participant, watching. Transport-rung membership
    /// in the host's EffectiveTransports is checked at START (the
    /// spec's wording), not here — the resolved set can change
    /// between request and start.</summary>
    public Session? CreateSession(string scopeId, string hostDeviceId, string initiatorUserId,
        string kind, string transportRung, string recording = "none", string? recordingRef = null,
        string? mouseTakeoverMode = null, string? keyboardTakeoverMode = null)
    {
        var normalizedKind = Normalize(kind, ValidKinds);
        var normalizedRecording = Normalize(recording, ValidRecordings);
        if (normalizedKind is null || normalizedRecording is null) return null;
        if (normalizedKind == "camera_share") return null; // RMM-22: camera shares are minted ONLY by CameraShareService, on the phone owner's initiation — never through the generic session path
        if (!RosterService.IsValidRung(transportRung)) return null;
        if (IsRemoteRecordingRef(recordingRef)) return null; // D36: local storage only
        lock (_gate)
        {
            if (_roster.GetScope(scopeId) is not { } scope) return null;
            var device = _enrollments.List().FirstOrDefault(
                d => string.Equals(d.DeviceId, hostDeviceId ?? "", StringComparison.OrdinalIgnoreCase));
            if (device is null || device.Revoked) return null;
            var group = _roster.FindDeviceGroup(device.GroupId);
            if (group is null || !string.Equals(group.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase))
                return null; // host device is not filed in this scope (D8)
            var initiator = _roster.GetUser(scope.Id, initiatorUserId);
            if (initiator is null || initiator.Suspended) return null; // removed/suspended can never initiate (D14)
            var session = new Session(
                Id: Guid.NewGuid().ToString("N"),
                ScopeId: scope.Id,
                HostDeviceId: device.DeviceId,
                InitiatorUserId: initiator.Id,
                Kind: normalizedKind,
                State: "requested",
                StartedUtc: null,
                EndedUtc: null,
                TransportRung: transportRung.Trim().ToLowerInvariant(),
                Recording: normalizedRecording,
                RecordingRef: normalizedRecording == "none" ? null : recordingRef?.Trim(),
                MouseTakeoverMode: NormalizeTakeoverMode(mouseTakeoverMode),
                KeyboardTakeoverMode: NormalizeTakeoverMode(keyboardTakeoverMode));
            _sessions[session.Id] = session;
            _participants[session.Id] = new List<Participant>
            {
                new(session.Id, initiator.Id, "controller", "watching"),
            };
            _events[session.Id] = new List<SessionEvent>();
            _chat[session.Id] = new List<ChatMessage>();
            RecordEventLocked(session, "created", initiator.Id, device.DeviceId,
                $"{normalizedKind} session requested on rung '{session.TransportRung}'.");
            // FR-120: the active modes are part of the record from
            // the start — recorded as an event beside "created"
            // whenever the caller carried them.
            if (session.MouseTakeoverMode is not null || session.KeyboardTakeoverMode is not null)
                RecordEventLocked(session, TakeoverRecordKinds.ModesAtStart, initiator.Id, device.DeviceId,
                    TakeoverRecordDetail.Modes(
                        Enum.Parse<TakeoverMode>(session.MouseTakeoverMode ?? nameof(TakeoverMode.TakeOver)),
                        Enum.Parse<TakeoverMode>(session.KeyboardTakeoverMode ?? nameof(TakeoverMode.TakeOver))));
            RecordEventLocked(session, "participant_added", initiator.Id, initiator.Id,
                "Initiator joined as controller.");
            Changed?.Invoke();
            return session;
        }
    }

    public Session? GetSession(string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return null;
        lock (_gate) return _sessions.TryGetValue(sessionId, out var s) ? s : null;
    }

    /// <summary>FR-120 mode-name normalization for the record:
    /// an exact mode name (any case) is kept canonical; anything
    /// else is dropped to null (the record never carries a mode
    /// name the vocabulary does not define).</summary>
    private static string? NormalizeTakeoverMode(string? value) =>
        value is not null && Enum.TryParse<TakeoverMode>(value.Trim(), ignoreCase: true, out var m)
            ? m.ToString() : null;

    /// <summary>FR-120: record a mode change ON a live session —
    /// the change, and HOW it arrived (TakeoverActors: owner-local
    /// vs in-session), are session-record facts. The record also
    /// updates the session's active-mode fields so the record's
    /// current state and its event history agree. False for an
    /// unknown or ended session: a change with no live session is
    /// a device-settings fact, not a session-record entry.</summary>
    public bool RecordTakeoverModeChange(string sessionId, string actor,
        TakeoverInputClass inputClass, TakeoverMode from, TakeoverMode to)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            var updated = inputClass == TakeoverInputClass.Mouse
                ? session with { MouseTakeoverMode = to.ToString() }
                : session with { KeyboardTakeoverMode = to.ToString() };
            _sessions[session.Id] = updated;
            RecordEventLocked(updated, TakeoverRecordKinds.ModeChanged, actor, session.HostDeviceId,
                TakeoverRecordDetail.ModeChange(inputClass, from, to));
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>FR-120: record a takeover event (yield / hand-back
    /// / hotkey) on a session. Kind is restricted to the takeover
    /// vocabulary — this door writes no other event kind. False
    /// for an unknown/ended session or a foreign kind.</summary>
    public bool RecordTakeoverEvent(string sessionId, string kind, string actor, string detail)
    {
        if (kind is not TakeoverRecordKinds.Yield and not TakeoverRecordKinds.HandBack and not TakeoverRecordKinds.Hotkey)
            return false;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            RecordEventLocked(session, kind, actor, session.HostDeviceId, detail ?? "");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Sessions of ONE scope only (D8 scope isolation);
    /// null scope lists all (operator-side store read).</summary>
    public IReadOnlyList<Session> ListSessions(string? scopeId = null)
    {
        lock (_gate)
            return _sessions.Values
                .Where(s => scopeId is null || string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    public IReadOnlyList<Participant> ListParticipants(string sessionId)
    {
        lock (_gate)
            return _participants.TryGetValue(sessionId ?? "", out var list)
                ? list.ToList()
                : new List<Participant>();
    }

    /// <summary>The session's append-only event list — the replay
    /// data source (D36 form 2). Callers receive a copy; the store's
    /// list is only ever appended to, by the store.</summary>
    public IReadOnlyList<SessionEvent> ListEvents(string sessionId)
    {
        lock (_gate)
            return _events.TryGetValue(sessionId ?? "", out var list)
                ? list.ToList()
                : new List<SessionEvent>();
    }

    // ---- consent: host-side accept -------------------------------------------

    /// <summary>Record the accept of an attended session (Slice 3
    /// consent gate, as REDEFINED by the 2026-11-19 endpoint-local
    /// ruling, resolving DG-FIND-05). Acceptance is an endpoint-local
    /// act: ONLY an accept event originating from the endpoint host's
    /// local UI is honored — <paramref name="origin"/> must be
    /// <see cref="SessionAcceptOrigin.EndpointLocal"/>. An accept
    /// arriving over the initiating channel refuses ALWAYS, in every
    /// scope, whoever sends it (the requester, a host user, an admin):
    /// a channel accept is the request approving itself, which is
    /// what D38 F1 proved broken. Locality, not identity, is the
    /// consent signal, so an endpoint-local accept is valid even when
    /// the acceptor IS the initiator — the one-user personal scope,
    /// where the owner initiates from one device and accepts at the
    /// controlled machine, works under exactly the same rule as a
    /// company scope (no self-accept exception is carved; the local
    /// origin IS the rule). The acceptor must still be a live HUMAN
    /// user of the session's scope: an AI has no presence at the
    /// local UI, and a removed/suspended user consents to nothing.
    /// The acceptor joins as the "host" participant (or is promoted
    /// to it). The accept is recorded ON the session (AcceptedByUserId
    /// + AcceptOrigin) and as an "accepted" event whose detail states
    /// the locality honestly — "Accepted at &lt;device&gt;, locally" —
    /// as distinct from the pre-ruling "accepted by &lt;user&gt;" form
    /// that only legacy/imported records can still carry. False for
    /// unknown/ended sessions, an unattended session (no accept gate
    /// exists there — the grant is its consent, checked at start), a
    /// channel origin, an unknown/suspended/AI acceptor, or a second
    /// accept.</summary>
    /// <summary>W12 / DS-P5-F1: the capability-carrying accept — the
    /// production path. The caller must present THIS service's
    /// <see cref="LocalAcceptCapability"/> instance (reference
    /// equality); the enum-only overload below remains the model's
    /// documented seam for tests and embedders that compose their
    /// own locality proof, and the Core's laptop channel uses this
    /// overload.</summary>
    public bool AcceptSessionLocal(string sessionId, string acceptByUserId, EndpointLocalAcceptCapability capability)
    {
        if (!ReferenceEquals(capability, LocalAcceptCapability))
        {
            RecordRefusalIfKnown(sessionId, "accept", acceptByUserId, "capability_mismatch"); // W13 DS-P5-F5
            return false;
        }
        return AcceptSession(sessionId, acceptByUserId, SessionAcceptOrigin.EndpointLocal);
    }

    public bool AcceptSession(string sessionId, string acceptByUserId, SessionAcceptOrigin origin)
    {
        if (origin != SessionAcceptOrigin.EndpointLocal)
        {
            RecordRefusalIfKnown(sessionId, "accept", acceptByUserId, "channel_origin_never_counts"); // W13 DS-P5-F5
            return false; // channel accepts never count (ruling)
        }
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.Kind != "attended" || session.State == "ended") return false;
            if (session.AcceptedByUserId is not null)
            {
                RecordRefusalLocked(session, "accept", acceptByUserId, "already_accepted"); // W13 DS-P5-F5
                return false;
            }
            if (EnforceOffboardingLocked(session)) return false; // a dead participant set accepts nothing
            session = _sessions[session.Id];
            var acceptor = _roster.GetUser(session.ScopeId, acceptByUserId);
            if (acceptor is null || acceptor.Suspended || acceptor.Kind != "human")
            {
                // W12 / DS-P5-F5: refusals are audited too.
                RecordRefusalLocked(session, "accept", acceptByUserId, "acceptor_not_live_human");
                return false;
            }
            var participants = _participants[session.Id];
            var existing = participants.FindIndex(p => string.Equals(p.UserId, acceptor.Id, StringComparison.OrdinalIgnoreCase));
            if (existing >= 0)
                participants[existing] = participants[existing] with { Role = "host" };
            else
            {
                participants.Add(new Participant(session.Id, acceptor.Id, "host", "watching"));
                RecordEventLocked(session, "participant_added", acceptor.Id, acceptor.Id, "Host joined on accept.");
            }
            _sessions[session.Id] = session with
            {
                AcceptedByUserId = acceptor.Id,
                AcceptOrigin = AcceptOriginEndpointLocal,
            };
            RecordEventLocked(session, "accepted", acceptor.Id, session.HostDeviceId,
                $"Accepted at {session.HostDeviceId}, locally.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>W12 / DS-P5-F2: revocation ends sessions. Ends every
    /// non-ended session hosted on <paramref name="deviceId"/> with
    /// reason device_revoked (full EndLocked cascade: calls die, file
    /// jobs cancel, surface flags clear). Returns the number ended.
    /// The revocation path (enrollment revoke / offboarding) calls
    /// this so a pairing revoked mid-session does not leave a live
    /// session behind it.</summary>
    public int EndSessionsForDevice(string deviceId, string reason = "device_revoked")
    {
        lock (_gate)
        {
            var victims = _sessions.Values.Where(s =>
                s.State != "ended" &&
                string.Equals(s.HostDeviceId, deviceId ?? "", StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (var victim in victims)
            {
                RecordEventLocked(victim, "device_revoked", "revocation", victim.HostDeviceId,
                    $"Host device revoked ({reason}); session ended by the revocation sweep (DS-P5-F2).");
                EndLocked(_sessions[victim.Id], "revocation", EndReasonDeviceRevoked);
            }
            if (victims.Count > 0) Changed?.Invoke();
            return victims.Count;
        }
    }

    // ---- lifecycle transitions --------------------------------------------------

    /// <summary>Start a session: requested → active, through EVERY
    /// start gate, in order — (1) the offboarding re-read: if the
    /// initiator or any participant has been removed/suspended since
    /// creation, the session is ENDED with reason
    /// participant_removed and the start refuses; (2) consent: an
    /// attended session needs a recorded host accept, an unattended
    /// session needs the initiator to hold the Slice 2 "use" right
    /// on the host's device group; (3) the transport rung must be in
    /// the host device's EffectiveTransports NOW (Slice 2
    /// resolution). A gate refusal (2)/(3) changes nothing — the
    /// session stays "requested".</summary>
    public bool StartSession(string sessionId, string? actorUserId = null)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State != "requested") return false;
            if (session.Kind == "camera_share") return false; // RMM-22: a camera share's lifecycle is CameraShareService's alone — even an imported record can never be started through the generic path
            if (EnforceOffboardingLocked(session)) return false; // ended by the hook
            session = _sessions[session.Id];
            if (!DeviceStillHostableLocked(session)) { RecordRefusalLocked(session, "start", actorUserId, "host_device_not_hostable"); return false; } // F10 + refusal record
            // W12 / DS-P5-F10: Start validates its actor like every
            // other transition — a forged actor string is never
            // recorded as the starter.
            if (!IsTransitionActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "start", actorUserId, "actor_not_authorized"); return false; }
            if (session.Kind == "attended")
            {
                if (session.AcceptedByUserId is null)
                {
                    RecordRefusalLocked(session, "start", actorUserId, "no_accept_recorded"); // DS-P5-F5
                    return false; // no accept, no start (consent floor)
                }
                // W12 / DS-P5-F16: the acceptor must STILL be a live
                // human of the scope — a removed/suspended acceptor's
                // stored string is not consent any more.
                if (!IsLiveHumanLocked(session, session.AcceptedByUserId)) { RecordRefusalLocked(session, "start", actorUserId, "acceptor_not_live_human"); return false; }
            }
            else
            {
                var device = _enrollments.List().FirstOrDefault(
                    d => string.Equals(d.DeviceId, session.HostDeviceId, StringComparison.OrdinalIgnoreCase));
                if (device is null ||
                    !_roster.UserHasRight(session.ScopeId, session.InitiatorUserId, device.GroupId, "use"))
                { RecordRefusalLocked(session, "start", actorUserId, "no_use_grant"); return false; } // unattended without the use grant: refused (Slice 2 grants)
            }
            var effective = _roster.EffectiveTransportsForDevice(session.HostDeviceId);
            if (effective is null ||
                !effective.Contains(session.TransportRung, StringComparer.OrdinalIgnoreCase))
            { RecordRefusalLocked(session, "start", actorUserId, "transport_rung_unavailable"); return false; } // rung not in the host's resolved set at start (D31/D32)
            // TOTAL POLICY CONTROL, required half (G-07): when
            // policy requires the watermark, an unwatermarked
            // stream may not start. The flag is settable from
            // "requested" precisely so this gate can be satisfied.
            if (FeatureIsRequired(session, PolicyFeatures.Watermark) && !session.Watermarked)
            { RecordRefusalLocked(session, "start", actorUserId, "watermark_required"); return false; }
            return TransitionLocked(session, "active", actorUserId ?? session.InitiatorUserId, "started",
                s => s with { StartedUtc = DateTimeOffset.UtcNow });
        }
    }

    /// <summary>Pause: active → paused. Re-reads offboarding first
    /// (every transition does): a session with a removed/suspended
    /// participant ends with participant_removed instead.</summary>
    public bool PauseSession(string sessionId, string? actorUserId = null)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State != "active") return false;
            if (EnforceOffboardingLocked(session)) return false;
            if (!IsTransitionActorLocked(_sessions[session.Id], actorUserId)) { RecordRefusalLocked(_sessions[session.Id], "pause", actorUserId, "actor_not_authorized"); return false; } // F9 + W13 refusal record
            var actor = actorUserId ?? session.InitiatorUserId;
            if (!TransitionLocked(_sessions[session.Id], "paused", actor, "paused", null))
                return false;
            // G-03: the input block exists only while input flows
            // (active). Pausing releases it — the record never
            // claims a block over a frozen session.
            var paused = _sessions[session.Id];
            if (paused.InputBlocked)
            {
                _sessions[session.Id] = paused with { InputBlocked = false };
                RecordEventLocked(paused, "input_block_cleared", actor, paused.HostDeviceId,
                    "Input block released by pause.");
                Changed?.Invoke();
            }
            return true;
        }
    }

    /// <summary>Resume: paused → active. Same offboarding re-read
    /// as every transition. Consent and transport were settled at
    /// start and are not re-litigated here — but a policy
    /// requirement that arrived while paused IS applied (D38
    /// review F8): a required watermark traps resume exactly as
    /// it traps start.</summary>
    public bool ResumeSession(string sessionId, string? actorUserId = null)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State != "paused") return false;
            if (EnforceOffboardingLocked(session)) return false;
            if (!IsTransitionActorLocked(_sessions[session.Id], actorUserId)) { RecordRefusalLocked(_sessions[session.Id], "resume", actorUserId, "actor_not_authorized"); return false; } // F9 + W13 refusal record
            if (!DeviceStillHostableLocked(_sessions[session.Id])) { RecordRefusalLocked(_sessions[session.Id], "resume", actorUserId, "host_device_not_hostable"); return false; } // F10, on resume too
            if (FeatureIsRequired(_sessions[session.Id], PolicyFeatures.Watermark) &&
                !_sessions[session.Id].Watermarked)
            { RecordRefusalLocked(_sessions[session.Id], "resume", actorUserId, "watermark_required"); return false; } // F8 (D38-G): required watermark traps resume too
            // W12 / DS-P5-F3: resume re-reads the consent it reactivates —
            // an unattended session whose "use" grant was revoked while
            // paused does not come back, and an attended session whose
            // acceptor is no longer a live human does not either.
            var live = _sessions[session.Id];
            if (live.Kind == "attended")
            {
                if (live.AcceptedByUserId is null || !IsLiveHumanLocked(live, live.AcceptedByUserId)) { RecordRefusalLocked(live, "resume", actorUserId, "acceptor_not_live_human"); return false; }
            }
            else if (!HoldsUseGrantLocked(live, live.InitiatorUserId)) { RecordRefusalLocked(live, "resume", actorUserId, "no_use_grant"); return false; }
            // W12 / DS-P5-F19: a resume is recorded as "resumed", not
            // as a second "started".
            return TransitionLocked(_sessions[session.Id], "active",
                actorUserId ?? session.InitiatorUserId, "resumed", null);
        }
    }

    /// <summary>Block: active|paused → blocked. From blocked the
    /// ONLY outgoing edge is ended (the closed set), so a blocked
    /// session can never be resumed, re-paused, or re-blocked into
    /// a stuck state — the host's clear path is ending it.</summary>
    public bool BlockSession(string sessionId, string? actorUserId = null)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State is not ("active" or "paused")) return false;
            if (EnforceOffboardingLocked(session)) return false;
            if (!IsTransitionActorLocked(_sessions[session.Id], actorUserId)) { RecordRefusalLocked(_sessions[session.Id], "block", actorUserId, "actor_not_authorized"); return false; } // F9 + W13 refusal record
            var actor = actorUserId ?? session.InitiatorUserId;
            if (!TransitionLocked(_sessions[session.Id], "blocked", actor, "blocked", null))
                return false;
            // W12 / DS-P5-F8: blocking releases the input block, like
            // pause does — the model asserts InputBlocked is active-only,
            // and a blocked record must not claim an enforced hook.
            var blockedNow = _sessions[session.Id];
            if (blockedNow.InputBlocked)
            {
                _sessions[session.Id] = blockedNow with { InputBlocked = false };
                RecordEventLocked(blockedNow, "input_block_cleared", actor, blockedNow.HostDeviceId,
                    "Input block released by session block.");
            }
            // G-05: blocked is stopped-pending-end and no content
            // flows through it (chat already refuses) — a live call
            // ends with the block, on the record.
            EndLiveCallsLocked(_sessions[session.Id], actor, "Call ended by session block.");
            return true;
        }
    }

    /// <summary>End a session from any non-ended state (the one
    /// edge out of "blocked", and a legal edge out of every other
    /// live state). Ending cascades: every non-terminal file job is
    /// forced "cancelled". False only for unknown/already-ended.</summary>
    public bool EndSession(string sessionId, string? actorUserId = null) =>
        EndSessionInternal(sessionId, actorUserId, EndReasonEnded);

    /// <summary>End a live session because its transport rung died
    /// (transport failover engine, D29/D32). Same terminal cascade
    /// as EndSession; the reason records the truth.</summary>
    public bool EndSessionForFailover(string sessionId, string? actorUserId = null) =>
        EndSessionInternal(sessionId, actorUserId, EndReasonTransportFailover);

    /// <summary>Public form of the host-side actor rule (the
    /// session's recorded acceptor, its host participant, or a
    /// company admin — always a live human), for sibling services
    /// (G-08 session tunnels) that must apply the SAME rule rather
    /// than a copy of it.</summary>
    public bool IsHostSideActor(string sessionId, string? actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            return IsHostSideActorLocked(session, actorUserId);
        }
    }

    /// <summary>Append an event to a session's replay list (the
    /// transport layer's linkage record: failover end+new-start are
    /// linked by events naming both session ids). False for an
    /// unknown session; the list stays append-only.</summary>
    /// <summary>Event kinds an EXTERNAL caller may append (W12 /
    /// DS-P5-F12): linkage annotations only. Lifecycle/consent kinds
    /// ("accepted", "ended", "started", "participant_removed", …) are
    /// written only by the service's own transitions — an in-process
    /// caller can no longer forge them into the replay.</summary>
    private static readonly IReadOnlySet<string> AppendableEventKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "tunnel_opened", "tunnel_closed", "terminal_opened", "terminal_input", "terminal_closed",
        "transport_failover", "wake_sent",
    };

    public bool AppendEvent(string sessionId, string kind, string? actorUserId, string? subjectId, string detail)
    {
        var normalized = (kind ?? "").Trim().ToLowerInvariant();
        if (!AppendableEventKinds.Contains(normalized))
        {
            RecordRefusalIfKnown(sessionId, "append_event", actorUserId, "event_kind_not_appendable"); // W13 DS-P5-F5
            return false;
        }
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            // The actor must be a participant, a host-side actor, or a
            // reserved system actor (null = the trusted in-process
            // composition, "policy", the device console).
            if (actorUserId is not null &&
                actorUserId != "policy" &&
                actorUserId != StandaloneTransferService.DeviceConsoleActor &&
                !_participants[session.Id].Any(p => string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase)) &&
                !IsHostSideActorLocked(session, actorUserId))
            { RecordRefusalLocked(session, "append_event", actorUserId, "actor_not_authorized"); return false; }
            RecordEventLocked(session, normalized, actorUserId, subjectId, detail ?? "");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>STOP (host-side): from ANY state except "ended",
    /// the session passes through "blocked" and immediately ends
    /// with reason host_stop — STOP always works and always
    /// terminates; there is no state in which a session is alive
    /// but unstoppable. The actor must be host-side: the session's
    /// host participant, its recorded acceptor, or a company admin
    /// of the scope. Both the blocked pass-through and the stop are
    /// events, so the replay shows exactly what happened.</summary>
    public bool StopSession(string sessionId, string? actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            // W12 / DS-P5-F4 (reconciled with the D38 contract): STOP
            // does NOT pre-run the offboarding hook — a removed
            // acceptor's STOP refuses and changes nothing (the live
            // authority re-read in CanStopOrphanedSessionLocked is
            // the F4 fix); the teardown fires on the next host act,
            // exactly as DestructionSessionTests D38_F4 pins.
            // A null actor is the trusted in-process caller path (the
            // same convention as every other transition, DS-P5-F4).
            if (actorUserId is not null &&
                !IsHostSideActorLocked(session, actorUserId) &&
                !CanStopOrphanedSessionLocked(session, actorUserId))
            {
                RecordRefusalLocked(session, "stop", actorUserId, "not_host_side"); // DS-P5-F5
                return false;
            }
            var actor = actorUserId ?? session.InitiatorUserId;
            // W12 / DS-P5-F20: the blocked pass-through uses only legal
            // edges (active/paused → blocked). From "requested" there is
            // no such edge in the closed set, so STOP ends directly.
            if (session.State is "active" or "paused")
            {
                _sessions[session.Id] = session with { State = "blocked" };
                RecordEventLocked(session, "blocked", actor, session.HostDeviceId,
                    "Session blocked by host STOP.");
                session = _sessions[session.Id];
            }
            RecordEventLocked(session, "stopped", actor, session.HostDeviceId, "Host STOP.");
            EndLocked(session, actor, EndReasonHostStop);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>BD-SHARED-SESSION F4 — the device-console STOP: the
    /// person physically at this machine can end ANY non-ended
    /// session, with no roster user id at all. A quick-assist helpee
    /// or an unattended endpoint's local user may not be in the
    /// roster; before this, StopSession needed a host-side roster
    /// actor, so such a person could not end the session — despite
    /// SetBlanked's doc promising the person at the machine can
    /// always clear it. Recorded under the reserved
    /// StandaloneTransferService.DeviceConsoleActor, exactly like
    /// the tunnel/transfer device stops. Reachable ONLY from inside
    /// the host process (the Core's laptop-UI IPC channel); there is
    /// deliberately no MCP/mesh/HTTP path into it. STOP-only: it
    /// grants no other act (§7.10 fail-safe direction).</summary>
    public bool StopSessionFromDevice(string sessionId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            var actor = StandaloneTransferService.DeviceConsoleActor;
            // W12 / DS-P5-F20: legal edges only — from "requested" the
            // STOP ends directly (requested → blocked is not in the set).
            if (session.State is "active" or "paused")
            {
                _sessions[session.Id] = session with { State = "blocked" };
                RecordEventLocked(session, "blocked", actor, session.HostDeviceId,
                    "Session blocked by device-console STOP (the person at this machine).");
                session = _sessions[session.Id];
            }
            RecordEventLocked(session, "stopped", actor, session.HostDeviceId,
                "Device-console STOP by the person at this machine (no roster identity required).");
            EndLocked(session, actor, EndReasonHostStop);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>BD-SHARED-SESSION F4 — the device-console surface
    /// clear: the person at this machine can always release a
    /// privacy blank or an input block on a live session, roster
    /// membership or not. Clearing only — this path can never SET a
    /// flag. Recorded under the device-console actor.</summary>
    public bool ClearSurfacesFromDevice(string sessionId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (!session.Blanked && !session.InputBlocked) return true; // nothing to clear: the clear itself holds
            var actor = StandaloneTransferService.DeviceConsoleActor;
            if (session.Blanked)
                RecordEventLocked(session, "blank_cleared", actor, session.HostDeviceId,
                    "Privacy blank cleared from the device console by the person at this machine.");
            if (session.InputBlocked)
                RecordEventLocked(session, "input_block_cleared", actor, session.HostDeviceId,
                    "Input block released from the device console by the person at this machine.");
            _sessions[session.Id] = session with { Blanked = false, InputBlocked = false };
            Changed?.Invoke();
            return true;
        }
    }

    private bool EndSessionInternal(string sessionId, string? actorUserId, string reason)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (!IsTransitionActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "end", actorUserId, "actor_not_authorized"); return false; } // F9: no forged-actor endings + W13 refusal record
            EndLocked(session, actorUserId ?? session.InitiatorUserId, reason);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Transition authorization (D38 F9): an explicitly
    /// named actor must be a participant of the session, a host-side
    /// actor, or a company admin — a stranger's string (or a ghost's)
    /// drives nothing, so the replay never attributes an act to
    /// someone who could not have performed it. A null actor is the
    /// trusted in-process caller path (the store's own composition
    /// root) and keeps the initiator attribution.</summary>
    private bool IsTransitionActorLocked(Session session, string? actorUserId)
    {
        if (actorUserId is null) return true;
        // W12 / DS-P5-F3: a mere watcher participant drives no
        // lifecycle transition — participant rows qualify only in a
        // working role (controller/host) or while holding the floor.
        if (_participants[session.Id].Any(p =>
                string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase) &&
                (p.Role != "watcher" || p.Floor == "holds")))
            return true;
        return IsHostSideActorLocked(session, actorUserId);
    }

    /// <summary>Start/resume device re-validation (D38 F10): repeat
    /// CreateSession's device checks — the host device must still be
    /// enrolled, unrevoked, and filed in a device group of THIS
    /// scope. A device revoked between create and start can never
    /// go active.</summary>
    private bool DeviceStillHostableLocked(Session session)
    {
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, session.HostDeviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null || device.Revoked) return false;
        var group = _roster.FindDeviceGroup(device.GroupId);
        return group is not null &&
               string.Equals(group.ScopeId, session.ScopeId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Terminal transition + file-job cascade. Caller holds
    /// the gate and has already established the session is live.</summary>
    private void EndLocked(Session session, string actorUserId, string reason)
    {
        // Block G flags die with the session, on the record, with
        // their own events: a blanked screen unblanks, blocked input
        // is released, and no ended session claims a watermark —
        // there is no end path (STOP, offboarding, failover,
        // restart) that leaves a surface flag standing.
        if (session.Blanked)
            RecordEventLocked(session, "blank_cleared", actorUserId, session.HostDeviceId,
                "Privacy blank cleared by session end.");
        if (session.InputBlocked)
            RecordEventLocked(session, "input_block_cleared", actorUserId, session.HostDeviceId,
                "Input block released by session end.");
        // W12 / DS-P5-F18: the watermark dies with its own event too —
        // the comment above promises all three flags their own events.
        if (session.Watermarked)
            RecordEventLocked(session, "watermark_cleared", actorUserId, session.HostDeviceId,
                "Watermark cleared by session end.");
        var ended = session with
        {
            State = "ended",
            EndedUtc = DateTimeOffset.UtcNow,
            EndReason = reason,
            Blanked = false,
            InputBlocked = false,
            Watermarked = false,
        };
        _sessions[session.Id] = ended;
        RecordEventLocked(ended, "ended", actorUserId, session.HostDeviceId, $"Session ended ({reason}).");
        // G-05: a live call dies with its session, on the record.
        EndLiveCallsLocked(ended, actorUserId, "Call ended by session end.");
        foreach (var job in _fileJobs.Values
                     .Where(j => string.Equals(j.SessionId, session.Id, StringComparison.OrdinalIgnoreCase) &&
                                 j.State is not ("done" or "failed" or "cancelled"))
                     .ToList())
        {
            _fileJobs[job.Id] = job with { State = "cancelled" };
            RecordEventLocked(ended, "file_job_cancelled", actorUserId, job.Id,
                $"File job '{job.Name}' cancelled by session end.");
        }
    }

    /// <summary>Apply a lifecycle transition already validated by
    /// the caller against the closed set; re-validates here so no
    /// code path can move a session along an illegal edge. An
    /// illegal attempt changes nothing.</summary>
    private bool TransitionLocked(Session session, string to, string actorUserId, string eventKind,
        Func<Session, Session>? adjust)
    {
        if (!IsLegalTransition(session.State, to)) return false;
        var next = (adjust?.Invoke(session) ?? session) with { State = to };
        _sessions[session.Id] = next;
        RecordEventLocked(next, eventKind, actorUserId, session.HostDeviceId, $"Session {eventKind}.");
        Changed?.Invoke();
        return true;
    }

    // ---- offboarding hook (D14, discharged here) --------------------------------

    /// <summary>The offboarding hook, callable on demand and run
    /// internally before start and every state transition: if the
    /// initiator or ANY participant has been removed or suspended in
    /// the Slice 2 roster since the session was created, the
    /// session is ended with reason participant_removed (file jobs
    /// cascade-cancelled) and true is returned. A live session with
    /// all participants intact returns false and changes nothing;
    /// an already-ended session returns false.</summary>
    public bool EnforceOffboarding(string sessionId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (!EnforceOffboardingLocked(session)) return false;
            return true; // Changed raised inside EnforceOffboardingLocked (W12 DS-P5-F9)
        }
    }

    /// <summary>True (and session ended) when any participant —
    /// initiator included — is gone from the roster or suspended.
    /// "Gone" is read three ways, belt and braces: the user record
    /// is absent (removal deletes it), the record is suspended, or
    /// a Slice 2 "user_removed" offboarding event names them.</summary>
    private bool EnforceOffboardingLocked(Session session)
    {
        var offender = FindOffboardedParticipantLocked(session);
        if (offender is null) return false;
        // W12 / DS-P5-F9: the end is attributed to the offboarding
        // system actor, never to the initiator (who may BE the removed
        // user), and Changed is raised HERE — callers that invoke this
        // as a side effect and then return false previously never
        // raised it, so the persistence layer never saw the auto-end.
        RecordEventLocked(session, "participant_removed", "offboarding", offender,
            "Participant removed or suspended in the roster; session ended (D14).");
        EndLocked(_sessions[session.Id], "offboarding", EndReasonParticipantRemoved);
        Changed?.Invoke();
        return true;
    }

    private string? FindOffboardedParticipantLocked(Session session)
    {
        var userIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { session.InitiatorUserId };
        foreach (var p in _participants[session.Id]) userIds.Add(p.UserId);
        var removedEvents = _roster.ListEvents(session.ScopeId)
            .Where(e => e.Kind == "user_removed" && e.SubjectId is not null)
            .Select(e => e.SubjectId!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var userId in userIds)
        {
            var user = _roster.GetUser(session.ScopeId, userId);
            if (user is null || user.Suspended || removedEvents.Contains(userId))
                return userId;
        }
        return null;
    }

    // ---- participants & floor (D35, model half) -----------------------------------

    /// <summary>Add a participant. The actor must be the initiator,
    /// the session's host participant, or a company admin of the
    /// scope. The added user must be a live user of the scope (a
    /// removed user cannot be added; a suspended user cannot be
    /// added either). New participants join "watching" — the floor
    /// is only ever granted explicitly. False on an ended session.
    /// The "host" role is NOT assignable here (D38 F2): it is
    /// created only by AcceptSession, from the human at the host
    /// device — an initiator assigning "host" (to anyone, above all
    /// to an AI) would mint host authority out of nothing.</summary>
    public bool AddParticipant(string sessionId, string userId, string role, string actorUserId)
    {
        var normalizedRole = Normalize(role, ValidRoles);
        if (normalizedRole is null) return false;
        if (normalizedRole == "host") { RecordRefusalIfKnown(sessionId, "add_participant", actorUserId, "host_role_not_assignable"); return false; } // F2 + W13 refusal record
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4: re-read before acting
            var user = _roster.GetUser(session.ScopeId, userId);
            if (user is null || user.Suspended) { RecordRefusalLocked(session, "add_participant", actorUserId, "user_not_live"); return false; }
            var participants = _participants[session.Id];
            if (participants.Any(p => string.Equals(p.UserId, user.Id, StringComparison.OrdinalIgnoreCase)))
                return false; // already a participant (state, not a guard decision)
            if (!string.Equals(actorUserId, session.InitiatorUserId, StringComparison.OrdinalIgnoreCase) &&
                !IsHostSideActorLocked(session, actorUserId))
            { RecordRefusalLocked(session, "add_participant", actorUserId, "actor_not_authorized"); return false; }
            participants.Add(new Participant(session.Id, user.Id, normalizedRole, "watching"));
            RecordEventLocked(session, "participant_added", actorUserId, user.Id,
                $"Participant added as {normalizedRole}.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Remove a participant (host act: host participant or
    /// company admin only). If they held the floor, the floor is
    /// released — nobody holds it until it is granted again. The
    /// removal is a "participant_removed" event.</summary>
    public bool RemoveParticipant(string sessionId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "remove_participant", actorUserId, "not_host_side"); return false; }
            var participants = _participants[session.Id];
            var idx = participants.FindIndex(p => string.Equals(p.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            var removed = participants[idx];
            participants.RemoveAt(idx);
            RecordEventLocked(session, "participant_removed", actorUserId, removed.UserId,
                "Participant removed by a host-side actor.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Grant the floor (host act). ATOMIC one-holder rule:
    /// the previous holder is set "watching" in the same update that
    /// sets the target "holds" — no observable state ever has two
    /// holders or passes through two holders. The target must be a
    /// participant and a live, unsuspended roster user; an AI target
    /// must be one that could initiate (D9 scope: a paired,
    /// unsuspended AI of this scope) — a suspended AI can NEVER hold
    /// the floor. Holding the floor grants NO host acts.</summary>
    public bool GrantFloor(string sessionId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "grant_floor", actorUserId, "not_host_side"); return false; }
            var participants = _participants[session.Id];
            var idx = participants.FindIndex(p => string.Equals(p.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            var target = _roster.GetUser(session.ScopeId, participants[idx].UserId);
            if (target is null || target.Suspended) { RecordRefusalLocked(session, "grant_floor", actorUserId, "target_not_live"); return false; } // removed/suspended never hold the floor
            for (var i = 0; i < participants.Count; i++)
                participants[i] = participants[i] with
                {
                    Floor = i == idx ? "holds" : "watching",
                };
            RecordEventLocked(session, "floor_granted", actorUserId, target.Id,
                "Floor granted (previous holder released atomically).");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Take the floor back (host act): the floor goes to
    /// the session's host participant. When the actor IS the host
    /// participant they take it themselves; a company-admin actor
    /// returns it to the host participant. Refused when the session
    /// has no host participant to take it back to.</summary>
    public bool TakeFloorBack(string sessionId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "take_floor_back", actorUserId, "not_host_side"); return false; }
            var participants = _participants[session.Id];
            var hostIdx = participants.FindIndex(p => p.Role == "host");
            if (hostIdx < 0) return false;
            // F12: the floor's recipient gets GrantFloor's liveness
            // rule — a removed/suspended host participant can never
            // end up holding the floor.
            var hostUser = _roster.GetUser(session.ScopeId, participants[hostIdx].UserId);
            if (hostUser is null || hostUser.Suspended || hostUser.Kind != "human") { RecordRefusalLocked(session, "take_floor_back", actorUserId, "host_not_live"); return false; }
            for (var i = 0; i < participants.Count; i++)
                participants[i] = participants[i] with { Floor = i == hostIdx ? "holds" : "watching" };
            RecordEventLocked(session, "floor_taken", actorUserId, participants[hostIdx].UserId,
                "Floor taken back to the host participant.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Set a participant watch-only (host act): their
    /// floor becomes "watching". If they held the floor, nobody
    /// holds it afterwards until it is granted again.</summary>
    public bool SetWatchOnly(string sessionId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "set_watch_only", actorUserId, "not_host_side"); return false; }
            var participants = _participants[session.Id];
            var idx = participants.FindIndex(p => string.Equals(p.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            participants[idx] = participants[idx] with { Floor = "watching" };
            RecordEventLocked(session, "watch_only", actorUserId, participants[idx].UserId,
                "Participant set watch-only.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Host-side authorization for the D35 host acts and
    /// STOP: the actor is the session's host participant, its
    /// recorded acceptor, or a company admin of the scope. Holding
    /// the floor is NOT host authority — a floor-holding controller
    /// or AI fails this check. AI actors can never pass: they cannot
    /// be company admins (D9, enforced by the roster) and the host
    /// participant is the human who accepted at the host device.
    /// Liveness (D38 F4): every path re-reads the roster — a removed
    /// or suspended acceptor/admin keeps the STRING of their old
    /// authority but none of its power.
    /// The fallback is STOP-only (see CanStopOrphanedSessionLocked):
    /// host ACTS (floor, removal, watch-only) never fall back.</summary>
    private bool IsHostSideActorLocked(Session session, string? actorUserId)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (string.Equals(actorUserId, session.AcceptedByUserId, StringComparison.OrdinalIgnoreCase) &&
            IsLiveHumanLocked(session, actorUserId))
            return true;
        if (_participants[session.Id].Any(p =>
                p.Role == "host" && string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase)) &&
            IsLiveHumanLocked(session, actorUserId))
            return true;
        return _roster.IsCompanyAdmin(session.ScopeId, actorUserId) &&
               IsLiveHumanLocked(session, actorUserId);
    }

    /// <summary>STOP fallback (D38 F3): a session with NO host-side
    /// authority at all (unattended — no acceptor, no host
    /// participant) must still be stoppable by the person at the
    /// machine, so any live HUMAN user of the scope may stop it. A
    /// session that HAS a host side gets no fallback: only its host
    /// side (or an admin) can stop it. Without this, an unattended
    /// session on a scope without company admins is a live session
    /// nobody can clear — the exact STOP trap the closed transition
    /// set exists to kill. STOP only: stopping is the fail-safe
    /// direction; this grants no other act.</summary>
    private bool CanStopOrphanedSessionLocked(Session session, string? actorUserId)
    {
        // W12 / DS-P5-F4: the fallback tests LIVE host-side authority,
        // not string/row presence. An acceptor string whose user was
        // removed or suspended, or a host row whose user is no longer
        // a live human, is NOT a host side — the session is orphaned
        // and any live human of the scope may stop it.
        if (session.AcceptedByUserId is not null && IsLiveHumanLocked(session, session.AcceptedByUserId)) return false;
        if (_participants[session.Id].Any(p => p.Role == "host" && IsLiveHumanLocked(session, p.UserId))) return false;
        return IsLiveHumanLocked(session, actorUserId);
    }

    /// <summary>Roster liveness for authority: the user record must
    /// exist in the session's scope, be human, and be unsuspended.
    /// Authority strings (an acceptor id, an admin seat) are never
    /// trusted on their own (D38 F4).</summary>
    private bool IsLiveHumanLocked(Session session, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        var user = _roster.GetUser(session.ScopeId, userId);
        return user is not null && user.Kind == "human" && !user.Suspended;
    }

    // ---- recording (D36) ------------------------------------------------------------

    /// <summary>Set the recording mode + local storage reference.
    /// Refused on an ended session, for an unknown mode, and —
    /// always — for a RecordingRef that looks remote (D36: local
    /// storage only, never a cloud reference). Setting "none"
    /// clears the reference. Because the flag lives on the session
    /// record, IsRecording reflects the change immediately — there
    /// is no path that records without the record saying so.
    /// Authorization (D38 F5): turning recording ON is a host-side
    /// act — the host accepted THIS session's recording posture, and
    /// no controller, watcher, outsider, or anonymous caller may
    /// escalate it afterwards; turning it OFF is always allowed to
    /// a host-side actor or any participant (the safe direction).
    /// Turning on is also refused in "blocked" — a blocked session
    /// is stopped-pending-end and starts nothing new.</summary>
    public bool SetRecording(string sessionId, string recording, string? recordingRef, string? actorUserId = null)
    {
        var normalized = Normalize(recording, ValidRecordings);
        if (normalized is null) return false;
        if (IsRemoteRecordingRef(recordingRef)) return false;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            session = _sessions[session.Id];
            if (normalized == "none")
            {
                if (!IsHostSideActorLocked(session, actorUserId) &&
                    !_participants[session.Id].Any(p => string.Equals(p.UserId, actorUserId ?? "",
                        StringComparison.OrdinalIgnoreCase)))
                { RecordRefusalLocked(session, "set_recording", actorUserId, "actor_not_authorized"); return false; }
            }
            else
            {
                if (session.State == "blocked") return false;
                if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "set_recording", actorUserId, "not_host_side"); return false; } // F5 + W13 refusal record
            }
            _sessions[session.Id] = session with
            {
                Recording = normalized,
                RecordingRef = normalized == "none" ? null : recordingRef?.Trim(),
            };
            RecordEventLocked(session, "recording_changed", actorUserId, session.HostDeviceId,
                $"Recording set to {normalized}.");
            Changed?.Invoke();
            return true;
        }
    }

    // ---- session surfaces (Block G: G-02 blank, G-03 input block, G-07 watermark) -------

    /// <summary>Who may ACT on a session surface at all: the
    /// floor holder (the participant actually driving) or a
    /// host-side actor. A watcher, a non-holder controller, an AI
    /// without the floor, and every outsider fail — surfaces that
    /// affect the person at the machine are never touched by
    /// bystanders. This is the CLEARING shape: the actor who set
    /// a flag can always release it (see CanEnableSurfaceLocked
    /// for the enabling shape).</summary>
    private bool CanActOnSurfaceLocked(Session session, string? actorUserId)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (IsHostSideActorLocked(session, actorUserId)) return true;
        var holder = _participants[session.Id].FirstOrDefault(p =>
            p.Floor == "holds" && string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (holder is null) return false;
        // The floor holder drives — human or AI (D35 grants the
        // floor to either) — but a removed/suspended holder's stale
        // participant row confers nothing (the F4 liveness rule).
        var user = _roster.GetUser(session.ScopeId, actorUserId);
        return user is not null && !user.Suspended;
    }

    /// <summary>W12 / DS-P5-F6: who may CLEAR a surface flag — a
    /// host-side actor, or the actor who SET it (recorded at set
    /// time). The floor holder as such no longer suffices: the remote
    /// driver who is being constrained by the host's blank/input
    /// block cannot release it themselves. When no setter is recorded
    /// (an imported flag), host-side only.</summary>
    private bool CanClearSurfaceLocked(Session session, string flag, string? actorUserId)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (IsHostSideActorLocked(session, actorUserId)) return true;
        return _surfaceSetters.TryGetValue($"{session.Id}|{flag}", out var setter) &&
               string.Equals(setter, actorUserId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Who may ENABLE a session surface flag:
    /// CanActOnSurfaceLocked PLUS the per-act grant re-check
    /// (Block H — the D38 AF3 remainder): the floor was handed
    /// over when the session formed, but the Slice 2 "use" right
    /// underneath it is re-read NOW, on every enabling act. A
    /// grant revoked mid-session stops the surfaces being SET at
    /// the next act instead of lasting to the session's end.
    /// CLEARING deliberately does NOT re-read the grant: the
    /// escape direction can never depend on the very right whose
    /// loss is being escaped — a revoked driver must still be
    /// able to unblank the screen they blanked. (UserHasRight
    /// passes scope admins, so the personal-scope owner and
    /// company admins are unaffected; host-side actors returned
    /// inside CanAct.)</summary>
    private bool CanEnableSurfaceLocked(Session session, string? actorUserId)
    {
        if (!CanActOnSurfaceLocked(session, actorUserId)) return false;
        if (IsHostSideActorLocked(session, actorUserId)) return true;
        // BD-SHARED-SESSION F5: an AI floor holder may DRIVE, but
        // enabling a surface that locks the owner out of their own
        // screen/input is a different power — refused unless the
        // pairing scope grants the named capability (default OFF),
        // the same leash shape as Terminal's `terminal` capability
        // and the tunnel service's outright AI refusal.
        var actor = _roster.GetUser(session.ScopeId, actorUserId!);
        if (actor is not null && string.Equals(actor.Kind, "ai", StringComparison.OrdinalIgnoreCase) &&
            !(_aiSurfaceCapability?.Invoke(session.ScopeId, actorUserId!) ?? false))
            return false;
        return HoldsUseGrantLocked(session, actorUserId!);
    }

    /// <summary>Does this user CURRENTLY hold the Slice 2 "use"
    /// right on the session host's device group? Re-read from the
    /// live roster + enrollment stores on every call — nothing
    /// about the answer is cached from session creation.</summary>
    private bool HoldsUseGrantLocked(Session session, string userId)
    {
        var device = _enrollments.List().FirstOrDefault(d =>
            string.Equals(d.DeviceId, session.HostDeviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null) return false;
        // A REVOKED device confers no "use" right (Block H D38
        // fix F9): every other device check in this service
        // refuses revoked devices; the grant re-read silently
        // skipped it, so surfaces stayed enable-able on a device
        // the hub had revoked.
        if (device.Revoked) return false;
        return _roster.UserHasRight(session.ScopeId, userId, device.GroupId, "use");
    }

    /// <summary>Public per-act "use"-grant re-read for the
    /// session satellite services (Block H D38 fix F9 — the
    /// tunnel service above all): the same live re-read
    /// CanEnableSurfaceLocked performs for the session's own
    /// surfaces, exposed so a tunnel open / a tunnel's continued
    /// life is gated by the CURRENT grant on the session host's
    /// device group (revoked grant or revoked device = no grant),
    /// never by the state at session creation.</summary>
    public bool HoldsUseGrant(string sessionId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            return HoldsUseGrantLocked(session, userId);
        }
    }

    /// <summary>G-02 — privacy blank. Bounds from the register: the
    /// blank can never hide the presence composition or STOP (the
    /// agent renders the blank UNDER the presence windows and the
    /// flag is part of the presence payload), and the person at the
    /// machine can always clear it: clearing is a host-side act
    /// that no state in this model can refuse while the session
    /// lives, and session end clears it unconditionally. Setting
    /// requires a live session (active or paused — never requested:
    /// there is nothing on the host screen to protect before the
    /// session starts; never blocked: blocked starts nothing new).
    /// Policy (TOTAL POLICY CONTROL, key "blank_screen") gates
    /// ENABLING via the constructor's feature gate; clearing is
    /// never policy-gated — policy cannot trap the person at the
    /// machine behind a blank screen.</summary>
    public bool SetBlanked(string sessionId, bool blanked, string? actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false;
            session = _sessions[session.Id];
            if (blanked)
            {
                if (!FeatureAllowed(session, PolicyFeatures.BlankScreen)) { RecordRefusalLocked(session, "set_blanked", actorUserId, "policy_disabled:blank_screen"); return false; }
                if (session.State is not ("active" or "paused")) return false;
                if (!CanEnableSurfaceLocked(session, actorUserId)) { RecordRefusalLocked(session, "set_blanked", actorUserId, "actor_not_authorized"); return false; }
                if (session.Blanked) return true;
                _sessions[session.Id] = session with { Blanked = true };
                if (actorUserId is not null) _surfaceSetters[$"{session.Id}|blank"] = actorUserId;
                RecordEventLocked(session, "blank_set", actorUserId, session.HostDeviceId,
                    "Host screen blanked for privacy (presence and STOP remain visible).");
            }
            else
            {
                if (!CanClearSurfaceLocked(session, "blank", actorUserId)) { RecordRefusalLocked(session, "clear_blanked", actorUserId, "not_host_side_or_setter"); return false; } // DS-P5-F6 + W13 refusal record
                if (!session.Blanked) return true;
                _sessions[session.Id] = session with { Blanked = false };
                RecordEventLocked(session, "blank_cleared", actorUserId, session.HostDeviceId,
                    "Privacy blank cleared.");
            }
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>G-03 — local input block. Same authorization shape
    /// as the blank, with one harder bound: the block is an
    /// agent-side mechanism that can fail or be killed, so the
    /// MODEL never lets the record claim a block the session state
    /// contradicts — the flag is live-session-only (active; a
    /// paused session's block is released by PauseSession's own
    /// transition through here), and clearing is a host-side act
    /// that always works while the session lives. The agent-side
    /// escape (Ctrl+Alt+Del is never hookable; STOP ends the
    /// session, which clears the flag and the hooks together) is
    /// documented on the agent surface, not pretended here.</summary>
    public bool SetInputBlocked(string sessionId, bool blocked, string? actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State == "ended") return false;
            if (EnforceOffboardingLocked(session)) return false;
            session = _sessions[session.Id];
            if (blocked)
            {
                if (!FeatureAllowed(session, PolicyFeatures.InputBlock)) { RecordRefusalLocked(session, "set_input_blocked", actorUserId, "policy_disabled:input_block"); return false; }
                if (session.State != "active") return false; // input flows only in active; so does its block
                if (!CanEnableSurfaceLocked(session, actorUserId)) { RecordRefusalLocked(session, "set_input_blocked", actorUserId, "actor_not_authorized"); return false; }
                if (session.InputBlocked) return true;
                _sessions[session.Id] = session with { InputBlocked = true };
                if (actorUserId is not null) _surfaceSetters[$"{session.Id}|input"] = actorUserId;
                RecordEventLocked(session, "input_block_set", actorUserId, session.HostDeviceId,
                    "Host local input blocked (presence and STOP remain operable; Ctrl+Alt+Del always reaches the host).");
            }
            else
            {
                if (!CanClearSurfaceLocked(session, "input", actorUserId)) { RecordRefusalLocked(session, "clear_input_blocked", actorUserId, "not_host_side_or_setter"); return false; } // DS-P5-F6 + W13 refusal record
                if (!session.InputBlocked) return true;
                _sessions[session.Id] = session with { InputBlocked = false };
                RecordEventLocked(session, "input_block_cleared", actorUserId, session.HostDeviceId,
                    "Input block released.");
            }
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>G-07 — stream/recording watermark. The watermark
    /// TEXT is never caller-supplied: the stream layer derives it
    /// from this session's record + the roster (WatermarkSpec), so
    /// a caller cannot stamp someone else's name into a recording.
    /// This flag is the whole control: settable from "requested"
    /// (so a stream can start watermarked) through paused; refused
    /// in blocked/ended. Clearing is host-side only — the mark is
    /// an accountability surface, and the driving side cannot
    /// quietly remove it mid-session; policy may additionally
    /// REQUIRE it (enforced at session start, and a required
    /// watermark may not be cleared by anyone while the policy
    /// stands). Policy (TOTAL POLICY CONTROL, key "watermark")
    /// gates enabling via the constructor's feature gate.</summary>
    public bool SetWatermarked(string sessionId, bool watermarked, string? actorUserId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return false;
            if (session.State is "ended" or "blocked") return false;
            if (EnforceOffboardingLocked(session)) return false;
            session = _sessions[session.Id];
            if (watermarked)
            {
                if (!FeatureAllowed(session, PolicyFeatures.Watermark)) { RecordRefusalLocked(session, "set_watermarked", actorUserId, "policy_disabled:watermark"); return false; }
                if (!CanEnableSurfaceLocked(session, actorUserId) &&
                    !string.Equals(actorUserId, session.InitiatorUserId, StringComparison.OrdinalIgnoreCase))
                { RecordRefusalLocked(session, "set_watermarked", actorUserId, "actor_not_authorized"); return false; }
                if (session.Watermarked) return true;
                _sessions[session.Id] = session with { Watermarked = true };
                RecordEventLocked(session, "watermark_set", actorUserId, session.HostDeviceId,
                    "Stream/recording watermark enabled (text derived from the session record).");
            }
            else
            {
                // A policy-required watermark may not be cleared
                // while the policy stands — by anyone. (The stream
                // start gate is the other half, in StartSession.)
                if (FeatureIsRequired(session, PolicyFeatures.Watermark)) { RecordRefusalLocked(session, "clear_watermarked", actorUserId, "watermark_required"); return false; }
                if (!IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "clear_watermarked", actorUserId, "not_host_side"); return false; }
                if (!session.Watermarked) return true;
                _sessions[session.Id] = session with { Watermarked = false };
                RecordEventLocked(session, "watermark_cleared", actorUserId, session.HostDeviceId,
                    "Watermark cleared by a host-side actor.");
            }
            Changed?.Invoke();
            return true;
        }
    }

    // ---- in-session voice/video calls (Block G: G-05) ----------------------------

    /// <summary>End every live (ringing/active) call on a session,
    /// with an event per call. The cascade half of G-05: session
    /// end and session block both route through here, so no call
    /// can outlive the state that carries it. Caller holds the
    /// gate.</summary>
    private void EndLiveCallsLocked(Session session, string actorUserId, string detail)
    {
        foreach (var call in _calls.Values
                     .Where(c => string.Equals(c.SessionId, session.Id, StringComparison.OrdinalIgnoreCase) &&
                                 c.State is "ringing" or "active")
                     .ToList())
        {
            _calls[call.Id] = call with { State = "ended", EndedUtc = DateTimeOffset.UtcNow };
            RecordEventLocked(session, "call_ended", actorUserId, call.Id, detail);
        }
    }

    /// <summary>The session's live call, if any (at most one —
    /// enforced at start).</summary>
    public SessionCall? GetLiveCall(string sessionId)
    {
        lock (_gate)
            return _calls.Values.FirstOrDefault(c =>
                string.Equals(c.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase) &&
                c.State is "ringing" or "active");
    }

    public SessionCall? GetCall(string? callId)
    {
        if (string.IsNullOrWhiteSpace(callId)) return null;
        lock (_gate) return _calls.TryGetValue(callId, out var c) ? c : null;
    }

    public IReadOnlyList<SessionCall> ListCalls(string sessionId)
    {
        lock (_gate)
            return _calls.Values
                .Where(c => string.Equals(c.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    /// <summary>Start a voice/video call inside a live session.
    /// Null on refusal: policy-disabled (TOTAL POLICY CONTROL,
    /// key "voice_video"), unknown kind, a session that is not
    /// active/paused (no media before the session starts, none
    /// through a blocked one), a caller who is not a participant,
    /// or a session that already has a live call (one call per
    /// session — a second "call" is a second session's business).
    /// The offboarding re-read runs first, as on every act: a
    /// session with a removed participant ends instead. The call
    /// starts "ringing": media flows only after the other side
    /// answers (AnswerCall) — an unanswered call carries nothing.</summary>
    public SessionCall? StartCall(string sessionId, string initiatorUserId, string kind)
    {
        var normalized = (kind ?? "").Trim().ToLowerInvariant();
        if (!ValidCallKinds.Contains(normalized)) return null;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return null;
            if (EnforceOffboardingLocked(session)) return null;
            session = _sessions[session.Id];
            if (!FeatureAllowed(session, PolicyFeatures.VoiceVideo)) { RecordRefusalLocked(session, "start_call", initiatorUserId, "policy_disabled:voice_video"); return null; }
            if (session.State is not ("active" or "paused")) return null;
            var caller = _participants[session.Id].FirstOrDefault(p =>
                string.Equals(p.UserId, initiatorUserId ?? "", StringComparison.OrdinalIgnoreCase));
            if (caller is null) { RecordRefusalLocked(session, "start_call", initiatorUserId, "not_participant"); return null; } // participants only
            // Per-act grant re-check (Block H, AF3): a remote
            // participant's "use" right is re-read at call start,
            // exactly as on the floor surfaces.
            if (!IsHostSideActorLocked(session, caller.UserId) &&
                !HoldsUseGrantLocked(session, caller.UserId)) { RecordRefusalLocked(session, "start_call", initiatorUserId, "no_use_grant"); return null; }
            if (GetLiveCallLocked(session.Id) is not null) return null;
            var call = new SessionCall(Guid.NewGuid().ToString("N"), session.Id, normalized,
                "ringing", caller.UserId, DateTimeOffset.UtcNow, null, null);
            _calls[call.Id] = call;
            RecordEventLocked(session, "call_started", caller.UserId, call.Id,
                $"{normalized} call started (ringing).");
            Changed?.Invoke();
            return call;
        }
    }

    private SessionCall? GetLiveCallLocked(string sessionId) =>
        _calls.Values.FirstOrDefault(c =>
            string.Equals(c.SessionId, sessionId, StringComparison.OrdinalIgnoreCase) &&
            c.State is "ringing" or "active");

    /// <summary>Answer a ringing call: media may start. The
    /// answerer must be a participant OTHER than the caller —
    /// the host participant picking up at the machine is one.
    /// The caller answering their own call is refused on EVERY
    /// path (D38 review F11: the host-side branch previously let
    /// a host-side caller self-answer, and let a non-participant
    /// company admin join someone else's call), and a policy
    /// disable of voice_video refuses the answer too (the gate
    /// is re-consulted on continuing acts, F6).</summary>
    public bool AnswerCall(string callId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_calls.TryGetValue(callId ?? "", out var call)) return false;
            if (!_sessions.TryGetValue(call.SessionId, out var session)) return false;
            if (EnforceOffboardingLocked(session)) return false;
            session = _sessions[session.Id];
            if (session.State is not ("active" or "paused")) return false;
            if (call.State != "ringing") return false;
            if (!FeatureAllowed(session, PolicyFeatures.VoiceVideo)) { RecordRefusalLocked(session, "answer_call", actorUserId, "policy_disabled:voice_video"); return false; }
            if (string.Equals(actorUserId ?? "", call.InitiatorUserId, StringComparison.OrdinalIgnoreCase))
            { RecordRefusalLocked(session, "answer_call", actorUserId, "self_answer"); return false; } // never self-answered, on any path
            var otherParticipant = _participants[session.Id].Any(p =>
                string.Equals(p.UserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase));
            if (!otherParticipant) { RecordRefusalLocked(session, "answer_call", actorUserId, "not_participant"); return false; }
            // Per-act grant re-check (Block H, AF3): answering is a
            // continuing act — a remote answerer whose "use" right
            // was revoked since the call started cannot pick up.
            if (!IsHostSideActorLocked(session, actorUserId) &&
                !HoldsUseGrantLocked(session, actorUserId!)) { RecordRefusalLocked(session, "answer_call", actorUserId, "no_use_grant"); return false; }
            _calls[call.Id] = call with { State = "active", AnsweredUtc = DateTimeOffset.UtcNow };
            RecordEventLocked(session, "call_answered", actorUserId, call.Id, "Call answered.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>End a live call. Any participant may hang up, the
    /// caller may cancel a ringing call, and a host-side actor may
    /// always end it (the person at the machine is never trapped
    /// in a call). An ended call refuses; an unknown one refuses.</summary>
    public bool EndCall(string callId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_calls.TryGetValue(callId ?? "", out var call)) return false;
            if (call.State == "ended") return false;
            if (!_sessions.TryGetValue(call.SessionId, out var session)) return false;
            var isParticipant = _participants[session.Id].Any(p =>
                string.Equals(p.UserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase));
            if (!isParticipant && !IsHostSideActorLocked(session, actorUserId)) { RecordRefusalLocked(session, "end_call", actorUserId, "actor_not_authorized"); return false; }
            _calls[call.Id] = call with { State = "ended", EndedUtc = DateTimeOffset.UtcNow };
            RecordEventLocked(session, "call_ended", actorUserId, call.Id, "Call ended.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Policy-change TEARDOWN sweep (Block H — the D38
    /// F6/AF7 remainder): when a policy reload DISABLES a feature,
    /// its live effects in that scope end on the spot — a live
    /// call ends, a blanked screen unblanks, an input block
    /// releases, a watermark clears. (Per-act gate re-checks stop
    /// NEW acts; without this sweep a disabled feature's already-
    /// running effect would persist to the session's end, which
    /// is exactly the gap F6 named.) Every teardown is a recorded
    /// session event under the actor "policy". Returns the number
    /// of effects torn down. Clearing directions are the host-
    /// escape directions, so the sweep never traps anyone: it only
    /// ever ENDS effects, never starts them.</summary>
    public int SweepPolicyTeardown(string scopeId, Func<string, bool> featureDisabled)
    {
        lock (_gate)
        {
            var torn = 0;
            foreach (var snapshot in _sessions.Values.Where(s =>
                         string.Equals(s.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase) &&
                         s.State is "active" or "paused").ToList())
            {
                var session = _sessions[snapshot.Id];
                if (featureDisabled(PolicyFeatures.VoiceVideo) && GetLiveCallLocked(session.Id) is not null)
                {
                    EndLiveCallsLocked(session, "policy",
                        "Call ended: a policy change disabled voice_video for this scope.");
                    torn++;
                }
                session = _sessions[session.Id];
                if (featureDisabled(PolicyFeatures.BlankScreen) && session.Blanked)
                {
                    _sessions[session.Id] = session with { Blanked = false };
                    RecordEventLocked(_sessions[session.Id], "blank_cleared", "policy", session.HostDeviceId,
                        "Privacy blank cleared: a policy change disabled blank_screen for this scope.");
                    torn++;
                    session = _sessions[session.Id];
                }
                if (featureDisabled(PolicyFeatures.InputBlock) && session.InputBlocked)
                {
                    _sessions[session.Id] = session with { InputBlocked = false };
                    RecordEventLocked(_sessions[session.Id], "input_block_cleared", "policy", session.HostDeviceId,
                        "Input block released: a policy change disabled input_block for this scope.");
                    torn++;
                    session = _sessions[session.Id];
                }
                // W12 / DS-P5-F14: a policy-REQUIRED watermark is never
                // swept — the sweep honours the same required gate
                // SetWatermarked enforces, so a caller-supplied
                // predicate cannot strip a required accountability mark.
                if (featureDisabled(PolicyFeatures.Watermark) && session.Watermarked &&
                    !FeatureIsRequired(session, PolicyFeatures.Watermark))
                {
                    _sessions[session.Id] = session with { Watermarked = false };
                    RecordEventLocked(_sessions[session.Id], "watermark_cleared", "policy", session.HostDeviceId,
                        "Watermark cleared: a policy change disabled watermark for this scope.");
                    torn++;
                }
            }
            if (torn > 0) Changed?.Invoke();
            return torn;
        }
    }

    /// <summary>The derived watermark for a session (G-07): the
    /// text the stream layer renders while the session's
    /// Watermarked flag stands. Null when the flag is off — there
    /// is no watermark text for an unwatermarked session.</summary>
    public WatermarkSpec.Spec? GetWatermark(string sessionId)
    {
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return null;
            if (!session.Watermarked) return null;
            // D38 review F8: the stamped name comes from LIVE
            // participants only — a suspended/removed holder's
            // stale row supplies nothing.
            var live = _participants[session.Id].Where(p =>
            {
                var u = _roster.GetUser(session.ScopeId, p.UserId);
                return u is not null && !u.Suspended;
            }).ToList();
            return WatermarkSpec.Derive(session, _roster, live);
        }
    }

    // ---- chat (model half) --------------------------------------------------------------

    /// <summary>Send a chat message. The sender must be a
    /// participant of the session; an ended session refuses; empty
    /// text refuses. The message is stored and a "chat_message"
    /// marker lands in the event list (the replay shows chat
    /// activity without duplicating message bodies into events).
    /// A blocked session refuses too: blocked is stopped-pending-end
    /// and no content flows through it. Every send re-reads
    /// offboarding first (D38 F4) — if any participant has been
    /// removed or suspended, the session ends and the send refuses.</summary>
    public ChatMessage? SendChatMessage(string sessionId, string senderUserId, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return null;
            if (session.State == "ended") return null;
            if (EnforceOffboardingLocked(session)) return null; // F4: session just ended
            session = _sessions[session.Id];
            // W12 / DS-P5-F13: chat requires a RUNNING session
            // (active/paused), like calls and file jobs — content no
            // longer flows into a merely "requested" session before
            // the host has consented.
            if (session.State is not ("active" or "paused")) { RecordRefusalLocked(session, "send_chat", senderUserId, "session_not_running"); return null; }
            var sender = _participants[session.Id].FirstOrDefault(
                p => string.Equals(p.UserId, senderUserId ?? "", StringComparison.OrdinalIgnoreCase));
            if (sender is null) { RecordRefusalLocked(session, "send_chat", senderUserId, "not_participant"); return null; } // participants only
            // W12 / DS-P5-F3: the sender must be a LIVE roster user —
            // a removed/suspended participant's row confers nothing.
            var senderUser = _roster.GetUser(session.ScopeId, sender.UserId);
            if (senderUser is null || senderUser.Suspended) { RecordRefusalLocked(session, "send_chat", senderUserId, "sender_not_live"); return null; }
            var message = new ChatMessage(session.Id, sender.UserId, DateTimeOffset.UtcNow, text);
            _chat[session.Id].Add(message);
            RecordEventLocked(session, "chat_message", sender.UserId, session.HostDeviceId, "Chat message sent.");
            Changed?.Invoke();
            return message;
        }
    }

    public IReadOnlyList<ChatMessage> ListChat(string sessionId)
    {
        lock (_gate)
            return _chat.TryGetValue(sessionId ?? "", out var list)
                ? list.ToList()
                : new List<ChatMessage>();
    }

    // ---- file jobs (model half) ------------------------------------------------------------

    /// <summary>Create a file job on a live session. Null on
    /// refusal: unknown/ended session, unknown direction, empty
    /// name, negative size. New jobs are "queued" at 0 bytes.
    /// Authorization + state (D38 F8): the actor must be a live
    /// participant of the session, and transfers exist only once
    /// the session is running — creation requires "active" or
    /// "paused" (never "requested", never "blocked": blocked is
    /// stopped-pending-end). Offboarding is re-read first (F4).</summary>
    public FileJob? CreateFileJob(string sessionId, string direction, string name, long sizeBytes,
        string? actorUserId = null)
    {
        var normalizedDirection = Normalize(direction, ValidDirections);
        if (normalizedDirection is null || string.IsNullOrWhiteSpace(name) || sizeBytes < 0) return null;
        lock (_gate)
        {
            if (!_sessions.TryGetValue(sessionId ?? "", out var session)) return null;
            if (session.State == "ended") return null;
            if (EnforceOffboardingLocked(session)) return null; // F4: session just ended
            session = _sessions[session.Id];
            if (session.State is not ("active" or "paused")) { RecordRefusalLocked(session, "create_file_job", actorUserId, "session_not_running"); return null; } // F8 + W13 refusal record
            if (!IsParticipantLocked(session, actorUserId)) { RecordRefusalLocked(session, "create_file_job", actorUserId, "not_participant"); return null; } // F8: live participant actors only
            // W12 / DS-P5-F3: creating a file job (above all
            // "from_host", an exfiltration of host files) additionally
            // requires a NON-WATCHER participant who is host-side, the
            // initiator, or a CURRENT "use"-grant holder whose device
            // is unrevoked — a revoked grant/device stops content acts
            // mid-session, not just session starts.
            if (!CanActContentLocked(session, actorUserId)) { RecordRefusalLocked(session, "create_file_job", actorUserId, "content_not_authorized"); return null; }
            var job = new FileJob(Guid.NewGuid().ToString("N"), session.Id, normalizedDirection,
                name.Trim(), sizeBytes, 0, "queued");
            _fileJobs[job.Id] = job;
            RecordEventLocked(session, "file_job_added", actorUserId, job.Id,
                $"File job '{job.Name}' ({normalizedDirection}, {sizeBytes} bytes) queued.");
            Changed?.Invoke();
            return job;
        }
    }

    public FileJob? GetFileJob(string? jobId)
    {
        if (string.IsNullOrWhiteSpace(jobId)) return null;
        lock (_gate) return _fileJobs.TryGetValue(jobId, out var j) ? j : null;
    }

    public IReadOnlyList<FileJob> ListFileJobs(string sessionId)
    {
        lock (_gate)
            return _fileJobs.Values
                .Where(j => string.Equals(j.SessionId, sessionId ?? "", StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    /// <summary>Report transfer progress. MONOTONIC: a value below
    /// the current TransferredBytes refuses and changes nothing; a
    /// value above SizeBytes refuses too (progress cannot exceed
    /// the job). Terminal jobs refuse. Equal is a no-op success.
    /// Progress flows only while the session is "active" (D38 F8):
    /// a paused session freezes its jobs, a blocked or ended session
    /// moves nothing. When an actor is named it must be a live
    /// participant; offboarding is re-read first (F4).</summary>
    public bool UpdateFileProgress(string jobId, long transferredBytes, string? actorUserId = null)
    {
        lock (_gate)
        {
            if (!_fileJobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (job.State is "done" or "failed" or "cancelled") return false;
            if (!_sessions.TryGetValue(job.SessionId, out var session)) return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (_sessions[job.SessionId].State != "active") return false; // F8: frozen unless active
            if (actorUserId is not null && !IsParticipantLocked(session, actorUserId)) { RecordRefusalLocked(session, "file_progress", actorUserId, "not_participant"); return false; } // F8 + W13 refusal record
            if (transferredBytes < job.TransferredBytes) return false; // monotonic — never decreases
            if (transferredBytes > job.SizeBytes) return false;
            if (transferredBytes == job.TransferredBytes) return true;
            _fileJobs[job.Id] = job with { TransferredBytes = transferredBytes };
            // W12 / DS-P5-F21: the validated actor is the event actor.
            RecordEventLocked(session, "file_progress", actorUserId, job.Id,
                $"File job '{job.Name}' at {transferredBytes}/{job.SizeBytes} bytes.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Move a file job along its closed transition set.
    /// "done" requires TransferredBytes == SizeBytes — a short job
    /// can never be marked done. Illegal moves change nothing.
    /// Job state moves only while the session is "active" (D38 F8),
    /// by a live participant when an actor is named, with the
    /// offboarding re-read first (F4).</summary>
    public bool SetFileJobState(string jobId, string state, string? actorUserId = null)
    {
        var normalized = Normalize(state, ValidFileJobStates);
        if (normalized is null) return false;
        lock (_gate)
        {
            if (!_fileJobs.TryGetValue(jobId ?? "", out var job)) return false;
            if (!_sessions.TryGetValue(job.SessionId, out var session)) return false;
            if (EnforceOffboardingLocked(session)) return false; // F4
            if (_sessions[job.SessionId].State != "active") return false; // F8
            if (actorUserId is not null && !IsParticipantLocked(session, actorUserId)) { RecordRefusalLocked(session, "file_job_state", actorUserId, "not_participant"); return false; } // F8 + W13 refusal record
            if (!IsLegalFileJobTransition(job.State, normalized)) return false;
            if (normalized == "done" && job.TransferredBytes != job.SizeBytes) return false;
            _fileJobs[job.Id] = job with { State = normalized };
            RecordEventLocked(session, "file_job_state", actorUserId, job.Id, // DS-P5-F21
                $"File job '{job.Name}' → {normalized}.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Live-participant test for the content acts (chat is
    /// checked inline; file jobs share this): the actor must be a
    /// participant of the session AND a live, unsuspended roster
    /// user of its scope. A null actor is never a participant —
    /// file-job creation names its actor or does not happen (F8).</summary>
    private bool IsParticipantLocked(Session session, string? actorUserId)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (!_participants[session.Id].Any(p =>
                string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase)))
            return false;
        var user = _roster.GetUser(session.ScopeId, actorUserId);
        return user is not null && !user.Suspended;
    }

    /// <summary>W12 / DS-P5-F3: the content-act rule for file jobs —
    /// a live participant who is not a mere watcher, and who is
    /// host-side, the session's initiator, or a CURRENT "use"-grant
    /// holder (HoldsUseGrantLocked refuses revoked devices). A
    /// participant whose grant was revoked mid-session, or who only
    /// watches, moves no host data.</summary>
    private bool CanActContentLocked(Session session, string? actorUserId)
    {
        if (!IsParticipantLocked(session, actorUserId)) return false;
        var participant = _participants[session.Id].First(p =>
            string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (participant.Role == "watcher") return false;
        if (IsHostSideActorLocked(session, actorUserId)) return true;
        if (string.Equals(actorUserId, session.InitiatorUserId, StringComparison.OrdinalIgnoreCase)) return true;
        return HoldsUseGrantLocked(session, actorUserId!);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private void RecordEventLocked(Session session, string kind, string? actor, string? subject, string detail)
    {
        if (!_events.TryGetValue(session.Id, out var list))
            _events[session.Id] = list = new List<SessionEvent>();
        list.Add(new SessionEvent(DateTimeOffset.UtcNow, kind, actor, subject, detail));
    }

    private static string? Normalize(string? value, IReadOnlySet<string> valid)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim().ToLowerInvariant();
        return valid.Contains(v) ? v : null;
    }

    // ---- persistence ---------------------------------------------------------------------------

    private sealed record SessionDto(
        string Id, string ScopeId, string HostDeviceId, string InitiatorUserId, string Kind,
        string State, DateTimeOffset? StartedUtc, DateTimeOffset? EndedUtc, string TransportRung,
        string Recording, string? RecordingRef, string? AcceptedByUserId, string? EndReason,
        string? AcceptOrigin = null,
        bool Blanked = false, bool InputBlocked = false, bool Watermarked = false);
    private sealed record ParticipantDto(string SessionId, string UserId, string Role, string Floor);
    private sealed record EventDto(string SessionId, DateTimeOffset Utc, string Kind,
        string? ActorUserId, string? SubjectId, string Detail);
    private sealed record ChatDto(string SessionId, string SenderUserId, DateTimeOffset Utc, string Text);
    private sealed record FileJobDto(
        string Id, string SessionId, string Direction, string Name,
        long SizeBytes, long TransferredBytes, string State);
    private sealed record CallDto(
        string Id, string SessionId, string Kind, string State, string InitiatorUserId,
        DateTimeOffset StartedUtc, DateTimeOffset? AnsweredUtc, DateTimeOffset? EndedUtc);
    private sealed record StoreDto(
        SessionDto[] Sessions, ParticipantDto[] Participants, EventDto[] Events,
        ChatDto[] Chat, FileJobDto[] FileJobs, CallDto[]? Calls = null);

    /// <summary>Serialize the whole session store: sessions,
    /// participants, event lists (the replay source), chat, and
    /// file jobs. No secret of any kind exists in this store —
    /// recording references are local paths by construction.</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _sessions.Values.Select(s => new SessionDto(s.Id, s.ScopeId, s.HostDeviceId,
                    s.InitiatorUserId, s.Kind, s.State, s.StartedUtc, s.EndedUtc, s.TransportRung,
                    s.Recording, s.RecordingRef, s.AcceptedByUserId, s.EndReason, s.AcceptOrigin,
                    s.Blanked, s.InputBlocked, s.Watermarked)).ToArray(),
                _participants.SelectMany(kv => kv.Value.Select(p =>
                    new ParticipantDto(p.SessionId, p.UserId, p.Role, p.Floor))).ToArray(),
                _events.SelectMany(kv => kv.Value.Select(e =>
                    new EventDto(kv.Key, e.Utc, e.Kind, e.ActorUserId, e.SubjectId, e.Detail))).ToArray(),
                _chat.SelectMany(kv => kv.Value.Select(m =>
                    new ChatDto(m.SessionId, m.SenderUserId, m.Utc, m.Text))).ToArray(),
                _fileJobs.Values.Select(j => new FileJobDto(j.Id, j.SessionId, j.Direction,
                    j.Name, j.SizeBytes, j.TransferredBytes, j.State)).ToArray(),
                _calls.Values.Select(c => new CallDto(c.Id, c.SessionId, c.Kind, c.State,
                    c.InitiatorUserId, c.StartedUtc, c.AnsweredUtc, c.EndedUtc)).ToArray());
            return JsonSerializer.Serialize(store);
        }
    }

    /// <summary>Restore a store previously produced by ExportJson.
    /// Malformed entries are skipped, never fatal — unknown kinds /
    /// states / roles / recording modes, non-rung transports,
    /// remote recording refs, orphaned participants/events/chat/
    /// jobs, and non-monotonic or over-size job progress are all
    /// dropped at the entry that carries them, and malformed JSON
    /// as a whole restores nothing rather than throwing. A stored
    /// session with two floor holders is repaired to watching for
    /// all but the first holder — the one-holder invariant holds
    /// even for hand-edited stores. Consent is re-validated, never
    /// trusted (D38 F7): a stored live session whose recorded accept
    /// is missing/invalid or whose initiator is gone is repaired to
    /// ended, and child records attach only to sessions restored by
    /// this call (D38 F12). Returns the number of entries restored.</summary>
    public int ImportJson(string json)
    {
        StoreDto? store;
        try { store = JsonSerializer.Deserialize<StoreDto>(json); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            // Sessions restored by THIS call. Child records (partici-
            // pants/events/chat/jobs) attach only to these — re-importing
            // a file over a live store must not replay history into
            // sessions that were already there (D38 F12).
            var importedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dto in store.Sessions ?? Array.Empty<SessionDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    string.IsNullOrWhiteSpace(dto.ScopeId) ||
                    string.IsNullOrWhiteSpace(dto.HostDeviceId) ||
                    string.IsNullOrWhiteSpace(dto.InitiatorUserId)) continue;
                var kind = Normalize(dto.Kind, ValidKinds);
                var state = Normalize(dto.State, ValidStates);
                var recording = Normalize(dto.Recording, ValidRecordings);
                if (kind is null || state is null || recording is null) continue;
                // W12 / DS-P5-F7 (reconciled with RMM-22 F5):
                // camera_share is minted ONLY by CameraShareService,
                // so an imported camera_share record is forced ENDED
                // below (state rewritten before the record is built)
                // — it survives as audit history, never as a live or
                // startable session.
                var forceEnded = kind == "camera_share";
                if (forceEnded) state = "ended";
                if (!RosterService.IsValidRung(dto.TransportRung)) continue;
                if (IsRemoteRecordingRef(dto.RecordingRef)) continue; // D36 holds on import too
                if (_sessions.ContainsKey(dto.Id)) continue;

                // Consent + offboarding RE-VALIDATION (D38 F7): the
                // stored record is untrusted input. An accept counts
                // only if the acceptor is a live HUMAN user of the
                // scope AND its origin is one the ruling honors: an
                // "endpoint_local" accept is valid for any live human
                // acceptor, the initiator included (2026-11-19 ruling);
                // an "initiating_channel" accept NEVER counts; a
                // record with no origin predates the ruling and keeps
                // the original F1 rule (a live human who is not the
                // initiator). A live (non-requested, non-ended)
                // session whose consent or initiator fails validation
                // is repaired to ENDED — a hand-edited store can never
                // mint a live session whose consent was never given.
                // A merely-requested session keeps its place with the
                // forged accept cleared.
                var acceptedBy = dto.AcceptedByUserId;
                var acceptOrigin = (dto.AcceptOrigin ?? "").Trim().ToLowerInvariant() switch
                {
                    AcceptOriginEndpointLocal => AcceptOriginEndpointLocal,
                    AcceptOriginInitiatingChannel => AcceptOriginInitiatingChannel,
                    _ => null,
                };
                var acceptValid = false;
                if (acceptedBy is not null &&
                    _roster.GetUser(dto.ScopeId, acceptedBy) is { Kind: "human", Suspended: false })
                {
                    acceptValid = acceptOrigin switch
                    {
                        AcceptOriginEndpointLocal => true,
                        AcceptOriginInitiatingChannel => false,
                        _ => !string.Equals(acceptedBy, dto.InitiatorUserId, StringComparison.OrdinalIgnoreCase),
                    };
                }
                if (!acceptValid) { acceptedBy = null; acceptOrigin = null; }
                var initiator = _roster.GetUser(dto.ScopeId, dto.InitiatorUserId);
                var initiatorLive = initiator is not null && !initiator.Suspended;
                var endedUtc = dto.EndedUtc;
                var endReason = dto.EndReason;
                if (forceEnded)
                {
                    // DS-P5-F7: the retired kind ends at the import
                    // boundary, with the reason named.
                    endReason = "kind_retired_on_import";
                    endedUtc ??= DateTimeOffset.UtcNow;
                }
                if (state is "active" or "paused" or "blocked")
                {
                    if (!initiatorLive || (kind == "attended" && !acceptValid))
                    {
                        state = "ended";
                        endReason = EndReasonImportRepair;
                        endedUtc ??= DateTimeOffset.UtcNow;
                    }
                    else
                    {
                        // D38-G review F3 (second half): a live
                        // imported session is ALSO re-checked the
                        // way StartSession checks — the host device
                        // must still be hostable (enrolled,
                        // unrevoked, filed in this scope), and an
                        // UNATTENDED session's initiator must still
                        // hold the "use" grant. Failing either, the
                        // session is repaired to ended, never
                        // resurrected live on stale authority.
                        var device = _enrollments.List().FirstOrDefault(
                            d => string.Equals(d.DeviceId, dto.HostDeviceId, StringComparison.OrdinalIgnoreCase));
                        var deviceGroup = device is null ? null : _roster.GetDeviceGroup(dto.ScopeId, device.GroupId);
                        var hostable = device is not null && !device.Revoked &&
                            deviceGroup is not null &&
                            string.Equals(deviceGroup.ScopeId, dto.ScopeId, StringComparison.OrdinalIgnoreCase);
                        var grantOk = kind != "unattended" || (device is not null &&
                            _roster.UserHasRight(dto.ScopeId, dto.InitiatorUserId, device.GroupId, "use"));
                        if (!hostable || !grantOk)
                        {
                            state = "ended";
                            endReason = EndReasonImportRepair;
                            endedUtc ??= DateTimeOffset.UtcNow;
                        }
                    }
                }
                // Block G surface flags on import: a stored flag is
                // trusted only as far as the state allows — an ended
                // session carries none (EndLocked's invariant), and
                // an input block is live-session-only, so a stored
                // block on a non-active session is dropped, never
                // resurrected as a claim nothing is enforcing.
                // W12 / DS-P5-F15: flags gated by the states that may
                // carry them live — blank: active/paused only (the
                // SetBlanked rule); watermark: never on blocked.
                var importedBlanked = dto.Blanked && state is "active" or "paused";
                var importedBlocked = dto.InputBlocked && state == "active";
                var importedWatermark = dto.Watermarked && state is "active" or "paused" or "requested";
                _sessions[dto.Id] = new Session(dto.Id, dto.ScopeId, dto.HostDeviceId,
                    dto.InitiatorUserId, kind, state, dto.StartedUtc, endedUtc,
                    dto.TransportRung.Trim().ToLowerInvariant(), recording,
                    recording == "none" ? null : dto.RecordingRef,
                    acceptedBy, endReason, acceptOrigin,
                    importedBlanked, importedBlocked, importedWatermark);
                _participants[dto.Id] = new List<Participant>();
                _events[dto.Id] = new List<SessionEvent>();
                _chat[dto.Id] = new List<ChatMessage>();
                importedIds.Add(dto.Id);
                restored++;
            }
            foreach (var dto in store.Participants ?? Array.Empty<ParticipantDto>())
            {
                if (dto is null || dto.SessionId is null || !importedIds.Contains(dto.SessionId)) continue;
                var session = _sessions[dto.SessionId];
                var role = Normalize(dto.Role, ValidRoles);
                if (role is null || string.IsNullOrWhiteSpace(dto.UserId)) continue;
                // D38-G review F3: the "host" role is an AUTHORITY
                // row (it makes its holder a host-side actor).
                // AddParticipant refuses to mint it live; import
                // must not mint it from a hand-edited file either —
                // a stored host row survives only for the user the
                // session's VALIDATED accept names; anyone else is
                // demoted to watcher.
                if (role == "host" &&
                    !string.Equals(dto.UserId, session.AcceptedByUserId, StringComparison.OrdinalIgnoreCase))
                    role = "watcher";
                // F7: a participant must be a user of the scope —
                // unknown ids are dropped, and a suspended user is
                // demoted to watching (never a floor holder).
                var user = _roster.GetUser(session.ScopeId, dto.UserId);
                if (user is null) continue;
                var participants = _participants[session.Id];
                if (participants.Any(p => string.Equals(p.UserId, dto.UserId, StringComparison.OrdinalIgnoreCase)))
                    continue;
                var floor = (dto.Floor ?? "").Trim().ToLowerInvariant() == "holds" ? "holds" : "watching";
                if (user.Suspended) floor = "watching";
                if (floor == "holds" && participants.Any(p => p.Floor == "holds"))
                    floor = "watching"; // one-holder invariant survives import
                participants.Add(new Participant(session.Id, dto.UserId, role, floor));
                restored++;
            }
            foreach (var dto in store.Events ?? Array.Empty<EventDto>())
            {
                if (dto is null || dto.SessionId is null || !importedIds.Contains(dto.SessionId)) continue;
                var session = _sessions[dto.SessionId];
                if (string.IsNullOrWhiteSpace(dto.Kind)) continue;
                _events[session.Id].Add(new SessionEvent(dto.Utc, dto.Kind, dto.ActorUserId,
                    dto.SubjectId, dto.Detail ?? ""));
                restored++;
            }
            foreach (var dto in store.Chat ?? Array.Empty<ChatDto>())
            {
                if (dto is null || dto.SessionId is null || !importedIds.Contains(dto.SessionId)) continue;
                var session = _sessions[dto.SessionId];
                if (string.IsNullOrWhiteSpace(dto.SenderUserId) || string.IsNullOrWhiteSpace(dto.Text)) continue;
                _chat[session.Id].Add(new ChatMessage(session.Id, dto.SenderUserId, dto.Utc, dto.Text));
                restored++;
            }
            foreach (var dto in store.FileJobs ?? Array.Empty<FileJobDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    dto.SessionId is null || !importedIds.Contains(dto.SessionId)) continue;
                var session = _sessions[dto.SessionId];
                var direction = Normalize(dto.Direction, ValidDirections);
                var state = Normalize(dto.State, ValidFileJobStates);
                if (direction is null || state is null || string.IsNullOrWhiteSpace(dto.Name)) continue;
                if (dto.SizeBytes < 0 || dto.TransferredBytes < 0 || dto.TransferredBytes > dto.SizeBytes) continue;
                if (state == "done" && dto.TransferredBytes != dto.SizeBytes) continue;
                if (_fileJobs.ContainsKey(dto.Id)) continue;
                // The end cascade's invariant holds on import too: a
                // job on an ended session is never left live.
                if (session.State == "ended" && state is not ("done" or "failed" or "cancelled"))
                    state = "cancelled";
                _fileJobs[dto.Id] = new FileJob(dto.Id, session.Id, direction, dto.Name,
                    dto.SizeBytes, dto.TransferredBytes, state);
                restored++;
            }
            foreach (var dto in store.Calls ?? Array.Empty<CallDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) ||
                    dto.SessionId is null || !importedIds.Contains(dto.SessionId)) continue;
                var session = _sessions[dto.SessionId];
                var kind = Normalize(dto.Kind, ValidCallKinds);
                var state = Normalize(dto.State, ValidCallStates);
                if (kind is null || state is null ||
                    string.IsNullOrWhiteSpace(dto.InitiatorUserId)) continue;
                if (_calls.ContainsKey(dto.Id)) continue;
                // W12 / DS-P5-F15: at most ONE live call per session,
                // and a live call only on a started (active/paused)
                // session — the same invariants StartCall enforces.
                if (state is "ringing" or "active")
                {
                    if (session.State is not ("active" or "paused")) continue;
                    if (_calls.Values.Any(c => string.Equals(c.SessionId, session.Id, StringComparison.OrdinalIgnoreCase) &&
                            c.State is "ringing" or "active")) continue;
                }
                // The cascade invariant holds on import too: no
                // live call on an ended or blocked session.
                var endedUtc = dto.EndedUtc;
                if (session.State is "ended" or "blocked" && state != "ended")
                {
                    state = "ended";
                    endedUtc ??= DateTimeOffset.UtcNow;
                }
                if (state == "ended" && endedUtc is null) endedUtc = dto.StartedUtc;
                _calls[dto.Id] = new SessionCall(dto.Id, session.Id, kind, state,
                    dto.InitiatorUserId, dto.StartedUtc, dto.AnsweredUtc, endedUtc);
                restored++;
            }
        }
        return restored;
    }

    /// <summary>Restart reconciliation (D38 F11): Core calls this
    /// once after restoring the store at startup. A session record
    /// that was live when the previous Core died has nothing live
    /// behind it — leaving it "active" would present a phantom
    /// session (and a phantom recording) to the presence layer.
    /// Every non-ended session is ended with reason core_restart
    /// and its file jobs cascade-cancel. Returns the number of
    /// sessions reconciled; idempotent.</summary>
    public int ReconcileAfterRestart()
    {
        lock (_gate)
        {
            var count = 0;
            foreach (var session in _sessions.Values.Where(s => s.State != "ended").ToList())
            {
                EndLocked(session, session.InitiatorUserId, EndReasonCoreRestart);
                count++;
            }
            if (count > 0) Changed?.Invoke();
            return count;
        }
    }
}

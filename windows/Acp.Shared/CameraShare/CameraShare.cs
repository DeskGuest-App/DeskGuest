using System.Text.Json;
using Acp.Shared.Enrollment;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Roster;
using Acp.Shared.Streaming;

namespace Acp.Shared.CameraShare;

// =====================================================================
// RMM-22 — Camera-share sessions: "see the rack." (ADOPTED
// 2026-11-20, owner directive: "Implement it all".)
//
// A consent-gated SESSION KIND (SessionService.ValidKinds carries
// "camera_share") where the person on site points their phone
// camera at the problem and a named helper watches live. The
// bounds below are the directive, not commentary:
//
//  * THE CAMERA SIDE IS ALWAYS THE INITIATOR. A share is created
//    ONLY by the phone owner, on the phone, naming ONE specific
//    watcher. "The phone owner" is a checked fact, not a caller
//    claim (D38 F1): a phone must be BOUND to its owner in this
//    service (BindPhoneOwner — by the owner, or by a company admin
//    provisioning the phone) before anyone can initiate a share
//    or mint an AI grant for it, and initiation/granting then
//    require the caller to BE that bound owner. An unbound phone
//    fails closed. There is no remote-start path anywhere in this file:
//    the generic SessionService refuses to mint or start a
//    camera_share at all (see Sessions.cs), and this service's
//    only creation entry point requires the owner as its actor.
//  * PRESENCE IN FULL (SPEC §7.10). While a share exists, the
//    phone-side presence surface (CameraSharePresence, derived
//    ONLY from the share record) names the watcher, shows the
//    share state, and carries a STOP that is always available.
//    STOP is the owner's act, works from every non-ended state,
//    and ends the share in the same call — frames submitted after
//    STOP refuse, there is no draining/grace state.
//  * ONE-WAY VIDEO. Frames flow phone → watcher only, as Block D
//    ACPF envelopes (StreamProtocol is the frame gate: an invalid
//    envelope is dropped, never forwarded). The watcher's voice
//    channel is a SEPARATE explicit toggle, default OFF (REC-06
//    spirit), owner-controlled, and policy-gated.
//  * LIVE ONLY — NO RECORDING SURFACE. Frames are validated,
//    forwarded to the sink, and discarded; the model retains only
//    a frame COUNT. There is no frame store, no recording flag
//    that can be true, and no export of media. Recording a share
//    is a separate explicit act under the REC rules and is out of
//    scope here; TryEnableRecording refuses (and audits) always.
//  * AI WATCHERS NEED AN EXPLICIT GRANT (D12-style). An AI pairing
//    can be named watcher ONLY under an AiCameraShareGrant minted
//    by the phone owner for that AI + that phone + a bounded TTL.
//    Default is denied; no grant path is silently assumed — the
//    camera is the most intimate surface in the product.
//  * POLICY (RMM-07 / TOTAL POLICY CONTROL). The seeded toggle
//    rmm.camera_share.enabled (default ON) gates initiation, and
//    is re-read while a share lives: a policy that turns the
//    feature off ends live shares (Tick). Voice rides its own
//    key, default OFF.
//  * AUDIT. Start, watcher join, voice/torch acts, every end with
//    its cause and duration, and EVERY refusal land in the shared
//    hash-chained ledger (ChainedAuditLog) — audit-first, like the
//    camera-viewing service: the start entry is chained before
//    the stream sink is touched, so no ordering of failures can
//    produce an unaudited live share.
//
// ANDROID HOST INTEGRATION (honest labelling): the Android camera
// pipeline (CameraX → encoder → transport) is host work for when
// the phone channel and the Android build path are live. This file
// is the shared model + service + contracts both hosts bind to;
// the exact Android hook points are named in the lane log
// (~/workspace/builds/rmm-r-logs/log-rmm22.md).
// =====================================================================

public static class CameraSharePolicyKeys
{
    /// <summary>The RMM-07 seeded toggle (default ON).</summary>
    public const string Enabled = "rmm.camera_share.enabled";

    /// <summary>The watcher's voice channel: separate key, no
    /// registry seed — ManagementPolicyEngine.IsEnabled fails
    /// closed for an unset key, so voice is OFF unless policy
    /// explicitly turns it on for the phone's scope/group/device.</summary>
    public const string VoiceEnabled = "rmm.camera_share.voice.enabled";

    /// <summary>Optional policy cap on share length, in minutes.
    /// Unset/unparsable/out-of-range falls back to the service
    /// default — a policy value can shorten a share, and a sane
    /// ceiling stops a typo from making shares effectively
    /// unbounded.</summary>
    public const string MaxDurationMinutes = "rmm.camera_share.max_duration_minutes";
}

public static class CameraShareStates
{
    /// <summary>Owner has started the share; the named watcher has
    /// not joined yet. Presence shows "waiting for &lt;watcher&gt;".</summary>
    public const string Waiting = "waiting";

    /// <summary>The named watcher is joined; frames flow.</summary>
    public const string Sharing = "sharing";

    /// <summary>Terminal. Every end carries a cause (EndReasons).</summary>
    public const string Ended = "ended";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Waiting, Sharing, Ended };
}

public static class CameraShareEndReasons
{
    /// <summary>The phone owner's STOP.</summary>
    public const string OwnerStop = "owner_stop";
    /// <summary>The named watcher disconnected.</summary>
    public const string WatcherDisconnect = "watcher_disconnect";
    /// <summary>The share hit its maximum duration.</summary>
    public const string Timeout = "timeout";
    /// <summary>The phone owner navigated away from the share surface.</summary>
    public const string OwnerNavigatedAway = "owner_navigated_away";
    /// <summary>Owner or watcher was removed/suspended mid-share (D14).</summary>
    public const string ParticipantRemoved = "participant_removed";
    /// <summary>Policy turned the feature off while the share lived.</summary>
    public const string PolicyDisabled = "policy_disabled";
    /// <summary>A restored store never resumes a live share: consent
    /// was given before the restart, so the share imports ended.</summary>
    public const string ImportRepair = "import_repair";
}

/// <summary>One camera-share session. Kind is always
/// "camera_share" (a session kind in the shared model, not a
/// parallel system). Recording is a constant "none": the record
/// carries the flag precisely so that — exactly as with
/// Session.IsRecording — any reader can derive from the record
/// itself that this share is not recording, and there is no state
/// in which it could be. FramesForwarded is a COUNT; no frame
/// bytes exist anywhere on this record.</summary>
public sealed record CameraShareSession(
    string Id,
    string ScopeId,
    string PhoneDeviceId,
    string OwnerUserId,
    string WatcherUserId,
    string WatcherKind,               // "human" | "ai" (from the roster, never caller-supplied)
    string State,
    DateTimeOffset StartedUtc,
    DateTimeOffset? WatcherJoinedUtc,
    DateTimeOffset? EndedUtc,
    string? EndReason,
    bool VoiceEnabled,
    bool TorchEnabled,
    long FramesForwarded,
    long AnnotationsForwarded,
    string? AiGrantId = null)
{
    public string Kind => "camera_share";
    public string Recording => "none";
    public bool IsRecording => false;
    public bool IsLive => State is CameraShareStates.Waiting or CameraShareStates.Sharing;
    public bool IsBeingWatched => State == CameraShareStates.Sharing;
    public TimeSpan? Duration => EndedUtc is { } end ? end - StartedUtc : null;
}

/// <summary>An explicit D12-style grant letting ONE named AI
/// pairing be named watcher of camera shares from ONE phone,
/// minted by that phone's owner, bounded by a TTL. This record is
/// the ONLY path by which an AI can watch a camera share: no
/// grant, no share — and a grant names exactly (owner, AI, phone);
/// it confers nothing else (not a session right, not another
/// device, not another AI).</summary>
public sealed record AiCameraShareGrant(
    string Id,
    string ScopeId,
    string OwnerUserId,
    string AiUserId,
    string PhoneDeviceId,
    DateTimeOffset GrantedUtc,
    DateTimeOffset ExpiresUtc,
    bool Revoked)
{
    public bool IsLiveAt(DateTimeOffset now) => !Revoked && now < ExpiresUtc;
}

/// <summary>The phone-side presence surface contract (SPEC §7.10),
/// DERIVED from the share record — the Android host renders exactly
/// this and derives nothing of its own, so the phone can never show
/// a share state the record does not hold. StopAvailable is part of
/// the contract: it is true in every live state, by construction —
/// there is no constructor path that produces a live presence
/// without STOP.</summary>
public sealed record CameraSharePresence(
    string ShareId,
    string WatcherUserId,
    string WatcherDisplayName,
    string State,
    bool IsBeingWatched,
    bool VoiceEnabled,
    bool TorchEnabled,
    DateTimeOffset StartedUtc,
    bool StopAvailable,
    bool IsRecording,
    string BannerText);

/// <summary>The stream hand-off: the service validates and presents
/// frames; the sink (Block D StreamService on Windows, the Android
/// host's transport on the phone side) carries them to the named
/// watcher. Delivery is transient — a sink that retains frames is
/// a different feature (recording) and out of contract.</summary>
public interface ICameraShareSink
{
    (bool Ok, string Detail) OpenShare(string shareId, string watcherUserId);
    void DeliverFrame(string shareId, byte[] envelope);
    void DeliverAnnotation(string shareId, int x, int y);
    void CloseShare(string shareId, string reason);
}

/// <summary>Recording test double for ICameraShareSink. It keeps
/// the envelopes it was handed ONLY so tests can prove what flowed;
/// production sinks forward-and-drop.</summary>
public sealed class RecordingCameraShareSink : ICameraShareSink
{
    public List<(string ShareId, string WatcherUserId)> Opened { get; } = new();
    public List<(string ShareId, byte[] Envelope)> Frames { get; } = new();
    public List<(string ShareId, int X, int Y)> Annotations { get; } = new();
    public List<(string ShareId, string Reason)> Closed { get; } = new();
    public bool FailOpen { get; set; }

    public (bool Ok, string Detail) OpenShare(string shareId, string watcherUserId)
    {
        if (FailOpen) return (false, "stream layer refused (recording double)");
        Opened.Add((shareId, watcherUserId));
        return (true, "share opened (recording double)");
    }

    public void DeliverFrame(string shareId, byte[] envelope) => Frames.Add((shareId, envelope));
    public void DeliverAnnotation(string shareId, int x, int y) => Annotations.Add((shareId, x, y));
    public void CloseShare(string shareId, string reason) => Closed.Add((shareId, reason));
}

public sealed record CameraShareStartResult(bool Ok, CameraShareSession? Share, string Reason);

/// <summary>The camera-share service. Every public act re-reads
/// the roster and the policy at act time (a user suspended or a
/// policy flipped mid-share takes effect at the next act, and
/// Tick enforces both proactively). Guard refusals return
/// false/null with an audit entry — fail-closed, never an
/// exception, never a partial mutation.</summary>
public sealed class CameraShareService
{
    /// <summary>Default maximum share length when policy does not
    /// set one: a camera pointed at a rack is a bounded act.</summary>
    public static readonly TimeSpan DefaultMaxDuration = TimeSpan.FromMinutes(60);

    /// <summary>Hard ceiling for the policy-set maximum, and for
    /// AI-grant TTLs: no single consent covers an unbounded stare.</summary>
    public static readonly TimeSpan AbsoluteMaxDuration = TimeSpan.FromHours(8);

    /// <summary>How long an ENDED share record is retained before
    /// Tick prunes it (D38 F9): the audit ledger is the permanent
    /// record of the share; the in-memory record is not, and the
    /// store must not grow with every share ever created.</summary>
    public static readonly TimeSpan EndedShareRetention = TimeSpan.FromHours(24);

    private readonly RosterService _roster;
    private readonly EnrollmentService _enrollments;
    private readonly ManagementPolicyEngine _policy;
    private readonly ChainedAuditLog _audit;
    private readonly ICameraShareSink _sink;
    private readonly Func<DateTimeOffset> _now;

    private readonly Dictionary<string, CameraShareSession> _shares = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AiCameraShareGrant> _aiGrants = new(StringComparer.OrdinalIgnoreCase);

    // D38 F1: phone → owner bindings. A phone is tied to exactly
    // one owner user in this service; initiation and AI granting
    // require the caller to BE that bound owner. Keyed
    // "scopeId\u001fdeviceId". Guarded by _gate.
    private readonly Dictionary<string, string> _phoneOwners = new(StringComparer.OrdinalIgnoreCase);

    // D38 F9: refused-frame audit aggregation — a count per
    // (share, reason); the ledger gets the first refusal and every
    // 100th, not one chained entry per frame at stream rate.
    // Guarded by _gate.
    private readonly Dictionary<string, int> _frameRefusals = new(StringComparer.OrdinalIgnoreCase);

    private readonly object _gate = new();

    public CameraShareService(
        RosterService roster, EnrollmentService enrollments,
        ManagementPolicyEngine policy, ChainedAuditLog audit,
        ICameraShareSink sink, Func<DateTimeOffset>? now = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Raised after any durable mutation so the host can
    /// persist the store (the PairingService pattern).</summary>
    public event Action? Changed;

    // ---- helpers ---------------------------------------------------------------

    private IDeviceFacts FactsFor(string scopeId, EnrolledDevice device) =>
        StaticDeviceFacts.Of(device.DeviceId, scopeId,
            groups: new[] { device.GroupId },
            attributes: new Dictionary<string, string> { ["kind"] = "phone" });

    private EnrolledDevice? FiledDevice(string scopeId, string? deviceId)
    {
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId ?? "", StringComparison.OrdinalIgnoreCase));
        if (device is null || device.Revoked) return null;
        var group = _roster.FindDeviceGroup(device.GroupId);
        return group is not null &&
               string.Equals(group.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)
            ? device : null;
    }

    private TimeSpan MaxDurationFor(IDeviceFacts facts)
    {
        var setting = _policy.ComputeEffective(facts).Get(CameraSharePolicyKeys.MaxDurationMinutes);
        if (setting is not null && double.TryParse(setting.Value,
                System.Globalization.NumberStyles.Number,
                System.Globalization.CultureInfo.InvariantCulture, out var minutes) &&
            minutes > 0 && double.IsFinite(minutes))
        {
            // D38 F3: apply the ceiling BEFORE constructing the
            // TimeSpan — TimeSpan.FromMinutes throws OverflowException
            // above ~1.54e10 minutes, and a policy typo at exactly
            // that scale must clamp, not crash the Tick loop.
            if (minutes >= AbsoluteMaxDuration.TotalMinutes) return AbsoluteMaxDuration;
            return TimeSpan.FromMinutes(minutes);
        }
        return DefaultMaxDuration;
    }

    private static string BindingKey(string scopeId, string deviceId) => scopeId + "\u001f" + deviceId;

    /// <summary>The bound owner of a phone, or null when the phone
    /// is unbound (fail-closed). Caller holds _gate.</summary>
    private string? BoundOwnerLocked(string scopeId, string deviceId) =>
        _phoneOwners.TryGetValue(BindingKey(scopeId, deviceId), out var owner) ? owner : null;

    /// <summary>Aggregated frame refusal (D38 F9). Caller holds
    /// _gate. The first refusal of a kind for a share is chained in
    /// full, and every 100th after it — a phone streaming before
    /// its watcher joins (the normal CameraX startup race) or a
    /// misbehaving client at 30 fps cannot flood the ledger, but
    /// the refusal stream stays visible and counted.</summary>
    private bool RefuseFrame(string shareId, string actor, string reason, DateTimeOffset now)
    {
        var key = shareId + "\u001f" + reason;
        var n = _frameRefusals.TryGetValue(key, out var count) ? count + 1 : 1;
        _frameRefusals[key] = n;
        if (n == 1 || n % 100 == 0)
            _audit.Append("camera_share_frame_refused",
                string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
                $"share={shareId} reason={reason} refusals={n}", now);
        return false;
    }

    /// <summary>Act-time revalidation (D38 F8): the class contract
    /// is that every public act re-reads the roster and the policy.
    /// Returns the end cause when the world no longer consents to
    /// this share (a party removed/suspended, the AI grant dead,
    /// the phone revoked/unfiled, the feature policy off), else
    /// null. Caller holds _gate.</summary>
    private string? ActTimeEndCauseLocked(CameraShareSession share, DateTimeOffset now)
    {
        var owner = _roster.GetUser(share.ScopeId, share.OwnerUserId);
        var watcher = _roster.GetUser(share.ScopeId, share.WatcherUserId);
        if (owner is null || owner.Suspended || watcher is null || watcher.Suspended)
            return CameraShareEndReasons.ParticipantRemoved;
        if (watcher.Kind == "ai" &&
            LiveGrantFor(share.ScopeId, share.OwnerUserId, watcher.Id, share.PhoneDeviceId, now) is null)
            return CameraShareEndReasons.ParticipantRemoved;
        var device = FiledDevice(share.ScopeId, share.PhoneDeviceId);
        if (device is null) return CameraShareEndReasons.ParticipantRemoved;
        if (!_policy.IsEnabled(FactsFor(share.ScopeId, device), CameraSharePolicyKeys.Enabled))
            return CameraShareEndReasons.PolicyDisabled;
        return null;
    }

    private CameraShareStartResult Refuse(string scopeId, string actor, string watcher, string deviceId, string reason, DateTimeOffset now)
    {
        _audit.Append("camera_share_refused", string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
            $"scope={scopeId} watcher={watcher} phone={deviceId} reason={reason}", now);
        return new CameraShareStartResult(false, null, reason);
    }

    private bool RefuseAct(string kind, string shareId, string actor, string reason, DateTimeOffset now)
    {
        _audit.Append(kind, string.IsNullOrWhiteSpace(actor) ? "unknown" : actor,
            $"share={shareId} reason={reason}", now);
        return false;
    }

    // ---- phone ownership binding (D38 F1) -----------------------------------------

    /// <summary>Bind a phone to its owner. Until a phone is bound,
    /// NOBODY can initiate a share on it or mint an AI grant for it
    /// (fail-closed): being a live human of the scope is not enough
    /// — the caller must be the phone's owner, and ownership is a
    /// recorded fact, not a caller claim. Binding is done by the
    /// owner themselves (a live human of the scope, for their own
    /// id) or by a company admin provisioning the phone.
    /// Rebinding to a DIFFERENT owner requires the current bound
    /// owner or a company admin. Every bind and refusal is audited.</summary>
    public bool BindPhoneOwner(string scopeId, string actorUserId, string phoneDeviceId, string ownerUserId)
    {
        var now = _now();
        if (_roster.GetScope(scopeId) is not { } scope)
        {
            _audit.Append("camera_share_phone_bind_refused", actorUserId ?? "unknown",
                $"scope={scopeId} phone={phoneDeviceId} owner={ownerUserId} reason=unknown scope", now);
            return false;
        }
        var device = FiledDevice(scope.Id, phoneDeviceId);
        if (device is null)
        {
            _audit.Append("camera_share_phone_bind_refused", actorUserId ?? "unknown",
                $"scope={scope.Id} phone={phoneDeviceId} owner={ownerUserId} reason=phone is not an enrolled device filed in this scope", now);
            return false;
        }
        var owner = _roster.GetUser(scope.Id, ownerUserId);
        if (owner is null || owner.Suspended || owner.Kind != "human")
        {
            _audit.Append("camera_share_phone_bind_refused", actorUserId ?? "unknown",
                $"scope={scope.Id} phone={device.DeviceId} owner={ownerUserId} reason=owner is not a live human user of the scope", now);
            return false;
        }
        lock (_gate)
        {
            var current = BoundOwnerLocked(scope.Id, device.DeviceId);
            var isSelfBind = string.Equals(actorUserId ?? "", owner.Id, StringComparison.OrdinalIgnoreCase);
            var isAdmin = _roster.IsCompanyAdmin(scope.Id, actorUserId ?? "");
            var isCurrentOwner = current is not null &&
                string.Equals(actorUserId ?? "", current, StringComparison.OrdinalIgnoreCase);
            if (current is null ? !(isSelfBind || isAdmin) : !(isCurrentOwner || isAdmin))
            {
                _audit.Append("camera_share_phone_bind_refused", actorUserId ?? "unknown",
                    $"scope={scope.Id} phone={device.DeviceId} owner={owner.Id} reason=only the owner themselves, the current bound owner, or a company admin can bind this phone", now);
                return false;
            }
            _phoneOwners[BindingKey(scope.Id, device.DeviceId)] = owner.Id;
            _audit.Append("camera_share_phone_bound", actorUserId,
                $"scope={scope.Id} phone={device.DeviceId} owner={owner.Id}", now);
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>The bound owner of a phone in a scope, or null when
    /// unbound.</summary>
    public string? BoundOwnerOf(string scopeId, string phoneDeviceId)
    {
        lock (_gate) return BoundOwnerLocked(scopeId ?? "", phoneDeviceId ?? "");
    }

    // ---- AI watcher grants (the explicit D12-style path) -------------------------

    /// <summary>Mint an AI-watcher grant. The grantor must be the
    /// phone's BOUND owner (D38 F1 — a live human of the scope who
    /// is recorded as this phone's owner, see BindPhoneOwner); the
    /// grantee must be a live AI user of the SAME scope; the phone
    /// must be enrolled and filed in the scope. TTL must be
    /// positive; a TTL above AbsoluteMaxDuration is CLAMPED to the
    /// ceiling, and the clamped value is what the grant record and
    /// the audit detail state — never granted unbounded, never
    /// silently different from what the record says.</summary>
    public AiCameraShareGrant? GrantAiWatcher(string scopeId, string ownerUserId, string aiUserId,
        string phoneDeviceId, TimeSpan ttl)
    {
        var now = _now();
        var owner = _roster.GetUser(scopeId, ownerUserId);
        if (owner is null || owner.Suspended || owner.Kind != "human")
        {
            _audit.Append("camera_share_ai_grant_refused", ownerUserId ?? "unknown",
                $"scope={scopeId} ai={aiUserId} phone={phoneDeviceId} reason=grantor is not a live human user of the scope", now);
            return null;
        }
        var ai = _roster.GetUser(scopeId, aiUserId);
        if (ai is null || ai.Suspended || ai.Kind != "ai")
        {
            _audit.Append("camera_share_ai_grant_refused", owner.Id,
                $"scope={scopeId} ai={aiUserId} phone={phoneDeviceId} reason=grantee is not a live AI user of the scope", now);
            return null;
        }
        var filedPhone = FiledDevice(scopeId, phoneDeviceId);
        if (filedPhone is null)
        {
            _audit.Append("camera_share_ai_grant_refused", owner.Id,
                $"scope={scopeId} ai={ai.Id} phone={phoneDeviceId} reason=phone is not an enrolled device filed in this scope", now);
            return null;
        }
        string? boundOwner;
        lock (_gate) boundOwner = BoundOwnerLocked(owner.ScopeId, filedPhone.DeviceId);
        if (boundOwner is null || !string.Equals(boundOwner, owner.Id, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("camera_share_ai_grant_refused", owner.Id,
                $"scope={scopeId} ai={ai.Id} phone={filedPhone.DeviceId} reason=grantor is not the phone's bound owner — a grant is minted by the phone owner, and ownership is a recorded binding, not a caller claim", now);
            return null;
        }
        if (ttl <= TimeSpan.Zero)
        {
            _audit.Append("camera_share_ai_grant_refused", owner.Id,
                $"scope={scopeId} ai={ai.Id} phone={phoneDeviceId} reason=grant TTL must be positive", now);
            return null;
        }
        var effectiveTtl = ttl <= AbsoluteMaxDuration ? ttl : AbsoluteMaxDuration;
        var grant = new AiCameraShareGrant(Guid.NewGuid().ToString("N"), owner.ScopeId,
            owner.Id, ai.Id, phoneDeviceId, now, now + effectiveTtl, false);
        lock (_gate) _aiGrants[grant.Id] = grant;
        _audit.Append("camera_share_ai_granted", owner.Id,
            $"grant={grant.Id} scope={grant.ScopeId} ai={ai.Id} phone={phoneDeviceId} expiresUtc={grant.ExpiresUtc:O} ttlMinutes={(long)effectiveTtl.TotalMinutes}", now);
        Changed?.Invoke();
        return grant;
    }

    /// <summary>Revoke an AI-watcher grant (grantor or company
    /// admin). Revocation is immediate and also ends any LIVE share
    /// that AI is currently watching — a revoked watcher does not
    /// finish the share it is in.</summary>
    public bool RevokeAiGrant(string grantId, string actorUserId)
    {
        var now = _now();
        AiCameraShareGrant? grant;
        lock (_gate) _aiGrants.TryGetValue(grantId ?? "", out grant);
        if (grant is null || grant.Revoked)
        {
            // D38 F10: EVERY refusal lands in the ledger — an
            // unknown or already-revoked grant id is a refusal,
            // not a silent false.
            _audit.Append("camera_share_ai_grant_refused", actorUserId ?? "unknown",
                $"grant={grantId} reason={(grant is null ? "no grant with this id" : "grant is already revoked")}", now);
            return false;
        }
        var isGrantor = string.Equals(grant.OwnerUserId, actorUserId, StringComparison.OrdinalIgnoreCase);
        if (!isGrantor && !_roster.IsCompanyAdmin(grant.ScopeId, actorUserId ?? ""))
            return RefuseAct("camera_share_ai_grant_refused", "", actorUserId ?? "",
                "revoke actor is neither the grantor nor a company admin", now);
        lock (_gate) _aiGrants[grant.Id] = grant with { Revoked = true };
        _audit.Append("camera_share_ai_grant_revoked", actorUserId,
            $"grant={grant.Id} scope={grant.ScopeId} ai={grant.AiUserId} phone={grant.PhoneDeviceId}", now);
        // End any live share THIS grant was carrying (D38 F10): a
        // share is carried by the grant recorded on it at
        // initiation — revoking one grant must not end a share a
        // different, still-live grant (even for the same AI and
        // phone) is carrying. Imported records that predate the
        // grant id fall back to the full (owner, AI, phone) tuple.
        lock (_gate)
        {
            var live = _shares.Values
                .Where(s => s.IsLive && s.WatcherKind == "ai" &&
                            (string.Equals(s.AiGrantId, grant.Id, StringComparison.OrdinalIgnoreCase) ||
                             (s.AiGrantId is null &&
                              string.Equals(s.OwnerUserId, grant.OwnerUserId, StringComparison.OrdinalIgnoreCase) &&
                              string.Equals(s.WatcherUserId, grant.AiUserId, StringComparison.OrdinalIgnoreCase) &&
                              string.Equals(s.PhoneDeviceId, grant.PhoneDeviceId, StringComparison.OrdinalIgnoreCase))))
                .ToList();
            foreach (var share in live)
                EndLocked(share, actorUserId, CameraShareEndReasons.ParticipantRemoved, now);
        }
        Changed?.Invoke();
        return true;
    }

    public IReadOnlyList<AiCameraShareGrant> ListAiGrants(string? scopeId = null)
    {
        lock (_gate) return _aiGrants.Values
            .Where(g => scopeId is null || string.Equals(g.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(g => g.GrantedUtc).ToList();
    }

    private AiCameraShareGrant? LiveGrantFor(string scopeId, string ownerUserId, string aiUserId,
        string phoneDeviceId, DateTimeOffset now)
    {
        lock (_gate) return _aiGrants.Values.FirstOrDefault(g =>
            g.IsLiveAt(now) &&
            string.Equals(g.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(g.OwnerUserId, ownerUserId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(g.AiUserId, aiUserId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(g.PhoneDeviceId, phoneDeviceId, StringComparison.OrdinalIgnoreCase));
    }

    // ---- initiation: the phone owner, and only the phone owner -------------------

    /// <summary>Start a camera share. THE creation path, and the
    /// only one: the actor is the phone owner (a live HUMAN user of
    /// the scope — an AI cannot own a phone camera consent), the
    /// phone is an enrolled device filed in this scope, and the
    /// watcher is ONE named, live user of the same scope. A human
    /// watcher needs nothing further — being named by the owner IS
    /// the consent scope. An AI watcher additionally needs a live
    /// AiCameraShareGrant for exactly (owner, AI, phone). Policy
    /// (rmm.camera_share.enabled) is consulted against the phone's
    /// facts. One live share per phone: a second initiation while
    /// one is live refuses (the owner ends the first, or it ends —
    /// two watchers on one camera is a different consent than the
    /// one that was given).</summary>
    public CameraShareStartResult InitiateShare(string scopeId, string ownerUserId, string phoneDeviceId, string watcherUserId)
    {
        var now = _now();
        if (_roster.GetScope(scopeId) is not { } scope)
            return Refuse(scopeId ?? "", ownerUserId ?? "", watcherUserId ?? "", phoneDeviceId ?? "", "unknown scope — refused", now);
        var owner = _roster.GetUser(scope.Id, ownerUserId);
        if (owner is null || owner.Suspended)
            return Refuse(scope.Id, ownerUserId ?? "", watcherUserId ?? "", phoneDeviceId ?? "", "owner is not a live user of the scope — refused", now);
        if (owner.Kind != "human")
            return Refuse(scope.Id, owner.Id, watcherUserId ?? "", phoneDeviceId ?? "", "the camera side must be a human phone owner — an AI cannot initiate or consent to a camera share", now);
        var device = FiledDevice(scope.Id, phoneDeviceId);
        if (device is null)
            return Refuse(scope.Id, owner.Id, watcherUserId ?? "", phoneDeviceId ?? "", "phone is not an enrolled device filed in this scope — refused", now);
        // D38 F1: the caller must BE this phone's bound owner. Any
        // other live human of the scope — a tech, a peer — starting
        // a share on someone else's phone is refused here, however
        // well authenticated they are: authentication proves who
        // the caller is, the binding proves the phone is theirs.
        string? boundOwner;
        lock (_gate) boundOwner = BoundOwnerLocked(scope.Id, device.DeviceId);
        if (boundOwner is null)
            return Refuse(scope.Id, owner.Id, watcherUserId ?? "", device.DeviceId,
                "this phone is not bound to an owner — a phone must be bound to its owner (BindPhoneOwner) before it can share — refused", now);
        if (!string.Equals(boundOwner, owner.Id, StringComparison.OrdinalIgnoreCase))
            return Refuse(scope.Id, owner.Id, watcherUserId ?? "", device.DeviceId,
                "the caller is not this phone's bound owner — only the phone's owner can start a share on it — refused", now);
        var watcher = _roster.GetUser(scope.Id, watcherUserId);
        if (watcher is null || watcher.Suspended)
            return Refuse(scope.Id, owner.Id, watcherUserId ?? "", device.DeviceId, "named watcher is not a live user of the scope — refused", now);
        if (string.Equals(watcher.Id, owner.Id, StringComparison.OrdinalIgnoreCase))
            return Refuse(scope.Id, owner.Id, watcher.Id, device.DeviceId, "owner cannot name themselves as watcher — refused", now);
        if (!_policy.IsEnabled(FactsFor(scope.Id, device), CameraSharePolicyKeys.Enabled))
            return Refuse(scope.Id, owner.Id, watcher.Id, device.DeviceId,
                $"camera-share sessions are disabled by policy ({CameraSharePolicyKeys.Enabled}) — refused", now);
        string? aiGrantId = null;
        if (watcher.Kind == "ai")
        {
            var grant = LiveGrantFor(scope.Id, owner.Id, watcher.Id, device.DeviceId, now);
            if (grant is null)
                return Refuse(scope.Id, owner.Id, watcher.Id, device.DeviceId,
                    "AI watcher has no live explicit camera-share grant for this owner and phone — refused (default denied; a grant is minted by the phone owner, never assumed)", now);
            aiGrantId = grant.Id;
        }
        else if (watcher.Kind != "human")
        {
            return Refuse(scope.Id, owner.Id, watcher.Id, device.DeviceId, $"watcher kind '{watcher.Kind}' cannot watch a camera share — refused", now);
        }

        var shareId = Guid.NewGuid().ToString("N");
        // D38 F2: the one-live-share check, the audit append, the
        // sink open and the insert happen under ONE lock hold.
        // The earlier shape checked under the lock, released it,
        // and inserted later without re-checking — two concurrent
        // initiations for the same phone both passed and created
        // two live shares (two watchers on one camera, exactly
        // what this rule refuses). Audit stays FIRST inside the
        // hold: the start entry is chained before the stream layer
        // is touched, so no failure ordering yields an unaudited
        // live share; a sink that refuses OR THROWS (D38 F7)
        // leaves started+failed entries and no share.
        CameraShareSession share;
        lock (_gate)
        {
            if (_shares.Values.Any(s => s.IsLive &&
                    string.Equals(s.PhoneDeviceId, device.DeviceId, StringComparison.OrdinalIgnoreCase)))
                return Refuse(scope.Id, owner.Id, watcher.Id, device.DeviceId,
                    "this phone already has a live camera share — end it before starting another (one share, one named watcher)", now);
            _audit.Append("camera_share_started", owner.Id,
                $"share={shareId} scope={scope.Id} phone={device.DeviceId} watcher={watcher.Id} watcherKind={watcher.Kind} aiGrant={aiGrantId ?? "none"} voice=false", now);
            bool opened;
            string detail;
            try { (opened, detail) = _sink.OpenShare(shareId, watcher.Id); }
            catch (Exception ex) { opened = false; detail = $"stream layer threw {ex.GetType().Name}: {ex.Message}"; }
            if (!opened)
            {
                _audit.Append("camera_share_failed", owner.Id,
                    $"share={shareId} phone={device.DeviceId} watcher={watcher.Id} reason=stream layer refused: {detail}", now);
                return new CameraShareStartResult(false, null, $"stream layer refused: {detail}");
            }
            share = new CameraShareSession(shareId, scope.Id, device.DeviceId, owner.Id, watcher.Id,
                watcher.Kind, CameraShareStates.Waiting, now, null, null, null, false, false, 0, 0, aiGrantId);
            _shares[shareId] = share;
        }
        Changed?.Invoke();
        return new CameraShareStartResult(true, share, "camera share started; presence is live on the phone naming the watcher");
    }

    /// <summary>THE REMOTE-START REFUSAL, as a named surface: any
    /// attempt to start a share from the watcher side — the shape a
    /// compromised operator client or hub would use — refuses and
    /// audits. It exists as a method (rather than merely not
    /// existing) so the refusal is testable and the audit trail
    /// records the attempt; it can NEVER create a share.</summary>
    public CameraShareStartResult RequestShareFromWatcher(string scopeId, string watcherUserId, string phoneDeviceId, string ownerUserId)
    {
        var now = _now();
        _audit.Append("camera_share_remote_start_refused", watcherUserId ?? "unknown",
            $"scope={scopeId} phone={phoneDeviceId} owner={ownerUserId} reason=a camera share can only be started by the phone owner on the phone — watcher-initiated start refused", now);
        return new CameraShareStartResult(false, null,
            "a camera share can only be started by the phone owner on the phone — watcher-initiated start refused");
    }

    // ---- watcher join -------------------------------------------------------------

    /// <summary>The named watcher joins. ONLY the exact user named
    /// at initiation can join — any other identity (including the
    /// owner, including an admin, including a second AI with its
    /// own grant) refuses and audits. Joining is what turns
    /// presence from "waiting" to "X is watching".</summary>
    public bool WatcherJoin(string shareId, string watcherUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_join_refused", shareId ?? "", watcherUserId ?? "", "no live share with this id", now);
            if (share.State != CameraShareStates.Waiting)
                return RefuseAct("camera_share_join_refused", share.Id, watcherUserId ?? "", "watcher has already joined this share", now);
            if (!string.Equals(share.WatcherUserId, watcherUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_join_refused", share.Id, watcherUserId ?? "",
                    "only the watcher named by the phone owner at initiation can join — substitution refused", now);
            var watcher = _roster.GetUser(share.ScopeId, share.WatcherUserId);
            if (watcher is null || watcher.Suspended)
            {
                EndLocked(share, share.OwnerUserId, CameraShareEndReasons.ParticipantRemoved, now);
                return false;
            }
            if (watcher.Kind == "ai" && LiveGrantFor(share.ScopeId, share.OwnerUserId, watcher.Id, share.PhoneDeviceId, now) is null)
            {
                EndLocked(share, share.OwnerUserId, CameraShareEndReasons.ParticipantRemoved, now);
                return RefuseAct("camera_share_join_refused", share.Id, watcherUserId ?? "",
                    "the AI watcher's grant is no longer live — share ended rather than watched ungranted", now);
            }
            var joined = share with { State = CameraShareStates.Sharing, WatcherJoinedUtc = now };
            _shares[share.Id] = joined;
            _audit.Append("camera_share_watcher_joined", watcher.Id,
                $"share={share.Id} phone={share.PhoneDeviceId} owner={share.OwnerUserId}", now);
            Changed?.Invoke();
            return true;
        }
    }

    // ---- the stream: one-way frames, validated, never stored -----------------------

    /// <summary>Submit one camera frame envelope (Block D ACPF).
    /// Sender must be the phone owner; the share must be in
    /// "sharing" (a joined watcher exists to receive it); the
    /// envelope must pass StreamProtocol — the same parser that
    /// guards every ACP stream. On success the envelope is handed
    /// to the sink and DISCARDED: the service increments a counter
    /// and keeps no bytes. Frames from the watcher (reverse flow),
    /// frames after STOP/end, and malformed envelopes all refuse.</summary>
    public bool SubmitFrame(string shareId, string senderUserId, byte[]? envelope)
    {
        var now = _now();
        CameraShareSession share;
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var found) || !found.IsLive)
                return RefuseFrame(shareId ?? "", senderUserId ?? "", "no live share with this id — frame dropped", now);
            share = found;
            if (!string.Equals(share.OwnerUserId, senderUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseFrame(share.Id, senderUserId ?? "",
                    "frames flow phone → watcher only; the sender is not the phone owner — frame dropped", now);
            if (share.State != CameraShareStates.Sharing)
                return RefuseFrame(share.Id, senderUserId,
                    "the named watcher has not joined — frames have no consented recipient and are dropped, never buffered", now);
            if (envelope is null || StreamProtocol.TryParse(envelope) is null)
                return RefuseFrame(share.Id, senderUserId,
                    "envelope failed the stream protocol gate — frame dropped", now);
            // D38 F8: act-time revalidation — a watcher suspended
            // (or a policy flipped) since the last act does not
            // receive one more frame while the host waits for Tick.
            if (ActTimeEndCauseLocked(share, now) is { } cause)
            {
                EndLocked(share, "camera-share-service", cause, now);
                Changed?.Invoke();
                return RefuseFrame(share.Id, senderUserId,
                    $"the share ended at act time (cause={cause}) — frame dropped", now);
            }
        }
        // D38 F4: delivery happens OUTSIDE the gate. A slow or
        // blocking network sink must never stall the owner's STOP
        // (or any other act) behind a frame; the earlier shape
        // delivered — and fired Changed, which the host answers
        // with a full store persist — inside the lock at frame
        // rate. Changed is therefore also NOT fired per frame: the
        // frame/annotation counts are telemetry that persist with
        // the next durable mutation, not a per-frame store write.
        try { _sink.DeliverFrame(share.Id, envelope!); }
        catch (Exception ex)
        {
            _audit.Append("camera_share_frame_refused", senderUserId,
                $"share={share.Id} reason=stream sink threw on delivery ({ex.GetType().Name}) — frame dropped", now);
            return false;
        }
        lock (_gate)
        {
            if (_shares.TryGetValue(share.Id, out var current) && current.IsLive)
                _shares[share.Id] = current with { FramesForwarded = current.FramesForwarded + 1 };
        }
        return true;
    }

    /// <summary>The watcher's annotation pointer (the "point at
    /// that bolt" half of the directive): transient coordinates
    /// forwarded to the phone's overlay, counted, never stored as
    /// content. Watcher-only, sharing-only, bounded coordinates.</summary>
    public bool SendAnnotation(string shareId, string watcherUserId, int x, int y)
    {
        var now = _now();
        CameraShareSession share;
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var found) || found.State != CameraShareStates.Sharing)
                return RefuseAct("camera_share_annotation_refused", shareId ?? "", watcherUserId ?? "", "no sharing camera share with this id", now);
            share = found;
            if (!string.Equals(share.WatcherUserId, watcherUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_annotation_refused", share.Id, watcherUserId ?? "", "only the named watcher annotates", now);
            if (x is < 0 or > 1000 || y is < 0 or > 1000)
                return RefuseAct("camera_share_annotation_refused", share.Id, watcherUserId, "annotation coordinates out of bounds (0..1000 normalized)", now);
            // D38 F8: act-time revalidation, as in SubmitFrame.
            if (ActTimeEndCauseLocked(share, now) is { } cause)
            {
                EndLocked(share, "camera-share-service", cause, now);
                Changed?.Invoke();
                return RefuseAct("camera_share_annotation_refused", share.Id, watcherUserId,
                    $"the share ended at act time (cause={cause}) — annotation dropped", now);
            }
        }
        // D38 F4: delivery outside the gate, no per-annotation
        // Changed — same reasoning as SubmitFrame.
        try { _sink.DeliverAnnotation(share.Id, x, y); }
        catch (Exception ex)
        {
            _audit.Append("camera_share_annotation_refused", watcherUserId,
                $"share={share.Id} reason=stream sink threw on delivery ({ex.GetType().Name}) — annotation dropped", now);
            return false;
        }
        lock (_gate)
        {
            if (_shares.TryGetValue(share.Id, out var current) && current.IsLive)
                _shares[share.Id] = current with { AnnotationsForwarded = current.AnnotationsForwarded + 1 };
        }
        return true;
    }

    // ---- owner-controlled toggles: voice + torch ------------------------------------

    /// <summary>Set the watcher's voice channel. Default OFF.
    /// ENABLING is the owner's act alone (the person being listened
    /// to decides), and additionally requires the voice policy key
    /// for the phone — the watcher can never enable their own
    /// microphone into someone's site. Disabling is allowed by
    /// owner or watcher (silence is always permitted).</summary>
    public bool SetVoice(string shareId, string actorUserId, bool enabled)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_voice_refused", shareId ?? "", actorUserId ?? "", "no live share with this id", now);
            if (ActTimeEndCauseLocked(share, now) is { } cause)
            {
                EndLocked(share, "camera-share-service", cause, now);
                Changed?.Invoke();
                return RefuseAct("camera_share_voice_refused", share.Id, actorUserId ?? "",
                    $"the share ended at act time (cause={cause})", now);
            }
            if (enabled)
            {
                if (!string.Equals(share.OwnerUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase))
                    return RefuseAct("camera_share_voice_refused", share.Id, actorUserId ?? "",
                        "only the phone owner can enable the watcher's voice channel", now);
                var device = FiledDevice(share.ScopeId, share.PhoneDeviceId);
                if (device is null || !_policy.IsEnabled(FactsFor(share.ScopeId, device), CameraSharePolicyKeys.VoiceEnabled))
                    return RefuseAct("camera_share_voice_refused", share.Id, actorUserId,
                        $"watcher voice is disabled by policy ({CameraSharePolicyKeys.VoiceEnabled}) — it is a separate, default-OFF dimension (REC-06)", now);
                if (share.VoiceEnabled) return true;
                _shares[share.Id] = share with { VoiceEnabled = true };
                _audit.Append("camera_share_voice_enabled", actorUserId,
                    $"share={share.Id} watcher={share.WatcherUserId}", now);
            }
            else
            {
                var isParty = string.Equals(share.OwnerUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(share.WatcherUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase);
                if (!isParty)
                    return RefuseAct("camera_share_voice_refused", share.Id, actorUserId ?? "", "actor is not a party to this share", now);
                if (!share.VoiceEnabled) return true;
                _shares[share.Id] = share with { VoiceEnabled = false };
                _audit.Append("camera_share_voice_disabled", actorUserId,
                    $"share={share.Id} watcher={share.WatcherUserId}", now);
            }
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Set the phone torch. Owner-only: the torch is the
    /// phone owner's hardware; the watcher ASKS (RequestTorch) and
    /// the owner decides.</summary>
    public bool SetTorch(string shareId, string actorUserId, bool enabled)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_torch_refused", shareId ?? "", actorUserId ?? "", "no live share with this id", now);
            if (!string.Equals(share.OwnerUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_torch_refused", share.Id, actorUserId ?? "",
                    "only the phone owner controls the torch — the watcher requests it", now);
            if (ActTimeEndCauseLocked(share, now) is { } cause)
            {
                EndLocked(share, "camera-share-service", cause, now);
                Changed?.Invoke();
                return RefuseAct("camera_share_torch_refused", share.Id, actorUserId ?? "",
                    $"the share ended at act time (cause={cause})", now);
            }
            _shares[share.Id] = share with { TorchEnabled = enabled };
            _audit.Append(enabled ? "camera_share_torch_on" : "camera_share_torch_off", actorUserId,
                $"share={share.Id} watcher={share.WatcherUserId}", now);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>The named watcher asks for the torch. A request is
    /// an audited event and nothing more — it changes no state.</summary>
    public bool RequestTorch(string shareId, string watcherUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_torch_refused", shareId ?? "", watcherUserId ?? "", "no live share with this id", now);
            if (!string.Equals(share.WatcherUserId, watcherUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_torch_refused", share.Id, watcherUserId ?? "", "only the named watcher can request the torch", now);
            _audit.Append("camera_share_torch_requested", watcherUserId,
                $"share={share.Id} owner={share.OwnerUserId}", now);
            return true;
        }
    }

    // ---- the acts that must always refuse --------------------------------------------

    /// <summary>Watcher substitution mid-share ALWAYS refuses: the
    /// consent named one watcher, so a different watcher is a new
    /// consent and a new share. The owner ends this share and
    /// initiates another; there is no reassign path.</summary>
    public bool ReassignWatcher(string shareId, string actorUserId, string newWatcherUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share))
                return RefuseAct("camera_share_reassign_refused", shareId ?? "", actorUserId ?? "", "no share with this id", now);
            return RefuseAct("camera_share_reassign_refused", share.Id, actorUserId ?? "",
                $"watcher substitution refused: consent named '{share.WatcherUserId}'; a different watcher ({newWatcherUserId}) requires ending this share and initiating a new one", now);
        }
    }

    /// <summary>Recording a camera share is NOT part of this
    /// feature (REC cluster: recording is a separate explicit act
    /// with its own consent artefacts). Any attempt to enable
    /// recording on a share refuses and audits — silent recording
    /// is structurally absent (no frame store exists), and this
    /// named refusal keeps the attempt visible.</summary>
    public bool TryEnableRecording(string shareId, string actorUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share))
                return RefuseAct("camera_share_recording_refused", shareId ?? "", actorUserId ?? "", "no share with this id", now);
            return RefuseAct("camera_share_recording_refused", share.Id, actorUserId ?? "",
                "camera shares are live-only; recording is a separate explicit act under the REC rules and is not part of a camera share", now);
        }
    }

    /// <summary>Scope-creep gate: a camera share authorizes exactly
    /// one purpose — "camera_view" — for exactly its two parties,
    /// while live. Any attempt to spend the share on another
    /// purpose (a full session, file transfer, a second device)
    /// refuses and audits. Returns true only for the one purpose.</summary>
    public bool AuthorizeUse(string shareId, string actorUserId, string purpose)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_use_refused", shareId ?? "", actorUserId ?? "", $"purpose={purpose} no live share with this id", now);
            var isParty = string.Equals(share.OwnerUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase) ||
                          string.Equals(share.WatcherUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase);
            if (!isParty)
                return RefuseAct("camera_share_use_refused", share.Id, actorUserId ?? "", $"purpose={purpose} actor is not a party to this share", now);
            if (!string.Equals(purpose, "camera_view", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_use_refused", share.Id, actorUserId ?? "",
                    $"purpose={purpose} a camera-share grant covers camera viewing only — it opens no session, no file channel, no second device", now);
            // D38 F11: "camera viewing" exists only once the watcher
            // has JOINED. A share still in Waiting authorizes
            // nothing — there is no view yet to spend.
            if (share.State != CameraShareStates.Sharing)
                return RefuseAct("camera_share_use_refused", share.Id, actorUserId ?? "",
                    $"purpose={purpose} the watcher has not joined — there is no camera view to authorize yet", now);
            return true;
        }
    }

    // ---- lifecycle ends -----------------------------------------------------------------

    /// <summary>STOP — the phone owner's act, from any live state,
    /// effective in this call: the record ends, the sink closes,
    /// and any frame submitted afterwards refuses. No other actor
    /// can STOP (the watcher leaving is WatcherDisconnect; an admin
    /// has no off switch for someone else's camera consent — the
    /// floor is the floor).</summary>
    public bool StopShare(string shareId, string actorUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_stop_refused", shareId ?? "", actorUserId ?? "", "no live share with this id", now);
            if (!string.Equals(share.OwnerUserId, actorUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_stop_refused", share.Id, actorUserId ?? "",
                    "STOP belongs to the phone owner — only the owner ends a share by STOP", now);
            EndLocked(share, actorUserId, CameraShareEndReasons.OwnerStop, now);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>The named watcher disconnects: the share ends —
    /// a camera share with no watcher is over, never parked open
    /// waiting for a reconnect under the old consent.</summary>
    public bool WatcherDisconnect(string shareId, string watcherUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_disconnect_refused", shareId ?? "", watcherUserId ?? "", "no live share with this id", now);
            if (!string.Equals(share.WatcherUserId, watcherUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_disconnect_refused", share.Id, watcherUserId ?? "", "only the named watcher can disconnect as the watcher", now);
            EndLocked(share, watcherUserId, CameraShareEndReasons.WatcherDisconnect, now);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>The phone owner navigated away from the share
    /// surface: the share ends. Presence honesty — a share the
    /// owner is no longer looking at does not keep streaming.</summary>
    public bool OwnerNavigatedAway(string shareId, string ownerUserId)
    {
        var now = _now();
        lock (_gate)
        {
            if (!_shares.TryGetValue(shareId ?? "", out var share) || !share.IsLive)
                return RefuseAct("camera_share_end_refused", shareId ?? "", ownerUserId ?? "", "no live share with this id", now);
            if (!string.Equals(share.OwnerUserId, ownerUserId ?? "", StringComparison.OrdinalIgnoreCase))
                return RefuseAct("camera_share_end_refused", share.Id, ownerUserId ?? "", "only the phone owner reports owner navigation", now);
            EndLocked(share, ownerUserId, CameraShareEndReasons.OwnerNavigatedAway, now);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>The standing enforcer, called by the host on a
    /// timer and before acts: ends every live share whose time is
    /// up, whose owner/watcher left the roster (removed/suspended),
    /// whose AI grant died, or whose policy switched off. Returns
    /// the number of shares ended. Every end is audited with its
    /// cause by EndLocked.</summary>
    public int Tick()
    {
        var now = _now();
        var ended = 0;
        var mutated = false;
        lock (_gate)
        {
            foreach (var share in _shares.Values.Where(s => s.IsLive).ToList())
            {
                string? cause = null;
                var owner = _roster.GetUser(share.ScopeId, share.OwnerUserId);
                var watcher = _roster.GetUser(share.ScopeId, share.WatcherUserId);
                if (owner is null || owner.Suspended || watcher is null || watcher.Suspended)
                    cause = CameraShareEndReasons.ParticipantRemoved;
                else if (watcher.Kind == "ai" &&
                         LiveGrantFor(share.ScopeId, share.OwnerUserId, watcher.Id, share.PhoneDeviceId, now) is null)
                    cause = CameraShareEndReasons.ParticipantRemoved;
                else
                {
                    var device = FiledDevice(share.ScopeId, share.PhoneDeviceId);
                    if (device is null) cause = CameraShareEndReasons.ParticipantRemoved;
                    else if (!_policy.IsEnabled(FactsFor(share.ScopeId, device), CameraSharePolicyKeys.Enabled))
                        cause = CameraShareEndReasons.PolicyDisabled;
                    else if (now - share.StartedUtc >= MaxDurationFor(FactsFor(share.ScopeId, device)))
                        cause = CameraShareEndReasons.Timeout;
                }
                if (cause is not null)
                {
                    EndLocked(share, "camera-share-service", cause, now);
                    ended++;
                }
                else if (share.VoiceEnabled)
                {
                    // D38 F8: voice is policy-gated for the share's
                    // whole life, not only at enable time — turning
                    // the voice key off mid-share turns the channel
                    // OFF (the share itself continues; voice was
                    // always a separate, revocable dimension).
                    var device = FiledDevice(share.ScopeId, share.PhoneDeviceId);
                    if (device is null || !_policy.IsEnabled(FactsFor(share.ScopeId, device), CameraSharePolicyKeys.VoiceEnabled))
                    {
                        _shares[share.Id] = share with { VoiceEnabled = false };
                        _audit.Append("camera_share_voice_disabled", "camera-share-service",
                            $"share={share.Id} watcher={share.WatcherUserId} reason=voice policy no longer permits the channel — voice turned off, the share continues", now);
                        mutated = true;
                    }
                }
            }
            // D38 F9: prune ended shares past retention — the
            // ledger is the permanent record; the store is not.
            var cutoff = now - EndedShareRetention;
            foreach (var stale in _shares.Values
                         .Where(s => !s.IsLive && s.EndedUtc is { } e && e < cutoff).ToList())
            {
                _shares.Remove(stale.Id);
                foreach (var key in _frameRefusals.Keys
                             .Where(k => k.StartsWith(stale.Id + "\u001f", StringComparison.OrdinalIgnoreCase)).ToList())
                    _frameRefusals.Remove(key);
                mutated = true;
            }
        }
        if (ended > 0 || mutated) Changed?.Invoke();
        return ended;
    }

    /// <summary>Terminal transition. Caller MUST hold the gate
    /// (every caller does — including RevokeAiGrant's sweep, which
    /// takes the gate before sweeping). EndLocked takes no lock of
    /// its own; it mutates the dictionaries directly. The order is
    /// fixed and deliberate (D38 F7): (1) the record ends, (2) the
    /// camera_share_ended entry is chained, (3) the sink close is
    /// attempted inside a guard. A sink whose CloseShare THROWS
    /// therefore cannot leave an ended share with no audit entry,
    /// and cannot abort the caller's loop (e.g. Tick) halfway: the
    /// close failure itself is chained as
    /// camera_share_sink_close_failed and the end stands.</summary>
    private void EndLocked(CameraShareSession share, string actorUserId, string reason, DateTimeOffset now)
    {
        var current = _shares.TryGetValue(share.Id, out var s) ? s : share;
        if (!current.IsLive) return;
        var endedShare = current with
        {
            State = CameraShareStates.Ended,
            EndedUtc = now,
            EndReason = reason,
            VoiceEnabled = false,
            TorchEnabled = false,
        };
        _shares[share.Id] = endedShare;
        _audit.Append("camera_share_ended", actorUserId,
            $"share={share.Id} scope={current.ScopeId} phone={current.PhoneDeviceId} watcher={current.WatcherUserId} cause={reason} durationSeconds={(long)(now - current.StartedUtc).TotalSeconds} frames={current.FramesForwarded}", now);
        try { _sink.CloseShare(share.Id, reason); }
        catch (Exception ex)
        {
            _audit.Append("camera_share_sink_close_failed", actorUserId,
                $"share={share.Id} cause={reason} error={ex.GetType().Name}: {ex.Message} — the share is ended and audited; the stream layer failed to confirm its close", now);
        }
    }

    // ---- reads + presence -----------------------------------------------------------------

    public CameraShareSession? GetShare(string? shareId)
    {
        if (string.IsNullOrWhiteSpace(shareId)) return null;
        lock (_gate) return _shares.TryGetValue(shareId, out var s) ? s : null;
    }

    /// <summary>Shares of ONE scope only (D8 scope isolation);
    /// null scope lists all (operator-side store read).</summary>
    public IReadOnlyList<CameraShareSession> ListShares(string? scopeId = null)
    {
        lock (_gate) return _shares.Values
            .Where(s => scopeId is null || string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .OrderBy(s => s.StartedUtc).ToList();
    }

    /// <summary>The presence contract for the phone surface,
    /// derived from the record alone. Null for an unknown share;
    /// an ended share still derives (state "ended", STOP no longer
    /// offered because there is nothing left to stop — StopAvailable
    /// is true exactly while the share is live).</summary>
    public CameraSharePresence? GetPresence(string? shareId)
    {
        var share = GetShare(shareId);
        if (share is null) return null;
        var watcher = _roster.GetUser(share.ScopeId, share.WatcherUserId);
        var name = watcher is not null && !string.IsNullOrWhiteSpace(watcher.DisplayName)
            ? watcher.DisplayName.Trim() : share.WatcherUserId;
        var banner = share.State switch
        {
            CameraShareStates.Sharing => $"{name} is watching your camera",
            CameraShareStates.Waiting => $"Waiting for {name} to join your camera share",
            _ => "Camera share ended",
        };
        return new CameraSharePresence(share.Id, share.WatcherUserId, name, share.State,
            share.IsBeingWatched, share.VoiceEnabled, share.TorchEnabled, share.StartedUtc,
            StopAvailable: share.IsLive, IsRecording: false, BannerText: banner);
    }

    // ---- persistence -------------------------------------------------------------------------

    private sealed record ShareDto(string Id, string ScopeId, string PhoneDeviceId, string OwnerUserId,
        string WatcherUserId, string WatcherKind, string State, DateTimeOffset StartedUtc,
        DateTimeOffset? WatcherJoinedUtc, DateTimeOffset? EndedUtc, string? EndReason,
        bool VoiceEnabled, bool TorchEnabled, long FramesForwarded, long AnnotationsForwarded,
        string? AiGrantId = null);

    private sealed record GrantDto(string Id, string ScopeId, string OwnerUserId, string AiUserId,
        string PhoneDeviceId, DateTimeOffset GrantedUtc, DateTimeOffset ExpiresUtc, bool Revoked);

    private sealed record BindingDto(string ScopeId, string PhoneDeviceId, string OwnerUserId);

    private sealed record StoreDto(List<ShareDto> Shares, List<GrantDto> Grants,
        List<BindingDto>? Bindings = null);

    /// <summary>Export the store. Carries NO media — there is none
    /// to carry; frames were never stored.</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var dto = new StoreDto(
                _shares.Values.Select(s => new ShareDto(s.Id, s.ScopeId, s.PhoneDeviceId, s.OwnerUserId,
                    s.WatcherUserId, s.WatcherKind, s.State, s.StartedUtc, s.WatcherJoinedUtc, s.EndedUtc,
                    s.EndReason, s.VoiceEnabled, s.TorchEnabled, s.FramesForwarded, s.AnnotationsForwarded,
                    s.AiGrantId)).ToList(),
                _aiGrants.Values.Select(g => new GrantDto(g.Id, g.ScopeId, g.OwnerUserId, g.AiUserId,
                    g.PhoneDeviceId, g.GrantedUtc, g.ExpiresUtc, g.Revoked)).ToList(),
                _phoneOwners.Select(kv => new BindingDto(
                    kv.Key.Split('\u001f')[0], kv.Key.Split('\u001f')[1], kv.Value)).ToList());
            return JsonSerializer.Serialize(dto);
        }
    }

    /// <summary>Import a store. Malformed entries are skipped,
    /// never fatal. A share that was live in the export imports
    /// ENDED with reason import_repair: consent was given to a
    /// share in a previous process lifetime, and a restored record
    /// must never silently resume a camera — the owner starts a
    /// new share. The repair is audited. Grants are restored under
    /// the same rules that mint them (D38 F6): the TTL ceiling is
    /// applied, a grant this process already holds is never
    /// overwritten (an import can add a revocation, never remove
    /// one), every restored grant is audited, and an imported
    /// share whose id matches a live in-memory share ends that
    /// share properly (sink closed, end chained) rather than
    /// overwriting it. Returns entries restored.</summary>
    public int ImportJson(string json)
    {
        StoreDto? dto;
        try { dto = JsonSerializer.Deserialize<StoreDto>(json ?? ""); }
        catch { return 0; }
        if (dto is null) return 0;
        var now = _now();
        var restored = 0;
        lock (_gate)
        {
            foreach (var b in dto.Bindings ?? new List<BindingDto>())
            {
                if (string.IsNullOrWhiteSpace(b.ScopeId) || string.IsNullOrWhiteSpace(b.PhoneDeviceId) ||
                    string.IsNullOrWhiteSpace(b.OwnerUserId)) continue;
                // An import never rebinds a phone this process has
                // already bound — bindings are only added.
                var key = BindingKey(b.ScopeId, b.PhoneDeviceId);
                if (_phoneOwners.ContainsKey(key)) continue;
                _phoneOwners[key] = b.OwnerUserId;
                restored++;
            }
            foreach (var g in dto.Grants ?? new List<GrantDto>())
            {
                // D38 F6: imported grants are validated, clamped,
                // audited — and never overwrite a grant this
                // process already holds.
                if (string.IsNullOrWhiteSpace(g.Id) || string.IsNullOrWhiteSpace(g.AiUserId) ||
                    string.IsNullOrWhiteSpace(g.OwnerUserId) || string.IsNullOrWhiteSpace(g.ScopeId) ||
                    string.IsNullOrWhiteSpace(g.PhoneDeviceId)) continue;
                if (string.Equals(g.OwnerUserId, g.AiUserId, StringComparison.OrdinalIgnoreCase)) continue;
                var expires = g.ExpiresUtc;
                var maxExpiry = g.GrantedUtc + AbsoluteMaxDuration;
                if (expires > maxExpiry) expires = maxExpiry; // the TTL ceiling holds on import too
                if (expires <= g.GrantedUtc) continue;        // no positive TTL: not a grant
                if (_aiGrants.TryGetValue(g.Id, out var existing))
                {
                    // The one change an import may make to a held
                    // grant is ADDING a revocation — a stale or
                    // tampered store can never un-revoke one.
                    if (g.Revoked && !existing.Revoked)
                    {
                        _aiGrants[g.Id] = existing with { Revoked = true };
                        restored++;
                    }
                    continue;
                }
                _aiGrants[g.Id] = new AiCameraShareGrant(g.Id, g.ScopeId, g.OwnerUserId, g.AiUserId,
                    g.PhoneDeviceId, g.GrantedUtc, expires, g.Revoked);
                _audit.Append("camera_share_ai_grant_restored", g.OwnerUserId,
                    $"grant={g.Id} scope={g.ScopeId} ai={g.AiUserId} phone={g.PhoneDeviceId} expiresUtc={expires:O} revoked={g.Revoked}", now);
                restored++;
            }
            foreach (var s in dto.Shares ?? new List<ShareDto>())
            {
                if (string.IsNullOrWhiteSpace(s.Id) || !CameraShareStates.All.Contains(s.State)) continue;
                var share = new CameraShareSession(s.Id, s.ScopeId, s.PhoneDeviceId, s.OwnerUserId,
                    s.WatcherUserId, s.WatcherKind, s.State, s.StartedUtc, s.WatcherJoinedUtc, s.EndedUtc,
                    s.EndReason, s.VoiceEnabled, s.TorchEnabled, s.FramesForwarded, s.AnnotationsForwarded,
                    s.AiGrantId);
                // D38 F6: if this id is a LIVE share in memory, end
                // it properly first (sink closed, end chained) —
                // overwriting it with the imported record would
                // leave an open stream behind an ended record.
                if (_shares.TryGetValue(share.Id, out var current) && current.IsLive)
                    EndLocked(current, "camera-share-service", CameraShareEndReasons.ImportRepair, now);
                if (share.IsLive)
                {
                    share = share with
                    {
                        State = CameraShareStates.Ended,
                        EndedUtc = now,
                        EndReason = CameraShareEndReasons.ImportRepair,
                        VoiceEnabled = false,
                        TorchEnabled = false,
                    };
                    _audit.Append("camera_share_ended", "camera-share-service",
                        $"share={share.Id} scope={share.ScopeId} phone={share.PhoneDeviceId} watcher={share.WatcherUserId} cause={CameraShareEndReasons.ImportRepair} durationSeconds={(long)(now - share.StartedUtc).TotalSeconds} frames={share.FramesForwarded}", now);
                }
                _shares[share.Id] = share;
                restored++;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

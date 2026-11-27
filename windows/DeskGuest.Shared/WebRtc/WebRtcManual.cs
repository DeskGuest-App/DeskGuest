using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Shared.WebRtc;

// =====================================================================
// Manual WebRTC rung — the DeskGuest side (Block F, D28/D29). Manual BY
// DESIGN: the exchanged codes ARE the setup. This service builds
// and verifies the signaling codes and binds the exchange to a
// Slice 3 session; it carries NO media.
//
// AUDIT STATUS, stated plainly (D37/T7): the WebRTC stack (the
// library that would carry media for this rung) is UNAUDITED in
// the audit universe. Until its D37 audit runs, DeskGuest does not adopt
// a WebRTC library, so this rung's media leg is NOT BUILT and is
// labeled so everywhere it surfaces: signaling + session binding
// are built and proven; media is `media_unavailable_t7_unaudited`,
// never silently adopted and never faked.
// =====================================================================

public sealed record WebRtcCode(
    int Version, string Kind, string SessionId, string DeviceId,
    string Nonce, string SdpSha256, DateTimeOffset ExpiresUtc);

public static class WebRtcMediaStatus
{
    /// <summary>The one honest label for this rung's media leg.</summary>
    public const string Label = "media_unavailable_t7_unaudited";
    public const string Explanation =
        "Signaling and session binding are built; the WebRTC media stack (audit-universe entry T7) " +
        "is unaudited, and DeskGuest does not ship an unaudited adopted component (D37). No media flows on this rung yet.";
}

public sealed class WebRtcSignaling
{
    public static readonly TimeSpan CodeTtl = TimeSpan.FromMinutes(10);
    private const string Prefix = "DGWR1";
    private readonly EnrollmentService _enrollments;
    private readonly SessionService _sessions;
    private readonly Func<Session, string, bool>? _isSessionPartyDevice;
    // BD-SHARED-TRANSPORT F5: consumed nonces carry their code's
    // expiry and are pruned once expired — the set previously
    // grew without limit. They can be exported/imported so a
    // restart inside the TTL does not reopen the replay window
    // (the host persists them through HubPersistence; the export
    // shape is below).
    private readonly Dictionary<string, DateTimeOffset> _consumedNonces = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <param name="isSessionPartyDevice">BD-SHARED-TRANSPORT F5:
    /// is this device a party to this session? Default: the
    /// session's HOST device only. AcceptCode previously checked
    /// enrollment + liveness but never the device's relation to
    /// the session, so any enrolled device could set up any live
    /// session's WebRTC leg.</param>
    public WebRtcSignaling(EnrollmentService enrollments, SessionService sessions,
        Func<Session, string, bool>? isSessionPartyDevice = null)
    {
        _enrollments = enrollments; _sessions = sessions;
        _isSessionPartyDevice = isSessionPartyDevice ??
            ((session, deviceId) => string.Equals(session.HostDeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Snapshot of consumed nonces (nonce key → expiry)
    /// for host persistence across restarts (F5).</summary>
    public IReadOnlyDictionary<string, DateTimeOffset> ExportConsumedNonces()
    { lock (_gate) return new Dictionary<string, DateTimeOffset>(_consumedNonces); }

    /// <summary>Restore consumed nonces after a restart; expired
    /// entries are dropped, live ones keep their replay refusal.</summary>
    public void ImportConsumedNonces(IReadOnlyDictionary<string, DateTimeOffset> nonces, DateTimeOffset now)
    {
        lock (_gate)
            foreach (var (key, expiry) in nonces)
                if (expiry > now) _consumedNonces[key] = expiry;
    }

    /// <summary>Create a signed code (offer or answer) bound to a
    /// session + this device. The SDP body itself never travels in
    /// the code — only its hash; the peers exchange SDP out of band
    /// alongside the code, and a swapped SDP fails the hash.</summary>
    public string CreateCode(string kind, string sessionId, string sdp, DeviceIdentity identity, DateTimeOffset now)
    {
        if (kind is not ("offer" or "answer")) throw new InvalidOperationException("code kind must be offer|answer");
        var session = _sessions.GetSession(sessionId)
            ?? throw new InvalidOperationException("unknown session — a WebRTC code binds to a live session only");
        if (session.State is "ended") throw new InvalidOperationException("session ended — its codes are dead");
        var payload = new WebRtcCode(1, kind, sessionId, identity.DeviceId,
            Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(sdp ?? ""))).ToLowerInvariant(),
            now + CodeTtl);
        var json = JsonSerializer.Serialize(payload);
        var sig = identity.Sign(Encoding.UTF8.GetBytes(Canonical(json)));
        return $"{Prefix}.{B64Url(Encoding.UTF8.GetBytes(json))}.{B64Url(sig)}";
    }

    /// <summary>Verify a presented code: shape, signature against
    /// the ENROLLED public key of the device it names (a code from
    /// an unenrolled or revoked device refuses), expiry, SDP hash,
    /// session liveness, and single-use of the nonce (a replayed
    /// code refuses — the codes are the setup, so a replay would
    /// be a second setup).</summary>
    public (bool Ok, string Detail, WebRtcCode? Code) AcceptCode(string? code, string presentedSdp, DateTimeOffset now)
    {
        if (code is null) return (false, "no code", null);
        var parts = code.Trim().Split('.');
        if (parts.Length != 3 || parts[0] != Prefix) return (false, "not an DeskGuest WebRTC code", null);
        WebRtcCode? payload;
        byte[] sig;
        try
        {
            payload = JsonSerializer.Deserialize<WebRtcCode>(Encoding.UTF8.GetString(FromB64Url(parts[1])));
            sig = FromB64Url(parts[2]);
        }
        catch { return (false, "code does not decode", null); }
        if (payload is null || payload.Version != 1) return (false, "unsupported code version", null);
        if (now > payload.ExpiresUtc) return (false, "code expired", null);
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, payload.DeviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null || device.Revoked) return (false, "code names an unknown or revoked device", null);
        var json = JsonSerializer.Serialize(payload);
        bool sigOk;
        try { sigOk = Ed25519.Verify(Convert.FromBase64String(device.PublicKeyBase64), Encoding.UTF8.GetBytes(Canonical(json)), sig); }
        catch { sigOk = false; }
        if (!sigOk) return (false, "code signature invalid — refused", null);
        var sdpHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(presentedSdp ?? ""))).ToLowerInvariant();
        if (sdpHash != payload.SdpSha256) return (false, "SDP does not match the code's hash — a swapped SDP refuses", null);
        var session = _sessions.GetSession(payload.SessionId);
        if (session is null || session.State is "ended") return (false, "the session this code binds to is not live", null);
        // BD-SHARED-TRANSPORT F5: the code's device must be a
        // PARTY to the session (its host, or a device the host's
        // resolver names as a participant) — enrollment alone
        // never entitled a device to set up another session's leg.
        if (!_isSessionPartyDevice(session, payload.DeviceId))
            return (false, "code names a device that is not a party to this session — refused", null);
        lock (_gate)
        {
            var dead = _consumedNonces.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();
            foreach (var k in dead) _consumedNonces.Remove(k);
            var nonceKey = payload.DeviceId + "|" + payload.Nonce;
            if (_consumedNonces.ContainsKey(nonceKey))
                return (false, "code replayed — each code sets up once", null);
            _consumedNonces[nonceKey] = payload.ExpiresUtc;
        }
        return (true, $"code accepted ({payload.Kind}); media leg: {WebRtcMediaStatus.Label}", payload);
    }

    private static string Canonical(string json) => "deskguest-webrtc-v1|" + json;
    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] FromB64Url(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
        return Convert.FromBase64String(b64);
    }
}

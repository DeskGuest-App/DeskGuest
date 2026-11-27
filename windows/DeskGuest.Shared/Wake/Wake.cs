using System.Net;
using System.Text.Json;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Shared.Wake;

// =====================================================================
// G-01 — Wake-on-LAN as a SESSION capability (census §3 row; §5
// table stakes; §13 sibling pattern). The pre-programme agent tool
// (WakeOnLanModule) could already throw a magic packet from the
// Windows host; what did not exist is everything that makes it a
// product feature: a governed registry of WHO may be woken (a MAC
// is a network fact about a device, recorded deliberately — never
// guessed, never scanned for), an authorization rule (the Slice 2
// "use" grant on the target's device group — waking a machine is
// an act ON that machine), the session integration (wake the
// target, then connect: the wake is an event on the session it
// precedes), and the policy toggle (TOTAL POLICY CONTROL).
//
// The sibling shape (§13): the sender runs wherever an DeskGuest Core
// sits on the target's LAN — this service is that sibling. A remote
// operator's request reaches the sibling over the mesh; the packet
// itself never leaves the site.
// =====================================================================

/// <summary>The canonical magic packet: 6 × 0xFF + the target MAC
/// repeated 16 times (102 bytes). One builder for the whole
/// product — the agent tool delegates here so the packet shape can
/// never diverge between the tool and the session feature.</summary>
public static class MagicPacket
{
    public const int PacketLength = 102;
    public const int WakePort = 9;

    /// <summary>Strict MAC parse: exactly 6 hex octets, colon- or
    /// dash-separated. Returns the 6 bytes, or null. (The old tool
    /// builder threw on bad input; the registry refuses instead.)</summary>
    public static byte[]? ParseMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;
        var parts = mac.Trim().Split(':', '-');
        if (parts.Length != 6) return null;
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            if (parts[i].Length != 2) return null;
            try { bytes[i] = Convert.ToByte(parts[i], 16); }
            catch { return null; }
        }
        return bytes;
    }

    /// <summary>Canonical text form: uppercase, colon-separated.</summary>
    public static string NormalizeMac(byte[] bytes) =>
        string.Join(":", bytes.Select(b => b.ToString("X2")));

    /// <summary>A wake target is one machine's NIC: the broadcast
    /// address and a multicast address are not wakeable targets.</summary>
    public static bool IsWakeableMac(byte[] bytes) =>
        bytes.Length == 6 &&
        (bytes[0] & 0x01) == 0 &&                       // not multicast (I/G bit clear)
        !bytes.All(b => b == 0xFF) &&                   // not the broadcast address
        !bytes.All(b => b == 0x00);                     // not the zero address

    public static byte[] Build(byte[] macBytes)
    {
        if (macBytes.Length != 6) throw new ArgumentException("MAC must be 6 octets");
        var packet = new byte[PacketLength];
        for (var i = 0; i < 6; i++) packet[i] = 0xFF;
        for (var r = 0; r < 16; r++) Array.Copy(macBytes, 0, packet, 6 + r * 6, 6);
        return packet;
    }

    public static byte[] Build(string mac)
    {
        var bytes = ParseMac(mac) ?? throw new ArgumentException("unparseable MAC address");
        return Build(bytes);
    }
}

/// <summary>The packet's exit door. The production implementation
/// is a UDP broadcast; tests substitute a recorder. The service
/// never touches a socket itself.</summary>
public interface IWakeSender
{
    void Send(byte[] packet, string broadcastAddress, int port);
}

/// <summary>Production sender: one UDP datagram, broadcast enabled.</summary>
public sealed class UdpWakeSender : IWakeSender
{
    public void Send(byte[] packet, string broadcastAddress, int port)
    {
        using var udp = new System.Net.Sockets.UdpClient { EnableBroadcast = true };
        udp.Send(packet, new IPEndPoint(IPAddress.Parse(broadcastAddress), port));
    }
}

/// <summary>A registered wake target: an enrolled device + the MAC
/// of the NIC to wake + the broadcast address of its LAN segment.
/// Registered deliberately (by a company admin, or by the device's
/// own Core over the trusted in-process path); a device with no
/// registered target simply cannot be woken — the feature never
/// invents a MAC.</summary>
public sealed record WakeTarget(
    string DeviceId,
    string MacAddress,
    string BroadcastAddress,
    string? RegisteredByUserId,
    DateTimeOffset RegisteredUtc,
    DateTimeOffset? LastWakeUtc);

public sealed record WakeEvent(
    DateTimeOffset Utc, string Kind, string DeviceId, string? ActorUserId, string Detail);

public sealed class WakeService
{
    private readonly RosterService _roster;
    private readonly EnrollmentService _enrollments;
    private readonly IWakeSender _sender;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly Action<string, string?, string>? _auditSink;
    private readonly Dictionary<string, WakeTarget> _targets = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<WakeEvent> _events = new();
    private readonly object _gate = new();

    /// <param name="featureGate">TOTAL POLICY CONTROL gate,
    /// SCOPE-AWARE (scopeId, featureKey) — D38 review F2.</param>
    /// <param name="auditSink">Optional chained-audit sink
    /// (kind, actor, detail) — D38 review F1.</param>
    public WakeService(RosterService roster, EnrollmentService enrollments, IWakeSender sender,
        Func<string, string, PolicyVerdict>? featureGate = null,
        Action<string, string?, string>? auditSink = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _sender = sender ?? throw new ArgumentNullException(nameof(sender));
        _featureGate = featureGate;
        _auditSink = auditSink;
    }

    public event Action? Changed;
    public IReadOnlyList<WakeEvent> Events { get { lock (_gate) return _events.ToList(); } }

    private bool FeatureAllowed(string scopeId) =>
        _featureGate?.Invoke(scopeId, PolicyFeatures.WakeOnLan).Allowed ?? true;

    private EnrolledDevice? Device(string? deviceId) =>
        _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId ?? "", StringComparison.OrdinalIgnoreCase));

    private string? ScopeOf(EnrolledDevice device)
    {
        var group = _roster.FindDeviceGroup(device.GroupId);
        return group?.ScopeId;
    }

    private void RecordLocked(string kind, string deviceId, string? actor, string detail)
    {
        _events.Add(new WakeEvent(DateTimeOffset.UtcNow, kind, deviceId, actor, detail));
        _auditSink?.Invoke(kind, actor, detail);
        Changed?.Invoke();
    }

    /// <summary>Register (or replace) a device's wake target. The
    /// actor must be a live company admin of the device's scope,
    /// or null — the trusted in-process path, by which a device's
    /// own Core registers the MACs it can read from its own NICs.
    /// A remote caller can never register a target: the registry is
    /// what stands between "any paired agent" and "wake any MAC on
    /// the LAN", so it is written only from inside the trust
    /// boundary or by an admin's deliberate act.</summary>
    public bool RegisterTarget(string deviceId, string macAddress, string broadcastAddress, string? actorUserId)
    {
        var mac = MagicPacket.ParseMac(macAddress);
        if (mac is null || !MagicPacket.IsWakeableMac(mac)) return false;
        if (!IPAddress.TryParse(broadcastAddress ?? "", out var ip) ||
            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;
        lock (_gate)
        {
            var device = Device(deviceId);
            if (device is null || device.Revoked) return false;
            var scopeId = ScopeOf(device);
            if (scopeId is null) return false;
            if (actorUserId is not null &&
                (!_roster.IsCompanyAdmin(scopeId, actorUserId) ||
                 _roster.GetUser(scopeId, actorUserId) is not { Kind: "human", Suspended: false }))
                return false;
            _targets[device.DeviceId] = new WakeTarget(
                device.DeviceId, MagicPacket.NormalizeMac(mac), ip.ToString(),
                actorUserId, DateTimeOffset.UtcNow,
                _targets.TryGetValue(device.DeviceId, out var old) ? old.LastWakeUtc : null);
            RecordLocked("wake_target_registered", device.DeviceId, actorUserId,
                $"Wake target registered: {MagicPacket.NormalizeMac(mac)} via {ip}.");
            return true;
        }
    }

    public bool UnregisterTarget(string deviceId, string? actorUserId)
    {
        lock (_gate)
        {
            var device = Device(deviceId);
            if (device is null) return false;
            var scopeId = ScopeOf(device);
            if (scopeId is null) return false;
            if (actorUserId is not null &&
                (!_roster.IsCompanyAdmin(scopeId, actorUserId) ||
                 _roster.GetUser(scopeId, actorUserId) is not { Kind: "human", Suspended: false }))
                return false;
            if (!_targets.Remove(device.DeviceId)) return false;
            RecordLocked("wake_target_removed", device.DeviceId, actorUserId, "Wake target removed.");
            return true;
        }
    }

    public WakeTarget? GetTarget(string deviceId)
    {
        lock (_gate) return _targets.TryGetValue(deviceId ?? "", out var t) ? t : null;
    }

    public IReadOnlyList<WakeTarget> ListTargets()
    {
        lock (_gate) return _targets.Values.ToList();
    }

    /// <summary>Send the wake. Gates, in order: a registered
    /// target; the device still enrolled and unrevoked (re-read
    /// at send time — a device revoked since registration is
    /// never woken); the policy toggle FOR THE DEVICE'S SCOPE
    /// (D38 review F2); the actor a live user of the device's
    /// scope holding the Slice 2 "use" grant on the device's
    /// group (waking is an act on the machine, authorized exactly
    /// like starting an unattended session on it). The UDP send
    /// itself runs OUTSIDE the lock (D38 review F12: no network
    /// I/O under _gate); the outcome is recorded under the lock
    /// afterwards.</summary>
    public (bool Sent, string Detail) SendWake(string deviceId, string actorUserId)
    {
        WakeTarget target;
        string scopeId;
        string actorId;
        lock (_gate)
        {
            var device = Device(deviceId);
            if (device is null) return (false, "unknown device");
            if (device.Revoked) return (false, "device is revoked — never woken");
            if (!_targets.TryGetValue(device.DeviceId, out var found))
                return (false, "no wake target registered for this device");
            target = found;
            var scope = ScopeOf(device);
            if (scope is null) return (false, "device is not filed in any scope");
            scopeId = scope;
            if (!FeatureAllowed(scopeId))
                return (false, "wake-on-LAN is disabled by policy for this scope");
            var actor = _roster.GetUser(scopeId, actorUserId);
            if (actor is null || actor.Suspended)
                return (false, "actor is not a live user of the device's scope");
            if (!_roster.UserHasRight(scopeId, actor.Id, device.GroupId, "use"))
                return (false, "actor holds no 'use' grant on the device's group");
            actorId = actor.Id;
            deviceId = device.DeviceId;
        }
        var packet = MagicPacket.Build(target.MacAddress);
        try { _sender.Send(packet, target.BroadcastAddress, MagicPacket.WakePort); }
        catch (Exception ex) { return (false, $"wake send failed: {ex.GetType().Name}"); }
        lock (_gate)
        {
            if (_targets.TryGetValue(deviceId, out var current))
                _targets[deviceId] = current with { LastWakeUtc = DateTimeOffset.UtcNow };
            RecordLocked("wake_sent", deviceId, actorId,
                $"Magic packet sent for {target.MacAddress} via {target.BroadcastAddress}:{MagicPacket.WakePort}.");
        }
        return (true, $"magic packet sent for {target.MacAddress}");
    }

    /// <summary>The session form: wake the host of a REQUESTED
    /// session, then the normal connect flow proceeds. The actor
    /// must be the session's initiator or one of its participants;
    /// the wake lands on the session's event list (the replay shows
    /// the machine was woken for this session) as well as in this
    /// service's own events. Waking for an active session is
    /// meaningless and for an ended one refused — both refuse.</summary>
    public (bool Sent, string Detail) SendWakeForSession(SessionService sessions, string sessionId, string actorUserId)
    {
        var session = sessions.GetSession(sessionId);
        if (session is null) return (false, "unknown session");
        if (session.State != "requested")
            return (false, $"session is {session.State} — wake precedes connect and applies only to a requested session");
        var isInitiator = string.Equals(session.InitiatorUserId, actorUserId, StringComparison.OrdinalIgnoreCase);
        var isParticipant = sessions.ListParticipants(session.Id).Any(
            p => string.Equals(p.UserId, actorUserId, StringComparison.OrdinalIgnoreCase));
        if (!isInitiator && !isParticipant)
            return (false, "actor is not part of this session");
        var device = Device(session.HostDeviceId);
        if (device is not null)
        {
            var scopeId = ScopeOf(device);
            if (scopeId is not null &&
                !string.Equals(scopeId, session.ScopeId, StringComparison.OrdinalIgnoreCase))
                return (false, "host device is not filed in the session's scope (D8)");
        }
        var result = SendWake(session.HostDeviceId, actorUserId);
        if (result.Sent)
            sessions.AppendEvent(session.Id, "wake_sent", actorUserId, session.HostDeviceId,
                "Target woken for this session (wake-on-LAN).");
        return result;
    }

    // ---- persistence ------------------------------------------------------

    private sealed record TargetDto(string DeviceId, string MacAddress, string BroadcastAddress,
        string? RegisteredByUserId, DateTimeOffset RegisteredUtc, DateTimeOffset? LastWakeUtc);

    private sealed record EventDto(DateTimeOffset Utc, string Kind, string DeviceId,
        string? ActorUserId, string Detail);

    private sealed record StoreDto(TargetDto[] Targets, EventDto[]? Events);

    /// <summary>Serialize the registry AND its event history
    /// (D38 review F1: the acts are part of the record — they
    /// persist and, via the audit sink, chain). MACs are network
    /// facts, not secrets; nothing else lives in this store.</summary>
    public string ExportJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new StoreDto(
                _targets.Values.Select(t => new TargetDto(
                    t.DeviceId, t.MacAddress, t.BroadcastAddress, t.RegisteredByUserId,
                    t.RegisteredUtc, t.LastWakeUtc)).ToArray(),
                _events.Select(e => new EventDto(e.Utc, e.Kind, e.DeviceId, e.ActorUserId, e.Detail)).ToArray()));
    }

    /// <summary>Restore, re-validated: targets for unknown or
    /// revoked devices are dropped, MACs and broadcast addresses
    /// are re-parsed strictly, duplicates collapse to the first.
    /// The pre-F1 bare-array shape is still accepted.</summary>
    public int ImportJson(string json)
    {
        TargetDto[]? dtos;
        EventDto[]? eventDtos = null;
        try
        {
            var store = JsonSerializer.Deserialize<StoreDto>(json);
            dtos = store?.Targets;
            eventDtos = store?.Events;
        }
        catch { dtos = null; }
        if (dtos is null)
        {
            try { dtos = JsonSerializer.Deserialize<TargetDto[]>(json); }
            catch { return 0; }
        }
        if (dtos is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            // BD-SHARED-TRANSPORT F12: an import REPLACES the event
            // history — previously it appended onto the live list,
            // so importing the same export twice doubled the
            // history (and every re-import compounded it).
            _events.Clear();
            foreach (var dto in eventDtos ?? Array.Empty<EventDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Kind) ||
                    string.IsNullOrWhiteSpace(dto.DeviceId)) continue;
                _events.Add(new WakeEvent(dto.Utc, dto.Kind, dto.DeviceId, dto.ActorUserId, dto.Detail ?? ""));
            }
            foreach (var dto in dtos)
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.DeviceId)) continue;
                var device = Device(dto.DeviceId);
                if (device is null || device.Revoked) continue;
                if (_targets.ContainsKey(device.DeviceId)) continue;
                var mac = MagicPacket.ParseMac(dto.MacAddress);
                if (mac is null || !MagicPacket.IsWakeableMac(mac)) continue;
                if (!IPAddress.TryParse(dto.BroadcastAddress ?? "", out var ip) ||
                    ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    continue;
                _targets[device.DeviceId] = new WakeTarget(device.DeviceId,
                    MagicPacket.NormalizeMac(mac), ip.ToString(), dto.RegisteredByUserId,
                    dto.RegisteredUtc, dto.LastWakeUtc);
                restored++;
            }
        }
        return restored;
    }
}

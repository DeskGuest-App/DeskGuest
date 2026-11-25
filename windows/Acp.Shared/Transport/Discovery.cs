using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Acp.Shared.Transport;

/// <summary>Local discovery (D19/D20), formalized. An ACP install
/// announces ONLY three things: a HASH of its device id (never the
/// id itself), its display name, and its enrollment state. That is
/// enough for an enrolled peer to recognize it and for an operator
/// to see it as available to enroll — and nothing more. Discovery
/// is NOT a network scan: ACP never probes addresses or lists
/// strangers; a device appears only because ACP is installed on it
/// and it announced itself (D20). Discovery grants NO trust: a
/// discovered device is never controllable from discovery — control
/// still requires pairing/enrollment and the proof-of-possession
/// handshake, which a spoofed announcement cannot pass.</summary>
public sealed record DiscoveryAnnouncement(string DeviceIdHash, string DisplayName, string EnrollmentState)
{
    public const string Magic = "ACP1";
    public const string StateEnrolled = "enrolled";
    public const string StateAvailable = "available";

    /// <summary>The broadcast hash: SHA-256 of the DeviceId string.
    /// Peers that already know the DeviceId (enrolled) can match it;
    /// strangers learn no usable identifier.</summary>
    public static string HashDeviceId(string deviceId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(deviceId ?? ""))).ToLowerInvariant();

    public static string? SanitizeName(string? name)
    {
        if (name is null) return null;
        var t = name.Trim();
        if (t.Length == 0 || t.Length > 64) return null;
        if (t.Any(c => char.IsControl(c) || c == '|')) return null;
        return t;
    }

    public static DiscoveryAnnouncement? ForDevice(string deviceId, string displayName, bool enrolled)
    {
        var name = SanitizeName(displayName);
        if (name is null || string.IsNullOrWhiteSpace(deviceId)) return null;
        return new DiscoveryAnnouncement(HashDeviceId(deviceId), name, enrolled ? StateEnrolled : StateAvailable);
    }

    public string Encode() =>
        $"{Magic}|{DeviceIdHash}|{EnrollmentState}|{Convert.ToBase64String(Encoding.UTF8.GetBytes(DisplayName))}";

    /// <summary>Strict parse: wrong magic, a hash that is not 64
    /// lowercase hex chars, an unknown state, or a hostile name all
    /// refuse the whole datagram — never a partial trust.</summary>
    public static DiscoveryAnnouncement? Decode(string? datagram)
    {
        if (datagram is null) return null;
        var parts = datagram.Trim().Split('|');
        if (parts.Length != 4 || parts[0] != Magic) return null;
        var hash = parts[1];
        if (hash.Length != 64 || hash.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) return null;
        if (parts[2] is not (StateEnrolled or StateAvailable)) return null;
        string name;
        try { name = Encoding.UTF8.GetString(Convert.FromBase64String(parts[3])); }
        catch { return null; }
        var clean = SanitizeName(name);
        if (clean is null || clean != name) return null;
        return new DiscoveryAnnouncement(hash, name, parts[2]);
    }
}

/// <summary>A discovered device, classified for operator surfaces.
/// IsControllable is ALWAYS false: discovery is an introduction,
/// never a grant (D19/D20).</summary>
public sealed record DiscoveredDevice(DiscoveryAnnouncement Announcement, bool IsKnownPeer)
{
    public bool AvailableToEnroll => !IsKnownPeer;
    public bool IsControllable => false;
}

/// <summary>Announcement + browse over UDP (broadcast where the
/// platform allows it; unicast to a known subnet address where it
/// does not). Same-network only by construction (D19): nothing
/// here routes, relays, or scans.</summary>
public sealed class DiscoveryService
{
    public const int DefaultPort = 47622;
    private readonly IReadOnlySet<string> _knownHashes;

    /// <param name="knownDeviceIds">DeviceIds this install is
    /// enrolled/paired with — matched by hash, never broadcast.</param>
    public DiscoveryService(IEnumerable<string>? knownDeviceIds = null) =>
        _knownHashes = new HashSet<string>(
            (knownDeviceIds ?? Array.Empty<string>()).Select(DiscoveryAnnouncement.HashDeviceId),
            StringComparer.OrdinalIgnoreCase);

    public DiscoveredDevice Classify(DiscoveryAnnouncement announcement) =>
        new(announcement, _knownHashes.Contains(announcement.DeviceIdHash));

    public static DiscoveredDevice? ParseDatagram(byte[] data, DiscoveryService classifier)
    {
        var text = Encoding.UTF8.GetString(data);
        var announcement = DiscoveryAnnouncement.Decode(text);
        return announcement is null ? null : classifier.Classify(announcement);
    }

    /// <summary>Send one announcement to a target (broadcast
    /// 255.255.255.255 by default, or a subnet/unicast address).</summary>
    public async Task AnnounceAsync(DiscoveryAnnouncement announcement, string targetHost = "255.255.255.255", int port = DefaultPort, CancellationToken ct = default)
    {
        using var udp = new UdpClient();
        udp.EnableBroadcast = true;
        var bytes = Encoding.UTF8.GetBytes(announcement.Encode());
        await udp.SendAsync(bytes, bytes.Length, targetHost, port);
    }

    /// <summary>Listen for announcements for a bounded window and
    /// return the unique devices heard, classified. Bounded by
    /// design: browse is a window, not a background scan.</summary>
    public async Task<IReadOnlyList<DiscoveredDevice>> BrowseAsync(TimeSpan window, int port = DefaultPort, CancellationToken ct = default)
    {
        using var udp = new UdpClient();
        udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));
        var found = new Dictionary<string, DiscoveredDevice>(StringComparer.OrdinalIgnoreCase);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(window);
        try
        {
            while (!deadline.IsCancellationRequested)
            {
                var result = await udp.ReceiveAsync(deadline.Token);
                var device = ParseDatagram(result.Buffer, this);
                if (device is not null) found[device.Announcement.DeviceIdHash] = device;
            }
        }
        catch (OperationCanceledException) { /* window closed */ }
        catch (SocketException) { /* window closed by disposal */ }
        return found.Values.ToList();
    }
}

using System.Net;
using System.Net.Sockets;
using Acp.Shared.Enrollment;
using Acp.Shared.Hub;
using Acp.Shared.Security;

namespace Acp.Shared.Transport;

/// <summary>A rung whose session connects authenticate with the
/// local device identity (proof of possession, LanProtocol). The
/// failover engine calls ConnectSessionAsync on these rungs for a
/// real session; the bare ConnectAsync is a reachability probe
/// only and never carries a session on an authenticated rung.</summary>
public interface IAuthenticatedRung : ITransportRung
{
    Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default);
}

/// <summary>Mesh addressing for the coordination rungs: hub and
/// mesh peers are addressed by their tailnet IPs, which live in
/// the shared CGNAT block 100.64.0.0/10. A coordination rung must
/// never silently become a LAN backdoor: an address outside the
/// mesh block is refused before any socket opens.</summary>
public static class MeshAddress
{
    public static bool IsTailnetAddress(string? host)
    {
        if (host is null || !IPAddress.TryParse(host.Trim(), out var ip)) return false;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        // 100.64.0.0/10: first octet 100, second octet 64..127.
        return b[0] == 100 && b[1] >= 64 && b[1] <= 127;
    }

    /// <summary>BD-SHARED-TRANSPORT F10: the /10 prefix alone is
    /// NOT proof of tailnet membership — ISP carrier-grade NAT
    /// uses the same 100.64.0.0/10 block. When the caller can
    /// supply the local tailnet's actual peer address list (from
    /// `tailscale status`), membership means being ON that list;
    /// the prefix check remains only as the shape gate.</summary>
    public static bool IsKnownTailnetPeer(string? host, IReadOnlyCollection<string>? tailnetPeerAddresses)
    {
        if (!IsTailnetAddress(host)) return false;
        if (tailnetPeerAddresses is null) return false;
        return tailnetPeerAddresses.Contains(host!.Trim());
    }
}

/// <summary>The `hub` rung (D27, Block C part 3): an ACP session
/// carried over the ACP-managed Headscale mesh. The data plane is
/// the system Tailscale client (≥1.104.4, enforced at join by the
/// hub lane's ClientVersionGate) pointed at the ACP hub; this rung
/// connects TCP to the peer's tailnet IP and then runs the SAME
/// LanProtocol proof-of-possession handshake as the `lan` rung.
///
/// Two gates, deliberately separate (mesh membership must never
/// equal ACP admission):
///  1. Membership: the target device must be a live node in ACP's
///     hub registry (joined, not decommissioned/deleted). An
///     unenrolled node — even one whose packets the mesh would
///     carry — is refused here before any socket opens.
///  2. Admission: the host side still requires the enrollment
///     handshake (LanHostListener on the mesh address); a peer
///     that cannot sign for an enrolled, unrevoked DeviceId is
///     refused and dropped, exactly as on `lan`.</summary>
public sealed class HubRung : IAuthenticatedRung
{
    private readonly Func<string, bool> _isLiveHubNode;
    private readonly Func<string, bool> _isMeshAddress;
    private readonly EnrollmentService? _enrollments;

    /// <param name="isLiveHubNode">Membership gate: true only for a
    /// device with a live (joined, not deleted) hub node.</param>
    /// <param name="isMeshAddress">Address gate seam for tests; the
    /// production default is the tailnet CGNAT block.</param>
    /// <param name="enrollments">Enrollment store for the v2
    /// mutual handshake; a session connect without it refuses
    /// (fail closed).</param>
    public HubRung(Func<string, bool> isLiveHubNode, Func<string, bool>? isMeshAddress = null,
        EnrollmentService? enrollments = null)
    {
        _isLiveHubNode = isLiveHubNode;
        _isMeshAddress = isMeshAddress ?? MeshAddress.IsTailnetAddress;
        _enrollments = enrollments;
    }

    /// <summary>Production constructor: membership from the hub
    /// lane's node registry.</summary>
    public HubRung(HubNodeRegistry registry, Func<string, bool>? isMeshAddress = null,
        EnrollmentService? enrollments = null)
        : this(deviceId => registry.Get(deviceId) is { Deleted: false }, isMeshAddress, enrollments) { }

    public string Id => "hub";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, null, ct);

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, identity, ct);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, DeviceIdentity? identity, CancellationToken ct)
    {
        ConnectAttempts++;
        if (string.IsNullOrWhiteSpace(target.Address))
            return new TransportConnectResult(false, "hub: no mesh address for this device (not discovered on the hub mesh, none entered)");
        if (!_isLiveHubNode(target.DeviceId))
            return new TransportConnectResult(false,
                "hub: target device is not a live hub node — mesh membership is required before ACP will even address it, and membership alone never grants a session");
        var (host, port) = LanRung.ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"hub: bad address '{target.Address}'");
        if (!_isMeshAddress(host))
            return new TransportConnectResult(false,
                $"hub: '{host}' is not a tailnet (100.64.0.0/10) address — the hub rung rides the mesh only and never falls back to a LAN address");
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(host, port, timeout.Token);
            var stream = client.GetStream();
            Stream sessionStream = stream;
            if (identity is not null)
            {
                var (ok, detail, channel) = await RungHandshake.RunAsync("hub", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail + " (ACP admission is the enrollment handshake, not mesh membership)"); }
                sessionStream = channel;
            }
            return new TransportConnectResult(true, $"hub: connected over the ACP hub mesh to {host}:{port}", new TcpStreamOwner(client, sessionStream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"hub: {ex.GetType().Name}");
        }
    }

    // Same stream-ownership shape as LanRung's (the socket dies with
    // the session channel, never before).
    private sealed class TcpStreamOwner : Stream
    {
        private readonly TcpClient _client; private readonly Stream _inner;
        public TcpStreamOwner(TcpClient client, Stream inner) { _client = client; _inner = inner; }
        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _inner.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _inner.ReadAsync(buffer, offset, count, ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => _inner.WriteAsync(buffer, ct);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _inner.WriteAsync(buffer, offset, count, ct);
        protected override void Dispose(bool disposing) { if (disposing) { _inner.Dispose(); _client.Dispose(); } base.Dispose(disposing); }
    }
}

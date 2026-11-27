using System.Net.Sockets;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Transport;

namespace DeskGuest.Shared.Tailscale;

/// <summary>The `mesh` rung (D4, Block C part 3): an DeskGuest session
/// over the vendor Tailscale tailnet. The rung exists in the
/// engine only behind a VERIFIED setup: the setup service must be
/// in the Ready state (client floored, kill switch asserted and
/// verified on desktop, no SSH/Serve/Funnel, scoped credentials,
/// D12 policy applied). Without that, every connect refuses and
/// says which condition is unmet — the rung never quietly rides a
/// default-config Tailscale install (T2: DO NOT ADOPT in default
/// configuration).
///
/// Admission is DeskGuest's, as on every rung: the host side runs the
/// same LanProtocol enrollment handshake. Being on the tailnet —
/// even being a tagged, policy-visible node — grants no DeskGuest
/// session by itself.</summary>
public sealed class MeshRung : IAuthenticatedRung
{
    private readonly Func<MeshSetupState> _setupState;
    private readonly Func<string, bool> _isMeshAddress;
    private readonly EnrollmentService? _enrollments;
    private readonly Func<bool>? _readinessRecheck;
    private readonly Func<IReadOnlyCollection<string>?>? _tailnetPeers;

    /// <param name="readinessRecheck">BD-SHARED-TRANSPORT F9:
    /// re-verification run on EVERY connect (kill switch + SSH /
    /// Serve / Funnel probe through MeshSetupService).
    /// Setup passing once no longer keeps the rung live forever:
    /// drift after setup drops the connect, by name.</param>
    /// <param name="tailnetPeers">BD-SHARED-TRANSPORT F10: the
    /// local tailnet's actual peer addresses; when supplied, the
    /// target must be a known peer, not merely inside 100.64/10
    /// (which ISP CGNAT shares).</param>
    public MeshRung(Func<MeshSetupState> setupState, Func<string, bool>? isMeshAddress = null,
        EnrollmentService? enrollments = null, Func<bool>? readinessRecheck = null,
        Func<IReadOnlyCollection<string>?>? tailnetPeers = null)
    {
        _setupState = setupState;
        _isMeshAddress = isMeshAddress ?? MeshAddress.IsTailnetAddress;
        _enrollments = enrollments;
        _readinessRecheck = readinessRecheck;
        _tailnetPeers = tailnetPeers;
    }

    public string Id => "mesh";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, null, ct);

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, identity, ct);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, DeviceIdentity? identity, CancellationToken ct)
    {
        ConnectAttempts++;
        var state = _setupState();
        if (state.Stage != MeshSetupStage.Ready)
            return new TransportConnectResult(false,
                $"mesh: rung not set up under the T2 conditions (state: {state.Stage} — {state.Detail})");
        if (_readinessRecheck is not null && !_readinessRecheck())
            return new TransportConnectResult(false,
                "mesh: readiness re-verification failed on this connect (kill switch / SSH / Serve / Funnel drift since setup) — rung refused until setup re-verifies");
        if (string.IsNullOrWhiteSpace(target.Address))
            return new TransportConnectResult(false, "mesh: no tailnet address for this device");
        var (host, port) = LanRung.ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"mesh: bad address '{target.Address}'");
        if (!_isMeshAddress(host))
            return new TransportConnectResult(false,
                $"mesh: '{host}' is not a tailnet (100.64.0.0/10) address — the mesh rung rides the tailnet only");
        if (_tailnetPeers?.Invoke() is { } peers && !MeshAddress.IsKnownTailnetPeer(host, peers))
            return new TransportConnectResult(false,
                $"mesh: '{host}' is inside 100.64/10 but is NOT a peer on this device's tailnet (the block is shared with ISP carrier-grade NAT) — refused");
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
                var (ok, detail, channel) = await RungHandshake.RunAsync("mesh", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail + " (tailnet membership is not DeskGuest admission)"); }
                sessionStream = channel;
            }
            return new TransportConnectResult(true, $"mesh: connected over the Tailscale tailnet to {host}:{port}", new MeshStreamOwner(client, sessionStream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"mesh: {ex.GetType().Name}");
        }
    }

    private sealed class MeshStreamOwner : Stream
    {
        private readonly TcpClient _client; private readonly Stream _inner;
        public MeshStreamOwner(TcpClient client, Stream inner) { _client = client; _inner = inner; }
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

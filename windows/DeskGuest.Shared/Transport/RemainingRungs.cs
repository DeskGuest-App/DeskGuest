using System.Net;
using System.Net.Sockets;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.OwnPath;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Transport;

// =====================================================================
// Block F — the remaining automatic rungs (D32's six: lan, hub,
// mesh, ipv6, ownpath, tor) behind the transport engine's public
// surface (IAuthenticatedRung). Every rung here runs the SAME
// LanProtocol proof-of-possession handshake after its data plane
// connects: the rung changes how packets reach the peer, never who
// is admitted. Every rung is honest about reachability — a rung
// that cannot prove its precondition refuses BEFORE any socket
// opens, with the reason named, and never silently falls back to a
// different rung's semantics (the engine owns failover; a rung
// never impersonates another rung).
// =====================================================================


/// <summary>Shared v2 handshake leg for the Block F rungs
/// (BD-SHARED-TRANSPORT F1): every rung runs the SAME mutually
/// authenticated AEAD handshake after its data plane connects; a
/// rung without an enrollment store refuses session connects
/// (fail closed), and the stream a session rides is the AEAD
/// channel, never the raw socket.</summary>
internal static class RungHandshake
{
    public static async Task<(bool Ok, string Detail, Stream? Channel)> RunAsync(
        string rung, Stream stream, DeviceIdentity identity, EnrollmentService? enrollments,
        string targetDeviceId, CancellationToken ct)
    {
        if (enrollments is null)
            return (false, $"{rung}: no enrollment store wired on this rung — the host cannot be verified, session refused (fail closed)", null);
        var hs = await LanProtocol.ClientHandshakeDetailedAsync(stream, identity, enrollments, targetDeviceId, ct);
        return hs.Outcome switch
        {
            LanProtocol.ClientHandshakeOutcome.Connected when hs.Channel is not null =>
                (true, "", hs.Channel),
            LanProtocol.ClientHandshakeOutcome.HostRefused =>
                (false, $"{rung}: host refused our proof of possession", null),
            LanProtocol.ClientHandshakeOutcome.HostAuthenticationFailed =>
                (false, $"{rung}: the peer could not prove it is the enrolled host — refused before signing anything", null),
            _ => (false, $"{rung}: no DeskGuest challenge received — the peer did not speak the DeskGuest protocol", null),
        };
    }
}

/// <summary>Honest IPv6 reachability classification (Block F): a
/// target is direct-IPv6-reachable only when it is a GLOBAL unicast
/// address (2000::/3). Loopback, link-local, unique-local, multicast
/// and documentation ranges are named refusals, not "reachable".</summary>
public static class Ipv6Reachability
{
    public static (bool Ok, string Reason) Classify(string? host)
    {
        if (host is null || !IPAddress.TryParse(host.Trim(), out var ip))
            return (false, "ipv6: target is not an IPv6 address");
        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
            return (false, "ipv6: target is not an IPv6 address");
        if (IPAddress.IsLoopback(ip)) return (false, "ipv6: loopback is not a direct session target");
        var b = ip.GetAddressBytes();
        if ((b[0] & 0xE0) != 0x20) // not 2000::/3 global unicast
        {
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return (false, "ipv6: link-local address (fe80::/10) is not globally reachable");
            if ((b[0] & 0xFE) == 0xFC) return (false, "ipv6: unique-local address (fc00::/7) is not globally reachable");
            if (b[0] == 0xFF) return (false, "ipv6: multicast is not a session target");
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return (false, "ipv6: documentation range (2001:db8::/32) is not reachable");
            return (false, "ipv6: address is outside the global unicast range (2000::/3)");
        }
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8)
            return (false, "ipv6: documentation range (2001:db8::/32) is not reachable");
        return (true, "ipv6: global unicast target");
    }

    /// <summary>This device's own global IPv6 presence, read from the
    /// OS interface list — the rung's other precondition. No probing
    /// traffic is sent to learn it.</summary>
    public static bool LocalHasGlobalIpv6()
    {
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (Classify(ua.Address.ToString()).Ok) return true;
            }
        }
        catch { /* no interfaces readable = no global IPv6, honestly */ }
        return false;
    }
}

/// <summary>The `ipv6` rung: a direct TCP session over global IPv6
/// where BOTH ends have it. The target must classify global; the
/// local precondition is checked when a probe delegate is supplied
/// (the Core supplies the real interface check; tests supply their
/// own truth). After connect, the LanProtocol handshake decides
/// admission, exactly as on `lan`.</summary>
public sealed class Ipv6Rung : IAuthenticatedRung
{
    private readonly Func<bool> _localHasGlobal;
    private readonly EnrollmentService? _enrollments;
    public Ipv6Rung(Func<bool>? localHasGlobal = null, EnrollmentService? enrollments = null)
    { _localHasGlobal = localHasGlobal ?? Ipv6Reachability.LocalHasGlobalIpv6; _enrollments = enrollments; }
    public string Id => "ipv6";
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
            return new TransportConnectResult(false, "ipv6: no address (target must carry the peer's global IPv6 address)");
        var (host, port) = LanRung.ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"ipv6: bad address '{target.Address}'");
        var cls = Ipv6Reachability.Classify(host);
        if (!cls.Ok) return new TransportConnectResult(false, cls.Reason);
        if (!_localHasGlobal())
            return new TransportConnectResult(false, "ipv6: this device has no global IPv6 address — the rung cannot carry a session from here");
        var client = new TcpClient(AddressFamily.InterNetworkV6);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(host, port, timeout.Token);
            var stream = client.GetStream();
            Stream sessionStream = stream;
            if (identity is not null)
            {
                var (ok, detail, channel) = await RungHandshake.RunAsync("ipv6", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail); }
                sessionStream = channel;
            }
            return new TransportConnectResult(true, $"ipv6: connected to [{host}]:{port}", new RungStreamOwner(client, sessionStream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"ipv6: {ex.GetType().Name}");
        }
    }
}

/// <summary>The peer set the `ownpath` rung may use: generated,
/// validated WireGuard peer configs keyed by device id. The Core
/// builds this from its on-disk own-path store; a device with no
/// validated config is refused before any socket opens.</summary>
public sealed record OwnPathPeerSet(IReadOnlyDictionary<string, OwnPathPeer> Peers)
{
    public static OwnPathPeerSet Empty { get; } = new(new Dictionary<string, OwnPathPeer>());
}

/// <summary>The `ownpath` rung: DeskGuest-generated WireGuard is the data
/// plane (the OS WireGuard stack carries the tunnel; DeskGuest generates
/// and validates its configuration per the T5 binding conditions).
/// This rung connects to the peer's TUNNEL address (the address
/// inside the generated config) and runs the enrollment handshake
/// over it. Where the tunnel is not up, the connect fails honestly
/// — DeskGuest never tunnels by itself and never pretends the WireGuard
/// data plane is its own code. The OpenSSH channel (generated by
/// SshChannelConfigGenerator) is the alternate own-path where
/// configured: same peer set, carried over the SSH endpoint.</summary>
public sealed class OwnPathRung : IAuthenticatedRung
{
    private readonly Func<OwnPathPeerSet> _peers;
    private readonly EnrollmentService? _enrollments;
    private readonly Func<string, string?>? _onDiskConfigText;

    /// <param name="onDiskConfigText">BD-SHARED-TRANSPORT F4(4):
    /// supplies the config text AS IT EXISTS ON DISK for a device
    /// (the bytes the OS WireGuard service actually runs). When
    /// supplied, the rung validates THOSE bytes and refuses when
    /// they differ from the generated config — validating only
    /// its own freshly generated output proved nothing about the
    /// file that was swapped on disk.</param>
    public OwnPathRung(Func<OwnPathPeerSet> peers, EnrollmentService? enrollments = null,
        Func<string, string?>? onDiskConfigText = null)
    { _peers = peers; _enrollments = enrollments; _onDiskConfigText = onDiskConfigText; }
    public string Id => "ownpath";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, null, ct);

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, identity, ct);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, DeviceIdentity? identity, CancellationToken ct)
    {
        ConnectAttempts++;
        var set = _peers();
        if (!set.Peers.TryGetValue(target.DeviceId, out var peer))
            return new TransportConnectResult(false, "ownpath: no generated WireGuard config for this device — run own-path setup first");
        // Re-validate the stored config at use time: a config swapped
        // on disk between setup and connect must not carry a session.
        string config;
        try { config = WireGuardConfigGenerator.GeneratePeerConfig(peer); }
        catch (InvalidOperationException ex) { return new TransportConnectResult(false, "ownpath: stored peer config fails validation — " + ex.Message); }
        var verdict = WireGuardConfigGenerator.ValidateConfigText(config);
        if (!verdict.Ok) return new TransportConnectResult(false, "ownpath: " + verdict.Reason);
        if (_onDiskConfigText is not null)
        {
            var disk = _onDiskConfigText(target.DeviceId);
            if (disk is null)
                return new TransportConnectResult(false, "ownpath: no on-disk WireGuard config found for this device — the tunnel the OS would run does not exist; refused");
            var diskVerdict = WireGuardConfigGenerator.ValidateConfigText(disk);
            if (!diskVerdict.Ok) return new TransportConnectResult(false, "ownpath: on-disk config fails validation — " + diskVerdict.Reason);
            if (!string.Equals(OwnPathFingerprint.Of(disk), OwnPathFingerprint.Of(config), StringComparison.Ordinal))
                return new TransportConnectResult(false, "ownpath: on-disk config differs from the generated peer config (fingerprint mismatch) — a swapped config must not carry a session; refused");
        }
        var tunnelHost = peer.TunnelAddress.Trim();
        var port = LanProtocol.DefaultPort;
        if (!string.IsNullOrWhiteSpace(target.Address))
        {
            var (h, p) = LanRung.ParseAddress(target.Address);
            if (h is not null && h == tunnelHost) port = p;
        }
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await client.ConnectAsync(tunnelHost, port, timeout.Token);
            var stream = client.GetStream();
            Stream sessionStream = stream;
            if (identity is not null)
            {
                var (ok, detail, channel) = await RungHandshake.RunAsync("ownpath", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail); }
                sessionStream = channel;
            }
            return new TransportConnectResult(true, $"ownpath: connected over the WireGuard tunnel to {tunnelHost}:{port}", new RungStreamOwner(client, sessionStream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"ownpath: tunnel connect failed ({ex.GetType().Name}) — is the WireGuard tunnel up?");
        }
    }
}

/// <summary>Tor as configured by DeskGuest: the rung speaks through a
/// SOCKS5 proxy that DeskGuest's Tor setup provides — a genuine Tor
/// client DeskGuest provisions itself: the Tor Project's expert bundle,
/// pinned by hash in code and in tor-component/PACKAGE-MANIFEST.md,
/// downloaded from the Tor Project's own distribution directory
/// and verified against the pins before first run (A2,
/// DeskGuest.Shared.Tor). The setup act launches it as a local-only
/// SOCKS listener and is the only writer of the configuration
/// this rung reads; where no proxy is configured the rung refuses
/// with that reason named. Latency cost is a product label,
/// carried on the rung: sessions over Tor are slow by design of
/// the Tor network.</summary>
public sealed record TorConfig(string SocksHost, int SocksPort)
{
    public const string LatencyLabel = "Tor: high latency by design — expect a slow session; the cost of this rung is speed, not setup (D28).";
}

public sealed class TorRung : IAuthenticatedRung
{
    private readonly Func<TorConfig?> _config;
    private readonly EnrollmentService? _enrollments;
    public TorRung(Func<TorConfig?> config, EnrollmentService? enrollments = null)
    { _config = config; _enrollments = enrollments; }
    public string Id => "tor";
    public string LatencyLabel => TorConfig.LatencyLabel;
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public async Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, null, ct);

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default) =>
        await ConnectCoreAsync(target, identity, ct);

    private async Task<TransportConnectResult> ConnectCoreAsync(TransportTarget target, DeviceIdentity? identity, CancellationToken ct)
    {
        ConnectAttempts++;
        var cfg = _config();
        if (cfg is null)
            return new TransportConnectResult(false, "tor: not configured — DeskGuest's Tor setup has not provided a local Tor SOCKS proxy on this device");
        // BD-SHARED-TRANSPORT F10: the SOCKS endpoint must be the
        // LOCAL Tor client DeskGuest provisioned. A non-loopback SOCKS
        // host would hand the session's circuit (and its target)
        // to a remote proxy that is not Tor at all.
        if (!IPAddress.TryParse(cfg.SocksHost, out var socksIp) || !IPAddress.IsLoopback(socksIp))
            return new TransportConnectResult(false, $"tor: configured SOCKS host '{cfg.SocksHost}' is not loopback — DeskGuest's Tor proxy is a local-only listener; refused");
        if (string.IsNullOrWhiteSpace(target.Address))
            return new TransportConnectResult(false, "tor: no target address (the peer's .onion address or reachable host:port is required)");
        var (host, port) = LanRung.ParseAddress(target.Address);
        if (host is null) return new TransportConnectResult(false, $"tor: bad address '{target.Address}'");
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30)); // Tor circuit build is slow — the label's cost, budgeted honestly.
            await client.ConnectAsync(cfg.SocksHost, cfg.SocksPort, timeout.Token);
            var stream = client.GetStream();
            if (!await Socks5ConnectAsync(stream, host, port, timeout.Token))
            { client.Dispose(); return new TransportConnectResult(false, "tor: SOCKS5 connect through the configured Tor proxy failed"); }
            Stream sessionStream = stream;
            if (identity is not null)
            {
                var (ok, detail, channel) = await RungHandshake.RunAsync("tor", stream, identity, _enrollments, target.DeviceId, timeout.Token);
                if (!ok || channel is null) { client.Dispose(); return new TransportConnectResult(false, detail); }
                sessionStream = channel;
            }
            return new TransportConnectResult(true, $"tor: connected to {host}:{port} via the configured Tor proxy ({TorConfig.LatencyLabel})", new RungStreamOwner(client, sessionStream));
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"tor: {ex.GetType().Name}");
        }
    }

    /// <summary>SOCKS5 no-auth CONNECT (RFC 1928). Metadata honesty:
    /// the target host:port is visible to the local Tor client (it
    /// must be, to build the circuit) and to the exit/onion service
    /// exactly as Tor's design specifies — DeskGuest claims no more
    /// metadata protection than Tor itself provides.</summary>
    internal static async Task<bool> Socks5ConnectAsync(Stream stream, string host, int port, CancellationToken ct)
    {
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, ct);
        var greeting = new byte[2];
        if (await ReadExactAsync(stream, greeting, ct) < 2 || greeting[0] != 5 || greeting[1] != 0) return false;
        byte[] request;
        if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            request = new byte[] { 5, 1, 0, 1, b[0], b[1], b[2], b[3], (byte)(port >> 8), (byte)port };
        }
        else
        {
            var name = System.Text.Encoding.ASCII.GetBytes(host);
            if (name.Length > 255) return false;
            request = new byte[5 + name.Length + 2];
            request[0] = 5; request[1] = 1; request[2] = 0; request[3] = 3; request[4] = (byte)name.Length;
            name.CopyTo(request, 5);
            request[^2] = (byte)(port >> 8); request[^1] = (byte)port;
        }
        await stream.WriteAsync(request, ct);
        var head = new byte[4];
        if (await ReadExactAsync(stream, head, ct) < 4 || head[0] != 5 || head[1] != 0) return false;
        var skip = head[3] switch { 1 => 4, 3 => -1, 4 => 16, _ => -2 };
        if (skip == -2) return false;
        if (skip == -1)
        {
            var lenBuf = new byte[1];
            if (await ReadExactAsync(stream, lenBuf, ct) < 1) return false;
            skip = lenBuf[0];
        }
        var rest = new byte[skip + 2];
        return await ReadExactAsync(stream, rest, ct) == rest.Length;
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        return read;
    }
}

/// <summary>Stream owner shared by the Block F rungs (same shape as
/// the lan rung's: disposing the stream disposes the socket).</summary>
internal sealed class RungStreamOwner : Stream
{
    private readonly TcpClient _client; private readonly Stream _inner;
    public RungStreamOwner(TcpClient client, Stream inner) { _client = client; _inner = inner; }
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

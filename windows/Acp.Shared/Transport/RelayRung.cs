using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Enrollment;
using Acp.Shared.Security;

namespace Acp.Shared.Transport;

// =====================================================================
// FR-131 — the `relay` rung: the public sealed relay ("public
// postman", BUILD-PROGRAMME profiles route (c); D18 exception 1 —
// the guaranteed road when both ends sit behind hostile NATs and
// no user-owned node exists to relay).
//
// Shape: a dumb rendezvous server (SealedRelayServer) pairs two
// outbound connections addressed by device id. Both ends dial OUT
// to the relay, so neither needs a reachable listener. After the
// pairing line, the relay is BYTE-BLIND: it forwards a stream
// whose admission is the same LanProtocol v2 handshake as every
// rung and whose content is the end-to-end AEAD channel. The
// relay learns the two device ids, the rendezvous time and byte
// counts — metadata it cannot avoid — and nothing else: it holds
// no enrollment keys, cannot admit anyone (a substituted host
// fails the client's host authentication, exactly as on `lan`),
// and cannot read or forge session content (AEAD).
//
// The frp audit conditions (BUILD-PROGRAMME T5, FR-01…FR-04) are
// the design constraints and map as follows: FR-01 (the relay
// carries only already-encrypted ACP traffic) — by construction:
// pairing is pre-handshake and everything after it is the ACP
// AEAD channel; the one plaintext the relay forwards is the v2
// handshake's public material (ids, nonces, ephemeral keys,
// signatures), the same material any network observer of any rung
// sees. FR-02 (per-device tokens, never a shared inline token) —
// rendezvous requires a per-device token proof (HMAC) from BOTH
// legs, keyed by a token the relay's operator issued to that
// device alone. FR-03 (transport pinned to ACP's own relay) — the
// endpoint comes only from this device's relay.json, set by the
// owner; the rung has no other endpoint source. FR-04 (surface
// limits) — one waiting host per device id, rendezvous timeouts,
// no admin/dashboard surface exists in the postman at all.
// Packaging frp itself as an alternate relay engine remains
// possible behind this same rung id; nothing here depends on it.
//
// The connected-stream seams (ConnectSessionOverStreamAsync,
// HandleLegCoreAsync, ServeLegOverStreamAsync) are public for
// the same reason LanHostListener.ServeConnectedStreamAsync is:
// the pairing must be exercisable over any stream transport in
// tests. Production always dials TCP.
// =====================================================================

/// <summary>This device's relay configuration (relay.json in the
/// data dir): the postman's endpoint and THIS device's per-device
/// rendezvous token. Absent/malformed = the rung is unconfigured
/// and refuses honestly, like `tor` without tor.json.</summary>
public sealed record RelayConfig(string Endpoint, string Token);

/// <summary>The rendezvous wire protocol (pre-handshake only —
/// after PAIRED the relay forwards bytes and speaks no more).
/// Proofs are HMAC-SHA256 over a domain string binding role, the
/// proving device and the peer, keyed by the proving device's
/// per-device token; the relay verifies against its own token
/// table and never sees an enrollment key.</summary>
public static class RelayProtocol
{
    public const string Domain = "acp-relay-v1";
    public const int MaxLineBytes = 8192;

    public static string Proof(string token, string role, string deviceId, string peerDeviceId)
    {
        var msg = Encoding.UTF8.GetBytes($"{Domain}|{role}|{deviceId}|{peerDeviceId}");
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(token), msg);
        return Convert.ToHexString(mac).ToLowerInvariant();
    }

    public static bool Verify(string token, string role, string deviceId, string peerDeviceId, string? proofHex)
    {
        if (proofHex is null || proofHex.Length != 64) return false;
        byte[] given;
        try { given = Convert.FromHexString(proofHex); }
        catch { return false; }
        var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(token),
            Encoding.UTF8.GetBytes($"{Domain}|{role}|{deviceId}|{peerDeviceId}"));
        return CryptographicOperations.FixedTimeEquals(given, expected);
    }

    public static string HostLine(string deviceId, string token) =>
        $"RELAY1 HOST {deviceId} {Proof(token, "host", deviceId, "")}";

    public static string JoinLine(string clientDeviceId, string targetDeviceId, string token) =>
        $"RELAY1 JOIN {clientDeviceId} {targetDeviceId} {Proof(token, "join", clientDeviceId, targetDeviceId)}";
}

/// <summary>The `relay` rung: dial the configured postman, ask
/// for the target device by id, and — once paired — run the SAME
/// enrollment handshake as every rung over the paired stream.
/// The rendezvous names both devices, so this rung offers no
/// anonymous reachability probe: the bare ConnectAsync refuses by
/// name rather than pairing unauthenticated.</summary>
public sealed class RelayRung : IAuthenticatedRung
{
    private readonly Func<RelayConfig?> _config;
    private readonly EnrollmentService? _enrollments;

    public RelayRung(Func<RelayConfig?> config, EnrollmentService? enrollments = null)
    { _config = config; _enrollments = enrollments; }

    public string Id => "relay";
    public bool IsDormant => ConnectAttempts == 0;
    public int ConnectAttempts { get; private set; }

    public Task<TransportConnectResult> ConnectAsync(TransportTarget target, CancellationToken ct = default) =>
        Task.FromResult(new TransportConnectResult(false,
            "relay: no anonymous probe on this rung — a relay rendezvous names both devices and is proven with per-device tokens, so only an authenticated session connect can use it"));

    public async Task<TransportConnectResult> ConnectSessionAsync(TransportTarget target, DeviceIdentity identity, CancellationToken ct = default)
    {
        ConnectAttempts++;
        var cfg = _config();
        if (cfg is null)
            return new TransportConnectResult(false,
                "relay: not configured — no public relay is set on this device (relay.json names the postman endpoint and this device's rendezvous token)");
        if (string.IsNullOrWhiteSpace(cfg.Token))
            return new TransportConnectResult(false,
                "relay: relay.json carries no rendezvous token for this device — the postman refuses tokenless rendezvous (per-device tokens only)");
        var (host, port) = LanRung.ParseAddress(cfg.Endpoint);
        if (host is null) return new TransportConnectResult(false, $"relay: bad relay endpoint '{cfg.Endpoint}' in relay.json");
        var client = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await client.ConnectAsync(host, port, timeout.Token);
            var result = await ConnectSessionOverStreamAsync(client.GetStream(), cfg, target, identity, client, ct);
            if (!result.Ok) client.Dispose();
            return result;
        }
        catch (Exception ex)
        {
            client.Dispose();
            return new TransportConnectResult(false, $"relay: {ex.GetType().Name}");
        }
    }

    /// <summary>The rendezvous + handshake over an already-connected
    /// stream to the postman (ConnectSessionAsync adds only the TCP
    /// dial). `transport`, when given, is disposed with the session
    /// stream. Public so the pairing can be exercised over any
    /// stream transport in tests.</summary>
    public async Task<TransportConnectResult> ConnectSessionOverStreamAsync(
        Stream stream, RelayConfig cfg, TransportTarget target, DeviceIdentity identity,
        IDisposable? transport = null, CancellationToken ct = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30)); // the JOIN wait is the server's; this bounds OUR leg
            await LanProtocol.WriteLineAsync(stream,
                RelayProtocol.JoinLine(identity.DeviceId, target.DeviceId, cfg.Token), timeout.Token);
            var reply = await LanProtocol.ReadLineAsync(stream, timeout.Token);
            if (reply is null || !reply.StartsWith("RELAY1 PAIRED", StringComparison.Ordinal))
            {
                var reason = reply is not null && reply.StartsWith("RELAY1 ERR ", StringComparison.Ordinal)
                    ? reply["RELAY1 ERR ".Length..] : "the postman closed the rendezvous without pairing";
                return new TransportConnectResult(false, $"relay: rendezvous refused by the postman at {cfg.Endpoint} — {reason}");
            }
            var (ok, detail, channel) = await RungHandshake.RunAsync("relay", stream, identity, _enrollments, target.DeviceId, timeout.Token);
            if (!ok || channel is null) return new TransportConnectResult(false, detail);
            return new TransportConnectResult(true,
                $"relay: connected to {target.DeviceId} via the public postman at {cfg.Endpoint} — the postman paired the rendezvous and forwards bytes it cannot read (the session rides the end-to-end AEAD channel; the postman holds no keys and admits no one)",
                new RelayStreamOwner(channel, transport));
        }
        catch (Exception ex)
        {
            return new TransportConnectResult(false, $"relay: {ex.GetType().Name}");
        }
    }

    private sealed class RelayStreamOwner : Stream
    {
        private readonly Stream _inner; private readonly IDisposable? _transport;
        public RelayStreamOwner(Stream inner, IDisposable? transport) { _inner = inner; _transport = transport; }
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
        protected override void Dispose(bool disposing) { if (disposing) { _inner.Dispose(); _transport?.Dispose(); } base.Dispose(disposing); }
    }
}

/// <summary>The public postman itself: a rendezvous server that
/// pairs one waiting HOST leg per device id with a JOIN leg naming
/// that id, after verifying BOTH legs' per-device token proofs,
/// then forwards bytes blindly until either side closes. It has
/// no other surface: no admin port, no dashboard, no store —
/// pairings exist only in memory and die with the connections.
/// The tap hook exists for the sealing pins and for an operator's
/// own byte accounting; it receives COPIES of forwarded chunks
/// and can neither alter nor delay the stream.</summary>
public sealed class SealedRelayServer : IDisposable
{
    private readonly IReadOnlyDictionary<string, string> _tokens;
    private readonly TimeSpan _hostWaitTimeout;
    private readonly TimeSpan _joinWaitTimeout;
    private readonly Dictionary<string, PendingHost> _waiting = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    private sealed class PendingHost
    {
        public required Stream Stream;
        public required Action Release;
        public readonly TaskCompletionSource<Stream?> Paired = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <param name="tokens">device id → that device's rendezvous
    /// token, issued by whoever operates the postman. A device id
    /// with no token here cannot rendezvous at all.</param>
    /// <param name="tap">Optional observer of forwarded bytes
    /// (direction is "host-to-client" or "client-to-host").</param>
    public SealedRelayServer(IReadOnlyDictionary<string, string> tokens,
        TimeSpan? hostWaitTimeout = null, TimeSpan? joinWaitTimeout = null,
        Action<string, byte[]>? tap = null)
    {
        _tokens = tokens;
        _hostWaitTimeout = hostWaitTimeout ?? TimeSpan.FromMinutes(5);
        _joinWaitTimeout = joinWaitTimeout ?? TimeSpan.FromSeconds(30);
        Tap = tap;
    }

    public Action<string, byte[]>? Tap { get; set; }
    public int Port { get; private set; }
    public int PairedCount { get; private set; }
    public int RefusedCount { get; private set; }

    public void Start(IPAddress address, int port = 0)
    {
        if (_listener is not null) return;
        _listener = new TcpListener(address, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _cts = new CancellationTokenSource();
        _ = AcceptLoopAsync(_cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct); }
            catch { return; }
            _ = HandleSocketLegAsync(client, ct);
        }
    }

    private async Task HandleSocketLegAsync(TcpClient client, CancellationToken ct)
    {
        try { await HandleLegCoreAsync(client.GetStream(), () => { try { client.Dispose(); } catch { } }, ct); }
        catch { try { client.Dispose(); } catch { } }
    }

    /// <summary>One rendezvous leg over any connected stream
    /// (production feeds accepted sockets). `release` disposes the
    /// underlying transport when the leg ends unpaired; a paired
    /// JOIN leg's ownership passes to the pumps instead.</summary>
    public async Task HandleLegCoreAsync(Stream stream, Action release, CancellationToken ct)
    {
        try
        {
            using var lineTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            lineTimeout.CancelAfter(TimeSpan.FromSeconds(15));
            var line = await LanProtocol.ReadLineAsync(stream, lineTimeout.Token);
            var parts = line?.Split(' ') ?? Array.Empty<string>();
            if (parts.Length >= 2 && parts[0] == "RELAY1" && parts[1] == "HOST")
                await HandleHostLegAsync(stream, release, parts, ct);
            else if (parts.Length >= 2 && parts[0] == "RELAY1" && parts[1] == "JOIN")
                await HandleJoinLegAsync(stream, release, parts, ct);
            else { RefusedCount++; release(); }
        }
        catch { try { release(); } catch { } }
    }

    private async Task HandleHostLegAsync(Stream stream, Action release, string[] parts, CancellationToken ct)
    {
        // RELAY1 HOST <deviceId> <proof>
        if (parts.Length != 4 || !_tokens.TryGetValue(parts[2], out var token) ||
            !RelayProtocol.Verify(token, "host", parts[2], "", parts[3]))
        { RefusedCount++; await TryErrAsync(stream, "host rendezvous refused (unknown device or bad token proof)", ct); release(); return; }
        var deviceId = parts[2];
        var pending = new PendingHost { Stream = stream, Release = release };
        lock (_gate)
        {
            if (_waiting.ContainsKey(deviceId))
            { RefusedCount++; _ = TryErrAsync(stream, "a host leg for this device is already waiting", ct); release(); return; }
            _waiting[deviceId] = pending;
        }
        try
        {
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(_hostWaitTimeout);
            var paired = await pending.Paired.Task.WaitAsync(wait.Token);
            if (paired is null) { release(); return; } // server shutting down / replaced
            await PumpBothWaysAsync(stream, paired, ct);
        }
        catch { /* wait timed out or the leg died — the rendezvous is over */ }
        finally
        {
            lock (_gate) { if (_waiting.TryGetValue(deviceId, out var p) && ReferenceEquals(p, pending)) _waiting.Remove(deviceId); }
            try { release(); } catch { }
        }
    }

    private async Task HandleJoinLegAsync(Stream stream, Action release, string[] parts, CancellationToken ct)
    {
        // RELAY1 JOIN <clientDeviceId> <targetDeviceId> <proof>
        if (parts.Length != 5 || !_tokens.TryGetValue(parts[2], out var token) ||
            !RelayProtocol.Verify(token, "join", parts[2], parts[3], parts[4]))
        { RefusedCount++; await TryErrAsync(stream, "join rendezvous refused (unknown device or bad token proof)", ct); release(); return; }
        var targetDeviceId = parts[3];
        PendingHost? pending = null;
        var deadline = DateTimeOffset.UtcNow + _joinWaitTimeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            lock (_gate) { if (_waiting.TryGetValue(targetDeviceId, out var p)) { _waiting.Remove(targetDeviceId); pending = p; } }
            if (pending is not null) break;
            try { await Task.Delay(100, ct); } catch { release(); return; }
        }
        if (pending is null)
        { RefusedCount++; await TryErrAsync(stream, $"no host leg for '{targetDeviceId}' is waiting at this postman", ct); release(); return; }
        try
        {
            await LanProtocol.WriteLineAsync(pending.Stream, $"RELAY1 PAIRED {parts[2]}", ct);
            await LanProtocol.WriteLineAsync(stream, $"RELAY1 PAIRED {targetDeviceId}", ct);
        }
        catch { pending.Paired.TrySetResult(null); release(); return; }
        PairedCount++;
        pending.Paired.TrySetResult(stream);
        // This leg's work is done: ownership of the stream passed
        // to the host leg's pumps via the paired stream.
    }

    /// <summary>Blind forwarding: copy bytes both ways until
    /// either side ends, then close both. The postman's whole
    /// data plane — it parses nothing after the pairing lines.</summary>
    private async Task PumpBothWaysAsync(Stream hostSide, Stream clientSide, CancellationToken ct)
    {
        async Task Pump(Stream from, Stream to, string direction)
        {
            var buffer = new byte[64 * 1024];
            try
            {
                int n;
                while ((n = await from.ReadAsync(buffer, ct)) > 0)
                {
                    Tap?.Invoke(direction, buffer.AsSpan(0, n).ToArray());
                    await to.WriteAsync(buffer.AsMemory(0, n), ct);
                    await to.FlushAsync(ct);
                }
            }
            catch { /* a dead side ends the pairing */ }
        }
        var a = Pump(hostSide, clientSide, "host-to-client");
        var b = Pump(clientSide, hostSide, "client-to-host");
        await Task.WhenAny(a, b);
        // The pairing is over when either direction ends: close
        // both legs so neither peer waits on a dead postman.
        try { hostSide.Dispose(); } catch { }
        try { clientSide.Dispose(); } catch { }
    }

    private static async Task TryErrAsync(Stream stream, string reason, CancellationToken ct)
    {
        try { await LanProtocol.WriteLineAsync(stream, $"RELAY1 ERR {reason}", ct); } catch { }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        lock (_gate)
        {
            foreach (var p in _waiting.Values) { p.Paired.TrySetResult(null); try { p.Release(); } catch { } }
            _waiting.Clear();
        }
    }
}

/// <summary>The host side of the relay: this device dials OUT to
/// the postman and stands as the waiting HOST leg for its own
/// device id, so a peer behind any NAT can rendezvous with it.
/// Each pairing is served by the SAME host-session routine a
/// socket listener serves (LanHostListener.ServeConnectedStreamAsync)
/// — admission is the enrollment handshake, never the rendezvous.
/// One pairing at a time in this first shape; the connector
/// re-registers after every pairing, refusal or drop.</summary>
public sealed class RelayHostConnector
{
    private readonly LanHostListener _server;
    private readonly DeviceIdentity _identity;
    private readonly Func<RelayConfig?> _config;

    public RelayHostConnector(LanHostListener server, DeviceIdentity identity, Func<RelayConfig?> config)
    { _server = server; _identity = identity; _config = config; }

    public bool IsWaiting { get; private set; }
    public int ServedCount { get; private set; }
    public string State { get; private set; } = "not started";

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var cfg = _config();
            if (cfg is null || string.IsNullOrWhiteSpace(cfg.Token))
            {
                State = "dormant — no relay configured on this device (relay.json)";
                IsWaiting = false;
                try { await Task.Delay(TimeSpan.FromSeconds(30), ct); } catch { return; }
                continue;
            }
            try { await RunOneLegAsync(cfg, ct); }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { State = $"relay leg failed ({ex.GetType().Name}) — re-registering"; }
            try { await Task.Delay(TimeSpan.FromSeconds(2), ct); } catch { return; }
        }
    }

    private async Task RunOneLegAsync(RelayConfig cfg, CancellationToken ct)
    {
        var (host, port) = LanRung.ParseAddress(cfg.Endpoint);
        if (host is null) { State = $"relay endpoint '{cfg.Endpoint}' in relay.json is not a valid host:port"; await Task.Delay(TimeSpan.FromSeconds(30), ct); return; }
        using var client = new TcpClient();
        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectTimeout.CancelAfter(TimeSpan.FromSeconds(15));
        await client.ConnectAsync(host, port, connectTimeout.Token);
        await ServeLegOverStreamAsync(client.GetStream(), cfg, ct);
    }

    /// <summary>One host leg over an already-connected stream to
    /// the postman: register as the waiting host, take the
    /// pairing when it comes, serve it through the one host
    /// session routine. RunOneLegAsync adds only the TCP dial.
    /// Public so the leg can be exercised over any stream
    /// transport in tests.</summary>
    public async Task ServeLegOverStreamAsync(Stream stream, RelayConfig cfg, CancellationToken ct)
    {
        await LanProtocol.WriteLineAsync(stream,
            RelayProtocol.HostLine(_identity.DeviceId, cfg.Token), ct);
        State = $"registered at {cfg.Endpoint} — waiting for a rendezvous";
        IsWaiting = true;
        string? reply;
        try
        {
            using var waitTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            waitTimeout.CancelAfter(TimeSpan.FromMinutes(10));
            reply = await LanProtocol.ReadLineAsync(stream, waitTimeout.Token);
        }
        finally { IsWaiting = false; }
        if (reply is null || !reply.StartsWith("RELAY1 PAIRED", StringComparison.Ordinal))
        {
            State = reply is not null && reply.StartsWith("RELAY1 ERR ", StringComparison.Ordinal)
                ? $"postman refused the host leg — {reply["RELAY1 ERR ".Length..]}"
                : "host leg ended without a pairing";
            return;
        }
        State = "paired — serving the session";
        if (await _server.ServeConnectedStreamAsync(stream, ct)) ServedCount++;
        State = "pairing served — re-registering";
    }
}

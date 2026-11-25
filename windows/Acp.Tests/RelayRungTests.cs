using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Acp.Shared.Transport;

namespace Acp.Tests;

/// <summary>FR-131 — the `relay` rung and the sealed postman:
/// rendezvous proofs bind role/device/peer, bad proofs and absent
/// hosts refuse by name, an end-to-end session rides the pairing
/// through the SAME enrollment handshake + AEAD channel as every
/// rung, and the postman's own view of that session is metadata
/// only (device ids visible; session content never in the clear).
/// The full flow is pinned over in-memory streams through the
/// components' connected-stream seams, so the proof does not
/// depend on socket availability; one socket smoke test covers
/// the TcpListener wiring itself.</summary>
public class RelayRungTests
{
    private static RelayConfig Cfg(int port, string token) => new($"127.0.0.1:{port}", token);
    private static RelayConfig Cfg(string token) => new("postman.test:9000", token);

    /// <summary>A connected pair of in-memory streams: what A
    /// writes, B reads, and vice versa. Stands in for the two TCP
    /// connections to the postman in the seam-level proofs.</summary>
    private sealed class PipeEnd : Stream
    {
        private readonly Queue<byte> _inbox = new();
        private readonly SemaphoreSlim _signal = new(0);
        private readonly object _gate = new();
        private bool _closed;
        private PipeEnd _peer = null!;

        public static (PipeEnd A, PipeEnd B) Pair()
        {
            var a = new PipeEnd(); var b = new PipeEnd();
            a._peer = b; b._peer = a;
            return (a, b);
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            while (true)
            {
                lock (_gate)
                {
                    if (_inbox.Count > 0)
                    {
                        var n = Math.Min(buffer.Length, _inbox.Count);
                        for (var i = 0; i < n; i++) buffer.Span[i] = _inbox.Dequeue();
                        return n;
                    }
                    if (_closed) return 0;
                }
                await _signal.WaitAsync(ct);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            var bytes = buffer.ToArray();
            lock (_peer._gate) { foreach (var b in bytes) _peer._inbox.Enqueue(b); }
            _peer._signal.Release();
            return ValueTask.CompletedTask;
        }

        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override void Flush() { }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count), default).AsTask().GetAwaiter().GetResult();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count), default).AsTask().GetAwaiter().GetResult();
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (_peer._gate) _peer._closed = true;
                _peer._signal.Release();
            }
            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task RelayRung_Unconfigured_RefusesByName()
    {
        var w = TransportTests.Setup(new[] { "relay" });
        var rung = new RelayRung(() => null, w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, ""), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not configured", result.Detail);
    }

    [Fact]
    public async Task RelayRung_BareProbe_RefusedByName()
    {
        var w = TransportTests.Setup(new[] { "relay" });
        var rung = new RelayRung(() => Cfg(1, "t"), w.Enrollments);
        var result = await rung.ConnectAsync(new TransportTarget(w.DeviceId, ""));
        Assert.False(result.Ok);
        Assert.Contains("no anonymous probe", result.Detail);
    }

    [Fact]
    public void RelayProof_BindsRoleDevicePeerAndToken()
    {
        var proof = RelayProtocol.Proof("tok", "join", "dev-a", "dev-b");
        Assert.True(RelayProtocol.Verify("tok", "join", "dev-a", "dev-b", proof));
        Assert.False(RelayProtocol.Verify("tok", "host", "dev-a", "dev-b", proof));   // role is bound
        Assert.False(RelayProtocol.Verify("tok", "join", "dev-a", "dev-c", proof));   // peer is bound
        Assert.False(RelayProtocol.Verify("tok", "join", "dev-x", "dev-b", proof));   // device is bound
        Assert.False(RelayProtocol.Verify("other", "join", "dev-a", "dev-b", proof)); // token is the key
        Assert.False(RelayProtocol.Verify("tok", "join", "dev-a", "dev-b", "zz"));    // malformed refuses
        Assert.False(RelayProtocol.Verify("tok", "join", "dev-a", "dev-b", null));
    }

    [Fact]
    public async Task SealedRelay_BadHostProof_RefusedAndCounted()
    {
        using var server = new SealedRelayServer(new Dictionary<string, string> { ["dev-h"] = "right" });
        var (mine, theirs) = PipeEnd.Pair();
        using var cts = new CancellationTokenSource();
        var leg = server.HandleLegCoreAsync(theirs, () => theirs.Dispose(), cts.Token);
        await LanProtocol.WriteLineAsync(mine, "RELAY1 HOST dev-h deadbeef", default);
        var reply = await LanProtocol.ReadLineAsync(mine, default);
        Assert.NotNull(reply);
        Assert.Contains("RELAY1 ERR", reply);
        Assert.Equal(1, server.RefusedCount);
        Assert.Equal(0, server.PairedCount);
        cts.Cancel();
        try { await leg; } catch { /* ended by the refusal */ }
    }

    [Fact]
    public async Task SealedRelay_JoinForAbsentHost_RefusedByName()
    {
        using var server = new SealedRelayServer(
            new Dictionary<string, string> { ["dev-c"] = "tok-c", ["dev-h"] = "tok-h" },
            joinWaitTimeout: TimeSpan.FromMilliseconds(300));
        var (mine, theirs) = PipeEnd.Pair();
        using var cts = new CancellationTokenSource();
        var leg = server.HandleLegCoreAsync(theirs, () => theirs.Dispose(), cts.Token);
        await LanProtocol.WriteLineAsync(mine, RelayProtocol.JoinLine("dev-c", "dev-h", "tok-c"), default);
        var reply = await LanProtocol.ReadLineAsync(mine, default);
        Assert.NotNull(reply);
        Assert.Contains("no host leg", reply);
        Assert.Equal(0, server.PairedCount);
        cts.Cancel();
        try { await leg; } catch { /* ended by the refusal */ }
    }

    [Fact]
    public async Task Relay_EndToEnd_SessionRidesPairing_PostmanSeesMetadataOnly()
    {
        var w = TransportTests.Setup(new[] { "relay" });
        var tokens = new Dictionary<string, string>
        {
            [w.DeviceId] = "host-token",
            [w.OperatorIdentity.DeviceId] = "op-token",
        };
        var tapped = new ConcurrentBag<byte[]>();
        using var server = new SealedRelayServer(tokens,
            hostWaitTimeout: TimeSpan.FromSeconds(30), joinWaitTimeout: TimeSpan.FromSeconds(5),
            tap: (_, chunk) => tapped.Add(chunk));
        using var cts = new CancellationTokenSource();

        // The postman's two legs, fed over pipes: HOST from the
        // host device's connector, JOIN from the operator's rung.
        var (hostSide, serverHostSide) = PipeEnd.Pair();
        var (joinSide, serverJoinSide) = PipeEnd.Pair();
        var hostLeg = server.HandleLegCoreAsync(serverHostSide, () => serverHostSide.Dispose(), cts.Token);
        var joinLeg = server.HandleLegCoreAsync(serverJoinSide, () => serverJoinSide.Dispose(), cts.Token);

        // The host device: its LAN listener serves the paired
        // stream directly (ServeConnectedStreamAsync).
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        var connector = new RelayHostConnector(listener, w.HostIdentity, () => Cfg("host-token"));
        var serveLeg = connector.ServeLegOverStreamAsync(hostSide, Cfg("host-token"), cts.Token);
        var waited = 0;
        while (!connector.IsWaiting && waited < 5000) { await Task.Delay(25); waited += 25; }
        Assert.True(connector.IsWaiting, "host leg never registered at the postman");

        var rung = new RelayRung(() => Cfg("op-token"), w.Enrollments);
        var result = await rung.ConnectSessionOverStreamAsync(
            joinSide, Cfg("op-token"), new TransportTarget(w.DeviceId, ""), w.OperatorIdentity, null, cts.Token);
        Assert.True(result.Ok, result.Detail);
        Assert.Contains("cannot read", result.Detail);
        Assert.Equal(1, server.PairedCount);
        Assert.Equal(1, listener.AcceptedSessions);

        // The session protocol works over the pairing.
        await LanProtocol.WriteLineAsync(result.Stream!, "PING", default);
        var pong = await LanProtocol.ReadLineAsync(result.Stream!, default);
        Assert.Equal("PONG", pong);

        // The postman's tap: device ids (rendezvous metadata) are
        // visible; the session's content never appears in clear.
        var seen = Encoding.ASCII.GetString(tapped.SelectMany(b => b).ToArray());
        Assert.Contains(w.DeviceId, seen);
        Assert.DoesNotContain("PING", seen);
        Assert.DoesNotContain("PONG", seen);

        result.Stream!.Dispose();
        await serveLeg.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(1, connector.ServedCount);
        cts.Cancel();
        try { await Task.WhenAll(hostLeg, joinLeg); } catch { /* legs end with the pairing */ }
    }

    [Fact]
    public async Task RelayHostConnector_NoConfig_StaysDormant()
    {
        var w = TransportTests.Setup(new[] { "relay" });
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        var connector = new RelayHostConnector(listener, w.HostIdentity, () => null);
        using var cts = new CancellationTokenSource();
        var run = connector.RunAsync(cts.Token);
        await Task.Delay(250);
        Assert.False(connector.IsWaiting);
        Assert.Contains("dormant", connector.State);
        cts.Cancel();
        try { await run; } catch { /* cancellation is the expected end */ }
    }

    [Fact]
    public async Task SealedRelay_SocketSmoke_BadProofRefusedOverTcp()
    {
        using var server = new SealedRelayServer(new Dictionary<string, string> { ["dev-h"] = "right" });
        server.Start(IPAddress.Loopback, 0);
        Assert.True(server.Port > 0);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port);
        var stream = client.GetStream();
        await LanProtocol.WriteLineAsync(stream, "RELAY1 HOST dev-h deadbeef", default);
        var reply = await LanProtocol.ReadLineAsync(stream, default);
        Assert.NotNull(reply);
        Assert.Contains("RELAY1 ERR", reply);
        Assert.Equal(1, server.RefusedCount);
    }
}

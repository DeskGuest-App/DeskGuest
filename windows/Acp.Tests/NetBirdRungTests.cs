using System.Net;
using Acp.Shared.Tailscale;
using Acp.Shared.Transport;

namespace Acp.Tests;

/// <summary>FR-132 — the `netbird` rung: the borrowed-mesh shape.
/// Refusals name the missing condition (not installed / not
/// connected under the OWNER's own account), the address gates
/// match `mesh` discipline (mesh range + known peer when the
/// client reports its set), and a live session rides the same
/// enrollment handshake. The probe is seamed: exercising the rung
/// against a real account is the owner's act, not a test's.</summary>
public class NetBirdRungTests
{
    private static NetBirdProbeResult Ready(string[]? peers = null) => new(
        NetBirdReadiness.Ready, new[] { "100.64.0.5" }, peers, "owner's NetBird client connected");

    [Fact]
    public async Task NetBird_NotInstalled_RefusesByName()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        var rung = new NetBirdRung(
            () => new NetBirdProbeResult(NetBirdReadiness.NotInstalled, Array.Empty<string>(), null, "no client"),
            w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "100.64.0.9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not installed", result.Detail);
        Assert.Contains("YOUR OWN NetBird account", result.Detail);
        Assert.Contains("never required", result.Detail);
    }

    [Fact]
    public async Task NetBird_NotConnected_RefusesByName()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        var rung = new NetBirdRung(
            () => new NetBirdProbeResult(NetBirdReadiness.NotConnected, Array.Empty<string>(), null, "client is installed but not connected"),
            w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "100.64.0.9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not connected", result.Detail);
    }

    [Fact]
    public async Task NetBird_ProbeFailure_RefusesClosed()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        var rung = new NetBirdRung(() => throw new InvalidOperationException("boom"), w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "100.64.0.9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("probe failed", result.Detail);
    }

    [Fact]
    public async Task NetBird_LanAddress_RefusedByTheRangeGate()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        var rung = new NetBirdRung(() => Ready(), w.Enrollments); // production address gate
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "192.168.1.20"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not a mesh-range", result.Detail);
    }

    [Fact]
    public async Task NetBird_UnknownPeerInRange_RefusedByThePeerGate()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        var rung = new NetBirdRung(() => Ready(new[] { "100.64.0.9" }), w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "100.64.0.77"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("NOT a peer", result.Detail);
    }

    [Fact]
    public async Task NetBird_LiveSession_OverTheOwnersMesh()
    {
        var w = TransportTests.Setup(new[] { "netbird" });
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // Socket leg on loopback via the range-gate seam
        // (MeshRung's own test discipline); the production range
        // gate and the known-peer gate are pinned separately
        // above (the peer helper itself requires a mesh-range
        // host, so it cannot combine with a loopback target).
        var rung = new NetBirdRung(() => Ready(), w.Enrollments, _ => true);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, $"127.0.0.1:{listener.Port}"), w.OperatorIdentity);
        Assert.True(result.Ok, result.Detail);
        Assert.Contains("NetBird", result.Detail);
        Assert.Equal(1, listener.AcceptedSessions);
        await LanProtocol.WriteLineAsync(result.Stream!, "PING", default);
        Assert.Equal("PONG", await LanProtocol.ReadLineAsync(result.Stream!, default));
        result.Stream!.Dispose();
    }
}

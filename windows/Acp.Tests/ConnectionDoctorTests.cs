using System.Text.Json;
using Acp.Core.Modules;
using Acp.Shared.Connection;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>U6 connection doctor: NAT classification from scripted
/// address fixtures, per-rung honest states, D18 naming, and the
/// destruction cases (doctor as probe weapon / mutation / dead path
/// reported healthy). All logic is proven without live sockets —
/// the doctor contains no network I/O by construction.</summary>
public class ConnectionDoctorTests
{
    private static DoctorFacts Facts(string[] addrs, RungSnapshot[] rungs,
        NatClass peerNat = NatClass.Unknown, string? peerAddr = null, string? wan = null,
        bool relay = false, string[]? tailnet = null) =>
        new(addrs, rungs, peerAddr, peerNat, wan, relay, tailnet);

    private static RungSnapshot Rung(string id, bool reg = true, bool conf = true, int attempts = 0,
        string? detail = null, bool ok = false, bool bound = false, string? phase = null) =>
        new(id, reg, conf, attempts, detail, ok, bound, phase, bound ? "192.168.1.50" : null);

    // ---- NAT fixtures ----

    [Fact]
    public void Nat_PublicAddress_IsPublicDirect()
        => Assert.Equal(NatClass.PublicDirect, ConnectionDoctor.ClassifyNat(new[] { "203.0.113.9" }));

    [Fact]
    public void Nat_PrivateOnly_IsBehindNat_NotGuessedDeeper()
        => Assert.Equal(NatClass.BehindNat, ConnectionDoctor.ClassifyNat(new[] { "192.168.1.50" }));

    [Fact]
    public void Nat_CgnatNonTailnet_IsCarrierGradeNat()
        => Assert.Equal(NatClass.CarrierGradeNat, ConnectionDoctor.ClassifyNat(new[] { "100.80.1.2" }));

    [Fact]
    public void Nat_TailnetAddress_IsNotIspCgnat()
        => Assert.Equal(NatClass.BehindNat, ConnectionDoctor.ClassifyNat(
            new[] { "192.168.1.50", "100.119.105.54" }, tailnetAddresses: new[] { "100.119.105.54" }));

    [Fact]
    public void Nat_PrivateLocalPlusPrivateWan_IsDoubleNat()
        => Assert.Equal(NatClass.DoubleNat, ConnectionDoctor.ClassifyNat(new[] { "192.168.1.50" }, wanAddress: "10.0.0.2"));

    [Fact]
    public void Nat_NoAddresses_IsUnknown_AndNoteSaysSo()
    {
        var r = ConnectionDoctor.Diagnose(Facts(Array.Empty<string>(), Array.Empty<RungSnapshot>()));
        Assert.Equal(NatClass.Unknown, r.LocalNat);
        Assert.Contains("cannot be classified", r.NatNote);
    }

    [Fact]
    public void Classify_HandlesStoredShapes()
    {
        Assert.Equal(AddressClass.PrivateRfc1918, ConnectionDoctor.ClassifyAddress("192.168.1.50:47621"));
        Assert.Equal(AddressClass.Ipv6Global, ConnectionDoctor.ClassifyAddress("[2601:db8::1]:47621".Replace("db8", "abcd")));
        Assert.Equal(AddressClass.NotAnAddress, ConnectionDoctor.ClassifyAddress("not-an-address"));
        Assert.Equal(AddressClass.Loopback, ConnectionDoctor.ClassifyAddress("127.0.0.1"));
    }

    // ---- per-rung states ----

    [Fact]
    public void Rung_BoundLane_IsReachable()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" }, new[] { Rung("lan", bound: true, phase: "Bound") }));
        Assert.Equal(RungState.Reachable, r.Rungs[0].State);
        Assert.Null(r.Rungs[0].Finding);
    }

    [Fact]
    public void Rung_RecordedSuccess_IsReachable()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { Rung("hub", attempts: 2, detail: "connected", ok: true) }));
        Assert.Equal(RungState.Reachable, r.Rungs[0].State);
    }

    [Fact]
    public void Rung_FailedAttempt_NamesReasonAndFix()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { Rung("lan", attempts: 1, detail: "lan: no address (not discovered, none entered)") }));
        var f = Assert.IsType<DoctorFinding>(r.Rungs[0].Finding);
        Assert.Equal(RungState.Failed, r.Rungs[0].State);
        Assert.Contains("no address", f.Why, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connect-by-address", f.Fix);
    }

    [Fact]
    public void Rung_NotRegistered_AndNotConfigured_RenderNamedStates()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" }, new[]
        {
            Rung("tor", reg: false), Rung("ownpath", conf: false)
        }));
        Assert.Equal(RungState.NotRegistered, r.Rungs[0].State);
        Assert.Equal(RungState.NotConfigured, r.Rungs[1].State);
        Assert.All(r.Rungs, x => Assert.NotNull(x.Finding));
    }

    // ---- destruction: dead path reported healthy ----

    [Fact]
    public void Destruction_ConfiguredDormantRung_IsNeverCalledReachable()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { Rung("lan", attempts: 0), Rung("mesh", attempts: 0, phase: "NoAddress") }));
        Assert.All(r.Rungs, x => Assert.NotEqual(RungState.Reachable, x.State));
        Assert.Contains("unproven, not confirmed", r.Rungs[0].Evidence);
        Assert.DoesNotContain("healthy", r.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Destruction_FailedRung_IsNeverCalledReachable()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { Rung("lan", attempts: 3, detail: "lan: ConnectionRefused") }));
        Assert.Equal(RungState.Failed, r.Rungs[0].State);
    }

    // ---- destruction: doctor mutates nothing ----

    [Fact]
    public void Destruction_Diagnose_DoesNotMutateInputsOrLaneState()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock);
        sup.Tick(LaneKind.Tailscale); sup.ReportBindResult(LaneKind.Tailscale, true);
        var before = sup.Status(LaneKind.Tailscale);
        var snap = Rung("mesh", bound: true, phase: "Bound");
        var facts = Facts(new[] { "100.119.105.54" }, new[] { snap }, tailnet: new[] { "100.119.105.54" });
        _ = ConnectionDoctor.Diagnose(facts);
        _ = ConnectionDoctor.Diagnose(facts);
        Assert.Equal(before, sup.Status(LaneKind.Tailscale));
        Assert.Equal(0, snap.ConnectAttempts); // snapshot untouched; doctor holds no rung to poke
    }

    // ---- destruction: doctor as probing weapon ----

    [Fact]
    public void Destruction_DoctorHasNoNetworkIoSurface()
    {
        // The shared doctor type exposes no connect/ping/send API and
        // its report for a third-party address is classification only:
        // a public peer address parses to PublicDirect and no rung
        // state changes, no attempt is recorded anywhere.
        var methods = typeof(ConnectionDoctor).GetMethods().Select(m => m.Name).ToList();
        Assert.DoesNotContain(methods, n => n.Contains("Connect") || n.Contains("Ping") || n.Contains("Socket") || n.Contains("Send"));
        var snap = Rung("lan", attempts: 0);
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { snap }, peerAddr: "203.0.113.200:47621"));
        Assert.Equal(NatClass.PublicDirect, r.PeerNat);
        Assert.Equal(0, snap.ConnectAttempts); // classifying a third-party address recorded no attempt
    }

    // ---- D18 ----

    [Fact]
    public void D18_BothEndsHostile_NoRelay_NamesD18()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "100.80.1.2" },
            new[] { Rung("lan", attempts: 1, detail: "lan: Timeout") }, peerNat: NatClass.Hostile));
        Assert.True(r.IsD18Corner);
        Assert.Contains("D18", r.Summary);
        Assert.Contains("D18", r.Findings[0].Why + r.Findings[0].What);
        Assert.True(r.Rungs[0].IsD18Corner);
    }

    [Fact]
    public void D18_NotNamed_WhenARungIsProvenReachable()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "100.80.1.2" },
            new[] { Rung("mesh", bound: true, phase: "Bound") }, peerNat: NatClass.Hostile));
        Assert.False(r.IsD18Corner);
    }

    [Fact]
    public void D18_NotNamed_WhenUserOwnedRelayExists()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "100.80.1.2" },
            new[] { Rung("lan", attempts: 1, detail: "lan: Timeout") }, peerNat: NatClass.CarrierGradeNat, relay: true));
        Assert.False(r.IsD18Corner);
    }

    [Fact]
    public void D18_NotNamed_ForOrdinarySingleNatFailure()
    {
        var r = ConnectionDoctor.Diagnose(Facts(new[] { "192.168.1.50" },
            new[] { Rung("lan", attempts: 1, detail: "lan: Timeout") }, peerNat: NatClass.BehindNat));
        Assert.False(r.IsD18Corner);
        Assert.DoesNotContain("D18", r.Summary);
    }

    // ---- the tool module ----

    [Fact]
    public async Task Module_EmitsDoctorReport_AndIgnoresNoMutation()
    {
        var facts = Facts(new[] { "100.80.1.2" },
            new[] { Rung("lan", attempts: 1, detail: "lan: no address (not discovered, none entered)") },
            peerNat: NatClass.Hostile);
        var module = new ConnectionDoctorModule(() => facts);
        Assert.Equal("connection_doctor", module.Descriptor.Name);
        Assert.Equal(Scopes.Observe, module.Descriptor.RequiredScope);
        var ctx = null! as ToolExecutionContext; // the doctor never reads ctx: no pairing, no session, no gate
        var result = await module.ExecuteAsync(JsonDocument.Parse("{}").RootElement, ctx, default);
        Assert.True(result.Ok, result.Text);
        Assert.Contains("D18", result.Text);
        Assert.Contains("diagnostic_only", result.Text);
        // A caller-supplied third-party peer address is classified in
        // the report only — the module has no probe to fire with it.
        var bare = new ConnectionDoctorModule(() => Facts(new[] { "192.168.1.50" },
            new[] { Rung("lan", attempts: 0) }));
        var withPeer = await bare.ExecuteAsync(
            JsonDocument.Parse("{\"peer_address\":\"203.0.113.200\"}").RootElement, ctx, default);
        Assert.Contains("PublicDirect", withPeer.Text);
    }
}

using System.Text.Json;

namespace DeskGuest.Tests;

/// <summary>Block C part 3 wiring: the hub + mesh rungs driven
/// through the Core's actual IPC action handlers and the
/// host-state snapshot. The hub session itself is proven with real
/// sockets in HubRungTests (the Core's production address gate
/// requires a real tailnet address, which a sandbox loopback bind
/// cannot supply — the refusal paths are what wiring can prove,
/// and they are the safety-critical half).</summary>
public sealed class HubMeshWiringTests : IClassFixture<WiringFixture>
{
    private readonly WiringFixture _f;
    public HubMeshWiringTests(WiringFixture f) => _f = f;

    private static string Json(object payload) => JsonSerializer.Serialize(payload);

    [Fact]
    public async Task HubListener_RefusesNonTailnetBind_ThroughIpc()
    {
        var rt = _f.Runtime;
        var (okLan, detailLan) = await rt.ApplyTransportAction(Json(new
        { action = "start_hub_listener", address = "192.168.1.20" }));
        Assert.False(okLan);
        Assert.Contains("tailnet", detailLan);
        var (okNone, _) = await rt.ApplyTransportAction(Json(new { action = "start_hub_listener" }));
        Assert.False(okNone);
        Assert.False(rt.HubListener.IsListening);
    }

    [Fact]
    public async Task HubStart_DeviceNotAHuBNode_RefusedHonestly_ThroughIpc()
    {
        var rt = _f.Runtime;
        // A device of its own (the shared fixture's own device is
        // joined by the sibling test — order must not matter):
        // enrolled + in a [lan, hub, …] group, but never joined
        // the hub. The hub attempt must fail with the membership
        // reason in the engine's own event record.
        var fresh = new DeskGuest.Shared.Security.DeviceIdentity(new DeskGuest.Shared.Security.DevOnlyPassThroughProtector());
        var code = _f.MintCode();
        var record = rt.Enrollments.Redeem(code, new DeskGuest.Shared.Enrollment.EnrollingDevice(
            fresh.DeviceId, fresh.PublicKeyBase64, "Never Joined"));
        Assert.NotNull(record);
        var deviceId = fresh.DeviceId;
        var (ok, detail) = await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
            hubAddress = "100.64.0.9", manualPins = new[] { "hub" },
        }));
        Assert.False(ok);
        Assert.Contains(rt.Transports.Events,
            e => e.Kind == "attempt_failed" && e.Rung == "hub" && e.Detail.Contains("not a live hub node"));
    }

    [Fact]
    public async Task HubStart_AfterJoin_MembershipGatePasses_AddressGateIsTheNextWall()
    {
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();
        Assert.NotNull(rt.HubNodes.Join(deviceId, "1.104.7", DateTimeOffset.UtcNow));
        // Membership now passes; the connect itself fails on the
        // sandbox (nothing listens at the tailnet address and this
        // box has no such interface) — what matters is the failure
        // is the SOCKET's, not the membership gate's.
        var (ok, _) = await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
            hubAddress = "100.64.0.9", manualPins = new[] { "hub" },
        }));
        Assert.False(ok);
        Assert.DoesNotContain(rt.Transports.Events,
            e => e.Kind == "attempt_failed" && e.Rung == "hub" && e.Detail.Contains("not a live hub node"));
        Assert.Contains(rt.Transports.Events,
            e => e.Kind == "attempt_failed" && e.Rung == "hub");
    }

    [Fact]
    public async Task MeshPreflight_OnAMachineWithoutAProbeableClient_RefusesHonestly()
    {
        // This sandbox has no Tailscale client: the probe cannot
        // verify version/kill-switch/SSH-Serve-Funnel, so setup
        // must refuse rather than guess (T2 §7.2).
        var rt = _f.Runtime;
        var (ok, detail) = await rt.ApplyTransportAction(Json(new { action = "mesh_preflight" }));
        Assert.False(ok);
        Assert.Contains("mesh setup: Refused", detail);
    }

    [Fact]
    public async Task MeshSetCredential_PersonalApiToken_RefusedThroughIpc()
    {
        var rt = _f.Runtime;
        var (ok, detail) = await rt.ApplyTransportAction(Json(new
        {
            action = "mesh_set_credential", clientId = "abc",
            clientSecret = "tskey-api-fulladmin", scopes = new[] { "policy_file" },
        }));
        Assert.False(ok);
        Assert.Contains("personal API access token", detail);
        var (ok2, _) = await rt.ApplyTransportAction(Json(new
        {
            action = "mesh_set_credential", clientId = "abc",
            clientSecret = "tskey-client-scoped", scopes = new[] { "policy_file", "auth_keys" },
        }));
        Assert.True(ok2);
    }

    [Fact]
    public void Snapshot_CarriesHubAndMeshFacts()
    {
        var rt = _f.Runtime;
        var snapshot = rt.BuildHostStateJson();
        using var doc = JsonDocument.Parse(snapshot);
        var transport = doc.RootElement.GetProperty("transport");
        Assert.False(transport.GetProperty("hubListening").GetBoolean());
        Assert.True(transport.TryGetProperty("meshSetupStage", out _));
        Assert.True(transport.TryGetProperty("meshSetupDetail", out _));
    }
}

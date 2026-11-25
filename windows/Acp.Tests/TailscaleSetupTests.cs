using System.Net;
using Acp.Shared.Enrollment;
using Acp.Shared.Security;
using Acp.Shared.Tailscale;
using Acp.Shared.Transport;

namespace Acp.Tests;

/// <summary>Block C part 3 — in-app Tailscale setup (D4) against
/// the T2 audit's binding conditions, proven on ACP's side of the
/// sign-in boundary with a local mock of the vendor API. The live
/// account leg is UNPROVEN by programme law (no external accounts,
/// no signing in as anyone) and is not simulated here as if real:
/// the mock stands in for the API surface only.</summary>
public class TailscaleSetupTests
{
    private sealed class FakeProbe : ITailscaleDaemonProbe
    {
        public TailscaleDaemonFacts Facts = new("1.104.7", "disabled-no-logs", false, false, false, false);
        public TailscaleDaemonFacts Probe() => Facts;
    }

    private sealed class MockApi : ITailscaleApi
    {
        public string Policy = "{\"acls\": []}";
        public bool FailValidate, FailApply, FailExchange;
        public int ExchangeCalls, ApplyCalls;
        public string? LastApplied;
        public bool? LastKeySingleUse; public TimeSpan LastKeyExpiry; public IReadOnlyList<string>? LastKeyTags;

        public Task<ApiResult> ExchangeOAuthAsync(string clientId, string clientSecret, IReadOnlyList<string> scopes, CancellationToken ct = default)
        { ExchangeCalls++; return Task.FromResult(FailExchange ? new ApiResult(false, "mock exchange failure") : new ApiResult(true, "ok", Token: "mock-token-1h")); }
        public Task<ApiResult> ExchangeFederatedAsync(IReadOnlyList<string> scopes, CancellationToken ct = default) =>
            Task.FromResult(new ApiResult(true, "ok", Token: "mock-fed-token"));
        public Task<ApiResult> GetPolicyAsync(string token, CancellationToken ct = default) =>
            Task.FromResult(new ApiResult(true, "ok", Policy: Policy));
        public Task<ApiResult> ValidatePolicyAsync(string token, string policy, CancellationToken ct = default) =>
            Task.FromResult(FailValidate ? new ApiResult(false, "mock: policy invalid") : new ApiResult(true, "valid"));
        public Task<ApiResult> ApplyPolicyAsync(string token, string policy, CancellationToken ct = default)
        {
            ApplyCalls++;
            if (FailApply) { FailApply = false; return Task.FromResult(new ApiResult(false, "mock apply failure (one-shot)")); }
            LastApplied = policy; Policy = policy;
            return Task.FromResult(new ApiResult(true, "applied"));
        }
        public Task<ApiResult> CreateAuthKeyAsync(string token, IReadOnlyList<string> tags, bool singleUse, TimeSpan expiry, CancellationToken ct = default)
        {
            LastKeySingleUse = singleUse; LastKeyExpiry = expiry; LastKeyTags = tags;
            return Task.FromResult(new ApiResult(true, "minted", AuthKey: "tskey-auth-mock"));
        }
    }

    private static TailnetMapping Mapping() => new(
        UserGroups: new Dictionary<string, IReadOnlyList<string>> { ["techs"] = new[] { "alice", "bob" } },
        DeviceGroups: new[] { "fleet" },
        EnrollRights: new Dictionary<string, IReadOnlyList<string>> { ["fleet"] = new[] { "techs" } },
        Grants: new[] { new TailnetGrant("techs", "fleet", new[] { "47621" }) });

    private static MeshSetupService Setup(MockApi api, FakeProbe probe) =>
        new(probe, api, new DevOnlyPassThroughProtector());

    private static void SetGoodCredential(MeshSetupService svc) =>
        Assert.True(svc.Broker.SetCredential("client-id", "tskey-client-secret",
            new[] { "policy_file", "auth_keys", "devices:core:read" }).Ok);

    // ---- TS-05: credential-scope confusion -----------------------

    [Fact]
    public void CredentialGuard_PersonalApiToken_RefusedByShape()
    {
        var cls = TailscaleCredentialGuard.Classify("tskey-api-abc123");
        Assert.Equal(CredentialClass.PersonalApiToken, cls);
        var verdict = TailscaleCredentialGuard.AcceptForStorage("tskey-api-abc123", new[] { "policy_file" });
        Assert.False(verdict.Ok);
        Assert.Contains("personal API access token", verdict.Detail);
    }

    [Fact]
    public void CredentialGuard_ScopedOAuth_Accepted_PersonalTokenRefusedAtTheBroker()
    {
        var svc = Setup(new MockApi(), new FakeProbe());
        Assert.False(svc.Broker.SetCredential("id", "tskey-api-full-admin", new[] { "policy_file" }).Ok);
        SetGoodCredential(svc);
        Assert.False(svc.Broker.SetCredential("id", "tskey-client-x", Array.Empty<string>()).Ok); // scopeless refused
        Assert.False(svc.Broker.SetCredential("id", "totally-bogus", new[] { "policy_file" }).Ok);
    }

    [Fact]
    public async Task Broker_ExchangesOnceAndCachesTheHourToken()
    {
        var api = new MockApi();
        var svc = Setup(api, new FakeProbe());
        SetGoodCredential(svc);
        var now = DateTimeOffset.UtcNow;
        var t1 = await svc.Broker.GetTokenAsync(now);
        var t2 = await svc.Broker.GetTokenAsync(now.AddMinutes(30));
        Assert.True(t1.Ok); Assert.True(t2.Ok);
        Assert.Equal(1, api.ExchangeCalls);
        var t3 = await svc.Broker.GetTokenAsync(now.AddMinutes(61));
        Assert.True(t3.Ok);
        Assert.Equal(2, api.ExchangeCalls); // expired cache re-exchanges
    }

    // ---- TS-01/02: kill switch -----------------------------------

    [Fact]
    public void KillSwitch_UnassertedDaemon_RefusesTheRung()
    {
        var probe = new FakeProbe { Facts = new("1.104.7", "uploading", false, false, false, false) };
        var svc = Setup(new MockApi(), probe);
        var st = svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator);
        Assert.Equal(MeshSetupStage.Refused, st.Stage);
        Assert.Contains("log pipeline", st.Detail);
    }

    [Fact]
    public void KillSwitch_LaunchPlan_AssertsFromFirstStart()
    {
        Assert.True(TailscaleDaemonLaunchPlan.PlanAssertsKillSwitch(
            TailscaleDaemonLaunchPlan.Environment(), TailscaleDaemonLaunchPlan.DaemonArguments()));
        Assert.Equal("true", TailscaleDaemonLaunchPlan.Environment()["TS_NO_LOGS_NO_SUPPORT"]);
        Assert.Equal("1", TailscaleDaemonLaunchPlan.Environment()["TS_SSH_DISABLE_FORWARDING"]);
    }

    [Fact]
    public void KillSwitch_UnreliableProbe_RefusesRatherThanGuesses()
    {
        var probe = new FakeProbe { Facts = new("1.104.7", "disabled-no-logs", false, false, false, false, ProbeReliable: false) };
        var svc = Setup(new MockApi(), probe);
        Assert.Equal(MeshSetupStage.Refused, svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator).Stage);
    }

    // ---- client floor (HS-03 / TS floor) --------------------------

    [Theory]
    [InlineData("1.90.0", false)]
    [InlineData("1.104.3", false)]
    [InlineData("1.104.4", true)]
    [InlineData("1.104.7", true)]
    [InlineData(null, false)]
    [InlineData("garbage", false)]
    public void ClientFloor_EnforcedAtSetup(string? version, bool admitted)
    {
        var probe = new FakeProbe { Facts = new(version, "disabled-no-logs", false, false, false, false) };
        var svc = Setup(new MockApi(), probe);
        var st = svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator);
        Assert.Equal(admitted, st.Stage == MeshSetupStage.AwaitingSignIn);
    }

    // ---- no SSH / Serve / Funnel (TS-10) --------------------------

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void SshServeFunnel_AnyOn_RefusesSetup(bool ssh, bool serve, bool funnel)
    {
        var probe = new FakeProbe { Facts = new("1.104.7", "disabled-no-logs", ssh, serve, funnel, false) };
        var svc = Setup(new MockApi(), probe);
        Assert.Equal(MeshSetupStage.Refused, svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator).Stage);
    }

    // ---- role gates + mobile carve-out (D3 / TS-03) ---------------

    [Fact]
    public void EndpointRole_NeverOfferedMesh_OnAnyPlatform()
    {
        var svc = Setup(new MockApi(), new FakeProbe());
        Assert.Equal(MeshSetupStage.Refused, svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Endpoint).Stage);
        Assert.Equal(MeshSetupStage.Refused, svc.RunPreSignIn(MeshPlatform.Android, MeshRole.Endpoint, mobileCarveOutAcknowledged: true).Stage);
    }

    [Fact]
    public void Android_WithoutCarveOutAcknowledgment_Refuses()
    {
        var svc = Setup(new MockApi(), new FakeProbe());
        var st = svc.RunPreSignIn(MeshPlatform.Android, MeshRole.Operator);
        Assert.Equal(MeshSetupStage.Refused, st.Stage);
        Assert.Contains("log", st.Detail);
    }

    [Fact]
    public void Android_OperatorPersonal_WithAcknowledgment_ReachesTheBoundary_AndSaysSo()
    {
        var svc = Setup(new MockApi(), new FakeProbe());
        var st = svc.RunPreSignIn(MeshPlatform.Android, MeshRole.Operator, mobileCarveOutAcknowledged: true);
        Assert.Equal(MeshSetupStage.AwaitingSignIn, st.Stage);
        Assert.True(st.MobileCarveOut);
    }

    [Fact]
    public void Honesty_VendorAndMeteringNamedInTheFlow()
    {
        Assert.Contains("Tailscale Inc. processes connection metadata", MeshHonesty.VendorLabel);
        Assert.Contains("6 users", MeshHonesty.VendorLabel);
        Assert.Contains("50 tagged resources", MeshHonesty.VendorLabel);
        var svc = Setup(new MockApi(), new FakeProbe());
        var st = svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator);
        Assert.Contains("Tailscale Inc. processes connection metadata", st.Detail);
    }

    // ---- D12 mapping + injection (TS-07 / T5 OP-01) ---------------

    [Fact]
    public void AclBuilder_D12Mapping_GroupsTagsTagOwners_NoSshEver()
    {
        var json = AclBuilder.Build(Mapping());
        Assert.Contains("\"group:techs\"", json);
        Assert.Contains("\"tag:fleet\"", json);
        Assert.Contains("\"tag:fleet:47621\"", json);
        Assert.DoesNotContain("\"ssh\"", json);
        Assert.DoesNotContain("\"*\"", json);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var owners = doc.RootElement.GetProperty("tagOwners").GetProperty("tag:fleet");
        Assert.Equal("group:techs", owners[0].GetString());
    }

    [Theory]
    [InlineData("fleet\"\n,\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}")] // quote+newline injection
    [InlineData("fleet tag")]                                                                          // space
    [InlineData("")]                                                                                   // empty
    public void AclBuilder_HostileDeviceGroupName_Refused(string hostile)
    {
        var m = new TailnetMapping(
            new Dictionary<string, IReadOnlyList<string>>(), new[] { hostile },
            new Dictionary<string, IReadOnlyList<string>>(), Array.Empty<TailnetGrant>());
        Assert.Throws<InvalidOperationException>(() => AclBuilder.Build(m));
    }

    [Fact]
    public void AclBuilder_HostileMemberAndPort_Refused()
    {
        var badMember = new TailnetMapping(
            new Dictionary<string, IReadOnlyList<string>> { ["techs"] = new[] { "alice\n\"src\": [\"*\"]" } },
            Array.Empty<string>(), new Dictionary<string, IReadOnlyList<string>>(), Array.Empty<TailnetGrant>());
        Assert.Throws<InvalidOperationException>(() => AclBuilder.Build(badMember));
        var badPort = new TailnetMapping(
            new Dictionary<string, IReadOnlyList<string>>(), Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>(),
            new[] { new TailnetGrant("techs", "fleet", new[] { "47621\",\"dst\":[\"*" }) });
        Assert.Throws<InvalidOperationException>(() => AclBuilder.Build(badPort));
        var noPorts = new TailnetMapping(
            new Dictionary<string, IReadOnlyList<string>>(), Array.Empty<string>(),
            new Dictionary<string, IReadOnlyList<string>>(),
            new[] { new TailnetGrant("techs", "fleet", Array.Empty<string>()) });
        Assert.Throws<InvalidOperationException>(() => AclBuilder.Build(noPorts));
    }

    // ---- guarded policy writes (TS-07) -----------------------------

    [Fact]
    public async Task PolicyGuard_ValidatePreviewApply_KeepsRollbackCopy()
    {
        var api = new MockApi();
        var guard = new PolicyGuard(api);
        var built = AclBuilder.Build(Mapping());
        var res = await guard.ApplyAsync("tok", built);
        Assert.True(res.Ok, res.Detail);
        Assert.Equal(built, api.LastApplied);
        Assert.Equal("{\"acls\": []}", guard.LastKnownGoodPolicy);
        Assert.NotNull(guard.LastDiff);
    }

    [Fact]
    public async Task PolicyGuard_ValidationFailure_WritesNothing()
    {
        var api = new MockApi { FailValidate = true };
        var guard = new PolicyGuard(api);
        var res = await guard.ApplyAsync("tok", AclBuilder.Build(Mapping()));
        Assert.False(res.Ok);
        Assert.Equal(0, api.ApplyCalls);
    }

    [Fact]
    public async Task PolicyGuard_ApplyFailure_RollsBackToLastKnownGood()
    {
        var api = new MockApi();
        var guard = new PolicyGuard(api);
        var built = AclBuilder.Build(Mapping());
        Assert.True((await guard.ApplyAsync("tok", built)).Ok);
        api.FailApply = true;
        var second = await guard.ApplyAsync("tok", built + "\n");
        Assert.False(second.Ok);
        Assert.Contains("restored", second.Detail);
        Assert.Equal(built, api.Policy); // the rollback re-applied the previous document
    }

    // ---- endpoint auth keys (D3) -----------------------------------

    [Fact]
    public async Task AuthKeys_SingleUseTaggedShortLived_Only()
    {
        var api = new MockApi();
        var keys = new EndpointAuthKeyService(api);
        Assert.False((await keys.MintAsync("tok", new[] { "tag:fleet" }, reusable: true)).Ok);
        Assert.False((await keys.MintAsync("tok", new[] { "tag:fleet" }, TimeSpan.FromDays(91))).Ok);
        Assert.False((await keys.MintAsync("tok", Array.Empty<string>())).Ok);
        Assert.False((await keys.MintAsync("tok", new[] { "fleet" })).Ok); // missing tag: prefix
        var ok = await keys.MintAsync("tok", new[] { "tag:fleet" });
        Assert.True(ok.Ok);
        Assert.Equal(true, api.LastKeySingleUse);
        Assert.Equal(TimeSpan.FromDays(7), api.LastKeyExpiry);
    }

    // ---- the full flow across the boundary --------------------------

    [Fact]
    public async Task Flow_SignInNotCompleted_StopsAndConfiguresNothing()
    {
        var api = new MockApi();
        var svc = Setup(api, new FakeProbe());
        SetGoodCredential(svc);
        Assert.Equal(MeshSetupStage.AwaitingSignIn, svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator).Stage);
        var st = await svc.CompleteAfterSignInAsync(() => Task.FromResult(false), Mapping(), DateTimeOffset.UtcNow);
        Assert.Equal(MeshSetupStage.Refused, st.Stage);
        Assert.Equal(0, api.ApplyCalls);
        Assert.Equal(0, api.ExchangeCalls);
    }

    [Fact]
    public async Task Flow_CompletedSignIn_DrivesPolicyThroughTheGuard_ToReady()
    {
        var api = new MockApi();
        var svc = Setup(api, new FakeProbe());
        SetGoodCredential(svc);
        svc.RunPreSignIn(MeshPlatform.DesktopWindows, MeshRole.Operator);
        var st = await svc.CompleteAfterSignInAsync(() => Task.FromResult(true), Mapping(), DateTimeOffset.UtcNow);
        Assert.Equal(MeshSetupStage.Ready, st.Stage);
        Assert.Equal(1, api.ExchangeCalls);
        Assert.NotNull(api.LastApplied);
        Assert.Contains("tag:fleet", api.LastApplied);
    }

    [Fact]
    public async Task Flow_PostSignInBeforePreflight_Refused()
    {
        var svc = Setup(new MockApi(), new FakeProbe());
        var st = await svc.CompleteAfterSignInAsync(() => Task.FromResult(true), Mapping(), DateTimeOffset.UtcNow);
        Assert.Equal(MeshSetupStage.Refused, st.Stage);
    }

    // ---- the mesh rung itself ---------------------------------------

    [Fact]
    public async Task MeshRung_NotSetUp_RefusesEveryConnect()
    {
        var rung = new MeshRung(() => new MeshSetupState(MeshSetupStage.NotStarted, "not run"));
        var w = TransportTests.Setup(new[] { "mesh" });
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, "100.64.0.9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not set up", result.Detail);
    }

    [Fact]
    public async Task MeshRung_Ready_ConnectsAndHandshakes_LanAddressRefused()
    {
        var w = TransportTests.Setup(new[] { "mesh" });
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        var ready = new MeshRung(
            () => new MeshSetupState(MeshSetupStage.Ready, "ready"),
            _ => true, // loopback seam for the socket leg
            w.Enrollments); // BD-SHARED-TRANSPORT F1: rungs carry enrollments for the v2 handshake
        Assert.True(ready.IsDormant);
        // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
        // the Ready rung's own client leg is a TcpClient this
        // sandbox's egress proxy intercepts, so the socket leg is
        // driven at the level the CONV-F3 probe proved (probe E2/E3)
        // — the SAME LanProtocol proof-of-possession handshake the
        // Ready rung runs, over a raw Socket, against the real
        // listener; the host's acceptance is asserted verbatim. The
        // rung's setup gate is asserted at its refusal shape by
        // MeshRung_NotSetUp_RefusesEveryConnect above, and the
        // production address gate by the second leg below, unchanged.
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(listener.Port);
        Assert.True(await LanProtocol.ClientHandshakeAsync(stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default));
        stream.Dispose();
        await RawSocketTestLeg.WaitUntilAsync(() => listener.AcceptedSessions == 1);
        Assert.Equal(1, listener.AcceptedSessions);

        var production = new MeshRung(() => new MeshSetupState(MeshSetupStage.Ready, "ready"));
        var lan = await production.ConnectSessionAsync(new TransportTarget(w.DeviceId, "192.168.1.20"), w.OperatorIdentity);
        Assert.False(lan.Ok);
        Assert.Contains("not a tailnet", lan.Detail);
    }
}

using System.Text;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Modules;
using Acp.Core.Services;
using Acp.Shared.Enrollment;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Sessions;

namespace Acp.Tests;

/// <summary>Block A wiring (2026-11-19): Slices 2–3 driven through
/// the LIVE surfaces — the Core's laptop-UI IPC action handlers, the
/// host-state snapshot the window renders, the mesh state, the MCP
/// session_status tool, and the one SessionPicture they all share.
/// Fixtures build a real CoreRuntime (VaultIpcTests pattern) and act
/// only through the public handler methods the IPC event calls.</summary>
public sealed class WiringFixture : IAsyncLifetime
{
    public readonly string DataDir = TestUtil.TempDir();
    public CoreRuntime Runtime = null!;

    public const string ScopeId = "acme";
    public const string OwnerId = "owner";
    public const string Admin2Id = "admin2";
    public const string GroupId = "fleet";

    public Task InitializeAsync()
    {
        Runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = DataDir,
            FactChecks = new FakeFactChecks(),
        });
        var roster = Runtime.Roster;
        Assert.NotNull(roster.CreateScope(ScopeId, "company", "Acme"));
        Assert.NotNull(roster.CreateUser(OwnerId, ScopeId, "Olivia Owner", "human"));
        Assert.NotNull(roster.CreateUser(Admin2Id, ScopeId, "Second Admin", "human"));
        Assert.True(roster.AddCompanyAdmin(ScopeId, OwnerId));
        Assert.True(roster.AddCompanyAdmin(ScopeId, Admin2Id));
        Assert.NotNull(roster.CreateDeviceGroup(GroupId, ScopeId, "Fleet",
            new[] { "lan", "hub", "mesh", "ipv6", "ownpath", "tor" }));
        Assert.NotNull(roster.CreateUserGroup("ops", ScopeId, "Operators", new[] { OwnerId }));
        Assert.NotNull(roster.AddGrant(ScopeId, "ops", GroupId, new[] { "use", "enroll" }));
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await Runtime.DisposeAsync();

    /// <summary>Mint (the enrollment_mint handler's call) + redeem
    /// through the REAL IPC redeem handler: the full round trip that
    /// was impossible before this wiring.</summary>
    public string MintCode(string mintedBy = OwnerId) =>
        Runtime.Enrollments.CreateEnrollmentCode("company", GroupId, "Fleet",
            TimeSpan.FromMinutes(10), "inherit", null, mintedBy);

    public (bool Ok, string Detail) Redeem(string code) =>
        Runtime.ApplyEnrollmentRedeem(JsonSerializer.Serialize(new
        {
            code,
            displayName = "HOST-LAPTOP",
            rosterScopeId = ScopeId,
            mintedByUserId = OwnerId,
        }));

    public string EnrollThisDevice()
    {
        var (ok, detail) = Redeem(MintCode());
        Assert.True(ok, detail);
        return Runtime.Identity.DeviceId;
    }

    public string CreateAttendedSession(string initiator = OwnerId)
    {
        var (ok, detail) = Runtime.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "create", scopeId = ScopeId, hostDeviceId = Runtime.Identity.DeviceId,
            initiatorUserId = initiator, kind = "attended", transportRung = "lan", recording = "none",
        }));
        Assert.True(ok, detail);
        // detail is "session <id> requested"
        return detail.Split(' ')[1];
    }

    public (bool, string) SessionAction(object payload) =>
        Runtime.ApplySessionAction(JsonSerializer.Serialize(payload));
}

public sealed class WiringTests : IClassFixture<WiringFixture>
{
    private readonly WiringFixture _f;
    public WiringTests(WiringFixture f) => _f = f;

    [Fact]
    public void Enrollment_RoundTrip_ThroughIpcHandlers_FilesDeviceIntoRoster()
    {
        var deviceId = _f.EnrollThisDevice();
        // The device is in the Slice 1 roster, filed into the minted group.
        var device = _f.Runtime.Enrollments.List().Single(d => d.DeviceId == deviceId);
        Assert.Equal(WiringFixture.GroupId, device.GroupId);
        Assert.Equal("company", device.Scope);
        Assert.False(device.Revoked);
        // ...and in the Slice 2 operator roster for the scope.
        var op = _f.Runtime.Roster.OperatorRoster(WiringFixture.ScopeId);
        Assert.NotNull(op);
        Assert.Contains(op!.Devices, d => d.DeviceId == deviceId);
        // ...and the minted-by attribution exists for D14.
        Assert.Contains(_f.Runtime.Roster.ListMintedEnrollments(WiringFixture.ScopeId, WiringFixture.OwnerId),
            m => m.DeviceId == deviceId);
        // ...and this device's endpoint view resolves (D2).
        var view = _f.Runtime.Roster.EndpointView(deviceId);
        Assert.NotNull(view);
        Assert.Equal(deviceId, view!.Device.DeviceId);
    }

    [Fact]
    public void RosterActions_ThroughIpc_CreateScopeUserGroupsGrant()
    {
        var rt = _f.Runtime;
        var (ok1, d1) = rt.ApplyRosterAction("""{"action":"create_scope","id":"beta","kind":"company","name":"Beta Co"}""");
        Assert.True(ok1, d1);
        var (ok2, d2) = rt.ApplyRosterAction("""{"action":"create_user","id":"bea","scopeId":"beta","displayName":"Bea","kind":"human"}""");
        Assert.True(ok2, d2);
        var (ok3, d3) = rt.ApplyRosterAction("""{"action":"create_device_group","id":"beta-fleet","scopeId":"beta","name":"Beta Fleet","transportSet":["lan","tor"]}""");
        Assert.True(ok3, d3);
        var (ok4, d4) = rt.ApplyRosterAction("""{"action":"create_user_group","id":"beta-ops","scopeId":"beta","name":"Beta Ops","members":["bea"]}""");
        Assert.True(ok4, d4);
        var (ok5, d5) = rt.ApplyRosterAction("""{"action":"add_grant","scopeId":"beta","userGroupId":"beta-ops","deviceGroupId":"beta-fleet","rights":["use"]}""");
        Assert.True(ok5, d5);
        Assert.True(rt.Roster.UserHasRight("beta", "bea", "beta-fleet", "use"));
        // AI admin through the IPC surface refuses, like everywhere else (D9).
        var (okAi, _) = rt.ApplyRosterAction("""{"action":"create_user","id":"bea-ai","scopeId":"beta","displayName":"AI","kind":"ai","pairedByUserId":"bea"}""");
        Assert.True(okAi);
        var (okSeat, _) = rt.ApplyRosterAction("""{"action":"add_company_admin","scopeId":"beta","userId":"bea-ai"}""");
        Assert.False(okSeat);
    }

    [Fact]
    public void Session_Lifecycle_ThroughIpc_CreateAcceptLocalStart_AppearsInEveryPicture()
    {
        _f.EnrollThisDevice();
        var sessionId = _f.CreateAttendedSession();

        // Before accept: start refuses (consent floor).
        var (startEarly, _) = _f.SessionAction(new { action = "start", sessionId, actorUserId = WiringFixture.OwnerId });
        Assert.False(startEarly);

        // Accept from THIS window = endpoint-local: works even for
        // the initiator (locality is the signal, 2026-11-19 ruling).
        var (acceptOk, acceptDetail) = _f.SessionAction(new
        {
            action = "accept", sessionId, acceptByUserId = WiringFixture.OwnerId,
        });
        Assert.True(acceptOk, acceptDetail);
        var session = _f.Runtime.HumanSessions.GetSession(sessionId);
        Assert.NotNull(session);
        Assert.Equal(SessionService.AcceptOriginEndpointLocal, session!.AcceptOrigin);

        var (startOk, startDetail) = _f.SessionAction(new { action = "start", sessionId, actorUserId = WiringFixture.OwnerId });
        Assert.True(startOk, startDetail);
        Assert.Equal("active", _f.Runtime.HumanSessions.GetSession(sessionId)!.State);

        // One picture: host-state snapshot headline + humanSessions.
        using var doc = JsonDocument.Parse(_f.Runtime.BuildHostStateJson());
        var root = doc.RootElement;
        Assert.True(root.GetProperty("session").GetProperty("active").GetBoolean());
        Assert.Equal("Olivia Owner", root.GetProperty("session").GetProperty("agent").GetString());
        var humans = root.GetProperty("humanSessions");
        var mine = humans.EnumerateArray().Single(h => h.GetProperty("id").GetString() == sessionId);
        Assert.Equal("active", mine.GetProperty("state").GetString());
        Assert.Equal("Olivia Owner", mine.GetProperty("initiator").GetString());

        // One picture: SessionPicture.PrimaryLive (presence source).
        var primary = SessionPicture.PrimaryLive(_f.Runtime.HumanSessions, _f.Runtime.Roster, DateTimeOffset.UtcNow);
        Assert.NotNull(primary);
        Assert.Equal(sessionId, primary!.Id);
        Assert.Equal("Olivia Owner", primary.InitiatorName);

        // One picture: mesh state.
        var mesh = new MeshService(new FakeChannel(), () => null, () => 0, () => true, () => null,
            deviceName: "TEST-PC",
            humanSessions: () => SessionPicture.All(_f.Runtime.HumanSessions, _f.Runtime.Roster, DateTimeOffset.UtcNow));
        var stateJson = JsonDocument.Parse(Encoding.UTF8.GetString(mesh.GetState().Body)).RootElement;
        Assert.Equal("HUMAN_SESSION", stateJson.GetProperty("state").GetString());
        Assert.Equal("Olivia Owner", stateJson.GetProperty("agent").GetString());
        Assert.Equal(1, stateJson.GetProperty("humanSessions").GetArrayLength());

        // One picture: MCP session_status.
        var module = new SessionStatusModule(_f.Runtime.Sessions,
            () => SessionPicture.All(_f.Runtime.HumanSessions, _f.Runtime.Roster, DateTimeOffset.UtcNow));
        var result = module.ExecuteAsync(default, null!, default).Result;
        Assert.True(result.Ok);
        using var statusDoc = JsonDocument.Parse(result.Text!);
        Assert.True(statusDoc.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal("human", statusDoc.RootElement.GetProperty("source").GetString());

        // End it; every picture goes quiet.
        var (endOk, _) = _f.SessionAction(new { action = "end", sessionId, actorUserId = WiringFixture.OwnerId });
        Assert.True(endOk);
        Assert.Null(SessionPicture.PrimaryLive(_f.Runtime.HumanSessions, _f.Runtime.Roster, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Offboard_PreviewThenFire_ThroughIpc_BlastMatchesWhatFired()
    {
        var rt = _f.Runtime;
        // A victim user with a seat, an owned AI, and a minted device.
        Assert.NotNull(rt.Roster.CreateUser("victim", WiringFixture.ScopeId, "Vic Tim", "human"));
        Assert.NotNull(rt.Roster.CreateUser("victim-ai", WiringFixture.ScopeId, "Vic AI", "ai", "victim"));
        var victimDevice = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = rt.Enrollments.CreateEnrollmentCode("company", WiringFixture.GroupId, "Fleet",
            TimeSpan.FromMinutes(10), "inherit", null, "victim");
        var enrolled = rt.Enrollments.Redeem(code,
            new EnrollingDevice(victimDevice.DeviceId, victimDevice.PublicKeyBase64, "Victim PC"));
        Assert.NotNull(enrolled);
        Assert.True(rt.Roster.RecordMintedEnrollment(WiringFixture.ScopeId, "victim", enrolled!.DeviceId));

        var blastJson = rt.BuildOffboardBlastJson("""{"scopeId":"acme","userId":"victim"}""");
        Assert.NotNull(blastJson);
        using var blast = JsonDocument.Parse(blastJson!);
        Assert.Contains(enrolled.DeviceId, blast.RootElement.GetProperty("mintedEnrollmentDeviceIds").EnumerateArray().Select(e => e.GetString()));
        Assert.Contains("victim-ai", blast.RootElement.GetProperty("ownedAiUserIds").EnumerateArray().Select(e => e.GetString()));
        Assert.True(blast.RootElement.GetProperty("requiresLiveSessionTermination").GetBoolean());
        // Preview fired nothing.
        Assert.NotNull(rt.Roster.GetUser(WiringFixture.ScopeId, "victim"));

        var (ok, detail) = rt.ApplyRosterAction("""{"action":"remove_user","scopeId":"acme","userId":"victim","actorUserId":"owner","stepUp":false}""");
        Assert.True(ok, detail);
        Assert.Null(rt.Roster.GetUser(WiringFixture.ScopeId, "victim"));
        Assert.True(rt.Enrollments.List().Single(d => d.DeviceId == enrolled.DeviceId).Revoked);
        Assert.True(rt.Roster.GetUser(WiringFixture.ScopeId, "victim-ai")!.Suspended);
    }

    [Fact]
    public void HostState_RosterSection_IsLiveStoreData()
    {
        using var doc = JsonDocument.Parse(_f.Runtime.BuildHostStateJson());
        var roster = doc.RootElement.GetProperty("roster");
        var acme = roster.EnumerateArray().Single(s => s.GetProperty("id").GetString() == "acme");
        Assert.Equal("company", acme.GetProperty("kind").GetString());
        Assert.Contains(acme.GetProperty("users").EnumerateArray(), u => u.GetProperty("id").GetString() == "owner");
        Assert.Contains(acme.GetProperty("companyAdmins").EnumerateArray(), a => a.GetString() == "owner");
        var fleet = acme.GetProperty("deviceGroups").EnumerateArray().Single(g => g.GetProperty("id").GetString() == "fleet");
        Assert.Equal("lan", fleet.GetProperty("transportSet")[0].GetString());
        Assert.Contains(acme.GetProperty("grants").EnumerateArray(),
            g => g.GetProperty("userGroupId").GetString() == "ops" && g.GetProperty("rights").EnumerateArray().Any(r => r.GetString() == "use"));
    }

    private sealed class FakeChannel : Acp.Core.Ipc.IAgentChannel
    {
        public bool AgentConnected => true;
        public Task<Acp.Shared.Tools.ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct) =>
            Task.FromResult(Acp.Shared.Tools.ToolResult.Success("ok"));
    }
}

/// <summary>STOP from presence ends Slice 3 sessions too: the real
/// supervisor loop, a real STOP file, a live human session.</summary>
public sealed class StopEndsHumanSessionsTests : IAsyncLifetime
{
    private readonly string _dataDir = TestUtil.TempDir();
    private CoreRuntime _runtime = null!;

    public async Task InitializeAsync()
    {
        _runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = _dataDir,
            FactChecks = new FakeFactChecks(),
            SupervisorPeriod = TimeSpan.FromMilliseconds(100),
        });
        await _runtime.StartAsync(default);
    }

    public async Task DisposeAsync()
    {
        await _runtime.StopAsync(default);
        await _runtime.DisposeAsync();
    }

    [Fact]
    public async Task StopFile_EndsLiveHumanSession_WithHostStopReason()
    {
        var roster = _runtime.Roster;
        roster.CreateScope("acme", "company", "Acme");
        roster.CreateUser("owner", "acme", "Olivia Owner", "human");
        roster.AddCompanyAdmin("acme", "owner");
        roster.CreateDeviceGroup("fleet", "acme", "Fleet", new[] { "lan" });
        roster.CreateUserGroup("ops", "acme", "Operators", new[] { "owner" });
        roster.AddGrant("acme", "ops", "fleet", new[] { "use" });
        var code = _runtime.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet");
        var (redeemOk, redeemDetail) = _runtime.ApplyEnrollmentRedeem(
            JsonSerializer.Serialize(new { code, displayName = "TEST-PC" }));
        Assert.True(redeemOk, redeemDetail);
        var (createOk, createDetail) = _runtime.ApplySessionAction(
            JsonSerializer.Serialize(new
            {
                action = "create", scopeId = "acme", hostDeviceId = _runtime.Identity.DeviceId,
                initiatorUserId = "owner", kind = "attended", transportRung = "lan", recording = "none",
            }));
        Assert.True(createOk, createDetail);
        var sessionId = createDetail.Split(' ')[1];
        Assert.True(_runtime.ApplySessionAction(
            JsonSerializer.Serialize(new { action = "accept", sessionId, acceptByUserId = "owner" })).Ok);
        Assert.True(_runtime.ApplySessionAction(
            JsonSerializer.Serialize(new { action = "start", sessionId, actorUserId = "owner" })).Ok);
        Assert.Equal("active", _runtime.HumanSessions.GetSession(sessionId)!.State);

        // Presence STOP's file form: the supervisor must end it.
        await File.WriteAllTextAsync(_runtime.StopFilePath, "stop");
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline &&
               _runtime.HumanSessions.GetSession(sessionId)!.State != "ended")
            await Task.Delay(100);
        var ended = _runtime.HumanSessions.GetSession(sessionId)!;
        Assert.Equal("ended", ended.State);
        Assert.Equal(SessionService.EndReasonHostStop, ended.EndReason);
    }
}

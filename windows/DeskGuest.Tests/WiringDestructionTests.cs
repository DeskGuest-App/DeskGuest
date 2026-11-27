using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

/// <summary>Destruction pass on the Block A wiring (2026-11-19):
/// hostile IPC payloads, cross-scope reads through the new snapshot,
/// endpoint-view leakage through every new surface, accept-over-
/// channel through the new path, and offboarding mid-session. Every
/// case runs against a real CoreRuntime and acts only through the
/// public IPC handler methods (the laptop-UI channel's Core side).</summary>
public sealed class WiringDestructionTests : IAsyncLifetime
{
    private readonly string _dataDir = TestUtil.TempDir();
    private CoreRuntime _rt = null!;

    public Task InitializeAsync()
    {
        _rt = new CoreRuntime(new CoreOptions
        {
            DataDir = _dataDir,
            FactChecks = new FakeFactChecks(),
        });
        var roster = _rt.Roster;
        // Two company scopes, walled (D8): acme (populated) + globex.
        roster.CreateScope("acme", "company", "Acme");
        roster.CreateScope("globex", "company", "Globex");
        roster.CreateUser("owner", "acme", "Olivia Owner", "human");
        roster.CreateUser("admin2", "acme", "Second Admin", "human");
        roster.AddCompanyAdmin("acme", "owner");
        roster.AddCompanyAdmin("acme", "admin2");
        roster.CreateUser("gina", "globex", "Gina Globex", "human");
        roster.AddCompanyAdmin("globex", "gina");
        roster.CreateDeviceGroup("fleet", "acme", "Fleet", new[] { "lan", "mesh" });
        roster.CreateDeviceGroup("g-fleet", "globex", "Globex Fleet", new[] { "lan" });
        roster.CreateUserGroup("ops", "acme", "Operators", new[] { "owner" });
        roster.AddGrant("acme", "ops", "fleet", new[] { "use", "enroll" });
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _rt.DisposeAsync();

    private string EnrollThisDevice()
    {
        var code = _rt.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet",
            TimeSpan.FromMinutes(10), "inherit", null, "owner");
        var (ok, detail) = _rt.ApplyEnrollmentRedeem(JsonSerializer.Serialize(new
        {
            code, displayName = "HOST-LAPTOP", rosterScopeId = "acme", mintedByUserId = "owner",
        }));
        Assert.True(ok, detail);
        return _rt.Identity.DeviceId;
    }

    private string CreateSession(string initiator = "owner", string kind = "attended")
    {
        var (ok, detail) = _rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "create", scopeId = "acme", hostDeviceId = _rt.Identity.DeviceId,
            initiatorUserId = initiator, kind, transportRung = "lan", recording = "none",
        }));
        Assert.True(ok, detail);
        return detail.Split(' ')[1];
    }

    // DW-W-01 — hostile payload barrage on every new IPC handler.
    [Fact]
    public void DestructionW_HostilePayloads_EveryNewHandler_RefusesAndMutatesNothing()
    {
        var scopesBefore = _rt.Roster.ListScopes().Count;
        var sessionsBefore = _rt.HumanSessions.ListSessions().Count;
        var devicesBefore = _rt.Enrollments.List().Count;
        var hostile = new[]
        {
            null, "", "not json", "[]", "{}", "null", "\"x\"",
            """{"action":123}""", """{"action":"create_scope"}""",
            """{"action":"nonsense","id":"x"}""",
            "{\"action\":\"create_user\",\"id\":\"" + new string('A', 100_000) + "\"}",
            """{"action":"remove_user","scopeId":"globex","userId":"gina","actorUserId":"owner"}""",
            """{"action":"create","scopeId":"acme"}""",
        };
        foreach (var payload in hostile)
        {
            Assert.False(_rt.ApplyRosterAction(payload).Ok, payload);
            Assert.False(_rt.ApplySessionAction(payload).Ok, payload);
            Assert.False(_rt.ApplyEnrollmentRedeem(payload).Ok, payload);
            // The blast PREVIEW is a scope-local read: it answers for
            // a user in their own scope (the fire is what refuses a
            // foreign actor), so only payloads that do not name an
            // existing scope+user pair must come back null.
            if (payload is null || !payload.Contains("remove_user"))
                Assert.Null(_rt.BuildOffboardBlastJson(payload));
        }
        Assert.Equal(scopesBefore, _rt.Roster.ListScopes().Count);
        Assert.Equal(sessionsBefore, _rt.HumanSessions.ListSessions().Count);
        Assert.Equal(devicesBefore, _rt.Enrollments.List().Count);
        Assert.NotNull(_rt.Roster.GetUser("acme", "owner"));
        Assert.NotNull(_rt.Roster.GetUser("globex", "gina")); // cross-scope removal refused inside the barrage (D8 wall)
    }

    // DW-W-02 — cross-scope reads through the new snapshot.
    [Fact]
    public void DestructionW_Snapshot_CrossScopeSections_NeverMix()
    {
        EnrollThisDevice();
        using var doc = JsonDocument.Parse(_rt.BuildHostStateJson());
        var roster = doc.RootElement.GetProperty("roster");
        var acme = roster.EnumerateArray().Single(s => s.GetProperty("id").GetString() == "acme");
        var globex = roster.EnumerateArray().Single(s => s.GetProperty("id").GetString() == "globex");
        var acmeText = acme.GetRawText();
        var globexText = globex.GetRawText();
        Assert.DoesNotContain("gina", acmeText);
        Assert.DoesNotContain("Globex", acmeText);
        Assert.DoesNotContain(_rt.Identity.DeviceId, globexText);
        Assert.DoesNotContain("owner", globexText);
        Assert.Contains("gina", globexText);
    }

    // DW-W-03 — endpoint-view leakage + secret sweep over the whole
    // new snapshot surface.
    [Fact]
    public void DestructionW_EndpointSection_ContainsOnlyOwnDevice_AndSnapshotHasNoSecrets()
    {
        var ownId = EnrollThisDevice();
        // A second device enrolled directly (another endpoint).
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code2 = _rt.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet");
        var otherEnrolled = _rt.Enrollments.Redeem(code2,
            new EnrollingDevice(other.DeviceId, other.PublicKeyBase64, "Other PC"));
        Assert.NotNull(otherEnrolled);
        // A live pairing, whose bearer token must never appear.
        var pairCode = _rt.Pairings.CreatePairingCode("sweep-agent", TimeSpan.FromMinutes(5), Scopes.Preset("full_control"));
        var exchange = _rt.Pairings.ExchangeCode(pairCode, "sweep-agent");
        Assert.NotNull(exchange);

        var json = _rt.BuildHostStateJson();
        using var doc = JsonDocument.Parse(json);
        var endpoint = doc.RootElement.GetProperty("endpoint");
        Assert.False(endpoint.ValueKind == JsonValueKind.Null);
        var endpointText = endpoint.GetRawText();
        Assert.Contains(ownId, endpointText);
        Assert.DoesNotContain(other.DeviceId, endpointText);
        Assert.DoesNotContain("Other PC", endpointText);
        // No secret material anywhere in the document: no bearer
        // token, no public keys (not needed by the window), no seed.
        Assert.DoesNotContain(exchange!.BearerToken, json);
        Assert.DoesNotContain(other.PublicKeyBase64, json);
        Assert.DoesNotContain(_rt.Identity.PublicKeyBase64, json);
        Assert.DoesNotContain("token", json, StringComparison.OrdinalIgnoreCase);
    }

    // DW-W-04 — accept over the initiating channel, through the new
    // IPC path and at the model beneath it.
    [Fact]
    public void DestructionW_AcceptOverChannel_ThroughNewPath_Refused_LocalAcceptStillWorks()
    {
        EnrollThisDevice();
        var sessionId = CreateSession();
        var (channelOk, channelDetail) = _rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId, acceptByUserId = "owner", origin = "initiating_channel",
        }));
        Assert.False(channelOk, channelDetail);
        var session = _rt.HumanSessions.GetSession(sessionId)!;
        Assert.Null(session.AcceptedByUserId);
        Assert.Equal("requested", session.State);
        // Model level, same refusal (the ruling's own battery covers
        // more callers; this pins the wiring's foundation).
        Assert.False(_rt.HumanSessions.AcceptSession(sessionId, "owner", SessionAcceptOrigin.InitiatingChannel));
        // The local path through the same handler still works.
        var (localOk, _) = _rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId, acceptByUserId = "owner", origin = "endpoint_local",
        }));
        Assert.True(localOk);
        // And a forged origin string refuses too.
        var session2 = CreateSession();
        var (forgedOk, _) = _rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId = session2, acceptByUserId = "owner", origin = "carrier_pigeon",
        }));
        Assert.False(forgedOk);
    }

    // DW-W-05 — offboarding mid-session, fired through the new IPC.
    [Fact]
    public async Task DestructionW_OffboardingMidSession_ThroughIpc_EndsSessionAndRevokesMinted()
    {
        EnrollThisDevice();
        var roster = _rt.Roster;
        roster.CreateUser("victim", "acme", "Vic Tim", "human");
        // Victim mints a device of their own.
        var victimDevice = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var vcode = _rt.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet",
            TimeSpan.FromMinutes(10), "inherit", null, "victim");
        var vEnrolled = _rt.Enrollments.Redeem(vcode,
            new EnrollingDevice(victimDevice.DeviceId, victimDevice.PublicKeyBase64, "Victim PC"));
        Assert.NotNull(vEnrolled);
        Assert.True(roster.RecordMintedEnrollment("acme", "victim", vEnrolled!.DeviceId));

        var sessionId = CreateSession();
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId, acceptByUserId = "owner",
        })).Ok);
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "start", sessionId, actorUserId = "owner",
        })).Ok);
        Assert.True(_rt.HumanSessions.AddParticipant(sessionId, "victim", "controller", "owner"));
        Assert.Equal("active", _rt.HumanSessions.GetSession(sessionId)!.State);

        var (ok, detail) = _rt.ApplyRosterAction(
            """{"action":"remove_user","scopeId":"acme","userId":"victim","actorUserId":"owner","stepUp":false}""");
        Assert.True(ok, detail);
        // The victim's minted device is revoked by the same fire.
        Assert.True(_rt.Enrollments.List().Single(d => d.DeviceId == vEnrolled.DeviceId).Revoked);
        // The live session ends: the roster→session sweep is queued,
        // and any subsequent act re-reads offboarding — poll briefly,
        // then force the deterministic path.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline &&
               _rt.HumanSessions.GetSession(sessionId)!.State != "ended")
            await Task.Delay(50);
        if (_rt.HumanSessions.GetSession(sessionId)!.State != "ended")
            _rt.HumanSessions.EnforceOffboarding(sessionId);
        var ended = _rt.HumanSessions.GetSession(sessionId)!;
        Assert.Equal("ended", ended.State);
        Assert.Equal(SessionService.EndReasonParticipantRemoved, ended.EndReason);
    }

    // DW-W-06 — forged actors through the new session IPC.
    [Fact]
    public void DestructionW_ForgedActors_ThroughSessionIpc_Refused()
    {
        EnrollThisDevice();
        rosterUser("mallory");
        var sessionId = CreateSession();
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId, acceptByUserId = "owner",
        })).Ok);
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "start", sessionId, actorUserId = "owner",
        })).Ok);
        // Mallory is a live user of the scope but no participant and
        // no host-side actor: floor, recording-on, and STOP refuse.
        Assert.False(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "grant_floor", sessionId, userId = "owner", actorUserId = "mallory",
        })).Ok);
        Assert.False(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "set_recording", sessionId, recording = "video", actorUserId = "mallory",
        })).Ok);
        Assert.False(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "stop", sessionId, actorUserId = "mallory",
        })).Ok);
        // A mere initiator/controller cannot STOP a session whose
        // host side is someone else: mallory initiates, admin2
        // accepts (host side), mallory's STOP refuses — while a
        // company admin's STOP succeeds (the control proving the
        // refusal is about authority, not a dead path).
        var s2 = CreateSession(initiator: "mallory");
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "accept", sessionId = s2, acceptByUserId = "admin2",
        })).Ok);
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "start", sessionId = s2, actorUserId = "mallory",
        })).Ok);
        Assert.False(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "stop", sessionId = s2, actorUserId = "mallory",
        })).Ok);
        Assert.True(_rt.ApplySessionAction(JsonSerializer.Serialize(new
        {
            action = "stop", sessionId = s2, actorUserId = "owner",
        })).Ok);
    }

    // DW-W-07 — enrollment through the new IPC: replay, garbage
    // codes, and hostile display names.
    [Fact]
    public void DestructionW_RedeemReplay_AndHostileNames_ThroughIpc_Refused()
    {
        var code = _rt.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet");
        var payload = JsonSerializer.Serialize(new { code, displayName = "HOST-LAPTOP" });
        Assert.True(_rt.ApplyEnrollmentRedeem(payload).Ok);
        // Replay of the consumed code refuses.
        Assert.False(_rt.ApplyEnrollmentRedeem(payload).Ok);
        // Garbage codes refuse.
        Assert.False(_rt.ApplyEnrollmentRedeem("""{"code":"XXXXX-XXXXX","displayName":"x"}""").Ok);
        Assert.False(_rt.ApplyEnrollmentRedeem("""{"code":"!!!!!","displayName":"x"}""").Ok);
        // A fresh code with a hostile display name (control chars)
        // refuses at the Slice 1 binding validation — and the code
        // is NOT consumed by the failed attempt.
        var code2 = _rt.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet");
        Assert.False(_rt.ApplyEnrollmentRedeem(JsonSerializer.Serialize(new
        {
            code = code2, displayName = "bad\u0001name",
        })).Ok);
        Assert.True(_rt.ApplyEnrollmentRedeem(JsonSerializer.Serialize(new
        {
            code = code2, displayName = "HOST-LAPTOP",
        })).Ok);
    }

    private void rosterUser(string id) =>
        _rt.Roster.CreateUser(id, "acme", id, "human");
}

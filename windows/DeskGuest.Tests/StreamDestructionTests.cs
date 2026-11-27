using System.Text;
using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Streaming;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>Block D destruction battery — the stream layer under
/// attack. The floor rule and the session binding are enforced in
/// StreamService (never in a viewer), so every attack is driven at
/// the raw service/protocol level: watcher input injection,
/// non-participant and cross-scope injection, subscription without
/// a live session, floor-theft races, STOP races, session end /
/// block / offboarding mid-stream, and hostile bytes from the
/// capture path. The invariant after every attack: input reaches
/// the agent channel ONLY from the live floor holder of an active
/// session, and frames are served ONLY for a live session.</summary>
public class StreamDestructionTests
{
    private sealed class FakeChannel : IAgentChannel
    {
        public bool AgentConnected { get; set; } = true;
        public List<(string Tool, string Args)> Calls { get; } = new();
        public Func<string, string, ToolResult> Handler { get; set; } = (_, _) => ToolResult.Success("ok");
        public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
        {
            lock (Calls) Calls.Add((tool, argumentsJson));
            return Task.FromResult(Handler(tool, argumentsJson));
        }
        public int CountTool(string tool) { lock (Calls) return Calls.Count(c => c.Tool == tool); }
        public int InputToolCalls => CountTool("mouse_move_rel") + CountTool("mouse_move_abs_stream")
            + CountTool("button_here") + CountTool("key_press") + CountTool("type_text") + CountTool("scroll");
    }

    private sealed class World
    {
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World { Roster = roster, Sessions = new SessionService(roster, enrollments), DeviceId = device!.DeviceId };
    }

    /// <summary>An ACTIVE session: ctrl initiated, host accepted
    /// (endpoint-local), peer added as a second controller, ai
    /// watcher not used here. Floor starts with nobody holding it
    /// unless <paramref name="floorTo"/> names the grantee.</summary>
    private static string ActiveSession(World w, string? floorTo = null)
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan", "none");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.True(w.Sessions.AddParticipant(s.Id, "peer", "controller", "ctrl"));
        if (floorTo is not null) Assert.True(w.Sessions.GrantFloor(s.Id, floorTo, "host"));
        Assert.Equal("active", w.Sessions.GetSession(s.Id)!.State);
        return s.Id;
    }

    private static byte[] KeyAu() =>
        new byte[] { 0, 0, 0, 1, 7, 0x64, 0x00 }.Concat(new byte[] { 0, 0, 0, 1, 8, 0xEE })
            .Concat(new byte[] { 0, 0, 0, 1, 5, 0x88 }).ToArray();

    private static string FrameJson(long seq)
    {
        var header = new StreamProtocol.FrameHeader(seq, 100, 1_700_000_000_000, true, 1920, 1080, 0,
            "h264", "Test MFT", true, "dxgi", null, 3, 4);
        var body = StreamProtocol.Pack(header, KeyAu());
        return JsonSerializer.Serialize(new { seq, data = Convert.ToBase64String(body) });
    }

    private sealed class Fixture
    {
        public World W { get; } = Setup();
        public FakeChannel Channel { get; } = new();
        public bool Unlocked = true;
        public bool StopInForce;
        public StreamService Service { get; }
        public Fixture()
        {
            Channel.Handler = (tool, _) => tool switch
            {
                "stream_start" => ToolResult.Success("{\"streaming\":true}"),
                "stream_frame" => ToolResult.Success(FrameJson(1)),
                "stream_monitors" => ToolResult.Success("[{\"index\":0,\"x\":0,\"y\":0,\"width\":1920,\"height\":1080,\"primary\":true}]"),
                "stream_stats" => ToolResult.Success("{\"framesEncoded\":42}"),
                _ => ToolResult.Success("ok"),
            };
            Service = new StreamService(Channel, W.Sessions, () => Unlocked, () => StopInForce,
                displayName: (scope, user) => W.Roster.GetUser(scope, user)?.DisplayName);
        }
        public string StartBody(string sessionId, string userId) =>
            JsonSerializer.Serialize(new { sessionId, userId, monitor = 0 });
        public string InputBody(string sessionId, string userId, string type = "key", string key = "enter") =>
            JsonSerializer.Serialize(new { sessionId, userId, @event = new { type, key } });
    }

    private static string ErrorOf(MeshReply reply) =>
        JsonDocument.Parse(Encoding.UTF8.GetString(reply.Body)).RootElement.GetProperty("error").GetString() ?? "";

    // ---- no session, no stream ------------------------------------

    [Fact]
    public async Task Start_UnknownSession_404_NoAgentCall()
    {
        var f = new Fixture();
        var reply = await f.Service.StartAsync(f.StartBody("nope", "ctrl"), "ctrl", default);
        Assert.Equal(404, reply.Status);
        Assert.Equal(0, f.Channel.CountTool("stream_start"));
    }

    [Fact]
    public async Task Start_RequestedSession_409_StreamRequiresActive()
    {
        var f = new Fixture();
        var s = f.W.Sessions.CreateSession("company-1", f.W.DeviceId, "ctrl", "attended", "lan", "none");
        var reply = await f.Service.StartAsync(f.StartBody(s!.Id, "ctrl"), "ctrl", default);
        Assert.Equal(409, reply.Status);
        Assert.Contains("requested", ErrorOf(reply));
        Assert.Equal(0, f.Channel.CountTool("stream_start"));
    }

    [Fact]
    public async Task Start_NonParticipant_403_CrossScope_403()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W);
        Assert.Equal(403, (await f.Service.StartAsync(f.StartBody(id, "outsider-x"), "outsider-x", default)).Status);
        // "owner" exists — in the personal scope. Not a participant
        // of this company session: cross-scope ids buy nothing.
        Assert.Equal(403, (await f.Service.StartAsync(f.StartBody(id, "owner"), "owner", default)).Status);
        Assert.Equal(0, f.Channel.CountTool("stream_start"));
    }

    [Fact]
    public async Task Start_ActiveParticipant_200_BindsStream()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W);
        var reply = await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        Assert.Equal(200, reply.Status);
        Assert.True(f.Service.IsStreaming(id));
        Assert.Equal(1, f.Service.Stats(id).Started);
    }

    [Fact]
    public async Task Start_LockedDesktop_OrAgentDown_503()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W);
        f.Unlocked = false;
        Assert.Equal(503, (await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default)).Status);
        f.Unlocked = true;
        f.Channel.AgentConnected = false;
        Assert.Equal(503, (await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default)).Status);
    }

    // ---- the floor gate --------------------------------------------

    [Fact]
    public async Task Input_WatcherParticipant_403_NeverReachesAgent()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        // peer is a live participant whose floor state is "watching".
        var reply = await f.Service.PostInputAsync(f.InputBody(id, "peer"), "peer", default);
        Assert.Equal(403, reply.Status);
        Assert.Contains("stream layer", ErrorOf(reply));
        Assert.Equal(0, f.Channel.InputToolCalls);
        Assert.Equal(1, f.Service.Stats(id).InputsRefusedFloor);
    }

    [Fact]
    public async Task Input_NonParticipant_And_CrossScope_403()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, "ghost"), "ghost", default)).Status);
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, "owner"), "owner", default)).Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task Input_FloorHolder_200_ReachesAgent()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        var reply = await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "ctrl", default);
        Assert.Equal(200, reply.Status);
        Assert.Equal(1, f.Channel.CountTool("key_press"));
        Assert.Equal(1, f.Service.Stats(id).InputsAccepted);
    }

    [Fact]
    public async Task Input_FloorGrantMidStream_TakesEffectOnNextEvent()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, "peer"), "peer", default)).Status);
        Assert.True(f.W.Sessions.GrantFloor(id, "peer", "host"));
        // The very next event from the new holder is accepted; the
        // very next event from the old holder is refused.
        Assert.Equal(200, (await f.Service.PostInputAsync(f.InputBody(id, "peer"), "peer", default)).Status);
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "ctrl", default)).Status);
        Assert.True(f.W.Sessions.TakeFloorBack(id, "host"));
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, "peer"), "peer", default)).Status);
        Assert.Equal(1, f.Channel.InputToolCalls); // exactly one event ever reached the desktop
    }

    [Fact]
    public async Task FloorTheftRace_TwoSimultaneousGrants_ExactlyOneHolder()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        // Two grants racing on separate threads: the session model
        // serializes them; afterwards exactly ONE participant holds
        // the floor and only that one's input is accepted.
        Parallel.Invoke(
            () => f.W.Sessions.GrantFloor(id, "peer", "host"),
            () => f.W.Sessions.GrantFloor(id, "ctrl", "host"));
        var holders = f.W.Sessions.ListParticipants(id).Where(p => p.Floor == "holds").ToList();
        var holder = Assert.Single(holders);
        var loser = holder.UserId == "peer" ? "ctrl" : "peer";
        Assert.Equal(200, (await f.Service.PostInputAsync(f.InputBody(id, holder.UserId), holder.UserId, default)).Status);
        Assert.Equal(403, (await f.Service.PostInputAsync(f.InputBody(id, loser), loser, default)).Status);
    }

    // ---- stream dies with the session -------------------------------

    [Fact]
    public async Task SessionEnd_MidStream_KillsStream_OnNextFrameAndInput()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        Assert.Equal(200, (await f.Service.GetFrameAsync(id, 0, "ctrl", default)).Status);
        Assert.True(f.W.Sessions.EndSession(id, "ctrl"));
        Assert.Equal(409, (await f.Service.GetFrameAsync(id, 0, "ctrl", default)).Status);
        Assert.False(f.Service.IsStreaming(id));
        Assert.True(f.Channel.CountTool("stream_stop") >= 1); // capture told to die
        Assert.Equal(409, (await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "ctrl", default)).Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task SessionBlock_MidStream_KillsStream()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        Assert.True(f.W.Sessions.BlockSession(id, "ctrl"));
        Assert.Equal(409, (await f.Service.GetFrameAsync(id, 0, "ctrl", default)).Status);
        Assert.False(f.Service.IsStreaming(id));
    }

    [Fact]
    public async Task StopInForce_RefusesStart_And_KillsLiveStream()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        f.StopInForce = true;
        Assert.Equal(409, (await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "ctrl", default)).Status);
        Assert.False(f.Service.IsStreaming(id));
        Assert.Equal(409, (await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default)).Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task Offboarding_MidStream_EndsSessionAndStream()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        // The floor holder is removed from the roster entirely —
        // the Slice 3 offboarding hook must end the session, and
        // the stream with it, on the next stream-layer call.
        Assert.NotNull(f.W.Roster.RemoveUser("company-1", "ctrl", "admin"));
        var reply = await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "ctrl", default);
        Assert.Equal(409, reply.Status);
        Assert.Equal("ended", f.W.Sessions.GetSession(id)!.State);
        Assert.False(f.Service.IsStreaming(id));
        Assert.Equal(0, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task ExplicitStop_KillsStream_FramesRefuseAfter()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        var stop = await f.Service.StopAsync(JsonSerializer.Serialize(new { sessionId = id }), "ctrl", default);
        Assert.Equal(200, stop.Status);
        Assert.False(f.Service.IsStreaming(id));
        Assert.Equal(409, (await f.Service.GetFrameAsync(id, 0, "ctrl", default)).Status);
        Assert.Equal("active", f.W.Sessions.GetSession(id)!.State); // session itself untouched
    }

    // ---- frames ------------------------------------------------------

    [Fact]
    public async Task Frame_Valid_Served_AndCounted()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        var reply = await f.Service.GetFrameAsync(id, 0, "ctrl", default);
        Assert.Equal(200, reply.Status);
        var frame = StreamProtocol.TryParse(reply.Body);
        Assert.NotNull(frame);
        Assert.True(frame!.Header.Keyframe);
        Assert.Equal(1, f.Service.Stats(id).FramesServed);
        // Same seq again → 204 (nothing newer).
        Assert.Equal(204, (await f.Service.GetFrameAsync(id, 1, "ctrl", default)).Status);
    }

    [Fact]
    public async Task Frame_HostileAgentBytes_DroppedAndCounted_NeverServed()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        f.Channel.Handler = (tool, _) => tool == "stream_frame"
            ? ToolResult.Success(JsonSerializer.Serialize(new { seq = 9, data = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5 }) }))
            : ToolResult.Success("ok");
        var reply = await f.Service.GetFrameAsync(id, 0, "ctrl", default);
        Assert.Equal(502, reply.Status);
        Assert.Equal(1, f.Service.Stats(id).FramesDroppedInvalid);
        Assert.Equal(0, f.Service.Stats(id).FramesServed);
    }

    [Fact]
    public async Task Frame_WithoutStreamStart_409()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        Assert.Equal(409, (await f.Service.GetFrameAsync(id, 0, "ctrl", default)).Status);
    }

    [Fact]
    public async Task Info_CarriesRosterFloorAndEncoderTruth()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        await f.Service.StartAsync(f.StartBody(id, "ctrl"), "ctrl", default);
        await f.Service.GetFrameAsync(id, 0, "ctrl", default);
        var reply = await f.Service.GetInfoAsync(id, default);
        Assert.Equal(200, reply.Status);
        var json = JsonDocument.Parse(Encoding.UTF8.GetString(reply.Body)).RootElement;
        Assert.True(json.GetProperty("ok").GetBoolean());
        Assert.True(json.GetProperty("streaming").GetBoolean());
        Assert.Equal("ctrl", json.GetProperty("floor").GetProperty("userId").GetString());
        Assert.Equal("Controller", json.GetProperty("floor").GetProperty("name").GetString());
        Assert.Equal(42, json.GetProperty("framesEncoded").GetInt64());
        Assert.Equal("Test MFT", json.GetProperty("encoder").GetString());
        Assert.True(json.GetProperty("hardware").GetBoolean());
        var roster = json.GetProperty("roster").EnumerateArray().ToList();
        Assert.Contains(roster, p => p.GetProperty("userId").GetString() == "peer" && p.GetProperty("floor").GetString() == "watching");
    }

    [Fact]
    public async Task Input_PointerAbs_CarriesTheStreamsMonitor()
    {
        // Regression (Block D recovery 2026-11-19): pointer_abs args
        // must name the monitor the stream is bound to — without it
        // the agent places absolute input on monitor 0 regardless of
        // which monitor is streaming.
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        var startBody = JsonSerializer.Serialize(new { sessionId = id, userId = "ctrl", monitor = 1 });
        Assert.Equal(200, (await f.Service.StartAsync(startBody, "ctrl", default)).Status);
        var input = JsonSerializer.Serialize(new
        {
            sessionId = id, userId = "ctrl",
            @event = new { type = "pointer_abs", x = 40, y = 50 },
        });
        Assert.Equal(200, (await f.Service.PostInputAsync(input, "ctrl", default)).Status);
        var call = Assert.Single(f.Channel.Calls, c => c.Tool == "mouse_move_abs_stream");
        using var doc = JsonDocument.Parse(call.Args);
        Assert.Equal(1, doc.RootElement.GetProperty("monitor").GetInt32());
        Assert.Equal(40, doc.RootElement.GetProperty("x").GetInt32());
    }

    [Fact]
    public async Task Input_UnknownEventType_400_And_Malformed_400()
    {
        var f = new Fixture();
        var id = ActiveSession(f.W, floorTo: "ctrl");
        var bad = JsonSerializer.Serialize(new { sessionId = id, userId = "ctrl", @event = new { type = "teleport" } });
        Assert.Equal(400, (await f.Service.PostInputAsync(bad, "ctrl", default)).Status);
        Assert.Equal(400, (await f.Service.PostInputAsync("{not json", "ctrl", default)).Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
    }
}

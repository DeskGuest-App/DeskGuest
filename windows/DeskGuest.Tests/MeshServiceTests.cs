using System.Text;
using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>Mesh companion protocol v1 (M2) — the server side of the
/// contract the Android device page already speaks. Pins: the state
/// derivation (IDLE / AI_DRIVING / HUMAN_MANUAL) from real facts,
/// the heartbeat field set the client parses, manual claim/release
/// semantics (input claims, handoff/disconnect/timeout release —
/// never latched), and honest refusals (locked desktop, agent down,
/// malformed events).</summary>
public class MeshServiceTests
{
    private sealed class FakeChannel : IAgentChannel
    {
        public bool AgentConnected { get; set; } = true;
        public List<(string Tool, string Args)> Calls { get; } = new();
        public Func<string, string, ToolResult> Handler { get; set; } = (_, _) => ToolResult.Success("ok");
        public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
        {
            Calls.Add((tool, argumentsJson));
            return Task.FromResult(Handler(tool, argumentsJson));
        }
    }

    private static readonly DateTimeOffset T0 = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);

    private sealed class Fixture
    {
        public FakeChannel Channel { get; } = new();
        public DateTimeOffset Now = T0;
        public SessionRecord? Session;
        public int Actions;
        public bool Unlocked = true;
        public string? Narration;
        private MeshService? _service;
        public MeshService Service => _service ??= new(Channel,
            () => Session,
            () => Actions,
            () => Unlocked,
            () => Narration,
            () => Now,
            deviceName: "HOST-LAPTOP");

        public SessionRecord StartSession(string agent = "Muse") =>
            Session = new SessionRecord("s1", "p1", agent, new HashSet<string> { "drive" }, Now, Now, null, true);
    }

    private static JsonElement StateJson(MeshReply reply)
    {
        Assert.Equal(200, reply.Status);
        return JsonDocument.Parse(Encoding.UTF8.GetString(reply.Body)).RootElement;
    }

    [Fact]
    public void State_Idle_CarriesTheContractFields()
    {
        var f = new Fixture();
        var json = StateJson(f.Service.GetState());
        Assert.Equal("IDLE", json.GetProperty("state").GetString());
        Assert.Equal("HOST-LAPTOP", json.GetProperty("device").GetString());
        Assert.Equal("", json.GetProperty("agent").GetString());
        Assert.Equal(0, json.GetProperty("sessionSeconds").GetInt64());
        Assert.Equal(0, json.GetProperty("actions").GetInt32());
        Assert.Equal("", json.GetProperty("intent").GetString());
        Assert.True(json.GetProperty("preview").GetBoolean()); // agent connected + unlocked
    }

    [Fact]
    public void State_AiDriving_ReportsSessionFacts()
    {
        var f = new Fixture();
        f.StartSession("Muse");
        f.Actions = 7;
        f.Narration = "Rebuilding the presence layer";
        f.Now = T0 + TimeSpan.FromSeconds(95);
        var json = StateJson(f.Service.GetState());
        Assert.Equal("AI_DRIVING", json.GetProperty("state").GetString());
        Assert.Equal("Muse", json.GetProperty("agent").GetString());
        Assert.Equal(95, json.GetProperty("sessionSeconds").GetInt64());
        Assert.Equal(7, json.GetProperty("actions").GetInt32());
        Assert.Equal("Rebuilding the presence layer", json.GetProperty("intent").GetString());
    }

    [Fact]
    public void State_PreviewUnavailable_WhenLockedOrAgentDown()
    {
        var f = new Fixture();
        f.Unlocked = false;
        Assert.False(StateJson(f.Service.GetState()).GetProperty("preview").GetBoolean());
        f.Unlocked = true;
        f.Channel.AgentConnected = false;
        Assert.False(StateJson(f.Service.GetState()).GetProperty("preview").GetBoolean());
    }

    [Fact]
    public async Task Input_Pointer_ClaimsManual_AndForwardsRelativeMove()
    {
        var f = new Fixture();
        f.StartSession();
        var reply = await f.Service.PostInputAsync("""{"type":"pointer","dx":0.5,"dy":-0.25}""", default);
        Assert.Equal(200, reply.Status);
        Assert.Equal("HUMAN_MANUAL", f.Service.CurrentState);
        var call = Assert.Single(f.Channel.Calls);
        Assert.Equal("mouse_move_rel", call.Tool);
        using var args = JsonDocument.Parse(call.Args);
        Assert.Equal(0.5, args.RootElement.GetProperty("dx").GetDouble());
        Assert.Equal(-0.25, args.RootElement.GetProperty("dy").GetDouble());
    }

    [Fact]
    public async Task Input_KeyAndText_MapToEngineTools()
    {
        var f = new Fixture();
        await f.Service.PostInputAsync("""{"type":"key","key":"alt_tab"}""", default);
        await f.Service.PostInputAsync("""{"type":"key","key":"win"}""", default);
        await f.Service.PostInputAsync("""{"type":"text","text":"hello"}""", default);
        await f.Service.PostInputAsync("""{"type":"button","button":"right","action":"click"}""", default);
        Assert.Equal("key_press", f.Channel.Calls[0].Tool);
        using (var chord = JsonDocument.Parse(f.Channel.Calls[0].Args))
            Assert.Equal("alt+tab", chord.RootElement.GetProperty("keys").GetString());
        using (var win = JsonDocument.Parse(f.Channel.Calls[1].Args))
            Assert.Equal("win", win.RootElement.GetProperty("keys").GetString());
        Assert.Equal("type_text", f.Channel.Calls[2].Tool);
        Assert.Equal("button_here", f.Channel.Calls[3].Tool);
        Assert.Contains("\"right\"", f.Channel.Calls[3].Args);
    }

    [Fact]
    public async Task Input_RefusedHonestly_WhenLockedOrAgentDownOrMalformed()
    {
        var f = new Fixture();
        f.Unlocked = false;
        var locked = await f.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0.1}""", default);
        Assert.Equal(503, locked.Status);
        Assert.Equal("IDLE", f.Service.CurrentState); // a refused input claims nothing

        f.Unlocked = true;
        f.Channel.AgentConnected = false;
        Assert.Equal(503, (await f.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0.1}""", default)).Status);

        f.Channel.AgentConnected = true;
        Assert.Equal(400, (await f.Service.PostInputAsync("not json", default)).Status);
        Assert.Equal(400, (await f.Service.PostInputAsync("""{"type":"teleport"}""", default)).Status);
    }

    [Fact]
    public async Task Handoff_AndDisconnect_ReleaseManual()
    {
        var f = new Fixture();
        f.StartSession();
        await f.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0}""", default);
        Assert.Equal("HUMAN_MANUAL", f.Service.CurrentState);
        f.Service.PostHandoff();
        Assert.Equal("AI_DRIVING", f.Service.CurrentState); // back to the live session

        await f.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0}""", default);
        Assert.Equal("HUMAN_MANUAL", f.Service.CurrentState);
        f.Service.PostDisconnect();
        Assert.Equal("AI_DRIVING", f.Service.CurrentState);
    }

    [Fact]
    public async Task Manual_TimesOut_UnlessThePhoneIsStillWatching()
    {
        var f = new Fixture();
        await f.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0}""", default);
        Assert.Equal("HUMAN_MANUAL", f.Service.CurrentState);
        f.Now = T0 + TimeSpan.FromSeconds(120); // no heartbeat, no input
        Assert.Equal("IDLE", f.Service.CurrentState); // never latched

        // With a fresh watching heartbeat, manual holds past the
        // input-recency window.
        var f2 = new Fixture();
        await f2.Service.PostInputAsync("""{"type":"pointer","dx":0.1,"dy":0}""", default);
        f2.Now = T0 + TimeSpan.FromSeconds(120);
        f2.Service.PostHeartbeat("""{"from":"Android","watching":true,"at":0}""");
        Assert.Equal("HUMAN_MANUAL", f2.Service.CurrentState);
        f2.Now = T0 + TimeSpan.FromSeconds(200); // heartbeat now stale too
        Assert.Equal("IDLE", f2.Service.CurrentState);
    }

    [Fact]
    public void Heartbeat_Malformed_IsA400_NotASilentAccept()
    {
        var f = new Fixture();
        Assert.Equal(400, f.Service.PostHeartbeat("{nope").Status);
        Assert.Equal(200, f.Service.PostHeartbeat("""{"from":"Android","watching":true,"at":0}""").Status);
    }

    [Fact]
    public async Task Preview_ServesJpegBytes_AndRefusesWhenLocked()
    {
        var f = new Fixture();
        var jpeg = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3 };
        f.Channel.Handler = (tool, _) => tool == "screenshot_jpeg"
            ? ToolResult.Success(Convert.ToBase64String(jpeg))
            : ToolResult.Success("ok");
        var reply = await f.Service.GetPreviewAsync(default);
        Assert.Equal(200, reply.Status);
        Assert.Equal("image/jpeg", reply.ContentType);
        Assert.Equal(jpeg, reply.Body);

        f.Unlocked = false;
        Assert.Equal(503, (await f.Service.GetPreviewAsync(default)).Status);
    }
}

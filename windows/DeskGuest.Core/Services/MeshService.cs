using System.Text;
using System.Text.Json;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Modules;

namespace DeskGuest.Core.Services;

/// <summary>One mesh endpoint answer: HTTP status, content type, body.</summary>
public sealed record MeshReply(int Status, string ContentType, byte[] Body)
{
    public static MeshReply Json(int status, object payload) =>
        new(status, "application/json", Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
    public static MeshReply Error(int status, string error) => Json(status, new { error });
}

/// <summary>
/// The mesh companion protocol v1 (MESH-CONTRACT.md) — the server
/// side the Android 0.4.x device page already speaks:
///
///   GET  /mesh/state     heartbeat JSON {state, device, agent,
///                        sessionSeconds, actions, intent, preview}
///   GET  /mesh/preview   a JPEG of the desktop (when preview=true)
///   POST /mesh/input     one manual input event (the phone's
///                        trackpad/buttons/keys/text)
///   POST /mesh/handoff   the phone yields manual control back
///   POST /mesh/disconnect the phone link ends (manual released)
///   POST /mesh/heartbeat the phone's presence while its page is open
///
/// States: IDLE (no session, no manual) | AI_DRIVING (an DeskGuest
/// session is live) | HUMAN_MANUAL (the phone has sent input and
/// its page is still open). Manual is claimed by the first accepted
/// input event, held while the phone heartbeats as watching (or
/// for 90 s after the last input), and released by handoff,
/// disconnect, or timeout — it can never latch on forever.
///
/// Trust (BD-WIN-CORE-3/F1, hardened + built): the HTTP mesh
/// routes FAIL CLOSED (401) at LaneHostManager unless the request
/// carries the pairing bearer token and MeshIdentityResolver maps
/// it to a unique live roster user — the tailnet is a network
/// boundary, NOT an identity, and any tailnet peer or local
/// process must not be able to type, click or capture the desktop.
/// This service is the in-process
/// half; the route gate lives in LaneHostManager. A user STOP in
/// force also refuses mesh input/preview here: STOP is the
/// person's veto over remote control, and the phone is a remote
/// hand. A locked desktop refuses honestly, exactly like the
/// desktop tools.
///
/// Execution goes through the same IPC desktop channel as the
/// agent's tools (mouse_move_rel / button_here / key_press /
/// type_text / screenshot_jpeg on the Session Agent), so manual
/// drive and agent drive share one input plane and one takeover
/// yield.
/// </summary>
public sealed class MeshService
{
    private static readonly TimeSpan HeartbeatFreshness = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ManualHoldAfterInput = TimeSpan.FromSeconds(90);

    private readonly IAgentChannel _channel;
    private readonly Func<SessionRecord?> _currentSession;
    private readonly Func<int> _sessionActions;
    private readonly Func<bool> _desktopUnlocked;
    private readonly Func<string?> _narration;
    private readonly Func<DateTimeOffset> _now;
    private readonly string _deviceName;
    private readonly Func<IReadOnlyList<HumanSessionFact>>? _humanSessions;
    // BD-WIN-CORE-3/F1: the user STOP (CoreState.StopInForce) DOES
    // block mesh manual input + preview. STOP is the person's
    // one-action veto over remote control of their desktop; the
    // phone is a remote hand, not the person at the keyboard, so
    // a stop in force refuses mesh drive/capture by name.
    private readonly Func<bool>? _stopInForce;

    private readonly object _gate = new();
    private bool _manualClaimed;
    private DateTimeOffset _lastInputUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _lastHeartbeatUtc = DateTimeOffset.MinValue;
    private bool _phoneWatching;
    private string? _phoneName;

    public MeshService(
        IAgentChannel channel,
        Func<SessionRecord?> currentSession,
        Func<int> sessionActions,
        Func<bool> desktopUnlocked,
        Func<string?> narration,
        Func<DateTimeOffset>? now = null,
        string? deviceName = null,
        Func<IReadOnlyList<HumanSessionFact>>? humanSessions = null,
        Func<bool>? stopInForce = null)
    {
        _channel = channel;
        _currentSession = currentSession;
        _sessionActions = sessionActions;
        _desktopUnlocked = desktopUnlocked;
        _narration = narration;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _deviceName = deviceName ?? Environment.MachineName;
        _humanSessions = humanSessions;
        _stopInForce = stopInForce;
    }

    /// <summary>BD-WIN-CORE-3/F1: true while the user's STOP is in
    /// force (when the host wired the stop delegate).</summary>
    public bool StopInForce => _stopInForce?.Invoke() ?? false;

    /// <summary>The primary LIVE Slice 3 human session in the one
    /// session picture, or null. Agent (MCP) sessions and human
    /// sessions are both first-class here (Block A wiring).</summary>
    private HumanSessionFact? PrimaryHuman
    {
        get
        {
            var all = _humanSessions?.Invoke();
            if (all is null) return null;
            // Same precedence as SessionPicture.PrimaryLive: active
            // over paused over blocked (the provider list is already
            // newest-first, which breaks ties).
            return all.Where(f => f.State is "active" or "paused" or "blocked")
                .OrderBy(f => f.State == "active" ? 0 : f.State == "paused" ? 1 : 2)
                .FirstOrDefault();
        }
    }

    /// <summary>The phone currently linked to the mesh, if any:
    /// its self-reported name + whether it is watching right now
    /// (heartbeat-fresh). Facts for the host snapshot (Block H:
    /// the tray popup reads mesh truth from the snapshot, not from
    /// a loopback HTTP fetch the production lane set never serves).</summary>
    public (string? PhoneName, bool PhoneWatching) PhoneFacts
    {
        get
        {
            lock (_gate)
            {
                var watching = _phoneWatching && _now() - _lastHeartbeatUtc <= HeartbeatFreshness;
                return (_phoneName, watching);
            }
        }
    }

    /// <summary>The state the phone should show right now.</summary>
    public string CurrentState
    {
        get
        {
            if (ManualActive) return "HUMAN_MANUAL";
            if (_currentSession() is not null) return "AI_DRIVING";
            return PrimaryHuman is not null ? "HUMAN_SESSION" : "IDLE";
        }
    }

    private bool ManualActive
    {
        get
        {
            lock (_gate)
            {
                if (!_manualClaimed) return false;
                var now = _now();
                var heldByWatching = _phoneWatching && now - _lastHeartbeatUtc <= HeartbeatFreshness;
                var heldByRecency = now - _lastInputUtc <= ManualHoldAfterInput;
                return heldByWatching || heldByRecency;
            }
        }
    }

    private bool PreviewAvailable => _channel.AgentConnected && _desktopUnlocked();

    public MeshReply GetState()
    {
        var session = _currentSession();
        var now = _now();
        var human = PrimaryHuman;
        var humanFacts = _humanSessions?.Invoke() ?? Array.Empty<HumanSessionFact>();
        return MeshReply.Json(200, new
        {
            state = CurrentState,
            device = _deviceName,
            // The headline fields describe the controlling session,
            // whichever kind it is: the agent (MCP) session when one
            // is live, else the live human session (its initiator is
            // the named party), else empty.
            agent = session?.ActorAgentName ?? human?.InitiatorName ?? "",
            sessionSeconds = session is not null
                ? Math.Max(0, (long)(now - session.StartedUtc).TotalSeconds)
                : human?.Seconds ?? 0,
            actions = session is not null ? _sessionActions() : human?.Actions ?? 0,
            intent = _narration() ?? "",
            preview = PreviewAvailable,
            // The full human-session picture rides along so the
            // operator side sees agent and human sessions in ONE
            // state document (Block A wiring).
            humanSessions = humanFacts.Select(h => new
            {
                id = h.Id, initiator = h.InitiatorName, kind = h.Kind,
                state = h.State, seconds = h.Seconds, recording = h.Recording,
                isRecording = h.IsRecording, floorHolder = h.FloorHolderName,
                participants = h.ParticipantCount,
            }).ToArray()
        });
    }

    public async Task<MeshReply> GetPreviewAsync(CancellationToken ct)
    {
        if (StopInForce)
            return MeshReply.Error(503, "user STOP is in force — mesh preview refused");
        if (!_channel.AgentConnected)
            return MeshReply.Error(503, "session agent not connected");
        if (!_desktopUnlocked())
            return MeshReply.Error(503, "desktop locked — no preview");
        var result = await _channel.CallDesktopToolAsync("screenshot_jpeg", "{}", ct);
        if (!result.Ok || result.Text is null)
            return MeshReply.Error(502, result.UnavailableReason ?? result.Text ?? "preview capture failed");
        try
        {
            return new MeshReply(200, "image/jpeg", Convert.FromBase64String(result.Text));
        }
        catch (FormatException)
        {
            return MeshReply.Error(502, "preview capture returned undecodable bytes");
        }
    }

    public async Task<MeshReply> PostInputAsync(string bodyJson, CancellationToken ct)
    {
        if (StopInForce)
            return MeshReply.Error(503, "user STOP is in force — mesh manual input refused");
        if (!_channel.AgentConnected)
            return MeshReply.Error(503, "session agent not connected");
        if (!_desktopUnlocked())
            return MeshReply.Error(503, "desktop locked — manual input refused");
        JsonDocument doc;
        try { doc = JsonDocument.Parse(bodyJson); }
        catch (JsonException) { return MeshReply.Error(400, "input event is not JSON"); }
        using (doc)
        {
            var root = doc.RootElement;
            var type = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("type", out var t) ? t.GetString() : null;
            var (tool, args) = type switch
            {
                "pointer" => ("mouse_move_rel", JsonSerializer.Serialize(new
                {
                    dx = Number(root, "dx"),
                    dy = Number(root, "dy")
                })),
                "button" => ("button_here", JsonSerializer.Serialize(new
                {
                    button = Text(root, "button") ?? "left",
                    action = Text(root, "action") ?? "click"
                })),
                "key" => ("key_press", JsonSerializer.Serialize(new
                {
                    keys = MapKey(Text(root, "key") ?? "")
                })),
                "text" => ("type_text", JsonSerializer.Serialize(new
                {
                    text = Text(root, "text") ?? ""
                })),
                _ => (null, null)
            };
            if (tool is null) return MeshReply.Error(400, $"unknown input event type: {type ?? "(missing)"}");
            var result = await _channel.CallDesktopToolAsync(tool, args!, ct);
            if (!result.Ok)
                return MeshReply.Error(502, result.UnavailableReason ?? result.Text ?? "input failed in the session agent");
        }
        lock (_gate)
        {
            _manualClaimed = true;
            _lastInputUtc = _now();
        }
        return MeshReply.Json(200, new { state = CurrentState });
    }

    public MeshReply PostHandoff()
    {
        lock (_gate) { _manualClaimed = false; }
        return MeshReply.Json(200, new { state = CurrentState });
    }

    public MeshReply PostDisconnect()
    {
        lock (_gate)
        {
            _manualClaimed = false;
            _phoneWatching = false;
        }
        return MeshReply.Json(200, new { state = CurrentState });
    }

    public MeshReply PostHeartbeat(string bodyJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(bodyJson);
            var root = doc.RootElement;
            lock (_gate)
            {
                _lastHeartbeatUtc = _now();
                _phoneWatching = root.ValueKind == JsonValueKind.Object
                    && root.TryGetProperty("watching", out var w) && w.ValueKind == JsonValueKind.True;
                _phoneName = Text(root, "from") ?? _phoneName;
            }
        }
        catch (JsonException)
        {
            return MeshReply.Error(400, "heartbeat is not JSON");
        }
        return MeshReply.Json(200, new { state = CurrentState });
    }

    /// <summary>Phone key names → the desktop engine's chord syntax.
    /// BD-WIN-CORE-3/F12(d): ONLY the known chord names are mapped;
    /// every other key name passes through UNCHANGED — the old
    /// blanket '_'→'+' rewrite corrupted legitimate key names that
    /// contain underscores (e.g. a named key like "page_up" became
    /// a bogus chord).</summary>
    internal static string MapKey(string key) => key switch
    {
        "alt_tab" => "alt+tab",
        "ctrl_alt_delete" => "ctrl+alt+delete",
        "ctrl_shift_escape" => "ctrl+shift+escape",
        _ => key
    };

    private static double Number(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number ? el.GetDouble() : 0;

    private static string? Text(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;
}

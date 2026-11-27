using System.Text.Json;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.State;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Phase2;

/// <summary>
/// OWNER CONSOLE (the owner's idea, 2026-11-14 evening): the cross-device
/// layer of the platform. Three capabilities, one model:
///  1. Fleet board — every host publishes its live session board;
///     any host (or the owner's app) can read the fleet's state.
///  2. Live view — while an agent drives, the owner can window in and
///     watch the screen stream the agent is already producing.
///  3. Takeover + owner-remote — the owner outranks every agent, from
///     either end; and the hosts double as plain remote-access
///     endpoints for the owner himself when no agent is connected.
/// The asymmetry is named in the model, not hidden: a Windows host can
/// be reached from a cold locked state (Route B); an Android host
/// cannot be remotely unlocked (OS wall + X1). Publications carry it.
/// </summary>
public sealed record HostPublication(
    string HostId,
    string HostName,
    string Platform,                 // "windows" | "android"
    EndpointState State,
    bool SessionLive,
    string? ActingAgent,
    string? Narration,
    bool OwnerCanUnlockRemotely,     // true for Windows+Route B; false for Android
    DateTimeOffset PublishedUtc);

/// <summary>Publishes this host's board and aggregates peers'. Peer
/// fetch rides the same authenticated channels as everything else;
/// the transport is an interface so the board logic is VM-testable.</summary>
public interface IPeerBoardTransport
{
    Task<HostPublication?> FetchAsync(string hostId, CancellationToken ct);
}

public sealed class FleetBoard
{
    private readonly Dictionary<string, HostPublication> _peers = new();
    private readonly IPeerBoardTransport? _transport;
    private readonly string[] _peerIds;

    public FleetBoard(IPeerBoardTransport? transport = null, IEnumerable<string>? peerIds = null)
    {
        _transport = transport;
        _peerIds = peerIds?.ToArray() ?? Array.Empty<string>();
    }

    public HostPublication Publish(HostPublication publication)
    {
        lock (_peers) _peers[publication.HostId] = publication;
        return publication;
    }

    /// <summary>Per-peer fetch budget (BD-WIN-CORE-2/F12): peers are
    /// fetched in PARALLEL, each with its own timeout, so one hung
    /// peer cannot stall the whole board; a successful fetch is
    /// cached into _peers so the 'last known, timestamped' fallback
    /// actually has data to fall back to.</summary>
    public TimeSpan PeerFetchTimeout { get; set; } = TimeSpan.FromSeconds(2);

    public async Task<IReadOnlyList<HostPublication>> BoardAsync(HostPublication self, CancellationToken ct)
    {
        var board = new Dictionary<string, HostPublication> { [self.HostId] = self };
        if (_transport is not null && _peerIds.Length > 0)
        {
            var fetches = _peerIds.Select(async peerId =>
            {
                HostPublication? pub = null;
                try
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(PeerFetchTimeout);
                    var fetch = _transport.FetchAsync(peerId, timeout.Token);
                    // Race the fetch against the budget: a transport
                    // that ignores its cancellation token must not be
                    // able to stall the board (found by the F12 test —
                    // the first version only cancelled cooperatively).
                    pub = await Task.WhenAny(fetch, Task.Delay(PeerFetchTimeout, ct)) == fetch
                        ? await fetch
                        : null;
                }
                catch { pub = null; /* timeout / transport failure: fall back to last known below */ }
                if (pub is not null)
                {
                    lock (_peers) _peers[peerId] = pub; // cache successes for the fallback
                    return (peerId, pub);
                }
                lock (_peers) return (peerId, _peers.TryGetValue(peerId, out var cached) ? cached : null);
            });
            foreach (var (peerId, pub) in await Task.WhenAll(fetches))
                if (pub is not null) board[peerId] = pub;
        }
        lock (_peers)
        {
            foreach (var kv in _peers) board.TryAdd(kv.Key, kv.Value);
        }
        return board.Values.OrderBy(p => p.HostName).ToList();
    }
}

/// <summary>
/// Takeover arbitration: the owner outranks the agent — always, from
/// either end. While the owner holds the desktop, agent desktop tools
/// are denied by the policy engine (SessionFacts.TakeoverActive) and
/// capture is suspended entirely: the log records THAT a takeover
/// occurred, never its content (SPEC §7.9). Handback is explicit.
/// </summary>
public sealed class TakeoverArbiter
{
    private readonly CoreState _state;
    private readonly IAuditLog? _audit;
    public TakeoverArbiter(CoreState state, IAuditLog? audit = null) { _state = state; _audit = audit; }

    public bool OwnerHoldsDesktop => _state.Session.TakeoverActive;

    /// <summary>OWNER-LOCAL ONLY (BD-WIN-CORE-2/F1, the blocker):
    /// seize/handback are acts of the owner at the machine (or the
    /// owner's own authenticated console channel) — they are NOT
    /// agent-callable. These methods are the owner-side API; the MCP
    /// module below refuses every pairing, Admin scope included, so
    /// no agent can seize the desktop in the owner's name or hand
    /// back a takeover the owner started. Every transition is
    /// audit-appended when a log is wired (the result text claimed
    /// this before it was true; now it is).</summary>
    public ToolResult Seize(string ownerIdentity)
    {
        _state.UpdateSession(s => s with { TakeoverActive = true });
        _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, ownerIdentity, "owner_takeover", "seize", null, "owner_takeover_seized", "Owner", null));
        return ToolResult.Success($"the owner ({ownerIdentity}) has taken over: the agent is paused, capture is suspended, and the takeover — never its content — is in the audit log");
    }

    public ToolResult HandBack()
    {
        _state.UpdateSession(s => s with { TakeoverActive = false });
        _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, "owner_takeover", "handback", null, "owner_takeover_handback", "Owner", null));
        return ToolResult.Success("desktop handed back to the agent session");
    }
}

/// <summary>Live view: the Agent already produces frames for its own
/// work; the latest frame is mirrored to the owner on request. Frames
/// flow Agent → Core over IPC (tool "live_view_frame"); the owner
/// polls through this module. While a takeover is active, live view
/// shows the takeover state, not the screen (takeover privacy).</summary>
public sealed class LiveViewService
{
    private readonly Ipc.AgentIpcServer _ipc;
    private readonly CoreState _state;
    private readonly IAuditLog? _audit;
    private readonly string _ownerDisplayName;
    public LiveViewService(Ipc.AgentIpcServer ipc, CoreState state, IAuditLog? audit = null, string ownerDisplayName = "the owner")
    { _ipc = ipc; _state = state; _audit = audit; _ownerDisplayName = string.IsNullOrWhiteSpace(ownerDisplayName) ? "the owner" : ownerDisplayName; }

    public Task<ToolResult> LatestFrameAsync(CancellationToken ct) => LatestFrameAsync(null, null, ct);

    /// <summary>Frame pulls are audited as owner views (BD-WIN-CORE-2/F12):
    /// who pulled a frame of the driven desktop is a fact the log keeps.
    /// The takeover note names the CONFIGURED owner, never a hardcoded
    /// person (the product is multi-owner / enterprise-capable).</summary>
    public async Task<ToolResult> LatestFrameAsync(string? pairingId, string? agentName, CancellationToken ct)
    {
        if (_state.Session.TakeoverActive)
        {
            _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairingId, agentName, "live_view", "frame", null, "live_view_suspended:takeover", "SYSTEM", null));
            return ToolResult.Success(JsonSerializer.Serialize(new { takeover = true, frame = (string?)null, note = $"{_ownerDisplayName} has taken over; capture is suspended by the takeover-privacy rule" }));
        }
        if (!_ipc.AgentConnected)
            return ToolResult.Unavailable("no session agent is connected; there is no live view of a desktop that has no session");
        _audit?.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairingId, agentName, "live_view", "frame", null, "live_view_frame_pulled", "SYSTEM", null));
        return await _ipc.CallDesktopToolAsync("screenshot", "{}", ct);
    }
}

public sealed class FleetBoardModule : IToolModule
{
    private readonly FleetBoard _board;
    private readonly CoreState _state;
    private readonly Modules.SessionManager _sessions;
    private readonly string _hostName;

    public FleetBoardModule(FleetBoard board, CoreState state, Modules.SessionManager sessions, string hostName)
    {
        _board = board; _state = state; _sessions = sessions; _hostName = hostName;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "fleet_board", "The Owner Console fleet board: every host's live session state (this host plus paired peers), with staleness timestamps.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var session = _sessions.Current;
        var self = new HostPublication(
            HostId: _hostName, HostName: _hostName, Platform: "windows",
            State: _state.ComputeState(),
            SessionLive: session is not null,
            ActingAgent: session?.ActorAgentName,
            Narration: null,
            OwnerCanUnlockRemotely: true, // Windows + Route B (Phase 2 gate); Android peers publish false
            PublishedUtc: DateTimeOffset.UtcNow);
        _board.Publish(self);
        var board = await _board.BoardAsync(self, ct);
        return ToolResult.Success(JsonSerializer.Serialize(board, new JsonSerializerOptions { WriteIndented = true }));
    }
}

public sealed class OwnerTakeoverModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "owner_takeover", "Owner Console takeover status surface. Takeover is an OWNER-LOCAL act: seize/handback are never agent-callable (any scope, Admin included) — the owner seizes by taking the machine (presence/STOP channel) and hands back the same way. This tool exists so an agent can be TOLD that, in-band.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["seize","handback"]}}}""");

    /// <summary>BD-WIN-CORE-2/F1 (blocker): the previous implementation
    /// let any Admin-scope pairing call handback (ending a takeover the
    /// owner started) or seize (recording the AGENT's name as 'the
    /// owner'). "The owner outranks every agent" cannot be enforced by
    /// a tool the agent can call — so the tool now refuses, always.
    /// The owner-side transitions live on TakeoverArbiter and are
    /// reached only from owner-local channels (the session agent's
    /// presence report of a physical takeover, the owner's console).</summary>
    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Error("owner_only",
            "owner_takeover is not agent-callable: seize and handback are owner-local acts. An agent pairing — Admin scope included — can neither seize the desktop in the owner's name nor hand back a takeover the owner started. If the owner has taken over, wait; the owner hands back from the machine."));
}

/// <summary>FR-120 (W73): the agent's ASK for control back. The
/// F1 rule stands untouched — handback itself is never
/// agent-callable (see OwnerTakeoverModule). What DeskGuest's FR-120
/// adds is the REQUEST path: this tool's only effect is to raise
/// the per-action gate at the endpoint (its declared gate class
/// is deliberately NOT in PolicyEngine.GatedClasses, so it can
/// never be standing-approved into silence: every ask shows the
/// owner a card). The owner's approval on that card is routed by
/// the Session Agent to the presence layer's hand-back; a denial,
/// a timeout, or no card at all leaves the owner driving. This
/// module's execution is merely the receipt that an approval
/// happened — it performs no state change itself.</summary>
public sealed class TakeoverHandBackRequestModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        DeskGuest.Shared.Presence.TakeoverGate.HandBackTool,
        "Ask the owner for control back after a takeover (FR-120). This tool NEVER takes control: it raises an approval card on the owner's screen, and only the owner's approval there hands control back. Denied or unanswered, the owner keeps driving and you keep observing. Call it once, then wait — do not retry in a loop.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Medium,
        GateClass: DeskGuest.Shared.Presence.TakeoverGate.HandBackGateClass, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Success(
            "The owner approved your request on the gate card; control is being handed back at the endpoint. The presence layer owns the exact moment — resume driving only when your next action confirms it."));
}

public sealed class LiveViewModule : IToolModule
{
    private readonly LiveViewService _liveView;
    public LiveViewModule(LiveViewService liveView) => _liveView = liveView;
    public ToolDescriptor Descriptor { get; } = new(
        "live_view", "Owner Console live view: the latest frame of the driven desktop, so the owner can window in and watch. Suspended during owner takeover by design. Frame pulls are audited.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        await _liveView.LatestFrameAsync(ctx.Pairing.Id, ctx.Pairing.AgentName, ct);
}

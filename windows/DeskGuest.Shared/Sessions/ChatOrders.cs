using System.Text.Json;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Shared.Sessions;

/// <summary>
/// W120 — S13 AI Chat + Order Cards (FEATURES.md §8 expansion;
/// REVISION-DRAFT §2.1 S13, ADDED-IN-LANGUAGE). The §8 law as one
/// UI-free model, shared by the Core (proposal validation,
/// execution) and the host window (the thread surface):
///
///  * Messaging is NOT a session: it grants no capability and
///    raises NO presence. The only execution door out of a thread
///    is an APPROVED order card — free text never executes. An
///    agent proposing action in prose gets nothing; a proposal
///    becomes a card only through the structured chat_order tool,
///    carrying the exact argument bytes the card will show.
///  * A card is a STRUCTURED ACTION CARD: title, exact steps with
///    real artefacts (the GatePayloadRenderer's rendering of the
///    exact payload — the same renderer S12's sheet uses), the
///    target device named, and S12's exact three exits. The exits
///    are GateSheetModel.Exits() themselves — the card consumes
///    the shared constants, so byte-identity with S12 holds by
///    construction, never by retyping. Approve = run this card.
///  * A card may only propose what the pairing's access slider
///    already grants (MayPropose): an order never widens a grant.
///  * Cross-device: an order aimed at another device names that
///    device on the card and can NEVER execute here — an order
///    runs only on the device it names, under that device's own
///    pairing, scopes and presence.
///  * Reachability is truth read from real state (the pairing's
///    last authenticated connection — W97 Pairing.cs state), never
///    a chat-local guess: «{name} can answer now» while the agent
///    side authenticated within the answer-now window, else
///    «{name} is away — your message will be delivered when it
///    wakes», with the queued count visible.
/// </summary>
public static class ChatOrderStatus
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Done = "done";
    public const string Failed = "failed";
    public const string Denied = "denied";
    public const string DeniedAndEnded = "denied_and_ended";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    { Pending, Running, Done, Failed, Denied, DeniedAndEnded };

    /// <summary>A status the owner can no longer answer.</summary>
    public static bool IsResolved(string status) => status != Pending && status != Running;
}

/// <summary>One structured order proposed in a pairing's thread.
/// ArgumentsJson is the EXACT argument bytes: the card renders
/// them (GatePayloadRenderer, OI-12 discipline) and an approval
/// submits exactly them — never re-encoded, never trimmed.</summary>
public sealed record ChatOrder(
    string Id,
    string PairingId,
    string Tool,
    string? GateClass,
    string ArgumentsJson,
    string Title,
    string TargetDevice,
    string Status,
    string? ResultLine,
    long CreatedAtMs,
    long? ResolvedAtMs);

/// <summary>The thread's order store: one JSON-lines file per
/// pairing beside the thread files. Orders are small and few;
/// a status change rewrites the pairing's file whole (atomic
/// temp + move), so a crash never leaves a half-written order.</summary>
public sealed class ChatOrderStore
{
    private readonly string _dir;
    private readonly object _gate = new();

    public ChatOrderStore(string dir) => _dir = dir ?? throw new ArgumentNullException(nameof(dir));

    private string OrderFile(string pairingId)
    {
        var safe = new string((pairingId ?? "").Select(c =>
            char.IsLetterOrDigit(c) || c is '_' or '-' ? c : '_').ToArray());
        return Path.Combine(_dir, safe + ".orders.jsonl");
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public IReadOnlyList<ChatOrder> Load(string pairingId)
    {
        lock (_gate)
        {
            var f = OrderFile(pairingId);
            if (!File.Exists(f)) return Array.Empty<ChatOrder>();
            var result = new List<ChatOrder>();
            foreach (var line in File.ReadLines(f))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var o = JsonSerializer.Deserialize<ChatOrder>(line, JsonOpts);
                    if (o is not null) result.Add(o);
                }
                catch { /* a torn line is skipped, never fatal — the rest of the record stands */ }
            }
            return result;
        }
    }

    public ChatOrder? Find(string pairingId, string orderId) =>
        Load(pairingId).FirstOrDefault(o => o.Id == orderId);

    public ChatOrder Append(ChatOrder order)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(_dir);
            File.AppendAllText(OrderFile(order.PairingId),
                JsonSerializer.Serialize(order, JsonOpts) + "\n");
            return order;
        }
    }

    /// <summary>Move one order to a new status (with its outcome
    /// line). Only a Pending order may be answered; only a Running
    /// order may complete. Anything else is refused — an answer
    /// can never resurrect or double-resolve a card.</summary>
    public bool TryResolve(string pairingId, string orderId, string newStatus, string? resultLine, long resolvedAtMs)
    {
        lock (_gate)
        {
            var all = Load(pairingId).ToList();
            var idx = all.FindIndex(o => o.Id == orderId);
            if (idx < 0) return false;
            var cur = all[idx];
            var legal = (cur.Status == ChatOrderStatus.Pending &&
                         newStatus is ChatOrderStatus.Running or ChatOrderStatus.Denied or ChatOrderStatus.DeniedAndEnded)
                     || (cur.Status == ChatOrderStatus.Running &&
                         newStatus is ChatOrderStatus.Done or ChatOrderStatus.Failed);
            if (!legal) return false;
            all[idx] = cur with { Status = newStatus, ResultLine = resultLine, ResolvedAtMs = resolvedAtMs };
            var f = OrderFile(pairingId);
            Directory.CreateDirectory(_dir);
            var tmp = f + ".tmp";
            File.WriteAllText(tmp, string.Join("\n", all.Select(o => JsonSerializer.Serialize(o, JsonOpts))) + "\n");
            File.Move(tmp, f, overwrite: true);
            return true;
        }
    }

    /// <summary>Unpairing ends the thread; its orders end with it.</summary>
    public void EndOrders(string pairingId)
    {
        lock (_gate)
        {
            var f = OrderFile(pairingId);
            if (File.Exists(f)) File.Delete(f);
        }
    }
}

/// <summary>The S13 card + reachability model (UI-free).</summary>
public static class ChatOrderModel
{
    /// <summary>The tool an agent uses to propose an order. It is
    /// a chat tool: like chat_read/chat_post it needs no session
    /// and grants nothing — proposing is not acting.</summary>
    public const string ProposeToolName = "chat_order";

    /// <summary>The chat tool family. None of these can be the
    /// SUBJECT of an order (an order to post a message would be
    /// free text wearing a card's clothes).</summary>
    public static bool IsChatTool(string? name) =>
        name is "chat_read" or "chat_post" or ProposeToolName;

    /// <summary>§8 HARD LAW: free text never executes. There is no
    /// conversion from prose to an executable — a proposal exists
    /// only as the structured chat_order call, or it doesn't
    /// happen. This is the pin the suite holds: prose in, nothing
    /// out.</summary>
    public static ChatOrder? FromProse(string pairingId, string prose, string thisDevice) => null;

    /// <summary>The card's exits ARE S12's exits — the shared
    /// GateSheetModel constants (Approve / Deny / Deny and end
    /// session, weight 600 each). The card renders these, so its
    /// labels are byte-identical to the gate sheet's by
    /// construction.</summary>
    public static IReadOnlyList<GateSheetModel.Exit> CardExits() => GateSheetModel.Exits();

    /// <summary>Slider law (W79 access state): a card may propose
    /// only what this pairing's grant already allows — the tool's
    /// required scope must be inside the pairing's scope set. An
    /// order never widens any device's grant (§8(5)).</summary>
    public static bool MayPropose(IReadOnlySet<string> pairingScopes, ToolDescriptor tool) =>
        !IsChatTool(tool.Name) && pairingScopes.Contains(tool.RequiredScope);

    /// <summary>True when the order names a device other than the
    /// one rendering/executing it. A foreign-target order never
    /// executes here (§8(5): it runs on the named device, under
    /// that device's own pairing and presence, in full).</summary>
    public static bool IsForeignTarget(ChatOrder order, string thisDevice) =>
        !string.IsNullOrWhiteSpace(order.TargetDevice) &&
        !string.Equals(order.TargetDevice.Trim(), thisDevice.Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>The card's rendered body: the S12 payload law over
    /// the order's exact bytes — title naming agent + action +
    /// exact target, plain steps with real artefacts, technical
    /// lines. Non-gated tools render through the same renderer's
    /// generic path (every field listed, flagged) — a card never
    /// hides an argument.</summary>
    public static GatePayloadView CardView(ChatOrder order, string agentName) =>
        GatePayloadRenderer.Render(agentName, order.GateClass ?? "", order.Tool,
            System.Text.Encoding.UTF8.GetBytes(order.ArgumentsJson));

    /// <summary>The card's title of record: the agent's proposed
    /// title when it carries one, else the renderer's title from
    /// the exact payload.</summary>
    public static string CardTitle(ChatOrder order, string agentName) =>
        string.IsNullOrWhiteSpace(order.Title) ? CardView(order, agentName).Title : order.Title;
}

/// <summary>Reachability truth for the thread header, from the
/// pairing's REAL connection state (W97: PairingService.
/// LastConnection — the last authenticated arrival rung + time,
/// the same facts the host snapshot's currentRung carries).</summary>
public static class ChatReachability
{
    /// <summary>How fresh the agent side's last authenticated
    /// arrival must be to say it can answer now. The agent reads
    /// its thread by polling chat_read over its authenticated
    /// channel; an arrival inside this window means its side is
    /// awake and connected NOW. Older (or never) is the away
    /// truth — the message queues, and the thread says so.</summary>
    public static readonly TimeSpan AnswerNowWindow = TimeSpan.FromSeconds(180);

    public sealed record State(bool CanAnswerNow, string Line, string? Rung, DateTimeOffset? LastSeenUtc);

    public static State Evaluate(string agentName, string? currentRung, DateTimeOffset? lastSeenUtc, DateTimeOffset now)
    {
        var name = string.IsNullOrWhiteSpace(agentName) ? "The agent" : agentName;
        var fresh = currentRung is not null && lastSeenUtc is { } at && now - at <= AnswerNowWindow && now >= at;
        return fresh
            ? new State(true, $"{name} can answer now", currentRung, lastSeenUtc)
            : new State(false, $"{name} is away — your message will be delivered when it wakes", currentRung, lastSeenUtc);
    }

    /// <summary>The queued-state line: owner messages the agent
    /// has not yet read. Zero queued renders nothing — the header
    /// never claims a queue that isn't there.</summary>
    public static string? QueuedLine(string agentName, long queuedCount)
    {
        if (queuedCount <= 0) return null;
        var name = string.IsNullOrWhiteSpace(agentName) ? "The agent" : agentName;
        return queuedCount == 1
            ? $"1 message is queued — it will be delivered when {name} wakes."
            : $"{queuedCount} messages are queued — they will be delivered when {name} wakes.";
    }
}

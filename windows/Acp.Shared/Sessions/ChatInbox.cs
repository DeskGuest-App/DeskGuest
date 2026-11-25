namespace Acp.Shared.Sessions;

/// <summary>
/// W122 — N22 Chat thread list / unified inbox (REVISION-DRAFT
/// §2.3 N22, ADDED-IN-LANGUAGE; NO floor coverage exists for this
/// surface). The signed design call of record: BOTH — per-pairing
/// threads living with the agent cards are the home; one unified
/// inbox view is a LENS over them.
///
/// The law this file holds:
///
///  * ONE STORE. The inbox is an INDEX over S13's real thread
///    store — AgentChatStore (messages) + ChatOrderStore (cards),
///    both keyed by pairing id under the Core's chat dir. Nothing
///    here persists a second copy of a thread; the only new
///    persisted fact is the owner's seen cursor (ChatSeenStore),
///    which is index metadata, not thread content.
///  * TWO UNREAD CLASSES, never conflated. A thread can be
///    WAITING ON YOU — it holds a pending order card only the
///    owner can answer — or merely UNREAD — it holds agent
///    messages the owner has not seen. The classes carry
///    different words and different visual weight, and the
///    waiting class DOMINATES: a thread with both shows waiting.
///  * A PLAIN MESSAGE CAN NEVER PRODUCE THE WAITING CLASS. The
///    pending count is computed ONLY from ChatOrderStore orders
///    in the Pending status; the message leg contributes to the
///    unread count and nothing else. There is no code path from
///    a message body to a pending count.
///  * REACHABILITY IS ONE TRUTH. The inbox row's reachability is
///    ChatReachability over the pairing's PairingService.
///    LastConnection facts — the exact evaluation S13's thread
///    header performs over the same snapshot fields — so a row
///    and its thread header can never disagree for a pairing.
/// </summary>
public enum ChatThreadClass
{
    /// <summary>Nothing unseen, nothing waiting.</summary>
    Quiet = 0,
    /// <summary>Agent messages the owner has not seen.</summary>
    UnreadMessages = 1,
    /// <summary>A pending order card only the owner can answer.</summary>
    WaitingOnYou = 2,
}

/// <summary>The inbox facts for one pairing's thread, computed
/// from the one store: messages the agent sent beyond the owner's
/// seen cursor, orders still pending the owner's answer, and the
/// thread's last activity (message or card, whichever is newer).</summary>
public sealed record ChatThreadFacts(
    string PairingId,
    int UnreadMessages,
    int PendingOrders,
    long LastActivityMs)
{
    public ChatThreadClass Class =>
        PendingOrders > 0 ? ChatThreadClass.WaitingOnYou
        : UnreadMessages > 0 ? ChatThreadClass.UnreadMessages
        : ChatThreadClass.Quiet;
}

/// <summary>The owner's seen cursor per pairing: the sequence
/// number of the last thread message the owner has been shown
/// (the thread was opened for them). One small file per pairing
/// beside the thread files in the chat dir — index metadata over
/// the one store, ended with the thread on unpair.</summary>
public sealed class ChatSeenStore
{
    private readonly string _dir;
    private readonly object _gate = new();

    public ChatSeenStore(string dir) => _dir = dir ?? throw new ArgumentNullException(nameof(dir));

    private string SeenFile(string pairingId)
    {
        var safe = new string((pairingId ?? "").Select(c =>
            char.IsLetterOrDigit(c) || c is '_' or '-' ? c : '_').ToArray());
        return Path.Combine(_dir, safe + ".seen");
    }

    /// <summary>The last sequence the owner has seen; 0 (nothing
    /// seen) for a thread never opened or a cursor that cannot be
    /// read — a lost cursor over-reports unread, never hides it.</summary>
    public long Load(string pairingId)
    {
        lock (_gate)
        {
            var f = SeenFile(pairingId);
            if (!File.Exists(f)) return 0;
            try { return long.TryParse(File.ReadAllText(f).Trim(), out var v) && v >= 0 ? v : 0; }
            catch { return 0; }
        }
    }

    /// <summary>Record that the owner has been shown the thread
    /// through sequence <paramref name="seq"/>. The cursor only
    /// moves FORWARD: a stale push can never un-see a message.</summary>
    public void Save(string pairingId, long seq)
    {
        lock (_gate)
        {
            if (seq <= Load(pairingId)) return;
            Directory.CreateDirectory(_dir);
            var f = SeenFile(pairingId);
            var tmp = f + ".tmp";
            File.WriteAllText(tmp, seq.ToString());
            File.Move(tmp, f, overwrite: true);
        }
    }

    /// <summary>Unpairing ends the thread; its cursor ends too.</summary>
    public void EndSeen(string pairingId)
    {
        lock (_gate)
        {
            var f = SeenFile(pairingId);
            if (File.Exists(f)) File.Delete(f);
        }
    }
}

/// <summary>The N22 summary model (UI-free): facts from the one
/// store, the two classes' exact words, and the lens ordering.</summary>
public static class ChatInboxModel
{
    /// <summary>Compute one pairing's inbox facts from the ONE
    /// store. Messages arrive in thread order (sequence = index
    /// + 1, the store's own numbering); only AGENT-direction
    /// messages beyond the owner's seen cursor are unread — the
    /// owner's own messages are never unread to the owner. The
    /// pending count reads ONLY the order store's Pending cards:
    /// no message, of any body, can raise it.</summary>
    public static ChatThreadFacts Summarize(
        string pairingId,
        IReadOnlyList<AgentChatStore.Message> messages,
        IReadOnlyList<ChatOrder> orders,
        long ownerSeenSeq)
    {
        var unread = 0;
        long last = 0;
        for (var i = 0; i < messages.Count; i++)
        {
            if (messages[i].Direction == AgentChatStore.DirAgent && i + 1 > ownerSeenSeq) unread++;
            if (messages[i].AtMs > last) last = messages[i].AtMs;
        }
        var pending = 0;
        foreach (var o in orders)
        {
            if (o.Status == ChatOrderStatus.Pending) pending++;
            if (o.CreatedAtMs > last) last = o.CreatedAtMs;
        }
        return new ChatThreadFacts(pairingId, unread, pending, last);
    }

    /// <summary>The waiting class's words — an agent is WAITING
    /// ON YOU, and what it waits for is an answer to a card.
    /// Null when nothing is pending (the class is never claimed
    /// for a thread that holds no pending card).</summary>
    public static string? WaitingLine(string agentName, int pendingOrders)
    {
        if (pendingOrders <= 0) return null;
        var name = string.IsNullOrWhiteSpace(agentName) ? "The agent" : agentName;
        return pendingOrders == 1
            ? $"{name} is waiting on you — an order card needs your answer."
            : $"{name} is waiting on you — {pendingOrders} order cards need your answer.";
    }

    /// <summary>The mere-unread class's words — new messages,
    /// nothing that needs an answer. Null at zero.</summary>
    public static string? UnreadLine(int unreadMessages) => unreadMessages switch
    {
        <= 0 => null,
        1 => "1 new message",
        var n => $"{n} new messages",
    };

    /// <summary>The one state line a thread row shows: the
    /// waiting class when it holds (it dominates), else the
    /// unread class, else null — a quiet row claims nothing.</summary>
    public static string? StateLine(string agentName, ChatThreadFacts facts) =>
        facts.Class switch
        {
            ChatThreadClass.WaitingOnYou => WaitingLine(agentName, facts.PendingOrders),
            ChatThreadClass.UnreadMessages => UnreadLine(facts.UnreadMessages),
            _ => null,
        };

    /// <summary>The inbox lens ordering: waiting threads first,
    /// then unread, then quiet — within a class, the most recent
    /// activity first. The lens never reorders by name: what
    /// needs the owner floats up.</summary>
    public static IReadOnlyList<ChatThreadFacts> OrderForLens(IEnumerable<ChatThreadFacts> facts) =>
        facts.OrderByDescending(f => (int)f.Class)
             .ThenByDescending(f => f.LastActivityMs)
             .ToArray();

    /// <summary>The lens header line over every pairing at once:
    /// waiting named before unread, each class counted in its
    /// own words; "All caught up" only when both are truly zero.</summary>
    public static string LensSummary(int waitingThreads, int unreadThreads)
    {
        if (waitingThreads <= 0 && unreadThreads <= 0) return "All caught up";
        var parts = new List<string>();
        if (waitingThreads > 0)
            parts.Add(waitingThreads == 1 ? "1 agent is waiting on you" : $"{waitingThreads} agents are waiting on you");
        if (unreadThreads > 0)
            parts.Add(unreadThreads == 1 ? "1 thread has new messages" : $"{unreadThreads} threads have new messages");
        return string.Join(" · ", parts);
    }
}

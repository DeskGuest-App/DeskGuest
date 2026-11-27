using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

/// <summary>
/// W122 — N22 Chat thread list / unified inbox (REVISION-DRAFT
/// §2.3 N22, ADDED-IN-LANGUAGE; no floor coverage). The signed
/// law pinned: the inbox is an INDEX over S13's one thread store
/// (never a second store); unread state DISTINGUISHES an agent
/// waiting on you (a pending order card) from mere unread
/// messages — and a plain message can never produce the waiting
/// class; per-thread reachability is the same ChatReachability
/// evaluation over the same ConnFacts fields S13's header uses;
/// a pending card opened from the inbox surfaces through W119's
/// GateSheet control itself, fed the card's own payload view.
/// </summary>
public class W122InboxTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    private static ChatOrder PendingOrder(string id = "ord1", long atMs = 5000) =>
        new(id, "pair1", "file_delete", "deletions",
            "{\"path\":\"C:\\\\Users\\\\Jacob\\\\Desktop\\\\scratch.txt\"}",
            "", "", ChatOrderStatus.Pending, null, atMs, null);

    private static (AgentChatStore Chat, ChatOrderStore Orders, ChatSeenStore Seen, string Dir) Stores()
    {
        var dir = Directory.CreateTempSubdirectory("w122-inbox");
        return (new AgentChatStore(dir.FullName), new ChatOrderStore(dir.FullName),
                new ChatSeenStore(dir.FullName), dir.FullName);
    }

    // ---------- one store: the lens reads S13's stores ----------

    [Fact]
    public void Summary_ReadsTheOneThreadStore()
    {
        var (chat, orders, seen, dir) = Stores();
        try
        {
            chat.Append("pair1", AgentChatStore.DirAgent, "first", 1000);
            chat.Append("pair1", AgentChatStore.DirOwner, "reply", 2000);
            chat.Append("pair1", AgentChatStore.DirAgent, "second", 3000);
            orders.Append(PendingOrder());
            var facts = ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1"));
            Assert.Equal(2, facts.UnreadMessages);       // both agent messages unseen
            Assert.Equal(1, facts.PendingOrders);
            Assert.Equal(5000, facts.LastActivityMs);    // the card is the newest activity
            Assert.Equal(ChatThreadClass.WaitingOnYou, facts.Class);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void Core_InboxFacts_AreComputedFromTheSameStores()
    {
        // The Core's snapshot facts come from Chat.Load +
        // Orders.Load + ChatSeen.Load over the pairing — there
        // is no inbox store anywhere in the Core.
        var core = SrcFile("DeskGuest.Core", "CoreRuntime.cs");
        Assert.Contains("BuildChatThreadFacts()", core);
        Assert.Contains("ChatInboxModel.Summarize(p.Id, messages, orders, ChatSeen.Load(p.Id))", core);
        Assert.DoesNotContain("InboxStore", core);
        Assert.DoesNotContain("ThreadListStore", core);
        // The window keeps no store either: it renders snapshot
        // facts and opens threads through the S13 channel.
        var inbox = SrcFile("DeskGuest.SessionAgent", "MainWindow.Inbox.cs");
        Assert.DoesNotContain("new AgentChatStore", inbox);
        Assert.DoesNotContain("new ChatOrderStore", inbox);
        Assert.DoesNotContain("new ChatSeenStore", inbox);
        Assert.DoesNotContain("File.ReadAllText", inbox);
    }

    [Fact]
    public void Snapshot_CarriesTheInboxIndex()
    {
        var facts = new HostStateSnapshot.ChatThreadFact("pair1", 2, 1, 5000,
            new[] { new HostStateSnapshot.ChatPendingOrderFact("ord1", "file_delete", "deletions", "{}", "", "", 5000) });
        var json = HostStateSnapshot.Build(
            "1.0.0", "PC", 8741, Array.Empty<string>(), true, true, false,
            new HostStateSnapshot.SessionFacts(false, null, 0, 0, null),
            Array.Empty<Pairing>(), Array.Empty<string>(), new HashSet<string>(),
            Array.Empty<AuditEntry>(), chatThreads: new[] { facts });
        Assert.Contains("\"chatThreads\"", json);
        Assert.Contains("\"unreadMessages\":2", json);
        Assert.Contains("\"pendingOrders\":1", json);
        Assert.Contains("\"pendingOrderList\"", json);
        // Message bodies never ride the snapshot — the index
        // carries counts and pending cards only.
        Assert.DoesNotContain("\"body\"", json);
    }

    // ---------- the two unread classes ----------

    [Fact]
    public void PlainMessage_CanNeverProduceTheWaitingClass()
    {
        var (chat, orders, seen, dir) = Stores();
        try
        {
            // Agent messages — including one whose body begs for
            // an action — raise ONLY the unread count. The
            // waiting class reads the order store and nothing else.
            chat.Append("pair1", AgentChatStore.DirAgent, "please delete the file, it is urgent", 1000);
            chat.Append("pair1", AgentChatStore.DirAgent, "approve my order card", 2000);
            var facts = ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1"));
            Assert.Equal(0, facts.PendingOrders);
            Assert.Equal(2, facts.UnreadMessages);
            Assert.Equal(ChatThreadClass.UnreadMessages, facts.Class);
            Assert.Null(ChatInboxModel.WaitingLine("Axle", facts.PendingOrders));
            Assert.Equal("2 new messages", ChatInboxModel.StateLine("Axle", facts));
            // Only a real pending card flips the class.
            orders.Append(PendingOrder());
            var after = ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1"));
            Assert.Equal(ChatThreadClass.WaitingOnYou, after.Class);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void ResolvedCard_LeavesTheWaitingClass()
    {
        var (chat, orders, seen, dir) = Stores();
        try
        {
            orders.Append(PendingOrder());
            Assert.True(orders.TryResolve("pair1", "ord1", ChatOrderStatus.Denied, "no", 6000));
            var facts = ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1"));
            Assert.Equal(0, facts.PendingOrders);
            Assert.Equal(ChatThreadClass.Quiet, facts.Class);
            Assert.Null(ChatInboxModel.StateLine("Axle", facts));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void WaitingLine_AndUnreadLine_AreDifferentWords()
    {
        Assert.Equal("Axle is waiting on you — an order card needs your answer.",
            ChatInboxModel.WaitingLine("Axle", 1));
        Assert.Equal("Axle is waiting on you — 3 order cards need your answer.",
            ChatInboxModel.WaitingLine("Axle", 3));
        Assert.Null(ChatInboxModel.WaitingLine("Axle", 0));
        Assert.Equal("1 new message", ChatInboxModel.UnreadLine(1));
        Assert.Equal("4 new messages", ChatInboxModel.UnreadLine(4));
        Assert.Null(ChatInboxModel.UnreadLine(0));
        // Waiting dominates: a thread with both shows waiting.
        var both = new ChatThreadFacts("pair1", UnreadMessages: 5, PendingOrders: 1, LastActivityMs: 1);
        Assert.Equal("Axle is waiting on you — an order card needs your answer.",
            ChatInboxModel.StateLine("Axle", both));
    }

    [Fact]
    public void LensSummary_NamesEachClassSeparately()
    {
        Assert.Equal("All caught up", ChatInboxModel.LensSummary(0, 0));
        Assert.Equal("1 agent is waiting on you", ChatInboxModel.LensSummary(1, 0));
        Assert.Equal("2 agents are waiting on you · 1 thread has new messages",
            ChatInboxModel.LensSummary(2, 1));
        Assert.Equal("3 threads have new messages", ChatInboxModel.LensSummary(0, 3));
    }

    [Fact]
    public void LensOrder_WaitingThenUnreadThenQuiet_NewestFirst()
    {
        var quiet = new ChatThreadFacts("q", 0, 0, 9000);
        var unreadOld = new ChatThreadFacts("u1", 1, 0, 1000);
        var unreadNew = new ChatThreadFacts("u2", 2, 0, 8000);
        var waiting = new ChatThreadFacts("w", 0, 1, 500);
        var ordered = ChatInboxModel.OrderForLens(new[] { quiet, unreadOld, waiting, unreadNew });
        Assert.Equal(new[] { "w", "u2", "u1", "q" }, ordered.Select(f => f.PairingId).ToArray());
    }

    // ---------- the seen cursor ----------

    [Fact]
    public void SeenCursor_ClearsUnread_AndOnlyMovesForward()
    {
        var (chat, orders, seen, dir) = Stores();
        try
        {
            chat.Append("pair1", AgentChatStore.DirAgent, "one", 1000);
            chat.Append("pair1", AgentChatStore.DirAgent, "two", 2000);
            Assert.Equal(2, ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1")).UnreadMessages);
            seen.Save("pair1", 2);
            Assert.Equal(0, ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1")).UnreadMessages);
            // A stale save can never un-see.
            seen.Save("pair1", 1);
            Assert.Equal(2, seen.Load("pair1"));
            // A new agent message after the cursor is unread again.
            chat.Append("pair1", AgentChatStore.DirAgent, "three", 3000);
            Assert.Equal(1, ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1")).UnreadMessages);
            // The owner's own messages are never unread.
            chat.Append("pair1", AgentChatStore.DirOwner, "mine", 4000);
            Assert.Equal(1, ChatInboxModel.Summarize("pair1", chat.Load("pair1"), orders.Load("pair1"), seen.Load("pair1")).UnreadMessages);
            seen.EndSeen("pair1");
            Assert.Equal(0, seen.Load("pair1"));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void OpenedFlag_IsTheOnlySeenAdvance_AndOnlyTheWindowSetsIt()
    {
        // The Core advances the cursor only on a thread request
        // carrying opened=true; its internal re-pushes (agent
        // post, card events) serialize {pairingId} only.
        var core = SrcFile("DeskGuest.Core", "CoreRuntime.cs");
        Assert.Contains("ChatSeen.Save(pairingId, messages.Count)", core);
        // The cursor advances in exactly one place in the Core.
        Assert.Equal(1, core.Split("ChatSeen.Save(").Length - 1);
        // The window's request is the only sender of the flag.
        Assert.Contains("new { pairingId, opened = true }", SrcFile("DeskGuest.SessionAgent", "IpcClient.cs"));
        // The Core's own re-pushes serialize the pairing only.
        Assert.Contains("JsonSerializer.Serialize(new { pairingId = audit.PairingId })", core);
        Assert.Contains("JsonSerializer.Serialize(new { pairingId })", core);
        Assert.Contains("JsonSerializer.Serialize(new { pairingId = proposal.PairingId })", core);
    }

    // ---------- reachability: one truth with S13's header ----------

    [Fact]
    public void InboxRow_AndThreadHeader_EvaluateTheSameReachability()
    {
        var inbox = SrcFile("DeskGuest.SessionAgent", "MainWindow.Inbox.cs");
        var chat = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        // Both surfaces evaluate ChatReachability over ConnFacts
        // — the snapshot's PairingService.LastConnection fields —
        // so row and header cannot disagree for a pairing.
        Assert.Contains("ConnFacts(pairingId)", inbox);
        Assert.Contains("ChatReachability.Evaluate(agentName, conn.CurrentRung, conn.AtUtc", inbox);
        Assert.Contains("ConnFacts(pairingId)", chat);
        Assert.Contains("ChatReachability.Evaluate(agentName, facts.CurrentRung, facts.AtUtc", chat);
        // And both use the pairing's W103 ring-with-initial.
        Assert.Contains("BuildIdentityRing(agentName, revoked: false)", inbox);
        Assert.Contains("BuildIdentityRing(agentName, revoked: false)", chat);
    }

    // ---------- pending cards open through the S12 sheet ----------

    [Fact]
    public void Inbox_OpensPendingCardsThroughTheGateSheetControl()
    {
        var inbox = SrcFile("DeskGuest.SessionAgent", "MainWindow.Inbox.cs");
        // The same control, not a copy: GateSheet.Present itself,
        // fed the card's own payload view over its exact bytes,
        // marked as asked from Agent chat.
        Assert.Contains("GateSheet.Present(view, bytes, fromChat: true", inbox);
        Assert.Contains("ChatOrderModel.CardView(order, agentName)", inbox);
        Assert.Contains("Encoding.UTF8.GetBytes(order.ArgumentsJson)", inbox);
        // The sheet's exits return as the card's answer through
        // the S13 answer channel — the same sender the thread's
        // inline exits use.
        Assert.Contains("_chatOrderAnswerSender(pairingId, orderId, answer)", inbox);
        Assert.Contains("GateAnswers.Allow", inbox);
        Assert.Contains("GateAnswers.Deny", inbox);
        Assert.Contains("GateAnswers.DenyAndEnd", inbox);
        // A foreign-target card never goes to the sheet (its
        // Approve must stay off — it opens the thread instead).
        Assert.Contains("ChatOrderModel.IsForeignTarget(oldest", inbox);
    }

    [Fact]
    public void Home_RendersTheLensAboveTheCards_AndStateOnTheCards()
    {
        var main = SrcFile("DeskGuest.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("RenderInboxSection(pairings)", main);
        Assert.Contains("InboxSignature()", main);
        Assert.Contains("ChatInboxModel.StateLine(pname, cardData.Facts(id))", main);
        var inbox = SrcFile("DeskGuest.SessionAgent", "MainWindow.Inbox.cs");
        Assert.Contains("ChatInboxModel.OrderForLens", inbox);
        Assert.Contains("ChatInboxModel.LensSummary", inbox);
        Assert.Contains("\"Inbox\"", inbox);
    }
}

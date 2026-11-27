using System.Text;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>
/// W120 — S13 AI Chat + Order Cards (FEATURES.md §8 expansion;
/// REVISION-DRAFT §2.1 S13, ADDED-IN-LANGUAGE). The §8 law pinned:
/// free text never executes; a card's exits are S12's exits by
/// construction (shared constants, never retyped); an off-device
/// send writes a Sent ledger entry; messaging opens no session
/// and raises no presence; reachability lines are the spec's
/// exact words over real connection state; a card may only
/// propose what the pairing's slider already grants; a foreign
/// target never executes here; S09(d)'s «Message {agent}» door
/// is wired to this thread.
/// </summary>
public class W120ChatOrderTests
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

    private static ChatOrder Order(string tool = "file_delete", string? gateClass = "deletions",
        string args = "{\"path\":\"C:\\\\Users\\\\DeskGuest\\\\Desktop\\\\scratch.txt\"}",
        string target = "", string status = ChatOrderStatus.Pending) =>
        new("ord1", "pair1", tool, gateClass, args, "", target, status, null, 1000, null);

    // ---------- free text never executes ----------

    [Fact]
    public void Prose_NeverBecomesAnOrder()
    {
        // Even prose that names a real tool and a real path: the
        // conversion does not exist. Only the structured
        // chat_order call can create a card.
        Assert.Null(ChatOrderModel.FromProse("pair1",
            "Please delete C:\\Users\\DeskGuest\\Desktop\\scratch.txt using file_delete", "JACOBS-LAPTOP"));
        Assert.Null(ChatOrderModel.FromProse("pair1", "run file_delete now", "JACOBS-LAPTOP"));
        Assert.Null(ChatOrderModel.FromProse("pair1", "", "JACOBS-LAPTOP"));
    }

    [Fact]
    public void ChatPost_HasNoExecutionPath()
    {
        // The message leg's source: appends to the thread store
        // and raises a metadata event. No order store, no pairing
        // execution, no gate — a posted message cannot act.
        var src = SrcFile("DeskGuest.Core", "Modules", "ChatModules.cs");
        var post = src[src.IndexOf("class ChatPostModule", StringComparison.Ordinal)..];
        Assert.DoesNotContain("ExecuteForPairing", post);
        Assert.DoesNotContain("ChatOrderStore", post);
        Assert.DoesNotContain("GateRaiser", post);
    }

    [Fact]
    public void ChatOrderTool_IsTheOnlyProposalDoor_AndItExecutesNothing()
    {
        var src = SrcFile("DeskGuest.Core", "Modules", "ChatOrderModules.cs");
        Assert.Contains("ChatOrderModel.ProposeToolName", src);
        // The module validates and hands off; execution lives
        // only behind the owner's card answer in the Core.
        Assert.DoesNotContain("ExecuteForPairingAsync", src);
        Assert.DoesNotContain("Sessions.Start", src);
        Assert.Contains("ApplyChatOrderAnswerFromLaptop", SrcFile("DeskGuest.Core", "CoreRuntime.cs"));
    }

    // ---------- card exits byte-identical to S12 ----------

    [Fact]
    public void CardExits_AreTheGateExits_SameLabelsSameWeights()
    {
        var card = ChatOrderModel.CardExits();
        var gate = GateSheetModel.Exits();
        Assert.Equal(gate.Count, card.Count);
        for (var i = 0; i < gate.Count; i++)
        {
            Assert.Equal(gate[i].Label, card[i].Label);
            Assert.Equal(gate[i].Weight, card[i].Weight);
        }
        Assert.Equal(new[] { "Approve", "Deny", "Deny and end session" }, card.Select(e => e.Label).ToArray());
    }

    [Fact]
    public void ChatSurface_ConsumesSharedExits_NeverRetypesThem()
    {
        var src = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("ChatOrderModel.CardExits()", src);
        // The third exit's label appears NOWHERE in the chat
        // surface's source — it arrives only via the shared
        // constants. (The STOP button is a different control and
        // is labelled STOP, not an exit label.)
        Assert.DoesNotContain("Deny and end session", src);
        // No default button on a card: no exit is ever IsDefault.
        Assert.DoesNotContain("IsDefault", src);
        // Red binds only to the third exit, from the shared
        // GateCardColors — the chat file names it exactly once
        // for the card fills (plus the STOP button's fill).
        Assert.Contains("GateCardColors.DenyAndEndBackground", src);
        Assert.Contains("GateCardColors.ApproveBackground", src);
        Assert.Contains("GateCardColors.DenyBackground", src);
    }

    // ---------- off-device send = Sent ledger entry ----------

    [Fact]
    public void NoteChatMessage_WritesASentLedgerEntry()
    {
        var dir = Directory.CreateTempSubdirectory("w120-flows");
        try
        {
            var ledger = new DataFlowLedger(Path.Combine(dir.FullName, "flows.json"));
            ledger.NoteChatMessage("pair1", "W120 Proof", "", DateTimeOffset.UtcNow);
            var report = DataFlowReport.Build(ledger.Records(), Array.Empty<DeskGuest.Shared.Audit.AuditEntry>());
            var agent = Assert.Single(report.Agents);
            Assert.True(agent.ByClass.TryGetValue(DataFlowClasses.Sent, out var sent));
            Assert.Equal(1, sent.Calls);
            // The send path in the Core writes exactly this entry.
            Assert.Contains("NoteChatMessage(pairingId, pairing.AgentName",
                SrcFile("DeskGuest.Core", "CoreRuntime.cs"));
        }
        finally { dir.Delete(recursive: true); }
    }

    // ---------- messaging is not a session ----------

    [Fact]
    public void ChatTools_AreSessionExempt_AndOrderToolNeedsNoSession()
    {
        // The choke point's session binding exempts the chat
        // family by name — chat_read / chat_post / chat_order all
        // ride the pairing channel with no session, so using chat
        // can never require (or create) presence.
        var handler = SrcFile("DeskGuest.Core", "Mcp", "McpHandler.cs");
        Assert.Contains("name is \"chat_read\" or \"chat_post\" or \"chat_order\"", handler);
        var src = SrcFile("DeskGuest.Core", "Modules", "ChatOrderModules.cs");
        Assert.Contains("SessionRequirement.Core", src);
        Assert.Contains("Scopes.Observe", src);
    }

    [Fact]
    public void ThreadSurface_StatesTheNotASessionLaw()
    {
        var src = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("ChatCapabilityLine", src);
        var resx = SrcFile("DeskGuest.SessionAgent", "Strings.resx");
        Assert.Contains("Messaging does not use this access", resx);
    }

    // ---------- reachability truth ----------

    [Fact]
    public void Reachability_FreshArrival_CanAnswerNow()
    {
        var now = DateTimeOffset.UtcNow;
        var s = ChatReachability.Evaluate("Axle", "mesh", now.AddSeconds(-30), now);
        Assert.True(s.CanAnswerNow);
        Assert.Equal("Axle can answer now", s.Line);
    }

    [Fact]
    public void Reachability_StaleOrNever_IsAway_WithTheSpecLine()
    {
        var now = DateTimeOffset.UtcNow;
        var stale = ChatReachability.Evaluate("Axle", "mesh", now.AddSeconds(-3600), now);
        Assert.False(stale.CanAnswerNow);
        Assert.Equal("Axle is away — your message will be delivered when it wakes", stale.Line);
        var never = ChatReachability.Evaluate("Axle", null, null, now);
        Assert.False(never.CanAnswerNow);
        Assert.Equal("Axle is away — your message will be delivered when it wakes", never.Line);
    }

    [Fact]
    public void QueuedLine_CountsHonestly()
    {
        Assert.Null(ChatReachability.QueuedLine("Axle", 0));
        Assert.Equal("1 message is queued — it will be delivered when Axle wakes.",
            ChatReachability.QueuedLine("Axle", 1));
        Assert.Equal("3 messages are queued — they will be delivered when Axle wakes.",
            ChatReachability.QueuedLine("Axle", 3));
    }

    [Fact]
    public void ThreadHeader_ReadsRealConnectionState_NotAGuess()
    {
        // The header's reachability comes from ConnFacts — the
        // W97 snapshot facts (Pairing.cs last-authenticated rung).
        var src = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.Contains("ConnFacts(pairingId)", src);
        Assert.Contains("ChatReachability.Evaluate(agentName, facts.CurrentRung, facts.AtUtc", src);
        Assert.Contains("BuildIdentityRing(agentName, revoked: false)", src);
    }

    // ---------- slider law + card rendering ----------

    [Fact]
    public void MayPropose_OnlyInsideThePairingsGrant()
    {
        var scopes = new HashSet<string> { Scopes.Observe, Scopes.Drive, Scopes.Shell };
        var del = new ToolDescriptor("file_delete", "", Scopes.Shell, SessionRequirement.Core, RiskTier.Critical, GateClass: "deletions");
        var admin = new ToolDescriptor("registry_set", "", "admin", SessionRequirement.Core, RiskTier.High, GateClass: "registry_write");
        var chat = new ToolDescriptor("chat_post", "", Scopes.Observe, SessionRequirement.Core, RiskTier.Low);
        Assert.True(ChatOrderModel.MayPropose(scopes, del));
        Assert.False(ChatOrderModel.MayPropose(scopes, admin));
        Assert.False(ChatOrderModel.MayPropose(scopes, chat));
    }

    [Fact]
    public void CardView_RendersExactArtefactSteps_FromTheExactBytes()
    {
        var view = ChatOrderModel.CardView(Order(), "W120 Proof");
        Assert.Contains(view.PlainLines, l => l.Contains("scratch.txt"));
        Assert.Contains(view.TechnicalLines, l => l.Contains("path: C:\\Users\\DeskGuest\\Desktop\\scratch.txt"));
        Assert.Contains("W120 Proof", view.Title);
    }

    [Fact]
    public void ForeignTarget_IsDetectedByName_AndNeverRunsHere()
    {
        Assert.True(ChatOrderModel.IsForeignTarget(Order(target: "DESKTOP-OTHER"), "JACOBS-LAPTOP"));
        Assert.False(ChatOrderModel.IsForeignTarget(Order(target: "jacobs-laptop"), "JACOBS-LAPTOP"));
        Assert.False(ChatOrderModel.IsForeignTarget(Order(target: ""), "JACOBS-LAPTOP"));
        // The Core's answer path refuses a foreign approval into
        // a FAILED resolution — it never reaches the executor.
        var core = SrcFile("DeskGuest.Core", "CoreRuntime.cs");
        Assert.Contains("chat_order_foreign_target_refused", core);
    }

    // ---------- order store transitions ----------

    [Fact]
    public void OrderStore_AnswerTransitionsAreOneWay()
    {
        var dir = Directory.CreateTempSubdirectory("w120-orders");
        try
        {
            var store = new ChatOrderStore(dir.FullName);
            store.Append(Order());
            // Pending cannot jump straight to Done (Running first).
            Assert.False(store.TryResolve("pair1", "ord1", ChatOrderStatus.Done, "x", 2000));
            Assert.True(store.TryResolve("pair1", "ord1", ChatOrderStatus.Running, "Approved — running…", 2000));
            Assert.True(store.TryResolve("pair1", "ord1", ChatOrderStatus.Done, "deleted", 3000));
            // A resolved card can never be answered again.
            Assert.False(store.TryResolve("pair1", "ord1", ChatOrderStatus.Denied, "x", 4000));
            var loaded = Assert.Single(store.Load("pair1"));
            Assert.Equal(ChatOrderStatus.Done, loaded.Status);
            Assert.Equal("deleted", loaded.ResultLine);
            store.EndOrders("pair1");
            Assert.Empty(store.Load("pair1"));
        }
        finally { dir.Delete(recursive: true); }
    }

    [Fact]
    public void OrderStore_DenyFromPending_Resolves()
    {
        var dir = Directory.CreateTempSubdirectory("w120-orders2");
        try
        {
            var store = new ChatOrderStore(dir.FullName);
            store.Append(Order());
            Assert.True(store.TryResolve("pair1", "ord1", ChatOrderStatus.DeniedAndEnded, "no", 2000));
            Assert.Equal(ChatOrderStatus.DeniedAndEnded, Assert.Single(store.Load("pair1")).Status);
        }
        finally { dir.Delete(recursive: true); }
    }

    // ---------- wiring: push, answers, S09(d) ----------

    [Fact]
    public void ThreadPush_CarriesOrdersQueueAndDevice()
    {
        var core = SrcFile("DeskGuest.Core", "CoreRuntime.cs");
        Assert.Contains("orders = Orders.Load(pairingId)", core);
        Assert.Contains("queuedForAgent = queued", core);
        Assert.Contains("thisDevice = Environment.MachineName", core);
        Assert.Contains("IpcKinds.ChatOrderAnswer", core);
    }

    [Fact]
    public void ApprovedCard_ExecutesThroughTheChokePoint_WithOneShotApproval()
    {
        var core = SrcFile("DeskGuest.Core", "CoreRuntime.cs");
        Assert.Contains("ExecuteForPairingAsync(order.PairingId, order.Tool, args, _cts.Token, approved)", core);
        Assert.Contains("chat_order_executed", core);
        Assert.Contains("chat_order_approved", core);
        // Deny-and-end from a card keeps the audit-first order.
        var dae = core.IndexOf("case Shared.Ipc.GateAnswers.DenyAndEnd:", StringComparison.Ordinal);
        var auditFirst = core.IndexOf("approval_deny_and_end: order=", dae, StringComparison.Ordinal);
        var stopAfter = core.IndexOf("Sessions.Stop()", dae, StringComparison.Ordinal);
        Assert.True(dae >= 0 && auditFirst > dae && stopAfter > auditFirst,
            "card deny-and-end must audit before it stops the session");
    }

    [Fact]
    public void S09d_MessageButton_OpensThisPairingsThread()
    {
        var src = SrcFile("DeskGuest.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("$\"Message {pname}\"", src);
        Assert.Contains("_chatOpenPairingId = capturedMsgId", src);
        // W135 (ruling U-7): the thread is a full-window page —
        // the door navigates to the chat page, not Home's column.
        Assert.Contains("ShowPage(\"chat\")", src);
        Assert.Contains("_chatThreadSender(capturedMsgId)", src);
    }

    [Fact]
    public void Composer_HasNoEmojiOrPaperclipFurniture_OnlyTheStrokeSendGlyph()
    {
        var src = SrcFile("DeskGuest.SessionAgent", "MainWindow.Chat.cs");
        Assert.DoesNotContain("📎", src);
        Assert.DoesNotContain("😀", src);
        Assert.Contains("Geometry.Parse(\"M3,20 L21,10 L3,4 L7,10 Z M7,10 L21,10\")", src);
        Assert.Contains("ToolTip = \"Send\"", src);
    }
}

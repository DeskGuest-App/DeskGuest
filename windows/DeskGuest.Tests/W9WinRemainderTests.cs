using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.DirectoryEnrollment;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.State;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>
/// W9 Lane A (Windows remainders) — the gate broker's destruction
/// surface: forgery, replay, and the race with session end. These
/// run in the plain harness (no pipes, no sockets): the broker and
/// the payload parser are the state machine both sides share, so
/// what is proven here is what the IPC path enforces.
/// </summary>
public class W9GateBrokerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    private static GateRequest Register(GateRequestBroker broker, string session = "sess-1", string pairing = "pair-1") =>
        broker.Register(pairing, session, "power", "power_tool",
            Encoding.UTF8.GetBytes("""{"action":"restart"}"""), fromChat: false, T0);

    [Fact]
    public void Answer_Once_ThenReplayRefused()
    {
        var broker = new GateRequestBroker();
        var req = Register(broker);
        var first = broker.TryAnswer(req.Id, GateAnswers.Allow, "sess-1", T0.AddSeconds(1), out var got, out var answer);
        Assert.Equal(GateResolution.Answered, first);
        Assert.Equal(GateAnswers.Allow, answer);
        Assert.Equal(req.Id, got!.Id);
        // Replay of the same captured "allow": the request is gone.
        var replay = broker.TryAnswer(req.Id, GateAnswers.Allow, "sess-1", T0.AddSeconds(2), out _, out var replayAnswer);
        Assert.Equal(GateResolution.UnknownOrConsumed, replay);
        Assert.Null(replayAnswer);
        Assert.Equal(0, broker.PendingCount);
    }

    [Fact]
    public void Answer_AfterSessionEnded_RefusedAsSessionEnded()
    {
        // The race: the gate was raised by sess-1; by answer time the
        // Core's live session is a DIFFERENT one (or none). The
        // answer must not be honored for anything.
        var broker = new GateRequestBroker();
        var req = Register(broker);
        var res = broker.TryAnswer(req.Id, GateAnswers.Allow, "sess-2", T0.AddSeconds(1), out _, out var answer);
        Assert.Equal(GateResolution.SessionEnded, res);
        Assert.Null(answer);
        var res2 = broker.TryAnswer(req.Id, GateAnswers.Allow, null, T0.AddSeconds(1), out _, out _);
        Assert.Equal(GateResolution.UnknownOrConsumed, res2); // consumed by the refused attempt too
    }

    [Fact]
    public void InvalidateSession_KillsPending_AnswerFindsNothing()
    {
        var broker = new GateRequestBroker();
        var a = Register(broker);
        var b = Register(broker);
        var other = broker.Register("pair-1", "sess-9", "power", "power_tool",
            Array.Empty<byte>(), false, T0);
        Assert.Equal(2, broker.InvalidateSession("sess-1"));
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(a.Id, GateAnswers.Allow, "sess-1", T0.AddSeconds(1), out _, out _));
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(b.Id, GateAnswers.Deny, "sess-1", T0.AddSeconds(1), out _, out _));
        // The other session's request is untouched.
        Assert.Equal(GateResolution.Answered,
            broker.TryAnswer(other.Id, GateAnswers.Deny, "sess-9", T0.AddSeconds(1), out _, out _));
    }

    [Fact]
    public void Expired_AnswerRefused_AndConsumed()
    {
        var broker = new GateRequestBroker();
        var req = broker.Register("pair-1", "sess-1", "power", "power_tool",
            Array.Empty<byte>(), false, T0, TimeSpan.FromSeconds(5));
        var res = broker.TryAnswer(req.Id, GateAnswers.Allow, "sess-1", T0.AddSeconds(6), out _, out var answer);
        Assert.Equal(GateResolution.Expired, res);
        Assert.Null(answer);
        Assert.Equal(0, broker.PendingCount);
    }

    [Fact]
    public void Abandon_ThenLateAnswerRefused()
    {
        var broker = new GateRequestBroker();
        var req = Register(broker);
        Assert.True(broker.Abandon(req.Id));
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(req.Id, GateAnswers.Allow, "sess-1", T0.AddSeconds(1), out _, out _));
    }

    [Fact]
    public void NonAnswer_NeverResolves()
    {
        var broker = new GateRequestBroker();
        var req = Register(broker);
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(req.Id, "yes", "sess-1", T0.AddSeconds(1), out _, out _));
        Assert.Equal(GateResolution.UnknownOrConsumed,
            broker.TryAnswer(req.Id, "", "sess-1", T0.AddSeconds(1), out _, out _));
        // A non-answer does not consume: the real answer still lands.
        Assert.Equal(GateResolution.Answered,
            broker.TryAnswer(req.Id, GateAnswers.Deny, "sess-1", T0.AddSeconds(1), out _, out _));
    }

    [Fact]
    public void ParseAnswer_FramePayloadDisagreement_Refused()
    {
        // Forgery shape: an answer payload naming request B carried
        // on a frame for request A — the two must agree or the
        // answer is refused before it can be re-pointed.
        var payload = GateRequestPayload.BuildAnswer("req-B", GateAnswers.Allow);
        Assert.Null(GateRequestPayload.ParseAnswer(payload, "req-A"));
        var ok = GateRequestPayload.ParseAnswer(payload, "req-B");
        Assert.NotNull(ok);
        Assert.Equal(GateAnswers.Allow, ok!.Value.Answer);
        // A frame carrying no id accepts the payload's own id.
        Assert.NotNull(GateRequestPayload.ParseAnswer(payload, null));
    }

    [Fact]
    public void ParseAnswer_MalformedAndInventedAnswers_Refused()
    {
        Assert.Null(GateRequestPayload.ParseAnswer(null, null));
        Assert.Null(GateRequestPayload.ParseAnswer("not json", null));
        Assert.Null(GateRequestPayload.ParseAnswer("""{"requestId":"x"}""", null));
        Assert.Null(GateRequestPayload.ParseAnswer("""{"requestId":"x","answer":"approve"}""", null));
        Assert.Null(GateRequestPayload.ParseAnswer("""{"requestId":"x","answer":"ALLOW"}""", null));
        Assert.Null(GateRequestPayload.ParseAnswer("""{"answer":"allow"}""", null));
    }

    [Fact]
    public void RequestPayload_RoundTrips_ByteForByte()
    {
        // OI-12: the bytes the sheet renders are the bytes raised.
        var payloadBytes = Encoding.UTF8.GetBytes("""{"path":"C:\\a b","n":1}""");
        var req = GateRequest.Create("pair-1", "sess-1", "deletions", "file_delete",
            payloadBytes, fromChat: true, T0, TimeSpan.FromSeconds(30));
        var parsed = GateRequestPayload.Parse(GateRequestPayload.Build(req));
        Assert.NotNull(parsed);
        Assert.Equal(req.Id, parsed!.Id);
        Assert.Equal("pair-1", parsed.PairingId);
        Assert.Equal("sess-1", parsed.SessionId);
        Assert.True(parsed.FromChat);
        Assert.Equal(payloadBytes, parsed.PayloadBytes());
        Assert.Null(GateRequestPayload.Parse("""{"requestId":"x"}"""));
        Assert.Null(GateRequestPayload.Parse("junk"));
    }
}

/// <summary>
/// W9 Lane A — the per-action gate at the MCP choke point, with a
/// fake raiser standing in for the Core→agent IPC leg (the pipe
/// itself is the W7-named environmental neighbourhood; the handler
/// + broker behaviour proven here is what the pipe carries).
/// </summary>
public class W9GateHandlerTests
{
    private sealed class StubModule(string name, string? gate, string text) : IToolModule
    {
        public ToolDescriptor Descriptor { get; } = new(name, "stub", Scopes.Drive, SessionRequirement.Agent, RiskTier.Medium, gate, "Agent");
        public int Calls;
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(ToolResult.Success(text));
        }
    }

    private sealed class Rig
    {
        public required McpHandler Handler;
        public required SessionManager Sessions;
        public required string Token;
        public required StubModule Power;
        public required FileAuditLog Audit;
        public int Raises;
        public string? NextAnswer;
        public bool AuditHadDenyAndEndAtTeardown;
        public bool TeardownFired;

        public async Task<string> Call(string tool, string argsJson = "{}")
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":" + argsJson + "}}";
            var resp = await Handler.HandleAsync(body, $"Bearer {Token}", new HashSet<string>(), default);
            return resp.Json!;
        }

        public IReadOnlyList<AuditEntry> Entries() => Audit.ReadTail(200);
    }

    private static Rig BuildRig()
    {
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new SessionStopModule(sessions, state));
        var power = new StubModule("power_tool", "power", "power acted");
        registry.Register(power);
        var auditDir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(auditDir);
        var handler = new McpHandler(pairings, new PolicyEngine(), registry, audit, state, sessions, auditDir);
        var rig = new Rig { Handler = handler, Sessions = sessions, Token = token, Power = power, Audit = audit };
        handler.GateRaiser = (raise, _) =>
        {
            rig.Raises++;
            return Task.FromResult(rig.NextAnswer);
        };
        handler.GateDenyAndEndTeardown = _ =>
        {
            rig.TeardownFired = true;
            rig.AuditHadDenyAndEndAtTeardown = rig.Entries().Any(e => e.Outcome == "approval_deny_and_end");
        };
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return rig;
    }

    [Fact]
    public async Task Allow_ExecutesOnce_AndIsNotSticky()
    {
        var rig = BuildRig();
        rig.NextAnswer = GateAnswers.Allow;
        await rig.Call("session_start");
        var first = await rig.Call("power_tool");
        Assert.Contains("power acted", first);
        Assert.Equal(1, rig.Power.Calls);
        Assert.Equal(1, rig.Raises);
        Assert.Contains(rig.Entries(), e => e.Outcome == "gate_raised:power");
        Assert.Contains(rig.Entries(), e => e.Outcome == "gate_allowed:power");
        // One-shot: the standing set was NOT mutated — a second gated
        // call raises the gate again rather than sailing through.
        var second = await rig.Call("power_tool");
        Assert.Contains("power acted", second);
        Assert.Equal(2, rig.Raises);
        Assert.Equal(2, rig.Power.Calls);
    }

    [Fact]
    public async Task Deny_BlocksExecution_AndAudits()
    {
        var rig = BuildRig();
        rig.NextAnswer = GateAnswers.Deny;
        await rig.Call("session_start");
        var resp = await rig.Call("power_tool");
        Assert.Contains("gate_denied:power", resp);
        Assert.Equal(0, rig.Power.Calls);
        Assert.NotNull(rig.Sessions.Current); // a plain deny ends nothing
        Assert.Contains(rig.Entries(), e => e.Outcome == "gate_denied:power");
    }

    [Fact]
    public async Task DenyAndEnd_AuditsFirst_ThenTearsDown()
    {
        var rig = BuildRig();
        rig.NextAnswer = GateAnswers.DenyAndEnd;
        await rig.Call("session_start");
        Assert.NotNull(rig.Sessions.Current);
        var resp = await rig.Call("power_tool");
        Assert.Contains("gate_deny_and_end:power", resp);
        Assert.Equal(0, rig.Power.Calls);
        // Teardown happened, and at teardown time the audit entry
        // ALREADY existed — audit-first is the contract, proven from
        // inside the teardown callback itself.
        Assert.True(rig.TeardownFired);
        Assert.True(rig.AuditHadDenyAndEndAtTeardown);
        Assert.Null(rig.Sessions.Current);
    }

    [Fact]
    public async Task NoAnswer_IsADeny_NeverAYes()
    {
        var rig = BuildRig();
        rig.NextAnswer = null; // sheet closed / timeout / channel down
        await rig.Call("session_start");
        var resp = await rig.Call("power_tool");
        Assert.Contains("gate_no_answer:power", resp);
        Assert.Equal(0, rig.Power.Calls);
        Assert.Contains(rig.Entries(), e => e.Outcome == "gate_no_answer:power");
    }

    [Fact]
    public async Task NoRaiserWired_StandingDenyStands()
    {
        // Pre-W9 posture: with no raiser composed, a gated call is
        // simply denied — wiring the gate can only add the person's
        // decision, never weaken the default.
        var rig = BuildRig();
        rig.Handler.GateRaiser = null;
        await rig.Call("session_start");
        var resp = await rig.Call("power_tool");
        Assert.Contains("gated:", resp);
        Assert.Equal(0, rig.Power.Calls);
        Assert.Equal(0, rig.Raises);
    }

    [Fact]
    public async Task StandingApprovedClass_NeverRaises()
    {
        var rig = BuildRig();
        rig.NextAnswer = GateAnswers.Deny; // would block if asked — must not be asked
        await rig.Call("session_start");
        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"power_tool\",\"arguments\":{}}}";
        var resp = await rig.Handler.HandleAsync(body, $"Bearer {rig.Token}",
            new HashSet<string> { "power" }, default);
        Assert.Contains("power acted", resp.Json!);
        Assert.Equal(0, rig.Raises);
        Assert.Equal(1, rig.Power.Calls);
    }
}

/// <summary>W9 Lane A — chat parity: store cursor semantics,
/// per-pairing isolation, and the metadata-only audit rule.</summary>
public class W9ChatTests
{
    private static ToolExecutionContext Ctx(Pairing pairing) =>
        new(pairing, TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "");

    private static JsonElement Args(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void Store_CursorResumesWithoutLossOrDuplication()
    {
        var store = new AgentChatStore(TestUtil.TempDir());
        store.Append("p1", AgentChatStore.DirOwner, "one", 100);
        store.Append("p1", AgentChatStore.DirAgent, "two", 200);
        store.Append("p1", AgentChatStore.DirOwner, "three", 300);
        Assert.Equal(3, store.NextCursor("p1"));
        var page1 = store.LoadAfter("p1", 0);
        Assert.Equal(new long[] { 1, 2, 3 }, page1.Select(s => s.Seq).ToArray());
        var page2 = store.LoadAfter("p1", page1[^1].Seq);
        Assert.Empty(page2);
        store.Append("p1", AgentChatStore.DirAgent, "four", 400);
        var page3 = store.LoadAfter("p1", 3);
        Assert.Single(page3);
        Assert.Equal("four", page3[0].Message.Body);
        Assert.Equal(4, page3[0].Seq);
    }

    [Fact]
    public void Store_ThreadsAreIsolatedPerPairing()
    {
        var store = new AgentChatStore(TestUtil.TempDir());
        store.Append("p1", AgentChatStore.DirOwner, "for one", 1);
        store.Append("p2", AgentChatStore.DirOwner, "for two", 2);
        Assert.Equal("for one", Assert.Single(store.Load("p1")).Body);
        Assert.Equal("for two", Assert.Single(store.Load("p2")).Body);
        store.EndThread("p1");
        Assert.Empty(store.Load("p1"));
        Assert.False(store.ThreadExists("p1"));
        Assert.Single(store.Load("p2")); // the other thread is untouched
    }

    [Fact]
    public void Store_RefusesBlankAndOverLimit()
    {
        var store = new AgentChatStore(TestUtil.TempDir());
        Assert.Throws<ArgumentException>(() => store.Append("p1", AgentChatStore.DirOwner, "   ", 1));
        Assert.Throws<ArgumentException>(() => store.Append("p1", AgentChatStore.DirOwner,
            new string('x', AgentChatStore.MaxBodyChars + 1), 1));
        var ok = store.Append("p1", AgentChatStore.DirOwner, new string('x', AgentChatStore.MaxBodyChars), 1);
        Assert.Equal(1, ok.Seq);
        Assert.Equal(AgentChatStore.MaxBodyChars, ok.Audit.Chars);
    }

    [Fact]
    public async Task Modules_CallerBound_AndDeadPairingCloses()
    {
        var store = new AgentChatStore(TestUtil.TempDir());
        var alive = new HashSet<string> { "p1", "p2" };
        var read = new ChatReadModule(store, id => alive.Contains(id));
        var post = new ChatPostModule(store, id => alive.Contains(id));
        var p1 = TestUtil.BarePairing(Scopes.All, "p1");
        var p2 = TestUtil.BarePairing(Scopes.All, "p2");

        var posted = await post.ExecuteAsync(Args("""{"body":"hello from p1"}"""), Ctx(p1), default);
        Assert.True(posted.Ok);
        // p2 reading ITS OWN thread sees nothing of p1's — the
        // pairing comes from the caller's context, never an argument.
        var p2View = await read.ExecuteAsync(Args("{}"), Ctx(p2), default);
        Assert.DoesNotContain("hello from p1", p2View.Text);
        var p1View = await read.ExecuteAsync(Args("{}"), Ctx(p1), default);
        Assert.Contains("hello from p1", p1View.Text);
        Assert.Contains("\"next_cursor\":1", p1View.Text);

        // Unpair: both legs report the thread closed.
        alive.Remove("p1");
        var deadRead = await read.ExecuteAsync(Args("{}"), Ctx(p1), default);
        Assert.Contains("thread is closed", deadRead.Text);
        var deadPost = await post.ExecuteAsync(Args("""{"body":"anyone there"}"""), Ctx(p1), default);
        Assert.Contains("thread is closed", deadPost.Text);
    }

    [Fact]
    public async Task Modules_RefuseBlankAndOverLimitPosts()
    {
        var store = new AgentChatStore(TestUtil.TempDir());
        var post = new ChatPostModule(store, _ => true);
        var p1 = TestUtil.BarePairing(Scopes.All, "p1");
        var blank = await post.ExecuteAsync(Args("""{"body":"  "}"""), Ctx(p1), default);
        Assert.False(blank.Ok);
        var over = await post.ExecuteAsync(
            Args(JsonSerializer.Serialize(new { body = new string('y', AgentChatStore.MaxBodyChars + 1) })), Ctx(p1), default);
        Assert.False(over.Ok);
        Assert.Empty(store.Load("p1"));
    }

    [Fact]
    public void AuditSummary_NeverCarriesTheBody()
    {
        // The handler writes ChatAuditSummary for chat calls instead
        // of the redacted arguments: a body mentioning secret-shaped
        // words must appear NOWHERE in the audit text — only counts.
        var secretBody = "my password is hunter2, call me";
        var postSummary = McpHandler.ChatAuditSummary("chat_post", Args(JsonSerializer.Serialize(new { body = secretBody })));
        Assert.DoesNotContain("hunter2", postSummary);
        Assert.DoesNotContain("password", postSummary);
        Assert.Contains("\"chars\":31", postSummary);
        var readSummary = McpHandler.ChatAuditSummary("chat_read", Args("""{"after_seq":7}"""));
        Assert.Contains("\"after_seq\":7", readSummary);
    }

    [Fact]
    public async Task ChatTools_WorkWithoutASession()
    {
        // Chat is not a session: through the real handler, with NO
        // session started, chat_read/chat_post still work (the F6
        // session-binding leg exempts them by name), while a control
        // tool in the same rig is refused for want of a session.
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        var store = new AgentChatStore(TestUtil.TempDir());
        registry.Register(new ChatReadModule(store, _ => true));
        registry.Register(new ChatPostModule(store, _ => true));
        var auditDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(auditDir), state, sessions, auditDir);
        async Task<string> Call(string tool, string argsJson)
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":" + argsJson + "}}";
            var resp = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            return resp.Json!;
        }
        var post = await Call("chat_post", """{"body":"no session, still chat"}""");
        Assert.Contains("posted", post); // the module's success payload, JSON-escaped inside the result
        Assert.Contains("seq", post);
        var read = await Call("chat_read", "{}");
        Assert.Contains("no session, still chat", read);
        Assert.Null(sessions.Current); // and no session was conjured
    }
}

/// <summary>
/// W9 Lane A — CreateRequest authorization context (bd-shared-plat-2
/// / F12 remainder half). Before W9 the service accepted a bare
/// caller-named `requestedBy` string from anyone; now the requester
/// must be a live roster user of the scope holding the "use" right
/// on the device group (or a scope admin), judged live at request
/// time. Refusals are audited and create nothing.
/// </summary>
public class W9CreateRequestGateTests
{
    private const string Scope = "co-w9";
    private const string Admin = "admin-w9";
    private const string Op = "op-w9";
    private const string Outsider = "outsider-w9";
    private const string UG = "ug-w9";
    private const string DG = "dg-w9";

    private sealed class Rig
    {
        public required MobileApprovalService Approvals;
        public required ChainedAuditLog Audit;
    }

    private static Rig BuildRig()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        roster.CreateScope(Scope, "company", "Acme");
        roster.CreateUser(Admin, Scope, "Admin One", "human");
        roster.CreateUser(Op, Scope, "Operator One", "human");
        roster.CreateUser(Outsider, Scope, "Outsider One", "human");
        roster.AddCompanyAdmin(Scope, Admin);
        roster.CreateUserGroup(UG, Scope, "Techs", new[] { Op }, new[] { Admin });
        roster.CreateDeviceGroup(DG, Scope, "Workstations");
        roster.AddGrant(Scope, UG, DG, new[] { "use", "enroll", "admin", "view" });
        var audit = new ChainedAuditLog();
        var clients = new MobileClientRegistry(enrollments, roster, audit);
        var auth = new MobileAuthorization(roster, clients, () => true);
        return new Rig { Approvals = new MobileApprovalService(enrollments, clients, auth, audit), Audit = audit };
    }

    private static readonly DateTimeOffset Now = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ScopeAdmin_CanRequest()
    {
        var rig = BuildRig();
        var req = rig.Approvals.CreateRequest(Scope, DG, "restart service", Admin, TimeSpan.FromMinutes(10), Now);
        Assert.NotNull(req);
        Assert.Equal(Admin, req!.RequestedBy);
    }

    [Fact]
    public void UseRightHolder_CanRequest()
    {
        var rig = BuildRig();
        var req = rig.Approvals.CreateRequest(Scope, DG, "restart service", Op, TimeSpan.FromMinutes(10), Now);
        Assert.NotNull(req);
    }

    [Fact]
    public void Outsider_Refused_AndAudited()
    {
        var rig = BuildRig();
        var req = rig.Approvals.CreateRequest(Scope, DG, "restart service", Outsider, TimeSpan.FromMinutes(10), Now);
        Assert.Null(req);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mobile_approval_request_refused");
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "mobile_approval_requested");
    }

    [Fact]
    public void UnknownUser_Refused()
    {
        // The pre-W9 hole exactly: a bare string naming nobody the
        // roster knows must not mint an approval request.
        var rig = BuildRig();
        var req = rig.Approvals.CreateRequest(Scope, DG, "restart service", "mallory", TimeSpan.FromMinutes(10), Now);
        Assert.Null(req);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mobile_approval_request_refused");
    }

    [Fact]
    public void WrongDeviceGroup_Refused()
    {
        // The right is per-group: Op's grant covers DG, not another.
        var rig = BuildRig();
        var req = rig.Approvals.CreateRequest(Scope, "dg-other", "restart service", Op, TimeSpan.FromMinutes(10), Now);
        Assert.Null(req);
    }
}

/// <summary>
/// W9 Lane A — the disk-backed P2P content store. Blobs verified
/// once must survive a Core restart (a fresh store instance over
/// the same directory serves them), tampered bytes on disk are
/// NEVER served (and are deleted), and revocation removes the file.
/// </summary>
public class W9P2pDiskStoreTests
{
    private static byte[] Payload(int seed, int size = 5000)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    [Fact]
    public void Blob_SurvivesNewStoreInstanceOverSameDirectory()
    {
        var dir = TestUtil.TempDir();
        var contentDir = Path.Combine(dir, "p2p-content");
        var payload = Payload(1);
        var manifest = ContentManifest.Build(payload, 1024);
        var first = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.True(first.PutVerified(manifest, payload));

        var second = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.True(second.Has(manifest.ContentHash));
        Assert.Equal(payload, second.GetWhole(manifest.ContentHash));
        Assert.Equal(payload.AsSpan(1024, 1024).ToArray(), second.GetChunk(manifest.ContentHash, manifest, 1));
    }

    [Fact]
    public void TamperedDiskBlob_NeverServed_AndDeleted()
    {
        var dir = TestUtil.TempDir();
        var contentDir = Path.Combine(dir, "p2p-content");
        var payload = Payload(2);
        var manifest = ContentManifest.Build(payload, 1024);
        var first = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.True(first.PutVerified(manifest, payload));
        var blobFile = Path.Combine(contentDir, manifest.ContentHash + ".blob");
        Assert.True(File.Exists(blobFile));
        // Corrupt the bytes on disk, then ask a FRESH store (no
        // memory cache to hide behind) for the blob.
        var tampered = File.ReadAllBytes(blobFile);
        tampered[0] ^= 0xFF;
        File.WriteAllBytes(blobFile, tampered);
        var second = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.False(second.Has(manifest.ContentHash));
        Assert.Null(second.GetWhole(manifest.ContentHash));
        Assert.False(File.Exists(blobFile)); // failing bytes are removed, not left to be retried
    }

    [Fact]
    public void Revoke_DeletesTheDiskBlob()
    {
        var dir = TestUtil.TempDir();
        var contentDir = Path.Combine(dir, "p2p-content");
        var payload = Payload(3);
        var manifest = ContentManifest.Build(payload, 1024);
        var store = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.True(store.PutVerified(manifest, payload));
        var blobFile = Path.Combine(contentDir, manifest.ContentHash + ".blob");
        Assert.True(File.Exists(blobFile));
        store.Revoke(manifest.ContentHash);
        Assert.False(File.Exists(blobFile));
        Assert.False(store.Has(manifest.ContentHash));
        var fresh = new PeerContentStore(Path.Combine(dir, "rev.json"), contentDir);
        Assert.False(fresh.Has(manifest.ContentHash)); // the revocation itself persisted too
    }

    [Fact]
    public void MemoryOnlyStore_WritesNothingToDisk()
    {
        var payload = Payload(4);
        var manifest = ContentManifest.Build(payload, 1024);
        var store = new PeerContentStore();
        Assert.True(store.PutVerified(manifest, payload));
        Assert.Equal(payload, store.GetWhole(manifest.ContentHash));
    }
}

/// <summary>
/// W9 Lane A — EndpointSecurityService's Windows bindings and its
/// composition in CoreRuntime. Off-Windows, the bindings must say
/// so honestly (unknown AV posture, isolation actuation refuses)
/// rather than inventing a posture.
/// </summary>
public class W9EndpointSecurityBindingTests
{
    [Fact]
    public async Task FileActivitySource_ReportsRealFileEvents()
    {
        var dir = TestUtil.TempDir();
        using var source = new FileSystemActivitySource(new[] { dir });
        Assert.Equal(1, source.WatchedRootCount);
        var file = Path.Combine(dir, "probe.txt");
        await File.WriteAllTextAsync(file, "hello");
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        IReadOnlyList<FileActivityEvent> events = Array.Empty<FileActivityEvent>();
        while (DateTimeOffset.UtcNow < deadline)
        {
            events = source.Drain();
            if (events.Any(e => e.Path.Contains("probe.txt"))) break;
            await Task.Delay(100);
        }
        Assert.Contains(events, e => e.Path.Contains("probe.txt"));
    }

    [Fact]
    public void AvSource_OffWindows_ReportsUnknownHonestly()
    {
        if (OperatingSystem.IsWindows()) return; // the live posture path is Windows-only by construction
        var readings = new WindowsAvStatusSource().Read(DateTimeOffset.UtcNow);
        var reading = Assert.Single(readings);
        Assert.False(reading.SourceAlive);
        Assert.Equal("unknown", reading.ClaimedState);
        Assert.False(reading.Installed);
    }

    [Fact]
    public void NetworkControl_OffWindows_ApplyThrowsSoTheManagerRecordsFailure()
    {
        if (OperatingSystem.IsWindows()) return;
        var control = new WindowsEndpointNetworkControl();
        var plan = new IsolationPlan(new[]
        {
            new DeskGuestChannelExemption(ExemptionKinds.LanRung, "127.0.0.1", 18765),
        });
        Assert.ThrowsAny<Exception>(() => control.ApplyIsolation(plan));
    }

    [Fact]
    public void CoreRuntime_ComposesEndpointSecurity()
    {
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = TestUtil.TempDir(),
            Port = 18798,
            Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(),
            FactChecks = new FakeFactChecks(),
        });
        Assert.NotNull(runtime.EndpointSecurity);
    }
}

/// <summary>
/// W9 Lane A — the STOP-hotkey fixture's verdicts, pinned. The
/// three chords the design rounds rejected stay rejected; the
/// four-modifier F-row is thinned by the slip-adjacency rule; the
/// landed default is the first survivor.
/// </summary>
public class W9StopHotkeyFixtureTests
{
    private static IReadOnlyDictionary<string, StopHotkeyFixture.Verdict> ByChord() =>
        StopHotkeyFixture.Evaluate().ToDictionary(v => v.Candidate.Chord, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void AllFiveListsWereConsulted()
    {
        Assert.Equal(5, StopHotkeyFixture.ConsultedLists.Count);
        Assert.Contains(StopHotkeyFixture.ListWindowsOs, StopHotkeyFixture.ConsultedLists);
        Assert.Contains(StopHotkeyFixture.ListRdpClient, StopHotkeyFixture.ConsultedLists);
        Assert.Contains(StopHotkeyFixture.ListGpuHotkeys, StopHotkeyFixture.ConsultedLists);
        Assert.Contains(StopHotkeyFixture.ListOemUtilities, StopHotkeyFixture.ConsultedLists);
        Assert.Contains(StopHotkeyFixture.ListClipboardScreenTools, StopHotkeyFixture.ConsultedLists);
    }

    [Fact]
    public void EveryClaim_CarriesASource()
    {
        Assert.NotEmpty(StopHotkeyFixture.Claims);
        Assert.All(StopHotkeyFixture.Claims, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Source));
            Assert.False(string.IsNullOrWhiteSpace(c.ClaimedBy));
            Assert.Contains(c.ListName, StopHotkeyFixture.ConsultedLists);
        });
    }

    [Fact]
    public void RecordRejectedChords_StayRejected()
    {
        var verdicts = ByChord();
        Assert.False(verdicts["Ctrl+Shift+Esc"].Survives);   // Windows Task Manager
        Assert.False(verdicts["Ctrl+Alt+End"].Survives);     // RDP secure-attention chord
        Assert.False(verdicts["Ctrl+Alt+F12"].Survives);     // Intel graphics hotkey
    }

    [Fact]
    public void FixtureFoundClaims_KillTheirChords()
    {
        var verdicts = ByChord();
        Assert.False(verdicts["Ctrl+Alt+Break"].Survives);   // RDP fullscreen toggle
        Assert.False(verdicts["Ctrl+Alt+Home"].Survives);    // RDP connection bar
        Assert.False(verdicts["Ctrl+Alt+Minus"].Survives);   // RDP window snapshot
        Assert.False(verdicts["Win+Ctrl+Shift+B"].Survives); // Windows graphics-driver restart
        Assert.False(verdicts["Alt+Shift+F10"].Survives);    // NVIDIA Instant Replay toggle
        Assert.False(verdicts["Ctrl+Shift+O"].Survives);     // AMD performance overlay
    }

    [Fact]
    public void SlipAdjacency_ThinsTheFourModifierFRow()
    {
        var verdicts = ByChord();
        // One modifier away from a claimed chord with the same key:
        Assert.False(verdicts["Ctrl+Alt+Shift+F12"].Survives); // ~ Intel Ctrl+Alt+F12
        Assert.Contains("slip-adjacent", verdicts["Ctrl+Alt+Shift+F12"].Reason);
        Assert.False(verdicts["Ctrl+Alt+Shift+F10"].Survives); // ~ NVIDIA Alt+Shift+F10
        Assert.Contains("slip-adjacent", verdicts["Ctrl+Alt+Shift+F10"].Reason);
    }

    [Fact]
    public void DefaultChord_IsTheFirstSurvivor()
    {
        var verdicts = ByChord();
        Assert.True(verdicts["Ctrl+Alt+Shift+F9"].Survives);
        Assert.NotNull(StopHotkeyFixture.DefaultChord);
        Assert.Equal("Ctrl+Alt+Shift+F9", StopHotkeyFixture.DefaultChord!.Chord);
        // F11 also passes every list; it is recorded as a survivor
        // but is NOT the default — preference order decides, and the
        // fixture keeps the fact visible rather than hiding it.
        Assert.True(verdicts["Ctrl+Alt+Shift+F11"].Survives);
    }
}

/// <summary>
/// W9 Lane A — the dotnet catalogue pin verification (bd-shared-
/// plat-1/F8 remainder), pinned at the level the evidence supports:
/// the starter entry's declared version, its install script's
/// --exact version, and the winget package id all agree on the
/// verified 8.0.0; the neighbouring vcredist full-build-number pin
/// (the F8 fix itself) is guarded against regression.
/// </summary>
public class W9DotnetPinTests
{
    [Fact]
    public void DotnetStarterPin_VersionAndScriptAgree()
    {
        var pack = DeskGuest.Shared.Deployment.StarterContentPacks.RuntimePack();
        var dotnet = pack.Packages.Single(p => p.Id == "dotnet-desktop-runtime");
        Assert.Equal("8.0.0", dotnet.Version);
        var install = dotnet.Install.Steps.Concat(dotnet.Uninstall.Steps).Select(s => s.ScriptBody ?? "").ToList();
        Assert.Contains(install, s => s.Contains("winget install --id Microsoft.DotNet.DesktopRuntime.8")
                                      && s.Contains("--version 8.0.0 --exact"));
    }

    [Fact]
    public void VcRedistPin_KeepsTheFullBuildNumber()
    {
        var pack = DeskGuest.Shared.Deployment.StarterContentPacks.RuntimePack();
        var vc = pack.Packages.Single(p => p.Id == "vcredist-x64");
        Assert.Equal("14.40.33810.0", vc.Version);
    }
}

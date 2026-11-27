using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>U5 regression tests: per-agent data-flow transparency.
/// Fixture payloads reconcile exactly; counters are per-pairing and
/// never merge; ended sessions keep totals (persisted); gaps in the
/// audit cross-check show as gaps, never as fabricated flows; the
/// human-session picture derives its bytes from the file-job records
/// that already exist.</summary>
public class DataFlowTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    // ---------- unit: the ledger ----------

    [Fact]
    public void Ledger_KnownPayloads_ReconcileExactly()
    {
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "p1", "agent-a", T0);
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 2, 10, null, T0);
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 2, 5, null, T0);
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "click", DataFlowClasses.Changed, 7, 3, null, T0);

        var rec = Assert.Single(ledger.Records());
        Assert.Equal(11, rec.BytesIn);   // 2 + 2 + 7
        Assert.Equal(18, rec.BytesOut);  // 10 + 5 + 3
        var read = Assert.Single(rec.Tools, t => t.Tool == "file_read");
        Assert.Equal(2, read.Calls);
        Assert.Equal(4, read.BytesIn);
        Assert.Equal(15, read.BytesOut);
        Assert.Equal(DataFlowClasses.Read, read.Class);
        var click = Assert.Single(rec.Tools, t => t.Tool == "click");
        Assert.Equal(DataFlowClasses.Changed, click.Class);
    }

    [Fact]
    public void Ledger_NegativeBytes_Refused_CountersOnlyGrow()
    {
        var ledger = new DataFlowLedger();
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, -5, 10, null, T0);
        Assert.Empty(ledger.Records());
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 5, 10, null, T0);
        Assert.Equal(5, Assert.Single(ledger.Records()).BytesIn);
    }

    [Fact]
    public void Ledger_EndedSessions_KeepTotals_AndPersistAcrossInstances()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "data-flows.json");
        var first = new DataFlowLedger(path);
        first.BeginSession("s1", "p1", "agent-a", T0);
        first.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 2, 42, "dev-9", T0);
        first.EndSession("s1", T0 + TimeSpan.FromMinutes(3));

        var second = new DataFlowLedger(path); // reload from disk
        var rec = Assert.Single(second.Records());
        Assert.Equal(42, rec.BytesOut);
        Assert.NotNull(rec.EndedUtc);
        Assert.Contains("dev-9", rec.Destinations);
    }

    // ---------- destruction (recovery-verification, 2026-11-22) ----------

    [Fact]
    public void Ledger_CrossPairingSessionIdCollision_RefusesMerge()
    {
        // A call presented under pairing A's session id but carrying
        // pairing B's identity must NOT fold B's bytes into A's
        // record (nor rebind the record to B). The ledger refuses
        // the merge itself, not just the choke point.
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "pA", "agent-a", T0);
        ledger.NoteCall("s1", "agent", "pA", "agent-a", "file_read", DataFlowClasses.Read, 2, 100, null, T0);
        ledger.NoteCall("s1", "agent", "pB", "agent-b", "file_read", DataFlowClasses.Read, 2, 999, null, T0);

        var rec = Assert.Single(ledger.Records());
        Assert.Equal("pA", rec.PairingId);
        Assert.Equal(100, rec.BytesOut);
        Assert.Equal(1, rec.Tools.Single(t => t.Tool == "file_read").Calls);

        var report = DataFlowReport.Build(ledger.Records(), Array.Empty<AuditEntry>());
        Assert.Single(report.Agents);
        Assert.Equal(100, report.Agents[0].BytesOut); // B's 999 never lands anywhere
    }

    [Fact]
    public void Ledger_KindConfusion_RefusesMerge()
    {
        // Stream (human) bytes presented under an agent record's id
        // — or agent bytes under a human record's id — never merge
        // across kinds.
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "pA", "agent-a", T0);
        ledger.NoteCall("s1", "human", null, "stream", "stream", DataFlowClasses.Read, 0, 555, "dev-1", T0);
        var rec = Assert.Single(ledger.Records());
        Assert.Equal("agent", rec.Kind);
        Assert.Equal(0, rec.BytesOut);
        Assert.Empty(rec.Tools);
    }

    [Fact]
    public void Report_AuditCannotFabricateAgentRowsOrBytes()
    {
        // Destruction: an audit stuffed with entries for a pairing
        // that has NO flow records must produce gaps only — never an
        // agent row, never an estimated byte.
        var audit = Enumerable.Range(0, 5)
            .Select(_ => ToolCallAudit("p-forged", "forged-agent", "file_read")).ToArray();
        var report = DataFlowReport.Build(Array.Empty<SessionFlowRecord>(), audit);
        Assert.Empty(report.Agents);
        Assert.Empty(report.HumanFlows);
        Assert.Contains(report.Gaps, g => g.Contains("5 audited tool call(s) have no flow record"));
    }

    // ---------- unit: classification ----------

    [Fact]
    public void Classifier_MapsReadSentChanged()
    {
        ToolDescriptor D(string name, string scope, string? gate = null) =>
            new(name, "stub", scope, SessionRequirement.Core, RiskTier.Low, gate, "Core");
        Assert.Equal(DataFlowClasses.Read, DataFlowClassifier.Classify(D("file_read", Scopes.Shell)));       // egress by name
        Assert.Equal(DataFlowClasses.Read, DataFlowClassifier.Classify(D("session_status", Scopes.Observe))); // observe
        Assert.Equal(DataFlowClasses.Sent, DataFlowClassifier.Classify(D("send_message", Scopes.Drive, BudgetClasses.Sending)));
        Assert.Equal(DataFlowClasses.Changed, DataFlowClassifier.Classify(D("click", Scopes.Drive)));
        Assert.Equal(DataFlowClasses.Changed, DataFlowClassifier.Classify(D("file_delete", Scopes.Shell)));
    }

    // ---------- unit: the report + its gaps ----------

    private static AuditEntry ToolCallAudit(string? pairingId, string? agent, string tool) =>
        new(T0, "tool_call", pairingId, agent, tool, null, "{}", "executed", "SYSTEM", 1);

    [Fact]
    public void Report_TwoPairings_NeverMerge()
    {
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "p1", "agent-a", T0);
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 2, 100, null, T0);
        ledger.BeginSession("s2", "p2", "agent-b", T0);
        ledger.NoteCall("s2", "agent", "p2", "agent-b", "file_read", DataFlowClasses.Read, 2, 7, null, T0);

        var audit = new[] { ToolCallAudit("p1", "agent-a", "file_read"), ToolCallAudit("p2", "agent-b", "file_read") };
        var report = DataFlowReport.Build(ledger.Records(), audit);
        Assert.Equal(2, report.Agents.Count);
        Assert.Equal(100, report.Agents.Single(a => a.PairingId == "p1").BytesOut);
        Assert.Equal(7, report.Agents.Single(a => a.PairingId == "p2").BytesOut);
        Assert.Empty(report.Gaps); // audit and records corroborate exactly
    }

    [Fact]
    public void Report_AuditedCallsWithoutFlowRecords_ShowAsGap_NothingFabricated()
    {
        var audit = new[]
        {
            ToolCallAudit("p-ghost", "ghost-agent", "file_read"),
            ToolCallAudit("p-ghost", "ghost-agent", "file_read"),
            ToolCallAudit("p-ghost", "ghost-agent", "screenshot"),
        };
        var report = DataFlowReport.Build(Array.Empty<SessionFlowRecord>(), audit);
        // No agent row is invented for the ghost pairing, and no
        // byte total is estimated — the gap is named with its count.
        Assert.Empty(report.Agents);
        var gap = Assert.Single(report.Gaps);
        Assert.Contains("ghost-agent", gap);
        Assert.Contains("3 audited tool call(s) have no flow record", gap);
        Assert.Contains("NOT estimated", gap);
    }

    [Fact]
    public void Report_PartialGap_CountsOnlyTheMissingCalls()
    {
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "p1", "agent-a", T0);
        ledger.NoteCall("s1", "agent", "p1", "agent-a", "file_read", DataFlowClasses.Read, 2, 10, null, T0);
        var audit = new[] { ToolCallAudit("p1", "agent-a", "file_read"), ToolCallAudit("p1", "agent-a", "file_read") };
        var report = DataFlowReport.Build(ledger.Records(), audit);
        var agent = Assert.Single(report.Agents);
        Assert.Equal(10, agent.BytesOut); // the recorded flow stands as recorded
        var gap = Assert.Single(report.Gaps);
        Assert.Contains("1 audited tool call(s) have no flow record", gap);
    }

    [Fact]
    public void Report_UnattributedAuditEntries_ShownUnattributed_NeverAssigned()
    {
        var audit = new[] { ToolCallAudit(null, null, "file_read") };
        var report = DataFlowReport.Build(Array.Empty<SessionFlowRecord>(), audit);
        Assert.Empty(report.Agents);
        Assert.Contains(report.Gaps, g => g.Contains("no pairing id") && g.Contains("never assigned"));
    }

    // ---------- choke-point integration ----------

    private sealed class StubModule(string name, string scope, SessionRequirement session, string? gate, string text) : IToolModule
    {
        public ToolDescriptor Descriptor { get; } = new(name, "stub", scope, session, RiskTier.Low, gate, "Core");
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
        public required string TokenA;
        public required string TokenB;
        public required string PairingA;
        public required string PairingB;

        public async Task<string> Call(string token, string tool, string args = "{}")
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":" + args + "}}";
            var resp = await Handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            return resp.Json!;
        }
    }

    private static Rig BuildRig()
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        (string Id, string Token) Mint(string agent)
        {
            var code = pairings.CreatePairingCode(agent, TimeSpan.FromMinutes(5), Scopes.All);
            var ex = pairings.ExchangeCode(code, agent);
            Assert.NotNull(ex);
            return (ex!.PairingId, ex.BearerToken);
        }
        var (idA, tokenA) = Mint("agent-a");
        var (idB, tokenB) = Mint("agent-b");

        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new SessionStopModule(sessions, state));
        registry.Register(new StubModule("file_read", Scopes.Shell, SessionRequirement.Core, null, "0123456789")); // 10 bytes out
        registry.Register(new StubModule("click", Scopes.Drive, SessionRequirement.Agent, null, "clicked"));      // 7 bytes out
        var dir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(dir), state, sessions, dir);
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return new Rig
        {
            Handler = handler, Sessions = sessions,
            TokenA = tokenA, TokenB = tokenB, PairingA = idA, PairingB = idB,
        };
    }

    [Fact]
    public async Task ChokePoint_CountsBytes_PerSessionToolAndClass()
    {
        var rig = BuildRig();
        await rig.Call(rig.TokenA, "session_start");
        await rig.Call(rig.TokenA, "file_read");            // args "{}" = 2 in, "0123456789" = 10 out
        await rig.Call(rig.TokenA, "click", "{\"x\":1}");   // 7 in, "clicked" = 7 out

        var flows = rig.Handler.Flows;
        Assert.NotNull(flows);
        var sessionRecord = flows!.Records().Single(r => !r.OutsideSession);
        Assert.Equal(rig.PairingA, sessionRecord.PairingId);
        var read = Assert.Single(sessionRecord.Tools, t => t.Tool == "file_read");
        Assert.Equal(DataFlowClasses.Read, read.Class);
        Assert.Equal(2, read.BytesIn);
        Assert.Equal(10, read.BytesOut);
        var click = Assert.Single(sessionRecord.Tools, t => t.Tool == "click");
        Assert.Equal(DataFlowClasses.Changed, click.Class);
        Assert.Equal(7, click.BytesIn);
        Assert.Equal(7, click.BytesOut);
        Assert.Null(sessionRecord.EndedUtc); // still live
    }

    [Fact]
    public async Task ChokePoint_SecondPairing_NeverLandsOnFirstPairingsSession()
    {
        var rig = BuildRig();
        await rig.Call(rig.TokenA, "session_start");
        await rig.Call(rig.TokenA, "file_read");
        // Pairing B calls while A's session is live: the call is
        // denied (session owned by A) and its bytes land on B's own
        // standing record — never inside A's session record.
        var denied = await rig.Call(rig.TokenB, "file_read");
        Assert.Contains("session_owned_by_other_pairing", denied);

        var records = rig.Handler.Flows!.Records();
        var aSession = records.Single(r => !r.OutsideSession);
        Assert.Equal(rig.PairingA, aSession.PairingId);
        Assert.Equal(1, aSession.Tools.Single(t => t.Tool == "file_read").Calls); // only A's own call
        var bStanding = records.Single(r => r.OutsideSession);
        Assert.Equal(rig.PairingB, bStanding.PairingId);
        Assert.Equal(1, bStanding.Tools.Single(t => t.Tool == "file_read").Calls);

        var report = DataFlowReport.Build(records, Array.Empty<AuditEntry>());
        Assert.Equal(2, report.Agents.Count);
        Assert.Equal(10, report.Agents.Single(a => a.PairingId == rig.PairingA)
            .Tools.Single(t => t.Tool == "file_read").BytesOut);
        // B's only outbound bytes are its refusal text — no payload
        // of A's session ever flowed to B, and none of B's bytes
        // were folded into A's totals.
        var bFlow = report.Agents.Single(a => a.PairingId == rig.PairingB);
        Assert.True(bFlow.BytesOut > 0);
        Assert.Equal(1, bFlow.Tools.Single(t => t.Tool == "file_read").Calls);
    }

    [Fact]
    public async Task ChokePoint_SessionStop_ClosesRecord_TotalsKept()
    {
        var rig = BuildRig();
        await rig.Call(rig.TokenA, "session_start");
        await rig.Call(rig.TokenA, "file_read");
        await rig.Call(rig.TokenA, "session_stop");

        var rec = rig.Handler.Flows!.Records().Single(r => !r.OutsideSession);
        Assert.NotNull(rec.EndedUtc);
        // Totals survive the end: the file_read payload is intact
        // in the closed record (session_start/session_stop results
        // are counted on the same record, so assert the tool row).
        Assert.Equal(10, rec.Tools.Single(t => t.Tool == "file_read").BytesOut);
        Assert.True(rec.BytesOut >= 10);
        // And they survive a reload from the persisted ledger file.
        var reloaded = new DataFlowLedger(rig.Handler.Flows.FilePath);
        var rec2 = reloaded.Records().Single(r => !r.OutsideSession);
        Assert.Equal(10, rec2.Tools.Single(t => t.Tool == "file_read").BytesOut);
        Assert.NotNull(rec2.EndedUtc);
    }

    // ---------- destruction: the agent-callable surface ----------

    [Fact]
    public async Task SessionStatus_ShowsCallerOnly_ItsOwnFlows_NeverAnotherPairings()
    {
        var ledger = new DataFlowLedger();
        ledger.BeginSession("s1", "pA", "agent-a", T0);
        ledger.NoteCall("s1", "agent", "pA", "agent-a", "file_read", DataFlowClasses.Read, 2, 111, null, T0);
        ledger.BeginSession("s2", "pB", "agent-b", T0);
        ledger.NoteCall("s2", "agent", "pB", "agent-b", "file_read", DataFlowClasses.Read, 2, 222, null, T0);
        var audit = new[]
        {
            ToolCallAudit("pA", "agent-a", "file_read"),
            ToolCallAudit("pB", "agent-b", "file_read"),
            ToolCallAudit("p-ghost", "ghost-agent", "file_read"),
        };
        var report = DataFlowReport.Build(ledger.Records(), audit);
        var module = new SessionStatusModule(new SessionManager(), null, null, () => report);

        async Task<string> StatusFor(string pairingId)
        {
            var ctx = new ToolExecutionContext(
                TestUtil.BarePairing(Scopes.All, pairingId),
                TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "");
            var result = await module.ExecuteAsync(default, ctx, default);
            return result.Text!;
        }

        var forA = await StatusFor("pA");
        Assert.Contains("agent-a", forA);
        Assert.Contains("111", forA);
        Assert.DoesNotContain("agent-b", forA);   // B's identity + volumes stay B's
        Assert.DoesNotContain("222", forA);
        Assert.DoesNotContain("ghost-agent", forA); // another pairing's gap is not A's business

        var forB = await StatusFor("pB");
        Assert.Contains("agent-b", forB);
        Assert.DoesNotContain("agent-a", forB);
        Assert.DoesNotContain("111", forB);
    }

    // ---------- human-session picture derivation ----------

    [Fact]
    public void Picture_FileJobs_DeriveBytesInOutAndDestinations()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);

        var sessions = new SessionService(roster, enrollments);
        var s = sessions.CreateSession("company-1", device!.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(sessions.StartSession(s.Id));

        var inbound = sessions.CreateFileJob(s.Id, "to_host", "logs.zip", 1000, "ctrl");
        Assert.NotNull(inbound);
        Assert.True(sessions.UpdateFileProgress(inbound!.Id, 400, "ctrl")); // 400 of 1000 actually moved
        var outbound = sessions.CreateFileJob(s.Id, "from_host", "report.pdf", 250, "ctrl");
        Assert.NotNull(outbound);
        Assert.True(sessions.UpdateFileProgress(outbound!.Id, 250, "ctrl"));

        var fact = SessionPicture.Shape(sessions, roster, sessions.GetSession(s.Id)!, DateTimeOffset.UtcNow);
        Assert.Equal(400, fact.BytesIn);   // transferred, not the declared 1000
        Assert.Equal(250, fact.BytesOut);
        Assert.Contains(device.DeviceId, fact.Destinations!);
    }
}

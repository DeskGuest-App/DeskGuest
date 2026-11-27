using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>U4 regression tests: per-session agent budgets +
/// tripwires. Every cap class, the pause-not-kill tripwire, the
/// per-session reset, the policy plumbing (RMM-07 keys), and the
/// wired SCAM sensitive-context pause are pinned here.</summary>
public class SessionBudgetTests
{
    private static SessionBudgetCaps TinyCaps(long total = 100, long input = 100, long deletions = 100,
        long sending = 100, long egressCalls = 100, long egressBytes = long.MaxValue) =>
        new(Total: total, Input: input, Deletions: deletions, Sending: sending,
            EgressCalls: egressCalls, EgressBytes: egressBytes);

    // ---------- unit: the counter ----------

    [Fact]
    public void CapHit_Trips_WithClassAndNumbers()
    {
        var b = new SessionBudget();
        b.BeginSession("s1", TinyCaps(deletions: 2));
        var classes = new[] { BudgetClasses.Total, BudgetClasses.Deletions };
        Assert.Equal(BudgetVerdictKind.Allow, b.CheckAndCount("s1", classes).Kind);
        Assert.Equal(BudgetVerdictKind.Allow, b.CheckAndCount("s1", classes).Kind);
        var trip = b.CheckAndCount("s1", classes);
        Assert.Equal(BudgetVerdictKind.TripPause, trip.Kind);
        Assert.Equal(BudgetClasses.Deletions, trip.Class);
        Assert.Equal(3, trip.Count);
        Assert.Equal(2, trip.Cap);
        Assert.Contains("paused", trip.Reason);
    }

    [Fact]
    public void AfterTrip_FurtherChecks_DenyAsPaused_UntilResume()
    {
        var b = new SessionBudget();
        b.BeginSession("s1", TinyCaps(total: 1));
        Assert.Equal(BudgetVerdictKind.Allow, b.CheckAndCount("s1", new[] { BudgetClasses.Total }).Kind);
        Assert.Equal(BudgetVerdictKind.TripPause, b.CheckAndCount("s1", new[] { BudgetClasses.Total }).Kind);
        var denied = b.CheckAndCount("s1", new[] { BudgetClasses.Total });
        Assert.Equal(BudgetVerdictKind.Deny, denied.Kind);
        Assert.Contains("session_paused", denied.Reason);
        b.Resume("s1");
        // Counts stand after resume: the very next total call trips again.
        Assert.Equal(BudgetVerdictKind.TripPause, b.CheckAndCount("s1", new[] { BudgetClasses.Total }).Kind);
    }

    [Fact]
    public void Budgets_ResetPerSession()
    {
        var b = new SessionBudget();
        b.BeginSession("s1", TinyCaps(total: 1));
        b.CheckAndCount("s1", new[] { BudgetClasses.Total });
        Assert.Equal(BudgetVerdictKind.TripPause, b.CheckAndCount("s1", new[] { BudgetClasses.Total }).Kind);
        b.EndSession("s1");
        b.BeginSession("s2", TinyCaps(total: 1));
        Assert.Equal(BudgetVerdictKind.Allow, b.CheckAndCount("s2", new[] { BudgetClasses.Total }).Kind);
        var snap = b.Snapshot("s2", false, null)!;
        Assert.Equal(1, snap.Counts[BudgetClasses.Total]);
        Assert.Equal(1, snap.Caps[BudgetClasses.Total]);
    }

    [Fact]
    public void UnknownSession_Denies_NotSilentlyUncounted()
    {
        var b = new SessionBudget();
        var v = b.CheckAndCount("nope", new[] { BudgetClasses.Total });
        Assert.Equal(BudgetVerdictKind.Deny, v.Kind);
        Assert.Contains("no budget counters", v.Reason);
    }

    [Fact]
    public void EgressBytes_TripOnCumulativeCrossing()
    {
        var b = new SessionBudget();
        b.BeginSession("s1", TinyCaps(egressBytes: 10));
        Assert.Equal(BudgetVerdictKind.Allow, b.NoteEgressBytes("s1", 6).Kind);
        var trip = b.NoteEgressBytes("s1", 6);
        Assert.Equal(BudgetVerdictKind.TripPause, trip.Kind);
        Assert.Equal(BudgetClasses.EgressBytes, trip.Class);
        Assert.Equal(12, trip.Count);
        Assert.Contains("already returned its payload", trip.Reason);
    }

    [Fact]
    public void ZeroCap_ForbidsClassOutright()
    {
        var b = new SessionBudget();
        b.BeginSession("s1", TinyCaps(sending: 0));
        var v = b.CheckAndCount("s1", new[] { BudgetClasses.Total, BudgetClasses.Sending });
        Assert.Equal(BudgetVerdictKind.TripPause, v.Kind);
        Assert.Equal(BudgetClasses.Sending, v.Class);
    }

    // ---------- classifier ----------

    [Fact]
    public void Classifier_ClassesByGateAndName()
    {
        ToolDescriptor D(string name, string scope, string? gate = null) =>
            new(name, "x", scope, SessionRequirement.Core, RiskTier.Low, gate);
        Assert.Contains(BudgetClasses.Deletions, BudgetClassifier.ClassesFor(D("file_delete", Scopes.Shell)));
        Assert.Contains(BudgetClasses.Deletions, BudgetClassifier.ClassesFor(D("anything", Scopes.Shell, "deletions")));
        Assert.Contains(BudgetClasses.Sending, BudgetClassifier.ClassesFor(D("anything", Scopes.Drive, "sending")));
        Assert.Contains(BudgetClasses.Input, BudgetClassifier.ClassesFor(D("click", Scopes.Drive)));
        Assert.Contains(BudgetClasses.Input, BudgetClassifier.ClassesFor(D("type_text", Scopes.Drive)));
        Assert.Contains(BudgetClasses.EgressCalls, BudgetClassifier.ClassesFor(D("file_read", Scopes.Shell)));
        Assert.Contains(BudgetClasses.EgressCalls, BudgetClassifier.ClassesFor(D("clipboard_get", Scopes.Drive, "clipboard_read")));
        var plain = BudgetClassifier.ClassesFor(D("device_info", Scopes.Observe));
        Assert.Equal(new[] { BudgetClasses.Total }, plain);
    }

    // ---------- policy plumbing (RMM-07 pattern) ----------

    [Fact]
    public void PolicyKeys_ResolveCapsFromEffectivePolicy()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "scope1");
        var doc = new ManagementPolicyDocument("d1", PolicyLevels.Device, "dev1",
            new Dictionary<string, string>
            {
                ["session_budget.cap.deletions"] = "3",
                ["session_budget.cap.egress_bytes"] = "1048576",
                ["session_budget.cap.input"] = "not-a-number", // ignored: default stands
                ["session_budget.cap.sending"] = "-5",          // ignored: default stands
            }, 1);
        Assert.True(engine.AddDocument(doc).Allowed);
        var caps = SessionBudgetCaps.FromEffective(engine.ComputeEffective(facts));
        Assert.Equal(3, caps.Deletions);
        Assert.Equal(1048576, caps.EgressBytes);
        Assert.Equal(SessionBudgetCaps.DefaultInput, caps.Input);
        Assert.Equal(SessionBudgetCaps.DefaultSending, caps.Sending);
        Assert.Equal(SessionBudgetCaps.DefaultTotal, caps.Total);
    }

    [Fact]
    public void Registry_CarriesTheBudgetToggle_DefaultOn()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet("rmm.session_budget.enabled", out var toggle));
        Assert.True(toggle!.DefaultEnabled);
        var engine = new ManagementPolicyEngine(registry);
        Assert.True(engine.IsEnabled(StaticDeviceFacts.Of("dev1", ""), "rmm.session_budget.enabled"));
    }

    // ---------- SCAM sensitive context ----------

    [Fact]
    public void SensitiveContext_Classifier_MapsForegroundVocabulary()
    {
        Assert.Equal("banking", SensitiveContextClassifier.ContextFor("Chase Online Banking", "chrome"));
        Assert.Equal("password_manager", SensitiveContextClassifier.ContextFor("Vault — 1Password", "1Password"));
        Assert.Equal("password_field", SensitiveContextClassifier.ContextFor("Enter password", "login"));
        Assert.Null(SensitiveContextClassifier.ContextFor("notes.txt — Notepad", "notepad"));
        Assert.Null(SensitiveContextClassifier.ContextFor(null, null));
        Assert.True(SensitiveContextClassifier.Pauses("Chase Online Banking", "chrome"));
        Assert.False(SensitiveContextClassifier.Pauses("notes.txt — Notepad", "notepad"));
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
        public required CoreState State;
        public required string Token;
        public required string AuditDir;
        public required StubModule Click;
        public required StubModule Delete;
        public required StubModule Read;

        public async Task<string> Call(string tool)
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":{}}}";
            var resp = await Handler.HandleAsync(body, $"Bearer {Token}", new HashSet<string> { "deletions" }, default);
            return resp.Json!;
        }
    }

    private static Rig BuildRig(SessionBudgetCaps caps)
    {
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new SessionStopModule(sessions, state));
        var click = new StubModule("click", Scopes.Drive, SessionRequirement.Agent, null, "clicked");
        var delete = new StubModule("file_delete", Scopes.Shell, SessionRequirement.Core, "deletions", "deleted");
        var read = new StubModule("file_read", Scopes.Shell, SessionRequirement.Core, null, "0123456789");
        registry.Register(click);
        registry.Register(delete);
        registry.Register(read);
        var auditDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(auditDir), state, sessions, auditDir);
        handler.BudgetCapsProvider = () => caps;
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return new Rig
        {
            Handler = handler, Sessions = sessions, State = state, Token = token,
            AuditDir = auditDir, Click = click, Delete = delete, Read = read,
        };
    }

    [Fact]
    public async Task ChokePoint_CapBreach_PausesSession_AuditsTripwire_AndFurtherCallsDenyAsPaused()
    {
        var rig = BuildRig(TinyCaps(deletions: 1));
        await rig.Call("session_start");
        Assert.Contains("deleted", await rig.Call("file_delete"));
        var tripped = await rig.Call("file_delete");
        Assert.Contains("budget tripwire", tripped);
        Assert.True(rig.Sessions.IsPaused);
        Assert.Contains("deletions", rig.Sessions.PauseReason);
        Assert.Equal(1, rig.Delete.Calls); // the tripping call never executed
        // Further calls deny as paused — even an unrelated class.
        var after = await rig.Call("click");
        Assert.Contains("session_paused", after);
        Assert.Equal(0, rig.Click.Calls);
        // The tripwire is in the audit log with its numbers.
        var auditText = string.Join("\n", Directory.GetFiles(rig.AuditDir).Select(File.ReadAllText));
        Assert.Contains("budget_tripwire", auditText);
        Assert.Contains("class=deletions", auditText);
        // session_stop still works while paused (pause is not a trap).
        await rig.Call("session_stop");
        Assert.Null(rig.Sessions.Current);
        Assert.False(rig.Sessions.IsPaused);
    }

    [Fact]
    public async Task ChokePoint_OwnerResume_ClearsPause_CountsStand()
    {
        var rig = BuildRig(TinyCaps(total: 2));
        await rig.Call("session_start");
        await rig.Call("file_read");            // total 1 (session_start itself is not counted)
        var trip = await rig.Call("file_read"); // would be total 2... allowed; next trips
        Assert.DoesNotContain("budget tripwire", trip);
        var tripped = await rig.Call("file_read");
        Assert.Contains("budget tripwire", tripped);
        Assert.True(rig.Sessions.IsPaused);
        // Owner resume (the SessionManager/Budgets pair CoreRuntime's
        // host-window act drives): pause clears, counts stand.
        var sessionId = rig.Sessions.Current!.Id;
        var cleared = rig.Sessions.Resume();
        Assert.NotNull(cleared);
        rig.Handler.Budgets.Resume(sessionId);
        Assert.False(rig.Sessions.IsPaused);
        var again = await rig.Call("file_read"); // total still over cap: trips again
        Assert.Contains("budget tripwire", again);
    }

    [Fact]
    public async Task ChokePoint_ScamContext_PausesDriveCall_ButNotObserve()
    {
        var rig = BuildRig(TinyCaps());
        await rig.Call("session_start");
        rig.State.ApplyAgentSessionReport(null, null, "Chase Online Banking", "chrome");
        var drive = await rig.Call("click");
        Assert.Contains("scam_sensitive_context", drive);
        Assert.True(rig.Sessions.IsPaused);
        Assert.Equal(0, rig.Click.Calls);
        var auditText = string.Join("\n", Directory.GetFiles(rig.AuditDir).Select(File.ReadAllText));
        Assert.Contains("budget_tripwire", auditText);
        Assert.Contains("banking", auditText);
    }

    [Fact]
    public async Task ChokePoint_ScamContext_ObserveCall_NotTripped()
    {
        var rig = BuildRig(TinyCaps());
        await rig.Call("session_start");
        rig.State.ApplyAgentSessionReport(null, null, "Chase Online Banking", "chrome");
        // file_read is Shell scope, not Drive: the SCAM pause binds control, not reads.
        var read = await rig.Call("file_read");
        Assert.Contains("0123456789", read);
        Assert.False(rig.Sessions.IsPaused);
    }

    [Fact]
    public async Task ChokePoint_EgressByteCap_TripsAfterTheCrossingCall()
    {
        var rig = BuildRig(TinyCaps(egressBytes: 15));
        await rig.Call("session_start");
        var first = await rig.Call("file_read"); // 10 bytes out — under
        Assert.Contains("0123456789", first);
        Assert.False(rig.Sessions.IsPaused);
        var second = await rig.Call("file_read"); // 20 cumulative — crosses; payload still returns
        Assert.Contains("0123456789", second);
        Assert.True(rig.Sessions.IsPaused);
        Assert.Contains("egress_bytes", rig.Sessions.PauseReason);
        var third = await rig.Call("file_read");
        Assert.Contains("session_paused", third);
        Assert.Equal(2, rig.Read.Calls);
    }

    [Fact]
    public async Task ChokePoint_NewSession_ResetsBudgets()
    {
        var rig = BuildRig(TinyCaps(deletions: 1));
        await rig.Call("session_start");
        await rig.Call("file_delete");
        Assert.Contains("budget tripwire", await rig.Call("file_delete"));
        await rig.Call("session_stop");
        await rig.Call("session_start");
        Assert.Contains("deleted", await rig.Call("file_delete"));
        Assert.False(rig.Sessions.IsPaused);
    }

    [Fact]
    public async Task ChokePoint_BudgetsDisabledByPolicy_NoCountingNoPause()
    {
        var rig = BuildRig(TinyCaps(deletions: 0));
        rig.Handler.BudgetCapsProvider = () => null; // rmm.session_budget.enabled = false
        await rig.Call("session_start");
        Assert.Contains("deleted", await rig.Call("file_delete"));
        Assert.Contains("deleted", await rig.Call("file_delete"));
        Assert.False(rig.Sessions.IsPaused);
    }
}

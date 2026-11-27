using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Presence;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;
using DeskGuest.Shared.Wake;
using IServiceProvider = DeskGuest.Core.Modules.IServiceProvider;

namespace DeskGuest.Tests;

/// <summary>Block H — the inherited fixes: (a) the service_restart
/// defect that stranded the Core in the 2026-11-20 drill, (b) the
/// tray popup's mesh line, (c) version stamping, (e) the six Block
/// G remainders (teardown sweep, tunnel allowlist, factor
/// throttling, passkey challenge binding, per-act floor-grant
/// re-check, G-service exposure), and (f) the break-glass Rotate
/// surface. Attack coverage for the new surfaces lives in
/// BlockHDestructionTests; this file proves the fixes WORK as
/// specified.</summary>
public class BlockHTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    // ---- shared world (the BlockGTests fixture shape) ----

    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public SessionService Sessions { get; set; } = null!;
        public required string DeviceId { get; init; }
        public HashSet<string> Disabled { get; } = new();
        public HashSet<string> Required { get; } = new();
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("outsider", "company-1", "Outsider", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);

        var w = new World { Enrollments = enrollments, Roster = roster, Sessions = null!, DeviceId = device!.DeviceId };
        w.Sessions = new SessionService(roster, enrollments,
            (scopeId, key) => w.Disabled.Contains(key)
                ? new PolicyVerdict(false, $"feature '{key}' disabled by test policy")
                : new PolicyVerdict(true, "permitted by test policy"),
            (scopeId, key) => w.Required.Contains(key));
        return w;
    }

    private static string ActiveSession(World w, string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    private static ToolExecutionContext Ctx(string agentName = "test-agent", IReadOnlySet<string>? gates = null) =>
        new(new Pairing("p1", agentName, Scopes.All, T0, null, null, false),
            TestUtil.Session(), TestUtil.State(), gates ?? new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---- (c) version stamping ---------------------------------

    [Fact]
    public void Version_AssembliesCarryTheProductVersion_NotThePlaceholder()
    {
        var core = typeof(CoreState).Assembly.GetName().Version;
        var shared = typeof(SessionService).Assembly.GetName().Version;
        Assert.NotNull(core);
        Assert.Equal(new Version(0, 0, 1, 0), core);
        // One source (Directory.Build.props) stamps every project.
        Assert.Equal(core, shared);
        // The Core's reported version IS the assembly's — MCP
        // serverInfo, system info and the self-check read this.
        var state = new CoreState();
        Assert.StartsWith("0.0.1", state.CoreVersion);
        Assert.NotEqual("0.1.0", state.CoreVersion);
    }

    // ---- (a) service restart: the module's discipline ----------

    private sealed class FakeSvc : IServiceProvider
    {
        public bool Available => true;
        public Dictionary<string, string> States { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls { get; } = new();
        public IReadOnlyList<ServiceInfo> List() =>
            States.Select(kv => new ServiceInfo(kv.Key, kv.Key, kv.Value, "Automatic")).ToList();
        public ServiceInfo? Status(string name) =>
            States.TryGetValue(name, out var s) ? new ServiceInfo(name, name, s, "Automatic") : null;
        public void Start(string name) { Calls.Add("start:" + name); States[name] = "Running"; }
        public void Stop(string name) { Calls.Add("stop:" + name); States[name] = "Stopped"; }
        public void Restart(string name) { Calls.Add("restart:" + name); }
    }

    private sealed class FakeArmer : ISelfRestartArmer
    {
        public List<string> Armed { get; } = new();
        public List<string>? Order;
        public bool Throw;
        public void Arm(string serviceName, string dataDir, string exePath)
        {
            if (Throw) throw new InvalidOperationException("cannot spawn");
            Armed.Add(serviceName);
            Order?.Add("arm:" + serviceName);
        }
    }

    [Fact]
    public async Task Restart_DeskGuestRunning_ArmsWatchdog_AuditsFirst_NeverStopsInline()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Running";
        var order = new List<string>();
        var armer = new FakeArmer { Order = order };
        var module = new ServiceControlModule(svc, "restart", armer, "DeskGuestCore",
            (kind, actor, detail) => order.Add("audit:" + kind));
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(), default);
        Assert.True(r.Ok, r.Text);
        Assert.Equal(new[] { "DeskGuestCore" }, armer.Armed);
        // The chained-audit intent precedes the arm; the module
        // itself never calls Stop on its own service.
        Assert.Equal("audit:service_restart_armed", order[0]);
        Assert.Equal("arm:DeskGuestCore", order[1]);
        Assert.DoesNotContain(svc.Calls, c => c.StartsWith("stop", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Restart_DeskGuestRunning_NoArmer_RefusesAndLeavesServiceUntouched()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Running";
        var module = new ServiceControlModule(svc, "restart", armer: null);
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Empty(svc.Calls);
        Assert.Equal("Running", svc.States["DeskGuestCore"]);
    }

    [Fact]
    public async Task Restart_DeskGuestRunning_ArmFailure_RefusesAuditedAndUntouched()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Running";
        var audits = new List<string>();
        var module = new ServiceControlModule(svc, "restart", new FakeArmer { Throw = true }, "DeskGuestCore",
            (kind, actor, detail) => audits.Add(kind));
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Empty(svc.Calls);
        Assert.Contains("service_restart_armed", audits);   // intent first
        Assert.Contains("service_restart_refused", audits); // refusal recorded
    }

    [Fact]
    public async Task Restart_DeskGuestStopped_StartsDirectly_TheRecoveryAct()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Stopped";
        var audits = new List<string>();
        // No armer at all: a stopped service needs no watchdog —
        // the caller survives a Start. This is the DeskGuest-ON recovery
        // the drill needed and the old code never reached.
        var module = new ServiceControlModule(svc, "restart", armer: null, auditSink:
            (kind, actor, detail) => audits.Add(kind));
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(), default);
        Assert.True(r.Ok, r.Text);
        Assert.Equal(new[] { "start:DeskGuestCore" }, svc.Calls);
        Assert.Contains("service_restart", audits);
    }

    [Fact]
    public async Task Restart_NonDeskGuest_StaysInline_AndReportsObservedStatus()
    {
        // F7-staleness repair (BLOCKH F7 REPAIR lane): BD-WIN-CORE-1
        // F7 closed a gate bypass — a restart stops the service
        // first, so service_restart on a NON-DeskGuest service now
        // requires the service_stop_non_deskguest gate approval, exactly
        // as service_stop always did. This test previously called
        // the module with a context holding no approval, so F7
        // correctly gated it before the inline path ran. The
        // PRODUCT behaviour is correct; only this setup was stale.
        // Repair: the context now legitimately carries the
        // approval — supplied the same way the BdWinCore1FixTests
        // F5/F7 controls supply gate approvals to direct module
        // calls (Ctx(gates: …)), mirroring production, where the
        // MCP choke point assembles ToolExecutionContext with the
        // owner's approved gate classes (CoreRuntime's gate-
        // approval path). The gate is not weakened and no product
        // code is special-cased; the test's purpose (a non-DeskGuest
        // restart stays inline and reports the observed status)
        // and its assertions below are unchanged.
        var svc = new FakeSvc(); svc.States["Spooler"] = "Running";
        var module = new ServiceControlModule(svc, "restart");
        var r = await module.ExecuteAsync(Args("""{"name":"Spooler"}"""),
            Ctx(gates: new HashSet<string> { "service_stop_non_deskguest" }), default);
        Assert.True(r.Ok, r.Text);
        Assert.Equal(new[] { "restart:Spooler" }, svc.Calls);
        Assert.Contains("status now Running", r.Text);
    }

    [Fact]
    public async Task Stop_DeskGuestService_StillRefused()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Running";
        var module = new ServiceControlModule(svc, "stop", new FakeArmer());
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Empty(svc.Calls);
    }

    // ---- (a) the watchdog state machine ------------------------

    private sealed class ScriptSvc : IServiceProvider
    {
        public bool Available => true;
        public string State = "Running";
        public int StartCalls, StopCalls;
        public Queue<bool> StartResults { get; } = new();
        public bool StopWorks = true;
        public IReadOnlyList<ServiceInfo> List() => new[] { new ServiceInfo("DeskGuestCore", "DeskGuestCore", State, "Automatic") };
        public ServiceInfo? Status(string name) => new(name, name, State, "Automatic");
        public void Start(string name) { StartCalls++; if ((StartResults.Count > 0 ? StartResults.Dequeue() : true)) State = "Running"; }
        public void Stop(string name) { StopCalls++; if (StopWorks) State = "Stopped"; }
        public void Restart(string name) { }
    }

    private sealed class FakeSink : IRestartOutcomeSink
    {
        public List<RestartOutcome> Outcomes { get; } = new();
        public void WriteOutcome(RestartOutcome outcome) => Outcomes.Add(outcome);
        public void Loud(string detail) { }
    }

    private sealed class TickingClock
    {
        private DateTimeOffset _t = T0;
        public DateTimeOffset Now() => _t += TimeSpan.FromSeconds(1);
    }

    private static RestartWatchdog Watchdog(ScriptSvc svc, FakeSink sink, TickingClock clock) => new(
        svc, sink, delay: (t, ct) => Task.CompletedTask, now: clock.Now)
    { GracePeriod = TimeSpan.Zero, PollInterval = TimeSpan.Zero };

    [Fact]
    public async Task Watchdog_CleanRestart_ReportsRestarted()
    {
        var svc = new ScriptSvc(); var sink = new FakeSink();
        var outcome = await Watchdog(svc, sink, new TickingClock()).RunAsync("DeskGuestCore", "C:\\Program Files\\DeskGuest\\DeskGuestCore.exe");
        Assert.Equal("restarted", outcome.State);
        Assert.Equal(1, outcome.StartAttempts);
        Assert.False(outcome.RollbackUsed);
        Assert.Single(sink.Outcomes);
    }

    [Fact]
    public async Task Watchdog_StartRetries_ThenSucceeds()
    {
        var svc = new ScriptSvc(); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(true);
        var outcome = await Watchdog(svc, new FakeSink(), new TickingClock()).RunAsync("DeskGuestCore", "C:\\Program Files\\DeskGuest\\DeskGuestCore.exe");
        Assert.Equal("restarted", outcome.State);
        Assert.Equal(3, outcome.StartAttempts);
    }

    [Fact]
    public async Task Watchdog_StartAlwaysFails_RollsBackToPreviousBinary()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "DeskGuestCore.exe");
        var prev = exe + ".prev12";
        await File.WriteAllTextAsync(exe, "new-binary");
        await File.WriteAllTextAsync(prev, "old-binary");
        await File.WriteAllTextAsync(prev + ".sha256", "88a7a16419fe6663dd2eb62912b2eb4c5a5d58fb7f024d0d94bf0548e3c35836");
        var svc = new ScriptSvc();
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        svc.StartResults.Enqueue(true); // the rolled-back binary starts
        var outcome = await Watchdog(svc, new FakeSink(), new TickingClock()).RunAsync("DeskGuestCore", exe);
        Assert.Equal("rolled_back", outcome.State);
        Assert.True(outcome.RollbackUsed);
        // The previous binary is in place and running; the failed
        // one is kept beside it, named, never deleted silently.
        Assert.Equal("old-binary", await File.ReadAllTextAsync(exe));
        var failed = Directory.EnumerateFiles(dir, "DeskGuestCore.exe.failed-*").Single();
        Assert.Equal("new-binary", await File.ReadAllTextAsync(failed));
    }

    [Fact]
    public async Task Watchdog_StartAlwaysFails_NoRollbackBinary_ReportsFailed()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "DeskGuestCore.exe");
        await File.WriteAllTextAsync(exe, "new-binary");
        var svc = new ScriptSvc();
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        var outcome = await Watchdog(svc, new FakeSink(), new TickingClock()).RunAsync("DeskGuestCore", exe);
        Assert.Equal("failed", outcome.State);
        Assert.False(outcome.RollbackUsed);
        Assert.Contains("DeskGuest-ON", outcome.Detail);
    }

    [Fact]
    public async Task Watchdog_ServiceWontStop_StartIsNeverAttempted()
    {
        var svc = new ScriptSvc { StopWorks = false };
        var outcome = await Watchdog(svc, new FakeSink(), new TickingClock()).RunAsync("DeskGuestCore", "C:\\Program Files\\DeskGuest\\DeskGuestCore.exe");
        Assert.Equal("failed_to_stop", outcome.State);
        Assert.Equal(0, svc.StartCalls);
        Assert.Equal("Running", svc.State); // left as found, not stranded
    }

    [Fact]
    public void WatchdogOutcomeSink_WritesTheFileTheNextStartConsumes()
    {
        var dir = TestUtil.TempDir();
        var sink = new FileRestartOutcomeSink(dir);
        sink.WriteOutcome(new RestartOutcome("DeskGuestCore", "restarted", 1, false, "ok", T0));
        var path = FileRestartOutcomeSink.OutcomePath(dir);
        Assert.True(File.Exists(path));
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal("restarted", doc.RootElement.GetProperty("State").GetString());
    }

    // ---- (b) tray popup mesh line -------------------------------

    [Fact]
    public void MeshLine_EveryStateRenders_AndUnknownIsHonest()
    {
        Assert.Contains("an AI session is live", MeshLineText.For("AI_DRIVING", null));
        Assert.Contains("being driven from Pixel 9", MeshLineText.For("HUMAN_MANUAL", "Pixel 9"));
        Assert.Contains("being driven from the phone", MeshLineText.For("HUMAN_MANUAL", null));
        Assert.Contains("a remote session is live", MeshLineText.For("HUMAN_SESSION", null));
        Assert.Contains("Idle", MeshLineText.For("IDLE", null));
        Assert.Equal(MeshLineText.Unavailable, MeshLineText.For("SOMETHING_ELSE", null));
        Assert.Equal(MeshLineText.Unavailable, MeshLineText.For(null, null));
    }

    [Fact]
    public void MeshLine_FromSnapshot_ParsesTheCoreFact_AndDegradesHonestly()
    {
        Assert.Contains("Idle", MeshLineText.FromSnapshotJson(
            """{"mesh":{"state":"IDLE","phone":null,"phoneWatching":false}}"""));
        Assert.Contains("being driven from Owner's phone", MeshLineText.FromSnapshotJson(
            """{"mesh":{"state":"HUMAN_MANUAL","phone":"Owner's phone","phoneWatching":true}}"""));
        // No mesh fact (an older Core), garbage, or nothing at all:
        // the unavailable line — never a fabricated state.
        Assert.Equal(MeshLineText.Unavailable, MeshLineText.FromSnapshotJson("""{"coreVersion":"0.4.9"}"""));
        Assert.Equal(MeshLineText.Unavailable, MeshLineText.FromSnapshotJson("not json"));
        Assert.Equal(MeshLineText.Unavailable, MeshLineText.FromSnapshotJson(null));
    }

    // ---- (f) the Rotate surface ---------------------------------

    private static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static EnterpriseService BreakGlassWorld(string dataDir)
    {
        var holders = new[]
        {
            new { holderId = "holder-a", secretSha256 = Sha256Hex("secret-a") },
            new { holderId = "holder-b", secretSha256 = Sha256Hex("secret-b") },
        };
        File.WriteAllText(Path.Combine(dataDir, "breakglass-holders.json"), JsonSerializer.Serialize(holders));
        return LoadBreakGlassWorld(dataDir);
    }

    /// <summary>Load a service over an existing data dir WITHOUT
    /// touching the holders file (the Core-restart shape).</summary>
    private static EnterpriseService LoadBreakGlassWorld(string dataDir) =>
        new(dataDir, new RosterService(new EnrollmentService()), () => T0);

    [Fact]
    public void Rotate_UseRequiresEveryHolderRotated_ThenNewSecretsWork()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        var grant = svc.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true, T0);
        Assert.NotNull(grant);
        Assert.True(svc.BreakGlass.RotationRequired);
        Assert.Equal(2, svc.BreakGlass.RotationPendingHolders.Count);

        // Rotating ONE holder through the surface leaves the
        // requirement standing, naming the other holder. (D38 fix
        // F2 shape: the actor IS the holder, proving possession
        // of the current secret.)
        var one = svc.RotateBreakGlassHolders("holder-a", new[] { ("holder-a", "secret-a", "secret-a2") });
        Assert.True(one.Ok, one.Detail);
        Assert.True(svc.BreakGlass.RotationRequired);
        Assert.Equal(new[] { "holder-b" }, svc.BreakGlass.RotationPendingHolders);
        Assert.Null(svc.BreakGlass.Use("co1", "holder-a", "secret-a2", "holder-b", "secret-b", "too soon", true, T0));

        var two = svc.RotateBreakGlassHolders("holder-b", new[] { ("holder-b", "secret-b", "secret-b2") });
        Assert.True(two.Ok, two.Detail);
        Assert.False(svc.BreakGlass.RotationRequired);
        // The retired pair is dead; the rotated pair works.
        Assert.Null(svc.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "old pair", true, T0));
        Assert.NotNull(svc.BreakGlass.Use("co1", "holder-a", "secret-a2", "holder-b", "secret-b2", "rotated pair", true, T0));
        // Every rotation is in the chained audit.
        Assert.Equal(2, svc.AuditLog.Entries.Count(e => e.Kind == "break_glass_rotate"));
    }

    [Fact]
    public void Rotate_UnknownHolder_RefusesTheWholeAct_NothingApplied()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        var r = svc.RotateBreakGlassHolders("holder-a", new[] { ("holder-a", "secret-a", "secret-a2"), ("typo-holder", "x", "y") });
        Assert.False(r.Ok);
        // holder-a was NOT rotated despite being named first:
        // the original pair still opens a drill.
        Assert.NotNull(svc.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true, T0));
    }

    [Fact]
    public void Rotate_PersistsAcrossServiceRestart()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        Assert.NotNull(svc.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true, T0));
        Assert.True(svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
        Assert.True(svc.RotateBreakGlassHolders("holder-b",
            new[] { ("holder-b", "secret-b", "secret-b2") }).Ok);
        // A fresh service over the same data dir (a Core restart)
        // honors the rotated secrets and refuses the retired ones.
        var fresh = LoadBreakGlassWorld(dir);
        Assert.Null(fresh.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "old", true, T0));
        Assert.NotNull(fresh.BreakGlass.Use("co1", "holder-a", "secret-a2", "holder-b", "secret-b2", "new", true, T0));
    }

    // ---- (e3) factor attempt throttling --------------------------

    private static (SecondFactorService Svc, byte[] Secret) EnrolledTotp(World w, string user)
    {
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var begin = svc.BeginTotpEnrollment("company-1", user);
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret)!;
        Assert.True(svc.ConfirmTotpEnrollment("company-1", user, Totp.At(secret, T0), T0));
        return (svc, secret);
    }

    private static string WrongCode(byte[] secret, DateTimeOffset at)
    {
        var real = Totp.At(secret, at);
        return real[..5] + (real[5] == '0' ? '1' : '0'); // deterministically not the real code
    }

    [Fact]
    public void Throttle_FiveFailures_LockOutEvenTheRightCode_ThenRecover()
    {
        var w = Setup();
        var (svc, secret) = EnrolledTotp(w, "ctrl");
        var t = T0.AddSeconds(30);
        DateTimeOffset lockedAt = default;
        for (var i = 0; i < 5; i++)
        {
            Assert.False(svc.VerifyTotp("company-1", "ctrl", WrongCode(secret, t), t));
            lockedAt = t;
            t = t.AddSeconds(30);
        }
        Assert.Contains(svc.Events, e => e.Kind == "factor_throttled");
        // During lockout the CORRECT code refuses too — the
        // material is never even checked.
        Assert.False(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, t), t));
        // After the lockout window the factor works again.
        var after = lockedAt.AddSeconds(SecondFactorService.LockoutSeconds + 31);
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, after), after));
    }

    [Fact]
    public void Throttle_CounterIsSharedAcrossVerifyPaths()
    {
        var w = Setup();
        var (svc, secret) = EnrolledTotp(w, "peer");
        var t = T0.AddSeconds(30);
        for (var i = 0; i < 3; i++)
        {
            Assert.False(svc.VerifyTotp("company-1", "peer", WrongCode(secret, t), t));
            t = t.AddSeconds(30);
        }
        // Two more failures through the re-enrollment current-code
        // check reach the same counter: 3 + 2 = the lockout.
        for (var i = 0; i < 2; i++)
        {
            Assert.Null(svc.BeginTotpEnrollment("company-1", "peer", WrongCode(secret, t), t));
            t = t.AddSeconds(30);
        }
        Assert.False(svc.VerifyTotp("company-1", "peer", Totp.At(secret, t), t)); // locked
    }

    [Fact]
    public void Throttle_ImportMergesMax_NeverClearsALiveLockout()
    {
        var w = Setup();
        var (svcA, secretA) = EnrolledTotp(w, "host");
        var t = T0.AddSeconds(30);
        for (var i = 0; i < 5; i++)
        {
            Assert.False(svcA.VerifyTotp("company-1", "host", WrongCode(secretA, t), t));
            t = t.AddSeconds(30);
        }
        // A fresh service importing the locked state is locked.
        var svcB = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        svcB.ImportJson(svcA.ExportJson());
        Assert.False(svcB.VerifyTotp("company-1", "host", Totp.At(secretA, t), t));
        // Importing a CLEAN export (no throttle state at all) over
        // the locked service does not clear the lockout either.
        var (svcC, secretC) = EnrolledTotp(w, "host");
        svcB.ImportJson(svcC.ExportJson());
        var t2 = t.AddSeconds(30);
        Assert.False(svcB.VerifyTotp("company-1", "host", Totp.At(secretC, t2), t2));
    }

    // ---- (e4) passkey challenge binding --------------------------

    private sealed class PasskeyFixture
    {
        public required SecondFactorService Svc { get; init; }
        public required ECDsa Key { get; init; }
        public required string CredId { get; init; }

        public (byte[] AuthData, string ClientJson, byte[] Sig) Make(uint counter, string challenge, bool corruptSig = false)
        {
            const string rpId = "deskguest.local";
            var clientJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge +
                "\",\"origin\":\"https://deskguest.local\",\"crossOrigin\":false}";
            var authData = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authData, 0);
            authData[32] = 0x01;
            BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33, 4), counter);
            var signed = authData.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(clientJson))).ToArray();
            var sig = Key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSig) sig[^1] ^= 0xFF;
            return (authData, clientJson, sig);
        }
    }

    private static PasskeyFixture Passkeys(World w, params string[] users)
    {
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(false);
        var credId = Convert.ToBase64String(new byte[] { 4, 2, 0 });
        foreach (var user in users)
            Assert.True(svc.RegisterPasskey("company-1", user, credId,
                Convert.ToBase64String(p.Q.X!), Convert.ToBase64String(p.Q.Y!)));
        return new PasskeyFixture { Svc = svc, Key = ecdsa, CredId = credId };
    }

    [Fact]
    public void Challenge_NeverIssued_Refused()
    {
        var w = Setup();
        var f = Passkeys(w, "ctrl");
        var a = f.Make(1, "attacker-chosen-challenge");
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            a.AuthData, a.ClientJson, a.Sig, "attacker-chosen-challenge", "deskguest.local", T0));
    }

    [Fact]
    public void Challenge_FailedAttemptBurnsIt_SuccessConsumesIt()
    {
        var w = Setup();
        var f = Passkeys(w, "ctrl");
        var c1 = f.Svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        var bad = f.Make(1, c1, corruptSig: true);
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            bad.AuthData, bad.ClientJson, bad.Sig, c1, "deskguest.local", T0));
        // The burned challenge does not work even for the genuine
        // assertion — a failed ceremony leaves nothing reusable.
        var good = f.Make(1, c1);
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            good.AuthData, good.ClientJson, good.Sig, c1, "deskguest.local", T0));
        // A fresh ceremony works — and its challenge is single-use.
        var c2 = f.Svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        var good2 = f.Make(1, c2);
        Assert.True(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            good2.AuthData, good2.ClientJson, good2.Sig, c2, "deskguest.local", T0));
        var replay = f.Make(2, c2);
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            replay.AuthData, replay.ClientJson, replay.Sig, c2, "deskguest.local", T0));
    }

    [Fact]
    public void Challenge_Expired_AndCrossUser_Refused()
    {
        var w = Setup();
        var f = Passkeys(w, "ctrl", "peer");
        var c = f.Svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        var a = f.Make(1, c);
        // Expired: issued at T0, presented after the 300 s window.
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            a.AuthData, a.ClientJson, a.Sig, c, "deskguest.local", T0.AddSeconds(SecondFactorService.ChallengeSeconds + 1)));
        // Cross-user: ctrl's challenge is not peer's ceremony.
        var c2 = f.Svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        var a2 = f.Make(1, c2);
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "peer", f.CredId,
            a2.AuthData, a2.ClientJson, a2.Sig, c2, "deskguest.local", T0));
        // The caller's expected challenge must BE the issued one.
        var a3 = f.Make(1, c2);
        Assert.False(f.Svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            a3.AuthData, a3.ClientJson, a3.Sig, "some-other-ceremony", "deskguest.local", T0));
    }

    // ---- (e2) tunnel destination allowlist -----------------------

    [Fact]
    public void Allowlist_ConfiguredSet_EnforcedAtOpen_CaseInsensitiveHost()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster,
            allowedTargets: new HashSet<string> { "192.168.1.10:8080", "printer.local:9100" });
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.10", 8080, 18080));
        Assert.Null(tunnels.Open(id, "host", "192.168.1.11", 80, 18081));       // unlisted host
        Assert.Null(tunnels.Open(id, "host", "192.168.1.10", 22, 18082));       // unlisted port
        Assert.NotNull(tunnels.Open(id, "host", "PRINTER.LOCAL", 9100, 18083)); // host case folds
    }

    [Fact]
    public void Allowlist_EmptySet_RefusesEverything_NullSet_KeepsBlockGPosture()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var empty = new SessionTunnelService(w.Sessions, w.Roster, allowedTargets: new HashSet<string>());
        Assert.Null(empty.Open(id, "host", "192.168.1.10", 8080, 18080));
        var unset = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(unset.Open(id, "host", "192.168.1.10", 8080, 18080));
    }

    [Fact]
    public void Allowlist_ImportRestoresUnlistedTunnelsClosed()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var source = new SessionTunnelService(w.Sessions, w.Roster);
        var open = source.Open(id, "host", "10.0.0.5", 22, 18080);
        Assert.NotNull(open);
        var json = source.ExportJson();
        var guarded = new SessionTunnelService(w.Sessions, w.Roster,
            allowedTargets: new HashSet<string> { "192.168.1.10:8080" });
        Assert.Equal(1, guarded.ImportJson(json));
        Assert.Equal("closed", guarded.GetTunnel(open!.Id)!.State);
        var listed = new SessionTunnelService(w.Sessions, w.Roster,
            allowedTargets: new HashSet<string> { "10.0.0.5:22" });
        Assert.Equal(1, listed.ImportJson(json));
        Assert.Equal("open", listed.GetTunnel(open.Id)!.State);
    }

    // ---- (e5) per-act floor-grant re-check -----------------------

    [Fact]
    public void FloorGrant_RevokedMidSession_NextSurfaceActRefuses_ClearingAndHostSideSurvive()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Sessions.SetBlanked(id, true, "ctrl")); // grant held: works
        Assert.True(w.Sessions.SetInputBlocked(id, true, "ctrl"));
        // The grant is revoked mid-session (admin act).
        Assert.True(w.Roster.RemoveGrant("company-1", "ug-1", "dg-1", "admin"));
        // Clearing is the escape direction — it never re-reads
        // the grant (the first Block H draft gated it through the
        // same helper as enabling; this test caught the trap: a
        // revoked driver could not unblank their own blank).
        Assert.True(w.Sessions.SetBlanked(id, false, "ctrl"));
        Assert.True(w.Sessions.SetInputBlocked(id, false, "ctrl"));
        // Every ENABLING act re-reads the grant and now refuses.
        Assert.False(w.Sessions.SetBlanked(id, true, "ctrl"));
        Assert.False(w.Sessions.SetInputBlocked(id, true, "ctrl"));
        Assert.Null(w.Sessions.StartCall(id, "ctrl", "video"));
        // The watermark is the deliberate exception: ENABLING it
        // only ADDS accountability, and the model has always let
        // the session's initiator enable it (the sensitive
        // direction — clearing — is host-side only, grant or no
        // grant). AF3 governs the driving surfaces and calls.
        Assert.True(w.Sessions.SetWatermarked(id, true, "ctrl"));
        // The host side (the person at the device) is exempt —
        // their surface control never depended on a roster grant.
        Assert.True(w.Sessions.SetBlanked(id, true, "host"));
    }

    // ---- (e1) policy-change teardown sweep ------------------------

    [Fact]
    public void TeardownSweep_EndsLiveEffectsInScope_LeavesOtherScopesAlone()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Sessions.SetBlanked(id, true, "ctrl"));
        Assert.True(w.Sessions.SetWatermarked(id, true, "ctrl"));
        var call = w.Sessions.StartCall(id, "ctrl", "video");
        Assert.NotNull(call);
        Assert.True(w.Sessions.AnswerCall(call!.Id, "host"));
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        var tunnel = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(tunnel);
        var transfers = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = transfers.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "logs.zip", 10);
        Assert.NotNull(job);

        // A sweep aimed at ANOTHER scope tears nothing down here.
        Assert.Equal(0, w.Sessions.SweepPolicyTeardown("personal-1", _ => true));
        Assert.True(w.Sessions.GetSession(id)!.Blanked);

        // The real sweep: call ended, blank + watermark cleared,
        // tunnel closed, job cancelled — all recorded as policy.
        var torn = w.Sessions.SweepPolicyTeardown("company-1", _ => true);
        Assert.Equal(3, torn); // call + blank + watermark
        var after = w.Sessions.GetSession(id)!;
        Assert.False(after.Blanked);
        Assert.False(after.Watermarked);
        Assert.Null(w.Sessions.GetLiveCall(id));
        Assert.Equal(1, tunnels.SweepPolicyTeardown("company-1", _ => true));
        Assert.Equal("closed", tunnels.GetTunnel(tunnel!.Id)!.State);
        Assert.Equal(1, transfers.SweepPolicyTeardown("company-1", _ => true));
        Assert.Equal("cancelled", transfers.GetJob(job!.Id)!.State);
    }

    [Fact]
    public void TeardownSweep_IsSelectivePerFeature()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Sessions.SetBlanked(id, true, "ctrl"));
        Assert.True(w.Sessions.SetWatermarked(id, true, "ctrl"));
        var torn = w.Sessions.SweepPolicyTeardown("company-1",
            key => key == PolicyFeatures.Watermark);
        Assert.Equal(1, torn);
        var after = w.Sessions.GetSession(id)!;
        Assert.True(after.Blanked);        // not the disabled feature: untouched
        Assert.False(after.Watermarked);
    }

    // ---- (e6) G-service MCP exposure ------------------------------

    private sealed class FakeWakeSender : IWakeSender
    {
        public int Count;
        public void Send(byte[] packet, string broadcastAddress, int port) => Count++;
    }

    [Fact]
    public async Task Exposure_WakeSend_ResolvesTheRosterAiMember_AndSends()
    {
        var w = Setup();
        var sender = new FakeWakeSender();
        var wake = new WakeService(w.Roster, w.Enrollments, sender);
        Assert.True(wake.RegisterTarget(w.DeviceId, "00:11:22:33:44:55", "255.255.255.255", "admin"));
        var module = new WakeSendModule(wake, w.Roster);
        // The fixture's AI user is enrolled as "Agent One" — the
        // pairing named "Agent One" acts AS that roster member.
        var ok = await module.ExecuteAsync(
            Args($$"""{"scopeId":"company-1","deviceId":"{{w.DeviceId}}"}"""), Ctx("Agent One"), default);
        Assert.True(ok.Ok, ok.Text);
        Assert.Equal(1, sender.Count);
        // A pairing whose name matches NO roster AI member is
        // refused — a pairing alone is not a membership (D9).
        var refused = await module.ExecuteAsync(
            Args($$"""{"scopeId":"company-1","deviceId":"{{w.DeviceId}}"}"""), Ctx("test-agent"), default);
        Assert.False(refused.Ok);
        Assert.Equal("no_roster_member", refused.ErrorClass);
        Assert.Equal(1, sender.Count);
    }

    [Fact]
    public async Task Exposure_TransferLifecycle_ThroughTheModules()
    {
        var w = Setup();
        var transfers = new StandaloneTransferService(w.Roster, w.Enrollments);
        var start = new TransferStartModule(transfers, w.Roster);
        var r = await start.ExecuteAsync(
            Args($$"""{"scopeId":"company-1","deviceId":"{{w.DeviceId}}","direction":"to_host","name":"logs.zip","sizeBytes":1024}"""),
            Ctx("Agent One"), default);
        Assert.True(r.Ok, r.Text);
        var job = Assert.Single(transfers.ListJobs("company-1"));
        var list = new TransferListModule(transfers, w.Roster);
        var listed = await list.ExecuteAsync(Args("""{"scopeId":"company-1"}"""), Ctx("Agent One"), default);
        Assert.True(listed.Ok, listed.Text);
        Assert.Contains(job.Id, listed.Text);
        var cancel = new TransferCancelModule(transfers, w.Roster);
        var cancelled = await cancel.ExecuteAsync(
            Args($$"""{"jobId":"{{job.Id}}"}"""), Ctx("Agent One"), default);
        Assert.True(cancelled.Ok, cancelled.Text);
        Assert.Equal("cancelled", transfers.GetJob(job.Id)!.State);
    }

    [Fact]
    public async Task Exposure_FactorStatus_CountsOnly_AndTunnelListIsScoped()
    {
        var w = Setup();
        var (svc, _) = EnrolledTotp(w, "ctrl");
        var factors = new FactorStatusModule(svc);
        var r = await factors.ExecuteAsync(Args("{}"), Ctx("Agent One"), default);
        Assert.True(r.Ok, r.Text);
        Assert.Contains("active TOTP enrollments: 1", r.Text);
        Assert.DoesNotContain("ctrl", r.Text); // counts only — never who

        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.10", 8080, 18080));
        var module = new TunnelListModule(tunnels, w.Sessions, w.Roster);
        var inScope = await module.ExecuteAsync(Args("""{"scopeId":"company-1"}"""), Ctx("Agent One"), default);
        Assert.Contains("192.168.1.10:8080", inScope.Text);
        // D38 fix F3: tunnel_list now requires roster membership
        // in the named scope — "Agent One" is not a member of
        // personal-1, so the other scope refuses instead of
        // answering (before the fix it answered for ANY pairing).
        var otherScope = await module.ExecuteAsync(Args("""{"scopeId":"personal-1"}"""), Ctx("Agent One"), default);
        Assert.False(otherScope.Ok);
        Assert.Contains("no live AI roster user", otherScope.Text);
    }
}

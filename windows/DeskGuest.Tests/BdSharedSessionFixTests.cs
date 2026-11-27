using System.Net;
using System.Text;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Presence;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.State;
using DeskGuest.Shared.Streaming;
using DeskGuest.Shared.Terminal;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>BD-SHARED-SESSION (packet 38c41efb) D38 fix lane —
/// one regression test per CONFIRMED finding F1–F12, plus
/// destruction cases. Dispositions in
/// builds/completion-logs/log-bd-sharedsession-fix.md.</summary>
public class BdSharedSessionFixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup(Func<RosterService, EnrollmentService, SessionService>? sessionFactory = null)
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World
        {
            Enrollments = enrollments, Roster = roster,
            Sessions = sessionFactory?.Invoke(roster, enrollments) ?? new SessionService(roster, enrollments),
            DeviceId = device!.DeviceId,
        };
    }

    private static string ActiveSession(World w, string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    private sealed class FakeSink : ITerminalSink
    {
        public List<string> Written { get; } = new();
        public void Start(string terminalId) { }
        public void Write(string terminalId, string text) => Written.Add(text);
        public void Close(string terminalId) { }
    }

    // ---- F1: IPC consent provenance ---------------------------------

    [Fact]
    public void F1_ConsentKinds_RefusedWhileAgentSessionLive_WithoutPhysicalProvenance()
    {
        foreach (var kind in new[] { IpcKinds.GateApproval, IpcKinds.PairingCreateCode,
                     IpcKinds.SessionAction, IpcKinds.UserStopClear, IpcKinds.VaultSet })
        {
            var bare = new IpcMessage(kind, null, null, "{}", null, null, null, null, null, null);
            Assert.True(IpcConsent.IsConsentKind(kind));
            Assert.False(IpcConsent.CanHonor(bare, agentSessionLive: true), kind);
            var injected = bare with { InputProvenance = IpcProvenance.AgentInjected };
            Assert.False(IpcConsent.CanHonor(injected, agentSessionLive: true), kind);
            var selfReported = bare with { AgentSessionLive = true };
            Assert.False(IpcConsent.CanHonor(selfReported, agentSessionLive: false), kind);
            var physical = bare with { InputProvenance = IpcProvenance.PhysicalHuman };
            Assert.True(IpcConsent.CanHonor(physical, agentSessionLive: true), kind);
            // W10 / V2-C4: provenance is required in EVERY state —
            // the pre-fix pin ("no live session: the authenticated
            // channel is the consent") was the C4 crack: a consent
            // act applied from the bare IPC message alone.
            Assert.False(IpcConsent.CanHonor(bare, agentSessionLive: false), kind);
            Assert.True(IpcConsent.CanHonor(physical, agentSessionLive: false), kind);
        }
        var heartbeat = new IpcMessage(IpcKinds.Heartbeat, null, null, null, null, null, null, null, null, null);
        Assert.True(IpcConsent.CanHonor(heartbeat, agentSessionLive: true)); // non-consent kinds unaffected
    }

    // ---- F2: terminal fresh gating ----------------------------------

    [Fact]
    public void F2_Terminal_SuspendedFloorHolder_CannotWrite()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: sink);
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var (ok, _, term) = terminals.Open(id, "ctrl", T0);
        Assert.True(ok);
        Assert.True(terminals.Write(term!.Id, "ctrl", "echo hi").Ok);
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", true));
        Assert.False(terminals.Write(term.Id, "ctrl", "echo pwned").Ok);
        Assert.Single(sink.Written);
    }

    [Fact]
    public void F2_Terminal_GrantRevokedMidSession_CannotWrite()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: sink);
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var (ok, _, term) = terminals.Open(id, "ctrl", T0);
        Assert.True(ok);
        Assert.True(w.Roster.RemoveGrant("company-1", "ug-1", "dg-1", "admin"));
        Assert.False(terminals.Write(term!.Id, "ctrl", "echo pwned").Ok);
        Assert.Empty(sink.Written);
    }

    [Fact]
    public void F2_Terminal_PolicyGateRefusesOpen_AndSweepClosesOpenTerminals()
    {
        var w = Setup();
        var allowed = true;
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: new FakeSink(),
            featureGate: (_, _) => new PolicyVerdict(allowed, allowed ? "ok" : "disabled"));
        var id = ActiveSession(w);
        var (ok, _, term) = terminals.Open(id, "host", T0);
        Assert.True(ok);
        allowed = false;
        Assert.Equal(1, terminals.SweepPolicyTeardown("company-1", k => k == TerminalService.FeatureKey));
        Assert.Null(terminals.OpenTerminalFor(id));
        var id2 = ActiveSession(w);
        Assert.False(terminals.Open(id2, "host", T0).Ok);
    }

    // ---- F3: pivot blocklist -----------------------------------------

    [Theory]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("0:0:0:0:0:0:0:1")]
    [InlineData("::1")]
    [InlineData("2130706433")]
    [InlineData("0x7f000001")]
    [InlineData("foo.localhost")]
    [InlineData("localhost.")]
    [InlineData("fe90::1")]
    [InlineData("fe80::1")]
    [InlineData("169.254.1.1")]
    [InlineData("127.5.6.7")]
    public void F3_PivotTargets_AllRefused(string host)
        => Assert.True(SessionTunnelService.IsPivotTarget(host), host);

    [Theory]
    [InlineData("192.168.1.20")]
    [InlineData("10.0.0.5")]
    [InlineData("printer.local")]
    [InlineData("2001:db8::5")]
    public void F3_LegitimateLanTargets_NotPivot(string host)
        => Assert.False(SessionTunnelService.IsPivotTarget(host), host);

    [Fact]
    public void F3_ResolvedAddresses_ReCheckedAtConnectTime()
    {
        Assert.True(SessionTunnelService.IsResolvedPivotTarget(
            new[] { IPAddress.Parse("192.168.1.20"), IPAddress.Parse("127.0.0.1") }));
        Assert.True(SessionTunnelService.IsResolvedPivotTarget(
            new[] { IPAddress.Parse("::ffff:127.0.0.1") }));
        Assert.True(SessionTunnelService.IsResolvedPivotTarget(Array.Empty<IPAddress>())); // fail closed
        Assert.False(SessionTunnelService.IsResolvedPivotTarget(new[] { IPAddress.Parse("192.168.1.20") }));
        Assert.False(SessionTunnelService.IsValidTargetHost("0.0.0.0"));
        Assert.False(SessionTunnelService.IsValidTargetHost("::"));
    }

    // ---- F4: device-console STOP / clear ------------------------------

    [Fact]
    public void F4_DeviceConsole_StopsSession_AndClearsSurfaces_WithoutRosterId()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Sessions.SetBlanked(id, true, "ctrl"));
        Assert.True(w.Sessions.SetInputBlocked(id, true, "ctrl"));
        Assert.True(w.Sessions.ClearSurfacesFromDevice(id));
        var after = w.Sessions.GetSession(id)!;
        Assert.False(after.Blanked); Assert.False(after.InputBlocked);
        Assert.True(w.Sessions.StopSessionFromDevice(id));
        Assert.Equal("ended", w.Sessions.GetSession(id)!.State);
        Assert.Contains(w.Sessions.ListEvents(id),
            e => e.Kind == "stopped" && e.ActorUserId == StandaloneTransferService.DeviceConsoleActor);
        Assert.False(w.Sessions.StopSessionFromDevice(id)); // already ended
        Assert.False(w.Sessions.StopSessionFromDevice("nope"));
    }

    // ---- F5: AI leash on blank / input block --------------------------

    [Fact]
    public void F5_AiFloorHolder_CannotBlankOrBlockInput_ByDefault()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "controller", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ai-1", "host"));
        Assert.False(w.Sessions.SetBlanked(id, true, "ai-1"));
        Assert.False(w.Sessions.SetInputBlocked(id, true, "ai-1"));
        var s = w.Sessions.GetSession(id)!;
        Assert.False(s.Blanked); Assert.False(s.InputBlocked);
    }

    [Fact]
    public void F5_AiWithNamedCapability_MayBlank_ButClearingAlwaysOpenToHolder()
    {
        var w = Setup((roster, enrollments) => new SessionService(roster, enrollments,
            aiSurfaceCapability: (_, user) => user == "ai-1"));
        var id = ActiveSession(w);
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "controller", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ai-1", "host"));
        Assert.True(w.Sessions.SetBlanked(id, true, "ai-1"));
        Assert.True(w.Sessions.SetBlanked(id, false, "ai-1")); // clearing is never capability-gated
    }

    // ---- F6: data-flow ledger ------------------------------------------

    [Fact]
    public void F6_CorruptLedger_IsQuarantined_NotOverwritten()
    {
        var dir = Path.Combine(Path.GetTempPath(), "deskguest-bdss-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "flows.json");
        File.WriteAllText(path, "{ this is not json ]");
        var ledger = new DataFlowLedger(path);
        Assert.Empty(ledger.Records());
        Assert.False(File.Exists(path)); // moved aside, not silently kept for overwrite
        Assert.Single(Directory.GetFiles(dir, "flows.json.corrupt-*"));
        ledger.BeginSession("s1", "p1", "agent", T0); // a fresh store can still be written
        Assert.True(File.Exists(path));
        Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void F6_NullPairingMerge_Refused()
    {
        var ledger = new DataFlowLedger();
        ledger.NoteCall("s1", "agent", "p1", "agent", "tap", "changed", 1, 1, null, T0);
        ledger.NoteCall("s1", "agent", null, "agent", "tap", "changed", 5, 5, null, T0); // refused merge
        ledger.NoteCall("s2", "agent", null, "agent", "tap", "changed", 1, 1, null, T0);
        ledger.NoteCall("s2", "agent", "p9", "agent", "tap", "changed", 5, 5, null, T0); // refused merge
        var records = ledger.Records();
        Assert.Equal(1, records.Single(r => r.SessionId == "s1").Tools.Single().Calls);
        Assert.Equal(1, records.Single(r => r.SessionId == "s2").Tools.Single().Calls);
    }

    // ---- F7: terminal output persistence + pause ------------------------

    [Fact]
    public void F7_TerminalOutput_RingCapped_AndSurvivesExportImport()
    {
        var w = Setup();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: new FakeSink());
        var id = ActiveSession(w);
        var (ok, _, term) = terminals.Open(id, "host", T0);
        Assert.True(ok);
        for (var i = 0; i < TerminalService.MaxOutputLines + 50; i++)
            Assert.True(terminals.AppendOutput(term!.Id, $"line {i}"));
        var output = terminals.Output(term!.Id);
        Assert.Equal(TerminalService.MaxOutputLines, output.Count);
        Assert.Equal("line 50", output[0]);
        var restored = new TerminalService(w.Sessions, w.Roster, sink: new FakeSink());
        Assert.Equal(1, restored.ImportJson(terminals.ExportJson()));
        Assert.Equal(output, restored.Output(term.Id));
        Assert.Null(restored.OpenTerminalFor(id)); // restored closed: output for replay, no live shell
    }

    [Fact]
    public void F7_PausedSession_WriteRefused_ButTerminalSurvives()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: sink);
        var id = ActiveSession(w);
        var (ok, _, term) = terminals.Open(id, "host", T0);
        Assert.True(ok);
        Assert.True(w.Sessions.PauseSession(id, "ctrl"));
        Assert.False(terminals.Write(term!.Id, "host", "echo hi").Ok);
        Assert.NotNull(terminals.OpenTerminalFor(id)); // kept open through pause
        Assert.Empty(sink.Written);
    }

    // ---- F8: presence ---------------------------------------------------

    [Fact]
    public void F8_Presence_CarriesSurfacesAndEpoch_NewBlockResurfaces()
    {
        var lines = PresenceDirective.IndicatorLines(new PresenceDirective.Inputs(
            SessionActive: true, StopInForce: false, Recording: true, Blanked: true,
            InputBlocked: true, DriverIsAi: true));
        Assert.Contains("recording", lines);
        Assert.Contains("screen_blanked", lines);
        Assert.Contains("input_blocked", lines);
        Assert.Contains("ai_driving", lines);

        var m = new PresenceStateMachine();
        m.StopEngaged();
        Assert.Equal(1, m.StopEpoch);
        Assert.True(m.Dismiss());
        Assert.Equal(PresenceMode.BlockedDismissed, m.Mode);
        // A reconnect directive carrying a NEWER epoch re-surfaces.
        m.ApplyDirective(new PresenceDirective.Inputs(false, true, StopEpoch: 2));
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        Assert.Equal(2, m.StopEpoch);
    }

    [Fact]
    public void F8_Dismiss_RefusedWhileSessionActive_MinimalIndicatorStays()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted("Agent");
        m.StopEngaged();
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        Assert.False(m.Dismiss()); // a live session's presence cannot be dismissed away
        Assert.True(m.MinimalIndicatorVisible);
    }

    // ---- F9: connection doctor -------------------------------------------

    [Theory]
    [InlineData("0.1.2.3")]
    [InlineData("192.0.2.9")]
    [InlineData("198.18.0.7")]
    [InlineData("198.19.255.1")]
    [InlineData("224.0.0.9")]
    [InlineData("250.1.1.1")]
    public void F9_SpecialRanges_AreReserved_NotPublic(string addr)
        => Assert.Equal(AddressClass.Reserved, ConnectionDoctor.ClassifyAddress(addr));

    [Fact]
    public void F9_GlobalIpv6_DoesNotMakeIpv4BehindNat_PublicDirect()
    {
        var nat = ConnectionDoctor.ClassifyNat(new[] { "192.168.1.50", "2601:abcd::1" });
        Assert.Equal(NatClass.BehindNat, nat);
        Assert.Equal(NatClass.PublicDirect, ConnectionDoctor.ClassifyNatV6(new[] { "192.168.1.50", "2601:abcd::1" }));
        // A v6-only device still classifies direct from its v6 facts.
        Assert.Equal(NatClass.PublicDirect, ConnectionDoctor.ClassifyNat(new[] { "2601:abcd::1" }));
    }

    [Fact]
    public void F9_PeerTailnetAddress_NotTreatedAsIspCgnat()
    {
        var facts = new DoctorFacts(new[] { "192.168.1.50" }, Array.Empty<RungSnapshot>(),
            PeerAddress: "100.119.105.54", TailnetAddresses: new[] { "100.119.105.54" });
        var report = ConnectionDoctor.Diagnose(facts);
        Assert.Equal(NatClass.BehindNat, report.PeerNat);
        Assert.Equal(NatClass.Unknown, report.LocalNatV6);
    }

    // ---- F10: stale authority on read paths --------------------------------

    [Fact]
    public void F10_EventDelivery_RequiresObserveNow()
    {
        var store = new EventSubscriptionStore();
        Assert.True(store.Subscribe("p1", new[] { AgentEventKinds.ForegroundApp }).Ok);
        var evt = new AgentEvent(T0, AgentEventKinds.ForegroundApp, "host fact", null);
        Assert.True(AgentEventBus.ShouldDeliver(store, "p1", evt, _ => true));
        Assert.False(AgentEventBus.ShouldDeliver(store, "p1", evt, _ => false)); // Observe removed after subscribing
        var bus = new AgentEventBus(store, _ => false);
        var delivered = 0;
        bus.Attach("p1", _ => delivered++);
        bus.Publish(AgentEventKinds.ForegroundApp, "host fact", null);
        Assert.Equal(0, delivered);
    }

    [Fact]
    public void F10_CapabilityReport_StopInForce_MakesEverythingUnavailable()
    {
        var pairing = new Pairing("p1", "agent",
            new HashSet<string> { Scopes.Observe, Scopes.Drive }, DateTimeOffset.UtcNow, null, null, false);
        var registry = new ToolRegistry();
        registry.Register(new StubModule(new ToolDescriptor("tap", "tap", Scopes.Drive, SessionRequirement.Agent, RiskTier.Medium)));
        registry.Register(new StubModule(new ToolDescriptor("gated", "gated", Scopes.Drive, SessionRequirement.Agent, RiskTier.High, GateClass: "power")));
        var stopped = new SessionFacts(true, true, true, false, "agent", T0, StopInForce: true, false);
        var report = registry.CapabilityReport(pairing, stopped, EndpointState.LogonUnlocked);
        Assert.All(report, line => Assert.False(line.Available));
        Assert.All(report, line => Assert.Contains("STOP", line.WhyNot!));
        var live = new SessionFacts(true, true, true, false, "agent", T0, StopInForce: false, false);
        var liveReport = registry.CapabilityReport(pairing, live, EndpointState.LogonUnlocked);
        Assert.True(liveReport.Single(l => l.Tool == "tap").Available);
        var gated = liveReport.Single(l => l.Tool == "gated");
        Assert.False(gated.Available);
        Assert.Contains("gate", gated.WhyNot!, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class StubModule(ToolDescriptor descriptor) : IToolModule
    {
        public ToolDescriptor Descriptor => descriptor;
        public Task<ToolResult> ExecuteAsync(System.Text.Json.JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
            => Task.FromResult(ToolResult.Success("ok"));
    }

    // ---- F11: lane supervisor -----------------------------------------------

    [Fact]
    public void F11_BindEmittedOnce_UntilOutcomeReported()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock);
        Assert.Single(sup.Tick(LaneKind.Tailscale));
        Assert.Equal(LanePhase.Binding, sup.Status(LaneKind.Tailscale).Phase);
        Assert.Empty(sup.Tick(LaneKind.Tailscale));
        Assert.Empty(sup.Tick(LaneKind.Tailscale));
        sup.ReportBindResult(LaneKind.Tailscale, true);
        Assert.Equal(LanePhase.Bound, sup.Status(LaneKind.Tailscale).Phase);
    }

    [Fact]
    public void F11_Rebind_LeavesBound_UntilOutcomeReported()
    {
        var clock = new FakeClock();
        var current = "100.119.105.54";
        var probe = new FakeProbe { Handler = _ => current };
        var sup = new LaneSupervisor(probe, clock);
        sup.Tick(LaneKind.Tailscale);
        sup.ReportBindResult(LaneKind.Tailscale, true);
        current = "100.119.105.99";
        var actions = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(actions, a => a.Action == "unbind");
        Assert.Contains(actions, a => a.Action == "rebind" && a.Address == "100.119.105.99");
        Assert.Equal(LanePhase.Binding, sup.Status(LaneKind.Tailscale).Phase); // NOT bound on an unproven address
        sup.ReportBindResult(LaneKind.Tailscale, false);
        Assert.Equal(LanePhase.BindFailed, sup.Status(LaneKind.Tailscale).Phase);
    }

    [Fact]
    public void F11_JitteredBackoff_NeverExceedsCap()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock, jitter: () => 1.0);
        sup.Tick(LaneKind.Tailscale);
        sup.ReportBindResult(LaneKind.Tailscale, false);
        for (var i = 0; i < 6; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(3));
            sup.Tick(LaneKind.Tailscale);
            sup.ReportBindResult(LaneKind.Tailscale, false);
        }
        var status = sup.Status(LaneKind.Tailscale);
        Assert.True(status.NextRetryUtc - clock.UtcNow <= LaneSupervisor.MaxRetry,
            $"backoff {(status.NextRetryUtc - clock.UtcNow)} exceeded the 60 s cap");
    }

    // ---- F12: wire boundaries --------------------------------------------------

    [Fact]
    public async Task F12_PreAuthFrameCap_RefusesOversizedFrame()
    {
        using var ms = new MemoryStream();
        var payload = Encoding.UTF8.GetBytes(new string('x', IpcFraming.PreAuthMaxFrameBytes + 1));
        ms.Write(BitConverter.GetBytes(payload.Length));
        ms.Write(payload);
        ms.Position = 0;
        Assert.Null(await IpcFraming.ReadAsync(ms, default, IpcFraming.PreAuthMaxFrameBytes));
        ms.Position = 0;
        Assert.NotNull(await IpcFraming.ReadAsync(ms, default)); // same frame fine after auth (full cap)
    }

    [Fact]
    public void F12_DamageRectOutsideFrame_RefusesParse()
    {
        var au = BuildKeyframeAu();
        var header = new StreamProtocol.FrameHeader(1, 0, 0, true, 100, 100, 0, "h264", "enc", false, "gdi",
            new StreamProtocol.DamageRect(90, 90, 50, 50)); // extends past 100x100
        var body = StreamProtocol.Pack(header, au);
        Assert.Null(StreamProtocol.TryParse(body));
        var inside = header with { Damage = new StreamProtocol.DamageRect(10, 10, 50, 50) };
        Assert.NotNull(StreamProtocol.TryParse(StreamProtocol.Pack(inside, au)));
    }

    [Fact]
    public void F12_DamageTracker_OnePixelChangeOnOddRowAndColumn_IsDetected()
    {
        var tracker = new DamageTracker();
        const int w = 128, h = 128, stride = w * 4;
        var frame = new byte[stride * h];
        Assert.NotNull(tracker.Diff(frame, w, h, stride)); // first frame: full damage
        Assert.Null(tracker.Diff(frame, w, h, stride));    // identical: static
        var changed = (byte[])frame.Clone();
        changed[(63 * stride) + (65 * 4)] = 0xFF; // odd row, odd column, single pixel
        Assert.NotNull(tracker.Diff(changed, w, h, stride));
    }

    [Fact]
    public void F12_DamageTracker_ShortBuffer_FailsClosedWithoutThrowing()
    {
        var tracker = new DamageTracker();
        var shortBuffer = new byte[100];
        var damage = tracker.Diff(shortBuffer, 128, 128, 128 * 4);
        Assert.Equal(new StreamProtocol.DamageRect(0, 0, 128, 128), damage);
    }

    /// <summary>A minimal valid keyframe AU: SPS(7), PPS(8), IDR(5).</summary>
    private static byte[] BuildKeyframeAu()
    {
        var bytes = new List<byte>();
        foreach (var nal in new byte[] { 0x67, 0x68, 0x65 })
        {
            bytes.AddRange(new byte[] { 0, 0, 0, 1, nal, 0x11, 0x22 });
        }
        return bytes.ToArray();
    }

    // ---- destruction pass -------------------------------------------------------

    [Fact]
    public void Destruction_ConsentGuard_NonConsentKindsNeverBlocked_AndUnknownProvenanceRefused()
    {
        var stop = new IpcMessage(IpcKinds.UserStop, null, null, null, null, null, null, null, null, null);
        Assert.True(IpcConsent.CanHonor(stop, agentSessionLive: true)); // STOP itself is never gated
        var clear = new IpcMessage(IpcKinds.UserStopClear, null, null, null, null, null, null, null, null, null,
            InputProvenance: "keyboard-ish"); // near-miss strings are not the physical assertion
        Assert.False(IpcConsent.CanHonor(clear, agentSessionLive: true));
    }

    [Fact]
    public void Destruction_DeviceConsoleStop_GrantsNoOtherAct()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.StopSessionFromDevice(id));
        // The reserved actor string holds no roster authority anywhere else:
        Assert.False(w.Sessions.SetBlanked(id, true, StandaloneTransferService.DeviceConsoleActor));
        Assert.False(w.Sessions.StopSession(id, StandaloneTransferService.DeviceConsoleActor));
    }

    [Fact]
    public void Destruction_PivotByDnsName_LocalhostSubdomainShapes()
    {
        Assert.True(SessionTunnelService.IsPivotTarget("LOCALHOST"));
        Assert.True(SessionTunnelService.IsPivotTarget("a.b.localhost."));
        Assert.False(SessionTunnelService.IsPivotTarget("localhost.example.com")); // a real name, not loopback
    }
}

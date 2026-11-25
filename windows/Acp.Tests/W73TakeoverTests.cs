using Acp.Shared.Enrollment;
using Acp.Shared.Ipc;
using Acp.Shared.Security;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Policy;
using Acp.Shared.Presence;
using Acp.Shared.Roster;
using Acp.Shared.Sessions;

namespace Acp.Tests;

/// <summary>
/// W73 / FR-120 — TUNABLE TAKEOVER, full implementation pins.
///
/// Behaviour: the shared state machine decides each input class
/// by its OWN mode (yield / share-observe / hotkey-only-ignore),
/// the chord yields in every mode, hand-back is explicit-only,
/// and STOP never consults a mode (source pins: the STOP paths
/// contain no mode read; the machine has no stop surface at all).
/// Record: modes at session start, change entries with the actor
/// distinction, takeover events — on the SessionService record;
/// the agent→Core report vocabulary is closed (CoreRuntime
/// coerces kind/actor through it).
/// Settings: the Presence page group writes through
/// PresencePalette.SetTakeoverModes and nothing else can — the
/// no-API-write pins scan every MCP module descriptor, every IPC
/// kind, and the whole Core for a mode write path.
/// Policy: the fleet defaults resolve from Effective Policy
/// (plain keys, U1 pattern), the keys are NOT consent-floor
/// denied, and a device choice outranks the fleet default.
/// </summary>
public class W73TakeoverTests
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
        throw new DirectoryNotFoundException(string.Join("/", parts) + " not found above " + AppContext.BaseDirectory);
    }

    private static string AgentFile(string file) => SrcFile("Acp.SessionAgent", file);
    private static string CoreFile(params string[] parts) => SrcFile("Acp.Core", Path.Combine(parts));

    private static string SrcPath(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return c;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(string.Join("/", parts));
    }

    // ---------------- behaviour: per-mode, per-class ----------------

    [Theory]
    [InlineData(TakeoverInputClass.Mouse)]
    [InlineData(TakeoverInputClass.Keyboard)]
    public void TakeOver_yields_for_both_classes(TakeoverInputClass cls)
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.Yielded, m.LocalInput(cls, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
        Assert.True(m.OwnerDriving);
    }

    [Theory]
    [InlineData(TakeoverInputClass.Mouse)]
    [InlineData(TakeoverInputClass.Keyboard)]
    public void Share_never_yields_for_either_class(TakeoverInputClass cls)
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.ObservedShare, m.LocalInput(cls, TakeoverMode.Share, TakeoverMode.Share));
        Assert.False(m.OwnerDriving);
    }

    [Theory]
    [InlineData(TakeoverInputClass.Mouse)]
    [InlineData(TakeoverInputClass.Keyboard)]
    public void HotkeyOnly_ignores_input_for_either_class(TakeoverInputClass cls)
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.IgnoredHotkeyOnly, m.LocalInput(cls, TakeoverMode.HotkeyOnly, TakeoverMode.HotkeyOnly));
        Assert.False(m.OwnerDriving);
    }

    [Fact]
    public void Classes_are_independent_mouse_share_keyboard_takeover()
    {
        var m = new TakeoverStateMachine();
        // Mouse in Share: observed, agent keeps driving.
        Assert.Equal(TakeoverInputOutcome.ObservedShare,
            m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.Share, TakeoverMode.TakeOver));
        Assert.False(m.OwnerDriving);
        // Keyboard in TakeOver: yields, same machine, same moment.
        Assert.Equal(TakeoverInputOutcome.Yielded,
            m.LocalInput(TakeoverInputClass.Keyboard, TakeoverMode.Share, TakeoverMode.TakeOver));
        Assert.True(m.OwnerDriving);
    }

    [Fact]
    public void Classes_are_independent_mouse_takeover_keyboard_hotkeyonly()
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.IgnoredHotkeyOnly,
            m.LocalInput(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly));
        Assert.Equal(TakeoverInputOutcome.Yielded,
            m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly));
    }

    [Fact]
    public void Hotkey_yields_in_every_mode()
    {
        foreach (var mode in new[] { TakeoverMode.TakeOver, TakeoverMode.Share, TakeoverMode.HotkeyOnly })
        {
            var m = new TakeoverStateMachine();
            Assert.True(m.TakeoverHotkey());
            Assert.True(m.OwnerDriving);
            Assert.False(m.TakeoverHotkey()); // already driving: no second transition
        }
    }

    [Fact]
    public void Hand_back_is_explicit_and_idempotent_safe()
    {
        var m = new TakeoverStateMachine();
        Assert.False(m.HandBack()); // nothing to hand back
        m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver);
        Assert.True(m.HandBack());
        Assert.False(m.OwnerDriving);
        Assert.False(m.HandBack());
        // After hand-back the agent drives and a fresh yield works again.
        Assert.Equal(TakeoverInputOutcome.Yielded,
            m.LocalInput(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
    }

    [Fact]
    public void Reset_clears_ownership_with_the_session()
    {
        var m = new TakeoverStateMachine();
        m.TakeoverHotkey();
        m.Reset();
        Assert.False(m.OwnerDriving);
    }

    // ---------------- STOP from every state ----------------

    [Fact]
    public void Stop_paths_never_consult_a_takeover_mode()
    {
        // The pill STOP click flow, the IPC client's STOP wiring
        // and the STOP hotkey host: none reads a mode, ever. STOP
        // ends the session from owner-driving, SHARE, any state.
        var presence = AgentFile("Presence.cs");
        var stopFlow = presence[presence.IndexOf("private Button MakeStopButton")..];
        stopFlow = stopFlow[..stopFlow.IndexOf("private void BuildActiveBox")];
        Assert.DoesNotContain("TakeoverMode", stopFlow);
        Assert.DoesNotContain("LocalInputYields", stopFlow);
        var ipc = AgentFile("IpcClient.cs");
        Assert.Contains("_presence.StopPressed += () => { _stop.CancelCurrentWork(); _engine.ReleaseAllInputs();", ipc);
        var hotkey = AgentFile("StopHotkeyHost.cs");
        Assert.DoesNotContain("Takeover", hotkey);
        // The state machine itself has no stop surface to gate.
        Assert.DoesNotContain("Stop", typeof(TakeoverStateMachine).GetMethods().Select(m => m.Name).Aggregate((a, b) => a + b));
    }

    [Fact]
    public void Presence_layer_wires_both_read_points_and_the_handback_paths()
    {
        var presence = AgentFile("Presence.cs");
        // Mouse read point (W72) + keyboard read point (W73), each
        // consulting its OWN class mode exactly once.
        Assert.Equal(1, System.Text.RegularExpressions.Regex.Matches(presence,
            "_takeover.LocalInput\\(TakeoverInputClass.Mouse").Count);
        Assert.Equal(1, System.Text.RegularExpressions.Regex.Matches(presence,
            "_takeover.LocalInput\\(TakeoverInputClass.Keyboard").Count);
        Assert.Contains("public void SetOwnerDrivingFromKeyboard(bool driving)", presence);
        Assert.Contains("public void TakeoverHotkeyPressed()", presence);
        Assert.Contains("public void HandBackToAgent(string actor)", presence);
        // The pill's hand-back affordance exists ONLY in the
        // owner-driving branch of the one Box composition.
        Assert.Contains("if (_ownerDriving)", presence);
        Assert.Contains("Strings.Get(\"HandBackControl\")", presence);
        // Owner-driving state sentence: W117 / F2 amended this
        // pin decision-driven — the bare "Paused — you're
        // driving" string named NO agent (W115 finding 2), so
        // the branch now reads the one branch-sentence home,
        // which names the driver in the same copy register. The
        // trim rule below is unchanged.
        Assert.Contains("PresenceBranch.OwnerDriving", presence);
        Assert.Contains("PresenceComposition.BranchSentence", presence);
        Assert.Contains("pill && CurrentActor == PresenceLaw.Actor.Ai ? PillGold : CurrentHue", presence);
        // Live-found race (audit seq 4851→4852): the hand-back
        // click's own input re-yielded 23 ms later. The layer now
        // suppresses local-input yields for a grace window after
        // a successful hand-back, in BOTH class entry points; the
        // chord path (TakeoverHotkeyPressed) carries no such
        // check — a deliberate chord is never settle noise.
        Assert.Contains("_yieldSuppressedUntilUtc = DateTime.UtcNow.AddMilliseconds(1500)", presence);
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(presence,
            "if \\(YieldSuppressed\\) return;").Count);
        var chord = presence[presence.IndexOf("public void TakeoverHotkeyPressed")..];
        chord = chord[..chord.IndexOf("public void HandBackToAgent")];
        Assert.DoesNotContain("YieldSuppressed", chord);
    }

    [Fact]
    public void Gate_path_approval_routes_to_handback_and_denial_does_not()
    {
        var app = AgentFile("App.xaml.cs");
        Assert.Contains("request.Tool == Acp.Shared.Presence.TakeoverGate.HandBackTool", app);
        Assert.Contains("if (isHandBackAsk && outcome == GateSheet.Outcome.Approved)", app);
        Assert.Contains("presence.HandBackToAgent(Acp.Shared.Presence.TakeoverActors.OwnerGateApproval)", app);
        // The hand-back ASK tool: gated by its own class, which is
        // NOT a standing-approvable known class (every ask shows a
        // card), and its execution performs no state change.
        var console = CoreFile("Phase2", "OwnerConsole.cs");
        Assert.Contains("TakeoverHandBackRequestModule", console);
        Assert.Contains("GateClass: Acp.Shared.Presence.TakeoverGate.HandBackGateClass", console);
        var engine = SrcFile("Acp.Shared", "Policy", "PolicyEngine.cs");
        var gated = engine[engine.IndexOf("GatedClasses = ")..];
        gated = gated[..gated.IndexOf("};")];
        Assert.DoesNotContain("takeover_handback", gated);
        var runtime = CoreFile("CoreRuntime.cs");
        Assert.Contains("Tools.Register(new TakeoverHandBackRequestModule())", runtime);
    }

    // ---------------- session record ----------------

    private sealed class World
    {
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World { Sessions = new SessionService(roster, enrollments), DeviceId = device!.DeviceId };
    }

    [Fact]
    public void Session_record_carries_modes_at_start()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan",
            mouseTakeoverMode: "Share", keyboardTakeoverMode: "hotkeyonly");
        Assert.NotNull(s);
        Assert.Equal("Share", s!.MouseTakeoverMode);
        Assert.Equal("HotkeyOnly", s.KeyboardTakeoverMode);
        var events = w.Sessions.ListEvents(s.Id);
        var modes = Assert.Single(events, e => e.Kind == TakeoverRecordKinds.ModesAtStart);
        Assert.Equal("mouse=Share keyboard=HotkeyOnly", modes.Detail);
    }

    [Fact]
    public void Session_record_rejects_foreign_mode_names()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan",
            mouseTakeoverMode: "bogus-mode");
        Assert.NotNull(s);
        Assert.Null(s!.MouseTakeoverMode);
        Assert.DoesNotContain(w.Sessions.ListEvents(s.Id), e => e.Kind == TakeoverRecordKinds.ModesAtStart);
    }

    [Fact]
    public void Mode_change_entries_distinguish_the_actor()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan",
            mouseTakeoverMode: "TakeOver", keyboardTakeoverMode: "TakeOver");
        Assert.NotNull(s);
        Assert.True(w.Sessions.RecordTakeoverModeChange(s!.Id, TakeoverActors.OwnerLocal,
            TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.Share));
        Assert.True(w.Sessions.RecordTakeoverModeChange(s.Id, TakeoverActors.InSession,
            TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly));
        var changes = w.Sessions.ListEvents(s.Id).Where(e => e.Kind == TakeoverRecordKinds.ModeChanged).ToList();
        Assert.Equal(2, changes.Count);
        Assert.Equal(TakeoverActors.OwnerLocal, changes[0].ActorUserId);
        Assert.Equal("mouse mode TakeOver -> Share", changes[0].Detail);
        Assert.Equal(TakeoverActors.InSession, changes[1].ActorUserId);
        Assert.Equal("keyboard mode TakeOver -> HotkeyOnly", changes[1].Detail);
        // The record's current state agrees with its history.
        var now = w.Sessions.GetSession(s.Id);
        Assert.Equal("Share", now!.MouseTakeoverMode);
        Assert.Equal("HotkeyOnly", now.KeyboardTakeoverMode);
    }

    [Fact]
    public void Takeover_events_record_and_foreign_kinds_refuse()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.RecordTakeoverEvent(s!.Id, TakeoverRecordKinds.Yield,
            TakeoverActors.LocalInput, TakeoverRecordDetail.Yield(TakeoverInputClass.Mouse)));
        Assert.True(w.Sessions.RecordTakeoverEvent(s.Id, TakeoverRecordKinds.HandBack,
            TakeoverActors.OwnerGateApproval, TakeoverRecordDetail.HandBack(TakeoverActors.OwnerGateApproval)));
        Assert.True(w.Sessions.RecordTakeoverEvent(s.Id, TakeoverRecordKinds.Hotkey,
            TakeoverActors.OwnerHotkey, "takeover hotkey yielded driving to the owner"));
        Assert.False(w.Sessions.RecordTakeoverEvent(s.Id, "ended", TakeoverActors.LocalInput, "forged"));
        Assert.False(w.Sessions.RecordTakeoverEvent("no-such-session", TakeoverRecordKinds.Yield,
            TakeoverActors.LocalInput, "x"));
        var kinds = w.Sessions.ListEvents(s.Id).Select(e => e.Kind).ToList();
        Assert.Contains(TakeoverRecordKinds.Yield, kinds);
        Assert.Contains(TakeoverRecordKinds.HandBack, kinds);
        Assert.Contains(TakeoverRecordKinds.Hotkey, kinds);
    }

    [Fact]
    public void Agent_report_vocabulary_is_closed_and_core_coerces_through_it()
    {
        var runtime = CoreFile("CoreRuntime.cs");
        Assert.Contains("else if (msg.Kind == IpcKinds.TakeoverEvent)", runtime);
        Assert.Contains("RecordTakeoverEvent(msg.ArgumentsJson)", runtime);
        Assert.Contains("Shared.Presence.TakeoverRecordKinds.ModesAtStart", runtime);
        Assert.Contains("Shared.Presence.TakeoverActors.OwnerLocal", runtime);
        // The IPC kind is a report, never a consent/act kind.
        Assert.DoesNotContain(IpcKinds.TakeoverEvent, IpcConsent.ConsentKinds);
        var ipc = AgentFile("IpcClient.cs");
        Assert.Contains("IpcKinds.TakeoverEvent", ipc);
        Assert.Contains("TakeoverRecordKinds.ModesAtStart", ipc); // modes at session start
        Assert.Contains("_sessionWasActive ? TakeoverActors.InSession : TakeoverActors.OwnerLocal", ipc);
        Assert.Contains("_watcher?.Start()", ipc);
        Assert.Contains("_watcher?.Stop()", ipc);
    }

    // ---------------- settings UI + the one write path ----------------

    [Fact]
    public void Settings_group_lives_on_the_presence_page_through_the_strings_door()
    {
        var pages = AgentFile("MainWindow.Pages.cs");
        Assert.Contains("Strings.Get(\"TakeoverGroupTitle\")", pages);
        Assert.Contains("Strings.Get(\"TakeoverMouseLabel\")", pages);
        Assert.Contains("Strings.Get(\"TakeoverKeyboardLabel\")", pages);
        Assert.Contains("Strings.Get(\"TakeoverModeTakeOverSentence\")", pages);
        Assert.Contains("Strings.Get(\"TakeoverModeShareSentence\")", pages);
        Assert.Contains("Strings.Get(\"TakeoverModeHotkeyOnlySentence\")", pages);
        Assert.Contains("p.SetTakeoverModes(", pages);
        // The write exists in exactly one place in the agent: the
        // palette's UI-only setter.
        var palette = AgentFile("PresencePalette.cs");
        Assert.Contains("public void SetTakeoverModes(TakeoverMode mouse, TakeoverMode keyboard)", palette);
    }

    [Fact]
    public void No_api_write_path_exists_for_the_modes()
    {
        // No IPC kind can set the modes: the only takeover kinds
        // are a defaults PUSH (Core→Agent, applied in memory only
        // where the device has not chosen) and an event REPORT.
        var kinds = typeof(IpcKinds).GetFields().Select(f => (string)f.GetValue(null)!).ToList();
        Assert.DoesNotContain(kinds, k => k.Contains("takeover") && k.Contains("set"));
        // No Core code writes the palette or presence.json modes.
        var coreDir = new DirectoryInfo(Path.GetDirectoryName(SrcPath("Acp.Core", "CoreRuntime.cs"))!);
        foreach (var file in coreDir.EnumerateFiles("*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file.FullName);
            Assert.DoesNotContain("SetTakeoverModes", text);
            Assert.DoesNotContain("MouseTakeoverMode =", text);
            Assert.DoesNotContain("KeyboardTakeoverMode =", text);
        }
        // The hand-back ASK tool performs no state change (its
        // execution is a receipt); the F1 owner_takeover refusal
        // stands verbatim beside it.
        var console = CoreFile("Phase2", "OwnerConsole.cs");
        Assert.Contains("owner_takeover is not agent-callable", console);
        var ask = console[console.IndexOf("class TakeoverHandBackRequestModule")..];
        ask = ask[..ask.IndexOf("class LiveViewModule")];
        Assert.DoesNotContain("TakeoverArbiter", ask);
        Assert.DoesNotContain("UpdateSession", ask);
        // The watcher reports signals only: it never references a
        // mode, a setter, or key identity beyond the chord check.
        var watcher = AgentFile("LocalInputWatcher.cs");
        Assert.DoesNotContain("SetTakeoverModes", watcher);
        Assert.DoesNotContain("TakeoverMode.", watcher);
    }

    // ---------------- policy mapping ----------------

    [Fact]
    public void Policy_keys_are_not_consent_floor_denied()
    {
        Assert.False(ConsentFloorGuard.IsDenied(TakeoverPolicyKeys.MouseMode));
        Assert.False(ConsentFloorGuard.IsDenied(TakeoverPolicyKeys.KeyboardMode));
        Assert.False(ConsentFloorGuard.IsDenied(TakeoverPolicyKeys.FeatureToggle));
    }

    [Fact]
    public void Fleet_defaults_resolve_from_effective_policy_fail_safe()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev-1", "scope-1");
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("d1", PolicyLevels.Org, "scope-1",
            new Dictionary<string, string>
            {
                [TakeoverPolicyKeys.MouseMode] = "Share",
                [TakeoverPolicyKeys.KeyboardMode] = "not-a-mode",
            }, 1)).Allowed);
        var defaults = TakeoverFleetDefaults.FromEffective(engine.ComputeEffective(facts));
        Assert.Equal(TakeoverMode.Share, defaults.Mouse);
        Assert.Null(defaults.Keyboard); // unparsable is ignored, never coerced
        Assert.Equal(TakeoverMode.Share, defaults.DefaultFor(TakeoverInputClass.Mouse));
        Assert.Equal(TakeoverMode.TakeOver, defaults.DefaultFor(TakeoverInputClass.Keyboard));
        // The toggle is registered with the FR-120 directive.
        Assert.True(engine.Registry.TryGet(TakeoverPolicyKeys.FeatureToggle, out var toggle));
        Assert.Equal("FR-120", toggle!.Directive);
        Assert.True(toggle.DefaultEnabled);
    }

    [Fact]
    public void Fleet_default_applies_only_where_the_device_has_not_chosen()
    {
        var palette = AgentFile("PresencePalette.cs");
        // The active-mode rule: chosen → the device's stored value;
        // not chosen → the fleet default (which itself falls back
        // to TakeOver). Policy never persists into the file.
        Assert.Contains("TakeoverModesChosen", palette);
        Assert.Contains("FleetDefaults.DefaultFor(TakeoverInputClass.Mouse)", palette);
        Assert.Contains("FleetDefaults.DefaultFor(TakeoverInputClass.Keyboard)", palette);
        Assert.Contains("public static Acp.Shared.Policy.TakeoverFleetDefaults FleetDefaults { get; set; }", palette);
        // IPC payload round-trip: names only, malformed → none.
        var d = TakeoverFleetDefaults.FromIpcJson("{\"mouse\": \"Share\", \"keyboard\": \"HotkeyOnly\"}");
        Assert.Equal(TakeoverMode.Share, d.Mouse);
        Assert.Equal(TakeoverMode.HotkeyOnly, d.Keyboard);
        Assert.Equal(TakeoverFleetDefaults.None, TakeoverFleetDefaults.FromIpcJson("{broken"));
        Assert.Equal(TakeoverFleetDefaults.None, TakeoverFleetDefaults.FromIpcJson(null));
        var json = new TakeoverFleetDefaults(TakeoverMode.Share, null).ToIpcJson();
        Assert.Contains("\"mouse\": \"Share\"", json);
        Assert.DoesNotContain("keyboard", json);
    }

    [Fact]
    public void Core_pushes_defaults_on_auth_and_presence_push()
    {
        var runtime = CoreFile("CoreRuntime.cs");
        Assert.Contains("PushTakeoverDefaultsSafelyAsync", runtime);
        Assert.Contains("TakeoverFleetDefaults.FromEffective(ManagementPolicies.ComputeEffective(facts))", runtime);
        Assert.Contains("ManagementPolicies.IsEnabled(facts, TakeoverPolicyKeys.FeatureToggle)", runtime);
        var ipc = AgentFile("IpcClient.cs");
        Assert.Contains("case IpcKinds.TakeoverDefaults:", ipc);
        Assert.Contains("PresencePalette.FleetDefaults = TakeoverFleetDefaults.FromIpcJson(msg.ArgumentsJson)", ipc);
    }

    // ---------------- W107 (C1): stationary-pointer classification ----------------

    private static LocalInputClassification.MousePoll Poll(
        bool moved = false, bool down = false, bool pressedSince = false, bool wheel = false) =>
        new(CursorMoved: moved, AnyButtonDown: down,
            AnyButtonPressedSinceLastPoll: pressedSince, WheelActivity: wheel);

    [Fact]
    public void MouseButtonVks_SitBelowTheKeyboardScanFloor()
    {
        // The C1 gap stated as data: every mouse-button VK is
        // below 0x08, where the keyboard scan starts — a click
        // could never be keyboard input, and pre-W107 nothing
        // classified it at all.
        Assert.Equal(new[] { 0x01, 0x02, 0x04, 0x05, 0x06 },
            LocalInputClassification.MouseButtonVirtualKeys);
        Assert.All(LocalInputClassification.MouseButtonVirtualKeys, vk => Assert.True(vk < 0x08));
    }

    [Fact]
    public void StationaryClick_IsMouseSignal_OneYieldEventPerPress()
    {
        var latch = new LocalInputClassification.MouseButtonLatch();
        // press poll: stationary pointer, button down → signal
        Assert.True(LocalInputClassification.IsMouseSignal(Poll(down: true), latch));
        // held across further polls: NO re-fire (one click = one
        // yield event, however long the hold)
        Assert.False(LocalInputClassification.IsMouseSignal(Poll(down: true), latch));
        Assert.False(LocalInputClassification.IsMouseSignal(Poll(down: true), latch));
        // release poll: no signal, latch released
        Assert.False(LocalInputClassification.IsMouseSignal(Poll(), latch));
        // a second press signals again
        Assert.True(LocalInputClassification.IsMouseSignal(Poll(down: true), latch));
    }

    [Fact]
    public void SubPollTap_PressedSinceBit_StillSignals()
    {
        // Pressed AND released inside one 60 ms poll window: not
        // currently down, but the pressed-since bit saw it.
        var latch = new LocalInputClassification.MouseButtonLatch();
        Assert.True(LocalInputClassification.IsMouseSignal(Poll(pressedSince: true), latch));
        Assert.False(LocalInputClassification.IsMouseSignal(Poll(), latch)); // latch released by the quiet poll
    }

    [Fact]
    public void WheelAndMovement_AreMouseSignals_IdlePollIsNot()
    {
        var latch = new LocalInputClassification.MouseButtonLatch();
        Assert.True(LocalInputClassification.IsMouseSignal(Poll(wheel: true), latch));
        Assert.True(LocalInputClassification.IsMouseSignal(Poll(moved: true), latch));
        Assert.False(LocalInputClassification.IsMouseSignal(Poll(), latch));
    }

    [Fact]
    public void StationaryClick_YieldsMouseClass_ByItsOwnMode_NeverKeyboard()
    {
        // The verified DeepSeek sequence, end to end at the
        // classifier + state machine: mouse TAKE OVER, keyboard
        // HOTKEY ONLY, owner clicks with the pointer stationary.
        var latch = new LocalInputClassification.MouseButtonLatch();
        var signal = LocalInputClassification.IsMouseSignal(Poll(down: true), latch);
        Assert.True(signal);
        var machine = new TakeoverStateMachine();
        var outcome = machine.LocalInput(TakeoverInputClass.Mouse,
            TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly);
        Assert.Equal(TakeoverInputOutcome.Yielded, outcome);
        Assert.True(machine.OwnerDriving);

        // The mirror: keyboard TAKE OVER + a click — the click is
        // MOUSE class, so with mouse HOTKEY ONLY nothing yields;
        // the click is never read as keyboard input.
        var machine2 = new TakeoverStateMachine();
        var outcome2 = machine2.LocalInput(TakeoverInputClass.Mouse,
            TakeoverMode.HotkeyOnly, TakeoverMode.TakeOver);
        Assert.Equal(TakeoverInputOutcome.IgnoredHotkeyOnly, outcome2);
        Assert.False(machine2.OwnerDriving);
    }

    // ---------------- W111 (W110-C1): keyboard sub-poll tap + VK_CANCEL ----------------

    private static LocalInputClassification.KeyboardPoll KPoll(
        bool down = false, bool pressedSince = false) =>
        new(AnyKeyDown: down, AnyKeyPressedSinceLastPoll: pressedSince);

    [Fact]
    public void KeyboardSubPollTap_PressedSinceBit_SignalsExactlyOnce()
    {
        // The W110-C1 counter-example: keyboard TAKE OVER, a
        // ~40 ms tap pressed AND released inside one 60 ms poll
        // window — not currently down, only the pressed-since
        // bit remembers it. Exactly one keyboard-class signal.
        var latch = new LocalInputClassification.KeyboardLatch();
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(pressedSince: true), latch));
        // the following quiet polls do not re-fire
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(), latch));
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(), latch));
    }

    [Fact]
    public void KeyboardHeldKey_DoesNotReFirePerPoll_ReleaseReArms()
    {
        var latch = new LocalInputClassification.KeyboardLatch();
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(), latch)); // release re-arms
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch)); // next press signals
    }

    [Fact]
    public void KeyboardLatch_HeldModifier_DoesNotReFire_AndDoesNotSwallowALaterTap()
    {
        // W113 (the W112 held-modifier edge, stated precisely):
        // a modifier is pressed and HELD across polls; while it
        // is still held, the owner taps a second key (press +
        // release inside one poll window, so only its
        // pressed-since bit remembers it). Correct behaviour:
        // (1) the modifier's own press signals exactly once and
        // the held modifier never re-fires on later polls;
        // (2) the later tap still signals — it is a new press,
        // and its pressed-since bit is consumed by the very poll
        // that reads it, so a latch that swallowed it here would
        // lose it forever (no later poll can recover it);
        // (3) after everything is released the latch re-arms.
        // The chord path cannot consume the tap's bit either:
        // the watcher derives the chord from the SAME sample's
        // down bits (pinned in WatcherSource_*), never a second
        // probe of the chord keys.
        var latch = new LocalInputClassification.KeyboardLatch();
        // modifier press: down + its pressed-since bit → signals once
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(down: true, pressedSince: true), latch));
        // modifier held across polls: no re-fire
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        // a second key tapped while the modifier is still held:
        // its pressed-since bit arrives on a down=true poll (the
        // modifier) → the tap signals, it is NOT swallowed
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(down: true, pressedSince: true), latch));
        // modifier still held afterwards: quiet again
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
        // full release re-arms; the next press signals
        Assert.False(LocalInputClassification.IsKeyboardSignal(KPoll(), latch));
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(down: true), latch));
    }

    [Fact]
    public void VkCancel_IsKeyboardClass_Explicitly_NotMouse_NotInScanRange()
    {
        // VK_CANCEL 0x03 sits below the 0x08 scan floor and in
        // neither pre-W111 class; W111 assigns it to keyboard.
        Assert.Equal(0x03, LocalInputClassification.VkCancel);
        Assert.True(LocalInputClassification.VkCancel < LocalInputClassification.KeyboardScanFloor);
        Assert.True(LocalInputClassification.IsKeyboardVirtualKey(0x03));
        Assert.Contains(0x03, LocalInputClassification.KeyboardVirtualKeys);
        Assert.DoesNotContain(0x03, LocalInputClassification.MouseButtonVirtualKeys);
        // and no mouse-button VK is keyboard-class, ever
        Assert.All(LocalInputClassification.MouseButtonVirtualKeys,
            vk => Assert.False(LocalInputClassification.IsKeyboardVirtualKey(vk)));
        Assert.All(LocalInputClassification.KeyboardVirtualKeys,
            vk => Assert.True(LocalInputClassification.IsKeyboardVirtualKey(vk)));
    }

    [Fact]
    public void KeyboardSubPollTap_YieldsKeyboardClass_ByItsOwnMode()
    {
        // The exact W110-C1 sequence end to end: keyboard TAKE
        // OVER, mouse HOTKEY ONLY, owner taps a key sub-poll,
        // pointer stationary → keyboard yields.
        var latch = new LocalInputClassification.KeyboardLatch();
        Assert.True(LocalInputClassification.IsKeyboardSignal(KPoll(pressedSince: true), latch));
        var machine = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.Yielded, machine.LocalInput(
            TakeoverInputClass.Keyboard, TakeoverMode.HotkeyOnly, TakeoverMode.TakeOver));
        Assert.True(machine.OwnerDriving);
        // Mirror: keyboard HOTKEY ONLY — the tap is ignored,
        // never re-read as a mouse signal.
        var machine2 = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.IgnoredHotkeyOnly, machine2.LocalInput(
            TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly));
        Assert.False(machine2.OwnerDriving);
    }

    [Fact]
    public void WatcherSource_SamplesKeyboardPressedSince_ThroughTheClassifier()
    {
        var watcher = AgentFile("LocalInputWatcher.cs");
        Assert.Contains("LocalInputClassification.IsKeyboardSignal", watcher);
        Assert.Contains("KeyboardState", watcher);
        Assert.Contains("KeyboardVirtualKeys", watcher);
        // the instantaneous-only scan is gone
        Assert.DoesNotContain("AnyKeyDown()", watcher);
    }

    [Fact]
    public void WatcherSource_UsesTheClassifier_AndStatesTheSendInputLimitHonestly()
    {
        var watcher = AgentFile("LocalInputWatcher.cs");
        // the watcher classifies buttons + wheel through the
        // pinned shared classifier, not a cursor-delta-only check
        Assert.Contains("LocalInputClassification.IsMouseSignal", watcher);
        Assert.Contains("MouseButtonState", watcher);
        Assert.Contains("WM_MOUSEWHEEL", watcher);
        // the false premise is GONE from both files that asserted
        // it: neither may claim injected input never advances the
        // tick (W73's live record contradicts it for one path)
        var native = AgentFile("NativeMethods.cs");
        Assert.DoesNotContain("does NOT advance for SendInput-injected", watcher);
        Assert.DoesNotContain("SendInput-injected events do NOT advance it", native);
        Assert.Contains("DID advance this laptop's tick", watcher);
    }

    // ---------------- record detail vocabulary ----------------

    [Fact]
    public void Record_detail_strings_are_canonical()
    {
        Assert.Equal("mouse=Share keyboard=HotkeyOnly",
            TakeoverRecordDetail.Modes(TakeoverMode.Share, TakeoverMode.HotkeyOnly));
        Assert.Equal("mouse mode TakeOver -> Share",
            TakeoverRecordDetail.ModeChange(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.Share));
        Assert.Equal("local keyboard input yielded driving to the owner",
            TakeoverRecordDetail.Yield(TakeoverInputClass.Keyboard));
    }
}

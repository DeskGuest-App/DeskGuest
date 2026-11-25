using System.Text;
using Acp.Shared.BackgroundTools;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-10 DESTRUCTION PASS — attack the background toolset and the
// Backstage gate: scope confusion, audit evasion, kit poisoning,
// Backstage gate games, and process-kill abuse shapes against ACP's
// own consent surface. Tests drive fakes only — no real process is
// killed and no real registry is touched on this VM.
public class Rmm10DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingBackgroundExecutor Exec = new();
        public BackgroundToolsService Service;
        public RecordingBackstageStreamSink BackstageSink = new();
        public BackstageService Backstage;
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;

        public Rig(bool withGate = false)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new BackgroundToolsService(Audit, Policy,
                id => id == Dev ? Facts : null, Exec, new ExecutorKitByteStore(Exec),
                withGate ? Gate : null, () => Now);
            Backstage = new BackstageService(Audit, Policy,
                id => id == Dev ? Facts : null, BackstageSink, Service, () => Now);
            Exec.Processes[100] = new BackgroundProcessInfo(100, 1, "notepad", 10_000);
            Exec.Processes[400] = new BackgroundProcessInfo(400, 1, "AcpCore", 50_000);
            Exec.Processes[500] = new BackgroundProcessInfo(500, 1, "evil-parent", 10_000);
            Exec.Processes[501] = new BackgroundProcessInfo(501, 500, "Acp.SessionAgent", 40_000);
            Exec.Services["AcpCore"] = new BackgroundServiceInfo("AcpCore", "Agentic Control", "Running");
            Exec.Services["Niagara"] = new BackgroundServiceInfo("Niagara", "Niagara", "Running");
        }

        public void SetPolicy(string key, string value, long rev = 1, string docId = "doc") =>
            Assert.True(Policy.AddDocument(new ManagementPolicyDocument(
                docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev)).Allowed);

        public void EnableTools() => SetPolicy(BackgroundPolicyKeys.ToolsEnabled, "true", docId: "tools-on");
        public void EnableBackstage() => SetPolicy(BackgroundPolicyKeys.BackstageEnabled, "true", docId: "bs-on");
    }

    private static BackgroundCallContext Ctx(params string[] scopes) => new(
        "pair-1", "tech-1", new HashSet<string>(scopes), Dev);
    private static BackgroundCallContext BgCtx() => Ctx(Scopes.BackgroundTools);

    // BD-SHARED-RMM-1 F6 test repair: admitting a SHARED kit now
    // requires the dedicated background_kit_admin scope (admission
    // changes what every pairing may run). Kit admissions below
    // use an admin context; all other acts keep the plain
    // background context, and the negative admission tests still
    // refuse for their own reasons (validation, policy, scope).
    private static BackgroundCallContext KitAdminCtx() => Ctx(Scopes.BackgroundTools, Scopes.KitAdmin);

    // ---- scope confusion ----------------------------------------------------

    [Fact]
    public void ScopeConfusion_FullSessionScopes_WithoutBackgroundScope_Refused_NothingExecutes_Audited()
    {
        var rig = new Rig(); rig.EnableTools();
        // observe+drive+shell+admin+unlock: EVERY session scope there
        // is — and still not background rights.
        var sessionOnly = Ctx(Scopes.Observe, Scopes.Drive, Scopes.Shell, Scopes.Admin, Scopes.Unlock);
        var kill = rig.Service.KillProcess(sessionOnly, 100);
        Assert.False(kill.Ok);
        Assert.Contains(Scopes.BackgroundTools, kill.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("kill:"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_refused");
        Assert.True(rig.Audit.Verify().Ok);
        // …and the reverse direction: background scope alone sees no
        // session tools — the surface for background is its own list.
        Assert.Empty(rig.Service.Surface.AvailableTools(rig.Facts,
            new HashSet<string> { Scopes.Observe }));
    }

    [Fact]
    public void ScopeConfusion_PolicyOff_RefusesEverything_AndSurfaceIsEmpty()
    {
        var rig = new Rig(); // policy never enabled
        Assert.False(rig.Service.KillProcess(BgCtx(), 100).Ok);
        Assert.False(rig.Service.StartService(BgCtx(), "Niagara").Ok);
        Assert.False(rig.Service.RegistrySet(BgCtx(), @"HKLM\SOFTWARE\Vendor\App", "X", "1").Ok);
        Assert.Empty(rig.Exec.Calls.Where(c => !c.StartsWith("get_")));
        Assert.Equal(3, rig.Audit.Entries.Count(e => e.Kind == "background_action_refused"));
        Assert.Empty(rig.Service.Surface.AvailableTools(rig.Facts, BgCtx().PairingScopes));
    }

    [Fact]
    public void PolicyFlipOff_AfterBeingOn_NextCallRefuses()
    {
        var rig = new Rig(); rig.EnableTools();
        Assert.True(rig.Service.KillProcess(BgCtx(), 100).Ok);
        rig.SetPolicy(BackgroundPolicyKeys.ToolsEnabled, "false", rev: 2, docId: "tools-on");
        var after = rig.Service.StartService(BgCtx(), "Niagara");
        Assert.False(after.Ok);
        Assert.Contains("disabled by policy", after.Detail);
    }

    // ---- audit evasion ---------------------------------------------------------

    [Fact]
    public void AuditEvasion_ExecutorThrows_ErrorIsChained_ChainStillVerifies()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.ThrowOn.Add("kill");
        var result = rig.Service.KillProcess(BgCtx(), 100);
        Assert.False(result.Ok);
        Assert.Contains("executor error", result.Detail);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_error");
        Assert.True(rig.Audit.Verify().Ok);
        Assert.Contains(rig.Service.SessionHistory, h => h.Outcome.StartsWith("error"));
    }

    [Fact]
    public void AuditEvasion_EveryPathLeavesAChainedEvent_NoSilentPath()
    {
        var rig = new Rig(); rig.EnableTools();
        var before = rig.Audit.Entries.Count;
        rig.Service.KillProcess(Ctx(Scopes.Shell), 100);                    // scope refusal
        rig.Service.KillProcess(BgCtx(), 400);                              // protected refusal
        rig.Service.KillProcess(BgCtx(), 999);                              // unknown pid refusal
        rig.Service.RegistrySet(BgCtx(), @"HKLM\SOFTWARE\ACP\Pairings", "x", "y"); // protected key refusal
        rig.Service.RunKitTool(BgCtx(), "ghost-kit", "diag", "");           // unadmitted kit refusal
        var entries = rig.Audit.Entries.Skip(before).ToList();
        Assert.Equal(5, entries.Count(e => e.Kind == "background_action_refused"));
        Assert.True(rig.Audit.Verify().Ok);
        Assert.Equal(5, rig.Service.SessionHistory.Count);
    }

    // ---- kit poisoning --------------------------------------------------------------

    private static (ToolboxKit Kit, byte[] GoodBytes) KitWithBytes(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        var pin = KitToolDefinition.HashBytes(bytes);
        var kit = new ToolboxKit("site-kit", "site-kit", 1, KitOwnerKinds.Shared, "team",
            new[] { new KitToolDefinition("diag", "tools/diag.exe", pin) });
        return (kit, bytes);
    }

    [Fact]
    public void KitPoisoning_HashMismatchedBytes_NeverRun_Audited()
    {
        var rig = new Rig(); rig.EnableTools();
        var (kit, _) = KitWithBytes("the-real-diag");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        // The store is poisoned AFTER admission: bytes swapped.
        rig.Exec.SeedKitBytes("site-kit", "diag", "attacker-bytes");
        var run = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "");
        Assert.False(run.Ok);
        Assert.Contains("do NOT match", run.Detail);
        Assert.Empty(rig.Exec.KitRuns);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "background_action_refused" && e.Detail.Contains("pin"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void KitPoisoning_DefinitionMutatedAfterAdmission_FrozenCopyGoverns()
    {
        var rig = new Rig(); rig.EnableTools();
        var (kit, good) = KitWithBytes("frozen-diag");
        rig.Exec.KitBytes["site-kit/diag"] = good;
        var callerTools = new List<KitToolDefinition>(kit.Tools);
        var callerKit = kit with { Tools = callerTools };
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), callerKit).Ok);
        // Attacker mutates the caller's list post-admission, repointing
        // the pin at attacker bytes, then poisons the store to match.
        var evil = Encoding.UTF8.GetBytes("evil-diag");
        callerTools[0] = new KitToolDefinition("diag", "tools/diag.exe", KitToolDefinition.HashBytes(evil));
        rig.Exec.KitBytes["site-kit/diag"] = evil;
        var run = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "");
        Assert.False(run.Ok); // the FROZEN pin governs: evil bytes mismatch it
        Assert.Empty(rig.Exec.KitRuns);
        // And the honest bytes still run against the frozen definition.
        rig.Exec.KitBytes["site-kit/diag"] = good;
        Assert.True(rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "").Ok);
    }

    [Fact]
    public void KitPoisoning_SameVersionRedefinition_AndStaleVersion_RefusedAtAdmission()
    {
        var rig = new Rig(); rig.EnableTools();
        var (kit, _) = KitWithBytes("v1-diag");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        var (swapped, _) = KitWithBytes("different-diag");
        var refused = rig.Service.AdmitKit(KitAdminCtx(), swapped);
        Assert.False(refused.Ok);
        Assert.Contains("different content", refused.Reason);
        var v2 = kit with { Version = 2 };
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), v2).Ok);
        Assert.False(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok); // v1 now stale
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_kit_refused");
    }

    [Fact]
    public void KitPoisoning_TraversalPath_BadPin_DuplicateTool_RefusedWholeAtAdmission()
    {
        var rig = new Rig(); rig.EnableTools();
        var goodPin = KitToolDefinition.HashBytes(Encoding.UTF8.GetBytes("x"));
        var traversal = new ToolboxKit("bad", "bad", 1, KitOwnerKinds.Shared, "team",
            new[] { new KitToolDefinition("diag", "../escape.exe", goodPin) });
        Assert.False(rig.Service.AdmitKit(KitAdminCtx(), traversal).Ok);
        var badPin = new ToolboxKit("bad2", "bad2", 1, KitOwnerKinds.Shared, "team",
            new[] { new KitToolDefinition("diag", "tools/diag.exe", "not-a-pin") });
        Assert.False(rig.Service.AdmitKit(KitAdminCtx(), badPin).Ok);
        var dup = new ToolboxKit("bad3", "bad3", 1, KitOwnerKinds.Shared, "team",
            new[]
            {
                new KitToolDefinition("diag", "tools/a.exe", goodPin),
                new KitToolDefinition("diag", "tools/b.exe", goodPin),
            });
        Assert.False(rig.Service.AdmitKit(KitAdminCtx(), dup).Ok);
        Assert.Empty(rig.Service.Kits);
    }

    // ---- Backstage gate games -----------------------------------------------------------

    [Fact]
    public void Backstage_PolicyOn_WithoutSeparatePermission_Refused_SinkNeverTouched()
    {
        var rig = new Rig(); rig.EnableBackstage();
        // Even a pairing holding background_tools + admin + everything else.
        var almost = Ctx(Scopes.BackgroundTools, Scopes.Admin, Scopes.Shell, Scopes.Drive, Scopes.Observe);
        var start = rig.Backstage.StartSession(almost);
        Assert.False(start.Ok);
        Assert.Contains(Scopes.Backstage, start.Reason);
        Assert.Empty(rig.BackstageSink.Opened);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_session_refused");
    }

    [Fact]
    public void Backstage_PermissionWithoutPolicy_Refused_AndCapabilityDoesNotExistInSurface()
    {
        var rig = new Rig(); // backstage policy stays OFF (the default)
        var ctx = Ctx(Scopes.Backstage);
        Assert.False(rig.Backstage.ExistsInSurface(rig.Facts, ctx.PairingScopes));
        var start = rig.Backstage.StartSession(ctx);
        Assert.False(start.Ok);
        Assert.Contains("disabled by policy", start.Reason);
        Assert.Empty(rig.BackstageSink.Opened);
        // The attempt is still on the device's record — a refused
        // hidden-session attempt is exactly what the history is for.
        Assert.Contains(rig.Service.SessionHistory, h => h.Kind == "backstage");
    }

    [Fact]
    public void Backstage_BackgroundScopeDoesNotImplyBackstage_AndViceVersa()
    {
        var rig = new Rig(); rig.EnableTools(); rig.EnableBackstage();
        // background_tools scope cannot start Backstage…
        Assert.False(rig.Backstage.StartSession(BgCtx()).Ok);
        // …and the backstage scope cannot run background tools.
        var kill = rig.Service.KillProcess(Ctx(Scopes.Backstage), 100);
        Assert.False(kill.Ok);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
    }

    [Fact]
    public void Backstage_ActsByNonOwner_Refused_AndSessionCloseCarriesActCount()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var start = rig.Backstage.StartSession(Ctx(Scopes.Backstage));
        Assert.True(start.Ok, start.Reason);
        // D38 F9 (amended): ownership is the PAIRING ID — the
        // non-owner context is a different pairing, not just a
        // different self-reported name.
        var stranger = new BackgroundCallContext("pair-2", "someone-else",
            new HashSet<string> { Scopes.Backstage }, Dev);
        Assert.False(rig.Backstage.RecordAct(stranger, start.Session!.SessionId, "snoop"));
        Assert.True(rig.Backstage.RecordAct(Ctx(Scopes.Backstage), start.Session.SessionId, "restarted print spooler"));
        Assert.False(rig.Backstage.EndSession(stranger, start.Session.SessionId));
        Assert.True(rig.Backstage.EndSession(Ctx(Scopes.Backstage), start.Session.SessionId));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_act_refused");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_session_ended" && e.Detail.Contains("acts=1"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- process-kill abuse shapes: the consent surface defends itself ----------------------

    [Theory]
    [InlineData("AcpCore")]
    [InlineData("acpcore.exe")]
    [InlineData("ACP.SessionAgent")]
    [InlineData("Acp.SessionAgent.exe")]
    public void Protected_KillAcpProcesses_ByResolvedName_Refused_ProcessSurvives(string name)
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.Processes[777] = new BackgroundProcessInfo(777, 1, name, 10_000);
        var result = rig.Service.KillProcess(BgCtx(), 777);
        Assert.False(result.Ok);
        Assert.Contains("consent surface", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(777));
        Assert.DoesNotContain(rig.Exec.Calls, c => c == "kill:777");
    }

    [Fact]
    public void Protected_TreeContainingAcpChild_RefusesWhole_NothingInTreeKilled()
    {
        var rig = new Rig(); rig.EnableTools();
        // pid 500 "evil-parent" is innocuous; its child 501 is the
        // ACP session agent (presence + STOP). The whole tree refuses.
        var result = rig.Service.KillProcessTree(BgCtx(), 500);
        Assert.False(result.Ok);
        Assert.Contains("consent surface", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(500));
        Assert.True(rig.Exec.Processes.ContainsKey(501));
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("kill:"));
    }

    [Fact]
    public void Protected_StopOrRestartAcpService_Refused_ServiceStillRunning()
    {
        var rig = new Rig(); rig.EnableTools();
        Assert.False(rig.Service.StopService(BgCtx(), "AcpCore").Ok);
        Assert.False(rig.Service.RestartService(BgCtx(), "acpcore").Ok);
        Assert.Equal("Running", rig.Exec.Services["AcpCore"].State);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.Contains("AcpCore") && c.StartsWith("service_"));
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\ACP\Pairings")]
    [InlineData(@"HKEY_LOCAL_MACHINE\Software\AgenticControl\Policy")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\AcpCore")]
    [InlineData(@"software/acp")]
    public void Protected_RegistryWritesAndDeletesToAcpKeys_Refused(string key)
    {
        var rig = new Rig(); rig.EnableTools();
        Assert.False(rig.Service.RegistrySet(BgCtx(), key, "Tamper", "1").Ok);
        Assert.False(rig.Service.RegistryDelete(BgCtx(), key, "Tamper").Ok);
        Assert.False(rig.Service.RegistryGet(BgCtx(), key, "Tamper").Ok);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("registry_set") || c.StartsWith("registry_delete"));
        // A neighbouring vendor key is NOT protected — the guard is
        // scoped to ACP's own keys, not a registry lockdown.
        Assert.True(rig.Service.RegistrySet(BgCtx(), @"HKLM\SOFTWARE\Vendor\App", "Mode", "Auto").Ok);
    }

    [Fact]
    public void Protected_KitToolPointedAtAcpProcess_Refused()
    {
        var rig = new Rig(); rig.EnableTools();
        var bytes = Encoding.UTF8.GetBytes("taskkill-clone");
        rig.Exec.SeedKitBytes("site-kit", "diag", "taskkill-clone");
        var kit = new ToolboxKit("site-kit", "site-kit", 1, KitOwnerKinds.Shared, "team",
            new[] { new KitToolDefinition("diag", "tools/diag.exe", KitToolDefinition.HashBytes(bytes)) });
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        var run = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "AcpCore.exe");
        Assert.False(run.Ok);
        Assert.Contains("consent surface", run.Detail);
        Assert.Empty(rig.Exec.KitRuns);
    }

    // ---- signed-command games -----------------------------------------------------------------

    [Fact]
    public void Signed_ForgedEnvelope_Refused_NothingExecutes()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var strangerSigner = new SignedCommandSigner(stranger);
        var payload = Encoding.UTF8.GetBytes("""{"tool":"process_kill"}""");
        var forged = strangerSigner.Sign(SignedCommandClasses.BackgroundAction, payload, T0, TimeSpan.FromMinutes(5));
        var ctx = new BackgroundCallContext("pair-1", "tech-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev, forged.ToJson());
        var result = rig.Service.KillProcess(ctx, 100);
        Assert.False(result.Ok);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "signed_command_refused");
    }

    [Fact]
    public void Signed_EnvelopeForDifferentTool_ExecutesNothingHere()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        // A genuine envelope — but minted for the registry editor.
        // Presented to the process kill path it must execute nothing.
        var payload = Encoding.UTF8.GetBytes("""{"tool":"registry_set"}""");
        // D38 F1 (amended): addressed to this device, so the refusal
        // under test is the tool mismatch, not the audience check.
        var env = rig.Signer.Sign(SignedCommandClasses.BackgroundAction, payload, T0, TimeSpan.FromMinutes(5), Dev);
        var ctx = new BackgroundCallContext("pair-1", "tech-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev, env.ToJson());
        var result = rig.Service.KillProcess(ctx, 100);
        Assert.False(result.Ok);
        Assert.Contains("what was signed", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
    }

    [Fact]
    public void Signed_PresentedButNoGateWired_RefusesNamed_NeverDowngradesSilently()
    {
        var rig = new Rig(withGate: false); rig.EnableTools();
        var ctx = new BackgroundCallContext("pair-1", "tech-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev, "{\"Version\":1}");
        var result = rig.Service.KillProcess(ctx, 100);
        Assert.False(result.Ok);
        Assert.Contains("no customer command key", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
    }
}

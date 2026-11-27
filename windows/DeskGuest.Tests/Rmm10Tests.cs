using System.Text;
using DeskGuest.Shared.BackgroundTools;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-10 — Background tools: fix without taking the screen.
// Toolset gates (policy setting key default OFF, dedicated scope,
// signed hub initiation), the four tool families, hash-pinned kits,
// session history, and the Backstage capability gate happy path.
// Attack shapes live in Rmm10DestructionTests.
public class Rmm10Tests
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
            Exec.Processes[200] = new BackgroundProcessInfo(200, 100, "worker", 20_000);
            Exec.Processes[300] = new BackgroundProcessInfo(300, 200, "subworker", 30_000);
            Exec.Services["Niagara"] = new BackgroundServiceInfo("Niagara", "Niagara", "Stopped");
            Exec.Directories[@"C:\Temp"] = new List<BackgroundFileEntry>
            {
                new("a.txt", false, 5), new("sub", true, null),
            };
            Exec.Files[@"C:\Temp\a.txt"] = "hello";
        }

        public void SetPolicy(string key, string value, long rev = 1) =>
            Assert.True(Policy.AddDocument(new ManagementPolicyDocument(
                $"doc-{key}-{rev}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev)).Allowed);

        public void EnableTools(long rev = 1) => SetPolicy(BackgroundPolicyKeys.ToolsEnabled, "true", rev);
        public void EnableBackstage(long rev = 1) => SetPolicy(BackgroundPolicyKeys.BackstageEnabled, "true", rev);
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

    // ---- policy + surface -------------------------------------------------

    [Fact]
    public void Toolset_SettingKey_DefaultsOff_UntilPolicyEnables()
    {
        var rig = new Rig();
        Assert.False(rig.Policy.IsEnabled(rig.Facts, BackgroundPolicyKeys.ToolsEnabled));
        rig.EnableTools();
        Assert.True(rig.Policy.IsEnabled(rig.Facts, BackgroundPolicyKeys.ToolsEnabled));
    }

    [Fact]
    public void Surface_PolicyOff_ToolsetDoesNotExist_EvenWithScope()
    {
        var rig = new Rig();
        Assert.Empty(rig.Service.Surface.AvailableTools(rig.Facts, BgCtx().PairingScopes));
        rig.EnableTools();
        Assert.Equal(BackgroundTools.All.OrderBy(t => t), rig.Service.Surface
            .AvailableTools(rig.Facts, BgCtx().PairingScopes).OrderBy(t => t));
    }

    [Fact]
    public void Surface_NoBackgroundScope_NothingListed_AndPerToolDisableRemovesOne()
    {
        var rig = new Rig();
        rig.EnableTools();
        Assert.Empty(rig.Service.Surface.AvailableTools(rig.Facts,
            new HashSet<string> { Scopes.Observe, Scopes.Drive, Scopes.Shell, Scopes.Admin }));
        rig.SetPolicy(BackgroundPolicyKeys.ToolEnabled(BackgroundTools.RegistrySet), "false", rev: 7);
        var tools = rig.Service.Surface.AvailableTools(rig.Facts, BgCtx().PairingScopes);
        Assert.DoesNotContain(BackgroundTools.RegistrySet, tools);
        Assert.Contains(BackgroundTools.ProcessKill, tools);
    }

    // ---- process manager -----------------------------------------------------

    [Fact]
    public void KillProcess_HappyPath_AuditedChained_AndFiledInSessionHistory()
    {
        var rig = new Rig(); rig.EnableTools();
        var result = rig.Service.KillProcess(BgCtx(), 100);
        Assert.True(result.Ok, result.Detail);
        Assert.False(rig.Exec.Processes.ContainsKey(100));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_started" && e.Detail.Contains("process_kill"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_completed");
        Assert.True(rig.Audit.Verify().Ok);
        var history = Assert.Single(rig.Service.SessionHistory);
        Assert.Equal("completed", history.Outcome);
        Assert.Equal("tech-1", history.ActorName);
    }

    [Fact]
    public void KillProcessTree_KillsRootAndAllDescendants()
    {
        var rig = new Rig(); rig.EnableTools();
        var result = rig.Service.KillProcessTree(BgCtx(), 100);
        Assert.True(result.Ok, result.Detail);
        Assert.Empty(rig.Exec.Processes);
        Assert.Contains("killed 3/3", result.Detail);
    }

    [Fact]
    public void KillProcess_UnknownPid_Refused_Audited_NothingKilled()
    {
        var rig = new Rig(); rig.EnableTools();
        var result = rig.Service.KillProcess(BgCtx(), 999);
        Assert.False(result.Ok);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("kill:"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_refused");
    }

    // ---- service manager -------------------------------------------------------

    [Fact]
    public void ServiceManager_StartStopRestart_StateChangesAndAudit()
    {
        var rig = new Rig(); rig.EnableTools();
        Assert.True(rig.Service.StartService(BgCtx(), "Niagara").Ok);
        Assert.Equal("Running", rig.Exec.Services["Niagara"].State);
        Assert.True(rig.Service.StopService(BgCtx(), "Niagara").Ok);
        Assert.Equal("Stopped", rig.Exec.Services["Niagara"].State);
        Assert.True(rig.Service.RestartService(BgCtx(), "Niagara").Ok);
        Assert.Equal("Running", rig.Exec.Services["Niagara"].State);
        Assert.Equal(3, rig.Audit.Entries.Count(e => e.Kind == "background_action_completed"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- file browser --------------------------------------------------------------

    [Fact]
    public void FileBrowser_ListReadDelete()
    {
        var rig = new Rig(); rig.EnableTools();
        var list = rig.Service.ListFiles(BgCtx(), @"C:\Temp");
        Assert.True(list.Ok, list.Detail);
        Assert.Contains("a.txt", list.Output);
        var read = rig.Service.ReadFile(BgCtx(), @"C:\Temp\a.txt");
        Assert.True(read.Ok);
        Assert.Equal("hello", read.Output);
        Assert.True(rig.Service.DeleteFile(BgCtx(), @"C:\Temp\a.txt").Ok);
        Assert.False(rig.Exec.Files.ContainsKey(@"C:\Temp\a.txt"));
    }

    // ---- registry editor ---------------------------------------------------------------

    [Fact]
    public void RegistryEditor_SetGetDelete_RoundTrips()
    {
        var rig = new Rig(); rig.EnableTools();
        const string key = @"HKLM\SOFTWARE\Vendor\App";
        Assert.True(rig.Service.RegistrySet(BgCtx(), key, "Mode", "Auto").Ok);
        var got = rig.Service.RegistryGet(BgCtx(), key, "Mode");
        Assert.True(got.Ok);
        Assert.Equal("Auto", got.Output);
        Assert.True(rig.Service.RegistryDelete(BgCtx(), key, "Mode").Ok);
        Assert.False(rig.Service.RegistryGet(BgCtx(), key, "Mode").Ok);
    }

    // ---- kits ------------------------------------------------------------------------------

    private static ToolboxKit MakeKit(RecordingBackgroundExecutor exec, string id, string ownerKind, string ownerId,
        string toolName = "diag", string content = "diag-bytes-v1")
    {
        exec.SeedKitBytes(id, toolName, content);
        var pin = KitToolDefinition.HashBytes(Encoding.UTF8.GetBytes(content));
        return new ToolboxKit(id, id, 1, ownerKind, ownerId,
            new[] { new KitToolDefinition(toolName, $"tools/{toolName}.exe", pin) });
    }

    [Fact]
    public void Kit_SharedKit_AdmitAndRun_HappyPath()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig.Exec, "site-kit", KitOwnerKinds.Shared, "team-controls");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        var run = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "--quick");
        Assert.True(run.Ok, run.Detail);
        Assert.Single(rig.Exec.KitRuns);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_kit_admitted");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Kit_PersonalKit_RunsForOwner_RefusesForAnotherPairing()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig.Exec, "my-kit", KitOwnerKinds.Personal, "pair-1");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        Assert.True(rig.Service.RunKitTool(BgCtx(), "my-kit", "diag", "").Ok);
        var stranger = new BackgroundCallContext("pair-9", "tech-9",
            new HashSet<string> { Scopes.BackgroundTools }, Dev);
        var refused = rig.Service.RunKitTool(stranger, "my-kit", "diag", "");
        Assert.False(refused.Ok);
        Assert.Contains("personal kit", refused.Detail);
        Assert.Single(rig.Exec.KitRuns); // only the owner's run executed
    }

    // ---- signed hub initiation -------------------------------------------------------------

    [Fact]
    public void SignedHubAction_VerifiedEnvelope_ExecutesTheSignedTool()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        // D38 F1 (amended): the signed payload binds the TARGET
        // (pid) as well as the tool, and the envelope is addressed
        // to this device (audience).
        var payload = Encoding.UTF8.GetBytes("""{"tool":"process_kill","pid":100}""");
        var env = rig.Signer.Sign(SignedCommandClasses.BackgroundAction, payload, T0, TimeSpan.FromMinutes(5), Dev);
        var ctx = new BackgroundCallContext("pair-1", "tech-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev, env.ToJson());
        var result = rig.Service.KillProcess(ctx, 100);
        Assert.True(result.Ok, result.Detail);
        Assert.False(rig.Exec.Processes.ContainsKey(100));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "signed_command_accepted");
    }

    // ---- Backstage happy path ------------------------------------------------------------------

    [Fact]
    public void Backstage_PolicyAndSeparateScope_StartActEnd_AllLogged_AndInDeviceHistory()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var ctx = Ctx(Scopes.Backstage);
        Assert.True(rig.Backstage.ExistsInSurface(rig.Facts, ctx.PairingScopes));

        var start = rig.Backstage.StartSession(ctx);
        Assert.True(start.Ok, start.Reason);
        Assert.Single(rig.BackstageSink.Opened);
        // The session is in the device's history from its first instant.
        Assert.Contains(rig.Service.SessionHistory,
            h => h.Kind == "backstage" && h.SessionId == start.Session!.SessionId && h.Outcome == "started");

        Assert.True(rig.Backstage.RecordAct(ctx, start.Session!.SessionId, "opened services console"));
        rig.Now = T0.AddMinutes(4);
        Assert.True(rig.Backstage.EndSession(ctx, start.Session.SessionId));
        Assert.Single(rig.BackstageSink.Closed);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_session_started");
        // LANE W1 REPAIR (bd-shared-rmm-1 F7): caller-supplied act
        // text is AuditText-escaped in the audit detail now (an
        // act carrying " outcome=allowed" must not mint a field),
        // so the logged form is the escaped one.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_act" && e.Detail.Contains("opened_services_console"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_session_ended" && e.Detail.Contains("acts=1"));
        Assert.True(rig.Audit.Verify().Ok);
        var (total, last, backstageCount, refusedCount) = rig.Service.DescribePresenceActivity();
        Assert.Equal(1, backstageCount);
        Assert.True(total >= 2); // start + end history entries at minimum
        Assert.Equal(0, refusedCount);
        Assert.NotNull(last);
    }
}

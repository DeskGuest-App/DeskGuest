using System.Text;
using System.Text.Json;
using Acp.Core.Modules;
using Acp.Shared.BackgroundTools;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

// RMM-10 D38 FIX — regression tests for the 12 cross-review
// findings (packet 87805cb2). Every test here names the finding it
// pins. Fakes only — no real process, service, file or registry is
// touched.
public class Rmm10FixTests
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
        public List<string> PresencePushes = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public CustomerCommandKeyRing Ring = new();
        public SignedCommandGate Gate;
        public SignedCommandSigner Signer;

        public Rig(bool withGate = false, TimeSpan? backstageMax = null)
        {
            Ring.AddCurrent(Customer.PublicKey);
            Gate = new SignedCommandGate(new SignedCommandVerifier(Ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            Service = new BackgroundToolsService(Audit, Policy,
                id => id == Dev ? Facts : null, Exec, new ExecutorKitByteStore(Exec),
                withGate ? Gate : null, () => Now);
            Backstage = new BackstageService(Audit, Policy,
                id => id == Dev ? Facts : null, BackstageSink, Service, () => Now,
                backstageMax, (evt, id) => PresencePushes.Add($"{evt}:{id}"));

            Exec.Processes[100] = new BackgroundProcessInfo(100, 1, "notepad", 10_000);
            Exec.Processes[200] = new BackgroundProcessInfo(200, 1, "worker", 20_000);
            Exec.Processes[400] = new BackgroundProcessInfo(400, 1, "AcpCore", 50_000,
                @"C:\Program Files\ACP\AcpCore.exe");
            Exec.Services["Niagara"] = new BackgroundServiceInfo("Niagara", "Niagara", "Running");
            Exec.Services["AcpWatchdog"] = new BackgroundServiceInfo("AcpWatchdog", "Watchdog Svc", "Running");
            Exec.Files[@"C:\Temp\a.txt"] = "hello";
        }

        public void SetPolicy(string key, string value, long rev = 1, string docId = "doc") =>
            Assert.True(Policy.AddDocument(new ManagementPolicyDocument(
                docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, rev)).Allowed);

        public void EnableTools() => SetPolicy(BackgroundPolicyKeys.ToolsEnabled, "true", docId: "tools-on");
        public void EnableBackstage() => SetPolicy(BackgroundPolicyKeys.BackstageEnabled, "true", docId: "bs-on");

        public string Sign(string payloadJson, string audience = Dev)
        {
            var env = Signer.Sign(SignedCommandClasses.BackgroundAction,
                Encoding.UTF8.GetBytes(payloadJson), Now, TimeSpan.FromMinutes(5), audience);
            return env.ToJson();
        }
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
    private static BackgroundCallContext SignedCtx(string signedJson) => new(
        "pair-1", "tech-1", new HashSet<string> { Scopes.BackgroundTools }, Dev, signedJson);

    private static ToolboxKit MakeKit(Rig rig, string id, string ownerKind, string ownerId,
        string toolName = "diag", string content = "diag-bytes")
    {
        rig.Exec.SeedKitBytes(id, toolName, content);
        var pin = KitToolDefinition.HashBytes(Encoding.UTF8.GetBytes(content));
        return new ToolboxKit(id, id, 1, ownerKind, ownerId,
            new[] { new KitToolDefinition(toolName, $"tools/{toolName}.exe", pin) });
    }

    // ---- F1: the signed payload binds the TARGET and the device -------------

    [Fact]
    public void F1_EnvelopeForOnePid_AuthorizesNoOtherPid()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var ctx = SignedCtx(rig.Sign("""{"tool":"process_kill","pid":100}"""));
        var substituted = rig.Service.KillProcess(ctx, 200);
        Assert.False(substituted.Ok);
        Assert.Contains("what was signed", substituted.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(200));
        Assert.True(rig.Exec.Processes.ContainsKey(100)); // nothing ran at all
        // …and the SAME envelope against its signed target works.
        Assert.True(rig.Service.KillProcess(SignedCtx(rig.Sign("""{"tool":"process_kill","pid":100}""")), 100).Ok);
    }

    [Fact]
    public void F1_EnvelopeAddressedToAnotherDevice_RefusedHere()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var ctx = SignedCtx(rig.Sign("""{"tool":"process_kill","pid":100}""", audience: "dev-2"));
        var result = rig.Service.KillProcess(ctx, 100);
        Assert.False(result.Ok);
        Assert.Contains("audience", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
    }

    [Fact]
    public void F1_RegistryEnvelope_BindsKeyAndValue()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var signed = rig.Sign("""{"tool":"registry_set","key":"HKLM\\SOFTWARE\\Vendor\\App","value_name":"Mode","value":"Auto"}""");
        var ok = rig.Service.RegistrySet(SignedCtx(signed), @"HKLM\SOFTWARE\Vendor\App", "Mode", "Auto");
        Assert.True(ok.Ok, ok.Detail);
        var tampered = rig.Service.RegistrySet(SignedCtx(rig.Sign(
            """{"tool":"registry_set","key":"HKLM\\SOFTWARE\\Vendor\\App","value_name":"Mode","value":"Auto"}""")),
            @"HKLM\SOFTWARE\Vendor\App", "Mode", "Manual");
        Assert.False(tampered.Ok);
    }

    // ---- F2: 'local' must be established; posture is distinguishable --------

    [Fact]
    public void F2_GateWired_NoEnvelope_NotEstablishedLocal_Refused()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var result = rig.Service.KillProcess(BgCtx(), 100);
        Assert.False(result.Ok);
        Assert.Contains("not established as local", result.Detail);
        Assert.True(rig.Exec.Processes.ContainsKey(100));
    }

    [Fact]
    public void F2_EstablishedLocalCall_Proceeds_AndPosturesDifferInAudit()
    {
        var rig = new Rig(withGate: true); rig.EnableTools();
        var local = new BackgroundCallContext("pair-1", "tech-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev, null, LocalOrigin: true);
        Assert.True(rig.Service.KillProcess(local, 100).Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_started" && e.Detail.Contains("posture=local_origin"));
        var signed = SignedCtx(rig.Sign("""{"tool":"process_kill","pid":200}"""));
        Assert.True(rig.Service.KillProcess(signed, 200).Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "background_action_started" && e.Detail.Contains("posture=signed"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- F3: registry aliases and adjacent tamper keys -----------------------

    [Theory]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\AcpCore")]        // CurrentControlSet alias
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\AcpWatchdog")] // the watchdog's own service key
    [InlineData(@"HKLM\SOFTWARE\WOW6432Node\ACP\Policy")]               // 32-bit view
    [InlineData(@"HKU\S-1-5-21-100\Software\ACP\Pairings")]             // per-user hive path
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcpCore.exe")] // IFEO hijack
    [InlineData(@"HKLM\\SOFTWARE\\ACP\\Pairings")]                      // repeated separators
    public void F3_RegistryAliasForms_OfProtectedKeys_Refused(string key)
    {
        var rig = new Rig(); rig.EnableTools();
        Assert.False(rig.Service.RegistrySet(BgCtx(), key, "Tamper", "1").Ok);
        Assert.False(rig.Service.RegistryDelete(BgCtx(), key, "Tamper").Ok);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("registry_set") || c.StartsWith("registry_delete"));
    }

    [Fact]
    public void F3_RunKeyLaunchEntry_ForAcpBinary_Refused_NeighbourWritable()
    {
        var rig = new Rig(); rig.EnableTools();
        const string run = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        Assert.False(rig.Service.RegistrySet(BgCtx(), run, "AcpCore", @"C:\Program Files\ACP\AcpCore.exe").Ok);
        Assert.True(rig.Service.RegistrySet(BgCtx(), run, "VendorApp", @"C:\Vendor\app.exe").Ok);
        Assert.True(rig.Service.RegistrySet(BgCtx(), @"HKLM\SOFTWARE\Vendor\App", "Mode", "Auto").Ok);
    }

    // ---- F4: file tools carry the consent-surface protection ------------------

    [Fact]
    public void F4_FileDeleteAndRead_OfAcpFiles_Refused_FilesSurvive()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.Files[@"C:\Program Files\ACP\AcpCore.exe"] = "binary";
        rig.Exec.Files[@"C:\ProgramData\ACP\pairings.json"] = "secrets";
        Assert.False(rig.Service.DeleteFile(BgCtx(), @"C:\Program Files\ACP\AcpCore.exe").Ok);
        Assert.False(rig.Service.ReadFile(BgCtx(), @"C:\ProgramData\ACP\pairings.json").Ok);
        Assert.False(rig.Service.DeleteFile(BgCtx(), @"C:\ProgramData\ACP\audit.log").Ok);
        Assert.True(rig.Exec.Files.ContainsKey(@"C:\Program Files\ACP\AcpCore.exe"));
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("file_delete") || c.StartsWith("file_read"));
        // Ordinary files are unaffected.
        Assert.True(rig.Service.DeleteFile(BgCtx(), @"C:\Temp\a.txt").Ok);
    }

    // ---- F5: kit admission is gated; kit argument screening is real -----------

    [Fact]
    public void F5_KitRun_PidArgumentNamingAcpProcess_Refused()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig, "site-kit", KitOwnerKinds.Shared, "team");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        var byPid = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "taskkill /F /PID 400");
        Assert.False(byPid.Ok);
        Assert.Contains("consent surface", byPid.Detail);
        var byWildcard = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", "/IM acp*");
        Assert.False(byWildcard.Ok);
        Assert.Empty(rig.Exec.KitRuns);
    }

    [Fact]
    public void F5_AdmitKit_RequiresScopeAndPolicy()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig, "site-kit", KitOwnerKinds.Shared, "team");
        var scopeless = Ctx(Scopes.Shell, Scopes.Admin);
        Assert.False(rig.Service.AdmitKit(scopeless, kit).Ok);
        Assert.Empty(rig.Service.Kits);
        var offRig = new Rig(); // policy never enabled
        var kit2 = MakeKit(offRig, "site-kit", KitOwnerKinds.Shared, "team");
        Assert.False(offRig.Service.AdmitKit(KitAdminCtx(), kit2).Ok);
        Assert.Empty(offRig.Service.Kits);
    }

    // ---- F6: §7.10 — STOP path, live presence, mid-session re-checks ----------

    [Fact]
    public void F6_EndpointStop_EndsAnotherActorsSession_AndPresenceIsPushed()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var start = rig.Backstage.StartSession(Ctx(Scopes.Backstage));
        Assert.True(start.Ok, start.Reason);
        Assert.Contains(rig.PresencePushes, p => p.StartsWith("started:"));
        // The endpoint user — not the owner, not any pairing — stops it.
        Assert.True(rig.Backstage.StopSession(start.Session!.SessionId, "endpoint-user"));
        Assert.Contains(rig.BackstageSink.Closed, c => c == start.Session.SessionId);
        Assert.False(rig.Backstage.Sessions.Single().IsActive);
        Assert.Contains(rig.PresencePushes, p => p.StartsWith("stopped:"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "backstage_session_ended" && e.Detail.Contains("how=stopped"));
    }

    [Fact]
    public void F6_PolicyFlippedOffMidSession_NextActRefused_AndSessionEnded()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var ctx = Ctx(Scopes.Backstage);
        var start = rig.Backstage.StartSession(ctx);
        Assert.True(start.Ok, start.Reason);
        Assert.True(rig.Backstage.RecordAct(ctx, start.Session!.SessionId, "first act"));
        rig.SetPolicy(BackgroundPolicyKeys.BackstageEnabled, "false", rev: 2, docId: "bs-on");
        Assert.False(rig.Backstage.RecordAct(ctx, start.Session.SessionId, "second act"));
        Assert.False(rig.Backstage.Sessions.Single().IsActive);
    }

    [Fact]
    public void F6_SessionPastMaxDuration_EndsItselfAtNextAct()
    {
        var rig = new Rig(backstageMax: TimeSpan.FromMinutes(1)); rig.EnableBackstage();
        var ctx = Ctx(Scopes.Backstage);
        var start = rig.Backstage.StartSession(ctx);
        Assert.True(start.Ok, start.Reason);
        rig.Now = T0.AddMinutes(2);
        Assert.False(rig.Backstage.RecordAct(ctx, start.Session!.SessionId, "too late"));
        Assert.False(rig.Backstage.Sessions.Single().IsActive);
        Assert.Contains(rig.PresencePushes, p => p.StartsWith("expired:"));
    }

    // ---- F7: protection judges the RESOLVED service / process ------------------

    [Fact]
    public void F7_StopService_ByDisplayName_ResolvesAndRefuses()
    {
        var rig = new Rig(); rig.EnableTools();
        // "Watchdog Svc" is not in the protected name set — only
        // RESOLUTION reveals it is AcpWatchdog's display name.
        Assert.False(rig.Service.StopService(BgCtx(), "Watchdog Svc").Ok);
        Assert.Equal("Running", rig.Exec.Services["AcpWatchdog"].State);
        Assert.DoesNotContain(rig.Exec.Calls, c => c.StartsWith("service_stop"));
    }

    [Fact]
    public void F7_ProcessReportedAsFullPath_StillProtected()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.Processes[777] = new BackgroundProcessInfo(777, 1, @"C:\Program Files\ACP\AcpCore.exe", 10_000);
        Assert.False(rig.Service.KillProcess(BgCtx(), 777).Ok);
        Assert.True(rig.Exec.Processes.ContainsKey(777));
    }

    // ---- F8: instance identity, not bare name -----------------------------------

    [Fact]
    public void F8_SameNamedBinaryOutsideAcpRoots_IsNotAcp_AndKills()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.Processes[778] = new BackgroundProcessInfo(778, 1, "acpcore.exe", 10_000, @"C:\Tools\acpcore.exe");
        var result = rig.Service.KillProcess(BgCtx(), 778);
        Assert.True(result.Ok, result.Detail);
        Assert.False(rig.Exec.Processes.ContainsKey(778));
        // …while the genuine ACP instance (ACP install root) refuses.
        Assert.False(rig.Service.KillProcess(BgCtx(), 400).Ok);
        Assert.True(rig.Exec.Processes.ContainsKey(400));
    }

    // ---- F9: ownership is the pairing id, never the self-reported name ---------

    [Fact]
    public void F9_PersonalKit_NameImpersonation_Refused()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig, "my-kit", KitOwnerKinds.Personal, "pair-1");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        // Attacker pairing NAMES itself after the owner id.
        var impersonator = new BackgroundCallContext("pair-2", "pair-1",
            new HashSet<string> { Scopes.BackgroundTools }, Dev);
        Assert.False(rig.Service.RunKitTool(impersonator, "my-kit", "diag", "").Ok);
        Assert.Empty(rig.Exec.KitRuns);
        Assert.True(rig.Service.RunKitTool(BgCtx(), "my-kit", "diag", "").Ok);
    }

    [Fact]
    public void F9_Backstage_NameImpersonation_CannotActOrEnd()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var owner = Ctx(Scopes.Backstage);
        var start = rig.Backstage.StartSession(owner);
        Assert.True(start.Ok, start.Reason);
        var impersonator = new BackgroundCallContext("pair-2", "tech-1",
            new HashSet<string> { Scopes.Backstage }, Dev);
        Assert.False(rig.Backstage.RecordAct(impersonator, start.Session!.SessionId, "snoop"));
        Assert.False(rig.Backstage.EndSession(impersonator, start.Session.SessionId));
        Assert.True(rig.Backstage.Sessions.Single().IsActive);
        Assert.True(rig.Backstage.EndSession(owner, start.Session.SessionId));
    }

    // ---- F10: history is bounded; refusals don't inflate activity ---------------

    [Fact]
    public void F10_RefusalFlood_HistoryStaysBounded()
    {
        var rig = new Rig(); rig.EnableBackstage();
        var scopeless = Ctx(Scopes.Shell);
        for (var i = 0; i < BackgroundToolsService.MaxHistoryEntries + 100; i++)
            rig.Backstage.StartSession(scopeless);
        Assert.True(rig.Service.SessionHistory.Count <= BackgroundToolsService.MaxHistoryEntries,
            $"history grew to {rig.Service.SessionHistory.Count}");
    }

    [Fact]
    public void F10_PresenceActivity_RefusalsCountedSeparately()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Service.KillProcess(Ctx(Scopes.Shell), 100); // refused (scope)
        Assert.True(rig.Service.KillProcess(BgCtx(), 100).Ok);
        var (total, _, _, refused) = rig.Service.DescribePresenceActivity();
        Assert.Equal(1, total);
        Assert.Equal(1, refused);
    }

    // ---- F11: no executor touch before the chained start entry; no unaudited throws

    [Fact]
    public void F11_TreeKill_ExecutorThrows_StartEntryPrecedesError_NothingUnaudited()
    {
        var rig = new Rig(); rig.EnableTools();
        rig.Exec.ThrowOn.Add("list_processes");
        var result = rig.Service.KillProcessTree(BgCtx(), 100);
        Assert.False(result.Ok);
        var kinds = rig.Audit.Entries.Select(e => e.Kind).ToList();
        var started = kinds.IndexOf("background_action_started");
        var error = kinds.IndexOf("background_action_error");
        Assert.True(started >= 0 && error > started, $"started={started} error={error}");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void F11_KitRun_NullArguments_NoThrow_Audited()
    {
        var rig = new Rig(); rig.EnableTools();
        var kit = MakeKit(rig, "site-kit", KitOwnerKinds.Shared, "team");
        Assert.True(rig.Service.AdmitKit(KitAdminCtx(), kit).Ok);
        var run = rig.Service.RunKitTool(BgCtx(), "site-kit", "diag", null!);
        Assert.True(run.Ok, run.Detail);
        Assert.Single(rig.Exec.KitRuns);
    }

    [Fact]
    public async Task F11_Module_NonStringSignedCommand_DoesNotThrow()
    {
        var rig = new Rig(); rig.EnableTools();
        var module = new BackgroundProcessKillModule(rig.Service);
        using var doc = JsonDocument.Parse("""{"pid":100,"signed_command":123}""");
        var ctx = new ToolExecutionContext(
            new Pairing("pair-1", "tech-1", new HashSet<string> { Scopes.BackgroundTools }, T0, null, null, false),
            TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "unused");
        var result = await module.ExecuteAsync(doc.RootElement.Clone(), ctx, CancellationToken.None);
        Assert.False(result.Ok); // device-id binding unbound in this rig — fails closed, never throws
    }

    // ---- F12: audit details cannot be field-injected by target text --------------

    [Fact]
    public void F12_TargetText_CannotInjectAuditFields()
    {
        var rig = new Rig(); rig.EnableTools();
        var evil = @"C:\x pairing=pair-admin posture=signed";
        rig.Service.DeleteFile(BgCtx(), evil);
        Assert.All(rig.Audit.Entries, e => Assert.DoesNotContain("pairing=pair-admin", e.Detail));
        Assert.Contains(rig.Audit.Entries, e => e.Detail.Contains("pairing%3Dpair-admin"));
        Assert.True(rig.Audit.Verify().Ok);
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Services;
using DeskGuest.Shared.ApplicationControl;
using DeskGuest.Shared.Deployment;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.DirectoryEnrollment;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.HealthScoring;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.PeripheralControl;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>BD-WIN-CORE-3 fix lane regression tests (packet
/// b4a4f57a) plus the W4-A host-wiring remainders (verify_install
/// probe, mobile store persistence). One or more tests per finding,
/// named F&lt;n&gt;_* / W&lt;n&gt;_*; several re-attack the fixed
/// surface (destruction discipline). Windows-native execution paths
/// (PowerShell, registry, named pipes) cannot run in this sandbox —
/// those surfaces are pinned at their pure seams and reported
/// untested-on-Windows in the lane log.</summary>
public class BdWinCore3FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    // ================= F1: mesh identity through the pairing =================

    private sealed class MeshWorld
    {
        public PairingService Pairings = new(new DevOnlyPassThroughProtector());
        public RosterService Roster = new(new EnrollmentService());
        public MeshIdentityResolver Resolver;
        public MeshWorld()
        {
            Roster.CreateScope("co-1", "company", "Acme");
            Roster.CreateUser("ctrl", "co-1", "Controller", "human");
            Resolver = new MeshIdentityResolver(Pairings, Roster);
        }
        public string TokenFor(string agentName)
        {
            var code = Pairings.CreatePairingCode(agentName, TimeSpan.FromMinutes(5));
            var exchange = Pairings.ExchangeCode(code, agentName);
            Assert.True(exchange is not null);
            return exchange!.BearerToken;
        }
    }

    [Fact]
    public void F1_Resolver_ValidPairingToken_ResolvesToRosterUser()
    {
        var w = new MeshWorld();
        var token = w.TokenFor("Controller");
        Assert.Equal("ctrl", w.Resolver.ResolveUserId("Bearer " + token));
        Assert.True(w.Resolver.IsAuthenticated("Bearer " + token));
    }

    [Fact]
    public void F1_Resolver_FailsClosed_OnEveryForgery()
    {
        var w = new MeshWorld();
        var token = w.TokenFor("Controller");
        Assert.Null(w.Resolver.ResolveUserId(null));
        Assert.Null(w.Resolver.ResolveUserId(""));
        Assert.Null(w.Resolver.ResolveUserId(token)); // no Bearer scheme
        Assert.Null(w.Resolver.ResolveUserId("Bearer not-a-token"));
        Assert.Null(w.Resolver.ResolveUserId("Bearer " + token + "x"));
        // Revoked pairing: dead on the next check.
        var pairingId = w.Pairings.Authenticate(token)!.Id;
        Assert.True(w.Pairings.Revoke(pairingId));
        Assert.Null(w.Resolver.ResolveUserId("Bearer " + token));
    }

    [Fact]
    public void F1_Resolver_AmbiguousOrSuspendedName_ResolvesToNobody()
    {
        var w = new MeshWorld();
        // A second live user with the SAME display name in another
        // scope makes the name ambiguous — nobody resolves.
        w.Roster.CreateScope("co-2", "company", "Other");
        w.Roster.CreateUser("ctrl-2", "co-2", "Controller", "human");
        var token = w.TokenFor("Controller");
        Assert.Null(w.Resolver.ResolveUserId("Bearer " + token));

        var w2 = new MeshWorld();
        Assert.True(w2.Roster.SetUserSuspended("co-1", "ctrl", true));
        var token2 = w2.TokenFor("Controller");
        Assert.Null(w2.Resolver.ResolveUserId("Bearer " + token2));
    }

    private sealed class FakeChannel : IAgentChannel
    {
        public bool AgentConnected { get; set; } = true;
        public List<(string Tool, string Args)> Calls { get; } = new();
        public Func<string, string, ToolResult> Handler { get; set; } = (_, _) => ToolResult.Success("ok");
        public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
        {
            lock (Calls) Calls.Add((tool, argumentsJson));
            return Task.FromResult(Handler(tool, argumentsJson));
        }
        public int InputToolCalls => Calls.Count(c => c.Tool is "mouse_move_rel" or "mouse_move_abs_stream"
            or "button_here" or "key_press" or "type_text" or "scroll");
    }

    [Fact]
    public async Task F1_Stream_InputRunsUnderResolvedIdentity_NotBodyClaim()
    {
        // Session world (the win-core-4 fixture shape): ctrl holds
        // the floor, peer watches.
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        roster.CreateScope("company-1", "company", "Company A");
        roster.CreateUser("admin", "company-1", "Admin", "human");
        roster.AddCompanyAdmin("company-1", "admin");
        roster.CreateUser("host", "company-1", "Host User", "human");
        roster.CreateUser("ctrl", "company-1", "Controller", "human");
        roster.CreateUser("peer", "company-1", "Peer", "human");
        roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host", "peer" });
        roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" });
        roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" });
        var identity = new DeskGuest.Shared.Security.DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        var sessions = new SessionService(roster, enrollments);
        var channel = new FakeChannel
        {
            Handler = (tool, _) => tool == "stream_start"
                ? ToolResult.Success("{\"streaming\":true}") : ToolResult.Success("ok"),
        };
        var streams = new StreamService(channel, sessions, () => true, () => false,
            displayName: (scope, user) => roster.GetUser(scope, user)?.DisplayName);
        var s = sessions.CreateSession("company-1", device!.DeviceId, "ctrl", "attended", "lan", "none");
        Assert.NotNull(s);
        Assert.True(sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(sessions.StartSession(s.Id));
        Assert.True(sessions.GrantFloor(s.Id, "ctrl", "host"));

        // The identity the host wiring supplies: the pairing-bound
        // resolver output for the floor holder's agent name.
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var pcode = pairings.CreatePairingCode("Controller", TimeSpan.FromMinutes(5));
        var exchange = pairings.ExchangeCode(pcode, "Controller");
        var resolver = new MeshIdentityResolver(pairings, roster);
        var resolved = resolver.ResolveUserId("Bearer " + exchange!.BearerToken);
        Assert.Equal("ctrl", resolved);

        var body = JsonSerializer.Serialize(new
        {
            sessionId = s.Id,
            userId = "mallory", // body claim: worthless either way
            @event = new { type = "key", key = "enter" },
        });
        // No authenticated identity → 401, nothing reaches the agent.
        var refused = await streams.PostInputAsync(body, null, default);
        Assert.Equal(401, refused.Status);
        Assert.Equal(0, channel.InputToolCalls);
        // The resolved floor-holder identity → input flows.
        var accepted = await streams.PostInputAsync(body, resolved, default);
        Assert.Equal(200, accepted.Status);
        Assert.True(channel.InputToolCalls > 0);
    }

    // ================= F2/F3: OS policy writers (pure seams) =================

    [Fact]
    public void F2_AppLocker_ApplyShapeIsFixedScript_NeverDeviceText()
    {
        var args = AppLockerPolicyWriter.ApplyArguments(@"C:\DeskGuest\apply.ps1", @"C:\DeskGuest\policy.xml");
        Assert.Contains("-File", args);
        Assert.DoesNotContain(args, a => a.Contains("-Command") || a.Contains("$args"));
        Assert.Contains("param(", AppLockerPolicyWriter.ApplyScript);
        Assert.Contains("Set-AppLockerPolicy", AppLockerPolicyWriter.ApplyScript);
        Assert.Contains("-Merge", AppLockerPolicyWriter.ApplyScript);
        // A crafted device id can never become a path segment.
        var name = AppLockerPolicyWriter.PolicyFileName("../../evil\"; rm -rf");
        Assert.DoesNotContain("..", name);
        Assert.DoesNotContain("evil", name);
        Assert.StartsWith("applocker-", name);
        Assert.Equal(name, AppLockerPolicyWriter.PolicyFileName("../../evil\"; rm -rf"));
    }

    [Fact]
    public void F2_AppLocker_EnforceCarriesDefaultAllows_AuditDoesNot()
    {
        var rule = new AppRule("r1", RuleEffects.Deny, "path", null, null, null,
            @"C:\evil\bad.exe", "device", "dev-1", null, null);
        var enforce = new AppEnforcementPlan("dev-1", AppControlModes.Enforce, new[] { rule }, T0);
        var xml = AppLockerPolicyWriter.BuildPolicyXml(enforce);
        Assert.Contains("EnforcementMode=\"Enabled\"", xml);
        Assert.Contains("%WINDIR%", xml);
        Assert.Contains("%PROGRAMFILES%", xml);
        var audit = new AppEnforcementPlan("dev-1", AppControlModes.Audit, new[] { rule }, T0);
        var auditXml = AppLockerPolicyWriter.BuildPolicyXml(audit);
        Assert.Contains("EnforcementMode=\"AuditOnly\"", auditXml);
        Assert.DoesNotContain("%WINDIR%", auditXml);
    }

    [Fact]
    public void F2_AppLocker_PublisherRule_SplitsPublisherAndProduct()
    {
        var rule = new AppRule("r2", RuleEffects.Allow, "publisher", null, null,
            "Widget Pro", null, "device", "dev-1", null, null);
        // PublisherName comes from the signer anchor; with no signer
        // thumbprint the rule still renders a publisher condition
        // whose ProductName is the product — never "PublisherName=
        // product" (the pre-fix conflation).
        var xml = AppLockerPolicyWriter.BuildPolicyXml(
            new AppEnforcementPlan("dev-1", AppControlModes.Enforce, new[] { rule }, T0));
        Assert.Contains("FilePublisherCondition", xml);
        Assert.Contains("PublisherName=\"*\"", xml);
        Assert.Contains("ProductName=\"Widget Pro\"", xml);
    }

    [Fact]
    public void F3_DeviceControl_ClassesMapToSetupGuids_UnmappedRefuses()
    {
        var blockHid = new PeripheralRule("p1", PeripheralEffects.Block, PeripheralRuleKinds.Class,
            DeviceClasses.Hid, null, null, null, "device", "m1", null, null);
        var allowStorage = new PeripheralRule("p2", PeripheralEffects.Allow, PeripheralRuleKinds.Class,
            DeviceClasses.Storage, null, null, null, "device", "m1", null, null);
        var plan = new PeripheralEnforcementPlan("m1", PeripheralModes.Enforce, new[] { blockHid, allowStorage }, T0);
        var (denied, allowed, refusal) = DeviceControlPolicyWriter.BuildClassLists(plan);
        Assert.Null(refusal);
        Assert.Equal(new[] { "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" }, denied);
        Assert.Equal(new[] { "{4d36e967-e325-11ce-bfc1-08002be10318}" }, allowed);

        var alien = new PeripheralRule("p3", PeripheralEffects.Block, PeripheralRuleKinds.Class,
            "quantum-bus", null, null, null, "device", "m1", null, null);
        var bad = DeviceControlPolicyWriter.BuildClassLists(
            new PeripheralEnforcementPlan("m1", PeripheralModes.Enforce, new[] { alien }, T0));
        Assert.NotNull(bad.Refusal);
        Assert.Contains("quantum-bus", bad.Refusal);
    }

    // ================= F4/F11: break-glass holder store =================

    /// <summary>A protector that actually transforms (test-only):
    /// Protect = "T1:" + base64(reversed bytes).</summary>
    private sealed class ReversingProtector : ISecretProtector
    {
        public string Name => "test-reversing";
        public bool IsRealProtection => true;
        public string Protect(string plaintext)
        {
            var bytes = Encoding.UTF8.GetBytes(plaintext).Reverse().ToArray();
            return "T1:" + Convert.ToBase64String(bytes);
        }
        public string Unprotect(string protectedText)
        {
            if (!protectedText.StartsWith("T1:", StringComparison.Ordinal))
                throw new FormatException("not sealed by this protector");
            var bytes = Convert.FromBase64String(protectedText[3..]).Reverse().ToArray();
            return Encoding.UTF8.GetString(bytes);
        }
    }

    private static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static string SeedLegacyHolders(string dir)
    {
        var path = Path.Combine(dir, "breakglass-holders.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new[]
        {
            new { holderId = "holder-a", secretSha256 = Sha256Hex("secret-a") },
            new { holderId = "holder-b", secretSha256 = Sha256Hex("secret-b") },
        }));
        return path;
    }

    [Fact]
    public void F4_HolderStore_SealsAtRest_VerifiersArePbkdf2AfterRotation()
    {
        var dir = TestUtil.TempDir();
        var path = SeedLegacyHolders(dir);
        var protector = new ReversingProtector();
        var svc = new EnterpriseService(dir, new RosterService(new EnrollmentService()),
            () => T0, protector);
        var used = svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true);
        Assert.True(used.Ok, used.Detail);
        // The Use persisted state — sealed, not plain JSON.
        var raw = File.ReadAllText(path);
        Assert.StartsWith("T1:", raw);
        Assert.DoesNotContain("holder-a", raw);
        // Rotate holder-a: the durable verifier becomes PBKDF2.
        var (ok, detail) = svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a2") });
        Assert.True(ok, detail);
        var unsealed = protector.Unprotect(File.ReadAllText(path));
        Assert.Contains("pbkdf2$", unsealed);
        Assert.DoesNotContain(Sha256Hex("secret-a2"), unsealed);
        Assert.DoesNotContain("secretSha256", unsealed);
        // A fresh service over the sealed store still carries the
        // pending rotation for holder-b; rotate it there, and only
        // then does dual control open again — with BOTH new secrets.
        var fresh = new EnterpriseService(dir, new RosterService(new EnrollmentService()),
            () => T0, protector);
        Assert.True(fresh.BreakGlass.RotationRequired);
        Assert.Equal(new[] { "holder-b" }, fresh.BreakGlass.RotationPendingHolders);
        var (okB, detailB) = fresh.RotateBreakGlassHolders("holder-b",
            new[] { ("holder-b", "secret-b", "secret-b2") });
        Assert.True(okB, detailB);
        Assert.False(fresh.BreakGlass.RotationRequired);
        // The retired secrets are dead (checked while no rotation
        // is pending, so the refusal is the secrets themselves).
        var stale = fresh.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true);
        Assert.False(stale.Ok);
        var reUse = fresh.UseBreakGlass("co1", "holder-a", "secret-a2", "holder-b", "secret-b2", "drill", true);
        Assert.True(reUse.Ok, reUse.Detail);
    }

    [Fact]
    public void F4_HolderStore_TamperedSeal_SealsNobody()
    {
        var dir = TestUtil.TempDir();
        var path = SeedLegacyHolders(dir);
        var protector = new ReversingProtector();
        var svc = new EnterpriseService(dir, new RosterService(new EnrollmentService()),
            () => T0, protector);
        Assert.True(svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true).Ok);
        // Attack: rewrite the sealed file (flip the pending flags /
        // swap a verifier) — without the protector the bytes are
        // not JSON and not unsealable after tampering.
        var raw = File.ReadAllText(path);
        File.WriteAllText(path, raw[..^4] + "AAAA");
        var victim = new EnterpriseService(dir, new RosterService(new EnrollmentService()),
            () => T0, protector);
        var attempt = victim.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true);
        Assert.False(attempt.Ok);
    }

    [Fact]
    public void F4_LegacyPlainStore_StillLoads_WithoutProtector()
    {
        var dir = TestUtil.TempDir();
        SeedLegacyHolders(dir);
        var svc = new EnterpriseService(dir, new RosterService(new EnrollmentService()), () => T0);
        Assert.True(svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true).Ok);
        // After the Use-triggered save, verifiers were upgraded in
        // place to salted PBKDF2 — the file no longer carries bare
        // unsalted SHA-256 verifiers.
        var raw = File.ReadAllText(Path.Combine(dir, "breakglass-holders.json"));
        Assert.DoesNotContain(Sha256Hex("secret-a"), raw);
    }

    // ================= F5/F6: hub process + reporting listener =================

    [Fact]
    public void F5_HubProcess_HealthOk_IsLoopbackOnly()
    {
        var hub = new HubProcess();
        Assert.False(hub.HealthOk("https://8.8.8.8/health"));
        Assert.False(hub.HealthOk("http://192.168.1.20:8443/health"));
        Assert.False(hub.HealthOk("not a url"));
        Assert.False(hub.HealthOk("http://127.0.0.1:1/health")); // nothing listening
        Assert.Empty(hub.RecentOutput);
    }

    [Fact]
    public void F6_Listener_StartRefusesWhenPolicyOff_CleartextNonLoopbackCtorRefused()
    {
        var audit = new ChainedAuditLog();
        var reporting = new ReportingService(audit,
            new ManagementPolicyService(audit, null),
            new InventoryStore(),
            new DeskGuest.Shared.Security.DeviceIdentity(new DevOnlyPassThroughProtector()));
        using var listener = new ReportingHttpListener(reporting,
            "http://127.0.0.1:8799/", null, httpEnabled: () => false);
        listener.Start();
        Assert.False(listener.IsListening);
        Assert.True(listener.StartRefusedByPolicy);
        Assert.Throws<ArgumentException>(() =>
            new ReportingHttpListener(reporting, "http://0.0.0.0:8799/"));
    }

    // ================= F7: remediation executor is real, fails by name =================

    [Fact]
    public void F7_WindowsExecutor_ClearPathActs_RunScriptFailsByName()
    {
        var exec = new WindowsRemediationStepExecutor();
        var ctx = new RemediationExecutionContext("exec-1", "rem-1", "dev-1", "alert-1", "cond-1");
        var dir = TestUtil.TempDir();
        var victim = Path.Combine(dir, "junk.tmp");
        File.WriteAllText(victim, "x");
        var clear = RemediationStep.Create("s1", RemediationStepKinds.ClearPath, target: dir);
        var result = exec.Execute(clear, ctx);
        Assert.True(result.Ok, result.Error ?? result.Output);
        Assert.False(File.Exists(victim));
        // run_script NEVER executes a body directly — it fails by
        // name, naming the signed shell gate as the only path.
        var script = RemediationStep.Create("s2", RemediationStepKinds.RunScript,
            scriptBody: "echo hi");
        var scriptResult = exec.Execute(script, ctx);
        Assert.False(scriptResult.Ok);
        Assert.Contains("signed shell gate", scriptResult.Error ?? scriptResult.Output);
        // uninstall_app likewise fails by name (host wiring), it
        // does not pretend.
        var uninstall = RemediationStep.Create("s3", RemediationStepKinds.UninstallApp, target: "Widget");
        var uninstallResult = exec.Execute(uninstall, ctx);
        Assert.False(uninstallResult.Ok);
        Assert.Contains("not wired", uninstallResult.Error ?? uninstallResult.Output);
    }

    // ================= F9: health snapshot import requires a keyed store =================

    [Fact]
    public void F9_UnkeyedImport_AdmittedUnderRmm28Contract_ButAuditNamesThePosture()
    {
        // The RMM-28 F6 contract: an unkeyed store verifies by
        // content hash + decomposition integrity; imports are
        // segregated and actor/audit gated. BD-WIN-CORE-3/F9's
        // durable fix is that the posture is NAMED in the audit
        // entry — never a silent integrity-only admission.
        var audit = new ChainedAuditLog();
        var svc = Rmm28Kit.Service(audit: audit);
        var json = new HealthScoreStore().Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));
        var (ok, reason) = svc.ImportSnapshot(json, Rmm28Kit.Admin, expectedScopeId: Rmm28Kit.Scope);
        Assert.True(ok, reason);
        var entry = Assert.Single(audit.Entries, e => e.Kind == "health_score_snapshot_imported");
        Assert.Contains("verification=integrity-only", entry.Detail);

        // Garbage still refuses, keyed or not.
        var (okBad, _) = svc.ImportSnapshot("{\"anything\":true}", Rmm28Kit.Admin);
        Assert.False(okBad);
    }

    [Fact]
    public void F9_KeyedStore_UnsignedSnapshotRefused_SignedPostureNamed()
    {
        // With a hub signing key provisioned, provenance is real:
        // a snapshot exported from an UNKEYED store (no signature)
        // refuses, and an admitted import's audit entry names
        // signature verification.
        var key = RandomNumberGenerator.GetBytes(32);
        var audit = new ChainedAuditLog();
        var svc = new HealthScoringService(audit, new ManagementPolicyEngine(),
            id => StaticDeviceFacts.Of(id, Rmm28Kit.Scope), null, null, null, null, null,
            store: new HealthScoreStore(key), now: () => Rmm28Kit.T0, signingKey: key);
        var unsigned = new HealthScoreStore().Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));
        var (ok, reason) = svc.ImportSnapshot(unsigned, Rmm28Kit.Admin, expectedScopeId: Rmm28Kit.Scope);
        Assert.False(ok);
        Assert.Contains("signature", reason);
    }

    // ================= F10: endpoint security — isolation outlives the feature gate =================

    [Fact]
    public void F10_IsolatedDevice_StillReportsObligation_WhenFeatureTurnsOff()
    {
        var rig = new Rmm17Tests.Rig();
        var plan = Rmm17Tests.Rig.DefaultPlan();
        var (applied, _) = rig.Isolation.Isolate(plan, "test", rig.Now);
        Assert.True(applied);
        Assert.True(rig.Isolation.Status.IsIsolated);
        // Feature gate OFF: the cycle must still surface the
        // isolation obligation (the pre-fix shape skipped straight
        // past it when the feature was disabled).
        rig.SetPolicy(EndpointSecurityPolicyKeys.Enabled, "false");
        var result = rig.Service.RunDetectionCycle();
        Assert.False(result.FeatureEnabled);
        Assert.Contains("isolation alert re-raised", result.Detail);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "endpoint_security_disabled_while_isolated");
    }

    // ================= F11: LAN TLS password sealed at rest =================

    [Fact]
    public void F11_LanCertificateStore_PasswordFileIsSealed()
    {
        var dir = TestUtil.TempDir();
        var protector = new ReversingProtector();
        var store = new LanCertificateStore(dir, protector);
        var cert = store.EnsureCertificate();
        Assert.NotNull(cert);
        var passwordFile = Path.Combine(dir, "lan-tls", "lan-host.password");
        Assert.True(File.Exists(passwordFile));
        var raw = File.ReadAllText(passwordFile);
        Assert.StartsWith("sealed:T1:", raw); // sealed by the wired protector, never plaintext
        // Second store over the same dir loads the same certificate.
        var again = new LanCertificateStore(dir, protector);
        Assert.Equal(store.Fingerprint, again.Fingerprint);
    }

    // ================= F12: typed outcomes, chain state, key map =================

    [Fact]
    public void F12c_StaleDiff_CarriesTypedKind_AndServiceRebaselines()
    {
        var store = new InventoryStore();
        var software = new List<SoftwareItem> { new("App", "1.0", "Pub", null, null) };
        var svc = new InventoryService("dev-1", "company-1",
            hardwareCollector: () => Hw(), softwareCollector: () => software.ToList(),
            hostname: () => "WS-01", clock: new FakeClock());
        Assert.True(svc.CollectAndReport(store).Accepted);
        // An external writer advances the stored revision (another
        // agent instance reporting first).
        var stored = store.Get("dev-1")!;
        var external = Record("dev-1", hw: Hw(ram: 32_000_000_000));
        var diff = InventoryDiffer.Compute(stored, external, stored.Revision, T0.AddHours(1));
        Assert.True(store.ApplyChangeReport(new InventoryChangeReport(diff, external), T0.AddHours(1)).Accepted);
        // The service's next report is built on its stale revision:
        // the store refuses with the TYPED kind and the service
        // re-baselines instead of deadlocking on the refusal.
        software[0] = new SoftwareItem("App", "2.0", "Pub", null, null);
        var r = svc.CollectAndReport(store);
        Assert.True(r.Accepted, r.Outcome);
        Assert.Equal("2.0", store.Get("dev-1")!.Software.Single(s => s.Name == "App").Version);

        // The typed kind itself, at the store surface:
        var staleDiff = InventoryDiffer.Compute(stored, external, stored.Revision, T0.AddHours(2));
        var stale = store.ApplyChangeReport(new InventoryChangeReport(staleDiff, external), T0.AddHours(2));
        Assert.False(stale.Accepted);
        Assert.Equal(InventoryOutcomeKinds.StaleOrReplayed, stale.OutcomeKind);
    }

    [Fact]
    public void F12d_MeshMapKey_OnlyKnownChordsAreTranslated()
    {
        Assert.Equal("alt+tab", MeshService.MapKey("alt_tab"));
        Assert.Equal("ctrl+alt+delete", MeshService.MapKey("ctrl_alt_delete"));
        Assert.Equal("ctrl+shift+escape", MeshService.MapKey("ctrl_shift_escape"));
        Assert.Equal("page_up", MeshService.MapKey("page_up"));
        Assert.Equal("f5", MeshService.MapKey("f5"));
    }

    // ================= W1: verify_install production probe =================

    private static DeploymentPackage Pkg(string? installedName) => new(
        "pkg-1", "2.0.0", "Widget", "", true, installedName,
        Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(),
        Rmm16Tests.Def("pkg-install"), Rmm16Tests.Def("pkg-uninstall"));

    private static DeviceInventoryRecord RecordWith(string deviceId, params SoftwareItem[] software) => new(
        DeviceId: deviceId, ScopeId: "co-1", Hostname: "WS-01",
        Hardware: Hw(), Software: software,
        CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 1);

    [Fact]
    public void W1_Probe_ObservesFromInventory_FailsClosedOtherwise()
    {
        var record = RecordWith("dev-9", new SoftwareItem("Widget Pro", "3.1.4", "Acme", null, null));
        var probe = new ProductionInstalledVersionProbe(id => id == "dev-9" ? record : null, "dev-local",
            localRegistryVersion: _ => null, serviceQuery: _ => (false, ""));
        // Inventory hit (name normalized: case/whitespace-insensitive).
        Assert.Equal("3.1.4", probe.Observe(Pkg("widget pro"), "dev-9"));
        // No record for the device → unobservable → null (fail closed).
        Assert.Null(probe.Observe(Pkg("Widget Pro"), "dev-unknown"));
        // No inventory name on the package → unobservable.
        Assert.Null(probe.Observe(Pkg(null), "dev-9"));
        Assert.Null(probe.Observe(Pkg("  "), "dev-9"));
    }

    [Fact]
    public void W1_Probe_UnknownVersionIsNotAnObservation_LocalRegistryLegOnlyForLocalDevice()
    {
        var record = RecordWith("dev-local", new SoftwareItem("Widget Pro", "unknown", "Acme", null, null));
        var probe = new ProductionInstalledVersionProbe(_ => record, "dev-local",
            localRegistryVersion: name => name == "Widget Pro" ? "4.0.0" : null,
            serviceQuery: _ => (true, "STATE : 4 RUNNING"));
        // "unknown" in inventory is not an observation; the local
        // registry leg answers for the LOCAL device.
        Assert.Equal("4.0.0", probe.Observe(Pkg("Widget Pro"), "dev-local"));
        // The same record under a DIFFERENT device id never triggers
        // local OS reads.
        var remote = new ProductionInstalledVersionProbe(_ => record, "dev-local",
            localRegistryVersion: _ => "4.0.0", serviceQuery: _ => (true, "STATE : 4 RUNNING"));
        Assert.Null(remote.Observe(Pkg("Widget Pro"), "dev-remote"));
        // Service presence alone (RUNNING, no version) observes nothing.
        var svcOnly = new ProductionInstalledVersionProbe(_ => null, "dev-local",
            localRegistryVersion: _ => null, serviceQuery: _ => (true, "STATE : 4 RUNNING"));
        Assert.Null(svcOnly.Observe(Pkg("Widget Pro"), "dev-local"));
        Assert.True(ProductionInstalledVersionProbe.ServiceRunning("STATE              : 4  RUNNING"));
        Assert.False(ProductionInstalledVersionProbe.ServiceRunning("STATE              : 1  STOPPED"));
    }

    // ================= W2 + composition: CoreRuntime wiring =================

    private static CoreRuntime Runtime(string dir) =>
        new(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });

    [Fact]
    public async Task W2_MobileApprovals_PersistAcrossRuntimeRestart()
    {
        var dir = TestUtil.TempDir();
        var rt = Runtime(dir);
        // W10 note: this test predates the bd-shared-plat-2/F12
        // authorization closure on CreateRequest — a bare
        // caller-named requestedBy with no roster right now mints
        // NOTHING (by design), so the persistence assertion below
        // could never fire. Seed the requester as a live scope
        // admin, the minimal legitimate authorization context;
        // the production gate is unchanged.
        rt.Roster.CreateScope("co-1", "company", "Acme");
        rt.Roster.CreateUser("operator-1", "co-1", "Operator One", "human");
        rt.Roster.AddCompanyAdmin("co-1", "operator-1");
        var req = rt.MobileOperator.Approvals.CreateRequest("co-1", "dg-1", "session.start",
            "operator-1", TimeSpan.FromMinutes(10), T0);
        Assert.True(req is not null, "a scope admin's approval request must mint");
        Assert.True(File.Exists(Path.Combine(dir, "mobile-approvals.json")),
            "an approval request must write through to the hub store at once");
        // W95 / FR-124 amendment: a restart means the first runtime
        // STOPS first — the single-instance guard refuses a second
        // LIVE Core on the same data dir (defect D-W93-1's fix).
        await rt.StopAsync(default);
        await rt.DisposeAsync();
        var rt2 = Runtime(dir);
        var restored = rt2.MobileOperator.Approvals.Get(req.Id);
        Assert.NotNull(restored);
        Assert.Equal("session.start", restored!.Action);
        await rt2.StopAsync(default);
        await rt2.DisposeAsync();
    }

    [Fact]
    public void W2_MobileNotifications_ChangedFires_AndRuntimeRestoresSeededStore()
    {
        // Model level: an enqueue raises Changed (the event the
        // host write-through subscribes to).
        var alert = new HealthAlertEvent("alert-1", "dev-1", "disk-low", "disk", "critical",
            "firing", T0, T0, 1, "disk full", null, null, null, null, "hub");
        var queue = new MobileNotificationQueue(id => id == "alert-1" ? alert : null,
            new ChainedAuditLog());
        var fires = 0;
        queue.Changed += () => fires++;
        var (note, reason) = queue.EnqueueFromHubAlert("alert-1", "operator-1", T0);
        Assert.True(note is not null, reason);
        Assert.Equal(1, fires);

        // Host level: a store file in the hub envelope (exactly
        // what the runtime's write-through produces) is restored
        // by a fresh CoreRuntime over the same data dir.
        var dir = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir, "mobile-notifications.json"), queue.ExportJson());
        var rt = Runtime(dir);
        Assert.Contains(rt.MobileOperator.Notifications.ForOperator("operator-1"),
            n => n.Id == note!.Id);
    }

    [Fact]
    public void W1_W2_RuntimeComposesDeploymentsProbeAndMeshIdentity()
    {
        var rt = Runtime(TestUtil.TempDir());
        Assert.NotNull(rt.SoftwareDeployments);
        Assert.NotNull(rt.SoftwareDeployments.InstalledVersionProbe);
        Assert.NotNull(rt.MeshIdentity);
        Assert.Null(rt.MeshIdentity.ResolveUserId(null));
        Assert.Null(rt.MeshIdentity.ResolveUserId("Bearer forged"));
    }

    private sealed class FakeClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = T0;
    }

    private static HardwareSnapshot Hw(long ram = 16_000_000_000) => new(
        Manufacturer: "Dell Inc.", Model: "OptiPlex 7010", SerialNumber: "ABC1234",
        CpuModel: "Intel i7-13700", CpuCores: 16, RamBytes: ram,
        OsName: "Windows 11 Pro", OsBuild: "26100.1", OsVersion: "10.0.26100",
        BiosVersion: "1.2.3",
        Disks: new[] { new DiskInfo("C:", "Samsung SSD 990", "DISK001", 512_000_000_000, "NVMe", "SSD") },
        Peripherals: new[] { new PeripheralInfo("monitor", "Dell U2723", "Dell", "U2723") },
        CollectedUtc: T0);

    private static DeviceInventoryRecord Record(string deviceId, HardwareSnapshot? hw = null) => new(
        DeviceId: deviceId, ScopeId: "company-1", Hostname: "WS-01",
        Hardware: hw ?? Hw(),
        Software: new[] { new SoftwareItem("App", "1.0", "Pub", null, null) },
        CustomFields: new Dictionary<string, string>(),
        Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    [Fact]
    public async Task W2_VendorPasses_PersistAcrossRuntimeRestart_SealedAtRest()
    {
        var dir = TestUtil.TempDir();
        var rt = Runtime(dir);
        rt.Roster.CreateScope("co-1", "company", "Acme");
        rt.Roster.CreateUser("ops-admin", "co-1", "Ops Admin", "human");
        rt.Roster.AddCompanyAdmin("co-1", "ops-admin");
        var (issue, reason) = rt.VendorPasses.IssuePass("ops-admin",
            new DeskGuest.Shared.VendorAccess.VendorIdentity("vendor-jane", "Jane Vendor", "VendorCorp", "jane@vendorcorp.example"),
            "co-1", new[] { "dev-1" }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null);
        Assert.True(issue is not null, reason);
        // A non-admin issuer is refused by the roster-backed
        // authorizer the runtime wires (plat-3 F7 in production).
        var (forged, forgedReason) = rt.VendorPasses.IssuePass("random-string",
            new DeskGuest.Shared.VendorAccess.VendorIdentity("vendor-bob", "Bob Vendor", "VendorCorp", "bob@vendorcorp.example"),
            "co-1", new[] { "dev-1" }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null);
        Assert.Null(forged);
        Assert.Contains("not a live human scope admin", forgedReason);

        var path = Path.Combine(dir, "vendor-passes.json");
        Assert.True(File.Exists(path), "the pass store must write through on change");
        Assert.DoesNotContain(issue!.Pass.Id, File.ReadAllText(path)); // sealed at rest
        // W95 / FR-124 amendment: stop the first runtime before the
        // restart constructs (single-instance guard — see above).
        await rt.StopAsync(default);
        await rt.DisposeAsync();
        var rt2 = Runtime(dir);
        var restored = rt2.VendorPasses.Store.Get(issue.Pass.Id);
        Assert.NotNull(restored);
        Assert.False(restored!.Revoked);
        await rt2.StopAsync(default);
        await rt2.DisposeAsync();
    }
}

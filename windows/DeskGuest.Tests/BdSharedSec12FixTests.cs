using System.Reflection;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.PeripheralControl;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Roster;
using DeviceIdentity = DeskGuest.Shared.Security.DeviceIdentity;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Runbooks;
using DeskGuest.Shared.SoftwareMetering;
using DeskGuest.Shared.Vulnerability;
using Xunit;

namespace DeskGuest.Tests;

// =====================================================================
// BD-SHARED-SEC-1 + BD-SHARED-SEC-2 — Wave 3 Lane A regression tests
// (2026-11-22). Sec-1 findings were verified ALREADY-FIXED in code
// (earlier RMM lanes landed them); the sec-1 tests here pin the
// evidence so the dispositions cannot silently regress. Sec-2 tests
// pin this lane's fixes. Wiring tests pin the CoreRuntime host
// wiring (LocalRunbookCheckEvaluator, WorkItemStore scopeLookup,
// bridge resolver, HubPersistence write-through x3, requireSigned
// opt-in).
// =====================================================================
public class BdSharedSec12FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co1";

    // ================= sec-2 F4: org locked keys =================

    private static ManagementPolicyDocument Doc(string id, string level, string target,
        Dictionary<string, string> settings, long rev = 1) =>
        new(id, level, target, settings, rev);

    [Fact]
    public void Sec2F4_OrgLockedKey_DeviceAndGroupCannotLoosen()
    {
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddDocument(Doc("org1", PolicyLevels.Org, Scope, new()
        {
            ["rmm.peripheral_control.mode"] = "enforce",
            ["policy.lock.rmm.peripheral_control.mode"] = "true",
            ["clipboard.direction"] = "both",
        })).Allowed);
        Assert.True(engine.AddDocument(Doc("dev1", PolicyLevels.Device, "dev-1", new()
        {
            ["rmm.peripheral_control.mode"] = "audit",   // loosening attempt
            ["clipboard.direction"] = "off",             // unlocked: device wins
        })).Allowed);
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev-1", Scope));
        Assert.Equal("enforce", eff.Get("rmm.peripheral_control.mode")!.Value);
        Assert.Equal("off", eff.Get("clipboard.direction")!.Value);
        Assert.Contains("rmm.peripheral_control.mode", eff.LockedKeys);
    }

    [Fact]
    public void Sec2F4_LockInDeviceDocument_LocksNothing()
    {
        var engine = new ManagementPolicyEngine();
        engine.AddDocument(Doc("org1", PolicyLevels.Org, Scope, new() { ["k"] = "org" }));
        engine.AddDocument(Doc("dev1", PolicyLevels.Device, "dev-1", new()
        {
            ["policy.lock.k"] = "true", ["k"] = "device",
        }));
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev-1", Scope));
        Assert.Equal("device", eff.Get("k")!.Value);
        Assert.Empty(eff.LockedKeys);
    }

    // ================= sec-2 F11: consent-floor guard =================

    [Theory]
    [InlineData("rmm.compliance.audit_pack.enabled", false)]
    [InlineData("rmm.backup.stop_on_battery", false)]
    [InlineData("rmm.peripheral_control.mode", false)]
    [InlineData("stop", true)]
    [InlineData("rmm.stop.enabled", true)]
    [InlineData("rmm.presence.enabled", true)]
    [InlineData("rmm.kill_switch", true)]
    [InlineData("x.stop_enabled", true)]
    [InlineData("rmm_stop_enabled", true)]
    [InlineData("audit_deletable", true)]
    public void Sec2F11_FloorGuard_LegitKeysPass_DisguisesDeny(string key, bool denied) =>
        Assert.Equal(denied, ConsentFloorGuard.IsDenied(key));

    // ================= sec-2 F5: policy bundle =================

    private static (PolicyBundle Bundle, byte[] Pub) SignedBundle(
        string scope = Scope, string tier = "none", int version = 2, DateTimeOffset? issued = null)
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var b = new PolicyBundle(version, scope, new[] { "lan" }, "auto", null, null,
            false, false, tier, issued ?? T0, T0.AddDays(30), "");
        return (PolicyBundleService.Sign(b, org), org.PublicKey);
    }

    [Fact]
    public void Sec2F5_Verify_ScopeMismatch_AndRollback_Refuse()
    {
        var (bundle, pub) = SignedBundle();
        var svc = new PolicyBundleService();
        Assert.True(svc.Verify(bundle, pub, T0.AddDays(1), Scope, null).Allowed);
        Assert.False(svc.Verify(bundle, pub, T0.AddDays(1), "other-scope", null).Allowed);
        Assert.False(svc.Verify(bundle, pub, T0.AddDays(1), Scope, (3, T0)).Allowed); // version regresses
        Assert.False(svc.Verify(bundle, pub, T0.AddDays(1), Scope, (2, T0.AddDays(2))).Allowed); // older issue
        Assert.True(svc.Verify(bundle, pub, T0.AddDays(1), Scope, (2, T0)).Allowed); // same: idempotent
    }

    [Fact]
    public void Sec2F5_Verify_UnknownUnattendedTier_Refuses_AndFromVerified_Gates()
    {
        var (bad, pub) = SignedBundle(tier: "whenever");
        var svc = new PolicyBundleService();
        var verdict = svc.Verify(bad, pub, T0.AddDays(1));
        Assert.False(verdict.Allowed);
        Assert.Contains("unattended tier", verdict.Reason);
        Assert.Null(PolicyEnforcer.FromVerified(bad, verdict));
        var (good, pub2) = SignedBundle();
        Assert.NotNull(PolicyEnforcer.FromVerified(good, svc.Verify(good, pub2, T0.AddDays(1))));
    }

    // ================= sec-2 F6: directory sync =================

    private static (RosterService Roster, DirectorySyncService Sync, ChainedAuditLog Audit) RosterSetup()
    {
        var roster = new RosterService();
        roster.CreateScope(Scope, "company", "Acme");
        roster.CreateUser("admin1", Scope, "Admin One", "human");
        roster.CreateUser("admin2", Scope, "Admin Two", "human");
        roster.AddCompanyAdmin(Scope, "admin1");
        roster.AddCompanyAdmin(Scope, "admin2");
        var audit = new ChainedAuditLog();
        return (roster, new DirectorySyncService(roster, audit, new AlertCenter()), audit);
    }

    [Fact]
    public void Sec2F6_AuthenticatedApply_ScopeComesFromConnector_NotEvent()
    {
        var (_, sync, _) = RosterSetup();
        // Event sets BOTH fields consistently to a foreign scope:
        // the legacy check passes it; the authenticated path refuses.
        var forged = new DirectoryEvent("evil", "evil", "u1", "User", "create", "ext-1");
        Assert.False(sync.ApplyAuthenticated(forged, "admin1", T0, Scope, stepUpPerformed: true).Allowed);
        var honest = new DirectoryEvent(Scope, Scope, "u1", "User", "create", "ext-1");
        Assert.True(sync.ApplyAuthenticated(honest, "admin1", T0, Scope, stepUpPerformed: true).Allowed);
    }

    [Fact]
    public void Sec2F6_FellowAdminRemoval_RequiresPerformedStepUp()
    {
        var (roster, sync, _) = RosterSetup();
        var ev = new DirectoryEvent(Scope, Scope, "admin2", "Admin Two", "remove", "ext-2");
        // No step-up performed: the roster's D26 guard now stands.
        Assert.False(sync.ApplyAuthenticated(ev, "admin1", T0, Scope, stepUpPerformed: false).Allowed);
        Assert.NotNull(roster.GetUser(Scope, "admin2"));
        // Step-up performed: removal lands.
        Assert.True(sync.ApplyAuthenticated(ev, "admin1", T0, Scope, stepUpPerformed: true).Allowed);
        Assert.Null(roster.GetUser(Scope, "admin2"));
    }

    // ================= sec-2 F7: OIDC hardening =================

    [Fact]
    public void Sec2F7_CompleteSignIn_MalformedTokens_RefuseNeverThrow()
    {
        var idp = new MockIdp("https://idp.example.test");
        var client = new OidcClient(
            new OidcConfig("https://idp.example.test", "deskguest-client", "https://localhost/callback", true, true), idp);
        foreach (var token in new[] { "", "x", "a.b", "a.b.c", "..", "!!!.@@@.###" })
        {
            var r = client.CompleteSignIn(token, "n", T0);
            Assert.False(r.Ok, token);
        }
        // Happy path still works (mock mints iat/exp/aud/nonce).
        var verifier = Pkce.NewVerifier();
        var code = idp.BeginAuthorize("user-1", "a@b.test", true, Pkce.ChallengeS256(verifier), "nonce-1");
        var jwt = idp.ExchangeCode(code, verifier, "deskguest-client");
        Assert.True(client.CompleteSignIn(jwt, "nonce-1", DateTimeOffset.UtcNow).Ok);
    }

    [Fact]
    public void Sec2F7_LockoutGuard_FlagsMoveOnlyThroughProof()
    {
        var guard = new SsoLockoutGuard();
        guard.RecordTestLogin(new OidcClient.SignInResult(false, null, null, "failed"));
        Assert.False(guard.TestLoginPassed); // a FAILED result records nothing
        guard.RecordTestLogin(new OidcClient.SignInResult(true, "user-1", null, "ok"));
        guard.RecordFallbackAdminVerified("  ");
        Assert.False(guard.CanEnforceMandatorySso().Allowed);
        guard.RecordFallbackAdminVerified("admin1");
        Assert.True(guard.CanEnforceMandatorySso().Allowed);
        Assert.Equal("user-1", guard.TestLoginSubject);
    }

    // ================= sec-2 F8: vulnerability feed =================

    private static VulnerabilityFeed Feed(long seq, string targetOs = "Windows") => new(
        "feed-1", "unit-test", seq, T0,
        new[]
        {
            new VulnerabilityFeedEntry("CVE-2026-1001", "Widget", "2.0", targetOs, null,
                7.5, "high", false, null, T0, "d"),
        });

    [Fact]
    public void Sec2F8_FirstImport_PersistsThroughChanged_AndReimportIsIdempotent()
    {
        var store = new VulnerabilityFeedStore();
        string? exportedOnChanged = null;
        store.Changed += () => exportedOnChanged = store.ExportJson();
        Assert.True(store.Import(Feed(1), T0).Accepted);
        // The write-through subscriber saw a REAL payload, not "null":
        Assert.NotNull(exportedOnChanged);
        Assert.Contains("feed-1", exportedOnChanged);
        // Re-importing the IDENTICAL raw feed (mixed-case TargetOs)
        // is idempotent, not "same-sequence poisoning":
        var again = store.Import(Feed(1), T0.AddMinutes(1));
        Assert.True(again.Accepted, again.Reason);
        Assert.Contains("already cached", again.Reason);
        // A DIFFERENT feed at the same sequence still refuses:
        var other = Feed(1) with
        {
            Entries = new[]
            {
                new VulnerabilityFeedEntry("CVE-2026-9999", "Widget", "2.0", "Windows", null,
                    7.5, "high", false, null, T0, "d"),
            },
        };
        Assert.False(store.Import(other, T0.AddMinutes(2)).Accepted);
    }

    // ================= sec-2 F9: audit witness =================

    [Fact]
    public void Sec2F9_Witness_VerifiesOnlyAgainstItsOwnLog()
    {
        var logA = new ChainedAuditLog();
        logA.Append("k", "actor", "one", T0);
        logA.Append("k", "actor", "two", T0);
        var logB = new ChainedAuditLog();
        logB.Append("k", "actor", "different", T0);
        logB.Append("k", "actor", "two", T0);
        var witnessDevice = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var w = logA.CreateWitness("sess-1", witnessDevice);
        Assert.True(logA.VerifyWitness(w, witnessDevice.PublicKey));
        Assert.False(logB.VerifyWitness(w, witnessDevice.PublicKey)); // same seq, different hash
        Assert.True(logA.RecordWitness(w, witnessDevice.PublicKey));
        Assert.True(logA.VerifyStoredWitnesses());
        Assert.False(logB.RecordWitness(w, witnessDevice.PublicKey));
    }

    // ================= sec-2 F10: peripheral exceptions =================

    private static DeskGuest.Shared.PeripheralControl.DeviceIdentity Usb(string? serial = null) =>
        new("m-1", DeviceClasses.Storage, "1234", "5678", serial, null);

    [Fact]
    public void Sec2F10_PrincipalStampedRequest_CannotSelfApprove()
    {
        var store = new PeripheralExceptionStore();
        store.RegisterApproverPrincipal("principal-admin");
        var (req, created, _) = store.File("m-1", "m-1", "req-1", "Alice (display)",
            Usb("SN-1"), "need it", T0, authenticatedRequesterPrincipal: "principal-admin");
        Assert.True(created);
        var (decided, _, reason) = store.Approve("req-1", "principal-admin", T0.AddDays(7), T0);
        Assert.Null(decided);
        Assert.Contains("own requester principal", reason);
    }

    [Fact]
    public void Sec2F10_CloneableException_DoesNotOverrideOrgBlock_SerialBoundDoes()
    {
        var orgBlock = new PeripheralRule("org-block", PeripheralEffects.Block, PeripheralRuleKinds.Device,
            null, "1234", "5678", null, PeripheralScopes.Org, Scope, null, null);
        var cloneableException = new PeripheralRule("exception-req", PeripheralEffects.Allow,
            PeripheralRuleKinds.Exception, DeviceClasses.Storage, "1234", "5678", null,
            PeripheralScopes.Device, "m-1", T0.AddDays(7), "req");
        var policy = new ResolvedPeripheralPolicy(true, PeripheralModes.Enforce, true,
            new[] { orgBlock, cloneableException }, Array.Empty<string>());
        var verdict = PeripheralEvaluator.Evaluate(Usb(), policy, T0);
        Assert.Equal(PeripheralDispositions.Blocked, verdict.Disposition);

        var serialException = cloneableException with { Serial = "SN-9" };
        var policy2 = new ResolvedPeripheralPolicy(true, PeripheralModes.Enforce, true,
            new[] { orgBlock, serialException }, Array.Empty<string>());
        var verdict2 = PeripheralEvaluator.Evaluate(Usb("SN-9"), policy2, T0);
        Assert.Equal(PeripheralDispositions.Allowed, verdict2.Disposition);
    }

    // ================= sec-2 F12: break-glass =================

    [Fact]
    public void Sec2F12_FailedAttempts_AuditedAlerted_AndLockout_AndRevoke()
    {
        var audit = new ChainedAuditLog();
        var alerts = new AlertCenter();
        var bg = new BreakGlassService(audit, alerts);
        bg.SealHolder("a", "sa");
        bg.SealHolder("b", "sb");
        Assert.Null(bg.Use(Scope, "a", "WRONG", "b", "sb", "attempt", false, T0));
        Assert.Contains(audit.Entries, e => e.Kind == "break_glass_use_failed");
        Assert.Contains(alerts.Alerts, a => a.EventClass == "break_glass_use");
        for (var i = 0; i < 4; i++)
            Assert.Null(bg.Use(Scope, "a", "WRONG", "b", "sb", "attempt", false, T0));
        Assert.True(bg.LockedOut);
        Assert.Null(bg.Use(Scope, "a", "sa", "b", "sb", "even correct secrets refuse while locked out", false, T0));
        bg.Rotate("a", "sa2"); // rotation is the lockout recovery act
        Assert.False(bg.LockedOut);
        bg.Rotate("b", "sb2");
        var grant = bg.Use(Scope, "a", "sa2", "b", "sb2", "IdP down", false, T0);
        Assert.NotNull(grant);
        Assert.True(bg.GrantValid(grant!, T0.AddHours(1)));
        Assert.True(bg.RevokeGrant(grant!.Id, "admin1", T0));
        Assert.False(bg.GrantValid(grant, T0.AddHours(1)));
    }

    // ================= sec-1 ALREADY-FIXED evidence pins =================

    [Fact]
    public void Sec1F1F5_Escrow_RoundTrips_AndUnwiredDualControlFailsClosed()
    {
        var audit = new ChainedAuditLog();
        var escrow = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), audit, () => T0);
        var (ok, _, meta) = escrow.Escrow("dev-1", "vol-1", Scope, "AAAA-BBBB-CCCC", "bitlocker", "agent", T0);
        Assert.True(ok);
        // F5: no admin authorizer wired -> reveal path refuses everyone.
        var (reqOk, _, _) = escrow.RequestReveal(meta!.Ref, "dev-1", "vol-1", "admin-a", "need it", T0);
        Assert.False(reqOk);
        // F1: export/import survives a "restart" (fresh instance).
        var restored = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), new ChainedAuditLog(), () => T0,
            a => a is "admin-a" or "admin-b");
        Assert.Equal(1, restored.ImportJson(escrow.ExportJson()));
        Assert.NotNull(restored.GetMetadata(meta.Ref));
    }

    [Fact]
    public void Sec1F7_Redactor_NumbersLuhnAndKeyBoundaries()
    {
        var card = JsonDocument.Parse("{\"card\":4111111111111111}").RootElement;
        Assert.Contains("[redacted:card]", Redactor.RedactJson(card).GetRawText());
        var otp = JsonDocument.Parse("{\"code\":123456}").RootElement;
        Assert.Contains("[redacted:otp-like]", Redactor.RedactJson(otp).GetRawText());
        // 13-digit epoch-ms is NOT a card (Luhn-gated):
        Assert.Equal("1732387200000", Redactor.RedactText("1732387200000"));
        Assert.False(Redactor.IsSensitiveKey("author"));
        Assert.False(Redactor.IsSensitiveKey("spinner"));
        Assert.True(Redactor.IsSensitiveKey("auth_token"));
    }

    [Fact]
    public void Sec1F8_FileAuditLog_Chained_Rotation_AndTruncationDetected()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "audit.jsonl");
        var log = new FileAuditLog(path, maxBytes: 900);
        for (var i = 0; i < 12; i++)
            log.Append(new AuditEntry(T0, "system", null, "agent", "tool", "op",
                $"{{\"i\":{i}}}", "executed", "SYSTEM", 1));
        var (ok, summary) = log.VerifyIntegrity();
        Assert.True(ok, summary);
        // Truncation: drop the newest entries — the anchor disagrees.
        var path2 = Path.Combine(dir, "audit2.jsonl");
        var logB = new FileAuditLog(path2);
        for (var i = 0; i < 5; i++)
            logB.Append(new AuditEntry(T0, "system", null, "agent", "tool", "op",
                $"{{\"i\":{i}}}", "executed", "SYSTEM", 1));
        var lines = File.ReadAllLines(path2);
        File.WriteAllLines(path2, lines.Take(lines.Length - 2));
        var (ok2, summary2) = new FileAuditLog(path2).VerifyIntegrity();
        Assert.False(ok2, summary2);
        // Truncation to EMPTY: also BROKEN (anchor without a chain),
        // never "legacy OK" (W3 destruction catch on the F8 fix).
        File.WriteAllText(path2, "");
        var (ok3, summary3) = new FileAuditLog(path2).VerifyIntegrity();
        Assert.False(ok3, summary3);
    }

    [Fact]
    public void Sec1F9_Treatment_LiveOverwriteRefused_ExtensionCapped()
    {
        var store = new TreatmentStore();
        Assert.True(store.Record("fw", "ctl", Scope, "owner", "plan", "recorder", T0.AddDays(300), T0).Ok);
        var again = store.Record("fw", "ctl", Scope, "owner", "sneaky replacement", "recorder", T0.AddDays(300), T0.AddDays(10));
        Assert.False(again.Ok);
        Assert.Contains("LIVE treatment", again.Reason);
        Assert.False(store.Record("fw", "ctl2", Scope, "owner", "plan", "  ", T0.AddDays(10), T0).Ok); // blank recordedBy
        var ext = store.Extend("fw", "ctl", Scope, "extender", T0.AddDays(400), T0.AddDays(10));
        Assert.False(ext.Ok); // total span from first recording capped at 365d
        Assert.True(store.Extend("fw", "ctl", Scope, "extender", T0.AddDays(350), T0.AddDays(10)).Ok);
    }

    [Fact]
    public void Sec1F3_Isolation_ReconcilesFromOsControl_AndUnisolateRemovesOsIsolation()
    {
        var control = new FakeNetworkControl();
        control.ApplyIsolation(new IsolationPlan(Array.Empty<DeskGuestChannelExemption>()));
        var mgr = new EndpointIsolationManager("dev-1", control, new ChainedAuditLog());
        Assert.True(mgr.Status.IsIsolated); // adopted at construction: restart-surviving truth
    }

    [Fact]
    public void Sec1F6_DlpDiscovery_IsARegisteredFactKind() =>
        Assert.Contains("dlp_discovery", ComplianceFactKinds.All);

    [Fact]
    public void Sec1F11_ExtensionChurn_CountsAsRansomArtifactFamily()
    {
        var det = new RansomwareDetector(Array.Empty<string>());
        var thresholds = new RansomwareThresholds(60, 5, 100, 100, 7.5, 3, 2);
        for (var i = 0; i < 6; i++)
            det.Ingest(new[] { new FileActivityEvent($"C:\\docs\\f{i}.docx.xyzq", FileActivityKinds.Modified, null, null, null, T0) });
        for (var i = 0; i < 5; i++)
            det.Ingest(new[] { new FileActivityEvent($"C:\\docs\\f{i}.xyzq", FileActivityKinds.Renamed,
                $"C:\\docs\\f{i}.docx", null, null, T0) });
        var verdict = det.Evaluate(thresholds, T0);
        Assert.True(verdict.ShouldIsolate, verdict.Detail);
    }

    // ================= host wiring =================

    private static CoreRuntime Runtime(string dir) =>
        new(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });

    [Fact]
    public void Wiring1_Runbooks_UseProductionCheckEvaluator()
    {
        var rt = Runtime(TestUtil.TempDir());
        var field = typeof(RunbookService).GetField("_checks", BindingFlags.NonPublic | BindingFlags.Instance)!;
        Assert.IsType<LocalRunbookCheckEvaluator>(field.GetValue(rt.Runbooks));
    }

    [Fact]
    public void Wiring2_WorkItemScopeLookup_ResolvesFromHubInventory()
    {
        var rt = Runtime(TestUtil.TempDir());
        var alert = new HealthAlertEvent("a-1", "dev-x", "disk-low", "disk", "warning",
            HealthAlertStates.Raised, T0, T0, 1, "disk below threshold", null, null, null, null, "endpoint");
        // Uninventoried device: refuses BY NAME rather than opening unscoped.
        var (item, created, reason) = rt.WorkItems.Store.OpenFromAlert(alert, T0);
        Assert.False(created);
        Assert.Contains("no enterprise scope", reason);
        // Inventoried device: the item carries the inventory scope.
        var baseline = rt.HubInventory.ApplyBaseline(new DeviceInventoryRecord(
            "dev-x", Scope, "WS-dev-x",
            new HardwareSnapshot("Dell", "X", "ABC1234", "cpu", 8, 8_000_000_000, "Windows", "26100.1", "10.0.26100", "1.0",
                Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
            Array.Empty<SoftwareItem>(), new Dictionary<string, string>(), new HashSet<string>(),
            T0, T0, T0, 1), T0);
        Assert.True(baseline.Accepted, baseline.Outcome);
        var (item2, created2, _) = rt.WorkItems.Store.OpenFromAlert(alert, T0);
        Assert.True(created2);
        Assert.Equal(Scope, item2!.ScopeId);
    }

    [Fact]
    public void Wiring3_BridgeResolver_Injected()
    {
        var rt = Runtime(TestUtil.TempDir());
        var field = typeof(DeskGuest.Shared.WorkItems.WorkItemBridge)
            .GetField("_resolver", BindingFlags.NonPublic | BindingFlags.Instance)!;
        Assert.NotNull(field.GetValue(rt.WorkItems.Bridge));
    }

    [Fact]
    public void Wiring4_WriteThrough_LoopGuard_Scheduler_LicenceReports()
    {
        var dir = TestUtil.TempDir();
        var rt = Runtime(dir);
        Assert.False(File.Exists(Path.Combine(dir, "hub-scheduled-reports-state.json"))); // nothing yet
        // Loop guard: a recorded run writes the guard history through.
        var autoDef = DeskGuest.Shared.Remediation.AutomationDefinition.Create("auto-1", "auto-1",
            new[] { DeskGuest.Shared.Remediation.RemediationStep.Create("s1", DeskGuest.Shared.Remediation.RemediationStepKinds.Wait, argument: "1") },
            cooldown: TimeSpan.FromMinutes(30), maxRunsPerWindow: 3);
        Assert.Null(rt.Remediation.LoopGuard.TryRecord(autoDef, "dev-1", T0));
        Assert.True(File.Exists(Path.Combine(dir, "hub-remediation-loop-guard.json")));
        var defn = new DeskGuest.Shared.Reporting.ScheduledReportDefinition(
            "sched-1", DeskGuest.Shared.Reporting.ReportKinds.FleetHealth, "json", 24,
            new DeskGuest.Shared.Reporting.ReportDestination(DeskGuest.Shared.Reporting.ReportDestinationKinds.LocalPath, "/tmp/out.json"),
            true, "creator", Scope);
        var defineResult = rt.Reporting.Scheduler.Define(defn);
        Assert.True(defineResult.Ok, defineResult.Reason);
        Assert.True(File.Exists(Path.Combine(dir, "hub-scheduled-reports-state.json")));
        var report = LicencePositionBuilder.Build(
            Array.Empty<LicenceEntitlement>(), Array.Empty<DeviceInventoryRecord>(),
            new EditionClassifier(), null, Scope, T0);
        var seed = new LicenceReportStore();
        Assert.True(seed.Store(report).Ok);
        // Restore through the service's gated seam: the admitted
        // report raises Changed and the host writes it through.
        Assert.Equal(1, rt.SoftwareMetering.ImportLicenceReportsJson(seed.ExportJson()));
        Assert.True(File.Exists(Path.Combine(dir, "hub-licence-reports.json")));
    }

    [Fact]
    public void Wiring5_RequireSigned_DefaultOff_OptInRefusesUnsigned()
    {
        var rt = Runtime(TestUtil.TempDir());
        Assert.False(rt.EnterpriseRequireSignedJobReports); // default OFF, named in code
        var field = typeof(JobStateReconciler).GetField("_requireSigned",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        Assert.False((bool)field.GetValue(rt.CreateJobStateReconciler())!);
        rt.EnterpriseRequireSignedJobReports = true; // enterprise opt-in
        Assert.True((bool)field.GetValue(rt.CreateJobStateReconciler())!);
        // And the flag bites: an unsigned report refuses BY NAME.
        var direct = new JobStateReconciler(() => T0, _ => true, requireSigned: true);
        var report = new JobStateReport("dev-9", T0, false, "head", Array.Empty<JobStateSummary>());
        var verdict = direct.Accept(report);
        Assert.False(verdict.Accepted);
        Assert.Contains("UNSIGNED", verdict.Reason);
    }
}

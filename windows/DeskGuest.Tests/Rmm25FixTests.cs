using DeskGuest.Core.Services;
using DeskGuest.Shared.ApplicationControl;
using DeskGuest.Shared.Deployment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Tests;

// FL-25 (a+b+c) — permanent regression tests for the RMM-25
// reconciled-review findings F1–F5, F7–F12 (verdict 49f4092c).
// F6: Approve half already fixed by recovery R25R-F5 (verified by
// F6_Verify test below + R25R-03); Deny half is accepted-residual.
public class Rmm25FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string User = "user-1";
    private const string SignerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly string HashA = new('1', 64);
    private static readonly string HashB = new('2', 64);

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-a" });
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope, groups: new[] { "grp-b" });
        public RecordingAppControlApplier Applier = new();
        public RecordingAppBlockAlertSink Sink = new();
        public WorkItemStore WorkItems;
        public Dictionary<string, DeploymentPackage> Packages = new(StringComparer.OrdinalIgnoreCase);
        public AppControlService Svc;
        public bool WithPrincipals = true;

        public Rig()
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Policy.AddGroup(new GroupDefinition("grp-b", "Group B", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            Svc = Build();
        }

        public AppControlService Build() => new(Audit, Policy, Applier, Sink, WorkItems,
            id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
            id => Packages.TryGetValue(id, out var p) ? p : null,
            () => Now,
            approverPrincipalIds: WithPrincipals ? new[] { Admin } : null);

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
        public void SetEnforce() => SetPolicy(AppControlKeys.Mode, AppControlModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(AppControlKeys.Rules, rules, "doc-rules");

        public DeploymentPackage AddPackage(string id, string softwareName, bool enabled = true)
        {
            var def = new AutomationDefinition(id + "-install", "install", "", "standard",
                TimeSpan.Zero, 1, TimeSpan.FromMinutes(1), true, Array.Empty<RemediationStep>());
            var pkg = new DeploymentPackage(id, "1.0", softwareName, "", enabled, softwareName,
                Array.Empty<PackageFileComponent>(), Array.Empty<PackageLicenceComponent>(), def, def);
            Packages[id] = pkg;
            return pkg;
        }

        public void File(string device = Dev, string id = "req-1", string product = "Widget", string? hash = null) =>
            Svc.FileRequest(device, device, id, User,
                new AppIdentity(device, product, "1.0", "Widget Corp", SignerA, hash ?? HashA,
                    @"C:\Program Files\Widget\widget.exe"),
                "site survey work", "agent");
    }

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // ---- F1: group approvals -------------------------------------

    [Fact]
    public void F1_NonMemberGroupApproval_Refused_MintsNothing()
    {
        var rig = new Rig(); rig.SetEnforce(); rig.File();
        var (req, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "group", "grp-b",
            T0.AddDays(7), null, "console");
        Assert.Null(rule); Assert.Null(req);
        Assert.Contains("not a member", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }

    [Fact]
    public void F1_UnknownGroupApproval_Refused()
    {
        var rig = new Rig(); rig.File();
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "group", "grp-ghost",
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("does not exist", reason);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }

    [Fact]
    public void F1_UnwiredGroupAuthority_StoreRefusesFailClosed()
    {
        var store = new AppAccessRequestStore();
        store.RegisterApproverPrincipal(Admin);
        var identity = new AppIdentity(Dev, "Widget", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (filed, created, _) = store.File(Dev, Dev, "req-1", User, identity, "reason", T0);
        Assert.True(created);
        var (_, rule, reason) = store.Approve("req-1", Admin, "group", "grp-a",
            T0.AddDays(7), null, T0);
        Assert.Null(rule);
        Assert.Contains("fail closed", reason);
    }

    // ---- F2: product rules deny-only ------------------------------

    [Fact]
    public void F2_ProductAllowRule_Refused_ProductDenyStillDecides()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "product", "Widget", id: "r-prod-allow"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("deny-only"));
        Assert.Empty(policy.Rules);
        var identity = new AppIdentity(Dev, "Widget", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (blocked, _) = rig.Svc.EvaluateLaunch(Dev, identity, "agent");
        Assert.Equal(AppDispositions.Blocked, blocked!.Disposition); // default-deny, not the product allow

        var rig2 = new Rig(); rig2.SetEnforce();
        rig2.SetRules(string.Join("|",
            RuleEntry("allow", "hash", HashA, id: "r-hash-allow"),
            RuleEntry("deny", "product", "Widget", id: "r-prod-deny")));
        var (stillBlocked, _) = rig2.Svc.EvaluateLaunch(Dev, identity, "agent");
        // product deny (rank 2) does not beat hash allow (rank 4)...
        Assert.Equal(AppDispositions.Allowed, stillBlocked!.Disposition);
        var other = new AppIdentity(Dev, "Widget", "1.0", null, SignerA, HashB, @"C:\w\w.exe");
        var (denied, _) = rig2.Svc.EvaluateLaunch(Dev, other, "agent");
        Assert.Equal(AppDispositions.Blocked, denied!.Disposition); // ...but decides where no stronger rule matches
        Assert.Equal("r-prod-deny", denied.MatchedRule!.Id);
    }

    // ---- F3: principal-bound decisions ----------------------------

    [Fact]
    public void F3_UnregisteredApprover_Refused_RegisteredApproverSucceeds()
    {
        var rig = new Rig(); rig.File();
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", "mallory-user", "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("not a registered approver principal", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
        var (_, rule2, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.NotNull(rule2);
    }

    [Fact]
    public void F3_UnregisteredDenier_Refused()
    {
        var rig = new Rig(); rig.File();
        var (req, reason) = rig.Svc.DenyRequest("req-1", "mallory-user", "no", "console");
        Assert.Null(req);
        Assert.Contains("not a registered approver principal", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
    }

    [Fact]
    public void F3_NoPrincipalsRegistered_DecisionsFailClosed()
    {
        var rig = new Rig { WithPrincipals = false };
        rig.Svc = rig.Build();
        rig.File();
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("no approver principals are registered", reason);
    }

    // ---- F4: per-device request ids --------------------------------

    [Fact]
    public void F4_SameRequestIdOnTwoDevices_NoLeak_BothStand_DecisionAmbiguous()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.File(Dev, "req-x", "Widget", HashA);
        rig.File(Dev2, "req-x", "Gadget", HashB);
        // Both stand, each on its own device — the second filing did
        // NOT return the first device's request.
        Assert.Equal("Widget", rig.Svc.Requests.Get(Dev, "req-x")!.Identity.NormalizedProduct);
        Assert.Equal("Gadget", rig.Svc.Requests.Get(Dev2, "req-x")!.Identity.NormalizedProduct);
        Assert.Null(rig.Svc.Requests.Get("req-x")); // bare id is ambiguous, never a silent pick
        // Idempotent re-filing on dev-1 returns dev-1's own request.
        var (again, created, _) = rig.Svc.FileRequest(Dev, Dev, "req-x", User,
            new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", SignerA, HashA, @"C:\w\w.exe"),
            "again", "agent");
        Assert.False(created);
        Assert.Equal(Dev, again!.DeviceId);
        // A bare-id approval refuses as ambiguous and decides nothing.
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-x", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("multiple devices", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get(Dev, "req-x")!.State);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get(Dev2, "req-x")!.State);
    }

    // ---- F5: ledger escaping / control chars -----------------------

    [Fact]
    public void F5_CraftedProduct_CannotPlantFakeModeOrBlockedMarkers()
    {
        var rig = new Rig(); rig.SetEnforce();
        var evil = new AppIdentity(Dev, "Widget mode=AUDIT-ONLY (nothing is blocked) actuallyBlocked=False x",
            "1.0", "Pub actuallyBlocked=False", SignerA, HashA, @"C:\w\w.exe");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, evil, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        var entry = rig.Audit.Entries.Single(e => e.Kind == "app_control_blocked");
        Assert.Contains("actuallyBlocked=True", entry.Detail);
        Assert.DoesNotContain("actuallyBlocked=False", entry.Detail);
        Assert.Contains("mode%3D", entry.Detail); // the crafted field was encoded, not interpolated raw
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void F5_ControlCharactersInIdentity_Refused()
    {
        var rig = new Rig();
        var evil = new AppIdentity(Dev, "Widget\napp_control_allowed mode=AUDIT", "1.0", null,
            SignerA, HashA, @"C:\w\w.exe");
        var (decision, reason) = rig.Svc.EvaluateLaunch(Dev, evil, "agent");
        Assert.Null(decision);
        Assert.Contains("control characters", reason);
    }

    // ---- F6 verification (already fixed by recovery R25R-F5) -------

    [Fact]
    public void F6_Verify_ApprovalWhileToggleOff_Refused_DenyStillAvailable()
    {
        var rig = new Rig(); rig.SetEnforce(); rig.File();
        rig.SetPolicy(AppControlKeys.FeatureEnabled, "false", "doc-toggle");
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("disabled by policy", reason);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
        var (denied, _) = rig.Svc.DenyRequest("req-1", Admin, "cleaning the queue", "console");
        Assert.NotNull(denied); // denial mints nothing; accepted-residual half, untouched
    }

    // ---- F7: rule cap fail-closed ----------------------------------

    [Fact]
    public void F7_OverCapRuleDocument_RefusedWhole_FailClosed()
    {
        var rig = new Rig(); rig.SetEnforce();
        var entries = new List<string> { RuleEntry("allow", "hash", HashA, id: "r-first") };
        for (var i = 1; i <= AppControlLimits.MaxRulesPerPolicy; i++)
            entries.Add(RuleEntry("deny", "path", $@"C:\junk\{i}.exe", id: $"r-{i}"));
        rig.SetRules(string.Join("|", entries)); // 1025 entries
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("ENTIRE rule document is refused"));
        Assert.Empty(policy.Rules);
        var identity = new AppIdentity(Dev, "Widget", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, identity, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition); // the first-entry allow did NOT survive truncation
        Assert.Null(decision.MatchedRule);
    }

    // ---- F8: approval rank / label / 8.3 ----------------------------

    [Fact]
    public void F8_PathOnlyApproval_RanksWeakest_LabelledWeakest_ProductDenyBeatsIt()
    {
        var rig = new Rig(); rig.SetEnforce();
        var pathOnly = new AppIdentity(Dev, "FieldTool", "2.0", null, null, null, @"C:\Tools\Field\field.exe");
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, pathOnly, "site work", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(14), null, "console");
        Assert.NotNull(rule);
        Assert.Equal(1, rule!.Rank);
        Assert.Contains("WEAKEST", rule.StrengthLabel);
        var (ok, _) = rig.Svc.EvaluateLaunch(Dev, pathOnly, "agent");
        Assert.Equal(AppDispositions.Allowed, ok!.Disposition);
        // A product deny (rank 2) now beats the path-only approval
        // (rank 1) — the explicit precedence decision.
        rig.SetRules(RuleEntry("deny", "product", "FieldTool", id: "r-prod-deny"));
        var (no, _) = rig.Svc.EvaluateLaunch(Dev, pathOnly, "agent");
        Assert.Equal(AppDispositions.Blocked, no!.Disposition);
        Assert.Equal("r-prod-deny", no.MatchedRule!.Id);
    }

    [Fact]
    public void F8_ApprovalPathMatch_AppliesShortNameCheck()
    {
        var rig = new Rig(); rig.SetEnforce();
        var pathOnly = new AppIdentity(Dev, "FieldTool", "2.0", null, null, null, @"C:\Tools\FieldTool\field.exe");
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, pathOnly, "site work", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(14), null, "console");
        Assert.NotNull(rule);
        var shortNamed = new AppIdentity(Dev, "FieldTool", "2.0", null, null, null, @"C:\Tools\FIELD~1\field.exe");
        Assert.False(rule!.Matches(shortNamed, T0)); // 8.3 segment never satisfies the approval's path anchor
    }

    // ---- F9 residual: ADS + \??\ ------------------------------------

    [Fact]
    public void F9_NtPrefixAndDefaultAds_Equate_NonDefaultAdsNeverMatchesPathRule()
    {
        Assert.True(AppPathNormalizer.Equals(@"C:\Tools\evil.exe", @"\??\C:\Tools\evil.exe"));
        Assert.True(AppPathNormalizer.Equals(@"C:\Tools\evil.exe", @"C:\Tools\evil.exe::$DATA"));
        Assert.True(AppPathNormalizer.HasAlternateDataStreamSegment(
            AppPathNormalizer.Normalize(@"C:\Tools\evil.exe:hidden")));
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "path", @"C:\Tools\evil.exe", id: "r-path-allow"));
        var ads = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, @"C:\Tools\evil.exe:hidden");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, ads, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition); // ADS bytes are not the allowed file
        Assert.Null(decision.MatchedRule);
        var nt = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, @"\??\C:\Tools\evil.exe");
        var (allowed, _) = rig.Svc.EvaluateLaunch(Dev, nt, "agent");
        Assert.Equal(AppDispositions.Allowed, allowed!.Disposition);
    }

    // ---- F10: ledgered refusals + rollback ---------------------------

    [Fact]
    public void F10_NullIdentityAndDeviceMismatch_AreLedgered()
    {
        var rig = new Rig();
        var (d1, _) = rig.Svc.EvaluateLaunch(Dev, null, "agent");
        Assert.Null(d1);
        var wrong = new AppIdentity(Dev2, "Widget", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (d2, _) = rig.Svc.EvaluateLaunch(Dev, wrong, "agent");
        Assert.Null(d2);
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "app_control_launch_refused"));
    }

    [Fact]
    public void F10_UnknownApproveAndPackageOfferRefusals_AreLedgered()
    {
        var rig = new Rig(); rig.File();
        var before = rig.Audit.Entries.Count(e => e.Kind == "app_request_approval_refused");
        var (_, _, r1) = rig.Svc.ApproveRequest("req-ghost", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Contains("unknown request", r1);
        var (_, _, r2) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), "pkg-ghost", "console");
        Assert.Contains("does not exist", r2);
        Assert.Equal(before + 2, rig.Audit.Entries.Count(e => e.Kind == "app_request_approval_refused"));
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
    }

    [Fact]
    public void F10_WorkItemIntakeFailure_RollsBackTheRequest()
    {
        var rig = new Rig();
        // A business reason + identity whose composed work-item text
        // exceeds the RMM-12 text cap: store filing accepts it, the
        // intake yields no item — the request must not stand.
        var identity = new AppIdentity(Dev, new string('P', 200), "1.0", "Widget Corp",
            SignerA, HashA, @"C:\Program Files\Widget\widget.exe");
        var (req, created, reason) = rig.Svc.FileRequest(Dev, Dev, "req-1", User, identity,
            new string('x', 1900), "agent");
        Assert.Null(req); Assert.False(created);
        Assert.Contains("rolled back", reason);
        Assert.Null(rig.Svc.Requests.Get(Dev, "req-1"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_refused" && e.Detail.Contains("rolled back"));
    }

    // ---- F11: eviction ----------------------------------------------

    [Fact]
    public void F11_ExpiredApprovalRules_EvictedAfterBeingNamedOnce()
    {
        var rig = new Rig(); rig.SetEnforce(); rig.File();
        rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        Assert.Single(rig.Svc.Requests.AllApprovalRules);
        rig.Now = T0.AddDays(8);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("expired") && n.Contains("approval-req-1"));
        Assert.Empty(rig.Svc.Requests.AllApprovalRules); // evicted after naming, store does not grow
    }

    // ---- F12 residual: expiry culture/offset + gate alias ------------

    [Fact]
    public void F12_ExpiryWithoutExplicitOffset_Dropped_OffsetFormParses()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "hash", HashA, expires: "2027-01-01T00:00:00", id: "r-nooffset"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("no explicit offset"));
        Assert.Empty(policy.Rules);
        var rig2 = new Rig(); rig2.SetEnforce();
        rig2.SetRules(RuleEntry("allow", "hash", HashA, expires: "2027-01-01T00:00:00Z", id: "r-z"));
        var (policy2, _) = rig2.Svc.ResolvePolicy(Dev);
        Assert.Single(policy2!.Rules);
    }

    [Fact]
    public void F12_AliasToggleOff_ApprovalGateRefuses()
    {
        var rig = new Rig(); rig.File();
        rig.SetPolicy(AppControlKeys.FeatureEnabledAlias, "false", "doc-alias");
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("disabled by policy", reason);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }
}

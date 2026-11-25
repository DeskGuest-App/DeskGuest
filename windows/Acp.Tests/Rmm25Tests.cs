using Acp.Core.Services;
using Acp.Shared.ApplicationControl;
using Acp.Shared.Deployment;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Remediation;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-25 — Application control: allow/deny rules by hash, publisher
// (signer certificate), product and path (precedence in that order)
// delivered as RMM-07 policy content; audit (safe default) vs
// enforce modes with the effective mode unambiguous in every
// surface; block events into the RMM-01 alert centre with the full
// identity + matched rule; the access-request workflow over RMM-12
// work items with scoped, expiring approvals that cannot widen.
public class Rmm25Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string User = "user-1";
    private const string SignerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 40 hex (SHA-1 thumbprint form)
    private const string SignerB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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

        public Rig()
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Policy.AddGroup(new GroupDefinition("grp-b", "Group B", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            // FL-25b/F3 amendment: decisions now require a
            // registered approver principal — the rig registers
            // Admin (previously any free-text approver was accepted).
            Svc = new AppControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                id => Packages.TryGetValue(id, out var p) ? p : null,
                () => Now, approverPrincipalIds: new[] { Admin });
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1, string level = "org", string target = Scope) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, level, target,
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
    }

    private static AppIdentity App(string product = "Widget", string? hash = null, string? signer = SignerA,
        string? publisher = "Widget Corp", string? path = @"C:\Program Files\Widget\widget.exe",
        string device = Dev, string? version = "1.0") =>
        new(device, product, version, publisher, signer, hash, path);

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // ---- modes: audit is the safe default ------------------------------

    [Fact]
    public void DefaultMode_IsAudit_NothingBlocked_WouldBlockNamedAndLabelled()
    {
        var rig = new Rig();
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.NotNull(decision);
        Assert.Equal(AppDispositions.WouldBlock, decision!.Disposition);
        Assert.False(decision.ActuallyBlocked);
        Assert.Equal(AppControlModes.Audit, decision.EffectiveMode);
        Assert.Contains("AUDIT-ONLY", decision.EffectiveModeLabel);
        Assert.Contains("NOT stopped", decision.Reason);
        // The block event carries the same unambiguous mode.
        var ev = Assert.Single(rig.Sink.Events);
        Assert.False(ev.ActuallyBlocked);
        Assert.Contains("AUDIT-ONLY", ev.EffectiveModeLabel);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_control_would_block");
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "app_control_blocked");
    }

    [Fact]
    public void EnforceMode_UnlistedApp_Blocked_EventAndAuditSayBlocked()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.True(decision.ActuallyBlocked);
        Assert.Contains("ENFORCE", decision.EffectiveModeLabel);
        var ev = Assert.Single(rig.Sink.Events);
        Assert.True(ev.ActuallyBlocked);
        Assert.Contains("default-deny", ev.MatchedRuleDescription);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_control_blocked" && e.Detail.Contains("actuallyBlocked=True"));
    }

    [Fact]
    public void UnparsableMode_FallsBackToAudit_NamedInNotes()
    {
        var rig = new Rig();
        rig.SetPolicy(AppControlKeys.Mode, "enforc", "doc-mode"); // typo
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Equal(AppControlModes.Audit, policy!.Mode);
        Assert.Contains(policy.Notes, n => n.Contains("not a known mode") && n.Contains("AUDIT-ONLY"));
    }

    [Fact]
    public void ModeSwitchToEnforce_IsAnExplicitPolicyAct_NewRevisionChangesDecisions()
    {
        var rig = new Rig();
        var (before, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.WouldBlock, before!.Disposition);
        rig.SetPolicy(AppControlKeys.Mode, AppControlModes.Enforce, "doc-mode", rev: 1);
        var (after, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, after!.Disposition);
    }

    // ---- rules + precedence ----------------------------------------------

    [Fact]
    public void AllowByHash_InEnforce_Allows_OtherHashBlocked()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "hash", HashA));
        var (ok, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, ok!.Disposition);
        Assert.Equal("hash", ok.MatchedRule!.Kind);
        var (no, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent");
        Assert.Equal(AppDispositions.Blocked, no!.Disposition);
    }

    [Fact]
    public void Precedence_HashBeatsPublisherBeatsProductBeatsPath()
    {
        var rig = new Rig();
        rig.SetEnforce();
        // deny at every rank except the one under test is layered in
        // one at a time below via separate policies per device scope.
        rig.SetRules(string.Join("|",
            RuleEntry("allow", "path", @"C:\Program Files\Widget\widget.exe", id: "r-path"),
            RuleEntry("deny", "product", "Widget", id: "r-prod"),
            RuleEntry("allow", "publisher", SignerA, id: "r-pub"),
            RuleEntry("deny", "hash", HashA, id: "r-hash")));
        // Hash deny (rank 4) decides over publisher allow + product deny + path allow.
        var (d1, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, d1!.Disposition);
        Assert.Equal("r-hash", d1.MatchedRule!.Id);
        // No hash rule matches HashB: publisher allow (rank 3) beats product deny + path allow.
        var (d2, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent");
        Assert.Equal(AppDispositions.Allowed, d2!.Disposition);
        Assert.Equal("r-pub", d2.MatchedRule!.Id);
        // Different signer: product deny (rank 2) beats path allow (rank 1).
        var (d3, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB, signer: SignerB), "agent");
        Assert.Equal(AppDispositions.Blocked, d3!.Disposition);
        Assert.Equal("r-prod", d3.MatchedRule!.Id);
    }

    [Fact]
    public void PathOnlyAllow_IsLabelledWeakest_InRuleAndDecision()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "path", @"C:\Program Files\Widget\widget.exe"));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, decision!.Disposition);
        Assert.Contains("WEAKEST", decision.MatchedRule!.StrengthLabel);
        Assert.Contains("WEAKEST", decision.Reason);
    }

    [Fact]
    public void MalformedRuleEntries_DroppedAndNamed_ValidOnesStillApply()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(string.Join("|", "garbage-entry", RuleEntry("allow", "hash", HashA, id: "r-ok")));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("malformed rule entry"));
        Assert.Single(policy.Rules);
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, decision!.Disposition);
    }

    [Fact]
    public void PolicyRuleWithExpiry_StopsMatchingAfterExpiry()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "hash", HashA, expires: T0.AddDays(1).ToString("O")));
        var (before, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, before!.Disposition);
        rig.Now = T0.AddDays(2);
        var (after, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, after!.Disposition);
    }

    [Fact]
    public void GroupScopedRule_AppliesToMembersOnly()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "hash", HashA, scopeKind: "group", scopeId: "grp-a"));
        var (member, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, member!.Disposition);
        var (other, _) = rig.Svc.EvaluateLaunch(Dev2, App(hash: HashA, device: Dev2), "agent");
        Assert.Equal(AppDispositions.Blocked, other!.Disposition);
    }

    // ---- identity discipline ----------------------------------------------

    [Fact]
    public void Identity_TooThin_Refused()
    {
        var rig = new Rig();
        var thin = new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", null, null, null);
        var (decision, reason) = rig.Svc.EvaluateLaunch(Dev, thin, "agent");
        Assert.Null(decision);
        Assert.Contains("too thin", reason);
    }

    [Fact]
    public void Identity_MalformedHashOrSigner_Refused()
    {
        var rig = new Rig();
        var (d1, r1) = rig.Svc.EvaluateLaunch(Dev, App(hash: "not-a-hash"), "agent");
        Assert.Null(d1); Assert.Contains("SHA-256", r1);
        var (d2, r2) = rig.Svc.EvaluateLaunch(Dev, App(signer: "Widget Corp Inc"), "agent");
        Assert.Null(d2); Assert.Contains("certificate thumbprint", r2);
    }

    // ---- applier seam --------------------------------------------------------

    [Fact]
    public void EvaluateAndApply_RecordingApplier_GetsPlanWithModeLabel()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var (result, _) = rig.Svc.EvaluateAndApply(Dev, Admin);
        Assert.True(result!.Applied);
        var plan = Assert.Single(rig.Applier.Plans);
        Assert.Contains("ENFORCE", plan.EffectiveModeLabel);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_control_applied");
    }

    [Fact]
    public void EvaluateAndApply_UnavailableApplier_ReportsNotAppliedHonestly()
    {
        var rig = new Rig();
        var svc = new AppControlService(rig.Audit, rig.Policy, new UnavailableAppControlApplier(),
            rig.Sink, rig.WorkItems, id => id == Dev ? rig.Facts1 : null, null, () => rig.Now);
        var (result, reason) = svc.EvaluateAndApply(Dev, Admin);
        Assert.False(result!.Applied);
        Assert.Contains("NOT applied", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_control_not_applied");
    }

    [Fact]
    public void FeatureToggleOff_ServiceRefuses_AndResolverReportsNotControlled()
    {
        var rig = new Rig();
        rig.SetPolicy(AppControlKeys.FeatureEnabled, "false", "doc-toggle");
        var (decision, reason) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Null(decision);
        Assert.Contains("disabled by policy", reason);
    }

    // ---- block events into the RMM-01 alert centre ----------------------------

    [Fact]
    public void BlockEvent_LandsInHealthAlertCentre_WithFullIdentityAndRule()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "hash", HashA, id: "r-deny"));
        var centre = new HealthAlertCentre(rig.Audit, new AlertCenter());
        var svc = new AppControlService(rig.Audit, rig.Policy, rig.Applier,
            new HealthAlertCentreAppBlockSink(centre), rig.WorkItems,
            id => id == Dev ? rig.Facts1 : null, null, () => rig.Now);
        var (decision, _) = svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        var alert = Assert.Single(centre.ActiveAlerts);
        Assert.Equal(AppBlockAlertKind.Kind, alert.Kind);
        Assert.Equal(AlertSeverities.Warning, alert.Severity);
        Assert.Contains("r-deny", alert.Detail);
        Assert.Contains(HashA, alert.Detail);
    }

    // ---- request workflow -------------------------------------------------------

    private static (Rig Rig, AppAccessRequest Req) FiledRig()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var (req, created, reason) = rig.Svc.FileRequest(Dev, Dev, "req-1", User,
            App(hash: HashA), "Needed for the site survey", "session-agent");
        Assert.True(created, reason);
        return (rig, req!);
    }

    [Fact]
    public void FileRequest_CreatesWorkItem_NamingIdentityAndReason()
    {
        var (rig, req) = FiledRig();
        Assert.Equal(AppRequestStates.Pending, req.State);
        var item = rig.WorkItems.Get(WorkItem.IdForRequest("req-1@dev-1")); // FL-25b/DF3: work items are keyed by the device-scoped request key;
        Assert.NotNull(item);
        Assert.Equal(WorkItemKinds.Request, item!.Kind);
        Assert.Contains("Widget", item.Title);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_filed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Approve_MintsScopedExpiringRule_ExactIdentityAllowed_OthersStillBlocked()
    {
        var (rig, _) = FiledRig();
        var (req, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(30), null, "console");
        Assert.NotNull(rule); Assert.NotNull(req);
        Assert.Equal(AppRequestStates.Approved, req!.State);
        Assert.Equal(T0.AddDays(30), rule!.ExpiresUtc);
        Assert.Equal("req-1", rule.SourceRequestId);
        // The exact requested application now runs...
        var (allowed, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, allowed!.Disposition);
        Assert.Equal(rule.Id, allowed.MatchedRule!.Id);
        // ...but the same product with a different hash does not.
        var (other, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent");
        Assert.Equal(AppDispositions.Blocked, other!.Disposition);
        // The work item closed with the approval outcome recorded.
        var item = rig.WorkItems.Get(WorkItem.IdForRequest("req-1@dev-1")); // FL-25b/DF3: work items are keyed by the device-scoped request key;
        Assert.True(item!.IsClosed);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_approved");
    }

    // FL-25a/F1 REWRITE (disclosed): the original version of this
    // test approved dev-1's request into grp-b — a group dev-1 is
    // NOT a member of — and asserted the rule landed on dev-2. That
    // baked in the F1 leak (a group approval naming any group, with
    // no membership or existence check). The rewritten test pins
    // the fixed contract: approval into the requester's OWN group
    // works and reaches its members only; approval into a group
    // the requester is not in REFUSES and mints nothing.
    [Fact]
    public void Approve_GroupScope_AllowsGroupMembersOnly()
    {
        var (rig, _) = FiledRig();
        // dev-1 is in grp-a: approval into grp-a mints, and the
        // exact identity is allowed for the member (dev-1)...
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "group", "grp-a",
            T0.AddDays(7), null, "console");
        Assert.NotNull(rule);
        var (mine, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, mine!.Disposition);
        // ...but NOT for dev-2, which is in grp-b only.
        var (theirs, _) = rig.Svc.EvaluateLaunch(Dev2, App(hash: HashA, device: Dev2), "agent");
        Assert.Equal(AppDispositions.Blocked, theirs!.Disposition);

        // A fresh request approved into grp-b (dev-1 is not a
        // member) refuses and mints nothing.
        var (rig2, _) = FiledRig();
        var (req2, rule2, reason2) = rig2.Svc.ApproveRequest("req-1", Admin, "group", "grp-b",
            T0.AddDays(7), null, "console");
        Assert.Null(rule2); Assert.Null(req2);
        Assert.Contains("not a member", reason2);
        Assert.Equal(AppRequestStates.Pending, rig2.Svc.Requests.Get("req-1")!.State);
        Assert.Empty(rig2.Svc.Requests.AllApprovalRules);
    }

    [Fact]
    public void Deny_RecordsReason_AndMintsNothing()
    {
        var (rig, _) = FiledRig();
        var (req, reason) = rig.Svc.DenyRequest("req-1", Admin, "No business need established", "console");
        Assert.NotNull(req);
        Assert.Equal(AppRequestStates.Denied, req!.State);
        Assert.Equal("No business need established", req.DecisionReason);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_denied");
    }

    [Fact]
    public void Approve_WithPackageOffer_RecordsOffer_WhenPackageMatches()
    {
        var (rig, _) = FiledRig();
        rig.AddPackage("pkg-widget", "Widget");
        var (req, _, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(30), "pkg-widget", "console");
        Assert.NotNull(req);
        Assert.Equal("pkg-widget", req!.OfferedPackageId);
    }

    [Fact]
    public void Approve_WithoutExpiry_Refused_ApprovalsAreNotPermanent()
    {
        var (rig, _) = FiledRig();
        var (req, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, null, null, "console");
        Assert.Null(rule); Assert.Null(req);
        Assert.Contains("MUST carry an expiry", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
    }
}

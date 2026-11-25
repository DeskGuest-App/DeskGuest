using Acp.Core.Services;
using Acp.Shared.ApplicationControl;
using Acp.Shared.Deployment;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Remediation;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// FL-25b — permanent regression tests for the RMM-25 DELTA
// re-review findings DF1–DF12 (packet 153068aa): the residuals and
// regressions the FL-25 fixes themselves carried. Each test names
// the delta finding it pins.
public class Rmm25DeltaFixTests
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
        public AppControlService Svc;

        public Rig()
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Policy.AddGroup(new GroupDefinition("grp-b", "Group B", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            Svc = new AppControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                null, () => Now, approverPrincipalIds: new[] { Admin });
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
        public void SetEnforce() => SetPolicy(AppControlKeys.Mode, AppControlModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(AppControlKeys.Rules, rules, "doc-rules");

        public static AppIdentity Identity(string device = Dev, string product = "Widget",
            string? hash = null, string? signer = null, string? path = null) =>
            new(device, product, "1.0", "Widget Corp", signer ?? SignerA, hash ?? HashA,
                path ?? @"C:\Program Files\Widget\widget.exe");

        public void File(string device = Dev, string id = "req-1", string product = "Widget") =>
            Svc.FileRequest(device, device, id, User, Identity(device, product), "site survey work", "agent");
    }

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // ---- DF1: request-id validation + ledger escaping -------------

    [Fact]
    public void DF1_CraftedRequestId_RefusedAtFiling_NothingPlantedInLedger()
    {
        var rig = new Rig();
        var crafted = "x mode=ENFORCE actuallyBlocked=False";
        var (req, created, reason) = rig.Svc.FileRequest(Dev, Dev, crafted, User,
            Rig.Identity(), "need it", "agent");
        Assert.Null(req); Assert.False(created);
        Assert.Contains("not admissible", reason);
        Assert.Empty(rig.Svc.Requests.Requests);
        // The refusal IS ledgered, with the crafted id percent-encoded:
        var entry = Assert.Single(rig.Audit.Entries, e => e.Kind == "app_request_refused");
        Assert.DoesNotContain("actuallyBlocked=False", entry.Detail);
        Assert.Contains("actuallyBlocked%3DFalse", entry.Detail);
        // Over-length and separator-carrying ids refuse the same way.
        Assert.Null(rig.Svc.FileRequest(Dev, Dev, new string('a', 65), User, Rig.Identity(), "r", "agent").Request);
        Assert.Null(rig.Svc.FileRequest(Dev, Dev, "a|b", User, Rig.Identity(), "r", "agent").Request);
        // A plain admissible id still files.
        Assert.NotNull(rig.Svc.FileRequest(Dev, Dev, "req-1.ok_2", User, Rig.Identity(), "r", "agent").Request);
    }

    [Fact]
    public void DF1_DenialReasonAndDenier_EscapedInLedger()
    {
        var rig = new Rig(); rig.File();
        var (denied, _) = rig.Svc.DenyRequest("req-1", Admin,
            "rejected actuallyBlocked=False mode=ENFORCE", "console");
        Assert.NotNull(denied);
        var entry = Assert.Single(rig.Audit.Entries, e => e.Kind == "app_request_denied");
        Assert.DoesNotContain("actuallyBlocked=False", entry.Detail);
        Assert.Contains("actuallyBlocked%3DFalse", entry.Detail);
    }

    [Fact]
    public void DF1_DeviceMismatch_DeviceIdEscapedInLedger()
    {
        var rig = new Rig(); rig.SetEnforce();
        var foreign = Rig.Identity(device: "dev-9 mode=ENFORCE actuallyBlocked=False");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, foreign, "agent");
        Assert.Null(decision);
        var entry = Assert.Single(rig.Audit.Entries, e => e.Kind == "app_control_launch_refused");
        Assert.DoesNotContain("actuallyBlocked=False", entry.Detail);
        Assert.Contains("%3D", entry.Detail);
    }

    // ---- DF2: denial is principal-gated too ------------------------

    [Fact]
    public void DF2_UnregisteredDenier_Refused_RequestStaysPending()
    {
        var rig = new Rig(); rig.File();
        var (denied, reason) = rig.Svc.DenyRequest("req-1", "mallory-user", "no", "console");
        Assert.Null(denied);
        Assert.Contains("not a registered approver principal", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
        // The registered principal can still deny.
        Assert.NotNull(rig.Svc.DenyRequest("req-1", Admin, "no need", "console").Request);
    }

    // ---- DF3: per-device keyspaces + device-scoped decisions -------

    [Fact]
    public void DF3_SameIdTwoDevices_DistinctWorkItemsAndRules_ScopedDecisionsWork()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.File(Dev, "req-1"); rig.File(Dev2, "req-1");
        // Distinct work items, one per device.
        var item1 = rig.WorkItems.Get(WorkItem.IdForRequest("req-1@dev-1"));
        var item2 = rig.WorkItems.Get(WorkItem.IdForRequest("req-1@dev-2"));
        Assert.NotNull(item1); Assert.NotNull(item2);
        Assert.NotEqual(item1!.Id, item2!.Id);
        // Bare-id approval still refuses as ambiguous...
        var (bareReq, bareRule, bareReason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(bareRule);
        Assert.Contains("multiple devices", bareReason);
        // ...but the device-scoped decision decides dev-1's request,
        // closing ONLY dev-1's work item (the DF3 freeze is gone).
        var (req1, rule1, _) = rig.Svc.ApproveRequest(Dev, "req-1", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.NotNull(rule1);
        Assert.Equal("approval-req-1@dev-1", rule1!.Id);
        Assert.True(rig.WorkItems.Get(item1.Id)!.IsClosed);
        Assert.False(rig.WorkItems.Get(item2.Id)!.IsClosed);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get(Dev2, "req-1")!.State);
        // Dev-2's approval mints its OWN rule; neither overwrites the other.
        var (_, rule2, _) = rig.Svc.ApproveRequest(Dev2, "req-1", Admin, "device", Dev2,
            T0.AddDays(7), null, "console");
        Assert.Equal("approval-req-1@dev-2", rule2!.Id);
        Assert.Equal(2, rig.Svc.Requests.AllApprovalRules.Count);
        // Device-scoped denial also works under a colliding id.
        var rig2 = new Rig();
        rig2.File(Dev, "req-9"); rig2.File(Dev2, "req-9");
        var (denied, _) = rig2.Svc.DenyRequest(Dev2, "req-9", Admin, "no", "console");
        Assert.NotNull(denied);
        Assert.Equal(AppRequestStates.Pending, rig2.Svc.Requests.Get(Dev, "req-9")!.State);
    }

    // ---- DF4: strict expiry offset ---------------------------------

    [Fact]
    public void DF4_DateOnlyExpiry_DroppedNamed_NeverParsedWithHostOffset()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "hash", HashA, expires: "2027-01-01", id: "r-dateonly"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Empty(policy!.Rules);
        Assert.Contains(policy.Notes, n => n.Contains("no explicit offset"));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, Rig.Identity(), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition); // default-deny, not the date-only allow

        // A bare local datetime also refuses; Z and numeric-offset forms parse.
        var rig2 = new Rig();
        rig2.SetRules(string.Join("|",
            RuleEntry("allow", "hash", HashA, expires: "2027-01-01T00:00:00", id: "r-bare"),
            RuleEntry("allow", "hash", HashB, expires: "2027-01-01T00:00:00+05:00", id: "r-offset")));
        var (policy2, _) = rig2.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy2!.Notes, n => n.Contains("r-bare") && n.Contains("no explicit offset"));
        Assert.Contains(policy2.Rules, r => r.Id == "r-offset");
    }

    // ---- DF5: approvals rank by their WEAKEST anchor ----------------

    [Fact]
    public void DF5_HashApproval_DoesNotTrumpPublisherOrProductDeny()
    {
        // Direct rank pins: an approval's weakest bound anchor is
        // the product (2); a path-bound approval ranks 1.
        var hashApproval = new AppRule("approval-x@dev-1", "allow", "approval",
            HashA, SignerA, "Widget", null, "device", Dev, T0.AddDays(7), "req-x");
        Assert.Equal(2, hashApproval.Rank);
        var pathApproval = new AppRule("approval-y@dev-1", "allow", "approval",
            null, null, "Widget", @"C:\w\w.exe", "device", Dev, T0.AddDays(7), "req-y");
        Assert.Equal(1, pathApproval.Rank);

        // A publisher DENY (rank 3) beats a hash-anchored approval.
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "publisher", SignerA, id: "r-pub-deny"));
        rig.File();
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        Assert.NotNull(rule);
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, Rig.Identity(), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Equal("r-pub-deny", decision.MatchedRule!.Id);

        // A product DENY (rank 2, same rank) also beats it: deny
        // wins within a rank — an approval is never a trump.
        var rig2 = new Rig(); rig2.SetEnforce();
        rig2.SetRules(RuleEntry("deny", "product", "Widget", id: "r-prod-deny"));
        rig2.File();
        rig2.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        var (decision2, _) = rig2.Svc.EvaluateLaunch(Dev, Rig.Identity(), "agent");
        Assert.Equal(AppDispositions.Blocked, decision2!.Disposition);
        Assert.Equal("r-prod-deny", decision2.MatchedRule!.Id);

        // With no policy deny in play the same approval still allows.
        var rig3 = new Rig(); rig3.SetEnforce(); rig3.File();
        rig3.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        var (decision3, _) = rig3.Svc.EvaluateLaunch(Dev, Rig.Identity(), "agent");
        Assert.Equal(AppDispositions.Allowed, decision3!.Disposition);
    }

    // ---- DF6: resolver scope-first, no cross-device leak ------------

    [Fact]
    public void DF6_OtherDevicesExpiredApproval_NotNamedNotEvictedByMyResolution()
    {
        var rig = new Rig(); rig.SetEnforce();
        rig.File(Dev2, "req-1");
        rig.Svc.ApproveRequest("req-1", Admin, "device", Dev2, T0.AddDays(7), null, "console");
        Assert.Single(rig.Svc.Requests.AllApprovalRules);
        rig.Now = T0.AddDays(8); // dev-2's approval is now expired

        // Dev-1 resolves: dev-2's expired rule is NOT named in
        // dev-1's notes, NOT ledgered via dev-1's apply, NOT evicted.
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.DoesNotContain(policy!.Notes, n => n.Contains("dev-2"));
        // Only entries written BY dev-1's apply are in scope here:
        // dev-2's own filing/approval entries legitimately name
        // dev-2's rule (they are dev-2's records, written earlier).
        var entriesBefore = rig.Audit.Entries.Count;
        rig.Svc.EvaluateAndApply(Dev, "agent");
        Assert.DoesNotContain(rig.Audit.Entries.Skip(entriesBefore), e => e.Detail.Contains("approval-req-1@dev-2"));
        Assert.Single(rig.Svc.Requests.AllApprovalRules);

        // Dev-2 resolves: its own expired rule is named AS EXPIRED
        // (the live branch, not Validate's admission message), then evicted.
        var (policy2, _) = rig.Svc.ResolvePolicy(Dev2);
        Assert.Contains(policy2!.Notes, n => n.Contains("approval-req-1@dev-2") && n.Contains("is expired"));
        Assert.DoesNotContain(policy2.Notes, n => n.Contains("already expired at admission"));
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }

    // ---- DF7: bounds enforced ---------------------------------------

    [Fact]
    public void DF7_PerDeviceHourlyCap_RotatingRequesterNamesCannotBypass()
    {
        var store = new AppAccessRequestStore();
        for (var i = 0; i < AppControlLimits.MaxRequestsPerDevicePerHour; i++)
        {
            var identity = new AppIdentity(Dev, $"App{i}", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
            var (filed, created, reason) = store.File(Dev, Dev, $"req-{i}", $"user-{i % 5}",
                identity, "need it", T0);
            Assert.True(created, reason);
            // Decide each one so the PENDING caps never bite first;
            // the hourly filing count is what is under test.
            store.RegisterApproverPrincipal(Admin);
            var (denied, denyReason) = store.Deny($"req-{i}", Admin, "no", T0);
            Assert.NotNull(denied);
        }
        // The 51st filing in the same hour — under a FRESH requester
        // name — is refused by the per-DEVICE cap.
        var fresh = new AppIdentity(Dev, "AppFresh", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (req, created2, reason2) = store.File(Dev, Dev, "req-fresh", "brand-new-name",
            fresh, "need it", T0);
        Assert.Null(req); Assert.False(created2);
        Assert.Contains("cap " + AppControlLimits.MaxRequestsPerDevicePerHour, reason2);
        // An hour later the same filing is admitted again.
        var (_, created3, _) = store.File(Dev, Dev, "req-fresh", "brand-new-name",
            fresh, "need it", T0.AddHours(2));
        Assert.True(created3);
    }

    [Fact]
    public void DF7_FleetWidePendingBound_Enforced()
    {
        var store = new AppAccessRequestStore();
        var devices = AppControlLimits.MaxPendingRequestsTotal / AppControlLimits.MaxPendingRequestsPerDevice;
        for (var d = 0; d < devices; d++)
        {
            var device = $"dev-x{d}";
            for (var i = 0; i < AppControlLimits.MaxPendingRequestsPerDevice; i++)
            {
                var identity = new AppIdentity(device, $"App{i}", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
                var (_, created, reason) = store.File(device, device, $"req-{i}", $"u-{d}-{i}",
                    identity, "need it", T0);
                Assert.True(created, reason);
            }
        }
        var extra = new AppIdentity("dev-extra", "App", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (req, created2, reason2) = store.File("dev-extra", "dev-extra", "req-0", "u-x",
            extra, "need it", T0);
        Assert.Null(req); Assert.False(created2);
        Assert.Contains("fleet-wide pending-request bound", reason2);
    }

    // ---- DF8: extended-length UNC normalization ----------------------

    [Fact]
    public void DF8_ExtendedUncForms_NormalizeToPlainUnc_PathDenyMatches()
    {
        Assert.True(AppPathNormalizer.Equals(@"\\?\UNC\server\share\evil.exe", @"\\server\share\evil.exe"));
        Assert.True(AppPathNormalizer.Equals(@"\??\UNC\server\share\evil.exe", @"\\server\share\evil.exe"));
        var rig = new Rig(); rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "path", @"\\server\share\evil.exe", id: "r-unc-deny"));
        var identity = Rig.Identity(path: @"\\?\UNC\server\share\evil.exe");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, identity, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        // The matched rule is named — not a default-deny that would
        // hide the evasion in the ledger.
        Assert.Equal("r-unc-deny", decision.MatchedRule!.Id);
    }

    // ---- DF9: source refresh unions constructor ids ------------------

    [Fact]
    public void DF9_RefreshFromSource_UnionsConstructorPrincipals()
    {
        var rig = new Rig();
        var sourceIds = new List<string> { "second-admin" };
        var svc = new AppControlService(rig.Audit, rig.Policy, rig.Applier, rig.Sink, rig.WorkItems,
            id => id == Dev ? rig.Facts1 : null, null, () => rig.Now,
            approverPrincipalIds: new[] { Admin },
            approverPrincipalSource: () => sourceIds);
        svc.FileRequest(Dev, Dev, "req-1", User, Rig.Identity(), "need it", "agent");
        // The source-provided principal can decide...
        Assert.NotNull(svc.DenyRequest("req-1", "second-admin", "no", "console").Request);
        svc.FileRequest(Dev, Dev, "req-2", User, Rig.Identity(), "need it", "agent");
        // ...and the constructor-registered principal was NOT
        // silently discarded by the first refresh.
        Assert.NotNull(svc.DenyRequest("req-2", Admin, "no", "console").Request);
        // When the source drops a principal, that principal loses
        // power at the next decision; the constructor id remains.
        sourceIds.Clear();
        svc.FileRequest(Dev, Dev, "req-3", User, Rig.Identity(), "need it", "agent");
        var (refused, reason) = svc.DenyRequest("req-3", "second-admin", "no", "console");
        Assert.Null(refused);
        Assert.Contains("not a registered approver principal", reason);
        Assert.NotNull(svc.DenyRequest("req-3", Admin, "no", "console").Request);
    }

    // ---- DF10: filing gate alias parity -------------------------------

    [Fact]
    public void DF10_AliasOnlyDisable_FilingRefuses_NoWorkItemCreated()
    {
        var rig = new Rig();
        rig.SetPolicy(AppControlKeys.FeatureEnabledAlias, "false", "doc-alias-off");
        var (req, created, reason) = rig.Svc.FileRequest(Dev, Dev, "req-1", User,
            Rig.Identity(), "need it", "agent");
        Assert.Null(req); Assert.False(created);
        Assert.Contains("disabled by policy", reason);
        Assert.Empty(rig.Svc.Requests.Requests);
        Assert.Null(rig.WorkItems.Get(WorkItem.IdForRequest("req-1@dev-1")));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_refused");
    }

    // ---- DF11: group callbacks never run under the store lock ---------

    [Fact]
    public void DF11_GroupCallbacks_RunOutsideTheStoreLock()
    {
        var store = new AppAccessRequestStore();
        store.RegisterApproverPrincipal(Admin);
        var identity = new AppIdentity(Dev, "Widget", "1.0", null, SignerA, HashA, @"C:\w\w.exe");
        var (_, created, _) = store.File(Dev, Dev, "req-1", User, identity, "need it", T0);
        Assert.True(created);
        store.GroupExistenceCheck = _ => true;
        store.GroupMembershipCheck = (_, _) =>
        {
            // Re-enter the store from ANOTHER thread while the
            // approval is in flight. If the callback ran under the
            // store lock (the FL-25 code), that thread blocks on
            // the lock while this callback waits for it — deadlock,
            // and this Wait times out.
            var probe = Task.Run(() => store.CountById("req-1"));
            return probe.Wait(TimeSpan.FromSeconds(10)) && probe.Result == 1;
        };
        var (_, rule, reason) = store.Approve("req-1", Admin, "group", "grp-a",
            T0.AddDays(7), null, T0);
        Assert.NotNull(rule);
    }

    // ---- DF12: Deny stays available while the feature is off ----------

    [Fact]
    public void DF12_DenyWhileDisabled_StillAvailable_ApprovalStillRefused()
    {
        var rig = new Rig();
        rig.File(Dev, "req-1"); rig.File(Dev, "req-2", "Gadget");
        rig.SetPolicy(AppControlKeys.FeatureEnabledAlias, "false", "doc-alias-off");
        // Denial mints nothing and stays available to clean the
        // queue while disabled (accepted residual, re-pinned)...
        var (denied, _) = rig.Svc.DenyRequest("req-1", Admin, "cleaning the queue", "console");
        Assert.NotNull(denied);
        // ...while approval — which MINTS policy power — refuses.
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-2", Admin, "device", Dev,
            T0.AddDays(7), null, "console");
        Assert.Null(rule);
        Assert.Contains("disabled by policy", reason);
    }
}

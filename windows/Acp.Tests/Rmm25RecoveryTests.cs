using Acp.Core.Services;
using Acp.Shared.ApplicationControl;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-25 RECOVERY DESTRUCTION PASS — the recovery lane's own
// attacks, run on top of the original lane's battery after that
// lane died unverified. Baseline (recovery lane's own harness run
// over the as-found artefacts): 68/73 with 5 failures — three real
// defects (B1 thin-identity, B3 block-event identity, group-rig)
// plus the expiry-naming gap. The parallel lane's fixes for B1/B2/
// B3 and the group rigs were verified on their merits and kept.
// The attacks below cover what NEITHER battery covered; breaks
// found here were fixed in the model/service and are pinned by
// these tests (fixes R25R-F3..F6, see ledger-rmm25.md addendum).
public class Rmm25RecoveryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
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
        public RecordingAppControlApplier Applier = new();
        public RecordingAppBlockAlertSink Sink = new();
        public WorkItemStore WorkItems;
        public AppControlService Svc;

        public Rig()
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            // FL-25b/F3 amendment: rig registers Admin as an
            // approver principal (decisions are principal-gated now).
            Svc = new AppControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : null, null, () => Now,
                approverPrincipalIds: new[] { Admin });
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
        public void SetEnforce() => SetPolicy(AppControlKeys.Mode, AppControlModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(AppControlKeys.Rules, rules, "doc-rules");
    }

    private static AppIdentity App(string product = "Widget", string? hash = null, string? signer = SignerA,
        string? publisher = "Widget Corp", string? path = @"C:\Program Files\Widget\widget.exe",
        string device = Dev) =>
        new(device, product, "1.0", publisher, signer, hash, path);

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // R25R-01 — '..' segments ABOVE the root must clamp at the drive
    // (Win32 semantics), not pop the drive segment. Before fix
    // R25R-F3, C:\Tools\..\..\evil.exe normalized to \evil.exe and a
    // deny-by-path written for C:\evil.exe did not match it.
    [Fact]
    public void DotDotAboveRoot_ClampsAtDrive_DenyByPathStillMatches()
    {
        Assert.True(AppPathNormalizer.Equals(@"C:\evil.exe", @"C:\Tools\..\..\evil.exe"));
        Assert.True(AppPathNormalizer.Equals(@"\\srv\share\evil.exe", @"\\srv\share\sub\..\..\evil.exe"));
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "path", @"C:\evil.exe", id: "r-deny-root"));
        var sneaky = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, @"C:\Tools\..\..\evil.exe");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, sneaky, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Equal("r-deny-root", decision.MatchedRule!.Id);
    }

    // R25R-02 — the Win32 extended-length prefix \\?\ names the same
    // file; it must not slip past a deny written for the plain path.
    [Fact]
    public void ExtendedLengthPrefix_DoesNotDefeatDenyByPath()
    {
        Assert.True(AppPathNormalizer.Equals(@"C:\Tools\Evil\evil.exe", @"\\?\C:\Tools\Evil\evil.exe"));
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "path", @"C:\Tools\Evil\evil.exe", id: "r-deny"));
        var sneaky = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, @"\\?\C:\Tools\Evil\evil.exe");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, sneaky, "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Equal("r-deny", decision.MatchedRule!.Id);
    }

    // R25R-03 — kill-switch on DECISIONS: an approval attempted
    // while the feature toggle is OFF refuses and mints nothing
    // (before fix R25R-F5 the approval landed silently and its rule
    // went live when the toggle returned). Denial stays available.
    [Fact]
    public void Approval_WhileToggleOff_Refused_MintsNothing_WorksAfterReEnable()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        rig.SetPolicy(AppControlKeys.FeatureEnabled, "false", "doc-toggle", rev: 1);
        var (req, rule, reason) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(30), null, "console");
        Assert.Null(rule); Assert.Null(req);
        Assert.Contains("disabled by policy", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "app_request_approval_refused");
        // Denial is NOT gated — the queue can be cleaned while off.
        var (denied, _) = rig.Svc.DenyRequest("req-1", Admin, "no need", "console");
        Assert.NotNull(denied);
        // A fresh request approved after re-enable works normally.
        rig.SetPolicy(AppControlKeys.FeatureEnabled, "true", "doc-toggle", rev: 2);
        rig.Svc.FileRequest(Dev, Dev, "req-2", User, App(hash: HashB), "survey", "agent");
        var (_, rule2, _) = rig.Svc.ApproveRequest("req-2", Admin, "device", Dev,
            T0.AddDays(30), null, "console");
        Assert.NotNull(rule2);
    }

    // R25R-04 — an expired approval is NAMED in the resolver notes
    // (not silently vanished) and allows nothing. Pins R25R-F4.
    [Fact]
    public void ExpiredApproval_NamedInResolverNotes_AllowsNothing()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        rig.Now = T0.AddDays(8);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        Assert.Contains(policy!.Notes, n => n.Contains("expired") && n.Contains("approval-req-1"));
        Assert.DoesNotContain(policy.Rules, r => r.IsApprovalRule);
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
    }

    // R25R-05 — self-approval under a case/whitespace disguise is
    // still self-approval.
    [Fact]
    public void SelfApproval_CaseAndWhitespaceVariant_Refused()
    {
        var rig = new Rig();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", "  USER-1 ", "device", Dev,
            T0.AddDays(30), null, "console");
        Assert.Null(rule);
        Assert.Contains("never self-approve", reason);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
    }

    // R25R-06 — an approval-minted allow does NOT override an
    // explicit policy deny of the same hash: same rank, deny wins,
    // conflict named. An approval is not a trump over policy.
    [Fact]
    public void ApprovalAllow_DoesNotTrump_ExplicitHashDeny()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("deny", "hash", HashA, id: "r-policy-deny"));
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(30), null, "console");
        Assert.NotNull(rule);
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Equal("r-policy-deny", decision.MatchedRule!.Id);
        Assert.Contains("conflict is named", decision.Reason);
    }

    // R25R-07 — toggle alias discipline: the register spelling
    // rmm.application_control.enabled=false alone turns the feature
    // off at resolution (labelled NotControlled, never silently
    // enforcing); the seeded spelling wins when both are set.
    [Fact]
    public void ToggleAlias_HonouredAtResolution_SeededSpellingWins()
    {
        var rig = new Rig();
        rig.SetPolicy(AppControlKeys.FeatureEnabledAlias, "false", "doc-alias");
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.NotNull(decision);
        Assert.Equal(AppDispositions.NotControlled, decision!.Disposition);

        var rig2 = new Rig();
        rig2.SetPolicy(AppControlKeys.FeatureEnabled, "false", "doc-primary");
        rig2.SetPolicy(AppControlKeys.FeatureEnabledAlias, "true", "doc-alias");
        var (refused, reason) = rig2.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Null(refused);
        Assert.Contains("disabled by policy", reason);
    }

    // R25R-08 — a thin identity wearing an EMPTY-STRING path (not
    // just null) is still too thin to bind. Companion shape to B1.
    [Fact]
    public void ThinIdentity_EmptyStringPath_Refused()
    {
        var rig = new Rig();
        var thin = new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", null, null, "");
        var (decision, reason) = rig.Svc.EvaluateLaunch(Dev, thin, "agent");
        Assert.Null(decision);
        Assert.Contains("too thin", reason);
        var rootOnly = new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", null, null, @"\");
        var (d2, r2) = rig.Svc.EvaluateLaunch(Dev, rootOnly, "agent");
        Assert.Null(d2);
        Assert.Contains("too thin", r2);
    }

    // R25R-09 — precedence in the other direction: an allow-by-hash
    // beats a deny-by-publisher for the same binary (rank decides,
    // not effect). Pins that precedence is rank-first both ways.
    [Fact]
    public void AllowByHash_BeatsDenyByPublisher()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(string.Join("|",
            RuleEntry("deny", "publisher", SignerA, id: "r-pub-deny"),
            RuleEntry("allow", "hash", HashA, id: "r-hash-allow")));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Allowed, decision!.Disposition);
        Assert.Equal("r-hash-allow", decision.MatchedRule!.Id);
        // A different hash from the same (denied) signer is blocked.
        var (other, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent");
        Assert.Equal(AppDispositions.Blocked, other!.Disposition);
        Assert.Equal("r-pub-deny", other.MatchedRule!.Id);
    }

    // R25R-10 — path-only requested identity: the approval binds
    // product+path exactly; the same product at a different path
    // stays blocked, the requested path runs.
    [Fact]
    public void Approval_PathOnlyIdentity_BindsExactPath()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var pathOnly = new AppIdentity(Dev, "FieldTool", "2.0", null, null, null, @"C:\Tools\Field\field.exe");
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, pathOnly, "site work", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(14), null, "console");
        Assert.NotNull(rule);
        Assert.Equal(@"C:\Tools\Field\field.exe", rule!.Path);
        var (ok, _) = rig.Svc.EvaluateLaunch(Dev, pathOnly, "agent");
        Assert.Equal(AppDispositions.Allowed, ok!.Disposition);
        var moved = new AppIdentity(Dev, "FieldTool", "2.0", null, null, null, @"C:\Tools\Other\field.exe");
        var (no, _) = rig.Svc.EvaluateLaunch(Dev, moved, "agent");
        Assert.Equal(AppDispositions.Blocked, no!.Disposition);
    }
}

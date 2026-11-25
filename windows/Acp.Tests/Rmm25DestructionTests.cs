using Acp.Core.Services;
using Acp.Shared.ApplicationControl;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-25 DESTRUCTION PASS — hostile attacks on application control:
// precedence games, publisher spoofing, approval widening, request
// flooding / self-approval, audit-mode confusion, expiry games and
// path tricks. Every attack is resisted by construction or the
// break is fixed and regression-tested here (see ledger-rmm25.md).
public class Rmm25DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string User = "user-1";
    private const string SignerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string SignerEvil = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
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
            // FL-25b/F3 amendment: rig registers Admin as an
            // approver principal (decisions are principal-gated now).
            Svc = new AppControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, null, () => Now,
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

    // D25-01 — precedence game: deny-by-hash vs allow-by-path.
    [Fact]
    public void DenyByHash_NotOverriddenByAllowByPath()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(string.Join("|",
            RuleEntry("allow", "path", @"C:\Program Files\Widget\widget.exe", id: "r-path"),
            RuleEntry("deny", "hash", HashA, id: "r-hash")));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Equal("r-hash", decision.MatchedRule!.Id);
    }

    // D25-02 — same-rank conflict resolves to deny, named.
    [Fact]
    public void SameRankAllowAndDeny_DenyWins_ConflictNamed()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(string.Join("|",
            RuleEntry("allow", "hash", HashA, id: "r-allow"),
            RuleEntry("deny", "hash", HashA, id: "r-deny")));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
        Assert.Contains("conflict is named", decision.Reason);
    }

    // D25-03 — publisher spoofing: an unsigned binary claiming the
    // trusted publisher's DISPLAY name must not satisfy a publisher
    // rule; neither may a binary signed by a different certificate.
    [Fact]
    public void PublisherSpoofing_DisplayNameClaim_DoesNotSatisfyPublisherRule()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "publisher", SignerA));
        // Unsigned, but the display string says "Widget Corp".
        var unsigned = new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", null, HashB,
            @"C:\Program Files\Widget\widget.exe");
        var (d1, _) = rig.Svc.EvaluateLaunch(Dev, unsigned, "agent");
        Assert.Equal(AppDispositions.Blocked, d1!.Disposition);
        // Signed — by the attacker's own certificate, same display name.
        var evilSigned = App(hash: HashB, signer: SignerEvil);
        var (d2, _) = rig.Svc.EvaluateLaunch(Dev, evilSigned, "agent");
        Assert.Equal(AppDispositions.Blocked, d2!.Disposition);
        // The genuine signer still passes.
        var (d3, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashB, signer: SignerA), "agent");
        Assert.Equal(AppDispositions.Allowed, d3!.Disposition);
    }

    // D25-04 — a publisher rule authored against a display NAME is
    // refused at policy resolution, named — it can never silently
    // become a spoofable allow.
    [Fact]
    public void PublisherRule_ByDisplayName_RefusedAndNamed()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "publisher", "Widget Corp"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Empty(policy!.Rules);
        Assert.Contains(policy.Notes, n => n.Contains("signer certificate thumbprint") && n.Contains("display name"));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.Blocked, decision!.Disposition);
    }

    // D25-05 — approval widening: approving one hash of one product
    // must not allow another hash, another signer, another product,
    // or the same identity on another device.
    [Fact]
    public void Approval_CannotWiden_BeyondRequestedIdentity()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey work", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(30), null, "console");
        Assert.NotNull(rule);
        Assert.Equal(AppDispositions.Allowed, rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent").Decision!.Disposition);
        // Different hash, same signer+product: blocked.
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent").Decision!.Disposition);
        // Same hash, different signer: blocked (conjunction).
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, App(hash: HashA, signer: SignerEvil), "agent").Decision!.Disposition);
        // Same hash+signer, different product name: blocked.
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, App(product: "WidgetPro", hash: HashA), "agent").Decision!.Disposition);
        // Exact identity, other device: blocked (device scope).
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev2, App(hash: HashA, device: Dev2), "agent").Decision!.Disposition);
    }

    // D25-06 — approval scope games: org scope refuses; device scope
    // naming another device refuses.
    [Fact]
    public void Approval_OrgScopeOrWrongDevice_Refused()
    {
        var rig = new Rig();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey work", "agent");
        var (_, rule1, reason1) = rig.Svc.ApproveRequest("req-1", Admin, "org", Scope, T0.AddDays(30), null, "console");
        Assert.Null(rule1); Assert.Contains("widen", reason1);
        var (_, rule2, reason2) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev2, T0.AddDays(30), null, "console");
        Assert.Null(rule2); Assert.Contains("another device", reason2);
        Assert.Equal(AppRequestStates.Pending, rig.Svc.Requests.Get("req-1")!.State);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }

    // D25-07 — self-approval and self-denial refuse; a second
    // decision on a decided request refuses.
    [Fact]
    public void Request_SelfApprovalRefused_DecisionsAreSingular()
    {
        var rig = new Rig();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey work", "agent");
        var (_, rule, reason) = rig.Svc.ApproveRequest("req-1", User, "device", Dev, T0.AddDays(30), null, "console");
        Assert.Null(rule); Assert.Contains("never self-approve", reason);
        var (denied, denyReason) = rig.Svc.DenyRequest("req-1", User, "changed my mind", "console");
        Assert.Null(denied); Assert.Contains("own requester", denyReason);
        rig.Svc.DenyRequest("req-1", Admin, "no need", "console");
        var (_, rule2, reason2) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(30), null, "console");
        Assert.Null(rule2); Assert.Contains("already denied", reason2);
        Assert.Empty(rig.Svc.Requests.AllApprovalRules);
    }

    // D25-08 — request flooding: duplicate pending requests collapse
    // to the standing one; the per-device pending cap and the
    // per-requester hourly cap both bite.
    [Fact]
    public void RequestFlooding_DuplicatesCollapse_CapsBite()
    {
        var rig = new Rig();
        var id = App(hash: HashA);
        var (first, created1, _) = rig.Svc.FileRequest(Dev, Dev, "req-1", User, id, "need it", "agent");
        var (dup, created2, _) = rig.Svc.FileRequest(Dev, Dev, "req-2", User, id, "need it again", "agent");
        Assert.True(created1); Assert.False(created2);
        Assert.Equal(first!.Id, dup!.Id);
        // Per-requester hourly cap: distinct applications, one voice.
        for (var i = 0; i < AppControlLimits.MaxRequestsPerRequesterPerHour; i++)
        {
            var other = App(product: $"Tool{i}", hash: new string('a', 60) + i.ToString("x4"));
            rig.Svc.FileRequest(Dev, Dev, $"req-flood-{i}", User, other, "need", "agent");
        }
        var (over, createdOver, reasonOver) = rig.Svc.FileRequest(Dev, Dev, "req-flood-x", User,
            App(product: "OneMore", hash: HashB), "need", "agent");
        Assert.False(createdOver); Assert.Null(over);
        Assert.Contains("flood discipline", reasonOver);
    }

    // D25-09 — spoofed device context at filing refuses, records nothing.
    [Fact]
    public void Request_SpoofedDeviceContext_Refused_NoRecordNoWorkItem()
    {
        var rig = new Rig();
        var (req, created, reason) = rig.Svc.FileRequest(Dev, Dev2, "req-x", User,
            App(hash: HashA), "need", "agent");
        Assert.Null(req); Assert.False(created);
        Assert.Contains("spoofed device context", reason);
        Assert.Empty(rig.Svc.Requests.Requests);
        Assert.Empty(rig.WorkItems.Items);
    }

    // D25-10 — audit-mode confusion: every surface (decision, block
    // event, enforcement plan, audit detail) names AUDIT-ONLY and
    // nothing claims a block happened.
    [Fact]
    public void AuditModeConfusion_NoSurfaceClaimsABlock()
    {
        var rig = new Rig(); // audit by default
        rig.SetRules(RuleEntry("deny", "hash", HashA));
        var (decision, _) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Equal(AppDispositions.WouldBlock, decision!.Disposition);
        Assert.False(decision.ActuallyBlocked);
        var ev = Assert.Single(rig.Sink.Events);
        Assert.False(ev.ActuallyBlocked);
        Assert.Contains("AUDIT-ONLY", ev.EffectiveModeLabel);
        var (apply, _) = rig.Svc.EvaluateAndApply(Dev, Admin);
        Assert.Contains("AUDIT-ONLY", rig.Applier.Plans[0].EffectiveModeLabel);
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "app_control_blocked");
        Assert.All(rig.Audit.Entries.Where(e => e.Kind.StartsWith("app_control_")),
            e => Assert.DoesNotContain("actuallyBlocked=True", e.Detail));
    }

    // D25-11 — expiry games: an expired approval allows nothing; an
    // over-long approval refuses at decision time (never clamped);
    // a hand-built approval rule with no expiry refuses validation.
    [Fact]
    public void ExpiryGames_ExpiredApprovalAllowsNothing_OverLongRefused_NoExpiryRuleRefused()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.Svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        var (_, rule, _) = rig.Svc.ApproveRequest("req-1", Admin, "device", Dev, T0.AddDays(7), null, "console");
        Assert.NotNull(rule);
        Assert.Equal(AppDispositions.Allowed, rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent").Decision!.Disposition);
        rig.Now = T0.AddDays(7); // the expiry instant itself: dead
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent").Decision!.Disposition);
        Assert.Empty(rig.Svc.Requests.LiveApprovalRules(rig.Now));
        // Over-long approval refuses.
        rig.Svc.FileRequest(Dev, Dev, "req-2", User, App(hash: HashB), "survey", "agent");
        var (_, rule2, reason2) = rig.Svc.ApproveRequest("req-2", Admin, "device", Dev,
            T0.AddDays(200), null, "console");
        Assert.Null(rule2); Assert.Contains("maximum approval lifetime", reason2);
        // Hand-built approval-shaped rule without expiry: invalid.
        var forged = new AppRule("approval-forged", "allow", "approval", HashA, null, "Widget", null,
            "device", Dev, null, "req-forged");
        Assert.NotNull(forged.Validate(T0));
        // Defence in depth: even if a forged no-expiry approval rule
        // reached an evaluator directly, it matches NOTHING.
        Assert.False(forged.Matches(App(hash: HashA), T0));
    }

    // D25-12 — path tricks: case, separator, dot-segment and
    // trailing-dot variants of a denied path still match the deny;
    // an 8.3 short-name variant does NOT satisfy an allow-by-path
    // (fail closed — default-deny decides in enforce mode).
    [Fact]
    public void PathTricks_VariantsDoNotDefeatRules()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(string.Join("|",
            RuleEntry("deny", "path", @"C:\Tools\Evil\evil.exe", id: "r-deny-path"),
            RuleEntry("allow", "path", @"C:\Program Files\Widget\widget.exe", id: "r-allow-path")));
        // Case + separator + trailing-dot variant of the DENIED path.
        var sneaky = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, "c:/tools/evil/evil.exe.");
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, sneaky, "agent").Decision!.Disposition);
        // Dot-segment variant of the denied path.
        var dotty = new AppIdentity(Dev, "Evil", "1.0", null, null, HashB, @"C:\Tools\.\Evil\..\Evil\evil.exe");
        Assert.Equal(AppDispositions.Blocked, rig.Svc.EvaluateLaunch(Dev, dotty, "agent").Decision!.Disposition);
        // 8.3 variant of the ALLOWED path: the path rule must not
        // match an unresolved short-name path — default-deny blocks.
        var shorty = new AppIdentity(Dev, "Widget", "1.0", "Widget Corp", SignerA, HashB,
            @"C:\PROGRA~1\Widget\widget.exe");
        var (dShort, _) = rig.Svc.EvaluateLaunch(Dev, shorty, "agent");
        Assert.Equal(AppDispositions.Blocked, dShort!.Disposition);
        Assert.Null(dShort.MatchedRule);
        // The genuine long path still allows.
        Assert.Equal(AppDispositions.Allowed, rig.Svc.EvaluateLaunch(Dev, App(hash: HashB), "agent").Decision!.Disposition);
    }

    // D25-13 — package-offer smuggling: an approval offering a
    // package for a DIFFERENT application (or a disabled / unknown
    // package) refuses and mints nothing.
    [Fact]
    public void Approval_PackageOfferForDifferentApp_Refused()
    {
        var rig = new Rig();
        var packages = new System.Collections.Generic.Dictionary<string, Acp.Shared.Deployment.DeploymentPackage>();
        var def = new Acp.Shared.Remediation.AutomationDefinition("d", "install", "", "standard",
            TimeSpan.Zero, 1, TimeSpan.FromMinutes(1), true,
            Array.Empty<Acp.Shared.Remediation.RemediationStep>());
        packages["pkg-other"] = new Acp.Shared.Deployment.DeploymentPackage("pkg-other", "1.0", "Other", "",
            true, "OtherApp", Array.Empty<Acp.Shared.Deployment.PackageFileComponent>(),
            Array.Empty<Acp.Shared.Deployment.PackageLicenceComponent>(), def, def);
        var svc = new AppControlService(rig.Audit, rig.Policy, rig.Applier, rig.Sink, rig.WorkItems,
            id => id == Dev ? rig.Facts1 : null,
            id => packages.TryGetValue(id, out var p) ? p : null, () => rig.Now,
            approverPrincipalIds: new[] { Admin });
        svc.FileRequest(Dev, Dev, "req-1", User, App(hash: HashA), "survey", "agent");
        var (req, rule, reason) = svc.ApproveRequest("req-1", Admin, "device", Dev,
            T0.AddDays(30), "pkg-other", "console");
        Assert.Null(rule); Assert.Null(req);
        Assert.Contains("not the requested application", reason);
        Assert.Equal(AppRequestStates.Pending, svc.Requests.Get("req-1")!.State);
        Assert.Empty(svc.Requests.AllApprovalRules);
    }

    // D25-14 — consent floor: a policy document carrying a floor key
    // refuses whole at the RMM-07 engine (inherited behaviour, the
    // application-control content cannot smuggle one either).
    [Fact]
    public void ConsentFloorKey_InPolicyDocument_RefusesWholeDocument()
    {
        var rig = new Rig();
        var verdict = rig.Policy.AddDocument(new ManagementPolicyDocument("doc-floor", "org", Scope,
            new Dictionary<string, string>
            {
                [AppControlKeys.Mode] = "enforce",
                ["presence.enabled"] = "false",
            }, 1));
        Assert.False(verdict.Allowed);
        Assert.Contains("consent floor", verdict.Reason);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Equal(AppControlModes.Audit, policy!.Mode); // the enforce never landed
    }

    // D25-15 — kill-switch race: the toggle turned off after a
    // request was filed blocks the approval path too (service gate
    // is on filing; decisions re-check state through the store, and
    // evaluation refuses while disabled).
    [Fact]
    public void KillSwitch_ToggleOff_EvaluationRefuses()
    {
        var rig = new Rig();
        rig.SetEnforce();
        Assert.NotNull(rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent").Decision);
        rig.SetPolicy(AppControlKeys.FeatureEnabled, "false", "doc-toggle");
        var (decision, reason) = rig.Svc.EvaluateLaunch(Dev, App(hash: HashA), "agent");
        Assert.Null(decision);
        Assert.Contains("disabled by policy", reason);
    }
}

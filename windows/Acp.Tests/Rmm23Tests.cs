using Acp.Core.Services;
using Acp.Shared.BrowserPolicy;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Shared.VendorAccess;

namespace Acp.Tests;

// RMM-23 — Privileged access passes for vendors + browser hardening
// policy. Item 1: time-boxed (48h–30d, RefuseOutsideBounds), named-
// vendor, device-scoped passes under full presence/audit rules with
// credential injection. Item 2: extension inventory + allow/block/
// default-deny + browser settings policy as RMM-07 content. Browser
// HISTORY is class-(c) excluded — no surface here touches it.
public class Rmm23Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Issuer = "ops-lead";
    private const string Secret = "V3ndor-Target-P@ssw0rd!";

    private static VendorIdentity Vendor(string id = "vendor-jane") =>
        new(id, "Jane Vendor", "VendorCorp", "jane@vendorcorp.example");

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-a" });
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope, groups: new[] { "grp-b" });
        public InMemoryVendorCredentialVault Vault = new(new DevOnlyPassThroughProtector());
        public RecordingCredentialSink Sink = new();
        public VaultCredentialInjector Injector;
        public RecordingSessionTeardown Teardown = new();
        public VendorPassService Passes;
        public RecordingBrowserPolicyApplier BrowserApplier = new();
        public BrowserPolicyService Browser;

        public Rig(bool withInjector = true, bool withTeardown = true)
        {
            Injector = new VaultCredentialInjector(Vault, Sink);
            Passes = new VendorPassService(Audit, Policy,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                withInjector ? Injector : null,
                withTeardown ? Teardown : null,
                () => Now);
            Browser = new BrowserPolicyService(Audit, Policy, BrowserApplier,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                () => Now);
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1, string level = "org", string target = Scope) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, level, target,
                new Dictionary<string, string> { [key] = value }, rev));

        public VendorPassIssue IssueOk(TimeSpan? duration = null, string? credentialRef = null,
            IEnumerable<string>? devices = null, IEnumerable<string>? groups = null,
            IEnumerable<string>? scopes = null, VendorIdentity? vendor = null)
        {
            var (issue, reason) = Passes.IssuePass(Issuer, vendor ?? Vendor(), Scope,
                devices ?? new[] { Dev }, groups ?? Array.Empty<string>(),
                scopes ?? new[] { Scopes.Observe, Scopes.Drive }, duration ?? TimeSpan.FromDays(7), credentialRef);
            Assert.True(issue is not null, reason);
            return issue!;
        }
    }

    private static BrowserExtensionFact Ext(string id, string name, string version = "1.0",
        string? publisher = null, string device = Dev, string browser = "chrome", bool enabled = true) =>
        new(device, browser, id, name, version, publisher, enabled, "store", T0);

    // ---- passes: issue + duration rule --------------------------------

    [Fact]
    public void Issue_HappyPath_TokenShownOnce_HashOnlyAtRest_AuditComplete()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.Equal(Issuer, issue.Pass.IssuerId);
        Assert.Equal("vendor-jane", issue.Pass.Vendor.Id);
        Assert.Equal(T0, issue.Pass.IssuedUtc);
        Assert.Equal(T0.AddDays(7), issue.Pass.ExpiresUtc);
        Assert.False(issue.Pass.Revoked);
        // Export carries the hash, never the token.
        var export = rig.Passes.Store.ExportJson();
        Assert.DoesNotContain(issue.BearerToken, export);
        // Per-pass trail + chained ledger both carry the issue.
        Assert.Contains(rig.Passes.Store.AuditTrail(issue.Pass.Id),
            e => e.Kind == PassAuditKinds.Issued);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vendor_pass_issued");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Issue_DurationBounds_Exactly48hAnd30dAccepted_OutsideRefusedByNamedRule()
    {
        var rig = new Rig();
        Assert.NotNull(rig.IssueOk(TimeSpan.FromHours(48)).Pass);
        Assert.NotNull(rig.IssueOk(TimeSpan.FromDays(30)).Pass);
        var (short_, shortReason) = rig.Passes.IssuePass(Issuer, Vendor(), Scope,
            new[] { Dev }, Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromHours(47), null);
        Assert.Null(short_);
        Assert.Contains(VendorPassDurationRule.Name, shortReason);
        Assert.Contains("48h", shortReason);
        var (long_, longReason) = rig.Passes.IssuePass(Issuer, Vendor(), Scope,
            new[] { Dev }, Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(31), null);
        Assert.Null(long_);
        Assert.Contains(VendorPassDurationRule.Name, longReason);
        Assert.Contains("30d", longReason);
        // Refusals are NOT clamped into existence: still exactly 2 passes.
        Assert.Equal(2, rig.Passes.Store.List().Count);
    }

    [Fact]
    public void Issue_AnonymousOrSelfIssuedOrUnscoped_RefusedByName()
    {
        var rig = new Rig();
        var anon = new VendorIdentity("v-x", "", "Org", "c@example");
        Assert.Null(rig.Passes.IssuePass(Issuer, anon, Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null).Issue);
        var self = rig.Passes.IssuePass("vendor-jane", Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null);
        Assert.Null(self.Issue);
        Assert.Contains("same identity", self.Reason);
        var unscoped = rig.Passes.IssuePass(Issuer, Vendor(), Scope, Array.Empty<string>(),
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null);
        Assert.Null(unscoped.Issue);
        Assert.Contains("device scope", unscoped.Reason);
    }

    [Fact]
    public void Issue_ForbiddenScopes_RefusedByName_EachOne()
    {
        var rig = new Rig();
        foreach (var scope in new[] { Scopes.Admin, Scopes.BackgroundTools, Scopes.Backstage, Scopes.Unlock, Scopes.Terminal, "teleport" })
        {
            var (issue, reason) = rig.Passes.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
                Array.Empty<string>(), new[] { Scopes.Observe, scope }, TimeSpan.FromDays(3), null);
            Assert.Null(issue);
            Assert.Contains(scope, reason);
        }
        Assert.Empty(rig.Passes.Store.List());
    }

    // ---- passes: authenticate ------------------------------------------

    [Fact]
    public void Authenticate_HappyPath_DeviceAndGroupScope()
    {
        var rig = new Rig();
        var byDevice = rig.IssueOk();
        var (pass, _) = rig.Passes.Authenticate(byDevice.BearerToken, "vendor-jane", Dev, new[] { "grp-a" });
        Assert.NotNull(pass);
        // Group-scoped passes are covered at store level below
        // (service issue requires a named device for its policy gate).
    }

    [Fact]
    public void Store_GroupScopedPass_AuthenticatesMemberDevice_RefusesNonMember()
    {
        var store = new VendorPassStore();
        var (issue, reason) = store.Issue(Issuer, Vendor(), Scope,
            Array.Empty<string>(), new[] { "grp-a" }, new[] { Scopes.Observe },
            TimeSpan.FromDays(5), null, T0);
        Assert.True(issue is not null, reason);
        Assert.NotNull(store.Authenticate(issue!.BearerToken, "vendor-jane", Dev, new[] { "grp-a" }, T0).Pass);
        Assert.Null(store.Authenticate(issue.BearerToken, "vendor-jane", Dev2, new[] { "grp-b" }, T0).Pass);
        Assert.Null(store.Authenticate(issue.BearerToken, "vendor-jane", Dev2, null, T0).Pass);
    }

    [Fact]
    public void Authenticate_UnknownToken_AndWrongVendor_Refused()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.Null(rig.Passes.Authenticate("not-a-token", "vendor-jane", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(null, "vendor-jane", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-other", Dev, null).Pass);
    }

    // ---- passes: credential injection ------------------------------------

    [Fact]
    public void Injection_VendorSession_GetsReceipt_ValueReachesSinkOnly_NowhereElse()
    {
        var rig = new Rig();
        rig.Vault.Store("cred-target-1", Secret);
        var issue = rig.IssueOk(credentialRef: "cred-target-1");
        var (ok, reason, receipt) = rig.Passes.BeginVendorSession(
            issue.BearerToken, "vendor-jane", Dev, new[] { "grp-a" }, "sess-1");
        Assert.True(ok, reason);
        Assert.NotNull(receipt);
        Assert.Equal("cred-target-1", receipt!.CredentialRef);
        // The sink (session layer) received the value — by fingerprint.
        Assert.Equal(new[] { "sess-1" }, rig.Sink.Sessions);
        Assert.Equal(new[] { rig.Sink.FingerprintOf(Secret) }, rig.Sink.Fingerprints);
        // The value appears in NO pass surface: receipt text, trails,
        // ledger details, store export.
        Assert.DoesNotContain(Secret, receipt.ToString());
        foreach (var e in rig.Passes.Store.AuditTrail(issue.Pass.Id))
            Assert.DoesNotContain(Secret, e.Detail);
        foreach (var e in rig.Audit.Entries)
            Assert.DoesNotContain(Secret, e.Detail);
        Assert.DoesNotContain(Secret, rig.Passes.Store.ExportJson());
        Assert.Contains(rig.Passes.Store.AuditTrail(issue.Pass.Id),
            e => e.Kind == PassAuditKinds.CredentialInjected);
    }

    [Fact]
    public void Injection_MissingVaultEntry_RefusesSession_NoFallback()
    {
        var rig = new Rig();
        // D38 F3: issue now requires the reference to resolve, so
        // the dangling-at-begin state is reached honestly — the
        // vault entry exists at issue and is REMOVED before the
        // session begins (vault rotation / entry deleted).
        rig.Vault.Store("cred-ghost", Secret);
        var issue = rig.IssueOk(credentialRef: "cred-ghost");
        Assert.True(rig.Vault.Remove("cred-ghost"));
        var (ok, reason, receipt) = rig.Passes.BeginVendorSession(
            issue.BearerToken, "vendor-jane", Dev, null, "sess-1");
        Assert.False(ok);
        Assert.Null(receipt);
        Assert.Contains("resolves to nothing", reason);
        Assert.Empty(rig.Sink.Sessions);
        // The failed session was unbound: revocation later names none.
        Assert.Empty(rig.Passes.Store.LiveSessions(issue.Pass.Id));
    }

    [Fact]
    public void Issue_CredentialValueShapedReference_Refused()
    {
        var rig = new Rig();
        // A "reference" that is actually a password value refuses.
        var (issue, reason) = rig.Passes.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), Secret);
        Assert.Null(issue);
        Assert.Contains("REFERENCE only", reason);
    }

    // ---- passes: revocation / extension / policy --------------------------

    [Fact]
    public void Revoke_KillsLiveSessions_ViaTeardown_AuthenticationDies()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1").Ok);
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-2").Ok);
        var (ok, reason, ended, notEnded) = rig.Passes.RevokePass(issue.Pass.Id, Issuer, "vendor contract ended");
        Assert.True(ok, reason);
        Assert.Equal(new[] { "sess-1", "sess-2" }, ended.OrderBy(x => x).ToArray());
        Assert.Empty(notEnded);
        Assert.Single(rig.Teardown.Calls);
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
        Assert.False(rig.Passes.RevalidatePass(issue.Pass.Id));
        Assert.Contains(rig.Passes.Store.AuditTrail(issue.Pass.Id), e => e.Kind == PassAuditKinds.Revoked);
    }

    [Fact]
    public void Extend_AlwaysRefused_NewPassIsTheOnlyPath()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        var (ok, reason) = rig.Passes.ExtendPass(issue.Pass.Id, TimeSpan.FromDays(10), Issuer);
        Assert.False(ok);
        Assert.Contains("NEW pass", reason);
        Assert.Equal(T0.AddDays(7), rig.Passes.Store.Get(issue.Pass.Id)!.ExpiresUtc);
        Assert.Contains(rig.Passes.Store.AuditTrail(issue.Pass.Id),
            e => e.Kind == PassAuditKinds.ExtensionRefused);
    }

    [Fact]
    public void Policy_ToggleOff_BlocksIssueAndAuthenticate()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        rig.SetPolicy(VendorPassPolicyKeys.Enabled, "false", "off-1");
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
        var (blocked, _) = rig.Passes.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null);
        Assert.Null(blocked);
    }

    [Fact]
    public void Persistence_ExportImport_RoundTrips_HandEditedForbiddenScopeSkipped()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        var export = rig.Passes.Store.ExportJson();
        var store2 = new VendorPassStore();
        Assert.Equal(1, store2.ImportJson(export));
        Assert.NotNull(store2.Authenticate(issue.BearerToken, "vendor-jane", Dev, null, T0).Pass);
        // Hand-edit: smuggle an admin scope into the export.
        var tampered = export.Replace("\"observe\"", "\"admin\"");
        var store3 = new VendorPassStore();
        Assert.Equal(0, store3.ImportJson(tampered));
    }

    // ---- browser: inventory ----------------------------------------------

    [Fact]
    public void Inventory_Report_AcceptsValidFacts_InvalidDroppedAndNamed()
    {
        var rig = new Rig();
        var (accepted, refusals) = rig.Browser.ReportInventory(Dev, "chrome", new[]
        {
            Ext("ext-good", "Good Tool", "2.1", "GoodCorp"),
            Ext("ext-noname", "", "1.0"),
            Ext("ext-nover", "No Version", ""),
            Ext("ext-wrongdev", "Wrong Device", "1.0", device: Dev2),
        }, Issuer);
        Assert.Equal(1, accepted);
        Assert.Equal(3, refusals.Count);
        Assert.Single(rig.Browser.Inventory.FactsFor(Dev));
    }

    [Fact]
    public void Inventory_Replacement_VanishedExtensionLeavesSnapshot()
    {
        var rig = new Rig();
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("a", "A"), Ext("b", "B") }, Issuer);
        Assert.Equal(2, rig.Browser.Inventory.FactsFor(Dev).Count);
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("a", "A") }, Issuer);
        Assert.Single(rig.Browser.Inventory.FactsFor(Dev));
    }

    // ---- browser: evaluation ------------------------------------------------

    private static Rig BrowserRigWithPolicy(Action<Rig> configure)
    {
        var rig = new Rig();
        configure(rig);
        return rig;
    }

    [Fact]
    public void Evaluate_DefaultDeny_UnlistedDenied_AllowListedAllowed()
    {
        var rig = BrowserRigWithPolicy(r => r.SetPolicy(BrowserPolicyKeys.AllowIds, "ext-ok", "allow-1"));
        rig.Browser.ReportInventory(Dev, "chrome", new[]
        {
            Ext("ext-ok", "Okay Tool"),
            Ext("ext-unknown", "Mystery Tool"),
        }, Issuer);
        var (decisions, policy, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.NotNull(decisions);
        Assert.Equal(BrowserModes.DefaultDeny, policy!.Mode);
        Assert.Equal(ExtensionDispositions.Allowed,
            decisions!.Single(d => d.Fact.ExtensionId == "ext-ok").Disposition);
        Assert.Equal(ExtensionDispositions.DeniedByDefault,
            decisions.Single(d => d.Fact.ExtensionId == "ext-unknown").Disposition);
    }

    [Fact]
    public void Evaluate_BlockByIdNamePublisher_AllBlock()
    {
        var rig = new Rig();
        rig.Policy.AddDocument(new ManagementPolicyDocument("bp-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.BlockIds] = "ext-bad",
                [BrowserPolicyKeys.BlockNames] = "Evil Tool",
                [BrowserPolicyKeys.BlockPublishers] = "BadCorp",
                [BrowserPolicyKeys.ExtensionMode] = "default_allow",
            }, 1));
        rig.Browser.ReportInventory(Dev, "chrome", new[]
        {
            Ext("ext-bad", "Whatever"),
            Ext("ext-other", "Evil Tool"),
            Ext("ext-third", "Fine Name", publisher: "BadCorp"),
            Ext("ext-fine", "Fine Name", publisher: "GoodCorp"),
        }, Issuer);
        var (decisions, _, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.Equal(ExtensionDispositions.Blocked, decisions!.Single(d => d.Fact.ExtensionId == "ext-bad").Disposition);
        Assert.Equal(ExtensionDispositions.Blocked, decisions.Single(d => d.Fact.ExtensionId == "ext-other").Disposition);
        Assert.Equal(ExtensionDispositions.Blocked, decisions.Single(d => d.Fact.ExtensionId == "ext-third").Disposition);
        Assert.Equal(ExtensionDispositions.Allowed, decisions.Single(d => d.Fact.ExtensionId == "ext-fine").Disposition);
    }

    [Fact]
    public void Evaluate_BlockWinsOverAllow_ConflictNamed()
    {
        var rig = new Rig();
        rig.Policy.AddDocument(new ManagementPolicyDocument("bp-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.AllowIds] = "ext-x",
                [BrowserPolicyKeys.BlockIds] = "ext-x",
            }, 1));
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-x", "Conflicted") }, Issuer);
        var (decisions, _, _) = rig.Browser.EvaluateDevice(Dev);
        var d = decisions!.Single();
        Assert.Equal(ExtensionDispositions.Blocked, d.Disposition);
        Assert.Contains("ALSO allow-listed", d.Reason);
    }

    [Fact]
    public void Settings_ClosedSetEnforced_SafeBrowsingOffRefusedAndNamed()
    {
        var rig = new Rig();
        rig.Policy.AddDocument(new ManagementPolicyDocument("bp-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.DeveloperMode)] = "false",
                [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.SafeBrowsing)] = "off",
                [BrowserPolicyKeys.SettingKey("made_up_setting")] = "true",
            }, 1));
        var (_, policy, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.NotNull(policy);
        Assert.Equal("false", policy!.Settings[BrowserSettingKeys.DeveloperMode]);
        Assert.False(policy.Settings.ContainsKey(BrowserSettingKeys.SafeBrowsing));
        Assert.Contains(policy.Notes, n => n.Contains("safe_browsing=off"));
        Assert.Contains(policy.Notes, n => n.Contains("made_up_setting"));
    }

    [Fact]
    public void Apply_RecordingApplier_ReceivesPlan_UnavailableApplier_ReportsNotApplied()
    {
        var rig = new Rig();
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-1", "Tool") }, Issuer);
        var (result, _) = rig.Browser.EvaluateAndApply(Dev, Issuer);
        Assert.NotNull(result);
        Assert.True(result!.Applied);
        Assert.Single(rig.BrowserApplier.Plans);

        var rig2 = new Rig();
        var svc = new BrowserPolicyService(rig2.Audit, rig2.Policy,
            new UnavailableBrowserPolicyApplier(), id => rig2.Facts1, () => T0);
        svc.ReportInventory(Dev, "chrome", new[] { Ext("ext-1", "Tool") }, Issuer);
        var (result2, reason2) = svc.EvaluateAndApply(Dev, Issuer);
        Assert.NotNull(result2);
        Assert.False(result2!.Applied);
        Assert.Contains("NOT applied", reason2);
    }

    [Fact]
    public void Browser_PolicyOff_ReportAndEvaluateRefuse()
    {
        var rig = new Rig();
        rig.SetPolicy(BrowserPolicyKeys.FeatureEnabled, "false", "off-1");
        var (accepted, _) = rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("a", "A") }, Issuer);
        Assert.Equal(0, accepted);
        Assert.Null(rig.Browser.EvaluateDevice(Dev).Decisions);
    }

    [Fact]
    public void BrowserModel_HasNoHistorySurface_ReflectionGuard()
    {
        // The §5 boundary, regression-locked: no public member of any
        // RMM-23 browser type may name history/visits/browsing URLs.
        var types = new[]
        {
            typeof(BrowserExtensionFact), typeof(BrowserInventoryStore),
            typeof(ResolvedBrowserPolicy), typeof(ExtensionDecision),
            typeof(BrowserEnforcementPlan), typeof(BrowserPolicyService),
        };
        foreach (var t in types)
            foreach (var m in t.GetMembers())
            {
                var n = m.Name.ToLowerInvariant();
                Assert.False(n.Contains("history") || n.Contains("visit") || n.Contains("browsing"),
                    $"{t.Name}.{m.Name} names a history surface — §5 boundary breached");
            }
    }
}

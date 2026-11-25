using System.Reflection;
using Acp.Core.Services;
using Acp.Shared.BrowserPolicy;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Shared.VendorAccess;

namespace Acp.Tests;

// RMM-23 D38 FIX — permanent regression tests for the twelve D38
// findings (F1–F12). Each test names the finding it locks. Where a
// prior lane already fixed the model half (F1/F3/F5/F6/F8/F9/F10/
// F11/F12 in VendorPassModel/BrowserPolicyModel), these tests are
// the evidence; the service-layer halves (F2/F4/F5-door/F7) are
// fixed in VendorPassService/BrowserPolicyService and locked here.
public class Rmm23D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Issuer = "ops-lead";
    private const string Secret = "D38-Fix-Secret-Value-7!";

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
        public RecordingSessionTeardown Teardown = new();
        public VendorPassService Passes;
        public RecordingBrowserPolicyApplier BrowserApplier = new();
        public BrowserPolicyService Browser;

        public Rig(ICredentialInjector? injector = null)
        {
            Passes = new VendorPassService(Audit, Policy,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                injector ?? new VaultCredentialInjector(Vault, Sink), Teardown, () => Now);
            Browser = new BrowserPolicyService(Audit, Policy, BrowserApplier,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, () => Now);
        }

        public VendorPassIssue IssueOk(string? credentialRef = null, VendorIdentity? vendor = null,
            IEnumerable<string>? devices = null, IEnumerable<string>? groups = null)
        {
            var (issue, reason) = Passes.IssuePass(Issuer, vendor ?? Vendor(), Scope,
                devices ?? new[] { Dev }, groups ?? Array.Empty<string>(),
                new[] { Scopes.Observe, Scopes.Drive }, TimeSpan.FromDays(7), credentialRef);
            Assert.True(issue is not null, reason);
            return issue!;
        }

        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, 1));
    }

    private static BrowserExtensionFact Ext(string id, string name, string version = "1.0",
        string? publisher = null, string device = Dev) =>
        new(device, "chrome", id, name, version, publisher, true, "store", T0);

    // F1 — the handle yields the value to NO public consumer ------

    [Fact]
    public void F1_Handle_ExposesNoPublicValuePath_Reflection()
    {
        var rig = new Rig();
        rig.Vault.Store("cred-1", Secret);
        var handle = rig.Vault.ResolveForInjection("cred-1");
        Assert.NotNull(handle);
        // Use is not public — code outside the model assembly that
        // obtains a handle cannot present the value anywhere.
        Assert.Null(typeof(VaultCredentialHandle).GetMethod("Use",
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(VaultCredentialHandle).GetMethod("Use",
            BindingFlags.NonPublic | BindingFlags.Instance));
        // No public member returns the value: ToString is the only
        // public string surface and it never carries the secret.
        Assert.DoesNotContain(Secret, handle!.ToString());
        foreach (var m in typeof(VaultCredentialHandle).GetMethods(
                     BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            Assert.False(m.ReturnType == typeof(string) && m.Name != nameof(ToString),
                $"VaultCredentialHandle.{m.Name} returns a string — a possible value path");
    }

    // F2 — revocation racing bind→inject ----------------------------

    private sealed class RevokeDuringInjectInjector : ICredentialInjector
    {
        private readonly ICredentialInjector _inner;
        public VendorPassStore? Store;
        public string PassId = "";
        public RevokeDuringInjectInjector(ICredentialInjector inner) => _inner = inner;
        public bool ReferenceResolves(string credentialRef) => _inner.ReferenceResolves(credentialRef);
        public (CredentialInjectionReceipt? Receipt, string Reason) Inject(
            string passId, string sessionId, string credentialRef, DateTimeOffset now)
        {
            // The race, made deterministic: the pass is revoked
            // (through the store, the sharpest path) WHILE the
            // injection is in flight.
            Store!.Revoke(PassId, Issuer, "race: revoked mid-injection", now);
            return _inner.Inject(passId, sessionId, credentialRef, now);
        }
    }

    [Fact]
    public void F2_RevokeLandingDuringInjection_BeginRefusesAndUnbinds()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-a" });
        var vault = new InMemoryVendorCredentialVault(new DevOnlyPassThroughProtector());
        var sink = new RecordingCredentialSink();
        var racing = new RevokeDuringInjectInjector(new VaultCredentialInjector(vault, sink));
        var svc = new VendorPassService(audit, policy, _ => facts, racing,
            new RecordingSessionTeardown(), () => T0);
        racing.Store = svc.Store; // internal store, visible to the test assembly
        vault.Store("cred-race", Secret);
        var (issue, reason) = svc.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(7), "cred-race");
        Assert.True(issue is not null, reason);
        racing.PassId = issue!.Pass.Id;
        var (ok, beginReason, receipt) = svc.BeginVendorSession(
            issue.BearerToken, "vendor-jane", Dev, null, "sess-race");
        Assert.False(ok);
        Assert.Null(receipt);
        Assert.Contains("revoked or expired", beginReason);
        Assert.Empty(svc.Store.LiveSessions(issue.Pass.Id));
    }

    // F3 — reference shape + resolution ------------------------------

    [Fact]
    public void F3_PasswordShapedAndDanglingReferences_RefusedAtIssue()
    {
        var rig = new Rig();
        foreach (var bad in new[] { "Summer2026", "hunter2", "cred-ghost", "cred-üser1", "cred has space" })
        {
            var (issue, reason) = rig.Passes.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
                Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), bad);
            Assert.Null(issue);
            Assert.False(string.IsNullOrWhiteSpace(reason));
        }
        Assert.Empty(rig.Passes.Store.List());
        // Store level too: a direct store issue cannot persist a
        // value-shaped "reference" either.
        var store = new VendorPassStore();
        var (direct, _) = store.Issue(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), "Summer2026", T0);
        Assert.Null(direct);
        // A real, resolving reference issues fine.
        rig.Vault.Store("cred-real", Secret);
        Assert.NotNull(rig.IssueOk(credentialRef: "cred-real").Pass);
    }

    // F4 — forged caller group list ----------------------------------

    [Fact]
    public void F4_ForgedCallerGroups_DoNotWidenPass_AuthoritativeFactsDecide()
    {
        var rig = new Rig();
        // Pass scoped to grp-a (plus Dev named for the service's
        // policy gate at issue).
        var issue = rig.IssueOk(groups: new[] { "grp-a" });
        // Attack: present on dev-2 claiming dev-2 is in grp-a.
        // dev-2's authoritative facts say grp-b — refused.
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev2,
            new[] { "grp-a" }).Pass);
        Assert.False(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev2,
            new[] { "grp-a" }, "sess-forged").Ok);
        // The real member device authenticates even when the
        // caller claims NO groups — facts, not claims, decide.
        Assert.NotNull(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
    }

    // F5 — store is not a public door; import cannot un-revoke -------

    [Fact]
    public void F5_StoreIsNotPublicOnService_AndImportCannotUnRevoke()
    {
        Assert.Null(typeof(VendorPassService).GetProperty("Store",
            BindingFlags.Public | BindingFlags.Instance));
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.True(rig.Passes.RevokePass(issue.Pass.Id, Issuer, "contract ended").Ok);
        var revokedExport = rig.Passes.Store.ExportJson();
        var store2 = new VendorPassStore();
        Assert.Equal(1, store2.ImportJson(revokedExport));
        Assert.True(store2.Get(issue.Pass.Id)!.Revoked);
        // Hand-edit the export back to Revoked:false and re-import
        // into the SAME store: the entry must not overwrite.
        var doctored = revokedExport.Replace("\"Revoked\":true", "\"Revoked\":false");
        Assert.NotEqual(revokedExport, doctored);
        Assert.Equal(0, store2.ImportJson(doctored));
        Assert.True(store2.Get(issue.Pass.Id)!.Revoked);
        Assert.Null(store2.Authenticate(issue.BearerToken, "vendor-jane", Dev, null, T0).Pass);
    }

    // F6 — expired/revoked holders cannot mint ------------------------

    [Fact]
    public void F6_ExpiredOrRevokedPassHolder_CannotMintPasses()
    {
        var store = new VendorPassStore();
        var (jane, _) = store.Issue(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromHours(48), null, T0);
        Assert.NotNull(jane);
        // After expiry, jane (a PAST holder) still mints nothing.
        var (minted, reason) = store.Issue("vendor-jane", Vendor("vendor-accomplice"), Scope,
            new[] { Dev }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null, T0.AddDays(3));
        Assert.Null(minted);
        Assert.Contains("cannot mint passes", reason);
        // After revocation, same refusal.
        var store2 = new VendorPassStore();
        var (jane2, _) = store2.Issue(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(7), null, T0);
        Assert.True(store2.Revoke(jane2!.Pass.Id, Issuer, "ended", T0).Ok);
        var (minted2, _) = store2.Issue("vendor-jane", Vendor("vendor-alias"), Scope,
            new[] { Dev }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null, T0);
        Assert.Null(minted2);
    }

    // F7 — kill switch applies to revalidation -------------------------

    [Fact]
    public void F7_PolicyOff_MidSession_RevalidationFails()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1").Ok);
        Assert.True(rig.Passes.RevalidatePass(issue.Pass.Id));
        Assert.True(rig.Passes.RevalidatePass(issue.Pass.Id, Dev));
        rig.SetPolicy(VendorPassPolicyKeys.Enabled, "false", "kill-1");
        Assert.False(rig.Passes.RevalidatePass(issue.Pass.Id));
        Assert.False(rig.Passes.RevalidatePass(issue.Pass.Id, Dev));
    }

    // F8 — duplicate session id -----------------------------------------

    [Fact]
    public void F8_DuplicateSessionBind_Refused_OriginalBindingSurvives()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1").Ok);
        // A second begin with the SAME session id refuses (bind is
        // once-only) and — critically — does not disturb the
        // original live binding.
        Assert.False(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1").Ok);
        Assert.Equal(new[] { "sess-1" }, rig.Passes.Store.LiveSessions(issue.Pass.Id));
        // Revocation still names and ends the original session.
        var (ok, _, ended, _) = rig.Passes.RevokePass(issue.Pass.Id, Issuer, "done");
        Assert.True(ok);
        Assert.Equal(new[] { "sess-1" }, ended);
    }

    // F9 — toggles decoupled ----------------------------------------------

    [Fact]
    public void F9_VendorToggleOff_BrowserStillWorks_AndViceVersa()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        // Vendor kill switch OFF: browser hardening unaffected.
        rig.SetPolicy(VendorPassPolicyKeys.Enabled, "false", "vendor-off");
        var (accepted, _) = rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("e1", "Tool") }, Issuer);
        Assert.Equal(1, accepted);
        Assert.NotNull(rig.Browser.EvaluateDevice(Dev).Decisions);
        // Browser toggle OFF: vendor passes unaffected (fresh rig,
        // the two policy docs must not interact).
        var rig2 = new Rig();
        var issue2 = rig2.IssueOk();
        rig2.SetPolicy(BrowserPolicyKeys.FeatureEnabled, "false", "browser-off");
        Assert.Equal(0, rig2.Browser.ReportInventory(Dev, "chrome", new[] { Ext("e1", "Tool") }, Issuer).Accepted);
        Assert.NotNull(rig2.Passes.Authenticate(issue2.BearerToken, "vendor-jane", Dev, null).Pass);
        _ = issue;
    }

    // F10 — relabel variants ------------------------------------------------

    [Fact]
    public void F10_RelabelVariants_StillBlockedByNormalizedName()
    {
        var rig = new Rig();
        rig.Policy.AddDocument(new ManagementPolicyDocument("bp-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.BlockNames] = "Evil Tool",
                [BrowserPolicyKeys.BlockPublishers] = "BadCorp",
                [BrowserPolicyKeys.ExtensionMode] = "default_allow",
            }, 1));
        var variants = new[]
        {
            Ext("v1", "Evil  Tool"),                 // repeated internal whitespace
            Ext("v2", "Evil-Tool"),                  // dash for space… (dash variant of the separator)
            Ext("v3", "Evil Tool\u200B"),           // zero-width space suffix
            Ext("v4", "evil tool"),                  // case
            Ext("v5", "Evil T\u043E\u043El"),        // Cyrillic о homoglyphs
            Ext("v6", "Innocent", publisher: "Bad\u200BCorp"), // publisher zero-width relabel
            Ext("v7", "Innocent", publisher: "BadCorp"),   // publisher block, renamed extension
        };
        foreach (var fact in variants)
        {
            rig.Browser.ReportInventory(Dev, "chrome", new[] { fact }, Issuer);
            var (decisions, _, _) = rig.Browser.EvaluateDevice(Dev);
            Assert.Equal(ExtensionDispositions.Blocked, decisions!.Single().Disposition);
        }
    }

    // F11 — settings value validation -----------------------------------------

    [Fact]
    public void F11_SettingValues_ValidatedAgainstClosedSets()
    {
        var rig = new Rig();
        foreach (var badOff in new[] { "disabled", "none", "false", "0" })
        {
            var r = new Rig();
            r.Policy.AddDocument(new ManagementPolicyDocument("bp-" + badOff, PolicyLevels.Org, Scope,
                new Dictionary<string, string>
                { [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.SafeBrowsing)] = badOff }, 1));
            var (_, policy, _) = r.Browser.EvaluateDevice(Dev);
            Assert.False(policy!.Settings.ContainsKey(BrowserSettingKeys.SafeBrowsing));
            Assert.Contains(policy.Notes, n => n.Contains("safe_browsing"));
        }
        // Arbitrary values for other keys are dropped and named too.
        rig.Policy.AddDocument(new ManagementPolicyDocument("bp-x", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.DeveloperMode)] = "banana",
                [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.ThirdPartyCookies)] = "sometimes",
                [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.SafeBrowsing)] = "enhanced",
            }, 1));
        var (_, resolved, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.False(resolved!.Settings.ContainsKey(BrowserSettingKeys.DeveloperMode));
        Assert.False(resolved.Settings.ContainsKey(BrowserSettingKeys.ThirdPartyCookies));
        Assert.Equal("enhanced", resolved.Settings[BrowserSettingKeys.SafeBrowsing]);
        Assert.Contains(resolved.Notes, n => n.Contains("developer_mode=banana"));
    }

    // F12 — bounded growth -------------------------------------------------------

    [Fact]
    public void F12_InventoryCapEnforcedDuringEnumeration_AndTrailBounded()
    {
        var rig = new Rig();
        var flood = Enumerable.Range(0, BrowserInventoryLimits.MaxExtensionsPerBrowser + 88)
            .Select(i => Ext($"ext-{i}", $"Tool {i}")).ToList();
        var (accepted, refusals) = rig.Browser.ReportInventory(Dev, "chrome", flood, Issuer);
        Assert.Equal(0, accepted);
        Assert.Contains(refusals, r => r.Contains("cap"));
        Assert.Empty(rig.Browser.Inventory.FactsFor(Dev));

        // Per-pass trail: 2100 failed authentications cannot grow
        // it past the named cap.
        var store = new VendorPassStore();
        var (issue, _) = store.Issue(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(7), null, T0);
        for (var i = 0; i < 2100; i++)
            store.Authenticate(issue!.BearerToken, "vendor-mallory", Dev, null, T0);
        Assert.True(store.AuditTrail(issue.Pass.Id).Count <= VendorPassLimits.MaxAuditEntriesPerPass);
    }
}

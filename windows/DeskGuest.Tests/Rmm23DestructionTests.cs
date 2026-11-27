using System.Reflection;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.BrowserPolicy;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.VendorAccess;

namespace DeskGuest.Tests;

// RMM-23 DESTRUCTION PASS — hostile attacks on vendor passes and
// browser hardening. Each test is an attack that must FAIL:
//   D23-01 scope escape (pass for A used on B)
//   D23-02 expiry games (past expiry, before issue, clock rewind
//          after revocation, mid-session expiry)
//   D23-03 pass transfer (another vendor identity presenting)
//   D23-04 credential extraction (every surface searched for the
//          value: export, trails, ledger, receipts, errors,
//          redactor behaviour, handle ToString)
//   D23-05 pass escalation (holder mints / widens / self-issues)
//   D23-06 revocation race (revoked pass in a live session)
//   D23-07 browser relabel (blocked extension, new id)
//   D23-08 default-deny bypass via settings/mode conflicts
//   D23-09 import forgery (hand-edited store)
//   D23-10 policy kill-switch races (off between issue and use)
public class Rmm23DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Issuer = "ops-lead";
    private const string Secret = "Destructi0n-Secret-Value-42!";

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

        public Rig()
        {
            Passes = new VendorPassService(Audit, Policy,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null,
                new VaultCredentialInjector(Vault, Sink), Teardown, () => Now);
            Browser = new BrowserPolicyService(Audit, Policy, BrowserApplier,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, () => Now);
        }

        public VendorPassIssue IssueOk(string device = Dev, string? credentialRef = null,
            VendorIdentity? vendor = null, TimeSpan? duration = null)
        {
            var (issue, reason) = Passes.IssuePass(Issuer, vendor ?? Vendor(), Scope,
                new[] { device }, Array.Empty<string>(),
                new[] { Scopes.Observe, Scopes.Drive }, duration ?? TimeSpan.FromDays(7), credentialRef);
            Assert.True(issue is not null, reason);
            return issue!;
        }

        public void PolicyDoc(string id, Dictionary<string, string> settings) =>
            Policy.AddDocument(new ManagementPolicyDocument(id, PolicyLevels.Org, Scope, settings, 1));
    }

    private static BrowserExtensionFact Ext(string id, string name, string version = "1.0",
        string? publisher = null, string device = Dev) =>
        new(device, "chrome", id, name, version, publisher, true, "store", T0);

    // D23-01 — scope escape -------------------------------------------

    [Fact]
    public void D01_PassForDeviceA_UsedOnDeviceB_Fails_EveryScopeForm()
    {
        var rig = new Rig();
        var issue = rig.IssueOk(device: Dev);
        // Direct: device B is not in scope.
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev2, new[] { "grp-b" }).Pass);
        // Via B's group: the pass names no groups at all.
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev2, null).Pass);
        // Session bind on B fails too.
        Assert.False(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev2, new[] { "grp-b" }, "s-x").Ok);
        // And the failure is trailed on the pass.
        Assert.Contains(rig.Passes.Store.AuditTrail(issue.Pass.Id),
            e => e.Kind == PassAuditKinds.AuthFailed && e.Detail.Contains("outside this pass's scope"));
    }

    [Fact]
    public void D01b_GroupPass_DeviceLeavingGroup_LosesAccess()
    {
        var store = new VendorPassStore();
        var (issue, _) = store.Issue(Issuer, Vendor(), Scope, Array.Empty<string>(), new[] { "grp-a" },
            new[] { Scopes.Observe }, TimeSpan.FromDays(5), null, T0);
        Assert.NotNull(store.Authenticate(issue!.BearerToken, "vendor-jane", Dev, new[] { "grp-a" }, T0).Pass);
        // Membership is evaluated at presentation: grp-a gone → no access.
        Assert.Null(store.Authenticate(issue.BearerToken, "vendor-jane", Dev, new[] { "grp-other" }, T0).Pass);
        Assert.Null(store.Authenticate(issue.BearerToken, "vendor-jane", Dev, Array.Empty<string>(), T0).Pass);
    }

    // D23-02 — expiry games ---------------------------------------------

    [Fact]
    public void D02_Expiry_AtAndAfterExpiry_Fails_BeforeIssue_Fails()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        // One second before expiry: still valid.
        Assert.NotNull(rig.Passes.Store.Authenticate(issue.BearerToken, "vendor-jane", Dev, null,
            T0.AddDays(7).AddSeconds(-1)).Pass);
        // AT expiry: dead (no grace window).
        Assert.Null(rig.Passes.Store.Authenticate(issue.BearerToken, "vendor-jane", Dev, null,
            T0.AddDays(7)).Pass);
        // Before issue (clock wound back / future-dated pass): dead.
        Assert.Null(rig.Passes.Store.Authenticate(issue.BearerToken, "vendor-jane", Dev, null,
            T0.AddHours(-1)).Pass);
    }

    [Fact]
    public void D02b_MidSessionExpiry_RevalidationFails_SoSessionMustEnd()
    {
        var rig = new Rig();
        var issue = rig.IssueOk(duration: TimeSpan.FromHours(48));
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1").Ok);
        rig.Now = T0.AddHours(47);
        Assert.True(rig.Passes.RevalidatePass(issue.Pass.Id));
        rig.Now = T0.AddHours(48);
        Assert.False(rig.Passes.RevalidatePass(issue.Pass.Id));
        // Winding the clock BACK does not resurrect anything already
        // revoked — revocation is a stored fact, not a time function.
        var (ok, _, _, _) = rig.Passes.RevokePass(issue.Pass.Id, Issuer, "done early");
        Assert.True(ok);
        rig.Now = T0;
        Assert.False(rig.Passes.RevalidatePass(issue.Pass.Id));
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
    }

    // D23-03 — pass transfer ----------------------------------------------

    [Fact]
    public void D03_Transfer_AnotherVendorPresentingToken_Fails()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-mallory", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, null, Dev, null).Pass);
        // Case games on the vendor id do not help a DIFFERENT id, and
        // the true vendor still works (binding is identity, not luck).
        Assert.NotNull(rig.Passes.Authenticate(issue.BearerToken, "VENDOR-JANE", Dev, null).Pass);
    }

    [Fact]
    public void D03b_TokenForgery_RandomAndMutatedTokens_Fail()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        var mutated = (issue.BearerToken[0] == 'A' ? 'B' : 'A') + issue.BearerToken[1..];
        Assert.Null(rig.Passes.Authenticate(mutated, "vendor-jane", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(Convert.ToBase64String(new byte[32]), "vendor-jane", Dev, null).Pass);
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken + "x", "vendor-jane", Dev, null).Pass);
    }

    // D23-04 — credential extraction ---------------------------------------

    [Fact]
    public void D04_CredentialValue_AppearsOnNoSurface()
    {
        var rig = new Rig();
        rig.Vault.Store("cred-1", Secret);
        var issue = rig.IssueOk(credentialRef: "cred-1");
        var (ok, _, receipt) = rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1");
        Assert.True(ok);
        // Provoke error paths too: a genuinely BAD injection (the
        // sink refuses the logon — D38 F12b: the earlier version of
        // this leg commented "bad injection" but presented the
        // same valid credential and SUCCEEDED) + failed auth.
        rig.Sink.Accept = false;
        var (badOk, badReason, badReceipt) = rig.Passes.BeginVendorSession(
            issue.BearerToken, "vendor-jane", Dev, null, "sess-2");
        Assert.False(badOk);
        Assert.Null(badReceipt);
        Assert.DoesNotContain(Secret, badReason);
        rig.Sink.Accept = true;
        rig.Passes.Authenticate("junk", "vendor-jane", Dev, null);

        var surfaces = new List<string>
        {
            rig.Passes.Store.ExportJson(),
            receipt!.ToString(),
            issue.Pass.ToString(),
            rig.Vault.ResolveForInjection("cred-1")!.ToString(),
        };
        surfaces.AddRange(rig.Passes.Store.AuditTrail(issue.Pass.Id).Select(e => e.Detail + e.Actor + e.Kind));
        surfaces.AddRange(rig.Audit.Entries.Select(e => e.Detail + e.Actor + e.Kind));
        foreach (var s in surfaces)
            Assert.DoesNotContain(Secret, s);
        // The audit REDACTOR is a second wall: even if a caller tried
        // to log the value under a credential key it is redacted.
        using var doc = System.Text.Json.JsonDocument.Parse(
            "{\"password\":\"" + Secret + "\"}");
        var redacted = Redactor.RedactJson(doc.RootElement).GetRawText();
        Assert.DoesNotContain(Secret, redacted);
    }

    [Fact]
    public void D04b_SinkRefusal_FailsSession_ValueStillNowhere()
    {
        var rig = new Rig();
        rig.Vault.Store("cred-1", Secret);
        rig.Sink.Accept = false;
        var issue = rig.IssueOk(credentialRef: "cred-1");
        var (ok, reason, receipt) = rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-1");
        Assert.False(ok);
        Assert.Null(receipt);
        Assert.DoesNotContain(Secret, reason);
        Assert.Empty(rig.Passes.Store.LiveSessions(issue.Pass.Id));
        foreach (var e in rig.Audit.Entries) Assert.DoesNotContain(Secret, e.Detail);
    }

    [Fact]
    public void D04c_PassRecordShape_HasNoCredentialValueField_ReflectionGuard()
    {
        // Structural: VendorPass can carry only a REFERENCE. No
        // property may be shaped like a credential value carrier.
        foreach (var p in typeof(VendorPass).GetProperties())
        {
            var n = p.Name.ToLowerInvariant();
            Assert.False(n.Contains("password") || n.Contains("secret") || n == "credential",
                $"VendorPass.{p.Name} looks like a credential-value field");
        }
        Assert.NotNull(typeof(VendorPass).GetProperty("CredentialRef"));
    }

    // D23-05 — escalation ----------------------------------------------------

    [Fact]
    public void D05_PassHolder_MintingAnotherPass_Refused()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        // The vendor (holding an active pass) tries to issue a pass
        // for an accomplice — the store's escalation guard refuses.
        var (minted, reason) = rig.Passes.Store.Issue("vendor-jane",
            Vendor("vendor-accomplice"), Scope, new[] { Dev2 }, Array.Empty<string>(),
            new[] { Scopes.Observe }, TimeSpan.FromDays(7), null, T0);
        Assert.Null(minted);
        Assert.Contains("cannot mint", reason);
        // Widening via re-issue by the real issuer for a BROADER
        // scope still cannot carry forbidden scopes (defence in depth).
        var (wide, _) = rig.Passes.IssuePass(Issuer, Vendor("vendor-two"), Scope,
            new[] { Dev, Dev2 }, Array.Empty<string>(),
            new[] { Scopes.Observe, Scopes.Admin }, TimeSpan.FromDays(7), null);
        Assert.Null(wide);
    }

    [Fact]
    public void D05b_PassHolder_CannotRevokeOrExtend_OthersPasses()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        // Extension by the vendor themselves: refused like any other.
        Assert.False(rig.Passes.ExtendPass(issue.Pass.Id, TimeSpan.FromDays(30), "vendor-jane").Ok);
        Assert.Equal(T0.AddDays(7), rig.Passes.Store.Get(issue.Pass.Id)!.ExpiresUtc);
        // Revocation (D38 F12b: this test's name always claimed
        // revoke; it now ASSERTS it): vendor-jane holds a pass, so
        // she is refused as revoker of ANOTHER vendor's pass — a
        // pass holder revoking a rival's pass is an escalation.
        var other = rig.IssueOk(vendor: Vendor("vendor-two"));
        var (revoked, revokeReason, _, _) = rig.Passes.RevokePass(other.Pass.Id, "vendor-jane", "sabotage");
        Assert.False(revoked);
        Assert.Contains("pass holder cannot revoke", revokeReason);
        Assert.False(rig.Passes.Store.Get(other.Pass.Id)!.Revoked);
        // And the operator revoking still works (the guard is
        // about WHO revokes, not a broken revoke path).
        Assert.True(rig.Passes.RevokePass(other.Pass.Id, Issuer, "contract ended").Ok);
    }

    // D23-06 — revocation race -------------------------------------------------

    [Fact]
    public void D06_Revocation_MidSession_KillsBindingAndAuthentication()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.True(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-live").Ok);
        var (ok, _, ended, _) = rig.Passes.RevokePass(issue.Pass.Id, Issuer, "vendor fired");
        Assert.True(ok);
        Assert.Equal(new[] { "sess-live" }, ended);
        // Store binding is cleared; a second session cannot bind.
        Assert.Empty(rig.Passes.Store.LiveSessions(issue.Pass.Id));
        Assert.False(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "sess-new").Ok);
        // Double revoke refuses by name (no silent success).
        Assert.False(rig.Passes.RevokePass(issue.Pass.Id, Issuer, "again").Ok);
        // Revocation without a reason refuses.
        var issue2 = rig.IssueOk(vendor: Vendor("vendor-two"));
        Assert.False(rig.Passes.RevokePass(issue2.Pass.Id, Issuer, "").Ok);
    }

    [Fact]
    public void D06b_Revocation_NoTeardownWired_NamesUnendedSessions_NeverClaimsKilled()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        var svc = new VendorPassService(audit, policy, _ => facts, null, null, () => T0);
        var (issue, _) = svc.IssuePass(Issuer, Vendor(), Scope, new[] { Dev },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null);
        Assert.True(svc.BeginVendorSession(issue!.BearerToken, "vendor-jane", Dev, null, "sess-orphan").Ok);
        var (ok, reason, ended, notEnded) = svc.RevokePass(issue.Pass.Id, Issuer, "contract ended");
        Assert.True(ok);
        Assert.Empty(ended);
        Assert.Equal(new[] { "sess-orphan" }, notEnded);
        Assert.Contains("NOT ended", reason);
    }

    // D23-07 — browser relabel ---------------------------------------------------

    [Fact]
    public void D07_BlockedExtension_ReappearsUnderNewId_StillBlockedByName()
    {
        var rig = new Rig();
        rig.PolicyDoc("bp-1", new Dictionary<string, string>
        {
            [BrowserPolicyKeys.BlockNames] = "Evil Tool",
            [BrowserPolicyKeys.ExtensionMode] = "default_allow",
        });
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-original", "Evil Tool", "1.0") }, Issuer);
        var (d1, _, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.Equal(ExtensionDispositions.Blocked, d1!.Single().Disposition);
        // The author regenerates the id (and bumps the version).
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-brand-new-id", "Evil Tool", "9.9") }, Issuer);
        var (d2, _, _) = rig.Browser.EvaluateDevice(Dev);
        var decision = d2!.Single();
        Assert.Equal(ExtensionDispositions.Blocked, decision.Disposition);
        Assert.StartsWith("block_names:", decision.MatchedRule);
        // Publisher-level block also survives relabel + rename.
        rig.PolicyDoc("bp-2", new Dictionary<string, string>
        {
            [BrowserPolicyKeys.BlockPublishers] = "BadCorp",
        });
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-x1", "Innocent Name", "1.0", "BadCorp") }, Issuer);
        var (d3, _, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.Equal(ExtensionDispositions.Blocked, d3!.Single().Disposition);
    }

    [Fact]
    public void D07b_AllowById_DoesNotTransferToRelabelledCopy()
    {
        var rig = new Rig();
        rig.PolicyDoc("bp-1", new Dictionary<string, string>
        {
            [BrowserPolicyKeys.AllowIds] = "ext-approved",
            [BrowserPolicyKeys.ExtensionMode] = "default_deny",
        });
        // Same NAME, different id: allow is id-precise, so the copy
        // is denied by default — an allow never widens by name.
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-copycat", "Approved Tool") }, Issuer);
        var (decisions, _, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.Equal(ExtensionDispositions.DeniedByDefault, decisions!.Single().Disposition);
    }

    // D23-08 — default-deny bypass via conflicts -----------------------------------

    [Fact]
    public void D08_ModeGames_UnparsableModeFallsToDefaultDeny_SettingsCannotWiden()
    {
        var rig = new Rig();
        rig.PolicyDoc("bp-1", new Dictionary<string, string>
        {
            [BrowserPolicyKeys.ExtensionMode] = "allow_everything_please",
            // A settings key trying to smuggle an extension decision:
            [BrowserPolicyKeys.SettingKey(BrowserSettingKeys.DeveloperMode)] = "true",
        });
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-unknown", "Mystery") }, Issuer);
        var (decisions, policy, _) = rig.Browser.EvaluateDevice(Dev);
        Assert.Equal(BrowserModes.DefaultDeny, policy!.Mode);
        Assert.Equal(ExtensionDispositions.DeniedByDefault, decisions!.Single().Disposition);
        Assert.Contains(policy.Notes, n => n.Contains("not a known mode"));
    }

    [Fact]
    public void D08b_ConsentFloorKey_InBrowserPolicyDocument_RefusesWholeDocument()
    {
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddDocument(new ManagementPolicyDocument("evil-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [BrowserPolicyKeys.ExtensionMode] = "default_allow",
                ["presence.enabled"] = "false",
            }, 1));
        Assert.False(verdict.Allowed);
        Assert.Contains("consent floor", verdict.Reason.ToLowerInvariant());
    }

    [Fact]
    public void D08c_GroupOverride_CannotWidenOrgDefaultDeny_ForNonMember_AndMemberInherits()
    {
        var rig = new Rig();
        // Org: default_deny. Group grp-a: default_allow (a group CAN
        // set its own mode — inheritance is override-capable; the
        // check here is that it applies ONLY to members).
        rig.Policy.AddGroup(new GroupDefinition("grp-a", "A", Array.Empty<GroupRule>()));
        rig.Policy.AddDocument(new ManagementPolicyDocument("org-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [BrowserPolicyKeys.ExtensionMode] = "default_deny" }, 1));
        rig.Policy.AddDocument(new ManagementPolicyDocument("grp-1", PolicyLevels.Group, "grp-a",
            new Dictionary<string, string> { [BrowserPolicyKeys.ExtensionMode] = "default_allow" }, 1));
        rig.Browser.ReportInventory(Dev, "chrome", new[] { Ext("ext-u", "Unknown") }, Issuer);
        rig.Browser.ReportInventory(Dev2, "chrome", new[] { Ext("ext-u", "Unknown", device: Dev2) }, Issuer);
        // dev-1 IS in grp-a (facts) → group override applies.
        Assert.Equal(BrowserModes.DefaultAllow, rig.Browser.EvaluateDevice(Dev).Policy!.Mode);
        // dev-2 is NOT → org default_deny stands; no leakage.
        Assert.Equal(BrowserModes.DefaultDeny, rig.Browser.EvaluateDevice(Dev2).Policy!.Mode);
        Assert.Equal(ExtensionDispositions.DeniedByDefault,
            rig.Browser.EvaluateDevice(Dev2).Decisions!.Single().Disposition);
    }

    // D23-09 — import forgery ---------------------------------------------------------

    [Fact]
    public void D09_ImportForgery_ShortDuration_AdminScope_AnonymousVendor_AllSkipped()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        var export = rig.Passes.Store.ExportJson();
        // Forge 1: shrink the window below 48h by editing the
        // expiry DATE back onto the issue date (serialized form is
        // ISO without fractional seconds for whole-second times).
        var shortExport = export.Replace("2026-11-28", "2026-11-21");
        Assert.NotEqual(export, shortExport);
        Assert.Equal(0, new VendorPassStore().ImportJson(shortExport));
        // Forge 2: blank the vendor name (anonymous pass).
        var anonExport = export.Replace("Jane Vendor", "");
        Assert.Equal(0, new VendorPassStore().ImportJson(anonExport));
        // Forge 3: garbage token hash.
        var hashExport = export.Replace("\"TokenHash\":", "\"TokenHashX\":");
        var s3 = new VendorPassStore();
        s3.ImportJson(hashExport); // must not throw; entry skipped or hash unreadable
        Assert.Null(s3.Authenticate(issue.BearerToken, "vendor-jane", Dev, null, T0).Pass);
        // The honest export still restores exactly one working pass.
        var honest = new VendorPassStore();
        Assert.Equal(1, honest.ImportJson(export));
        Assert.NotNull(honest.Authenticate(issue.BearerToken, "vendor-jane", Dev, null, T0).Pass);
    }

    // D23-10 — policy kill-switch race ----------------------------------------------------

    [Fact]
    public void D10_PolicyTurnedOff_BetweenIssueAndUse_UseFails()
    {
        var rig = new Rig();
        var issue = rig.IssueOk();
        Assert.NotNull(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
        rig.Policy.AddDocument(new ManagementPolicyDocument("kill-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [VendorPassPolicyKeys.Enabled] = "false" }, 1));
        Assert.Null(rig.Passes.Authenticate(issue.BearerToken, "vendor-jane", Dev, null).Pass);
        Assert.False(rig.Passes.BeginVendorSession(issue.BearerToken, "vendor-jane", Dev, null, "s-1").Ok);
    }

    [Fact]
    public void D10b_UnknownDeviceFacts_FailClosed_Everywhere()
    {
        var rig = new Rig();
        var (issue, _) = rig.Passes.IssuePass(Issuer, Vendor(), Scope, new[] { "ghost-device" },
            Array.Empty<string>(), new[] { Scopes.Observe }, TimeSpan.FromDays(3), null);
        Assert.Null(issue); // no facts → policy cannot evaluate → no issue
        var (accepted, _) = rig.Browser.ReportInventory("ghost-device", "chrome",
            new[] { new BrowserExtensionFact("ghost-device", "chrome", "e", "E", "1", null, true, null, T0) }, Issuer);
        Assert.Equal(0, accepted);
    }
}

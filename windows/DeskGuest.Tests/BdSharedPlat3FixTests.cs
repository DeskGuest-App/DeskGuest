using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.SiteDocs;
using DeskGuest.Shared.Tools;
using DeskGuest.Shared.Update;
using DeskGuest.Shared.VendorAccess;

namespace DeskGuest.Tests;

/// <summary>BD-SHARED-PLAT-3 fix lane regression tests (packet
/// 55df0812). One or more tests per finding, named F&lt;n&gt;_*; each
/// pins the FIXED behaviour and several re-attack the fixed surface
/// (destruction discipline). All secrets are fake test strings.</summary>
public class BdSharedPlat3FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = Rmm21TestsScope.Scope;
    private const string Admin = Rmm21TestsScope.Admin;
    private const string Tech = Rmm21TestsScope.Tech;
    private const string Dev1 = Rmm21TestsScope.Dev1;
    private const string GrpA = Rmm21TestsScope.GrpA;
    private const string Secret = "FAKE-vendor-target-secret-1";

    private static VendorIdentity Vendor(string id = "vendor-jane") =>
        new(id, "Jane Vendor", "VendorCorp", "jane@vendorcorp.example");

    private static (VendorPassStore Store, VendorPassIssue Issue) IssuedStore(ISecretProtector? protector = null)
    {
        var store = new VendorPassStore(protector);
        var (issue, reason) = store.Issue("ops-lead", Vendor(), Scope,
            new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null, T0);
        Assert.True(issue is not null, reason);
        return (store, issue!);
    }

    // ---------- F2: sink fingerprints are salted HMACs ----------

    [Fact]
    public void F2_SinkFingerprint_IsNotBareSha256_AndDiffersPerInstance()
    {
        var bare = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Secret))).ToLowerInvariant();
        var a = new RecordingCredentialSink();
        var b = new RecordingCredentialSink();
        Assert.NotEqual(bare, a.FingerprintOf(Secret));
        Assert.NotEqual(a.FingerprintOf(Secret), b.FingerprintOf(Secret));
        // The sink still records a stable fingerprint for ITS value:
        Assert.True(a.PresentCredential("sess-1", Secret));
        Assert.Equal(a.FingerprintOf(Secret), Assert.Single(a.Fingerprints));
        // And a different secret fingerprints differently.
        Assert.NotEqual(a.FingerprintOf(Secret), a.FingerprintOf(Secret + "x"));
    }

    // ---------- F3: production vault over the site credential store ----------

    [Fact]
    public void F3_SiteDocsVault_ResolvesAudits_AndDeletionTakesEffect()
    {
        var rig = new Rmm21Tests.Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Rmm21Tests.Secret1, users: new[] { Tech });
        var vault = new SiteDocsVendorCredentialVault(rig.Service);
        var sink = new RecordingCredentialSink();
        var injector = new VaultCredentialInjector(vault, sink);

        Assert.True(vault.Contains(meta.Id));
        var (receipt, reason) = injector.Inject("pass-1", "sess-1", meta.Id, T0);
        Assert.True(receipt is not null, reason);
        Assert.Equal(sink.FingerprintOf(Rmm21Tests.Secret1), Assert.Single(sink.Fingerprints));
        // The injection is chained-audited by the vault BEFORE the
        // value left it, under its own kind (never a reveal).
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "site_credential_injected");
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "site_credential_revealed");

        // Deleting the site credential takes effect on the vault
        // surface immediately: no resolve, no injection.
        Assert.True(rig.Service.DeleteCredential(Admin, Scope, meta.Id).Ok);
        Assert.False(vault.Contains(meta.Id));
        var (receipt2, _) = injector.Inject("pass-1", "sess-2", meta.Id, T0);
        Assert.Null(receipt2);
        Assert.Single(sink.Fingerprints); // nothing new reached the sink

        // The adapter is a view, not a second store of record.
        Assert.Throws<InvalidOperationException>(() => vault.Store("cred-x", "v"));
        Assert.Throws<InvalidOperationException>(() => vault.Remove("cred-x"));
    }

    [Fact]
    public void F3_PassRevalidation_FailsAfterSiteCredentialDeleted()
    {
        var rig = new Rmm21Tests.Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Rmm21Tests.Secret1, users: new[] { Tech });
        var vault = new SiteDocsVendorCredentialVault(rig.Service);
        var injector = new VaultCredentialInjector(vault, new RecordingCredentialSink());
        var passes = new VendorPassService(rig.Audit, rig.Policy,
            id => StaticDeviceFacts.Of(id, Scope), injector, null, () => rig.Now);
        var (issue, reason) = passes.IssuePass("ops-lead", Vendor(), Scope,
            new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), meta.Id);
        Assert.True(issue is not null, reason);
        Assert.True(passes.RevalidatePass(issue!.Pass.Id));
        Assert.True(rig.Service.DeleteCredential(Admin, Scope, meta.Id).Ok);
        Assert.False(passes.RevalidatePass(issue.Pass.Id),
            "a deleted site credential must end the pass's credential validity at revalidation");
    }

    // ---------- F4: import integrity (empty hash / blank provenance refused) ----------

    [Fact]
    public void F4_Import_BlankSnapshotHash_Refused_DeletedDocStaysDeleted()
    {
        var rig = new Rmm21Tests.Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ network", rig.NetworkFacts());
        Assert.True(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        var export = rig.Service.ExportJson();
        // Attack: strip the snapshot hash so the deleted document
        // looks like unverifiable "legacy" material.
        var tampered = TamperDocArray(export, docs =>
        {
            foreach (var d in docs) d["SnapshotHash"] = "";
        });
        var fresh = new Rmm21Tests.Rig();
        var restored = fresh.Service.ImportJson(tampered);
        Assert.Equal(0, restored);
        Assert.Null(fresh.Service.GetDocument(Admin, Scope, doc.Id));
    }

    [Fact]
    public void F4_Import_BlankProtectorName_RefusedForCredentials()
    {
        var rig = new Rmm21Tests.Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Rmm21Tests.Secret1, users: new[] { Tech });
        var export = rig.Service.ExportJson();
        var tampered = TamperCredArray(export, creds =>
        {
            foreach (var c in creds) c["ProtectorName"] = "";
        });
        var fresh = new Rmm21Tests.Rig();
        fresh.Service.ImportJson(tampered);
        Assert.DoesNotContain(fresh.Service.ListCredentialsFor(Scope, Admin), m => m.Id == meta.Id);
    }

    [Fact]
    public void F4_LegitExport_StillRoundTrips()
    {
        var rig = new Rmm21Tests.Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ network", rig.NetworkFacts());
        var meta = rig.Cred("device", Dev1, "Site server", Rmm21Tests.Secret1, users: new[] { Tech });
        var fresh = new Rmm21Tests.Rig();
        var restored = fresh.Service.ImportJson(rig.Service.ExportJson());
        Assert.True(restored >= 2, $"expected docs+creds restored, got {restored}");
        Assert.NotNull(fresh.Service.GetDocument(Admin, Scope, doc.Id));
        Assert.Contains(fresh.Service.ListCredentialsFor(Scope, Admin), m => m.Id == meta.Id);
        Assert.True(fresh.Service.VerifyHistory(Scope, doc.Id));
    }

    private static string TamperDocArray(string exportJson, Action<List<JsonObject>> edit)
    {
        var root = JsonNode.Parse(exportJson)!.AsObject();
        var docs = root["Documents"]!.AsArray().Select(n => n!.AsObject()).ToList();
        edit(docs);
        return root.ToJsonString();
    }

    private static string TamperCredArray(string exportJson, Action<List<JsonObject>> edit)
    {
        var root = JsonNode.Parse(exportJson)!.AsObject();
        var creds = root["Credentials"]!.AsArray().Select(n => n!.AsObject()).ToList();
        edit(creds);
        return root.ToJsonString();
    }

    // ---------- F5: trail cap keeps lifecycle acts; trail persists ----------

    [Fact]
    public void F5_AuthFailureFlood_CannotEvictTheRevocation()
    {
        var (store, issue) = IssuedStore();
        var passId = issue.Pass.Id;
        // Flood matched-token auth failures (wrong vendor identity)
        // well past the 2048-entry cap.
        for (var i = 0; i < VendorPassLimits.MaxAuditEntriesPerPass + 200; i++)
            store.Authenticate(issue.BearerToken, "vendor-mallory", Dev1, null, T0.AddMinutes(1));
        var (ok, _, _) = store.Revoke(passId, "ops-lead", "incident", T0.AddMinutes(2));
        Assert.True(ok);
        var trail = store.AuditTrail(passId);
        Assert.Contains(trail, e => e.Kind == PassAuditKinds.Revoked);
        Assert.Contains(trail, e => e.Kind == PassAuditKinds.Issued);
        Assert.True(trail.Count <= VendorPassLimits.MaxAuditEntriesPerPass + 2,
            $"trail must stay bounded, got {trail.Count}");
    }

    [Fact]
    public void F5_Trail_SurvivesExportImport()
    {
        var (store, issue) = IssuedStore();
        store.Authenticate(issue.BearerToken, issue.Pass.Vendor.Id, Dev1, null, T0.AddMinutes(1));
        store.Revoke(issue.Pass.Id, "ops-lead", "done", T0.AddMinutes(2));
        var restored = new VendorPassStore();
        Assert.Equal(1, restored.ImportJson(store.ExportJson()));
        var trail = restored.AuditTrail(issue.Pass.Id);
        Assert.Contains(trail, e => e.Kind == PassAuditKinds.Issued);
        Assert.Contains(trail, e => e.Kind == PassAuditKinds.AuthSucceeded);
        Assert.Contains(trail, e => e.Kind == PassAuditKinds.Revoked);
    }

    // ---------- F6: sealed export + revocation consistency on import ----------

    [Fact]
    public void F6_SealedExport_TamperRestoresNothing_RevocationSurvivesIntoEmptyStore()
    {
        var protector = new DevOnlyPassThroughProtector();
        var (store, issue) = IssuedStore(protector);
        store.Revoke(issue.Pass.Id, "ops-lead", "compromised", T0.AddMinutes(1));
        var export = store.ExportJson();
        Assert.True(store.ExportsSealed);
        Assert.ThrowsAny<Exception>(() => JsonDocument.Parse(export)); // sealed, not plain JSON

        var restored = new VendorPassStore(protector);
        Assert.Equal(1, restored.ImportJson(export));
        var pass = restored.Get(issue.Pass.Id);
        Assert.NotNull(pass);
        Assert.True(pass!.Revoked, "a revoked pass must never resurrect as live on import");
        var (auth, _) = restored.Authenticate(issue.BearerToken, issue.Pass.Vendor.Id, Dev1, null, T0.AddMinutes(2));
        Assert.Null(auth);

        // Tamper with the sealed text: import restores nothing.
        var tampered = export[..(export.Length / 2)];
        var victim = new VendorPassStore(protector);
        Assert.Equal(0, victim.ImportJson(tampered));
        Assert.Empty(victim.List());
    }

    [Fact]
    public void F6_Import_InconsistentRevocationFields_Skipped()
    {
        var (store, issue) = IssuedStore();
        var export = store.ExportJson();
        // Forge: mark the pass revoked but strip WHO revoked it.
        var root = JsonNode.Parse(export)!.AsArray();
        var pass0 = root[0]!.AsObject();
        pass0["Revoked"] = true;
        pass0["RevokedBy"] = null;
        pass0["RevokedUtc"] = T0.AddMinutes(5).ToString("O");
        var restored = new VendorPassStore();
        Assert.Equal(0, restored.ImportJson(root.ToJsonString()));
        Assert.Empty(restored.List());
    }

    // ---------- F7: roster-backed escalation authority ----------

    private sealed class VendorRig
    {
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public VendorPassService Passes;
        public VendorRig(Func<string, string, bool>? authorizer)
        {
            Passes = new VendorPassService(Audit, Policy,
                id => StaticDeviceFacts.Of(id, Scope), null, null, () => T0,
                operatorAuthorizer: authorizer);
        }
        public VendorPassIssue IssueOk(string issuer = "ops-admin")
        {
            var (issue, reason) = Passes.IssuePass(issuer, Vendor(), Scope,
                new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
                TimeSpan.FromDays(7), null);
            Assert.True(issue is not null, reason);
            return issue!;
        }
    }

    [Fact]
    public void F7_NonAdminIssuer_Refused_WhenAuthorizerWired()
    {
        var rig = new VendorRig((scope, user) => user == "ops-admin");
        var (issue, reason) = rig.Passes.IssuePass("random-string", Vendor(), Scope,
            new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null);
        Assert.Null(issue);
        Assert.Contains("not a live human scope admin", reason);
        var ok = rig.IssueOk();
        Assert.NotNull(ok);
    }

    [Fact]
    public void F7_NonAdminRevoker_Refused_VendorSelfSurrender_Allowed()
    {
        var rig = new VendorRig((scope, user) => user == "ops-admin");
        var issue = rig.IssueOk();
        var (okForged, forgedReason, _, _) = rig.Passes.RevokePass(issue.Pass.Id, "random-string", "forged");
        Assert.False(okForged);
        Assert.Contains("not a live human scope admin", forgedReason);
        Assert.False(rig.Passes.Store.Get(issue.Pass.Id)!.Revoked);
        // The vendor surrendering their OWN pass needs no admin.
        var (okSelf, _, _, _) = rig.Passes.RevokePass(issue.Pass.Id, Vendor().Id, "we are done");
        Assert.True(okSelf);
        Assert.True(rig.Passes.Store.Get(issue.Pass.Id)!.Revoked);
    }

    [Fact]
    public void F7_NoAuthorizer_KeepsLegacyBehaviour()
    {
        var rig = new VendorRig(null);
        var issue = rig.IssueOk("any-named-operator");
        var (ok, _, _, _) = rig.Passes.RevokePass(issue.Pass.Id, "another-operator", "cleanup");
        Assert.True(ok);
    }

    // ---------- F8: live-human gate + audited refusals on destructive acts ----------

    [Fact]
    public void F8_SuspendedAdmin_CannotDeleteOrRegrant()
    {
        var rig = new Rmm21Tests.Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ network", rig.NetworkFacts());
        var meta = rig.Cred("device", Dev1, "Site server", Rmm21Tests.Secret1, users: new[] { Tech });
        // A second live admin, so suspending Admin is a legal act
        // (the roster refuses to suspend a scope's SOLE live admin).
        Assert.NotNull(rig.Roster.CreateUser("admin-2", Scope, "Admin Two", "human"));
        Assert.True(rig.Roster.AddCompanyAdmin(Scope, "admin-2"));
        Assert.True(rig.Roster.SetUserSuspended(Scope, Admin, true));
        Assert.False(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        Assert.False(rig.Service.DeleteCredential(Admin, Scope, meta.Id).Ok);
        Assert.False(rig.Service.UpdateCredentialGrants(Admin, Scope, meta.Id, new[] { Tech }, null).Ok);
        Assert.NotNull(rig.Service.GetDocument(Tech, Scope, doc.Id));
        Assert.Contains(rig.Service.ListCredentialsFor(Scope, Tech), m => m.Id == meta.Id);
    }

    [Fact]
    public void F8_AiAdmin_CannotDeleteOrRegrant()
    {
        var rig = new Rmm21Tests.Rig();
        // Company scope: the roster itself refuses to seat an AI
        // admin (D9) — asserted so the design fact is pinned.
        Assert.NotNull(rig.Roster.CreateUser("ai-admin", Scope, "AI Admin", "ai", pairedByUserId: Admin));
        Assert.False(rig.Roster.AddCompanyAdmin(Scope, "ai-admin"));
        // Personal scope: the one shape where an AI user coexists
        // with admin semantics (the human owner is admin by kind).
        // The AI actor must still be refused every destructive act.
        Assert.NotNull(rig.Roster.CreateScope("pers-1", "personal", "Personal"));
        Assert.NotNull(rig.Roster.CreateUser("owner-1", "pers-1", "Owner", "human"));
        Assert.NotNull(rig.Roster.CreateUser("ai-1", "pers-1", "Agent", "ai", pairedByUserId: "owner-1"));
        var svc = new SiteDocumentationService(new DevOnlyPassThroughProtector(), rig.Audit, rig.Roster,
            rig.Policy, id => StaticDeviceFacts.Of(id, "pers-1"), new Rmm21Tests.FakeReAuth(), () => rig.Now);
        var (dok, dreason, doc) = svc.CreateDocument("owner-1", "pers-1", "device", Dev1,
            DocTemplateKinds.SiteNotes, "Notes", new Dictionary<string, string> { ["site_name"] = "Home" }, "");
        Assert.True(dok, dreason);
        var (cok, creason, meta) = svc.CreateCredential("owner-1", "pers-1", "device", Dev1,
            "Site server", "svc-account", "server", Rmm21Tests.Secret1, new[] { "owner-1" }, null);
        Assert.True(cok, creason);
        Assert.False(svc.DeleteDocument("ai-1", doc!.Id).Ok);
        Assert.False(svc.DeleteCredential("ai-1", "pers-1", meta!.Id).Ok);
        Assert.False(svc.UpdateCredentialGrants("ai-1", "pers-1", meta.Id, new[] { "owner-1" }, null).Ok);
    }

    [Fact]
    public void F8_Refusals_AreAudited()
    {
        var rig = new Rmm21Tests.Rig();
        var before = rig.Audit.Entries.Count;
        Assert.False(rig.Service.DeleteDocument(Admin, "doc-does-not-exist").Ok);
        Assert.False(rig.Service.DeleteCredential(Admin, Scope, "cred-does-not-exist").Ok);
        var entries = rig.Audit.Entries.Skip(before).ToList();
        Assert.Contains(entries, e => e.Kind == "site_doc_refused");
        Assert.Contains(entries, e => e.Kind == "site_credential_refused");
    }

    // ---------- F9: session context honours per-target policy for group docs ----------

    [Fact]
    public void F9_SessionContext_GroupDocHiddenWhenPolicyDeniesTheGroup()
    {
        var rig = new Rmm21Tests.Rig();
        var groupDoc = rig.Doc(Tech, "group", GrpA, DocTemplateKinds.SiteNotes, "Site A notes", new Dictionary<string, string> { ["site_name"] = "Site A" });
        var deviceDoc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.SiteNotes, "Device notes", new Dictionary<string, string> { ["site_name"] = "Site A" });
        // Deny site-docs for the GROUP target only (device-level
        // policy document aimed at the group's facts).
        rig.Policy.AddDocument(new ManagementPolicyDocument("grp-off", PolicyLevels.Device, GrpA,
            new Dictionary<string, string> { [SiteDocumentationPolicyKeys.Enabled] = "false" }, 1));
        var (ok, _, ctx) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA });
        Assert.True(ok);
        Assert.NotNull(ctx);
        Assert.DoesNotContain(ctx!.Documents, d => d.Id == groupDoc.Id);
        Assert.Contains(ctx.Documents, d => d.Id == deviceDoc.Id);
    }

    // ---------- F10/F11: indexed auth + Changed outside the gate ----------

    [Fact]
    public void F10_Authenticate_ResolvesAmongManyPasses_AndDiesOnRevoke()
    {
        var store = new VendorPassStore();
        VendorPassIssue? last = null;
        for (var i = 0; i < 40; i++)
        {
            var (issue, reason) = store.Issue("ops-lead", Vendor($"vendor-{i}"), Scope,
                new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
                TimeSpan.FromDays(7), null, T0);
            Assert.True(issue is not null, reason);
            last = issue;
        }
        var (pass, _) = store.Authenticate(last!.BearerToken, "vendor-39", Dev1, null, T0.AddMinutes(1));
        Assert.Equal(last.Pass.Id, pass?.Id);
        store.Revoke(last.Pass.Id, "ops-lead", "done", T0.AddMinutes(2));
        var (after, _) = store.Authenticate(last.BearerToken, "vendor-39", Dev1, null, T0.AddMinutes(3));
        Assert.Null(after);
    }

    [Fact]
    public void F11_Changed_FiresOnlyOnRealChange_AndHandlerMayReenter()
    {
        var store = new VendorPassStore();
        var fires = 0;
        store.Changed += () =>
        {
            fires++;
            // Re-entrant read from inside the notification: the
            // pre-fix shape raised Changed under the store gate.
            _ = store.ExportJson();
            _ = store.List();
        };
        var (issue, _) = store.Issue("ops-lead", Vendor(), Scope,
            new[] { Dev1 }, Array.Empty<string>(), new[] { Scopes.Observe },
            TimeSpan.FromDays(7), null, T0);
        Assert.Equal(1, fires);
        // ExtendPass on an unknown id changes nothing (no trail
        // entry can land) → no event. On a REAL pass the refusal
        // itself is trailed (extension is always refused by design:
        // more time is a new pass) → exactly one more event.
        Assert.False(store.ExtendPass("pass-nope", TimeSpan.FromDays(1), "ops-lead", T0).Ok);
        Assert.Equal(1, fires);
        Assert.False(store.ExtendPass(issue!.Pass.Id, TimeSpan.FromDays(1), "ops-lead", T0).Ok);
        Assert.Equal(2, fires);
        Assert.Contains(store.AuditTrail(issue.Pass.Id), e => e.Kind == PassAuditKinds.ExtensionRefused);
    }

    // ---------- F12: slot pointer fallback is named, never silent ----------

    [Fact]
    public void F12_SlotPointer_FallbacksAreNamed()
    {
        var root = TestUtil.TempDir();
        var missing = SlotPointer.ReadDetailed(root);
        Assert.NotNull(missing.FellBack);
        Assert.Contains("missing", missing.FellBack);
        Assert.Equal(SlotId.A, missing.Pointer.Active);

        File.WriteAllText(SlotPointer.PointerPath(root), "{not json");
        var corrupt = SlotPointer.ReadDetailed(root);
        Assert.Contains("corrupt", corrupt.FellBack!);

        File.WriteAllText(SlotPointer.PointerPath(root),
            JsonSerializer.Serialize(new { Active = 7, Version = "9.9.9" }));
        var unknown = SlotPointer.ReadDetailed(root);
        Assert.Contains("unknown slot value 7", unknown.FellBack!);
        Assert.Equal(SlotId.A, unknown.Pointer.Active);

        File.WriteAllText(SlotPointer.PointerPath(root),
            JsonSerializer.Serialize(new { Active = 1, Version = "2.0.0" }));
        var valid = SlotPointer.ReadDetailed(root);
        Assert.Null(valid.FellBack);
        Assert.Equal(SlotId.B, valid.Pointer.Active);
        Assert.Equal("2.0.0", valid.Pointer.Version);
    }

}

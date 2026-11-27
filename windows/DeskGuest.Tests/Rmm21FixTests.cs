using System.Text.Json;
using System.Text.Json.Nodes;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.SiteDocs;

namespace DeskGuest.Tests;

// RMM-21 D38 FIX lane — regression tests for the 12 findings of
// packet 533661d7 (fresh cross-review, verdict FAIL). Every test
// names its finding. Amended pre-existing tests are disclosed in
// log-rmm21-fix.md; these are all new.
public class Rmm21FixTests
{
    private const string Scope = Rmm21TestsScope.Scope;
    private const string Scope2 = Rmm21TestsScope.Scope2;
    private const string Admin = Rmm21TestsScope.Admin;
    private const string Tech = Rmm21TestsScope.Tech;
    private const string Tech2 = Rmm21TestsScope.Tech2;
    private const string Outsider = Rmm21TestsScope.Outsider;
    private const string Dev1 = Rmm21TestsScope.Dev1;
    private const string Dev2 = Rmm21TestsScope.Dev2;
    private const string GrpA = Rmm21TestsScope.GrpA;
    private const string GrpB = Rmm21TestsScope.GrpB;
    private const string S1 = Rmm21Tests.Secret1;
    private const string S2 = Rmm21Tests.Secret2;

    private static Rmm21Tests.Rig Rig() => new();

    private static JsonObject ExportObj(Rmm21Tests.Rig rig) =>
        JsonNode.Parse(rig.Service.ExportJson())!.AsObject();

    // ---- F1: no crackable fingerprint of the secret anywhere ----

    [Fact]
    public void F1_NoSurfaceCarriesASha256OfTheSecret()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var hashOfSecret = EncryptionHash.Sha256Hex(S1);
        var surfaces = new List<string>
        {
            JsonSerializer.Serialize(meta),
            JsonSerializer.Serialize(rig.Service.ListCredentialsFor(Scope, Tech)),
            JsonSerializer.Serialize(rig.Service.GetCredentialMetadata(Scope, meta.Id, Tech)),
            JsonSerializer.Serialize(rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA }).Context),
            rig.Service.ExportJson(),
        };
        Assert.True(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
        Assert.True(rig.Service.RotateCredentialSecret(Admin, Scope, meta.Id, S2, "good-proof").Ok);
        Assert.True(rig.Service.DeleteCredential(Admin, Scope, meta.Id).Ok);
        surfaces.Add(JsonSerializer.Serialize(rig.Audit.Entries));
        surfaces.Add(rig.Audit.ExportEntriesJson());
        foreach (var s in surfaces)
        {
            Assert.DoesNotContain(hashOfSecret, s);
            Assert.DoesNotContain(EncryptionHash.Sha256Hex(S2), s);
        }
        // The metadata type has no fingerprint-shaped member at all.
        Assert.DoesNotContain(typeof(SiteCredentialMetadata).GetProperties(),
            p => p.Name.Contains("Fingerprint", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void F1_GuessingTheSecretFromAListingIsImpossible_NoOracleRemains()
    {
        // The pre-fix attack: read the fingerprint from a listing,
        // hash candidate passwords offline until one matches. With
        // no hash of the secret on any surface, the listing gives a
        // guesser nothing to verify against — asserted structurally
        // in F1 above; here the SAME secret under two labels yields
        // two metadata records with no common secret-derived value.
        var rig = Rig();
        var a = rig.Cred("device", Dev1, "Label A", S1, users: new[] { Tech });
        var b = rig.Cred("device", Dev2, "Label B", S1, users: new[] { Tech });
        Assert.NotEqual(a.Id, b.Id);
        var ja = JsonSerializer.Serialize(a);
        var jb = JsonSerializer.Serialize(b);
        Assert.DoesNotContain(EncryptionHash.Sha256Hex(S1), ja + jb);
    }

    // ---- F2: credential id is not a password-confirmation oracle ----

    [Fact]
    public void F2_SameSecretSameLabel_CreatesTwiceWithDistinctIds_NoCollisionOracle()
    {
        var rig = Rig();
        var first = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        // Pre-fix this refused with "already exists" whenever the
        // guess (scope+target+label+secret) was right — a free
        // password-confirmation oracle for any live user.
        var (ok, reason, second) = rig.Service.CreateCredential(Admin, Scope, "device", Dev1,
            "Site server", "svc-account", "server", S1, new[] { Tech }, null);
        Assert.True(ok, reason);
        Assert.NotEqual(first.Id, second!.Id);
        Assert.Equal(S1, rig.Service.RevealCredential(Tech, Scope, first.Id, "good-proof").Secret);
        Assert.Equal(S1, rig.Service.RevealCredential(Tech, Scope, second.Id, "good-proof").Secret);
    }

    // ---- F3: import re-validates scope, target and grants ----

    [Fact]
    public void F3_Import_GrantToNonexistentUser_DropsCredential_AndAuditsImport()
    {
        var rig = Rig();
        rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var export = ExportObj(rig);
        export["Credentials"]![0]!["GrantedUserIds"] = new JsonArray("mallory-1");
        var rig2 = Rig();
        Assert.Equal(0, rig2.Service.ImportJson(export.ToJsonString()));
        Assert.Empty(rig2.Service.ListCredentialsFor(Scope, Admin));
        Assert.Contains(rig2.Audit.Entries, e => e.Kind == "site_store_imported" && e.Detail.Contains("dropped=1"));
    }

    [Fact]
    public void F3_Import_CredentialMovedToAnotherScope_DropsCredential()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var export = ExportObj(rig);
        export["Credentials"]![0]!["ScopeId"] = Scope2; // Tech is not a user of Scope2
        var rig2 = Rig();
        Assert.Equal(0, rig2.Service.ImportJson(export.ToJsonString()));
        Assert.Null(rig2.Service.GetCredentialMetadata(Scope2, meta.Id, Admin));
        Assert.Empty(rig2.Service.ListCredentialsFor(Scope2, Admin));
    }

    // ---- F4: chain binds identity; snapshot hash; audit anchor ----

    [Fact]
    public void F4_Import_UndeletedTombstone_DropsDocument()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        Assert.True(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        var export = ExportObj(rig);
        export["Documents"]![0]!["Deleted"] = false; // un-delete attack
        var rig2 = Rig();
        rig2.Service.ImportJson(export.ToJsonString());
        Assert.Empty(rig2.Service.GetHistory(Admin, Scope, doc.Id));
    }

    [Fact]
    public void F4_Import_RehomedOrRetitledDocument_DropsDocument()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());

        var rehomed = ExportObj(rig);
        rehomed["Documents"]![0]!["ScopeId"] = Scope2;
        var rig2 = Rig();
        rig2.Service.ImportJson(rehomed.ToJsonString());
        Assert.Empty(rig2.Service.GetHistory(Admin, Scope2, doc.Id));

        var retitled = ExportObj(rig);
        retitled["Documents"]![0]!["Title"] = "Forged title";
        var rig3 = Rig();
        rig3.Service.ImportJson(retitled.ToJsonString());
        Assert.Empty(rig3.Service.GetHistory(Admin, Scope, doc.Id));
    }

    [Fact]
    public void F4_AuditAnchorsChainHead_AndVerifyHistoryCoversSnapshot()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var edited = rig.NetworkFacts(); edited["gateway"] = "10.4.0.254";
        Assert.True(rig.Service.EditDocument(Tech, doc.Id, edited, "").Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "site_doc_created" && e.Detail.Contains("hash="));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "site_doc_edited" && e.Detail.Contains("hash="));
        Assert.True(rig.Service.VerifyHistory(Scope, doc.Id));
        Assert.True(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        Assert.True(rig.Service.VerifyHistory(Scope, doc.Id)); // tombstone is inside the snapshot hash
    }

    // ---- F5: concurrent mutations cannot corrupt state ----

    [Fact]
    public void F5_ConcurrentEdits_ProduceContiguousUniqueVersions_VerifiedChain()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        const int writers = 8;
        var results = new (bool Ok, string Reason, SiteDocument? Document)[writers];
        Parallel.For(0, writers, i =>
        {
            var fields = rig.NetworkFacts();
            fields["gateway"] = $"10.4.0.{100 + i}";
            results[i] = rig.Service.EditDocument(Tech, doc.Id, fields, $"edit {i}");
        });
        var successes = results.Where(r => r.Ok).ToList();
        Assert.True(successes.Count >= 2, "at least two concurrent edits should land");
        var versions = successes.Select(r => r.Document!.CurrentVersion).ToList();
        Assert.Equal(versions.Count, versions.Distinct().Count()); // no duplicate version numbers
        var history = rig.Service.GetHistory(Admin, Scope, doc.Id);
        Assert.Equal(successes.Count + 1, history.Count);
        Assert.Equal(Enumerable.Range(1, history.Count), history.Select(v => v.Version));
        Assert.True(rig.Service.VerifyHistory(Scope, doc.Id)); // and the doc still imports/verifies
    }

    [Fact]
    public void F5_RotateRacingGrantUpdate_NeitherIsLost()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var rotate = Task.Run(() => rig.Service.RotateCredentialSecret(Admin, Scope, meta.Id, S2, "good-proof"));
        var grants = Task.Run(() => rig.Service.UpdateCredentialGrants(Admin, Scope, meta.Id, new[] { Tech, Outsider }, null));
        Assert.True(rotate.Result.Ok, rotate.Result.Reason);
        Assert.True(grants.Result.Ok, grants.Result.Reason);
        // The rotation survived the grant update (no stale write-back)…
        Assert.Equal(S2, rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Secret);
        // …and the grant update survived the rotation.
        Assert.Equal(S2, rig.Service.RevealCredential(Outsider, Scope, meta.Id, "good-proof").Secret);
    }

    // ---- F6: policy gate fails closed and covers the claimed paths ----

    [Fact]
    public void F6_UnresolvableFacts_PolicyGateFailsClosed()
    {
        var rig = Rig();
        var noFacts = new SiteDocumentationService(new DevOnlyPassThroughProtector(), rig.Audit, rig.Roster,
            rig.Policy, _ => null, new Rmm21Tests.FakeReAuth(), () => rig.Now);
        Assert.False(noFacts.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts(), "").Ok);
        Assert.False(noFacts.GetSessionContext(Tech, Scope, Dev1, null).Ok);
        var (ok, reason, _) = noFacts.CreateCredential(Admin, Scope, "device", Dev1,
            "x", "u", "c", S1, new[] { Tech }, null);
        Assert.False(ok, reason);
    }

    [Fact]
    public void F6_GroupCredentialReveal_IsPolicyGated()
    {
        var rig = Rig();
        var meta = rig.Cred("group", GrpA, "Group cred", S1, users: new[] { Tech });
        Assert.True(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
        var verdict = rig.Policy.AddDocument(new ManagementPolicyDocument("org-off", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [SiteDocumentationPolicyKeys.Enabled] = "false" }, 1));
        Assert.True(verdict.Allowed, verdict.Reason);
        // Pre-fix: group reveals had NO policy check at all.
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void F6_DocumentReads_ArePolicyGated()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var verdict = rig.Policy.AddDocument(new ManagementPolicyDocument("org-off", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [SiteDocumentationPolicyKeys.Enabled] = "false" }, 1));
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Null(rig.Service.GetDocument(Tech, Scope, doc.Id));
        Assert.Empty(rig.Service.ListDocuments(Admin, Scope));
        Assert.Empty(rig.Service.GetHistory(Admin, Scope, doc.Id));
        Assert.False(rig.Service.EditDocument(Tech, doc.Id, rig.NetworkFacts(), "x").Ok);
    }

    // ---- F7: session membership + document-read authorization ----

    [Fact]
    public void F7_Session_NamingAnotherDevicesGroup_YieldsNothingOfThatGroup()
    {
        var rig = Rig();
        rig.Doc(Tech, "group", GrpA, DocTemplateKinds.SiteNotes, "Site A",
            new Dictionary<string, string> { ["site_name"] = "Site A" });
        var credGrpA = rig.Cred("group", GrpA, "A group cred", S1, users: new[] { Tech });
        // EnrolledDev1 IS enrolled in GrpA: its session sees the group records.
        var (_, _, ctxMember) = rig.Service.GetSessionContext(Tech, Scope, rig.EnrolledDev1, new[] { GrpA });
        Assert.Contains(ctxMember!.Credentials, c => c.Id == credGrpA.Id);
        // EnrolledDev2 is enrolled in GrpB only: naming GrpA pulls nothing.
        var (_, _, ctxOther) = rig.Service.GetSessionContext(Tech, Scope, rig.EnrolledDev2, new[] { GrpA });
        Assert.Empty(ctxOther!.Documents);
        Assert.Empty(ctxOther.Credentials);
    }

    [Fact]
    public void F7_DocumentReads_RequireALiveActor()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        Assert.Null(rig.Service.GetDocument("ghost", Scope, doc.Id));
        Assert.Empty(rig.Service.ListDocuments("ghost", Scope));
        Assert.Empty(rig.Service.GetHistory("ghost", Scope, doc.Id));
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.Null(rig.Service.GetDocument(Tech, Scope, doc.Id));
        Assert.Empty(rig.Service.ListDocuments(Tech, Scope));
    }

    // ---- F8: read grant ≠ rotation rights ----

    [Fact]
    public void F8_ReadGranteeCannotRotate_CreatorCanRotate()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        Assert.False(rig.Service.RotateCredentialSecret(Tech, Scope, meta.Id, S2, "good-proof").Ok);
        Assert.Equal(S1, rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Secret); // unchanged

        // The creator owns rotation for their own credential.
        var own = rig.Cred("device", Dev1, "Tech's cred", S1, users: new[] { Tech2 }, actor: Tech);
        Assert.True(rig.Service.RotateCredentialSecret(Tech, Scope, own.Id, S2, "good-proof").Ok);
        Assert.Equal(S2, rig.Service.RevealCredential(Tech2, Scope, own.Id, "good-proof").Secret);
    }

    // ---- F9: dead actors list nothing; AI authors nothing ----

    [Fact]
    public void F9_SuspendedAndAiActors_ListNoCredentialMetadata()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        rig.Roster.CreateUser("ai-1", Scope, "Agent", "ai", pairedByUserId: Admin);
        Assert.True(rig.Service.UpdateCredentialGrants(Admin, Scope, meta.Id, new[] { Tech, "ai-1" }, null).Ok);
        // An AI user holding a DIRECT grant lists nothing (pre-fix:
        // no LiveUser check on the listing paths at all).
        Assert.Empty(rig.Service.ListCredentialsFor(Scope, "ai-1"));
        Assert.Null(rig.Service.GetCredentialMetadata(Scope, meta.Id, "ai-1"));
        // A suspended user with a leftover grant lists nothing.
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.Empty(rig.Service.ListCredentialsFor(Scope, Tech));
        Assert.Null(rig.Service.GetCredentialMetadata(Scope, meta.Id, Tech));
        // A non-member lists nothing.
        Assert.Empty(rig.Service.ListCredentialsFor(Scope, "ghost"));
    }

    [Fact]
    public void F9_AiUser_CannotCreateOrEditDocuments()
    {
        var rig = Rig();
        rig.Roster.CreateUser("ai-1", Scope, "Agent", "ai", pairedByUserId: Admin);
        Assert.False(rig.Service.CreateDocument("ai-1", Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts(), "").Ok);
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var edited = rig.NetworkFacts(); edited["gateway"] = "10.4.0.254";
        Assert.False(rig.Service.EditDocument("ai-1", doc.Id, edited, "").Ok);
    }

    // ---- F10: export names its protector honestly ----

    [Fact]
    public void F10_ExportCarriesProtectorProvenance_ImportStampsIt()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var export = ExportObj(rig);
        var cred = export["Credentials"]![0]!;
        Assert.Equal(meta.ProtectorName, cred["ProtectorName"]!.GetValue<string>());
        Assert.False(cred["IsRealProtection"]!.GetValue<bool>()); // dev protector, honestly flagged
        var rig2 = Rig();
        Assert.Equal(1, rig2.Service.ImportJson(export.ToJsonString()));
        var restored = rig2.Service.GetCredentialMetadata(Scope, meta.Id, Tech);
        Assert.NotNull(restored);
        Assert.Equal(meta.ProtectorName, restored!.ProtectorName);
        Assert.False(restored.IsRealProtection);
    }

    [Fact]
    public void F10_Import_ProtectorMismatch_DropsCredential()
    {
        var rig = Rig();
        rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var export = ExportObj(rig);
        export["Credentials"]![0]!["ProtectorName"] = "some-other-protector";
        var rig2 = Rig();
        Assert.Equal(0, rig2.Service.ImportJson(export.ToJsonString()));
        Assert.Empty(rig2.Service.ListCredentialsFor(Scope, Admin));
    }

    // ---- F11: history growth is capped by name ----

    [Fact]
    public void F11_HistoryCap_RefusesByName_ChainStillVerifies()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        for (var v = 2; v <= SiteDocumentationService.MaxHistoryVersions; v++)
        {
            var fields = rig.NetworkFacts();
            fields["gateway"] = $"10.4.{v % 250}.1";
            var (ok, reason, _) = rig.Service.EditDocument(Tech, doc.Id, fields, "");
            Assert.True(ok, $"edit to v{v}: {reason}");
        }
        var over = rig.NetworkFacts(); over["gateway"] = "10.9.9.9";
        var refused = rig.Service.EditDocument(Tech, doc.Id, over, "");
        Assert.False(refused.Ok);
        Assert.Contains("maximum", refused.Reason);
        Assert.Equal(SiteDocumentationService.MaxHistoryVersions,
            rig.Service.GetHistory(Admin, Scope, doc.Id).Count);
        Assert.True(rig.Service.VerifyHistory(Scope, doc.Id));
    }
}

using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.SiteDocs;

namespace Acp.Tests;

// RMM-21 DESTRUCTION — attack the site-documentation store and the
// credential vault: reveal without re-auth, reveal by an
// out-of-scope user, secret leakage through every surface, history
// rewriting, cross-device bleed, template injection, bulk export
// through the in-session path, vault substitution, dead actors.
public class Rmm21DestructionTests
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

    [Fact]
    public void Reveal_AttackBattery_NoProofFormReveals()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        foreach (var proof in new string?[] { null, "", " ", "good-proof ", "GOOD-PROOF", "good-proo", "good-proof\0" })
            Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, proof).Ok, $"proof '{proof}' revealed");
        // Every refusal was audited; the chain still verifies.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "site_credential_reveal_refused");
        Assert.True(rig.Audit.Verify().Ok);
        // And the honest path still works afterwards (no lockout poisoning of the vault itself).
        Assert.True(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void SecretLeakageSweep_NoSurfaceCarriesTheSecret()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var surfaces = new List<string>();
        surfaces.Add(JsonSerializer.Serialize(rig.Service.ListCredentialsFor(Scope, Tech)));
        surfaces.Add(JsonSerializer.Serialize(rig.Service.ListCredentialsFor(Scope, Admin)));
        surfaces.Add(JsonSerializer.Serialize(rig.Service.GetCredentialMetadata(Scope, meta.Id, Tech)));
        var (_, ctxReason, ctx) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA });
        surfaces.Add(ctxReason);
        surfaces.Add(JsonSerializer.Serialize(ctx));
        surfaces.Add(rig.Service.RevealCredential(Tech, Scope, meta.Id, "wrong").Reason);
        surfaces.Add(rig.Service.RevealCredential(Outsider, Scope, meta.Id, "good-proof").Reason);
        surfaces.Add(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Reason);
        surfaces.Add(rig.Service.RotateCredentialSecret(Tech, Scope, meta.Id, S2, "good-proof").Reason);
        surfaces.Add(JsonSerializer.Serialize(rig.Audit.Entries));
        surfaces.Add(rig.Audit.ExportEntriesJson());
        surfaces.Add(rig.Service.ExportJson()); // protected form only — plaintext must not appear
        surfaces.Add(JsonSerializer.Serialize(rig.Service.ListDocuments(Admin, Scope)));
        foreach (var s in surfaces)
        {
            Assert.DoesNotContain(S1, s);
            Assert.DoesNotContain(S2, s);
        }
        // Even a 10-char slice of either secret appears nowhere in the audit.
        var auditJson = JsonSerializer.Serialize(rig.Audit.Entries);
        Assert.DoesNotContain(S1[..10], auditJson);
        Assert.DoesNotContain(S2[..10], auditJson);
    }

    [Fact]
    public void HistoryRewrite_TamperedImport_DropsTheDocument()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var edited = rig.NetworkFacts(); edited["gateway"] = "10.4.0.254";
        Assert.True(rig.Service.EditDocument(Tech, doc.Id, edited, "").Ok);
        var json = rig.Service.ExportJson();

        // Attack 1: rewrite v1's gateway in the exported history.
        var tampered = json.Replace("10.4.0.1\"", "9.9.9.9\"");
        Assert.NotEqual(json, tampered);
        var rig2 = Rig();
        rig2.Service.ImportJson(tampered);
        Assert.Null(rig2.Service.GetDocument(Tech, Scope, doc.Id));
        Assert.Empty(rig2.Service.GetHistory(Admin, Scope, doc.Id));

        // Attack 2: renumber a version (gap in the chain).
        var renumbered = json.Replace("\"Version\":2", "\"Version\":3");
        if (renumbered == json) renumbered = json.Replace("\"version\":2", "\"version\":3");
        var rig3 = Rig();
        rig3.Service.ImportJson(renumbered);
        Assert.Empty(rig3.Service.GetHistory(Admin, Scope, doc.Id));
    }

    [Fact]
    public void HistoryRewrite_NoApiMutatesAnExistingVersion()
    {
        var rig = Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts(), "original notes");
        var before = JsonSerializer.Serialize(rig.Service.GetHistory(Admin, Scope, doc.Id));
        var edited = rig.NetworkFacts(); edited["subnet"] = "10.9.0.0/24";
        Assert.True(rig.Service.EditDocument(Tech, doc.Id, edited, "changed").Ok);
        Assert.True(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        var history = rig.Service.GetHistory(Admin, Scope, doc.Id);
        Assert.Equal(2, history.Count);
        // Version 1 is byte-identical to what it was before the edit + delete.
        Assert.Equal(before, JsonSerializer.Serialize(new[] { history[0] }));
    }

    [Fact]
    public void CrossDeviceBleed_DeviceBContextContainsNothingOfDeviceA()
    {
        var rig = Rig();
        rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "A net", rig.NetworkFacts());
        rig.Doc(Tech, "group", GrpA, DocTemplateKinds.SiteNotes, "A site",
            new Dictionary<string, string> { ["site_name"] = "A" });
        var credA = rig.Cred("device", Dev1, "A cred", S1, users: new[] { Tech });
        var credGrpA = rig.Cred("group", GrpA, "A group cred", S2, users: new[] { Tech });

        // Session on Dev2, claiming NO groups:
        var (_, _, ctxB) = rig.Service.GetSessionContext(Tech, Scope, Dev2, null);
        Assert.Empty(ctxB!.Documents);
        Assert.Empty(ctxB.Credentials);
        // Session on Dev2 claiming Dev1's group — D38 F7 (amended):
        // naming a group is no longer enough. Membership is
        // enrollment-derived and Dev2 is enrolled in GrpB, not GrpA,
        // so GrpA's records — documents AND credentials — bleed
        // NOTHING into Dev2's session. (The pre-fix assertion here
        // expected the group credential to surface; the D38 review
        // correctly called that the bleed itself.)
        var (_, _, ctxB2) = rig.Service.GetSessionContext(Tech, Scope, Dev2, new[] { GrpA });
        Assert.DoesNotContain(ctxB2!.Documents, d => d.TargetKind == "device");
        Assert.DoesNotContain(ctxB2.Credentials, c => c.Id == credA.Id);
        Assert.DoesNotContain(ctxB2.Credentials, c => c.Id == credGrpA.Id);
        Assert.Empty(ctxB2.Documents);
        // A group id from another scope names nothing here:
        rig.Roster.CreateDeviceGroup("grp-foreign", Scope2, "Foreign");
        rig.Doc(Tech, "device", Dev1, DocTemplateKinds.SiteNotes, "x",
            new Dictionary<string, string> { ["site_name"] = "y" });
        var (_, _, ctxForeign) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { "grp-foreign" });
        Assert.DoesNotContain(ctxForeign!.Documents, d => d.TargetId == "grp-foreign");
    }

    [Fact]
    public void TemplateInjection_OversizeControlCharsAndFieldNameAttacksRefused()
    {
        var rig = Rig();
        var oversize = rig.NetworkFacts(); oversize["subnet"] = new string('9', 5000);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "x", oversize, "").Ok);
        var ctrl = rig.NetworkFacts(); ctrl["gateway"] = "10.0.0.1\0evil";
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "x", ctrl, "").Ok);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "title\u0007bell", rig.NetworkFacts(), "").Ok);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "x", rig.NetworkFacts(), "notes\u0001soh").Ok);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, new string('t', 201), rig.NetworkFacts(), "").Ok);
        // Nothing entered the store through any of those doors.
        Assert.Empty(rig.Service.ListDocuments(Admin, Scope));
    }

    [Fact]
    public void BulkExport_InSessionPathNeverYieldsSecrets_RepeatedQueriesStable()
    {
        var rig = Rig();
        rig.Cred("device", Dev1, "c1", S1, users: new[] { Tech });
        rig.Cred("device", Dev1, "c2", S2, users: new[] { Tech });
        for (var i = 0; i < 5; i++)
        {
            var (ok, _, ctx) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA, GrpB });
            Assert.True(ok);
            Assert.Equal(2, ctx!.Credentials.Count);
            var json = JsonSerializer.Serialize(ctx);
            Assert.DoesNotContain(S1, json);
            Assert.DoesNotContain(S2, json);
            // The metadata DTO type itself has no member that could
            // carry a secret — and (D38 F1) no fingerprint member
            // either: the exception this assertion used to carve
            // out for "SecretFingerprint" is gone.
            Assert.DoesNotContain(typeof(SiteCredentialMetadata).GetProperties(),
                p => p.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
                     p.Name.Contains("Fingerprint", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void VaultSubstitution_TamperedProtectedMaterial_NeverImportedNeverRevealed()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        var json = rig.Service.ExportJson();
        // Swap the protected payload for the protected form of a DIFFERENT secret:
        // the fingerprint binding must refuse it at import.
        var otherProtected = new Acp.Shared.Security.DevOnlyPassThroughProtector().Protect(S2);
        using var doc = JsonDocument.Parse(json);
        var protectedValue = doc.RootElement.GetProperty("Credentials")[0].GetProperty("ProtectedSecret").GetString()!;
        var tampered = json.Replace(protectedValue, otherProtected);
        Assert.NotEqual(json, tampered);
        var rig2 = Rig();
        Assert.Equal(0, rig2.Service.ImportJson(tampered));
        Assert.Empty(rig2.Service.ListCredentialsFor(Scope, Admin));
        Assert.False(rig2.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void DeadActors_SuspendedUserAndAiUser_RevealNothing()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
        Assert.False(rig.Service.GetSessionContext(Tech, Scope, Dev1, null).Ok);
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, false));

        // An AI user, even directly granted, reveals nothing (D9: a factor
        // is a human's possession proof; credential reveal is human-only).
        rig.Roster.CreateUser("ai-1", Scope, "Agent", "ai", pairedByUserId: Admin);
        Assert.True(rig.Service.UpdateCredentialGrants(Admin, Scope, meta.Id, new[] { "ai-1" }, null).Ok);
        Assert.False(rig.Service.RevealCredential("ai-1", Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void GrantEscalation_NonAdminCannotWidenGrantsOrDelete()
    {
        var rig = Rig();
        var meta = rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        // Tech (grantee) tries to grant Outsider, delete, or rotate to a known value:
        Assert.False(rig.Service.UpdateCredentialGrants(Tech, Scope, meta.Id, new[] { Outsider }, null).Ok);
        Assert.False(rig.Service.DeleteCredential(Tech, Scope, meta.Id).Ok);
        Assert.Empty(rig.Service.ListCredentialsFor(Scope, Outsider));
        // Outsider cannot rotate what they cannot see:
        Assert.False(rig.Service.RotateCredentialSecret(Outsider, Scope, meta.Id, S2, "good-proof").Ok);
        var (ok, _, secret) = rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof");
        Assert.True(ok);
        Assert.Equal(S1, secret); // unchanged by every attack above
    }

    [Fact]
    public void SessionContext_DisabledPolicy_BleedsNothingAndAuditsRefusal()
    {
        var rig = Rig();
        rig.Cred("device", Dev1, "Site server", S1, users: new[] { Tech });
        rig.Policy.AddDocument(new Acp.Shared.ManagementPolicy.ManagementPolicyDocument(
            "org-off", Acp.Shared.ManagementPolicy.PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [SiteDocumentationPolicyKeys.Enabled] = "false" }, 1));
        var (ok, _, ctx) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA });
        Assert.False(ok);
        Assert.Null(ctx);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "site_session_context_refused");
        // Reveal of a device credential is policy-gated too:
        var meta = rig.Service.ListCredentialsFor(Scope, Admin).Single();
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void Import_GarbageAndHostileJson_NeverFatal_NeverPartial()
    {
        var rig = Rig();
        Assert.Equal(0, rig.Service.ImportJson("not json"));
        Assert.Equal(0, rig.Service.ImportJson("{}"));
        Assert.Equal(0, rig.Service.ImportJson("{\"Documents\":[{\"Id\":\"doc-x\"}],\"Credentials\":[]}"));
        Assert.Empty(rig.Service.ListDocuments(Admin, Scope));
        Assert.True(rig.Audit.Verify().Ok);
    }
}

/// <summary>Shared constants for the RMM-21 destruction lane (kept
/// in one place so the two test classes cannot drift).</summary>
public static class Rmm21TestsScope
{
    public const string Scope = "co-1";
    public const string Scope2 = "co-2";
    public const string Admin = "admin-1";
    public const string Tech = "tech-1";
    public const string Tech2 = "tech-2";
    public const string Outsider = "outsider-1";
    public const string Dev1 = "dev-1";
    public const string Dev2 = "dev-2";
    public const string GrpA = "grp-a";
    public const string GrpB = "grp-b";
}

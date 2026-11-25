using System.Text.Json;
using Acp.Shared.Encryption;
using Acp.Shared.Enrollment;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.SiteDocs;

namespace Acp.Tests;

// RMM-21 — Site documentation + credential vault, surfaced
// in-session. Structured templated docs (devices + groups) with
// versioned history; an RBAC credential vault under the existing
// secret-protection machinery (re-auth on reveal, audit on every
// reveal, metadata-only listings); the in-session query contract
// returning docs + credential METADATA for the session's device.
// All secrets below are fake test strings.
public class Rmm21Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    // D38 F12: constants come from the ONE shared home
    // (Rmm21TestsScope, in Rmm21DestructionTests.cs) — this class
    // no longer keeps a driftable private copy.
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
    public const string Secret1 = "FAKE-site-secret-alpha-123";
    public const string Secret2 = "FAKE-site-secret-bravo-456";

    public sealed class FakeReAuth : IReAuthGate
    {
        public bool Verify(string scopeId, string userId, string proof, DateTimeOffset now) =>
            proof == "good-proof";
    }

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public EnrollmentService Enrollments = new();
        public RosterService Roster;
        public ManagementPolicyEngine Policy = new();
        public SiteDocumentationService Service;
        public SecondFactorService? SecondFactor;

        public Rig(bool reAuth = true, bool withSecondFactor = false)
        {
            Roster = new RosterService(Enrollments);
            Roster.CreateScope(Scope, "company", "Acme");
            Roster.CreateScope(Scope2, "company", "Other Co");
            Roster.CreateUser(Admin, Scope, "Admin One", "human");
            Roster.CreateUser(Tech, Scope, "Tech One", "human");
            Roster.CreateUser(Tech2, Scope, "Tech Two", "human");
            Roster.CreateUser(Outsider, Scope, "Outsider", "human");
            Roster.AddCompanyAdmin(Scope, Admin);
            Roster.CreateUserGroup("techs", Scope, "Technicians", new[] { Tech });
            Roster.CreateUserGroup("leads", Scope, "Leads", new[] { Tech2 });
            Roster.CreateDeviceGroup(GrpA, Scope, "Site A devices");
            Roster.CreateDeviceGroup(GrpB, Scope, "Site B devices");
            // D38 F7 plumbing: group membership is enrollment-
            // derived, so the rig enrolls two devices into GrpA /
            // GrpB — session group surfacing is now membership-
            // checked by the service itself. An enrolled device id
            // is its key fingerprint (EnrollmentService refuses any
            // other id), so the enrolled ids are NOT the Dev1/Dev2
            // label constants: they are exposed here, from fixed
            // seeds so every rig agrees on them.
            EnrolledDev1 = Enroll(0x21, GrpA, "Site A devices");
            EnrolledDev2 = Enroll(0x22, GrpB, "Site B devices");
            IReAuthGate? gate = null;
            if (withSecondFactor)
            {
                SecondFactor = new SecondFactorService(Roster, new DevOnlyPassThroughProtector());
                gate = new TotpReAuthGate(SecondFactor);
            }
            else if (reAuth) gate = new FakeReAuth();
            Service = new SiteDocumentationService(new DevOnlyPassThroughProtector(), Audit, Roster,
                Policy, id => StaticDeviceFacts.Of(id, Scope), gate, () => Now);
        }

        public readonly string EnrolledDev1 = "";
        public readonly string EnrolledDev2 = "";

        private string Enroll(byte seedByte, string groupId, string groupName)
        {
            var seed = new byte[32];
            Array.Fill(seed, seedByte);
            var identity = new DeviceIdentity(new DevOnlyPassThroughProtector(), seed);
            var code = Enrollments.CreateEnrollmentCode("company", groupId, groupName);
            var enrolled = Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, groupName));
            Assert.NotNull(enrolled);
            return enrolled!.DeviceId;
        }

        public SiteDocument Doc(string actor, string targetKind, string targetId, string template,
            string title, Dictionary<string, string> fields, string notes = "")
        {
            var (ok, reason, doc) = Service.CreateDocument(actor, Scope, targetKind, targetId, template, title, fields, notes);
            Assert.True(ok, reason);
            return doc!;
        }

        public SiteCredentialMetadata Cred(string targetKind, string targetId, string label, string secret,
            string[]? users = null, string[]? groups = null, string actor = Admin)
        {
            var (ok, reason, meta) = Service.CreateCredential(actor, Scope, targetKind, targetId,
                label, "svc-account", "server", secret, users, groups);
            Assert.True(ok, reason);
            return meta!;
        }

        public Dictionary<string, string> NetworkFacts() => new()
        {
            ["subnet"] = "10.4.0.0/24", ["gateway"] = "10.4.0.1",
            ["dns_servers"] = "10.4.0.5, 10.4.0.6", ["vlans"] = "10=office, 20=bas",
        };
    }

    // ---- (a) templated documentation -------------------------------------------

    [Fact]
    public void NetworkFactsDoc_TypedFieldsRoundTrip()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ network", rig.NetworkFacts(), "verified on site");
        Assert.Equal(1, doc.CurrentVersion);
        Assert.Equal("10.4.0.0/24", doc.Fields["subnet"]);
        var read = rig.Service.GetDocument(Tech, Scope, doc.Id);
        Assert.NotNull(read);
        Assert.Equal("10.4.0.1", read!.Fields["gateway"]);
        Assert.Equal("verified on site", read.Notes);
    }

    [Fact]
    public void VendorContactDoc_RequiresNameAndCompany()
    {
        var rig = new Rig();
        var (ok, reason, _) = rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.VendorContact, "BAS vendor", new Dictionary<string, string> { ["name"] = "Sam" }, "");
        Assert.False(ok);
        Assert.Contains("company", reason);
    }

    [Fact]
    public void CreateDoc_UnknownFieldRefused_UnknownTemplateRefused_MissingRequiredRefused()
    {
        var rig = new Rig();
        var badField = rig.NetworkFacts(); badField["shoe_size"] = "11";
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "x", badField, "").Ok);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            "free_for_all", "x", rig.NetworkFacts(), "").Ok);
        var missing = rig.NetworkFacts(); missing.Remove("subnet");
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "device", Dev1,
            DocTemplateKinds.NetworkFacts, "x", missing, "").Ok);
        Assert.Empty(rig.Service.ListDocuments(Admin, Scope));
    }

    [Fact]
    public void GroupDocument_AttachesToRosterGroup_UnknownGroupRefused()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "group", GrpA, DocTemplateKinds.SiteNotes, "Site A notes",
            new Dictionary<string, string> { ["site_name"] = "Site A", ["address"] = "1 Main St" });
        Assert.Equal(GrpA, doc.TargetId);
        Assert.False(rig.Service.CreateDocument(Tech, Scope, "group", "grp-nope",
            DocTemplateKinds.SiteNotes, "x", new Dictionary<string, string> { ["site_name"] = "X" }, "").Ok);
    }

    [Fact]
    public void EditDocument_AppendsVersion_PreviousVersionIntactInHistory()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ network", rig.NetworkFacts());
        var edited = rig.NetworkFacts(); edited["gateway"] = "10.4.0.254";
        var (ok, reason, v2) = rig.Service.EditDocument(Tech2, doc.Id, edited, "gateway replaced");
        Assert.True(ok, reason);
        Assert.Equal(2, v2!.CurrentVersion);
        var history = rig.Service.GetHistory(Admin, Scope, doc.Id);
        Assert.Equal(2, history.Count);
        Assert.Equal("10.4.0.1", history[0].Fields["gateway"]);   // v1 untouched
        Assert.Equal(Tech, history[0].ChangedBy);
        Assert.Equal("10.4.0.254", history[1].Fields["gateway"]);
        Assert.Equal(Tech2, history[1].ChangedBy);
        Assert.Contains("gateway", history[1].ChangedFields);
        Assert.Contains("notes", history[1].ChangedFields);
    }

    [Fact]
    public void EditDocument_NoOpRefused_AndUnknownFieldOnEditRefused()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts(), "n");
        Assert.False(rig.Service.EditDocument(Tech, doc.Id, rig.NetworkFacts(), "n").Ok);
        var bad = rig.NetworkFacts(); bad["bogus"] = "x";
        Assert.False(rig.Service.EditDocument(Tech, doc.Id, bad, "n").Ok);
        Assert.Equal(1, rig.Service.GetHistory(Admin, Scope, doc.Id).Count);
    }

    [Fact]
    public void DeleteDocument_AdminOnly_Tombstones_HistoryRetained()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        Assert.False(rig.Service.DeleteDocument(Tech, doc.Id).Ok);       // not an admin
        Assert.True(rig.Service.DeleteDocument(Admin, doc.Id).Ok);
        Assert.Null(rig.Service.GetDocument(Tech, Scope, doc.Id));
        Assert.Empty(rig.Service.ListDocuments(Admin, Scope));
        Assert.Single(rig.Service.GetHistory(Admin, Scope, doc.Id));             // the record survives
    }

    // ---- (b) credential vault -----------------------------------------------------

    [Fact]
    public void CredentialMetadata_HasNoSecretField_ListingsCarryMetadataOnly()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        var json = JsonSerializer.Serialize(meta);
        Assert.DoesNotContain(Secret1, json);
        // D38 F1: the metadata carries NO fingerprint of the secret —
        // neither the plain SHA-256 (an offline-cracking oracle) nor
        // any member named for one.
        Assert.DoesNotContain(EncryptionHash.Sha256Hex(Secret1), json);
        Assert.DoesNotContain("Fingerprint", json);
        var listed = rig.Service.ListCredentialsFor(Scope, Tech);
        Assert.Single(listed);
        Assert.DoesNotContain(Secret1, JsonSerializer.Serialize(listed));
    }

    [Fact]
    public void Reveal_GrantedUserWithReAuth_ReturnsSecret_AndAuditsWithoutSecret()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        var (ok, reason, secret) = rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof");
        Assert.True(ok, reason);
        Assert.Equal(Secret1, secret);
        var auditJson = JsonSerializer.Serialize(rig.Audit.Entries);
        Assert.Contains("site_credential_revealed", auditJson);
        Assert.Contains(meta.Id, auditJson);
        Assert.DoesNotContain(Secret1, auditJson);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Reveal_WithoutReAuth_AndWithoutGate_Refused()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, null).Ok);
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "").Ok);
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "wrong-proof").Ok);

        var noGate = new Rig(reAuth: false);
        var meta2 = noGate.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        var (ok, reason, _) = noGate.Service.RevealCredential(Tech, Scope, meta2.Id, "good-proof");
        Assert.False(ok);
        Assert.Contains("no re-auth gate", reason);
    }

    [Fact]
    public void Reveal_GrantShapes_DirectUser_UserGroup_ScopeAdmin_OutsiderRefused()
    {
        var rig = new Rig();
        var direct = rig.Cred("device", Dev1, "Direct", Secret1, users: new[] { Tech });
        var viaGroup = rig.Cred("device", Dev1, "ViaGroup", Secret2, groups: new[] { "techs" });
        Assert.True(rig.Service.RevealCredential(Tech, Scope, direct.Id, "good-proof").Ok);
        Assert.True(rig.Service.RevealCredential(Tech, Scope, viaGroup.Id, "good-proof").Ok); // Tech ∈ techs
        Assert.True(rig.Service.RevealCredential(Admin, Scope, direct.Id, "good-proof").Ok);  // scope admin
        Assert.False(rig.Service.RevealCredential(Outsider, Scope, direct.Id, "good-proof").Ok);
        Assert.False(rig.Service.RevealCredential(Tech2, Scope, viaGroup.Id, "good-proof").Ok); // Tech2 ∈ leads, not techs
        Assert.Empty(rig.Service.ListCredentialsFor(Scope, Outsider));
        Assert.Null(rig.Service.GetCredentialMetadata(Scope, direct.Id, Outsider));
    }

    [Fact]
    public void Reveal_CrossScopeRefused()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        Assert.False(rig.Service.RevealCredential(Tech, Scope2, meta.Id, "good-proof").Ok);
        Assert.False(rig.Service.RevealCredential(Tech, "no-such-scope", meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void Rotate_RequiresOwnershipAndReAuth_OldSecretDead()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        Assert.False(rig.Service.RotateCredentialSecret(Outsider, Scope, meta.Id, Secret2, "good-proof").Ok);
        // D38 F8 (amended): Tech holds a READ grant — a grant to read
        // no longer authorizes replacing the secret. Rotation is
        // ownership: the creator (Admin, the rig's default) or a
        // scope admin.
        Assert.False(rig.Service.RotateCredentialSecret(Tech, Scope, meta.Id, Secret2, "good-proof").Ok);
        Assert.False(rig.Service.RotateCredentialSecret(Admin, Scope, meta.Id, Secret2, "wrong").Ok);
        Assert.True(rig.Service.RotateCredentialSecret(Admin, Scope, meta.Id, Secret2, "good-proof").Ok);
        var (ok, _, secret) = rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof");
        Assert.True(ok);
        Assert.Equal(Secret2, secret);
        var auditJson = JsonSerializer.Serialize(rig.Audit.Entries);
        Assert.DoesNotContain(Secret1, auditJson);
        Assert.DoesNotContain(Secret2, auditJson);
    }

    [Fact]
    public void UpdateGrants_AdminOnly_AndDeleteCredential_AdminOnly()
    {
        var rig = new Rig();
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        Assert.False(rig.Service.UpdateCredentialGrants(Tech, Scope, meta.Id, new[] { Outsider }, null).Ok);
        Assert.True(rig.Service.UpdateCredentialGrants(Admin, Scope, meta.Id, new[] { Outsider }, null).Ok);
        Assert.True(rig.Service.RevealCredential(Outsider, Scope, meta.Id, "good-proof").Ok);
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof").Ok); // grant replaced, not merged
        Assert.False(rig.Service.DeleteCredential(Tech, Scope, meta.Id).Ok);
        Assert.True(rig.Service.DeleteCredential(Admin, Scope, meta.Id).Ok);
        Assert.False(rig.Service.RevealCredential(Admin, Scope, meta.Id, "good-proof").Ok);
    }

    [Fact]
    public void CreateCredential_GrantOutsideScopeRefused()
    {
        var rig = new Rig();
        rig.Roster.CreateUser("other-user", Scope2, "Other", "human");
        Assert.False(rig.Service.CreateCredential(Admin, Scope, "device", Dev1, "x", "u", "c",
            Secret1, new[] { "other-user" }, null).Ok);
        Assert.False(rig.Service.CreateCredential(Admin, Scope, "device", Dev1, "x", "u", "c",
            Secret1, null, new[] { "no-such-group" }).Ok);
    }

    // ---- (c) in-session surfacing ---------------------------------------------------

    [Fact]
    public void SessionContext_DeviceDocs_GroupDocs_VisibleCredMetadata_NoSecrets()
    {
        var rig = new Rig();
        // The session device is the ENROLLED device (GrpA member);
        // device-targeted records bind to its enrolled id.
        var dev = rig.EnrolledDev1;
        rig.Doc(Tech, "device", dev, DocTemplateKinds.NetworkFacts, "HQ net", rig.NetworkFacts());
        rig.Doc(Tech, "group", GrpA, DocTemplateKinds.SiteNotes, "Site A",
            new Dictionary<string, string> { ["site_name"] = "Site A" });
        rig.Doc(Tech, "device", rig.EnrolledDev2, DocTemplateKinds.NetworkFacts, "Other net", rig.NetworkFacts());
        var cred = rig.Cred("device", dev, "Site server", Secret1, users: new[] { Tech });
        rig.Cred("group", GrpA, "Group cred", Secret2, groups: new[] { "techs" });
        rig.Cred("device", dev, "Not yours", Secret2, users: new[] { Tech2 });

        var (ok, reason, ctx) = rig.Service.GetSessionContext(Tech, Scope, dev, new[] { GrpA });
        Assert.True(ok, reason);
        Assert.Equal(2, ctx!.Documents.Count);          // device doc + group doc, NOT Dev2's
        Assert.Equal(2, ctx.Credentials.Count);         // direct + group-granted, NOT Tech2's
        Assert.Contains(ctx.Credentials, c => c.Id == cred.Id);
        var json = JsonSerializer.Serialize(ctx);
        Assert.DoesNotContain(Secret1, json);
        Assert.DoesNotContain(Secret2, json);
    }

    [Fact]
    public void SessionContext_PolicyDisabled_Refuses()
    {
        var rig = new Rig();
        rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ net", rig.NetworkFacts());
        var verdict = rig.Policy.AddDocument(new ManagementPolicyDocument("org-off", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [SiteDocumentationPolicyKeys.Enabled] = "false" }, 1));
        Assert.True(verdict.Allowed, verdict.Reason);
        var (ok, reason, ctx) = rig.Service.GetSessionContext(Tech, Scope, Dev1, new[] { GrpA });
        Assert.False(ok);
        Assert.Null(ctx);
        Assert.Contains("disabled by policy", reason);
    }

    [Fact]
    public void SessionContext_UnknownUserRefused()
    {
        var rig = new Rig();
        Assert.False(rig.Service.GetSessionContext("ghost", Scope, Dev1, null).Ok);
    }

    // ---- persistence -------------------------------------------------------------------

    [Fact]
    public void ExportImport_RoundTrip_HistoryAndRevealSurvive()
    {
        var rig = new Rig();
        var doc = rig.Doc(Tech, "device", Dev1, DocTemplateKinds.NetworkFacts, "HQ", rig.NetworkFacts());
        var edited = rig.NetworkFacts(); edited["gateway"] = "10.4.0.254";
        Assert.True(rig.Service.EditDocument(Tech, doc.Id, edited, "").Ok);
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        var json = rig.Service.ExportJson();
        Assert.DoesNotContain(Secret1, json);

        var rig2 = new Rig();
        var restored = rig2.Service.ImportJson(json);
        Assert.Equal(2, restored);
        Assert.Equal(2, rig2.Service.GetHistory(Admin, Scope, doc.Id).Count);
        var (ok, _, secret) = rig2.Service.RevealCredential(Tech, Scope, meta.Id, "good-proof");
        Assert.True(ok);
        Assert.Equal(Secret1, secret);
    }

    // ---- real second-factor re-auth -------------------------------------------------------

    [Fact]
    public void TotpReAuthGate_RealSecondFactor_ProofConsumedAcrossReveals()
    {
        var rig = new Rig(withSecondFactor: true);
        var meta = rig.Cred("device", Dev1, "Site server", Secret1, users: new[] { Tech });
        var begun = rig.SecondFactor!.BeginTotpEnrollment(Scope, Tech, null, T0);
        Assert.NotNull(begun);
        var secretBytes = Base32.Decode(begun!.Value.Base32Secret)!;
        var confirmCode = Totp.At(secretBytes, T0);
        Assert.True(rig.SecondFactor.ConfirmTotpEnrollment(Scope, Tech, confirmCode, T0));

        var t1 = T0.AddSeconds(31);
        rig.Now = t1;
        var code1 = Totp.At(secretBytes, t1);
        var (ok, reason, revealed) = rig.Service.RevealCredential(Tech, Scope, meta.Id, code1);
        Assert.True(ok, reason);
        Assert.Equal(Secret1, revealed);
        // The same code can never reveal twice — its step was consumed.
        Assert.False(rig.Service.RevealCredential(Tech, Scope, meta.Id, code1).Ok);
        // A fresh code in the next step works.
        var t2 = t1.AddSeconds(30);
        rig.Now = t2;
        Assert.True(rig.Service.RevealCredential(Tech, Scope, meta.Id, Totp.At(secretBytes, t2)).Ok);
    }
}

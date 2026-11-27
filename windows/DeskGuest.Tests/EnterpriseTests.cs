using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// Block E — enterprise pack + BUILD-NOW backlog. Test names cite the
// directive id they prove (programme instruction for this lane).
public class EnterpriseTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private static PolicyBundle UnsignedBundle(string? pin = null, DateTimeOffset? defer = null, bool forbidAi = false) => new(
        Version: 1, ScopeId: "co1", TransportCeiling: new[] { "lan", "hub" }, TransportMode: "auto",
        PinnedVersion: pin, UpdateDeferUntil: defer, ForbidAiPairings: forbidAi, DisableRecording: false,
        UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "");

    private static (PolicyBundle Bundle, byte[] OrgPub) SignedBundle(string? pin = null, DateTimeOffset? defer = null, bool forbidAi = false)
    {
        var org = NewIdentity();
        return (PolicyBundleService.Sign(UnsignedBundle(pin, defer, forbidAi), org), org.PublicKey);
    }

    // ---- DIR-25 / DIR-56 chained audit ----
    [Fact]
    public void DIR25_ChainedAudit_VerifiesIntactChain()
    {
        var log = new ChainedAuditLog();
        log.Append("session", "alice", "started", T0);
        log.Append("session", "alice", "ended", T0.AddMinutes(5));
        var v = log.Verify();
        Assert.True(v.Ok);
        Assert.Equal(2, log.Entries.Count);
        Assert.Equal(log.Entries[0].Hash, log.Entries[1].PrevHash);
    }

    [Fact]
    public void DIR56_ChainedAudit_BackwardsClockIsFlaggedNotTrusted()
    {
        var log = new ChainedAuditLog();
        log.Append("a", "x", "first", T0.AddHours(1));
        var e2 = log.Append("a", "x", "second with earlier clock", T0);
        Assert.True(e2.ClockSkewFlagged);
        Assert.Equal(2, e2.Seq); // sequence still orders the chain
        Assert.True(log.Verify().Ok);
    }

    [Fact]
    public void DIR25_Witness_SignsChainHead_AndVerifies()
    {
        var log = new ChainedAuditLog();
        log.Append("session", "alice", "started", T0);
        var witnessDevice = NewIdentity();
        var w = log.CreateWitness("sess1", witnessDevice);
        Assert.True(log.VerifyWitness(w, witnessDevice.PublicKey));
        var other = NewIdentity();
        Assert.False(log.VerifyWitness(w, other.PublicKey));
    }

    // ---- DIR-23 exports ----
    [Fact]
    public void DIR23_Exports_CarryChainVerdict_AndExportIsAudited()
    {
        var log = new ChainedAuditLog();
        log.Append("session", "alice", "started", T0);
        var json = log.ExportJson("admin1", T0.AddMinutes(1));
        Assert.Contains("chainVerification=OK", json);
        Assert.Contains("audit_export", json); // the export itself is in the ledger
        var csv = log.ExportCsv("admin1", T0.AddMinutes(2));
        Assert.Contains("chainVerification=OK", csv);
        var cef = log.ExportCef("admin1", T0.AddMinutes(3));
        Assert.Contains("CEF:0|DeskGuest|", cef);
        Assert.Contains("chainVerification=OK", cef);
    }

    [Fact]
    public void ADIR30_WebhookPayload_SignsAndVerifies_MetadataOnly()
    {
        var alert = new Alert("offboarding", "user removed", T0);
        var payload = AlertCenter.SignedWebhookPayload(alert, "hook-secret");
        Assert.True(AlertCenter.VerifyWebhookPayload(payload, "hook-secret"));
        Assert.False(AlertCenter.VerifyWebhookPayload(payload, "wrong-secret"));
        Assert.DoesNotContain("hook-secret", payload);
    }

    // ---- DIR-22 policy bundle ----
    [Fact]
    public void DIR22_PolicyBundle_VerifiedBundle_Accepted()
    {
        var (bundle, pub) = SignedBundle();
        Assert.True(new PolicyBundleService().Verify(bundle, pub, T0.AddDays(1)).Allowed);
    }

    [Fact]
    public void DIR22_PolicyEnforcer_PinRefusesOtherVersions()
    {
        var (bundle, _) = SignedBundle(pin: "1.2.3");
        var enf = new PolicyEnforcer(bundle);
        Assert.True(enf.CheckUpdate("1.2.3", T0).Allowed);
        var refused = enf.CheckUpdate("1.2.4", T0);
        Assert.False(refused.Allowed);
        Assert.Contains("pins version 1.2.3", refused.Reason);
    }

    [Fact]
    public void DIR22_PolicyEnforcer_DeferRefusesUntilDate()
    {
        var (bundle, _) = SignedBundle(defer: T0.AddDays(7));
        var enf = new PolicyEnforcer(bundle);
        Assert.False(enf.CheckUpdate("9.9.9", T0.AddDays(1)).Allowed);
        Assert.True(enf.CheckUpdate("9.9.9", T0.AddDays(8)).Allowed);
    }

    [Fact]
    public void DIR22_PolicyEnforcer_CeilingRefusesOutsideRungs()
    {
        var (bundle, _) = SignedBundle();
        var enf = new PolicyEnforcer(bundle);
        Assert.True(enf.CheckTransport("lan").Allowed);
        Assert.False(enf.CheckTransport("tor").Allowed);
    }

    [Fact]
    public void DIR65_PolicyEnforcer_AiPairingProhibition()
    {
        var (bundle, _) = SignedBundle(forbidAi: true);
        Assert.False(new PolicyEnforcer(bundle).CheckAiPairing().Allowed);
        var (open, _) = SignedBundle();
        Assert.True(new PolicyEnforcer(open).CheckAiPairing().Allowed);
    }

    [Fact]
    public void DIR22_ManualPolicy_MustNameExactlyOneRung()
    {
        var org = NewIdentity();
        var bad = PolicyBundleService.Sign(UnsignedBundle() with { TransportMode = "manual" }, org); // ceiling has 2 rungs
        var verdict = new PolicyBundleService().Verify(bad, org.PublicKey, T0.AddDays(1));
        Assert.False(verdict.Allowed);
        Assert.Contains("exactly one approved rung", verdict.Reason);
    }

    [Fact]
    public void DIR22_ExpiredBundle_Refused()
    {
        var (bundle, pub) = SignedBundle();
        Assert.False(new PolicyBundleService().Verify(bundle, pub, T0.AddDays(31)).Allowed);
    }

    // ---- DIR-38 unattended tier carried in bundle ----
    [Fact]
    public void DIR38_UnattendedTier_IsPartOfSignedBundle()
    {
        var (bundle, pub) = SignedBundle();
        Assert.Equal("business_hours", bundle.UnattendedTier);
        var tampered = bundle with { UnattendedTier = "always_with_gates" };
        Assert.False(new PolicyBundleService().Verify(tampered, pub, T0.AddDays(1)).Allowed);
    }

    // ---- REC model ----
    [Fact]
    public void REC01_Recording_WithoutConsentArtefact_Refused()
    {
        var req = new RecordingRequest("company", false, false, false, false, false, false);
        Assert.False(RecordingPolicy.CanStart(req, null, null).Allowed);
    }

    [Fact]
    public void REC06_Audio_RequiresSeparateConsent()
    {
        var req = new RecordingRequest("company", true, false, false, false, false, false);
        var videoOnly = new ConsentArtefact("r1", "s1", "op", false, "host", "op", "explicit_prompt", T0, false, "support", null);
        Assert.False(RecordingPolicy.CanStart(req, videoOnly, null).Allowed);
        var withAudio = videoOnly with { AudioIncluded = true };
        Assert.True(RecordingPolicy.CanStart(req, withAudio, null).Allowed);
    }

    [Fact]
    public void REC08_HostStopRecording_AlwaysStops_EvenWhenMandated()
    {
        Assert.Equal("recording_stopped", RecordingPolicy.ApplyHostStopRecording(mandated: true));
        Assert.Equal("recording_stopped", RecordingPolicy.ApplyHostStopRecording(mandated: false));
    }

    [Fact]
    public void REC13_DisableRecordingPolicy_BlocksAll()
    {
        var (bundle, _) = SignedBundle();
        var disabling = bundle with { DisableRecording = true };
        var req = new RecordingRequest("company", false, false, false, false, false, false);
        var art = new ConsentArtefact("r1", "s1", "op", false, "host", "op", "explicit_prompt", T0, false, "support", null);
        Assert.False(RecordingPolicy.CanStart(req, art, disabling).Allowed);
    }

    [Fact]
    public void REC10_ByodMandate_RequiresOwnerEnablement()
    {
        var req = new RecordingRequest("company", false, true, true, false, false, false);
        var art = new ConsentArtefact("r1", "s1", "op", false, "host", "op", "explicit_prompt", T0, false, "support", null);
        Assert.False(RecordingPolicy.CanStart(req, art, null).Allowed);
        var enabled = req with { ByodRecordingEnabledByOwner = true };
        Assert.True(RecordingPolicy.CanStart(enabled, art, null).Allowed);
    }

    [Fact]
    public void REC19_AgentRecording_RequiresHumanPolicy()
    {
        var req = new RecordingRequest("company", false, false, false, false, true, false);
        var art = new ConsentArtefact("r1", "s1", "agent-x", true, "host", "op", "explicit_prompt", T0, false, "support", null);
        Assert.False(RecordingPolicy.CanStart(req, art, null).Allowed);
    }

    [Fact]
    public void REC14_IndefiniteRetention_IsNotSelectable()
    {
        Assert.False(RecordingPolicy.ValidateRetentionDays(-1).Allowed);
        Assert.False(RecordingPolicy.ValidateRetentionDays(0).Allowed);
        Assert.True(RecordingPolicy.ValidateRetentionDays(30).Allowed);
    }

    [Fact]
    public void REC24_MandateReconfirmation_After90DaysOrPolicyChange()
    {
        Assert.True(RecordingPolicy.ReconfirmationDue(T0, false, T0.AddDays(91)));
        Assert.True(RecordingPolicy.ReconfirmationDue(T0, true, T0.AddDays(1)));
        Assert.False(RecordingPolicy.ReconfirmationDue(T0, false, T0.AddDays(30)));
    }

    [Fact]
    public void REC11_NoticeArtefact_RequiresCounselMarker()
    {
        var store = new NoticeArtefactStore();
        Assert.Throws<InvalidOperationException>(() =>
            store.Record(new NoticeArtefact("NY", "v1", "u1", T0, T0, "looks fine")));
        store.Record(new NoticeArtefact("NY", "v1", "u1", T0, T0, "have counsel review before use"));
        Assert.Single(store.For("u1"));
    }

    [Fact]
    public void REC12_ProportionalityPack_Incomplete_Refused()
    {
        Assert.False(NoticeArtefactStore.CheckProportionalityPack(true, true, false, true, true).Allowed);
        Assert.True(NoticeArtefactStore.CheckProportionalityPack(true, true, true, true, true).Allowed);
    }

    // ---- DIR-21 OIDC + mock IdP ----
    private static (OidcClient Client, MockIdp Idp) OidcSetup()
    {
        var idp = new MockIdp("https://idp.example.test");
        var cfg = new OidcConfig("https://idp.example.test", "deskguest-client", "https://localhost/callback", true, true);
        return (new OidcClient(cfg, idp), idp);
    }

    [Fact]
    public void DIR21_OidcConfig_HttpIssuerRefused_PkceAndVerifiedEmailRequired()
    {
        Assert.False(OidcConfigValidator.Validate(new OidcConfig("http://idp.example.test", "c", "r", true, true)).Allowed);
        Assert.False(OidcConfigValidator.Validate(new OidcConfig("https://idp.example.test", "c", "r", false, true)).Allowed);
        Assert.False(OidcConfigValidator.Validate(new OidcConfig("https://idp.example.test", "c", "r", true, false)).Allowed);
    }

    [Fact]
    public void DIR21_MockIdp_SignInFlow_SucceedsWithPkce()
    {
        var (client, idp) = OidcSetup();
        var verifier = Pkce.NewVerifier();
        var code = idp.BeginAuthorize("user-1", "a@b.test", true, Pkce.ChallengeS256(verifier), "nonce-1");
        var token = idp.ExchangeCode(code, verifier, "deskguest-client");
        var result = client.CompleteSignIn(token, "nonce-1", DateTimeOffset.UtcNow);
        Assert.True(result.Ok);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    public void DIR21_MockIdp_UnverifiedEmail_Refused()
    {
        var (client, idp) = OidcSetup();
        var verifier = Pkce.NewVerifier();
        var code = idp.BeginAuthorize("user-2", "a@b.test", false, Pkce.ChallengeS256(verifier), "nonce-2");
        var token = idp.ExchangeCode(code, verifier, "deskguest-client");
        Assert.False(client.CompleteSignIn(token, "nonce-2", DateTimeOffset.UtcNow).Ok);
    }

    [Fact]
    public void DIR21_MockIdp_WrongPkceVerifier_ExchangeRefused()
    {
        var (_, idp) = OidcSetup();
        var code = idp.BeginAuthorize("user-1", "a@b.test", true, Pkce.ChallengeS256(Pkce.NewVerifier()), "n");
        Assert.Throws<InvalidOperationException>(() => idp.ExchangeCode(code, Pkce.NewVerifier(), "deskguest-client"));
    }

    [Fact]
    public void ADIR27_SsoEnforcement_RequiresTestLoginAndFallback()
    {
        var guard = new SsoLockoutGuard();
        Assert.False(guard.CanEnforceMandatorySso().Allowed);
        // bd-shared-sec-2/F7: the flags are no longer publicly
        // settable -- they move only through the proof-recording
        // methods (a completed sign-in result; a verified
        // fallback admin id).
        guard.RecordTestLogin(new OidcClient.SignInResult(true, "user-1", "a@b.test", "test login"));
        Assert.False(guard.CanEnforceMandatorySso().Allowed);
        guard.RecordFallbackAdminVerified("admin1");
        Assert.True(guard.CanEnforceMandatorySso().Allowed);
    }

    // ---- DIR-51/52 directory sync ----
    private static (RosterService Roster, DirectorySyncService Sync, AlertCenter Alerts) RosterSetup()
    {
        var roster = new RosterService();
        roster.CreateScope("co1", "company", "Acme");
        roster.CreateUser("admin1", "co1", "Admin One", "human");
        roster.AddCompanyAdmin("co1", "admin1");
        var audit = new ChainedAuditLog();
        var alerts = new AlertCenter();
        return (roster, new DirectorySyncService(roster, audit, alerts), alerts);
    }

    [Fact]
    public void DIR51_DirectorySync_CreateThenRemove_DrivesD14Offboarding()
    {
        var (roster, sync, _) = RosterSetup();
        Assert.True(sync.Apply(new DirectoryEvent("co1", "co1", "u100", "User Hundred", "create", "ext-100"), "admin1", T0).Allowed);
        Assert.NotNull(roster.GetUser("co1", "u100"));
        var verdict = sync.Apply(new DirectoryEvent("co1", "co1", "u100", "User Hundred", "remove", "ext-100"), "admin1", T0);
        Assert.True(verdict.Allowed);
        Assert.Null(roster.GetUser("co1", "u100")); // offboarded via the D14 path
    }

    [Fact]
    public void ADIR28_DirectorySync_RemovingLastAdmin_RefusedAndAlerts_BreakGlassIsOnlyPath()
    {
        // Cross-directive reconciliation (recorded in the Block E ledger):
        // ADIR-28's "suspends-and-alerts instead" collides with the D38
        // S2-WIN F1 guard, which refuses to suspend the sole LIVE admin.
        // The composed behavior: removal refused, sprawl alert raised,
        // admin untouched, break-glass named as the only path (BAD-19/32).
        var (roster, sync, alerts) = RosterSetup();
        var verdict = sync.Apply(new DirectoryEvent("co1", "co1", "admin1", "Admin One", "remove", "ext-a"), "admin1", T0);
        Assert.False(verdict.Allowed);
        Assert.Contains("break-glass", verdict.Reason);
        var admin = roster.GetUser("co1", "admin1");
        Assert.NotNull(admin);
        Assert.False(admin!.Suspended);
        Assert.Contains(alerts.Alerts, a => a.EventClass == "sprawl");
    }

    // ---- DIR-53 / BAD-32 break-glass ----
    private static (BreakGlassService Bg, ChainedAuditLog Audit, AlertCenter Alerts) BreakGlassSetup()
    {
        var audit = new ChainedAuditLog(); var alerts = new AlertCenter();
        var bg = new BreakGlassService(audit, alerts);
        bg.SealHolder("holder-a", "secret-a");
        bg.SealHolder("holder-b", "secret-b");
        return (bg, audit, alerts);
    }

    [Fact]
    public void BAD32_BreakGlass_DualControl_IssuesTimeBoxedGrant_AndIsLoud()
    {
        var (bg, audit, alerts) = BreakGlassSetup();
        var grant = bg.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "IdP down, restore admin", false, T0);
        Assert.NotNull(grant);
        Assert.True(bg.GrantValid(grant!, T0.AddHours(3)));
        Assert.False(bg.GrantValid(grant!, T0.AddHours(5)));
        Assert.Contains(audit.Entries, e => e.Kind == "break_glass_use");
        Assert.Contains(alerts.Alerts, a => a.EventClass == "break_glass_use");
        Assert.True(bg.RotationRequired); // use triggers rotation
    }

    [Fact]
    public void BAD32_BreakGlass_SingleHolder_Refused()
    {
        var (bg, audit, _) = BreakGlassSetup();
        Assert.Null(bg.Use("co1", "holder-a", "secret-a", "holder-a", "secret-a", "solo attempt", false, T0));
        Assert.DoesNotContain(audit.Entries, e => e.Kind == "break_glass_use");
    }

    [Fact]
    public void ADIR34_BreakGlassTest_OverdueAfter90Days()
    {
        Assert.True(BreakGlassService.TestOverdue(null, T0));
        Assert.True(BreakGlassService.TestOverdue(T0.AddDays(-91), T0));
        Assert.False(BreakGlassService.TestOverdue(T0.AddDays(-10), T0));
    }

    // ---- DIR-57 / ADIR-23/24 alerting ----
    [Fact]
    public void DIR57_AlertCenter_NamedClassesOnly()
    {
        var alerts = new AlertCenter();
        alerts.Raise("stop", "STOP pressed", T0);
        Assert.Throws<ArgumentException>(() => alerts.Raise("made_up_class", "x", T0));
    }

    [Fact]
    public void ADIR24_SprawlEvaluation_WarnsAtThreeAdmins()
    {
        var alerts = new AlertCenter();
        var cards = alerts.EvaluateSprawl(3, 1, 0, true, T0);
        Assert.Equal(3, cards.Count);
        Assert.Contains(cards, c => c.Contains("warn at 3"));
    }

    // ---- BAD tracker / inventory ----
    [Fact]
    public void BAD03_Tracker_NeverSaysRevokedWhileAcksPending()
    {
        var t = new RevocationTracker("inc-1", "stolen laptop", T0);
        t.Add("deskguest_identity", "dev-1");
        t.Add("mesh_node", "dev-1", T0.AddHours(24));
        var wording = t.SummaryWording();
        Assert.StartsWith("Revocation in progress", wording);
        Assert.Contains("dev-1", wording);
        t.SetState("deskguest_identity", "dev-1", "confirmed");
        t.SetState("mesh_node", "dev-1", "confirmed");
        Assert.StartsWith("Revoked:", t.SummaryWording());
    }

    [Fact]
    public void BAD04_Tracker_IdentityAndMeshAreSeparateSubActions()
    {
        var t = new RevocationTracker("inc-1", "stolen laptop", T0);
        t.Add("deskguest_identity", "dev-1");
        t.Add("mesh_node", "dev-1");
        t.SetState("deskguest_identity", "dev-1", "confirmed");
        Assert.NotNull(t.FirstUnconfirmed()); // mesh still pending — never inferred
        Assert.Equal("mesh_node", t.FirstUnconfirmed()!.Kind);
    }

    [Fact]
    public void BAD36_Tracker_CheckpointResume_FirstUnconfirmedSurvivesRoundtrip()
    {
        var t = new RevocationTracker("inc-1", "leaked code", T0);
        t.Add("enrollment_keys", "code-1");
        t.Add("sessions", "sess-1");
        t.SetState("enrollment_keys", "code-1", "confirmed");
        var restored = RevocationTracker.ImportState(t.ExportState());
        Assert.Equal("sess-1", restored.FirstUnconfirmed()!.TargetId);
    }

    [Fact]
    public void BAD37_Tracker_SignedIncidentRecord_Verifies()
    {
        var signer = NewIdentity();
        var t = new RevocationTracker("inc-1", "stolen laptop", T0);
        t.Add("deskguest_identity", "dev-1");
        var exported = t.ExportSignedIncidentRecord(signer, T0.AddHours(2));
        Assert.Contains(signer.DeviceId, exported);
        Assert.Contains("inc-1", exported);
    }

    [Fact]
    public void BAD35_SignedRevocation_AppliesOnReceipt_TamperRefused()
    {
        var issuer = NewIdentity();
        var rec = SignedRevocation.Create(issuer, "dev-9", "device_identity", T0, TimeSpan.FromHours(24));
        Assert.True(SignedRevocation.ApplyOnReceipt(rec, issuer.PublicKey, T0.AddHours(1)).Allowed);
        var tampered = rec with { TargetId = "dev-OTHER" };
        Assert.False(SignedRevocation.ApplyOnReceipt(tampered, issuer.PublicKey, T0.AddHours(1)).Allowed);
        Assert.False(SignedRevocation.ApplyOnReceipt(rec, issuer.PublicKey, T0.AddDays(2)).Allowed); // expired backstop
    }

    [Fact]
    public void BAD05_TokenLifetime_CapEnforced_AndWindowStated()
    {
        Assert.True(TokenLifetimePolicy.Validate(TimeSpan.FromHours(4)).Allowed);
        Assert.False(TokenLifetimePolicy.Validate(TimeSpan.FromDays(7)).Allowed);
        Assert.Contains("worst-case offline revocation window", TokenLifetimePolicy.StatedOfflineWindow);
    }

    [Fact]
    public void BAD15_Inventory_CreatorAttribution_Queryable()
    {
        var inv = new SecurityObjectInventory();
        inv.Record(new SecurityObject("enrollment_code", "code-1", "rogue-admin", "co1", T0, new[] { "dev-x", "dev-y" }));
        Assert.Single(inv.CreatedBy("rogue-admin"));
        Assert.Empty(inv.CreatedBy("someone-else"));
    }

    [Fact]
    public void BAD16_EvictionList_CoversAdmittedIdentities_SparingNeedsReason()
    {
        var inv = new SecurityObjectInventory();
        inv.Record(new SecurityObject("enrollment_code", "code-1", "rogue-admin", "co1", T0, new[] { "dev-x", "dev-y" }));
        var evict = inv.EvictionList("rogue-admin", new Dictionary<string, string> { ["dev-x"] = "verified legitimate, in person" });
        Assert.Equal(new[] { "dev-y" }, evict);
        Assert.False(SecurityObjectInventory.ValidateSparing("dev-x", null).Allowed);
        Assert.True(SecurityObjectInventory.ValidateSparing("dev-x", "named reason").Allowed);
    }

    [Fact]
    public void BAD20_RotationChecklist_StatesExternalBoundary()
    {
        var inv = new SecurityObjectInventory();
        inv.Record(new SecurityObject("api_key", "key-1", "leaver", "co1", T0, Array.Empty<string>()));
        var lines = inv.RotationChecklist("leaver", "the org IdP");
        Assert.Contains(lines, l => l.Contains("cannot list passwords held only in"));
    }

    [Fact]
    public void BAD14_SpofDetector_NamesRemedies()
    {
        var warnings = SpofDetector.Detect(true, false, true, false, false);
        Assert.Equal(2, warnings.Count);
        Assert.Contains(warnings, w => w.Contains("break-glass"));
    }

    [Fact]
    public void BAD18_AdminRemoval_DualControlOrCoolingOff()
    {
        Assert.Equal("dual_control_required", AdminRemovalGuard.Evaluate(3, false, T0).Mode);
        Assert.Equal("dual_control_satisfied", AdminRemovalGuard.Evaluate(3, true, T0).Mode);
        var cooling = AdminRemovalGuard.Evaluate(1, false, T0);
        Assert.Equal("cooling_off", cooling.Mode);
        Assert.NotNull(cooling.CoolingOffEndsUtc);
    }

    [Fact]
    public void BAD33_SuspendedResume_RequiresNewOwnerReauthorisation()
    {
        Assert.False(SuspendedResumeGuard.CheckResume("grant", null).Allowed);
        Assert.True(SuspendedResumeGuard.CheckResume("grant", "new-owner-1").Allowed);
    }

    [Fact]
    public void BAD34_CleanVerification_RequiresTwoHoldersAndNoResiduals()
    {
        Assert.True(new CleanVerification(true, true, true, 2, Array.Empty<string>()).IsClean);
        Assert.False(new CleanVerification(true, true, true, 1, Array.Empty<string>()).IsClean);
        Assert.False(new CleanVerification(true, true, true, 2, new[] { "one residual" }).Verdict == "clean");
    }

    // ---- SCAM friction ----
    private static readonly OperatorHistory Fresh = new(0, 0, 0, null, false);

    [Fact]
    public void SCAM01_FirstSession_StartsViewOnly_WithDelayedSecondConsent()
    {
        var d = ScamFriction.Evaluate("op-key-1", "Helper", Fresh, T0.AddDays(-30), T0, false);
        Assert.True(d.StartsViewOnly);
        Assert.True(d.SecondConsentRequired);
        Assert.Equal(60, d.SecondConsentEarliestSeconds);
    }

    [Fact]
    public void SCAM04_PresenceLabel_ShowsVerificationState()
    {
        var d = ScamFriction.Evaluate("op-key-1", "Helper", Fresh, T0.AddDays(-30), T0, false);
        Assert.StartsWith("Unverified helper calling themselves", d.PresenceLabel);
    }

    [Fact]
    public void SCAM05_ImpersonationName_TriggersFriction_EvenForKnownOperator()
    {
        var known = new OperatorHistory(5, 0, 0, null, false);
        var d = ScamFriction.Evaluate("op-key-1", "Microsoft Support", known, T0.AddDays(-30), T0, false);
        Assert.True(d.WarningRequired);
        var trusted = known with { MarkedKnownTrustedLocally = true };
        Assert.False(ScamFriction.Evaluate("op-key-1", "Microsoft Support", trusted, T0.AddDays(-30), T0, false).WarningRequired);
    }

    [Fact]
    public void SCAM15_EstablishedOperator_EarnsFastPath()
    {
        var est = new OperatorHistory(3, 0, 0, null, false);
        var d = ScamFriction.Evaluate("op-key-1", "Helper", est, T0.AddDays(-30), T0, false);
        Assert.Equal("established", d.Level);
        Assert.False(d.StartsViewOnly);
    }

    [Fact]
    public void SCAM08_CooldownAfterStop_BlocksFastPath()
    {
        var est = new OperatorHistory(5, 0, 0, T0.AddMinutes(-10), false);
        var d = ScamFriction.Evaluate("op-key-1", "Helper", est, T0.AddDays(-30), T0, false);
        Assert.True(d.WarningRequired);
        Assert.Contains("cooldown", d.Reason);
    }

    [Fact]
    public void SCAM13_FreshInstall_TreatedAsFirstContact()
    {
        var est = new OperatorHistory(5, 0, 0, null, false);
        var d = ScamFriction.Evaluate("op-key-1", "Helper", est, T0.AddHours(-2), T0, false);
        Assert.True(d.StartsViewOnly);
    }

    [Fact]
    public void SCAM09_SensitiveContext_PausesForNonEstablished()
    {
        Assert.True(ScamFriction.SensitiveContextPauses("banking", Fresh));
        Assert.True(ScamFriction.SensitiveContextPauses("password_field", Fresh));
        Assert.False(ScamFriction.SensitiveContextPauses("banking", new OperatorHistory(3, 0, 0, null, false)));
        Assert.False(ScamFriction.SensitiveContextPauses("text_editor", Fresh));
    }

    [Fact]
    public void SCAM11_InSessionPersistenceActions_Prohibited()
    {
        Assert.False(ScamFriction.InSessionAction("create_unattended_access").Allowed);
        Assert.False(ScamFriction.InSessionAction("modify_allowed_operators").Allowed);
        Assert.True(ScamFriction.InSessionAction("move_pointer").Allowed);
    }

    [Fact]
    public void SCAM12_OneOffCode_SingleUseAndTenMinuteExpiry()
    {
        Assert.True(ScamFriction.ValidateOneOffCode(T0, false, T0.AddMinutes(5)).Allowed);
        Assert.False(ScamFriction.ValidateOneOffCode(T0, true, T0.AddMinutes(5)).Allowed);
        Assert.False(ScamFriction.ValidateOneOffCode(T0, false, T0.AddMinutes(11)).Allowed);
    }

    [Fact]
    public void SCAM02_PairingCeremony_LocalOnly_OperatorClaimRefused()
    {
        Assert.True(ScamFriction.CompletePairingCeremony(true, false).Allowed);
        Assert.False(ScamFriction.CompletePairingCeremony(false, true).Allowed);
        Assert.False(ScamFriction.CompletePairingCeremony(true, true).Allowed);
    }

    // ---- HELP receipt ----
    [Fact]
    public void HELP09_Receipt_NeverOmitsCategories_AndStatesNoRecording()
    {
        var receipt = SessionReceipt.Generate(new ReceiptFacts("Sam", T0, T0.AddMinutes(23), 10, 13,
            Array.Empty<string>(), Array.Empty<string>(), false, "you pressed STOP"));
        Assert.Contains("No files were copied.", receipt);
        Assert.Contains("No programs were opened.", receipt);
        Assert.Contains("We did not record this session.", receipt);
    }

    [Fact]
    public void SCAM18_Receipt_ListsCopiedFilesWhenPresent()
    {
        var receipt = SessionReceipt.Generate(new ReceiptFacts("Sam", T0, T0.AddMinutes(5), 5, 0,
            new[] { "report.pdf" }, new[] { "Mail" }, true, "operator disconnected"));
        Assert.Contains("report.pdf", receipt);
        Assert.Contains("This session was recorded.", receipt);
    }

    // ---- DIR-54 / DIR-55 / DIR-62 / ADIR-29 / ADIR-35 ----
    [Fact]
    public void DIR54_AccessReview_NonResponseDefaultsToSuspend()
    {
        var campaign = new AccessReviewCampaign(new[] { "u1", "u2" }, T0.AddDays(14));
        campaign.Attest("u1");
        var items = campaign.ApplyDeadlineDefaults(T0.AddDays(15));
        Assert.Equal("attested", items.Single(i => i.UserId == "u1").Decision);
        Assert.Equal("defaulted_suspend", items.Single(i => i.UserId == "u2").Decision);
    }

    [Fact]
    public void DIR55_DriftReport_NamesDriftedDevicesOnly()
    {
        var fleet = new[]
        {
            new DeviceDriftState("dev-ok", "3", "1.0"),
            new DeviceDriftState("dev-old", "2", "1.0")
        };
        var drift = DriftReport.Compare(fleet, "3", "1.0");
        Assert.Single(drift);
        Assert.Contains("dev-old", drift[0]);
    }

    [Fact]
    public void DIR62_TransferControls_BlockMaliciousAndUnverdicted()
    {
        var policy = new TransferPolicy(1_000_000, new HashSet<string> { ".exe" }, RequireScanVerdict: true);
        Assert.False(FileTransferControls.Evaluate("tool.exe", 10, "clean", policy).Allowed);
        Assert.False(FileTransferControls.Evaluate("doc.pdf", 10, "malicious", policy).Allowed);
        Assert.False(FileTransferControls.Evaluate("doc.pdf", 10, null, policy).Allowed);
        Assert.True(FileTransferControls.Evaluate("doc.pdf", 10, "clean", policy).Allowed);
    }

    [Fact]
    public void ADIR29_ServiceTokens_ScopedAndExpiring_NeverInheritRoles()
    {
        var store = new ServiceTokenStore();
        var (id, secret) = store.Issue(new HashSet<string> { "audit.read" }, TimeSpan.FromDays(7), T0);
        Assert.True(store.Authorize(id, secret, "audit.read", T0.AddDays(1)).Allowed);
        Assert.False(store.Authorize(id, secret, "grants.write", T0.AddDays(1)).Allowed);
        Assert.False(store.Authorize(id, secret, "audit.read", T0.AddDays(8)).Allowed);
    }

    [Fact]
    public void ADIR35_LegalHold_BlocksDeletion_AndGrantsNoViewing()
    {
        var holds = new LegalHoldStore();
        Assert.False(holds.Place("rec-1", "member", T0.AddDays(30)).Allowed);
        Assert.True(holds.Place("rec-1", "company_admin", T0.AddDays(30)).Allowed);
        Assert.True(holds.IsHeld("rec-1", T0.AddDays(1)));
        Assert.False(holds.CheckDeletion("rec-1", T0.AddDays(1)).Allowed);
        Assert.DoesNotContain(PermissionVocabulary.All, p => p.Contains("hold.view"));
    }

    [Fact]
    public void ADIR06_ForbiddenPermissions_DoNotExistInVocabulary()
    {
        foreach (var forbidden in PermissionVocabulary.ForbiddenConcepts)
            Assert.DoesNotContain(PermissionVocabulary.All, p => p == forbidden || p.StartsWith(forbidden.Split('.')[0] + ".edit"));
        Assert.DoesNotContain(PermissionVocabulary.All, p => p.Contains("impersonate") || p.Contains("private_key") || p.Contains("credential.view"));
    }

    [Fact]
    public void ADIR07_AdminSessionSurface_HasNoContentPath()
    {
        Assert.Equal(new HashSet<string> { "session.metadata", "session.terminate" }, PermissionVocabulary.AdminSessionSurface);
        Assert.DoesNotContain(PermissionVocabulary.AdminSessionSurface, s => s.Contains("content") || s.Contains("frame") || s.Contains("watch"));
    }
}

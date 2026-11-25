using System.Text;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

// Block E DESTRUCTION GATE — hostile passes against everything this
// lane built. Each test is a genuine break attempt; a pass means the
// attack was REFUSED. Ledger: DESTRUCTION-LEDGER.md (DE-E-01..07).
public class EnterpriseDestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private static PolicyBundle Unsigned() => new(
        Version: 1, ScopeId: "co1", TransportCeiling: new[] { "lan" }, TransportMode: "manual",
        PinnedVersion: "1.0.0", UpdateDeferUntil: null, ForbidAiPairings: true, DisableRecording: false,
        UnattendedTier: "none", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "");

    // DE-E-01: hand-edited policy must fail closed, never widen.
    [Fact]
    public void DE_E_01_PolicyTampering_WideningAttempt_FailsClosed()
    {
        var org = NewIdentity();
        var signed = PolicyBundleService.Sign(Unsigned(), org);
        var svc = new PolicyBundleService();
        // Attacker edits the ceiling to add Tor, lifts the pin, un-forbids AI.
        var widened = signed with { TransportCeiling = new[] { "lan", "tor" } };
        Assert.False(svc.Verify(widened, org.PublicKey, T0.AddDays(1)).Allowed);
        var unpinned = signed with { PinnedVersion = null };
        Assert.False(svc.Verify(unpinned, org.PublicKey, T0.AddDays(1)).Allowed);
        var aiAllowed = signed with { ForbidAiPairings = false };
        Assert.False(svc.Verify(aiAllowed, org.PublicKey, T0.AddDays(1)).Allowed);
        // Garbage signature encoding also refuses (no exception escapes).
        var garbage = signed with { SignatureBase64 = "!!!not-base64!!!" };
        Assert.False(svc.Verify(garbage, org.PublicKey, T0.AddDays(1)).Allowed);
    }

    // DE-E-02: pin/defer bypass attempts.
    [Fact]
    public void DE_E_02_PinDeferBypass_AttemptsRefused()
    {
        var org = NewIdentity();
        var bundle = PolicyBundleService.Sign(Unsigned() with { UpdateDeferUntil = T0.AddDays(30) }, org);
        var enf = new PolicyEnforcer(bundle);
        Assert.False(enf.CheckUpdate("1.0.1", T0.AddDays(1)).Allowed);   // pin bypass
        Assert.False(enf.CheckUpdate("1.0.0", T0.AddDays(1)).Allowed);   // defer bypass (even the pinned version waits)
        Assert.False(enf.CheckUpdate("0.0.1", T0.AddDays(31)).Allowed);  // downgrade after defer still hits the pin
        Assert.True(enf.CheckUpdate("1.0.0", T0.AddDays(31)).Allowed);   // only the pinned version, after defer
    }

    // DE-E-03: audit chain forgery — head/witness substitution and
    // cross-device witness forgery must refuse; the export header is
    // derived from Verify() at export time, so an export cannot claim
    // OK for a head that does not match the chain it carries.
    [Fact]
    public void DE_E_03_ChainForgery_WitnessAndHeadSubstitution_Refused()
    {
        var log = new ChainedAuditLog();
        log.Append("session", "alice", "started", T0);
        log.Append("session", "alice", "ended", T0.AddMinutes(5));
        var device = NewIdentity();
        var witness = log.CreateWitness("s1", device);
        // Substituting a forged head into the witness: refused.
        var forgedHead = witness with { HeadHash = new string('0', 64) };
        Assert.False(log.VerifyWitness(forgedHead, device.PublicKey));
        // A witness forged by a DIFFERENT device key: refused.
        var attacker = NewIdentity();
        var forgedWitness = log.CreateWitness("s1", attacker);
        Assert.False(log.VerifyWitness(forgedWitness, device.PublicKey));
        // Export consistency: the header's verdict and head come from the
        // same Verify() pass over the exported entries.
        var v = log.Verify();
        Assert.True(v.Ok);
        Assert.Contains(log.HeadHash, v.Summary);
        var exported = log.ExportJson("admin", T0.AddMinutes(6));
        Assert.Contains("chainVerification=OK", exported);
        Assert.Contains("audit_export", exported);
    }

    // DE-E-04: directory-sync injection — cross-scope event must refuse.
    [Fact]
    public void DE_E_04_DirectorySync_CrossScopeInjection_RefusedAndAudited()
    {
        var roster = new RosterService();
        roster.CreateScope("co1", "company", "Acme");
        roster.CreateScope("personal1", "personal", "Mine");
        roster.CreateUser("admin1", "co1", "Admin", "human");
        roster.AddCompanyAdmin("co1", "admin1");
        roster.CreateUser("victim", "personal1", "Victim", "human");
        var audit = new ChainedAuditLog();
        var sync = new DirectorySyncService(roster, audit, new AlertCenter());
        // Attack: an event bound to co1 tries to remove a user by naming the personal scope.
        var verdict = sync.Apply(new DirectoryEvent("co1", "personal1", "victim", "Victim", "remove", "ext-x"), "admin1", T0);
        Assert.False(verdict.Allowed);
        Assert.NotNull(roster.GetUser("personal1", "victim")); // untouched
        Assert.Contains(audit.Entries, e => e.Kind == "directory_sync_refused");
    }

    // DE-E-05: break-glass silent-use attempts.
    [Fact]
    public void DE_E_05_BreakGlass_NoSilentPath_EveryUseIsLoudAndRotationLocked()
    {
        var audit = new ChainedAuditLog(); var alerts = new AlertCenter();
        var bg = new BreakGlassService(audit, alerts);
        bg.SealHolder("a", "sa"); bg.SealHolder("b", "sb");
        // Wrong secret: no grant, and crucially no quiet success path.
        Assert.Null(bg.Use("co1", "a", "WRONG", "b", "sb", "attempt", false, T0));
        // Empty reason: refused — an unexplained emergency grant must not exist.
        Assert.Null(bg.Use("co1", "a", "sa", "b", "sb", "", false, T0));
        // Legit use: loud BEFORE grant (audit + alert counts move).
        var grant = bg.Use("co1", "a", "sa", "b", "sb", "IdP down", false, T0);
        Assert.NotNull(grant);
        Assert.Single(audit.Entries, e => e.Kind == "break_glass_use");
        // bd-shared-sec-2/F12 (W3): failed attempts are ALSO loud
        // (kind break_glass_use_failed + their own alerts) -- the
        // Single below therefore pins the SUCCESS alert by its
        // text, and the failures' loudness is asserted alongside.
        Assert.Single(alerts.Alerts, a => a.EventClass == "break_glass_use" && a.Detail.Contains("USE in scope"));
        Assert.Equal(2, audit.Entries.Count(e => e.Kind == "break_glass_use_failed"));
        // Second use without rotation: refused (use triggers rotation).
        Assert.Null(bg.Use("co1", "a", "sa", "b", "sb", "again", false, T0));
        bg.Rotate("a", "sa2");
        // Block H per-holder rotation: rotating ONE of the two
        // holders who took part does NOT unlock — the other's used
        // secret is still live. (This test previously reused after
        // a single rotation; the semantics were deliberately
        // hardened when Rotate gained its product surface, and
        // the live drill rotated the pair. The loudness and
        // refusal assertions above are unchanged.)
        Assert.Null(bg.Use("co1", "a", "sa2", "b", "sb", "half-rotated", false, T0));
        bg.Rotate("b", "sb2");
        Assert.NotNull(bg.Use("co1", "a", "sa2", "b", "sb2", "after rotation", true, T0));
        Assert.Equal(2, audit.Entries.Count(e => e.Kind == "break_glass_use")); // the DRILL is loud too
    }

    // DE-E-06: OIDC token forgery against the mock-backed client.
    [Fact]
    public void DE_E_06_Oidc_ForgedToken_Refused()
    {
        var idp = new MockIdp("https://idp.example.test");
        var client = new OidcClient(new OidcConfig("https://idp.example.test", "acp-client", "https://localhost/cb", true, true), idp);
        var verifier = Pkce.NewVerifier();
        var code = idp.BeginAuthorize("user-1", "a@b.test", true, Pkce.ChallengeS256(verifier), "nonce-1");
        var token = idp.ExchangeCode(code, verifier, "acp-client");
        // Attacker flips the subject in the payload without re-signing.
        var parts = token.Split('.');
        var forgedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"iss\":\"https://idp.example.test\",\"sub\":\"admin\",\"aud\":\"acp-client\",\"exp\":9999999999,\"nonce\":\"nonce-1\",\"email_verified\":true}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var forged = $"{parts[0]}.{forgedPayload}.{parts[2]}";
        Assert.False(client.CompleteSignIn(forged, "nonce-1", T0).Ok);
        // Code replay: the same code cannot be exchanged twice.
        Assert.Throws<InvalidOperationException>(() => idp.ExchangeCode(code, verifier, "acp-client"));
    }

    // DE-E-08: fleet-enrollment material extraction from the installer
    // package — the deployment script and schema must contain no
    // plaintext token, no private key, no reusable credential.
    [Fact]
    public void DE_E_08_InstallerPackage_ContainsNoExtractableSecretMaterial()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? enterpriseDir = null;
        while (dir is not null && enterpriseDir is null)
        {
            var candidate = Path.Combine(dir.FullName, "agent-control-app", "enterprise");
            if (Directory.Exists(candidate)) enterpriseDir = candidate;
            dir = dir.Parent;
        }
        Assert.NotNull(enterpriseDir);
        var script = File.ReadAllText(Path.Combine(enterpriseDir!, "Install-AcpEnterprise.ps1"));
        Assert.DoesNotContain("PRIVATE KEY", script);
        Assert.DoesNotContain("BEGIN RSA", script);
        Assert.DoesNotContain("hskey-api-", script); // no hub API key material
        Assert.DoesNotContain("Bearer ", script);    // no bearer token value
        // No credential ASSIGNMENT with a literal value (prose stating the
        // absence of passwords is the opposite of material; assignments are not).
        foreach (var line in script.Split('\n'))
        {
            var t = line.TrimStart();
            if (t.StartsWith("#")) continue;
            Assert.False(t.Contains("password =", StringComparison.OrdinalIgnoreCase) || t.Contains("secret =", StringComparison.OrdinalIgnoreCase),
                $"credential assignment found in installer script: {t}");
        }
        // The only secret-class input is a single-use code delivered by
        // file reference — the script names the property, never a value.
        Assert.Contains("-EnrollFile", script);
        Assert.Contains("single-use", script);
    }

    // DE-E-07: friction cannot be disabled by policy or configuration.
    [Fact]
    public void DE_E_07_ScamFriction_HasNoPolicyOffSwitch()
    {
        // ScamFriction.Evaluate takes no policy/config input at all — the
        // type's surface is the proof. A first-seen operator under ANY
        // signed policy bundle still gets full friction.
        var org = NewIdentity();
        var permissive = PolicyBundleService.Sign(Unsigned() with { ForbidAiPairings = false, DisableRecording = false }, org);
        Assert.NotNull(permissive);
        var d = ScamFriction.Evaluate("op-new", "Helper", new OperatorHistory(0, 0, 0, null, false), T0.AddDays(-30), T0, false);
        Assert.True(d.StartsViewOnly);
        Assert.True(d.WarningRequired);
    }
}

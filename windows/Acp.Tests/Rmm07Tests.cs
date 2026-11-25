using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-07 — Management-policy inheritance + Effective Policy view,
// and the TOTAL POLICY CONTROL contract (seeded toggle registry,
// IsEnabled query, §7.10 consent-floor refusal).
public class Rmm07Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static ManagementPolicyDocument Doc(string id, string level, string target,
        Dictionary<string, string> settings, long rev = 1) =>
        new(id, level, target, settings, rev);

    private static StaticDeviceFacts Device(string id = "dev1", string scope = "co1",
        string[]? groups = null, Dictionary<string, string>? attrs = null, string[]? software = null) =>
        StaticDeviceFacts.Of(id, scope, groups, attrs, software);

    [Fact]
    public void RMM07_Inheritance_ChildInherits_Overrides_AndProvenanceIsNamed()
    {
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddDocument(Doc("org-1", PolicyLevels.Org, "co1", new()
        {
            ["rmm.patch.enabled"] = "true",
            ["patch.ring"] = "fleet",
            ["backup.window"] = "02:00",
        })).Allowed);
        Assert.True(engine.AddDocument(Doc("grp-1", PolicyLevels.Group, "site-servers", new()
        {
            ["patch.ring"] = "pilot",
        })).Allowed);
        Assert.True(engine.AddDocument(Doc("dev-1", PolicyLevels.Device, "dev1", new()
        {
            ["backup.window"] = "03:30",
        })).Allowed);
        engine.AddGroup(new GroupDefinition("site-servers", "Site servers", Array.Empty<GroupRule>()));

        var eff = engine.ComputeEffective(Device(groups: new[] { "site-servers" }));
        // Inherited untouched from org.
        var inh = eff.Get("rmm.patch.enabled");
        Assert.NotNull(inh); Assert.Equal("true", inh!.Value);
        Assert.Equal(PolicyLevels.Org, inh.SourceLevel);
        Assert.Equal("org-1", inh.SourceDocumentId);
        // Group override wins over org, provenance names the group doc.
        var ring = eff.Get("patch.ring");
        Assert.Equal("pilot", ring!.Value);
        Assert.Equal(PolicyLevels.Group, ring.SourceLevel);
        Assert.Equal("grp-1", ring.SourceDocumentId);
        // Device override wins over all.
        var win = eff.Get("backup.window");
        Assert.Equal("03:30", win!.Value);
        Assert.Equal(PolicyLevels.Device, win.SourceLevel);
    }

    [Fact]
    public void RMM07_RevertToInherited_LetsTheInheritedValueShowThrough()
    {
        var engine = new ManagementPolicyEngine();
        engine.AddDocument(Doc("org-1", PolicyLevels.Org, "co1", new() { ["patch.ring"] = "fleet" }));
        engine.AddDocument(Doc("dev-1", PolicyLevels.Device, "dev1", new()
        {
            ["patch.ring"] = ManagementPolicyDocument.InheritMarker,
        }));
        var eff = engine.ComputeEffective(Device());
        var ring = eff.Get("patch.ring");
        Assert.Equal("fleet", ring!.Value);
        Assert.Equal(PolicyLevels.Org, ring.SourceLevel); // provenance reverts too
    }

    [Fact]
    public void RMM07_DynamicTargeting_AttributeAndSoftwareRules()
    {
        var engine = new ManagementPolicyEngine();
        engine.AddGroup(new GroupDefinition("acrobat-machines", "Has Acrobat", new[]
        {
            new GroupRule("software_installed", null, "Acrobat"),
        }));
        engine.AddGroup(new GroupDefinition("site-servers", "Site servers", new[]
        {
            new GroupRule("attribute_equals", "role", "site-server"),
        }));
        engine.AddGroup(new GroupDefinition("tagged-bas", "BAS tagged", new[]
        {
            new GroupRule("tag", null, "bas"),
        }));
        engine.AddDocument(Doc("g-acro", PolicyLevels.Group, "acrobat-machines", new() { ["rmm.metering.enabled"] = "true" }));
        engine.AddDocument(Doc("g-srv", PolicyLevels.Group, "site-servers", new() { ["backup.window"] = "01:00" }));
        engine.AddDocument(Doc("g-bas", PolicyLevels.Group, "tagged-bas", new() { ["rmm.monitoring.enabled"] = "true" }));

        var facts = Device(attrs: new Dictionary<string, string>
        {
            ["role"] = "site-server", ["tags"] = "office, bas",
        }, software: new[] { "Acrobat", "Niagara" });
        var eff = engine.ComputeEffective(facts);
        Assert.Contains("acrobat-machines", eff.MemberGroupIds);
        Assert.Contains("site-servers", eff.MemberGroupIds);
        Assert.Contains("tagged-bas", eff.MemberGroupIds);
        Assert.NotNull(eff.Get("backup.window"));
        Assert.NotNull(eff.Get("rmm.metering.enabled"));

        // A plain workstation matches none of them.
        var plain = engine.ComputeEffective(Device(id: "dev2", attrs: new Dictionary<string, string> { ["role"] = "workstation" }));
        Assert.Empty(plain.MemberGroupIds);
        Assert.Null(plain.Get("backup.window"));
    }

    [Fact]
    public void RMM07_UnknownRuleKind_MatchesNothing_FailClosed()
    {
        var engine = new ManagementPolicyEngine();
        engine.AddGroup(new GroupDefinition("weird", "Weird", new[]
        {
            new GroupRule("mind_reading", null, "yes"),
        }));
        var eff = engine.ComputeEffective(Device());
        Assert.Empty(eff.MemberGroupIds);
    }

    [Fact]
    public void RMM07_Registry_SeededWithAllBlockRToggles_AndRegisterDefaults()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.Equal(43, registry.All.Count); // RMM-01..32 + the RMM-11 camera extension + RMM-04's two sub-toggles + RMM-10's background-tools toggle (coordinator integrations, 2026-11-21) + RMM-23's browser-hardening toggle (RMM-23 D38 F9 fix lane, 2026-11-22 — count updated by the RMM-03/07 D38 recovery lane, whose harness run caught the stale 36) + U4's session-budget toggle (UNION BUILD lane U4, 2026-11-22 — count updated by the U4 lane, same precedent) + RMM-22's camera-share toggle rmm.camera_share.enabled (registered in FeatureToggleRegistry.Seeded by the RMM-22 lane; the accounting comment previously omitted it — annotated bump by Wave 2 Lane B, 2026-11-22, per the U4 precedent: the registry-growing change is legitimate product, the count follows it) + RMM-24's mobile-operator toggle rmm.mobile_operator.enabled (bd-shared-plat-2 F4 fix, Wave 4 Lane A, 2026-11-22 — the mobile operator client previously read the enrollment-PUSH key; its own toggle is legitimate product, annotated bump per the same precedent) + A2's Tor-provisioning toggle rmm.tor_provisioning.enabled and A3's AiPack-download toggle rmm.aipack_download.enabled (Wave 19 Lane C, 2026-11-23 — the two wiring-gap acts gained their TOTAL POLICY CONTROL toggles as they were wired into the production surface; annotated bump per the same precedent) + FR-120's takeover-modes toggle rmm.takeover_modes.enabled (Lane W73, 2026-11-23 — the tunable-takeover fleet-default layer's toggle, default ON; annotated bump per the same precedent)
        foreach (var d in new[]
        {
            "RMM-01", "RMM-02", "RMM-03", "RMM-04", "RMM-05", "RMM-06", "RMM-07", "RMM-08",
            "RMM-09", "RMM-10", "RMM-11", "RMM-12", "RMM-13", "RMM-14", "RMM-15", "RMM-16",
            "RMM-17", "RMM-18", "RMM-19", "RMM-20", "RMM-21", "RMM-22", "RMM-23", "RMM-24",
            "RMM-25", "RMM-26", "RMM-27", "RMM-28", "RMM-29", "RMM-30", "RMM-31", "RMM-32",
        })
            Assert.Contains(registry.All, t => t.Directive == d);
        // RMM-10 Backstage defaults OFF (its directive records the
        // presence tension and the OFF default explicitly).
        Assert.True(registry.TryGet("rmm.backstage.enabled", out var backstage));
        Assert.False(backstage!.DefaultEnabled);
        Assert.True(registry.TryGet("rmm.camera_viewing.enabled", out var cam));
        Assert.False(cam!.DefaultEnabled);
    }

    [Fact]
    public void RMM07_IsEnabled_RegistryDefault_PolicyOverride_UnknownKeyFailsClosed()
    {
        var engine = new ManagementPolicyEngine();
        var facts = Device();
        Assert.True(engine.IsEnabled(facts, "rmm.patch.enabled"));     // registry default on
        Assert.False(engine.IsEnabled(facts, "rmm.backstage.enabled")); // registry default off
        Assert.False(engine.IsEnabled(facts, "rmm.no_such_feature.enabled")); // unknown → false
        engine.AddDocument(Doc("org-1", PolicyLevels.Org, "co1", new()
        {
            ["rmm.patch.enabled"] = "false",
            ["rmm.backstage.enabled"] = "true",
        }));
        Assert.False(engine.IsEnabled(facts, "rmm.patch.enabled"));   // policy overrides default
        Assert.True(engine.IsEnabled(facts, "rmm.backstage.enabled")); // org may enable Backstage by policy
        // Device-level re-enable of patching wins for this device only.
        engine.AddDocument(Doc("dev-1", PolicyLevels.Device, "dev1", new() { ["rmm.patch.enabled"] = "true" }));
        Assert.True(engine.IsEnabled(facts, "rmm.patch.enabled"));
        Assert.False(engine.IsEnabled(Device(id: "dev2"), "rmm.patch.enabled"));
        // An unparsable toggle value never enables.
        engine.AddDocument(Doc("dev-2", PolicyLevels.Device, "dev2", new() { ["rmm.patch.enabled"] = "maybe" }));
        Assert.False(engine.IsEnabled(Device(id: "dev2"), "rmm.patch.enabled"));
    }

    [Fact]
    public void RMM07_ConsentFloorKeys_RefusedAtDocumentAndRegistry()
    {
        var engine = new ManagementPolicyEngine();
        foreach (var key in new[]
        {
            "presence.enabled", "stop.enabled", "audit.enabled", "consent.floor",
            "rmm.presence.enabled", "presence", "audit.deletable",
        })
        {
            var verdict = engine.AddDocument(Doc($"bad-{key}", PolicyLevels.Org, "co1",
                new Dictionary<string, string> { [key] = "false" }));
            Assert.False(verdict.Allowed, $"key '{key}' must refuse");
            Assert.Contains("consent floor", verdict.Reason);
        }
        Assert.Throws<InvalidOperationException>(() =>
            new FeatureToggleRegistry().Register(new FeatureToggle("presence.enabled", "X", true, "smuggled")));
        // And IsEnabled can never answer true for a floor key.
        Assert.False(engine.IsEnabled(Device(), "presence.enabled"));
        Assert.False(engine.IsEnabled(Device(), "stop.enabled"));
    }

    [Fact]
    public void RMM07_StaleAndConflictingRevisions_Refuse()
    {
        var engine = new ManagementPolicyEngine();
        var v1 = Doc("doc", PolicyLevels.Org, "co1", new() { ["a"] = "1" }, rev: 2);
        Assert.True(engine.AddDocument(v1).Allowed);
        Assert.True(engine.AddDocument(v1).Allowed); // idempotent re-delivery
        var stale = Doc("doc", PolicyLevels.Org, "co1", new() { ["a"] = "0" }, rev: 1);
        Assert.False(engine.AddDocument(stale).Allowed);
        var conflict = Doc("doc", PolicyLevels.Org, "co1", new() { ["a"] = "2" }, rev: 2);
        var cv = engine.AddDocument(conflict);
        Assert.False(cv.Allowed);
        Assert.Contains("conflicts", cv.Reason);
        var newer = Doc("doc", PolicyLevels.Org, "co1", new() { ["a"] = "3" }, rev: 3);
        Assert.True(engine.AddDocument(newer).Allowed);
        Assert.Equal("3", engine.ComputeEffective(Device()).Get("a")!.Value);
    }

    [Fact]
    public void RMM07_SignedDelivery_VerifiedBeforeApplication_RefusalsAudited()
    {
        var audit = new ChainedAuditLog();
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var service = new ManagementPolicyService(audit, gate, now: () => T0);
        var signer = new SignedCommandSigner(customer);

        var doc = Doc("org-1", PolicyLevels.Org, "co1", new() { ["rmm.patch.enabled"] = "false" });
        var env = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(doc.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = service.ApplySignedDocument(env);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.False(service.IsEnabled(Device(), "rmm.patch.enabled"));
        Assert.Contains(audit.Entries, e => e.Kind == "policy_applied");

        // Tampered payload: the envelope no longer verifies; nothing applies.
        var tampered = env with
        {
            PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                Doc("org-2", PolicyLevels.Org, "co1", new() { ["rmm.patch.enabled"] = "true" }, rev: 9).ToCanonicalJson())),
        };
        Assert.False(service.ApplySignedDocument(tampered).Allowed);
        // Unsigned delivery: refused.
        Assert.False(service.ApplySignedDocument(null).Allowed);
        Assert.Contains(audit.Entries, e => e.Kind == "signed_command_refused");
        Assert.True(audit.Verify().Ok);
    }

    [Fact]
    public void RMM07_SignedDelivery_ConsentFloorDocument_RefusedEvenWithValidSignature()
    {
        // A VALIDLY SIGNED document that smuggles a consent-floor key
        // still refuses: the signature proves origin, not permission
        // to move the floor.
        var audit = new ChainedAuditLog();
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var service = new ManagementPolicyService(audit, gate, now: () => T0);
        var signer = new SignedCommandSigner(customer);
        var evil = Doc("evil", PolicyLevels.Org, "co1", new() { ["presence.enabled"] = "false" });
        var env = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(evil.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = service.ApplySignedDocument(env);
        Assert.False(verdict.Allowed);
        Assert.Contains("consent floor", verdict.Reason);
        Assert.Contains(audit.Entries, e => e.Kind == "policy_refusal");
        Assert.Empty(service.Engine.Documents);
    }

    [Fact]
    public void RMM07_NoGateConfigured_SignedDeliveryRefuses_Named()
    {
        var audit = new ChainedAuditLog();
        var service = new ManagementPolicyService(audit, gate: null, now: () => T0);
        var verdict = service.ApplySignedDocument(null);
        Assert.False(verdict.Allowed);
        Assert.Contains("no customer command key", verdict.Reason);
    }

    [Fact]
    public void RMM07_EnterpriseBundle_BridgesIntoEngine_AsOrgDocument()
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var unsigned = new PolicyBundle(
            Version: 2, ScopeId: "co1", TransportCeiling: new[] { "lan", "hub" }, TransportMode: "auto",
            PinnedVersion: "1.2.3", UpdateDeferUntil: null, ForbidAiPairings: true, DisableRecording: false,
            UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "",
            DisabledFeatures: new[] { PolicyFeatures.WakeOnLan }, RequiredFeatures: new[] { PolicyFeatures.Watermark });
        var bundle = PolicyBundleService.Sign(unsigned, org);
        // The bundle itself still verifies under the existing machinery.
        Assert.True(new PolicyBundleService().Verify(bundle, org.PublicKey, T0).Allowed);

        var doc = EnterpriseBundleBridge.FromBundle(bundle);
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddDocument(doc).Allowed);
        var eff = engine.ComputeEffective(Device());
        Assert.Equal("lan,hub", eff.Get("transport.ceiling")!.Value);
        Assert.Equal(PolicyLevels.Org, eff.Get("transport.ceiling")!.SourceLevel);
        Assert.Equal("1.2.3", eff.Get("update.pinned_version")!.Value);
        Assert.Equal("true", eff.Get("enterprise.forbid_ai_pairings")!.Value);
        Assert.Equal("false", eff.Get($"feature.{PolicyFeatures.WakeOnLan}")!.Value);
        Assert.Equal("true", eff.Get($"feature.{PolicyFeatures.Watermark}.required")!.Value);
    }

    [Fact]
    public void RMM07_DocumentsForOtherScopesAndDevices_DoNotLeak()
    {
        var engine = new ManagementPolicyEngine();
        engine.AddDocument(Doc("org-other", PolicyLevels.Org, "other-co", new() { ["x"] = "other" }));
        engine.AddDocument(Doc("dev-other", PolicyLevels.Device, "dev99", new() { ["y"] = "other" }));
        var eff = engine.ComputeEffective(Device());
        Assert.Null(eff.Get("x"));
        Assert.Null(eff.Get("y"));
        // A wildcard org document DOES apply everywhere.
        engine.AddDocument(Doc("org-all", PolicyLevels.Org, "*", new() { ["z"] = "all" }));
        Assert.Equal("all", engine.ComputeEffective(Device()).Get("z")!.Value);
    }
}

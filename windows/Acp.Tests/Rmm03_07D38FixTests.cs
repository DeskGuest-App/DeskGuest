using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

// D38 cross-review of packet 8b8cd115 (RMM-03/RMM-07 foundation) —
// FAIL with 12 findings. This file is the fix lane's regression
// battery: one or more tests per CONFIRMED finding, each named for
// the finding it pins. Verdicts per finding live in
// builds/rmm-r-logs/log-rmm03-07-fix.md.
public class Rmm03_07D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());
    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    private static StaticDeviceFacts Facts(string id = "dev1", string scope = "co1",
        IDictionary<string, string>? attrs = null) =>
        StaticDeviceFacts.Of(id, scope, attributes: attrs);

    private static ManagementPolicyDocument Doc(string id, string level, string target,
        Dictionary<string, string> settings, long rev = 1) =>
        new(id, level, target, settings, rev);

    private static ToolExecutionContext Ctx() =>
        new(TestUtil.BarePairing(Scopes.All), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement ArgsJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static byte[] TinyZipBytes()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("payload.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("update payload");
        }
        return ms.ToArray();
    }

    // ---- F1: audience binding ------------------------------------

    [Fact]
    public void F1_EnvelopeMintedForDeviceA_RefusedOnDeviceB_AcceptedOnA()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var signer = new SignedCommandSigner(customer);
        var env = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"),
            T0, TimeSpan.FromMinutes(5), audience: "device-A");

        var onB = new SignedCommandVerifier(ring, (IReplayGuard?)null, expectedAudience: "device-B");
        var refused = onB.Verify(env, T0.AddMinutes(1));
        Assert.False(refused.Allowed);
        Assert.Contains("audience", refused.Reason);
        Assert.Contains("device-A", refused.Reason);

        var onA = new SignedCommandVerifier(ring, (IReplayGuard?)null, expectedAudience: "device-A");
        Assert.True(onA.Verify(env, T0.AddMinutes(1)).Allowed);
    }

    [Fact]
    public void F1_FleetWideEnvelope_RefusedWhereEndpointExpectsItsOwnId()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var signer = new SignedCommandSigner(customer);
        // No audience: the pre-F1 shape — one envelope for the fleet.
        var env = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"), T0, TimeSpan.FromMinutes(5));
        var endpoint = new SignedCommandVerifier(ring, (IReplayGuard?)null, expectedAudience: "device-A");
        var verdict = endpoint.Verify(env, T0.AddMinutes(1));
        Assert.False(verdict.Allowed);
        Assert.Contains("fleet-wide", verdict.Reason);
    }

    [Fact]
    public void F1_AudienceIsSigned_RetargetingBreaksTheSignature()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var signer = new SignedCommandSigner(customer);
        var env = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo hi"),
            T0, TimeSpan.FromMinutes(5), audience: "device-A");
        // A compromised hub rewrites the audience to device-B:
        var retargeted = env with { Audience = "device-B" };
        var onB = new SignedCommandVerifier(ring, (IReplayGuard?)null, expectedAudience: "device-B");
        var verdict = onB.Verify(retargeted, T0.AddMinutes(1));
        Assert.False(verdict.Allowed);
        Assert.Contains("signature", verdict.Reason);
    }

    // ---- F3: group definitions -----------------------------------

    [Fact]
    public void F3_GroupRedefinition_Refused_OriginalDefinitionStands()
    {
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.AddGroup(new GroupDefinition("narrow", "Narrow",
            new[] { new GroupRule("attribute_equals", "role", "server") })).Allowed);
        // Redefine the same id to match everything:
        var widen = engine.AddGroup(new GroupDefinition("narrow", "Narrow",
            new[] { new GroupRule("attribute_equals", "role", "workstation") }));
        Assert.False(widen.Allowed);
        Assert.Contains("cannot be redefined", widen.Reason);
        // The original definition still governs membership:
        Assert.Contains("narrow", engine.MemberGroupIds(Facts(attrs: new Dictionary<string, string> { ["role"] = "server" })));
        Assert.DoesNotContain("narrow", engine.MemberGroupIds(Facts(attrs: new Dictionary<string, string> { ["role"] = "workstation" })));
        // Identical re-add is idempotent, not a refusal:
        Assert.True(engine.AddGroup(new GroupDefinition("narrow", "Narrow",
            new[] { new GroupRule("attribute_equals", "role", "server") })).Allowed);
    }

    [Fact]
    public void F3_AttributeContainsEmptyValue_RefusedAtAdmission_AndMatchesNothing()
    {
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddGroup(new GroupDefinition("sneaky", "Sneaky",
            new[] { new GroupRule("attribute_contains", "role", "") }));
        Assert.False(verdict.Allowed);
        // And even a rule object evaluated directly matches nothing:
        var rule = new GroupRule("attribute_contains", "role", "");
        Assert.False(rule.Matches(Facts(attrs: new Dictionary<string, string> { ["role"] = "server" })));
        var wsRule = new GroupRule("attribute_contains", "role", "   ");
        Assert.False(wsRule.Matches(Facts(attrs: new Dictionary<string, string> { ["role"] = "server" })));
    }

    [Fact]
    public void F3_ServiceAddGroup_RefusalsAreAudited()
    {
        var audit = new ChainedAuditLog();
        var service = new ManagementPolicyService(audit, gate: null, now: () => T0);
        Assert.True(service.AddGroup(new GroupDefinition("g1", "G1", Array.Empty<GroupRule>())).Allowed);
        var refused = service.AddGroup(new GroupDefinition("g1", "G1",
            new[] { new GroupRule("attribute_equals", "role", "server") }));
        Assert.False(refused.Allowed);
        Assert.Contains(audit.Entries, e => e.Kind == "policy_changed");
        Assert.Contains(audit.Entries, e => e.Kind == "policy_refusal");
        Assert.True(audit.Verify().Ok);
    }

    // ---- F4: consent-floor disguises ------------------------------

    [Theory]
    [InlineData("rmm.kill_switch")]
    [InlineData("rmm.audit_chain")]
    [InlineData("rmm.stop_button")]
    [InlineData("rmm.presence_indicator")]
    [InlineData("rmm-presence-enabled")]
    [InlineData("rmm/stop")]
    [InlineData("rmm_presence_enabled")]
    [InlineData("rmm. stop.enabled")]
    [InlineData("pres\u200Bence.enabled")]
    [InlineData("kill_switch")]
    [InlineData("audit_chain.enabled")]
    public void F4_DisguisedFloorKeys_AreDenied(string key)
    {
        Assert.True(ConsentFloorGuard.IsDenied(key), $"key '{key}' must be denied");
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddDocument(Doc($"d-{key}", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { [key] = "true" }));
        Assert.False(verdict.Allowed, $"document carrying '{key}' must refuse");
        Assert.False(engine.IsEnabled(Facts(), key));
    }

    [Fact]
    public void F4_LegitimateKeys_AreNotDenied()
    {
        foreach (var key in new[]
        {
            "rmm.patch.enabled", "rmm.signed_commands.enabled", "rmm.camera_viewing.enabled",
            "rmm.inventory.warrantyLookup.enabled", "transport.ceiling", "update.pinned_version",
        })
            Assert.False(ConsentFloorGuard.IsDenied(key), $"key '{key}' must NOT be denied");
        // The seeded registry still builds (Register runs the guard).
        // 40 = the 36 of the original RMM-07 count + RMM-23's
        // browser-hardening toggle (RMM-23 D38 F9 fix lane) + U4's
        // session-budget toggle (UNION BUILD lane U4, 2026-11-22)
        // + U1's clipboard-policy toggle + RMM-22's camera-share
        // toggle rmm.camera_share.enabled (the last two were omitted
        // from this comment's accounting — annotated bump by Wave 2
        // Lane B, 2026-11-22, same U4 precedent as Rmm07Tests)
        // + RMM-24's mobile-operator toggle rmm.mobile_operator.enabled
        // (bd-shared-plat-2 F4 fix, Wave 4 Lane A, 2026-11-22)
        // + A2/A3 toggles rmm.tor_provisioning.enabled /
        // rmm.aipack_download.enabled (Wave 19 Lane C, 2026-11-23 —
        // annotated bump per the same precedent)
        // + FR-120's takeover-modes toggle rmm.takeover_modes.enabled
        // (Lane W73, 2026-11-23 — the tunable-takeover fleet-default
        // layer's TOTAL POLICY CONTROL toggle; annotated bump per
        // the same precedent).
        Assert.Equal(43, FeatureToggleRegistry.Seeded().All.Count);
    }

    // ---- F5: nonce store crash consistency ------------------------

    [Fact]
    public void F5_CrashBetweenStoreAndAnchorWrites_Recovers_NotBroken()
    {
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env1 = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo 1"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env1, T0.AddMinutes(1)));
        var anchorAfterFirst = File.ReadAllText(path + ".anchor");
        var env2 = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo 2"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env2, T0.AddMinutes(2)));
        // Simulate the crash: the store file is the NEW generation,
        // the anchor is still the OLD one.
        File.WriteAllText(path + ".anchor", anchorAfterFirst);
        var reloaded = new PersistedNonceStore(path);
        Assert.False(reloaded.IsBroken);
        Assert.Contains("recovered", reloaded.State);
        Assert.Equal(2, reloaded.TrackedCount); // both nonces survived
        // The recovered store still refuses replays of both:
        Assert.False(reloaded.TryRegister(env1, T0.AddMinutes(3)));
        Assert.False(reloaded.TryRegister(env2, T0.AddMinutes(3)));
        // And the anchor was repaired: a third load is a clean load.
        var third = new PersistedNonceStore(path);
        Assert.False(third.IsBroken);
        Assert.Contains("loaded", third.State);
    }

    [Fact]
    public void F5_RolledBackStore_BehindAnchor_IsBroken()
    {
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env1 = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo 1"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env1, T0.AddMinutes(1)));
        var oldStoreBytes = File.ReadAllText(path); // generation 1 snapshot
        var env2 = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo 2"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env2, T0.AddMinutes(2))); // generation 2 + anchor 2
        // Rollback: the OLD store file returns next to the NEW anchor.
        File.WriteAllText(path, oldStoreBytes);
        var reloaded = new PersistedNonceStore(path);
        Assert.True(reloaded.IsBroken);
        Assert.Contains("anchor", reloaded.State);
    }

    [Fact]
    public void F5_HandEditedStore_FailsInternalChecksum_Broken()
    {
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env1 = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo 1"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env1, T0.AddMinutes(1)));
        // Hand-edit: corrupt the nonce inside the file, then
        // refresh the anchor to match the edited file (same
        // generation, recomputed hash) — so ONLY the store's
        // internal checksum stands in the way:
        var raw = File.ReadAllText(path);
        var edited = raw.Replace(env1.Nonce, new string('0', env1.Nonce.Length));
        File.WriteAllText(path, edited);
        var anchor = File.ReadAllText(path + ".anchor").Trim();
        var gen = anchor.Split(':')[0];
        var editedHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(edited + "|1"))).ToLowerInvariant();
        File.WriteAllText(path + ".anchor", $"{gen}:{editedHash}");
        var reloaded = new PersistedNonceStore(path);
        Assert.True(reloaded.IsBroken);
        Assert.Contains("checksum", reloaded.State);
    }

    // ---- F6: key ring rotation discipline --------------------------

    [Fact]
    public void F6_AddCurrentTwice_SupersededKeyRetiresBounded_NotForever()
    {
        var k1 = NewIdentity(); var k2 = NewIdentity(); var k3 = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(k1.PublicKey);
        ring.AddCurrent(k2.PublicKey); // supersedes K1 without an explicit Rotate
        var k1Entry = ring.Keys.Single(k => k.KeyId == CustomerCommandKeyRing.KeyIdFor(k1.PublicKey));
        Assert.NotNull(k1Entry.RetiredUntilUtc); // bounded, not indefinite
        Assert.True(k1Entry.RetiredUntilUtc!.Value <= DateTimeOffset.UtcNow + CustomerCommandKeyRing.SupersededKeyGrace + TimeSpan.FromMinutes(1));
        Assert.Equal(CustomerCommandKeyRing.KeyIdFor(k2.PublicKey), ring.CurrentKeyId);
        // Rotate retires K2 as well; exactly one non-retired key remains:
        ring.Rotate(k3.PublicKey, T0, TimeSpan.FromHours(1));
        var live = ring.Keys.Where(k => k.RetiredUntilUtc is null).ToList();
        Assert.Single(live);
        Assert.Equal(CustomerCommandKeyRing.KeyIdFor(k3.PublicKey), live[0].KeyId);
    }

    [Fact]
    public void F6_RetiredKey_CannotBeResurrected()
    {
        var k1 = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddRetired(k1.PublicKey, T0.AddHours(1));
        Assert.Throws<InvalidOperationException>(() => ring.AddCurrent(k1.PublicKey));
        Assert.Throws<InvalidOperationException>(() => ring.Rotate(k1.PublicKey, T0, TimeSpan.FromHours(1)));
        // Re-adding as retired with a LATER deadline keeps the earlier one:
        ring.AddRetired(k1.PublicKey, T0.AddHours(9));
        var entry = ring.Keys.Single();
        Assert.Equal(T0.AddHours(1), entry.RetiredUntilUtc);
    }

    // ---- F7: envelope lifetime bound -------------------------------

    [Fact]
    public void F7_SignerRefusesExcessiveTtl_VerifierRefusesLongLivedEnvelope()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var signer = new SignedCommandSigner(customer);
        Assert.Throws<ArgumentException>(() =>
            signer.Sign(SignedCommandClasses.ShellExec, Bytes("x"), T0, TimeSpan.FromDays(7)));
        // A long-lived envelope crafted by hand (bypassing the
        // signer) still refuses at verify:
        var unsigned = new SignedCommandEnvelope(1, SignedCommandClasses.ShellExec, signer.KeyId,
            T0, T0.AddDays(7), "abc123", SignedCommandEnvelope.HashPayload(Bytes("x")),
            Convert.ToBase64String(Bytes("x")), "");
        var sig = customer.Sign(Encoding.UTF8.GetBytes(SignedCommandEnvelope.CanonicalBody(unsigned)));
        var env = unsigned with { SignatureBase64 = Convert.ToBase64String(sig) };
        var verdict = new SignedCommandVerifier(ring).Verify(env, T0.AddMinutes(1));
        Assert.False(verdict.Allowed);
        Assert.Contains("lifetime", verdict.Reason);
    }

    // ---- F8: stage_signed metadata --------------------------------

    [Fact]
    public async Task F8_StageSigned_RawPackagePayload_Refused_VersionMustBeSigned()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var audit = new ChainedAuditLog();
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var signer = new SignedCommandSigner(customer);
        using var rsa = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(TestUtil.TempDir(), rsa, _ => Task.FromResult(true));
        var module = new AgentUpdateModule(updates, gate);
        var pkg = TinyZipBytes();
        // Envelope over the RAW package (the pre-F8 shape) with the
        // version riding as an unsigned argument:
        var env = signer.Sign(SignedCommandClasses.UpdateStaging, pkg, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));
        var args = JsonSerializer.Serialize(new
        {
            action = "stage_signed", signed_command = env.ToJson(),
            signature_base64 = Convert.ToBase64String(rsa.Sign(pkg)), version = "9.9.9",
        });
        var result = await module.ExecuteAsync(ArgsJson(args), Ctx(), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Null(updates.Status().StagedVersion);
    }

    [Fact]
    public async Task F8_LegacyStage_ClosedWhenGateWired_OpenWhenNot()
    {
        using var rsa = new RsaUpdateSignatureVerifier();
        var pkg = TinyZipBytes();
        var args = JsonSerializer.Serialize(new
        {
            action = "stage",
            package_base64 = Convert.ToBase64String(pkg),
            signature_base64 = Convert.ToBase64String(rsa.Sign(pkg)),
            version = "1.0.0",
        });
        // No gate: the pre-RMM-03 posture still works.
        var bareUpdates = new UpdateManager(TestUtil.TempDir(), rsa, _ => Task.FromResult(true));
        var bare = new AgentUpdateModule(bareUpdates);
        var okResult = await bare.ExecuteAsync(ArgsJson(args), Ctx(), CancellationToken.None);
        Assert.True(okResult.Ok, okResult.Text);
        // Gate wired: legacy stage refuses by name.
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), new ChainedAuditLog());
        var gatedUpdates = new UpdateManager(TestUtil.TempDir(), rsa, _ => Task.FromResult(true));
        var gated = new AgentUpdateModule(gatedUpdates, gate);
        var refused = await gated.ExecuteAsync(ArgsJson(args), Ctx(), CancellationToken.None);
        Assert.False(refused.Ok);
        Assert.Equal("signed_command_refused", refused.ErrorClass);
        Assert.Null(gatedUpdates.Status().StagedVersion);
    }

    // ---- F9: bundle bridge provenance ------------------------------

    private static PolicyBundle Bundle(int version, string scope = "co1") =>
        PolicyBundleService.Sign(new PolicyBundle(
            Version: version, ScopeId: scope, TransportCeiling: new[] { "lan" }, TransportMode: "auto",
            PinnedVersion: null, UpdateDeferUntil: null, ForbidAiPairings: false, DisableRecording: false,
            UnattendedTier: "business_hours", IssuedUtc: T0, ExpiresUtc: T0.AddDays(30), SignatureBase64: "",
            DisabledFeatures: Array.Empty<string>(), RequiredFeatures: Array.Empty<string>()),
            NewIdentity());

    [Fact]
    public void F9_BundleVersions_ShareOneDocumentId_StaleBundleRefuses()
    {
        var engine = new ManagementPolicyEngine();
        var v9 = EnterpriseBundleBridge.FromBundle(Bundle(9));
        var v10 = EnterpriseBundleBridge.FromBundle(Bundle(10));
        Assert.Equal(v9.Id, v10.Id); // stable id; version is the revision
        Assert.True(engine.AddDocument(v9).Allowed);
        Assert.True(engine.AddDocument(v10).Allowed);
        // The stale v9 re-delivered after v10 refuses — it cannot
        // coexist and win on an ordinal id sort:
        var stale = engine.AddDocument(EnterpriseBundleBridge.FromBundle(Bundle(9)));
        Assert.False(stale.Allowed);
        Assert.Contains("stale", stale.Reason);
        Assert.Single(engine.Documents);
    }

    [Fact]
    public void F9_HigherRevisionWins_EvenWhenDocumentIdsSortBackwards()
    {
        var engine = new ManagementPolicyEngine();
        // 'aaa' r1 vs 'zzz' r2 for the same target: revision order
        // is applied after id order within the target, so r2 wins.
        Assert.True(engine.AddDocument(Doc("zzz", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["k"] = "new" }, rev: 2)).Allowed);
        Assert.True(engine.AddDocument(Doc("aaa", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["k"] = "old" }, rev: 1)).Allowed);
        Assert.Equal("new", engine.ComputeEffective(Facts()).Get("k")!.Value);
    }

    // ---- F10: policy durability -------------------------------------

    [Fact]
    public void F10_PolicySurvivesRestart_RevisionFloorToo()
    {
        var path = Path.Combine(TestUtil.TempDir(), "policy.json");
        var audit = new ChainedAuditLog();
        var s1 = new ManagementPolicyService(audit, gate: null, now: () => T0, storePath: path);
        Assert.True(s1.AdmitLocalDocument(Doc("org-1", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["rmm.patch.enabled"] = "false" }, rev: 3), "test").Allowed);
        Assert.True(s1.AddGroup(new GroupDefinition("servers", "Servers", Array.Empty<GroupRule>())).Allowed);

        // RESTART: a brand-new service over the same store file.
        var s2 = new ManagementPolicyService(new ChainedAuditLog(), gate: null, now: () => T0, storePath: path);
        Assert.Contains("loaded", s2.PolicyStoreState);
        Assert.False(s2.IsEnabled(Facts(), "rmm.patch.enabled")); // the signed policy still applies
        Assert.Single(s2.Engine.Groups);
        // The revision floor survived: a stale re-delivery refuses.
        var stale = s2.AdmitLocalDocument(Doc("org-1", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { ["rmm.patch.enabled"] = "true" }, rev: 2), "test");
        Assert.False(stale.Allowed);
        Assert.Contains("stale", stale.Reason);
    }

    [Fact]
    public void F10_CorruptPolicyStore_IsNamedBroken_NeverSilent()
    {
        var path = Path.Combine(TestUtil.TempDir(), "policy.json");
        File.WriteAllText(path, "{ not a policy store");
        var audit = new ChainedAuditLog();
        var service = new ManagementPolicyService(audit, gate: null, now: () => T0, storePath: path);
        Assert.Contains("BROKEN", service.PolicyStoreState);
        Assert.Contains(audit.Entries, e => e.Kind == "policy_store_broken");
    }

    // ---- F11: persisted nonce store coverage ------------------------

    [Fact]
    public void F11_V1ShapeStore_StillLoads()
    {
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        // v1 on-disk shape: a bare list of nonces, no anchor.
        var v1 = JsonSerializer.Serialize(new[]
        {
            new PersistedNonce("cust-x", "nonce-1", T0.AddHours(1)),
        });
        File.WriteAllText(path, v1);
        var store = new PersistedNonceStore(path);
        Assert.False(store.IsBroken);
        Assert.Equal(1, store.TrackedCount);
    }

    [Fact]
    public void F11_MissingStoreWithSurvivingAnchor_IsBroken_StoreLost()
    {
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env, T0.AddMinutes(1)));
        File.Delete(path); // store deleted, anchor survives
        var reloaded = new PersistedNonceStore(path);
        Assert.True(reloaded.IsBroken);
        Assert.Contains("store_lost", reloaded.State);
        Assert.False(reloaded.TryRegister(env, T0.AddMinutes(2)));
    }

    [Fact]
    public void F11_FlushFailure_RollsBackRegistration_AndBreaksStore()
    {
        // The store path sits under a path component that is a
        // FILE, so the flush's directory creation must fail:
        // TryRegister returns false, the in-memory registration is
        // rolled back, and the store goes BROKEN (fail closed)
        // rather than pretending the nonce is durable.
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var dir = TestUtil.TempDir();
        var blocker = Path.Combine(dir, "blocker");
        File.WriteAllText(blocker, "not a directory");
        var path = Path.Combine(blocker, "nonces.json");
        var store = new PersistedNonceStore(path);
        Assert.False(store.IsBroken); // fresh: nothing on disk yet
        var env = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo"), T0, TimeSpan.FromMinutes(30));
        Assert.False(store.TryRegister(env, T0.AddMinutes(1)));
        Assert.True(store.IsBroken);
        Assert.Contains("BROKEN", store.State);
        Assert.Equal(0, store.TrackedCount); // rolled back, not half-registered
    }

    [Fact]
    public void F11_ClockFloor_FutureFloorRefusesEarlierEnvelopes_UntilTimeCatchesUp()
    {
        // The floor side effect, pinned as DOCUMENTED behaviour:
        // an envelope accepted while the wall clock is wrongly
        // AHEAD moves the persisted floor into the future; later
        // envelopes expiring before the floor refuse until real
        // time catches up. That is the deliberate trade (the floor
        // is what stops clock-rollback replay) — this test pins it
        // so the behaviour is evidence, not a surprise.
        var customer = NewIdentity();
        var signer = new SignedCommandSigner(customer);
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var ahead = T0.AddHours(3); // wall clock glitched 3h ahead
        var futureEnv = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo future"), ahead, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(futureEnv, ahead.AddMinutes(1)));
        // Clock corrected back to T0: a normal envelope expiring at
        // T0+30m is BEFORE the persisted floor (T0+3h01m) and refuses:
        var normal = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo normal"), T0, TimeSpan.FromMinutes(30));
        Assert.False(store.TryRegister(normal, T0.AddMinutes(1)));
        // Once real time passes the floor, registrations work again:
        var later = signer.Sign(SignedCommandClasses.ShellExec, Bytes("echo later"), ahead.AddHours(1), TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(later, ahead.AddHours(1).AddMinutes(1)));
    }
}

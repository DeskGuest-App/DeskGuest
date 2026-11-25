using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.Input;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;
using Acp.Shared.Vulnerability;
using Xunit;

namespace Acp.Tests;

/// <summary>
/// Wave 11 Lane A (Windows buildable register) — regression pins
/// for R-15 (BackupService host wiring), R-22 (vulnerability feed
/// signing), R-21 (real OIDC: discovery / JWKS / RS256), R-32
/// (held-input startup sweep coverage) and the multi-target
/// routing the R-15 wiring requires. Every test drives the REAL
/// classes (no rig-local reimplementation of the thing under
/// test); the OIDC leg runs against an RSA key + JWKS crafted in
/// the test, fetched through the client's injectable HTTP seam.
/// </summary>
public sealed class W11WinBuildTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    private static string TempDir(string name)
    {
        var dir = Path.Combine(Path.GetTempPath(), "acp-w11", name + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    // ================= R-15: backup host wiring =================

    private static Dictionary<string, string> LocalPolicy(string targetDir, string selection) => new()
    {
        ["backup.targets"] = "tgt1",
        ["backup.target.tgt1.kind"] = "local",
        ["backup.target.tgt1.locator"] = targetDir,
        ["backup.jobs"] = "job1",
        ["backup.job.job1.device"] = "dev1",
        ["backup.job.job1.owner"] = "alice",
        ["backup.job.job1.kind"] = "file",
        ["backup.job.job1.selection"] = selection,
        ["backup.job.job1.target"] = "tgt1",
        ["backup.job.job1.interval_hours"] = "24",
        ["backup.job.job1.retention_days"] = "7",
    };

    private static (BackupService Service, BackupHostWiring.WiringReport Report, string DataDir) WireUp(
        Dictionary<string, string> settings, string rootName)
    {
        var dataDir = TempDir(rootName);
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", settings, 1)).Allowed);
        var audit = new ChainedAuditLog();
        var (service, report) = BackupHostWiring.Build(
            audit, policy, id => StaticDeviceFacts.Of(id, "scope1"),
            StaticDeviceFacts.Of("dev1", "scope1"),
            dataDir, new DevOnlyPassThroughProtector(), gate: null);
        return (service, report, dataDir);
    }

    [Fact]
    public void R15_Wiring_RunsRealBackup_SealedAtRest_KeyAndCataloguePersisted()
    {
        var srcDir = TempDir("src");
        var fileA = Path.Combine(srcDir, "a.txt");
        File.WriteAllText(fileA, "alpha-content");
        var targetDir = TempDir("target");
        var (service, report, dataDir) = WireUp(LocalPolicy(targetDir, fileA), "data");

        Assert.Single(report.Wired);
        Assert.Empty(report.Refused);
        Assert.Equal(new[] { "tgt1" }, service.WiredTargetIds);

        var outcomes = service.RunDueJobs("dev1", envelope: null);
        var outcome = Assert.Single(outcomes);
        Assert.True(outcome.Ok, outcome.Outcome);

        // The bytes at the target are SEALED (ACPENCW1 magic),
        // never the plaintext content.
        var stored = Directory.EnumerateFiles(targetDir, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".tmp")).ToList();
        Assert.NotEmpty(stored);
        foreach (var f in stored)
        {
            var bytes = File.ReadAllBytes(f);
            Assert.True(BackupAtRest.IsSealed(bytes), $"stored blob {f} is not sealed");
            Assert.DoesNotContain("alpha-content", Encoding.UTF8.GetString(bytes));
        }
        // The key file lives in the CORE data dir — never at the target.
        Assert.True(File.Exists(Path.Combine(dataDir, "backup-keys", "tgt1.key")));
        Assert.False(File.Exists(Path.Combine(targetDir, "tgt1.key")));
        // The catalogue persisted via the service's dirty hook.
        Assert.True(File.Exists(Path.Combine(dataDir, "backup-catalogues", "tgt1.json")));

        // A fresh wiring over the same dirs reloads the catalogue:
        // the snapshot survives a Core restart and restores.
        var (service2, report2, _) = WireUp(LocalPolicy(targetDir, fileA), "data2-unused");
        // NOTE: service2 was built over a DIFFERENT data dir (fresh
        // keys) — its store must refuse the sealed blobs by key,
        // which is the at-rest discipline working, not a bug. The
        // honest restart proof reuses the SAME data dir:
        Assert.Single(report2.Wired);
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", LocalPolicy(targetDir, fileA), 1)).Allowed);
        var (restarted, _) = BackupHostWiring.Build(
            new ChainedAuditLog(), policy, id => StaticDeviceFacts.Of(id, "scope1"),
            StaticDeviceFacts.Of("dev1", "scope1"), dataDir, new DevOnlyPassThroughProtector(), gate: null);
        Assert.Equal(1, restarted.Usage().SealedSnapshots);
        var restoreTarget = new InMemoryRestoreTarget("restore-root");
        var restored = restarted.SelfRestore(outcome.SnapshotId!, null, restoreTarget,
            new RestoreRequester("alice", "dev1", false));
        Assert.True(restored.Ok, restored.Outcome);
        Assert.Equal(1, restored.FilesRestored);
    }

    [Fact]
    public void R15_Wiring_HubTarget_RefusedByName_LocalTargetStillWires()
    {
        var targetDir = TempDir("target");
        var settings = LocalPolicy(targetDir, Path.Combine(targetDir, "x.txt"));
        settings["backup.targets"] = "tgt1,hub1";
        settings["backup.target.hub1.kind"] = "hub";
        settings["backup.target.hub1.locator"] = "hub-device-9";
        var (_, report, _) = WireUp(settings, "data");
        Assert.Single(report.Wired);
        var refusal = Assert.Single(report.Refused);
        Assert.Contains("hub1", refusal);
        Assert.Contains("hub-side backup storage is not wired", refusal);
    }

    [Fact]
    public void R15_Wiring_CorruptKeyFile_RefusesThatTargetByName()
    {
        var targetDir = TempDir("target");
        var dataDir = TempDir("data");
        Directory.CreateDirectory(Path.Combine(dataDir, "backup-keys"));
        File.WriteAllText(Path.Combine(dataDir, "backup-keys", "tgt1.key"), "not-a-protected-key");
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", LocalPolicy(targetDir, "x"), 1)).Allowed);
        var (service, report) = BackupHostWiring.Build(
            new ChainedAuditLog(), policy, id => StaticDeviceFacts.Of(id, "scope1"),
            StaticDeviceFacts.Of("dev1", "scope1"), dataDir, new DevOnlyPassThroughProtector(), gate: null);
        Assert.Empty(report.Wired);
        var refusal = Assert.Single(report.Refused);
        Assert.Contains("at-rest key refused", refusal);
        Assert.Empty(service.WiredTargetIds);
    }

    [Fact]
    public void R15_Service_JobForUnwiredTarget_RefusesByName_NothingWritten()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", LocalPolicy(TempDir("t"), "x"), 1)).Allowed);
        // The zero-engine service: the honest shape of "policy
        // names targets this host could not construct".
        var service = new BackupService(audit, policy, id => StaticDeviceFacts.Of(id, "scope1"),
            new Dictionary<string, BackupEngine>(), gate: null, now: () => T0);
        var outcomes = service.RunDueJobs("dev1", envelope: null);
        var outcome = Assert.Single(outcomes);
        Assert.False(outcome.Ok);
        Assert.Contains("no backup store is wired on this host for target 'tgt1'", outcome.Outcome);
        Assert.Equal(0, service.Usage().SealedSnapshots);
        Assert.False(service.HealthFacts("dev1").StorageReachable);
    }

    [Fact]
    public void R15_Service_MultiTargetRouting_RunsAndRestoresPerTarget()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var settings = LocalPolicy(TempDir("t"), @"C:\data\a.txt");
        settings["backup.targets"] = "tgt1,tgt2";
        settings["backup.target.tgt2.kind"] = "local";
        settings["backup.target.tgt2.locator"] = TempDir("t2");
        settings["backup.jobs"] = "job1,job2";
        settings["backup.job.job2.device"] = "dev1";
        settings["backup.job.job2.owner"] = "alice";
        settings["backup.job.job2.kind"] = "file";
        settings["backup.job.job2.selection"] = @"C:\data\a.txt";
        settings["backup.job.job2.target"] = "tgt2";
        settings["backup.job.job2.interval_hours"] = "24";
        settings["backup.job.job2.retention_days"] = "7";
        Assert.True(policy.AddDocument(new ManagementPolicyDocument(
            "org-backup", PolicyLevels.Org, "scope1", settings, 1)).Allowed);

        BackupEngine EngineFor(string target, string content)
        {
            var store = new BackupSnapshotStore(target, new InMemoryBackupStorage());
            var capture = new FakeBackupCaptureSource().AddFile("C:\\data\\a.txt", content);
            return new BackupEngine(store, capture, audit);
        }
        var engines = new Dictionary<string, BackupEngine>(StringComparer.OrdinalIgnoreCase)
        {
            ["tgt1"] = EngineFor("tgt1", "one"),
            ["tgt2"] = EngineFor("tgt2", "two"),
        };
        var service = new BackupService(audit, policy, id => StaticDeviceFacts.Of(id, "scope1"),
            engines, gate: null, now: () => T0);
        var outcomes = service.RunDueJobs("dev1", envelope: null);
        Assert.Equal(2, outcomes.Count);
        Assert.All(outcomes, o => Assert.True(o.Ok, o.Outcome));
        Assert.Equal(2, service.Usage().SealedSnapshots);
        // Each snapshot restores through the engine that holds it.
        foreach (var o in outcomes)
        {
            var restored = service.SelfRestore(o.SnapshotId!, null, new InMemoryRestoreTarget("restore-root"),
                new RestoreRequester("alice", "dev1", false));
            Assert.True(restored.Ok, restored.Outcome);
        }
        // An unknown snapshot refuses by name at the service seam.
        var missing = service.SelfRestore("snap-nope", null, new InMemoryRestoreTarget("restore-root"),
            new RestoreRequester("alice", "dev1", false));
        Assert.False(missing.Ok);
        Assert.Contains("not in any wired backup target's catalogue", missing.Outcome);
    }

    [Fact]
    public void R15_FileCapture_ReadsRealFiles_NotesMissing_RefusesEmptyAndImage()
    {
        var dir = TempDir("cap");
        var real = Path.Combine(dir, "real.txt");
        File.WriteAllText(real, "live-bytes");
        var sub = Path.Combine(dir, "sub");
        Directory.CreateDirectory(sub);
        var nested = Path.Combine(sub, "nested.txt");
        File.WriteAllText(nested, "nested-bytes");
        var capture = new FileBackupCaptureSource();
        BackupJobDefinition Job(string kind, params string[] sel) => new(
            "j", "dev1", "alice", kind, sel, "tgt1", new BackupSchedule(24), 7, true);

        var result = capture.Capture(Job(BackupKinds.File, real, dir, Path.Combine(dir, "gone.txt")), T0);
        Assert.Contains(result.Items, i => i.Content.SequenceEqual(Encoding.UTF8.GetBytes("live-bytes")));
        Assert.Contains(result.Items, i => i.Content.SequenceEqual(Encoding.UTF8.GetBytes("nested-bytes")));
        Assert.Contains(result.Notes, n => n.StartsWith("not_read:") && n.Contains("gone.txt"));
        Assert.Contains(result.Notes, n => n.Contains("WITHOUT a VSS shadow copy"));

        var empty = Assert.Throws<InvalidOperationException>(() =>
            capture.Capture(Job(BackupKinds.File, Path.Combine(dir, "gone.txt")), T0));
        Assert.Contains("read nothing", empty.Message);
        var image = Assert.Throws<InvalidOperationException>(() =>
            capture.Capture(Job(BackupKinds.Image, real), T0));
        Assert.Contains("no VSS shadow-copy provider", image.Message);
    }

    // ================= R-22: feed signing =================

    private static VulnerabilityFeed Feed(long seq = 1, string cve = "CVE-2026-1001") => new(
        "feed-1", "org-scanner", seq, T0,
        new[]
        {
            new VulnerabilityFeedEntry(cve, "Widget", "2.0", null, null, 7.5, "high", false, null, T0, null),
        });

    [Fact]
    public void R22_PinnedKey_SignedFeedImports_UnsignedAndWrongKeyRefuse()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var store = new VulnerabilityFeedStore();
        store.PinSigningKey(pub);

        var unsigned = store.Import(Feed(), T0);
        Assert.False(unsigned.Accepted);
        Assert.Contains("carries NO signature", unsigned.Reason);

        var signed = VulnerabilityFeedSigning.Sign(Feed(), seed);
        var accepted = store.Import(signed, T0);
        Assert.True(accepted.Accepted, accepted.Reason);
        Assert.Contains("verified against the host-pinned", store.CurrentProvenance(T0, 30).SignatureState);

        // A different producer key cannot sign for this host.
        var (otherSeed, _) = Ed25519.GenerateKeyPair();
        var forged = VulnerabilityFeedSigning.Sign(Feed(seq: 2), otherSeed);
        var refused = store.Import(forged, T0);
        Assert.False(refused.Accepted);
        Assert.Contains("does NOT verify", refused.Reason);
    }

    [Fact]
    public void R22_PinnedKey_TamperedAfterSigning_Refuses()
    {
        var (seed, pub) = Ed25519.GenerateKeyPair();
        var store = new VulnerabilityFeedStore();
        store.PinSigningKey(pub);
        var signed = VulnerabilityFeedSigning.Sign(Feed(), seed);
        // Swap in a quieter CVE set under the same signature: the
        // content hash moves, the signature no longer verifies.
        var tampered = signed with
        {
            Entries = new[]
            {
                new VulnerabilityFeedEntry("CVE-2026-9999", "Widget", "2.0", null, null, 0.1, "low", false, null, T0, null),
            },
        };
        var result = store.Import(tampered, T0);
        Assert.False(result.Accepted);
        Assert.Contains("does NOT verify", result.Reason);
    }

    [Fact]
    public void R22_Unpinned_UnsignedImports_ProvenanceStatesUnsigned()
    {
        var store = new VulnerabilityFeedStore();
        var result = store.Import(Feed(), T0);
        Assert.True(result.Accepted, result.Reason);
        Assert.Contains("unsigned — no feed-signing key is pinned",
            store.CurrentProvenance(T0, 30).SignatureState);
    }

    // ================= R-21: real OIDC =================

    private sealed record IdpRig(RSA Rsa, string JwksJson, OidcConfig Config, RealOidcClient Client);

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static IdpRig NewIdp()
    {
        var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var jwks = JsonSerializer.Serialize(new
        {
            keys = new object[]
            {
                new { kty = "RSA", kid = "key-1", n = B64Url(p.Modulus!), e = B64Url(p.Exponent!) },
                new { kty = "EC", kid = "ec-1", crv = "P-256" },
            },
        });
        var config = new OidcConfig("https://idp.example.test", "acp-client", "acp://oidc/callback", true, true);
        return new IdpRig(rsa, jwks, config, new RealOidcClient(config));
    }

    private static string SignRs256(RSA rsa, string headerJson, object payload)
    {
        var header = B64Url(Encoding.UTF8.GetBytes(headerJson));
        var body = B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        var sig = rsa.SignData(Encoding.ASCII.GetBytes(header + "." + body),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{body}.{B64Url(sig)}";
    }

    private static object GoodPayload(DateTimeOffset now, string nonce = "nonce-1") => new
    {
        iss = "https://idp.example.test",
        sub = "user-42",
        aud = "acp-client",
        exp = now.AddMinutes(10).ToUnixTimeSeconds(),
        iat = now.ToUnixTimeSeconds(),
        nonce,
        email = "user@example.test",
        email_verified = true,
    };

    [Fact]
    public void R21_RealOidc_Rs256Token_ValidatesAgainstJwks()
    {
        var rig = NewIdp();
        var (keys, _) = JwksKeySet.Parse(rig.JwksJson);
        Assert.NotNull(keys);
        Assert.Equal(1, keys!.Count); // the EC key is skipped by shape
        var token = SignRs256(rig.Rsa, "{\"alg\":\"RS256\",\"kid\":\"key-1\",\"typ\":\"JWT\"}", GoodPayload(T0));
        var result = rig.Client.ValidateIdToken(token, keys, "nonce-1", T0);
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("user-42", result.Subject);
        Assert.Contains("RS256 verified", result.Reason);
    }

    [Fact]
    public void R21_RealOidc_AlgConfusion_NoneAndHs256_RefuseBeforeKeys()
    {
        var rig = NewIdp();
        var (keys, _) = JwksKeySet.Parse(rig.JwksJson);
        var body = B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(GoodPayload(T0))));
        var noneHeader = B64Url(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
        var noneResult = rig.Client.ValidateIdToken($"{noneHeader}.{body}.", keys!, "nonce-1", T0);
        Assert.False(noneResult.Ok);
        Assert.Contains("not RS256", noneResult.Reason);
        var hsHeader = B64Url(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"kid\":\"key-1\",\"typ\":\"JWT\"}"));
        var hsResult = rig.Client.ValidateIdToken($"{hsHeader}.{body}.{B64Url(new byte[32])}", keys!, "nonce-1", T0);
        Assert.False(hsResult.Ok);
        Assert.Contains("not RS256", hsResult.Reason);
    }

    [Fact]
    public void R21_RealOidc_UnknownKid_TamperedPayload_Expired_AllRefuse()
    {
        var rig = NewIdp();
        var (keys, _) = JwksKeySet.Parse(rig.JwksJson);
        var unknownKid = SignRs256(rig.Rsa, "{\"alg\":\"RS256\",\"kid\":\"key-9\"}", GoodPayload(T0));
        var r1 = rig.Client.ValidateIdToken(unknownKid, keys!, "nonce-1", T0);
        Assert.False(r1.Ok);
        Assert.Contains("names no key", r1.Reason);

        var good = SignRs256(rig.Rsa, "{\"alg\":\"RS256\",\"kid\":\"key-1\"}", GoodPayload(T0));
        var parts = good.Split('.');
        var tamperedPayload = B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
            new { iss = "https://idp.example.test", sub = "admin", aud = "acp-client",
                  exp = T0.AddMinutes(10).ToUnixTimeSeconds(), iat = T0.ToUnixTimeSeconds(),
                  nonce = "nonce-1", email_verified = true })));
        var r2 = rig.Client.ValidateIdToken($"{parts[0]}.{tamperedPayload}.{parts[2]}", keys!, "nonce-1", T0);
        Assert.False(r2.Ok);
        Assert.Contains("signature invalid", r2.Reason);

        var expired = SignRs256(rig.Rsa, "{\"alg\":\"RS256\",\"kid\":\"key-1\"}", new
        {
            iss = "https://idp.example.test", sub = "user-42", aud = "acp-client",
            exp = T0.AddMinutes(-5).ToUnixTimeSeconds(), iat = T0.AddMinutes(-15).ToUnixTimeSeconds(),
            nonce = "nonce-1", email_verified = true,
        });
        var r3 = rig.Client.ValidateIdToken(expired, keys!, "nonce-1", T0);
        Assert.False(r3.Ok);
        Assert.Contains("expired", r3.Reason);
    }

    [Fact]
    public async Task R21_RealOidc_DiscoveryAndExchange_EndToEnd_ViaInjectedHttp()
    {
        var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var config = new OidcConfig("https://idp.example.test", "acp-client", "acp://oidc/callback", true, true);
        var discoveryJson = JsonSerializer.Serialize(new
        {
            issuer = "https://idp.example.test",
            authorization_endpoint = "https://idp.example.test/authorize",
            token_endpoint = "https://idp.example.test/token",
            jwks_uri = "https://idp.example.test/jwks",
        });
        var jwksJson = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", kid = "key-1", n = B64Url(p.Modulus!), e = B64Url(p.Exponent!) } },
        });
        string? postedForm = null;
        var client = new RealOidcClient(config,
            getJson: url => Task.FromResult(url.EndsWith("openid-configuration") ? discoveryJson : jwksJson),
            postForm: (url, form) =>
            {
                postedForm = form;
                var token = SignRs256(rsa, "{\"alg\":\"RS256\",\"kid\":\"key-1\"}", GoodPayload(T0));
                return Task.FromResult(JsonSerializer.Serialize(new { id_token = token }));
            });
        var (discovery, _) = await client.DiscoverAsync();
        Assert.NotNull(discovery);
        var url = client.BuildAuthorizationUrl(discovery!, "state-1", "nonce-1", Pkce.ChallengeS256("verifier-1"));
        Assert.Contains("code_challenge_method=S256", url);
        var result = await client.ExchangeAndValidateAsync(discovery!, "code-1", "verifier-1", "nonce-1", T0);
        Assert.True(result.Ok, result.Reason);
        Assert.Contains("code_verifier=verifier-1", postedForm);

        // A discovery document for ANOTHER issuer refuses.
        var foreign = new RealOidcClient(config, getJson: _ => Task.FromResult(
            discoveryJson.Replace("https://idp.example.test", "https://evil.example.test")));
        var (badDiscovery, badReason) = await foreign.DiscoverAsync();
        Assert.Null(badDiscovery);
        Assert.Contains("does not equal the configured issuer", badReason);
    }

    // ============ Destruction pass: audit-chain re-base ============
    // Found by this lane: a persisted audit chain tampered at a
    // JSON-structural character fails to PARSE at restore; the old
    // ImportEntriesJson left the log at genesis, so the next
    // Verify() (and every audit export) called the re-based chain
    // OK and the next save overwrote the broken store. The break
    // must LATCH.

    [Fact]
    public void Destruction_AuditChain_UnparseableStore_LatchesBroken_NeverRebases()
    {
        var log = new ChainedAuditLog();
        log.Append("kind_a", "actor", "detail one", T0);
        log.Append("kind_b", "actor", "detail two", T0.AddMinutes(1));
        var exported = log.ExportEntriesJson();
        // Attack 1: truncate the store mid-entry — the JSON no
        // longer parses at all (the shape that silently re-based).
        var structural = exported[..(exported.Length / 2)];
        var fresh = new ChainedAuditLog();
        var verdict = fresh.ImportEntriesJson(structural);
        Assert.False(verdict.Ok);
        Assert.Contains("did not parse", verdict.Summary);
        // Appends after the failed restore must NOT heal the verdict.
        fresh.Append("kind_c", "actor", "post-restore act", T0.AddMinutes(2));
        var after = fresh.Verify();
        Assert.False(after.Ok);
        Assert.Contains("never re-based", after.Summary);
        // A CONTENT tamper (parseable) latches the same way.
        var content = exported.Replace("detail one", "detail ONE");
        var fresh2 = new ChainedAuditLog();
        Assert.False(fresh2.ImportEntriesJson(content).Ok);
        fresh2.Append("kind_c", "actor", "post-restore act", T0.AddMinutes(2));
        Assert.False(fresh2.Verify().Ok);
        // And a clean import clears the latch (recovery is an
        // explicit import of a good store, not an accident of time).
        Assert.True(fresh2.ImportEntriesJson(exported).Ok);
        Assert.True(fresh2.Verify().Ok);
    }

    // ================= R-32: held-input sweep =================

    private sealed class RecordingSink : IInputReleaseSink
    {
        public List<string> Released { get; } = new();
        public void ReleaseKey(ushort virtualKey) => Released.Add($"key:0x{virtualKey:X2}");
        public void ReleaseMouseButton(string button) => Released.Add($"button:{button}");
    }

    [Fact]
    public void R32_StartupSweep_CoversEveryHoldableKey_NotJustModifiers()
    {
        var sink = new RecordingSink();
        var swept = HeldInputTracker.SweepAllPossible(sink);
        Assert.Contains("key:0x41", swept); // 'A' — holdable via chords, previously unswept
        Assert.Contains("key:0x20", swept); // SPACE
        Assert.Contains("key:0x74", swept); // F5
        Assert.Contains("key:0x11", swept); // CTRL (the pre-W11 set still covered)
        Assert.Contains("button:left", swept);
        Assert.DoesNotContain("key:0xE7", swept); // VK_PACKET excluded by name
        Assert.Equal(3 + (0xFE - 0x08 + 1) - 1, swept.Count);
        Assert.Equal(swept, sink.Released);
    }
}

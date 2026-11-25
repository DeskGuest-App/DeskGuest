using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Distribution;
using Acp.Shared.Jobs;
using Acp.Shared.Security;

namespace Acp.Tests;

// DESTRUCTION PASS — RMM-14 + RMM-15 (Block R gate law).
// Attacker models: (15) an attacker with write access to the
// endpoint's journal file but NOT the customer key and NOT the
// endpoint key; a compromised hub replaying reports. (14) a
// malicious peer on the LAN: serves wrong bytes, serves slowly
// forever, advertises content it does not have, spoofs other
// devices' availability, and a cache serving revoked/stale content.
public class Rmm14_15DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private sealed record Auth(DeviceIdentity Customer, SignedCommandSigner Signer, CustomerCommandKeyRing Ring);
    private static Auth NewAuth()
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        return new Auth(customer, new SignedCommandSigner(customer), ring);
    }

    private static JobStepDefinition Idem(string id) => new(id, id, StepIdempotency.Idempotent);
    private static JobStepDefinition NonIdem(string id) => new(id, id, StepIdempotency.NonIdempotent);

    private static (JobJournal Journal, ResumableJob Job) RunningPatchJob(Auth a, DeviceIdentity? endpoint = null)
    {
        var j = endpoint is null ? new JobJournal() : new JobJournal(endpoint);
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("job-payload"), T0, TimeSpan.FromHours(4));
        var job = j.CreateJob(JobKinds.PatchRun, "dev1",
            new[] { Idem("s1"), Idem("s2") }, env, T0)!;
        j.StartJob(job.Id, T0);
        j.BeginStep(job.Id, "s1", T0);
        return (j, job);
    }

    // Attacker tool: rewrite exported journal entries and RECOMPUTE
    // the whole hash chain correctly (the strongest journal attack
    // short of holding keys).
    private static string RecomputeChain(string exportJson, Func<JsonElement, (string Kind, string Detail)> mutate)
    {
        using var doc = JsonDocument.Parse(exportJson);
        var entries = doc.RootElement.EnumerateArray().ToList();
        var sb = new StringBuilder("[");
        var prev = "GENESIS";
        var first = true;
        foreach (var e in entries)
        {
            var seq = e.GetProperty("Seq").GetInt64();
            var jobId = e.GetProperty("JobId").GetString()!;
            var at = e.GetProperty("AtUtc").GetDateTimeOffset();
            var (kind, detail) = mutate(e);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{seq}|{jobId}|{at:O}|{kind}|{detail}|{prev}"))).ToLowerInvariant();
            if (!first) sb.Append(',');
            first = false;
            sb.Append(JsonSerializer.Serialize(new
            {
                Seq = seq, JobId = jobId, AtUtc = at, Kind = kind, Detail = detail,
                PrevHash = prev, Hash = hash, SignatureBase64 = (string?)null,
            }));
            prev = hash;
        }
        return sb.Append(']').ToString();
    }

    // ---------- RMM-15 attacks ----------

    [Fact]
    public void ATTACK_JournalTamper_SingleDetailEdit_BreaksChain_NothingResumes()
    {
        var a = NewAuth();
        var (j, job) = RunningPatchJob(a);
        var tampered = j.ExportJson().Replace("step=s1", "step=s9");
        Assert.NotEqual(j.ExportJson(), tampered);
        var restored = new JobJournal();
        var v = restored.ImportJson(tampered);
        Assert.False(v.Ok, v.Summary);
        var report = restored.ResumeAll(T0.AddMinutes(5), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(0, report.ResumedCount);
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, r.State);
        Assert.Equal(JobFailureReasons.JournalTampered, r.FailureReason);
    }

    [Fact]
    public void ATTACK_ForgedCheckpoint_KindSwap_BreaksChain()
    {
        var a = NewAuth();
        var (j, job) = RunningPatchJob(a);
        // attacker flips step_started into step_completed in the raw export:
        var forged = j.ExportJson().Replace("\"step_started\"", "\"step_completed\"");
        var restored = new JobJournal();
        Assert.False(restored.ImportJson(forged).Ok);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Failed, restored.GetJob(job.Id)!.State);
        Assert.Equal(JobFailureReasons.JournalTampered, restored.GetJob(job.Id)!.FailureReason);
    }

    [Fact]
    public void ATTACK_RecomputedChain_SignedJournal_SignatureCheckStillBreaksIt()
    {
        var endpoint = NewIdentity();
        var a = NewAuth();
        var (j, job) = RunningPatchJob(a, endpoint);
        // Attacker edits history (pretends s1 completed) AND recomputes
        // every hash correctly. Against a SIGNED journal this still
        // fails: the attacker holds no endpoint seed to re-sign.
        var forged = RecomputeChain(j.ExportJson(), e =>
        {
            var kind = e.GetProperty("Kind").GetString()!;
            var detail = e.GetProperty("Detail").GetString()!;
            return kind == "step_started" ? ("step_completed", detail) : (kind, detail);
        });
        var restored = JobJournal.ForVerification(endpoint.PublicKey);
        var v = restored.ImportJson(forged);
        Assert.False(v.Ok, v.Summary);
        Assert.Contains("signature", v.Summary);
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        // D38 F2 SUPERSEDES the original tail of this test (recovery
        // lane, 2026-11-21): the recompute nulls EVERY signature, so
        // the chain breaks at seq 1 — the genesis itself is
        // untrusted, replay stops there, and the job never
        // materialises at all (stronger than the pre-fix semantics,
        // which replayed forged entries and then failed the job).
        // What must hold: no live/forged state, and the hub refuses
        // the broken journal's report outright.
        var after = restored.GetJob(job.Id);
        Assert.True(after is null ||
            (after.State == JobStates.Failed && after.FailureReason == JobFailureReasons.JournalTampered),
            "a job from an untrusted journal must never exist in a live state");
        var report = restored.BuildStateReport("dev1", true, T0.AddMinutes(6));
        Assert.False(report.ChainOk);
        Assert.False(new JobStateReconciler(() => T0.AddMinutes(6)).Accept(report).Accepted);
    }

    [Fact]
    public void ATTACK_RecomputedChain_UnsignedJournal_IsTheNamedResidual()
    {
        // HONEST RESIDUAL, asserted so it can never be forgotten:
        // an UNSIGNED journal's hash chain alone does NOT resist a
        // full recompute — that is exactly why production journals
        // are endpoint-signed and why checkpoint heads are anchored
        // into the chained audit log when a sink is wired. This test
        // documents the boundary; it does not bless it.
        var a = NewAuth();
        var (j, _) = RunningPatchJob(a);
        var forged = RecomputeChain(j.ExportJson(), e =>
            (e.GetProperty("Kind").GetString()!, e.GetProperty("Detail").GetString()!));
        var restored = new JobJournal();
        Assert.True(restored.ImportJson(forged).Ok); // identical content, valid chain — as designed
    }

    [Fact]
    public void ATTACK_AuthorityResurrection_ExtendedExpiry_FailsSignatureRecheck()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("job-payload"), T0, TimeSpan.FromMinutes(30));
        var job = j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, env, T0)!;
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "s1", T0);
        // Attacker rewrites the genesis entry: swaps in an envelope
        // JSON whose expiry is a year out, fixes the stored envelope
        // hash to match, and recomputes the chain. The envelope's own
        // Ed25519 signature (over the ORIGINAL expiry) is the wall:
        var forged = RecomputeChain(j.ExportJson(), e =>
        {
            var kind = e.GetProperty("Kind").GetString()!;
            var detail = e.GetProperty("Detail").GetString()!;
            if (kind != "job_created") return (kind, detail);
            using var doc = JsonDocument.Parse(detail);
            var root = doc.RootElement;
            var envJson = root.GetProperty("envelopeJson").GetString()!;
            var envObj = SignedCommandEnvelope.FromJson(envJson)!;
            var extended = envObj with { ExpiresUtc = T0.AddYears(1) };
            var newJson = extended.ToJson();
            var newHash = Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes(newJson))).ToLowerInvariant();
            var newDetail = JsonSerializer.Serialize(new
            {
                kind = root.GetProperty("kind").GetString(),
                deviceId = root.GetProperty("deviceId").GetString(),
                createdUtc = root.GetProperty("createdUtc").GetDateTimeOffset(),
                envelopeHash = newHash,
                envelopeClass = root.GetProperty("envelopeClass").GetString(),
                envelopeExpiresUtc = (DateTimeOffset?)T0.AddYears(1),
                envelopeJson = newJson,
                steps = root.GetProperty("steps").EnumerateArray().Select(s => new
                {
                    stepId = s.GetProperty("stepId").GetString(),
                    name = s.GetProperty("name").GetString(),
                    idempotency = s.GetProperty("idempotency").GetString(),
                }).ToArray(),
            });
            return (kind, newDetail);
        });
        var restored = new JobJournal();
        Assert.True(restored.ImportJson(forged).Ok); // chain recomputed correctly...
        var report = restored.ResumeAll(T0.AddHours(2), resumeEnabled: true, ring: a.Ring);
        Assert.Equal(0, report.ResumedCount);        // ...but authority does NOT resurrect
        var r = restored.GetJob(job.Id)!;
        Assert.Equal(JobStates.Failed, r.State);
        Assert.Equal(JobFailureReasons.AuthorityInvalid, r.FailureReason);
    }

    [Fact]
    public void ATTACK_ParkedJob_CannotBeForcedPastTheHuman()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("p"), T0, TimeSpan.FromHours(4));
        var job = j.CreateJob(JobKinds.PatchRun, "dev1", new[] { NonIdem("risky") }, env, T0)!;
        j.StartJob(job.Id, T0); j.BeginStep(job.Id, "risky", T0);
        var restored = new JobJournal();
        restored.ImportJson(j.ExportJson());
        restored.ResumeAll(T0.AddMinutes(5), true, a.Ring);
        Assert.Equal(JobStates.Parked, restored.GetJob(job.Id)!.State);
        // every non-human path refuses:
        Assert.False(restored.StartJob(job.Id, T0.AddMinutes(6)));
        Assert.False(restored.BeginStep(job.Id, "risky", T0.AddMinutes(6)));
        Assert.False(restored.CompleteStep(job.Id, "risky", T0.AddMinutes(6)));
        Assert.False(restored.ResumeAll(T0.AddMinutes(7), true, a.Ring).ResumedCount > 0);
        Assert.Equal(JobStates.Parked, restored.GetJob(job.Id)!.State);
    }

    [Fact]
    public void ATTACK_HubReportReplay_TerminalRegressionAndStaleReports_Refused()
    {
        var a = NewAuth();
        var j = new JobJournal();
        var env = a.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("p"), T0, TimeSpan.FromHours(4));
        var job = j.CreateJob(JobKinds.PatchRun, "dev1", new[] { Idem("s1") }, env, T0)!;
        j.StartJob(job.Id, T0);
        var running = j.BuildStateReport("dev1", true, T0.AddMinutes(1));
        j.BeginStep(job.Id, "s1", T0.AddMinutes(2)); j.CompleteStep(job.Id, "s1", T0.AddMinutes(2));
        var done = j.BuildStateReport("dev1", true, T0.AddMinutes(3));
        var hub = new JobStateReconciler();
        Assert.True(hub.Accept(done).Accepted);
        // replaying the OLD running report cannot resurrect the job:
        var replay = hub.Accept(running);
        Assert.False(replay.Accepted);
        Assert.Equal(JobStates.Done, hub.GetJob("dev1", job.Id)!.State);
        // a fabricated same-time report claiming "running" also refuses:
        var forged = new JobStateReport("dev1", T0.AddMinutes(3), true, "FORGEDHEAD",
            new[] { new JobStateSummary(job.Id, JobKinds.PatchRun, JobStates.Running, null, 0, 1, 0) });
        Assert.False(hub.Accept(forged).Accepted);
    }

    // ---------- RMM-14 attacks ----------

    private static byte[] Payload(string seed, int size = 200_000)
    {
        var bytes = new byte[size];
        var s = Encoding.UTF8.GetBytes(seed);
        for (var i = 0; i < size; i++) bytes[i] = s[i % s.Length];
        for (var i = 0; i < size; i += 4096) bytes[i] ^= (byte)(i / 4096);
        return bytes;
    }

    private sealed class EvilSource : IContentSource
    {
        public string SourceId => "evil-peer";
        public bool IsHub => false;
        public int Calls;
        public byte[]? FetchChunk(ContentManifest manifest, int index)
        {
            Calls++;
            var len = (int)manifest.ChunkLength(index);
            return Payload("evil-bytes", 64 * 1024)[..len]; // plausible length, wrong bytes
        }
    }

    private sealed class SlowForeverSource : IContentSource
    {
        public string SourceId => "slow-peer";
        public bool IsHub => false;
        public int Calls;
        public byte[]? FetchChunk(ContentManifest manifest, int index)
        {
            Calls++;
            throw new TimeoutException("simulated peer that never answers usefully");
        }
    }

    [Fact]
    public void ATTACK_PeerPoisoning_WrongBytes_FailsVerify_FailsOverToHub_CostBounded()
    {
        var content = Payload("real-patch");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var evil = new EvilSource();
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            evil, new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("hub", result.SourceUsed);
        Assert.Equal(content, result.Content);
        // the poisoning cost is bounded by the per-source budget:
        // at most (budget+1) chunks of waste from the evil peer.
        var wasted = result.WastedBytesBySource.GetValueOrDefault("evil-peer");
        Assert.True(wasted <= (ContentFetcher.DefaultMaxFailedChunksPerSource + 1) * m.ChunkSize,
            $"wasted {wasted} exceeds the named bound");
        Assert.True(evil.Calls <= ContentFetcher.DefaultMaxFailedChunksPerSource + 1);
    }

    [Fact]
    public void ATTACK_PeerServesWronglyForever_OnlySource_FetchFailsCleanly()
    {
        var m = ContentManifest.Build(Payload("real"), chunkSize: 64 * 1024);
        var evil = new EvilSource();
        var result = new ContentFetcher().Fetch(m, new IContentSource[] { evil });
        Assert.False(result.Ok);
        Assert.Null(result.Content);
        Assert.True(evil.Calls <= ContentFetcher.DefaultMaxFailedChunksPerSource + 1); // never wedged
    }

    [Fact]
    public void ATTACK_SlowPeerForever_RequesterFailsOverToHub()
    {
        var content = Payload("real-patch");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var slow = new SlowForeverSource();
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            slow, new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("hub", result.SourceUsed);
        Assert.True(slow.Calls <= ContentFetcher.DefaultMaxFailedChunksPerSource + 1);
    }

    [Fact]
    public void ATTACK_AvailabilitySpoofing_CannotAdvertiseInAnotherDevicesName()
    {
        var victim = NewIdentity(); var attacker = NewIdentity();
        var coord = new HubDistributionCoordinator(id => id == "victim" ? victim.PublicKey : null);
        var m = ContentManifest.Build(Payload("x"), chunkSize: 64 * 1024);
        // attacker signs with THEIR key but claims to be the victim:
        var spoof = AvailabilityClaim.Sign(attacker, "victim", m.ContentHash, false, T0, TimeSpan.FromHours(1));
        Assert.False(coord.AdmitClaim(spoof, T0).Accepted);
        // unenrolled device: refused outright
        var ghost = AvailabilityClaim.Sign(attacker, "ghost", m.ContentHash, false, T0, TimeSpan.FromHours(1));
        Assert.False(coord.AdmitClaim(ghost, T0).Accepted);
        // unsigned claim: refused
        var unsigned = new AvailabilityClaim("victim", m.ContentHash, false, T0, T0.AddHours(1), "");
        Assert.False(coord.AdmitClaim(unsigned, T0).Accepted);
        Assert.Empty(coord.SourcesFor(m.ContentHash, T0));
    }

    [Fact]
    public void ATTACK_FalseAvailabilityClaim_ValidSignatureButNoContent_WastesAtMostOneBudget()
    {
        // A malicious ENROLLED peer signs a truthful-looking claim for
        // content it does not hold. The claim is admissible (it proves
        // who claims, not possession — by design); the FETCH is where
        // the lie dies: no chunk verifies, budget exhausts, hub serves.
        var liar = NewIdentity();
        var coord = new HubDistributionCoordinator(id => id == "liar1" ? liar.PublicKey : null);
        var content = Payload("real-patch");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var claim = AvailabilityClaim.Sign(liar, "liar1", m.ContentHash, false, T0, TimeSpan.FromHours(1));
        Assert.True(coord.AdmitClaim(claim, T0).Accepted);
        var liarStore = new PeerContentStore(); // holds NOTHING
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m, content);
        var result = new ContentFetcher().Fetch(m, new IContentSource[]
        {
            new StoreContentSource("liar1", liarStore),
            new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok);
        Assert.Equal("hub", result.SourceUsed);
        Assert.Equal(content, result.Content);
    }

    [Fact]
    public void ATTACK_HashCollisionClaim_StoreCannotHoldWrongBytesUnderAGoodHash()
    {
        var m = ContentManifest.Build(Payload("genuine"), chunkSize: 64 * 1024);
        var store = new PeerContentStore();
        // there is no API path that stores unverified bytes — the
        // "collision" claim dies at the store's whole-hash gate:
        Assert.False(store.PutVerified(m, Payload("attacker-chosen")));
        Assert.False(store.Has(m.ContentHash));
        Assert.Null(store.GetWhole(m.ContentHash));
    }

    [Fact]
    public void ATTACK_CacheServingStaleVersion_RequesterGetsTheRequestedHash_NotTheStaleOne()
    {
        var v1 = Payload("patch-v1"); var v2 = Payload("patch-v2");
        var m1 = ContentManifest.Build(v1, chunkSize: 64 * 1024);
        var m2 = ContentManifest.Build(v2, chunkSize: 64 * 1024);
        var cache = new PeerContentStore(); cache.PutVerified(m1, v1); // stale cache: v1 only
        var hubStore = new PeerContentStore(); hubStore.PutVerified(m2, v2);
        var result = new ContentFetcher().Fetch(m2, new IContentSource[]
        {
            new StoreContentSource("cache1", cache),
            new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok);
        Assert.Equal(v2, result.Content); // content addressing: v1 bytes can never answer a v2 request
        Assert.Equal("hub", result.SourceUsed);
    }

    [Fact]
    public void ATTACK_CacheServingRevokedContent_ServesNothingAfterRevocation()
    {
        var content = Payload("pulled-patch");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var cache = new PeerContentStore(); cache.PutVerified(m, content);
        Assert.NotNull(cache.GetChunk(m.ContentHash, m, 0));
        cache.Revoke(m.ContentHash);
        Assert.Null(cache.GetChunk(m.ContentHash, m, 0));
        Assert.Null(cache.GetWhole(m.ContentHash));
        Assert.Empty(cache.HeldHashes);
    }
}

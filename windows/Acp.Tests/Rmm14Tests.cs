using System.Text;
using Acp.Shared.Distribution;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-14 — P2P LAN distribution + patch caching. Loopback/fake
// transports only; live-LAN proof is pending (named, not faked).
public class Rmm14Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());

    private static byte[] Payload(string seed, int size = 200_000)
    {
        var bytes = new byte[size];
        var s = Encoding.UTF8.GetBytes(seed);
        for (var i = 0; i < size; i++) bytes[i] = s[i % s.Length];
        // make chunks distinct so a wrong-chunk attack is detectable per chunk:
        for (var i = 0; i < size; i += 4096) bytes[i] ^= (byte)(i / 4096);
        return bytes;
    }

    private sealed class Rig
    {
        public required DeviceIdentity CacheId;
        public required DeviceIdentity PeerId;
        public required DeviceIdentity HubId;
        public required HubDistributionCoordinator Coordinator;
        public byte[]? KeyOf(string deviceId) =>
            deviceId == "cache1" ? CacheId.PublicKey :
            deviceId == "peer1" ? PeerId.PublicKey :
            deviceId == "hub" ? HubId.PublicKey : null;
    }

    private static Rig NewRig()
    {
        var rig = new Rig { CacheId = NewIdentity(), PeerId = NewIdentity(), HubId = NewIdentity(), Coordinator = null! };
        rig.Coordinator = new HubDistributionCoordinator(rig.KeyOf);
        return rig;
    }

    [Fact]
    public void RMM14_Manifest_ChunkAndWholeHashes_Verify()
    {
        var content = Payload("patch-v1");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024, label: "KB5001");
        Assert.True(m.VerifyWhole(content));
        Assert.False(m.VerifyWhole(Payload("patch-v2")));
        for (var i = 0; i < m.ChunkCount; i++)
        {
            var len = (int)m.ChunkLength(i);
            var chunk = content.AsSpan(i * m.ChunkSize, len).ToArray();
            Assert.True(m.VerifyChunk(i, chunk));
            chunk[0] ^= 0xFF;
            Assert.False(m.VerifyChunk(i, chunk));
        }
    }

    [Fact]
    public void RMM14_Store_AdmitsOnlyHashVerifiedBytes_TheHubGateAppliedToPeers()
    {
        var content = Payload("good");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var store = new PeerContentStore();
        Assert.False(store.PutVerified(m, Payload("evil"))); // wrong bytes under a good hash: refused
        Assert.False(store.Has(m.ContentHash));
        Assert.True(store.PutVerified(m, content));
        Assert.True(store.Has(m.ContentHash));
        Assert.Equal(content, store.GetWhole(m.ContentHash));
    }

    [Fact]
    public void RMM14_Fetch_FromPeerOverLoopback_HubNotNeeded_AndLocalStoreFills()
    {
        var content = Payload("peer-served");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var peerStore = new PeerContentStore();
        Assert.True(peerStore.PutVerified(m, content));
        var local = new PeerContentStore();
        var fetcher = new ContentFetcher();
        var result = fetcher.Fetch(m, new IContentSource[] { new StoreContentSource("peer1", peerStore) }, local);
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("peer1", result.SourceUsed);
        Assert.Equal(content, result.Content);
        Assert.True(local.Has(m.ContentHash)); // now this device can serve others
    }

    [Fact]
    public void RMM14_Fetch_FallsBackToHub_WhenNoPeerHasIt()
    {
        var content = Payload("hub-only");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var hubStore = new PeerContentStore();
        hubStore.PutVerified(m, content);
        var emptyPeer = new PeerContentStore();
        var fetcher = new ContentFetcher();
        var result = fetcher.Fetch(m, new IContentSource[]
        {
            new StoreContentSource("peer1", emptyPeer),
            new StoreContentSource("hub", hubStore, isHub: true),
        });
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("hub", result.SourceUsed);
    }

    [Fact]
    public void RMM14_Coordinator_CacheFirstOrdering_AndSignedClaims()
    {
        var rig = NewRig();
        var m = ContentManifest.Build(Payload("ordered"), chunkSize: 64 * 1024);
        var peerClaim = AvailabilityClaim.Sign(rig.PeerId, "peer1", m.ContentHash, false, T0, TimeSpan.FromHours(1));
        var cacheClaim = AvailabilityClaim.Sign(rig.CacheId, "cache1", m.ContentHash, true, T0, TimeSpan.FromHours(1));
        Assert.True(rig.Coordinator.AdmitClaim(peerClaim, T0).Accepted);
        Assert.True(rig.Coordinator.AdmitClaim(cacheClaim, T0).Accepted);
        var sources = rig.Coordinator.SourcesFor(m.ContentHash, T0.AddMinutes(1));
        Assert.Equal(new[] { "cache1", "peer1" }, sources); // designated cache serves first
    }

    [Fact]
    public void RMM14_Claim_ExpiredClaimsArePruned_NeverServedAsSources()
    {
        var rig = NewRig();
        var m = ContentManifest.Build(Payload("stale-claim"), chunkSize: 64 * 1024);
        var claim = AvailabilityClaim.Sign(rig.PeerId, "peer1", m.ContentHash, false, T0, TimeSpan.FromMinutes(5));
        Assert.True(rig.Coordinator.AdmitClaim(claim, T0).Accepted);
        Assert.Empty(rig.Coordinator.SourcesFor(m.ContentHash, T0.AddHours(1)));
    }

    [Fact]
    public void RMM14_Policy_ToggleAndCacheDesignation_ViaRmm07()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "co1");
        Assert.True(DistributionPolicy.IsEnabled(engine, facts)); // registry default ON
        Assert.False(DistributionPolicy.IsDesignatedCache(engine, facts));
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("d1", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { [DistributionPolicy.CacheKey] = "true" }, 1)).Allowed);
        Assert.True(DistributionPolicy.IsDesignatedCache(engine, facts));
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("d2", PolicyLevels.Org, "co1",
            new Dictionary<string, string> { [DistributionPolicy.EnabledKey] = "false" }, 1)).Allowed);
        // device doc d1 does not set the toggle; org-level false applies:
        Assert.False(DistributionPolicy.IsEnabled(engine, facts));
    }

    [Fact]
    public void RMM14_Revocation_StoreDropsBytes_CoordinatorDropsClaims_FetcherRefuses()
    {
        var rig = NewRig();
        var content = Payload("revoked-patch");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var store = new PeerContentStore();
        store.PutVerified(m, content);
        var claim = AvailabilityClaim.Sign(rig.CacheId, "cache1", m.ContentHash, true, T0, TimeSpan.FromHours(1));
        Assert.True(rig.Coordinator.AdmitClaim(claim, T0).Accepted);

        store.Revoke(m.ContentHash);
        rig.Coordinator.RevokeContent(m.ContentHash);
        Assert.False(store.Has(m.ContentHash));
        Assert.Null(store.GetChunk(m.ContentHash, m, 0));
        Assert.Empty(rig.Coordinator.SourcesFor(m.ContentHash, T0.AddMinutes(1)));
        // new claims for revoked content refuse:
        Assert.False(rig.Coordinator.AdmitClaim(
            AvailabilityClaim.Sign(rig.PeerId, "peer1", m.ContentHash, false, T0, TimeSpan.FromHours(1)), T0).Accepted);
        // and a fetcher told of the revocation refuses even a willing source:
        var willing = new PeerContentStore();
        // (a second store that never heard of the revocation still holds bytes;
        //  the fetcher's revocation check is what protects this device)
        var other = new PeerContentStore();
        other.PutVerified(m, content);
        var result = new ContentFetcher().Fetch(m,
            new IContentSource[] { new StoreContentSource("cache1", other) },
            isRevoked: h => rig.Coordinator.IsRevoked(h));
        Assert.False(result.Ok);
        Assert.Contains("revoked", result.Reason);
        _ = willing;
    }

    [Fact]
    public void RMM14_AssembleVerified_ChunkComposition_MustAlsoPassWholeHash()
    {
        var content = Payload("assembled");
        var m = ContentManifest.Build(content, chunkSize: 64 * 1024);
        var chunks = Enumerable.Range(0, m.ChunkCount)
            .Select(i => content.AsSpan(i * m.ChunkSize, (int)m.ChunkLength(i)).ToArray()).ToList();
        var store = new PeerContentStore();
        Assert.True(store.AssembleVerified(m, chunks));
        var bad = chunks.Select(c => c.ToArray()).ToList();
        bad[0][0] ^= 0xFF;
        var store2 = new PeerContentStore();
        Assert.False(store2.AssembleVerified(m, bad));
        Assert.False(store2.Has(m.ContentHash));
    }
}

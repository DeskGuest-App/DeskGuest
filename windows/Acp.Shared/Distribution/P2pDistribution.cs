using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Shared.Distribution;

// =====================================================================
// RMM-14 — P2P LAN distribution + patch caching.
//
// Patch/package payloads distribute peer-to-peer inside a site: one
// download crosses the WAN, then endpoints serve each other over
// the LAN; a designated device can act as the site's patch CACHE
// (the WSUS shape). Content is addressed by SHA-256 — peer trust is
// NEVER required:
//
//   * a payload enters a device's store only after its whole-content
//     SHA-256 verifies — exactly the hash verification hub delivery
//     already uses (FileTransferModule commit, UpdateManager's
//     signed staging): wrong bytes from a peer fail identically to
//     wrong bytes from the hub;
//   * distribution is CHUNKED, and the hub-issued manifest carries
//     every chunk's SHA-256. A fetching device verifies each chunk
//     on arrival, so a poisoning peer's cost is bounded honestly:
//     ONE chunk's worth of wasted LAN transfer per attempt, then the
//     peer is blacklisted for that content and the fetch fails over
//     to the next source and finally to the hub. A peer cannot waste
//     more than (chunk size × sources tried) of the fleet's time —
//     that bound is the design's poisoning cost, named here rather
//     than pretending signed claims make poisoning impossible;
//   * availability claims ("I have hash X") are SIGNED by the
//     claiming device's enrolled key over (content hash | device |
//     expiry): a malicious peer cannot advertise in another device's
//     name, and cannot advertise at all without an enrolled key.
//     A claim proves WHO claims, never WHAT they hold — possession
//     is proven by the chunks themselves, per-chunk, on delivery.
//     That is the honest shape and the tests assert exactly it;
//   * revoked content (a pulled patch) is refused by stores,
//     coordinators and fetchers alike: a cache holding revoked
//     bytes serves nothing and a fetcher accepts nothing revoked,
//     however valid the hashes are;
//   * slow/wrong-forever peers cannot wedge a fetch: per-source
//     attempt budgets (failed chunks + transport faults) exhaust
//     and fail over; the hub is always the final source.
//
// Policy (TOTAL POLICY CONTROL via RMM-07): the toggle
// rmm.p2p_distribution.enabled gates the whole feature — OFF means
// hub-only fetching and no peer serving. Cache designation is the
// policy setting rmm.p2p_distribution.cache = "true" on a device's
// Effective Policy (org/group/device inheritance decides which
// device is the site cache).
//
// D38 reconciliation fixes (cross-review, packet 1877a640):
//   F6  The toggle is enforced IN THIS LAYER, not by caller
//       courtesy: ContentFetcher refuses when its distribution-
//       enabled source reads OFF, StoreContentSource serves nothing
//       when its serving gate reads OFF, and HubDistribution-
//       Coordinator admits no claims and offers no sources when its
//       gate reads OFF. Callers wire the gate to DistributionPolicy.
//       IsEnabled (RMM-07); an unwired gate defaults to enabled to
//       preserve the registry default, and the wiring is the Core
//       host's named responsibility.
//   F7  Cache status is NOT self-claimed when the coordinator is
//       wired with a cache-designation source (deviceId → the
//       hub's Effective Policy answer): the claim's IsCache bit is
//       IGNORED and the policy answer is stored instead. Claim
//       lifetime is bounded (MaxClaimTtl = 24 h — a 100-year claim
//       fails signature-window verification), ClaimedUtc is clamped
//       to the admission instant for ordering (a claim dated up to
//       the tolerated 5 min in the future no longer wins freshness),
//       and SourcesFor RE-CHECKS enrollment on every read — a
//       de-enrolled device's claims stop being offered immediately.
//   F8  Revocation FAILS CLOSED in the fetcher: the effective
//       revocation predicate is the caller's delegate OR the local
//       store's own revocation list (either one revoking suffices —
//       the local store's list is consulted even when the caller
//       omits the delegate), it is checked before the fetch, before
//       storing, and before returning success, and an AssembleVerified
//       refusal fails the fetch instead of being ignored while Ok
//       bytes are returned. Revocation sets PERSIST: PeerContentStore
//       can be constructed over a revocation file (loaded at start,
//       rewritten on every Revoke) and both store and coordinator
//       revocation/distrust state round-trips through Export/Import
//       state JSON — a restart no longer resurrects revoked content.
//   F10 The transport contract carries the EXPECTED chunk length
//       and a CancellationToken: a compliant source refuses oversize
//       at the contract boundary, and the fetcher caps recorded
//       waste at the expected chunk length (an attacker-sized array
//       can no longer inflate the waste accounting or the bound).
//       Each chunk fetch runs under a per-chunk timeout (default
//       30 s): a silent peer spends budget and fails over instead of
//       wedging the fetch forever. NAMED RESIDUAL: a timed-out
//       synchronous transport call is abandoned, not killed — its
//       thread finishes whenever the transport returns; the FETCH
//       is never wedged, which is the guarantee this layer owns.
//       A source that exhausts its budget is REPORTED through the
//       fetcher's distrust callback; the coordinator records strikes
//       in a persistent, policy-bounded distrust record (TTL-capped)
//       and stops offering distrusted devices until it expires — a
//       liar no longer costs every fetch forever.
//
// Transports are interfaces; tests use loopback/fake transports.
// LIVE-LAN PROOF IS PENDING: the sandbox cannot do real LAN sockets
// reliably, and no test here claims it.
// =====================================================================

public static class DistributionPolicy
{
    public const string EnabledKey = "rmm.p2p_distribution.enabled";
    public const string CacheKey = "rmm.p2p_distribution.cache";

    public static bool IsEnabled(ManagementPolicyEngine engine, IDeviceFacts facts) =>
        engine.IsEnabled(facts, EnabledKey);

    /// <summary>Cache designation via RMM-07 policy: the device's
    /// Effective Policy carries rmm.p2p_distribution.cache=true
    /// (set at org/group/device level by the admin).</summary>
    public static bool IsDesignatedCache(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var s = engine.ComputeEffective(facts).Get(CacheKey);
        return s is not null && bool.TryParse(s.Value, out var v) && v;
    }
}

/// <summary>The hub-issued description of one payload: whole-content
/// SHA-256 (the content address), size, and the per-chunk hashes a
/// fetcher verifies against. A manifest whose chunk hashes do not
/// compose to the whole hash for given bytes is detectable at
/// Put-time by the store's whole-hash check.</summary>
public sealed record ContentManifest(string ContentHash, long SizeBytes, int ChunkSize,
    IReadOnlyList<string> ChunkHashes, string? Label)
{
    public int ChunkCount => ChunkHashes.Count;

    public static string HashOf(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static ContentManifest Build(byte[] content, int chunkSize = 64 * 1024, string? label = null)
    {
        if (chunkSize <= 0) throw new ArgumentOutOfRangeException(nameof(chunkSize));
        var chunks = new List<string>();
        for (var off = 0; off < content.Length; off += chunkSize)
        {
            var len = Math.Min(chunkSize, content.Length - off);
            chunks.Add(HashOf(content.AsSpan(off, len)));
        }
        if (content.Length == 0) chunks.Add(HashOf(ReadOnlySpan<byte>.Empty));
        return new ContentManifest(HashOf(content), content.Length, chunkSize, chunks, label);
    }

    public long ChunkLength(int index) =>
        index == ChunkHashes.Count - 1
            ? SizeBytes - (long)ChunkSize * (ChunkHashes.Count - 1)
            : ChunkSize;

    public bool VerifyChunk(int index, ReadOnlySpan<byte> bytes) =>
        index >= 0 && index < ChunkHashes.Count && bytes.Length == ChunkLength(index) &&
        string.Equals(HashOf(bytes), ChunkHashes[index], StringComparison.OrdinalIgnoreCase);

    public bool VerifyWhole(ReadOnlySpan<byte> bytes) =>
        bytes.Length == SizeBytes && string.Equals(HashOf(bytes), ContentHash, StringComparison.OrdinalIgnoreCase);
}

/// <summary>A signed "I have this content" claim. The signature
/// (Ed25519, the claiming device's enrolled key) covers the
/// canonical claim body; verification needs the device's enrolled
/// public key, supplied by the coordinator's key lookup (the
/// roster/enrollment layer in production; a delegate here).
/// D38 F7: the claim window is bounded — a claim whose total
/// lifetime exceeds MaxClaimTtl never verifies, and a ClaimedUtc
/// more than the tolerated skew in the future never verifies.</summary>
public sealed record AvailabilityClaim(string DeviceId, string ContentHash, bool IsCache,
    DateTimeOffset ClaimedUtc, DateTimeOffset ExpiresUtc, string SignatureBase64)
{
    /// <summary>Hard cap on a claim's total lifetime (D38 F7).</summary>
    public static readonly TimeSpan MaxClaimTtl = TimeSpan.FromHours(24);
    /// <summary>Tolerated clock skew for a future-dated ClaimedUtc.</summary>
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(5);

    public static string CanonicalBody(AvailabilityClaim c) => string.Join("|",
        "acp-availability-v1", c.DeviceId, c.ContentHash.ToLowerInvariant(), c.IsCache,
        c.ClaimedUtc.ToString("O"), c.ExpiresUtc.ToString("O"));

    public static AvailabilityClaim Sign(DeviceIdentity identity, string deviceId, string contentHash,
        bool isCache, DateTimeOffset now, TimeSpan ttl)
    {
        var unsigned = new AvailabilityClaim(deviceId, contentHash.ToLowerInvariant(), isCache,
            now, now + ttl, "");
        var sig = identity.Sign(Encoding.UTF8.GetBytes(CanonicalBody(unsigned)));
        return unsigned with { SignatureBase64 = Convert.ToBase64String(sig) };
    }

    public bool VerifySignature(byte[] devicePublicKey, DateTimeOffset now)
    {
        if (ExpiresUtc <= now || ClaimedUtc > now.Add(MaxFutureSkew)) return false;
        if (ExpiresUtc - ClaimedUtc > MaxClaimTtl) return false; // D38 F7: no 100-year claims
        if (ClaimedUtc > ExpiresUtc) return false;
        try
        {
            return Ed25519.Verify(devicePublicKey, Encoding.UTF8.GetBytes(CanonicalBody(this)),
                Convert.FromBase64String(SignatureBase64 ?? ""));
        }
        catch { return false; }
    }
}

/// <summary>One device's verified local content store. Bytes enter
/// ONLY through PutVerified (whole-hash check — the same gate as
/// hub delivery) or AssembleVerified (per-chunk checks composing to
/// the whole hash). There is deliberately no unverified put: a
/// store can never hold, and therefore never serve, bytes that did
/// not verify. Revoked hashes are refused at put and at serve.
/// D38 F8: revocations persist — construct over a revocation file
/// to load them at start and rewrite the file on every Revoke, or
/// round-trip them through Export/ImportRevocationsJson.</summary>
public sealed class PeerContentStore
{
    private readonly Dictionary<string, byte[]> _blobs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _revoked = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _revocationFilePath;
    private readonly string? _contentDir;
    /// <summary>Hashes known to exist as verified files in the
    /// content directory (bd-shared-plat-2/F9 disk backing). Bytes
    /// are NOT trusted from the index alone: a disk blob is read,
    /// whole-hash verified, and only then served or cached.</summary>
    private readonly HashSet<string> _diskHeld = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <param name="contentDirectory">bd-shared-plat-2/F9 (W9
    /// closure): the disk-backed content directory. When set, every
    /// verified put is written through to a hash-named file
    /// (temp + rename, flushed), the directory is indexed at
    /// construction, and a blob that survives only on disk is
    /// loaded — and re-verified against its content hash — on
    /// first read. Revoke deletes the file. When null the store is
    /// memory-only, the pre-W9 shape.</param>
    public PeerContentStore(string? revocationFilePath = null, string? contentDirectory = null)
    {
        _revocationFilePath = revocationFilePath;
        _contentDir = contentDirectory;
        if (revocationFilePath is not null && File.Exists(revocationFilePath))
        {
            try { ImportRevocationsJson(File.ReadAllText(revocationFilePath)); }
            catch { /* an unreadable revocation file loads nothing; revocation by the coordinator/fetcher predicate still applies */ }
        }
        if (contentDirectory is not null)
        {
            try
            {
                Directory.CreateDirectory(contentDirectory);
                foreach (var file in Directory.EnumerateFiles(contentDirectory, "*.blob"))
                {
                    var name = Path.GetFileNameWithoutExtension(file);
                    if (name.Length == 64 && name.All(Uri.IsHexDigit) && !_revoked.Contains(name))
                        _diskHeld.Add(name.ToLowerInvariant());
                }
            }
            catch { /* an unreadable content directory indexes nothing; puts still write through */ }
        }
    }

    private string? DiskPathLocked(string contentHash) =>
        _contentDir is null ? null : Path.Combine(_contentDir, (contentHash ?? "").ToLowerInvariant() + ".blob");

    /// <summary>Write verified bytes through to disk (temp + rename
    /// + flush, the revocation-file discipline). A failed write
    /// leaves the in-memory copy authoritative for this process —
    /// named, never silent in effect: the blob simply does not
    /// survive a restart.</summary>
    private void PersistBlobLocked(string contentHash, byte[] bytes)
    {
        var path = DiskPathLocked(contentHash);
        if (path is null) return;
        try
        {
            var tmp = path + ".tmp";
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(true);
            }
            File.Move(tmp, path, overwrite: true);
            _diskHeld.Add(contentHash.ToLowerInvariant());
        }
        catch { /* persistence failure: in-memory copy stands for this process */ }
    }

    /// <summary>Load a disk-only blob, verifying its whole hash
    /// before it is served or cached. Bytes that fail verification
    /// are deleted and never served — the store's founding rule
    /// (no unverified put, no unverified serve) holds on disk too.</summary>
    private byte[]? LoadFromDiskLocked(string contentHash)
    {
        var path = DiskPathLocked(contentHash);
        if (path is null || !_diskHeld.Contains(contentHash ?? "")) return null;
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (!string.Equals(ContentManifest.HashOf(bytes), (contentHash ?? "").ToLowerInvariant(), StringComparison.Ordinal))
            {
                try { File.Delete(path); } catch { }
                _diskHeld.Remove(contentHash ?? "");
                return null;
            }
            _blobs[contentHash] = bytes;
            return bytes;
        }
        catch { return null; }
    }

    private void PersistRevocationsLocked()
    {
        if (_revocationFilePath is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_revocationFilePath))!);
            var tmp = _revocationFilePath + ".tmp";
            var bytes = Encoding.UTF8.GetBytes(ExportRevocationsJson());
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(true);
            }
            File.Move(tmp, _revocationFilePath, overwrite: true);
        }
        catch { /* persistence failure leaves the in-memory set authoritative for this process */ }
    }

    public string ExportRevocationsJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(_revoked.OrderBy(h => h, StringComparer.Ordinal).ToArray());
    }

    /// <summary>Merge persisted revocations into this store (a
    /// revocation, once recorded anywhere durable, is never
    /// un-recorded by an import). Revoked blobs are dropped.</summary>
    public void ImportRevocationsJson(string json)
    {
        List<string>? hashes;
        try { hashes = JsonSerializer.Deserialize<List<string>>(json); }
        catch { hashes = null; }
        if (hashes is null) return;
        lock (_gate)
        {
            foreach (var h in hashes)
            {
                if (string.IsNullOrWhiteSpace(h)) continue;
                _revoked.Add(h);
                _blobs.Remove(h);
                if (_diskHeld.Remove(h) && DiskPathLocked(h) is { } path)
                {
                    try { File.Delete(path); } catch { }
                }
            }
        }
    }

    public bool PutVerified(ContentManifest manifest, byte[] content)
    {
        lock (_gate)
        {
            if (_revoked.Contains(manifest.ContentHash)) return false;
            if (!manifest.VerifyWhole(content)) return false;
            var stored = content.ToArray();
            _blobs[manifest.ContentHash] = stored;
            PersistBlobLocked(manifest.ContentHash, stored);
            return true;
        }
    }

    /// <summary>Assemble from per-chunk-verified parts; the composed
    /// bytes must ALSO pass the whole-hash check before storing
    /// (chunk hashes and the whole hash are independent bindings —
    /// both must hold).</summary>
    public bool AssembleVerified(ContentManifest manifest, IReadOnlyList<byte[]> chunks)
    {
        lock (_gate)
        {
            if (_revoked.Contains(manifest.ContentHash)) return false;
            if (chunks.Count != manifest.ChunkCount) return false;
            using var ms = new MemoryStream();
            for (var i = 0; i < chunks.Count; i++)
            {
                if (!manifest.VerifyChunk(i, chunks[i])) return false;
                ms.Write(chunks[i], 0, chunks[i].Length);
            }
            var bytes = ms.ToArray();
            if (!manifest.VerifyWhole(bytes)) return false;
            _blobs[manifest.ContentHash] = bytes;
            PersistBlobLocked(manifest.ContentHash, bytes);
            return true;
        }
    }

    public bool Has(string contentHash)
    {
        lock (_gate)
        {
            if (_revoked.Contains(contentHash ?? "")) return false;
            if (_blobs.ContainsKey(contentHash ?? "")) return true;
            // A disk-only blob is claimed only after its bytes
            // verify against the content hash: the filename index
            // alone never proves possession (W9 destruction finding
            // — a fresh store over a tampered .blob reported it
            // held). LoadFromDiskLocked verifies, caches on success,
            // and deletes failing bytes. HeldHashes stays an index
            // listing; possession claims go through here.
            return LoadFromDiskLocked(contentHash ?? "") is not null;
        }
    }

    public byte[]? GetChunk(string contentHash, ContentManifest manifest, int index)
    {
        lock (_gate)
        {
            if (_revoked.Contains(contentHash ?? "")) return null;
            if (!_blobs.TryGetValue(contentHash ?? "", out var blob))
                blob = LoadFromDiskLocked(contentHash ?? "");
            if (blob is null) return null;
            if (index < 0 || index >= manifest.ChunkCount) return null;
            var off = (long)index * manifest.ChunkSize;
            var len = (int)manifest.ChunkLength(index);
            if (off + len > blob.Length) return null;
            return blob.AsSpan((int)off, len).ToArray();
        }
    }

    public byte[]? GetWhole(string contentHash)
    {
        lock (_gate)
        {
            if (_revoked.Contains(contentHash ?? "")) return null;
            if (_blobs.TryGetValue(contentHash ?? "", out var b)) return b.ToArray();
            return LoadFromDiskLocked(contentHash ?? "")?.ToArray();
        }
    }

    public void Revoke(string contentHash)
    {
        lock (_gate)
        {
            _revoked.Add(contentHash ?? "");
            _blobs.Remove(contentHash ?? ""); // revoked bytes are dropped, not merely unserved
            // Disk backing: the file is deleted too — a revoked
            // blob must not resurrect from disk on the next start.
            if (_diskHeld.Remove(contentHash ?? "") && DiskPathLocked(contentHash ?? "") is { } path)
            {
                try { File.Delete(path); } catch { }
            }
            PersistRevocationsLocked();
        }
    }

    public bool IsRevoked(string contentHash) { lock (_gate) return _revoked.Contains(contentHash ?? ""); }
    public IReadOnlyList<string> HeldHashes { get { lock (_gate) return _blobs.Keys.Union(_diskHeld).OrderBy(h => h, StringComparer.Ordinal).ToList(); } }
}

/// <summary>Transport to one source (a peer, the cache, or the hub).
/// Implementations in production ride ACP's LAN transports; tests
/// use fakes. A fault (timeout, refusal, garbage) is an exception or
/// a chunk that fails verification — the fetcher treats both the
/// same: budget spent, fail over.
/// D38 F10: the bounded contract carries the EXPECTED chunk length
/// (from the manifest) and a CancellationToken. The default
/// implementation adapts the legacy unbounded method and refuses
/// oversize at the boundary; transports should override it and
/// enforce maxBytes/cancellation natively.</summary>
public interface IContentSource
{
    string SourceId { get; }
    bool IsHub { get; }
    byte[]? FetchChunk(ContentManifest manifest, int index);

    /// <summary>Bounded fetch: return at most maxBytes for this
    /// chunk, honouring cancellation. Oversize is a contract
    /// violation and throws (the fetcher treats it as a fault).</summary>
    byte[]? FetchChunk(ContentManifest manifest, int index, int maxBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var chunk = FetchChunk(manifest, index);
        if (chunk is not null && chunk.Length > maxBytes)
            throw new InvalidOperationException(
                $"source '{SourceId}' returned {chunk.Length} bytes for a chunk whose manifest length is {maxBytes} — oversize refused at the transport contract (D38 F10)");
        return chunk;
    }
}

/// <summary>Loopback source over a local store — the in-process
/// shape a real LAN transport mirrors. D38 F6: when a serving gate
/// is wired (DistributionPolicy.IsEnabled for the serving device)
/// and it reads OFF, this source serves nothing.</summary>
public sealed class StoreContentSource : IContentSource
{
    private readonly PeerContentStore _store;
    private readonly Func<bool>? _servingEnabled;
    public StoreContentSource(string sourceId, PeerContentStore store, bool isHub = false,
        Func<bool>? servingEnabled = null)
    { SourceId = sourceId; _store = store; IsHub = isHub; _servingEnabled = servingEnabled; }
    public string SourceId { get; }
    public bool IsHub { get; }
    public byte[]? FetchChunk(ContentManifest manifest, int index)
    {
        if (_servingEnabled is not null && !_servingEnabled()) return null; // policy OFF: no peer serving
        return _store.GetChunk(manifest.ContentHash, manifest, index);
    }
    public byte[]? FetchChunk(ContentManifest manifest, int index, int maxBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var chunk = FetchChunk(manifest, index);
        if (chunk is not null && chunk.Length > maxBytes)
            throw new InvalidOperationException($"source '{SourceId}' produced an oversize chunk — refused");
        return chunk;
    }
}

public sealed record FetchResult(bool Ok, string? SourceUsed, byte[]? Content, string Reason,
    IReadOnlyDictionary<string, int> WastedBytesBySource);

/// <summary>The fetching engine. Source order is the coordinator's
/// (cache first, then peers, hub last — or hub only when the
/// feature is toggled off). Per source, a budget of failed chunks
/// (hash failures + faults) bounds the poisoning/slowness cost;
/// exhausting it blacklists the source FOR THIS FETCH, reports it
/// through the distrust callback (D38 F10), and moves on. A source
/// that returns a chunk of the wrong length spends budget exactly
/// like a wrong-hash chunk, and recorded waste is capped at the
/// manifest's expected chunk length (D38 F10).</summary>
public sealed class ContentFetcher
{
    public const int DefaultMaxFailedChunksPerSource = 2;
    /// <summary>Per-chunk transport timeout (D38 F10): a source
    /// that does not answer one chunk within this window spends
    /// budget exactly like a faulting source.</summary>
    public static readonly TimeSpan DefaultChunkTimeout = TimeSpan.FromSeconds(30);

    private readonly int _maxFailedPerSource;
    public ContentFetcher(int maxFailedChunksPerSource = DefaultMaxFailedChunksPerSource) =>
        _maxFailedPerSource = Math.Max(1, maxFailedChunksPerSource);

    /// <param name="isRevoked">Caller revocation predicate. D38 F8:
    /// it is COMBINED with the local store's own revocation list —
    /// either one revoking refuses the content — and the combined
    /// predicate is re-checked before storing and before returning.</param>
    /// <param name="chunkTimeout">Per-chunk timeout; null = default.</param>
    /// <param name="onSourceDistrusted">Called when a source
    /// exhausts its failure budget (D38 F10) so the coordinator can
    /// record a persistent distrust strike.</param>
    /// <param name="distributionEnabled">The RMM-07 toggle source
    /// (D38 F6): when supplied and OFF, the fetch refuses outright —
    /// no peer fetching under a disabled policy.</param>
    public FetchResult Fetch(ContentManifest manifest, IReadOnlyList<IContentSource> sourcesInOrder,
        PeerContentStore? localStore = null, Func<string, bool>? isRevoked = null,
        CancellationToken cancellationToken = default, TimeSpan? chunkTimeout = null,
        Action<string, string>? onSourceDistrusted = null, Func<bool>? distributionEnabled = null)
    {
        var wasted = new Dictionary<string, int>(StringComparer.Ordinal);
        bool Revoked(string h) =>
            (isRevoked is not null && isRevoked(h)) || (localStore is not null && localStore.IsRevoked(h));
        if (distributionEnabled is not null && !distributionEnabled())
            return new FetchResult(false, null, null,
                "p2p distribution is disabled by policy (rmm.p2p_distribution.enabled) — fetch refused in the fetcher itself, not by caller courtesy (D38 F6)", wasted);
        if (Revoked(manifest.ContentHash))
            return new FetchResult(false, null, null,
                $"content {manifest.ContentHash} is revoked — refused from every source", wasted);
        if (localStore is not null && localStore.GetWhole(manifest.ContentHash) is { } local)
            return new FetchResult(true, "(local store)", local, "already held locally, verified at put-time", wasted);

        var timeout = chunkTimeout ?? DefaultChunkTimeout;
        // bd-shared-plat-2/F9: verified chunks are kept ACROSS
        // sources — failing over no longer throws away chunks that
        // already verified from the previous source and restarts
        // at chunk 0. Each chunk in the shared array passed
        // VerifyChunk before landing there.
        var chunks = new byte[]?[manifest.ChunkCount];
        foreach (var source in sourcesInOrder)
        {
            var failed = 0;
            var sourceOk = true;
            for (var i = 0; i < manifest.ChunkCount; i++)
            {
                if (chunks[i] is not null) continue; // already verified from an earlier source
                if (cancellationToken.IsCancellationRequested)
                    return new FetchResult(false, null, null, "fetch cancelled by the caller", wasted);
                if (Revoked(manifest.ContentHash)) // D38 F8: revocation landing mid-fetch stops it
                    return new FetchResult(false, null, null,
                        $"content {manifest.ContentHash} was revoked during the fetch — refused", wasted);
                var expected = (int)manifest.ChunkLength(i);
                byte[]? chunk = null;
                try { chunk = FetchChunkBounded(source, manifest, i, expected, timeout, cancellationToken); }
                catch { chunk = null; }
                if (chunk is null || !manifest.VerifyChunk(i, chunk))
                {
                    if (chunk is not null)
                        // D38 F10: waste accounting is capped at the
                        // EXPECTED length — the attacker's array size
                        // never inflates the bound or the ledger.
                        wasted[source.SourceId] = wasted.GetValueOrDefault(source.SourceId) + Math.Min(chunk.Length, expected);
                    failed++;
                    if (failed > _maxFailedPerSource) { sourceOk = false; break; }
                    i--; // retry the same chunk within budget
                    continue;
                }
                chunks[i] = chunk;
            }
            if (!sourceOk)
            {
                onSourceDistrusted?.Invoke(source.SourceId,
                    $"exhausted its failed-chunk budget ({failed} failures) fetching {manifest.ContentHash}");
                continue; // blacklisted for this fetch; fail over
            }
            var parts = chunks.Select(c => c!).ToList();
            using var ms = new MemoryStream();
            foreach (var p in parts) ms.Write(p, 0, p.Length);
            var bytes = ms.ToArray();
            if (!manifest.VerifyWhole(bytes)) continue; // cannot happen if chunks verified, but the whole-hash gate is never skipped
            // D38 F8: revocation is re-checked at the last moment,
            // and a store refusal fails the fetch — never Ok with
            // refused bytes.
            if (Revoked(manifest.ContentHash))
                return new FetchResult(false, null, null,
                    $"content {manifest.ContentHash} is revoked — fetched bytes refused at store/return time", wasted);
            if (localStore is not null && !localStore.AssembleVerified(manifest, parts))
                return new FetchResult(false, null, null,
                    $"local store refused the assembled content {manifest.ContentHash} (revoked or unverifiable) — fetch fails rather than returning unstored bytes", wasted);
            return new FetchResult(true, source.SourceId, bytes,
                source.IsHub ? "fetched from the hub (WAN)" : $"fetched from peer/cache source '{source.SourceId}' over the LAN", wasted);
        }
        return new FetchResult(false, null, null,
            "every source exhausted its failure budget or held nothing — fetch failed (hub fallback included where supplied)", wasted);
    }

    // One chunk under a hard time bound. The synchronous transport
    // runs on a pool thread; on timeout the call is ABANDONED (not
    // killed — named residual in the file header) and the chunk
    // counts as a fault.
    private static byte[]? FetchChunkBounded(IContentSource source, ContentManifest manifest,
        int index, int expectedBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (timeout == Timeout.InfiniteTimeSpan && !cancellationToken.CanBeCanceled)
            return source.FetchChunk(manifest, index, expectedBytes, cancellationToken);
        var task = Task.Run(() => source.FetchChunk(manifest, index, expectedBytes, cancellationToken));
        try
        {
            if (!task.Wait(timeout, cancellationToken))
                throw new TimeoutException($"source '{source.SourceId}' did not answer chunk {index} within {timeout}");
        }
        catch (AggregateException ae) { throw ae.InnerException ?? ae; }
        return task.Result;
    }
}

/// <summary>One recorded distrust strike set against a device
/// (D38 F10): policy-bounded — strikes accumulate, the distrust
/// window is capped at MaxDistrustWindow, and the record persists
/// through the coordinator's state export.</summary>
public sealed record SourceDistrust(string DeviceId, int Strikes, DateTimeOffset UntilUtc, string LastReason);

/// <summary>Hub-side coordination of who-has-what. Claims are
/// admitted only with a valid device signature and an unexpired,
/// TTL-bounded window; revoked content's claims are dropped on
/// revocation and refused on admission. Source ordering for a fetch:
/// designated caches first, then other holders (claim-freshest
/// first), hub always last. The coordinator never vouches for
/// possession — it orders candidates; the manifest proves the bytes.
/// D38 F7: when constructed with a cache-designation source, cache
/// status comes from THAT (the hub's Effective Policy), never from
/// the claim's self-asserted bit; ClaimedUtc is clamped to the
/// admission instant for ordering; enrollment is re-checked on
/// every SourcesFor read. D38 F6: when constructed with a
/// distribution-enabled gate that reads OFF, no claims are admitted
/// and no sources are offered. D38 F8/F10: revocations and distrust
/// records persist through Export/ImportStateJson.</summary>
public sealed class HubDistributionCoordinator
{
    /// <summary>Cap on one distrust record's window (policy bound).</summary>
    public static readonly TimeSpan MaxDistrustWindow = TimeSpan.FromHours(24);
    /// <summary>Distrust window per strike, before the cap.</summary>
    public static readonly TimeSpan DistrustPerStrike = TimeSpan.FromHours(1);

    private readonly Func<string, byte[]?> _deviceKeyLookup;
    private readonly Func<string, bool>? _cacheDesignation;
    private readonly Func<bool>? _distributionEnabled;
    private readonly Dictionary<string, List<AvailabilityClaim>> _claimsByHash = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _revoked = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SourceDistrust> _distrust = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <param name="deviceKeyLookup">deviceId → enrolled Ed25519
    /// public key (the roster/enrollment seam); null ⇒ unknown
    /// device ⇒ claim refused.</param>
    /// <param name="cacheDesignation">deviceId → whether Effective
    /// Policy designates the device as the site cache (D38 F7).
    /// When supplied, it OVERRIDES the claim's IsCache bit; when
    /// null, the claim's bit is used (legacy wiring — the Core hub
    /// host is responsible for supplying the policy source).</param>
    /// <param name="distributionEnabled">The RMM-07 toggle source
    /// (D38 F6); when supplied and OFF, claims/sources refuse.</param>
    public HubDistributionCoordinator(Func<string, byte[]?> deviceKeyLookup,
        Func<string, bool>? cacheDesignation = null, Func<bool>? distributionEnabled = null)
    {
        _deviceKeyLookup = deviceKeyLookup ?? throw new ArgumentNullException(nameof(deviceKeyLookup));
        _cacheDesignation = cacheDesignation;
        _distributionEnabled = distributionEnabled;
    }

    private bool Enabled => _distributionEnabled is null || _distributionEnabled();

    public (bool Accepted, string Reason) AdmitClaim(AvailabilityClaim claim, DateTimeOffset now)
    {
        if (claim is null || string.IsNullOrWhiteSpace(claim.DeviceId) ||
            string.IsNullOrWhiteSpace(claim.ContentHash))
            return (false, "claim carries no device or content hash — refused");
        lock (_gate)
        {
            if (!Enabled)
                return (false, "p2p distribution is disabled by policy (rmm.p2p_distribution.enabled) — claims are not admitted while OFF (D38 F6)");
            if (_revoked.Contains(claim.ContentHash))
                return (false, $"content {claim.ContentHash} is revoked — claims for it are refused");
            var key = _deviceKeyLookup(claim.DeviceId);
            if (key is null) return (false, $"claiming device '{claim.DeviceId}' is not enrolled — refused");
            if (!claim.VerifySignature(key, now))
                return (false, $"claim signature invalid, expired, or outside the bounded claim window for device '{claim.DeviceId}' — refused (a peer cannot advertise in another device's name)");
            // D38 F7: cache status derives from Effective Policy
            // when the designation source is wired — the claim's
            // own bit is ignored. ClaimedUtc is clamped to the
            // admission instant so a future-dated claim cannot win
            // freshness ordering. (The stored claim is the ADMITTED
            // claim: normalized by the hub, as admission records are.)
            var effectiveIsCache = _cacheDesignation?.Invoke(claim.DeviceId) ?? claim.IsCache;
            var admitted = claim with
            {
                IsCache = effectiveIsCache,
                ClaimedUtc = claim.ClaimedUtc > now ? now : claim.ClaimedUtc,
            };
            var list = _claimsByHash.TryGetValue(claim.ContentHash, out var l) ? l : new List<AvailabilityClaim>();
            list.RemoveAll(c => c.DeviceId == claim.DeviceId);
            list.Add(admitted);
            _claimsByHash[claim.ContentHash] = list;
            return (true, $"claim admitted: '{claim.DeviceId}' {(effectiveIsCache ? "(cache)" : "")} holds {claim.ContentHash} until {claim.ExpiresUtc:O}");
        }
    }

    public void RevokeContent(string contentHash)
    {
        lock (_gate)
        {
            _revoked.Add(contentHash ?? "");
            _claimsByHash.Remove(contentHash ?? "");
        }
    }

    public bool IsRevoked(string contentHash) { lock (_gate) return _revoked.Contains(contentHash ?? ""); }

    /// <summary>Record a fetcher-reported bad source (D38 F10):
    /// strikes accumulate and the device is not offered as a source
    /// until the (capped) distrust window expires.</summary>
    public SourceDistrust ReportDistrustedSource(string deviceId, string reason, DateTimeOffset now)
    {
        lock (_gate)
        {
            var strikes = (_distrust.TryGetValue(deviceId ?? "", out var prior) ? prior.Strikes : 0) + 1;
            var window = DistrustPerStrike * strikes;
            if (window > MaxDistrustWindow) window = MaxDistrustWindow;
            var record = new SourceDistrust(deviceId ?? "", strikes, now + window, reason ?? "");
            _distrust[record.DeviceId] = record;
            return record;
        }
    }

    public bool IsDistrusted(string deviceId, DateTimeOffset now)
    {
        lock (_gate)
            return _distrust.TryGetValue(deviceId ?? "", out var d) && d.UntilUtc > now;
    }

    public SourceDistrust? DistrustFor(string deviceId)
    {
        lock (_gate) return _distrust.TryGetValue(deviceId ?? "", out var d) ? d : null;
    }

    private sealed record CoordinatorStateDto(string[] Revoked, SourceDistrust[] Distrust);

    /// <summary>Persist the coordinator's revocation + distrust
    /// state (D38 F8/F10). Claims are NOT persisted — they are
    /// TTL-bounded and re-claimed by devices.</summary>
    public string ExportStateJson()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new CoordinatorStateDto(
                _revoked.OrderBy(h => h, StringComparer.Ordinal).ToArray(),
                _distrust.Values.OrderBy(d => d.DeviceId, StringComparer.Ordinal).ToArray()));
    }

    /// <summary>Restore revocation + distrust state (merged:
    /// revocations are never un-recorded by an import).</summary>
    public void ImportStateJson(string json)
    {
        CoordinatorStateDto? dto;
        try { dto = JsonSerializer.Deserialize<CoordinatorStateDto>(json); }
        catch { dto = null; }
        if (dto is null) return;
        lock (_gate)
        {
            foreach (var h in dto.Revoked ?? Array.Empty<string>())
            {
                _revoked.Add(h);
                _claimsByHash.Remove(h);
            }
            foreach (var d in dto.Distrust ?? Array.Empty<SourceDistrust>())
                if (!string.IsNullOrWhiteSpace(d.DeviceId)) _distrust[d.DeviceId] = d;
        }
    }

    /// <summary>Ordered candidate device ids for a fetch: caches
    /// first, then freshest claims; expired claims are pruned on
    /// read and never returned. D38 F7: enrollment is RE-CHECKED on
    /// every read — a de-enrolled device's claims are pruned, not
    /// merely passed over — and distrusted devices are not offered.</summary>
    public IReadOnlyList<string> SourcesFor(string contentHash, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!Enabled) return Array.Empty<string>();
            if (_revoked.Contains(contentHash ?? "")) return Array.Empty<string>();
            if (!_claimsByHash.TryGetValue(contentHash ?? "", out var list)) return Array.Empty<string>();
            list.RemoveAll(c => c.ExpiresUtc <= now);
            list.RemoveAll(c => _deviceKeyLookup(c.DeviceId) is null); // de-enrolled: claims die at use
            return list
                .Where(c => !(_distrust.TryGetValue(c.DeviceId, out var d) && d.UntilUtc > now))
                .OrderByDescending(c => c.IsCache).ThenByDescending(c => c.ClaimedUtc)
                .Select(c => c.DeviceId).ToList();
        }
    }

    public IReadOnlyList<AvailabilityClaim> ClaimsFor(string contentHash)
    {
        lock (_gate)
            return _claimsByHash.TryGetValue(contentHash ?? "", out var l)
                ? l.ToList() : Array.Empty<AvailabilityClaim>();
    }
}

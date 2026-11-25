using System.Globalization;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.Security;

namespace Acp.Shared.Backup;

// =====================================================================
// RMM-06 — the snapshot store (immutability), the backup engine
// (runs as RMM-15 jobs), the restore engine (file / image-browse /
// bare-metal plan / self-restore), storage accounting, and the
// RMM-01 HEALTH-FACTS SEAM.
//
// IMMUTABILITY, stated precisely: a SEALED snapshot cannot be
// modified or deleted before its retention expiry — by the end
// user, by the endpoint agent itself, or under a hub-issued signed
// command. The store's public surface has NO delete for a sealed
// snapshot at all (TryDeleteSnapshot exists so a hub command has
// something to be refused BY, with the refusal audited). The only
// removal path is TryPurgeExpired, and it is guarded twice:
//   1. retention: now must be at/after the snapshot's own expiry;
//   2. clock discipline: the store keeps a persisted high-water
//      mark of every time it has ever observed. Rolling the clock
//      FORWARD past the high-water by more than MaxUnattestedClock
//      Jump refuses the purge unless the caller presents a
//      hub-signed time attestation (RMM-03, class automation,
//      payload binding this target + the attested time) — the hub
//      is the fleet's trusted time source, a rolled endpoint clock
//      is not. Jumped readings FREEZE the effective time at the
//      high-water (they never advance it — a refused operation
//      must not be able to launder a roll into trusted time; the
//      destruction pass found and closed exactly that). Rolling
//      the clock BACK never helps an attacker: the effective time
//      is max(presented, high-water). D38 F4 bound: unattested
//      advance of the mark is anchored to REAL elapsed time (see
//      TrustedCeilingLocked) — a tight loop of ≤48h steps cannot
//      ratchet a lock away in seconds; trusted time accrues at the
//      rate real time passes, and only a hub-signed attestation
//      re-anchors across a jump. Named residual: an attacker who
//      controls the endpoint clock continuously AND waits real
//      time can still ratchet at real-time speed — indistinguishable
//      from honest passage of time at this layer; storage-side
//      object lock (host wiring) is the backstop.
//
// VERIFIED BYTES (the RMM-15 full-bytes discipline, applied to
// backup): a run completes only after every chunk it wrote is read
// BACK from storage and re-hashed. A capture that yields nothing
// for a non-empty selection fails as empty_capture — a backup job
// NEVER reports success while writing nothing.
//
// RESTORE INTEGRITY: every restored file is reassembled from
// chunks, each chunk hash-verified (content addressing), and the
// assembled file re-hashed against the manifest before a single
// byte is written to the target. A manifest that lies about its
// contents fails the restore by name and rolls back the files the
// restore already wrote.
//
// RMM-01 HEALTH-FACTS SEAM (named): BackupHealthFacts +
// BackupHealthEvaluator + IBackupHealthFactsProvider (implemented
// by BackupEngine). Findings carry RMM-06 condition ids/kinds
// (BackupConditionKinds) shaped exactly for RMM-01's
// HealthAlertCentre.Raise(deviceId, finding.ConditionId,
// finding.Kind, finding.Severity, finding.Detail, "backup",
// cooldown, now) — the monitor consumes them as data; this lane
// edits no Monitoring file.
// =====================================================================

/// <summary>RMM-06's alert condition kinds + ids — the vocabulary
/// of the health-facts seam. Failed/stale backup is a first-class
/// alert condition under RMM-01 per the directive; these kinds are
/// what the monitor raises.</summary>
public static class BackupConditionKinds
{
    public const string BackupFailed = "backup_failed";
    public const string BackupStale = "backup_stale";
    public const string BackupNeverRun = "backup_never_run";
    public const string BackupStorageUnreachable = "backup_storage_unreachable";
    public const string BackupCatalogueTampered = "backup_catalogue_tampered";

    public static string ConditionId(string kind, string jobId) => $"backup:{kind}:{jobId}";
    public static string DeviceConditionId(string kind, string deviceId) => $"backup:{kind}:{deviceId}";
}

// ---- the snapshot store --------------------------------------------------

public sealed record PurgeOutcome(bool Purged, string Reason);
public sealed record DeleteOutcome(bool Deleted, string Reason);

/// <summary>The immutable snapshot store over one raw storage
/// target. Thread-safe; all state moves under one gate. The
/// catalogue (snapshot records + high-water mark) persists as one
/// JSON document written temp+replace by the caller-facing
/// Save/Load pair; on load the hash chain is verified and a broken
/// chain marks the catalogue TAMPERED — restores and purges refuse
/// until an operator deals with it, because a catalogue that was
/// rewritten cannot be trusted to say what is locked or whose a
/// snapshot is.</summary>
public sealed class BackupSnapshotStore
{
    public const int ChunkSizeBytes = 256 * 1024;
    public const string CatalogueGenesis = "GENESIS";

    /// <summary>How far the presented clock may run ahead of the
    /// store's high-water mark before a purge demands a hub-signed
    /// time attestation.</summary>
    public static readonly TimeSpan MaxUnattestedClockJump = TimeSpan.FromHours(48);

    private readonly IBackupStorage _storage;
    private readonly SignedCommandVerifier? _timeVerifier;
    // W10 / V2-C1: the at-rest data key (null = legacy plaintext
    // store, a deliberate construction choice — never a fallback).
    private readonly byte[]? _atRestKey;
    private readonly string? _atRestKeyId;
    private readonly List<BackupSnapshot> _catalogue = new();
    private readonly Dictionary<string, BackupManifest> _staged = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _captureStartedUtc = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private DateTimeOffset _highWaterUtc = DateTimeOffset.MinValue;
    // D38 F4: the unattested advance of the high-water mark is
    // anchored to REAL elapsed time. The anchor pairs the presented
    // time at genesis (or at the last verified attestation / verified
    // catalogue import) with the wall-clock time then; the mark may
    // run ahead of the anchor by at most (real elapsed since the
    // anchor) + MaxUnattestedClockJump. A tight in-process loop of
    // ≤48h steps therefore cannot ratchet a 30-day lock away in
    // seconds — unattested trusted time accrues at the rate real
    // time passes, and only a hub-signed attestation re-anchors
    // across a jump.
    private DateTimeOffset _anchorPresentedUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _anchorRealUtc = DateTimeOffset.MinValue;
    private readonly Dictionary<string, (string BytesHash, BackupManifest Manifest)> _manifestCache = new(StringComparer.Ordinal);
    private bool _catalogueTampered;
    private string _catalogueState = "OK: empty catalogue";

    /// <param name="atRestKey">W10 / V2-C1: the 32-byte AES key
    /// sealing every chunk and manifest at rest (see BackupAtRest).
    /// When supplied, plaintext blobs are REFUSED (no silent
    /// downgrade) and the key's fingerprint is bound into the
    /// catalogue chain. When null the store keeps the legacy
    /// plaintext shape — host wiring supplies a key through
    /// BackupAtRest.LoadOrCreateKeyFile (DPAPI-wrapped custody).</param>
    public BackupSnapshotStore(string targetId, IBackupStorage storage, SignedCommandVerifier? timeVerifier = null,
        byte[]? atRestKey = null)
    {
        TargetId = targetId ?? throw new ArgumentNullException(nameof(targetId));
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _timeVerifier = timeVerifier;
        if (atRestKey is not null)
        {
            if (atRestKey.Length != BackupAtRest.KeyBytes)
                throw new ArgumentException($"a backup at-rest key is exactly {BackupAtRest.KeyBytes} bytes", nameof(atRestKey));
            _atRestKey = atRestKey.ToArray();
            _atRestKeyId = BackupAtRest.KeyId(_atRestKey);
        }
    }

    public string TargetId { get; }

    /// <summary>Whether this store seals blobs at rest, and under
    /// which key fingerprint (null = plaintext store).</summary>
    public bool EncryptionAtRestEnabled => _atRestKey is not null;
    public string? EncryptionKeyId => _atRestKeyId;

    /// <summary>Seal bytes for storage under this store's key
    /// discipline; identity when no key is configured.</summary>
    private byte[] SealForStorage(string storageKey, byte[] plaintext) =>
        _atRestKey is null ? plaintext : BackupAtRest.Seal(_atRestKey, storageKey, plaintext);

    /// <summary>Open stored bytes under this store's key discipline.
    /// With a key configured, an unsealed or undecryptable blob is a
    /// named refusal (BackupAtRest.Open) — never a plaintext pass.</summary>
    private byte[] OpenFromStorage(string storageKey, byte[] stored) =>
        _atRestKey is null ? stored : BackupAtRest.Open(_atRestKey, storageKey, stored);
    public bool CatalogueTampered { get { lock (_gate) return _catalogueTampered; } }

    /// <summary>Raw-storage reachability probe for the health
    /// facts: a listing that throws means the target is gone.</summary>
    public bool StorageReachable
    {
        get { try { _ = _storage.ListKeys("chunks/"); return true; } catch { return false; } }
    }

    public long? StorageFreeBytes
    {
        get { try { return _storage.FreeBytes; } catch { return null; } }
    }

    /// <summary>Free-space percentage needs the volume total, which
    /// the raw store does not claim — reported as unknown rather
    /// than invented.</summary>
    public double? StorageFreePercent => null;

    /// <summary>The catalogue's current chain head — anchored into
    /// the chained audit log by the engine on seal and purge, so a
    /// recomputed catalogue disagrees with the audit history.</summary>
    public string CatalogueHeadHash
    {
        get { lock (_gate) return _catalogue.Count == 0 ? CatalogueGenesis : _catalogue[^1].CatalogueHash; }
    }
    public string CatalogueState { get { lock (_gate) return _catalogueState; } }
    public DateTimeOffset HighWaterUtc { get { lock (_gate) return _highWaterUtc; } }

    public IReadOnlyList<BackupSnapshot> Snapshots
    {
        get { lock (_gate) return _catalogue.OrderBy(s => s.CapturedUtc).ToList(); }
    }

    public BackupSnapshot? GetSnapshot(string? snapshotId)
    {
        lock (_gate) return snapshotId is not null && _catalogue.FirstOrDefault(s => s.Id == snapshotId) is { } s ? s : null;
    }

    /// <summary>The effective time for a presented reading. A
    /// reading within MaxUnattestedClockJump of the high-water
    /// advances it (normal passage of time, including a device
    /// that was off for a day or two). A reading BEYOND the jump
    /// bound FREEZES the effective time at the high-water: the
    /// reading is untrusted, and letting it advance the mark would
    /// let any refused operation (a delete attempt, a failed
    /// attestation) launder a clock roll into trusted time. Only a
    /// hub-signed attestation advances the mark across a jump
    /// (TryPurgeExpired). Rolling BACK never lowers the mark.</summary>
    private void AnchorLocked(DateTimeOffset presented)
    {
        _anchorPresentedUtc = presented;
        _anchorRealUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>The furthest the high-water mark may advance without
    /// a hub attestation: the anchored presented time plus the REAL
    /// time elapsed since the anchor, plus one jump bound of grace
    /// (a device off for a day or two, clock skew).</summary>
    private DateTimeOffset TrustedCeilingLocked() =>
        _anchorPresentedUtc == DateTimeOffset.MinValue
            ? DateTimeOffset.MaxValue
            : _anchorPresentedUtc + (DateTimeOffset.UtcNow - _anchorRealUtc) + MaxUnattestedClockJump;

    private DateTimeOffset EffectiveNowLocked(DateTimeOffset now)
    {
        if (_highWaterUtc == DateTimeOffset.MinValue) { _highWaterUtc = now; AnchorLocked(now); return now; } // genesis: the first reading establishes the mark + anchor
        if (now > _highWaterUtc + MaxUnattestedClockJump) return _highWaterUtc;
        if (now > _highWaterUtc)
        {
            // D38 F4: within the per-call jump bound is not enough —
            // the advance must also fit inside the real-time-anchored
            // ceiling, so repeated ≤48h steps in a tight loop freeze
            // at the ceiling instead of ratcheting the mark.
            if (now > TrustedCeilingLocked()) return _highWaterUtc;
            _highWaterUtc = now;
        }
        return _highWaterUtc > now ? _highWaterUtc : now;
    }

    /// <summary>Observe a time (every public operation does this;
    /// Core wiring also calls it on heartbeat). The high-water mark
    /// only ever moves forward.</summary>
    public void ObserveTime(DateTimeOffset now) { lock (_gate) EffectiveNowLocked(now); }

    // -- capture staging --

    /// <summary>Begin a capturing snapshot. Not yet in the
    /// catalogue: an aborted capture leaves no record pretending to
    /// be a backup.</summary>
    public string BeginSnapshot(BackupJobDefinition job, DateTimeOffset now)
    {
        lock (_gate)
        {
            EffectiveNowLocked(now);
            var id = Guid.NewGuid().ToString("N");
            _staged[id] = new BackupManifest(id, job.Id, job.DeviceId, job.OwnerUserId, job.Kind,
                Array.Empty<BackupManifestEntry>(), Array.Empty<VolumeDescriptor>());
            _captureStartedUtc[id] = now;
            return id;
        }
    }

    /// <summary>Write one chunk (content-addressed: the key IS the
    /// hash of the PLAINTEXT bytes, computed here — a caller cannot
    /// name a chunk anything but what it is). The stored bytes are
    /// sealed when an at-rest key is configured (W10 / V2-C1).
    /// Returns the chunk hash.</summary>
    public string WriteChunk(byte[] bytes)
    {
        var hash = BackupHashing.Sha256Hex(bytes);
        var storageKey = $"chunks/{hash}";
        _storage.Put(storageKey, SealForStorage(storageKey, bytes));
        return hash;
    }

    /// <summary>Split content into chunks, write them, and return
    /// the manifest entry. An empty file is one zero-length entry
    /// with no chunks and the hash of empty content.</summary>
    public BackupManifestEntry AddFile(string snapshotId, string relativePath, byte[] content)
    {
        var pathError = ValidateManifestPath(relativePath);
        if (pathError is not null) throw new ArgumentException(pathError, nameof(relativePath));
        // W12 / DS-P9-F21: validate the snapshot is capturing BEFORE
        // writing any chunks — an AddFile for an unknown/aborted id
        // previously wrote permanent unreferenced chunk blobs, and a
        // racing AbortSnapshot GC could delete a just-written chunk.
        lock (_gate)
        {
            if (!_staged.ContainsKey(snapshotId))
                throw new InvalidOperationException($"snapshot '{snapshotId}' is not capturing — files can only be added before seal");
        }
        var chunks = new List<string>();
        for (var offset = 0; offset < content.Length; offset += ChunkSizeBytes)
        {
            var slice = content.AsSpan(offset, Math.Min(ChunkSizeBytes, content.Length - offset)).ToArray();
            chunks.Add(WriteChunk(slice));
        }
        var entry = new BackupManifestEntry(relativePath, content.Length, BackupHashing.Sha256Hex(content), chunks);
        lock (_gate)
        {
            if (!_staged.TryGetValue(snapshotId, out var manifest))
                throw new InvalidOperationException($"snapshot '{snapshotId}' is not capturing — files can only be added before seal");
            _staged[snapshotId] = manifest with
            {
                Entries = manifest.Entries.Concat(new[] { entry }).ToList(),
            };
        }
        return entry;
    }

    public void SetVolumes(string snapshotId, IReadOnlyList<VolumeDescriptor> volumes)
    {
        lock (_gate)
        {
            if (!_staged.TryGetValue(snapshotId, out var manifest))
                throw new InvalidOperationException($"snapshot '{snapshotId}' is not capturing");
            _staged[snapshotId] = manifest with { Volumes = volumes };
        }
    }

    /// <summary>Read a chunk back and verify it against its content
    /// address. Null when absent; throws when the stored bytes do
    /// not hash to their key (storage poisoning).</summary>
    public byte[] ReadChunkVerified(string chunkHash)
    {
        var storageKey = $"chunks/{chunkHash}";
        var stored = _storage.Get(storageKey);
        if (stored is null) throw new InvalidOperationException($"chunk {chunkHash} is missing from storage");
        // W10 / V2-C1: unseal first (a wrong key, a tampered or
        // swapped blob, or a plaintext blob under an encrypted store
        // refuses BY NAME inside BackupAtRest.Open), then the
        // content-address hash check runs over the plaintext exactly
        // as before.
        var bytes = OpenFromStorage(storageKey, stored);
        if (BackupHashing.Sha256Hex(bytes) != chunkHash)
            throw new InvalidOperationException($"chunk {chunkHash} failed hash verification — stored bytes do not match their content address (storage poisoning or corruption)");
        return bytes;
    }

    /// <summary>Verify EVERY chunk of a staged snapshot by reading
    /// it back from storage and re-hashing — the completion gate a
    /// backup run must pass before sealing.</summary>
    public (bool Ok, string Detail) VerifyStaged(string snapshotId)
    {
        BackupManifest manifest;
        lock (_gate)
        {
            if (!_staged.TryGetValue(snapshotId, out var staged))
                return (false, $"snapshot '{snapshotId}' is not capturing");
            manifest = staged;
        }
        long verified = 0;
        foreach (var entry in manifest.Entries)
        {
            long assembled = 0;
            foreach (var chunk in entry.ChunkHashes)
            {
                try { assembled += ReadChunkVerified(chunk).Length; }
                catch (Exception ex) { return (false, $"file '{entry.Path}': {ex.Message}"); }
            }
            if (assembled != entry.SizeBytes)
                return (false, $"file '{entry.Path}': read-back assembled {assembled} bytes, manifest says {entry.SizeBytes} — verification failed");
            verified += entry.SizeBytes;
        }
        return (true, $"verified {verified} bytes across {manifest.Entries.Count} file(s) by read-back");
    }

    /// <summary>Seal a staged snapshot: manifest paths re-validated,
    /// retention floor re-checked (defence in depth — policy parsing
    /// is not the only gate), the manifest persisted, and the
    /// catalogue record appended with its chain hash. After this
    /// call the snapshot is immutable.</summary>
    public BackupSnapshot SealSnapshot(string snapshotId, int retentionDays, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_catalogueTampered)
                throw new InvalidOperationException($"catalogue is TAMPERED ({_catalogueState}) — sealing refuses until the catalogue is dealt with");
            if (retentionDays < BackupJobDefinition.MinRetentionDays)
                throw new ArgumentException($"retention {retentionDays}d is below the {BackupJobDefinition.MinRetentionDays}-day immutability floor — refused", nameof(retentionDays));
            if (!_staged.TryGetValue(snapshotId, out var manifest))
                throw new InvalidOperationException($"snapshot '{snapshotId}' is not capturing");
            foreach (var entry in manifest.Entries)
                if (ValidateManifestPath(entry.Path) is { } err)
                    throw new InvalidOperationException($"manifest path refused at seal: {err}");
            var effective = EffectiveNowLocked(now);
            var manifestHash = manifest.ComputeHash();
            var manifestBytes = Encoding.UTF8.GetBytes(manifest.CanonicalJson());
            // W10 / V2-C1: the manifest is sealed at rest under the
            // same key discipline as the chunks; its catalogue hash
            // still covers the PLAINTEXT canonical form.
            var manifestStorageKey = $"manifests/{snapshotId}.json";
            var manifestStored = SealForStorage(manifestStorageKey, manifestBytes);
            _storage.Put(manifestStorageKey, manifestStored);
            // D38 F9: read the manifest blob BACK before the snapshot
            // is catalogued — read-back verification covers the
            // manifest, not only the chunks. A store that does not
            // return what it was given refuses the seal.
            var readBack = _storage.Get(manifestStorageKey);
            if (readBack is null || BackupHashing.Sha256Hex(readBack) != BackupHashing.Sha256Hex(manifestStored))
                throw new InvalidOperationException($"manifest for snapshot '{snapshotId}' failed read-back verification after write — seal refused (storage did not return the bytes it was given)");
            var prev = _catalogue.Count == 0 ? CatalogueGenesis : _catalogue[^1].CatalogueHash;
            var capturedUtc = _captureStartedUtc.TryGetValue(snapshotId, out var started) ? started : effective;
            var snapshot = new BackupSnapshot(
                snapshotId, manifest.JobId, manifest.DeviceId, manifest.OwnerUserId, TargetId,
                manifest.Kind, SnapshotStates.Sealed,
                capturedUtc,
                effective, effective + TimeSpan.FromDays(retentionDays),
                manifestHash, manifest.TotalBytes, manifest.Entries.Count,
                prev, "");
            snapshot = snapshot with { CatalogueHash = ComputeCatalogueHash(snapshot) };
            _catalogue.Add(snapshot);
            _staged.Remove(snapshotId);
            _captureStartedUtc.Remove(snapshotId);
            return snapshot;
        }
    }

    /// <summary>Abort a CAPTURING snapshot (never a sealed one):
    /// staging is dropped and chunks no sealed snapshot references
    /// are removed. This is the only pre-seal cleanup, and it cannot
    /// reach sealed content.</summary>
    public void AbortSnapshot(string snapshotId)
    {
        List<string> orphanCandidates;
        lock (_gate)
        {
            if (!_staged.TryGetValue(snapshotId, out var manifest)) return; // sealed or unknown: nothing to abort, by design
            orphanCandidates = manifest.Entries.SelectMany(e => e.ChunkHashes).Distinct().ToList();
            _staged.Remove(snapshotId);
            _captureStartedUtc.Remove(snapshotId);
        }
        DeleteUnreferencedChunks(orphanCandidates);
    }

    // -- manifest access --

    /// <summary>Load a sealed snapshot's manifest from storage and
    /// verify it against the catalogue: the stored manifest's hash
    /// must equal the catalogue's chained ManifestHash, and its
    /// identity fields must match the record. A swapped or edited
    /// manifest refuses here — restore never trusts storage bytes
    /// over the chained catalogue.</summary>
    public BackupManifest? GetManifestVerified(string snapshotId)
    {
        var snapshot = GetSnapshot(snapshotId);
        if (snapshot is null || !snapshot.IsSealed) return null;
        var manifestStorageKey = $"manifests/{snapshotId}.json";
        var storedBytes = _storage.Get(manifestStorageKey);
        if (storedBytes is null) return null;
        // W10 / V2-C1: unseal under the store's key discipline. Any
        // refusal (plaintext under an encrypted store, wrong key,
        // tampered/swapped blob) verifies as NO manifest — restore
        // and browse refuse by that name, exactly as for a hash
        // mismatch below.
        byte[] bytes;
        try { bytes = OpenFromStorage(manifestStorageKey, storedBytes); }
        catch (InvalidOperationException) { return null; }
        // D38 F12: parse once per distinct blob — abort/purge/usage
        // paths call this for every sealed snapshot, and re-parsing
        // every manifest on every call made each operation O(store).
        // The cache is keyed by the blob's own hash, so poisoned or
        // swapped bytes never hit a stale entry, and the full
        // verification below still runs for every fresh blob.
        var bytesHash = BackupHashing.Sha256Hex(bytes);
        lock (_gate)
            if (_manifestCache.TryGetValue(snapshotId, out var cached) && cached.BytesHash == bytesHash
                && cached.Manifest.ComputeHash() == snapshot.ManifestHash
                && cached.Manifest.JobId == snapshot.JobId && cached.Manifest.DeviceId == snapshot.DeviceId
                && cached.Manifest.OwnerUserId == snapshot.OwnerUserId)
                return cached.Manifest;
        BackupManifest? manifest;
        try
        {
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(bytes));
            var root = doc.RootElement;
            var entries = root.GetProperty("entries").EnumerateArray().Select(e => new BackupManifestEntry(
                e.GetProperty("path").GetString() ?? "",
                e.GetProperty("size").GetInt64(),
                e.GetProperty("hash").GetString() ?? "",
                e.GetProperty("chunks").EnumerateArray().Select(c => c.GetString() ?? "").ToList())).ToList();
            var volumes = root.GetProperty("volumes").EnumerateArray().Select(v => new VolumeDescriptor(
                v.GetProperty("id").GetString() ?? "", v.GetProperty("size").GetInt64(),
                v.GetProperty("fs").GetString() ?? "", v.GetProperty("part").GetInt32(),
                v.GetProperty("boot").GetBoolean(), v.GetProperty("sys").GetBoolean())).ToList();
            manifest = new BackupManifest(
                root.GetProperty("snapshotId").GetString() ?? "",
                root.GetProperty("jobId").GetString() ?? "",
                root.GetProperty("deviceId").GetString() ?? "",
                root.GetProperty("ownerUserId").GetString() ?? "",
                root.GetProperty("kind").GetString() ?? "",
                entries, volumes);
        }
        catch { return null; }
        if (manifest.SnapshotId != snapshot.Id || manifest.JobId != snapshot.JobId ||
            manifest.DeviceId != snapshot.DeviceId || manifest.OwnerUserId != snapshot.OwnerUserId)
            return null;
        if (manifest.ComputeHash() != snapshot.ManifestHash) return null;
        lock (_gate) _manifestCache[snapshotId] = (bytesHash, manifest);
        return manifest;
    }

    // -- deletion: refused by shape, purge: retention + clock --

    /// <summary>THE deletion surface — it exists so that any caller
    /// (the agent itself, a hub-issued signed command handler) has
    /// its request refused BY NAME with the refusal auditable. A
    /// sealed snapshot has no delete path; an expired lock still
    /// does not delete here — purge is a separate, deliberate act.</summary>
    public DeleteOutcome TryDeleteSnapshot(string snapshotId, string actor, DateTimeOffset now)
    {
        lock (_gate)
        {
            var s = _catalogue.FirstOrDefault(x => x.Id == snapshotId);
            if (s is null) return new DeleteOutcome(false, $"snapshot '{snapshotId}' does not exist — nothing deleted");
            if (s.State == SnapshotStates.Purged) return new DeleteOutcome(false, $"snapshot '{snapshotId}' is already purged");
            // D38 F4: a delete request is a REFUSED operation — it
            // must not advance the high-water mark at all. The lock
            // state is judged against the mark as it stands.
            var effective = _highWaterUtc == DateTimeOffset.MinValue ? now : _highWaterUtc;
            return new DeleteOutcome(false,
                $"snapshot '{snapshotId}' is SEALED and immutable — deletion is refused for every caller including the endpoint agent and hub-issued commands (actor '{actor}'); " +
                (s.IsLocked(effective)
                    ? $"its retention lock runs until {s.RetentionExpiresUtc:O} and early deletion is not a feature — it is the ransomware attack this design exists to refuse"
                    : "its retention has expired, but removal still requires the deliberate purge path (TryPurgeExpired), never a delete"));
        }
    }

    /// <summary>The ONLY removal path for a sealed snapshot.
    /// Requires: catalogue intact, retention expired at the
    /// EFFECTIVE time, and — when the presented clock has jumped
    /// ahead of the high-water mark by more than
    /// MaxUnattestedClockJump — a valid hub-signed time attestation
    /// whose attested time is itself past expiry. Purging removes
    /// the manifest and the chunks no remaining snapshot references,
    /// and REWRITES the catalogue record as purged with a fresh
    /// chain hash (the record of the snapshot's existence and purge
    /// is itself never deleted).</summary>
    public PurgeOutcome TryPurgeExpired(string snapshotId, DateTimeOffset now, SignedCommandEnvelope? timeAttestation = null)
    {
        lock (_gate)
        {
            if (_catalogueTampered)
                return new PurgeOutcome(false, $"catalogue is TAMPERED ({_catalogueState}) — purge refuses: a rewritten catalogue cannot be trusted to say a lock expired");
            var idx = _catalogue.FindIndex(x => x.Id == snapshotId);
            if (idx < 0) return new PurgeOutcome(false, $"snapshot '{snapshotId}' does not exist — nothing purged");
            var s = _catalogue[idx];
            if (s.State == SnapshotStates.Purged) return new PurgeOutcome(false, $"snapshot '{snapshotId}' is already purged");
            if (!s.IsSealed) return new PurgeOutcome(false, $"snapshot '{snapshotId}' is not sealed — purge does not apply");

            var jumped = now > _highWaterUtc + MaxUnattestedClockJump;
            DateTimeOffset trustedNow;
            if (jumped)
            {
                // Attestation is verified BEFORE any time state
                // moves: a failed attestation changes nothing.
                var attested = VerifyTimeAttestation(timeAttestation, now);
                if (attested is null)
                    return new PurgeOutcome(false,
                        $"clock jumped {(now - _highWaterUtc)} ahead of the store's high-water mark (>{MaxUnattestedClockJump}) — purge REFUSED: a rolled-forward endpoint clock cannot expire retention locks; a hub-signed time attestation is required");
                trustedNow = attested.Value;
                // The hub vouched for this time: the mark may cross
                // the jump on the strength of the attestation, and
                // the real-time anchor re-bases to the attested time
                // (D38 F4) so later unattested time flows from it.
                if (trustedNow > _highWaterUtc) _highWaterUtc = trustedNow;
                AnchorLocked(trustedNow);
            }
            else
            {
                trustedNow = EffectiveNowLocked(now);
            }
            if (trustedNow < s.RetentionExpiresUtc)
                return new PurgeOutcome(false,
                    $"snapshot '{snapshotId}' retention lock runs until {s.RetentionExpiresUtc:O} — purge refused at {trustedNow:O} (immutability: early removal is the attack, not a feature)");

            // Read the manifest BEFORE the state flip (after it,
            // the record no longer reads as sealed).
            var manifest = GetManifestVerified(snapshotId);
            // Commit: the record becomes purged. Its hash covers the
            // state, so the flip changes this record's hash — every
            // LATER record is therefore re-chained by the store (the
            // legitimate writer) so the catalogue still verifies as
            // written. The engine anchors the new head into the
            // chained audit log, which a catalogue recompute cannot
            // rewrite.
            _catalogue[idx] = s with { State = SnapshotStates.Purged, CatalogueHash = "" };
            _catalogue[idx] = _catalogue[idx] with { CatalogueHash = ComputeCatalogueHash(_catalogue[idx]) };
            for (var i = idx + 1; i < _catalogue.Count; i++)
            {
                var next = _catalogue[i] with { PrevCatalogueHash = _catalogue[i - 1].CatalogueHash, CatalogueHash = "" };
                _catalogue[i] = next with { CatalogueHash = ComputeCatalogueHash(next) };
            }
            _storage.Delete($"manifests/{snapshotId}.json");
            if (manifest is not null)
                DeleteUnreferencedChunks(manifest.Entries.SelectMany(e => e.ChunkHashes).Distinct().ToList());
            return new PurgeOutcome(true, $"snapshot '{snapshotId}' purged after retention expiry {s.RetentionExpiresUtc:O} (trusted time {trustedNow:O})");
        }
    }

    private DateTimeOffset? VerifyTimeAttestation(SignedCommandEnvelope? envelope, DateTimeOffset now)
    {
        if (envelope is null || _timeVerifier is null) return null;
        var verdict = _timeVerifier.Verify(envelope, now, SignedCommandClasses.Automation);
        if (!verdict.Allowed || verdict.Payload is null) return null;
        try
        {
            var parts = Encoding.UTF8.GetString(verdict.Payload).Split('|');
            if (parts.Length != 3 || parts[0] != "acp-backup-time-v1") return null;
            if (parts[1] != $"target={TargetId}") return null;
            // D38 F12: culture-invariant parse, and the attested
            // time must carry an explicit offset — a bare local time
            // is ambiguous and refuses.
            if (!parts[2].Contains('+') && !parts[2].EndsWith("Z", StringComparison.OrdinalIgnoreCase)
                && !System.Text.RegularExpressions.Regex.IsMatch(parts[2], @"T\d{2}:\d{2}:\d{2}(\.\d+)?-\d{2}:\d{2}$"))
                return null;
            return DateTimeOffset.TryParse(parts[2], CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var attested) ? attested : null;
        }
        catch { return null; }
    }

    private void DeleteUnreferencedChunks(IEnumerable<string> candidates)
    {
        // D38 F3: garbage collection FAILS CLOSED and is race-free.
        // The catalogue + staging sets are snapshotted under the
        // gate (AbortSnapshot calls this after releasing it, while
        // SealSnapshot can mutate the catalogue), and if ANY sealed
        // snapshot's manifest fails to load or verify, that snapshot
        // drops out of the provably-referenced set — so NOTHING is
        // deleted: an unverifiable sealed snapshot's deduplicated
        // chunks are never collected from under it.
        List<BackupSnapshot> sealedList;
        List<BackupManifest> stagedManifests;
        lock (_gate)
        {
            sealedList = _catalogue.Where(x => x.IsSealed).ToList();
            stagedManifests = _staged.Values.ToList();
        }
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in sealedList)
        {
            var m = GetManifestVerified(s.Id);
            if (m is null) return; // fail closed: delete nothing
            foreach (var c in m.Entries.SelectMany(e => e.ChunkHashes)) referenced.Add(c);
        }
        foreach (var staged in stagedManifests)
            foreach (var c in staged.Entries.SelectMany(e => e.ChunkHashes)) referenced.Add(c);
        foreach (var c in candidates)
            if (!referenced.Contains(c)) _storage.Delete($"chunks/{c}");
    }

    // -- catalogue persistence --

    // W10 / V2-C1: when the store is encrypted, the at-rest key's
    // fingerprint is bound into every catalogue record hash — a
    // catalogue sealed under one key cannot be re-anchored under
    // another, and importing it into a store holding a different
    // key (or none) verifies as a chain break, by name. Plaintext
    // stores keep the exact legacy hash input.
    private string ComputeCatalogueHash(BackupSnapshot s) =>
        BackupHashing.Sha256Hex(string.Join("|",
            "acp-backup-catalogue-v1", s.PrevCatalogueHash, s.Id, s.JobId, s.DeviceId, s.OwnerUserId,
            s.TargetId, s.Kind, s.State, s.CapturedUtc.ToString("O"),
            s.SealedUtc?.ToString("O") ?? "", s.RetentionExpiresUtc?.ToString("O") ?? "",
            s.ManifestHash, s.TotalBytes, s.FileCount,
            _atRestKeyId is null ? "" : $"atrest:{_atRestKeyId}"));

    private sealed record CatalogueDto(
        string TargetId, DateTimeOffset HighWaterUtc, List<BackupSnapshot> Snapshots, string Integrity = "");

    /// <summary>D38 F1/F2: the catalogue DOCUMENT integrity hash.
    /// It covers exactly what the per-record chain does not: the
    /// target id, the persisted high-water mark, the record count
    /// and the chain head. Editing the high-water field alone,
    /// dropping the TAIL records, or retargeting the document breaks
    /// it — no chain recompute of individual records repairs it.
    /// (An attacker who recomputes the chain AND this hash AND the
    /// audit-log head anchor is the named full-recompute residual.)</summary>
    // W12 / DS-P9-F3/F4: when this store holds an at-rest key, the
    // document integrity is an HMAC-SHA-256 under that key (held
    // outside the backup target) — an attacker with only storage
    // write access can no longer recompute a consistent forged
    // catalogue. Plaintext (unkeyed) stores keep the legacy unkeyed
    // hash, named as the weaker posture it is.
    private string ComputeCatalogueIntegrity(string targetId, DateTimeOffset highWaterUtc, IReadOnlyList<BackupSnapshot> records)
    {
        var input = string.Join("|",
            "acp-backup-catalogue-doc-v1", targetId, highWaterUtc.ToString("O"),
            records.Count, records.Count == 0 ? CatalogueGenesis : records[^1].CatalogueHash);
        if (_atRestKey is null) return BackupHashing.Sha256Hex(input);
        using var hmac = new System.Security.Cryptography.HMACSHA256(_atRestKey);
        return Convert.ToHexString(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }

    private string CatalogueIntegrityLocked() => ComputeCatalogueIntegrity(TargetId, _highWaterUtc, _catalogue);

    public string ExportCatalogue()
    {
        lock (_gate)
            return JsonSerializer.Serialize(new CatalogueDto(TargetId, _highWaterUtc, _catalogue.ToList(), CatalogueIntegrityLocked()));
    }

    /// <summary>Import + verify the chain. A single altered field,
    /// a dropped record, or a re-ordered record breaks verification
    /// and the catalogue imports as TAMPERED (visible, named) —
    /// snapshots remain listed for reporting, but restores and
    /// purges refuse.</summary>
    public (bool Ok, string Summary) ImportCatalogue(string json)
    {
        CatalogueDto? dto;
        try { dto = JsonSerializer.Deserialize<CatalogueDto>(json); }
        catch { dto = null; }
        lock (_gate)
        {
            if (dto is null || dto.Snapshots is null)
            {
                _catalogueTampered = true;
                _catalogueState = "catalogue store did not parse — NOT trusted";
                return (false, _catalogueState);
            }
            // D38 F11: the document must name THIS store's target —
            // a catalogue written for another target imports nowhere.
            if (!string.Equals(dto.TargetId, TargetId, StringComparison.Ordinal))
            {
                _catalogueTampered = true;
                _catalogueState = $"catalogue names target '{dto.TargetId}' but this store is '{TargetId}' — NOT trusted";
                return (false, _catalogueState);
            }
            if (dto.Snapshots.Any(s => !string.Equals(s.TargetId, TargetId, StringComparison.Ordinal)))
            {
                _catalogueTampered = true;
                _catalogueState = "catalogue carries a record for another target — NOT trusted";
                return (false, _catalogueState);
            }
            // Verify EVERYTHING before any live state moves (D38 F1:
            // the old code raised the live high-water mark from the
            // file BEFORE the chain was checked, so a forged import
            // moved trusted time even when it then failed).
            var prev = CatalogueGenesis;
            foreach (var s in dto.Snapshots)
            {
                // W12 / DS-P9-F10: snapshot ids are UUIDs — an imported
                // id is validated before it is ever interpolated into
                // a storage key (a path-carrying id is a traversal).
                if (!Guid.TryParse(s.Id, out _))
                {
                    _catalogueTampered = true;
                    _catalogueState = $"BROKEN at snapshot {s.Id}: snapshot id is not a canonical UUID — NOT trusted";
                    return (false, _catalogueState);
                }
                if (s.PrevCatalogueHash != prev || s.CatalogueHash != ComputeCatalogueHash(s))
                {
                    _catalogueTampered = true;
                    _catalogueState = $"BROKEN at snapshot {s.Id}: catalogue chain mismatch (a record was altered, dropped, or reordered)";
                    return (false, _catalogueState);
                }
                prev = s.CatalogueHash;
            }
            // D38 F1/F2: document integrity — the high-water mark,
            // the record count and the chain head are covered, so a
            // lone high-water edit or a dropped TAIL record (which
            // the forward chain alone cannot see) imports TAMPERED.
            if (string.IsNullOrEmpty(dto.Integrity) ||
                dto.Integrity != ComputeCatalogueIntegrity(dto.TargetId, dto.HighWaterUtc, dto.Snapshots))
            {
                _catalogueTampered = true;
                _catalogueState = "BROKEN: catalogue document integrity mismatch (the high-water mark, record count, or chain head was altered — e.g. a tail record dropped or the mark forged)";
                return (false, _catalogueState);
            }
            // D38 F2: importing into a store that already holds a
            // catalogue may not regress it — a shorter catalogue or a
            // different head than the live one is a truncation, not
            // a load.
            if (_catalogue.Count > 0 &&
                (dto.Snapshots.Count < _catalogue.Count ||
                 (dto.Snapshots.Count == _catalogue.Count && dto.Snapshots.Count > 0 &&
                  dto.Snapshots[^1].CatalogueHash != _catalogue[^1].CatalogueHash)))
            {
                _catalogueTampered = true;
                _catalogueState = "BROKEN: imported catalogue regresses the live catalogue (fewer records or a different head) — truncation refused";
                return (false, _catalogueState);
            }
            _catalogue.Clear();
            _catalogue.AddRange(dto.Snapshots);
            _manifestCache.Clear();
            if (dto.HighWaterUtc > _highWaterUtc) { _highWaterUtc = dto.HighWaterUtc; AnchorLocked(_highWaterUtc); }
            _catalogueTampered = false;
            _catalogueState = $"OK: {_catalogue.Count} snapshot record(s), chain intact, high-water {_highWaterUtc:O}";
            return (true, _catalogueState);
        }
    }

    public void SaveCatalogueToFile(string path)
    {
        // W12 / DS-P9-F9: the catalogue JSON and its anchor are
        // computed from ONE lock span — previously the file was
        // written from an ExportCatalogue snapshot and the anchor
        // computed under a later lock, so a concurrent seal/purge
        // produced a file/anchor pair describing different states
        // and the next load reported a false TAMPERED.
        // W12 / DS-P9-F13: the anchor generation also carries the
        // chain HEAD, so a state-only change (a purge that moves
        // neither the count nor the high-water) is recognisable as
        // newer at load instead of misclassifying as tamper.
        string json, anchorText;
        lock (_gate)
        {
            var integrity = CatalogueIntegrityLocked();
            var head = _catalogue.Count == 0 ? CatalogueGenesis : _catalogue[^1].CatalogueHash;
            json = JsonSerializer.Serialize(new CatalogueDto(TargetId, _highWaterUtc, _catalogue.ToList(), integrity));
            anchorText = $"{integrity}|{_highWaterUtc:O}|{_catalogue.Count}|{head}";
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
        // D38 F2: anchor sidecar — the catalogue's integrity hash
        // written NEXT to the catalogue file. Deleting the catalogue
        // file outright, or swapping in an older/truncated one, is
        // detectable at load because the anchor survives and
        // disagrees. (An attacker who rewrites BOTH files
        // consistently is the named full-recompute residual; the
        // engine also anchors the head into the chained audit log.)
        var anchorTmp = path + ".anchor.tmp";
        File.WriteAllText(anchorTmp, anchorText);
        File.Move(anchorTmp, path + ".anchor", overwrite: true);
    }

    public (bool Ok, string Summary) LoadCatalogueFromFile(string path)
    {
        var anchorPath = path + ".anchor";
        if (!File.Exists(path))
        {
            // D38 F2: a missing catalogue file is a legitimate empty
            // catalogue ONLY when no anchor says one ever existed.
            if (File.Exists(anchorPath))
            {
                lock (_gate)
                {
                    _catalogueTampered = true;
                    _catalogueState = "catalogue file is MISSING but its anchor sidecar survives — the catalogue was deleted outright; NOT trusted as empty";
                    return (false, _catalogueState);
                }
            }
            return (true, "no catalogue file — empty catalogue");
        }
        var json = File.ReadAllText(path);
        if (File.Exists(anchorPath))
        {
            CatalogueDto? dto;
            try { dto = JsonSerializer.Deserialize<CatalogueDto>(json); } catch { dto = null; }
            var anchorParts = File.ReadAllText(anchorPath).Trim().Split('|');
            var expected = anchorParts[0];
            if (dto is null || dto.Snapshots is null ||
                ComputeCatalogueIntegrity(dto.TargetId, dto.HighWaterUtc, dto.Snapshots) != expected)
            {
                // bd-shared-plat-1/F10: distinguish a TORN WRITE
                // (crash between the catalogue replace and the
                // anchor replace) from a ROLLBACK. Recovery requires
                // ALL of: the catalogue's OWN embedded integrity
                // verifies (D38 F1/F2), the anchor carries a
                // generation, and the catalogue's generation is
                // NEWER than the anchor's. An older catalogue
                // against a newer anchor is a rollback — tamper,
                // refused exactly as before.
                DateTimeOffset anchorHighWater = default;
                var anchorCount = 0;
                var anchorGenKnown = anchorParts.Length >= 3 &&
                    DateTimeOffset.TryParse(anchorParts[1], out anchorHighWater) &&
                    int.TryParse(anchorParts[2], out anchorCount);
                // W12 / DS-P9-F13: a state-only change (purge) moves
                // the chain head but neither count nor high-water —
                // with the head in the anchor generation (4th field),
                // that catalogue is recognisably NEWER, not tamper.
                var anchorHead = anchorParts.Length >= 4 ? anchorParts[3] : null;
                var dtoHead = dto is not null && dto.Snapshots is { Count: > 0 } ? dto.Snapshots[^1].CatalogueHash : CatalogueGenesis;
                var catalogueNewer = anchorGenKnown && dto is not null && dto.Snapshots is not null &&
                    (dto.HighWaterUtc > anchorHighWater ||
                     (dto.HighWaterUtc == anchorHighWater && dto.Snapshots.Count > anchorCount) ||
                     (dto.HighWaterUtc == anchorHighWater && dto.Snapshots.Count == anchorCount &&
                      anchorHead is not null && dtoHead != anchorHead));
                if (catalogueNewer &&
                    !string.IsNullOrEmpty(dto!.Integrity) &&
                    dto.Integrity == ComputeCatalogueIntegrity(dto.TargetId, dto.HighWaterUtc, dto.Snapshots))
                {
                    var recovered = ImportCatalogue(json);
                    if (recovered.Ok)
                    {
                        try
                        {
                            var anchorTmp = anchorPath + ".tmp";
                            File.WriteAllText(anchorTmp, $"{dto.Integrity}|{dto.HighWaterUtc:O}|{dto.Snapshots.Count}");
                            File.Move(anchorTmp, anchorPath, overwrite: true);
                        }
                        catch { /* re-anchor best-effort; the load itself is verified */ }
                        lock (_gate)
                            _catalogueState = "RECOVERED-TORN-WRITE: catalogue's embedded integrity verifies but its anchor sidecar is stale (a crash between the two replaces) — catalogue accepted and re-anchored; this is a recoverable torn write, not tamper";
                        return (true, _catalogueState);
                    }
                    return recovered;
                }
                lock (_gate)
                {
                    _catalogueTampered = true;
                    _catalogueState = "catalogue file disagrees with its anchor sidecar (truncated, replaced, or the high-water mark forged) — NOT trusted";
                    return (false, _catalogueState);
                }
            }
        }
        return ImportCatalogue(json);
    }

    private static readonly IReadOnlySet<string> ReservedDeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
      "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

    /// <summary>A manifest path is admissible only as a clean
    /// relative path: no root, no drive, no traversal, no empty
    /// segments. Enforced at seal AND at restore, because a manifest
    /// is data an attacker may have written.</summary>
    public static string? ValidateManifestPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "manifest path is empty — refused";
        var p = path.Replace('\\', '/');
        if (p.StartsWith('/') || (p.Length >= 2 && p[1] == ':'))
            return $"manifest path '{path}' is rooted — refused";
        foreach (var seg in p.Split('/'))
        {
            if (seg.Length == 0) return $"manifest path '{path}' carries an empty segment — refused";
            if (seg is "." or "..") return $"manifest path '{path}' carries traversal segment '{seg}' — refused";
            // W12 / DS-P9-F17: a colon ANYWHERE in a segment is an
            // NTFS alternate-data-stream name on Windows, not a file;
            // reserved device basenames and trailing dot/space
            // segments address devices or collapse onto other files.
            if (seg.Contains(':')) return $"manifest path '{path}' carries a colon segment '{seg}' (alternate data stream) — refused";
            if (seg.EndsWith('.') || seg.EndsWith(' ')) return $"manifest path '{path}' carries a trailing dot/space segment '{seg}' — refused";
            var baseName = seg.Split('.')[0];
            if (ReservedDeviceNames.Contains(baseName))
                return $"manifest path '{path}' carries reserved device segment '{seg}' — refused";
        }
        return null;
    }
}

// ---- restore targets -------------------------------------------------------

/// <summary>Where restored files land. Implementations are rooted:
/// every write is confined under the root by construction, and the
/// engine additionally validates every path itself (defence in
/// depth — the engine never trusts a target to police traversal).</summary>
public interface IRestoreTarget
{
    string RootPath { get; }
    void Write(string relativePath, byte[] content);
    void Delete(string relativePath);
    bool Exists(string relativePath);
    /// <summary>D38 F8: read back what a path currently holds (null
    /// when absent) so a restore can PRESERVE a file it overwrites
    /// and put the original back on rollback — rollback that only
    /// deletes destroys the user's pre-existing files.</summary>
    byte[]? Read(string relativePath);
}

/// <summary>In-memory restore target (tests). Its RootPath is a
/// logical Windows-style path so the engine's system-path policy is
/// exercised exactly as production would exercise it.</summary>
public sealed class InMemoryRestoreTarget : IRestoreTarget
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);
    public InMemoryRestoreTarget(string rootPath) => RootPath = rootPath;
    public string RootPath { get; }
    public IReadOnlyDictionary<string, byte[]> Files => _files;
    public void Write(string relativePath, byte[] content) => _files[relativePath] = content.ToArray();
    public void Delete(string relativePath) => _files.Remove(relativePath);
    public bool Exists(string relativePath) => _files.ContainsKey(relativePath);
    public byte[]? Read(string relativePath) => _files.TryGetValue(relativePath, out var b) ? b.ToArray() : null;
}

/// <summary>Directory restore target: files land under a real root
/// directory, traversal-checked on every operation.</summary>
public sealed class DirectoryRestoreTarget : IRestoreTarget
{
    private readonly string _root;
    public DirectoryRestoreTarget(string root)
    {
        if (!Path.IsPathFullyQualified(root ?? ""))
            throw new ArgumentException("restore root must be an absolute path", nameof(root));
        _root = Path.GetFullPath(root!);
        Directory.CreateDirectory(_root);
        // D38 F6 (partial): a restore root that IS a junction /
        // reparse point silently redirects every write outside the
        // named root — refuse it by name. (Junctions BELOW the root
        // created mid-restore remain a named residual: the engine
        // validates paths, the host owns the filesystem.)
        if ((File.GetAttributes(_root) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException($"restore root '{_root}' is a reparse point (junction/symlink) — refused: writes would land outside the named root", nameof(root));
    }
    public string RootPath => _root;

    private string FullPath(string relativePath)
    {
        if (BackupSnapshotStore.ValidateManifestPath(relativePath) is { } err)
            throw new ArgumentException(err, nameof(relativePath));
        var full = Path.GetFullPath(Path.Combine(_root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException($"restore path '{relativePath}' escapes the restore root — refused", nameof(relativePath));
        return full;
    }

    public void Write(string relativePath, byte[] content)
    {
        var full = FullPath(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var tmp = full + ".tmp";
        File.WriteAllBytes(tmp, content);
        File.Move(tmp, full, overwrite: true);
    }

    public void Delete(string relativePath)
    {
        var full = FullPath(relativePath);
        if (File.Exists(full)) File.Delete(full);
    }

    public bool Exists(string relativePath) => File.Exists(FullPath(relativePath));

    public byte[]? Read(string relativePath)
    {
        var full = FullPath(relativePath);
        return File.Exists(full) ? File.ReadAllBytes(full) : null;
    }
}

// ---- restore model ---------------------------------------------------------

/// <summary>Who is asking for a restore. Self-restore scope is
/// (UserId, DeviceId): a user restores THEIR OWN files from THEIR
/// OWN device's backups. Admins restore through the hub under a
/// signed command (RMM-03) — never on a bare claim of adminhood.</summary>
public sealed record RestoreRequester(string UserId, string DeviceId, bool IsAdmin);

public sealed record RestoreOutcome(bool Ok, string Outcome, int FilesRestored, long BytesRestored);

/// <summary>The bare-metal restore plan: the model a bootable
/// restore environment executes. Execution is host wiring (boot
/// media + a restore environment); this lane models the plan, its
/// integrity hash, and the media shape — and names that boundary.</summary>
public sealed record BareMetalRestorePlan(
    string SnapshotId, string DeviceId, string PlanHash,
    IReadOnlyList<VolumeDescriptor> Volumes,
    IReadOnlyList<string> Steps,
    RestoreMediaShape Media,
    // W13 / DS-P9-F16: the DESTINATION device this plan restores
    // onto, when one was named and v2-bound at planning time; null
    // for a legacy v1 plan (same-device restore assumed, unnamed).
    string? TargetDeviceId = null);

public sealed record RestoreMediaShape(string MediaId, string SnapshotId, string PlanHash, DateTimeOffset CreatedUtc);

// ---- health facts (the RMM-01 seam) -----------------------------------------

/// <summary>The backup health facts for one device — the shape the
/// RMM-01 monitor's evaluator consumes. Facts, not verdicts: the
/// evaluator below maps them to findings, and the monitor raises
/// them as alerts. Silence is never health: a device with no facts
/// is unknown to the monitor, exactly as in RMM-01's own model.</summary>
public sealed record BackupHealthFacts(
    string DeviceId,
    DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? LastSuccessUtc,
    string? LastOutcome,
    int ConsecutiveFailures,
    int LockedSnapshots,
    long LockedBytes,
    bool StorageReachable,
    double? StorageFreePercent,
    bool CatalogueTampered,
    DateTimeOffset GeneratedUtc);

public sealed record BackupHealthFinding(string ConditionId, string Kind, string Severity, string Detail);

/// <summary>The facts seam's provider side: anything that can state
/// a device's backup health as facts. BackupEngine implements it;
/// the hub-side monitor wiring consumes it.</summary>
public interface IBackupHealthFactsProvider
{
    BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now);
}

public static class BackupHealthEvaluator
{
    /// <summary>Pure evaluation of backup health facts into alert
    /// findings. `staleAfter` is policy-shaped (typically 2× the
    /// job interval + grace, supplied by the caller from the job's
    /// schedule — the evaluator invents no threshold).</summary>
    public static IReadOnlyList<BackupHealthFinding> Evaluate(BackupHealthFacts facts, TimeSpan staleAfter, DateTimeOffset now)
    {
        var findings = new List<BackupHealthFinding>();
        if (facts.CatalogueTampered)
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupCatalogueTampered, facts.DeviceId),
                BackupConditionKinds.BackupCatalogueTampered, "critical",
                $"device {facts.DeviceId}: backup catalogue chain is BROKEN — snapshots cannot be trusted until the catalogue is dealt with"));
        if (!facts.StorageReachable)
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupStorageUnreachable, facts.DeviceId),
                BackupConditionKinds.BackupStorageUnreachable, "critical",
                $"device {facts.DeviceId}: backup storage target is unreachable"));
        if (facts.LastAttemptUtc is null && facts.LastSuccessUtc is null)
        {
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupNeverRun, facts.DeviceId),
                BackupConditionKinds.BackupNeverRun, "warning",
                $"device {facts.DeviceId}: no backup has ever run — the device is unprotected, and 'never ran' is a finding, not an absence of one"));
            return findings;
        }
        if (facts.LastOutcome is not null && facts.LastOutcome != "completed")
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupFailed, facts.DeviceId),
                BackupConditionKinds.BackupFailed,
                facts.ConsecutiveFailures >= 3 ? "critical" : "warning",
                $"device {facts.DeviceId}: last backup outcome '{facts.LastOutcome}' ({facts.ConsecutiveFailures} consecutive failure(s))"));
        if (facts.LastSuccessUtc is { } last && now - last > staleAfter)
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupStale, facts.DeviceId),
                BackupConditionKinds.BackupStale, "warning",
                $"device {facts.DeviceId}: last successful backup {last:O} is older than the staleness bound {staleAfter}"));
        if (facts.LastSuccessUtc is null && facts.LastAttemptUtc is not null)
            findings.Add(new BackupHealthFinding(
                BackupConditionKinds.DeviceConditionId(BackupConditionKinds.BackupStale, facts.DeviceId),
                BackupConditionKinds.BackupStale, "critical",
                $"device {facts.DeviceId}: backups have been attempted but NEVER succeeded"));
        return findings;
    }
}

// ---- usage -------------------------------------------------------------------

/// <summary>Truthful storage accounting for one target. The product
/// meters nothing: these numbers describe the user's own storage,
/// computed from the catalogue + chunk store, for the user's own
/// capacity decisions.</summary>
public sealed record BackupUsageReport(
    string TargetId, int SealedSnapshots, int LockedSnapshots,
    long LogicalBytes, long StoredBytes, long LockedBytes,
    DateTimeOffset? OldestSealedUtc, DateTimeOffset? NewestSealedUtc,
    long? StorageFreeBytes);

// ---- the engine ----------------------------------------------------------------

public sealed record BackupRunOutcome(bool Ok, string Outcome, string? SnapshotId, string? JobId, long Bytes, int Files);

/// <summary>The backup engine: runs jobs (checkpointed as RMM-15
/// `backup` jobs), restores (file granularity, image browse,
/// bare-metal plan, self-restore), purges (via the store's guarded
/// path), reports usage, and serves backup health facts. Every act
/// and every refusal is a chained audit event.</summary>
public sealed class BackupEngine : IBackupHealthFactsProvider
{
    private readonly BackupSnapshotStore _store;
    private readonly IBackupCaptureSource _capture;
    private readonly ChainedAuditLog _audit;
    private readonly JobJournal? _journal;
    private readonly SignedCommandVerifier? _commandVerifier;
    private readonly Func<string, bool>? _policyGate;
    private readonly Func<RestoreRequester, bool>? _requesterAuthenticator;
    // D38 F10: run state is keyed by JOB (with its device recorded),
    // never by device alone — sibling jobs on one device must not
    // reset each other's last-attempt or failure counts.
    private readonly Dictionary<string, (string DeviceId, DateTimeOffset? Attempt, DateTimeOffset? Success, string? Outcome, int Failures)> _runState =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <param name="commandVerifier">Verifies hub-issued restore
    /// commands (RMM-03, class automation, payload binding snapshot
    /// + device). When null, admin/hub restores refuse — self-restore
    /// (scope-checked) still works.</param>
    /// <param name="policyGate">TOTAL POLICY CONTROL seam: key →
    /// enabled, consulted before a run starts and again before it
    /// seals (the kill-switch race). When null, the engine treats
    /// policy as enabled and the Core service is the gate — the
    /// service always wires it.</param>
    /// <param name="requesterAuthenticator">D38 F7: the host's proof
    /// that a RestoreRequester's (UserId, DeviceId) is the
    /// AUTHENTICATED caller, not a caller-supplied claim. The engine
    /// cannot authenticate a local caller itself — identity comes
    /// from the host session (the Core service / endpoint agent
    /// process). When wired, an unauthenticated requester refuses
    /// browse/restore outright. When NOT wired, scope checks compare
    /// the claimed identity only — host wiring MUST supply this
    /// before any real endpoint exposes self-restore; that
    /// dependency is named here, not silent.</param>
    public BackupEngine(BackupSnapshotStore store, IBackupCaptureSource capture, ChainedAuditLog audit,
        JobJournal? journal = null, SignedCommandVerifier? commandVerifier = null,
        Func<string, bool>? policyGate = null,
        Func<RestoreRequester, bool>? requesterAuthenticator = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _capture = capture ?? throw new ArgumentNullException(nameof(capture));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _journal = journal;
        _commandVerifier = commandVerifier;
        _policyGate = policyGate;
        _requesterAuthenticator = requesterAuthenticator;
    }

    private string? CheckAuthenticated(RestoreRequester requester, string act)
    {
        if (requester.IsAdmin) return null; // admin identity is proven by the signed envelope, verified per call
        if (_requesterAuthenticator is not null && !_requesterAuthenticator(requester))
            return $"self-{act} refused: the requester's claimed identity ('{requester.UserId}' on '{requester.DeviceId}') could not be authenticated by the host — self-restore acts on authenticated identity, never on a caller-supplied claim";
        return null;
    }

    public BackupSnapshotStore Store => _store;

    private bool PolicyEnabled(string key) => _policyGate?.Invoke(key) ?? true;

    private void RecordRun(BackupJobDefinition job, DateTimeOffset now, bool success, string outcome)
    {
        lock (_gate)
        {
            var prev = _runState.TryGetValue(job.Id, out var p) ? p : (job.DeviceId, null, null, null, 0);
            _runState[job.Id] = success
                ? (job.DeviceId, now, now, outcome, 0)
                : (job.DeviceId, now, prev.Success, outcome, prev.Failures + 1);
        }
    }

    // -- running backups --

    /// <summary>Run one backup job end to end. The run is an RMM-15
    /// job (kind backup, authorised by the presented automation
    /// envelope) when a journal is wired; the journal's steps are
    /// capture → store → verify → seal, all idempotent
    /// (content-addressed writes + read-back verify + atomic seal
    /// are safe to re-run). Completion REQUIRES verified bytes:
    /// the verify step reads every chunk back from storage.</summary>
    public BackupRunOutcome RunBackup(BackupJobDefinition job, SignedCommandEnvelope? envelope, DateTimeOffset now)
    {
        BackupRunOutcome Fail(string outcome, string? jobId = null, string? snapshotId = null)
        {
            RecordRun(job, now, false, outcome);
            _audit.Append("backup_failed", "backup-engine",
                $"job={job.Id} device={job.DeviceId} outcome={outcome}", now);
            return new BackupRunOutcome(false, outcome, snapshotId, jobId, 0, 0);
        }

        if (!PolicyEnabled(BackupPolicyKeys.BackupEnabled))
        {
            const string outcome = "refused: rmm.backup.enabled is OFF by policy";
            _audit.Append("backup_refused", "backup-engine", $"job={job.Id} device={job.DeviceId} reason={outcome}", now);
            return new BackupRunOutcome(false, outcome, null, null, 0, 0);
        }
        if (!job.Enabled) return Fail("job_disabled_by_policy");
        if (_store.CatalogueTampered) return Fail($"catalogue_tampered: {_store.CatalogueState}");
        // D38 F11: a job aimed at another target must not silently
        // write into whichever store this engine happens to hold.
        if (!string.Equals(job.TargetId, _store.TargetId, StringComparison.OrdinalIgnoreCase))
            return Fail($"job_target_mismatch: job '{job.Id}' names target '{job.TargetId}' but this engine's store is '{_store.TargetId}' — refused, nothing written to the wrong target");

        // The RMM-15 job is created BEFORE any byte moves: a crash
        // mid-run leaves a resumable, honest record, not a gap.
        ResumableJob? jjob = null;
        if (_journal is not null)
        {
            jjob = _journal.CreateJob(JobKinds.Backup, job.DeviceId, new[]
            {
                new JobStepDefinition("capture", "capture", StepIdempotency.Idempotent),
                new JobStepDefinition("store", "store", StepIdempotency.Idempotent),
                new JobStepDefinition("verify", "verify", StepIdempotency.Idempotent),
                new JobStepDefinition("seal", "seal", StepIdempotency.Idempotent),
            }, envelope, now);
            if (jjob is null)
                return Fail("refused: the RMM-15 job journal refused job creation (backup runs require a valid automation-class signed envelope — RMM-03)");
            _journal.StartJob(jjob.Id, now);
        }

        string? snapshotId = null;
        bool Begin(string s) => jjob is null || _journal!.BeginStep(jjob.Id, s, now);
        bool Complete(string s) => jjob is null || _journal!.CompleteStep(jjob.Id, s, now);
        BackupRunOutcome FailStep(string s, string outcome)
        {
            if (snapshotId is not null) _store.AbortSnapshot(snapshotId);
            if (jjob is not null) _journal!.FailStep(jjob.Id, s, outcome, now);
            return Fail(outcome, jjob?.Id, snapshotId);
        }

        // capture
        if (!Begin("capture")) return Fail("journal_refused_capture_step", jjob?.Id);
        CaptureResult captured;
        try { captured = _capture.Capture(job, now); }
        catch (Exception ex) { return FailStep("capture", $"capture_failed:{ex.GetType().Name}:{ex.Message}"); }
        if (captured.Items.Count == 0)
            return FailStep("capture",
                job.Kind == BackupKinds.Image && captured.Volumes.Count == 0
                    ? "empty_capture: the image capture produced no volumes — a backup of nothing never reports success"
                    : "empty_capture: the capture produced no files for a non-empty selection — a backup of nothing never reports success");
        if (job.Kind == BackupKinds.Image && captured.Volumes.Count == 0)
            return FailStep("capture", "empty_capture: image capture carried files but no volume layout — a bare-metal restore would have nothing to lay out");
        // D38 F9: capture NOTES are consulted — a capture that could
        // not read part of its selection is a PARTIAL backup, and a
        // partial backup never completes as "completed" with health
        // green. The gaps travel into the run record by name.
        var gaps = captured.Notes.Where(n => n.StartsWith("not_read:", StringComparison.OrdinalIgnoreCase)).ToList();
        if (gaps.Count > 0)
            return FailStep("capture", $"capture_incomplete: the capture could not read {gaps.Count} selection item(s) [{string.Join(", ", gaps)}] — a backup that missed part of its selection does not report success");
        // W12 / DS-P9-F19: a refused CompleteStep fails the run —
        // the journal is the crash/resume record and a backup whose
        // checkpoint did not persist never reports "completed".
        if (!Complete("capture")) return FailStep("capture", "journal_refused_complete_capture_step");

        // store
        if (!Begin("store")) return Fail("journal_refused_store_step", jjob?.Id);
        try
        {
            snapshotId = _store.BeginSnapshot(job, now);
            foreach (var item in captured.Items)
                _store.AddFile(snapshotId, item.RelativePath, item.Content);
            if (job.Kind == BackupKinds.Image) _store.SetVolumes(snapshotId, captured.Volumes);
        }
        catch (Exception ex) { return FailStep("store", $"store_failed:{ex.GetType().Name}:{ex.Message}"); }
        if (!Complete("store")) return FailStep("store", "journal_refused_complete_store_step");

        // verify (read-back, the full-bytes discipline)
        // W12 / DS-P9-F20: journal refusals route through FailStep so
        // the staged snapshot is aborted, not leaked with its chunks.
        if (!Begin("verify")) return FailStep("verify", "journal_refused_verify_step");
        var (verified, verifyDetail) = _store.VerifyStaged(snapshotId!);
        if (!verified) return FailStep("verify", $"verify_failed:{verifyDetail}");
        if (!Complete("verify")) return FailStep("verify", "journal_refused_complete_verify_step");

        // policy kill-switch race: re-check before the seal commits
        if (!PolicyEnabled(BackupPolicyKeys.BackupEnabled))
        {
            if (snapshotId is not null) _store.AbortSnapshot(snapshotId);
            if (jjob is not null) _journal!.FailStep(jjob.Id, "seal", "policy_disabled_mid_run", now);
            return Fail("policy_disabled_mid_run", jjob?.Id, snapshotId);
        }

        // seal
        if (!Begin("seal")) return FailStep("seal", "journal_refused_seal_step"); // DS-P9-F20
        BackupSnapshot sealedSnapshot;
        try { sealedSnapshot = _store.SealSnapshot(snapshotId!, job.RetentionDays, now); }
        catch (Exception ex) { return FailStep("seal", $"seal_failed:{ex.GetType().Name}:{ex.Message}"); }
        if (!Complete("seal")) return FailStep("seal", "journal_refused_complete_seal_step");

        RecordRun(job, now, true, "completed");
        _audit.Append("backup_completed", "backup-engine",
            $"job={job.Id} device={job.DeviceId} snapshot={sealedSnapshot.Id} files={sealedSnapshot.FileCount} bytes={sealedSnapshot.TotalBytes} retention_until={sealedSnapshot.RetentionExpiresUtc:O} catalogue_head={_store.CatalogueHeadHash} verify='{verifyDetail}' notes='{string.Join(", ", captured.Notes)}'", now);
        return new BackupRunOutcome(true, "completed", sealedSnapshot.Id, jjob?.Id, sealedSnapshot.TotalBytes, sealedSnapshot.FileCount);
    }

    // -- browsing + restore --

    /// <summary>Browse inside a snapshot — for an image snapshot
    /// this IS browsing inside the image: the manifest's
    /// volume-prefixed file list, no bytes moved. Scope-checked
    /// exactly like a restore (browsing another user's backup is
    /// reading it).</summary>
    public (IReadOnlyList<BackupManifestEntry>? Entries, string? Refusal) BrowseSnapshot(
        string snapshotId, RestoreRequester requester, DateTimeOffset now)
    {
        // D38 F11: browse enforces the SAME gates restore does —
        // policy toggle and catalogue tamper — not a subset.
        if (!PolicyEnabled(BackupPolicyKeys.BackupEnabled))
            return (null, "rmm.backup.enabled is OFF by policy — browse refuses");
        if (_store.CatalogueTampered)
            return (null, $"catalogue_tampered: {_store.CatalogueState} — browse refuses until the catalogue is dealt with");
        if (CheckAuthenticated(requester, "browse") is { } authRefusal) return (null, authRefusal);
        var scope = CheckScope(snapshotId, requester, now, "browse");
        if (scope is not null) return (null, scope);
        var manifest = _store.GetManifestVerified(snapshotId);
        if (manifest is null)
            return (null, $"snapshot '{snapshotId}' manifest failed verification against the catalogue — browse refused (a manifest that does not match its chained hash is not browsed, it is reported)");
        return (manifest.Entries, null);
    }

    /// <summary>Restore files from a snapshot (file backup, or
    /// files browsed out of an image — the same path). Every file
    /// is hash-verified against the manifest BEFORE it is written;
    /// a mismatch aborts the restore, rolls back what this restore
    /// already wrote, and names the lying entry.</summary>
    public RestoreOutcome RestoreFiles(
        string snapshotId, IReadOnlyList<string>? paths, IRestoreTarget target,
        RestoreRequester requester, SignedCommandEnvelope? envelope, DateTimeOffset now,
        bool allowSystemPaths = false)
    {
        RestoreOutcome Refuse(string reason)
        {
            _audit.Append("restore_refused", requester.UserId,
                $"snapshot={snapshotId} device={requester.DeviceId} reason={reason}", now);
            return new RestoreOutcome(false, reason, 0, 0);
        }

        if (!PolicyEnabled(BackupPolicyKeys.BackupEnabled))
            return Refuse("rmm.backup.enabled is OFF by policy — restores refuse");
        if (_store.CatalogueTampered)
            return Refuse($"catalogue_tampered: {_store.CatalogueState} — restores refuse until the catalogue is dealt with");
        var snapshot = _store.GetSnapshot(snapshotId);
        if (snapshot is null || !snapshot.IsSealed)
            return Refuse($"snapshot '{snapshotId}' does not exist or is not sealed — nothing to restore");

        var payloadBindsDestination = false;
        if (requester.IsAdmin)
        {
            if (_commandVerifier is null)
                return Refuse("no signed-command verifier is wired on this engine — hub/admin restores refuse (RMM-03)");
            var verdict = _commandVerifier.Verify(envelope, now, SignedCommandClasses.Automation);
            if (!verdict.Allowed) return Refuse($"signed restore command refused: {verdict.Reason}");
            var expected = $"acp-backup-restore-v1|{snapshotId}|{snapshot.DeviceId}";
            var payloadText = verdict.Payload is null ? "" : Encoding.UTF8.GetString(verdict.Payload);
            // W12 / DS-P9-F16: the v2 payload additionally binds the
            // destination root, the system-path permission and the
            // selected paths. A v1 envelope remains valid for
            // ordinary restores, but it can NEVER authorize a
            // system-path destination — that requires v2.
            var pathsPart = paths is null ? "*" : string.Join(",", paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase));
            var expectedV2 = $"acp-backup-restore-v2|{snapshotId}|{snapshot.DeviceId}|{target.RootPath}|{(allowSystemPaths ? "true" : "false")}|{pathsPart}";
            payloadBindsDestination = payloadText == expectedV2;
            if (payloadText != expected && !payloadBindsDestination)
                return Refuse("signed restore command payload does not bind this snapshot and device — refused (an envelope minted for another restore restores nothing here)");
        }
        else
        {
            if (CheckAuthenticated(requester, "restore") is { } authRefusal) return Refuse(authRefusal);
            var scope = CheckScope(snapshotId, requester, now, "restore");
            if (scope is not null) return Refuse(scope);
        }

        // Destination discipline. D38 F6: allowSystemPaths is
        // honoured ONLY for an admin requester whose signed envelope
        // verified above — a self-restore caller cannot set the flag
        // and walk into the OS tree.
        var systemAllowed = allowSystemPaths && requester.IsAdmin;
        // W12 / DS-P9-F16: exercising the system-path permission
        // requires the v2 payload that binds THIS destination, the
        // flag and the selected paths — a v1 envelope issued for a
        // benign restore cannot be redirected into the OS tree.
        if (systemAllowed && IsSystemPath(target.RootPath) && !payloadBindsDestination)
            return Refuse("restore destination is a system path but the signed payload does not bind this destination/permission (acp-backup-restore-v2 required) — refused (DS-P9-F16)");
        if (!systemAllowed && IsSystemPath(target.RootPath))
            return Refuse($"restore destination '{target.RootPath}' is a system path — restoring over system paths is refused by default (only a signed admin restore may explicitly allow it)");

        var manifest = _store.GetManifestVerified(snapshotId);
        if (manifest is null)
            return Refuse($"snapshot '{snapshotId}' manifest failed verification against the catalogue — restore refused (the manifest in storage does not match its chained hash)");

        // D38 F12: duplicate or case-colliding paths refuse BY NAME
        // instead of throwing from a lookup or silently restoring a
        // subset.
        if (manifest.Entries.GroupBy(e => e.Path, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
            return Refuse($"manifest for snapshot '{snapshotId}' carries duplicate (case-colliding) paths — restore refused");
        List<BackupManifestEntry> wanted;
        if (paths is null || paths.Count == 0)
        {
            wanted = manifest.Entries.ToList();
        }
        else
        {
            var distinct = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (distinct.Count != paths.Count)
                return Refuse("restore request carries duplicate paths — refused (name each file once)");
            var byPath = manifest.Entries.ToDictionary(e => e.Path, StringComparer.OrdinalIgnoreCase);
            wanted = new List<BackupManifestEntry>();
            foreach (var p in distinct)
            {
                if (!byPath.TryGetValue(p, out var entry))
                    return Refuse($"path '{p}' is not in snapshot '{snapshotId}' — restore refused (nothing partial on a mistaken request)");
                wanted.Add(entry);
            }
        }

        // D38 F8, phase 1: assemble and verify EVERY file before a
        // single byte is written. A lying manifest or poisoned chunk
        // now aborts the restore with the target untouched, instead
        // of leaving earlier files already on disk.
        var staged = new List<(BackupManifestEntry Entry, byte[] Bytes)>();
        foreach (var entry in wanted)
        {
            if (BackupSnapshotStore.ValidateManifestPath(entry.Path) is { } pathErr)
                return Refuse($"manifest entry refused: {pathErr} — restore aborted before any file was written");
            byte[] assembled;
            try
            {
                using var ms = new MemoryStream();
                foreach (var chunk in entry.ChunkHashes)
                {
                    var bytes1 = _store.ReadChunkVerified(chunk);
                    ms.Write(bytes1, 0, bytes1.Length);
                }
                assembled = ms.ToArray();
            }
            catch (Exception ex)
            {
                return Refuse($"chunk verification failed for '{entry.Path}': {ex.Message} — restore aborted before any file was written");
            }
            if (assembled.LongLength != entry.SizeBytes || BackupHashing.Sha256Hex(assembled) != entry.FileHash)
                return Refuse($"manifest_hash_mismatch:{entry.Path} — the manifest lies about this file's contents (assembled {assembled.LongLength} bytes, hash {(assembled.Length == 0 ? "(empty)" : BackupHashing.Sha256Hex(assembled))} != manifest {entry.FileHash}); restore aborted before any file was written, nothing poisoned was written");
            staged.Add((entry, assembled));
        }

        // Phase 2: write, PRESERVING every overwritten original. If
        // a write throws partway through, rollback restores the
        // originals and removes the files this restore created —
        // and rollback failures are NAMED in the outcome and the
        // audit, never swallowed behind a "rolled back" claim.
        var written = new List<(string Path, byte[]? Prior)>();
        long bytes = 0;
        foreach (var (entry, assembled) in staged)
        {
            byte[]? prior;
            try { prior = target.Exists(entry.Path) ? target.Read(entry.Path) : null; }
            catch (Exception ex)
            {
                var rb = Rollback(target, written);
                return Refuse($"restore target refused to read existing '{entry.Path}' before overwrite ({ex.Message}) — restore aborted; rollback: {rb}");
            }
            try { target.Write(entry.Path, assembled); }
            catch (Exception ex)
            {
                var rb = Rollback(target, written);
                _audit.Append("restore_rollback", requester.UserId,
                    $"snapshot={snapshotId} failed_path={entry.Path} rollback={rb}", now);
                return Refuse($"restore write failed for '{entry.Path}': {ex.Message} — restore aborted; rollback: {rb}");
            }
            written.Add((entry.Path, prior));
            bytes += assembled.LongLength;
        }

        _audit.Append(requester.IsAdmin ? "restore_completed" : "self_restore_completed", requester.UserId,
            $"snapshot={snapshotId} device={snapshot.DeviceId} files={written.Count} bytes={bytes} destination={target.RootPath}", now);
        return new RestoreOutcome(true, "completed", written.Count, bytes);
    }

    /// <summary>Undo a partial restore: files this restore created
    /// are deleted; files it OVERWROTE get their original bytes back.
    /// Returns a plain-language result; failures are listed, never
    /// swallowed (D38 F8).</summary>
    private string Rollback(IRestoreTarget target, List<(string Path, byte[]? Prior)> written)
    {
        var failures = new List<string>();
        foreach (var (p, prior) in written.AsEnumerable().Reverse())
        {
            try
            {
                if (prior is not null) target.Write(p, prior);
                else target.Delete(p);
            }
            catch (Exception ex) { failures.Add($"{p}: {ex.Message}"); }
        }
        return failures.Count == 0
            ? $"rolled back {written.Count} file(s), overwritten originals restored"
            : $"rollback INCOMPLETE — {failures.Count} path(s) could not be restored: {string.Join("; ", failures)}";
    }

    private string? CheckScope(string snapshotId, RestoreRequester requester, DateTimeOffset now, string act)
    {
        var snapshot = _store.GetSnapshot(snapshotId);
        if (snapshot is null || !snapshot.IsSealed)
            return $"snapshot '{snapshotId}' does not exist or is not sealed";
        if (!string.Equals(snapshot.DeviceId, requester.DeviceId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("self_restore_refused", requester.UserId,
                $"snapshot={snapshotId} act={act} reason=cross_device snapshot_device={snapshot.DeviceId} requester_device={requester.DeviceId}", now);
            return $"self-{act} refused: snapshot '{snapshotId}' belongs to device '{snapshot.DeviceId}', not the requester's device '{requester.DeviceId}' — self-restore is scoped to the requester's own device";
        }
        if (!string.Equals(snapshot.OwnerUserId, requester.UserId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("self_restore_refused", requester.UserId,
                $"snapshot={snapshotId} act={act} reason=cross_user snapshot_owner={snapshot.OwnerUserId} requester={requester.UserId}", now);
            return $"self-{act} refused: snapshot '{snapshotId}' belongs to user '{snapshot.OwnerUserId}', not the requester '{requester.UserId}' — self-restore is scoped to the requester's own backups";
        }
        return null;
    }

    /// <summary>D38 F6: the system-path guard works on a NORMALISED
    /// path, not a literal C: string. Device prefixes (\\?\, \\.\)
    /// are stripped, admin-share UNC (\\host\C$\...) is mapped back
    /// to its drive path, 8.3 short names for the protected
    /// directories are expanded, and the protected directories are
    /// recognised on ANY drive (Windows is not always on C:). A
    /// bare drive root (C:\, D:\, ...) is itself a system
    /// destination: a restore rooted there writes manifest-relative
    /// paths straight into the OS tree.</summary>
    public static bool IsSystemPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Trim().Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ||
            p.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
            p = p[4..];
        // Admin-share UNC: \\host\C$\Windows\... → C:\Windows\...
        var unc = System.Text.RegularExpressions.Regex.Match(p, @"^\\\\[^\\]+\\([A-Za-z])\$\\(.*)$");
        if (unc.Success) p = $"{unc.Groups[1].Value}:\\{unc.Groups[2].Value}";
        else if (System.Text.RegularExpressions.Regex.IsMatch(p, @"^\\\\[^\\]+\\[A-Za-z]\$$"))
            return true; // the admin share root itself
        // Bare drive root:
        if (System.Text.RegularExpressions.Regex.IsMatch(p, @"^[A-Za-z]:\\?$")) return true;
        // 8.3 expansion for the protected directory names:
        p = System.Text.RegularExpressions.Regex.Replace(p, @"(?i)PROGRA~1(?=\\|$)", "Program Files");
        p = System.Text.RegularExpressions.Regex.Replace(p, @"(?i)PROGRA~2(?=\\|$)", "Program Files (x86)");
        p = System.Text.RegularExpressions.Regex.Replace(p, @"(?i)WINDOW~1(?=\\|$)", "Windows");
        return SystemPathSuffixes.Any(suffix =>
            System.Text.RegularExpressions.Regex.IsMatch(p, $@"^[A-Za-z]:\\{suffix}(\\|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
    }

    private static readonly string[] SystemPathSuffixes =
    {
        @"Windows", @"Program Files", @"Program Files \(x86\)", @"ProgramData\\Microsoft", @"System Volume Information",
    };

    // -- bare-metal plan --

    /// <summary>Build the bare-metal restore plan for an IMAGE
    /// snapshot: volume layout, ordered steps, and the restore-media
    /// shape. The plan is a model — executing it (boot media, a
    /// restore environment writing volumes onto new hardware) is
    /// host wiring, named here rather than simulated.</summary>
    public (BareMetalRestorePlan? Plan, string? Refusal) BuildBareMetalPlan(
        string snapshotId, RestoreRequester requester, SignedCommandEnvelope? envelope, DateTimeOffset now,
        string? targetDeviceId = null)
    {
        // D38 F11: the same policy + tamper gates restore enforces.
        if (!PolicyEnabled(BackupPolicyKeys.BackupEnabled))
            return (null, "rmm.backup.enabled is OFF by policy — bare-metal planning refuses");
        if (_store.CatalogueTampered)
            return (null, $"catalogue_tampered: {_store.CatalogueState} — bare-metal planning refuses until the catalogue is dealt with");
        var snapshot = _store.GetSnapshot(snapshotId);
        if (snapshot is null || !snapshot.IsSealed) return (null, $"snapshot '{snapshotId}' does not exist or is not sealed");
        // Bare-metal is an admin act: it overwrites a machine.
        if (!requester.IsAdmin)
            return (null, "bare-metal restore planning is an admin act — self-restore covers files, not whole machines");
        if (snapshot.Kind != BackupKinds.Image)
            return (null, $"snapshot '{snapshotId}' is a file backup — bare-metal restore needs an image snapshot");
        if (_commandVerifier is null)
            return (null, "no signed-command verifier is wired on this engine — bare-metal planning refuses (RMM-03)");
        var verdict = _commandVerifier.Verify(envelope, now, SignedCommandClasses.Automation);
        if (!verdict.Allowed) return (null, $"signed bare-metal command refused: {verdict.Reason}");
        var manifest = _store.GetManifestVerified(snapshotId);
        if (manifest is null) return (null, $"snapshot '{snapshotId}' manifest failed verification — bare-metal planning refuses");
        // W13 / DS-P9-F16 (closure): the v2 payload binds the
        // snapshot, the source device, the DESTINATION device the
        // plan will restore onto, and the verified manifest hash —
        // the same destination-binding discipline RestoreFiles got
        // in W12. Naming a destination REQUIRES the v2 payload: a
        // v1 envelope minted for a same-device plan can never be
        // redirected onto different hardware. With no destination
        // named, v1 remains valid (the plan is for the source
        // device itself, and TargetDeviceId stays null — unnamed,
        // never silently assumed in the record).
        var payloadText = verdict.Payload is null ? "" : Encoding.UTF8.GetString(verdict.Payload);
        var expected = $"acp-backup-restore-v1|{snapshotId}|{snapshot.DeviceId}";
        var expectedV2 = targetDeviceId is null ? null
            : $"acp-backup-restore-v2|{snapshotId}|{snapshot.DeviceId}|{targetDeviceId}|{snapshot.ManifestHash}";
        var bindsV2 = expectedV2 is not null && payloadText == expectedV2;
        if (targetDeviceId is not null && !bindsV2)
            return (null, "a destination device was named but the signed payload does not bind this snapshot, source, destination and manifest (acp-backup-restore-v2 required) — refused (DS-P9-F16)");
        if (targetDeviceId is null && payloadText != expected)
            return (null, "signed bare-metal command payload does not bind this snapshot and device — refused");

        var steps = new List<string>
        {
            "boot the target hardware from the ACP restore media (model shape below; media production is host wiring)",
            "verify this plan's hash against the hub-signed command before writing anything",
        };
        if (targetDeviceId is not null)
            steps.Insert(1, $"destination binding (v2): this plan restores onto device '{targetDeviceId}' and no other — the signed payload binds that destination and the source manifest hash");
        foreach (var vol in manifest.Volumes.OrderBy(v => v.PartitionIndex))
            steps.Add($"recreate partition {vol.PartitionIndex} ({vol.FileSystem}, {vol.SizeBytes} bytes{(vol.IsBoot ? ", boot" : "")}{(vol.IsSystem ? ", system" : "")}) and restore volume '{vol.VolumeId}' file-by-file from the verified manifest");
        steps.Add("verify every restored volume against the manifest hashes before first boot");
        steps.Add("first boot into the restored OS; the endpoint agent re-registers and resumes its job journal");

        var planHash = BackupHashing.Sha256Hex(JsonSerializer.Serialize(new
        {
            snapshot = snapshotId, manifest = snapshot.ManifestHash,
            volumes = manifest.Volumes.Select(v => v.VolumeId).ToArray(), steps,
        }));
        var media = new RestoreMediaShape(Guid.NewGuid().ToString("N"), snapshotId, planHash, now);
        var plan = new BareMetalRestorePlan(snapshotId, snapshot.DeviceId, planHash, manifest.Volumes, steps, media, targetDeviceId);
        _audit.Append("bare_metal_plan_created", requester.UserId,
            $"snapshot={snapshotId} device={snapshot.DeviceId} plan={planHash} volumes={manifest.Volumes.Count} media={media.MediaId}", now);
        return (plan, null);
    }

    // -- deletion / purge (audited wrappers over the store) --

    /// <summary>Handle a delete request for a snapshot — from the
    /// agent, from a user, or under a hub-issued signed command.
    /// The store refuses by shape; this wrapper makes the refusal
    /// (and the attempt) a chained audit event whoever asked.</summary>
    public DeleteOutcome RequestDelete(string snapshotId, string actor, bool underSignedCommand, DateTimeOffset now)
    {
        var outcome = _store.TryDeleteSnapshot(snapshotId, actor, now);
        _audit.Append("snapshot_delete_refused", actor,
            $"snapshot={snapshotId} signed_command={underSignedCommand} reason={outcome.Reason}", now);
        return outcome;
    }

    public PurgeOutcome PurgeExpired(string snapshotId, string actor, DateTimeOffset now, SignedCommandEnvelope? timeAttestation = null)
    {
        var outcome = _store.TryPurgeExpired(snapshotId, now, timeAttestation);
        _audit.Append(outcome.Purged ? "snapshot_purged" : "snapshot_purge_refused", actor,
            $"snapshot={snapshotId} catalogue_head={_store.CatalogueHeadHash} reason={outcome.Reason}", now);
        return outcome;
    }

    // -- schedule + usage + health --

    /// <summary>Jobs from policy content that are due for a device
    /// at `now`, by their schedule against the engine's run state
    /// (falling back to the newest sealed snapshot's capture time
    /// for a job the engine has not run this session).</summary>
    public IReadOnlyList<BackupJobDefinition> DueJobs(IEnumerable<BackupJobDefinition> jobs, string deviceId, DateTimeOffset now)
    {
        var due = new List<BackupJobDefinition>();
        foreach (var job in jobs.Where(j => j.Enabled && string.Equals(j.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)))
        {
            // D38 F10: due-ness is judged against THIS JOB's last
            // attempt — a sibling job's runs never reset it.
            DateTimeOffset? lastAttempt;
            lock (_gate)
                lastAttempt = _runState.TryGetValue(job.Id, out var s) ? s.Attempt : null;
            lastAttempt ??= _store.Snapshots
                .Where(s => s.JobId == job.Id && s.IsSealed)
                .Select(s => (DateTimeOffset?)s.CapturedUtc).Max();
            if (job.Schedule.IsDue(lastAttempt, now)) due.Add(job);
        }
        return due;
    }

    public BackupUsageReport Usage(DateTimeOffset now)
    {
        var sealedSnapshots = _store.Snapshots.Where(s => s.IsSealed).ToList();
        var storedChunks = new Dictionary<string, long>(StringComparer.Ordinal);
        long lockedBytes = 0;
        var locked = 0;
        foreach (var s in sealedSnapshots)
        {
            if (s.IsLocked(now)) { locked++; lockedBytes += s.TotalBytes; }
            var manifest = _store.GetManifestVerified(s.Id);
            if (manifest is null) continue;
            foreach (var entry in manifest.Entries)
                for (var i = 0; i < entry.ChunkHashes.Count; i++)
                {
                    var hash = entry.ChunkHashes[i];
                    if (storedChunks.ContainsKey(hash)) continue;
                    // Chunk size: all but a file's last chunk are full-size.
                    var size = i < entry.ChunkHashes.Count - 1
                        ? BackupSnapshotStore.ChunkSizeBytes
                        : entry.SizeBytes - (long)BackupSnapshotStore.ChunkSizeBytes * (entry.ChunkHashes.Count - 1);
                    storedChunks[hash] = Math.Max(0, size);
                }
        }
        return new BackupUsageReport(
            _store.TargetId, sealedSnapshots.Count, locked,
            sealedSnapshots.Sum(s => s.TotalBytes), storedChunks.Values.Sum(), lockedBytes,
            sealedSnapshots.Select(s => s.SealedUtc).Min(), sealedSnapshots.Select(s => s.SealedUtc).Max(),
            StorageFreeBytesSafe());
    }

    private long? StorageFreeBytesSafe()
    {
        // The engine does not hold the raw storage; the store's
        // usage is computed from the catalogue. Free space is read
        // through the store-exposed seam below when available.
        return _store.StorageFreeBytes;
    }

    // -- the health-facts seam --

    public BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now) =>
        GetFacts(deviceId, jobId: null, now);

    /// <summary>D38 F10: health facts can be taken PER JOB (the
    /// per-job condition-id shape BackupConditionKinds.ConditionId
    /// exists for). The device-level overload aggregates the
    /// device's jobs WITHOUT letting one job's success erase a
    /// sibling's failures: the reported outcome is the most recent
    /// attempt's, and consecutive failures are summed over jobs
    /// whose last outcome was a failure.</summary>
    public BackupHealthFacts GetFacts(string deviceId, string? jobId, DateTimeOffset now)
    {
        (DateTimeOffset? Attempt, DateTimeOffset? Success, string? Outcome, int Failures) state;
        lock (_gate)
        {
            if (jobId is not null)
            {
                state = _runState.TryGetValue(jobId, out var s) ? (s.Attempt, s.Success, s.Outcome, s.Failures) : (null, null, null, 0);
            }
            else
            {
                var mine2 = _runState.Values
                    .Where(s => string.Equals(s.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToList();
                var latest = mine2.Where(s => s.Attempt is not null).OrderByDescending(s => s.Attempt).FirstOrDefault();
                // W12 / DS-P9-F14: the device-level outcome must not
                // hide a failing sibling job behind a newer success —
                // when any job is failing, the aggregate outcome is
                // the most recent FAILING job's outcome.
                var latestFailing = mine2.Where(s => s.Attempt is not null && s.Outcome is not null && s.Outcome != "completed")
                    .OrderByDescending(s => s.Attempt).FirstOrDefault();
                state = mine2.Count == 0
                    ? (null, null, null, 0)
                    : (mine2.Select(s => s.Attempt).Max(),
                       mine2.Select(s => s.Success).Max(),
                       latestFailing.Outcome ?? latest.Outcome,
                       mine2.Where(s => s.Outcome is not null && s.Outcome != "completed").Sum(s => s.Failures));
            }
        }
        var mine = _store.Snapshots
            .Where(s => string.Equals(s.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) && s.IsSealed
                        && (jobId is null || s.JobId == jobId)).ToList();
        var success = state.Success ?? mine.Select(s => (DateTimeOffset?)s.SealedUtc).Max();
        var locked = mine.Where(s => s.IsLocked(now)).ToList();
        return new BackupHealthFacts(
            deviceId,
            state.Attempt,
            success,
            state.Outcome,
            state.Failures,
            locked.Count,
            locked.Sum(s => s.TotalBytes),
            StorageReachableSafe(),
            StorageFreePercentSafe(),
            _store.CatalogueTampered,
            now);
    }

    private bool StorageReachableSafe() => _store.StorageReachable;
    private double? StorageFreePercentSafe() => _store.StorageFreePercent;
}

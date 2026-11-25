using System.Text.Json;

namespace Acp.Shared.Security;

// =====================================================================
// RMM-03 residual closure (RMM-02 precondition, 2026-11-21) —
// PERSISTED replay guard.
//
// The original SignedCommandReplayGuard is in-memory: a Core
// restart cleared every seen nonce, so an envelope captured before
// the restart could be replayed after it (within its TTL). This
// store closes that: seen nonces live in a data-dir file, written
// temp+replace (the UpdateManager / JobJournal pointer discipline),
// and are pruned only once their envelope's expiry + margin has
// passed (a replay after that point is refused by the expiry check
// anyway, so pruning cannot reopen a window).
//
// Crash consistency (D38 F5): the store and its anchor are two
// files, so a crash between their replaces is a real state, not a
// torn one — and it must not brick the store. Every flush carries
// a GENERATION and an internal checksum over (floor, generation,
// nonces); the anchor records "generation:hash". On load:
//   * anchor matches the file          → loaded;
//   * anchor is exactly BEHIND a file whose internal checksum
//     verifies (the crash-between-replaces state) → RECOVERED:
//     the file is accepted and the anchor is rewritten to match;
//   * file generation BEHIND the anchor (rollback), checksum
//     invalid, or anchor ahead in any other way → BROKEN.
// The anchor is an UNKEYED hash: it detects naive tampering,
// partial writes and single-file rollback, but an actor who can
// rewrite BOTH files consistently can roll the pair back — that
// residual is named here, not claimed away (a keyed MAC needs a
// vault-held store key; see the RMM-03 nonce ledger).
//
// Fail-closed posture: a store file that exists but does not parse
// is BROKEN, and a broken store refuses EVERY registration — the
// guard would rather deny a fresh command than admit a replay it
// can no longer rule out. The broken state is named on the store
// (State), never silent. A missing file is a fresh store (first
// boot), which is the only empty state that is not a refusal.
// =====================================================================

/// <summary>The replay-guard contract the verifier consumes. The
/// in-memory guard and the persisted guard share it, so Core wiring
/// chooses durability without touching verification logic.</summary>
public interface IReplayGuard
{
    /// <summary>True when the nonce was NOT seen before (and is now
    /// registered); false on replay or when registration cannot be
    /// trusted (broken store).</summary>
    bool TryRegister(SignedCommandEnvelope e, DateTimeOffset now);
}

/// <summary>One persisted seen-nonce: the (key id, nonce) pair and
/// the instant after which it may be pruned.</summary>
public sealed record PersistedNonce(string KeyId, string Nonce, DateTimeOffset KeepUntilUtc);

/// <summary>File-backed nonce store. Thread-safe; every accepted
/// registration is flushed to disk BEFORE TryRegister returns true,
/// so a crash after acceptance can never lose the registration —
/// that ordering is the whole point of the store.</summary>
public sealed class PersistedNonceStore
{
    private readonly string _path;
    private readonly Dictionary<string, DateTimeOffset> _seen = new(); // keyId|nonce -> keep-until
    private readonly object _gate = new();
    private bool _broken;
    private string _state;
    // D38 F9(c): the highest instant this store has ever pruned
    // against, persisted in the file. Pruning uses max(now, floor):
    // moving the wall clock BACK after a prune can no longer make
    // a pruned envelope's nonce "unexpired and unseen" again —
    // the store's own clock never goes backwards.
    private DateTimeOffset _floorUtc = DateTimeOffset.MinValue;

    // D38 F5: the generation of the loaded file (0 for legacy
    // shapes). Every flush increments it; the anchor records it,
    // which is what makes crash-between-replaces recoverable and
    // single-file rollback detectable.
    private long _generation;

    /// <summary>On-disk shape (v3): the prune floor, a monotonic
    /// GENERATION and an internal CHECKSUM over (floor, generation,
    /// nonces) ride with the nonces. The v2 shape (floor + nonces)
    /// and the v1 shape (a bare list) still load — with no checksum
    /// recorded, so for them the anchor must match exactly, as
    /// before (their crash-recovery starts with the first v3
    /// write).</summary>
    private sealed record StoreFile(DateTimeOffset? FloorUtc, List<PersistedNonce> Nonces,
        long Generation = 0, string? Checksum = null);

    public PersistedNonceStore(string path)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                // D38 F9(b): a missing file is a fresh store ONLY
                // when nothing says a store ever existed. A
                // surviving anchor means the file was deleted —
                // replay history was wiped — and that is named
                // store_lost (BROKEN), never silently "fresh".
                // (Anchor and file are co-located: deleting BOTH
                // is undetectable locally, the same named residual
                // the job journal carries; ACLs on the data dir are
                // the host's half of that defence.)
                if (File.Exists(_path + ".anchor"))
                {
                    _broken = true;
                    _state = $"BROKEN: store_lost — nonce store at '{_path}' is missing but its anchor survives; the replay history was deleted or rolled back and is NOT treated as a fresh store — every registration refuses until the store is restored (fail closed)";
                    return;
                }
                _state = "fresh: no nonce store file yet (first boot)";
                return;
            }
            try
            {
                var raw = File.ReadAllText(_path);
                List<PersistedNonce> dtos;
                string? fileChecksum = null;
                try
                {
                    var file = JsonSerializer.Deserialize<StoreFile>(raw)
                        ?? throw new InvalidOperationException("nonce store parsed to null");
                    dtos = file.Nonces ?? throw new InvalidOperationException("nonce store carries no nonce list");
                    _floorUtc = file.FloorUtc ?? DateTimeOffset.MinValue;
                    _generation = file.Generation;
                    fileChecksum = file.Checksum;
                }
                catch (JsonException)
                {
                    // v1 shape: a bare list of nonces.
                    dtos = JsonSerializer.Deserialize<List<PersistedNonce>>(raw)
                        ?? throw new InvalidOperationException("nonce store parsed to null");
                }
                foreach (var n in dtos)
                {
                    if (string.IsNullOrWhiteSpace(n.KeyId) || string.IsNullOrWhiteSpace(n.Nonce))
                        throw new InvalidOperationException("nonce store carries an empty key id or nonce");
                    _seen[n.KeyId + "|" + n.Nonce] = n.KeepUntilUtc;
                }
                // The v3 internal checksum: verifies the file is
                // internally whole (not torn, not hand-edited)
                // independent of the anchor.
                var checksumOk = fileChecksum is not null
                    && string.Equals(fileChecksum, ChecksumOf(_floorUtc, _generation, dtos), StringComparison.Ordinal);
                if (fileChecksum is not null && !checksumOk)
                {
                    _broken = true;
                    _seen.Clear();
                    _state = $"BROKEN: nonce store at '{_path}' fails its internal checksum — the file is torn or was hand-edited; every registration refuses until the store is repaired (fail closed)";
                    return;
                }
                // Anchor check (D38 F5): the anchor records
                // "generation:hash". A mismatch is BROKEN — except
                // the one state a crash can honestly produce: the
                // store was replaced, the anchor was not yet, and
                // the store's own checksum verifies. That state
                // RECOVERS (anchor rewritten) instead of bricking
                // every signed command until a human repairs it.
                if (File.Exists(_path + ".anchor"))
                {
                    var anchor = File.ReadAllText(_path + ".anchor").Trim();
                    var (anchorGen, anchorHash) = ParseAnchor(anchor);
                    var hashMatches = string.Equals(anchorHash, AnchorOf(raw, _seen.Count), StringComparison.Ordinal);
                    if (hashMatches && (anchorGen is null || anchorGen.Value == _generation))
                    {
                        // consistent pair — fall through to loaded
                    }
                    else if (checksumOk && anchorGen is not null && _generation > anchorGen.Value)
                    {
                        // Crash between the two replaces (or an
                        // anchor write lost to power failure): the
                        // store on disk is whole and NEWER than its
                        // anchor. Accept it and repair the anchor.
                        try
                        {
                            WriteFileFsync(_path + ".anchor.tmp", AnchorText(_generation, AnchorOf(raw, _seen.Count)));
                            File.Move(_path + ".anchor.tmp", _path + ".anchor", overwrite: true);
                            _state = $"recovered: {_seen.Count} seen nonce(s) restored; the store (generation {_generation}) was ahead of its anchor (generation {anchorGen.Value}) — a crash between the store and anchor writes; the anchor was rewritten to match (D38 F5)";
                            return;
                        }
                        catch
                        {
                            _broken = true;
                            _seen.Clear();
                            _state = $"BROKEN: nonce store at '{_path}' was ahead of its anchor but the anchor could not be rewritten — every registration refuses until the store is repaired (fail closed)";
                            return;
                        }
                    }
                    else
                    {
                        _broken = true;
                        _seen.Clear();
                        _state = $"BROKEN: nonce store at '{_path}' does not match its anchor — the file was replaced or rolled back; every registration refuses until the store is repaired (fail closed)";
                        return;
                    }
                }
                _state = $"loaded: {_seen.Count} seen nonce(s) restored from disk";
            }
            catch (Exception ex)
            {
                _broken = true;
                _seen.Clear();
                _state = $"BROKEN: nonce store at '{_path}' did not load ({ex.GetType().Name}) — every registration refuses until the store is repaired (fail closed: an unreadable replay history can never be treated as an empty one)";
            }
        }
    }

    private static string AnchorOf(string raw, int count) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(raw + "|" + count))).ToLowerInvariant();

    /// <summary>The v3 internal checksum: SHA-256 over the
    /// canonical (floor, generation, ordered nonces) content —
    /// computed from the PARSED values, so it verifies the file's
    /// meaning, not its formatting.</summary>
    private static string ChecksumOf(DateTimeOffset floorUtc, long generation, List<PersistedNonce> dtos)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("acp-nonce-store-v3|").Append(floorUtc.ToString("O")).Append('|').Append(generation);
        foreach (var n in dtos.OrderBy(n => n.KeyId, StringComparer.Ordinal).ThenBy(n => n.Nonce, StringComparer.Ordinal))
            sb.Append('|').Append(n.KeyId).Append('|').Append(n.Nonce).Append('|').Append(n.KeepUntilUtc.ToString("O"));
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    private static string AnchorText(long generation, string hash) => $"{generation}:{hash}";

    /// <summary>Parse an anchor: "generation:hash" (v3) or a bare
    /// hash (legacy — generation unknown, null).</summary>
    private static (long? Generation, string Hash) ParseAnchor(string anchor)
    {
        var sep = anchor.IndexOf(':');
        if (sep > 0 && long.TryParse(anchor[..sep], out var gen))
            return (gen, anchor[(sep + 1)..]);
        return (null, anchor);
    }

    /// <summary>Named store health: "fresh…", "loaded: N…", or
    /// "BROKEN: …". Surfaced so Core can report the posture instead
    /// of implying coverage it does not have.</summary>
    public string State { get { lock (_gate) return _state; } }
    public bool IsBroken { get { lock (_gate) return _broken; } }
    public int TrackedCount { get { lock (_gate) return _seen.Count; } }

    /// <summary>Register a nonce durably. Returns false when the
    /// nonce was already seen (in memory OR restored from disk —
    /// the restart case) or when the store is broken / the flush
    /// failed (the in-memory registration is rolled back, so memory
    /// and disk never disagree about what was accepted).</summary>
    public bool TryRegister(SignedCommandEnvelope e, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_broken) return false;
            // Monotonic floor (D38 F9(c)): the store's clock never
            // moves backwards, for pruning or for the floor itself.
            var effectiveNow = now > _floorUtc ? now : _floorUtc;
            _floorUtc = effectiveNow;
            PruneLocked(effectiveNow);
            // An envelope already expired by the store's monotonic
            // clock refuses even when the caller's (rolled-back)
            // clock calls it live: once its nonce has been pruned,
            // this check is the only thing standing between a
            // clock rollback and a replay, so it is structural,
            // not a courtesy. (With an honest clock the verifier's
            // own expiry check fires first — same verdict.)
            if (e.ExpiresUtc <= effectiveNow) return false;
            var id = e.KeyId + "|" + e.Nonce;
            if (_seen.ContainsKey(id)) return false;
            _seen[id] = e.ExpiresUtc.AddMinutes(5);
            try { FlushLocked(); }
            catch
            {
                _seen.Remove(id);
                _broken = true;
                _state = "BROKEN: nonce store flush failed — registrations refuse (fail closed)";
                return false;
            }
            return true;
        }
    }

    private void PruneLocked(DateTimeOffset now)
    {
        var stale = _seen.Where(kv => kv.Value < now).Select(kv => kv.Key).ToList();
        foreach (var s in stale) _seen.Remove(s);
    }

    private void FlushLocked()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        var dtos = _seen.Select(kv =>
        {
            var sep = kv.Key.IndexOf('|');
            return new PersistedNonce(kv.Key[..sep], kv.Key[(sep + 1)..], kv.Value);
        }).OrderBy(n => n.KeyId, StringComparer.Ordinal).ThenBy(n => n.Nonce, StringComparer.Ordinal).ToList();
        _generation++;
        var raw = JsonSerializer.Serialize(new StoreFile(_floorUtc, dtos, _generation,
            ChecksumOf(_floorUtc, _generation, dtos)));
        var tmp = _path + ".tmp";
        // D38 F9(a): flush-before-accept must reach the DISK, not
        // just the OS page cache — WriteAllText + Move left a
        // power-loss window in which an accepted nonce vanished
        // while its command had already run. The temp file is
        // fsynced BEFORE the rename, and the anchor after it.
        // D38 F5: a crash between the two renames is recovered at
        // load (generation + internal checksum), never a brick.
        WriteFileFsync(tmp, raw);
        File.Move(tmp, _path, overwrite: true);
        WriteFileFsync(_path + ".anchor.tmp", AnchorText(_generation, AnchorOf(raw, dtos.Count)));
        File.Move(_path + ".anchor.tmp", _path + ".anchor", overwrite: true);
    }

    private static void WriteFileFsync(string path, string content)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        fs.Write(bytes, 0, bytes.Length);
        fs.Flush(true);
    }
}

/// <summary>The persisted replay guard: the RMM-03 guard's exact
/// semantics (single-use nonce per key, kept until expiry + 5 min,
/// pruned on access) backed by <see cref="PersistedNonceStore"/> so
/// they survive a Core restart.</summary>
public sealed class PersistedSignedCommandReplayGuard : IReplayGuard
{
    private readonly PersistedNonceStore _store;
    public PersistedSignedCommandReplayGuard(PersistedNonceStore store) =>
        _store = store ?? throw new ArgumentNullException(nameof(store));
    public PersistedNonceStore Store => _store;
    public bool TryRegister(SignedCommandEnvelope e, DateTimeOffset now) => _store.TryRegister(e, now);
}

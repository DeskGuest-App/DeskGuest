using System.Security.Cryptography;
using System.Threading;
using Acp.Shared.Enterprise;

namespace Acp.Shared.Update;

/// <summary>
/// W15 / DS-P9-F18 limb (b): pointer integrity WITHOUT a production
/// signing key. The pointer file (active-slot.json) is unsigned; an
/// attacker who can rewrite BOTH the slot and the pointer defeats
/// the slot hash alone. What exists without a key is the Core's
/// enterprise audit chain — a hash-chained, append-only record in a
/// DIFFERENT file (enterprise-audit.json in the data dir, beside
/// the updates root). Since W15 the Core records the SHA-256 of
/// every pointer state it writes into that chain
/// (kind "update_pointer_written", via UpdateManager's pointerAudit
/// seam + EnterpriseService.AppendServiceAudit, which persists the
/// chain on every append).
///
/// The launcher cross-checks before exec:
///   * no audit file / no pointer record → the named LEGACY posture:
///     the slot decision rests on the slot hash alone, exactly as
///     before W15, and the reason string says so;
///   * audit chain BROKEN, record malformed, or the on-disk
///     pointer's hash ≠ the last recorded hash → the slot is
///     REFUSED by name (fallback to base binaries). A pointer-only
///     rewrite — the F18 limb as named — is caught here.
///
/// W17 / DS-B-16 — the downgrade-by-deletion leg, CLOSED as far as
/// is sound without a key. The W15 shape above had a hole named exactly: deleting enterprise-audit.json, truncating it to
/// "[]", or truncating it to a valid prefix carrying no pointer
/// record all landed in the LEGACY branch — an attacker with data-
/// dir write access could strip the anchor and have a rewritten
/// pointer + slot judged as a pre-anchor install. The fix is that
/// anchor PRESENCE is itself witnessed in two other places:
///   * the Core writes a marker (pointer-anchor.marker) into the
///     UPDATES ROOT on every audit-anchored pointer write
///     (UpdateManager.WritePointer, only when the audit seam is
///     wired — the marker witnesses "this pointer was anchored");
///   * the launcher writes a marker into the directory it is given
///     as <paramref name="markerDir"/> (production: the install
///     root, a different ACL domain from the data dir) on every
///     VOUCHED check, recording the pointer hash, the chain's
///     entry count and its head hash.
/// Rules from W17:
///   * audit file missing / chain carries no pointer record, but
///     ANY marker survives → REFUSED, by name. Absence-of-record
///     after first anchoring is a refusal, never a downgrade.
///   * chain present and intact, but SHORTER than a launcher
///     marker's recorded entry count, or the same length with a
///     different head → REFUSED (truncated / rolled back /
///     rewritten chain — including the restore-an-old-pointer-
///     plus-old-chain-prefix rollback, whose hashes all match).
///   * the pointer file hashed is the one SlotPointer.ReadDetailed
///     actually SELECTED (main or .bak, via SelectedPath) — the
///     pre-fix code hashed main-if-exists even when the reader
///     had fallen back to the backup, refusing legitimate crash
///     recovery and never checking the file in force.
///   * a vouched check REFRESHES the launcher marker (a legitimate
///     update grows the chain; growth is accepted, shrinkage and
///     same-length rewrite are not).
///
/// W19 / DS-B-16 round-3 closure of the two sound legs:
///   (a) SWAP RACE: Check no longer re-reads the pointer. It hashes
///     the bytes of the single read ResolveTarget consumed
///     (SlotPointerRead.SelectedBytes, carried from ReadDetailed);
///     the standalone Check entry point likewise makes ONE read
///     and hashes the bytes that read parsed.
///   (b) PREFIX BINDING: growth no longer skips the head
///     comparison. For every marker carrying a recorded count +
///     head, the chain entry AT that count must hash-match the
///     recorded head — a grown chain whose genuine prefix was
///     rewritten refuses, however valid its new links are — AND
///     the resolved pointer must match the chain's LAST
///     update_pointer_written record. The marker is refreshed
///     only on a check where BOTH bind.
///
/// W30 / D-DEC-7 — the SIGNATURE leg (W29-A Option 1), closing
/// the W19 remainder at exactly W21 precision. A dedicated runtime
/// Ed25519 pointer-signing keypair (PointerSigningCustody) signs
/// every pointer state the Core commits; the private half is
/// custodied in the install root, outside the data dir, and the
/// public half is pinned in the install root, (re)pinnable only
/// at install / production-signed update events, rotating at each
/// apply. Check now verifies, IN ADDITION TO every binding above
/// and on the same single-read bytes: the selected pointer's
/// signature sidecar against the install-root runtime pin.
/// Migration is fail-closed and named (W29 §4): before first
/// keying, the LEGACY-UNKEYED posture above stands and says so;
/// once keying has begun (witnessed by the updates-root keying
/// marker and/or the install-root pin), an unsigned, badly-signed
/// or pin-less pointer is REFUSED BY NAME — never a downgrade,
/// and the .bak selection is judged under the same posture.
///
/// HONEST LIMIT (W21 precision — narrowed by W30, not erased):
/// the prefix-preserving growth forgery is now CLOSED for a
/// data-dir-only attacker: their appended records and rewritten
/// pointer cannot carry a valid signature, so the forged pointer
/// refuses at the signature leg however valid the chain looks.
/// What remains open, NAMED: replay/rollback when the install
/// root is ALSO writable — the attacker restores an old genuine
/// signed pointer + sidecar + old chain + old pin/marker set and
/// every signature verifies; the marker regression rule still
/// refuses shrinkage only while a genuine launcher marker
/// survives. An attacker executing as the Core/SYSTEM can sign
/// (pre-existing game-over class). Under the UNKEYED legacy
/// posture (pre-keying installs) the W19 limit stands verbatim:
/// a growth forgery preserving the genuine prefix is
/// indistinguishable under an unkeyed chain.
///
/// W36 / DS round-8 — the POSITION leg. Round 8 proved the W30
/// boundary claim WRONG within the data-dir-only model: the
/// signature bound pointer bytes, not chain position/freshness,
/// so an appended record naming an old signed pointer's hash
/// plus that pointer + its genuine sidecar was ACCEPTED (the
/// replay is reproduced in W36PointerPositionTests). Check now
/// adds the position leg on a keyed install: the selected
/// pointer's v2 sidecar must verify over (pointer bytes + the
/// chain index and own hash of the chain's LAST pointer record,
/// read from the verified chain itself — the record's identity
/// IS the commitment; its detail carries the pre-append v2
/// scheme marker as witness). The attacker's appended record sits at a new
/// index with a new hash, so the restored pointer's committed
/// position no longer matches the last pointer record — refusal
/// by name at this leg. Non-pointer growth after the pointer
/// record does NOT invalidate it (the anchor is the last
/// POINTER record, not the chain head). Truncation/rollback
/// WITHOUT the appended record stays refused by the marker /
/// prefix binding above. Migration: W30 v1 (position-less)
/// sidecars are accepted ONLY while no position witness survives
/// (no pointer record carrying a position commitment, no v2
/// sidecar on either pointer file) — the named
/// LEGACY-POSITIONLESS posture, the W17 fail-closed pattern;
/// once position binding has begun, a v1 sidecar refuses by
/// name. NEW BOUNDARY, exact: a data-dir-only attacker can
/// neither forge (W30) nor replay/roll back (W36) a pointer;
/// rollback requires a writable install root (named above) or
/// Core/SYSTEM execution.
///
/// W45 / DS round-9 Item 3 — CORE-ADVANCED freshness. Round 9
/// proved the boundary above still wrong for STAGED pointers:
/// staging does not rotate the pointer-signing key, so two
/// genuine staged writes exist under the same key; the
/// install-root marker vouched only the FIRST position (it was
/// refreshed only on a launcher visit), and restoring the older
/// staged pointer + its genuine sidecar while truncating the
/// chain to EXACTLY the marker's count/head passed every leg —
/// the marker refused lengths BELOW its count but bound no
/// freshness ABOVE it. The fix moves the marker's freshness
/// source from the launcher to the Core: the Core ADVANCES the
/// install-root marker on every anchored append it makes
/// (append first, then marker update to the new count/head, in
/// that order — see AdvanceInstallRootMarker and its callers in
/// EnterpriseService / ComplianceService), so the marker always
/// names the newest genuine chain state the Core itself
/// produced. A crash can therefore leave the chain LONGER than
/// the marker (growth — the prefix rule accepts) but a chain
/// truncated to an older genuine position now MISMATCHES the
/// advanced marker (fewer entries / prefix head differs) and
/// refuses at the same marker leg as before. The launcher keeps
/// verifying and may still refresh the marker on a vouched
/// check; freshness no longer DEPENDS on a launcher visit.
/// Marker-ahead-of-chain (count above the chain's length) is
/// refused by the same leg; under the Core's write order
/// (append → persist → advance) it cannot arise from a Core
/// crash — the marker is only ever written AFTER the append it
/// names is durable — so its presence means the chain was
/// truncated or the marker was written outside the Core, both
/// of which are exactly the refusal case. NEW BOUNDARY, exact:
/// a data-dir-only attacker can neither forge (W30),
/// replay/roll back (W36), nor staged-roll back (W45) a pointer;
/// rollback requires a writable install root (named above) or
/// Core/SYSTEM execution.
///
/// W47 / DS round-10 Item 2 — the advance is ATOMIC with the
/// append it vouches for. Round 10 proved the W45 mechanism
/// itself inadequate in three ways, all one root (the advance
/// was not part of the gated, verified append operation):
///   (1) the pack-compile advance sat OUTSIDE the chain save
///       gate, so a concurrent pointer stage could advance the
///       marker to N+3 and the pack's pending advance then
///       REGRESSED it to its stale snapshot N+2 — after which
///       the round-9 staged rollback passed again;
///   (2) the service-audit advance ran even when SaveChain had
///       SWALLOWED a persistence failure, so marker-ahead-of-
///       chain was reachable, falsifying the W45 crash-window
///       claim as implemented;
///   (3) keyed pack Compile advanced with no chain save at all.
/// The fix, by construction:
///   (a) every Core advance happens INSIDE the chain save gate,
///       AFTER the append's persist is VERIFIED durable — the
///       persisted store is re-read and must match the in-memory
///       chain's (count, head) exactly (EnterpriseService.
///       SaveChainVerifiedLocked / PersistChainVerified). A
///       persist that cannot be verified produces NO advance
///       and a named FAILED state; marker-ahead-of-chain is
///       therefore impossible by construction, not by write
///       order alone: the marker is only ever written after the
///       append it names is proven durable, under the same gate
///       that serializes the appends.
///   (b) a MONOTONICITY GUARD in the advance operation itself
///       (AdvanceInstallRootMarker, below): an attempted advance
///       to a (count, head) below the marker's current value —
///       or a same-count rewrite to a different head — is
///       REFUSED BY NAME and the marker is left unchanged, so
///       no caller, inside or outside the gate, with a fresh or
///       a stale snapshot, can move freshness backward through
///       the advance operation. (The low-level PointerAnchorMarker
///       .Write primitive is unchanged: its install-root callers
///       are this advance and the launcher's vouched refresh,
///       which writes only a chain state that has just passed
///       FreshnessRefusal against the marker — count >= the
///       marker's, prefix-identical at the marker's count — so
///       it is monotonic by the check that precedes it.)
///   (c) the pack-compile path takes the SAME gate and the SAME
///       verified persist as the pointer path when composed
///       with the Core (CoreRuntime wires EnterpriseService's
///       gate + PersistChainVerified into ComplianceService):
///       its two appends, the persist verification and the
///       advance are one gated operation, and the advance is
///       computed from the chain's live entries INSIDE the gate,
///       never from a snapshot taken before it. In compositions
///       with no chain-persistence delegate there is no separate
///       chain store to verify against — the chain is the hub's
///       in-memory ledger whose persistence the composing Core
///       owns — and the advance is still gated, still computed
///       from live entries, still landing-checked, and still
///       guarded by (b).
/// RE-DERIVED CRASH WINDOW, exactly: a crash between the
/// verified persist and the advance leaves the chain LONGER
/// than the marker (accepted growth, prefix binds). A crash
/// cannot leave the marker ahead of the chain: the advance is
/// gated after a verified persist, so every position the
/// marker names was proven durable in the persisted store
/// before the marker moved. Marker-ahead therefore still
/// means exactly what W45 said — truncation, or a marker
/// written outside the Core's advance operation — and refuses
/// at the same leg; the difference is that the Core can no
/// longer produce it itself (round-10 defects 2 and 3), and no
/// advance can regress the marker (defect 1).
///
/// W49 / DS round-11 Item 2 — the guard moves INTO the write
/// primitive, under a CROSS-PROCESS lock. Round 11 proved the
/// W47 construction still inadequate in exactly the two places
/// the W47 log had named as residuals: (1) the guard's
/// read-check-write in AdvanceInstallRootMarker was not itself
/// atomic for callers OUTSIDE the chain gate — writer A reads
/// N and passes for N+2, writer B writes N+3, A writes N+2,
/// regression; (2) the launcher's vouched refresh was the same
/// TOCTOU — FreshnessRefusal passes against marker N, the Core
/// advances to N+4, the launcher's then-unguarded
/// PointerAnchorMarker.Write lands its stale N+3. The Core and
/// the launcher are SEPARATE PROCESSES, so no in-process lock
/// (the chain gate included) can close either shape. The fix:
/// PointerAnchorMarker.Write itself now (a) acquires an
/// OS-level exclusive lock for the marker — a lock file beside
/// the marker in the same directory, opened with
/// FileShare.None and held across the whole read-check-write;
/// a file lock, not a named mutex, because every other custody
/// artefact of this install (marker, pin, signing key) is a
/// file in the install root, the lock therefore travels with
/// the install root it guards, needs no global namespace name
/// derived from a path, and its exclusion is enforced by the
/// kernel per open file description, identically within and
/// across processes; (b) re-reads the CURRENT marker under
/// that lock; (c) REFUSES BY NAME — marker left byte-unchanged
/// — a write that would regress (count below current, or same
/// count with a different head), and a witness-only write
/// (no count proposed) PRESERVES the recorded count/head
/// rather than dropping the regression fields; (d) writes
/// atomically (the W45 per-write GUID tmp + move discipline)
/// and releases. AdvanceInstallRootMarker keeps its API and
/// delegates to the guarded write; the launcher's refresh in
/// Check calls the same primitive, so it is guarded by the
/// same path — its stale write is now refused by name at the
/// primitive and treated as subsumed (a fresher marker already
/// stands). LOCK CONTENTION, named: a writer that cannot
/// acquire the lock within the bounded wait (5 s default)
/// FAILS CLOSED with MarkerLockTimeoutException — it never
/// writes unlocked and never waits forever. CUSTODY: the lock
/// file lives beside the marker in the install root, is
/// created with the platform's default file permissions —
/// on Windows it inherits the install root's ACLs exactly as
/// the marker file itself does; no ACL is widened or set —
/// and it is never deleted (deleting a lock file another
/// process holds would split the lock). Its content is never
/// read; existence + the kernel lock are the whole mechanism.
/// </summary>
public static class PointerAuditAnchor
{
    public const string RecordKind = "update_pointer_written";
    public const string AuditFileName = "enterprise-audit.json";

    /// <summary>Check the on-disk pointer under
    /// <paramref name="updatesRoot"/> against the audit-chained
    /// record in the data dir that is its parent. Ok=true with a
    /// non-null Note is the legacy posture (proceed, named);
    /// Ok=false refuses the slot, with the reason in Note.
    /// <paramref name="markerDir"/>, when supplied (production:
    /// the install root), is where the launcher-side anchor marker
    /// lives: it is consulted on every check and refreshed on
    /// every vouched one (W17 / DS-B-16).</summary>
    public static (bool Ok, string? Note) Check(string updatesRoot, string? markerDir = null)
        => Check(updatesRoot, markerDir, resolvedRead: null);

    /// <summary>W19 / DS-B-16 (a): the ResolveTarget entry point.
    /// <paramref name="resolvedRead"/> is the single pointer read
    /// the caller actually resolved from; the anchor hashes THOSE
    /// bytes (SlotPointerRead.SelectedBytes) and never re-reads
    /// the pointer file, so a main/.bak swap between resolve and
    /// check cannot validate one pointer while executing another's
    /// slot.</summary>
    public static (bool Ok, string? Note) Check(string updatesRoot, string? markerDir, SlotPointerRead? resolvedRead)
    {
        string? dataDir;
        try { dataDir = Path.GetDirectoryName(Path.GetFullPath(updatesRoot)); }
        catch { dataDir = null; }
        if (dataDir is null) return (true, "pointer audit anchor: updates root has no parent data dir — legacy posture (slot hash only)");
        var markers = PointerAnchorMarker.ReadAll(updatesRoot, markerDir);
        // W30 / D-DEC-7 keying state: keying has begun when the
        // install-root runtime pin exists OR the updates-root
        // keying marker survives. Either witness makes every
        // absence below a refusal, never a downgrade (W29 §4).
        var pinExists = PointerSigningCustody.PinFileExists(markerDir);
        var runtimePin = PointerSigningCustody.ReadPin(markerDir);
        var keyingBegun = pinExists || PointerSigningCustody.KeyingMarkerExists(updatesRoot);
        var auditPath = Path.Combine(dataDir, AuditFileName);
        if (!File.Exists(auditPath))
        {
            if (markers.Count > 0)
                return (false, $"pointer audit anchor: the enterprise audit chain is MISSING but an anchor marker survives at '{markers[0].SourcePath}' — a pointer was audit-anchored before, so absence refuses rather than downgrading to the legacy posture (W17/DS-B-16); slot refused");
            if (keyingBegun)
                return (false, "pointer audit anchor: the enterprise audit chain is MISSING but pointer keying has begun (a runtime pin and/or keying marker survives) — absence of the chain after first keying refuses by name rather than downgrading to the LEGACY-UNKEYED posture (W30/D-DEC-7); slot refused");
            return (true, "pointer audit anchor: no enterprise audit chain exists and no anchor marker — LEGACY-UNKEYED posture (legacy posture, slot hash only; no signed pointer has ever been vouched and no runtime pin exists, W30/D-DEC-7)");
        }
        ChainedAuditLog log = new();
        ChainVerification verdict;
        try { verdict = log.ImportEntriesJson(File.ReadAllText(auditPath)); }
        catch (Exception ex) { return (false, $"pointer audit anchor: enterprise audit chain at '{auditPath}' is unreadable ({ex.GetType().Name}) — slot refused"); }
        if (!verdict.Ok)
            return (false, $"pointer audit anchor: enterprise audit chain is BROKEN ({verdict.Summary}) — slot refused rather than trust a pointer the chain cannot vouch for");
        var entries = log.Entries;
        var record = entries.LastOrDefault(e => e.Kind == RecordKind);
        if (record is null)
        {
            if (markers.Count > 0)
                return (false, $"pointer audit anchor: the enterprise audit chain carries NO pointer record but an anchor marker survives at '{markers[0].SourcePath}' — the chain was truncated or replaced after a pointer was anchored (W17/DS-B-16); slot refused rather than downgraded to the legacy posture");
            if (keyingBegun)
                return (false, "pointer audit anchor: the enterprise audit chain carries NO pointer record but pointer keying has begun (a runtime pin and/or keying marker survives) — a chain with no pointer record after first keying refuses by name rather than downgrading to the LEGACY-UNKEYED posture (W30/D-DEC-7); slot refused");
            return (true, "pointer audit anchor: audit chain carries no pointer record and no anchor marker — LEGACY-UNKEYED posture (legacy posture, slot hash only; no signed pointer has ever been vouched and no runtime pin exists, W30/D-DEC-7)");
        }
        var recorded = ExtractHash(record.Detail);
        if (recorded is null)
            return (false, "pointer audit anchor: the last pointer record in the audit chain carries no pointer_sha256 — slot refused");
        // W17 / DS-B-16 rollback rule + W19 / DS-B-16 (b) PREFIX
        // BINDING: a launcher marker records how long the chain
        // was and where its head was when last vouched. A shorter
        // chain was truncated or rolled back. A chain of ANY
        // length >= the recorded count — same length OR grown —
        // must still have, AT the recorded count, the recorded
        // head: the entry at that position hash-matching the
        // marker is what proves the genuine prefix survives. The
        // W17 shape compared heads only at equal length, so a
        // growth forgery over a rewritten prefix skipped the
        // comparison entirely (round-3, verbatim in the
        // W18 confirmation log).
        if (FreshnessRefusal(markers, entries) is { } freshnessRefusal)
            return (false, freshnessRefusal);
        // W17 selection rule + W19 / DS-B-16 (a) SINGLE READ: hash
        // the pointer bytes the resolving read actually consumed
        // (main or .bak, as selected) — never a fresh read of the
        // path. The standalone entry point (no resolved read
        // supplied) makes its ONE read here and hashes the bytes
        // that read parsed.
        var read = resolvedRead ?? SlotPointer.ReadDetailed(updatesRoot);
        var path = read.SelectedPath;
        if (path is null)
            return (false, "pointer audit anchor: an audit-chained pointer record exists but no pointer file was selected by the pointer read — slot refused");
        string current;
        if (read.SelectedBytes is { } resolvedBytes)
        {
            current = Convert.ToHexString(SHA256.HashData(resolvedBytes)).ToLowerInvariant();
        }
        else
        {
            // A caller-constructed read carrying no bytes: hash the
            // SELECTED path once (still never a re-selection).
            try { current = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant(); }
            catch (Exception ex) { return (false, $"pointer audit anchor: pointer file '{path}' could not be hashed ({ex.GetType().Name}) — slot refused"); }
        }
        if (!string.Equals(current, recorded, StringComparison.OrdinalIgnoreCase))
            return (false, $"pointer audit anchor: pointer file '{path}'{(read.FellBack is null ? "" : $" (selected via fallback: {read.FellBack})")} hash {current} does NOT match the audit-chained record {recorded} — the pointer was rewritten outside the Core (DS-P9-F18 limb (b)); slot refused");
        var notePositionless = false;
        // W30 / D-DEC-7 SIGNATURE leg: on a keyed install the
        // selected pointer must ALSO carry a signature, in its
        // sidecar, verifying against the install-root runtime pin
        // over the SAME single-read bytes hashed above. This is
        // the leg that refuses the prefix-preserving growth
        // forgery: the attacker's appended chain record made the
        // hash leg pass, but they hold no signing key. On an
        // unkeyed install (no pin, no keying marker) this leg is
        // the named LEGACY-UNKEYED posture and does not bind.
        if (keyingBegun)
        {
            if (runtimePin is null)
                return (false, $"pointer audit anchor: pointer keying has begun (a keying witness survives) but the runtime public pin in '{markerDir ?? "(no install root supplied)"}' is missing or malformed — a pin-less pointer after first keying refuses by name, never a downgrade to the LEGACY-UNKEYED posture (W30/D-DEC-7); slot refused");
            var sigPath = PointerSigningCustody.SignaturePathFor(path);
            if (!File.Exists(sigPath))
                return (false, $"pointer audit anchor: pointer file '{path}' carries NO signature sidecar ('{sigPath}') but pointer keying has begun — an unsigned pointer after first keying refuses by name, never a downgrade (W30/D-DEC-7); slot refused");
            byte[] signature; bool positionBound;
            try
            {
                if (!PointerSigningCustody.TryParseSidecar(File.ReadAllText(sigPath), out signature, out positionBound))
                    return (false, $"pointer audit anchor: the signature sidecar '{sigPath}' is not base64 on a keyed install — slot refused by name (W30/D-DEC-7)");
            }
            catch (Exception ex) { return (false, $"pointer audit anchor: the signature sidecar '{sigPath}' is unreadable ({ex.GetType().Name}) on a keyed install — slot refused by name (W30/D-DEC-7)"); }
            if (signature.Length != 64)
                return (false, $"pointer audit anchor: the signature sidecar '{sigPath}' carries {signature.Length} bytes — an Ed25519 signature is exactly 64; slot refused by name (W30/D-DEC-7)");
            byte[] signedBytes;
            if (read.SelectedBytes is { } sb) signedBytes = sb;
            else
            {
                try { signedBytes = File.ReadAllBytes(path); }
                catch (Exception ex) { return (false, $"pointer audit anchor: pointer file '{path}' could not be read for signature verification ({ex.GetType().Name}) — slot refused"); }
            }
            // W36 / DS round-8 POSITION leg: a v2 sidecar must
            // verify over (pointer bytes + the LAST pointer
            // record's own chain index and hash, read from the
            // verified chain itself). The commitment needs no
            // separate storage: the record's identity IS the
            // commitment, and the record's detail carries the
            // pre-append scheme marker (pointer_sig_scheme=v2)
            // as the migration witness. This is the leg that
            // refuses the round-8 replay: the attacker's appended
            // record is a DIFFERENT record (new index, new hash)
            // than the one the restored pointer's signature
            // commits to, so verification over the last record's
            // actual position fails.
            if (positionBound)
            {
                if (!HasPositionScheme(record.Detail))
                    return (false, $"pointer audit anchor: pointer file '{path}' carries a POSITION-BOUND (v2) signature but the chain's last pointer record (seq {record.Seq}) carries NO v2 scheme marker — that record is not the record the signature was made over; slot refused by name at the position leg (W36/DS-round-8)");
                var payload = PointerSigningCustody.BuildPositionPayload(signedBytes, record.Seq, record.Hash);
                if (!Security.Ed25519.Verify(runtimePin, payload, signature))
                    return (false, $"pointer audit anchor: pointer file '{path}' POSITION-BOUND signature does NOT verify over the pointer bytes + the last pointer record's position (seq {record.Seq}, hash {record.Hash}) against the install-root runtime pin (fingerprint {PointerSigningCustody.FingerprintOf(runtimePin)}) — the pointer's committed position is not the chain's last pointer record; a data-dir-only replay/rollback (an appended record naming an old signed pointer) is refused at this leg (W36/DS-round-8); slot refused");
            }
            else
            {
                // W36 migration (W17 fail-closed pattern, named):
                // a W30 v1 position-less sidecar is judged under
                // the LEGACY-POSITIONLESS posture ONLY while no
                // position witness survives — no pointer record
                // anywhere in the chain carries the v2 scheme
                // marker and neither pointer file carries a v2
                // sidecar. Once position binding has begun, a
                // position-less signature refuses by name. (The
                // chain-history witness matters: an attacker who
                // deletes both v2 sidecars and restores a v1
                // pointer still faces the genuine v2 records in
                // the prefix the install-root marker binds.)
                var positionBegun = entries.Any(e => e.Kind == RecordKind && HasPositionScheme(e.Detail))
                    || SiblingSidecarIsPositionBound(updatesRoot, path);
                if (positionBegun)
                    return (false, $"pointer audit anchor: pointer file '{path}' carries a POSITION-LESS (v1, W30) signature but position binding has begun (a v2 scheme record / v2 sidecar survives) — the LEGACY-POSITIONLESS posture no longer applies and a position-less pointer refuses by name, never a silent acceptance (W36/DS-round-8, W17 pattern); slot refused");
                if (!Security.Ed25519.Verify(runtimePin, signedBytes, signature))
                    return (false, $"pointer audit anchor: pointer file '{path}' signature does NOT verify against the install-root runtime pin (fingerprint {PointerSigningCustody.FingerprintOf(runtimePin)}) — the pointer was not signed by the custodied runtime key; a data-dir-only growth forgery is refused at this leg (W30/D-DEC-7); slot refused");
                notePositionless = true;
            }
        }
        // Vouched: BOTH bindings held (prefix binding above, and
        // the resolved pointer matching the chain's LAST pointer
        // record — the comparison immediately above). ONLY a check
        // where both bind refreshes the markers (W19/DS-B-16 (b)),
        // so the NEXT absence, truncation, rollback or
        // prefix-rewrite is judged against this state.
        // The updates-root marker is the Core's witness to refresh
        // too (an older Core may not have written one); the
        // markerDir marker carries the chain regression fields.
        string? note = notePositionless
            ? "pointer audit anchor: LEGACY-POSITIONLESS posture — the selected pointer carries a W30 v1 position-less signature and no position witness survives, so it is judged on its bytes alone under the named migration posture; the first W36 position-bound write ends this posture for good (W36/DS-round-8)"
            : null;
        try { PointerAnchorMarker.Write(updatesRoot, current, null, null); } catch { /* best-effort witness */ }
        if (markerDir is not null)
        {
            // W49: this refresh IS the launcher write path, and it
            // routes through the same guarded primitive as the
            // Core's advance — under the cross-process marker
            // lock, re-read and refused by name if it would
            // regress. The round-11 TOCTOU (FreshnessRefusal
            // passes, the Core advances past this snapshot, the
            // refresh lands stale) now ends in a named refusal at
            // the primitive, which here is BENIGN: a fresher
            // marker already stands, so freshness is armed at a
            // later position than this check vouched — subsumed,
            // not failed, and no note is owed.
            try { PointerAnchorMarker.Write(markerDir, current, entries.Count, log.HeadHash); }
            catch (PointerAnchorMarker.MarkerWriteRefusedException) { /* subsumed by a fresher marker (W49) */ }
            catch (Exception ex) { note = $"pointer audit anchor: pointer vouched, but the anchor marker could not be persisted in '{markerDir}' ({ex.GetType().Name}) — deletion/truncation protection is not armed from that location"; }
        }
        return (true, note);
    }

    /// <summary>W45: the marker freshness/prefix rule, shared by
    /// the launcher's pointer check and the Core's pack
    /// verification (ComplianceService): for every marker carrying
    /// a recorded count + head, a chain SHORTER than the count was
    /// truncated or rolled back, and a chain of ANY length >= the
    /// count must still hash-match the recorded head AT that
    /// count (the genuine prefix survives). Returns the refusal
    /// note, or null when every marker binds. This is the leg the
    /// round-9 staged rollback passed when the marker was only
    /// launcher-refreshed; with the Core advancing the marker on
    /// every anchored append (AdvanceInstallRootMarker), the same
    /// leg now refuses it.</summary>
    public static string? FreshnessRefusal(
        IReadOnlyList<PointerAnchorMarker.Marker> markers, IReadOnlyList<ChainedAuditEntry> entries)
    {
        foreach (var m in markers)
        {
            if (m.ChainEntries is not { } seenCount) continue;
            if (entries.Count < seenCount)
                return $"pointer audit anchor: the enterprise audit chain has {entries.Count} entries, FEWER than the {seenCount} vouched in the anchor marker at '{m.SourcePath}' — the chain was truncated or rolled back (W17/DS-B-16); slot refused";
            // W53 sibling audit: this comparison is ORDINAL too —
            // the marker is covered by no hash/signature of its
            // own, so a case-only tamper of its recorded head must
            // refuse here, not pass as the same digest. Chain entry
            // hashes are canonical lowercase hex (EntUtil.Sha256Hex
            // ToLowerInvariant), so no legitimate marker head needs
            // case-insensitivity.
            if (m.ChainHead is not null && seenCount >= 1 && seenCount <= entries.Count &&
                !string.Equals(entries[(int)seenCount - 1].Hash, m.ChainHead, StringComparison.Ordinal))
                return $"pointer audit anchor: the enterprise audit chain's entry at the anchor marker's recorded count ({seenCount}, marker at '{m.SourcePath}') hashes to {entries[(int)seenCount - 1].Hash}, NOT the marker's recorded head {m.ChainHead} — the genuine prefix was rewritten, whatever was appended after it (W19/DS-B-16 prefix binding); slot refused";
        }
        return null;
    }

    /// <summary>W45: the pointer hash a pointer record's detail
    /// carries ("pointer_sha256=…"), or null when it carries none.
    /// Public form of the anchor's own extraction, for the Core's
    /// marker advance (the marker's pointer-hash field names the
    /// last pointer record the chain vouches for).</summary>
    public static string? ExtractPointerHash(string detail) => ExtractHash(detail);

    /// <summary>W45 / DS round-9 Item 3: the CORE-side marker
    /// advance. Called by the Core AFTER an anchored append has
    /// landed durably (append → persist → advance, in that
    /// order), with the chain's entries as they now stand: the
    /// install-root marker is rewritten to (entries.Count, head)
    /// and the write's LANDING is checked by re-reading the
    /// marker (the W35/W43 durability discipline — a write that
    /// did not land is a named state, never a silent success).
    /// Never throws: the returned State is the named posture the
    /// caller surfaces (EnterpriseService.AnchorMarkerState /
    /// ComplianceService.AnchorMarkerState, riding the host-state
    /// surface). Ok=false means freshness is NOT armed from the
    /// Core for this append — the state says so, by name.</summary>
    public static (bool Ok, string State) AdvanceInstallRootMarker(
        string? markerDir, IReadOnlyList<ChainedAuditEntry> entries)
    {
        if (markerDir is null)
            return (false, "anchor marker advance NOT ARMED: no install root supplied to this composition — the install-root anchor marker cannot be advanced by the Core (W45)");
        if (entries.Count == 0)
            return (false, "anchor marker advance SKIPPED: the audit chain is empty — there is no position to vouch (W45)");
        var count = (long)entries.Count;
        var head = entries[^1].Hash;
        // The marker's pointer-hash field names the chain's last
        // pointer record; when the chain carries none yet (or the
        // advancing append is a pack record on a pointer-less
        // chain), the previous marker's hash is preserved, and a
        // first marker on such a chain simply omits the field —
        // presence + the chain regression fields are what bind.
        string? sha = null;
        for (var i = entries.Count - 1; i >= 0; i--)
            if (entries[i].Kind == RecordKind) { sha = ExtractHash(entries[i].Detail); break; }
        if (sha is null)
        {
            try { sha = PointerAnchorMarker.ReadAll(markerDir).FirstOrDefault()?.PointerSha256; }
            catch { /* no prior marker — the field is omitted */ }
        }
        // W47 (b) placed the MONOTONICITY GUARD here, in the
        // advance operation; W49 (round-11 Item 2) moves it one
        // level down, INTO PointerAnchorMarker.Write itself,
        // under the cross-process marker lock — the guard's
        // read-check-write here was not atomic against callers
        // outside the chain gate, and the launcher's refresh
        // never passed through this operation at all. This
        // advance now DELEGATES to the guarded write: a
        // regression attempt surfaces as the primitive's named
        // refusal, a lock that cannot be acquired in the bounded
        // wait as the named fail-closed timeout — both mapped to
        // this operation's named states, marker left unchanged.
        try
        {
            PointerAnchorMarker.Write(markerDir, sha, count, head);
        }
        catch (PointerAnchorMarker.MarkerWriteRefusedException ex)
        {
            return (false, $"anchor marker advance REFUSED (monotonicity guard, W49) — {ex.Message}");
        }
        catch (PointerAnchorMarker.MarkerLockTimeoutException ex)
        {
            return (false, $"anchor marker advance FAILED (marker lock timeout — fail closed, W49): {ex.Message} — the chain is durable at {count} entries but the marker was NOT advanced, so Core-armed freshness does not cover this append until a later advance or a vouched launcher check succeeds");
        }
        catch (Exception ex)
        {
            return (false, $"anchor marker advance FAILED: the install-root anchor marker in '{markerDir}' could not be written ({ex.GetType().Name}: {ex.Message}) — the chain is durable at {count} entries but the marker was NOT advanced, so Core-armed freshness does not cover this append until a later advance or a vouched launcher check succeeds (W45)");
        }
        // Landing check: re-read the marker and require it to name
        // exactly the position just written — or a LATER one: a
        // vouched launcher refresh landing between this write and
        // the re-read names a position at or beyond this advance
        // (it passed FreshnessRefusal against the marker first),
        // which subsumes this advance rather than falsifying it.
        try
        {
            var landed = PointerAnchorMarker.ReadAll(markerDir).FirstOrDefault();
            if (landed is not null && landed.ChainEntries is { } landedCount && landedCount > count)
                return (true, $"advanced:chain_entries={landedCount}");
            // W53 sibling audit: ORDINAL — this is the landing
            // proof for the head just written; a case-only
            // difference means the marker does NOT stand at the
            // exact position this advance wrote.
            if (landed is null || landed.ChainEntries != count ||
                !string.Equals(landed.ChainHead, head, StringComparison.Ordinal))
                return (false, $"anchor marker advance FAILED: the install-root anchor marker in '{markerDir}' was written but does NOT read back at the advanced position (count {count}, head {head}) — the write's landing could not be proven, so Core-armed freshness does not cover this append (W45)");
        }
        catch (Exception ex)
        {
            return (false, $"anchor marker advance FAILED: the install-root anchor marker in '{markerDir}' could not be re-read after writing ({ex.GetType().Name}: {ex.Message}) — the write's landing could not be proven, so Core-armed freshness does not cover this append (W45)");
        }
        return (true, $"advanced:chain_entries={count}");
    }

    /// <summary>W36: does a pointer record's detail carry the
    /// v2 scheme marker ("pointer_sig_scheme=v2")? The marker is
    /// known BEFORE the append, so it can live in the detail the
    /// record's own hash covers — unlike the record's index/hash
    /// themselves, which are the commitment the signature binds
    /// and are read from the verified chain, never stored. Its
    /// presence anywhere in the chain is a position-binding
    /// witness for the migration posture.</summary>
    private static bool HasPositionScheme(string detail) =>
        detail.Contains("pointer_sig_scheme=v2", StringComparison.Ordinal);

    /// <summary>W36 migration witness: true when the OTHER
    /// pointer file (main when the backup was selected, and vice
    /// versa) carries a v2 position-bound sidecar — position
    /// binding has begun on this install even if the selected
    /// file's own sidecar is a W30 v1.</summary>
    private static bool SiblingSidecarIsPositionBound(string updatesRoot, string selectedPath)
    {
        var main = SlotPointer.PointerPath(updatesRoot);
        var bak = SlotPointer.PointerBackupPath(updatesRoot);
        var other = string.Equals(selectedPath, main, StringComparison.OrdinalIgnoreCase) ? bak : main;
        try
        {
            var sig = PointerSigningCustody.SignaturePathFor(other);
            if (!File.Exists(sig)) return false;
            return PointerSigningCustody.TryParseSidecar(File.ReadAllText(sig), out _, out var bound) && bound;
        }
        catch { return false; }
    }

    private static string? ExtractHash(string detail)
    {
        const string marker = "pointer_sha256=";
        var i = detail.IndexOf(marker, StringComparison.Ordinal);
        if (i < 0) return null;
        var rest = detail.AsSpan(i + marker.Length);
        var end = rest.IndexOf(' ');
        var token = (end < 0 ? rest : rest[..end]).ToString();
        return token.Length == 64 ? token : null;
    }
}

/// <summary>W17 / DS-B-16: the anchor-presence witness. A small
/// line-based file (pointer-anchor.marker) whose EXISTENCE is the
/// signal: once any pointer has been audit-anchored, a marker
/// exists, and PointerAuditAnchor refuses to fall back to the
/// legacy posture while one survives. The launcher-side copy also
/// carries the vouched chain length + head for the rollback rule.
/// A marker's recorded pointer hash is NOT a refusal authority
/// (a crash between the Core's audit append and its marker write
/// can leave it one write stale while chain and pointer agree) —
/// presence and the chain regression fields are what bind.
/// Parse failures still count as presence: a garbled marker is
/// evidence of anchoring (or of tampering), never of a fresh
/// install.
///
/// W49 / DS round-11 Item 2: Write is the GUARDED write — the
/// monotonicity guard lives in this primitive, executed under
/// an OS-level exclusive lock on the lock file beside the
/// marker (FileShare.None, bounded wait, fail closed by name),
/// with the current marker re-read under the lock. See the
/// PointerAuditAnchor W49 block for the full construction and
/// the custody terms of the lock file.</summary>
public static class PointerAnchorMarker
{
    public const string MarkerFileName = "pointer-anchor.marker";

    /// <summary>W49: the cross-process lock file, living beside
    /// the marker it guards (see LockPath / AcquireMarkerLock).</summary>
    public const string LockFileName = MarkerFileName + ".lock";

    /// <summary>W49: the bounded wait for the marker lock. A
    /// writer that cannot acquire within this wait fails closed
    /// (MarkerLockTimeoutException) — never writes unlocked,
    /// never waits forever.</summary>
    public static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(5);

    public sealed record Marker(string SourcePath, string? PointerSha256, long? ChainEntries, string? ChainHead);

    /// <summary>W49: the named refusal of a marker write that
    /// would regress vouched freshness (count below the current
    /// marker's, or same count with a different head). The
    /// marker is left byte-unchanged. Thrown by Write — the
    /// guard lives in the primitive, under the cross-process
    /// lock, so it binds every caller in every process.</summary>
    public sealed class MarkerWriteRefusedException(string message) : InvalidOperationException(message);

    /// <summary>W49: the named fail-closed outcome when the
    /// cross-process marker lock cannot be acquired within the
    /// bounded wait. The write was NOT attempted unlocked; the
    /// marker is left byte-unchanged.</summary>
    public sealed class MarkerLockTimeoutException(string message) : IOException(message);

    public static string MarkerPath(string dir) => Path.Combine(dir, MarkerFileName);

    public static string LockPath(string dir) => Path.Combine(dir, LockFileName);

    /// <summary>Every marker present in the given directories
    /// (deduplicated, missing files skipped).</summary>
    public static IReadOnlyList<Marker> ReadAll(params string?[] dirs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var found = new List<Marker>();
        foreach (var dir in dirs)
        {
            if (dir is null) continue;
            if (!seen.Add(Path.GetFullPath(MarkerPath(dir)))) continue;
            if (ReadOne(dir) is { } marker) found.Add(marker);
        }
        return found;
    }

    /// <summary>The marker in ONE directory, or null when no
    /// marker file exists there. Parse failures still count as
    /// presence with null fields (see the class summary).</summary>
    private static Marker? ReadOne(string dir)
    {
        var path = MarkerPath(dir);
        if (!File.Exists(path)) return null;
        string? sha = null; long? count = null; string? head = null;
        try
        {
            foreach (var line in File.ReadAllLines(path))
            {
                var eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var key = line[..eq].Trim(); var value = line[(eq + 1)..].Trim();
                if (key == "pointer_sha256" && value.Length == 64) sha = value;
                else if (key == "chain_entries" && long.TryParse(value, out var n)) count = n;
                else if (key == "chain_head" && value.Length > 0) head = value;
            }
        }
        catch { /* presence is the signal; fields stay null */ }
        return new Marker(path, sha, count, head);
    }

    /// <summary>W49: acquire the OS-level exclusive lock for the
    /// marker in <paramref name="dir"/> — the lock file beside
    /// the marker, opened with FileShare.None. The kernel
    /// enforces the exclusion per open file description, so it
    /// binds other PROCESSES (Core vs launcher) exactly as it
    /// binds other threads; no in-process state is involved.
    /// The lock file is created with default permissions — it
    /// inherits the directory's ACL posture exactly as the
    /// marker file itself does, and no ACL is set or widened —
    /// and it is NEVER deleted: unlinking a lock file another
    /// process holds would let a third process lock a fresh
    /// inode and split the exclusion. Retries on sharing
    /// violations until <paramref name="timeout"/> elapses,
    /// then throws MarkerLockTimeoutException (fail closed).</summary>
    private static FileStream AcquireMarkerLock(string dir, TimeSpan timeout)
    {
        Directory.CreateDirectory(dir);
        var lockPath = LockPath(dir);
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(25);
            }
            catch (IOException)
            {
                throw new MarkerLockTimeoutException(
                    $"pointer anchor marker LOCK TIMEOUT (W49): the cross-process marker lock at '{lockPath}' could not be acquired within {timeout.TotalSeconds:0.###}s — the write FAILED CLOSED: the marker was NOT written, no unlocked write was attempted, and the wait was bounded rather than forever");
            }
        }
    }

    /// <summary>Write (or refresh) the marker in
    /// <paramref name="dir"/> — W49: THE GUARDED WRITE. Every
    /// marker write in the product (the Core's advance via
    /// AdvanceInstallRootMarker, the launcher's vouched refresh
    /// in Check, the updates-root witness writes) goes through
    /// this primitive, which: (1) acquires the cross-process
    /// marker lock (bounded wait, fail closed by name); (2)
    /// re-reads the CURRENT marker under the lock; (3) refuses
    /// by name (MarkerWriteRefusedException, marker left
    /// byte-unchanged) a write that would regress — a proposed
    /// count below the current count, or the same count with a
    /// different head, where W51 makes "different" include a
    /// null head on either side (value→null erasure and
    /// null→value un-vouching both refuse; only a byte-identical
    /// (count, head) rewrite proceeds at the same count); a
    /// witness-only write (no count proposed) preserves the
    /// recorded count/head rather than dropping the regression
    /// fields the freshness leg binds on, so it is not a
    /// same-count head change; at a GREATER count a write
    /// proceeds as a new position exactly as before (W51 does
    /// not widen the rule: a greater-count write with a null
    /// head still lands, creating a headless position at the
    /// new count — no vouched head exists at that count yet to
    /// be rewritten, and production writers always supply the
    /// head; that headless position is then itself immutable
    /// at its count under the same-count rule); W53 / DS
    /// round-13 Item 2: "different" at the same count is judged
    /// ORDINALLY (case-only head changes refuse), and a
    /// witness-only write preserves count AND head independently
    /// from the standing marker, whatever combination it carries
    /// (including head-only); (4)
    /// writes atomically (per-write GUID tmp + move) and
    /// releases the lock. Throws on IO failure — callers decide
    /// whether that is fatal (the Core maps it to a named
    /// state; the launcher surfaces a failed arm as a note on
    /// an otherwise vouched check).</summary>
    public static void Write(string dir, string? pointerSha256, long? chainEntries, string? chainHead,
        TimeSpan? lockTimeout = null)
    {
        using var held = AcquireMarkerLock(dir, lockTimeout ?? DefaultLockTimeout);
        var existing = ReadOne(dir);
        long? effectiveEntries = chainEntries;
        string? effectiveHead = chainHead;
        if (existing is not null)
        {
            if (chainEntries is { } proposed && existing.ChainEntries is { } current)
            {
                if (proposed < current)
                    throw new MarkerWriteRefusedException(
                        $"pointer anchor marker write REFUSED (monotonicity guard, W49): the marker in '{dir}' already stands at chain_entries={current} (head {existing.ChainHead ?? "(none recorded)"}) and the attempted write to chain_entries={proposed} (head {chainHead ?? "(none)"}) would move freshness BACKWARD — the marker is left byte-unchanged; the guard is in the write primitive under the cross-process marker lock, so no caller — Core advance, launcher refresh, inside or outside any in-process gate, in this process or another — can regress the marker");
                // W51 / DS round-12 Item 2: at the SAME count the
                // head is immutable in EVERY direction. The W49
                // form of this check required both heads non-null,
                // so Write(dir, null, 5, null) after (5, Head(5))
                // ERASED chain_head, and the erasure then disarmed
                // this refusal for a later (5, Head(9)). "Differs"
                // now includes value→null (erasure), null→value
                // (un-vouching a headless position into a headed
                // one) and value→different-value: string.Equals
                // treats null vs a value as unequal and null vs
                // null as equal, so the only same-count counted
                // writes that proceed are byte-identical (count,
                // head) rewrites. W53 / DS round-13 Item 2: the
                // comparison is ORDINAL (case-sensitive) — the
                // W51 form used OrdinalIgnoreCase, so a case-only
                // head change ('f'x64 -> 'F'x64 at the same count)
                // was judged "same" and LANDS, rewriting the marker
                // bytes under a byte-identical-only claim. The
                // marker head is not constrained to lowercase hex
                // (ReadOne accepts any non-empty value), and the
                // marker is covered by no hash/signature of its
                // own, so case is content here, not encoding.
                // A witness-only write proposes no
                // count at all (chainEntries is null) and never
                // reaches this check — it preserves the standing
                // count/head below, so it is not a same-count head
                // change and stays allowed.
                if (proposed == current &&
                    !string.Equals(existing.ChainHead, chainHead, StringComparison.Ordinal))
                    throw new MarkerWriteRefusedException(
                        $"pointer anchor marker write REFUSED (monotonicity guard, W49; same-count head immutability, W51): the marker in '{dir}' already stands at chain_entries={current} with head {existing.ChainHead ?? "(none recorded)"} and the attempted write names a DIFFERENT head {chainHead ?? "(none)"} at the same count — a same-count rewrite of vouched freshness; the marker is left byte-unchanged");
            }
            if (chainEntries is null)
            {
                // A witness-only refresh updates the pointer hash
                // but must not DROP the chain regression fields:
                // losing them would disarm FreshnessRefusal for
                // this marker — a regression by erasure.
                // W53 / DS round-13 Item 2 (additional gap): each
                // field is preserved INDEPENDENTLY from the
                // standing marker. The W49/W51 form gated this
                // branch on a non-null standing count, so a
                // HEAD-ONLY marker (head, no count) lost its head
                // to a witness write. A witness write proposes no
                // position, so count AND head stay exactly as they
                // stand, whatever combination the standing marker
                // carries (count-only, head-only, both, neither).
                effectiveEntries = existing.ChainEntries;
                effectiveHead = existing.ChainHead;
            }
        }
        var lines = new List<string>();
        if (pointerSha256 is not null) lines.Add($"pointer_sha256={pointerSha256}");
        if (effectiveEntries is { } n) lines.Add($"chain_entries={n}");
        if (effectiveHead is not null) lines.Add($"chain_head={effectiveHead}");
        // W45: a per-write tmp name — the Core (advancing on every
        // anchored append) and the launcher (refreshing on a
        // vouched check) can write concurrently; a shared tmp path
        // let one writer's move consume the other's file.
        var tmp = MarkerPath(dir) + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllLines(tmp, lines);
            File.Move(tmp, MarkerPath(dir), overwrite: true);
        }
        catch { try { File.Delete(tmp); } catch { } throw; }
    }
}

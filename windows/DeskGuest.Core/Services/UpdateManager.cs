using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Core.Services;

/// <summary>Verifies update package signatures. Production pins the
/// product key (D-DEC-1: Ed25519, via PinnedUpdateKey; the legacy
/// RSA PEM pin remains loadable); the dev/test implementation
/// generates a keypair so the whole A/B flow is provable on the
/// build VM.</summary>
public interface IUpdateSignatureVerifier
{
    bool Verify(byte[] packageBytes, byte[] signature);
    string KeyId { get; }
}

/// <summary>W15 / DS-P9-F6: the production no-key verifier. When the
/// installer ships NO pinned product key (update-key.pub absent) and
/// no explicit dev opt-in is in force, production composition binds
/// THIS verifier — never the ephemeral dev keypair. It verifies
/// nothing, its KeyId names the posture, and UpdateManager's
/// fail-closed reason (wired alongside it) refuses stage/apply by
/// name before signature work. The dev-ephemeral keypair remains
/// available ONLY behind the update posture's own explicit dev
/// opt-in (CoreOptions.AllowDevEphemeralUpdateKey or
/// DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1, decided by
/// DevEphemeralUpdateKeyOptIn — W19/DS-B-17: DESKGUEST_DEV_ALLOW_NO_TOKEN
/// is the IPC opt-in and no longer enables this posture), labelled
/// "dev-ephemeral" in every status surface.</summary>
public sealed class AbsentKeyUpdateVerifier : IUpdateSignatureVerifier
{
    public string KeyId => "no-pinned-product-key";
    public bool Verify(byte[] packageBytes, byte[] signature) => false;
}

public sealed class RsaUpdateSignatureVerifier : IUpdateSignatureVerifier, IDisposable
{
    private readonly RSA _rsa;
    private readonly bool _ownsKey;
    public string KeyId { get; }

    /// <summary>Dev/test: ephemeral keypair. Sign with <see cref="Sign"/>.</summary>
    public RsaUpdateSignatureVerifier()
    {
        _rsa = RSA.Create(3072);
        _ownsKey = true;
        KeyId = "dev-ephemeral";
    }

    public RsaUpdateSignatureVerifier(string publicKeyPem, string keyId)
    {
        _rsa = RSA.Create();
        _rsa.ImportFromPem(publicKeyPem);
        _ownsKey = true; // W12 / DS-P9-F25: the PEM ctor owns its RSA too — Dispose must dispose it
        KeyId = keyId;
    }

    public byte[] Sign(byte[] packageBytes) =>
        _rsa.SignData(packageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public bool Verify(byte[] packageBytes, byte[] signature)
    {
        try { return _rsa.VerifyData(packageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
        catch (CryptographicException) { return false; }
    }

    public string ExportPublicKeyPem() => _rsa.ExportSubjectPublicKeyInfoPem();
    public void Dispose() { if (_ownsKey) _rsa.Dispose(); }
}

/// <summary>W24 / R-05 / D-DEC-1: the production update verifier
/// over the product's Ed25519 discipline (DeskGuest.Shared.Security.
/// Ed25519 — the same primitive and fail-closed shape as feed
/// signing, W11 / R-22). The pinned public key is the raw 32-byte
/// Ed25519 public key, carried in update-key.pub as base64 (the
/// feed-key file format). Signing is the release act: it happens
/// OFF the endpoint with the custody-held 32-byte seed
/// (Ed25519.Sign); this class verifies only, and its static Sign
/// exists for the release tooling / round-trip proofs that run
/// against the custody seed outside the shipped composition.</summary>
public sealed class Ed25519UpdateSignatureVerifier : IUpdateSignatureVerifier
{
    private readonly byte[] _publicKey;
    public string KeyId { get; }

    public Ed25519UpdateSignatureVerifier(byte[] publicKey, string keyId)
    {
        if (publicKey is null || publicKey.Length != 32)
            throw new ArgumentException("an Ed25519 update public key is exactly 32 bytes", nameof(publicKey));
        if (Shared.Security.Ed25519.IsSmallOrderPublicKey(publicKey))
            throw new ArgumentException("small-order Ed25519 public keys are forgeable and never pin", nameof(publicKey));
        _publicKey = publicKey.ToArray();
        KeyId = keyId;
    }

    /// <summary>Release-side signing with the custody seed
    /// (32 bytes). Never called by the endpoint composition.</summary>
    public static byte[] Sign(byte[] seed, byte[] packageBytes) =>
        Shared.Security.Ed25519.Sign(seed, packageBytes);

    public bool Verify(byte[] packageBytes, byte[] signature) =>
        Shared.Security.Ed25519.Verify(_publicKey, packageBytes, signature);

    public byte[] ExportPublicKey() => _publicKey.ToArray();
}

/// <summary>W24 / R-05: the ONE loader for the pinned update key
/// file (update-key.pub). Two pinned formats, discriminated by
/// content, never by filename trust:
///   * PEM ("-----BEGIN") — the legacy RSA product key
///     (RsaUpdateSignatureVerifier, SHA-256 / PKCS#1);
///   * base64 of exactly 32 bytes — the D-DEC-1 Ed25519 product
///     key (Ed25519UpdateSignatureVerifier).
/// Anything else throws FormatException; production composition
/// catches it and fails CLOSED by name (never guesses a format,
/// never falls back to an ephemeral key).</summary>
public static class PinnedUpdateKey
{
    public const string ProductPinnedKeyId = "product-pinned";

    public static IUpdateSignatureVerifier Create(string fileText)
    {
        var text = (fileText ?? "").Trim();
        if (text.StartsWith("-----BEGIN", StringComparison.Ordinal))
            return new RsaUpdateSignatureVerifier(text, ProductPinnedKeyId);
        byte[] raw;
        try { raw = Convert.FromBase64String(text); }
        catch (FormatException ex)
        {
            throw new FormatException(
                "pinned update key is neither a PEM (RSA) key nor base64 (Ed25519) — refused", ex);
        }
        if (raw.Length != 32)
            throw new FormatException(
                $"pinned update key decodes to {raw.Length} bytes — an Ed25519 public key is exactly 32 (a non-PEM RSA key is not a pinned format) — refused");
        return new Ed25519UpdateSignatureVerifier(raw, ProductPinnedKeyId);
    }
}

public enum UpdateSlot { A, B }
public sealed record UpdateStatusReport(UpdateSlot ActiveSlot, string ActiveVersion, string? StagedVersion, string? LastOutcome, string SignatureKeyId = "unknown",
    // W13 / DS-P9-F2 (closure): the status report NAMES the probe
    // posture — a reader can tell whether apply will prove the
    // staged slot's version by probe or rest on hash+health only.
    bool StagedSlotProbeWired = false);

/// <summary>
/// Self-update that cannot brick the endpoint (DESIGN §4.6): two
/// versioned slots + a pointer. A package stages into the IDLE slot,
/// signature-verified against the pinned key; the pointer flips only
/// after the health gate passes; failure rolls the pointer back and
/// quarantines the bad slot. Policy default is notify-only until the owner
/// picks D-UPDATE; this machinery implements either policy — the
/// manager stages and reports, the policy decides who may flip.
/// </summary>
public sealed class UpdateManager
{
    private readonly string _root;
    private readonly IUpdateSignatureVerifier _verifier;
    private readonly Func<CancellationToken, Task<bool>> _healthGate;
    private readonly Func<string, (bool Allowed, string Reason)>? _policyGate;
    private readonly IReadOnlySet<string>? _pinnedKeyIds;
    private readonly Func<string, string, bool>? _stagedSlotProbe;
    private readonly string? _failClosedReason;
    private readonly Action<string>? _pointerAudit;
    private readonly Func<string, (long Seq, string Hash)>? _pointerAuditPositioned;
    private readonly Shared.Update.PointerSigningCustody? _pointerSigning;
    private readonly Action<string>? _keyingAudit;
    private readonly SemaphoreSlim _applyLock = new(1, 1);

    /// <param name="pinnedKeyIds">W12 / DS-P9-F6: the pinned signer
    /// set. When supplied, staging refuses any verifier whose KeyId
    /// is not a member — a composition-root mistake can no longer
    /// silently widen trust to an arbitrary (or dev-ephemeral) key.</param>
    /// <param name="stagedSlotProbe">W12 / DS-P9-F2: the
    /// installed-version probe (slotDir, stagedVersion) → true only
    /// when the STAGED slot itself proves it carries the staged
    /// version. When supplied, apply requires it in addition to the
    /// health gate; when null, apply's success wording stays limited
    /// to the pointer flip taking effect at the next restart.</param>
    /// <param name="failClosedReason">W15 / DS-P9-F6: when non-null,
    /// stage and apply BOTH refuse with exactly this named reason —
    /// the production no-pinned-key posture. Production composition
    /// sets it whenever the verifier is not the pinned product key
    /// and no explicit dev opt-in is in force.</param>
    /// <param name="pointerAudit">W15 / DS-P9-F18 limb (b): invoked
    /// with a detail string carrying the SHA-256 of every pointer
    /// state this manager writes, so the host can record it in the
    /// enterprise audit chain (a different file than the pointer).
    /// The launcher cross-checks the on-disk pointer against that
    /// record and refuses a rewritten pointer by name.</param>
    /// <param name="pointerSigning">W30 / D-DEC-7: the runtime
    /// pointer-signing custody (private half in the install root,
    /// outside the data dir — see PointerSigningCustody). When
    /// supplied, every pointer state this manager commits is
    /// signed over its exact bytes (signature in the sidecar), the
    /// first signed write begins keying (keying marker + the
    /// keyingAudit record), and a successful apply ROTATES the
    /// runtime key — the apply is the production-signed update
    /// event that authorises the repin. When null, pointers are
    /// written unsigned and the launcher judges them under the
    /// named LEGACY-UNKEYED posture (pre-keying installs and
    /// embedders that compose no custody).</param>
    /// <param name="keyingAudit">W30 / D-DEC-7: invoked ONCE, at
    /// the first signed pointer write, with a detail string
    /// carrying the runtime public key's fingerprint, so the host
    /// can record the keying transition in the audit chain under
    /// kind "update_pointer_keying_begun" (W29 §4: the migration
    /// moment is itself chain evidence).</param>
    /// <param name="pointerAuditPositioned">W36 / DS round-8:
    /// the POSITIONED pointer-audit seam. Invoked with a detail
    /// PROTOTYPE (the pointer hash + state, without the position
    /// commitment); the host appends the record to the audit
    /// chain and RETURNS the appended entry's chain index (Seq)
    /// and own hash, so WritePointer can (a) record the final
    /// detail's commitment as an in-memory fact and (b) sign over
    /// (pointer bytes + that exact position). REQUIRED whenever
    /// pointerSigning is composed: a keyed write without a
    /// positioned seam refuses by name rather than emit a W30
    /// position-less signature (which the launcher, once position
    /// binding has begun, refuses anyway). The seam receives the
    /// prototype because the record's own hash cannot be known
    /// before the append that creates it — append-then-sign is
    /// the ordering that makes the commitment true.</param>
    public UpdateManager(string installRoot, IUpdateSignatureVerifier verifier, Func<CancellationToken, Task<bool>> healthGate,
        Func<string, (bool Allowed, string Reason)>? policyGate = null,
        IReadOnlySet<string>? pinnedKeyIds = null,
        Func<string, string, bool>? stagedSlotProbe = null,
        string? failClosedReason = null,
        Action<string>? pointerAudit = null,
        Shared.Update.PointerSigningCustody? pointerSigning = null,
        Action<string>? keyingAudit = null,
        Func<string, (long Seq, string Hash)>? pointerAuditPositioned = null)
    {
        _root = installRoot;
        _verifier = verifier;
        _healthGate = healthGate;
        _policyGate = policyGate;
        _pinnedKeyIds = pinnedKeyIds;
        _stagedSlotProbe = stagedSlotProbe;
        _failClosedReason = failClosedReason;
        _pointerAudit = pointerAudit;
        _pointerSigning = pointerSigning;
        _keyingAudit = keyingAudit;
        _pointerAuditPositioned = pointerAuditPositioned;
        Directory.CreateDirectory(SlotDir(UpdateSlot.A));
        Directory.CreateDirectory(SlotDir(UpdateSlot.B));
        if (!File.Exists(PointerPath))
            WritePointer(new Pointer(UpdateSlot.A, "0.1.0", null, "initial install"));
    }

    private sealed record Pointer(UpdateSlot Active, string Version, string? StagedVersion, string? LastOutcome,
        // BD-WIN-CORE-4/F10: hash of the staged slot's extracted
        // contents, recorded at stage time and re-verified at
        // apply time — a slot tampered with between stage and
        // apply is never flipped to.
        string? StagedSlotHash = null,
        // BD-WIN-AGENT F6: hash of the ACTIVE slot's contents,
        // carried across the flip from the staged hash, so the
        // launcher can re-verify the slot it is about to exec
        // against the signature-verified package's contents.
        string? ActiveSlotHash = null);
    private string PointerPath => Path.Combine(_root, "active-slot.json");
    private string SlotDir(UpdateSlot slot) => Path.Combine(_root, "slots", slot.ToString());
    private readonly object _pointerLock = new();

    public string SignatureKeyId => _verifier.KeyId;

    /// <summary>W30 / D-DEC-7: the runtime pointer-signing key's
    /// fingerprint when a custody is composed; null in the
    /// LEGACY-UNKEYED composition (no custody).</summary>
    public string? PointerSigningFingerprint => _pointerSigning?.Fingerprint;

    private string PointerBackupPath => PointerPath + ".bak";
    private bool _pointerUnrecoverable;

    // BD-WIN-CORE-4/F10: a corrupt pointer must NOT silently
    // default to slot A "0.1.0" — if B was active, the launcher
    // would next run whatever sits in A. Every successful write
    // also refreshes a last-known-good backup; a corrupt main
    // pointer falls back to that backup. Only when BOTH are
    // unreadable does the surface default — and then it is marked
    // unrecoverable, and stage/apply REFUSE rather than flip.
    private Pointer ReadPointer()
    {
        lock (_pointerLock)
        {
            foreach (var path in new[] { PointerPath, PointerBackupPath })
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    var p = JsonSerializer.Deserialize<Pointer>(File.ReadAllText(path));
                    // W12 / DS-P9-F8: "{}" deserializes to a non-null
                    // Pointer with Version null — that is corruption,
                    // not slot A. Missing required fields fall through
                    // to the backup, then to the named default.
                    if (p is not null && p.Version is not null) { _pointerUnrecoverable = false; return p; }
                }
                catch { /* try the backup next */ }
            }
            _pointerUnrecoverable = true;
            return new Pointer(UpdateSlot.A, "0.1.0", null, "pointer file AND its last-known-good backup are unreadable; defaulted to slot A for REPORTING ONLY — stage/apply refuse until the pointer is repaired");
        }
    }

    // Atomic-enough pointer writes (M3): temp file + replace, so a crash
    // mid-write leaves the OLD pointer, never a torn one.
    private void WritePointer(Pointer p)
    {
        lock (_pointerLock)
        {
            var json = JsonSerializer.Serialize(p);
            var pointerBytes = Encoding.UTF8.GetBytes(json);
            var hash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(pointerBytes)).ToLowerInvariant();
            // W30 / D-DEC-7 + W36 / DS round-8: sign BEFORE any
            // pointer file moves — a custody refusal (seed inside
            // the data dir, malformed seed, pin mismatch) throws
            // by name here and no unsigned pointer is committed
            // under a keyed composition. W36 ordering is
            // APPEND-THEN-SIGN: the pointer record is appended to
            // the host's audit chain FIRST (via the positioned
            // seam, which returns the appended entry's Seq + own
            // hash), and the signature commits to (pointer bytes +
            // that exact chain position) — the position a
            // data-dir-only attacker cannot re-target, because
            // any record THEY append lands at a different index
            // with a different hash. A keyed composition WITHOUT
            // the positioned seam refuses by name: emitting a W30
            // position-less signature after position binding has
            // begun would be refused by the launcher anyway.
            // The first signed write begins keying: keying marker
            // in the updates root + the keyingAudit record.
            string? signatureB64 = null;
            var auditAppendedHere = false;
            var keyingBeginsHere = false;
            if (_pointerSigning is not null)
            {
                keyingBeginsHere = !_pointerSigning.KeyingBegun
                    && !Shared.Update.PointerSigningCustody.KeyingMarkerExists(_root);
                // Custody first: a refused custody (seed inside
                // the data dir, malformed seed, pin mismatch)
                // names itself before any other refusal.
                _pointerSigning.EnsureKeyForInstall();
                if (_pointerAuditPositioned is null)
                    throw new InvalidOperationException(
                        "pointer signing REFUSED: this composition supplies a pointer-signing custody but no POSITIONED pointer-audit seam — a position-bound (W36) signature cannot be made, and a position-less (W30) signature is not emitted once position binding exists; wire pointerAuditPositioned (CoreRuntime does) or compose no custody");
                var detail = $"pointer_sha256={hash} active={p.Active} version={p.Version} staged={p.StagedVersion ?? "-"} activeSlotHash={p.ActiveSlotHash ?? "-"} pointer_sig_scheme=v2";
                var (seq, recordHash) = _pointerAuditPositioned(detail);
                auditAppendedHere = true;
                signatureB64 = Shared.Update.PointerSigningCustody.FormatSidecar(
                    _pointerSigning.SignPositioned(pointerBytes, seq, recordHash), positionBound: true);
                try { Shared.Update.PointerAnchorMarker.Write(_root, hash, null, null); } catch { }
            }
            // W12 / DS-P9-F23: write BOTH temp files first, then move
            // main, then backup. A backup-write failure after the main
            // move is non-fatal (the main pointer is the committed
            // state; the stale .bak is refreshed on the next write)
            // instead of an exception that makes a committed flip
            // look uncommitted to the caller.
            var tmp = PointerPath + ".tmp";
            var bakTmp = PointerBackupPath + ".tmp";
            File.WriteAllText(tmp, json);
            try { File.WriteAllText(bakTmp, json); } catch { /* backup refresh is best-effort */ }
            File.Move(tmp, PointerPath, overwrite: true);
            try { File.Move(bakTmp, PointerBackupPath, overwrite: true); } catch { /* as above */ }
            // W30 / D-DEC-7: the signature sidecars ride with the
            // pointer files they sign (main + .bak carry the same
            // bytes at write time, hence the same signature). A
            // sidecar write failure after the main move is treated
            // like the backup's: the next write refreshes it, and
            // until then the launcher refuses the keyed pointer by
            // name rather than accept it unsigned — fail-closed,
            // never a silent unsigned commit.
            if (signatureB64 is not null)
            {
                try
                {
                    var sigTmp = Shared.Update.PointerSigningCustody.SignaturePathFor(PointerPath) + ".tmp";
                    File.WriteAllText(sigTmp, signatureB64);
                    File.Move(sigTmp, Shared.Update.PointerSigningCustody.SignaturePathFor(PointerPath), overwrite: true);
                    try
                    {
                        var bakSigTmp = Shared.Update.PointerSigningCustody.SignaturePathFor(PointerBackupPath) + ".tmp";
                        File.WriteAllText(bakSigTmp, signatureB64);
                        File.Move(bakSigTmp, Shared.Update.PointerSigningCustody.SignaturePathFor(PointerBackupPath), overwrite: true);
                    }
                    catch { /* as above: a stale .bak sidecar refuses by name at the signature leg, never vouches */ }
                }
                catch { /* as above */ }
                if (keyingBeginsHere)
                {
                    // The migration moment is chain evidence (W29
                    // §4): witness in the updates root + the named
                    // audit record carrying the fingerprint.
                    try
                    {
                        Shared.Update.PointerSigningCustody.WriteKeyingMarker(_root, _pointerSigning!.Fingerprint ?? "unknown");
                        _keyingAudit?.Invoke($"pointer_key_fingerprint={_pointerSigning.Fingerprint} custody=install-root-outside-data-dir pin=install-root rotation=at-production-signed-apply");
                    }
                    catch { /* the pin's existence is itself a keying witness; the marker/record are the second witness, best-effort like the anchor marker */ }
                }
            }
            _pointerUnrecoverable = false;
            // W15 / DS-P9-F18 limb (b): record the written pointer's
            // hash in the host's audit chain. Best-effort by design:
            // the pointer is already committed; a failed audit write
            // must not make a committed flip look uncommitted (the
            // W12-F23 rule). The launcher treats a MISSING record as
            // the named legacy posture, never as a match.
            // W36: under a keyed composition the record was ALREADY
            // appended above (append-then-sign, via the positioned
            // seam) — appending again here would make a DIFFERENT
            // record the chain's last pointer record and break the
            // very position commitment just signed.
            if (!auditAppendedHere && _pointerAudit is not null)
            {
                try
                {
                    _pointerAudit($"pointer_sha256={hash} active={p.Active} version={p.Version} staged={p.StagedVersion ?? "-"} activeSlotHash={p.ActiveSlotHash ?? "-"}");
                    // W17 / DS-B-16: witness the anchoring OUTSIDE
                    // the audit chain itself — a marker in the
                    // updates root recording that this pointer was
                    // audit-anchored. Deleting or truncating
                    // enterprise-audit.json afterwards no longer
                    // downgrades the launcher to the legacy
                    // posture while this marker survives
                    // (PointerAuditAnchor). Best-effort, as above:
                    // the pointer is already committed.
                    try { Shared.Update.PointerAnchorMarker.Write(_root, hash, null, null); } catch { }
                }
                catch { /* as above */ }
            }
        }
    }

    /// <summary>Deterministic hash over a slot's extracted contents.
    /// BD-WIN-AGENT F6: delegates to the ONE shared implementation
    /// (DeskGuest.Shared.Update.SlotIntegrity) so the hash recorded here
    /// and the hash the launcher re-verifies at exec time are the
    /// same algorithm by construction, not by copy.</summary>
    private static string SlotContentHash(string dir) => Shared.Update.SlotIntegrity.ContentHash(dir);

    public UpdateStatusReport Status()
    {
        var p = ReadPointer();
        return new UpdateStatusReport(p.Active, p.Version, p.StagedVersion, p.LastOutcome, _verifier.KeyId,
            StagedSlotProbeWired: _stagedSlotProbe is not null);
    }

    public string ActiveSlotDir => SlotDir(ReadPointer().Active);

    /// <summary>Stage a signed package (zip) into the idle slot.
    /// Unsigned or bad-signature packages are refused and logged by the
    /// caller; nothing is extracted from an unverified package.</summary>
    public (bool Ok, string Message) StagePackage(byte[] packageZip, byte[] signature, string version)
    {
        // Enterprise policy gate (Block F wiring of DIR-22): a
        // loaded policy bundle's pin/defer REFUSES the update here,
        // in the update surface itself — before signature work and
        // before anything is extracted.
        if (_policyGate is not null)
        {
            var (allowed, reason) = _policyGate(version);
            if (!allowed) return (false, reason);
        }
        // W15 / DS-P9-F6: the production no-key posture refuses by
        // name before any signature work — an ephemeral or absent
        // key never stages anything in production composition.
        if (_failClosedReason is not null) return (false, _failClosedReason);
        // W12 / DS-P9-F6: pinned signer set — the verifier's KeyId
        // must be a member when a set is configured.
        if (_pinnedKeyIds is not null && !_pinnedKeyIds.Contains(_verifier.KeyId))
            return (false, $"signature key '{_verifier.KeyId}' is not in the pinned signer set — package refused, nothing extracted");
        if (!_verifier.Verify(packageZip, signature))
            return (false, $"signature verification FAILED against key '{_verifier.KeyId}'; package refused, nothing extracted");
        lock (_pointerLock)
        {
            var pointer = ReadPointer();
            if (_pointerUnrecoverable)
                return (false, "pointer file and its last-known-good backup are unreadable — staging refuses rather than guess the active slot (BD-WIN-CORE-4/F10)");
            var idle = pointer.Active == UpdateSlot.A ? UpdateSlot.B : UpdateSlot.A;
            var dir = SlotDir(idle);
            // W12 / DS-P9-F15: validate the package FULLY before the
            // existing staged slot is touched — a refused package
            // must not destroy a previously valid staging.
            using (var ms = new MemoryStream(packageZip))
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                // Explicit guards, not framework faith (M3): entry paths
                // must stay inside the slot (zip-slip), and the package
                // is capped in entries and total uncompressed size.
                if (zip.Entries.Count > 10_000)
                    return (false, "package refused: more than 10,000 entries");
                long total = 0;
                var dirFull = Path.GetFullPath(dir) + Path.DirectorySeparatorChar;
                foreach (var entry in zip.Entries)
                {
                    total += entry.Length;
                    if (total > 2L * 1024 * 1024 * 1024)
                        return (false, "package refused: uncompressed size over the 2 GiB cap");
                    var dest = Path.GetFullPath(Path.Combine(dir, entry.FullName));
                    if (!dest.StartsWith(dirFull, StringComparison.Ordinal) && entry.FullName.Length > 0)
                        return (false, $"package refused: entry '{entry.FullName}' escapes the slot directory");
                }
            }
            Directory.Delete(dir, recursive: true);
            Directory.CreateDirectory(dir);
            try
            {
                using var ms2 = new MemoryStream(packageZip);
                using var zip2 = new ZipArchive(ms2, ZipArchiveMode.Read);
                zip2.ExtractToDirectory(dir);
            }
            catch (Exception ex)
            {
                return (false, $"package refused: extraction failed ({ex.GetType().Name}) — slot {idle} holds no valid staging");
            }
            var slotHash = SlotContentHash(dir);
            WritePointer(pointer with { StagedVersion = version, StagedSlotHash = slotHash, LastOutcome = $"staged {version} into slot {idle}" });
            return (true, $"staged {version} into idle slot {idle}");
        }
    }

    /// <summary>Flip the pointer to the staged slot IF the health gate
    /// passes; otherwise roll back (pointer unchanged, staged slot
    /// quarantined). The gate is the §4.5 self-check + canary calls on
    /// the real host; in tests it is a delegate.</summary>
    public async Task<(bool Ok, string Message)> ApplyStagedAsync(CancellationToken ct)
    {
        // W12 / DS-P9-F7: stage/apply are serialized — an apply never
        // flips a pointer describing a slot a concurrent stage replaced.
        await _applyLock.WaitAsync(ct);
        try { return await ApplyStagedLockedAsync(ct); }
        finally { _applyLock.Release(); }
    }

    private async Task<(bool Ok, string Message)> ApplyStagedLockedAsync(CancellationToken ct)
    {
        // W15 / DS-P9-F6: apply fails closed under the same named
        // posture as stage — a slot staged under a dev key (or a
        // hand-written pointer) is never flipped by a production
        // composition that holds no pinned product key.
        if (_failClosedReason is not null) return (false, _failClosedReason);
        var pointer = ReadPointer();
        if (_pointerUnrecoverable)
            return (false, "pointer file and its last-known-good backup are unreadable — apply refuses rather than guess the active slot (BD-WIN-CORE-4/F10)");
        if (pointer.StagedVersion is null) return (false, "nothing staged");
        // BD-WIN-CORE-4/F10: the policy gate guards the FLIP, not
        // only staging — "the policy decides who may flip".
        if (_policyGate is not null)
        {
            var (allowed, reason) = _policyGate(pointer.StagedVersion);
            if (!allowed) return (false, reason);
        }
        var idle = pointer.Active == UpdateSlot.A ? UpdateSlot.B : UpdateSlot.A;
        // W12 / DS-P9-F5: a missing staged hash REFUSES the flip —
        // absence of the integrity anchor disables nothing.
        if (pointer.StagedSlotHash is null)
            return (false, $"staged slot {idle} carries no content hash (pre-anchor pointer or hand-edited) — apply refused, pointer unchanged; re-stage the package to anchor it");
        // BD-WIN-CORE-4/F10: re-verify the extracted slot still
        // matches what was staged from the signed package.
        {
            string current;
            try { current = SlotContentHash(SlotDir(idle)); }
            catch { current = ""; }
            if (!string.Equals(current, pointer.StagedSlotHash, StringComparison.OrdinalIgnoreCase))
                return (false, $"staged slot {idle} contents no longer match the signed package staged as {pointer.StagedVersion} — apply refused, pointer unchanged");
        }

        bool healthy;
        // W12 / DS-P9-F22: cancellation is not a health failure — it
        // propagates and quarantines nothing.
        try { healthy = await _healthGate(ct); }
        catch (OperationCanceledException) { throw; }
        catch { healthy = false; }

        if (!healthy)
        {
            // Rollback: pointer stays; the bad slot is quarantined, never served.
            // The caller-supplied version is sanitised before it becomes
            // a path segment (M3: "../" in a version string escaped the root).
            var safeVersion = string.Concat(pointer.StagedVersion.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_'));
            // W12 / DS-P9-F22: unique quarantine name (Guid suffix) —
            // a same-second retry no longer throws out of the apply.
            var quarantine = Path.Combine(_root, "quarantine", $"{idle}-{safeVersion}-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path.GetDirectoryName(quarantine)!);
            if (Directory.Exists(SlotDir(idle))) Directory.Move(SlotDir(idle), quarantine);
            Directory.CreateDirectory(SlotDir(idle));
            WritePointer(pointer with { StagedVersion = null, LastOutcome = $"health gate FAILED for {pointer.StagedVersion}; rolled back, slot quarantined at {quarantine}" });
            return (false, $"health gate failed; pointer unchanged (still {pointer.Version} on slot {pointer.Active}), bad slot quarantined");
        }

        // W12 / DS-P9-F7: re-read + re-verify AFTER the await — the
        // flip writes only values that still describe the slot NOW.
        var fresh = ReadPointer();
        if (_pointerUnrecoverable || fresh.StagedVersion != pointer.StagedVersion ||
            !string.Equals(fresh.StagedSlotHash, pointer.StagedSlotHash, StringComparison.OrdinalIgnoreCase))
            return (false, "the staged pointer changed while the health gate ran — apply refused, pointer unchanged; re-apply against the current staging");
        pointer = fresh;
        idle = pointer.Active == UpdateSlot.A ? UpdateSlot.B : UpdateSlot.A;
        {
            string current;
            try { current = SlotContentHash(SlotDir(idle)); }
            catch { current = ""; }
            if (!string.Equals(current, pointer.StagedSlotHash, StringComparison.OrdinalIgnoreCase))
                return (false, $"staged slot {idle} contents changed while the health gate ran — apply refused, pointer unchanged");
        }

        // W12 / DS-P9-F2: when an installed-version probe is wired,
        // it must prove the STAGED slot carries the staged version —
        // the health gate alone (which exercises the RUNNING code)
        // is not that proof, and its absence is a named partial
        // failure on this path, never a silent success.
        if (_stagedSlotProbe is not null)
        {
            bool probed;
            try { probed = _stagedSlotProbe(SlotDir(idle), pointer.StagedVersion!); }
            catch { probed = false; }
            if (!probed)
                return (false, $"installed-version probe FAILED for staged {pointer.StagedVersion} in slot {idle} — the staged slot does not prove it carries that version; pointer unchanged (honest partial failure, DS-P9-F2)");
        }

        // W30 / D-DEC-7: ROTATION at apply. This apply is a
        // production-signed update event — the staged package
        // verified against the pinned production key at stage time
        // (and the flip has now passed the health gate + probe) —
        // so it, and only an event of this class, authorises the
        // runtime pointer key to rotate: fresh keypair, pin
        // rewritten in the install root, and the flipped pointer
        // below is signed under the NEW key. A rotation failure
        // refuses the flip by name before the pointer moves: a
        // pointer signed under a key the pin no longer names would
        // refuse at the launcher, so the flip must not commit.
        if (_pointerSigning is not null)
        {
            try { _pointerSigning.RotateAuthorisedByProductionSignedUpdate(); }
            catch (Exception ex) { return (false, $"pointer-signing rotation at apply REFUSED by name ({ex.GetType().Name}: {ex.Message}) — pointer unchanged (W30/D-DEC-7)"); }
        }

        // BD-WIN-AGENT F6: the staged hash becomes the ACTIVE slot's
        // anchor in the flipped pointer — the launcher re-verifies
        // the slot against it before every exec.
        WritePointer(new Pointer(idle, pointer.StagedVersion, null, $"pointer flipped to {pointer.StagedVersion} on slot {idle}; health gate passed", StagedSlotHash: null, ActiveSlotHash: pointer.StagedSlotHash));
        // Honest wording (H6): the gate exercised the RUNNING code's
        // self-check, not the staged binaries. The swap itself is the
        // launcher shim's job: DeskGuestLauncher is the service binary, it
        // reads this pointer at every service start and execs the Core
        // from the active slot — so a flipped pointer takes effect at
        // the next Core restart, and this message claims exactly that,
        // never a running version it cannot prove.
        // W13 / DS-P9-F2 (closure): the UNWIRED-probe posture is
        // stated in the success message itself, not only in docs —
        // production composition (CoreRuntime) always wires the
        // probe, so this clause appears only for embedders/tests
        // that composed the manager without one, and it says
        // exactly what was and was not proven.
        var probeClause = _stagedSlotProbe is not null
            ? " The staged slot's installed-version probe PASSED for this version."
            : " NO installed-version probe is wired on this manager: the staged slot's version was NOT probe-proven — the flip rests on the signature-verified slot content hash and the health gate only (DS-P9-F2 posture, named).";
        return (true, $"update pointer flipped to {pointer.StagedVersion} on slot {idle}; the launcher shim (DeskGuestLauncher, the service binary) execs the Core from the active slot, so the swap takes effect at the next Core restart." + probeClause);
    }
}

/// <summary>Census row 85 (update half) + the §4.6 policy surface.</summary>
public sealed class AgentUpdateModule : Shared.Tools.IToolModule
{
    private readonly UpdateManager _updates;
    private readonly Shared.Security.SignedCommandGate? _commandGate;

    /// <param name="commandGate">RMM-03 verify-gate for the
    /// stage_signed action: the package AND its staged version
    /// travel inside the payload of a customer-signed envelope
    /// (class update_staging) and are verified BEFORE the existing
    /// product-key signature check and staging — defence in depth:
    /// hub compromise alone can stage nothing. When a gate is
    /// wired, the legacy product-key-only stage action refuses
    /// (D38 F8); it keeps its pre-RMM-03 posture only on endpoints
    /// with no customer key configured.</param>
    public AgentUpdateModule(UpdateManager updates, Shared.Security.SignedCommandGate? commandGate = null)
    {
        _updates = updates;
        _commandGate = commandGate;
    }

    public Shared.Tools.ToolDescriptor Descriptor { get; } = new(
        "agent_update", "Self-update status, or stage/apply a signed package (admin scope). Staging verifies the signature before anything is extracted; applying is health-gated with automatic rollback.",
        Shared.Security.Scopes.Admin, Shared.Security.SessionRequirement.Core, Shared.Security.RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["status","stage","apply","stage_signed"]},"package_base64":{"type":"string"},"signature_base64":{"type":"string"},"version":{"type":"string"},"signed_command":{"type":"string"}}}""");

    public async Task<Shared.Tools.ToolResult> ExecuteAsync(JsonElement arguments, Shared.Tools.ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = arguments.TryGetProperty("action", out var a) ? a.GetString() : "status";
        switch (action)
        {
            case "status":
                return Shared.Tools.ToolResult.Success(JsonSerializer.Serialize(_updates.Status(), new JsonSerializerOptions { WriteIndented = true }));
            case "stage":
            {
                // D38 F8 (second half): once a customer command gate
                // is wired on this endpoint, the legacy product-key-
                // only stage path CLOSES — staging requires the
                // customer-signed stage_signed path. The legacy
                // action remains only on endpoints with no customer
                // key configured (the pre-RMM-03 posture, named in
                // CoreRuntime's CommandGateState).
                if (_commandGate is not null)
                    return Shared.Tools.ToolResult.Error("signed_command_refused",
                        "a customer command key is configured on this endpoint — the legacy product-key-only stage action is closed; use stage_signed (RMM-03 / D38 F8)");
                // W12 / DS-P9-F24: malformed base64 is a tool error,
                // never an exception out of ExecuteAsync.
                byte[] pkg, sig;
                try
                {
                    pkg = Convert.FromBase64String(arguments.TryGetProperty("package_base64", out var p) ? p.GetString() ?? "" : "");
                    sig = Convert.FromBase64String(arguments.TryGetProperty("signature_base64", out var s) ? s.GetString() ?? "" : "");
                }
                catch (FormatException) { return Shared.Tools.ToolResult.Error("bad_arguments", "package_base64 / signature_base64 is not valid base64 — refused"); }
                var version = arguments.TryGetProperty("version", out var v) ? v.GetString() ?? "?" : "?";
                var (ok, msg) = _updates.StagePackage(pkg, sig, version);
                return ok ? Shared.Tools.ToolResult.Success(msg) : Shared.Tools.ToolResult.Error("signature_refused", msg);
            }
            case "stage_signed":
            {
                if (_commandGate is null)
                    return Shared.Tools.ToolResult.Error("signed_command_refused",
                        "no customer command key is configured on this endpoint — stage_signed refuses (RMM-03); the legacy stage action remains product-key gated");
                var envelope = Shared.Security.SignedCommandEnvelope.FromJson(
                    arguments.TryGetProperty("signed_command", out var sc) ? sc.GetString() : null);
                var verdict = _commandGate.Authorize(envelope, DateTimeOffset.UtcNow, Shared.Security.SignedCommandClasses.UpdateStaging);
                if (!verdict.Allowed)
                    return Shared.Tools.ToolResult.Error("signed_command_refused", verdict.Reason);
                // D38 F8: EVERYTHING that controls staging travels
                // INSIDE the signed payload — the package bytes AND
                // the version they will be staged as, as JSON
                // {"version": "...", "package_base64": "..."}. The
                // unsigned `version` / `package_base64` tool
                // arguments are ignored on this path: a compromised
                // hub must not be able to relabel a genuine package
                // with a version the customer never signed (version
                // drives pinning, downgrade logic and reporting).
                string version; byte[] pkg;
                try
                {
                    using var payloadDoc = JsonDocument.Parse(verdict.Payload!);
                    var root = payloadDoc.RootElement;
                    version = root.GetProperty("version").GetString() ?? "";
                    pkg = Convert.FromBase64String(root.GetProperty("package_base64").GetString() ?? "");
                    if (version.Length == 0 || pkg.Length == 0) throw new InvalidOperationException("empty version or package");
                }
                catch
                {
                    return Shared.Tools.ToolResult.Error("signed_command_refused",
                        "stage_signed payload does not carry the staged version and package as signed JSON — refused (D38 F8: staging metadata is signed, never taken from unsigned arguments)");
                }
                byte[] sig;
                try { sig = Convert.FromBase64String(arguments.TryGetProperty("signature_base64", out var s) ? s.GetString() ?? "" : ""); }
                catch (FormatException) { return Shared.Tools.ToolResult.Error("bad_arguments", "signature_base64 is not valid base64 — refused"); }
                var (ok, msg) = _updates.StagePackage(pkg, sig, version);
                return ok ? Shared.Tools.ToolResult.Success(msg) : Shared.Tools.ToolResult.Error("signature_refused", msg);
            }
            case "apply":
            {
                var (ok, msg) = await _updates.ApplyStagedAsync(ct);
                return ok ? Shared.Tools.ToolResult.Success(msg) : Shared.Tools.ToolResult.Error("health_gate_failed", msg);
            }
            default:
                return Shared.Tools.ToolResult.Error("bad_arguments", $"unknown action '{action}'");
        }
    }
}


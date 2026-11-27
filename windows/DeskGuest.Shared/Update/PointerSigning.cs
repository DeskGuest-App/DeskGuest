using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Update;

/// <summary>
/// W30 / D-DEC-7 / DS-B-16 pointer signing (W29-A Option 1): a
/// dedicated RUNTIME Ed25519 pointer-signing keypair, so the
/// prefix-preserving growth forgery the unkeyed audit chain
/// cannot distinguish (W19's named limit) is refused at a
/// signature leg in the launcher.
///
/// Hierarchy (two levels, the production key never signs pointer
/// states):
///   production update key (custody seed OFF the endpoint,
///   W24/D-DEC-1) — authorises install events and update APPLY
///   events, at which — and ONLY at which — the runtime pin may
///   be (re)written;
///   runtime pointer key (this class) — signs every pointer state
///   the Core's UpdateManager commits, at runtime, on the endpoint.
///
/// Custody (the tested red line): the runtime PRIVATE seed lives
/// in the INSTALL ROOT (pointer-signing.seed, beside the base
/// binaries — the install root's ACL domain: installer / SYSTEM /
/// administrators, the same domain as the launcher anchor marker),
/// NEVER in the data dir. A data-dir-only attacker can rewrite the
/// pointer, its signature sidecar and the audit chain, but cannot
/// read the seed and cannot forge a signature. Custody refuses BY
/// NAME when the key directory resolves inside the data dir —
/// that is a construction assertion in this class, not a
/// convention, and it is re-checked on every sign.
///
/// The PUBLIC half is pinned in the install root
/// (pointer-signing.pub, base64 of the raw 32-byte key — the
/// update-key.pub file format). (Re)pinning happens only in
/// <see cref="EnsureKeyForInstall"/> (install / first-run keying,
/// and only to fill an ABSENT pin — an existing differing pin is
/// never silently replaced there) and in
/// <see cref="RotateAuthorisedByProductionSignedUpdate"/>
/// (rotation at each production-signed update apply, invoked only
/// from UpdateManager's apply success path, whose staged package
/// verified against the pinned production key at stage time).
/// <see cref="TryRepin"/> refuses any repin not authorised by one
/// of those events, by name.
///
/// Pointer format: the signature travels in a SIDECAR bound to
/// the exact pointer bytes (the design's allowed form, W29 §3):
/// active-slot.json.sig beside the pointer, and
/// active-slot.json.bak.sig beside its last-known-good backup —
/// base64 of the 64-byte Ed25519 signature over the exact bytes
/// of the sibling pointer file. The pointer bytes themselves are
/// unchanged, so the W15 audit-hash leg hashes exactly what it
/// hashed before, and the W19 single-read discipline is intact:
/// the launcher verifies the sidecar against the bytes of the
/// ONE read it resolved from (SlotPointerRead.SelectedBytes).
///
/// Migration (W29 §4, fail-closed and named, the W17 pattern):
///   * no signed pointer ever vouched and no pin and no keying
///     witness → the named LEGACY-UNKEYED posture: the existing
///     anchor bindings alone decide, and the reason string says so;
///   * once ANY signed pointer has been vouched — witnessed by
///     the keying marker in the updates root AND/OR the install-
///     root pin's existence — an unsigned, badly-signed or
///     pin-less pointer is REFUSED BY NAME, never downgraded;
///   * the first signed write records the transition in the audit
///     chain under kind "update_pointer_keying_begun", carrying
///     the runtime public key's fingerprint.
///
/// HONEST LIMIT (W21 precision, named — NOT closed by this work):
/// rollback with a WRITABLE INSTALL ROOT remains open. An attacker
/// who can write the install root can restore an old genuine
/// signed pointer + its sidecar + the old audit chain + the old
/// pin/marker set, and every signature verifies; the existing
/// marker regression rule still refuses shrinkage only while a
/// genuine launcher marker survives. An attacker executing as the
/// Core/SYSTEM can sign — the pre-existing game-over class,
/// unchanged. What this closes is exactly: prefix-preserving
/// growth FORGERY by a data-dir-only attacker.
///
/// W36 / round-8 — POSITION BINDING. The W30 signature bound
/// pointer BYTES only, and the round-8 replay broke the
/// claimed boundary WITHIN the data-dir-only model: keep the
/// genuine prefix the install-root marker binds, append ONE valid
/// unkeyed pointer record naming an OLD genuinely-signed pointer's
/// hash, restore that pointer + its genuine sidecar — chain,
/// prefix binding, last-record match and the byte signature all
/// passed, so a rolled-back pointer was accepted with NO
/// install-root write. The "rollback needs a writable install
/// root" boundary was therefore WRONG and is superseded: from W36
/// the signature commits to the pointer's POSITION as well as its
/// bytes. The signed payload (see BuildPositionPayload) covers
/// the pointer bytes AND the chain index (Seq) AND the own hash
/// of the ONE update_pointer_written record that publishes them.
/// The Core appends that record FIRST (append-then-sign, via
/// UpdateManager's positioned audit seam) and signs over the
/// resulting position before any pointer file moves, so the
/// commitment is true by construction. The launcher's position
/// leg requires the chain's LAST pointer record to be exactly
/// the committed record (index + hash) and verifies the signature
/// over (pointer bytes + that commitment); ordinary non-pointer
/// growth after the pointer record does not invalidate it,
/// because the anchor is the last POINTER record, not the head.
/// The round-8 replay now fails by name at that leg: the
/// attacker's appended record sits at a new index with a new
/// hash, so the restored pointer's committed position no longer
/// matches the last pointer record. NEW BOUNDARY, exact: a
/// data-dir-only attacker can neither forge a pointer (W30) nor
/// replay/roll back a genuine one (W36); rollback now genuinely
/// requires a writable install root (restore pointer + sidecar +
/// chain + pin/marker set together — the named limit above,
/// unchanged) or execution as the Core/SYSTEM.
/// Sidecar format: W30 wrote bare base64 (position-less, "v1");
/// W36 writes "v2:" + base64 over the position payload. Once
/// position binding has begun — witnessed by the keying witnesses
/// AND/OR any v2 sidecar / position record surviving — a v1
/// sidecar is a NAMED LEGACY-POSITIONLESS refusal under the W17
/// fail-closed pattern, never a silent acceptance; rotation at
/// apply re-signs under v2 as part of the existing rotation.
/// </summary>
public sealed class PointerSigningCustody
{
    public const string PinFileName = "pointer-signing.pub";
    public const string SeedFileName = "pointer-signing.seed";
    public const string KeyingMarkerFileName = "pointer-keying.marker";
    public const string KeyingRecordKind = "update_pointer_keying_begun";
    public const string SignatureSidecarSuffix = ".sig";

    /// <summary>W36: sidecar format marker for a POSITION-BOUND
    /// signature ("v2:" + base64). A sidecar WITHOUT this prefix
    /// is a W30 position-less ("v1") signature over the pointer
    /// bytes alone — judged under the named
    /// LEGACY-POSITIONLESS migration posture in
    /// PointerAuditAnchor, never silently accepted once position
    /// binding has begun.</summary>
    public const string PositionSidecarPrefix = "v2:";

    private readonly string _keyDir;
    private readonly string _dataDir;

    /// <param name="keyDir">Custody directory: production is the
    /// install root (beside the base binaries).</param>
    /// <param name="dataDir">The Core's data dir — the directory a
    /// data-dir-only attacker can write. The key directory must
    /// NOT resolve inside it.</param>
    public PointerSigningCustody(string keyDir, string dataDir)
    {
        _keyDir = Path.GetFullPath(keyDir);
        _dataDir = Path.GetFullPath(dataDir);
        CustodyRefusal = IsInside(_keyDir, _dataDir)
            ? $"pointer signing custody REFUSED: the runtime pointer-signing key directory '{_keyDir}' resolves INSIDE the data dir '{_dataDir}' — a data-dir-only attacker could read the private seed and the B-16 forgery closure would be void (W30/D-DEC-7 custody red line); the private half is custodied in the install root, outside the data dir"
            : null;
    }

    /// <summary>Non-null when this custody is refused by name
    /// (key directory inside the data dir). Signing and keying
    /// throw with this reason; nothing is signed under a refused
    /// custody.</summary>
    public string? CustodyRefusal { get; }

    public string SeedPath => Path.Combine(_keyDir, SeedFileName);
    public string PinPath => Path.Combine(_keyDir, PinFileName);

    private static bool IsInside(string path, string dir)
    {
        var p = Path.TrimEndingDirectorySeparator(path);
        var d = Path.TrimEndingDirectorySeparator(dir);
        return string.Equals(p, d, StringComparison.OrdinalIgnoreCase)
            || p.StartsWith(d + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || p.StartsWith(d + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when keying has begun under this custody: a
    /// seed or a pin exists in the key directory.</summary>
    public bool KeyingBegun => File.Exists(SeedPath) || File.Exists(PinPath);

    /// <summary>SHA-256 (lowercase hex) of the raw 32-byte public
    /// key — the fingerprint shape the production update key uses
    /// (W24/D-DEC-1).</summary>
    public static string FingerprintOf(ReadOnlySpan<byte> publicKey) =>
        Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();

    /// <summary>The current runtime public key: derived from the
    /// seed when one is custodied, else read from the pin. Null
    /// when keying has not begun or the material is malformed.</summary>
    public byte[]? PublicKey
    {
        get
        {
            var seed = TryReadSeed();
            if (seed is not null) return Ed25519.DerivePublicKey(seed);
            return ReadPin(_keyDir);
        }
    }

    public string? Fingerprint => PublicKey is { } pub ? FingerprintOf(pub) : null;

    private byte[]? TryReadSeed()
    {
        try
        {
            if (!File.Exists(SeedPath)) return null;
            var raw = Convert.FromBase64String(File.ReadAllText(SeedPath).Trim());
            return raw.Length == 32 ? raw : null;
        }
        catch { return null; }
    }

    private byte[] LoadSeedOrThrow()
    {
        if (CustodyRefusal is not null) throw new InvalidOperationException(CustodyRefusal);
        return TryReadSeed()
            ?? throw new InvalidOperationException(
                $"pointer signing: no usable runtime seed at '{SeedPath}' — keying has not begun or the custodied seed is malformed; signing refuses by name rather than write an unsigned pointer after keying (W30/D-DEC-7)");
    }

    /// <summary>Install / first-run keying (an authorised pinning
    /// event): generate the keypair when no seed is custodied and
    /// pin the public half when the pin is ABSENT. An existing pin
    /// that DIFFERS from the custodied seed's public half is never
    /// silently replaced here — that is a repin, and repinning is
    /// authorised only by a production-signed update apply
    /// (rotation) — so this refuses by name instead. Returns true
    /// when this call BEGAN keying (no seed and no pin existed).</summary>
    public bool EnsureKeyForInstall()
    {
        if (CustodyRefusal is not null) throw new InvalidOperationException(CustodyRefusal);
        Directory.CreateDirectory(_keyDir);
        var began = !File.Exists(SeedPath) && !File.Exists(PinPath);
        var seed = TryReadSeed();
        if (seed is null)
        {
            if (File.Exists(SeedPath))
                throw new InvalidOperationException(
                    $"pointer signing: the custodied seed at '{SeedPath}' is malformed — keying refuses by name; recovery is the next production-signed update (rotation) or a reinstall (W30/D-DEC-7)");
            var (newSeed, _) = Ed25519.GenerateKeyPair();
            WriteAtomic(SeedPath, Convert.ToBase64String(newSeed));
            seed = newSeed;
        }
        var pub = Ed25519.DerivePublicKey(seed);
        var pin = ReadPin(_keyDir);
        if (pin is null)
        {
            if (File.Exists(PinPath))
                throw new InvalidOperationException(
                    $"pointer signing: the runtime public pin at '{PinPath}' exists but is malformed — keying refuses by name rather than silently repin outside an install/update event (W30/D-DEC-7)");
            WriteAtomic(PinPath, Convert.ToBase64String(pub));
        }
        else if (!pin.AsSpan().SequenceEqual(pub))
        {
            throw new InvalidOperationException(
                $"pointer signing: the install-root pin at '{PinPath}' (fingerprint {FingerprintOf(pin)}) does NOT match the custodied runtime key (fingerprint {FingerprintOf(pub)}) — repinning outside an install / production-signed update event is refused by name (W30/D-DEC-7)");
        }
        return began;
    }

    /// <summary>Rotation at a production-signed update apply — the
    /// ONLY routine repin. Invoked solely from UpdateManager's
    /// apply success path: the staged package verified against the
    /// pinned production key at stage time, so the apply IS the
    /// authorising production-signed update event (W29 §3). A fresh
    /// keypair replaces the custodied seed and the pin together.</summary>
    public void RotateAuthorisedByProductionSignedUpdate()
    {
        if (CustodyRefusal is not null) throw new InvalidOperationException(CustodyRefusal);
        Directory.CreateDirectory(_keyDir);
        // W37: archive the OUTGOING pin before it is replaced, so
        // signatures made under it — compliance-pack anchors name
        // their signing key's fingerprint (PackAuditAnchor) —
        // remain verifiable after rotation. The archive lives in
        // the install root, the same custody domain as the pin.
        ArchiveCurrentPin(_keyDir);
        var (seed, pub) = Ed25519.GenerateKeyPair();
        WriteAtomic(SeedPath, Convert.ToBase64String(seed));
        WriteAtomic(PinPath, Convert.ToBase64String(pub));
    }

    /// <summary>W37: directory (inside the key directory / install
    /// root) holding pins retired by rotation, one file per key
    /// fingerprint, so position-bound signatures made under a
    /// rotated-out key — pack anchors in particular — stay
    /// verifiable under the pin they were actually made with.</summary>
    public const string PinArchiveDirName = "pointer-signing-pub-archive";

    /// <summary>The directory this custody reads pins from
    /// (production: the install root).</summary>
    public string KeyDirectory => _keyDir;

    /// <summary>W37: copy the current pin (if any and readable)
    /// into the pin archive under its fingerprint. Best-effort by
    /// design at the rotation call site's discretion — a missing
    /// archive entry makes old signatures refuse BY NAME at
    /// verification, never silently pass.</summary>
    public static void ArchiveCurrentPin(string keyDir)
    {
        var pin = ReadPin(keyDir);
        if (pin is null) return;
        var dir = Path.Combine(keyDir, PinArchiveDirName);
        Directory.CreateDirectory(dir);
        WriteAtomic(Path.Combine(dir, FingerprintOf(pin) + ".pub"), Convert.ToBase64String(pin));
    }

    /// <summary>W37: read an archived (rotated-out) pin by its
    /// fingerprint. Null when absent or malformed — callers refuse
    /// by name, because a signature naming an unarchived,
    /// non-current fingerprint cannot be judged.</summary>
    public static byte[]? ReadArchivedPin(string? keyDir, string? fingerprint)
    {
        if (keyDir is null || string.IsNullOrWhiteSpace(fingerprint)) return null;
        try
        {
            var path = Path.Combine(keyDir, PinArchiveDirName, fingerprint.Trim().ToLowerInvariant() + ".pub");
            if (!File.Exists(path)) return null;
            var raw = Convert.FromBase64String(File.ReadAllText(path).Trim());
            return raw.Length == 32 && !Ed25519.IsSmallOrderPublicKey(raw) &&
                   string.Equals(FingerprintOf(raw), fingerprint.Trim(), StringComparison.OrdinalIgnoreCase)
                ? raw : null;
        }
        catch { return null; }
    }

    /// <summary>An explicit repin attempt. Refused by name unless
    /// the caller names a production-signed install/update event as
    /// its authority — a bare runtime or data-dir request can never
    /// move the pin (W29 §3 Option 1: (re)pinning authorised ONLY
    /// by install events or production-signed update events).</summary>
    public (bool Ok, string Reason) TryRepin(byte[] publicKey, bool authorisedByProductionSignedEvent)
    {
        if (CustodyRefusal is not null) return (false, CustodyRefusal);
        if (publicKey is null || publicKey.Length != 32)
            return (false, "pointer signing repin REFUSED: a runtime public key is exactly 32 bytes (W30/D-DEC-7)");
        if (Ed25519.IsSmallOrderPublicKey(publicKey))
            return (false, "pointer signing repin REFUSED: small-order Ed25519 public keys are forgeable and never pin (W30/D-DEC-7)");
        if (!authorisedByProductionSignedEvent)
            return (false, "pointer signing repin REFUSED: (re)pinning the runtime pointer key is authorised ONLY by an install event or a production-signed update event — this attempt names neither (W30/D-DEC-7); pin unchanged");
        Directory.CreateDirectory(_keyDir);
        WriteAtomic(PinPath, Convert.ToBase64String(publicKey));
        return (true, $"pointer signing: runtime public pin replaced under a production-signed event (new fingerprint {FingerprintOf(publicKey)})");
    }

    /// <summary>Sign the exact pointer bytes about to be committed.
    /// Re-checks the custody red line on EVERY sign: a seed found
    /// inside the data dir at sign time refuses by name, however it
    /// got there (W29 §5 test 6).</summary>
    public byte[] Sign(byte[] pointerBytes)
    {
        if (CustodyRefusal is not null) throw new InvalidOperationException(CustodyRefusal);
        if (IsInside(SeedPath, _dataDir))
            throw new InvalidOperationException(
                $"pointer signing REFUSED: the runtime private seed '{SeedPath}' resolves inside the data dir '{_dataDir}' — signing under a data-dir-readable key would void the B-16 forgery closure (W30/D-DEC-7 custody red line)");
        return Ed25519.Sign(LoadSeedOrThrow(), pointerBytes);
    }

    /// <summary>W36 / round-8: the POSITION-BOUND signed
    /// payload — a domain separator, the chain index (Seq) and
    /// own hash of the update_pointer_written record publishing
    /// this pointer, and the exact pointer bytes. The record hash
    /// commits to the record's full content (which itself carries
    /// pointer_sha256), its predecessor and its position in the
    /// chain's hash linkage, so a data-dir attacker cannot
    /// re-target the commitment to a record they append: their
    /// record necessarily sits at a different index with a
    /// different hash.</summary>
    public static byte[] BuildPositionPayload(byte[] pointerBytes, long recordSeq, string recordHash)
    {
        var head = Encoding.UTF8.GetBytes(
            $"deskguest-pointer-position-v2|seq={recordSeq}|record_hash={recordHash.ToLowerInvariant()}|");
        var payload = new byte[head.Length + pointerBytes.Length];
        Buffer.BlockCopy(head, 0, payload, 0, head.Length);
        Buffer.BlockCopy(pointerBytes, 0, payload, head.Length, pointerBytes.Length);
        return payload;
    }

    /// <summary>W36: sign the position payload for the pointer
    /// record the Core has JUST appended (append-then-sign: the
    /// caller appends the record, learns its Seq + Hash, then
    /// signs over that exact position — see UpdateManager).
    /// Custody discipline is Sign's, unchanged.</summary>
    public byte[] SignPositioned(byte[] pointerBytes, long recordSeq, string recordHash) =>
        Sign(BuildPositionPayload(pointerBytes, recordSeq, recordHash));

    /// <summary>W36: format a signature for its sidecar. v2
    /// (position-bound) carries the prefix; v1 is bare base64.</summary>
    public static string FormatSidecar(byte[] signature, bool positionBound) =>
        positionBound ? PositionSidecarPrefix + Convert.ToBase64String(signature)
                      : Convert.ToBase64String(signature);

    /// <summary>W36: parse a sidecar's text. Returns false when
    /// the content is not base64 at all (callers refuse by name);
    /// <paramref name="positionBound"/> distinguishes a v2
    /// position-bound signature from a W30 v1 position-less one.</summary>
    public static bool TryParseSidecar(string text, out byte[] signature, out bool positionBound)
    {
        signature = Array.Empty<byte>(); positionBound = false;
        var t = (text ?? "").Trim();
        if (t.StartsWith(PositionSidecarPrefix, StringComparison.Ordinal))
        {
            positionBound = true;
            t = t[PositionSidecarPrefix.Length..].Trim();
        }
        try { signature = Convert.FromBase64String(t); return true; }
        catch { signature = Array.Empty<byte>(); return false; }
    }

    // ---- pin / sidecar / witness statics (the launcher's half) ----

    /// <summary>Read the pinned runtime public key from a pin
    /// directory (production: the install root). Null when absent
    /// or malformed — callers judge presence separately, because
    /// after first keying a missing/malformed pin is a REFUSAL,
    /// not a legacy downgrade.</summary>
    public static byte[]? ReadPin(string? pinDir)
    {
        if (pinDir is null) return null;
        try
        {
            var path = Path.Combine(pinDir, PinFileName);
            if (!File.Exists(path)) return null;
            var raw = Convert.FromBase64String(File.ReadAllText(path).Trim());
            return raw.Length == 32 && !Ed25519.IsSmallOrderPublicKey(raw) ? raw : null;
        }
        catch { return null; }
    }

    public static bool PinFileExists(string? pinDir) =>
        pinDir is not null && File.Exists(Path.Combine(pinDir, PinFileName));

    /// <summary>The signature sidecar for a pointer file: the
    /// pointer path + ".sig" (active-slot.json.sig /
    /// active-slot.json.bak.sig).</summary>
    public static string SignaturePathFor(string pointerPath) => pointerPath + SignatureSidecarSuffix;

    /// <summary>The keying witness in the updates root: written at
    /// the first signed pointer write. Its existence (with the
    /// pin's) is what makes a later unsigned/pin-less state a
    /// refusal rather than a downgrade (W29 §4).</summary>
    public static string KeyingMarkerPath(string updatesRoot) => Path.Combine(updatesRoot, KeyingMarkerFileName);

    public static bool KeyingMarkerExists(string updatesRoot) => File.Exists(KeyingMarkerPath(updatesRoot));

    public static void WriteKeyingMarker(string updatesRoot, string fingerprint)
    {
        Directory.CreateDirectory(updatesRoot);
        WriteAtomic(KeyingMarkerPath(updatesRoot),
            $"pointer_key_fingerprint={fingerprint}" + Environment.NewLine +
            "keying=begun (W30/D-DEC-7: after this witness exists, an unsigned or badly-signed pointer refuses by name)" + Environment.NewLine);
    }

    private static void WriteAtomic(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}

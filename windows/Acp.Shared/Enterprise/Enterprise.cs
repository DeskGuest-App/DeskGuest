using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Connection;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Shared.Enterprise;

// =====================================================================
// Block E — enterprise pack model layer (Slice 5 / D10).
// Everything here is fail-closed: a malformed, tampered, expired or
// out-of-scope input REFUSES; nothing widens silently. Directive ids
// are cited per type; the regression tests cite them again by name.
// =====================================================================

internal static class EntUtil
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    public static string Canonical(JsonElement el) => el.GetRawText();

    public static bool FixedEq(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}

// ------------------------------------------------- DIR-25 / DIR-56 /
// ADIR-22 / ADIR-30 / ADIR-36 / REC-15: hash-chained audit ledger.
// Each entry carries a per-device monotonic sequence number and the
// hash of its predecessor (DIR-56 time discipline: sequence orders the
// chain even when wall clocks skew; a skewed timestamp is FLAGGED on
// the entry, never silently trusted). Verification names the first
// broken link. Exports state the verification result in their header:
// a broken chain exports as BROKEN, never silently (Block E brief).

public sealed record ChainedAuditEntry(
    long Seq, DateTimeOffset AtUtc, string Kind, string Actor, string Detail,
    string PrevHash, string Hash, bool ClockSkewFlagged);

public sealed record ChainVerification(bool Ok, long? BrokenAtSeq, string Summary);

public sealed class ChainedAuditLog
{
    public const string GenesisHash = "GENESIS";
    private readonly List<ChainedAuditEntry> _entries = new();
    private readonly object _gate = new();
    private DateTimeOffset _lastAt = DateTimeOffset.MinValue;

    public IReadOnlyList<ChainedAuditEntry> Entries { get { lock (_gate) return _entries.ToList(); } }
    public string HeadHash { get { lock (_gate) return _entries.Count == 0 ? GenesisHash : _entries[^1].Hash; } }

    private static string ComputeHash(long seq, DateTimeOffset at, string kind, string actor, string detail, string prev) =>
        EntUtil.Sha256Hex($"{seq}|{at:O}|{kind}|{actor}|{detail}|{prev}");

    public ChainedAuditEntry Append(string kind, string actor, string detail, DateTimeOffset atUtc)
    {
        lock (_gate)
        {
            var seq = _entries.Count + 1L;
            var prev = _entries.Count == 0 ? GenesisHash : _entries[^1].Hash;
            // DIR-56: wall-clock going backwards is flagged, sequence still orders.
            var skew = atUtc < _lastAt;
            if (atUtc > _lastAt) _lastAt = atUtc;
            var e = new ChainedAuditEntry(seq, atUtc, kind, actor, detail, prev,
                ComputeHash(seq, atUtc, kind, actor, detail, prev), skew);
            _entries.Add(e);
            return e;
        }
    }

    // W11 (found by the lane's destruction pass, via BlockFTests):
    // a store that fails to PARSE at import previously left this
    // log at genesis — Verify() then reported the fresh, empty
    // chain as OK and the next SaveChain overwrote the broken
    // store with it: a silent re-base, exactly what the import
    // comment below forbids. A failed import now LATCHES: Verify()
    // reports the import failure until a clean store imports.
    private string? _importFailure;

    public ChainVerification Verify()
    {
        lock (_gate)
        {
            if (_importFailure is not null)
                return new ChainVerification(false, null,
                    $"BROKEN: {_importFailure} — the break is carried by this log, never re-based");
            return VerifyEntriesLocked();
        }
    }

    private ChainVerification VerifyEntriesLocked()
    {
        var prev = GenesisHash;
        foreach (var e in _entries)
        {
            if (e.PrevHash != prev)
                return new ChainVerification(false, e.Seq, $"BROKEN at seq {e.Seq}: prev-hash link mismatch");
            if (e.Hash != ComputeHash(e.Seq, e.AtUtc, e.Kind, e.Actor, e.Detail, e.PrevHash))
                return new ChainVerification(false, e.Seq, $"BROKEN at seq {e.Seq}: entry hash mismatch (content altered)");
            prev = e.Hash;
        }
        return new ChainVerification(true, null, $"OK: {_entries.Count} entries, chain intact, head {prev}");
    }

    // --- Persistence (Block F wiring): the Core persists the ledger
    // across restarts. Restore is VERBATIM + VERIFIED: entries are
    // restored exactly as recorded and the chain is re-verified on
    // import; a tampered store imports as a BROKEN chain (visible),
    // never as a silently re-based one.
    public string ExportEntriesJson()
    {
        lock (_gate) return JsonSerializer.Serialize(_entries);
    }

    public ChainVerification ImportEntriesJson(string json)
    {
        List<ChainedAuditEntry> restored;
        try { restored = JsonSerializer.Deserialize<List<ChainedAuditEntry>>(json) ?? new List<ChainedAuditEntry>(); }
        catch
        {
            // W11: a store that does not parse imports NOTHING and
            // the failure LATCHES (see Verify) — the previous shape
            // returned a broken verdict for the import call itself
            // but left the log at a pristine genesis, so every
            // later Verify() called the re-based chain OK.
            lock (_gate)
            {
                _entries.Clear();
                _lastAt = DateTimeOffset.MinValue;
                _importFailure = "audit store did not parse — prior chain NOT trusted and NOT re-based";
            }
            return new ChainVerification(false, null, _importFailure);
        }
        lock (_gate)
        {
            _entries.Clear();
            _entries.AddRange(restored);
            _lastAt = _entries.Count == 0 ? DateTimeOffset.MinValue : _entries.Max(e => e.AtUtc);
            var verdict = VerifyEntriesLocked();
            _importFailure = verdict.Ok ? null : verdict.Summary;
            return verdict;
        }
    }

    /// <summary>DIR-25 cross-witness: at session close a peer device signs the
    /// chain head; the witness record is verifiable against that device's
    /// enrolled public key and binds (head, seq, session).</summary>
    public sealed record Witness(string SessionId, string WitnessDeviceId, long HeadSeq, string HeadHash, string SignatureBase64);

    public Witness CreateWitness(string sessionId, DeviceIdentity witness)
    {
        lock (_gate)
        {
            var head = _entries.Count == 0 ? GenesisHash : _entries[^1].Hash;
            var seq = _entries.Count;
            var msg = Encoding.UTF8.GetBytes($"acp-witness-v1|{sessionId}|{seq}|{head}");
            return new Witness(sessionId, witness.DeviceId, seq, head, Convert.ToBase64String(witness.Sign(msg)));
        }
    }

    public bool VerifyWitness(Witness w, byte[] witnessPublicKey)
    {
        // bd-shared-sec-2/F9: a witness signature alone proved
        // only that SOME log once had this head -- the witness
        // was never checked against THIS log's entries, so a
        // witness from another log (or a fabricated head) verified
        // against a rewritten chain. The witness now verifies
        // only when this log's entry at HeadSeq carries exactly
        // HeadHash.
        lock (_gate)
        {
            if (w.HeadSeq < 1 || w.HeadSeq > _entries.Count) return false;
            if (!string.Equals(_entries[(int)w.HeadSeq - 1].Hash, w.HeadHash, StringComparison.Ordinal))
                return false;
        }
        var msg = Encoding.UTF8.GetBytes($"acp-witness-v1|{w.SessionId}|{w.HeadSeq}|{w.HeadHash}");
        try { return Ed25519.Verify(witnessPublicKey, msg, Convert.FromBase64String(w.SignatureBase64)); }
        catch { return false; }
    }

    /// <summary>bd-shared-sec-2/F9: witnesses this log holds
    /// (recorded via RecordWitness). A recorded witness is
    /// re-verified against the live chain on every read of this
    /// property's backing check in VerifyStoredWitnesses, so a
    /// persisted-then-rewritten store whose recomputed hashes
    /// pass Verify() still fails against a witness recorded
    /// before the rewrite.</summary>
    private readonly List<(Witness W, byte[] PublicKey)> _witnesses = new();

    public bool RecordWitness(Witness w, byte[] witnessPublicKey)
    {
        if (!VerifyWitness(w, witnessPublicKey)) return false;
        lock (_gate) _witnesses.Add((w, witnessPublicKey.ToArray()));
        return true;
    }

    /// <summary>True when every recorded witness still matches
    /// this log's chain AND signature. False when any recorded
    /// witness disagrees -- the rewrite/truncation signal.</summary>
    public bool VerifyStoredWitnesses()
    {
        List<(Witness W, byte[] PublicKey)> copy;
        lock (_gate) copy = _witnesses.ToList();
        return copy.All(x => VerifyWitness(x.W, x.PublicKey));
    }

    public int StoredWitnessCount { get { lock (_gate) return _witnesses.Count; } }

    // --- Exports (DIR-23). The export itself is audited BEFORE the export
    // is produced, so the exported ledger contains its own export record.
    private string ExportHeader(ChainVerification v, string format, DateTimeOffset now) =>
        $"ACP audit export | format={format} | exportedUtc={now:O} | chainVerification={(v.Ok ? "OK" : "BROKEN")} | {v.Summary}";

    public string ExportJson(string exportedBy, DateTimeOffset now)
    {
        Append("audit_export", exportedBy, "format=json", now);
        var v = Verify();
        lock (_gate)
        {
            var payload = new { header = ExportHeader(v, "json", now), entries = _entries };
            return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        }
    }

    public string ExportCsv(string exportedBy, DateTimeOffset now)
    {
        Append("audit_export", exportedBy, "format=csv", now);
        var v = Verify();
        var sb = new StringBuilder();
        sb.AppendLine("# " + ExportHeader(v, "csv", now));
        sb.AppendLine("seq,atUtc,kind,actor,detail,prevHash,hash,clockSkewFlagged");
        lock (_gate)
            foreach (var e in _entries)
                sb.AppendLine($"{e.Seq},{e.AtUtc:O},{Csv(e.Kind)},{Csv(e.Actor)},{Csv(e.Detail)},{e.PrevHash},{e.Hash},{e.ClockSkewFlagged}");
        return sb.ToString();
    }

    /// <summary>Syslog CEF-shaped export (DIR-23): one CEF line per entry,
    /// preceded by a header line carrying the chain verdict.</summary>
    public string ExportCef(string exportedBy, DateTimeOffset now)
    {
        Append("audit_export", exportedBy, "format=cef", now);
        var v = Verify();
        var sb = new StringBuilder();
        sb.AppendLine("# " + ExportHeader(v, "cef", now));
        lock (_gate)
            foreach (var e in _entries)
                sb.AppendLine($"CEF:0|ACP|AgenticControl|1|{Cef(e.Kind)}|{Cef(e.Kind)}|5|rt={e.AtUtc:MMM dd yyyy HH:mm:ss} act={Cef(e.Actor)} msg={Cef(e.Detail)} externalId={e.Seq} cs1={e.Hash} cs1Label=entryHash cs2={e.PrevHash} cs2Label=prevHash");
        return sb.ToString();
    }

    private static string Csv(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
    private static string Cef(string s) => s.Replace("\\", "\\\\").Replace("=", "\\=").Replace("|", "\\|").Replace("\n", " ");
}

// ------------------------------------------------- DIR-22 / DIR-38 /
// DIR-65 / REC-13: signed policy bundle. The bundle is Ed25519-signed
// by the org policy key; verification is fail-closed (bad signature,
// expired bundle, or unknown fields that change meaning all refuse).
// A hand-edited policy file can therefore only ever NARROW or refuse —
// it can never widen (destruction-gate requirement).

public sealed record PolicyBundle(
    int Version,
    string ScopeId,
    IReadOnlyList<string> TransportCeiling,   // D10/D29: org ceiling; Manual+one rung is expressed as Mode=manual + one ceiling rung
    string TransportMode,                      // "auto" | "manual"
    string? PinnedVersion,                     // update pin: only this version may run
    DateTimeOffset? UpdateDeferUntil,          // updates deferred until this instant
    bool ForbidAiPairings,                     // DIR-65
    bool DisableRecording,                     // REC-13
    string UnattendedTier,                     // DIR-38: "none" | "business_hours" | "always_with_gates"
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string SignatureBase64,
    // TOTAL POLICY CONTROL (2026-11-20 standing directive), policy
    // format v2: per-feature toggles. A feature key in DisabledFeatures
    // is refused at its gate; a key in RequiredFeatures must be active
    // for the surface it guards (e.g. watermark required → an
    // unwatermarked stream may not start). Both lists are INSIDE the
    // signed canonical body for Version >= 2 — a hand-edited toggle
    // breaks the signature and the whole bundle refuses. A v1 bundle
    // carrying non-empty lists refuses outright: toggles can never be
    // smuggled past the signature by downgrading the format.
    IReadOnlyList<string>? DisabledFeatures = null,
    IReadOnlyList<string>? RequiredFeatures = null)
{
    /// <summary>Disabled feature keys, normalized (trimmed,
    /// lowercased, distinct, sorted) — the form the canonical body
    /// and the enforcer both read.</summary>
    public IReadOnlyList<string> Disabled => PolicyFeatures.Normalize(DisabledFeatures);

    /// <summary>Required feature keys, normalized like <see cref="Disabled"/>.</summary>
    public IReadOnlyList<string> Required => PolicyFeatures.Normalize(RequiredFeatures);
}

/// <summary>The closed set of policy-toggleable feature keys
/// (TOTAL POLICY CONTROL). Every Block G feature registers its key
/// here and consults PolicyEnforcer.CheckFeature at its gate; a
/// bundle naming a key outside this set refuses at verification —
/// an unknown toggle is a field that changes meaning, and unknown
/// fields refuse (the bundle's standing rule). The §7.10 consent
/// floor is NOT in this set and can never be added: presence, STOP,
/// and the audit chain are not features and have no toggle.</summary>
public static class PolicyFeatures
{
    public const string WakeOnLan = "wake_on_lan";                 // G-01
    public const string BlankScreen = "blank_screen";              // G-02
    public const string InputBlock = "input_block";                // G-03
    public const string StandaloneFileTransfer = "standalone_file_transfer"; // G-04
    public const string VoiceVideo = "voice_video";                // G-05
    public const string LocalSecondFactor = "local_second_factor"; // G-06
    public const string Watermark = "watermark";                   // G-07
    public const string TcpTunnel = "tcp_tunnel";                  // G-08

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        WakeOnLan, BlankScreen, InputBlock, StandaloneFileTransfer,
        VoiceVideo, LocalSecondFactor, Watermark, TcpTunnel,
    };

    /// <summary>Canonical list form: trimmed, lowercased, distinct,
    /// sorted — so two bundles with the same toggles in different
    /// orders sign and compare identically.</summary>
    public static IReadOnlyList<string> Normalize(IReadOnlyList<string>? keys) =>
        (keys ?? Array.Empty<string>())
            .Select(k => (k ?? "").Trim().ToLowerInvariant())
            .Where(k => k.Length > 0)
            .Distinct()
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
}

public sealed record PolicyVerdict(bool Allowed, string Reason);

public sealed class PolicyBundleService
{
    public static string CanonicalBody(PolicyBundle b)
    {
        var body = string.Join("|",
            b.Version, b.ScopeId, string.Join(",", b.TransportCeiling), b.TransportMode,
            b.PinnedVersion ?? "-", b.UpdateDeferUntil?.ToString("O") ?? "-",
            b.ForbidAiPairings, b.DisableRecording, b.UnattendedTier,
            b.IssuedUtc.ToString("O"), b.ExpiresUtc.ToString("O"));
        // Policy format v2: the feature toggles are inside the
        // signed body. v1 bodies are byte-identical to the original
        // format, so existing v1 bundles keep verifying.
        if (b.Version >= 2)
            body += "|disabled:" + string.Join(",", b.Disabled) +
                    "|required:" + string.Join(",", b.Required);
        return body;
    }

    public static PolicyBundle Sign(PolicyBundle unsigned, DeviceIdentity orgKey) =>
        unsigned with { SignatureBase64 = Convert.ToBase64String(orgKey.Sign(Encoding.UTF8.GetBytes(CanonicalBody(unsigned)))) };

    /// <summary>bd-shared-sec-2/F5: the closed set for
    /// UnattendedTier (DIR-38). Verify previously never checked
    /// it, so a signed bundle could carry any string here and
    /// consumers comparing against the known tiers silently
    /// mismatched.</summary>
    public static readonly IReadOnlySet<string> UnattendedTiers =
        new HashSet<string>(StringComparer.Ordinal) { "none", "business_hours", "always_with_gates" };

    public PolicyVerdict Verify(PolicyBundle b, byte[] orgPublicKey, DateTimeOffset now)
        => Verify(b, orgPublicKey, now, expectedScopeId: null, lastAccepted: null);

    /// <summary>bd-shared-sec-2/F5: scope- and rollback-aware
    /// verification. The base Verify never compared the bundle's
    /// ScopeId to the device's scope and never compared
    /// Version/IssuedUtc to the last accepted bundle, so an
    /// older or other-scope bundle that was still unexpired (and
    /// validly signed, e.g. captured from another scope) was
    /// accepted. When the caller supplies them, a scope mismatch
    /// refuses, and a bundle whose Version regresses -- or whose
    /// (Version, IssuedUtc) pair is older than the last accepted
    /// -- refuses as a rollback.</summary>
    public PolicyVerdict Verify(PolicyBundle b, byte[] orgPublicKey, DateTimeOffset now,
        string? expectedScopeId, (long Version, DateTimeOffset IssuedUtc)? lastAccepted)
    {
        if (expectedScopeId is not null &&
            !string.Equals(b.ScopeId, expectedScopeId, StringComparison.OrdinalIgnoreCase))
            return new PolicyVerdict(false, $"policy bundle is for scope '{b.ScopeId}', not this device's scope '{expectedScopeId}' — refused (a bundle never crosses scopes)");
        if (lastAccepted is { } last)
        {
            if (b.Version < last.Version)
                return new PolicyVerdict(false, $"policy bundle version {b.Version} regresses below the last accepted version {last.Version} — refused (rollback protection)");
            if (b.Version == last.Version && b.IssuedUtc < last.IssuedUtc)
                return new PolicyVerdict(false, $"policy bundle v{b.Version} was issued {b.IssuedUtc:O}, before the last accepted v{last.Version} issued {last.IssuedUtc:O} — refused (rollback protection)");
        }
        if (!UnattendedTiers.Contains(b.UnattendedTier ?? ""))
            return new PolicyVerdict(false, $"unknown unattended tier '{b.UnattendedTier}' — refused (closed set: none | business_hours | always_with_gates)");
        if (b.ExpiresUtc <= now) return new PolicyVerdict(false, "policy bundle expired — refused (fail closed)");
        if (b.IssuedUtc > now.AddMinutes(5)) return new PolicyVerdict(false, "policy bundle issued in the future — refused");
        if (b.TransportMode is not ("auto" or "manual")) return new PolicyVerdict(false, $"unknown transport mode '{b.TransportMode}' — refused");
        if (b.TransportMode == "manual" && b.TransportCeiling.Count != 1)
            return new PolicyVerdict(false, "manual policy must name exactly one approved rung (D10/D29) — refused");
        foreach (var r in b.TransportCeiling)
            if (!RosterService.IsValidRung(r)) return new PolicyVerdict(false, $"unknown rung '{r}' in ceiling — refused");
        // TOTAL POLICY CONTROL toggles (format v2). A v1 bundle
        // carrying toggles refuses: the v1 signature does not cover
        // them, so honoring them would let a hand edit widen or
        // narrow policy unsigned. Unknown keys refuse (a field that
        // changes meaning); a key in BOTH lists is a contradiction
        // and refuses rather than picking a winner.
        if (b.Version < 2 && (b.Disabled.Count > 0 || b.Required.Count > 0))
            return new PolicyVerdict(false, "feature toggles require policy format v2 — a v1 bundle carrying them is refused (unsigned toggles are never honored)");
        foreach (var k in b.Disabled.Concat(b.Required))
            if (!PolicyFeatures.All.Contains(k))
                return new PolicyVerdict(false, $"unknown feature key '{k}' in policy toggles — refused");
        if (b.Disabled.Intersect(b.Required).Any())
            return new PolicyVerdict(false, "a feature cannot be both disabled and required by policy — refused as contradictory");
        bool ok;
        try { ok = Ed25519.Verify(orgPublicKey, Encoding.UTF8.GetBytes(CanonicalBody(b)), Convert.FromBase64String(b.SignatureBase64)); }
        catch { ok = false; }
        return ok ? new PolicyVerdict(true, "policy bundle verified") : new PolicyVerdict(false, "policy bundle signature invalid — refused (fail closed)");
    }
}

public sealed class PolicyEnforcer
{
    private readonly PolicyBundle _bundle;
    public PolicyEnforcer(PolicyBundle verifiedBundle) => _bundle = verifiedBundle;

    /// <summary>bd-shared-sec-2/F5: construct an enforcer ONLY
    /// from a successful Verify verdict -- the plain constructor
    /// accepts any bundle, so "verified" was a comment, not a
    /// property of the type. Callers with a verdict in hand use
    /// this; it refuses (null) on a failed verdict.</summary>
    public static PolicyEnforcer? FromVerified(PolicyBundle bundle, PolicyVerdict verdict) =>
        verdict.Allowed ? new PolicyEnforcer(bundle) : null;
    public PolicyBundle Bundle => _bundle;

    /// <summary>Update gate: the Core must REFUSE an update that violates
    /// pin/defer policy (Block E brief). Pin wins over defer; both refuse.</summary>
    public PolicyVerdict CheckUpdate(string candidateVersion, DateTimeOffset now)
    {
        if (_bundle.PinnedVersion is { } pin && pin != candidateVersion)
            return new PolicyVerdict(false, $"update to {candidateVersion} refused: policy pins version {pin} (DIR-22)");
        if (_bundle.UpdateDeferUntil is { } until && now < until)
            return new PolicyVerdict(false, $"update to {candidateVersion} refused: updates deferred until {until:O} by policy (DIR-22)");
        return new PolicyVerdict(true, "update permitted by policy");
    }

    public PolicyVerdict CheckTransport(string rung) =>
        _bundle.TransportCeiling.Contains(rung)
            ? new PolicyVerdict(true, "rung within policy ceiling")
            : new PolicyVerdict(false, $"rung '{rung}' is outside the policy ceiling — refused (D10)");

    public PolicyVerdict CheckAiPairing() =>
        _bundle.ForbidAiPairings
            ? new PolicyVerdict(false, "AI pairings are forbidden in this scope by policy (DIR-65)")
            : new PolicyVerdict(true, "AI pairing permitted by policy");

    /// <summary>The three-state feature posture (TOTAL POLICY
    /// CONTROL): "disabled" | "required" | "allowed". An unknown
    /// key reads "disabled" — the policy layer never silently
    /// allows a feature it does not know.</summary>
    public string FeatureState(string featureKey)
    {
        var key = (featureKey ?? "").Trim().ToLowerInvariant();
        if (!PolicyFeatures.All.Contains(key)) return "disabled";
        if (_bundle.Disabled.Contains(key)) return "disabled";
        if (_bundle.Required.Contains(key)) return "required";
        return "allowed";
    }

    /// <summary>The feature gate every toggleable feature consults
    /// before it acts. Disabled refuses; required and allowed pass
    /// (a required feature's MUST-BE-ACTIVE half is enforced by the
    /// surface it guards — e.g. the stream refuses to start
    /// unwatermarked when watermark is required).</summary>
    public PolicyVerdict CheckFeature(string featureKey)
    {
        var key = (featureKey ?? "").Trim().ToLowerInvariant();
        if (!PolicyFeatures.All.Contains(key))
            return new PolicyVerdict(false, $"unknown feature key '{featureKey}' — refused (fail closed)");
        return _bundle.Disabled.Contains(key)
            ? new PolicyVerdict(false, $"feature '{key}' is disabled by policy for this scope (TOTAL POLICY CONTROL)")
            : new PolicyVerdict(true, $"feature '{key}' permitted by policy");
    }

    /// <summary>True when policy REQUIRES the feature to be active
    /// on the surfaces it guards.</summary>
    public bool FeatureRequired(string featureKey)
    {
        var key = (featureKey ?? "").Trim().ToLowerInvariant();
        return PolicyFeatures.All.Contains(key) && _bundle.Required.Contains(key);
    }
}

// ------------------------------------------------- REC-01..24 model:
// recording policy. Consent is a logged ARTEFACT, never the indicator
// (REC-03). Audio is a separate default-OFF dimension (REC-06). The
// host-side stop can never be overridden by a mandate (REC-08).
// Retention is finite; "indefinite" is not representable (REC-14).

public sealed record ConsentArtefact(
    string RecordingId, string SessionId, string InitiatedBy, bool InitiatorIsAgent,
    string HostConsentedBy, string OperatorConsentedBy, string Method,
    DateTimeOffset AtUtc, bool AudioIncluded, string Purpose, string? PolicyId);

public sealed record RecordingRequest(
    string ScopeKind, bool AudioRequested, bool Mandated, bool DeviceIsPersonalOrByod,
    bool ByodRecordingEnabledByOwner, bool InitiatedByAgent, bool AgentRecordingAllowedByHumanPolicy);

public static class RecordingPolicy
{
    public static PolicyVerdict CanStart(RecordingRequest r, ConsentArtefact? artefact, PolicyBundle? bundle)
    {
        if (bundle is { DisableRecording: true })
            return new PolicyVerdict(false, "recording is disabled by policy for this group/device (REC-13)");
        if (artefact is null)
            return new PolicyVerdict(false, "no consent artefact — recording may not start (REC-01/REC-04)");
        if (string.IsNullOrWhiteSpace(artefact.HostConsentedBy) || string.IsNullOrWhiteSpace(artefact.OperatorConsentedBy))
            return new PolicyVerdict(false, "all-party consent artefact incomplete (REC-01)");
        if (r.AudioRequested && !artefact.AudioIncluded)
            return new PolicyVerdict(false, "audio was not separately consented — video-only at most (REC-06)");
        if (r.ScopeKind == "personal" && r.Mandated)
            return new PolicyVerdict(false, "mandated recording does not exist in personal scope (REC-09)");
        if (r.DeviceIsPersonalOrByod && r.Mandated && !r.ByodRecordingEnabledByOwner)
            return new PolicyVerdict(false, "company mandate cannot record a personal/BYOD device without the owner's specific enablement (REC-10)");
        if (r.InitiatedByAgent && !r.AgentRecordingAllowedByHumanPolicy)
            return new PolicyVerdict(false, "agent-initiated recording requires a human-set policy authorising agent recording (REC-19)");
        return new PolicyVerdict(true, "recording permitted: consent artefact present and policy satisfied");
    }

    /// <summary>REC-08: returns the recording state after a host stop. A
    /// mandate may define the SESSION consequence; it may never keep the
    /// recording running.</summary>
    public static string ApplyHostStopRecording(bool mandated) => "recording_stopped";

    public const string RedactionHonestyLabel = "auto-redacted — may still contain personal data; review before sharing"; // REC-18

    /// <summary>REC-14: finite retention only. Days must be a positive,
    /// finite number; the indefinite sentinel (-1 / 0) refuses.</summary>
    public static PolicyVerdict ValidateRetentionDays(int days) =>
        days <= 0
            ? new PolicyVerdict(false, "retention must be a finite positive period — 'indefinite' is not a selectable value (REC-14)")
            : new PolicyVerdict(true, "retention accepted");

    /// <summary>REC-24: standing-mandate notice decays: re-confirmation is
    /// due after 90 days, and immediately on any policy change.</summary>
    public static bool ReconfirmationDue(DateTimeOffset lastNoticeUtc, bool policyChanged, DateTimeOffset now) =>
        policyChanged || now - lastNoticeUtc > TimeSpan.FromDays(90);
}

/// <summary>REC-11: monitoring-notice artefacts (CT/NY/DE regimes are
/// different mechanics; the store records WHICH artefact, for whom,
/// when, and its acknowledgment — templates are marked for counsel
/// review and are never represented as legally sufficient).</summary>
public sealed record NoticeArtefact(string Regime, string TextVersion, string RecipientUserId,
    DateTimeOffset DeliveredUtc, DateTimeOffset? AcknowledgedUtc, string CounselReviewMarker);

public sealed class NoticeArtefactStore
{
    private readonly List<NoticeArtefact> _items = new();
    public void Record(NoticeArtefact a)
    {
        if (a.CounselReviewMarker != "have counsel review before use")
            throw new InvalidOperationException("notice templates must carry the counsel-review marker (REC-11)");
        _items.Add(a);
    }
    public IReadOnlyList<NoticeArtefact> For(string userId) => _items.Where(i => i.RecipientUserId == userId).ToList();
    /// <summary>REC-12 proportionality pack: the checklist must EXIST and
    /// cannot be skipped silently — enabling without it is refused here;
    /// whether the shipped product hard-blocks is the counsel decision
    /// recorded in the ledger (track 2 §g item 6).</summary>
    public static PolicyVerdict CheckProportionalityPack(bool purposeStated, bool lawfulBasisSelected, bool dpiaOrReasonPresent, bool consultationStatusRecorded, bool barbulescuChecklistComplete) =>
        purposeStated && lawfulBasisSelected && dpiaOrReasonPresent && consultationStatusRecorded && barbulescuChecklistComplete
            ? new PolicyVerdict(true, "proportionality pack complete (REC-12)")
            : new PolicyVerdict(false, "proportionality pack incomplete — mandated recording may not be enabled silently (REC-12)");
}

// ------------------------------------------------- DIR-21 / ADIR-27:
// OIDC sign-in against the org's own IdP, proven against a LOCAL MOCK
// IdP only. Validator posture mirrors the hub lane's: https issuers,
// PKCE S256, email_verified required. Local hub credentials remain the
// fallback where no IdP exists (accounts model) — modelled by
// SsoLockoutGuard's fallback-verified requirement.

public sealed record OidcConfig(string Issuer, string ClientId, string RedirectUri, bool RequirePkceS256, bool RequireEmailVerified);

public static class OidcConfigValidator
{
    public static PolicyVerdict Validate(OidcConfig c)
    {
        if (!c.Issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return new PolicyVerdict(false, "OIDC issuer must be https — refused");
        if (!c.RequirePkceS256) return new PolicyVerdict(false, "PKCE S256 is required — refused");
        if (!c.RequireEmailVerified) return new PolicyVerdict(false, "email_verified is required — refused");
        if (string.IsNullOrWhiteSpace(c.ClientId)) return new PolicyVerdict(false, "client id missing — refused");
        return new PolicyVerdict(true, "OIDC configuration accepted");
    }
}

public static class Pkce
{
    public static string NewVerifier() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string ChallengeS256(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>A local, in-process mock IdP. It issues HMAC-signed ID tokens
/// for test subjects only; it is not connected to any real identity
/// provider and cannot sign anyone in anywhere else.</summary>
public sealed class MockIdp
{
    private readonly byte[] _signingSecret = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, (string CodeChallenge, string Nonce, string Subject, string Email, bool EmailVerified)> _codes = new();
    public string Issuer { get; }
    public MockIdp(string issuer) => Issuer = issuer;

    public string BeginAuthorize(string subject, string email, bool emailVerified, string codeChallenge, string nonce)
    {
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _codes[code] = (codeChallenge, nonce, subject, email, emailVerified);
        return code;
    }

    public string ExchangeCode(string code, string codeVerifier, string clientId)
    {
        if (!_codes.Remove(code, out var grant)) throw new InvalidOperationException("unknown or replayed authorization code");
        if (!EntUtil.FixedEq(Pkce.ChallengeS256(codeVerifier), grant.CodeChallenge))
            throw new InvalidOperationException("PKCE verification failed");
        var header = B64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        var payloadObj = new
        {
            iss = Issuer, sub = grant.Subject, aud = clientId, exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = grant.Nonce, email = grant.Email, email_verified = grant.EmailVerified
        };
        var payload = B64Url(JsonSerializer.Serialize(payloadObj));
        var sig = B64Url(Convert.ToBase64String(HMACSHA256.HashData(_signingSecret, Encoding.ASCII.GetBytes(header + "." + payload))));
        return $"{header}.{payload}.{sig}";
    }

    public bool VerifySignature(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return false;
        var expected = B64Url(Convert.ToBase64String(HMACSHA256.HashData(_signingSecret, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]))));
        return EntUtil.FixedEq(expected, parts[2]);
    }

    private static string B64Url(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed class OidcClient
{
    private readonly OidcConfig _config; private readonly MockIdp _idp;
    public OidcClient(OidcConfig config, MockIdp idp)
    {
        var v = OidcConfigValidator.Validate(config);
        if (!v.Allowed) throw new InvalidOperationException(v.Reason);
        _config = config; _idp = idp;
    }

    public sealed record SignInResult(bool Ok, string? Subject, string? Email, string Reason);

    public SignInResult CompleteSignIn(string idToken, string expectedNonce, DateTimeOffset now)
    {
        if (!_idp.VerifySignature(idToken)) return new SignInResult(false, null, null, "ID token signature invalid — refused");
        var parts = idToken.Split('.');
        string payloadJson;
        try
        {
            var b64 = parts[1].Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }
        catch { return new SignInResult(false, null, null, "ID token malformed — refused"); }
        return OidcClaims.Validate(payloadJson, _config, expectedNonce, now, "signed in via org IdP (mock)");
    }
}

/// <summary>The claim discipline shared by the mock client and the
/// real RS256 client (W11 / R-21): ONE validator, so the two legs
/// can never drift apart on what a valid ID token is. Signature
/// verification is each client's own job and runs BEFORE this.</summary>
public static class OidcClaims
{
    public static OidcClient.SignInResult Validate(string payloadJson, OidcConfig config,
        string expectedNonce, DateTimeOffset now, string successReason)
    {
        // bd-shared-sec-2/F7: every claim read is TOTAL -- a
        // missing or mistyped claim is a named REFUSAL, never an
        // exception escaping validation (GetProperty threw
        // KeyNotFoundException; GetString/GetInt64 throw on
        // wrong-typed values). aud may be a string OR an array
        // (OIDC Core); iat/nbf are checked with a 5-minute skew
        // allowance when present, and iat is REQUIRED (a token
        // with no issued-at cannot be freshness-judged).
        JsonDocument doc;
        try { doc = JsonDocument.Parse(payloadJson); }
        catch { return new OidcClient.SignInResult(false, null, null, "ID token payload is not JSON — refused"); }
        using var _doc = doc;
        var root = doc.RootElement;
        string? Claim(string name) =>
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;
        long? ClaimInt(string name) =>
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n)
                ? n : null;
        if (Claim("iss") != config.Issuer) return new OidcClient.SignInResult(false, null, null, "issuer mismatch or missing — refused");
        var audOk = false;
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("aud", out var aud))
        {
            if (aud.ValueKind == JsonValueKind.String) audOk = aud.GetString() == config.ClientId;
            else if (aud.ValueKind == JsonValueKind.Array)
                audOk = aud.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && a.GetString() == config.ClientId);
        }
        if (!audOk) return new OidcClient.SignInResult(false, null, null, "audience mismatch or missing — refused");
        var nowSec = now.ToUnixTimeSeconds();
        const long Skew = 300;
        if (ClaimInt("exp") is not { } exp) return new OidcClient.SignInResult(false, null, null, "exp claim missing or not a number — refused");
        if (exp < nowSec) return new OidcClient.SignInResult(false, null, null, "ID token expired — refused");
        if (ClaimInt("iat") is not { } iat) return new OidcClient.SignInResult(false, null, null, "iat claim missing or not a number — refused (a token with no issued-at cannot be freshness-judged)");
        if (iat > nowSec + Skew) return new OidcClient.SignInResult(false, null, null, "ID token issued in the future — refused");
        if (ClaimInt("nbf") is { } nbf && nbf > nowSec + Skew) return new OidcClient.SignInResult(false, null, null, "ID token not yet valid (nbf) — refused");
        if (Claim("nonce") != expectedNonce) return new OidcClient.SignInResult(false, null, null, "nonce mismatch or missing — refused");
        if (config.RequireEmailVerified &&
            !(root.ValueKind == JsonValueKind.Object && root.TryGetProperty("email_verified", out var ev) &&
              ev.ValueKind == JsonValueKind.True))
            return new OidcClient.SignInResult(false, null, null, "email_verified is not true — refused");
        if (Claim("sub") is null) return new OidcClient.SignInResult(false, null, null, "sub claim missing — refused");
        return new OidcClient.SignInResult(true, Claim("sub"), Claim("email"), successReason);
    }
}

// ------------------------------------------------- W11 / R-21:
// REAL OIDC — discovery, JWKS and RS256 ID-token validation
// against the org's own IdP. The pre-W11 client was welded to the
// in-process MockIdp (HMAC, a shared secret no real IdP has): the
// "proof-recording shape only", as the W3 winsec lane named it.
// This leg speaks the actual protocol: it fetches the issuer's
// discovery document, requires the document's issuer to EQUAL
// the configured issuer, fetches the JWKS from the document's own
// jwks_uri, and verifies RS256 signatures with the RSA key the
// token's kid names. alg is PINNED to RS256 — a token asking for
// "none" or HS256 (the alg-confusion shape, where the public key
// gets reused as an HMAC secret) refuses before any key is
// touched. HTTP is an injectable fetch delegate so the whole leg
// is testable offline; production passes an HttpClient fetch.
// The browser hand-off (the org's own sign-in page, D4 shape) is
// the caller's surface: this client produces the authorization
// URL and consumes the returned code — ACP never sees, types, or
// stores the user's IdP credential, exactly as before.

/// <summary>The subset of the discovery document ACP depends on,
/// parsed totally: a missing or mistyped member refuses.</summary>
public sealed record OidcDiscovery(string Issuer, string AuthorizationEndpoint, string TokenEndpoint, string JwksUri)
{
    public static (OidcDiscovery? Discovery, string Reason) Parse(string json, string expectedIssuer)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch { return (null, "discovery document is not JSON — refused"); }
        using var _ = doc;
        var root = doc.RootElement;
        string? Str(string name) =>
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;
        var issuer = Str("issuer");
        if (issuer is null) return (null, "discovery document carries no issuer — refused");
        if (!string.Equals(issuer, expectedIssuer, StringComparison.Ordinal))
            return (null, $"discovery issuer '{issuer}' does not equal the configured issuer '{expectedIssuer}' — refused (a discovery document served for another issuer is not evidence about this one)");
        var auth = Str("authorization_endpoint");
        var token = Str("token_endpoint");
        var jwks = Str("jwks_uri");
        if (auth is null || token is null || jwks is null)
            return (null, "discovery document is missing authorization_endpoint, token_endpoint, or jwks_uri — refused");
        foreach (var (name, url) in new[] { ("authorization_endpoint", auth), ("token_endpoint", token), ("jwks_uri", jwks) })
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return (null, $"discovery {name} '{url}' is not https — refused");
        return (new OidcDiscovery(issuer, auth, token, jwks), "discovery accepted");
    }
}

/// <summary>An RSA key set from a JWKS document. Non-RSA keys are
/// skipped by shape (this client verifies RS256 only); a key with
/// no kid can never be selected, because selection is by kid.</summary>
public sealed class JwksKeySet
{
    private readonly Dictionary<string, System.Security.Cryptography.RSAParameters> _byKid = new(StringComparer.Ordinal);

    public int Count => _byKid.Count;

    public static (JwksKeySet? Keys, string Reason) Parse(string json)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch { return (null, "JWKS document is not JSON — refused"); }
        using var _ = doc;
        var set = new JwksKeySet();
        if (doc.RootElement.ValueKind != JsonValueKind.Object ||
            !doc.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
            return (null, "JWKS document carries no keys array — refused");
        foreach (var key in keys.EnumerateArray())
        {
            string? Str(string name) =>
                key.ValueKind == JsonValueKind.Object && key.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                    ? v.GetString() : null;
            if (Str("kty") != "RSA") continue;
            var kid = Str("kid"); var n = Str("n"); var e = Str("e");
            if (kid is null || n is null || e is null) continue;
            try
            {
                set._byKid[kid] = new System.Security.Cryptography.RSAParameters
                {
                    Modulus = Base64UrlDecode(n),
                    Exponent = Base64UrlDecode(e),
                };
            }
            catch { /* an undecodable key is skipped, never half-imported */ }
        }
        return set.Count == 0
            ? (null, "JWKS document carries no usable RSA keys — refused")
            : (set, $"JWKS accepted ({set.Count} RSA key(s))");
    }

    public bool TryGet(string kid, out System.Security.Cryptography.RSAParameters parameters) =>
        _byKid.TryGetValue(kid, out parameters);

    internal static byte[] Base64UrlDecode(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
        return Convert.FromBase64String(b64);
    }
}

public sealed class RealOidcClient
{
    private readonly OidcConfig _config;
    private readonly Func<string, Task<string>> _getJson;
    private readonly Func<string, string, Task<string>> _postForm;

    /// <param name="getJson">GET a URL, return the body. Null =
    /// a real HttpClient fetch (production).</param>
    /// <param name="postForm">POST a form body to a URL, return
    /// the response body. Null = a real HttpClient form post.</param>
    public RealOidcClient(OidcConfig config,
        Func<string, Task<string>>? getJson = null,
        Func<string, string, Task<string>>? postForm = null)
    {
        var v = OidcConfigValidator.Validate(config);
        if (!v.Allowed) throw new InvalidOperationException(v.Reason);
        _config = config;
        _getJson = getJson ?? DefaultGet;
        _postForm = postForm ?? DefaultPostForm;
    }

    private static readonly System.Net.Http.HttpClient Http = new();

    private static async Task<string> DefaultGet(string url) =>
        await Http.GetStringAsync(url).ConfigureAwait(false);

    private static async Task<string> DefaultPostForm(string url, string formBody)
    {
        using var content = new System.Net.Http.StringContent(
            formBody, Encoding.UTF8, "application/x-www-form-urlencoded");
        using var response = await Http.PostAsync(url, content).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    public string DiscoveryUrl => _config.Issuer.TrimEnd('/') + "/.well-known/openid-configuration";

    public async Task<(OidcDiscovery? Discovery, string Reason)> DiscoverAsync()
    {
        string json;
        try { json = await _getJson(DiscoveryUrl).ConfigureAwait(false); }
        catch (Exception ex) { return (null, $"discovery fetch failed ({ex.GetType().Name}) — refused"); }
        return OidcDiscovery.Parse(json, _config.Issuer);
    }

    public async Task<(JwksKeySet? Keys, string Reason)> FetchKeysAsync(OidcDiscovery discovery)
    {
        string json;
        try { json = await _getJson(discovery.JwksUri).ConfigureAwait(false); }
        catch (Exception ex) { return (null, $"JWKS fetch failed ({ex.GetType().Name}) — refused"); }
        return JwksKeySet.Parse(json);
    }

    /// <summary>The authorization URL the user's browser is sent
    /// to (the org's own page — D4). PKCE S256 always; state and
    /// nonce are the caller's freshly minted values.</summary>
    public string BuildAuthorizationUrl(OidcDiscovery discovery, string state, string nonce, string codeChallengeS256)
    {
        string Q(string s) => Uri.EscapeDataString(s);
        return $"{discovery.AuthorizationEndpoint}?response_type=code" +
            $"&client_id={Q(_config.ClientId)}&redirect_uri={Q(_config.RedirectUri)}" +
            $"&scope=openid%20email%20profile&state={Q(state)}&nonce={Q(nonce)}" +
            $"&code_challenge={Q(codeChallengeS256)}&code_challenge_method=S256";
    }

    /// <summary>Exchange the returned code at the token endpoint
    /// and validate the ID token end-to-end (signature via the
    /// discovery-pinned JWKS, then the shared claim discipline).</summary>
    public async Task<OidcClient.SignInResult> ExchangeAndValidateAsync(
        OidcDiscovery discovery, string code, string codeVerifier, string expectedNonce, DateTimeOffset now)
    {
        string Q(string s) => Uri.EscapeDataString(s);
        var form = $"grant_type=authorization_code&code={Q(code)}" +
            $"&redirect_uri={Q(_config.RedirectUri)}&client_id={Q(_config.ClientId)}" +
            $"&code_verifier={Q(codeVerifier)}";
        string tokenJson;
        try { tokenJson = await _postForm(discovery.TokenEndpoint, form).ConfigureAwait(false); }
        catch (Exception ex) { return new OidcClient.SignInResult(false, null, null, $"token exchange failed ({ex.GetType().Name}) — refused"); }
        string? idToken;
        try
        {
            using var doc = JsonDocument.Parse(tokenJson);
            idToken = doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("id_token", out var t) && t.ValueKind == JsonValueKind.String
                ? t.GetString() : null;
        }
        catch { return new OidcClient.SignInResult(false, null, null, "token response is not JSON — refused"); }
        if (idToken is null) return new OidcClient.SignInResult(false, null, null, "token response carries no id_token — refused");
        var (keys, keyReason) = await FetchKeysAsync(discovery).ConfigureAwait(false);
        if (keys is null) return new OidcClient.SignInResult(false, null, null, keyReason);
        return ValidateIdToken(idToken, keys, expectedNonce, now);
    }

    /// <summary>Validate one ID token against a fetched JWKS:
    /// alg pinned to RS256, signature verified under the kid's
    /// RSA key, then the shared claim validator. Every failure is
    /// a named refusal.</summary>
    public OidcClient.SignInResult ValidateIdToken(string idToken, JwksKeySet keys, string expectedNonce, DateTimeOffset now)
    {
        var parts = idToken.Split('.');
        if (parts.Length != 3) return new OidcClient.SignInResult(false, null, null, "ID token malformed — refused");
        string headerJson, payloadJson;
        try
        {
            headerJson = Encoding.UTF8.GetString(JwksKeySet.Base64UrlDecode(parts[0]));
            payloadJson = Encoding.UTF8.GetString(JwksKeySet.Base64UrlDecode(parts[1]));
        }
        catch { return new OidcClient.SignInResult(false, null, null, "ID token malformed — refused"); }
        string? alg, kid;
        try
        {
            using var doc = JsonDocument.Parse(headerJson);
            var root = doc.RootElement;
            alg = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("alg", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
            kid = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("kid", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
        }
        catch { return new OidcClient.SignInResult(false, null, null, "ID token header is not JSON — refused"); }
        // alg PINNED: anything but RS256 refuses before a key is
        // touched — "none" and the HS256 public-key-confusion
        // shape die here, by construction.
        if (alg != "RS256")
            return new OidcClient.SignInResult(false, null, null, $"ID token alg '{alg ?? "(missing)"}' is not RS256 — refused (algorithm is pinned; substitution is refused, never negotiated)");
        if (kid is null || !keys.TryGet(kid, out var rsaParams))
            return new OidcClient.SignInResult(false, null, null, $"ID token kid '{kid ?? "(missing)"}' names no key in the issuer's JWKS — refused");
        bool signatureOk;
        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(rsaParams);
            signatureOk = rsa.VerifyData(
                Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]),
                JwksKeySet.Base64UrlDecode(parts[2]),
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        }
        catch { return new OidcClient.SignInResult(false, null, null, "ID token signature could not be verified — refused"); }
        if (!signatureOk) return new OidcClient.SignInResult(false, null, null, "ID token signature invalid — refused");
        return OidcClaims.Validate(payloadJson, _config, expectedNonce, now,
            $"signed in via org IdP ({_config.Issuer}, RS256 verified against the issuer's JWKS)");
    }
}

/// <summary>ADIR-27 lockout safety: mandatory SSO cannot be enabled until
/// a test login has passed AND a non-SSO fallback admin path verifies.</summary>
public sealed class SsoLockoutGuard
{
    // bd-shared-sec-2/F7: these were public SETTABLE bools --
    // any caller could simply set both true and enforce
    // mandatory SSO with no test login and no fallback ever
    // proven. The flags now move only through the Record*
    // methods, which demand the proof artefact (the signed-in
    // subject for a test login; the fallback admin's id for the
    // fallback verification) and keep it for inspection.
    public bool TestLoginPassed { get; private set; }
    public bool FallbackAdminVerified { get; private set; }
    public string? TestLoginSubject { get; private set; }
    public string? FallbackAdminId { get; private set; }

    /// <summary>Record a REAL successful test sign-in: the
    /// subject comes from the completed OidcClient result, so
    /// the flag cannot stand without a sign-in having happened
    /// in this process.</summary>
    public void RecordTestLogin(OidcClient.SignInResult result)
    {
        if (result is null || !result.Ok || string.IsNullOrWhiteSpace(result.Subject)) return;
        TestLoginPassed = true; TestLoginSubject = result.Subject;
    }

    /// <summary>Record a verified non-SSO fallback admin login
    /// (the admin id that actually authenticated).</summary>
    public void RecordFallbackAdminVerified(string adminUserId)
    {
        if (string.IsNullOrWhiteSpace(adminUserId)) return;
        FallbackAdminVerified = true; FallbackAdminId = adminUserId.Trim();
    }
    public PolicyVerdict CanEnforceMandatorySso() =>
        TestLoginPassed && FallbackAdminVerified
            ? new PolicyVerdict(true, "mandatory SSO may be enforced: test login passed and fallback admin verified")
            : new PolicyVerdict(false, "mandatory SSO refused: test-login and a verified non-SSO fallback admin path are both required first (ADIR-27)");
}

// ------------------------------------------------- DIR-51 / DIR-52 /
// ADIR-28: SCIM-shaped inbound directory sync against a local mock
// directory. Events carry the directory's scope binding; an event
// naming a user in a DIFFERENT scope than its binding refuses
// (directory-sync injection defense). Deactivation drives the D14
// offboarding path; removing the last admin suspends + alerts instead.

public sealed record DirectoryEvent(string ExternalScopeBinding, string ScopeId, string UserId,
    string DisplayName, string Action, string ExternalId); // Action: create | suspend | remove

public sealed class DirectorySyncService
{
    private readonly RosterService _roster; private readonly ChainedAuditLog _audit; private readonly AlertCenter _alerts;
    public DirectorySyncService(RosterService roster, ChainedAuditLog audit, AlertCenter alerts) { _roster = roster; _audit = audit; _alerts = alerts; }

    /// <summary>bd-shared-sec-2/F6: the AUTHENTICATED entry
    /// point. The scope is taken from the connector's
    /// registration (authenticatedConnectorScope -- the scope the
    /// connector's credential was issued for), never from the
    /// event: both event fields must AGREE with it, so an event
    /// submitter setting both fields consistently gains nothing.
    /// Removals pass stepUpPerformed through to the roster --
    /// the step-up is the caller's performed proof, not an
    /// assertion this service makes on its behalf.</summary>
    public PolicyVerdict ApplyAuthenticated(DirectoryEvent e, string actorAdminUserId, DateTimeOffset now,
        string authenticatedConnectorScope, bool stepUpPerformed)
    {
        if (!string.Equals(e.ScopeId, authenticatedConnectorScope, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(e.ExternalScopeBinding, authenticatedConnectorScope, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("directory_sync_refused", "directory-sync", $"cross-scope event refused: connector scope={authenticatedConnectorScope} binding={e.ExternalScopeBinding} scope={e.ScopeId} user={e.UserId}", now);
            return new PolicyVerdict(false, $"directory event names scope '{e.ScopeId}' (binding '{e.ExternalScopeBinding}') but the authenticated connector is registered for scope '{authenticatedConnectorScope}' — refused (the scope comes from the connector registration, not the event)");
        }
        return ApplyCore(e, actorAdminUserId, now, stepUpPerformed);
    }

    public PolicyVerdict Apply(DirectoryEvent e, string actorAdminUserId, DateTimeOffset now)
        => ApplyCore(e, actorAdminUserId, now, stepUpPerformed: false);

    private PolicyVerdict ApplyCore(DirectoryEvent e, string actorAdminUserId, DateTimeOffset now, bool stepUpPerformed)
    {
        // Injection defense (legacy shape, kept for the
        // unauthenticated entry point): the event's binding must
        // match the scope it names. bd-shared-sec-2/F6: this
        // compares two fields of the same untrusted event, so it
        // is a consistency check only -- ApplyAuthenticated is
        // the entry point whose scope is trustworthy.
        if (e.ExternalScopeBinding != e.ScopeId)
        {
            _audit.Append("directory_sync_refused", "directory-sync", $"cross-scope event refused: binding={e.ExternalScopeBinding} scope={e.ScopeId} user={e.UserId}", now);
            return new PolicyVerdict(false, "directory event scope binding mismatch — refused (cross-scope injection defense)");
        }
        if (_roster.GetScope(e.ScopeId) is null) return new PolicyVerdict(false, $"unknown scope '{e.ScopeId}' — refused");
        switch (e.Action)
        {
            case "create":
            {
                var u = _roster.CreateUser(e.UserId, e.ScopeId, e.DisplayName, "human");
                if (u is null) return new PolicyVerdict(false, "create refused by roster (duplicate or invalid)");
                _audit.Append("directory_sync_create", "directory-sync", $"user={e.UserId} scope={e.ScopeId} external={e.ExternalId}", now);
                return new PolicyVerdict(true, "user created from directory event");
            }
            case "suspend":
            {
                if (!_roster.SetUserSuspended(e.ScopeId, e.UserId, true)) return new PolicyVerdict(false, "suspend refused: unknown user");
                _audit.Append("directory_sync_suspend", "directory-sync", $"user={e.UserId} scope={e.ScopeId}", now);
                return new PolicyVerdict(true, "user suspended from directory event");
            }
            case "remove":
            {
                // ADIR-28 meets the D38 S2-WIN F1 guard: sync attempting to
                // remove the last admin must not remove them. The dossier's
                // "suspends-and-alerts instead" is attempted first — but the
                // roster REFUSES to suspend the sole LIVE admin too (that
                // suspension would strand the scope identically). When the
                // suspension refuses, the sync refuses the removal, alerts,
                // and names the only remaining path: break-glass (BAD-19/32).
                // Recorded as a cross-directive reconciliation in the ledger.
                var admins = _roster.CompanyAdmins(e.ScopeId);
                if (admins.Count == 1 && admins.Contains(e.UserId))
                {
                    if (_roster.SetUserSuspended(e.ScopeId, e.UserId, true))
                    {
                        _alerts.Raise("sprawl", $"directory sync tried to remove the last company admin {e.UserId}; suspended + alerted instead (ADIR-28)", now);
                        _audit.Append("directory_sync_last_admin_suspended", "directory-sync", $"user={e.UserId} scope={e.ScopeId}", now);
                        return new PolicyVerdict(true, "last admin suspended + alerted instead of removed (last-admin guard)");
                    }
                    _alerts.Raise("sprawl", $"directory sync tried to remove the sole live company admin {e.UserId}; refused + alerted — removal is possible only via break-glass (ADIR-28 x S2-WIN F1 guard, BAD-19/32)", now);
                    _audit.Append("directory_sync_last_admin_refused", "directory-sync", $"user={e.UserId} scope={e.ScopeId}", now);
                    return new PolicyVerdict(false, "directory removal of the sole live company admin refused: the roster guard also refuses that suspension; the only path is break-glass (BAD-19/32)");
                }
                // bd-shared-sec-2/F6: step-up is the caller's
                // PERFORMED proof, threaded through -- it was
                // previously hardcoded `stepUp: true`, so the
                // roster's fellow-admin step-up guard (D26) never
                // actually stood on this path.
                var blast = _roster.RemoveUser(e.ScopeId, e.UserId, actorAdminUserId, stepUp: stepUpPerformed);
                if (blast is null) return new PolicyVerdict(false, "offboarding refused by roster guards");
                _audit.Append("directory_sync_offboard", "directory-sync", $"user={e.UserId} scope={e.ScopeId} blast={blast.UserGroupSeatIds.Count} seats", now);
                _alerts.Raise("offboarding", $"directory removal offboarded {e.UserId} in scope {e.ScopeId} (D14 path)", now);
                return new PolicyVerdict(true, "user offboarded via D14 path from directory removal");
            }
            default:
                return new PolicyVerdict(false, $"unknown directory action '{e.Action}' — refused");
        }
    }
}

// ------------------------------------------------- DIR-57 / ADIR-23 /
// ADIR-24 / ADIR-30: alerting. Named event classes only; delivery is
// local (in-product list) + signed webhook payload model. A broken
// delivery channel surfaces as its own alert record.

public sealed record Alert(string EventClass, string Detail, DateTimeOffset AtUtc, bool IsDeliveryFailure = false);

public sealed class AlertCenter
{
    public static readonly IReadOnlySet<string> EventClasses = new HashSet<string>
        { "stop", "offboarding", "policy_refusal", "verification_failure", "break_glass_use", "recording_review_playback", "sprawl", "failed_pairing",
          // RMM-01 extension (2026-11-21): DIR-57's centre extended from
          // ACP-security events to endpoint-health events. Health alert
          // lifecycle lives in Acp.Shared.Monitoring.HealthAlertCentre;
          // raises mirror here so the alert centre stays ONE surface.
          "endpoint_health", "warranty" };
    private readonly List<Alert> _alerts = new();
    public IReadOnlyList<Alert> Alerts => _alerts.ToList();
    public Alert Raise(string eventClass, string detail, DateTimeOffset now)
    {
        if (!EventClasses.Contains(eventClass)) throw new ArgumentException($"unknown alert class '{eventClass}'", nameof(eventClass));
        var a = new Alert(eventClass, detail, now);
        _alerts.Add(a);
        return a;
    }
    /// <summary>ADIR-30: webhook payloads are metadata-only and signed;
    /// the signing secret is shown once at creation and never stored
    /// in the payload.</summary>
    public static string SignedWebhookPayload(Alert a, string signingSecret)
    {
        // The signed body travels as a STRING: re-serializing a parsed
        // JsonElement is not byte-stable, and a signature over unstable
        // bytes would fail verification at honest receivers.
        var body = JsonSerializer.Serialize(new { eventClass = a.EventClass, detail = a.Detail, atUtc = a.AtUtc });
        var sig = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingSecret), Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        return JsonSerializer.Serialize(new { body, signature = sig });
    }
    public static bool VerifyWebhookPayload(string payloadJson, string signingSecret)
    {
        using var doc = JsonDocument.Parse(payloadJson);
        var body = doc.RootElement.GetProperty("body").GetString() ?? "";
        var expected = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingSecret), Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        return EntUtil.FixedEq(expected, doc.RootElement.GetProperty("signature").GetString() ?? "");
    }
    /// <summary>ADIR-24 sprawl guardrails: warn at 3 company admins
    /// (Entra's fewer-than-5 discipline), stale admins (90 days),
    /// dormant reviewer grants, overdue break-glass test.</summary>
    public IReadOnlyList<string> EvaluateSprawl(int companyAdminCount, int staleAdminCount, int dormantReviewerGrants, bool breakGlassTestOverdue, DateTimeOffset now)
    {
        var cards = new List<string>();
        if (companyAdminCount >= 3) { cards.Add($"company admins at {companyAdminCount} (warn at 3)"); Raise("sprawl", cards[^1], now); }
        if (staleAdminCount > 0) { cards.Add($"{staleAdminCount} stale admin(s) with no activity in 90 days"); Raise("sprawl", cards[^1], now); }
        if (dormantReviewerGrants > 0) { cards.Add($"{dormantReviewerGrants} dormant recording-reviewer grant(s)"); Raise("sprawl", cards[^1], now); }
        if (breakGlassTestOverdue) { cards.Add("break-glass test overdue (>90 days)"); Raise("sprawl", cards[^1], now); }
        return cards;
    }
}

// ------------------------------------------------- DIR-53 / ADIR-34 /
// BAD-19 / BAD-32: company break-glass. Sealed, dual-control,
// time-boxed, independent of the hub, and USELESS SILENTLY: the only
// path to a grant appends loud chained-audit entries and raises the
// highest-severity alert BEFORE the grant exists. Use (or a drill)
// triggers mandatory rotation; the grant cannot erase audit history
// and cannot mint long-lived keys (no such API exists here).

public sealed class BreakGlassService
{
    public sealed record Grant(string Id, string ScopeId, string Reason, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, bool IsDrill);
    private readonly ChainedAuditLog _audit; private readonly AlertCenter _alerts;
    private readonly Dictionary<string, string> _holderSecretHashes = new(); // holderId -> stored verifier (see SealHolder)
    // bd-shared-sec-2/F12: failed-use bookkeeping. Failures were
    // SILENT (Use returned null with no audit, no alert, no
    // counter) and holder secrets were stored as fast unsalted
    // SHA-256. Now: every failed attempt is chained + alerted
    // with its reason, attempts are counted per holder pair, and
    // MaxFailedAttempts consecutive failures lock the service
    // until a holder rotates (Rotate clears the lockout). New
    // seals store a salted PBKDF2 verifier
    // ("pbkdf2$<iterations>$<saltB64>$<hashB64>"); legacy
    // sha256-hex verifiers (SealHolderHash, the Core holder
    // store's shape) still VERIFY, and a successful legacy
    // verification upgrades the stored verifier to PBKDF2 in
    // place (the plaintext is in hand at that moment only).
    public const int MaxFailedAttempts = 5;
    private int _failedAttempts;
    private readonly Dictionary<string, Grant> _grants = new();
    public int FailedAttempts => _failedAttempts;
    public bool LockedOut => _failedAttempts >= MaxFailedAttempts;

    private static string Pbkdf2Store(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            secret, salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        return $"pbkdf2$100000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static bool VerifyStored(string stored, string secret)
    {
        if (stored.StartsWith("pbkdf2$", StringComparison.Ordinal))
        {
            var parts = stored.Split('$');
            if (parts.Length != 4 || !int.TryParse(parts[1], out var iter)) return false;
            byte[] salt, expect;
            try { salt = Convert.FromBase64String(parts[2]); expect = Convert.FromBase64String(parts[3]); }
            catch { return false; }
            var actual = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
                secret, salt, iter, System.Security.Cryptography.HashAlgorithmName.SHA256, expect.Length);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actual, expect);
        }
        return EntUtil.FixedEq(stored, EntUtil.Sha256Hex(secret)); // legacy verifier
    }

    private Grant? FailUse(string scopeId, string holderA, string holderB, string reason, DateTimeOffset now)
    {
        _failedAttempts++;
        _audit.Append("break_glass_use_failed", $"{holderA}+{holderB}",
            $"scope={scopeId} reason={reason} attempts={_failedAttempts} lockout={LockedOut} — a failed break-glass attempt is never silent (bd-shared-sec-2/F12)", now);
        _alerts.Raise("break_glass_use", $"Break-glass FAILED attempt in scope {scopeId} by {holderA}+{holderB}: {reason} (attempt {_failedAttempts}{(LockedOut ? $", LOCKED OUT after {MaxFailedAttempts}" : "")})", now);
        return null;
    }
    // Rotation bookkeeping (hardened in Block H when Rotate gained
    // its product surface): a use/drill puts EVERY holder sealed
    // at that moment on the pending list, and the requirement
    // clears only when each of them has rotated — rotating one of
    // two holders never completed a rotation, and the old
    // single-Rotate-clears-all shape would have let the surface
    // ship exactly that weakness.
    private readonly HashSet<string> _rotationPending = new(StringComparer.OrdinalIgnoreCase);
    public BreakGlassService(ChainedAuditLog audit, AlertCenter alerts) { _audit = audit; _alerts = alerts; }

    public void SealHolder(string holderId, string holderSecret) => _holderSecretHashes[holderId] = Pbkdf2Store(holderSecret);
    /// <summary>Seal from a stored HASH (Block F wiring): the Core's
    /// holder store carries sha256(secret) only, never a secret.</summary>
    public void SealHolderHash(string holderId, string secretSha256Hex)
    {
        if (secretSha256Hex.Length != 64 || !secretSha256Hex.All(c => char.IsDigit(c) || c is >= 'a' and <= 'f'))
            throw new InvalidOperationException("holder seal must be a lowercase sha256 hex hash");
        _holderSecretHashes[holderId] = secretSha256Hex;
    }

    /// <summary>Seal from a STORED VERIFIER (BD-WIN-CORE-3/F4+F11):
    /// accepts the salted PBKDF2 form ("pbkdf2$…") or a legacy
    /// sha256-hex verifier (which a successful Use upgrades in
    /// place). Anything else throws — a malformed verifier must
    /// never silently seal a holder with an unverifiable secret.</summary>
    public void SealHolderVerifier(string holderId, string storedVerifier)
    {
        if (storedVerifier is not null && storedVerifier.StartsWith("pbkdf2$", StringComparison.Ordinal))
        {
            var parts = storedVerifier.Split('$');
            if (parts.Length != 4 || !int.TryParse(parts[1], out _) ||
                !IsBase64(parts[2]) || !IsBase64(parts[3]))
                throw new InvalidOperationException("holder seal is not a well-formed pbkdf2 verifier");
            _holderSecretHashes[holderId] = storedVerifier;
            return;
        }
        SealHolderHash(holderId, storedVerifier ?? "");
    }

    private static bool IsBase64(string s)
    {
        try { _ = Convert.FromBase64String(s); return true; } catch { return false; }
    }

    /// <summary>The stored verifier for a holder (never a secret):
    /// lets the Core's durable holder store persist exactly what
    /// this service verifies against, PBKDF2 upgrades included.</summary>
    public string? StoredVerifier(string holderId) =>
        holderId is not null && _holderSecretHashes.TryGetValue(holderId, out var v) ? v : null;

    /// <summary>Verify a presented secret against a stored verifier
    /// (PBKDF2 or legacy sha256 form), constant-time where the form
    /// allows. Public so the Core holder-store surface applies the
    /// SAME verification as a break-glass Use.</summary>
    public static bool VerifyStoredVerifier(string stored, string secret) =>
        stored is not null && secret is not null && VerifyStored(stored, secret);
    public bool RotationRequired => _rotationPending.Count > 0;

    /// <summary>Restore rotation-pending state from the durable
    /// holder store (Block H D38 fix F1): the pending list is part
    /// of the store, not just of this process — a Core restart
    /// between a use/drill and the rotation must NOT clear the
    /// BAD-32 requirement and resurrect the exposed secrets. Only
    /// ids that are sealed holders right now are restored; a stale
    /// id in the file confers nothing.</summary>
    public void RestoreRotationPending(IEnumerable<string> holderIds)
    {
        foreach (var id in holderIds)
            if (id is not null && _holderSecretHashes.ContainsKey(id))
                _rotationPending.Add(id);
    }

    /// <summary>The holders whose rotation is still owed.</summary>
    public IReadOnlyList<string> RotationPendingHolders =>
        _rotationPending.OrderBy(h => h, StringComparer.Ordinal).ToList();

    public Grant? Use(string scopeId, string holderA, string secretA, string holderB, string secretB, string reason, bool isDrill, DateTimeOffset now)
    {
        // bd-shared-sec-2/F12: EVERY refusal below is audited +
        // alerted through FailUse -- "useless silently" was the
        // design, and silent failure was the defect.
        if (LockedOut) return FailUse(scopeId, holderA, holderB, $"locked out after {MaxFailedAttempts} failed attempts — a holder rotation is required before any further use", now);
        if (RotationRequired) return FailUse(scopeId, holderA, holderB, "rotation from a prior use/drill is still pending — refused until every holder has rotated", now);
        if (holderA == holderB) return FailUse(scopeId, holderA, holderB, "the two holders are the same person — dual control requires two DISTINCT holders", now);
        if (!_holderSecretHashes.TryGetValue(holderA, out var ha) || !VerifyStored(ha, secretA)) return FailUse(scopeId, holderA, holderB, $"holder '{holderA}' is unknown or their secret does not verify", now);
        if (!_holderSecretHashes.TryGetValue(holderB, out var hb) || !VerifyStored(hb, secretB)) return FailUse(scopeId, holderA, holderB, $"holder '{holderB}' is unknown or their secret does not verify", now);
        if (string.IsNullOrWhiteSpace(reason)) return FailUse(scopeId, holderA, holderB, "no reason given — a break-glass use without a stated reason is refused", now);
        _failedAttempts = 0;
        // Legacy-verifier upgrade: a holder who just proved the
        // secret gets a PBKDF2 verifier stored in place of the
        // fast unsalted hash.
        if (!ha.StartsWith("pbkdf2$", StringComparison.Ordinal)) _holderSecretHashes[holderA] = Pbkdf2Store(secretA);
        if (!hb.StartsWith("pbkdf2$", StringComparison.Ordinal)) _holderSecretHashes[holderB] = Pbkdf2Store(secretB);
        // LOUD FIRST: audit + alert are written before the grant exists.
        _audit.Append("break_glass_use", $"{holderA}+{holderB}",
            $"scope={scopeId} drill={isDrill} reason={reason} PROMINENT: break-glass used — all admins alerted; post-use review required", now);
        _alerts.Raise("break_glass_use", $"Break-glass {(isDrill ? "DRILL" : "USE")} in scope {scopeId} by {holderA}+{holderB}: {reason}", now);
        // Use or drill triggers rotation (BAD-32): every holder
        // sealed at this moment owes a fresh secret.
        _rotationPending.UnionWith(_holderSecretHashes.Keys);
        var grant = new Grant(Guid.NewGuid().ToString("N"), scopeId, reason, now, now.AddHours(4), isDrill);
        _grants[grant.Id] = grant;
        return grant;
    }

    public bool GrantValid(Grant g, DateTimeOffset now) =>
        g is not null && _grants.TryGetValue(g.Id, out var standing) && standing == g && now < g.ExpiresUtc;

    /// <summary>bd-shared-sec-2/F12: grant revocation. A grant
    /// was previously valid until expiry with no way to kill
    /// it; Revoke removes it by id and chains the act. Returns
    /// false for an unknown (or already revoked/expired-away)
    /// grant id.</summary>
    public bool RevokeGrant(string grantId, string revokedBy, DateTimeOffset now)
    {
        if (grantId is null || !_grants.Remove(grantId, out var g)) return false;
        _audit.Append("break_glass_grant_revoked", revokedBy,
            $"scope={g.ScopeId} grant={g.Id} drill={g.IsDrill} — grant revoked before expiry", now);
        return true;
    }

    /// <summary>Rotate one holder's secret. The holder leaves the
    /// rotation-pending list; the requirement stands until the
    /// list is empty. Unknown holders throw — a rotation against
    /// a mistyped id must never look like success.</summary>
    public void Rotate(string holderId, string newSecret)
    {
        if (!_holderSecretHashes.ContainsKey(holderId)) throw new InvalidOperationException("unknown break-glass holder");
        _holderSecretHashes[holderId] = Pbkdf2Store(newSecret);
        _rotationPending.Remove(holderId);
        _failedAttempts = 0; // bd-sec-2/F12: rotation is the lockout recovery act
    }
    /// <summary>ADIR-34: a drill is due at least every 90 days.</summary>
    public static bool TestOverdue(DateTimeOffset? lastDrillUtc, DateTimeOffset now) =>
        lastDrillUtc is null || now - lastDrillUtc.Value > TimeSpan.FromDays(90);
}

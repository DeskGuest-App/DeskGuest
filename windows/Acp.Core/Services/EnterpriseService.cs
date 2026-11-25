using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Update;

namespace Acp.Core.Services;

/// <summary>
/// Enterprise wiring (Block F): the Block E model layer, live in
/// the Core. Everything here is reached from the host window over
/// the authenticated agent-IPC channel (CoreRuntime) — the same
/// laptop-UI-only discipline as every other Core act.
///
///  * Policy: a signed bundle (policy-bundle.json) + the org public
///    key (policy-orgkey.txt, base64) in the data dir. Load verifies
///    the signature fail-closed; a swapped or edited policy file
///    refuses at load and can never widen anything. The loaded
///    enforcer gates the update channel (pin/defer REFUSE in
///    UpdateManager.StagePackage via CoreRuntime's gate delegate)
///    and names the transport ceiling.
///  * Audit: the hash-chained ledger persists across Core restarts
///    (enterprise-audit.json, verbatim restore + re-verify). A
///    broken chain at restore is an ALERT, and exports carry the
///    BROKEN verdict in their header — never a silent re-base.
///  * Directory sync: SCIM-shaped events drive the real roster
///    (D14 offboarding end-to-end through the live Core).
///  * Break-glass: dual-control use through this service writes
///    the loud chained-audit entry + alert BEFORE the grant exists
///    (the model's own ordering).
///  * IdP: the mock-IdP leg runs end-to-end locally; the real leg
///    stops at the same sign-in boundary as the mesh rung's D4
///    boundary — ACP never sees or types a real credential.
/// </summary>
public sealed class EnterpriseService
{
    private readonly string _dataDir;
    private readonly RosterService _roster;
    private readonly Func<DateTimeOffset> _now;
    private readonly ISecretProtector? _protector;

    public ChainedAuditLog AuditLog { get; } = new();
    public AlertCenter Alerts { get; } = new();
    public DirectorySyncService DirectorySync { get; }
    public BreakGlassService BreakGlass { get; }
    public PolicyEnforcer? Enforcer { get; private set; }

    /// <summary>True when a policy bundle file is PRESENT but was
    /// refused — missing org key, bad signature, unparseable
    /// (Block H D38 fix F6). This is a different state from "no
    /// bundle": no bundle means the owner's own device, ungated;
    /// a present-but-refused bundle means someone (or some
    /// corruption) supplied policy material that did not verify,
    /// and every gate must fail CLOSED. Before this fix LoadPolicy
    /// nulled the enforcer on refusal and CheckFeature read a null
    /// enforcer as "allowed", so deleting policy-orgkey.txt or
    /// corrupting the bundle silently re-enabled every disabled
    /// feature — TOTAL POLICY CONTROL failed open.</summary>
    public bool PolicyRefused { get; private set; }
    public string PolicyState { get; private set; } = "no policy bundle loaded";
    public ChainVerification RestoreVerdict { get; }

    private MockIdp? _mockIdp;
    private OidcClient? _mockClient;
    private string? _pendingVerifier;
    private string? _pendingNonce;

    /// <param name="protector">BD-WIN-CORE-3/F4+F11: when wired
    /// (production: CoreRuntime's host protector), the break-glass
    /// holder store is SEALED with it — replacing a verifier or
    /// flipping rotationPending in breakglass-holders.json then
    /// requires defeating the protector, not editing a text file.
    /// Verifiers themselves are salted PBKDF2 (never unsalted
    /// SHA-256) whether or not a protector is wired.</param>
    public EnterpriseService(string dataDir, RosterService roster, Func<DateTimeOffset>? now = null,
        ISecretProtector? protector = null)
    {
        _dataDir = dataDir;
        _roster = roster;
        _protector = protector;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        DirectorySync = new DirectorySyncService(roster, AuditLog, Alerts);
        BreakGlass = new BreakGlassService(AuditLog, Alerts);

        var auditPath = Path.Combine(dataDir, "enterprise-audit.json");
        if (File.Exists(auditPath))
        {
            RestoreVerdict = AuditLog.ImportEntriesJson(File.ReadAllText(auditPath));
            if (!RestoreVerdict.Ok)
                Alerts.Raise("verification_failure",
                    $"enterprise audit chain restored BROKEN: {RestoreVerdict.Summary} — exports will carry the BROKEN verdict", _now());
        }
        else RestoreVerdict = new ChainVerification(true, null, "no prior enterprise audit store (genesis)");
        LoadBreakGlassHolders();
        LoadPolicy();
    }

    private string AuditPath => Path.Combine(_dataDir, "enterprise-audit.json");

    /// <summary>BD-WIN-CORE-3/F12(a): named state of the last
    /// audit-chain persistence. A save failure is NOT silent: it
    /// sets this to "BROKEN: …" and raises an alert — the
    /// ManagementPolicyService posture for the same failure.</summary>
    public string ChainPersistenceState { get; private set; } = "ok";

    /// <summary>W45 / DS round-9 Item 3: the install root the Core
    /// advances the pointer anchor marker in on every anchored
    /// append (set by CoreRuntime from CoreOptions.InstallRoot —
    /// the same directory the pointer-signing seed/pin live in,
    /// under the same custody discipline: the Core runs as the
    /// install owner in the console-host shape and as SYSTEM in
    /// the service shape, both of which already write there).
    /// Null = not composed (embedders/tests): no advance is
    /// attempted and AnchorMarkerState says so.</summary>
    public string? AnchorMarkerInstallRoot { get; set; }

    /// <summary>W45: named state of the Core's install-root anchor
    /// marker advance — "advanced:chain_entries=N" when the last
    /// advance landed (proven by re-read), a FAILED state naming
    /// the cause when it did not, "not-composed" when no install
    /// root was supplied. A marker-write failure is THIS state,
    /// never silent; CoreRuntime rides it on the host-state
    /// surface beside the W43 posture-audit states.</summary>
    public string AnchorMarkerState { get; private set; } =
        "not-composed: no install root supplied — the Core does not advance the install-root anchor marker in this composition (W45)";

    /// <summary>W45/W47: advance the install-root anchor marker
    /// to the chain's current (count, head). Called INSIDE the
    /// chain gate from both service-audit append paths, ONLY
    /// after the append's persist has been VERIFIED durable
    /// (SaveChainVerifiedLocked — the persisted store re-read and
    /// matched; W47 (a)): a persist that failed or could not be
    /// verified produces NO advance and the named FAILED state
    /// below, so marker-ahead-of-chain is impossible by
    /// construction. A crash can therefore leave the chain LONGER
    /// than the marker (growth, accepted by the prefix rule) but
    /// never leaves the marker naming an append that is not
    /// durable, and the advance itself is monotonicity-guarded
    /// (PointerAuditAnchor, W47 (b)). Never throws: failure is
    /// the named AnchorMarkerState.</summary>
    private void AdvanceAnchorMarker()
    {
        if (AnchorMarkerInstallRoot is null) return;
        try
        {
            var (_, state) = PointerAuditAnchor.AdvanceInstallRootMarker(
                AnchorMarkerInstallRoot, AuditLog.Entries);
            AnchorMarkerState = state;
        }
        catch (Exception ex)
        {
            AnchorMarkerState =
                $"anchor marker advance FAILED: advancing the install-root anchor marker in '{AnchorMarkerInstallRoot}' threw ({ex.GetType().Name}: {ex.Message}) — Core-armed freshness does not cover the latest append until a later advance or a vouched launcher check succeeds (W45)";
        }
    }

    /// <summary>W43 (F2): the ONE gate every chain save passes
    /// through. The pre-fix SaveChain was unlocked and wrote
    /// through a single shared tmp path (enterprise-audit.json
    /// .tmp): two saves overlapping — composition appends racing
    /// the background services composition itself started — could
    /// interleave on the tmp file, throw, or move an OLDER export
    /// over a newer one, and both saves still reported "ok"
    /// because the export each had taken was valid when taken.
    /// That is the W42 boot-1 shape exactly: the update posture
    /// landed as the chain's last entry, the pointer posture's
    /// append verified in memory, and the persisted chain held
    /// zero "pointer" entries. Now the ordering is EXPLICIT, not
    /// retry-based: saves are totally ordered by this gate, the
    /// export is taken INSIDE the gate at save time (so a save
    /// can never carry a snapshot older than a save that already
    /// completed), each save writes its OWN tmp file, and the
    /// bytes are flushed to disk before the move. The persisted
    /// chain is therefore monotonic: once an entry is in a
    /// completed save, no later save can remove it.</summary>
    private readonly object _chainSaveGate = new();

    /// <summary>W47: the chain gate itself, exposed so a service
    /// appending to THIS chain through another surface (the
    /// pack-compile path in ComplianceService, composed over
    /// Enterprise.AuditLog by CoreRuntime) can take the SAME
    /// gate for its append + persist + marker advance — one
    /// gate, one total order for every anchored advance over
    /// this chain. Monitor locking is re-entrant, so a holder
    /// of this gate may still call SaveChain/PersistChainVerified.</summary>
    public object ChainGate => _chainSaveGate;

    private void SaveChain()
    {
        lock (_chainSaveGate)
        {
            SaveChainLocked();
        }
    }

    /// <summary>W47: persist the chain AND verify the persisted
    /// store — re-read enterprise-audit.json, import it into a
    /// probe log, and require the probe's (count, head) to match
    /// the in-memory chain exactly (the W43 durability discipline:
    /// check the persisted state, never trust a swallowed result).
    /// Returns false — with ChainPersistenceState naming the
    /// failure — when the save failed OR the persisted store does
    /// not match. Callers holding the chain gate may call this
    /// directly (re-entrant).</summary>
    public bool PersistChainVerified()
    {
        lock (_chainSaveGate)
        {
            return SaveChainVerifiedLocked();
        }
    }

    /// <summary>SaveChainVerifiedLocked: as PersistChainVerified,
    /// for a caller already holding the chain gate.</summary>
    private bool SaveChainVerifiedLocked()
    {
        SaveChainLocked();
        if (!ChainPersistenceState.StartsWith("ok", StringComparison.Ordinal))
            return false;
        try
        {
            if (!File.Exists(AuditPath)) throw new InvalidOperationException("the persisted audit store does not exist after save");
            var probe = new ChainedAuditLog();
            var verdict = probe.ImportEntriesJson(File.ReadAllText(AuditPath));
            var entries = AuditLog.Entries;
            var head = entries.Count == 0 ? ChainedAuditLog.GenesisHash : entries[^1].Hash;
            if (!verdict.Ok || probe.Entries.Count != entries.Count ||
                !string.Equals(probe.HeadHash, head, StringComparison.OrdinalIgnoreCase))
            {
                ChainPersistenceState =
                    $"BROKEN: enterprise audit chain persistence could not be VERIFIED after save — the persisted store ({probe.Entries.Count} entries, head {probe.HeadHash}, verdict {(verdict.Ok ? "OK" : verdict.Summary)}) does not match the in-memory chain ({entries.Count} entries, head {head}); the append is NOT durable as persisted (W47)";
                try
                {
                    Alerts.Raise("verification_failure",
                        "enterprise audit persistence UNVERIFIED: " + ChainPersistenceState, _now());
                }
                catch { /* the alert centre failing must not mask the state */ }
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            ChainPersistenceState =
                $"BROKEN: enterprise audit chain persistence could not be VERIFIED after save ({ex.GetType().Name}: {ex.Message}) — the persisted store could not be re-read and matched against the in-memory chain; the append is NOT durable as persisted (W47)";
            try
            {
                Alerts.Raise("verification_failure",
                    "enterprise audit persistence UNVERIFIED: " + ChainPersistenceState, _now());
            }
            catch { /* the alert centre failing must not mask the state */ }
            return false;
        }
    }

    private void SaveChainLocked()
    {
            try
            {
                var tmp = AuditPath + ".tmp-" + Guid.NewGuid().ToString("N");
                try
                {
                    var json = AuditLog.ExportEntriesJson();
                    using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    using (var writer = new StreamWriter(fs))
                    {
                        writer.Write(json);
                        writer.Flush();
                        fs.Flush(flushToDisk: true);
                    }
                    File.Move(tmp, AuditPath, overwrite: true);
                }
                catch { try { File.Delete(tmp); } catch { } throw; }
                ChainPersistenceState = "ok";
            }
            catch (Exception ex)
            {
                ChainPersistenceState =
                    $"BROKEN: enterprise audit chain could not be persisted ({ex.GetType().Name}: {ex.Message}) — the in-memory chain is the live truth but is NOT durable";
                try
                {
                    Alerts.Raise("verification_failure",
                        "enterprise audit persistence BROKEN: " + ChainPersistenceState, _now());
                }
                catch { /* the alert centre failing must not mask the state */ }
            }
    }

    /// <summary>W43 (F2): is an entry of this kind DURABLE — i.e.
    /// present in the chain as persisted on disk, in a store that
    /// itself verifies? The W35 check read only the in-memory
    /// chain + the persistence STATE flag, and the flag is a
    /// last-save verdict: a save that overwrote the entry (the
    /// pre-fix race) still left it "ok". This reads the actual
    /// persisted store, so "recorded" means a restart would find
    /// the entry. Fail-closed: any read/parse/verify failure is
    /// "not durable".</summary>
    public bool ChainEntryIsDurable(string kind)
    {
        try
        {
            if (!File.Exists(AuditPath)) return false;
            var probe = new ChainedAuditLog();
            var verdict = probe.ImportEntriesJson(File.ReadAllText(AuditPath));
            return verdict.Ok && probe.Entries.Any(e => e.Kind == kind);
        }
        catch { return false; }
    }

    // ---- policy ---------------------------------------------------

    /// <summary>(Re)load the policy bundle from the data dir. A
    /// missing bundle is a named state, not an error; a present but
    /// invalid bundle REFUSES (fail closed) and any previously
    /// loaded enforcer is dropped — a policy file swap between Core
    /// restarts can never leave a stale, wider policy in force.</summary>
    public (bool Ok, string Detail) LoadPolicy()
    {
        var bundlePath = Path.Combine(_dataDir, "policy-bundle.json");
        var keyPath = Path.Combine(_dataDir, "policy-orgkey.txt");
        Enforcer = null;
        PolicyRefused = false;
        if (!File.Exists(bundlePath))
        {
            // BD-WIN-CORE-3/F4: a bundle that was loaded before and
            // is now MISSING is not the owner's ungated device —
            // deleting policy-bundle.json must not resurrect every
            // disabled feature. The chained audit's policy_loaded
            // entries are the durable "this device was managed"
            // marker: if one exists, a missing bundle is a REFUSAL
            // (fail closed), exactly like a present-but-bad bundle.
            if (AuditLog.Entries.Any(e => e.Kind == "policy_loaded"))
            {
                PolicyRefused = true;
                PolicyState = "policy bundle MISSING after a bundle was previously loaded — refused (fail closed: deleting the bundle does not un-manage this device)";
                AuditLog.Append("policy_refusal", "enterprise", PolicyState, _now());
                Alerts.Raise("policy_refusal", PolicyState, _now());
                SaveChain();
                return (false, PolicyState);
            }
            PolicyState = "no policy bundle loaded";
            return (true, PolicyState);
        }
        try
        {
            if (!File.Exists(keyPath))
            {
                PolicyRefused = true;
                PolicyState = "policy bundle present but the org public key is missing — refused (fail closed)";
                AuditLog.Append("policy_refusal", "enterprise", PolicyState, _now());
                SaveChain();
                return (false, PolicyState);
            }
            var bundle = JsonSerializer.Deserialize<PolicyBundle>(File.ReadAllText(bundlePath))
                ?? throw new InvalidOperationException("bundle did not parse");
            var pub = Convert.FromBase64String(File.ReadAllText(keyPath).Trim());
            var verdict = new PolicyBundleService().Verify(bundle, pub, _now());
            if (!verdict.Allowed)
            {
                PolicyRefused = true;
                PolicyState = "policy refused: " + verdict.Reason;
                AuditLog.Append("policy_refusal", "enterprise", PolicyState, _now());
                Alerts.Raise("policy_refusal", PolicyState, _now());
                SaveChain();
                return (false, PolicyState);
            }
            Enforcer = new PolicyEnforcer(bundle);
            PolicyState = $"policy v{bundle.Version} loaded for scope {bundle.ScopeId}: ceiling [{string.Join(",", bundle.TransportCeiling)}], mode {bundle.TransportMode}" +
                (bundle.PinnedVersion is not null ? $", updates pinned to {bundle.PinnedVersion}" : "") +
                (bundle.UpdateDeferUntil is not null ? $", updates deferred until {bundle.UpdateDeferUntil:O}" : "") +
                (bundle.Disabled.Count > 0 ? $", features disabled [{string.Join(",", bundle.Disabled)}]" : "") +
                (bundle.Required.Count > 0 ? $", features required [{string.Join(",", bundle.Required)}]" : "");
            AuditLog.Append("policy_loaded", "enterprise", PolicyState, _now());
            SaveChain();
            return (true, PolicyState);
        }
        catch (Exception ex)
        {
            PolicyRefused = true;
            PolicyState = $"policy bundle unreadable ({ex.GetType().Name}) — refused (fail closed)";
            AuditLog.Append("policy_refusal", "enterprise", PolicyState, _now());
            SaveChain();
            return (false, PolicyState);
        }
    }

    /// <summary>The update gate UpdateManager consults: with no
    /// bundle loaded, updates are the owner's own act; with one,
    /// pin/defer REFUSE (DIR-22).</summary>
    public PolicyVerdict CheckUpdate(string candidateVersion) =>
        PolicyRefused
            ? new PolicyVerdict(false, "policy bundle present but refused — update denied (fail closed)")
            : Enforcer?.CheckUpdate(candidateVersion, _now())
              ?? new PolicyVerdict(true, "no policy bundle loaded — update not policy-gated");

    public PolicyVerdict CheckTransport(string rung) =>
        PolicyRefused
            ? new PolicyVerdict(false, "policy bundle present but refused — transport denied (fail closed)")
            : Enforcer?.CheckTransport(rung)
              ?? new PolicyVerdict(true, "no policy bundle loaded — transport not policy-gated");

    /// <summary>The TOTAL POLICY CONTROL feature gate (Block G):
    /// every toggleable feature consults this before it acts. With
    /// no bundle loaded the device is the owner's own and features
    /// are not policy-gated — the same posture as update/transport.
    /// With a bundle PRESENT BUT REFUSED the gate fails CLOSED
    /// (Block H D38 fix F6): a refused bundle denies every
    /// feature, in every scope — its scope claim is part of what
    /// did not verify, so it cannot be trusted to limit the
    /// denial either.</summary>
    public PolicyVerdict CheckFeature(string featureKey) =>
        PolicyRefused
            ? new PolicyVerdict(false, "policy bundle present but refused — feature denied (fail closed)")
            : Enforcer?.CheckFeature(featureKey)
              ?? new PolicyVerdict(true, "no policy bundle loaded — feature not policy-gated");

    /// <summary>SCOPE-AWARE feature check (D38 review F2): a
    /// bundle governs ONLY its own scope. Asking about any other
    /// scope gets the no-bundle posture — never another scope's
    /// rules leaking across the D8 wall. A REFUSED bundle is the
    /// exception (F6): it denies in every scope, because nothing
    /// about it — including its claimed scope — verified.</summary>
    public PolicyVerdict CheckFeature(string scopeId, string featureKey) =>
        PolicyRefused
            ? new PolicyVerdict(false, "policy bundle present but refused — feature denied (fail closed)")
            : Enforcer is null ||
              !string.Equals(Enforcer.Bundle.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)
                ? new PolicyVerdict(true, "no policy bundle loaded for this scope — feature not policy-gated")
                : Enforcer.CheckFeature(featureKey);

    /// <summary>Three-state feature posture for surfaces that must
    /// render policy state ("allowed" when no bundle is loaded;
    /// "disabled" when a present bundle was refused — every
    /// feature is in fact denied, and surfaces must not render
    /// the fail-open lie).</summary>
    public string FeatureState(string featureKey) =>
        PolicyRefused ? "disabled" : Enforcer?.FeatureState(featureKey) ?? "allowed";

    /// <summary>True when a loaded bundle REQUIRES the feature
    /// (e.g. watermark) on the surfaces it guards.</summary>
    public bool FeatureRequired(string featureKey) =>
        Enforcer?.FeatureRequired(featureKey) ?? false;

    /// <summary>SCOPE-AWARE required check (D38 review F2).</summary>
    public bool FeatureRequired(string scopeId, string featureKey) =>
        Enforcer is not null &&
        string.Equals(Enforcer.Bundle.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
        Enforcer.FeatureRequired(featureKey);

    /// <summary>Append a Block G service act to the ENTERPRISE
    /// chained audit (D38 review F1) and persist the chain. The G
    /// services' acts are enterprise-plane acts; they belong in
    /// the same hash-chained record the auditor exports.</summary>
    public void AppendServiceAudit(string kind, string? actor, string detail)
    {
        // W43 (F2): append + save are ATOMIC under the chain gate
        // (SaveChain re-enters it) — no other save can interleave
        // between this entry landing in memory and its export, so
        // a completed AppendServiceAudit is a completed durable
        // append, in chain order.
        lock (_chainSaveGate)
        {
            AuditLog.Append(kind, actor ?? "block-g", detail, _now());
            // W47 (a): append → persist VERIFIED → advance, all
            // inside the gate. Pre-fix the advance ran even when
            // SaveChain had swallowed a persistence failure, so
            // the marker could name an append a restart would
            // never see (marker-ahead-of-chain). Now an unverified
            // persist means NO advance, named here.
            if (SaveChainVerifiedLocked())
                AdvanceAnchorMarker();
            else
                AnchorMarkerState =
                    $"anchor marker advance FAILED: the chain append's persistence could not be verified ({ChainPersistenceState}) — the marker was NOT advanced, so the marker cannot stand ahead of the durable chain from this append (W47)";
        }
    }

    /// <summary>W36 / DS round-8: as AppendServiceAudit, but
    /// RETURNS the appended entry — its chain index (Seq) and own
    /// hash are the position commitment the pointer-signing flow
    /// signs over (append-then-sign: the record exists first, the
    /// signature commits to where it landed). Used by
    /// UpdateManager's positioned pointer-audit seam.</summary>
    public ChainedAuditEntry AppendServiceAuditReturningEntry(string kind, string? actor, string detail)
    {
        // W43 (F2): atomic under the chain gate, like
        // AppendServiceAudit — the returned (Seq, Hash) position
        // commitment is durable at the moment it is returned.
        lock (_chainSaveGate)
        {
            var entry = AuditLog.Append(kind, actor ?? "block-g", detail, _now());
            // W47 (a): as AppendServiceAudit — the returned
            // position commitment is marker-vouched only when its
            // persist VERIFIED durable; an unverified persist
            // advances nothing and names the failure in
            // AnchorMarkerState. (The entry is still returned: its
            // in-memory position is real, and callers that sign
            // over it are judged by the anchor legs, which refuse
            // a position the durable chain does not carry.)
            if (SaveChainVerifiedLocked())
                AdvanceAnchorMarker();
            else
                AnchorMarkerState =
                    $"anchor marker advance FAILED: the chain append's persistence could not be verified ({ChainPersistenceState}) — the marker was NOT advanced, so the marker cannot stand ahead of the durable chain from this append (W47)";
            return entry;
        }
    }

    // ---- audit export ----------------------------------------------

    public (bool Ok, string Detail, string? Path) ExportAudit(string format, string exportedBy)
    {
        var now = _now();
        string content;
        string ext;
        switch ((format ?? "").Trim().ToLowerInvariant())
        {
            case "json": content = AuditLog.ExportJson(exportedBy, now); ext = "json"; break;
            case "csv": content = AuditLog.ExportCsv(exportedBy, now); ext = "csv"; break;
            case "cef": content = AuditLog.ExportCef(exportedBy, now); ext = "cef"; break;
            default: return (false, $"unknown export format '{format}' (json|csv|cef)", null);
        }
        var verdict = AuditLog.Verify();
        if (!verdict.Ok)
            Alerts.Raise("verification_failure", $"audit exported with a BROKEN chain: {verdict.Summary}", now);
        var dir = Path.Combine(_dataDir, "exports");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"audit-export-{now:yyyyMMddHHmmss}.{ext}");
        File.WriteAllText(path, content);
        SaveChain(); // the export itself was appended to the chain
        return (true, $"export written: {path} | chain {(verdict.Ok ? "OK" : "BROKEN")} — {verdict.Summary}", path);
    }

    public ChainVerification VerifyChain() => AuditLog.Verify();

    // ---- directory sync ---------------------------------------------

    public PolicyVerdict ApplyDirectoryEvent(DirectoryEvent e, string actorAdminUserId)
    {
        var verdict = DirectorySync.Apply(e, actorAdminUserId, _now());
        SaveChain();
        return verdict;
    }

    // ---- break-glass --------------------------------------------------

    // The holder verifiers as loaded from disk (holderId -> stored
    // verifier: salted PBKDF2, or a legacy sha256 hex from a store
    // written before BD-WIN-CORE-3/F11), kept so a rotation can
    // rewrite the store: a rotation that lived only in memory
    // would resurrect the OLD secret at the next Core start — the
    // file is the durable half of the Rotate() surface (Block H).
    private readonly Dictionary<string, string> _holderHashes = new(StringComparer.OrdinalIgnoreCase);

    private void LoadBreakGlassHolders()
    {
        var path = Path.Combine(_dataDir, "breakglass-holders.json");
        if (!File.Exists(path)) return;
        try
        {
            var text = File.ReadAllText(path);
            // BD-WIN-CORE-3/F4: a sealed store does not parse as
            // JSON — unseal it with the wired protector. A store
            // that neither parses nor unseals seals NOBODY.
            try { _ = JsonDocument.Parse(text); }
            catch
            {
                if (_protector is null) return;
                text = _protector.Unprotect(text);
            }
            using var doc = JsonDocument.Parse(text);
            var pending = new List<string>();
            foreach (var h in doc.RootElement.EnumerateArray())
            {
                var id = h.GetProperty("holderId").GetString();
                var verifier = (h.TryGetProperty("secretVerifier", out var sv) ? sv.GetString() : null)
                    ?? (h.TryGetProperty("secretSha256", out var sh) ? sh.GetString() : null);
                if (id is not null && verifier is not null)
                {
                    BreakGlass.SealHolderVerifier(id, verifier);
                    _holderHashes[id] = verifier;
                    // F1: the rotation-pending flag is part of the
                    // durable store. A store written before this
                    // field existed simply has nobody pending.
                    if (h.TryGetProperty("rotationPending", out var rp) &&
                        rp.ValueKind == JsonValueKind.True)
                        pending.Add(id);
                }
            }
            BreakGlass.RestoreRotationPending(pending);
        }
        catch { /* a malformed holder store seals nobody — break-glass stays unavailable, never weakened */ }
    }

    /// <summary>Rewrite the holder store (tmp + move): holder
    /// hashes AND each holder's rotation-pending flag (F1), so a
    /// restart between a use/drill and the owed rotation keeps
    /// the BAD-32 requirement — and the exposed secrets — exactly
    /// where the live service has them.</summary>
    private void SaveBreakGlassHolders()
    {
        // Sync from the live service first: a Use may have upgraded
        // a legacy verifier to PBKDF2 in place, and that upgrade is
        // part of the durable state.
        foreach (var id in _holderHashes.Keys.ToList())
            if (BreakGlass.StoredVerifier(id) is { } live) _holderHashes[id] = live;
        var pending = new HashSet<string>(BreakGlass.RotationPendingHolders, StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(_dataDir, "breakglass-holders.json");
        var tmp = path + ".tmp";
        var json = JsonSerializer.Serialize(_holderHashes
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => new
            {
                holderId = kv.Key,
                secretVerifier = kv.Value,
                rotationPending = pending.Contains(kv.Key),
            }).ToArray());
        // BD-WIN-CORE-3/F4: sealed at rest when a protector is
        // wired — the file alone no longer confers a holder or
        // clears a pending rotation.
        File.WriteAllText(tmp, _protector is null ? json : _protector.Protect(json));
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Rotate ONE break-glass holder's secret — the
    /// product surface for BreakGlassService.Rotate (Block H).
    /// Authority (Block H D38 fix F2 — the previous shape needed
    /// no proof of the current secret, never checked the actor,
    /// and let ONE caller rotate BOTH holders in a single call,
    /// collapsing dual control into the caller's hands):
    ///  * ONE holder per act. Rotating both holders takes two
    ///    acts, each by its own holder.
    ///  * The actor must BE the holder (actor == holderId): a
    ///    rotation is the holder's own act, never something done
    ///    to them by an operator, an admin, or the other holder.
    ///  * The holder proves possession of the CURRENT secret
    ///    (checked constant-time against the sealed hash): a
    ///    rotation is a change of a known secret, not a reset.
    ///  * A rotation is accepted only while one is PENDING for
    ///    that holder (post-use/drill, BAD-32): gratuitous
    ///    rotations outside the mandatory window are refused.
    ///  * The new secret must differ from the current one.
    /// Each accepted rotation reseals the holder in the live
    /// service AND rewrites the holder store (hash + pending
    /// flags), so the new secret — and the remaining holders'
    /// still-pending state — are the durable ones.</summary>
    public (bool Ok, string Detail) RotateBreakGlassHolders(string actor,
        IReadOnlyList<(string HolderId, string CurrentSecret, string NewSecret)> rotations)
    {
        if (rotations.Count == 0) return (false, "no rotation supplied");
        if (rotations.Count > 1)
            return (false, "one holder per rotation act — dual control: each holder rotates their own secret, proven by their current secret; rotating both holders in one call would put both new secrets in one person's hands");
        var (holderId, currentSecret, newSecret) = rotations[0];
        if (string.IsNullOrWhiteSpace(holderId) || string.IsNullOrWhiteSpace(currentSecret) ||
            string.IsNullOrWhiteSpace(newSecret))
            return (false, "a rotation needs the holder id, the holder's CURRENT secret (proof of possession), and a new secret");
        if (!_holderHashes.TryGetValue(holderId, out var sealedVerifier))
            return (false, $"unknown break-glass holder '{holderId}' — nothing was rotated");
        if (!string.Equals(actor, holderId, StringComparison.OrdinalIgnoreCase))
            return (false, $"rotation refused: the actor ('{actor}') is not the holder ('{holderId}') — a holder rotates their own secret, in person, proven by the current secret");
        if (!BreakGlass.RotationPendingHolders.Contains(holderId, StringComparer.OrdinalIgnoreCase))
            return (false, $"rotation refused: no rotation is pending for holder '{holderId}' — rotation is accepted only in the mandatory post-use window (BAD-32)");
        // BD-WIN-CORE-3/F11: verification runs against the stored
        // verifier through the SAME check a break-glass Use applies
        // (salted PBKDF2 for current stores; legacy sha256 stores
        // still verify and are upgraded by the rotation itself).
        if (!BreakGlassService.VerifyStoredVerifier(sealedVerifier, currentSecret))
            return (false, $"rotation refused: the current secret presented for holder '{holderId}' does not match the sealed secret — nothing was rotated");
        if (BreakGlassService.VerifyStoredVerifier(sealedVerifier, newSecret))
            return (false, "rotation refused: the new secret is the current secret — a rotation must retire the exposed secret, not re-seal it");

        BreakGlass.Rotate(holderId, newSecret);
        _holderHashes[holderId] = BreakGlass.StoredVerifier(holderId)!;
        AuditLog.Append("break_glass_rotate", actor,
            $"break-glass holder '{holderId}' rotated their own secret (current-secret proof presented); rotation still required for: " +
            (BreakGlass.RotationPendingHolders.Count == 0
                ? "none — rotation complete"
                : string.Join(", ", BreakGlass.RotationPendingHolders)), _now());
        SaveBreakGlassHolders();
        SaveChain();
        return (true,
            $"rotated: {holderId} — holder store rewritten; " +
            (BreakGlass.RotationRequired
                ? $"rotation still REQUIRED for: {string.Join(", ", BreakGlass.RotationPendingHolders)}"
                : "rotation complete — break-glass is usable again"));
    }

    public (bool Ok, string Detail, BreakGlassService.Grant? Grant) UseBreakGlass(
        string scopeId, string holderA, string secretA, string holderB, string secretB, string reason, bool isDrill)
    {
        var grant = BreakGlass.Use(scopeId, holderA, secretA, holderB, secretB, reason, isDrill, _now());
        // F1: a successful use/drill makes rotation pending for
        // every holder — persist that state with the act, so a
        // restart before the rotation cannot clear it.
        if (grant is not null) SaveBreakGlassHolders();
        SaveChain();
        return grant is null
            ? (false, "break-glass refused (dual control: two distinct sealed holders, correct secrets, a stated reason, and no pending rotation)", null)
            : (true, $"break-glass {(isDrill ? "DRILL" : "USE")} granted until {grant.ExpiresUtc:O} — recorded loudly in the chained audit + alerts BEFORE the grant existed", grant);
    }

    // ---- IdP sign-in ----------------------------------------------------

    /// <summary>The mock-IdP leg, end-to-end and local: ACP's OIDC
    /// client runs the full PKCE S256 flow against the in-process
    /// mock IdP. The REAL leg stops at the sign-in boundary (the
    /// org's own page, in ACP's frame — D4 shape): no real IdP is
    /// configured or contacted by this build.</summary>
    public (bool Ok, string Detail) BeginMockIdpSignIn(string subject, string email, bool emailVerified)
    {
        var config = new OidcConfig("https://idp.mock.local/acp", "acp-core", "acp://oidc/callback",
            RequirePkceS256: true, RequireEmailVerified: true);
        var verdict = OidcConfigValidator.Validate(config);
        if (!verdict.Allowed) return (false, verdict.Reason);
        _mockIdp = new MockIdp(config.Issuer);
        _mockClient = new OidcClient(config, _mockIdp);
        _pendingVerifier = Pkce.NewVerifier();
        _pendingNonce = Guid.NewGuid().ToString("N");
        var code = _mockIdp.BeginAuthorize(subject, email, emailVerified,
            Pkce.ChallengeS256(_pendingVerifier), _pendingNonce);
        _pendingCode = code;
        return (true, "mock IdP authorization issued (PKCE S256, local only) — complete with CompleteMockIdpSignIn");
    }

    private string? _pendingCode;

    public (bool Ok, string Detail, string? Subject) CompleteMockIdpSignIn()
    {
        if (_mockIdp is null || _mockClient is null || _pendingCode is null || _pendingVerifier is null || _pendingNonce is null)
            return (false, "no mock sign-in in flight — begin one first", null);
        try
        {
            var jwt = _mockIdp.ExchangeCode(_pendingCode, _pendingVerifier, "acp-core");
            var result = _mockClient.CompleteSignIn(jwt, _pendingNonce, _now());
            _pendingCode = null;
            if (result.Ok)
                AuditLog.Append("idp_signin_mock", result.Subject ?? "unknown", $"mock IdP sign-in completed for {result.Email}", _now());
            SaveChain();
            return (result.Ok, result.Reason, result.Subject);
        }
        catch (InvalidOperationException ex)
        {
            return (false, "mock IdP exchange refused: " + ex.Message, null);
        }
    }

    // ---- Real IdP sign-in (W11 / R-21) ------------------------------
    // The protocol leg is now REAL: discovery + JWKS + RS256 via
    // RealOidcClient (Acp.Shared). Begin fetches the issuer's
    // discovery document and returns the authorization URL; the
    // user's browser runs the org's own sign-in page (D4 shape —
    // ACP never sees, types, or stores that credential); Complete
    // exchanges the returned code and validates the ID token
    // end-to-end. The HTTP fetch is injectable for tests; in
    // production it is the client's real HttpClient fetch.

    private RealOidcClient? _realClient;
    private OidcDiscovery? _realDiscovery;
    private string? _realVerifier;
    private string? _realNonce;
    private string? _realState;

    /// <summary>Test seam: replace the real client's HTTP GET.
    /// Null (the production default) = real HttpClient fetch.</summary>
    public Func<string, Task<string>>? RealIdpHttpGetOverride { get; set; }

    /// <summary>Test seam: replace the real client's token POST.</summary>
    public Func<string, string, Task<string>>? RealIdpHttpPostOverride { get; set; }

    public (bool Ok, string Detail, string? AuthorizationUrl) BeginRealIdpSignIn(OidcConfig config)
    {
        var verdict = OidcConfigValidator.Validate(config);
        if (!verdict.Allowed) return (false, verdict.Reason, null);
        _realClient = new RealOidcClient(config, RealIdpHttpGetOverride, RealIdpHttpPostOverride);
        var (discovery, reason) = _realClient.DiscoverAsync().GetAwaiter().GetResult();
        if (discovery is null) return (false, $"real IdP discovery refused: {reason}", null);
        _realDiscovery = discovery;
        _realVerifier = Pkce.NewVerifier();
        _realNonce = Guid.NewGuid().ToString("N");
        _realState = Guid.NewGuid().ToString("N");
        var url = _realClient.BuildAuthorizationUrl(discovery, _realState, _realNonce,
            Pkce.ChallengeS256(_realVerifier));
        return (true, $"real IdP discovery accepted for {config.Issuer} — send the user's browser to the authorization URL; complete with the returned code", url);
    }

    public (bool Ok, string Detail, string? Subject) CompleteRealIdpSignIn(string authorizationCode)
    {
        if (_realClient is null || _realDiscovery is null || _realVerifier is null || _realNonce is null)
            return (false, "no real sign-in in flight — begin one first", null);
        if (string.IsNullOrWhiteSpace(authorizationCode))
            return (false, "no authorization code presented — refused", null);
        var result = _realClient.ExchangeAndValidateAsync(
            _realDiscovery, authorizationCode, _realVerifier, _realNonce, _now()).GetAwaiter().GetResult();
        _realVerifier = null; _realNonce = null; _realState = null;
        if (result.Ok)
        {
            AuditLog.Append("idp_signin_real", result.Subject ?? "unknown",
                $"real IdP sign-in completed for {result.Email} ({result.Reason})", _now());
            SaveChain();
        }
        return (result.Ok, result.Reason, result.Subject);
    }

    public const string RealIdpBoundary =
        "real IdP leg: BUILT (W11 / R-21) — discovery, JWKS and RS256 signature validation run against the organization's own IdP via BeginRealIdpSignIn/CompleteRealIdpSignIn; " +
        "the sign-in itself still runs on the organization's own IdP page inside ACP's frame (D4): ACP never sees, types, or stores that credential. " +
        "The mock leg above remains the local proof path. No IdP is configured by default — an operator supplies issuer + client id to begin a real sign-in.";
}

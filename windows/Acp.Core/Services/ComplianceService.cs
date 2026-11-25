using Acp.Shared.Compliance;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Patching;
using Acp.Shared.Security;
using Acp.Shared.Update;

namespace Acp.Core.Services;

// =====================================================================
// RMM-09 — ComplianceService: the hub-side wiring for compliance
// evidence packs (offline GRC over ACP-collected facts).
//
// Compiles packs LOCALLY from hub data only — no external service
// is consulted at compile time, ever:
//   * RMM-04 InventoryStore     → inventory + patch facts
//     (patch state via RMM-02's PatchScanner over the catalogue);
//   * RMM-01 security-state     → encryption / AV / firewall facts,
//     via the SecurityStateStore seam the monitor's reports feed;
//   * the enterprise chained audit → chain-integrity + history
//     facts (verified at compile time, head hash as evidence ref);
//   * DIR-54 AccessReviewCampaigns → access-review facts;
//   * RMM-05 VulnerabilityService.BuildReport → vulnerability
//     facts, carrying the feed provenance's staleness verdict as
//     UpstreamStale so a stale feed makes stale gaps, never passes.
//
// Every compile, admission, treatment and refusal is a chained-
// audit event (compliance_* kinds). Compilation refuses when the
// rmm.compliance.enabled policy toggle is off for the scope.
// =====================================================================
public sealed class ComplianceService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly InventoryStore _inventory;
    private readonly PatchService _patches;
    private readonly VulnerabilityService _vulns;
    private readonly Func<DateTimeOffset> _now;
    // W37: the runtime pointer-signing custody (install-root key),
    // when composed, key-anchors every compiled pack — see
    // PackAuditAnchor. Null = the named LEGACY-UNKEYED-PACK
    // posture (unkeyed hash anchor only), never a silent claim of
    // keying.
    private readonly PointerSigningCustody? _packSigning;
    // W47 (c): the pack-compile marker advance is part of the
    // SAME gated, verified operation as its appends. When this
    // service is composed over the Core's enterprise chain
    // (CoreRuntime), the caller supplies the chain owner's gate
    // (EnterpriseService.ChainGate) and its verified-persist
    // delegate (EnterpriseService.PersistChainVerified): the
    // keyed compile then holds that gate across append → persist
    // verification → advance, totally ordered with every pointer
    // stage on the same chain. Without a supplied gate this
    // service uses its own (the compile is still one gated
    // operation internally); without a persist delegate there is
    // no separate chain store in this composition to verify
    // against — the advance is computed from the chain's live
    // entries inside the gate and landing-checked, never from a
    // pre-gate snapshot.
    private readonly object _chainGate;
    private readonly Func<bool>? _persistChainVerified;

    /// <summary>W45 / DS round-9 Item 4 parenthetical: named state
    /// of this service's install-root anchor marker advances —
    /// the same marker the pointer leg advances (one marker, one
    /// chain), so a keyed pack compile vouches the chain position
    /// it landed at and a whole-chain rollback to an older genuine
    /// pack truncates BELOW the marker and refuses at the
    /// freshness leg in VerifyStoredPack. "advanced:chain_entries=N"
    /// when the last advance landed (proven by re-read); a FAILED
    /// state naming the cause otherwise; "not-composed" in the
    /// LEGACY-UNKEYED-PACK composition.</summary>
    public string AnchorMarkerState { get; private set; } =
        "not-composed: no pack-signing custody composed — this service does not advance the install-root anchor marker (W45)";
    private readonly List<(string CampaignId, string ScopeId, AccessReviewCampaign Campaign)> _campaigns = new();
    private readonly List<CompliancePack> _packHistory = new();
    private readonly Dictionary<string, CompliancePack> _packsById = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    // D38-F12: audit-chain verification is O(chain) — cache the
    // verdict keyed by (entry count, head hash); any append moves
    // the head and re-verifies. Compiles no longer re-verify and
    // re-copy an unchanged chain on every call.
    private (int Count, string HeadHash, ChainVerification Result)? _auditVerificationCache;

    /// <summary>D38-F12: pack history is bounded — a hub that
    /// compiles forever cannot grow this without limit. The
    /// oldest packs evict first; 512 packs of history is far
    /// beyond any movement-diff horizon in the programme.</summary>
    private const int MaxPackHistory = 512;

    public ComplianceContentPackStore ContentPacks { get; } = new();
    public TreatmentStore Treatments { get; } = new();
    public SecurityStateStore SecurityStates { get; }

    public ComplianceService(ChainedAuditLog audit, ManagementPolicyService policies,
        InventoryStore inventory, PatchService patches, VulnerabilityService vulns,
        Func<DateTimeOffset>? now = null, PointerSigningCustody? packSigning = null,
        object? chainGate = null, Func<bool>? persistChainVerified = null)
    {
        _chainGate = chainGate ?? new object();
        _persistChainVerified = persistChainVerified;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        _patches = patches ?? throw new ArgumentNullException(nameof(patches));
        _vulns = vulns ?? throw new ArgumentNullException(nameof(vulns));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _packSigning = packSigning;
        // D38-F3: the security-state store judges future-dated
        // observations against the SERVICE's clock, not its own.
        SecurityStates = new SecurityStateStore(() => _now());
        ContentPacks.SeedDefaults();
    }

    public bool IsEnabled(IDeviceFacts facts) =>
        _policies.IsEnabled(facts, CompliancePolicyKeys.Enabled);

    public IReadOnlyList<CompliancePack> PackHistory
    {
        get { lock (_gate) return _packHistory.ToList(); }
    }

    public CompliancePack? GetPack(string packId)
    {
        lock (_gate) return packId is not null && _packsById.TryGetValue(packId, out var p) ? p : null;
    }

    public CompliancePack? LatestPack(string frameworkId, string scopeId)
    {
        lock (_gate) return _packHistory
            .Where(p => string.Equals(p.FrameworkId, frameworkId, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(p.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(p => p.GeneratedUtc).FirstOrDefault();
    }

    // ---- policy content -------------------------------------------------

    public ComplianceStalenessPolicy StalenessFor(IDeviceFacts facts)
    {
        var effective = _policies.ComputeEffective(facts);
        int Read(string key, int fallback)
        {
            var s = effective.Get(key);
            return s is not null && int.TryParse(s.Value, out var v) && v is >= 1 and <= 365 ? v : fallback;
        }
        var d = ComplianceStalenessPolicy.Default;
        return new ComplianceStalenessPolicy(
            Read(CompliancePolicyKeys.FactStaleDays, d.DefaultDays),
            Read(CompliancePolicyKeys.InventoryStaleDays, d.InventoryDays));
    }

    // ---- content packs ----------------------------------------------------

    /// <summary>Admit a checklist content pack (a signed-content
    /// revision in production; this surface is the admission point).
    /// Removals are audited BY NAME in their own event — a pack
    /// revision that drops hard controls is loud by construction.</summary>
    public PackAdmission AdmitContentPack(ComplianceContentPack? pack, string admittedBy)
    {
        var now = _now();
        var result = ContentPacks.Admit(pack);
        _audit.Append(result.Accepted ? "compliance_pack_admitted" : "compliance_pack_refused", admittedBy,
            $"pack={pack?.Id} framework={pack?.FrameworkId} revision={pack?.Revision} reason={result.Reason}", now);
        if (result.Accepted && result.RemovedControlIds.Count > 0)
            _audit.Append("compliance_pack_controls_removed", admittedBy,
                $"pack={pack!.Id} framework={pack.FrameworkId} revision={pack.Revision} REMOVED CONTROLS: {string.Join(", ", result.RemovedControlIds)}", now);
        if (result.Accepted && result.RemappedControlIds.Count > 0)
            _audit.Append("compliance_pack_controls_remapped", admittedBy,
                $"pack={pack!.Id} framework={pack.FrameworkId} revision={pack.Revision} REMAPPED CONTROLS (same id, changed fact kind/rule/title — a kept id is not a kept control): {string.Join(", ", result.RemappedControlIds)}", now);
        return result;
    }

    // ---- fact-source intake -------------------------------------------------

    /// <summary>Record an endpoint security-state observation
    /// (RMM-01's report landing on the hub). A stale replay refuses
    /// at the store and the refusal is audited.</summary>
    public bool RegisterSecurityState(DeviceSecurityState state, string reportedBy)
    {
        var ok = SecurityStates.Record(state);
        _audit.Append(ok ? "compliance_security_state_reported" : "compliance_security_state_refused",
            reportedBy,
            $"device={state.DeviceId} observed={state.ObservedUtc:O} av={state.AvEnabled} fw={state.FirewallEnabled} enc={state.EncryptionEnabled}" +
            (ok ? "" : " reason=observation refused (not newer than the stored one — stale replay — or future-dated beyond clock skew)"), _now());
        return ok;
    }

    /// <summary>D38-F1: a campaign is registered FOR a scope. Before
    /// this fix registration took no scope and the fact builder used
    /// the latest campaign from ANY scope, stamped with the target
    /// scopeId — one site's review evidenced every other site.</summary>
    public void RegisterAccessReview(string campaignId, AccessReviewCampaign campaign, string scopeId, string registeredBy)
    {
        lock (_gate) _campaigns.Add((campaignId, scopeId, campaign));
        _audit.Append("compliance_access_review_registered", registeredBy,
            $"campaign={campaignId} scope={scopeId} deadline={campaign.DeadlineUtc:O}", _now());
    }

    // ---- fact building -------------------------------------------------------

    /// <summary>Assemble the fact set for one scope from hub data.
    /// Public so the coordinator/tests can inspect exactly what a
    /// pack rested on. Facts are built ONLY from the stores above;
    /// nothing here invents a value a store does not hold.</summary>
    public ComplianceFactSet BuildFactSet(string scopeId, IDeviceFacts vulnFacts)
    {
        var now = _now();
        var records = _inventory.List(scopeId == "" ? null : scopeId);
        if (scopeId == "") records = _inventory.List();
        var facts = new List<ComplianceFact>();
        var deviceIds = records.Select(r => r.DeviceId).OrderBy(d => d, StringComparer.Ordinal).ToList();

        foreach (var record in records)
        {
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.InventoryPresence, record.DeviceId, record.ScopeId,
                Passing: true, record.LastSeenUtc,
                $"inventory record revision {record.Revision}, hostname {record.Hostname}, {record.Software.Count} software item(s)",
                ComplianceHash.Sha256Hex($"inv|{record.DeviceId}|{record.Revision}|{record.LastSeenUtc:O}")));

            var missing = PatchScanner.DetermineMissing(record, _patches.Catalogue);
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.PatchState, record.DeviceId, record.ScopeId,
                Passing: missing.Count == 0, record.LastSeenUtc,
                missing.Count == 0
                    ? "no catalogue patch is missing on this device"
                    : $"missing patches: {string.Join(", ", missing.Select(m => m.EntryId))}",
                ComplianceHash.Sha256Hex($"patch|{record.DeviceId}|{record.LastSeenUtc:O}|{string.Join(",", missing.Select(m => m.EntryId))}")));

            var sec = SecurityStates.Get(record.DeviceId);
            if (sec is not null && string.Equals(sec.ScopeId, record.ScopeId, StringComparison.OrdinalIgnoreCase))
            {
                if (sec.EncryptionEnabled is { } enc)
                    facts.Add(new ComplianceFact(
                        ComplianceFactKinds.EncryptionState, record.DeviceId, record.ScopeId,
                        enc, sec.ObservedUtc,
                        $"disk encryption {(enc ? "ENABLED" : "DISABLED")} as observed by the endpoint monitor",
                        ComplianceHash.Sha256Hex($"enc|{record.DeviceId}|{sec.ObservedUtc:O}|{enc}")));
                if (sec.AvEnabled is { } av && sec.FirewallEnabled is { } fw)
                    facts.Add(new ComplianceFact(
                        ComplianceFactKinds.SecurityState, record.DeviceId, record.ScopeId,
                        av && fw, sec.ObservedUtc,
                        $"antivirus {(av ? "ENABLED" : "DISABLED")}, firewall {(fw ? "ENABLED" : "DISABLED")} as observed by the endpoint monitor",
                        ComplianceHash.Sha256Hex($"sec|{record.DeviceId}|{sec.ObservedUtc:O}|{av}|{fw}")));
            }
        }

        // Audit facts (scope-level): verified at build time; the
        // head hash is the evidence reference. An empty chain emits
        // NO fact — there is no history to evidence anything with.
        // D38-F2: BOTH audit facts carry the chain-verification
        // verdict — before this fix AuditHistory passed
        // unconditionally, so gdpr-accountability and
        // cmmc-au-audit-records ("history exists AND the chain
        // verifies intact") were satisfied on a tampered chain.
        // D38-F2 (scope): the chain is the HUB's chain; it is only
        // offered as evidence for a scope that actually has
        // inventory in this hub (or the fleet scope "") — an empty
        // or foreign scope gets no in-scope "history" from it.
        var entries = _audit.Entries;
        if (entries.Count > 0 && (scopeId == "" || records.Count > 0))
        {
            var verification = VerifyAuditChainCached(entries);
            var last = entries[^1];
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.AuditChain, null, scopeId,
                verification.Ok, last.AtUtc,
                $"hash chain verification: {verification.Summary}",
                _audit.HeadHash));
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.AuditHistory, null, scopeId,
                verification.Ok, last.AtUtc,
                $"{entries.Count} chained audit entries in the hub's chain, {entries[0].AtUtc:O} → {last.AtUtc:O}; chain verification: {verification.Summary}",
                _audit.HeadHash));
        }

        // Access-review fact (scope-level): the latest campaign
        // registered FOR THIS SCOPE (D38-F1). Deadline defaults are
        // applied so non-response shows as the suspensions DIR-54
        // prescribes, in the detail.
        // D38-F1 (passing): a campaign nobody answered does NOT
        // pass. Deadline defaults turn pending items into
        // defaulted_suspend, so "no pending" alone was satisfied
        // by timing out — passing now requires pending == 0 AND
        // defaulted == 0: every item answered by a human decision
        // (attested or remove). The seeded control titles say so.
        // D38-F1 (staleness): the fact's observation instant is the
        // campaign DEADLINE once it has passed (the last instant
        // the campaign's state could change), not the compile
        // instant — a campaign that closed years ago goes stale
        // like any other fact instead of being re-stamped fresh
        // at every compile.
        (string CampaignId, AccessReviewCampaign Campaign)? latest = null;
        lock (_gate)
        {
            for (var i = _campaigns.Count - 1; i >= 0; i--)
                if (string.Equals(_campaigns[i].ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                { latest = (_campaigns[i].CampaignId, _campaigns[i].Campaign); break; }
        }
        if (latest is { } l)
        {
            var items = l.Campaign.ApplyDeadlineDefaults(now);
            var pending = items.Count(i => i.Decision == "pending");
            var defaulted = items.Count(i => i.Decision == "defaulted_suspend");
            var attested = items.Count(i => i.Decision == "attested");
            var remove = items.Count(i => i.Decision == "remove");
            var observed = l.Campaign.DeadlineUtc <= now ? l.Campaign.DeadlineUtc : now;
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.AccessReview, null, scopeId,
                Passing: pending == 0 && defaulted == 0, observed,
                $"campaign {l.CampaignId}: attested={attested} remove={remove} defaulted_suspend={defaulted} pending={pending} deadline={l.Campaign.DeadlineUtc:O}",
                ComplianceHash.Sha256Hex($"review|{l.CampaignId}|{attested}|{remove}|{defaulted}|{pending}")));
        }

        // Vulnerability fact (scope-level) from RMM-05's report —
        // its provenance staleness verdict rides as UpstreamStale.
        // D38-F4: BuildReport scopes to the FACTS' scope, so the
        // report must be built from facts naming THIS scope —
        // re-scope the caller's facts when they name another one,
        // or one scope's exposure data would be stamped with
        // another scope's id (a cross-scope fact the compiler
        // cannot detect, since it is born wearing the target id).
        var scopedVulnFacts = string.Equals(vulnFacts.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)
            ? vulnFacts
            : StaticDeviceFacts.Of(vulnFacts.DeviceId, scopeId, vulnFacts.DirectGroupIds,
                new Dictionary<string, string>(vulnFacts.Attributes), vulnFacts.InstalledSoftware);
        var report = _vulns.BuildReport(scopedVulnFacts);
        // A policy-refused report carries zeroed counts — emitting
        // a fact from it would mint a clean vulnerability posture
        // out of a refusal. No fact: the vuln controls are
        // missing_fact gaps, honestly.
        if (report.PolicyEnabled && report.Provenance.FeedId is not null)
        {
            var open = report.OpenCount + report.CompensatedCount + report.RemediationRequestedCount;
            var overdue = report.Overdue.Count;
            // D38-F10: a feed with no publication instant has no
            // evidenced freshness — never fall back to the report's
            // generation instant (≈ now, fresh by construction).
            // The fact is stamped at the earliest instant and
            // flagged upstream-stale: a stale gap, never a pass.
            var feedPublished = report.Provenance.FeedPublishedUtc;
            facts.Add(new ComplianceFact(
                ComplianceFactKinds.VulnerabilityState, null, scopeId,
                Passing: overdue == 0 && report.KevOpenCount == 0,
                feedPublished ?? DateTimeOffset.MinValue,
                $"open={open}; overdue={overdue}; kevOpen={report.KevOpenCount}; closed={report.ClosedCount}",
                report.Provenance.ContentHash ?? ComplianceHash.Sha256Hex("vuln|no-content-hash"),
                UpstreamStale: report.Provenance.IsStale || feedPublished is null,
                UpstreamStaleNote: feedPublished is null
                    ? "feed provenance carries no publication instant — the fact's freshness cannot be evidenced"
                    : report.Provenance.StalenessNote));
        }

        return new ComplianceFactSet(scopeId, deviceIds, facts, now);
    }

    // ---- compilation ---------------------------------------------------------

    public sealed record CompileResult(bool Ok, string Reason, CompliancePack? Pack);

    public CompileResult CompilePack(IDeviceFacts facts, string frameworkId, string compiledBy) =>
        Compile(facts, frameworkId, compiledBy, PackKinds.EvidencePack, facts.ScopeId, null);

    /// <summary>The site assessment: the same machinery aimed at
    /// ONE site/scope — devices, facts and verdicts all restricted
    /// to that scope, labelled as an assessment of it.</summary>
    public CompileResult CompileSiteAssessment(IDeviceFacts facts, string frameworkId, string siteScopeId, string compiledBy) =>
        Compile(facts, frameworkId, compiledBy, PackKinds.SiteAssessment, siteScopeId, siteScopeId);

    /// <summary>D38-F12: verify the audit chain, reusing the last
    /// verdict while the chain's (count, head) is unchanged.</summary>
    private ChainVerification VerifyAuditChainCached(IReadOnlyList<ChainedAuditEntry> entries)
    {
        var head = _audit.HeadHash;
        lock (_gate)
        {
            if (_auditVerificationCache is { } c && c.Count == entries.Count && c.HeadHash == head)
                return c.Result;
        }
        var result = _audit.Verify();
        lock (_gate) _auditVerificationCache = (entries.Count, head, result);
        return result;
    }

    private CompileResult Compile(IDeviceFacts facts, string frameworkId, string compiledBy,
        string kind, string targetScopeId, string? siteLabel)
    {
        var now = _now();
        CompileResult Refuse(string reason)
        {
            _audit.Append("compliance_pack_refused", compiledBy,
                $"framework={frameworkId} scope={targetScopeId} kind={kind} reason={reason}", now);
            return new CompileResult(false, reason, null);
        }
        // D38-F4: EVERY policy input to this compile — the enabled
        // gate, the staleness windows, and (via BuildFactSet) the
        // vulnerability report — is evaluated for the TARGET
        // scope, never the caller's. Before this fix a caller in
        // an enabled, lenient scope could compile another site
        // that had compliance disabled, under the caller's lenient
        // windows, with the caller's exposure data.
        var scopeFacts = string.Equals(facts.ScopeId, targetScopeId, StringComparison.OrdinalIgnoreCase)
            ? facts
            : StaticDeviceFacts.Of(facts.DeviceId, targetScopeId, facts.DirectGroupIds,
                new Dictionary<string, string>(facts.Attributes), facts.InstalledSoftware);
        if (!IsEnabled(scopeFacts))
            return Refuse("compliance evidence packs are disabled by policy for this scope (rmm.compliance.enabled) — compilation refuses (fail closed)");
        var contentPack = ContentPacks.Get(frameworkId);
        if (contentPack is null)
            return Refuse($"no content pack admitted for framework '{frameworkId}' — there is no checklist to compile against");

        var factSet = BuildFactSet(targetScopeId, scopeFacts);
        var pack = ComplianceCompiler.Compile(contentPack, factSet, Treatments, StalenessFor(scopeFacts),
            now, compiledBy, kind, siteLabel);
        void StorePack()
        {
            lock (_gate)
            {
                _packHistory.Add(pack);
                _packsById[pack.PackId] = pack;
                while (_packHistory.Count > MaxPackHistory)
                {
                    var evicted = _packHistory[0];
                    _packHistory.RemoveAt(0);
                    _packsById.Remove(evicted.PackId);
                }
            }
        }
        if (_packSigning is not null)
        {
            // W47 (c): the WHOLE keyed operation — both appends,
            // the chain persist, and the marker advance — runs
            // under the chain gate (the Core chain owner's gate
            // when composed with one), so it is totally ordered
            // with every other anchored append on this chain.
            // Pre-fix the advance sat outside any gate and named
            // a snapshot taken before it: a concurrent pointer
            // stage could advance the marker past this compile,
            // and this compile's pending advance then REGRESSED
            // the marker to its stale snapshot (round-10 Item 2).
            // The advance below is computed from the chain's LIVE
            // entries inside the gate, after a VERIFIED persist,
            // and is monotonicity-guarded in the advance itself —
            // regression is impossible by construction.
            lock (_chainGate)
            {
                // W37 keyed anchoring — append-then-sign (the W36
                // discipline): custody refusals and signing failures
                // refuse the compile BY NAME and store no pack; a pack
                // committed without its position-bound signature could
                // never carry a true commitment.
                if (_packSigning.CustodyRefusal is not null)
                    return Refuse(_packSigning.CustodyRefusal);
                ChainedAuditEntry compiledEntry;
                byte[] signature;
                try
                {
                    _packSigning.EnsureKeyForInstall();
                    compiledEntry = _audit.Append(PackAuditAnchor.CompiledKind, compiledBy,
                        $"pack={pack.PackId} framework={frameworkId} scope={targetScopeId} kind={kind} satisfied={pack.SatisfiedCount} gaps={pack.GapCount} treated={pack.TreatedGapCount} contentHash={pack.ContentHash} {PackAuditAnchor.SchemeMarker} headline={pack.Headline}", now);
                    signature = _packSigning.Sign(
                        PackAuditAnchor.BuildPackPayload(pack.PackId, pack.ContentHash, compiledEntry.Seq, compiledEntry.Hash));
                }
                catch (Exception ex)
                {
                    return Refuse($"pack keyed anchoring FAILED ({ex.GetType().Name}: {ex.Message}) — compilation refuses by name rather than store a pack its position-bound signature cannot vouch for (W37)");
                }
                _audit.Append(PackAuditAnchor.SignatureKind, compiledBy,
                    $"pack={pack.PackId} compiled_seq={compiledEntry.Seq} pack_key_fp={_packSigning.Fingerprint} pack_sig={Convert.ToBase64String(signature)}", now);
                // W47 (a): appends landed — now PERSIST, VERIFIED,
                // before any advance. Pre-fix this path advanced
                // with NO chain save at all (round-10 Item 2,
                // defect 3): the marker vouched appends no durable
                // store carried. When a persist delegate is wired
                // (the Core composition), an unverified persist
                // refuses the compile BY NAME, stores no pack, and
                // advances nothing — marker-ahead-of-chain cannot
                // arise from this path.
                if (_persistChainVerified is not null && !_persistChainVerified())
                {
                    AnchorMarkerState =
                        "anchor marker advance FAILED: the pack compile's chain persistence could not be verified — the marker was NOT advanced, so the marker cannot stand ahead of the durable chain from this compile (W47)";
                    return Refuse($"pack anchor marker advance FAILED ({AnchorMarkerState}) — compilation refuses by name rather than store a pack whose appends are not verified durable (W47)");
                }
                // Advance the install-root anchor marker to the
                // chain position AS IT STANDS INSIDE THE GATE
                // (live entries, not a pre-gate snapshot), with
                // the landing checked and the monotonicity guard
                // in the advance itself. A marker that cannot be
                // advanced refuses the compile BY NAME and stores
                // no pack: a pack whose freshness the marker does
                // not vouch is exactly the round-9 staged-rollback
                // shape on the pack leg, and it is not committed
                // silently.
                var (markerOk, markerState) = PointerAuditAnchor.AdvanceInstallRootMarker(
                    _packSigning.KeyDirectory, _audit.Entries);
                AnchorMarkerState = markerState;
                if (!markerOk)
                    return Refuse($"pack anchor marker advance FAILED ({markerState}) — compilation refuses by name rather than store a pack the install-root marker does not vouch as the newest genuine state (W45/W47)");
                StorePack();
                return new CompileResult(true, pack.Headline, pack);
            }
        }
        StorePack();
        _audit.Append("compliance_pack_compiled", compiledBy,
            $"pack={pack.PackId} framework={frameworkId} scope={targetScopeId} kind={kind} satisfied={pack.SatisfiedCount} gaps={pack.GapCount} treated={pack.TreatedGapCount} contentHash={pack.ContentHash} headline={pack.Headline}", now);
        return new CompileResult(true, pack.Headline, pack);
    }

    /// <summary>W37: re-register a previously compiled pack into
    /// history after a Core restart, so VerifyStoredPack can judge
    /// it against the (re-imported) chain and its keyed anchor.
    /// Registration grants NOTHING: verification still requires
    /// the chain, hash and — once keying has begun — the
    /// position-bound signature legs to pass.</summary>
    public void RestoreStoredPack(CompliancePack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);
        lock (_gate)
        {
            if (!_packsById.ContainsKey(pack.PackId)) _packHistory.Add(pack);
            _packsById[pack.PackId] = pack;
            while (_packHistory.Count > MaxPackHistory)
            {
                var evicted = _packHistory[0];
                _packHistory.RemoveAt(0);
                _packsById.Remove(evicted.PackId);
            }
        }
    }

    /// <summary>D38-F6: verify a stored pack against the hash the
    /// chained audit recorded at its compile. The pack ContentHash
    /// is unkeyed SHA-256 — on its own it proves nothing against a
    /// forger who can recompute it; the audit chain is the
    /// independent anchor (recomputing the pack's hash must match
    /// the hash written into the tamper-evident chain at compile
    /// time, and the chain itself must still verify). Returns
    /// false with the reason on any mismatch.
    /// W37: that unkeyed anchor alone was append-replayable (a
    /// data-dir attacker could recompute the hash AND append its
    /// record — W36-B §3). When pack keying has begun, the
    /// signature leg in PackAuditAnchor is additionally required:
    /// the anchored record must carry the scheme marker and a
    /// follow-up signature record whose position-bound signature
    /// verifies under the install-root pin.</summary>
    public bool VerifyStoredPack(string packId, out string reason)
    {
        var pack = GetPack(packId);
        if (pack is null) { reason = $"no pack '{packId}' in history"; return false; }
        var verification = _audit.Verify();
        if (!verification.Ok) { reason = $"audit chain does not verify ({verification.Summary}) — no pack hash can be anchored"; return false; }
        var entries = _audit.Entries;
        // W45 / DS round-9 Item 4 parenthetical — FRESHNESS leg:
        // the W37 boundary covered forge/replay onto an appended
        // record, but a WHOLE-CHAIN rollback to an older genuine
        // pack is the pointer leg's staged-rollback shape: every
        // restored byte genuine, every W37 leg passing on the
        // truncated chain. It closes the same way: keyed compiles
        // advance the install-root anchor marker (Compile, above),
        // and this leg judges the chain against that marker with
        // the pointer leg's own rule — shorter than the marker, or
        // a rewritten prefix at the marker's count, refuses by
        // name. Growth past the marker is accepted (the prefix
        // binds), so packs compiled before later appends still
        // verify; only truncation/rollback refuses.
        if (_packSigning is not null)
        {
            var markers = PointerAnchorMarker.ReadAll(_packSigning.KeyDirectory);
            if (PointerAuditAnchor.FreshnessRefusal(markers, entries) is { } freshnessRefusal)
            { reason = $"pack '{packId}': the audit chain does not bind the install-root anchor marker — {freshnessRefusal} — a whole-chain rollback to an older genuine pack is refused at the freshness leg (W45)"; return false; }
        }
        var anchored = entries.LastOrDefault(e =>
            e.Kind == "compliance_pack_compiled" && e.Detail.Contains($"pack={packId} "));
        if (anchored is null) { reason = $"no compliance_pack_compiled audit event anchors pack '{packId}'"; return false; }
        var marker = "contentHash=";
        var at = anchored.Detail.IndexOf(marker, StringComparison.Ordinal);
        if (at < 0) { reason = "the anchoring audit event carries no content hash"; return false; }
        var anchoredHash = anchored.Detail[(at + marker.Length)..].Split(' ')[0];
        if (!pack.VerifyContentHash(anchoredHash))
        { reason = $"pack content hash {pack.ContentHash} does not match the audit-anchored hash {anchoredHash} — the stored pack was altered after compilation"; return false; }
        // W37 signature leg (PackAuditAnchor): a scheme-marked
        // (keyed) record must ALSO carry a position-bound
        // signature, in its follow-up signature record, verifying
        // under the install-root pin over (pack id + anchored hash
        // + the anchored record's Seq + Hash). An appended forged
        // record sits at a new position, so a replayed signature
        // refuses HERE, and a forged one cannot be produced
        // without the custodied seed.
        var keyingBegun = entries.Any(e =>
                (e.Kind == PackAuditAnchor.CompiledKind && e.Detail.Contains(PackAuditAnchor.SchemeMarker)) ||
                e.Kind == PackAuditAnchor.SignatureKind)
            || (_packSigning is not null && _packSigning.KeyingBegun);
        if (anchored.Detail.Contains(PackAuditAnchor.SchemeMarker))
        {
            if (_packSigning is null)
            { reason = $"pack '{packId}' was compiled under pack keying ({PackAuditAnchor.SchemeMarker}) but this composition carries no pack-signing custody — its position-bound signature cannot be judged against an install-root pin, so verification refuses by name rather than fall back to the unkeyed hash alone (W37)"; return false; }
            var sigRecord = entries.LastOrDefault(e =>
                e.Kind == PackAuditAnchor.SignatureKind &&
                e.Detail.Contains($"pack={packId} ") &&
                e.Detail.Contains($"compiled_seq={anchored.Seq} "));
            if (sigRecord is null)
            { reason = $"pack '{packId}'s anchoring record is keyed ({PackAuditAnchor.SchemeMarker}) but NO compliance_pack_signature record names its position (seq {anchored.Seq}) — a position-less keyed pack record refuses by name; an appended record without the custodied signature is not an anchor (W37)"; return false; }
            var sigToken = ExtractToken(sigRecord.Detail, "pack_sig=");
            var fpToken = ExtractToken(sigRecord.Detail, "pack_key_fp=");
            byte[] signature;
            try { signature = Convert.FromBase64String(sigToken ?? ""); }
            catch { reason = $"pack '{packId}'s signature record carries an unreadable pack_sig — verification refuses by name (W37)"; return false; }
            if (signature.Length != 64)
            { reason = $"pack '{packId}'s signature record carries {signature.Length} bytes — an Ed25519 signature is exactly 64; verification refuses by name (W37)"; return false; }
            // Rotation discipline: judge the signature under the
            // pin it names — the current pin, or the archived
            // (rotated-out) pin in the install root.
            var keyDir = _packSigning.KeyDirectory;
            var currentPin = PointerSigningCustody.ReadPin(keyDir);
            byte[]? pin = null;
            if (fpToken is not null && currentPin is not null &&
                string.Equals(PointerSigningCustody.FingerprintOf(currentPin), fpToken, StringComparison.OrdinalIgnoreCase))
                pin = currentPin;
            else if (fpToken is not null)
                pin = PointerSigningCustody.ReadArchivedPin(keyDir, fpToken);
            if (pin is null)
            { reason = $"pack '{packId}'s signature names key fingerprint '{fpToken ?? "(none)"}' but neither the current install-root pin nor its archive in '{keyDir}' carries that key — verification refuses by name (W37)"; return false; }
            var payload = PackAuditAnchor.BuildPackPayload(packId, anchoredHash, anchored.Seq, anchored.Hash);
            if (!Ed25519.Verify(pin, payload, signature))
            { reason = $"pack '{packId}'s POSITION-BOUND signature does NOT verify over the pack hash + the anchoring record's position (seq {anchored.Seq}, hash {anchored.Hash}) under the install-root pin (fingerprint {PointerSigningCustody.FingerprintOf(pin)}) — a data-dir-only append-replay or forged anchor is refused at this leg (W37)"; return false; }
            reason = $"pack content hash matches the audit-anchored hash AND its position-bound signature verifies under the install-root pin (fingerprint {PointerSigningCustody.FingerprintOf(pin)}) over the anchoring record's position (seq {anchored.Seq}) — keyed anchor (W37)";
            return true;
        }
        if (keyingBegun)
        { reason = $"pack '{packId}'s anchoring record is LEGACY-UNKEYED-PACK (no {PackAuditAnchor.SchemeMarker}, no position-bound signature) but pack keying has begun — a position-less pack record after first keying refuses by name, never a silent acceptance (W37, the W17 pattern)"; return false; }
        reason = "pack content hash matches the hash anchored in the verified audit chain at compile time — LEGACY-UNKEYED-PACK posture (pre-W37 pack: no pack keying has begun, so the unkeyed hash anchor alone decides, named)";
        return true;
    }

    private static string? ExtractToken(string detail, string marker)
    {
        var i = detail.IndexOf(marker, StringComparison.Ordinal);
        if (i < 0) return null;
        var rest = detail.AsSpan(i + marker.Length);
        var end = rest.IndexOf(' ');
        return (end < 0 ? rest : rest[..end]).ToString();
    }

    // ---- treatments ------------------------------------------------------------

    public (bool Ok, string Reason, ComplianceTreatment? Treatment) RecordTreatment(
        string frameworkId, string controlId, string scopeId,
        string owner, string treatment, DateTimeOffset targetDateUtc, string recordedBy)
    {
        var now = _now();
        // D38-F9: a treatment treats a GAP. Before this fix a plan
        // could be recorded for a control id that does not exist,
        // or for a control that is currently satisfied — pre-arming
        // it so a later failure surfaced as gap_treated the instant
        // it appeared, with no human decision at that moment.
        // Refuse both: the control must exist in the admitted
        // checklist, and if a pack for this framework+scope stands
        // in history with the control satisfied, there is no gap
        // to treat. (Residual, named: a control satisfied in fact
        // but never compiled has no pack to check against — the
        // existence check still applies.)
        var contentPack = ContentPacks.Get(frameworkId);
        (bool Ok, string Reason, ComplianceTreatment? Treatment) RefuseTreatment(string reason)
        {
            _audit.Append("compliance_treatment_refused", recordedBy,
                $"framework={frameworkId} control={controlId} scope={scopeId} owner={owner} target={targetDateUtc:O} reason={reason}", now);
            return (false, reason, null);
        }
        if (contentPack is null)
            return RefuseTreatment($"no content pack admitted for framework '{frameworkId}' — there is no checklist whose gap this could treat; refused");
        if (!contentPack.Controls.Any(c => string.Equals(c.ControlId, controlId, StringComparison.OrdinalIgnoreCase)))
            return RefuseTreatment($"control '{controlId}' does not exist in framework '{frameworkId}' — a treatment for a nonexistent control pre-arms a future gap; refused");
        var latest = LatestPack(frameworkId, scopeId);
        var latestVerdict = latest?.Verdicts.FirstOrDefault(v =>
            string.Equals(v.ControlId, controlId, StringComparison.OrdinalIgnoreCase));
        if (latestVerdict is not null && !latestVerdict.IsGap)
            return RefuseTreatment($"control '{controlId}' is SATISFIED in the latest pack for {frameworkId}@{scopeId} — a treatment treats a gap, and there is none; refused");
        var result = Treatments.Record(frameworkId, controlId, scopeId, owner, treatment, recordedBy, targetDateUtc, now);
        _audit.Append(result.Ok ? "compliance_treatment_recorded" : "compliance_treatment_refused", recordedBy,
            $"framework={frameworkId} control={controlId} scope={scopeId} owner={owner} target={targetDateUtc:O} reason={result.Reason}", now);
        return result;
    }

    // ---- movement -----------------------------------------------------------------

    /// <summary>Diff two packs from history. D38-F8: same framework
    /// + scope is now ENFORCED by the differ (it throws
    /// ArgumentException naming the mismatch) — it was previously
    /// only "expected", and a cross-scope diff reported the other
    /// site's gaps as closed.</summary>
    public CompliancePackDiff DiffPacks(string earlierPackId, string laterPackId, string requestedBy)
    {
        var earlier = GetPack(earlierPackId) ?? throw new ArgumentException($"unknown pack '{earlierPackId}'", nameof(earlierPackId));
        var later = GetPack(laterPackId) ?? throw new ArgumentException($"unknown pack '{laterPackId}'", nameof(laterPackId));
        var diff = CompliancePackDiffer.Compare(earlier, later);
        _audit.Append("compliance_movement_computed", requestedBy,
            $"earlier={earlierPackId} later={laterPackId} summary={diff.Summary}", _now());
        return diff;
    }
}

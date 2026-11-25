using System.Text;

namespace Acp.Shared.Compliance;

// =====================================================================
// RMM-09 — the pure compiler + movement differ + plain-text
// rendering. The compiler is a pure function of (content pack,
// fact set, treatments, staleness policy, now): given the same
// inputs it produces the same pack, and there is NO input that
// produces "satisfied" without a fresh, passing, in-scope fact —
// that is the honesty rule enforced as code, not as a convention.
//
// Scope discipline: facts whose ScopeId differs from the fact
// set's scope are IGNORED (counted in the provenance notes as
// excluded), and a device-scoped fact evidences only the device it
// names. Cross-scope / cross-device evidence bleed is therefore
// impossible at this layer even if a caller assembles a sloppy
// fact set; the destruction tests prove it.
// =====================================================================

public static class ComplianceCompiler
{
    public static CompliancePack Compile(
        ComplianceContentPack contentPack,
        ComplianceFactSet factSet,
        TreatmentStore treatments,
        ComplianceStalenessPolicy staleness,
        DateTimeOffset now,
        string generatedBy,
        string kind = PackKinds.EvidencePack,
        string? siteLabel = null)
    {
        ArgumentNullException.ThrowIfNull(contentPack);
        ArgumentNullException.ThrowIfNull(factSet);
        ArgumentNullException.ThrowIfNull(treatments);
        staleness ??= ComplianceStalenessPolicy.Default;

        var inScope = factSet.Facts.Where(f => string.Equals(f.ScopeId, factSet.ScopeId, StringComparison.OrdinalIgnoreCase)).ToList();
        var excluded = factSet.Facts.Count - inScope.Count;

        var notes = new List<string>
        {
            $"fact set {factSet.ContentHash[..16]}…: {factSet.DeviceIds.Count} device(s), {inScope.Count} in-scope fact(s) for scope '{factSet.ScopeId}'",
            // D38-F7: the windows this pack is judged under, on its
            // face (and in its content hash via the pack fields).
            $"freshness windows applied: facts {staleness.DefaultDays}d, inventory {staleness.InventoryDays}d (policy content at compile time)",
        };
        if (excluded > 0)
            notes.Add($"EXCLUDED: {excluded} fact(s) named a different scope and were not used as evidence for this pack");
        foreach (var k in ComplianceFactKinds.All.OrderBy(x => x, StringComparer.Ordinal))
        {
            var ofKind = inScope.Where(f => f.Kind == k).ToList();
            if (ofKind.Count == 0) notes.Add($"no '{k}' facts were collected for this scope — controls requiring them are gaps (missing_fact)");
            else notes.Add($"'{k}': {ofKind.Count} fact(s), oldest observation {ofKind.Min(f => f.ObservedUtc):O}");
        }

        // D38-F12: index the in-scope facts ONCE per compile —
        // device facts by (kind, device), scope facts by kind —
        // instead of filtering the whole list for every
        // (control × device) pair: O(facts + controls × devices).
        var deviceFacts = new Dictionary<(string Kind, string DeviceId), ComplianceFact>();
        var scopeFacts = new Dictionary<string, ComplianceFact>(StringComparer.Ordinal);
        foreach (var f in inScope)
        {
            if (f.DeviceId is { } dev)
            {
                var key = (f.Kind, dev.ToUpperInvariant());
                if (!deviceFacts.TryGetValue(key, out var cur) || f.ObservedUtc > cur.ObservedUtc)
                    deviceFacts[key] = f;
            }
            else if (!scopeFacts.TryGetValue(f.Kind, out var curS) || f.ObservedUtc > curS.ObservedUtc)
                scopeFacts[f.Kind] = f;
        }

        var verdicts = new List<ControlVerdict>();
        foreach (var control in contentPack.Controls.OrderBy(c => c.ControlId, StringComparer.Ordinal))
            verdicts.Add(Evaluate(control, factSet, deviceFacts, scopeFacts, treatments, contentPack.FrameworkId, staleness, now));

        return new CompliancePack(
            CompliancePack.IdFor(contentPack.FrameworkId, factSet.ScopeId, factSet.ContentHash, now),
            kind, contentPack.FrameworkId, contentPack.Id, contentPack.Revision, contentPack.ContentHash,
            factSet.ScopeId, siteLabel, now, generatedBy, factSet.ContentHash, verdicts, notes,
            staleness.DefaultDays, staleness.InventoryDays);
    }

    /// <summary>D38-F3: a fact dated further into the future than
    /// honest clock skew is not fresh — it is poison. It is judged
    /// exactly like a stale fact (it evidences nothing about the
    /// present) in both evaluation paths.</summary>
    private static bool IsFuturePoisoned(ComplianceFact fact, DateTimeOffset now) =>
        fact.ObservedUtc > now + ComplianceLimits.MaxFutureSkew;

    private static ControlVerdict Evaluate(
        ComplianceControl control, ComplianceFactSet factSet,
        IReadOnlyDictionary<(string Kind, string DeviceId), ComplianceFact> deviceFacts,
        IReadOnlyDictionary<string, ComplianceFact> scopeFacts,
        TreatmentStore treatments, string frameworkId, ComplianceStalenessPolicy staleness, DateTimeOffset now)
    {
        ControlVerdict Raw(string outcome, string? gapKind, string reason,
            IReadOnlyList<string> refs, IReadOnlyList<string> failingDevices, DateTimeOffset? observed)
        {
            // Treatment overlay: a gap with a LIVE plan is gap_treated;
            // an EXPIRED plan leaves the gap open and says so. A
            // treatment never touches a satisfied verdict.
            var treatmentId = (string?)null;
            if (outcome == ControlOutcomes.Gap)
            {
                var t = treatments.Get(frameworkId, control.ControlId, factSet.ScopeId);
                if (t is not null)
                {
                    if (t.IsExpired(now))
                        reason += $" | treatment '{t.TreatmentId}' (owner {t.Owner}) EXPIRED {t.TargetDateUtc:O} — gap reopened";
                    else
                    {
                        outcome = ControlOutcomes.GapTreated;
                        treatmentId = t.TreatmentId;
                        reason += $" | under treatment '{t.TreatmentId}': owner={t.Owner} target={t.TargetDateUtc:O} plan={t.Treatment}";
                    }
                }
            }
            return new ControlVerdict(control.ControlId, control.FrameworkRef, control.Title,
                control.RequiredFactKind, control.Rule, outcome, gapKind, reason, refs, failingDevices, observed, treatmentId);
        }

        var window = staleness.WindowFor(control.RequiredFactKind);

        if (ComplianceFactKinds.IsDeviceScoped(control.RequiredFactKind))
        {
            if (factSet.DeviceIds.Count == 0)
                return Raw(ControlOutcomes.Gap, GapKinds.MissingFact,
                    "scope has NO devices — there is nothing this control could be evidenced against (vacuous satisfaction is refused)",
                    Array.Empty<string>(), Array.Empty<string>(), null);

            var missing = new List<string>(); var stale = new List<string>(); var failing = new List<string>();
            var refs = new List<string>(); DateTimeOffset? oldest = null;
            foreach (var deviceId in factSet.DeviceIds)
            {
                var fact = deviceFacts.TryGetValue((control.RequiredFactKind, deviceId.ToUpperInvariant()), out var df) ? df : null;
                if (fact is null) { missing.Add(deviceId); continue; }
                refs.Add(fact.EvidenceRef);
                if (oldest is null || fact.ObservedUtc < oldest) oldest = fact.ObservedUtc;
                if (fact.UpstreamStale || IsFuturePoisoned(fact, now) || now - fact.ObservedUtc > window) stale.Add(deviceId);
                else if (!fact.Passing) failing.Add(deviceId);
            }
            var badDevices = missing.Concat(stale).Concat(failing)
                .OrderBy(d => d, StringComparer.Ordinal).ToList();
            if (failing.Count > 0)
                return Raw(ControlOutcomes.Gap, GapKinds.FailingFact,
                    $"fact '{control.RequiredFactKind}' is present and fresh but FAILING for: {string.Join(", ", failing)}" +
                    (missing.Count > 0 ? $" | also missing for: {string.Join(", ", missing)}" : "") +
                    (stale.Count > 0 ? $" | also stale for: {string.Join(", ", stale)}" : ""),
                    refs, badDevices, oldest);
            if (missing.Count > 0)
                return Raw(ControlOutcomes.Gap, GapKinds.MissingFact,
                    $"no '{control.RequiredFactKind}' fact was collected for: {string.Join(", ", missing)} — a control with no backing fact is a gap, never satisfied by assertion" +
                    (stale.Count > 0 ? $" | also stale for: {string.Join(", ", stale)}" : ""),
                    refs, badDevices, oldest);
            if (stale.Count > 0)
                return Raw(ControlOutcomes.Gap, GapKinds.StaleFact,
                    $"'{control.RequiredFactKind}' facts for: {string.Join(", ", stale)} are older than the {window.TotalDays:F0}d freshness window, future-dated beyond clock skew, or their source names itself stale — stale facts evidence nothing about the present",
                    refs, badDevices, oldest);
            return Raw(ControlOutcomes.Satisfied, null,
                $"every device in scope ({factSet.DeviceIds.Count}) carries a fresh, passing '{control.RequiredFactKind}' fact",
                refs, Array.Empty<string>(), oldest);
        }

        // Scope-level fact kinds.
        var scopeFact = scopeFacts.TryGetValue(control.RequiredFactKind, out var sf) ? sf : null;
        if (scopeFact is null)
            return Raw(ControlOutcomes.Gap, GapKinds.MissingFact,
                $"no '{control.RequiredFactKind}' fact was collected for scope '{factSet.ScopeId}' — a control with no backing fact is a gap, never satisfied by assertion",
                Array.Empty<string>(), Array.Empty<string>(), null);
        var srefs = new[] { scopeFact.EvidenceRef };
        if (IsFuturePoisoned(scopeFact, now))
            return Raw(ControlOutcomes.Gap, GapKinds.StaleFact,
                $"'{control.RequiredFactKind}' fact is dated in the FUTURE ({scopeFact.ObservedUtc:O}, beyond clock skew) — a future-dated observation evidences nothing and is judged stale, never fresh",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc);
        if (scopeFact.UpstreamStale)
            return Raw(ControlOutcomes.Gap, GapKinds.StaleFact,
                $"'{control.RequiredFactKind}' fact's source names itself STALE: {scopeFact.UpstreamStaleNote ?? scopeFact.Detail}",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc);
        if (now - scopeFact.ObservedUtc > window)
            return Raw(ControlOutcomes.Gap, GapKinds.StaleFact,
                $"'{control.RequiredFactKind}' fact was observed {scopeFact.ObservedUtc:O}, older than the {window.TotalDays:F0}d freshness window — stale facts evidence nothing about the present",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc);
        var passes = control.Rule switch
        {
            ComplianceRules.VulnNoOverdue =>
                ComplianceRules.TryReadVulnCounts(scopeFact.Detail, out var od, out _) ? od == 0 : (bool?)null,
            ComplianceRules.VulnNoKevOpen =>
                ComplianceRules.TryReadVulnCounts(scopeFact.Detail, out _, out var kev) ? kev == 0 : (bool?)null,
            _ => scopeFact.Passing,
        };
        if (passes is null)
            return Raw(ControlOutcomes.Gap, GapKinds.FailingFact,
                $"'{control.RequiredFactKind}' fact is present but its detail cannot be evaluated against rule '{control.Rule}' — cannot evidence this control",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc);
        return passes.Value
            ? Raw(ControlOutcomes.Satisfied, null,
                $"'{control.RequiredFactKind}' fact (observed {scopeFact.ObservedUtc:O}) passes rule '{control.Rule}': {scopeFact.Detail}",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc)
            : Raw(ControlOutcomes.Gap, GapKinds.FailingFact,
                $"'{control.RequiredFactKind}' fact is present and fresh but FAILING under rule '{control.Rule}': {scopeFact.Detail}",
                srefs, Array.Empty<string>(), scopeFact.ObservedUtc);
    }
}

/// <summary>Pack-over-pack movement. See CompliancePackDiff for the
/// completeness property this differ maintains by construction.</summary>
public static class CompliancePackDiffer
{
    public static CompliancePackDiff Compare(CompliancePack earlier, CompliancePack later)
    {
        ArgumentNullException.ThrowIfNull(earlier);
        ArgumentNullException.ThrowIfNull(later);
        // D38-F8: a movement diff is only meaningful within one
        // framework + scope. Before this fix, diffing hipaa@siteA
        // (gaps) against hipaa@siteB (clean) reported every gap as
        // "closed" with 0 unaccounted — cross-site movement that
        // never happened. Refuse, by name.
        if (!string.Equals(earlier.FrameworkId, later.FrameworkId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"cannot diff packs of different frameworks ('{earlier.FrameworkId}' vs '{later.FrameworkId}') — movement across frameworks is meaningless and refuses", nameof(later));
        if (!string.Equals(earlier.ScopeId, later.ScopeId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"cannot diff packs of different scopes ('{earlier.ScopeId}' vs '{later.ScopeId}') — one site's clean pack does not close another site's gaps; refused", nameof(later));
        var e = IndexVerdicts(earlier);
        var l = IndexVerdicts(later);
        var union = e.Keys.Union(l.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.Ordinal).ToList();
        var movements = new List<ControlMovement>();
        foreach (var id in union)
        {
            var hasE = e.TryGetValue(id, out var ev);
            var hasL = l.TryGetValue(id, out var lv);
            if (hasE && !hasL)
            {
                movements.Add(new ControlMovement(id, ev!.Outcome, "absent", MovementCategories.ControlRemoved,
                    $"control '{id}' was in pack {earlier.PackId} and is GONE from {later.PackId} — named here, never silently dropped from the movement record"));
                continue;
            }
            if (!hasE && hasL)
            {
                movements.Add(lv!.IsGap
                    ? new ControlMovement(id, "absent", lv.Outcome, MovementCategories.Opened,
                        $"new control '{id}' enters as a GAP ({lv.GapKind}): {lv.Reason}")
                    : new ControlMovement(id, "absent", lv.Outcome, MovementCategories.NewSatisfied,
                        $"new control '{id}' enters satisfied"));
                continue;
            }
            // D38-F5: same id, different mapping — the control was
            // hollowed out (or honestly re-pointed) between packs.
            // That movement is named FIRST: a remapped control must
            // never be reported as a closed gap.
            if (ev.RequiredFactKind != lv.RequiredFactKind || ev.Rule != lv.Rule ||
                ev.FrameworkRef != lv.FrameworkRef || ev.Title != lv.Title)
            {
                movements.Add(new ControlMovement(id, ev.Outcome, lv.Outcome, MovementCategories.ControlRemapped,
                    $"control '{id}' was REMAPPED between packs: fact kind '{ev.RequiredFactKind}' → '{lv.RequiredFactKind}', rule '{ev.Rule}' → '{lv.Rule}', ref '{ev.FrameworkRef}' → '{lv.FrameworkRef}' — its gap/satisfied movement across the remap is not comparable and is NOT reported as closed or opened"));
                continue;
            }
            var from = ev!.Outcome; var to = lv!.Outcome;
            if (!ev.IsGap && !lv.IsGap)
                movements.Add(new ControlMovement(id, from, to, MovementCategories.StillSatisfied, "satisfied in both packs"));
            else if (ev.IsGap && !lv.IsGap)
                movements.Add(new ControlMovement(id, from, to, MovementCategories.Closed,
                    $"gap closed ({ev.GapKind}) — now evidenced: {lv.Reason}"));
            else if (!ev.IsGap && lv.IsGap)
                movements.Add(new ControlMovement(id, from, to, MovementCategories.Opened,
                    $"NEWLY OPENED GAP ({lv.GapKind}): {lv.Reason}"));
            else if (ev.TreatmentId != lv.TreatmentId || ev.Outcome != lv.Outcome)
                movements.Add(new ControlMovement(id, from, to, MovementCategories.TreatmentChanged,
                    $"gap persists ({lv.GapKind}); treatment state moved {from} → {to}"));
            else
                movements.Add(new ControlMovement(id, from, to, MovementCategories.StillOpen,
                    $"gap persists ({lv.GapKind}) across {(later.GeneratedUtc - earlier.GeneratedUtc).TotalDays:F1} days: {lv.Reason}"));
        }
        return new CompliancePackDiff(later.FrameworkId, later.ScopeId, earlier.PackId, later.PackId,
            earlier.GeneratedUtc, later.GeneratedUtc, movements)
        { UnionControlCount = union.Count };
    }

    /// <summary>D38-F8: index a pack's verdicts by control id,
    /// refusing a hand-built pack with duplicate ids BY NAME
    /// instead of dying inside ToDictionary with a bare
    /// ArgumentException that names neither pack nor control.</summary>
    private static Dictionary<string, ControlVerdict> IndexVerdicts(CompliancePack pack)
    {
        var byId = new Dictionary<string, ControlVerdict>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in pack.Verdicts)
            if (!byId.TryAdd(v.ControlId, v))
                throw new ArgumentException(
                    $"pack '{pack.PackId}' carries control id '{v.ControlId}' more than once — a diff over duplicate controls cannot account honestly; refused", nameof(pack));
        return byId;
    }
}

/// <summary>The human-readable rendering AS DATA: a plain-text
/// document produced from the structured pack (the pretty document
/// is design-phase). Every gap is named with its kind; every
/// control carries its oldest backing observation, so staleness is
/// on the face of the rendering, not buried in the JSON.</summary>
public static class CompliancePackRenderer
{
    public static string RenderPlainText(CompliancePack pack)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"COMPLIANCE EVIDENCE PACK — {pack.FrameworkId.ToUpperInvariant()} ({(pack.Kind == PackKinds.SiteAssessment ? "SITE ASSESSMENT" : "evidence pack")})");
        sb.AppendLine($"pack={pack.PackId} contentHash={pack.ContentHash}");
        sb.AppendLine($"scope={pack.ScopeId}{(pack.SiteLabel is not null ? $" site={pack.SiteLabel}" : "")} generated={pack.GeneratedUtc:O} by={pack.GeneratedBy}");
        sb.AppendLine($"checklist={pack.ContentPackId} r{pack.ContentPackRevision} hash={pack.ContentPackHash}");
        sb.AppendLine($"freshness windows: facts {pack.StalenessDefaultDays}d, inventory {pack.StalenessInventoryDays}d");
        sb.AppendLine($"facts={pack.FactSetHash}");
        sb.AppendLine(pack.Headline);
        sb.AppendLine();
        sb.AppendLine("PROVENANCE / STALENESS (on the face, per the honesty rule):");
        foreach (var n in pack.ProvenanceNotes) sb.AppendLine($"  - {n}");
        sb.AppendLine();
        sb.AppendLine("CONTROLS:");
        foreach (var v in pack.Verdicts.OrderBy(v => v.ControlId, StringComparer.Ordinal))
        {
            var age = v.FactObservedUtc is { } o ? $"oldestFact={o:O} (age {(pack.GeneratedUtc - o).TotalDays:F1}d)" : "oldestFact=NONE";
            sb.AppendLine($"  [{v.Outcome}] {v.ControlId} ({v.FrameworkRef}) — {v.Title}");
            sb.AppendLine($"      fact={v.RequiredFactKind} {age} evidence={string.Join(",", v.EvidenceRefs)}");
            sb.AppendLine($"      {v.Reason}");
        }
        if (pack.GapCount > 0)
        {
            sb.AppendLine();
            sb.AppendLine("GAP ANALYSIS (what's missing, named by kind):");
            foreach (var g in pack.Gaps.OrderBy(g => g.ControlId, StringComparer.Ordinal))
                sb.AppendLine($"  - {g.ControlId}: {g.GapKind} — {g.Reason}");
        }
        return sb.ToString();
    }

    public static string RenderDiffPlainText(CompliancePackDiff diff)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"COMPLIANCE MOVEMENT — {diff.FrameworkId} @ {diff.ScopeId}");
        sb.AppendLine(diff.Summary);
        foreach (var m in diff.Movements.OrderBy(m => m.Category, StringComparer.Ordinal).ThenBy(m => m.ControlId, StringComparer.Ordinal))
            sb.AppendLine($"  [{m.Category}] {m.ControlId}: {m.FromOutcome} → {m.ToOutcome} — {m.Detail}");
        return sb.ToString();
    }
}

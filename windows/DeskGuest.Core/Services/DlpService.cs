using System.Text;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Dlp;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-32 — DLP service: the Core surface over the Shared model.
// Every operation gates on rmm.dlp.enabled (seeded OFF). Scans run
// over a FROZEN snapshot of the definition; every enumerated file is
// scope-checked individually (a source that yields a path outside
// the declared scope has that file refused + named, never scanned).
// Scan definitions, starts, completions, findings READS and egress
// blocks are audited acts in the chained audit. Findings reads are
// RBAC-scoped; a refused read is audited too.
// =====================================================================

/// <summary>One file offered to a scan: path + content. Content is
/// read on-device and never leaves the scan loop except as counts +
/// a masked excerpt inside the findings chain.</summary>
public sealed record DlpFileItem(string FullPath, string Content, long SizeBytes);

/// <summary>The scan source seam. The directory implementation reads
/// declared roots on the endpoint; tests use the in-memory source.</summary>
public interface IDlpFileSource
{
    IEnumerable<DlpFileItem> Enumerate(DlpScanDefinition snapshot);
    IReadOnlyList<string> Skipped { get; }
}

public sealed class InMemoryDlpFileSource : IDlpFileSource
{
    private readonly IReadOnlyList<DlpFileItem> _files;
    private readonly Action? _onEnumerate;
    public InMemoryDlpFileSource(IEnumerable<DlpFileItem> files, Action? onEnumerate = null)
    {
        _files = files.ToList();
        _onEnumerate = onEnumerate;
    }
    public IReadOnlyList<string> Skipped => Array.Empty<string>();
    public IEnumerable<DlpFileItem> Enumerate(DlpScanDefinition snapshot)
    {
        _onEnumerate?.Invoke();
        foreach (var f in _files) yield return f;
    }
}

/// <summary>Endpoint directory source: walks ONLY the snapshot's
/// declared roots, honours the extension scope, skips oversize and
/// binary-looking files (named in Skipped, counted in the summary —
/// a skipped file is a named gap, never silent coverage).</summary>
public sealed class DirectoryDlpFileSource : IDlpFileSource
{
    private readonly List<string> _skipped = new();
    public IReadOnlyList<string> Skipped => _skipped;

    public IEnumerable<DlpFileItem> Enumerate(DlpScanDefinition snapshot)
    {
        _skipped.Clear();
        // D38 F12: never recurse through reparse points (junctions /
        // symlinks) — content outside the declared scope must not be
        // scanned under an in-scope path string. Reparse-point
        // entries are skipped by the enumerator itself, and a root
        // that IS a reparse point is refused by name.
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Hidden | FileAttributes.System,
        };
        foreach (var root in snapshot.RootPaths)
        {
            var dir = DlpScanDefinition.NormalizeRoot(root);
            if (!Directory.Exists(dir)) { _skipped.Add($"root '{dir}' does not exist on this endpoint — skipped (named)"); continue; }
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
            { _skipped.Add($"root '{dir}' is a reparse point (junction/symlink) — refused (named): a scan's declared scope is the real directory, not a link out of it"); continue; }
            foreach (var path in Directory.EnumerateFiles(dir, "*", options))
            {
                if (!snapshot.ExtensionInScope(path)) continue;
                var info = new FileInfo(path);
                // D38 F6: skip notes carry the MASKED path — a file
                // name can itself be the sensitive value.
                if (info.Length > DlpLimits.MaxFileBytes) { _skipped.Add($"'{DlpMasking.MaskPath(path)}' is {info.Length} bytes over the {DlpLimits.MaxFileBytes}-byte scan cap — skipped (named)"); continue; }
                string content;
                try { content = File.ReadAllText(path, Encoding.UTF8); }
                catch (Exception ex) { _skipped.Add($"'{DlpMasking.MaskPath(path)}' could not be read ({ex.GetType().Name}) — skipped (named)"); continue; }
                if (content.Contains('\0')) { _skipped.Add($"'{DlpMasking.MaskPath(path)}' looks binary (NUL bytes) — skipped (named): text classifiers do not scan binary content"); continue; }
                yield return new DlpFileItem(path, content, info.Length);
            }
        }
    }
}

public sealed record DlpScanSummary(
    string ScanId, string MachineId, string DefinitionHash,
    int FilesScanned, int FilesWithFindings, int TotalMatches,
    int FilesSkippedOutOfScope, IReadOnlyList<string> Notes,
    int FilesSkippedBySource = 0, bool Incomplete = false);

public sealed record DlpEgressApplyResult(bool Applied, string Detail);

/// <summary>The egress enforcement seam (RMM-30 applier pattern):
/// an applier that cannot act on a channel reports Applied=false
/// with the reason — a block decision without an applier is a policy
/// verdict, never a claimed enforcement.</summary>
public interface IDlpEgressApplier
{
    DlpEgressApplyResult Apply(string channel, DlpEgressDecision decision);
}

public sealed class UnavailableDlpEgressApplier : IDlpEgressApplier
{
    public DlpEgressApplyResult Apply(string channel, DlpEgressDecision decision) =>
        new(false, $"no egress enforcer is wired for channel '{channel}' on this host — decision '{decision.Disposition}' was computed but NOT enforced (named remainder: host wiring)");
}

public sealed class RecordingDlpEgressApplier : IDlpEgressApplier
{
    public List<(string Channel, DlpEgressDecision Decision)> Applied { get; } = new();
    public DlpEgressApplyResult Apply(string channel, DlpEgressDecision decision)
    {
        Applied.Add((channel, decision));
        return new DlpEgressApplyResult(true, $"egress decision '{decision.Disposition}' applied on channel '{channel}'");
    }
}

public sealed class DlpService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly IDlpAlertSink _alertSink;
    private readonly IDlpEgressApplier _egressApplier;
    private readonly Func<string, IDeviceFacts?> _factsByMachine;
    private readonly Func<DateTimeOffset> _now;

    public DlpFindingStore Findings { get; } = new();

    public DlpService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        IDlpAlertSink alertSink,
        IDlpEgressApplier egressApplier,
        Func<string, IDeviceFacts?> factsByMachine,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _alertSink = alertSink ?? throw new ArgumentNullException(nameof(alertSink));
        _egressApplier = egressApplier ?? throw new ArgumentNullException(nameof(egressApplier));
        _factsByMachine = factsByMachine ?? throw new ArgumentNullException(nameof(factsByMachine));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>The actor string written into the chained audit —
    /// D38 F5: a caller-supplied actor is NEVER written verbatim
    /// when it is missing or over bounds; the audit records a bounded
    /// description instead of attacker-controlled unbounded text.</summary>
    private static string AuditActor(string? actor)
    {
        if (string.IsNullOrWhiteSpace(actor)) return "dlp-service";
        var trimmed = actor.Trim();
        return trimmed.Length > DlpLimits.MaxActorLength
            ? $"<over-length actor: {trimmed.Length} chars>"
            : trimmed;
    }

    private (ResolvedDlpPolicy? Policy, string Reason) Gate(string machineId, string op)
    {
        var facts = _factsByMachine(machineId);
        if (facts is null)
            return (null, $"no device facts for '{machineId}' — {op} refuses (policy cannot be evaluated; fail closed)");
        var resolved = DlpResolver.Resolve(_policy, facts);
        if (!resolved.FeatureEnabled)
            return (null, $"DLP is disabled by policy for machine '{machineId}' ({DlpKeys.FeatureEnabled}, seeded OFF) — {op} refuses: no content inspection runs without explicit enable");
        return (resolved, "ok");
    }

    public (ResolvedDlpPolicy? Policy, string Reason) ResolvePolicy(string machineId)
    {
        var facts = _factsByMachine(machineId);
        if (facts is null) return (null, $"no device facts for '{machineId}' — policy resolution refuses (fail closed)");
        var resolved = DlpResolver.Resolve(_policy, facts);
        return (resolved, $"resolved DLP for machine '{machineId}': enabled={resolved.FeatureEnabled}, classifiers=[{string.Join(", ", resolved.Classifiers.Select(c => c.Id + " v" + c.Version))}], retention={resolved.RetentionDays}d, readers={resolved.Access.ReadersCount()}");
    }

    /// <summary>The endpoint-visible view (no-hidden-inspection).
    /// Available whether DLP is on or off — the user can always see
    /// the state of inspection on their own machine.</summary>
    public (DlpEffectiveView? View, string Reason) EffectiveView(string machineId)
    {
        var facts = _factsByMachine(machineId);
        if (facts is null) return (null, $"no device facts for '{machineId}' — effective view refuses (fail closed)");
        var resolved = DlpResolver.Resolve(_policy, facts);
        return (DlpEffectiveView.Build(machineId, resolved), "ok");
    }

    /// <summary>Run one discovery scan. Audited acts: definition
    /// admission, start, completion. The scan runs over the frozen
    /// snapshot; each file is individually scope-checked (path AND
    /// extension) against the SNAPSHOT — a source yielding an
    /// out-of-scope path has it refused + counted, never scanned.</summary>
    public (DlpScanSummary? Summary, string Reason) RunScan(
        string machineId, DlpScanDefinition? definition, IDlpFileSource? source, string actor)
    {
        var now = _now();
        var (policy, gateReason) = Gate(machineId, "discovery scan");
        if (policy is null)
        {
            _audit.Append("dlp_scan_refused", AuditActor(actor),
                $"machine={machineId} scan={definition?.Id} reason={gateReason}", now);
            return (null, gateReason);
        }
        if (definition is null) return (null, "no scan definition presented — scan refused");
        if (definition.Validate() is { } invalid)
        {
            _audit.Append("dlp_scan_refused", AuditActor(actor),
                $"machine={machineId} scan={definition.Id} reason={invalid}", now);
            return (null, invalid);
        }
        if (!string.Equals(definition.MachineId, machineId, StringComparison.OrdinalIgnoreCase))
            return (null, $"the scan definition names machine '{definition.MachineId}' inside a scan for '{machineId}' — refused");
        if (source is null) return (null, "no file source presented — scan refused");

        // Classifier check: the definition may only name classifiers
        // the resolved policy carries (policy is the authority on
        // what may be scanned for).
        var byId = policy.Classifiers.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var unknown = definition.ClassifierIds.Where(id => !byId.ContainsKey(id.Trim())).ToList();
        if (unknown.Count > 0)
            return (null, $"scan definition names classifier(s) not carried by policy [{string.Join(", ", unknown)}] — refused: a scan cannot widen beyond policy's classifier set");

        var snapshot = definition.Snapshot();
        var hashAtStart = snapshot.DefinitionHash;
        _audit.Append("dlp_scan_defined", AuditActor(actor),
            $"machine={machineId} scan={snapshot.Id} definitionHash={hashAtStart} roots=[{string.Join(", ", snapshot.RootPaths)}] classifiers=[{string.Join(", ", snapshot.ClassifierIds)}] by={snapshot.CreatedBy}", now);
        Findings.RecordScanStarted(snapshot, now);
        _audit.Append("dlp_scan_started", AuditActor(actor),
            $"machine={machineId} scan={snapshot.Id} definitionHash={hashAtStart}", now);

        var filesScanned = 0; var filesWithFindings = 0; var totalMatches = 0; var outOfScope = 0;
        var notes = new List<string>();
        var timedOutClassifiers = new List<string>();
        var scanFailed = false;
        // D38 F8: the scan ALWAYS closes its own chain — a classifier
        // timeout or a source failure marks the scan INCOMPLETE and
        // still records scan_completed + the audit completion, never
        // a dangling scan_started. Exception objects are never
        // logged: a RegexMatchTimeoutException carries the full file
        // content in its Input property.
        try
        {
            foreach (var file in source.Enumerate(snapshot))
            {
                if (!snapshot.PathInScope(file.FullPath) || !snapshot.ExtensionInScope(file.FullPath))
                {
                    outOfScope++;
                    notes.Add($"'{DlpMasking.MaskPath(file.FullPath)}' is OUTSIDE the declared scan scope — refused, not scanned (named)");
                    continue;
                }
                if (file.SizeBytes > DlpLimits.MaxFileBytes)
                {
                    outOfScope++;
                    notes.Add($"'{DlpMasking.MaskPath(file.FullPath)}' exceeds the scan size cap — skipped (named)");
                    continue;
                }
                filesScanned++;
                var fileHadFinding = false;
                foreach (var classifierId in snapshot.ClassifierIds)
                {
                    var classifier = byId[classifierId.Trim()];
                    IReadOnlyList<DlpMatch> matches;
                    try { matches = classifier.Find(file.Content); }
                    catch (RegexMatchTimeoutException)
                    {
                        if (!timedOutClassifiers.Contains(classifier.Id)) timedOutClassifiers.Add(classifier.Id);
                        continue; // this classifier's matches on this file are incomplete — named below, never a clean pass
                    }
                    if (matches.Count == 0) continue;
                    fileHadFinding = true;
                    totalMatches += Math.Min(matches.Count, DlpLimits.MaxMatchesPerFilePerClassifier);
                    Findings.RecordFinding(snapshot.Id, machineId, file.FullPath, classifier, matches, _now());
                }
                if (fileHadFinding) filesWithFindings++;
            }
        }
        catch (Exception ex)
        {
            scanFailed = true;
            notes.Add($"scan source failed mid-run ({ex.GetType().Name}) — the scan is INCOMPLETE (named, never presented as a clean pass)");
        }
        foreach (var skipped in source.Skipped) notes.Add(skipped);
        var sourceSkipped = source.Skipped.Count;
        foreach (var c in policy.Classifiers.OfType<AdminRegexClassifier>().Where(c => c.TimedOut))
        {
            if (!timedOutClassifiers.Contains(c.Id)) timedOutClassifiers.Add(c.Id);
            // D38 F7: the pattern is never echoed — classifier id only.
            notes.Add($"admin regex classifier '{c.Id}' TIMED OUT on at least one file — its matches on that content are incomplete (named, never presented as a clean pass)");
        }
        // D38 F2: incompleteness is a first-class completion fact —
        // it lands in the findings chain, the audit and an alert, not
        // only in summary notes.
        var incomplete = scanFailed || timedOutClassifiers.Count > 0 || sourceSkipped > 0;

        var completedAt = _now();
        Findings.RecordScanCompleted(snapshot.Id, machineId, filesScanned, filesWithFindings, totalMatches, outOfScope, completedAt,
            sourceSkipped: sourceSkipped, incomplete: incomplete);
        _audit.Append("dlp_scan_completed", AuditActor(actor),
            $"machine={machineId} scan={snapshot.Id} definitionHash={hashAtStart} files={filesScanned} withFindings={filesWithFindings} matches={totalMatches} outOfScopeRefused={outOfScope} sourceSkipped={sourceSkipped} incomplete={incomplete} timedOutClassifiers=[{string.Join(", ", timedOutClassifiers)}] scanFailed={scanFailed} findingsHead={Findings.HeadHash}", completedAt);
        if (incomplete)
            _alertSink.Raise(new DlpEvent(DlpAlertKind.ScanIncomplete, machineId, snapshot.Id, sourceSkipped,
                $"DLP discovery scan '{snapshot.Id}' on machine '{machineId}' was INCOMPLETE: {filesScanned} file(s) inspected, {sourceSkipped} skipped by the source, timeouts=[{string.Join(", ", timedOutClassifiers)}], sourceFailed={scanFailed} — its result is NOT a clean pass (counts only)",
                completedAt));
        if (filesWithFindings > 0)
            _alertSink.Raise(new DlpEvent(DlpAlertKind.ScanFindings, machineId, snapshot.Id, totalMatches,
                $"DLP discovery scan '{snapshot.Id}' on machine '{machineId}': {totalMatches} classified match(es) in {filesWithFindings} file(s) [classifiers: {string.Join(", ", snapshot.ClassifierIds)}] — counts only; findings are RBAC-scoped in the findings store",
                completedAt));

        var summary = new DlpScanSummary(snapshot.Id, machineId, hashAtStart,
            filesScanned, filesWithFindings, totalMatches, outOfScope, notes,
            FilesSkippedBySource: sourceSkipped, Incomplete: incomplete);
        return (summary, $"scan '{snapshot.Id}' completed on machine '{machineId}': {filesScanned} files scanned, {filesWithFindings} with findings, {totalMatches} matches, {outOfScope} out-of-scope refused/skipped (named), {sourceSkipped} skipped by the source{(incomplete ? ", INCOMPLETE — not a clean pass" : "")}");
    }

    /// <summary>Read findings — RBAC-scoped + audited. Both granted
    /// and refused reads land in the chained audit: who looked at the
    /// sensitive inventory is itself sensitive evidence.</summary>
    public (IReadOnlyList<DlpFindingRecord>? Records, string Reason) ReadFindings(string machineId, string? actor)
    {
        var now = _now();
        var facts = _factsByMachine(machineId);
        if (facts is null) return (null, $"no device facts for '{machineId}' — findings read refuses (fail closed)");
        var policy = DlpResolver.Resolve(_policy, facts);
        if (string.IsNullOrWhiteSpace(actor) || actor.Trim().Length > DlpLimits.MaxActorLength)
        {
            _audit.Append("dlp_findings_read_refused", AuditActor(actor),
                $"machine={machineId} reason=reader identity missing or over bounds", now);
            return (null, "a findings read needs a reader identity within bounds — refused");
        }
        if (!policy.Access.CanReadFindings(actor))
        {
            _audit.Append("dlp_findings_read_refused", actor.Trim(),
                $"machine={machineId} reason=actor '{actor.Trim()}' is not a policy-named findings reader ({DlpKeys.FindingsReaders}) — findings are RBAC-scoped and this refusal is audited", now);
            return (null, $"actor '{actor.Trim()}' is not a policy-named findings reader for machine '{machineId}' — read refused (audited)");
        }
        var records = Findings.Records.Where(r => r.MachineId == machineId).ToList();
        _audit.Append("dlp_findings_read", actor.Trim(),
            $"machine={machineId} records={records.Count} findings={records.Count(r => r.Kind == DlpFindingKinds.Finding)} chainHead={Findings.HeadHash}", now);
        return (records, $"findings read by '{actor.Trim()}' for machine '{machineId}': {records.Count} chain records (audited act)");
    }

    /// <summary>Retention sweep for one machine's policy window.
    /// D38 F1: the sweep is a DESTRUCTIVE act on sensitive records —
    /// it requires the same authority as reading findings (a
    /// policy-named findings reader, exact match, within bounds);
    /// any other caller, or none, is refused and the refusal is
    /// audited. The purge itself is scoped to THIS machine's records
    /// only (the store is shared across machines). Audited with the
    /// purged count; the store chains the purge.</summary>
    public (int Purged, string Reason) SweepRetention(string machineId, string actor)
    {
        var now = _now();
        var facts = _factsByMachine(machineId);
        if (facts is null) return (0, $"no device facts for '{machineId}' — retention sweep refuses (fail closed)");
        var policy = DlpResolver.Resolve(_policy, facts);
        if (string.IsNullOrWhiteSpace(actor) || actor.Trim().Length > DlpLimits.MaxActorLength ||
            !policy.Access.CanReadFindings(actor))
        {
            _audit.Append("dlp_retention_sweep_refused", AuditActor(actor),
                $"machine={machineId} reason=sweep actor is not a policy-named findings reader — a retention purge is a destructive act on sensitive records and needs the same authority as reading them (refusal audited)", now);
            return (0, $"retention sweep for machine '{machineId}' refused: the sweep actor must be a policy-named findings reader (audited)");
        }
        var (purged, reason) = Findings.PurgeExpired(now, TimeSpan.FromDays(policy.RetentionDays), machineId);
        _audit.Append("dlp_retention_sweep", AuditActor(actor),
            $"machine={machineId} retentionDays={policy.RetentionDays} purged={purged} reason={reason}", now);
        return (purged, reason);
    }

    /// <summary>Evaluate (and, via the applier seam, attempt to
    /// enforce) one egress of content whose classification is the
    /// classifier-id list. Content itself never enters this call —
    /// classification is computed by the scan/classify step on-device
    /// and only ids travel. A block with no wired applier reports
    /// NOT enforced, plainly. D38 F3, named plainly: in this
    /// foundation the classification is ASSERTED by the caller — no
    /// content is classified at egress, because no channel enforcer
    /// exists here to intercept content; the decision is only as
    /// good as the caller's classification, and surfaces say so.</summary>
    public (DlpEgressDecision? Decision, DlpEgressApplyResult? Apply, string Reason) EvaluateEgress(
        string machineId, string channel, IReadOnlyList<string>? matchedClassifierIds, string actor)
    {
        var now = _now();
        var facts = _factsByMachine(machineId);
        if (facts is null) return (null, null, $"no device facts for '{machineId}' — egress evaluation refuses (fail closed)");
        var policy = DlpResolver.Resolve(_policy, facts);
        var decision = DlpEgressEvaluator.Evaluate(channel, matchedClassifierIds ?? Array.Empty<string>(),
            policy.EgressRules, policy.FeatureEnabled);
        DlpEgressApplyResult? apply = null;
        if (decision.Disposition is DlpEgressDispositions.Blocked or DlpEgressDispositions.ApprovalRequired)
            apply = _egressApplier.Apply(decision.Channel, decision);
        // D38 F9: EVERY decision is audited — including classified
        // content allowed by the unnamed default on an unruled
        // channel (previously the most common leak path left no
        // record at all). The audit names whether a rule matched or
        // the DEFAULT applied.
        _audit.Append("dlp_egress_decision", AuditActor(actor),
            $"machine={machineId} channel={decision.Channel} disposition={decision.Disposition} classifiers=[{string.Join(", ", decision.ClassifierIds)}] matchedRule={decision.MatchedRule ?? "none — DEFAULT"} reason={decision.Reason}" +
            (apply is null ? "" : $" enforced={apply.Applied} applier={apply.Detail}"), now);
        if (decision.Disposition is DlpEgressDispositions.Blocked or DlpEgressDispositions.ApprovalRequired)
        {
            if (decision.Disposition == DlpEgressDispositions.Blocked)
                _alertSink.Raise(new DlpEvent(DlpAlertKind.EgressBlocked, machineId, decision.Channel, decision.ClassifierIds.Count,
                    $"DLP egress BLOCK decision on machine '{machineId}', channel '{decision.Channel}': classified content [{string.Join(", ", decision.ClassifierIds)}] — enforced={apply!.Applied} ({apply.Detail})",
                    now));
        }
        return (decision, apply, decision.Reason + (apply is null ? "" : $" | enforcement: {(apply.Applied ? "applied" : "NOT applied — " + apply.Detail)}"));
    }
}

public static class DlpAccessPolicyExtensions
{
    public static int ReadersCount(this DlpAccessPolicy access) => access.FindingsReaders.Count;
}

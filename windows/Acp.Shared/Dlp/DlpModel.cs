using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Acp.Shared.Compliance;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;

namespace Acp.Shared.Dlp;

// =====================================================================
// RMM-32 — Endpoint DLP + sensitive-data discovery (HONEST FOUNDATION).
//
// SCALE, LABELLED PLAINLY (the register itself flags RMM-32 as
// programme-scale; the owner adopted it, so this lane builds the honest
// foundation and names the remainder — it does not imply it):
//   BUILT: a closed, inspectable classifier set; admin-initiated
//     discovery scans over DECLARED scope; findings as redacted
//     metadata (a finding proves presence — it is never a copy of
//     the secret); an egress POLICY MODEL enforced at the channels
//     ACP actually controls; findings under RBAC + audit + retention.
//   NOT BUILT (future-decision remainder, named): kernel-level
//     channel blocking; content interception at every egress point;
//     any opaque ML classifier. Channels ACP cannot see are NAMED
//     unseeable in DlpChannelVisibility and ship in every surface.
//
// PRIVACY DISCIPLINE (DLP is the most privacy-sensitive capability
// in the programme):
//   * Toggle rmm.dlp.enabled is seeded OFF (RMM-07 registry); every
//     operation gates on it. Content inspection happens ONLY under
//     an explicit enable.
//   * All processing is on-device. A finding stores file path,
//     classifier id+version, match COUNT and a masked excerpt under
//     the named MaskRule — the matched value itself is NEVER stored
//     in a finding, an audit detail, an alert or an export.
//   * Reading findings is RBAC-scoped and is itself an audited act.
//   * No hidden inspection: the endpoint's effective-policy view
//     surfaces that DLP is enabled and exactly which classifier
//     classes are scanned for (DlpEffectiveView).
// =====================================================================

public static class DlpKeys
{
    public const string FeatureEnabled = "rmm.dlp.enabled";
    /// <summary>Comma-separated classifier ids enabled for scans;
    /// unset → the built-in set. Admin keyword/regex classifiers are
    /// added by their own keys, never by editing this list.</summary>
    public const string Classifiers = "rmm.dlp.classifiers";
    /// <summary>Admin keywords, '|' separated (literal, case-insensitive).</summary>
    public const string Keywords = "rmm.dlp.keywords";
    /// <summary>Admin regexes, '|' separated. Each is compiled with a
    /// match timeout; an invalid or catastrophic pattern is refused
    /// and NAMED in the resolution notes, never silently dropped.</summary>
    public const string Regexes = "rmm.dlp.regexes";
    /// <summary>Comma-separated ACTOR NAMES allowed to READ findings.
    /// Actors only — there is no role-resolution layer in the policy
    /// model, so a listed name grants exactly that actor name (exact,
    /// case-sensitive match); naming a role grants nothing.</summary>
    public const string FindingsReaders = "rmm.dlp.findings_readers";
    /// <summary>Findings retention in days; unset/unparsable → the
    /// named default. Findings older than retention are purged by the
    /// sweep; there is no "keep forever" value (0/invalid → default).</summary>
    public const string FindingsRetentionDays = "rmm.dlp.findings_retention_days";
    /// <summary>Egress rules, '|' separated "channel:action" entries.</summary>
    public const string EgressRules = "rmm.dlp.egress_rules";
}

public static class DlpLimits
{
    public const int DefaultRetentionDays = 90;
    public const int MaxRetentionDays = 3650;
    public const long MaxFileBytes = 10 * 1024 * 1024; // larger files are skipped, NAMED in the scan summary
    public const int MaxMatchesPerFilePerClassifier = 10_000;
    public const int MaxKeywords = 256;
    public const int MaxRegexes = 64;
    public const int MaxScanPaths = 64;
    public const int MaxActorLength = 128;
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
}

/// <summary>THE masking rule, named so every surface can cite it:
/// "first2-last2" — an excerpt is the first 2 and last 2 characters
/// of the matched value joined by an ellipsis, produced ONLY when
/// the value is at least 9 characters long (so at most 4 of 9+
/// characters ever show, and never a contiguous run longer than 2).
/// Shorter values produce NO excerpt at all. The full matched value
/// is never stored anywhere.</summary>
public static class DlpMasking
{
    public const string RuleName = "first2-last2 (values under 9 chars: excerpt omitted entirely)";
    public const int MinLengthForExcerpt = 9;

    public static string? Mask(string? rawValue)
    {
        var v = (rawValue ?? "").Trim();
        if (v.Length < MinLengthForExcerpt) return null;
        return $"{v[..2]}…{v[^2..]}";
    }

    /// <summary>Mask a file path for storage in a finding or a scan
    /// note (D38 F6): a file NAME is user-controlled content and can
    /// itself carry the sensitive value (a card number or password
    /// used as a filename), so the name segment is masked under the
    /// same first2-last2 rule — a name too short to excerpt is
    /// replaced whole, never kept. Directory segments are retained
    /// (they are the declared scan scope, needed to locate the
    /// finding); that retention is a named limitation.</summary>
    public static string MaskPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path ?? "";
        var p = path.Trim();
        var cut = p.LastIndexOfAny(new[] { '\\', '/' });
        var dir = cut >= 0 ? p[..(cut + 1)] : "";
        var name = cut >= 0 ? p[(cut + 1)..] : p;
        var dot = name.LastIndexOf('.');
        var stem = dot > 0 ? name[..dot] : name;
        var ext = dot > 0 ? name[dot..] : "";
        var maskedStem = Mask(stem) ?? "…";
        return dir + maskedStem + ext;
    }
}

// ---- classifiers --------------------------------------------------------

public sealed record DlpMatch(string ClassifierId, string RawValue);

/// <summary>One classifier: named, versioned, inspectable, testable
/// with known vectors. NO opaque ML classifier exists in this set —
/// every detector is a stated pattern + stated validation.</summary>
public interface IDlpClassifier
{
    string Id { get; }
    string Version { get; }
    string Description { get; }
    IReadOnlyList<DlpMatch> Find(string content);
}

public static class DlpClassifierIds
{
    public const string PaymentCard = "payment_card";
    public const string NationalId = "national_id";
    public const string CredentialSecret = "credential_secret";
    public const string AdminKeyword = "admin_keyword";
    public const string AdminRegex = "admin_regex";
}

/// <summary>Payment-card detector v1: digit runs of 13–19 digits,
/// allowing a single space or dash separator between digits (the
/// common printed groupings), validated by LUHN. A pattern match
/// that fails Luhn is NOT a finding. NAMED LIMITATION: digits
/// separated by anything else (dots, letters, words, line breaks)
/// are not reassembled — the detector catches less than a determined
/// obfuscator can hide, and says so rather than claiming more.</summary>
public sealed class PaymentCardClassifier : IDlpClassifier
{
    public string Id => DlpClassifierIds.PaymentCard;
    public string Version => "1";
    public string Description => "Payment-card numbers: 13–19 digits (single space/dash separators allowed), Luhn-validated. When a longer separator-grouped digit run fails Luhn as a whole, contiguous separator-delimited group ranges of 13–19 digits are retried (a card printed next to an expiry/CVV or a short reference number is still caught). Limitation: digits separated by other characters are not reassembled, and sub-runs inside one unseparated digit string are never split out (a card must not be part of a longer contiguous digit run).";
    private static readonly Regex Candidate = new(@"\d(?:[ -]?\d){12,18}", RegexOptions.Compiled, DlpLimits.RegexTimeout);

    public static bool LuhnValid(string digits)
    {
        if (digits.Length is < 13 or > 19 || !digits.All(char.IsDigit)) return false;
        var sum = 0; var alt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (alt) { d *= 2; if (d > 9) d -= 9; }
            sum += d; alt = !alt;
        }
        return sum % 10 == 0;
    }

    public IReadOnlyList<DlpMatch> Find(string content)
    {
        var hits = new List<DlpMatch>();
        foreach (Match m in Candidate.Matches(content ?? ""))
        {
            var digits = new string(m.Value.Where(char.IsDigit).ToArray());
            if (LuhnValid(digits)) { hits.Add(new DlpMatch(Id, m.Value)); continue; }
            // D38 F4: the greedy candidate absorbed neighbouring digits
            // (expiry, CVV, a short reference) into one Luhn-invalid
            // run. Retry contiguous ranges of the separator-delimited
            // digit GROUPS, longest first — group boundaries only, so
            // an unseparated long digit string is never split.
            var groups = m.Value.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (groups.Length < 2) continue;
            var found = false;
            for (var total = Math.Min(19, digits.Length); total >= 13 && !found; total--)
            {
                for (var start = 0; start < groups.Length && !found; start++)
                {
                    var len = 0; var end = start;
                    while (end < groups.Length && len < total) { len += groups[end].Length; end++; }
                    if (len != total) continue;
                    var sub = string.Concat(groups[start..end]);
                    if (!LuhnValid(sub)) continue;
                    hits.Add(new DlpMatch(Id, string.Join(" ", groups[start..end])));
                    found = true;
                }
            }
        }
        return hits;
    }
}

/// <summary>National-ID detector v1 (US SSN shape): AAA-GG-SSSS with
/// the SSA validity rules applied (area 000/666/900–999, group 00 and
/// serial 0000 are not findings) — the rules exist to keep false
/// positives from flooding findings with random 9-digit strings.</summary>
public sealed class NationalIdClassifier : IDlpClassifier
{
    public string Id => DlpClassifierIds.NationalId;
    public string Version => "1";
    public string Description => "US national-ID (SSN) shape AAA-GG-SSSS with SSA area/group/serial validity rules; dashed form only (undashed 9-digit runs are not claimed — named limitation). Widely circulated sample numbers (123-45-6789, 078-05-1120, 219-09-9999) are never findings — the SSA does not issue them.";
    private static readonly Regex Candidate = new(@"\b(\d{3})-(\d{2})-(\d{4})\b", RegexOptions.Compiled, DlpLimits.RegexTimeout);
    // D38 F12: sample SSNs circulated in wallets/advertising and used
    // as textbook examples — shape-valid under the area/group/serial
    // rules but never issued, so accepting them is a false positive.
    private static readonly IReadOnlySet<string> SampleNumbers = new HashSet<string>
        { "123-45-6789", "078-05-1120", "219-09-9999" };

    public IReadOnlyList<DlpMatch> Find(string content)
    {
        var hits = new List<DlpMatch>();
        foreach (Match m in Candidate.Matches(content ?? ""))
        {
            if (SampleNumbers.Contains(m.Value)) continue;
            var area = int.Parse(m.Groups[1].Value);
            if (area == 0 || area == 666 || area >= 900) continue;
            if (m.Groups[2].Value == "00" || m.Groups[3].Value == "0000") continue;
            hits.Add(new DlpMatch(Id, m.Value));
        }
        return hits;
    }
}

/// <summary>Credential/secret detector v1: stated shapes only —
/// AWS access-key ids (AKIA/ASIA + 16), PEM private-key headers, and
/// keyword assignments (password|passwd|api_key|apikey|secret|token
/// = value of 8+ non-space chars). The matched VALUE carried to the
/// finding pipeline is masked there; the assignment's value part is
/// what is masked, never the whole line.</summary>
public sealed class CredentialSecretClassifier : IDlpClassifier
{
    public string Id => DlpClassifierIds.CredentialSecret;
    public string Version => "1";
    public string Description => "Credential shapes: AWS key ids (AKIA/ASIA…), PEM private-key headers, keyword assignments (password/api_key/secret/token = value≥8 chars).";
    private static readonly Regex AwsKey = new(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", RegexOptions.Compiled, DlpLimits.RegexTimeout);
    private static readonly Regex PemHeader = new(@"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", RegexOptions.Compiled, DlpLimits.RegexTimeout);
    private static readonly Regex Assignment = new(@"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*[""']?(\S{8,})", RegexOptions.Compiled, DlpLimits.RegexTimeout);

    public IReadOnlyList<DlpMatch> Find(string content)
    {
        var text = content ?? "";
        var hits = new List<DlpMatch>();
        foreach (Match m in AwsKey.Matches(text)) hits.Add(new DlpMatch(Id, m.Value));
        foreach (Match m in PemHeader.Matches(text)) hits.Add(new DlpMatch(Id, m.Value));
        foreach (Match m in Assignment.Matches(text)) hits.Add(new DlpMatch(Id, m.Groups[1].Value));
        return hits;
    }
}

/// <summary>Admin-defined keyword classifier: literal terms from
/// policy content, case-insensitive. The term itself is admin policy
/// content (not a discovered secret); findings still store only the
/// masked excerpt rule output.</summary>
public sealed class AdminKeywordClassifier : IDlpClassifier
{
    private readonly IReadOnlyList<string> _terms;
    public AdminKeywordClassifier(IEnumerable<string> terms) =>
        _terms = terms.Select(t => t.Trim()).Where(t => t.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    public string Id => DlpClassifierIds.AdminKeyword;
    public string Version => "1";
    public string Description => $"Admin-defined keywords from policy ({_terms.Count} term(s)), literal case-insensitive match.";
    public IReadOnlyList<string> Terms => _terms;

    public IReadOnlyList<DlpMatch> Find(string content)
    {
        var text = content ?? "";
        var hits = new List<DlpMatch>();
        foreach (var term in _terms)
        {
            var idx = 0;
            while ((idx = text.IndexOf(term, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                hits.Add(new DlpMatch(Id, text.Substring(idx, term.Length)));
                idx += Math.Max(1, term.Length);
            }
        }
        return hits;
    }
}

/// <summary>Admin-defined regex classifier. Construction REFUSES an
/// invalid pattern (named) — a broken admin regex never silently
/// scans as nothing. Matching runs under DlpLimits.RegexTimeout; a
/// timeout aborts that pattern's scan of that content and the caller
/// surfaces it as a named scan note via TimedOut.</summary>
public sealed class AdminRegexClassifier : IDlpClassifier
{
    private readonly Regex _regex;
    public string Pattern { get; }
    public bool TimedOut { get; private set; }

    public AdminRegexClassifier(string pattern)
    {
        Pattern = pattern ?? throw new ArgumentNullException(nameof(pattern));
        _regex = new Regex(pattern, RegexOptions.None, DlpLimits.RegexTimeout); // throws ArgumentException on invalid pattern — by design
    }

    public string Id => DlpClassifierIds.AdminRegex;
    public string Version => "1";
    // D38 F7: the pattern itself is admin policy content that can
    // embed literal sensitive strings (codenames, specific ids) — it
    // is NEVER published to endpoint-facing surfaces; like keywords,
    // only its size is shown. The pattern stays available at the
    // model layer (Pattern) for the policy's own audience.
    public string Description => $"Admin-defined regex from policy ({Pattern.Length} chars; pattern withheld — admin policy content is described by size, never published)";

    public IReadOnlyList<DlpMatch> Find(string content)
    {
        try
        {
            var hits = new List<DlpMatch>();
            foreach (Match m in _regex.Matches(content ?? "")) hits.Add(new DlpMatch(Id, m.Value));
            return hits;
        }
        catch (RegexMatchTimeoutException) { TimedOut = true; return Array.Empty<DlpMatch>(); }
    }
}

/// <summary>The closed built-in classifier set. Admin classifiers are
/// constructed from policy content by the resolver, separately.</summary>
public static class DlpClassifiers
{
    public static IReadOnlyList<IDlpClassifier> BuiltIns() => new IDlpClassifier[]
    {
        new PaymentCardClassifier(), new NationalIdClassifier(), new CredentialSecretClassifier(),
    };
    public static IDlpClassifier? BuiltIn(string id) =>
        BuiltIns().FirstOrDefault(c => string.Equals(c.Id, (id ?? "").Trim(), StringComparison.OrdinalIgnoreCase));
}

// ---- scan definitions ---------------------------------------------------

/// <summary>One discovery-scan definition. Scope is DECLARED and
/// closed: the root paths + extensions enumerated here are all a scan
/// may touch — a scan never silently widens. The definition is
/// fingerprinted (DefinitionHash over canonical content); the scan
/// runs over a frozen snapshot taken at start, so mutating the
/// caller's lists mid-run changes nothing (destruction-tested).</summary>
public sealed record DlpScanDefinition(
    string Id,
    string MachineId,
    IReadOnlyList<string> RootPaths,
    IReadOnlyList<string> Extensions,   // e.g. ".txt"; empty + IncludeAllExtensions=false is REFUSED
    bool IncludeAllExtensions,
    IReadOnlyList<string> ClassifierIds,
    string CreatedBy,
    DateTimeOffset CreatedUtc)
{
    public string Canonical() => string.Join("\n",
        $"id={Id}", $"machine={MachineId}",
        "roots=" + string.Join(",", RootPaths.Select(NormalizeRoot).OrderBy(r => r, StringComparer.Ordinal)),
        "exts=" + (IncludeAllExtensions ? "*" : string.Join(",", Extensions.Select(NormalizeExt).OrderBy(e => e, StringComparer.Ordinal))),
        "classifiers=" + string.Join(",", ClassifierIds.Select(c => c.Trim().ToLowerInvariant()).OrderBy(c => c, StringComparer.Ordinal)),
        $"by={CreatedBy}", $"at={CreatedUtc:O}");

    public string DefinitionHash => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(Canonical()))).ToLowerInvariant();

    public static string NormalizeRoot(string root)
    {
        var r = (root ?? "").Trim().Replace('/', '\\');
        while (r.Length > 3 && r.EndsWith('\\')) r = r[..^1];
        return r;
    }

    public static string NormalizeExt(string ext)
    {
        var e = (ext ?? "").Trim().ToLowerInvariant();
        return e.StartsWith('.') ? e : "." + e;
    }

    /// <summary>True when fullPath sits under a declared root —
    /// separator-aware (C:\Data2 is NOT under C:\Data), case-insensitive
    /// (Windows paths), and any ".." segment refuses outright: a path
    /// that needs traversal to fit the scope is outside it.</summary>
    public bool PathInScope(string? fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;
        var p = fullPath.Trim().Replace('/', '\\');
        if (p.Split('\\').Any(seg => seg == "..")) return false;
        foreach (var root in RootPaths)
        {
            var r = NormalizeRoot(root);
            if (r.Length == 0) continue;
            if (string.Equals(p, r, StringComparison.OrdinalIgnoreCase)) return true;
            // D38 F12: a drive root normalizes to "C:\" (length 3, kept)
            // — appending another separator made the required prefix
            // "C:\\", which no real path has, so a drive-root scope
            // matched NOTHING. The prefix must not double the separator.
            var prefix = r.EndsWith('\\') ? r : r + "\\";
            if (p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public bool ExtensionInScope(string? fullPath)
    {
        if (IncludeAllExtensions) return true;
        var ext = Path.GetExtension(fullPath ?? "");
        return ext.Length > 0 && Extensions.Select(NormalizeExt).Contains(ext.ToLowerInvariant());
    }

    /// <summary>Absolute-path test for WINDOWS paths, done manually:
    /// scan scope is declared in Windows path form regardless of the
    /// OS the model code happens to run on (Path.IsPathFullyQualified
    /// would judge a Windows path by the host OS's rules).</summary>
    private static bool IsAbsoluteWindowsPath(string normalized)
    {
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal)) return true; // UNC
        return normalized.Length >= 3 && char.IsLetter(normalized[0]) &&
               normalized[1] == ':' && normalized[2] == '\\';
    }

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id)) return "a scan definition needs an id — refused";
        if (string.IsNullOrWhiteSpace(MachineId)) return "a scan definition needs a machine id — refused";
        if (RootPaths is null || RootPaths.Count == 0) return "a scan definition declares NO root paths — refused: a scan's scope is enumerated, never implicit";
        if (RootPaths.Count > DlpLimits.MaxScanPaths) return $"a scan definition declares {RootPaths.Count} roots over the cap {DlpLimits.MaxScanPaths} — refused";
        foreach (var root in RootPaths)
        {
            var r = NormalizeRoot(root);
            if (r.Length == 0 || !IsAbsoluteWindowsPath(r))
                return $"scan root '{root}' is not an absolute path — refused: relative roots widen unpredictably with the working directory";
            if (r.Split('\\').Any(seg => seg == ".."))
                return $"scan root '{root}' contains a traversal segment — refused";
        }
        if (!IncludeAllExtensions && (Extensions is null || Extensions.Count == 0))
            return "a scan definition declares no extensions and does not explicitly include all extensions — refused: extension scope is declared, or explicitly all";
        if (ClassifierIds is null || ClassifierIds.Count == 0) return "a scan definition names no classifiers — refused";
        if (string.IsNullOrWhiteSpace(CreatedBy)) return "a scan definition needs its creator — refused (scan starts are audited acts; an anonymous scan is unrepresentable)";
        return null;
    }

    /// <summary>A frozen deep copy: new lists, so later mutation of
    /// the caller's collections cannot reach a running scan.</summary>
    public DlpScanDefinition Snapshot() => this with
    {
        RootPaths = RootPaths.ToList(),
        Extensions = Extensions.ToList(),
        ClassifierIds = ClassifierIds.ToList(),
    };
}

// ---- findings -----------------------------------------------------------

public static class DlpFindingKinds
{
    public const string ScanStarted = "scan_started";
    public const string Finding = "finding";
    public const string ScanCompleted = "scan_completed";
    public const string RetentionPurge = "retention_purge";
}

/// <summary>One record in the findings chain. A FINDING carries: file
/// path, classifier id + version, match COUNT, and ONE masked excerpt
/// (DlpMasking rule) from the first match. There is NO field that can
/// hold the matched value — the record type itself enforces the
/// privacy discipline, not a caller's good behaviour.</summary>
public sealed record DlpFindingRecord(
    long Seq,
    string Kind,
    string ScanId,
    string MachineId,
    string? FilePath,
    string? ClassifierId,
    string? ClassifierVersion,
    int MatchCount,
    string? MaskedExcerpt,
    DateTimeOffset AtUtc,
    string PrevHash,
    string Hash);

/// <summary>The hash-chained findings store (RMM-30 trace pattern).
/// Append-only except for the retention purge. D38 F10 design: a
/// purge NEVER rewrites a surviving record — seq/prev-hash/hash of
/// every survivor stay exactly as appended, so hashes recorded
/// earlier (audit findingsHead, compliance EvidenceRef) still verify
/// against the records they named. The purge removes ONLY the named
/// machine's expired records and appends a retention_purge record
/// (chained to the current head) attesting the purged count + the
/// pre-purge head; VerifyChain accounts every missing seq against
/// those attestations, and purge records themselves never expire,
/// so the store keeps a permanent history of its own purges.</summary>
public sealed class DlpFindingStore
{
    private readonly List<DlpFindingRecord> _records = new();
    private readonly object _gate = new();
    private long _nextSeq = 1; // never reused, never reset by a purge
    public const string GenesisHash = "GENESIS";

    public IReadOnlyList<DlpFindingRecord> Records { get { lock (_gate) return _records.ToList(); } }
    public IReadOnlyList<DlpFindingRecord> Findings =>
        Records.Where(r => r.Kind == DlpFindingKinds.Finding).ToList();
    public string HeadHash { get { lock (_gate) return _records.Count == 0 ? GenesisHash : _records[^1].Hash; } }

    private static string ComputeHash(long seq, string kind, string scanId, string machine,
        string? path, string? cls, string? ver, int count, string? excerpt, DateTimeOffset at, string prev) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{seq}|{kind}|{scanId}|{machine}|{path}|{cls}|{ver}|{count}|{excerpt}|{at:O}|{prev}"))).ToLowerInvariant();

    private DlpFindingRecord Append(string kind, string scanId, string machine, string? path,
        string? cls, string? ver, int count, string? excerpt, DateTimeOffset now)
    {
        lock (_gate)
        {
            var seq = _nextSeq++;
            var prev = _records.Count == 0 ? GenesisHash : _records[^1].Hash;
            var hash = ComputeHash(seq, kind, scanId, machine, path, cls, ver, count, excerpt, now, prev);
            var rec = new DlpFindingRecord(seq, kind, scanId, machine, path, cls, ver, count, excerpt, now, prev, hash);
            _records.Add(rec);
            return rec;
        }
    }

    public DlpFindingRecord RecordScanStarted(DlpScanDefinition def, DateTimeOffset now) =>
        Append(DlpFindingKinds.ScanStarted, def.Id, def.MachineId, null, null, null, 0,
            $"scope-hash {def.DefinitionHash[..16]}… roots={def.RootPaths.Count}", now);

    /// <summary>Record one file's matches for one classifier. The raw
    /// matches enter ONLY to be counted and masked — the first match
    /// is masked here and the raw values go out of scope unrecorded.</summary>
    public DlpFindingRecord RecordFinding(string scanId, string machineId, string filePath,
        IDlpClassifier classifier, IReadOnlyList<DlpMatch> matches, DateTimeOffset now)
    {
        var count = Math.Min(matches.Count, DlpLimits.MaxMatchesPerFilePerClassifier);
        var excerpt = matches.Count > 0 ? DlpMasking.Mask(matches[0].RawValue) : null;
        // D38 F6: the stored path is masked at record time — a file
        // name can itself be the sensitive value.
        return Append(DlpFindingKinds.Finding, scanId, machineId, DlpMasking.MaskPath(filePath),
            classifier.Id, classifier.Version, count, excerpt, now);
    }

    public DlpFindingRecord RecordScanCompleted(string scanId, string machineId,
        int filesScanned, int filesWithFindings, int totalMatches, int filesSkipped, DateTimeOffset now,
        int sourceSkipped = 0, bool incomplete = false) =>
        Append(DlpFindingKinds.ScanCompleted, scanId, machineId, null, null, null, totalMatches,
            $"files={filesScanned} withFindings={filesWithFindings} skipped={filesSkipped} sourceSkipped={sourceSkipped} incomplete={(incomplete ? 1 : 0)}", now);

    /// <summary>Remove ONE machine's findings (and its scan lifecycle
    /// records) older than the retention window — D38 F1: the store
    /// is multi-machine, so a sweep resolved from one machine's
    /// policy must never touch another machine's records. Retention
    /// purge records are exempt from expiry (the store keeps its own
    /// purge history permanently). Returns the purged count. The
    /// purge appends its own chained record attesting count +
    /// pre-purge head — expiry is provable, never a silent vanish,
    /// and no surviving record is rewritten (D38 F10). A retention
    /// window is ALWAYS finite (resolver-enforced), so findings
    /// cannot be made immortal by policy.</summary>
    public (int Purged, string Reason) PurgeExpired(DateTimeOffset now, TimeSpan retention, string machineId)
    {
        if (retention <= TimeSpan.Zero) return (0, "retention window is not positive — purge refused (the resolver never produces this; defence in depth)");
        if (string.IsNullOrWhiteSpace(machineId)) return (0, "a retention purge needs the machine whose policy resolved the window — refused: an unscoped purge across the shared store is exactly what must never happen");
        lock (_gate)
        {
            var cutoff = now - retention;
            var expired = _records.Where(r => r.MachineId == machineId &&
                r.Kind != DlpFindingKinds.RetentionPurge && r.AtUtc < cutoff).ToList();
            if (expired.Count == 0) return (0, $"no findings for machine '{machineId}' older than the retention window ({retention.TotalDays:0} days) — nothing purged");
            var preHead = _records[^1].Hash;
            // bd-shared-sec-1/F10: seq-set membership, not a List
            // Contains inside RemoveAll (was O(n·m)).
            var expiredSeqs = expired.Select(r => r.Seq).ToHashSet();
            _records.RemoveAll(r => expiredSeqs.Contains(r.Seq));
            Append(DlpFindingKinds.RetentionPurge, "-", machineId, null, null, null,
                expired.Count, $"purged {expired.Count} record(s) for machine '{machineId}' older than {cutoff:O}; pre-purge head {preHead}", now);
            return (expired.Count, $"purged {expired.Count} expired finding record(s) for machine '{machineId}' past the {retention.TotalDays:0}-day retention window; purge is chained (pre-purge head {preHead}); other machines' records untouched; no surviving record rewritten");
        }
    }

    public (bool Ok, string Summary) VerifyChain() => VerifyChain(null);

    /// <summary>bd-shared-sec-1/F10: chain verification with the
    /// gaps accounted PER MACHINE and, when the caller supplies the
    /// externally anchored head (the findingsHead recorded in the
    /// chained audit at append time), a head check — internal
    /// consistency alone cannot detect deletion of the NEWEST
    /// records, because a truncated chain still verifies against
    /// itself. Per-machine accounting: a seq gap is attributed to
    /// the machine of the NEXT retention_purge record (a purge is
    /// appended immediately after its removal, for the purged
    /// machine only), and that machine's attested count must cover
    /// the gap — a purge for machine A no longer 'accounts for'
    /// records missing from machine B.</summary>
    public (bool Ok, string Summary) VerifyChain(string? anchoredHeadHash)
    {
        lock (_gate)
        {
            var prev = GenesisHash;
            long expectedSeq = 1; long missing = 0; long attested = 0;
            var attestedByMachine = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            // Pass 1: content hashes + per-machine purge attestations.
            foreach (var r in _records)
            {
                var expect = ComputeHash(r.Seq, r.Kind, r.ScanId, r.MachineId, r.FilePath, r.ClassifierId,
                    r.ClassifierVersion, r.MatchCount, r.MaskedExcerpt, r.AtUtc, r.PrevHash);
                if (r.Hash != expect) return (false, $"BROKEN at seq {r.Seq}: record hash mismatch (content altered)");
                if (r.Kind == DlpFindingKinds.RetentionPurge)
                {
                    attested += r.MatchCount;
                    attestedByMachine[r.MachineId] =
                        attestedByMachine.GetValueOrDefault(r.MachineId) + r.MatchCount;
                }
            }
            // Pass 2: links + gaps. Each gap must be covered by a
            // purge attestation FROM THE SAME MACHINE the following
            // purge record names; an unattributed gap is a break.
            var pendingGap = 0L;
            foreach (var r in _records)
            {
                if (r.Seq < expectedSeq) return (false, $"BROKEN at seq {r.Seq}: seq out of order or duplicated");
                if (r.Seq > expectedSeq)
                {
                    pendingGap += r.Seq - expectedSeq;
                    missing += r.Seq - expectedSeq;
                }
                else if (r.PrevHash != prev && _records.Count > 0 && r.Seq != _records[0].Seq)
                {
                    return (false, $"BROKEN at seq {r.Seq}: prev-hash link mismatch");
                }
                if (pendingGap > 0 && r.Kind == DlpFindingKinds.RetentionPurge)
                {
                    var cover = attestedByMachine.GetValueOrDefault(r.MachineId);
                    if (cover < pendingGap)
                        return (false, $"BROKEN at seq {r.Seq}: {pendingGap} record(s) are missing before this purge, but machine '{r.MachineId}' purges attest only {cover} — a purge for one machine cannot account for another machine's missing records");
                    pendingGap = 0;
                }
                expectedSeq = r.Seq + 1;
                prev = r.Hash;
            }
            if (pendingGap > 0)
                return (false, $"BROKEN: {pendingGap} record(s) are missing with no following retention purge attesting them — records vanished without a chained purge");
            if (missing > attested)
                return (false, $"BROKEN: {missing} record(s) are missing from the chain but retention purges attest only {attested} — records vanished without a chained purge");
            if (anchoredHeadHash is not null &&
                !string.Equals(anchoredHeadHash, prev, StringComparison.OrdinalIgnoreCase))
                return (false, $"BROKEN: chain head {prev} does not match the externally anchored head {anchoredHeadHash} — the newest record(s) were deleted or the chain was replaced (internal consistency alone cannot see this; the anchor can)");
            return (true, $"OK: {_records.Count} finding records, chain intact ({missing} purged record(s) attested by chained retention purges, accounted per machine), head {prev}");
        }
    }
}

// ---- egress policy (model layer) ---------------------------------------

public static class DlpChannels
{
    public const string RemovableMedia = "removable_media";
    public const string Print = "print";
    public const string Clipboard = "clipboard";
    public const string NetworkShare = "network_share";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { RemovableMedia, Print, Clipboard, NetworkShare };
}

public static class DlpEgressActions
{
    public const string Allow = "allow";
    public const string Block = "block";
    public const string RequireApproval = "require_approval";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Allow, Block, RequireApproval };
}

public static class DlpEgressDispositions
{
    public const string Allowed = "allowed";
    public const string Blocked = "blocked";
    public const string ApprovalRequired = "approval_required";
    /// <summary>DLP is disabled — the transfer is NOT covered and the
    /// disposition says so. A disabled window is never presented as
    /// an allow.</summary>
    public const string NotCovered = "not_covered_dlp_disabled";
    /// <summary>The channel is one ACP cannot see/enforce — named,
    /// never dressed as a decision.</summary>
    public const string UnseeableChannel = "unseeable_channel";
    public const string NoClassifiedContent = "allowed_no_classified_content";
}

/// <summary>Channel visibility honesty (the RMM-30 pattern): the
/// enforceable list IS the coverage claim; the unseeable list ships
/// alongside it in every surface that mentions egress.</summary>
public static class DlpChannelVisibility
{
    // D38 F3: these are the channels the egress POLICY MODEL renders
    // decisions for — this foundation lane builds NO channel enforcer
    // (no clipboard monitor, no print monitor, no SMB watcher exists
    // in the tree), and the entries say so. Enforcement happens only
    // where a host wires an IDlpEgressApplier; the shipped default
    // applier reports NOT enforced. Calling this list "enforceable"
    // without that qualifier was the overclaim.
    public static readonly IReadOnlyList<string> Enforceable = new[]
    {
        "removable_media — egress policy decisions are computed for this channel; enforcement composes with RMM-30 peripheral control ONLY where its applier is wired (no enforcer is built in this foundation)",
        "clipboard — egress policy decisions are computed for this channel; NO clipboard monitor is built in this foundation — a decision here is a policy verdict, not an interception",
        "print — egress policy decisions are computed for this channel; NO print monitor is built in this foundation — a decision here is a policy verdict, not an interception",
        "network_share — egress policy decisions are computed for this channel; NO filesystem watcher is built in this foundation — a decision here is a policy verdict, not an interception",
    };
    public static readonly IReadOnlyList<string> Unseeable = new[]
    {
        "email sent from third-party mail clients (ACP sees no content in another app's TLS session)",
        "cloud-sync clients' internal uploads (OneDrive/Drive sync of a folder ACP does not watch)",
        "photographs/screenshots of the screen, and anything read aloud or retyped by a person",
        "channels on machines where the endpoint agent is stopped or DLP policy is disabled — those windows are NOT covered and are never reported as covered",
        "raw/below-filesystem writes (composed from RMM-30's named gap: imaging tools writing a device directly)",
    };
    public static string CoverageStatement =>
        "POLICY-DECISION CHANNELS (decisions computed; enforcement only where an applier is wired — none is built in this foundation): " + string.Join("; ", Enforceable) + " || UNSEEABLE (named, never claimed): " + string.Join("; ", Unseeable);
}

public sealed record DlpEgressDecision(
    string Channel, string Disposition, string? MatchedRule, IReadOnlyList<string> ClassifierIds, string Reason);

/// <summary>The egress evaluator (pure). Rules apply ONLY when the
/// content is classified (≥1 classifier matched): unclassified
/// content is allowed on every channel and the disposition names why.
/// A channel with no rule defaults to ALLOW for classified content —
/// named in the decision, because DLP egress is an explicit block
/// list, not a default-deny on work.</summary>
public static class DlpEgressEvaluator
{
    public static DlpEgressDecision Evaluate(string channel, IReadOnlyList<string> matchedClassifierIds,
        IReadOnlyDictionary<string, string> rules, bool dlpEnabled)
    {
        var ch = (channel ?? "").Trim().ToLowerInvariant();
        var ids = matchedClassifierIds ?? Array.Empty<string>();
        if (!DlpChannels.All.Contains(ch))
            return new DlpEgressDecision(ch, DlpEgressDispositions.UnseeableChannel, null, ids,
                $"channel '{channel}' is not a channel ACP can see — NO decision is claimed for it. {DlpChannelVisibility.CoverageStatement}");
        if (!dlpEnabled)
            return new DlpEgressDecision(ch, DlpEgressDispositions.NotCovered, null, ids,
                $"DLP is DISABLED by policy ({DlpKeys.FeatureEnabled}) — this transfer window is NOT covered by DLP and is not presented as allowed-by-DLP");
        if (ids.Count == 0)
            return new DlpEgressDecision(ch, DlpEgressDispositions.NoClassifiedContent, null, ids,
                "no classifier matched the content — egress policy governs classified content only");
        // D38 F9: an unruled channel is a DEFAULT allow — the decision
        // must say so structurally (MatchedRule = null + the default
        // named in the reason), not dress it as a policy rule. The
        // service audits every decision, so the default path leaves
        // the same record a ruled path does.
        string? ruleAction = null;
        var hasRule = rules is not null && rules.TryGetValue(ch, out ruleAction);
        var action = hasRule ? ruleAction! : DlpEgressActions.Allow;
        return action switch
        {
            DlpEgressActions.Block => new DlpEgressDecision(ch, DlpEgressDispositions.Blocked, $"{ch}:{action}", ids,
                $"classified content [{string.Join(", ", ids)}] is BLOCKED on channel '{ch}' by egress policy"),
            DlpEgressActions.RequireApproval => new DlpEgressDecision(ch, DlpEgressDispositions.ApprovalRequired, $"{ch}:{action}", ids,
                $"classified content [{string.Join(", ", ids)}] on channel '{ch}' REQUIRES approval by egress policy — it does not proceed on the user's say-so"),
            _ when hasRule => new DlpEgressDecision(ch, DlpEgressDispositions.Allowed, $"{ch}:{action}", ids,
                $"classified content [{string.Join(", ", ids)}] is allowed on channel '{ch}' by an explicit egress policy rule"),
            _ => new DlpEgressDecision(ch, DlpEgressDispositions.Allowed, null, ids,
                $"classified content [{string.Join(", ", ids)}] is allowed on channel '{ch}' by the DEFAULT (no egress rule names this channel; the default is ALLOW — named here and audited by the service, never hidden)"),
        };
    }
}

// ---- policy resolution ---------------------------------------------------

/// <summary>Who may read findings. Policy content lists actor NAMES
/// (there is no role-resolution layer — a listed name grants that
/// exact actor, case-sensitively, and nothing else); an EMPTY list
/// means NOBODY can read findings (fail closed — findings are
/// sensitive, and an unconfigured reader list never widens to
/// everyone). The scan operator who ran a scan does not thereby gain
/// read access.</summary>
public sealed record DlpAccessPolicy(IReadOnlySet<string> FindingsReaders)
{
    public bool CanReadFindings(string? actor) =>
        actor is not null && FindingsReaders.Contains(actor.Trim());
}

public sealed record ResolvedDlpPolicy(
    bool FeatureEnabled,
    IReadOnlyList<IDlpClassifier> Classifiers,
    IReadOnlyDictionary<string, string> EgressRules,
    DlpAccessPolicy Access,
    int RetentionDays,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public static class DlpResolver
{
    public static ResolvedDlpPolicy Resolve(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var notes = new List<string>();
        var eff = engine.ComputeEffective(facts);
        var enabled = engine.IsEnabled(facts, DlpKeys.FeatureEnabled);
        if (!enabled)
            notes.Add($"DLP is disabled for machine '{facts.DeviceId}' ({DlpKeys.FeatureEnabled} seeded OFF — content inspection runs only under explicit enable)");

        // Classifier selection: policy list or the built-in set.
        var wanted = new List<string>();
        if (eff.Get(DlpKeys.Classifiers) is { } cl && !string.IsNullOrWhiteSpace(cl.Value))
            wanted.AddRange(cl.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
        else
            wanted.AddRange(DlpClassifiers.BuiltIns().Select(c => c.Id));
        var classifiers = new List<IDlpClassifier>();
        foreach (var id in wanted.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var builtIn = DlpClassifiers.BuiltIn(id);
            if (builtIn is not null) classifiers.Add(builtIn);
            else if (!string.Equals(id, DlpClassifierIds.AdminKeyword, StringComparison.OrdinalIgnoreCase) &&
                     !string.Equals(id, DlpClassifierIds.AdminRegex, StringComparison.OrdinalIgnoreCase))
                notes.Add($"policy names unknown classifier '{id}' — dropped (named): the classifier set is closed and inspectable");
        }

        // Admin keywords.
        if (eff.Get(DlpKeys.Keywords) is { } kw && !string.IsNullOrWhiteSpace(kw.Value))
        {
            var terms = kw.Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Take(DlpLimits.MaxKeywords).ToList();
            if (terms.Count > 0) classifiers.Add(new AdminKeywordClassifier(terms));
        }
        // Admin regexes — invalid patterns refused + named.
        if (eff.Get(DlpKeys.Regexes) is { } rx && !string.IsNullOrWhiteSpace(rx.Value))
        {
            var patterns = rx.Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Take(DlpLimits.MaxRegexes);
            var patternIndex = 0;
            foreach (var pattern in patterns)
            {
                patternIndex++;
                try { classifiers.Add(new AdminRegexClassifier(pattern)); }
                // D38 F7: neither the pattern nor the parser's message
                // (which can quote the pattern) is echoed into notes —
                // the refusal is named by position + size only.
                catch (ArgumentException) { notes.Add($"admin regex #{patternIndex} ({pattern.Length} chars) is invalid and was REFUSED (named, never silently scanning as nothing; pattern withheld — admin policy content)"); }
            }
        }

        // Egress rules.
        var egress = new Dictionary<string, string>(StringComparer.Ordinal);
        if (eff.Get(DlpKeys.EgressRules) is { } eg && !string.IsNullOrWhiteSpace(eg.Value))
        {
            foreach (var entry in eg.Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = entry.Split(':', 2);
                if (parts.Length == 2 && DlpChannels.All.Contains(parts[0].Trim().ToLowerInvariant()) &&
                    DlpEgressActions.All.Contains(parts[1].Trim().ToLowerInvariant()))
                    egress[parts[0].Trim().ToLowerInvariant()] = parts[1].Trim().ToLowerInvariant();
                else notes.Add($"egress rule entry '{entry}' is malformed or names an unknown channel/action — dropped (named)");
            }
        }

        // Findings readers (fail closed when unset). D38 F5: matching
        // is EXACT (ordinal, case-sensitive) — actor identity is a
        // security decision, and "Compliance-Reader" is not the
        // policy-named reader "compliance-reader".
        var readers = new HashSet<string>(StringComparer.Ordinal);
        if (eff.Get(DlpKeys.FindingsReaders) is { } fr && !string.IsNullOrWhiteSpace(fr.Value))
            foreach (var r in fr.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) readers.Add(r);
        if (readers.Count == 0)
            notes.Add($"no findings readers are configured ({DlpKeys.FindingsReaders}) — findings are readable by NOBODY until policy names a reader (fail closed: findings are themselves sensitive)");

        // Retention: unset/unparsable/non-positive → default; capped.
        var retention = DlpLimits.DefaultRetentionDays;
        if (eff.Get(DlpKeys.FindingsRetentionDays) is { } ret)
        {
            if (int.TryParse(ret.Value, out var days) && days > 0)
                retention = Math.Min(days, DlpLimits.MaxRetentionDays);
            else notes.Add($"findings retention '{ret.Value}' is unparsable or non-positive — the {DlpLimits.DefaultRetentionDays}-day default applies (retention is always finite; there is no keep-forever value)");
        }

        return new ResolvedDlpPolicy(enabled, classifiers, egress, new DlpAccessPolicy(readers), retention, notes);
    }
}

/// <summary>What the ENDPOINT USER sees — the no-hidden-inspection
/// surface. Built from the same resolved policy the engine enforces,
/// so the view cannot drift from the reality: it names whether DLP
/// is on, exactly which classifier classes are scanned for (with
/// versions + plain descriptions), the channels governed, the
/// channels named unseeable, and the findings retention.</summary>
public sealed record DlpEffectiveView(
    string MachineId, bool DlpEnabled,
    IReadOnlyList<string> ClassifierDescriptions,
    IReadOnlyList<string> GovernedChannels,
    IReadOnlyList<string> UnseeableChannels,
    int FindingsRetentionDays,
    string PlainStatement)
{
    public static DlpEffectiveView Build(string machineId, ResolvedDlpPolicy policy)
    {
        var classifiers = policy.Classifiers.Select(c => $"{c.Id} v{c.Version} — {c.Description}").ToList();
        // D38 F3: GovernedChannels lists ONLY channels a policy egress
        // rule actually names — with no rules, NO channel is governed,
        // and the view says so instead of listing every channel the
        // model can render decisions for. Enforcement honesty rides
        // along: decisions are computed here; enforcement exists only
        // where a host wires an applier (none is built in this
        // foundation).
        var governed = policy.EgressRules.Keys.OrderBy(c => c, StringComparer.Ordinal)
            .Select(c => $"{c} — governed by egress rule '{c}:{policy.EgressRules[c]}' (decision computed by policy; enforcement only where an egress applier is wired — none is built in this foundation)")
            .ToList();
        var statement = policy.FeatureEnabled
            ? $"Data-loss prevention (DLP) is ENABLED on this machine. Discovery scans look for: {string.Join("; ", classifiers)}. " +
              $"Findings record only WHERE a match was found (file, kind, count, masked excerpt under rule '{DlpMasking.RuleName}') — never the matched value itself. " +
              $"Findings are kept {policy.RetentionDays} days and readable only by policy-named readers; every read is audited. " +
              (governed.Count > 0
                ? $"Egress rules govern {governed.Count} channel(s); egress classification is supplied by the caller's on-device classification step (content is not re-inspected at egress), and enforcement happens only where an applier is wired."
                : "No egress rules are configured, so NO channel is governed by egress policy.")
            : "Data-loss prevention (DLP) is DISABLED on this machine. No content inspection is running.";
        return new DlpEffectiveView(machineId, policy.FeatureEnabled, classifiers,
            governed, DlpChannelVisibility.Unseeable,
            policy.RetentionDays, statement);
    }
}

// ---- alert sink (RMM-01 composition) -------------------------------------

public sealed record DlpEvent(string Kind, string MachineId, string ScanId, int FindingCount, string Detail, DateTimeOffset OccurredUtc);

public static class DlpAlertKind
{
    public const string ScanFindings = "dlp_scan_findings";
    public const string ScanIncomplete = "dlp_scan_incomplete";
    public const string EgressBlocked = "dlp_egress_blocked";
    public static string ConditionIdFor(string kind, string scanOrChannel) =>
        "dlp:" + kind + ":" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(scanOrChannel))).ToLowerInvariant()[..16];
}

public interface IDlpAlertSink { void Raise(DlpEvent dlpEvent); }

public sealed class RecordingDlpAlertSink : IDlpAlertSink
{
    public List<DlpEvent> Events { get; } = new();
    public void Raise(DlpEvent dlpEvent) => Events.Add(dlpEvent);
}

/// <summary>Adapter into RMM-01's HealthAlertCentre. Details carry
/// counts and classifier ids ONLY — never a matched value, never even
/// a masked excerpt (alerts are a wider audience than findings).</summary>
public sealed class HealthAlertCentreDlpSink : IDlpAlertSink
{
    private readonly HealthAlertCentre _centre;
    public HealthAlertCentreDlpSink(HealthAlertCentre centre) => _centre = centre ?? throw new ArgumentNullException(nameof(centre));
    public void Raise(DlpEvent e)
    {
        _centre.Raise(e.MachineId, DlpAlertKind.ConditionIdFor(e.Kind, e.ScanId), e.Kind,
            AlertSeverities.Warning, e.Detail, "dlp", TimeSpan.Zero, e.OccurredUtc);
    }
}

// ---- compliance facts (RMM-09 fact shapes) --------------------------------

public static class DlpComplianceFacts
{
    public const string FactKind = "dlp_discovery";

    /// <summary>Compose discovery findings into an RMM-09-shaped
    /// ComplianceFact: counts only, evidence = the machine's OWN
    /// latest chain record (D38 F10 — never the global store head,
    /// which may be another machine's record). Passing requires the
    /// LATEST completed scan for the device to have actually
    /// inspected something, completely: D38 F2 — a scan that
    /// inspected NOTHING (missing root, every file skipped, a
    /// classifier timeout, a source failure) is NOT a pass, however
    /// clean its (empty) findings are. A device with findings is NOT
    /// passing; a device never scanned produces NO fact
    /// (missing_fact honesty — absence of a scan is not a clean
    /// bill).</summary>
    public static ComplianceFact? Build(DlpFindingStore store, string machineId, string scopeId, DateTimeOffset now)
    {
        var records = store.Records.Where(r => r.MachineId == machineId).ToList();
        var completions = records.Where(r => r.Kind == DlpFindingKinds.ScanCompleted).ToList();
        if (completions.Count == 0) return null;
        var latest = completions.OrderByDescending(r => r.Seq).First();
        var stats = ParseCompletionStats(latest.MaskedExcerpt);
        // bd-shared-sec-1/F6: the fact describes the LATEST SCAN
        // only. (a) ObservedUtc is that scan's completion instant —
        // previously it was the max over ALL the machine's records
        // including retention_purge records, so a purge today made
        // an ancient scan look fresh. (b) The finding set is the
        // latest scan's findings (by its ScanId) — previously every
        // historical finding counted, so a remediated device stayed
        // failing until its findings aged out of retention.
        var findings = records.Where(r => r.Kind == DlpFindingKinds.Finding &&
            string.Equals(r.ScanId, latest.ScanId, StringComparison.Ordinal)).ToList();
        var byClassifier = findings.GroupBy(f => f.ClassifierId ?? "?")
            .Select(g => $"{g.Key}×{g.Sum(f => f.MatchCount)}");
        var coverageOk = stats.Files > 0 && !stats.Incomplete;
        var passing = coverageOk && findings.Count == 0;
        var detail = passing
            ? "DLP discovery: latest scan completed and inspected files, no sensitive-data findings on this device"
            : findings.Count > 0
                ? $"DLP discovery: {findings.Count} finding record(s) in the latest scan on this device [{string.Join(", ", byClassifier)}] (counts only — no matched values in this fact)"
                : $"DLP discovery: latest scan is NOT a clean pass — it inspected {stats.Files} file(s) and was {(stats.Incomplete ? "INCOMPLETE (files skipped by the source, a classifier timeout, or a scan failure — coverage has named gaps)" : "empty")}; a scan that inspected nothing proves nothing";
        return new ComplianceFact(
            FactKind, machineId, scopeId,
            Passing: passing,
            ObservedUtc: latest.AtUtc,
            Detail: detail,
            EvidenceRef: latest.Hash);
    }

    private static (int Files, bool Incomplete) ParseCompletionStats(string? excerpt)
    {
        var files = 0; var incomplete = true; // an unparseable completion record is not a pass
        if (excerpt is null) return (files, incomplete);
        incomplete = false;
        foreach (var token in excerpt.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = token.Split('=', 2);
            if (kv.Length != 2) continue;
            if (kv[0] == "files") int.TryParse(kv[1], out files);
            if (kv[0] == "incomplete") incomplete = kv[1] == "1";
            if (kv[0] == "sourceSkipped" && int.TryParse(kv[1], out var ss) && ss > 0) incomplete = true;
        }
        return (files, incomplete);
    }
}

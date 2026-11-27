using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Compliance;

// =====================================================================
// RMM-09 — checklist CONTENT PACKS: versioned local content, the
// RMM-01 condition-library discipline applied to compliance
// checklists. A pack is DATA (framework, revision, controls mapped
// to fact kinds DeskGuest collects). Admission is whole-pack: any defect
// refuses the pack entire — a partially-admitted checklist would
// silently un-check whatever the defect touched.
//
// POISONING DEFENCES (destruction pass):
//   * the rule set is CLOSED — there is no "always pass" rule and
//     admission refuses any rule outside ComplianceRules.All, so a
//     poisoned pack cannot mint a control that passes by assertion;
//   * a control may only require a fact kind in
//     ComplianceFactKinds.All — evidence DeskGuest does not collect can
//     neither be demanded nor faked;
//   * revision is monotonic per pack id and a same-revision pack
//     with different content refuses (the silent-swap refusal);
//   * CONTROL REMOVAL IS LOUD: admitting a revision that drops
//     controls returns their ids by name, and the service records
//     a chained-audit event naming every one. A new pack version
//     may legitimately retire controls — but never silently.
// =====================================================================

/// <summary>The closed set of pass rules a control may declare.
/// fact_passing: every backing fact passes. The two vuln rules read
/// the vulnerability fact's structured detail (open/overdue/kevOpen
/// counts, written by the service's fact builder in the documented
/// format) so one collected fact can evidence both "nothing
/// overdue" and "nothing known-exploited open" without inventing a
/// second fact.</summary>
public static class ComplianceRules
{
    public const string FactPassing = "fact_passing";
    public const string VulnNoOverdue = "vuln_no_overdue";
    public const string VulnNoKevOpen = "vuln_no_kev_open";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        FactPassing, VulnNoOverdue, VulnNoKevOpen,
    };

    /// <summary>Parse the vulnerability fact detail format:
    /// "open=N; overdue=N; kevOpen=N; closed=N". D38-F10: STRICT —
    /// both judged keys must be present EXACTLY ONCE with a
    /// non-negative integer value, and every part must be a
    /// well-formed key=value pair. Before this fix, missing keys
    /// read as 0 (a detail of "overdue=0" alone passed
    /// vuln_no_kev_open with no kevOpen key at all) and a duplicate
    /// key's LAST value won ("kevOpen=5; kevOpen=0" passed). Any
    /// defect returns false, and the compiler treats an
    /// unparseable detail as a failing gap — never a pass.</summary>
    public static bool TryReadVulnCounts(string? detail, out int overdue, out int kevOpen)
    {
        overdue = 0; kevOpen = 0;
        if (string.IsNullOrWhiteSpace(detail)) return false;
        var seenOverdue = false; var seenKev = false;
        foreach (var part in detail.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length != 2 || kv[0].Length == 0 || !int.TryParse(kv[1], out var n) || n < 0)
                return false;
            if (kv[0] == "overdue") { if (seenOverdue) return false; overdue = n; seenOverdue = true; }
            else if (kv[0] == "kevOpen") { if (seenKev) return false; kevOpen = n; seenKev = true; }
        }
        return seenOverdue && seenKev;
    }
}

/// <summary>One checklist control: a framework requirement mapped
/// to the DeskGuest fact that evidences it (DIR-24 mapping discipline —
/// the mapping is the control; there is no free-text "we comply"
/// field anywhere in this type).</summary>
public sealed record ComplianceControl(
    string ControlId,
    string FrameworkRef,
    string Title,
    string RequiredFactKind,
    string Rule);

/// <summary>One versioned checklist for one framework.</summary>
public sealed record ComplianceContentPack(
    string Id,                 // pack id, e.g. "deskguest-hipaa"
    string FrameworkId,        // "hipaa" | "gdpr" | "nist-csf" | "cmmc" | org-defined
    long Revision,
    IReadOnlyList<ComplianceControl> Controls)
{
    public IReadOnlyList<ComplianceControl> Controls { get; init; } =
        Controls ?? Array.Empty<ComplianceControl>();

    public string ToCanonicalJson()
    {
        var controls = Controls.OrderBy(c => c.ControlId, StringComparer.Ordinal).Select(c => new
        {
            controlId = c.ControlId, frameworkRef = c.FrameworkRef, title = c.Title,
            requiredFactKind = c.RequiredFactKind, rule = c.Rule,
        }).ToList();
        return JsonSerializer.Serialize(new { id = Id, frameworkId = FrameworkId, revision = Revision, controls });
    }

    public string ContentHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()))).ToLowerInvariant();

    public static ComplianceContentPack? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var controls = new List<ComplianceControl>();
            foreach (var el in root.GetProperty("controls").EnumerateArray())
                controls.Add(new ComplianceControl(
                    el.GetProperty("controlId").GetString() ?? "",
                    el.GetProperty("frameworkRef").GetString() ?? "",
                    el.GetProperty("title").GetString() ?? "",
                    el.GetProperty("requiredFactKind").GetString() ?? "",
                    el.GetProperty("rule").GetString() ?? ""));
            return new ComplianceContentPack(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("frameworkId").GetString() ?? "",
                root.GetProperty("revision").GetInt64(),
                controls);
        }
        catch { return null; }
    }

    /// <summary>Whole-pack admission validation. Null when
    /// admissible; otherwise the refusal reason naming the first
    /// defect.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > ComplianceLimits.MaxControlIdLength)
            return "content pack needs an id within bounds — refused";
        if (string.IsNullOrWhiteSpace(FrameworkId))
            return $"content pack '{Id}' names no framework — refused";
        if (Revision < 1)
            return $"content pack '{Id}' revision {Revision} is not positive — refused";
        if (Controls.Count == 0)
            return $"content pack '{Id}' carries no controls — an empty checklist evidences nothing and refuses (it would otherwise 'pass' vacuously)";
        if (Controls.Count > ComplianceLimits.MaxControlsPerPack)
            return $"content pack '{Id}' carries {Controls.Count} controls over the cap {ComplianceLimits.MaxControlsPerPack} — refused";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in Controls)
        {
            if (string.IsNullOrWhiteSpace(c.ControlId) || c.ControlId.Length > ComplianceLimits.MaxControlIdLength)
                return $"content pack '{Id}': a control id is empty or over bounds — refused";
            if (!seen.Add(c.ControlId))
                return $"content pack '{Id}': duplicate control id '{c.ControlId}' — refused";
            if (string.IsNullOrWhiteSpace(c.Title) || c.Title.Length > ComplianceLimits.MaxControlTitleLength)
                return $"content pack '{Id}': control '{c.ControlId}' title empty or over bounds — refused";
            if (string.IsNullOrWhiteSpace(c.FrameworkRef))
                return $"content pack '{Id}': control '{c.ControlId}' names no framework reference — a control that cites nothing is not a checklist item; refused";
            if (!ComplianceFactKinds.All.Contains(c.RequiredFactKind ?? ""))
                return $"content pack '{Id}': control '{c.ControlId}' requires unknown fact kind '{c.RequiredFactKind}' — DeskGuest does not collect it, so the control could only ever be asserted, never evidenced; refused";
            if (!ComplianceRules.All.Contains(c.Rule ?? ""))
                return $"content pack '{Id}': control '{c.ControlId}' declares unknown rule '{c.Rule}' — the rule set is closed and contains no always-pass rule; refused";
            if ((c.Rule == ComplianceRules.VulnNoOverdue || c.Rule == ComplianceRules.VulnNoKevOpen) &&
                c.RequiredFactKind != ComplianceFactKinds.VulnerabilityState)
                return $"content pack '{Id}': control '{c.ControlId}' uses a vulnerability rule over fact kind '{c.RequiredFactKind}' — refused (rule/fact mismatch)";
        }
        return null;
    }
}

public sealed record PackAdmission(
    bool Accepted, string Reason,
    IReadOnlyList<string> RemovedControlIds,
    IReadOnlyList<string> AddedControlIds,
    // D38-F5: controls present in BOTH revisions whose mapping
    // (FrameworkRef / Title / RequiredFactKind / Rule) changed —
    // a revision that keeps a hard control's id but re-points it
    // at an always-evidenced fact kind has hollowed the control
    // out, and that is reported BY NAME exactly like a removal.
    IReadOnlyList<string>? RemappedControlIds = null)
{
    public IReadOnlyList<string> RemappedControlIds { get; init; } =
        RemappedControlIds ?? Array.Empty<string>();
}

/// <summary>The content-pack store: one current pack per framework,
/// monotonic revision, removal diff computed at admission.</summary>
public sealed class ComplianceContentPackStore
{
    private readonly Dictionary<string, ComplianceContentPack> _byFramework = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public PackAdmission Admit(ComplianceContentPack? pack)
    {
        if (pack is null) return new PackAdmission(false, "no content pack — refused", Array.Empty<string>(), Array.Empty<string>());
        if (pack.Validate() is { } defect)
            return new PackAdmission(false, defect, Array.Empty<string>(), Array.Empty<string>());
        lock (_gate)
        {
            if (_byFramework.TryGetValue(pack.FrameworkId, out var existing))
            {
                if (pack.Revision < existing.Revision)
                    return new PackAdmission(false,
                        $"content pack '{pack.Id}' revision {pack.Revision} is stale (current {existing.Revision}) — refused: yesterday's checklist cannot be re-presented as today's",
                        Array.Empty<string>(), Array.Empty<string>());
                if (pack.Revision == existing.Revision)
                {
                    if (pack.ContentHash != existing.ContentHash)
                        return new PackAdmission(false,
                            $"content pack '{pack.Id}' revision {pack.Revision} conflicts with the admitted pack of the same revision — refused (silent swap)",
                            Array.Empty<string>(), Array.Empty<string>());
                    return new PackAdmission(true,
                        $"content pack '{pack.Id}' r{pack.Revision} already admitted (idempotent)",
                        Array.Empty<string>(), Array.Empty<string>());
                }
                var removed = existing.Controls.Select(c => c.ControlId)
                    .Except(pack.Controls.Select(c => c.ControlId), StringComparer.OrdinalIgnoreCase)
                    .OrderBy(id => id, StringComparer.Ordinal).ToList();
                var added = pack.Controls.Select(c => c.ControlId)
                    .Except(existing.Controls.Select(c => c.ControlId), StringComparer.OrdinalIgnoreCase)
                    .OrderBy(id => id, StringComparer.Ordinal).ToList();
                // D38-F5: id-preserving remaps — the control keeps
                // its name while its evidence requirement changes.
                var priorById = existing.Controls.ToDictionary(c => c.ControlId, StringComparer.OrdinalIgnoreCase);
                var remapped = pack.Controls
                    .Where(c => priorById.TryGetValue(c.ControlId, out var prior) &&
                        (prior.FrameworkRef != c.FrameworkRef || prior.Title != c.Title ||
                         prior.RequiredFactKind != c.RequiredFactKind || prior.Rule != c.Rule))
                    .Select(c => c.ControlId)
                    .OrderBy(id => id, StringComparer.Ordinal).ToList();
                _byFramework[pack.FrameworkId] = pack;
                return new PackAdmission(true,
                    $"content pack '{pack.Id}' r{pack.Revision} admitted for '{pack.FrameworkId}'" +
                    (removed.Count > 0 ? $" — CONTROLS REMOVED: {string.Join(", ", removed)}" : "") +
                    (remapped.Count > 0 ? $" — CONTROLS REMAPPED (same id, changed mapping): {string.Join(", ", remapped)}" : "") +
                    (added.Count > 0 ? $" — controls added: {string.Join(", ", added)}" : ""),
                    removed, added, remapped);
            }
            _byFramework[pack.FrameworkId] = pack;
            return new PackAdmission(true,
                $"content pack '{pack.Id}' r{pack.Revision} admitted for '{pack.FrameworkId}' ({pack.Controls.Count} controls)",
                Array.Empty<string>(),
                pack.Controls.Select(c => c.ControlId).OrderBy(id => id, StringComparer.Ordinal).ToList());
        }
    }

    public ComplianceContentPack? Get(string frameworkId)
    {
        lock (_gate) return frameworkId is not null && _byFramework.TryGetValue(frameworkId, out var p) ? p : null;
    }

    public IReadOnlyList<ComplianceContentPack> All
    {
        get { lock (_gate) return _byFramework.Values.OrderBy(p => p.FrameworkId, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Admit all four seeded framework packs (fresh store
    /// only — used by the service constructor; later revisions go
    /// through Admit so removals stay loud).</summary>
    public void SeedDefaults()
    {
        foreach (var pack in SeededPacks.All) Admit(pack);
    }
}

/// <summary>The shipped checklist content: HIPAA, GDPR, NIST CSF and
/// CMMC, every control mapped to a fact DeskGuest already collects. These
/// are code-seeded v1 packs (part of the signed binary, like
/// RMM-01's default library); org revisions arrive as data through
/// the store's admission path.</summary>
public static class SeededPacks
{
    private static ComplianceControl C(string id, string frameworkRef, string title, string factKind, string rule = ComplianceRules.FactPassing) =>
        new(id, frameworkRef, title, factKind, rule);

    public static ComplianceContentPack Hipaa() => new("deskguest-hipaa", "hipaa", 1, new[]
    {
        C("hipaa-risk-analysis", "45 CFR 164.308(a)(1)", "Risk analysis: known vulnerabilities are tracked and none is past its remediation SLA", ComplianceFactKinds.VulnerabilityState, ComplianceRules.VulnNoOverdue),
        C("hipaa-security-updates", "45 CFR 164.308(a)(5)", "Security updates: no security patch is missing on any in-scope device", ComplianceFactKinds.PatchState),
        C("hipaa-encryption", "45 CFR 164.312(a)(2)(iv)", "Encryption and decryption: disk encryption is enabled on every in-scope device", ComplianceFactKinds.EncryptionState),
        C("hipaa-malware-protection", "45 CFR 164.308(a)(5)(ii)(B)", "Protection from malicious software: antivirus and firewall are enabled on every in-scope device", ComplianceFactKinds.SecurityState),
        C("hipaa-audit-controls", "45 CFR 164.312(b)", "Audit controls: the tamper-evident audit chain verifies intact", ComplianceFactKinds.AuditChain),
        C("hipaa-access-review", "45 CFR 164.308(a)(4)", "Information access management: the latest access review for this scope is complete with no pending items and no deadline-defaulted suspensions", ComplianceFactKinds.AccessReview),
        C("hipaa-device-inventory", "45 CFR 164.310(d)(2)(iii)", "Device and media accountability: every in-scope device has a current inventory record", ComplianceFactKinds.InventoryPresence),
    });

    public static ComplianceContentPack Gdpr() => new("deskguest-gdpr", "gdpr", 1, new[]
    {
        C("gdpr-encryption", "Art. 32(1)(a)", "Encryption of personal data: disk encryption is enabled on every in-scope device", ComplianceFactKinds.EncryptionState),
        C("gdpr-integrity-confidentiality", "Art. 32(1)(b)", "Ongoing integrity and confidentiality: no security patch is missing on any in-scope device", ComplianceFactKinds.PatchState),
        C("gdpr-security-state", "Art. 32(1)(b)", "Systems protected: antivirus and firewall are enabled on every in-scope device", ComplianceFactKinds.SecurityState),
        C("gdpr-records-of-processing", "Art. 30", "Records of processing assets: every in-scope device has a current inventory record", ComplianceFactKinds.InventoryPresence),
        C("gdpr-accountability", "Art. 5(2)", "Accountability: audit history exists and the chain verifies intact", ComplianceFactKinds.AuditHistory),
        C("gdpr-access-limitation", "Art. 32(4)", "Access limited to instructed persons: the latest access review for this scope is complete with no pending items and no deadline-defaulted suspensions", ComplianceFactKinds.AccessReview),
        C("gdpr-testing-evaluation", "Art. 32(1)(d)", "Regular testing and evaluation: no vulnerability exposure is past its remediation SLA", ComplianceFactKinds.VulnerabilityState, ComplianceRules.VulnNoOverdue),
    });

    public static ComplianceContentPack NistCsf() => new("deskguest-nist-csf", "nist-csf", 1, new[]
    {
        C("nist-idam-asset-management", "ID.AM-01", "Asset management: every in-scope device has a current inventory record", ComplianceFactKinds.InventoryPresence),
        C("nist-prac-access-review", "PR.AC-04", "Access permissions managed: the latest access review for this scope is complete with no pending items and no deadline-defaulted suspensions", ComplianceFactKinds.AccessReview),
        C("nist-prds-encryption", "PR.DS-01", "Data at rest protected: disk encryption is enabled on every in-scope device", ComplianceFactKinds.EncryptionState),
        C("nist-prma-maintenance", "PR.MA-01", "Maintenance and repair: no security patch is missing on any in-scope device", ComplianceFactKinds.PatchState),
        C("nist-prip-improvement", "PR.IP-12", "Vulnerability management: no exposure is past its remediation SLA and none known-exploited is open", ComplianceFactKinds.VulnerabilityState, ComplianceRules.VulnNoOverdue),
        C("nist-prip-kev", "PR.IP-12", "Known-exploited vulnerabilities: no CISA-KEV exposure is open", ComplianceFactKinds.VulnerabilityState, ComplianceRules.VulnNoKevOpen),
        C("nist-decm-monitoring", "DE.CM-01", "Security monitoring: antivirus and firewall are enabled on every in-scope device", ComplianceFactKinds.SecurityState),
        C("nist-audit-integrity", "PR.DS-06", "Integrity checking: the tamper-evident audit chain verifies intact", ComplianceFactKinds.AuditChain),
    });

    public static ComplianceContentPack Cmmc() => new("deskguest-cmmc", "cmmc", 1, new[]
    {
        C("cmmc-cm-system-inventory", "CM.L2-3.4.1", "Establish and maintain an inventory of organizational systems: every in-scope device has a current inventory record", ComplianceFactKinds.InventoryPresence),
        C("cmmc-si-flaw-remediation", "SI.L2-3.14.1", "Identify, report and correct information and system flaws in a timely manner: no security patch is missing", ComplianceFactKinds.PatchState),
        C("cmmc-si-malicious-code", "SI.L2-3.14.2", "Provide protection from malicious code: antivirus and firewall are enabled on every in-scope device", ComplianceFactKinds.SecurityState),
        C("cmmc-si-vuln-scan", "SI.L2-3.14.6", "Monitor security alerts and scan for vulnerabilities: no exposure is past its remediation SLA", ComplianceFactKinds.VulnerabilityState, ComplianceRules.VulnNoOverdue),
        C("cmmc-sc-encryption", "SC.L2-3.13.11", "Employ FIPS-validated cryptography to protect CUI: disk encryption is enabled on every in-scope device", ComplianceFactKinds.EncryptionState),
        C("cmmc-au-audit-records", "AU.L2-3.3.1", "Create and retain system audit logs: audit history exists for the scope and the chain verifies intact", ComplianceFactKinds.AuditHistory),
        C("cmmc-au-audit-protection", "AU.L2-3.3.8", "Protect audit information from unauthorized modification: the audit chain verifies intact", ComplianceFactKinds.AuditChain),
        C("cmmc-ac-access-review", "AC.L2-3.1.9", "Limit information system access to authorized users: the latest access review for this scope is complete with no pending items and no deadline-defaulted suspensions", ComplianceFactKinds.AccessReview),
    });

    public static IReadOnlyList<ComplianceContentPack> All => new[] { Hipaa(), Gdpr(), NistCsf(), Cmmc() };
}

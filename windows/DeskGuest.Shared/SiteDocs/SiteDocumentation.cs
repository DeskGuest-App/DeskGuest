using System.Text.Json;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.VendorAccess;

namespace DeskGuest.Shared.SiteDocs;

// =====================================================================
// RMM-21 — Site documentation + credential vault, surfaced in-session.
//
// Three parts, one store, hub-side and local:
//
//   (a) STRUCTURED, TEMPLATED documentation attached to devices and
//       device groups in the roster. Templates carry typed fields
//       (a network-facts doc HAS subnet/gateway/DNS/VLAN fields; a
//       vendor-contact doc HAS name/company/phone/contract) — a
//       free-text-only doc is the failure mode this replaces, so
//       unknown fields refuse, required fields must be present, and
//       every value is length- and control-character-checked at the
//       door. A free-text Notes field rides on every template.
//       Edits are VERSIONED: every edit appends an immutable version
//       record (fields snapshot, who, when, which fields changed);
//       no API rewrites or deletes a version. Deleting a document
//       tombstones it — the history is retained, because the record
//       is the value.
//
//   (b) A CREDENTIAL VAULT for site passwords under the existing
//       security machinery: secret material exists ONLY as
//       ISecretProtector-protected text (DPAPI in production — the
//       RMM-18 escrow discipline). Listings are metadata DTOs with
//       NO secret field by construction. Visibility is RBAC-scoped:
//       a credential is visible only to the users / user groups an
//       admin grants (plus scope admins). REVEAL requires re-auth
//       against the existing second-factor machinery (IReAuthGate;
//       TotpReAuthGate adapts SecondFactorService) and is audited
//       BEFORE the secret leaves the vault — every reveal and every
//       refused reveal is a chained-audit event carrying who, which
//       credential, and when. NEVER the secret, and never a hash OF
//       the secret: an unsalted SHA-256 of a low-entropy site
//       password is an offline-cracking oracle for anyone who can
//       read a listing or the audit log (D38 F1). The vault's
//       substitution binding is a hash of the PROTECTED text, held
//       only inside the entry (and the persistence export, beside
//       the protected text itself): it detects swapped material
//       without ever letting a reader verify a guessed secret.
//       Credential ids are random, never derived from the secret —
//       a content-derived id would let any live user confirm a
//       guessed password via the create-collision refusal (D38 F2).
//       This store is NOT the RMM-18 escrow: escrow is dual-control
//       machine recovery keys; this vault is RBAC + re-auth human
//       site credentials. The models are neighbours, deliberately
//       not merged.
//
//   (c) IN-SESSION SURFACING: GetSessionContext is the query
//       contract the session view calls for the device being worked
//       on. It returns that device's documents, its groups'
//       documents, and the credential METADATA visible to the
//       requesting user for that device/groups — secrets are NEVER
//       part of the context; they move only through Reveal. The
//       query is target-strict: another device's records cannot
//       appear in this device's context (cross-device bleed is
//       refused by construction, and destruction-tested).
//
// Policy: TOTAL POLICY CONTROL toggle `rmm.site_documentation.enabled`
// (RMM-07 registry, seeded ON) gates the in-session surfacing, every
// document read/write, and every credential reveal. The gate FAILS
// CLOSED (D38 F6): when a policy engine is wired but a target's
// facts do not resolve (or resolve for another scope/device), the
// answer is no. Device targets evaluate against the device's facts;
// group targets evaluate at scope level (org/scope policy documents
// and the registry default — a group has no device attributes).
// =====================================================================

public static class DocTargetKinds
{
    public const string Device = "device";
    public const string Group = "group";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Device, Group };
}

public static class DocTemplateKinds
{
    public const string SiteNotes = "site_notes";
    public const string NetworkFacts = "network_facts";
    public const string VendorContact = "vendor_contact";
    public const string Procedure = "procedure";
}

/// <summary>One typed field of a documentation template.</summary>
public sealed record DocFieldDef(string Name, bool Required, int MaxLength = 500);

/// <summary>A documentation template: a closed, typed field set.
/// A document may carry exactly these fields (plus the universal
/// free-text Notes) — anything else refuses at the door.</summary>
public sealed record DocTemplate(string Kind, string DisplayName, IReadOnlyList<DocFieldDef> Fields)
{
    public DocFieldDef? Field(string name) =>
        Fields.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));
}

public static class DocTemplates
{
    public static readonly IReadOnlyList<DocTemplate> All = new[]
    {
        new DocTemplate(DocTemplateKinds.SiteNotes, "Site notes", new[]
        {
            new DocFieldDef("site_name", Required: true, MaxLength: 200),
            new DocFieldDef("address", Required: false, MaxLength: 300),
            new DocFieldDef("contact_name", Required: false, MaxLength: 200),
            new DocFieldDef("access_instructions", Required: false, MaxLength: 1000),
            new DocFieldDef("parking_loading", Required: false, MaxLength: 500),
        }),
        new DocTemplate(DocTemplateKinds.NetworkFacts, "Network facts", new[]
        {
            new DocFieldDef("subnet", Required: true, MaxLength: 100),
            new DocFieldDef("gateway", Required: false, MaxLength: 100),
            new DocFieldDef("dns_servers", Required: false, MaxLength: 300),
            new DocFieldDef("vlans", Required: false, MaxLength: 500),
            new DocFieldDef("dhcp_range", Required: false, MaxLength: 200),
            new DocFieldDef("public_ip", Required: false, MaxLength: 100),
            new DocFieldDef("isp", Required: false, MaxLength: 200),
        }),
        new DocTemplate(DocTemplateKinds.VendorContact, "Vendor contact", new[]
        {
            new DocFieldDef("name", Required: true, MaxLength: 200),
            new DocFieldDef("company", Required: true, MaxLength: 200),
            new DocFieldDef("phone", Required: false, MaxLength: 60),
            new DocFieldDef("email", Required: false, MaxLength: 200),
            new DocFieldDef("contract_ref", Required: false, MaxLength: 200),
            new DocFieldDef("support_hours", Required: false, MaxLength: 200),
        }),
        new DocTemplate(DocTemplateKinds.Procedure, "Procedure", new[]
        {
            new DocFieldDef("steps", Required: true, MaxLength: 4000),
            new DocFieldDef("prerequisites", Required: false, MaxLength: 1000),
            new DocFieldDef("escalation", Required: false, MaxLength: 500),
            new DocFieldDef("expected_duration", Required: false, MaxLength: 100),
        }),
    };

    public static DocTemplate? TryGet(string? kind) =>
        All.FirstOrDefault(t => string.Equals(t.Kind, (kind ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal));
}

/// <summary>One immutable version of a document. History is
/// append-only: an edit creates the next version; no operation
/// modifies or removes a version once written. Each version carries
/// a chain hash over the previous version's hash + its own content
/// + the document's IDENTITY binding (id, scope, target kind/id,
/// template, title, creator — D38 F4), so a rewritten history (an
/// old version's fields quietly changed in a stored export, or the
/// document re-homed to another scope/target) fails verification
/// and refuses at import — the same tamper-evidence discipline as
/// the chained audit. The chain head is also recorded in the
/// chained-audit create/edit entries, anchoring the head outside
/// the export: a fully resealed chain still disagrees with the
/// audit. The current snapshot (including the Deleted tombstone
/// flag) carries its own hash over the chain head, so an export
/// edit that un-deletes a document fails the same check.</summary>
public sealed record SiteDocumentVersion(
    int Version,
    IReadOnlyDictionary<string, string> Fields,
    string Notes,
    string ChangedBy,
    DateTimeOffset ChangedUtc,
    IReadOnlyList<string> ChangedFields,
    string ContentHash = "");

/// <summary>A site document: the current snapshot. The full version
/// history lives in the store and is read via GetHistory.</summary>
public sealed record SiteDocument(
    string Id,
    string ScopeId,
    string TargetKind,          // DocTargetKinds.*
    string TargetId,            // device id or device-group id
    string TemplateKind,
    string Title,
    int CurrentVersion,
    IReadOnlyDictionary<string, string> Fields,
    string Notes,
    string CreatedBy,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    bool Deleted = false,
    string SnapshotHash = "");

/// <summary>Credential metadata — the ONLY shape listings and the
/// in-session context expose. There is deliberately no secret field
/// and no protected-text field: a listing cannot leak what it does
/// not hold (the RMM-16/RMM-18 listing discipline).</summary>
public sealed record SiteCredentialMetadata(
    string Id,
    string ScopeId,
    string TargetKind,
    string TargetId,
    string Label,
    string Username,
    string Category,
    IReadOnlySet<string> GrantedUserIds,
    IReadOnlySet<string> GrantedUserGroupIds,
    // NO secret fingerprint (D38 F1): a plain SHA-256 of the secret
    // in a listing is an offline-cracking oracle. The substitution
    // binding (a hash of the protected text) never leaves the entry.
    string CreatedBy,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    string ProtectorName,
    bool IsRealProtection);

/// <summary>The in-session query result: everything the session view
/// needs for the device being worked on — its documents (device +
/// its groups), and the credential metadata visible to the
/// requesting user. Secrets are absent by construction.</summary>
public sealed record SessionDeviceContext(
    string ScopeId,
    string DeviceId,
    string RequestedBy,
    DateTimeOffset QueriedUtc,
    IReadOnlyList<SiteDocument> Documents,
    IReadOnlyList<SiteCredentialMetadata> Credentials);

/// <summary>The re-auth gate a reveal must pass: the revealing user
/// re-authenticates at reveal time. Implementations bind to the
/// existing second-factor machinery; a reveal with NO gate wired
/// refuses (fail closed — re-auth is the control, not a courtesy).</summary>
public interface IReAuthGate
{
    bool Verify(string scopeId, string userId, string proof, DateTimeOffset now);
}

/// <summary>Re-auth against DeskGuest's local second factor (TOTP): the
/// reveal proof is a current TOTP code, verified (and its step
/// consumed, so a code cannot be replayed across reveals) by
/// SecondFactorService — the existing machinery, not a new one.</summary>
public sealed class TotpReAuthGate : IReAuthGate
{
    private readonly SecondFactorService _secondFactor;
    public TotpReAuthGate(SecondFactorService secondFactor) =>
        _secondFactor = secondFactor ?? throw new ArgumentNullException(nameof(secondFactor));
    public bool Verify(string scopeId, string userId, string proof, DateTimeOffset now) =>
        !string.IsNullOrWhiteSpace(proof) && _secondFactor.VerifyTotp(scopeId, userId, proof, now);
}

public static class SiteDocumentationPolicyKeys
{
    public const string Enabled = "rmm.site_documentation.enabled";
}

public sealed class SiteDocumentationService
{
    public const int MaxTitleLength = 200;
    public const int MaxNotesLength = 8000;
    public const int MaxSecretLength = 512;
    public const int MaxLabelLength = 200;
    /// <summary>Per-document version cap (D38 F11): history is the
    /// record and stays generous, but unbounded growth per document
    /// is a storage denial-of-service — an edit past the cap refuses
    /// by name instead of growing the store forever.</summary>
    public const int MaxHistoryVersions = 1000;

    private sealed class DocEntry
    {
        public required SiteDocument Current;
        public required List<SiteDocumentVersion> History;
    }

    /// <summary>A vault entry. BindingHash = SHA-256 of the
    /// PROTECTED text (D38 F1): it detects substituted material at
    /// reveal/import, and — unlike a hash of the secret — it cannot
    /// be used to verify a guessed secret without the protector.
    /// It is never copied into metadata, listings, or audit.</summary>
    private sealed record CredEntry(string ProtectedSecret, string BindingHash, SiteCredentialMetadata Metadata);

    private static string BindingOf(string protectedSecret) => EncryptionHash.Sha256Hex(protectedSecret);

    private readonly ISecretProtector _protector;
    private readonly ChainedAuditLog _audit;
    private readonly RosterService? _roster;
    private readonly ManagementPolicyEngine? _policy;
    private readonly Func<string, IDeviceFacts?>? _facts;
    private readonly IReAuthGate? _reAuth;
    private readonly Func<DateTimeOffset> _now;
    private readonly Dictionary<string, DocEntry> _docs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CredEntry> _creds = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public event Action? Changed;

    /// <param name="roster">When wired, scope membership, liveness
    /// and RBAC grants are enforced against the roster. When null
    /// (bare hub tooling), direct user grants still apply and scope
    /// admins cannot be resolved — reveals then require a direct
    /// grant. Production wiring passes the roster.</param>
    /// <param name="reAuth">The re-auth gate. When null, EVERY
    /// reveal and rotation refuses — named, never silent.</param>
    public SiteDocumentationService(
        ISecretProtector protector,
        ChainedAuditLog audit,
        RosterService? roster = null,
        ManagementPolicyEngine? policy = null,
        Func<string, IDeviceFacts?>? facts = null,
        IReAuthGate? reAuth = null,
        Func<DateTimeOffset>? now = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _roster = roster;
        _policy = policy;
        _facts = facts;
        _reAuth = reAuth;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public bool IsRealProtection => _protector.IsRealProtection;

    // ---- validation helpers -------------------------------------------------

    private static bool IsValidId(string? id) =>
        !string.IsNullOrWhiteSpace(id) && !id.Any(char.IsControl);

    /// <summary>Clean a documentation text value: trims, refuses
    /// control characters (tab/newline allowed only where the field
    /// is multi-line prose) and refuses oversize. This is the
    /// template-injection door: a value that could break the
    /// session-view contract never enters the store.</summary>
    private static bool TryClean(string? value, int maxLength, bool allowNewlines, out string cleaned)
    {
        cleaned = "";
        if (value is null) return false;
        var v = value.Trim();
        if (v.Length > maxLength) return false;
        foreach (var c in v)
        {
            if (char.IsControl(c) && c != '\t' && !(allowNewlines && (c == '\n' || c == '\r')))
                return false;
        }
        cleaned = v;
        return true;
    }

    private static bool ValidateFields(DocTemplate template, IReadOnlyDictionary<string, string>? fields,
        out Dictionary<string, string> cleaned, out string reason)
    {
        cleaned = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        reason = "";
        fields ??= new Dictionary<string, string>();
        foreach (var (rawName, rawValue) in fields)
        {
            var def = template.Field((rawName ?? "").Trim());
            if (def is null)
            {
                reason = $"field '{rawName}' is not part of template '{template.Kind}' — refused (structured templates are closed: free-form fields are the failure mode this replaces)";
                return false;
            }
            var multiLine = def.MaxLength > 500;
            if (!TryClean(rawValue, def.MaxLength, multiLine, out var v))
            {
                reason = $"field '{def.Name}' is oversize (max {def.MaxLength}) or carries control characters — refused";
                return false;
            }
            if (v.Length > 0) cleaned[def.Name] = v;
        }
        foreach (var def in template.Fields.Where(f => f.Required))
        {
            if (!cleaned.TryGetValue(def.Name, out var v) || v.Length == 0)
            {
                reason = $"template '{template.Kind}' requires field '{def.Name}' — refused";
                return false;
            }
        }
        return true;
    }

    /// <summary>The identity a document's chain is bound to (D38
    /// F4): id, scope, target, template, title and creator. Editing
    /// any of these in an export invalidates every version hash, so
    /// a document cannot be silently re-homed or retitled.</summary>
    private static string DocBinding(string id, string scopeId, string targetKind, string targetId,
        string templateKind, string title, string createdBy) =>
        $"{id}|{scopeId}|{targetKind}|{targetId}|{templateKind}|{title}|{createdBy}";

    private static string CanonicalFields(IReadOnlyDictionary<string, string> fields) =>
        string.Join("\n", fields
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value}"));

    /// <summary>The version chain hash: the document's identity
    /// binding + previous hash + this version's number, canonical
    /// field set, notes, author and timestamp. Canonical = field
    /// names sorted ordinal, so the hash is a function of content,
    /// not dictionary order. Private (D38 F4): the algorithm is not
    /// a public resealing kit; the residual reseal threat is named
    /// in the lane ledger (R3) and backstopped by the audit anchor.</summary>
    private static string VersionHash(string docBinding, string prevHash, int version,
        IReadOnlyDictionary<string, string> fields, string notes, string changedBy, DateTimeOffset changedUtc) =>
        EncryptionHash.Sha256Hex($"{docBinding}|{prevHash}|{version}|{CanonicalFields(fields)}|{notes}|{changedBy}|{changedUtc:O}");

    /// <summary>The current-snapshot hash: chain head + tombstone
    /// flag + version count + canonical snapshot. An export edit
    /// that flips Deleted (un-deleting a tombstoned document) or
    /// rewrites the snapshot without touching the chain fails this
    /// check at import and in VerifyHistory (D38 F4).</summary>
    private static string SnapshotHashOf(string headHash, bool deleted, int currentVersion,
        IReadOnlyDictionary<string, string> fields, string notes) =>
        EncryptionHash.Sha256Hex($"snapshot|{headHash}|{deleted}|{currentVersion}|{CanonicalFields(fields)}|{notes}");

    public const string HistoryGenesis = "GENESIS";

    private bool LiveUser(string scopeId, string? userId, bool humanOnly = false)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        if (_roster is null) return true; // bare tooling: identity is the caller's seam
        var user = _roster.GetUser(scopeId, userId);
        return user is not null && !user.Suspended && (!humanOnly || user.Kind == "human");
    }

    private bool IsScopeAdmin(string scopeId, string? userId) =>
        _roster is not null && !string.IsNullOrWhiteSpace(userId) && _roster.IsScopeAdmin(scopeId, userId);

    /// <summary>The policy gate (D38 F6) — FAILS CLOSED. No policy
    /// engine wired = no gate (bare tooling). Engine wired: the
    /// device's facts must resolve, must name THIS device, and must
    /// belong to THIS scope when they carry one; anything else is a
    /// refusal, never an allow-by-default.</summary>
    private bool PolicyAllowsDevice(string scopeId, string deviceId)
    {
        if (_policy is null) return true;
        if (_facts is null) return false;
        var facts = _facts(deviceId);
        if (facts is null) return false;
        if (!string.Equals(facts.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(facts.ScopeId) &&
            !string.Equals(facts.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)) return false;
        return _policy.IsEnabled(facts, SiteDocumentationPolicyKeys.Enabled);
    }

    /// <summary>Policy for a document/credential target. Devices
    /// evaluate against their own facts; groups have no device
    /// facts, so they evaluate at scope level (synthetic facts for
    /// the group id in the scope — org/scope policy documents and
    /// the registry default decide). Group targets therefore have a
    /// real policy check too (D38 F6/R2).</summary>
    private bool PolicyAllowsTarget(string scopeId, string targetKind, string targetId)
    {
        if (targetKind == DocTargetKinds.Device) return PolicyAllowsDevice(scopeId, targetId);
        if (_policy is null) return true;
        return _policy.IsEnabled(StaticDeviceFacts.Of(targetId, scopeId), SiteDocumentationPolicyKeys.Enabled);
    }

    private void Audit(string kind, string actor, string detail) =>
        _audit.Append(kind, actor ?? "", detail, _now());

    // ---- documents ------------------------------------------------------------

    public (bool Ok, string Reason, SiteDocument? Document) CreateDocument(
        string actorUserId, string scopeId, string targetKind, string targetId,
        string templateKind, string title, IReadOnlyDictionary<string, string>? fields, string? notes)
    {
        (bool, string, SiteDocument?) Refuse(string r)
        {
            Audit("site_doc_refused", actorUserId, $"op=create scope={scopeId} target={targetKind}:{targetId} template={templateKind} reason={r}");
            return (false, r, null);
        }
        var kind = (targetKind ?? "").Trim().ToLowerInvariant();
        if (!DocTargetKinds.All.Contains(kind)) return Refuse($"unknown target kind '{targetKind}' — refused (documentation attaches to a device or a device group)");
        if (!IsValidId(scopeId) || !IsValidId(targetId)) return Refuse("documentation needs a valid scope and target id — refused");
        if (!LiveUser(scopeId, actorUserId, humanOnly: true)) return Refuse($"actor '{actorUserId}' is not a live human user of scope '{scopeId}' — refused (documentation is authored by humans; D38 F9)");
        var template = DocTemplates.TryGet(templateKind);
        if (template is null) return Refuse($"unknown template kind '{templateKind}' — refused (templates are a closed set)");
        if (!TryClean(title, MaxTitleLength, allowNewlines: false, out var cleanTitle) || cleanTitle.Length == 0)
            return Refuse($"title is empty, oversize (max {MaxTitleLength}) or carries control characters — refused");
        if (!ValidateFields(template, fields, out var cleanedFields, out var fieldReason)) return Refuse(fieldReason);
        if (!TryClean(notes ?? "", MaxNotesLength, allowNewlines: true, out var cleanNotes))
            return Refuse($"notes are oversize (max {MaxNotesLength}) or carry disallowed control characters — refused");
        if (kind == DocTargetKinds.Group && _roster is not null && _roster.GetDeviceGroup(scopeId, targetId) is null)
            return Refuse($"device group '{targetId}' does not exist in scope '{scopeId}' — refused (documentation attaches to roster targets)");
        if (!PolicyAllowsTarget(scopeId, kind, targetId))
            return Refuse($"site documentation is disabled by policy for {kind} '{targetId}' ({SiteDocumentationPolicyKeys.Enabled}) — refused");

        var now = _now();
        var id = "doc-" + EncryptionHash.Sha256Hex($"{scopeId}|{kind}|{targetId}|{template.Kind}|{cleanTitle}|{actorUserId}|{now:O}")[..20];
        var changedFields = cleanedFields.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        if (cleanNotes.Length > 0) changedFields.Add("notes");
        var binding = DocBinding(id, scopeId, kind, targetId, template.Kind, cleanTitle, actorUserId);
        var headHash = VersionHash(binding, HistoryGenesis, 1, cleanedFields, cleanNotes, actorUserId, now);
        var doc = new SiteDocument(id, scopeId, kind, targetId, template.Kind, cleanTitle, 1,
            cleanedFields, cleanNotes, actorUserId, now, now, false,
            SnapshotHashOf(headHash, false, 1, cleanedFields, cleanNotes));
        lock (_gate)
        {
            if (_docs.ContainsKey(id)) return Refuse("a document with this identity already exists — refused");
            _docs[id] = new DocEntry
            {
                Current = doc,
                History = new List<SiteDocumentVersion>
                {
                    new(1, new Dictionary<string, string>(cleanedFields, StringComparer.OrdinalIgnoreCase),
                        cleanNotes, actorUserId, now, changedFields, headHash),
                },
            };
        }
        // The audit carries the chain head (D38 F4): the head is
        // anchored in the chained audit, outside the export.
        Audit("site_doc_created", actorUserId,
            $"doc={id} scope={scopeId} target={kind}:{targetId} template={template.Kind} version=1 fields={string.Join(",", changedFields)} hash={headHash}");
        Changed?.Invoke();
        return (true, $"document '{cleanTitle}' created as {id} (template {template.Kind}, version 1)", doc);
    }

    /// <summary>Edit a document: full field-set replacement under
    /// the template, appended as the NEXT version. The previous
    /// version is never modified — history rewriting is impossible
    /// through this API. A no-op edit refuses (a version that
    /// changes nothing would falsify the history).</summary>
    public (bool Ok, string Reason, SiteDocument? Document) EditDocument(
        string actorUserId, string documentId, IReadOnlyDictionary<string, string>? fields, string? notes)
    {
        (bool, string, SiteDocument?) Refuse(string r)
        {
            Audit("site_doc_refused", actorUserId, $"op=edit doc={documentId} reason={r}");
            return (false, r, null);
        }
        DocEntry? probe;
        lock (_gate) _docs.TryGetValue(documentId ?? "", out probe);
        if (probe is null) return Refuse($"no document under id '{documentId}' — refused");
        var probeCurrent = probe.Current;
        if (!LiveUser(probeCurrent.ScopeId, actorUserId, humanOnly: true)) return Refuse($"actor '{actorUserId}' is not a live human user of scope '{probeCurrent.ScopeId}' — refused (D38 F9)");
        if (!PolicyAllowsTarget(probeCurrent.ScopeId, probeCurrent.TargetKind, probeCurrent.TargetId))
            return Refuse($"site documentation is disabled by policy for {probeCurrent.TargetKind} '{probeCurrent.TargetId}' — refused");
        var template = DocTemplates.TryGet(probeCurrent.TemplateKind)!;
        if (!ValidateFields(template, fields, out var cleanedFields, out var fieldReason)) return Refuse(fieldReason);
        if (!TryClean(notes ?? "", MaxNotesLength, allowNewlines: true, out var cleanNotes))
            return Refuse($"notes are oversize (max {MaxNotesLength}) or carry disallowed control characters — refused");

        // D38 F5: the version computation runs INSIDE the gate
        // against the CURRENT entry — two concurrent edits can no
        // longer both compute CurrentVersion+1 from a stale copy
        // and append duplicate version numbers.
        var now = _now();
        SiteDocument next;
        List<string> changed;
        string headHash;
        lock (_gate)
        {
            if (!_docs.TryGetValue(documentId ?? "", out var entry))
                return Refuse($"no document under id '{documentId}' — refused");
            var current = entry.Current;
            if (current.Deleted) return Refuse($"document '{documentId}' is deleted — refused (its history is retained read-only)");
            if (entry.History.Count >= MaxHistoryVersions)
                return Refuse($"document '{documentId}' already holds the maximum {MaxHistoryVersions} versions — refused (history cap, D38 F11)");
            changed = new List<string>();
            var allKeys = new HashSet<string>(current.Fields.Keys, StringComparer.OrdinalIgnoreCase);
            allKeys.UnionWith(cleanedFields.Keys);
            foreach (var k in allKeys.OrderBy(k => k, StringComparer.Ordinal))
            {
                var before = current.Fields.TryGetValue(k, out var b) ? b : null;
                var after = cleanedFields.TryGetValue(k, out var a) ? a : null;
                if (!string.Equals(before, after, StringComparison.Ordinal)) changed.Add(k);
            }
            if (!string.Equals(current.Notes, cleanNotes, StringComparison.Ordinal)) changed.Add("notes");
            if (changed.Count == 0) return Refuse("the edit changes nothing — refused (a version must record a real change)");
            var binding = DocBinding(current.Id, current.ScopeId, current.TargetKind, current.TargetId,
                current.TemplateKind, current.Title, current.CreatedBy);
            var prevHash = entry.History.Count > 0 ? entry.History[^1].ContentHash : HistoryGenesis;
            headHash = VersionHash(binding, prevHash, current.CurrentVersion + 1, cleanedFields, cleanNotes, actorUserId, now);
            next = current with
            {
                CurrentVersion = current.CurrentVersion + 1,
                Fields = cleanedFields,
                Notes = cleanNotes,
                UpdatedUtc = now,
                SnapshotHash = SnapshotHashOf(headHash, current.Deleted, current.CurrentVersion + 1, cleanedFields, cleanNotes),
            };
            entry.History.Add(new SiteDocumentVersion(next.CurrentVersion,
                new Dictionary<string, string>(cleanedFields, StringComparer.OrdinalIgnoreCase),
                cleanNotes, actorUserId, now, changed, headHash));
            entry.Current = next;
        }
        Audit("site_doc_edited", actorUserId,
            $"doc={next.Id} scope={next.ScopeId} target={next.TargetKind}:{next.TargetId} version={next.CurrentVersion} changed={string.Join(",", changed)} hash={headHash}");
        Changed?.Invoke();
        return (true, $"document '{next.Id}' edited — now version {next.CurrentVersion} (changed: {string.Join(", ", changed)})", next);
    }

    /// <summary>Tombstone a document (scope admins only). The
    /// document leaves every listing and session context; its full
    /// version history is RETAINED and stays readable — deletion
    /// never erases the record.</summary>
    public (bool Ok, string Reason) DeleteDocument(string actorUserId, string documentId)
    {
        DocEntry? entry;
        lock (_gate) _docs.TryGetValue(documentId ?? "", out entry);
        if (entry is null)
        {
            // BD-SHARED-PLAT-3/F8: EVERY refusal is audited — the
            // not-found refusal used to return silently.
            Audit("site_doc_refused", actorUserId, $"op=delete doc={documentId} reason=not_found");
            return (false, $"no document under id '{documentId}' — refused");
        }
        var current = entry.Current;
        // BD-SHARED-PLAT-3/F8: admin-only mutations run the SAME
        // live-human check every other path runs — IsScopeAdmin
        // alone would let a suspended or AI-kind admin principal
        // delete records (RotateCredentialSecret already required
        // LiveUser(humanOnly:true); the delete/grant paths did not).
        if (!LiveUser(current.ScopeId, actorUserId, humanOnly: true))
        {
            Audit("site_doc_refused", actorUserId, $"op=delete doc={documentId} reason=not_live_human");
            return (false, "only a live human scope admin may delete a document — refused");
        }
        if (!IsScopeAdmin(current.ScopeId, actorUserId))
        {
            Audit("site_doc_refused", actorUserId, $"op=delete doc={documentId} reason=not_scope_admin");
            return (false, "only a scope admin may delete a document — refused");
        }
        int retained;
        lock (_gate)
        {
            // Re-check under the gate (D38 F5): a racing edit/delete
            // must not resurrect or double-tombstone the document.
            // BD-SHARED-PLAT-3/F8: these race refusals are audited
            // too (the audit append is chain-locked, not gate-locked).
            if (!_docs.TryGetValue(documentId ?? "", out var fresh))
            {
                Audit("site_doc_refused", actorUserId, $"op=delete doc={documentId} reason=not_found_race");
                return (false, $"no document under id '{documentId}' — refused");
            }
            if (fresh.Current.Deleted)
            {
                Audit("site_doc_refused", actorUserId, $"op=delete doc={documentId} reason=already_deleted");
                return (false, $"document '{documentId}' is already deleted — refused");
            }
            var head = fresh.History.Count > 0 ? fresh.History[^1].ContentHash : HistoryGenesis;
            fresh.Current = fresh.Current with
            {
                Deleted = true,
                UpdatedUtc = _now(),
                SnapshotHash = SnapshotHashOf(head, true, fresh.Current.CurrentVersion, fresh.Current.Fields, fresh.Current.Notes),
            };
            retained = fresh.History.Count;
        }
        Audit("site_doc_deleted", actorUserId,
            $"doc={current.Id} scope={current.ScopeId} target={current.TargetKind}:{current.TargetId} versions_retained={retained}");
        Changed?.Invoke();
        return (true, $"document '{current.Id}' deleted (tombstoned; {entry.History.Count} version(s) retained in history)");
    }

    /// <summary>Read one document. Actor-checked (D38 F7): the
    /// document APIs take an actor and require a live user of the
    /// scope — knowing a scope id is not an authorization. Policy-
    /// gated per target (D38 F6).</summary>
    public SiteDocument? GetDocument(string actorUserId, string scopeId, string documentId)
    {
        if (!LiveUser(scopeId, actorUserId)) return null;
        lock (_gate)
            return _docs.TryGetValue(documentId ?? "", out var e) &&
                   string.Equals(e.Current.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                   !e.Current.Deleted &&
                   PolicyAllowsTarget(scopeId, e.Current.TargetKind, e.Current.TargetId) ? Clone(e.Current) : null;
    }

    /// <summary>Documents for one target (or all targets of a kind
    /// in a scope). Deleted documents never list. Actor-checked and
    /// policy-gated (D38 F6/F7): a non-live actor lists nothing,
    /// and documents on policy-disabled targets are absent.</summary>
    public IReadOnlyList<SiteDocument> ListDocuments(string actorUserId, string scopeId, string? targetKind = null, string? targetId = null)
    {
        if (!LiveUser(scopeId, actorUserId)) return Array.Empty<SiteDocument>();
        lock (_gate) return _docs.Values.Select(e => e.Current)
            .Where(d => !d.Deleted &&
                        string.Equals(d.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                        (targetKind is null || string.Equals(d.TargetKind, targetKind, StringComparison.OrdinalIgnoreCase)) &&
                        (targetId is null || string.Equals(d.TargetId, targetId, StringComparison.OrdinalIgnoreCase)) &&
                        PolicyAllowsTarget(scopeId, d.TargetKind, d.TargetId))
            .OrderBy(d => d.Id, StringComparer.Ordinal).Select(Clone).ToList();
    }

    /// <summary>The full version history of a document, oldest
    /// first — including for a deleted document (the record is the
    /// value). Actor- and scope-checked (D38 F7): history of a
    /// document in another scope is not readable through this
    /// scope, and no actor means no history.</summary>
    public IReadOnlyList<SiteDocumentVersion> GetHistory(string actorUserId, string scopeId, string documentId)
    {
        if (!LiveUser(scopeId, actorUserId)) return Array.Empty<SiteDocumentVersion>();
        lock (_gate)
        {
            if (!_docs.TryGetValue(documentId ?? "", out var e) ||
                !string.Equals(e.Current.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) ||
                !PolicyAllowsTarget(scopeId, e.Current.TargetKind, e.Current.TargetId))
                return Array.Empty<SiteDocumentVersion>();
            return e.History.Select(v => v with
            {
                Fields = new Dictionary<string, string>(v.Fields, StringComparer.OrdinalIgnoreCase),
                ChangedFields = v.ChangedFields.ToList(),
            }).ToList();
        }
    }

    /// <summary>Re-verify a document's version chain from genesis:
    /// true only when every version's content still hashes to its
    /// recorded chain hash and the versions run 1..N.</summary>
    public bool VerifyHistory(string scopeId, string documentId)
    {
        lock (_gate)
        {
            if (!_docs.TryGetValue(documentId ?? "", out var e) ||
                !string.Equals(e.Current.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                return false;
            var binding = DocBinding(e.Current.Id, e.Current.ScopeId, e.Current.TargetKind, e.Current.TargetId,
                e.Current.TemplateKind, e.Current.Title, e.Current.CreatedBy);
            var prev = HistoryGenesis;
            for (var i = 0; i < e.History.Count; i++)
            {
                var v = e.History[i];
                if (v.Version != i + 1) return false;
                var expect = VersionHash(binding, prev, v.Version, v.Fields, v.Notes, v.ChangedBy, v.ChangedUtc);
                if (!string.Equals(expect, v.ContentHash, StringComparison.OrdinalIgnoreCase)) return false;
                prev = expect;
            }
            if (e.History.Count == 0 || e.Current.CurrentVersion != e.History.Count) return false;
            // The snapshot (incl. the tombstone flag) must hash to
            // its recorded snapshot hash over the verified head.
            // BD-SHARED-PLAT-3/F4: an EMPTY snapshot hash verifies
            // NOTHING — the old shape returned true for it, so a
            // record whose hash had been blanked (the legacy-import
            // shape) passed as "verified" with no seal at all.
            var snap = SnapshotHashOf(prev, e.Current.Deleted, e.Current.CurrentVersion, e.Current.Fields, e.Current.Notes);
            return e.Current.SnapshotHash.Length != 0 &&
                   string.Equals(snap, e.Current.SnapshotHash, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static SiteDocument Clone(SiteDocument d) => d with
    {
        Fields = new Dictionary<string, string>(d.Fields, StringComparer.OrdinalIgnoreCase),
    };

    // ---- credential vault -------------------------------------------------------

    /// <summary>One user's visibility facts for one scope, computed
    /// ONCE per call and OUTSIDE the vault gate (D38 F11): the old
    /// shape re-ran ListUserGroups + IsScopeAdmin per credential
    /// while holding the lock — O(creds × groups) roster calls
    /// under the gate, with a lock-ordering hazard if the roster
    /// ever called back.</summary>
    private sealed record Visibility(bool IsAdmin, IReadOnlySet<string> UserGroupIds);

    private Visibility ComputeVisibility(string scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId) || _roster is null)
            return new Visibility(false, new HashSet<string>());
        var groups = _roster.ListUserGroups(scopeId)
            .Where(g => g.MemberUserIds.Contains(userId)).Select(g => g.Id);
        return new Visibility(_roster.IsScopeAdmin(scopeId, userId),
            new HashSet<string>(groups, StringComparer.OrdinalIgnoreCase));
    }

    private static bool CanSeeCredential(SiteCredentialMetadata meta, string userId, Visibility vis)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        if (vis.IsAdmin) return true;
        if (meta.GrantedUserIds.Contains(userId)) return true;
        return meta.GrantedUserGroupIds.Any(id => vis.UserGroupIds.Contains(id));
    }

    public (bool Ok, string Reason, SiteCredentialMetadata? Metadata) CreateCredential(
        string actorUserId, string scopeId, string targetKind, string targetId,
        string label, string username, string category, string secret,
        IEnumerable<string>? grantedUserIds = null, IEnumerable<string>? grantedUserGroupIds = null)
    {
        (bool, string, SiteCredentialMetadata?) Refuse(string r)
        {
            Audit("site_credential_refused", actorUserId, $"op=create scope={scopeId} target={targetKind}:{targetId} label={label} reason={r}");
            return (false, r, null);
        }
        var kind = (targetKind ?? "").Trim().ToLowerInvariant();
        if (!DocTargetKinds.All.Contains(kind)) return Refuse($"unknown target kind '{targetKind}' — refused");
        if (!IsValidId(scopeId) || !IsValidId(targetId)) return Refuse("a credential needs a valid scope and target id — refused");
        if (!LiveUser(scopeId, actorUserId, humanOnly: true)) return Refuse($"actor '{actorUserId}' is not a live human user of scope '{scopeId}' — refused");
        if (!TryClean(label, MaxLabelLength, allowNewlines: false, out var cleanLabel) || cleanLabel.Length == 0)
            return Refuse($"label is empty, oversize (max {MaxLabelLength}) or carries control characters — refused");
        if (!TryClean(username ?? "", 200, allowNewlines: false, out var cleanUser))
            return Refuse("username is oversize or carries control characters — refused");
        if (!TryClean(category ?? "", 100, allowNewlines: false, out var cleanCategory))
            return Refuse("category is oversize or carries control characters — refused");
        if (string.IsNullOrEmpty(secret) || secret.Length > MaxSecretLength || secret.Any(char.IsControl))
            return Refuse($"secret is empty, oversize (max {MaxSecretLength}) or carries control characters — refused (the secret itself is never recorded in this refusal)");
        if (kind == DocTargetKinds.Group && _roster is not null && _roster.GetDeviceGroup(scopeId, targetId) is null)
            return Refuse($"device group '{targetId}' does not exist in scope '{scopeId}' — refused");
        if (!PolicyAllowsTarget(scopeId, kind, targetId))
            return Refuse($"site documentation is disabled by policy for {kind} '{targetId}' ({SiteDocumentationPolicyKeys.Enabled}) — refused");

        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in grantedUserIds ?? Array.Empty<string>())
        {
            if (!IsValidId(u)) return Refuse($"granted user id '{u}' is malformed — refused");
            if (_roster is not null && _roster.GetUser(scopeId, u) is null)
                return Refuse($"granted user '{u}' is not a user of scope '{scopeId}' — refused (grants never reach outside the scope)");
            users.Add(u.Trim());
        }
        var groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in grantedUserGroupIds ?? Array.Empty<string>())
        {
            if (!IsValidId(g)) return Refuse($"granted user-group id '{g}' is malformed — refused");
            if (_roster is not null && _roster.GetUserGroup(scopeId, g) is null)
                return Refuse($"granted user group '{g}' does not exist in scope '{scopeId}' — refused");
            groups.Add(g.Trim());
        }

        var now = _now();
        // D38 F2: the id is RANDOM — never derived from the secret,
        // its hash, or anything a guesser can reproduce. The old
        // content-derived id turned the collision refusal into a
        // password-confirmation oracle for any live user.
        var id = "cred-" + EncryptionHash.Sha256Hex($"{scopeId}|{kind}|{targetId}|{cleanLabel}|{actorUserId}|{now:O}|{Guid.NewGuid():N}")[..20];
        var meta = new SiteCredentialMetadata(id, scopeId, kind, targetId, cleanLabel, cleanUser, cleanCategory,
            users, groups, actorUserId, now, now, _protector.Name, _protector.IsRealProtection);
        var protectedSecret = _protector.Protect(secret);
        lock (_gate)
        {
            if (_creds.ContainsKey(id)) return Refuse("a credential with this identity already exists — refused (rotate it instead of re-creating)");
            _creds[id] = new CredEntry(protectedSecret, BindingOf(protectedSecret), meta);
        }
        // D38 F1: no fingerprint in the audit — id/target/label only.
        Audit("site_credential_created", actorUserId,
            $"cred={id} scope={scopeId} target={kind}:{targetId} label={cleanLabel} grantedUsers={users.Count} grantedGroups={groups.Count} protector={meta.ProtectorName} realProtection={meta.IsRealProtection}");
        Changed?.Invoke();
        return (true, $"credential '{cleanLabel}' stored as {id}", meta);
    }

    /// <summary>Metadata visible to one user: their grants (direct,
    /// via user-group membership, or scope-admin) decide. Other
    /// users' credentials are absent, not hidden. The caller must
    /// be a LIVE HUMAN user of the scope (D38 F9): a suspended
    /// user, an AI user, or a non-member with a leftover direct
    /// grant lists nothing — grants do not resurrect dead actors.</summary>
    public IReadOnlyList<SiteCredentialMetadata> ListCredentialsFor(string scopeId, string userId,
        string? targetKind = null, string? targetId = null)
    {
        if (!LiveUser(scopeId, userId, humanOnly: true)) return Array.Empty<SiteCredentialMetadata>();
        var vis = ComputeVisibility(scopeId, userId);
        lock (_gate) return _creds.Values.Select(c => c.Metadata)
            .Where(m => string.Equals(m.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                        (targetKind is null || string.Equals(m.TargetKind, targetKind, StringComparison.OrdinalIgnoreCase)) &&
                        (targetId is null || string.Equals(m.TargetId, targetId, StringComparison.OrdinalIgnoreCase)) &&
                        CanSeeCredential(m, userId, vis))
            .OrderBy(m => m.Id, StringComparer.Ordinal).ToList();
    }

    public SiteCredentialMetadata? GetCredentialMetadata(string scopeId, string credentialId, string userId)
    {
        if (!LiveUser(scopeId, userId, humanOnly: true)) return null;
        var vis = ComputeVisibility(scopeId, userId);
        lock (_gate)
            return _creds.TryGetValue(credentialId ?? "", out var c) &&
                   string.Equals(c.Metadata.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                   CanSeeCredential(c.Metadata, userId, vis) ? c.Metadata : null;
    }

    /// <summary>THE reveal — the ONLY path secret material leaves
    /// this vault. Gates, all fail-closed: the credential exists in
    /// the caller's scope; the caller is a live HUMAN user; the
    /// caller holds a grant (direct / user-group / scope admin);
    /// policy allows the credential's target (device facts, or
    /// scope-level for group targets — D38 F6); a re-auth gate is
    /// wired AND the presented proof verifies (SecondFactorService
    /// TOTP via TotpReAuthGate — the step is consumed, so a proof
    /// cannot be replayed); the stored material still matches its
    /// binding (a hash of the protected text — substitution /
    /// tamper check, D38 F1). The final check + unprotect + audit
    /// run under the gate against the CURRENT entry, so a delete
    /// or rotation racing the reveal cannot leak stale material
    /// (D38 F5). The audit entry is appended BEFORE the secret is
    /// returned, so no crash produces an unaudited reveal. Every
    /// refusal is audited too. Audit details carry id/target/label
    /// only — never the secret, never the proof, never a hash of
    /// the secret.</summary>
    public (bool Ok, string Reason, string? Secret) RevealCredential(
        string actorUserId, string scopeId, string credentialId, string? reAuthProof)
    {
        (bool, string, string?) Refuse(string r)
        {
            Audit("site_credential_reveal_refused", actorUserId,
                $"cred={credentialId} scope={scopeId} reason={r}");
            return (false, r, null);
        }
        CredEntry? entry;
        lock (_gate) _creds.TryGetValue(credentialId ?? "", out entry);
        if (entry is null) return Refuse($"no credential under id '{credentialId}' — refused");
        var meta = entry.Metadata;
        if (!string.Equals(meta.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"credential '{credentialId}' does not belong to scope '{scopeId}' — refused (cross-scope reveal is impossible)");
        if (!LiveUser(scopeId, actorUserId, humanOnly: true))
            return Refuse($"actor '{actorUserId}' is not a live human user of scope '{scopeId}' — refused (an AI or a suspended user reveals nothing)");
        if (!CanSeeCredential(meta, actorUserId, ComputeVisibility(scopeId, actorUserId)))
            return Refuse($"actor '{actorUserId}' holds no grant on credential '{credentialId}' — refused (RBAC: visibility is granted, never assumed)");
        if (!PolicyAllowsTarget(meta.ScopeId, meta.TargetKind, meta.TargetId))
            return Refuse($"site documentation is disabled by policy for {meta.TargetKind} '{meta.TargetId}' — refused");
        if (_reAuth is null)
            return Refuse("no re-auth gate is wired on this vault — reveal refuses (re-auth is the control, not a courtesy)");
        if (!_reAuth.Verify(scopeId, actorUserId, reAuthProof ?? "", _now()))
            return Refuse("re-authentication failed — refused (the revealing user must re-authenticate at reveal time)");

        string secret;
        lock (_gate)
        {
            // D38 F5: re-read under the gate — the entry authorized
            // above may have been rotated or deleted since.
            if (!_creds.TryGetValue(credentialId ?? "", out var fresh) ||
                !string.Equals(fresh.ProtectedSecret, entry.ProtectedSecret, StringComparison.Ordinal))
                return Refuse($"credential '{credentialId}' changed while the reveal was being authorized — refused; re-authenticate and retry");
            if (!string.Equals(BindingOf(fresh.ProtectedSecret), fresh.BindingHash, StringComparison.OrdinalIgnoreCase))
                return Refuse($"credential '{credentialId}' material does not match its binding — SUBSTITUTION/TAMPER suspected; refused, the mismatched material is never revealed");
            try { secret = _protector.Unprotect(fresh.ProtectedSecret); }
            catch { return Refuse($"credential '{credentialId}' could not be unprotected — refused (no secret leaves the vault on a protection failure)"); }
            // Audit BEFORE the secret leaves the vault.
            Audit("site_credential_revealed", actorUserId,
                $"cred={meta.Id} scope={meta.ScopeId} target={meta.TargetKind}:{meta.TargetId} label={meta.Label}");
        }
        return (true, $"credential '{meta.Label}' revealed to '{actorUserId}' under re-auth (audited)", secret);
    }

    /// <summary>Existence check for the vendor-pass injection seam
    /// (BD-SHARED-PLAT-3/F3): does this cred- reference name a live
    /// vault entry? Metadata only — no secret material moves.</summary>
    public bool CredentialExistsForInjection(string? credentialRef)
    {
        lock (_gate)
            return credentialRef is not null && _creds.ContainsKey(credentialRef);
    }

    /// <summary>THE vendor-pass injection seam (BD-SHARED-PLAT-3/F3):
    /// resolve a site credential to an opaque handle for the
    /// VaultCredentialInjector, under the vault's own discipline —
    /// the binding is verified (substituted material resolves to
    /// nothing), the chained audit records `site_credential_injected`
    /// BEFORE the value leaves the vault, and a deleted or rotated
    /// credential resolves to nothing (so deleting a site credential
    /// takes effect on every pass that references it at its next
    /// injection). This is deliberately NOT RevealCredential: reveal
    /// is a human act under re-auth that hands the secret to a
    /// person; injection is host code moving the value to the
    /// session layer's sink under a vendor pass, and the two are
    /// audited under different kinds so neither can masquerade as
    /// the other. The handle's Use is internal to this assembly —
    /// only the injector can present the value, and only to a sink.</summary>
    public VaultCredentialHandle? ResolveCredentialForInjection(string? credentialRef)
    {
        if (string.IsNullOrWhiteSpace(credentialRef)) return null;
        lock (_gate)
        {
            if (!_creds.TryGetValue(credentialRef, out var entry)) return null;
            if (!string.Equals(BindingOf(entry.ProtectedSecret), entry.BindingHash, StringComparison.OrdinalIgnoreCase))
            {
                Audit("site_credential_injection_refused", "vendor-pass-injection",
                    $"cred={entry.Metadata.Id} scope={entry.Metadata.ScopeId} reason=binding_mismatch");
                return null;
            }
            string secret;
            try { secret = _protector.Unprotect(entry.ProtectedSecret); }
            catch
            {
                Audit("site_credential_injection_refused", "vendor-pass-injection",
                    $"cred={entry.Metadata.Id} scope={entry.Metadata.ScopeId} reason=unprotect_failed");
                return null;
            }
            Audit("site_credential_injected", "vendor-pass-injection",
                $"cred={entry.Metadata.Id} scope={entry.Metadata.ScopeId} target={entry.Metadata.TargetKind}:{entry.Metadata.TargetId} label={entry.Metadata.Label}");
            return new VaultCredentialHandle(secret);
        }
    }

    /// <summary>Rotate a credential's secret. Authorization is
    /// OWNERSHIP, not read access (D38 F8): only a scope admin or
    /// the credential's creator may rotate, plus live-human and
    /// re-auth gates as for reveal. A read grantee who could rotate
    /// could overwrite the shared site password with a value only
    /// they know — read permission must never double as write
    /// permission. The rotation is audited (never either secret,
    /// never a hash of either secret).</summary>
    public (bool Ok, string Reason) RotateCredentialSecret(
        string actorUserId, string scopeId, string credentialId, string newSecret, string? reAuthProof)
    {
        (bool, string) Refuse(string r)
        {
            Audit("site_credential_refused", actorUserId, $"op=rotate cred={credentialId} scope={scopeId} reason={r}");
            return (false, r);
        }
        CredEntry? entry;
        lock (_gate) _creds.TryGetValue(credentialId ?? "", out entry);
        if (entry is null) return Refuse($"no credential under id '{credentialId}' — refused");
        var meta = entry.Metadata;
        if (!string.Equals(meta.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"credential '{credentialId}' does not belong to scope '{scopeId}' — refused");
        if (!LiveUser(scopeId, actorUserId, humanOnly: true))
            return Refuse($"actor '{actorUserId}' is not a live human user of scope '{scopeId}' — refused");
        if (!IsScopeAdmin(scopeId, actorUserId) &&
            !string.Equals(meta.CreatedBy, actorUserId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"actor '{actorUserId}' is neither a scope admin nor the credential's creator — refused (a read grant does not authorize rotation, D38 F8)");
        if (string.IsNullOrEmpty(newSecret) || newSecret.Length > MaxSecretLength || newSecret.Any(char.IsControl))
            return Refuse($"new secret is empty, oversize (max {MaxSecretLength}) or carries control characters — refused");
        if (_reAuth is null) return Refuse("no re-auth gate is wired on this vault — rotation refuses");
        if (!_reAuth.Verify(scopeId, actorUserId, reAuthProof ?? "", _now()))
            return Refuse("re-authentication failed — refused");

        var newProtected = _protector.Protect(newSecret);
        lock (_gate)
        {
            // D38 F5: rotate the CURRENT entry or none — a racing
            // delete must not be resurrected, and a racing rotation
            // must not be silently lost under a stale write-back.
            if (!_creds.TryGetValue(meta.Id, out var fresh) ||
                !string.Equals(fresh.BindingHash, entry.BindingHash, StringComparison.OrdinalIgnoreCase))
                return Refuse($"credential '{credentialId}' changed while the rotation was being authorized — refused; re-authenticate and retry");
            var updated = fresh.Metadata with
            {
                UpdatedUtc = _now(),
                ProtectorName = _protector.Name,
                IsRealProtection = _protector.IsRealProtection,
            };
            _creds[meta.Id] = new CredEntry(newProtected, BindingOf(newProtected), updated);
        }
        Audit("site_credential_rotated", actorUserId,
            $"cred={meta.Id} scope={meta.ScopeId} target={meta.TargetKind}:{meta.TargetId} label={meta.Label}");
        Changed?.Invoke();
        return (true, $"credential '{meta.Label}' rotated");
    }

    /// <summary>Replace a credential's grants (scope admins only).
    /// Grant changes are audited with counts + the new grantee ids
    /// (ids are not secrets).</summary>
    public (bool Ok, string Reason) UpdateCredentialGrants(
        string actorUserId, string scopeId, string credentialId,
        IEnumerable<string>? grantedUserIds, IEnumerable<string>? grantedUserGroupIds)
    {
        (bool, string) Refuse(string r)
        {
            Audit("site_credential_refused", actorUserId, $"op=grants cred={credentialId} scope={scopeId} reason={r}");
            return (false, r);
        }
        CredEntry? entry;
        lock (_gate) _creds.TryGetValue(credentialId ?? "", out entry);
        if (entry is null) return Refuse($"no credential under id '{credentialId}' — refused");
        var meta = entry.Metadata;
        if (!string.Equals(meta.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"credential '{credentialId}' does not belong to scope '{scopeId}' — refused");
        // BD-SHARED-PLAT-3/F8: live-human before admin, as in
        // DeleteDocument — a suspended or AI-kind admin must not
        // rewrite grants (including granting a credential to
        // itself or an accomplice).
        if (!LiveUser(scopeId, actorUserId, humanOnly: true))
            return Refuse($"actor '{actorUserId}' is not a live human user of scope '{scopeId}' — refused");
        if (!IsScopeAdmin(scopeId, actorUserId))
            return Refuse("only a scope admin may change a credential's grants — refused");
        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in grantedUserIds ?? Array.Empty<string>())
        {
            if (!IsValidId(u) || (_roster is not null && _roster.GetUser(scopeId, u) is null))
                return Refuse($"granted user '{u}' is malformed or not a user of scope '{scopeId}' — refused");
            users.Add(u.Trim());
        }
        var groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in grantedUserGroupIds ?? Array.Empty<string>())
        {
            if (!IsValidId(g) || (_roster is not null && _roster.GetUserGroup(scopeId, g) is null))
                return Refuse($"granted user group '{g}' is malformed or does not exist in scope '{scopeId}' — refused");
            groups.Add(g.Trim());
        }
        lock (_gate)
        {
            // D38 F5: apply to the CURRENT entry — a grant update
            // racing a rotation must keep the rotation (the old
            // shape wrote the stale entry back over it).
            if (!_creds.TryGetValue(meta.Id, out var fresh))
                return Refuse($"no credential under id '{credentialId}' — refused");
            _creds[meta.Id] = fresh with
            {
                Metadata = fresh.Metadata with { GrantedUserIds = users, GrantedUserGroupIds = groups, UpdatedUtc = _now() },
            };
        }
        Audit("site_credential_grants_changed", actorUserId,
            $"cred={meta.Id} scope={meta.ScopeId} grantedUsers=[{string.Join(",", users.OrderBy(u => u, StringComparer.Ordinal))}] grantedGroups=[{string.Join(",", groups.OrderBy(g => g, StringComparer.Ordinal))}]");
        Changed?.Invoke();
        return (true, $"grants for credential '{meta.Label}' updated ({users.Count} user(s), {groups.Count} group(s))");
    }

    /// <summary>Delete a credential (scope admins only). The secret
    /// is destroyed with the entry; the audit keeps the metadata
    /// record (id, label, actor) — deletion of a credential is
    /// itself evidence.</summary>
    public (bool Ok, string Reason) DeleteCredential(string actorUserId, string scopeId, string credentialId)
    {
        CredEntry? entry;
        lock (_gate) _creds.TryGetValue(credentialId ?? "", out entry);
        // BD-SHARED-PLAT-3/F8: not-found and cross-scope refusals
        // are audited like every other refusal (they used to return
        // silently), and the live-human check runs before the
        // admin check, as on every other mutation path.
        if (entry is null)
        {
            Audit("site_credential_refused", actorUserId, $"op=delete cred={credentialId} scope={scopeId} reason=not_found");
            return (false, $"no credential under id '{credentialId}' — refused");
        }
        var meta = entry.Metadata;
        if (!string.Equals(meta.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
        {
            Audit("site_credential_refused", actorUserId, $"op=delete cred={credentialId} scope={scopeId} reason=cross_scope");
            return (false, $"credential '{credentialId}' does not belong to scope '{scopeId}' — refused");
        }
        if (!LiveUser(scopeId, actorUserId, humanOnly: true))
        {
            Audit("site_credential_refused", actorUserId, $"op=delete cred={credentialId} scope={scopeId} reason=not_live_human");
            return (false, "only a live human scope admin may delete a credential — refused");
        }
        if (!IsScopeAdmin(scopeId, actorUserId))
        {
            Audit("site_credential_refused", actorUserId, $"op=delete cred={credentialId} scope={scopeId} reason=not_scope_admin");
            return (false, "only a scope admin may delete a credential — refused");
        }
        lock (_gate)
        {
            // Remove the CURRENT entry atomically (D38 F5): if a
            // racing operation already removed it, say so.
            if (!_creds.Remove(meta.Id))
            {
                Audit("site_credential_refused", actorUserId, $"op=delete cred={credentialId} scope={scopeId} reason=not_found_race");
                return (false, $"no credential under id '{credentialId}' — refused");
            }
        }
        Audit("site_credential_deleted", actorUserId,
            $"cred={meta.Id} scope={meta.ScopeId} target={meta.TargetKind}:{meta.TargetId} label={meta.Label}");
        Changed?.Invoke();
        return (true, $"credential '{meta.Label}' deleted (secret destroyed; the deletion is on the audit record)");
    }

    // ---- in-session surfacing -----------------------------------------------------

    /// <summary>THE in-session query contract: for the device being
    /// worked on, return its documentation set (device documents +
    /// documents of the device groups it belongs to) and the
    /// credential METADATA visible to the requesting user for that
    /// device/groups. Secrets are never part of this result — the
    /// session view holds metadata; a secret moves only through
    /// RevealCredential, per credential, under re-auth + audit.
    /// Target-strict: records bound to any other device or group
    /// cannot appear. Policy-gated fail-closed: when policy
    /// disables the feature for this device (or its facts do not
    /// resolve), the context refuses. Group ids count only when
    /// the roster's enrollment-derived membership puts THIS device
    /// in the group (D38 F7).</summary>
    public (bool Ok, string Reason, SessionDeviceContext? Context) GetSessionContext(
        string actorUserId, string scopeId, string deviceId, IEnumerable<string>? deviceGroupIds = null)
    {
        (bool, string, SessionDeviceContext?) Refuse(string r)
        {
            Audit("site_session_context_refused", actorUserId, $"scope={scopeId} device={deviceId} reason={r}");
            return (false, r, null);
        }
        if (!IsValidId(scopeId) || !IsValidId(deviceId)) return Refuse("a session context needs a valid scope and device id — refused");
        if (!LiveUser(scopeId, actorUserId)) return Refuse($"actor '{actorUserId}' is not a live user of scope '{scopeId}' — refused");
        if (!PolicyAllowsDevice(scopeId, deviceId))
            return Refuse($"site documentation is disabled by policy for device '{deviceId}' ({SiteDocumentationPolicyKeys.Enabled}) — refused; policy is the kill switch");

        var groupIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in deviceGroupIds ?? Array.Empty<string>())
        {
            if (!IsValidId(g)) continue;
            // A group id only counts when it is a real device group
            // of THIS scope (roster-wired): a caller cannot pull
            // another scope's group documents by naming its id.
            if (_roster is not null && _roster.GetDeviceGroup(scopeId, g) is null) continue;
            // D38 F7: existence is not membership. The device must
            // BELONG to the group per the roster's enrollment-
            // derived membership — a session on any device can no
            // longer pull any group's records by naming the group.
            // (Bare tooling without a roster keeps the caller's
            // assertion as its documented seam.)
            if (_roster is not null &&
                !_roster.DeviceGroupDeviceIds(scopeId, g).Contains(deviceId, StringComparer.OrdinalIgnoreCase)) continue;
            groupIds.Add(g.Trim());
        }

        // Credential metadata surfaces only to live HUMAN actors
        // (D38 F9); documents surface to any live actor.
        var actorIsHuman = LiveUser(scopeId, actorUserId, humanOnly: true);
        var vis = ComputeVisibility(scopeId, actorUserId);
        List<SiteDocument> docs;
        List<SiteCredentialMetadata> creds;
        lock (_gate)
        {
            docs = _docs.Values.Select(e => e.Current)
                .Where(d => !d.Deleted &&
                            string.Equals(d.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                            ((d.TargetKind == DocTargetKinds.Device && string.Equals(d.TargetId, deviceId, StringComparison.OrdinalIgnoreCase)) ||
                             // BD-SHARED-PLAT-3/F9: group-target docs
                             // run the SAME PolicyAllowsTarget gate
                             // ListDocuments/GetDocument run — the
                             // device gate above covers device docs
                             // only, so group docs used to surface
                             // with no policy check at all.
                             (d.TargetKind == DocTargetKinds.Group && groupIds.Contains(d.TargetId) &&
                              PolicyAllowsTarget(scopeId, d.TargetKind, d.TargetId))))
                .OrderBy(d => d.Id, StringComparer.Ordinal).Select(Clone).ToList();
            creds = !actorIsHuman ? new List<SiteCredentialMetadata>() : _creds.Values.Select(c => c.Metadata)
                .Where(m => string.Equals(m.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                            ((m.TargetKind == DocTargetKinds.Device && string.Equals(m.TargetId, deviceId, StringComparison.OrdinalIgnoreCase)) ||
                             (m.TargetKind == DocTargetKinds.Group && groupIds.Contains(m.TargetId))) &&
                            CanSeeCredential(m, actorUserId, vis))
                .OrderBy(m => m.Id, StringComparer.Ordinal).ToList();
        }
        var context = new SessionDeviceContext(scopeId, deviceId, actorUserId, _now(), docs, creds);
        return (true, $"session context for device '{deviceId}': {docs.Count} document(s), {creds.Count} credential(s) visible to '{actorUserId}' (metadata only — secrets move only through the audited reveal path)", context);
    }

    // ---- persistence ----------------------------------------------------------------

    private sealed record DocVersionDto(int Version, Dictionary<string, string> Fields, string Notes,
        string ChangedBy, DateTimeOffset ChangedUtc, List<string> ChangedFields, string ContentHash = "");
    private sealed record DocDto(string Id, string ScopeId, string TargetKind, string TargetId,
        string TemplateKind, string Title, int CurrentVersion, Dictionary<string, string> Fields, string Notes,
        string CreatedBy, DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc, bool Deleted,
        List<DocVersionDto> History, string SnapshotHash = "");
    // CredDto (D38 F1/F10): BindingHash is the hash of the
    // PROTECTED text (never of the secret), and the producing
    // protector is named with its real-protection flag — an export
    // under the dev pass-through protector can never again be
    // mistaken for a DPAPI one, and import refuses material whose
    // named protector is not the protector in force.
    private sealed record CredDto(string Id, string ScopeId, string TargetKind, string TargetId,
        string Label, string Username, string Category, List<string> GrantedUserIds, List<string> GrantedUserGroupIds,
        string BindingHash, string CreatedBy, DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc,
        string ProtectedSecret, string ProtectorName = "", bool IsRealProtection = false);
    private sealed record StoreDto(List<DocDto> Documents, List<CredDto> Credentials);

    /// <summary>Serialize the store. Secrets travel ONLY in their
    /// protected form; document history travels in full (the record
    /// is the value).</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _docs.Values.Select(e => new DocDto(e.Current.Id, e.Current.ScopeId, e.Current.TargetKind,
                    e.Current.TargetId, e.Current.TemplateKind, e.Current.Title, e.Current.CurrentVersion,
                    new Dictionary<string, string>(e.Current.Fields, StringComparer.OrdinalIgnoreCase), e.Current.Notes,
                    e.Current.CreatedBy, e.Current.CreatedUtc, e.Current.UpdatedUtc, e.Current.Deleted,
                    e.History.Select(v => new DocVersionDto(v.Version,
                        new Dictionary<string, string>(v.Fields, StringComparer.OrdinalIgnoreCase), v.Notes,
                        v.ChangedBy, v.ChangedUtc, v.ChangedFields.ToList(), v.ContentHash)).ToList(),
                    e.Current.SnapshotHash)).ToList(),
                _creds.Values.Select(c => new CredDto(c.Metadata.Id, c.Metadata.ScopeId, c.Metadata.TargetKind,
                    c.Metadata.TargetId, c.Metadata.Label, c.Metadata.Username, c.Metadata.Category,
                    c.Metadata.GrantedUserIds.ToList(), c.Metadata.GrantedUserGroupIds.ToList(),
                    c.BindingHash, c.Metadata.CreatedBy, c.Metadata.CreatedUtc, c.Metadata.UpdatedUtc,
                    c.ProtectedSecret, c.Metadata.ProtectorName, c.Metadata.IsRealProtection)).ToList());
            return JsonSerializer.Serialize(store);
        }
    }

    /// <summary>Restore. Re-validated, never trusted: EVERY field
    /// an export carries is re-checked the way Create checks it
    /// (D38 F3/F4) — ids valid, title cleaned, grants validated
    /// against the roster of the credential's OWN scope, group
    /// targets required to exist, protector provenance required to
    /// match the protector in force. A document whose history is
    /// not a contiguous 1..N chain — bound to the document's
    /// identity and ending at a snapshot whose hash verifies — is
    /// dropped whole (a rewritten history is indistinguishable
    /// from a corrupt one — both refuse); a credential whose
    /// protected material no longer matches its binding is dropped
    /// (substitution evidence, never a silent wrong secret). The
    /// import itself is audited with restored/dropped counts:
    /// imported grants never land silently. Malformed entries are
    /// skipped, never fatal.</summary>
    public int ImportJson(string json)
    {
        StoreDto? store;
        try { store = JsonSerializer.Deserialize<StoreDto>(json); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        var dropped = 0;
        lock (_gate)
        {
            foreach (var dto in store.Documents ?? new List<DocDto>())
            {
                if (dto is null || !IsValidId(dto.Id) || _docs.ContainsKey(dto.Id)) { dropped++; continue; }
                var template = DocTemplates.TryGet(dto.TemplateKind);
                if (template is null || !DocTargetKinds.All.Contains(dto.TargetKind ?? "")) { dropped++; continue; }
                // Identity fields are validated, never taken on
                // faith (D38 F4): the chain is bound to them, and a
                // malformed scope/target/title refuses the record.
                if (!IsValidId(dto.ScopeId) || !IsValidId(dto.TargetId) || !IsValidId(dto.CreatedBy)) { dropped++; continue; }
                if (!TryClean(dto.Title, MaxTitleLength, allowNewlines: false, out var cleanTitle) || cleanTitle.Length == 0) { dropped++; continue; }
                if (dto.TargetKind == DocTargetKinds.Group && _roster is not null &&
                    _roster.GetDeviceGroup(dto.ScopeId, dto.TargetId) is null) { dropped++; continue; }
                if (dto.History is null || dto.History.Count == 0 || dto.History.Count > MaxHistoryVersions) { dropped++; continue; }
                var binding = DocBinding(dto.Id, dto.ScopeId, dto.TargetKind, dto.TargetId,
                    template.Kind, cleanTitle, dto.CreatedBy);
                var historyOk = true;
                var history = new List<SiteDocumentVersion>();
                var prevHash = HistoryGenesis;
                for (var i = 0; i < dto.History.Count; i++)
                {
                    var v = dto.History[i];
                    Dictionary<string, string> vf = new(StringComparer.OrdinalIgnoreCase);
                    var vn = "";
                    if (v is null || v.Version != i + 1 ||
                        !ValidateFields(template, v.Fields, out vf, out _) ||
                        !TryClean(v.Notes ?? "", MaxNotesLength, allowNewlines: true, out vn))
                    { historyOk = false; break; }
                    // Chain verification: a version whose content no
                    // longer hashes to its recorded chain hash is a
                    // REWRITTEN history — the whole document refuses.
                    var expect = VersionHash(binding, prevHash, v.Version, vf, vn, v.ChangedBy ?? "", v.ChangedUtc);
                    if (!string.Equals(expect, v.ContentHash ?? "", StringComparison.OrdinalIgnoreCase))
                    { historyOk = false; break; }
                    prevHash = expect;
                    history.Add(new SiteDocumentVersion(v.Version, vf, vn, v.ChangedBy ?? "",
                        v.ChangedUtc, (v.ChangedFields ?? new List<string>()).ToList(), expect));
                }
                if (!historyOk) { dropped++; continue; }
                if (dto.CurrentVersion != history.Count) { dropped++; continue; }
                if (!ValidateFields(template, dto.Fields, out var fields, out _)) { dropped++; continue; }
                if (!TryClean(dto.Notes ?? "", MaxNotesLength, allowNewlines: true, out var notes)) { dropped++; continue; }
                var last = history[^1];
                if (!string.Equals(last.Notes, notes, StringComparison.Ordinal) ||
                    last.Fields.Count != fields.Count ||
                    last.Fields.Any(kv => !fields.TryGetValue(kv.Key, out var fv) || fv != kv.Value))
                { dropped++; continue; } // current snapshot disagrees with its own final version — rewritten record, refused
                // Snapshot-hash verification (D38 F4): an export
                // that flips Deleted or rewrites the snapshot
                // without resealing the snapshot hash refuses.
                // BD-SHARED-PLAT-3/F4: an EMPTY snapshot hash now
                // refuses too — the legacy acceptance let a
                // hand-edited export blank the hash and un-delete a
                // tombstoned document with no resealing at all.
                // Exports predating the field must be re-exported
                // by a current build (which always writes the hash)
                // rather than imported unsealed.
                var snap = SnapshotHashOf(prevHash, dto.Deleted, dto.CurrentVersion, fields, notes);
                if (string.IsNullOrEmpty(dto.SnapshotHash) ||
                    !string.Equals(snap, dto.SnapshotHash, StringComparison.OrdinalIgnoreCase))
                { dropped++; continue; }
                _docs[dto.Id] = new DocEntry
                {
                    Current = new SiteDocument(dto.Id, dto.ScopeId, dto.TargetKind, dto.TargetId,
                        template.Kind, cleanTitle, dto.CurrentVersion, fields, notes,
                        dto.CreatedBy, dto.CreatedUtc, dto.UpdatedUtc, dto.Deleted, snap),
                    History = history,
                };
                restored++;
            }
            foreach (var dto in store.Credentials ?? new List<CredDto>())
            {
                if (dto is null || !IsValidId(dto.Id) || _creds.ContainsKey(dto.Id)) { dropped++; continue; }
                if (!DocTargetKinds.All.Contains(dto.TargetKind ?? "")) { dropped++; continue; }
                // Scope/target/label/grants re-validated exactly as
                // at Create (D38 F3): an edited export cannot move
                // a credential to another scope, retarget it, or
                // grant it to the editor.
                if (!IsValidId(dto.ScopeId) || !IsValidId(dto.TargetId)) { dropped++; continue; }
                if (!TryClean(dto.Label, MaxLabelLength, allowNewlines: false, out var cleanLabel) || cleanLabel.Length == 0) { dropped++; continue; }
                if (!TryClean(dto.Username ?? "", 200, allowNewlines: false, out var cleanUser)) { dropped++; continue; }
                if (!TryClean(dto.Category ?? "", 100, allowNewlines: false, out var cleanCategory)) { dropped++; continue; }
                if (dto.TargetKind == DocTargetKinds.Group && _roster is not null &&
                    _roster.GetDeviceGroup(dto.ScopeId, dto.TargetId) is null) { dropped++; continue; }
                var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var grantsOk = true;
                foreach (var u in dto.GrantedUserIds ?? new List<string>())
                {
                    if (!IsValidId(u) || (_roster is not null && _roster.GetUser(dto.ScopeId, u) is null)) { grantsOk = false; break; }
                    users.Add(u.Trim());
                }
                if (!grantsOk) { dropped++; continue; }
                var userGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var g in dto.GrantedUserGroupIds ?? new List<string>())
                {
                    if (!IsValidId(g) || (_roster is not null && _roster.GetUserGroup(dto.ScopeId, g) is null)) { grantsOk = false; break; }
                    userGroups.Add(g.Trim());
                }
                if (!grantsOk) { dropped++; continue; }
                // Protector provenance (D38 F10): material produced
                // by a DIFFERENT named protector than the one in
                // force never enters the vault under this
                // protector's name. BD-SHARED-PLAT-3/F4: a BLANK
                // protector name refuses too — it skipped this check
                // entirely and entered the vault labelled
                // "unknown-legacy-export" with no provenance at all.
                if (string.IsNullOrEmpty(dto.ProtectorName) ||
                    !string.Equals(dto.ProtectorName, _protector.Name, StringComparison.OrdinalIgnoreCase))
                { dropped++; continue; }
                if (!string.Equals(BindingOf(dto.ProtectedSecret ?? ""), dto.BindingHash ?? "", StringComparison.OrdinalIgnoreCase))
                { dropped++; continue; } // tampered/substituted material never enters the vault
                string secret;
                try { secret = _protector.Unprotect(dto.ProtectedSecret ?? ""); }
                catch { dropped++; continue; }
                if (secret.Length == 0 || secret.Length > MaxSecretLength || secret.Any(char.IsControl))
                { dropped++; continue; }
                _creds[dto.Id] = new CredEntry(dto.ProtectedSecret, BindingOf(dto.ProtectedSecret), new SiteCredentialMetadata(
                    dto.Id, dto.ScopeId, dto.TargetKind, dto.TargetId, cleanLabel,
                    cleanUser, cleanCategory, users, userGroups,
                    dto.CreatedBy ?? "", dto.CreatedUtc, dto.UpdatedUtc,
                    dto.ProtectorName, dto.IsRealProtection));
                restored++;
            }
        }
        if (restored > 0 || dropped > 0)
            Audit("site_store_imported", "site-store-import", $"restored={restored} dropped={dropped}");
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

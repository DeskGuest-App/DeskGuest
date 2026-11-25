using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Hub;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;

namespace Acp.Shared.ApplicationControl;

// =====================================================================
// RMM-25 — Application control: allow/blocklisting with an
// access-request workflow (MEC pattern).
//
//   (a) POLICY: allow/deny rules by HASH, PUBLISHER, PRODUCT and
//       PATH — in that precedence order (hash beats publisher beats
//       product beats path) — delivered as RMM-07 signed policy
//       content. Modes: audit-only (log would-block, never block)
//       and enforce (block). AUDIT is the safe default for a new
//       policy; switching to enforce is an explicit policy act and
//       every surface the model produces names the EFFECTIVE mode
//       unambiguously (a decision, a plan and a block event all
//       carry it — "we thought it was enforcing" is unrepresentable
//       as a silent state).
//   (b) BLOCK EVENTS: a stopped (enforce) or would-be-stopped
//       (audit) launch lands in the alert centre (RMM-01 sink
//       shapes) with the FULL application identity + the rule that
//       matched.
//   (c) REQUEST WORKFLOW: a blocked user REQUESTS approval; the
//       request is an RMM-12 work item (composed by the Core
//       service) naming the application identity + business reason.
//       An admin approval mints a SCOPED allow rule — that exact
//       application identity, that device or one named group, WITH
//       AN EXPIRY (approvals are never permanent by default) —
//       delivered through the same signed-policy path (the rule
//       joins the device's resolved rule set). Denial is recorded
//       with its reason. A request can NEVER self-approve, and an
//       approval can NEVER widen beyond the requested identity:
//       the minted rule binds the CONJUNCTION of the identity's
//       strong anchors, so approving "this hash of this product"
//       cannot become "this publisher, everything".
//
// IDENTITY DISCIPLINE (the destruction pass's home ground, shared
// with RMM-04 inventory and RMM-23 browser extensions): application
// identity = product + SIGNING identity + content hash + version +
// path. The publisher DISPLAY name is presentation only and NEVER
// binds policy: an unsigned binary can claim any display string,
// so publisher rules bind the Authenticode signer CERTIFICATE
// THUMBPRINT. A publisher rule carrying only a display name is
// refused at admission, by name.
//
// ENFORCEMENT is OS machinery (AppLocker/WDAC on Windows): this
// file is model + policy + evaluation + workflow; the applier is
// an interface with fakes, following RMM-23's applier pattern —
// the honest unavailable applier reports NOT applied.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-25. The feature
/// toggle is the RMM-07 seeded key (default ON); the alias key is
/// also honoured at resolution so either spelling gates the
/// feature (the seeded spelling wins when both are set).</summary>
public static class AppControlKeys
{
    public const string FeatureEnabled = "rmm.app_control.enabled";
    public const string FeatureEnabledAlias = "rmm.application_control.enabled";
    /// <summary>"audit" | "enforce". Unset or unparsable → audit
    /// (the safe default), named in the resolver's notes.</summary>
    public const string Mode = "rmm.app_control.mode";
    /// <summary>Rule list, one rule per '|' entry, fields
    /// comma-separated in the parser's order: effect,kind,
    /// scopeKind,scopeId,expiresIsoOrDash,ruleId,anchor. The anchor
    /// is the LAST field's remainder so a path anchor may itself
    /// contain commas. (Recovery fix R25R-F6: this comment
    /// previously named a different field order than the parser
    /// implements — a policy authored from the comment would have
    /// been dropped as malformed, named but useless.)</summary>
    public const string Rules = "rmm.app_control.rules";
}

public static class AppControlModes
{
    public const string Audit = "audit";
    public const string Enforce = "enforce";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Audit, Enforce };

    /// <summary>The unambiguous effective-mode label every surface
    /// carries: there is no rendering of this model in which the
    /// mode is implicit.</summary>
    public static string Label(string mode) => mode == Enforce
        ? "ENFORCE (blocks are real)"
        : "AUDIT-ONLY (nothing is blocked; would-block events are logged)";
}

public static class RuleEffects
{
    public const string Allow = "allow";
    public const string Deny = "deny";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Allow, Deny };
}

public static class RuleKinds
{
    public const string Hash = "hash";
    public const string Publisher = "publisher";
    public const string Product = "product";
    public const string Path = "path";
    /// <summary>Approval-minted rules: bind the CONJUNCTION of the
    /// requested identity's strong anchors (see AppRule).</summary>
    public const string Approval = "approval";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Hash, Publisher, Product, Path, Approval };

    /// <summary>Precedence rank: hash beats publisher beats product
    /// beats path. Approval rules rank by their WEAKEST bound anchor
    /// (computed on the rule — FL-25b/F5 delta: the FL-25 code ranked
    /// them by their strongest anchor while the docs claimed the
    /// weakest). Unknown kinds rank below everything.</summary>
    public static int Rank(string kind) => kind switch
    {
        Hash => 4,
        Publisher => 3,
        Product => 2,
        Path => 1,
        _ => 0,
    };

    /// <summary>The strength label a rule carries in every surface.
    /// A path-only allow is the weakest form and is LABELLED as
    /// such in the model — never presented as equivalent to a hash
    /// or publisher rule.</summary>
    public static string StrengthLabel(string kind) => kind switch
    {
        Hash => "strongest (content hash)",
        Publisher => "strong (signer certificate identity)",
        Product => "moderate (product name)",
        Path => "WEAKEST (path only — any binary placed at this path matches; labelled as such wherever the rule appears)",
        Approval => "scoped approval (exact requested identity conjunction, expiring)",
        _ => "unknown",
    };
}

public static class RuleScopes
{
    public const string Org = "org";
    public const string Group = "group";
    public const string Device = "device";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Org, Group, Device };
}

public static class AppControlLimits
{
    public const int MaxProductLength = 256;
    public const int MaxPublisherLength = 256;
    public const int MaxPathLength = 1024;
    public const int MaxVersionLength = 64;
    public const int MaxRulesPerPolicy = 1024;
    public const int MaxReasonLength = 2048;
    public const int MaxActorLength = 128;
    /// <summary>An approval's maximum lifetime: approvals are timed
    /// by construction; a longer or unbounded approval refuses.</summary>
    public static readonly TimeSpan MaxApprovalDuration = TimeSpan.FromDays(90);
    /// <summary>Request flood discipline (per device, pending).</summary>
    public const int MaxPendingRequestsPerDevice = 20;
    /// <summary>Request flood discipline (per requester, per hour).</summary>
    public const int MaxRequestsPerRequesterPerHour = 10;
    /// <summary>Decided requests are retained this long for the
    /// record, then evicted at filing time (FL-25c/F11 — the store
    /// previously grew without bound).</summary>
    public static readonly TimeSpan DecidedRequestRetention = TimeSpan.FromDays(30);
    /// <summary>Request ids are caller-chosen but are interpolated
    /// into rule ids, work-item keys and ledger details, so they are
    /// admitted only in a strict charset and length (FL-25b/F1
    /// delta: the FL-25 F5 fix escaped identity fields but left the
    /// request id unvalidated — a crafted id could still plant fake
    /// ledger markers).</summary>
    public const int MaxRequestIdLength = 64;
    /// <summary>Per-DEVICE hourly filing cap (FL-25b/F7 delta): the
    /// per-requester cap keys on a free-text name a filer can
    /// rotate; the device cap cannot be rotated away.</summary>
    public const int MaxRequestsPerDevicePerHour = 50;
    /// <summary>Fleet-wide pending bound (FL-25b/F7 delta): pending
    /// was capped per device but not in total.</summary>
    public const int MaxPendingRequestsTotal = 1000;
    /// <summary>Hard bound on the whole request store (pending +
    /// retained decided), enforced at filing (FL-25b/F7 delta).</summary>
    public const int MaxStoredRequests = 5000;
}

/// <summary>Request-id admission discipline (FL-25b/DF1). A
/// request id is chosen by the filing device and is interpolated
/// into rule ids, work-item keys and structured ledger details.
/// The FL-25 F5 fix escaped the IDENTITY fields but left the id
/// itself unchecked, so a crafted id such as
/// 'x mode=ENFORCE actuallyBlocked=False' still planted fake
/// markers in the ledger and in rule descriptions. Ids are now
/// admitted only in a strict charset (ASCII letters, digits,
/// '-', '_', '.') within a length bound — no spaces, no '=', no
/// controls, nothing that can forge a field.</summary>
public static class AppRequestIds
{
    public static bool IsValid(string? id) =>
        id is not null && id.Length >= 1 && id.Length <= AppControlLimits.MaxRequestIdLength &&
        id.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
            or '-' or '_' or '.');
    public const string Refusal =
        "the request id is not admissible — refused (request ids are 1-64 characters of ASCII letters, digits, '-', '_' or '.'; a device-chosen id is interpolated into rule ids and ledger details, so no other characters are admitted)";

    /// <summary>Map an arbitrary id segment (e.g. a device id,
    /// whose admission rules predate this discipline) into the
    /// admissible charset for embedding in a composite key — rule
    /// ids and work-item keys — so the composite is always
    /// ledger-safe. Characters outside the charset become '-'.</summary>
    public static string Segment(string? s) =>
        string.IsNullOrEmpty(s) ? "none"
        : new string(s.Trim().Select(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
            or '-' or '_' or '.' ? c : '-').ToArray());
}

/// <summary>Path normalization for rule matching. Windows path
/// semantics are applied EXPLICITLY so case, separator, dot-segment
/// and trailing-dot/space variants of one path compare equal — the
/// variants must not defeat a rule. 8.3 short names are NEVER
/// equated with long names: an identity whose path still carries an
//  8.3 segment is unresolved, and a path rule does not match it
/// (fail closed — in enforce mode the default-deny decides).</summary>
public static class AppPathNormalizer
{
    public static string Normalize(string? path)
    {
        var p = (path ?? "").Trim().Replace('/', '\\');
        // The Win32 extended-length / device prefixes (\\?\ and \\.)
        // name the same file as the plain path — strip them so a
        // prefix variant cannot slip past a rule written for the
        // plain path (recovery fix R25R-F3).
        var strippedPrefix = false;
        if (p.StartsWith(@"\\?\") || p.StartsWith(@"\\.\"))
        { p = p.Substring(4); strippedPrefix = true; }
        // The NT object-manager prefix \??\ names the same file too
        // (fix FL-25c/F9 residual — it was not stripped, so a \??\
        // variant slipped past plain-path rules).
        if (p.StartsWith(@"\??\"))
        { p = p.Substring(4); strippedPrefix = true; }
        // FL-25b/F8 (delta): the extended-length UNC forms
        // (\\?\UNC\server\share\... and \??\UNC\server\share\...)
        // name \\server\share\... — after the prefix strip, the
        // "UNC\" remainder must map back to the "\\" UNC root, or
        // one file carries two normalized forms: a path ALLOW then
        // fails closed (harmless) but a path DENY is evaded and the
        // ledger records default-deny instead of the matched rule.
        if (strippedPrefix && p.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
            p = @"\\" + p.Substring(4);
        // The DEFAULT alternate data stream suffix (::$DATA) IS the
        // file itself — strip it so it cannot slip a plain-path
        // rule. Any OTHER ADS suffix names different bytes and is
        // NOT stripped: HasAlternateDataStreamSegment flags it and
        // path matching fails closed on it (FL-25c/F9).
        var lastSep = p.LastIndexOf('\\');
        var lastSeg = lastSep >= 0 ? p.Substring(lastSep + 1) : p;
        if (lastSeg.EndsWith("::$DATA", StringComparison.OrdinalIgnoreCase))
            p = p.Substring(0, p.Length - "::$DATA".Length);
        var unc = p.StartsWith(@"\\");
        var segments = new List<string>();
        foreach (var raw in p.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            // Dot segments are resolved BEFORE trailing-dot
            // trimming: TrimEnd('.') would eat ".." itself and turn
            // resolution into silent segment-dropping (recovery fix
            // R25R-F3b — the '..' branch below was unreachable for
            // exactly this reason; D25-12 passed only because the
            // dropped '..' happened to leave the denied folder in
            // place).
            if (raw == ".") continue;
            if (raw == "..")
            {
                // '..' clamps AT the root anchor — it never pops it.
                // The anchor is the drive segment ("C:") for a local
                // path, server+share for a UNC path. (Recovery fix
                // R25R-F3: previously '..' popped the drive segment
                // too, so C:\Tools\..\..\evil.exe normalized to
                // \evil.exe instead of Win32's C:\evil.exe.)
                var anchor = unc ? 2 : (segments.Count > 0 && segments[0].EndsWith(':') ? 1 : 0);
                if (segments.Count > anchor) segments.RemoveAt(segments.Count - 1);
                continue;
            }
            // Win32 strips trailing dots and spaces from a segment.
            var seg = raw.TrimEnd('.', ' ');
            if (seg.Length == 0) continue;
            segments.Add(seg);
        }
        if (segments.Count == 0) return ""; // no path is NO path — never a root separator (D25 thin-identity break)
        var prefix = p.StartsWith("\\\\") ? "\\\\" : (segments[0].EndsWith(':') ? "" : "\\");
        return prefix + string.Join("\\", segments);
    }

    /// <summary>True when any segment looks like an 8.3 short name
    /// (NAME~n[.EXT]): such a path is not resolved to its long form
    /// and must not satisfy a path rule.</summary>
    public static bool HasShortNameSegment(string? normalizedPath)
    {
        foreach (var seg in (normalizedPath ?? "").Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            var tilde = seg.IndexOf('~');
            if (tilde > 0 && tilde + 1 < seg.Length && char.IsDigit(seg[tilde + 1])) return true;
        }
        return false;
    }

    /// <summary>True when any segment carries a NON-default
    /// alternate-data-stream suffix (name:stream): such a path
    /// names bytes other than the file at the plain path, so a
    /// path rule must never match it (fail closed, FL-25c/F9).
    /// The drive segment's own colon ("C:") is not a stream.</summary>
    public static bool HasAlternateDataStreamSegment(string? normalizedPath)
    {
        var segs = (normalizedPath ?? "").Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < segs.Length; i++)
        {
            if (i == 0 && segs[i].EndsWith(':')) continue; // drive anchor
            if (segs[i].Contains(':')) return true;
        }
        return false;
    }

    public static bool Equals(string? a, string? b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);
}

/// <summary>One application's identity — the RMM-04 discipline
/// (publisher + product + hash/version) extended with the launch
/// path and the SIGNING identity. PublisherName is a DISPLAY string
/// only; SignerThumbprint is the certificate identity policy binds.
/// An identity with no strong anchor (no hash, no signer, no path)
/// is too thin to bind and refuses.</summary>
public sealed record AppIdentity(
    string DeviceId,
    string Product,
    string? Version,
    string? PublisherName,
    string? SignerThumbprint,
    string? Sha256,
    string? Path)
{
    public string NormalizedProduct => (Product ?? "").Trim();
    public string NormalizedSigner => (SignerThumbprint ?? "").Trim().ToLowerInvariant();
    public string NormalizedHash => (Sha256 ?? "").Trim().ToLowerInvariant();
    public string NormalizedPath => AppPathNormalizer.Normalize(Path);
    public bool IsSigned => NormalizedSigner.Length > 0;

    /// <summary>The dedup / alert-condition key for this identity
    /// on this device: strongest anchors first.</summary>
    public string Key =>
        $"{DeviceId}|{NormalizedProduct.ToLowerInvariant()}|{NormalizedHash}|{NormalizedSigner}|{NormalizedPath.ToLowerInvariant()}";

    public static bool IsHex(string s, params int[] lengths) =>
        lengths.Contains(s.Length) && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>Control characters (incl. CR/LF/TAB) in an identity
    /// or actor string are a ledger-forgery vector: they can plant
    /// fake fields/markers in structured audit details. Any string
    /// carrying one refuses at admission (FL-25c/F5).</summary>
    public static bool HasControlChars(string? s) =>
        s is not null && s.Any(c => char.IsControl(c));

    /// <summary>Admission validation. Null when admissible.</summary>
    public string? Validate()
    {
        if (HasControlChars(DeviceId) || HasControlChars(Product) || HasControlChars(Version) ||
            HasControlChars(PublisherName) || HasControlChars(Path))
            return "application identity carries control characters in an identity field — refused (control characters are a ledger-forgery vector)";
        if (string.IsNullOrWhiteSpace(DeviceId)) return "application identity needs a device id — refused";
        if (string.IsNullOrWhiteSpace(Product) || Product.Length > AppControlLimits.MaxProductLength)
            return "application identity needs a product name within bounds — refused";
        if (Version is { Length: > AppControlLimits.MaxVersionLength }) return "application version over bounds — refused";
        if (PublisherName is { Length: > AppControlLimits.MaxPublisherLength }) return "publisher name over bounds — refused";
        if (Path is { Length: > AppControlLimits.MaxPathLength }) return "application path over bounds — refused";
        if (Sha256 is not null && !IsHex(NormalizedHash, 64))
            return "application hash is not a SHA-256 hex digest — refused (a malformed hash binds nothing)";
        if (SignerThumbprint is not null && !IsHex(NormalizedSigner, 40, 64))
            return "signer thumbprint is not a certificate thumbprint (40/64 hex) — refused (publisher identity binds the certificate, never a display string)";
        if (NormalizedHash.Length == 0 && NormalizedSigner.Length == 0 && NormalizedPath.Length == 0)
            return "application identity carries no hash, no signer and no path — too thin to bind policy to; refused (a product name plus a display publisher string is spoofable)";
        return null;
    }
}

/// <summary>One allow/deny rule. Policy rules bind ONE anchor (the
/// rule's Kind). Approval-minted rules (Kind=approval) bind the
/// CONJUNCTION of the requested identity's strong anchors via the
/// Required* fields — that conjunction is what makes widening
/// unrepresentable: the rule matches only an application that is
/// simultaneously the requested product AND (when present) the
/// requested hash AND the requested signer.</summary>
public sealed record AppRule(
    string Id,
    string Effect,                 // RuleEffects.*
    string Kind,                   // RuleKinds.*
    string? Hash,                  // kind=hash anchor / approval conjunction part
    string? SignerThumbprint,      // kind=publisher anchor / conjunction part
    string? Product,               // kind=product anchor / conjunction part
    string? Path,                  // kind=path anchor
    string ScopeKind,              // RuleScopes.*
    string ScopeId,                // device id | group id | scope id / "*"
    DateTimeOffset? ExpiresUtc,    // REQUIRED for approval rules
    string? SourceRequestId)       // set exactly for approval-minted rules
{
    public bool IsApprovalRule => SourceRequestId is not null;

    /// <summary>An approval rule's label names its WEAKEST anchor:
    /// a path-only approval is the weakest form and is labelled
    /// WEAKEST, never with the generic scoped-approval label
    /// (FL-25c/F8 — previously every approval carried the same
    /// label regardless of anchors).</summary>
    public string StrengthLabel => Kind == RuleKinds.Approval && Rank == 1
        ? "WEAKEST (path-only approval — any binary placed at this path matches; labelled as such wherever the rule appears)"
        : RuleKinds.StrengthLabel(Kind);

    /// <summary>Rank by the WEAKEST anchor an approval actually
    /// binds (FL-25c/F8, corrected FL-25b/DF5): an approval ALWAYS
    /// binds the product anchor (rank 2), so its weakest anchor is
    /// the product — rank 2 — unless it also binds a path, whose
    /// rank 1 is weaker still. A hash or signer anchor NEVER raises
    /// an approval above its weakest bound anchor: the FL-25 code
    /// returned 4/3 for hash/signer approvals (strongest anchor),
    /// so a hash-anchored approval silently out-ranked a publisher
    /// deny (3) and a product deny (2) while the docs claimed the
    /// opposite. With weakest-anchor ranking an approval beats only
    /// path-rank policy; every higher-or-equal-rank DENY wins —
    /// an approval is never a trump over policy, at any rank.</summary>
    public int Rank => Kind == RuleKinds.Approval
        ? (!string.IsNullOrEmpty(Path) ? 1 : 2)
        : RuleKinds.Rank(Kind);

    /// <summary>Admission validation (evaluated at a stated instant
    /// so expiry discipline is testable). Null when admissible.</summary>
    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(Id)) return "a rule needs an id — refused";
        if (!RuleEffects.All.Contains(Effect ?? "")) return $"unknown rule effect '{Effect}' — refused";
        if (!RuleKinds.All.Contains(Kind ?? "")) return $"unknown rule kind '{Kind}' — refused";
        if (!RuleScopes.All.Contains(ScopeKind ?? "")) return $"unknown rule scope '{ScopeKind}' — refused";
        if (string.IsNullOrWhiteSpace(ScopeId)) return "a rule needs a scope id — refused";
        switch (Kind)
        {
            case RuleKinds.Hash:
                if (Hash is null || !AppIdentity.IsHex(Hash.Trim(), 64))
                    return $"hash rule '{Id}' carries no valid SHA-256 anchor — refused";
                break;
            case RuleKinds.Publisher:
                if (SignerThumbprint is null || !AppIdentity.IsHex(SignerThumbprint.Trim(), 40, 64))
                    return $"publisher rule '{Id}' carries no signer certificate thumbprint — REFUSED: publisher policy binds the signing identity (certificate thumbprint), never a publisher display name, which any unsigned binary can claim";
                break;
            case RuleKinds.Product:
                if (string.IsNullOrWhiteSpace(Product)) return $"product rule '{Id}' carries no product anchor — refused";
                // FL-25a/F2: a product anchor is a SELF-REPORTED
                // string any binary can claim — it can never be the
                // sole basis for ALLOWING code. Product rules are
                // DENY-ONLY; an allow must bind a hash, a signer, or
                // an approval conjunction (the AppLocker pattern).
                if (Effect == RuleEffects.Allow)
                    return $"product rule '{Id}' is an ALLOW bound only to a self-reported product name — REFUSED: product rules are deny-only (an allow must bind a content hash, a signer certificate, or an approval conjunction)";
                break;
            case RuleKinds.Path:
                if (string.IsNullOrWhiteSpace(Path)) return $"path rule '{Id}' carries no path anchor — refused";
                break;
            case RuleKinds.Approval:
                if (!IsApprovalRule) return $"approval rule '{Id}' names no source request — refused";
                // FL-25b/DF1: the source request id is rendered raw
                // by Describe() into block-event and ledger text —
                // it must satisfy the same admission charset as a
                // filed request id, wherever the rule came from.
                if (!AppRequestIds.IsValid(SourceRequestId))
                    return $"approval rule '{Id}' carries a source request id outside the admissible charset — refused (the id is interpolated into ledger details)";
                if (ExpiresUtc is null)
                    return $"approval rule '{Id}' carries NO expiry — refused: approvals are timed by construction and never permanent by default";
                if (string.IsNullOrWhiteSpace(Product))
                    return $"approval rule '{Id}' binds no product — refused (an approval names the exact application)";
                break;
        }
        if (IsApprovalRule && ExpiresUtc is null)
            return $"approval rule '{Id}' carries NO expiry — refused: approvals are timed by construction and never permanent by default";
        if (ExpiresUtc is { } exp && exp <= now && IsApprovalRule)
            return $"approval rule '{Id}' is already expired at admission — refused";
        return null;
    }

    public bool IsExpired(DateTimeOffset now) => ExpiresUtc is { } exp && now >= exp;

    /// <summary>Scope test: org rules apply fleet-wide within their
    /// scope ("*" or the device's scope id), group rules to member
    /// groups, device rules to the one device.</summary>
    public bool ScopeApplies(AppIdentity identity, string scopeId, IReadOnlySet<string> groupIds)
    {
        return ScopeKind switch
        {
            RuleScopes.Device => string.Equals(ScopeId, identity.DeviceId, StringComparison.OrdinalIgnoreCase),
            RuleScopes.Group => groupIds.Contains(ScopeId),
            RuleScopes.Org => ScopeId == "*" || string.Equals(ScopeId, scopeId, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    /// <summary>Anchor match against an identity at an instant.
    /// Expired rules never match. Path anchors compare normalized
    /// and never match an unresolved (8.3-carrying) identity path.</summary>
    public bool Matches(AppIdentity identity, DateTimeOffset now)
    {
        if (IsExpired(now)) return false;
        // Defence in depth (destruction pass D25-11): an approval
        // rule with NO expiry matches nothing, even if one reached
        // an evaluator without passing admission validation —
        // approvals are timed by construction at every layer.
        if (IsApprovalRule && ExpiresUtc is null) return false;
        switch (Kind)
        {
            case RuleKinds.Hash:
                return identity.NormalizedHash.Length > 0 &&
                    string.Equals(identity.NormalizedHash, (Hash ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal);
            case RuleKinds.Publisher:
                // The SIGNING identity decides. A display-name claim
                // by an unsigned (or differently-signed) binary is
                // not consulted — PublisherName plays no part here.
                return identity.NormalizedSigner.Length > 0 &&
                    string.Equals(identity.NormalizedSigner, (SignerThumbprint ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal);
            case RuleKinds.Product:
                return string.Equals(identity.NormalizedProduct, (Product ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
            case RuleKinds.Path:
                if (identity.NormalizedPath.Length == 0) return false;
                if (AppPathNormalizer.HasShortNameSegment(identity.NormalizedPath)) return false;
                if (AppPathNormalizer.HasAlternateDataStreamSegment(identity.NormalizedPath)) return false;
                return AppPathNormalizer.Equals(identity.Path, Path);
            case RuleKinds.Approval:
                if (!string.Equals(identity.NormalizedProduct, (Product ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
                    return false;
                if (Hash is not null && !string.Equals(identity.NormalizedHash, Hash.Trim().ToLowerInvariant(), StringComparison.Ordinal))
                    return false;
                if (SignerThumbprint is not null && !string.Equals(identity.NormalizedSigner, SignerThumbprint.Trim().ToLowerInvariant(), StringComparison.Ordinal))
                    return false;
                if (Path is not null)
                {
                    // FL-25c/F8: the approval path branch applies
                    // the SAME unresolved-path discipline as path
                    // rules — an 8.3 segment or a non-default ADS
                    // suffix never satisfies it (previously skipped).
                    if (AppPathNormalizer.HasShortNameSegment(identity.NormalizedPath)) return false;
                    if (AppPathNormalizer.HasAlternateDataStreamSegment(identity.NormalizedPath)) return false;
                    if (!AppPathNormalizer.Equals(identity.Path, Path)) return false;
                }
                return true;
            default:
                return false;
        }
    }

    /// <summary>The one-line naming of this rule used in decisions,
    /// block events and audit details — effect, kind, strength and
    /// expiry travel with it so no surface presents a weak or
    /// expiring rule as a strong permanent one.</summary>
    public string Describe() =>
        $"{Effect}/{Kind} rule '{Id}' [{StrengthLabel}] scope={ScopeKind}:{ScopeId}" +
        (ExpiresUtc is { } e ? $" expires={e:O}" : " no-expiry") +
        (SourceRequestId is not null ? $" source-request={SourceRequestId}" : "");
}

/// <summary>The resolved application-control policy for one device:
/// feature state, EFFECTIVE mode (labelled), the applicable rules,
/// and every drop the resolver made, NAMED in Notes.</summary>
public sealed record ResolvedAppControlPolicy(
    bool FeatureEnabled,
    string Mode,
    IReadOnlyList<AppRule> Rules,
    IReadOnlyList<string> Notes)
{
    public string EffectiveModeLabel => AppControlModes.Label(Mode);
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public static class AppControlResolver
{
    /// <summary>Resolve from RMM-07 Effective Policy + the scoped
    /// approval rules minted for this device (the request store's
    /// live rules — the signed-policy path's second half: approvals
    /// are delivered as policy content and join resolution here).
    /// Malformed policy rules are dropped AND named, never silently
    /// applied; an unparsable mode falls back to AUDIT, named.</summary>
    public static ResolvedAppControlPolicy Resolve(
        ManagementPolicyEngine engine, IDeviceFacts facts,
        IEnumerable<AppRule>? approvalRules = null, DateTimeOffset now = default)
    {
        if (now == default) now = DateTimeOffset.UtcNow;
        var eff = engine.ComputeEffective(facts);
        var notes = new List<string>();

        var enabledSetting = eff.Get(AppControlKeys.FeatureEnabled) ?? eff.Get(AppControlKeys.FeatureEnabledAlias);
        var enabled = enabledSetting is not null
            ? bool.TryParse(enabledSetting.Value, out var v) && v
            : engine.Registry.TryGet(AppControlKeys.FeatureEnabled, out var t) && t!.DefaultEnabled;
        if (!enabled)
            return new ResolvedAppControlPolicy(false, AppControlModes.Audit,
                Array.Empty<AppRule>(), new[] { $"application control is disabled by policy for device '{facts.DeviceId}' ({AppControlKeys.FeatureEnabled})" });

        var mode = AppControlModes.Audit;
        if (eff.Get(AppControlKeys.Mode) is { } m)
        {
            var candidate = m.Value.Trim().ToLowerInvariant();
            if (AppControlModes.All.Contains(candidate)) mode = candidate;
            else notes.Add($"application control mode '{m.Value}' is not a known mode — AUDIT-ONLY applies (an unparsable mode never enforces and never silently widens)");
        }
        else notes.Add("no application control mode set by policy — AUDIT-ONLY (the safe default for a new policy; switching to enforce is an explicit, audited policy act)");

        var rules = new List<AppRule>();
        // FL-25c/F11: the membership set + probe are computed ONCE
        // per resolution, not rebuilt per rule.
        var memberGroups = new HashSet<string>(engine.MemberGroupIds(facts), StringComparer.OrdinalIgnoreCase);
        var probe = new AppIdentity(facts.DeviceId, "probe", null, null, null, null, null);
        if (eff.Get(AppControlKeys.Rules) is { } raw && !string.IsNullOrWhiteSpace(raw.Value))
        {
            var entries = raw.Value.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            // FL-25c/F7: the cap is enforced BEFORE parsing, and an
            // over-cap document refuses WHOLE (fail closed) —
            // previously the document was fully parsed and the
            // TRUNCATED set decided, so rules past the cut silently
            // stopped existing while earlier allows kept working.
            if (entries.Length > AppControlLimits.MaxRulesPerPolicy)
            {
                notes.Add($"policy carries {entries.Length} rule entries over the cap {AppControlLimits.MaxRulesPerPolicy} — the ENTIRE rule document is refused (fail closed: a truncated rule set never decides; in enforce mode the default-deny applies)");
            }
            else
            {
                foreach (var entry in entries)
                {
                    var rule = ParseRuleEntry(entry, out var refusal);
                    if (rule is null) { notes.Add(refusal!); continue; }
                    if (rule.Validate(now) is { } invalid) { notes.Add(invalid + " (dropped from policy, named)"); continue; }
                    if (!rule.ScopeApplies(probe, facts.ScopeId, memberGroups)) continue;
                    rules.Add(rule);
                }
            }
        }

        foreach (var rule in approvalRules ?? Array.Empty<AppRule>())
        {
            // FL-25b/DF6: SCOPE FIRST. The FL-25 order validated
            // before the scope filter, so an expired or malformed
            // approval minted for ANOTHER device was named in THIS
            // device's notes — and those notes are ledgered by the
            // service, leaking other devices' request ids across
            // the fleet. Out-of-scope rules are not this device's
            // business and are skipped silently.
            if (!rule.ScopeApplies(probe, facts.ScopeId, memberGroups)) continue;
            // Expiry is checked BEFORE Validate: Validate refuses an
            // expired approval as "already expired at admission",
            // which made the FL-25 "is expired" branch dead code
            // carrying the wrong message. An expired approval for
            // THIS device is named as expired, once, here.
            if (rule.IsExpired(now)) { notes.Add($"approval rule '{rule.Id}' (request {rule.SourceRequestId}) is expired — it no longer allows anything"); continue; }
            if (rule.Validate(now) is { } invalid) { notes.Add(invalid + " (approval rule dropped at resolution, named)"); continue; }
            rules.Add(rule);
        }

        return new ResolvedAppControlPolicy(true, mode, rules, notes);
    }

    /// <summary>Strict explicit-offset test for an ISO-8601 expiry
    /// (FL-25b/DF4): a time component must be present (a date-only
    /// string NEVER carries an offset), and the value must end in
    /// 'Z' or a numeric offset designator ±HH, ±HHMM or ±HH:MM
    /// appearing after the time separator.</summary>
    private static bool HasExplicitOffset(string s)
    {
        if (s.EndsWith("Z", StringComparison.OrdinalIgnoreCase)) return s.Contains('T') || s.Contains(' ');
        var t = Math.Max(s.IndexOf('T'), s.IndexOf(' '));
        if (t < 0) return false; // date-only — no time, no offset
        var tail = s.Substring(t + 1);
        var sign = Math.Max(tail.LastIndexOf('+'), tail.LastIndexOf('-'));
        if (sign < 0) return false;
        var designator = tail.Substring(sign + 1);
        // ±HH | ±HHMM | ±HH:MM
        return designator.Length == 2 && designator.All(char.IsDigit)
            || designator.Length == 4 && designator.All(char.IsDigit)
            || designator.Length == 5 && designator[2] == ':' &&
               char.IsDigit(designator[0]) && char.IsDigit(designator[1]) &&
               char.IsDigit(designator[3]) && char.IsDigit(designator[4]);
    }

    private static AppRule? ParseRuleEntry(string entry, out string? refusal)
    {
        refusal = null;
        var parts = entry.Split(',');
        if (parts.Length < 7)
        {
            refusal = $"malformed rule entry '{entry}' — dropped (named): expected effect,kind,scopeKind,scopeId,expires,ruleId,anchor";
            return null;
        }
        var effect = parts[0].Trim().ToLowerInvariant();
        var kind = parts[1].Trim().ToLowerInvariant();
        var scopeKind = parts[2].Trim().ToLowerInvariant();
        var scopeId = parts[3].Trim();
        var expiresRaw = parts[4].Trim();
        var ruleId = parts[5].Trim();
        var anchor = string.Join(",", parts.Skip(6)).Trim();
        DateTimeOffset? expires = null;
        if (expiresRaw != "-" && expiresRaw.Length > 0)
        {
            // FL-25c/F12: expiry parsing is culture-invariant AND
            // requires an explicit offset designator — previously a
            // bare local-time string parsed against the HOST's
            // culture/timezone, so one policy text meant different
            // instants on different hosts.
            // FL-25b/DF4: the FL-25 heuristic accepted a DATE-ONLY
            // expiry ('2027-01-01': no 'T', and the date's own last
            // '-' scored as an offset sign), so TryParse applied
            // the host's local offset — the exact host-dependent
            // behaviour F12 was meant to remove. The check is now
            // strict: a time component must exist, and the string
            // must end in 'Z' or a ±HH / ±HHMM / ±HH:MM designator.
            var hasOffset = HasExplicitOffset(expiresRaw);
            if (!hasOffset || !DateTimeOffset.TryParse(expiresRaw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            {
                refusal = $"rule entry '{entry}' carries an expiry that is unparsable or carries no explicit offset — dropped (named): expiries must be ISO-8601 with an offset (e.g. 2027-01-01T00:00:00Z), parsed culture-invariantly";
                return null;
            }
            expires = parsed;
        }
        return new AppRule(
            Id: ruleId, Effect: effect, Kind: kind,
            Hash: kind == RuleKinds.Hash ? anchor : null,
            SignerThumbprint: kind == RuleKinds.Publisher ? anchor : null,
            Product: kind == RuleKinds.Product ? anchor : null,
            Path: kind == RuleKinds.Path ? anchor : null,
            ScopeKind: scopeKind, ScopeId: scopeId,
            ExpiresUtc: expires, SourceRequestId: null);
    }
}

public static class AppDispositions
{
    public const string Allowed = "allowed";
    public const string Blocked = "blocked";               // enforce mode stopped it
    public const string WouldBlock = "would_block";         // audit mode: logged, NOT stopped
    public const string NotControlled = "not_controlled";   // feature disabled by policy
}

/// <summary>One launch's verdict. Carries the EFFECTIVE MODE and
/// its unambiguous label, whether a block actually happened
/// (Blocked) vs would have (WouldBlock) — audit-mode confusion is
/// unrepresentable: an audit verdict never claims a block.</summary>
public sealed record AppDecision(
    AppIdentity Identity, string Disposition, AppRule? MatchedRule,
    string EffectiveMode, string Reason)
{
    public string EffectiveModeLabel => AppControlModes.Label(EffectiveMode);
    public bool ActuallyBlocked => Disposition == AppDispositions.Blocked;
    public bool IsStoppedOrWouldStop =>
        Disposition is AppDispositions.Blocked or AppDispositions.WouldBlock;
}

/// <summary>The pure evaluator. Precedence: the STRONGEST matching
/// rank decides (hash &gt; publisher &gt; product &gt; path);
/// within one rank, DENY beats ALLOW and the conflict is named.
/// EXPLICIT PRECEDENCE DECISION (FL-25c/F8): an approval rule
/// carries the rank of its weakest anchor, so a higher-rank policy
/// DENY (e.g. a product deny over a path-only approval) beats an
/// approval allow — an approval is never a trump over policy, at
/// any rank. No matching rule → default-deny (only approved code
/// runs): blocked in enforce mode, would-block in audit mode.</summary>
public static class AppControlEvaluator
{
    public static AppDecision Evaluate(AppIdentity identity, ResolvedAppControlPolicy policy, DateTimeOffset now)
    {
        if (!policy.FeatureEnabled)
            return new AppDecision(identity, AppDispositions.NotControlled, null, policy.Mode,
                $"application control is disabled by policy — '{identity.NormalizedProduct}' is not controlled (mode label: {policy.EffectiveModeLabel})");
        var matching = policy.Rules.Where(r => r.Matches(identity, now)).ToList();
        if (matching.Count > 0)
        {
            var topRank = matching.Max(r => r.Rank);
            var top = matching.Where(r => r.Rank == topRank).ToList();
            var deny = top.FirstOrDefault(r => r.Effect == RuleEffects.Deny);
            var winner = deny ?? top[0];
            var conflict = deny is not null && top.Any(r => r.Effect == RuleEffects.Allow)
                ? " (an allow rule of the SAME precedence also matched — deny wins within a rank; the conflict is named, never silently resolved)"
                : deny is not null && matching.Any(r => r.Effect == RuleEffects.Allow)
                ? " (an allow rule of LOWER precedence also matched — the higher-precedence deny wins; the conflict is named, never silently resolved)"
                : "";
            if (winner.Effect == RuleEffects.Deny)
                return policy.Mode == AppControlModes.Enforce
                    ? new AppDecision(identity, AppDispositions.Blocked, winner, policy.Mode,
                        $"'{identity.NormalizedProduct}' BLOCKED by {winner.Describe()}{conflict}")
                    : new AppDecision(identity, AppDispositions.WouldBlock, winner, policy.Mode,
                        $"'{identity.NormalizedProduct}' WOULD be blocked by {winner.Describe()} — AUDIT-ONLY mode: the launch was NOT stopped{conflict}");
            return new AppDecision(identity, AppDispositions.Allowed, winner, policy.Mode,
                $"'{identity.NormalizedProduct}' allowed by {winner.Describe()}");
        }
        return policy.Mode == AppControlModes.Enforce
            ? new AppDecision(identity, AppDispositions.Blocked, null, policy.Mode,
                $"'{identity.NormalizedProduct}' BLOCKED: no allow rule matches and application control default-denies unlisted applications in ENFORCE mode")
            : new AppDecision(identity, AppDispositions.WouldBlock, null, policy.Mode,
                $"'{identity.NormalizedProduct}' WOULD be blocked: no allow rule matches and application control default-denies unlisted applications — AUDIT-ONLY mode: the launch was NOT stopped");
    }
}

// ---- block events (RMM-01 alert-centre sink shapes) -------------------

public static class AppBlockAlertKind
{
    public const string Kind = "app_blocked";
    public static string ConditionIdFor(AppIdentity identity) =>
        "app-control:" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(identity.Key))).ToLowerInvariant()[..16];
}

/// <summary>One block (or would-block) event: the FULL application
/// identity, the rule that matched (or the default-deny named), the
/// effective mode, and whether a block actually happened.</summary>
public sealed record AppBlockEvent(
    string DeviceId, AppIdentity Identity, string? MatchedRuleDescription,
    string EffectiveMode, bool ActuallyBlocked, DateTimeOffset OccurredUtc, string Detail)
{
    public string EffectiveModeLabel => AppControlModes.Label(EffectiveMode);
}

/// <summary>The alert-centre sink seam for block events (RMM-01
/// shapes). Implementations deliver into the alert centre; the
/// recording double is the test fake.</summary>
public interface IAppBlockAlertSink
{
    void Raise(AppBlockEvent blockEvent);
}

public sealed class RecordingAppBlockAlertSink : IAppBlockAlertSink
{
    public List<AppBlockEvent> Events { get; } = new();
    public void Raise(AppBlockEvent blockEvent) => Events.Add(blockEvent);
}

/// <summary>The production-shaped adapter: block events land in
/// RMM-01's HealthAlertCentre (which mirrors into the DIR-57 centre
/// and the shared chained ledger). Enforce blocks raise at warning;
/// audit would-blocks at info — the severity itself names whether
/// anything was actually stopped.</summary>
public sealed class HealthAlertCentreAppBlockSink : IAppBlockAlertSink
{
    private readonly HealthAlertCentre _centre;
    public HealthAlertCentreAppBlockSink(HealthAlertCentre centre) =>
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));

    public void Raise(AppBlockEvent blockEvent)
    {
        _centre.Raise(
            blockEvent.DeviceId,
            AppBlockAlertKind.ConditionIdFor(blockEvent.Identity),
            AppBlockAlertKind.Kind,
            blockEvent.ActuallyBlocked ? AlertSeverities.Warning : AlertSeverities.Info,
            blockEvent.Detail, "app-control", TimeSpan.Zero, blockEvent.OccurredUtc);
    }
}

// ---- enforcement seam (host wiring: AppLocker / WDAC) -----------------

public sealed record AppEnforcementPlan(
    string DeviceId, string EffectiveMode, IReadOnlyList<AppRule> Rules, DateTimeOffset PlannedUtc)
{
    public string EffectiveModeLabel => AppControlModes.Label(EffectiveMode);
}

public sealed record AppApplyResult(bool Applied, string Detail);

/// <summary>The OS-enforcement applier seam (AppLocker/WDAC policy
/// writer). Implementations must be honest: an applier that cannot
/// write OS policy reports Applied=false with the reason — a
/// computed plan is never reported as enforced.</summary>
public interface IAppControlApplier
{
    AppApplyResult Apply(AppEnforcementPlan plan);
}

/// <summary>The honest placeholder where no AppLocker/WDAC writer
/// is wired: every apply reports NOT applied, by name.</summary>
public sealed class UnavailableAppControlApplier : IAppControlApplier
{
    public AppApplyResult Apply(AppEnforcementPlan plan) =>
        new(false, $"no AppLocker/WDAC policy writer is wired on this host — plan for device '{plan.DeviceId}' ({plan.Rules.Count} rules, mode {plan.EffectiveModeLabel}) was computed but NOT applied (named remainder: host wiring)");
}

/// <summary>Test double: records every plan and reports applied.</summary>
public sealed class RecordingAppControlApplier : IAppControlApplier
{
    public List<AppEnforcementPlan> Plans { get; } = new();
    public AppApplyResult Apply(AppEnforcementPlan plan)
    {
        Plans.Add(plan);
        return new AppApplyResult(true, $"applied {plan.Rules.Count} rules to device {plan.DeviceId} (mode {plan.EffectiveModeLabel})");
    }
}

// ---- the access-request workflow ---------------------------------------

public static class AppRequestStates
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
}

/// <summary>One user's request to run blocked software. The device
/// identity is stamped from the AUTHENTICATED channel at filing
/// (the store compares the body's claim, exactly as RMM-12's intake
/// does — a mismatch is a spoof refusal, no record created).</summary>
public sealed record AppAccessRequest(
    string Id,
    string DeviceId,
    string Requester,
    AppIdentity Identity,
    string BusinessReason,
    string State,
    DateTimeOffset CreatedUtc,
    string? DecidedBy,
    DateTimeOffset? DecidedUtc,
    string? DecisionReason,
    string? MintedRuleId,
    string? OfferedPackageId,
    // bd-shared-sec-1/F4: the requester's AUTHENTICATED principal
    // id, stamped from the channel at filing exactly as the device
    // id is stamped — never the free-text Requester display name.
    // Decision-time self-approval checks compare principal ids
    // against this stamp. Null on requests filed before stamping
    // existed (the display-name check still applies to those).
    string? RequesterPrincipal = null);

/// <summary>The request store: filing discipline (spoof refusal,
/// idempotency, flood caps), decision discipline (no self-approval,
/// no widening, expiry mandatory and bounded), and the live
/// approval-rule set the resolver consumes. Pure state + rules; the
/// Core service adds the chained audit and the RMM-12 work item.</summary>
public sealed class AppAccessRequestStore
{
    // FL-25b/F4: requests are keyed PER DEVICE (device|id). Request
    // ids are caller-chosen, so a global keyspace let one device's
    // filing return (leak) another device's request on collision.
    private readonly Dictionary<string, AppAccessRequest> _byId = new(StringComparer.Ordinal);
    // FL-25b/DF7: bare-id index (request id -> the store keys that
    // hold it, one per device). Locate/CountById previously scanned
    // every stored request on every decision (three full scans per
    // approval at the service); the index makes them proportional
    // to the number of devices actually holding the id.
    private readonly Dictionary<string, List<string>> _keysById = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AppRule> _rulesById = new(StringComparer.Ordinal);
    private readonly HashSet<string> _approverPrincipals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>Raised after every successful mutation (file,
    /// approve, deny, remove, evict, import) so the host can write
    /// the store through to disk — bd-shared-sec-1/F2.</summary>
    public event Action? Changed;

    private static string KeyFor(string deviceId, string requestId) =>
        (deviceId ?? "").Trim().ToLowerInvariant() + "|" + (requestId ?? "").Trim();

    /// <summary>Group-authority seam for FL-25a/F1, wired by the
    /// Core service from the RMM-07 engine: (deviceId, groupId) →
    /// the device is a member of the group. When UNWIRED, group
    /// approvals refuse (fail closed) — a group approval can never
    /// rest on the approver's say-so alone.</summary>
    public Func<string, string, bool>? GroupMembershipCheck { get; set; }
    /// <summary>(groupId) → the group exists. Wired with
    /// GroupMembershipCheck; unwired group approvals refuse.</summary>
    public Func<string, bool>? GroupExistenceCheck { get; set; }

    /// <summary>Register an approver PRINCIPAL: a decision
    /// (approve or deny) is accepted only from a registered
    /// principal id. The registry is the AUTHORIZATION (role)
    /// check — decisions compare principal ids from this registry,
    /// never free-text display names. With NO principals
    /// registered, decisions refuse (fail closed).
    /// HONEST BOUNDARY (FL-25b/DF2): the registry authorizes an id;
    /// it does not AUTHENTICATE the caller presenting it — exactly
    /// as the filing path trusts the channel's authenticated device
    /// id, the decision path trusts the host channel to present
    /// only the authenticated caller's principal id. No
    /// authenticated-caller abstraction exists in this tree; the
    /// earlier comment claiming decisions come from "an
    /// authenticated approver principal" overclaimed and is
    /// corrected here.</summary>
    public void RegisterApproverPrincipal(string? principalId)
    {
        if (string.IsNullOrWhiteSpace(principalId)) return;
        lock (_gate) _approverPrincipals.Add(principalId.Trim());
    }

    /// <summary>REPLACE the approver-principal set from the live
    /// source (Lane A item 4). Replacement (not just addition) is
    /// what keeps the gate fail-closed when a principal is
    /// suspended or offboarded after registration: the next refresh
    /// removes them and their decisions refuse again. The SERVICE
    /// refresh passes the UNION of its constructor-registered ids
    /// and the source's ids (FL-25b/DF9), so wiring a source never
    /// silently discards statically registered principals.</summary>
    public void SetApproverPrincipals(IEnumerable<string>? principalIds)
    {
        lock (_gate)
        {
            _approverPrincipals.Clear();
            foreach (var id in principalIds ?? Array.Empty<string>())
                if (!string.IsNullOrWhiteSpace(id)) _approverPrincipals.Add(id.Trim());
        }
    }

    public IReadOnlyList<string> ApproverPrincipals
    {
        get { lock (_gate) return _approverPrincipals.OrderBy(p => p, StringComparer.Ordinal).ToList(); }
    }

    private string? PrincipalRefusal(string? actor, string verb)
    {
        // Caller holds _gate.
        if (_approverPrincipals.Count == 0)
            return $"no approver principals are registered — {verb} refused (fail closed: a decision must come from a registered approver principal, never a free-text name)";
        if (string.IsNullOrWhiteSpace(actor) || !_approverPrincipals.Contains(actor.Trim()))
            return $"'{actor}' is not a registered approver principal — {verb} refused (decisions are made by principal id with an approver role, not by any caller-supplied name)";
        return null;
    }

    // Index maintenance. Caller holds _gate.
    private void IndexAdd(string bareId, string key)
    {
        if (!_keysById.TryGetValue(bareId, out var keys)) _keysById[bareId] = keys = new List<string>();
        if (!keys.Contains(key)) keys.Add(key);
    }

    private void IndexRemove(string bareId, string key)
    {
        if (_keysById.TryGetValue(bareId, out var keys))
        {
            keys.Remove(key);
            if (keys.Count == 0) _keysById.Remove(bareId);
        }
    }

    /// <summary>Locate a request by its bare id across devices.
    /// Caller holds _gate. More than one device holding the id is
    /// an AMBIGUITY refusal, never a silent pick (FL-25b/F4).</summary>
    private (AppAccessRequest? Request, string? Ambiguity) Locate(string? requestId)
    {
        if (requestId is null || !_keysById.TryGetValue(requestId, out var keys) || keys.Count == 0)
            return (null, null);
        if (keys.Count > 1)
            return (null, $"request id '{requestId}' exists on {keys.Count} devices — the id is ambiguous across devices and no decision may pick one silently; refused (request ids are scoped per device; decide it with the device-scoped decision overload)");
        return (_byId[keys[0]], null);
    }

    public IReadOnlyList<AppAccessRequest> Requests
    {
        get { lock (_gate) return _byId.Values.OrderBy(r => r.CreatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>The request with this id, ONLY when exactly one
    /// device holds it; an id standing on several devices returns
    /// null here (decisions use the ambiguity-refusing path).</summary>
    public AppAccessRequest? Get(string? id)
    {
        lock (_gate) { var (r, _) = Locate(id); return r; }
    }

    public AppAccessRequest? Get(string? deviceId, string? id)
    {
        lock (_gate) return id is not null && deviceId is not null &&
            _byId.TryGetValue(KeyFor(deviceId, id), out var r) ? r : null;
    }

    /// <summary>How many devices hold a request with this bare id
    /// (0 = unknown, 1 = unique, &gt;1 = ambiguous across devices).</summary>
    public int CountById(string? id)
    {
        lock (_gate) return id is not null && _keysById.TryGetValue(id, out var keys) ? keys.Count : 0;
    }

    /// <summary>Remove a request outright (service rollback when a
    /// downstream step — the work-item intake — fails after filing:
    /// a request must not stand for work that was never queued,
    /// FL-25c/F10). Returns true when a request was removed.</summary>
    public bool Remove(string deviceId, string requestId)
    {
        lock (_gate)
        {
            var key = KeyFor(deviceId, requestId);
            if (!_byId.Remove(key)) return false;
            IndexRemove(requestId, key);
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Evict approval rules that have expired (the store
    /// previously kept them forever, FL-25c/F11). Returns the
    /// number evicted. Decided-request eviction happens at filing
    /// time under DecidedRequestRetention.</summary>
    public int EvictExpiredApprovalRules(DateTimeOffset now) => EvictExpiredApprovalRules(now, null);

    /// <summary>Evict expired approval rules, optionally only those
    /// matching a predicate (FL-25b/DF6: the service evicts only
    /// the expired rules the resolver just named for the resolving
    /// device — a rule is never evicted by a device that did not
    /// own it before its owner saw it named).</summary>
    public int EvictExpiredApprovalRules(DateTimeOffset now, Func<AppRule, bool>? only)
    {
        lock (_gate)
        {
            var dead = _rulesById.Values
                .Where(r => r.IsExpired(now) && (only is null || only(r))).Select(r => r.Id).ToList();
            foreach (var id in dead) _rulesById.Remove(id);
            if (dead.Count > 0) Changed?.Invoke();
            return dead.Count;
        }
    }

    /// <summary>File a request. `authenticatedDeviceId` is the
    /// channel's device identity — the ONLY identity the request
    /// ever carries. Idempotent per request id; a second PENDING
    /// request for the same device+identity returns the standing
    /// one (a user re-clicking "request" mints nothing twice).</summary>
    public (AppAccessRequest? Request, bool Created, string Reason) File(
        string? authenticatedDeviceId, string? claimedDeviceId, string requestId,
        string? requester, AppIdentity? identity, string? businessReason, DateTimeOffset now,
        string? authenticatedRequesterPrincipal = null)
    {
        // bd-shared-sec-1/F4: the requester principal, when the
        // channel supplies one, is validated like any principal id
        // and STAMPED on the request; decisions compare against the
        // stamp, so an approver who files under a borrowed display
        // name can no longer approve their own request.
        if (authenticatedRequesterPrincipal is not null &&
            (string.IsNullOrWhiteSpace(authenticatedRequesterPrincipal) ||
             authenticatedRequesterPrincipal.Trim().Length > AppControlLimits.MaxActorLength ||
             AppIdentity.HasControlChars(authenticatedRequesterPrincipal)))
            return (null, false, "the authenticated requester principal is out of bounds — refused");
        if (string.IsNullOrWhiteSpace(authenticatedDeviceId))
            return (null, false, "the request arrived on no authenticated device channel — refused");
        if (string.IsNullOrWhiteSpace(requestId)) return (null, false, "the request carries no request id — refused");
        // FL-25b/DF1: the id is device-chosen and reaches rule ids,
        // work-item keys and ledger details — strict charset only.
        if (!AppRequestIds.IsValid(requestId)) return (null, false, AppRequestIds.Refusal);
        if (identity is null) return (null, false, "the request names no application identity — refused");
        if (identity.Validate() is { } invalid) return (null, false, invalid);
        if (!string.Equals((claimedDeviceId ?? "").Trim(), authenticatedDeviceId.Trim(), StringComparison.OrdinalIgnoreCase))
            return (null, false, $"the request claims device '{claimedDeviceId}' but arrived on the authenticated channel of '{authenticatedDeviceId}' — refused as a spoofed device context; no request recorded");
        if (!string.Equals(identity.DeviceId, authenticatedDeviceId.Trim(), StringComparison.OrdinalIgnoreCase))
            return (null, false, $"the application identity names device '{identity.DeviceId}' inside a request for '{authenticatedDeviceId}' — refused (a request speaks for its own device only)");
        if (string.IsNullOrWhiteSpace(requester) || requester.Trim().Length > AppControlLimits.MaxActorLength)
            return (null, false, "a request needs a requester name within bounds — refused");
        if (AppIdentity.HasControlChars(requester) || AppIdentity.HasControlChars(businessReason))
            return (null, false, "requester and business reason must not carry control characters — refused (ledger-forgery vector)");
        if (string.IsNullOrWhiteSpace(businessReason) || businessReason.Trim().Length > AppControlLimits.MaxReasonLength)
            return (null, false, $"a request needs a business reason within {AppControlLimits.MaxReasonLength} characters — refused (an approval decision is made on the stated reason; no reason, no request)");
        lock (_gate)
        {
            // FL-25c/F11: one pass over the store computes the
            // standing-duplicate, the per-device pending count and
            // the per-requester rate count (previously three
            // separate scans per filing), and evicts decided
            // requests past their retention in the same pass.
            AppAccessRequest? standing = null;
            var pendingForDevice = 0;
            var recentByRequester = 0;
            // FL-25b/DF7: the same single pass also computes the
            // bounds the FL-25 constants declared but nothing
            // enforced — pending in TOTAL (was per-device only) and
            // filings per DEVICE per hour (the per-requester cap
            // keys on a free-text name a filer can rotate; the
            // device cap cannot be rotated away).
            var pendingTotal = 0;
            var recentByDevice = 0;
            List<(string Key, string Id)>? evict = null;
            foreach (var r in _byId.Values)
            {
                if (r.State != AppRequestStates.Pending &&
                    r.DecidedUtc is { } d && now - d > AppControlLimits.DecidedRequestRetention)
                    (evict ??= new List<(string, string)>()).Add((KeyFor(r.DeviceId, r.Id), r.Id));
                if (r.State == AppRequestStates.Pending)
                {
                    pendingTotal++;
                    if (string.Equals(r.DeviceId, authenticatedDeviceId, StringComparison.OrdinalIgnoreCase))
                    {
                        pendingForDevice++;
                        if (standing is null && r.Identity.Key == identity.Key) standing = r;
                    }
                }
                if (string.Equals(r.DeviceId, authenticatedDeviceId, StringComparison.OrdinalIgnoreCase) &&
                    now - r.CreatedUtc < TimeSpan.FromHours(1))
                    recentByDevice++;
                if (string.Equals(r.Requester, requester.Trim(), StringComparison.OrdinalIgnoreCase) &&
                    now - r.CreatedUtc < TimeSpan.FromHours(1))
                    recentByRequester++;
            }
            if (evict is not null) foreach (var (k, id) in evict) { _byId.Remove(k); IndexRemove(id, k); }
            // Per-device idempotency (FL-25b/F4): only THIS device's
            // own request with this id is returned — another
            // device's request under the same id is never leaked.
            if (_byId.TryGetValue(KeyFor(authenticatedDeviceId, requestId), out var existing))
                return (existing, false, $"request '{requestId}' already stands on device '{authenticatedDeviceId}' (idempotent filing)");
            if (standing is not null)
                return (standing, false, $"a pending request '{standing.Id}' already covers this application on device '{authenticatedDeviceId}' — the standing request is returned, no duplicate minted");
            if (pendingForDevice >= AppControlLimits.MaxPendingRequestsPerDevice)
                return (null, false, $"pending-request cap ({AppControlLimits.MaxPendingRequestsPerDevice}) reached for device '{authenticatedDeviceId}' — request refused (flood discipline, counted not silent)");
            if (recentByRequester >= AppControlLimits.MaxRequestsPerRequesterPerHour)
                return (null, false, $"requester '{requester.Trim()}' has filed {recentByRequester} requests in the last hour (cap {AppControlLimits.MaxRequestsPerRequesterPerHour}) — request refused (flood discipline)");
            // FL-25b/DF7 bounds, enforced (they were constants only):
            if (recentByDevice >= AppControlLimits.MaxRequestsPerDevicePerHour)
                return (null, false, $"device '{authenticatedDeviceId}' has filed {recentByDevice} requests in the last hour (cap {AppControlLimits.MaxRequestsPerDevicePerHour}) — request refused (flood discipline that a rotated requester name cannot bypass)");
            if (pendingTotal >= AppControlLimits.MaxPendingRequestsTotal)
                return (null, false, $"the fleet-wide pending-request bound ({AppControlLimits.MaxPendingRequestsTotal}) is reached — request refused (flood discipline, counted not silent)");
            if (_byId.Count >= AppControlLimits.MaxStoredRequests)
                return (null, false, $"the request store bound ({AppControlLimits.MaxStoredRequests} stored requests) is reached — request refused (bounded store, counted not silent)");
            var request = new AppAccessRequest(
                requestId, authenticatedDeviceId.Trim(), requester.Trim(), identity,
                businessReason.Trim(), AppRequestStates.Pending, now,
                null, null, null, null, null,
                authenticatedRequesterPrincipal?.Trim());
            _byId[KeyFor(authenticatedDeviceId, requestId)] = request;
            IndexAdd(requestId, KeyFor(authenticatedDeviceId, requestId));
            Changed?.Invoke();
            return (request, true, $"request '{requestId}' filed for '{identity.NormalizedProduct}' on device '{authenticatedDeviceId}'");
        }
    }

    /// <summary>Approve a pending request, minting the scoped allow
    /// rule. THE ANTI-WIDENING CONTRACT: the rule binds the
    /// conjunction of the REQUESTED identity's strong anchors
    /// (product always; hash and signer when the identity carries
    /// them; path only when it is the identity's sole anchor beyond
    /// product) — there is no parameter by which an approver can
    /// broaden it. Scope is the request's device or ONE named group;
    /// org scope refuses (that would widen beyond the request).
    /// Expiry is mandatory and bounded. Self-approval refuses.</summary>
    public (AppAccessRequest? Request, AppRule? Rule, string Reason) Approve(
        string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, DateTimeOffset now) =>
        ApproveCore(null, requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, now);

    /// <summary>Device-scoped approval (FL-25b/DF3): when several
    /// devices hold the same bare request id, the bare overload
    /// refuses as ambiguous — this overload decides ONE device's
    /// request, so a colliding id filed by a rogue device can no
    /// longer freeze a victim's pending request forever.</summary>
    public (AppAccessRequest? Request, AppRule? Rule, string Reason) Approve(
        string deviceId, string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, DateTimeOffset now) =>
        ApproveCore(deviceId, requestId, approver, scopeKind, scopeId, expiresUtc, offeredPackageId, now);

    private (AppAccessRequest? Request, AppRule? Rule, string Reason) ApproveCore(
        string? deviceId, string requestId, string? approver, string scopeKind, string? scopeId,
        DateTimeOffset? expiresUtc, string? offeredPackageId, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(approver) || approver.Trim().Length > AppControlLimits.MaxActorLength)
            return (null, null, "an approval needs an approver name within bounds — refused");
        if (AppIdentity.HasControlChars(approver))
            return (null, null, "the approver principal id carries control characters — refused");
        AppAccessRequest request;
        lock (_gate)
        {
            AppAccessRequest? located;
            if (deviceId is not null)
            {
                located = _byId.TryGetValue(KeyFor(deviceId, requestId), out var scoped) ? scoped : null;
                if (located is null)
                    return (null, null, $"unknown request '{requestId}' on device '{deviceId}' — approval refused");
            }
            else
            {
                var (found, ambiguity) = Locate(requestId);
                if (ambiguity is not null) return (null, null, ambiguity);
                located = found;
                if (located is null)
                    return (null, null, $"unknown request '{requestId}' — approval refused");
            }
            request = located;
            if (request.State != AppRequestStates.Pending)
                return (null, null, $"request '{requestId}' is already {request.State} — decisions are terminal and singular");
            if (string.Equals(approver.Trim(), request.Requester, StringComparison.OrdinalIgnoreCase))
                return (null, null, $"request '{requestId}' cannot be approved by its own requester '{request.Requester}' — a request can never self-approve");
            // bd-shared-sec-1/F4: principal-id self-approval check —
            // the approver's principal id against the requester's
            // STAMPED principal id, whatever display name the filing
            // carried. This is the check that cannot be rotated away.
            if (request.RequesterPrincipal is { } requesterPrincipal &&
                string.Equals(approver.Trim(), requesterPrincipal, StringComparison.OrdinalIgnoreCase))
                return (null, null, $"request '{requestId}' cannot be approved by its own requester principal '{requesterPrincipal}' — a request can never self-approve (the filing display name is not the identity; the stamped principal is)");
            // FL-25b/F3 principal gate — after the self-approval
            // check so a self-approval attempt gets its specific
            // refusal; both refuse, neither mints.
            if (PrincipalRefusal(approver, "approval") is { } principalRefusal)
                return (null, null, principalRefusal);
            if (expiresUtc is null)
                return (null, null, "an approval MUST carry an expiry — refused: approvals are not permanent by default");
            if (expiresUtc.Value <= now)
                return (null, null, "the approval expiry is not in the future — refused");
            if (expiresUtc.Value - now > AppControlLimits.MaxApprovalDuration)
                return (null, null, $"the approval expiry exceeds the maximum approval lifetime ({AppControlLimits.MaxApprovalDuration.TotalDays:0} days) — refused, never clamped");
        }
        // Scope resolution. FL-25b/DF11: the group-authority
        // callbacks call OUT into the policy engine and the facts
        // provider — external code must never run under the store
        // lock (deadlock/re-entrancy if either ever calls back into
        // the store), so they run here, unlocked; the decision is
        // re-validated under the lock before anything is minted.
        string scope;
        string scopeTarget;
        switch ((scopeKind ?? "").Trim().ToLowerInvariant())
        {
            case RuleScopes.Device:
                if (!string.Equals(scopeId, request.DeviceId, StringComparison.OrdinalIgnoreCase))
                    return (null, null, $"a device-scoped approval must name the requesting device '{request.DeviceId}' — naming '{scopeId}' would move the approval to another device; refused");
                scope = RuleScopes.Device; scopeTarget = request.DeviceId; break;
            case RuleScopes.Group:
                if (string.IsNullOrWhiteSpace(scopeId))
                    return (null, null, "a group-scoped approval must name the group — refused");
                // FL-25a/F1: a group approval must name a group
                // that EXISTS and that the REQUESTING DEVICE
                // belongs to — previously any non-blank string
                // minted a rule for a group the requester was
                // never in (the approval silently landed on
                // other devices). Unwired authority refuses.
                if (GroupExistenceCheck is null || GroupMembershipCheck is null)
                    return (null, null, "a group-scoped approval needs a group authority (existence + membership) and none is wired — refused (fail closed)");
                if (!GroupExistenceCheck(scopeId.Trim()))
                    return (null, null, $"group '{scopeId.Trim()}' does not exist — group-scoped approval refused (a named group must be a real group)");
                if (!GroupMembershipCheck(request.DeviceId, scopeId.Trim()))
                    return (null, null, $"device '{request.DeviceId}' is not a member of group '{scopeId.Trim()}' — group-scoped approval refused: an approval can only widen to a group the requesting device itself belongs to");
                scope = RuleScopes.Group; scopeTarget = scopeId.Trim(); break;
            case RuleScopes.Org:
                return (null, null, "an org-scoped approval would widen one user's request to the whole fleet — refused: approvals scope to the requesting device or one named group");
            default:
                return (null, null, $"unknown approval scope '{scopeKind}' — refused");
        }
        lock (_gate)
        {
            // Re-validate after the unlocked scope phase: the
            // request must still be the SAME pending request.
            if (!_byId.TryGetValue(KeyFor(request.DeviceId, request.Id), out var current) ||
                current.State != AppRequestStates.Pending || current.CreatedUtc != request.CreatedUtc)
                return (null, null, $"request '{requestId}' changed while its approval scope was being checked — approval refused (decisions land on the request that was examined, or not at all)");
            if (PrincipalRefusal(approver, "approval") is { } principalRefusal2)
                return (null, null, principalRefusal2);
            var identity = request.Identity;
            var rule = new AppRule(
                // FL-25b/DF3: the minted rule id is scoped to the
                // requesting DEVICE — approval rules were a second
                // global keyspace ('approval-' + bare id), so one
                // device's approval could overwrite another's live
                // rule under the same request id.
                Id: "approval-" + request.Id + "@" + AppRequestIds.Segment(request.DeviceId),
                Effect: RuleEffects.Allow,
                Kind: RuleKinds.Approval,
                Hash: identity.NormalizedHash.Length > 0 ? identity.NormalizedHash : null,
                SignerThumbprint: identity.NormalizedSigner.Length > 0 ? identity.NormalizedSigner : null,
                Product: identity.NormalizedProduct,
                Path: identity.NormalizedHash.Length == 0 && identity.NormalizedSigner.Length == 0
                    ? identity.NormalizedPath : null,
                ScopeKind: scope, ScopeId: scopeTarget,
                ExpiresUtc: expiresUtc.Value,
                SourceRequestId: request.Id);
            if (rule.Validate(now) is { } invalid) return (null, null, invalid);
            _rulesById[rule.Id] = rule;
            var decided = request with
            {
                State = AppRequestStates.Approved,
                DecidedBy = approver.Trim(), DecidedUtc = now,
                DecisionReason = $"approved; scoped allow minted as rule '{rule.Id}' ({rule.StrengthLabel})",
                MintedRuleId = rule.Id, OfferedPackageId = offeredPackageId,
            };
            _byId[KeyFor(request.DeviceId, request.Id)] = decided;
            Changed?.Invoke();
            return (decided, rule, $"request '{requestId}' approved by {approver.Trim()}; scoped allow rule '{rule.Id}' minted for the exact requested identity, scope {scope}:{scopeTarget}, expiring {expiresUtc.Value:O}");
        }
    }

    /// <summary>Deny a pending request. The denial + its reason are
    /// recorded on the request — a silent denial is unrepresentable.
    /// Self-denial also refuses (a decision is another person's act).</summary>
    public (AppAccessRequest? Request, string Reason) Deny(
        string requestId, string? denier, string? reason, DateTimeOffset now) =>
        DenyCore(null, requestId, denier, reason, now);

    /// <summary>Device-scoped denial (FL-25b/DF3): decides ONE
    /// device's request when the bare id is ambiguous across
    /// devices — the bare overload's ambiguity refusal must not
    /// freeze the request forever.</summary>
    public (AppAccessRequest? Request, string Reason) Deny(
        string deviceId, string requestId, string? denier, string? reason, DateTimeOffset now) =>
        DenyCore(deviceId, requestId, denier, reason, now);

    private (AppAccessRequest? Request, string Reason) DenyCore(
        string? deviceId, string requestId, string? denier, string? reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(denier)) return (null, "a denial needs a named decider — refused");
        if (AppIdentity.HasControlChars(denier) || AppIdentity.HasControlChars(reason))
            return (null, "denier and denial reason must not carry control characters — refused (ledger-forgery vector)");
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length > AppControlLimits.MaxReasonLength)
            return (null, $"a denial must record its reason within {AppControlLimits.MaxReasonLength} characters — refused (denial is recorded WITH reason, never silently)");
        lock (_gate)
        {
            AppAccessRequest? request;
            if (deviceId is not null)
            {
                request = _byId.TryGetValue(KeyFor(deviceId, requestId), out var scoped) ? scoped : null;
                if (request is null)
                    return (null, $"unknown request '{requestId}' on device '{deviceId}' — denial refused");
            }
            else
            {
                var (found, ambiguity) = Locate(requestId);
                if (ambiguity is not null) return (null, ambiguity);
                request = found;
                if (request is null)
                    return (null, $"unknown request '{requestId}' — denial refused");
            }
            if (request.State != AppRequestStates.Pending)
                return (null, $"request '{requestId}' is already {request.State} — decisions are terminal and singular");
            if (string.Equals(denier.Trim(), request.Requester, StringComparison.OrdinalIgnoreCase))
                return (null, $"request '{requestId}' cannot be decided by its own requester '{request.Requester}' — refused");
            if (request.RequesterPrincipal is { } denierPrincipal &&
                string.Equals(denier.Trim(), denierPrincipal, StringComparison.OrdinalIgnoreCase))
                return (null, $"request '{requestId}' cannot be decided by its own requester principal '{denierPrincipal}' — refused (bd-shared-sec-1/F4)");
            // FL-25b/F3: denial is a decision too — it must come
            // from a registered approver principal. (This is the
            // principal/role gate only; denial remains deliberately
            // NOT gated on the feature toggle — see the service.)
            if (PrincipalRefusal(denier, "denial") is { } principalRefusal)
                return (null, principalRefusal);
            var decided = request with
            {
                State = AppRequestStates.Denied,
                DecidedBy = denier.Trim(), DecidedUtc = now,
                DecisionReason = reason.Trim(),
            };
            _byId[KeyFor(request.DeviceId, request.Id)] = decided;
            Changed?.Invoke();
            return (decided, $"request '{requestId}' denied by {denier.Trim()}: {reason.Trim()}");
        }
    }

    /// <summary>The live approval rules (unexpired at `now`) — the
    /// set the resolver joins into a device's policy. Expired rules
    /// are excluded here AND fail Matches defensively.</summary>
    public IReadOnlyList<AppRule> LiveApprovalRules(DateTimeOffset now)
    {
        lock (_gate) return _rulesById.Values.Where(r => !r.IsExpired(now))
            .OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
    }

    public IReadOnlyList<AppRule> AllApprovalRules
    {
        get { lock (_gate) return _rulesById.Values.OrderBy(r => r.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>The approval rules whose scope CAN apply to one
    /// device (live and expired alike — the resolver names the
    /// expired ones for their own device). FL-25b/DF6: resolution
    /// previously received EVERY approval rule in the fleet, so
    /// other devices' rules were validated, named in this device's
    /// notes, ledgered, and evicted by a device that did not own
    /// them. The service now fetches only this device's slice.</summary>
    public IReadOnlyList<AppRule> ApprovalRulesFor(AppIdentity probe, string scopeId, IReadOnlySet<string> groupIds)
    {
        lock (_gate) return _rulesById.Values.Where(r => r.ScopeApplies(probe, scopeId, groupIds)).ToList();
    }

    // ---- hub persistence (bd-shared-sec-1/F2) -------------------
    // Approval-minted rules + the request store previously lived
    // ONLY in memory: a hub restart in ENFORCE mode returned every
    // approved application to default-deny and orphaned the RMM-12
    // work items pointing at vanished pending requests.

    private sealed record StoreDto(List<AppAccessRequest> Requests, List<AppRule> Rules);

    public string ExportJson()
    {
        lock (_gate)
            return HubPersistence.Wrap("acp-app-control-requests-v1",
                JsonSerializer.Serialize(new StoreDto(
                    _byId.Values.OrderBy(r => r.CreatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal).ToList(),
                    _rulesById.Values.OrderBy(r => r.Id, StringComparer.Ordinal).ToList())));
    }

    public int ImportJson(string json) => ImportJson(json, DateTimeOffset.UtcNow);

    /// <summary>Restore requests + approval rules. Every entry is
    /// re-admitted: a request restores only when its identity
    /// validates, its id is admissible, its state is a known state
    /// and its (device, id) key does not already stand; a rule
    /// restores only when AppRule.Validate(now) passes (which
    /// includes the approval-expiry check — an approval that
    /// expired while persisted is dead, never resurrected).
    /// Indexes are rebuilt from the restored requests. Returns the
    /// number of entries (requests + rules) restored.</summary>
    public int ImportJson(string json, DateTimeOffset now)
    {
        var payload = HubPersistence.Unwrap(json, "acp-app-control-requests-v1");
        if (payload is null) return 0;
        StoreDto? dto;
        try { dto = JsonSerializer.Deserialize<StoreDto>(payload); } catch { return 0; }
        if (dto is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var r in dto.Requests ?? new List<AppAccessRequest>())
            {
                if (r is null || r.Identity is null) continue;
                if (!AppRequestIds.IsValid(r.Id)) continue;
                if (r.Identity.Validate() is not null) continue;
                if (r.State is not (AppRequestStates.Pending or AppRequestStates.Approved or AppRequestStates.Denied)) continue;
                if (string.IsNullOrWhiteSpace(r.DeviceId) || string.IsNullOrWhiteSpace(r.Requester)) continue;
                var key = KeyFor(r.DeviceId, r.Id);
                if (_byId.ContainsKey(key)) continue;
                _byId[key] = r;
                IndexAdd(r.Id, key);
                restored++;
            }
            foreach (var rule in dto.Rules ?? new List<AppRule>())
            {
                if (rule is null) continue;
                if (rule.Validate(now) is not null) continue;
                if (rule.IsExpired(now)) continue;
                if (_rulesById.ContainsKey(rule.Id)) continue;
                _rulesById[rule.Id] = rule;
                restored++;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

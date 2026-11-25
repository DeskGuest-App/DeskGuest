using Acp.Shared.ManagementPolicy;

namespace Acp.Shared.BrowserPolicy;

// =====================================================================
// RMM-23 (item 2) — Browser hardening policy: the CONTROL half of
// browser management.
//
// SCOPE BOUNDARY (hard, from the register §5 exclusion): browser
// HISTORY visibility is class-(c) EXCLUDED — monitoring a person's
// reading is incompatible with ACP's consent/presence law. This
// file therefore contains NO history surface at all: no type, field
// or method reads, stores or names browsing history, URLs visited,
// or visit timestamps. What ships is control only:
//   * extension INVENTORY per device (browser extensions as
//     RMM-04-style device facts: id + name + version + publisher —
//     the real identity policy binds);
//   * allow / block / DEFAULT-DENY policy for extensions,
//     delivered as RMM-07 policy content;
//   * browser SETTINGS policy (a closed key set), also RMM-07
//     content.
// Enforcement rides the OS/browser policy mechanisms as HOST
// WIRING: this file is model + policy + inventory + evaluation;
// the applier is an interface with fakes, and the honest
// unavailable applier reports "not applied" rather than pretending.
//
// IDENTITY RULE (the destruction pass's home ground): policy binds
// the extension's REAL identity. A block matches by id OR by
// normalized name OR by publisher — an extension blocked by name
// that reappears under a NEW id is still blocked, because the
// inventory carries name+version+publisher, not just an id an
// author can regenerate. An allow matches by id ONLY (precise:
// allowing is the widening act, so it names exactly one extension
// build identity). Inventory facts missing name or version are
// REFUSED — a fact too thin to bind policy to is not a fact.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-23 item 2. D38 F9:
/// browser hardening has its OWN seeded toggle
/// (rmm.browser_hardening.enabled, default ON) — it no longer
/// rides the vendor-pass kill switch, so turning vendor access
/// off during a vendor incident does not also blind browser
/// inventory/evaluation/enforcement, and enabling browser
/// hardening does not require vendor passes to be on. The keys
/// below are its policy CONTENT.</summary>
public static class BrowserPolicyKeys
{
    public const string FeatureEnabled = "rmm.browser_hardening.enabled";
    /// <summary>"default_deny" | "default_allow". Default is
    /// default_deny: an unlisted extension is denied unless policy
    /// says otherwise.</summary>
    public const string ExtensionMode = "rmm.browser.extension_mode";
    /// <summary>Comma list of extension ids explicitly allowed.</summary>
    public const string AllowIds = "rmm.browser.allow_ids";
    /// <summary>Comma list of extension ids explicitly blocked.</summary>
    public const string BlockIds = "rmm.browser.block_ids";
    /// <summary>Comma list of extension NAMES blocked (normalized
    /// compare) — the anti-relabel rule: a blocked extension under
    /// a new id still matches its name.</summary>
    public const string BlockNames = "rmm.browser.block_names";
    /// <summary>Comma list of publishers blocked wholesale.</summary>
    public const string BlockPublishers = "rmm.browser.block_publishers";
    /// <summary>Prefix for browser settings policy values:
    /// rmm.browser.settings.&lt;key&gt; = value.</summary>
    public const string SettingsPrefix = "rmm.browser.settings.";
    public static string SettingKey(string key) => SettingsPrefix + key;
}

public static class BrowserModes
{
    public const string DefaultDeny = "default_deny";
    public const string DefaultAllow = "default_allow";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { DefaultDeny, DefaultAllow };
}

/// <summary>The closed set of browsers inventory can name. An
/// unknown browser refuses — a fact from an unnamed browser cannot
/// be bound to that browser's policy mechanism.</summary>
public static class Browsers
{
    public const string Chrome = "chrome";
    public const string Edge = "edge";
    public const string Firefox = "firefox";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Chrome, Edge, Firefox };
    public static string? Normalize(string? browser)
    {
        var b = (browser ?? "").Trim().ToLowerInvariant();
        return All.Contains(b) ? b : null;
    }
}

/// <summary>The closed set of browser settings policy may govern.
/// A policy document naming a setting outside this set is dropped
/// AND named by the resolver (a settings typo must not silently
/// widen or narrow hardening); the consent floor is not here and
/// can never be a browser setting.</summary>
public static class BrowserSettingKeys
{
    public const string PasswordManagerEnabled = "password_manager_enabled";
    public const string AutofillEnabled = "autofill_enabled";
    public const string ThirdPartyCookies = "third_party_cookies"; // block | allow
    public const string SafeBrowsing = "safe_browsing";             // enhanced | standard | off(policy may not set off — see resolver)
    public const string DeveloperMode = "developer_mode";
    public const string IncognitoAllowed = "incognito_allowed";
    public const string ExtensionDeveloperMode = "extension_developer_mode";
    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        PasswordManagerEnabled, AutofillEnabled, ThirdPartyCookies, SafeBrowsing,
        DeveloperMode, IncognitoAllowed, ExtensionDeveloperMode,
    };

    /// <summary>D38 F11: the closed VALUE set for each setting.
    /// Settings values are validated against this in the resolver —
    /// a value outside the set is dropped AND named, never passed
    /// through into an enforcement plan. (Before this, only the
    /// exact string "off" was refused for safe_browsing, so
    /// "disabled"/"none"/"false"/"0" sailed into the plan, and
    /// every other key took any value at all.)</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> AllowedValues =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            [PasswordManagerEnabled] = new HashSet<string> { "true", "false" },
            [AutofillEnabled] = new HashSet<string> { "true", "false" },
            [ThirdPartyCookies] = new HashSet<string> { "block", "allow" },
            [SafeBrowsing] = new HashSet<string> { "enhanced", "standard", "off" },
            [DeveloperMode] = new HashSet<string> { "true", "false" },
            [IncognitoAllowed] = new HashSet<string> { "true", "false" },
            [ExtensionDeveloperMode] = new HashSet<string> { "true", "false" },
        };
}

/// <summary>D38 F10: identity normalization for extension names
/// and publishers. Policy binds the NORMALIZED form on BOTH sides
/// (policy sets are normalized at resolve time; facts normalize
/// here), so trivial relabels cannot slip a block: surrounding and
/// repeated internal whitespace collapses, zero-width/format
/// characters are stripped, dash variants unify to '-', and common
/// Cyrillic/Greek homoglyphs fold to their Latin lookalikes.
/// Name/publisher remain author-controlled metadata — this raises
/// the relabel cost, it does not make metadata trustworthy (the
/// id/publisher facts and default_deny remain the hard walls).</summary>
public static class BrowserIdentityNormalization
{
    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c',
        ['х'] = 'x', ['у'] = 'y', ['і'] = 'i', ['ѕ'] = 's', ['һ'] = 'h',
        ['ο'] = 'o', ['α'] = 'a', ['ε'] = 'e', ['ρ'] = 'p', ['τ'] = 't',
        ['ν'] = 'v', ['κ'] = 'k', ['μ'] = 'u',
    };

    public static string Normalize(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new System.Text.StringBuilder(value.Length);
        var lastWasSpace = true; // also trims leading whitespace
        foreach (var raw in value)
        {
            var c = raw;
            if (c is '​' or '‌' or '‍' or '﻿' or '­') continue; // zero-width / format
            // D38 F10 (fix-lane strengthening): every dash variant
            // AND the ASCII hyphen fold to a word SEPARATOR, so
            // "Evil-Tool" normalizes to the same form as
            // "Evil Tool" — a separator swap is the cheapest
            // relabel of all and must not slip a name block.
            if (c is '-' or '‐' or '‑' or '‒' or '–' or '—' or '−') c = ' ';
            if (Homoglyphs.TryGetValue(char.ToLowerInvariant(c), out var latin) &&
                !char.IsAsciiLetter(c)) c = latin;
            if (char.IsWhiteSpace(c))
            {
                if (!lastWasSpace) { sb.Append(' '); lastWasSpace = true; }
                continue;
            }
            sb.Append(c);
            lastWasSpace = false;
        }
        if (sb.Length > 0 && sb[^1] == ' ') sb.Length--; // trailing
        return sb.ToString();
    }
}

/// <summary>Named bounds for browser inventory facts.</summary>
public static class BrowserInventoryLimits
{
    public const int MaxExtensionsPerBrowser = 512;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    public const int MaxVersionLength = 64;
    public const int MaxPublisherLength = 256;
}

/// <summary>One browser extension as an inventory fact (the RMM-04
/// shape: a device fact the hub stores and policy binds). Identity
/// is (Browser, ExtensionId); Name + Version + Publisher are the
/// anti-relabel surface — policy can bind any of them.</summary>
public sealed record BrowserExtensionFact(
    string DeviceId,
    string Browser,
    string ExtensionId,
    string Name,
    string Version,
    string? Publisher,
    bool Enabled,
    string? Source,
    DateTimeOffset CollectedUtc)
{
    /// <summary>The normalized name policy compares against
    /// (D38 F10 normalization, case-insensitive by comparer at
    /// match time).</summary>
    public string NormalizedName => BrowserIdentityNormalization.Normalize(Name);
    /// <summary>The normalized publisher policy compares against.</summary>
    public string NormalizedPublisher => BrowserIdentityNormalization.Normalize(Publisher);

    /// <summary>Admission validation. Null when admissible; a fact
    /// missing its id, name or version refuses — policy binds the
    /// real identity, and a fact too thin to bind is refused rather
    /// than inventoried as unbindable.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(DeviceId)) return "extension fact needs a device id — refused";
        if (Browsers.Normalize(Browser) is null) return $"extension fact names unknown browser '{Browser}' — refused";
        if (string.IsNullOrWhiteSpace(ExtensionId) || ExtensionId.Length > BrowserInventoryLimits.MaxIdLength)
            return "extension fact needs an extension id within bounds — refused";
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > BrowserInventoryLimits.MaxNameLength)
            return $"extension '{ExtensionId}' carries no name — refused (policy binds id+name+version; a nameless fact cannot be bound and is not inventoried)";
        if (string.IsNullOrWhiteSpace(Version) || Version.Length > BrowserInventoryLimits.MaxVersionLength)
            return $"extension '{ExtensionId}' carries no version — refused (policy binds id+name+version; a versionless fact cannot be bound and is not inventoried)";
        if (Publisher is { Length: > BrowserInventoryLimits.MaxPublisherLength })
            return $"extension '{ExtensionId}' publisher over bounds — refused";
        return null;
    }
}

/// <summary>The per-device browser inventory store: the latest
/// snapshot per (device, browser). A report REPLACES that browser's
/// snapshot wholesale (inventory is a current-state fact, not an
/// event stream — a vanished extension leaves the snapshot, and
/// the evaluation that follows sees its absence). Invalid facts
/// are dropped AND counted, never silently inventoried.</summary>
public sealed class BrowserInventoryStore
{
    private readonly Dictionary<string, List<BrowserExtensionFact>> _byDeviceBrowser = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private static string Key(string deviceId, string browser) => $"{deviceId}|{browser}";

    public (int Accepted, IReadOnlyList<string> Refusals) Report(
        string deviceId, string browser, IEnumerable<BrowserExtensionFact> facts, DateTimeOffset now)
    {
        var normalizedBrowser = Browsers.Normalize(browser);
        if (normalizedBrowser is null)
            return (0, new[] { $"unknown browser '{browser}' — whole report refused" });
        var refusals = new List<string>();
        var accepted = new List<BrowserExtensionFact>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fact in facts ?? Array.Empty<BrowserExtensionFact>())
        {
            if (fact is null) { refusals.Add("null extension fact — dropped"); continue; }
            if (!string.Equals(fact.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            { refusals.Add($"extension '{fact.ExtensionId}' names device '{fact.DeviceId}' inside a report for '{deviceId}' — dropped (a report speaks for its own device only)"); continue; }
            if (Browsers.Normalize(fact.Browser) != normalizedBrowser)
            { refusals.Add($"extension '{fact.ExtensionId}' names browser '{fact.Browser}' inside a '{normalizedBrowser}' report — dropped"); continue; }
            if (fact.Validate() is { } invalid) { refusals.Add(invalid); continue; }
            if (!seen.Add(fact.ExtensionId)) { refusals.Add($"duplicate extension id '{fact.ExtensionId}' in one report — later copy dropped"); continue; }
            accepted.Add(fact with { Browser = normalizedBrowser, CollectedUtc = now });
            // D38 F12: the cap is enforced DURING enumeration, not
            // after it — a hostile or broken collector streaming an
            // unbounded fact sequence is cut off at the cap instead
            // of being fully materialized first.
            if (accepted.Count > BrowserInventoryLimits.MaxExtensionsPerBrowser)
                return (0, new[] { $"report carries more than the cap {BrowserInventoryLimits.MaxExtensionsPerBrowser} extensions — whole report refused (enumeration stopped at the cap)" });
        }
        lock (_gate) _byDeviceBrowser[Key(deviceId, normalizedBrowser)] = accepted;
        return (accepted.Count, refusals);
    }

    public IReadOnlyList<BrowserExtensionFact> FactsFor(string deviceId, string? browser = null)
    {
        lock (_gate)
        {
            var result = new List<BrowserExtensionFact>();
            foreach (var (key, facts) in _byDeviceBrowser)
            {
                var parts = key.Split('|');
                if (!string.Equals(parts[0], deviceId, StringComparison.OrdinalIgnoreCase)) continue;
                if (browser is not null && Browsers.Normalize(browser) is { } b &&
                    !string.Equals(parts[1], b, StringComparison.OrdinalIgnoreCase)) continue;
                result.AddRange(facts);
            }
            return result.OrderBy(f => f.Browser, StringComparer.Ordinal)
                .ThenBy(f => f.ExtensionId, StringComparer.Ordinal).ToList();
        }
    }
}

/// <summary>The resolved browser policy for one device: mode,
/// allow/block identity sets, settings, and every drop/clamp the
/// resolver made, NAMED in Notes (a policy typo is surfaced, never
/// silently applied).</summary>
public sealed record ResolvedBrowserPolicy(
    string Mode,
    IReadOnlySet<string> AllowIds,
    IReadOnlySet<string> BlockIds,
    IReadOnlySet<string> BlockNames,
    IReadOnlySet<string> BlockPublishers,
    IReadOnlyDictionary<string, string> Settings,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public static class BrowserPolicyResolver
{
    private static HashSet<string> CsvSet(EffectivePolicy eff, string key, bool normalizeIdentity = false)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (eff.Get(key) is { } s && !string.IsNullOrWhiteSpace(s.Value))
            foreach (var part in s.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                set.Add(normalizeIdentity ? BrowserIdentityNormalization.Normalize(part) : part);
        return set;
    }

    public static ResolvedBrowserPolicy Resolve(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var eff = engine.ComputeEffective(facts);
        var notes = new List<string>();

        var mode = BrowserModes.DefaultDeny;
        if (eff.Get(BrowserPolicyKeys.ExtensionMode) is { } m)
        {
            var candidate = m.Value.Trim().ToLowerInvariant();
            if (BrowserModes.All.Contains(candidate)) mode = candidate;
            else notes.Add($"extension mode '{m.Value}' is not a known mode — default_deny applies (an unparsable mode never widens)");
        }

        var settings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, setting) in eff.Settings)
        {
            if (!key.StartsWith(BrowserPolicyKeys.SettingsPrefix, StringComparison.Ordinal)) continue;
            var settingKey = key[BrowserPolicyKeys.SettingsPrefix.Length..];
            if (!BrowserSettingKeys.All.Contains(settingKey))
            {
                notes.Add($"browser setting '{settingKey}' is not in the closed settings set — dropped (named, never silently applied)");
                continue;
            }
            // Hardening floor inside settings policy: safe_browsing
            // may be raised by policy but never turned OFF by it —
            // a policy that disarms the browser's own protection is
            // refused by name and the setting is dropped.
            if (settingKey == BrowserSettingKeys.SafeBrowsing &&
                string.Equals(setting.Value.Trim(), "off", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add("browser setting 'safe_browsing=off' refused — policy may raise safe browsing but never disable it (dropped; the device's current setting stands)");
                continue;
            }
            // D38 F11: closed VALUE sets. Synonyms for off
            // ("disabled", "none", "false", "0") and every other
            // out-of-set value are dropped AND named — they never
            // reach an enforcement plan.
            var value = setting.Value.Trim().ToLowerInvariant();
            if (!BrowserSettingKeys.AllowedValues[settingKey].Contains(value))
            {
                notes.Add($"browser setting '{settingKey}={setting.Value}' is not an allowed value for that setting (allowed: {string.Join("|", BrowserSettingKeys.AllowedValues[settingKey].OrderBy(x => x, StringComparer.Ordinal))}) — dropped (named, never applied)");
                continue;
            }
            settings[settingKey] = value;
        }

        return new ResolvedBrowserPolicy(
            mode,
            CsvSet(eff, BrowserPolicyKeys.AllowIds),
            CsvSet(eff, BrowserPolicyKeys.BlockIds),
            CsvSet(eff, BrowserPolicyKeys.BlockNames, normalizeIdentity: true),
            CsvSet(eff, BrowserPolicyKeys.BlockPublishers, normalizeIdentity: true),
            settings, notes);
    }
}

public static class ExtensionDispositions
{
    public const string Allowed = "allowed";
    public const string Blocked = "blocked";
    public const string DeniedByDefault = "denied_by_default";
}

/// <summary>One extension's verdict under a resolved policy, with
/// the rule that decided it named — an unexplained verdict is not
/// an auditable one.</summary>
public sealed record ExtensionDecision(
    BrowserExtensionFact Fact, string Disposition, string MatchedRule, string Reason);

/// <summary>The pure evaluator. Precedence: BLOCK beats ALLOW
/// beats default — a blocked identity is blocked even if also
/// allow-listed (the conflict resolves to the safer side, and the
/// decision names the conflict). Block matches by id, name or
/// publisher; allow matches by id only.</summary>
public static class BrowserPolicyEvaluator
{
    public static ExtensionDecision Evaluate(BrowserExtensionFact fact, ResolvedBrowserPolicy policy)
    {
        string? blockRule = null;
        if (policy.BlockIds.Contains(fact.ExtensionId)) blockRule = $"block_ids:{fact.ExtensionId}";
        else if (policy.BlockNames.Contains(fact.NormalizedName)) blockRule = $"block_names:{fact.NormalizedName}";
        else if (fact.Publisher is not null && policy.BlockPublishers.Contains(fact.NormalizedPublisher))
            blockRule = $"block_publishers:{fact.NormalizedPublisher}";

        var allowedById = policy.AllowIds.Contains(fact.ExtensionId);
        if (blockRule is not null)
        {
            var conflict = allowedById ? " (the id is ALSO allow-listed — block wins; the conflict is named, never silently resolved)" : "";
            return new ExtensionDecision(fact, ExtensionDispositions.Blocked, blockRule,
                $"extension '{fact.Name}' ({fact.ExtensionId} v{fact.Version}) blocked by {blockRule}{conflict}");
        }
        if (allowedById)
            return new ExtensionDecision(fact, ExtensionDispositions.Allowed, $"allow_ids:{fact.ExtensionId}",
                $"extension '{fact.Name}' ({fact.ExtensionId} v{fact.Version}) allowed by allow_ids");
        if (policy.Mode == BrowserModes.DefaultDeny)
            return new ExtensionDecision(fact, ExtensionDispositions.DeniedByDefault, "mode:default_deny",
                $"extension '{fact.Name}' ({fact.ExtensionId} v{fact.Version}) is not allow-listed and the mode is default_deny — denied by default");
        return new ExtensionDecision(fact, ExtensionDispositions.Allowed, "mode:default_allow",
            $"extension '{fact.Name}' ({fact.ExtensionId} v{fact.Version}) allowed by default_allow mode (not blocked)");
    }

    public static IReadOnlyList<ExtensionDecision> EvaluateAll(
        IEnumerable<BrowserExtensionFact> facts, ResolvedBrowserPolicy policy) =>
        facts.Select(f => Evaluate(f, policy)).ToList();
}

// ---- enforcement seam (host wiring) ---------------------------------

/// <summary>One enforcement instruction for the OS/browser policy
/// mechanism: which extension, which disposition, which browser
/// settings. The applier translates this into the platform's
/// policy surface (Chrome/Edge ExtensionInstallForcelist +
/// ExtensionInstallBlocklist, Firefox policies.json, …) — that
/// translation is host wiring behind this interface.</summary>
public sealed record BrowserEnforcementPlan(
    string DeviceId, IReadOnlyList<ExtensionDecision> Decisions,
    IReadOnlyDictionary<string, string> Settings, DateTimeOffset PlannedUtc);

public sealed record BrowserApplyResult(bool Applied, string Detail);

/// <summary>The enforcement applier seam. Implementations must be
/// honest: an applier that cannot write OS/browser policy reports
/// Applied=false with the reason — a plan is never reported as
/// enforced because it was computed.</summary>
public interface IBrowserPolicyApplier
{
    BrowserApplyResult Apply(BrowserEnforcementPlan plan);
}

/// <summary>The honest placeholder where no OS/browser policy
/// writer is wired: every apply reports NOT applied, by name. The
/// inventory + policy + evaluation layers are fully real; the
/// last-mile writer is a named remainder, never a silent success.</summary>
public sealed class UnavailableBrowserPolicyApplier : IBrowserPolicyApplier
{
    public BrowserApplyResult Apply(BrowserEnforcementPlan plan) =>
        new(false, $"no OS/browser policy writer is wired on this host — plan for device '{plan.DeviceId}' ({plan.Decisions.Count} extension decisions, {plan.Settings.Count} settings) was computed but NOT applied (named remainder: host wiring)");
}

/// <summary>Test double: records every plan it was handed and
/// reports applied (the seam's contract, exercised).</summary>
public sealed class RecordingBrowserPolicyApplier : IBrowserPolicyApplier
{
    public List<BrowserEnforcementPlan> Plans { get; } = new();
    public BrowserApplyResult Apply(BrowserEnforcementPlan plan)
    {
        Plans.Add(plan);
        return new BrowserApplyResult(true, $"applied {plan.Decisions.Count} decisions to device {plan.DeviceId}");
    }
}

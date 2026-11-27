using System.Text.Json;
using DeskGuest.Shared.Dlp;
using DeskGuest.Shared.ManagementPolicy;

namespace DeskGuest.Shared.Policy;

// =====================================================================
// U1 — Clipboard transfer direction policy + sensitive-item skip +
// per-read indicator (UNION BUILD lane U1).
//
// Until this lane the clipboard tools existed with a single gate
// class (clipboard_read, on the GET only) and no direction control
// at all: any paired agent that passed the gate could move clipboard
// content in BOTH directions, and a password-manager clip was
// returned exactly like any other text. This file is the policy
// layer:
//
//   * DIRECTION is a TOTAL POLICY CONTROL setting (RMM-07 pattern,
//     same as U4's session budgets): the feature toggle is
//     registered in FeatureToggleRegistry ("rmm.clipboard_policy
//     .enabled", default ON) and the direction itself is the plain
//     settings key "clipboard.direction" an admitted management-
//     policy document may set: both | host_to_agent | agent_to_host
//     | off. Unset → "both" (the pre-U1 behaviour). An unparsable
//     value is IGNORED (the default stands) — a malformed policy
//     value can neither widen nor break the clipboard by accident.
//   * SENSITIVE SKIP is the plain settings key
//     "clipboard.sensitive_skip" (default ON): clipboard_get runs
//     the closed built-in DLP classifier set over the clip text at
//     the real clipboard path (DesktopEngine / AccessToolHost) and,
//     on a hit, returns a NAMED refusal — never the content. The
//     classifiers are the inspectable DlpClassifiers.BuiltIns()
//     (payment_card / national_id / credential_secret); no opaque
//     classifier is involved.
//   * Enforcement is layered, like the rest of DeskGuest: the MCP choke
//     point (McpHandler) denies a direction-forbidden call before
//     it executes, and the desktop engine enforces the same policy
//     again at the clipboard itself (its copy is pushed by the Core
//     over the authenticated IPC channel), so paths that reach the
//     engine without the choke point (batch steps over the channel)
//     meet the same wall. The consent floor is untouched: STOP,
//     scopes and gate classes are all evaluated BEFORE this layer
//     and outrank it.
//   * PER-READ INDICATOR: a successful read publishes a
//     "clipboard_read" agent event (origin-scoped to the reading
//     pairing), sets the presence narration line, and the engine
//     narrates the read on the banner at the moment it happens.
//     The event and the audit carry the character COUNT only —
//     never the content.
// =====================================================================

/// <summary>Which way clipboard content may move between the host
/// and an agent. HostToAgent = the agent may READ the host's
/// clipboard (clipboard_get) but not write it; AgentToHost = the
/// agent may SET the clipboard (clipboard_set) but not read it;
/// Off = neither; Both = both (the pre-U1 behaviour).</summary>
public enum ClipboardDirection
{
    Both,
    HostToAgent,
    AgentToHost,
    Off,
}

/// <summary>The TOTAL POLICY CONTROL keys for the clipboard layer.</summary>
public static class ClipboardPolicyKeys
{
    /// <summary>Feature toggle registered in FeatureToggleRegistry
    /// (directive U1, default ON). OFF disables this whole layer:
    /// direction enforcement and the sensitive skip stand down and
    /// the clipboard behaves exactly as it did before U1.</summary>
    public const string FeatureToggle = "rmm.clipboard_policy.enabled";

    /// <summary>The direction setting: both | host_to_agent |
    /// agent_to_host | off. Unset/unparsable → both.</summary>
    public const string Direction = "clipboard.direction";

    /// <summary>The sensitive-skip setting: true | false.
    /// Unset/unparsable → true (skip is the shipped default).</summary>
    public const string SensitiveSkip = "clipboard.sensitive_skip";
}

/// <summary>The resolved clipboard policy for this device: one
/// direction + the sensitive-skip switch. Immutable; resolved per
/// call from Effective Policy so an admitted policy document takes
/// effect without a restart.</summary>
public sealed record ClipboardPolicy(ClipboardDirection Direction, bool SensitiveSkip)
{
    /// <summary>The named defaults: both directions, sensitive skip
    /// ON. This is what an unset policy means.</summary>
    public static readonly ClipboardPolicy Default = new(ClipboardDirection.Both, true);

    /// <summary>The pre-U1 behaviour, used as the engine's standing
    /// instruction when the policy layer is toggled OFF: both
    /// directions, no skip. (The choke point simply does not deny;
    /// the engine copy must match or the two walls would disagree.)</summary>
    public static readonly ClipboardPolicy Legacy = new(ClipboardDirection.Both, false);

    public bool AllowsRead => Direction is ClipboardDirection.Both or ClipboardDirection.HostToAgent;
    public bool AllowsWrite => Direction is ClipboardDirection.Both or ClipboardDirection.AgentToHost;

    /// <summary>The settings-string form of a direction.</summary>
    public static string Name(ClipboardDirection direction) => direction switch
    {
        ClipboardDirection.Both => "both",
        ClipboardDirection.HostToAgent => "host_to_agent",
        ClipboardDirection.AgentToHost => "agent_to_host",
        ClipboardDirection.Off => "off",
        _ => "both",
    };

    public string DirectionName => Name(Direction);

    /// <summary>Parse a settings value; null when the value names no
    /// direction (the caller then keeps the default — a malformed
    /// policy value never widens or narrows anything by accident).</summary>
    public static ClipboardDirection? ParseDirection(string? raw) =>
        (raw ?? "").Trim().ToLowerInvariant() switch
        {
            "both" => ClipboardDirection.Both,
            "host_to_agent" => ClipboardDirection.HostToAgent,
            "agent_to_host" => ClipboardDirection.AgentToHost,
            "off" => ClipboardDirection.Off,
            _ => null,
        };

    /// <summary>Resolve the policy from an Effective Policy: each
    /// key overrides its named default; unparsable values are
    /// ignored (the default stands), same rule as U4's caps.</summary>
    public static ClipboardPolicy FromEffective(EffectivePolicy? effective)
    {
        if (effective is null) return Default;
        var direction = Default.Direction;
        if (effective.Get(ClipboardPolicyKeys.Direction) is { } d &&
            ParseDirection(d.Value) is { } parsed)
            direction = parsed;
        var skip = Default.SensitiveSkip;
        if (effective.Get(ClipboardPolicyKeys.SensitiveSkip) is { } s &&
            bool.TryParse(s.Value.Trim(), out var b))
            skip = b;
        return new ClipboardPolicy(direction, skip);
    }

    /// <summary>The named refusal for a direction-forbidden tool, or
    /// null when the direction permits it. Non-clipboard tools are
    /// never this layer's business.</summary>
    public string? DenyReasonFor(string tool) => tool switch
    {
        "clipboard_get" when !AllowsRead =>
            $"clipboard_direction: policy direction is '{DirectionName}' — clipboard_get moves clipboard content host → agent, which this policy does not permit ({ClipboardPolicyKeys.Direction})",
        "clipboard_set" when !AllowsWrite =>
            $"clipboard_direction: policy direction is '{DirectionName}' — clipboard_set moves clipboard content agent → host, which this policy does not permit ({ClipboardPolicyKeys.Direction})",
        _ => null,
    };

    /// <summary>The IPC form pushed Core → Session Agent over the
    /// authenticated channel (IpcKinds.ClipboardPolicy).</summary>
    public string ToIpcJson() => JsonSerializer.Serialize(new
    {
        direction = DirectionName,
        sensitiveSkip = SensitiveSkip,
    });

    /// <summary>Parse the IPC form. A malformed push yields null and
    /// the agent keeps its standing instruction — a garbled policy
    /// must never silently change what the engine permits.</summary>
    public static ClipboardPolicy? FromIpcJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var direction = root.TryGetProperty("direction", out var d) && d.ValueKind == JsonValueKind.String
                ? ParseDirection(d.GetString()) : null;
            if (direction is null) return null;
            var skip = Default.SensitiveSkip;
            if (root.TryGetProperty("sensitiveSkip", out var s) &&
                (s.ValueKind == JsonValueKind.True || s.ValueKind == JsonValueKind.False))
                skip = s.GetBoolean();
            return new ClipboardPolicy(direction.Value, skip);
        }
        catch (JsonException) { return null; }
    }
}

/// <summary>The sensitive-item classifier for clipboard reads: the
/// closed built-in DLP classifier set, run over clip text. Returns
/// the id of the first classifier that hits, or null when the text
/// is clean. Classifier errors refuse nothing here (a throwing
/// classifier is skipped, exactly as the DLP resolver treats its
/// own set) — the direction wall and the gates stand regardless.</summary>
public static class ClipboardSensitivity
{
    public static string? SensitiveClassifierFor(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        foreach (var classifier in DlpClassifiers.BuiltIns())
        {
            IReadOnlyList<DlpMatch> hits;
            try { hits = classifier.Find(text); }
            catch { continue; }
            if (hits.Count > 0) return classifier.Id;
        }
        return null;
    }

    /// <summary>The named refusal a sensitive read returns. It names
    /// the classifier class — never the matched content.</summary>
    public static string SensitiveRefusal(string classifierId) =>
        $"clipboard_sensitive: the clipboard holds a sensitive-class item ({classifierId}) — not read; the content was not returned ({ClipboardPolicyKeys.SensitiveSkip})";
}

/// <summary>The gate the desktop engine applies at the real
/// clipboard path, so the decision logic is identical (and testable)
/// on both sides of the IPC channel. The engine consults this AFTER
/// the Core's choke point has already approved the call — it is the
/// second wall, for paths that reach the engine directly.</summary>
public static class ClipboardGate
{
    /// <summary>Verdict for a read of <paramref name="clipText"/>
    /// under <paramref name="policy"/>: (true, null) = hand the text
    /// over; (false, refusal) = return the named refusal instead of
    /// the content. Direction is checked before content, and the
    /// sensitive check runs only when the direction permits the
    /// read at all.</summary>
    public static (bool Ok, string? Refusal) CheckRead(ClipboardPolicy policy, string clipText)
    {
        if (policy.DenyReasonFor("clipboard_get") is { } denied) return (false, denied);
        if (policy.SensitiveSkip && ClipboardSensitivity.SensitiveClassifierFor(clipText) is { } id)
            return (false, ClipboardSensitivity.SensitiveRefusal(id));
        return (true, null);
    }

    /// <summary>Verdict for a write under <paramref name="policy"/>.</summary>
    public static (bool Ok, string? Refusal) CheckWrite(ClipboardPolicy policy) =>
        policy.DenyReasonFor("clipboard_set") is { } denied ? (false, denied) : (true, null);
}

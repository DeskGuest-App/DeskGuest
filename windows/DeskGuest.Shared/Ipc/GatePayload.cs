using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Policy;

namespace DeskGuest.Shared.Ipc;

/// <summary>
/// W119 (S12, REVISION-DRAFT §2.1 — MINIMUM-LAW-CORRECTION): the
/// gate's payload law. The sheet shows the EXACT payload as it
/// will be submitted (OI-12: these are the caller's argument
/// bytes, never re-encoded or trimmed), rendered per gate class:
/// plain lines a person reads, technical lines that name the
/// exact artefacts, and — for the sending class — the draft
/// itself in a quoted block marked «DRAFT · NOT SENT».
///
/// Class coverage is enumerated, never assumed. The classes the
/// Core can actually raise are: every PolicyEngine.GatedClasses
/// member (the policy leg denies them "gated:&lt;class&gt;" and
/// McpHandler raises the gate on exactly that deny), plus every
/// GateClass a tool descriptor declares (AdminModules /
/// FileExtraModules / SystemInfoModules / SafeMode /
/// WindowsAdminModules / EngineModules / OwnerConsole):
/// registry_write, credential_inject, takeover_handback. Each of
/// those classes has a named rendering below. A class outside
/// the enumeration still renders — every payload field, listed —
/// but is FLAGGED (IsGenericFallback) so the gap is named on the
/// sheet and in the suite, never silent.
///
/// Credential law (SPEC §7.4): typing into a credential field is
/// refused outright — no approval can enable it — and the
/// credential_inject class is refused at the gate the same way:
/// the sheet states the refusal and offers NO exits. Pre-approval
/// ("always allow for this pairing") exists only as the per-class
/// setting of SPEC §7.4, granted from the host window's Approval
/// Gates panel — the sheet itself grants nothing standing
/// (GateSheetModel.HasSessionAllow stays false); it only names,
/// for a pre-approvable class, where that setting lives. The
/// credential class is never pre-approvable.
/// </summary>
public sealed record GatePayloadView(
    string Title,
    string AgentName,
    string GateClass,
    string Tool,
    IReadOnlyList<string> PlainLines,
    IReadOnlyList<string> TechnicalLines,
    IReadOnlyList<string> QuoteLines,
    bool ShowDraftMarker,
    bool IsRefusal,
    string? RefusalLine,
    bool PreApprovalEligible,
    bool IsGenericFallback,
    string ExactPayloadText);

public static class GatePayloadRenderer
{
    /// <summary>The credential gate class: refused outright at
    /// the gate, stated on the sheet, never pre-approvable.</summary>
    public const string CredentialClass = "credential_inject";

    /// <summary>The refusal sentence of record (SPEC §7.4).</summary>
    public const string CredentialRefusalLine =
        "Refused outright: agents never type into password, OTP or PIN fields, and no approval can enable it (SPEC §7.4).";

    /// <summary>Every gate class the Core can raise, enumerated
    /// from PolicyEngine.GatedClasses + the descriptor-declared
    /// classes. The suite pins this set against both sources, so
    /// a class added at either source without a rendering here
    /// fails the build's own evidence.</summary>
    public static readonly IReadOnlySet<string> KnownClasses = new HashSet<string>(StringComparer.Ordinal)
    {
        "payments", "sending", "deletions", "installs",
        "service_stop_non_deskguest", "shutdown", "vault_ops", "power",
        "clipboard_read", "clipboard_write",
        "registry_write", "credential_inject", "takeover_handback",
    };

    /// <summary>Per-class pre-approval (SPEC §7.4) is offered in
    /// settings for exactly the classes the host window's Approval
    /// Gates panel lists — PolicyEngine.GatedClasses. The
    /// credential class is never among them.</summary>
    public static bool PreApprovalEligible(string gateClass) =>
        gateClass != CredentialClass && PolicyEngine.GatedClasses.Contains(gateClass);

    public static GatePayloadView Render(string agentName, string gateClass, string tool, byte[] payloadBytes)
    {
        var exact = Encoding.UTF8.GetString(payloadBytes);
        var agent = string.IsNullOrWhiteSpace(agentName) ? "The agent" : agentName;
        using var doc = TryParse(exact);
        var root = doc?.RootElement;
        bool Has(string n) => root is { ValueKind: JsonValueKind.Object } r && r.TryGetProperty(n, out _);
        string? S(string n) => root is { ValueKind: JsonValueKind.Object } r
            && r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        string? Raw(string n) => root is { ValueKind: JsonValueKind.Object } r
            && r.TryGetProperty(n, out var v) ? (v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText()) : null;

        // Credential refusal: the class itself, or any payload
        // that targets a credential field (the NEVER rule's flag).
        var credentialField = root is { ValueKind: JsonValueKind.Object } cr
            && cr.TryGetProperty("target_is_credential_field", out var cf) && cf.ValueKind == JsonValueKind.True;
        if (gateClass == CredentialClass || credentialField)
        {
            return new GatePayloadView(
                Title: $"{agent} — refused",
                AgentName: agent, GateClass: gateClass, Tool: tool,
                PlainLines: new[] { CredentialRefusalLine },
                TechnicalLines: Technical(root, tool, gateClass),
                QuoteLines: Array.Empty<string>(),
                ShowDraftMarker: false, IsRefusal: true,
                RefusalLine: CredentialRefusalLine,
                PreApprovalEligible: false, IsGenericFallback: false,
                ExactPayloadText: exact);
        }

        var plain = new List<string>();
        var quote = new List<string>();
        var draft = false;
        string title;
        var known = KnownClasses.Contains(gateClass);

        switch (gateClass)
        {
            case "deletions":
            {
                var targets = CollectTargets(root, S);
                if (S("key") is { } key) // registry_delete: key (+ value name)
                    targets.Add(S("value") is { } vn ? $"{key} — value {vn}" : key);
                if (targets.Count == 0 && S("path") is { } p) targets.Add(p);
                foreach (var t in targets) plain.Add($"Delete {t}");
                if (targets.Count == 0) plain.Add($"Delete using {tool} — the exact arguments are listed below.");
                title = Title(agent, "delete", targets.Count == 1 ? targets[0] : $"{targets.Count} items", tool);
                break;
            }
            case "sending":
            {
                draft = true;
                var to = S("to") ?? S("recipient") ?? S("address") ?? "(no recipient in the payload)";
                var subject = S("subject") ?? "(no subject)";
                plain.Add($"Send a message to {to}");
                quote.Add($"To: {to}");
                quote.Add($"Subject: {subject}");
                quote.Add($"Body: {S("body") ?? S("text") ?? S("message") ?? ""}");
                if (root is { ValueKind: JsonValueKind.Object } sr
                    && sr.TryGetProperty("attachment", out var att) && att.ValueKind == JsonValueKind.Object)
                {
                    var an = att.TryGetProperty("name", out var av) ? av.GetString() : null;
                    var asz = att.TryGetProperty("size", out var sv) ? sv.GetRawText() : null;
                    var asrc = att.TryGetProperty("source", out var scv) ? scv.GetString() : null;
                    quote.Add($"Attachment: {an ?? "(unnamed)"} · {asz ?? "?"} bytes · from {asrc ?? "(source not named)"}");
                }
                else if (S("attachment") is { } attName)
                    quote.Add($"Attachment: {attName}");
                title = Title(agent, "send a message to", to, tool);
                break;
            }
            case "payments":
            {
                var amount = Raw("amount") ?? "?";
                var currency = S("currency") ?? "";
                var payee = S("payee") ?? S("to") ?? S("recipient") ?? "(payee not named)";
                plain.Add($"Pay {amount} {currency} to {payee}".Replace("  ", " "));
                if (S("description") is { } d) plain.Add(d);
                title = Title(agent, "pay", $"{amount} {currency} to {payee}".Replace("  ", " "), tool);
                break;
            }
            case "installs":
            {
                var action = S("action") ?? "install";
                var pkg = S("package_id") ?? S("package") ?? S("name") ?? "(package not named)";
                plain.Add($"{Capitalize(action)} {pkg}");
                if (S("source") is { } src) plain.Add($"From: {src}");
                plain.Add("This will change the software installed on this computer.");
                title = Title(agent, action, pkg, tool);
                break;
            }
            case "power":
            case "shutdown":
            {
                var verb = tool.Contains("reboot") || (S("action") ?? "").Contains("reboot") ? "restart this computer"
                    : tool.Contains("shutdown") || gateClass == "shutdown" ? "shut down this computer"
                    : "change this computer's power state";
                plain.Add($"{agent} will {verb}.");
                title = $"{agent} wants to {verb}";
                break;
            }
            case "service_stop_non_deskguest":
            {
                var svc = S("name") ?? S("service") ?? "(service not named)";
                plain.Add($"Stop the service {svc}");
                title = Title(agent, "stop the service", svc, tool);
                break;
            }
            case "vault_ops":
            {
                var op = S("operation") ?? S("action") ?? tool;
                plain.Add($"Use the credential vault: {op}");
                title = Title(agent, "use the credential vault", op, tool);
                break;
            }
            case "clipboard_read":
                plain.Add("Read the clipboard's current contents.");
                title = Title(agent, "read", "the clipboard", tool);
                break;
            case "clipboard_write":
                plain.Add("Replace the clipboard's contents.");
                if (S("text") is { } ct) quote.Add(ct);
                title = Title(agent, "write to", "the clipboard", tool);
                break;
            case "registry_write":
            {
                var key = S("key") ?? "(key not named)";
                var name = S("name") ?? S("value_name") ?? S("value") ?? "";
                var data = S("data") ?? S("new_value") ?? "";
                plain.Add(name.Length > 0 ? $"Set {key} — {name} to {data}" : $"Write to the registry key {key}");
                title = Title(agent, "write to the registry key", key, tool);
                break;
            }
            case "takeover_handback":
                plain.Add($"{agent} is asking for control of the desktop back.");
                title = $"{agent} asks for control back";
                break;
            default:
            {
                // Folder-open shape (the revision's first example):
                // any class whose payload names a folder/path to
                // open gets the full path in plain + technical lines.
                var folder = S("folder") ?? S("directory") ?? (tool.Contains("folder") ? S("path") : null);
                if (folder is not null)
                {
                    plain.Add($"Open the folder {folder}");
                    title = Title(agent, "open the folder", folder, tool);
                }
                else if (S("path") is { } p)
                {
                    plain.Add($"Run {tool} on {p}");
                    title = Title(agent, "run " + tool + " on", p, tool);
                }
                else
                {
                    plain.Add($"Run {tool} — the exact arguments are listed below.");
                    title = $"{agent} — {tool}";
                }
                break;
            }
        }

        return new GatePayloadView(
            Title: title, AgentName: agent, GateClass: gateClass, Tool: tool,
            PlainLines: plain,
            TechnicalLines: Technical(root, tool, gateClass),
            QuoteLines: quote,
            ShowDraftMarker: draft, IsRefusal: false, RefusalLine: null,
            PreApprovalEligible: PreApprovalEligible(gateClass),
            IsGenericFallback: !known,
            ExactPayloadText: exact);
    }

    private static string Title(string agent, string verb, string target, string tool) =>
        string.IsNullOrWhiteSpace(target) ? $"{agent} — {tool}" : $"{agent} wants to {verb} {target}";

    private static string Capitalize(string s) =>
        s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s.Substring(1);

    private static List<string> CollectTargets(JsonElement? root, Func<string, string?> s)
    {
        var list = new List<string>();
        if (root is not { ValueKind: JsonValueKind.Object } r) return list;
        foreach (var name in new[] { "paths", "files", "targets" })
            if (r.TryGetProperty(name, out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var el in arr.EnumerateArray())
                    list.Add(el.ValueKind == JsonValueKind.String ? el.GetString()! : el.GetRawText());
        if (s("path") is { } p) list.Add(p);
        if (s("file") is { } f) list.Add(f);
        return list;
    }

    /// <summary>Technical lines: the tool, the class, and every
    /// payload field exactly as named in the payload — the sheet's
    /// second, checkable rendering of the same bytes.</summary>
    private static IReadOnlyList<string> Technical(JsonElement? root, string tool, string gateClass)
    {
        var lines = new List<string> { $"tool: {tool}", $"class: {gateClass}" };
        if (root is { ValueKind: JsonValueKind.Object } r)
            foreach (var prop in r.EnumerateObject())
                lines.Add($"{prop.Name}: {(prop.Value.ValueKind == JsonValueKind.String ? prop.Value.GetString() : prop.Value.GetRawText())}");
        return lines;
    }

    private static JsonDocument? TryParse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonDocument.Parse(text); } catch (JsonException) { return null; }
    }
}

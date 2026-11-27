using System.Text.Json;
using System.Text.Json.Nodes;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>BUILD-PROGRAMME item (16) amendment (2026-11-25,
/// issue #25): the Terms acknowledgment as a standard MCP tool —
/// the same act as the deskguest/terms_acknowledge protocol
/// method, in the shape tool-surface hosts can actually send.
///
/// Why this exists: the Tested-AI battery (run 4) proved that
/// mainstream AI hosts — ChatGPT/Codex first — expose tools and
/// resource reads to the model but give it NO way to emit a
/// custom JSON-RPC method. A method-only ack is therefore a wall
/// no such host can pass, however faithfully it read the Terms.
/// This module is a thin envelope over TermsAckService, the one
/// operation behind both surfaces: same exact-match rule against
/// the currently served bundle, same store fields, same
/// audit-chain acceptance entry, same re-lock on a Terms update.
///
/// Placement in the catalog is deliberate: Observe scope (every
/// pairing preset holds it, so the tool is listed for observe
/// and full pairings alike) and SessionRequirement.Core — and
/// the choke point's session-binding leg exempts Observe tools,
/// so the ack is callable BEFORE any session exists, which is
/// the whole point: sessions stay locked until it lands.</summary>
public sealed class TermsAcknowledgeModule : IToolModule
{
    private readonly TermsAckService _ack;

    public TermsAcknowledgeModule(TermsAckService ack) => _ack = ack;

    public ToolDescriptor Descriptor { get; } = new(
        TermsBundle.AckToolName,
        "Acknowledge the DeskGuest Terms of Service for this pairing. Read the full current text at resource deskguest://terms first, then return its exact terms_version and terms_sha256. Sessions stay locked until the acknowledgment is recorded; an acknowledgment of any other version or hash is refused and the refusal is recorded.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "Core",
        InputSchemaJson: """{"type":"object","properties":{"terms_version":{"type":"string","description":"The Terms version served at deskguest://terms"},"terms_sha256":{"type":"string","description":"The SHA-256 of the exact Terms text served at deskguest://terms"}},"required":["terms_version","terms_sha256"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (_ack.Terms is null)
            return Task.FromResult(ToolResult.Unavailable("terms machinery is not wired on this host"));
        // Argument reading mirrors the protocol method exactly:
        // an absent field reads as null (and is refused as a
        // mismatch, recorded with "(none)"); a present field of
        // the wrong JSON type is an invalid-params refusal.
        string? version = null, hash = null;
        if (arguments.ValueKind == JsonValueKind.Object)
        {
            if (arguments.TryGetProperty("terms_version", out var v))
            {
                if (v.ValueKind != JsonValueKind.String)
                    return Task.FromResult(ToolResult.Error("invalid_params", "invalid params: terms_version and terms_sha256 must be strings"));
                version = v.GetString();
            }
            if (arguments.TryGetProperty("terms_sha256", out var h))
            {
                if (h.ValueKind != JsonValueKind.String)
                    return Task.FromResult(ToolResult.Error("invalid_params", "invalid params: terms_version and terms_sha256 must be strings"));
                hash = h.GetString();
            }
        }
        var result = _ack.Acknowledge(ctx.Pairing, version, hash);
        return Task.FromResult(result.Outcome switch
        {
            TermsAckOutcome.Acknowledged => ToolResult.Success(new JsonObject
            {
                ["acknowledged"] = true,
                ["terms_version"] = _ack.Terms.Version,
                ["terms_sha256"] = _ack.Terms.Sha256,
                ["acknowledged_utc"] = result.AckUtc!.Value.ToString("o")
            }.ToJsonString()),
            TermsAckOutcome.RefusedPairingInvalid =>
                ToolResult.Error("terms_ack_refused", result.RefusalMessage!),
            _ => ToolResult.Error("terms_ack_refused", result.RefusalMessage!),
        });
    }
}

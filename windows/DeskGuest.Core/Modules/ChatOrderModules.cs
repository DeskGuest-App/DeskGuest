using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>
/// W120 — S13 order proposals (FEATURES.md §8 expansion). The
/// agent side of the order card: ONE structured tool, chat_order,
/// by which a paired agent proposes an action to its owner. The
/// proposal lands in the pairing's thread as a structured action
/// card (title, exact steps from the exact argument bytes, target
/// device named, S12's three exits) and NOTHING executes until
/// the owner answers Approve on the card — the Core then runs the
/// exact bytes through the same policy choke point as a wire
/// call, with the card's approval as the one-shot gate answer.
///
/// Proposing is not acting: like chat_read/chat_post this tool
/// needs no session, grants no capability and raises no presence
/// (§8 HARD LAW). Free text never executes — chat_post carries no
/// execution path at all; an agent that describes an action in
/// prose has proposed nothing (ChatOrderModel.FromProse is null
/// by construction). Validation lives in the Core's propose
/// handler (tool exists, not a chat tool, inside the pairing's
/// access-slider grant); this module is the wire shape only, and
/// the pairing is read from the authenticated execution context —
/// never from an argument — so a proposal can only ever land in
/// the caller's own thread.
/// </summary>
public sealed class ChatOrderModule : IToolModule
{
    /// <summary>One validated proposal, handed to the Core.</summary>
    public sealed record Proposal(string PairingId, string Tool, JsonElement Arguments, string? Title, string? TargetDevice);

    /// <summary>The Core's propose handler: returns the stored
    /// order's id + status, or a refusal detail. Null = unwired
    /// (proposals refuse, never pretend).</summary>
    public Func<Proposal, (bool Ok, string Detail)>? Propose { get; set; }

    public ToolDescriptor Descriptor { get; } = new(
        ChatOrderModel.ProposeToolName,
        "Propose an action to your user as a structured order card in your Agent chat thread. " +
        "Proposing NEVER executes anything: the card shows the exact tool and arguments, names the target device, " +
        "and carries the approval gate's three exits (Approve / Deny / Deny and end session). Only the user's Approve " +
        "on the card runs it — exactly these arguments, through the device's normal policy checks. " +
        "Describing an action in a chat message does nothing; if you want to act, propose it here. " +
        "You may only propose tools within this pairing's granted access. " +
        "Chat is not a session: proposing starts nothing, grants nothing, and shows no presence.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"tool":{"type":"string","description":"The tool to run if the user approves (e.g. file_delete)."},"arguments":{"type":"object","description":"The exact arguments for that tool, as they will be submitted on approval."},"title":{"type":"string","description":"Optional short title for the card; the payload's own rendering is used when omitted."},"target_device":{"type":"string","description":"Optional name of the device the action runs on. Omit for this device. An order naming another device never runs here."}},"required":["tool","arguments"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (Propose is null)
            return Task.FromResult(ToolResult.Error("unavailable", "chat_order is unavailable: order proposals are not wired on this device."));
        string? S(string n) => arguments.ValueKind == JsonValueKind.Object &&
                               arguments.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;
        var tool = (S("tool") ?? "").Trim();
        if (tool.Length == 0)
            return Task.FromResult(ToolResult.Error("bad_arguments", "chat_order refused: 'tool' is required — name the tool the card would run."));
        if (arguments.ValueKind != JsonValueKind.Object ||
            !arguments.TryGetProperty("arguments", out var args) || args.ValueKind != JsonValueKind.Object)
            return Task.FromResult(ToolResult.Error("bad_arguments", "chat_order refused: 'arguments' must be the tool's argument object — the card shows exactly these bytes."));
        var (ok, detail) = Propose(new Proposal(ctx.Pairing.Id, tool, args.Clone(), S("title"), S("target_device")));
        return Task.FromResult(ok
            ? ToolResult.Success(JsonSerializer.Serialize(new { proposed = true, detail }))
            : ToolResult.Error("proposal_refused", $"chat_order refused: {detail}"));
    }
}

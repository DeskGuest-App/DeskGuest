using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

/// <summary>
/// W9 — Agent chat on the Windows Core MCP surface (Addendum A;
/// Android ChatToolHost parity, W8-B). The pairing's MCP channel is
/// the channel an agent already has to this device, so chat rides
/// it as two tools, authenticated by the pairing's own bearer <redacted>
/// and bound to the CALLER's pairing only — the pairing is read
/// from the execution context (the authenticated token), never
/// from an argument, so a tool can only ever touch its own
/// pairing's thread.
///
///  - chat_read: the owner→agent delivery leg. Returns this
///    pairing's thread messages after the caller's cursor plus the
///    next cursor. Delivery is pull-based: this architecture has
///    no server-initiated push leg for message bodies (the event
///    stream carries event kinds, never bodies), and the tool
///    description says so.
///  - chat_post: the agent→device leg. Appends an agent message to
///    the same thread the owner reads in the host window, and
///    emits a metadata-only event.
///
/// Chat is not a session: these tools need no capability beyond
/// the pairing itself, start nothing, and grant nothing (the
/// handler exempts them from the session/budget gates like the
/// status tools). Audit stays metadata-only: the handler writes a
/// chars/cursor summary for chat calls, never the body. Unpairing
/// ends the thread: the token dies (the call never authenticates)
/// AND the thread file is removed, so both legs refuse/empty for a
/// dead pairing.
/// </summary>
public sealed class ChatReadModule : IToolModule
{
    private readonly AgentChatStore _store;
    private readonly Func<string, bool> _pairingAlive;

    /// <summary>W120: raised after a successful read with the
    /// pairing id and the next cursor handed to the agent — the
    /// Core's queued-count truth for the thread header (owner
    /// messages beyond this cursor are still queued).</summary>
    public Action<string, long>? Read { get; set; }

    public ChatReadModule(AgentChatStore store, Func<string, bool> pairingAlive)
    {
        _store = store;
        _pairingAlive = pairingAlive;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "chat_read",
        "Read messages your user sent you in Agent chat on this PC. " +
        "Returns this pairing's thread messages after 'after_seq' (omit or 0 for all) " +
        "with their sequence numbers and the next cursor to pass next time. " +
        "Delivery is pull-based: call this to receive; nothing is pushed to you. " +
        "Chat is not a session — reading starts nothing and grants nothing.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"after_seq":{"type":"integer","description":"Return only messages after this sequence number."}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_pairingAlive(ctx.Pairing.Id))
            return Task.FromResult(ToolResult.Success("Agent chat is unavailable: this pairing has ended, so its thread is closed."));
        var afterSeq = arguments.ValueKind == JsonValueKind.Object &&
                       arguments.TryGetProperty("after_seq", out var a) && a.ValueKind == JsonValueKind.Number
            ? a.GetInt64() : 0L;
        if (afterSeq < 0)
            return Task.FromResult(ToolResult.Error("bad_arguments", "chat_read refused: after_seq cannot be negative."));
        var messages = _store.LoadAfter(ctx.Pairing.Id, afterSeq);
        var nextCursor = _store.NextCursor(ctx.Pairing.Id);
        try { Read?.Invoke(ctx.Pairing.Id, nextCursor); } catch { /* the read landed; a failed cursor note never unmakes it */ }
        var payload = JsonSerializer.Serialize(new
        {
            pairing = ctx.Pairing.Id,
            messages = messages.Select(s => new
            {
                seq = s.Seq,
                atMs = s.Message.AtMs,
                direction = s.Message.Direction,
                body = s.Message.Body,
            }).ToArray(),
            next_cursor = nextCursor,
        });
        return Task.FromResult(ToolResult.Success(payload));
    }
}

/// <summary>The agent→device leg of Agent chat (see ChatReadModule).</summary>
public sealed class ChatPostModule : IToolModule
{
    private readonly AgentChatStore _store;
    private readonly Func<string, bool> _pairingAlive;

    /// <summary>Raised after a successful post with the store's
    /// metadata-only audit event (pairing / direction / chars /
    /// time — never a body). CoreRuntime wires it to the event bus.</summary>
    public Action<AgentChatStore.ChatAuditEvent>? Posted { get; set; }

    public ChatPostModule(AgentChatStore store, Func<string, bool> pairingAlive)
    {
        _store = store;
        _pairingAlive = pairingAlive;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "chat_post",
        "Post a message to your user in Agent chat on this PC. " +
        "The message lands in the same thread the user reads in the host window. " +
        "Chat is not a session and cannot approve anything: to act, the user " +
        "still goes through the on-device approval gate.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"body":{"type":"string","description":"The message text (max 4000 characters)."}},"required":["body"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_pairingAlive(ctx.Pairing.Id))
            return Task.FromResult(ToolResult.Success("Agent chat is unavailable: this pairing has ended, so its thread is closed."));
        var body = arguments.ValueKind == JsonValueKind.Object &&
                   arguments.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String
            ? (b.GetString() ?? "").Trim() : "";
        if (body.Length == 0)
            return Task.FromResult(ToolResult.Error("bad_arguments", "chat_post refused: the message body is empty."));
        if (body.Length > AgentChatStore.MaxBodyChars)
            return Task.FromResult(ToolResult.Error("bad_arguments",
                $"chat_post refused: the message is {body.Length} characters; the limit is {AgentChatStore.MaxBodyChars}."));
        var atMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var (seq, audit) = _store.Append(ctx.Pairing.Id, AgentChatStore.DirAgent, body, atMs);
        // Metadata only — the body never enters an event/audit path.
        try { Posted?.Invoke(audit); } catch { /* the post landed; a failed event never unmakes it */ }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            posted = true,
            pairing = ctx.Pairing.Id,
            seq,
            chars = body.Length,
        })));
    }
}

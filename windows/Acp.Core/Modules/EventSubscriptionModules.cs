using System.Text.Json;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Core.Modules;

/// <summary>U2 — events_subscribe: record the CALLING pairing's
/// event-kind filter. Observe scope, so a pairing without Observe
/// can never subscribe; the filter is enforced at delivery time by
/// AgentEventBus.ShouldDeliver (kind filter + origin rule), so this
/// tool grants nothing beyond what the pairing already is. The call
/// itself passes the normal policy choke point and audit like every
/// tool call — subscribing is not an audit-evasion channel: the
/// subscription acts are audited under the pairing's own identity,
/// and delivery never suppresses or replaces audit entries.</summary>
public sealed class EventsSubscribeModule : IToolModule
{
    private readonly EventSubscriptionStore _store;
    public EventsSubscribeModule(EventSubscriptionStore store) => _store = store;

    // BD-SUPP-EVENTSUB F9: description + schema enum are BUILT from
    // AgentEventKinds.All — the pre-fix hand-written list named six
    // kinds while the registry held seven (clipboard_read was
    // invisible to agents), and the two would keep drifting apart.
    private static readonly string KindList = string.Join(", ", AgentEventKinds.All.OrderBy(k => k));
    private static readonly string KindEnum = string.Join(",", AgentEventKinds.All.OrderBy(k => k).Select(k => $"\"{k}\""));

    public ToolDescriptor Descriptor { get; } = new(
        "events_subscribe",
        $"Subscribe this pairing to agent event kinds ({KindList}), delivered on the GET /mcp event stream. A subscription only ever covers this pairing's own events. Delivery is best-effort with a per-bus sequence number (the SSE id); a subscription expires after 24 hours unless renewed by subscribing again.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: "{\"type\":\"object\",\"properties\":{\"kinds\":{\"type\":\"array\",\"maxItems\":14,\"items\":{\"type\":\"string\",\"enum\":[" + KindEnum + "]}}},\"required\":[\"kinds\"]}");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var kinds = ReadKinds(arguments);
        if (kinds is null)
            return Task.FromResult(ToolResult.Error("bad_arguments", "events_subscribe requires {kinds:[\"session\", ...]}"));
        var (ok, error) = _store.Subscribe(ctx.Pairing.Id, kinds);
        if (!ok) return Task.FromResult(ToolResult.Error("bad_arguments", error!));
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            subscribed = _store.FilterFor(ctx.Pairing.Id).OrderBy(k => k).ToArray(),
            stream = "GET /mcp with Accept: text/event-stream and this pairing's bearer token"
        })));
    }

    internal static List<string>? ReadKinds(JsonElement arguments)
    {
        if (!arguments.TryGetProperty("kinds", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return null;
        // F11: cap the array before materialising/validating it —
        // untrusted input never allocates unboundedly on this path.
        if (arr.GetArrayLength() > AgentEventKinds.All.Count * 2) return null;
        var kinds = new List<string>();
        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.String) return null;
            kinds.Add(el.GetString()!);
        }
        return kinds;
    }
}

/// <summary>U2 — events_unsubscribe: drop kinds from the calling
/// pairing's filter; no kinds (or an empty list) drops the whole
/// subscription. Only ever touches the caller's own filter.</summary>
public sealed class EventsUnsubscribeModule : IToolModule
{
    private readonly EventSubscriptionStore _store;
    public EventsUnsubscribeModule(EventSubscriptionStore store) => _store = store;

    public ToolDescriptor Descriptor { get; } = new(
        "events_unsubscribe",
        "Unsubscribe this pairing from event kinds; omit kinds to drop the whole subscription.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"kinds":{"type":"array","items":{"type":"string"}}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        List<string>? kinds = null;
        if (arguments.TryGetProperty("kinds", out var arr))
        {
            kinds = EventsSubscribeModule.ReadKinds(arguments);
            if (kinds is null)
                return Task.FromResult(ToolResult.Error("bad_arguments", "kinds must be an array of event-kind strings"));
        }
        var (ok, error) = _store.Unsubscribe(ctx.Pairing.Id, kinds);
        if (!ok) return Task.FromResult(ToolResult.Error("bad_arguments", error!));
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            subscribed = _store.FilterFor(ctx.Pairing.Id).OrderBy(k => k).ToArray()
        })));
    }
}

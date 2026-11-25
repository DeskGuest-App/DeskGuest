using System.Text.Json;
using Acp.Core.Ipc;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Modules;

/// <summary>
/// Desktop-plane tools (census rows 6/7/13/14/15). The Core owns policy;
/// the Session Agent owns the desktop. Each call is policy-checked in
/// the choke point, then proxied over IPC. If no agent is connected, or
/// the desktop is locked, the answer is an honest unavailable — the
/// design never fakes a capture (DESIGN §5.2, §7.1).
/// </summary>
public abstract class DesktopProxyModule : IToolModule
{
    private readonly IAgentChannel _channel;
    protected DesktopProxyModule(IAgentChannel channel) => _channel = channel;
    public abstract ToolDescriptor Descriptor { get; }

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_channel.AgentConnected)
            return ToolResult.Unavailable("session agent not connected (no interactive session, or the agent is down)");
        return await _channel.CallDesktopToolAsync(Descriptor.Name, arguments.GetRawText(), ct);
    }
}

public sealed class ScreenshotModule : DesktopProxyModule
{
    public ScreenshotModule(IAgentChannel channel) : base(channel) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "screenshot", "Capture the desktop (base64 PNG). Live, unlocked session only; refuses honestly when locked.",
        Scopes.Observe, SessionRequirement.Agent, RiskTier.Low, ExecutionContext: "Agent");
}

public sealed class SnapshotModule : DesktopProxyModule
{
    public SnapshotModule(IAgentChannel channel) : base(channel) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "snapshot", "UI Automation tree of the desktop with snapshot-scoped element refs. Stale refs fail with a re-snapshot hint, never a guessed click.",
        Scopes.Observe, SessionRequirement.Agent, RiskTier.Low, ExecutionContext: "Agent");
}

public sealed class ClickModule : DesktopProxyModule
{
    public ClickModule(IAgentChannel channel) : base(channel) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "click", "Click by element ref or coordinates. The ghost cursor glides first — the owner's interruption window.",
        Scopes.Drive, SessionRequirement.Agent, RiskTier.High, ExecutionContext: "Agent",
        InputSchemaJson: """{"type":"object","properties":{"element_ref":{"type":"string"},"x":{"type":"integer"},"y":{"type":"integer"},"button":{"type":"string","enum":["left","right","middle"],"default":"left"},"double":{"type":"boolean","default":false}}}""");
}

public sealed class TypeTextModule : DesktopProxyModule
{
    public TypeTextModule(IAgentChannel channel) : base(channel) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "type_text", "Type text into the focused field. Credential-class fields are refused outright in every scope (X1).",
        Scopes.Drive, SessionRequirement.Agent, RiskTier.High, ExecutionContext: "Agent",
        InputSchemaJson: """{"type":"object","properties":{"text":{"type":"string"},"target_is_credential_field":{"type":"boolean","default":false}},"required":["text"]}""");
}

public sealed class KeyPressModule : DesktopProxyModule
{
    public KeyPressModule(IAgentChannel channel) : base(channel) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "key_press", "Press a key or chord (e.g. 'ctrl+l'). SAS-class combos can never be injected (platform).",
        Scopes.Drive, SessionRequirement.Agent, RiskTier.High, ExecutionContext: "Agent",
        InputSchemaJson: """{"type":"object","properties":{"keys":{"type":"string"}},"required":["keys"]}""");
}

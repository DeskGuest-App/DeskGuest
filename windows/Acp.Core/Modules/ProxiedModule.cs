using System.Text.Json;
using Acp.Core.Ipc;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Modules;

/// <summary>A desktop-plane tool whose execution lives in the Session
/// Agent. The descriptor carries the contract (scope, session
/// requirement, risk, gate); the Core's policy engine checks it; the
/// Agent executes. One class serves the whole desktop census because
/// the per-tool difference is the descriptor, not the plumbing.</summary>
public sealed class ProxiedModule : IToolModule
{
    private readonly IAgentChannel _channel;
    private readonly string _engineTool;

    public ProxiedModule(IAgentChannel channel, ToolDescriptor descriptor, string? engineTool = null)
    {
        _channel = channel;
        Descriptor = descriptor;
        _engineTool = engineTool ?? descriptor.Name;
    }

    public ToolDescriptor Descriptor { get; }

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_channel.AgentConnected)
            return ToolResult.Unavailable("session agent not connected (no interactive session, or the agent is down)");
        return await _channel.CallDesktopToolAsync(_engineTool, arguments.GetRawText(), ct);
    }
}

public static class DesktopToolDescriptors
{
    private static ToolDescriptor D(string name, string desc, string scope, RiskTier risk, string? gate = null, string schema = """{"type":"object","properties":{}}""") =>
        new(name, desc, scope, SessionRequirement.Agent, risk, gate, "Agent", schema);

    public static IEnumerable<ToolDescriptor> All()
    {
        yield return D("screenshot_annotated", "Capture with interactive elements labelled and numbered.", Scopes.Observe, RiskTier.Low);
        yield return D("screenshot_region", "Capture a region of the desktop for close inspection.", Scopes.Observe, RiskTier.Low, schema: """{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"},"width":{"type":"integer"},"height":{"type":"integer"}}}""");
        yield return D("display_inventory", "Monitors, resolution, and which display is driven.", Scopes.Observe, RiskTier.Low);
        yield return D("current_window", "Foreground app/window and focused element.", Scopes.Observe, RiskTier.Low);
        yield return D("wait_for", "Wait for text/element to appear; a timeout reports honestly, never pretends.", Scopes.Observe, RiskTier.Low, schema: """{"type":"object","properties":{"text":{"type":"string"},"timeout_seconds":{"type":"integer","default":10}}}""");
        yield return D("scroll", "Scroll wheel by delta at the cursor.", Scopes.Drive, RiskTier.Low, schema: """{"type":"object","properties":{"delta":{"type":"integer"}}}""");
        yield return D("mouse_move", "Move the ghost cursor to coordinates (it glides; it never teleports).", Scopes.Drive, RiskTier.Low, schema: """{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"}},"required":["x","y"]}""");
        yield return D("drag", "Press-move-release path between two points.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"from_x":{"type":"integer"},"from_y":{"type":"integer"},"to_x":{"type":"integer"},"to_y":{"type":"integer"}}}""");
        yield return D("multi_select", "Ctrl-click a list of points as one visible flow.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"points":{"type":"array","items":{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"}}}}}}""");
        yield return D("multi_edit", "Type into several fields as one visible flow. Credential fields refused.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"fields":{"type":"array","items":{"type":"object","properties":{"element_ref":{"type":"string"},"text":{"type":"string"}}}}}}""");
        yield return D("input_primitives", "mouse_down/up, key_down/up, triple_click, cursor_position as separate acts.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"action":{"type":"string"},"button":{"type":"string"},"key":{"type":"string"}}}""");
        yield return D("uia_pattern_action", "Semantic UIA pattern operations (invoke, set_value, toggle, select, expand, collapse, focus) without synthetic input where the OS permits.", Scopes.Drive, RiskTier.Medium, schema: """{"type":"object","properties":{"element_ref":{"type":"string"},"action":{"type":"string"},"value":{"type":"string"}}}""");
        yield return D("window_state", "Minimise/maximise/restore/bring-to-front/move/resize a window by element ref.", Scopes.Drive, RiskTier.Medium, schema: """{"type":"object","properties":{"element_ref":{"type":"string"},"action":{"type":"string"}}}""");
        yield return D("ui_menu_dialog", "Invoke a menu item or handle a dialog structurally, by visible name. If a dialog with that name is already open, it reports that and clicks nothing — a window's own surface is never a click target.", Scopes.Drive, RiskTier.Medium, schema: """{"type":"object","properties":{"item":{"type":"string"}}}""");
        yield return D("app_launch", "Launch an app by path or Start-menu name, in the signed-in user's session.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"path":{"type":"string"},"name":{"type":"string"},"arguments":{"type":"string"}}}""");
        yield return D("app_switch", "Bring a window to the foreground by title.", Scopes.Drive, RiskTier.Medium, schema: """{"type":"object","properties":{"title":{"type":"string"}}}""");
        yield return D("open_url", "Open a URL or protocol handler in the signed-in user's session.", Scopes.Drive, RiskTier.Medium, schema: """{"type":"object","properties":{"url":{"type":"string"}}}""");
        yield return D("clipboard_get", "Read the clipboard. Gate-classed: the clipboard is the owner's, not the agent's. Direction policy applies: policy may forbid host → agent transfer, and a sensitive-class clip is refused by name, never returned.", Scopes.Drive, RiskTier.Medium, gate: "clipboard_read");
        yield return D("clipboard_set", "Place text on the clipboard for the owner's one-tap paste or session work. Gate-classed (clipboard_write) and direction policy applies: policy may forbid agent → host transfer.", Scopes.Drive, RiskTier.Medium, gate: "clipboard_write", schema: """{"type":"object","properties":{"text":{"type":"string"}}}""");
        yield return D("shell_exec", "Run one command as the signed-in user (their profile, their network credentials), via the session agent.", Scopes.Shell, RiskTier.Critical, schema: """{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}""");
        yield return D("session_lock", "Lock the workstation now (executed in-session by the agent).", Scopes.Drive, RiskTier.Medium);
        yield return D("ocr_text", "OCR the screen or a region; the fallback for custom-drawn apps with no UIA tree.", Scopes.Observe, RiskTier.Low, schema: """{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"},"width":{"type":"integer"},"height":{"type":"integer"}}}""");
        yield return D("shortcut", "Alias of key_press for key chords.", Scopes.Drive, RiskTier.High, schema: """{"type":"object","properties":{"keys":{"type":"string"}}}""");
    }
}

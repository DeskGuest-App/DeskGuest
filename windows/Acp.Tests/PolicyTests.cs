using System.Text.Json;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

public class PolicyTests
{
    private static ToolDescriptor Tool(string name, string scope, SessionRequirement session = SessionRequirement.Core, string? gate = null) =>
        new(name, "test", scope, session, RiskTier.High, gate, "SYSTEM");

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void StopInForce_DeniesEverything()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, Tool("shell_exec_system", Scopes.Shell), Args("{}"),
            TestUtil.Session(stop: true), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.Contains("stopped_by_user", d.DenyReason);
    }

    [Fact]
    public void MissingScope_Denied()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(new HashSet<string> { Scopes.Observe });
        var d = engine.Evaluate(pairing, Tool("shell_exec_system", Scopes.Shell), Args("{}"),
            TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.Contains("scope", d.DenyReason);
    }

    [Fact]
    public void AgentTool_WithoutAgentConnected_Denied()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, Tool("screenshot", Scopes.Observe, SessionRequirement.Agent), Args("{}"),
            TestUtil.Session(agent: false), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.Contains("no_session", d.DenyReason);
    }

    [Fact]
    public void AgentTool_DesktopLocked_Denied()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, Tool("screenshot", Scopes.Observe, SessionRequirement.Agent), Args("{}"),
            TestUtil.Session(unlocked: false), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.Contains("desktop_locked", d.DenyReason);
    }

    [Fact]
    public void Takeover_SuspendsAgentTools()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, Tool("screenshot", Scopes.Observe, SessionRequirement.Agent), Args("{}"),
            TestUtil.Session(takeover: true), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.Contains("takeover", d.DenyReason);
    }

    [Fact]
    public void GatedClass_RequiresApproval()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var tool = Tool("clipboard_get", Scopes.Drive, SessionRequirement.Agent, gate: "clipboard_read");
        var denied = engine.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(denied.Allowed);
        Assert.Contains("gated:clipboard_read", denied.DenyReason);
        var allowed = engine.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string> { "clipboard_read" });
        Assert.True(allowed.Allowed);
    }

    [Fact]
    public void X1_TypingIntoCredentialField_IsNeverRule()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var tool = Tool("type_text", Scopes.Drive, SessionRequirement.Agent);
        var d = engine.Evaluate(pairing, tool, Args("""{"text":"x","target_is_credential_field":true}"""),
            TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(d.Allowed);
        Assert.True(d.IsNeverRule);
        Assert.Contains("never", d.DenyReason);
    }

    [Fact]
    public void X1_NormalTyping_Allowed()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var tool = Tool("type_text", Scopes.Drive, SessionRequirement.Agent);
        var d = engine.Evaluate(pairing, tool, Args("""{"text":"hello"}"""),
            TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.True(d.Allowed);
    }

    [Fact]
    public void RateLimit_Trips()
    {
        var engine = new PolicyEngine(maxCallsPerMinute: 3);
        var pairing = TestUtil.BarePairing(Scopes.All);
        var tool = Tool("endpoint_state", Scopes.Observe);
        for (var i = 0; i < 3; i++)
            Assert.True(engine.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>()).Allowed);
        var fourth = engine.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(fourth.Allowed);
        Assert.Contains("rate_limited", fourth.DenyReason);
    }
}

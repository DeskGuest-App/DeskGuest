using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Tests;

/// <summary>W76 — Windows hardening lane pins.
/// FR-119: the orphaned-agent token retry policy (bounded env
/// failures -> file fallback -> clean exit; connect failures are
/// not auth failures and are never recorded here).
/// FR-121: fail-closed driver naming — the generic "An agent"
/// fallback is abolished; an unnamed live session is the named
/// defect state DriverNameMissing, and the renderers / IPC path
/// refuse or flag it (source pins).
/// Blocked-box frame: the blocked presence window carries the
/// same Transparent background W72 gave BoxShell (source pin).
/// FR-110: the Agent parses the snapshot's posture-audit states
/// and renders them as text on the Enterprise page through the
/// Strings door (source pins; the snapshot side is W43-pinned).
/// </summary>
public class W76HardeningTests
{
    private const string TokenA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 hex
    private const string TokenB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    // ---- FR-119: token retry policy -------------------------------

    [Fact]
    public void Fr119_BeforeAnyFailure_EnvWins_Unchanged()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        var (token, source) = p.Current(TokenA, TokenB);
        Assert.Equal(TokenA, token);
        Assert.Equal(IpcTokenSource.Environment, source);
        Assert.False(p.EnvRejected);
        Assert.False(p.ShouldExit);
    }

    [Fact]
    public void Fr119_EnvFailuresBelowLimit_EnvStillWins()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        p.RecordAuthFailure(IpcTokenSource.Environment);
        p.RecordAuthFailure(IpcTokenSource.Environment);
        Assert.False(p.EnvRejected);
        var (_, source) = p.Current(TokenA, TokenB);
        Assert.Equal(IpcTokenSource.Environment, source);
    }

    [Fact]
    public void Fr119_EnvRejectedAfterBoundedFailures_FileFallbackWins()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.EnvAuthFailureLimit; i++)
            p.RecordAuthFailure(IpcTokenSource.Environment);
        Assert.True(p.EnvRejected);
        Assert.False(p.ShouldExit); // the fallback is still untried
        var (token, source) = p.Current(TokenA, TokenB);
        Assert.Equal(TokenB, token);
        Assert.Equal(IpcTokenSource.File, source);
    }

    [Fact]
    public void Fr119_FileFallbackSuccess_ResetsAccounting()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.EnvAuthFailureLimit; i++)
            p.RecordAuthFailure(IpcTokenSource.Environment);
        p.RecordAuthFailure(IpcTokenSource.File);
        p.RecordSuccess();
        Assert.False(p.EnvRejected);
        Assert.False(p.ShouldExit);
        var (_, source) = p.Current(TokenA, TokenB);
        Assert.Equal(IpcTokenSource.Environment, source); // fresh launches start from env again
    }

    [Fact]
    public void Fr119_FileFallbackExhausted_ShouldExit()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.EnvAuthFailureLimit; i++)
            p.RecordAuthFailure(IpcTokenSource.Environment);
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.FileAuthFailureLimit - 1; i++)
        {
            p.RecordAuthFailure(IpcTokenSource.File);
            Assert.False(p.ShouldExit);
        }
        p.RecordAuthFailure(IpcTokenSource.File);
        Assert.True(p.ShouldExit);
    }

    [Fact]
    public void Fr119_EnvRejectedAndNoFileToken_ShouldExitOnNextAuthFailure()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.EnvAuthFailureLimit; i++)
            p.RecordAuthFailure(IpcTokenSource.Environment);
        var (token, source) = p.Current(TokenA, null);
        Assert.Null(token);
        Assert.Equal(IpcTokenSource.None, source);
        p.RecordAuthFailure(source); // the no-token handshake refusal
        Assert.True(p.ShouldExit);
    }

    [Fact]
    public void Fr119_EnvRejectedAndFileTokenIdenticalToEnv_OffersNothingNew()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < IpcTokenFile.TokenRetryPolicy.EnvAuthFailureLimit; i++)
            p.RecordAuthFailure(IpcTokenSource.Environment);
        var (token, source) = p.Current(TokenA, TokenA);
        Assert.Null(token);
        Assert.Equal(IpcTokenSource.None, source);
    }

    [Fact]
    public void Fr119_NoTokenFailureBeforeEnvRejection_NeverExits()
    {
        // A fresh agent with no token yet (RefuseNoToken posture)
        // must NOT be turned into an exit by the orphan bound —
        // only post-rejection exhaustion exits.
        var p = new IpcTokenFile.TokenRetryPolicy();
        for (var i = 0; i < 10; i++) p.RecordAuthFailure(IpcTokenSource.None);
        Assert.False(p.ShouldExit);
        Assert.False(p.EnvRejected);
    }

    [Fact]
    public void Fr119_FileOnlyAgent_BehavesAsBefore_BelowLimit()
    {
        var p = new IpcTokenFile.TokenRetryPolicy();
        var (token, source) = p.Current(null, TokenB);
        Assert.Equal(TokenB, token);
        Assert.Equal(IpcTokenSource.File, source);
    }

    [Fact]
    public void Fr119_AgentClientWiresPolicyFallbackAndCleanExit()
    {
        var ipc = ReadAgent("IpcClient.cs");
        Assert.Contains("TokenRetryPolicy", ipc);
        Assert.Contains("RecordAuthFailure(_presentedSource)", ipc);
        Assert.Contains("ExitRequested", ipc);
        // The fallback re-reads the channels on every attempt.
        Assert.Contains("_tokenPolicy.Current(fromEnv, fromFile)", ipc);
        var app = ReadAgent("App.xaml.cs");
        Assert.Contains("ExitRequested", app);
        Assert.Contains("Shutdown()", app);
    }

    // ---- FR-121: fail-closed driver naming -------------------------

    [Fact]
    public void Fr121_NamedSession_DisplayNameIsTheSpecificName()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted("W69 Proof");
        Assert.True(m.HasDriverName);
        Assert.False(m.DriverNameMissing);
        Assert.Equal("W69 Proof", m.DisplayName);
    }

    [Fact]
    public void Fr121_UnnamedSessionStart_IsTheNamedDefect_NeverGeneric()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted(null);
        Assert.True(m.SessionActive);
        Assert.False(m.HasDriverName);
        Assert.True(m.DriverNameMissing);
        Assert.Equal("", m.DisplayName);
        Assert.NotEqual("An agent", m.DisplayName);
    }

    [Fact]
    public void Fr121_UnnamedDirective_IsTheNamedDefect()
    {
        var m = new PresenceStateMachine();
        m.ApplyDirective(sessionActive: true, agentName: "  ", stopInForce: false);
        Assert.True(m.DriverNameMissing);
        Assert.Equal("", m.DisplayName);
    }

    [Fact]
    public void Fr121_NameArrivingLater_ClearsTheDefect()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted(null);
        Assert.True(m.DriverNameMissing);
        m.ApplyDirective(sessionActive: true, agentName: "Muse", stopInForce: false);
        Assert.False(m.DriverNameMissing);
        Assert.Equal("Muse", m.DisplayName);
    }

    [Fact]
    public void Fr121_StandaloneStop_NoSession_IsNotTheDefect_AndNamesNobody()
    {
        // A STOP with no session ever is not a session rendering:
        // no defect, and no fabricated name either — the blocked
        // box's STOP-banner branch (source-pinned below) applies.
        var m = new PresenceStateMachine();
        m.StopEngaged();
        Assert.False(m.DriverNameMissing);
        Assert.Equal("", m.DisplayName);
    }

    [Fact]
    public void Fr121_GenericFallback_AbolishedInSharedStateMachine()
    {
        var logic = ReadShared("Presence", "PresenceLogic.cs");
        Assert.DoesNotContain("\"An agent\"", logic);
        Assert.Contains("DriverNameMissing", logic);
    }

    [Fact]
    public void Fr121_IpcPathRefusesUnnamedStart_AndRenderersGuard()
    {
        var ipc = ReadAgent("IpcClient.cs");
        Assert.Contains("SessionWouldBeUnnamed(agent)", ipc);
        Assert.Contains("FlagDriverNameMissing", ipc);
        var presence = ReadAgent("Presence.cs");
        Assert.Contains("BuildDefectBox", presence);
        Assert.Contains("_machine.DriverNameMissing", presence);
        // The blocked box branches: defect / named / STOP banner —
        // the named format is only reached with a held name.
        var blocked = Segment(presence, "private void BuildBlockedBox()", "private void BuildNoticeBox");
        Assert.Contains("_driverNameDefect", blocked);
        Assert.Contains("_machine.HasDriverName", blocked);
        Assert.Contains("StopInForceBanner", blocked);
        Assert.Contains("PresenceBlockedFormat", blocked);
    }

    // ---- Blocked-box latent frame ----------------------------------

    [Fact]
    public void BlockedBox_WindowBackgroundIsTransparent_SameAsPillFix()
    {
        var presence = ReadAgent("Presence.cs");
        var blocked = Segment(presence, "private void BuildBlockedBox()", "private void BuildNoticeBox");
        Assert.Contains("Background = Brushes.Transparent", blocked);
        // And the W72 BoxShell fix itself is still in place.
        var shell = Segment(presence, "private Window BoxShell", "private Grid PillFace");
        Assert.Contains("Background = Brushes.Transparent", shell);
    }

    // ---- FR-110: posture states eye-visible -------------------------

    [Fact]
    public void Fr110_AgentParsesAllThreePostureStatesFromSnapshot()
    {
        var parse = ReadAgent("MainWindow.RosterSessions.cs");
        Assert.Contains("\"pointerSigningPostureAudit\"", parse);
        Assert.Contains("\"updateSigningPostureAudit\"", parse);
        Assert.Contains("\"anchorMarker\"", parse);
        Assert.Contains("PointerSigningPostureAudit", parse);
        Assert.Contains("UpdateSigningPostureAudit", parse);
        Assert.Contains("AnchorMarker", parse);
    }

    [Fact]
    public void Fr110_EnterprisePageRendersPostureStatesAsText_ThroughStringsDoor()
    {
        var page = ReadAgent("MainWindow.Enterprise.cs");
        Assert.Contains("Strings.Format(\"PosturePointerSigningFormat\", e.PointerSigningPostureAudit)", page);
        Assert.Contains("Strings.Format(\"PostureUpdateSigningFormat\", e.UpdateSigningPostureAudit)", page);
        Assert.Contains("Strings.Format(\"PostureAnchorMarkerFormat\", e.AnchorMarker)", page);
        var strings = ReadAgent("Strings.cs");
        Assert.Contains("[\"PosturePointerSigningFormat\"]", strings);
        Assert.Contains("[\"PostureUpdateSigningFormat\"]", strings);
        Assert.Contains("[\"PostureAnchorMarkerFormat\"]", strings);
        Assert.Contains("[\"PresenceDriverNameMissing\"]", strings);
        Assert.Contains("[\"PresenceDriverNameMissingHint\"]", strings);
    }

    // ---- source helpers (W60 pattern) -------------------------------

    private static string AgentDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var rel in new[]
            {
                Path.Combine("src", "DeskGuest.SessionAgent"),
                Path.Combine("windows-agent", "src", "DeskGuest.SessionAgent"),
            })
            {
                var candidate = Path.Combine(dir.FullName, rel);
                if (Directory.Exists(candidate)) return candidate;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("DeskGuest.SessionAgent source dir not found above " + AppContext.BaseDirectory);
    }

    private static string ReadAgent(string file) => File.ReadAllText(Path.Combine(AgentDir(), file));

    private static string ReadShared(params string[] parts)
    {
        var agent = new DirectoryInfo(AgentDir());
        var src = agent.Parent!.FullName; // .../src
        return File.ReadAllText(Path.Combine(new[] { src, "DeskGuest.Shared" }.Concat(parts).ToArray()));
    }

    private static string Segment(string text, string startMarker, string endMarker)
    {
        var start = text.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.True(start >= 0, "start marker not found: " + startMarker);
        var end = text.IndexOf(endMarker, start, StringComparison.Ordinal);
        Assert.True(end > start, "end marker not found: " + endMarker);
        return text[start..end];
    }
}

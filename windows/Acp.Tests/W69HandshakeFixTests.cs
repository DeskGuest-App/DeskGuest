using Acp.Core.Ipc;
using Acp.Core.Platform;

namespace Acp.Tests;

/// <summary>
/// Lane W69 (FR-116) — regression pins for the Agent↔Core handshake
/// deadlock proven live 2026-11-23 on ALEX-LAPTOP. Root: the Path B
/// console-host Core runs as the unprivileged console user, but two
/// mechanisms silently assumed the SYSTEM-service shape:
/// (F1) the agent pipe's owner grant came ONLY from ACP_LOGON_USER —
/// a launch that omitted it (W65's direct launch) produced a
/// SYSTEM+Administrators pipe the console user's agent could never
/// connect to ("Access to the path is denied" on every attempt,
/// AgentConnected stuck false, no Core-side error). W57's launch
/// script set the variable and the same build authenticated.
/// (F2) the watchdog launcher's WTSQueryUserToken route needs
/// SE_TCB, which a console-user Core can never hold — every relaunch
/// in that shape returned false (agent_relaunch_failed under both
/// the old and the new Core at 01:00 UTC, build-independent).
/// </summary>
public class W69HandshakeFixTests
{
    // ---------- F1: pipe owner resolution ----------

    [Fact]
    public void F1_EnvVarWinsWhenSet()
    {
        Assert.Equal(@"MACHINE\Owner",
            AgentIpcServer.ResolvePipeOwnerAccount(@"MACHINE\Owner", @"OTHER\DomainUser"));
    }

    [Fact]
    public void F1_DerivedConsoleAccountUsedWhenEnvUnset()
    {
        Assert.Equal(@"MACHINE\Owner",
            AgentIpcServer.ResolvePipeOwnerAccount(null, @"MACHINE\Owner"));
        Assert.Equal(@"MACHINE\Owner",
            AgentIpcServer.ResolvePipeOwnerAccount("", @"MACHINE\Owner"));
        Assert.Equal(@"MACHINE\Owner",
            AgentIpcServer.ResolvePipeOwnerAccount("   ", @"MACHINE\Owner"));
    }

    [Fact]
    public void F1_NoOwnerAnywhereStaysFailClosed()
    {
        // Null owner → BuildPipeSecurity adds no owner rule: the
        // SYSTEM + Administrators ACL stands, never a default-ACL pipe.
        Assert.Null(AgentIpcServer.ResolvePipeOwnerAccount(null, null));
        Assert.Null(AgentIpcServer.ResolvePipeOwnerAccount("", "  "));
    }

    [Fact]
    public void F1_PipeSecurityBuildsWithDerivedOwnerShape()
    {
        // A real account name in DOMAIN\user shape must translate on
        // the machine running the test only if it exists there; the
        // current user always does. Use the current identity.
        if (!OperatingSystem.IsWindows()) return; // NTAccount translation is Windows-only
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        var security = AgentIpcServer.BuildPipeSecurity(me);
        Assert.NotNull(security);
    }

    // ---------- F2: same-session launcher fallback gate ----------

    [Fact]
    public void F2_FallbackAppliesOnlyInTheConsoleSession()
    {
        Assert.True(WindowsAgentLauncher.SameSessionFallbackApplies(1, 1));
        Assert.True(WindowsAgentLauncher.SameSessionFallbackApplies(3, 3));
    }

    [Fact]
    public void F2_FallbackRefusedFromSessionZeroOrOtherSession()
    {
        // A SYSTEM Core in session 0 must NOT plain-start the agent
        // (it would strand in session 0); the WTS route is its only
        // correct path and its failure stays a failure.
        Assert.False(WindowsAgentLauncher.SameSessionFallbackApplies(0, 1));
        Assert.False(WindowsAgentLauncher.SameSessionFallbackApplies(2, 1));
    }

    [Fact]
    public void F2_FallbackRefusedWithNoConsoleSession()
    {
        Assert.False(WindowsAgentLauncher.SameSessionFallbackApplies(0, 0xFFFFFFFF));
        Assert.False(WindowsAgentLauncher.SameSessionFallbackApplies(1, 0xFFFFFFFF));
    }
}

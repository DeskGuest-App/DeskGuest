using Acp.Core;
using Acp.Core.Platform;
using Acp.Core.Services;
using Acp.Shared.Ipc;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>Wave 22 Lane A — Windows token-channel hardening +
/// named defects (round-4, log-laneW21-dsconfirm3).
/// One section per numbered item in the lane brief:
/// 1) token file write order (plan first, ACL before secret bytes,
///    every failure path deletes — directory inspected after each
///    failure injection);
/// 2) Core image binding to the expected full path;
/// 3) ACP_IPC_TOKEN stale inheritance stripped;
/// 4) Tor setup claim atomic under concurrency;
/// 5) accept_licence bound to the host-resolved channel identity;
/// 6) AiPack download throw path → failed-with-reason + audit;
/// plus the two smaller notes: fast-user-switching posture is a
/// code-doc disposition (IpcTokenFile class doc — no test can pin
/// prose; the rotation bound it states IS pinned by the W20
/// per-boot rotation tests), and tokenSource is audit-only
/// (coercion + posture-independence pins below).
/// The Windows ACL applier itself is OS-only; item 1 is pinned
/// through the channel's applier seam with recording/throwing
/// appliers, which is exactly the ordering the applier serves.</summary>
public class W22WinHardenTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string TokenA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 hex

    private static CoreRuntime NewRuntime(string dir) => new(new CoreOptions
    {
        DataDir = dir, Port = 18922, Protector = new DevOnlyPassThroughProtector(),
        Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
    });

    private static void AssertNoSecretAnywhere(string dir, string token)
    {
        foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain(token, File.ReadAllText(file));
        Assert.Empty(Directory.EnumerateFiles(dir, "*.tmp-*", SearchOption.AllDirectories));
    }

    // ---- Item 1: token file write order ---------------------------

    [Fact]
    public void TokenPublish_NullPlan_WritesNothing_RefusesByName()
    {
        // The round-4 blocker: the pre-fix null-plan return left
        // the secret on disk under inherited ACLs. Plan first:
        // no plan ⇒ the directory stays EMPTY.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan: null, consoleSid: null,
            (p, plan) => throw new InvalidOperationException("applier must never run without a plan"));
        Assert.Equal("ipc_file_acl_refused:no-console-user-sid", status);
        Assert.False(File.Exists(path));
        Assert.Empty(Directory.EnumerateFiles(dir));
    }

    [Fact]
    public void TokenPublish_AclAppliesToTempBeforeSecretLands()
    {
        // Recording applier: at temp-ACL time the temp must be
        // EMPTY (no secret bytes under a non-plan ACL, ever); at
        // target-ACL (verification) time the target holds the
        // token, having arrived there by the protected move.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var seen = new List<(string Path, string ContentAtAclTime)>();
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => seen.Add((p, File.Exists(p) ? File.ReadAllText(p) : "<absent>")));
        Assert.StartsWith("ipc_file_published", status);
        Assert.Equal(2, seen.Count);
        Assert.Contains(".tmp-", seen[0].Path);
        Assert.Equal("", seen[0].ContentAtAclTime); // protected BEFORE the secret landed
        Assert.Equal(path, seen[1].Path);
        Assert.Equal(TokenA, seen[1].ContentAtAclTime);
        Assert.Equal(TokenA, IpcTokenFile.Read(path));
        Assert.Empty(Directory.EnumerateFiles(dir, "*.tmp-*"));
    }

    [Fact]
    public void TokenPublish_TempAclThrows_NoSecretAnywhere()
    {
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => throw new InvalidOperationException("acl boom"));
        Assert.StartsWith("ipc_file_write_failed", status);
        Assert.False(File.Exists(path));
        AssertNoSecretAnywhere(dir, TokenA);
    }

    [Fact]
    public void TokenPublish_TargetAclVerificationThrows_FileRemoved()
    {
        // The applier succeeds on the temp but throws on the
        // post-move verification: the file must be REMOVED rather
        // than left with an unverified ACL.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => { if (p == path) throw new InvalidOperationException("verify boom"); });
        Assert.StartsWith("ipc_file_acl_failed_removed", status);
        Assert.False(File.Exists(path));
        AssertNoSecretAnywhere(dir, TokenA);
    }

    [Fact]
    public void TokenWriteProtected_ProtectThrows_TempDeleted_TargetUntouched()
    {
        // Seam-level pin, including rotation: a failed re-publish
        // leaves the PREVIOUS boot's properly-ACL'd file in place
        // and no temp behind.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        IpcTokenFile.WriteAtomicProtected(path, TokenA, _ => { });
        Assert.Equal(TokenA, IpcTokenFile.Read(path));
        var tokenB = new string('B', 64);
        Assert.Throws<InvalidOperationException>(() =>
            IpcTokenFile.WriteAtomicProtected(path, tokenB, _ => throw new InvalidOperationException("boom")));
        Assert.Equal(TokenA, IpcTokenFile.Read(path));
        Assert.Empty(Directory.EnumerateFiles(dir, "*.tmp-*"));
        AssertNoSecretAnywhere(dir, tokenB);
    }

    // ---- Item 2: Core image binding -------------------------------

    private const string AgentImage = @"C:\Program Files\ACP\Acp.SessionAgent.exe";

    [Theory]
    [InlineData(@"C:\Program Files\ACP\AcpCore.exe", true)]
    [InlineData(@"C:\Program Files\ACP\Acp.Core.exe", true)]
    [InlineData(@"c:\program files\acp\acpcore.exe", true)] // case-insensitive
    [InlineData(@"C:\Users\Public\AcpCore.exe", false)]     // the review's fake-Core path
    [InlineData(@"C:\ACP-Install\agent-v19-live\..\core-v19-live\AcpCore.exe", false)] // sibling-dir Core is NOT this agent's Core
    [InlineData(@"C:\Program Files\ACP\sub\AcpCore.exe", false)]
    [InlineData(@"AcpCore.exe", false)]
    [InlineData(null, false)]
    public void CoreImage_MustEqualExpectedPath_BesideAgent(string? image, bool expected)
        => Assert.Equal(expected, IpcTrust.IsCoreServerImage(image, AgentImage));

    [Fact]
    public void CoreImage_Override_WinsOverColocation_AndMalformedOverrideFailsClosed()
    {
        // W25 SUPERSESSION (round-5 proved this test's
        // original rule was the break): the pre-W25 semantics —
        // "a valid override wins over co-location" — let any
        // launcher (a fake Core included) name its own path as
        // the expected Core. The override may now only SELECT
        // among the co-located install paths; an override naming
        // a sibling-dir Core establishes NOTHING. The original
        // assertions are inverted accordingly, deliberately:
        var agent = @"C:\ACP-Install\agent-v19-live\Acp.SessionAgent.exe";
        var core = @"C:\ACP-Install\core-v19-live\AcpCore.exe";
        Assert.False(IpcTrust.IsCoreServerImage(core, agent, core));
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(agent, core));
        // Selection among equals still works: an override naming
        // the co-located Core narrows the set to exactly it.
        var colocatedAgent = @"C:\Program Files\ACP\Acp.SessionAgent.exe";
        var colocatedCore = @"C:\Program Files\ACP\AcpCore.exe";
        Assert.True(IpcTrust.IsCoreServerImage(colocatedCore, colocatedAgent, colocatedCore));
        Assert.False(IpcTrust.IsCoreServerImage(@"C:\Program Files\ACP\Acp.Core.exe", colocatedAgent, colocatedCore));
        // A malformed explicit binding establishes nothing — it
        // does NOT fall back to the co-location guess.
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(agent, @"AcpCore.exe"));
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(agent, @"C:\evil\Notepad.exe"));
        Assert.False(IpcTrust.IsCoreServerImage(core, agent, @"AcpCore.exe"));
    }

    [Fact]
    public void CoreImage_NoEstablishableExpectedPath_RefusesEverything()
    {
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(null, null));
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths("", null));
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(@"Acp.SessionAgent.exe", null)); // relative agent path
        Assert.False(IpcTrust.IsCoreServerImage(@"C:\Program Files\ACP\AcpCore.exe", null, null));
        Assert.False(IpcTrust.IsCoreServerImage(@"C:\Program Files\ACP\AcpCore.exe", @"relative\agent.exe"));
    }

    // ---- Item 3: stale ACP_IPC_TOKEN inheritance ------------------

    [Fact]
    public void ChildEnv_ProviderNull_StaleTokenStripped_NeverInherited()
    {
        var source = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ACP_IPC_TOKEN"] = "stale-or-forged",
            ["ACP_CORE_EXE"] = @"C:\forged\AcpCore.exe",
            ["FOO"] = "bar",
        };
        var child = WindowsAgentLauncher.BuildChildEnvironment(source, ipcToken: null);
        Assert.False(child.ContainsKey("ACP_IPC_TOKEN"));
        Assert.False(child.ContainsKey("ACP_CORE_EXE"));
        Assert.Equal("bar", child["FOO"]);
        // And with a provider value, exactly that value lands.
        var child2 = WindowsAgentLauncher.BuildChildEnvironment(source, "fresh-token", @"C:\real\AcpCore.exe");
        Assert.Equal("fresh-token", child2["ACP_IPC_TOKEN"]);
        Assert.Equal(@"C:\real\AcpCore.exe", child2["ACP_CORE_EXE"]);
    }

    // ---- Item 4: Tor setup claim is atomic ------------------------

    [Fact]
    public void TorClaim_ConcurrentHammer_ExactlyOneWinner_AndReclaimAfterSettle()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var winners = 0;
        Parallel.For(0, 64, _ => { if (runtime.TryClaimTorSetup()) Interlocked.Increment(ref winners); });
        Assert.Equal(1, winners);
        Assert.False(runtime.TryClaimTorSetup());
        // After the in-flight setup settles (here: failed), a new
        // claim is admitted again — the gate is a claim, not a latch.
        var settle = runtime.ApplyTorActionAsync("{\"action\":\"stop\"}").GetAwaiter().GetResult();
        Assert.True(settle.Ok, settle.Detail);
        Assert.True(runtime.TryClaimTorSetup());
    }

    // ---- Item 5: accept_licence binds the channel identity --------

    [Fact]
    public void AcceptLicence_ForgedUserIdIgnored_HostResolvedIdentityRecorded()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        var expected = runtime.ChannelConsoleIdentity();
        var (ok, detail) = runtime.ApplyAiPackAction("{\"action\":\"accept_licence\",\"userId\":\"mallory-the-forger\"}");
        Assert.True(ok, detail);
        Assert.True(runtime.AiPack.LicenceAccepted);
        Assert.Equal(expected, runtime.AiPack.LicenceAcceptedBy);
        Assert.NotEqual("mallory-the-forger", runtime.AiPack.LicenceAcceptedBy);
        Assert.Contains(expected, detail);
        Assert.DoesNotContain("mallory", detail);
        // A second, different forgery changes nothing.
        Assert.True(runtime.ApplyAiPackAction("{\"action\":\"accept_licence\",\"userId\":\"admin\"}").Ok);
        Assert.Equal(expected, runtime.AiPack.LicenceAcceptedBy);
    }

    // ---- Item 6: AiPack download throw path -----------------------

    [Fact]
    public async Task AiPackDownloadBody_Throw_FailedWithReason_NotWedged()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        using var cts = new CancellationTokenSource();
        await runtime.RunAiPackDownloadAsync(cts,
            _ => throw new InvalidOperationException("kaboom-in-download"));
        var snap = runtime.AiPackDownloadSnapshot();
        Assert.Equal("failed", snap.State);
        Assert.Contains("kaboom-in-download", snap.Detail);
        Assert.Contains("InvalidOperationException", snap.Detail);
        // Not wedged: the status surface reports the failure, and
        // the state is a terminal one a retry can leave.
        var status = runtime.ApplyAiPackAction("{\"action\":\"download_status\"}");
        Assert.True(status.Ok, status.Detail);
        Assert.Contains("failed", status.Detail);
    }

    [Fact]
    public async Task AiPackDownloadBody_CancelledThrow_ReportsCancelled()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await runtime.RunAiPackDownloadAsync(cts,
            ct => throw new OperationCanceledException(ct));
        Assert.Equal("cancelled", runtime.AiPackDownloadSnapshot().State);
    }

    [Fact]
    public async Task AiPackDownloadBody_CleanReturn_StillLandsReady()
    {
        var runtime = NewRuntime(TestUtil.TempDir());
        using var cts = new CancellationTokenSource();
        await runtime.RunAiPackDownloadAsync(cts, _ => Task.FromResult((true, "pack installed: fixture")));
        var snap = runtime.AiPackDownloadSnapshot();
        Assert.Equal("ready", snap.State);
        Assert.Contains("pack installed", snap.Detail);
    }

    // ---- Smaller note: tokenSource is audit-only ------------------

    [Theory]
    [InlineData("env", "env")]
    [InlineData("file", "file")]
    [InlineData("none", "none")]
    [InlineData("ENV", "unrecognized")]
    [InlineData("file; DROP TABLE audit", "unrecognized")]
    [InlineData("", "unrecognized")]
    [InlineData(null, "unrecognized")]
    public void TokenSource_AuditLabel_CoercesForgedLabels(string? asserted, string expected)
        => Assert.Equal(expected, IpcTokenFile.AuditLabel(asserted));

    [Fact]
    public void TokenSource_NeverAGate_PostureDependsOnTokenPresenceOnly()
    {
        // Resolve() takes no label at all: the same token presence
        // yields the same posture whatever an agent might assert,
        // and no token yields RefuseNoToken even if a label
        // claims a channel delivered one.
        Assert.Equal(IpcTrustPosture.Authenticated, IpcTokenFile.Resolve(TokenA, null, null).Posture);
        Assert.Equal(IpcTrustPosture.Authenticated, IpcTokenFile.Resolve(null, TokenA, null).Posture);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTokenFile.Resolve(null, null, null).Posture);
    }
}

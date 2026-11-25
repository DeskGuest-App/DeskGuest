using Acp.Core;
using Acp.Core.Services;
using Acp.Shared.Ipc;

namespace Acp.Tests;

/// <summary>W20 token channel (Wave 20 Lane A): the sanctioned
/// per-boot token file for task-launched agents. Pins: the ACL plan
/// shape, rotation, source resolution (env unchanged / file equal /
/// neither ⇒ RefuseNoToken stands), unreadable-file behaviour, the
/// B-17 switch independence, and the Core's publish/delete cycle.
/// The Windows ACL itself is OS-only; what is pinned here is the
/// plan construction the Windows applier consumes verbatim plus
/// every trust decision around it.</summary>
public class W20TokenChannelTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string TokenA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 hex
    private const string TokenB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    // ---- ACL plan shape ----
    [Fact]
    public void AclPlan_ExactlySystemFullControl_PlusConsoleUserReadAndDelete()
    {
        // ReadAndDelete, not Read alone: the console-host Core runs
        // AS the console user, and a Read-only grant locked the
        // writer out of its own rotation (W20 live finding). Delete
        // grants no content access beyond the Read the design
        // already grants, and no other principal appears.
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid);
        Assert.NotNull(plan);
        Assert.Equal(2, plan!.Count);
        Assert.Contains(plan, e => e.IsSystem && e.Sid == IpcTokenFile.SystemSid && e.Rights == "FullControl");
        Assert.Contains(plan, e => !e.IsSystem && e.Sid == ConsoleSid && e.Rights == "ReadAndDelete");
        // No other reader exists in the plan — a different local
        // user is granted nothing, by construction.
        Assert.DoesNotContain(plan, e => e.Sid == "S-1-5-21-9999");
    }

    [Fact]
    public void AclPlan_NoConsoleUser_Refused()
    {
        Assert.Null(IpcTokenFile.BuildAclPlan(null));
        Assert.Null(IpcTokenFile.BuildAclPlan(""));
        Assert.Null(IpcTokenFile.BuildAclPlan("  "));
    }

    [Fact]
    public void AclPlan_ConsoleUserIsSystem_Refused()
        => Assert.Null(IpcTokenFile.BuildAclPlan(IpcTokenFile.SystemSid));

    // ---- Source resolution / trust decision ----
    [Fact]
    public void Resolve_EnvToken_AuthenticatedFromEnv_Unchanged()
    {
        var (posture, source) = IpcTokenFile.Resolve(TokenA, null, null);
        Assert.Equal(IpcTrustPosture.Authenticated, posture);
        Assert.Equal(IpcTokenSource.Environment, source);
        Assert.Equal("env", IpcTokenFile.SourceLabel(source));
    }

    [Fact]
    public void Resolve_FileToken_AuthenticatedFromFile_SameWorth()
    {
        var (posture, source) = IpcTokenFile.Resolve(null, TokenB, null);
        Assert.Equal(IpcTrustPosture.Authenticated, posture);
        Assert.Equal(IpcTokenSource.File, source);
        Assert.Equal("file", IpcTokenFile.SourceLabel(source));
    }

    [Fact]
    public void Resolve_BothPresent_EnvWins()
    {
        var (posture, source) = IpcTokenFile.Resolve(TokenA, TokenB, null);
        Assert.Equal(IpcTrustPosture.Authenticated, posture);
        Assert.Equal(IpcTokenSource.Environment, source);
    }

    [Fact]
    public void Resolve_NoTokenEitherChannel_RefuseNoTokenStands()
    {
        var (posture, source) = IpcTokenFile.Resolve(null, null, null);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, posture);
        Assert.Equal(IpcTokenSource.None, source);
    }

    [Fact]
    public void Resolve_NoToken_DevOptInStillWorks_AndOnlyViaItsOwnSwitch()
    {
        var (posture, _) = IpcTokenFile.Resolve(null, null, "1");
        Assert.Equal(IpcTrustPosture.DevUnauthenticated, posture);
        // B-17 independence: the IPC dev opt-in variable is not the
        // update-key opt-in variable, and neither token channel is
        // gated on either switch — a file token authenticates with
        // every dev switch unset (asserted by the File test above,
        // which passes null for the opt-in).
        Assert.NotEqual(IpcTrust.DevOptInVariable, Acp.Core.DevEphemeralUpdateKeyOptIn.Variable);
    }

    // ---- File mechanics: rotation, malformed, unreadable ----
    [Fact]
    public void File_Rotation_FreshTokenReplacesOldAtomically()
    {
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        IpcTokenFile.WriteAtomic(path, TokenA);
        Assert.Equal(TokenA, IpcTokenFile.Read(path));
        IpcTokenFile.WriteAtomic(path, TokenB);
        Assert.Equal(TokenB, IpcTokenFile.Read(path));
        Assert.Empty(Directory.EnumerateFiles(dir, "*.tmp-*"));
    }

    [Fact]
    public void File_MissingOrMalformed_ReadsAsNoToken()
    {
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        Assert.Null(IpcTokenFile.Read(path)); // absent
        File.WriteAllText(path, "not-a-token");
        Assert.Null(IpcTokenFile.Read(path)); // malformed
        File.WriteAllText(path, "");
        Assert.Null(IpcTokenFile.Read(path)); // empty
    }

    [Fact]
    public void File_Unreadable_ReadsAsNoToken_RefuseStands()
    {
        // Wrong-user simulation at the decision level: an unreadable
        // file (any read failure) must resolve to no token. chmod
        // 000 is not meaningful for every test user (root ignores
        // it), so the pin is on the contract the agent uses: Read()
        // over a path inside a nonexistent directory, and Resolve()
        // over a null file token, both yield RefuseNoToken.
        var bogus = Path.Combine(TestUtil.TempDir(), "no-such-dir", IpcTokenFile.FileName);
        Assert.Null(IpcTokenFile.Read(bogus));
        var (posture, source) = IpcTokenFile.Resolve(null, IpcTokenFile.Read(bogus), null);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, posture);
        Assert.Equal(IpcTokenSource.None, source);
    }

    // ---- Core publish / clean-shutdown delete cycle ----
    [Fact]
    public async Task Core_PublishesTokenFile_AndCleanShutdownDeletesIt()
    {
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var path = Path.Combine(dir, "ipc-token.txt");
        Assert.True(File.Exists(path));
        var first = File.ReadAllText(path).Trim();
        Assert.True(IpcTokenFile.IsWellFormed(first));
        Assert.StartsWith("ipc_file_published", rt.IpcTokenFileStatus);
        await rt.StopAsync(default);
        Assert.False(File.Exists(path), "clean shutdown must delete the token file");
    }

    [Fact]
    public async Task Core_EveryBootRotates_TheTokenFile()
    {
        var dir = TestUtil.TempDir();
        // W95 / FR-124 amendment: a "boot" is now a real boot — the
        // first Core must STOP before the second constructs, because
        // the single-instance guard (correctly) refuses a second
        // live Core on the same data dir. The original shape built
        // two live Cores at once, which is exactly defect D-W93-1.
        // The pin's substance is unchanged: each boot rotates.
        var first1 = new CoreRuntime(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var first = File.ReadAllText(Path.Combine(dir, "ipc-token.txt")).Trim();
        await first1.StopAsync(default);
        await first1.DisposeAsync();
        var second1 = new CoreRuntime(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var second = File.ReadAllText(Path.Combine(dir, "ipc-token.txt")).Trim();
        Assert.True(IpcTokenFile.IsWellFormed(first));
        Assert.True(IpcTokenFile.IsWellFormed(second));
        Assert.NotEqual(first, second);
        await second1.StopAsync(default);
        await second1.DisposeAsync();
    }

    [Fact]
    public void Channel_Publish_ReturnsNamedStatus_AndFileReadsBack()
    {
        var dir = TestUtil.TempDir();
        var status = IpcTokenFileChannel.Publish(dir, TokenA);
        Assert.StartsWith("ipc_file_published", status);
        Assert.Equal(TokenA, IpcTokenFile.Read(IpcTokenFile.DefaultPath(dir)));
        IpcTokenFileChannel.Remove(dir);
        Assert.False(File.Exists(IpcTokenFile.DefaultPath(dir)));
    }
}

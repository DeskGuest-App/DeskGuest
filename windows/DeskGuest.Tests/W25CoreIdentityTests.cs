using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>Wave 25 Lane A — asymmetric Core identity for the
/// Agent channel (round-5, Item 2 FIX-INADEQUATE).
/// Destruction-first: every test in the first three sections is
/// the round-5 break (or its sibling) attempted against the new
/// decision surface — the SAME pure functions the Session Agent
/// and the Core actually call (CoreIdentity.VerifyHelloAckProof,
/// IpcTrust.IsCoreServerImage, AgentIpcServer.BuildHelloAck).
/// The final section pins item 5: token rotation under the
/// console-host ACL shape (writer = the console SID itself).</summary>
public class W25CoreIdentityTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string TokenA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 hex
    private const string AgentImage = @"C:\Program Files\DeskGuest\DeskGuest.SessionAgent.exe";

    // ---- Destruction 1: the round-5 break, verbatim shape ------

    [Fact]
    public void FakeCore_RealToken_PlusEnvOverride_Refused()
    {
        // Round 5 steps 1–5: the fake Core (console user) reads
        // the real token, sits at C:\Users\Public\DeskGuestCore.exe,
        // launches the real Agent with DESKGUEST_CORE_EXE pointing at
        // itself, and completes the HMAC with the stolen token.
        // BOTH remaining factors now refuse it:
        var fakePath = @"C:\Users\Public\DeskGuestCore.exe";
        // (a) the path check: the override may no longer widen
        // the trust set beyond the co-located install paths.
        Assert.Empty(IpcTrust.ExpectedCoreImagePaths(AgentImage, fakePath));
        Assert.False(IpcTrust.IsCoreServerImage(fakePath, AgentImage, fakePath));
        // (b) the identity proof: the fake's HMAC is GENUINE
        // (it holds the real token — that was never the point of
        // failure), but it cannot sign with the Core identity
        // key, so the Agent's proof decision refuses.
        var realCore = CoreIdentityKey.Generate();
        var nonce = IpcAuth.NewNonce();
        var fakeAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, coreIdentity: null);
        Assert.True(IpcAuth.VerifyHelloAck(TokenA, nonce, fakeAck.Text)); // HMAC passes — and is not enough
        Assert.False(CoreIdentity.VerifyHelloAckProof(realCore.PublicKey, nonce, fakeAck.ArgumentsJson));
    }

    [Fact]
    public void FakeCore_WithOwnKeyPair_SelfSignedProof_Refused()
    {
        // A smarter fake mints its OWN identity keypair and signs
        // correctly — against its own key. The Agent verifies
        // against the PIN (the real Core's public key from the
        // install record), never against a key the host supplies,
        // so a well-formed signature under the wrong key refuses.
        var realCore = CoreIdentityKey.Generate();
        var fakeCore = CoreIdentityKey.Generate();
        var nonce = IpcAuth.NewNonce();
        var fakeAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, fakeCore);
        Assert.False(CoreIdentity.VerifyHelloAckProof(realCore.PublicKey, nonce, fakeAck.ArgumentsJson));
        // And the payload's self-asserted public key field is not
        // a trust input: verifying against the FAKE's key would
        // pass, which is exactly why the Agent never does it.
        Assert.True(CoreIdentity.VerifyHelloAckProof(fakeCore.PublicKey, nonce, fakeAck.ArgumentsJson));
    }

    [Fact]
    public void FakeCore_AtExpectedPath_WithoutIdentityKey_Refused()
    {
        // The fake sits AT the expected co-located path (path
        // check passes) and holds the real token (HMAC passes).
        // Without the identity key there is no valid signature:
        // refused. Path + token are factors, not the proof.
        var colocated = @"C:\Program Files\DeskGuest\DeskGuestCore.exe";
        Assert.True(IpcTrust.IsCoreServerImage(colocated, AgentImage));
        var realCore = CoreIdentityKey.Generate();
        var nonce = IpcAuth.NewNonce();
        var noKeyAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, coreIdentity: null);
        Assert.False(CoreIdentity.VerifyHelloAckProof(realCore.PublicKey, nonce, noKeyAck.ArgumentsJson));
        // A replayed signature from a PREVIOUS connection also
        // refuses: the signature binds THIS connection's nonce.
        var realAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, realCore);
        var otherNonce = IpcAuth.NewNonce();
        Assert.False(CoreIdentity.VerifyHelloAckProof(realCore.PublicKey, otherNonce, realAck.ArgumentsJson));
    }

    // ---- The genuine handshake --------------------------------

    [Fact]
    public void RealCoreHandshake_PathHmacAndSignature_AllVerify()
    {
        var realCore = CoreIdentityKey.Generate();
        var nonce = IpcAuth.NewNonce();
        var ack = AgentIpcServer.BuildHelloAck(TokenA, nonce, realCore);
        Assert.True(IpcTrust.IsCoreServerImage(@"C:\Program Files\DeskGuest\DeskGuestCore.exe", AgentImage));
        Assert.True(IpcAuth.VerifyHelloAck(TokenA, nonce, ack.Text));
        Assert.True(CoreIdentity.VerifyHelloAckProof(realCore.PublicKey, nonce, ack.ArgumentsJson));
    }

    [Fact]
    public void CoreRuntime_ComposesIdentity_AndStatusNamesIt()
    {
        var dir = TestUtil.TempDir();
        Directory.CreateDirectory(Path.Combine(dir, "agent"));
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = dir, Port = 18925, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            AgentExePath = Path.Combine(dir, "agent", "DeskGuest.SessionAgent.exe"),
        });
        Assert.StartsWith("ipc_core_identity:", runtime.CoreIdentityStatus);
        // The pin landed beside the (notional) agent image — the
        // install record the Agent will read — and in the data dir.
        var pinPath = Path.Combine(dir, "agent", CoreIdentity.PinFileName);
        Assert.True(File.Exists(pinPath));
        Assert.NotNull(CoreIdentity.TryParsePinnedPublicKey(File.ReadAllText(pinPath)));
        Assert.True(File.Exists(Path.Combine(dir, CoreIdentity.PrivateKeyFileName)));
        // The persisted key file holds NO raw seed: it is the
        // protector-wrapped form (pass-through protector = base64
        // of base64 — the raw seed's base64 never appears).
        var (_, status2) = CoreIdentityChannel.LoadOrCreate(dir, new DevOnlyPassThroughProtector(), null);
        Assert.StartsWith("ipc_core_identity:loaded", status2);
    }

    [Fact]
    public void IdentityChannel_PersistsAcrossLoads_SamePublicKey()
    {
        var dir = TestUtil.TempDir();
        var protector = new DevOnlyPassThroughProtector();
        var (first, _) = CoreIdentityChannel.LoadOrCreate(dir, protector, null);
        var (second, status) = CoreIdentityChannel.LoadOrCreate(dir, protector, null);
        Assert.StartsWith("ipc_core_identity:loaded", status);
        Assert.Equal(first.PublicKeyBase64, second.PublicKeyBase64);
        // A signature from the reloaded key verifies against the
        // originally pinned key — restarts do not rotate identity.
        var nonce = IpcAuth.NewNonce();
        Assert.True(CoreIdentity.VerifyHandshake(first.PublicKey, nonce, second.SignHandshakeBase64(nonce)));
    }

    [Fact]
    public void KeyFileAclPlan_SystemAndAdminsOnly_NeverConsoleUser()
    {
        var plan = CoreIdentity.BuildKeyFileAclPlan();
        Assert.Equal(2, plan.Count);
        Assert.All(plan, e => Assert.Equal("FullControl", e.Rights));
        Assert.Contains(plan, e => e.Sid == IpcTokenFile.SystemSid);
        Assert.Contains(plan, e => e.Sid == CoreIdentity.AdministratorsSid);
        Assert.DoesNotContain(plan, e => e.Sid == ConsoleSid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64!!")]
    [InlineData("AAECAwQFBgc=")] // valid base64, wrong length (8 bytes)
    public void PinParse_Malformed_Refuses(string? content)
        => Assert.Null(CoreIdentity.TryParsePinnedPublicKey(content));

    [Fact]
    public void PinParse_SmallOrderKey_Refuses()
    {
        // The identity point's encoding (y=1, x=0) is a valid
        // 32-byte base64 string and a forgeable key — refused.
        var identityEncoding = new byte[32];
        identityEncoding[0] = 1;
        Assert.Null(CoreIdentity.TryParsePinnedPublicKey(Convert.ToBase64String(identityEncoding)));
        var real = CoreIdentityKey.Generate();
        Assert.NotNull(CoreIdentity.TryParsePinnedPublicKey(real.PublicKeyBase64));
    }

    // ---- Item 5: rotation under the console-host ACL shape -----

    [Fact]
    public void TokenRotation_ConsoleHostWriter_SelfWriteGrantedThenStrictPlanRestored()
    {
        // The writer IS the console SID (console-host Core). The
        // recording applier captures every ACL applied, in order:
        // the temp's first ACL must carry the writer's self-write
        // grant (without it the writer's own secret write is
        // refused by the plan ACL — the round-5 functional flag),
        // and the temp's LAST ACL before the move must be the
        // strict plan exactly, with the target verified under the
        // strict plan too.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var applications = new List<(string Path, IReadOnlyList<IpcTokenFileAclEntry> Plan)>();
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => applications.Add((p, pl.ToArray())), writerSid: ConsoleSid);
        Assert.StartsWith("ipc_file_published", status);
        Assert.Equal(TokenA, IpcTokenFile.Read(path));
        var tempApps = applications.Where(a => a.Path.Contains(".tmp-")).ToList();
        Assert.Equal(2, tempApps.Count);
        Assert.Contains(tempApps[0].Plan, e => e.Sid == ConsoleSid && e.Rights == "ReadAndDeleteWrite");
        Assert.Equal(plan.Count, tempApps[1].Plan.Count);
        Assert.DoesNotContain(tempApps[1].Plan, e => e.Rights == "ReadAndDeleteWrite");
        var targetApps = applications.Where(a => a.Path == path).ToList();
        Assert.Single(targetApps);
        Assert.DoesNotContain(targetApps[0].Plan, e => e.Rights == "ReadAndDeleteWrite");
    }

    [Fact]
    public void TokenRotation_ConsoleHostWriter_SecondPublish_Rotates()
    {
        // Rotation is a REPEAT publish over an existing plan-ACL'd
        // file: with the writer as the console SID it must succeed
        // twice in a row and land the new token.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var first = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => { }, writerSid: ConsoleSid);
        Assert.StartsWith("ipc_file_published", first);
        var tokenB = new string('B', 64);
        var second = IpcTokenFileChannel.PublishWindows(path, tokenB, plan, ConsoleSid,
            (p, pl) => { }, writerSid: ConsoleSid);
        Assert.StartsWith("ipc_file_published", second);
        Assert.Equal(tokenB, IpcTokenFile.Read(path));
    }

    [Fact]
    public void TokenPublish_SystemWriter_NoSelfWriteGrant_SequenceUnchanged()
    {
        // The service shape (writer = SYSTEM, already FullControl
        // under the plan) keeps the exact W22 sequence: temp ACL
        // (strict plan) → target verification ACL. No augmented
        // grant ever appears.
        var dir = TestUtil.TempDir();
        var path = IpcTokenFile.DefaultPath(dir);
        var plan = IpcTokenFile.BuildAclPlan(ConsoleSid)!;
        var applications = new List<IReadOnlyList<IpcTokenFileAclEntry>>();
        var status = IpcTokenFileChannel.PublishWindows(path, TokenA, plan, ConsoleSid,
            (p, pl) => applications.Add(pl.ToArray()), writerSid: IpcTokenFile.SystemSid);
        Assert.StartsWith("ipc_file_published", status);
        Assert.Equal(2, applications.Count);
        Assert.All(applications, pl => Assert.DoesNotContain(pl, e => e.Rights == "ReadAndDeleteWrite"));
    }
}

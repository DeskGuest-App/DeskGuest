using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>Wave 28 Lane B — the install trust record (round-6, Item 2 FIX-INADEQUATE: the W25 anchor relocated with
/// the Agent image). Destruction-first: the round-6 copied-Agent
/// attack, its symlink variant, a fake Core at the registered
/// path, an attacker-written record in a user location, and the
/// absent-record case are all run against the NEW decision
/// surface (InstallTrust.Evaluate + the record-based
/// IsCoreServerImage) — the exact pure functions
/// DeskGuest.SessionAgent now calls — with the genuine handshake as
/// the positive control. The first test is the pre-fix probe,
/// kept: it asserts the W25 surface DID let the attack through,
/// so the regression this wave closes stays visible.
/// See log-laneW28-trustanchor.md for the firsthand probe log.</summary>
public class W28TrustAnchorTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string TokenA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string InstallAgent = @"C:\Program Files\DeskGuest\DeskGuest.SessionAgent.exe";
    private const string InstallCore = @"C:\Program Files\DeskGuest\DeskGuestCore.exe";
    private const string CopyAgent = @"C:\Users\alice\deskguest\DeskGuestAgent.exe";
    private const string FakeCore = @"C:\Users\alice\deskguest\DeskGuestCore.exe";

    private static IReadOnlyList<IpcTokenFileAclEntry> ProtectedPlan =>
        InstallTrust.BuildRecordAclPlan(ConsoleSid);

    private static string GenuineRecord(CoreIdentityKey genuine) =>
        InstallTrust.SerializeRecord(new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore));

    private static InstallTrustDecision GenuineDecision(CoreIdentityKey genuine, string agentImage,
        string? coreOverride = null, Func<string, string?>? resolver = null) =>
        InstallTrust.Evaluate(GenuineRecord(genuine), IpcTokenFile.SystemSid, ProtectedPlan,
            ConsoleSid, serviceShape: true, agentImage, coreOverride, resolver);

    // ---- The pre-fix probe, kept as a regression witness ----

    [Fact]
    public void Probe_Round6CopiedAgentAttack_PassesAgainstW25Surface()
    {
        // The round-6 sequence, verbatim, against the W25
        // decision functions (kept: this is what W28 closes).
        // The copied Agent's pin path, expected Core path, HMAC
        // and identity proof are ALL attacker-supplied.
        Assert.Equal(@"C:\Users\alice\deskguest\core-identity.pub", CoreIdentity.PinPathBeside(CopyAgent));
        Assert.Contains(FakeCore, IpcTrust.ExpectedCoreImagePaths(CopyAgent, FakeCore));
        Assert.True(IpcTrust.IsCoreServerImage(FakeCore, CopyAgent, FakeCore));
        var attacker = CoreIdentityKey.Generate();
        var nonce = IpcAuth.NewNonce();
        var fakeAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, attacker);
        Assert.True(IpcAuth.VerifyHelloAck(TokenA, nonce, fakeAck.Text));
        Assert.True(CoreIdentity.VerifyHelloAckProof(attacker.PublicKey, nonce, fakeAck.ArgumentsJson));
    }

    // ---- Destruction 1: the copied-Agent attack, verbatim ----

    [Fact]
    public void CopiedAgentAttack_GenuineRecord_Refused_AgentNotRegistered()
    {
        // The real Core runs as SYSTEM and has provisioned the
        // genuine protected record. The console user launches the
        // COPY: every anchor the copy reads is now the protected
        // record, and its canonical image path is not the
        // registered Agent path.
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, CopyAgent, FakeCore);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.AgentNotRegistered, decision.Refusal);
        Assert.Equal("install_trust_record:agent-not-registered", decision.State);
        Assert.Null(decision.PinnedCorePublicKey);
    }

    [Fact]
    public void CopiedAgentAttack_AttackerRecordInServiceShape_Refused_StoreUntrusted()
    {
        // The attacker writes their OWN record (their key, the
        // copy as the Agent, the fake as the Core) — as a file the
        // console user owns, with an ACL granting themselves
        // write. In the service shape the Agent refuses the STORE
        // before ever comparing paths: a non-protected record is
        // untrusted, however well-formed.
        var attacker = CoreIdentityKey.Generate();
        var attackerRecord = InstallTrust.SerializeRecord(
            new InstallTrustRecord(attacker.PublicKey, CopyAgent, FakeCore));
        var attackerEntries = new[]
        {
            new IpcTokenFileAclEntry(IpcTokenFile.SystemSid, "FullControl", IsSystem: true),
            new IpcTokenFileAclEntry(ConsoleSid, "FullControl", IsSystem: false),
        };
        var decision = InstallTrust.Evaluate(attackerRecord, ConsoleSid, attackerEntries,
            ConsoleSid, serviceShape: true, CopyAgent, FakeCore);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.RecordStoreUntrusted, decision.Refusal);
        Assert.Equal("install_trust_record:store-untrusted", decision.State);
        // The attacker's proof WOULD verify against their own
        // record — that is why the store check, not the crypto,
        // is what refuses them. (The key parse is sound; the
        // record is the thing that may not be trusted.)
        var nonce = IpcAuth.NewNonce();
        var fakeAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, attacker);
        Assert.True(CoreIdentity.VerifyHelloAckProof(attacker.PublicKey, nonce, fakeAck.ArgumentsJson));
    }

    // ---- Destruction 2: the symlink variant -----------------

    [Fact]
    public void SymlinkLaunch_OfRegisteredImage_CanonicalisesToRegistered_Accepted()
    {
        // the review's claimed variant, with the link RESOLVED:
        // the Agent is launched through a symlink in the user's
        // directory that points AT the registered image. The
        // canonical path is the registered image, so the check
        // accepts — correctly: the running image IS the
        // registered image, and pin + Core path come from the
        // protected record, not from beside the link.
        string? Resolver(string prefix) => prefix switch
        {
            @"C:\Users\alice\link" => @"C:\Program Files\DeskGuest",
            _ => null,
        };
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, @"C:\Users\alice\link\DeskGuest.SessionAgent.exe", resolver: Resolver);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok", decision.State);
        Assert.Equal(InstallTrustPosture.ProtectedService, decision.Posture);
    }

    [Fact]
    public void SymlinkLaunch_ToACopy_CanonicalisesToCopy_Refused()
    {
        // The same variant pointed at the COPY: canonicalising
        // resolves to the copy, which is not registered — refused.
        // This holds whether Environment.ProcessPath names the
        // link or the target (the probe found .NET 10/Linux
        // resolves it to the target; Windows is not assumed).
        string? Resolver(string prefix) => prefix switch
        {
            @"C:\Users\alice\link" => @"C:\Users\alice\deskguest",
            _ => null,
        };
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, @"C:\Users\alice\link\DeskGuestAgent.exe", resolver: Resolver);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.AgentNotRegistered, decision.Refusal);
    }

    [Fact]
    public void Canonicalisation_DotSegments_AndSlashes_ResolveToSameImage()
    {
        // "C:\Program Files\DeskGuest\.\DeskGuest.SessionAgent.exe" and
        // "C:/Program Files/DeskGuest/../DeskGuest/DeskGuest.SessionAgent.exe"
        // name the registered image; a ".." that escapes to a
        // sibling directory names a different image.
        var genuine = CoreIdentityKey.Generate();
        Assert.True(GenuineDecision(genuine, @"C:\Program Files\DeskGuest\.\DeskGuest.SessionAgent.exe").Accepted);
        Assert.True(GenuineDecision(genuine, @"C:/Program Files/DeskGuest/../DeskGuest/DeskGuest.SessionAgent.exe").Accepted);
        Assert.False(GenuineDecision(genuine, @"C:\Program Files\DeskGuest\..\Other\DeskGuest.SessionAgent.exe").Accepted);
        Assert.Equal(@"C:\Program Files\DeskGuest\DeskGuest.SessionAgent.exe",
            InstallTrust.CanonicalizeImagePath(@"C:\Program Files\DeskGuest\.\DeskGuest.SessionAgent.exe"));
    }

    [Fact]
    public void Canonicalisation_RealFilesystemSymlink_ResolvesBothSidesToTarget()
    {
        // The link-walk against the real filesystem (POSIX
        // symlinks here): a symlinked directory and its target
        // canonicalise identically, and a symlinked FILE does too.
        var root = TestUtil.TempDir();
        var real = Path.Combine(root, "real");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "agent.bin"), "x");
        var linkDir = Path.Combine(root, "link");
        File.CreateSymbolicLink(linkDir, real);
        var linkFile = Path.Combine(root, "agent-link.bin");
        File.CreateSymbolicLink(linkFile, Path.Combine(real, "agent.bin"));
        var viaDir = InstallTrust.CanonicalizeImagePath(Path.Combine(linkDir, "agent.bin"));
        var direct = InstallTrust.CanonicalizeImagePath(Path.Combine(real, "agent.bin"));
        Assert.Equal(direct, viaDir);
        Assert.Equal(direct, InstallTrust.CanonicalizeImagePath(linkFile));
    }

    // ---- Destruction 3: fake Core at the registered path ----

    [Fact]
    public void FakeCore_AtRegisteredPath_WithoutIdentityKey_RefusedByProof()
    {
        // The strongest sibling: the fake sits AT the registered
        // Core path and holds the read token, so path + HMAC pass
        // — but it cannot sign with the Core identity key, and
        // the proof is against the RECORD's pin.
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, InstallAgent);
        Assert.True(decision.Accepted, decision.State);
        Assert.True(InstallTrust.IsCoreServerImage(InstallCore, decision.Record!));
        var nonce = IpcAuth.NewNonce();
        var noKeyAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, coreIdentity: null);
        Assert.True(IpcAuth.VerifyHelloAck(TokenA, nonce, noKeyAck.Text));
        Assert.False(CoreIdentity.VerifyHelloAckProof(decision.PinnedCorePublicKey!, nonce, noKeyAck.ArgumentsJson));
        // A replayed genuine signature from another nonce refuses.
        var realAck = AgentIpcServer.BuildHelloAck(TokenA, nonce, genuine);
        Assert.False(CoreIdentity.VerifyHelloAckProof(decision.PinnedCorePublicKey!, IpcAuth.NewNonce(), realAck.ArgumentsJson));
    }

    // ---- Destruction 4: attacker record in a user location ---

    [Fact]
    public void AttackerRecordInUserLocation_Ignored_FixedPathRecordAbsent_Refuses()
    {
        // The Agent reads ONLY the fixed record path. An
        // attacker record placed anywhere the user can write —
        // beside the copy, in a user dir, in the env-pointed
        // location — is never read: with nothing at the fixed
        // path, the decision is record-absent, fail closed.
        // (The test drives Evaluate with recordContent: null,
        // which is exactly what TryReadRecordContent returns
        // for the fixed path when it holds no record — the
        // user-location file is not an input to the decision.)
        var decision = InstallTrust.Evaluate(recordContent: null, storeOwnerSid: null,
            storeEntries: null, currentUserSid: ConsoleSid, serviceShape: true,
            agentImagePath: CopyAgent, coreExeOverride: FakeCore);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.RecordAbsent, decision.Refusal);
        Assert.Equal("install_trust_record:absent", decision.State);
    }

    // ---- Destruction 5: record absent / malformed -------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-json")]
    [InlineData("{\"version\":\"deskguest-install-trust:v0\",\"corePublicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"agentImagePath\":\"C:\\\\Program Files\\\\DeskGuest\\\\DeskGuest.SessionAgent.exe\",\"coreImagePath\":\"C:\\\\Program Files\\\\DeskGuest\\\\DeskGuestCore.exe\"}")]
    [InlineData("{\"version\":\"deskguest-install-trust:v1\",\"corePublicKey\":\"not-base64!!\",\"agentImagePath\":\"C:\\\\Program Files\\\\DeskGuest\\\\DeskGuest.SessionAgent.exe\",\"coreImagePath\":\"C:\\\\Program Files\\\\DeskGuest\\\\DeskGuestCore.exe\"}")]
    [InlineData("{\"version\":\"deskguest-install-trust:v1\",\"corePublicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"agentImagePath\":\"relative\\\\DeskGuest.SessionAgent.exe\",\"coreImagePath\":\"C:\\\\Program Files\\\\DeskGuest\\\\DeskGuestCore.exe\"}")]
    public void Record_AbsentOrMalformed_Refuses(string? content)
    {
        var decision = InstallTrust.Evaluate(content, IpcTokenFile.SystemSid, ProtectedPlan,
            ConsoleSid, serviceShape: true, InstallAgent, null);
        Assert.False(decision.Accepted);
        Assert.Equal(content is null ? InstallTrustRefusal.RecordAbsent : InstallTrustRefusal.RecordMalformed,
            decision.Refusal);
    }

    // ---- Genuine handshake (positive control) -----------------

    [Fact]
    public void GenuineHandshake_RecordPaths_Pin_AndProof_AllVerify()
    {
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, InstallAgent);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok", decision.State);
        Assert.Equal(genuine.PublicKeyBase64, decision.PinnedCorePublicKey is null
            ? null : Convert.ToBase64String(decision.PinnedCorePublicKey));
        Assert.Equal(InstallCore, decision.ExpectedCoreImagePath);
        Assert.Single(InstallTrust.ExpectedCoreImagePaths(decision.Record!, null));
        Assert.True(InstallTrust.IsCoreServerImage(InstallCore, decision.Record!));
        var nonce = IpcAuth.NewNonce();
        var ack = AgentIpcServer.BuildHelloAck(TokenA, nonce, genuine);
        Assert.True(IpcAuth.VerifyHelloAck(TokenA, nonce, ack.Text));
        Assert.True(CoreIdentity.VerifyHelloAckProof(decision.PinnedCorePublicKey!, nonce, ack.ArgumentsJson));
    }

    // ---- DESKGUEST_CORE_EXE remains selection-only ------------------

    [Fact]
    public void CoreExeOverride_NamesRegisteredCore_SelectsIt()
    {
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, InstallAgent, InstallCore);
        Assert.True(decision.Accepted, decision.State);
        Assert.Single(InstallTrust.ExpectedCoreImagePaths(decision.Record!, InstallCore));
    }

    [Fact]
    public void CoreExeOverride_NamesAnythingElse_Refuses()
    {
        var genuine = CoreIdentityKey.Generate();
        var decision = GenuineDecision(genuine, InstallAgent, FakeCore);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.CoreOverrideOutsideRecord, decision.Refusal);
        Assert.Equal("install_trust_record:core-override-outside-record", decision.State);
        Assert.Empty(InstallTrust.ExpectedCoreImagePaths(
            new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore), FakeCore));
        Assert.False(InstallTrust.IsCoreServerImage(FakeCore,
            new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore), FakeCore));
    }

    // ---- Store ACL plan + classification ----------------------

    [Fact]
    public void RecordAclPlan_SystemAndAdminsFull_ConsoleReadOnly()
    {
        var plan = InstallTrust.BuildRecordAclPlan(ConsoleSid);
        Assert.Equal(3, plan.Count);
        Assert.Contains(plan, e => e.Sid == IpcTokenFile.SystemSid && e.Rights == "FullControl");
        Assert.Contains(plan, e => e.Sid == CoreIdentity.AdministratorsSid && e.Rights == "FullControl");
        Assert.Contains(plan, e => e.Sid == ConsoleSid && e.Rights == "Read");
        Assert.DoesNotContain(plan, e => e.Sid == ConsoleSid && e.Rights != "Read");
        // Record file path: sibling trust dir, NOT the data dir
        // (whose installer ACL grants the console user Modify).
        var dataDir = TestUtil.TempDir();
        var recordPath = InstallTrust.RecordPathForDataDir(dataDir);
        Assert.Equal(Path.Combine(Path.GetDirectoryName(dataDir)!, "trust", InstallTrust.RecordFileName), recordPath);
        Assert.DoesNotContain(dataDir + Path.DirectorySeparatorChar, recordPath);
    }

    [Fact]
    public void ClassifyStore_ServiceShape_UnprotectedRecord_IsUntrusted()
    {
        // Owner = console user, or a console write-like grant,
        // in the service shape: untrusted — the shape the
        // attacker-planted record lands in.
        var consoleOwned = new[] { new IpcTokenFileAclEntry(ConsoleSid, "FullControl", IsSystem: false) };
        Assert.Equal(InstallTrustPosture.Untrusted,
            InstallTrust.ClassifyStore(ConsoleSid, consoleOwned, ConsoleSid, serviceShape: true));
        var privilegedOwnerButConsoleWrite = new[]
        {
            new IpcTokenFileAclEntry(IpcTokenFile.SystemSid, "FullControl", IsSystem: true),
            new IpcTokenFileAclEntry(ConsoleSid, "Write", IsSystem: false),
        };
        Assert.Equal(InstallTrustPosture.Untrusted,
            InstallTrust.ClassifyStore(IpcTokenFile.SystemSid, privilegedOwnerButConsoleWrite, ConsoleSid, serviceShape: true));
        Assert.Equal(InstallTrustPosture.ProtectedService,
            InstallTrust.ClassifyStore(IpcTokenFile.SystemSid, ProtectedPlan, ConsoleSid, serviceShape: true));
        Assert.Equal(InstallTrustPosture.ProtectedService,
            InstallTrust.ClassifyStore(CoreIdentity.AdministratorsSid, ProtectedPlan, ConsoleSid, serviceShape: true));
    }

    [Fact]
    public void ClassifyStore_ConsoleHostShape_SameUserRecord_IsConsoleHost_NamedLimit()
    {
        // No service installed, record written by the console
        // user's own Core: ConsoleHost — accepted with the named
        // limit, never presented as service-grade. A record owned
        // by a THIRD user is untrusted even here.
        var userEntries = new[] { new IpcTokenFileAclEntry(ConsoleSid, "FullControl", IsSystem: false) };
        Assert.Equal(InstallTrustPosture.ConsoleHost,
            InstallTrust.ClassifyStore(ConsoleSid, userEntries, ConsoleSid, serviceShape: false));
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(GenuineRecord(genuine), ConsoleSid, userEntries,
            ConsoleSid, serviceShape: false, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok-console-host-named-limit", decision.State);
        Assert.Equal(InstallTrustPosture.ConsoleHost, decision.Posture);
        Assert.Equal(InstallTrustPosture.Untrusted,
            InstallTrust.ClassifyStore("S-1-5-21-9999", userEntries, ConsoleSid, serviceShape: false));
    }

    // ---- Provisioning channel ----------------------------------

    [Fact]
    public void Provision_SystemWriter_WritesGenuineRecord_OverwritesAttackerRecord()
    {
        // A pre-created attacker record at the record path is
        // overwritten by the genuine Core's provisioning, never
        // read or trusted.
        var dir = TestUtil.TempDir();
        var recordPath = InstallTrust.RecordPathForDataDir(dir);
        Directory.CreateDirectory(Path.GetDirectoryName(recordPath)!);
        var attacker = CoreIdentityKey.Generate();
        File.WriteAllText(recordPath, InstallTrust.SerializeRecord(
            new InstallTrustRecord(attacker.PublicKey, CopyAgent, FakeCore)));
        var genuine = CoreIdentityKey.Generate();
        var status = InstallTrustRecordChannel.ProvisionTo(recordPath,
            new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore),
            ProtectedPlan, applyAcl: null, writerSid: IpcTokenFile.SystemSid);
        Assert.StartsWith("install_trust_record:provisioned-service", status);
        var record = InstallTrust.TryParseRecord(File.ReadAllText(recordPath));
        Assert.NotNull(record);
        Assert.Equal(genuine.PublicKeyBase64, record!.CorePublicKeyBase64);
        Assert.Equal(InstallAgent, record.AgentImagePath);
        Assert.Equal(InstallCore, record.CoreImagePath);
    }

    [Fact]
    public void Provision_ConsoleWriter_StatusNamesConsoleHostLimit()
    {
        var dir = TestUtil.TempDir();
        var recordPath = InstallTrust.RecordPathForDataDir(dir);
        var genuine = CoreIdentityKey.Generate();
        var status = InstallTrustRecordChannel.ProvisionTo(recordPath,
            new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore),
            ProtectedPlan, applyAcl: null, writerSid: ConsoleSid);
        Assert.StartsWith("install_trust_record:provisioned-console-host-named-limit", status);
        Assert.NotNull(InstallTrust.TryParseRecord(File.ReadAllText(recordPath)));
    }

    [Fact]
    public void Provision_AclFailure_RemovesRecord_FailClosed()
    {
        var dir = TestUtil.TempDir();
        var recordPath = InstallTrust.RecordPathForDataDir(dir);
        var genuine = CoreIdentityKey.Generate();
        var status = InstallTrustRecordChannel.ProvisionTo(recordPath,
            new InstallTrustRecord(genuine.PublicKey, InstallAgent, InstallCore),
            ProtectedPlan, applyAcl: (_, _) => throw new UnauthorizedAccessException("test"),
            writerSid: IpcTokenFile.SystemSid);
        Assert.StartsWith("install_trust_record:acl-failed-removed", status);
        Assert.False(File.Exists(recordPath));
    }

    [Fact]
    public void CoreRuntime_ComposesRecord_AndStatusNamesIt()
    {
        var dir = TestUtil.TempDir();
        Directory.CreateDirectory(Path.Combine(dir, "agent"));
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = dir, Port = 18926, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            AgentExePath = Path.Combine(dir, "agent", "DeskGuest.SessionAgent.exe"),
        });
        Assert.StartsWith("install_trust_record:", runtime.InstallTrustRecordStatus);
        var recordPath = InstallTrust.RecordPathForDataDir(dir);
        Assert.True(File.Exists(recordPath));
        var record = InstallTrust.TryParseRecord(File.ReadAllText(recordPath));
        Assert.NotNull(record);
        Assert.Equal(Path.Combine(dir, "agent", "DeskGuest.SessionAgent.exe"), record!.AgentImagePath);
    }
}

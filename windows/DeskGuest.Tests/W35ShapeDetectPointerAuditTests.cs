using DeskGuest.Core;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>Wave 35 Lane A — two live-failure fixes from W33-B.
///
/// Item 1 (shape detection): W28 classified the machine as
/// service shape from the mere EXISTENCE of the HKLM DeskGuestCore
/// service key. On the reference laptop the service is installed but
/// Stopped (v16 binary) while Core+Agent run console-host, so
/// the console-provisioned record was judged store-untrusted
/// and the Agent refused everything. The decision now takes
/// the service state IN FORCE (InstallTrustServiceState):
/// protected store binds regardless; running + unprotected
/// refuses; not-running + console-provisioned record at the
/// fixed location accepts under the named limit.
///
/// Item 2 (pointer posture audit): the pointer_signing_posture
/// append sat in a swallow-all try/catch in CoreRuntime
/// composition — W33-B's chain held zero "pointer" entries
/// while keying had begun. The append must land (verified in
/// the chain) or surface as the named
/// PointerSigningPostureAuditState FAILED state.</summary>
public class W35ShapeDetectPointerAuditTests
{
    private const string ConsoleSid = "S-1-5-21-1000-1000-1000-1001";
    private const string InstallAgent = @"C:\Program Files\DeskGuest\DeskGuest.SessionAgent.exe";
    private const string InstallCore = @"C:\Program Files\DeskGuest\DeskGuestCore.exe";
    private const string CopyAgent = @"C:\Users\alice\deskguest\DeskGuestAgent.exe";
    private const string FakeCore = @"C:\Users\alice\deskguest\DeskGuestCore.exe";

    private static IReadOnlyList<IpcTokenFileAclEntry> ProtectedPlan =>
        InstallTrust.BuildRecordAclPlan(ConsoleSid);

    private static IReadOnlyList<IpcTokenFileAclEntry> ConsoleEntries =>
        new[] { new IpcTokenFileAclEntry(ConsoleSid, "FullControl", IsSystem: false) };

    private static string RecordFor(CoreIdentityKey key, string agent = InstallAgent, string core = InstallCore) =>
        InstallTrust.SerializeRecord(new InstallTrustRecord(key.PublicKey, agent, core));

    // ---- Item 1: the W33-B live scenario, reproduced ----

    [Fact]
    public void W33BScenario_ServiceKeyPresentButStopped_ConsoleRecord_AcceptedNamedLimit()
    {
        // Service installed (key present) but STOPPED; the record
        // was provisioned by the console-host Core: owned by the
        // console user, plan-exact console ACL, at the fixed
        // location, registering the co-located Agent/Core paths,
        // and this Agent IS the registered image. Pre-W35 this
        // exact state decided store-untrusted (serviceShape was
        // keyed off key existence). Now: named-limit acceptance.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), ConsoleSid, ConsoleEntries,
            ConsoleSid, InstallTrustServiceState.Stopped, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok-console-host-named-limit", decision.State);
        Assert.Equal(InstallTrustPosture.ConsoleHost, decision.Posture);
        Assert.Equal(genuine.PublicKeyBase64, Convert.ToBase64String(decision.PinnedCorePublicKey!));
    }

    [Fact]
    public void ServiceRunning_ConsoleProvisionedRecord_Refused_StoreUntrusted()
    {
        // The anomaly stays fail-closed: a RUNNING SYSTEM Core
        // re-asserts its own protected record; a console-owned
        // record while it runs is wrong.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), ConsoleSid, ConsoleEntries,
            ConsoleSid, InstallTrustServiceState.Running, InstallAgent, null);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.RecordStoreUntrusted, decision.Refusal);
        Assert.Equal("install_trust_record:store-untrusted", decision.State);
    }

    [Fact]
    public void ServiceRunning_ProtectedRecord_AcceptedServiceShape()
    {
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), IpcTokenFile.SystemSid, ProtectedPlan,
            ConsoleSid, InstallTrustServiceState.Running, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok", decision.State);
        Assert.Equal(InstallTrustPosture.ProtectedService, decision.Posture);
    }

    [Fact]
    public void ServiceStopped_ProtectedRecord_StillBindsServiceShape()
    {
        // A provably protected store (SYSTEM/Admins-owned, no
        // non-privileged write) binds the service shape
        // REGARDLESS of service state — only SYSTEM/Admins could
        // have written it, stopped service or not.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), IpcTokenFile.SystemSid, ProtectedPlan,
            ConsoleSid, InstallTrustServiceState.Stopped, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal(InstallTrustPosture.ProtectedService, decision.Posture);
        Assert.Equal(InstallTrustPosture.ProtectedService, InstallTrust.ClassifyStore(
            IpcTokenFile.SystemSid, ProtectedPlan, ConsoleSid, InstallTrustServiceState.Stopped));
    }

    [Fact]
    public void ServiceStateUnknown_ConsoleRecord_Refused_FailClosed()
    {
        // Key present but running state unreadable: Unknown is
        // treated as in force — an unreadable state never opens
        // the console-host limit.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), ConsoleSid, ConsoleEntries,
            ConsoleSid, InstallTrustServiceState.Unknown, InstallAgent, null);
        Assert.False(decision.Accepted);
        Assert.Equal("install_trust_record:store-untrusted", decision.State);
        Assert.True(InstallTrust.ServiceInForce(InstallTrustServiceState.Unknown));
        Assert.True(InstallTrust.ServiceInForce(InstallTrustServiceState.Running));
        Assert.False(InstallTrust.ServiceInForce(InstallTrustServiceState.Stopped));
        Assert.False(InstallTrust.ServiceInForce(InstallTrustServiceState.NotInstalled));
    }

    [Fact]
    public void CopiedAgentAttack_StoppedServiceMachine_GenuineRecord_StillRefused_NotRegistered()
    {
        // Round-6 verbatim, in the stopped-service machine state
        // W35 opens for console-host: the genuine record sits at
        // the FIXED location registering the genuine paths. The
        // copied Agent's own canonical path is not the registered
        // path, and DESKGUEST_CORE_EXE naming the fake Core widens
        // nothing — the registration check still binds, before
        // any store-shape leniency can help the copy.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), ConsoleSid, ConsoleEntries,
            ConsoleSid, InstallTrustServiceState.Stopped, CopyAgent, FakeCore);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.AgentNotRegistered, decision.Refusal);
        Assert.Equal("install_trust_record:agent-not-registered", decision.State);
    }

    [Fact]
    public void RecordAbsent_StoppedService_FailsClosedAsBefore()
    {
        var decision = InstallTrust.Evaluate(recordContent: null, storeOwnerSid: null,
            storeEntries: null, currentUserSid: ConsoleSid, InstallTrustServiceState.Stopped,
            agentImagePath: InstallAgent, coreExeOverride: null);
        Assert.False(decision.Accepted);
        Assert.Equal(InstallTrustRefusal.RecordAbsent, decision.Refusal);
        Assert.Equal("install_trust_record:absent", decision.State);
    }

    [Fact]
    public void ThirdUserRecord_StoppedService_Untrusted()
    {
        // The named limit is same-user only: a record owned by a
        // THIRD user is untrusted even with the service stopped.
        var genuine = CoreIdentityKey.Generate();
        var decision = InstallTrust.Evaluate(RecordFor(genuine), "S-1-5-21-9999-9999-9999-1009",
            ConsoleEntries, ConsoleSid, InstallTrustServiceState.Stopped, InstallAgent, null);
        Assert.False(decision.Accepted);
        Assert.Equal("install_trust_record:store-untrusted", decision.State);
    }

    // ---- Item 2: pointer posture audit append ----

    private static CoreRuntime Compose(string dir, int port, Action<string, string?, string>? sink = null)
    {
        var dataDir = Path.Combine(dir, "data");
        var install = Path.Combine(dir, "install"); Directory.CreateDirectory(install);
        return new CoreRuntime(new CoreOptions
        {
            DataDir = dataDir, Port = port, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
            InstallRoot = install, PointerSigningPostureAuditSink = sink,
        });
    }

    [Fact]
    public void PointerPosture_AuditEntryExistsInChain_AfterComposition()
    {
        var runtime = Compose(TestUtil.TempDir(), 18941);
        Assert.Equal("recorded:pointer_signing_posture", runtime.PointerSigningPostureAuditState);
        var entries = runtime.Enterprise.AuditLog.Entries
            .Where(e => e.Kind == "pointer_signing_posture").ToList();
        Assert.Single(entries);
        Assert.Contains("pointer signing: runtime key keyed", entries[0].Detail);
        Assert.True(runtime.Enterprise.AuditLog.Verify().Ok);
    }

    [Fact]
    public void PointerPosture_ForcedAppendFailure_IsVisibleNamedError_NotSwallowed()
    {
        var runtime = Compose(TestUtil.TempDir(), 18942,
            sink: (_, _, _) => throw new InvalidOperationException("forced append failure (W35 test)"));
        Assert.StartsWith("FAILED: pointer_signing_posture audit append failed", runtime.PointerSigningPostureAuditState);
        Assert.Contains("forced append failure", runtime.PointerSigningPostureAuditState);
        // And the posture itself still composed — the failure is
        // in the RECORDING, named as such, not hidden behind a
        // posture change.
        Assert.Contains("pointer signing: runtime key keyed", runtime.PointerSigningStatus);
    }
}

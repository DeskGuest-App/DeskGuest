using System.Security.AccessControl;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>W37 — the second R1 live failure (2026-11-26),
/// converted to permanent pins. With the W36 mapping fixed and
/// the DeskGuestCore service properly started, the Session Agent
/// passed the trust-record check and then refused its own Core
/// with "could not open the pipe server process for identity
/// verification": the Agent's image-path leg opens the pipe host
/// process, and in the service shape that process is LocalSystem
/// while the Agent is the interactive user — the OS denies the
/// handle, so the leg is unexecutable in exactly the shape the
/// trust record exists for. The leg now stands down ONLY in the
/// ProtectedService posture (InstallTrust.MaySkipCoreImageCheck),
/// where the record store's protection + the SCM state + the
/// still-mandatory W25 identity signature carry strictly more
/// proof than an image-path string. These tests pin the rule and
/// the two live postures; the W25 signature check itself is
/// untouched and remains mandatory in every shape.</summary>
public class W37AgentTrustImageLegTests
{
    private const string ConsoleSid = "S-1-5-21-3406511525-3477290766-3810443984-1001";
    private const string InstallAgent = @"C:\DeskGuest-Install\DeskGuest.SessionAgent.exe";
    private const string InstallCore = @"C:\DeskGuest-Install\DeskGuestCore.exe";

    [Theory]
    [InlineData(InstallTrustPosture.ProtectedService, true)]
    [InlineData(InstallTrustPosture.ConsoleHost, false)]
    [InlineData(InstallTrustPosture.Untrusted, false)]
    public void ImageLeg_StandsDown_OnlyInProtectedService(InstallTrustPosture posture, bool expected) =>
        Assert.Equal(expected, InstallTrust.MaySkipCoreImageCheck(posture));

    [Fact]
    public void R1ServiceShape_RecordEvaluatesProtected_AndTheLegStandsDown()
    {
        // The live R1 chain after the service start: the same
        // protected store facts as W36, with the DeskGuestCore
        // service RUNNING. The decision accepts as
        // ProtectedService, and in that posture the unexecutable
        // image leg stands down — the Agent proceeds to the token
        // HMAC and the W25 signature, which remain mandatory.
        var key = CoreIdentityKey.Generate();
        var content = InstallTrust.SerializeRecord(
            new InstallTrustRecord(key.PublicKey, InstallAgent, InstallCore));
        var entries = new[]
        {
            new IpcTokenFileAclEntry(IpcTokenFile.SystemSid,
                InstallTrust.MapRightsVocabulary(FileSystemRights.FullControl), IsSystem: true),
            new IpcTokenFileAclEntry(CoreIdentity.AdministratorsSid,
                InstallTrust.MapRightsVocabulary(FileSystemRights.FullControl), IsSystem: true),
            new IpcTokenFileAclEntry(ConsoleSid,
                InstallTrust.MapRightsVocabulary(FileSystemRights.Read | FileSystemRights.Synchronize), IsSystem: false),
        };
        var decision = InstallTrust.Evaluate(content, IpcTokenFile.SystemSid, entries,
            ConsoleSid, InstallTrustServiceState.Running, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal(InstallTrustPosture.ProtectedService, decision.Posture);
        Assert.True(InstallTrust.MaySkipCoreImageCheck(decision.Posture));
    }

    [Fact]
    public void ConsoleShape_RecordEvaluatesConsoleHost_AndTheLegStaysMandatory()
    {
        // The console-host shape: the record is the console user's
        // own, the service is stopped. Host and Agent share a
        // user, the process handle opens, and the image leg is
        // that shape's main anti-squatter proof — it must NOT
        // stand down.
        var key = CoreIdentityKey.Generate();
        var content = InstallTrust.SerializeRecord(
            new InstallTrustRecord(key.PublicKey, InstallAgent, InstallCore));
        var entries = new[]
        {
            new IpcTokenFileAclEntry(ConsoleSid,
                InstallTrust.MapRightsVocabulary(FileSystemRights.FullControl), IsSystem: false),
        };
        var decision = InstallTrust.Evaluate(content, ConsoleSid, entries,
            ConsoleSid, InstallTrustServiceState.Stopped, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal(InstallTrustPosture.ConsoleHost, decision.Posture);
        Assert.False(InstallTrust.MaySkipCoreImageCheck(decision.Posture));
    }
}

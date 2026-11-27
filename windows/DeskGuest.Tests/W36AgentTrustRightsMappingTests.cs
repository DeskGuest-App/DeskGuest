using System.Security.AccessControl;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>W36 — the R1 live failure (2026-11-26), converted to
/// permanent pins. The first service-shape install produced a
/// provably protected trust record (SYSTEM-owned; SYSTEM +
/// Administrators FullControl; the console user Read only), yet
/// the Session Agent refused its own Core with
/// install_trust_record:store-untrusted. Root cause: the Agent's
/// inline FileSystemRights-to-vocabulary mapping included the
/// COMPOSITE FileSystemRights.Modify in its write mask, and
/// Modify's bit pattern contains every Read bit, so the console
/// user's pure Read grant mapped to "Write" and the protected
/// store misclassified. The W28/W35 suites never caught it
/// because they built ACL entries from vocabulary strings
/// directly and never exercised the live mapping. The mapping
/// now lives in InstallTrust.MapRightsVocabulary (Shared), the
/// Agent calls it, and these tests pin it from REAL
/// FileSystemRights values — the tested code is the live
/// code.</summary>
public class W36AgentTrustRightsMappingTests
{
    private const string ConsoleSid = "S-1-5-21-3406511525-3477290766-3810443984-1001";
    private const string InstallAgent = @"C:\DeskGuest-Install\DeskGuest.SessionAgent.exe";
    private const string InstallCore = @"C:\DeskGuest-Install\DeskGuestCore.exe";

    [Theory]
    [InlineData(FileSystemRights.FullControl, "FullControl")]
    [InlineData(FileSystemRights.Read, "Read")]
    [InlineData(FileSystemRights.ReadAndExecute, "Read")]
    [InlineData(FileSystemRights.Read | FileSystemRights.Synchronize, "Read")]
    [InlineData(FileSystemRights.ExecuteFile, "Read")]
    [InlineData(FileSystemRights.Write, "Write")]
    [InlineData(FileSystemRights.Modify, "Write")]
    [InlineData(FileSystemRights.Delete, "Write")]
    [InlineData(FileSystemRights.Read | FileSystemRights.WriteData, "Write")]
    [InlineData(FileSystemRights.ChangePermissions, "Write")]
    [InlineData(FileSystemRights.TakeOwnership, "Write")]
    public void RightsVocabulary_FromRealFileSystemRights(FileSystemRights rights, string expected) =>
        Assert.Equal(expected, InstallTrust.MapRightsVocabulary(rights));

    [Fact]
    public void R1LiveScenario_ProtectedRecordAsInstalled_Accepted()
    {
        // The exact store facts of the first service-shape
        // install (R1, 2026-11-26), with every entry's vocabulary
        // produced by the REAL mapping: record owned by SYSTEM;
        // SYSTEM + Administrators FullControl; the console user
        // Read + Synchronize; the DeskGuestCore service installed
        // but Stopped; this Agent IS the registered image. The
        // pre-fix mapping refused this exact state
        // store-untrusted.
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
            ConsoleSid, InstallTrustServiceState.Stopped, InstallAgent, null);
        Assert.True(decision.Accepted, decision.State);
        Assert.Equal("install_trust_record:ok", decision.State);
        Assert.Equal(InstallTrustPosture.ProtectedService, decision.Posture);
    }
}

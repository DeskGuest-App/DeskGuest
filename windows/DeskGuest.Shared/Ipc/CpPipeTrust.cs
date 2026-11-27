namespace DeskGuest.Shared.Ipc;

/// <summary>
/// BD-WIN-AGENT F3 (Core-side limb): before the Core writes a logon
/// password into the credential-provider pipe, it must prove the
/// pipe SERVER is the real thing — LogonUI.exe (the process that
/// hosts credential providers on the logon/unlock surfaces) running
/// as SYSTEM. The pre-fix client connected to the pipe name blind:
/// a squatter owning the name first would have received the vault
/// password the Core sends. The CP side already refuses non-Core
/// clients and fails on a squatted name (FILE_FLAG_FIRST_PIPE_
/// INSTANCE); this is the matching client-side check. Pure image
/// decision so the test project can pin it; the Core performs the
/// process/token queries itself.
///
/// W10 / V2-C3: the pre-fix decision compared only the FILE NAME —
/// a SYSTEM process could drop a copy named LogonUI.exe anywhere
/// (a writable directory, SysWOW64) and pass. The decision now
/// binds the FULL canonical path: the image must be exactly
/// &lt;SystemRoot&gt;\System32\LogonUI.exe. A bare file name, a
/// relative path, or the right name in any other directory refuses.
/// </summary>
public static class CpPipeTrust
{
    /// <summary>The one legitimate credential-host image path,
    /// under the Windows system root. Path handling here is
    /// string-based Windows semantics ON PURPOSE: the decision is
    /// about Windows paths wherever it runs (the test project pins
    /// it on the Linux build VM, where System.IO.Path would treat
    /// drive-letter paths as relative).</summary>
    public static string ExpectedHostPath(string systemRoot) =>
        WindowsPath.Normalize(systemRoot) + "\\System32\\LogonUI.exe";

    /// <param name="systemRoot">The Windows directory (e.g.
    /// C:\Windows). Null uses this machine's Windows directory —
    /// tests pass it explicitly so the decision stays pure.</param>
    public static bool IsCredentialHostImage(string? imagePath, string? systemRoot = null)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return false;
        var root = systemRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(root)) return false;
        if (!WindowsPath.IsFullyQualified(imagePath)) return false;
        return string.Equals(WindowsPath.Normalize(imagePath), ExpectedHostPath(root),
            StringComparison.OrdinalIgnoreCase);
    }
}

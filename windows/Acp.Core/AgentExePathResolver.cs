namespace Acp.Core;

/// <summary>FR-135 (#15): resolving the Session Agent exe path.
/// The shipped agent binary is `Acp.SessionAgent.exe` (with the
/// dot); the pre-fix fallback named `AcpSessionAgent.exe`, a file
/// that does not exist — so a bare Core launch provisioned the
/// install trust record, the watchdog and the IPC server's
/// expected image with a phantom path, and no agent could ever
/// connect again (fail closed, by design, forever).
///
/// Resolution, in order: an explicit ACP_AGENT_EXE always wins
/// (launchers that set it are untouched); otherwise the sibling
/// that EXISTS — the shipped dotted name preferred, the legacy
/// undotted name honoured when it is the one on disk, so a future
/// rename degrades to the file that is actually there instead of
/// silently re-breaking; when neither exists the canonical
/// shipped name is returned (a correct install carries it, and a
/// broken install then names the file it SHOULD have).</summary>
public static class AgentExePathResolver
{
    public const string ShippedAgentExeName = "Acp.SessionAgent.exe";
    public const string LegacyAgentExeName = "AcpSessionAgent.exe";

    public static string Resolve(string baseDir, string? envValue)
    {
        if (!string.IsNullOrWhiteSpace(envValue)) return envValue;
        var shipped = Path.Combine(baseDir, ShippedAgentExeName);
        if (File.Exists(shipped)) return shipped;
        var legacy = Path.Combine(baseDir, LegacyAgentExeName);
        if (File.Exists(legacy)) return legacy;
        return shipped;
    }
}

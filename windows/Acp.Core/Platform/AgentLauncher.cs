using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Acp.Core.Platform;

/// <summary>How the Core (re)launches the Session Agent in the owner's session
/// (DESIGN §3.4). The watchdog calls this; it never launches blindly —
/// the supervisor owns the decision and the audit entry.</summary>
public interface IAgentLauncher
{
    /// <summary>Launch the agent. Returns false if the launch could not be made.</summary>
    bool Launch(string agentExePath);
}

/// <summary>
/// Windows implementation: WTSQueryUserToken + CreateProcessAsUser into
/// the active console session — the standard systems pattern (DESIGN
/// §3.4). COMPILED here; UNPROVEN-ON-WINDOWS until the kill-the-Agent
/// drill passes on the laptop.
/// </summary>
public sealed class WindowsAgentLauncher : IAgentLauncher
{
    private readonly Func<string?>? _ipcTokenProvider;

    /// <param name="ipcTokenProvider">BD-WIN-CORE-1 F1: supplies the
    /// per-boot IPC token so it can be handed to the agent IN THE
    /// LAUNCH ENVIRONMENT BLOCK (ACP_IPC_TOKEN) — the token is never
    /// written to a file on disk any more, so holding shell/SYSTEM
    /// access no longer means holding the owner's UI credential.
    /// Null keeps the legacy environment (no token variable added).</param>
    public WindowsAgentLauncher(Func<string?>? ipcTokenProvider = null) => _ipcTokenProvider = ipcTokenProvider;

    public bool Launch(string agentExePath)
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (LaunchViaConsoleToken(agentExePath)) return true;
        // W69 (FR-116): the WTS route needs SE_TCB — a SYSTEM-only
        // privilege. A Core running as the console user (the Path B
        // console host) can NEVER hold it, so pre-fix every watchdog
        // relaunch in that shape returned false and the audit filled
        // with agent_relaunch_failed under both the old and the new
        // Core (proven live 2026-11-23; W57's acceptance never hit it
        // because the logon-launched agent stayed up). When THIS
        // process already runs in the active console session, a plain
        // process start lands the child in the right session as the
        // right user by construction — the same facts CreateProcess-
        // AsUser would have asserted — with the same child-environment
        // discipline. A session-0/SYSTEM Core keeps the WTS route
        // only: a plain start from there would strand the agent in
        // session 0, so its failure stays a failure.
        return LaunchSameSession(agentExePath);
    }

    /// <summary>W69: the same-session fallback may fire ONLY when this
    /// process's own session IS the active console session. Pure so
    /// the matrix tests pin it.</summary>
    internal static bool SameSessionFallbackApplies(uint ownSessionId, uint consoleSessionId) =>
        consoleSessionId != 0xFFFFFFFF && ownSessionId == consoleSessionId;

    private bool LaunchSameSession(string agentExePath)
    {
        try
        {
            var consoleSession = NativeMethods.WTSGetActiveConsoleSessionId();
            if (!NativeMethods.ProcessIdToSessionId((uint)Environment.ProcessId, out var ownSession)) return false;
            if (!SameSessionFallbackApplies(ownSession, consoleSession)) return false;
            var source = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
                if (e.Key is string k && e.Value is string v) source[k] = v;
            var vars = BuildChildEnvironment(source, _ipcTokenProvider?.Invoke(), Environment.ProcessPath);
            var psi = new ProcessStartInfo(agentExePath) { UseShellExecute = false };
            psi.Environment.Clear();
            foreach (var (k, v) in vars) psi.Environment[k] = v;
            var dir = Path.GetDirectoryName(agentExePath);
            if (!string.IsNullOrEmpty(dir)) psi.WorkingDirectory = dir;
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }

    private bool LaunchViaConsoleToken(string agentExePath)
    {
        try
        {
            var sessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF) return false; // no console session
            if (!NativeMethods.WTSQueryUserToken(sessionId, out var token)) return false;
            using (token)
            {
                var si = new NativeMethods.STARTUPINFO { cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>(), lpDesktop = @"winsta0\default" };
                var cmdline = $"\"{agentExePath}\"";
                var envBlock = BuildEnvironmentBlock();
                try
                {
                    var ok = NativeMethods.CreateProcessAsUser(
                        token.DangerousGetHandle(), null, cmdline, IntPtr.Zero, IntPtr.Zero, false,
                        NativeMethods.CREATE_UNICODE_ENVIRONMENT, envBlock,
                        Path.GetDirectoryName(agentExePath), ref si, out var pi);
                    if (!ok) return false;
                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);
                    return true;
                }
                finally { if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock); }
            }
        }
        catch { return false; }
    }

    /// <summary>W19 / DS-B-17: the child Agent's environment,
    /// built PURELY so the matrix tests can pin it: this process's
    /// environment, plus ACP_IPC_TOKEN from the provider (when one
    /// is wired), MINUS both dev opt-in variables. Neither
    /// ACP_DEV_ALLOW_NO_TOKEN (IPC posture) nor
    /// ACP_DEV_ALLOW_EPHEMERAL_UPDATE_KEY (update posture) ever
    /// propagates to the child Agent: a dev posture the operator
    /// granted the Core's process is not silently inherited by the
    /// Agent — the Agent's own process must carry its own explicit
    /// opt-in, granted by whoever launches it directly.
    ///
    /// W22 (round-4, B-17 caveat i): a PRE-EXISTING
    /// ACP_IPC_TOKEN in the source environment is stripped FIRST
    /// and re-added only from the provider — when the provider
    /// returns null the child inherits NO token, never a stale or
    /// forged one planted in the Core's own environment. The same
    /// strip-then-set discipline applies to ACP_CORE_EXE (W22 item
    /// 2): the child learns the Core's image path only from the
    /// Core's own process path, never from an inherited value.</summary>
    public static SortedDictionary<string, string> BuildChildEnvironment(
        IReadOnlyDictionary<string, string> source, string? ipcToken, string? coreExePath = null)
    {
        var vars = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in source) vars[k] = v;
        vars.Remove(Shared.Ipc.IpcTrust.DevOptInVariable);
        vars.Remove(DevEphemeralUpdateKeyOptIn.Variable);
        vars.Remove(Shared.Ipc.IpcTokenFile.TokenEnvironmentVariable);
        vars.Remove(Shared.Ipc.IpcTrust.CoreExeEnvironmentVariable);
        if (!string.IsNullOrEmpty(ipcToken)) vars[Shared.Ipc.IpcTokenFile.TokenEnvironmentVariable] = ipcToken;
        if (!string.IsNullOrEmpty(coreExePath)) vars[Shared.Ipc.IpcTrust.CoreExeEnvironmentVariable] = coreExePath;
        return vars;
    }

    /// <summary>The child environment block for CreateProcessAsUser:
    /// BuildChildEnvironment over this process's environment,
    /// marshalled as a Unicode block. Always built (never the
    /// inherit-everything zero block) so the no-propagation rule
    /// above holds even when no IPC token is supplied.</summary>
    private IntPtr BuildEnvironmentBlock()
    {
        var source = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
            if (e.Key is string k && e.Value is string v) source[k] = v;
        var vars = BuildChildEnvironment(source, _ipcTokenProvider?.Invoke(), Environment.ProcessPath);
        var sb = new System.Text.StringBuilder();
        foreach (var (k, v) in vars) sb.Append(k).Append('=').Append(v).Append('\0');
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }

    private static class NativeMethods
    {
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
        [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSQueryUserToken(uint sessionId, out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string? lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }
    }
}

/// <summary>Dev/test launcher: plain process start (used off-Windows and by tests via fakes).</summary>
public sealed class ProcessStartAgentLauncher : IAgentLauncher
{
    public bool Launch(string agentExePath)
    {
        try
        {
            // W19 / DS-B-17: same no-propagation rule as the Windows
            // launcher — the child Agent never inherits either dev
            // opt-in variable from this process.
            // W22: same strip for the IPC token — this launcher has
            // no token provider, so a pre-existing ACP_IPC_TOKEN in
            // this process's environment must NOT ride into the
            // child (stale/forged inheritance); ACP_CORE_EXE is set
            // from THIS process's own path (the Core's launch
            // relationship), replacing any inherited value.
            var psi = new ProcessStartInfo(agentExePath) { UseShellExecute = false };
            psi.Environment.Remove(Shared.Ipc.IpcTrust.DevOptInVariable);
            psi.Environment.Remove(DevEphemeralUpdateKeyOptIn.Variable);
            psi.Environment.Remove(Shared.Ipc.IpcTokenFile.TokenEnvironmentVariable);
            psi.Environment.Remove(Shared.Ipc.IpcTrust.CoreExeEnvironmentVariable);
            if (!string.IsNullOrEmpty(Environment.ProcessPath))
                psi.Environment[Shared.Ipc.IpcTrust.CoreExeEnvironmentVariable] = Environment.ProcessPath!;
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }
}

/// <summary>Records launches instead of performing them (tests).</summary>
public sealed class FakeAgentLauncher : IAgentLauncher
{
    public List<string> Launches { get; } = new();
    public bool Result { get; set; } = true;
    public bool Launch(string agentExePath)
    {
        Launches.Add(agentExePath);
        return Result;
    }
}

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Acp.Shared.Terminal;
using Microsoft.Win32.SafeHandles;

namespace Acp.Core.Services;

/// <summary>
/// The terminal channel's platform component (Block F): a ConPTY
/// pseudo-console per terminal on Windows. The shell is cmd.exe in
/// the SIGNED-IN USER's session, launched with that user's token
/// (WTSQueryUserToken + CreateProcessAsUser, the WindowsAgentLauncher
/// pattern) — BD-WIN-CORE-2/F6: the previous implementation called
/// CreateProcessW from the LocalSystem Core, producing a SYSTEM shell
/// in session 0 while the docstring claimed the host's session. When
/// no interactive console session exists, Start reports the shell as
/// unavailable — it never silently falls back to a SYSTEM shell.
/// Its output is pumped line-by-line back into TerminalService (the
/// session record / replay source). ACP's own authority (floor gate,
/// AI capability, session liveness) lives in TerminalService — this
/// class only owns the OS shell lifecycle: Start spawns it, Write
/// feeds its input pipe, Close kills it. Every failure path disposes
/// the partial shell (pseudo-console + pipe handles) — the previous
/// Fail() early-returns leaked hPc / inWrite / outRead.
///
/// Off Windows there is no ConPTY: Start reports the shell as
/// unavailable through the output channel (the test suites exercise
/// the service with a fake sink; the laptop is the ConPTY proof).
/// </summary>
public sealed class ConPtyTerminalSink : ITerminalSink
{
    private readonly Action<string, string> _onOutput;
    private readonly Dictionary<string, Shell> _shells = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ConPtyTerminalSink(Action<string, string> onOutput) => _onOutput = onOutput;

    private sealed class Shell : IDisposable
    {
        public IntPtr PseudoConsole;
        public IntPtr ProcessHandle;
        public FileStream? Input;
        public FileStream? Output;
        public CancellationTokenSource Cts = new();
        public void Dispose()
        {
            Cts.Cancel();
            try { Input?.Dispose(); } catch { }
            try { Output?.Dispose(); } catch { }
            if (ProcessHandle != IntPtr.Zero) { TerminateProcess(ProcessHandle, 0); CloseHandle(ProcessHandle); }
            if (PseudoConsole != IntPtr.Zero) ClosePseudoConsole(PseudoConsole);
        }
    }

    public void Start(string terminalId)
    {
        if (!OperatingSystem.IsWindows())
        {
            _onOutput(terminalId, "(terminal shell unavailable: ConPTY is a Windows platform component)");
            return;
        }
        lock (_gate)
        {
            if (_shells.ContainsKey(terminalId)) return;
            var shell = StartConPty(terminalId);
            if (shell is not null) _shells[terminalId] = shell;
        }
    }

    public void Write(string terminalId, string text)
    {
        Shell? shell;
        lock (_gate) _shells.TryGetValue(terminalId, out shell);
        if (shell?.Input is null) return;
        try
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            shell.Input.Write(bytes, 0, bytes.Length);
            shell.Input.Flush();
        }
        catch { /* a dead shell surfaces through its output ending */ }
    }

    public void Close(string terminalId)
    {
        Shell? shell;
        lock (_gate) { if (_shells.Remove(terminalId, out shell)) { } }
        shell?.Dispose();
    }

    private Shell? StartConPty(string terminalId)
    {
        // Standard ConPTY sequence: pipes → pseudo console →
        // CreateProcessW with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE →
        // pump the output pipe on a thread.
        if (!CreatePipe(out var inRead, out var inWrite, IntPtr.Zero, 0)) return Fail(terminalId, "CreatePipe (input)");
        if (!CreatePipe(out var outRead, out var outWrite, IntPtr.Zero, 0)) return Fail(terminalId, "CreatePipe (output)");
        var hr = CreatePseudoConsole(new Coord { X = 120, Y = 30 }, inRead, outWrite, 0, out var hPc);
        CloseHandle(inRead); CloseHandle(outWrite);
        if (hr != 0) { CloseHandle(inWrite); CloseHandle(outRead); return Fail(terminalId, $"CreatePseudoConsole 0x{hr:X8}"); }

        var attrSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
        var attrList = Marshal.AllocHGlobal(attrSize);
        var shell = new Shell { PseudoConsole = hPc };
        var handlesTransferred = false;
        try
        {
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) return Fail(terminalId, "InitializeProcThreadAttributeList");
            if (!UpdateProcThreadAttribute(attrList, 0, (IntPtr)0x20016 /* PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE */, hPc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                return Fail(terminalId, "UpdateProcThreadAttribute");
            var si = new StartupInfoEx
            {
                StartupInfo = new StartupInfo { Cb = Marshal.SizeOf<StartupInfoEx>(), Flags = 0, Desktop = @"winsta0\default" },
                AttributeList = attrList,
            };
            // The user's own token (F6): no token, no shell — never a
            // SYSTEM shell in session 0 wearing the user's name.
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF) return Fail(terminalId, "no interactive console session; a user-session terminal is unavailable rather than a SYSTEM shell");
            if (!WTSQueryUserToken(sessionId, out var userToken)) return Fail(terminalId, "WTSQueryUserToken " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
            using (userToken)
            {
                var envBlock = IntPtr.Zero;
                CreateEnvironmentBlock(out envBlock, userToken.DangerousGetHandle(), false);
                try
                {
                    var cmdline = new StringBuilder("cmd.exe");
                    if (!CreateProcessAsUser(userToken.DangerousGetHandle(), null, cmdline, IntPtr.Zero, IntPtr.Zero, false,
                            0x00080000 /* EXTENDED_STARTUPINFO_PRESENT */ | 0x00000400 /* CREATE_UNICODE_ENVIRONMENT */,
                            envBlock, null, ref si, out var pi))
                        return Fail(terminalId, "CreateProcessAsUser " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    shell.ProcessHandle = pi.Process;
                    CloseHandle(pi.Thread);
                }
                finally { if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock); }
            }
            shell.Input = new FileStream(new SafeFileHandle(inWrite, ownsHandle: true), FileAccess.Write);
            shell.Output = new FileStream(new SafeFileHandle(outRead, ownsHandle: true), FileAccess.Read);
            handlesTransferred = true;
            var output = shell.Output;
            var token = shell.Cts.Token;
            _ = Task.Run(() =>
            {
                try
                {
                    using var reader = new StreamReader(output, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
                    string? line;
                    while (!token.IsCancellationRequested && (line = reader.ReadLine()) is not null)
                        _onOutput(terminalId, line);
                }
                catch { /* shell exit ends the pump */ }
            }, token);
            return shell;
        }
        finally
        {
            DeleteProcThreadAttributeList(attrList);
            Marshal.FreeHGlobal(attrList);
            if (!handlesTransferred)
            {
                // F6 leak fix: every failure path above returns through
                // here — the pseudo-console and both pipe handles the
                // Shell never took ownership of are closed, not leaked.
                CloseHandle(inWrite);
                CloseHandle(outRead);
                shell.Dispose(); // closes hPc (and the process handle if one was created)
            }
        }

        Shell? Fail(string id, string what)
        {
            _onOutput(id, $"(terminal shell failed to start: {what})");
            return null;
        }
    }

    // ---- ConPTY / process P/Invoke --------------------------------

    [StructLayout(LayoutKind.Sequential)] private struct Coord { public short X; public short Y; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Cb; public string? Reserved; public string? Desktop; public string? Title;
        public int X; public int Y; public int XSize; public int YSize; public int XCountChars; public int YCountChars;
        public int FillAttribute; public int Flags; public short ShowWindow; public short Reserved2Count;
        public IntPtr Reserved2; public IntPtr StdInput; public IntPtr StdOutput; public IntPtr StdError;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr AttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { public IntPtr Process; public IntPtr Thread; public int ProcessId; public int ThreadId; }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, IntPtr attrs, int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern int CreatePseudoConsole(Coord size, IntPtr input, IntPtr output, int flags, out IntPtr pseudoConsole);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern void ClosePseudoConsole(IntPtr pseudoConsole);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, int flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr prevValue, IntPtr returnSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint sessionId, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr hToken, string? appName, StringBuilder commandLine, IntPtr procAttrs, IntPtr threadAttrs, bool inheritHandles, int flags, IntPtr env, string? cwd, ref StartupInfoEx startupInfo, out ProcessInformation processInfo);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, int exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
}

using System.Runtime.InteropServices;

namespace DeskGuest.SessionAgent;

/// <summary>
/// Win32 interop for the desktop plane: SendInput, capture support,
/// foreground/lock detection. UNPROVEN-ON-WINDOWS: compiled in the
/// Linux build VM, first exercised at the laptop gate (DESIGN §8).
/// </summary>
internal static class NativeMethods
{
    // ---- Input (SendInput) ----
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public InputUnion U; }
    [StructLayout(LayoutKind.Explicit)]
    public struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT
    {
        public int dx, dy;
        public uint mouseData, dwFlags, time;
        public IntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT
    {
        public ushort wVk, wScan;
        public uint dwFlags, time;
        public IntPtr dwExtraInfo;
    }

    public const uint INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
    public const uint MOUSEEVENTF_MOVE = 0x0001, MOUSEEVENTF_LEFTDOWN = 0x0002, MOUSEEVENTF_LEFTUP = 0x0004,
        MOUSEEVENTF_RIGHTDOWN = 0x0008, MOUSEEVENTF_RIGHTUP = 0x0010, MOUSEEVENTF_MIDDLEDOWN = 0x0020,
        MOUSEEVENTF_MIDDLEUP = 0x0040, MOUSEEVENTF_WHEEL = 0x0800, MOUSEEVENTF_ABSOLUTE = 0x8000,
        MOUSEEVENTF_VIRTUALDESK = 0x4000;
    public const uint KEYEVENTF_KEYUP = 0x0002, KEYEVENTF_UNICODE = 0x0004;

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT lpPoint);

    // ---- FR-120 local-input watch (W73) ----
    // GetLastInputInfo reports the tick of the last input event
    // the session received. W107 HONESTY FIX (W106-verified C1):
    // an earlier comment here claimed SendInput-injected events
    // do NOT advance this tick. That is NOT proven and must not
    // be asserted: W73's own live record shows the windows-mcp
    // bridge's injected input DID advance this laptop's tick (the
    // watcher fired on it exactly as designed), and the agent's
    // own SendInput path was never separately proven either way.
    // The watcher therefore treats the tick as "input arrived",
    // with no injected-vs-physical distinction — see
    // LocalInputClassification for the named limit.
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
    public const int VK_BACK = 0x08, VK_CONTROL = 0x11, VK_MENU = 0x12, VK_SHIFT = 0x10;

    // ---- W107: wheel watch (WH_MOUSE_LL) ----
    // The wheel has no pollable state (no VK, no async key state),
    // so the watcher observes it through a low-level mouse hook
    // on its own message-loop thread. Only WM_MOUSEWHEEL /
    // WM_MOUSEHWHEEL are consumed; everything is passed on.
    public const int WH_MOUSE_LL = 14;
    public const uint WM_MOUSEWHEEL = 0x020A, WM_MOUSEHWHEEL = 0x020E;
    public delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct MSLLHOOKSTRUCT { public POINT pt; public uint mouseData; public uint flags; public uint time; public IntPtr dwExtraInfo; }
    /// <summary>MSLLHOOKSTRUCT.flags bit: the event was injected
    /// (SendInput / SetCursorPos class) rather than physical.</summary>
    public const uint LLMHF_INJECTED = 0x00000001;

    // ---- FR-141: physical-input watch (WH_KEYBOARD_LL) ----
    // A low-level hook event is the one signal that carries the
    // injected-vs-physical distinction: KBDLLHOOKSTRUCT.flags
    // sets LLKHF_INJECTED for synthesised events (any process's
    // SendInput) and clears it for real device input. The watcher
    // counts physical key-downs through this hook so a genuine
    // owner keystroke is never suppressed by the agent's own
    // self-input window — see LocalSignalGate (DeskGuest.Shared).
    public const int WH_KEYBOARD_LL = 13;
    public const uint WM_KEYDOWN = 0x0100, WM_SYSKEYDOWN = 0x0104;
    public const uint LLKHF_INJECTED = 0x00000010;
    public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT { public uint vkCode; public uint scanCode; public uint flags; public uint time; public IntPtr dwExtraInfo; }
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")]
    public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] public static extern bool PostThreadMessage(uint idThread, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    public const uint WM_QUIT = 0x0012;
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    [DllImport("user32.dll")] public static extern bool LockWorkStation();

    // ---- Window close (BD-WIN-AGENT F9: WM_CLOSE, never SW_HIDE) ----
    [DllImport("user32.dll", SetLastError = true)] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    public const uint WM_CLOSE = 0x0010;

    // ---- Service Control Manager status (W35) ----
    // Unprivileged reads: SC_MANAGER_CONNECT + SERVICE_QUERY_STATUS
    // are granted to Authenticated Users by default; no elevation,
    // no service control. Used ONLY to read DeskGuestCore's running state
    // for the install-trust shape detection (shape in force).
    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode,
            dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out SERVICE_STATUS_PROCESS status, int bufferSize, out int bytesNeeded);
    [DllImport("advapi32.dll")] public static extern bool CloseServiceHandle(IntPtr handle);
    public const uint SC_MANAGER_CONNECT = 0x0001, SERVICE_QUERY_STATUS = 0x0004;
    public const int SC_STATUS_PROCESS_INFO = 0;
    public const uint SERVICE_RUNNING = 0x00000004;

    // ---- Pipe server identity (BD-WIN-AGENT F4) ----
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X, Y; }

    // ---- Input desktop (lock detection) ----
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);
    // CharSet.Unicode is load-bearing: without it this binds to the ANSI
    // variant, the desktop name comes back as ANSI bytes, and the
    // caller's Unicode decode garbles "Default" — which made
    // InputDesktopIsDefault() report a locked desktop forever on the
    // first live install (2026-11-14).
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, byte[] pvInfo, uint nLength, out uint lpnLengthNeeded);
    [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr hDesktop);
    public const int UOI_NAME = 2;
    private const uint DESKTOP_READOBJECTS = 0x0001;

    /// <summary>True when the input desktop is the user's Default desktop;
    /// on the secure (Winlogon) desktop this reads "Winlogon" and desktop
    /// tools must report LOGON_LOCKED rather than fake results.</summary>
    public static bool InputDesktopIsDefault()
    {
        var desktop = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        if (desktop == IntPtr.Zero) return false;
        try
        {
            var buffer = new byte[256];
            if (!GetUserObjectInformation(desktop, UOI_NAME, buffer, (uint)buffer.Length, out _)) return false;
            var name = System.Text.Encoding.Unicode.GetString(buffer).TrimEnd('\0');
            return string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase);
        }
        finally { CloseDesktop(desktop); }
    }

    // ---- Extended window styles (presence click-through) ----
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll")] public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TRANSPARENT = 0x00000020, WS_EX_LAYERED = 0x00080000, WS_EX_NOACTIVATE = 0x08000000;

    // ---- Physical-pixel window placement (ghost cursor, M1) ----
    // WPF Left/Top are device-independent units; agent input
    // coordinates are physical pixels. Positioning the ghost through
    // SetWindowPos keeps it exactly on the acted point at any DPI.
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    public static readonly IntPtr HWND_TOPMOST = new(-1);
    public const uint SWP_NOSIZE = 0x0001, SWP_NOACTIVATE = 0x0010, SWP_SHOWWINDOW = 0x0040;
}

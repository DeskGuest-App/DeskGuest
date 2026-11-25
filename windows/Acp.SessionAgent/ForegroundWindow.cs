using System.Diagnostics;
using System.Text;

namespace Acp.SessionAgent;

/// <summary>
/// The protected-targets foreground feed (DESIGN §6.5, inspector M5):
/// the current foreground window's title and owning process name,
/// reported to the Core over IPC so the policy engine can match them
/// against the owner's protected-targets set. Title and process NAME only
/// — no content is ever read or captured here. UNPROVEN-ON-WINDOWS.
/// </summary>
public static class ForegroundWindow
{
    public static (string? Title, string? Process) Current()
    {
        try
        {
            var hwnd = NativeMethods.GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return (null, null);
            var sb = new StringBuilder(512);
            var len = NativeMethods.GetWindowText(hwnd, sb, sb.Capacity);
            var title = len > 0 ? sb.ToString() : null;
            string? process = null;
            if (NativeMethods.GetWindowThreadProcessId(hwnd, out var pid) != 0 && pid != 0)
            {
                try { process = Process.GetProcessById((int)pid).ProcessName; } catch { /* process exited mid-read */ }
            }
            return (title, process);
        }
        catch { return (null, null); }
    }
}

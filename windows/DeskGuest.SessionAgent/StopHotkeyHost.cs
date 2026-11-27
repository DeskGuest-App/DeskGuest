using System.Runtime.InteropServices;
using System.Windows.Interop;
using DeskGuest.Shared.Design;

namespace DeskGuest.SessionAgent;

/// <summary>
/// W9 Task 4: the fixture-chosen STOP hotkey, live. The chord comes
/// from StopHotkeyFixture.DefaultChord (Ctrl+Alt+Shift+F9 on the
/// 2026-11-23 run) — never a literal here, so a future fixture run
/// re-points the registration by changing the fixture alone.
/// Registered globally for the agent's lifetime with MOD_NOREPEAT;
/// Windows consumes the chord (it is never forwarded anywhere, and
/// the agent never injects it). A press runs the same user-stop the
/// tray and the window send. Registration is non-disableable by
/// design — there is no setting, here or anywhere, that turns it
/// off. If registration itself fails on a machine (chord already
/// held), RegisteredSuccessfully says so and the Box STOP remains
/// the floor, exactly as the design law provides.
/// </summary>
public sealed class StopHotkeyHost : IDisposable
{
    private const int HotkeyId = 0xAC95;
    private const int WmHotkey = 0x0312;
    private const uint ModAlt = 0x0001;
    private const uint ModControl = 0x0002;
    private const uint ModShift = 0x0004;
    private const uint ModWin = 0x0008;
    private const uint ModNoRepeat = 0x4000;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    private readonly HwndSource _source;
    private readonly Func<Task> _onStop;
    private bool _disposed;

    public bool RegisteredSuccessfully { get; }

    public StopHotkeyHost(Func<Task> onStop)
    {
        _onStop = onStop;
        var parameters = new HwndSourceParameters("DeskGuestStopHotkeyHost")
        {
            ParentWindow = new IntPtr(-3), // HWND_MESSAGE: message-only window
            WindowStyle = 0,
        };
        _source = new HwndSource(parameters);
        _source.AddHook(WndProc);

        var chord = StopHotkeyFixture.DefaultChord;
        if (chord is null) { RegisteredSuccessfully = false; return; }
        uint mods = ModNoRepeat;
        if (chord.Modifiers.Contains("Ctrl")) mods |= ModControl;
        if (chord.Modifiers.Contains("Alt")) mods |= ModAlt;
        if (chord.Modifiers.Contains("Shift")) mods |= ModShift;
        if (chord.Modifiers.Contains("Win")) mods |= ModWin;
        RegisteredSuccessfully = RegisterHotKey(_source.Handle, HotkeyId, mods, VirtualKeyFor(chord.Key));
    }

    private static uint VirtualKeyFor(string key)
    {
        // F-row keys map to VK_F1..VK_F24 (0x70..0x87); the fixture's
        // pool is F-row only — anything else is a fixture bug and
        // must fail loudly at startup, never silently register 0.
        if (key.Length >= 2 && key[0] == 'F' && int.TryParse(key.AsSpan(1), out var n) && n is >= 1 and <= 24)
            return (uint)(0x70 + n - 1);
        throw new InvalidOperationException($"StopHotkeyFixture produced a non-F-row key '{key}'; the host registers F-row chords only.");
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmHotkey && wParam.ToInt32() == HotkeyId)
        {
            handled = true;
            _ = _onStop();
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { UnregisterHotKey(_source.Handle, HotkeyId); } catch { }
        _source.RemoveHook(WndProc);
        _source.Dispose();
    }
}

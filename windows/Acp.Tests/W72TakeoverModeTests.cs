using Acp.Shared.Presence;

namespace Acp.Tests;

/// <summary>
/// W72 / FR-120 — the tunable-takeover READ POINT. This lane
/// ships the vocabulary, the one settings home, and the yield
/// decision; the modes' full behaviour, settings UI and the
/// session-record field are W73. Pinned here: the default is
/// TakeOver (the owner's stated default for mouse), only
/// TakeOver yields, the settings home (PresencePalette — the
/// device's own DeskGuest instance state) defaults both modes
/// to TakeOver and parses fail-safe, and the presence layer
/// consults the mode at exactly one read point which the STOP
/// path never touches. (PresencePalette lives in the WPF
/// SessionAgent, which this project source-pins rather than
/// references — the W60 pattern.)
/// </summary>
public class W72TakeoverModeTests
{
    private static string AgentFile(string file)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var rel in new[] { Path.Combine("src", "Acp.SessionAgent", file),
                                        Path.Combine("windows-agent", "src", "Acp.SessionAgent", file) })
            {
                var c = Path.Combine(dir.FullName, rel);
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Acp.SessionAgent/" + file + " not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Default_mode_is_take_over()
    {
        Assert.Equal(TakeoverMode.TakeOver, TakeoverModes.Default);
    }

    [Fact]
    public void Only_take_over_yields()
    {
        Assert.True(TakeoverModes.LocalInputYields(TakeoverMode.TakeOver));
        Assert.False(TakeoverModes.LocalInputYields(TakeoverMode.Share));
        Assert.False(TakeoverModes.LocalInputYields(TakeoverMode.HotkeyOnly));
    }

    [Fact]
    public void Settings_home_defaults_both_modes_to_take_over_and_parses_fail_safe()
    {
        var palette = AgentFile("PresencePalette.cs");
        Assert.Contains("public string MouseTakeoverMode { get; set; } = nameof(TakeoverMode.TakeOver);", palette);
        Assert.Contains("public string KeyboardTakeoverMode { get; set; } = nameof(TakeoverMode.TakeOver);", palette);
        // Fail-safe parse: anything unrecognized resolves to TakeOver.
        Assert.Contains("Enum.TryParse<TakeoverMode>(MouseTakeoverMode, ignoreCase: true, out var m) ? m : TakeoverMode.TakeOver", palette);
        Assert.Contains("Enum.TryParse<TakeoverMode>(KeyboardTakeoverMode, ignoreCase: true, out var m) ? m : TakeoverMode.TakeOver", palette);
    }

    [Fact]
    public void Yield_read_point_is_single_and_stop_never_consults_it()
    {
        // W73 SUPERSEDES the count half of this pin: FR-120's full
        // implementation wires the KEYBOARD read point beside the
        // mouse one (the lane's explicit item 1), so each class
        // mode is now consulted at the state-machine call in its
        // own entry point. What stands from W72: the decision is
        // never hard-coded — both entry points feed the shared
        // TakeoverStateMachine with the palette's active modes,
        // and STOP still never consults a mode (pinned in full by
        // W73TakeoverTests.Stop_paths_never_consult_a_takeover_mode).
        var code = AgentFile("Presence.cs");
        Assert.Contains("_takeover.LocalInput(TakeoverInputClass.Mouse,", code);
        Assert.Contains("_takeover.LocalInput(TakeoverInputClass.Keyboard,", code);
        Assert.Contains("_palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode", code);
    }
}

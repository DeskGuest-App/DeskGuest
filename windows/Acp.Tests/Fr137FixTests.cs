using Acp.Core;

namespace Acp.Tests;

/// <summary>
/// FR-137 — the Core supervisor appended a bogus stop_file_cleared
/// audit entry roughly once a second while a USER stop was
/// latched. The supervisor compared the STOP file's presence
/// against the combined StopInForce (file OR user stop); with a
/// user stop latched and no file present, the comparison read as
/// a fresh transition on every tick.
///
/// Pins: the two stop facts are independent in CoreState (the
/// file's own state is readable apart from the combined state,
/// and neither fact's changes disturb the other), and the
/// supervisor's transition test compares against the file's own
/// recorded state.
/// </summary>
public class Fr137FixTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(string.Join("/", parts) + " not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void UserStopLatched_NoFile_TheFileFactStaysAbsentAcrossTicks()
    {
        // The FR-137 state, held steady: the supervisor's
        // transition test (file present != recorded file state)
        // must read "no transition" on every tick.
        var state = new CoreState();
        state.SetStopFilePresent(false);
        state.SetUserStop(true);
        Assert.True(state.StopInForce);       // the stop IS in force
        Assert.False(state.StopFilePresent);  // but not via the file
        for (var tick = 0; tick < 5; tick++)
            Assert.False(false != state.StopFilePresent); // no transition, ever
    }

    [Fact]
    public void FileTransitions_RegisterIndependentlyOfTheUserStop()
    {
        var state = new CoreState();
        state.SetUserStop(true);
        state.SetStopFilePresent(true);
        Assert.True(state.StopFilePresent);
        Assert.True(state.StopInForce);
        // The file goes away; the user stop still holds the force.
        state.SetStopFilePresent(false);
        Assert.False(state.StopFilePresent);
        Assert.True(state.StopInForce);
        // And the reverse: clearing the user stop with the file
        // present keeps the force via the file.
        state.SetStopFilePresent(true);
        state.SetUserStop(false);
        Assert.True(state.StopFilePresent);
        Assert.True(state.StopInForce);
    }

    [Fact]
    public void Supervisor_ComparesTheFileAgainstItsOwnRecordedState()
    {
        var runtime = SrcFile("Acp.Core", "CoreRuntime.cs");
        Assert.Contains("stopPresent != State.StopFilePresent", runtime);
        Assert.DoesNotContain("stopPresent != State.StopInForce", runtime);
    }
}

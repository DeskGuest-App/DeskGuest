using Acp.Shared.Design;

namespace Acp.Tests;

/// <summary>W103 / S09(a) — the agent-detail identity is the
/// signed ring-with-initial: the pairing name's initial centered
/// in a ring whose color follows the pairing's state family (the
/// PresenceLaw hues). The initial derives from the REAL pairing
/// name at render — never stored art — through the same
/// derivation the pill face and the Ghost use. The gold tile +
/// A3 mark strip it replaced is gone from the page builder.</summary>
public class W103RingIdentityTests
{
    private static string SrcDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AcpWindows.slnx")))
            dir = dir.Parent;
        return dir!.FullName;
    }

    private static string ReadSrc(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { SrcDir() }.Concat(parts).ToArray()));

    // ---- the initial derivation (the app's own, shared) --------

    [Fact]
    public void Initial_DerivesFromTheRealPairingName()
    {
        Assert.Equal("A", PresenceLaw.GhostInitial("Axle"));
        Assert.Equal("P", PresenceLaw.GhostInitial("Parity Proof"));
        Assert.Equal("M", PresenceLaw.GhostInitial("muse"));
        Assert.Equal("W", PresenceLaw.GhostInitial("  W97 Proof"));
    }

    [Fact]
    public void Initial_EmptyNameFallsBackToQuestionMark_NeverBlank()
    {
        Assert.Equal("?", PresenceLaw.GhostInitial(""));
        Assert.Equal("?", PresenceLaw.GhostInitial(null!));
    }

    // ---- the state hues are the app's real state colors --------

    [Fact]
    public void StateHues_AreThePresenceLawFamily()
    {
        Assert.Equal(unchecked((int)0xFF7C4DFF), PresenceLaw.HueAi);    // violet — AI acting
        Assert.Equal(unchecked((int)0xFFF2A900), PresenceLaw.HueIdle);  // amber — waiting
        Assert.Equal(unchecked((int)0xFFDC2626), PresenceLaw.HueStop);  // red — stopped
        Assert.Equal(unchecked((int)0xFFF2EEDF), PresenceLaw.PillFaceCream);
    }

    // ---- the surface's source shape -----------------------------

    [Fact]
    public void Surface_IdentityIsRingWithInitial_NotTheGoldTile()
    {
        var page = ReadSrc("Acp.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("BuildIdentityRing(pname, revoked)", page);
        Assert.Contains("PresenceLaw.GhostInitial(pname)", page);   // initial from the real name at render
        Assert.Contains("PresenceLaw.PillFaceCream", page);         // the pill face's disc token
        Assert.Contains("IdentityRingArgb", page);
        Assert.DoesNotContain("deskguest-mark-tight", page);        // the A3 mark strip is gone from this page
    }

    [Fact]
    public void Surface_RingColorFollowsThePairingsStateFamily()
    {
        var page = ReadSrc("Acp.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("PresenceLaw.HueAi", page);                 // live session → AI family
        Assert.Contains("PresenceLaw.HueIdle", page);               // not connected → waiting family
        Assert.Contains("PresenceLaw.HueStop", page);               // revoked → stopped
        Assert.Contains("_host.SessionAgent == pname", page);       // live state from the snapshot, not stored
        Assert.Contains("|sess:", page);                           // re-renders when the session state moves
    }
}

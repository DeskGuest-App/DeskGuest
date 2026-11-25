using Acp.Launcher;
using Acp.Shared.Input;
using Acp.Shared.Ipc;
using Acp.Shared.Streaming;
using Acp.Shared.Tools;
using Acp.Shared.Update;

namespace Acp.Tests;

// BD-WIN-AGENT fix lane (Wave 6A) — permanent regression tests for
// the reconciled bd-win-agent packet (768f74ef). The Session Agent
// and Credential Provider bodies are WPF/native and cannot run in
// this harness; every finding's decision logic was factored into
// pure Acp.Shared seams by the original fix, and those seams are
// pinned here. F1 (CP serialization) and the CP pipe protocol are
// native-only: their invariants live in the .cpp source and remain
// UNPROVEN-ON-WINDOWS (named remainder, supervised LogonUI proof).
public class BdWinAgentFixTests
{
    // ================= F4: IPC trust fails closed =================

    [Fact]
    public void IpcTrust_TokenPresent_Authenticates()
        => Assert.Equal(IpcTrustPosture.Authenticated, IpcTrust.Decide("abc123", null));

    [Fact]
    public void IpcTrust_NoTokenNoOptIn_Refuses()
        => Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, null));

    [Fact]
    public void IpcTrust_NoTokenBlankOptIn_Refuses()
        => Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide("", "yes"));

    [Fact]
    public void IpcTrust_NoTokenExplicitDevOptIn_DevUnauthenticated()
        => Assert.Equal(IpcTrustPosture.DevUnauthenticated, IpcTrust.Decide(null, "1"));

    // W22: the binding is the EXPECTED FULL PATH from the agent's
    // launch/install relationship (here: the agent image beside
    // the Core in the install root). The pre-W22 theory pinned
    // name-only acceptance — C:\ACP\Acp.Core.exe passed from ANY
    // directory; that is exactly the fake-Core leg the round-4 exploit chain used, and it now refuses. The full
    // W22 matrix (override, split dirs, unestablishable path)
    // lives in W22WinHardenTests.
    [Theory]
    [InlineData(@"C:\Program Files\ACP\AcpCore.exe", true)]
    [InlineData(@"C:\Program Files\ACP\Acp.Core.exe", true)]
    [InlineData(@"C:\ACP\Acp.Core.exe", false)] // right name, wrong directory (pre-W22: accepted)
    [InlineData(@"C:\evil\AcpCore.exe", false)] // right name, attacker directory (pre-W22: accepted)
    [InlineData(@"C:\evil\AcpCore.exe.exe", false)]
    [InlineData(@"C:\evil\Notepad.exe", false)]
    // W10 / V2-C3: a bare file name is not an OS-reported image path.
    [InlineData(@"AcpCore.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IpcTrust_CoreServerImage(string? path, bool expected)
        => Assert.Equal(expected, IpcTrust.IsCoreServerImage(path, @"C:\Program Files\ACP\Acp.SessionAgent.exe"));

    // ================= F3: CP pipe server identity (Core side) ===

    [Theory]
    [InlineData(@"C:\Windows\System32\LogonUI.exe", true)]
    [InlineData(@"C:\Windows\System32\logonui.exe", true)] // case-insensitive
    // W10 / V2-C3: the pre-fix name-only check accepted the right
    // NAME in ANY directory — including SysWOW64, which this theory
    // previously pinned as TRUE. The full-path binding refuses all
    // of these: LogonUI legitimately lives only in System32.
    [InlineData(@"C:\Windows\SysWOW64\logonui.exe", false)]
    [InlineData(@"C:\evil\LogonUI.exe", false)]
    [InlineData(@"LogonUI.exe", false)] // bare name: not an OS-reported path
    [InlineData(@"C:\evil\LogonUI.exe.exe", false)]
    [InlineData(@"C:\evil\AcpCore.exe", false)]
    [InlineData(null, false)]
    public void CpPipeTrust_OnlyLogonUiHostsTheProvider(string? path, bool expected)
        => Assert.Equal(expected, CpPipeTrust.IsCredentialHostImage(path, @"C:\Windows"));

    // ================= F5: STOP precedence ========================

    [Fact]
    public void StopCoordinator_CancelCancelsInFlight_AndArmsFreshToken()
    {
        using var stop = new StopCoordinator();
        var inFlight = stop.CurrentToken;
        Assert.False(inFlight.IsCancellationRequested);
        stop.CancelCurrentWork();
        Assert.True(inFlight.IsCancellationRequested);
        var next = stop.CurrentToken;
        Assert.False(next.IsCancellationRequested);
        Assert.NotEqual(inFlight, next);
    }

    [Fact]
    public void StopCoordinator_CancelWithNothingRunning_IsHarmless()
    {
        using var stop = new StopCoordinator();
        Assert.True(stop.CancelCurrentWork());
        Assert.False(stop.CurrentToken.IsCancellationRequested);
    }

    // ================= F7: the one input guard ====================

    [Theory]
    [InlineData("ctrl+alt+del")]
    [InlineData("alt+ctrl+del")]
    [InlineData("control+alt+delete")]
    [InlineData("DELETE+ALT+CONTROL")]
    [InlineData("win+l")]
    [InlineData("l+win")]
    [InlineData("windows+l")]
    [InlineData("l+windows")]
    public void InputGuard_ForbiddenCombos_EverySpellingAndOrder(string keys)
    {
        var chord = InputGuard.ParseChord(keys);
        Assert.NotNull(chord);
        Assert.True(InputGuard.IsForbiddenCombo(chord!));
    }

    [Theory]
    [InlineData("ctrl+alt+shift")]
    [InlineData("ctrl+c")]
    [InlineData("win+r")]
    [InlineData("alt+f4")]
    public void InputGuard_OrdinaryChords_AreNotForbidden(string keys)
    {
        var chord = InputGuard.ParseChord(keys);
        Assert.NotNull(chord);
        Assert.False(InputGuard.IsForbiddenCombo(chord!));
    }

    [Fact]
    public void InputGuard_SplitKeyDown_CompletingCombo_IsCaught()
    {
        // The bypass the per-tool checks missed: assemble SAS one
        // key_down at a time. The completing key must be refused.
        var held = new[] { InputGuard.VkControl, InputGuard.VkAlt };
        Assert.True(InputGuard.WouldCompleteForbiddenCombo(held, InputGuard.VkDelete));
        Assert.False(InputGuard.WouldCompleteForbiddenCombo(held, (ushort)'A'));
        var heldWin = new[] { InputGuard.VkLWin };
        Assert.True(InputGuard.WouldCompleteForbiddenCombo(heldWin, (ushort)'L'));
    }

    [Fact]
    public void InputGuard_PasteChord_AndTextKeys_NeedCredentialCheck()
    {
        var paste = InputGuard.ParseChord("ctrl+v")!;
        Assert.True(InputGuard.IsPasteChord(paste));
        Assert.True(InputGuard.NeedsCredentialFieldCheck(paste));
        Assert.True(InputGuard.NeedsCredentialFieldCheck(new[] { (ushort)'A' }));
        Assert.True(InputGuard.NeedsCredentialFieldCheck(new[] { InputGuard.VkReturn }));
        // A pure modifier press types nothing: no credential check.
        Assert.False(InputGuard.NeedsCredentialFieldCheck(new[] { InputGuard.VkControl }));
    }

    [Fact]
    public void InputGuard_UnknownKey_RefusesWholeChord()
    {
        Assert.Null(InputGuard.ParseChord("ctrl+banana"));
        Assert.Null(InputGuard.ParseChord(""));
        Assert.Equal((ushort)0, InputGuard.VirtualKeyFor("banana"));
        Assert.Equal(InputGuard.VkDelete, InputGuard.VirtualKeyFor("delete"));
        Assert.Equal(InputGuard.VkControl, InputGuard.VirtualKeyFor("control"));
    }

    // ================= F10: open_url scope ========================

    [Theory]
    [InlineData("https://example.com/page", true)]
    [InlineData("http://192.168.1.10:8080/", true)]
    [InlineData("mailto:ops@example.com", true)]
    [InlineData("file:///C:/Windows/System32/calc.exe", false)]
    [InlineData(@"C:\tools\run.bat", false)]
    [InlineData("ms-settings:display", false)]
    [InlineData("search-ms:query=x", false)]
    [InlineData("https://", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OpenUrlPolicy_OnlyBrowserSchemes(string? url, bool allowed)
        => Assert.Equal(allowed, OpenUrlPolicy.IsAllowed(url));

    // ================= F12: stream ring gap =======================

    [Theory]
    [InlineData(0, 50, 90, true)]    // fell behind the ring: gap
    [InlineData(49, 50, 90, false)]  // next needed frame is the oldest: fine
    [InlineData(89, 50, 90, false)]  // one behind the newest: fine
    [InlineData(90, 50, 90, false)]  // caught up: empty answer is honest
    [InlineData(0, 0, 0, false)]     // nothing encoded yet
    public void RingGap_DetectsMissedFrames(long after, long oldest, long newest, bool expected)
        => Assert.Equal(expected, RingGap.HasGap(after, oldest, newest));

    // ================= F6: launcher slot integrity ================

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "acp-w6-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void SlotIntegrity_TamperedSlot_FailsVerification()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "AcpCore.exe"), "core-v1");
            File.WriteAllText(Path.Combine(dir, "Acp.SessionAgent.exe"), "agent-v1");
            var hash = SlotIntegrity.ContentHash(dir);
            Assert.True(SlotIntegrity.Verify(dir, hash));
            // Destruction: one flipped byte in the agent binary.
            File.WriteAllText(Path.Combine(dir, "Acp.SessionAgent.exe"), "agent-vX");
            Assert.False(SlotIntegrity.Verify(dir, hash));
            // A dropped-in extra file also breaks the anchor.
            File.WriteAllText(Path.Combine(dir, "Acp.SessionAgent.exe"), "agent-v1");
            File.WriteAllText(Path.Combine(dir, "evil.exe"), "payload");
            Assert.False(SlotIntegrity.Verify(dir, hash));
            // No anchor at all: never verified.
            Assert.False(SlotIntegrity.Verify(dir, null));
            Assert.False(SlotIntegrity.Verify(dir, ""));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void Launcher_UnanchoredSlot_FallsBackToBase()
    {
        var root = TempDir();
        try
        {
            var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
            var updates = Path.Combine(root, "updates"); Directory.CreateDirectory(updates);
            var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
            File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core, no anchor");
            File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
            // Pointer with NO integrity anchor (the pre-fix shape).
            File.WriteAllText(SlotPointer.PointerPath(updates),
                "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":null}");
            var target = LauncherCore.ResolveTarget(install, updates);
            Assert.True(target.FellBack);
            Assert.Equal(Path.Combine(install, "AcpCore.exe"), target.CoreExe);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void Launcher_AnchoredSlot_Verifies_ThenTamperFallsBack()
    {
        var root = TempDir();
        try
        {
            var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
            var updates = Path.Combine(root, "updates"); Directory.CreateDirectory(updates);
            var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
            File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "slot core");
            File.WriteAllText(Path.Combine(slotA, "Acp.SessionAgent.exe"), "slot agent");
            File.WriteAllText(Path.Combine(install, "AcpCore.exe"), "base core");
            var hash = SlotIntegrity.ContentHash(slotA);
            File.WriteAllText(SlotPointer.PointerPath(updates),
                "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":null,\"ActiveSlotHash\":\"" + hash + "\"}");
            var target = LauncherCore.ResolveTarget(install, updates);
            Assert.False(target.FellBack);
            Assert.Equal(Path.Combine(slotA, "AcpCore.exe"), target.CoreExe);
            Assert.Equal(Path.Combine(slotA, "Acp.SessionAgent.exe"), target.AgentExe);
            // Destruction: swap the slot core after the anchor was
            // recorded — the launcher must refuse it as SYSTEM.
            File.WriteAllText(Path.Combine(slotA, "AcpCore.exe"), "attacker core");
            var refused = LauncherCore.ResolveTarget(install, updates);
            Assert.True(refused.FellBack);
            Assert.Equal(Path.Combine(install, "AcpCore.exe"), refused.CoreExe);
        }
        finally { Directory.Delete(root, true); }
    }
}

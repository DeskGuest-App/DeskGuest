using System.Diagnostics;
using Acp.Core;
using Acp.Shared.Heartbeat;

namespace Acp.Tests;

/// <summary>FR-135 — the two bare-launch lockouts from the W135
/// deploy. #15: the agent exe fallback named a file that does not
/// exist (`AcpSessionAgent.exe` vs the shipped
/// `Acp.SessionAgent.exe`), so a bare Core launch provisioned the
/// trust record / watchdog / IPC expectation with a phantom path
/// and no agent could ever connect. #16: a pid-less run marker
/// (pre-single-instance build) judged by freshness alone stranded
/// a successor Core forever (exit 41) even when process
/// enumeration had already proven the machine Core-free.</summary>
public class Fr135FixTests
{
    // ---- #15: agent exe resolution ------------------------------

    private static string TempDir()
    {
        var dir = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "acp-fr135-" + Guid.NewGuid().ToString("N")));
        return dir.FullName;
    }

    [Fact]
    public void AgentExe_EnvValueAlwaysWins()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "Acp.SessionAgent.exe"), Array.Empty<byte>());
            var resolved = AgentExePathResolver.Resolve(dir, @"X:\custom\agent.exe");
            Assert.Equal(@"X:\custom\agent.exe", resolved);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void AgentExe_ShippedDottedNamePreferredWhenPresent()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "Acp.SessionAgent.exe"), Array.Empty<byte>());
            File.WriteAllBytes(Path.Combine(dir, "AcpSessionAgent.exe"), Array.Empty<byte>());
            Assert.Equal(Path.Combine(dir, "Acp.SessionAgent.exe"),
                AgentExePathResolver.Resolve(dir, null));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void AgentExe_LegacyNameHonouredWhenItIsTheOneOnDisk()
    {
        var dir = TempDir();
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "AcpSessionAgent.exe"), Array.Empty<byte>());
            Assert.Equal(Path.Combine(dir, "AcpSessionAgent.exe"),
                AgentExePathResolver.Resolve(dir, null));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void AgentExe_NeitherPresent_DefaultsToTheShippedName()
    {
        var dir = TempDir();
        try
        {
            // A correct install carries the dotted name; a broken
            // one must name the file it SHOULD have, never the
            // phantom legacy name the old fallback invented.
            Assert.Equal(Path.Combine(dir, "Acp.SessionAgent.exe"),
                AgentExePathResolver.Resolve(dir, null));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void CoreOptions_DefaultAgentExe_IsTheShippedName()
    {
        var options = new CoreOptions { DataDir = Path.GetTempPath() };
        Assert.Equal("Acp.SessionAgent.exe", options.AgentExePath);
    }

    // ---- #16: the marker block decision -------------------------

    private static readonly DateTimeOffset Now = new(2026, 11, 25, 6, 20, 0, TimeSpan.Zero);

    private static RunMarker.MarkerSnapshot Pidless(DateTimeOffset lastSeen, bool endedCleanly = false) =>
        new(EndedCleanly: endedCleanly, OwnerPid: 0, LastSeenUtc: lastSeen, LastState: null);

    [Fact]
    public void Marker_NoMarker_NeverBlocks() =>
        Assert.False(RunMarker.MarkerBlocksStart(null, Now, null, enumerationProvedNoOtherCore: false));

    [Fact]
    public void Marker_PidlessFresh_BlocksWithoutEnumerationProof()
    {
        // The pre-fix discipline, preserved where no process
        // evidence exists: freshness alone cannot prove death.
        var marker = Pidless(Now - TimeSpan.FromSeconds(10));
        Assert.True(RunMarker.MarkerBlocksStart(marker, Now, null, enumerationProvedNoOtherCore: false));
    }

    [Fact]
    public void Marker_PidlessFresh_DoesNotBlockWhenEnumerationProvedNoCore()
    {
        // THE W135 CASE: the old Core died uncleanly seconds ago
        // (fresh pid-less marker, fresh heartbeat) and its
        // successor refused forever — while enumeration had
        // already proven no Core process exists.
        var marker = Pidless(Now - TimeSpan.FromSeconds(10));
        Assert.False(RunMarker.MarkerBlocksStart(marker, Now, Now - TimeSpan.FromSeconds(5),
            enumerationProvedNoOtherCore: true));
    }

    [Fact]
    public void Marker_PidlessStale_NeverBlocks()
    {
        var marker = Pidless(Now - TimeSpan.FromHours(2));
        Assert.False(RunMarker.MarkerBlocksStart(marker, Now, Now - TimeSpan.FromHours(2),
            enumerationProvedNoOtherCore: false));
    }

    [Fact]
    public void Marker_PidlessCleanEnded_NeverBlocks()
    {
        var marker = Pidless(Now - TimeSpan.FromSeconds(10), endedCleanly: true);
        Assert.False(RunMarker.MarkerBlocksStart(marker, Now, null, enumerationProvedNoOtherCore: false));
    }

    [Fact]
    public void Marker_RecordedLivePid_BlocksEvenWithEnumerationProof()
    {
        // Defence in depth (W111): a marker naming a RECORDED pid
        // whose owner cannot be proven dead is never overridden
        // by the enumeration flag. The deterministic live pid is a
        // spawned child that started before the marker's LastSeen
        // (so it is not a recycled pid) and is not this process
        // (a marker naming THIS process's pid reads as recycled
        // to the successor itself — provably dead by the W107
        // rule). Real clock throughout: the production check
        // compares real process start times.
        using var child = Process.Start(new ProcessStartInfo(
            OperatingSystem.IsWindows() ? "ping.exe" : "/bin/sleep",
            OperatingSystem.IsWindows() ? "-n 30 127.0.0.1" : "30")
        { CreateNoWindow = true });
        Assert.NotNull(child);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var marker = new RunMarker.MarkerSnapshot(
                EndedCleanly: false, OwnerPid: child!.Id, LastSeenUtc: now, LastState: null);
            Assert.True(RunMarker.MarkerBlocksStart(marker, now, null, enumerationProvedNoOtherCore: true));
        }
        finally { try { child!.Kill(); } catch { /* already gone */ } }
    }

    [Fact]
    public void Marker_RecordedDeadPid_DoesNotBlock()
    {
        // A pid from a process that has exited is provably dead:
        // the legitimate restart.
        using var p = Process.Start(new ProcessStartInfo(
            OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/true",
            OperatingSystem.IsWindows() ? "/c exit 0" : "") { CreateNoWindow = true });
        Assert.NotNull(p);
        p!.WaitForExit();
        var marker = new RunMarker.MarkerSnapshot(
            EndedCleanly: false, OwnerPid: p.Id, LastSeenUtc: Now, LastState: null);
        Assert.False(RunMarker.MarkerBlocksStart(marker, Now, null, enumerationProvedNoOtherCore: false));
    }
}

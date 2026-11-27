using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Files;
using Xunit;

namespace DeskGuest.Tests;

/// <summary>W65 — V21 Phase 1: FR-113 generated Guardrails label,
/// FR-115 registry gating, and the v2.0.0 token sweep over the
/// rebuilt shell surfaces.</summary>
public class W65V21DesignTests
{
    [Fact]
    public void FileRootsLabel_is_generated_from_the_configured_roots()
    {
        var (chip, detail) = FileRootsLabel.Generate(new[] { @"C:\Users\DeskGuest\Desktop", @"C:\Users\DeskGuest\Documents" });
        Assert.Contains("2 folders", chip);
        Assert.Contains(@"C:\Users\DeskGuest\Desktop", detail);
        Assert.Contains(@"C:\Users\DeskGuest\Documents", detail);
        Assert.DoesNotContain("unscoped", chip + detail);
    }

    [Fact]
    public void FileRootsLabel_changes_when_the_roots_change()
    {
        var a = FileRootsLabel.Generate(new[] { @"D:\Work" });
        var b = FileRootsLabel.Generate(new[] { @"D:\Work", @"D:\Play" });
        Assert.NotEqual(a.Chip, b.Chip);
        Assert.Contains("1 folder", a.Chip);
        Assert.Contains("2 folders", b.Chip);
    }

    [Fact]
    public void FileRootsLabel_staging_only_says_so_plainly()
    {
        var (chip, detail) = FileRootsLabel.Generate(new[] { @"C:\ProgramData\DeskGuest\data\staging" });
        Assert.Equal("Staging folder only", chip);
        Assert.Contains("staging", detail);
        Assert.DoesNotContain("unscoped", chip + detail);
    }

    [Fact]
    public void FileRootsLabel_unreported_roots_claim_nothing()
    {
        var (chip, _) = FileRootsLabel.Generate(null);
        Assert.Equal("Not reported", chip);
        var (chip2, _) = FileRootsLabel.Generate(Array.Empty<string>());
        Assert.Equal("Not reported", chip2);
    }

    [Fact]
    public void HostStateSnapshot_carries_the_effective_file_roots()
    {
        var json = HostStateSnapshot.Build(
            coreVersion: "1.0.0.0", machineName: "TESTPC", port: 8741,
            runningLanes: Array.Empty<string>(), agentConnected: true,
            desktopUnlocked: true, userStopInForce: false,
            session: new HostStateSnapshot.SessionFacts(false, null, 0, 0, null),
            pairings: Array.Empty<DeskGuest.Shared.Security.Pairing>(),
            gatedClasses: Array.Empty<string>(), approvedGates: new HashSet<string>(),
            auditTail: Array.Empty<DeskGuest.Shared.Audit.AuditEntry>(),
            fileRoots: new[] { @"C:\Users\DeskGuest\Desktop" });
        using var doc = JsonDocument.Parse(json);
        var roots = doc.RootElement.GetProperty("fileRoots").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Equal(new[] { @"C:\Users\DeskGuest\Desktop" }, roots);
    }

    [Fact]
    public void Registry_set_and_delete_declare_gate_classes()
    {
        // FR-115: Critical-tier registry writes gate like the other
        // sensitive classes — before W65 they declared no GateClass
        // and ran ungated.
        var set = new RegistrySetModule(new FakeRegistry());
        var del = new RegistryDeleteModule(new FakeRegistry());
        Assert.Equal("registry_write", set.Descriptor.GateClass);
        Assert.Equal("deletions", del.Descriptor.GateClass);
    }

    private sealed class FakeRegistry : IRegistryProvider
    {
        public bool Available => true;
        public string? GetValue(string key, string valueName) => null;
        public void SetValue(string key, string valueName, string data) { }
        public void DeleteValue(string key, string valueName) { }
        public void DeleteKey(string key) { }
        public IReadOnlyList<string> ListValues(string key) => Array.Empty<string>();
        public IReadOnlyList<string> ListSubKeys(string key) => Array.Empty<string>();
    }

    [Fact]
    public void Rebuilt_shell_surfaces_carry_no_retired_palette_values()
    {
        var dir = SessionAgentDir();
        // W74: CornerRadius="14" left the retired list — it was a
        // W65 token-shell value then, but W70's MEASURED geometry
        // (builds/lane-w70-artefacts/MEASUREMENT-SHEET.md: the
        // rounded-square avatar tile, 64x64, radius ~14) re-adopted
        // 14 for the sidebar A3 logo tile and helper avatar tiles.
        // The measured values are pinned positively below instead.
        string[] retired = { "#F6F4EF", "#EFEBE3", "#E4DFD3", "#C42B2B", "#0086F0" };
        foreach (var file in new[] { "MainWindow.xaml", "TrayPopup.xaml", "DeskGuestTheme.xaml" })
        {
            var xaml = File.ReadAllText(Path.Combine(dir, file));
            foreach (var bad in retired)
                Assert.False(xaml.Contains(bad, StringComparison.OrdinalIgnoreCase), $"{file} still carries retired value {bad}");
        }
        var theme = File.ReadAllText(Path.Combine(dir, "DeskGuestTheme.xaml"));
        Assert.Contains("#2F8BC9", theme);
        Assert.Contains("#0F2537", theme);
        Assert.Contains("#E5A93B", theme);
        var main = File.ReadAllText(Path.Combine(dir, "MainWindow.xaml"));
        Assert.Contains("DeskGuestTheme", File.ReadAllText(Path.Combine(dir, "App.xaml")));
        Assert.Contains("CornerRadius\" Value=\"16\"", main); // card radius of record
        // W74 — W70 measured radii, pinned as the design of record
        // (MEASUREMENT-SHEET.md + log-laneW70 build record): nav
        // pill radius 26, rounded-square logo/avatar tile radius 14.
        Assert.Contains("CornerRadius=\"26\"", main); // nav pill (W70 measured build)
        Assert.Contains("CornerRadius=\"14\"", main); // logo tile (sheet: avatar tile radius ~14)
    }

    private static string SessionAgentDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DeskGuestWindows.slnx")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "DeskGuest.SessionAgent");
    }
}

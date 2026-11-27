using DeskGuest.Core.Services;
using DeskGuest.Shared.Install;
using Xunit;

namespace DeskGuest.Tests;

/// <summary>R1 SERVICE-FORM INSTALLER pins (BUILD-LOG #155): the
/// installer's Terms gate + first-run role step logic
/// (DeskGuest.Shared.Install.InstallGate), plus script-structure pins
/// on Install-DeskGuestWindows.ps1 in the EnterpriseDestructionTests
/// pattern. The decline-writes-nothing proof is a full directory diff
/// around the decline call.</summary>
public class R1InstallerGateTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "dg-r1-" + Guid.NewGuid().ToString("N"));
    private string DataDir => Path.Combine(_root, "data");
    private static readonly DateTimeOffset T0 = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);

    private const string TermsFixture =
        "# DeskGuest — Terms of Service\n\n**Version:** 1.0 · **Date:** 2026-11-24\n\nFixture terms text.\n";

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private TermsGateSession NewSession() =>
        new(DataDir, TermsFixture, "0.0.1-pre", "bench-user", () => T0);

    private static SortedDictionary<string, string> Snapshot(string dir)
    {
        var map = new SortedDictionary<string, string>();
        if (!Directory.Exists(dir)) return map;
        foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            map[Path.GetRelativePath(dir, f)] = File.ReadAllText(f);
        return map;
    }

    [Fact]
    public void Checkbox_IsUntickedByDefault_AndAcceptRefusesUntilTicked()
    {
        var gate = NewSession();
        Assert.False(gate.AcceptanceCheckboxTicked);
        Assert.Throws<InvalidOperationException>(() => gate.Accept());
        Assert.Empty(Snapshot(_root));
    }

    [Fact]
    public void Decline_WritesNothing_DirectoryDiffEmpty()
    {
        Directory.CreateDirectory(DataDir);
        File.WriteAllText(Path.Combine(DataDir, "pre-existing.txt"), "keep me");
        var before = Snapshot(_root);
        var gate = NewSession();
        var outcome = gate.Decline();
        Assert.Equal(GateOutcome.DeclinedNothingWritten, outcome);
        Assert.Equal(before, Snapshot(_root));
    }

    [Fact]
    public void Decline_OnFreshTree_CreatesNoDirectory()
    {
        var gate = NewSession();
        gate.Decline();
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public void Accept_WritesExactlyTheReceipt_WithExactVersionAndHash()
    {
        var gate = NewSession();
        gate.TickAcceptanceCheckbox();
        var outcome = gate.Accept();
        Assert.Equal(GateOutcome.AcceptedReceiptWritten, outcome);
        var files = Snapshot(DataDir);
        Assert.Single(files);
        Assert.True(files.ContainsKey(InstallGate.ReceiptFileName));
        var receipt = AcceptanceReceipt.FromJson(files[InstallGate.ReceiptFileName]);
        Assert.Equal("1.0", receipt.TermsVersion);
        Assert.Equal(InstallGate.ComputeTermsSha256(TermsFixture), receipt.TermsSha256);
        Assert.Equal("0.0.1-pre", receipt.AppVersion);
        Assert.Equal("bench-user", receipt.AcceptedBy);
        Assert.Equal(T0, receipt.AcceptedUtc);
        // v0.0.1 reconciliation (BUILD-LOG #155): the receipt records
        // the acceptance act; it does NOT claim the v1.0 text binding.
        Assert.False(receipt.Binding);
    }

    [Fact]
    public void UntickAfterTick_BlocksAcceptAgain()
    {
        var gate = NewSession();
        gate.TickAcceptanceCheckbox();
        gate.UntickAcceptanceCheckbox();
        Assert.Throws<InvalidOperationException>(() => gate.Accept());
    }

    [Fact]
    public void UnversionedTerms_RefusedAtPresentation()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new TermsGateSession(DataDir, "# Terms with no version line\n", "0.0.1-pre", "bench-user", () => T0));
    }

    [Fact]
    public void GateHash_MatchesTheCoreServedBundle_ForTheCanonicalText()
    {
        // The canonical legal text, located by walking up from the
        // test binary (the EnterpriseDestructionTests pattern).
        string? dir = AppContext.BaseDirectory;
        string? legalPath = null;
        while (dir is not null && legalPath is null)
        {
            var candidate = Path.Combine(dir, "agent-control-app", "legal", "terms-of-service.md");
            if (File.Exists(candidate)) legalPath = candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(legalPath);
        var text = File.ReadAllText(legalPath!);
        var gate = new TermsGateSession(DataDir, text, "0.0.1-pre", "bench-user", () => T0);
        // Same text, same method as TermsBundle.Load: the installer's
        // page and the Core's deskguest://terms MUST agree exactly.
        Assert.Equal(TermsBundleProvider.Current.Sha256, gate.TermsSha256);
        Assert.Equal(TermsBundleProvider.Current.Version, gate.TermsVersion);
        Assert.Equal(TermsBundleProvider.Current.Text, gate.TermsText);
    }

    [Fact]
    public void Role_NoneSelected_IsRefused()
    {
        var gate = NewSession();
        Assert.Throws<InvalidOperationException>(() =>
            gate.RecordRole(new DeviceRoleSelection(DeviceRoles.None, T0)));
    }

    [Fact]
    public void Role_AttendedOnly_RequiresNoService_UnattendedDoes()
    {
        Assert.False(new DeviceRoleSelection(DeviceRoles.AttendedEndpoint, T0).RequiresService);
        Assert.False(new DeviceRoleSelection(DeviceRoles.Operator | DeviceRoles.AttendedEndpoint, T0).RequiresService);
        Assert.True(new DeviceRoleSelection(DeviceRoles.UnattendedEndpoint, T0).RequiresService);
        Assert.True(new DeviceRoleSelection(DeviceRoles.Operator | DeviceRoles.UnattendedEndpoint, T0).RequiresService);
    }

    [Fact]
    public void Role_Recorded_RoundTrips()
    {
        var gate = NewSession();
        var selection = new DeviceRoleSelection(DeviceRoles.Operator | DeviceRoles.UnattendedEndpoint, T0);
        gate.RecordRole(selection);
        var read = DeviceRoleSelection.FromJson(File.ReadAllText(Path.Combine(DataDir, InstallGate.RoleFileName)));
        Assert.Equal(selection, read);
    }

    // ---- script-structure pins on the shipped installer script ----

    private static string ReadInstallerScript()
    {
        string? dir = AppContext.BaseDirectory;
        string? path = null;
        while (dir is not null && path is null)
        {
            var candidate = Path.Combine(dir, "windows-agent", "installer", "Install-DeskGuestWindows.ps1");
            if (File.Exists(candidate)) path = candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(path);
        return File.ReadAllText(path!);
    }

    [Fact]
    public void InstallerScript_TermsGateRunsBeforeAnyInstallStep()
    {
        var script = ReadInstallerScript();
        var gateAt = script.IndexOf("Invoke-TermsGate", StringComparison.Ordinal);
        Assert.True(gateAt >= 0, "installer must invoke the Terms gate");
        // Every state-changing step must come after the gate call.
        foreach (var step in new[] { "Create install + data layout", "Register service", "Register logon task", "Scope firewall", "Start the Core service" })
        {
            var stepAt = script.IndexOf(step, StringComparison.Ordinal);
            Assert.True(stepAt > gateAt, $"step '{step}' must come after the Terms gate");
        }
    }

    [Fact]
    public void InstallerScript_DeclineExitsCleanBeforeWrites()
    {
        var script = ReadInstallerScript();
        Assert.Contains("DECLINED", script);
        Assert.Contains("nothing was written", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InstallerScript_DefaultsAreTheDeskGuestPaths()
    {
        var script = ReadInstallerScript();
        Assert.Contains("C:\\DeskGuest-Install", script);
        Assert.Contains("C:\\ProgramData\\DeskGuest\\data", script);
        Assert.DoesNotContain("C:\\ACP-Install", script);
        Assert.DoesNotContain("ProgramData\\ACP", script);
    }

    [Fact]
    public void InstallerScript_RoleStepDrivesServiceInstall()
    {
        var script = ReadInstallerScript();
        Assert.Contains("What will this device do?", script);
        Assert.Contains("RequiresService", script);
    }
}

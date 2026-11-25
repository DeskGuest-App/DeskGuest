using Acp.Shared.Inventory;
using Acp.Shared.Patching;
using Acp.Shared.Vulnerability;

namespace Acp.Tests;

// RMM-05 DESTRUCTION PASS — hostile attacks on the vulnerability
// loop. Attacker models: a poisoned feed (downgrades, KEV drops,
// invented CVEs, rollbacks), a forged scanner export, a control
// forger (owner/review games, cross-exposure controls), an
// evidence substituter, an SLA clock gamer, and inventory that
// hides a vulnerable install behind a fixed one. Every test is a
// permanent regression: if it ever fails, the attack succeeded.
public class Rmm05DestructionTests
{
    private static readonly DateTimeOffset T0 = Rmm05Tests.T0;

    private static Rmm05Tests.Rig RigWithExposure(out ExposureWorkItem item)
    {
        var rig = Rmm05Tests.RigWithFleet();
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        item = Assert.Single(rig.Service.Exposures.OpenItems());
        return rig;
    }

    // ---- feed poisoning -------------------------------------------------

    [Fact]
    public void ATTACK_FeedDowngradesCvssAndDropsKev_CachedRiskStands_AndOpenExposureUnmoved()
    {
        var rig = RigWithExposure(out var item);
        Assert.Equal(9.8, item.CvssScore);
        Assert.True(item.IsKev);
        // The poisoned successor feed: same CVE, CVSS slashed, KEV gone.
        var poisoned = Rmm05Tests.Feed(2, entries: new[]
        {
            Rmm05Tests.AcrobatCve(cvss: 2.0, severity: "low", kev: false),
        });
        var result = rig.Service.ImportFeed(poisoned, "attacker-feed");
        Assert.True(result.Accepted); // the feed imports — but its downgrades do not land
        Assert.Equal(3, result.DowngradeFlags.Count); // CVSS + severity + KEV, each flagged by name
        var cached = Assert.Single(rig.Service.Feeds.Current!.Entries);
        Assert.Equal(9.8, cached.CvssScore);
        Assert.True(cached.IsKev);
        Assert.Equal("critical", cached.Severity);
        // And the OPEN exposure's snapshots never moved:
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var after = rig.Service.Exposures.Get(item.Id)!;
        Assert.Equal(9.8, after.CvssScore);
        Assert.True(after.IsKev);
        Assert.Equal(item.SlaDueUtc, after.SlaDueUtc);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_feed_downgrade_flagged");
    }

    [Fact]
    public void ATTACK_FeedRollback_OlderSequenceOrOlderPublished_Refused()
    {
        var rig = Rmm05Tests.NewRig();
        Assert.True(rig.Service.ImportFeed(Rmm05Tests.Feed(5), "admin").Accepted);
        // older sequence:
        var older = rig.Service.ImportFeed(Rmm05Tests.Feed(4), "attacker");
        Assert.False(older.Accepted);
        Assert.Contains("rollback", older.Reason);
        // newer sequence but OLDER published data (last month's feed re-dated):
        var redated = rig.Service.ImportFeed(
            Rmm05Tests.Feed(6, published: T0.AddDays(-90)), "attacker");
        Assert.False(redated.Accepted);
        Assert.Contains("rollback", redated.Reason);
        // same sequence, different content (the silent swap):
        var swap = rig.Service.ImportFeed(Rmm05Tests.Feed(5, entries: new[]
        {
            Rmm05Tests.AcrobatCve(cvss: 5.0, severity: "medium", kev: false),
        }), "attacker");
        Assert.False(swap.Accepted);
        Assert.Equal(5, rig.Service.Feeds.Current!.Sequence);
        Assert.Equal(9.8, rig.Service.Feeds.Current.Entries[0].CvssScore);
    }

    [Fact]
    public void ATTACK_FeedInventsCveForProductNotInstalled_NoExposure()
    {
        var rig = Rmm05Tests.RigWithFleet();
        var ghost = new VulnerabilityFeedEntry("CVE-2024-66666", "Nonexistent Suite", "9.9", null, null,
            10.0, "critical", true, T0, T0.AddDays(-1), "scariest CVE ever, for software nobody runs");
        rig.Service.ImportFeed(Rmm05Tests.Feed(entries: new[] { ghost, Rmm05Tests.AcrobatCve() }), "admin");
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Equal(1, run.Created); // only the real Acrobat exposure
        Assert.DoesNotContain(rig.Service.Exposures.Items, i => i.CveId == "CVE-2024-66666");
    }

    [Fact]
    public void ATTACK_FeedDropsCveEntirely_OpenExposureDoesNotAutoClose()
    {
        var rig = RigWithExposure(out var item);
        // A successor feed where the CVE has simply VANISHED:
        var other = new VulnerabilityFeedEntry("CVE-2024-11111", "Google Chrome", "131.0", null, null,
            5.0, "medium", false, null, T0.AddDays(-1), null);
        Assert.True(rig.Service.ImportFeed(Rmm05Tests.Feed(2, entries: new[] { other }), "admin").Accepted);
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var after = rig.Service.Exposures.Get(item.Id)!;
        Assert.False(after.IsClosed); // absence of data is not closure evidence
        Assert.Equal(ExposureStates.Open, after.State);
    }

    [Fact]
    public void ATTACK_EmptyOrUnprovenancedFeed_Refused()
    {
        var rig = Rmm05Tests.NewRig();
        Assert.False(rig.Service.ImportFeed(null, "attacker").Accepted);
        Assert.False(rig.Service.ImportFeed(
            new VulnerabilityFeed("", "", 1, T0, new[] { Rmm05Tests.AcrobatCve() }), "attacker").Accepted);
        Assert.Null(rig.Service.Feeds.Current);
    }

    // ---- scanner spoofing -------------------------------------------------

    [Fact]
    public void ATTACK_ScannerInventsFleetWideFindings_OrphansHeld_NoExposures()
    {
        var rig = Rmm05Tests.RigWithFleet();
        // No feed at all; a forged scanner file claims Acrobat CVEs
        // on dev2 (which runs the FIXED version, with a catalogue
        // fix present) and on a device that does not exist.
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        var forged = """
            {"findings":[
              {"id":"x-1","host_id":"dev2","software":"Adobe Acrobat","version":"25.2.0","cve":"CVE-2024-12345","cvss":9.8},
              {"id":"x-2","host_id":"ghost-device","software":"Adobe Acrobat","version":"1.0","cve":"CVE-2024-12345","cvss":9.8},
              {"id":"x-3","host_id":"dev1","software":"Not Installed App","version":"1.0","cve":"CVE-2024-12345","cvss":9.8}]}
            """;
        Assert.True(rig.Service.ImportScannerResults("tenable", forged, "attacker").Ok);
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.True(run.Ok);
        // dev2's install is at/above the catalogue fix → scanner is
        // stale, no exposure. ghost + not-installed → orphans.
        Assert.Empty(rig.Service.Exposures.Items);
        Assert.Equal(2, run.Result!.OrphanFindings.Count);
    }

    // ---- compensating-control forgery ---------------------------------------

    [Fact]
    public void ATTACK_ControlWithNoOwnerOrBackdatedReview_Refused()
    {
        var rig = RigWithExposure(out var item);
        Assert.False(rig.Service.RecordCompensatingControl(item.Id,
            "A real-sounding control description.", "", T0.AddDays(30), "doc", "tech").Ok); // no owner
        Assert.False(rig.Service.RecordCompensatingControl(item.Id,
            "A real-sounding control description.", "owner-a", T0.AddDays(-1), "doc", "tech").Ok); // review already past
        Assert.False(rig.Service.RecordCompensatingControl(item.Id,
            "A real-sounding control description.", "owner-a", T0, "doc", "tech").Ok); // review = now
        Assert.False(rig.Service.RecordCompensatingControl(item.Id,
            "A real-sounding control description.", "owner-a", T0.AddDays(400), "doc", "tech").Ok); // review beyond the year horizon
        Assert.False(rig.Service.RecordCompensatingControl(item.Id,
            "short", "owner-a", T0.AddDays(30), "doc", "tech").Ok); // not a documented control
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(item.Id)!.State);
    }

    [Fact]
    public void ATTACK_ControlNamingAnotherExposureOrDevice_ClosesNothing()
    {
        var rig = Rmm05Tests.RigWithFleet();
        var chrome = new VulnerabilityFeedEntry("CVE-2024-22222", "Google Chrome", "131.0", null, null,
            8.0, "high", false, null, T0.AddDays(-2), null);
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev9", software: new[] { ("Google Chrome", "120.0") }), T0);
        rig.Service.ImportFeed(Rmm05Tests.Feed(entries: new[] { Rmm05Tests.AcrobatCve(), chrome }), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var acrobat = rig.Service.Exposures.Items.Single(i => i.CveId == "CVE-2024-12345" && i.DeviceId == "dev1");
        var chromeItem = rig.Service.Exposures.Items.Single(i => i.CveId == "CVE-2024-22222" && i.DeviceId == "dev9");
        // A control honestly recorded against the CHROME exposure…
        Assert.True(rig.Service.RecordCompensatingControl(chromeItem.Id,
            "Chrome auto-update enforced by policy.", "owner-a", T0.AddDays(30), "chrome doc", "tech").Ok);
        // …presented directly to the store against the ACROBAT item:
        var foreign = new CompensatingControl("ctl-foreign", acrobat.Id, chromeItem.DeviceId, chromeItem.CveId,
            "Chrome auto-update enforced by policy.", "owner-a", "tech", T0, T0.AddDays(30),
            VulnerabilityHash.Sha256Hex("chrome doc"));
        var direct = rig.Service.Exposures.RecordCompensatingControl(foreign, T0);
        Assert.False(direct.Ok);
        Assert.Contains("closes only the exposure it names", direct.Reason);
        // And closing Acrobat with Chrome's control evidence refuses:
        var evidence = new ClosureEvidence(acrobat.Id, ClosureKinds.CompensatingControl,
            ClosureEvidence.ComputeControlHash(acrobat.Id, acrobat.DeviceId, "ctl-foreign",
                VulnerabilityHash.Sha256Hex("chrome doc"), T0, "tech"),
            "forged", "tech", T0);
        Assert.False(rig.Service.Exposures.Close(acrobat.Id, evidence, T0).Ok);
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(acrobat.Id)!.State);
    }

    [Fact]
    public void ATTACK_ExpiredControlCannotClose_AndReopenIsAudited()
    {
        var rig = RigWithExposure(out var item);
        Assert.True(rig.Service.RecordCompensatingControl(item.Id,
            "Short-lived isolation control.", "owner-a", T0.AddDays(3), "doc", "tech").Ok);
        rig.Clock.Now = T0.AddDays(4);
        // The service-level closure now refuses (control expired):
        var closed = rig.Service.CloseWithControlEvidence(item.Id, "tech");
        Assert.False(closed.Ok);
        // The correlation run reopens it and the audit names it:
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Single(run.Reopened);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_exposure_reopened");
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(item.Id)!.State);
    }

    // ---- closure-evidence substitution ---------------------------------------

    [Fact]
    public void ATTACK_PatchClosureWithoutConvergenceOrApproval_Refused()
    {
        var rig = RigWithExposure(out var item);
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        // No request at all:
        Assert.False(rig.Service.CloseWithPatchEvidence(item.Id, "tech").Ok);
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        // Requested but never approved, device still vulnerable:
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("approval", refused.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.False(rig.Service.Exposures.Get(item.Id)!.IsClosed);
    }

    [Fact]
    public void ATTACK_CatalogueSwappedAfterRequest_PatchClosureRefused()
    {
        var rig = RigWithExposure(out var item);
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech");
        rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1", approve: true, decidedBy: "admin");
        // The catalogue entry is swapped at a new revision (new pin):
        var swapped = entry with { Revision = 2, Title = "Swapped" };
        Assert.True(rig.Patches.Service.Catalogue.AddOrReplace(swapped).Accepted);
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("changed after the remediation request", refused.Reason);
    }

    [Fact]
    public void ATTACK_EvidenceReplayedAcrossExposures_RefusedByStore()
    {
        var rig = Rmm05Tests.RigWithFleet();
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev9", software: new[] { ("Adobe Acrobat", "23.0.5") }), T0);
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var a = rig.Service.Exposures.Items.Single(i => i.DeviceId == "dev1");
        var b = rig.Service.Exposures.Items.Single(i => i.DeviceId == "dev9");
        rig.Service.RecordCompensatingControl(a.Id, "Isolation control for A.", "owner-a", T0.AddDays(30), "doc-a", "tech");
        Assert.True(rig.Service.CloseWithControlEvidence(a.Id, "tech").Ok);
        var evidenceA = rig.Service.Exposures.Get(a.Id)!.Closure!;
        // Replay A's exact evidence against B:
        var replay = rig.Service.Exposures.Close(b.Id, evidenceA, T0);
        Assert.False(replay.Ok);
        Assert.False(rig.Service.Exposures.Get(b.Id)!.IsClosed);
        // Double closure of A also refuses (closure is singular):
        Assert.False(rig.Service.Exposures.Close(a.Id, evidenceA, T0).Ok);
    }

    // ---- SLA clock games -------------------------------------------------------

    [Fact]
    public void ATTACK_ReCorrelationCannotResetSlaClock_OrLaunderSeverity()
    {
        var rig = RigWithExposure(out var item);
        var due = item.SlaDueUtc;
        rig.Clock.Now = T0.AddDays(2); // exposure is now 2 days old, 1 day of SLA left
        for (var i = 0; i < 5; i++) rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var after = rig.Service.Exposures.Get(item.Id)!;
        Assert.Equal(T0, after.FirstSeenUtc);
        Assert.Equal(due, after.SlaDueUtc);
        Assert.Single(rig.Service.Exposures.Items); // and no duplicates were minted
    }

    [Fact]
    public void ATTACK_PolicySlaZeroOrAbsurd_NeverProducesZeroDeadline()
    {
        var sla = new VulnerabilitySlaPolicy(CriticalHours: 0, HighHours: -5, MediumHours: 0, LowHours: 999999, KevCapHours: 0);
        // Every field falls back to a sane positive span:
        Assert.True(sla.SlaFor("critical", false) > TimeSpan.Zero);
        Assert.True(sla.SlaFor("high", false) > TimeSpan.Zero);
        Assert.True(sla.SlaFor("low", true) > TimeSpan.Zero);
        Assert.True(sla.SlaFor("low", true) <= TimeSpan.FromDays(365));
    }

    // ---- correlation spoofing ----------------------------------------------------

    [Fact]
    public void ATTACK_InventoryHidingVulnerableVersionBehindFixedOne_StillExposed_AndClosureBlocked()
    {
        var rig = Rmm05Tests.NewRig();
        // "24.0.1" sorts BEFORE "9.0" in the inventory normalizer's
        // ordinal order, so PatchScanner's FirstOrDefault read sees
        // the FIXED install and calls the patch not-missing — while
        // version semantics know 9.0 < 24.0 (vulnerable).
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev1", software: new[]
        {
            ("Adobe Acrobat", "24.0.1"), ("Adobe Acrobat", "9.0"),
        }), T0);
        var entry = Rmm02Tests.ThirdParty() with
        {
            ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
            CveIds = new[] { "CVE-2024-12345" },
        };
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Contains("9.0", item.VulnerableVersions);
        rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech");
        rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1", approve: true, decidedBy: "admin");
        // The 9.0 straggler blocks closure. REPAIRED (Wave 2 Lane B,
        // 2026-11-22) for bd-shared-rmm-2/F7: DetermineMissing now
        // evaluates every install, so the scanner reports the patch
        // missing and closure refuses with the scanner's reason
        // instead of falling through to the ANY-install check — the
        // refusal invariant is unchanged, the governing reason moved.
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("still reports patch", refused.Reason);
    }
}

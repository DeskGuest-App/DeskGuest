using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Patching;
using Acp.Shared.Vulnerability;

namespace Acp.Tests;

// RMM-05 D38 FIX LANE — regression tests for the 12 findings of
// packet 8c367938 (fresh-packet cross-review, verdict FAIL).
// Every test is a permanent regression: it names the finding it
// pins and fails if the attack/defect ever returns. Fixtures are
// Rmm05Tests' rig (mutable clock, real PatchService approvals,
// real inventory store).
public class Rmm05D38FixTests
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

    private static PatchCatalogueEntry AcrobatEntry() => Rmm02Tests.ThirdParty() with
    {
        ProductName = "Adobe Acrobat", FixedInVersion = "24.0",
        CveIds = new[] { "CVE-2024-12345" },
    };

    private static void SetInstalled(Rmm05Tests.Rig rig, string deviceId, string osBuild,
        params (string Name, string Version)[] software) =>
        SetInstalledAt(rig, deviceId, osBuild, 3, software);

    private static void SetInstalledAt(Rmm05Tests.Rig rig, string deviceId, string osBuild, int atHours,
        params (string Name, string Version)[] software)
    {
        var stored = rig.Inventory.Get(deviceId)!;
        var next = Rmm05Tests.Record(deviceId, osBuild: osBuild, software: software);
        var diff = InventoryDiffer.Compute(stored, next, stored.Revision, T0.AddHours(atHours));
        Assert.True(rig.Inventory.ApplyChangeReport(
            new InventoryChangeReport(diff, next), T0.AddHours(atHours)).Accepted);
    }

    // ---- F1: control closure is bounded by the review date --------

    [Fact]
    public void D38F1_StoreExpiry_ReopensControlClosedItem_SameEpisodeOriginalClock()
    {
        var rig = RigWithExposure(out var item);
        Assert.True(rig.Service.RecordCompensatingControl(item.Id,
            "Isolation control, review in 3 days.", "owner-a", T0.AddDays(3), "doc", "tech").Ok);
        Assert.True(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
        Assert.True(rig.Service.Exposures.Get(item.Id)!.IsClosed);
        // Review date passes: EvaluateExpirations reopens the
        // CLOSED item (pre-fix it only looked at Compensated).
        var reopened = rig.Service.Exposures.EvaluateExpirations(T0.AddDays(4));
        var back = Assert.Single(reopened);
        Assert.Equal(item.Id, back.Id);                    // same episode, no #2
        Assert.Equal(ExposureStates.Open, back.State);
        Assert.Equal(T0, back.FirstSeenUtc);               // clock never reset
        Assert.Equal(item.SlaDueUtc, back.SlaDueUtc);
        Assert.Null(back.Closure);
    }

    [Fact]
    public void D38F1_PatchClosed_Reappearance_StillMintsEpisode2()
    {
        var rig = RigWithExposure(out var item);
        var entry = AcrobatEntry();
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        SetInstalled(rig, "dev1", "22631.1000", ("Adobe Acrobat", "24.0.1"));
        Assert.True(rig.Service.CloseWithPatchEvidence(item.Id, "tech").Ok);
        // The patch regresses (vulnerable install returns): a
        // patch closure IS terminal history, so a NEW episode
        // mints — the asymmetry with control closures is the point.
        SetInstalledAt(rig, "dev1", "22631.1000", 5, ("Adobe Acrobat", "23.0.5"));
        rig.Clock.Now = T0.AddDays(1);
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Equal(1, run.Created);
        var ep2 = Assert.Single(rig.Service.Exposures.Items, i => !i.IsClosed);
        Assert.EndsWith("#2", ep2.Id);
        Assert.True(rig.Service.Exposures.Get(item.Id)!.IsClosed); // old closure stands
    }

    // ---- F2: the store recomputes ALL closure evidence ------------

    [Fact]
    public void D38F2_FabricatedPatchEvidence_DirectToStore_Refused()
    {
        var rig = RigWithExposure(out var item);
        var entry = AcrobatEntry();
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        // The pre-fix attack: any 64-hex string + a standing
        // request id closed the item, bypassing approval and
        // convergence entirely. The store now recomputes the hash
        // from the recorded request — fabrication cannot match.
        var forged = new ClosureEvidence(item.Id, ClosureKinds.Patch,
            new string('a', 64), "forged detail", "attacker", T0);
        var direct = rig.Service.Exposures.Close(item.Id, forged, T0);
        Assert.False(direct.Ok);
        Assert.Contains("does not recompute", direct.Reason);
        Assert.False(rig.Service.Exposures.Get(item.Id)!.IsClosed);
    }

    [Fact]
    public void D38F2_BackdatedControlEvidence_Refused_ClosureInstantIsStores()
    {
        var rig = RigWithExposure(out var item);
        var (_, _, control) = rig.Service.RecordCompensatingControl(item.Id,
            "Isolation control for the BAS host.", "owner-a", T0.AddDays(30), "doc-a", "tech");
        Assert.NotNull(control);
        // Evidence minted for YESTERDAY with a self-consistent
        // hash over that instant: pre-fix the store re-hashed the
        // caller's own ClosedUtc and accepted. Now the closure
        // instant must be the store's `now`.
        var backdated = new ClosureEvidence(item.Id, ClosureKinds.CompensatingControl,
            ClosureEvidence.ComputeControlHash(item.Id, item.DeviceId, control!.ControlId,
                control.DocumentHash, T0.AddDays(-1), "attacker"),
            "backdated", "attacker", T0.AddDays(-1));
        var direct = rig.Service.Exposures.Close(item.Id, backdated, T0);
        Assert.False(direct.Ok);
        Assert.Contains("closure instant", direct.Reason);
        Assert.False(rig.Service.Exposures.Get(item.Id)!.IsClosed);
        // The honest service path (minted at the store's instant) closes:
        Assert.True(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
    }

    // ---- F3: closure uses the item's CURRENT request --------------

    [Fact]
    public void D38F3_AfterCatalogueSwap_FreshRequest_ThenClosureSucceeds()
    {
        var rig = RigWithExposure(out var item);
        var entry = AcrobatEntry();
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        var swapped = entry with { Revision = 2, Title = "Swapped" };
        Assert.True(rig.Patches.Service.Catalogue.AddOrReplace(swapped).Accepted);
        Assert.False(rig.Service.CloseWithPatchEvidence(item.Id, "tech").Ok); // stale request refuses
        // The refusal says "a fresh request is required" — pre-fix
        // the fresh request was recorded alongside the old one and
        // closure kept reading the OLD one (FirstOrDefault), so it
        // refused forever. Now the item's current request rules.
        var (ok, reason, request2) = rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech");
        Assert.True(ok, reason);
        Assert.Equal(swapped.ContentHash, request2!.EntryContentHash);
        Assert.Equal(request2.RequestId, rig.Service.Exposures.Get(item.Id)!.RemediationRequestId);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        SetInstalled(rig, "dev1", "22631.1000", ("Adobe Acrobat", "24.0.1"));
        var closed = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.True(closed.Ok, closed.Reason);
    }

    // ---- F4: convergence always has a fix reference ---------------

    [Fact]
    public void D38F4_FeedNamesNoFix_CatalogueFix_SecondVulnerableInstall_BlocksClosure()
    {
        var rig = Rmm05Tests.NewRig();
        // First-listed install is FIXED (PatchScanner's first read
        // is satisfied); the second is vulnerable. Feed names NO fix.
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev1", software: new[]
        {
            ("Adobe Acrobat", "24.0.1"), ("Adobe Acrobat", "9.0"),
        }), T0);
        rig.Service.ImportFeed(Rmm05Tests.Feed(entries: new[]
        {
            Rmm05Tests.AcrobatCve(fixedIn: null),
        }), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Null(item.FixedInVersion); // the feed named no fix — the F4 precondition
        // Catalogue entry admitted AFTER discovery (found by the
        // request fallback), approved, scanner read satisfied:
        var entry = AcrobatEntry();
        rig.Patches.Service.AdmitEntries(new[] { entry }, "setup");
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), entry.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        // Pre-fix the ANY-install check was skipped (item fix was
        // null) and this closed. Now the ENTRY's fix binds:
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        // REPAIRED (Wave 2 Lane B, 2026-11-22) for bd-shared-rmm-2/F7:
        // PatchScanner.DetermineMissing now evaluates EVERY install
        // (lowest version), so the scanner itself reports the patch
        // missing and closure refuses UPSTREAM with the scanner's
        // reason — it no longer falls through to the ANY-install
        // check that produced the old string. The refusal (the F4
        // invariant) is unchanged; the governing reason moved.
        Assert.Contains("still reports patch", refused.Reason);
    }

    [Fact]
    public void D38F4_OsExposure_BuildConvergenceChecked_AndProductlessEntryServesOnlyOsItems()
    {
        var rig = Rmm05Tests.NewRig();
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev1", osBuild: "22631.1000"), T0);
        var osCve = new VulnerabilityFeedEntry("CVE-2024-99999", "Windows OS", null, "windows", "22631.3000",
            9.1, "critical", false, null, T0.AddDays(-2), "OS flaw");
        rig.Service.ImportFeed(Rmm05Tests.Feed(entries: new[] { osCve }), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal("22631.3000", item.FixedInOsBuild);
        // Productless OS entry admitted after discovery: the
        // fallback may serve THIS (OS-shaped) item…
        var kb = Rmm02Tests.OsKb();
        rig.Patches.Service.AdmitEntries(new[] { kb }, "setup");
        var (ok, reason, _) = rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech");
        Assert.True(ok, reason);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), kb.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        // …but closure refuses while the device build is below
        // the fix (pre-fix: no build check existed on this path
        // at all). DISPOSITION (completion #4, D38F4 reconciliation):
        // the refusal fires at the PatchScanner still-missing step
        // — DetermineMissing is itself build-aware for OS entries,
        // so it names the patch "missing" BEFORE the dedicated
        // build-convergence branch is reached. The original test
        // asserted the later branch's "fixed build" wording and
        // failed on the reason string while the service behaviour
        // (refuse below the fix, close above it) was correct —
        // TEST side wrong, amended here. The dedicated build
        // branch is pinned separately by
        // D38F4_OsExposure_BuildBranch_BindsSnapshot_WhenScannerSatisfied.
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("missing", refused.Reason);
        SetInstalled(rig, "dev1", "22631.4000");
        var closed = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.True(closed.Ok, closed.Reason);
    }

    [Fact]
    public void D38F4_OsExposure_BuildBranch_BindsSnapshot_WhenScannerSatisfied()
    {
        // The dedicated OS-build convergence branch in
        // CloseWithPatchEvidence, isolated: the catalogue entry's
        // OWN fixed build (22631.0500) is BELOW the device build
        // (22631.1000), so PatchScanner reports the patch NOT
        // missing and the scanner step passes — but the exposure's
        // discovery-time snapshot names 22631.3000, and the build
        // branch must still refuse until the device reaches it.
        var rig = Rmm05Tests.NewRig();
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev1", osBuild: "22631.1000"), T0);
        var osCve = new VulnerabilityFeedEntry("CVE-2024-99999", "Windows OS", null, "windows", "22631.3000",
            9.1, "critical", false, null, T0.AddDays(-2), "OS flaw");
        rig.Service.ImportFeed(Rmm05Tests.Feed(entries: new[] { osCve }), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.Equal("22631.3000", item.FixedInOsBuild);
        var kb = Rmm02Tests.OsKb() with { FixedInOsBuild = "22631.0500" };
        rig.Patches.Service.AdmitEntries(new[] { kb }, "setup");
        Assert.True(rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech").Ok);
        Assert.True(rig.Patches.Service.Decide(Rmm05Tests.Facts(), kb.Id, "dev1",
            approve: true, decidedBy: "admin").Ok);
        var refused = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.False(refused.Ok);
        Assert.Contains("fixed build", refused.Reason);
        SetInstalled(rig, "dev1", "22631.4000");
        var closed = rig.Service.CloseWithPatchEvidence(item.Id, "tech");
        Assert.True(closed.Ok, closed.Reason);
    }

    [Fact]
    public void D38F4_ProductlessOsEntry_DoesNotServeProductExposure()
    {
        var rig = RigWithExposure(out var item); // Acrobat product exposure, no PatchEntryId yet
        var kb = Rmm02Tests.OsKb() with { CveIds = new[] { "CVE-2024-12345" } };
        rig.Patches.Service.AdmitEntries(new[] { kb }, "setup");
        // Pre-fix the fallback matched ANY productless entry
        // carrying the CVE — an OS patch for a product exposure.
        var (ok, reason, _) = rig.Service.RequestPatchRemediation(Rmm05Tests.Facts(), item.Id, "tech");
        Assert.False(ok);
        Assert.Contains("nothing to request", reason);
    }

    // ---- F5: reports are scoped + policy-gated ---------------------

    [Fact]
    public void D38F5_BuildReport_OnlyCallersScope_HubScopeSeesAll()
    {
        var rig = Rmm05Tests.RigWithFleet();
        var dev8 = Rmm05Tests.Record("dev8", software: new[] { ("Adobe Acrobat", "23.0.5") })
            with { ScopeId = "scope2" };
        rig.Inventory.ApplyBaseline(dev8, T0);
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());                    // scope1: dev1
        rig.Service.RunCorrelation(Rmm05Tests.Facts("dev8", "scope2"));    // scope2: dev8
        Assert.Equal(2, rig.Service.Exposures.Items.Count);
        var r1 = rig.Service.BuildReport(Rmm05Tests.Facts());
        Assert.Equal(1, r1.OpenCount);
        Assert.All(r1.PrioritisedOpen, i => Assert.Equal("scope1", i.ScopeId));
        var r2 = rig.Service.BuildReport(Rmm05Tests.Facts("dev8", "scope2"));
        Assert.Equal(1, r2.OpenCount);
        Assert.All(r2.PrioritisedOpen, i => Assert.Equal("dev8", i.DeviceId));
        var hub = rig.Service.BuildReport(Rmm05Tests.Facts("hub", ""));    // "" = hub = whole fleet
        Assert.Equal(2, hub.OpenCount);
    }

    [Fact]
    public void D38F5_BuildReport_PolicyDisabled_RefusesEmptyAndNamed()
    {
        var rig = RigWithExposure(out _);
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "vuln-off", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { [VulnerabilityPolicyKeys.Enabled] = "false" }, 1), "test");
        var report = rig.Service.BuildReport(Rmm05Tests.Facts("dev1"));
        Assert.False(report.PolicyEnabled);
        Assert.NotNull(report.RefusalReason);
        Assert.Equal(0, report.OpenCount);
        Assert.Empty(report.PrioritisedOpen);
        Assert.Empty(report.Overdue);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_report_refused");
    }

    // ---- F6: scanner-only path honours the feed's fix --------------

    [Fact]
    public void D38F6_ScannerOnlyFinding_DeviceAboveFeedFix_NoExposureManufactured()
    {
        var rig = Rmm05Tests.RigWithFleet(); // dev2 runs Acrobat 25.2; feed fix is 24.0; NO catalogue
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        var forged = """
            {"findings":[
              {"id":"x-1","host_id":"dev2","software":"Adobe Acrobat","version":"25.2.0","cve":"CVE-2024-12345","cvss":9.8}]}
            """;
        Assert.True(rig.Service.ImportScannerResults("tenable", forged, "attacker").Ok);
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        // dev1's feed exposure exists; dev2 (at/above the FEED fix)
        // gets NO scanner-only exposure — pre-fix the scanner-only
        // path never consulted the feed's FixedInVersion.
        var item = Assert.Single(rig.Service.Exposures.Items);
        Assert.Equal("dev1", item.DeviceId);
    }

    // ---- F7: scanner device resolution is corroborated -------------

    [Fact]
    public void D38F7_DuplicateHostname_FindingOrphanedNotArbitrarilyPinned()
    {
        var rig = Rmm05Tests.NewRig();
        var a = Rmm05Tests.Record("devA", software: new[] { ("Adobe Acrobat", "23.0.5") }) with { Hostname = "pc01" };
        var b = Rmm05Tests.Record("devB", software: new[] { ("Adobe Acrobat", "23.0.5") }) with { Hostname = "pc01" };
        rig.Inventory.ApplyBaseline(a, T0);
        rig.Inventory.ApplyBaseline(b, T0);
        var json = """
            {"findings":[
              {"id":"x-1","host_name":"pc01","software":"Adobe Acrobat","version":"23.0.5","cve":"CVE-2024-12345","cvss":9.8}]}
            """;
        Assert.True(rig.Service.ImportScannerResults("tenable", json, "admin").Ok);
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Empty(rig.Service.Exposures.Items);          // NOT pinned to an arbitrary pc01
        Assert.Single(run.Result!.OrphanFindings);
    }

    [Fact]
    public void D38F7_VendorIdAndHostnameDisagree_FindingOrphaned()
    {
        var rig = Rmm05Tests.RigWithFleet(); // dev1 = host-dev1, dev2 = host-dev2
        // Vendor id names dev1; hostname names dev2's host. Two
        // namespaces, two different devices: conflict, not a match.
        var json = """
            {"findings":[
              {"id":"x-1","host_id":"dev1","host_name":"host-dev2","software":"Adobe Acrobat","version":"23.0.5","cve":"CVE-2024-12345","cvss":9.8}]}
            """;
        Assert.True(rig.Service.ImportScannerResults("tenable", json, "admin").Ok);
        var run = rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Empty(rig.Service.Exposures.Items);
        Assert.Single(run.Result!.OrphanFindings);
    }

    // ---- F8: fix references are sticky + snapshot ------------------

    [Fact]
    public void D38F8_FeedLowersFixedVersion_CachedFixStands_Flagged_DiscoveryContinues()
    {
        var rig = Rmm05Tests.RigWithFleet();
        rig.Inventory.ApplyBaseline(Rmm05Tests.Record("dev7",
            software: new[] { ("Adobe Acrobat", "12.0") }), T0);
        Assert.True(rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin").Accepted);
        var poisoned = Rmm05Tests.Feed(2, entries: new[]
        {
            Rmm05Tests.AcrobatCve(cvss: 9.8, severity: "critical", kev: true, fixedIn: "1.0"),
        });
        var result = rig.Service.ImportFeed(poisoned, "attacker-feed");
        Assert.True(result.Accepted);
        Assert.Contains(result.DowngradeFlags, f => f.Contains("fixed-in version downgrade"));
        Assert.Equal("24.0", Assert.Single(rig.Service.Feeds.Current!.Entries).FixedInVersion);
        // Discovery continues against the cached fix: dev7's 12.0
        // is still an exposure (at fix "1.0" it would have vanished).
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        Assert.Contains(rig.Service.Exposures.Items, i => i.DeviceId == "dev7");
    }

    [Fact]
    public void D38F8_Refresh_FillsButNeverRewrites_FixSnapshot()
    {
        var rig = RigWithExposure(out var item);
        Assert.Equal("24.0", item.FixedInVersion);
        var fact = new ExposureFact(item.DeviceId, item.ScopeId, item.CveId, item.ProductName,
            new[] { "23.0.5" }, "1.0", null, 9.8, "critical", true,
            ExposureSources.Feed, false, null);
        var (after, created) = rig.Service.Exposures.Upsert(fact, "feed", "hash",
            VulnerabilitySlaPolicy.Default, T0.AddHours(1));
        Assert.False(created);
        Assert.Equal("24.0", after.FixedInVersion); // snapshot stands
    }

    // ---- F9: findings bookkeeping ----------------------------------

    [Fact]
    public void D38F9_ScannerReimport_Dedupes_HeldCountStable()
    {
        var rig = Rmm05Tests.RigWithFleet();
        var json = """{"findings":[{"id":"t-1","host_id":"dev1","software":"Adobe Acrobat","version":"23.0.5","cve":"CVE-2024-12345","cvss":9.8}]}""";
        Assert.True(rig.Service.ImportScannerResults("tenable", json, "admin").Ok);
        Assert.True(rig.Service.ImportScannerResults("tenable", json, "admin").Ok);
        Assert.Single(rig.Service.Findings);
    }

    // ---- F10: every verb is policy-gated; report reopenings audited -

    [Fact]
    public void D38F10_PolicyDisabled_RecordControlAndBothClosuresRefuse()
    {
        var rig = RigWithExposure(out var item);
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "vuln-off", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { [VulnerabilityPolicyKeys.Enabled] = "false" }, 1), "test");
        var control = rig.Service.RecordCompensatingControl(item.Id,
            "Isolation control for the BAS host.", "owner-a", T0.AddDays(30), "doc", "tech");
        Assert.False(control.Ok);
        Assert.Contains("disabled by policy", control.Reason);
        Assert.False(rig.Service.CloseWithPatchEvidence(item.Id, "tech").Ok);
        Assert.False(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(item.Id)!.State);
    }

    [Fact]
    public void D38F10_BuildReport_ReopeningsAreChainedAudited()
    {
        var rig = RigWithExposure(out var item);
        Assert.True(rig.Service.RecordCompensatingControl(item.Id,
            "Short-lived isolation control.", "owner-a", T0.AddDays(3), "doc", "tech").Ok);
        Assert.True(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
        rig.Clock.Now = T0.AddDays(4); // review passed; NO correlation run
        var report = rig.Service.BuildReport(Rmm05Tests.Facts());
        // The report's own expiry evaluation reopened the item —
        // and unlike pre-fix, that reopening is in the audit chain.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_exposure_reopened");
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(item.Id)!.State);
        Assert.Equal(1, report.OpenCount);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- F11: per-field SLA fallback --------------------------------

    [Fact]
    public void D38F11_SlaPolicy_PerFieldFallback_ExactDeadlines()
    {
        var sla = new VulnerabilitySlaPolicy(
            CriticalHours: 0, HighHours: -5, MediumHours: 0, LowHours: 999999, KevCapHours: 0);
        Assert.Equal(TimeSpan.FromHours(72), sla.SlaFor("critical", false));  // default critical, not medium
        Assert.Equal(TimeSpan.FromHours(336), sla.SlaFor("high", false));
        Assert.Equal(TimeSpan.FromHours(720), sla.SlaFor("medium", false));
        Assert.Equal(TimeSpan.FromHours(2160), sla.SlaFor("low", false));
        // The F11 shape: KevCapHours=0 must NOT widen a KEV item
        // to the 720h medium — the cap falls back to the default
        // 336h cap, and a KEV critical keeps its 72h.
        Assert.Equal(TimeSpan.FromHours(336), sla.SlaFor("low", true));
        Assert.Equal(TimeSpan.FromHours(72), sla.SlaFor("critical", true));
    }

    // ---- F12: correlator never throws on duplicate fact keys --------

    [Fact]
    public void D38F12_DirectCorrelator_DuplicateFactKeys_MergeNeverThrow()
    {
        // A feed presented DIRECTLY to the pure correlator (the
        // feed store's duplicate refusal bypassed) carrying two
        // entries whose facts key identically — pre-fix the
        // ToDictionary fact index threw and crashed the run.
        var records = new[] { Rmm05Tests.Record("dev1", software: new[] { ("Adobe Acrobat", "23.0.5") }) };
        var feed = new VulnerabilityFeed("direct", "test", 1, T0, new[]
        {
            Rmm05Tests.AcrobatCve(),
            Rmm05Tests.AcrobatCve() with { ProductName = "Adobe Acrobat " }, // trailing space: same normalised key
        });
        var findings = new[]
        {
            new ScannerFinding("tenable", "f-1", "dev1", "host-dev1", "Adobe Acrobat", "23.0.5", "CVE-2024-12345", 9.8),
        };
        var result = VulnerabilityCorrelator.Correlate(records, feed, null, findings, FeedProvenance.None(T0));
        Assert.NotEmpty(result.Facts);
        Assert.Contains(result.Facts, f => f.DeviceId == "dev1" && f.Source == ExposureSources.FeedAndScanner);
    }
}

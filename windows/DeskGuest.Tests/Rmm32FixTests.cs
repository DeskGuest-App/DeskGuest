using DeskGuest.Core.Services;
using DeskGuest.Shared.Dlp;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;

namespace DeskGuest.Tests;

// RMM-32 D38 FIX lane — regression tests for packet 02be4dd4
// (12 findings, F1–F12). Each test names the finding it pins.
// FAKE test vectors only.
public class Rmm32FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string Reader = "compliance-reader";
    private const string TestVisa = "4111111111111111";
    private const string TestMc = "5500005555555559";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope);
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope);
        public RecordingDlpAlertSink Sink = new();
        public RecordingDlpEgressApplier Applier = new();
        public DlpService Svc;
        public Rig()
        {
            Svc = new DlpService(Audit, Policy, Sink, Applier,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, () => Now);
            SetPolicy(DlpKeys.FeatureEnabled, "true", "doc-enable");
        }
        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
    }

    private static DlpScanDefinition Def(string machine = Dev, string id = "scan-1",
        IReadOnlyList<string>? roots = null, IReadOnlyList<string>? classifiers = null) =>
        new(id, machine, roots ?? new[] { @"C:\Data" }, new[] { ".txt" }, false,
            classifiers ?? new[] { DlpClassifierIds.PaymentCard }, Admin, T0);

    private static InMemoryDlpFileSource Source(params (string Path, string Content)[] files) =>
        new(files.Select(f => new DlpFileItem(f.Path, f.Content, f.Content.Length)));

    private sealed class SkippingSource : IDlpFileSource
    {
        public IReadOnlyList<string> Skipped => new[] { "root 'C:\\Data' does not exist on this endpoint — skipped (named)" };
        public IEnumerable<DlpFileItem> Enumerate(DlpScanDefinition snapshot) => Array.Empty<DlpFileItem>();
    }

    private sealed class ThrowingSource : IDlpFileSource
    {
        public IReadOnlyList<string> Skipped => Array.Empty<string>();
        public IEnumerable<DlpFileItem> Enumerate(DlpScanDefinition snapshot) =>
            throw new InvalidOperationException("source boom");
    }

    // ---- F1: per-machine purge + sweep authorization --------------------

    [Fact]
    public void F1_SweepForOneMachine_LeavesOtherMachinesRecordsIntact()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        rig.Svc.RunScan(Dev2, Def(machine: Dev2), Source((@"C:\Data\b.txt", TestMc)), Admin);
        Assert.Single(rig.Svc.Findings.Findings.Where(f => f.MachineId == Dev));
        Assert.Single(rig.Svc.Findings.Findings.Where(f => f.MachineId == Dev2));

        rig.Now = T0.AddDays(91);
        var (purged, _) = rig.Svc.SweepRetention(Dev, Reader);
        Assert.True(purged >= 3);
        Assert.Empty(rig.Svc.Findings.Findings.Where(f => f.MachineId == Dev));
        // The other machine's equally-old records SURVIVE a sweep
        // resolved from dev-1's policy — the pre-fix purge deleted
        // them too.
        Assert.Single(rig.Svc.Findings.Findings.Where(f => f.MachineId == Dev2));
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
    }

    [Fact]
    public void F1_SweepWithoutReaderAuthority_IsRefusedAndAudited()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        rig.Now = T0.AddDays(91);
        // The scan operator, an intruder, and nobody are all refused.
        Assert.Equal(0, rig.Svc.SweepRetention(Dev, Admin).Purged);
        Assert.Equal(0, rig.Svc.SweepRetention(Dev, "mallory-intruder").Purged);
        Assert.Equal(0, rig.Svc.SweepRetention(Dev, null!).Purged);
        Assert.Single(rig.Svc.Findings.Findings);                     // nothing was destroyed
        Assert.Equal(3, rig.Audit.Entries.Count(e => e.Kind == "dlp_retention_sweep_refused"));
    }

    // ---- F2: a scan that inspected nothing is not a pass -----------------

    [Fact]
    public void F2_EmptyScan_ProducesFact_ThatIsNotPassing()
    {
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), Source(), Admin);
        Assert.NotNull(summary);
        Assert.Equal(0, summary!.FilesScanned);
        var fact = DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0);
        Assert.NotNull(fact);
        Assert.False(fact!.Passing);
        Assert.Contains("inspected 0", fact.Detail);
    }

    [Fact]
    public void F2_SourceSkips_MarkScanIncomplete_InChainAuditAndAlert_NotPassing()
    {
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), new SkippingSource(), Admin);
        Assert.NotNull(summary);
        Assert.True(summary!.Incomplete);
        Assert.Equal(1, summary.FilesSkippedBySource);
        var completion = rig.Svc.Findings.Records.Single(r => r.Kind == DlpFindingKinds.ScanCompleted);
        Assert.Contains("incomplete=1", completion.MaskedExcerpt);
        Assert.Contains("sourceSkipped=1", completion.MaskedExcerpt);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_scan_completed" && e.Detail.Contains("incomplete=True"));
        Assert.Contains(rig.Sink.Events, e => e.Kind == DlpAlertKind.ScanIncomplete);
        var fact = DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0);
        Assert.False(fact!.Passing);
    }

    [Fact]
    public void F2_MissingRoot_DirectorySource_NamedSkip_NotPassing()
    {
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev,
            Def(roots: new[] { @"C:\NoSuchDir-DlpFix" }), new DirectoryDlpFileSource(), Admin);
        Assert.NotNull(summary);
        Assert.Equal(0, summary!.FilesScanned);
        Assert.True(summary.Incomplete);
        Assert.Contains(summary.Notes, n => n.Contains("does not exist"));
        Assert.False(DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0)!.Passing);
    }

    // ---- F3: channel labelling honesty -----------------------------------

    [Fact]
    public void F3_ViewGovernedChannels_OnlyChannelsWithRules_EnforcersNamedUnbuilt()
    {
        var rig = new Rig();
        var (view, _) = rig.Svc.EffectiveView(Dev);
        Assert.NotNull(view);
        Assert.Empty(view!.GovernedChannels);                         // no rules → nothing governed
        Assert.Contains("NO channel is governed", view.PlainStatement);
        // The decision-channel list itself names that no enforcer is built.
        Assert.All(DlpChannelVisibility.Enforceable, e => Assert.Contains("foundation", e));

        rig.SetPolicy(DlpKeys.EgressRules, "removable_media:block", "doc-egress");
        var (view2, _) = rig.Svc.EffectiveView(Dev);
        var governed = Assert.Single(view2!.GovernedChannels);
        Assert.Contains("removable_media", governed);
        Assert.Contains("none is built in this foundation", governed);
    }

    // ---- F4: card adjacent to other digits --------------------------------

    [Fact]
    public void F4_CardNextToExpiryOrShortNumber_StillCaught()
    {
        var c = new PaymentCardClassifier();
        Assert.Single(c.Find($"{TestVisa} 12/27"));                   // card + expiry
        Assert.Single(c.Find($"{TestVisa} 123"));                     // card + CVV-shaped tail
        Assert.Single(c.Find($"ref 42 {TestVisa}"));                  // short number before the card
        Assert.Single(c.Find("4111 1111 1111 1111 12/27"));           // grouped card + expiry
        Assert.Single(c.Find($"card {TestMc} exp 01/28"));
        // An unseparated over-long digit run is still NOT split.
        Assert.Empty(c.Find("4111111111111111111"));                  // 19 digits, Luhn-invalid as a whole
        // And the description names the retry + the remaining limitation.
        Assert.Contains("retried", c.Description);
        Assert.Contains("never split out", c.Description);
    }

    // ---- F5: findings-access identity discipline ---------------------------

    [Fact]
    public void F5_ReaderMatch_IsExactAndCaseSensitive()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        Assert.Null(rig.Svc.ReadFindings(Dev, "Compliance-Reader").Records);   // case differs → not the named reader
        Assert.Null(rig.Svc.ReadFindings(Dev, "COMPLIANCE-READER").Records);
        Assert.NotNull(rig.Svc.ReadFindings(Dev, Reader).Records);
    }

    [Fact]
    public void F5_OverLengthActor_IsNeverWrittenVerbatimIntoTheAudit()
    {
        var rig = new Rig();
        var longActor = new string('x', 500);
        rig.Svc.ReadFindings(Dev, longActor);
        rig.Svc.SweepRetention(Dev, longActor);
        Assert.All(rig.Audit.Entries, e => Assert.True(e.Actor.Length <= DlpLimits.MaxActorLength + 32,
            $"audit actor of {e.Actor.Length} chars was written unbounded"));
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Actor == longActor);
        Assert.Contains(rig.Audit.Entries, e => e.Actor.Contains("over-length actor"));
    }

    // ---- F6: paths are masked on every surface ------------------------------

    [Fact]
    public void F6_SecretInFileName_AppearsInNoFindingNoteOrSkipNote()
    {
        var rig = new Rig();
        var secretPath = $@"C:\Data\{TestVisa}.txt";
        var (summary, _) = rig.Svc.RunScan(Dev, Def(),
            Source((secretPath, $"content holds {TestMc}")), Admin);
        Assert.NotNull(summary);
        var finding = Assert.Single(rig.Svc.Findings.Findings);
        Assert.DoesNotContain(TestVisa, finding.FilePath);
        Assert.Contains("…", finding.FilePath);
        // Oversize file with a secret name: the skip note is masked too.
        var big = new DlpFileItem($@"C:\Data\{PlantedName}.txt", "x", DlpLimits.MaxFileBytes + 1);
        var (summary2, _) = rig.Svc.RunScan(Dev, Def(id: "scan-2"),
            new InMemoryDlpFileSource(new[] { big }), Admin);
        Assert.Contains(summary2!.Notes, n => n.Contains("exceeds the scan size cap"));
        Assert.All(summary2.Notes, n => Assert.DoesNotContain(PlantedName, n));
    }

    private const string PlantedName = "hunter2hunter2";

    // ---- F7: admin regex pattern is never published --------------------------

    [Fact]
    public void F7_AdminRegexPattern_AppearsInNoEndpointSurface()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.Regexes, "ProjectFalcon[0-9]+", "doc-rx");
        var (policy, reason) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        var classifier = Assert.Single(policy!.Classifiers.OfType<AdminRegexClassifier>());
        Assert.DoesNotContain("ProjectFalcon", classifier.Description);
        Assert.DoesNotContain("ProjectFalcon", reason);
        var (view, _) = rig.Svc.EffectiveView(Dev);
        Assert.All(view!.ClassifierDescriptions, d => Assert.DoesNotContain("ProjectFalcon", d));
        Assert.DoesNotContain("ProjectFalcon", view.PlainStatement);
    }

    [Fact]
    public void F7_InvalidAdminRegex_RefusalNoteWithholdsThePattern()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.Regexes, "ProjectFalcon([", "doc-rx");
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("REFUSED"));
        Assert.All(policy.Notes, n => Assert.DoesNotContain("ProjectFalcon", n));
    }

    // ---- F8: timeouts / source failure never dangle a scan -------------------

    [Fact]
    public void F8_AdminRegexTimeout_ScanStillCompletes_Incomplete_NotPassing()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.Regexes, "(a+)+$", "doc-rx");
        var content = new string('a', 60_000) + "b";
        var (summary, _) = rig.Svc.RunScan(Dev,
            Def(classifiers: new[] { DlpClassifierIds.AdminRegex }),
            Source((@"C:\Data\hard.txt", content)), Admin);
        Assert.NotNull(summary);                                      // the scan did not abort
        Assert.True(summary!.Incomplete);
        Assert.Contains(summary.Notes, n => n.Contains("TIMED OUT"));
        Assert.Contains(rig.Svc.Findings.Records, r => r.Kind == DlpFindingKinds.ScanCompleted);   // started is always paired
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_scan_completed");
        Assert.False(DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0)!.Passing);
    }

    [Fact]
    public void F8_SourceFailure_ScanStillCompletes_Incomplete()
    {
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), new ThrowingSource(), Admin);
        Assert.NotNull(summary);
        Assert.True(summary!.Incomplete);
        Assert.Contains(summary.Notes, n => n.Contains("INCOMPLETE"));
        Assert.Contains(rig.Svc.Findings.Records, r => r.Kind == DlpFindingKinds.ScanStarted);
        Assert.Contains(rig.Svc.Findings.Records, r => r.Kind == DlpFindingKinds.ScanCompleted);
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
    }

    // ---- F9: default-allow egress is audited ----------------------------------

    [Fact]
    public void F9_ClassifiedContentAllowedByDefault_LeavesAnAuditRecord()
    {
        var rig = new Rig();
        var ids = new[] { DlpClassifierIds.PaymentCard };
        var (decision, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.Clipboard, ids, Admin);
        Assert.Equal(DlpEgressDispositions.Allowed, decision!.Disposition);
        Assert.Null(decision.MatchedRule);                            // structurally the default, not a rule
        Assert.Contains("DEFAULT", decision.Reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_egress_decision"
            && e.Detail.Contains("disposition=allowed") && e.Detail.Contains("DEFAULT"));
        // An explicit allow rule is distinguishable from the default.
        rig.SetPolicy(DlpKeys.EgressRules, "clipboard:allow", "doc-egress");
        var (ruled, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.Clipboard, ids, Admin);
        Assert.Equal("clipboard:allow", ruled!.MatchedRule);
    }

    // ---- F10: purge rewrites nothing; purge history persists -------------------

    [Fact]
    public void F10_PurgePreservesSurvivorHashes_AndItsOwnHistory()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        rig.Now = T0.AddDays(100);
        rig.Svc.RunScan(Dev, Def(id: "scan-2"), Source((@"C:\Data\b.txt", TestMc)), Admin);
        var survivorsBefore = rig.Svc.Findings.Records.Where(r => r.ScanId == "scan-2")
            .Select(r => (r.Seq, r.PrevHash, r.Hash)).ToList();
        Assert.Equal(3, survivorsBefore.Count);

        var (purged, _) = rig.Svc.SweepRetention(Dev, Reader);        // 90d window: scan-1 (day 0) expires, scan-2 (day 100) survives
        Assert.Equal(3, purged);
        var survivorsAfter = rig.Svc.Findings.Records.Where(r => r.ScanId == "scan-2")
            .Select(r => (r.Seq, r.PrevHash, r.Hash)).ToList();
        Assert.Equal(survivorsBefore, survivorsAfter);                // NOTHING about a survivor was rewritten
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
        Assert.Single(rig.Svc.Findings.Records.Where(r => r.Kind == DlpFindingKinds.RetentionPurge));

        // Compliance evidence points at the machine's OWN record —
        // never the global head. REPAIRED (Wave 2 Lane B, 2026-11-22)
        // with disclosure: this assertion originally expected the
        // machine's latest record OVERALL (here the purge anchor).
        // bd-shared-sec-1/F6 deliberately changed the semantics: the
        // fact describes the LATEST SCAN, so its evidence ref is that
        // scan's completion record — a later retention_purge record
        // proves retention happened, not scan coverage, and pointing
        // evidence at it made an ancient scan look fresh (the F6
        // defect). The D38-F10 core intent (the machine's OWN record,
        // never another machine's head) is preserved and asserted.
        var fact = DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, rig.Now);
        Assert.NotNull(fact);
        Assert.Equal(rig.Svc.Findings.Records.Where(r => r.MachineId == Dev
                && r.Kind == DlpFindingKinds.ScanCompleted)
            .OrderByDescending(r => r.Seq).First().Hash, fact!.EvidenceRef);

        rig.Now = T0.AddDays(200);
        var (purged2, _) = rig.Svc.SweepRetention(Dev, Reader);       // scan-2 expires now
        Assert.Equal(3, purged2);
        // BOTH purge records survive — the store keeps its purge history.
        Assert.Equal(2, rig.Svc.Findings.Records.Count(r => r.Kind == DlpFindingKinds.RetentionPurge));
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
        // Once every completion record has itself expired, the device
        // produces NO fact (missing-fact honesty) rather than a stale pass.
        Assert.Null(DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, rig.Now));
    }

    // ---- F12: scope edges -------------------------------------------------------

    [Fact]
    public void F12_DriveRootScope_ActuallyMatches()
    {
        var def = Def(roots: new[] { @"C:\" });
        Assert.True(def.PathInScope(@"C:\Data\a.txt"));
        Assert.True(def.PathInScope(@"C:\a.txt"));
        Assert.False(def.PathInScope(@"D:\Data\a.txt"));
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev, def, Source((@"C:\Data\a.txt", TestVisa)), Admin);
        Assert.Equal(1, summary!.FilesScanned);
    }

    [Fact]
    public void F12_DirectorySource_DoesNotFollowSymlinksOutOfScope()
    {
        // On this Linux runner a Windows-form root is a literal
        // relative directory name — enough to exercise the walker.
        var rootName = @"C:\DlpFixLink";
        var rootPath = Path.Combine(Environment.CurrentDirectory, rootName);
        var outside = Path.Combine(Environment.CurrentDirectory, "dlp-fix-outside.txt");
        Directory.CreateDirectory(rootPath);
        try
        {
            File.WriteAllText(Path.Combine(rootPath, "real.txt"), $"card {TestVisa}");
            File.WriteAllText(outside, $"card {TestMc}");
            File.CreateSymbolicLink(Path.Combine(rootPath, "link.txt"), outside);
            var rig = new Rig();
            var (summary, _) = rig.Svc.RunScan(Dev, Def(roots: new[] { rootName }),
                new DirectoryDlpFileSource(), Admin);
            Assert.NotNull(summary);
            Assert.Equal(1, summary!.FilesScanned);                   // only the real in-scope file
            Assert.Equal(1, summary.TotalMatches);                    // the linked outside card was NOT scanned
        }
        finally
        {
            try { File.Delete(Path.Combine(rootPath, "link.txt")); } catch { }
            try { Directory.Delete(rootPath, recursive: true); } catch { }
            try { File.Delete(outside); } catch { }
        }
    }
}

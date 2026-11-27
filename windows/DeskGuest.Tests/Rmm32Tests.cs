using DeskGuest.Core.Services;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Dlp;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;

namespace DeskGuest.Tests;

// RMM-32 — Endpoint DLP + sensitive-data discovery (honest foundation):
// Luhn-validated card classifier + SSA-ruled national-ID + stated secret
// shapes + admin keyword/regex classifiers; declared-scope discovery
// scans producing redacted metadata findings (never the matched value);
// egress policy at DeskGuest-controlled channels with unseeable channels
// named; findings RBAC + audited reads + finite retention; the
// endpoint effective view naming what is scanned for (no hidden
// inspection). FAKE test vectors only (standard published test card
// numbers, example-range SSNs are NOT used — SSA-valid-shaped fakes).
public class Rmm32Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string Reader = "compliance-reader";
    // Standard published test card numbers (Visa/MC test vectors).
    private const string TestVisa = "4111111111111111";
    private const string TestMc = "5500005555555559";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-a" });
        public RecordingDlpAlertSink Sink = new();
        public RecordingDlpEgressApplier Applier = new();
        public DlpService Svc;

        public Rig(bool enable = true)
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Svc = new DlpService(Audit, Policy, Sink, Applier, id => id == Dev ? Facts1 : null, () => Now);
            if (enable) SetPolicy(DlpKeys.FeatureEnabled, "true", "doc-enable");
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
    }

    private static DlpScanDefinition Def(
        IReadOnlyList<string>? roots = null, IReadOnlyList<string>? exts = null,
        IReadOnlyList<string>? classifiers = null, bool allExts = false, string id = "scan-1") =>
        new(id, Dev, roots ?? new[] { @"C:\Data" }, exts ?? new[] { ".txt" }, allExts,
            classifiers ?? new[] { DlpClassifierIds.PaymentCard }, Admin, T0);

    private static InMemoryDlpFileSource Source(params (string Path, string Content)[] files) =>
        new(files.Select(f => new DlpFileItem(f.Path, f.Content, f.Content.Length)));

    // ---- classifiers ---------------------------------------------------

    [Fact]
    public void CardClassifier_LuhnValidTestCards_AreFindings_FailedLuhn_IsNot()
    {
        var c = new PaymentCardClassifier();
        Assert.Single(c.Find($"card on file: {TestVisa}"));
        Assert.Single(c.Find($"mc: {TestMc}"));
        Assert.Single(c.Find("grouped 4111 1111 1111 1111"));      // grouped form caught
        Assert.Single(c.Find("dashed 4111-1111-1111-1111"));
        Assert.Empty(c.Find("not a card: 4111111111111112"));       // fails Luhn → NOT a finding
        Assert.Empty(c.Find("short: 411111111111"));                // 12 digits: not a card shape
        Assert.True(PaymentCardClassifier.LuhnValid(TestVisa));
        Assert.False(PaymentCardClassifier.LuhnValid("4111111111111112"));
    }

    [Fact]
    public void NationalIdClassifier_SsaRules_FilterInvalidShapes()
    {
        var c = new NationalIdClassifier();
        Assert.Single(c.Find("ssn 321-54-9876"));
        // D38 F12 (test amended — baked-in defect): 123-45-6789 is a
        // widely circulated SAMPLE number the SSA never issues; the
        // original vector asserted it as a valid finding.
        Assert.Empty(c.Find("sample number 123-45-6789"));
        Assert.Empty(c.Find("area zero 000-45-6789"));
        Assert.Empty(c.Find("area 666 666-45-6789"));
        Assert.Empty(c.Find("area 9xx 900-45-6789"));
        Assert.Empty(c.Find("group zero 123-00-6789"));
        Assert.Empty(c.Find("serial zero 123-45-0000"));
        Assert.Empty(c.Find("undashed 123456789"));                 // named limitation: dashed only
    }

    [Fact]
    public void SecretClassifier_StatedShapesOnly()
    {
        var c = new CredentialSecretClassifier();
        Assert.Contains(c.Find("key AKIAIOSFODNN7EXAMPLE here"), m => m.RawValue.StartsWith("AKIA"));
        Assert.Contains(c.Find("-----BEGIN PRIVATE KEY-----"), m => m.RawValue.Contains("PRIVATE KEY"));
        Assert.Contains(c.Find("password = hunter2hunter2"), m => m.RawValue == "hunter2hunter2");
        Assert.Contains(c.Find("api_key: abcdefgh12345678"), m => m.RawValue == "abcdefgh12345678");
        Assert.Empty(c.Find("the password is mentioned in prose with no assignment"));
    }

    [Fact]
    public void AdminClassifiers_KeywordsLiteral_RegexValidated()
    {
        var kw = new AdminKeywordClassifier(new[] { "Project Falcon", "merger" });
        Assert.Equal(2, kw.Find("notes on PROJECT FALCON and the Merger").Count);
        var rx = new AdminRegexClassifier(@"EMP-\d{4}");
        Assert.Single(rx.Find("badge EMP-1234 issued"));
        Assert.ThrowsAny<ArgumentException>(() => new AdminRegexClassifier("([unclosed"));
    }

    [Fact]
    public void MaskingRule_First2Last2_ShortValuesOmittedEntirely()
    {
        Assert.Equal("41…11", DlpMasking.Mask(TestVisa));
        Assert.Equal("hu…r2", DlpMasking.Mask("hunter2hunter2"));
        Assert.Null(DlpMasking.Mask("short"));
        Assert.Null(DlpMasking.Mask("12345678"));                    // 8 chars: under the 9-char floor
        Assert.Equal("12…89", DlpMasking.Mask("123456789"));
    }

    // ---- policy gate -----------------------------------------------------

    [Fact]
    public void Dlp_DefaultsOff_ScanRefuses_UntilExplicitlyEnabled()
    {
        var rig = new Rig(enable: false);
        var (summary, reason) = rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        Assert.Null(summary);
        Assert.Contains("seeded OFF", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_scan_refused");
        Assert.Empty(rig.Svc.Findings.Records);

        var seeded = FeatureToggleRegistry.Seeded();
        Assert.True(seeded.TryGet(DlpKeys.FeatureEnabled, out var toggle));
        Assert.False(toggle!.DefaultEnabled);
    }

    [Fact]
    public void Resolver_UnknownClassifierDroppedNamed_InvalidRegexRefusedNamed()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.Classifiers, "payment_card,ml_magic", "doc-cls");
        rig.SetPolicy(DlpKeys.Regexes, @"EMP-\d{4}|([broken", "doc-rx");
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        Assert.DoesNotContain(policy!.Classifiers, c => c.Id == "ml_magic");
        Assert.Contains(policy.Notes, n => n.Contains("ml_magic") && n.Contains("closed"));
        // D38 F7 (test amended — baked-in defect): the original
        // assertion required the refusal note to echo the raw admin
        // pattern; the note now names the refusal by position + size
        // and withholds the pattern.
        Assert.Contains(policy.Notes, n => n.Contains("REFUSED") && n.Contains("withheld"));
        Assert.DoesNotContain(policy.Notes, n => n.Contains("([broken"));
        Assert.Single(policy.Classifiers.OfType<AdminRegexClassifier>());
    }

    // ---- scans + findings --------------------------------------------------

    [Fact]
    public void Scan_ProducesRedactedFindings_CountsAndMaskedExcerptOnly()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        var content = $"two cards {TestVisa} and {TestMc}, plus a non-card 4111111111111112";
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\cards.txt", content)), Admin);
        Assert.NotNull(summary);
        Assert.Equal(1, summary!.FilesScanned);
        Assert.Equal(1, summary.FilesWithFindings);
        Assert.Equal(2, summary.TotalMatches);                       // Luhn failures never counted

        var finding = Assert.Single(rig.Svc.Findings.Findings);
        Assert.Equal(DlpClassifierIds.PaymentCard, finding.ClassifierId);
        Assert.Equal("1", finding.ClassifierVersion);
        Assert.Equal(2, finding.MatchCount);
        Assert.Equal("41…11", finding.MaskedExcerpt);
        // D38 F6 (test amended — baked-in defect): the original
        // assertion required the RAW path in the finding; the stored
        // path is masked (file name under the first2-last2 rule — a
        // short name is replaced whole).
        Assert.Equal(@"C:\Data\….txt", finding.FilePath);
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_scan_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_scan_completed");
        Assert.Single(rig.Sink.Events, e => e.Kind == DlpAlertKind.ScanFindings && e.FindingCount == 2);
    }

    [Fact]
    public void Scan_ScopeIsClosed_OutOfScopeFilesRefusedNamedNotScanned()
    {
        var rig = new Rig();
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), Source(
            (@"C:\Data\ok.txt", TestVisa),
            (@"C:\Data2\escape.txt", TestVisa),                       // sibling prefix is NOT inside C:\Data
            (@"C:\Data\..\Secrets\escape2.txt", TestVisa),            // traversal
            (@"C:\Data\wrong.csv", TestVisa),                         // extension outside scope
            (@"D:\Elsewhere\x.txt", TestVisa)), Admin);
        Assert.NotNull(summary);
        Assert.Equal(1, summary!.FilesScanned);
        Assert.Equal(4, summary.FilesSkippedOutOfScope);
        Assert.Single(rig.Svc.Findings.Findings);
        Assert.Contains(summary.Notes, n => n.Contains("OUTSIDE the declared scan scope"));
    }

    [Fact]
    public void ScanDefinition_ValidationRefusesImplicitScope()
    {
        Assert.NotNull(Def(roots: Array.Empty<string>()).Validate());
        Assert.NotNull(Def(exts: Array.Empty<string>(), allExts: false).Validate());
        Assert.NotNull(Def(roots: new[] { "relative\\path" }).Validate());
        Assert.NotNull(Def(roots: new[] { @"C:\Data\..\Secrets" }).Validate());
        Assert.NotNull(Def(classifiers: Array.Empty<string>()).Validate());
        Assert.Null(Def().Validate());
        Assert.Null(Def(exts: Array.Empty<string>(), allExts: true).Validate());
    }

    [Fact]
    public void Scan_CannotNameClassifierPolicyDoesNotCarry()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.Classifiers, "payment_card", "doc-cls");
        var (summary, reason) = rig.Svc.RunScan(Dev,
            Def(classifiers: new[] { DlpClassifierIds.CredentialSecret }),
            Source((@"C:\Data\a.txt", "password = hunter2hunter2")), Admin);
        Assert.Null(summary);
        Assert.Contains("cannot widen beyond policy", reason);
    }

    // ---- findings access / retention ---------------------------------------

    [Fact]
    public void FindingsRead_RbacScoped_AndEveryReadAudited()
    {
        var rig = new Rig();
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        // No readers configured → nobody reads, not even the scan operator.
        var (denied, denyReason) = rig.Svc.ReadFindings(Dev, Admin);
        Assert.Null(denied);
        Assert.Contains("not a policy-named findings reader", denyReason);

        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        var (records, _) = rig.Svc.ReadFindings(Dev, Reader);
        Assert.NotNull(records);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_findings_read" && e.Actor == Reader);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_findings_read_refused");
    }

    [Fact]
    public void Retention_DefaultIs90Days_SweepPurgesExpiredAndChainsThePurge()
    {
        var rig = new Rig();
        // D38 F1 (test amended): the sweep is a destructive act that
        // now requires findings-reader authority — the scan operator
        // (Admin, not a reader) can no longer purge.
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        Assert.Single(rig.Svc.Findings.Findings);
        rig.Now = T0.AddDays(91);
        var (purged, _) = rig.Svc.SweepRetention(Dev, Reader);
        Assert.True(purged >= 3);                                     // started + finding + completed
        Assert.Empty(rig.Svc.Findings.Findings);
        Assert.Contains(rig.Svc.Findings.Records, r => r.Kind == DlpFindingKinds.RetentionPurge);
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "dlp_retention_sweep");
    }

    // ---- egress --------------------------------------------------------------

    [Fact]
    public void Egress_ClassifiedContent_BlockedOrApprovalPerChannelRule()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.EgressRules, "removable_media:block|print:require_approval", "doc-egress");
        var ids = new[] { DlpClassifierIds.PaymentCard };

        var (blocked, apply, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.RemovableMedia, ids, Admin);
        Assert.Equal(DlpEgressDispositions.Blocked, blocked!.Disposition);
        Assert.True(apply!.Applied);
        Assert.Single(rig.Applier.Applied);

        var (approval, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.Print, ids, Admin);
        Assert.Equal(DlpEgressDispositions.ApprovalRequired, approval!.Disposition);

        var (allowed, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.Clipboard, ids, Admin);
        Assert.Equal(DlpEgressDispositions.Allowed, allowed!.Disposition);   // no rule → named default allow

        var (clean, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.RemovableMedia, Array.Empty<string>(), Admin);
        Assert.Equal(DlpEgressDispositions.NoClassifiedContent, clean!.Disposition);
    }

    [Fact]
    public void Egress_UnseeableChannel_ClaimsNoDecision()
    {
        var rig = new Rig();
        var (decision, _, reason) = rig.Svc.EvaluateEgress(Dev, "email_via_third_party_client",
            new[] { DlpClassifierIds.PaymentCard }, Admin);
        Assert.Equal(DlpEgressDispositions.UnseeableChannel, decision!.Disposition);
        Assert.Contains("NO decision is claimed", reason);
        Assert.Contains("UNSEEABLE", DlpChannelVisibility.CoverageStatement);
    }

    [Fact]
    public void Egress_WhenDlpDisabled_IsNotCovered_NeverPresentedAsAllowed()
    {
        var rig = new Rig(enable: false);
        var (decision, _, reason) = rig.Svc.EvaluateEgress(Dev, DlpChannels.RemovableMedia,
            new[] { DlpClassifierIds.PaymentCard }, Admin);
        Assert.Equal(DlpEgressDispositions.NotCovered, decision!.Disposition);
        Assert.Contains("NOT covered", reason);
    }

    // ---- effective view / compliance ------------------------------------------

    [Fact]
    public void EffectiveView_NamesWhatIsScannedFor_NoHiddenInspection()
    {
        var rig = new Rig();
        var (view, _) = rig.Svc.EffectiveView(Dev);
        Assert.NotNull(view);
        Assert.True(view!.DlpEnabled);
        Assert.Contains(view.ClassifierDescriptions, d => d.Contains("payment_card"));
        Assert.Contains("ENABLED on this machine", view.PlainStatement);
        Assert.Contains("never the matched value", view.PlainStatement);
        Assert.Equal(90, view.FindingsRetentionDays);
        Assert.NotEmpty(view.UnseeableChannels);

        var off = new Rig(enable: false);
        var (offView, _) = off.Svc.EffectiveView(Dev);
        Assert.False(offView!.DlpEnabled);
        Assert.Contains("DISABLED", offView.PlainStatement);
    }

    [Fact]
    public void ComplianceFact_CountsOnly_NeverScannedDeviceProducesNoFact()
    {
        var rig = new Rig();
        Assert.Null(DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0));
        rig.Svc.RunScan(Dev, Def(), Source((@"C:\Data\a.txt", TestVisa)), Admin);
        var fact = DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0);
        Assert.NotNull(fact);
        Assert.False(fact!.Passing);
        Assert.Equal("dlp_discovery", fact.Kind);
        Assert.DoesNotContain(TestVisa, fact.Detail);
        Assert.Equal(rig.Svc.Findings.HeadHash, fact.EvidenceRef);
    }
}

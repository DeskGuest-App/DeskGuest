using System.Text;
using Acp.Core.Services;
using Acp.Shared.Dlp;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;

namespace Acp.Tests;

// RMM-32 DESTRUCTION — attack the honest foundation:
//  D32-01 secret leakage FROM findings (the store as the best place
//         to steal secrets): planted secrets must appear NOWHERE —
//         not in findings, audit details, alerts, compliance facts
//         or any serialized surface.
//  D32-02 classifier evasion: separated digits — what the card
//         detector honestly catches vs its NAMED limitation.
//  D32-03 Luhn false-positive flood: random digit strings must not
//         flood findings.
//  D32-04 scan-scope widening: definition mutated mid-run; a source
//         yielding traversal paths.
//  D32-05 findings-access abuse: out-of-scope reader, anonymous read.
//  D32-06 retention games: keep-forever policy values cannot mint
//         immortal findings.
//  D32-07 DLP-off gaps presented as covered.
//  D32-08 findings-chain tampering is detected.
public class Rmm32DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string Reader = "compliance-reader";
    private const string TestVisa = "4111111111111111";
    private const string PlantedSecret = "hunter2hunter2";
    private const string PlantedAws = "AKIAIOSFODNN7EXAMPLE";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingDlpAlertSink Sink = new();
        public RecordingDlpEgressApplier Applier = new();
        public DlpService Svc;
        public Rig(bool enable = true)
        {
            Svc = new DlpService(Audit, Policy, Sink, Applier, id => id == Dev ? Facts1 : null, () => Now);
            if (enable) SetPolicy(DlpKeys.FeatureEnabled, "true", "doc-enable");
        }
        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
    }

    private static DlpScanDefinition Def(IReadOnlyList<string>? classifiers = null) =>
        new("scan-1", Dev, new[] { @"C:\Data" }, new[] { ".txt" }, false,
            classifiers ?? new[] { DlpClassifierIds.PaymentCard, DlpClassifierIds.CredentialSecret }, Admin, T0);

    [Fact]
    public void D32_01_PlantedSecrets_AppearNowhereInAnySurface()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        var content = $"card {TestVisa}; password = {PlantedSecret}; key {PlantedAws}";
        // D38 F6/F11 (test strengthened): the file NAME itself is a
        // planted secret — paths are a surface too.
        var (summary, _) = rig.Svc.RunScan(Dev, Def(),
            new InMemoryDlpFileSource(new[] { new DlpFileItem($@"C:\Data\{TestVisa}.txt", content, content.Length) }), Admin);
        Assert.NotNull(summary);
        Assert.True(rig.Svc.Findings.Findings.Count >= 2);

        // Serialize EVERY surface an attacker could read — now
        // including scan summary Notes, the policy-resolution reason,
        // and the effective view's classifier descriptions (all named
        // as omissions by D38 F11).
        var sb = new StringBuilder();
        foreach (var r in rig.Svc.Findings.Records)
            sb.Append(r.FilePath).Append(r.ClassifierId).Append(r.MaskedExcerpt).Append(r.MatchCount);
        foreach (var e in rig.Audit.Entries) sb.Append(e.Detail).Append(e.Actor).Append(e.Kind);
        foreach (var e in rig.Sink.Events) sb.Append(e.Detail);
        foreach (var n in summary!.Notes) sb.Append(n);
        var fact = DlpComplianceFacts.Build(rig.Svc.Findings, Dev, Scope, T0);
        sb.Append(fact?.Detail);
        var (view, _) = rig.Svc.EffectiveView(Dev);
        sb.Append(view?.PlainStatement);
        foreach (var d in view!.ClassifierDescriptions) sb.Append(d);
        var (_, resolveReason) = rig.Svc.ResolvePolicy(Dev);
        sb.Append(resolveReason);
        var surfaces = sb.ToString();

        Assert.DoesNotContain(TestVisa, surfaces);
        Assert.DoesNotContain(PlantedSecret, surfaces);
        Assert.DoesNotContain(PlantedAws, surfaces);
        // D38 F11 (test strengthened): the original checked only two
        // hand-picked 7–8-char substrings while claiming ">2
        // contiguous". Now EVERY contiguous substring of length >= 4
        // of the card and the password must be absent from every
        // surface. The floor is 4, not 3, for a named reason: at
        // length 3 the password's substring "unt" collides with the
        // ordinary English word "counts" in the surfaces' own prose
        // ("counts only") — a false positive, not leakage; the mask
        // rule's ">2 contiguous" guarantee governs value-bearing
        // fields (excerpts), and no excerpt here carries more than
        // the rule's first2-last2. (The AWS key is checked at >= 5:
        // its 4-char "AKIA" prefix is the published shape marker
        // named in the classifier's own description.)
        foreach (var sub in AllSubstrings(TestVisa, 4)) Assert.DoesNotContain(sub, surfaces);
        foreach (var sub in AllSubstrings(PlantedSecret, 4)) Assert.DoesNotContain(sub, surfaces);
        foreach (var sub in AllSubstrings(PlantedAws, 5)) Assert.DoesNotContain(sub, surfaces);
        // The chain itself verifies — leakage is not hiding in a broken record.
        Assert.True(rig.Svc.Findings.VerifyChain().Ok);
    }

    private static IEnumerable<string> AllSubstrings(string value, int minLength)
    {
        for (var len = minLength; len <= value.Length; len++)
            for (var i = 0; i + len <= value.Length; i++)
                yield return value.Substring(i, len);
    }

    [Fact]
    public void D32_02_Evasion_Honesty_SpacedGroupsCaught_OtherSeparatorsNamedLimitation()
    {
        var c = new PaymentCardClassifier();
        // Single space/dash separators between digits ARE reassembled.
        Assert.Single(c.Find("4111 1111 1111 1111"));
        Assert.Single(c.Find("4111-1111-1111-1111"));
        // Digits separated by other characters are NOT caught — and the
        // classifier's own description NAMES that limitation instead of
        // claiming coverage it does not have (the failure would be the
        // claim, not the evasion).
        Assert.Empty(c.Find("4111.1111.1111.1111"));
        Assert.Empty(c.Find("4 1 1 1 x 1 1 1 1 x 1 1 1 1 x 1 1 1 1"));
        Assert.Contains("not reassembled", c.Description);
        Assert.Contains("Limitation", c.Description);
    }

    [Fact]
    public void D32_03_LuhnFlood_RandomDigitStrings_ProduceNoFindings()
    {
        // D38 F11 (test reworked — the original could not fail): it
        // DELETED every Luhn-valid string from the corpus before
        // scanning, then asserted zero findings. Now the corpus is
        // scanned as generated: the expected match count is exactly
        // the number of Luhn-valid strings in it (a Luhn-valid random
        // string IS the finding shape — the gate's job is to keep the
        // other ~90% out), and the flood bound is asserted: without
        // the Luhn gate all 500 would match.
        var rig = new Rig();
        var sb = new StringBuilder();
        var rng = new Random(42);
        var expected = 0;
        for (var i = 0; i < 500; i++)
        {
            var digits = string.Concat(Enumerable.Range(0, 16).Select(_ => (char)('0' + rng.Next(10))));
            if (PaymentCardClassifier.LuhnValid(digits)) expected++;
            sb.Append(digits).Append("\n#\n"); // '#' breaks digit runs: candidates cannot span strings
        }
        Assert.True(expected > 0 && expected < 100,
            $"corpus sanity: {expected} of 500 random strings are Luhn-valid (expect roughly 10%)");
        var content = sb.ToString();
        var (summary, _) = rig.Svc.RunScan(Dev, Def(classifiers: new[] { DlpClassifierIds.PaymentCard }),
            new InMemoryDlpFileSource(new[] { new DlpFileItem(@"C:\Data\noise.txt", content, content.Length) }), Admin);
        Assert.NotNull(summary);
        Assert.Equal(expected, summary!.TotalMatches);                // exactly the Luhn-valid ones — no flood beyond the gate
        Assert.Equal(expected, rig.Svc.Findings.Findings.Sum(f => f.MatchCount));
    }

    [Fact]
    public void D32_04_DefinitionMutatedMidRun_ScanUsesFrozenSnapshot()
    {
        var rig = new Rig();
        var roots = new List<string> { @"C:\Data" };
        var classifiers = new List<string> { DlpClassifierIds.PaymentCard };
        var def = new DlpScanDefinition("scan-1", Dev, roots, new List<string> { ".txt" }, false, classifiers, Admin, T0);
        var hashBefore = def.DefinitionHash;
        // The source mutates the caller's lists DURING enumeration:
        // widens roots to C:\ and swaps the classifier set.
        var source = new InMemoryDlpFileSource(
            new[]
            {
                new DlpFileItem(@"C:\Data\a.txt", TestVisa, 16),
                new DlpFileItem(@"C:\Windows\evil.txt", TestVisa, 16),
            },
            onEnumerate: () => { roots.Add(@"C:\"); classifiers.Clear(); classifiers.Add(DlpClassifierIds.CredentialSecret); });
        var (summary, _) = rig.Svc.RunScan(Dev, def, source, Admin);
        Assert.NotNull(summary);
        Assert.Equal(hashBefore, summary!.DefinitionHash);            // the scan that ran is the scan that was defined
        Assert.Equal(1, summary.FilesScanned);                        // the widened root's file was refused
        Assert.Equal(1, summary.FilesSkippedOutOfScope);
        Assert.Single(rig.Svc.Findings.Findings);
        Assert.Equal(DlpClassifierIds.PaymentCard, rig.Svc.Findings.Findings[0].ClassifierId);
    }

    [Fact]
    public void D32_05_FindingsAccessAbuse_OutOfScopeAndAnonymousReadersRefused()
    {
        var rig = new Rig();
        rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
        rig.Svc.RunScan(Dev, Def(), new InMemoryDlpFileSource(
            new[] { new DlpFileItem(@"C:\Data\a.txt", TestVisa, 16) }), Admin);
        Assert.Null(rig.Svc.ReadFindings(Dev, "mallory-intruder").Records);
        Assert.Null(rig.Svc.ReadFindings(Dev, null).Records);
        Assert.Null(rig.Svc.ReadFindings(Dev, "").Records);
        Assert.Null(rig.Svc.ReadFindings(Dev, Admin).Records);        // operating a scan grants no read
        Assert.NotNull(rig.Svc.ReadFindings(Dev, Reader).Records);
        Assert.True(rig.Audit.Entries.Count(e => e.Kind == "dlp_findings_read_refused") >= 3);
    }

    [Fact]
    public void D32_06_RetentionGames_KeepForeverValuesCannotMintImmortalFindings()
    {
        foreach (var bad in new[] { "0", "-5", "forever", "99999999" })
        {
            var rig = new Rig();
            rig.SetPolicy(DlpKeys.FindingsRetentionDays, bad, "doc-ret");
            // D38 F1: the sweep now requires findings-reader authority.
            rig.SetPolicy(DlpKeys.FindingsReaders, Reader, "doc-readers");
            var (policy, _) = rig.Svc.ResolvePolicy(Dev);
            Assert.NotNull(policy);
            Assert.True(policy!.RetentionDays >= 1 && policy.RetentionDays <= DlpLimits.MaxRetentionDays,
                $"retention '{bad}' resolved to {policy.RetentionDays} — must stay finite and capped");
            rig.Svc.RunScan(Dev, Def(), new InMemoryDlpFileSource(
                new[] { new DlpFileItem(@"C:\Data\a.txt", TestVisa, 16) }), Admin);
            rig.Now = T0.AddDays(policy.RetentionDays + 1);
            var (purged, _) = rig.Svc.SweepRetention(Dev, Reader);
            Assert.True(purged > 0, $"retention '{bad}': findings must expire");
            Assert.Empty(rig.Svc.Findings.Findings);
        }
    }

    [Fact]
    public void D32_07_DlpOffGaps_NeverPresentedAsCovered()
    {
        var rig = new Rig(enable: false);
        // Egress during the disabled window:
        var (decision, _, _) = rig.Svc.EvaluateEgress(Dev, DlpChannels.RemovableMedia,
            new[] { DlpClassifierIds.PaymentCard }, Admin);
        Assert.Equal(DlpEgressDispositions.NotCovered, decision!.Disposition);
        Assert.NotEqual(DlpEgressDispositions.Allowed, decision.Disposition);
        // Coverage statement names disabled windows as uncovered:
        Assert.Contains(DlpChannelVisibility.Unseeable, u => u.Contains("DLP policy is disabled"));
        // And scans refuse outright rather than producing an empty "clean" result:
        var (summary, _) = rig.Svc.RunScan(Dev, Def(), new InMemoryDlpFileSource(
            new[] { new DlpFileItem(@"C:\Data\a.txt", TestVisa, 16) }), Admin);
        Assert.Null(summary);
        Assert.Empty(rig.Svc.Findings.Records);
    }

    [Fact]
    public void D32_08_FindingsChain_TamperIsDetected()
    {
        var store = new DlpFindingStore();
        var def = Def();
        store.RecordScanStarted(def, T0);
        var classifier = new PaymentCardClassifier();
        store.RecordFinding("scan-1", Dev, @"C:\Data\a.txt", classifier, classifier.Find(TestVisa), T0);
        Assert.True(store.VerifyChain().Ok);
        // The store's surface is append-only: Records hands out a copy,
        // so mutating the returned list reaches nothing inside.
        var records = store.Records;
        Assert.Equal(1, records[1].MatchCount);
        var headBefore = store.HeadHash;
        store.RecordScanCompleted("scan-1", Dev, 1, 1, 1, 0, T0);
        Assert.NotEqual(headBefore, store.HeadHash);                  // every append moves the head
        Assert.True(store.VerifyChain().Ok);
        // D38 F11 (test reworked — the original never tampered with
        // anything): ACTUALLY tamper — reach into the store's private
        // record list and alter a record's content while keeping its
        // original hash, exactly the forgery VerifyChain exists to
        // catch. The recomputation must reject it.
        var field = typeof(DlpFindingStore).GetField("_records",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var inner = (List<DlpFindingRecord>)field.GetValue(store)!;
        var original = inner[1];
        inner[1] = original with { MatchCount = original.MatchCount + 41 };
        var (ok, summary) = store.VerifyChain();
        Assert.False(ok);
        Assert.Contains("hash mismatch", summary);
        inner[1] = original;                                          // restore: the untouched chain verifies again
        Assert.True(store.VerifyChain().Ok);
    }
}

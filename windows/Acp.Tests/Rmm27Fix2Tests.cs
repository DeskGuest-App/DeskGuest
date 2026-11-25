using Acp.Core.Services;
using Acp.Shared.AnomalyBaselining;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;

namespace Acp.Tests;

// FL-27b — permanent regressions for the D38 RMM-27 findings
// F6–F10 (verdict f1791c9e, reconciled in d38-sweep.md A3):
//   F6 key vs ConditionId normalization mismatch + per-process
//      (unaggregated) observations
//   F7 device-id case/normalization inconsistency (same root
//      cause as F6: raw-string key equality vs the service's
//      case-insensitive device handling)
//   F8 sort-per-Admit under one global lock — the per-Admit sort
//      was already removed by FL-27a (frozen admission range);
//      pinned here so it cannot regress
//   F9 no eviction anywhere (unbounded profile growth)
//   F10 blank sensitivity/severity silently defaulted;
//      MinSustainSeconds=0 vs the "brief spike never alerts" claim
// Each test fails against the pre-FL-27b code for the reason named
// in its comment (F8's pins FL-27a's already-landed fix).
public class Rmm27Fix2Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ================= F6 — key normalization =================

    // Pre-fix: AnomalyProfileKey equality was ordinal on the RAW
    // strings while ConditionId trimmed/lowercased the target —
    // " C: " and "C:" were one condition but two profiles.
    [Fact]
    public void F6_KeyNormalization_TargetWhitespaceAndBlank_UnifyWithConditionId()
    {
        var padded = new AnomalyProfileKey(Dev, AnomalyMetrics.DiskFreePercent, " C: ");
        var plain = new AnomalyProfileKey(Dev, AnomalyMetrics.DiskFreePercent, "C:");
        Assert.Equal(plain, padded);
        Assert.Equal(plain.GetHashCode(), padded.GetHashCode());
        Assert.Equal(plain.ConditionId, padded.ConditionId);

        var blank = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "  ");
        var star = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        Assert.Equal(star, blank);
        Assert.Equal(star.ConditionId, blank.ConditionId);
    }

    // Pre-fix: observations whose targets differed only by padding
    // created separate store profiles for the same disk.
    [Fact]
    public void F6_Store_PaddedAndPlainTargets_ShareOneProfile()
    {
        var store = new AnomalyProfileStore();
        // Chronological batches (the store refuses stale timestamps
        // by design — FL-27a/F2): padded targets first, plain second.
        for (var i = 0; i < 5; i++)
            Assert.Equal(AdmissionOutcomes.Admitted, store.Admit(
                new MetricObservation(Dev, AnomalyMetrics.DiskFreePercent, " C: ", 40, T0.AddHours(i)), false, 2.0).Outcome);
        for (var i = 0; i < 5; i++)
            Assert.Equal(AdmissionOutcomes.Admitted, store.Admit(
                new MetricObservation(Dev, AnomalyMetrics.DiskFreePercent, "C:", 41, T0.AddHours(5 + i)), false, 2.0).Outcome);
        Assert.Equal(1, store.ProfileCount);
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.DiskFreePercent, "C:");
        Assert.Equal(10, store.Counters(key).Admitted);
    }

    // Pre-fix: the extractor emitted one observation per
    // ProcessSample, so two instances of one process produced two
    // competing observations for the same profile in one instant.
    [Fact]
    public void F6_Extractor_AggregatesSameNameProcesses_IntoOneSummedObservation()
    {
        var sample = new EndpointSample(
            Dev, T0, null, null,
            Array.Empty<DiskSample>(), Array.Empty<ServiceSample>(),
            new[]
            {
                new ProcessSample("Niagara", 300_000_000, null),
                new ProcessSample(" niagara ", 200_000_000, null),
                new ProcessSample("Other", 50_000_000, null),
            },
            Array.Empty<AppSample>(), Array.Empty<EventLogSample>(), null, null,
            Array.Empty<GuestSample>(), Array.Empty<string>());
        var obs = MetricObservationExtractor.FromSample(sample)
            .Where(o => o.Metric == AnomalyMetrics.ProcessWorkingSetBytes).ToList();
        Assert.Equal(2, obs.Count);
        var niagara = Assert.Single(obs, o => o.Target.Trim().Equals("niagara", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(500_000_000.0, niagara.Value);
    }

    // ================= F7 — device identity =================

    // Pre-fix: the key carried the raw device string while the
    // service filtered and reported devices case-insensitively —
    // " dev-1 " (or a differently-padded id from a feed) split one
    // device's learning from the profile the service looked up.
    [Fact]
    public void F7_KeyNormalization_DevicePadding_UnifiesProfile()
    {
        var padded = new AnomalyProfileKey(" dev-1 ", AnomalyMetrics.CpuPercent, "*");
        var plain = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        Assert.Equal(plain, padded);

        var store = new AnomalyProfileStore();
        store.Admit(new MetricObservation(" dev-1 ", AnomalyMetrics.CpuPercent, "*", 50, T0), false, 2.0);
        Assert.Equal(1, store.Counters(plain).Admitted);
    }

    // ================= F8 — no per-Admit sort (FL-27a pin) =====

    // FL-27a removed the per-Admit full sort: admission is judged
    // against the CACHED frozen range. Pin: admitting many values
    // inside the range never moves it (a live recomputation would
    // drift it), and only Recompute refreshes it.
    [Fact]
    public void F8_AdmissionRangeStaysFrozenAcrossManyAdmits_UntilRecompute()
    {
        // LANE W1 REPAIR (bd-shared-rmm-1 F4): the frozen range
        // now exists only once the profile is MATURE (30 samples
        // over 24h) — the original setup read it after 10 samples,
        // the self-sealing provisional freeze F4 removed. The pin
        // itself is unchanged: once frozen, many inside admits
        // never move it; only Recompute refreshes it.
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 30; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        var frozen = store.FrozenAdmissionRange(key);
        Assert.NotNull(frozen);
        for (var i = 0; i < 100; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 51, T0.AddHours(30 + i)), false, 2.0);
        Assert.Equal(frozen!.Value, store.FrozenAdmissionRange(key)!.Value);
    }

    // ================= F9 — eviction + cap =====================

    // Pre-fix: nothing was ever evicted — dead profiles (renamed
    // disks, vanished processes) accumulated forever.
    [Fact]
    public void F9_EvictStale_RemovesIdleProfiles_KeepsFreshOnes()
    {
        var store = new AnomalyProfileStore();
        var staleKey = new AnomalyProfileKey(Dev, AnomalyMetrics.DiskFreePercent, "OLD:");
        var freshKey = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        store.Admit(new MetricObservation(Dev, AnomalyMetrics.DiskFreePercent, "OLD:", 40, T0), false, 2.0);
        store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddDays(40)), false, 2.0);

        var evicted = store.EvictStale(T0.AddDays(41));
        Assert.Equal(1, evicted);
        Assert.Equal(1, store.ProfileCount);
        Assert.Equal(1, store.Counters(freshKey).Admitted);
        Assert.Equal(0, store.Counters(staleKey).Admitted);
    }

    // Pre-fix: a feed inventing unbounded distinct targets grew
    // the store without limit.
    [Fact]
    public void F9_PerDeviceProfileCap_RefusesNewProfilesByName()
    {
        var store = new AnomalyProfileStore();
        for (var i = 0; i < AnomalyLimits.MaxProfilesPerDevice; i++)
            Assert.Equal(AdmissionOutcomes.Admitted, store.Admit(
                new MetricObservation(Dev, AnomalyMetrics.DiskFreePercent, $"vol-{i}", 40, T0), false, 2.0).Outcome);
        var refused = store.Admit(
            new MetricObservation(Dev, AnomalyMetrics.DiskFreePercent, "vol-overflow", 40, T0), false, 2.0);
        Assert.Equal(AdmissionOutcomes.RefusedProfileCap, refused.Outcome);
        Assert.Contains("cap", refused.Detail);
        // Existing profiles are undisturbed, and ANOTHER device
        // still gets its own full allowance.
        Assert.Equal(AnomalyLimits.MaxProfilesPerDevice, store.ProfileCount);
        Assert.Equal(AdmissionOutcomes.Admitted, store.Admit(
            new MetricObservation("dev-2", AnomalyMetrics.DiskFreePercent, "vol-0", 40, T0), false, 2.0).Outcome);
    }

    // ================= F10 — policy honesty ====================

    private static (ManagementPolicyService Policies, ResolvedAnomalyPolicy Resolved) ResolveWith(
        params (string Key, string Value)[] entries)
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null);
        var doc = new ManagementPolicyDocument("fl27b-doc", PolicyLevels.Org, Scope,
            entries.ToDictionary(e => e.Key, e => e.Value), 1);
        var v = policies.AdmitLocalDocument(doc, "test");
        Assert.True(v.Allowed, v.Reason);
        var resolved = AnomalyPolicyResolver.Resolve(policies.Engine, StaticDeviceFacts.Of(Dev, Scope));
        return (policies, resolved);
    }

    // Pre-fix: a present-but-blank sensitivity fell through the
    // IsNullOrWhiteSpace guard and defaulted with NO note — the
    // default was applied silently.
    [Fact]
    public void F10_BlankSensitivityAndSeverity_AreNamedInNotes()
    {
        var (_, resolved) = ResolveWith(
            (AnomalyPolicyKeys.Sensitivity, "  "),
            (AnomalyPolicyKeys.Severity, ""));
        Assert.Equal(AnomalyPolicyKeys.DefaultSensitivity, resolved.Sensitivity);
        Assert.Contains(resolved.Notes, n => n.Contains("sensitivity is set but blank"));
        Assert.Contains(resolved.Notes, n => n.Contains("severity is set but blank"));
    }

    // Pre-fix: sustain could be 0 (a single spike alerts) while
    // the design doctrine claimed "a brief spike never alerts" —
    // the contradiction was nowhere named.
    [Fact]
    public void F10_ZeroSustain_CarriesHonestyNote_PositiveSustainDoesNot()
    {
        var (_, zero) = ResolveWith((AnomalyPolicyKeys.SustainSeconds, "0"));
        Assert.Equal(TimeSpan.Zero, zero.Sustain);
        Assert.Contains(zero.Notes, n => n.Contains("sustain is 0s") && n.Contains("brief spike never alerts"));

        var (_, positive) = ResolveWith((AnomalyPolicyKeys.SustainSeconds, "600"));
        Assert.DoesNotContain(positive.Notes, n => n.Contains("sustain is 0s"));
    }
}

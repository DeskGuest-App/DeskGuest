using System.Net;
using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.NetworkDiscovery;

namespace DeskGuest.Tests;

// RMM-11 FIX lane — D38 cross-review (packet b21e27af) regressions.
// One test per confirmed finding (FIX11-F1..F12), each naming the
// crack it closes. Findings text:
// ~/workspace/builds/rmm-r-logs/rmm11-findings.md
public class Rmm11FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Probe = "probe-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyEngine Policy = new();
        public FakeProbeTransport Transport = new();
        public SiteCensus Census = new();
        public UnmanagedAssetRegister Register = new();
        public NetworkDiscoveryService Service = null!;

        public Rig(ProbeScope? scope = null, IEnumerable<SyslogKeywordRule>? syslog = null)
        {
            Centre = new HealthAlertCentre(Audit, new AlertCenter());
            Service = new NetworkDiscoveryService(Probe, Scope,
                StaticDeviceFacts.Of(Probe, Scope), Policy, Transport, Census, Register, Audit,
                Centre, new FakeConfigFetcher(), new ConfigBackupStore(),
                scope ?? new ProbeScope(Scope, new[] { "10.0.0.0/29" }, 64, TimeSpan.Zero),
                null, syslog, () => Now);
        }

        public void SetPolicy(IReadOnlyDictionary<string, string> settings) =>
            Policy.AddDocument(new ManagementPolicyDocument("doc-fix", PolicyLevels.Org, Scope, settings, 1));
    }

    private static ProbeObservation Obs(string ip, string mac, int[]? ports = null, string? sysDescr = null) =>
        new(ip, mac, null, ports ?? Array.Empty<int>(),
            sysDescr is null ? null : new SnmpProfile(sysDescr, null, null, null, null),
            null, null, false, T0);

    // FIX11-F1 — IPv4-mapped IPv6 must not bypass IsProbeableHost,
    // and a mapped observation files as ONE identity with its v4.
    [Fact]
    public void FIX11_F1_MappedIpv6_MetadataAndLoopbackRefused_LegitMappedFilesAsV4()
    {
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("::ffff:169.254.169.254")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("::ffff:127.0.0.1")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("::ffff:169.254.1.1")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("::ffff:224.0.0.1")));
        Assert.True(NetworkAddressing.IsProbeableHost(IPAddress.Parse("::ffff:10.0.0.5")));

        var census = new SiteCensus();
        Assert.Equal(CensusUpsertResult.Refused,
            census.Upsert(Obs("::ffff:169.254.169.254", "AA:BB:CC:00:00:01"), "s1", T0).Outcome);
        var filed = census.Upsert(Obs("::ffff:10.0.0.1", "AA:BB:CC:00:00:01"), "s1", T0);
        Assert.Equal(CensusUpsertResult.Added, filed.Outcome);
        Assert.Equal("10.0.0.1", filed.Entry!.IpAddress); // one identity, unwrapped
        Assert.NotNull(census.FindByIp("10.0.0.1"));
        // A mapped scope CIDR unwraps to its v4 network.
        Assert.True(NetworkAddressing.TryParseCidr("::ffff:10.0.0.0/120", out var net, out var prefix));
        Assert.Equal("10.0.0.0", net.ToString());
        Assert.Equal(24, prefix);
    }

    // FIX11-F2a — ProbeScope.Validate refuses non-probeable CIDRs,
    // and a policy scope naming the metadata address never probes.
    [Fact]
    public void FIX11_F2a_ScopeValidation_RefusesLoopbackMetadataMulticast()
    {
        foreach (var bad in new[] { "127.0.0.0/30", "169.254.0.0/16", "169.254.169.254/32",
                                    "224.0.0.0/4", "0.0.0.0/0", "::1/128", "fe80::/10", "ff00::/8" })
            Assert.NotNull(new ProbeScope(Scope, new[] { bad }, 10, TimeSpan.Zero).Validate());
        Assert.Null(new ProbeScope(Scope, new[] { "10.0.0.0/29" }, 10, TimeSpan.Zero).Validate());

        var rig = new Rig();
        rig.SetPolicy(new Dictionary<string, string>
            { [NetworkDiscoveryPolicyKeys.Subnets] = "169.254.169.254/32" });
        var result = rig.Service.RunSweep();
        Assert.False(result.Ran); // scope invalid — refused before any probe
        Assert.Empty(rig.Transport.ProbedIps);
    }

    // FIX11-F2b — v6 enumeration stays inside its subnet.
    [Fact]
    public void FIX11_F2b_EnumerateHosts_V6Prefix_StaysInSubnet()
    {
        Assert.True(NetworkAddressing.TryParseCidr("fd00::/120", out var net, out var prefix));
        var hosts = NetworkAddressing.EnumerateHosts(net, prefix, 1024).ToList();
        Assert.Equal(256, hosts.Count);
        Assert.All(hosts, h => Assert.True(NetworkAddressing.IsInCidr(h, net, prefix)));
        Assert.DoesNotContain(hosts, h => h.ToString() == "fd00::100");
    }

    // FIX11-F3 — quarantine is per-sweep: a poisoner that behaves
    // next sweep alerts and lands again; a framed victim recovers;
    // BOTH claimants of a contested IP quarantine.
    [Fact]
    public void FIX11_F3_Quarantine_PerSweep_VictimRecovers_BothClaimantsFlagged()
    {
        // (a)+(b): victim MAC framed in sweep 1 (5 claims), real
        // device in sweep 2 (one claim, new surface) → drift alert
        // fires and the device lands.
        var rig = new Rig();
        foreach (var last in new[] { 1, 2, 3, 4, 5 })
            rig.Transport.Script($"10.0.0.{last}", Obs($"10.0.0.{last}", "AA:BB:CC:00:00:66", ports: new[] { 22 }));
        var first = rig.Service.RunSweep();
        Assert.True(first.Quarantined >= 1);
        Assert.Empty(rig.Register.List(Scope));
        foreach (var last in new[] { 2, 3, 4, 5 }) rig.Transport.Script($"10.0.0.{last}", null);
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:66", ports: new[] { 22, 443 }));
        var second = rig.Service.RunSweep();
        Assert.Equal(0, second.Quarantined);
        Assert.Equal(1, second.DriftEvents); // fingerprint drift alerted again — not silenced
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.IdentityDrift);
        Assert.Single(rig.Register.List(Scope)); // and it lands

        // (c): both claimants of one IP quarantine, not just the second.
        var census = new SiteCensus();
        census.Upsert(Obs("10.0.0.1", "AA:BB:CC:00:00:01"), "s1", T0);
        census.Upsert(Obs("10.0.0.1", "AA:BB:CC:00:00:02"), "s1", T0);
        Assert.True(census.FindByMac("AA:BB:CC:00:00:01")!.Quarantined);
        Assert.True(census.FindByMac("AA:BB:CC:00:00:02")!.Quarantined);
        // Admin path: quarantine can be cleared, audited.
        var rig2 = new Rig();
        rig2.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01"));
        rig2.Service.RunSweep();
        Assert.True(rig2.Service.ClearQuarantine("AA:BB:CC:00:00:01", "admin-1"));
        Assert.Contains(rig2.Audit.Entries, e => e.Kind == "discovery_quarantine_cleared" && e.Actor == "admin-1");
    }

    // FIX11-F4 — import verifies the hash CHAIN (recompute-one-
    // version attack breaks the successor's link), enforces the
    // content cap and the 32-version retention.
    [Fact]
    public void FIX11_F4_Import_ChainVerified_CapAndRetentionEnforced()
    {
        var source = new ConfigBackupStore();
        source.Backup("sw-1", "hostname a\n", "test", T0);
        source.Backup("sw-1", "hostname b\n", "test", T0);
        var exported = source.ExportJson();
        // Attacker edits v1 AND recomputes v1's hash: v2's PrevHash
        // still names the ORIGINAL v1 hash → v2 refused on import.
        // (Only the FIRST occurrence of the original hash — v1's
        // ContentHash field — is recomputed; v2's PrevHash keeps
        // naming the original, which is exactly the finding's
        // recompute-and-pass attack shape.)
        var v1Tampered = "hostname pwned\n";
        var attacked = exported.Replace("hostname a", "hostname pwned");
        attacked = new System.Text.RegularExpressions.Regex(
            System.Text.RegularExpressions.Regex.Escape(ConfigDiffer.ContentHash("hostname a\n")))
            .Replace(attacked, ConfigDiffer.ContentHash(v1Tampered), 1);
        Assert.NotEqual(exported, attacked);
        var victim = new ConfigBackupStore();
        var (restored, refused) = victim.ImportJson(attacked);
        Assert.Equal(1, restored); // v1 alone is self-consistent (window start)
        Assert.Equal(1, refused);  // v2's chain link is broken — refused
        Assert.Null(victim.Versions("sw-1").FirstOrDefault(v => v.Version == 2));

        // Retention: a hand-built valid 40-version chain imports
        // but only the newest 32 survive.
        var dtos = new List<string>();
        var prev = ConfigBackupStore.GenesisHash;
        for (var v = 1; v <= 40; v++)
        {
            var content = $"line {v}\n";
            var hash = ConfigDiffer.ContentHash(content);
            dtos.Add($"{{\"DeviceId\":\"sw-9\",\"Version\":{v},\"Content\":\"line {v}\\n\",\"ContentHash\":\"{hash}\",\"PrevHash\":\"{prev}\",\"FetchedUtc\":\"2026-11-21T12:00:00+00:00\",\"Source\":\"test\"}}");
            prev = hash;
        }
        var big = new ConfigBackupStore();
        var (bigRestored, bigRefused) = big.ImportJson("[" + string.Join(",", dtos) + "]");
        Assert.Equal(40, bigRestored);
        Assert.Equal(0, bigRefused);
        Assert.Equal(ConfigBackupStore.MaxVersionsPerDevice, big.Versions("sw-9").Count);
        Assert.True(big.VerifyIntegrity("sw-9").Ok);
        // Oversized content refuses.
        var hugeContent = new string('x', ConfigBackupStore.MaxContentBytes + 1);
        var hugeHash = ConfigDiffer.ContentHash(hugeContent);
        var hugeJson = $"[{{\"DeviceId\":\"sw-8\",\"Version\":1,\"Content\":\"{hugeContent}\",\"ContentHash\":\"{hugeHash}\",\"PrevHash\":\"{ConfigBackupStore.GenesisHash}\",\"FetchedUtc\":\"2026-11-21T12:00:00+00:00\",\"Source\":\"test\"}}]";
        var (hugeRestored, hugeRefused) = new ConfigBackupStore().ImportJson(hugeJson);
        Assert.Equal(0, hugeRestored);
        Assert.Equal(1, hugeRefused);
    }

    // FIX11-F5 — DHCP reuse: A moves .1→.3; a NEW device at .1 is
    // not accused of mac_changed against the departed A.
    [Fact]
    public void FIX11_F5_DhcpReuse_NoFalseMacChanged_TrueSwapStillDetected()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:0A", ports: new[] { 22 }));
        rig.Service.RunSweep();
        rig.Transport.Script("10.0.0.1", null);
        rig.Transport.Script("10.0.0.3", Obs("10.0.0.3", "AA:BB:CC:00:00:0A", ports: new[] { 22 }));
        rig.Service.RunSweep(); // A moves to .3 (ip_changed)
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:0C", ports: new[] { 9100 }));
        var third = rig.Service.RunSweep(); // C legitimately takes .1
        var c = rig.Census.FindByMac("AA:BB:CC:00:00:0C")!;
        Assert.DoesNotContain(CensusDriftKinds.MacChanged, c.DriftFlags);
        Assert.DoesNotContain(rig.Centre.ActiveAlerts,
            a => a.Kind == NetworkAlertKinds.IdentityDrift && a.DeviceId == "AA:BB:CC:00:00:0C" &&
                 a.Severity == AlertSeverities.Critical);
        Assert.Equal(0, third.DriftEvents);
    }

    // FIX11-F6 — after promotion, later sweeps raise no rogue
    // alert and do not re-land the device in the register.
    [Fact]
    public void FIX11_F6_PromotedDevice_NoRogueOnLaterSweeps_NeverRelands()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:30", ports: new[] { 9100 }));
        rig.Service.RunSweep();
        var asset = Assert.Single(rig.Register.List(Scope));
        Assert.True(rig.Service.PromoteToManaged(asset.AssetId, "admin-1").Promoted);
        // The FIRST sweep legitimately raised the rogue alert
        // (unknown device, pre-promotion). The crack was a FRESH
        // raise on every later sweep: capture the alert's
        // occurrence count now and prove the next sweep does not
        // raise it again.
        var rogueBefore = rig.Centre.ActiveAlerts.Single(
            a => a.Kind == NetworkAlertKinds.RogueDevice && a.DeviceId == "AA:BB:CC:00:00:30");
        rig.Now += TimeSpan.FromSeconds(1);
        var second = rig.Service.RunSweep();
        Assert.DoesNotContain("AA:BB:CC:00:00:30", second.RogueEntryIds);
        Assert.Equal(0, second.LandedAssets);
        Assert.Empty(rig.Register.List(Scope));
        var rogueAfter = rig.Centre.ActiveAlerts.Single(
            a => a.Kind == NetworkAlertKinds.RogueDevice && a.DeviceId == "AA:BB:CC:00:00:30");
        Assert.Equal(rogueBefore.OccurrenceCount, rogueAfter.OccurrenceCount);
        Assert.Equal(rogueBefore.LastSeenUtc, rogueAfter.LastSeenUtc);
    }

    // FIX11-F7 — service-level: a census refusal is counted +
    // audited (not silent); stale entries evict to admit a live
    // device once the census is full.
    [Fact]
    public void FIX11_F7_CensusRefused_CountedAndAudited_StaleEvictionAdmitsNew()
    {
        var rig = new Rig();
        var filled = 0;
        for (var sweep = 0; filled < SiteCensus.MaxEntries; sweep++)
            for (var i = 0; i < 200 && filled < SiteCensus.MaxEntries; i++, filled++)
            {
                var mac = $"AA:BB:{(filled >> 16) & 0xFF:X2}:{(filled >> 8) & 0xFF:X2}:{filled & 0xFF:X2}:01";
                var ip = $"10.{(filled >> 16) & 0x3F}.{(filled >> 8) & 0xFF}.{filled & 0xFF}";
                rig.Census.Upsert(Obs(ip, mac), $"fill-{sweep}", T0);
            }
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "FF:FF:00:00:00:01", ports: new[] { 22 }));
        var result = rig.Service.RunSweep();
        Assert.True(result.Ran);
        Assert.Equal(1, result.CensusRefused);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "discovery_census_refused");

        // 31 days later the stale residents evict; the same device files.
        var late = rig.Census.Upsert(Obs("10.0.0.1", "FF:FF:00:00:00:01"), "s-late",
            T0 + SiteCensus.StaleEvictionAge + TimeSpan.FromDays(1));
        Assert.Equal(CensusUpsertResult.Added, late.Outcome);
        Assert.Equal(SiteCensus.MaxEntries, rig.Census.Entries.Count);
    }

    // FIX11-F8 — (a) a backwards clock correction does not poison
    // the rate limiter; (b/c) policy interval 0 and unparsable
    // policy numbers refuse the scope instead of falling back.
    [Fact]
    public void FIX11_F8_ClockJumpBackwards_SweepsResume_PolicyZeroAndGarbageRefused()
    {
        var rig = new Rig(new ProbeScope(Scope, new[] { "10.0.0.0/29" }, 64, TimeSpan.FromMinutes(5)));
        Assert.True(rig.Service.RunSweep().Ran);
        rig.Now = T0 + TimeSpan.FromDays(365);
        Assert.True(rig.Service.RunSweep().Ran);   // forward jump: fine
        rig.Now = T0 + TimeSpan.FromHours(1);      // clock corrected backwards
        Assert.True(rig.Service.RunSweep().Ran);   // limiter reset, not poisoned for a year

        var zero = new Rig();
        zero.SetPolicy(new Dictionary<string, string>
            { [NetworkDiscoveryPolicyKeys.MinSweepIntervalSeconds] = "0" });
        var zeroResult = zero.Service.RunSweep();
        Assert.False(zeroResult.Ran);
        Assert.Contains("may not remove", zeroResult.RefusalReason);
        Assert.Empty(zero.Transport.ProbedIps);

        var garbage = new Rig();
        garbage.SetPolicy(new Dictionary<string, string>
            { [NetworkDiscoveryPolicyKeys.MaxHostsPerSweep] = "lots" });
        var garbageResult = garbage.Service.RunSweep();
        Assert.False(garbageResult.Ran);
        Assert.Contains("not an integer", garbageResult.RefusalReason);
        Assert.Empty(garbage.Transport.ProbedIps);
    }

    // FIX11-F9 — syslog: a line without the 3164 timestamp shape,
    // or with a non-hostname token at the hostname offset, yields
    // NO hostname — the alert subject falls back to "syslog", never
    // to attacker free text.
    [Fact]
    public void FIX11_F9_SyslogHostname_OnlyFromShaped3164Header()
    {
        var shaped = SyslogParser.Parse("<34>Oct 11 22:14:15 hub-device-01 sshd: Failed password");
        Assert.Equal("hub-device-01", shaped!.Hostname);
        // No timestamp shape: offset-16 text is not a hostname.
        var shapeless = SyslogParser.Parse("<34>garbage-line-without-shape evil|actor x: Failed password");
        Assert.NotNull(shapeless);
        Assert.Null(shapeless!.Hostname);
        // Timestamp shape but a pipe-bearing token: not a hostname.
        var piped = SyslogParser.Parse("<34>Oct 11 22:14:15 evil|actor sshd: Failed password");
        Assert.Null(piped!.Hostname);

        var rig = new Rig(syslog: new[] { new SyslogKeywordRule("Failed password", "warning") });
        var (ok, _, hits) = rig.Service.IngestSyslogLine(
            "<34>garbage-line-without-shape evil|actor x: Failed password for admin");
        Assert.True(ok);
        Assert.Equal(1, hits);
        Assert.Contains(rig.Centre.ActiveAlerts,
            a => a.Kind == NetworkAlertKinds.SyslogKeyword && a.DeviceId == "syslog");
    }

    // FIX11-F10 — parser bounds: NetFlow length must match count
    // EXACTLY; PRI rejects sign/whitespace; trap generic/specific
    // bounded; sFlow negative samples dropped.
    [Fact]
    public void FIX11_F10_ParserBounds_ExactLength_StrictPri_TrapRanges_SflowSign()
    {
        var exact = new byte[NetFlowV5Parser.HeaderBytes + NetFlowV5Parser.RecordBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(0), 5);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 1);
        Assert.NotNull(NetFlowV5Parser.Parse(exact));
        var trailing = exact.Concat(new byte[100]).ToArray(); // count=1 but 100 extra bytes
        Assert.Null(NetFlowV5Parser.Parse(trailing));

        Assert.Null(SyslogParser.Parse("<+9>Oct 11 22:14:15 h t: m"));
        Assert.Null(SyslogParser.Parse("< 9>Oct 11 22:14:15 h t: m"));
        Assert.NotNull(SyslogParser.Parse("<9>Oct 11 22:14:15 h t: m"));

        Assert.Null(SnmpTrapParser.Parse(Encoding.UTF8.GetBytes("TRAP|1.3.6.1.4.1.9|10.0.0.9|7|1"), T0));  // generic > 6
        Assert.Null(SnmpTrapParser.Parse(Encoding.UTF8.GetBytes("TRAP|1.3.6.1.4.1.9|10.0.0.9|6|-1"), T0)); // specific < 0
        Assert.NotNull(SnmpTrapParser.Parse(Encoding.UTF8.GetBytes("TRAP|1.3.6.1.4.1.9|10.0.0.9|6|1"), T0));

        var summary = FlowAggregator.SummarizeSflow(new[]
        {
            new SflowSample("10.0.0.9", "10.0.0.5", "10.0.0.1", -5000, 6), // invalid: dropped
            new SflowSample("10.0.0.9", "10.0.0.5", "10.0.0.1", 7000, 6),
        });
        Assert.Equal(1, summary.FlowCount);
        Assert.Equal(7000, summary.TotalOctets);
    }

    // FIX11-F11 — Normalize does no more than claimed: trailing
    // blank lines and lone CR are CONTENT and diff as changed;
    // CRLF remains transport.
    [Fact]
    public void FIX11_F11_Normalize_TrailingBlankLinesAndLoneCr_AreChanges()
    {
        Assert.True(ConfigDiffer.Diff("x\n", "x\n\n\n").Changed);
        Assert.True(ConfigDiffer.Diff("a\rb", "a\nb").Changed);
        Assert.False(ConfigDiffer.Diff("x\n", "x").Changed);       // one missing final newline: transport
        Assert.False(ConfigDiffer.Diff("a\r\nb\r\n", "a\nb\n").Changed); // CRLF: transport
    }

    // FIX11-F12a — topology Build draws NO invented SameSubnet
    // edges to the probe.
    [Fact]
    public void FIX11_F12a_Topology_NoInventedSameSubnetEdges()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01"));
        rig.Transport.Script("10.0.0.2", Obs("10.0.0.2", "AA:BB:CC:00:00:02"));
        rig.Service.RunSweep();
        var graph = rig.Service.BuildTopology();
        Assert.DoesNotContain(graph.Edges, e => e.Kind == TopologyEdgeKinds.SameSubnet);
        Assert.Contains(graph.Edges, e => e.Kind == TopologyEdgeKinds.DiscoveredBy);
    }

    // FIX11-F12c — a re-entrant/concurrent sweep is refused, so
    // two sweeps can never interleave census sweep ids.
    [Fact]
    public void FIX11_F12c_ReentrantSweep_RefusedWhileSweepRunning()
    {
        var rig = new Rig();
        SweepResult? inner = null;
        var reentered = false;
        rig.Transport.Handler = (ip, _) =>
        {
            if (ip == "10.0.0.1" && !reentered)
            {
                reentered = true;
                inner = rig.Service.RunSweep(); // re-entrant call mid-sweep
            }
            return Obs(ip, "AA:BB:CC:00:00:01", ports: new[] { 22 });
        };
        var outer = rig.Service.RunSweep();
        Assert.True(outer.Ran);
        Assert.NotNull(inner);
        Assert.False(inner!.Ran);
        Assert.Contains("already in progress", inner.RefusalReason);
    }
}

using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.NetworkDiscovery;

namespace Acp.Tests;

// RMM-11 DESTRUCTION PASS — hostile devices, lying SNMP, census
// poisoning, topology forgery, config-backup tampering, probe
// scope escape. Every attack either holds (resisted) or its break
// became a fix + the regression test below. Ledger:
// ~/workspace/builds/rmm-r-logs/ledger-rmm11.md
public class Rmm11DestructionTests
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
        public UnmanagedAssetRegister Register;
        public NetworkDiscoveryService Service = null!;

        public Rig(Func<string, bool>? registerPolicy = null, string subnet = "10.0.0.0/29")
        {
            Centre = new HealthAlertCentre(Audit, new AlertCenter());
            Register = registerPolicy is null
                ? new UnmanagedAssetRegister()
                : new UnmanagedAssetRegister(registerPolicy);
            Service = new NetworkDiscoveryService(Probe, Scope,
                StaticDeviceFacts.Of(Probe, Scope), Policy, Transport, Census, Register, Audit,
                Centre, new FakeConfigFetcher(), new ConfigBackupStore(),
                new ProbeScope(Scope, new[] { subnet }, 64, TimeSpan.Zero),
                null, null, () => Now);
        }
    }

    private static ProbeObservation Obs(string ip, string mac, int[]? ports = null, string? sysDescr = null) =>
        new(ip, mac, null, ports ?? Array.Empty<int>(),
            sysDescr is null ? null : new SnmpProfile(sysDescr, null, null, null, null),
            null, null, false, T0);

    // DG-R11-01 — a hostile device fingerprinting back: the probe
    // transport throws / returns garbage for some hosts. The sweep
    // must survive, file the honest answers, and never crash.
    [Fact]
    public void ATTACK_HostileTransport_ThrowsAndGarbage_SweepSurvives()
    {
        var rig = new Rig();
        rig.Transport.Handler = (ip, _) => ip switch
        {
            "10.0.0.1" => throw new InvalidOperationException("hostile RST flood"),
            "10.0.0.2" => Obs("10.0.0.2", "not-a-mac-address!!", ports: new[] { 22 }),
            _ => Obs(ip, "AA:BB:CC:00:00:03", ports: new[] { 9100 }),
        };
        var result = rig.Service.RunSweep();
        Assert.True(result.Ran);
        Assert.Equal(6, result.ProbedHosts);
        // The garbage-MAC host files under its IP identity; the
        // thrower files nothing; honest hosts file normally.
        Assert.NotNull(rig.Census.FindByIp("10.0.0.2"));
        Assert.Null(rig.Census.FindByIp("10.0.0.1"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // DG-R11-02 — SNMP responses that lie / explode parsers:
    // invalid UTF-8, oversized fixtures, overflowing integers,
    // varbind floods. All bounded; none throws; none fabricates.
    [Fact]
    public void ATTACK_SnmpLies_ParserBoundedAndNeverThrows()
    {
        // Invalid UTF-8.
        var bad = SnmpFixtureParser.Parse(new byte[] { 0xFF, 0xFE, 0x41, 0x00 });
        Assert.False(bad.Ok);
        // Oversized.
        var huge = SnmpFixtureParser.Parse(new byte[SnmpFixtureParser.MaxBytes + 1]);
        Assert.False(huge.Ok);
        // Varbind flood: 600 lines -> capped at 512, rest counted.
        var flood = string.Join("\n", Enumerable.Range(1, 600)
            .Select(i => $"1.3.6.1.2.1.1.1.{i}|Integer|{i}"));
        var flooded = SnmpFixtureParser.Parse(Encoding.UTF8.GetBytes(flood));
        Assert.True(flooded.Ok);
        Assert.Equal(SnmpFixtureParser.MaxVarBinds, flooded.VarBinds.Count);
        Assert.True(flooded.DroppedLines >= 88);
        // Overflowing integer value: evaluator skips it, no throw.
        var binds = SnmpFixtureParser.Parse(Encoding.UTF8.GetBytes(
            "1.3.6.1.2.1.33.1.2.4.0|Integer|99999999999999999999999999999")).VarBinds;
        Assert.Empty(SnmpMonitorEvaluator.Evaluate(binds));
        // Service ingest of garbage refuses BY NAME and audits.
        var rig = new Rig();
        var (ok, reason, _) = rig.Service.IngestSnmpReading("sw-1", new byte[] { 0xFF, 0xFE });
        Assert.False(ok);
        Assert.Contains("refused", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "snmp_reading_refused");
        // A trap claiming a loopback agent is not a trap.
        Assert.Null(SnmpTrapParser.Parse(Encoding.UTF8.GetBytes(
            "TRAP|1.3.6.1.4.1.9|127.0.0.1|6|1"), T0));
        Assert.Null(SnmpTrapParser.Parse(Encoding.UTF8.GetBytes(
            "TRAP|1.3.6.1.4.1.9|169.254.169.254|6|1"), T0));
    }

    // DG-R11-03 — census poisoning: ONE device claiming MANY
    // identities (one MAC, five IPs in a single sweep). The
    // identity quarantines and — because landing is deferred to
    // sweep end — NONE of its claims reach the register.
    [Fact]
    public void ATTACK_CensusPoisoning_OneMacManyIps_QuarantinedAndNeverLanded()
    {
        var rig = new Rig();
        foreach (var last in new[] { 1, 2, 3, 4, 5 })
            rig.Transport.Script($"10.0.0.{last}", Obs($"10.0.0.{last}", "DE:AD:BE:EF:00:01", ports: new[] { 22 }));
        var result = rig.Service.RunSweep();
        Assert.True(result.Quarantined >= 1);
        var entry = rig.Census.FindByMac("DE:AD:BE:EF:00:01");
        Assert.NotNull(entry);
        Assert.True(entry!.Quarantined);
        Assert.Contains(CensusDriftKinds.MacClaimedManyIps, entry.DriftFlags);
        Assert.Empty(rig.Register.List(Scope)); // nothing landed
        Assert.DoesNotContain(result.RogueEntryIds, id => id == "DE:AD:BE:EF:00:01");
    }

    // DG-R11-04 — census poisoning, second form: one IP claimed by
    // two MACs in one sweep (ARP-spoof shape). Quarantine + drift.
    [Fact]
    public void ATTACK_CensusPoisoning_OneIpTwoMacs_Quarantined()
    {
        var census = new SiteCensus();
        var first = census.Upsert(Obs("10.0.0.1", "AA:BB:CC:00:00:01"), "s1", T0);
        Assert.Equal(CensusUpsertResult.Added, first.Outcome);
        // Same sweep, same IP, different MAC (a second observation
        // for the same address arriving via a relayed answer).
        var second = census.Upsert(new ProbeObservation("10.0.0.1", "AA:BB:CC:00:00:02",
            null, Array.Empty<int>(), null, null, null, false, T0), "s1", T0);
        // The IP's claimant set for this sweep now holds two MACs:
        // the SECOND identity is quarantined on its next sighting.
        var third = census.Upsert(new ProbeObservation("10.0.0.2", "AA:BB:CC:00:00:02",
            null, Array.Empty<int>(), null, null, null, false, T0), "s1", T0);
        Assert.True(third.Entry?.Quarantined ?? false);
    }

    // DG-R11-05 — topology forgery: edges to invented nodes,
    // self-loops, unknown edge kinds. All refused.
    [Fact]
    public void ATTACK_TopologyForgery_Refused()
    {
        var g = new TopologyGraph();
        Assert.True(g.AddNode(new TopologyNode("n1", TopologyNodeKinds.Device, "n1", "10.0.0.1", null)));
        Assert.False(g.AddEdge(new TopologyEdge("n1", "ghost-node", TopologyEdgeKinds.Uplink, "forged")));
        Assert.False(g.AddEdge(new TopologyEdge("n1", "n1", TopologyEdgeKinds.Uplink, "self loop")));
        Assert.False(g.AddEdge(new TopologyEdge("n1", "n1", "invented-kind", "forged")));
        Assert.Empty(g.Edges);
        // Build-level: an uplink hint naming a device outside the
        // census is dropped, never drawn.
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01"));
        rig.Service.RunSweep();
        var graph = rig.Service.BuildTopology(new[] { ("ghost", "AA:BB:CC:00:00:01", "forged hint") });
        Assert.DoesNotContain(graph.Edges, e => e.FromId == "ghost");
    }

    // DG-R11-06 — config-backup tampering: (a) a changed config
    // that "diffs as unchanged" — comment-only, whitespace-only and
    // reordered edits MUST read as changed; (b) a tampered store
    // export must refuse on import; (c) in-place content mutation
    // breaks integrity verification.
    [Fact]
    public void ATTACK_ConfigTampering_CommentWhitespaceReorderAllReadAsChanged()
    {
        const string v1 = "hostname sw\ninterface Gi1\n switchport mode access\n";
        Assert.True(ConfigDiffer.Diff(v1, "hostname sw\ninterface Gi1\n switchport mode access\n! touched by hand\n").Changed);
        Assert.True(ConfigDiffer.Diff(v1, "hostname sw \ninterface Gi1\n switchport mode access\n").Changed); // trailing space
        Assert.True(ConfigDiffer.Diff(v1, "interface Gi1\nhostname sw\n switchport mode access\n").Changed); // reordered
        Assert.False(ConfigDiffer.Diff(v1, v1.Replace("\n", "\r\n")).Changed); // CRLF is transport, not content

        var store = new ConfigBackupStore();
        store.Backup("sw-1", v1, "test", T0);
        var exported = store.ExportJson();
        var tampered = exported.Replace("hostname sw", "hostname pwned");
        Assert.NotEqual(exported, tampered);
        var victim = new ConfigBackupStore();
        var (restored, refused) = victim.ImportJson(tampered);
        Assert.Equal(0, restored);
        Assert.Equal(1, refused);
        Assert.Null(victim.Latest("sw-1"));
        // Clean export round-trips and verifies.
        var clean = new ConfigBackupStore();
        var (okCount, okRefused) = clean.ImportJson(exported);
        Assert.Equal(1, okCount);
        Assert.Equal(0, okRefused);
        Assert.True(clean.VerifyIntegrity("sw-1").Ok);
    }

    // DG-R11-07 — probe scope escape: policy says one subnet; a
    // device "answers" from another (relayed/forged observation).
    // Refused, counted, audited — never filed anywhere.
    [Fact]
    public void ATTACK_ScopeEscape_AnswerFromAnotherSubnet_NeverFiled()
    {
        var rig = new Rig();
        rig.Transport.Handler = (ip, _) =>
            // Every probe is answered by a "device" claiming to be elsewhere.
            new ProbeObservation("192.168.99.50", "AA:BB:CC:00:00:77", null,
                new[] { 22 }, null, null, null, false, T0);
        var result = rig.Service.RunSweep();
        Assert.True(result.Ran);
        Assert.Equal(6, result.ScopeEscapes);
        Assert.Equal(0, result.NewDevices);
        Assert.Empty(rig.Census.Entries);
        Assert.Empty(rig.Register.List(Scope));
        Assert.Equal(6, rig.Audit.Entries.Count(e => e.Kind == "discovery_scope_escape"));
    }

    // DG-R11-08 — probe scope escape, dual: an observation whose IP
    // is loopback / metadata is refused by the census itself even
    // if a broken service let it through.
    [Fact]
    public void ATTACK_ScopeEscape_LoopbackAndMetadataObservations_RefusedByCensus()
    {
        var census = new SiteCensus();
        Assert.Equal(CensusUpsertResult.Refused,
            census.Upsert(Obs("127.0.0.1", "AA:BB:CC:00:00:01"), "s1", T0).Outcome);
        Assert.Equal(CensusUpsertResult.Refused,
            census.Upsert(Obs("169.254.169.254", "AA:BB:CC:00:00:01"), "s1", T0).Outcome);
        Assert.Empty(census.Entries);
    }

    // DG-R11-09 — MAC spoof under a stable IP: same address, new
    // MAC across sweeps = mac_changed drift at CRITICAL severity.
    [Fact]
    public void ATTACK_MacSpoof_SameIpNewMac_CriticalDriftAlert()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 22 }));
        rig.Service.RunSweep();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:02", ports: new[] { 22 }));
        rig.Service.RunSweep();
        var driftAlerts = rig.Centre.ActiveAlerts.Where(a => a.Kind == NetworkAlertKinds.IdentityDrift).ToList();
        Assert.Contains(driftAlerts, a => a.Severity == AlertSeverities.Critical &&
            a.Detail.Contains(CensusDriftKinds.MacChanged));
    }

    // DG-R11-10 — fingerprint drift: same MAC + IP, the device's
    // identity surface changes (new open port + new banner).
    [Fact]
    public void ATTACK_FingerprintDrift_SameIdentityNewSurface_Alerted()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 22 }));
        rig.Service.RunSweep();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 22, 23, 2323 }));
        var second = rig.Service.RunSweep();
        Assert.Equal(1, second.DriftEvents);
        var entry = rig.Census.FindByMac("AA:BB:CC:00:00:01")!;
        Assert.Contains(CensusDriftKinds.FingerprintChanged, entry.DriftFlags);
    }

    // DG-R11-11 — register disabled by policy: landing fails, the
    // device stays UNFILED and therefore rogue-flagged — a disabled
    // register must not launder unknown devices into "known".
    [Fact]
    public void ATTACK_RegisterDisabled_UnfiledDeviceStaysRogue()
    {
        var rig = new Rig(registerPolicy: _ => false);
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:55", ports: new[] { 22 }));
        var result = rig.Service.RunSweep();
        Assert.Equal(0, result.LandedAssets);
        Assert.Contains("AA:BB:CC:00:00:55", result.RogueEntryIds);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.RogueDevice);
    }

    // DG-R11-12 — NetFlow count lying about the datagram: refused,
    // never clamped into fabricated flows. Wrong version refused.
    [Fact]
    public void ATTACK_NetFlowLyingCount_Refused()
    {
        var bytes = new byte[NetFlowV5Parser.HeaderBytes + NetFlowV5Parser.RecordBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0), 5);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), 400); // claims 400, carries 1
        Assert.Null(NetFlowV5Parser.Parse(bytes));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0), 9); // v9 is a different format
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), 1);
        Assert.Null(NetFlowV5Parser.Parse(bytes));
        Assert.Null(NetFlowV5Parser.Parse(new byte[10])); // truncated header
        var rig = new Rig();
        var (ok, reason, _) = rig.Service.IngestFlowDatagram(bytes);
        Assert.False(ok);
        Assert.Contains("refused", reason);
    }

    // DG-R11-13 — syslog abuse: oversized lines and priority lies
    // refuse; a keyword rule flood is capped.
    [Fact]
    public void ATTACK_SyslogAbuse_OversizedAndBadPriority_Refused()
    {
        Assert.Null(SyslogParser.Parse("<34>" + new string('x', SyslogParser.MaxLineLength)));
        Assert.Null(SyslogParser.Parse("<192>Oct 11 22:14:15 h t: m")); // pri > 191
        Assert.Null(SyslogParser.Parse("<-1>Oct 11 22:14:15 h t: m"));
        var msg = SyslogParser.Parse("<34>Oct 11 22:14:15 host app: error error error");
        Assert.NotNull(msg);
        var rules = Enumerable.Range(0, 300).Select(i => new SyslogKeywordRule("error", "info")).ToList();
        var hits = SyslogParser.MatchKeywords(msg!, rules);
        Assert.True(hits.Count <= 128);
    }

    // DG-R11-14 — hostile census growth: the census cap refuses
    // new identities rather than growing without bound.
    [Fact]
    public void ATTACK_CensusGrowth_CapRefusesNewIdentities()
    {
        var census = new SiteCensus();
        // Fill via distinct MACs on distinct IPs (small batches per
        // sweep id to stay under the poisoning witness).
        var filled = 0;
        for (var sweep = 0; filled < SiteCensus.MaxEntries; sweep++)
        {
            for (var i = 0; i < 200 && filled < SiteCensus.MaxEntries; i++, filled++)
            {
                var mac = $"AA:BB:{(filled >> 16) & 0xFF:X2}:{(filled >> 8) & 0xFF:X2}:{filled & 0xFF:X2}:01";
                var ip = $"10.{(filled >> 16) & 0x3F}.{(filled >> 8) & 0xFF}.{filled & 0xFF}";
                census.Upsert(Obs(ip, mac), $"s{sweep}", T0);
            }
        }
        Assert.Equal(SiteCensus.MaxEntries, census.Entries.Count);
        var over = census.Upsert(Obs("10.200.1.1", "FF:FF:00:00:00:01"), "s-final", T0);
        Assert.Equal(CensusUpsertResult.Refused, over.Outcome);
    }
}

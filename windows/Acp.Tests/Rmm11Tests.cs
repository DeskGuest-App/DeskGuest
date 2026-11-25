using System.Buffers.Binary;
using System.Net;
using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.NetworkDiscovery;

namespace Acp.Tests;

// RMM-11 — Network discovery + agentless monitoring: probe scope,
// census, topology model, SNMP/syslog/flow parsers, config backup.
// NO real network anywhere: every transport/fetcher is a fake and
// every protocol input is a byte fixture.
public class Rmm11Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Probe = "probe-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public AlertCenter Dir57 = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Probe, Scope);
        public FakeProbeTransport Transport = new();
        public SiteCensus Census = new();
        public UnmanagedAssetRegister Register = new();
        public FakeConfigFetcher Fetcher = new();
        public ConfigBackupStore ConfigStore = new();
        public NetworkDiscoveryService Service = null!;

        public Rig(ProbeScope? scope = null, IEnumerable<SyslogKeywordRule>? syslog = null,
            IEnumerable<SnmpOidRule>? snmp = null)
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Service = new NetworkDiscoveryService(Probe, Scope, Facts, Policy, Transport,
                Census, Register, Audit, Centre, Fetcher, ConfigStore,
                scope ?? new ProbeScope(Scope, new[] { "10.0.0.0/29" }, 64, TimeSpan.Zero),
                snmp, syslog, () => Now);
        }

        public void DisableDiscovery()
        {
            Policy.AddDocument(new ManagementPolicyDocument("doc-disc-off", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [NetworkDiscoveryPolicyKeys.DiscoveryEnabled] = "false" }, 1));
        }

        public void SetPolicySubnets(string subnets)
        {
            Policy.AddDocument(new ManagementPolicyDocument("doc-subnets", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [NetworkDiscoveryPolicyKeys.Subnets] = subnets }, 1));
        }
    }

    private static ProbeObservation Obs(string ip, string mac, int[]? ports = null,
        string? sysDescr = null, string? sysObjectId = null, bool onvif = false, string? hostname = null) =>
        new(ip, mac, hostname, ports ?? Array.Empty<int>(),
            sysDescr is null && sysObjectId is null ? null : new SnmpProfile(sysDescr, hostname, sysObjectId, null, null),
            null, null, onvif, T0);

    // ---- addressing / scope -------------------------------------------

    [Fact]
    public void Cidr_Validation_RefusesHostBitsAndBadShapes()
    {
        Assert.True(NetworkAddressing.TryParseCidr("10.0.0.0/24", out _, out _));
        Assert.False(NetworkAddressing.TryParseCidr("10.0.0.5/24", out _, out _)); // host bits set
        Assert.False(NetworkAddressing.TryParseCidr("10.0.0.0/33", out _, out _));
        Assert.False(NetworkAddressing.TryParseCidr("10.0.0.0", out _, out _));
        Assert.False(NetworkAddressing.TryParseCidr("nonsense/24", out _, out _));
        var scope = new ProbeScope(Scope, new[] { "10.0.0.5/24" }, 10, TimeSpan.Zero);
        Assert.NotNull(scope.Validate());
        Assert.NotNull(new ProbeScope(Scope, Array.Empty<string>(), 10, TimeSpan.Zero).Validate());
    }

    [Fact]
    public void ProbeableHost_RefusesLoopbackLinkLocalMulticast()
    {
        Assert.True(NetworkAddressing.IsProbeableHost(IPAddress.Parse("10.0.0.5")));
        Assert.True(NetworkAddressing.IsProbeableHost(IPAddress.Parse("192.168.1.20")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("127.0.0.1")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("169.254.169.254"))); // cloud metadata
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("169.254.1.1")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Parse("224.0.0.1")));
        Assert.False(NetworkAddressing.IsProbeableHost(IPAddress.Any));
    }

    [Fact]
    public void EnumerateHosts_SkipsNetworkAndBroadcast_AndCaps()
    {
        Assert.True(NetworkAddressing.TryParseCidr("10.0.0.0/29", out var net, out var prefix));
        var hosts = NetworkAddressing.EnumerateHosts(net, prefix, 100).Select(ip => ip.ToString()).ToList();
        Assert.Equal(new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6" }, hosts);
        var capped = NetworkAddressing.EnumerateHosts(net, prefix, 2).ToList();
        Assert.Equal(2, capped.Count);
    }

    // ---- the sweep ------------------------------------------------------

    [Fact]
    public void Sweep_DiscoversAndLandsInRegister_WithDiscoveredBy()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01",
            ports: new[] { 9100, 161 }, sysDescr: "HP LaserJet Pro", hostname: "printer-1"));
        rig.Transport.Script("10.0.0.2", Obs("10.0.0.2", "AA:BB:CC:00:00:02",
            ports: new[] { 47808 }, sysDescr: "Tridium JACE-8000", hostname: "jace-1"));

        var result = rig.Service.RunSweep();

        Assert.True(result.Ran);
        Assert.Equal(6, result.ProbedHosts);
        Assert.Equal(2, result.Answered);
        Assert.Equal(2, result.NewDevices);
        Assert.Equal(2, result.LandedAssets);
        var assets = rig.Register.List(Scope);
        Assert.Equal(2, assets.Count);
        Assert.All(assets, a => Assert.Equal("rmm11-discovery", a.DiscoveredBy));
        Assert.All(assets, a => Assert.Equal(UnmanagedLifecycleStates.Discovered, a.LifecycleState));
        Assert.Contains(assets, a => a.Kind == UnmanagedAssetKinds.Printer);
        Assert.Contains(assets, a => a.Kind == UnmanagedAssetKinds.BasController);
        Assert.Equal(2, rig.Census.Entries.Count);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "discovery_sweep");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Sweep_SecondSighting_UpdatesCensusWithoutDuplicatingRegister()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 9100 }));
        rig.Service.RunSweep();
        var second = rig.Service.RunSweep();
        Assert.Equal(0, second.NewDevices);
        Assert.Equal(0, second.LandedAssets);
        Assert.Single(rig.Register.List(Scope));
        Assert.Equal(2, rig.Census.Entries[0].SweepCount);
    }

    [Fact]
    public void Sweep_PolicyDisabled_RefusesAndAudits()
    {
        var rig = new Rig();
        rig.DisableDiscovery();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01"));
        var result = rig.Service.RunSweep();
        Assert.False(result.Ran);
        Assert.Contains("disabled by policy", result.RefusalReason);
        Assert.Empty(rig.Transport.ProbedIps); // the probe never fired
        Assert.Empty(rig.Census.Entries);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "discovery_sweep_refused");
    }

    [Fact]
    public void Sweep_RateLimit_RefusesInsideMinInterval()
    {
        var rig = new Rig(new ProbeScope(Scope, new[] { "10.0.0.0/29" }, 64, TimeSpan.FromMinutes(10)));
        Assert.True(rig.Service.RunSweep().Ran);
        var second = rig.Service.RunSweep();
        Assert.False(second.Ran);
        Assert.Contains("rate limit", second.RefusalReason);
        rig.Now += TimeSpan.FromMinutes(11);
        Assert.True(rig.Service.RunSweep().Ran);
    }

    [Fact]
    public void Sweep_PolicySubnets_OverrideFallbackScope()
    {
        var rig = new Rig(); // fallback 10.0.0.0/29
        rig.SetPolicySubnets("10.0.0.0/30"); // policy narrows to .1-.2
        rig.Transport.Script("10.0.0.5", Obs("10.0.0.5", "AA:BB:CC:00:00:05"));
        var result = rig.Service.RunSweep();
        Assert.True(result.Ran);
        Assert.Equal(2, result.ProbedHosts);
        Assert.DoesNotContain("10.0.0.5", rig.Transport.ProbedIps);
        Assert.Empty(rig.Census.Entries);
    }

    [Fact]
    public void Sweep_InvalidPolicySubnets_RefuseRatherThanFallBack()
    {
        var rig = new Rig();
        rig.SetPolicySubnets("10.0.0.5/24"); // host bits set — invalid scope content
        var result = rig.Service.RunSweep();
        Assert.False(result.Ran);
        Assert.Contains("policy probe scope invalid", result.RefusalReason);
        Assert.Empty(rig.Transport.ProbedIps);
    }

    // ---- drift + rogue ------------------------------------------------------

    [Fact]
    public void Drift_IpChange_RaisesDriftAlert()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:09", ports: new[] { 22 }));
        rig.Service.RunSweep();
        rig.Transport.Script("10.0.0.1", null);
        rig.Transport.Script("10.0.0.3", Obs("10.0.0.3", "AA:BB:CC:00:00:09", ports: new[] { 22 }));
        var second = rig.Service.RunSweep();
        Assert.Equal(1, second.DriftEvents);
        var entry = rig.Census.FindByMac("AA:BB:CC:00:00:09")!;
        Assert.Equal("10.0.0.3", entry.IpAddress);
        Assert.Contains(CensusDriftKinds.IpChanged, entry.DriftFlags);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.IdentityDrift);
    }

    [Fact]
    public void Rogue_FirstSighting_RaisesRogueAlert_ManagedMacDoesNot()
    {
        var rig = new Rig();
        rig.Service.SetKnownManagedMacs(new[] { "AA:BB:CC:00:00:20" });
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:20", ports: new[] { 22 })); // managed
        rig.Transport.Script("10.0.0.2", Obs("10.0.0.2", "AA:BB:CC:00:00:21", ports: new[] { 22 })); // unknown
        var result = rig.Service.RunSweep();
        Assert.Equal(new[] { "AA:BB:CC:00:00:21" }, result.RogueEntryIds);
        Assert.Contains(rig.Centre.ActiveAlerts,
            a => a.Kind == NetworkAlertKinds.RogueDevice && a.DeviceId == "AA:BB:CC:00:00:21");
        Assert.DoesNotContain(rig.Centre.ActiveAlerts,
            a => a.Kind == NetworkAlertKinds.RogueDevice && a.DeviceId == "AA:BB:CC:00:00:20");
    }

    [Fact]
    public void Promote_RemovesRegisterRecord_AndAudits()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:30", ports: new[] { 9100 }));
        rig.Service.RunSweep();
        var asset = Assert.Single(rig.Register.List(Scope));
        var (promoted, facts, _) = rig.Service.PromoteToManaged(asset.AssetId, "admin-1");
        Assert.True(promoted);
        Assert.NotNull(facts);
        Assert.Equal("AA:BB:CC:00:00:30", facts!.MacAddress);
        Assert.Empty(rig.Register.List(Scope));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "discovery_promoted" && e.Actor == "admin-1");
        var again = rig.Service.PromoteToManaged(asset.AssetId, "admin-1");
        Assert.False(again.Promoted);
    }

    // ---- topology -------------------------------------------------------------

    [Fact]
    public void Topology_BuildsNodesAndEdges_FromCensusAndHints()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 9100 }));
        rig.Transport.Script("10.0.0.2", Obs("10.0.0.2", "AA:BB:CC:00:00:02",
            ports: new[] { 22, 161 }, sysDescr: "Cisco Catalyst Switch"));
        rig.Service.RunSweep();
        var graph = rig.Service.BuildTopology(new[]
        {
            ("AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "bridge table: port 12"),
        });
        Assert.Equal(3, graph.Nodes.Count); // probe + 2 devices
        Assert.Contains(graph.Edges, e => e.Kind == TopologyEdgeKinds.Uplink &&
            e.FromId == "AA:BB:CC:00:00:01" && e.ToId == "AA:BB:CC:00:00:02");
        Assert.Contains(graph.Edges, e => e.Kind == TopologyEdgeKinds.DiscoveredBy);
        Assert.Contains(graph.Nodes, n => n.Kind == TopologyNodeKinds.Switch);
    }

    // ---- kind guessing ----------------------------------------------------------

    [Fact]
    public void KindGuessing_PrinterCameraBasSwitchUps()
    {
        Assert.Equal("printer", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 9100 })));
        Assert.Equal("camera", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01", onvif: true)));
        Assert.Equal("camera", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 554 })));
        Assert.Equal("bas-controller", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01", ports: new[] { 47808 })));
        Assert.Equal("ups", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01", sysDescr: "APC UPS")));
        Assert.Equal("other", DeviceFingerprint.GuessKind(Obs("10.0.0.1", "AA:BB:CC:00:00:01")));
    }

    // ---- SNMP ---------------------------------------------------------------------

    private static byte[] SnmpFixture(params string[] lines) => Encoding.UTF8.GetBytes(string.Join("\n", lines));

    [Fact]
    public void SnmpParser_ParsesVarBinds_AndCountsMalformedLines()
    {
        var result = SnmpFixtureParser.Parse(SnmpFixture(
            "1.3.6.1.2.1.1.1.0|OctetString|HP LaserJet",
            "not-an-oid|Integer|5",
            "1.3.6.1.2.1.33.1.2.4.0|Integer|87",
            "garbage line"));
        Assert.True(result.Ok);
        Assert.Equal(2, result.VarBinds.Count);
        Assert.Equal(2, result.DroppedLines);
    }

    [Fact]
    public void SnmpEvaluator_TonerBatteryPortAndCustomRules()
    {
        var binds = SnmpFixtureParser.Parse(SnmpFixture(
            "1.3.6.1.2.1.43.11.1.1.9.1.1|Integer|10",   // toner 10%
            "1.3.6.1.2.1.33.1.2.4.0|Integer|25",        // battery 25%
            "1.3.6.1.2.1.33.1.2.2.0|Integer|2",         // on battery
            "1.3.6.1.2.1.2.2.1.8.3|Integer|2",          // port 3 down
            "1.3.6.1.2.1.2.2.1.8.4|Integer|1",          // port 4 up
            "1.3.6.1.4.1.9999.1.1|Integer|950"))        // custom OID
            .VarBinds;
        var rules = new[] { new SnmpOidRule("1.3.6.1.4.1.9999.1.1", SnmpOidRule.Above, 900, "critical", "custom temp") };
        var findings = SnmpMonitorEvaluator.Evaluate(binds, rules);
        Assert.Contains(findings, f => f.Kind == SnmpFindingKinds.TonerLow);
        Assert.Contains(findings, f => f.Kind == SnmpFindingKinds.BatteryLow);
        Assert.Contains(findings, f => f.Kind == SnmpFindingKinds.OnBattery && f.Severity == "critical");
        Assert.Contains(findings, f => f.Kind == SnmpFindingKinds.PortDown && f.Oid.EndsWith(".3"));
        Assert.DoesNotContain(findings, f => f.Kind == SnmpFindingKinds.PortDown && f.Oid.EndsWith(".4"));
        Assert.Contains(findings, f => f.Kind == SnmpFindingKinds.CustomAbove);
        // Healthy readings produce nothing.
        var ok = SnmpFixtureParser.Parse(SnmpFixture(
            "1.3.6.1.2.1.43.11.1.1.9.1.1|Integer|80",
            "1.3.6.1.2.1.33.1.2.4.0|Integer|100",
            "1.3.6.1.2.1.33.1.2.2.0|Integer|1")).VarBinds;
        Assert.Empty(SnmpMonitorEvaluator.Evaluate(ok));
        // Sentinel toner values (-3 = some remaining) are not percentages.
        var sentinel = SnmpFixtureParser.Parse(SnmpFixture(
            "1.3.6.1.2.1.43.11.1.1.9.1.1|Integer|-3")).VarBinds;
        Assert.Empty(SnmpMonitorEvaluator.Evaluate(sentinel));
    }

    [Fact]
    public void SnmpIngest_RaisesCentreAlerts_AndTrapParses()
    {
        var rig = new Rig();
        var (ok, _, findings) = rig.Service.IngestSnmpReading("printer-1",
            SnmpFixture("1.3.6.1.2.1.43.11.1.1.9.1.1|Integer|5"));
        Assert.True(ok);
        Assert.Single(findings);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.SnmpThreshold);

        var trap = rig.Service.IngestSnmpTrap(SnmpFixture(
            "TRAP|1.3.6.1.4.1.9.9.43|10.0.0.9|6|1",
            "1.3.6.1.2.1.1.5.0|OctetString|switch-1"));
        Assert.True(trap.Ok);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.SnmpTrap);
    }

    // ---- syslog ----------------------------------------------------------------------

    [Fact]
    public void Syslog_ParsesAndKeywordAlerts()
    {
        var msg = SyslogParser.Parse("<34>Oct 11 22:14:15 jace-1 sshd: Failed password for admin");
        Assert.NotNull(msg);
        Assert.Equal(4, msg!.Facility);
        Assert.Equal(2, msg.Severity);
        Assert.Equal("jace-1", msg.Hostname);
        Assert.Equal("sshd", msg.Tag);
        Assert.Contains("Failed password", msg.Message);
        Assert.Null(SyslogParser.Parse("not a syslog line"));
        Assert.Null(SyslogParser.Parse("<999>bad pri"));

        var rig = new Rig(syslog: new[] { new SyslogKeywordRule("Failed password", "warning") });
        var (ok, _, hits) = rig.Service.IngestSyslogLine("<34>Oct 11 22:14:15 jace-1 sshd: Failed password for admin");
        Assert.True(ok);
        Assert.Equal(1, hits);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.SyslogKeyword);
        var quiet = rig.Service.IngestSyslogLine("<38>Oct 11 22:15:15 jace-1 cron: job finished");
        Assert.Equal(0, quiet.Hits);
    }

    // ---- flow ---------------------------------------------------------------------------

    private static byte[] NetFlowDatagram(params (string Src, string Dst, uint Packets, uint Octets, int Prot)[] flows)
    {
        var bytes = new byte[NetFlowV5Parser.HeaderBytes + flows.Length * NetFlowV5Parser.RecordBytes];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0), 5);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)flows.Length);
        for (var i = 0; i < flows.Length; i++)
        {
            var r = bytes.AsSpan(NetFlowV5Parser.HeaderBytes + i * NetFlowV5Parser.RecordBytes, NetFlowV5Parser.RecordBytes);
            IPAddress.Parse(flows[i].Src).GetAddressBytes().CopyTo(r);
            IPAddress.Parse(flows[i].Dst).GetAddressBytes().CopyTo(r.Slice(4));
            BinaryPrimitives.WriteUInt32BigEndian(r.Slice(16), flows[i].Packets);
            BinaryPrimitives.WriteUInt32BigEndian(r.Slice(20), flows[i].Octets);
            BinaryPrimitives.WriteUInt16BigEndian(r.Slice(32), 51000);
            BinaryPrimitives.WriteUInt16BigEndian(r.Slice(34), 443);
            r[38] = (byte)flows[i].Prot;
        }
        return bytes;
    }

    [Fact]
    public void NetFlow_ParsesRealWireFormat_AndSummarizes()
    {
        var summary = NetFlowV5Parser.Parse(NetFlowDatagram(
            ("10.0.0.5", "10.0.0.1", 100, 50000, 6),
            ("10.0.0.5", "10.0.0.2", 50, 30000, 6),
            ("10.0.0.6", "10.0.0.1", 10, 5000, 17)));
        Assert.NotNull(summary);
        Assert.Equal(3, summary!.FlowCount);
        Assert.Equal(85000, summary.TotalOctets);
        Assert.Equal(160, summary.TotalPackets);
        Assert.Equal(("10.0.0.5", 80000L), summary.TopTalkers[0]);

        var rig = new Rig();
        var (ok, _, svcSummary) = rig.Service.IngestFlowDatagram(NetFlowDatagram(("10.0.0.5", "10.0.0.1", 1, 100, 6)));
        Assert.True(ok);
        Assert.NotNull(svcSummary);
        Assert.NotNull(rig.Service.LastFlowSummary);
    }

    [Fact]
    public void Sflow_SamplesSummarizeThroughTheSameAggregator()
    {
        var summary = FlowAggregator.SummarizeSflow(new[]
        {
            new SflowSample("10.0.0.9", "10.0.0.5", "10.0.0.1", 7000, 6),
            new SflowSample("10.0.0.9", "10.0.0.5", "10.0.0.2", 3000, 6),
            new SflowSample("10.0.0.9", "10.0.0.7", "10.0.0.1", 1000, 17),
        });
        Assert.Equal(3, summary.FlowCount);
        Assert.Equal(11000, summary.TotalOctets);
        Assert.Equal(("10.0.0.5", 10000L), summary.TopTalkers[0]);
    }

    // ---- config backup ---------------------------------------------------------------------

    private const string ConfigV1 = "hostname switch-1\ninterface Gi1/0/1\n switchport mode access\n";
    private const string ConfigV2 = "hostname switch-1\ninterface Gi1/0/1\n switchport mode trunk\n";

    [Fact]
    public void ConfigBackup_FirstUnchangedChanged_VersionsDiffAndChain()
    {
        var store = new ConfigBackupStore();
        var first = store.Backup("sw-1", ConfigV1, "test", T0);
        Assert.Equal(ConfigBackupResult.FirstVersion, first.Outcome);
        var same = store.Backup("sw-1", ConfigV1, "test", T0);
        Assert.Equal(ConfigBackupResult.Unchanged, same.Outcome);
        var changed = store.Backup("sw-1", ConfigV2, "test", T0);
        Assert.Equal(ConfigBackupResult.Changed, changed.Outcome);
        Assert.True(changed.Diff!.Changed);
        Assert.Contains(changed.Diff.AddedLines, l => l.Contains("trunk"));
        Assert.Contains(changed.Diff.RemovedLines, l => l.Contains("access"));
        Assert.Equal(2, store.Versions("sw-1").Count);
        var (ok, _) = store.VerifyIntegrity("sw-1");
        Assert.True(ok);
        // CRLF transport difference is NOT a change.
        var crlf = store.Backup("sw-1", ConfigV2.Replace("\n", "\r\n"), "test", T0);
        Assert.Equal(ConfigBackupResult.Unchanged, crlf.Outcome);
    }

    [Fact]
    public void ConfigBackupCycle_FetchesSwitches_AndAlertsOnChange()
    {
        var rig = new Rig();
        var asset = new UnmanagedAsset("sw-1", Scope, "Switch 1", UnmanagedAssetKinds.NetworkSwitch,
            "Cisco", "Catalyst", null, "10.0.0.9", "AA:BB:CC:00:00:99", null, null,
            UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
            new Dictionary<string, string>(), null, "manual", T0, T0);
        Assert.NotNull(rig.Register.Add(asset));
        rig.Fetcher.Script("sw-1", ConfigV1);
        var first = rig.Service.RunConfigBackupCycle();
        Assert.Equal(ConfigBackupResult.FirstVersion, first[0].Outcome);
        rig.Fetcher.Script("sw-1", ConfigV2);
        var second = rig.Service.RunConfigBackupCycle();
        Assert.Equal(ConfigBackupResult.Changed, second[0].Outcome);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == NetworkAlertKinds.ConfigChanged);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "config_changed");
        // Fetch failure is named, not silent.
        rig.Fetcher.ScriptFailure("sw-1", "ssh timeout");
        var third = rig.Service.RunConfigBackupCycle();
        Assert.Equal("fetch_failed", third[0].Outcome);
    }

    [Fact]
    public void CameraLanding_OnvifCameraLandsViewable_CloudCameraLandsInventoryOnly()
    {
        var rig = new Rig();
        rig.Transport.Script("10.0.0.1", Obs("10.0.0.1", "AA:BB:CC:00:00:41", onvif: true,
            sysDescr: "Hikvision DS-2CD", hostname: "cam-lobby"));
        rig.Transport.Script("10.0.0.2", Obs("10.0.0.2", "AA:BB:CC:00:00:42", ports: new[] { 443 },
            sysDescr: "Wyze Cam v3", hostname: "cam-nursery"));
        rig.Service.RunSweep();
        var cams = rig.Register.List(Scope, UnmanagedAssetKinds.Camera);
        Assert.Equal(2, cams.Count);
        var onvif = cams.Single(c => c.MacAddress == "AA:BB:CC:00:00:41");
        Assert.Equal(CameraViewCapabilities.Onvif, onvif.ViewCapability);
        Assert.Null(onvif.InventoryOnlyReason);
        var wyze = cams.Single(c => c.MacAddress == "AA:BB:CC:00:00:42");
        Assert.Equal(CameraViewCapabilities.InventoryOnly, wyze.ViewCapability);
        Assert.Contains("Cloud-locked", wyze.InventoryOnlyReason);
        Assert.All(cams, c => Assert.Equal("rmm11-discovery", c.DiscoveredBy));
    }
}

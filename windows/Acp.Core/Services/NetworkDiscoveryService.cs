using System.Net;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.NetworkDiscovery;

namespace Acp.Core.Services;

// =====================================================================
// RMM-11 — the discovery probe service. Sibling pattern (the Wake
// shape): this service runs on whichever ACP device sits on the
// site LAN (or the hub); a remote admin's request reaches it over
// ACP transports, and the probing itself never leaves the site.
// Discovery data is filed LOCALLY — census, register, alerts,
// audit — there is no outbound path in this service at all.
//
// The cycle: policy gate (rmm.network_discovery.enabled, RMM-07
// engine) → effective scope from policy (subnets / caps / interval
// are policy content; the constructor scope is only the fallback)
// → rate limit (minimum interval between sweeps, injected clock)
// → bounded enumeration (host cap) → transport probes → scope
// re-check per observation (an answer from outside the scope is
// REFUSED, never filed) → census upsert (drift + poisoning) →
// register landing for new, non-quarantined identities
// (DiscoveredBy="rmm11-discovery") → rogue/drift alerts into
// RMM-01's HealthAlertCentre.
//
// Agentless monitoring rides the same service: SNMP readings,
// traps, syslog lines and flow datagrams are ingested as fixtures
// the collectors produce; evaluation is the pure model layer's.
// Config backup is a per-device cycle over the register's network
// gear through IConfigFetcher, with change alerts into the centre.
// =====================================================================

public sealed record SweepResult(
    bool Ran, string? RefusalReason, int ProbedHosts, int Answered,
    int NewDevices, int DriftEvents, int Quarantined, int ScopeEscapes,
    int LandedAssets, IReadOnlyList<string> RogueEntryIds,
    int CensusRefused = 0)
{
    public IReadOnlyList<string> RogueEntryIds { get; init; } = RogueEntryIds ?? Array.Empty<string>();
}

public sealed class NetworkDiscoveryService
{
    private readonly string _probeDeviceId;
    private readonly string _scopeId;
    private readonly IDeviceFacts _probeFacts;
    private readonly ManagementPolicyEngine _policy;
    private readonly IProbeTransport _transport;
    private readonly SiteCensus _census;
    private readonly UnmanagedAssetRegister _register;
    private readonly HealthAlertCentre? _alerts;
    private readonly ChainedAuditLog _audit;
    private readonly IConfigFetcher? _configFetcher;
    private readonly ConfigBackupStore _configStore;
    private readonly Func<DateTimeOffset> _now;
    private readonly ProbeScope _fallbackScope;
    private readonly IReadOnlyList<SnmpOidRule> _snmpRules;
    private readonly IReadOnlyList<SyslogKeywordRule> _syslogRules;

    private readonly object _gate = new();
    private DateTimeOffset? _lastSweepUtc;
    private long _sweepSeq;
    private bool _sweepRunning;
    private readonly HashSet<string> _knownManagedMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _assetIdByEntryId = new(StringComparer.OrdinalIgnoreCase);
    private FlowSummary? _lastFlowSummary;

    public NetworkDiscoveryService(
        string probeDeviceId, string scopeId, IDeviceFacts probeFacts,
        ManagementPolicyEngine policy, IProbeTransport transport,
        SiteCensus census, UnmanagedAssetRegister register,
        ChainedAuditLog audit,
        HealthAlertCentre? alerts = null,
        IConfigFetcher? configFetcher = null,
        ConfigBackupStore? configStore = null,
        ProbeScope? fallbackScope = null,
        IEnumerable<SnmpOidRule>? snmpRules = null,
        IEnumerable<SyslogKeywordRule>? syslogRules = null,
        Func<DateTimeOffset>? now = null)
    {
        _probeDeviceId = probeDeviceId ?? throw new ArgumentNullException(nameof(probeDeviceId));
        _scopeId = scopeId ?? throw new ArgumentNullException(nameof(scopeId));
        _probeFacts = probeFacts ?? throw new ArgumentNullException(nameof(probeFacts));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _census = census ?? throw new ArgumentNullException(nameof(census));
        _register = register ?? throw new ArgumentNullException(nameof(register));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _alerts = alerts;
        _configFetcher = configFetcher;
        _configStore = configStore ?? new ConfigBackupStore();
        _fallbackScope = fallbackScope ?? ProbeScope.Default(scopeId);
        _snmpRules = (snmpRules ?? Array.Empty<SnmpOidRule>()).ToList();
        _syslogRules = (syslogRules ?? Array.Empty<SyslogKeywordRule>()).ToList();
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public SiteCensus Census => _census;
    public ConfigBackupStore ConfigStore => _configStore;
    public FlowSummary? LastFlowSummary { get { lock (_gate) return _lastFlowSummary; } }

    /// <summary>THE policy gate: rmm.network_discovery.enabled for
    /// the probe device, via the RMM-07 engine (TOTAL POLICY
    /// CONTROL — the probe role itself is policy-gated).</summary>
    public bool DiscoveryEnabled => _policy.IsEnabled(_probeFacts, NetworkDiscoveryPolicyKeys.DiscoveryEnabled);

    /// <summary>The managed fleet's network identities (MACs), as
    /// wired from the enrollment store at hub integration: a census
    /// identity matching one is a managed device seen on the wire,
    /// never a rogue. This is the rogue baseline alongside the
    /// register.</summary>
    public void SetKnownManagedMacs(IEnumerable<string> macs)
    {
        lock (_gate)
        {
            _knownManagedMacs.Clear();
            foreach (var m in macs ?? Array.Empty<string>())
            {
                var n = DeviceFingerprint.NormalizeMac(m);
                if (n is not null) _knownManagedMacs.Add(n);
            }
        }
    }

    /// <summary>The effective probe scope: policy content wins
    /// (subnets / host cap / interval from the probe's Effective
    /// Policy); the constructor scope fills what policy leaves
    /// unset. An invalid policy scope refuses the sweep — policy
    /// content is never silently replaced by the fallback.</summary>
    public (ProbeScope? Scope, string? Error) EffectiveScope()
    {
        var effective = _policy.ComputeEffective(_probeFacts);
        var subnetsSetting = effective.Get(NetworkDiscoveryPolicyKeys.Subnets);
        var maxHostsSetting = effective.Get(NetworkDiscoveryPolicyKeys.MaxHostsPerSweep);
        var intervalSetting = effective.Get(NetworkDiscoveryPolicyKeys.MinSweepIntervalSeconds);
        // Policy content fills what it sets; the constructor scope
        // fills the rest (the documented contract). The fallback is
        // used verbatim only when policy sets NOTHING — the old
        // code keyed everything off the subnets setting alone, so
        // a policy that set only max_hosts or only the interval
        // was silently ignored (found by FIX11-F8's first run).
        if (subnetsSetting is null && maxHostsSetting is null && intervalSetting is null)
        {
            var err = _fallbackScope.Validate();
            return err is null ? (_fallbackScope, null) : (null, err);
        }
        // FIX (D38 F8c): a null policy value must not throw out of
        // the sweep — it is scope content that names nothing.
        var subnets = subnetsSetting is null
            ? _fallbackScope.Subnets
            : (subnetsSetting.Value ?? string.Empty).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var maxHosts = _fallbackScope.MaxHostsPerSweep;
        // FIX (D38 F8c): policy content that is PRESENT but
        // unparsable refuses the scope — the old code silently
        // kept the constructor fallback, contradicting the rule
        // that policy content is never silently replaced.
        if (maxHostsSetting is not null)
        {
            if (!int.TryParse(maxHostsSetting.Value, out var parsedHosts))
                return (null, $"policy probe scope invalid: max_hosts_per_sweep '{maxHostsSetting.Value}' is not an integer — refused");
            maxHosts = parsedHosts;
        }
        var interval = _fallbackScope.MinSweepInterval;
        if (intervalSetting is not null)
        {
            if (!int.TryParse(intervalSetting.Value, out var parsedSecs))
                return (null, $"policy probe scope invalid: min_sweep_interval_seconds '{intervalSetting.Value}' is not an integer — refused");
            // FIX (D38 F8b): policy may not remove the politeness
            // bound — an interval of 0 (or negative) from POLICY
            // refuses the scope rather than authorizing back-to-
            // back sweeps. (The constructor fallback is the
            // operator's own choice and is not policed here.)
            if (parsedSecs <= 0)
                return (null, $"policy probe scope invalid: min_sweep_interval_seconds must be positive (policy may not remove the sweep politeness bound) — refused");
            interval = TimeSpan.FromSeconds(parsedSecs);
        }
        var scope = new ProbeScope(_scopeId, subnets, maxHosts, interval);
        var validation = scope.Validate();
        return validation is null ? (scope, null) : (null, $"policy probe scope invalid: {validation}");
    }

    // ---- the sweep ---------------------------------------------------

    public SweepResult RunSweep()
    {
        var now = _now();
        SweepResult Refused(string reason)
        {
            _audit.Append("discovery_sweep_refused", "rmm11-probe",
                $"probe={_probeDeviceId} scope={_scopeId} reason={reason}", now);
            return new SweepResult(false, reason, 0, 0, 0, 0, 0, 0, 0, Array.Empty<string>());
        }

        if (!DiscoveryEnabled)
            return Refused($"network discovery is disabled by policy ({NetworkDiscoveryPolicyKeys.DiscoveryEnabled})");
        var (scope, scopeError) = EffectiveScope();
        if (scope is null) return Refused(scopeError ?? "no valid probe scope");

        string sweepId;
        lock (_gate)
        {
            // FIX (D38 F12c): one sweep at a time, and the sequence
            // number is minted under the same lock — the old code
            // incremented it after releasing the lock, so concurrent
            // sweeps could interleave census sweep ids and clear
            // each other's poisoning witnesses mid-sweep.
            if (_sweepRunning)
                return Refused("a discovery sweep is already in progress on this probe");
            if (_lastSweepUtc is { } last)
            {
                var elapsed = now - last;
                // FIX (D38 F8a): a NEGATIVE elapsed (the clock was
                // corrected backwards after a forward jump) is not
                // "inside the interval" — the old check stored a
                // future _lastSweepUtc and then refused every sweep
                // until real time caught up, up to a year of dead
                // discovery from one clock jump. A backwards clock
                // resets the limiter instead of poisoning it.
                if (elapsed >= TimeSpan.Zero && elapsed < scope.MinSweepInterval)
                    return Refused($"sweep rate limit: last sweep {last:O}, minimum interval {scope.MinSweepInterval}");
            }
            _lastSweepUtc = now;
            _sweepRunning = true;
            sweepId = $"sweep-{++_sweepSeq}-{now:yyyyMMddHHmmss}";
        }

        // BD-WIN-CORE-3/F8: EVERYTHING after the lock runs under
        // try/finally — the old shape cleared _sweepRunning only on
        // the normal return path, so one throw from census/register/
        // alerts/audit left discovery refused as "already in
        // progress" until a Core restart.
        try
        {
            return RunSweepBody(now, scope, sweepId);
        }
        catch (Exception ex)
        {
            _audit.Append("discovery_sweep_failed", "rmm11-probe",
                $"probe={_probeDeviceId} scope={_scopeId} sweep={sweepId} error={ex.GetType().Name}: {ex.Message}", now);
            return new SweepResult(false,
                $"discovery sweep failed: {ex.GetType().Name}: {ex.Message}", 0, 0, 0, 0, 0, 0, 0, Array.Empty<string>());
        }
        finally
        {
            lock (_gate) _sweepRunning = false;
        }
    }

    private SweepResult RunSweepBody(DateTimeOffset now, ProbeScope scope, string sweepId)
    {
        var probed = 0; var answered = 0; var newDevices = 0;
        var driftEvents = 0; var quarantined = 0; var escapes = 0; var landed = 0;
        var censusRefused = 0;
        var rogueIds = new List<string>();
        var budget = scope.MaxHostsPerSweep;
        // Landing is DEFERRED to the end of the sweep: an identity
        // that trips the census poisoning quarantine mid-sweep must
        // not already be sitting in the register from its first
        // claims. Candidates are re-read after enumeration — only
        // identities still clean at sweep end land.
        var landingCandidates = new List<(CensusEntry Entry, ProbeObservation Obs, bool WasNew)>();

        foreach (var cidr in scope.Subnets)
        {
            if (budget <= 0) break;
            if (!NetworkAddressing.TryParseCidr(cidr, out var network, out var prefix)) continue;
            foreach (var host in NetworkAddressing.EnumerateHosts(network, prefix, budget))
            {
                // FIX (D38 F2a, second line): never SEND a probe to
                // a non-probeable target. Scope validation refuses
                // such subnets up front; this check is the belt to
                // that suspender — a target that is not probeable
                // is skipped, not probed-then-refused-at-filing.
                if (!NetworkAddressing.IsProbeableHost(host)) continue;
                budget--; probed++;
                ProbeObservation? obs;
                try { obs = _transport.Probe(host.ToString(), now); }
                catch { obs = null; } // a hostile/broken answer path is "no answer", never a sweep crash
                if (obs is null) continue;
                answered++;
                // SCOPE ESCAPE: the answer must BE the probed host,
                // inside the configured scope. Anything else is
                // refused and counted — never filed.
                if (!IPAddress.TryParse(obs.IpAddress ?? "", out var obsIp) ||
                    !NetworkAddressing.UnwrapMapped(obsIp).Equals(host) || !scope.Contains(obsIp) ||
                    !NetworkAddressing.IsProbeableHost(obsIp))
                {
                    escapes++;
                    _audit.Append("discovery_scope_escape", "rmm11-probe",
                        $"probe={_probeDeviceId} probed={host} answeredAs={obs.IpAddress} sweep={sweepId} — refused, not filed", now);
                    continue;
                }
                var upsert = _census.Upsert(obs, sweepId, now);
                switch (upsert.Outcome)
                {
                    case CensusUpsertResult.Added: newDevices++; break;
                    case CensusUpsertResult.Drift: driftEvents++; break;
                    case CensusUpsertResult.Quarantined: quarantined++; break;
                    // FIX (D38 F7): a census refusal (full census of
                    // fresh entries) is COUNTED and AUDITED per
                    // device — the old switch had no Refused case
                    // and the device vanished silently: uncounted,
                    // unalerted, unaudited.
                    case CensusUpsertResult.Refused:
                        censusRefused++;
                        _audit.Append("discovery_census_refused", "rmm11-probe",
                            $"probe={_probeDeviceId} ip={obs.IpAddress} mac={obs.MacAddress} sweep={sweepId} reason={upsert.Detail} — device NOT filed", now);
                        break;
                }
                if (upsert.Entry is null) continue;
                if (upsert.DriftKinds.Count > 0 && upsert.Outcome != CensusUpsertResult.Quarantined)
                    RaiseDriftAlert(upsert.Entry, upsert.DriftKinds, now);
                if (upsert.Entry.Quarantined) continue; // quarantined identities never land
                landingCandidates.Add((upsert.Entry, obs, upsert.Outcome == CensusUpsertResult.Added));
            }
        }

        // FIX (D38 F12b): the register is listed ONCE for the
        // landing phase — IsUnfiled/LandInRegister previously each
        // called List per candidate (O(candidates × register)).
        // The list is mutable: LandInRegister appends what it
        // lands, so the unfiled test still sees this sweep's own
        // landings exactly as the old per-candidate List did.
        var filedSnapshot = _register.List(_scopeId).ToList();
        foreach (var (candidate, obs, wasNew) in landingCandidates)
        {
            var current = _census.Get(candidate.EntryId);
            if (current is null || current.Quarantined) continue; // poisoned mid-sweep: never lands
            // FIX (D38 F6): a KNOWN MANAGED identity never lands in
            // the unmanaged register — after promotion this is what
            // keeps a promoted device from being re-filed (and
            // re-rogue-alerted) on every later sweep.
            if (IsKnownManaged(current)) continue;
            if (LandInRegister(current, obs, now, filedSnapshot)) landed++;
            // ROGUE: a FIRST sighting of an identity that is neither
            // a known managed device nor already filed is the rogue
            // event (Cyber Hawk pattern) — the alert is what brings
            // an admin to claim the discovered record.
            if ((wasNew && !IsKnownManaged(current)) || IsUnfiled(current, filedSnapshot))
                rogueIds.Add(current.EntryId);
        }

        foreach (var rogueId in rogueIds)
        {
            var entry = _census.Get(rogueId)!;
            _alerts?.Raise(entry.EntryId, $"rogue:{entry.EntryId}", NetworkAlertKinds.RogueDevice,
                AlertSeverities.Warning,
                $"device {entry.EntryId} at {entry.IpAddress} (kind guess {entry.KindGuess}) appeared on the network unknown to the census, the register and the managed fleet — rogue until an admin claims it",
                "rmm11-probe", TimeSpan.FromHours(1), now);
        }

        _audit.Append("discovery_sweep", "rmm11-probe",
            $"probe={_probeDeviceId} sweep={sweepId} probed={probed} answered={answered} new={newDevices} drift={driftEvents} quarantined={quarantined} escapes={escapes} landed={landed} rogues={rogueIds.Count} censusRefused={censusRefused}", now);
        return new SweepResult(true, null, probed, answered, newDevices, driftEvents,
            quarantined, escapes, landed, rogueIds, censusRefused);
    }

    private bool IsKnownManaged(CensusEntry entry)
    {
        lock (_gate)
            return entry.MacAddress is not null && _knownManagedMacs.Contains(entry.MacAddress);
    }

    /// <summary>Unfiled test: the identity matches no register
    /// record by MAC or IP — its landing was refused (register
    /// disabled, invalid record) or an admin removed the record
    /// while the device remains on the wire. An unfiled device is
    /// rogue on every sweep until it is filed or managed.</summary>
    private bool IsUnfiled(CensusEntry entry, List<UnmanagedAsset> filedSnapshot)
    {
        if (IsKnownManaged(entry)) return false;
        var filed = filedSnapshot.Any(a =>
            (entry.MacAddress is not null && string.Equals(a.MacAddress, entry.MacAddress, StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(a.IpAddress, entry.IpAddress, StringComparison.OrdinalIgnoreCase));
        return !filed;
    }

    private void RaiseDriftAlert(CensusEntry entry, IReadOnlyList<string> driftKinds, DateTimeOffset now)
    {
        var severity = driftKinds.Contains(CensusDriftKinds.MacChanged) ? AlertSeverities.Critical : AlertSeverities.Warning;
        _alerts?.Raise(entry.EntryId, $"drift:{entry.EntryId}", NetworkAlertKinds.IdentityDrift,
            severity,
            $"identity drift for {entry.EntryId} at {entry.IpAddress}: {string.Join(",", driftKinds)}",
            "rmm11-probe", TimeSpan.FromHours(1), now);
        _audit.Append("discovery_drift", "rmm11-probe",
            $"entry={entry.EntryId} ip={entry.IpAddress} drift={string.Join(",", driftKinds)}", now);
    }

    /// <summary>Land a census identity in the RMM-04 register
    /// (DiscoveredBy="rmm11-discovery"). Already-filed identities
    /// (same MAC or IP in this scope) are not duplicated. Cameras
    /// carry their ViewCapability from capability evidence —
    /// cloud-locked and unprofiled cameras land inventory-only with
    /// the reason stated, per the extension's bounds.</summary>
    private bool LandInRegister(CensusEntry entry, ProbeObservation obs, DateTimeOffset now,
        List<UnmanagedAsset> filedSnapshot)
    {
        string assetId;
        lock (_gate)
        {
            if (_assetIdByEntryId.ContainsKey(entry.EntryId)) return false;
            assetId = "disc-" + entry.EntryId.Replace(":", "").Replace(".", "-").ToLowerInvariant();
        }
        var already = filedSnapshot.Any(a =>
            (entry.MacAddress is not null && string.Equals(a.MacAddress, entry.MacAddress, StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(a.IpAddress, entry.IpAddress, StringComparison.OrdinalIgnoreCase));
        if (already)
        {
            lock (_gate) _assetIdByEntryId[entry.EntryId] = assetId;
            return false;
        }

        string? viewCapability = null; string? inventoryReason = null;
        if (entry.KindGuess == UnmanagedAssetKinds.Camera)
        {
            var rtsp = (obs.OpenPorts ?? Array.Empty<int>()).Contains(554);
            var (cap, reason) = CloudCameraClassifier.CapabilityFor(
                obs.OnvifCapable, rtsp, entry.Make, entry.Model, obs.Snmp?.SysDescr);
            viewCapability = cap; inventoryReason = reason;
        }
        var asset = new UnmanagedAsset(
            AssetId: assetId, ScopeId: _scopeId,
            Name: obs.Hostname ?? entry.EntryId,
            Kind: entry.KindGuess,
            Make: entry.Make, Model: entry.Model,
            SerialNumber: null, IpAddress: entry.IpAddress, MacAddress: entry.MacAddress,
            SiteId: null, Location: null,
            LifecycleState: UnmanagedLifecycleStates.Discovered,
            ManagedDeviceIds: Array.Empty<string>(),
            Tags: new HashSet<string>(),
            CustomFields: new Dictionary<string, string>(),
            Notes: $"discovered by rmm11 probe {_probeDeviceId}",
            DiscoveredBy: "rmm11-discovery",
            CreatedUtc: now, UpdatedUtc: now,
            PurchaseDateUtc: null, ViewCapability: viewCapability, InventoryOnlyReason: inventoryReason);
        var added = _register.Add(asset) is not null;
        if (added)
        {
            lock (_gate) _assetIdByEntryId[entry.EntryId] = assetId;
            filedSnapshot.Add(asset); // this sweep's unfiled test sees the landing (F12b)
        }
        return added;
    }

    /// <summary>Admin promotion: a found device becomes managed.
    /// Enrollment itself lives in the enrollment store — this act
    /// removes the register record (one identity, one home: the
    /// register's managed-collision rule then guards the seam) and
    /// returns the discovered facts the enrollment is minted from.
    /// Audited either way.</summary>
    public (bool Promoted, CensusEntry? Facts, string Reason) PromoteToManaged(string assetId, string actorUserId)
    {
        var now = _now();
        var asset = _register.Get(assetId);
        if (asset is null)
        {
            _audit.Append("discovery_promotion_refused", actorUserId ?? "unknown",
                $"asset={assetId} reason=unknown asset", now);
            return (false, null, "unknown asset — promotion refused");
        }
        string? entryId;
        lock (_gate)
            entryId = _assetIdByEntryId.FirstOrDefault(kv =>
                string.Equals(kv.Value, asset.AssetId, StringComparison.OrdinalIgnoreCase)).Key;
        var facts = entryId is not null ? _census.Get(entryId) : null;
        if (!_register.Remove(asset.AssetId))
            return (false, null, "register refused the removal — promotion refused");
        // FIX (D38 F6): promotion must change the service's own
        // bookkeeping — the old code left the MAC out of
        // _knownManagedMacs and left the entry→asset map in place,
        // so the promoted device was rogue-alerted on EVERY later
        // sweep and could never land or settle. Now the promoted
        // MAC is known-managed (never rogue, never re-landed) and
        // the stale asset map entry is dropped.
        lock (_gate)
        {
            var promotedMac = DeviceFingerprint.NormalizeMac(asset.MacAddress);
            if (promotedMac is not null) _knownManagedMacs.Add(promotedMac);
            if (entryId is not null) _assetIdByEntryId.Remove(entryId);
        }
        _audit.Append("discovery_promoted", actorUserId,
            $"asset={asset.AssetId} ip={asset.IpAddress} mac={asset.MacAddress} — register record removed; enrollment proceeds in the enrollment store", now);
        return (true, facts, "promoted: register record removed for enrollment");
    }

    /// <summary>Admin unquarantine (FIX D38 F3): clears a census
    /// identity's quarantine so it can land and alert again.
    /// Audited either way — clearing a quarantine is a trust act
    /// and leaves a record.</summary>
    public bool ClearQuarantine(string entryId, string actorUserId)
    {
        var now = _now();
        var ok = _census.ClearQuarantine(entryId);
        _audit.Append(ok ? "discovery_quarantine_cleared" : "discovery_quarantine_clear_refused",
            actorUserId ?? "unknown", $"entry={entryId}", now);
        return ok;
    }

    // ---- agentless monitoring ingest -----------------------------------

    /// <summary>Evaluate one device's SNMP reading fixture: vendor
    /// facts + custom OID rules → findings → RMM-01 centre alerts.
    /// A parse failure is a named refusal (and audited): a lying
    /// SNMP response must not become a silent "healthy".</summary>
    public (bool Ok, string Reason, IReadOnlyList<SnmpFinding> Findings) IngestSnmpReading(
        string subjectId, ReadOnlySpan<byte> fixture)
    {
        var now = _now();
        var parsed = SnmpFixtureParser.Parse(fixture);
        if (!parsed.Ok)
        {
            _audit.Append("snmp_reading_refused", "rmm11-probe",
                $"subject={subjectId} reason={parsed.Error}", now);
            return (false, parsed.Error ?? "snmp parse failed", Array.Empty<SnmpFinding>());
        }
        var findings = SnmpMonitorEvaluator.Evaluate(parsed.VarBinds, _snmpRules);
        foreach (var f in findings)
            _alerts?.Raise(subjectId, $"snmp:{f.Oid}", NetworkAlertKinds.SnmpThreshold,
                f.Severity, $"{f.Kind}: {f.Detail}", "rmm11-probe", TimeSpan.FromMinutes(30), now);
        return (true, parsed.DroppedLines > 0
            ? $"evaluated with {parsed.DroppedLines} malformed varbind lines dropped"
            : "evaluated", findings);
    }

    public (bool Ok, string Reason) IngestSnmpTrap(ReadOnlySpan<byte> fixture)
    {
        var now = _now();
        var trap = SnmpTrapParser.Parse(fixture, now);
        if (trap is null) return (false, "trap fixture did not parse — refused");
        _alerts?.Raise(trap.AgentIp, $"trap:{trap.EnterpriseOid}:{trap.Generic}:{trap.Specific}",
            NetworkAlertKinds.SnmpTrap, AlertSeverities.Warning,
            $"SNMP trap enterprise={trap.EnterpriseOid} generic={trap.Generic} specific={trap.Specific} varbinds={trap.VarBinds.Count}",
            "rmm11-probe", TimeSpan.FromMinutes(30), now);
        _audit.Append("snmp_trap", "rmm11-probe",
            $"agent={trap.AgentIp} enterprise={trap.EnterpriseOid} generic={trap.Generic} specific={trap.Specific}", now);
        return (true, "trap recorded");
    }

    public (bool Ok, string Reason, int Hits) IngestSyslogLine(string line)
    {
        var now = _now();
        var message = SyslogParser.Parse(line);
        if (message is null) return (false, "syslog line did not parse — refused", 0);
        var hits = SyslogParser.MatchKeywords(message, _syslogRules);
        foreach (var (rule, msg) in hits)
            _alerts?.Raise(msg.Hostname ?? "syslog", $"syslog:{rule.Keyword}", NetworkAlertKinds.SyslogKeyword,
                rule.Severity, $"syslog keyword '{rule.Keyword}' from {msg.Hostname}: {msg.Message}",
                "rmm11-probe", TimeSpan.FromMinutes(30), now);
        return (true, "parsed", hits.Count);
    }

    public (bool Ok, string Reason, FlowSummary? Summary) IngestFlowDatagram(ReadOnlySpan<byte> datagram)
    {
        var summary = NetFlowV5Parser.Parse(datagram);
        if (summary is null) return (false, "flow datagram did not parse as NetFlow v5 — refused", null);
        lock (_gate) _lastFlowSummary = summary;
        return (true, "summarized", summary);
    }

    // ---- config backup ----------------------------------------------------

    /// <summary>One config-backup cycle over the register's network
    /// gear in this scope (switches/routers/firewalls filed as
    /// network-switch / bas-controller / other-with-IP — precisely:
    /// assets whose kind is network-switch). A fetch failure is a
    /// named per-device outcome, never a silent skip; a CHANGE
    /// raises config_changed into the centre + audit.</summary>
    public IReadOnlyList<(string AssetId, string Outcome, string Detail)> RunConfigBackupCycle()
    {
        var now = _now();
        var results = new List<(string, string, string)>();
        if (_configFetcher is null)
        {
            _audit.Append("config_backup_unavailable", "rmm11-probe",
                $"scope={_scopeId} reason=no config fetcher wired", now);
            return results;
        }
        if (!DiscoveryEnabled) return results;
        foreach (var asset in _register.List(_scopeId, UnmanagedAssetKinds.NetworkSwitch))
        {
            if (asset.IpAddress is null) { results.Add((asset.AssetId, "skipped", "no management address")); continue; }
            var (ok, content, error) = _configFetcher.Fetch(asset.AssetId, asset.IpAddress);
            if (!ok || content is null)
            {
                results.Add((asset.AssetId, "fetch_failed", error ?? "fetch failed"));
                _audit.Append("config_backup_failed", "rmm11-probe",
                    $"asset={asset.AssetId} reason={error}", now);
                continue;
            }
            var result = _configStore.Backup(asset.AssetId, content, $"rmm11:{_probeDeviceId}", now);
            results.Add((asset.AssetId, result.Outcome,
                result.Diff?.Summary ?? result.Outcome));
            if (result.Outcome == ConfigBackupResult.Changed && result.Diff is not null)
            {
                _alerts?.Raise(asset.AssetId, $"config:{asset.AssetId}", NetworkAlertKinds.ConfigChanged,
                    AlertSeverities.Warning,
                    $"config changed on {asset.AssetId}: {result.Diff.Summary}",
                    "rmm11-probe", TimeSpan.Zero, now);
                _audit.Append("config_changed", "rmm11-probe",
                    $"asset={asset.AssetId} version={result.Version?.Version} {result.Diff.Summary}", now);
            }
        }
        return results;
    }

    /// <summary>The topology model for this site (design renders
    /// it; this lane models it).</summary>
    public TopologyGraph BuildTopology(
        IEnumerable<(string FromId, string ToId, string Evidence)>? uplinkHints = null) =>
        TopologyGraph.Build(_probeDeviceId, $"probe {_probeDeviceId}", _census.Entries, uplinkHints);
}

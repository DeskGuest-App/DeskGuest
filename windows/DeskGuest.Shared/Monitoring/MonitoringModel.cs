using System.Text.Json;

namespace DeskGuest.Shared.Monitoring;

// =====================================================================
// RMM-01 — Continuous endpoint health monitoring + threshold alerting
// (ADOPTED 2026-11-20). MODEL LAYER: health samples, collectors behind
// interfaces, monitor conditions and their PURE on-endpoint evaluation.
//
// Doctrine carried from the register:
//   * ALL condition evaluation happens ON THE ENDPOINT. The hub never
//     re-evaluates raw samples; it ingests alert events + health
//     reports (MonitoringAlerts.cs) — the same shape as the existing
//     heartbeat/state channel.
//   * Collectors sit behind interfaces. Tests drive fakes; the Core's
//     runtime collector reads only what existing DeskGuest state machinery
//     can state honestly (drives, uptime, process names). Real
//     WMI/CIM CPU+RAM percentages, SMART detail, the Windows Event
//     Log and the Security Center (AV/firewall/encryption) readers
//     are WINDOWS-HOST WIRING — named remainders, never fabricated:
//     a reading the collector did not take is null, and a condition
//     over a null reading evaluates to NOT FIRING with the gap named
//     in the cycle result — never to a guessed value.
//   * Silence is never health. A missing reading, a dead collector
//     and a missing device report are three distinct, named states
//     (see MonitorHealth / DeviceDownDetector) — none of them reads
//     as "healthy".
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-01 and the actions it
/// can fire. The monitoring toggle itself is seeded in the RMM-07
/// registry (`rmm.monitoring.enabled`, default ON); the action keys
/// belong to RMM-12 / RMM-08 and are consulted here so an alert
/// action can never fire while its own feature is policy-disabled.</summary>
public static class MonitoringPolicyKeys
{
    public const string MonitoringEnabled = "rmm.monitoring.enabled";
    public const string WorkItemsEnabled = "rmm.work_items.enabled";
    public const string RemediationEnabled = "rmm.remediation.enabled";
}

/// <summary>Alert severities, ordered. The string form is what
/// travels in events and audit details.</summary>
public static class AlertSeverities
{
    public const string Info = "info";
    public const string Warning = "warning";
    public const string Critical = "critical";

    public static readonly IReadOnlySet<string> All = new HashSet<string> { Info, Warning, Critical };

    public static int Rank(string? severity) => severity switch
    {
        Critical => 3,
        Warning => 2,
        Info => 1,
        _ => 0,
    };
}

/// <summary>The closed set of condition kinds. A condition naming a
/// kind outside this set refuses at library admission — an unknown
/// kind is a field that changes meaning (house fail-closed rule).</summary>
public static class ConditionKinds
{
    public const string CpuHigh = "cpu_high";                       // CpuPercent >= ThresholdPercent
    public const string RamHigh = "ram_high";                       // RamPercent >= ThresholdPercent
    public const string DiskLow = "disk_low";                       // free % <= ThresholdPercent (Target = volume, "*" = any)
    public const string DiskSmartFailure = "disk_smart_failure";    // SMART status not OK (Target = volume, "*" = any)
    public const string DiskPredictiveFailure = "disk_predictive_failure"; // OS predictive-failure flag
    public const string ServiceStopped = "service_stopped";         // Target service not Running (incl. missing)
    public const string ProcessMissing = "process_missing";         // Target process absent
    public const string ProcessHighMemory = "process_high_memory";  // Target process bytes >= ThresholdBytes
    public const string AppMissing = "app_missing";                 // Target application not installed
    public const string AppNotRunning = "app_not_running";          // Target application installed but not running
    public const string EventLogMatch = "eventlog_match";           // Target = source, EventId set
    public const string SecurityAvOff = "security_av_off";
    public const string SecurityFirewallOff = "security_firewall_off";
    public const string SecurityEncryptionOff = "security_encryption_off";
    public const string UptimeExceeded = "uptime_exceeded";         // uptime >= ThresholdSeconds (reboot overdue)
    public const string GuestDown = "guest_down";                   // Target = guest id, "*" = any guest not Running
    public const string Warranty = "warranty";                      // consumed from RMM-04 events, never sample-evaluated
    public const string SerialConflict = "serial_conflict";         // consumed from RMM-04 events (D38-F5(d)), never sample-evaluated
    public const string DeviceDown = "device_down";                 // hub-side (silence), never sample-evaluated
    public const string MonitorFailure = "monitor_failure";         // the monitor's own collector/watchdog, never suppressed

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        CpuHigh, RamHigh, DiskLow, DiskSmartFailure, DiskPredictiveFailure,
        ServiceStopped, ProcessMissing, ProcessHighMemory, AppMissing, AppNotRunning,
        EventLogMatch, SecurityAvOff, SecurityFirewallOff, SecurityEncryptionOff,
        UptimeExceeded, GuestDown, Warranty, SerialConflict, DeviceDown, MonitorFailure,
    };

    /// <summary>Kinds whose alerts a maintenance window may NEVER
    /// suppress: the security state of the machine, the machine being
    /// down, the monitor itself, an expired warranty (a legal/
    /// contractual fact, not noise), and a duplicate-serial conflict
    /// (an inventory-integrity fact). Planned work does not make an
    /// unprotected machine protected, or a duplicated serial unique.</summary>
    public const string RansomwareIsolation = "ransomware_isolation"; // RMM-17 kind (EndpointSecurityAlertKinds.RansomwareIsolation)
    public const string BaselineDrift = "baseline_drift";             // RMM-19 kind (BaselineAlertKinds.Kind)

    public static readonly IReadOnlySet<string> NeverSuppressible = new HashSet<string>
    {
        SecurityAvOff, SecurityFirewallOff, SecurityEncryptionOff,
        DeviceDown, MonitorFailure, Warranty, SerialConflict,
        // RES-3 + RMM-19 remainder (closing integration, 2026-11-21):
        // a ransomware isolation event and a desired-state drift are
        // security/integrity facts, not noise — a maintenance window
        // must never suppress their NOTIFICATIONS. This set governs
        // notification suppression only; evaluations and audit are
        // unaffected (recorded semantics).
        RansomwareIsolation, BaselineDrift,
    };

    /// <summary>Kinds evaluated from endpoint samples. Warranty,
    /// serial-conflict, device-down and monitor-failure arrive
    /// through their own paths and are never produced by sample
    /// evaluation.</summary>
    public static bool IsSampleEvaluated(string kind) =>
        All.Contains(kind) && kind is not (Warranty or SerialConflict or DeviceDown or MonitorFailure);
}

/// <summary>Condition ids the SYSTEM itself raises under (the
/// monitor's own failure alert, the hub's device-down alert, and the
/// warranty / serial-conflict id families minted by the ingest paths
/// in MonitoringAlerts.cs). D38-F9: these share the alert centre's
/// (device, conditionId) dedup namespace with library condition ids,
/// so a library condition carrying one of them would absorb the
/// system's own alert as a "refresh" and take over its identity.
/// Library admission therefore RESERVES them (ConditionLibrary
/// .Validate); system raisers use these constants so the two sides
/// of the namespace can never drift apart.</summary>
public static class SystemAlertConditionIds
{
    public const string MonitorFailure = "monitor-failure";
    public const string DeviceDown = "device-down";
    public const string WarrantyPrefix = "warranty:";
    public const string SerialConflictPrefix = "serial-conflict:";

    public static bool IsReserved(string? conditionId) =>
        !string.IsNullOrWhiteSpace(conditionId) &&
        (string.Equals(conditionId, MonitorFailure, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(conditionId, DeviceDown, StringComparison.OrdinalIgnoreCase) ||
         conditionId.StartsWith(WarrantyPrefix, StringComparison.OrdinalIgnoreCase) ||
         conditionId.StartsWith(SerialConflictPrefix, StringComparison.OrdinalIgnoreCase));
}

// ---- samples -----------------------------------------------------------

public sealed record DiskSample(
    string Name,
    long FreeBytes,
    long TotalBytes,
    string? SmartStatus,          // "OK" | "Degraded" | "Failed" | null = not read
    bool? PredictiveFailure)      // null = not read
{
    public double? FreePercent =>
        TotalBytes > 0 ? FreeBytes * 100.0 / TotalBytes : null;
}

public sealed record ServiceSample(string Name, string State); // "Running" | "Stopped" | other OS state

public sealed record ProcessSample(string Name, long WorkingSetBytes, double? CpuPercent);

public sealed record AppSample(string Name, bool Installed, string? Version, bool? Running);

public sealed record EventLogSample(string Source, int EventId, string Level, DateTimeOffset AtUtc, string? Message);

public sealed record SecurityStateSample(bool? AvEnabled, bool? FirewallEnabled, bool? EncryptionEnabled);

public sealed record GuestSample(string GuestId, string State); // "Running" | "Stopped" | "Paused" | ...

/// <summary>One endpoint health sample: everything the collectors
/// observed at one instant. Every section is optional — a collector
/// that could not read a section leaves it null/empty and the gap is
/// visible in the sample itself (CollectorNotes names what was not
/// read and why), never papered over with invented values.</summary>
public sealed record EndpointSample(
    string DeviceId,
    DateTimeOffset AtUtc,
    double? CpuPercent,
    double? RamPercent,
    IReadOnlyList<DiskSample> Disks,
    IReadOnlyList<ServiceSample> Services,
    IReadOnlyList<ProcessSample> Processes,
    IReadOnlyList<AppSample> Applications,
    IReadOnlyList<EventLogSample> EventLog,
    SecurityStateSample? Security,
    TimeSpan? Uptime,
    IReadOnlyList<GuestSample> Guests,
    IReadOnlyList<string> CollectorNotes)
{
    public IReadOnlyList<DiskSample> Disks { get; init; } = Disks ?? Array.Empty<DiskSample>();
    public IReadOnlyList<ServiceSample> Services { get; init; } = Services ?? Array.Empty<ServiceSample>();
    public IReadOnlyList<ProcessSample> Processes { get; init; } = Processes ?? Array.Empty<ProcessSample>();
    public IReadOnlyList<AppSample> Applications { get; init; } = Applications ?? Array.Empty<AppSample>();
    public IReadOnlyList<EventLogSample> EventLog { get; init; } = EventLog ?? Array.Empty<EventLogSample>();
    public IReadOnlyList<GuestSample> Guests { get; init; } = Guests ?? Array.Empty<GuestSample>();
    public IReadOnlyList<string> CollectorNotes { get; init; } = CollectorNotes ?? Array.Empty<string>();

    /// <summary>An empty sample for a device at an instant — the
    /// honest shape a fully-failed collection produces (every reading
    /// absent). Conditions over it fire nothing; the monitor's
    /// watchdog treats repeated empties as monitor failure.</summary>
    public static EndpointSample Empty(string deviceId, DateTimeOffset atUtc, string note) => new(
        deviceId, atUtc, null, null,
        Array.Empty<DiskSample>(), Array.Empty<ServiceSample>(), Array.Empty<ProcessSample>(),
        Array.Empty<AppSample>(), Array.Empty<EventLogSample>(), null, null,
        Array.Empty<GuestSample>(), new[] { note });

    /// <summary>True when the sample carries NO readings at all —
    /// the watchdog's "collector produced nothing" signal.</summary>
    public bool IsEmpty =>
        CpuPercent is null && RamPercent is null && Disks.Count == 0 && Services.Count == 0 &&
        Processes.Count == 0 && Applications.Count == 0 && EventLog.Count == 0 &&
        Security is null && Uptime is null && Guests.Count == 0;
}

// ---- collectors --------------------------------------------------------

/// <summary>The collector contract. One call = one sample attempt.
/// Implementations must not fabricate: an unreadable section is
/// absent + a CollectorNote. Throwing is permitted — the monitor
/// treats a throw as a failed cycle (watchdog), never as health.</summary>
public interface IHealthCollector
{
    EndpointSample Collect(string deviceId, DateTimeOffset now);
}

/// <summary>Test double: a scripted sequence of samples (the last one
/// repeats), call-counted. A step may throw to simulate a dead
/// collector.</summary>
public sealed class FakeHealthCollector : IHealthCollector
{
    private readonly Queue<Func<EndpointSample>> _steps = new();
    private EndpointSample? _last;

    public int CallCount { get; private set; }

    public FakeHealthCollector(params EndpointSample[] samples)
    {
        foreach (var s in samples) _steps.Enqueue(() => s);
    }

    public FakeHealthCollector ThenThrow(Exception ex)
    {
        _steps.Enqueue(() => throw ex);
        return this;
    }

    public FakeHealthCollector Then(EndpointSample sample)
    {
        _steps.Enqueue(() => sample);
        return this;
    }

    public EndpointSample Collect(string deviceId, DateTimeOffset now)
    {
        CallCount++;
        if (_steps.Count > 0) _last = _steps.Dequeue()();
        if (_last is null) throw new InvalidOperationException("fake collector has no scripted sample");
        return _last;
    }
}

/// <summary>Composes section collectors into one sample. Each
/// section delegate may return null (not read); a throwing section
/// degrades to absent + a note naming the section — one dead section
/// never kills the whole sample, and never invents its data.</summary>
public sealed class CompositeHealthCollector : IHealthCollector
{
    public Func<DateTimeOffset, (double? Cpu, double? Ram)>? Resources { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<DiskSample>>? Disks { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<ServiceSample>>? Services { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<ProcessSample>>? Processes { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<AppSample>>? Applications { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<EventLogSample>>? EventLog { get; set; }
    public Func<DateTimeOffset, SecurityStateSample?>? Security { get; set; }
    public Func<DateTimeOffset, TimeSpan?>? Uptime { get; set; }
    public Func<DateTimeOffset, IReadOnlyList<GuestSample>>? Guests { get; set; }

    public EndpointSample Collect(string deviceId, DateTimeOffset now)
    {
        var notes = new List<string>();
        T? Section<T>(string name, Func<DateTimeOffset, T?>? fn) where T : class
        {
            if (fn is null) { notes.Add($"not_read:{name}"); return null; }
            try { return fn(now); }
            catch (Exception ex) { notes.Add($"collector_failed:{name}:{ex.GetType().Name}"); return null; }
        }

        (double? Cpu, double? Ram) res = (null, null);
        if (Resources is null) notes.Add("not_read:resources");
        else
        {
            try { res = Resources(now); }
            catch (Exception ex) { notes.Add($"collector_failed:resources:{ex.GetType().Name}"); }
        }

        TimeSpan? uptime;
        if (Uptime is null) { notes.Add("not_read:uptime"); uptime = null; }
        else uptime = SafeUptime(now, notes);

        return new EndpointSample(
            deviceId, now, res.Cpu, res.Ram,
            Section("disks", Disks) ?? Array.Empty<DiskSample>(),
            Section("services", Services) ?? Array.Empty<ServiceSample>(),
            Section("processes", Processes) ?? Array.Empty<ProcessSample>(),
            Section("applications", Applications) ?? Array.Empty<AppSample>(),
            Section("eventlog", EventLog) ?? Array.Empty<EventLogSample>(),
            Section("security", Security),
            uptime,
            Section("guests", Guests) ?? Array.Empty<GuestSample>(),
            notes);
    }

    private TimeSpan? SafeUptime(DateTimeOffset now, List<string> notes)
    {
        try { return Uptime!(now); }
        catch (Exception ex) { notes.Add($"collector_failed:uptime:{ex.GetType().Name}"); return null; }
    }
}

// ---- conditions --------------------------------------------------------

/// <summary>What an alert does when it first raises. Every action is
/// independently policy-gated at fire time (notify is the alert
/// centre itself; work items need RMM-12's toggle; remediation needs
/// RMM-08's toggle AND a named remediation id).</summary>
public sealed record AlertActions(bool Notify, bool OpenWorkItem, string? RemediationId)
{
    public static readonly AlertActions NotifyOnly = new(true, false, null);
    public bool WantsRemediation => !string.IsNullOrWhiteSpace(RemediationId);
}

/// <summary>One monitor condition: a tuned threshold over one kind of
/// reading. ConsecutiveSamples debounces (the condition must fire on
/// N consecutive samples before it alerts — the ConnectWise lesson:
/// signal quality is content). Cooldown bounds re-alerting after an
/// auto-reset. Targets are data: a service name, a volume, an event
/// source — the BAS template in the default library targets the site
/// JACE/vendor daemon service by name.</summary>
public sealed record MonitorCondition(
    string Id,
    string Name,
    string Kind,
    string? Target,
    int? EventId,
    double? ThresholdPercent,
    long? ThresholdBytes,
    long? ThresholdSeconds,
    string Severity,
    int ConsecutiveSamples,
    TimeSpan Cooldown,
    AlertActions Actions,
    bool Enabled,
    string Description)
{
    public static MonitorCondition Create(
        string id, string name, string kind, string severity = AlertSeverities.Warning,
        string? target = null, int? eventId = null,
        double? thresholdPercent = null, long? thresholdBytes = null, long? thresholdSeconds = null,
        int consecutiveSamples = 1, TimeSpan? cooldown = null,
        AlertActions? actions = null, bool enabled = true, string description = "") =>
        new(id, name, kind, target, eventId, thresholdPercent, thresholdBytes, thresholdSeconds,
            severity, Math.Max(1, consecutiveSamples), cooldown ?? TimeSpan.FromMinutes(30),
            actions ?? AlertActions.NotifyOnly, enabled, description);
}

/// <summary>The outcome of evaluating one condition against one
/// sample. Indeterminate (the reading the condition needs was not in
/// the sample) is a distinct state from both firing and clear: it
/// neither raises nor auto-resets an alert — a collector gap must
/// never clear a real alert, and never fabricate one.</summary>
public enum ConditionOutcome { Clear, Firing, Indeterminate }

public sealed record ConditionEvaluation(ConditionOutcome Outcome, string Detail);

public static class ConditionEvaluator
{
    /// <summary>Pure evaluation of one condition against one sample.
    /// No state, no clock beyond the sample's own timestamp.</summary>
    public static ConditionEvaluation Evaluate(MonitorCondition c, EndpointSample s)
    {
        ConditionEvaluation Fire(string d) => new(ConditionOutcome.Firing, d);
        ConditionEvaluation Clear(string d) => new(ConditionOutcome.Clear, d);
        ConditionEvaluation Gap(string d) => new(ConditionOutcome.Indeterminate, d);

        switch (c.Kind)
        {
            case ConditionKinds.CpuHigh:
                if (s.CpuPercent is not { } cpu) return Gap("cpu reading not collected");
                return cpu >= (c.ThresholdPercent ?? 90)
                    ? Fire($"cpu {cpu:F1}% >= {c.ThresholdPercent ?? 90}%")
                    : Clear($"cpu {cpu:F1}%");
            case ConditionKinds.RamHigh:
                if (s.RamPercent is not { } ram) return Gap("ram reading not collected");
                return ram >= (c.ThresholdPercent ?? 90)
                    ? Fire($"ram {ram:F1}% >= {c.ThresholdPercent ?? 90}%")
                    : Clear($"ram {ram:F1}%");
            case ConditionKinds.DiskLow:
            {
                var disks = MatchDisks(c, s);
                if (disks.Count == 0) return Gap($"no disk reading for target '{c.Target ?? "*"}'");
                var worst = disks.Where(d => d.FreePercent is not null)
                    .OrderBy(d => d.FreePercent).FirstOrDefault();
                if (worst is null) return Gap("disk sizes not readable");
                return worst.FreePercent <= (c.ThresholdPercent ?? 10)
                    ? Fire($"disk {worst.Name} free {worst.FreePercent:F1}% <= {c.ThresholdPercent ?? 10}%")
                    : Clear($"disk {worst.Name} free {worst.FreePercent:F1}%");
            }
            case ConditionKinds.DiskSmartFailure:
            {
                var disks = MatchDisks(c, s);
                if (disks.Count == 0) return Gap($"no disk reading for target '{c.Target ?? "*"}'");
                var read = disks.Where(d => d.SmartStatus is not null).ToList();
                if (read.Count == 0) return Gap("SMART status not read (host wiring)");
                var bad = read.FirstOrDefault(d =>
                    !string.Equals(d.SmartStatus, "OK", StringComparison.OrdinalIgnoreCase));
                return bad is not null
                    ? Fire($"disk {bad.Name} SMART status '{bad.SmartStatus}'")
                    : Clear("SMART OK on all read disks");
            }
            case ConditionKinds.DiskPredictiveFailure:
            {
                var disks = MatchDisks(c, s);
                if (disks.Count == 0) return Gap($"no disk reading for target '{c.Target ?? "*"}'");
                var read = disks.Where(d => d.PredictiveFailure is not null).ToList();
                if (read.Count == 0) return Gap("predictive-failure flag not read (host wiring)");
                var bad = read.FirstOrDefault(d => d.PredictiveFailure == true);
                return bad is not null
                    ? Fire($"disk {bad.Name} reports predictive failure")
                    : Clear("no predictive failure reported");
            }
            case ConditionKinds.ServiceStopped:
            {
                if (string.IsNullOrWhiteSpace(c.Target)) return Gap("service condition carries no target");
                var svc = s.Services.FirstOrDefault(x =>
                    string.Equals(x.Name, c.Target, StringComparison.OrdinalIgnoreCase));
                if (s.Services.Count == 0) return Gap("service list not collected");
                return svc is null
                    ? Fire($"service '{c.Target}' not present on this endpoint")
                    : string.Equals(svc.State, "Running", StringComparison.OrdinalIgnoreCase)
                        ? Clear($"service '{c.Target}' running")
                        : Fire($"service '{c.Target}' state '{svc.State}'");
            }
            case ConditionKinds.ProcessMissing:
            {
                if (string.IsNullOrWhiteSpace(c.Target)) return Gap("process condition carries no target");
                if (s.Processes.Count == 0) return Gap("process list not collected");
                return s.Processes.Any(p => string.Equals(p.Name, c.Target, StringComparison.OrdinalIgnoreCase))
                    ? Clear($"process '{c.Target}' present")
                    : Fire($"process '{c.Target}' not running");
            }
            case ConditionKinds.ProcessHighMemory:
            {
                if (string.IsNullOrWhiteSpace(c.Target)) return Gap("process condition carries no target");
                var proc = s.Processes.FirstOrDefault(p =>
                    string.Equals(p.Name, c.Target, StringComparison.OrdinalIgnoreCase));
                if (proc is null) return Gap($"process '{c.Target}' not in sample");
                var limit = c.ThresholdBytes ?? 2_147_483_648L;
                return proc.WorkingSetBytes >= limit
                    ? Fire($"process '{c.Target}' working set {proc.WorkingSetBytes} >= {limit}")
                    : Clear($"process '{c.Target}' working set {proc.WorkingSetBytes}");
            }
            case ConditionKinds.AppMissing:
            {
                if (string.IsNullOrWhiteSpace(c.Target)) return Gap("app condition carries no target");
                if (s.Applications.Count == 0) return Gap("application list not collected");
                var app = s.Applications.FirstOrDefault(a =>
                    string.Equals(a.Name, c.Target, StringComparison.OrdinalIgnoreCase));
                return app is { Installed: true }
                    ? Clear($"application '{c.Target}' installed")
                    : Fire($"application '{c.Target}' not installed");
            }
            case ConditionKinds.AppNotRunning:
            {
                if (string.IsNullOrWhiteSpace(c.Target)) return Gap("app condition carries no target");
                if (s.Applications.Count == 0) return Gap("application list not collected");
                var app = s.Applications.FirstOrDefault(a =>
                    string.Equals(a.Name, c.Target, StringComparison.OrdinalIgnoreCase));
                if (app is null || !app.Installed) return Gap($"application '{c.Target}' not installed (app_missing covers absence)");
                if (app.Running is not { } running) return Gap($"application '{c.Target}' running state not read");
                return running
                    ? Clear($"application '{c.Target}' running")
                    : Fire($"application '{c.Target}' installed but not running");
            }
            case ConditionKinds.EventLogMatch:
            {
                if (string.IsNullOrWhiteSpace(c.Target) || c.EventId is null)
                    return Gap("event-log condition needs a source and an event id");
                // D38-F1: an EMPTY event-log section is a section that
                // was not read (the sample model coerces null to empty,
                // and the runtime collector leaves this section unset),
                // exactly like the service/process/app sections above.
                // It must evaluate Indeterminate — returning Clear here
                // reported "no crashes" on every endpoint whose Event
                // Log was never read, and auto-reset real alerts on the
                // next blind cycle.
                if (s.EventLog.Count == 0)
                    return Gap("event log not collected (section absent — not read, or read with no entries in the sampled window)");
                var hit = s.EventLog.FirstOrDefault(e =>
                    string.Equals(e.Source, c.Target, StringComparison.OrdinalIgnoreCase) &&
                    e.EventId == c.EventId.Value);
                return hit is not null
                    ? Fire($"event log {c.Target}/{c.EventId} at {hit.AtUtc:O} level {hit.Level}")
                    : Clear($"no {c.Target}/{c.EventId} in sampled window");
            }
            case ConditionKinds.SecurityAvOff:
                if (s.Security?.AvEnabled is not { } av) return Gap("AV state not read (host wiring)");
                return av ? Clear("antivirus on") : Fire("antivirus is OFF");
            case ConditionKinds.SecurityFirewallOff:
                if (s.Security?.FirewallEnabled is not { } fw) return Gap("firewall state not read (host wiring)");
                return fw ? Clear("firewall on") : Fire("firewall is OFF");
            case ConditionKinds.SecurityEncryptionOff:
                if (s.Security?.EncryptionEnabled is not { } enc) return Gap("encryption state not read (host wiring)");
                return enc ? Clear("disk encryption on") : Fire("disk encryption is OFF");
            case ConditionKinds.UptimeExceeded:
                if (s.Uptime is not { } up) return Gap("uptime not collected");
                var limitSecs = c.ThresholdSeconds ?? 2_592_000; // 30 days
                return up.TotalSeconds >= limitSecs
                    ? Fire($"uptime {up.TotalDays:F1} days >= {limitSecs / 86400.0:F1} days")
                    : Clear($"uptime {up.TotalDays:F1} days");
            case ConditionKinds.GuestDown:
            {
                if (s.Guests.Count == 0) return Gap("no VM guest readings (not a host, or host wiring absent)");
                var guests = string.IsNullOrWhiteSpace(c.Target) || c.Target == "*"
                    ? s.Guests
                    : s.Guests.Where(g => string.Equals(g.GuestId, c.Target, StringComparison.OrdinalIgnoreCase)).ToList();
                if (guests.Count == 0) return Gap($"guest '{c.Target}' not in sample");
                var down = guests.FirstOrDefault(g =>
                    !string.Equals(g.State, "Running", StringComparison.OrdinalIgnoreCase));
                return down is not null
                    ? Fire($"guest '{down.GuestId}' state '{down.State}'")
                    : Clear("all sampled guests running");
            }
            default:
                // Warranty / device-down / monitor-failure and any
                // unknown kind never fire from a sample.
                return Gap($"kind '{c.Kind}' is not sample-evaluated");
        }
    }

    private static IReadOnlyList<DiskSample> MatchDisks(MonitorCondition c, EndpointSample s) =>
        string.IsNullOrWhiteSpace(c.Target) || c.Target == "*"
            ? s.Disks
            : s.Disks.Where(d => string.Equals(d.Name, c.Target, StringComparison.OrdinalIgnoreCase)).ToList();
}

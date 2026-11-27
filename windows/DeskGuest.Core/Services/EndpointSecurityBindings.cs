using System.Collections.Concurrent;
using DeskGuest.Shared.EndpointSecurity;
using Microsoft.Win32;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-17 host bindings (bd-win-core-3/F7 remainder, W9 closure):
// the Windows bindings behind EndpointSecurityService's three
// seams. Each binding is honest about its observation limits:
//   * FileSystemActivitySource — real FileSystemWatcher events
//     over the watched roots, entropy sampled from the file itself;
//     the producing PROCESS is not observable from a watcher and
//     is reported null, never invented.
//   * WindowsAvStatusSource — Defender posture from the service
//     state (OsTool sc.exe) + the Defender registry keys. When the
//     facts cannot be observed (non-Windows host, query failure),
//     the reading says so (SourceAlive=false, ClaimedState
//     "unknown") — the posture model's anti-lying shape reads that
//     as Unknown/Stale, never as healthy.
//   * WindowsEndpointNetworkControl — isolation via netsh
//     advfirewall rules named DeskGuest-ISOLATE-*: an allow rule per plan
//     exemption, then block-all in both directions. Off-Windows it
//     throws, and the isolation manager records isolation_failed —
//     the designed honest failure, never a pretend isolation.
// =====================================================================

/// <summary>File activity from real filesystem watchers. The queue
/// is bounded (drop-oldest, counted): a burst can never grow this
/// host's memory without limit, and the drop count is visible.</summary>
public sealed class FileSystemActivitySource : IFileActivitySource, IDisposable
{
    public const int MaxQueuedEvents = 8192;

    private readonly ConcurrentQueue<FileActivityEvent> _queue = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private int _queued;
    private long _dropped;

    public long DroppedCount => Interlocked.Read(ref _dropped);
    public int WatchedRootCount => _watchers.Count;

    public FileSystemActivitySource(IEnumerable<string> roots)
    {
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!Directory.Exists(root)) continue;
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                };
                watcher.Created += (_, e) => Enqueue(new FileActivityEvent(e.FullPath, FileActivityKinds.Created, null, null, null, DateTimeOffset.UtcNow));
                watcher.Changed += (_, e) => Enqueue(new FileActivityEvent(e.FullPath, FileActivityKinds.Modified, null, SampleEntropy(e.FullPath), null, DateTimeOffset.UtcNow));
                watcher.Renamed += (_, e) => Enqueue(new FileActivityEvent(e.FullPath, FileActivityKinds.Renamed, e.OldFullPath, SampleEntropy(e.FullPath), null, DateTimeOffset.UtcNow));
                watcher.Deleted += (_, e) => Enqueue(new FileActivityEvent(e.FullPath, FileActivityKinds.Deleted, null, null, null, DateTimeOffset.UtcNow));
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch { /* an unwatchable root watches nothing; the detector simply sees less, and WatchedRootCount says how much */ }
        }
    }

    private void Enqueue(FileActivityEvent ev)
    {
        if (Interlocked.Increment(ref _queued) > MaxQueuedEvents)
        {
            // Bounded: drop the OLDEST, count the drop.
            if (_queue.TryDequeue(out _)) Interlocked.Increment(ref _dropped);
            else Interlocked.Decrement(ref _queued);
        }
        _queue.Enqueue(ev);
    }

    /// <summary>Shannon entropy of the first 64 KB — the detector's
    /// entropy-surge signal reads the file's real bytes. An
    /// unreadable file (locked, gone) samples null: unknown, never
    /// a fabricated number.</summary>
    internal static double? SampleEntropy(string path)
    {
        try
        {
            var buffer = new byte[64 * 1024];
            int read;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                read = fs.Read(buffer, 0, buffer.Length);
            if (read == 0) return null;
            var counts = new int[256];
            for (var i = 0; i < read; i++) counts[buffer[i]]++;
            var entropy = 0.0;
            for (var i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                var p = (double)counts[i] / read;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
        catch { return null; }
    }

    public IReadOnlyList<FileActivityEvent> Drain()
    {
        var result = new List<FileActivityEvent>();
        while (_queue.TryDequeue(out var ev))
        {
            Interlocked.Decrement(ref _queued);
            result.Add(ev);
        }
        return result;
    }

    public void Dispose()
    {
        foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
        _watchers.Clear();
    }
}

/// <summary>Defender posture from observable Windows facts only.</summary>
public sealed class WindowsAvStatusSource : IAvStatusSource
{
    public const string DefenderProductId = "windows-defender";

    public IReadOnlyList<AvStatusReading> Read(DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows())
            return new[] { Unknown(now, "not a Windows host — Defender posture is unobservable here") };
        try
        {
            var (serviceOk, serviceOut) = OsTool.Run("sc.exe", new[] { "query", "WinDefend" });
            if (!serviceOk || !serviceOut.Contains("WINDEFEND", StringComparison.OrdinalIgnoreCase))
                return new[] { Unknown(now, "the WinDefend service query returned nothing readable") };
            var installed = !serviceOut.Contains("FAILED 1060", StringComparison.OrdinalIgnoreCase);
            var running = serviceOut.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
            var disabledByPolicy = RegistryDword(@"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware") == 1;
            var rtDisabled = RegistryDword(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring") == 1;
            var enabled = installed && running && !disabledByPolicy;
            DateTimeOffset? definitions = null;
            try
            {
                var defDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    @"Microsoft\Windows Defender\Definition Updates");
                if (Directory.Exists(defDir))
                {
                    var latest = Directory.EnumerateFiles(defDir, "*.vdm", SearchOption.AllDirectories)
                        .Select(f => (DateTimeOffset)File.GetLastWriteTimeUtc(f)).OrderByDescending(t => t).FirstOrDefault();
                    if (latest != default) definitions = latest;
                }
            }
            catch { /* definitions time unobservable — null says so */ }
            return new[]
            {
                new AvStatusReading(DefenderProductId, installed, enabled, enabled && !rtDisabled,
                    definitions, null, now, SourceAlive: true,
                    ClaimedState: enabled ? "healthy" : "disabled"),
            };
        }
        catch
        {
            return new[] { Unknown(now, "the Defender posture query faulted") };
        }
    }

    private static AvStatusReading Unknown(DateTimeOffset now, string why) =>
        new(DefenderProductId, false, false, false, null, null, now, SourceAlive: false, ClaimedState: "unknown");

    private static int? RegistryDword(string subKey, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: false);
            return key?.GetValue(valueName) as int?;
        }
        catch { return null; }
    }
}

/// <summary>Isolation actuation through the Windows firewall.
/// Rules are named DeskGuest-ISOLATE-* so reconcile + removal find
/// exactly DeskGuest's own rules and nothing else's.</summary>
public sealed class WindowsEndpointNetworkControl : IEndpointNetworkControl
{
    public const string RulePrefix = "DeskGuest-ISOLATE";

    private IsolationPlan? _appliedPlan;
    public bool IsIsolationApplied => _appliedPlan is not null;
    public IsolationPlan? AppliedPlan => _appliedPlan;

    public void ApplyIsolation(IsolationPlan plan)
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("endpoint network isolation actuates through the Windows firewall (netsh advfirewall) — this host is not Windows, so no isolation was applied");
        // Allow the DeskGuest channel exemptions FIRST, then block the
        // rest: at no instant is the device both unblocked and
        // without its management lifeline.
        foreach (var ex in plan.Exemptions)
        {
            if (string.IsNullOrWhiteSpace(ex.Host)) continue;
            RunNetsh("add", "rule", $"name={RulePrefix}-ALLOW-{ex.Kind}", "dir=out", "action=allow",
                $"remoteip={ex.Host}", $"remoteport={ex.Port}", "protocol=TCP");
        }
        RunNetsh("add", "rule", $"name={RulePrefix}-OUT", "dir=out", "action=block");
        RunNetsh("add", "rule", $"name={RulePrefix}-IN", "dir=in", "action=block");
        _appliedPlan = plan;
    }

    public void RemoveIsolation()
    {
        if (!OperatingSystem.IsWindows())
        {
            _appliedPlan = null;
            return;
        }
        // Delete by the DeskGuest-ISOLATE name family (netsh deletes by
        // exact name; the three shapes this binding creates).
        if (_appliedPlan is not null)
            foreach (var ex in _appliedPlan.Exemptions)
                TryNetsh("delete", "rule", $"name={RulePrefix}-ALLOW-{ex.Kind}");
        TryNetsh("delete", "rule", $"name={RulePrefix}-OUT");
        TryNetsh("delete", "rule", $"name={RulePrefix}-IN");
        _appliedPlan = null;
    }

    private static void RunNetsh(params string[] args)
    {
        var full = new List<string> { "advfirewall", "firewall" };
        full.AddRange(args);
        var (ok, output) = OsTool.Run("netsh.exe", full);
        if (!ok) throw new InvalidOperationException($"netsh advfirewall failed: {output.Trim()}");
    }

    private static void TryNetsh(params string[] args)
    {
        try { RunNetsh(args); } catch { /* removal is best-effort per rule; a missing rule is already removed */ }
    }
}

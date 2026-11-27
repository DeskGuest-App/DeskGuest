using System.Text.Json;
using DeskGuest.Shared.Hub;

namespace DeskGuest.Shared.Reporting;

// =====================================================================
// RMM-13 — Scheduled reports: a hub job that generates on schedule
// and delivers to USER-OWNED destinations only.
//
// Destination discipline (refused BY SHAPE at definition time — a
// refused destination is never stored, so it can never be sent to):
//   * local_path: an absolute path (or a UNC path to a non-cloud
//     host) — the report lands on storage the user owns.
//   * smtp: the ORG'S OWN mail server. Consumer/vendor mail relays
//     (Gmail, Outlook.com, Yahoo, iCloud, SES/SendGrid/Mailgun
//     class) are refused by suffix — a report destination that is a
//     vendor cloud wearing an SMTP costume is still a vendor cloud.
//     Loopback/link-local/metadata hosts refuse too.
//   * webhook: must pass the RMM-13 outbound guard in full.
// Delivery failures are records with states (pending → delivered |
// failed → dead), attempts counted, never silently dropped — the
// same shape as the webhook pump. NO live SMTP/file client ships in
// this file beyond a directory sink rooted at an admin-chosen path;
// SMTP delivery runs through ISmtpSink (host wiring / fakes).
// =====================================================================

public static class ReportDestinationKinds
{
    public const string LocalPath = "local_path";
    public const string Smtp = "smtp";
    public const string Webhook = "webhook";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { LocalPath, Smtp, Webhook };
}

public static class ReportDestinationGuard
{
    /// <summary>Host suffixes naming vendor-cloud / consumer mail
    /// and storage services. A scheduled-report destination resolving
    /// to one of these is a vendor cloud — refused by shape.</summary>
    private static readonly string[] VendorSuffixes =
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
        "yahoo.com", "ymail.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
        "amazonaws.com", "sendgrid.net", "mailgun.org", "sparkpostmail.com",
        "postmarkapp.com", "mandrillapp.com", "googleapis.com", "blob.core.windows.net",
        "dropbox.com", "box.com", "drive.google.com",
        // D38-F5: Azure Files / queue / table live under the same
        // core.windows.net suffix as blob — listing blob alone
        // admitted \\acct.file.core.windows.net\share.
        "core.windows.net",
        // Microsoft 365 / Exchange Online mail is a vendor cloud,
        // not the org's own SMTP.
        "office365.com",
    };

    /// <summary>D38-F5: extract the HOST from a UNC locator,
    /// handling the shapes the raw split got wrong: the extended
    /// prefixes \\?\UNC\host\share, \\?\host\share and
    /// \\.\host\share, and WebDAV suffixes (\\host@SSL\DavWWWRoot,
    /// \\host@443\share) where everything from '@' on is not part
    /// of the host.</summary>
    public static string ParseUncHost(string loc)
    {
        var rest = (loc ?? "").Trim();
        if (rest.StartsWith(@"\\", StringComparison.Ordinal)) rest = rest[2..];
        if (rest.StartsWith(@"?\", StringComparison.Ordinal) || rest.StartsWith(@".\", StringComparison.Ordinal))
        {
            rest = rest[2..];
            if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase)) rest = rest[4..];
        }
        var host = rest.Split('\\', '/')[0];
        var at = host.IndexOf('@');
        if (at >= 0) host = host[..at];
        return host.Trim().TrimEnd('.');
    }

    public static bool IsVendorHost(string host)
    {
        var h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        return VendorSuffixes.Any(s => h == s || h.EndsWith("." + s, StringComparison.Ordinal));
    }

    /// <summary>Validate one destination locator for its kind. Null
    /// when admissible; otherwise the refusal reason.</summary>
    public static string? Validate(string? kind, string? locator)
    {
        var k = (kind ?? "").Trim().ToLowerInvariant();
        if (!ReportDestinationKinds.All.Contains(k))
            return $"unknown report destination kind '{kind}' — refused (destinations are local_path, smtp, webhook — user-owned only)";
        var loc = (locator ?? "").Trim();
        if (loc.Length == 0) return "report destination locator is empty — refused";
        switch (k)
        {
            case ReportDestinationKinds.LocalPath:
            {
                foreach (var scheme in new[] { "http://", "https://", "s3://", "gs://", "az://", "ftp://" })
                    if (loc.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                        return $"local_path destination '{loc}' is a remote-object URL — REFUSED: scheduled reports deliver to user-owned destinations only";
                if (loc.StartsWith(@"\\", StringComparison.Ordinal))
                {
                    var host = ParseUncHost(loc);
                    if (host.Length == 0)
                        return "local_path UNC destination names no host — refused";
                    if (IsVendorHost(host))
                        return $"local_path destination host '{host}' is a vendor-cloud endpoint dressed as a share — REFUSED";
                    if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
                        return "local_path UNC destination host is localhost — refused";
                    if (System.Net.IPAddress.TryParse(host, out var uncIp) && !WebhookTargetGuard.IsAdmissible(uncIp))
                        return $"local_path UNC destination host '{host}' is a loopback/link-local/metadata address — refused";
                    return null;
                }
                if (Backup.BackupStorageTarget.IsAbsolutePathShape(loc)) return null;
                return $"local_path destination '{loc}' is not an absolute path — refused";
            }
            case ReportDestinationKinds.Smtp:
            {
                // locator shape: host[:port] or user@host — the host is what is judged.
                var host = loc;
                var at = host.LastIndexOf('@');
                if (at >= 0) host = host[(at + 1)..];
                var colon = host.LastIndexOf(':');
                if (colon > 0 && int.TryParse(host[(colon + 1)..], out _)) host = host[..colon];
                host = host.Trim().TrimEnd('.');
                if (host.Length == 0) return "smtp destination names no host — refused";
                if (IsVendorHost(host))
                    return $"smtp destination host '{host}' is a vendor/consumer mail service — REFUSED: scheduled reports deliver via the org's own SMTP only";
                if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
                    return "smtp destination host is localhost — refused";
                if (System.Net.IPAddress.TryParse(host, out var ip) && !WebhookTargetGuard.IsAdmissible(ip))
                    return $"smtp destination host '{host}' is a loopback/link-local/metadata address — refused";
                return null;
            }
            case ReportDestinationKinds.Webhook:
                return WebhookTargetGuard.ValidateTarget(loc);
            default:
                return $"unknown report destination kind '{kind}' — refused";
        }
    }
}

/// <summary>One scheduled-report destination.</summary>
public sealed record ReportDestination(string Kind, string Locator)
{
    public string? Validate() => ReportDestinationGuard.Validate(Kind, Locator);
}

/// <summary>One scheduled report definition: which report, in which
/// format, how often, to where. Interval-based like RMM-06's
/// schedules: due when the last generation is at least
/// IntervalHours old (or never happened).</summary>
public sealed record ScheduledReportDefinition(
    string Id, string ReportKind, string Format, int IntervalHours,
    ReportDestination Destination, bool Enabled, string DefinedBy,
    string ScopeId = "")
{
    public bool IsDue(DateTimeOffset? lastGeneratedUtc, DateTimeOffset now) =>
        lastGeneratedUtc is null || now - lastGeneratedUtc.Value >= TimeSpan.FromHours(Math.Max(1, IntervalHours));

    /// <summary>Admission check for a definition. Null when
    /// admissible; otherwise the refusal (unknown kind/format,
    /// non-positive interval, or a destination the guard refuses).</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id)) return "scheduled report needs an id — refused";
        if (!ReportKinds.All.Contains(ReportKind ?? "")) return $"scheduled report '{Id}' names unknown report kind '{ReportKind}' — refused";
        if (!ReportExportFormats.All.Contains((Format ?? "").Trim().ToLowerInvariant()))
            return $"scheduled report '{Id}' names unknown format '{Format}' — refused (formats are json, csv, text)";
        if (IntervalHours < 1) return $"scheduled report '{Id}' interval must be at least 1 hour — refused";
        if (string.IsNullOrWhiteSpace(DefinedBy)) return $"scheduled report '{Id}' needs a defining admin — refused";
        if (Destination is null) return "scheduled report carries no destination — refused";
        return Destination.Validate();
    }
}

public static class ScheduledDeliveryStates
{
    public const string Delivered = "delivered";
    public const string Failed = "failed";
    public const string Dead = "dead";
}

/// <summary>One generation+delivery attempt's record. Failures are
/// states on records — a scheduled report that could not be
/// delivered is visible here forever, never a silent gap in the
/// schedule.</summary>
public sealed record ScheduledDelivery(
    string DeliveryId, string DefinitionId, string ReportId, string State,
    int Attempts, string? LastError, DateTimeOffset GeneratedUtc, DateTimeOffset? DeliveredUtc)
{
    public const int MaxAttempts = 3;
}

/// <summary>The delivery sink contract: one method per destination
/// kind the sink supports; unsupported kinds return a named failure.
/// Host wiring supplies SMTP; tests use the recording fake.</summary>
public interface IReportDeliverySink
{
    (bool Ok, string Detail) Deliver(ReportDestination destination, string fileName, string content);
}

/// <summary>Recording test double + in-memory sink (house pattern).</summary>
public sealed class RecordingReportSink : IReportDeliverySink
{
    public List<(ReportDestination Destination, string FileName, string Content)> Sent { get; } = new();
    public (bool Ok, string Detail) Result { get; set; } = (true, "recorded (test double)");
    public (bool Ok, string Detail) Deliver(ReportDestination destination, string fileName, string content)
    {
        Sent.Add((destination, fileName, content));
        return Result;
    }
}

/// <summary>Directory sink for local_path destinations: writes the
/// rendered report under the destination path (which the guard has
/// already admitted as an absolute, user-owned path). Writes are
/// temp+replace so a reader never sees a half-written report.</summary>
public sealed class DirectoryReportSink : IReportDeliverySink
{
    public (bool Ok, string Detail) Deliver(ReportDestination destination, string fileName, string content)
    {
        if (destination.Kind != ReportDestinationKinds.LocalPath)
            return (false, $"directory sink cannot deliver to kind '{destination.Kind}' — a host-wired sink is required for that kind");
        try
        {
            Directory.CreateDirectory(destination.Locator);
            var safe = string.Concat(fileName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
            var full = Path.Combine(destination.Locator, safe);
            var tmp = full + ".tmp";
            File.WriteAllText(tmp, content);
            File.Move(tmp, full, overwrite: true);
            return (true, $"written to {full}");
        }
        catch (Exception ex) { return (false, $"write failed: {ex.GetType().Name}: {ex.Message}"); }
    }
}

/// <summary>The scheduler: definitions + last-run state + delivery
/// records. RunDue generates each due, enabled definition through
/// the caller's report factory and delivers through the sink;
/// a failed delivery retries on the next pass up to the attempt
/// cap, then pronounces DEAD — visibly.</summary>
public sealed class ScheduledReportRunner
{
    /// <summary>W3 host wiring: raised after every committed
    /// state mutation (define/remove/run/import) so CoreRuntime
    /// can write the runner state through to disk.</summary>
    public event Action? Changed;
    private readonly Dictionary<string, ScheduledReportDefinition> _defs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _lastGenerated = new(StringComparer.Ordinal);
    private readonly List<ScheduledDelivery> _deliveries = new();
    private readonly Dictionary<string, (ScheduledDelivery Pending, string Content, string FileName)> _retry = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public IReadOnlyList<ScheduledReportDefinition> Definitions
    {
        get { lock (_gate) return _defs.Values.OrderBy(d => d.Id, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<ScheduledDelivery> Deliveries
    {
        get { lock (_gate) return _deliveries.ToList(); }
    }

    public (bool Ok, string Reason) Define(ScheduledReportDefinition? def)
    {
        if (def is null) return (false, "no scheduled report definition presented — refused");
        if (def.Validate() is { } refusal) return (false, refusal);
        lock (_gate) _defs[def.Id] = def;
        Changed?.Invoke();
        return (true, $"scheduled report '{def.Id}' defined ({def.ReportKind}/{def.Format} every {def.IntervalHours}h → {def.Destination.Kind})");
    }

    public bool Remove(string definitionId)
    {
        bool removed;
        lock (_gate) { _retry.Remove(definitionId ?? ""); removed = _defs.Remove(definitionId ?? ""); }
        if (removed) Changed?.Invoke();
        return removed;
    }

    public DateTimeOffset? LastGenerated(string definitionId)
    {
        lock (_gate) return _lastGenerated.TryGetValue(definitionId ?? "", out var t) ? t : null;
    }

    // ---- durability (BD-SHARED-RMM-3/F12) --------------------------
    // Last-generated + retry state were in-memory only: a restart
    // re-fired every due report and dropped pending retries. They
    // now round-trip through the HubPersistence envelope (definitions
    // themselves are configuration and persist with the host's
    // config, not here). Retry CONTENT is persisted with the record —
    // a retry that loses its content could only fail dishonestly.

    private sealed record RetryDto(ScheduledDelivery Pending, string Content, string FileName);
    private sealed record RunnerStateDto(
        Dictionary<string, DateTimeOffset> LastGenerated,
        Dictionary<string, RetryDto> Retry);

    public string ExportStateJson()
    {
        lock (_gate)
        {
            var dto = new RunnerStateDto(
                new Dictionary<string, DateTimeOffset>(_lastGenerated),
                _retry.ToDictionary(kv => kv.Key,
                    kv => new RetryDto(kv.Value.Pending, kv.Value.Content, kv.Value.FileName), StringComparer.Ordinal));
            return HubPersistence.Wrap("deskguest-scheduled-reports-state-v1", JsonSerializer.Serialize(dto));
        }
    }

    /// <summary>Restore last-generated + retry state. Returns false
    /// (and changes nothing) on an envelope/parse failure.</summary>
    public bool ImportStateJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "deskguest-scheduled-reports-state-v1");
        if (payload is null) return false;
        RunnerStateDto? dto;
        try { dto = JsonSerializer.Deserialize<RunnerStateDto>(payload); } catch { return false; }
        if (dto is null) return false;
        lock (_gate)
        {
            _lastGenerated.Clear();
            foreach (var (k, v) in dto.LastGenerated ?? new Dictionary<string, DateTimeOffset>()) _lastGenerated[k] = v;
            _retry.Clear();
            foreach (var (k, v) in dto.Retry ?? new Dictionary<string, RetryDto>()) _retry[k] = (v.Pending, v.Content, v.FileName);
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>One scheduler pass. The factory renders the report
    /// (returning report id + content); a factory refusal is a
    /// FAILED delivery record, not an exception and not silence.</summary>
    /// <summary>D38-F11: terminal scheduled-delivery records are
    /// pruned beyond this count (newest kept).</summary>
    public const int MaxTerminalDeliveriesKept = 500;

    public IReadOnlyList<ScheduledDelivery> RunDue(
        Func<ScheduledReportDefinition, DateTimeOffset, (string? ReportId, string? Content, string? Error)> factory,
        IReportDeliverySink sink, DateTimeOffset now,
        Func<ScheduledReportDefinition, bool>? filter = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(sink);
        var results = new List<ScheduledDelivery>();
        List<ScheduledReportDefinition> defs;
        // D38-F8: an optional scope filter — the service runs only
        // the calling scope's own definitions, never every
        // definition under one caller's facts.
        lock (_gate) defs = _defs.Values.Where(d => d.Enabled && (filter is null || filter(d))).ToList();
        foreach (var def in defs)
        {
            // Retry a pending failed delivery before generating anew.
            (ScheduledDelivery Pending, string Content, string FileName) retry;
            bool hasRetry;
            lock (_gate) hasRetry = _retry.TryGetValue(def.Id, out retry);
            if (hasRetry)
            {
                results.Add(Attempt(def, retry.Pending, retry.Content, retry.FileName, sink, now));
                continue;
            }
            DateTimeOffset? last;
            lock (_gate) last = _lastGenerated.TryGetValue(def.Id, out var lg) ? lg : null;
            if (!def.IsDue(last, now)) continue;

            var (reportId, content, error) = factory(def, now);
            lock (_gate) _lastGenerated[def.Id] = now;
            if (content is null)
            {
                var failed = new ScheduledDelivery(NewId(def.Id, now), def.Id, reportId ?? "(none)",
                    ScheduledDeliveryStates.Failed, 1, error ?? "report factory produced nothing", now, null);
                lock (_gate) _deliveries.Add(failed);
                results.Add(failed);
                continue;
            }
            var ext = def.Format.Trim().ToLowerInvariant() == ReportExportFormats.Text ? "txt" : def.Format.Trim().ToLowerInvariant();
            var fileName = $"{def.ReportKind}-{now:yyyyMMdd-HHmmss}.{ext}";
            var fresh = new ScheduledDelivery(NewId(def.Id, now), def.Id, reportId!, "", 0, null, now, null);
            results.Add(Attempt(def, fresh, content, fileName, sink, now));
        }
        lock (_gate)
        {
            // Prune terminal records beyond the kept count (newest
            // kept); failed records still awaiting retry are kept.
            var terminal = 0;
            for (var i = _deliveries.Count - 1; i >= 0; i--)
            {
                if (_deliveries[i].State is not (ScheduledDeliveryStates.Delivered or ScheduledDeliveryStates.Dead)) continue;
                terminal++;
                if (terminal > MaxTerminalDeliveriesKept) _deliveries.RemoveAt(i);
            }
        }
        if (results.Count > 0) Changed?.Invoke();
        return results;
    }

    private ScheduledDelivery Attempt(ScheduledReportDefinition def, ScheduledDelivery prior,
        string content, string fileName, IReportDeliverySink sink, DateTimeOffset now)
    {
        var (ok, detail) = sink.Deliver(def.Destination, fileName, content);
        var attempts = prior.Attempts + 1;
        ScheduledDelivery next;
        if (ok)
        {
            next = prior with { State = ScheduledDeliveryStates.Delivered, Attempts = attempts, LastError = null, DeliveredUtc = now };
            lock (_gate) { _retry.Remove(def.Id); _deliveries.Add(next); }
        }
        else if (attempts >= ScheduledDelivery.MaxAttempts)
        {
            next = prior with { State = ScheduledDeliveryStates.Dead, Attempts = attempts, LastError = detail };
            lock (_gate) { _retry.Remove(def.Id); _deliveries.Add(next); }
        }
        else
        {
            next = prior with { State = ScheduledDeliveryStates.Failed, Attempts = attempts, LastError = detail };
            lock (_gate) { _retry[def.Id] = (next, content, fileName); _deliveries.Add(next); }
        }
        return next;
    }

    private static string NewId(string defId, DateTimeOffset now) =>
        "sch-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{defId}|{now:O}|{Guid.NewGuid():N}")))[..20].ToLowerInvariant();
}

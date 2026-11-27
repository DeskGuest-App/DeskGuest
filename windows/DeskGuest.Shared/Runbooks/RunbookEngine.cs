using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Audit;

namespace DeskGuest.Shared.Runbooks;

// =====================================================================
// RMM-20 — execution records + the check evaluator contract.
//
// The execution record is the run's evidence: every step's outcome,
// every attestation (who/when), every approval, every check result,
// every recorded skip. It is built to be RECONSTRUCTABLE and
// TAMPER-EVIDENT:
//   * each step record carries a running chain hash over the
//     record's canonical form (the ChainedAuditLog discipline,
//     applied to the record itself);
//   * the service anchors the final chain hash in the chained audit
//     log at every pause and at completion, so a rewritten record
//     disagrees with the audit chain and verification says so
//     (RunbookService.VerifyExecutionRecord);
//   * a check result starts UNKNOWN (CheckPassed = null) and a UI
//     must render null as "not yet known" — never as passed (the
//     RMM-08 ConditionCleared rule, carried here).
//
// Checks are evaluated through IRunbookCheckEvaluator: the agent /
// host observes the fact. Tests drive the recording fake; the
// shipped host evaluator fails every check BY NAME (host wiring
// pending) — a check that cannot be observed FAILS, it never
// silently passes.
// =====================================================================

public static class RunbookRunStatuses
{
    public const string Running = "running";
    public const string PausedAwaitingAttestation = "paused_awaiting_attestation";
    public const string PausedAwaitingApproval = "paused_awaiting_approval";
    public const string HaltedCheckFailed = "halted_check_failed";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string PartialFailure = "partial_failure";
    public const string AbortedPolicyDisabled = "aborted_policy_disabled";

    public static bool IsTerminal(string? s) =>
        s is Succeeded or Failed or PartialFailure or AbortedPolicyDisabled;
    public static bool IsPaused(string? s) =>
        s is PausedAwaitingAttestation or PausedAwaitingApproval or HaltedCheckFailed;
}

public static class RunbookStepStates
{
    public const string Pending = "pending";
    public const string AwaitingAttestation = "awaiting_attestation";
    public const string AwaitingApproval = "awaiting_approval";
    public const string Done = "done";
    public const string Failed = "failed";
    public const string CheckFailed = "check_failed";
    public const string Skipped = "skipped";
}

/// <summary>One check observation. Observed is the fact as seen
/// (bounded + redacted by the runner before it is recorded).</summary>
public sealed record CheckRunResult(bool Passed, string Observed)
{
    public static CheckRunResult Pass(string observed) => new(true, observed);
    public static CheckRunResult Fail(string observed) => new(false, observed);
}

/// <summary>The check evaluator contract: observe ONE check step's
/// fact on the device. Implementations are host wiring (service /
/// process / disk / file / socket probes); tests drive the fake.</summary>
public interface IRunbookCheckEvaluator
{
    CheckRunResult Evaluate(RunbookStep step, string runId, string deviceId);
}

/// <summary>Recording + scripted test double, keyed by step id; an
/// unscripted check PASSES with a named observation (test default,
/// stated here so no reader mistakes it for host behaviour). A hook
/// lets a test act during a check (kill-switch race, re-check after
/// a halt).</summary>
public sealed class RecordingRunbookCheckEvaluator : IRunbookCheckEvaluator
{
    public List<string> Calls { get; } = new();
    public Dictionary<string, CheckRunResult> Results { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, Action> Hooks { get; } = new(StringComparer.Ordinal);

    public CheckRunResult Evaluate(RunbookStep step, string runId, string deviceId)
    {
        Calls.Add(step.Id);
        if (Hooks.TryGetValue(step.Id, out var hook)) hook();
        return Results.TryGetValue(step.Id, out var r)
            ? r : CheckRunResult.Pass($"ok:{step.Id} (test default)");
    }
}

/// <summary>The honest shipped evaluator: host check probes are not
/// wired in this build, so every check FAILS BY NAME and no action
/// is implied — a runbook halts at its first check rather than
/// sailing through on an unobserved "pass". Retained for hosts that
/// cannot observe checks at all; hosts that can use
/// <see cref="LocalRunbookCheckEvaluator"/> (BD-SHARED-RMM-3/F2).</summary>
public sealed class HostWiringRunbookCheckEvaluator : IRunbookCheckEvaluator
{
    public CheckRunResult Evaluate(RunbookStep step, string runId, string deviceId) =>
        CheckRunResult.Fail(
            $"host wiring pending: check kind '{step.CheckKind}' is observed on the device host — not wired in this build; the check is recorded FAILED, never assumed passed");
}

/// <summary>BD-SHARED-RMM-3/F2: the REAL local check evaluator for
/// the five closed check kinds. Every probe observes the fact on
/// THIS host and any inability to observe FAILS BY NAME — the
/// fail-closed discipline of the host-wiring stub, with real
/// observations where the platform offers them:
///   * process_running — Process.GetProcessesByName;
///   * disk_free_percent — DriveInfo on the target's root;
///   * file_exists — File/Directory.Exists;
///   * tcp_port_listening — a bounded TCP connect (2s);
///   * service_running — `sc.exe query` on Windows (exit 0 +
///     RUNNING state); on any other platform it fails by name,
///     because no portable service API exists in this layer.</summary>
public sealed class LocalRunbookCheckEvaluator : IRunbookCheckEvaluator
{
    public CheckRunResult Evaluate(RunbookStep step, string runId, string deviceId)
    {
        try
        {
            return step.CheckKind switch
            {
                RunbookCheckKinds.ProcessRunning => CheckProcess(step),
                RunbookCheckKinds.DiskFreePercent => CheckDisk(step),
                RunbookCheckKinds.FileExists => CheckFile(step),
                RunbookCheckKinds.TcpPortListening => CheckTcp(step),
                RunbookCheckKinds.ServiceRunning => CheckService(step),
                _ => CheckRunResult.Fail($"unknown check kind '{step.CheckKind}' — failed by name, never assumed passed"),
            };
        }
        catch (Exception ex)
        {
            return CheckRunResult.Fail($"check '{step.CheckKind}' could not be observed ({ex.GetType().Name}) — failed by name, never assumed passed");
        }
    }

    private static CheckRunResult CheckProcess(RunbookStep step)
    {
        var name = (step.CheckTarget ?? "").Trim();
        if (name.Length == 0) return CheckRunResult.Fail("process_running check carries no process name");
        var found = System.Diagnostics.Process.GetProcessesByName(name);
        return found.Length > 0
            ? CheckRunResult.Pass($"process '{name}' running ({found.Length} instance(s))")
            : CheckRunResult.Fail($"process '{name}' is not running");
    }

    private static CheckRunResult CheckDisk(RunbookStep step)
    {
        if (!double.TryParse(step.CheckArgument, System.Globalization.NumberStyles.Number,
                System.Globalization.CultureInfo.InvariantCulture, out var minPercent))
            return CheckRunResult.Fail($"disk_free_percent check argument '{step.CheckArgument}' is not a percent");
        var root = System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(step.CheckTarget ?? "."));
        var drive = new System.IO.DriveInfo(root!);
        if (!drive.IsReady) return CheckRunResult.Fail($"drive '{root}' is not ready");
        var freePercent = 100.0 * drive.AvailableFreeSpace / drive.TotalSize;
        return freePercent >= minPercent
            ? CheckRunResult.Pass($"drive '{root}' free {freePercent:F1}% >= {minPercent}%")
            : CheckRunResult.Fail($"drive '{root}' free {freePercent:F1}% < {minPercent}%");
    }

    private static CheckRunResult CheckFile(RunbookStep step)
    {
        var path = step.CheckTarget ?? "";
        return System.IO.File.Exists(path) || System.IO.Directory.Exists(path)
            ? CheckRunResult.Pass($"'{path}' exists")
            : CheckRunResult.Fail($"'{path}' does not exist");
    }

    private static CheckRunResult CheckTcp(RunbookStep step)
    {
        if (!int.TryParse(step.CheckArgument, out var port) || port < 1 || port > 65535)
            return CheckRunResult.Fail($"tcp_port_listening check argument '{step.CheckArgument}' is not a port");
        var host = string.IsNullOrWhiteSpace(step.CheckTarget) ? "127.0.0.1" : step.CheckTarget.Trim();
        using var client = new System.Net.Sockets.TcpClient();
        var connect = client.ConnectAsync(host, port);
        if (!connect.Wait(TimeSpan.FromSeconds(2)) || !client.Connected)
            return CheckRunResult.Fail($"nothing listening on {host}:{port} (bounded 2s connect)");
        return CheckRunResult.Pass($"{host}:{port} accepts a TCP connection");
    }

    private static CheckRunResult CheckService(RunbookStep step)
    {
        var name = (step.CheckTarget ?? "").Trim();
        if (name.Length == 0) return CheckRunResult.Fail("service_running check carries no service name");
        if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                System.Runtime.InteropServices.OSPlatform.Windows))
            return CheckRunResult.Fail("service_running is observed via sc.exe on Windows hosts — this host cannot observe it, failed by name");
        var psi = new System.Diagnostics.ProcessStartInfo("sc.exe", "query \"" + name + "\"")
        {
            RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
        };
        using var proc = System.Diagnostics.Process.Start(psi)!;
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(5000);
        return output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase)
            ? CheckRunResult.Pass($"service '{name}' is RUNNING (sc.exe query)")
            : CheckRunResult.Fail($"service '{name}' is not RUNNING (sc.exe query)");
    }
}

/// <summary>One step's recorded execution. Attestation and approval
/// fields are set only through RunbookService's gated paths —
/// AttestedBy is the AUTHENTICATED actor the service was called by
/// (the same seam discipline as JobStateReport: identity comes from
/// the caller's authenticated session, never from runbook content).
/// RecordHash chains this record to the previous one.</summary>
public sealed record RunbookStepRecord(
    string StepId,
    string Kind,
    string State,
    int Attempts,
    string Output,
    string? Error,
    bool? CheckPassed,
    string? CheckObserved,
    string? AttestedBy,
    DateTimeOffset? AttestedUtc,
    string? ApprovedBy,
    DateTimeOffset? ApprovedUtc,
    string? SkippedBy,
    string? SkipReason,
    DateTimeOffset? SkippedUtc,
    string? InnerExecutionId,
    string RecordHash)
{
    /// <summary>Check result for display: null is "not yet known"
    /// (the RMM-08 honesty rule) — never rendered as passed.</summary>
    public string CheckResultText => CheckPassed switch
    {
        true => "passed",
        false => "failed",
        null => "not yet known",
    };

    public static RunbookStepRecord Pending(RunbookStep step, string prevHash) =>
        Seal(new RunbookStepRecord(step.Id, step.Kind, RunbookStepStates.Pending, 0,
            "", null, null, null, null, null, null, null, null, null, null, null, ""), prevHash);

    /// <summary>The canonical string the chain hash covers. Every
    /// evidence field is in it: rewriting any outcome, attestation,
    /// approval or skip after the fact changes the hash.</summary>
    public string Canonical(string prevHash) =>
        string.Join("|", prevHash, StepId, Kind, State, Attempts, Output, Error ?? "",
            CheckPassed?.ToString() ?? "unknown", CheckObserved ?? "",
            AttestedBy ?? "", AttestedUtc?.ToString("O") ?? "",
            ApprovedBy ?? "", ApprovedUtc?.ToString("O") ?? "",
            SkippedBy ?? "", SkipReason ?? "", SkippedUtc?.ToString("O") ?? "",
            InnerExecutionId ?? "");

    public static string HashOf(RunbookStepRecord r, string prevHash) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(r.Canonical(prevHash)))).ToLowerInvariant();

    /// <summary>Re-seal a mutated record into the chain at its
    /// position. Only the service calls this, at the moment it
    /// records the mutation, cascading to later records (their
    /// hashes cover this one). Tamper evidence does not rest on
    /// the chain alone: the service anchors the head hash in the
    /// chained audit log at every pause/decision/completion, so a
    /// record rewritten AFTER anchoring — even with its chain
    /// recomputed — disagrees with the anchor.</summary>
    public static RunbookStepRecord Seal(RunbookStepRecord r, string prevHash) =>
        r with { RecordHash = HashOf(r, prevHash) };
}

/// <summary>The full record of one runbook run. The definition is
/// PINNED: DefinitionHash + the service-held snapshot are the
/// version the run started with; the library may move on, the run
/// does not. WorkItemId links the run to an RMM-12 work item BY ID
/// (the work item's own record stays in its store).</summary>
public sealed record RunbookExecution(
    string RunId,
    string RunbookId,
    string LibraryId,
    long LibraryRevision,
    string DefinitionHash,
    string DeviceId,
    string InitiatedBy,
    string? WorkItemId,
    DateTimeOffset StartedUtc,
    DateTimeOffset? FinishedUtc,
    string Status,
    string? CurrentStepId,
    IReadOnlyList<RunbookStepRecord> Steps,
    string? JobId,
    int ResumeCount)
{
    public IReadOnlyList<RunbookStepRecord> Steps { get; init; } =
        Steps ?? Array.Empty<RunbookStepRecord>();
    public bool IsTerminal => RunbookRunStatuses.IsTerminal(Status);

    /// <summary>The record's head hash: the last step's chain hash,
    /// or the run's genesis hash when no step has been sealed yet.</summary>
    public string RecordHeadHash => Steps.Count == 0 ? GenesisHash : Steps[^1].RecordHash;
    public const string GenesisHash = "GENESIS";

    /// <summary>D38 F2: the canonical run-level header the audit
    /// anchor covers, IN ADDITION to the step-chain head. Status,
    /// initiator, definition pin, finish time, work-item link and
    /// current step are evidence too: rewriting any of them (e.g.
    /// partial_failure → succeeded) changes this hash, so an anchor
    /// comparison over the header makes run-level tampering
    /// detectable — the head hash alone never covered it.</summary>
    public string CanonicalHeader() =>
        string.Join("|", RunId, RunbookId, LibraryId, LibraryRevision, DefinitionHash,
            DeviceId, InitiatedBy, WorkItemId ?? "", StartedUtc.ToString("O"),
            FinishedUtc?.ToString("O") ?? "", Status, CurrentStepId ?? "",
            JobId ?? "", ResumeCount, RecordHeadHash);

    public string HeaderHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalHeader()))).ToLowerInvariant();

    /// <summary>Recompute the whole step chain. False ⇒ some step
    /// record was rewritten after sealing.</summary>
    public bool VerifyStepChain()
    {
        var prev = GenesisHash;
        foreach (var s in Steps)
        {
            if (RunbookStepRecord.HashOf(s, prev) != s.RecordHash) return false;
            prev = s.RecordHash;
        }
        return true;
    }
}

/// <summary>Capture observed/output text into evidence form:
/// redacted + bounded with the truncation named (the RMM-08 rule).</summary>
public static class RunbookCapture
{
    public const int MaxChars = 4_096;
    public static string Capture(string? raw)
    {
        var redacted = Redactor.RedactText(raw ?? "");
        return redacted.Length <= MaxChars
            ? redacted
            : redacted[..MaxChars] + $"…[truncated {redacted.Length - MaxChars} chars]";
    }
}

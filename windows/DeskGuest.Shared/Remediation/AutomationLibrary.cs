using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Remediation;

// =====================================================================
// RMM-08 — Auto-remediation engine: trigger → action, self-healing
// under policy. MODEL LAYER: the shared, versioned AUTOMATION
// LIBRARY and the bounded step vocabulary its definitions are
// written in.
//
// Doctrine carried from the register + the lane assignment:
//   * The library is hub-stored, versioned, SIGNED content. It
//     travels inside an RMM-03 signed-command envelope (class
//     policy_delivery, like RMM-01's condition library and RMM-07's
//     policy documents) and is verified BEFORE parsing; an unsigned,
//     altered or malformed library refuses WHOLE — a partially
//     applied automation set would silently un-link whatever the
//     tamper removed, and could silently ADD a hostile action.
//   * Steps are a CLOSED SET of typed steps with explicit semantics
//     (RemediationStepKinds). Honest naming (D38-F11): run_script IS
//     arbitrary code by definition — it is not dressed up as
//     anything else. Its containment is exactly: the body exists
//     ONLY as signed library content, it executes agent-side only
//     after the execution's own RMM-03 automation envelope verifies
//     (RemediationEngine.cs), its length is bounded at admission,
//     and policy can raise its definition to requires_approval.
//   * Conditionals, loops and chaining are expressed IN the step
//     model, bounded: a step's guard (When) is one of a closed set;
//     chaining is explicit next-step ids on success/failure; a step
//     may be re-entered (a loop) only up to its MaxExecutions, and
//     the engine enforces a global step-execution cap per run. An
//     unbounded loop is not expressible — admission refuses a step
//     whose MaxExecutions is outside 1..MaxStepExecutionsCap.
//   * Approval tiers are part of the definition (auto /
//     requires_approval) and are INHERITED FROM POLICY at dispatch:
//     policy may raise a tier (auto → requires_approval) but can
//     NEVER lower one (RemediationService.EffectiveTier) — a policy
//     "downgrade" of a human-gated action is exactly the game the
//     destruction pass attacks.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-08. The global toggle
/// is the registry-seeded `rmm.remediation.enabled` (RMM-07); the
/// per-action keys are computed from the action id at dispatch —
/// they are policy SETTINGS, read through the same Effective Policy
/// engine, never a second store.</summary>
public static class RemediationPolicyKeys
{
    public const string RemediationEnabled = "rmm.remediation.enabled";

    /// <summary>Per-action enable setting: "false" disables this one
    /// action for the device even while the engine is on.</summary>
    public static string ActionEnabled(string remediationId) =>
        $"rmm.remediation.{NormalizeId(remediationId)}.enabled";

    /// <summary>Per-action tier setting: "auto" | "requires_approval".
    /// Effective tier is the MORE restrictive of library and policy
    /// (see RemediationTiers.Combine) — this setting can only ever
    /// raise an action to requires_approval.</summary>
    public static string ActionTier(string remediationId) =>
        $"rmm.remediation.{NormalizeId(remediationId)}.tier";

    public static string NormalizeId(string? id) => (id ?? "").Trim().ToLowerInvariant();
}

/// <summary>Approval tiers for remediation actions. An action whose
/// effective tier is RequiresApproval NEVER runs from a trigger
/// alone: dispatch parks a pending approval against the alert, and
/// only a recorded human decision executes it.</summary>
public static class RemediationTiers
{
    public const string Auto = "auto";
    public const string RequiresApproval = "requires_approval";

    public static readonly IReadOnlySet<string> All = new HashSet<string> { Auto, RequiresApproval };

    /// <summary>The more restrictive of two tiers. An unknown tier
    /// value combines to RequiresApproval (fail closed: a tier
    /// nobody recognises is a tier that needs a human).</summary>
    public static string Combine(string? a, string? b)
    {
        if (a == RequiresApproval || b == RequiresApproval) return RequiresApproval;
        if (a == Auto && b == Auto) return Auto;
        if (a == Auto && b is null) return Auto;
        if (b == Auto && a is null) return Auto;
        if (a is null && b is null) return Auto;
        return RequiresApproval;
    }
}

/// <summary>The closed step vocabulary. A definition naming a kind
/// outside this set refuses at library admission — an unknown kind
/// is a field that changes meaning (house fail-closed rule).</summary>
public static class RemediationStepKinds
{
    public const string RestartService = "restart_service";   // Target = service name
    public const string StartService = "start_service";       // Target = service name
    public const string StopService = "stop_service";         // Target = service name
    public const string KillProcess = "kill_process";         // Target = process name
    public const string ClearPath = "clear_path";             // Target = path; Argument = min age hours (optional)
    public const string RunScript = "run_script";             // ScriptBody = signed script content
    public const string RerunPatch = "rerun_patch";           // Target = patch catalogue entry id
    public const string UninstallApp = "uninstall_app";       // Target = application name
    public const string Wait = "wait";                        // Argument = seconds, bounded

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        RestartService, StartService, StopService, KillProcess, ClearPath,
        RunScript, RerunPatch, UninstallApp, Wait,
    };

    /// <summary>Kinds that require a Target at admission.</summary>
    public static bool RequiresTarget(string kind) => kind is
        RestartService or StartService or StopService or KillProcess or
        ClearPath or RerunPatch or UninstallApp;

    /// <summary>Default re-run safety for a kind, used when a step
    /// does not state idempotency explicitly in canonical JSON:
    /// service restarts/starts, path clears, waits and patch re-runs
    /// are safe to repeat; stops, kills and uninstalls are NOT
    /// assumed safe — the journal parks them rather than guess.</summary>
    public static bool DefaultIdempotent(string kind) => kind is
        RestartService or StartService or ClearPath or RerunPatch or Wait;
}

/// <summary>Step guards (the conditional vocabulary). Evaluated by
/// the engine against the PREVIOUS executed step's result.</summary>
public static class StepGuards
{
    public const string Always = "always";
    public const string IfPreviousSucceeded = "if_previous_succeeded";
    public const string IfPreviousFailed = "if_previous_failed";
    public const string IfOutputContains = "if_output_contains"; // GuardArgument = needle

    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Always, IfPreviousSucceeded, IfPreviousFailed, IfOutputContains };
}

/// <summary>What a step does when it fails. Stop ends the run
/// (remaining steps are recorded skipped — never silently dropped);
/// Continue records the failure and moves on, and the run's outcome
/// is partial_failure, never succeeded.</summary>
public static class StepFailureModes
{
    public const string Stop = "stop";
    public const string Continue = "continue";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Stop, Continue };
}

/// <summary>Named bounds for automation-library admission and for a
/// single execution. Every bound refuses by name at admission or
/// stops the run by name at execution — none is a hidden constant
/// an author discovers by hanging the engine.</summary>
public static class AutomationLimits
{
    public const int MaxDefinitions = 256;
    public const int MaxStepsPerDefinition = 50;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    public const int MaxTargetLength = 512;
    public const int MaxScriptBodyChars = 16_384;
    /// <summary>D38-F11: every free-text field is bounded at
    /// admission — an unbounded Argument/GuardArgument/Description
    /// is an unbounded payload inside signed content.</summary>
    public const int MaxArgumentLength = 4_096;
    public const int MaxGuardArgumentLength = 512;
    public const int MaxDescriptionLength = 1_024;
    /// <summary>Per-step re-entry cap: the loop bound. A step may be
    /// executed at most this many times in one run.</summary>
    public const int MaxStepExecutionsCap = 20;
    /// <summary>Global per-run step-execution cap: even a library of
    /// mutually-chaining steps terminates.</summary>
    public const int MaxTotalStepExecutions = 100;
    /// <summary>Per-step captured-output cap (chars, after
    /// redaction). Output beyond it is truncated WITH a marker —
    /// captured output is evidence, and evidence is bounded.</summary>
    public const int MaxOutputChars = 4_096;
    public const int MaxWaitSeconds = 600;
    public static readonly TimeSpan MaxCooldown = TimeSpan.FromHours(24);
    public const int MaxRunsPerWindowCap = 100;
    public static readonly TimeSpan MaxWindow = TimeSpan.FromDays(7);
}

/// <summary>One typed step in an automation definition.
/// NextOnSuccess / NextOnFailure are the chaining vocabulary: null
/// means "the next step in list order" (on success) or "apply
/// OnFailure" (on failure); an explicit id jumps — including
/// backwards, which is how loops are written, bounded by
/// MaxExecutions (this step) and the engine's global cap.</summary>
public sealed record RemediationStep(
    string Id,
    string Kind,
    string? Target,
    string? Argument,
    string? ScriptBody,
    string When,
    string? GuardArgument,
    string OnFailure,
    string? NextOnSuccess,
    string? NextOnFailure,
    int MaxExecutions,
    bool Idempotent)
{
    public static RemediationStep Create(
        string id, string kind, string? target = null, string? argument = null,
        string? scriptBody = null, string when = StepGuards.Always, string? guardArgument = null,
        string onFailure = StepFailureModes.Stop, string? nextOnSuccess = null,
        string? nextOnFailure = null, int maxExecutions = 1, bool? idempotent = null) =>
        new(id, kind, target, argument, scriptBody, when, guardArgument, onFailure,
            nextOnSuccess, nextOnFailure, Math.Max(1, maxExecutions),
            idempotent ?? RemediationStepKinds.DefaultIdempotent(kind));
}

/// <summary>One automation definition: a named, tiered, loop-guarded
/// action a monitoring condition can link to by id (the remediation
/// id RMM-01's AlertActions carries IS this id).</summary>
public sealed record AutomationDefinition(
    string Id,
    string Name,
    string Description,
    string ApprovalTier,
    TimeSpan Cooldown,
    int MaxRunsPerWindow,
    TimeSpan Window,
    bool Enabled,
    IReadOnlyList<RemediationStep> Steps)
{
    public IReadOnlyList<RemediationStep> Steps { get; init; } = Steps ?? Array.Empty<RemediationStep>();

    public static AutomationDefinition Create(
        string id, string name, IReadOnlyList<RemediationStep> steps,
        string tier = RemediationTiers.Auto, TimeSpan? cooldown = null,
        int maxRunsPerWindow = 3, TimeSpan? window = null,
        bool enabled = true, string description = "") =>
        new(id, name, description, tier,
            cooldown ?? TimeSpan.FromMinutes(30), maxRunsPerWindow,
            window ?? TimeSpan.FromHours(1), enabled, steps);
}

/// <summary>A versioned set of automation definitions — the shared
/// automation library stored on the hub. Revision is monotonic per
/// library Id: a stale or same-revision-conflicting re-delivery
/// refuses (the management-policy discipline, applied to automation
/// content).</summary>
public sealed record AutomationLibrary(
    string Id,
    long Revision,
    IReadOnlyList<AutomationDefinition> Definitions)
{
    public IReadOnlyList<AutomationDefinition> Definitions { get; init; } =
        Definitions ?? Array.Empty<AutomationDefinition>();

    public AutomationDefinition? Get(string remediationId) =>
        Definitions.FirstOrDefault(d =>
            string.Equals(d.Id, remediationId ?? "", StringComparison.OrdinalIgnoreCase));

    /// <summary>Deterministic canonical JSON — the exact bytes the
    /// RMM-03 envelope payload carries and hashes. Definitions and
    /// steps are emitted in authored order (step order is semantics);
    /// definitions are sorted by id so two serializations of the
    /// same library are byte-identical.</summary>
    public string ToCanonicalJson()
    {
        var defs = Definitions.OrderBy(d => d.Id, StringComparer.Ordinal).Select(d => new
        {
            id = d.Id, name = d.Name, description = d.Description, tier = d.ApprovalTier,
            cooldownSeconds = d.Cooldown.TotalSeconds, maxRunsPerWindow = d.MaxRunsPerWindow,
            windowSeconds = d.Window.TotalSeconds, enabled = d.Enabled,
            steps = d.Steps.Select(s => new
            {
                id = s.Id, kind = s.Kind, target = s.Target, argument = s.Argument,
                scriptBody = s.ScriptBody, when = s.When, guardArgument = s.GuardArgument,
                onFailure = s.OnFailure, nextOnSuccess = s.NextOnSuccess,
                nextOnFailure = s.NextOnFailure, maxExecutions = s.MaxExecutions,
                idempotent = s.Idempotent,
            }).ToList(),
        }).ToList();
        return JsonSerializer.Serialize(new { id = Id, revision = Revision, definitions = defs });
    }

    /// <summary>SHA-256 of the canonical JSON — the content identity
    /// audit events and execution bindings carry.</summary>
    public string ContentHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()))).ToLowerInvariant();

    public static AutomationLibrary? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var defs = new List<AutomationDefinition>();
            foreach (var el in root.GetProperty("definitions").EnumerateArray())
            {
                var steps = new List<RemediationStep>();
                foreach (var s in el.GetProperty("steps").EnumerateArray())
                {
                    steps.Add(new RemediationStep(
                        s.GetProperty("id").GetString() ?? "",
                        s.GetProperty("kind").GetString() ?? "",
                        OptString(s, "target"), OptString(s, "argument"), OptString(s, "scriptBody"),
                        OptString(s, "when") ?? StepGuards.Always, OptString(s, "guardArgument"),
                        OptString(s, "onFailure") ?? StepFailureModes.Stop,
                        OptString(s, "nextOnSuccess"), OptString(s, "nextOnFailure"),
                        s.GetProperty("maxExecutions").GetInt32(),
                        s.GetProperty("idempotent").GetBoolean()));
                }
                defs.Add(new AutomationDefinition(
                    el.GetProperty("id").GetString() ?? "",
                    el.GetProperty("name").GetString() ?? "",
                    OptString(el, "description") ?? "",
                    el.GetProperty("tier").GetString() ?? "",
                    TimeSpan.FromSeconds(el.GetProperty("cooldownSeconds").GetDouble()),
                    el.GetProperty("maxRunsPerWindow").GetInt32(),
                    TimeSpan.FromSeconds(el.GetProperty("windowSeconds").GetDouble()),
                    el.GetProperty("enabled").GetBoolean(),
                    steps));
            }
            return new AutomationLibrary(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("revision").GetInt64(),
                defs);
        }
        catch { return null; }
    }

    private static string? OptString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Admission validation. Null when admissible;
    /// otherwise the refusal reason naming the first defect. A
    /// refused library changes NOTHING — the previously admitted
    /// library (or the built-in default) stays in force.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > AutomationLimits.MaxIdLength)
            return "automation library needs an id within bounds — refused";
        if (Id.IndexOfAny(IdForbiddenChars) >= 0)
            return $"automation library '{Id}': library id contains a separator or control character — refused";
        if (Revision < 1)
            return $"automation library '{Id}' revision {Revision} is not positive — refused";
        if (Definitions.Count > AutomationLimits.MaxDefinitions)
            return $"automation library '{Id}' carries {Definitions.Count} definitions over the cap {AutomationLimits.MaxDefinitions} — refused";
        var seenDefs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in Definitions)
        {
            if (string.IsNullOrWhiteSpace(d.Id) || d.Id.Length > AutomationLimits.MaxIdLength)
                return $"automation library '{Id}': a definition id is empty or over bounds — refused";
            if (!seenDefs.Add(d.Id))
                return $"automation library '{Id}': duplicate definition id '{d.Id}' — refused";
            if (string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > AutomationLimits.MaxNameLength)
                return $"automation '{d.Id}': name empty or over bounds — refused";
            if ((d.Description?.Length ?? 0) > AutomationLimits.MaxDescriptionLength)
                return $"automation '{d.Id}': description over the {AutomationLimits.MaxDescriptionLength}-char bound — refused";
            // D38-F12: ids enter length-prefixed bindings, but a
            // separator-bearing id is still a smell — refuse ids
            // containing '|' or control characters outright.
            if (d.Id.IndexOfAny(IdForbiddenChars) >= 0)
                return $"automation '{d.Id}': definition id contains a separator or control character — refused";
            if (!RemediationTiers.All.Contains(d.ApprovalTier ?? ""))
                return $"automation '{d.Id}': unknown approval tier '{d.ApprovalTier}' — refused";
            // D38-F11: high-impact kinds — arbitrary code
            // (run_script), process kills and software removal —
            // never ship at tier auto. A definition containing one
            // must be requires_approval, so a human gates every
            // execution; an author who wants auto must use the
            // bounded kinds.
            if (d.ApprovalTier == RemediationTiers.Auto &&
                d.Steps.Any(s => s.Kind is RemediationStepKinds.RunScript
                    or RemediationStepKinds.KillProcess or RemediationStepKinds.UninstallApp))
                return $"automation '{d.Id}': carries a high-impact step kind (run_script / kill_process / uninstall_app) at tier 'auto' — refused (high-impact kinds require the requires_approval tier)";
            if (d.Cooldown < TimeSpan.Zero || d.Cooldown > AutomationLimits.MaxCooldown)
                return $"automation '{d.Id}': cooldown {d.Cooldown} outside 0–{AutomationLimits.MaxCooldown} — refused";
            if (d.MaxRunsPerWindow < 1 || d.MaxRunsPerWindow > AutomationLimits.MaxRunsPerWindowCap)
                return $"automation '{d.Id}': max-runs-per-window {d.MaxRunsPerWindow} outside 1–{AutomationLimits.MaxRunsPerWindowCap} — refused (loop safety is not optional)";
            if (d.Window <= TimeSpan.Zero || d.Window > AutomationLimits.MaxWindow)
                return $"automation '{d.Id}': run window {d.Window} outside (0, {AutomationLimits.MaxWindow}] — refused";
            if (d.Steps.Count == 0)
                return $"automation '{d.Id}': carries no steps — refused (an action that does nothing is a false promise)";
            if (d.Steps.Count > AutomationLimits.MaxStepsPerDefinition)
                return $"automation '{d.Id}': {d.Steps.Count} steps over the cap {AutomationLimits.MaxStepsPerDefinition} — refused";
            var stepIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in d.Steps)
            {
                if (string.IsNullOrWhiteSpace(s.Id) || s.Id.Length > AutomationLimits.MaxIdLength)
                    return $"automation '{d.Id}': a step id is empty or over bounds — refused";
                if (!stepIds.Add(s.Id))
                    return $"automation '{d.Id}': duplicate step id '{s.Id}' — refused";
                if (!RemediationStepKinds.All.Contains(s.Kind ?? ""))
                    return $"automation '{d.Id}' step '{s.Id}': unknown step kind '{s.Kind}' — refused (the step vocabulary is a closed set; arbitrary code is not a step kind)";
                if (RemediationStepKinds.RequiresTarget(s.Kind) && string.IsNullOrWhiteSpace(s.Target))
                    return $"automation '{d.Id}' step '{s.Id}': kind '{s.Kind}' requires a target — refused";
                if (s.Id.IndexOfAny(IdForbiddenChars) >= 0)
                    return $"automation '{d.Id}' step '{s.Id}': step id contains a separator or control character — refused";
                if (s.Target is { Length: > AutomationLimits.MaxTargetLength })
                    return $"automation '{d.Id}' step '{s.Id}': target over bounds — refused";
                if ((s.Argument?.Length ?? 0) > AutomationLimits.MaxArgumentLength)
                    return $"automation '{d.Id}' step '{s.Id}': argument over the {AutomationLimits.MaxArgumentLength}-char bound — refused";
                if ((s.GuardArgument?.Length ?? 0) > AutomationLimits.MaxGuardArgumentLength)
                    return $"automation '{d.Id}' step '{s.Id}': guard argument over the {AutomationLimits.MaxGuardArgumentLength}-char bound — refused";
                // D38-F11: clear_path against a drive root or a
                // protected system root is not a remediation, it is
                // destruction — refused at admission by name.
                if (s.Kind == RemediationStepKinds.ClearPath && IsProtectedClearTarget(s.Target))
                    return $"automation '{d.Id}' step '{s.Id}': clear_path target '{s.Target}' is a drive root or protected system root — refused";
                if (s.Kind == RemediationStepKinds.RunScript)
                {
                    if (string.IsNullOrWhiteSpace(s.ScriptBody))
                        return $"automation '{d.Id}' step '{s.Id}': run_script carries no script body — refused";
                    if (s.ScriptBody.Length > AutomationLimits.MaxScriptBodyChars)
                        return $"automation '{d.Id}' step '{s.Id}': script body over the {AutomationLimits.MaxScriptBodyChars}-char bound — refused";
                }
                else if (!string.IsNullOrWhiteSpace(s.ScriptBody))
                {
                    return $"automation '{d.Id}' step '{s.Id}': a script body on a non-script step ('{s.Kind}') — refused (script content rides only run_script steps, where it is signed and gated)";
                }
                if (!StepGuards.All.Contains(s.When ?? ""))
                    return $"automation '{d.Id}' step '{s.Id}': unknown guard '{s.When}' — refused";
                if (s.When == StepGuards.IfOutputContains && string.IsNullOrWhiteSpace(s.GuardArgument))
                    return $"automation '{d.Id}' step '{s.Id}': if_output_contains guard carries no needle — refused";
                if (!StepFailureModes.All.Contains(s.OnFailure ?? ""))
                    return $"automation '{d.Id}' step '{s.Id}': unknown on-failure mode '{s.OnFailure}' — refused";
                if (s.MaxExecutions < 1 || s.MaxExecutions > AutomationLimits.MaxStepExecutionsCap)
                    return $"automation '{d.Id}' step '{s.Id}': max-executions {s.MaxExecutions} outside 1–{AutomationLimits.MaxStepExecutionsCap} — refused (loops are bounded or they are not admitted)";
                if (s.Kind == RemediationStepKinds.Wait &&
                    (!int.TryParse(s.Argument, out var secs) || secs < 0 || secs > AutomationLimits.MaxWaitSeconds))
                    return $"automation '{d.Id}' step '{s.Id}': wait argument must be seconds within 0–{AutomationLimits.MaxWaitSeconds} — refused";
                // BD-SHARED-RMM-2/F9: clear_path's Argument (minimum age
                // in hours) is validated like wait's — an unparseable or
                // unbounded age silently meant "delete everything".
                if (s.Kind == RemediationStepKinds.ClearPath && !string.IsNullOrWhiteSpace(s.Argument) &&
                    (!int.TryParse(s.Argument, out var ageHours) || ageHours < 0 || ageHours > 24 * 366))
                    return $"automation '{d.Id}' step '{s.Id}': clear_path argument must be a minimum age in hours within 0–{24 * 366} — refused";
            }
            foreach (var s in d.Steps)
            {
                if (s.NextOnSuccess is not null && !stepIds.Contains(s.NextOnSuccess))
                    return $"automation '{d.Id}' step '{s.Id}': chains on success to unknown step '{s.NextOnSuccess}' — refused";
                if (s.NextOnFailure is not null && !stepIds.Contains(s.NextOnFailure))
                    return $"automation '{d.Id}' step '{s.Id}': chains on failure to unknown step '{s.NextOnFailure}' — refused";
            }
        }
        return null;
    }

    private static readonly char[] IdForbiddenChars = new[] { '|' }
        .Concat(Enumerable.Range(0, 32).Select(i => (char)i)).ToArray();

    /// <summary>D38-F11: clear_path targets that are never a
    /// legitimate remediation: a drive root, or the Windows /
    /// System32 roots themselves (their SUBpaths, e.g.
    /// C:\Windows\Temp, remain admissible).</summary>
    private static bool IsProtectedClearTarget(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        var t = target.Trim().Replace('/', '\\');
        // BD-SHARED-RMM-2/F9: canonicalise BEFORE judging. The old
        // suffix check passed %SystemRoot%, \\?\C:\Windows,
        // C:\Windows\., C:\Windows\System32\.., C:\Users,
        // C:\Program Files and every UNC root.
        if (t.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            t.StartsWith("\\\\.\\", StringComparison.Ordinal))
            return true; // device-namespace forms are never a clear target
        if (t.StartsWith("\\\\", StringComparison.Ordinal))
            return true; // UNC roots/shares are never a clear target
        t = ExpandKnownEnvVars(t);
        // Collapse "." and ".." segments lexically (no filesystem touch):
        var drive = "";
        var rest = t;
        if (rest.Length >= 2 && rest[1] == ':' && char.IsLetter(rest[0])) { drive = rest[..2]; rest = rest[2..]; }
        var segments = new List<string>();
        foreach (var seg in rest.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg == ".") continue;
            if (seg == "..") { if (segments.Count > 0) segments.RemoveAt(segments.Count - 1); continue; }
            segments.Add(seg);
        }
        if (segments.Count == 0) return true; // a drive root (or bare \) itself
        var first = segments[0].ToLowerInvariant();
        if (first is "windows" or "users" or "program files" or "program files (x86)" or "programdata")
            return segments.Count == 1 || (first == "windows" && segments.Count == 2 &&
                segments[1].Equals("system32", StringComparison.OrdinalIgnoreCase));
        return false;
    }

    /// <summary>Expand the environment forms a clear_path target can
    /// carry (the default library itself relies on %TEMP% being
    /// expanded later — expansion here is for JUDGING the target,
    /// the executor still expands at run time). Unknown variables
    /// stay literal, and a target still containing one after the
    /// known set is judged on its literal segments.</summary>
    private static string ExpandKnownEnvVars(string t)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["%SystemRoot%"] = @"C:\Windows", ["%windir%"] = @"C:\Windows",
            ["%SystemDrive%"] = "C:", ["%ProgramFiles%"] = @"C:\Program Files",
            ["%ProgramFiles(x86)%"] = @"C:\Program Files (x86)",
            ["%ProgramData%"] = @"C:\ProgramData", ["%UserProfile%"] = @"C:\Users\User",
            ["%TEMP%"] = @"C:\Users\User\AppData\Local\Temp", ["%TMP%"] = @"C:\Users\User\AppData\Local\Temp",
        };
        foreach (var (k, v) in map) t = t.Replace(k, v, StringComparison.OrdinalIgnoreCase);
        return t;
    }

    /// <summary>The built-in starter library (code-seeded, part of
    /// the signed agent binary — the register's examples as data).
    /// The BAS service definition ships DISABLED with the template
    /// service name, for the same reason RMM-01's BAS condition
    /// does: the real service name is site fact, never guessed.</summary>
    public static AutomationLibrary Default() => new("deskguest-default-automation", 1, new[]
    {
        AutomationDefinition.Create("clear-disk-temp", "Clear temporary files",
            new[]
            {
                RemediationStep.Create("clear-user-temp", RemediationStepKinds.ClearPath, target: "%TEMP%"),
                RemediationStep.Create("clear-windows-temp", RemediationStepKinds.ClearPath, target: @"C:\Windows\Temp"),
            },
            description: "Clears user and Windows temp paths — the disk_low companion fix."),
        AutomationDefinition.Create("restart-print-spooler", "Restart print spooler",
            new[]
            {
                RemediationStep.Create("restart-spooler", RemediationStepKinds.RestartService, target: "Spooler"),
            },
            description: "Restarts the Print Spooler service."),
        AutomationDefinition.Create("restart-bas-service", "Restart BAS site service (template)",
            new[]
            {
                RemediationStep.Create("restart-bas", RemediationStepKinds.RestartService, target: "Niagara"),
            },
            enabled: false,
            description: "TEMPLATE — rename the step Target to the site's actual JACE/vendor daemon service name and enable in a signed site library revision. Ships disabled: the service name is site fact, never guessed."),
        AutomationDefinition.Create("remove-prohibited-app", "Uninstall prohibited application",
            new[]
            {
                RemediationStep.Create("uninstall", RemediationStepKinds.UninstallApp, target: "ProhibitedApp"),
            },
            tier: RemediationTiers.RequiresApproval,
            description: "TEMPLATE — uninstalls the named application. Requires approval by tier: removing software is a human's call, and the target name is site fact."),
    });
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Acp.Shared.Runbooks;

// =====================================================================
// RMM-20 — Runbooks: approval-gated SOP execution chains. MODEL
// LAYER: the runbook library — signed, versioned content in the
// RMM-03/RMM-08 admission discipline.
//
// A runbook is an ordered list of steps of three CLOSED kinds:
//   * automated        — composes the RMM-08 engine: the step names
//                        an AutomationDefinition id; the runbook
//                        carries NO script body and NO step payload
//                        of its own (arbitrary code is not a runbook
//                        step kind — code lives only as signed
//                        automation-library content);
//   * check            — a verification whose result GATES progress:
//                        the step names one of a closed set of check
//                        kinds + target + expected argument, and
//                        declares its own failure policy (halt /
//                        continue / route) — a failed check never
//                        advances the run silently;
//   * human_confirmation — a named human attests a fact. The step
//                        declares WHO may attest: a specific
//                        attester id and/or the rule that the
//                        attester must differ from the executing
//                        tech. Site facts are authored as these
//                        steps — placeholders a human fills by
//                        attestation, never invented facts.
//
// Approval gates are per-step (RequiresApproval): the step does not
// run until a recorded approval lands, and the approver may never
// be the run's initiator (enforced in RunbookService).
//
// The definition model IS the visual builder's data contract: it is
// constructible and manipulable as structured data (factories +
// canonical JSON round-trip), and Validate() is the builder's error
// surface — every refusal names the defect. A text/JSON authoring
// path ships now; the canvas is design-phase.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-20. The feature
/// toggle is the registry-seeded `rmm.runbooks.enabled` (RMM-07);
/// the per-runbook keys are policy SETTINGS read through the same
/// Effective Policy engine — policy content, never a second store.</summary>
public static class RunbookPolicyKeys
{
    public const string RunbooksEnabled = "rmm.runbooks.enabled";

    /// <summary>Per-runbook enable setting: "false" disables this
    /// one runbook for the device even while runbooks are on.</summary>
    public static string RunbookEnabled(string runbookId) =>
        $"rmm.runbooks.{NormalizeId(runbookId)}.enabled";

    public static string NormalizeId(string? id) => (id ?? "").Trim().ToLowerInvariant();
}

public static class RunbookStepKinds
{
    public const string Automated = "automated";
    public const string Check = "check";
    public const string HumanConfirmation = "human_confirmation";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Automated, Check, HumanConfirmation };
}

/// <summary>The closed check vocabulary. A check names WHAT is
/// verified; the evaluator (agent/host side) observes the fact. An
/// unknown check kind refuses at admission — a check nobody can
/// evaluate is a gate that means nothing.</summary>
public static class RunbookCheckKinds
{
    public const string ServiceRunning = "service_running";       // Target = service name
    public const string ProcessRunning = "process_running";       // Target = process name
    public const string DiskFreePercent = "disk_free_percent";    // Target = path/drive; Argument = minimum percent
    public const string FileExists = "file_exists";               // Target = path
    public const string TcpPortListening = "tcp_port_listening";  // Target = host; Argument = port

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        ServiceRunning, ProcessRunning, DiskFreePercent, FileExists, TcpPortListening,
    };
}

/// <summary>What a step does when it fails (automated failure or a
/// failed check). Halt stops the run AT the step (resumable: the
/// check can be re-run, or an authorised actor can record a skip);
/// Continue records the failure and moves on — the run's outcome is
/// then partial_failure, never succeeded; Route jumps to a named
/// step, recording the failure that routed.</summary>
public static class RunbookFailurePolicies
{
    public const string Halt = "halt";
    public const string Continue = "continue";
    public const string Route = "route";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Halt, Continue, Route };
}

public static class RunbookLimits
{
    public const int MaxRunbooks = 256;
    public const int MaxStepsPerRunbook = 50;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    public const int MaxTitleLength = 256;
    public const int MaxPromptLength = 1024;
    public const int MaxTargetLength = 512;
    public const int MaxArgumentLength = 512;
    public const int MaxDescriptionLength = 1024;
}

/// <summary>One runbook step. Kind-specific fields are null outside
/// their kind, and admission enforces exactly that shape — a script
/// body or a stray payload has nowhere to hide in this model.</summary>
public sealed record RunbookStep(
    string Id,
    string Kind,
    string Title,
    // automated
    string? AutomationId,
    // check
    string? CheckKind,
    string? CheckTarget,
    string? CheckArgument,
    // human_confirmation
    string? AttestationPrompt,
    string? RequiredAttesterId,
    bool RequireDistinctAttester,
    // gates + failure policy (all kinds)
    bool RequiresApproval,
    string? RequiredApproverId,
    string OnFailure,
    string? RouteStepId,
    bool Idempotent)
{
    public static RunbookStep Automated(string id, string title, string automationId,
        bool requiresApproval = false, string? requiredApproverId = null,
        string onFailure = RunbookFailurePolicies.Halt, string? routeStepId = null,
        bool idempotent = true) =>
        new(id, RunbookStepKinds.Automated, title, automationId,
            null, null, null, null, null, false,
            requiresApproval, requiredApproverId, onFailure, routeStepId, idempotent);

    public static RunbookStep Check(string id, string title, string checkKind, string checkTarget,
        string? checkArgument = null,
        bool requiresApproval = false, string? requiredApproverId = null,
        string onFailure = RunbookFailurePolicies.Halt, string? routeStepId = null) =>
        new(id, RunbookStepKinds.Check, title, null,
            checkKind, checkTarget, checkArgument, null, null, false,
            requiresApproval, requiredApproverId, onFailure, routeStepId, true);

    public static RunbookStep Human(string id, string title, string attestationPrompt,
        string? requiredAttesterId = null, bool requireDistinctAttester = false,
        bool idempotent = false) =>
        new(id, RunbookStepKinds.HumanConfirmation, title, null,
            null, null, null, attestationPrompt, requiredAttesterId, requireDistinctAttester,
            false, null, RunbookFailurePolicies.Halt, null, idempotent);
}

/// <summary>One runbook definition: a named standard procedure.
/// Executed identically by any tech — the definition a run starts
/// with is pinned by content hash for the whole run (RunbookService
/// holds a snapshot; a library revision mid-run changes nothing
/// under a running execution).</summary>
public sealed record RunbookDefinition(
    string Id,
    string Name,
    string Description,
    bool Enabled,
    IReadOnlyList<RunbookStep> Steps)
{
    public IReadOnlyList<RunbookStep> Steps { get; init; } = Steps ?? Array.Empty<RunbookStep>();

    public static RunbookDefinition Create(string id, string name, IReadOnlyList<RunbookStep> steps,
        bool enabled = true, string description = "") =>
        new(id, name, description, enabled, steps);
}

/// <summary>A versioned set of runbook definitions — signed library
/// content, same discipline as the automation library: canonical
/// JSON, SHA-256 content hash, monotonic revision per id, whole-
/// library admission validation, defensive copy at admission.</summary>
public sealed record RunbookLibrary(
    string Id,
    long Revision,
    IReadOnlyList<RunbookDefinition> Runbooks)
{
    public IReadOnlyList<RunbookDefinition> Runbooks { get; init; } =
        Runbooks ?? Array.Empty<RunbookDefinition>();

    public RunbookDefinition? Get(string runbookId) =>
        Runbooks.FirstOrDefault(r =>
            string.Equals(r.Id, runbookId ?? "", StringComparison.OrdinalIgnoreCase));

    public string ToCanonicalJson()
    {
        var books = Runbooks.OrderBy(r => r.Id, StringComparer.Ordinal).Select(r => new
        {
            id = r.Id, name = r.Name, description = r.Description, enabled = r.Enabled,
            steps = r.Steps.Select(s => new
            {
                id = s.Id, kind = s.Kind, title = s.Title,
                automationId = s.AutomationId,
                checkKind = s.CheckKind, checkTarget = s.CheckTarget, checkArgument = s.CheckArgument,
                attestationPrompt = s.AttestationPrompt, requiredAttesterId = s.RequiredAttesterId,
                requireDistinctAttester = s.RequireDistinctAttester,
                requiresApproval = s.RequiresApproval, requiredApproverId = s.RequiredApproverId,
                onFailure = s.OnFailure, routeStepId = s.RouteStepId, idempotent = s.Idempotent,
            }).ToList(),
        }).ToList();
        return JsonSerializer.Serialize(new { id = Id, revision = Revision, runbooks = books });
    }

    public string ContentHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()))).ToLowerInvariant();

    /// <summary>Content hash of ONE definition (steps in authored
    /// order) — the pin a run carries: the definition version it
    /// started with, verifiable after the fact.</summary>
    public static string DefinitionHash(RunbookDefinition def)
    {
        var single = new RunbookLibrary("__definition__", 1, new[] { def });
        return single.ContentHash;
    }

    public static RunbookLibrary? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var books = new List<RunbookDefinition>();
            foreach (var el in root.GetProperty("runbooks").EnumerateArray())
            {
                var steps = new List<RunbookStep>();
                foreach (var s in el.GetProperty("steps").EnumerateArray())
                {
                    steps.Add(new RunbookStep(
                        s.GetProperty("id").GetString() ?? "",
                        s.GetProperty("kind").GetString() ?? "",
                        s.GetProperty("title").GetString() ?? "",
                        OptString(s, "automationId"),
                        OptString(s, "checkKind"), OptString(s, "checkTarget"), OptString(s, "checkArgument"),
                        OptString(s, "attestationPrompt"), OptString(s, "requiredAttesterId"),
                        s.GetProperty("requireDistinctAttester").GetBoolean(),
                        s.GetProperty("requiresApproval").GetBoolean(),
                        OptString(s, "requiredApproverId"),
                        OptString(s, "onFailure") ?? RunbookFailurePolicies.Halt,
                        OptString(s, "routeStepId"),
                        s.GetProperty("idempotent").GetBoolean()));
                }
                books.Add(new RunbookDefinition(
                    el.GetProperty("id").GetString() ?? "",
                    el.GetProperty("name").GetString() ?? "",
                    OptString(el, "description") ?? "",
                    el.GetProperty("enabled").GetBoolean(),
                    steps));
            }
            return new RunbookLibrary(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("revision").GetInt64(),
                books);
        }
        catch { return null; }
    }

    private static string? OptString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Admission validation — the builder's error surface.
    /// Null when admissible; otherwise the refusal naming the first
    /// defect. A refused library changes NOTHING.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > RunbookLimits.MaxIdLength)
            return "runbook library needs an id within bounds — refused";
        if (Revision < 1)
            return $"runbook library '{Id}' revision {Revision} is not positive — refused";
        if (Runbooks.Count > RunbookLimits.MaxRunbooks)
            return $"runbook library '{Id}' carries {Runbooks.Count} runbooks over the cap {RunbookLimits.MaxRunbooks} — refused";
        var seenBooks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Runbooks)
        {
            if (string.IsNullOrWhiteSpace(r.Id) || r.Id.Length > RunbookLimits.MaxIdLength)
                return $"runbook library '{Id}': a runbook id is empty or over bounds — refused";
            if (!seenBooks.Add(r.Id))
                return $"runbook library '{Id}': duplicate runbook id '{r.Id}' — refused";
            if (string.IsNullOrWhiteSpace(r.Name) || r.Name.Length > RunbookLimits.MaxNameLength)
                return $"runbook '{r.Id}': name empty or over bounds — refused";
            if ((r.Description?.Length ?? 0) > RunbookLimits.MaxDescriptionLength)
                return $"runbook '{r.Id}': description over bounds ({RunbookLimits.MaxDescriptionLength}) — refused";
            if (r.Steps.Count == 0)
                return $"runbook '{r.Id}': carries no steps — refused (a procedure that does nothing is a false promise)";
            if (r.Steps.Count > RunbookLimits.MaxStepsPerRunbook)
                return $"runbook '{r.Id}': {r.Steps.Count} steps over the cap {RunbookLimits.MaxStepsPerRunbook} — refused";
            var stepIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in r.Steps)
            {
                if (string.IsNullOrWhiteSpace(s.Id) || s.Id.Length > RunbookLimits.MaxIdLength)
                    return $"runbook '{r.Id}': a step id is empty or over bounds — refused";
                if (!stepIds.Add(s.Id))
                    return $"runbook '{r.Id}': duplicate step id '{s.Id}' — refused";
                if (string.IsNullOrWhiteSpace(s.Title) || s.Title.Length > RunbookLimits.MaxTitleLength)
                    return $"runbook '{r.Id}' step '{s.Id}': title empty or over bounds — refused";
                if (!RunbookStepKinds.All.Contains(s.Kind ?? ""))
                    return $"runbook '{r.Id}' step '{s.Id}': unknown step kind '{s.Kind}' — refused (the step vocabulary is a closed set)";
                if (!RunbookFailurePolicies.All.Contains(s.OnFailure ?? ""))
                    return $"runbook '{r.Id}' step '{s.Id}': unknown failure policy '{s.OnFailure}' — refused";
                if (s.OnFailure == RunbookFailurePolicies.Route && string.IsNullOrWhiteSpace(s.RouteStepId))
                    return $"runbook '{r.Id}' step '{s.Id}': failure policy 'route' names no target step — refused";
                // D38 F9: the one-kind-per-step shape is COMPLETE —
                // every field outside a step's kind refuses, and the
                // gate/route fields must agree with each other.
                if (s.RouteStepId is not null && s.OnFailure != RunbookFailurePolicies.Route)
                    return $"runbook '{r.Id}' step '{s.Id}': carries a route target but its failure policy is '{s.OnFailure}' — refused (a route target exists only under the route policy)";
                if (s.RequiredApproverId is not null && !s.RequiresApproval)
                    return $"runbook '{r.Id}' step '{s.Id}': names a required approver but does not require approval — refused (gate fields must agree)";
                if ((s.CheckArgument?.Length ?? 0) > RunbookLimits.MaxArgumentLength)
                    return $"runbook '{r.Id}' step '{s.Id}': check argument over bounds ({RunbookLimits.MaxArgumentLength}) — refused";
                switch (s.Kind)
                {
                    case RunbookStepKinds.Automated:
                        if (string.IsNullOrWhiteSpace(s.AutomationId))
                            return $"runbook '{r.Id}' step '{s.Id}': an automated step names no automation definition — refused (automated steps compose the RMM-08 library; they carry no payload of their own)";
                        if (s.CheckKind is not null || s.CheckTarget is not null || s.CheckArgument is not null ||
                            s.AttestationPrompt is not null || s.RequiredAttesterId is not null || s.RequireDistinctAttester)
                            return $"runbook '{r.Id}' step '{s.Id}': an automated step carries check/human fields — refused (one kind per step)";
                        break;
                    case RunbookStepKinds.Check:
                        if (!RunbookCheckKinds.All.Contains(s.CheckKind ?? ""))
                            return $"runbook '{r.Id}' step '{s.Id}': unknown check kind '{s.CheckKind}' — refused (the check vocabulary is a closed set)";
                        if (string.IsNullOrWhiteSpace(s.CheckTarget) || s.CheckTarget.Length > RunbookLimits.MaxTargetLength)
                            return $"runbook '{r.Id}' step '{s.Id}': check step needs a target within bounds — refused";
                        if (s.RequiredAttesterId is not null || s.RequireDistinctAttester)
                            return $"runbook '{r.Id}' step '{s.Id}': a check step carries human attester fields — refused (one kind per step)";
                        if (s.CheckKind == RunbookCheckKinds.DiskFreePercent &&
                            (!int.TryParse(s.CheckArgument, out var pct) || pct < 1 || pct > 100))
                            return $"runbook '{r.Id}' step '{s.Id}': disk_free_percent needs a minimum percent within 1–100 — refused";
                        if (s.CheckKind == RunbookCheckKinds.TcpPortListening &&
                            (!int.TryParse(s.CheckArgument, out var port) || port < 1 || port > 65535))
                            return $"runbook '{r.Id}' step '{s.Id}': tcp_port_listening needs a port within 1–65535 — refused";
                        if (s.AutomationId is not null || s.AttestationPrompt is not null)
                            return $"runbook '{r.Id}' step '{s.Id}': a check step carries automated/human fields — refused (one kind per step)";
                        break;
                    case RunbookStepKinds.HumanConfirmation:
                        if (string.IsNullOrWhiteSpace(s.AttestationPrompt) ||
                            s.AttestationPrompt.Length > RunbookLimits.MaxPromptLength)
                            return $"runbook '{r.Id}' step '{s.Id}': a human-confirmation step needs an attestation prompt within bounds — refused (the attester must know exactly what fact they are attesting)";
                        if (s.RequiresApproval)
                            return $"runbook '{r.Id}' step '{s.Id}': a human-confirmation step cannot also require approval — refused (attestation IS the human gate for this kind)";
                        if (s.AutomationId is not null || s.CheckKind is not null || s.CheckTarget is not null ||
                            s.CheckArgument is not null || s.RequiredApproverId is not null)
                            return $"runbook '{r.Id}' step '{s.Id}': a human-confirmation step carries automated/check fields — refused (one kind per step)";
                        if (s.OnFailure != RunbookFailurePolicies.Halt || s.RouteStepId is not null)
                            return $"runbook '{r.Id}' step '{s.Id}': a human-confirmation step carries a failure policy/route — refused (a human step has no failure to route; its gate is the attestation)";
                        break;
                }
            }
            foreach (var s in r.Steps)
            {
                if (s.RouteStepId is null) continue;
                if (!stepIds.Contains(s.RouteStepId))
                    return $"runbook '{r.Id}' step '{s.Id}': routes on failure to unknown step '{s.RouteStepId}' — refused";
                // D38 F5: a route must go FORWARD to a later step.
                // A self-route or backward route re-evaluates steps
                // in a tight loop until the attempt cap, and a
                // backward route to an already-Done handler never
                // re-runs it — neither is a handler jump.
                var from = r.Steps.ToList().FindIndex(x => x.Id == s.Id);
                var to = r.Steps.ToList().FindIndex(x => x.Id == s.RouteStepId);
                if (to <= from)
                    return $"runbook '{r.Id}' step '{s.Id}': routes on failure to '{s.RouteStepId}', which is not a LATER step — refused (routes go forward to a handler; self/backward routes loop or silently no-op)";
            }
        }
        return null;
    }

    /// <summary>The starter runbook library (code-seeded, part of
    /// the signed binary). Honesty rule: site facts are NEVER
    /// invented — every site-specific fact is an explicit human-
    /// confirmation placeholder whose prompt names the fact the
    /// attester must supply from site paperwork / the ticket.
    /// Automated steps reference only automation definitions that
    /// ship in RMM-08's default library.</summary>
    public static RunbookLibrary Default() => new("acp-default-runbooks", 1, new[]
    {
        RunbookDefinition.Create("site-commissioning-checks", "Site commissioning checks",
            new[]
            {
                RunbookStep.Human("confirm-site-facts", "Confirm site facts from paperwork",
                    "Attest: the site name, device role and network segment recorded on the commissioning paperwork match this device. SITE FACT — taken from the site paperwork, never assumed.",
                    requireDistinctAttester: true),
                RunbookStep.Check("disk-headroom", "Disk headroom at least 20 percent",
                    RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
                RunbookStep.Check("os-present", "Operating system directory present",
                    RunbookCheckKinds.FileExists, @"C:\Windows"),
                RunbookStep.Automated("clear-temp", "Clear temporary files", "clear-disk-temp"),
                RunbookStep.Human("confirm-front-end-online", "Confirm device online at the front end",
                    "Attest: the site front end (supervisor/JACE) shows this device online and communicating. SITE FACT — verified on the site's own front end by the attester.",
                    requireDistinctAttester: true),
            },
            description: "Commissioning checks for a newly enrolled device. Site facts are human-confirmation placeholders by design."),
        RunbookDefinition.Create("monthly-maintenance", "Monthly maintenance",
            new[]
            {
                RunbookStep.Automated("clear-temp", "Clear temporary files", "clear-disk-temp"),
                RunbookStep.Check("disk-headroom", "Disk headroom at least 20 percent after cleanup",
                    RunbookCheckKinds.DiskFreePercent, @"C:\", "20"),
                RunbookStep.Automated("restart-spooler", "Restart print spooler (approval-gated)",
                    "restart-print-spooler", requiresApproval: true),
                RunbookStep.Human("confirm-no-impact", "Confirm no user impact and sign off",
                    "Attest: maintenance completed inside the agreed window and no user reported an impact. SITE FACT — confirmed with the site contact, never assumed.",
                    requireDistinctAttester: true),
            },
            description: "Monthly maintenance pass: cleanup, headroom check, an approval-gated service restart, and a human sign-off."),
        RunbookDefinition.Create("new-user-setup", "New-user setup",
            new[]
            {
                RunbookStep.Human("confirm-user-details", "Confirm new-user details from the ticket",
                    "Attest: the new user's name, role and manager approval are exactly as stated on the work ticket. SITE FACT — taken from the ticket, never guessed.",
                    requireDistinctAttester: true),
                RunbookStep.Human("create-account", "Create the account per the ticket",
                    "Attest: the account was created in the site directory with the role and group membership named on the ticket, and no access beyond the ticket was granted."),
                RunbookStep.Check("profile-dir", "User profile directory present after first sign-in",
                    RunbookCheckKinds.FileExists, @"C:\Users",
                    onFailure: RunbookFailurePolicies.Continue),
                RunbookStep.Human("confirm-handover", "Confirm credentials handed over securely",
                    "Attest: initial credentials were handed to the new user (or their manager) through the site's approved channel and a password change at first sign-in is enforced. SITE FACT — confirmed by the attester.",
                    requireDistinctAttester: true),
            },
            description: "New-user setup as attested procedure: the account work itself is site fact, recorded as human confirmations — nothing about the user is invented by the runbook."),
    });
}

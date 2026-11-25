using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Security;

namespace Acp.Shared.Reporting;

// =====================================================================
// RMM-13 — The governed MCP surface extends from host control to
// FLEET OPERATIONS, under the SAME RBAC/dual-control discipline as
// the host MCP (FEATURES §8): the fleet tools ride the pairing's
// scopes and the approval path; they are not a new auth model.
//
//   * READ-ONLY BY DEFAULT, STRUCTURALLY: query tools receive ONLY
//     an IFleetReadModel — an interface with no mutation methods.
//     A query tool cannot change hub state because the surface it
//     is handed has no verb that changes anything. Query tools
//     require the fleet_read scope.
//   * STATE-CHANGING FLEET ACTIONS go through dual control or do
//     not exist: an action tool executes only with (a) the
//     fleet_act scope AND (b) a live, unconsumed ApprovalGrant for
//     that exact action, granted by TWO DISTINCT approvers. A
//     grant is single-use and expires. Anything less refuses by
//     name — there is no direct-call path around the grant.
//   * Every call (query, action, refusal) is returned with its
//     outcome so the Core service can write it to the chained
//     audit before the caller sees a result (the McpHandler rule).
// =====================================================================

public static class FleetScopes
{
    public const string Read = "fleet_read";
    public const string Act = "fleet_act";
}

/// <summary>The read-only fleet surface. Every method is a query
/// over hub state as it stands; the interface deliberately exposes
/// no store, no writer, and no executor.</summary>
public interface IFleetReadModel
{
    HubReport FleetHealth(DateTimeOffset now);
    HubReport PatchCompliance(DateTimeOffset now);
    HubReport InventoryLifecycle(DateTimeOffset now);
    HubReport BackupStatus(DateTimeOffset now);
    HubReport AuditSummary(DateTimeOffset now);
    HubReport VulnerabilityPosture(DateTimeOffset now);
}

/// <summary>The state-changing side, kept on a SEPARATE interface
/// so it can never leak into a query tool's hands. Implementations
/// are the existing governed executors (or fakes in tests).</summary>
public interface IFleetActionExecutor
{
    (bool Ok, string Detail) Execute(string actionName, string argumentsJson);
}

/// <summary>One dual-control approval grant: TWO DISTINCT approvers
/// approved one named action. Single-use, expiring. The book
/// refuses a grant whose approvers coincide — one person approving
/// twice is not dual control, it is a costume.
/// D38-F3: a grant binds MORE than the action name — the canonical
/// arguments hash it was issued for, the target device set named
/// in those arguments (or given explicitly), and, when named at
/// issuance, the ONE caller who may redeem it. Approver identities
/// are canonicalised (Unicode format/zero-width characters stripped,
/// trimmed) before the distinctness check, so 'alice' and
/// 'alice\u200b' are the same approver, not two.</summary>
public sealed record ApprovalGrant(
    string GrantId, string ActionName, string Approver1, string Approver2,
    DateTimeOffset GrantedUtc, DateTimeOffset ExpiresUtc, bool Consumed,
    string ArgumentsHash = "", IReadOnlyList<string>? TargetDeviceIds = null, string? RedeemingCaller = null)
{
    public IReadOnlyList<string> TargetDeviceIds { get; init; } = TargetDeviceIds ?? Array.Empty<string>();
}

public sealed class FleetApprovalBook
{
    private readonly Dictionary<string, ApprovalGrant> _grants = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>Canonical identity form: Unicode format characters
    /// (zero-width spaces/joiners, bidi marks, BOM) are stripped and
    /// the result trimmed — visually-distinct-but-identical names
    /// collapse to one identity.</summary>
    public static string CanonicalIdentity(string? name) =>
        new string((name ?? "").Where(c =>
            System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.Format)
            .ToArray()).Trim();

    /// <summary>Canonical arguments: JSON is re-serialised with
    /// object keys sorted recursively, so key order and whitespace
    /// do not change the binding; unparseable input binds as its
    /// trimmed raw text. Null binds as the empty object.</summary>
    public static string CanonicalArguments(string? argumentsJson)
    {
        var raw = (argumentsJson ?? "").Trim();
        if (raw.Length == 0) raw = "{}";
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(raw);
            var sb = new StringBuilder();
            WriteCanonical(doc.RootElement, sb);
            return sb.ToString();
        }
        catch { return raw; }
    }

    private static void WriteCanonical(System.Text.Json.JsonElement el, StringBuilder sb)
    {
        switch (el.ValueKind)
        {
            case System.Text.Json.JsonValueKind.Object:
                sb.Append('{');
                var first = true;
                foreach (var p in el.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append(System.Text.Json.JsonSerializer.Serialize(p.Name));
                    sb.Append(':');
                    WriteCanonical(p.Value, sb);
                }
                sb.Append('}');
                break;
            case System.Text.Json.JsonValueKind.Array:
                sb.Append('[');
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    if (i++ > 0) sb.Append(',');
                    WriteCanonical(item, sb);
                }
                sb.Append(']');
                break;
            default:
                sb.Append(el.GetRawText());
                break;
        }
    }

    public static string ArgumentsHash(string? argumentsJson) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalArguments(argumentsJson)))).ToLowerInvariant();

    /// <summary>Target devices named by an arguments object:
    /// "deviceId" (string) and/or "deviceIds" (string array).</summary>
    public static IReadOnlyList<string> ExtractTargets(string? argumentsJson)
    {
        var targets = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse((argumentsJson ?? "").Trim());
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("deviceId", out var one) && one.ValueKind == System.Text.Json.JsonValueKind.String)
                    targets.Add(one.GetString()!);
                if (doc.RootElement.TryGetProperty("deviceIds", out var many) && many.ValueKind == System.Text.Json.JsonValueKind.Array)
                    foreach (var d in many.EnumerateArray())
                        if (d.ValueKind == System.Text.Json.JsonValueKind.String) targets.Add(d.GetString()!);
            }
        }
        catch { /* unparseable arguments name no targets */ }
        return targets.ToList();
    }

    public (bool Ok, string Reason, ApprovalGrant? Grant) Grant(
        string actionName, string approver1, string approver2, DateTimeOffset now, TimeSpan ttl,
        string? argumentsJson = null, IEnumerable<string>? targetDeviceIds = null, string? redeemingCaller = null)
    {
        if (string.IsNullOrWhiteSpace(actionName)) return (false, "approval grant needs an action name — refused", null);
        var a1 = CanonicalIdentity(approver1);
        var a2 = CanonicalIdentity(approver2);
        if (a1.Length == 0 || a2.Length == 0)
            return (false, "approval grant needs two approvers — refused", null);
        if (string.Equals(a1, a2, StringComparison.OrdinalIgnoreCase))
            return (false, "dual control requires TWO DISTINCT approvers — one approver named twice is refused (identities are canonicalised: zero-width/format characters do not make a second approver)", null);
        if (ttl <= TimeSpan.Zero) return (false, "approval grant ttl must be positive — refused", null);
        var targets = targetDeviceIds is not null
            ? targetDeviceIds.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToList()
            : ExtractTargets(argumentsJson);
        var grant = new ApprovalGrant(
            "apg-" + Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes($"{actionName}|{a1}|{a2}|{now:O}|{Guid.NewGuid():N}")))[..20].ToLowerInvariant(),
            actionName, a1, a2, now, now + ttl, false,
            ArgumentsHash(argumentsJson), targets,
            string.IsNullOrWhiteSpace(redeemingCaller) ? null : CanonicalIdentity(redeemingCaller));
        lock (_gate) _grants[grant.GrantId] = grant;
        return (true, $"dual-control grant '{grant.GrantId}' issued for '{actionName}' bound to arguments hash {grant.ArgumentsHash[..12]}…, {targets.Count} target device(s)" +
            (grant.RedeemingCaller is null ? "" : $", redeemable only by '{grant.RedeemingCaller}'") +
            $" (expires {grant.ExpiresUtc:O})", grant);
    }

    /// <summary>Consume a grant for an action: succeeds exactly
    /// once, only for the named action, only before expiry, only
    /// for the arguments / targets / redeeming caller the grant
    /// binds (D38-F3).</summary>
    public (bool Ok, string Reason) Consume(string? grantId, string actionName, DateTimeOffset now,
        string? argumentsJson = null, string? callerName = null)
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(grantId) || !_grants.TryGetValue(grantId, out var grant))
                return (false, $"unknown approval grant '{grantId}' — refused (fleet actions require a dual-control grant)");
            if (grant.Consumed) return (false, $"approval grant '{grantId}' was already consumed — grants are single-use, refused");
            if (grant.ExpiresUtc <= now) return (false, $"approval grant '{grantId}' expired at {grant.ExpiresUtc:O} — refused");
            if (!string.Equals(grant.ActionName, actionName, StringComparison.Ordinal))
                return (false, $"approval grant '{grantId}' names action '{grant.ActionName}', not '{actionName}' — refused");
            if (!string.Equals(grant.ArgumentsHash, ArgumentsHash(argumentsJson), StringComparison.Ordinal))
                return (false, $"approval grant '{grantId}' was issued for different arguments — refused (a grant authorises the exact call its approvers saw, not any call to the same action)");
            if (grant.TargetDeviceIds.Count > 0)
            {
                var presented = ExtractTargets(argumentsJson);
                if (!grant.TargetDeviceIds.SequenceEqual(presented, StringComparer.OrdinalIgnoreCase))
                    return (false, $"approval grant '{grantId}' binds target device(s) [{string.Join(",", grant.TargetDeviceIds)}], not [{string.Join(",", presented)}] — refused");
            }
            if (grant.RedeemingCaller is not null &&
                !string.Equals(grant.RedeemingCaller, CanonicalIdentity(callerName), StringComparison.OrdinalIgnoreCase))
                return (false, $"approval grant '{grantId}' may be redeemed only by '{grant.RedeemingCaller}' — refused for caller '{callerName}'");
            // BD-SHARED-RMM-3/F10: the two-person rule is defeated if
            // an APPROVER redeems their own grant. When the caller is
            // named, it must differ from BOTH approvers — previously
            // this was only implied when a RedeemingCaller happened
            // to be bound at issuance.
            var caller = CanonicalIdentity(callerName);
            if (caller.Length > 0 &&
                (string.Equals(caller, grant.Approver1, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(caller, grant.Approver2, StringComparison.OrdinalIgnoreCase)))
                return (false, $"approval grant '{grantId}' cannot be redeemed by one of its own approvers ('{callerName}') — dual control means the redeemer is a third party, refused");
            _grants[grantId] = grant with { Consumed = true };
            return (true, $"approval grant '{grantId}' consumed for '{actionName}'");
        }
    }

    public IReadOnlyList<ApprovalGrant> Grants
    {
        get { lock (_gate) return _grants.Values.OrderBy(g => g.GrantId, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>BD-SHARED-RMM-3/F10: prune consumed and expired
    /// grants — the book previously only ever grew. Returns the
    /// number pruned; live unconsumed grants are never touched.</summary>
    public int Prune(DateTimeOffset now)
    {
        lock (_gate)
        {
            var dead = _grants.Values.Where(g => g.Consumed || g.ExpiresUtc <= now)
                .Select(g => g.GrantId).ToList();
            foreach (var id in dead) _grants.Remove(id);
            return dead.Count;
        }
    }
}

/// <summary>One fleet MCP tool descriptor. MutatesState is declared
/// at registration and decides the execution path: queries are
/// served from the read model; actions demand scope + grant.</summary>
public sealed record FleetToolDescriptor(string Name, string Description, bool MutatesState, string RequiredScope);

public sealed record FleetToolResult(bool Ok, string Outcome, string Text,
    // BD-WIN-CORE-4/F5: true ONLY when this call actually redeemed
    // a dual-control grant — callers chain 'fleet_grant_consumed'
    // from this flag, never from the mere presence of a grant id.
    bool GrantConsumed = false);

/// <summary>The fleet-operations MCP host. Registration is split by
/// KIND (RegisterQuery / RegisterAction) so a tool's mutability is
/// a property of how it was registered, never of a flag its handler
/// can flip at call time.</summary>
public sealed class FleetMcpHost
{
    private readonly IFleetReadModel _readModel;
    private readonly IFleetActionExecutor? _actions;
    private readonly FleetApprovalBook _approvals;
    private readonly Dictionary<string, (FleetToolDescriptor Desc, Func<IFleetReadModel, string, DateTimeOffset, string> Handler)> _queries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, FleetToolDescriptor> _actionDescs = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public FleetMcpHost(IFleetReadModel readModel, FleetApprovalBook approvals, IFleetActionExecutor? actions = null)
    {
        _readModel = readModel ?? throw new ArgumentNullException(nameof(readModel));
        _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        _actions = actions;
    }

    public FleetApprovalBook Approvals => _approvals;

    public void RegisterQuery(string name, string description, Func<IFleetReadModel, string, DateTimeOffset, string> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("fleet tool needs a name", nameof(name));
        lock (_gate)
        {
            if (_queries.ContainsKey(name) || _actionDescs.ContainsKey(name))
                throw new ArgumentException($"fleet tool '{name}' is already registered", nameof(name));
            _queries[name] = (new FleetToolDescriptor(name, description ?? "", false, FleetScopes.Read), handler);
        }
    }

    public void RegisterAction(string name, string description)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("fleet tool needs a name", nameof(name));
        lock (_gate)
        {
            if (_queries.ContainsKey(name) || _actionDescs.ContainsKey(name))
                throw new ArgumentException($"fleet tool '{name}' is already registered", nameof(name));
            _actionDescs[name] = new FleetToolDescriptor(name, description ?? "", true, FleetScopes.Act);
        }
    }

    public IReadOnlyList<FleetToolDescriptor> Tools
    {
        get
        {
            lock (_gate)
                return _queries.Values.Select(q => q.Desc).Concat(_actionDescs.Values)
                    .OrderBy(d => d.Name, StringComparer.Ordinal).ToList();
        }
    }

    /// <summary>Register the standard fleet query set: one tool per
    /// report kind, each rendering through the report exporter (so
    /// MCP answers carry the same provenance + staleness as every
    /// other surface).</summary>
    public void RegisterStandardQueries()
    {
        RegisterQuery("fleet.health", "Fleet health report (RMM-01 hub ingest) as JSON with provenance + staleness.",
            (rm, _, now) => ReportExporter.ToJson(rm.FleetHealth(now), now));
        RegisterQuery("fleet.patch_compliance", "Patch compliance report (RMM-02 over RMM-04) as JSON with provenance + staleness.",
            (rm, _, now) => ReportExporter.ToJson(rm.PatchCompliance(now), now));
        RegisterQuery("fleet.inventory", "Inventory + lifecycle report (RMM-04) as JSON with provenance + staleness.",
            (rm, _, now) => ReportExporter.ToJson(rm.InventoryLifecycle(now), now));
        RegisterQuery("fleet.backup_status", "Backup status report (RMM-06 facts) as JSON with provenance + staleness.",
            (rm, _, now) => ReportExporter.ToJson(rm.BackupStatus(now), now));
        RegisterQuery("fleet.audit_summary", "Audit-ledger summary (counts by kind + chain verdict) as JSON.",
            (rm, _, now) => ReportExporter.ToJson(rm.AuditSummary(now), now));
        RegisterQuery("fleet.vulnerability_posture", "Vulnerability posture (RMM-05) as JSON; a stale feed names itself stale.",
            (rm, _, now) => ReportExporter.ToJson(rm.VulnerabilityPosture(now), now));
    }

    /// <summary>Execute one tool call under a caller's scopes.
    /// Queries: fleet_read required; the handler receives ONLY the
    /// read model. Actions: fleet_act required AND a consumable
    /// dual-control grant naming the action; the grant is consumed
    /// BEFORE execution, so a failed execution cannot be retried on
    /// the same approval. Every refusal names its reason.</summary>
    public FleetToolResult Call(string toolName, string argumentsJson, IReadOnlySet<string> callerScopes,
        string? approvalGrantId, DateTimeOffset now, string? callerName = null)
    {
        callerScopes ??= new HashSet<string>();
        (FleetToolDescriptor Desc, Func<IFleetReadModel, string, DateTimeOffset, string> Handler)? query;
        FleetToolDescriptor? action;
        lock (_gate)
        {
            query = _queries.TryGetValue(toolName ?? "", out var q) ? q : null;
            action = _actionDescs.TryGetValue(toolName ?? "", out var a) ? a : null;
        }
        if (query is null && action is null)
            return new FleetToolResult(false, $"unknown fleet tool '{toolName}'", $"unknown tool: {toolName}");

        if (query is { } qq)
        {
            if (!callerScopes.Contains(FleetScopes.Read))
                return new FleetToolResult(false, $"denied: tool '{toolName}' requires scope '{FleetScopes.Read}'",
                    "the calling pairing does not hold the fleet_read scope");
            try
            {
                var text = qq.Handler(_readModel, argumentsJson ?? "", now);
                return new FleetToolResult(true, "executed (read-only)", text);
            }
            catch (Exception ex)
            {
                return new FleetToolResult(false, $"error:{ex.GetType().Name}", ex.Message);
            }
        }

        // Action path — dual control or it does not happen.
        if (!callerScopes.Contains(FleetScopes.Act))
            return new FleetToolResult(false, $"denied: action '{toolName}' requires scope '{FleetScopes.Act}'",
                "the calling pairing does not hold the fleet_act scope");
        if (_actions is null)
            return new FleetToolResult(false, $"denied: action '{toolName}' has no executor wired on this hub",
                "fleet actions are not wired on this hub — the action does not exist here");
        var (grantOk, grantReason) = _approvals.Consume(approvalGrantId, toolName, now, argumentsJson, callerName);
        if (!grantOk)
            return new FleetToolResult(false, $"denied: {grantReason}", grantReason);
        // D38-F2: the grant is consumed BEFORE execution by design;
        // an executor throw must therefore NEVER escape this method
        // — it would burn the grant silently and skip the caller's
        // chained audit append. The throw becomes a named result
        // (grant stays consumed; the failure is on the record).
        try
        {
            var (ok, detail) = _actions.Execute(toolName, argumentsJson ?? "");
            return new FleetToolResult(ok, ok ? $"executed (dual-control grant {approvalGrantId})" : $"error: {detail}", detail, GrantConsumed: true);
        }
        catch (Exception ex)
        {
            return new FleetToolResult(false,
                $"error: executor threw {ex.GetType().Name} after dual-control grant {approvalGrantId} was consumed — the grant stays consumed and this failure is the chained record",
                ex.Message, GrantConsumed: true);
        }
    }
}

// ---- local AI seam (user-hosted model; outputs signed per RMM-03) ----------

/// <summary>The closed set of local-AI task kinds — the functions
/// the register names as surviving locally: script drafting,
/// session summarisation, worklog generation.</summary>
public static class LocalModelTaskKinds
{
    public const string ScriptDraft = "script_draft";
    public const string SessionSummary = "session_summary";
    public const string Worklog = "worklog";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { ScriptDraft, SessionSummary, Worklog };
}

/// <summary>The local-model integration seam. A REAL model is
/// user-hosted (the AI pack / DIR-37) and is NOT integrated here:
/// this interface + a deterministic fake are the seam the register
/// directs ("model the integration seam with a fake; do NOT
/// integrate a real model"). The model runs on the user's side of
/// the wall — no cloud model can implement this interface in ACP's
/// wiring, because the runner signs outputs as LOCAL artefacts and
/// the policy toggle names the deployment user-hosted.</summary>
public interface ILocalModel
{
    string Name { get; }
    string Complete(string taskKind, string prompt);
}

/// <summary>Deterministic fake local model (the seam's test double):
/// names itself a fake in every output, so a fake output can never
/// be mistaken for a real model's work downstream.</summary>
public sealed class FakeLocalModel : ILocalModel
{
    public string Name => "fake-local-model (test double — no real model integrated)";
    public string Complete(string taskKind, string prompt) =>
        $"[fake local model output for {taskKind}] prompt of {(prompt ?? "").Length} chars received; no real model is integrated in this build.";
}

/// <summary>One local-model output, SIGNED per RMM-03 discipline:
/// the signature (customer-held key, Ed25519) covers the task kind,
/// the model name, the prompt's hash, and the output itself — so a
/// worklog or script draft circulating as an ACP artefact can be
/// verified as exactly what the local model produced, unaltered.</summary>
public sealed record SignedModelOutput(
    string TaskKind, string ModelName, string PromptHash, string Output,
    string KeyId, string SignatureBase64, DateTimeOffset CreatedUtc)
{
    public static string Canonical(SignedModelOutput o) => string.Join("|",
        "acp-local-model-output-v1", o.TaskKind, o.ModelName, o.PromptHash,
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(o.Output ?? ""))).ToLowerInvariant(),
        o.CreatedUtc.ToString("O"));

    public static string HashPrompt(string prompt) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(prompt ?? ""))).ToLowerInvariant();
}

/// <summary>Runs tasks against an ILocalModel and signs the outputs.
/// Unknown task kinds refuse; a null model refuses by name (the
/// feature is off until the user hosts a model — it never falls
/// back to anything remote).</summary>
public sealed class LocalModelRunner
{
    private readonly ILocalModel? _model;
    private readonly DeviceIdentity _signer;

    public LocalModelRunner(ILocalModel? model, DeviceIdentity signer)
    {
        _model = model;
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    public bool HasModel => _model is not null;

    public (bool Ok, string Reason, SignedModelOutput? Output) Run(string taskKind, string prompt, DateTimeOffset now)
    {
        if (!LocalModelTaskKinds.All.Contains(taskKind ?? ""))
            return (false, $"unknown local-model task kind '{taskKind}' — refused (kinds are script_draft, session_summary, worklog)", null);
        if (_model is null)
            return (false, "no local model is hosted on this hub — local AI functions refuse rather than reaching for a remote model", null);
        if (string.IsNullOrWhiteSpace(prompt))
            return (false, "local-model task carries an empty prompt — refused", null);
        var text = _model.Complete(taskKind, prompt);
        var unsigned = new SignedModelOutput(taskKind, _model.Name, SignedModelOutput.HashPrompt(prompt),
            text, CustomerCommandKeyRing.KeyIdFor(_signer.PublicKey), "", now);
        var sig = _signer.Sign(Encoding.UTF8.GetBytes(SignedModelOutput.Canonical(unsigned)));
        return (true, $"local model '{_model.Name}' produced a signed {taskKind} output",
            unsigned with { SignatureBase64 = Convert.ToBase64String(sig) });
    }

    /// <summary>Verify a signed output against the hub's customer
    /// PUBLIC key: task, model, prompt binding, output bytes, and
    /// signature must all agree. Tampering with any field verifies
    /// FALSE.</summary>
    public static bool Verify(SignedModelOutput? output, byte[] hubPublicKey)
    {
        if (output is null || hubPublicKey is null || hubPublicKey.Length != 32) return false;
        if (output.KeyId != CustomerCommandKeyRing.KeyIdFor(hubPublicKey)) return false;
        try
        {
            var sig = Convert.FromBase64String(output.SignatureBase64 ?? "");
            return Ed25519.Verify(hubPublicKey, Encoding.UTF8.GetBytes(SignedModelOutput.Canonical(output)), sig);
        }
        catch { return false; }
    }
}

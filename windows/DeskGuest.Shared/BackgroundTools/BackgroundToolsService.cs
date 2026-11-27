using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.BackgroundTools;

// =====================================================================
// RMM-10 — the background toolset service + tool surface + the
// Backstage capability gate. (D38 fix pass applied — see the
// per-finding notes inline, marked "D38 F<n>".)
//
// GATE ORDER for every background action, every time, re-read per
// call (the CameraViewService discipline):
//   1. Device facts resolve — policy cannot be evaluated without
//      them; fail closed.
//   2. TOTAL POLICY CONTROL: the master setting
//      `rmm.background_tools.enabled` must be effectively TRUE for
//      this device, and the per-tool setting must not disable this
//      tool. OFF refuses — and OFF also removes the tool from the
//      tool SURFACE entirely (see BackgroundToolSurface): the
//      capability does not exist, it does not merely refuse.
//   3. PAIRING SCOPE: the pairing must hold the dedicated
//      `background_tools` scope (Scopes.BackgroundTools). A pairing
//      holding full session scopes (observe/drive/shell/admin) but
//      not this one is refused — sessions and background rights are
//      independent grants, in both directions.
//   4. RMM-03 SIGNED BINDING (D38 F1/F2): when a signed-command gate
//      is wired, a hub-initiated call MUST present an envelope
//      (class background_action) that verifies, is addressed to THIS
//      device (envelope audience), and whose signed payload binds
//      the tool AND the target (pid / service / path / key+value /
//      kit+args hash) — what runs is exactly what was signed, target
//      included. 'Local' is a positive origin fact on the call
//      context (LocalOrigin), never the absence of an envelope: a
//      non-local call with no envelope refuses when a gate is
//      wired. An envelope presented with no gate wired refuses by
//      name — never a silent downgrade. The audit posture names
//      which of these actually happened (signed / local_origin /
//      unsigned_no_gate_wired) so the record can tell them apart.
//   5. PROTECTED TARGETS: DeskGuest's own consent surface (agent /
//      presence / watchdog processes + services — checked on the
//      RESOLVED identity, not the caller's string — DeskGuest's protected
//      registry keys incl. alias forms, and DeskGuest's own files)
//      refuses unconditionally — policy and scope cannot override.
//   6. AUDIT FIRST: the action's start entry is chained BEFORE the
//      executor is touched (D38 F11: resolution reads happen inside
//      the audited body), and its outcome entry (completed / failed
//      / error / refused) is chained after — including when the
//      executor throws. There is no path that executes without a
//      chained event, and every refusal above is chained too.
//
// SESSION HISTORY (the endpoint user's window into background
// work): every action — executed, refused, or errored — appends a
// BackgroundHistoryEntry to the device's own session history,
// BOUNDED (D38 F10: a capped ring, so a hostile pairing cannot
// flood memory with refusals; the chained audit remains the
// unbounded record). "No visible session" means the user keeps
// their desktop; it never means the work is invisible in the
// record. The presence surface reads this history (see
// DescribePresenceActivity — action counts exclude refusals, which
// are reported separately).
//
// AUDIT FIELD INTEGRITY (D38 F12): caller-controlled target text is
// escaped before it enters a chained detail string (AuditText.Esc:
// spaces and '=' cannot survive, so a target cannot inject fake
// key=value fields into the record).
// =====================================================================

/// <summary>Escaping for caller-controlled text entering audit
/// detail strings (D38 F12). Space, '=' and control characters are
/// replaced, so injected text can never pose as a separate
/// key=value field of the chained entry.</summary>
internal static class AuditText
{
    public static string Esc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c == '=') sb.Append("%3D");
            else if (c <= ' ' || c == '\u007f') sb.Append('_');
            else sb.Append(c);
        }
        return sb.ToString();
    }
}

/// <summary>One entry in the device's own session history for
/// background work: what ran (or was attempted), by whom, when, and
/// how it ended. Backstage sessions file entries here too — hidden
/// from the desktop, never from this history.</summary>
public sealed record BackgroundHistoryEntry(
    string EntryId, string Kind, string Tool, string ActorName, string PairingId,
    string Target, string Outcome, DateTimeOffset AtUtc, string? SessionId);

public sealed class BackgroundToolSurface
{
    private readonly ManagementPolicyEngine _policy;

    public BackgroundToolSurface(ManagementPolicyEngine policy) =>
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));

    /// <summary>The tools that EXIST for this pairing on this device
    /// right now. Policy OFF ⇒ the background toolset contributes
    /// NOTHING to the surface (not a list of refusing stubs). Scope
    /// missing ⇒ likewise nothing: a session-only pairing does not
    /// even see the tools it may not call. Per-tool policy disables
    /// remove individual tools.</summary>
    public IReadOnlyList<string> AvailableTools(IDeviceFacts facts, IReadOnlySet<string> pairingScopes)
    {
        if (facts is null) return Array.Empty<string>();
        if (pairingScopes is null || !pairingScopes.Contains(Scopes.BackgroundTools))
            return Array.Empty<string>();
        if (!_policy.IsEnabled(facts, BackgroundPolicyKeys.ToolsEnabled))
            return Array.Empty<string>();
        return BackgroundTools.All
            .Where(t => !IsToolDisabled(facts, t))
            .ToList();
    }

    public bool IsToolDisabled(IDeviceFacts facts, string tool)
    {
        var eff = _policy.ComputeEffective(facts).Get(BackgroundPolicyKeys.ToolEnabled(tool));
        return eff is not null && bool.TryParse(eff.Value, out var v) && !v;
    }

    public bool ToolsetEnabled(IDeviceFacts facts) =>
        facts is not null && _policy.IsEnabled(facts, BackgroundPolicyKeys.ToolsEnabled);
}

public sealed class BackgroundToolsService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly IBackgroundExecutor _executor;
    private readonly IKitByteStore _kitBytes;
    private readonly SignedCommandGate? _commandGate;
    private readonly Func<DateTimeOffset> _now;
    private readonly BackgroundToolSurface _surface;

    private readonly Dictionary<string, ToolboxKit> _kits = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _kitVersions = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<BackgroundHistoryEntry> _history = new();
    private readonly object _gate = new();

    /// <summary>D38 F10: the in-memory session history is a bounded
    /// ring — beyond this many entries the oldest fall off (the
    /// hash-chained audit log is the unbounded record of record).
    /// Without the cap, any pairing — even a scopeless one, via
    /// refusal paths — could grow this list without limit.</summary>
    public const int MaxHistoryEntries = 1000;

    public BackgroundToolsService(
        ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        IBackgroundExecutor executor, IKitByteStore kitBytes,
        SignedCommandGate? commandGate = null, Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _kitBytes = kitBytes ?? throw new ArgumentNullException(nameof(kitBytes));
        _commandGate = commandGate;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _surface = new BackgroundToolSurface(policy);
    }

    public BackgroundToolSurface Surface => _surface;

    public IReadOnlyList<BackgroundHistoryEntry> SessionHistory
    {
        get { lock (_gate) return _history.ToList(); }
    }

    public IReadOnlyList<ToolboxKit> Kits
    {
        get { lock (_gate) return _kits.Values.OrderBy(k => k.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>What the endpoint's presence surface can honestly
    /// say about background activity: that it happened, how much,
    /// and when last — the activity is never hidden from the person
    /// at the machine, only from their desktop while it runs.
    /// D38 F10: TotalActions counts ACTIONS (started/completed/
    /// failed/errored work); refusals are reported separately as
    /// RefusedActions and never inflate the activity count.</summary>
    public (int TotalActions, DateTimeOffset? LastAtUtc, int BackstageSessions, int RefusedActions) DescribePresenceActivity()
    {
        lock (_gate)
        {
            var backstage = _history.Where(h => h.Kind == "backstage" && h.SessionId is not null)
                .Select(h => h.SessionId).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var refused = _history.Count(h => h.Outcome.StartsWith("refused", StringComparison.Ordinal));
            return (_history.Count - refused, _history.Count == 0 ? null : _history.Max(h => h.AtUtc), backstage, refused);
        }
    }

    internal void FileHistory(BackgroundHistoryEntry entry)
    {
        lock (_gate)
        {
            _history.Add(entry);
            // D38 F10: bounded ring — oldest entries fall off.
            while (_history.Count > MaxHistoryEntries) _history.RemoveAt(0);
        }
    }

    // ---- gate plumbing ---------------------------------------------------

    /// <summary>An action body throws this when the RESOLVED target
    /// turns out to be DeskGuest's consent surface (D38 F7/F8/F11): the
    /// resolution read happens inside the audit-first body, and the
    /// throw is converted by Execute into a chained refusal.</summary>
    private sealed class ProtectedRefusalException(string what) : Exception(what)
    {
        public string What => Message;
    }

    /// <summary>An action body throws this for a post-gate refusal
    /// discovered inside the audited body (e.g. unknown pid/service
    /// after resolution): converted by Execute into a chained
    /// refusal, never a silent or unaudited path.</summary>
    private sealed class ActionRefusalException(string reason) : Exception(reason)
    {
        public string Reason => Message;
    }

    private BackgroundActionResult Refuse(BackgroundCallContext ctx, string tool, string target, string reason, DateTimeOffset now)
    {
        // BD-SHARED-RMM-1 F7: reason and pairing are
        // attacker-influenceable (kit ids, service names, caller
        // pairing strings flow into refusal reasons) and were
        // appended RAW into the hash-chained audit detail — a
        // value containing " outcome=allowed" forged fields in
        // the chain's own text. Everything interpolated is Esc'd.
        _audit.Append("background_action_refused", ctx.ActorName ?? "unknown",
            $"tool={tool} device={ctx.DeviceId} target={AuditText.Esc(target)} pairing={AuditText.Esc(ctx.PairingId)} reason={AuditText.Esc(reason)}", now);
        FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "background_action",
            tool, ctx.ActorName ?? "unknown", ctx.PairingId ?? "", target, $"refused: {reason}", now, null));
        return new BackgroundActionResult(false, reason);
    }

    /// <summary>Runs gates 1–4. On success returns the facts and
    /// sets <paramref name="posture"/> to the audit posture that
    /// actually held (signed / local_origin / unsigned_no_gate_wired
    /// — D38 F2: the record can tell a verified signed call from an
    /// unsigned one). On any refusal returns null after chaining
    /// the refusal. Gate 5 (protected targets) is per-action and
    /// runs inside Execute's audited body.
    /// <paramref name="binding"/> is the signed-target binding
    /// (D38 F1): field name → the exact value the signed payload
    /// must carry for this call (pid, service, path, key, …).</summary>
    private IDeviceFacts? GateCommon(BackgroundCallContext ctx, string tool, string target, DateTimeOffset now,
        out BackgroundActionResult refusal, out string posture,
        IReadOnlyDictionary<string, string>? binding = null)
    {
        refusal = null!;
        posture = "unsigned_no_gate_wired";
        var facts = _factsByDevice(ctx.DeviceId);
        if (facts is null)
        {
            refusal = Refuse(ctx, tool, target, $"no device facts for '{ctx.DeviceId}' — refused (fail closed)", now);
            return null;
        }
        if (!_surface.ToolsetEnabled(facts))
        {
            refusal = Refuse(ctx, tool, target,
                $"background tools are disabled by policy ({BackgroundPolicyKeys.ToolsEnabled}) — refused; the toolset does not exist on this device until policy enables it", now);
            return null;
        }
        if (_surface.IsToolDisabled(facts, tool))
        {
            refusal = Refuse(ctx, tool, target,
                $"tool '{tool}' is disabled by policy ({BackgroundPolicyKeys.ToolEnabled(tool)}) — refused", now);
            return null;
        }
        if (ctx.PairingScopes is null || !ctx.PairingScopes.Contains(Scopes.BackgroundTools))
        {
            refusal = Refuse(ctx, tool, target,
                $"pairing lacks the '{Scopes.BackgroundTools}' scope — refused (background rights are a separate grant from session scopes)", now);
            return null;
        }
        if (ctx.SignedCommandJson is not null && _commandGate is not null)
        {
            var envelope = SignedCommandEnvelope.FromJson(ctx.SignedCommandJson);
            if (envelope is null)
            {
                refusal = Refuse(ctx, tool, target,
                    "signed command envelope is malformed — refused (fail closed)", now);
                return null;
            }
            var verdict = _commandGate.Authorize(envelope, now, SignedCommandClasses.BackgroundAction);
            if (!verdict.Allowed)
            {
                refusal = Refuse(ctx, tool, target, $"signed command refused: {verdict.Reason}", now);
                return null;
            }
            // D38 F1 (device binding): the envelope must be ADDRESSED
            // to this device — its signed audience names this
            // endpoint, not another and not the fleet at large.
            if (!string.Equals((envelope.Audience ?? "").Trim(), ctx.DeviceId ?? "", StringComparison.Ordinal))
            {
                refusal = Refuse(ctx, tool, target,
                    $"signed envelope audience '{envelope.Audience}' does not name this device '{ctx.DeviceId}' — refused (a signed command runs only on the endpoint it was minted for)", now);
                return null;
            }
            // D38 F1 (target binding): the SIGNED payload binds the
            // tool AND every target field of this call. One genuine
            // envelope for one target authorizes nothing else.
            string? signedTool = null;
            var payloadFields = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(verdict.Payload!));
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in doc.RootElement.EnumerateObject())
                        payloadFields[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                            ? prop.Value.GetString() ?? ""
                            : prop.Value.GetRawText();
                    if (doc.RootElement.TryGetProperty("tool", out var t) && t.ValueKind == JsonValueKind.String)
                        signedTool = t.GetString();
                }
            }
            catch { /* fall through to the mismatch refusal */ }
            if (!string.Equals(signedTool, tool, StringComparison.Ordinal))
            {
                refusal = Refuse(ctx, tool, target,
                    $"signed payload names tool '{signedTool ?? "(none)"}', not '{tool}' — refused (what runs is exactly what was signed)", now);
                return null;
            }
            if (binding is not null)
            {
                foreach (var (field, expected) in binding)
                {
                    if (!payloadFields.TryGetValue(field, out var actual) ||
                        !string.Equals(actual, expected, StringComparison.Ordinal))
                    {
                        refusal = Refuse(ctx, tool, target,
                            $"signed payload does not bind {field}='{expected}' for this call (payload carries '{actual ?? "(absent)"}') — refused (what runs is exactly what was signed, target included)", now);
                        return null;
                    }
                }
            }
            posture = "signed";
        }
        else if (ctx.SignedCommandJson is not null && _commandGate is null)
        {
            refusal = Refuse(ctx, tool, target,
                "a signed command was presented but no customer command key is configured on this endpoint — refused (named, never silently downgraded)", now);
            return null;
        }
        else if (_commandGate is not null && !ctx.LocalOrigin)
        {
            // D38 F2: a gate is wired and the call carries NO
            // envelope. That is 'local' only if the call's origin
            // was positively established as endpoint-local — the
            // absence of an envelope establishes nothing, and a
            // hub-relayed caller could simply drop the envelope.
            refusal = Refuse(ctx, tool, target,
                "signed-command gate is wired but this call presents no envelope and its origin is not established as local — refused (dropping the envelope cannot skip the signed-command gate)", now);
            return null;
        }
        else if (_commandGate is not null)
        {
            posture = "local_origin";
        }
        return facts;
    }

    /// <summary>Audit-first execution wrapper: chains the start
    /// entry BEFORE the executor runs, chains the outcome after,
    /// and converts an executor throw into a chained error entry +
    /// a failed result. Protected/not-found discoveries made inside
    /// the body (after resolution reads) become chained refusals.
    /// No path executes unaudited (D38 F11).</summary>
    private BackgroundActionResult Execute(BackgroundCallContext ctx, string tool, string target,
        DateTimeOffset now, string posture, Func<(bool Ok, string Detail, string? Output)> body)
    {
        _audit.Append("background_action_started", ctx.ActorName ?? "unknown",
            $"tool={tool} device={ctx.DeviceId} target={AuditText.Esc(target)} pairing={ctx.PairingId} posture={posture}", now);
        try
        {
            var (ok, detail, output) = body();
            var bounded = output is null ? null : Redactor.RedactText(output.Length > 512 ? output[..512] : output);
            _audit.Append(ok ? "background_action_completed" : "background_action_failed", ctx.ActorName ?? "unknown",
                $"tool={tool} device={ctx.DeviceId} target={AuditText.Esc(target)} detail={AuditText.Esc(detail)}", _now());
            FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "background_action",
                tool, ctx.ActorName ?? "unknown", ctx.PairingId ?? "", target,
                ok ? "completed" : $"failed: {detail}", now, null));
            return new BackgroundActionResult(ok, detail, bounded);
        }
        catch (ProtectedRefusalException ex)
        {
            return ProtectedRefusal(ctx, tool, target, ex.What, _now());
        }
        catch (ActionRefusalException ex)
        {
            return Refuse(ctx, tool, target, ex.Reason, _now());
        }
        catch (Exception ex)
        {
            _audit.Append("background_action_error", ctx.ActorName ?? "unknown",
                $"tool={tool} device={ctx.DeviceId} target={AuditText.Esc(target)} error={ex.GetType().Name}: {AuditText.Esc(ex.Message)}", _now());
            FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "background_action",
                tool, ctx.ActorName ?? "unknown", ctx.PairingId ?? "", target,
                $"error: {ex.GetType().Name}", now, null));
            return new BackgroundActionResult(false, $"executor error ({ex.GetType().Name}): {ex.Message}");
        }
    }

    private BackgroundActionResult ProtectedRefusal(BackgroundCallContext ctx, string tool, string target, string what, DateTimeOffset now) =>
        Refuse(ctx, tool, target,
            $"{what} is part of DeskGuest's own consent surface — refused unconditionally (the toolset can never blind the endpoint's presence/STOP/audit)", now);

    private static Dictionary<string, string> Bind(params (string Field, string Value)[] fields) =>
        fields.ToDictionary(f => f.Field, f => f.Value, StringComparer.Ordinal);

    // ---- process manager ---------------------------------------------------

    public BackgroundActionResult KillProcess(BackgroundCallContext ctx, int pid)
    {
        var now = _now();
        var target = $"pid {pid}";
        if (GateCommon(ctx, BackgroundTools.ProcessKill, target, now, out var refusal, out var posture,
                Bind(("pid", pid.ToString(System.Globalization.CultureInfo.InvariantCulture)))) is null) return refusal;
        return Execute(ctx, BackgroundTools.ProcessKill, target, now, posture, () =>
        {
            // Resolution happens INSIDE the audited body (D38 F11):
            // no executor read precedes the chained start entry.
            var proc = _executor.GetProcess(pid);
            if (proc is null)
                throw new ActionRefusalException($"no process with pid {pid} — refused");
            // D38 F7/F8: protection judges the resolved INSTANCE
            // (image path), not the bare name.
            if (ProtectedTargets.IsProtectedProcessInstance(proc))
                throw new ProtectedRefusalException($"process '{proc.Name}' (pid {pid})");
            // D38 F8 (pid-reuse race): re-resolve immediately before
            // the kill and require the SAME identity (name + image
            // path) that passed the check — a pid recycled in
            // between is a different process and is not killed.
            var again = _executor.GetProcess(pid);
            if (again is null ||
                !string.Equals(again.Name, proc.Name, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(again.ImagePath ?? "", proc.ImagePath ?? "", StringComparison.OrdinalIgnoreCase))
                return (false, $"process identity at pid {pid} changed between check and kill — not killed (pid-reuse guard)", null);
            var r = _executor.KillProcess(pid);
            return (r.Ok, r.Detail, null);
        });
    }

    public BackgroundActionResult KillProcessTree(BackgroundCallContext ctx, int rootPid)
    {
        var now = _now();
        var target = $"tree of pid {rootPid}";
        if (GateCommon(ctx, BackgroundTools.ProcessKillTree, target, now, out var refusal, out var posture,
                Bind(("pid", rootPid.ToString(System.Globalization.CultureInfo.InvariantCulture)))) is null) return refusal;
        return Execute(ctx, BackgroundTools.ProcessKillTree, target, now, posture, () =>
        {
            var all = _executor.ListProcesses();
            // Duplicate pids in a snapshot must not throw the walk
            // (D38 F11): first record wins.
            var byPid = new Dictionary<int, BackgroundProcessInfo>();
            foreach (var p in all) byPid.TryAdd(p.Pid, p);
            if (!byPid.TryGetValue(rootPid, out var root))
                throw new ActionRefusalException($"no process with pid {rootPid} — refused");
            // Collect the whole tree FIRST (children before parents
            // at kill time). A protected process ANYWHERE in the
            // tree refuses the WHOLE kill — a partial tree kill that
            // stops just short of the protected node would still be
            // the toolset being used to corner the consent surface.
            var tree = new List<BackgroundProcessInfo>();
            var queue = new Queue<BackgroundProcessInfo>(); queue.Enqueue(root);
            var seen = new HashSet<int>();
            while (queue.Count > 0)
            {
                var p = queue.Dequeue();
                if (!seen.Add(p.Pid)) continue;
                tree.Add(p);
                foreach (var child in all.Where(c => c.ParentPid == p.Pid)) queue.Enqueue(child);
            }
            var protectedNode = tree.FirstOrDefault(p => ProtectedTargets.IsProtectedProcessInstance(p));
            if (protectedNode is not null)
                throw new ProtectedRefusalException(
                    $"tree contains DeskGuest process '{protectedNode.Name}' (pid {protectedNode.Pid})");
            var killed = 0;
            foreach (var p in tree.OrderByDescending(p => Depth(p, byPid)))
            {
                // D38 F8: re-verify identity at kill time — a pid
                // recycled since the snapshot is not the process
                // that was checked, and is skipped, not killed.
                var again = _executor.GetProcess(p.Pid);
                if (again is null ||
                    !string.Equals(again.Name, p.Name, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(again.ImagePath ?? "", p.ImagePath ?? "", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (_executor.KillProcess(p.Pid).Ok) killed++;
            }
            return (killed == tree.Count, $"killed {killed}/{tree.Count} processes in tree of pid {rootPid}", null);
        });

        static int Depth(BackgroundProcessInfo p, Dictionary<int, BackgroundProcessInfo> byPid)
        {
            var d = 0; var cur = p;
            while (byPid.TryGetValue(cur.ParentPid, out var parent) && d < 64) { d++; cur = parent; }
            return d;
        }
    }

    // ---- service manager -----------------------------------------------------

    private BackgroundActionResult ControlService(BackgroundCallContext ctx, string tool, string action, string serviceName)
    {
        var now = _now();
        var target = $"service '{serviceName}'";
        if (GateCommon(ctx, tool, target, now, out var refusal, out var posture,
                Bind(("service", serviceName ?? ""))) is null) return refusal;
        if (ProtectedTargets.IsProtectedService(serviceName))
            return ProtectedRefusal(ctx, tool, target, $"service '{serviceName}'", now);
        return Execute(ctx, tool, target, now, posture, () =>
        {
            // D38 F7: protection judges the RESOLVED service — the
            // executor resolves the caller's string (name OR display
            // name, ServiceController semantics) to the service's
            // identity, and BOTH its name and display name are
            // checked. Resolution reads happen inside the audited
            // body (D38 F11).
            var svc = _executor.GetService(serviceName);
            if (svc is null)
                throw new ActionRefusalException($"no service named '{serviceName}' — refused");
            if (ProtectedTargets.IsProtectedServiceInfo(svc))
                throw new ProtectedRefusalException($"service '{svc.Name}'");
            var r = _executor.ControlService(svc.Name, action);
            return (r.Ok, r.Detail, null);
        });
    }

    public BackgroundActionResult StartService(BackgroundCallContext ctx, string name) =>
        ControlService(ctx, BackgroundTools.ServiceStart, "start", name);
    public BackgroundActionResult StopService(BackgroundCallContext ctx, string name) =>
        ControlService(ctx, BackgroundTools.ServiceStop, "stop", name);
    public BackgroundActionResult RestartService(BackgroundCallContext ctx, string name) =>
        ControlService(ctx, BackgroundTools.ServiceRestart, "restart", name);


    /// <summary>BD-SHARED-RMM-1 F12: the resolved-path re-check
    /// inside the audited body. The pre-gate IsProtectedFilePath
    /// sees the caller's string; this sees where the path
    /// actually GOES (junction / symlink / 8.3 alias resolved by
    /// the executor). Unresolvable or resolved-into-a-protected-
    /// root ⇒ post-gate refusal, chained like every refusal.</summary>
    private void RefuseIfResolvedProtected(string tool, string path)
    {
        string? final;
        try { final = _executor.ResolveFinalPath(path); }
        catch { final = null; }
        if (final is null)
            throw new ActionRefusalException(
                $"path '{path}' could not be resolved to a final path — refused (an unresolvable path cannot be protection-checked)");
        if (ProtectedTargets.IsProtectedFilePath(final))
            throw new ActionRefusalException(
                $"path '{path}' resolves to '{final}', which is a protected DeskGuest target — refused (the consent surface defends itself on the resolved path, not only the caller's string)");
    }

    // ---- file browser ----------------------------------------------------------

    public BackgroundActionResult ListFiles(BackgroundCallContext ctx, string path)
    {
        var now = _now();
        if (GateCommon(ctx, BackgroundTools.FileList, path ?? "", now, out var refusal, out var posture,
                Bind(("path", path ?? ""))) is null) return refusal;
        // D38 F4: the file tools carry the same consent-surface
        // protection as every other path — listing DeskGuest's own roots
        // is refused too (the pairing store / audit layout is not
        // the file browser's to enumerate).
        if (ProtectedTargets.IsProtectedFilePath(path))
            return ProtectedRefusal(ctx, BackgroundTools.FileList, path ?? "", $"path '{path}'", now);
        return Execute(ctx, BackgroundTools.FileList, path ?? "", now, posture, () =>
        {
            RefuseIfResolvedProtected(BackgroundTools.FileList, path ?? "");
            var r = _executor.ListDirectory(path);
            var text = r.Ok ? JsonSerializer.Serialize(r.Entries.Select(e => new { name = e.Name, dir = e.IsDirectory, size = e.SizeBytes })) : null;
            return (r.Ok, r.Detail, text);
        });
    }

    public BackgroundActionResult ReadFile(BackgroundCallContext ctx, string path)
    {
        var now = _now();
        if (GateCommon(ctx, BackgroundTools.FileRead, path ?? "", now, out var refusal, out var posture,
                Bind(("path", path ?? ""))) is null) return refusal;
        // D38 F4: reading DeskGuest's own binaries/config/pairing/audit
        // through the file browser is the registry editor's refused
        // read by another door — refused here too.
        if (ProtectedTargets.IsProtectedFilePath(path))
            return ProtectedRefusal(ctx, BackgroundTools.FileRead, path ?? "", $"path '{path}'", now);
        return Execute(ctx, BackgroundTools.FileRead, path ?? "", now, posture, () =>
        {
            RefuseIfResolvedProtected(BackgroundTools.FileRead, path ?? "");
            var r = _executor.ReadFile(path);
            var content = r.Content is { Length: > 8192 } c ? c[..8192] : r.Content;
            return (r.Ok, r.Detail, content);
        });
    }

    public BackgroundActionResult DeleteFile(BackgroundCallContext ctx, string path)
    {
        var now = _now();
        if (GateCommon(ctx, BackgroundTools.FileDelete, path ?? "", now, out var refusal, out var posture,
                Bind(("path", path ?? ""))) is null) return refusal;
        // D38 F4: file_delete can no longer delete DeskGuest's binaries,
        // config, pairing store or audit files.
        if (ProtectedTargets.IsProtectedFilePath(path))
            return ProtectedRefusal(ctx, BackgroundTools.FileDelete, path ?? "", $"path '{path}'", now);
        return Execute(ctx, BackgroundTools.FileDelete, path ?? "", now, posture,
            () =>
            {
                RefuseIfResolvedProtected(BackgroundTools.FileDelete, path ?? "");
                var r = _executor.DeleteFile(path); return (r.Ok, r.Detail, null);
            });
    }

    // ---- registry editor ---------------------------------------------------------

    public BackgroundActionResult RegistryGet(BackgroundCallContext ctx, string key, string valueName)
    {
        var now = _now();
        var target = $"{key} :: {valueName}";
        if (GateCommon(ctx, BackgroundTools.RegistryGet, target, now, out var refusal, out var posture,
                Bind(("key", key ?? ""), ("value_name", valueName ?? ""))) is null) return refusal;
        if (ProtectedTargets.IsProtectedRegistryKey(key))
            return ProtectedRefusal(ctx, BackgroundTools.RegistryGet, target, $"registry key '{key}'", now);
        return Execute(ctx, BackgroundTools.RegistryGet, target, now, posture,
            () => { var r = _executor.RegistryGet(key, valueName); return (r.Ok, r.Detail, r.Value); });
    }

    public BackgroundActionResult RegistrySet(BackgroundCallContext ctx, string key, string valueName, string value)
    {
        var now = _now();
        var target = $"{key} :: {valueName}";
        if (GateCommon(ctx, BackgroundTools.RegistrySet, target, now, out var refusal, out var posture,
                Bind(("key", key ?? ""), ("value_name", valueName ?? ""), ("value", value ?? ""))) is null) return refusal;
        // D38 F3: write-level protection — the key (alias-canonical:
        // ControlSet00x, WOW6432Node, HKU\<SID>, IFEO) AND Run-key
        // launch entries pointing at DeskGuest binaries.
        if (ProtectedTargets.IsProtectedRegistryWrite(key, valueName, value))
            return ProtectedRefusal(ctx, BackgroundTools.RegistrySet, target, $"registry key '{key}'", now);
        return Execute(ctx, BackgroundTools.RegistrySet, target, now, posture,
            () => { var r = _executor.RegistrySet(key, valueName, value); return (r.Ok, r.Detail, null); });
    }

    public BackgroundActionResult RegistryDelete(BackgroundCallContext ctx, string key, string valueName)
    {
        var now = _now();
        var target = $"{key} :: {valueName}";
        if (GateCommon(ctx, BackgroundTools.RegistryDelete, target, now, out var refusal, out var posture,
                Bind(("key", key ?? ""), ("value_name", valueName ?? ""))) is null) return refusal;
        if (ProtectedTargets.IsProtectedRegistryWrite(key, valueName, null))
            return ProtectedRefusal(ctx, BackgroundTools.RegistryDelete, target, $"registry key '{key}'", now);
        return Execute(ctx, BackgroundTools.RegistryDelete, target, now, posture,
            () => { var r = _executor.RegistryDelete(key, valueName); return (r.Ok, r.Detail, null); });
    }

    // ---- kits -----------------------------------------------------------------------

    /// <summary>Admit a kit definition. D38 F5: admission is itself
    /// a background act and passes the SAME gates as every other
    /// action (device facts → policy → dedicated scope → signed
    /// binding when a gate is wired) — previously anyone could
    /// admit anything and the hash pin only proved the bytes matched
    /// whatever an unauthorized caller chose. Validation is
    /// whole-kit; revision discipline is monotonic per id (a
    /// same-version redefinition with different content refuses —
    /// a kit definition cannot be swapped under its own version).
    /// The admitted copy is frozen; admission and refusals are
    /// chained audit events.</summary>
    public (bool Ok, string Reason) AdmitKit(BackgroundCallContext ctx, ToolboxKit kit)
    {
        var now = _now();
        var actor = ctx?.ActorName ?? "unknown";
        if (kit is null)
        {
            _audit.Append("background_kit_refused", actor, "kit=(null) reason=no kit — refused", now);
            return (false, "no kit — refused");
        }
        // BD-SHARED-RMM-1 F6: admission is BOUND like every other
        // gated act — the signed envelope (when a gate is wired)
        // must name this kit id, this version and this content
        // hash. It previously bound nothing, so a command signed
        // for any other purpose authorized admitting any kit.
        if (GateCommon(ctx, BackgroundTools.KitAdmit, $"kit {kit.Id}", now, out var refusal, out _,
                Bind(("kit_id", kit.Id), ("version", kit.Version.ToString()),
                     ("content_hash", kit.ContentHash))) is null)
            return (false, refusal.Detail);
        // F6 ownership: a PERSONAL kit may be admitted only by
        // its owning pairing (OwnerId is the pairing id, D38 F9);
        // a SHARED kit changes what every pairing may run, so it
        // requires the dedicated kit-admin scope.
        if (kit.OwnerKind == KitOwnerKinds.Personal &&
            !string.Equals(kit.OwnerId, ctx.PairingId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("background_kit_refused", actor,
                $"kit={AuditText.Esc(kit.Id)} reason=personal kit owned by pairing '{AuditText.Esc(kit.OwnerId)}' — admission refused for this pairing", now);
            return (false, $"personal kit '{kit.Id}' is owned by another pairing — admission refused");
        }
        if (kit.OwnerKind == KitOwnerKinds.Shared &&
            (ctx.PairingScopes is null || !ctx.PairingScopes.Contains(Scopes.KitAdmin)))
        {
            _audit.Append("background_kit_refused", actor,
                $"kit={AuditText.Esc(kit.Id)} reason=shared-kit admission requires the '{Scopes.KitAdmin}' scope — refused", now);
            return (false, $"admitting a shared kit requires the '{Scopes.KitAdmin}' scope — refused");
        }
        var invalid = kit.Validate();
        if (invalid is not null)
        {
            _audit.Append("background_kit_refused", actor, $"kit={AuditText.Esc(kit.Id)} reason={invalid}", now);
            return (false, invalid);
        }
        lock (_gate)
        {
            if (_kitVersions.TryGetValue(kit.Id, out var current))
            {
                if (kit.Version < current)
                {
                    _audit.Append("background_kit_refused", actor,
                        $"kit={AuditText.Esc(kit.Id)} reason=version {kit.Version} is stale (current {current}) — refused", now);
                    return (false, $"kit '{kit.Id}' version {kit.Version} is stale (current {current}) — refused");
                }
                if (kit.Version == current && _kits[kit.Id].ContentHash != kit.ContentHash)
                {
                    _audit.Append("background_kit_refused", actor,
                        $"kit={AuditText.Esc(kit.Id)} reason=same-version redefinition with different content — refused (a definition cannot be swapped under its own version)", now);
                    return (false, $"kit '{kit.Id}' version {kit.Version} already admitted with different content — refused");
                }
                if (kit.Version == current)
                    return (true, $"kit '{kit.Id}' v{kit.Version} already admitted (idempotent)");
            }
            _kits[kit.Id] = kit.FrozenCopy();
            _kitVersions[kit.Id] = kit.Version;
        }
        _audit.Append("background_kit_admitted", actor,
            $"kit={AuditText.Esc(kit.Id)} version={kit.Version} owner={kit.OwnerKind}:{AuditText.Esc(kit.OwnerId)} tools={kit.Tools.Count} hash={kit.ContentHash}", now);
        return (true, $"kit '{kit.Id}' v{kit.Version} admitted");
    }

    /// <summary>Run one tool from an ADMITTED kit. The bytes are
    /// fetched at run time and verified against the admitted
    /// definition's pin — a mismatch (poisoned cache, swapped
    /// binary) refuses and never executes. The definition consulted
    /// is the frozen admitted copy, never a caller-supplied one.
    /// D38 F5: the argument screening is a real target screen — the
    /// whole argument text is matched against protected processes /
    /// services / registry keys / file paths (incl. wildcard image
    /// patterns), and PID-shaped arguments are RESOLVED against the
    /// live process table inside the audited body: `taskkill /PID
    /// &lt;deskguest pid&gt;` refuses exactly like naming the process.
    /// (Named residual: a kit binary with a target compiled IN
    /// cannot be screened from its arguments — that is why kit
    /// ADMISSION is now a gated act, F5, and why kits remain
    /// hash-pinned definitions admitted by a scoped pairing.)
    /// D38 F9: personal-kit ownership matches the PAIRING ID only —
    /// the actor name is self-reported at pairing and matching on
    /// it widened access to anyone who named themselves the owner.</summary>
    public BackgroundActionResult RunKitTool(BackgroundCallContext ctx, string kitId, string toolName, string arguments)
    {
        var now = _now();
        arguments ??= ""; // D38 F11: null arguments never throw here
        var target = $"kit {kitId}/{toolName}";
        var argsHash = KitToolDefinition.HashBytes(Encoding.UTF8.GetBytes(arguments));
        if (GateCommon(ctx, BackgroundTools.KitRun, target, now, out var refusal, out var posture,
                Bind(("kit", kitId ?? ""), ("kit_tool", toolName ?? ""), ("args_sha256", argsHash))) is null) return refusal;
        ToolboxKit? kit;
        lock (_gate) _kits.TryGetValue(kitId ?? "", out kit);
        if (kit is null)
            return Refuse(ctx, BackgroundTools.KitRun, target, $"kit '{kitId}' is not admitted on this device — refused", now);
        // Personal kits run only for their owning PAIRING; shared
        // kits for any background-scoped pairing.
        if (kit.OwnerKind == KitOwnerKinds.Personal &&
            !string.Equals(kit.OwnerId, ctx.PairingId, StringComparison.OrdinalIgnoreCase))
            return Refuse(ctx, BackgroundTools.KitRun, target,
                $"kit '{kitId}' is a personal kit owned by pairing '{kit.OwnerId}' — refused for this pairing", now);
        var tool = kit.GetTool(toolName ?? "");
        if (tool is null)
            return Refuse(ctx, BackgroundTools.KitRun, target, $"kit '{kitId}' carries no tool '{toolName}' — refused", now);
        byte[]? bytes;
        try { bytes = _kitBytes.GetToolBytes(kit.Id, tool.Name); }
        catch (Exception ex)
        {
            // D38 F11: a throwing kit store is an audited error,
            // never an unaudited throw out of the service.
            return Execute(ctx, BackgroundTools.KitRun, target, now, posture, () => throw ex);
        }
        if (bytes is null)
            return Refuse(ctx, BackgroundTools.KitRun, target, $"no bytes for kit tool '{toolName}' in the kit store — refused", now);
        if (!tool.PinMatches(bytes))
            return Refuse(ctx, BackgroundTools.KitRun, target,
                $"kit tool '{toolName}' bytes do NOT match the admitted definition's sha256 pin — refused (hash-pinned governance: mismatched bytes never run)", now);
        // Text-level target screen over the WHOLE argument string
        // (D38 F5): names, wildcard patterns, registry keys, paths.
        if (ProtectedTargets.ArgumentsReferenceProtectedTarget(arguments))
            return ProtectedRefusal(ctx, BackgroundTools.KitRun, target, $"kit tool target '{arguments}'", now);
        return Execute(ctx, BackgroundTools.KitRun, target, now, posture, () =>
        {
            // PID-shaped arguments resolve against the live table
            // inside the audited body (D38 F5/F11): a bare pid
            // naming an DeskGuest process refuses like the name would.
            foreach (var tok in arguments.Split(new[] { ' ', '\t', '"', '\'', '=', ':', ';', ',', '(', ')', '/' },
                                                 StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(tok, out var pidArg) && pidArg > 0)
                {
                    var p = _executor.GetProcess(pidArg);
                    if (p is not null && ProtectedTargets.IsProtectedProcessInstance(p))
                        throw new ProtectedRefusalException($"kit tool argument pid {pidArg} ('{p.Name}')");
                }
            }
            var r = _executor.RunKitToolBinary(kit.Id, tool.Name, bytes, arguments);
            return (r.Ok, r.Detail, r.Output);
        });
    }
}

// =====================================================================
// THE BACKSTAGE HALF — capability gate only. NO streaming path is
// built here: IBackstageStreamSink is the seam the Block D session
// machinery would implement, and whether a hidden-desktop path
// should exist at all behind this gate is an owner-level design
// question this lane does not pre-empt.
//
// The gate's law (all, every start, re-read per start — and, per
// D38 F6, RE-READ DURING the session too):
//   1. POLICY: `rmm.backstage.enabled` effectively TRUE for the
//      device (seeded registry toggle, default OFF). OFF ⇒ the
//      capability does not exist in the tool surface at all
//      (BackstageService.ExistsInSurface), not merely a refusal.
//      A policy flip OFF mid-session ENDS the session at the next
//      act — "provably OFF" holds for the session's whole life,
//      not only at its start.
//   2. PERMISSION: the pairing holds the SEPARATE `backstage`
//      scope (Scopes.Backstage) — background_tools scope does NOT
//      imply it, session scopes do NOT imply it, admin does NOT
//      imply it. Ownership of a session is the PAIRING ID (D38
//      F9), never the self-reported actor name.
//   3. AUDIT + HISTORY + PRESENCE: the session record is created
//      and its start entry chained BEFORE the sink is touched;
//      every act is chained; the session files into the device's
//      session history at start (so even a crashed session is on
//      the record) and its close entry carries the duration. The
//      presence surface is PUSHED every lifecycle transition
//      (presencePush callback) as well as being pull-summarised by
//      DescribePresenceActivity — a live indicator, not only a
//      report nothing calls.
//   4. §7.10 STOP (D38 F6): the endpoint user can end ANY Backstage
//      session at any time via StopSession — the STOP path does
//      not need the owning actor, the owning pairing, or anyone's
//      permission. Sessions also carry a maximum duration; an
//      expired session ends itself at the next act.
// =====================================================================

/// <summary>The streaming seam for a hidden desktop session. This
/// lane ships NO implementation that streams a real desktop: the
/// recording double below is the only implementation, and it
/// streams nothing. A production sink is Block D machinery + a
/// owner-level design decision.</summary>
public interface IBackstageStreamSink
{
    (bool Ok, string Detail) OpenSession(string sessionId, string deviceId);
    void CloseSession(string sessionId);
}

/// <summary>Recording test double for IBackstageStreamSink. Opens
/// nothing, streams nothing — it records that the gate asked.</summary>
public sealed class RecordingBackstageStreamSink : IBackstageStreamSink
{
    public List<string> Opened { get; } = new();
    public List<string> Closed { get; } = new();
    public bool FailOpen { get; set; }

    public (bool Ok, string Detail) OpenSession(string sessionId, string deviceId)
    {
        if (FailOpen) return (false, "stream sink refused (recording double)");
        Opened.Add(sessionId);
        return (true, "session opened (recording double — no desktop is streamed by this lane)");
    }

    public void CloseSession(string sessionId) => Closed.Add(sessionId);
}

public sealed record BackstageSessionRecord(
    string SessionId, string DeviceId, string ActorName, string PairingId,
    DateTimeOffset StartedUtc, DateTimeOffset? EndedUtc,
    List<string> Acts)
{
    public bool IsActive => EndedUtc is null;
    public TimeSpan? Duration => EndedUtc is { } end ? end - StartedUtc : null;
}

public sealed record BackstageStartResult(bool Ok, BackstageSessionRecord? Session, string Reason);

public sealed class BackstageService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly IBackstageStreamSink _sink;
    private readonly BackgroundToolsService _historySink;
    private readonly Func<DateTimeOffset> _now;
    private readonly TimeSpan _maxSessionDuration;
    private readonly Action<string, string>? _presencePush;
    private readonly Dictionary<string, BackstageSessionRecord> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>D38 F6: no Backstage session lives longer than
    /// this; expiry is enforced at the next act (and the session
    /// ends itself rather than drifting on unbounded).</summary>
    public static readonly TimeSpan DefaultMaxSessionDuration = TimeSpan.FromHours(8);

    /// <param name="maxSessionDuration">Session lifetime cap
    /// (D38 F6); default 8h.</param>
    /// <param name="presencePush">D38 F6: live presence push —
    /// invoked with (event, sessionId) on every lifecycle
    /// transition (started / act / ended / stopped / expired /
    /// policy_revoked) so the endpoint's presence surface shows a
    /// LIVE indicator instead of waiting to be polled.</param>
    public BackstageService(
        ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        IBackstageStreamSink sink, BackgroundToolsService historySink,
        Func<DateTimeOffset>? now = null,
        TimeSpan? maxSessionDuration = null,
        Action<string, string>? presencePush = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _historySink = historySink ?? throw new ArgumentNullException(nameof(historySink));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _maxSessionDuration = maxSessionDuration ?? DefaultMaxSessionDuration;
        _presencePush = presencePush;
    }

    public IReadOnlyList<BackstageSessionRecord> Sessions
    {
        get { lock (_gate) return _sessions.Values.OrderBy(s => s.StartedUtc).ToList(); }
    }

    /// <summary>Does the Backstage capability EXIST for this pairing
    /// on this device? Policy OFF ⇒ it does not exist in the tool
    /// surface at all. (Start still re-checks everything.)</summary>
    public bool ExistsInSurface(IDeviceFacts facts, IReadOnlySet<string> pairingScopes) =>
        facts is not null && pairingScopes is not null &&
        pairingScopes.Contains(Scopes.Backstage) &&
        _policy.IsEnabled(facts, BackgroundPolicyKeys.BackstageEnabled);

    private BackstageStartResult Refuse(BackgroundCallContext ctx, string reason, DateTimeOffset now)
    {
        // BD-SHARED-RMM-1 F7: escaped like every other chained
        // detail — reason/pairing are caller-influenceable.
        _audit.Append("backstage_session_refused", ctx.ActorName ?? "unknown",
            $"device={ctx.DeviceId} pairing={AuditText.Esc(ctx.PairingId)} reason={AuditText.Esc(reason)}", now);
        _historySink.FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "backstage",
            "backstage_session", ctx.ActorName ?? "unknown", ctx.PairingId ?? "", ctx.DeviceId,
            $"refused: {reason}", now, null));
        return new BackstageStartResult(false, null, reason);
    }

    public BackstageStartResult StartSession(BackgroundCallContext ctx)
    {
        var now = _now();
        var facts = _factsByDevice(ctx.DeviceId);
        if (facts is null)
            return Refuse(ctx, $"no device facts for '{ctx.DeviceId}' — refused (fail closed)", now);
        if (!_policy.IsEnabled(facts, BackgroundPolicyKeys.BackstageEnabled))
            return Refuse(ctx,
                $"Backstage is disabled by policy ({BackgroundPolicyKeys.BackstageEnabled}) — refused; the capability does not exist on this device until org policy enables it (default OFF: a hidden desktop session sits in tension with DeskGuest's presence law, and the register records that tension rather than hiding it)", now);
        if (ctx.PairingScopes is null || !ctx.PairingScopes.Contains(Scopes.Backstage))
            return Refuse(ctx,
                $"pairing lacks the separate '{Scopes.Backstage}' scope — refused (Backstage is separately permissioned: background and session scopes do not imply it)", now);

        var sessionId = Guid.NewGuid().ToString("N");
        var record = new BackstageSessionRecord(sessionId, ctx.DeviceId, ctx.ActorName, ctx.PairingId, now, null, new List<string>());
        lock (_gate) _sessions[sessionId] = record;
        // Audit + history BEFORE the sink: a session that cannot be
        // recorded does not start, and a started session is in the
        // device's history from its first instant.
        _audit.Append("backstage_session_started", ctx.ActorName ?? "unknown",
            $"session={sessionId} device={ctx.DeviceId} pairing={ctx.PairingId} note=hidden from desktop, never from audit or session history", now);
        _historySink.FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "backstage",
            "backstage_session", ctx.ActorName ?? "unknown", ctx.PairingId ?? "", ctx.DeviceId,
            "started", now, sessionId));
        var (opened, detail) = _sink.OpenSession(sessionId, ctx.DeviceId);
        if (!opened)
        {
            _audit.Append("backstage_session_failed", ctx.ActorName ?? "unknown",
                $"session={sessionId} device={ctx.DeviceId} reason=stream sink refused: {detail}", _now());
            lock (_gate) _sessions[sessionId] = record with { EndedUtc = _now() };
            // BD-SHARED-RMM-1 F11: a failed start previously left
            // audit + a session record but NO history entry and NO
            // presence push — the endpoint's history showed
            // "started" for a session that never existed and the
            // live indicator never learned of the failure. The
            // failure is filed and pushed like every other
            // lifecycle transition.
            _historySink.FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "backstage",
                "backstage_session", ctx.ActorName ?? "unknown", ctx.PairingId ?? "", ctx.DeviceId,
                $"failed: stream sink refused: {detail}", _now(), sessionId));
            _presencePush?.Invoke("failed", sessionId);
            return new BackstageStartResult(false, null, $"stream sink refused: {detail}");
        }
        _presencePush?.Invoke("started", sessionId);
        return new BackstageStartResult(true, record, "backstage session started (gate model — no desktop streaming is built in this lane)");
    }

    /// <summary>Record one act inside a live Backstage session.
    /// Every act is a chained audit event — a session whose acts
    /// are not logged is exactly what the gate forbids. D38 F6/F9:
    /// the caller is the full call context — ownership is the
    /// PAIRING ID, and policy + scope are RE-CHECKED on every act:
    /// policy flipped OFF (or the pairing's backstage scope gone)
    /// ends the session here; a session past its maximum duration
    /// ends itself here.</summary>
    public bool RecordAct(BackgroundCallContext ctx, string sessionId, string act)
    {
        var now = _now();
        var actorName = ctx?.ActorName ?? "unknown";
        BackstageSessionRecord? session;
        lock (_gate) _sessions.TryGetValue(sessionId ?? "", out session);
        if (session is null || !session.IsActive)
        {
            _audit.Append("backstage_act_refused", actorName,
                $"session={sessionId} act={AuditText.Esc(act)} reason=no active backstage session with this id", now);
            return false;
        }
        if (!string.Equals(session.PairingId, ctx!.PairingId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("backstage_act_refused", actorName,
                $"session={sessionId} act={AuditText.Esc(act)} reason=pairing is not the session's owner", now);
            return false;
        }
        if (now - session.StartedUtc > _maxSessionDuration)
        {
            EndInternal(session, actorName, "expired", now,
                $"session exceeded its maximum duration of {_maxSessionDuration}");
            _audit.Append("backstage_act_refused", actorName,
                $"session={sessionId} act={AuditText.Esc(act)} reason=session expired (maximum duration reached) — session ended", now);
            return false;
        }
        var facts = _factsByDevice(session.DeviceId);
        if (facts is null || !_policy.IsEnabled(facts, BackgroundPolicyKeys.BackstageEnabled))
        {
            EndInternal(session, actorName, "policy_revoked", now,
                "Backstage policy is no longer enabled for this device");
            _audit.Append("backstage_act_refused", actorName,
                $"session={sessionId} act={AuditText.Esc(act)} reason=Backstage policy no longer enabled — session ended (provably OFF holds mid-session, not only at start)", now);
            return false;
        }
        if (ctx.PairingScopes is null || !ctx.PairingScopes.Contains(Scopes.Backstage))
        {
            EndInternal(session, actorName, "policy_revoked", now,
                "the owning pairing no longer holds the backstage scope");
            _audit.Append("backstage_act_refused", actorName,
                $"session={sessionId} act={AuditText.Esc(act)} reason=pairing no longer holds the '{Scopes.Backstage}' scope — session ended", now);
            return false;
        }
        lock (_gate) session.Acts.Add(act ?? "");
        // BD-SHARED-RMM-1 F7: the act text is caller-supplied and
        // was appended RAW (the refusal paths already Esc'd it —
        // the success path did not).
        _audit.Append("backstage_act", actorName,
            $"session={sessionId} device={session.DeviceId} act={AuditText.Esc(act)}", now);
        _presencePush?.Invoke("act", sessionId);
        return true;
    }

    /// <summary>End a session as its owning pairing (D38 F9:
    /// ownership is the pairing id). Ending is always permitted for
    /// the owner — it only ever reduces exposure, so no policy
    /// re-check gates it.</summary>
    public bool EndSession(BackgroundCallContext ctx, string sessionId)
    {
        var now = _now();
        var actorName = ctx?.ActorName ?? "unknown";
        BackstageSessionRecord? session;
        lock (_gate) _sessions.TryGetValue(sessionId ?? "", out session);
        if (session is null || !session.IsActive)
        {
            _audit.Append("backstage_session_end_refused", actorName,
                $"session={sessionId} reason=no active backstage session with this id", now);
            return false;
        }
        if (!string.Equals(session.PairingId, ctx!.PairingId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("backstage_session_end_refused", actorName,
                $"session={sessionId} reason=pairing is not the session's owner", now);
            return false;
        }
        EndInternal(session, actorName, "ended", now, null);
        return true;
    }

    /// <summary>§7.10 STOP (D38 F6): the endpoint user ends ANY live
    /// Backstage session, immediately, without the owning actor or
    /// pairing. This is the consent floor's own path — presence
    /// cannot be hidden and STOP cannot be disabled, so this method
    /// takes no context and checks no ownership: whoever is at the
    /// machine (or driving its STOP control) wins, always.</summary>
    public bool StopSession(string sessionId, string stoppedBy)
    {
        var now = _now();
        BackstageSessionRecord? session;
        lock (_gate) _sessions.TryGetValue(sessionId ?? "", out session);
        if (session is null || !session.IsActive)
        {
            _audit.Append("backstage_session_stop_refused", stoppedBy ?? "endpoint-user",
                $"session={sessionId} reason=no active backstage session with this id", now);
            return false;
        }
        EndInternal(session, stoppedBy ?? "endpoint-user", "stopped", now,
            $"stopped by the endpoint user ('{stoppedBy}') via the §7.10 STOP path");
        return true;
    }

    /// <summary>BD-SHARED-RMM-1 F11: expiry previously existed
    /// only as a check inside RecordAct — an idle session past its
    /// maximum duration stayed "active" (and the _sessions store
    /// grew) forever if nobody acted in it. The service's cycle
    /// calls this sweep: over-age live sessions end as "expired"
    /// through the same audited path as an act-driven expiry, and
    /// ended sessions are pruned beyond a retained tail so the
    /// store is bounded. Returns how many sessions the sweep
    /// expired.</summary>
    public int SweepExpired(DateTimeOffset now)
    {
        List<BackstageSessionRecord> expired;
        lock (_gate)
        {
            expired = _sessions.Values
                .Where(s => s.IsActive && now - s.StartedUtc > _maxSessionDuration).ToList();
            var ended = _sessions.Values.Where(s => !s.IsActive)
                .OrderByDescending(s => s.EndedUtc ?? s.StartedUtc).Skip(MaxRetainedEndedSessions).ToList();
            foreach (var e in ended) _sessions.Remove(e.SessionId);
        }
        foreach (var s in expired)
            EndInternal(s, "system", "expired", now,
                $"session exceeded its maximum duration of {_maxSessionDuration} (swept — no act arrived to end it)");
        return expired.Count;
    }

    /// <summary>Ended sessions retained for the surface after
    /// they end; older ones are pruned by SweepExpired (F11).</summary>
    public const int MaxRetainedEndedSessions = 128;

    private void EndInternal(BackstageSessionRecord session, string actorForAudit, string how, DateTimeOffset now, string? note)
    {
        _sink.CloseSession(session.SessionId);
        var ended = session with { EndedUtc = now };
        lock (_gate) _sessions[session.SessionId] = ended;
        _audit.Append("backstage_session_ended", actorForAudit,
            $"session={session.SessionId} device={session.DeviceId} acts={session.Acts.Count} durationSeconds={(long)(now - session.StartedUtc).TotalSeconds} how={how}" +
            (note is null ? "" : $" note={note}"), now);
        _historySink.FileHistory(new BackgroundHistoryEntry(Guid.NewGuid().ToString("N"), "backstage",
            "backstage_session", actorForAudit, session.PairingId, session.DeviceId,
            $"{how} after {(long)(now - session.StartedUtc).TotalSeconds}s, {session.Acts.Count} acts logged", now, session.SessionId));
        _presencePush?.Invoke(how, session.SessionId);
    }
}

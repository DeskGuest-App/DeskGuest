using System.Text.Json;
using System.Text.Json.Nodes;
using Acp.Core.Services;
using Acp.Shared.Audit;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Core.Mcp;

/// <summary>
/// Transport-independent MCP (streamable HTTP) request handling:
/// JSON-RPC in, JSON-RPC out. The HTTP layer is a thin adapter
/// (LaneHostManager); every call passes the policy choke point and is
/// written to the host audit log BEFORE the result returns
/// (DESIGN §3.1, §6.4). Pairing exchange lives on /pair (see
/// PairingHandler); everything here requires a bearer token.
/// </summary>
public sealed class McpHandler
{
    private readonly PairingService _pairings;
    private readonly PolicyEngine _policy;
    private readonly ToolRegistry _tools;
    private readonly IAuditLog _audit;
    private readonly CoreState _state;
    private readonly Modules.SessionManager _sessions;
    private readonly string _dataDir;
    private readonly SessionBudget _budgets = new();
    private readonly DataFlowLedger? _flows;
    // FR-134 / item (16): the Terms bundle this Core serves.
    // Null only in bare unit embedders (no Terms machinery: no
    // resource, no ack method, no session lock — the pre-FR-134
    // posture those embeds always had). Production wiring
    // (CoreRuntime) always passes TermsBundleProvider.Current.
    private readonly TermsBundle? _terms;

    /// <summary>U5: the per-agent data-flow ledger counted at this
    /// choke point (request/response bytes per pairing+tool,
    /// classified read/sent/changed). Exposed so session_status can
    /// show the owner the flows, cross-checked against the audit.
    /// Null only when the handler was built with no data dir and no
    /// injected ledger (bare unit embeds).</summary>
    public DataFlowLedger? Flows => _flows;

    /// <summary>U4: the session-budget counters enforced below at
    /// this choke point. Exposed so session_status can show the
    /// owner the caps, the counts and the pause state.</summary>
    public SessionBudget Budgets => _budgets;

    /// <summary>U2: the agent event bus + subscription store, wired
    /// by CoreRuntime. Null in unit embedders = no event channel
    /// (the subscribe tools are likewise unregistered there).</summary>
    public Shared.Sessions.AgentEventBus? Events { get; set; }

    /// <summary>W9: one per-action gate raise (design of record §3).
    /// ArgumentsJson is the call's argument JSON exactly as received
    /// — those bytes are what the GateSheet shows (OI-12) and what
    /// the module executes if the answer is Allow.</summary>
    public sealed record GateRaise(Pairing Pairing, string SessionId, string GateClass, string Tool, string ArgumentsJson, bool FromChat);

    /// <summary>W9: the per-action gate raiser, wired by CoreRuntime
    /// to the GateRequestBroker + the agent IPC channel. Returns one
    /// of GateAnswers (allow / deny / deny_and_end), or null when
    /// nobody answered in the window — null is a NO. Null delegate
    /// (unit embedders) = the standing gated deny stands, exactly
    /// the pre-W9 posture.</summary>
    public Func<GateRaise, CancellationToken, Task<string?>>? GateRaiser { get; set; }

    /// <summary>W9: teardown callback for a gate Deny-and-end,
    /// invoked by CallToolAsync ONLY AFTER the approval_deny_and_end
    /// audit entry is written and the session record is stopped —
    /// the audit-first ordering of GateSheetModel.DenyAndEndSteps is
    /// structural here, not a convention. CoreRuntime wires it to
    /// release held inputs, clear the acting-agent state and push
    /// the final presence directive.</summary>
    public Action<Modules.SessionRecord>? GateDenyAndEndTeardown { get; set; }

    /// <summary>W9 chat parity: chat tools are not a session (Android
    /// ChatToolHost rule) — they are exempt from the presence-session
    /// binding and the budget legs below, by name.</summary>
    internal static bool IsChatTool(string? name) => name is "chat_read" or "chat_post" or "chat_order";

    /// <summary>U2 SSE leg: stream this pairing's subscribed events
    /// as MCP notifications until the client disconnects or STOP
    /// comes into force — STOP kills the stream, it does not merely
    /// pause delivery. Delivery is filtered per event by
    /// AgentEventBus.ShouldDeliver (the pairing's own kind filter +
    /// the origin rule), enforced here at stream time. Returns
    /// false when the caller is unauthenticated or STOP is already
    /// in force (the HTTP layer answers 401/403).</summary>
    public async Task<bool> HandleEventStreamAsync(string? authorizationHeader,
        Func<string, CancellationToken, Task> writeAsync, CancellationToken ct, long lastEventId = 0, string? arrivalRung = null)
    {
        var pairing = Authenticate(authorizationHeader);
        if (pairing is null || Events is null) return false;
        // W97: the event stream is a connection too — the same
        // path policy refuses it before any byte is written.
        if (!PathAllowed(pairing, arrivalRung)) return false;
        if (_state.StopInForce) return false;
        var queue = new System.Collections.Concurrent.ConcurrentQueue<Shared.Sessions.AgentEvent>();
        using var wake = new SemaphoreSlim(0);
        Action<Shared.Sessions.AgentEvent> handler = evt => { queue.Enqueue(evt); try { wake.Release(); } catch { } };
        // Replay/live seam: snapshot the sequence BEFORE attaching,
        // so an event published during the replay is delivered once
        // (via the live queue), never twice.
        var attachSeq = Events.CurrentSequence;
        Events.Attach(pairing.Id, handler);
        try
        {
            // BD-SUPP-EVENTSUB F7: Last-Event-ID resume — replay
            // what the ring still holds for THIS pairing (filtered
            // by the same delivery rule) before live events flow.
            if (lastEventId > 0)
            {
                foreach (var evt in Events.ReplaySince(pairing.Id, lastEventId).Where(e => e.Sequence <= attachSeq))
                {
                    if (_state.StopInForce) break;
                    await WriteEventAsync(evt).ConfigureAwait(false);
                }
            }
            while (!ct.IsCancellationRequested)
            {
                if (_state.StopInForce) break; // STOP kills the stream
                // W107 (W106-verified C5, mid-stream half): the path
                // policy was checked ONCE at attach; a restriction
                // the owner lands mid-stream must bite the LIVE
                // stream too. On every loop cycle (the heartbeat
                // cadence, ~5 s) re-read the pairing's CURRENT
                // store record and re-check this stream's arrival
                // rung against it: a now-excluded rung — or a
                // pairing revoked/expired since attach — closes
                // the stream. PathAllowed audits the refusal with
                // the same pairing_connection_refused entry the
                // per-request choke point writes.
                var current = _pairings.CurrentPairing(pairing.Id);
                if (current is null) break;
                if (!PathAllowed(current, arrivalRung)) break;
                var signalled = await wake.WaitAsync(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
                if (!signalled && queue.IsEmpty)
                {
                    await writeAsync(": heartbeat\n\n", ct).ConfigureAwait(false);
                    continue;
                }
                while (queue.TryDequeue(out var evt))
                {
                    if (_state.StopInForce) break;
                    await WriteEventAsync(evt).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) { }
        finally { Events.Detach(pairing.Id, handler); }
        return true;

        async Task WriteEventAsync(Shared.Sessions.AgentEvent evt)
        {
            var payload = new JsonObject
            {
                ["jsonrpc"] = "2.0",
                ["method"] = "notifications/agent_event",
                ["params"] = new JsonObject
                {
                    ["kind"] = evt.Kind,
                    ["detail"] = evt.Detail,
                    ["at"] = evt.Utc.ToString("o"),
                    ["sequence"] = evt.Sequence
                }
            };
            // The SSE id IS the bus sequence: a reconnecting client
            // hands it back as Last-Event-ID and the ring replays
            // the gap; a jump in ids is how a loss past the ring
            // shows itself.
            var idLine = evt.Sequence > 0 ? $"id: {evt.Sequence}\n" : "";
            await writeAsync($"{idLine}data: {payload.ToJsonString()}\n\n", ct).ConfigureAwait(false);
        }
    }

    /// <summary>U4 TOTAL POLICY CONTROL seam: CoreRuntime wires this
    /// to the RMM-07 engine — it returns the effective caps for this
    /// device, or null when policy disables session budgets
    /// ("rmm.session_budget.enabled" = false). Unset (unit tests,
    /// embedders) = enabled with the named default caps.</summary>
    public Func<SessionBudgetCaps?>? BudgetCapsProvider { get; set; }

    private SessionBudgetCaps? ResolveBudgetCaps() =>
        BudgetCapsProvider is null ? new SessionBudgetCaps() : BudgetCapsProvider();

    /// <summary>U4 tripwire act: pause the session (never end it),
    /// make the reason presence-visible on the narration line, and
    /// write the audit entry BEFORE the denied result returns —
    /// a tripwire never fires silently.</summary>
    private void TripwirePause(Pairing pairing, string? toolName, string reason, string numbers)
    {
        Events?.Publish(Shared.Sessions.AgentEventKinds.Session, $"session_paused: {reason}", pairing.Id);
        _sessions.Pause(reason);
        _state.LastNarration = $"PAUSED — {reason}";
        try
        {
            _audit.Append(new AuditEntry(
                DateTimeOffset.UtcNow, "budget_tripwire", pairing.Id, pairing.AgentName, toolName, null,
                numbers, reason, "SYSTEM", null));
        }
        catch { _state.NoteAuditWriteFailure(); }
    }

    /// <param name="dataDir">The Core's data dir, carried into
    /// every tool execution context. Block H destruction find:
    /// this used to be hardcoded "" at the call site, and the one
    /// consumer — the self-restart watchdog's outcome file — wrote
    /// to the watchdog's working directory instead, so a restart
    /// outcome (and its failure alert) never reached the chained
    /// audit on the wire path.</param>
    public McpHandler(PairingService pairings, PolicyEngine policy, ToolRegistry tools, IAuditLog audit, CoreState state, Modules.SessionManager sessions, string dataDir = "", DataFlowLedger? flows = null, TermsBundle? terms = null)
    {
        _pairings = pairings;
        _policy = policy;
        _tools = tools;
        _audit = audit;
        _state = state;
        _sessions = sessions;
        _dataDir = dataDir;
        _terms = terms;
        // U5: default the ledger into the Core's data dir beside the
        // audit log, so production wiring needs no extra plumbing;
        // an injected ledger (tests, CoreRuntime sharing it with
        // the stream layer) wins.
        _flows = flows ?? (string.IsNullOrEmpty(dataDir)
            ? null
            : new DataFlowLedger(Path.Combine(dataDir, "data-flows.json")));
    }

    public sealed record McpResponse(int HttpStatus, string? Json);

    /// <summary>W97 / S09(b): the connection-path choke point.
    /// When the HTTP layer names the rung this request ARRIVED on
    /// (LaneHostManager always does for a real network arrival),
    /// the pairing's owner-set connection policy decides before
    /// anything else runs: an excluded rung does not authenticate
    /// — the request is refused and the refusal is audited; the
    /// policy never silently widens to another rung. An allowed
    /// arrival is noted as the pairing's live current rung. A null
    /// arrival rung means "not a network arrival" (in-process
    /// embedders and the Core's own ExecuteForPairingAsync engine
    /// path) — there is no path to police, and the caller is
    /// already inside the trust boundary.</summary>
    private bool PathAllowed(Pairing pairing, string? arrivalRung)
    {
        if (arrivalRung is null) return true;
        if (ConnectionPathPolicy.Allows(pairing.EffectiveConnection, arrivalRung))
        {
            _pairings.NoteConnection(pairing.Id, arrivalRung);
            return true;
        }
        _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairing.Id, pairing.AgentName,
            null, null, null,
            $"pairing_connection_refused:arrived over {ConnectionPathPolicy.PlainName(arrivalRung)}, " +
            $"which this pairing's connection setting excludes ({ConnectionPathPolicy.Describe(pairing.EffectiveConnection)})",
            "SYSTEM", null));
        return false;
    }

    /// <summary>Handle one JSON-RPC payload. Notifications return 202/null.</summary>
    public async Task<McpResponse> HandleAsync(string body, string? authorizationHeader, IReadOnlySet<string> approvedGateClasses, CancellationToken ct, string? arrivalRung = null)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(body); }
        catch (JsonException) { return new McpResponse(400, ErrorJson(null, -32700, "parse error")); }
        if (root is not JsonObject obj) return new McpResponse(400, ErrorJson(null, -32600, "invalid request"));

        // BD-WIN-CORE-1 F9: a non-string "method" is an invalid
        // request (-32600), never an unhandled exception.
        string? method;
        try { method = obj["method"]?.GetValue<string>(); }
        catch (InvalidOperationException) { return new McpResponse(400, ErrorJson(null, -32600, "invalid request: method must be a string")); }
        var id = obj["id"]?.DeepClone();

        // Notifications never get a response body.
        if (method is not null && method.StartsWith("notifications/"))
            return new McpResponse(202, null);

        var pairing = Authenticate(authorizationHeader);
        if (pairing is null)
            return new McpResponse(401, ErrorJson(id, -32001, "unauthorized: a valid pairing bearer token is required"));
        // W97: the bearer authenticated, but the PATH may still
        // refuse — same 401 surface as a bad token (the response
        // does not teach an excluded-path caller the policy; the
        // audit chain carries the truth for the owner).
        if (!PathAllowed(pairing, arrivalRung))
            return new McpResponse(401, ErrorJson(id, -32001, "unauthorized: this pairing may not connect over this path"));

        switch (method)
        {
            case "initialize":
            {
                var clientName = obj["params"]?["clientInfo"]?["name"]?.GetValue<string>();
                var capabilities = new JsonObject { ["tools"] = new JsonObject() };
                if (_terms is not null) capabilities["resources"] = new JsonObject();
                var result = new JsonObject
                {
                    ["protocolVersion"] = "2025-03-26",
                    ["capabilities"] = capabilities,
                    ["serverInfo"] = new JsonObject { ["name"] = "ACP-Windows", ["version"] = _state.CoreVersion },
                    ["_meta"] = new JsonObject { ["clientNameSeen"] = clientName }
                };
                // FR-134 / item (16): the Terms pointer rides the
                // handshake itself — a client learns at connect
                // where the Terms stand and what it must return.
                // A pairing whose acknowledgment is missing or
                // stale is (re)pushed the current Terms state on
                // this connection, and the push enters the audit
                // chain under the agent's name (item 16(c)/(d)).
                if (_terms is not null)
                {
                    result["instructions"] = _terms.Instructions;
                    if (!pairing.HasCurrentTermsAck(_terms.Sha256))
                    {
                        try
                        {
                            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairing.Id, pairing.AgentName,
                                null, null, null,
                                $"terms_pending_ack:agent holds {(pairing.TermsAckVersion is null ? "no acknowledgment" : $"v{pairing.TermsAckVersion}")}; " +
                                $"current Terms are v{_terms.Version} (sha256 {_terms.Sha256}), served in full at {TermsBundle.ResourceUri}; " +
                                "sessions are locked until the exact hash is acknowledged",
                                "SYSTEM", null));
                        }
                        catch { _state.NoteAuditWriteFailure(); }
                    }
                }
                return new McpResponse(200, ResultJson(id, result));
            }
            case "ping":
                return new McpResponse(200, ResultJson(id, new JsonObject()));
            case "tools/list":
            {
                // BD-WIN-CORE-1 F9: the list is filtered to the
                // calling pairing's scopes — an Observe-only agent
                // does not see shell/registry/background tools it
                // may never call. (Background tools additionally only
                // EXIST when policy-registered; see CoreRuntime.)
                var tools = new JsonArray();
                foreach (var d in _tools.Descriptors.Where(d => pairing.Scopes.Contains(d.RequiredScope)))
                {
                    tools.Add(new JsonObject
                    {
                        ["name"] = d.Name,
                        ["description"] = d.Description,
                        ["inputSchema"] = JsonNode.Parse(d.InputSchemaJson)
                    });
                }
                return new McpResponse(200, ResultJson(id, new JsonObject { ["tools"] = tools }));
            }
            case "tools/call":
                return await CallToolAsync(obj, id, pairing, approvedGateClasses, ct);
            // FR-134 / item (16)(e): the Terms stand as a permanent
            // MCP resource — listable and readable at any time,
            // before and after acknowledgment, always the FULL
            // current text (never a diff).
            case "resources/list":
            {
                var resources = new JsonArray();
                if (_terms is not null)
                {
                    resources.Add(new JsonObject
                    {
                        ["uri"] = TermsBundle.ResourceUri,
                        ["name"] = $"DeskGuest Terms of Service (v{_terms.Version})",
                        ["description"] = "The full Terms governing this pairing, with the agent rulebook. Acknowledge the exact sha256 via " + TermsBundle.AckMethod + ".",
                        ["mimeType"] = "text/markdown"
                    });
                }
                return new McpResponse(200, ResultJson(id, new JsonObject { ["resources"] = resources }));
            }
            case "resources/read":
            {
                string? uri;
                try { uri = obj["params"]?["uri"]?.GetValue<string>(); }
                catch (InvalidOperationException) { uri = null; }
                if (_terms is null || uri != TermsBundle.ResourceUri)
                    return new McpResponse(200, ErrorJson(id, -32602, $"unknown resource: {uri ?? "(none)"} — this host serves exactly one resource, {TermsBundle.ResourceUri}"));
                var contents = new JsonArray
                {
                    new JsonObject
                    {
                        ["uri"] = TermsBundle.ResourceUri,
                        ["mimeType"] = "text/markdown",
                        ["text"] = _terms.Text
                    }
                };
                return new McpResponse(200, ResultJson(id, new JsonObject { ["contents"] = contents }));
            }
            // FR-134 / item (16)(b): the protocol acknowledgment —
            // pairing completes only when the client returns the
            // EXACT current Terms hash.
            case TermsBundle.AckMethod:
                return AcknowledgeTerms(obj, id, pairing);
            default:
                return new McpResponse(200, ErrorJson(id, -32601, $"method not found: {method}"));
        }
    }

    /// <summary>FR-134 / item (16)(b)+(d): record the calling
    /// pairing's acknowledgment of the Terms. The returned version
    /// AND hash must equal the currently served bundle exactly —
    /// an ack of any other text (an old version, a corrupted copy,
    /// a guess) is refused and the refusal is audited, so the
    /// record never shows an acknowledgment that did not happen.
    /// A correct ack is written into the audit chain under the
    /// agent's own name with the version, the hash, and the time
    /// (the entry's timestamp) — the item (15)/(16) acceptance
    /// record.</summary>
    private McpResponse AcknowledgeTerms(JsonObject obj, JsonNode? id, Pairing pairing)
    {
        if (_terms is null)
            return new McpResponse(200, ErrorJson(id, -32601, $"method not found: {TermsBundle.AckMethod}"));
        string? version, hash;
        try
        {
            version = obj["params"]?["terms_version"]?.GetValue<string>();
            hash = obj["params"]?["terms_sha256"]?.GetValue<string>();
        }
        catch (InvalidOperationException)
        {
            return new McpResponse(200, ErrorJson(id, -32602, "invalid params: terms_version and terms_sha256 must be strings"));
        }
        if (!string.Equals(version, _terms.Version, StringComparison.Ordinal) ||
            !string.Equals(hash, _terms.Sha256, StringComparison.Ordinal))
        {
            try
            {
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairing.Id, pairing.AgentName,
                    null, null, null,
                    $"terms_ack_refused:agent returned version '{version ?? "(none)"}' sha256 '{hash ?? "(none)"}'; " +
                    $"this host serves Terms v{_terms.Version} sha256 {_terms.Sha256}",
                    "Agent", null));
            }
            catch { _state.NoteAuditWriteFailure(); }
            return new McpResponse(200, ErrorJson(id, -32602,
                $"terms acknowledgment refused: this host serves Terms v{_terms.Version} with sha256 {_terms.Sha256}. " +
                $"Read the full current text at {TermsBundle.ResourceUri} (resources/read) and acknowledge its exact version and hash."));
        }
        var (ok, ackUtc) = _pairings.RecordTermsAck(pairing.Id, _terms.Version, _terms.Sha256);
        if (!ok || ackUtc is null)
            return new McpResponse(200, ErrorJson(id, -32001, "terms acknowledgment refused: this pairing is no longer valid"));
        try
        {
            _audit.Append(new AuditEntry(ackUtc.Value, "system", pairing.Id, pairing.AgentName,
                null, null, null,
                $"terms_acknowledged:version={_terms.Version};sha256={_terms.Sha256}",
                "Agent", null));
        }
        catch { _state.NoteAuditWriteFailure(); }
        var result = new JsonObject
        {
            ["acknowledged"] = true,
            ["terms_version"] = _terms.Version,
            ["terms_sha256"] = _terms.Sha256,
            ["acknowledged_utc"] = ackUtc.Value.ToString("o")
        };
        return new McpResponse(200, ResultJson(id, result));
    }

    private async Task<McpResponse> CallToolAsync(JsonObject obj, JsonNode? id, Pairing pairing, IReadOnlySet<string> approvedGateClasses, CancellationToken ct)
    {
        var name = obj["params"]?["name"]?.GetValue<string>();
        var argsNode = obj["params"]?["arguments"] as JsonObject ?? new JsonObject();
        using var argsDoc = JsonDocument.Parse(argsNode.ToJsonString());
        var args = argsDoc.RootElement;

        var module = name is null ? null : _tools.Find(name);
        if (module is null)
            return new McpResponse(200, ErrorJson(id, -32602, $"unknown tool: {name}"));

        var started = DateTimeOffset.UtcNow;
        var preSessionId = _sessions.Current?.Id; // U4: the session this call may end (session_stop)
        var preSessionPairingId = _sessions.Current?.PairingId; // U5: whose session that is (a rider's calls never land on it)
        var session = _state.Session;
        // Protected-targets feed (M5): the session facts carry the
        // agent-reported foreground window title + process; the policy
        // engine matches them against the owner's protected set.
        var decision = _policy.Evaluate(pairing, module.Descriptor, args, session, _state.ComputeState(), approvedGateClasses,
            session.ForegroundTitle, session.ForegroundProcess);
        // FR-134 / item (16)(b)+(c): the Terms session lock, at
        // the same choke point as every other standing rule. A
        // pairing that has not acknowledged the CURRENT Terms
        // hash — never acked, or acked an older text before an
        // update — cannot start a session. Everything else stays
        // reachable (the agent must be able to read the Terms
        // resource and return the ack), so the lock names exactly
        // what is missing and how to clear it; the denial is
        // audited below like every other call outcome.
        if (decision.Allowed && name == "session_start" && _terms is not null && !pairing.HasCurrentTermsAck(_terms.Sha256))
        {
            decision = PolicyDecision.Deny(pairing.TermsAckHash is null
                ? $"terms_ack_required: this pairing has not acknowledged the DeskGuest Terms (current version {_terms.Version}, sha256 {_terms.Sha256}). " +
                  $"Read the full text at resource {TermsBundle.ResourceUri} and return the protocol acknowledgment ({TermsBundle.AckMethod} with the exact terms_version and terms_sha256); sessions stay locked until then"
                : $"terms_update_pending: this pairing acknowledged Terms v{pairing.TermsAckVersion}, but the current Terms are v{_terms.Version} (sha256 {_terms.Sha256}). " +
                  $"The full current text — never a diff — is at resource {TermsBundle.ResourceUri}; re-acknowledge its exact hash via {TermsBundle.AckMethod} before the next session");
        }
        // W9 per-action gate (design of record §3, live caller): a
        // call denied ONLY by the sensitive-action gate leg, in a
        // live session owned by this pairing, raises the gate at the
        // endpoint instead of dying on the standing deny — the
        // person at the machine decides THIS action. A class the
        // owner has standing-approved never reaches here (Evaluate
        // allowed it). Every other deny (scope, STOP, protected
        // target, the NEVER credential rule) stands untouched: the
        // gate can only ever answer the gate leg's own question.
        if (!decision.Allowed && GateRaiser is not null
            && decision.DenyReason is { } gateDeny && gateDeny.StartsWith("gated:", StringComparison.Ordinal)
            && module.Descriptor.GateClass is { } gateClass
            && _sessions.Current is { } gateSession
            && string.Equals(gateSession.PairingId, pairing.Id, StringComparison.Ordinal))
        {
            decision = await RaiseGateAsync(pairing, module, gateClass, argsNode.ToJsonString(), args, session, approvedGateClasses, ct);
        }
        // BD-WIN-CORE-1 F6: presence-session binding at the choke
        // point. Any tool beyond Observe requires a LIVE MCP session
        // owned by THIS pairing (session_start is the act that
        // creates it, so it is exempt by name). A second pairing can
        // no longer act inside another pairing's session, and
        // control tools can no longer run with no session — and
        // therefore no presence banner — at all.
        if (decision.Allowed && name != "session_start" && !IsChatTool(name) && module.Descriptor.RequiredScope != Scopes.Observe)
        {
            var live = _sessions.Current;
            if (live is null)
                decision = PolicyDecision.Deny("no_session: no live presence session; call session_start first (control tools never run without the presence layer)");
            else if (!string.Equals(live.PairingId, pairing.Id, StringComparison.Ordinal))
                decision = PolicyDecision.Deny("session_owned_by_other_pairing: the live session belongs to another pairing; it cannot be ridden or kept alive by this one");
        }
        // U1 clipboard direction leg, at the same choke point,
        // after policy + session binding and before the budget leg
        // (a direction-denied call must not consume budget): the
        // resolved clipboard policy forbids the transfer direction
        // this tool moves content in. The desktop engine enforces
        // the same policy again at the clipboard itself.
        if (decision.Allowed && name is "clipboard_get" or "clipboard_set")
        {
            if (_sessions.ResolveClipboardPolicy() is { } clipPolicy &&
                clipPolicy.DenyReasonFor(name) is { } clipReason)
                decision = PolicyDecision.Deny(clipReason);
        }
        // U4 budget leg, at the same choke point, after policy and
        // session binding, before execution. Only the session's
        // OWNING pairing is counted (the binding leg above already
        // denied riders); session_start is counted by beginning its
        // counters after it succeeds (below), never before it
        // exists.
        // U3 exemption: a batch_actions DRY RUN executes nothing, so
        // it must not move state either — no budget count, and the
        // SCAM tripwire must not pause a session over a call that
        // only validates. (The paused-session deny above still
        // applies: a paused session's pairings make no calls at
        // all.) The call is still policy-checked and audited like
        // every other call; the module audits the dry run itself.
        var isBatchDryRun = name == "batch_actions" &&
            args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty("dryRun", out var dryFlag) && dryFlag.ValueKind == JsonValueKind.True;
        if (decision.Allowed && name != "session_start" && !IsChatTool(name))
        {
            var liveNow = _sessions.Current;
            if (liveNow is not null && string.Equals(liveNow.PairingId, pairing.Id, StringComparison.Ordinal))
            {
                if (_sessions.IsPaused && name is not ("session_stop" or "session_status"))
                {
                    decision = PolicyDecision.Deny($"session_paused: {_sessions.PauseReason}");
                }
                else if (!_sessions.IsPaused && !isBatchDryRun)
                {
                    // SCAM tripwire (SCAM-09, wired by U4): a Drive
                    // call while a sensitive context is in the
                    // foreground pauses the session. Observe calls
                    // do not trip — looking is not acting.
                    if (module.Descriptor.RequiredScope == Scopes.Drive &&
                        SensitiveContextClassifier.Pauses(session.ForegroundTitle, session.ForegroundProcess))
                    {
                        var ctxName = SensitiveContextClassifier.ContextFor(session.ForegroundTitle, session.ForegroundProcess);
                        var reason = $"scam_sensitive_context: foreground context '{ctxName}' mechanically pauses control for a non-established operator (SCAM-09) — session paused; the owner resumes it from the host";
                        TripwirePause(pairing, name, reason, $"foreground_title={session.ForegroundTitle};foreground_process={session.ForegroundProcess}");
                        decision = PolicyDecision.Deny(reason);
                    }
                    else if (ResolveBudgetCaps() is { } caps)
                    {
                        if (!_budgets.HasSession(liveNow.Id)) _budgets.BeginSession(liveNow.Id, caps);
                        var verdict = _budgets.CheckAndCount(liveNow.Id, BudgetClassifier.ClassesFor(module.Descriptor));
                        if (verdict.Kind == BudgetVerdictKind.TripPause)
                        {
                            TripwirePause(pairing, name, verdict.Reason, $"class={verdict.Class};count={verdict.Count};cap={verdict.Cap}");
                            decision = PolicyDecision.Deny(verdict.Reason);
                        }
                        else if (verdict.Kind == BudgetVerdictKind.Deny)
                        {
                            decision = PolicyDecision.Deny(verdict.Reason);
                        }
                    }
                }
            }
        }
        ToolResult result;
        string outcome;
        if (!decision.Allowed)
        {
            result = ToolResult.Unavailable(decision.DenyReason!);
            outcome = $"denied:{decision.DenyReason}";
        }
        else
        {
            var execCtx = new ToolExecutionContext(pairing, session, _state.ComputeState(), approvedGateClasses, DataDir: _dataDir);
            try
            {
                result = await module.ExecuteAsync(args, execCtx, ct);
                outcome = result.Ok ? "executed" : result.UnavailableReason is not null ? $"unavailable:{result.UnavailableReason}" : $"error:{result.ErrorClass}";
            }
            catch (Exception ex)
            {
                result = ToolResult.Error(ex.GetType().Name, ex.Message);
                outcome = $"error:{ex.GetType().Name}";
            }
        }

        // U4 post-execution accounting: a successful session_start
        // begins its budget counters fresh; a successful
        // session_stop retires them; a successful egress-class call
        // counts the bytes it actually returned, and a byte-cap
        // breach trips the pause for everything after it (this
        // call's payload already returned — the audit entry built
        // by TripwirePause carries the numbers).
        if (decision.Allowed && result.Ok)
        {
            if (name == "session_start" && _sessions.Current is { } startedSession &&
                string.Equals(startedSession.PairingId, pairing.Id, StringComparison.Ordinal))
            {
                if (ResolveBudgetCaps() is { } caps) _budgets.BeginSession(startedSession.Id, caps);
            }
            else if (name == "session_stop" && preSessionId is not null)
            {
                _budgets.EndSession(preSessionId);
            }
            else if (_sessions.Current is { } liveAfter &&
                     string.Equals(liveAfter.PairingId, pairing.Id, StringComparison.Ordinal) &&
                     BudgetClassifier.IsEgress(module.Descriptor) && result.Text is not null)
            {
                var trip = _budgets.NoteEgressBytes(liveAfter.Id,
                    System.Text.Encoding.UTF8.GetByteCount(result.Text));
                if (trip.Kind == BudgetVerdictKind.TripPause)
                    TripwirePause(pairing, name, trip.Reason, $"class={trip.Class};count={trip.Count};cap={trip.Cap}");
            }
        }

        // U2 producers at the choke point: session lifecycle and
        // approval facts, origin-scoped to THIS pairing (they are
        // delivered only to this pairing's own subscribers). Detail
        // carries names/kinds only — never arguments or results.
        if (Events is not null)
        {
            if (!decision.Allowed && decision.DenyReason is { } deny && deny.StartsWith("gated:", StringComparison.Ordinal))
                Events.Publish(Shared.Sessions.AgentEventKinds.Approval, $"approval_required: {deny} (tool {name})", pairing.Id);
            else if (decision.Allowed && result.Ok && name == "session_start")
                Events.Publish(Shared.Sessions.AgentEventKinds.Session, $"session_started: {_sessions.Current?.Id}", pairing.Id);
            else if (decision.Allowed && result.Ok && name == "session_stop" && preSessionId is not null)
                Events.Publish(Shared.Sessions.AgentEventKinds.Session, $"session_ended: {preSessionId}", pairing.Id);
            else if (decision.Allowed && result.Ok && module.Descriptor.GateClass is { } gc && approvedGateClasses.Contains(gc))
                Events.Publish(Shared.Sessions.AgentEventKinds.Approval, $"approval_resolved: gate class '{gc}' approved for {name}", pairing.Id);
        }

        // U1 per-read indicator: a successful clipboard read is a
        // presence fact, not just an audit line — publish the
        // clipboard_read event (origin-scoped to the reading
        // pairing; character count only, never content) and put the
        // read on the narration line the banner/mesh show. The
        // engine narrates the same read at the clipboard itself.
        if (decision.Allowed && result.Ok && name == "clipboard_get")
        {
            Events?.Publish(Shared.Sessions.AgentEventKinds.ClipboardRead,
                $"clipboard_read: {pairing.AgentName} read the clipboard ({result.Text?.Length ?? 0} chars)", pairing.Id);
            _state.LastNarration = $"Clipboard read by {pairing.AgentName}";
        }

        // BD-WIN-CORE-1 F6: only the session's OWNING pairing keeps
        // it alive / accrues its action count.
        var ownsLiveSession = _sessions.Current is { } cur && string.Equals(cur.PairingId, pairing.Id, StringComparison.Ordinal);
        if (decision.Allowed && ownsLiveSession) _sessions.Touch(); // denied junk must not keep a session alive (M7)
        if (result.Ok && ownsLiveSession && !isBatchDryRun) _sessions.NoteAction(); // mesh heartbeat's action count (M2); U3: a dry run performed no action, so it is not counted as one
        // Host-side audit BEFORE the result returns (DESIGN §6.4). Arguments
        // are redacted host-side; raw values never reach the log. If the
        // append itself fails (disk full), the executed call still returns
        // its true result — a logging failure must not rewrite history —
        // and the failure is counted on CoreState for the self-check.
        try
        {
            // W9 chat parity: chat audit is METADATA-ONLY (Android
            // ChatToolHost rule) — the generic redactor passes a
            // chat body through untouched (it is not a secret-shaped
            // value), so chat calls write a chars/cursor summary
            // instead of the redacted arguments. The body lives only
            // in the thread store.
            var auditArgs = IsChatTool(name)
                ? ChatAuditSummary(name, args)
                : Redactor.RedactJson(args).GetRawText();
            _audit.Append(new AuditEntry(
                started, "tool_call", pairing.Id, pairing.AgentName, name, null,
                auditArgs, outcome,
                module.Descriptor.ExecutionContext,
                (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds));
        }
        catch { _state.NoteAuditWriteFailure(); }

        // U5 data-flow accounting, at the same choke point: the
        // request bytes this pairing sent in and the result bytes
        // that flowed back, per tool, classified read/sent/changed.
        // Attribution follows the U4 binding exactly — a call counts
        // under a session only when that session belongs to THIS
        // pairing; anything else lands on the pairing's standing
        // out-of-session record, so one pairing's flows can never
        // inflate (or hide inside) another's. Denied calls count
        // too: their bytes crossed, and the audit counts them, so
        // the report's cross-check reconciles. A ledger failure
        // never breaks a call (same posture as the audit append).
        try
        {
            if (_flows is not null && name is not null)
            {
                var bytesIn = System.Text.Encoding.UTF8.GetByteCount(argsNode.ToJsonString());
                var bytesOut = System.Text.Encoding.UTF8.GetByteCount(result.Text ?? result.UnavailableReason ?? "");
                var flowClass = DataFlowClassifier.Classify(module.Descriptor);
                if (name == "session_start" && result.Ok && _sessions.Current is { } startedFlow &&
                    string.Equals(startedFlow.PairingId, pairing.Id, StringComparison.Ordinal))
                {
                    _flows.BeginSession(startedFlow.Id, pairing.Id, pairing.AgentName, started);
                    _flows.NoteCall(startedFlow.Id, "agent", pairing.Id, pairing.AgentName, name, flowClass, bytesIn, bytesOut, null, started);
                }
                else if (name == "session_stop" && preSessionId is not null &&
                         string.Equals(preSessionPairingId, pairing.Id, StringComparison.Ordinal))
                {
                    _flows.NoteCall(preSessionId, "agent", pairing.Id, pairing.AgentName, name, flowClass, bytesIn, bytesOut, null, started);
                    if (result.Ok) _flows.EndSession(preSessionId, DateTimeOffset.UtcNow);
                }
                else if (_sessions.Current is { } liveFlow &&
                         string.Equals(liveFlow.PairingId, pairing.Id, StringComparison.Ordinal))
                {
                    _flows.NoteCall(liveFlow.Id, "agent", pairing.Id, pairing.AgentName, name, flowClass, bytesIn, bytesOut, null, started);
                }
                else
                {
                    _flows.NoteCall($"pairing:{pairing.Id}", "agent", pairing.Id, pairing.AgentName, name, flowClass, bytesIn, bytesOut, null, started, outsideSession: true);
                }
            }
        }
        catch { /* flow accounting is a view over the traffic, never a gate on it */ }

        var content = new JsonObject
        {
            ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = result.Text ?? result.UnavailableReason ?? "" } },
            ["isError"] = !result.Ok
        };
        return new McpResponse(200, ResultJson(id, content));
    }

    /// <summary>W9: the metadata-only audit summary for a chat call
    /// — tool, body length / cursor only. Never the body.</summary>
    internal static string ChatAuditSummary(string? name, JsonElement args)
    {
        if (name == "chat_post")
        {
            var chars = args.ValueKind == JsonValueKind.Object &&
                        args.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String
                ? (b.GetString() ?? "").Trim().Length : 0;
            return $"{{\"tool\":\"chat_post\",\"chars\":{chars}}}";
        }
        if (name == "chat_order")
        {
            // W120: the proposed tool's NAME only — the order's
            // argument bytes live on the card and in the order
            // store, never in the audit chain.
            var proposed = args.ValueKind == JsonValueKind.Object &&
                           args.TryGetProperty("tool", out var t) && t.ValueKind == JsonValueKind.String
                ? (t.GetString() ?? "") : "";
            return $"{{\"tool\":\"chat_order\",\"proposed\":\"{proposed}\"}}";
        }
        var after = args.ValueKind == JsonValueKind.Object &&
                    args.TryGetProperty("after_seq", out var a) && a.ValueKind == JsonValueKind.Number
            ? a.GetInt64() : 0L;
        return $"{{\"tool\":\"chat_read\",\"after_seq\":{after}}}";
    }

    /// <summary>W9: raise one per-action gate and fold its answer
    /// back into the choke point. Allow re-evaluates with a ONE-SHOT
    /// approved set (this call only — nothing is persisted, the
    /// standing approved set is never mutated, and the next gated
    /// call raises the gate again). Deny denies this call.
    /// Deny-and-end writes the approval_deny_and_end audit entry
    /// FIRST (GateSheetModel.DenyAndEndSteps), then stops the
    /// session, then hands the ended record to the host teardown
    /// callback. No answer (timeout / no agent / raiser fault) is a
    /// deny, audited as gate_no_answer.</summary>
    private async Task<PolicyDecision> RaiseGateAsync(Pairing pairing, IToolModule module, string gateClass,
        string argsJson, JsonElement args, Shared.State.SessionFacts sessionFacts,
        IReadOnlySet<string> approvedGateClasses, CancellationToken ct)
    {
        void AuditGate(string outcome) =>
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairing.Id, pairing.AgentName,
                module.Descriptor.Name, null, null, outcome, "SYSTEM", null));

        AuditGate($"gate_raised:{gateClass}");
        Events?.Publish(Shared.Sessions.AgentEventKinds.Approval,
            $"approval_required: gate '{gateClass}' raised for {module.Descriptor.Name}", pairing.Id);
        string? answer;
        try
        {
            answer = await GateRaiser!(new GateRaise(pairing, _sessions.Current!.Id, gateClass,
                module.Descriptor.Name, argsJson, FromChat: false), ct);
        }
        catch { answer = null; /* a faulting raiser is a NO, never a yes */ }

        switch (answer)
        {
            case Shared.Ipc.GateAnswers.Allow:
            {
                AuditGate($"gate_allowed:{gateClass}");
                Events?.Publish(Shared.Sessions.AgentEventKinds.Approval,
                    $"approval_resolved: gate '{gateClass}' allowed once for {module.Descriptor.Name}", pairing.Id);
                var oneShot = new HashSet<string>(approvedGateClasses, StringComparer.Ordinal) { gateClass };
                return _policy.Evaluate(pairing, module.Descriptor, args, sessionFacts, _state.ComputeState(), oneShot,
                    sessionFacts.ForegroundTitle, sessionFacts.ForegroundProcess);
            }
            case Shared.Ipc.GateAnswers.DenyAndEnd:
            {
                // Audit FIRST, teardown second — the order is the
                // contract (GateSheetModel.DenyAndEndSteps).
                AuditGate("approval_deny_and_end");
                var ended = _sessions.Stop();
                if (ended is not null)
                {
                    Events?.Publish(Shared.Sessions.AgentEventKinds.Session, $"session_ended: {ended.Id}", pairing.Id);
                    try { GateDenyAndEndTeardown?.Invoke(ended); } catch { /* teardown faults never resurrect the call */ }
                }
                return PolicyDecision.Deny($"gate_deny_and_end:{gateClass}: the person at the endpoint denied this action and ended the session");
            }
            case Shared.Ipc.GateAnswers.Deny:
                AuditGate($"gate_denied:{gateClass}");
                return PolicyDecision.Deny($"gate_denied:{gateClass}: the person at the endpoint denied this action at the gate");
            default:
                AuditGate($"gate_no_answer:{gateClass}");
                return PolicyDecision.Deny($"gate_no_answer:{gateClass}: nobody at the endpoint answered the gate in time; treated as a denial");
        }
    }

    /// <summary>Host-side execution path for durable engines (missions):
    /// runs one tool under an existing pairing through the SAME policy
    /// choke point and audit as a wire call. A revoked, expired, or
    /// unknown pairing halts the caller — missions die with their
    /// pairing, by design. Gate classes are NOT inherited: a mission
    /// step that needs a plan approval is denied until a human approves
    /// it through the normal path.</summary>
    public async Task<ToolResult> ExecuteForPairingAsync(string pairingId, string toolName, System.Text.Json.Nodes.JsonObject arguments, CancellationToken ct,
        IReadOnlySet<string>? approvedGateClasses = null)
    {
        var pairing = _pairings.List().FirstOrDefault(p => p.Id == pairingId);
        if (pairing is null || pairing.Revoked || (pairing.ExpiresUtc is { } exp && exp < DateTimeOffset.UtcNow))
            return ToolResult.Error("pairing_invalid", "the calling engine's pairing is revoked, expired, or unknown; execution halts");
        var obj = new JsonObject { ["params"] = new JsonObject { ["name"] = toolName, ["arguments"] = arguments } };
        // W120: an S13 order card's Approve passes the order's gate
        // class as the ONE-SHOT approved set for exactly this call
        // (the card showed the exact bytes; the owner's tap is the
        // gate answer for those bytes — RaiseGateAsync's Allow leg
        // re-evaluates with the same one-shot shape). Nothing is
        // persisted; the next gated call gates again.
        var response = await CallToolAsync(obj, null, pairing,
            approvedGateClasses is null ? new HashSet<string>() : new HashSet<string>(approvedGateClasses), ct);
        try
        {
            var root = JsonNode.Parse(response.Json ?? "{}")?.AsObject();
            if (root?["error"] is { } err) return ToolResult.Error("step_failed", err["message"]?.GetValue<string>() ?? "tool error");
            var result = root?["result"]?.AsObject();
            var text = result?["content"]?[0]?["text"]?.GetValue<string>() ?? "";
            var isError = result?["isError"]?.GetValue<bool>() ?? false;
            return isError ? ToolResult.Error("step_failed", text) : ToolResult.Success(text);
        }
        catch { return ToolResult.Error("step_failed", "unparseable tool response"); }
    }

    private Pairing? Authenticate(string? authorizationHeader)
    {
        if (authorizationHeader is null) return null;
        const string prefix = "Bearer ";
        if (!authorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        return _pairings.Authenticate(authorizationHeader[prefix.Length..].Trim());
    }

    private static string ResultJson(JsonNode? id, JsonObject result) =>
        new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result }.ToJsonString();

    private static string ErrorJson(JsonNode? id, int code, string message) =>
        new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["error"] = new JsonObject { ["code"] = code, ["message"] = message }
        }.ToJsonString();
}

/// <summary>POST /pair: exchange a one-time code (minted on the laptop)
/// for a pairing + bearer token. The code is the secret; no other
/// unauthenticated endpoint exists.</summary>
public sealed class PairingHandler
{
    private readonly PairingService _pairings;
    private readonly IAuditLog _audit;
    private readonly Func<string?>? _lanTlsPinProvider;
    private readonly object _throttleGate = new();
    // BD-WIN-CORE-1 F9: the brute-force brake is PER SOURCE, not one
    // global counter — an unauthenticated peer can no longer lock
    // the owner (or every other peer) out of pairing by spraying
    // bad codes.
    private readonly Dictionary<string, (int Failures, DateTimeOffset LockedUntil)> _throttleBySource = new();

    /// <param name="lanTlsPinProvider">Supplies the LAN lane's TLS
    /// certificate pin (SHA-256 fingerprint). The pin is disclosed ONLY
    /// here — inside a successful pairing exchange, which happens on
    /// the tailnet/loopback lane — so a client learns it over an
    /// already-encrypted channel and can pin the LAN lane from its
    /// first connection (H1 remainder closure).</param>
    public PairingHandler(PairingService pairings, IAuditLog audit, Func<string?>? lanTlsPinProvider = null,
        Shared.Sessions.EventSubscriptionStore? eventStore = null, Func<TermsBundle?>? termsProvider = null)
    {
        _pairings = pairings;
        _audit = audit;
        _lanTlsPinProvider = lanTlsPinProvider;
        _eventStore = eventStore;
        _termsProvider = termsProvider;
    }

    // FR-134 / item (16)(a): supplies the Terms bundle carried in
    // the exchange response. Null in bare unit embedders (the
    // pre-FR-134 response shape); CoreRuntime always wires it.
    private readonly Func<TermsBundle?>? _termsProvider;

    private readonly Shared.Sessions.EventSubscriptionStore? _eventStore;

    // Brute-force brake (second-inspector H1): codes are 64-bit, and
    // after 5 consecutive failed exchanges the endpoint refuses ALL
    // exchanges for 60 seconds. A legitimate pairing happens once, on
    // the owner's word; a guessing peer gets a wall.
    private bool LockedOut(string source)
    {
        lock (_throttleGate)
            return _throttleBySource.TryGetValue(source, out var t) && DateTimeOffset.UtcNow < t.LockedUntil;
    }
    private void NoteFailure(string source)
    {
        lock (_throttleGate)
        {
            var t = _throttleBySource.TryGetValue(source, out var cur) ? cur : (0, DateTimeOffset.MinValue);
            var failures = t.Item1 + 1;
            _throttleBySource[source] = failures >= 5
                ? (0, DateTimeOffset.UtcNow + TimeSpan.FromSeconds(60))
                : (failures, t.Item2);
        }
    }
    private void NoteSuccess(string source) { lock (_throttleGate) _throttleBySource.Remove(source); }

    public (int Status, string Json) Handle(string body, string? sourceKey = null, string? arrivalRung = null)
    {
        var source = string.IsNullOrWhiteSpace(sourceKey) ? "unknown-source" : sourceKey;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var code = root.TryGetProperty("code", out var c) ? c.GetString() : null;
            var agentName = root.TryGetProperty("agent_name", out var a) ? a.GetString() ?? "agent" : "agent";
            if (code is null) return (400, """{"error":"code required"}""");
            if (LockedOut(source))
            {
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "pairing_exchange_throttled", null, null));
                return (429, """{"error":"pairing temporarily locked after repeated failures; the host mints codes, wait a minute"}""");
            }
            // Scopes are NOT read from this request (C1): they were bound
            // to the code when the host minted it. A caller asking for a
            // "preset" here gets exactly what the host intended — the
            // field is ignored by design.
            // BD-WIN-CORE-1 F9: the request's agent_name is an
            // unauthenticated CLAIM. The pairing itself is bound to
            // the name the host minted the code for (PairingService
            // ignores the claim), and the audit records that
            // host-bound name — never the claimed one.
            // W97 / S09(b): the exchange door enforces the code's
            // bound connection setting against the ARRIVAL rung
            // before the code is consumed — a pairing pinned away
            // from this path cannot even be born over it. The
            // refusal does NOT consume the code and does NOT count
            // toward the brute-force brake: the code stays alive
            // for its allowed path, and a policy refusal is not a
            // guessing failure. The audit carries the full truth.
            if (arrivalRung is not null &&
                _pairings.PeekCodeConnection(code) is { } boundSetting &&
                !ConnectionPathPolicy.Allows(boundSetting, arrivalRung))
            {
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null,
                    $"pairing_exchange_refused_by_path:arrived over {ConnectionPathPolicy.PlainName(arrivalRung)}, " +
                    $"which the code's connection setting excludes ({ConnectionPathPolicy.Describe(boundSetting)})", null, null));
                return (403, """{"error":"this pairing code cannot be exchanged over this connection path"}""");
            }
            var exchange = _pairings.ExchangeCode(code, agentName);
            if (exchange is null)
            {
                NoteFailure(source);
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", null, null, null, null, null, "pairing_exchange_failed", null, null));
                return (403, """{"error":"invalid or expired pairing code"}""");
            }
            NoteSuccess(source);
            // W97: the exchange arrival is the pairing's first
            // connection — the card's current-rung label starts here.
            if (arrivalRung is not null) _pairings.NoteConnection(exchange.PairingId, arrivalRung);
            // BD-SUPP-EVENTSUB F5: a freshly exchanged pairing id is
            // live — clear any tombstone a prior revocation left
            // under a recycled store entry (ids are never reused, so
            // this can only ever un-tombstone THIS pairing's own id).
            _eventStore?.AllowPairing(exchange.PairingId);
            var boundName = _pairings.List().FirstOrDefault(p => p.Id == exchange.PairingId)?.AgentName;
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", exchange.PairingId, boundName, null, null, null, "pairing_created", null, null));
            var lanPin = _lanTlsPinProvider?.Invoke();
            var response = new JsonObject
            {
                ["pairing_id"] = exchange.PairingId,
                ["bearer_token"] = exchange.BearerToken,
                // JsonValue.Create keeps the key present with a
                // JSON null when the host has no LAN certificate
                // (never in production wiring) — the pre-FR-134
                // response shape, which clients already parse.
                ["lan_tls_pin"] = JsonValue.Create(lanPin)
            };
            // FR-134 / item (16)(a)+(d): the Terms travel inside
            // the pairing itself — full text, version, SHA-256 and
            // the agent rulebook are delivered in the exchange
            // response, and the delivery enters the audit chain
            // under the agent's name. Pairing completes only when
            // the client returns the protocol acknowledgment of
            // this exact hash (McpHandler, deskguest/terms_acknowledge);
            // until then the pairing is session-locked.
            if (_termsProvider?.Invoke() is { } terms)
            {
                response["terms"] = new JsonObject
                {
                    ["version"] = terms.Version,
                    ["sha256"] = terms.Sha256,
                    ["text"] = terms.Text,
                    ["rulebook"] = terms.Rulebook,
                    ["resource_uri"] = TermsBundle.ResourceUri,
                    ["ack_method"] = TermsBundle.AckMethod,
                    ["ack_required_before_session"] = true
                };
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", exchange.PairingId, boundName, null, null, null,
                    $"terms_delivered:version={terms.Version};sha256={terms.Sha256}", null, null));
            }
            return (200, response.ToJsonString());
        }
        catch (JsonException)
        {
            return (400, """{"error":"invalid json"}""");
        }
    }
}

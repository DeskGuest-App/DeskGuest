using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Shared.Sessions;

// =====================================================================
// U5 — Per-agent data-flow transparency (UNION BUILD lane U5).
//
// Until this lane, nothing in ACP counted bytes or destinations per
// pairing/agent: SessionPicture reported action COUNTS, and the
// audit log recorded tool calls, not data volumes. An owner could
// see THAT an agent acted, never HOW MUCH data moved, in which
// direction, or to where.
//
// This file is the flow-accounting layer:
//
//   * Counters live at the choke points that already see the
//     traffic — McpHandler (request/response byte lengths per
//     pairing+tool, classified read/sent/changed) and StreamService
//     (frame bytes served per human session + the host device the
//     stream targets). Human-session file-job bytes are NOT counted
//     twice: they already exist as records (FileJob.TransferredBytes)
//     and SessionPicture derives BytesIn/BytesOut/Destinations from
//     them at shaping time.
//   * The ledger persists into the Core's data dir alongside the
//     audit log. Ended sessions keep their totals — the record is
//     closed (EndedUtc), never deleted.
//   * ZERO TELEMETRY law: the ledger is a local file on the owner's
//     machine. Nothing here opens a socket, phones home, or collects
//     anything beyond the byte counts of traffic the product already
//     carries and the audit it already keeps. The view is READ-ONLY:
//     DataFlowReport.Build is a pure derivation over the ledger
//     records + audit entries; it writes nothing and the audit's
//     append-only surface (§7.10) gains no edit path through it.
//   * GAPS SHOW AS GAPS: the report cross-checks the audit against
//     the flow records per pairing. Audited calls with no flow
//     record (they predate flow accounting, or ran outside the
//     counted path) are reported as a named gap with their count —
//     their bytes are unknown and are NEVER estimated or folded
//     into an agent's totals. Unattributable audit entries (no
//     pairing id) are reported unattributed, never assigned.
//   * Per-pairing isolation is structural: records are keyed by
//     session, every record carries its pairing, and aggregation
//     groups strictly by pairing id — two pairings' flows can
//     never merge, and a session record only ever shows its own
//     pairing's calls (the choke point counts a call under a
//     session only when that session belongs to the calling
//     pairing — the same binding as the U4 budget leg).
// =====================================================================

/// <summary>The data-flow classes: what a call DID with data.
/// Read = host data flowed out to the agent (or the call only
/// observed); Sent = the agent sent something onward (message /
/// send gate class); Changed = the call acted on the host (input,
/// writes, deletions, shell…).</summary>
public static class DataFlowClasses
{
    public const string Read = "read";
    public const string Sent = "sent";
    public const string Changed = "changed";

    public static readonly IReadOnlyList<string> All = new[] { Read, Sent, Changed };
}

/// <summary>Classifies one tool call for flow accounting. The
/// descriptor's own declarations decide: egress tools (their RESULT
/// carries host data out) are Read; the sending gate class is Sent;
/// Observe-scope tools are Read; everything else acted on the host
/// and is Changed.</summary>
public static class DataFlowClassifier
{
    public static string Classify(ToolDescriptor tool)
    {
        if (BudgetClassifier.IsEgress(tool)) return DataFlowClasses.Read;
        if (tool.GateClass == BudgetClasses.Sending) return DataFlowClasses.Sent;
        if (tool.RequiredScope == Scopes.Observe) return DataFlowClasses.Read;
        return DataFlowClasses.Changed;
    }

    /// <summary>Android-parity classifier by tool NAME (the Android
    /// descriptors carry no gate class at the dispatch seam; the
    /// name sets mirror the Windows ones).</summary>
    public static string ClassifyByName(string tool, bool isEgress, bool isSendingGate, bool isObserveScope) =>
        isEgress || isObserveScope ? DataFlowClasses.Read
        : isSendingGate ? DataFlowClasses.Sent
        : DataFlowClasses.Changed;
}

/// <summary>One tool's flow totals inside one session record.</summary>
public sealed record ToolFlow(string Tool, string Class, long Calls, long BytesIn, long BytesOut);

/// <summary>One session's persisted flow record. Kind is "agent"
/// (an MCP pairing session, or the standing per-pairing record for
/// calls made outside any session — OutsideSession = true) or
/// "human" (stream bytes served inside a Slice 3 human session).
/// EndedUtc set = the session ended; its totals are final and the
/// record is kept.</summary>
public sealed record SessionFlowRecord(
    string SessionId,
    string Kind,
    string? PairingId,
    string AgentName,
    DateTimeOffset StartedUtc,
    DateTimeOffset? EndedUtc,
    bool OutsideSession,
    long BytesIn,
    long BytesOut,
    IReadOnlyList<ToolFlow> Tools,
    IReadOnlyList<string> Destinations);

/// <summary>Per-class totals for one agent.</summary>
public sealed record ClassTotals(long Calls, long BytesIn, long BytesOut);

/// <summary>One paired agent's aggregated flows across all its
/// sessions (live and ended).</summary>
public sealed record AgentFlow(
    string PairingId,
    string AgentName,
    int SessionCount,
    long BytesIn,
    long BytesOut,
    IReadOnlyDictionary<string, ClassTotals> ByClass,
    IReadOnlyList<ToolFlow> Tools,
    IReadOnlyList<string> Destinations,
    IReadOnlyList<SessionFlowRecord> Sessions);

/// <summary>The owner-visible data-flow view: per-agent flows,
/// human-session stream flows, and the gaps — audited activity the
/// flow records cannot account for, named instead of papered over.
/// Pure derivation; building it changes nothing.</summary>
public sealed record DataFlowReport(
    IReadOnlyList<AgentFlow> Agents,
    IReadOnlyList<SessionFlowRecord> HumanFlows,
    IReadOnlyList<string> Gaps)
{
    public static DataFlowReport Build(IReadOnlyList<SessionFlowRecord> records, IReadOnlyList<AuditEntry> audit)
    {
        var agentRecords = records.Where(r => r.Kind == "agent").ToList();
        var human = records.Where(r => r.Kind == "human")
            .OrderBy(r => r.StartedUtc).ToList();

        var agents = agentRecords
            .Where(r => r.PairingId is not null)
            .GroupBy(r => r.PairingId!)
            .Select(g =>
            {
                var tools = g.SelectMany(r => r.Tools)
                    .GroupBy(t => t.Tool)
                    .Select(tg => new ToolFlow(
                        tg.Key,
                        tg.First().Class,
                        tg.Sum(t => t.Calls),
                        tg.Sum(t => t.BytesIn),
                        tg.Sum(t => t.BytesOut)))
                    .OrderBy(t => t.Tool, StringComparer.Ordinal)
                    .ToList();
                var byClass = new Dictionary<string, ClassTotals>(StringComparer.Ordinal);
                foreach (var cls in DataFlowClasses.All)
                {
                    var rows = tools.Where(t => t.Class == cls).ToList();
                    byClass[cls] = new ClassTotals(
                        rows.Sum(t => t.Calls), rows.Sum(t => t.BytesIn), rows.Sum(t => t.BytesOut));
                }
                return new AgentFlow(
                    g.Key,
                    g.Select(r => r.AgentName).FirstOrDefault(n => !string.IsNullOrWhiteSpace(n)) ?? "",
                    g.Count(),
                    g.Sum(r => r.BytesIn),
                    g.Sum(r => r.BytesOut),
                    byClass,
                    tools,
                    g.SelectMany(r => r.Destinations).Distinct(StringComparer.Ordinal).OrderBy(d => d, StringComparer.Ordinal).ToList(),
                    g.OrderBy(r => r.StartedUtc).ToList());
            })
            .OrderBy(a => a.AgentName, StringComparer.Ordinal)
            .ToList();

        // ---- gap cross-check: audit vs flow records, per pairing ----
        var gaps = new List<string>();
        var recordedByPairing = agents.ToDictionary(
            a => a.PairingId,
            a => a.Tools.Sum(t => t.Calls),
            StringComparer.Ordinal);
        var auditedByPairing = new Dictionary<string, (long Count, string Name)>(StringComparer.Ordinal);
        long unattributed = 0;
        foreach (var e in audit)
        {
            if (e.Kind != "tool_call") continue;
            if (e.PairingId is null) { unattributed++; continue; }
            var cur = auditedByPairing.TryGetValue(e.PairingId, out var v) ? v : (0, e.AgentName ?? "");
            auditedByPairing[e.PairingId] = (cur.Item1 + 1, string.IsNullOrWhiteSpace(cur.Item2) ? (e.AgentName ?? "") : cur.Item2);
        }
        foreach (var (pairingId, (audited, name)) in auditedByPairing.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var recorded = recordedByPairing.TryGetValue(pairingId, out var r) ? r : 0;
            var label = string.IsNullOrWhiteSpace(name) ? pairingId : $"{name} ({pairingId})";
            if (audited > recorded)
                gaps.Add($"{label}: {audited - recorded} audited tool call(s) have no flow record " +
                         "(they predate flow accounting or ran outside the counted path) — shown as a gap; " +
                         "their byte volumes are unknown and are NOT estimated or included in any total.");
            else if (recorded > audited)
                gaps.Add($"{label}: flow records count {recorded - audited} more call(s) than the audit holds " +
                         "(audit write failures) — flows are shown from the flow records; the audit remains " +
                         "the authority for what was attempted.");
        }
        foreach (var a in agents)
        {
            if (!auditedByPairing.ContainsKey(a.PairingId))
                gaps.Add($"{(string.IsNullOrWhiteSpace(a.AgentName) ? a.PairingId : $"{a.AgentName} ({a.PairingId})")}: " +
                         "flow records exist but no audited tool calls were supplied to this view — " +
                         "the cross-check could not run for this agent, so its flows are shown uncorroborated.");
        }
        if (unattributed > 0)
            gaps.Add($"{unattributed} audited tool call(s) carry no pairing id — they cannot be attributed " +
                     "to any agent and are shown unattributed, never assigned to one.");

        return new DataFlowReport(agents, human, gaps);
    }
}

/// <summary>The persistent flow ledger. One instance serves the
/// Core; records are keyed by session id and persisted to a local
/// JSON file in the Core's data dir (atomic temp-file replace, the
/// D38 store discipline). A null path gives an in-memory ledger
/// (tests, embedders). Thread-safe: every public act takes the
/// gate. There is deliberately NO delete or rewrite API — a record
/// can be added to and closed, never edited down; totals only ever
/// grow, exactly like the audit they sit beside.</summary>
public sealed class DataFlowLedger
{
    private sealed class MutableTool
    {
        public string Tool = "";
        public string Class = DataFlowClasses.Read;
        public long Calls;
        public long BytesIn;
        public long BytesOut;
    }

    private sealed class MutableRecord
    {
        public string SessionId = "";
        public string Kind = "agent";
        public string? PairingId;
        public string AgentName = "";
        public DateTimeOffset StartedUtc;
        public DateTimeOffset? EndedUtc;
        public bool OutsideSession;
        public readonly Dictionary<string, MutableTool> Tools = new(StringComparer.Ordinal);
        public readonly List<string> Destinations = new();
    }

    private sealed record ToolDto(string Tool, string Class, long Calls, long BytesIn, long BytesOut);
    private sealed record RecordDto(
        string SessionId, string Kind, string? PairingId, string AgentName,
        DateTimeOffset StartedUtc, DateTimeOffset? EndedUtc, bool OutsideSession,
        ToolDto[] Tools, string[] Destinations);

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    private readonly string? _path;
    private readonly object _gate = new();
    private readonly Dictionary<string, MutableRecord> _bySession = new(StringComparer.Ordinal);

    public DataFlowLedger(string? path = null)
    {
        _path = path;
        if (path is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            Load();
        }
    }

    public string? FilePath => _path;

    /// <summary>Open the flow record for a session that just
    /// started. Re-beginning an id that already has a record keeps
    /// the record (a session id is never reused; this is a no-op
    /// guard, not a reset — totals are never zeroed).</summary>
    public void BeginSession(string sessionId, string? pairingId, string agentName, DateTimeOffset utc)
    {
        lock (_gate)
        {
            if (!_bySession.ContainsKey(sessionId))
            {
                _bySession[sessionId] = new MutableRecord
                {
                    SessionId = sessionId, Kind = "agent", PairingId = pairingId,
                    AgentName = agentName, StartedUtc = utc,
                };
                Save();
            }
        }
    }

    /// <summary>Count one call's bytes under a session record,
    /// creating the record when absent (out-of-session calls land
    /// on the caller's standing per-pairing record, flagged
    /// OutsideSession by the caller). Negative byte counts are
    /// refused — a counter only ever grows.</summary>
    public void NoteCall(string sessionId, string kind, string? pairingId, string agentName,
        string tool, string flowClass, long bytesIn, long bytesOut,
        string? destination, DateTimeOffset utc, bool outsideSession = false)
    {
        if (bytesIn < 0 || bytesOut < 0) return;
        lock (_gate)
        {
            if (!_bySession.TryGetValue(sessionId, out var rec))
            {
                rec = new MutableRecord
                {
                    SessionId = sessionId, Kind = kind, PairingId = pairingId,
                    AgentName = agentName, StartedUtc = utc, OutsideSession = outsideSession,
                };
                _bySession[sessionId] = rec;
            }
            else if (!string.Equals(rec.Kind, kind, StringComparison.Ordinal) ||
                     // BD-SHARED-SESSION F6: the isolation guard no
                     // longer skips null pairings — a record bound to
                     // a pairing refuses a null-pairing call and vice
                     // versa; only two nulls (genuinely unattributed)
                     // may merge.
                     !string.Equals(rec.PairingId, pairingId, StringComparison.Ordinal))
            {
                // RECOVERY-VERIFICATION destruction find (2026-11-22):
                // a record is bound to the pairing + kind that opened
                // it. A call arriving under the same session id but a
                // DIFFERENT pairing (or a different kind) must never
                // merge into it — that would fold one pairing's flows
                // into another's totals, breaking the structural
                // isolation this ledger claims. The choke points bind
                // correctly today; the ledger now refuses the merge
                // itself, so no future caller can reopen the hole.
                // The refused call is simply not counted here; if it
                // was audited, the report's gap cross-check names it.
                return;
            }
            if (!rec.Tools.TryGetValue(tool, out var t))
            {
                t = new MutableTool { Tool = tool, Class = flowClass };
                rec.Tools[tool] = t;
            }
            t.Calls++;
            t.BytesIn += bytesIn;
            t.BytesOut += bytesOut;
            if (!string.IsNullOrWhiteSpace(destination) && !rec.Destinations.Contains(destination))
                rec.Destinations.Add(destination);
            Save();
        }
    }

    /// <summary>W8 [R4]: one Agent-chat message to a paired agent.
    /// A paired agent is a separate principal reached over the
    /// pairing channel, so chat is OFF-DEVICE on every canonical
    /// board and counts as Sent in the data-flow ledger — recorded
    /// under the pairing's standing record (OutsideSession: chat is
    /// not a session), tool "agent_chat", class Sent, destination
    /// the agent's own device. The on-device Read wording is
    /// reserved for a co-located-agent scene, which no canonical
    /// board draws. Message TEXT is never recorded — counts only,
    /// matching the audit's metadata-only chat rule.</summary>
    public void NoteChatMessage(string pairingId, string agentName, string agentDevice, DateTimeOffset utc)
    {
        NoteCall($"chat:{pairingId}", "agent", pairingId, agentName,
            "agent_chat", DataFlowClasses.Sent, 0, 1,
            string.IsNullOrWhiteSpace(agentDevice) ? null : agentDevice,
            utc, outsideSession: true);
    }

    /// <summary>Close a session's record. Its totals are final and
    /// kept — ended sessions keep their totals by design.</summary>
    public void EndSession(string sessionId, DateTimeOffset utc)
    {
        lock (_gate)
        {
            if (_bySession.TryGetValue(sessionId, out var rec) && rec.EndedUtc is null)
            {
                rec.EndedUtc = utc;
                Save();
            }
        }
    }

    /// <summary>Immutable snapshots of every record, oldest first.</summary>
    public IReadOnlyList<SessionFlowRecord> Records()
    {
        lock (_gate)
        {
            return _bySession.Values
                .OrderBy(r => r.StartedUtc)
                .Select(r =>
                {
                    var tools = r.Tools.Values
                        .Select(t => new ToolFlow(t.Tool, t.Class, t.Calls, t.BytesIn, t.BytesOut))
                        .OrderBy(t => t.Tool, StringComparer.Ordinal)
                        .ToList();
                    return new SessionFlowRecord(
                        r.SessionId, r.Kind, r.PairingId, r.AgentName, r.StartedUtc, r.EndedUtc,
                        r.OutsideSession,
                        tools.Sum(t => t.BytesIn), tools.Sum(t => t.BytesOut),
                        tools, r.Destinations.ToList());
                })
                .ToList();
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var dtos = JsonSerializer.Deserialize<List<RecordDto>>(File.ReadAllText(_path!), JsonOpts);
            if (dtos is null) return;
            foreach (var d in dtos)
            {
                var rec = new MutableRecord
                {
                    SessionId = d.SessionId, Kind = d.Kind, PairingId = d.PairingId,
                    AgentName = d.AgentName, StartedUtc = d.StartedUtc, EndedUtc = d.EndedUtc,
                    OutsideSession = d.OutsideSession,
                };
                foreach (var t in d.Tools ?? Array.Empty<ToolDto>())
                    rec.Tools[t.Tool] = new MutableTool { Tool = t.Tool, Class = t.Class, Calls = t.Calls, BytesIn = t.BytesIn, BytesOut = t.BytesOut };
                foreach (var dest in d.Destinations ?? Array.Empty<string>())
                    if (!rec.Destinations.Contains(dest)) rec.Destinations.Add(dest);
                _bySession[rec.SessionId] = rec;
            }
        }
        catch (JsonException)
        {
            // BD-SHARED-SESSION F6: a torn store is EVIDENCE — it is
            // quarantined (renamed aside with a timestamp), never
            // silently overwritten by the next Save, which used to
            // wipe the entire flow history while the class claimed
            // "totals only ever grow". The ledger starts empty; the
            // quarantined file and the report's gap cross-check say so.
            QuarantineCorruptStore();
        }
        catch (IOException) { /* unreadable store: start empty rather than fail the Core */ }
    }

    private void QuarantineCorruptStore()
    {
        try
        {
            if (_path is not null && File.Exists(_path))
                File.Move(_path, _path + ".corrupt-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss"),
                    overwrite: false);
        }
        catch { /* quarantine is best-effort; starting empty still holds */ }
    }

    private void Save()
    {
        if (_path is null) return;
        var dtos = _bySession.Values.Select(r => new RecordDto(
            r.SessionId, r.Kind, r.PairingId, r.AgentName, r.StartedUtc, r.EndedUtc, r.OutsideSession,
            r.Tools.Values.Select(t => new ToolDto(t.Tool, t.Class, t.Calls, t.BytesIn, t.BytesOut)).ToArray(),
            r.Destinations.ToArray())).ToList();
        var tmp = _path + ".tmp";
        try
        {
            // BD-SHARED-SESSION F6: flush to disk before the replace,
            // and an IO failure NEVER surfaces into the choke point —
            // flow accounting is a witness, not a gate; a failed save
            // loses this increment, not the tool call. (Append-only
            // journaling remains the named larger redesign; the
            // per-call rewrite cost is bounded by the record count.)
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(dtos, JsonOpts));
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, _path, overwrite: true);
        }
        catch (IOException) { /* the call is not failed for a witness's IO error */ }
        catch (UnauthorizedAccessException) { /* same posture */ }
    }
}

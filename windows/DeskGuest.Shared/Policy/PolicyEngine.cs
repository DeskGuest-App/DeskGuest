using System.Text.Json;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.State;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Shared.Policy;

/// <summary>Outcome of the policy choke point (SPEC §4.4, DESIGN §3.1).</summary>
public sealed record PolicyDecision(bool Allowed, string? DenyReason, bool IsNeverRule = false)
{
    public static PolicyDecision Allow() => new(true, null);
    public static PolicyDecision Deny(string reason, bool never = false) => new(false, reason, never);
}

/// <summary>
/// The single choke point every tool call passes, in SPEC §4.4 order:
/// pairing scope → session state → sensitive-action gates →
/// protected targets → rate/volume limits → (execute) → log.
/// Enforcement lives here, never in agent behaviour.
/// </summary>
public sealed class PolicyEngine
{
    /// <summary>Gate classes gated in EVERY approval mode (DESIGN §6.7, SPEC §7.4).</summary>
    public static readonly IReadOnlySet<string> GatedClasses = new HashSet<string>
    {
        "payments", "sending", "deletions", "installs", "service_stop_non_deskguest", "shutdown", "vault_ops", "power", "clipboard_read", "clipboard_write"
    };

    private readonly int _maxCallsPerMinute;
    private readonly Dictionary<string, List<DateTimeOffset>> _callTimes = new();
    private readonly object _gate = new();

    public PolicyEngine(int maxCallsPerMinute = 240) => _maxCallsPerMinute = maxCallsPerMinute;

    /// <summary>Windows/process names the owner has marked protected (DESIGN §6.5).
    /// A protected foreground window blocks capture and input.
    /// W13 / DS-P7-F19 (closure): the set is a LOCKED set — every
    /// caller-side write (Add/Remove/Clear/…) and every read takes
    /// the same lock, so the W12 posture (engine reads under its own
    /// gate while callers wrote lock-free) is closed: there is no
    /// unsynchronized access path left, from inside or outside the
    /// engine. The public surface stays ISet&lt;string&gt; so existing
    /// callers compile unchanged; the instance is thread-safe by
    /// construction. Enumeration returns a snapshot.</summary>
    public ISet<string> ProtectedTargets { get; } = new LockedStringSet();

    /// <summary>A HashSet whose every operation serializes on one
    /// lock (W13 / DS-P7-F19). Ordinal-ignore-case, like the set it
    /// replaces. GetEnumerator enumerates a snapshot taken under
    /// the lock, so a caller iterating while another thread writes
    /// can neither tear nor throw.</summary>
    private sealed class LockedStringSet : ISet<string>
    {
        private readonly HashSet<string> _inner = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _setGate = new();
        public int Count { get { lock (_setGate) return _inner.Count; } }
        public bool IsReadOnly => false;
        public bool Add(string item) { lock (_setGate) return _inner.Add(item); }
        void ICollection<string>.Add(string item) => Add(item);
        public void Clear() { lock (_setGate) _inner.Clear(); }
        public bool Contains(string item) { lock (_setGate) return _inner.Contains(item); }
        public void CopyTo(string[] array, int arrayIndex) { lock (_setGate) _inner.CopyTo(array, arrayIndex); }
        public bool Remove(string item) { lock (_setGate) return _inner.Remove(item); }
        public IEnumerator<string> GetEnumerator()
        { string[] snap; lock (_setGate) snap = _inner.ToArray(); return ((IEnumerable<string>)snap).GetEnumerator(); }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public void ExceptWith(IEnumerable<string> other) { lock (_setGate) _inner.ExceptWith(other); }
        public void IntersectWith(IEnumerable<string> other) { lock (_setGate) _inner.IntersectWith(other); }
        public bool IsProperSubsetOf(IEnumerable<string> other) { lock (_setGate) return _inner.IsProperSubsetOf(other); }
        public bool IsProperSupersetOf(IEnumerable<string> other) { lock (_setGate) return _inner.IsProperSupersetOf(other); }
        public bool IsSubsetOf(IEnumerable<string> other) { lock (_setGate) return _inner.IsSubsetOf(other); }
        public bool IsSupersetOf(IEnumerable<string> other) { lock (_setGate) return _inner.IsSupersetOf(other); }
        public bool Overlaps(IEnumerable<string> other) { lock (_setGate) return _inner.Overlaps(other); }
        public bool SetEquals(IEnumerable<string> other) { lock (_setGate) return _inner.SetEquals(other); }
        public void SymmetricExceptWith(IEnumerable<string> other) { lock (_setGate) _inner.SymmetricExceptWith(other); }
        public void UnionWith(IEnumerable<string> other) { lock (_setGate) _inner.UnionWith(other); }
    }

    public PolicyDecision Evaluate(
        Pairing pairing,
        ToolDescriptor tool,
        JsonElement arguments,
        SessionFacts session,
        EndpointState endpointState,
        IReadOnlySet<string> approvedGateClasses,
        string? foregroundWindowName = null,
        string? foregroundProcessName = null) =>
        EvaluateCore(pairing, tool, arguments, session, endpointState, approvedGateClasses,
            foregroundWindowName, foregroundProcessName, recordRateCall: true);

    /// <summary>U3 dry-run evaluation: the SAME verdicts Evaluate
    /// would give, with NO state change — in particular the rate /
    /// volume leg is only PEEKED, never recorded, so validating a
    /// call consumes none of the pairing's budget and a dry run can
    /// be repeated freely. Honest limit: a dry run reserves nothing;
    /// a later live call is re-evaluated against the facts (and the
    /// rate window) as they stand at that moment.</summary>
    public PolicyDecision EvaluateDryRun(
        Pairing pairing,
        ToolDescriptor tool,
        JsonElement arguments,
        SessionFacts session,
        EndpointState endpointState,
        IReadOnlySet<string> approvedGateClasses,
        string? foregroundWindowName = null,
        string? foregroundProcessName = null) =>
        EvaluateCore(pairing, tool, arguments, session, endpointState, approvedGateClasses,
            foregroundWindowName, foregroundProcessName, recordRateCall: false);

    private PolicyDecision EvaluateCore(
        Pairing pairing,
        ToolDescriptor tool,
        JsonElement arguments,
        SessionFacts session,
        EndpointState endpointState,
        IReadOnlySet<string> approvedGateClasses,
        string? foregroundWindowName,
        string? foregroundProcessName,
        bool recordRateCall)
    {
        // 0. Kill switches outrank everything (DESIGN §6.6).
        if (session.StopInForce)
            return PolicyDecision.Deny("stopped_by_user: a kill switch (STOP) is in force on this host");

        // 1. Scope.
        if (!pairing.Scopes.Contains(tool.RequiredScope))
            return PolicyDecision.Deny($"scope: pairing '{pairing.AgentName}' lacks scope '{tool.RequiredScope}' for {tool.Name}");

        // 2. Session state.
        if (tool.Session == SessionRequirement.Agent)
        {
            if (!session.AgentConnected)
                return PolicyDecision.Deny("no_session: the session agent is not connected (nobody logged on, or the agent is down)");
            if (session.SessionExists && !session.DesktopUnlocked)
                return PolicyDecision.Deny("desktop_locked: the desktop is on the secure desktop; desktop tools report unavailable, never fake results");
            if (session.TakeoverActive)
                return PolicyDecision.Deny("takeover: the owner has taken over the desktop; capture and input are suspended");
        }

        // 3. Sensitive-action gates.
        if (tool.GateClass is { } gateClass && GatedClasses.Contains(gateClass) && !approvedGateClasses.Contains(gateClass))
            return PolicyDecision.Deny($"gated:{gateClass}: this action class requires approval; it is gated in every approval mode");
        // W12 / DS-P7-F12: an UNKNOWN or malformed gate class fails
        // CLOSED — previously a misspelled/new class ("deletion" for
        // "deletions") was treated as ungated and executed with no
        // approval. A declared-but-unknown class gates unless the
        // human explicitly approved that exact class.
        if (tool.GateClass is { } unknownClass && !GatedClasses.Contains(unknownClass))
        {
            if (string.IsNullOrWhiteSpace(unknownClass))
                return PolicyDecision.Deny("gated:malformed: the tool declares an empty gate class — refused (unknown policy denies)");
            if (!approvedGateClasses.Contains(unknownClass))
                return PolicyDecision.Deny($"gated:{unknownClass}: this action class is not a known gated class and is not approved — refused (unknown policy denies)");
        }

        // 3a. NEVER rule (X1 / SPEC §7.4): typing into a credential-class field
        // is refused outright in every scope; no approval can enable it.
        // bd-shared-sec-2/F3: this flag check is DEFENSE IN DEPTH, not the
        // authority -- the flag is agent-supplied, so an agent omitting it
        // defeats THIS check. The authority is host-side at the desktop
        // engine: DeskGuest.SessionAgent's DesktopEngine.FocusBlocksTyping reads
        // the focused element's UIA IsPassword property and fails CLOSED
        // when it cannot verify, for type_text, multi_edit and set_value
        // alike, whatever any argument claims.
        if (tool.Name is "type_text" or "multi_edit" or "set_value") // DS-P7-F23: set_value was named in the comment but missing from the check
        {
            if (arguments.ValueKind == JsonValueKind.Object &&
                arguments.TryGetProperty("target_is_credential_field", out var flag) &&
                flag.ValueKind == JsonValueKind.True)
                return PolicyDecision.Deny("never: typing into password/OTP/PIN fields is refused outright (DeskGuest §7.4); no approval enables it", never: true);
        }

        // 4. Protected targets (DESIGN §6.5). The agent's foreground
        // feed supplies BOTH the window title and the owning process
        // name (M5 wiring); a match on either blocks capture/input.
        if (tool.Session == SessionRequirement.Agent)
        {
            // W13 / DS-P7-F19 (closure): ProtectedTargets is a
            // locked set — Contains serializes against every
            // caller-side write on the set's own lock; no engine-side
            // gate is needed and no unsynchronized path remains.
            bool nameProtected, procProtected;
            {
                nameProtected = foregroundWindowName is not null && ProtectedTargets.Contains(foregroundWindowName);
                procProtected = foregroundProcessName is not null && ProtectedTargets.Contains(foregroundProcessName);
            }
            if (nameProtected)
                return PolicyDecision.Deny($"blocked_by_user_rule: '{foregroundWindowName}' is a protected target");
            if (procProtected)
                return PolicyDecision.Deny($"blocked_by_user_rule: '{foregroundProcessName}' is a protected target");
        }

        // 5. Rate / volume limits. A dry run peeks at the current
        // window without pruning or recording: it must leave the
        // counter exactly as it found it.
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (recordRateCall)
            {
                // W12 / DS-P7-F19: prune fully-stale pairing entries
                // so the map does not grow for the process lifetime.
                if (_callTimes.Count > 1024)
                {
                    foreach (var stale in _callTimes.Where(kv => kv.Value.All(t => now - t > TimeSpan.FromMinutes(1))).Select(kv => kv.Key).ToList())
                        _callTimes.Remove(stale);
                }
                if (!_callTimes.TryGetValue(pairing.Id, out var times))
                    _callTimes[pairing.Id] = times = new List<DateTimeOffset>();
                times.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
                if (times.Count >= _maxCallsPerMinute)
                    return PolicyDecision.Deny($"rate_limited: pairing exceeded {_maxCallsPerMinute} calls/minute");
                times.Add(now);
            }
            else
            {
                var recent = _callTimes.TryGetValue(pairing.Id, out var times)
                    ? times.Count(t => now - t <= TimeSpan.FromMinutes(1))
                    : 0;
                if (recent >= _maxCallsPerMinute)
                    return PolicyDecision.Deny($"rate_limited: pairing exceeded {_maxCallsPerMinute} calls/minute");
            }
        }

        return PolicyDecision.Allow();
    }
}

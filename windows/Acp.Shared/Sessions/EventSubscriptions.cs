using System.Threading.Channels;

namespace Acp.Shared.Sessions;

/// <summary>U2 — the agent event-kind registry (census kinds). This is
/// the shared contract: the subscribe tools validate against it, the
/// SSE stream filters by it, and producers publish only these kinds.
/// Android mirrors these exact strings in SessionEvents.kt.</summary>
public static class AgentEventKinds
{
    public const string Session = "session";
    public const string Approval = "approval";
    public const string ScreenChange = "screen_change";
    public const string ForegroundApp = "foreground_app";
    public const string AppCrash = "app_crash";
    public const string NotificationPosted = "notification_posted";
    /// <summary>U1 per-read indicator kind: published by the choke
    /// point after a successful clipboard_get, origin-scoped to the
    /// reading pairing. Detail carries the character count only —
    /// never the content.</summary>
    public const string ClipboardRead = "clipboard_read";

    // W12 / DS-P6-F15: a truly immutable set — the previous HashSet
    // exposed as IReadOnlySet could be downcast and mutated in-process.
    public static readonly IReadOnlySet<string> All = System.Collections.Frozen.FrozenSet.ToFrozenSet(
        new[] { Session, Approval, ScreenChange, ForegroundApp, AppCrash, NotificationPosted, ClipboardRead });

    public static bool IsValid(string kind) => All.Contains(kind);

    /// <summary>BD-SUPP-EVENTSUB F2 — the per-kind scope map: the
    /// scope a pairing must hold, live, for events of this kind to
    /// be delivered to it. Every current kind maps to Observe
    /// because the scope model has NO finer event scope: Scopes.All
    /// is observe/drive/shell/admin/unlock/background/backstage —
    /// there is no notification-read or app-read scope in the
    /// product for a kind to map TO (the packet's blocker condition
    /// — a notification scope exists and is bypassed — is false in
    /// this tree; notification_posted Detail is a producer-built
    /// factual string, never notification content from other apps).
    /// The map exists so the day a finer scope lands, kinds re-map
    /// here in ONE place and both Subscribe-side documentation and
    /// ShouldDeliver pick it up. Unknown kinds map to null = deny.</summary>
    public static string? RequiredScope(string kind) =>
        All.Contains(kind) ? Security.Scopes.Observe : null;
}

/// <summary>One agent event on the U2 bus. Detail is a short factual
/// string built by the producer from host facts — never tool
/// arguments and never tool results, so the stream can never become
/// a side channel for data the audit log redacts.</summary>
/// <param name="OriginPairingId">The pairing this event BELONGS to,
/// when it belongs to one (its session, its approval, or desktop
/// facts observed during its live session). D9 scoping: an
/// origin-scoped event is delivered ONLY to that pairing — a
/// subscription never widens what a pairing may see. Null = a host
/// fact belonging to no pairing (e.g. a foreground change with no
/// live session).</param>
/// <param name="Sequence">BD-SUPP-EVENTSUB F7: monotonic per-bus
/// sequence stamped by the bus at publish (0 = unstamped, e.g. a
/// hand-built event in a unit test). Carried to SSE as the event
/// id, so a reconnecting client can present Last-Event-ID and a
/// gap is detectable as a sequence jump.</param>
/// <param name="DeviceId">BD-SUPP-EVENTSUB F2: the host device this
/// event originated on, stamped by the bus from its configured
/// device id (the Core's own identity). The bus is per-host by
/// construction — one bus serves exactly one device — so this is a
/// provenance stamp for hub aggregation, not a filter dimension.
/// SessionId is deliberately NOT a field: this host runs at most
/// one live session (SessionManager.Current), origin-scoped events
/// already bind to that session's pairing, and null-origin events
/// are host facts that belong to no session; a session id on them
/// would be a false claim.</param>
public sealed record AgentEvent(
    DateTimeOffset Utc,
    string Kind,
    string Detail,
    string? OriginPairingId,
    long Sequence = 0,
    string? DeviceId = null);

/// <summary>One live subscription, for the consent surface
/// (BD-SUPP-EVENTSUB F6): who watches which kinds, until when.</summary>
public sealed record EventWatch(string PairingId, IReadOnlySet<string> Kinds, DateTimeOffset ExpiresUtc);

/// <summary>U2 — per-pairing subscription state. A pairing subscribes
/// to event KINDS; the filter is enforced at stream/delivery time,
/// never at publish time, so an unsubscribed pairing receives
/// nothing and a subscription can never widen a pairing's rights:
/// delivery additionally requires the pairing to hold the kind's
/// scope (see <see cref="AgentEventKinds.RequiredScope"/>) live at
/// delivery time, and passes the origin rule in
/// <see cref="AgentEventBus.ShouldDeliver"/>.
///
/// BD-SUPP-EVENTSUB: F5 — ClearPairing TOMBSTONES the pairing id, so
/// a subscribe that raced revocation cannot resurrect the watch;
/// only AllowPairing (called when a pairing is minted/exchanged —
/// ids are unguessable and never reused) clears a tombstone. F6 —
/// subscriptions EXPIRE (default 24 h; subscribing again renews)
/// and ListAll enumerates live watches for the presence/consent
/// surface.</summary>
public sealed class EventSubscriptionStore
{
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(24);

    private readonly object _gate = new();
    private readonly Dictionary<string, (HashSet<string> Kinds, DateTimeOffset ExpiresUtc)> _byPairing = new();
    private readonly HashSet<string> _tombstoned = new();
    private readonly Func<DateTimeOffset> _now;
    private readonly TimeSpan _lifetime;

    public EventSubscriptionStore(Func<DateTimeOffset>? now = null, TimeSpan? lifetime = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _lifetime = lifetime ?? DefaultLifetime;
    }

    /// <summary>Sanitise an untrusted kind string for an error
    /// message (F11): at most 32 chars, alphanumerics/underscore
    /// only — the caller's raw input never flows unbounded into a
    /// tool result or the audit trail.</summary>
    internal static string EchoKind(string? kind)
    {
        if (string.IsNullOrEmpty(kind)) return "(empty)";
        var chars = kind.Where(c => char.IsLetterOrDigit(c) || c == '_').Take(32).ToArray();
        return chars.Length == 0 ? "(invalid)" : new string(chars);
    }

    /// <summary>Subscribe a pairing to kinds. Atomic: any unknown
    /// kind refuses the whole call and changes nothing. A tombstoned
    /// (revoked) pairing cannot subscribe (F5).</summary>
    public (bool Ok, string? Error) Subscribe(string pairingId, IEnumerable<string> kinds)
    {
        var list = kinds.ToList();
        if (list.Count == 0) return (false, "kinds_required: name at least one event kind");
        if (list.Count > AgentEventKinds.All.Count * 2)
            return (false, $"too_many_kinds: at most {AgentEventKinds.All.Count * 2} kinds per call");
        // W12 / DS-P6-F16: a null kind is unknown too — FirstOrDefault
        // cannot distinguish "no match" from "the match was null".
        if (list.Any(k => k is null || !AgentEventKinds.IsValid(k)))
        {
            var unknown = list.FirstOrDefault(k => k is null || !AgentEventKinds.IsValid(k));
            return (false, $"unknown_event_kind: '{EchoKind(unknown)}' is not an event kind; valid kinds: {string.Join(", ", AgentEventKinds.All.OrderBy(k => k))}");
        }
        lock (_gate)
        {
            if (_tombstoned.Contains(pairingId))
                return (false, "pairing_revoked: a revoked pairing cannot subscribe");
            PurgeExpiredNoLock();
            if (!_byPairing.TryGetValue(pairingId, out var entry))
                _byPairing[pairingId] = entry = (new HashSet<string>(), default);
            foreach (var k in list) entry.Kinds.Add(k);
            _byPairing[pairingId] = (entry.Kinds, _now() + _lifetime); // subscribe renews (F6)
        }
        return (true, null);
    }

    /// <summary>Unsubscribe. Null/empty kinds = remove the pairing's
    /// whole subscription. Unknown kinds refuse (a typo must not
    /// silently leave a subscription in force).</summary>
    public (bool Ok, string? Error) Unsubscribe(string pairingId, IEnumerable<string>? kinds)
    {
        var list = kinds?.ToList();
        if (list is { Count: > 0 })
        {
            if (list.Count > AgentEventKinds.All.Count * 2)
                return (false, $"too_many_kinds: at most {AgentEventKinds.All.Count * 2} kinds per call");
            if (list.Any(k => k is null || !AgentEventKinds.IsValid(k)))
            {
                var unknown = list.FirstOrDefault(k => k is null || !AgentEventKinds.IsValid(k));
                return (false, $"unknown_event_kind: '{EchoKind(unknown)}' is not an event kind");
            }
        }
        lock (_gate)
        {
            if (list is null or { Count: 0 }) { _byPairing.Remove(pairingId); return (true, null); }
            if (_byPairing.TryGetValue(pairingId, out var entry))
            {
                foreach (var k in list) entry.Kinds.Remove(k);
                if (entry.Kinds.Count == 0) _byPairing.Remove(pairingId);
            }
        }
        return (true, null);
    }

    public IReadOnlySet<string> FilterFor(string pairingId)
    {
        lock (_gate)
        {
            PurgeExpiredNoLock();
            return _byPairing.TryGetValue(pairingId, out var entry)
                ? new HashSet<string>(entry.Kinds) : new HashSet<string>();
        }
    }

    /// <summary>F8: the delivery-path check — a Contains under the
    /// lock, no HashSet copy per event per handler.</summary>
    public bool IsSubscribed(string pairingId, string kind)
    {
        lock (_gate)
        {
            if (!_byPairing.TryGetValue(pairingId, out var entry)) return false;
            if (entry.ExpiresUtc <= _now()) { _byPairing.Remove(pairingId); return false; }
            return entry.Kinds.Contains(kind);
        }
    }

    /// <summary>F6: every live watch, for the presence/consent
    /// surface — a standing watch channel must be visible.</summary>
    public IReadOnlyList<EventWatch> ListAll()
    {
        lock (_gate)
        {
            PurgeExpiredNoLock();
            return _byPairing
                .Select(kv => new EventWatch(kv.Key, new HashSet<string>(kv.Value.Kinds), kv.Value.ExpiresUtc))
                .ToList();
        }
    }

    /// <summary>Drop a pairing's subscription outright AND tombstone
    /// the id (F5): a dead pairing keeps no event rights, and a
    /// subscribe racing this call cannot bring the watch back.</summary>
    public void ClearPairing(string pairingId)
    {
        lock (_gate)
        {
            _byPairing.Remove(pairingId); _tombstoned.Add(pairingId);
            // W12 / DS-P6-F14: tombstones are capped — a long-lived Core
            // revoking many pairings must not grow this set without
            // bound. Pairing ids are never reused, so dropping the
            // oldest tombstones past the cap cannot resurrect a watch
            // (a resurrected subscribe would still need the id, which
            // is unguessable and never re-minted).
            while (_tombstoned.Count > 4096)
            {
                var oldest = _tombstoned.FirstOrDefault(id => id != pairingId);
                if (oldest is null) break;
                _tombstoned.Remove(oldest);
            }
        }
    }

    /// <summary>Clear a tombstone. Called ONLY when a pairing id is
    /// minted/exchanged (ids are unguessable bearer-bound identities,
    /// never reused), never from the subscribe path itself.</summary>
    public void AllowPairing(string pairingId)
    {
        lock (_gate) _tombstoned.Remove(pairingId);
    }

    public bool IsTombstoned(string pairingId) { lock (_gate) return _tombstoned.Contains(pairingId); }

    private void PurgeExpiredNoLock()
    {
        var now = _now();
        foreach (var id in _byPairing.Where(kv => kv.Value.ExpiresUtc <= now).Select(kv => kv.Key).ToList())
            _byPairing.Remove(id);
    }
}

/// <summary>U2 — the event bus. Producers publish; each attached
/// stream receives only what <see cref="ShouldDeliver"/> allows for
/// ITS pairing.
///
/// BD-SUPP-EVENTSUB: F1 — the scope lookup is FAIL-CLOSED: a bus
/// built without one delivers NOTHING (the pre-fix one-arg
/// constructor left the delegate null and the 4-arg rule treated
/// null as allow, and the Core in fact wired the one-arg form, so
/// production delivery never checked Observe at all). F3 — Publish
/// never runs a handler on the producer's thread: each attachment
/// owns a bounded channel (128, drop-oldest) drained by its own
/// pump, so a stalled stream can neither block the producer (one
/// producer is the policy choke point) nor starve other streams.
/// F7 — every event is stamped with a monotonic sequence and kept
/// in a bounded 128-event ring; ReplaySince serves Last-Event-ID
/// reconnects, and a gap shows as a sequence jump. F4 —
/// RevokePairing clears the store, tombstones the id, detaches the
/// pairing's streams and completes their channels.</summary>
public sealed class AgentEventBus
{
    public const int StreamQueueCapacity = 128;
    public const int RingCapacity = 128;

    private readonly EventSubscriptionStore _store;
    private readonly Func<string, string, bool>? _holdsScopeNow;
    private readonly string? _deviceId;
    private readonly object _gate = new();
    private readonly List<Attachment> _attachments = new();
    private readonly Queue<AgentEvent> _ring = new();
    private readonly Dictionary<string, long> _pairingFloor = new(); // W12 DS-P6-F9: first-attach sequence per pairing
    private long _sequence;

    private sealed class Attachment
    {
        public required string PairingId;
        public required Action<AgentEvent> Handler;
        public required Channel<AgentEvent> Queue;
        public required Task Pump;
    }

    /// <summary>Fail-closed by construction (F1): with no scope
    /// source wired, this bus delivers nothing. Embedders with no
    /// pairing store must say so explicitly by passing a delegate —
    /// there is no silent legacy posture any more.</summary>
    public AgentEventBus(EventSubscriptionStore store) : this(store, null, null) { }

    /// <param name="holdsObserveNow">Legacy single-scope form: the
    /// live Observe lookup. Adapted onto the per-kind scope map —
    /// every current kind requires Observe (F2).</param>
    public AgentEventBus(EventSubscriptionStore store, Func<string, bool>? holdsObserveNow)
        : this(store, holdsObserveNow is null ? null : (Func<string, string, bool>)((id, scope) =>
            scope == Security.Scopes.Observe && holdsObserveNow(id)), null) { }

    /// <param name="holdsScopeNow">The live per-(pairing, scope)
    /// lookup consulted at every delivery. Null = deny everything.</param>
    /// <param name="deviceId">This host's device id, stamped onto
    /// every event as provenance (F2).</param>
    public AgentEventBus(EventSubscriptionStore store, Func<string, string, bool>? holdsScopeNow, string? deviceId)
    {
        _store = store;
        _holdsScopeNow = holdsScopeNow;
        _deviceId = deviceId;
    }

    public EventSubscriptionStore Store => _store;

    /// <summary>The D9 delivery rule (subscription + origin only).
    /// W12 / DS-P6-F4: this scope-free form is PRIVATE — it was public
    /// and any SSE call site grabbing the natural three-argument form
    /// delivered events to a pairing whose Observe scope was revoked.
    /// The only public predicates are the fail-closed scoped ones
    /// below, which additionally require the live scope RIGHT NOW.</summary>
    private static bool ShouldDeliverBasic(EventSubscriptionStore store, string pairingId, AgentEvent evt) =>
        store.IsSubscribed(pairingId, evt.Kind) &&
        (evt.OriginPairingId is null || string.Equals(evt.OriginPairingId, pairingId, StringComparison.Ordinal));

    /// <summary>BD-SHARED-SESSION F10 + BD-SUPP-EVENTSUB F1/F2:
    /// delivery ALSO requires the pairing to hold the kind's scope
    /// RIGHT NOW (see the per-kind map). A null scope source DENIES
    /// — the pre-fix rule treated null as allow, which is how a
    /// pairing whose Observe was removed kept receiving host facts.</summary>
    public static bool ShouldDeliver(EventSubscriptionStore store, string pairingId, AgentEvent evt,
        Func<string, bool>? holdsObserveNow)
    {
        if (!ShouldDeliverBasic(store, pairingId, evt)) return false;
        if (holdsObserveNow is null) return false;
        return holdsObserveNow(pairingId);
    }

    /// <summary>The scope-map form of the delivery rule (F2).</summary>
    public static bool ShouldDeliver(EventSubscriptionStore store, string pairingId, AgentEvent evt,
        Func<string, string, bool>? holdsScopeNow)
    {
        if (!ShouldDeliverBasic(store, pairingId, evt)) return false;
        if (holdsScopeNow is null) return false;
        var required = AgentEventKinds.RequiredScope(evt.Kind);
        return required is not null && holdsScopeNow(pairingId, required);
    }

    private bool ShouldDeliverScoped(string pairingId, AgentEvent evt) =>
        ShouldDeliver(_store, pairingId, evt, _holdsScopeNow);

    public void Attach(string pairingId, Action<AgentEvent> handler)
    {
        var queue = Channel.CreateBounded<AgentEvent>(new BoundedChannelOptions(StreamQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });
        var attachment = new Attachment
        {
            PairingId = pairingId,
            Handler = handler,
            Queue = queue,
            Pump = Task.Run(async () =>
            {
                try
                {
                    await foreach (var evt in queue.Reader.ReadAllAsync())
                    {
                        // W12 / DS-P6-F2: delivery-time re-check.
                        // TryComplete does NOT discard buffered items,
                        // so a pairing that banked events under TCP
                        // backpressure and was then revoked (or lost
                        // Observe) would otherwise drain them AFTER
                        // revocation. The scope/subscription test runs
                        // again immediately before the handler.
                        if (!ShouldDeliverScoped(pairingId, evt)) continue;
                        try { handler(evt); } catch { /* one dead stream never blocks delivery */ }
                    }
                }
                catch { /* channel completed during teardown */ }
            }),
        };
        lock (_gate)
        {
            _attachments.Add(attachment);
            // W12 / DS-P6-F9: remember the sequence at first attach so
            // ReplaySince can never backfill events from before this
            // pairing existed on the bus.
            if (!_pairingFloor.ContainsKey(pairingId)) _pairingFloor[pairingId] = _sequence;
        }
    }

    public void Detach(string pairingId, Action<AgentEvent> handler)
    {
        List<Attachment> removed;
        lock (_gate)
        {
            removed = _attachments.Where(a => a.PairingId == pairingId && a.Handler == handler).ToList();
            _attachments.RemoveAll(a => removed.Contains(a));
        }
        foreach (var a in removed) a.Queue.Writer.TryComplete();
    }

    /// <summary>F4: revocation, whole and immediate — the store
    /// entry is cleared and tombstoned, every attached stream for
    /// the pairing is detached and its channel completed (the SSE
    /// layer's pump ends, which ends the stream), and no later
    /// subscribe can resurrect the watch (F5).</summary>
    public void RevokePairing(string pairingId)
    {
        _store.ClearPairing(pairingId);
        List<Attachment> removed;
        lock (_gate)
        {
            removed = _attachments.Where(a => a.PairingId == pairingId).ToList();
            _attachments.RemoveAll(a => a.PairingId == pairingId);
            _pairingFloor.Remove(pairingId);
        }
        foreach (var a in removed) a.Queue.Writer.TryComplete();
    }

    /// <summary>F7: events after <paramref name="afterSequence"/>
    /// that this pairing may see, from the bounded ring — the
    /// Last-Event-ID resume. An empty result with a live sequence
    /// gap means the ring rolled past the client; the client sees
    /// the jump in the next live event's sequence.</summary>
    public IReadOnlyList<AgentEvent> ReplaySince(string pairingId, long afterSequence)
    {
        List<AgentEvent> ring;
        long floor;
        lock (_gate) { ring = _ring.ToList(); floor = _pairingFloor.TryGetValue(pairingId, out var f) ? f : 0; }
        // W12 / DS-P6-F9: never backfill before the pairing's first
        // attach. W12 / DS-P6-F8: always in sequence order.
        var effectiveAfter = Math.Max(afterSequence, floor);
        return ring.Where(e => e.Sequence > effectiveAfter && ShouldDeliverScoped(pairingId, e))
            .OrderBy(e => e.Sequence).ToList();
    }

    public long CurrentSequence => Interlocked.Read(ref _sequence);

    /// <summary>Publish one event. Unknown kinds are dropped (a
    /// producer bug must not invent a channel). F3: this method
    /// only stamps, rings and TryWrites — it never invokes a
    /// handler, so it cannot be stalled by any stream.</summary>
    public void Publish(string kind, string detail, string? originPairingId)
    {
        if (!AgentEventKinds.IsValid(kind)) return;
        List<Attachment> snapshot;
        AgentEvent evt;
        lock (_gate)
        {
            // W12 / DS-P6-F8: stamp AND enqueue under one gate, so ring
            // order is sequence order even with concurrent producers.
            evt = new AgentEvent(DateTimeOffset.UtcNow, kind, detail, originPairingId,
                ++_sequence, _deviceId);
            _ring.Enqueue(evt);
            while (_ring.Count > RingCapacity) _ring.Dequeue();
            snapshot = _attachments.ToList();
        }
        foreach (var a in snapshot)
        {
            if (!ShouldDeliverScoped(a.PairingId, evt)) continue;
            a.Queue.Writer.TryWrite(evt); // bounded + DropOldest: never blocks
        }
    }
}

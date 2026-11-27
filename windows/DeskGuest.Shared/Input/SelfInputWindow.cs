namespace DeskGuest.Shared.Input;

/// <summary>
/// FR-130 / FR-136 — the agent's own-injection window: how the
/// local-input watcher tells the session agent's OWN injected
/// input apart from input that arrived from outside this process.
///
/// The engine notes every raw injection it makes (SendInput
/// batches and real-cursor placements) before and after the send.
/// For a short tail after the last note, input evidence is treated
/// as self-generated: SendInput advances the same last-input tick
/// and sets the same pressed-since bits a physical press does, so
/// without this bracket the agent could yield driving to itself —
/// and with FR-136's cursor positioning (the engine now moves the
/// real cursor on every click) it would do so on every action.
///
/// Scope, stated plainly: this distinguishes ONLY this process's
/// own injections. Input injected by any other process (the
/// windows-mcp bridge, another tool) still classifies by class
/// exactly as before — the bridge's input firing the watcher is
/// the W73-proven, by-design behaviour. Physical input is never
/// inside the window unless it lands within the tail of an agent
/// injection, and then only its first poll is suppressed: the
/// owner's continued input yields normally a fraction of a second
/// later.
///
/// FR-141 amendment (battery run 6, 2026-11-25): the tail alone
/// does NOT cover a long operation. A sustained paced type_text
/// notes every character, yet the watcher still yielded to the
/// agent's own typing mid-operation — four audit-attributed
/// instances in run 6, and three more in this lane's live repro
/// (flips 5.5 s, 18.4 s and 22.4 s into continuous types): some
/// stall in the send path (a thread-pool or UI-thread hiccup
/// longer than the 350 ms tail) opens a gap the tail cannot
/// span, and the watcher's evidence of the agent's own keys is
/// waiting on the other side of it. The distinction therefore
/// also has an OPERATION scope: the engine brackets each whole
/// injection operation (a full type_text, however long; a click
/// glide; a key sequence) with <see cref="BeginOperation"/>, and
/// while any operation is open the window covers unconditionally
/// — no timing is involved. The tail remains for the evidence
/// that lands just after an operation closes. Genuine owner
/// input during an operation is NOT weakened by this: the
/// watcher separately observes physical (non-injected) input
/// through its low-level hooks and never suppresses a signal
/// that physical input backs (see LocalInputWatcher).
/// </summary>
public sealed class SelfInputWindow
{
    /// <summary>How long after the last noted injection input
    /// evidence still counts as self-generated. The watcher polls
    /// every 60 ms; 350 ms covers several polls past the send
    /// while keeping the worst-case delay to a genuine takeover
    /// under half a second.</summary>
    public static readonly TimeSpan DefaultTail = TimeSpan.FromMilliseconds(350);

    /// <summary>The one window for the session-agent process:
    /// the desktop engine notes, the local-input watcher reads.</summary>
    public static SelfInputWindow Shared { get; } = new(DefaultTail);

    private readonly long _tailTicks;
    private long _lastNoteTicks;
    private int _openOperations;

    public SelfInputWindow(TimeSpan tail) => _tailTicks = tail.Ticks;

    /// <summary>Record an injection at this instant. Called by
    /// the injecting path immediately before and after each raw
    /// send, so a send that itself takes time stays covered.</summary>
    public void Note(DateTime utcNow) =>
        Interlocked.Exchange(ref _lastNoteTicks, utcNow.Ticks);

    /// <summary>FR-141: open an injection operation. While at
    /// least one operation is open, <see cref="Covers"/> is true
    /// regardless of note timing — the bracket, not the clock,
    /// carries the distinction for the operation's whole
    /// duration. Operations nest (a batch brackets as one, its
    /// sub-operations bracket again); the window closes when the
    /// outermost scope disposes. Dispose is idempotent.</summary>
    public IDisposable BeginOperation()
    {
        Interlocked.Increment(ref _openOperations);
        return new OperationScope(this);
    }

    /// <summary>True while any injection operation is open.</summary>
    public bool OperationActive => Volatile.Read(ref _openOperations) > 0;

    /// <summary>True when input evidence observed at
    /// <paramref name="utcNow"/> falls inside the window of the
    /// most recent noted injection, or while an injection
    /// operation is open (FR-141).</summary>
    public bool Covers(DateTime utcNow)
    {
        if (OperationActive) return true;
        var last = Interlocked.Read(ref _lastNoteTicks);
        if (last == 0) return false;
        var delta = utcNow.Ticks - last;
        return delta >= 0 && delta <= _tailTicks;
    }

    private sealed class OperationScope : IDisposable
    {
        private SelfInputWindow? _owner;
        public OperationScope(SelfInputWindow owner) => _owner = owner;
        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            if (owner is not null) Interlocked.Decrement(ref owner._openOperations);
        }
    }
}

namespace Acp.Shared.Input;

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

    public SelfInputWindow(TimeSpan tail) => _tailTicks = tail.Ticks;

    /// <summary>Record an injection at this instant. Called by
    /// the injecting path immediately before and after each raw
    /// send, so a send that itself takes time stays covered.</summary>
    public void Note(DateTime utcNow) =>
        Interlocked.Exchange(ref _lastNoteTicks, utcNow.Ticks);

    /// <summary>True when input evidence observed at
    /// <paramref name="utcNow"/> falls inside the window of the
    /// most recent noted injection.</summary>
    public bool Covers(DateTime utcNow)
    {
        var last = Interlocked.Read(ref _lastNoteTicks);
        if (last == 0) return false;
        var delta = utcNow.Ticks - last;
        return delta >= 0 && delta <= _tailTicks;
    }
}

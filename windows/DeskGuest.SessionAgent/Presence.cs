using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Presence;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Image = System.Windows.Controls.Image;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The presence layer, re-skinned to the Windows design of record
/// (W8, TRIO-SIGNED merged record §1/§2). Presence is exactly THREE
/// elements, drawn ONLY from PresenceLaw:
///
/// (1) The BOX — in its live form the Screen 11 PILL (W72,
///     Board 4): a 640x94 navy pill (#0F2537, FR-117) holding the
///     agent face circle (the reference's own robot-head mark,
///     extracted from the board; cream disc, gold ring), the
///     one-sentence line from PresenceComposition.PillSentence
///     (live pairing name bold), and STOP (ESC) at the right.
///     Mirrored at top-centre of EVERY display; the primary
///     display's pill is the interactive one, mirrors are
///     click-through. Its trim carries the state: GOLD (#E5A93B,
///     the token's designated presence-banner border) while an
///     AI controls; the law hue otherwise — green while the
///     owner drives, amber while a session sits idle or a gate
///     is up — the state sentence is always in the pill, so hue
///     is never the only carrier (CVD rule).
/// (2) The GHOST — a ring with the actor's initial inside (one
///     geometry, both platforms). Glide per PresenceLaw.GlideMs,
///     90 ms settle, 650 ms dwell; parks dimmed at the edge;
///     withdraws while a gate is up or the owner is driving.
/// (3) The GLOW — an edge glow on EVERY display: full strength
///     (the owner's comfort intensity) on the display the agent is
///     acting on, the 40% legibility floor on the others, never
///     unlit. Static by default; the 6.4 s breath is comfort-only.
///
/// Blocked (STOP in force): the Box alone, naming the blocked
/// agent, with CLEAR STOP and DISMISS — both wired. No glow, no
/// ghost: nothing is being controlled. Off / BlockedDismissed:
/// every presence window is CLOSED, not hidden.
///
/// A presence SELF-TEST draws and verifies all three elements +
/// STOP before a session is accepted; a failed draw blocks the
/// session (the IpcClient directive path enforces it).
/// Presence is driven by session state, never by agent request.
/// UNPROVEN-ON-WINDOWS until rendered on the laptop.
///
/// W60-A (FR-111/FR-114) — ONE presence system: this layer is the
/// compositor and the ONLY owner of presence-bearing surfaces.
/// The approval gate is a card within this system: GateSheet
/// carries no presence header of its own — while a gate is up
/// this layer holds the Box (named agent, STOP) above the card
/// and the Ghost withdraws; the generic header sentence exists
/// nowhere in the session presence path (PresenceComposition
/// pins it).
///
/// W72 — the pill prints NO takeover hint (micro-decision under
/// delegation): STOP (ESC) is the visible control path; the
/// takeover chord is taught in setup/help. FR-145 (owner
/// ruling, 2026-11-25): ordinary local input NEVER yields —
/// SetOwnerDriving observes it through the state machine,
/// which returns coexist for every mode; the chord
/// (TakeoverHotkeyPressed) is the only input-path yield, and
/// hand-back is explicit only. Roster and elapsed no longer
/// print on the Box. Presence is session-bound and rendered
/// from session state on its own dispatcher path, never from
/// action cadence.
/// </summary>
public sealed class PresenceLayer
{
    private static Color LawColor(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    private static readonly Color BoxBg = LawColor(PresenceLaw.BoxBackground);
    private static readonly Color BoxFg = LawColor(PresenceLaw.BoxOnBackground);
    private static readonly Color StopRed = LawColor(PresenceLaw.HueStop);
    private static readonly Color NarrationTone = Color.FromRgb(0xC9, 0xD6, 0xE8);

    // W72 pill colours (FR-117 — the reference's own tokens).
    private static readonly Color PillBg = LawColor(PresenceLaw.PillBackground);
    private static readonly Color PillCream = LawColor(PresenceLaw.PillFaceCream);

    // FR-105 (W85): the trim and STOP colors read the owner's
    // scheme. At the default scheme these ARE the reference
    // tokens (gold trim while controlling; STOP #DC2626), so the
    // W72 rendering is unchanged until the owner customizes.
    private Color PillGold => _palette.Scheme.IsCustomized
        ? LawColor(_palette.Scheme.AiArgb) : LawColor(PresenceLaw.PillTrimGold);
    private Color PillStop => LawColor(_palette.Scheme.StopArgb);

    /// <summary>The owner's live scheme (PresencePalette — the one
    /// settings home), floor-clamped by the palette itself.</summary>
    private PresenceScheme Scheme => _palette.Scheme;

    private readonly Dispatcher _dispatcher;
    private readonly PresenceStateMachine _machine = new();
    private readonly List<Window> _glows = new();
    private Window? _box;
    private readonly List<Window> _boxMirrors = new();
    private Window? _ghost;
    private TextBlock? _narrationText;
    private Ellipse? _dwellRing;
    private CancellationTokenSource? _glideCts;
    private CancellationTokenSource? _noticeCts;
    private DispatcherTimer? _breathTimer;
    private string _narration = "";
    private long _sessionSeconds;
    private int _actionCount;
    private int _actingDisplay;
    private bool _ownerDriving;
    private bool _gateUp;
    /// <summary>W117 / F4: the Ghost's parked state — true while
    /// it sits at its park position, not yet driven this session.
    /// Parked renders DIMMED (GhostDimming); the first glide
    /// clears it and the Ghost drives at full strength.</summary>
    private bool _ghostParked = true;
    private bool _stopDrawn;
    private string? _floorHolder;
    private bool _terminalOpen;
    private List<(string Name, string Role, string Floor, string Transport)> _participants = new();
    private PresencePalette _palette = PresencePalette.Load();

    /// <summary>Raised when the owner presses STOP on the box.</summary>
    public event Action? StopPressed;
    /// <summary>Raised when the owner presses CLEAR STOP on the blocked box.</summary>
    public event Action? StopClearPressed;
    /// <summary>Raised when the owner takes over by interacting locally (reported, content never captured).</summary>
    public event Action? TakeoverDetected;
    /// <summary>FR-120 (W73): driving yielded to the owner — the
    /// argument is the input class whose signal yielded. Raised
    /// for the session record; carries no input content, ever.</summary>
    public event Action<TakeoverInputClass>? TakeoverYielded;
    /// <summary>FR-120 (W73): the takeover chord yielded driving.</summary>
    public event Action? TakeoverHotkeyYielded;
    /// <summary>FR-120 (W73): driving handed back to the agent —
    /// the argument is the actor (TakeoverActors: the owner's Box
    /// control, or the owner's gate approval).</summary>
    public event Action<string>? TakeoverHandedBack;
    /// <summary>FR-130: a stale owner-driving flag from an earlier
    /// session was cleared at a session start — the pill had
    /// latched "paused" while the Core reported no takeover.
    /// Raised so the correction lands in the audit chain.</summary>
    public event Action? TakeoverReconciled;
    /// <summary>FR-120 (W73): the active modes changed under the
    /// live layer (a UI save on this device, or a fleet-default
    /// push landing on a device that has not chosen). Arguments:
    /// (oldMouse, oldKeyboard, newMouse, newKeyboard).</summary>
    public event Action<TakeoverMode, TakeoverMode, TakeoverMode, TakeoverMode>? TakeoverModesChanged;

    private readonly TakeoverStateMachine _takeover = new();

    /// <summary>True while the owner drives (FR-120 state machine).</summary>
    public bool OwnerDrivingNow => _takeover.OwnerDriving;

    /// <summary>The active takeover modes right now (the record's
    /// modes-at-start values, read from the one settings home).</summary>
    public (TakeoverMode Mouse, TakeoverMode Keyboard) ActiveTakeoverModes =>
        (_palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode);

    /// <summary>The last self-test verdict. A session is accepted
    /// only when this passes (see IpcClient's directive path).</summary>
    public PresenceSelfTest.Result LastSelfTest { get; private set; } =
        PresenceSelfTest.Evaluate(false, false, false, false);

    public PresenceLayer(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        // Comfort edits repaint the live layer (M4 pattern, W8 law:
        // a save changes intensity/breath only — hues cannot move).
        // FR-120 (W73): a save that moved a takeover mode is ALSO a
        // session-record fact — the change is raised with old and
        // new values; the IPC client records it with its actor
        // (owner-local vs in-session, by whether a session is live).
        PresencePalette.Changed += () =>
        {
            var oldMouse = _palette.ActiveMouseTakeoverMode;
            var oldKeyboard = _palette.ActiveKeyboardTakeoverMode;
            _palette = PresencePalette.Load();
            if (_palette.ActiveMouseTakeoverMode != oldMouse || _palette.ActiveKeyboardTakeoverMode != oldKeyboard)
                TakeoverModesChanged?.Invoke(oldMouse, oldKeyboard,
                    _palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode);
            TeardownWindows();
            Render();
        };
    }

    /// <summary>The current view truth, for the host window.</summary>
    public (PresenceMode Mode, bool StopInForce, bool SessionActive, string DisplayName, long SessionSeconds, int ActionCount) ViewState =>
        (_machine.Mode, _machine.StopInForce, _machine.SessionActive, _machine.DisplayName, _sessionSeconds, _actionCount);

    // FR-121 (W76): fail-closed driver naming. The state machine
    // no longer fabricates a generic name; these are the checks
    // the IPC path and the renderers use to refuse / flag an
    // unnamed session instead of ever rendering one.
    /// <summary>True when the machine holds a SPECIFIC driver name.</summary>
    public bool HasDriverName => _machine.HasDriverName;

    /// <summary>True when a session starting with this directive
    /// name would run unnamed (no name in the directive and none
    /// already held): the FR-121 defect condition.</summary>
    public bool SessionWouldBeUnnamed(string? agentName) =>
        string.IsNullOrWhiteSpace(agentName) && !_machine.HasDriverName;

    private bool _driverNameDefect;

    /// <summary>FR-121: surface the named defect state — STOP is
    /// engaged on the machine and the blocked box renders the
    /// defect lines (never a generic driver line). Used by the IPC
    /// path when it refuses an unnamed session start.</summary>
    public void FlagDriverNameMissing(string narration)
    {
        _narration = narration;
        _driverNameDefect = true;
        _machine.ApplyDirective(false, null, true);
        Render();
    }

    /// <summary>The actor whose hue the elements currently carry.
    /// The presence directive exists only for AI sessions, so an
    /// active session is the AI acting (violet); the owner driving
    /// wins (green — reachable only by the deliberate Take
    /// control chord since FR-145); while a gate is up the Box is
    /// held amber (§3: the amber Box above the gate sheet).</summary>
    public PresenceLaw.Actor CurrentActor =>
        _ownerDriving ? PresenceLaw.Actor.Human
        : _gateUp ? PresenceLaw.Actor.Idle
        : PresenceLaw.Actor.Ai;

    /// <summary>FR-105 (W85): the state hue is the owner's scheme
    /// color for the current actor — at the default scheme exactly
    /// PresenceLaw.HueFor (violet/green/amber). State is never
    /// carried by this color alone: the pill's sentence and state
    /// word say it in words (triple-coding).</summary>
    public Color CurrentHue => LawColor(Scheme.ColorFor(CurrentActor));

    /// <summary>Owner driving: while the owner drives, the
    /// Glow/Box go green and the Box's sentence says "Paused —
    /// you're driving"; the Ghost withdraws. Since FR-145 the
    /// owner reaches this state ONLY by the deliberate Take
    /// control chord — ordinary input never yields.</summary>
    /// <summary>FR-120 (W73, live-found race): the hand-back
    /// click is itself local mouse input — without a grace
    /// window its own tick re-yields driving 23 ms after the
    /// hand-back lands (audit seq 4851→4852 on the live build).
    /// For 1.5 s after a successful hand-back, local-input yield
    /// signals are dropped: the owner has JUST said "you drive".
    /// The chord is NOT suppressed (a deliberate chord press in
    /// the window is a fresh takeover decision, not settle
    /// noise), and STOP is, as always, nowhere near this.
    /// FR-145: ordinary input can no longer yield at all (the
    /// state machine's LocalInput never yields, in any mode), so
    /// this window is now belt-and-braces on a path that cannot
    /// fire — kept so no future change can resurrect the race by
    /// re-adding a yield branch behind it.</summary>
    private DateTime _yieldSuppressedUntilUtc = DateTime.MinValue;
    private bool YieldSuppressed => DateTime.UtcNow < _yieldSuppressedUntilUtc;

    public void SetOwnerDriving(bool driving)
    {
        // FR-145 MOUSE read point: a local MOUSE-input signal is
        // OBSERVED through the shared state machine
        // (TakeoverControl), which under the FR-145 law never
        // yields — the owner coexists, the agent keeps driving,
        // in every mode. The modes are still passed from their
        // ONE settings home (PresencePalette) as record
        // vocabulary. The hand-back direction (driving == false)
        // is unchanged: it is the explicit Give control path.
        // STOP never passes through here.
        if (!driving) { HandBackToAgent(TakeoverActors.OwnerHandBackControl); return; }
        if (YieldSuppressed) return;
        _ = _takeover.LocalInput(TakeoverInputClass.Mouse,
            _palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode);
        // The outcome is always ObservedCoexist (or
        // AlreadyOwnerDriving, when the chord already handed
        // the floor over): no state change, no yield event, no
        // render — ordinary input is not a floor event.
    }

    /// <summary>FR-145: the KEYBOARD read point, beside the mouse
    /// one — a local KEYBOARD-input signal is observed through
    /// the same state machine and likewise NEVER yields, in any
    /// mode. The hand-back direction is unchanged.</summary>
    public void SetOwnerDrivingFromKeyboard(bool driving)
    {
        if (!driving) { HandBackToAgent(TakeoverActors.OwnerHandBackControl); return; }
        if (YieldSuppressed) return;
        _ = _takeover.LocalInput(TakeoverInputClass.Keyboard,
            _palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode);
        // Observed/coexist only — see the mouse path.
    }

    /// <summary>FR-120 (W73): the takeover chord
    /// (Ctrl+Alt+Shift+Backspace) pressed at the machine. Yields
    /// in EVERY mode — it is the deliberate act HotkeyOnly waits
    /// for, and it stays live under TakeOver and Share. STOP is a
    /// different chord on a different path and is never here.</summary>
    public void TakeoverHotkeyPressed()
    {
        if (!_takeover.TakeoverHotkey()) return;
        _ownerDriving = true;
        TakeoverDetected?.Invoke();
        TakeoverHotkeyYielded?.Invoke();
        Render();
    }

    /// <summary>FR-120 (W73): explicit hand-back — the ONLY way
    /// driving returns to the agent. Two callers, both the owner:
    /// the Box's hand-back control (shown only while the owner
    /// drives) and the gate path (the agent asked through the
    /// per-action gate; the owner approved on the gate card —
    /// App.xaml.cs routes that approval here). No agent-reachable
    /// path calls this: an agent cannot take control back.</summary>
    public void HandBackToAgent(string actor)
    {
        if (!_takeover.HandBack()) return;
        _ownerDriving = false;
        _yieldSuppressedUntilUtc = DateTime.UtcNow.AddMilliseconds(1500);
        TakeoverHandedBack?.Invoke(actor);
        Render();
    }

    /// <summary>FR-120 (W73): a fleet-default push landed (the
    /// Core set PresencePalette.FleetDefaults). Re-read the active
    /// modes; on a device that has not chosen they may have moved
    /// — that movement is a mode change like any other and is
    /// raised for the record (its actor is resolved by the IPC
    /// client: a push landing mid-session arrived in-session).
    /// On a device that HAS chosen, nothing moves — the local
    /// choice outranks the fleet default by construction.</summary>
    public void ApplyFleetDefaults()
    {
        var oldMouse = _palette.ActiveMouseTakeoverMode;
        var oldKeyboard = _palette.ActiveKeyboardTakeoverMode;
        _palette = PresencePalette.Load();
        if (_palette.ActiveMouseTakeoverMode != oldMouse || _palette.ActiveKeyboardTakeoverMode != oldKeyboard)
            TakeoverModesChanged?.Invoke(oldMouse, oldKeyboard,
                _palette.ActiveMouseTakeoverMode, _palette.ActiveKeyboardTakeoverMode);
        Render();
    }

    /// <summary>While a gate is up the Ghost withdraws (§2).</summary>
    public void SetGateUp(bool gateUp)
    {
        if (_gateUp == gateUp) return;
        _gateUp = gateUp;
        Render();
    }

    /// <summary>Reconcile with a complete directive from the Core.</summary>
    public void ApplyDirective(bool sessionActive, string? agentName, bool stopInForce, string? narration, long seconds = 0, int actions = 0,
        string? floorHolder = null, bool terminalOpen = false,
        List<(string Name, string Role, string Floor, string Transport)>? participants = null,
        int actingDisplay = 0)
    {
        if (narration is not null) _narration = narration;
        _sessionSeconds = seconds;
        _actionCount = actions;
        _floorHolder = floorHolder;
        _terminalOpen = terminalOpen;
        _participants = participants ?? new();
        _actingDisplay = Math.Max(0, actingDisplay);
        // FR-121: a directive that names its driver clears any
        // earlier defect flag; an all-off directive clears it too
        // (the defect belongs to the refused session, not forever).
        if (sessionActive && !string.IsNullOrWhiteSpace(agentName)) _driverNameDefect = false;
        else if (!sessionActive && !stopInForce) _driverNameDefect = false;
        var wasSessionActive = _machine.SessionActive;
        _machine.ApplyDirective(sessionActive, agentName, stopInForce);
        // FR-130: driving ownership never crosses a session
        // boundary. HideSession's reset carries this rule for the
        // legacy path, but the live lifecycle arrives HERE, as
        // directives — and before this fix nothing on this path
        // reset the takeover machine, so one yield (real or
        // spurious) latched the pill "paused — you're driving"
        // through every later session while the Core truthfully
        // reported takeover_active: false, and every agent input
        // was gated behind a hand-back nobody local was present
        // to give. On either edge the machine reconciles; a stale
        // flag cleared at a session START is a correction the
        // audit chain must carry, so it is raised, not silent.
        if (sessionActive != wasSessionActive)
        {
            var clearedStale = _takeover.ReconcileAtSessionBoundary();
            _ownerDriving = _takeover.OwnerDriving;
            if (clearedStale && sessionActive) TakeoverReconciled?.Invoke();
        }
        Render();
    }

    /// <summary>STOP engaged by any source the Core reports out-of-band.</summary>
    public void ApplyStopEngaged()
    {
        _machine.StopEngaged();
        Render();
    }

    /// <summary>Legacy session-on entry (notify path).</summary>
    public void ShowSession(string agentName, string narration)
    {
        _narration = narration;
        // FR-130: the same boundary rule as the directive path —
        // a session starting here never inherits a stale flag.
        if (_takeover.ReconcileAtSessionBoundary())
        {
            _ownerDriving = false;
            TakeoverReconciled?.Invoke();
        }
        _machine.SessionStarted(agentName);
        Render();
    }

    /// <summary>Full teardown: every presence window closes.</summary>
    public void HideSession()
    {
        // FR-120: ownership resets with the session — a new
        // session always starts with the agent driving.
        _takeover.Reset();
        _ownerDriving = false;
        // W117 / F4: the next session's Ghost parks (dimmed) again.
        _ghostParked = true;
        _machine.SessionEnded();
        if (!_machine.StopInForce) _machine.ApplyDirective(false, null, false);
        Render();
    }

    /// <summary>A transient notice: while a session or block is on
    /// screen it lands on the narration line; otherwise a
    /// dismissible notice box that hides itself after 20 s.</summary>
    public void ShowNotice(string text)
    {
        if (_machine.Mode is PresenceMode.Active or PresenceMode.Blocked)
        {
            SetNarration(text);
            return;
        }
        _dispatcher.Invoke(() =>
        {
            TeardownWindows();
            _noticeCts?.Cancel();
            _noticeCts = new CancellationTokenSource();
            var token = _noticeCts.Token;
            BuildNoticeBox(text);
            _box!.Show();
            PositionBoxes();
            _ = AutoHideNoticeAsync(token);
        });
    }

    private async Task AutoHideNoticeAsync(CancellationToken token)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(20), token); }
        catch (TaskCanceledException) { return; }
        _dispatcher.Invoke(() =>
        {
            if (_machine.Mode is PresenceMode.Off or PresenceMode.BlockedDismissed) TeardownWindows();
        });
    }

    public void SetNarration(string text)
    {
        _narration = text;
        _dispatcher.Invoke(() =>
        {
            if (_narrationText is null) return;
            // Controlling: the pill sentence is the board sentence
            // (PillSentence) and stands; narration rides the
            // session surfaces. Every other state: the pill's
            // sentence IS the state sentence, so refresh it.
            // FR-105 compact form: the refresh keeps the compact
            // line's shape (name + state word) — narration never
            // strips the driver's name off the compact pill.
            if (CurrentActor != PresenceLaw.Actor.Ai)
                // W117 / F2: branch sentences already carry the
                // driver's name — the compact refresh must not
                // prefix it a second time.
                _narrationText.Text = Scheme.Detail == PresenceDetail.CompactPill
                    && !StateSentence().StartsWith(_machine.DisplayName, StringComparison.Ordinal)
                    ? $"{_machine.DisplayName} · {StateSentence()}"
                    : StateSentence();
        });
    }

    // ---------------- Self-test ----------------

    /// <summary>Draw all three elements + STOP off the live state
    /// (a probe render on the primary display), verify each one
    /// actually drew, tear the probe down, and record the verdict.
    /// Run before a session is accepted; a failed draw blocks it.</summary>
    public PresenceSelfTest.Result RunSelfTest()
    {
        return _dispatcher.Invoke(() =>
        {
            var savedMode = _machine.Mode;
            Window? probeGlow = null, probeGhost = null, probeBox = null;
            var stopPresent = false;
            try
            {
                probeGlow = BuildGlowWindow(0, 100);
                probeGlow.Show();
                var glowDrawn = probeGlow.IsVisible && probeGlow.Content is not null;

                probeGhost = BuildGhostWindow();
                probeGhost.Show();
                var ghostDrawn = probeGhost.IsVisible && probeGhost.Content is not null;

                var stop = MakeStopButton();
                stopPresent = stop.Content as string == Strings.Get("StopEsc");
                probeBox = BoxShell(BoxContent("Self-test", stop), pill: true);
                probeBox.Show();
                var boxDrawn = probeBox.IsVisible && probeBox.Content is not null;

                LastSelfTest = PresenceSelfTest.Evaluate(boxDrawn, ghostDrawn, glowDrawn, stopPresent);
            }
            catch
            {
                LastSelfTest = PresenceSelfTest.Evaluate(false, false, false, false);
            }
            finally
            {
                try { probeGlow?.Close(); } catch { }
                try { probeGhost?.Close(); } catch { }
                try { probeBox?.Close(); } catch { }
                if (savedMode == PresenceMode.Active || savedMode == PresenceMode.Blocked) Render();
            }
            return LastSelfTest;
        });
    }

    // ---------------- Rendering ----------------

    private void Render()
    {
        _dispatcher.Invoke(() =>
        {
            switch (_machine.Mode)
            {
                case PresenceMode.Active:
                    _noticeCts?.Cancel();
                    // FR-121 (W76): an active session with no
                    // specific driver name renders the DEFECT box
                    // only — no glow, no ghost, no pill — because
                    // every one of those elements would be presence
                    // for an unnamed driver, which the law forbids.
                    if (_machine.DriverNameMissing)
                    {
                        CloseGlows();
                        CloseWindow(ref _ghost);
                        StopBreath();
                        BuildDefectBox();
                        _box!.Show();
                        PositionBoxes();
                        break;
                    }
                    EnsureGlows();
                    if (PresenceLaw.GhostDrawn(_gateUp, _ownerDriving)) EnsureGhost();
                    else CloseWindow(ref _ghost);
                    BuildActiveBox();
                    foreach (var g in _glows) g.Show();
                    _ghost?.Show();
                    _box!.Show();
                    foreach (var m in _boxMirrors) m.Show();
                    PositionBoxes();
                    StartBreathIfEnabled();
                    break;
                case PresenceMode.Blocked:
                    _noticeCts?.Cancel();
                    CloseGlows();
                    CloseWindow(ref _ghost);
                    StopBreath();
                    BuildBlockedBox();
                    _box!.Show();
                    foreach (var m in _boxMirrors) m.Show();
                    PositionBoxes();
                    break;
                default: // Off, BlockedDismissed
                    TeardownWindows();
                    break;
            }
        });
    }

    private void TeardownWindows()
    {
        _glideCts?.Cancel();
        StopBreath();
        CloseGlows();
        CloseWindow(ref _box);
        foreach (var m in _boxMirrors) { try { m.Close(); } catch { } }
        _boxMirrors.Clear();
        CloseWindow(ref _ghost);
        _narrationText = null;
        _dwellRing = null;
        _stopDrawn = false;
    }

    private void CloseGlows()
    {
        foreach (var g in _glows) { try { g.Close(); } catch { } }
        _glows.Clear();
    }

    private static void CloseWindow(ref Window? window)
    {
        try { window?.Close(); } catch { }
        window = null;
    }

    private TextBlock NameText(string text) => new()
    {
        Text = text,
        Foreground = new SolidColorBrush(BoxFg),
        FontSize = 21,
        FontWeight = FontWeights.SemiBold,
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(6, 0, 10, 0)
    };

    private TextBlock NarrationTextBlock(string? textOverride = null)
    {
        _narrationText = new TextBlock
        {
            Text = textOverride ?? _narration,
            Foreground = new SolidColorBrush(NarrationTone),
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(6, 2, 10, 0),
            TextTrimming = TextTrimming.CharacterEllipsis,
            MaxWidth = 560,
        };
        return _narrationText;
    }

    private StackPanel TextColumn(string name, string? narrationOverride = null)
    {
        var column = new StackPanel { Orientation = Orientation.Vertical, VerticalAlignment = VerticalAlignment.Center };
        column.Children.Add(NameText(name));
        column.Children.Add(NarrationTextBlock(narrationOverride));
        return column;
    }

    /// <summary>The state sentence the Box carries. W117 / F2:
    /// EVERY branch names the driver (PresenceComposition
    /// .BranchSentence is the one home) — the owner-driving
    /// branch previously read only "Paused — you're driving"
    /// and named no agent on any surface (W115 finding 2). The
    /// gate branch falls back to its branch sentence when the
    /// Core's narration has not supplied one; a supplied
    /// narration (which names the agent, as W115 captured) wins.</summary>
    private string StateSentence() =>
        _ownerDriving ? PresenceComposition.BranchSentence(
                PresenceComposition.PresenceBranch.OwnerDriving, _machine.DisplayName)
        : _gateUp && string.IsNullOrWhiteSpace(_narration) ? PresenceComposition.BranchSentence(
                PresenceComposition.PresenceBranch.Gate, _machine.DisplayName)
        : CurrentActor == PresenceLaw.Actor.Idle && string.IsNullOrWhiteSpace(_narration)
            ? PresenceComposition.BranchSentence(
                PresenceComposition.PresenceBranch.Waiting, _machine.DisplayName)
            : _narration;

    /// <summary>The Box shell. Panel form (default): always dark,
    /// hue edge, 480-640 wide — the gate/blocked/notice panels.
    /// Pill form (W72, the live session Box): fixed height 94,
    /// radius 44, FR-117 navy fill, padding (9,9,12,9) (W128 —
    /// the reference's offsets include the trim); the
    /// trim is GOLD while an AI controls (the token's designated
    /// presence-banner border, controlling-state default per the
    /// Q1 reconciliation in W71 BUILD-SPEC §2) and the state's
    /// law hue in every other state — gold never appears on
    /// gate/idle/owner-driving/blocked states.</summary>
    private Window BoxShell(UIElement content, bool clickThrough = false, bool pill = false) => new()
    {
        WindowStyle = WindowStyle.None,
        AllowsTransparency = true,
        // Transparent window background: without this the area
        // outside the Border's rounded corners paints WHITE
        // (visible at the old Box's radius-18 corners in W69's
        // capture; glaring at the pill's radius 44 — W72 live
        // capture 1). The Border is the only painted surface.
        Background = Brushes.Transparent,
        Topmost = true,
        ShowInTaskbar = false,
        ShowActivated = false,
        // W117 / F1: the pill's height is NEVER fixed — the
        // window sizes to its content in both axes, so a wrapped
        // sentence grows the pill instead of clipping mid-glyph
        // (W115: line 3 severed at the fixed 94). MinHeight is
        // the floor height (PillVisual.HeightFor — 94 full / 64
        // compact at the scheme's size), so at the reference fit
        // the pill is exactly the floor's 640×94, pixel-true;
        // growth happens only beyond it. The panel form keeps
        // its content-sized height as before.
        SizeToContent = SizeToContent.WidthAndHeight,
        MinHeight = pill ? PillVisual.HeightFor(Scheme) : double.NaN,
        Height = double.NaN,
        // W128: the FULL pill's width is the floor's 640 at the
        // scheme's size — pinned from below as well as above.
        // W117's rule ("the width never leaves 640") was only
        // half-implemented: MaxWidth capped growth, but
        // SizeToContent shrank the pill to its content, so at
        // the reference name "Axle" the live pill rendered 604
        // wide (the sentence's longest line measures 324 of the
        // 350 column) against the reference's 640 — measured
        // live this lane against W72/W115's 632–637 at longer
        // names. MinWidth = MaxWidth = 640 makes the stated
        // rule true; the sentence stays left-anchored at its
        // measured 99 DIP and the navy gap before STOP matches
        // the reference's composition. The compact pill keeps
        // its content-sized 480 floor (its own form).
        MinWidth = pill
            ? (Scheme.Detail == PresenceDetail.CompactPill ? 480 : 640) * Scheme.SizePct / 100.0
            : 480,
        MaxWidth = pill ? 640 * Scheme.SizePct / 100.0 : 640,
        Content = new Border
        {
            Background = new SolidColorBrush(pill ? PillBg : BoxBg),
            CornerRadius = new CornerRadius(pill ? 44 * Scheme.SizePct / 100.0 : 18),
            BorderBrush = new SolidColorBrush(pill && CurrentActor == PresenceLaw.Actor.Ai ? PillGold : CurrentHue),
            BorderThickness = new Thickness(2),
            // W128: pill padding (9,9,12,9), measured from the
            // Board 4 pill crop — the reference's offsets are
            // totals INCLUDING the 2-DIP trim: face at 11 DIP
            // from the pill edge (2 trim + 9 pad), STOP inset
            // 14 DIP at the right (2 + 12), and the vertical
            // stack 2+9+72+9+2 = 94 exactly (the shipped
            // (11,11,14,11) stacked to a 98-tall window —
            // GetWindowRect 640×98 measured live this lane —
            // while every prior lane read the height as the
            // spec's 94).
            Padding = pill ? new Thickness(9, 9, 12, 9) : new Thickness(22, 16, 22, 16),
            Child = content
        },
        IsHitTestVisible = !clickThrough
    };

    /// <summary>The pill face: a 72 DIP circle — cream disc, the
    /// reference's own robot-head mark extracted from Board 4
    /// (deskguest-pill-mark.png, Gemini's art; see the lane log
    /// for the extraction record), gold ring while controlling,
    /// the state hue otherwise. ONLY if the mark asset fails to
    /// load does the circle fall back to the pairing initial
    /// (PresenceLaw.GhostInitial — the W72 ruling-2 fallback,
    /// named here, never silent).</summary>
    private Grid PillFace(string name)
    {
        // FR-105 (W85): the face is drawn by PillVisual.Face — the
        // shared composition the Presence page's preview uses too.
        // The ring color rule is unchanged: gold while controlling
        // (the default scheme's trim), the state hue otherwise.
        var ringBrush = new SolidColorBrush(CurrentActor == PresenceLaw.Actor.Ai ? PillGold : CurrentHue);
        return PillVisual.Face(Scheme, name, ringBrush.Color);
    }

    /// <summary>Pill content, composed by PresenceComposition —
    /// the model yields exactly [DriverName, StateSentence, Stop]
    /// at every detail level (W72), and the pill renders exactly
    /// those: face circle (driver identity), the sentence, and
    /// STOP (ESC). Roster and elapsed are NOT pill content; the
    /// takeover hint is NOT pill content (it is taught in
    /// setup/help). Mirrors draw this same composition.
    /// FR-105 (W85): the grid itself is built by PillVisual
    /// .BuildPillContent — the shared composition the Presence
    /// page's live preview renders through, at the owner's scheme
    /// (size / detail / colors). The face ring rule is the pinned
    /// one: gold while controlling at the default scheme, the
    /// state hue otherwise.</summary>
    private UIElement BoxContent(string name, Button stop)
    {
        var ring = CurrentActor == PresenceLaw.Actor.Ai ? PillGold : CurrentHue;
        var grid = PillVisual.BuildPillContent(Scheme, CurrentActor, name,
            StateSentence(), stop, ring, tb => _narrationText = tb);
        // FR-120 (W73): while the OWNER drives, the pill gains its
        // hand-back affordance — a state of this one Box, drawn in
        // the pill's language (flat, radius 10, cream on navy),
        // sitting beside STOP. It exists ONLY in the owner-driving
        // state: when the agent drives there is nothing to hand
        // back and the pill is exactly the W72 composition.
        if (_ownerDriving)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var handBack = new Button
            {
                Content = Strings.Get("HandBackControl"),
                Height = 51,
                Background = Brushes.Transparent,
                Foreground = new SolidColorBrush(BoxFg),
                FontWeight = FontWeights.Bold,
                FontSize = 15,
                Padding = new Thickness(14, 0, 14, 0),
                Margin = new Thickness(10, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Cursor = System.Windows.Input.Cursors.Hand,
            };
            handBack.Click += (_, _) => HandBackToAgent(TakeoverActors.OwnerHandBackControl);
            Grid.SetColumn(handBack, 3);
            grid.Children.Add(handBack);
        }
        return grid;
    }

    /// <summary>The pill STOP (ESC): at the default scheme 152x51,
    /// flat #DC2626, white bold label from the pill's own Strings
    /// key (StopEsc — the tray/other STOP surfaces keep the plain
    /// Stop key). FR-105 (W85): the button is built by PillVisual
    /// .CreateStopButton — the shared builder the preview uses —
    /// at the scheme's size and STOP color. The click flow is the
    /// W60 flow, unchanged: engage the machine, re-render, raise
    /// StopPressed. Mirrors call this with interactive: false and
    /// draw the same button click-through.</summary>
    private Button MakeStopButton(bool interactive = true)
    {
        var stop = PillVisual.CreateStopButton(Scheme, interactive);
        if (interactive)
        {
            stop.Click += (_, _) =>
            {
                _dispatcher.BeginInvoke(new Action(() =>
                {
                    _machine.StopEngaged();
                    Render();
                    StopPressed?.Invoke();
                }));
            };
        }
        _stopDrawn = true;
        return stop;
    }

    private void BuildActiveBox()
    {
        CloseWindow(ref _box);
        foreach (var m in _boxMirrors) { try { m.Close(); } catch { } }
        _boxMirrors.Clear();
        // The pill names the LIVE paired agent (live-data region):
        // the raw pairing name feeds PillSentence's bold segment.
        var name = _machine.DisplayName;
        _box = BoxShell(BoxContent(name, MakeStopButton()), pill: true);
        // Mirrors on every other display: the same pill composition
        // (same face, same sentence, same STOP (ESC) drawn) —
        // click-through: the primary pill and the tray carry the
        // live STOP; a mirror never pretends to be a second
        // control surface.
        var monitors = MonitorRects();
        for (var i = 1; i < monitors.Count; i++)
        {
            var mirror = BoxShell(BoxContent(name, MakeStopButton(interactive: false)), clickThrough: true, pill: true);
            mirror.Loaded += (_, _) => MakeClickThrough(mirror);
            _boxMirrors.Add(mirror);
        }
    }

    /// <summary>FR-121 (W76): the defect box — the ONLY box an
    /// unnamed session can ever produce. It names the defect, not
    /// a driver, and carries STOP so the owner keeps a working
    /// control. Single primary-display box: this is a refusal
    /// surface, not session presence, so it is not mirrored.</summary>
    private void BuildDefectBox()
    {
        CloseWindow(ref _box);
        foreach (var m in _boxMirrors) { try { m.Close(); } catch { } }
        _boxMirrors.Clear();
        _driverNameDefect = true;
        var panel = new StackPanel { Orientation = Orientation.Vertical };
        panel.Children.Add(TextColumn(Strings.Get("PresenceDriverNameMissing"),
            Strings.Get("PresenceDriverNameMissingHint")));
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        row.Children.Add(MakeStopButton());
        panel.Children.Add(row);
        _box = BoxShell(panel);
    }

    private void BuildBlockedBox()
    {
        CloseWindow(ref _box);
        foreach (var m in _boxMirrors) { try { m.Close(); } catch { } }
        _boxMirrors.Clear();
        var panel = new StackPanel { Orientation = Orientation.Vertical };
        // FR-121 (W76): the blocked box names the SPECIFIC blocked
        // driver when one is held. It never renders a generic name:
        // a refused unnamed session shows the defect lines, and a
        // standalone STOP (no session ever ran) shows the STOP
        // banner form, which claims no driver at all.
        if (_driverNameDefect)
            panel.Children.Add(TextColumn(Strings.Get("PresenceDriverNameMissing"),
                Strings.Get("PresenceDriverNameMissingHint")));
        else if (_machine.HasDriverName)
            panel.Children.Add(TextColumn(Strings.Format("PresenceBlockedFormat", _machine.DisplayName),
                Strings.Get("PresenceBlockedHint")));
        else
            panel.Children.Add(TextColumn(Strings.Get("StopInForceBanner"),
                Strings.Get("PresenceBlockedHint")));
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        var clear = new System.Windows.Controls.Button
        {
            Content = Strings.Get("ClearStop"),
            Background = new SolidColorBrush(BoxFg),
            Foreground = new SolidColorBrush(BoxBg),
            FontWeight = FontWeights.Bold,
            FontSize = 14,
            Padding = new Thickness(16, 8, 16, 8),
            Margin = new Thickness(0, 0, 6, 0),
        };
        clear.Click += (_, _) =>
        {
            SetNarration(Strings.Get("ClearingStop"));
            StopClearPressed?.Invoke();
        };
        var dismiss = new System.Windows.Controls.Button
        {
            Content = Strings.Get("Dismiss"),
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(BoxFg),
            FontSize = 14,
            Padding = new Thickness(12, 8, 12, 8),
        };
        dismiss.Click += (_, _) =>
        {
            _dispatcher.BeginInvoke(new Action(() => { if (_machine.Dismiss()) Render(); }));
        };
        row.Children.Add(clear);
        row.Children.Add(dismiss);
        panel.Children.Add(row);
        // Blocked hue edge is the STOP red — set via a shell whose
        // border is StopRed, not the actor hue.
        _box = new Window
        {
            WindowStyle = WindowStyle.None,
            AllowsTransparency = true,
            // W76 (blocked-box latent frame, named by W72): the
            // SAME white-rectangular-frame defect W72 fixed on the
            // pill via BoxShell — this inline window never set a
            // transparent background, so the area outside the
            // Border's radius-18 corners painted white. The Border
            // is the only painted surface.
            Background = Brushes.Transparent,
            Topmost = true,
            ShowInTaskbar = false,
            ShowActivated = false,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = 480,
            MaxWidth = 640,
            Content = new Border
            {
                Background = new SolidColorBrush(BoxBg),
                CornerRadius = new CornerRadius(18),
                BorderBrush = new SolidColorBrush(StopRed),
                BorderThickness = new Thickness(2),
                Padding = new Thickness(22, 16, 22, 16),
                Child = panel
            }
        };
    }

    private void BuildNoticeBox(string text)
    {
        var dismiss = new System.Windows.Controls.Button
        {
            Content = Strings.Get("Dismiss"),
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(BoxFg),
            FontSize = 14,
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(10, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        dismiss.Click += (_, _) => _dispatcher.BeginInvoke(new Action(() => { _noticeCts?.Cancel(); TeardownWindows(); }));
        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        panel.Children.Add(NameText(text));
        panel.Children.Add(dismiss);
        _box = BoxShell(panel);
    }

    /// <summary>Monitor rectangles (DIPs approximated from the
    /// DXGI enumeration; UNPROVEN-ON-WINDOWS for scaled displays).
    /// Falls back to the primary screen alone.</summary>
    private static IReadOnlyList<(double X, double Y, double W, double H, bool Primary)> MonitorRects()
    {
        try
        {
            var mons = DxgiCapture.EnumerateMonitors();
            if (mons.Count > 0)
                return mons.Select(m => (X: (double)m.X, Y: (double)m.Y, W: (double)m.W, H: (double)m.H, Primary: m.Primary)).ToList();
        }
        catch { /* fall through */ }
        return new[] { (X: 0.0, Y: 0.0, W: SystemParameters.PrimaryScreenWidth, H: SystemParameters.PrimaryScreenHeight, Primary: true) };
    }

    /// <summary>The Box at top-centre of EVERY display (record §2):
    /// STOP is never on a screen the owner is not looking at.</summary>
    private void PositionBoxes()
    {
        var monitors = MonitorRects();
        void Place(Window w, (double X, double Y, double W, double H, bool Primary) mon)
        {
            var place = () =>
            {
                w.Left = mon.X + (mon.W - w.ActualWidth) / 2;
                w.Top = mon.Y + 12;
            };
            if (w.ActualWidth > 0) place();
            else w.SizeChanged += (_, _) => place();
        }
        if (_box is not null && monitors.Count > 0) Place(_box, monitors[0]);
        for (var i = 0; i < _boxMirrors.Count && i + 1 < monitors.Count; i++)
            Place(_boxMirrors[i], monitors[i + 1]);
    }

    // ---------------- Glow ----------------

    private Window BuildGlowWindow(int monitorIndex, int intensityPct)
    {
        const double depth = 220;
        var hue = CurrentHue;
        var edge = Color.FromArgb(0x7A, hue.R, hue.G, hue.B);
        var clear = Color.FromArgb(0x00, hue.R, hue.G, hue.B);
        System.Windows.Shapes.Rectangle Edge(GradientBrush brush, double w, double h,
            HorizontalAlignment ha, VerticalAlignment va) => new()
        {
            Width = w, Height = h, Fill = brush,
            HorizontalAlignment = ha, VerticalAlignment = va,
            IsHitTestVisible = false
        };
        var grid = new Grid { Background = Brushes.Transparent, IsHitTestVisible = false };
        grid.Children.Add(Edge(new LinearGradientBrush(edge, clear, new System.Windows.Point(0, 0), new System.Windows.Point(0, 1)),
            double.NaN, depth, HorizontalAlignment.Stretch, VerticalAlignment.Top));
        grid.Children.Add(Edge(new LinearGradientBrush(edge, clear, new System.Windows.Point(0, 1), new System.Windows.Point(0, 0)),
            double.NaN, depth, HorizontalAlignment.Stretch, VerticalAlignment.Bottom));
        grid.Children.Add(Edge(new LinearGradientBrush(edge, clear, new System.Windows.Point(0, 0), new System.Windows.Point(1, 0)),
            depth, double.NaN, HorizontalAlignment.Left, VerticalAlignment.Stretch));
        grid.Children.Add(Edge(new LinearGradientBrush(edge, clear, new System.Windows.Point(1, 0), new System.Windows.Point(0, 0)),
            depth, double.NaN, HorizontalAlignment.Right, VerticalAlignment.Stretch));
        var monitors = MonitorRects();
        var mon = monitorIndex < monitors.Count ? monitors[monitorIndex]
            : (X: 0.0, Y: 0.0, W: SystemParameters.PrimaryScreenWidth, H: SystemParameters.PrimaryScreenHeight, Primary: true);
        var window = new Window
        {
            WindowStyle = WindowStyle.None,
            AllowsTransparency = true,
            Background = Brushes.Transparent,
            Topmost = true,
            ShowActivated = false,
            ShowInTaskbar = false,
            Left = mon.X, Top = mon.Y, Width = mon.W, Height = mon.H,
            Content = grid,
            IsHitTestVisible = false,
            Opacity = Math.Clamp(intensityPct, PresenceLaw.GlowIntensityFloorPct, 100) / 100.0,
        };
        window.Loaded += (_, _) => MakeClickThrough(window);
        return window;
    }

    private void EnsureGlows()
    {
        if (_glows.Count > 0) return;
        var monitors = MonitorRects();
        for (var i = 0; i < monitors.Count; i++)
            _glows.Add(BuildGlowWindow(i, _palette.IntensityForDisplay(i == _actingDisplay)));
    }

    /// <summary>Breath (comfort only): opacity oscillates between
    /// 82% and 100% of the window's set intensity over 6.4 s. Off
    /// by default — the Glow is static (OI-04).</summary>
    private void StartBreathIfEnabled()
    {
        StopBreath();
        if (!_palette.BreathEnabled || _glows.Count == 0) return;
        var started = DateTime.UtcNow;
        _breathTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _breathTimer.Tick += (_, _) =>
        {
            var phase = (DateTime.UtcNow - started).TotalMilliseconds % PresenceLaw.GlowBreathPeriodMs
                / PresenceLaw.GlowBreathPeriodMs;
            var scale = (PresenceLaw.GlowBreathMinPct
                + (PresenceLaw.GlowBreathMaxPct - PresenceLaw.GlowBreathMinPct)
                * (0.5 - 0.5 * Math.Cos(phase * 2 * Math.PI))) / 100.0;
            for (var i = 0; i < _glows.Count; i++)
                _glows[i].Opacity = _palette.IntensityForDisplay(i == _actingDisplay) / 100.0 * scale;
        };
        _breathTimer.Start();
    }

    private void StopBreath()
    {
        _breathTimer?.Stop();
        _breathTimer = null;
    }

    // ---------------- Ghost ----------------

    private Window BuildGhostWindow()
    {
        // FR-105 (W85): the ghost is drawn by GhostVisual.Build —
        // the shared drawing code the Presence page's pointer
        // gallery uses — in the owner's chosen style, with the
        // halo in the current state's scheme color. At the default
        // scheme the style is the ring-with-initial the product
        // has always drawn. The dwell ring is drawn around it for
        // the floor holder only.
        var scale = Scheme.SizePct / 100.0;
        var size = 44 * scale;
        var style = PointerStyles.ById(Scheme.PointerStyleId);
        var haloArgb = Scheme.ColorFor(CurrentActor);
        _dwellRing = new Ellipse
        {
            Width = size + 8 * scale, Height = size + 8 * scale,
            Stroke = new SolidColorBrush(CurrentHue),
            StrokeThickness = 2,
            Opacity = 0,
            IsHitTestVisible = false
        };
        var grid = new Grid { Width = size + 8 * scale, Height = size + 8 * scale, IsHitTestVisible = false };
        grid.Children.Add(_dwellRing);
        var visual = GhostVisual.Build(style, haloArgb, PresenceLaw.GhostInitial(_machine.DisplayName), scale,
            parked: _ghostParked);
        grid.Children.Add(visual);
        var window = new Window
        {
            WindowStyle = WindowStyle.None,
            AllowsTransparency = true,
            Background = Brushes.Transparent,
            Topmost = true,
            ShowActivated = false,
            ShowInTaskbar = false,
            Width = size + 8 * scale, Height = size + 8 * scale,
            Left = SystemParameters.PrimaryScreenWidth - 52,
            Top = SystemParameters.PrimaryScreenHeight / 2,
            Content = grid,
            IsHitTestVisible = false
        };
        window.Loaded += (_, _) => MakeClickThrough(window);
        return window;
    }

    private void EnsureGhost()
    {
        if (_ghost is not null) return;
        _ghost = BuildGhostWindow();
    }

    /// <summary>The Ghost glides to (x, y) — physical pixels, the
    /// coordinates the input action will use — over
    /// PresenceLaw.GlideMs(distance), settles 90 ms, then dwells
    /// 650 ms at the acted point (the interruption window, SPEC
    /// §7.3) with the dwell ring shown for the floor holder. It
    /// never teleports, and it stays at the acted point so a
    /// screenshot after the action shows it there.</summary>
    public async Task GlideGhostToAsync(int x, int y)
    {
        // W117 / F4: driving un-dims — a parked (dimmed) Ghost is
        // rebuilt at full strength before it moves, so the dimmed
        // rendering exists only at the park position.
        if (_ghostParked)
        {
            _ghostParked = false;
            await _dispatcher.InvokeAsync(() =>
            {
                if (_ghost is null) return;
                var (l, t) = (_ghost.Left, _ghost.Top);
                CloseWindow(ref _ghost);
                _ghost = BuildGhostWindow();
                _ghost.Left = l; _ghost.Top = t;
                _ghost.Show();
            });
        }
        _glideCts?.Cancel();
        _glideCts = new CancellationTokenSource();
        var token = _glideCts.Token;
        // FR-105 (W85): the ghost window is (44 + 8) units at the
        // scheme's scale (halo + dwell margin) — centre it on the
        // acted point at whatever size the owner chose.
        var halfWindow = (int)(26 * Scheme.SizePct / 100.0);
        var targetX = x - halfWindow;
        var targetY = y - halfWindow;
        var (startX, startY) = await _dispatcher.InvokeAsync(() =>
        {
            if (_ghost is null) return (targetX, targetY);
            var hwnd = new WindowInteropHelper(_ghost).Handle;
            if (hwnd != IntPtr.Zero && NativeMethods.GetWindowRect(hwnd, out var r))
                return (r.Left, r.Top);
            return ((int)_ghost.Left, (int)_ghost.Top);
        });
        var distance = (int)Math.Sqrt(Math.Pow(targetX - startX, 2) + Math.Pow(targetY - startY, 2));
        var glideMs = PresenceLaw.GlideMs(distance);
        var steps = Math.Max(4, (int)(glideMs / 25));
        for (var i = 1; i <= steps; i++)
        {
            if (token.IsCancellationRequested) return;
            var t = i / (double)steps;
            var eased = 1 - Math.Pow(1 - t, 3);
            var px = (int)(startX + (targetX - startX) * eased);
            var py = (int)(startY + (targetY - startY) * eased);
            await _dispatcher.InvokeAsync(() =>
            {
                if (_ghost is null) return;
                var hwnd = new WindowInteropHelper(_ghost).Handle;
                if (hwnd != IntPtr.Zero)
                    NativeMethods.SetWindowPos(hwnd, NativeMethods.HWND_TOPMOST, px, py, 0, 0,
                        NativeMethods.SWP_NOSIZE | NativeMethods.SWP_NOACTIVATE | NativeMethods.SWP_SHOWWINDOW);
                else { _ghost.Left = px; _ghost.Top = py; }
            });
            try { await Task.Delay(25, token); } catch (TaskCanceledException) { return; }
        }
        try { await Task.Delay((int)PresenceLaw.SettleMs, token); } catch (TaskCanceledException) { return; }
        await DwellAsync(token);
    }

    /// <summary>The dwell: the ring holds at full opacity for the
    /// 650 ms consent dwell (floor holder only), then fades.</summary>
    private async Task DwellAsync(CancellationToken token)
    {
        if (!PresenceLaw.DwellShown(isFloorHolder: true)) return;
        await _dispatcher.InvokeAsync(() => { if (_dwellRing is not null) _dwellRing.Opacity = 0.9; });
        try { await Task.Delay((int)PresenceLaw.DwellMs, token); } catch (TaskCanceledException) { return; }
        await _dispatcher.InvokeAsync(() => { if (_dwellRing is not null) _dwellRing.Opacity = 0; });
    }

    private static void MakeClickThrough(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        var style = NativeMethods.GetWindowLong(hwnd, NativeMethods.GWL_EXSTYLE);
        NativeMethods.SetWindowLong(hwnd, NativeMethods.GWL_EXSTYLE,
            style | NativeMethods.WS_EX_TRANSPARENT | NativeMethods.WS_EX_LAYERED | NativeMethods.WS_EX_NOACTIVATE);
    }
}

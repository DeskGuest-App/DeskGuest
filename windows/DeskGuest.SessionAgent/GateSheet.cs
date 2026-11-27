using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Presence;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The gate (W8 — design of record §3): a dialog-class sheet over
/// the dimmed desktop. The amber Box is held above it by the
/// presence layer (GateUp), unchanged, STOP included.
///
/// W60-A (FR-111/FR-114) — the gate is a CARD WITHIN the one
/// presence system, not a presence surface of its own: it renders
/// NO presence header or banner (the Box the compositor holds
/// above it is the header — named agent, STOP, takeover line),
/// and the generic header sentence exists nowhere in this file
/// or the session presence path (PresenceComposition pins the
/// absence). Its lifecycle is bound to its gate
/// (GatePromptLifecycle): on the gate's timeout, on a decision,
/// and on session end the prompt dismisses itself and its exits
/// go inert — a prompt for a dead gate never presents a live
/// Approve. Exit colours come from the system's one home
/// (PresenceComposition.GateCardColors) and are bound through an
/// explicit ControlTemplate, so no platform template state
/// (notably the disabled wash) can repaint the labels toward
/// the background — FR-114's white-on-light Deny evidence.
///
/// Rules, from the record:
///  * Exits exactly: Approve / Deny / Deny and end session — three
///    exactly-equal exits (GateSheetModel.Exits, weight 600 each).
///    No session-wide allow, for any class, in any mode.
///  * NO default button. Esc does nothing. Clicking outside does
///    nothing (the sheet is modal and swallows both).
///  * Approve is achromatic; Deny directly beneath at equal weight.
///  * The artefact is shown as the agent will submit it — exact
///    recipient, subject, body, attachment — in a quoted block
///    marked "DRAFT · NOT SENT". A gate from Agent chat carries
///    "Asked from Agent chat".
///  * Gate-fidelity law (OI-12): the payload rendered here is the
///    byte array the caller will submit; the sheet never re-encodes
///    or trims it, and the fixture proves gate payload == submitted
///    payload byte-for-byte.
///  * Agent-input exclusion (OI-13): controls arm only after the
///    600 ms arming delay AND a human activation (a human input
///    event on this window, or a Narrator/UIA activation the caller
///    flags as from a non-agent source). Until armed, every exit
///    is disabled — an agent's Enter keystroke can never approve.
///  * W118 (W115 live defect): the owner's first click on the
///    card used to only latch the OI-13 activation — it landed
///    on a disabled exit, answered nothing, and the gate failed
///    closed, while the same click yielded driving through the
///    watcher. Two layers, both live-proven necessary: (1) the
///    activation completes the arming SYNCHRONOUSLY in the
///    input event's tunnel phase when the delay has already
///    elapsed (GateSheetModel.ArmsOnActivation); (2) because a
///    press on a still-disabled exit is routed to the element
///    beneath it (the exit never sees its own press, even armed
///    mid-event — W118 gate 1), the window records such a press
///    and completes it on the matching release over the same
///    exit (GateSheetModel.WindowPressAnswers), through the
///    same Decide path as the exit's own Click. One click now
///    both yields (TAKE OVER) and answers; the answer is
///    recorded against the gate that was up when it landed.
///  * Deny-and-end is wired to real teardown: the caller supplies
///    onDenyAndEnd, whose contract is GateSheetModel.DenyAndEndSteps
///    (audit approval_deny_and_end FIRST, then end the session) —
///    the same ordering Android's GateDenyAndEnd landed.
///  * W119 (S12 revision, MINIMUM-LAW-CORRECTION): the body is
///    the GatePayloadRenderer's per-class rendering of the exact
///    payload bytes — plain lines, technical lines, and for the
///    sending class the draft itself in the quoted block marked
///    «DRAFT · NOT SENT» (the marker appears ONLY there now).
///    The title names agent + action + exact target. Red
///    #DC2626 appears ONLY on «Deny and end session»
///    (GateCardColors.DenyAndEndBackground). The credential class
///    renders the refusal state: the §7.4 refusal stated, NO
///    exits — there is nothing to approve. The sheet sizes to
///    its content (SizeToContent.Height): the W115 composition
///    defect (~55% void below the buttons) is closed by
///    construction — the window IS its content's height.
/// </summary>
public sealed class GateSheet : Window
{
    public enum Outcome { Approved, Denied, DeniedAndEnded }

    private readonly long _shownAtMs = Environment.TickCount64;
    private bool _humanActivated;
    private readonly System.Windows.Threading.DispatcherTimer _armTimer;
    private readonly System.Windows.Threading.DispatcherTimer _lifecycleTimer;
    private readonly List<System.Windows.Controls.Button> _exits = new();
    private readonly Dictionary<System.Windows.Controls.Button, Outcome> _exitOutcome = new();
    // W118 (second layer): a press that lands on an exit which
    // was DISABLED at press start but armed by that very press
    // (GateSheetModel.WindowPressAnswers). WPF routes such a
    // press to the element beneath the exit, so the exit never
    // sees it; the window records the pending press here and
    // completes it on the matching release over the same exit.
    private System.Windows.Controls.Button? _pendingPressExit;
    private Outcome? _pendingPressOutcome;
    private readonly Func<Task>? _onDenyAndEnd;
    // FR-114: the prompt's lifecycle binding — the gate's own
    // expiry (from the wire request) and a probe of the session
    // the gate belongs to. Either one dying retires the prompt.
    private readonly DateTimeOffset _expiresUtc;
    private readonly Func<bool>? _sessionLive;
    private bool _decided;
    private bool _retired;

    public Outcome? Result { get; private set; }

    /// <summary>The exact payload bytes this sheet rendered — the
    /// OI-12 fixture compares this against the submitted bytes.</summary>
    public byte[] ShownPayload { get; }

    private GateSheet(GatePayloadView view, byte[] payloadBytes,
        bool fromChat, Func<Task>? onDenyAndEnd,
        DateTimeOffset expiresUtc = default, Func<bool>? sessionLive = null)
    {
        _onDenyAndEnd = onDenyAndEnd;
        _sessionLive = sessionLive;
        // A prompt can never be immortal: whatever the caller
        // supplied, the lifecycle model resolves a finite expiry.
        _expiresUtc = GatePromptLifecycle.ResolveExpiry(default, expiresUtc, DateTimeOffset.UtcNow);
        ShownPayload = payloadBytes;
        Title = view.Title;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        Topmost = true;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Width = 560;
        // W119 composition fix: the sheet sizes to its content —
        // payload fully visible, no void below the exits.
        SizeToContent = SizeToContent.Height;
        MaxHeight = 740;

        var exits = GateSheetModel.Exits();
        // W130 (S12 pixel pass, Board 04 Screen 12 measured): the
        // board's card opens with a navy header band carrying a
        // yellow warning disc. The band is now built: board-sampled
        // navy #0F283E, the disc in the sheet's own amber #F2A900,
        // the title beside the disc inside the band. The body
        // below keeps the W119 payload law unchanged.
        var panel = new StackPanel { Margin = new Thickness(24, 18, 24, 24) };
        var bandPanel = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        bandPanel.Children.Add(new Border
        {
            Width = 44, Height = 44, CornerRadius = new CornerRadius(22),
            Background = new SolidColorBrush(Color.FromRgb(0xF2, 0xA9, 0x00)),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = "!", FontSize = 24, FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x14, 0x14, 0x1C)),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
            },
        });
        bandPanel.Children.Add(new TextBlock
        {
            Text = view.Title, FontSize = 19, FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.White, TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(14, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            MaxWidth = 440,
        });
        var root = new StackPanel();
        root.Children.Add(new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x28, 0x3E)),
            CornerRadius = new CornerRadius(14, 14, 0, 0),
            Padding = new Thickness(24, 14, 24, 14),
            Child = bandPanel,
        });
        root.Children.Add(panel);
        if (fromChat)
            panel.Children.Add(new TextBlock
            {
                Text = Strings.Get("GateAskedFromChat"), FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(0xC9, 0xD6, 0xE8)),
                Margin = new Thickness(0, 4, 0, 0),
            });
        // Plain lines: what will happen, in the owner's words.
        foreach (var line in view.PlainLines)
            panel.Children.Add(new TextBlock
            {
                Text = line, FontSize = 14.5, Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 10, 0, 0),
            });
        if (view.IsRefusal)
        {
            // Credential refusal state (SPEC §7.4): the refusal is
            // stated and there are NO exits — nothing here can be
            // approved. The only control dismisses the sheet,
            // which the caller reads as NO answer (a deny).
            var close = new System.Windows.Controls.Button
            {
                Content = "Close",
                FontSize = 14.5,
                FontWeight = FontWeights.SemiBold,
                Padding = new Thickness(18, 10, 18, 10),
                Margin = new Thickness(0, 14, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                Background = new SolidColorBrush(CardColor(PresenceComposition.GateCardColors.ApproveBackground)),
                Foreground = new SolidColorBrush(CardColor(PresenceComposition.GateCardColors.ApproveForeground)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x33, 0x3F)),
                BorderThickness = new Thickness(1),
                Template = ExitTemplate(),
            };
            close.Click += (_, _) => Close();
            panel.Children.Add(close);
        }
        else
        {
        // The quoted block: for the sending class, the draft
        // itself under its «DRAFT · NOT SENT» marker; for every
        // other class, the technical lines naming the exact
        // artefacts. Below it, the payload exactly as submitted
        // (OI-12 — the same bytes, rendered whole).
        if (view.ShowDraftMarker)
            panel.Children.Add(new TextBlock
            {
                Text = Strings.Get("GateDraftNotSent"), FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xF2, 0xA9, 0x00)),
                Margin = new Thickness(0, 14, 0, 4),
            });
        var quoteLines = view.QuoteLines.Count > 0 ? view.QuoteLines : view.TechnicalLines;
        var quote = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x1B, 0x1B, 0x24)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x33, 0x3F)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10, 14, 10),
            Margin = new Thickness(0, view.ShowDraftMarker ? 0 : 14, 0, 0),
            Child = new TextBlock
            {
                Text = string.Join("\n", quoteLines), FontSize = 13.5, Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new FontFamily("Cascadia Mono"),
            },
        };
        panel.Children.Add(quote);
        if (view.QuoteLines.Count > 0)
            panel.Children.Add(new TextBlock
            {
                Text = string.Join("\n", view.TechnicalLines), FontSize = 11.5,
                Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xB0)),
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new FontFamily("Cascadia Mono"),
                Margin = new Thickness(0, 8, 0, 0),
            });
        panel.Children.Add(new TextBlock
        {
            Text = "Submitted exactly as: " + view.ExactPayloadText, FontSize = 11.5,
            Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xB0)),
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Cascadia Mono"),
            Margin = new Thickness(0, 6, 0, 0),
        });
        panel.Children.Add(new TextBlock
        {
            Text = Strings.Get("GateNoSessionAllow"), FontSize = 12.5,
            Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xB0)),
            Margin = new Thickness(0, 10, 0, 0), TextWrapping = TextWrapping.Wrap,
        });
        if (view.PreApprovalEligible)
            panel.Children.Add(new TextBlock
            {
                Text = $"To stop being asked for {view.GateClass} actions from this pairing, pre-approve the class in Settings → Approval Gates.",
                FontSize = 12.5,
                Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xB0)),
                Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap,
            });
        if (view.IsGenericFallback)
            panel.Children.Add(new TextBlock
            {
                Text = $"Gate class '{view.GateClass}' has no class-specific rendering yet — every field of the payload is listed above.",
                FontSize = 12.5,
                Foreground = new SolidColorBrush(Color.FromRgb(0xF2, 0xA9, 0x00)),
                Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap,
            });

        // Three exits, exactly equal: same size, same weight, same
        // border. Approve achromatic (dark fill, light text);
        // Deny directly beneath; Deny-and-end beneath that — the
        // ONLY red on the sheet (#DC2626, token sheet strict-use).
        // Colours come from the presence system's one home
        // (PresenceComposition.GateCardColors) and are bound
        // through ExitTemplate, so the authored foreground /
        // background pair holds in EVERY template state — the
        // default WPF template's disabled wash is what rendered
        // FR-114's Deny labels white-on-light.
        // W130: the board's exits sit side by side in one row at
        // equal width (measured: each 43.6% of card width, gap
        // 3.8%, insets 4.9%). Approve and Deny — the two exits
        // the board draws — take that row here; «Deny and end
        // session», the signed third exit the board does not
        // draw, sits full-width directly beneath it, in-language.
        // Equal weight is unchanged: same size class, same
        // font weight, no exit favoured.
        var exitsRow = new Grid { Margin = new Thickness(0, 8, 0, 0) };
        exitsRow.ColumnDefinitions.Add(new ColumnDefinition());
        exitsRow.ColumnDefinitions.Add(new ColumnDefinition());
        System.Windows.Controls.Button Exit(string label, Outcome outcome, int background, int foreground,
            Thickness margin, System.Windows.Controls.Panel host)
        {
            var b = new System.Windows.Controls.Button
            {
                Content = label,
                FontSize = 14.5,
                FontWeight = FontWeights.SemiBold,
                Padding = new Thickness(18, 12, 18, 12),
                Margin = margin,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                IsEnabled = false, // armed only per OI-13 + lifecycle (FR-114)
                Background = new SolidColorBrush(CardColor(background)),
                Foreground = new SolidColorBrush(CardColor(foreground)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x33, 0x3F)),
                BorderThickness = new Thickness(1),
                Template = ExitTemplate(),
            };
            b.Click += (_, _) => Decide(outcome);
            _exits.Add(b);
            _exitOutcome[b] = outcome;
            host.Children.Add(b);
            return b;
        }
        var approveButton = Exit(exits[0].Label, Outcome.Approved,
            PresenceComposition.GateCardColors.ApproveBackground,
            PresenceComposition.GateCardColors.ApproveForeground,
            new Thickness(0, 0, 10, 0), exitsRow);
        Grid.SetColumn(approveButton, 0);
        var denyButton = Exit(exits[1].Label, Outcome.Denied,
            PresenceComposition.GateCardColors.DenyBackground,
            PresenceComposition.GateCardColors.DenyForeground,
            new Thickness(11, 0, 0, 0), exitsRow);
        Grid.SetColumn(denyButton, 1);
        panel.Children.Add(exitsRow);
        Exit(exits[2].Label, Outcome.DeniedAndEnded,
            PresenceComposition.GateCardColors.DenyAndEndBackground,
            PresenceComposition.GateCardColors.DenyAndEndForeground,
            new Thickness(0, 8, 0, 0), panel);
        }

        Content = new Border
        {
            Background = new SolidColorBrush(CardColor(PresenceComposition.GateCardColors.CardBackground)),
            CornerRadius = new CornerRadius(14),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xF2, 0xA9, 0x00)),
            BorderThickness = new Thickness(1.5),
            Child = root,
        };

        // Human activation: any real input event on THIS window.
        // (Agent input targeting DeskGuest windows is refused at the
        // host's action layer, OI-13 — an activation that reaches
        // here is the owner's, or a Narrator/UIA activation the
        // caller vouches for via HumanActivate().)
        // W118: the activation ALSO attempts a synchronous arm
        // (Activate()). These are PREVIEW (tunnel) handlers: they
        // run before the target exit processes the press. Live
        // proof on the first W118 build showed arming alone does
        // not save the press: a press on a still-DISABLED exit is
        // routed to the element beneath it, so the exit never
        // captures it even once enabled mid-event. The window
        // therefore records such a press (RecordPress) and
        // completes it on the matching release over the same
        // exit (CompletePress) — one act, both effects: the
        // answer is recorded against this gate, and the same
        // press still yields driving through the watcher's
        // independent path in TAKE OVER mode.
        PreviewMouseDown += (_, e) =>
        {
            if (e.ChangedButton != MouseButton.Left) { Activate(); return; }
            var wasEnabled = _exits.ToDictionary(b => b, b => b.IsEnabled);
            Activate();
            RecordPress(e.GetPosition(this), wasEnabled);
        };
        PreviewMouseUp += (_, e) =>
        {
            if (e.ChangedButton == MouseButton.Left)
                CompletePress(e.GetPosition(this));
        };
        PreviewKeyDown += (_, e) =>
        {
            // Esc does nothing — it is swallowed, never a deny.
            if (e.Key == Key.Escape) { e.Handled = true; return; }
            Activate();
        };
        PreviewTouchDown += (_, e) =>
        {
            var wasEnabled = _exits.ToDictionary(b => b, b => b.IsEnabled);
            Activate();
            RecordPress(e.GetTouchPoint(this).Position, wasEnabled);
        };
        PreviewTouchUp += (_, e) => CompletePress(e.GetTouchPoint(this).Position);

        _armTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(50),
        };
        _armTimer.Tick += (_, _) => TryArmNow();
        // FR-114: the lifecycle watch — runs for the prompt's
        // whole life (unlike the arm timer, which stops at arming):
        // the gate's timeout or the session's end retires the
        // prompt within one tick, exits inert first.
        _lifecycleTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(200),
        };
        _lifecycleTimer.Tick += (_, _) =>
        {
            var state = GatePromptLifecycle.Evaluate(DateTimeOffset.UtcNow, _expiresUtc,
                _sessionLive?.Invoke() ?? true, _decided);
            if (GatePromptLifecycle.ShouldDismiss(state)) Retire();
        };
        Loaded += (_, _) => { _armTimer.Start(); _lifecycleTimer.Start(); };
        Closed += (_, _) => { _armTimer.Stop(); _lifecycleTimer.Stop(); };
    }

    /// <summary>W118: a human activation on this window — latch
    /// the OI-13 activation fact, then attempt the synchronous
    /// arm. Called from the PREVIEW (tunnel) input handlers:
    /// when GateSheetModel.ArmsOnActivation holds (the 600 ms
    /// delay already elapsed), the exits are enabled inside this
    /// same event. Inside the delay, nothing arms here — the arm
    /// timer completes arming at 600 ms and only a later press
    /// answers (OI-13 unchanged). Arming alone does not make the
    /// activating press the exit's own press — that is the
    /// pending-press layer's job (RecordPress/CompletePress).</summary>
    private void Activate()
    {
        _humanActivated = true;
        if (GateSheetModel.ArmsOnActivation(_shownAtMs, Environment.TickCount64))
            TryArmNow();
    }

    /// <summary>Arm the exits if the gate is live and OI-13
    /// arming has completed; retire the prompt instead if its
    /// gate is dead. The ONE arming path — the 50 ms arm timer is
    /// now only the backstop for an activation that arrived
    /// inside the 600 ms delay (it completes the arm at the
    /// delay's end, for the NEXT press). FR-114: arming never
    /// resurrects a dead gate.</summary>
    private void TryArmNow()
    {
        var state = GatePromptLifecycle.Evaluate(DateTimeOffset.UtcNow, _expiresUtc,
            _sessionLive?.Invoke() ?? true, _decided);
        if (GatePromptLifecycle.ShouldDismiss(state)) { Retire(); return; }
        if (GatePromptLifecycle.ExitsLive(state,
                GateSheetModel.ControlsArmed(_shownAtMs, Environment.TickCount64, _humanActivated)))
        {
            foreach (var b in _exits) b.IsEnabled = true;
            _armTimer.Stop();
        }
    }

    /// <summary>The ONE decision path — an exit's own Click and
    /// the window's completed pending press (W118) both land
    /// here, so every answer passes the same lifecycle + arming
    /// evaluation. FR-114: a decision attempt on a dead gate's
    /// prompt decides nothing — retire the prompt instead.</summary>
    private async void Decide(Outcome outcome)
    {
        var state = GatePromptLifecycle.Evaluate(DateTimeOffset.UtcNow, _expiresUtc,
            _sessionLive?.Invoke() ?? true, _decided);
        if (GatePromptLifecycle.ShouldDismiss(state)) { Retire(); return; }
        if (!GatePromptLifecycle.ExitsLive(state,
                GateSheetModel.ControlsArmed(_shownAtMs, Environment.TickCount64, _humanActivated))) return;
        _decided = true;
        Result = outcome;
        if (outcome == Outcome.DeniedAndEnded && _onDenyAndEnd is not null)
            await _onDenyAndEnd();
        Close();
    }

    /// <summary>W118: record a press that landed on an exit this
    /// very press just armed (GateSheetModel.WindowPressAnswers
    /// decides whether the record may complete). Any other press
    /// — off an exit, or on an exit that was already enabled
    /// (WPF's own capture path owns those) — clears the record.</summary>
    private void RecordPress(System.Windows.Point point, IReadOnlyDictionary<System.Windows.Controls.Button, bool> wasEnabled)
    {
        _pendingPressExit = null;
        _pendingPressOutcome = null;
        var hit = ExitAt(point);
        if (hit is null) return;
        // The press-side terms of WindowPressAnswers: the exit
        // was disabled when this press started and is enabled
        // now — within one event dispatch, only this press's
        // activation can have armed it. The release term is
        // evaluated in CompletePress through the full predicate.
        if (!wasEnabled[hit] && hit.IsEnabled)
        {
            _pendingPressExit = hit;
            _pendingPressOutcome = _exitOutcome[hit];
        }
    }

    /// <summary>W118: a release completes a recorded press only
    /// over the SAME exit it started on — press-and-drag-off
    /// answers nothing, exactly like a real button.</summary>
    private void CompletePress(System.Windows.Point point)
    {
        var exit = _pendingPressExit;
        var outcome = _pendingPressOutcome;
        _pendingPressExit = null;
        _pendingPressOutcome = null;
        if (exit is null || outcome is null) return;
        if (!GateSheetModel.WindowPressAnswers(
                exitEnabledAtPressStart: false, armedByThisPress: true,
                pressOnExit: true, releaseOnSameExit: ExitAt(point) == exit)) return;
        Decide(outcome.Value);
    }

    /// <summary>The exit whose rendered rectangle contains a
    /// window-relative point, or null. Geometry is computed from
    /// the exits themselves — never from the press's routed
    /// target, which is exactly what a disabled exit distorts.</summary>
    private System.Windows.Controls.Button? ExitAt(System.Windows.Point point)
    {
        foreach (var b in _exits)
        {
            if (b.RenderSize.Width <= 0 || b.RenderSize.Height <= 0) continue;
            var origin = b.TranslatePoint(new System.Windows.Point(0, 0), this);
            if (new Rect(origin, b.RenderSize).Contains(point)) return b;
        }
        return null;
    }

    /// <summary>FR-114 retire: the gate behind this prompt is dead
    /// (timed out, or its session ended). The exits go inert FIRST,
    /// then the prompt dismisses itself with NO result — the caller
    /// reads a null outcome as a deny, and the Core's broker has
    /// already resolved the gate the same way (gate_no_answer /
    /// session end), so no answer is ever sent for a dead gate.</summary>
    private void Retire()
    {
        if (_retired || _decided) return;
        _retired = true;
        foreach (var b in _exits) b.IsEnabled = false;
        _armTimer.Stop();
        _lifecycleTimer.Stop();
        Close();
    }

    private static Color CardColor(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    /// <summary>The exits' one template: a Border bound to the
    /// button's authored Background/BorderBrush and a content
    /// presenter centred in it. No state triggers repaint the
    /// foreground or background — enabled and not-yet-armed render
    /// identically, so a label can never wash toward its fill
    /// (FR-114). Arming is carried by responsiveness (OI-13),
    /// never by label contrast.</summary>
    private static ControlTemplate ExitTemplate()
    {
        // Template bindings in code form: a Binding whose source
        // is the templated parent — what a XAML TemplateBinding
        // compiles to.
        static System.Windows.Data.Binding Templated(DependencyProperty source) => new()
        {
            RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent),
            Path = new PropertyPath(source),
        };
        var border = new FrameworkElementFactory(typeof(Border));
        border.SetBinding(Border.BackgroundProperty, Templated(System.Windows.Controls.Button.BackgroundProperty));
        border.SetBinding(Border.BorderBrushProperty, Templated(System.Windows.Controls.Button.BorderBrushProperty));
        border.SetBinding(Border.BorderThicknessProperty, Templated(System.Windows.Controls.Button.BorderThicknessProperty));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        border.SetBinding(Border.PaddingProperty, Templated(System.Windows.Controls.Button.PaddingProperty));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetBinding(ContentPresenter.ContentProperty, Templated(ContentControl.ContentProperty));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.AppendChild(presenter);
        return new ControlTemplate(typeof(System.Windows.Controls.Button)) { VisualTree = border };
    }

    /// <summary>A Narrator/UIA activation from a non-agent source
    /// counts as the human activation (OI-13) — screen-reader
    /// owners are never locked out. W118: it takes the same
    /// synchronous arm attempt as a physical activation, on the
    /// UI thread (an off-thread caller is marshalled).</summary>
    public void HumanActivate()
    {
        if (Dispatcher.CheckAccess()) { Activate(); return; }
        Dispatcher.BeginInvoke(new Action(Activate));
    }

    /// <summary>Show the gate modally and return the owner's exit,
    /// or null if the sheet was closed without an exit (which the
    /// caller must treat as NO approval — the artefact is not
    /// submitted).</summary>
    public static Outcome? Present(
        string title, byte[] payloadBytes, bool fromChat,
        Func<Task>? onDenyAndEnd, PresenceLayer? presence = null,
        DateTimeOffset expiresUtc = default, Func<bool>? sessionLive = null) =>
        Present(GatePayloadRenderer.Render(title, "", "", payloadBytes),
            payloadBytes, fromChat, onDenyAndEnd, presence, expiresUtc, sessionLive);

    /// <summary>W119: present the gate from its rendered payload
    /// view — the caller builds the view from the wire request
    /// (agent name, gate class, tool, exact payload bytes) so the
    /// title and body carry the class's payload law.</summary>
    public static Outcome? Present(
        GatePayloadView view, byte[] payloadBytes, bool fromChat,
        Func<Task>? onDenyAndEnd, PresenceLayer? presence = null,
        DateTimeOffset expiresUtc = default, Func<bool>? sessionLive = null)
    {
        presence?.SetGateUp(true);
        try
        {
            var sheet = new GateSheet(view,
                payloadBytes, fromChat, onDenyAndEnd, expiresUtc, sessionLive);
            sheet.ShowDialog();
            return sheet.Result;
        }
        finally
        {
            presence?.SetGateUp(false);
        }
    }
}

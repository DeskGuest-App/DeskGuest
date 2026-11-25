using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Acp.Shared.Design;
using Acp.Shared.Ipc;
using Acp.Shared.Security;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using RadioButton = System.Windows.Controls.RadioButton;
using Color = System.Windows.Media.Color;
using Cursors = System.Windows.Input.Cursors;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace Acp.SessionAgent;

/// <summary>
/// W79 / S08 — the AI access-control surface (agent detail page).
/// ONE grant state (the pairing's real scope set, from the Core's
/// host-state snapshot), two views: the stepped slider and the
/// Fine-tune panel beneath it, both reading/writing through
/// <see cref="AccessControl"/> and staging into ONE pending set.
/// Nothing is written until Apply: staging a change renders the
/// «This changes: …» preview from AccessControl.Diff, and Apply
/// sends exactly the previewed set over the laptop-UI IPC channel
/// (PairingAccess, a consent kind). The Core validates again at
/// the store and audits every change.
///
/// Reached from the Home Trusted-Helpers row (the pairing/agent
/// card) and from the Settings index («My AI helpers' access»).
/// </summary>
public partial class MainWindow
{
    private string? _accessPairingId;
    private HashSet<string>? _accessPending;
    private bool _accessElevationConfirmed;
    private bool _accessFineTuneOpen;
    private int _accessDragStop = -1;
    private StackPanel? _accessBody;
    private TextBlock? _accessStatus;
    private string _accessSignature = "";

    // W97 / S09(b): the connection-path card's staged state — the
    // same staging discipline as the access slider (nothing is
    // written until Apply; the Core validates + audits).
    private string? _connMode;
    private HashSet<string>? _connRungs;
    private string? _connPin;
    private TextBlock? _connStatus;
    private bool _connRendering;

    private static readonly SolidColorBrush AccessNavy = new(Color.FromRgb(0x0F, 0x25, 0x37));
    private static readonly SolidColorBrush AccessTeal = new(Color.FromRgb(0x43, 0x8E, 0x8E));
    private static readonly SolidColorBrush AccessBlue = new(Color.FromRgb(0x1A, 0x88, 0xD4));
    private static readonly SolidColorBrush AccessTrackOff = new(Color.FromRgb(0xD5, 0xE1, 0xEA));
    private static readonly SolidColorBrush AccessGold = new(Color.FromRgb(0xE5, 0xA9, 0x3B));

    private UIElement BuildAgentDetailPage()
    {
        var root = new Grid { Margin = new Thickness(-26, 31, -26, -4) };
        _accessBody = new StackPanel { Margin = new Thickness(36, 0, 36, 0) };
        root.Children.Add(_accessBody);
        _accessSignature = "";
        RenderAgentAccess();
        return root;
    }

    /// <summary>Open the access surface for one pairing (Home card
    /// entry point).</summary>
    private void OpenAgentAccess(string pairingId)
    {
        _accessPairingId = pairingId;
        _accessPending = null;
        _accessElevationConfirmed = false;
        _connMode = null;
        _connRungs = null;
        _connPin = null;
        _accessSignature = "";
        ShowPage("agentdetail");
        RenderAgentAccess();
    }

    private (string Id, string Name, string[] Scopes, bool Revoked)? AccessPairing()
    {
        var pairings = _host?.Pairings;
        if (pairings is null || pairings.Count == 0) return null;
        var chosen = pairings.FirstOrDefault(p => p.Id == _accessPairingId);
        if (chosen.Id is null) chosen = pairings.FirstOrDefault(p => !p.Revoked);
        if (chosen.Id is null) chosen = pairings[0];
        _accessPairingId = chosen.Id;
        return chosen;
    }

    private void StageAccessGrants(HashSet<string> proposed, IReadOnlySet<string> current)
    {
        _accessPending = proposed.SetEquals(current) ? null : proposed;
        _accessElevationConfirmed = false;
        _accessSignature = "";
        RenderAgentAccess();
    }

    private void RenderAgentAccess()
    {
        if (_accessBody is null) return;
        var pairing = AccessPairing();
        var signature = pairing is null
            ? "none"
            : $"{pairing.Value.Id}:{string.Join(",", pairing.Value.Scopes)}:{pairing.Value.Revoked}" +
              $"|pend:{(_accessPending is null ? "-" : string.Join(",", _accessPending.OrderBy(s => s)))}" +
              $"|ft:{_accessFineTuneOpen}|drag:{_accessDragStop}|elev:{_accessElevationConfirmed}" +
              $"|conn:{ConnSignature(pairing.Value.Id)}" +
              $"|terms:{TermsSignature(pairing.Value.Id)}" +
              $"|sess:{_host?.SessionActive}:{_host?.SessionAgent}";
        if (signature == _accessSignature) return;
        _accessSignature = signature;
        _accessBody.Children.Clear();

        if (pairing is null)
        {
            _accessBody.Children.Add(new TextBlock
            {
                Text = "AI Agent Access", FontSize = 58, FontWeight = FontWeights.ExtraBold,
                Foreground = AccessNavy, Margin = new Thickness(4, 16, 0, 26),
            });
            _accessBody.Children.Add(Muted(Strings.Get("AccessNoPairings"), 14));
            return;
        }

        var (id, pname, scopeArr, revoked) = pairing.Value;
        var current = new HashSet<string>(scopeArr);
        var effective = _accessPending ?? current;
        var classify = AccessControl.Classify(effective);
        var isCustom = classify < 0;
        // The slider's displayed stop: the staged/exact stop, else
        // (Custom) the largest stop whose grants the state holds.
        var displayStop = classify >= 0 ? classify : LargestHeldStop(effective);
        if (_accessDragStop >= 0) displayStop = _accessDragStop;

        // ---- title + identity strip (S09 in-language) ----
        _accessBody.Children.Add(new TextBlock
        {
            Text = Strings.Format("AccessPageTitleFormat", pname),
            FontSize = 58, FontWeight = FontWeights.ExtraBold, Foreground = AccessNavy,
            Margin = new Thickness(4, 16, 0, 6),
        });
        var identity = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 0, 0, 20) };
        identity.Children.Add(BuildIdentityRing(pname, revoked));
        var identityText = new StackPanel { Margin = new Thickness(16, 4, 0, 0) };
        var nameRow = new StackPanel { Orientation = Orientation.Horizontal };
        nameRow.Children.Add(new TextBlock { Text = pname, FontSize = 21, FontWeight = FontWeights.SemiBold, Foreground = AccessNavy });
        if (isCustom && _accessPending is null)
            nameRow.Children.Add(CustomChip());
        identityText.Children.Add(nameRow);
        identityText.Children.Add(Muted(revoked
            ? Strings.Get("AccessRevokedLine")
            : isCustom
                ? "Custom access — the switches below show exactly what this helper may do."
                : $"{AccessControl.Stops[classify].Name} — {ScopeSummary(scopeArr)}", 13.5));
        identity.Children.Add(identityText);
        _accessBody.Children.Add(identity);

        // ---- W120 / S09(d): «Message {agent}» — the door into
        // this pairing's S13 thread. W135: the thread is a
        // full-window page (ruling U-7); the click navigates to
        // the chat page with this pairing's thread open and
        // requests the thread from the Core. A revoked pairing
        // has no thread (unpairing ended it) — no button.
        if (!revoked)
        {
            var capturedMsgId = id;
            var msgBtn = new Button
            {
                Content = $"Message {pname}",
                Style = (Style)FindResource("GhostButton"),
                FontSize = 13.5, Padding = new Thickness(14, 6, 14, 6),
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(4, 0, 0, 16),
            };
            msgBtn.Click += async (_, _) =>
            {
                _chatOpenPairingId = capturedMsgId;
                _chatMessages.Clear();
                _chatOrders.Clear();
                ShowPage("chat");
                RefreshDynamics();
                if (_chatThreadSender is not null) await _chatThreadSender(capturedMsgId);
            };
            _accessBody.Children.Add(msgBtn);
        }

        // ---- pairing selector (when more than one helper) ----
        var all = _host?.Pairings ?? new List<(string Id, string Name, string[] Scopes, bool Revoked)>();
        if (all.Count > 1)
        {
            var selector = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 0, 0, 14) };
            foreach (var p in all)
            {
                var captured = p.Id;
                var b = new Button
                {
                    Content = p.Name, Style = (Style)FindResource("GhostButton"),
                    FontSize = 13, Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0),
                    FontWeight = p.Id == id ? FontWeights.Bold : FontWeights.Normal,
                };
                b.Click += (_, _) => OpenAgentAccess(captured);
                selector.Children.Add(b);
            }
            _accessBody.Children.Add(selector);
        }

        if (revoked)
        {
            _accessStatus = Muted("", 13);
            _accessBody.Children.Add(_accessStatus);
            return;
        }

        // ---- the access card: slider + preview + fine-tune ----
        var card = new StackPanel();
        var headingRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        headingRow.Children.Add(new TextBlock
        {
            Text = "Access level", FontSize = 20, FontWeight = FontWeights.Bold, Foreground = AccessNavy,
        });
        if (isCustom) headingRow.Children.Add(CustomChip());
        card.Children.Add(headingRow);
        card.Children.Add(Muted("Move the slider, or fine-tune below. Nothing changes until you apply it.", 13));

        card.Children.Add(BuildAccessSlider(id, current, displayStop));
        var consequence = new TextBlock
        {
            Text = _accessDragStop >= 0
                ? AccessControl.Stops[_accessDragStop].Consequence
                : classify >= 0
                    ? AccessControl.Stops[classify].Consequence
                    : "Custom access — the switches below are the whole story.",
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 6),
        };
        card.Children.Add(consequence);

        // ---- preview (only when a change is staged) ----
        if (_accessPending is not null)
            card.Children.Add(BuildAccessPreview(id, current, _accessPending));

        // ---- fine-tune ----
        var ftHeader = new Button
        {
            Content = (_accessFineTuneOpen ? "▾ " : "▸ ") + Strings.Get("AccessFineTune"),
            Style = (Style)FindResource("GhostButton"), FontSize = 14.5, FontWeight = FontWeights.SemiBold,
            HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 10, 0, 2),
        };
        ftHeader.Click += (_, _) => { _accessFineTuneOpen = !_accessFineTuneOpen; _accessSignature = ""; RenderAgentAccess(); };
        card.Children.Add(ftHeader);
        if (_accessFineTuneOpen)
            card.Children.Add(BuildFineTune(current, effective));

        _accessStatus = Muted(_accessPending is null ? Strings.Get("AccessNoChanges") : "", 12.5);
        _accessStatus.Margin = new Thickness(0, 10, 0, 0);
        card.Children.Add(_accessStatus);
        var cardBorder = HomeCard(card);
        cardBorder.Margin = new Thickness(0, 0, 0, 14);
        _accessBody.Children.Add(cardBorder);
        _accessBody.Children.Add(Muted(Strings.Get("AccessAuditNote"), 12.5));

        // ---- W97 / S09(b): the connection-path card, beside the
        // access card — how this helper may connect, and the path
        // it is actually on (live snapshot facts, never stored).
        _accessBody.Children.Add(BuildConnectionCard(id, pname));

        // ---- FR-134 / item (16): the Terms line — when a helper
        // is session-locked over a Terms acknowledgment, the owner
        // sees why right here without lifting a finger.
        if (BuildTermsLine(id) is { } termsLine)
            _accessBody.Children.Add(termsLine);
    }

    // ================= FR-134 Terms acknowledgment =================

    /// <summary>The pairing's Terms facts from the live snapshot
    /// (no state at all when an older Core reports none).</summary>
    private (string? AckVersion, DateTimeOffset? AckUtc, string? CurrentVersion, bool Pending) TermsFacts(string pairingId)
    {
        if (_host is not null && _host.PairingTerms.TryGetValue(pairingId, out var f)) return f;
        return (null, null, null, false);
    }

    private string TermsSignature(string pairingId)
    {
        var f = TermsFacts(pairingId);
        return $"{f.AckVersion}:{f.AckUtc}:{f.CurrentVersion}:{f.Pending}";
    }

    /// <summary>The Terms line for the agent card. Null when the
    /// Core serves no Terms state (an older Core) — the page then
    /// shows nothing, exactly as before FR-134. Pending is stated
    /// plainly with the reason and the (lack of) owner action;
    /// current is one quiet line naming the version signed for.</summary>
    private UIElement? BuildTermsLine(string pairingId)
    {
        var f = TermsFacts(pairingId);
        if (f.CurrentVersion is null) return null;
        if (f.Pending)
        {
            return new TextBlock
            {
                Text = f.AckVersion is null
                    ? $"Terms acknowledgment pending — this helper hasn't acknowledged the Terms (v{f.CurrentVersion}), so it can't start a session yet. " +
                      "It receives the full text when it connects and acknowledges it from its own side; there is nothing for you to do."
                    : $"Terms update pending — this helper acknowledged Terms v{f.AckVersion}, but the current Terms are v{f.CurrentVersion}, so it can't start a session until it re-acknowledges. " +
                      "It receives the full new text when it connects; there is nothing for you to do.",
                FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 0, 0, 14),
            };
        }
        var line = Muted($"Terms v{f.AckVersion} acknowledged{(f.AckUtc is { } at ? $" on {at.ToLocalTime():MMM d, yyyy}" : "")} — the acknowledgment is in this device's Activity Record.", 12.5);
        line.Margin = new Thickness(4, 0, 0, 14);
        return line;
    }

    // ================= W103 / S09(a): ring-with-initial identity ==

    /// <summary>The pairing's identity ring color, from its state
    /// family — the app's real state hues (PresenceLaw), never a
    /// stored or drawn color: a live session with this agent is the
    /// AI-acting family (violet, the same ring-initial the presence
    /// stage and the Ghost carry); a pairing that is not connected
    /// is the waiting family (amber); a revoked pairing is stopped
    /// (STOP red).</summary>
    private static int IdentityRingArgb(bool revoked, bool liveNow) =>
        revoked ? PresenceLaw.HueStop
        : liveNow ? PresenceLaw.HueAi
        : PresenceLaw.HueIdle;

    private static SolidColorBrush ArgbBrush(int argb) => new(Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb));

    /// <summary>The signed S09(a) identity: the pairing name's
    /// initial centered in a ring in the pairing's state color —
    /// the floor's form, in the pill face's own tokens (cream disc,
    /// navy initial). The initial derives from the REAL pairing
    /// name at render (PresenceLaw.GhostInitial, the same
    /// derivation the pill face and the Ghost use); nothing is
    /// stored art. Same 56×56 footprint as the gold tile it
    /// replaces.</summary>
    private UIElement BuildIdentityRing(string pname, bool revoked)
    {
        var liveNow = _host is { SessionActive: true } && _host.SessionAgent == pname;
        var face = new Grid { Width = 56, Height = 56 };
        face.Children.Add(new System.Windows.Shapes.Ellipse
        {
            Width = 56, Height = 56,
            Fill = ArgbBrush(PresenceLaw.PillFaceCream),
            IsHitTestVisible = false,
        });
        face.Children.Add(new TextBlock
        {
            Text = PresenceLaw.GhostInitial(pname),
            FontSize = 26, FontWeight = FontWeights.Bold, Foreground = AccessNavy,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false,
        });
        face.Children.Add(new System.Windows.Shapes.Ellipse
        {
            Width = 56, Height = 56,
            Fill = Brushes.Transparent,
            Stroke = ArgbBrush(IdentityRingArgb(revoked, liveNow)),
            StrokeThickness = 3,
            IsHitTestVisible = false,
        });
        return face;
    }

    // ================= W97 connection-path card =================

    /// <summary>The pairing's connection facts from the live
    /// snapshot (AUTO / no rung when an older Core reports none).</summary>
    private (string Mode, string[] Rungs, string? Pin, string? CurrentRung, DateTimeOffset? AtUtc) ConnFacts(string pairingId)
    {
        if (_host is not null && _host.PairingConnections.TryGetValue(pairingId, out var f)) return f;
        return ("Auto", Array.Empty<string>(), null, null, null);
    }

    private string ConnSignature(string pairingId)
    {
        var f = ConnFacts(pairingId);
        return $"{f.Mode}:{string.Join(",", f.Rungs)}:{f.Pin}:{f.CurrentRung}:{f.AtUtc}" +
               $"|staged:{_connMode ?? "-"}:{(_connRungs is null ? "-" : string.Join(",", _connRungs.OrderBy(s => s)))}:{_connPin ?? "-"}";
    }

    private static string ModeToWire(string snapshotMode) => snapshotMode switch
    {
        "AutoRestricted" => "restricted",
        "Manual" => "manual",
        _ => "auto",
    };

    private static ConnectionPathSetting StagedSetting(string wireMode, HashSet<string>? rungs, string? pin) =>
        ConnectionPathPolicy.Parse(wireMode, rungs, pin) ?? ConnectionPathSetting.DefaultAuto;

    private void StageConnection(string wireMode, HashSet<string>? rungs, string? pin)
    {
        _connMode = wireMode;
        _connRungs = rungs;
        _connPin = pin;
        _accessSignature = "";
        RenderAgentAccess();
    }

    private UIElement BuildConnectionCard(string pairingId, string pname)
    {
        var facts = ConnFacts(pairingId);
        // W107 (C5): a present-but-corrupt stored setting restores
        // fail-closed on the Core; the snapshot mode names it
        // (CorruptRefused). The card must show THAT — needs
        // attention, connections refused — and never present AUTO
        // as the current setting (ModeToWire's default would).
        var corrupt = facts.Mode == "CorruptRefused";
        var currentWire = ModeToWire(facts.Mode);
        var currentSetting = corrupt
            ? ConnectionPathSetting.CorruptRefusedSetting
            : StagedSetting(currentWire,
                facts.Rungs.Length > 0 ? new HashSet<string>(facts.Rungs) : null, facts.Pin);
        var staged = _connMode is not null;
        var wireMode = _connMode ?? currentWire;
        var effRungs = _connRungs ?? (facts.Rungs.Length > 0
            ? new HashSet<string>(facts.Rungs)
            : new HashSet<string>(ConnectionPathPolicy.Rungs.Select(r => r.Id)));
        var effPin = _connPin ?? facts.Pin ?? facts.CurrentRung ?? "mesh";
        var stagedSetting = StagedSetting(wireMode, effRungs, effPin);
        var differs = staged &&
            ConnectionPathPolicy.Describe(stagedSetting) != ConnectionPathPolicy.Describe(currentSetting);

        var card = new StackPanel();
        card.Children.Add(new TextBlock
        {
            Text = "How this helper connects", FontSize = 20, FontWeight = FontWeights.Bold, Foreground = AccessNavy,
            Margin = new Thickness(0, 0, 0, 4),
        });

        // The current-rung line — live state only.
        var liveNow = _host is { SessionActive: true } && _host.SessionAgent == pname && facts.CurrentRung is not null;
        card.Children.Add(new TextBlock
        {
            Text = liveNow
                ? $"Connected now over {ConnectionPathPolicy.PlainName(facts.CurrentRung)}."
                : facts.CurrentRung is not null
                    ? $"Not connected right now. Last connected over {ConnectionPathPolicy.PlainName(facts.CurrentRung)}" +
                      (facts.AtUtc is { } at ? $" at {at.ToLocalTime():h:mm tt}." : ".")
                    : "Hasn't connected since this PC's program started — no path to show yet.",
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
        });
        card.Children.Add(Muted($"Path setting now: {ConnectionPathPolicy.Describe(currentSetting)}", 13));
        if (corrupt)
        {
            // W107: the owner's repair path, stated on the card:
            // pick how this helper connects below and Apply — the
            // Core refuses every connection until then.
            card.Children.Add(new TextBlock
            {
                Text = "This helper can't connect on any path until you pick how it connects below and choose Apply connection change.",
                FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
            });
        }

        _connRendering = true;
        // ---- the three modes ----
        var modes = new[]
        {
            ("auto", "Auto — use any working path", "Best working path, switches on its own if a path drops. No re-pairing."),
            ("restricted", "Auto, only the paths I pick", "Works only within the paths you tick below — never anything else."),
            ("manual", "Manual — one pinned path", "Uses exactly the one path you pin below, or doesn't connect."),
        };
        foreach (var (wire, title, blurb) in modes)
        {
            var captured = wire;
            var rb = new RadioButton
            {
                GroupName = "connmode97", IsChecked = wireMode == wire,
                Margin = new Thickness(0, 8, 0, 0),
                Content = new StackPanel
                {
                    Children =
                    {
                        new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.SemiBold },
                        Muted(blurb, 12),
                    },
                },
            };
            rb.Checked += (_, _) =>
            {
                if (_connRendering) return;
                StageConnection(captured,
                    captured == "restricted" ? new HashSet<string>(effRungs) : _connRungs,
                    captured == "manual" ? effPin : _connPin);
            };
            card.Children.Add(rb);
        }

        // ---- restricted subset ----
        if (wireMode == "restricted")
        {
            card.Children.Add(Muted("Paths this helper may use:", 12.5));
            foreach (var rung in ConnectionPathPolicy.Rungs)
            {
                var captured = rung.Id;
                var cb = new CheckBox
                {
                    Content = rung.PlainName, FontSize = 13.5, Margin = new Thickness(18, 3, 0, 0),
                    IsChecked = effRungs.Contains(captured),
                };
                cb.Checked += (_, _) => { if (_connRendering) return; var next = new HashSet<string>(effRungs) { captured }; StageConnection("restricted", next, _connPin); };
                cb.Unchecked += (_, _) => { if (_connRendering) return; var next = new HashSet<string>(effRungs); next.Remove(captured); StageConnection("restricted", next, _connPin); };
                card.Children.Add(cb);
            }
        }

        // ---- manual pin ----
        if (wireMode == "manual")
        {
            card.Children.Add(Muted("The one path this helper must use:", 12.5));
            foreach (var rung in ConnectionPathPolicy.Rungs)
            {
                var captured = rung.Id;
                var rb = new RadioButton
                {
                    GroupName = "connpin97", Content = rung.PlainName, FontSize = 13.5,
                    Margin = new Thickness(18, 3, 0, 0), IsChecked = effPin == captured,
                };
                rb.Checked += (_, _) => { if (_connRendering) return; StageConnection("manual", _connRungs, captured); };
                card.Children.Add(rb);
            }
        }
        _connRendering = false;

        // ---- staged preview + apply ----
        if (differs)
        {
            var panel = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0xF2, 0xF6, 0xF9)),
                CornerRadius = new CornerRadius(12), Padding = new Thickness(16),
                Margin = new Thickness(0, 12, 0, 2),
            };
            var stack = new StackPanel();
            stack.Children.Add(new TextBlock { Text = "This changes:", FontSize = 14.5, FontWeight = FontWeights.SemiBold, Foreground = AccessNavy });
            stack.Children.Add(new TextBlock
            {
                Text = $"{ConnectionPathPolicy.Describe(currentSetting)} → {ConnectionPathPolicy.Describe(stagedSetting)}",
                FontSize = 13.5, Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap,
            });
            stack.Children.Add(Muted("A path you turn off stops working for this helper right away. It never quietly switches to a path you didn't allow — if no allowed path works, it reports that instead.", 12));
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
            var apply = PairPrimaryButton("Apply connection change");
            apply.MinWidth = 210;
            apply.Padding = new Thickness(22, 8, 22, 8);
            apply.Click += async (_, _) =>
            {
                await SendHostActionAsync(IpcKinds.PairingConnection,
                    new
                    {
                        id = pairingId,
                        mode = wireMode,
                        allowedRungs = wireMode == "restricted" ? effRungs.OrderBy(s => s).ToArray() : Array.Empty<string>(),
                        pinnedRung = wireMode == "manual" ? effPin : null,
                    }, _connStatus);
                _connMode = null; _connRungs = null; _connPin = null;
                _accessSignature = "";
                RenderAgentAccess();
            };
            var cancel = new Button
            {
                Content = Strings.Get("AccessCancel"), Style = (Style)FindResource("GhostButton"),
                FontSize = 13.5, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(10, 0, 0, 0),
            };
            cancel.Click += (_, _) => { _connMode = null; _connRungs = null; _connPin = null; _accessSignature = ""; RenderAgentAccess(); };
            buttons.Children.Add(apply);
            buttons.Children.Add(cancel);
            stack.Children.Add(buttons);
            panel.Child = stack;
            card.Children.Add(panel);
        }

        _connStatus = Muted("", 12.5);
        _connStatus.Margin = new Thickness(0, 10, 0, 0);
        card.Children.Add(_connStatus);
        var border = HomeCard(card);
        border.Margin = new Thickness(0, 0, 0, 14);
        return border;
    }

    private Border CustomChip() => new()
    {
        CornerRadius = new CornerRadius(10), BorderBrush = AccessGold, BorderThickness = new Thickness(1.5),
        Padding = new Thickness(9, 2, 9, 2), Margin = new Thickness(12, 2, 0, 0),
        VerticalAlignment = VerticalAlignment.Center,
        Child = new TextBlock { Text = Strings.Get("AccessCustomChip"), FontSize = 12.5, FontWeight = FontWeights.SemiBold, Foreground = AccessNavy },
    };

    private static int LargestHeldStop(IReadOnlySet<string> grants)
    {
        var best = 0;
        for (var i = 0; i < AccessControl.Stops.Count; i++)
            if (AccessControl.Stops[i].Grants.IsSubsetOf(grants)) best = i;
        return best;
    }

    /// <summary>The STEPPED slider: five named stops with detents.
    /// Clicking a disc or its label stages that stop; dragging
    /// moves a live preview (stop name + consequence update while
    /// dragging) and stages on release; − / + steppers and the
    /// arrow keys are the text/stepper alternative. Staging never
    /// writes — the preview panel owns Apply.</summary>
    private UIElement BuildAccessSlider(string pairingId, HashSet<string> current, int displayStop)
    {
        var outer = new StackPanel { Margin = new Thickness(0, 14, 0, 0) };
        var grid = new Grid { Height = 44 };
        for (var i = 0; i < AccessControl.Stops.Count; i++)
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        // track segments (between disc centers): colored up to the displayed stop
        for (var i = 0; i < AccessControl.Stops.Count - 1; i++)
        {
            var seg = new Border
            {
                Height = 10, CornerRadius = new CornerRadius(5), VerticalAlignment = VerticalAlignment.Center,
                Background = i < displayStop ? AccessTeal : AccessTrackOff,
                Margin = new Thickness(i == 0 ? 60 : 0, 0, i == AccessControl.Stops.Count - 2 ? 60 : 0, 0),
            };
            Grid.SetColumn(seg, i); Grid.SetColumnSpan(seg, 2);
            grid.Children.Add(seg);
        }
        // discs
        for (var i = 0; i < AccessControl.Stops.Count; i++)
        {
            var stop = i;
            var selected = i == displayStop;
            var disc = new Border
            {
                Width = 34, Height = 34, CornerRadius = new CornerRadius(17),
                HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                Background = selected ? AccessBlue : Brushes.White,
                BorderBrush = selected ? AccessBlue : AccessTrackOff, BorderThickness = new Thickness(2),
                Cursor = Cursors.Hand,
                Child = new TextBlock
                {
                    Text = selected ? "✓" : (i + 1).ToString(),
                    FontSize = 14, FontWeight = FontWeights.Bold,
                    Foreground = selected ? Brushes.White : AccessNavy,
                    HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                },
            };
            Grid.SetColumn(disc, i);
            disc.MouseLeftButtonUp += (_, e) =>
            {
                e.Handled = true;
                StageAccessGrants(new HashSet<string>(AccessControl.Stops[stop].Grants), current);
            };
            grid.Children.Add(disc);
        }
        // drag: press anywhere on the track, move = live stop preview, release = stage
        grid.MouseLeftButtonDown += (_, e) =>
        {
            grid.CaptureMouse();
            _accessDragStop = StopFromX(grid, e);
            _accessSignature = ""; RenderAgentAccess();
        };
        grid.MouseMove += (_, e) =>
        {
            if (_accessDragStop < 0) return;
            var s = StopFromX(grid, e);
            if (s != _accessDragStop) { _accessDragStop = s; _accessSignature = ""; RenderAgentAccess(); }
        };
        grid.MouseLeftButtonUp += (_, _) =>
        {
            if (_accessDragStop < 0) return;
            var s = _accessDragStop;
            _accessDragStop = -1;
            StageAccessGrants(new HashSet<string>(AccessControl.Stops[s].Grants), current);
        };
        outer.Children.Add(grid);

        // labels (clickable text alternative) + steppers
        var labels = new Grid();
        for (var i = 0; i < AccessControl.Stops.Count; i++)
            labels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < AccessControl.Stops.Count; i++)
        {
            var stop = i;
            var label = new TextBlock
            {
                Text = AccessControl.Stops[i].Name, FontSize = 15, TextAlignment = TextAlignment.Center,
                FontWeight = i == displayStop ? FontWeights.SemiBold : FontWeights.Normal,
                Foreground = i == displayStop ? AccessNavy : new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
                Cursor = Cursors.Hand, Margin = new Thickness(2, 4, 2, 0),
            };
            label.MouseLeftButtonUp += (_, _) =>
                StageAccessGrants(new HashSet<string>(AccessControl.Stops[stop].Grants), current);
            Grid.SetColumn(label, i);
            labels.Children.Add(label);
        }
        outer.Children.Add(labels);

        var steppers = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        var minus = new Button { Content = "− Step down", Style = (Style)FindResource("GhostButton"), FontSize = 12.5, Padding = new Thickness(10, 3, 10, 3), Margin = new Thickness(0, 0, 8, 0) };
        minus.Click += (_, _) => { var s = Math.Max(0, displayStop - 1); StageAccessGrants(new HashSet<string>(AccessControl.Stops[s].Grants), current); };
        var plus = new Button { Content = "+ Step up", Style = (Style)FindResource("GhostButton"), FontSize = 12.5, Padding = new Thickness(10, 3, 10, 3) };
        plus.Click += (_, _) => { var s = Math.Min(AccessControl.Stops.Count - 1, displayStop + 1); StageAccessGrants(new HashSet<string>(AccessControl.Stops[s].Grants), current); };
        steppers.Children.Add(minus);
        steppers.Children.Add(plus);
        outer.Children.Add(steppers);
        return outer;
    }

    private static int StopFromX(FrameworkElement el, System.Windows.Input.MouseEventArgs e)
    {
        var x = e.GetPosition(el).X;
        var w = Math.Max(1, el.ActualWidth);
        var idx = (int)(x / (w / AccessControl.Stops.Count));
        return Math.Clamp(idx, 0, AccessControl.Stops.Count - 1);
    }

    /// <summary>The change preview: exactly the grants that will
    /// change (AccessControl.Diff), the elevation switch when any
    /// elevation-class grant (admin, unlock, background_kit_admin
    /// — W107, via AccessControl.AddsElevation) would be ADDED,
    /// and Apply/Cancel. Apply sends the previewed set — nothing
    /// else can be sent.</summary>
    private UIElement BuildAccessPreview(string pairingId, HashSet<string> current, HashSet<string> pending)
    {
        var panel = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF2, 0xF6, 0xF9)),
            CornerRadius = new CornerRadius(12), Padding = new Thickness(16),
            Margin = new Thickness(0, 12, 0, 2),
        };
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock { Text = Strings.Get("AccessThisChanges"), FontSize = 14.5, FontWeight = FontWeights.SemiBold, Foreground = AccessNavy });
        foreach (var change in AccessControl.Diff(current, pending))
        {
            stack.Children.Add(new TextBlock
            {
                Text = Strings.Format(change.Added ? "AccessGrantAddedFormat" : "AccessGrantRemovedFormat", change.Capability.Label),
                FontSize = 13.5, Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap,
            });
        }
        CheckBox? elevationBox = null;
        if (AccessControl.AddsElevation(current, pending))
        {
            elevationBox = new CheckBox
            {
                Content = Strings.Get("AccessElevationConfirm"), FontSize = 13.5,
                Margin = new Thickness(0, 10, 0, 0), IsChecked = _accessElevationConfirmed,
            };
            elevationBox.Checked += (_, _) => _accessElevationConfirmed = true;
            elevationBox.Unchecked += (_, _) => _accessElevationConfirmed = false;
            stack.Children.Add(elevationBox);
            stack.Children.Add(Muted(AccessControl.UacLine, 12));
        }
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 0) };
        var apply = PairPrimaryButton(Strings.Get("AccessApply"));
        apply.MinWidth = 210;
        apply.Padding = new Thickness(22, 8, 22, 8);
        apply.Click += async (_, _) =>
        {
            var scopes = pending.OrderBy(s => s).ToArray();
            var confirmed = elevationBox?.IsChecked == true;
            await SendHostActionAsync(IpcKinds.PairingAccess,
                new { id = pairingId, scopes, elevationConfirmed = confirmed }, _accessStatus);
            _accessPending = null;
            _accessElevationConfirmed = false;
            _accessSignature = "";
            RenderAgentAccess();
        };
        var cancel = new Button
        {
            Content = Strings.Get("AccessCancel"), Style = (Style)FindResource("GhostButton"),
            FontSize = 13.5, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(10, 0, 0, 0),
        };
        cancel.Click += (_, _) => { _accessPending = null; _accessElevationConfirmed = false; _accessSignature = ""; RenderAgentAccess(); };
        buttons.Children.Add(apply);
        buttons.Children.Add(cancel);
        stack.Children.Add(buttons);
        panel.Child = stack;
        return panel;
    }

    /// <summary>Fine-tune: one switch row per real capability.
    /// Toggling stages into the same pending set the slider uses
    /// (one state, two views); the elevation row is last,
    /// separated, and carries the standing UAC line.</summary>
    private UIElement BuildFineTune(HashSet<string> current, HashSet<string> effective)
    {
        var stack = new StackPanel { Margin = new Thickness(0, 4, 0, 0) };
        var caps = AccessControl.Capabilities;
        for (var ci = 0; ci < caps.Count; ci++)
        {
            var cap = caps[ci];
            // W107: the elevation class is a GROUP of rows (admin,
            // unlock, background_kit_admin): one separator before
            // the group and the standing UAC line once after it —
            // not a separator + line per row.
            if (cap.IsElevation && (ci == 0 || !caps[ci - 1].IsElevation))
            {
                stack.Children.Add(new Border { Height = 1, Background = AccessTrackOff, Margin = new Thickness(0, 10, 0, 4) });
            }
            var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var texts = new StackPanel();
            texts.Children.Add(new TextBlock { Text = cap.Label, FontSize = 14, TextWrapping = TextWrapping.Wrap });
            texts.Children.Add(Muted(cap.Scope, 11.5));
            Grid.SetColumn(texts, 0);
            row.Children.Add(texts);
            var on = effective.Contains(cap.Scope);
            var captured = cap.Scope;
            var toggle = new Border
            {
                Width = 58, Height = 32, CornerRadius = new CornerRadius(16), Cursor = Cursors.Hand,
                Background = on ? AccessTeal : new SolidColorBrush(Color.FromRgb(0xC3, 0xCF, 0xD9)),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new Border
                {
                    Width = 26, Height = 26, CornerRadius = new CornerRadius(13), Background = Brushes.White,
                    HorizontalAlignment = on ? HorizontalAlignment.Right : HorizontalAlignment.Left, Margin = new Thickness(3),
                },
            };
            toggle.MouseLeftButtonUp += (_, _) =>
            {
                var next = new HashSet<string>(effective);
                if (!next.Remove(captured)) next.Add(captured);
                StageAccessGrants(next, current);
            };
            Grid.SetColumn(toggle, 1);
            row.Children.Add(toggle);
            stack.Children.Add(row);
            if (cap.IsElevation && (ci == caps.Count - 1 || !caps[ci + 1].IsElevation))
                stack.Children.Add(Muted(AccessControl.UacLine, 12));
        }
        return stack;
    }
}

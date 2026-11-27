using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using RadioButton = System.Windows.Controls.RadioButton;
using Brush = System.Windows.Media.Brush;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// MP-4 / Screen 62 — the Connection Paths page: the full-page
/// form of the S09(b) connection-path card that lives on the
/// Agent Detail page (MainWindow.Access.cs). Per paired helper it
/// shows the transport rungs, the path in use now, and the
/// connection-path policy (Auto / Auto — Chosen Paths Only /
/// Pinned to One Path).
///
/// Design of record: design-trio/v1-face-packs/
/// 03-connection-paths (design.html + MANIFEST). The pack's
/// centred-window composition (its G-1) is hosted here as a full
/// page in the app shell, in the shell's own language: the
/// design's current-path pill and its three numbered option
/// cards carry over; the window chrome, backdrop and footer do
/// not (they are the single's framing, not product copy).
///
/// DATA LAW — real connection state only:
///  * The current path is the pairing's live/last rung from the
///    Core snapshot (ConnFacts, the same facts the S09(b) card
///    reads). No rung is ever painted as current, in use, or
///    working from anything else.
///  * Per-rung state lines come only from snapshot exposures:
///    the transport section (LAN / hub listener state, mesh
///    setup stage) and the running-lane list. A rung the
///    snapshot does not expose (NetBird, Direct IPv6, Direct
///    public IP, Public relay, Tor) is stated as not reported —
///    never as available, never as down.
///  * The rung NAMES are ConnectionPathPolicy.Rungs — the
///    policy vocabulary the Core enforces — shown in the
///    programme's chain order (LAN → hub → mesh → IPv6/own
///    path → Tor, loopback last as the local-only lane). Being
///    named in the policy list is not a claim that the path
///    works right now; each row's state line says what is
///    actually known, separately.
///  * Manual WebRTC sits below the chain in the programme's
///    rung model but has no rung id in ConnectionPathPolicy
///    and no snapshot exposure — it is named as a gap line,
///    never painted as a path.
///
/// Policy changes stage exactly like S09(b) (nothing is written
/// until Apply) and Apply sends the identical
/// IpcKinds.PairingConnection payload over the same
/// authenticated laptop-UI channel; the Core validates and
/// audits. This page's staging fields are its own, so staging
/// here and staging on the Agent Detail card never entangle;
/// the status line reuses _connStatus, the field the Core's
/// action-result routing already targets for
/// pairing_connection results.
/// </summary>
public partial class MainWindow
{
    private StackPanel? _connectionsBody;
    private string _connectionsSignature = "";
    private string? _mpPairingId;
    private string? _mpMode;
    private HashSet<string>? _mpRungs;
    private string? _mpPin;
    private bool _mpRendering;

    /// <summary>The programme's chain order for display:
    /// LAN → hub → mesh accounts → IPv6 / own path → relay →
    /// Tor, with this-PC-only loopback last. Ids are
    /// ConnectionPathPolicy.Rungs ids; any rung the policy adds
    /// later and this order does not name is appended in policy
    /// order rather than dropped.</summary>
    private static readonly string[] ConnectionsChainOrder =
        { "lan", "hub", "mesh", "netbird", "ipv6", "ownpath", "relay", "tor", "loopback" };

    private static IReadOnlyList<ConnectionPathPolicy.RungInfo> ConnectionsRungsInChainOrder()
    {
        var ordered = new List<ConnectionPathPolicy.RungInfo>();
        foreach (var id in ConnectionsChainOrder)
        {
            var rung = ConnectionPathPolicy.Rungs.FirstOrDefault(r => r.Id == id);
            if (rung is not null) ordered.Add(rung);
        }
        foreach (var rung in ConnectionPathPolicy.Rungs)
            if (!ordered.Contains(rung)) ordered.Add(rung);
        return ordered;
    }

    private UIElement BuildConnectionsPage()
    {
        var stack = new StackPanel();
        // #152: the title is carried locally at the painting's
        // scale (30px ExtraBold, the #149 pattern — the shared
        // PageTitle helper is the other pages' scale).
        stack.Children.Add(new TextBlock { Text = "Connection Paths", FontSize = 30, FontWeight = FontWeights.ExtraBold, Foreground = (Brush)FindResource("DgTextBrush"), Margin = new Thickness(0, 2, 0, 4) });
        stack.Children.Add(new TextBlock { Text = "For each paired helper: the paths it may use, the path it is on now, and how its path is chosen. A path is only ever shown from this PC's live state — nothing here invents one.", FontSize = 14.5, Foreground = (Brush)FindResource("DgMutedBrush"), Margin = new Thickness(0, 0, 0, 16), TextWrapping = TextWrapping.Wrap });
        _connectionsBody = new StackPanel();
        stack.Children.Add(_connectionsBody);
        _connectionsSignature = "";
        RenderConnections();
        return stack;
    }

    /// <summary>The selected pairing for this page (the Agent
    /// Detail page keeps its own selection; the two never fight —
    /// each page renders the pairing it last opened).</summary>
    private (string Id, string Name, string[] Scopes, bool Revoked)? ConnectionsPairing()
    {
        var pairings = _host?.Pairings;
        if (pairings is null || pairings.Count == 0) return null;
        var chosen = pairings.FirstOrDefault(p => p.Id == _mpPairingId);
        if (chosen.Id is null) chosen = pairings.FirstOrDefault(p => !p.Revoked);
        if (chosen.Id is null) chosen = pairings[0];
        _mpPairingId = chosen.Id;
        return chosen;
    }

    private void StageConnectionPage(string wireMode, HashSet<string>? rungs, string? pin)
    {
        _mpMode = wireMode;
        _mpRungs = rungs;
        _mpPin = pin;
        _connectionsSignature = "";
        RenderConnections();
    }

    private void RenderConnections()
    {
        if (_connectionsBody is null) return;
        var pairing = ConnectionsPairing();
        var transport = _host?.Transport;
        var signature = pairing is null
            ? $"none|host:{_host is not null}"
            : $"{pairing.Value.Id}:{pairing.Value.Revoked}" +
              $"|conn:{ConnSignature(pairing.Value.Id)}" +
              $"|mp:{_mpMode ?? "-"}:{(_mpRungs is null ? "-" : string.Join(",", _mpRungs.OrderBy(s => s)))}:{_mpPin ?? "-"}" +
              $"|lanes:{(_host is null ? "-" : string.Join(",", _host.Lanes))}" +
              $"|transport:{transport?.LanListening}:{transport?.LanPort}:{transport?.HubListening}:{transport?.HubPort}:{transport?.MeshSetupStage}" +
              $"|sess:{_host?.SessionActive}:{_host?.SessionAgent}" +
              $"|all:{(_host is null ? "-" : string.Join(",", _host.Pairings.Select(p => p.Id + p.Name)))}";
        if (signature == _connectionsSignature) return;
        _connectionsSignature = signature;
        _connectionsBody.Children.Clear();

        if (_host is null)
        {
            _connectionsBody.Children.Add(Card(new TextBlock
            {
                Text = "Waiting for the Core's snapshot — no path can be shown until it arrives.",
                FontSize = 15, TextWrapping = TextWrapping.Wrap,
            }));
            return;
        }
        if (pairing is null)
        {
            _connectionsBody.Children.Add(Card(new TextBlock
            {
                Text = "No paired helpers yet. Pair a helper on the AI Agents page and its connection paths will appear here.",
                FontSize = 15, TextWrapping = TextWrapping.Wrap,
            }));
            return;
        }

        var (id, pname, _, revoked) = pairing.Value;

        // ---- pairing selector (when more than one helper) ----
        var all = _host.Pairings;
        if (all.Count > 1)
        {
            // #152: a WrapPanel, not a single row — with a long
            // roster the single row ran off the window's edge and
            // the later pairings could not be clicked at all.
            var selector = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
            foreach (var p in all)
            {
                var captured = p.Id;
                var b = new Button
                {
                    Content = p.Name, Style = (Style)FindResource("GhostButton"),
                    FontSize = 14, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 8),
                    FontWeight = p.Id == id ? FontWeights.Bold : FontWeights.Normal,
                };
                b.Click += (_, _) =>
                {
                    _mpPairingId = captured;
                    _mpMode = null; _mpRungs = null; _mpPin = null;
                    _connectionsSignature = "";
                    RenderConnections();
                };
                selector.Children.Add(b);
            }
            _connectionsBody.Children.Add(selector);
        }

        var facts = ConnFacts(id);
        var liveNow = _host is { SessionActive: true } && _host.SessionAgent == pname && facts.CurrentRung is not null;
        var corrupt = facts.Mode == "CorruptRefused";

        // ---- the current-path pill (the design's signature
        // element; teal only when a path is genuinely in use
        // now — a stale or absent path never wears it) ----
        _connectionsBody.Children.Add(BuildCurrentPathPill(facts, liveNow, corrupt));

        // ---- the rung list, with real states only ----
        _connectionsBody.Children.Add(BuildConnectionsRungsCard(id, pname, facts, liveNow));

        // ---- the policy: the design's three option cards,
        // S09(b)'s behaviour ----
        if (revoked)
        {
            var note = new StackPanel();
            note.Children.Add(new TextBlock
            {
                Text = "This pairing has been revoked — it can't connect on any path.",
                FontSize = 15, TextWrapping = TextWrapping.Wrap,
            });
            _connectionsBody.Children.Add(Card(note));
        }
        else
        {
            _connectionsBody.Children.Add(BuildConnectionsPolicyCard(id, facts, corrupt));
        }

        // ---- back to the helper's own page (the design's
        // footer "Back", in shell language) ----
        var back = new Button
        {
            Content = $"‹ Back to {pname}",
            Style = (Style)FindResource("GhostButton"), FontSize = 14.5,
            Padding = new Thickness(16, 8, 16, 8),
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(0, 2, 0, 14),
        };
        back.Click += (_, _) => OpenAgentAccess(id);
        _connectionsBody.Children.Add(back);
    }

    /// <summary>The design's pill: "Current Path: …" — the rung
    /// name is the snapshot's real rung (its policy plain name),
    /// never the single's painted "Direct Local Wi-Fi (Fastest,
    /// No Cloud)": the build has no fastest/no-cloud measurement
    /// to claim. Not-live and never-connected states are stated
    /// on the pill itself, in the neutral token surface.</summary>
    private UIElement BuildCurrentPathPill(
        (string Mode, string[] Rungs, string? Pin, string? CurrentRung, DateTimeOffset? AtUtc) facts,
        bool liveNow, bool corrupt)
    {
        string text;
        Brush background;
        Brush foreground;
        if (corrupt)
        {
            text = "No path — connections are refused until the path setting below is set again";
            background = (Brush)FindResource("DgNavyBrush");
            foreground = Brushes.White;
        }
        else if (liveNow)
        {
            text = $"Current Path: {ConnectionPathPolicy.PlainName(facts.CurrentRung)}";
            background = (Brush)FindResource("DgTealBrush");
            foreground = Brushes.White;
        }
        else if (facts.CurrentRung is not null)
        {
            text = $"Not connected right now — last path: {ConnectionPathPolicy.PlainName(facts.CurrentRung)}" +
                   (facts.AtUtc is { } at ? $" at {at.ToLocalTime():h:mm tt}" : "");
            background = (Brush)FindResource("DgSubtleBrush");
            foreground = (Brush)FindResource("DgTextBrush");
        }
        else
        {
            text = "No path yet — this helper hasn't connected since this PC's program started";
            background = (Brush)FindResource("DgSubtleBrush");
            foreground = (Brush)FindResource("DgTextBrush");
        }
        // #152: the pill is the painting's signature element —
        // full-width, its text centred at hero scale (the
        // painting: 54px tall, 22px/700 centred; adapted here to
        // the shell's content column).
        return new Border
        {
            Background = background,
            // Stadium ends: radius = half the pill's height.
            // (999 rendered as a lens at full width — the corner
            // arcs met at points; seen on the first #152 deploy's
            // live capture and corrected.)
            CornerRadius = new CornerRadius(26),
            Padding = new Thickness(22, 13, 22, 13),
            Margin = new Thickness(0, 2, 0, 16),
            Child = new TextBlock
            {
                Text = text, FontSize = 19, FontWeight = FontWeights.Bold,
                Foreground = foreground, TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
            },
        };
    }

    /// <summary>What the snapshot actually exposes about one
    /// rung on THIS PC — the row's state line. Anything not
    /// exposed is said so, in those words.</summary>
    private string ConnectionsRungState(string rungId, string? currentRung, bool liveNow, DateTimeOffset? atUtc)
    {
        if (currentRung is not null && rungId == ConnectionPathSetting.NormalizeRung(currentRung))
        {
            return liveNow
                ? "In use now"
                : "Last used" + (atUtc is { } at ? $" at {at.ToLocalTime():h:mm tt}" : "");
        }
        var t = _host?.Transport;
        var lanes = _host?.Lanes ?? Array.Empty<string>();
        bool LaneRunning(string name) => lanes.Any(l => string.Equals(l, name, StringComparison.OrdinalIgnoreCase));
        return rungId switch
        {
            "lan" => t is not null
                ? t.LanListening
                    ? $"Listening on this PC (port {t.LanPort}) · {t.LanAccepted} session(s) accepted · {t.LanRefused} handshake(s) refused"
                    : "Listener off on this PC — no socket is open"
                : LaneRunning("Lan") ? "Lane running on this PC" : "Not reported by the Core yet",
            "hub" => t is not null
                ? t.HubListening
                    ? $"Listening on this PC (port {t.HubPort}) · {t.HubAccepted} session(s) accepted · {t.HubRefused} handshake(s) refused"
                    : "Listener off on this PC — no socket is open"
                : "Not reported by the Core yet",
            "mesh" => LaneRunning("Tailscale")
                ? "Lane running on this PC"
                : t is not null && t.MeshSetupStage.Length > 0
                    ? $"Mesh setup: {t.MeshSetupStage}{(t.MeshSetupDetail.Length > 0 ? $" — {t.MeshSetupDetail}" : "")}"
                    : "Not reported by the Core yet",
            "loopback" => LaneRunning("loopback")
                ? "Lane running on this PC"
                : "Lane not running on this PC",
            _ => "Not reported by the Core — this page can't say whether this path works right now",
        };
    }

    /// <summary>The rung list card: every policy rung in chain
    /// order, its real state on this PC, and whether the
    /// selected helper's CURRENT setting (not any staged change)
    /// allows it — two different facts, labelled as such.</summary>
    private UIElement BuildConnectionsRungsCard(string pairingId, string pname,
        (string Mode, string[] Rungs, string? Pin, string? CurrentRung, DateTimeOffset? AtUtc) facts,
        bool liveNow)
    {
        var currentSetting = facts.Mode == "CorruptRefused"
            ? ConnectionPathSetting.CorruptRefusedSetting
            : StagedSetting(ModeToWire(facts.Mode),
                facts.Rungs.Length > 0 ? new HashSet<string>(facts.Rungs) : null, facts.Pin);

        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = $"Paths for {pname}", FontSize = 23, FontWeight = FontWeights.Bold,
            Foreground = (Brush)FindResource("DgTextBrush"), Margin = new Thickness(0, 0, 0, 4),
        });
        body.Children.Add(Muted($"Path setting now: {ConnectionPathPolicy.Describe(currentSetting)}", 14));

        foreach (var rung in ConnectionsRungsInChainOrder())
        {
            var row = new Grid { Margin = new Thickness(0, 9, 0, 9) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var texts = new StackPanel();
            texts.Children.Add(new TextBlock { Text = rung.PlainName, FontSize = 16.5, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            texts.Children.Add(Muted(ConnectionsRungState(rung.Id, facts.CurrentRung, liveNow, facts.AtUtc), 13.5));
            Grid.SetColumn(texts, 0);
            row.Children.Add(texts);
            var allowed = ConnectionPathPolicy.Allows(currentSetting, rung.Id);
            var chip = ConnectionsChip(
                facts.Mode == "CorruptRefused" ? "Blocked — setting needs attention"
                : allowed ? "Allowed by the setting" : "Not allowed by the setting",
                allowed && facts.Mode != "CorruptRefused" ? GreenBg : GrayBg,
                allowed && facts.Mode != "CorruptRefused" ? GreenFg : GrayFg);
            chip.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(chip, 1);
            row.Children.Add(chip);
            body.Children.Add(row);
        }

        // Named gap (programme rung model): manual WebRTC sits
        // below the chain, but it has no policy rung id and the
        // snapshot exposes no WebRTC path state — it is named
        // here rather than painted as a path.
        body.Children.Add(Muted("Manual WebRTC is not shown as a path: it has no entry in this helper's path setting, and the Core's snapshot doesn't report a WebRTC path state for it.", 13));
        var card = HomeCard(body);
        card.Margin = new Thickness(0, 0, 0, 14);
        return card;
    }

    /// <summary>#152: the rung rows' allowed chip at the
    /// reworked scale (the shared Chip helper is the other
    /// pages' 12px form). Same colours, same words — a setting
    /// fact, never a state colour.</summary>
    private static Border ConnectionsChip(string text, Color bg, Color fg)
    {
        return new Border
        {
            Background = new SolidColorBrush(bg),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(13, 5, 13, 5),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = text, FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(fg) }
        };
    }

    private void StageFromConnections(string wireMode, HashSet<string>? rungs, string? pin) =>
        StageConnectionPage(wireMode, rungs, pin);

    /// <summary>The policy card: the design's three numbered
    /// option cards with S09(b)'s exact control behaviour —
    /// radios stage, the chosen-paths checkboxes and the
    /// pinned-path radios (the pickers the design's option 3
    /// refers to "below") show only for the mode that needs
    /// them, and a staged change renders the same preview +
    /// Apply the Agent Detail card renders.</summary>
    private UIElement BuildConnectionsPolicyCard(string pairingId,
        (string Mode, string[] Rungs, string? Pin, string? CurrentRung, DateTimeOffset? AtUtc) facts,
        bool corrupt)
    {
        var currentWire = ModeToWire(facts.Mode);
        var currentSetting = corrupt
            ? ConnectionPathSetting.CorruptRefusedSetting
            : StagedSetting(currentWire,
                facts.Rungs.Length > 0 ? new HashSet<string>(facts.Rungs) : null, facts.Pin);
        var staged = _mpMode is not null;
        var wireMode = _mpMode ?? currentWire;
        var effRungs = _mpRungs ?? (facts.Rungs.Length > 0
            ? new HashSet<string>(facts.Rungs)
            : new HashSet<string>(ConnectionPathPolicy.Rungs.Select(r => r.Id)));
        var effPin = _mpPin ?? facts.Pin ?? facts.CurrentRung ?? "mesh";
        var stagedSetting = StagedSetting(wireMode, effRungs, effPin);
        var differs = staged &&
            ConnectionPathPolicy.Describe(stagedSetting) != ConnectionPathPolicy.Describe(currentSetting);

        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = "How this helper's path is chosen", FontSize = 23, FontWeight = FontWeights.Bold,
            Foreground = (Brush)FindResource("DgTextBrush"), Margin = new Thickness(0, 0, 0, 4),
        });
        if (corrupt)
        {
            body.Children.Add(new TextBlock
            {
                Text = "This helper can't connect on any path until you pick how it connects below and choose Apply connection change.",
                FontSize = 15, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4),
            });
        }

        _mpRendering = true;
        var modes = new[]
        {
            ("auto", "1. Automatic (Recommended)", "Enables your paired AI to dynamically choose the fastest, most reliable route available."),
            ("restricted", "2. Automatic — Chosen Paths Only", ""),
            ("manual", "3. Pinned to One Path", "Forces your paired AI to use one dedicated path only. (Requires manual selection below.)"),
        };
        foreach (var (wire, title, blurb) in modes)
        {
            var captured = wire;
            var inner = new StackPanel();
            var rb = new RadioButton
            {
                GroupName = "connmode62", IsChecked = wireMode == wire,
                Content = new TextBlock { Text = title, FontSize = 19.5, FontWeight = FontWeights.Bold, TextWrapping = TextWrapping.Wrap },
            };
            rb.Checked += (_, _) =>
            {
                if (_mpRendering) return;
                StageFromConnections(captured,
                    captured == "restricted" ? new HashSet<string>(effRungs) : _mpRungs,
                    captured == "manual" ? effPin : _mpPin);
            };
            inner.Children.Add(rb);
            if (blurb.Length > 0)
                inner.Children.Add(new TextBlock
                {
                    Text = blurb, FontSize = 15.5, TextWrapping = TextWrapping.Wrap,
                    Foreground = (Brush)FindResource("DgMutedBrush"), Margin = new Thickness(22, 4, 0, 0),
                });

            // ---- chosen paths only: the subset checkboxes ----
            if (wire == "restricted" && wireMode == "restricted")
            {
                inner.Children.Add(Muted("Paths this helper may use:", 14));
                foreach (var rung in ConnectionsRungsInChainOrder())
                {
                    var capturedRung = rung.Id;
                    var cb = new CheckBox
                    {
                        Content = rung.PlainName, FontSize = 15, Margin = new Thickness(22, 4, 0, 0),
                        IsChecked = effRungs.Contains(capturedRung),
                    };
                    cb.Checked += (_, _) => { if (_mpRendering) return; var next = new HashSet<string>(effRungs) { capturedRung }; StageFromConnections("restricted", next, _mpPin); };
                    cb.Unchecked += (_, _) => { if (_mpRendering) return; var next = new HashSet<string>(effRungs); next.Remove(capturedRung); StageFromConnections("restricted", next, _mpPin); };
                    inner.Children.Add(cb);
                }
            }

            // ---- pinned to one path: the manual picker (the
            // design's "manual selection below" — G-2; the same
            // picker S09(b) renders, from the same rung list) ----
            if (wire == "manual" && wireMode == "manual")
            {
                inner.Children.Add(Muted("The one path this helper must use:", 14));
                foreach (var rung in ConnectionsRungsInChainOrder())
                {
                    var capturedRung = rung.Id;
                    var pin = new RadioButton
                    {
                        GroupName = "connpin62", Content = rung.PlainName, FontSize = 15,
                        Margin = new Thickness(22, 4, 0, 0), IsChecked = effPin == capturedRung,
                    };
                    pin.Checked += (_, _) => { if (_mpRendering) return; StageFromConnections("manual", _mpRungs, capturedRung); };
                    inner.Children.Add(pin);
                }
            }

            var optionCard = new Border
            {
                Background = (Brush)FindResource("DgSubtleBrush"),
                BorderBrush = (Brush)FindResource(wireMode == wire ? "DgBlueBrush" : "DgBorderBrush"),
                BorderThickness = new Thickness(wireMode == wire ? 2 : 1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(20),
                Margin = new Thickness(0, 10, 0, 0),
                Child = inner,
            };
            body.Children.Add(optionCard);
        }
        _mpRendering = false;

        // ---- staged preview + apply (S09(b)'s exact shape) ----
        if (differs)
        {
            var panel = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0xF2, 0xF6, 0xF9)),
                CornerRadius = new CornerRadius(12), Padding = new Thickness(16),
                Margin = new Thickness(0, 12, 0, 2),
            };
            var stack = new StackPanel();
            stack.Children.Add(new TextBlock { Text = "This changes:", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("DgTextBrush") });
            stack.Children.Add(new TextBlock
            {
                Text = $"{ConnectionPathPolicy.Describe(currentSetting)} → {ConnectionPathPolicy.Describe(stagedSetting)}",
                FontSize = 15, Margin = new Thickness(0, 3, 0, 0), TextWrapping = TextWrapping.Wrap,
            });
            stack.Children.Add(Muted("A path you turn off stops working for this helper right away. It never quietly switches to a path you didn't allow — if no allowed path works, it reports that instead.", 13));
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
                _mpMode = null; _mpRungs = null; _mpPin = null;
                _connectionsSignature = "";
                RenderConnections();
            };
            var cancel = new Button
            {
                Content = Strings.Get("AccessCancel"), Style = (Style)FindResource("GhostButton"),
                FontSize = 14.5, Padding = new Thickness(16, 8, 16, 8), Margin = new Thickness(10, 0, 0, 0),
            };
            cancel.Click += (_, _) => { _mpMode = null; _mpRungs = null; _mpPin = null; _connectionsSignature = ""; RenderConnections(); };
            buttons.Children.Add(apply);
            buttons.Children.Add(cancel);
            stack.Children.Add(buttons);
            panel.Child = stack;
            body.Children.Add(panel);
        }

        _connStatus = Muted("", 13.5);
        _connStatus.Margin = new Thickness(0, 10, 0, 0);
        body.Children.Add(_connStatus);
        var card = HomeCard(body);
        card.Margin = new Thickness(0, 0, 0, 14);
        return card;
    }
}

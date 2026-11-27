using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using Button = System.Windows.Controls.Button;
using ComboBox = System.Windows.Controls.ComboBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The Effective Policy page (Screen 60, census N12 half; Face
/// Tranche 1 item 2b). Design of record:
/// design-trio/v1-face-packs/02-effective-policy/ (design.html +
/// MANIFEST.md; render.png is the cold-judged transcription).
///
/// The page answers, per rule, "why is it like this": what the
/// rule does, whether it is in force, and where it came from —
/// company policy / group / device / pairing / DeskGuest default,
/// with the consent-floor items marked as NOT a setting (they
/// have no source layer and no toggle; ConsentFloorGuard keeps
/// them out of the policy engine entirely). It is the explanatory
/// view over the machinery the Guardrails page operates (the
/// policy toggles + approval gates) and the Enterprise page
/// summarises (the signed bundle's posture) — it operates
/// nothing itself.
///
/// DATA LAW: every row is built from the policy state the app
/// already reads on the host snapshot (_host: pairings, gates,
/// enterprise bundle state, Block G feature states, effective
/// file roots, endpoint/roster facts). No fixture values: the
/// design single's sample user/device and its "Company Group:
/// Engineering" attributions are NOT carried — attributions here
/// are only the ones the snapshot actually supports.
///
/// GAP-POLICY-PROVENANCE (named on the page, in the gap card):
/// the Core's signed management-policy engine
/// (DeskGuest.Shared.ManagementPolicy.ManagementPolicyEngine) computes
/// per-setting effective values with per-setting provenance
/// (org → group → device), but the host snapshot this window
/// receives does not carry that list, so group-layer settings
/// cannot appear as their own rows yet and company-layer rows
/// are the bundle-level facts the snapshot does carry (bundle
/// state + the eight Block G feature postures). When the Core
/// adds per-setting provenance to the snapshot, those rows land
/// here with no other change.
///
/// G-2 (binding, from the pack MANIFEST): the single's rule 3
/// promised a "green border" for presence, contradicting the
/// settled presence colour law (colour carries no state meaning;
/// red alone is reserved for STOP/danger). The build rewords it:
/// the presence floor row below describes presence being shown,
/// with no colour promised. See BUILD-DIFF.md in the pack.
///
/// States: the corpus paints no empty/loading/error state for
/// this page (pack gap G-4) — the no-snapshot, no-pairings and
/// no-match states below are composed in this page's own
/// language, following the Ledger/Block G pages' precedent.
/// </summary>
public partial class MainWindow
{
    private TextBlock? _effPolicyContext;
    private StackPanel? _effPolicyTarget;
    private Run? _effPolicyCrumbCurrent;
    private TextBox? _effPolicySearchTop;
    private TextBox? _effPolicySearchRules;
    private ComboBox? _effPolicyLayerFilter;
    private StackPanel? _effPolicyRules;
    private TextBlock? _effPolicyCount;
    private bool _effPolicyFiltersReady;
    private bool _effPolicySyncingSearch;

    /// <summary>One effective rule: what it does (+ a plain detail
    /// line), its status words, where it came from, and the layer
    /// key the filter matches. Layer is never invented: it is the
    /// layer the snapshot fact behind the row actually came from.</summary>
    private sealed record EffPolicyRule(
        string Rule, string? Detail, string Status, EffPolicyPill Pill,
        string Source, string Layer);

    private enum EffPolicyPill { On, Off, Info, Danger }

    private UIElement BuildPolicyPage()
    {
        var stack = new StackPanel();

        // Title row — the design places the Greeter at the title's
        // right; same asset and discipline as the Ledger page.
        var titleGrid = new Grid();
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        // #150: the header carries the painting's scale locally (the
        // shared PageTitle helper is the other pages' scale) — the
        // #149 Groups precedent.
        titleGrid.Children.Add(new TextBlock
        {
            Text = "Effective Policy", FontSize = 30, FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 2, 0, 2),
        });
        try
        {
            var mascot = new System.Windows.Media.Imaging.BitmapImage(
                new System.Uri("pack://application:,,,/deskguest-wave.png"));
            var img = new System.Windows.Controls.Image
            {
                Source = mascot, Height = 72,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center,
            };
            Grid.SetColumn(img, 1);
            titleGrid.Children.Add(img);
        }
        catch { /* the mascot is decoration; its absence never blanks the page */ }
        stack.Children.Add(titleGrid);
        _effPolicyContext = new TextBlock
        {
            Text = "", FontSize = 15,
            Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
            Margin = new Thickness(0, 0, 0, 16), TextWrapping = TextWrapping.Wrap,
        };
        stack.Children.Add(_effPolicyContext);

        // ---- context row: target card + breadcrumb/search card ----
        var context = new Grid { Margin = new Thickness(0, 0, 0, 14) };
        context.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
        context.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _effPolicyTarget = new StackPanel();
        var targetCard = Card(_effPolicyTarget);
        targetCard.Margin = new Thickness(0, 0, 7, 0);
        Grid.SetColumn(targetCard, 0);
        context.Children.Add(targetCard);

        var crumbPanel = new Grid { VerticalAlignment = VerticalAlignment.Center };
        crumbPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        crumbPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var crumb = new TextBlock { FontSize = 17, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
        crumb.Inlines.Add(new Run("⌂  ›  …  ›  "));
        _effPolicyCrumbCurrent = new Run("Effective Policy");
        crumb.Inlines.Add(_effPolicyCrumbCurrent);
        crumbPanel.Children.Add(crumb);
        _effPolicySearchTop = new TextBox
        {
            Width = 306, Height = 48, FontSize = 16, Padding = new Thickness(10, 0, 10, 0),
            VerticalContentAlignment = VerticalAlignment.Center,
            ToolTip = "Search the rules below",
        };
        _effPolicySearchTop.TextChanged += (_, _) => SyncPolicySearch(_effPolicySearchTop, _effPolicySearchRules);
        var topSearch = PolicySearchShell(_effPolicySearchTop);
        Grid.SetColumn(topSearch, 1);
        crumbPanel.Children.Add(topSearch);
        var crumbCard = Card(crumbPanel);
        crumbCard.Margin = new Thickness(7, 0, 0, 0);
        Grid.SetColumn(crumbCard, 1);
        context.Children.Add(crumbCard);
        stack.Children.Add(context);

        // ---- rules panel ----
        var rulesPanel = new StackPanel();
        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        head.Children.Add(new TextBlock
        {
            Text = "Effective Rules & Policies", FontSize = 24,
            FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center,
        });
        _effPolicySearchRules = new TextBox
        {
            Width = 306, Height = 48, FontSize = 16, Padding = new Thickness(10, 0, 10, 0),
            VerticalContentAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0),
            ToolTip = "Search the rules below",
        };
        _effPolicySearchRules.TextChanged += (_, _) => SyncPolicySearch(_effPolicySearchRules, _effPolicySearchTop);
        var rulesSearch = PolicySearchShell(_effPolicySearchRules);
        Grid.SetColumn(rulesSearch, 1);
        head.Children.Add(rulesSearch);
        _effPolicyFiltersReady = false;
        _effPolicyLayerFilter = new ComboBox
        {
            Width = 230, Height = 48, FontSize = 16,
            VerticalContentAlignment = VerticalAlignment.Center,
            ItemsSource = new[]
            {
                "Filter (all sources)", "Company policy", "Group", "This device",
                "Pairing", "DeskGuest default", "Not a setting",
            },
            SelectedIndex = 0,
            ToolTip = "Show only rules from one source",
        };
        _effPolicyLayerFilter.SelectionChanged += (_, _) => { if (_effPolicyFiltersReady) RenderPolicyView(); };
        Grid.SetColumn(_effPolicyLayerFilter, 2);
        head.Children.Add(_effPolicyLayerFilter);
        rulesPanel.Children.Add(head);

        _effPolicyCount = Muted("", 14);
        _effPolicyCount.Margin = new Thickness(0, 10, 0, 0);
        rulesPanel.Children.Add(_effPolicyCount);

        // Table header — the design's three columns, verbatim.
        var tableHead = new Grid { Margin = new Thickness(2, 12, 2, 6) };
        PolicyTableColumns(tableHead);
        void HeadCell(string text, int col)
        {
            var t = new TextBlock { Text = text, FontSize = 17, FontWeight = FontWeights.SemiBold };
            Grid.SetColumn(t, col);
            tableHead.Children.Add(t);
        }
        HeadCell("What This Rule Does", 1);
        HeadCell("Status", 2);
        HeadCell("Where This Rule Came From", 3);
        rulesPanel.Children.Add(tableHead);

        _effPolicyRules = new StackPanel();
        rulesPanel.Children.Add(_effPolicyRules);
        stack.Children.Add(Card(rulesPanel));

        // ---- the named gap, on the page (data law) ----
        var gap = new StackPanel();
        gap.Children.Add(new TextBlock
        {
            Text = "What this page can't show yet", FontSize = 20,
            FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6),
        });
        gap.Children.Add(Muted(
            "The rules on this PC are worked out in steps: your company's policy first, then your " +
            "group's settings, then this device's own settings — and each step remembers where a " +
            "rule came from. This page doesn't receive that step-by-step list yet, so group settings " +
            "don't get their own rows, and company rows show only the overall facts this page does " +
            "receive. Nothing is guessed to fill the gap: when the step-by-step list reaches this " +
            "page, those rows will appear here with where each one really came from.", 15));
        stack.Children.Add(Card(gap));

        _effPolicyFiltersReady = true;
        RenderPolicyView();
        return stack;
    }

    /// <summary>The rules table's shared column geometry: a 4 px
    /// selection accent, the rule, the status pill, the source.</summary>
    private static void PolicyTableColumns(Grid grid)
    {
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(168) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(330) });
    }

    /// <summary>The two search boxes (context card + rules header,
    /// as the design paints them) are one search: typing in either
    /// updates the other and re-renders once.</summary>
    // The design's search boxes carry a visible "Search" watermark
    // (Pack 02, Screen 60) — a bare white box reads as an unfinished
    // surface. WPF TextBox has no watermark of its own, so the box
    // sits in a shell with a muted, hit-test-transparent label that
    // hides the moment the box holds text (including text synced
    // from its twin).
    private Grid PolicySearchShell(TextBox box)
    {
        var shell = new Grid();
        var hint = new TextBlock
        {
            Text = "⌕  Search",
            FontSize = 16,
            Foreground = (Brush)FindResource("DgMutedBrush"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0),
            IsHitTestVisible = false,
        };
        box.TextChanged += (_, _) =>
            hint.Visibility = string.IsNullOrEmpty(box.Text)
                ? Visibility.Visible : Visibility.Collapsed;
        shell.Children.Add(box);
        shell.Children.Add(hint);
        return shell;
    }

    private void SyncPolicySearch(TextBox? from, TextBox? to)
    {
        if (_effPolicySyncingSearch || from is null) return;
        _effPolicySyncingSearch = true;
        if (to is not null && to.Text != from.Text) to.Text = from.Text;
        _effPolicySyncingSearch = false;
        if (_effPolicyFiltersReady) RenderPolicyView();
    }

    private string PolicyLayerWanted() => _effPolicyLayerFilter?.SelectedIndex switch
    {
        1 => "company",
        2 => "group",
        3 => "device",
        4 => "pairing",
        5 => "default",
        6 => "floor",
        _ => "",
    };

    /// <summary>Plain names for the eight bundle feature keys
    /// (PolicyFeatures) as rule sentences — what the feature does,
    /// in the design column's own voice.</summary>
    private static string PolicyFeatureRule(string key) => key switch
    {
        "wake_on_lan" => "Another device your company manages can wake this PC over the network.",
        "blank_screen" => "A session can blank this PC's screen while someone is connected.",
        "input_block" => "A session can block this PC's own keyboard and mouse while someone works on it.",
        "voice_video" => "Sessions can carry voice and video calls.",
        "standalone_file_transfer" => "Files can move to and from this PC without a live session.",
        "local_second_factor" => "Signing in on this PC needs a second check — a code or a passkey.",
        "watermark" => "A watermark is shown over session screens.",
        "tcp_tunnel" => "Sessions can pass other network traffic through this PC.",
        _ => $"Feature “{key.Replace('_', ' ')}” is governed by policy on this PC.",
    };

    /// <summary>Every rule the current snapshot backs, in reading
    /// order: the consent floor first (it is never a setting),
    /// then the built-in defaults, the company bundle's facts,
    /// this device's own settings, and the pairings. A layer with
    /// no snapshot fact behind it contributes no rows.</summary>
    private List<EffPolicyRule> PolicyRules()
    {
        var rules = new List<EffPolicyRule>();
        var host = _host;

        // ---- the consent floor: not a setting, no source layer ----
        rules.Add(new EffPolicyRule(
            "You always see who is connected to this PC. The on-screen presence signs stay on for the whole session, and no one can dim or hide them.",
            "This is not a setting and nothing can turn it off — it is always true, whoever set this PC up.",
            "Always on", EffPolicyPill.On, "Not a setting — always true", "floor"));
        rules.Add(new EffPolicyRule(
            "STOP ends any session instantly and blocks every agent until you clear it.",
            "No agent action can lift a STOP. Only the person at this PC can clear it.",
            host?.UserStop == true ? "In force now" : "Always on", EffPolicyPill.On,
            "Not a setting — always true", "floor"));
        rules.Add(new EffPolicyRule(
            "The record of what happened on this PC can't be edited or deleted.",
            "Every entry is linked to the one before it, so changing any entry breaks the link — and the break shows when the record is checked.",
            "Always on", EffPolicyPill.On, "Not a setting — always true", "floor"));

        // ---- built-in defaults (the Guardrails page's policy in force) ----
        rules.Add(new EffPolicyRule(
            "An agent can see your screen only inside a live session on this PC.",
            "There is no background viewing: no live session, no screen.",
            "Active", EffPolicyPill.On, "DeskGuest default", "default"));
        rules.Add(new EffPolicyRule(
            "An agent can move the mouse and type only inside that live session.",
            // FR-145 floor law: the owner's own input coexists with
            // the agent's — it never takes over and never interrupts.
            "Using your own mouse and keyboard at the same time is fine — it never interrupts the agent.",
            "Active", EffPolicyPill.On, "DeskGuest default", "default"));
        rules.Add(new EffPolicyRule(
            "An agent you gave full access can run commands and programs on this PC.",
            "That is part of full access. The kinds of action that need approval are listed below — they still ask first.",
            "Active", EffPolicyPill.On, "DeskGuest default", "default"));
        rules.Add(new EffPolicyRule(
            "An agent can change Windows settings in the Registry only with approval.",
            "Changing a setting needs one approval and deleting needs another. It is never open without asking, and never flatly refused.",
            "Approval needed", EffPolicyPill.Info, "DeskGuest default", "default"));

        // ---- company policy: the signed bundle's snapshot facts ----
        var e = host?.Enterprise;
        if (e is not null)
        {
            rules.Add(new EffPolicyRule(
                e.PolicyLoaded
                    ? "This PC follows the policy your company sent it."
                    : "No company policy is in force on this PC.",
                e.PolicyState,
                e.PolicyLoaded ? "In force" : "Not in force",
                e.PolicyLoaded ? EffPolicyPill.On : EffPolicyPill.Off,
                e.PolicyLoaded ? "Company policy" : "No company policy", "company"));
        }
        if (host?.BlockG is not null)
        {
            var loaded = e?.PolicyLoaded == true;
            foreach (var (key, state) in host.BlockG.FeatureStates.OrderBy(f => f.Key, StringComparer.Ordinal))
            {
                var (status, pill, detail) = state switch
                {
                    "required" => ("Required", EffPolicyPill.Info,
                        loaded ? "Your company policy requires this — it can't be turned off on this PC."
                               : "Required by the policy in force on this PC."),
                    "disabled" => ("Off", EffPolicyPill.Off,
                        loaded ? "Your company policy turned this off."
                               : "This is off in the policy in force on this PC."),
                    _ => ("Allowed", EffPolicyPill.On,
                        loaded ? "Your company policy leaves this on."
                               : "Nothing has turned this off, so DeskGuest's default stands."),
                };
                rules.Add(new EffPolicyRule(
                    PolicyFeatureRule(key), detail, status, pill,
                    loaded ? "Company policy" : "DeskGuest default",
                    loaded ? "company" : "default"));
            }
        }

        // ---- this device's own settings ----
        var fileLabel = DeskGuest.Shared.Files.FileRootsLabel.Generate(host?.FileRoots);
        rules.Add(new EffPolicyRule(
            fileLabel.Detail, null,
            fileLabel.Chip, fileLabel.Chip == "Not reported" ? EffPolicyPill.Off : EffPolicyPill.On,
            "Set on this device", "device"));
        if (host is not null)
        {
            foreach (var (id, approved) in host.Gates)
            {
                // Two shared GateLabels still carry engineering words
                // (and one the legacy product name); this page reads
                // them in plain words. The shared dictionary itself
                // belongs to the Guardrails surface — see the #150
                // register note in BUILD-LOG.md.
                var label = id switch
                {
                    "service_stop_non_deskguest" => "Stopping other services",
                    "vault_ops" => "Using saved passwords and keys",
                    _ => GateLabels.TryGetValue(id, out var friendly) ? friendly : id,
                };
                rules.Add(new EffPolicyRule(
                    $"{label} — an agent needs approval before doing this.",
                    approved
                        ? "You approved this on this PC, so agents may do it until you take the approval back on the Guardrails page."
                        : "No agent can do this right now. You can approve it on the Guardrails page — nowhere else.",
                    approved ? "Approved" : "Blocked",
                    approved ? EffPolicyPill.On : EffPolicyPill.Off,
                    "Set on this device", "device"));
            }
        }
        if (e is not null)
        {
            rules.Add(new EffPolicyRule(
                "The record of what happened on this PC is checked for changes.",
                e.ChainSummary,
                e.ChainOk ? "Intact" : "BROKEN",
                e.ChainOk ? EffPolicyPill.On : EffPolicyPill.Danger,
                "Set on this device", "device"));
        }

        // ---- pairings ----
        if (host is not null)
        {
            var anyPairing = false;
            foreach (var (_, pname, scopes, revoked) in host.Pairings)
            {
                if (revoked) continue;
                anyPairing = true;
                rules.Add(new EffPolicyRule(
                    $"{pname} is paired with this PC and can connect to it.",
                    $"What it can do: {string.Join(", ", scopes.Select(PlainScope))}",
                    "Active", EffPolicyPill.On, $"Pairing — {pname}", "pairing"));
            }
            if (!anyPairing)
                rules.Add(new EffPolicyRule(
                    "No agent is paired with this PC, so no agent can connect to it.",
                    "Pairing an agent adds its own row here, with the scopes it was given.",
                    "None paired", EffPolicyPill.Off, "Pairing", "pairing"));
        }
        return rules;
    }

    /// <summary>Plain words for a pairing's scope names — the raw
    /// scope ids are engineering vocabulary; a person reads what
    /// the agent can actually do. An unknown scope falls back to
    /// its raw name rather than a guessed meaning.</summary>
    private static string PlainScope(string scope) => scope switch
    {
        "observe" => "see the screen",
        "drive" => "move the mouse and type",
        "shell" => "run commands",
        "admin" => "manage this PC's settings",
        "unlock" => "unlock this PC",
        "terminal" => "use the terminal",
        "background_tools" => "work in the background",
        "backstage" => "use a separate desktop session",
        "background_kit_admin" => "manage shared tool sets",
        _ => scope,
    };

    private Border PolicyPillBorder(string text, EffPolicyPill pill)
    {
        var (bg, fg) = pill switch
        {
            EffPolicyPill.On => ((Brush)FindResource("DgTealBrush"), (Brush)FindResource("DgWhiteBrush")),
            EffPolicyPill.Danger => ((Brush)FindResource("DgRedBrush"), (Brush)FindResource("DgWhiteBrush")),
            EffPolicyPill.Info => ((Brush)FindResource("DgBlueBrush"), (Brush)FindResource("DgWhiteBrush")),
            _ => ((Brush)FindResource("DgSubtleBrush"), (Brush)FindResource("DgMutedBrush")),
        };
        return new Border
        {
            Background = bg,
            CornerRadius = new CornerRadius(999),
            Padding = new Thickness(18, 6, 18, 6),
            MinWidth = 100,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = text, FontSize = 15.5, FontWeight = FontWeights.SemiBold,
                Foreground = fg, TextAlignment = TextAlignment.Center,
            },
        };
    }

    private UIElement PolicyRuleRow(EffPolicyRule rule, bool selected, bool alt)
    {
        var grid = new Grid { Margin = new Thickness(0, 10, 0, 10) };
        PolicyTableColumns(grid);
        var accent = new Border
        {
            Background = selected ? (Brush)FindResource("DgBlueBrush") : Brushes.Transparent,
            Margin = new Thickness(0, 2, 0, 2),
        };
        Grid.SetColumn(accent, 0);
        grid.Children.Add(accent);

        var ruleStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(18, 0, 12, 0) };
        ruleStack.Children.Add(new TextBlock { Text = rule.Rule, FontSize = 17.5, TextWrapping = TextWrapping.Wrap });
        if (!string.IsNullOrEmpty(rule.Detail))
            ruleStack.Children.Add(Muted(rule.Detail, 14.5));
        Grid.SetColumn(ruleStack, 1);
        grid.Children.Add(ruleStack);

        var pill = PolicyPillBorder(rule.Status, rule.Pill);
        Grid.SetColumn(pill, 2);
        grid.Children.Add(pill);

        var source = new TextBlock
        {
            Text = rule.Source, FontSize = 16.5, TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(source, 3);
        grid.Children.Add(source);

        Brush bg = Brushes.Transparent;
        if (selected) bg = (Brush)FindResource("DgSubtleBrush");
        else if (alt) bg = new SolidColorBrush(((SolidColorBrush)FindResource("DgSubtleBrush")).Color) { Opacity = 0.45 };
        return new Border
        {
            Background = bg,
            BorderBrush = (Brush)FindResource("DgBorderBrush"),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Child = grid,
        };
    }

    /// <summary>Re-render the page's live parts from the current
    /// snapshot: the context line, the target card, the breadcrumb's
    /// current page, and the rules table under the current search +
    /// source filter. Called on build and on every snapshot while
    /// the page is current (the coordinator's RefreshDynamics arm).</summary>
    private void RenderPolicyView()
    {
        if (_effPolicyRules is null) return;

        var host = _host;
        var device = !string.IsNullOrWhiteSpace(host?.Endpoint?.Device.Name)
            ? host!.Endpoint!.Device.Name
            : !string.IsNullOrWhiteSpace(host?.MachineName) ? host!.MachineName : "this PC";
        if (_effPolicyContext is not null)
            _effPolicyContext.Text = host is null
                ? "Waiting for this PC's information — the built-in rules below are always true; the rest appear when it arrives."
                : $"Viewing active rules for this device — {device}. Every rule below names where it came from.";
        if (_effPolicyCrumbCurrent is not null)
            _effPolicyCrumbCurrent.Text = $"Effective Policy ({device})";
        if (_effPolicyTarget is not null)
        {
            _effPolicyTarget.Children.Clear();
            void TargetLine(string label, string value)
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
                row.Children.Add(new TextBlock { Text = label + "  ", FontSize = 17, FontWeight = FontWeights.SemiBold });
                row.Children.Add(new TextBlock { Text = value, FontSize = 17, TextWrapping = TextWrapping.Wrap });
                _effPolicyTarget.Children.Add(row);
            }
            var scope = host?.Roster.FirstOrDefault(s => s.Kind == "company")?.Name
                ?? host?.Endpoint?.Device.Scope;
            TargetLine("Target:", !string.IsNullOrWhiteSpace(scope) ? scope : "This PC");
            TargetLine("Device:", device);
            var group = host?.Endpoint?.Device.GroupName;
            if (!string.IsNullOrWhiteSpace(group)) TargetLine("Group:", group);
        }

        _effPolicyRules.Children.Clear();
        var all = PolicyRules();
        var query = (_effPolicySearchRules?.Text ?? "").Trim();
        var layer = PolicyLayerWanted();
        var shown = all.Where(r =>
            (layer.Length == 0 || r.Layer == layer) &&
            (query.Length == 0
                || r.Rule.Contains(query, StringComparison.OrdinalIgnoreCase)
                || (r.Detail?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
                || r.Source.Contains(query, StringComparison.OrdinalIgnoreCase))).ToList();
        if (_effPolicyCount is not null)
            _effPolicyCount.Text = shown.Count == all.Count
                ? $"{all.Count} rules in force"
                : $"{shown.Count} of {all.Count} rules shown";
        if (shown.Count == 0)
        {
            _effPolicyRules.Children.Add(Muted(layer == "group"
                ? "No group rules are shown — this page doesn't receive group settings yet (see “What this page can't show yet” below)."
                : "No rules match this search and source. Clear the search or choose “Filter (all sources)” to see every rule in force.", 15));
            return;
        }
        for (var i = 0; i < shown.Count; i++)
            _effPolicyRules.Children.Add(PolicyRuleRow(shown[i], selected: i == 0, alt: i % 2 == 1));
    }
}

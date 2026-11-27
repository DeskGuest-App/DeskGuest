using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using DeskGuest.Shared.Design;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using ComboBox = System.Windows.Controls.ComboBox;
using Brush = System.Windows.Media.Brush;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;
using VerticalAlignment = System.Windows.VerticalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// MP-3 / Face Tranche 1 item 2c — the Data Ledger page (Screen 61,
/// census N11; design pack 04-data-ledger). The per-agent data-flow
/// ledger: a chronological, plain-language record of what moved
/// between this PC and each paired agent, plus the per-agent totals
/// counted from the Core's data-flow record (U5 DataFlowLedger,
/// carried on the host-state snapshot's dataFlows section).
///
/// DATA LAW — every number and row on this page comes from the real
/// record the window already receives:
///   * the table rows are the snapshot's audit entries (the same
///     entries the Activity Record page renders), newest first;
///   * the per-agent totals are the snapshot's dataFlows aggregates,
///     shaped by SessionLedgerModel — the same model the Sessions
///     witness ledger uses, so this page and the agent surfaces can
///     never disagree;
///   * the gaps the report names are shown verbatim.
/// Nothing is estimated, no sample rows exist, and where the record
/// does not expose a design element (per-event byte sizes, the
/// design's Metadata column content, human-session flows) the page
/// renders the honest empty form and BUILD-DIFF.md in the design
/// pack names the missing exposure.
///
/// The owner's personal AI name never appears as a product entry
/// (pack substitution S-1): an agent whose record carries no name
/// is shown as "your paired AI"; a named pairing shows its real
/// name from its record.
/// </summary>
public partial class MainWindow
{
    private StackPanel? _ledgerRows;
    private StackPanel? _ledgerAgents;
    private TextBlock? _ledgerCount;
    private ComboBox? _ledgerEventFilter;
    private ComboBox? _ledgerDirectionFilter;
    private ComboBox? _ledgerDateFilter;
    private bool _ledgerFiltersReady;

    // The design's direction vocabulary, mapped from the record's
    // own tool names — the same sets the flow classifier and the
    // frame accounting already use (DataFlowClassifier /
    // SessionLedgerModel.FrameTools):
    //   VIEWED   — the agent saw this PC (frame tools);
    //   OUTGOING — data left this PC to the agent (clipboard read,
    //              chat sent off-device);
    //   INCOMING — the agent sent data or input to this PC
    //              (clipboard set, file write, typed input).
    // A tool in none of these sets carries NO badge rather than a
    // guessed one.
    // Owner-language lead-ins for the record's tool names (see
    // LedgerRow). Anything unmapped falls back to the tool name
    // itself — the page never invents a translation.
    private static string LedgerLead(string tool) => tool switch
    {
        "screenshot" or "annotated_screenshot" => "Screen viewed",
        "snapshot" => "Screen contents read",
        "camera_capture" => "Camera viewed",
        "click" => "Clicked",
        "key_press" => "Key pressed",
        "type_text" => "Text typed",
        "clipboard_read" or "clipboard_get" => "Clipboard read",
        "clipboard_set" or "clipboard_write" => "Clipboard set",
        "file_read" => "File read",
        "file_write" => "File written",
        "file_delete" => "File deleted",
        "file_transfer" or "file_transfer_begin" or "file_transfer_chunk" or "file_transfer_commit" => "File transferred",
        "shell_exec_system" or "shell_exec_user" or "shell_exec" => "Ran a command",
        "process_kill" => "Program stopped",
        "session_start" => "Session started",
        "session_stop" => "Session ended",
        "agent_chat" => "Chat message sent",
        // #151: the same acts under their current tool names (the
        // live record carries chat_post / scroll; their renamed
        // predecessors above were already mapped — display only).
        "chat_post" => "Chat message sent",
        "scroll" => "Scrolled",
        _ => tool,
    };

    private static string? LedgerDirection(string? tool) => tool switch
    {
        "screenshot" or "annotated_screenshot" or "snapshot" or "camera_capture"
            => "[ VIEWED ]",
        "clipboard_read" or "clipboard_get" or "agent_chat"
            => "[ OUTGOING ]",
        "clipboard_set" or "clipboard_write" or "file_write" or "type_text" or "key_press"
            => "[ INCOMING ]",
        _ => null,
    };

    private UIElement BuildLedgerPage()
    {
        var stack = new StackPanel();

        // Title row — the design places the Greeter at the title's
        // right; the app carries the same mascot as a PNG asset
        // (deskguest-wave.png), loaded like the About lockup.
        var titleGrid = new Grid();
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        // #151: the title is carried locally at the painting's scale
        // (the shared PageTitle helper is the other pages' scale —
        // the #149 Groups pattern).
        titleGrid.Children.Add(new TextBlock
        {
            Text = "Data Ledger", FontSize = 30, FontWeight = FontWeights.ExtraBold,
            Margin = new Thickness(0, 2, 0, 2), VerticalAlignment = VerticalAlignment.Center,
        });
        try
        {
            var mascot = new System.Windows.Media.Imaging.BitmapImage(
                new System.Uri("pack://application:,,,/deskguest-wave.png"));
            var img = new System.Windows.Controls.Image
            {
                Source = mascot, Height = 64,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center,
            };
            Grid.SetColumn(img, 1);
            titleGrid.Children.Add(img);
        }
        catch { /* the mascot is decoration; its absence never blanks the page */ }
        stack.Children.Add(titleGrid);
        var intro = Muted("Every file, screen view and clipboard transfer between this PC and your paired AI, in order. Counted from this PC's own data-flow record — the record is kept on this PC and sent nowhere.", 14.5);
        intro.Margin = new Thickness(0, 2, 0, 14);
        stack.Children.Add(intro);

        // ---- filters + export (the design's filter row) ----
        // The corpus paints only the selects' closed states (pack
        // gap G-4); the option lists below are the record's own
        // categories, and every option really filters the table.
        var filterRow = new Grid { Margin = new Thickness(0, 2, 0, 0) };
        filterRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        filterRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        filterRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        filterRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        filterRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _ledgerFiltersReady = false;
        _ledgerEventFilter = new ComboBox
        {
            Width = 250, Height = 46, FontSize = 16,
            VerticalContentAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 16, 0),
            ItemsSource = new[] { "All Events", "Tool calls", "Host events" },
            SelectedIndex = 0,
        };
        _ledgerDirectionFilter = new ComboBox
        {
            Width = 250, Height = 46, FontSize = 16,
            VerticalContentAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 16, 0),
            ItemsSource = new[] { "Direction (All)", "[ INCOMING ]", "[ VIEWED ]", "[ OUTGOING ]" },
            SelectedIndex = 0,
        };
        _ledgerDateFilter = new ComboBox
        {
            Width = 250, Height = 46, FontSize = 16,
            VerticalContentAlignment = VerticalAlignment.Center,
            ItemsSource = new[] { "Date (Today)", "Date (All)", "Date (Last 7 days)" },
            SelectedIndex = 0,
        };
        foreach (var box in new[] { _ledgerEventFilter, _ledgerDirectionFilter, _ledgerDateFilter })
            box.SelectionChanged += (_, _) => { if (_ledgerFiltersReady) RenderLedger(); };
        Grid.SetColumn(_ledgerEventFilter, 0);
        Grid.SetColumn(_ledgerDirectionFilter, 1);
        Grid.SetColumn(_ledgerDateFilter, 2);
        filterRow.Children.Add(_ledgerEventFilter);
        filterRow.Children.Add(_ledgerDirectionFilter);
        filterRow.Children.Add(_ledgerDateFilter);

        var export = new Button
        {
            Content = "Export Ledger",
            Style = (Style)FindResource("PrimaryButton"),
            Height = 46, FontSize = 16.5, FontWeight = FontWeights.SemiBold,
            Padding = new Thickness(20, 0, 20, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        export.Click += (_, _) => ExportLedger();
        Grid.SetColumn(export, 4);
        filterRow.Children.Add(export);
        stack.Children.Add(filterRow);

        _ledgerCount = Muted("", 13.5);
        _ledgerCount.Margin = new Thickness(0, 10, 0, 0);
        stack.Children.Add(_ledgerCount);

        // ---- table header (the design's Time / Activity / Metadata) ----
        var head = new Grid { Margin = new Thickness(20, 14, 20, 6) };
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });
        void HeadCell(string text, int col)
        {
            var t = new TextBlock { Text = text, FontSize = 17, FontWeight = FontWeights.SemiBold };
            Grid.SetColumn(t, col);
            head.Children.Add(t);
        }
        HeadCell("Time", 0);
        HeadCell("Activity", 2);
        HeadCell("Metadata", 3);
        stack.Children.Add(head);

        _ledgerRows = new StackPanel();
        stack.Children.Add(_ledgerRows);

        // ---- per-agent totals, from the data-flow record ----
        var agentsTitle = new TextBlock
        {
            Text = "By paired AI", FontSize = 20, FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 22, 0, 4),
        };
        stack.Children.Add(agentsTitle);
        stack.Children.Add(Muted("What each paired AI has read, sent and changed on this PC — counted from the data-flow record, never estimated. Totals are separate labelled numbers, never added into one score.", 13.5));
        _ledgerAgents = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        stack.Children.Add(_ledgerAgents);

        _ledgerFiltersReady = true;
        RenderLedger();
        return stack;
    }

    /// <summary>The audit entries the current filters show, newest
    /// first — the one filter derivation both the table and the
    /// export use, so what is exported is exactly what is shown.</summary>
    private List<(DateTimeOffset At, string? Agent, string? Tool, string? Operation, string Outcome, long? Ms)> LedgerShownEntries()
    {
        if (_host is null) return new();
        var entries = _host.Audit.AsEnumerable().Reverse();
        if (_ledgerEventFilter?.SelectedIndex == 1)
            entries = entries.Where(e => e.Tool is not null);
        else if (_ledgerEventFilter?.SelectedIndex == 2)
            entries = entries.Where(e => e.Tool is null);
        if (_ledgerDirectionFilter?.SelectedIndex is int di and > 0)
        {
            var wanted = _ledgerDirectionFilter.Items[di] as string;
            entries = entries.Where(e => LedgerDirection(e.Tool) == wanted);
        }
        if (_ledgerDateFilter?.SelectedIndex == 0)
            entries = entries.Where(e => e.At.ToLocalTime().Date == DateTime.Now.Date);
        else if (_ledgerDateFilter?.SelectedIndex == 2)
            entries = entries.Where(e => e.At >= DateTimeOffset.Now.AddDays(-7));
        return entries.ToList();
    }

    private void RenderLedger()
    {
        if (_ledgerRows is null || _ledgerAgents is null || _ledgerCount is null) return;
        _ledgerRows.Children.Clear();
        _ledgerAgents.Children.Clear();

        if (_host is null)
        {
            _ledgerCount.Text = "";
            _ledgerRows.Children.Add(Muted("Waiting for the Core's snapshot…", 14.5));
            _ledgerAgents.Children.Add(Muted("Waiting for the Core's snapshot…", 14.5));
            return;
        }

        var shown = LedgerShownEntries();
        _ledgerCount.Text = _host.Audit.Count == 0
            ? ""
            : $"{shown.Count} of {_host.Audit.Count} record entries shown";

        if (_host.Audit.Count == 0 && _host.Flows.Count == 0)
        {
            // The empty ledger — the common first-run state. No
            // design exists for it in the corpus (pack gap G-2);
            // composed in this page's own language.
            _ledgerRows.Children.Add(Card(Body(
                "Nothing has moved yet. When your paired AI receives a file, views the screen, or copies clipboard text, it will be listed here — counted from this PC's own record, in the order it happened.", 15)));
        }
        else if (shown.Count == 0)
        {
            _ledgerRows.Children.Add(Muted("Nothing in the record matches these filters. Widen the date or direction to see more of the record.", 14.5));
        }
        else
        {
            foreach (var entry in shown)
                _ledgerRows.Children.Add(LedgerRow(entry));
        }

        // ---- per-agent totals ----
        if (_host.Flows.Count == 0)
        {
            if (_host.Audit.Count > 0)
                _ledgerAgents.Children.Add(Muted("No data-flow totals yet — the record holds activity, but no paired AI has moved data in the counted record.", 14));
        }
        else
        {
            foreach (var flow in _host.Flows)
            {
                var name = string.IsNullOrWhiteSpace(flow.AgentName) ? "your paired AI" : flow.AgentName;
                var counts = new SessionLedgerModel.Counts(
                    flow.ClassCalls.TryGetValue("read", out var rc) ? rc : 0,
                    flow.ClassCalls.TryGetValue("sent", out var sc) ? sc : 0,
                    flow.ClassCalls.TryGetValue("changed", out var cc) ? cc : 0);
                var live = _host.SessionActive && _host.SessionAgent == flow.AgentName;
                var model = SessionLedgerModel.Build(
                    verdict: live ? $"{name} is in a session on this PC."
                                  : $"{name}'s sessions on this PC are over.",
                    counts: counts, live: live, agentName: name,
                    destinations: flow.Destinations, gaps: _host.FlowGaps);
                var body = new StackPanel();
                var headRow = new StackPanel { Orientation = Orientation.Horizontal };
                headRow.Children.Add(new TextBlock { Text = name, FontSize = 17, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
                var sessionsChip = Chip(flow.SessionCount == 1 ? "1 session" : $"{flow.SessionCount} sessions", GrayBg, GrayFg);
                sessionsChip.Margin = new Thickness(10, 0, 0, 0);
                headRow.Children.Add(sessionsChip);
                body.Children.Add(headRow);
                body.Children.Add(Body(model.Verdict, 14.5));
                body.Children.Add(Muted(SessionLedgerModel.CountsLine(model.Counts, model.Live), 14));
                foreach (var d in model.Destinations)
                    body.Children.Add(Muted($"→ {d}", 13));
                if (flow.FramesSent > 0)
                    body.Children.Add(Muted(SessionLedgerModel.SeenSoFarLine(flow.FramesSent), 13));
                if (flow.ChatSent > 0)
                    body.Children.Add(Muted(SessionLedgerModel.ChatSentLine(flow.ChatSent), 13));
                body.Children.Add(Muted(model.ProviderLine, 13));
                body.Children.Add(Muted(model.VendorLine, 13));
                if (model.GapsLine is not null)
                    body.Children.Add(Muted(model.GapsLine, 13));
                body.Children.Add(Muted(model.PresenceOnFramesLine, 13));
                _ledgerAgents.Children.Add(Card(body));
            }
        }

        // Gaps the report names and no agent card carried (the
        // per-agent cards above already include the gaps line via
        // SessionLedgerModel; when there are no flow cards, the
        // gaps still show — they are never hidden).
        if (_host.Flows.Count == 0 && _host.FlowGaps.Count > 0)
        {
            var gaps = new StackPanel();
            gaps.Children.Add(new TextBlock { Text = "Not seen", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
            foreach (var gap in _host.FlowGaps)
                gaps.Children.Add(Muted(gap, 13));
            _ledgerAgents.Children.Add(Card(gaps));
        }
    }

    private Border LedgerRow((DateTimeOffset At, string? Agent, string? Tool, string? Operation, string Outcome, long? Ms) entry)
    {
        var grid = new Grid { VerticalAlignment = VerticalAlignment.Center };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });

        var time = new TextBlock
        {
            Text = entry.At.ToLocalTime().ToString("h:mm tt"),
            FontSize = 17, VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(time, 0);
        grid.Children.Add(time);

        var direction = LedgerDirection(entry.Tool);
        if (direction is not null)
        {
            var badge = new Border
            {
                Background = (Brush)FindResource("DgTealBrush"),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(9, 5, 9, 5),
                MinWidth = 106,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = direction, FontSize = 12.5, FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White, TextAlignment = TextAlignment.Center,
                },
            };
            Grid.SetColumn(badge, 1);
            grid.Children.Add(badge);
        }

        // Activity: the design's form — a plain-language lead-in,
        // the acting agent after an em dash. Tool names are the
        // record's internal vocabulary, so the lead translates the
        // known tools into the owner's words (the design's rows are
        // owner sentences: "Screen viewed", "File received"); an
        // unmapped tool keeps its record name rather than a guessed
        // translation. Display only — the record itself and the
        // export keep the tool names untouched. An unnamed agent is
        // "your paired AI" (pack substitution S-1); a host entry
        // names the host.
        var lead = entry.Tool is not null ? LedgerLead(entry.Tool)
            : entry.Operation ?? entry.Outcome;
        var detail = entry.Tool is not null && entry.Operation is not null
            ? entry.Operation : null;
        var agent = entry.Agent ?? (entry.Tool is not null ? "your paired AI" : "this PC");
        var activity = new TextBlock
        {
            FontSize = 17, TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
        };
        activity.Inlines.Add(new Bold(new Run(lead)));
        var tail = detail is not null ? $" — {detail} · {agent}" : $" — {agent}";
        activity.Inlines.Add(new Run(tail));
        Grid.SetColumn(activity, 2);
        grid.Children.Add(activity);

        // Metadata: the corpus never says what this column holds
        // (pack gap G-1) — the build invents nothing; it carries
        // the record's own outcome for the entry, in the audit
        // page's words, and is empty when the record has none.
        var (chipText, _, _) = OutcomeChip(entry.Outcome, entry.Ms);
        var meta = new TextBlock
        {
            Text = chipText, FontSize = 14.5,
            Foreground = (Brush)FindResource("DgMutedBrush"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(meta, 3);
        grid.Children.Add(meta);

        return new Border
        {
            Background = (Brush)FindResource("DgSurfaceBrush"),
            BorderBrush = (Brush)FindResource("DgBorderBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(20, 0, 20, 0),
            MinHeight = 62,
            Margin = new Thickness(0, 0, 0, 14),
            Child = grid,
        };
    }

    private void ExportLedger()
    {
        if (_host is null) return;
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"deskguest-data-ledger-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
            Title = "Export Ledger"
        };
        if (dialog.ShowDialog(this) != true) return;
        var payload = new
        {
            exportedAtUtc = DateTimeOffset.UtcNow,
            entries = LedgerShownEntries().Select(e => new
            {
                atUtc = e.At,
                agent = e.Agent,
                tool = e.Tool,
                operation = e.Operation,
                outcome = e.Outcome,
                durationMs = e.Ms,
                direction = LedgerDirection(e.Tool),
            }),
            agents = _host.Flows.Select(f => new
            {
                pairingId = f.PairingId,
                agentName = f.AgentName,
                sessions = f.SessionCount,
                readCalls = f.ClassCalls.TryGetValue("read", out var rc) ? rc : 0,
                sentCalls = f.ClassCalls.TryGetValue("sent", out var sc) ? sc : 0,
                changedCalls = f.ClassCalls.TryGetValue("changed", out var cc) ? cc : 0,
                destinations = f.Destinations,
                framesSent = f.FramesSent,
                chatSent = f.ChatSent,
            }),
            gaps = _host.FlowGaps,
        };
        File.WriteAllText(dialog.FileName, System.Text.Json.JsonSerializer.Serialize(payload, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}

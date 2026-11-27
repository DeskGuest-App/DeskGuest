using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using DeskGuest.Shared.Design;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Presence;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using VerticalAlignment = System.Windows.VerticalAlignment;
using Point = System.Windows.Point;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;

namespace DeskGuest.SessionAgent;

/// <summary>The companion window's remaining pages (M4). Guardrails
/// carries the two functions that must never move to a tool: the
/// gate approvals and the credential vault, both laptop-UI-only over
/// the authenticated IPC channel, exactly as the old panel had them.</summary>
public partial class MainWindow
{
    // ---------------- Guardrails ----------------

    private UIElement BuildGuardrailsPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Guardrails"));
        stack.Children.Add(Sub("Host-enforced boundaries that cannot be overridden by AI prompts. Defaults follow your full-access grant — what you see here is the policy actually in force, read from the Core."));

        var columns = new Grid();
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var left = new StackPanel();
        left.Children.Add(new TextBlock { Text = "Tool & Capability Policy", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 8) });
        _policyBody = new StackPanel();
        left.Children.Add(_policyBody);
        var leftCard = Card(left);
        leftCard.Margin = new Thickness(0, 0, 7, 14);
        Grid.SetColumn(leftCard, 0);
        columns.Children.Add(leftCard);

        var right = new StackPanel();
        right.Children.Add(new TextBlock { Text = "Approval Gates", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        right.Children.Add(Muted("These action classes stay blocked for every agent until you approve them here. Approvals travel over the authenticated Core channel only — no agent, tool, or file can grant them."));
        var gatesPanel = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        foreach (var gate in PolicyEngine.GatedClasses.OrderBy(g => g, StringComparer.Ordinal))
        {
            var label = GateLabels.TryGetValue(gate, out var friendly) ? friendly : gate;
            var status = new TextBlock { Text = "blocked", Foreground = new SolidColorBrush(Color.FromRgb(0x9E, 0x1F, 0x1F)), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0), FontSize = 12.5 };
            _gateStatus[gate] = status;
            var approve = new Button { Content = "Approve", Style = (Style)FindResource("GhostButton"), Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(12, 2, 4, 2), Tag = gate };
            var revoke = new Button { Content = "Revoke", Style = (Style)FindResource("GhostButton"), Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 2, 0, 2), Tag = gate };
            approve.Click += async (_, _) => await SendGateApprovalAsync(gate, true);
            revoke.Click += async (_, _) => await SendGateApprovalAsync(gate, false);
            // Label + status stacked on the left, buttons on the
            // right: the status must never be pushed off the card
            // (first M4 build had it overflow past the edge).
            var leftStack = new StackPanel { Width = 168, VerticalAlignment = VerticalAlignment.Center };
            leftStack.Children.Add(new TextBlock { Text = label, FontSize = 13.5, TextWrapping = TextWrapping.Wrap });
            status.Margin = new Thickness(0, 1, 0, 0);
            leftStack.Children.Add(status);
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
            row.Children.Add(leftStack);
            row.Children.Add(approve);
            row.Children.Add(revoke);
            gatesPanel.Children.Add(row);
        }
        right.Children.Add(gatesPanel);
        _gateStatusText = Muted("");
        right.Children.Add(_gateStatusText);

        right.Children.Add(new TextBlock { Text = "Credential vault — agent unlock", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 18, 0, 4) });
        right.Children.Add(MutedT("Store your Windows password in this PC's protected vault so an agent can unlock the screen when you ask it to. You type it only in this box, only on this PC.", "It is stored LSA-protected, is never shown again, and no tool can read it back. If you change your Windows password, store the new one here."));
        _vaultPasswordBox = new PasswordBox { Margin = new Thickness(0, 8, 0, 8), Padding = new Thickness(8, 6, 8, 6) };
        right.Children.Add(_vaultPasswordBox);
        var vaultButtons = new StackPanel { Orientation = Orientation.Horizontal };
        var store = new Button { Content = "Store in vault", Style = (Style)FindResource("PrimaryButton") };
        store.Click += async (_, _) => await VaultStoreAsync();
        vaultButtons.Children.Add(store);
        var wipe = new Button { Content = "Wipe vault", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(8, 0, 0, 0) };
        wipe.Click += async (_, _) => await VaultWipeAsync();
        vaultButtons.Children.Add(wipe);
        right.Children.Add(vaultButtons);
        _vaultStatusText = Muted("");
        _vaultStatusText.Margin = new Thickness(0, 6, 0, 0);
        right.Children.Add(_vaultStatusText);

        var rightCard = Card(right);
        rightCard.Margin = new Thickness(7, 0, 0, 14);
        Grid.SetColumn(rightCard, 1);
        columns.Children.Add(rightCard);

        stack.Children.Add(columns);
        RenderPolicy();
        RenderGateStates();
        return stack;
    }

    private void RenderPolicy()
    {
        if (_policyBody is null) return;
        _policyBody.Children.Clear();
        void Row(string name, string detail, string chipText, Color bg, Color fg)
        {
            var row = new StackPanel { Margin = new Thickness(0, 5, 0, 5) };
            var head = new StackPanel { Orientation = Orientation.Horizontal };
            head.Children.Add(new TextBlock { Text = name, FontSize = 14.5, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
            var chip = Chip(chipText, bg, fg);
            chip.Margin = new Thickness(10, 0, 0, 0);
            head.Children.Add(chip);
            row.Children.Add(head);
            row.Children.Add(Muted(detail));
            _policyBody.Children.Add(row);
        }
        Row("Screen vision & UI automation", "The agent sees and drives the desktop only inside a live, visible session.", "Allowed · in session", GreenBg, GreenFg);
        Row("Mouse & keyboard injection", "Your own mouse and keyboard are always yours: using them never interrupts the agent (FR-145). Taking over is deliberate — the Ctrl + Alt + Shift + Backspace chord, or STOP.", "Allowed · coexists with you", GreenBg, GreenFg);
        Row("PowerShell & CLI execution", "Shell scope is part of your full-access grant; sensitive classes still pass the approval gates.", "Allowed · gated classes", BlueBg, BlueFg);
        // FR-113 (W65): the FileSystem row is GENERATED from the
        // Core's effective configured roots (host-state snapshot) —
        // the old hard-coded "Allowed · unscoped" claim is deleted;
        // it contradicted the staging confinement actually in force.
        var fileLabel = DeskGuest.Shared.Files.FileRootsLabel.Generate(_host?.FileRoots);
        Row("FileSystem access", fileLabel.Detail, fileLabel.Chip, GreenBg, GreenFg);
        // FR-115 (W65): registry_set now carries GateClass
        // "registry_write" and registry_delete GateClass "deletions"
        // (both fail closed in PolicyEngine until the owner approves
        // the class) — the label below now matches the behaviour.
        Row("Windows Registry", "Registry changes are gated by policy under your grant: setting a value needs the registry-write approval, deleting needs the deletions approval — never silently open, never hard-blocked.", "Gated by policy", BlueBg, BlueFg);
        Row("User STOP", "STOP ends the session and blocks every agent until you clear it. No agent action can lift it.", "Always on", GreenBg, GreenFg);
        Row("Presence", "Glow, presence box, and ghost cursor are on for the whole session. An agent cannot dim or hide them.", "Always visible", GreenBg, GreenFg);
        if (_host is not null)
        {
            foreach (var (id, pname, scopes, revoked) in _host.Pairings)
            {
                if (revoked) continue;
                Row($"Pairing — {pname}", $"Scopes in force: {string.Join(", ", scopes)}", ScopeSummary(scopes), GrayBg, GrayFg);
            }
        }
    }

    private void RenderGateStates()
    {
        if (_host is null) return;
        foreach (var (id, approved) in _host.Gates)
        {
            if (_gateStatus.TryGetValue(id, out var status))
            {
                status.Text = approved ? "approved" : "blocked";
                status.Foreground = new SolidColorBrush(approved ? Color.FromRgb(0x14, 0x6B, 0x33) : Color.FromRgb(0x9E, 0x1F, 0x1F));
            }
        }
    }

    private async Task SendGateApprovalAsync(string gate, bool approved)
    {
        var sender = _gateApprovalSender;
        if (sender is null)
        {
            if (_gateStatusText is not null) _gateStatusText.Text = "Not connected to the Core — the approval was NOT sent.";
            return;
        }
        var sent = await sender(gate, approved);
        if (sent)
        {
            if (_gateStatus.TryGetValue(gate, out var status))
            {
                status.Text = approved ? "approved (sent to Core)" : "blocked";
                status.Foreground = new SolidColorBrush(approved ? Color.FromRgb(0x14, 0x6B, 0x33) : Color.FromRgb(0x9E, 0x1F, 0x1F));
            }
            if (_gateStatusText is not null)
                _gateStatusText.Text = approved
                    ? $"'{gate}' approved. Agents may use this class until you revoke it or the Core restarts."
                    : $"'{gate}' blocked again.";
            _ = RequestHostStateAsync();
        }
        else if (_gateStatusText is not null)
        {
            _gateStatusText.Text = "Not connected to the Core — the approval was NOT sent.";
        }
    }

    private async Task VaultStoreAsync()
    {
        if (_vaultPasswordBox is null || _vaultStatusText is null) return;
        var password = _vaultPasswordBox.Password;
        _vaultPasswordBox.Clear();
        if (string.IsNullOrEmpty(password))
        {
            _vaultStatusText.Text = "Type your Windows password in the box first.";
            return;
        }
        var sender = _vaultSetSender;
        if (sender is null)
        {
            _vaultStatusText.Text = "Not connected to the Core — the password was NOT stored.";
            return;
        }
        _vaultStatusText.Text = "Sending to the Core…";
        var sent = await sender(password);
        _vaultStatusText.Text = sent
            ? "Sent to the Core. Its vault-state report appears here when it has stored it."
            : "Not connected to the Core — the password was NOT stored.";
    }

    private async Task VaultWipeAsync()
    {
        if (_vaultStatusText is null) return;
        _vaultPasswordBox?.Clear();
        var sender = _vaultWipeSender;
        if (sender is null)
        {
            _vaultStatusText.Text = "Not connected to the Core — the vault was NOT wiped.";
            return;
        }
        var sent = await sender();
        _vaultStatusText.Text = sent
            ? "Wipe sent to the Core. Its vault-state report appears here."
            : "Not connected to the Core — the vault was NOT wiped.";
    }

    /// <summary>The Core's vault-state report, shown verbatim on the
    /// Guardrails page (a state name only — never the credential).</summary>
    public void SetVaultStatus(string text)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetVaultStatus(text)); return; }
        if (_vaultStatusText is not null) _vaultStatusText.Text = text;
    }

    // ---------------- Audit Log ----------------

    private UIElement BuildAuditPage()
    {
        var stack = new StackPanel();
        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titleStack = new StackPanel();
        // W65 / Core-5: name of record is "Activity Record"
        // ("Audit Log" only as the IT parenthetical).
        titleStack.Children.Add(PageTitle("Activity Record"));
        titleStack.Children.Add(Sub("Append-only local ledger (Audit Log) · kept on this PC · arguments are redacted before they are written. This record lives on this device. It can't be edited or quietly deleted — entries only expire by the rule you set in Settings. Session records stay on this device. Nothing in this record is sent anywhere unless you export it."));
        head.Children.Add(titleStack);
        var export = new Button { Content = "Export shown entries (JSON)", Style = (Style)FindResource("PrimaryButton"), VerticalAlignment = VerticalAlignment.Top };
        export.Click += (_, _) => ExportAudit();
        Grid.SetColumn(export, 1);
        head.Children.Add(export);
        stack.Children.Add(head);
        _auditSummary = Muted("");
        stack.Children.Add(_auditSummary);
        _auditBody = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        stack.Children.Add(Card(_auditBody));
        RenderAudit();
        return stack;
    }

    private void RenderAudit()
    {
        if (_auditBody is null || _auditSummary is null) return;
        _auditBody.Children.Clear();
        if (_host is null)
        {
            _auditBody.Children.Add(Muted("Waiting for the Core's snapshot…"));
            return;
        }
        var blocked = _host.Audit.Count(a => a.Outcome.StartsWith("denied", StringComparison.Ordinal) || a.Outcome == "gated");
        _auditSummary.Text = $"{_host.SessionActions} action{(_host.SessionActions == 1 ? "" : "s")} in current session · {blocked} blocked in the {_host.Audit.Count} entries shown";
        foreach (var entry in _host.Audit.AsEnumerable().Reverse())
        {
            var (at, agent, tool, operation, outcome, ms) = entry;
            var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var texts = new StackPanel();
            texts.Children.Add(Muted($"{at.ToLocalTime():h:mm:ss tt} · {tool ?? operation ?? "system"} · {agent ?? "host"}", 12));
            texts.Children.Add(new TextBlock { Text = DescribeAudit(entry), FontSize = 14, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            row.Children.Add(texts);
            var (chipText, bg, fg) = OutcomeChip(outcome, ms);
            var chip = Chip(chipText, bg, fg);
            chip.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(chip, 1);
            row.Children.Add(chip);
            _auditBody.Children.Add(row);
        }
        if (_host.Audit.Count == 0)
            _auditBody.Children.Add(Muted("No audit entries yet in the current snapshot."));
    }

    private static string DescribeAudit((DateTimeOffset At, string? Agent, string? Tool, string? Operation, string Outcome, long? Ms) e)
    {
        if (e.Tool is not null) return e.Operation is not null ? $"{e.Tool} — {e.Operation}" : e.Tool;
        return e.Outcome;
    }

    private static (string, Color, Color) OutcomeChip(string outcome, long? ms)
    {
        var suffix = ms is not null ? $" · {ms}ms" : "";
        if (outcome == "executed") return ($"Verified{suffix}", GreenBg, GreenFg);
        if (outcome.StartsWith("denied", StringComparison.Ordinal)) return ("Blocked", RedBg, RedFg);
        if (outcome == "gated") return ("Gated — needs approval", RedBg, RedFg);
        if (outcome.StartsWith("error", StringComparison.Ordinal)) return ($"Error{suffix}", RedBg, RedFg);
        return (outcome + suffix, GrayBg, GrayFg);
    }

    private void ExportAudit()
    {
        if (_host is null) return;
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"deskguest-audit-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
            Title = "Export audit entries"
        };
        if (dialog.ShowDialog(this) != true) return;
        var entries = _host.Audit.Select(e => new
        {
            atUtc = e.At, agent = e.Agent, tool = e.Tool, operation = e.Operation, outcome = e.Outcome, durationMs = e.Ms
        });
        File.WriteAllText(dialog.FileName, System.Text.Json.JsonSerializer.Serialize(entries, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }

    // ---------------- Presence page ----------------
    // FR-105 (W85): the page IS the presence customizer now — the
    // pre-directive "colours are meanings… not a setting" copy is
    // gone. One page for the whole presence system: the mode
    // toggle at top (Helping on screen / Background Work Only)
    // switches the page's context; the preview is ALWAYS visible
    // and renders every state through PillVisual/GhostVisual —
    // the same composition code the real Box and Ghost use — in
    // the UNSAVED working scheme; saving writes through
    // PresencePalette.SetScheme, the palette being the only
    // settings home (the W73 write-path pattern). Background Work
    // Only MODE is a V2 item: this page customizes its indicator's
    // appearance and says plainly that the mode itself is not in
    // this version yet — it never fakes a working mode. The W73
    // "Taking back control" section below is integrated as-is.
    private PresenceScheme? _w85Working;
    private bool _w85BgContext;
    private StackPanel? _w85PreviewBody;
    private StackPanel? _w85ControlsBody;
    private TextBlock? _w85Warn;
    private TextBlock? _w85Saved;
    private System.Windows.Controls.Button? _w85ModeNormalBtn;
    private System.Windows.Controls.Button? _w85ModeBgBtn;

    private static readonly int[] W85Swatches =
    {
        unchecked((int)0xFF7C4DFF), unchecked((int)0xFF2FA84F),
        unchecked((int)0xFFF2A900), unchecked((int)0xFFDC2626),
        unchecked((int)0xFF2F8BC9), unchecked((int)0xFF4E9A94),
        unchecked((int)0xFFE5A93B), unchecked((int)0xFFE56399),
        unchecked((int)0xFFF4F4F6), unchecked((int)0xFF14141C),
    };

    private static Color W85Color(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    private TextBlock W85Section(string text) => new()
    {
        Text = text, Style = (Style)FindResource("SectionLabel"),
        Margin = new Thickness(0, 14, 0, 4),
    };

    private string W85PreviewName()
    {
        var vs = _presence?.ViewState;
        if (vs is not null && vs.Value.SessionActive && !string.IsNullOrWhiteSpace(vs.Value.DisplayName))
            return vs.Value.DisplayName;
        var pairing = _host?.Pairings.FirstOrDefault(
            x => !x.Revoked && !string.IsNullOrWhiteSpace(x.Name));
        return pairing is not null && !string.IsNullOrWhiteSpace(pairing.Value.Name)
            ? pairing.Value.Name : Strings.Get("PresencePreviewNameFallback");
    }

    private void StyleW85Toggle()
    {
        if (_w85ModeNormalBtn is null || _w85ModeBgBtn is null) return;
        _w85ModeNormalBtn.Style = (Style)FindResource(_w85BgContext ? "GhostButton" : "PrimaryButton");
        _w85ModeBgBtn.Style = (Style)FindResource(_w85BgContext ? "PrimaryButton" : "GhostButton");
    }

    private void RefreshW85Preview()
    {
        if (_w85PreviewBody is null || _w85Working is null) return;
        var w = _w85Working;
        _w85PreviewBody.Children.Clear();
        var name = W85PreviewName();
        if (!_w85BgContext)
        {
            var states = new[]
            {
                (PresenceLaw.Actor.Ai, "PresenceStateAi", ""),
                (PresenceLaw.Actor.Human, "PresenceStatePerson", "PresenceYoureDriving"),
                (PresenceLaw.Actor.Idle, "PresenceStateWaiting", "PresenceIdle"),
            };
            foreach (var (actor, labelKey, sentenceKey) in states)
            {
                _w85PreviewBody.Children.Add(Muted(Strings.Get(labelKey), 12));
                var ringArgb = actor == PresenceLaw.Actor.Ai && !w.IsCustomized
                    ? PresenceLaw.PillTrimGold : w.ColorFor(actor);
                var scale = w.SizePct / 100.0;
                // W117 / F2: the preview's branch sentences come
                // from the same one home as the real pill's
                // (BranchSentence — every branch names the agent);
                // W117 / F1: the preview pill takes the same
                // required height the real pill would.
                var sentence = actor switch
                {
                    PresenceLaw.Actor.Human => PresenceComposition.BranchSentence(
                        PresenceComposition.PresenceBranch.OwnerDriving, name),
                    PresenceLaw.Actor.Idle => PresenceComposition.BranchSentence(
                        PresenceComposition.PresenceBranch.Waiting, name),
                    _ => "",
                };
                var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 2) };
                var pill = new Border
                {
                    Background = new SolidColorBrush(W85Color(PresenceLaw.PillBackground)),
                    CornerRadius = new CornerRadius((w.Detail == PresenceDetail.CompactPill ? 32 : 44) * scale),
                    BorderBrush = new SolidColorBrush(W85Color(ringArgb)),
                    BorderThickness = new Thickness(2),
                    Padding = new Thickness(11, 11, 14, 11),
                    Height = PillVisual.HeightFor(w, actor, name, sentence),
                    VerticalAlignment = VerticalAlignment.Center,
                    Child = PillVisual.BuildPillContent(w, actor, name,
                        sentence,
                        PillVisual.CreateStopButton(w, interactive: false), W85Color(ringArgb)),
                };
                row.Children.Add(pill);
                var ghost = GhostVisual.Build(PointerStyles.ById(w.PointerStyleId),
                    w.ColorFor(actor), PresenceLaw.GhostInitial(name), scale);
                ghost.Margin = new Thickness(14, 0, 0, 0);
                ghost.VerticalAlignment = VerticalAlignment.Center;
                row.Children.Add(ghost);
                _w85PreviewBody.Children.Add(row);
                _w85PreviewBody.Children.Add(new Border
                {
                    Height = 8, CornerRadius = new CornerRadius(4),
                    Background = new SolidColorBrush(W85Color(w.ColorFor(actor))),
                    Opacity = w.BrightnessPct / 100.0,
                    Width = 320, HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(2, 2, 0, 10),
                });
            }
        }
        else
        {
            var bgScale = w.BgSizePct / 100.0;
            var indicator = new Border
            {
                Background = (Brush)FindResource("DgSurfaceBrush"),
                BorderBrush = new SolidColorBrush(W85Color(w.BgArgb)),
                BorderThickness = new Thickness(1.5),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(14),
                Opacity = w.BgBrightnessPct / 100.0,
                HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 4, 0, 4),
            };
            var line = new StackPanel { Orientation = Orientation.Horizontal };
            line.Children.Add(new Ellipse
            {
                Width = 12 * bgScale, Height = 12 * bgScale,
                Fill = new SolidColorBrush(W85Color(w.BgArgb)),
                VerticalAlignment = VerticalAlignment.Center,
            });
            line.Children.Add(new TextBlock
            {
                Text = Strings.Format("PresenceBgPreviewFormat", name),
                FontSize = 14.5 * bgScale,
                Foreground = (Brush)FindResource("DgTextBrush"),
                Margin = new Thickness(10, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
            });
            indicator.Child = line;
            _w85PreviewBody.Children.Add(indicator);
        }
        if (_w85Warn is not null)
        {
            var check = PresenceScheme.Validate(w);
            var notes = check.Errors.Concat(check.Warnings).ToList();
            _w85Warn.Text = string.Join(" ", notes);
            _w85Warn.Visibility = notes.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    private StackPanel W85SliderRow(string label, double min, double max, double value, Action<int> set)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 5) };
        var valueText = new TextBlock
        {
            Text = $"{(int)value}%", Width = 44,
            Foreground = (Brush)FindResource("DgTextBrush"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        var slider = new Slider
        {
            Minimum = min, Maximum = max, Value = value, Width = 280,
            VerticalAlignment = VerticalAlignment.Center,
        };
        slider.ValueChanged += (_, e) =>
        {
            set((int)e.NewValue);
            valueText.Text = $"{(int)e.NewValue}%";
            RefreshW85Preview();
        };
        row.Children.Add(new TextBlock
        {
            Text = label, Width = 150,
            Foreground = (Brush)FindResource("DgMutedBrush"),
            FontSize = 13.5, VerticalAlignment = VerticalAlignment.Center,
        });
        row.Children.Add(slider);
        row.Children.Add(valueText);
        return row;
    }

    private StackPanel W85SwatchRow(string label, int currentArgb, Action<int> pick)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 5) };
        row.Children.Add(new TextBlock
        {
            Text = label, Width = 150,
            Foreground = (Brush)FindResource("DgMutedBrush"),
            FontSize = 13.5, VerticalAlignment = VerticalAlignment.Center,
        });
        var panel = new WrapPanel();
        foreach (var swatch in W85Swatches)
        {
            var selected = swatch == currentArgb;
            var b = new System.Windows.Controls.Button
            {
                Width = 28, Height = 28, Margin = new Thickness(3),
                Background = new SolidColorBrush(W85Color(swatch)),
                BorderBrush = (Brush)FindResource(selected ? "DgBlueBrush" : "DgBorderBrush"),
                BorderThickness = new Thickness(selected ? 3 : 1),
                Cursor = System.Windows.Input.Cursors.Hand,
                ToolTip = $"#{swatch & 0xFFFFFF:X6}",
            };
            var captured = swatch;
            b.Click += (_, _) => { pick(captured); RefreshW85Controls(); RefreshW85Preview(); };
            panel.Children.Add(b);
        }
        row.Children.Add(panel);
        return row;
    }

    private void RefreshW85Controls()
    {
        if (_w85ControlsBody is null || _w85Working is null) return;
        var w = _w85Working;
        _w85ControlsBody.Children.Clear();
        if (!_w85BgContext)
        {
            _w85ControlsBody.Children.Add(W85SliderRow(Strings.Get("PresenceSizeLabel"), 60, 160, w.SizePct,
                v => _w85Working = w with { SizePct = v }));
            _w85ControlsBody.Children.Add(W85SliderRow(Strings.Get("PresenceBrightnessLabel"), 40, 100, w.BrightnessPct,
                v => _w85Working = w with { BrightnessPct = v }));
            var detailRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 5) };
            detailRow.Children.Add(new TextBlock
            {
                Text = Strings.Get("PresenceDetailLabel"), Width = 150,
                Foreground = (Brush)FindResource("DgMutedBrush"),
                FontSize = 13.5, VerticalAlignment = VerticalAlignment.Center,
            });
            var detail = new System.Windows.Controls.ComboBox
            {
                Width = 200,
                ItemsSource = new[] { Strings.Get("PresenceDetailFull"), Strings.Get("PresenceDetailCompact") },
                SelectedIndex = w.Detail == PresenceDetail.CompactPill ? 1 : 0,
            };
            detail.SelectionChanged += (_, _) =>
            {
                _w85Working = _w85Working! with
                {
                    Detail = detail.SelectedIndex == 1 ? PresenceDetail.CompactPill : PresenceDetail.Full,
                };
                RefreshW85Preview();
            };
            detailRow.Children.Add(detail);
            _w85ControlsBody.Children.Add(detailRow);
            _w85ControlsBody.Children.Add(W85Section(Strings.Get("PresenceColorsTitle")));
            _w85ControlsBody.Children.Add(W85SwatchRow(Strings.Get("PresenceColorAi"), w.AiArgb,
                c => _w85Working = _w85Working! with { AiArgb = c }));
            _w85ControlsBody.Children.Add(W85SwatchRow(Strings.Get("PresenceColorPerson"), w.HumanArgb,
                c => _w85Working = _w85Working! with { HumanArgb = c }));
            _w85ControlsBody.Children.Add(W85SwatchRow(Strings.Get("PresenceColorWaiting"), w.WaitingArgb,
                c => _w85Working = _w85Working! with { WaitingArgb = c }));
            _w85ControlsBody.Children.Add(W85SwatchRow(Strings.Get("PresenceColorStop"), w.StopArgb,
                c => _w85Working = _w85Working! with { StopArgb = c }));
            _w85ControlsBody.Children.Add(W85Section(Strings.Get("PresencePointerTitle")));
            _w85ControlsBody.Children.Add(Muted(Strings.Get("PresencePointerNote")));
            var gallery = new WrapPanel { Margin = new Thickness(0, 4, 0, 4) };
            foreach (var style in PointerStyles.All)
            {
                var selected = style.Id == w.PointerStyleId;
                var cell = new System.Windows.Controls.Button
                {
                    Width = 66, Height = 66, Margin = new Thickness(3), Padding = new Thickness(0),
                    Background = (Brush)FindResource("DgSurfaceBrush"),
                    BorderBrush = (Brush)FindResource(selected ? "DgBlueBrush" : "DgBorderBrush"),
                    BorderThickness = new Thickness(selected ? 3 : 1),
                    Cursor = System.Windows.Input.Cursors.Hand,
                    ToolTip = style.DisplayName,
                    Content = GhostVisual.Build(style, w.AiArgb, "A"),
                };
                var id = style.Id;
                cell.Click += (_, _) =>
                {
                    _w85Working = _w85Working! with { PointerStyleId = id };
                    RefreshW85Controls();
                    RefreshW85Preview();
                };
                gallery.Children.Add(cell);
            }
            _w85ControlsBody.Children.Add(gallery);
            var breath = new CheckBox
            {
                Content = Strings.Get("ComfortGlowBreath"),
                IsChecked = PresencePalette.Load().BreathEnabled,
                Foreground = (Brush)FindResource("DgTextBrush"),
                FontSize = 13.5,
                Margin = new Thickness(0, 8, 0, 2),
            };
            breath.Click += (_, _) =>
            {
                var p = PresencePalette.Load();
                p.BreathEnabled = breath.IsChecked == true;
                p.Save();
            };
            _w85ControlsBody.Children.Add(breath);
        }
        else
        {
            _w85ControlsBody.Children.Add(Muted(Strings.Get("PresenceBgNote")));
            _w85ControlsBody.Children.Add(W85SwatchRow(Strings.Get("PresenceBgColor"), w.BgArgb,
                c => _w85Working = _w85Working! with { BgArgb = c }));
            _w85ControlsBody.Children.Add(W85SliderRow(Strings.Get("PresenceSizeLabel"), 60, 160, w.BgSizePct,
                v => _w85Working = _w85Working! with { BgSizePct = v }));
            _w85ControlsBody.Children.Add(W85SliderRow(Strings.Get("PresenceBrightnessLabel"), 40, 100, w.BgBrightnessPct,
                v => _w85Working = _w85Working! with { BgBrightnessPct = v }));
        }
    }

    private UIElement BuildPresencePage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle(Strings.Get("PresenceTitle")));
        stack.Children.Add(Sub(Strings.Get("PresenceSub")));
        stack.Children.Add(Muted(Strings.Get("PresenceFloorSentence")));
        _w85Working = PresencePalette.Load().Scheme;
        _w85BgContext = false;
        var toggle = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 12, 0, 4) };
        _w85ModeNormalBtn = new System.Windows.Controls.Button
        {
            Content = Strings.Get("PresenceModeNormal"),
            Style = (Style)FindResource("PrimaryButton"),
        };
        _w85ModeBgBtn = new System.Windows.Controls.Button
        {
            Content = Strings.Get("PresenceModeBackground"),
            Style = (Style)FindResource("GhostButton"),
            Margin = new Thickness(8, 0, 0, 0),
        };
        _w85ModeNormalBtn.Click += (_, _) =>
        {
            _w85BgContext = false; StyleW85Toggle(); RefreshW85Controls(); RefreshW85Preview();
        };
        _w85ModeBgBtn.Click += (_, _) =>
        {
            _w85BgContext = true; StyleW85Toggle(); RefreshW85Controls(); RefreshW85Preview();
        };
        toggle.Children.Add(_w85ModeNormalBtn);
        toggle.Children.Add(_w85ModeBgBtn);
        stack.Children.Add(toggle);
        _w85PreviewBody = new StackPanel();
        _w85Warn = new TextBlock
        {
            Foreground = (Brush)FindResource("DgRedBrush"),
            FontSize = 12.5, TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed, Margin = new Thickness(0, 6, 0, 0),
        };
        var previewCardBody = new StackPanel();
        previewCardBody.Children.Add(W85Section(Strings.Get("PresencePreviewTitle")));
        previewCardBody.Children.Add(_w85PreviewBody);
        previewCardBody.Children.Add(_w85Warn);
        stack.Children.Add(Card(previewCardBody));
        _w85ControlsBody = new StackPanel();
        stack.Children.Add(Card(_w85ControlsBody));
        var saveRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 6) };
        var save = new System.Windows.Controls.Button
        {
            Content = Strings.Get("PresenceSave"),
            Style = (Style)FindResource("PrimaryButton"),
        };
        save.Click += (_, _) =>
        {
            if (_w85Working is null) return;
            var check = PresenceScheme.Validate(_w85Working);
            if (check.Errors.Count > 0)
            {
                if (_w85Warn is not null)
                {
                    _w85Warn.Text = string.Join(" ", check.Errors);
                    _w85Warn.Visibility = Visibility.Visible;
                }
                return;
            }
            PresencePalette.Load().SetScheme(_w85Working);
            if (_w85Saved is not null) _w85Saved.Text = Strings.Get("PresenceSaved");
        };
        var reset = new System.Windows.Controls.Button
        {
            Content = Strings.Get("PresenceReset"),
            Style = (Style)FindResource("GhostButton"),
            Margin = new Thickness(8, 0, 0, 0),
        };
        reset.Click += (_, _) =>
        {
            _w85Working = PresenceScheme.Default;
            RefreshW85Controls();
            RefreshW85Preview();
        };
        _w85Saved = new TextBlock
        {
            Foreground = (Brush)FindResource("DgMutedBrush"),
            FontSize = 12.5, VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0),
        };
        saveRow.Children.Add(save);
        saveRow.Children.Add(reset);
        saveRow.Children.Add(_w85Saved);
        stack.Children.Add(saveRow);
        RefreshW85Controls();
        RefreshW85Preview();
        // The sections below (W73 "Taking back control", the
        // consent floor, the self-test, event watches, Keyboard
        // STOP) keep their long-standing single-card home at the
        // foot of this page — integrated, not duplicated.
        var palette = PresencePalette.Load();
        var body = new StackPanel();
        // FR-120 (W73): "Taking back control" — the settings home
        // for the tunable takeover modes, in this page's language.
        // Two independent selectors (Mouse / Keyboard), each with
        // its one plain sentence. A change saves through
        // PresencePalette.SetTakeoverModes — the ONLY write path
        // (this device's own UI); it applies immediately, mid-
        // session included, and the presence layer records it.
        body.Children.Add(new TextBlock { Text = Strings.Get("TakeoverGroupTitle"), FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 16, 0, 4) });
        body.Children.Add(Muted(Strings.Get("TakeoverGroupIntro"), 12));
        var modeNames = new[]
        {
            (DeskGuest.Shared.Presence.TakeoverMode.TakeOver, Strings.Get("TakeoverModeTakeOver"), Strings.Get("TakeoverModeTakeOverSentence")),
            (DeskGuest.Shared.Presence.TakeoverMode.Share, Strings.Get("TakeoverModeShare"), Strings.Get("TakeoverModeShareSentence")),
            (DeskGuest.Shared.Presence.TakeoverMode.HotkeyOnly, Strings.Get("TakeoverModeHotkeyOnly"), Strings.Get("TakeoverModeHotkeyOnlySentence")),
        };
        System.Windows.Controls.ComboBox ModeSelector(DeskGuest.Shared.Presence.TakeoverMode current, TextBlock sentence)
        {
            var box = new System.Windows.Controls.ComboBox { Width = 320, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 2) };
            foreach (var (mode, name, _) in modeNames) box.Items.Add(name);
            box.SelectedIndex = Array.FindIndex(modeNames, m => m.Item1 == current);
            sentence.Text = modeNames[box.SelectedIndex].Item3;
            return box;
        }
        var mouseSentence = Muted("", 12);
        var keyboardSentence = Muted("", 12);
        var mouseBox = ModeSelector(palette.ActiveMouseTakeoverMode, mouseSentence);
        var keyboardBox = ModeSelector(palette.ActiveKeyboardTakeoverMode, keyboardSentence);
        void SaveTakeoverModes()
        {
            var p = PresencePalette.Load();
            p.SetTakeoverModes(modeNames[mouseBox.SelectedIndex].Item1, modeNames[keyboardBox.SelectedIndex].Item1);
            mouseSentence.Text = modeNames[mouseBox.SelectedIndex].Item3;
            keyboardSentence.Text = modeNames[keyboardBox.SelectedIndex].Item3;
        }
        mouseBox.SelectionChanged += (_, _) => { if (mouseBox.SelectedIndex >= 0 && keyboardBox.SelectedIndex >= 0) SaveTakeoverModes(); };
        keyboardBox.SelectionChanged += (_, _) => { if (mouseBox.SelectedIndex >= 0 && keyboardBox.SelectedIndex >= 0) SaveTakeoverModes(); };
        body.Children.Add(new TextBlock { Text = Strings.Get("TakeoverMouseLabel"), FontSize = 13.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 2) });
        body.Children.Add(mouseBox);
        body.Children.Add(mouseSentence);
        body.Children.Add(new TextBlock { Text = Strings.Get("TakeoverKeyboardLabel"), FontSize = 13.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 2) });
        body.Children.Add(keyboardBox);
        body.Children.Add(keyboardSentence);
        body.Children.Add(new TextBlock { Text = Strings.Get("FloorBoxTitle"), FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 16, 0, 4) });
        foreach (var item in DeskGuest.Shared.Design.HostHomeModel.ConsentFloorItems)
            body.Children.Add(Muted("· " + item));

        var selfTest = new Button { Content = "Run presence self-test", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 16, 0, 0) };
        var selfTestText = Muted("", 12.5);
        selfTest.Click += (_, _) =>
        {
            if (_presence is null) { selfTestText.Text = "Presence layer not attached yet."; return; }
            var result = _presence.RunSelfTest();
            selfTestText.Text = result.Passed
                ? Strings.Get("PresenceSelfTestPassed")
                : Strings.Format("PresenceSelfTestFailedFormat", string.Join("; ", result.Failures));
        };
        body.Children.Add(selfTest);
        body.Children.Add(selfTestText);
        body.Children.Add(Muted("The self-test also runs by itself before any session is accepted — a failed draw blocks the session.", 12));

        body.Children.Add(new TextBlock { Text = Strings.Get("EventWatchesTitle"), FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 16, 0, 4) });
        if (_host is null)
            body.Children.Add(Muted("Waiting for the Core's snapshot…", 12));
        else if (_host.EventWatches.Count == 0)
            body.Children.Add(Muted(DeskGuest.Shared.Design.EventWatchLines.EmptyLine(), 12));
        else
        {
            var watches = _host.EventWatches
                .Select(w => new DeskGuest.Shared.Sessions.EventWatch(w.PairingId,
                    new HashSet<string>(w.Kinds), w.ExpiresUtc)).ToList();
            foreach (var line in DeskGuest.Shared.Design.EventWatchLines.Lines(watches))
                body.Children.Add(Muted("· " + line, 12));
        }
        body.Children.Add(new TextBlock { Text = "Keyboard STOP", FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 16, 0, 4) });
        body.Children.Add(Muted(Strings.Get("KeyboardStopUnassigned"), 12));
        stack.Children.Add(Card(body));
        return stack;
    }


    // ---------------- Updates ----------------

    private UIElement BuildUpdatesPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Updates"));
        stack.Children.Add(Sub("How this PC's host software gets new versions — stated plainly, because there is no silent updater here."));
        var body = new StackPanel();
        body.Children.Add(new TextBlock { Text = $"Session agent {typeof(MainWindow).Assembly.GetName().Version}", FontSize = 16, FontWeight = FontWeights.SemiBold });
        body.Children.Add(Muted(_host is null ? "Core version: waiting for the Core's snapshot." : $"Core {_host.CoreVersion}"));
        body.Children.Add(new TextBlock
        {
            Text = "Windows host builds are delivered as signed packages and installed deliberately — nothing downloads or installs itself in the background.", ToolTip = "Builds arrive through the DeskGuest release process, and no update ever changes your pairings or settings. The Android app updates itself from the public releases repo (signed manifest, verified on the phone).",
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0)
        });
        body.Children.Add(MutedT("Enterprise policy gate: an update version the policy pins or defers is refused before anything is installed.", "When a policy bundle is loaded in the Core, the refusal happens at staging time — before signature work, before anything is extracted. The Enterprise page shows the live policy state and can check a version against it.", 12.5));
        stack.Children.Add(Card(body));
        return stack;
    }

    // ---------------- Settings ----------------

    private UIElement BuildSettingsPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Settings"));
        stack.Children.Add(Sub("This host's local facts and files. Presence comfort lives on the Presence page."));
        var body = new StackPanel();
        void Fact(string label, string value)
        {
            body.Children.Add(new TextBlock { Text = label, FontSize = 12, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)), FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 2) });
            body.Children.Add(new TextBlock { Text = value, FontSize = 13.5, TextWrapping = TextWrapping.Wrap });
        }
        var dataDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DeskGuest");
        Fact("Agent data folder", dataDir);
        var open = new Button { Content = "Open data folder", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
        open.Click += (_, _) => { try { Process.Start("explorer.exe", dataDir); } catch { } };
        body.Children.Add(open);
        Fact("Presence comfort file", PresencePalette.FilePath);
        Fact("Logon start", "The companion starts at logon (scheduled task “DeskGuest Session Agent”). The Core runs as a Windows service.");
        Fact("Switching access off", "The desktop shortcuts (DeskGuest-ON / DeskGuest-OFF) start and stop the whole host. STOP in this window blocks agents without stopping the host.");
        stack.Children.Add(Card(body));
        // W65 / Core-6 (S20 index): every settings area is named
        // here with the page that owns it — no setting hides.
        var index = new StackPanel();
        index.Children.Add(new TextBlock { Text = "Settings index", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        index.Children.Add(Muted("Presence & STOP appearance — on the Presence page: how the box, glow, and ghost look. You can change how it looks in every way — it just can't disappear while someone is here, and STOP is always STOP."));
        // W79 / S08: the Settings index entry IS a door to the
        // access-control surface (the same page the Home agent
        // card opens) — the index names it and takes you there.
        var accessDoor = new Button
        {
            Content = "My AI helpers' access — who is paired, what each helper may do, and the access level you granted. Open the access controls →",
            Style = (Style)FindResource("GhostButton"), FontSize = 12.5,
            HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 2),
        };
        accessDoor.Click += (_, _) => { _accessSignature = ""; ShowPage("agentdetail"); RenderAgentAccess(); };
        index.Children.Add(accessDoor);
        index.Children.Add(Muted("Connection paths — on the Devices page, per helper: which path a connection may take. DeskGuest will never quietly use a path you turned off."));
        index.Children.Add(Muted("Activity Record keeping — the record lives on this device and can't be edited or quietly deleted; entries expire only by the retention rule in force."));
        index.Children.Add(Muted("Cameras & policies — on the Company and Services pages: camera sharing and every policy toggle, each with its current state."));
        index.Children.Add(Muted("Always true — presence is always visible during a session, STOP always works, and the Activity Record can't be quietly edited. No setting changes these."));
        stack.Children.Add(Card(index));
        // C20 wiring: the owner-local recovery blob surface.
        stack.Children.Add(BuildRecoverySection());
        return stack;
    }

    // ---------------- About ----------------

    private UIElement BuildAboutPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("About"));
        stack.Children.Add(Sub("DeskGuest — the remote-access host for this PC."));
        try
        {
            var lockup = new System.Windows.Media.Imaging.BitmapImage(
                new System.Uri("pack://application:,,,/deskguest-lockup.png"));
            stack.Children.Add(new System.Windows.Controls.Image
            {
                Source = lockup, Height = 120, HorizontalAlignment = HorizontalAlignment.Left,
                Margin = new Thickness(0, 4, 0, 8)
            });
        }
        catch { /* the wordmark is decoration on About; its absence never blanks the page */ }
        var body = new StackPanel();
        body.Children.Add(new TextBlock
        {
            Text = "A remote control platform with consent at its core: an agent can only work inside a visible session — glow, presence box, ghost cursor — and you can stop it instantly, from the box, this window, or the tray.",
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap
        });
        body.Children.Add(new TextBlock
        {
            Text = "Free forever — no paid tier, no account, no telemetry, no vendor cloud. Everything runs on your own machines and your own mesh.",
            FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0)
        });
        body.Children.Add(Muted($"Session agent {typeof(MainWindow).Assembly.GetName().Version}" + (_host is null ? "" : $" · Core {_host.CoreVersion}"), 12));
        stack.Children.Add(Card(body));

        // W65 / Core-7 (S22): Help Center sections ride the Help
        // page — Getting Started / Troubleshooting / Plain-language
        // guide, plus the uh-oh promise in the L9 shape.
        var help = new StackPanel();
        help.Children.Add(new TextBlock { Text = "Help Center", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        help.Children.Add(Muted("Getting Started — pairing happens here, on this PC: create a pairing code on the Home page, give it only to someone you trust, and watch the session appear with the presence box, glow, and ghost cursor. STOP always works."));
        help.Children.Add(Muted("Troubleshooting — if a helper cannot connect, check the Home page: the Core must read Running, the desktop must be unlocked, and no STOP may be in force. Desktop tools report unavailable on a locked desktop — never faked."));
        help.Children.Add(Muted("Plain-language guide — Presence is how you always know who is here: the box at the top of the screen names who is controlling this computer, the glow marks the screen they are using, and the ghost pointer is their hand. The Activity Record keeps what happened, on this device only."));
        help.Children.Add(Muted("When something goes wrong, DeskGuest says what happened in plain words, what it means, and the one next action to take. To report a problem today, use the report form on the DeskGuest website (deskguest.app/report). Reporting from inside the app is in development: when it arrives, the report will be built from what happened on this device, with passwords, keys, and tokens scrubbed before anything is attached — and nothing will be sent until you tap Send."));
        stack.Children.Add(Card(help));
        return stack;
    }

    // ---------------- Keyboard STOP (OI-05) ----------------
    // Ctrl+Alt+End is REJECTED by the design of record (it is the
    // RDP client's Ctrl+Alt+Del chord); Ctrl+Shift+Esc and
    // Ctrl+Alt+F12 are likewise rejected. The law: the Box STOP is
    // the floor; a hotkey is a convenience whose default is chosen
    // by the reserved-shortcut fixture (OS + RDP + GPU/OEM + common
    // apps). Until that fixture runs, NO default chord is claimed
    // and none is registered. The Presence page states exactly
    // that (Strings KeyboardStopUnassigned).
}

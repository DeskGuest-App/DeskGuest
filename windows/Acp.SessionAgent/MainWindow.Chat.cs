using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Acp.Shared.Ipc;
using Acp.Shared.Presence;
using Acp.Shared.Sessions;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using TextBox = System.Windows.Controls.TextBox;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;

namespace Acp.SessionAgent;

/// <summary>
/// W120 / S13 — the AI Chat thread surface (FEATURES.md §8
/// expansion; REVISION-DRAFT §2.1 S13, ADDED-IN-LANGUAGE). One
/// thread per pairing, living with the agent card on Home:
///
///  * Header: the pairing's identity ring (W103 BuildIdentityRing
///    — the same component S09(a) ships; no robot glyph, no A3
///    tile) + REACHABILITY TRUTH from the pairing's real
///    connection state (W97 ConnFacts — the last authenticated
///    rung), rendered by ChatReachability: «{name} can answer
///    now» / «{name} is away — your message will be delivered when
///    it wakes», with the queued count visible under it.
///  * Orders render as STRUCTURED ACTION CARDS in the timeline:
///    the GatePayloadRenderer's title + exact steps over the
///    order's exact bytes, the target device named, and S12's
///    three exits — GateSheetModel.Exits() consumed directly
///    (ChatOrderModel.CardExits), GateCardColors bound the same
///    way the sheet binds them (red ONLY on Deny and end
///    session), equal weight, NO default button. Approve = run
///    this card (the Core executes the exact bytes through the
///    policy choke point). Free text never executes: messages
///    are bubbles, nothing more — there is no path from a bubble
///    to an action.
///  * While a session for this pairing runs, STOP sits beside
///    the thread (the owner's stop, same channel as everywhere).
///  * Composer furniture is the one icon family (L12: single
///    stroke, fill = selected only): one stroke send glyph. No
///    emoji button, no paperclip — attachments are not a chat
///    feature and the composer does not pretend otherwise.
///  * §8 HARD LAW, stated in the thread itself (the standing
///    capability line): messaging is not a session — it raises
///    no presence and grants no capability.
/// </summary>
public partial class MainWindow
{
    private static Color ChatColor(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    private Border BuildChatPanel(string pairingId, string agentName)
    {
        var stack = new StackPanel { Margin = new Thickness(16) };

        // ---- header: identity ring + reachability truth + STOP ----
        var header = new Grid { Margin = new Thickness(0, 0, 0, 6) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var ring = BuildIdentityRing(agentName, revoked: false);
        Grid.SetColumn(ring, 0);
        header.Children.Add(ring);
        var headText = new StackPanel { Margin = new Thickness(12, 4, 0, 0) };
        headText.Children.Add(new TextBlock { Text = $"Chat with {agentName}", FontSize = 24, FontWeight = FontWeights.Bold, Foreground = Brushes.White });
        var facts = ConnFacts(pairingId);
        var reach = ChatReachability.Evaluate(agentName, facts.CurrentRung, facts.AtUtc, DateTimeOffset.UtcNow);
        headText.Children.Add(new TextBlock
        {
            Text = reach.Line, FontSize = 12.5, TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(reach.CanAnswerNow ? Color.FromRgb(0x7D, 0xE0, 0xA3) : Color.FromRgb(0xC9, 0xD6, 0xE8)),
        });
        if (ChatReachability.QueuedLine(agentName, _chatQueuedForAgent) is { } queuedLine)
            headText.Children.Add(new TextBlock
            {
                Text = queuedLine, FontSize = 12, TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xB8, 0xCC)),
            });
        Grid.SetColumn(headText, 1);
        header.Children.Add(headText);
        // STOP beside the thread while this pairing's session runs.
        // Presence ViewState is the naming source of truth — the same
        // one the sidebar status line uses (the snapshot's session
        // "agent" field does not carry the pairing display name).
        var presenceView = _presence?.ViewState;
        if (presenceView is { } pv && pv.SessionActive && pv.DisplayName == agentName)
        {
            var stop = new Button
            {
                Content = "STOP", FontSize = 13, FontWeight = FontWeights.Bold,
                Foreground = Brushes.White, Padding = new Thickness(16, 6, 16, 6),
                Background = new SolidColorBrush(ChatColor(PresenceComposition.GateCardColors.DenyAndEndBackground)),
                BorderThickness = new Thickness(0), VerticalAlignment = VerticalAlignment.Center,
            };
            stop.Click += async (_, _) => await SendStopAsync();
            Grid.SetColumn(stop, 2);
            header.Children.Add(stop);
        }
        stack.Children.Add(header);

        stack.Children.Add(Muted(Strings.Get("ChatCapabilityLine"), 12));

        // ---- timeline: bubbles and order cards, in time order ----
        var items = new List<(long AtMs, int Kind, int Index)>();
        for (var i = 0; i < _chatMessages.Count; i++) items.Add((_chatMessages[i].AtMs, 0, i));
        for (var i = 0; i < _chatOrders.Count; i++) items.Add((_chatOrders[i].CreatedAtMs, 1, i));
        foreach (var (_, kind, idx) in items.OrderBy(x => x.AtMs).ThenBy(x => x.Kind))
        {
            if (kind == 0) stack.Children.Add(BuildChatBubble(_chatMessages[idx], agentName));
            else stack.Children.Add(BuildOrderCard(pairingId, _chatOrders[idx], agentName));
        }
        if (_chatMessages.Count == 0 && _chatOrders.Count == 0)
            stack.Children.Add(Muted("No messages yet. Messages are delivered when the agent next reads its chat — nothing is pushed.", 12));

        // ---- composer: one stroke send icon, no other furniture ----
        var compose = new Grid { Margin = new Thickness(0, 8, 0, 0) };
        compose.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        compose.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var box = new TextBox
        {
            FontSize = 14, Margin = new Thickness(0, 0, 8, 0), AcceptsReturn = false,
            Background = new SolidColorBrush(Color.FromRgb(0x1B, 0x2E, 0x3C)),
            Foreground = Brushes.White, BorderThickness = new Thickness(0),
            Padding = new Thickness(12, 9, 12, 9),
        };
        Grid.SetColumn(box, 0);
        compose.Children.Add(box);
        var status = Muted("", 11.5);
        var send = new Button
        {
            ToolTip = "Send",
            Padding = new Thickness(10, 5, 10, 5),
            Background = Brushes.Transparent, BorderThickness = new Thickness(0),
            Content = new System.Windows.Shapes.Path
            {
                // The one icon family's send glyph: a single
                // stroke paper plane, fill only when selected —
                // never filled here.
                Data = Geometry.Parse("M3,20 L21,10 L3,4 L7,10 Z M7,10 L21,10"),
                Stroke = new SolidColorBrush(Color.FromRgb(0x2F, 0x8B, 0xC9)),
                StrokeThickness = 1.8, Width = 22, Height = 22,
                Stretch = Stretch.Uniform,
            },
        };
        Grid.SetColumn(send, 1);
        compose.Children.Add(send);
        async Task DoSend()
        {
            var text = box.Text.Trim();
            if (text.Length == 0) return;
            var sent = _chatSendSender is not null && await _chatSendSender(pairingId, text);
            if (sent)
            {
                box.Clear();
                status.Text = "";
                if (_chatThreadSender is not null) await _chatThreadSender(pairingId);
            }
            else
            {
                status.Text = "Not sent — the Core did not accept it. Your text is still in the box.";
            }
        }
        send.Click += async (_, _) => await DoSend();
        box.KeyDown += async (_, e) =>
        {
            if (e.Key == System.Windows.Input.Key.Enter) { e.Handled = true; await DoSend(); }
        };
        stack.Children.Add(compose);
        stack.Children.Add(status);

        return new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x15, 0x2A, 0x3D)),
            CornerRadius = new CornerRadius(14),
            Margin = new Thickness(54, 0, 0, 10),
            Child = stack,
        };
    }

    /// <summary>One message bubble: the owner's right-aligned in
    /// the action blue tint, the agent's left in the card grey —
    /// conversational composition (Board 05), words only. A bubble
    /// is never a button and never executes anything.</summary>
    private Border BuildChatBubble((long Seq, string Direction, string Body, long AtMs) msg, string agentName)
    {
        var owner = msg.Direction == "owner";
        var inner = new StackPanel { Margin = new Thickness(14, 10, 14, 10) };
        inner.Children.Add(new TextBlock
        {
            Text = owner ? "You" : agentName, FontSize = 11,
            Foreground = new SolidColorBrush(Color.FromRgb(0x9F, 0xB3, 0xC8)),
        });
        inner.Children.Add(new TextBlock
        {
            Text = msg.Body, FontSize = 14, TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.White,
        });
        return new Border
        {
            Background = new SolidColorBrush(owner ? Color.FromRgb(0x2F, 0x8B, 0xC9) : Color.FromRgb(0x26, 0x39, 0x4B)),
            CornerRadius = new CornerRadius(12),
            Margin = new Thickness(owner ? 90 : 0, 3, owner ? 0 : 90, 3),
            HorizontalAlignment = owner ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Child = inner,
        };
    }

    /// <summary>One S13 order card in the thread. Pending cards
    /// carry S12's three exits (shared constants, shared colours,
    /// equal weight, no default); resolved cards carry their
    /// outcome line instead — a decided card never presents a
    /// live Approve again. A foreign-target card names its device
    /// and its Approve is disabled with the reason on the card:
    /// it runs there, not here.</summary>
    private Border BuildOrderCard(string pairingId, ChatOrder order, string agentName)
    {
        var view = ChatOrderModel.CardView(order, agentName);
        var foreign = ChatOrderModel.IsForeignTarget(order, _chatThisDevice);
        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock
        {
            Text = ChatOrderModel.CardTitle(order, agentName),
            FontSize = 17, FontWeight = FontWeights.Bold, Foreground = Brushes.White,
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(new TextBlock
        {
            Text = foreign
                ? $"Target: {order.TargetDevice} — this order runs on {order.TargetDevice}, not on this computer."
                : $"Target: {(string.IsNullOrWhiteSpace(order.TargetDevice) ? _chatThisDevice : order.TargetDevice)}",
            FontSize = 12.5, Foreground = new SolidColorBrush(Color.FromRgb(0xC9, 0xD6, 0xE8)),
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0),
        });
        foreach (var line in view.PlainLines)
            panel.Children.Add(new TextBlock
            {
                Text = line, FontSize = 13.5, Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0),
            });
        panel.Children.Add(new TextBlock
        {
            Text = string.Join("\n", view.TechnicalLines), FontSize = 11.5,
            Foreground = new SolidColorBrush(Color.FromRgb(0xA6, 0xA6, 0xB0)),
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Cascadia Mono"),
            Margin = new Thickness(0, 7, 0, 0),
        });

        var status = Muted("", 11.5);
        if (order.Status == ChatOrderStatus.Pending)
        {
            var exits = ChatOrderModel.CardExits();
            var answers = new[] { GateAnswers.Allow, GateAnswers.Deny, GateAnswers.DenyAndEnd };
            var fills = new[]
            {
                PresenceComposition.GateCardColors.ApproveBackground,
                PresenceComposition.GateCardColors.DenyBackground,
                PresenceComposition.GateCardColors.DenyAndEndBackground,
            };
            var texts = new[]
            {
                PresenceComposition.GateCardColors.ApproveForeground,
                PresenceComposition.GateCardColors.DenyForeground,
                PresenceComposition.GateCardColors.DenyAndEndForeground,
            };
            // W131: exits laid out to the reference's composition —
            // the first two exits side by side at equal width (the
            // W130 gate-row pattern), the session-ending third exit
            // full-width directly beneath, in-language. Same exits,
            // same Decide path, same colours, equal weight, no
            // default — layout only.
            Button MakeExit(int i, Thickness margin)
            {
                var answer = answers[i];
                var b = new Button
                {
                    Content = exits[i].Label,
                    FontSize = 14, FontWeight = FontWeights.SemiBold,
                    Padding = new Thickness(18, 10, 18, 10),
                    Margin = margin,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    Background = new SolidColorBrush(ChatColor(fills[i])),
                    Foreground = new SolidColorBrush(ChatColor(texts[i])),
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x33, 0x3F)),
                    BorderThickness = new Thickness(1),
                    IsEnabled = !(foreign && answer == GateAnswers.Allow),
                };
                b.Click += async (_, _) =>
                {
                    var sent = _chatOrderAnswerSender is not null &&
                               await _chatOrderAnswerSender(pairingId, order.Id, answer);
                    if (sent)
                    {
                        if (_chatThreadSender is not null) await _chatThreadSender(pairingId);
                    }
                    else
                    {
                        status.Text = "The answer was not sent — the Core did not receive it. The card is still waiting.";
                    }
                };
                return b;
            }
            var pairRow = new Grid { Margin = new Thickness(0, 10, 0, 0) };
            pairRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            pairRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var exit0 = MakeExit(0, new Thickness(0, 0, 5, 0));
            Grid.SetColumn(exit0, 0);
            pairRow.Children.Add(exit0);
            var exit1 = MakeExit(1, new Thickness(5, 0, 0, 0));
            Grid.SetColumn(exit1, 1);
            pairRow.Children.Add(exit1);
            panel.Children.Add(pairRow);
            panel.Children.Add(MakeExit(2, new Thickness(0, 10, 0, 0)));
            panel.Children.Add(new TextBlock
            {
                Text = "Pending your approval…", FontSize = 12.5,
                Foreground = new SolidColorBrush(Color.FromRgb(0xC9, 0xD6, 0xE8)),
                Margin = new Thickness(0, 8, 0, 0),
            });
            if (foreign)
                panel.Children.Add(new TextBlock
                {
                    Text = $"Approve is off here: this order can only run on {order.TargetDevice}. You can still deny it.",
                    FontSize = 12, Foreground = new SolidColorBrush(Color.FromRgb(0xF2, 0xA9, 0x00)),
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0),
                });
        }
        else
        {
            panel.Children.Add(new TextBlock
            {
                Text = order.Status switch
                {
                    ChatOrderStatus.Running => "Approved — running…",
                    ChatOrderStatus.Done => $"Approved — done. {order.ResultLine}",
                    ChatOrderStatus.Denied => "Denied — nothing ran.",
                    ChatOrderStatus.DeniedAndEnded => "Denied and the session ended — nothing ran.",
                    ChatOrderStatus.Failed => order.ResultLine ?? "Not run.",
                    _ => order.Status,
                },
                FontSize = 13, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 9, 0, 0),
                Foreground = new SolidColorBrush(
                    order.Status == ChatOrderStatus.Done ? Color.FromRgb(0x7D, 0xE0, 0xA3)
                    : order.Status == ChatOrderStatus.Failed ? Color.FromRgb(0xF2, 0xA9, 0x00)
                    : Color.FromRgb(0xC9, 0xD6, 0xE8)),
            });
        }
        panel.Children.Add(status);
        return new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x18, 0x2D, 0x3E)),
            CornerRadius = new CornerRadius(14),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE5, 0xA9, 0x3B)),
            BorderThickness = new Thickness(2),
            Margin = new Thickness(0, 6, 0, 6),
            Child = panel,
        };
    }
}

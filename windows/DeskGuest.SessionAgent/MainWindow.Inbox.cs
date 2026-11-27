using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Sessions;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;

namespace DeskGuest.SessionAgent;

/// <summary>
/// W122 / N22 — the unified inbox: a LENS over S13's threads,
/// rendered at the top of Home above the agent cards the threads
/// live with (REVISION-DRAFT §2.3 N22, ADDED-IN-LANGUAGE; design
/// call of record: BOTH — threads are the home, the inbox is a
/// lens). The lens is an index, never a second store: every row's
/// counts come from the Core's snapshot facts, which the Core
/// computes from the one AgentChatStore + ChatOrderStore +
/// seen-cursor store (ChatInboxModel). This window keeps no
/// inbox state of its own.
///
/// Row language is S14's (identity + plain state words):
///  * the pairing's W103 ring-with-initial (the same
///    BuildIdentityRing component the cards and the thread
///    header use), scaled to row size;
///  * reachability in ChatReachability's exact words, evaluated
///    over ConnFacts — the SAME snapshot fields S13's thread
///    header evaluates — so a row and its header can never
///    disagree for the same pairing;
///  * the state line in one of the two unread classes' words:
///    WAITING ON YOU (a pending order card — semibold navy with
///    an amber accent bar) or mere unread ("N new messages" in
///    the action blue). The classes are different words at
///    different weight because they ask different things of the
///    owner: an answer vs a read.
///
/// Opening a row: a waiting row surfaces its oldest pending card
/// through W119's S12 gate sheet — GateSheet.Present itself, the
/// same control, fed the card's own GatePayloadRenderer view
/// over its exact bytes (fromChat: the sheet says «Asked from
/// Agent chat»); the sheet's outcome returns as the card's
/// answer through the same ChatOrderAnswer channel the thread's
/// inline exits use. A foreign-target card is the one exception:
/// its Approve must stay off (it runs on the named device, not
/// here), and the sheet has no disabled-Approve form — so a
/// foreign waiting row opens the thread, where the card itself
/// carries that law. Any other row opens the pairing's thread
/// on Home (the home the design call names).
/// </summary>
public partial class MainWindow
{
    private static Color InboxColor(int argb) => Color.FromArgb(
        (byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);

    // The lens lives on Home's LIGHT surfaces (DeskGuestTheme
    // tokens): primary text is the theme navy, secondary the
    // theme slate, unread the action blue. The waiting class is
    // carried by semibold weight + its own words + an amber
    // accent bar (the token sheet's amber = waiting) — never by
    // light amber text on a white card, which no one could read.
    private static readonly Color InboxNavy = Color.FromRgb(0x0F, 0x25, 0x37);
    private static readonly Color InboxSlate = Color.FromRgb(0x48, 0x61, 0x75);
    private static readonly Color InboxBlue = Color.FromRgb(0x2F, 0x8B, 0xC9);
    private static readonly Color InboxAmber = Color.FromRgb(0xF2, 0xA9, 0x00);

    private static SolidColorBrush InboxStateBrush(bool waiting) =>
        new(waiting ? InboxNavy : InboxBlue);

    /// <summary>The inbox facts for one pairing, or null when the
    /// snapshot carries none (older Core / ended pairing).</summary>
    private ChatThreadData? InboxFacts(string pairingId) =>
        _host is not null && _host.ChatThreads.TryGetValue(pairingId, out var d) ? d : null;

    /// <summary>The lens signature fragment: every pairing's
    /// class-bearing counts, so a change in any thread's unread
    /// or pending state re-renders Home.</summary>
    private string InboxSignature()
    {
        if (_host is null) return "-";
        return string.Join("|", _host.Pairings.Select(p =>
            _host.ChatThreads.TryGetValue(p.Id, out var d)
                ? $"{p.Id}:{d.UnreadMessages}:{d.PendingOrders}:{d.LastActivityMs}"
                : $"{p.Id}:-"));
    }

    /// <summary>The lens section: header + the summary line in
    /// the two classes' own words, then one row per live pairing
    /// in the lens order (waiting, then unread, then quiet —
    /// ChatInboxModel.OrderForLens). Rendered only when the
    /// snapshot carries the index and at least one live pairing
    /// exists; an older Core shows no lens rather than a fake one.</summary>
    private void RenderInboxSection(List<(string Id, string Name, string[] Scopes, bool Revoked)> pairings)
    {
        if (_host is null || _host.ChatThreads.Count == 0) return;
        var live = pairings.Where(p => !p.Revoked).ToList();
        if (live.Count == 0) return;

        var facts = live
            .Select(p => (Pairing: p, Data: InboxFacts(p.Id)))
            .Where(x => x.Data is not null)
            .Select(x => (x.Pairing, Data: x.Data!))
            .ToList();
        if (facts.Count == 0) return;

        var waitingThreads = facts.Count(x => x.Data.PendingOrders > 0);
        var unreadThreads = facts.Count(x => x.Data.PendingOrders == 0 && x.Data.UnreadMessages > 0);

        _homeHelpersBody!.Children.Add(new TextBlock
        {
            Text = "Inbox", FontSize = 15.5, FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(InboxNavy), Margin = new Thickness(0, 4, 0, 0),
        });
        _homeHelpersBody.Children.Add(new TextBlock
        {
            Text = ChatInboxModel.LensSummary(waitingThreads, unreadThreads),
            FontSize = 12.5, Margin = new Thickness(0, 1, 0, 4),
            Foreground = new SolidColorBrush(InboxSlate),
        });

        var byId = facts.ToDictionary(x => x.Pairing.Id, x => x);
        foreach (var f in ChatInboxModel.OrderForLens(facts.Select(x => x.Data.Facts(x.Pairing.Id))))
        {
            var (pairing, data) = byId[f.PairingId];
            _homeHelpersBody.Children.Add(BuildInboxRow(pairing.Id, pairing.Name, data));
        }
        _homeHelpersBody.Children.Add(new Border
        {
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xD5, 0xE1, 0xEA)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Margin = new Thickness(0, 4, 0, 8),
        });
    }

    /// <summary>One lens row: ring + name + reachability + the
    /// class state line, the whole row one button. Waiting rows
    /// carry the amber state line at semibold; unread rows the
    /// plain new-messages line; quiet rows claim nothing beyond
    /// "No new messages".</summary>
    private Button BuildInboxRow(string pairingId, string agentName, ChatThreadData data)
    {
        var facts = data.Facts(pairingId);
        // #148 rework: lens rows run tighter (ring 0.58, 2px row
        // margins) so the card's first screen carries more of the
        // roster the card exists for — the agent cards below the
        // lens were scroll-only under the old spacing. Words,
        // classes and click behaviour are unchanged.
        var grid = new Grid { Margin = new Thickness(2, 2, 2, 2) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var ring = (FrameworkElement)BuildIdentityRing(agentName, revoked: false);
        ring.LayoutTransform = new ScaleTransform(0.58, 0.58);
        Grid.SetColumn(ring, 0);
        grid.Children.Add(ring);

        var texts = new StackPanel { Margin = new Thickness(10, 1, 0, 0) };
        texts.Children.Add(new TextBlock
        {
            Text = agentName, FontSize = 14.5, FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(InboxNavy),
        });
        // Reachability: the SAME evaluation the thread header
        // performs, over the SAME ConnFacts snapshot fields.
        var conn = ConnFacts(pairingId);
        var reach = ChatReachability.Evaluate(agentName, conn.CurrentRung, conn.AtUtc, DateTimeOffset.UtcNow);
        texts.Children.Add(new TextBlock
        {
            Text = reach.Line, FontSize = 12, TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(reach.CanAnswerNow ? Color.FromRgb(0x14, 0x6B, 0x33) : Color.FromRgb(0x48, 0x61, 0x75)),
        });
        var stateLine = ChatInboxModel.StateLine(agentName, facts);
        var isWaiting = facts.Class == ChatThreadClass.WaitingOnYou;
        if (stateLine is not null)
        {
            texts.Children.Add(new TextBlock
            {
                Text = stateLine, FontSize = 12.5, TextWrapping = TextWrapping.Wrap,
                FontWeight = isWaiting ? FontWeights.SemiBold : FontWeights.Normal,
                Foreground = InboxStateBrush(isWaiting),
                Margin = new Thickness(0, 1, 0, 0),
            });
        }
        else
        {
            texts.Children.Add(new TextBlock
            {
                Text = "No new messages", FontSize = 12.5,
                Foreground = new SolidColorBrush(InboxSlate),
                Margin = new Thickness(0, 1, 0, 0),
            });
        }
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);

        // A waiting row carries the amber accent bar at its left
        // edge — the waiting color, at full strength, where it
        // reads on a light card (the token sheet's triple coding:
        // word + weight + color).
        var rowContent = new Border
        {
            BorderBrush = new SolidColorBrush(isWaiting ? InboxAmber : Colors.Transparent),
            BorderThickness = new Thickness(isWaiting ? 3 : 0, 0, 0, 0),
            Padding = new Thickness(isWaiting ? 6 : 0, 0, 0, 0),
            Child = grid,
        };
        var row = new Button
        {
            Content = rowContent,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Padding = new Thickness(4, 2, 4, 2),
            ToolTip = isWaiting
                ? "Open the waiting order card"
                : "Open the thread",
        };
        var capturedId = pairingId;
        var capturedName = agentName;
        row.Click += async (_, _) => await OpenInboxRowAsync(capturedId, capturedName);
        return row;
    }

    /// <summary>Open one lens row. A waiting row with a local
    /// pending card surfaces that card through the S12 gate
    /// sheet (the same GateSheet control W119 built — not a
    /// copy); every other row opens the pairing's thread.</summary>
    private async Task OpenInboxRowAsync(string pairingId, string agentName)
    {
        var data = InboxFacts(pairingId);
        var oldest = data?.PendingOrderList.FirstOrDefault();
        if (oldest is not null && !ChatOrderModel.IsForeignTarget(oldest, _host?.MachineName ?? ""))
        {
            PresentPendingCardSheet(pairingId, agentName, oldest);
            return;
        }
        OpenChatThread(pairingId);
        await Task.CompletedTask;
    }

    /// <summary>Surface one pending card through the S12 gate
    /// sheet: the card's own payload view over its exact bytes,
    /// marked as asked from Agent chat. The sheet's three exits
    /// ARE the card's exits; the chosen one returns through the
    /// card-answer channel, and a sheet closed with no exit
    /// sends NO answer — the card stays pending, exactly as a
    /// thread card left unanswered stays pending.</summary>
    private void PresentPendingCardSheet(string pairingId, string agentName, ChatOrder order)
    {
        var view = ChatOrderModel.CardView(order, agentName);
        var bytes = Encoding.UTF8.GetBytes(order.ArgumentsJson);
        var outcome = GateSheet.Present(view, bytes, fromChat: true,
            onDenyAndEnd: null, presence: _presence);
        if (outcome is not { } o) return;
        var answer = o switch
        {
            GateSheet.Outcome.Approved => GateAnswers.Allow,
            GateSheet.Outcome.Denied => GateAnswers.Deny,
            _ => GateAnswers.DenyAndEnd,
        };
        _ = AnswerCardFromSheetAsync(pairingId, order.Id, answer);
    }

    private async Task AnswerCardFromSheetAsync(string pairingId, string orderId, string answer)
    {
        if (_chatOrderAnswerSender is not null)
            await _chatOrderAnswerSender(pairingId, orderId, answer);
        if (_chatOpenPairingId == pairingId && _chatThreadSender is not null)
            await _chatThreadSender(pairingId);
        if (_hostStateSender is not null)
            await _hostStateSender();
        RefreshDynamics();
    }

    /// <summary>Open a pairing's thread — the same door the agent
    /// card's Chat toggle and S09(d)'s «Message {agent}» button
    /// walk through: set the open thread, clear the stale copy,
    /// navigate to the full-window chat page (W135, ruling U-7),
    /// and ask the Core for the thread (which also advances the
    /// owner's seen cursor).</summary>
    private void OpenChatThread(string pairingId)
    {
        _chatOpenPairingId = pairingId;
        _chatMessages.Clear();
        _chatOrders.Clear();
        ShowPage("chat");
        RefreshDynamics();
        if (_chatThreadSender is not null) _ = _chatThreadSender(pairingId);
    }
}

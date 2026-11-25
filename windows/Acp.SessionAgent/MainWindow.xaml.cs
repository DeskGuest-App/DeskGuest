using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Acp.Shared.Ipc;
using Acp.Shared.Policy;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Color = System.Windows.Media.Color;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using VerticalAlignment = System.Windows.VerticalAlignment;
using Point = System.Windows.Point;
using RadioButton = System.Windows.Controls.RadioButton;

namespace Acp.SessionAgent;

/// <summary>The companion window (M4, 2026-11-17): the
/// design-of-record shell — Daylight-White, sidebar Overview /
/// Presence / Guardrails / Audit Log / Updates, MESH DEVICES,
/// Settings / About — rebuilt around the functions the old panel
/// already had (vault, gate approvals, STOP/CLEAR STOP) plus the
/// Core host-state snapshot. Every fact on every page comes from
/// the presence layer's truth or the Core's snapshot; a page never
/// invents state. Where the design mockups claimed capabilities ACP
/// does not have (Ctrl+Shift+Esc, cloaking, scoped defaults), the
/// plan's conflicts win: real states only.</summary>
public partial class MainWindow : Window
{
    private PresenceLayer? _presence;
    private Func<bool>? _desktopUnlocked;
    private Func<string, bool, Task<bool>>? _gateApprovalSender;
    private Func<string, Task<bool>>? _vaultSetSender;
    private Func<Task<bool>>? _vaultWipeSender;
    private Func<Task<bool>>? _stopSender;
    private Func<Task<bool>>? _stopClearSender;
    private Func<Task<bool>>? _hostStateSender;
    private Func<string, Task<bool>>? _pairingRevokeSender;
    private Func<string, string, string?, Task<bool>>? _pairingCreateSender;
    // W97 / S09(b): the Pair card's connection-mode choice at mint
    // (default AUTO). Compact: three radios; the subset/pin panels
    // show only for the mode that needs them.
    private RadioButton? _mintConnRestricted;
    private RadioButton? _mintConnManual;
    private StackPanel? _mintConnSubsetPanel;
    private StackPanel? _mintConnPinPanel;
    private readonly Dictionary<string, CheckBox> _mintConnRungs = new();
    private readonly Dictionary<string, RadioButton> _mintConnPins = new();
    private Func<string, string, Task<bool>>? _hostActionSender;

    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private int _tick;
    private string _currentPage = "overview";
    private readonly Dictionary<string, UIElement> _pages = new();
    private HostState? _host;
    private DateTimeOffset _hostAt = DateTimeOffset.MinValue;

    // Overview (Home) dynamics live in the W70 Home block below.
    // Guardrails dynamics
    private readonly Dictionary<string, TextBlock> _gateStatus = new();
    private TextBlock? _gateStatusText;
    private PasswordBox? _vaultPasswordBox;
    private TextBlock? _vaultStatusText;
    private StackPanel? _policyBody;
    // Pairing page dynamics
    private StackPanel? _checklistBody;
    private TextBlock? _pairingCodeText;
    private TextBlock? _pairingStatusText;
    private TextBlock? _pairingSasText;
    private string _setupRole = "endpoint";
    private TextBox? _pairingNameBox;
    private RadioButton? _presetFull;
    // W75: pairing page rebuild dynamics (role rows, reach line,
    // enter-theirs card).
    private readonly Dictionary<string, Border> _roleRows = new();
    private TextBlock? _pairingReachText;
    private TextBox? _enterCodeBox;
    private TextBox? _enterNameBox;
    private TextBlock? _enterStatusText;
    // Audit dynamics
    private StackPanel? _auditBody;
    private TextBlock? _auditSummary;

    /// <summary>Friendly names for the gated classes (DESIGN §6.7).</summary>
    private static readonly IReadOnlyDictionary<string, string> GateLabels = new Dictionary<string, string>
    {
        ["payments"] = "Payments",
        ["sending"] = "Sending messages / mail",
        ["deletions"] = "Deletions",
        ["installs"] = "Software installs",
        ["service_stop_non_acp"] = "Stopping non-ACP services",
        ["shutdown"] = "Shutdown",
        ["vault_ops"] = "Credential vault operations",
        ["power"] = "Power actions (reboot)",
        ["clipboard_read"] = "Reading the clipboard",
        ["clipboard_write"] = "Setting the clipboard",
    };

    [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    public MainWindow()
    {
        InitializeComponent();
        // W123: the Gemini master draws the window's title bar in the
        // product's own light chrome (#EBF3F6, navy text) — the same
        // bar on every screen. The OS default follows the user's
        // accent theme (dark red on the capture laptop), which is the
        // single largest diff region against the master. On Windows
        // 11 the app sets its caption colors to the reference's own
        // values (DWMWA_CAPTION_COLOR=35 / TEXT_COLOR=36); on older
        // Windows the attribute does not exist and the OS bar stands.
        SourceInitialized += (_, _) =>
        {
            if (Environment.OSVersion.Version.Build < 22000) return;
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            int caption = 0xF6F3EB; // #EBF3F6 in COLORREF (BGR)
            int text = 0x37250F;    // #0F2537 in COLORREF (BGR)
            _ = DwmSetWindowAttribute(hwnd, 35, ref caption, sizeof(int));
            _ = DwmSetWindowAttribute(hwnd, 36, ref text, sizeof(int));
        };
        // W8: no build label in owner chrome — the version is
        // stated on the About page only (record §4).
        _timer.Tick += (_, _) => OnTick();
        _timer.Start();
        ShowPage("overview");
    }

    // W9 (Addendum A): the Agent chat thread view state — the thread
    // lives on the agent's row in Overview (record §4): at most one
    // pairing's thread is open; its messages are the Core's own
    // thread answer (ChatThreadReceived), never a window-side store.
    private Func<string, string, Task<bool>>? _chatSendSender;
    private Func<string, Task<bool>>? _chatThreadSender;
    private string? _chatOpenPairingId;
    private readonly List<(long Seq, string Direction, string Body, long AtMs)> _chatMessages = new();
    // W120 / S13: the open thread's order cards + queue/device
    // facts, from the Core's thread push (owner channel only).
    private readonly List<Acp.Shared.Sessions.ChatOrder> _chatOrders = new();
    private long _chatQueuedForAgent;
    private string _chatThisDevice = "";
    private string _chatSignature = "";
    private Func<string, string, string, Task<bool>>? _chatOrderAnswerSender;

    public void Attach(PresenceLayer presence, Func<bool> desktopUnlocked, Func<string, bool, Task<bool>>? gateApprovalSender = null,
        Func<string, Task<bool>>? vaultSetSender = null, Func<Task<bool>>? vaultWipeSender = null,
        Func<Task<bool>>? stopSender = null, Func<Task<bool>>? stopClearSender = null,
        Func<Task<bool>>? hostStateSender = null, Func<string, Task<bool>>? pairingRevokeSender = null,
        Func<string, string, string?, Task<bool>>? pairingCreateSender = null,
        Func<string, string, Task<bool>>? hostActionSender = null,
        Func<string, string, Task<bool>>? chatSendSender = null,
        Func<string, Task<bool>>? chatThreadSender = null,
        Func<string, string, string, Task<bool>>? chatOrderAnswerSender = null)
    {
        _presence = presence;
        _desktopUnlocked = desktopUnlocked;
        _gateApprovalSender = gateApprovalSender;
        _vaultSetSender = vaultSetSender;
        _vaultWipeSender = vaultWipeSender;
        _stopSender = stopSender;
        _stopClearSender = stopClearSender;
        _hostStateSender = hostStateSender;
        _pairingRevokeSender = pairingRevokeSender;
        _pairingCreateSender = pairingCreateSender;
        _hostActionSender = hostActionSender;
        _chatSendSender = chatSendSender;
        _chatThreadSender = chatThreadSender;
        _chatOrderAnswerSender = chatOrderAnswerSender;
        _ = RequestHostStateAsync();
        RefreshDynamics();
    }

    /// <summary>W9: the Core's answer to a chat-thread request
    /// (owner channel only). Renders only when it names the pairing
    /// whose thread is open here; a thread answer for a pairing the
    /// owner has since closed (or unpairing ended) is dropped.</summary>
    public void SetChatThread(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetChatThread(json)); return; }
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            var pairingId = root.TryGetProperty("pairingId", out var p) ? p.GetString() : null;
            if (pairingId is null || pairingId != _chatOpenPairingId) return;
            _chatMessages.Clear();
            if (root.TryGetProperty("messages", out var msgs))
                foreach (var m in msgs.EnumerateArray())
                    _chatMessages.Add((
                        m.TryGetProperty("seq", out var s) ? s.GetInt64() : 0,
                        m.TryGetProperty("direction", out var d) ? d.GetString() ?? "" : "",
                        m.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "",
                        m.TryGetProperty("atMs", out var am) ? am.GetInt64() : 0));
            // W120 / S13: order cards + queue/device facts ride the
            // same push. An older Core sends none — the thread then
            // renders messages only, the pre-S13 truth.
            _chatOrders.Clear();
            if (root.TryGetProperty("orders", out var ords))
                foreach (var o in ords.EnumerateArray())
                {
                    string? GS(string n) => o.TryGetProperty(n, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
                    _chatOrders.Add(new Acp.Shared.Sessions.ChatOrder(
                        GS("id") ?? "", pairingId,
                        GS("tool") ?? "", GS("gateClass"),
                        GS("argumentsJson") ?? "{}", GS("title") ?? "",
                        GS("targetDevice") ?? "", GS("status") ?? "pending",
                        GS("resultLine"),
                        o.TryGetProperty("createdAtMs", out var cm) ? cm.GetInt64() : 0, null));
                }
            _chatQueuedForAgent = root.TryGetProperty("queuedForAgent", out var q) ? q.GetInt64() : 0;
            _chatThisDevice = root.TryGetProperty("thisDevice", out var td) ? td.GetString() ?? "" : "";
            _chatSignature = $"{_chatMessages.Count}:{_chatQueuedForAgent}:" +
                string.Join(",", _chatOrders.Select(o => $"{o.Id}={o.Status}"));
            RefreshDynamics();
        }
        catch { /* a malformed thread answer leaves the last rendered thread standing */ }
    }

    // ---------------- navigation ----------------

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string page }) ShowPage(page);
    }

    private void ShowPage(string page)
    {
        _currentPage = page;
        if (!_pages.TryGetValue(page, out var element))
        {
            element = page switch
            {
                "presence" => BuildPresencePage(),
                "guardrails" => BuildGuardrailsPage(),
                "audit" => BuildAuditPage(),
                "updates" => BuildUpdatesPage(),
                "settings" => BuildSettingsPage(),
                "about" => BuildAboutPage(),
                "pairing" => BuildPairingPage(),
                "agentdetail" => BuildAgentDetailPage(),
                "roster" => BuildRosterPage(),
                "sessions" => BuildSessionsPage(),
                "enterprise" => BuildEnterprisePage(),
                "services" => BuildServicesPage(),
                _ => BuildOverviewPage(),
            };
            _pages[page] = element;
        }
        PageHost.Content = element;
        if (PageHost.Parent is ScrollViewer sv)
            sv.VerticalScrollBarVisibility = page == "overview"
                ? ScrollBarVisibility.Hidden : ScrollBarVisibility.Auto;
        foreach (var (name, button) in new[]
        {
            ("overview", NavOverview), ("presence", NavPresence), ("guardrails", NavGuardrails),
            ("audit", NavAudit), ("updates", NavUpdates), ("settings", NavSettings), ("about", NavAbout),
            ("roster", NavRoster), ("sessions", NavSessions), ("enterprise", NavEnterprise), ("pairing", NavAgents),
            ("services", NavServices),
        })
        {
            // W70: selected nav = the master's navy pill, white text.
            button.Background = name == page
                ? new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37))
                : Brushes.Transparent;
            button.Foreground = name == page
                ? Brushes.White
                : new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37));
            button.FontWeight = name == page ? FontWeights.SemiBold : FontWeights.Normal;
        }
        RefreshDynamics();
    }

    // ---------------- shared builders ----------------

    private static TextBlock PageTitle(string text) => new() { Text = text, Style = null, FontSize = 27, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 2) };
    private static TextBlock Sub(string text) => new() { Text = text, FontSize = 13.5, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)), Margin = new Thickness(0, 0, 0, 16), TextWrapping = TextWrapping.Wrap };
    private static TextBlock Body(string text, double size = 13.5) => new() { Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap };
    private static TextBlock Muted(string text, double size = 12.5) => new() { Text = text, FontSize = size, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)), TextWrapping = TextWrapping.Wrap };
    // Density rule: the surface carries the plain-language minimum; depth rides the tooltip.
    private static TextBlock MutedT(string text, string tooltip, double size = 12.5) => new() { Text = text, FontSize = size, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)), TextWrapping = TextWrapping.Wrap, ToolTip = tooltip };

    private Border Card(UIElement content)
    {
        var card = new Border { Style = (Style)FindResource("Card") };
        card.Child = content;
        return card;
    }

    private static Border Chip(string text, Color bg, Color fg)
    {
        return new Border
        {
            Background = new SolidColorBrush(bg),
            CornerRadius = new CornerRadius(9),
            Padding = new Thickness(10, 3, 10, 3),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = text, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(fg) }
        };
    }

    private static readonly Color GreenBg = Color.FromRgb(0xDC, 0xF2, 0xE3);
    private static readonly Color GreenFg = Color.FromRgb(0x14, 0x6B, 0x33);
    private static readonly Color RedBg = Color.FromRgb(0xFB, 0xE3, 0xE3);
    private static readonly Color RedFg = Color.FromRgb(0x9E, 0x1F, 0x1F);
    // W65 token sweep: chips re-based on the v2.0.0 theme layer
    // (bgSubtle #E6EEF4 / textSecondary #486175); blue chip text is
    // the one action blue #2F8BC9 darkened only for text contrast.
    private static readonly Color GrayBg = Color.FromRgb(0xE6, 0xEE, 0xF4);
    private static readonly Color GrayFg = Color.FromRgb(0x48, 0x61, 0x75);
    private static readonly Color BlueBg = Color.FromRgb(0xE6, 0xEE, 0xF4);
    private static readonly Color BlueFg = Color.FromRgb(0x1D, 0x6F, 0xA8);

    // ---------------- host state ----------------

    private sealed class HostState
    {
        public string CoreVersion = "";
        public string MachineName = "";
        public int Port;
        public string[] Lanes = Array.Empty<string>();
        public bool AgentConnected;
        public bool DesktopUnlocked;
        public bool UserStop;
        public bool SessionActive;
        public string? SessionAgent;
        public long SessionSeconds;
        public int SessionActions;
        public string? SessionIntent;
        public List<(string Id, string Name, string[] Scopes, bool Revoked)> Pairings = new();
        // W97 / S09(b): per-pairing connection-path facts from the
        // same snapshot (mode + subset/pin + the LIVE current rung).
        // Absent fields (an older Core) parse as AUTO / no rung —
        // the card then shows the pre-policy truth, nothing invented.
        public Dictionary<string, (string Mode, string[] Rungs, string? Pin, string? CurrentRung, DateTimeOffset? CurrentRungAtUtc)> PairingConnections = new();
        public List<(string Id, bool Approved)> Gates = new();
        public List<(DateTimeOffset At, string? Agent, string? Tool, string? Operation, string Outcome, long? Ms)> Audit = new();
        // Slice 2/3 live wiring (Block A): roster scopes, human
        // sessions, and this device's endpoint view, parsed from the
        // same snapshot. Absent sections (an older Core) parse as
        // empty — the pages say so rather than inventing data.
        public List<RosterScopeData> Roster = new();
        public List<HumanSessionData> HumanSessions = new();
        public EndpointData? Endpoint;
        // Transport core (Block C part 1): LAN listener state + the
        // failover engine's recent events, from the same snapshot.
        public TransportData? Transport;
        // Enterprise wiring (Block F): policy/audit/break-glass
        // truth from the live Core, from the same snapshot.
        public EnterpriseData? Enterprise;
        // Block G facts (Block H Services page): counts + feature
        // postures from the same snapshot.
        public BlockGData? BlockG;
        // W8: the U5 data-flow report + live event watches, parsed
        // from the same snapshot (both sections have ridden it
        // since U5/W8-Core; the agent never rendered them before).
        public List<FlowAgentData> Flows = new();
        public List<string> FlowGaps = new();
        public List<(string PairingId, string[] Kinds, DateTimeOffset ExpiresUtc)> EventWatches = new();
        // FR-113 (W65): the Core's effective file roots, from the
        // snapshot — the Guardrails label is generated from these.
        public string[] FileRoots = Array.Empty<string>();
        // W122 / N22: the inbox index over the one chat store,
        // per pairing — unread counts, pending-card counts, and
        // the pending cards themselves (for the S12 sheet door).
        // Absent section (an older Core) parses as empty: no
        // inbox is shown rather than an invented one.
        public Dictionary<string, ChatThreadData> ChatThreads = new();
    }

    /// <summary>One pairing's N22 inbox facts (snapshot shape).</summary>
    private sealed class ChatThreadData
    {
        public int UnreadMessages;
        public int PendingOrders;
        public long LastActivityMs;
        public List<Acp.Shared.Sessions.ChatOrder> PendingOrderList = new();
        public Acp.Shared.Sessions.ChatThreadFacts Facts(string pairingId) =>
            new(pairingId, UnreadMessages, PendingOrders, LastActivityMs);
    }

    /// <summary>One agent's data-flow aggregate (snapshot shape).</summary>
    private sealed class FlowAgentData
    {
        public string PairingId = ""; public string AgentName = "";
        public int SessionCount;
        public Dictionary<string, long> ClassCalls = new(StringComparer.Ordinal);
        public List<string> Destinations = new();
        public long ChatSent;
        public long FramesSent;
    }

    /// <summary>The Core's snapshot, rendered verbatim. Called on the
    /// IPC event (background thread) — marshals to the UI thread.</summary>
    public void SetHostState(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetHostState(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var host = new HostState
            {
                CoreVersion = r.GetProperty("coreVersion").GetString() ?? "",
                MachineName = r.GetProperty("machineName").GetString() ?? "",
                Port = r.GetProperty("port").GetInt32(),
                Lanes = r.GetProperty("lanes").EnumerateArray().Select(e => e.GetString() ?? "").ToArray(),
                AgentConnected = r.GetProperty("agentConnected").GetBoolean(),
                DesktopUnlocked = r.GetProperty("desktopUnlocked").GetBoolean(),
                UserStop = r.GetProperty("userStop").GetBoolean(),
                // FR-113: tolerant — an older Core has no fileRoots
                // section; the label then honestly says "Not reported".
                FileRoots = r.TryGetProperty("fileRoots", out var fr)
                    ? fr.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                    : Array.Empty<string>(),
            };
            var s = r.GetProperty("session");
            host.SessionActive = s.GetProperty("active").GetBoolean();
            host.SessionAgent = s.GetProperty("agent").ValueKind == JsonValueKind.String ? s.GetProperty("agent").GetString() : null;
            host.SessionSeconds = s.GetProperty("seconds").GetInt64();
            host.SessionActions = s.GetProperty("actions").GetInt32();
            host.SessionIntent = s.GetProperty("intent").ValueKind == JsonValueKind.String ? s.GetProperty("intent").GetString() : null;
            foreach (var p in r.GetProperty("pairings").EnumerateArray())
            {
                var pid = p.GetProperty("id").GetString() ?? "";
                host.Pairings.Add((
                    pid,
                    p.GetProperty("name").GetString() ?? "",
                    p.GetProperty("scopes").EnumerateArray().Select(e => e.GetString() ?? "").ToArray(),
                    p.GetProperty("revoked").GetBoolean()));
                // W97: connection facts ride the same pairing rows;
                // every field is optional (older Core ⇒ AUTO, no rung).
                host.PairingConnections[pid] = (
                    p.TryGetProperty("connectionMode", out var cm) && cm.ValueKind == JsonValueKind.String ? cm.GetString() ?? "Auto" : "Auto",
                    p.TryGetProperty("connectionRungs", out var cr) && cr.ValueKind == JsonValueKind.Array
                        ? cr.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                        : Array.Empty<string>(),
                    p.TryGetProperty("connectionPin", out var cp) && cp.ValueKind == JsonValueKind.String ? cp.GetString() : null,
                    p.TryGetProperty("currentRung", out var cur) && cur.ValueKind == JsonValueKind.String ? cur.GetString() : null,
                    p.TryGetProperty("currentRungAtUtc", out var ca) && ca.ValueKind == JsonValueKind.String ? ca.GetDateTimeOffset() : null);
            }
            foreach (var g in r.GetProperty("gates").EnumerateArray())
                host.Gates.Add((g.GetProperty("id").GetString() ?? "", g.GetProperty("approved").GetBoolean()));
            foreach (var a in r.GetProperty("audit").EnumerateArray())
            {
                host.Audit.Add((
                    a.GetProperty("atUtc").GetDateTimeOffset(),
                    a.GetProperty("agent").ValueKind == JsonValueKind.String ? a.GetProperty("agent").GetString() : null,
                    a.GetProperty("tool").ValueKind == JsonValueKind.String ? a.GetProperty("tool").GetString() : null,
                    a.GetProperty("operation").ValueKind == JsonValueKind.String ? a.GetProperty("operation").GetString() : null,
                    a.GetProperty("outcome").GetString() ?? "",
                    a.GetProperty("durationMs").ValueKind == JsonValueKind.Number ? a.GetProperty("durationMs").GetInt64() : null));
            }
            ParseRosterSessions(host, r);
            ParseFlowsAndWatches(host, r);
            _host = host;
            _hostAt = DateTimeOffset.Now;
            RefreshDynamics();
        }
        catch { /* a malformed snapshot is ignored; the last good one stays on screen with its age */ }
    }

    /// <summary>W8: parse the snapshot's dataFlows + eventWatches
    /// sections. Tolerant by design: an older Core has neither, and
    /// the surfaces render the empty truth.</summary>
    private static void ParseFlowsAndWatches(HostState host, JsonElement r)
    {
        static long JLong(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
                ? v.GetInt64() : 0;
        static string JStr(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? "" : "";
        if (r.TryGetProperty("dataFlows", out var df) && df.ValueKind == JsonValueKind.Object)
        {
            if (df.TryGetProperty("agents", out var agents) && agents.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in agents.EnumerateArray())
                {
                    var flow = new FlowAgentData
                    {
                        PairingId = JStr(a, "pairingId"),
                        AgentName = JStr(a, "agentName"),
                        SessionCount = (int)JLong(a, "sessions"),
                    };
                    if (a.TryGetProperty("byClass", out var bc) && bc.ValueKind == JsonValueKind.Object)
                        foreach (var cls in bc.EnumerateObject())
                            flow.ClassCalls[cls.Name] = JLong(cls.Value, "calls") is var c && c != 0 ? c
                                : (cls.Value.ValueKind == JsonValueKind.Object ? JLong(cls.Value, "Calls") : 0);
                    if (a.TryGetProperty("destinations", out var dest) && dest.ValueKind == JsonValueKind.Array)
                        foreach (var d in dest.EnumerateArray())
                            if (d.ValueKind == JsonValueKind.String) flow.Destinations.Add(d.GetString() ?? "");
                    if (a.TryGetProperty("tools", out var tools) && tools.ValueKind == JsonValueKind.Array)
                        foreach (var t in tools.EnumerateArray())
                        {
                            var tool = JStr(t, "Tool") is { Length: > 0 } tn ? tn : JStr(t, "tool");
                            var calls = JLong(t, "Calls") != 0 ? JLong(t, "Calls") : JLong(t, "calls");
                            if (tool == "agent_chat") flow.ChatSent += calls;
                            if (tool is "screenshot" or "annotated_screenshot" or "snapshot" or "camera_capture")
                                flow.FramesSent += calls;
                        }
                    host.Flows.Add(flow);
                }
            }
            if (df.TryGetProperty("gaps", out var gaps) && gaps.ValueKind == JsonValueKind.Array)
                foreach (var g in gaps.EnumerateArray())
                    if (g.ValueKind == JsonValueKind.String) host.FlowGaps.Add(g.GetString() ?? "");
        }
        if (r.TryGetProperty("eventWatches", out var ew) && ew.ValueKind == JsonValueKind.Array)
        {
            foreach (var w in ew.EnumerateArray())
            {
                var kinds = new List<string>();
                if (w.TryGetProperty("kinds", out var ks) && ks.ValueKind == JsonValueKind.Array)
                    foreach (var k in ks.EnumerateArray())
                        if (k.ValueKind == JsonValueKind.String) kinds.Add(k.GetString() ?? "");
                var exp = w.TryGetProperty("expiresUtc", out var ev) && ev.ValueKind == JsonValueKind.String
                    && DateTimeOffset.TryParse(ev.GetString(), out var dto) ? dto : DateTimeOffset.MinValue;
                host.EventWatches.Add((JStr(w, "pairingId"), kinds.ToArray(), exp));
            }
        }
        // W122 / N22: the inbox index section. Tolerant like the
        // rest: an older Core has none and no inbox renders.
        if (r.TryGetProperty("chatThreads", out var ct) && ct.ValueKind == JsonValueKind.Array)
        {
            foreach (var t in ct.EnumerateArray())
            {
                var pid = JStr(t, "pairingId");
                if (pid.Length == 0) continue;
                var data = new ChatThreadData
                {
                    UnreadMessages = (int)JLong(t, "unreadMessages"),
                    PendingOrders = (int)JLong(t, "pendingOrders"),
                    LastActivityMs = JLong(t, "lastActivityMs"),
                };
                if (t.TryGetProperty("pendingOrderList", out var pol) && pol.ValueKind == JsonValueKind.Array)
                    foreach (var o in pol.EnumerateArray())
                        data.PendingOrderList.Add(new Acp.Shared.Sessions.ChatOrder(
                            JStr(o, "id"), pid, JStr(o, "tool"),
                            o.TryGetProperty("gateClass", out var gc) && gc.ValueKind == JsonValueKind.String ? gc.GetString() : null,
                            JStr(o, "argumentsJson") is { Length: > 0 } aj ? aj : "{}",
                            JStr(o, "title"), JStr(o, "targetDevice"),
                            Acp.Shared.Sessions.ChatOrderStatus.Pending, null,
                            JLong(o, "createdAtMs"), null));
                host.ChatThreads[pid] = data;
            }
        }
    }

    /// <summary>The Core's pairing-code answer for the pairing page.</summary>
    public void SetPairingCode(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetPairingCode(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var code = doc.RootElement.GetProperty("code").GetString() ?? "";
            var expires = doc.RootElement.GetProperty("expiresUtc").GetDateTimeOffset();
            // W70: Home's Ready card shows this same live code
            // (grouped by three) until it expires.
            _activeCode = code;
            _activeCodeExpires = expires;
            ShowPage("pairing");
            if (_pairingCodeText is not null)
            {
                // W65 / S07: one grouping everywhere — digits in
                // groups of three, one space separator (a 6-digit
                // code renders 3-3, per the token sheet).
                var digits = new string(code.Where(char.IsLetterOrDigit).ToArray());
                _pairingCodeText.Text = string.Join(" ",
                    Enumerable.Range(0, (digits.Length + 2) / 3)
                        .Select(i => digits.Substring(i * 3, Math.Min(3, digits.Length - i * 3))));
                _pairingCodeText.Visibility = Visibility.Visible;
                if (_pairingCodeText.Tag is UIElement noCode) noCode.Visibility = Visibility.Collapsed;
            }
            if (_pairingStatusText is not null)
                _pairingStatusText.Text = Strings.Format("PairingCodeHintFormat", expires.ToLocalTime().ToString("h:mm tt"));
        }
        catch { }
    }

    private async Task RequestHostStateAsync()
    {
        var sender = _hostStateSender;
        if (sender is null) return;
        try { await sender(); } catch { /* the window shows the snapshot's age honestly */ }
    }

    private void OnTick()
    {
        _tick++;
        RefreshDynamics();
        if (_tick % 5 == 0) _ = RequestHostStateAsync();
    }

    // ---------------- Home (W70: pixel-for-pixel rebuild to the
    // Gemini Windows Home & Devices master, 1376x768) ----------------
    // Composition of record: page title, Ready card (state heading +
    // teal pill, live pairing code + Copy, plain body copy), the
    // pill Add button, and the Trusted Helpers card (allow-list with
    // custom-drawn toggles). S04 additions in-language: Background
    // Work row + Last Session line + the allow-list floor sentence
    // under the left column. All values are live: pairings, session
    // state and the pairing code come from the Core snapshot / the
    // pairing flow — mock names and codes are never rendered.
    private TextBlock? _homeHeading;
    private Border? _homePill;
    private TextBlock? _homePillText;
    private StackPanel? _homeCodeArea;
    private StackPanel? _homeHelpersBody;
    private TextBlock? _homeBgText;
    private TextBlock? _homeLastText;
    private string _homeHelpersSignature = "";
    private string? _armedRevokeId;
    private string? _activeCode;
    private DateTimeOffset _activeCodeExpires;

    private static Border HomeCard(UIElement content, double pad = 28)
    {
        var card = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xD5, 0xE1, 0xEA)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(16),
            Padding = new Thickness(pad),
            Child = content,
        };
        card.Effect = new System.Windows.Media.Effects.DropShadowEffect
        {
            Color = Color.FromRgb(0x0F, 0x25, 0x37), BlurRadius = 14, ShadowDepth = 3, Opacity = 0.10,
        };
        return card;
    }

    private UIElement BuildOverviewPage()
    {
        // Fill the content panel: PageHost carries a 26/20 margin for
        // the other pages; Home's measured geometry starts at the
        // panel edge (panel coords: title x+40, cards x+36).
        var root = new Grid { Margin = new Thickness(-26, 31, -26, -4) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(586 + 36) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var title = new TextBlock
        {
            Text = "Home & Devices", FontSize = 58, FontWeight = FontWeights.ExtraBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            Margin = new Thickness(40, 16, 0, 24),
        };
        Grid.SetRow(title, 0); Grid.SetColumnSpan(title, 2);
        root.Children.Add(title);

        // ---- left column: Ready card + Add button + S04 additions ----
        var left = new StackPanel { Margin = new Thickness(36, 0, 0, 0) };

        var ready = new StackPanel();
        var headRow = new Grid();
        headRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _homeHeading = new TextBlock
        {
            Text = "This Computer is Ready", FontSize = 21, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(_homeHeading, 0);
        headRow.Children.Add(_homeHeading);
        _homePillText = new TextBlock
        {
            Text = "Protected & Local", FontSize = 13.5, FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.White,
        };
        _homePill = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x43, 0x8E, 0x8E)),
            CornerRadius = new CornerRadius(20),
            Padding = new Thickness(16, 7, 16, 7),
            VerticalAlignment = VerticalAlignment.Center,
            Child = _homePillText,
        };
        Grid.SetColumn(_homePill, 1);
        headRow.Children.Add(_homePill);
        ready.Children.Add(headRow);

        _homeCodeArea = new StackPanel { Margin = new Thickness(0, 26, 0, 0), MinHeight = 196 };
        ready.Children.Add(_homeCodeArea);
        var readyCard = HomeCard(ready);
        // S04 residual (W85): the reference's own Ready-card height
        // is 334 — the build had drifted to 343. Back at 334 (with
        // the Add button's spacing below tightened by the same
        // pass) the left column's whole stack — card, Add button,
        // Background Work row, Last Session line and the floor
        // sentence — fits the 768 window height: the floor
        // sentence renders fully, never half-clipped.
        readyCard.Height = 334;
        left.Children.Add(readyCard);

        var add = new Button
        {
            Height = 85, Margin = new Thickness(0, 50, 0, 0), Cursor = System.Windows.Input.Cursors.Hand,
            Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x88, 0xD4)),
            Foreground = Brushes.White, BorderThickness = new Thickness(0),
            Content = new TextBlock { Text = "+  Add Device or AI", FontSize = 20, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White },
        };
        // Custom-drawn pill: stock Button chrome cannot reach the
        // master's 42px pill radius, so the template is a Border.
        var addFactory = new FrameworkElementFactory(typeof(Border));
        addFactory.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("Background") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        addFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(42));
        var addPresenter = new FrameworkElementFactory(typeof(ContentPresenter));
        addPresenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        addPresenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        addFactory.AppendChild(addPresenter);
        add.Template = new ControlTemplate(typeof(Button)) { VisualTree = addFactory };
        add.Click += (_, _) => ShowPage("pairing");
        left.Children.Add(add);

        // S04 (c): Background Work status row (L1 never-zero-presence).
        var bgRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 6, 0, 0) };
        bgRow.Children.Add(new TextBlock { Text = "Background Work", FontSize = 13.5, FontWeight = FontWeights.SemiBold });
        _homeBgText = Muted("  ·  No agent is working in the background right now.", 13);
        bgRow.Children.Add(_homeBgText);
        left.Children.Add(bgRow);
        _homeLastText = Muted("", 13);
        _homeLastText.Margin = new Thickness(4, 0, 0, 0);
        left.Children.Add(_homeLastText);
        // S04 (a): the allow-list floor sentence, verbatim of record.
        var floorLine = Muted("People you allow can ask to connect. You will always see who is here, and STOP always works — that can never be turned off.", 11.5);
        floorLine.Margin = new Thickness(4, 0, 0, 0);
        left.Children.Add(floorLine);
        Grid.SetRow(left, 1); Grid.SetColumn(left, 0);
        root.Children.Add(left);

        // ---- right column: Trusted Helpers ----
        // W131: the column is a Grid, not a StackPanel — a
        // ScrollViewer inside a vertical StackPanel is measured
        // with unbounded height, so it grows to its full content
        // (measured live: 3,972px) and can never scroll; every
        // roster row below the card's fixed frame was clipped and
        // unreachable. The star row bounds the roster viewport to
        // the card's fixed 469 frame, as W123 intended.
        var helpers = new Grid();
        helpers.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        helpers.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        helpers.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var helpersTitle = new TextBlock
        {
            Text = "Trusted Helpers", FontSize = 21, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
        };
        Grid.SetRow(helpersTitle, 0);
        helpers.Children.Add(helpersTitle);
        var sub = Muted("Manage who can connect to this computer.", 13.5);
        sub.Margin = new Thickness(0, 4, 0, 18);
        Grid.SetRow(sub, 1);
        helpers.Children.Add(sub);
        _homeHelpersBody = new StackPanel();
        // W123: the reference's Helpers card is a FIXED 400x469 frame.
        // W70 built MinHeight=469 and the card grew with the roster;
        // with the post-W70 rows (W120 state lines, W122 inbox, Chat +
        // Access per row) it now fills the whole panel and the page
        // scrolls. The card keeps its measured frame and the roster
        // scrolls INSIDE it — no behavior is removed, the lens and
        // every row stay reachable.
        var helpersScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = _homeHelpersBody,
        };
        Grid.SetRow(helpersScroll, 2);
        helpers.Children.Add(helpersScroll);
        var helpersCard = HomeCard(helpers);
        helpersCard.Height = 469;
        helpersCard.Margin = new Thickness(22, 0, 36, 0);
        Grid.SetRow(helpersCard, 1); Grid.SetColumn(helpersCard, 1);
        root.Children.Add(helpersCard);
        return root;
    }

    private void RefreshDynamics()
    {
        // Sidebar mesh line for this PC follows presence truth.
        if (_presence is not null)
        {
            var (mode, stopInForce, sessionActive, name, _, _) = _presence.ViewState;
            MeshThisPcName.Text = $"This PC · {_host?.MachineName ?? "this PC"}";
            MeshThisPcState.Text = stopInForce ? Strings.Get("MeshBlockedStop")
                : sessionActive ? Strings.Format("MeshActiveSessionFormat", name)
                : "Idle";
            MeshThisPcState.Foreground = new SolidColorBrush(sessionActive && !stopInForce ? Color.FromRgb(0x03, 0x69, 0xA1) : Color.FromRgb(0x48, 0x61, 0x75));
        }
        switch (_currentPage)
        {
            case "overview": RenderOverview(); break;
            case "guardrails": RenderGateStates(); RenderPolicy(); break;
            case "audit": RenderAudit(); break;
            case "pairing": RenderChecklist(); break;
            case "agentdetail": RenderAgentAccess(); break;
            case "roster": RenderRoster(); break;
            case "sessions": RenderSessions(); break;
            case "enterprise": RenderEnterprise(); break;
            case "services": RenderBlockG(); break;
        }
    }

    private void RenderOverview()
    {
        if (_homeHeading is null || _homeCodeArea is null) return;
        var unlocked = _desktopUnlocked?.Invoke() ?? false;
        var (mode, stopInForce, sessionActive, name, seconds, actions) = _presence is null
            ? (default(Acp.Shared.Presence.PresenceMode), false, false, "", 0L, 0)
            : _presence.ViewState;
        var connected = _host is not null && _host.AgentConnected;

        // ---- Ready card state ----
        _homeCodeArea.Children.Clear();
        if (_presence is null)
        {
            _homeHeading.Text = "Starting…";
            SetHomePill("Starting", GrayBg, GrayFg, dark: false);
            _homeCodeArea.Children.Add(Body("DeskGuest is starting on this computer."));
        }
        else if (stopInForce)
        {
            _homeHeading.Text = Strings.Get("StopIsInForce");
            SetHomePill("Stopped", GrayBg, GrayFg, dark: false);
            _homeCodeArea.Children.Add(Body(Strings.Format("BlockedNameFormat", name), 15));
            _homeCodeArea.Children.Add(Body(Strings.Get("StopInForceBody")));
            var clear = new Button { Content = Strings.Get("ClearStopAllowAgents"), Style = (Style)FindResource("PrimaryButton"), Margin = new Thickness(0, 14, 0, 0), HorizontalAlignment = HorizontalAlignment.Left };
            clear.Click += async (_, _) => await SendStopClearAsync();
            _homeCodeArea.Children.Add(clear);
        }
        else if (sessionActive)
        {
            _homeHeading.Text = $"{name} is controlling this computer";
            SetHomePill("Session in progress", GrayBg, GrayFg, dark: false);
            var facts = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            facts.Children.Add(new TextBlock { Text = FormatClock(seconds), FontSize = 30, FontWeight = FontWeights.SemiBold, FontFamily = new FontFamily("Consolas") });
            var chip = Chip(actions == 1 ? Strings.Get("ActionSingular") : Strings.Format("ActionsFormat", actions), GrayBg, GrayFg);
            chip.Margin = new Thickness(12, 0, 0, 0);
            facts.Children.Add(chip);
            _homeCodeArea.Children.Add(facts);
            var intent = _host?.SessionIntent;
            _homeCodeArea.Children.Add(Muted(string.IsNullOrWhiteSpace(intent) ? Strings.Get("PresenceIntentFallback") : Strings.Format("CurrentIntentFormat", intent)));
            var stop = new Button { Content = Strings.Get("Stop"), Style = (Style)FindResource("DangerButton"), Margin = new Thickness(0, 14, 0, 0), HorizontalAlignment = HorizontalAlignment.Stretch };
            stop.Click += async (_, _) => await SendStopAsync();
            _homeCodeArea.Children.Add(stop);
        }
        else
        {
            _homeHeading.Text = "This Computer is Ready";
            SetHomePill(connected ? "Protected & Local" : "Not connected",
                connected ? Color.FromRgb(0x43, 0x8E, 0x8E) : GrayBg,
                connected ? Colors.White : GrayFg, dark: connected);
            RenderHomeCode();
        }

        // ---- Background Work + Last Session (S04 additions) ----
        if (_homeBgText is not null)
            _homeBgText.Text = sessionActive
                ? $"  ·  {name} is in a live session on screen — not background work."
                : "  ·  No agent is working in the background right now.";
        if (_homeLastText is not null)
        {
            var last = _host?.HumanSessions.LastOrDefault();
            _homeLastText.Text = last is null
                ? "Last Session:  No sessions yet."
                : $"Last Session:  {last.Initiator} · {last.Kind} · {last.State} · {FormatClock(last.Seconds)}";
        }

        RenderHomeHelpers();
    }

    private void SetHomePill(string text, Color bg, Color fg, bool dark)
    {
        if (_homePill is null || _homePillText is null) return;
        _homePill.Background = new SolidColorBrush(bg);
        _homePillText.Text = text;
        _homePillText.Foreground = new SolidColorBrush(fg);
    }

    /// <summary>The code slot of the Ready card (idle state): the
    /// REAL pairing code minted through the Pair page in this
    /// window session, grouped by three (S07 format of record),
    /// with the master's Copy affordance. No code is minted by
    /// opening Home — minting creates a pending pairing, which is
    /// the Pair page's deliberate act.</summary>
    private void RenderHomeCode()
    {
        if (_homeCodeArea is null) return;
        var code = _activeCode is not null && DateTimeOffset.Now < _activeCodeExpires ? _activeCode : null;
        if (code is null)
        {
            var none = new TextBlock
            {
                Text = "No code right now", FontSize = 24, FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
                HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 18, 0, 10),
            };
            _homeCodeArea.Children.Add(none);
            _homeCodeArea.Children.Add(new TextBlock
            {
                Text = "Tap + Add Device or AI to make a pairing code — it will appear here. Give it only to a helper you trust. You will always watch their activity and can stop them instantly.",
                FontSize = 15, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center,
                MaxWidth = 500, HorizontalAlignment = HorizontalAlignment.Center,
            });
            return;
        }
        var digits = new string(code.Where(char.IsLetterOrDigit).ToArray());
        var grouped = string.Join("  ", Enumerable.Range(0, (digits.Length + 2) / 3)
            .Select(i => digits.Substring(i * 3, Math.Min(3, digits.Length - i * 3))));
        // W123: the reference's digits sit at y346-396 (card-relative
        // 133-183); the build's row rode ~45px high. The margin puts
        // the live code on the reference's line; the body copy and
        // the live expiry line follow it down inside the fixed card.
        var row = new Grid { Margin = new Thickness(0, 48, 0, 0) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var codeText = new TextBlock
        {
            Text = grouped, FontSize = 30, FontWeight = FontWeights.ExtraBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(codeText, 0);
        row.Children.Add(codeText);
        var copyStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Cursor = System.Windows.Input.Cursors.Hand };
        var copyIcon = new Canvas { Width = 26, Height = 26, HorizontalAlignment = HorizontalAlignment.Center };
        var rectBack = new System.Windows.Shapes.Rectangle { Width = 15, Height = 18, Stroke = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)), StrokeThickness = 1.8 };
        Canvas.SetLeft(rectBack, 8); Canvas.SetTop(rectBack, 1);
        copyIcon.Children.Add(rectBack);
        var rectFront = new System.Windows.Shapes.Rectangle { Width = 15, Height = 18, Stroke = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)), StrokeThickness = 1.8, Fill = Brushes.White };
        Canvas.SetLeft(rectFront, 3); Canvas.SetTop(rectFront, 7);
        copyIcon.Children.Add(rectFront);
        copyStack.Children.Add(copyIcon);
        copyStack.Children.Add(new TextBlock { Text = "Copy", FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 3, 0, 0) });
        copyStack.MouseLeftButtonUp += (_, _) =>
        {
            try { System.Windows.Clipboard.SetText(grouped); } catch { /* clipboard busy: the code stays on screen */ }
        };
        Grid.SetColumn(copyStack, 1);
        row.Children.Add(copyStack);
        _homeCodeArea.Children.Add(row);
        _homeCodeArea.Children.Add(new TextBlock
        {
            // LC-1 (L6): the reference copy says "6-digit code"; the
            // real Windows code is longer, so the numeral is dropped
            // rather than lied about.
            Text = "Give this code to a trusted helper or enter it on another device to securely link them. You will always watch their activity and can stop them instantly.",
            FontSize = 15, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center,
            MaxWidth = 500, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 22, 0, 0),
        });
        _homeCodeArea.Children.Add(Muted($"Code expires at {_activeCodeExpires.ToLocalTime():h:mm tt} — after that, make a new one.", 12));
    }

    /// <summary>Custom-drawn allow-list toggle (stock WPF ToggleButton
    /// chrome cannot match the master's teal pill switch): teal track
    /// + white knob when allowed; gray track + left knob when revoked.
    /// Clicking an ON toggle arms revocation; a second click revokes
    /// through the same Core channel as Unpair.</summary>
    private Border BuildHelperToggle(string pairingId, bool allowed)
    {
        var armed = _armedRevokeId == pairingId;
        var track = new Border
        {
            Width = 58, Height = 32, CornerRadius = new CornerRadius(16),
            Background = new SolidColorBrush(allowed && !armed ? Color.FromRgb(0x43, 0x8E, 0x8E) : Color.FromRgb(0xC3, 0xCF, 0xD9)),
            Cursor = allowed ? System.Windows.Input.Cursors.Hand : System.Windows.Input.Cursors.Arrow,
            ToolTip = allowed ? (armed ? "Click again to stop allowing this helper" : "Allowed — click to stop allowing") : "Revoked",
        };
        var knob = new Border
        {
            Width = 26, Height = 26, CornerRadius = new CornerRadius(13),
            Background = Brushes.White, HorizontalAlignment = allowed ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Margin = new Thickness(3),
        };
        track.Child = knob;
        if (allowed)
        {
            track.MouseLeftButtonUp += async (_, _) =>
            {
                if (_armedRevokeId != pairingId)
                {
                    _armedRevokeId = pairingId;
                    RefreshDynamics();
                    return;
                }
                _armedRevokeId = null;
                if (_pairingRevokeSender is not null && await _pairingRevokeSender(pairingId))
                    _ = RequestHostStateAsync();
                RefreshDynamics();
            };
        }
        return track;
    }

    private void RenderHomeHelpers()
    {
        if (_homeHelpersBody is null) return;
        var pairings = _host?.Pairings ?? new List<(string Id, string Name, string[] Scopes, bool Revoked)>();
        var sessSig = _presence is null ? "-" : _presence.ViewState.SessionActive + ":" + _presence.ViewState.DisplayName;
        var signature = string.Join("|", pairings.Select(p => $"{p.Id}:{p.Name}:{p.Revoked}:{_chatOpenPairingId == p.Id}")) + "#" + (_armedRevokeId ?? "") + "#chat:" + _chatSignature + "#sess:" + sessSig + "#inbox:" + InboxSignature();
        if (signature == _homeHelpersSignature) return;
        _homeHelpersSignature = signature;
        _homeHelpersBody.Children.Clear();
        if (_host is null)
        {
            _homeHelpersBody.Children.Add(Muted("Waiting for the Core…"));
            return;
        }
        if (pairings.Count == 0)
        {
            _homeHelpersBody.Children.Add(Body("No helpers yet."));
            _homeHelpersBody.Children.Add(Muted("Pair an AI with + Add Device or AI and it will be listed here."));
            return;
        }
        // W122 / N22: the unified inbox lens sits above the
        // agent cards the threads live with — an index over the
        // same threads, not a second home for them.
        RenderInboxSection(pairings);
        foreach (var (id, pname, scopes, revoked) in pairings)
        {
            var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            // Agent identity tile: the A3 mark on the gold tile, as
            // the master draws the AI helper (kit art, not a drawing).
            var tile = new Border
            {
                Width = 64, Height = 64, CornerRadius = new CornerRadius(14),
                Background = new SolidColorBrush(Color.FromRgb(0xE5, 0xA9, 0x3B)),
                Child = new System.Windows.Controls.Image
                {
                    Width = 50, Height = 50,
                    Source = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/deskguest-mark-tight.png")),
                    HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                },
            };
            Grid.SetColumn(tile, 0);
            row.Children.Add(tile);
            var texts = new StackPanel { Margin = new Thickness(16, 2, 0, 0) };
            texts.Children.Add(new TextBlock { Text = pname, FontSize = 17, FontWeight = FontWeights.SemiBold });
            texts.Children.Add(Muted(revoked ? "Revoked" : _armedRevokeId == id ? "Click the switch again to stop allowing" : $"Allowed · {ScopeSummary(scopes)}", 13));
            var flowForAgent = _host.Flows.FirstOrDefault(f => f.PairingId == id);
            if (!revoked && flowForAgent is not null && flowForAgent.ChatSent > 0)
                texts.Children.Add(Muted(Strings.Format("ChatSentCountFormat", flowForAgent.ChatSent), 12));
            // W122 / N22: the thread's state lives with its agent
            // card — the same two-class line the inbox lens row
            // shows for this pairing (waiting dominates unread;
            // a quiet thread claims nothing here).
            if (!revoked && InboxFacts(id) is { } cardData &&
                Acp.Shared.Sessions.ChatInboxModel.StateLine(pname, cardData.Facts(id)) is { } cardState)
            {
                var cardWaiting = cardData.PendingOrders > 0;
                texts.Children.Add(new TextBlock
                {
                    Text = cardState, FontSize = 12, TextWrapping = TextWrapping.Wrap,
                    FontWeight = cardWaiting ? FontWeights.SemiBold : FontWeights.Normal,
                    Foreground = InboxStateBrush(cardWaiting),
                });
            }
            Grid.SetColumn(texts, 1);
            row.Children.Add(texts);
            var onLabel = new TextBlock
            {
                Text = revoked ? "OFF" : "ON", FontSize = 13, FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0),
            };
            Grid.SetColumn(onLabel, 2);
            row.Children.Add(onLabel);
            var toggleHost = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            toggleHost.Children.Add(BuildHelperToggle(id, !revoked));
            Grid.SetColumn(toggleHost, 3);
            row.Children.Add(toggleHost);
            _homeHelpersBody.Children.Add(row);
            // W123: one shared button row per agent (Chat + Access),
            // aligned to the text column (tile 64 + margin 16 = 80).
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(80, 0, 0, 3) };
            // The agent chat thread lives on the agent's row (§8
            // record) — kept from the previous Home, in-language.
            if (!revoked)
            {
                var capturedChatId = id;
                var chatToggle = new Button
                {
                    Content = _chatOpenPairingId == id ? "Close chat" : "Chat",
                    Style = (Style)FindResource("GhostButton"),
                    FontSize = 12, Padding = new Thickness(10, 3, 10, 3),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(0, 0, 6, 0),
                };
                chatToggle.Click += async (_, _) =>
                {
                    if (_chatOpenPairingId == capturedChatId)
                    {
                        _chatOpenPairingId = null;
                        _chatMessages.Clear();
                        RefreshDynamics();
                        return;
                    }
                    _chatOpenPairingId = capturedChatId;
                    _chatMessages.Clear();
                    RefreshDynamics();
                    if (_chatThreadSender is not null) await _chatThreadSender(capturedChatId);
                };
                btnRow.Children.Add(chatToggle);
            }
            // W79 / S08: the access-control surface lives on the
            // pairing/agent card — one click to this helper's
            // slider + Fine-tune page.
            {
                var capturedAccessId = id;
                var accessBtn = new Button
                {
                    Content = "Access",
                    Style = (Style)FindResource("GhostButton"),
                    FontSize = 12, Padding = new Thickness(10, 3, 10, 3),
                    HorizontalAlignment = HorizontalAlignment.Left,
                };
                accessBtn.Click += (_, _) => OpenAgentAccess(capturedAccessId);
                btnRow.Children.Add(accessBtn);
            }
            if (btnRow.Children.Count > 0)
                _homeHelpersBody.Children.Add(btnRow);
            if (!revoked && _chatOpenPairingId == id)
                _homeHelpersBody.Children.Add(BuildChatPanel(id, pname));
        }
    }

    private static string ScopeSummary(string[] scopes)
    {
        var set = new HashSet<string>(scopes);
        if (set.Contains("drive") && set.Contains("shell")) return "Full control";
        if (set.Count == 1 && set.Contains("observe")) return "Look only";
        return string.Join(" · ", scopes);
    }

    private static string FormatClock(long seconds)
    {
        var t = TimeSpan.FromSeconds(Math.Max(0, seconds));
        return t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:D2}:{t.Seconds:D2}" : $"{t.Minutes:D2}:{t.Seconds:D2}";
    }

    private async Task SendStopAsync()
    {
        var sender = _stopSender;
        if (sender is null) return;
        await sender();
        RefreshDynamics();
    }

    private async Task SendStopClearAsync()
    {
        var sender = _stopClearSender;
        if (sender is null) return;
        await sender();
        RefreshDynamics();
    }

    // ---------------- Pairing page (W75: pixel-for-pixel rebuild
    // to Gemini Board 03, Screen 7 "Add a Device" — the S07 floor;
    // disposition ADDED-IN-LANGUAGE per REVISION-DRAFT §2.1) --------
    // Composition of record: page title, then two columns. Left:
    // Step 1 role card (numbered signpost — the W58 zero-knowledge
    // fix), then the Pair card (name, access presets, the blue
    // Create button, the "Your Pairing Code" zone with the LIVE
    // grouped-hex code + Copy, expiry + live countdown, the trust
    // copy of record, the reachable-address line, the waiting /
    // paired line). Right: the reference's welcome block (words +
    // kit wave mascot in a white card), the "Enter code from
    // another device" card (wired to the real EnrollmentRedeem host
    // action — it enrolls THIS PC, and says so), and the Host
    // Readiness Checklist card. Mock codes and mock devices are
    // never rendered; every value is live product state.

    private static Button PairPrimaryButton(string text)
    {
        var b = new Button
        {
            Height = 56, Cursor = System.Windows.Input.Cursors.Hand,
            Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x88, 0xD4)),
            Foreground = Brushes.White, BorderThickness = new Thickness(0),
            Content = new TextBlock { Text = text, FontSize = 17, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White },
        };
        // Custom-drawn: stock Button chrome cannot reach the
        // reference's button radius at this height.
        var factory = new FrameworkElementFactory(typeof(Border));
        factory.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("Background") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(12));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        factory.AppendChild(presenter);
        b.Template = new ControlTemplate(typeof(Button)) { VisualTree = factory };
        return b;
    }

    private void SelectRole(string roleId)
    {
        _setupRole = roleId;
        foreach (var (id, row) in _roleRows)
        {
            var selected = id == roleId;
            row.Background = new SolidColorBrush(selected ? Color.FromRgb(0xE6, 0xEE, 0xF4) : Color.FromRgb(0xFF, 0xFF, 0xFF));
            row.BorderBrush = new SolidColorBrush(selected ? Color.FromRgb(0x2F, 0x8B, 0xC9) : Color.FromRgb(0xD5, 0xE1, 0xEA));
            row.BorderThickness = new Thickness(selected ? 2 : 1);
        }
    }

    private UIElement BuildPairingPage()
    {
        // Fill the content panel like Home (W70): PageHost carries a
        // 26/20 margin for the other pages; this page's measured
        // geometry starts at the panel edge.
        var root = new Grid { Margin = new Thickness(-26, 31, -26, -4) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(586 + 36) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var titleBlock = new StackPanel { Margin = new Thickness(40, 16, 0, 26) };
        titleBlock.Children.Add(new TextBlock
        {
            Text = "Add a Device", FontSize = 58, FontWeight = FontWeights.ExtraBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
        });
        titleBlock.Children.Add(new TextBlock
        {
            Text = "Setup & pairing — pairing happens on this PC, in this window, never remotely, never from a file.",
            FontSize = 15, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(2, 6, 0, 0),
        });
        Grid.SetRow(titleBlock, 0); Grid.SetColumnSpan(titleBlock, 2);
        root.Children.Add(titleBlock);

        // ---- left column: Step 1 role card + Pair card ----
        var left = new StackPanel { Margin = new Thickness(36, 0, 0, 0) };
        Grid.SetRow(left, 1); Grid.SetColumn(left, 0);

        var roleStack = new StackPanel();
        roleStack.Children.Add(new TextBlock
        {
            Text = Acp.Shared.Design.SetupWizardModel.StepLabel(0) + " — What is this PC for?",
            FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            Margin = new Thickness(0, 0, 0, 4),
        });
        roleStack.Children.Add(Muted("Choose the role that fits — it sets this PC's defaults. You can change it later in setup.", 13));
        _roleRows.Clear();
        var roleList = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        foreach (var role in Acp.Shared.Design.SetupWizardModel.Roles)
        {
            var captured = role;
            var inner = new StackPanel { Margin = new Thickness(14, 9, 14, 9) };
            inner.Children.Add(new TextBlock { Text = role.Title, FontSize = 14.5, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            inner.Children.Add(Muted(role.Consequence, 12));
            var rowBorder = new Border
            {
                Child = inner, CornerRadius = new CornerRadius(12),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0xD5, 0xE1, 0xEA)), BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 6), Cursor = System.Windows.Input.Cursors.Hand,
            };
            rowBorder.MouseLeftButtonUp += (_, _) => SelectRole(captured.Id);
            _roleRows[role.Id] = rowBorder;
            roleList.Children.Add(rowBorder);
        }
        roleStack.Children.Add(roleList);
        var roleCard = HomeCard(roleStack);
        roleCard.Margin = new Thickness(0, 0, 0, 14);
        left.Children.Add(roleCard);
        SelectRole(_setupRole);

        var pair = new StackPanel();
        pair.Children.Add(new TextBlock
        {
            Text = Acp.Shared.Design.SetupWizardModel.StepLabel(2) + " — Pair Your AI",
            FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            Margin = new Thickness(0, 0, 0, 4),
        });
        pair.Children.Add(Muted("Authorize and sync connection", 13));
        pair.Children.Add(new TextBlock { Text = "Your AI's name", FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 4) });
        _pairingNameBox = new TextBox { Text = "Muse", FontSize = 14.5, Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 0, 0, 10) };
        pair.Children.Add(_pairingNameBox);
        _presetFull = new RadioButton { Content = "Full control (drive, shell, admin)", IsChecked = true, FontSize = 13.5, Margin = new Thickness(0, 0, 0, 4), GroupName = "preset" };
        pair.Children.Add(_presetFull);
        pair.Children.Add(new RadioButton { Content = "Look only (observe)", FontSize = 13.5, Margin = new Thickness(0, 0, 0, 12), GroupName = "preset" });

        // W97 / S09(b): the connection-mode choice at mint —
        // compact, in-language, default AUTO. The Core binds the
        // choice to the code (the helper can't widen it later
        // without the owner changing it on the agent card).
        pair.Children.Add(new TextBlock { Text = "How this helper may connect", FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 4) });
        var mintAuto = new RadioButton { Content = "Auto — any working path", IsChecked = true, FontSize = 13.5, Margin = new Thickness(0, 0, 0, 4), GroupName = "mintconn" };
        _mintConnRestricted = new RadioButton { Content = "Auto, only the paths I pick", FontSize = 13.5, Margin = new Thickness(0, 0, 0, 4), GroupName = "mintconn" };
        _mintConnManual = new RadioButton { Content = "Manual — one pinned path", FontSize = 13.5, Margin = new Thickness(0, 0, 0, 4), GroupName = "mintconn" };
        pair.Children.Add(mintAuto);
        pair.Children.Add(_mintConnRestricted);
        pair.Children.Add(_mintConnManual);
        _mintConnRungs.Clear();
        _mintConnSubsetPanel = new StackPanel { Margin = new Thickness(18, 2, 0, 6), Visibility = Visibility.Collapsed };
        foreach (var rung in Acp.Shared.Security.ConnectionPathPolicy.Rungs)
        {
            var cb = new CheckBox { Content = rung.PlainName, IsChecked = true, FontSize = 13, Margin = new Thickness(0, 2, 0, 0) };
            _mintConnRungs[rung.Id] = cb;
            _mintConnSubsetPanel.Children.Add(cb);
        }
        pair.Children.Add(_mintConnSubsetPanel);
        _mintConnPins.Clear();
        _mintConnPinPanel = new StackPanel { Margin = new Thickness(18, 2, 0, 6), Visibility = Visibility.Collapsed };
        foreach (var rung in Acp.Shared.Security.ConnectionPathPolicy.Rungs)
        {
            var rb = new RadioButton { Content = rung.PlainName, IsChecked = rung.Id == "mesh", FontSize = 13, Margin = new Thickness(0, 2, 0, 0), GroupName = "mintpin" };
            _mintConnPins[rung.Id] = rb;
            _mintConnPinPanel.Children.Add(rb);
        }
        pair.Children.Add(_mintConnPinPanel);
        void MintConnVisibility()
        {
            if (_mintConnSubsetPanel is not null)
                _mintConnSubsetPanel.Visibility = _mintConnRestricted?.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            if (_mintConnPinPanel is not null)
                _mintConnPinPanel.Visibility = _mintConnManual?.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }
        mintAuto.Checked += (_, _) => MintConnVisibility();
        _mintConnRestricted.Checked += (_, _) => MintConnVisibility();
        _mintConnManual.Checked += (_, _) => MintConnVisibility();
        var create = PairPrimaryButton("Create pairing code");
        create.HorizontalAlignment = HorizontalAlignment.Stretch;
        create.Click += async (_, _) =>
        {
            var sender = _pairingCreateSender;
            if (sender is null)
            {
                if (_pairingStatusText is not null) _pairingStatusText.Text = "Not connected to the Core — no code was minted.";
                return;
            }
            // W8 (§5): the reachability gate — no reachable remote
            // address, no code is minted (W4-B F8 rule).
            var reachable = _host?.Lanes.FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
            if (!Acp.Shared.Design.SetupWizardModel.MayMintCode(reachable))
            {
                if (_pairingStatusText is not null)
                    _pairingStatusText.Text = "No reachable address on this PC yet — no code was minted. Connect a transport first.";
                return;
            }
            var preset = _presetFull?.IsChecked == true ? "full_control" : "look_only";
            var sent = await sender(_pairingNameBox?.Text?.Trim() ?? "", preset, MintConnectionJson());
            if (_pairingStatusText is not null)
                _pairingStatusText.Text = sent ? "Code requested from the Core…" : "Not connected to the Core — no code was minted.";
        };
        pair.Children.Add(create);

        // The code zone — the reference's "Your Pairing Code" card,
        // carried inside the Pair card as its display well.
        var codeWell = new Border
        {
            // The reference's code card is pure white; the well
            // matches it (its border carries the separation from
            // the Pair card's white).
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xD5, 0xE1, 0xEA)), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(12), Margin = new Thickness(0, 16, 0, 0), Padding = new Thickness(18, 14, 18, 14),
        };
        var well = new StackPanel();
        well.Children.Add(new TextBlock
        {
            Text = "Your Pairing Code", FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
        });
        _pairingCodeText = new TextBlock
        {
            // The real Windows code is the built grouped-hex form —
            // longer than the floor's mock digits; sized and wrapped
            // so the whole code is always visible (as on Home).
            FontSize = 30, FontWeight = FontWeights.ExtraBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center,
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 4),
            Visibility = Visibility.Collapsed,
        };
        well.Children.Add(_pairingCodeText);
        var noCode = Muted(Strings.Get("PairingNoCodeYet"), 13);
        noCode.HorizontalAlignment = HorizontalAlignment.Center;
        noCode.Margin = new Thickness(0, 10, 0, 4);
        well.Children.Add(noCode);
        _pairingCodeText.Tag = noCode;
        _pairingStatusText = Muted("");
        _pairingStatusText.HorizontalAlignment = HorizontalAlignment.Center;
        _pairingStatusText.TextAlignment = TextAlignment.Center;
        well.Children.Add(_pairingStatusText);
        codeWell.Child = well;
        pair.Children.Add(codeWell);

        pair.Children.Add(new TextBlock
        {
            Text = Strings.Get("PairingTrustLine"), FontSize = 13.5, TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(2, 12, 0, 0),
        });
        _pairingReachText = Muted("", 13);
        _pairingReachText.Margin = new Thickness(2, 4, 0, 0);
        pair.Children.Add(_pairingReachText);
        // W8 (§5): before redemption the pair step shows ONLY the
        // waiting line — the agent's name and the paired state
        // appear after the code is redeemed (SetupWizardModel).
        _pairingSasText = Muted(Strings.Get("WizardWaitingForAi"), 13);
        _pairingSasText.Margin = new Thickness(2, 4, 0, 0);
        pair.Children.Add(_pairingSasText);
        var pairCard = HomeCard(pair);
        left.Children.Add(pairCard);
        root.Children.Add(left);

        // ---- right column: welcome + enter-theirs + checklist ----
        var right = new StackPanel { Margin = new Thickness(22, 0, 36, 0) };
        Grid.SetRow(right, 1); Grid.SetColumn(right, 1);

        // W126: the reference draws the welcome zone as a portrait
        // strip ON THE CANVAS — text over the waving mascot, neither
        // inside a white card (Board 03 S07 panel, right edge). W75
        // built one landscape white card (text left, mascot right);
        // this rebuilds the zone to the reference's composition.
        // The kit wave art's ground is opaque white (verified), so
        // the mascot stands on a borderless white rounded ground —
        // no border, no shadow — the honest frame for white-ground
        // art, matching the reference's white-blended mascot zone.
        var welcome = new StackPanel();
        welcome.Children.Add(new TextBlock
        {
            Text = "Welcome to the connection.", FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            // W126: the reference's strip is narrow — its text wraps
            // to two lines ("Welcome to the / connection.") at the
            // mascot's width. The column is wider, so the wrap is
            // set explicitly at the mascot ground's 240 width.
            TextWrapping = TextWrapping.Wrap, Width = 240,
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(2, 6, 0, 10),
        });
        var wave = new System.Windows.Controls.Image
        {
            Width = 240, Height = 240, HorizontalAlignment = HorizontalAlignment.Left,
            Source = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/deskguest-wave.png")),
        };
        var waveGround = new Border
        {
            Background = Brushes.White, CornerRadius = new CornerRadius(16),
            Child = wave, HorizontalAlignment = HorizontalAlignment.Left,
        };
        welcome.Children.Add(waveGround);
        welcome.Margin = new Thickness(0, 0, 0, 14);
        right.Children.Add(welcome);

        var enter = new StackPanel();
        enter.Children.Add(new TextBlock
        {
            Text = "Enter code from another device", FontSize = 17, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            Margin = new Thickness(0, 0, 0, 4),
        });
        enter.Children.Add(Muted(Strings.Get("PairingEnterHint"), 12.5));
        _enterCodeBox = new TextBox { FontSize = 14.5, Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 10, 0, 8) };
        enter.Children.Add(_enterCodeBox);
        enter.Children.Add(new TextBlock { Text = "This PC's name", FontSize = 12.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        _enterNameBox = new TextBox { FontSize = 14.5, Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 0, 0, 12), Text = Environment.MachineName };
        enter.Children.Add(_enterNameBox);
        var connect = PairPrimaryButton("Connect");
        connect.HorizontalAlignment = HorizontalAlignment.Stretch;
        // W126: the reference's Connect button is inset ~6% of the
        // card's width from its edges (x178–330 in card x167–341).
        connect.Margin = new Thickness(10, 0, 10, 0);
        connect.Click += async (_, _) =>
        {
            await SendHostActionAsync(IpcKinds.EnrollmentRedeem,
                new { code = _enterCodeBox?.Text.Trim() ?? "", displayName = _enterNameBox?.Text.Trim() ?? "", rosterScopeId = (string?)null, mintedByUserId = (string?)null },
                _enterStatusText);
        };
        enter.Children.Add(connect);
        _enterStatusText = Muted("");
        _enterStatusText.Margin = new Thickness(2, 8, 0, 0);
        enter.Children.Add(_enterStatusText);
        var enterCard = HomeCard(enter);
        enterCard.Margin = new Thickness(0, 0, 0, 14);
        right.Children.Add(enterCard);

        var checkStack = new StackPanel();
        checkStack.Children.Add(new TextBlock
        {
            Text = "Host Readiness Checklist", FontSize = 17, FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x25, 0x37)),
            Margin = new Thickness(0, 0, 0, 4),
        });
        checkStack.Children.Add(Muted("Requirements checklist — every line is a live fact, checked now.", 12.5));
        _checklistBody = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
        checkStack.Children.Add(_checklistBody);
        right.Children.Add(HomeCard(checkStack));
        root.Children.Add(right);

        RenderChecklist();
        return root;
    }

    /// <summary>W97: the Pair card's connection choice as the
    /// mint payload's "connection" object; null for AUTO (the
    /// Core's default — nothing extra rides the mint).</summary>
    private string? MintConnectionJson()
    {
        if (_mintConnRestricted?.IsChecked == true)
        {
            var rungs = _mintConnRungs.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).OrderBy(s => s).ToArray();
            return System.Text.Json.JsonSerializer.Serialize(new { mode = "restricted", allowedRungs = rungs, pinnedRung = (string?)null });
        }
        if (_mintConnManual?.IsChecked == true)
        {
            var pin = _mintConnPins.FirstOrDefault(kv => kv.Value.IsChecked == true).Key ?? "mesh";
            return System.Text.Json.JsonSerializer.Serialize(new { mode = "manual", allowedRungs = Array.Empty<string>(), pinnedRung = pin });
        }
        return null;
    }

    private void RenderChecklist()
    {
        // W75: the pair card's live lines ride the same tick —
        // the reachable address (the connect address of record)
        // and the code's live countdown.
        if (_pairingReachText is not null)
        {
            // The host-state snapshot carries the running lanes by
            // name (Lan / Tailscale), not numeric addresses — the
            // line names the paths that are actually up, no more.
            var lanes = _host?.Lanes.Where(l => !string.IsNullOrWhiteSpace(l)).ToArray() ?? Array.Empty<string>();
            _pairingReachText.Text = lanes.Length == 0
                ? "No reachable path on this PC yet — connect a transport and it will show here."
                : Strings.Format("PairingReachFormat", string.Join(" · ", lanes));
        }
        if (_pairingCodeText is not null && _pairingCodeText.Visibility == Visibility.Visible && _pairingStatusText is not null)
        {
            var left = _activeCodeExpires - DateTimeOffset.Now;
            _pairingStatusText.Text = left <= TimeSpan.Zero
                ? Strings.Get("PairingExpiredLine")
                : Strings.Format("PairingCodeHintFormat", _activeCodeExpires.ToLocalTime().ToString("h:mm tt"))
                  + " " + Strings.Format("PairingExpiresInFormat", $"{(int)left.TotalMinutes}:{left.Seconds:00}");
        }
        if (_checklistBody is null) return;
        _checklistBody.Children.Clear();
        var unlocked = _desktopUnlocked?.Invoke() ?? false;
        AddCheck("Session agent (this app)", true, "Running");
        AddCheck("Core service", _host?.AgentConnected == true, _host?.AgentConnected == true ? "Connected" : "Not connected");
        AddCheck("Desktop", unlocked, unlocked ? "Unlocked" : "Locked");
        AddCheck("Pairings", _host is not null, _host is null ? "Unknown" : $"{_host.Pairings.Count(p => !p.Revoked)} active");
        AddCheck("User STOP", true, _host?.UserStop == true ? "In force" : "Ready");
        // W8 (§5): SAS confirmation renders only AFTER redemption —
        // when the named pairing exists in the Core's snapshot.
        // W11 / R-37 (with R-27): the design's words-check line
        // ("Check the words — they must match what your AI shows")
        // instructs a comparison that CANNOT be performed for an
        // MCP pairing: the Pairing record carries no key material
        // (Acp.Shared/Security/Pairing.cs — id, name, scopes,
        // expiry only), so no PairingSas phrase exists on either
        // side, and the AI shows no words to check against. The
        // phrase exists only for DEVICE ENROLLMENT pairings
        // (EnrollmentService computes it from both keys; the
        // Roster page renders it). Rendering the words-check
        // instruction here was a fake capability (§13), so this
        // surface now states the pairing's real posture. The
        // design string itself (wizard_sas_check in DesignLaw /
        // Strings) is trio-owned and stays untouched pending the
        // R-27 trio decision; this surface no longer speaks it for
        // MCP pairings.
        if (_pairingSasText is not null && _host is not null && _pairingNameBox is not null)
        {
            var redeemed = _host.Pairings.Any(p => !p.Revoked &&
                string.Equals(p.Name, _pairingNameBox.Text.Trim(), StringComparison.OrdinalIgnoreCase));
            _pairingSasText.Text = redeemed
                ? $"“{_pairingNameBox.Text.Trim()}” is paired. This kind of pairing has no word-phrase check — the words check belongs to device enrollment, whose phrase shows on the Roster page."
                : Strings.Get("WizardWaitingForAi");
        }
    }

    private void AddCheck(string label, bool ok, string state)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 5) };
        row.Children.Add(Chip(ok ? "✓" : "!", ok ? GreenBg : RedBg, ok ? GreenFg : RedFg));
        var text = new TextBlock { Text = label, FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, Width = 190 };
        row.Children.Add(text);
        row.Children.Add(Chip(state, GrayBg, GrayFg));
        _checklistBody!.Children.Add(row);
    }
}

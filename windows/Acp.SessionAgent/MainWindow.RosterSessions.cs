using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Acp.Shared.Ipc;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace Acp.SessionAgent;

/// <summary>The Roster and Sessions pages (Block A wiring,
/// 2026-11-19): the host window's live surfaces over the Slice 2
/// roster store and the Slice 3 session store. Every fact rendered
/// comes from the Core's host-state snapshot (live stores, read at
/// snapshot time); every act travels over the authenticated IPC
/// channel via <see cref="SendHostActionAsync"/> — the same
/// laptop-UI-only discipline as gate approvals and the vault.
/// Functional wiring in the existing page patterns only; the design
/// of record is untouched.</summary>
public partial class MainWindow
{
    // ---- parsed snapshot data (Slice 2/3 sections) -------------------

    private sealed class RosterUserData
    {
        public string Id = ""; public string Name = ""; public string Kind = "";
        public string? PairedBy; public bool Suspended;
    }

    private sealed class RosterUserGroupData
    {
        public string Id = ""; public string Name = "";
        public string[] Members = Array.Empty<string>(); public string[] Admins = Array.Empty<string>();
    }

    private sealed class RosterDeviceData
    {
        public string DeviceId = ""; public string Name = ""; public string GroupId = "";
        public string GroupName = ""; public string Scope = ""; public DateTimeOffset EnrolledUtc;
        public bool Revoked; public string TransportMode = "";
        public string Sas = ""; public bool SasConfirmed;
    }

    private sealed class RosterDeviceGroupData
    {
        public string Id = ""; public string Name = "";
        public string[] TransportSet = Array.Empty<string>();
        public List<RosterDeviceData> Devices = new();
    }

    private sealed class RosterGrantData
    {
        public string UserGroupId = ""; public string DeviceGroupId = "";
        public string[] Rights = Array.Empty<string>();
    }

    private sealed class RosterScopeData
    {
        public string Id = ""; public string Kind = ""; public string Name = "";
        public string[] Ceiling = Array.Empty<string>();
        public List<string> CompanyAdmins = new();
        public List<RosterUserData> Users = new();
        public List<RosterUserGroupData> UserGroups = new();
        public List<RosterDeviceGroupData> DeviceGroups = new();
        public List<RosterGrantData> Grants = new();
    }

    private sealed class HumanSessionData
    {
        public string Id = ""; public string ScopeId = ""; public string HostDeviceId = "";
        public string InitiatorId = ""; public string Initiator = ""; public string Kind = "";
        public string State = ""; public DateTimeOffset? StartedUtc; public long Seconds;
        public string Recording = ""; public bool IsRecording; public string? AcceptedBy;
        public string? FloorHolder;
        public bool TerminalOpen;
        public List<(string UserId, string Name, string Role, string Floor, string Transport)> Participants = new();
        public List<(DateTimeOffset At, string Kind, string? Actor, string Detail)> Events = new();
    }

    private sealed class EnterpriseData
    {
        public string PolicyState = "";
        public bool PolicyLoaded;
        public bool ChainOk;
        public string ChainSummary = "";
        public int AlertCount;
        public bool BreakGlassRotationRequired;
        public string RealIdpBoundary = "";
        // FR-110 (W76): the Core's posture-audit states, carried on
        // the snapshot's enterprise section since W43/W45 but never
        // parsed or rendered by the Agent before this lane — a
        // FAILED posture was API-visible, not eye-visible. Defaults
        // mirror the snapshot's own defaults for an older Core
        // whose enterprise section predates the fields.
        public string PointerSigningPostureAudit = "not-attempted";
        public string UpdateSigningPostureAudit = "not-attempted";
        public string AnchorMarker = "not-composed";
    }

    private sealed class BlockGData
    {
        public int WakeTargets;
        public int StandaloneJobsLive;
        public int TotpEnrollmentsActive;
        public int PasskeysRegistered;
        public int SessionTunnelsOpen;
        public List<(string Key, string State)> FeatureStates = new();
    }

    private sealed class EndpointData
    {
        public RosterDeviceData Device = new();
        public List<(string Name, string DeviceId, string Scope, string Group, DateTimeOffset EnrolledUtc)> Operators = new();
        public int ReceiptCount;
    }

    private sealed class TransportData
    {
        public bool LanListening; public int LanPort; public int LanAccepted; public int LanRefused;
        public bool HubListening; public int HubPort; public int HubAccepted; public int HubRefused;
        public string MeshSetupStage = ""; public string MeshSetupDetail = "";
        public List<(string Kind, string? Rung, string Detail, string? From, string? To)> Events = new();
    }

    private static string JStr(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static string? JStrOrNull(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

    private static string[] JArr(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").ToArray()
            : Array.Empty<string>();

    /// <summary>Parse the snapshot's Slice 2/3 sections. Tolerant by
    /// design: a Core predating the wiring simply has no sections,
    /// and the pages render the empty truth.</summary>
    private static void ParseRosterSessions(HostState host, JsonElement r)
    {
        RosterDeviceData Device(JsonElement d) => new()
        {
            DeviceId = JStr(d, "deviceId"), Name = JStr(d, "name"), GroupId = JStr(d, "groupId"),
            GroupName = JStr(d, "groupName"), Scope = JStr(d, "scope"),
            EnrolledUtc = d.TryGetProperty("enrolledUtc", out var eu) && eu.ValueKind != JsonValueKind.Null ? eu.GetDateTimeOffset() : default,
            Revoked = d.TryGetProperty("revoked", out var rv) && rv.ValueKind == JsonValueKind.True,
            TransportMode = JStr(d, "transportMode"),
            Sas = JStr(d, "sas"),
            SasConfirmed = d.TryGetProperty("sasConfirmed", out var sc) && sc.ValueKind == JsonValueKind.True,
        };
        if (r.TryGetProperty("roster", out var roster) && roster.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in roster.EnumerateArray())
            {
                var scope = new RosterScopeData
                {
                    Id = JStr(s, "id"), Kind = JStr(s, "kind"), Name = JStr(s, "name"),
                    Ceiling = JArr(s, "transportCeiling"),
                    CompanyAdmins = JArr(s, "companyAdmins").ToList(),
                };
                if (s.TryGetProperty("users", out var users))
                    foreach (var u in users.EnumerateArray())
                        scope.Users.Add(new RosterUserData
                        {
                            Id = JStr(u, "id"), Name = JStr(u, "name"), Kind = JStr(u, "kind"),
                            PairedBy = JStrOrNull(u, "pairedBy"),
                            Suspended = u.TryGetProperty("suspended", out var su) && su.ValueKind == JsonValueKind.True,
                        });
                if (s.TryGetProperty("userGroups", out var ugs))
                    foreach (var g in ugs.EnumerateArray())
                        scope.UserGroups.Add(new RosterUserGroupData
                        {
                            Id = JStr(g, "id"), Name = JStr(g, "name"),
                            Members = JArr(g, "members"), Admins = JArr(g, "admins"),
                        });
                if (s.TryGetProperty("deviceGroups", out var dgs))
                    foreach (var g in dgs.EnumerateArray())
                    {
                        var dg = new RosterDeviceGroupData
                        {
                            Id = JStr(g, "id"), Name = JStr(g, "name"), TransportSet = JArr(g, "transportSet"),
                        };
                        if (g.TryGetProperty("devices", out var devs))
                            foreach (var d in devs.EnumerateArray()) dg.Devices.Add(Device(d));
                        scope.DeviceGroups.Add(dg);
                    }
                if (s.TryGetProperty("grants", out var grants))
                    foreach (var g in grants.EnumerateArray())
                        scope.Grants.Add(new RosterGrantData
                        {
                            UserGroupId = JStr(g, "userGroupId"), DeviceGroupId = JStr(g, "deviceGroupId"),
                            Rights = JArr(g, "rights"),
                        });
                host.Roster.Add(scope);
            }
        }
        if (r.TryGetProperty("humanSessions", out var sessions) && sessions.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in sessions.EnumerateArray())
            {
                var hs = new HumanSessionData
                {
                    Id = JStr(s, "id"), ScopeId = JStr(s, "scopeId"), HostDeviceId = JStr(s, "hostDeviceId"),
                    InitiatorId = JStr(s, "initiatorId"), Initiator = JStr(s, "initiator"),
                    Kind = JStr(s, "kind"), State = JStr(s, "state"),
                    StartedUtc = s.TryGetProperty("startedUtc", out var st) && st.ValueKind == JsonValueKind.String ? st.GetDateTimeOffset() : null,
                    Seconds = s.TryGetProperty("seconds", out var sec) && sec.ValueKind == JsonValueKind.Number ? sec.GetInt64() : 0,
                    Recording = JStr(s, "recording"),
                    IsRecording = s.TryGetProperty("isRecording", out var rec) && rec.ValueKind == JsonValueKind.True,
                    AcceptedBy = JStrOrNull(s, "acceptedBy"),
                    FloorHolder = JStrOrNull(s, "floorHolder"),
                };
                hs.TerminalOpen = s.TryGetProperty("terminalOpen", out var tOpen) && tOpen.ValueKind == JsonValueKind.True;
                if (s.TryGetProperty("participants", out var parts))
                    foreach (var p in parts.EnumerateArray())
                        hs.Participants.Add((JStr(p, "userId"), JStr(p, "name"), JStr(p, "role"), JStr(p, "floor"), JStr(p, "transport")));
                if (s.TryGetProperty("events", out var evs))
                    foreach (var e in evs.EnumerateArray())
                        hs.Events.Add((
                            e.TryGetProperty("atUtc", out var at) && at.ValueKind != JsonValueKind.Null ? at.GetDateTimeOffset() : default,
                            JStr(e, "kind"), JStrOrNull(e, "actor"), JStr(e, "detail")));
                host.HumanSessions.Add(hs);
            }
        }
        if (r.TryGetProperty("endpoint", out var ep) && ep.ValueKind == JsonValueKind.Object &&
            ep.TryGetProperty("device", out var epDev))
        {
            var endpoint = new EndpointData { Device = Device(epDev) };
            if (ep.TryGetProperty("allowedOperators", out var ops))
                foreach (var o in ops.EnumerateArray())
                    endpoint.Operators.Add((JStr(o, "name"), JStr(o, "deviceId"), JStr(o, "scope"), JStr(o, "group"),
                        o.TryGetProperty("enrolledUtc", out var oe) && oe.ValueKind != JsonValueKind.Null ? oe.GetDateTimeOffset() : default));
            endpoint.ReceiptCount = ep.TryGetProperty("receiptCount", out var rc) && rc.ValueKind == JsonValueKind.Number ? rc.GetInt32() : 0;
            host.Endpoint = endpoint;
        }
        if (r.TryGetProperty("transport", out var tp) && tp.ValueKind == JsonValueKind.Object)
        {
            var transport = new TransportData
            {
                LanListening = tp.TryGetProperty("lanListening", out var ll) && ll.ValueKind == JsonValueKind.True,
                LanPort = tp.TryGetProperty("lanPort", out var lp) && lp.ValueKind == JsonValueKind.Number ? lp.GetInt32() : 0,
                LanAccepted = tp.TryGetProperty("lanAccepted", out var la) && la.ValueKind == JsonValueKind.Number ? la.GetInt32() : 0,
                LanRefused = tp.TryGetProperty("lanRefused", out var lr) && lr.ValueKind == JsonValueKind.Number ? lr.GetInt32() : 0,
                HubListening = tp.TryGetProperty("hubListening", out var hl) && hl.ValueKind == JsonValueKind.True,
                HubPort = tp.TryGetProperty("hubPort", out var hp) && hp.ValueKind == JsonValueKind.Number ? hp.GetInt32() : 0,
                HubAccepted = tp.TryGetProperty("hubAccepted", out var ha) && ha.ValueKind == JsonValueKind.Number ? ha.GetInt32() : 0,
                HubRefused = tp.TryGetProperty("hubRefused", out var hr) && hr.ValueKind == JsonValueKind.Number ? hr.GetInt32() : 0,
                MeshSetupStage = JStr(tp, "meshSetupStage"),
                MeshSetupDetail = JStr(tp, "meshSetupDetail"),
            };
            if (tp.TryGetProperty("events", out var evs) && evs.ValueKind == JsonValueKind.Array)
                foreach (var e in evs.EnumerateArray())
                    transport.Events.Add((JStr(e, "kind"), JStrOrNull(e, "rung"), JStr(e, "detail"),
                        JStrOrNull(e, "fromSessionId"), JStrOrNull(e, "toSessionId")));
            host.Transport = transport;
        }
        if (r.TryGetProperty("enterprise", out var ent) && ent.ValueKind == JsonValueKind.Object)
        {
            host.Enterprise = new EnterpriseData
            {
                PolicyState = JStr(ent, "policyState"),
                PolicyLoaded = ent.TryGetProperty("policyLoaded", out var pl) && pl.ValueKind == JsonValueKind.True,
                ChainOk = ent.TryGetProperty("chainOk", out var co) && co.ValueKind == JsonValueKind.True,
                ChainSummary = JStr(ent, "chainSummary"),
                AlertCount = ent.TryGetProperty("alertCount", out var ac) && ac.ValueKind == JsonValueKind.Number ? ac.GetInt32() : 0,
                BreakGlassRotationRequired = ent.TryGetProperty("breakGlassRotationRequired", out var bg) && bg.ValueKind == JsonValueKind.True,
                RealIdpBoundary = JStr(ent, "realIdpBoundary"),
                // FR-110 (W76): posture-audit states + anchor
                // marker — present on the snapshot since W43/W45;
                // absent fields keep the snapshot's own defaults.
                PointerSigningPostureAudit = JStr(ent, "pointerSigningPostureAudit") is { Length: > 0 } psp ? psp : "not-attempted",
                UpdateSigningPostureAudit = JStr(ent, "updateSigningPostureAudit") is { Length: > 0 } usp ? usp : "not-attempted",
                AnchorMarker = JStr(ent, "anchorMarker") is { Length: > 0 } am ? am : "not-composed",
            };
        }
        if (r.TryGetProperty("blockG", out var bgf) && bgf.ValueKind == JsonValueKind.Object)
        {
            var data = new BlockGData
            {
                WakeTargets = bgf.TryGetProperty("wakeTargets", out var wt) && wt.ValueKind == JsonValueKind.Number ? wt.GetInt32() : 0,
                StandaloneJobsLive = bgf.TryGetProperty("standaloneJobsLive", out var sj) && sj.ValueKind == JsonValueKind.Number ? sj.GetInt32() : 0,
                TotpEnrollmentsActive = bgf.TryGetProperty("totpEnrollmentsActive", out var te) && te.ValueKind == JsonValueKind.Number ? te.GetInt32() : 0,
                PasskeysRegistered = bgf.TryGetProperty("passkeysRegistered", out var pk) && pk.ValueKind == JsonValueKind.Number ? pk.GetInt32() : 0,
                SessionTunnelsOpen = bgf.TryGetProperty("sessionTunnelsOpen", out var st) && st.ValueKind == JsonValueKind.Number ? st.GetInt32() : 0,
            };
            if (bgf.TryGetProperty("featureStates", out var fs) && fs.ValueKind == JsonValueKind.Object)
                foreach (var kv in fs.EnumerateObject())
                    data.FeatureStates.Add((kv.Name, kv.Value.GetString() ?? ""));
            host.BlockG = data;
        }
    }

    // ---- shared send path ---------------------------------------------

    /// <summary>Send one host-window action to the Core over the
    /// authenticated channel. The window never pretends an unsent
    /// action landed: a disconnected send says so on the status line.</summary>
    private async Task SendHostActionAsync(string kind, object payload, TextBlock? status)
    {
        var sender = _hostActionSender;
        if (sender is null)
        {
            if (status is not null) status.Text = "Not connected to the Core — the action was NOT sent.";
            return;
        }
        var sent = await sender(kind, JsonSerializer.Serialize(payload));
        if (status is not null)
            status.Text = sent ? "Sent to the Core…" : "Not connected to the Core — the action was NOT sent.";
        if (sent) _ = RequestHostStateAsync();
    }

    /// <summary>The Core's action-result report, routed to the page
    /// that acted. Facts from the Core, verbatim detail.</summary>
    public void SetActionResult(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetActionResult(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var action = JStr(root, "action");
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            var detail = JStr(root, "detail");
            var line = (ok ? "Core: " : "Core refused: ") + detail;
            if (action.StartsWith("session", StringComparison.Ordinal) && _sessionStatus is not null) _sessionStatus.Text = line;
            else if (action.StartsWith("enrollment", StringComparison.Ordinal) && _enrollStatus is not null) _enrollStatus.Text = line;
            else if (action.StartsWith("terminal", StringComparison.Ordinal) && _currentPage == "sessions" && _sessionStatus is not null) _sessionStatus.Text = line;
            else if ((action.StartsWith("enterprise", StringComparison.Ordinal) || action.StartsWith("terminal", StringComparison.Ordinal) ||
                      action.StartsWith("quick_assist", StringComparison.Ordinal) || action.StartsWith("webrtc", StringComparison.Ordinal) ||
                      action.StartsWith("aipack", StringComparison.Ordinal)) && _enterpriseStatus is not null) _enterpriseStatus.Text = line;
            else if (action.StartsWith("blockg", StringComparison.Ordinal) && _blockGStatus is not null) _blockGStatus.Text = line;
            else if (action.StartsWith("recovery", StringComparison.Ordinal) && _recoveryStatus is not null) _recoveryStatus.Text = line;
            else if (action.StartsWith("pairing_access", StringComparison.Ordinal) && _accessStatus is not null) _accessStatus.Text = line;
            else if (action.StartsWith("pairing_connection", StringComparison.Ordinal) && _connStatus is not null) _connStatus.Text = line;
            else if (_rosterStatus is not null) _rosterStatus.Text = line;
            _ = RequestHostStateAsync();
        }
        catch { }
    }

    // ================= ROSTER PAGE =================

    private StackPanel? _rosterBody;
    private StackPanel? _endpointBody;
    private StackPanel? _transportBody;
    private StackPanel? _discoveryBody;
    private TextBlock? _rosterStatus;
    private TextBlock? _enrollStatus;
    private TextBlock? _enrollCodeText;
    private TextBlock? _enrollQrText;
    private StackPanel? _blastBody;
    private DateTimeOffset _rosterRenderedAt = DateTimeOffset.MinValue;
    private string? _blastScope;
    private string? _blastUser;
    private TextBox? _offScopeBox;
    private TextBox? _offUserBox;
    private TextBox? _offActorBox;
    private CheckBox? _offStepUpBox;

    private static TextBox Box(string text = "") => new()
    {
        Text = text, FontSize = 13, Padding = new Thickness(7, 4, 7, 4),
        Margin = new Thickness(0, 2, 8, 6), MinWidth = 110,
    };

    private static TextBlock Label(string text) => new()
    {
        Text = text, FontSize = 11.5, FontWeight = FontWeights.SemiBold,
        Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)),
    };

    private (StackPanel Row, TextBox Input) FieldRow(string label, string initial = "")
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal };
        var lab = Label(label);
        lab.Width = 118;
        lab.VerticalAlignment = VerticalAlignment.Center;
        row.Children.Add(lab);
        var input = Box(initial);
        row.Children.Add(input);
        return (row, input);
    }

    private UIElement BuildRosterPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Roster"));
        stack.Children.Add(Sub("Scopes, people, device groups, and grants — read live from the Core's roster store. Acts from this window travel over the authenticated Core channel only."));
        _rosterStatus = Muted("");
        stack.Children.Add(_rosterStatus);

        // Endpoint view (D2): this PC as an endpoint sees ONLY itself.
        var endpointCardBody = new StackPanel();
        endpointCardBody.Children.Add(new TextBlock { Text = "This PC as an endpoint", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        _endpointBody = new StackPanel();
        endpointCardBody.Children.Add(_endpointBody);
        stack.Children.Add(Card(endpointCardBody));

        _rosterBody = new StackPanel();
        stack.Children.Add(_rosterBody);

        // ---- create forms ----
        var forms = new StackPanel();
        forms.Children.Add(new TextBlock { Text = "Add to the roster", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });

        var (scopeRow, scopeId) = FieldRow("Scope id");
        var (scopeKindRow, scopeKind) = FieldRow("Scope kind", "company");
        var (scopeNameRow, scopeName) = FieldRow("Scope name");
        forms.Children.Add(scopeRow); forms.Children.Add(scopeKindRow); forms.Children.Add(scopeNameRow);
        var createScope = new Button { Content = "Create scope", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        createScope.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "create_scope", id = scopeId.Text.Trim(), kind = scopeKind.Text.Trim(), name = scopeName.Text.Trim() }, _rosterStatus);
        forms.Children.Add(createScope);

        var (userScopeRow, userScope) = FieldRow("User scope id");
        var (userIdRow, userId) = FieldRow("User id");
        var (userNameRow, userName) = FieldRow("User name");
        var (userKindRow, userKind) = FieldRow("User kind", "human");
        var (userOwnerRow, userOwner) = FieldRow("AI paired-by (AI only)");
        forms.Children.Add(userScopeRow); forms.Children.Add(userIdRow); forms.Children.Add(userNameRow); forms.Children.Add(userKindRow); forms.Children.Add(userOwnerRow);
        var createUser = new Button { Content = "Create user", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        createUser.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "create_user", id = userId.Text.Trim(), scopeId = userScope.Text.Trim(), displayName = userName.Text.Trim(), kind = userKind.Text.Trim(), pairedByUserId = string.IsNullOrWhiteSpace(userOwner.Text) ? null : userOwner.Text.Trim() }, _rosterStatus);
        forms.Children.Add(createUser);

        var (dgScopeRow, dgScope) = FieldRow("Device group scope");
        var (dgIdRow, dgId) = FieldRow("Device group id");
        var (dgNameRow, dgName) = FieldRow("Device group name");
        var (dgTransRow, dgTrans) = FieldRow("Transports (csv)", "lan,hub,mesh,ipv6,ownpath,tor");
        forms.Children.Add(dgScopeRow); forms.Children.Add(dgIdRow); forms.Children.Add(dgNameRow); forms.Children.Add(dgTransRow);
        var createDg = new Button { Content = "Create device group", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        createDg.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "create_device_group", id = dgId.Text.Trim(), scopeId = dgScope.Text.Trim(), name = dgName.Text.Trim(), transportSet = Csv(dgTrans.Text) }, _rosterStatus);
        forms.Children.Add(createDg);

        var (ugScopeRow, ugScope) = FieldRow("User group scope");
        var (ugIdRow, ugId) = FieldRow("User group id");
        var (ugNameRow, ugName) = FieldRow("User group name");
        forms.Children.Add(ugScopeRow); forms.Children.Add(ugIdRow); forms.Children.Add(ugNameRow);
        var createUg = new Button { Content = "Create user group", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        createUg.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "create_user_group", id = ugId.Text.Trim(), scopeId = ugScope.Text.Trim(), name = ugName.Text.Trim() }, _rosterStatus);
        forms.Children.Add(createUg);

        var (grScopeRow, grScope) = FieldRow("Grant scope id");
        var (grUgRow, grUg) = FieldRow("Grant user group");
        var (grDgRow, grDg) = FieldRow("Grant device group");
        var (grRightsRow, grRights) = FieldRow("Rights (csv)", "use");
        forms.Children.Add(grScopeRow); forms.Children.Add(grUgRow); forms.Children.Add(grDgRow); forms.Children.Add(grRightsRow);
        var addGrant = new Button { Content = "Add grant", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        addGrant.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "add_grant", scopeId = grScope.Text.Trim(), userGroupId = grUg.Text.Trim(), deviceGroupId = grDg.Text.Trim(), rights = Csv(grRights.Text) }, _rosterStatus);
        forms.Children.Add(addGrant);

        var (adScopeRow, adScope) = FieldRow("Admin scope id");
        var (adUserRow, adUser) = FieldRow("Admin user id");
        forms.Children.Add(adScopeRow); forms.Children.Add(adUserRow);
        var seatAdmin = new Button { Content = "Seat company admin", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left };
        seatAdmin.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "add_company_admin", scopeId = adScope.Text.Trim(), userId = adUser.Text.Trim() }, _rosterStatus);
        forms.Children.Add(seatAdmin);
        stack.Children.Add(Card(forms));

        // ---- enrollment ----
        var enroll = new StackPanel();
        enroll.Children.Add(new TextBlock { Text = "Enrollment", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        enroll.Children.Add(Muted("Mint a one-time code bound to a scope and device group, or redeem a code for this PC. The code is the only credential; it works once and expires."));
        var (mintScopeRow, mintScope) = FieldRow("Mint scope kind", "company");
        var (mintGroupRow, mintGroup) = FieldRow("Mint group id");
        var (mintGroupNameRow, mintGroupName) = FieldRow("Mint group name");
        var (mintByRow, mintBy) = FieldRow("Minted-by user id");
        enroll.Children.Add(mintScopeRow); enroll.Children.Add(mintGroupRow); enroll.Children.Add(mintGroupNameRow); enroll.Children.Add(mintByRow);
        var mint = new Button { Content = "Mint enrollment code", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 8) };
        mint.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnrollmentMint,
            new { scope = mintScope.Text.Trim(), groupId = mintGroup.Text.Trim(), groupName = mintGroupName.Text.Trim(), mintedByUserId = string.IsNullOrWhiteSpace(mintBy.Text) ? null : mintBy.Text.Trim() }, _enrollStatus);
        enroll.Children.Add(mint);
        _enrollCodeText = new TextBlock { FontSize = 20, FontWeight = FontWeights.SemiBold, FontFamily = new System.Windows.Media.FontFamily("Consolas"), Visibility = Visibility.Collapsed };
        enroll.Children.Add(_enrollCodeText);
        _enrollQrText = Muted("");
        enroll.Children.Add(_enrollQrText);
        var (redeemCodeRow, redeemCode) = FieldRow("Redeem code");
        var (redeemNameRow, redeemName) = FieldRow("This PC's name");
        var (redeemScopeRow, redeemScope) = FieldRow("Roster scope id");
        var (redeemByRow, redeemBy) = FieldRow("Minted-by user id");
        enroll.Children.Add(redeemCodeRow); enroll.Children.Add(redeemNameRow); enroll.Children.Add(redeemScopeRow); enroll.Children.Add(redeemByRow);
        var redeem = new Button { Content = "Redeem for this PC", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 2, 0, 4) };
        redeem.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnrollmentRedeem,
            new { code = redeemCode.Text.Trim(), displayName = redeemName.Text.Trim(), rosterScopeId = string.IsNullOrWhiteSpace(redeemScope.Text) ? null : redeemScope.Text.Trim(), mintedByUserId = string.IsNullOrWhiteSpace(redeemBy.Text) ? null : redeemBy.Text.Trim() }, _enrollStatus);
        enroll.Children.Add(redeem);
        _enrollStatus = Muted("");
        enroll.Children.Add(_enrollStatus);
        stack.Children.Add(Card(enroll));

        // ---- offboarding (D14) ----
        var off = new StackPanel();
        off.Children.Add(new TextBlock { Text = "Remove a user (offboarding)", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        off.Children.Add(Muted("Preview computes the full blast list first — seats, admin seat, grants, minted enrollments, owned AI pairings, and the live-session requirement. Nothing fires until you press Remove after reading it."));
        var (offScopeRow, offScope) = FieldRow("Scope id");
        var (offUserRow, offUser) = FieldRow("User id");
        var (offActorRow, offActor) = FieldRow("Actor (company admin)");
        _offScopeBox = offScope; _offUserBox = offUser; _offActorBox = offActor;
        off.Children.Add(offScopeRow); off.Children.Add(offUserRow); off.Children.Add(offActorRow);
        _offStepUpBox = new CheckBox { Content = "Step-up confirmed (required when removing a fellow company admin)", FontSize = 13, Margin = new Thickness(0, 2, 0, 8) };
        off.Children.Add(_offStepUpBox);
        var preview = new Button { Content = "Preview removal (blast list)", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left };
        preview.Click += async (_, _) =>
        {
            _blastScope = offScope.Text.Trim();
            _blastUser = offUser.Text.Trim();
            await SendHostActionAsync(IpcKinds.RosterOffboardPreview,
                new { scopeId = _blastScope, userId = _blastUser }, _rosterStatus);
        };
        off.Children.Add(preview);
        _blastBody = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        off.Children.Add(_blastBody);
        var fire = new Button { Content = "Remove user — fire the blast list above", Style = (Style)FindResource("DangerButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 8, 0, 0) };
        fire.Click += async (_, _) =>
        {
            if (_blastScope is null || _blastUser is null ||
                _blastScope != offScope.Text.Trim() || _blastUser != offUser.Text.Trim())
            {
                if (_rosterStatus is not null) _rosterStatus.Text = "Preview this exact scope + user first — removal will not fire on an unpreviewed target.";
                return;
            }
            await SendHostActionAsync(IpcKinds.RosterAction,
                new { action = "remove_user", scopeId = offScope.Text.Trim(), userId = offUser.Text.Trim(), actorUserId = offActor.Text.Trim(), stepUp = _offStepUpBox?.IsChecked == true }, _rosterStatus);
            _blastScope = null; _blastUser = null;
        };
        off.Children.Add(fire);
        stack.Children.Add(Card(off));

        // ---- transport sets (Block C part 1, D31/D32) ----
        var tset = new StackPanel();
        tset.Children.Add(new TextBlock { Text = "Transport sets", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        tset.Children.Add(MutedT("A group's ordered transport set is what Auto fails over across. Changing the set is a group-admin act.", "The company ceiling caps every device; a per-device override narrows or pins within the resolved set — a pin outside it is refused whole."));
        var (tsScopeRow, tsScope) = FieldRow("Scope id");
        var (tsGroupRow, tsGroup) = FieldRow("Device group id");
        var (tsActorRow, tsActor) = FieldRow("Actor (group admin)");
        var (tsSetRow, tsSet) = FieldRow("New set (csv, ordered)", "lan,hub,tor");
        tset.Children.Add(tsScopeRow); tset.Children.Add(tsGroupRow); tset.Children.Add(tsActorRow); tset.Children.Add(tsSetRow);
        var setTransports = new Button { Content = "Set group transports", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        setTransports.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "set_group_transports", scopeId = tsScope.Text.Trim(), groupId = tsGroup.Text.Trim(), actorUserId = tsActor.Text.Trim(), transportSet = Csv(tsSet.Text) }, _rosterStatus);
        tset.Children.Add(setTransports);
        var (ceScopeRow, ceScope) = FieldRow("Ceiling scope id");
        var (ceSetRow, ceSet) = FieldRow("Ceiling (csv; empty = clear)");
        tset.Children.Add(ceScopeRow); tset.Children.Add(ceSetRow);
        var setCeiling = new Button { Content = "Set company ceiling", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        setCeiling.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "set_scope_ceiling", scopeId = ceScope.Text.Trim(), transportCeiling = Csv(ceSet.Text) }, _rosterStatus);
        tset.Children.Add(setCeiling);
        var (dvDeviceRow, dvDevice) = FieldRow("Device id");
        var (dvModeRow, dvMode) = FieldRow("Mode", "inherit");
        var (dvPinsRow, dvPins) = FieldRow("Pins (csv, manual only)");
        tset.Children.Add(dvDeviceRow); tset.Children.Add(dvModeRow); tset.Children.Add(dvPinsRow);
        var setDevice = new Button { Content = "Set device transports", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left };
        setDevice.Click += async (_, _) => await SendHostActionAsync(IpcKinds.RosterAction,
            new { action = "update_device_transports", deviceId = dvDevice.Text.Trim(), transportMode = dvMode.Text.Trim(), allowedTransports = Csv(dvPins.Text) }, _rosterStatus);
        tset.Children.Add(setDevice);
        stack.Children.Add(Card(tset));

        // ---- local discovery + LAN listener (Block C part 1, D19/D20/D29) ----
        var disc = new StackPanel();
        disc.Children.Add(new TextBlock { Text = "Local discovery & LAN listener", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        disc.Children.Add(MutedT("Discovery announces only this PC's device-id hash, its name, and its enrollment state — discovery never grants control; enrollment does.", "Devices heard while browsing that are not enrolled show as available to enroll. The LAN listener stays off (dormant) until you start it; every session on it must still prove possession of an enrolled device key."));
        _transportBody = new StackPanel { Margin = new Thickness(0, 4, 0, 4) };
        disc.Children.Add(_transportBody);
        var discButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        var listen = new Button { Content = "Start LAN listener", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        listen.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "start_lan_listener" }, _rosterStatus);
        discButtons.Children.Add(listen);
        var unlisten = new Button { Content = "Stop listener", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        unlisten.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "stop_lan_listener" }, _rosterStatus);
        discButtons.Children.Add(unlisten);
        var announce = new Button { Content = "Announce this PC", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        announce.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "announce_discovery" }, _rosterStatus);
        discButtons.Children.Add(announce);
        var browse = new Button { Content = "Browse (3 s)", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(10, 5, 10, 5) };
        browse.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "browse_discovery", windowMs = 3000 }, _rosterStatus);
        discButtons.Children.Add(browse);
        disc.Children.Add(discButtons);
        // Hub listener (Block C part 3): the same enrollment
        // handshake bound to this PC's tailnet IP on the ACP hub
        // mesh. Membership on the mesh admits nobody by itself.
        var (hubBindRow, hubBind) = FieldRow("This PC's hub mesh address (tailnet IP)");
        disc.Children.Add(hubBindRow);
        var hubButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        var hubListen = new Button { Content = "Start hub listener", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        hubListen.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "start_hub_listener", address = hubBind.Text.Trim() }, _rosterStatus);
        hubButtons.Children.Add(hubListen);
        var hubUnlisten = new Button { Content = "Stop hub listener", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        hubUnlisten.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "stop_hub_listener" }, _rosterStatus);
        hubButtons.Children.Add(hubUnlisten);
        disc.Children.Add(hubButtons);
        _discoveryBody = new StackPanel();
        disc.Children.Add(_discoveryBody);
        stack.Children.Add(Card(disc));

        // ---- mesh rung setup (Block C part 3, D4 + T2 conditions) ----
        var mesh = new StackPanel();
        mesh.Children.Add(new TextBlock { Text = "Mesh rung — Tailscale setup", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        mesh.Children.Add(MutedT("About this rung: session traffic is end-to-end encrypted between your devices, but on this rung Tailscale Inc. processes connection metadata and the device inventory for the tailnet — ACP's 'no vendor server holds your data' claim does not cover this rung.", "The free tier covers 6 users and 50 tagged resources; beyond that a paid Tailscale plan is required."));
        mesh.Children.Add(MutedT("Setup checks run in order before this rung comes up.", "The installed client must be at or above version 1.104.4; the log-upload switch-off must be asserted and verified (the rung refuses to come up if it cannot be); Tailscale SSH, Serve and Funnel must be off; and ACP holds only a scoped OAuth trust credential — never a personal API token. Endpoints never sign in: they join with single-use keys ACP mints."));
        var (mScopeRow, mScope) = FieldRow("Scope id (for the policy mapping)");
        var (mClientRow, mClient) = FieldRow("OAuth client id");
        var (mSecretRow, mSecret) = FieldRow("OAuth client secret (scoped trust credential)");
        var (mScopesRow, mScopes) = FieldRow("Scopes (comma-separated)", "policy_file, auth_keys, devices:core:read");
        var (mPortRow, mPort) = FieldRow("Session port for policy grants", "47621");
        mesh.Children.Add(mScopeRow); mesh.Children.Add(mClientRow); mesh.Children.Add(mSecretRow);
        mesh.Children.Add(mScopesRow); mesh.Children.Add(mPortRow);
        var mButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        var mPreflight = new Button { Content = "Check this PC (preflight)", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        mPreflight.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "mesh_preflight" }, _rosterStatus);
        mButtons.Children.Add(mPreflight);
        var mCred = new Button { Content = "Store scoped credential", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        mCred.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "mesh_set_credential", clientId = mClient.Text.Trim(), clientSecret = mSecret.Text.Trim(), scopes = Csv(mScopes.Text) }, _rosterStatus);
        mButtons.Children.Add(mCred);
        var mSignIn = new Button { Content = "Open Tailscale sign-in", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        mSignIn.Click += (_, _) =>
        {
            // The ONE human moment (D4): Tailscale's own sign-in
            // page. ACP never sees, types, or stores that
            // credential — it only learns that sign-in completed.
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://login.tailscale.com/start") { UseShellExecute = true }); }
            catch { if (_rosterStatus is not null) _rosterStatus.Text = "Could not open the sign-in page."; }
        };
        mButtons.Children.Add(mSignIn);
        mesh.Children.Add(mButtons);
        var mDone = new CheckBox { Content = "I completed sign-in on Tailscale's own page", Margin = new Thickness(0, 2, 0, 4) };
        mesh.Children.Add(mDone);
        var mFinish = new Button { Content = "Finish setup (writes the policy, guarded)", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(10, 5, 10, 5) };
        mFinish.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new { action = "mesh_finish", scopeId = mScope.Text.Trim(), sessionPort = mPort.Text.Trim(), signInCompleted = mDone.IsChecked == true }, _rosterStatus);
        mesh.Children.Add(mFinish);
        stack.Children.Add(Card(mesh));

        RenderRoster();
        return stack;
    }

    private static string[] Csv(string text) =>
        text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private void RenderRoster()
    {
        RenderTransport();
        if (_rosterBody is null || _endpointBody is null) return;
        if (_host is not null && _hostAt == _rosterRenderedAt && _rosterBody.Children.Count > 0) return;
        _rosterRenderedAt = _hostAt;
        _endpointBody.Children.Clear();
        _rosterBody.Children.Clear();
        if (_host is null)
        {
            _endpointBody.Children.Add(Muted("Waiting for the Core's snapshot…"));
            _rosterBody.Children.Add(Muted("Waiting for the Core's snapshot…"));
            return;
        }
        if (_host.Endpoint is null)
        {
            _endpointBody.Children.Add(Muted("This PC has no enrollment record of its own yet — redeem a code below and it will appear here, with only its own operators (D2)."));
        }
        else
        {
            var d = _host.Endpoint.Device;
            _endpointBody.Children.Add(Body($"{d.Name} · {d.DeviceId[..Math.Min(12, d.DeviceId.Length)]}… · group {d.GroupName} · scope {d.Scope}{(d.Revoked ? " · REVOKED" : "")}"));
            foreach (var op in _host.Endpoint.Operators)
                _endpointBody.Children.Add(Muted($"Allowed operator: {op.Name} · enrolled {op.EnrolledUtc.ToLocalTime():yyyy-MM-dd} · {op.Group}"));
            if (_host.Endpoint.Operators.Count == 0)
                _endpointBody.Children.Add(Muted("No enrollment receipts on this PC yet."));
        }
        if (_host.Roster.Count == 0)
        {
            _rosterBody.Children.Add(Card(new StackPanel { Children = { Muted("No scopes in the roster yet. Create one below — it lands in the Core's roster store immediately.") } }));
            return;
        }
        foreach (var scope in _host.Roster)
        {
            var body = new StackPanel();
            body.Children.Add(new TextBlock { Text = $"{scope.Name} · {scope.Kind} scope · {scope.Id}", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
            if (scope.Ceiling.Length > 0)
                body.Children.Add(Muted($"Transport ceiling: {string.Join(", ", scope.Ceiling)}"));
            body.Children.Add(Muted($"Users ({scope.Users.Count})"));
            foreach (var u in scope.Users)
            {
                var admin = scope.CompanyAdmins.Contains(u.Id) ? " · company admin" : "";
                var ai = u.Kind == "ai" ? $" · AI (paired by {u.PairedBy})" : "";
                body.Children.Add(Body($"• {u.Name} ({u.Id}){ai}{admin}{(u.Suspended ? " · SUSPENDED" : "")}", 13));
            }
            body.Children.Add(Muted($"User groups ({scope.UserGroups.Count})"));
            foreach (var g in scope.UserGroups)
                body.Children.Add(Body($"• {g.Name} ({g.Id}) · members: {string.Join(", ", g.Members)} · admins: {string.Join(", ", g.Admins)}", 13));
            body.Children.Add(Muted($"Device groups ({scope.DeviceGroups.Count})"));
            foreach (var g in scope.DeviceGroups)
            {
                body.Children.Add(Body($"• {g.Name} ({g.Id}) · transports: {string.Join(" → ", g.TransportSet)}", 13));
                foreach (var d in g.Devices)
                {
                    body.Children.Add(Muted($"    device {d.Name} · {d.DeviceId[..Math.Min(12, d.DeviceId.Length)]}… · mode {d.TransportMode}{(d.Revoked ? " · REVOKED" : "")}", 12));
                    // U9: SAS compare line — shown until the endpoint-local confirm flips it.
                    if (!string.IsNullOrWhiteSpace(d.Sas))
                        body.Children.Add(Muted(d.SasConfirmed
                            ? $"    Compare: {d.Sas} · verified ✓"
                            : $"    Compare: {d.Sas} · not yet verified — compare with the string on the other device", 12));
                }
            }
            body.Children.Add(Muted($"Grants ({scope.Grants.Count})"));
            foreach (var g in scope.Grants)
                body.Children.Add(Body($"• {g.UserGroupId} → {g.DeviceGroupId}: {string.Join(", ", g.Rights)}", 13));
            _rosterBody.Children.Add(Card(body));
        }
    }

    /// <summary>The transport section of the roster page: LAN
    /// listener state (dormant until started) and the failover
    /// engine's recent events, from the Core's snapshot.</summary>
    private void RenderTransport()
    {
        if (_transportBody is null) return;
        _transportBody.Children.Clear();
        var t = _host?.Transport;
        if (t is null)
        {
            _transportBody.Children.Add(Muted("Waiting for the Core's transport facts…"));
            return;
        }
        _transportBody.Children.Add(Body(t.LanListening
            ? $"LAN listener: listening on port {t.LanPort} · {t.LanAccepted} session(s) accepted · {t.LanRefused} handshake(s) refused"
            : "LAN listener: off (dormant — no socket is open)", 13));
        _transportBody.Children.Add(Body(t.HubListening
            ? $"Hub listener: listening on port {t.HubPort} · {t.HubAccepted} session(s) accepted · {t.HubRefused} handshake(s) refused"
            : "Hub listener: off (dormant — no socket is open)", 13));
        if (t.MeshSetupStage.Length > 0)
            _transportBody.Children.Add(Muted($"Mesh (Tailscale) setup: {t.MeshSetupStage} — {t.MeshSetupDetail}", 12));
        foreach (var e in t.Events.TakeLast(6))
            _transportBody.Children.Add(Muted($"transport · {e.Kind}{(e.Rung is not null ? $" · {e.Rung}" : "")} · {e.Detail}", 12));
    }

    /// <summary>The Core's discovery-browse answer: the devices one
    /// browse window heard, classified. Unpaired devices read
    /// "available to enroll" — an operator-surface label only;
    /// nothing here can start a session (D20).</summary>
    public void SetDiscoveryResults(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetDiscoveryResults(json)); return; }
        try
        {
            if (_discoveryBody is null) return;
            using var doc = JsonDocument.Parse(json);
            _discoveryBody.Children.Clear();
            var devices = doc.RootElement.TryGetProperty("devices", out var arr) && arr.ValueKind == JsonValueKind.Array
                ? arr.EnumerateArray().ToList() : new List<JsonElement>();
            if (devices.Count == 0)
            {
                _discoveryBody.Children.Add(Muted("Browse heard no devices."));
                return;
            }
            foreach (var d in devices)
            {
                var known = d.TryGetProperty("knownPeer", out var kp) && kp.ValueKind == JsonValueKind.True;
                _discoveryBody.Children.Add(Body(known
                    ? $"{JStr(d, "name")} — enrolled peer"
                    : $"{JStr(d, "name")} — available to enroll", 13));
                _discoveryBody.Children.Add(Muted($"    id hash {JStr(d, "hash")[..Math.Min(12, JStr(d, "hash").Length)]}… · {JStr(d, "state")}", 12));
            }
            ShowPage("roster");
        }
        catch { }
    }

    /// <summary>The Core's enrollment-code answer: shown once, here,
    /// to the person at the keyboard (same rule as pairing codes).</summary>
    public void SetEnrollmentCode(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetEnrollmentCode(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var code = JStr(doc.RootElement, "code");
            var qr = JStr(doc.RootElement, "qr");
            var expires = doc.RootElement.TryGetProperty("expiresUtc", out var e) && e.ValueKind != JsonValueKind.Null ? e.GetDateTimeOffset() : default;
            ShowPage("roster");
            if (_enrollCodeText is not null)
            {
                _enrollCodeText.Text = string.Join(" ", code.ToCharArray());
                _enrollCodeText.Visibility = Visibility.Visible;
            }
            if (_enrollQrText is not null)
                _enrollQrText.Text = $"QR payload: {qr} · expires {expires.ToLocalTime():h:mm tt} · works once. Redeem it below for this PC, or give it to the device being enrolled.";
            if (_enrollStatus is not null) _enrollStatus.Text = "Code minted by the Core.";
        }
        catch { }
    }

    /// <summary>The Core's blast-list answer for the offboarding
    /// preview: the window displays exactly what firing will touch.</summary>
    public void SetOffboardBlast(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetOffboardBlast(json)); return; }
        try
        {
            if (_blastBody is null) return;
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            _blastBody.Children.Clear();
            _blastBody.Children.Add(new TextBlock { Text = $"Blast list for {JStr(r, "userId")} in scope {JStr(r, "scopeId")}", FontSize = 14.5, FontWeight = FontWeights.SemiBold });
            _blastBody.Children.Add(Body($"User-group seats removed: {string.Join(", ", JArr(r, "userGroupSeats"))}", 13));
            _blastBody.Children.Add(Body($"User-group admin seats removed: {string.Join(", ", JArr(r, "userGroupAdminSeats"))}", 13));
            _blastBody.Children.Add(Body($"Company admin seat: {(r.TryGetProperty("companyAdminSeat", out var ca) && ca.ValueKind == JsonValueKind.True ? "yes — removed" : "no")}", 13));
            _blastBody.Children.Add(Body($"Minted enrollments revoked: {string.Join(", ", JArr(r, "mintedEnrollmentDeviceIds"))}", 13));
            _blastBody.Children.Add(Body($"Owned AI pairings suspended (not deleted): {string.Join(", ", JArr(r, "ownedAiUserIds"))}", 13));
            if (r.TryGetProperty("grants", out var grants) && grants.ValueKind == JsonValueKind.Array)
                foreach (var g in grants.EnumerateArray())
                    _blastBody.Children.Add(Body($"Grant touched: {JStr(g, "userGroupId")} → {JStr(g, "deviceGroupId")} ({string.Join(", ", JArr(g, "rights"))})", 13));
            _blastBody.Children.Add(Muted(JStr(r, "liveSessionRequirement"), 12));
            ShowPage("roster");
        }
        catch { }
    }

    // ================= SESSIONS PAGE =================

    private StackPanel? _sessionListBody;
    private StackPanel? _sessionDetailBody;
    private TextBlock? _sessionStatus;
    private TextBox? _sessionActorBox;
    private DateTimeOffset _sessionsRenderedAt = DateTimeOffset.MinValue;
    private string? _selectedSessionId;

    private UIElement BuildSessionsPage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Sessions"));
        stack.Children.Add(Sub("Human remote sessions (Slice 3) — live from the Core's session store. Accepting a session happens only here, at this PC: the local accept is the consent (endpoint-local ruling). STOP from presence ends these sessions too."));
        _sessionStatus = Muted("");
        stack.Children.Add(_sessionStatus);

        _sessionListBody = new StackPanel();
        stack.Children.Add(_sessionListBody);

        var detail = new StackPanel();
        detail.Children.Add(new TextBlock { Text = "Session detail", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        var (actorRow, actor) = FieldRow("Actor / accept-by id");
        _sessionActorBox = actor;
        detail.Children.Add(actorRow);
        detail.Children.Add(Muted("Accept uses this id as the person at this PC. Start/pause/end and the floor acts use it as the actor; STOP requires a host-side actor (the acceptor, the host participant, or a company admin)."));
        _sessionDetailBody = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        detail.Children.Add(_sessionDetailBody);
        stack.Children.Add(Card(detail));

        var create = new StackPanel();
        create.Children.Add(new TextBlock { Text = "Request a session", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
        var (cScopeRow, cScope) = FieldRow("Scope id");
        var (cHostRow, cHost) = FieldRow("Host device id");
        var (cInitRow, cInit) = FieldRow("Initiator user id");
        var (cKindRow, cKind) = FieldRow("Kind", "attended");
        var (cRungRow, cRung) = FieldRow("Transport rung", "lan");
        var (cRecRow, cRec) = FieldRow("Recording", "none");
        create.Children.Add(cScopeRow); create.Children.Add(cHostRow); create.Children.Add(cInitRow);
        create.Children.Add(cKindRow); create.Children.Add(cRungRow); create.Children.Add(cRecRow);
        var request = new Button { Content = "Request session", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 0) };
        request.Click += async (_, _) => await SendHostActionAsync(IpcKinds.SessionAction,
            new { action = "create", scopeId = cScope.Text.Trim(), hostDeviceId = cHost.Text.Trim(), initiatorUserId = cInit.Text.Trim(), kind = cKind.Text.Trim(), transportRung = cRung.Text.Trim(), recording = cRec.Text.Trim() }, _sessionStatus);
        create.Children.Add(request);
        stack.Children.Add(Card(create));

        // ---- transport-layer start (Block C part 1, D29/D32) ----
        var tstart = new StackPanel();
        tstart.Children.Add(new TextBlock { Text = "Start over the transport layer", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
        tstart.Children.Add(MutedT("The failover engine walks the device's resolved transport set in order; the first rung that connects carries the session, and its record names that rung.", "An address is connect-by-address on the LAN rung, for when discovery cannot see across network segments. A pin narrows the walk to one rung from within the set; a pin outside the set refuses the start."));
        var (tScopeRow, tScope) = FieldRow("Scope id");
        var (tHostRow, tHost) = FieldRow("Host device id");
        var (tInitRow, tInit) = FieldRow("Initiator user id");
        var (tKindRow, tKind) = FieldRow("Kind", "unattended");
        var (tAddrRow, tAddr) = FieldRow("Address (host or host:port)");
        var (tHubRow, tHubAddr) = FieldRow("Hub address (peer's tailnet IP on the ACP hub)");
        var (tMeshRow, tMeshAddr) = FieldRow("Mesh address (peer's Tailscale IP)");
        var (tPinRow, tPin) = FieldRow("Pin (one rung, optional)");
        tstart.Children.Add(tScopeRow); tstart.Children.Add(tHostRow); tstart.Children.Add(tInitRow);
        tstart.Children.Add(tKindRow); tstart.Children.Add(tAddrRow); tstart.Children.Add(tHubRow);
        tstart.Children.Add(tMeshRow); tstart.Children.Add(tPinRow);
        var tgo = new Button { Content = "Start over the transport layer", Style = (Style)FindResource("PrimaryButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 0) };
        tgo.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new
            {
                action = "start", scopeId = tScope.Text.Trim(), hostDeviceId = tHost.Text.Trim(),
                initiatorUserId = tInit.Text.Trim(), kind = tKind.Text.Trim(), recording = "none",
                address = string.IsNullOrWhiteSpace(tAddr.Text) ? null : tAddr.Text.Trim(),
                hubAddress = string.IsNullOrWhiteSpace(tHubAddr.Text) ? null : tHubAddr.Text.Trim(),
                meshAddress = string.IsNullOrWhiteSpace(tMeshAddr.Text) ? null : tMeshAddr.Text.Trim(),
                manualPins = string.IsNullOrWhiteSpace(tPin.Text) ? null : new[] { tPin.Text.Trim() },
            }, _sessionStatus);
        tstart.Children.Add(tgo);
        stack.Children.Add(Card(tstart));

        RenderSessions();
        return stack;
    }

    private void RenderSessions()
    {
        if (_sessionListBody is null || _sessionDetailBody is null) return;
        if (_host is not null && _hostAt == _sessionsRenderedAt && _sessionListBody.Children.Count > 0) return;
        _sessionsRenderedAt = _hostAt;
        _sessionListBody.Children.Clear();
        _sessionDetailBody.Children.Clear();
        if (_host is null)
        {
            _sessionListBody.Children.Add(Muted("Waiting for the Core's snapshot…"));
            return;
        }
        if (_host.HumanSessions.Count == 0)
            _sessionListBody.Children.Add(Card(new StackPanel { Children = { Muted("No human sessions in the store yet. Request one below — an attended session starts only after it is accepted here, at this PC.") } }));
        foreach (var s in _host.HumanSessions)
        {
            var body = new StackPanel();
            var head = new StackPanel { Orientation = Orientation.Horizontal };
            // FR-107 (W85): the LIST ROW names the driver too (the
            // detail view always had it) — resolved from the floor
            // holder / participants by SessionDriverName, the pure
            // resolver in Acp.Shared.
            var driverName = Acp.Shared.Presence.SessionDriverName.Resolve(
                s.Initiator, s.FloorHolder,
                s.Participants.Select(p => (p.UserId, p.Name, p.Floor)).ToList());
            head.Children.Add(new TextBlock { Text = $"{s.Initiator} · {s.Kind} · {s.State}" +
                (string.IsNullOrWhiteSpace(driverName) ? "" : $" · driven by {driverName}"), FontSize = 15, FontWeight = FontWeights.SemiBold });
            if (s.IsRecording)
            {
                var chip = Chip("RECORDING", RedBg, RedFg);
                chip.Margin = new Thickness(10, 0, 0, 0);
                head.Children.Add(chip);
            }
            body.Children.Add(head);
            body.Children.Add(Muted($"session {s.Id[..Math.Min(8, s.Id.Length)]}… · host device {s.HostDeviceId[..Math.Min(12, s.HostDeviceId.Length)]}… · {FormatClock(s.Seconds)} · {s.Participants.Count} participant(s)" +
                (s.FloorHolder is not null ? $" · floor: {s.FloorHolder}" : "") +
                (s.AcceptedBy is not null ? $" · accepted by {s.AcceptedBy} at this device" : ""), 12));
            var select = new Button { Content = _selectedSessionId == s.Id ? "Selected" : "Select", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 0) };
            var captured = s.Id;
            select.Click += (_, _) => { _selectedSessionId = captured; _sessionsRenderedAt = DateTimeOffset.MinValue; RenderSessions(); };
            body.Children.Add(select);
            _sessionListBody.Children.Add(Card(body));
        }
        RenderSessionDetail();
    }

    /// <summary>W8 — the witness ledger (record §4, Sessions
    /// detail): the same accounting as Android A4, shaped by
    /// SessionLedgerModel from the snapshot's dataFlows section —
    /// verdict sentence, Read / Sent / Changed as separate labelled
    /// numbers ("so far" while live), destinations named, the
    /// provider line, the vendor line, gaps named, and the
    /// presence-on-frames note. Chat Sent entries live in the same
    /// ledger under the pairing, so this surface and the agent
    /// card agree.</summary>
    private void RenderWitnessLedger(HumanSessionData s)
    {
        if (_sessionDetailBody is null || _host is null) return;
        if (_host.Flows.Count == 0) return;
        _sessionDetailBody.Children.Add(new TextBlock
        {
            Text = Strings.Get("LedgerTitle"), FontSize = 14.5,
            FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 4),
        });
        var live = s.State is "active" or "live" or "running";
        foreach (var flow in _host.Flows)
        {
            var counts = new Acp.Shared.Design.SessionLedgerModel.Counts(
                flow.ClassCalls.TryGetValue("read", out var rc) ? rc : 0,
                flow.ClassCalls.TryGetValue("sent", out var sc) ? sc : 0,
                flow.ClassCalls.TryGetValue("changed", out var cc) ? cc : 0);
            var model = Acp.Shared.Design.SessionLedgerModel.Build(
                verdict: live ? $"{flow.AgentName} is in a session on this PC."
                              : $"{flow.AgentName}'s sessions on this PC are over.",
                counts: counts, live: live, agentName: flow.AgentName,
                destinations: flow.Destinations, gaps: _host.FlowGaps);
            _sessionDetailBody.Children.Add(Body(model.Verdict));
            _sessionDetailBody.Children.Add(Muted(
                Acp.Shared.Design.SessionLedgerModel.CountsLine(model.Counts, model.Live), 12.5));
            foreach (var d in model.Destinations)
                _sessionDetailBody.Children.Add(Muted($"→ {d}", 12));
            if (flow.FramesSent > 0)
                _sessionDetailBody.Children.Add(Muted(
                    Acp.Shared.Design.SessionLedgerModel.SeenSoFarLine(flow.FramesSent), 12));
            if (flow.ChatSent > 0)
                _sessionDetailBody.Children.Add(Muted(
                    Acp.Shared.Design.SessionLedgerModel.ChatSentLine(flow.ChatSent), 12));
            _sessionDetailBody.Children.Add(Muted(model.ProviderLine, 12));
            _sessionDetailBody.Children.Add(Muted(model.VendorLine, 12));
            if (model.GapsLine is not null)
                _sessionDetailBody.Children.Add(Muted(model.GapsLine, 12));
            _sessionDetailBody.Children.Add(Muted(model.PresenceOnFramesLine, 12));
        }
    }

    private void RenderSessionDetail()
    {
        if (_sessionDetailBody is null || _host is null) return;
        _sessionDetailBody.Children.Clear();
        var s = _host.HumanSessions.FirstOrDefault(x => x.Id == _selectedSessionId)
            ?? _host.HumanSessions.FirstOrDefault();
        if (s is null)
        {
            _sessionDetailBody.Children.Add(Muted("No session to show."));
            return;
        }
        _selectedSessionId = s.Id;
        _sessionDetailBody.Children.Add(Body($"{s.Initiator} ({s.InitiatorId}) → this PC · {s.Kind} · state {s.State} · recording {s.Recording}"));
        _sessionDetailBody.Children.Add(Muted($"Participants: {string.Join("; ", s.Participants.Select(p => $"{p.Name} — {p.Role}, floor {p.Floor}" + (string.IsNullOrEmpty(p.Transport) ? "" : $", via {p.Transport}")))}", 12));
        RenderWitnessLedger(s);

        var actions = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 4) };
        void Act(string label, string action, bool danger = false)
        {
            var b = new Button { Content = label, Style = (Style)FindResource(danger ? "DangerButton" : "GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
            b.Click += async (_, _) => await SendHostActionAsync(IpcKinds.SessionAction,
                new { action, sessionId = s.Id, actorUserId = _sessionActorBox?.Text.Trim(), acceptByUserId = _sessionActorBox?.Text.Trim() }, _sessionStatus);
            actions.Children.Add(b);
        }
        Act("Accept here (local)", "accept");
        Act("Start", "start");
        Act("Pause", "pause");
        Act("Resume", "resume");
        Act("End", "end");
        Act("STOP", "stop", danger: true);
        _sessionDetailBody.Children.Add(actions);

        // Failover (Block C part 1): re-establish THIS session on the
        // next rung of its resolved set. The current session ends
        // (transport failover) and a new one starts — a reconnect,
        // linked in both sessions' event lists, never seamless.
        var failoverRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        var reestablish = new Button { Content = "Re-establish on next rung (failover)", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        var hubAddrBox = new TextBox { Width = 190, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = "Peer's hub address (tailnet IP) — needed when the next rung is the hub" };
        reestablish.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TransportAction,
            new
            {
                action = "reestablish", sessionId = s.Id,
                hubAddress = string.IsNullOrWhiteSpace(hubAddrBox.Text) ? null : hubAddrBox.Text.Trim(),
            }, _sessionStatus);
        failoverRow.Children.Add(reestablish);
        failoverRow.Children.Add(hubAddrBox);
        _sessionDetailBody.Children.Add(failoverRow);

        var floor = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        var takeBack = new Button { Content = "Take floor back", Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5) };
        takeBack.Click += async (_, _) => await SendHostActionAsync(IpcKinds.SessionAction,
            new { action = "take_floor", sessionId = s.Id, actorUserId = _sessionActorBox?.Text.Trim() }, _sessionStatus);
        floor.Children.Add(takeBack);
        _sessionDetailBody.Children.Add(floor);

        foreach (var p in s.Participants)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            row.Children.Add(new TextBlock { Text = $"{p.Name} — {p.Role} · floor {p.Floor}" + (string.IsNullOrEmpty(p.Transport) ? "" : $" · via {p.Transport}"), FontSize = 13, Width = 300, VerticalAlignment = VerticalAlignment.Center });
            void PAct(string label, string action)
            {
                var b = new Button { Content = label, Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(8, 3, 8, 3) };
                b.Click += async (_, _) => await SendHostActionAsync(IpcKinds.SessionAction,
                    new { action, sessionId = s.Id, userId = p.UserId, actorUserId = _sessionActorBox?.Text.Trim() }, _sessionStatus);
                row.Children.Add(b);
            }
            PAct("Grant floor", "grant_floor");
            PAct("Watch-only", "set_watch_only");
            PAct("Remove", "remove_participant");
            _sessionDetailBody.Children.Add(row);
        }

        // Terminal channel (Block F): a session-scoped shell. The
        // roster shows it as a fact; only the floor holder's
        // keystrokes reach it (the Core's TerminalService gates
        // every write — this surface merely carries the acts).
        var termRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 4) };
        termRow.Children.Add(new TextBlock
        {
            Text = s.TerminalOpen ? "Terminal: OPEN on this session" : "Terminal: closed",
            FontSize = 13, FontWeight = FontWeights.SemiBold, Width = 300, VerticalAlignment = VerticalAlignment.Center,
        });
        void TAct(string label, string action)
        {
            var b = new Button { Content = label, Style = (Style)FindResource("GhostButton"), Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(8, 3, 8, 3) };
            b.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TerminalAction,
                new { action, sessionId = s.Id, actorUserId = _sessionActorBox?.Text.Trim() }, _sessionStatus);
            termRow.Children.Add(b);
        }
        if (s.TerminalOpen) { TAct("Close terminal", "close_session"); TAct("Show output", "output_session"); }
        else TAct("Open terminal", "open");
        _sessionDetailBody.Children.Add(termRow);
        if (s.TerminalOpen)
        {
            var writeRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
            var termInput = new TextBox { Width = 420, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center, ToolTip = "Keystrokes for the session terminal — sent only if the actor holds the floor (or is the host)" };
            var sendKeys = new Button { Content = "Send to terminal", Style = (Style)FindResource("GhostButton"), Padding = new Thickness(8, 3, 8, 3) };
            sendKeys.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TerminalAction,
                new { action = "write_session", sessionId = s.Id, actorUserId = _sessionActorBox?.Text.Trim(), text = termInput.Text + "\r\n" }, _sessionStatus);
            writeRow.Children.Add(termInput);
            writeRow.Children.Add(sendKeys);
            _sessionDetailBody.Children.Add(writeRow);
        }

        RenderStreamSection(s);

        if (s.Events.Count > 0)
        {
            _sessionDetailBody.Children.Add(Muted("Replay events (latest last):", 12));
            foreach (var e in s.Events.TakeLast(8))
                _sessionDetailBody.Children.Add(Muted($"{e.At.ToLocalTime():h:mm:ss tt} · {e.Kind} · {e.Detail}", 11.5));
        }
    }
}

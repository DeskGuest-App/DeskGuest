using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Acp.Shared.Ipc;
using Color = System.Windows.Media.Color;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;

namespace Acp.SessionAgent;

/// <summary>
/// The Enterprise page (Block F — the live wiring of Block E),
/// rebuilt by W100 to the floor pattern (S19 — the census's last
/// below-floor row, graded down for wall-of-text): the surface
/// carries ONLY the plain-language minimum — a live posture
/// summary a non-technical owner can read at a glance, rendered
/// from the REAL Core snapshot on every snapshot (FR-110, W76 —
/// never a stored claim) — and every tool (policy bundle,
/// chained audit, directory sync, break-glass, IdP sign-in,
/// quick assist, local AI pack, Tor) lives behind a clearly
/// labeled expansion, present but never dumped. NOTHING was
/// deleted to make it simpler: every control, handler and
/// explanatory line from the wall version survives inside its
/// expansion, word for word. Composition case: IN-LANGUAGE —
/// Gemini's S19 board exists but its body copy is garbled in
/// the source itself (revision draft §1: "unverifiable — rebuild
/// from UX-spec copy dictionary"), so the floor's layered
/// admin composition (summary first, rules/tools behind labeled
/// sections) is built in the DeskGuest component family of the
/// rebuilt Home (W70/W85) and agent-detail (W79/W97) pages.
/// </summary>
public partial class MainWindow
{
    private StackPanel? _enterpriseFacts;
    private TextBlock? _enterpriseStatus;
    private TextBlock? _quickAssistCodeText;
    private Expander? _quickAssistExpander;

    private UIElement BuildEnterprisePage()
    {
        var stack = new StackPanel();
        stack.Children.Add(PageTitle("Enterprise"));
        stack.Children.Add(Sub("Your company's protections, at a glance. The tools are below — open only the one you need."));
        // ---- the posture summary card (the whole default story) ----
        var summary = new StackPanel();
        summary.Children.Add(new TextBlock { Text = "How this PC is protected — right now", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        _enterpriseFacts = new StackPanel();
        summary.Children.Add(_enterpriseFacts);
        _enterpriseStatus = Muted("");
        summary.Children.Add(_enterpriseStatus);
        stack.Children.Add(Card(summary));

        TextBox Box(string tip, double width = 210) => new()
        {
            Width = width, Margin = new Thickness(0, 0, 6, 0),
            VerticalAlignment = VerticalAlignment.Center, ToolTip = tip,
        };
        Button Ghost(string label) => new()
        {
            Content = label, Style = (Style)FindResource("GhostButton"),
            Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5),
        };
        StackPanel Row() => new() { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        // W100: a tool section = one labeled expansion. Collapsed,
        // it is a single line (title + one plain hint); expanded,
        // it carries the section's full controls and prose —
        // layered, never amputated.
        Border ToolSection(string title, string hint, StackPanel body, out Expander expander)
        {
            var header = new StackPanel { Orientation = Orientation.Horizontal };
            header.Children.Add(new TextBlock { Text = title, FontSize = 15.5, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
            header.Children.Add(new TextBlock { Text = "  ·  " + hint, FontSize = 12.5, Foreground = new SolidColorBrush(Color.FromRgb(0x48, 0x61, 0x75)), VerticalAlignment = VerticalAlignment.Center });
            expander = new Expander { Header = header, Content = body, IsExpanded = false, Margin = new Thickness(0, 2, 0, 2) };
            return Card(expander);
        }

        // ---- policy + update enforcement ----
        var policy = new StackPanel();
        var policyRow = Row();
        var reload = Ghost("Reload policy bundle");
        reload.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "policy_reload" }, _enterpriseStatus);
        policyRow.Children.Add(reload);
        var versionBox = Box("Version to check, e.g. 0.5.0", 120);
        policyRow.Children.Add(versionBox);
        var check = Ghost("Check update against policy");
        check.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "update_check", version = versionBox.Text.Trim() }, _enterpriseStatus);
        policyRow.Children.Add(check);
        policy.Children.Add(policyRow);
        policy.Children.Add(Muted("The bundle lives in the Core's data folder (policy-bundle.json + the org key). A bundle that fails verification loads NOTHING — a swapped or forged bundle never widens policy, and the Updates surface refuses pinned/deferred versions at staging time."));
        stack.Children.Add(ToolSection("Policy bundle", "reload it, or check an update against it", policy, out _));

        // ---- chained audit ----
        var audit = new StackPanel();
        var auditRow = Row();
        foreach (var fmt in new[] { "json", "csv", "cef" })
        {
            var b = Ghost($"Export {fmt.ToUpperInvariant()}");
            var f = fmt;
            b.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
                new { action = "audit_export", format = f, actorUserId = "operator" }, _enterpriseStatus);
            auditRow.Children.Add(b);
        }
        var verify = Ghost("Verify chain");
        verify.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "audit_verify" }, _enterpriseStatus);
        auditRow.Children.Add(verify);
        var alerts = Ghost("Show alerts");
        alerts.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "alerts" }, _enterpriseStatus);
        auditRow.Children.Add(alerts);
        audit.Children.Add(auditRow);
        audit.Children.Add(Muted("Exports are written into the Core's exports folder and carry the chain verdict in their header — a broken chain exports as BROKEN, never dressed up."));
        stack.Children.Add(ToolSection("Chained audit", "export the record, verify it, see alerts", audit, out _));

        // ---- directory sync ----
        var sync = new StackPanel();
        var syncRow1 = Row();
        var bindBox = Box("External scope binding", 150); var scopeBox = Box("Scope id", 110);
        var userBox = Box("User id", 110); var nameBox = Box("Display name", 150);
        syncRow1.Children.Add(bindBox); syncRow1.Children.Add(scopeBox);
        syncRow1.Children.Add(userBox); syncRow1.Children.Add(nameBox);
        sync.Children.Add(syncRow1);
        var syncRow2 = Row();
        var actionBox = Box("Action: create | suspend | remove", 190);
        var extBox = Box("External id", 130); var actorBox = Box("Acting admin user id", 150);
        var applySync = Ghost("Apply event");
        applySync.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new
            {
                action = "sync_event", actorUserId = actorBox.Text.Trim(),
                @event = new
                {
                    externalScopeBinding = bindBox.Text.Trim(), scopeId = scopeBox.Text.Trim(),
                    userId = userBox.Text.Trim(), displayName = nameBox.Text.Trim(),
                    action = actionBox.Text.Trim(), externalId = extBox.Text.Trim(),
                },
            }, _enterpriseStatus);
        syncRow2.Children.Add(actionBox); syncRow2.Children.Add(extBox);
        syncRow2.Children.Add(actorBox); syncRow2.Children.Add(applySync);
        sync.Children.Add(syncRow2);
        sync.Children.Add(Muted("A remove event drives the real offboarding (D14) through the live Core. A binding that does not match the scope is refused as cross-scope injection; replaying an event changes nothing twice."));
        stack.Children.Add(ToolSection("Directory sync", "apply a create / suspend / remove event", sync, out _));

        // ---- break-glass ----
        var glass = new StackPanel();
        var gRow1 = Row();
        var gScope = Box("Scope id", 110); var gReason = Box("Reason (required)", 260);
        var gDrill = new CheckBox { Content = "Drill", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
        gRow1.Children.Add(gScope); gRow1.Children.Add(gReason); gRow1.Children.Add(gDrill);
        glass.Children.Add(gRow1);
        var gRow2 = Row();
        var h1 = Box("Holder 1 id", 110); var s1 = Box("Holder 1 secret", 130);
        var h2 = Box("Holder 2 id", 110); var s2 = Box("Holder 2 secret", 130);
        var use = new Button
        {
            Content = "Use break-glass", Style = (Style)FindResource("DangerButton"),
            Margin = new Thickness(0, 0, 6, 0), Padding = new Thickness(10, 5, 10, 5),
        };
        use.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new
            {
                action = "break_glass_use", scopeId = gScope.Text.Trim(), reason = gReason.Text.Trim(),
                holder1 = h1.Text.Trim(), secret1 = s1.Text.Trim(),
                holder2 = h2.Text.Trim(), secret2 = s2.Text.Trim(),
                drill = gDrill.IsChecked == true,
            }, _enterpriseStatus);
        gRow2.Children.Add(h1); gRow2.Children.Add(s1); gRow2.Children.Add(h2); gRow2.Children.Add(s2); gRow2.Children.Add(use);
        glass.Children.Add(gRow2);
        glass.Children.Add(Muted("Two DISTINCT sealed holders, a stated reason. The use is written into the chained audit and raised as an alert BEFORE the grant exists — loud by construction. Any use makes holder-secret rotation required."));
        var gRow3 = Row();
        var r1 = Box("Rotate: holder id", 110); var rc1 = Box("Holder's CURRENT secret", 140); var rs1 = Box("Holder's NEW secret", 130);
        var rotate = Ghost("Rotate this holder's secret");
        rotate.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new
            {
                action = "break_glass_rotate",
                holder1 = r1.Text.Trim(), currentSecret1 = rc1.Text.Trim(), newSecret1 = rs1.Text.Trim(),
            }, _enterpriseStatus);
        gRow3.Children.Add(r1); gRow3.Children.Add(rc1); gRow3.Children.Add(rs1); gRow3.Children.Add(rotate);
        glass.Children.Add(gRow3);
        glass.Children.Add(MutedT("Rotation is one holder at a time, by the holder themselves, and only while one is owed (after a use or drill). After any use or drill, break-glass stays refused until EVERY holder has rotated.", "The holder's CURRENT secret proves possession. Rotation replaces the secret in the live service AND in the holder store on disk, and is itself chained-audited — rotating one of two does not complete it."));
        stack.Children.Add(ToolSection("Break-glass", "emergency access — two holders, a stated reason", glass, out _));

        // ---- IdP sign-in (mock leg live) ----
        var idp = new StackPanel();
        var iRow = Row();
        var subjBox = Box("Subject", 130); var emailBox = Box("Email", 190);
        var verified = new CheckBox { Content = "Email verified", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
        var begin = Ghost("Begin (mock IdP)");
        begin.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "idp_begin", subject = subjBox.Text.Trim(), email = emailBox.Text.Trim(), emailVerified = verified.IsChecked == true }, _enterpriseStatus);
        var complete = Ghost("Complete sign-in");
        complete.Click += async (_, _) => await SendHostActionAsync(IpcKinds.EnterpriseAction,
            new { action = "idp_complete" }, _enterpriseStatus);
        iRow.Children.Add(subjBox); iRow.Children.Add(emailBox); iRow.Children.Add(verified);
        iRow.Children.Add(begin); iRow.Children.Add(complete);
        idp.Children.Add(iRow);
        stack.Children.Add(ToolSection("IdP sign-in", "the mock sign-in leg, live", idp, out _));

        // ---- quick assist ----
        var qa = new StackPanel();
        _quickAssistCodeText = new TextBlock { FontSize = 26, FontWeight = FontWeights.SemiBold, FontFamily = new System.Windows.Media.FontFamily("Consolas"), Visibility = Visibility.Collapsed, Margin = new Thickness(0, 2, 0, 4) };
        qa.Children.Add(_quickAssistCodeText);
        var qRow = Row();
        var qScope = Box("Scope id", 110); var qDevice = Box("Host device id", 170); var qInit = Box("Initiator user id", 130);
        var mint = Ghost("Mint session code");
        mint.Click += async (_, _) => await SendHostActionAsync(IpcKinds.QuickAssistAction,
            new { action = "mint", scopeId = qScope.Text.Trim(), hostDeviceId = qDevice.Text.Trim(), initiatorUserId = qInit.Text.Trim() }, _enterpriseStatus);
        qRow.Children.Add(qScope); qRow.Children.Add(qDevice); qRow.Children.Add(qInit); qRow.Children.Add(mint);
        qa.Children.Add(qRow);
        var qRow2 = Row();
        var qGrant = Box("Grant id to close", 240);
        var qClose = Ghost("Close code / grant");
        qClose.Click += async (_, _) => await SendHostActionAsync(IpcKinds.QuickAssistAction,
            new { action = "close", id = qGrant.Text.Trim() }, _enterpriseStatus);
        qRow2.Children.Add(qGrant); qRow2.Children.Add(qClose);
        qa.Children.Add(qRow2);
        qa.Children.Add(Muted("A code is single-use, view-only, and lives 10 minutes; five failed redeems burn the mint into a lockout. The web front door redeems over the mesh lanes only — browser side is view-only by platform law. Closing kills the code and its grant together."));
        stack.Children.Add(ToolSection("Quick assist", "mint or close a one-time help code", qa, out _quickAssistExpander));

        // ---- local AI pack + manual WebRTC ----
        var pack = new StackPanel();
        var pRow = Row();
        var pStatus = Ghost("Pack status");
        pStatus.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "status" }, _enterpriseStatus);
        var pLicence = Ghost("Show licence");
        pLicence.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "licence" }, _enterpriseStatus);
        var pAccept = Ghost("Accept licence");
        pAccept.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "accept_licence", userId = "operator" }, _enterpriseStatus);
        var wStatus = Ghost("WebRTC media status");
        wStatus.Click += async (_, _) => await SendHostActionAsync(IpcKinds.WebRtcAction,
            new { action = "media_status" }, _enterpriseStatus);
        pRow.Children.Add(pStatus); pRow.Children.Add(pLicence); pRow.Children.Add(pAccept); pRow.Children.Add(wStatus);
        pack.Children.Add(pRow);
        var pRow2 = Row();
        var pDownload = Ghost("Download pack");
        pDownload.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "download" }, _enterpriseStatus);
        var pDlStatus = Ghost("Download status");
        pDlStatus.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "download_status" }, _enterpriseStatus);
        var pDlCancel = Ghost("Cancel download");
        pDlCancel.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "download_cancel" }, _enterpriseStatus);
        var pVerify = Ghost("Verify installed pack");
        pVerify.Click += async (_, _) => await SendHostActionAsync(IpcKinds.AiPackAction,
            new { action = "verify", directory = "" }, _enterpriseStatus);
        pRow2.Children.Add(pDownload); pRow2.Children.Add(pDlStatus); pRow2.Children.Add(pDlCancel); pRow2.Children.Add(pVerify);
        pack.Children.Add(pRow2);
        pack.Children.Add(MutedT("The pack (UI-TARS-1.5-7B, Apache-2.0) downloads only from the author's official source, only against hashes pinned in the product, and refuses on any mismatch — no override.", "Accept the licence first; the download then runs in the background into the product's pack home (shown by Pack status), resumable across cancels — files already landed that still verify are skipped on restart. The pack runs as a leashed AI participant under its own identity, never as admin; its runtime is unaudited (T7/S11) and labeled so."));
        stack.Children.Add(ToolSection("Local AI pack · manual WebRTC", "the on-device AI pack and media status", pack, out _));

        // ---- Tor provisioning (A2, W19-C wiring) ----
        var tor = new StackPanel();
        var tRow = Row();
        var tSetup = Ghost("Set up Tor");
        tSetup.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TorAction,
            new { action = "setup" }, _enterpriseStatus);
        var tStatus = Ghost("Tor status");
        tStatus.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TorAction,
            new { action = "status" }, _enterpriseStatus);
        var tStop = Ghost("Stop Tor");
        tStop.Click += async (_, _) => await SendHostActionAsync(IpcKinds.TorAction,
            new { action = "stop" }, _enterpriseStatus);
        tRow.Children.Add(tSetup); tRow.Children.Add(tStatus); tRow.Children.Add(tStop);
        tor.Children.Add(tRow);
        tor.Children.Add(MutedT("Set up provisions the pinned Tor client (expert bundle 16.0.1, hashes pinned in the product) from the Tor Project's own distribution directory, and runs it as a local-only SOCKS listener.", "The binary is re-verified before launch, and tor.json is written only once the listener answers. The component is client-only: there is no onion service, and Tor's exits refuse private/LAN targets (that refusal is Tor's own behaviour)."));
        stack.Children.Add(ToolSection("Tor provisioning", "set up, check, or stop the Tor client", tor, out _));

        // ---- fleet register (W8, OI-17) ----
        var fleet = new StackPanel();
        var fleetHead = new TextBlock { Text = "Fleet register", FontSize = 16.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) };
        fleet.Children.Add(fleetHead);
        _fleetBody = new StackPanel();
        fleet.Children.Add(_fleetBody);
        stack.Children.Add(Card(fleet));

        // ---- detail behind one more labeled expansion: the
        // real-IdP boundary paragraph (kept word for word, no
        // longer dumped on the default surface) ----
        var detail = new StackPanel();
        _enterpriseDetail = new StackPanel();
        detail.Children.Add(_enterpriseDetail);
        stack.Children.Add(ToolSection("About sign-in with your company IdP", "what the real sign-in leg does and never does", detail, out _));

        RenderEnterprise();
        return stack;
    }

    private StackPanel? _enterpriseDetail;

    /// <summary>One readable status row in the posture summary:
    /// a short plain label, the live value in words, and a
    /// word-carrying chip when the state is a verdict (never
    /// colour alone). Values are rendered from the snapshot at
    /// render time — nothing here is stored.</summary>
    private static StackPanel PostureRow(string label, string value, string? chip = null, bool chipOk = true)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
        row.Children.Add(new TextBlock { Text = label, FontSize = 13.5, FontWeight = FontWeights.SemiBold, Width = 128, VerticalAlignment = VerticalAlignment.Top });
        var val = new TextBlock { Text = value, FontSize = 13.5, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Top, MaxWidth = 560 };
        row.Children.Add(val);
        if (chip is not null)
        {
            var c = Chip(chip, chipOk ? GreenBg : RedBg, chipOk ? GreenFg : RedFg);
            c.Margin = new Thickness(8, 0, 0, 0);
            row.Children.Add(c);
        }
        return row;
    }

    /// <summary>The posture summary at the top of the Enterprise
    /// page, re-rendered from every Core snapshot: the plain lead
    /// line, short status rows (policy, chain, alerts), the
    /// FR-110 posture lines (W76 — the Core's posture-audit
    /// states as text through the Strings door, so a FAILED
    /// posture is eye-visible, not only API-visible), and the
    /// locked "Always true" floor block (S19 revision item (i)).
    /// The live truth, not a cached claim.</summary>
    private void RenderEnterprise()
    {
        if (_enterpriseFacts is null) return;
        _enterpriseFacts.Children.Clear();
        var e = _host?.Enterprise;
        if (e is null)
        {
            _enterpriseFacts.Children.Add(Muted("Waiting for the Core's snapshot — enterprise facts arrive with it."));
            return;
        }
        var needsAttention = !e.PolicyLoaded || !e.ChainOk || e.AlertCount > 0 || e.BreakGlassRotationRequired;
        _enterpriseFacts.Children.Add(Body(needsAttention
            ? "Some protections need attention — they're marked below."
            : "Everything is on and checking out. Nothing here needs you right now.", 14));
        _enterpriseFacts.Children.Add(PostureRow("Policy", e.PolicyState, e.PolicyLoaded ? "On" : "Check", e.PolicyLoaded));
        _enterpriseFacts.Children.Add(PostureRow("Audit record", e.ChainSummary, e.ChainOk ? "Intact" : "BROKEN", e.ChainOk));
        _enterpriseFacts.Children.Add(Body(Strings.Format("PosturePointerSigningFormat", e.PointerSigningPostureAudit)));
        _enterpriseFacts.Children.Add(Body(Strings.Format("PostureUpdateSigningFormat", e.UpdateSigningPostureAudit)));
        _enterpriseFacts.Children.Add(Body(Strings.Format("PostureAnchorMarkerFormat", e.AnchorMarker)));
        _enterpriseFacts.Children.Add(PostureRow("Alerts", $"{e.AlertCount}" +
            (e.BreakGlassRotationRequired ? " · break-glass holder rotation REQUIRED" : ""),
            e.AlertCount > 0 || e.BreakGlassRotationRequired ? "Check" : null, false));
        // S19 revision (i): the floor properties are a locked
        // "Always true" block — words, no switches.
        _enterpriseFacts.Children.Add(new TextBlock { Text = "Always true — these can't be turned off", FontSize = 13.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 2) });
        _enterpriseFacts.Children.Add(Muted("You always see who is connected to this PC.  ·  STOP always works.  ·  The audit record can't be edited."));
        if (_enterpriseDetail is not null)
        {
            _enterpriseDetail.Children.Clear();
            if (!string.IsNullOrEmpty(e.RealIdpBoundary))
                _enterpriseDetail.Children.Add(Muted(e.RealIdpBoundary));
            else
                _enterpriseDetail.Children.Add(Muted("No company IdP is configured on this PC."));
        }
        RenderFleetRegister(e);
    }

    /// <summary>W8 — the Fleet/RMM register surface (record §6,
    /// OI-17): status by exception — what needs attention leads, in
    /// words — and EffectivePolicy sentences naming their setter.
    /// The consent floor renders ABOVE the register and is never
    /// attributed to a setter (FleetRegisterModel). The org name is
    /// the record's placeholder: Northwind.</summary>
    private StackPanel? _fleetBody;

    private void RenderFleetRegister(EnterpriseData e)
    {
        if (_fleetBody is null) return;
        _fleetBody.Children.Clear();
        _fleetBody.Children.Add(new TextBlock
        {
            Text = Acp.Shared.Design.FleetRegisterModel.ConsentFloorTitle(),
            FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4),
        });
        _fleetBody.Children.Add(Muted(Acp.Shared.Design.FleetRegisterModel.ConsentFloorLine(), 12));
        var setter = e.PolicyLoaded ? "Northwind IT" : null;
        var rules = new List<Acp.Shared.Design.FleetRegisterModel.Rule>
        {
            new($"Policy bundle: {e.PolicyState}", setter, NeedsAttention: !e.PolicyLoaded),
            new($"Audit chain: {(e.ChainOk ? "OK" : "BROKEN")} — {e.ChainSummary}", setter, NeedsAttention: !e.ChainOk),
            new($"Alerts: {e.AlertCount}", setter, NeedsAttention: e.AlertCount > 0),
            new("Break-glass holder rotation required", setter, NeedsAttention: e.BreakGlassRotationRequired),
        };
        foreach (var rule in Acp.Shared.Design.FleetRegisterModel.OrderByException(rules))
        {
            if (!rule.NeedsAttention && rule.Sentence.StartsWith("Break-glass", StringComparison.Ordinal)) continue;
            _fleetBody.Children.Add(Body(Acp.Shared.Design.FleetRegisterModel.RuleLine(rule)));
        }
    }

    /// <summary>The Core's minted quick-assist code, shown once,
    /// here, to the person at the keyboard (same discipline as
    /// pairing and enrollment codes). W100: the code lives inside
    /// the Quick assist expansion now, so minting opens it.</summary>
    public void SetQuickAssistCode(string json)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => SetQuickAssistCode(json)); return; }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var code = doc.RootElement.GetProperty("code").GetString() ?? "";
            ShowPage("enterprise");
            if (_quickAssistExpander is not null) _quickAssistExpander.IsExpanded = true;
            if (_quickAssistCodeText is not null)
            {
                _quickAssistCodeText.Text = string.Join(" ", code.ToCharArray());
                _quickAssistCodeText.Visibility = Visibility.Visible;
            }
            if (_enterpriseStatus is not null)
                _enterpriseStatus.Text = "Session code minted — give it to the person being helped. View-only, single-use, 10 minutes.";
        }
        catch { }
    }
}

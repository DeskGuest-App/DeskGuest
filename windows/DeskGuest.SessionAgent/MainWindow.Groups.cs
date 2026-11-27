using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DeskGuest.Shared.Ipc;
using Brushes = System.Windows.Media.Brushes;
using Button = System.Windows.Controls.Button;
using CheckBox = System.Windows.Controls.CheckBox;
using ComboBox = System.Windows.Controls.ComboBox;
using Orientation = System.Windows.Controls.Orientation;
using TextBox = System.Windows.Controls.TextBox;
using Color = System.Windows.Media.Color;
using HorizontalAlignment = System.Windows.HorizontalAlignment;

namespace DeskGuest.SessionAgent;

/// <summary>
/// The Groups Management page (Screen 59, census N06; Face Tranche 1
/// item 2a, pack 01-groups-management) WITH the Gemini convergence
/// from the five 1A–1E boards — every adopt/reject choice is recorded
/// in the pack MANIFEST's build record and in BUILD-DIFF.md.
///
/// DATA LAW: every fact rendered comes from the Core's host-state
/// snapshot roster section (scopes, users, user groups, grants,
/// device groups) — the same live feed the Roster page reads. The
/// snapshot carries NO email addresses, NO per-person presence and
/// NO pending-invite list, so the pack's email lines, Online/Offline
/// pills and pending-invite row are NOT rendered as data; the page
/// shows its designed empty/honest states for those slots instead
/// (see BUILD-DIFF). Acts: creating a user group rides the real
/// RosterAction create_user_group. Add-member, remove-from-group,
/// make-admin and email invites exist in the roster MODEL
/// (RosterService) but are NOT routed over IPC by the Core, so those
/// flows are built honestly up to the act and name the gap on the
/// surface — no dead clicks, no pretend success.
/// </summary>
public partial class MainWindow
{
    // ---- page state -------------------------------------------------
    private string _groupsTab = "company"; // "company" | "personal"
    private string? _selectedGroupKey;     // scopeId + "\n" + groupId
    private string _groupsSignature = "";
    private StackPanel? _groupsListPanel;
    private StackPanel? _groupsDetailPanel;
    private TextBlock? _groupsStatus;
    private Button? _tabCompany;
    private Button? _tabPersonal;
    private Border? _groupsOverlay;
    private StackPanel? _overlayBody;
    private string _overlayMode = "";      // "" | wizard | invite | member | remove | refusal

    // ---- wizard state (board 1C: 3 steps) ---------------------------
    private int _wizStep = 1;
    private string _wizKind = "personal";
    private string? _wizScopeId;
    private string _wizName = "";
    private string _wizId = "";
    private TextBox? _wizNameBox;
    private TextBox? _wizIdBox;
    private ComboBox? _wizScopeBox;
    private readonly Dictionary<string, CheckBox> _wizMembers = new();
    private readonly Dictionary<string, CheckBox> _wizAdmins = new();

    private System.Windows.Media.Brush Res(string key) => (System.Windows.Media.Brush)FindResource(key);
    private static string Key2(string scopeId, string groupId) => scopeId + "\n" + groupId;

    private (RosterScopeData Scope, RosterUserGroupData Group)? SelectedGroup()
    {
        if (_host is null) return null;
        foreach (var scope in _host.Roster)
            foreach (var g in scope.UserGroups)
                if (Key2(scope.Id, g.Id) == _selectedGroupKey) return (scope, g);
        return null;
    }

    private RosterUserData? FindUser(RosterScopeData scope, string userId) =>
        scope.Users.FirstOrDefault(u => string.Equals(u.Id, userId, StringComparison.OrdinalIgnoreCase));

    private string UserName(RosterScopeData scope, string userId) =>
        FindUser(scope, userId)?.Name ?? userId;

    private static string Initials(string name)
    {
        var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return "?";
        return parts.Length == 1
            ? parts[0][..Math.Min(2, parts[0].Length)].ToUpperInvariant()
            : (parts[0][0].ToString() + parts[^1][0]).ToUpperInvariant();
    }

    private static string Slug(string name)
    {
        var chars = name.Trim().ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        var slug = new string(chars).Trim('-');
        while (slug.Contains("--")) slug = slug.Replace("--", "-");
        return slug;
    }

    // ================= BUILD =================

    private UIElement BuildGroupsPage()
    {
        var root = new Grid();
        var stack = new StackPanel();
        // #149 rework: the painting's title scale (30px / bold) carried
        // locally — the shared PageTitle helper (27 / semibold) is the
        // other pages' scale and is not this page's to change. The
        // sub-line is plain language only: who is in each group, and
        // who looks after it (the earlier line's Core/roster wording
        // was engineering language on a person's surface).
        stack.Children.Add(new TextBlock { Text = "Groups Management", FontSize = 30, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 2, 0, 2) });
        stack.Children.Add(Sub("Who is in each group, and who looks after it."));

        // Tabs (pack: Company Groups selected with a navy underline,
        // Personal Groups muted). Board 1A lists both kinds in one
        // rail; the pack's tab split is kept — it is the stronger
        // company/personal wall presentation (D8).
        var tabRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
        _tabCompany = TabButton("Company Groups", "company");
        _tabPersonal = TabButton("Personal Groups", "personal");
        tabRow.Children.Add(_tabCompany);
        tabRow.Children.Add(_tabPersonal);
        stack.Children.Add(tabRow);
        stack.Children.Add(new Border { Height = 1, Background = Res("DgBorderBrush"), Margin = new Thickness(0, 0, 0, 18) });

        _groupsStatus = Muted("");
        _groupsStatus.Margin = new Thickness(0, 0, 0, 8);
        stack.Children.Add(_groupsStatus);

        // Two columns, pack geometry: 302px group rail + detail.
        var cols = new Grid();
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(302) });
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(38) });
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var left = new StackPanel();
        left.Children.Add(new TextBlock { Text = "Groups", FontSize = 26, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 8) });
        _groupsListPanel = new StackPanel();
        left.Children.Add(_groupsListPanel);
        // Board 1A adoption: the create door lives under the rail.
        var create = new Button
        {
            Content = "+  Create group", Style = (Style)FindResource("PrimaryButton"),
            HorizontalAlignment = HorizontalAlignment.Stretch, Margin = new Thickness(0, 16, 0, 0),
            Padding = new Thickness(14, 12, 14, 12), FontSize = 16,
        };
        create.Click += (_, _) => OpenWizard();
        left.Children.Add(create);
        Grid.SetColumn(left, 0);
        cols.Children.Add(left);
        _groupsDetailPanel = new StackPanel();
        Grid.SetColumn(_groupsDetailPanel, 2);
        cols.Children.Add(_groupsDetailPanel);
        stack.Children.Add(cols);
        root.Children.Add(stack);

        // Overlay host (wizard / invite / member actions / removal
        // preview / last-admin refusal) — one dimmed layer, one card.
        _overlayBody = new StackPanel();
        var card = new Border
        {
            Background = Res("DgSurfaceBrush"), CornerRadius = new CornerRadius(16),
            Padding = new Thickness(26, 22, 26, 22), MaxWidth = 660,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            Child = _overlayBody,
        };
        card.Effect = new System.Windows.Media.Effects.DropShadowEffect
        { Color = Color.FromRgb(0x0F, 0x25, 0x37), BlurRadius = 24, ShadowDepth = 4, Opacity = 0.25 };
        _groupsOverlay = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x66, 0x0F, 0x25, 0x37)),
            Visibility = Visibility.Collapsed, Child = card,
        };
        root.Children.Add(_groupsOverlay);

        RenderGroups();
        return root;
    }

    private Button TabButton(string label, string tab)
    {
        var b = new Button
        {
            Content = label, Tag = tab, Background = Brushes.Transparent, BorderThickness = new Thickness(0),
            FontSize = 18.5, Padding = new Thickness(2, 8, 2, 10), Margin = new Thickness(0, 0, 38, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        b.Click += (_, _) =>
        {
            _groupsTab = tab;
            _selectedGroupKey = null; // re-pick the first group of this kind
            _groupsSignature = "";
            RenderGroups();
        };
        return b;
    }

    // ================= RENDER =================

    private string GroupsSignature()
    {
        if (_host is null) return "nohost";
        var parts = new List<string> { _groupsTab, _selectedGroupKey ?? "-" };
        foreach (var s in _host.Roster)
        {
            parts.Add($"{s.Id}|{s.Kind}|{s.Name}|{string.Join(",", s.CompanyAdmins)}");
            foreach (var u in s.Users) parts.Add($"u:{u.Id}:{u.Name}:{u.Kind}:{u.PairedBy}:{u.Suspended}");
            foreach (var g in s.UserGroups) parts.Add($"g:{g.Id}:{g.Name}:[{string.Join(",", g.Members)}]:[{string.Join(",", g.Admins)}]");
            foreach (var d in s.DeviceGroups) parts.Add($"d:{d.Id}:{d.Devices.Count}");
            foreach (var gr in s.Grants) parts.Add($"gr:{gr.UserGroupId}>{gr.DeviceGroupId}:{string.Join(",", gr.Rights)}");
        }
        return string.Join(";", parts);
    }

    public void RenderGroups()
    {
        if (_groupsListPanel is null || _groupsDetailPanel is null) return;
        // Never rebuild under an open overlay: the wizard and invite
        // flows hold live text the 2s tick would wipe.
        if (_overlayMode.Length > 0) return;
        var sig = GroupsSignature();
        if (sig == _groupsSignature) return;
        _groupsSignature = sig;

        // Tab styling: selected = navy text + 3px navy underline
        // (carried on a bottom border), other = muted.
        StyleTab(_tabCompany, _groupsTab == "company");
        StyleTab(_tabPersonal, _groupsTab == "personal");

        _groupsListPanel.Children.Clear();
        _groupsDetailPanel.Children.Clear();

        // LOADING state (composed in-language, MANIFEST G-4): the
        // snapshot has not arrived yet.
        if (_host is null)
        {
            _groupsListPanel.Children.Add(Muted("Waiting for the Core's snapshot — groups arrive with it."));
            _groupsDetailPanel.Children.Add(Muted("Nothing to show yet."));
            return;
        }

        var scopes = _host.Roster.Where(s => s.Kind == _groupsTab).ToList();
        var groups = scopes.SelectMany(s => s.UserGroups.Select(g => (Scope: s, Group: g))).ToList();

        // Keep the selection inside this tab; default to its first group.
        if (_selectedGroupKey is null || groups.All(x => Key2(x.Scope.Id, x.Group.Id) != _selectedGroupKey))
            _selectedGroupKey = groups.Count > 0 ? Key2(groups[0].Scope.Id, groups[0].Group.Id) : null;

        // EMPTY state (G-4): no groups of this kind yet. #149 rework:
        // the empty state is a state of the surface, not an absence of
        // one — the rail card carries the fact at reading size, and
        // the detail column carries an anchored card in the painting's
        // language (kit mark, a heading, what a group is for in plain
        // words, and the group's standing rules as chips — product
        // law, not data) instead of one floating muted sentence over
        // a void. Every word here was already true of the surface;
        // no fact is invented and no door is added.
        if (groups.Count == 0)
        {
            var company = _groupsTab == "company";
            var empty = new StackPanel();
            empty.Children.Add(Body(company
                ? "No company groups yet."
                : "No personal groups yet.", 16));
            var railNote = Muted(_host.Roster.Count == 0
                ? "There are no scopes yet — a scope is created on the Roster page, then a group can be added to it here."
                : "Use Create group to add the first one.", 13);
            railNote.Margin = new Thickness(0, 6, 0, 0);
            empty.Children.Add(railNote);
            var railCard = Card(empty);
            railCard.Padding = new Thickness(18, 16, 18, 16);
            _groupsListPanel.Children.Add(railCard);

            var detail = new StackPanel();
            try
            {
                detail.Children.Add(new System.Windows.Controls.Image
                {
                    Width = 72, Height = 72, HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(0, 2, 0, 10),
                    Source = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/deskguest-mark-tight.png")),
                });
            }
            catch { /* the mark is decoration; its absence never blanks the card */ }
            detail.Children.Add(new TextBlock
            {
                Text = company ? "Company groups hold a team's people" : "Personal groups hold family and friends",
                FontSize = 20, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
            });
            detail.Children.Add(Body(company
                ? "A group is how you say who can reach which devices. The people in a group can use the devices linked to it, and the group's Admins look after who is in it."
                : "A personal group is a space for family, friends, or your own devices. The people in it can use the devices linked to it — and no workplace rules apply here.", 14.5));
            var facts = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 16, 0, 0) };
            var f1 = Chip("Admins manage members", GrayBg, GrayFg); facts.Children.Add(f1);
            var f2 = Chip("Members use linked devices", GrayBg, GrayFg); f2.Margin = new Thickness(8, 0, 0, 0); facts.Children.Add(f2);
            var f3 = Chip("An AI can join, never as Admin", GrayBg, GrayFg); f3.Margin = new Thickness(8, 0, 0, 0); facts.Children.Add(f3);
            detail.Children.Add(facts);
            var detailCard = Card(detail);
            detailCard.Padding = new Thickness(26, 24, 26, 24);
            detailCard.Margin = new Thickness(0, 34, 0, 0);
            _groupsDetailPanel.Children.Add(detailCard);
            return;
        }

        foreach (var (scope, g) in groups)
        {
            var selected = Key2(scope.Id, g.Id) == _selectedGroupKey;
            var inner = new StackPanel();
            inner.Children.Add(new TextBlock { Text = g.Name, FontSize = 19, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            inner.Children.Add(Muted(g.Members.Length == 1 ? "1 member" : $"{g.Members.Length} members", 13));
            if (scopes.Count > 1) inner.Children.Add(Muted(scope.Name, 12));
            var cardBtn = new Button
            {
                Content = inner, HorizontalContentAlignment = HorizontalAlignment.Left,
                Background = selected ? new SolidColorBrush(Color.FromRgb(0xE9, 0xF3, 0xFA)) : Res("DgSurfaceBrush"),
                BorderBrush = selected ? Res("DgBlueBrush") : Res("DgBorderBrush"),
                BorderThickness = new Thickness(selected ? 2 : 1),
                Padding = new Thickness(16, 16, 16, 16), Margin = new Thickness(0, 0, 0, 12),
                Cursor = System.Windows.Input.Cursors.Hand,
            };
            // Rounded card chrome (pack: radius 8 on group cards).
            var factory = new FrameworkElementFactory(typeof(Border));
            factory.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("Background") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            factory.SetBinding(Border.BorderBrushProperty, new System.Windows.Data.Binding("BorderBrush") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            factory.SetBinding(Border.BorderThicknessProperty, new System.Windows.Data.Binding("BorderThickness") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
            factory.SetBinding(Border.PaddingProperty, new System.Windows.Data.Binding("Padding") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
            var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
            factory.AppendChild(presenter);
            cardBtn.Template = new ControlTemplate(typeof(Button)) { VisualTree = factory };
            var key = Key2(scope.Id, g.Id);
            cardBtn.Click += (_, _) => { _selectedGroupKey = key; _groupsSignature = ""; RenderGroups(); };
            _groupsListPanel.Children.Add(cardBtn);
        }

        RenderGroupDetail();
    }

    private void StyleTab(Button? b, bool selected)
    {
        if (b is null) return;
        b.Foreground = selected ? Res("DgTextBrush") : Res("DgMutedBrush");
        b.FontWeight = selected ? FontWeights.Bold : FontWeights.Normal;
        b.BorderBrush = selected ? Res("DgNavyBrush") : Brushes.Transparent;
        b.BorderThickness = new Thickness(0, 0, 0, selected ? 3 : 0);
    }

    private void RenderGroupDetail()
    {
        if (_groupsDetailPanel is null || _host is null) return;
        var sel = SelectedGroup();
        if (sel is null) { _groupsDetailPanel.Children.Add(Muted("Pick a group on the left.")); return; }
        var (scope, g) = sel.Value;
        var personal = scope.Kind == "personal";

        // Header: group name + kind chip + invite door (pack +
        // boards 1A/1E: chip reads "Company Group"/"Personal Group";
        // the personal door reads "Invite person").
        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var titleRow = new StackPanel { Orientation = Orientation.Horizontal };
        titleRow.Children.Add(new TextBlock { Text = g.Name, FontSize = 28, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center });
        var kindChip = Chip(personal ? "Personal Group" : "Company Group", GrayBg, GrayFg);
        kindChip.Margin = new Thickness(10, 0, 0, 0);
        titleRow.Children.Add(kindChip);
        Grid.SetColumn(titleRow, 0);
        head.Children.Add(titleRow);
        var invite = new Button
        {
            Content = personal ? "Invite person" : "+  Invite Member",
            Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(20, 11, 20, 11), FontSize = 16,
        };
        invite.Click += (_, _) => OpenInvite(scope, g);
        Grid.SetColumn(invite, 1);
        head.Children.Add(invite);
        _groupsDetailPanel.Children.Add(head);

        // Board 1E adoption: a personal group states what it is.
        if (personal)
            _groupsDetailPanel.Children.Add(Muted("A personal space for family and friends — no workplace rules apply here.", 13.5));

        // Subheads (pack): Members | Linked Devices.
        var sub = new Grid { Margin = new Thickness(0, 16, 0, 2) };
        sub.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        sub.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var membersHead = new TextBlock { Text = "Members", FontSize = 18, FontWeight = FontWeights.SemiBold };
        Grid.SetColumn(membersHead, 0); sub.Children.Add(membersHead);
        var devicesHead = new TextBlock { Text = "Linked Devices", FontSize = 18, FontWeight = FontWeights.SemiBold };
        Grid.SetColumn(devicesHead, 1); sub.Children.Add(devicesHead);
        _groupsDetailPanel.Children.Add(sub);

        // Members (real snapshot data only: name, group-admin seat,
        // kind, paired-by, suspended. No email/presence feed exists).
        if (g.Members.Length == 0)
        {
            _groupsDetailPanel.Children.Add(Muted("No members yet. When this group was created its members were set; invites are not connected yet (see Invite)."));
        }
        foreach (var memberId in g.Members)
        {
            var user = FindUser(scope, memberId);
            var isAdmin = g.Admins.Contains(memberId, StringComparer.OrdinalIgnoreCase);
            _groupsDetailPanel.Children.Add(MemberRow(scope, g, memberId, user, isAdmin));
        }

        // Linked devices: the device groups this user group is
        // granted, with their real device counts (pack's per-member
        // device counts have no feed — devices belong to device
        // groups, not to people, in the roster model).
        var grants = _host.Roster
            .Where(s => s.Id == scope.Id)
            .SelectMany(s => s.Grants.Where(gr => string.Equals(gr.UserGroupId, g.Id, StringComparison.OrdinalIgnoreCase))
                .Select(gr => (Grant: gr, DeviceGroup: s.DeviceGroups.FirstOrDefault(d => string.Equals(d.Id, gr.DeviceGroupId, StringComparison.OrdinalIgnoreCase)))))
            .ToList();
        var linked = new StackPanel { Margin = new Thickness(0, 14, 0, 0) };
        if (grants.Count == 0)
        {
            linked.Children.Add(Muted("No device groups are linked to this group yet — a grant on the Roster page is what links them."));
        }
        foreach (var (grant, dg) in grants)
        {
            if (dg is null) continue;
            linked.Children.Add(Body($"{dg.Name} · {dg.Devices.Count} device(s) · rights: {string.Join(", ", grant.Rights)}", 13.5));
            foreach (var d in dg.Devices)
                linked.Children.Add(Muted($"    {d.Name}{(d.Revoked ? " · REVOKED" : "")}", 12));
        }
        _groupsDetailPanel.Children.Add(Card(linked));

        // Pending invites (pack section): NO invite feed exists in
        // the snapshot — the designed empty state, honestly named.
        _groupsDetailPanel.Children.Add(new TextBlock { Text = "Pending Invites", FontSize = 18, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 6) });
        // #149: the painting carries Pending Invites as a card row;
        // the honest empty line rides the same card chrome instead
        // of bare text under the section head.
        var pendingCard = Card(Body("No pending invites. Invites are not connected yet, so this list can only be empty — nothing is hidden.", 13.5));
        pendingCard.CornerRadius = new CornerRadius(8);
        pendingCard.Padding = new Thickness(18, 14, 18, 14);
        _groupsDetailPanel.Children.Add(pendingCard);
    }

    private Border MemberRow(RosterScopeData scope, RosterUserGroupData g, string memberId, RosterUserData? user, bool isAdmin)
    {
        var row = new Grid();
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var name = user?.Name ?? memberId;
        var avatar = new Border
        {
            Width = 52, Height = 52, CornerRadius = new CornerRadius(26),
            Background = Res("DgSubtleBrush"), VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = Initials(name), FontSize = 17, FontWeight = FontWeights.SemiBold,
                Foreground = Res("DgTextBrush"), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            },
        };
        Grid.SetColumn(avatar, 0);
        row.Children.Add(avatar);

        var who = new StackPanel { Margin = new Thickness(14, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        var nameRow = new StackPanel { Orientation = Orientation.Horizontal };
        nameRow.Children.Add(new TextBlock { Text = name, FontSize = 17.5, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
        // Pack badges: Group Admin = teal, Member = subtle.
        var badge = isAdmin
            ? Chip("Group Admin", Color.FromRgb(0x43, 0x8E, 0x8E), Colors.White)
            : Chip("Member", GrayBg, GrayFg);
        badge.Margin = new Thickness(9, 0, 0, 0);
        nameRow.Children.Add(badge);
        if (user is not null && user.Kind == "ai")
        {
            var ai = Chip("AI", GrayBg, GrayFg);
            ai.Margin = new Thickness(6, 0, 0, 0);
            nameRow.Children.Add(ai);
        }
        if (user is not null && user.Suspended)
        {
            var susp = Chip("Suspended", RedBg, RedFg);
            susp.Margin = new Thickness(6, 0, 0, 0);
            nameRow.Children.Add(susp);
        }
        who.Children.Add(nameRow);
        // Board 1A/1E subtitle: role · who brought them in. The
        // snapshot carries paired-by for AI users only; for humans
        // there is no inviter/email feed, so the line carries the
        // role and kind the snapshot does prove.
        var sub = isAdmin ? "Admin" : "Member";
        if (user is not null && !string.IsNullOrEmpty(user.PairedBy))
            sub += $" · Paired by {UserName(scope, user.PairedBy)}";
        else if (scope.CompanyAdmins.Contains(memberId, StringComparer.OrdinalIgnoreCase))
            sub += " · Company Admin";
        who.Children.Add(Muted(sub, 13));
        Grid.SetColumn(who, 1);
        row.Children.Add(who);

        // Boards' per-member "•••" door: member actions.
        var menu = new Button
        {
            Content = "•••", Style = (Style)FindResource("GhostButton"),
            Padding = new Thickness(10, 4, 10, 4), FontSize = 14, VerticalAlignment = VerticalAlignment.Center,
        };
        var capturedScope = scope; var capturedGroup = g; var capturedId = memberId;
        menu.Click += (_, _) => OpenMemberActions(capturedScope, capturedGroup, capturedId);
        Grid.SetColumn(menu, 2);
        row.Children.Add(menu);

        var card = Card(row);
        card.CornerRadius = new CornerRadius(8);
        card.Padding = new Thickness(18, 16, 18, 16);
        return card;
    }

    // ================= OVERLAY SHELL =================

    private void ShowOverlay(string mode)
    {
        _overlayMode = mode;
        if (_groupsOverlay is not null) _groupsOverlay.Visibility = Visibility.Visible;
    }

    private void CloseOverlay()
    {
        _overlayMode = "";
        if (_groupsOverlay is not null) _groupsOverlay.Visibility = Visibility.Collapsed;
        if (_overlayBody is not null) _overlayBody.Children.Clear();
        _groupsSignature = ""; // let the page re-render fresh facts
        RenderGroups();
    }

    private Button OverlayGhost(string label)
    {
        var b = new Button { Content = label, Style = (Style)FindResource("GhostButton"), Padding = new Thickness(14, 8, 14, 8), Margin = new Thickness(8, 0, 0, 0) };
        return b;
    }

    private TextBlock OverlayTitle(string text) => new()
    { Text = text, FontSize = 20, FontWeight = FontWeights.Bold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) };

    private static StackPanel ButtonRow() => new()
    { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };

    // ================= INVITE (gap-honest) =================

    private void OpenInvite(RosterScopeData scope, RosterUserGroupData g)
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Clear();
        var personal = scope.Kind == "personal";
        _overlayBody.Children.Add(OverlayTitle(personal ? $"Invite a person to {g.Name}" : $"Invite a member to {g.Name}"));
        _overlayBody.Children.Add(Body("Invites are not connected to the Core yet. DeskGuest has no invite list and sends no email today, so this panel cannot send anything — it is here so the door is in its place and the gap is named, not hidden.", 13.5));
        var email = new TextBox { FontSize = 14, Padding = new Thickness(8, 6, 8, 6), Margin = new Thickness(0, 12, 0, 0) };
        _overlayBody.Children.Add(Label("Email address"));
        _overlayBody.Children.Add(email);
        var status = Muted("");
        _overlayBody.Children.Add(status);
        var notInGroup = scope.Users.Where(u => !g.Members.Contains(u.Id, StringComparer.OrdinalIgnoreCase)).ToList();
        if (notInGroup.Count > 0)
        {
            _overlayBody.Children.Add(new TextBlock { Text = $"Already in {scope.Name}, not in this group", FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 14, 0, 4) });
            foreach (var u in notInGroup) _overlayBody.Children.Add(Muted($"• {u.Name}"));
            _overlayBody.Children.Add(Muted("Adding a person who is already in the scope to this group is also not connected yet — group members are set when a group is created."));
        }
        var row = ButtonRow();
        var send = new Button { Content = "Send invite", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(16, 8, 16, 8) };
        send.Click += (_, _) => status.Text = "Not sent — invites are not connected to the Core yet. Nothing was sent and no invite was recorded.";
        row.Children.Add(send);
        var cancel = OverlayGhost("Cancel");
        cancel.Click += (_, _) => CloseOverlay();
        row.Children.Add(cancel);
        _overlayBody.Children.Add(row);
        ShowOverlay("invite");
    }

    // ================= MEMBER ACTIONS / REMOVE / REFUSAL =================

    private void OpenMemberActions(RosterScopeData scope, RosterUserGroupData g, string memberId)
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Clear();
        var user = FindUser(scope, memberId);
        var name = user?.Name ?? memberId;
        var isAdmin = g.Admins.Contains(memberId, StringComparer.OrdinalIgnoreCase);
        _overlayBody.Children.Add(OverlayTitle(name));
        _overlayBody.Children.Add(Muted(isAdmin ? $"Group Admin of {g.Name}" : $"Member of {g.Name}", 13));
        var status = Muted("");
        status.Margin = new Thickness(0, 10, 0, 0);

        var actions = new StackPanel { Margin = new Thickness(0, 12, 0, 0) };
        if (!isAdmin && user is not null && user.Kind == "human")
        {
            var promote = new Button { Content = "Make Group Admin", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(14, 8, 14, 8), Margin = new Thickness(0, 0, 0, 8) };
            promote.Click += (_, _) => status.Text = "Not done — making a member a Group Admin is not connected to the Core from this window yet. Nothing changed.";
            actions.Children.Add(promote);
        }
        var remove = new Button { Content = $"Remove from {g.Name}…", Style = (Style)FindResource("GhostButton"), HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(14, 8, 14, 8) };
        remove.Click += (_, _) =>
        {
            // Board 1B law, computed from live data: the sole group
            // admin cannot be removed — refuse BEFORE any preview.
            if (isAdmin && g.Admins.Length <= 1) OpenLastAdminRefusal(scope, g, memberId);
            else OpenRemovePreview(scope, g, memberId);
        };
        actions.Children.Add(remove);
        _overlayBody.Children.Add(actions);
        _overlayBody.Children.Add(status);
        var row = ButtonRow();
        var close = OverlayGhost("Close");
        close.Click += (_, _) => CloseOverlay();
        row.Children.Add(close);
        _overlayBody.Children.Add(row);
        ShowOverlay("member");
    }

    /// <summary>What removing this member will touch, composed from
    /// live snapshot facts only (boards 1B/1D).</summary>
    private List<string> RemovalImpact(RosterScopeData scope, RosterUserGroupData g, string memberId)
    {
        var name = UserName(scope, memberId);
        var lines = new List<string>();
        var live = _host?.HumanSessions
            .Where(s => (string.Equals(s.InitiatorId, memberId, StringComparison.OrdinalIgnoreCase)
                      || s.Participants.Any(p => string.Equals(p.UserId, memberId, StringComparison.OrdinalIgnoreCase)))
                     && (s.State.Contains("live", StringComparison.OrdinalIgnoreCase) || s.State.Contains("active", StringComparison.OrdinalIgnoreCase)))
            .ToList() ?? new List<HumanSessionData>();
        lines.Add(live.Count > 0
            ? $"Stops {name}'s active session(s) — {live.Count} running now."
            : $"No live session of {name}'s is running right now.");
        var grants = scope.Grants.Where(gr => string.Equals(gr.UserGroupId, g.Id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (grants.Count == 0)
            lines.Add($"This group has no device grants, so no device access changes.");
        else
            foreach (var gr in grants)
            {
                var dg = scope.DeviceGroups.FirstOrDefault(d => string.Equals(d.Id, gr.DeviceGroupId, StringComparison.OrdinalIgnoreCase));
                lines.Add($"Removes access to {dg?.Name ?? gr.DeviceGroupId} devices that comes through {g.Name} (rights: {string.Join(", ", gr.Rights)}).");
            }
        lines.Add($"Removes {name} from {g.Name}. Their account and their other groups stay as they are.");
        lines.Add("Keeps all past session records and replays intact.");
        return lines;
    }

    private void OpenRemovePreview(RosterScopeData scope, RosterUserGroupData g, string memberId)
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Clear();
        var name = UserName(scope, memberId);
        _overlayBody.Children.Add(OverlayTitle($"Remove {name} from {g.Name}?"));
        _overlayBody.Children.Add(Body("Here is everything this removal will touch:", 14.5));
        var n = 1;
        foreach (var line in RemovalImpact(scope, g, memberId))
            _overlayBody.Children.Add(Body($"{n++}. {line}", 13.5));
        var status = Muted("");
        status.Margin = new Thickness(0, 10, 0, 0);
        _overlayBody.Children.Add(status);
        var row = ButtonRow();
        var fire = new Button { Content = $"Remove {name}", Style = (Style)FindResource("DangerButton"), Padding = new Thickness(16, 9, 16, 9), FontSize = 14 };
        fire.Click += (_, _) => status.Text = "Not removed — removing a member from just this group is not connected to the Core from this window yet. Nothing changed. Removing a person entirely, with its own preview, is on the Roster page.";
        row.Children.Add(fire);
        var cancel = OverlayGhost("Cancel");
        cancel.Click += (_, _) => CloseOverlay();
        row.Children.Add(cancel);
        _overlayBody.Children.Add(row);
        ShowOverlay("remove");
    }

    private void OpenLastAdminRefusal(RosterScopeData scope, RosterUserGroupData g, string memberId)
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Clear();
        var name = UserName(scope, memberId);
        _overlayBody.Children.Add(OverlayTitle("You can't remove the last Admin"));
        var others = g.Members.Where(m => !string.Equals(m, memberId, StringComparison.OrdinalIgnoreCase)).ToList();
        _overlayBody.Children.Add(Body(others.Count > 0
            ? $"{name} is the only Admin in {g.Name}. Every group needs at least one Admin so no one is locked out of managing it. Make {string.Join(" or ", others.Select(m => UserName(scope, m)))} an Admin first, then you can remove {name}."
            : $"{name} is the only Admin in {g.Name}, and the group's only member. Every group needs at least one Admin so no one is locked out of managing it.", 14));
        var box = new StackPanel();
        box.Children.Add(new TextBlock { Text = "What removing a member will touch", FontSize = 14.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
        foreach (var line in RemovalImpact(scope, g, memberId)) box.Children.Add(Muted("•  " + line, 12.5));
        var boxCard = Card(box);
        boxCard.Margin = new Thickness(0, 12, 0, 0);
        _overlayBody.Children.Add(boxCard);
        var status = Muted("");
        _overlayBody.Children.Add(status);
        var row = ButtonRow();
        if (others.Count > 0)
        {
            var choose = new Button { Content = "Choose another Admin", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(16, 8, 16, 8) };
            choose.Click += (_, _) => status.Text = "Not connected yet — appointing a Group Admin from this window is not wired to the Core, so no one was made an Admin and nothing changed.";
            row.Children.Add(choose);
        }
        var keep = OverlayGhost($"Keep {name} as Admin");
        keep.Click += (_, _) => CloseOverlay();
        row.Children.Add(keep);
        _overlayBody.Children.Add(row);
        ShowOverlay("refusal");
    }

    // ================= CREATE-GROUP WIZARD (board 1C) =================

    private void OpenWizard()
    {
        _wizStep = 1;
        _wizKind = _groupsTab;
        _wizScopeId = null;
        _wizName = "";
        _wizId = "";
        _wizMembers.Clear();
        _wizAdmins.Clear();
        RenderWizardStep();
        ShowOverlay("wizard");
    }

    private List<RosterScopeData> WizScopes() =>
        _host?.Roster.Where(s => s.Kind == _wizKind).ToList() ?? new List<RosterScopeData>();

    private void RenderWizardStep()
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Clear();
        _overlayBody.Children.Add(Muted($"Step {_wizStep} of 3", 12.5));
        // Progress segments (board 1C): filled up to the current step.
        var prog = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 12) };
        for (var i = 1; i <= 3; i++)
            prog.Children.Add(new Border
            {
                Width = 90, Height = 5, CornerRadius = new CornerRadius(2.5), Margin = new Thickness(0, 0, 8, 0),
                Background = i <= _wizStep ? Res("DgBlueBrush") : Res("DgSubtleBrush"),
            });
        _overlayBody.Children.Add(prog);
        if (_wizStep == 1) RenderWizardStep1();
        else if (_wizStep == 2) RenderWizardStep2();
        else RenderWizardStep3();
    }

    private Border KindCard(string kind, string title, string body)
    {
        var inner = new StackPanel();
        inner.Children.Add(new TextBlock { Text = title, FontSize = 16.5, FontWeight = FontWeights.SemiBold });
        inner.Children.Add(Muted(body, 12.5));
        var selected = _wizKind == kind;
        var b = new Button
        {
            Content = inner, HorizontalContentAlignment = HorizontalAlignment.Left, Width = 272,
            Background = selected ? new SolidColorBrush(Color.FromRgb(0xE9, 0xF3, 0xFA)) : Res("DgSurfaceBrush"),
            BorderBrush = selected ? Res("DgBlueBrush") : Res("DgBorderBrush"),
            BorderThickness = new Thickness(selected ? 2 : 1),
            Padding = new Thickness(14, 12, 14, 12), Margin = new Thickness(0, 0, 12, 0),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        var factory = new FrameworkElementFactory(typeof(Border));
        factory.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("Background") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        factory.SetBinding(Border.BorderBrushProperty, new System.Windows.Data.Binding("BorderBrush") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        factory.SetBinding(Border.BorderThicknessProperty, new System.Windows.Data.Binding("BorderThickness") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        factory.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
        factory.SetBinding(Border.PaddingProperty, new System.Windows.Data.Binding("Padding") { RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.TemplatedParent) });
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Left);
        factory.AppendChild(presenter);
        b.Template = new ControlTemplate(typeof(Button)) { VisualTree = factory };
        b.Click += (_, _) => { _wizKind = kind; _wizScopeId = null; RenderWizardStep(); };
        var wrap = new Border { Child = b };
        return wrap;
    }

    private void RenderWizardStep1()
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Add(OverlayTitle("Create a new group"));
        var cards = new StackPanel { Orientation = Orientation.Horizontal };
        cards.Children.Add(KindCard("personal", "Personal Group", "For family, friends, or your own devices. No workplace rules or admin overrides."));
        cards.Children.Add(KindCard("company", "Company Group", "For a team or workplace. Admins can set shared device rules and manage member access."));
        _overlayBody.Children.Add(cards);

        _overlayBody.Children.Add(Label("Group name"));
        _wizNameBox = new TextBox { FontSize = 14, Padding = new Thickness(8, 6, 8, 6), Text = _wizName };
        _wizNameBox.TextChanged += (_, _) =>
        {
            if (_wizIdBox is not null && (_wizIdBox.Tag as string) != "touched")
                _wizIdBox.Text = Slug(_wizNameBox.Text);
        };
        _overlayBody.Children.Add(_wizNameBox);
        _overlayBody.Children.Add(Label("Group id (how the Core names it)"));
        _wizIdBox = new TextBox { FontSize = 14, Padding = new Thickness(8, 6, 8, 6), Text = _wizId };
        if (_wizId.Length > 0) _wizIdBox.Tag = "touched";
        _wizIdBox.TextChanged += (_, _) => { if (_wizIdBox is not null) _wizIdBox.Tag = "touched"; };
        _overlayBody.Children.Add(_wizIdBox);

        var scopes = WizScopes();
        _overlayBody.Children.Add(Label(_wizKind == "personal" ? "Personal scope it belongs to" : "Company scope it belongs to"));
        var status = Muted("");
        if (scopes.Count == 0)
        {
            _overlayBody.Children.Add(Muted($"There is no {_wizKind} scope yet. A group lives inside a scope, and scopes are created on the Roster page — create one there first, then come back.", 12.5));
            _wizScopeBox = null;
        }
        else
        {
            _wizScopeBox = new ComboBox { FontSize = 14, Padding = new Thickness(6, 4, 6, 4) };
            foreach (var s in scopes) _wizScopeBox.Items.Add($"{s.Name}  ({s.Id})");
            _wizScopeBox.SelectedIndex = Math.Max(0, scopes.FindIndex(s => s.Id == _wizScopeId));
            if (_wizScopeBox.SelectedIndex < 0) _wizScopeBox.SelectedIndex = 0;
            _overlayBody.Children.Add(_wizScopeBox);
        }
        _overlayBody.Children.Add(status);

        var row = ButtonRow();
        var next = new Button { Content = "Next: Invite people", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(16, 8, 16, 8) };
        next.Click += (_, _) =>
        {
            var scopesNow = WizScopes();
            if (scopesNow.Count == 0 || _wizScopeBox is null || _wizScopeBox.SelectedIndex < 0)
            { status.Text = $"Pick a {_wizKind} scope first — there is none to pick until one is created on the Roster page."; return; }
            if (string.IsNullOrWhiteSpace(_wizNameBox?.Text) || string.IsNullOrWhiteSpace(_wizIdBox?.Text))
            { status.Text = "Give the group a name and an id first."; return; }
            _wizScopeId = scopesNow[_wizScopeBox.SelectedIndex].Id;
            _wizName = _wizNameBox?.Text.Trim() ?? "";
            _wizId = _wizIdBox?.Text.Trim() ?? "";
            _wizStep = 2;
            RenderWizardStep();
        };
        row.Children.Add(next);
        var cancel = OverlayGhost("Cancel");
        cancel.Click += (_, _) => CloseOverlay();
        row.Children.Add(cancel);
        _overlayBody.Children.Add(row);
    }

    private void RenderWizardStep2()
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Add(OverlayTitle("Invite people"));
        _overlayBody.Children.Add(Body("Invite people — pick who is in the group. Tick Admin to make someone a Group Admin (people only — an AI can be a member, never an Admin).", 13.5));
        var scope = WizScopes().FirstOrDefault(s => s.Id == _wizScopeId);
        _wizMembers.Clear();
        _wizAdmins.Clear();
        if (scope is null || scope.Users.Count == 0)
        {
            _overlayBody.Children.Add(Muted("This scope has no people in it yet — the group will be created empty, and members are set at creation until invites are connected."));
        }
        else
        {
            foreach (var u in scope.Users)
            {
                var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
                var member = new CheckBox { Content = $"{u.Name}{(u.Kind == "ai" ? "  ·  AI" : "")}", FontSize = 14, VerticalAlignment = VerticalAlignment.Center, Width = 300 };
                var admin = new CheckBox { Content = "Admin", FontSize = 14, VerticalAlignment = VerticalAlignment.Center, IsEnabled = u.Kind == "human" };
                admin.Checked += (_, _) => member.IsChecked = true;
                line.Children.Add(member);
                line.Children.Add(admin);
                _overlayBody.Children.Add(line);
                _wizMembers[u.Id] = member;
                _wizAdmins[u.Id] = admin;
            }
        }
        var row = ButtonRow();
        var next = new Button { Content = "Next: Review", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(16, 8, 16, 8) };
        next.Click += (_, _) => { _wizStep = 3; RenderWizardStep(); };
        row.Children.Add(next);
        var back = OverlayGhost("Back");
        back.Click += (_, _) => { _wizStep = 1; RenderWizardStep(); };
        row.Children.Add(back);
        var cancel = OverlayGhost("Cancel");
        cancel.Click += (_, _) => CloseOverlay();
        row.Children.Add(cancel);
        _overlayBody.Children.Add(row);
    }

    private void RenderWizardStep3()
    {
        if (_overlayBody is null) return;
        _overlayBody.Children.Add(OverlayTitle("Review the new group"));
        var scope = WizScopes().FirstOrDefault(s => s.Id == _wizScopeId);
        var members = _wizMembers.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToArray();
        var admins = _wizAdmins.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToArray();
        _overlayBody.Children.Add(Body($"{(_wizKind == "personal" ? "Personal Group" : "Company Group")} · in {scope?.Name ?? _wizScopeId}", 14.5));
        _overlayBody.Children.Add(Body($"Name: {_wizName}", 13.5));
        _overlayBody.Children.Add(Body($"Id: {_wizId}", 13.5));
        _overlayBody.Children.Add(Body(members.Length == 0
            ? "Members: none yet"
            : $"Members: {string.Join(", ", members.Select(id => scope is null ? id : UserName(scope, id)))}", 13.5));
        _overlayBody.Children.Add(Body(admins.Length == 0
            ? "Admins: none picked — the Core will refuse a group whose named Admin is an AI, and a group with no Admin can only be managed by a company admin."
            : $"Admins: {string.Join(", ", admins.Select(id => scope is null ? id : UserName(scope, id)))}", 13.5));
        var status = Muted("");
        status.Margin = new Thickness(0, 10, 0, 0);
        _overlayBody.Children.Add(status);
        var row = ButtonRow();
        var create = new Button { Content = "Create group", Style = (Style)FindResource("PrimaryButton"), Padding = new Thickness(16, 8, 16, 8) };
        create.Click += async (_, _) =>
        {
            if (scope is null) { status.Text = "The scope is gone — go back and pick it again."; return; }
            await SendHostActionAsync(IpcKinds.RosterAction,
                new
                {
                    action = "create_user_group",
                    id = _wizId, scopeId = scope.Id, name = _wizName,
                    members, admins,
                }, status);
            if (_groupsStatus is not null)
                _groupsStatus.Text = $"Create sent for group '{_wizName}' — it appears in the list when the Core's next snapshot lands. If the Core refuses it (duplicate id, unknown member, AI as Admin), the group simply never appears; the Roster page shows the Core's answer.";
        };
        row.Children.Add(create);
        var back = OverlayGhost("Back");
        back.Click += (_, _) => { _wizStep = 2; RenderWizardStep(); };
        row.Children.Add(back);
        var cancel = OverlayGhost("Cancel");
        cancel.Click += (_, _) => CloseOverlay();
        row.Children.Add(cancel);
        _overlayBody.Children.Add(row);
    }
}

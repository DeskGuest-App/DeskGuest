namespace Acp.Tests;

/// <summary>W100 — S19 Enterprise page de-densification pins.
/// The floor pattern: the default surface carries only the
/// plain-language posture summary (live, from the snapshot);
/// every tool section lives behind a labeled expansion; nothing
/// from the wall version is deleted. Source pins in the W76
/// tradition (the page is WPF code-behind with no headless
/// renderer in this tree).
/// </summary>
public class W100EnterpriseLayeringTests
{
    private static string Page() => File.ReadAllText(Path.Combine(AgentDir(), "MainWindow.Enterprise.cs"));

    [Fact]
    public void Summary_IsTheDefaultSurface_LiveLeadAndRows()
    {
        var page = Page();
        Assert.Contains("How this PC is protected — right now", page);
        Assert.Contains("Everything is on and checking out. Nothing here needs you right now.", page);
        Assert.Contains("Some protections need attention — they're marked below.", page);
        Assert.Contains("PostureRow(\"Policy\", e.PolicyState", page);
        Assert.Contains("PostureRow(\"Audit record\", e.ChainSummary", page);
    }

    [Fact]
    public void SnapshotUnavailable_LeadLine_IsNeutral_NeverTheAllGoodLine()
    {
        // W111 (S19 claim limit from W110): when the live
        // snapshot is unavailable (host Enterprise is null), the
        // summary must NOT render the all-good lead — that would
        // be fail-open security messaging. The code already
        // handles it: the null branch renders the neutral
        // waiting line and returns BEFORE the lead is chosen.
        var page = Page();
        var nullBranch = page[page.IndexOf("if (e is null)")..];
        nullBranch = nullBranch[..nullBranch.IndexOf("var needsAttention")];
        Assert.Contains("Waiting for the Core's snapshot", nullBranch);
        Assert.DoesNotContain("Everything is on and checking out", nullBranch);
        // The all-good line exists exactly once in the page, in
        // the needs-attention ternary that is only reached with
        // a real snapshot in hand.
        Assert.Equal(1, System.Text.RegularExpressions.Regex.Matches(page,
            "Everything is on and checking out").Count);
        Assert.Contains("? \"Some protections need attention", page);
    }

    [Fact]
    public void SnapshotPresentButUnpopulated_LeadLine_IsNeedsAttention_NeverAllGood()
    {
        // W113 (the W112 S19 residual): the W111 pin covers the
        // NULL snapshot. This pins the non-null-but-unpopulated
        // state DeepSeek named as an assumption: a snapshot whose
        // enterprise section is present but whose fields are
        // empty/default. It cannot read all-good BY CONSTRUCTION:
        // (1) EnterpriseData's defaults are PolicyLoaded=false
        // and ChainOk=false (no true initializer), and the
        // snapshot parser only sets them from explicit JSON true
        // values — absent fields stay false;
        // (2) RenderEnterprise's lead ternary requires
        // needsAttention == false, and needsAttention is
        // !PolicyLoaded || !ChainOk || alerts>0 || rotation —
        // so an unpopulated snapshot (both false) always takes
        // the needs-attention lead, never the all-good line.
        // The all-good line is reachable only when the Core's
        // snapshot explicitly reports a loaded policy AND an
        // intact chain AND zero alerts AND no rotation required.
        var roster = File.ReadAllText(Path.Combine(AgentDir(), "MainWindow.RosterSessions.cs"));
        var dataClass = roster[roster.IndexOf("private sealed class EnterpriseData")..];
        dataClass = dataClass[..dataClass.IndexOf("private sealed class BlockGData")];
        Assert.Contains("public bool PolicyLoaded;", dataClass);
        Assert.Contains("public bool ChainOk;", dataClass);
        Assert.DoesNotContain("PolicyLoaded = true", dataClass);
        Assert.DoesNotContain("ChainOk = true", dataClass);
        var page = Page();
        Assert.Contains("var needsAttention = !e.PolicyLoaded || !e.ChainOk || e.AlertCount > 0 || e.BreakGlassRotationRequired;", page);
    }

    [Fact]
    public void Fr110_PostureLines_StillRenderedFromTheSnapshot_ThroughStringsDoor()
    {
        var page = Page();
        Assert.Contains("Strings.Format(\"PosturePointerSigningFormat\", e.PointerSigningPostureAudit)", page);
        Assert.Contains("Strings.Format(\"PostureUpdateSigningFormat\", e.UpdateSigningPostureAudit)", page);
        Assert.Contains("Strings.Format(\"PostureAnchorMarkerFormat\", e.AnchorMarker)", page);
    }

    [Fact]
    public void AlwaysTrueBlock_IsWords_NotSwitches()
    {
        var page = Page();
        Assert.Contains("Always true — these can't be turned off", page);
        Assert.Contains("STOP always works", page);
        Assert.Contains("The audit record can't be edited.", page);
    }

    [Fact]
    public void EveryToolSection_IsOneLabeledExpansion_CollapsedByDefault()
    {
        var page = Page();
        foreach (var title in new[]
        {
            "Policy bundle", "Chained audit", "Directory sync", "Break-glass",
            "IdP sign-in", "Quick assist", "Local AI pack · manual WebRTC",
            "Tor provisioning", "About sign-in with your company IdP",
        })
            Assert.Contains($"ToolSection(\"{title}\"", page);
        Assert.Contains("IsExpanded = false", page);
        // The old wall dumped every section body unconditionally
        // via Section(...) headings — that helper call shape is gone.
        Assert.DoesNotContain("Section(policy,", page);
        Assert.DoesNotContain("Section(audit,", page);
        Assert.DoesNotContain("Section(glass,", page);
    }

    [Fact]
    public void NothingDeleted_EveryActionOfTheWallVersionSurvives()
    {
        var page = Page();
        foreach (var action in new[]
        {
            "policy_reload", "update_check", "audit_export", "audit_verify", "alerts",
            "sync_event", "break_glass_use", "break_glass_rotate", "idp_begin", "idp_complete",
        })
            Assert.Contains($"\"{action}\"", page);
        foreach (var label in new[]
        {
            "Reload policy bundle", "Check update against policy", "Verify chain", "Show alerts",
            "Apply event", "Use break-glass", "Rotate this holder's secret", "Begin (mock IdP)",
            "Complete sign-in", "Mint session code", "Close code / grant", "Pack status",
            "Show licence", "Accept licence", "WebRTC media status", "Download pack",
            "Download status", "Cancel download", "Verify installed pack",
            "Set up Tor", "Tor status", "Stop Tor",
        })
            Assert.Contains(label, page);
        // The deep prose survives inside the expansions, word for word.
        Assert.Contains("A bundle that fails verification loads NOTHING", page);
        Assert.Contains("a broken chain exports as BROKEN, never dressed up", page);
        Assert.Contains("loud by construction", page);
        Assert.Contains("refuses on any mismatch — no override", page);
    }

    [Fact]
    public void RealIdpBoundary_MovedBehindTheDetailExpansion_NotDeleted()
    {
        var page = Page();
        Assert.Contains("_enterpriseDetail.Children.Add(Muted(e.RealIdpBoundary))", page);
        Assert.Contains("About sign-in with your company IdP", page);
        // And it is no longer added to the default fact stack.
        Assert.DoesNotContain("_enterpriseFacts.Children.Add(Muted(e.RealIdpBoundary))", page);
    }

    [Fact]
    public void QuickAssistCode_OpensItsExpansion_WhenMinted()
    {
        var page = Page();
        Assert.Contains("_quickAssistExpander.IsExpanded = true", page);
        Assert.Contains("ToolSection(\"Quick assist\"", page);
    }

    [Fact]
    public void FleetRegister_StillRenderedFromTheSnapshot()
    {
        var page = Page();
        Assert.Contains("RenderFleetRegister(e)", page);
        Assert.Contains("FleetRegisterModel.ConsentFloorTitle()", page);
        Assert.Contains("FleetRegisterModel.OrderByException(rules)", page);
    }

    private static string AgentDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var rel in new[]
            {
                Path.Combine("src", "Acp.SessionAgent"),
                Path.Combine("windows-agent", "src", "Acp.SessionAgent"),
            })
            {
                var candidate = Path.Combine(dir.FullName, rel);
                if (Directory.Exists(candidate)) return candidate;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Acp.SessionAgent source dir not found above " + AppContext.BaseDirectory);
    }
}

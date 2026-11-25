using System.Text;
using Acp.Shared.Ipc;
using Acp.Shared.Policy;
using Acp.Shared.Presence;

namespace Acp.Tests;

/// <summary>
/// W119 — S12 Gate (Sensitive Action Approval), REVISION-DRAFT
/// §2.1 MINIMUM-LAW-CORRECTION. The gate's payload law: the sheet
/// shows the EXACT payload as it will be submitted, rendered per
/// gate class; the title names agent + action + exact target;
/// red #DC2626 only on «Deny and end session»; the credential
/// class is refused outright, stated on the gate; per-class
/// pre-approval exists only where SPEC §7.4 allows it; the sheet
/// sizes to its content (the W115 void is closed).
/// </summary>
public class W119GatePayloadTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    private static GatePayloadView Render(string cls, string tool, string json, string agent = "W119 Proof") =>
        GatePayloadRenderer.Render(agent, cls, tool, Encoding.UTF8.GetBytes(json));

    // ---------- class coverage: enumerated, never silent ----------

    [Fact]
    public void EveryPolicyGatedClass_HasANamedRendering()
    {
        foreach (var cls in PolicyEngine.GatedClasses)
        {
            Assert.Contains(cls, GatePayloadRenderer.KnownClasses);
            var view = Render(cls, "some_tool", "{}");
            Assert.False(view.IsGenericFallback, $"class '{cls}' fell back to the generic rendering");
        }
    }

    [Fact]
    public void EveryDescriptorDeclaredClass_HasANamedRendering()
    {
        // The descriptor-declared classes, enumerated from the
        // broker call sites (AdminModules, FileExtraModules,
        // SystemInfoModules, SafeMode, WindowsAdminModules,
        // EngineModules, OwnerConsole).
        foreach (var cls in new[] { "registry_write", "credential_inject", "takeover_handback" })
        {
            Assert.Contains(cls, GatePayloadRenderer.KnownClasses);
            var view = Render(cls, "some_tool", "{}");
            Assert.False(view.IsGenericFallback, $"class '{cls}' fell back to the generic rendering");
        }
    }

    [Fact]
    public void UnknownClass_RendersEveryField_AndIsFlaggedNotSilent()
    {
        var view = Render("brand_new_class", "new_tool", "{\"widget\":\"sprocket\",\"count\":3}");
        Assert.True(view.IsGenericFallback);
        Assert.Contains(view.TechnicalLines, l => l.Contains("widget: sprocket"));
        Assert.Contains(view.TechnicalLines, l => l.Contains("count: 3"));
    }

    // ---------- per-class payload renderings ----------

    [Fact]
    public void FolderOpen_FullPathInPlainAndTechnicalLines()
    {
        var view = Render("folder_open", "open_folder", "{\"path\":\"C:\\\\Users\\\\the owner\\\\Documents\"}");
        Assert.Contains(view.PlainLines, l => l.Contains("C:\\Users\\the owner\\Documents"));
        Assert.Contains(view.TechnicalLines, l => l.Contains("path: C:\\Users\\the owner\\Documents"));
        Assert.Contains("C:\\Users\\the owner\\Documents", view.Title);
    }

    [Fact]
    public void Deletions_NamesTheExactFiles()
    {
        var view = Render("deletions", "file_delete", "{\"path\":\"C:\\\\scratch\\\\a.txt\"}");
        Assert.Contains(view.PlainLines, l => l == "Delete C:\\scratch\\a.txt");
        var multi = Render("deletions", "file_delete", "{\"paths\":[\"C:\\\\a.txt\",\"C:\\\\b.txt\"]}");
        Assert.Contains(multi.PlainLines, l => l == "Delete C:\\a.txt");
        Assert.Contains(multi.PlainLines, l => l == "Delete C:\\b.txt");
    }

    [Fact]
    public void Sending_DraftBlockWithRecipientSubjectBodyAttachment_AndMarker()
    {
        var view = Render("sending", "send_message",
            "{\"to\":\"alex@example.com\",\"subject\":\"Status\",\"body\":\"All good.\",\"attachment\":{\"name\":\"report.pdf\",\"size\":2048,\"source\":\"C:\\\\docs\\\\report.pdf\"}}");
        Assert.True(view.ShowDraftMarker);
        Assert.Equal("DRAFT · NOT SENT", GateSheetModelDraftMarker());
        Assert.Contains(view.QuoteLines, l => l.Contains("alex@example.com"));
        Assert.Contains(view.QuoteLines, l => l.Contains("Subject: Status"));
        Assert.Contains(view.QuoteLines, l => l.Contains("Body: All good."));
        Assert.Contains(view.QuoteLines, l => l.Contains("report.pdf") && l.Contains("2048") && l.Contains("report.pdf"));
        Assert.Contains("alex@example.com", view.Title);
    }

    private static string GateSheetModelDraftMarker() => Acp.Shared.Design.GateSheetModel.DraftMarker();

    [Fact]
    public void NonSendingClasses_NeverCarryTheDraftMarker()
    {
        foreach (var cls in new[] { "deletions", "installs", "power", "payments", "registry_write" })
            Assert.False(Render(cls, "t", "{}").ShowDraftMarker, cls);
    }

    [Fact]
    public void Installs_NamesWhatFromWhereAndWhatChanges()
    {
        var view = Render("installs", "package_manage",
            "{\"action\":\"install\",\"package_id\":\"Git.Git\",\"source\":\"winget\"}");
        Assert.Contains(view.PlainLines, l => l.Contains("Git.Git"));
        Assert.Contains(view.PlainLines, l => l.Contains("winget"));
        Assert.Contains(view.PlainLines, l => l.Contains("change the software installed"));
        Assert.Contains("Git.Git", view.Title);
    }

    [Fact]
    public void Title_NamesAgentActionAndExactTarget()
    {
        var view = Render("deletions", "file_delete", "{\"path\":\"C:\\\\x.txt\"}", agent: "Axle");
        Assert.StartsWith("Axle", view.Title);
        Assert.Contains("C:\\x.txt", view.Title);
    }

    [Fact]
    public void ExactPayload_IsCarriedByteForByte()
    {
        var json = "{\"path\":\"C:\\\\x.txt\",\"mode\":\"overwrite\"}";
        var view = Render("deletions", "file_delete", json);
        Assert.Equal(json, view.ExactPayloadText);
    }

    // ---------- credential law ----------

    [Fact]
    public void CredentialClass_RefusedOutright_NoApprovalPath()
    {
        var view = Render("credential_inject", "credential_inject_service", "{\"service\":\"x\"}");
        Assert.True(view.IsRefusal);
        Assert.Contains("Refused outright", view.RefusalLine);
        Assert.False(view.PreApprovalEligible);
        Assert.False(GatePayloadRenderer.PreApprovalEligible("credential_inject"));
    }

    [Fact]
    public void CredentialFieldPayload_RefusedOutright_WhateverTheClass()
    {
        var view = Render("sending", "type_text", "{\"target_is_credential_field\":true,\"text\":\"hunter2\"}");
        Assert.True(view.IsRefusal);
    }

    [Fact]
    public void PreApproval_OnlyForTheSettingsClasses_NeverCredential()
    {
        foreach (var cls in PolicyEngine.GatedClasses)
            Assert.True(GatePayloadRenderer.PreApprovalEligible(cls), cls);
        Assert.False(GatePayloadRenderer.PreApprovalEligible("registry_write"));
        Assert.False(GatePayloadRenderer.PreApprovalEligible("takeover_handback"));
    }

    // ---------- sheet law (source pins) ----------

    [Fact]
    public void Sheet_RedOnlyOnDenyAndEnd_AndItIsTheTokenRed()
    {
        Assert.Equal(unchecked((int)0xFFDC2626), PresenceComposition.GateCardColors.DenyAndEndBackground);
        var gate = SrcFile("Acp.SessionAgent", "GateSheet.cs");
        // The deny-and-end pair is bound to exactly the third exit.
        Assert.Contains("PresenceComposition.GateCardColors.DenyAndEndBackground", gate);
        Assert.Contains("PresenceComposition.GateCardColors.DenyAndEndForeground", gate);
        // No other literal red anywhere in the sheet.
        Assert.DoesNotContain("DC, 0x26, 0x26", gate);
        Assert.DoesNotContain("0xDC, 0x26", gate);
        // Deny keeps its own dark pair — red did not spread.
        Assert.NotEqual(PresenceComposition.GateCardColors.DenyBackground,
            PresenceComposition.GateCardColors.DenyAndEndBackground);
        // White on the token red meets WCAG AA (large semibold text).
        var ratio = PresenceComposition.ContrastRatio(
            PresenceComposition.GateCardColors.DenyAndEndBackground,
            PresenceComposition.GateCardColors.DenyAndEndForeground);
        Assert.True(ratio >= 4.5, $"deny-and-end contrast {ratio:F2} < 4.5");
    }

    [Fact]
    public void Sheet_SizesToContent_NoVoid()
    {
        var gate = SrcFile("Acp.SessionAgent", "GateSheet.cs");
        Assert.Contains("SizeToContent = SizeToContent.Height;", gate);
    }

    [Fact]
    public void Sheet_NoDefaultButton_EscSwallowed()
    {
        var gate = SrcFile("Acp.SessionAgent", "GateSheet.cs");
        Assert.DoesNotContain("IsDefault", gate);
        Assert.Contains("if (e.Key == Key.Escape) { e.Handled = true; return; }", gate);
    }

    [Fact]
    public void Sheet_RefusalState_HasNoExits_OnlyAClose()
    {
        var gate = SrcFile("Acp.SessionAgent", "GateSheet.cs");
        Assert.Contains("if (view.IsRefusal)", gate);
        Assert.Contains("Content = \"Close\"", gate);
        // The refusal branch adds no exit: exits are added only in
        // the non-refusal branch (Exit( calls come after the else).
        var refusalAt = gate.IndexOf("if (view.IsRefusal)", StringComparison.Ordinal);
        var firstExitAt = gate.IndexOf("Exit(exits[0].Label", StringComparison.Ordinal);
        Assert.True(firstExitAt > refusalAt);
    }

    [Fact]
    public void Sheet_DraftMarker_ShownOnlyWhenTheViewSaysSo()
    {
        var gate = SrcFile("Acp.SessionAgent", "GateSheet.cs");
        Assert.Contains("if (view.ShowDraftMarker)", gate);
    }

    [Fact]
    public void App_BuildsTheGateViewFromTheWireRequest()
    {
        var app = SrcFile("Acp.SessionAgent", "App.xaml.cs");
        Assert.Contains("GatePayloadRenderer.Render(", app);
        Assert.Contains("request.GateClass, request.Tool", app);
    }

    [Fact]
    public void ThreeExits_ByteIdenticalLabels_EqualWeight()
    {
        var exits = Acp.Shared.Design.GateSheetModel.Exits();
        Assert.Equal(3, exits.Count);
        Assert.Equal("Approve", exits[0].Label);
        Assert.Equal("Deny", exits[1].Label);
        Assert.Equal("Deny and end session", exits[2].Label);
        Assert.All(exits, e => Assert.Equal(600, e.Weight));
        Assert.False(Acp.Shared.Design.GateSheetModel.HasSessionAllow());
    }
}

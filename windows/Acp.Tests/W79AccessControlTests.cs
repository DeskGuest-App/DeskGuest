using Acp.Shared.Ipc;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>W79 / S08 — the AI access-control surface pins.
/// The integrity rule: slider and Fine-tune are two views of ONE
/// grant state (a pairing's scope set). Pins cover: stop sets are
/// the product's real presets/scopes (no second model), Classify
/// exactness + the Custom flip, preview (Diff) accuracy, the
/// elevation class default-refused at the store, the one-write
/// path (PairingService.UpdateScopes) changing real enforcement
/// state (Authenticate + capability truth), the IPC consent kind,
/// and the surface's source shape (stepped slider, preview before
/// apply, UAC line, Settings + Home doors).</summary>
public class W79AccessControlTests
{
    private static HashSet<string> Set(params string[] s) => new(s);

    private static PairingService NewService(out string token, params string[] scopes)
    {
        var svc = new PairingService(new PlainProtector());
        var code = svc.CreatePairingCode("w79-agent", TimeSpan.FromMinutes(5), Set(scopes));
        var ex = svc.ExchangeCode(code, "w79-agent")!;
        token = ex.BearerToken;
        return svc;
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public string Name => "plain-test";
        public bool IsRealProtection => false;
        public string Protect(string plain) => plain;
        public string Unprotect(string protectedValue) => protectedValue;
    }

    // ---- stops reuse the real grant model ----------------------

    [Fact]
    public void Stops_AreFive_NamedPerSignedS08Row()
    {
        Assert.Equal(5, AccessControl.Stops.Count);
        Assert.Equal(
            new[] { "No access", "Watch only", "Suggest first", "Ask before acting", "Full help" },
            AccessControl.Stops.Select(s => s.Name).ToArray());
    }

    [Fact]
    public void Stops_MapToRealPresetsAndScopes_NoSecondModel()
    {
        Assert.Empty(AccessControl.Stops[0].Grants);
        Assert.Equal(Scopes.Preset("look_only"), AccessControl.Stops[1].Grants);
        Assert.Equal(Set(Scopes.Observe, Scopes.Drive), AccessControl.Stops[2].Grants);
        Assert.Equal(Set(Scopes.Observe, Scopes.Drive, Scopes.Shell), AccessControl.Stops[3].Grants);
        Assert.Equal(Scopes.Preset("full_control"), AccessControl.Stops[4].Grants);
        // every stop grant is a real scope; stop sets are distinct
        foreach (var stop in AccessControl.Stops)
            Assert.All(stop.Grants, g => Assert.Contains(g, Scopes.All));
        Assert.Equal(5, AccessControl.Stops.Select(s => string.Join(",", s.Grants.OrderBy(x => x))).Distinct().Count());
    }

    [Fact]
    public void ExplicitOnlyClasses_AreInNoStop_OnlyInFineTune()
    {
        foreach (var scope in new[] { Scopes.Terminal, Scopes.BackgroundTools, Scopes.Backstage, Scopes.KitAdmin, Scopes.Unlock })
        {
            Assert.All(AccessControl.Stops, s => Assert.DoesNotContain(scope, s.Grants));
            Assert.Contains(AccessControl.Capabilities, c => c.Scope == scope);
        }
        // every grantable scope appears exactly once in Fine-tune
        Assert.Equal(
            AccessControl.Capabilities.Select(c => c.Scope).OrderBy(s => s),
            AccessControl.Capabilities.Select(c => c.Scope).OrderBy(s => s).Distinct());
    }

    // ---- Classify: one state, exact stops, Custom flip ---------

    [Fact]
    public void Classify_EveryStopSet_IsItsStop()
    {
        for (var i = 0; i < AccessControl.Stops.Count; i++)
            Assert.Equal(i, AccessControl.Classify(AccessControl.Stops[i].Grants));
    }

    [Fact]
    public void Classify_FineTuneEdits_FlipToCustom()
    {
        // adding an explicit-only class to a stop state
        Assert.Equal(-1, AccessControl.Classify(Set(Scopes.Observe, Scopes.Terminal)));
        // adding elevation beyond the ladder top's own set is a stop;
        // adding it to a mid stop is Custom
        Assert.Equal(-1, AccessControl.Classify(Set(Scopes.Observe, Scopes.Admin)));
        // a non-cumulative ladder subset is Custom, never rounded
        Assert.Equal(-1, AccessControl.Classify(Set(Scopes.Drive)));
        Assert.Equal(-1, AccessControl.Classify(Set(Scopes.Observe, Scopes.Shell)));
        // full_control (carries admin) IS the top stop, exactly
        Assert.Equal(4, AccessControl.Classify(Scopes.Preset("full_control")));
        Assert.True(AccessControl.IsCustom(Set(Scopes.Observe, Scopes.Unlock)));
        Assert.False(AccessControl.IsCustom(Set()));
    }

    // ---- Preview accuracy --------------------------------------

    [Fact]
    public void Diff_NamesExactlyTheGrantsThatChange()
    {
        var diff = AccessControl.Diff(Set(Scopes.Observe), Set(Scopes.Observe, Scopes.Drive, Scopes.Shell));
        Assert.Equal(2, diff.Count);
        Assert.All(diff, c => Assert.True(c.Added));
        Assert.Equal(new[] { Scopes.Drive, Scopes.Shell }, diff.Select(c => c.Capability.Scope).ToArray());

        var down = AccessControl.Diff(Scopes.Preset("full_control"), Set(Scopes.Observe));
        Assert.Equal(3, down.Count);
        Assert.All(down, c => Assert.False(c.Added));
        Assert.Contains(down, c => c.Capability.Scope == Scopes.Admin && c.Capability.IsElevation);

        Assert.Empty(AccessControl.Diff(Set(Scopes.Observe), Set(Scopes.Observe)));
    }

    [Fact]
    public void Diff_UnknownHeldGrant_IsNamedAsRemoval_NeverDroppedSilently()
    {
        var diff = AccessControl.Diff(Set(Scopes.Observe, "mystery_scope"), Set(Scopes.Observe));
        var line = Assert.Single(diff);
        Assert.False(line.Added);
        Assert.Contains("mystery_scope", line.Capability.Label);
    }

    // ---- Elevation: default refused ----------------------------

    [Fact]
    public void Elevation_AddRequiresSeparateConfirmation()
    {
        // W107 AMENDMENT (reason recorded): W79 pinned the
        // confirmation as keyed to ADMIN ALONE — unlock and
        // background_kit_admin applied with no confirmation, at
        // the store. W106 verified that gap (C2) and the
        // coordinator ruled the requirement extends to the full
        // elevation class {admin, unlock, background_kit_admin}.
        // The pins below assert the extended class; the admin-only
        // assertions they replace were the defect, not the design.
        Assert.True(AccessControl.AddsElevation(Set(Scopes.Observe), Set(Scopes.Observe, Scopes.Admin)));
        Assert.False(AccessControl.AddsElevation(Set(Scopes.Observe, Scopes.Admin), Set(Scopes.Observe)));
        Assert.NotNull(AccessControl.ValidateProposal(Set(Scopes.Observe), Set(Scopes.Observe, Scopes.Admin), elevationConfirmed: false));
        Assert.Null(AccessControl.ValidateProposal(Set(Scopes.Observe), Set(Scopes.Observe, Scopes.Admin), elevationConfirmed: true));
        // W107: unlock and background_kit_admin are elevation-class
        Assert.True(AccessControl.AddsElevation(Set(Scopes.Observe, Scopes.Drive), Set(Scopes.Observe, Scopes.Drive, Scopes.Unlock)));
        Assert.True(AccessControl.AddsElevation(Set(Scopes.Observe, Scopes.Drive), Set(Scopes.Observe, Scopes.Drive, Scopes.KitAdmin)));
        Assert.NotNull(AccessControl.ValidateProposal(Set(Scopes.Observe, Scopes.Drive),
            Set(Scopes.Observe, Scopes.Drive, Scopes.Unlock, Scopes.KitAdmin), elevationConfirmed: false));
        Assert.Null(AccessControl.ValidateProposal(Set(Scopes.Observe, Scopes.Drive),
            Set(Scopes.Observe, Scopes.Drive, Scopes.Unlock, Scopes.KitAdmin), elevationConfirmed: true));
        // already holding one elevation scope does not smuggle in another
        Assert.True(AccessControl.AddsElevation(Set(Scopes.Admin), Set(Scopes.Admin, Scopes.Unlock)));
        // holding all of the class: no ADD, no confirmation needed
        Assert.False(AccessControl.AddsElevation(
            Set(Scopes.Admin, Scopes.Unlock, Scopes.KitAdmin), Set(Scopes.Admin, Scopes.Unlock, Scopes.KitAdmin)));
        // the refusal names the added elevation scopes
        var refusal = AccessControl.ValidateProposal(Set(Scopes.Observe),
            Set(Scopes.Observe, Scopes.Unlock), elevationConfirmed: false);
        Assert.Contains(Scopes.Unlock, refusal);
        Assert.Contains("elevation", refusal);
        // removing elevation never needs confirmation
        Assert.Null(AccessControl.ValidateProposal(Set(Scopes.Observe, Scopes.Admin), Set(Scopes.Observe), elevationConfirmed: false));
        Assert.Null(AccessControl.ValidateProposal(Set(Scopes.Observe, Scopes.Unlock, Scopes.KitAdmin), Set(Scopes.Observe), elevationConfirmed: false));
        // unknown grants refuse outright
        Assert.NotNull(AccessControl.ValidateProposal(Set(), Set("nope"), elevationConfirmed: true));
    }

    [Fact]
    public void UacLine_AndElevationLabel_AreTheSignedVerbatim()
    {
        Assert.Equal(
            "DeskGuest will never press Yes on a Windows permission popup for anyone — that Yes must come from a person at the computer.",
            AccessControl.UacLine);
        // W107 AMENDMENT (reason recorded): this pin asserted
        // admin was the SINGLE elevation capability — the C2 gap
        // stated as design. The elevation class is now the three
        // privilege-boundary scopes; admin's signed label stands.
        var elevation = AccessControl.Capabilities.Where(c => c.IsElevation).Select(c => c.Scope).ToHashSet();
        Assert.Equal(new HashSet<string> { Scopes.Admin, Scopes.Unlock, Scopes.KitAdmin }, elevation);
        Assert.Equal(AccessControl.ElevationScopes, elevation);
        var admin = Assert.Single(AccessControl.Capabilities, c => c.Scope == Scopes.Admin);
        Assert.Equal("Do admin jobs for me (installs, system changes) — off unless you turn it on", admin.Label);
    }

    // ---- The one write path changes REAL enforcement state -----

    [Fact]
    public void UpdateScopes_ChangesWhatAuthenticateEnforces()
    {
        var svc = NewService(out var token, Scopes.Observe);
        var id = svc.List()[0].Id;
        Assert.Equal(Set(Scopes.Observe), svc.Authenticate(token)!.Scopes);

        var (ok, _, old) = svc.UpdateScopes(id, Set(Scopes.Observe, Scopes.Drive), elevationConfirmed: false);
        Assert.True(ok);
        Assert.Equal(Set(Scopes.Observe), old);
        // the SAME bearer now enforces the new set — no re-pairing
        Assert.Equal(Set(Scopes.Observe, Scopes.Drive), svc.Authenticate(token)!.Scopes);

        // and the export/import round-trip (the persisted store) carries it
        var svc2 = new PairingService(new PlainProtector());
        svc2.ImportJson(svc.ExportJson());
        Assert.Equal(Set(Scopes.Observe, Scopes.Drive), svc2.List()[0].Scopes);
    }

    [Fact]
    public void UpdateScopes_ElevationDefaultRefused_AtTheStore()
    {
        var svc = NewService(out var token, Scopes.Observe);
        var id = svc.List()[0].Id;
        var (ok, detail, _) = svc.UpdateScopes(id, Set(Scopes.Observe, Scopes.Admin), elevationConfirmed: false);
        Assert.False(ok);
        Assert.Contains("elevation", detail);
        Assert.Equal(Set(Scopes.Observe), svc.Authenticate(token)!.Scopes); // unchanged

        var (ok2, _, _) = svc.UpdateScopes(id, Set(Scopes.Observe, Scopes.Admin), elevationConfirmed: true);
        Assert.True(ok2);
        Assert.Contains(Scopes.Admin, svc.Authenticate(token)!.Scopes);
    }

    [Fact]
    public void UpdateScopes_ElevationClassDefaultRefused_AtTheStore_UnlockAndKitAdmin()
    {
        // W107 (C2): the exact verified sequence — current
        // {observe, drive} → proposed {observe, drive, unlock,
        // background_kit_admin} with NO elevation confirmation
        // must refuse AT THE STORE (not merely in the editor),
        // leave the grant set untouched, and name elevation as
        // the reason — exactly as adding admin does. The Core
        // dispatch audits this refusal through the same
        // pairing_access_refused_via_agent entry as admin's.
        var svc = NewService(out var token, Scopes.Observe, Scopes.Drive);
        var id = svc.List()[0].Id;
        var proposed = Set(Scopes.Observe, Scopes.Drive, Scopes.Unlock, Scopes.KitAdmin);
        var (ok, detail, _) = svc.UpdateScopes(id, proposed, elevationConfirmed: false);
        Assert.False(ok);
        Assert.Contains("elevation", detail);
        Assert.Contains(Scopes.Unlock, detail);
        Assert.Contains(Scopes.KitAdmin, detail);
        Assert.Equal(Set(Scopes.Observe, Scopes.Drive), svc.Authenticate(token)!.Scopes); // unchanged

        // each one alone is refused too
        Assert.False(svc.UpdateScopes(id, Set(Scopes.Observe, Scopes.Drive, Scopes.Unlock), false).Ok);
        Assert.False(svc.UpdateScopes(id, Set(Scopes.Observe, Scopes.Drive, Scopes.KitAdmin), false).Ok);

        // with the owner's separate confirmation, the same
        // proposal applies — the gate is a confirmation, not a ban
        var (ok2, _, _) = svc.UpdateScopes(id, proposed, elevationConfirmed: true);
        Assert.True(ok2);
        Assert.Equal(proposed, svc.Authenticate(token)!.Scopes);

        // and the Diff the editor previews marks both additions
        // as elevation-class (the preview's switch is driven by
        // the same AddsElevation predicate — one model).
        var diff = AccessControl.Diff(Set(Scopes.Observe, Scopes.Drive), proposed);
        Assert.All(diff.Where(c => c.Added), c => Assert.True(c.Capability.IsElevation));
    }

    [Fact]
    public void UpdateScopes_RefusesUnknownPairing_Revoked_AndUnknownGrants()
    {
        var svc = NewService(out _, Scopes.Observe);
        var id = svc.List()[0].Id;
        Assert.False(svc.UpdateScopes("no-such-id", Set(Scopes.Observe), false).Ok);
        Assert.False(svc.UpdateScopes(id, Set("mystery"), false).Ok);
        svc.Revoke(id);
        Assert.False(svc.UpdateScopes(id, Set(Scopes.Observe), false).Ok);
    }

    [Fact]
    public void UpdateScopes_SliderApplyResult_ClassifiesBackToTheSameStop()
    {
        // the two-views-one-state round trip: for every stop,
        // applying its set then classifying returns that stop —
        // the slider can never land somewhere it doesn't point.
        var svc = NewService(out _, Scopes.Observe);
        var id = svc.List()[0].Id;
        for (var i = 0; i < AccessControl.Stops.Count; i++)
        {
            var needsElevation = AccessControl.AddsElevation(svc.List()[0].Scopes, AccessControl.Stops[i].Grants);
            var (ok, detail, _) = svc.UpdateScopes(id, AccessControl.Stops[i].Grants, needsElevation);
            Assert.True(ok, $"stop {i}: {detail}");
            Assert.Equal(i, AccessControl.Classify(svc.List()[0].Scopes));
        }
    }

    // ---- IPC discipline ----------------------------------------

    [Fact]
    public void PairingAccess_IsAConsentKind_LaptopUiOnly()
    {
        Assert.True(IpcConsent.IsConsentKind(IpcKinds.PairingAccess));
    }

    // ---- Surface source shape ----------------------------------

    private static string SrcDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AcpWindows.slnx")))
            dir = dir.Parent;
        return dir!.FullName;
    }

    private static string ReadSrc(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { SrcDir() }.Concat(parts).ToArray()));

    [Fact]
    public void Surface_SliderIsStepped_PreviewBeforeApply_UacLinePresent()
    {
        var page = ReadSrc("Acp.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("AccessControl.Stops", page);
        Assert.Contains("AccessControl.Diff", page);            // preview from the model
        Assert.Contains("IpcKinds.PairingAccess", page);       // the one write path
        Assert.Contains("AccessControl.UacLine", page);         // the refusal copy is on the surface
        Assert.Contains("AddsElevation", page);                 // elevation switch in the preview
        Assert.DoesNotContain("Slider", page.Replace("BuildAccessSlider", "").Replace("stepped slider", "").Replace("STEPPED slider", ""));
    }

    [Fact]
    public void Surface_LivesOnAgentCard_AndInSettings()
    {
        var main = ReadSrc("Acp.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("OpenAgentAccess", main);              // Home agent card door
        Assert.Contains("\"agentdetail\" => BuildAgentDetailPage()", main);
        var pages = ReadSrc("Acp.SessionAgent", "MainWindow.Pages.cs");
        Assert.Contains("ShowPage(\"agentdetail\")", pages);   // Settings index door
    }

    [Fact]
    public void Core_ApplyPairingAccess_AuditsEveryChange()
    {
        var core = ReadSrc("Acp.Core", "CoreRuntime.cs");
        Assert.Contains("pairing_access_via_agent", core);
        Assert.Contains("pairing_access_refused_via_agent", core);
        Assert.Contains("Pairings.UpdateScopes", core);
    }
}

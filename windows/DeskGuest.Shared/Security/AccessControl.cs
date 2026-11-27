namespace DeskGuest.Shared.Security;

/// <summary>
/// W79 / S08 — the AI access-control model: ONE grant state, two
/// views (the stepped slider and the Fine-tune panel), per the
/// signed S08 revision and the BUILD-PROGRAMME integrity rule.
///
/// The grant state is exactly a pairing's scope set
/// (<see cref="Pairing.Scopes"/>) — this type invents no second
/// model. The slider ladder runs over the SESSION scopes
/// (observe → drive → shell, cumulative); its top stop is the
/// product's own full_control preset verbatim. The elevation
/// class is part of that preset, but ADDING any of it — from
/// the slider or from Fine-tune — always requires the owner's
/// separate elevation confirmation in the preview (see
/// ValidateProposal): it is never granted by sliding alone.
/// Every explicit-only class (terminal, background_tools,
/// backstage, background_kit_admin, unlock — in no preset,
/// scoped in by name in the real model) lives ONLY in Fine-tune:
/// any state holding one — or holding a non-cumulative ladder
/// set — classifies as Custom. That is the integrity rule made
/// structural: touching Fine-tune flips the slider to "Custom"
/// because the state genuinely no longer equals any stop.
///
/// Elevation rule (W107, extending W79 per the W106 C2 ruling):
/// the elevation class is { admin, unlock, background_kit_admin }
/// — the grants that cross a privilege boundary on the machine
/// (do admin jobs / unlock the computer / admit shared tool
/// kits). W79 keyed the confirmation to admin alone; W106
/// verified unlock and background_kit_admin applied at the store
/// with NO confirmation, and the coordinator ruled the
/// confirmation requirement extends to the full class. ADDING
/// any elevation-class scope requires the owner's separate
/// elevation confirmation (the preview's own switch); it is
/// default-refused for AI pairings, at the STORE boundary, not
/// only in the editor. Removing one never requires confirmation.
/// DeskGuest never clicks through a live UAC prompt — the
/// standing line below is part of the surface.
/// </summary>
public static class AccessControl
{
    /// <summary>The standing UAC refusal line (S08, verbatim).</summary>
    public const string UacLine =
        "DeskGuest will never press Yes on a Windows permission popup for anyone — that Yes must come from a person at the computer.";

    /// <summary>The elevation class's Fine-tune label (S08, verbatim).</summary>
    public const string ElevationLabel =
        "Do admin jobs for me (installs, system changes) — off unless you turn it on";

    /// <summary>One slider stop: its signed name, its exact grant
    /// set, and the plain consequence shown live while dragging.</summary>
    public sealed record Stop(string Name, IReadOnlySet<string> Grants, string Consequence);

    /// <summary>The five signed stops (REVISION-DRAFT S08), each
    /// mapped to the product's real scopes. Stop 1 is the
    /// look_only preset verbatim. Stop 3's name is structurally
    /// true: the consequential gate classes (installs, deletions,
    /// power, shutdown…) are denied without approval in every
    /// approval mode (PolicyEngine), whatever the scopes say.</summary>
    public static readonly IReadOnlyList<Stop> Stops = new[]
    {
        new Stop("No access", new HashSet<string>(),
            "This helper can't see or do anything on this computer."),
        new Stop("Watch only", Scopes.Preset("look_only"),
            "Can see the screen and send messages. Can't click, type, or run anything."),
        new Stop("Suggest first", new HashSet<string> { Scopes.Observe, Scopes.Drive },
            "Can see the screen, and move the pointer and type to show you what it means. It can't run commands."),
        new Stop("Ask before acting", new HashSet<string> { Scopes.Observe, Scopes.Drive, Scopes.Shell },
            "Can also run commands. The big actions — installs, deletions, shutting down — still ask you first, every time."),
        new Stop("Full help", Scopes.Preset("full_control"),
            "Can see, drive, run commands, and do admin jobs. That includes the admin jobs switch below — it only turns on when you confirm it in the preview."),
    };

    /// <summary>One Fine-tune capability row: a real scope, its
    /// plain-verb label, and whether it is the elevation class.</summary>
    public sealed record Capability(string Scope, string Label, bool IsElevation);

    /// <summary>Every grantable capability, simple → advanced,
    /// the elevation class last and separated (the UI renders the
    /// separation; the order here is the panel's order).</summary>
    public static readonly IReadOnlyList<Capability> Capabilities = new[]
    {
        new Capability(Scopes.Observe, "See the screen, and send and read messages", false),
        new Capability(Scopes.Drive, "Move the pointer, click, and type", false),
        new Capability(Scopes.Shell, "Run commands", false),
        new Capability(Scopes.Terminal, "Use the terminal channel", false),
        new Capability(Scopes.BackgroundTools, "Work in the background between sessions", false),
        new Capability(Scopes.Backstage, "Use a hidden desktop (Backstage)", false),
        new Capability(Scopes.KitAdmin, "Admit shared tool kits", true),
        new Capability(Scopes.Unlock, "Unlock this computer", true),
        new Capability(Scopes.Admin, ElevationLabel, true),
    };

    /// <summary>W107: the full elevation class — every scope whose
    /// ADDITION requires the owner's separate elevation
    /// confirmation at the store. One named set, read by
    /// AddsElevation, ValidateProposal, and the editor's preview
    /// (which presents an addition of any of these behind the same
    /// elevation switch).</summary>
    public static readonly IReadOnlySet<string> ElevationScopes =
        new HashSet<string> { Scopes.Admin, Scopes.Unlock, Scopes.KitAdmin };

    /// <summary>The scopes the slider ladder can ever contain.</summary>
    public static readonly IReadOnlySet<string> LadderScopes =
        new HashSet<string> { Scopes.Observe, Scopes.Drive, Scopes.Shell };

    /// <summary>Classify a grant state: the stop index whose set
    /// it equals exactly, or -1 for Custom. Any state holding a
    /// non-ladder scope, or a non-cumulative ladder subset, is
    /// Custom — never silently rounded to a stop.</summary>
    public static int Classify(IReadOnlySet<string> grants)
    {
        for (var i = 0; i < Stops.Count; i++)
            if (Stops[i].Grants.SetEquals(grants)) return i;
        return -1;
    }

    public static bool IsCustom(IReadOnlySet<string> grants) => Classify(grants) < 0;

    /// <summary>One grant that would change: the capability, and
    /// whether it is being added (true) or removed (false).</summary>
    public sealed record GrantChange(Capability Capability, bool Added);

    /// <summary>The exact change preview: every grant that differs
    /// between the current state and a proposed state, in panel
    /// order. This is what the surface shows BEFORE applying —
    /// the applied set must equal the previewed set (pinned).</summary>
    public static IReadOnlyList<GrantChange> Diff(
        IReadOnlySet<string> current, IReadOnlySet<string> proposed)
    {
        var changes = new List<GrantChange>();
        foreach (var cap in Capabilities)
        {
            var has = current.Contains(cap.Scope);
            var want = proposed.Contains(cap.Scope);
            if (has != want) changes.Add(new GrantChange(cap, want));
        }
        // Unknown scope strings (not a named capability) can only
        // ever be REMOVED by this surface (a stop set or a panel
        // state never proposes one); name them honestly in the
        // preview rather than dropping them silently.
        foreach (var s in current.Where(s => Capabilities.All(c => c.Scope != s)).OrderBy(s => s))
            if (!proposed.Contains(s))
                changes.Add(new GrantChange(new Capability(s, $"Remove the '{s}' grant", false), false));
        return changes;
    }

    /// <summary>True when moving from current to proposed ADDS
    /// any elevation-class scope (admin, unlock, or
    /// background_kit_admin — W107) the current set does not
    /// already hold — the move that requires the owner's separate
    /// elevation confirmation.</summary>
    public static bool AddsElevation(IReadOnlySet<string> current, IReadOnlySet<string> proposed) =>
        ElevationScopes.Any(s => !current.Contains(s) && proposed.Contains(s));

    /// <summary>The elevation-class scopes a move would ADD, in
    /// panel order — named in the store's refusal so the audit
    /// says exactly which privileged grant was refused.</summary>
    public static IReadOnlyList<string> AddedElevationScopes(
        IReadOnlySet<string> current, IReadOnlySet<string> proposed) =>
        Capabilities.Where(c => ElevationScopes.Contains(c.Scope))
            .Select(c => c.Scope)
            .Where(s => !current.Contains(s) && proposed.Contains(s))
            .ToList();

    /// <summary>Validate a proposed grant set for the pairing
    /// surface: only named capabilities may be proposed, and
    /// adding any elevation-class scope requires the owner's
    /// separate confirmation (default refused). Returns null when
    /// valid, else the refusal reason. Used by PairingService so
    /// the rule holds at the store, not only in the window.</summary>
    public static string? ValidateProposal(
        IReadOnlySet<string> current, IReadOnlySet<string> proposed, bool elevationConfirmed)
    {
        foreach (var s in proposed)
            if (Capabilities.All(c => c.Scope != s))
                return $"unknown grant '{s}' — refused";
        if (AddsElevation(current, proposed) && !elevationConfirmed)
            return $"adding elevation-class grants ({string.Join(", ", AddedElevationScopes(current, proposed))}) " +
                "needs the owner's separate confirmation in the preview — refused (elevation is off unless the owner turns it on)";
        return null;
    }
}

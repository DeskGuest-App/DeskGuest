using Acp.Shared.Distribution;
using Acp.Shared.Jobs;

namespace Acp.Shared.Patching;

// =====================================================================
// RMM-02 — Endpoint application: applier shapes + run construction.
//
// An IPatchApplier knows how ONE OS installs a patch: it builds
// the install/verify command plans (executable + argv, never a
// shell string — argv arrays are the OP-01 config-injection
// discipline applied to patching). Execution itself is host
// wiring: the commands run as RMM-03 signed envelopes of class
// patch_deploy through the existing SignedCommandGate, on the
// endpoint, by the host's process machinery. This layer constructs
// and validates; it invokes NOTHING. Live patching proof (a real
// Windows Update / DISM / winget run) is PENDING — no test in this
// lane patches anything, and the build VM / the owner's laptop are
// never patched by this code.
//
// Run steps (PatchRunSteps) carry HONEST idempotency marks:
//   fetch_payload  — Idempotent (content-addressed; re-fetch is a
//                    no-op or a verified repeat);
//   verify_payload — Idempotent (a pure hash check);
//   apply_patch    — NonIdempotent (an installer interrupted
//                    mid-apply leaves genuinely unknown state; the
//                    RMM-15 journal PARKS the run for a human
//                    rather than guessing);
//   verify_install — Idempotent (re-reads installed state);
//   reboot_gate    — Idempotent (a pure policy evaluation; the
//                    reboot itself rides the power machinery).
// =====================================================================

/// <summary>One command plan: an executable and its argv. Built by
/// appliers from catalogue data; the payload path is a local path
/// the fetch step produced, never catalogue-controlled text beyond
/// the KB id / package identifier slots the builders validate.</summary>
public sealed record PatchCommandPlan(string OsKind, string Executable, IReadOnlyList<string> Arguments, string Purpose);

public sealed record PatchApplyRequest(PatchCatalogueEntry Entry, string PayloadPath, string DeviceId);
public sealed record PatchApplyResult(bool Ok, string Detail, PatchCommandPlan? InstallPlan, PatchCommandPlan? VerifyPlan);

/// <summary>The per-OS applier contract. Implementations in this
/// file are command-construction SHAPES; tests drive fakes through
/// the same interface.</summary>
public interface IPatchApplier
{
    string OsKind { get; }
    bool CanApply(PatchCatalogueEntry entry);
    PatchApplyResult BuildApply(PatchApplyRequest request);
}

/// <summary>Shared argv hygiene: a catalogue-controlled token that
/// contains whitespace, quotes, or shell metacharacters never
/// reaches a command plan — the entry is refused at build time.
/// (KB ids and package identifiers are slugs by construction in
/// every real catalogue; anything else is poisoning.)</summary>
internal static class PatchArgv
{
    private static readonly char[] Forbidden = { ' ', '\t', '"', '\'', ';', '&', '|', '<', '>', '`', '$', '\n', '\r' };
    public static bool IsCleanToken(string? token) =>
        !string.IsNullOrWhiteSpace(token) && token.Length <= 128 && !token.Any(c => Forbidden.Contains(c));
    public static string Refusal(string what, string? token) =>
        $"{what} '{token}' is not a clean command token — refused (catalogue content never reaches a command line unvalidated)";
}

/// <summary>Windows shape — the deepest of the three, per the
/// register. OS patches: KB .msu via wusa, .cab via DISM.
/// Third-party (BD-SHARED-RMM-2/F1): the install plan NEVER fetches
/// "whatever the source serves at the latest version". A staged
/// payload that is itself a runnable installer (.msi/.exe/.msix) is
/// installed FROM THE VERIFIED LOCAL PAYLOAD — the bytes the
/// PatchPayloadGate pin-checked. Any other payload shape installs
/// through winget at the PINNED --version FixedInVersion, and the
/// verify plan lists versions so the host compares the installed
/// version against FixedInVersion instead of mere presence.</summary>
public sealed class WindowsPatchApplier : IPatchApplier
{
    public string OsKind => PatchOsKinds.Windows;
    public bool CanApply(PatchCatalogueEntry entry) => entry.TargetOs == PatchOsKinds.Windows;

    public PatchApplyResult BuildApply(PatchApplyRequest request)
    {
        var e = request.Entry;
        if (!CanApply(e)) return new PatchApplyResult(false, $"entry '{e.Id}' does not target Windows", null, null);
        if (e.Kind == PatchKinds.ThirdParty)
        {
            if (!PatchArgv.IsCleanToken(e.Id)) return new PatchApplyResult(false, PatchArgv.Refusal("package identifier", e.Id), null, null);
            if (string.IsNullOrWhiteSpace(e.FixedInVersion) || !PatchArgv.IsCleanToken(e.FixedInVersion))
                return new PatchApplyResult(false, PatchArgv.Refusal("fixed-in version", e.FixedInVersion), null, null);
            var verify = new PatchCommandPlan(OsKind, "winget",
                new[] { "list", "--id", e.Id, "--exact", "--versions" }, $"verify {e.Id} installed version equals {e.FixedInVersion} (host compares the listed version; presence alone is not verification)");
            var payloadLower = (request.PayloadPath ?? "").ToLowerInvariant();
            if (payloadLower.EndsWith(".msi"))
            {
                var msi = new PatchCommandPlan(OsKind, "msiexec.exe",
                    new[] { "/i", request.PayloadPath, "/quiet", "/norestart" },
                    $"install {e.Id} {e.FixedInVersion} from the pinned local payload (msi)");
                return new PatchApplyResult(true, "local-payload install plan built — the verified payload bytes are what installs (execution is host wiring via the signed-command gate)", msi, verify);
            }
            if (payloadLower.EndsWith(".exe") || payloadLower.EndsWith(".msix") || payloadLower.EndsWith(".appx"))
            {
                var exe = new PatchCommandPlan(OsKind, request.PayloadPath!,
                    new[] { "/quiet", "/norestart" },
                    $"install {e.Id} {e.FixedInVersion} from the pinned local payload (installer)");
                return new PatchApplyResult(true, "local-payload install plan built — the verified payload bytes are what installs (execution is host wiring via the signed-command gate)", exe, verify);
            }
            var install = new PatchCommandPlan(OsKind, "winget",
                new[] { "install", "--id", e.Id, "--exact", "--version", e.FixedInVersion, "--silent", "--accept-package-agreements", "--accept-source-agreements" },
                $"winget install of {e.Id} PINNED to version {e.FixedInVersion} (never latest)");
            return new PatchApplyResult(true, "winget command plan built, version-pinned to FixedInVersion (execution is host wiring via the signed-command gate)", install, verify);
        }
        if (!PatchArgv.IsCleanToken(e.KbId)) return new PatchApplyResult(false, PatchArgv.Refusal("KB id", e.KbId), null, null);
        var lower = request.PayloadPath.ToLowerInvariant();
        if (lower.EndsWith(".cab"))
        {
            var install = new PatchCommandPlan(OsKind, "dism.exe",
                new[] { "/Online", "/Add-Package", $"/PackagePath:{request.PayloadPath}", "/NoRestart" },
                $"DISM add-package for {e.KbId}");
            return new PatchApplyResult(true, "DISM command plan built (execution is host wiring via the signed-command gate)",
                install, new PatchCommandPlan(OsKind, "dism.exe", new[] { "/Online", "/Get-PackageInfo", $"/PackagePath:{request.PayloadPath}" }, $"verify {e.KbId} package state"));
        }
        var wusa = new PatchCommandPlan(OsKind, "wusa.exe",
            new[] { request.PayloadPath, "/quiet", "/norestart" }, $"standalone installer for {e.KbId}");
        return new PatchApplyResult(true, "wusa command plan built (execution is host wiring via the signed-command gate)",
            wusa, new PatchCommandPlan(OsKind, "powershell.exe",
                new[] { "-NoProfile", "-Command", $"Get-HotFix -Id {e.KbId}" }, $"verify hotfix {e.KbId} present"));
    }
}

/// <summary>macOS shape: OS patches via softwareupdate by label;
/// third-party .pkg via installer. Label tokens are validated the
/// same way (softwareupdate labels carry spaces in the wild — the
/// label is therefore passed as ONE argv element built from the KB
/// slot only when it is a clean token; otherwise the plan refuses
/// rather than interpolating).</summary>
public sealed class MacOsPatchApplier : IPatchApplier
{
    public string OsKind => PatchOsKinds.MacOs;
    public bool CanApply(PatchCatalogueEntry entry) => entry.TargetOs == PatchOsKinds.MacOs;

    public PatchApplyResult BuildApply(PatchApplyRequest request)
    {
        var e = request.Entry;
        if (!CanApply(e)) return new PatchApplyResult(false, $"entry '{e.Id}' does not target macOS", null, null);
        if (e.Kind == PatchKinds.ThirdParty)
        {
            var install = new PatchCommandPlan(OsKind, "/usr/sbin/installer",
                new[] { "-pkg", request.PayloadPath, "-target", "/" }, $"installer pkg for {e.Id}");
            return new PatchApplyResult(true, "installer command plan built (execution is host wiring via the signed-command gate)",
                install, new PatchCommandPlan(OsKind, "/usr/sbin/pkgutil", new[] { "--pkgs" }, $"verify {e.Id} receipt"));
        }
        if (!PatchArgv.IsCleanToken(e.KbId)) return new PatchApplyResult(false, PatchArgv.Refusal("update label", e.KbId), null, null);
        var su = new PatchCommandPlan(OsKind, "/usr/sbin/softwareupdate",
            new[] { "--install", e.KbId!, "--restart" }, $"softwareupdate install {e.KbId}");
        return new PatchApplyResult(true, "softwareupdate command plan built (execution is host wiring via the signed-command gate)",
            su, new PatchCommandPlan(OsKind, "/usr/sbin/softwareupdate", new[] { "--list" }, "verify update no longer offered"));
    }
}

/// <summary>Linux shape: distro package tooling by package name —
/// apt (Debian family) is the constructed default; the plan names
/// the tool so host wiring can refuse a mismatch rather than run
/// apt on a dnf host.</summary>
public sealed class LinuxPatchApplier : IPatchApplier
{
    public string OsKind => PatchOsKinds.Linux;
    public bool CanApply(PatchCatalogueEntry entry) => entry.TargetOs == PatchOsKinds.Linux;

    public PatchApplyResult BuildApply(PatchApplyRequest request)
    {
        var e = request.Entry;
        if (!CanApply(e)) return new PatchApplyResult(false, $"entry '{e.Id}' does not target Linux", null, null);
        // The package token is the entry ID (a slug — for imported
        // entries, the package identifier), never the display
        // product name: display names carry spaces and would fail
        // the token check (or worse, reach a command line).
        var package = e.Kind == PatchKinds.ThirdParty ? e.Id : e.KbId;
        if (!PatchArgv.IsCleanToken(package)) return new PatchApplyResult(false, PatchArgv.Refusal("package name", package), null, null);
        // BD-SHARED-RMM-2/F1: a staged .deb payload installs FROM THE
        // VERIFIED LOCAL FILE (apt resolves its dependencies); the
        // repository form below is only for OS-channel packages and
        // payload-less entries, and stays version-pinned either way.
        if (e.Kind == PatchKinds.ThirdParty && (request.PayloadPath ?? "").ToLowerInvariant().EndsWith(".deb"))
        {
            var local = new PatchCommandPlan(OsKind, "apt-get",
                new[] { "install", "-y", request.PayloadPath }, $"apt install {package} from the pinned local payload .deb");
            var verifyDeb = new PatchCommandPlan(OsKind, "dpkg-query",
                new[] { "-W", "-f=${Version}", package! }, $"verify {package} version equals {e.FixedInVersion} (host compares)");
            return new PatchApplyResult(true, "local-payload install plan built — the verified payload bytes are what installs (execution is host wiring via the signed-command gate)", local, verifyDeb);
        }
        var install = new PatchCommandPlan(OsKind, "apt-get",
            new[] { "install", "-y", $"{package}={e.FixedInVersion}" }, $"apt install {package} at {e.FixedInVersion}");
        var verify = new PatchCommandPlan(OsKind, "dpkg-query",
            new[] { "-W", "-f=${Version}", package! }, $"verify {package} version");
        return new PatchApplyResult(true, "apt command plan built (execution is host wiring via the signed-command gate)", install, verify);
    }
}

public static class PatchAppliers
{
    public static IPatchApplier ForOs(string? osKind) => (osKind ?? "").Trim().ToLowerInvariant() switch
    {
        PatchOsKinds.Windows => new WindowsPatchApplier(),
        PatchOsKinds.MacOs => new MacOsPatchApplier(),
        PatchOsKinds.Linux => new LinuxPatchApplier(),
        _ => throw new ArgumentException($"no patch applier shape for OS '{osKind}'", nameof(osKind)),
    };
}

/// <summary>The PatchRun job's step list, with the honest
/// idempotency marks documented in the file header.</summary>
public static class PatchRunSteps
{
    public const string Fetch = "fetch_payload";
    public const string VerifyPayload = "verify_payload";
    public const string Apply = "apply_patch";
    public const string VerifyInstall = "verify_install";
    public const string RebootGateStep = "reboot_gate";

    public static IReadOnlyList<JobStepDefinition> For(PatchCatalogueEntry entry) => new[]
    {
        new JobStepDefinition(Fetch, $"Fetch payload for {entry.Id}", StepIdempotency.Idempotent),
        new JobStepDefinition(VerifyPayload, $"Verify payload hash for {entry.Id}", StepIdempotency.Idempotent),
        new JobStepDefinition(Apply, $"Apply {entry.Id}", StepIdempotency.NonIdempotent),
        new JobStepDefinition(VerifyInstall, $"Verify {entry.Id} installed", StepIdempotency.Idempotent),
        new JobStepDefinition(RebootGateStep, $"Reboot gate for {entry.Id}", StepIdempotency.Idempotent),
    };
}

/// <summary>The pre-distribution payload gate, shared by the
/// planner and the service: when an entry pins a payload hash, the
/// RMM-14 manifest for the payload MUST name that exact hash (and
/// the bytes must verify against the manifest) — a mismatch
/// refuses BEFORE any distribution or job creation. When an entry
/// pins no hash (OS-channel patches only, by admission rules), no
/// ACP payload may ride along: a manifest presented for such an
/// entry refuses too (an unpinned payload is exactly the poisoning
/// shape the pin exists to stop).</summary>
public static class PatchPayloadGate
{
    public static (bool Ok, string Reason) Check(PatchCatalogueEntry entry, ContentManifest? manifest, byte[]? payloadBytes)
    {
        if (entry.PayloadHash is null)
        {
            if (manifest is not null || payloadBytes is not null)
                return (false, $"entry '{entry.Id}' pins no payload hash (OS-channel patch) but a payload was presented — refused (unpinned payloads never distribute)");
            return (true, "OS-channel patch: no ACP payload, nothing to pin-check");
        }
        if (manifest is null)
            return (false, $"entry '{entry.Id}' pins payload hash {entry.PayloadHash[..12]}… but no content manifest was presented — refused before distribution");
        if (!string.Equals(manifest.ContentHash, entry.PayloadHash, StringComparison.OrdinalIgnoreCase))
            return (false, $"payload hash mismatch for entry '{entry.Id}': manifest names {manifest.ContentHash[..12]}…, the catalogue entry pins {entry.PayloadHash[..12]}… — refused BEFORE distribution (the payload is not the payload the admin curated)");
        if (payloadBytes is not null && !manifest.VerifyWhole(payloadBytes))
            return (false, $"payload bytes do not verify against the manifest for entry '{entry.Id}' — refused before distribution");
        return (true, "payload hash matches the catalogue pin and the manifest");
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.Install;

/// <summary>R1 SERVICE-FORM INSTALLER (BUILD-PROGRAMME V1 scope item 3;
/// BUILD-LOG #155): the install-time Terms gate + first-run role step,
/// modelled once here so the PowerShell installer, the bench harness
/// and the test suite all drive the SAME logic.
///
/// TERMS POSITION FOR v0.0.1 (reconciliation recorded in BUILD-LOG
/// #155): programme item (15) puts the full Terms on installer page
/// one — complete text on the page, unticked-by-default acceptance,
/// declining exits clean with NOTHING written, acceptance recorded
/// locally (timestamp + Terms version + SHA-256 of the exact text).
/// The later ASTRA TERMS REVIEW consequence (2026-11-25) HOLDS the
/// binding force of the v1.0 text: v0.0.1 does not ship BINDING terms
/// until the Terms v1.1 fix pass (issue #145) lands and is re-agreed.
/// The two reconcile without a third position: the v0.0.1 installer
/// PRESENTS the full text and RECORDS the acceptance as a local
/// receipt in exactly the item (15)(a) shape — which is also the flow
/// Astra item (7) requires be verified against the release candidate —
/// and neither the installer nor the receipt claims the v1.0 text is
/// binding. The receipt carries <see cref="AcceptanceReceipt.Binding"/>
/// = false so the shipped artefact states that plainly.</summary>
public static class InstallGate
{
    /// <summary>The receipt file the installer drops into the data
    /// dir on acceptance (and only on acceptance).</summary>
    public const string ReceiptFileName = "terms-acceptance.json";

    /// <summary>The role file the first-run role step drops into the
    /// data dir.</summary>
    public const string RoleFileName = "device-role.json";

    /// <summary>SHA-256 of the exact Terms text, computed exactly the
    /// way DeskGuest.Core's TermsBundle computes the served bundle's
    /// hash (UTF-8 bytes of the text as read, BOM stripped by the
    /// reader) — so the installer's page, the Core's deskguest://terms
    /// resource and the pairing acknowledgment can never disagree
    /// about which text was accepted.</summary>
    public static string ComputeTermsSha256(string termsText) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(termsText))).ToLowerInvariant();

    /// <summary>The Terms version declared inside the text itself
    /// ("**Version:** 1.0 · ..."). Refuses (throws) when the text
    /// carries no version line — a Terms file without a version is
    /// not presentable at the gate.</summary>
    public static string ParseTermsVersion(string termsText)
    {
        foreach (var rawLine in termsText.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("**Version:**", StringComparison.Ordinal))
            {
                var rest = line["**Version:**".Length..].Trim();
                var token = rest.Split(' ', '·', '\t')[0].Trim();
                if (token.Length > 0) return token;
            }
        }
        throw new InvalidOperationException(
            "the Terms text carries no '**Version:**' line — refusing to present unversioned Terms at the install gate");
    }
}

/// <summary>The local acceptance receipt (programme item (15)(a)):
/// timestamp, Terms version, hash of the exact text accepted, the
/// app version being installed, and who accepted. Written by the
/// installer into the data dir as part of the install — AFTER the
/// acceptance act, never before, and never on decline.</summary>
public sealed record AcceptanceReceipt(
    DateTimeOffset AcceptedUtc,
    string TermsVersion,
    string TermsSha256,
    string AppVersion,
    string AcceptedBy,
    bool Binding)
{
    public static AcceptanceReceipt Create(string termsText, string appVersion, string acceptedBy, DateTimeOffset utcNow) =>
        new(utcNow, InstallGate.ParseTermsVersion(termsText), InstallGate.ComputeTermsSha256(termsText),
            appVersion, acceptedBy, Binding: false);

    public string ToJson() => JsonSerializer.Serialize(this, InstallJson.Options);

    public static AcceptanceReceipt FromJson(string json) =>
        JsonSerializer.Deserialize<AcceptanceReceipt>(json, InstallJson.Options)
        ?? throw new InvalidOperationException("terms-acceptance.json did not deserialize");
}

/// <summary>The first-run role step's answer (SPEC §"ROLE ESTABLISHED
/// AT INSTALL"; FEATURES "Role established at install"): "What will
/// this device do?" — operator / attended endpoint / unattended
/// endpoint, COMBINABLE, at least one. Configuration follows the
/// role: unattended installs the Core service; an attended-only
/// install carries NO unattended pathway (no service at all).</summary>
[Flags]
public enum DeviceRoles
{
    None = 0,
    Operator = 1,
    AttendedEndpoint = 2,
    UnattendedEndpoint = 4,
}

public sealed record DeviceRoleSelection(DeviceRoles Roles, DateTimeOffset ChosenUtc)
{
    /// <summary>The Core service is installed iff the unattended
    /// role was chosen. Attended-only ⇒ no service, by design.</summary>
    public bool RequiresService => Roles.HasFlag(DeviceRoles.UnattendedEndpoint);

    public void Validate()
    {
        if (Roles == DeviceRoles.None)
            throw new InvalidOperationException(
                "the role step requires at least one role — \"What will this device do?\" cannot be answered with nothing");
    }

    public string ToJson() => JsonSerializer.Serialize(this, InstallJson.Options);

    public static DeviceRoleSelection FromJson(string json) =>
        JsonSerializer.Deserialize<DeviceRoleSelection>(json, InstallJson.Options)
        ?? throw new InvalidOperationException("device-role.json did not deserialize");
}

/// <summary>One run of the installer's Terms gate against one data
/// directory. The gate is deliberately write-free until the moment
/// of acceptance: <see cref="Decline"/> performs NO file system
/// writes at all (the decline-writes-nothing proof is a directory
/// diff around this call), and <see cref="Accept"/> writes exactly
/// the receipt. The unticked-by-default rule is structural: a fresh
/// session starts unaccepted, and <see cref="Accept"/> refuses to
/// run until <see cref="TickAcceptanceCheckbox"/> has been called —
/// there is no path where acceptance is the default.</summary>
public sealed class TermsGateSession
{
    private readonly string _dataDir;
    private readonly string _termsText;
    private readonly string _appVersion;
    private readonly string _acceptedBy;
    private readonly Func<DateTimeOffset> _utcNow;

    public TermsGateSession(string dataDir, string termsText, string appVersion, string acceptedBy,
        Func<DateTimeOffset>? utcNow = null)
    {
        _dataDir = dataDir;
        _termsText = termsText;
        _appVersion = appVersion;
        _acceptedBy = acceptedBy;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        // Fail loud at presentation time, not at accept time.
        TermsVersion = InstallGate.ParseTermsVersion(termsText);
        TermsSha256 = InstallGate.ComputeTermsSha256(termsText);
    }

    public string TermsVersion { get; }
    public string TermsSha256 { get; }
    public string TermsText => _termsText;

    /// <summary>Unticked by default — always false on a fresh
    /// session; only the installer's explicit checkbox act sets it.</summary>
    public bool AcceptanceCheckboxTicked { get; private set; }

    public void TickAcceptanceCheckbox() => AcceptanceCheckboxTicked = true;
    public void UntickAcceptanceCheckbox() => AcceptanceCheckboxTicked = false;

    /// <summary>Decline (or close the page): exits clean having
    /// written NOTHING. This method performs no I/O by construction.</summary>
    public GateOutcome Decline() => GateOutcome.DeclinedNothingWritten;

    /// <summary>Accept: requires the checkbox ticked; writes exactly
    /// one file — the acceptance receipt — into the data dir.</summary>
    public GateOutcome Accept()
    {
        if (!AcceptanceCheckboxTicked)
            throw new InvalidOperationException(
                "acceptance requires the explicit unticked-by-default checkbox act — the gate cannot accept on the installer's behalf");
        Directory.CreateDirectory(_dataDir);
        var receipt = AcceptanceReceipt.Create(_termsText, _appVersion, _acceptedBy, _utcNow());
        File.WriteAllText(Path.Combine(_dataDir, InstallGate.ReceiptFileName), receipt.ToJson());
        return GateOutcome.AcceptedReceiptWritten;
    }

    /// <summary>Record the role step's answer (one file).</summary>
    public void RecordRole(DeviceRoleSelection selection)
    {
        selection.Validate();
        Directory.CreateDirectory(_dataDir);
        File.WriteAllText(Path.Combine(_dataDir, InstallGate.RoleFileName), selection.ToJson());
    }
}

public enum GateOutcome
{
    DeclinedNothingWritten,
    AcceptedReceiptWritten,
}

internal static class InstallJson
{
    public static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
}

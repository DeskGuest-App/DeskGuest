using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Enrollment;

/// <summary>The device presenting itself at redeem time. It carries
/// NO scope or group: those are bound to the code at mint time, on the
/// enrolling side, and the redeeming side cannot choose or widen them.</summary>
public sealed record EnrollingDevice(string DeviceId, string PublicKeyBase64, string DisplayName);

/// <summary>One enrolled device in the roster. TransportMode /
/// AllowedTransports (D31): transport mode is decided at enrollment,
/// so both are bound to the code at mint time like scope and group.
/// TransportMode is "inherit" | "auto" | "manual" (default
/// "inherit"); AllowedTransports is this device's within-group-set
/// narrowing/pin per D32 — a narrowing of the group's own ordered
/// transport set (that group record is Slice 2, not Slice 1), NOT a
/// free-standing transport list (empty = no narrowing / inherit the
/// group set as-is). This slice is data model only — precedence
/// resolution is a later slice.</summary>
public sealed record EnrolledDevice(
    string DeviceId,
    string DisplayName,
    string PublicKeyBase64,
    string Scope,
    string GroupId,
    string GroupName,
    DateTimeOffset EnrolledUtc,
    bool Revoked,
    string TransportMode = "inherit",
    IReadOnlySet<string>? AllowedTransports = null,
    string Sas = "",
    bool SasConfirmed = false,
    // bd-shared-plat-2/F11: a reported SAS mismatch QUARANTINES
    // the device — signature verification refuses until the
    // endpoint-local human re-confirms the SAS (ConfirmSas) or
    // the owner revokes/re-pairs. The enrollment itself is NOT
    // torn down (the settled SAS rule), but high-trust signature
    // paths stop trusting the key.
    bool SasQuarantined = false,
    // W14 P3-F2 (W13-P3-F2 spec, Android mirror): the user id that
    // OWNS this device — mint/redeem-carried, persisted as a
    // trailing field. "" = unbound (legacy records load unbound,
    // parse-tolerant when absent). When non-empty, the host
    // session binding refuses a SESSION whose initiator is not
    // this owner for the handshake-proven peer device
    // (see SessionOwnerRefusal).
    string OwnerUserId = "")
{
    /// <summary>The device's within-set narrowing/pin (D32): the
    /// subset of the group's ordered transport set this device is
    /// pinned to; never null in records this service produces
    /// (empty set = no narrowing — inherit the group set as-is).</summary>
    public IReadOnlySet<string> AllowedTransports { get; init; } =
        AllowedTransports ?? new HashSet<string>();

    /// <summary>U9 SAS state, honestly reported: "sas_confirmed"
    /// only after the endpoint-local human confirm
    /// (<see cref="EnrollmentService.ConfirmSas"/>); otherwise
    /// "sas_unconfirmed" — including when no SAS could be computed
    /// (Sas empty: the enroller's local key was not wired).</summary>
    public string SasState => SasConfirmed ? PairingSas.StateConfirmed : PairingSas.StateUnconfirmed;
}

/// <summary>Endpoint-side record of who enrolled THIS device (kept by
/// the device that was enrolled, about its enroller).</summary>
public sealed record EnrollmentReceipt(
    string EnrollerName,
    string EnrollerDeviceId,
    string Scope,
    string GroupName,
    DateTimeOffset EnrolledUtc,
    string Sas = "",
    bool SasConfirmed = false)
{
    /// <summary>U9 SAS state for the enrollee side (see EnrolledDevice.SasState).</summary>
    public string SasState => SasConfirmed ? PairingSas.StateConfirmed : PairingSas.StateUnconfirmed;

    /// <summary>True when this receipt carries a computed SAS.
    /// False is the honest legacy state: the enroller sent no public
    /// key in its enrollment response, so the enrollee could not
    /// compute one (U9 follow-up) — absent, never faked.</summary>
    public bool HasSas => !string.IsNullOrWhiteSpace(Sas);
}

/// <summary>
/// U9 follow-up — the enrollment RESPONSE: the post-redeem payload
/// the ENROLLER returns to the enrollee. It carries the enroller's
/// 32-byte public key (base64) so the enrollee can compute the
/// identical SAS at redeem, enrollee-side.
///
/// The key is a REVEAL, not a trust root: the enrollee already holds
/// the enroller's DeviceId — the SHA-256 fingerprint of this key —
/// from the code/QR transcript, and MUST verify the transmitted key
/// against that committed fingerprint before any use
/// (<see cref="EnrollmentService.RecordReceiptFromResponse"/>). A
/// key that does not fingerprint to the committed DeviceId is
/// refused and audited; it never produces a SAS.
///
/// LEGACY: an old enroller sends no key
/// (<see cref="EnrollerPublicKeyBase64"/> null). The enrollee then
/// keeps the honest pre-follow-up state — receipt with an empty SAS,
/// audited as <see cref="PairingSas.AuditAbsentNoEnrollerKey"/> —
/// visibly absent, never faked.
/// </summary>
public sealed record EnrollmentResponse(
    string EnrollerDeviceId,
    string EnrollerName,
    string? EnrollerPublicKeyBase64,
    string EnrolledDeviceId,
    string Scope,
    string GroupId,
    string GroupName,
    DateTimeOffset EnrolledUtc);

/// <summary>Outcome of an enrollee ingesting an
/// <see cref="EnrollmentResponse"/> (U9 follow-up).</summary>
public enum EnrollmentResponseOutcome
{
    /// <summary>Key verified against the committed fingerprint; SAS
    /// computed enrollee-side and stored on the receipt, unconfirmed.</summary>
    Applied,
    /// <summary>Legacy enroller sent no key: receipt stored with an
    /// empty SAS, audited as absent — the honest no-SAS state.</summary>
    LegacyNoKey,
    /// <summary>The transmitted key does not fingerprint to the
    /// committed enroller DeviceId (or no commitment was held):
    /// refused, audited, NO receipt and NO SAS produced.</summary>
    RefusedKeyMismatch,
    /// <summary>The response or its key was malformed (bad base64,
    /// wrong length, small-order key, bad transcript/scope, or no
    /// enroller identity at all): refused, audited where an enroller
    /// id was available, NO receipt produced.</summary>
    RefusedMalformed,
}

/// <summary>Result of
/// <see cref="EnrollmentService.RecordReceiptFromResponse"/>.</summary>
public sealed record EnrollmentResponseResult(
    EnrollmentResponseOutcome Outcome,
    EnrollmentReceipt? Receipt,
    string Detail);

/// <summary>U9: one SAS audit-trail entry — the record of whether
/// the human compare happened. Action is "sas_unconfirmed" (at
/// redeem), "sas_confirmed" (endpoint-local confirm), or
/// "sas_mismatch_reported" (endpoint-local mismatch report).</summary>
public sealed record SasAuditEntry(string DeviceId, string Action, DateTimeOffset Utc);

/// <summary>Parsed QR enrollment payload.</summary>
public sealed record EnrollPayloadInfo(string Code, string Scope, string GroupId);

/// <summary>
/// QR enrollment payload: "deskguest://enroll/1?c=&lt;CODE&gt;&amp;s=&lt;scope&gt;&amp;g=&lt;groupId&gt;".
/// It carries the same one-time code and nothing else secret — the
/// code is the only credential, and it is single-use and short-lived.
/// The parser never throws on hostile input: wrong scheme, wrong
/// version, or a missing/invalid code all return null/false.
/// </summary>
public static class EnrollPayload
{
    public const string Scheme = "deskguest";
    public const string Host = "enroll";
    public const string Version = "1";

    public static string Build(string code, string scope, string groupId)
    {
        var normalized = EnrollmentService.NormalizeCode(code)
            ?? throw new ArgumentException("Invalid enrollment code.", nameof(code));
        return $"{Scheme}://{Host}/{Version}?c={normalized}" +
               $"&s={Uri.EscapeDataString(scope ?? "")}&g={Uri.EscapeDataString(groupId ?? "")}";
    }

    public static EnrollPayloadInfo? Parse(string? payload) =>
        TryParse(payload, out var info) ? info : null;

    public static bool TryParse(string? payload, out EnrollPayloadInfo? info)
    {
        info = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;
        try
        {
            if (!Uri.TryCreate(payload.Trim(), UriKind.Absolute, out var uri)) return false;
            if (!string.Equals(uri.Scheme, Scheme, StringComparison.OrdinalIgnoreCase)) return false;
            if (!string.Equals(uri.Host, Host, StringComparison.OrdinalIgnoreCase)) return false;
            if (uri.AbsolutePath != "/" + Version) return false;

            string? code = null, scope = "", groupId = "";
            var query = uri.Query.StartsWith("?") ? uri.Query.Substring(1) : uri.Query;
            foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                if (eq < 0) continue;
                var key = Uri.UnescapeDataString(pair.Substring(0, eq));
                var value = Uri.UnescapeDataString(pair.Substring(eq + 1));
                if (key == "c") code = value;
                else if (key == "s") scope = value;
                else if (key == "g") groupId = value;
            }
            var normalized = EnrollmentService.NormalizeCode(code);
            if (normalized is null) return false;
            info = new EnrollPayloadInfo(normalized, scope ?? "", groupId ?? "");
            return true;
        }
        catch
        {
            info = null;
            return false; // hostile input must never take the parser down
        }
    }
}

/// <summary>
/// Enrollment lifecycle, mirroring PairingService's discipline: codes
/// are minted on the enrolling side WITH their scope and device group
/// bound at mint time — the redeeming side can never choose or widen
/// its own scope or group. Codes are 10 characters from an
/// unambiguous alphabet, displayed XXXXX-XXXXX, compared without the
/// dash and case-insensitively, single-use (consumed on successful
/// redeem), and expire (default TTL 10 minutes).
///
/// The roster holds public keys only — no private seed and no
/// reusable secret ever enters this store or its JSON export.
/// </summary>
public sealed class EnrollmentService
{
    /// <summary>Unambiguous code alphabet: no I/L/O, no 0/1.</summary>
    public const string CodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    public const int CodeLength = 10;
    public static readonly TimeSpan DefaultCodeTtl = TimeSpan.FromMinutes(10);

    /// <summary>Valid enrollment scopes. "local" = LOCAL PAIRING.</summary>
    public static readonly IReadOnlySet<string> ValidScopes =
        new HashSet<string> { "local", "personal", "company" };

    /// <summary>Valid per-device transport modes (D31).</summary>
    public static readonly IReadOnlySet<string> ValidTransportModes =
        new HashSet<string> { "inherit", "auto", "manual" };

    private sealed record PendingCode(
        string Code, DateTimeOffset ExpiresUtc, string Scope, string GroupId, string GroupName,
        string TransportMode, IReadOnlySet<string> AllowedTransports,
        string? MintedByUserId = null,
        // W14 P3-F2: the device owner bound at MINT time (like scope
        // and group, the redeeming side can never supply it).
        string OwnerUserId = "");

    private readonly Dictionary<string, EnrolledDevice> _devices = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<EnrollmentReceipt> _receipts = new();
    private readonly Dictionary<string, PendingCode> _pending = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly IClock _clock;

    /// <summary>Time source for code expiry (D38 S1-WIN F10): the
    /// shared <see cref="IClock"/> when the host injects one, the
    /// system clock otherwise — tests can now drive expiry without
    /// abusing negative TTLs.</summary>
    public EnrollmentService(IClock? clock = null) => _clock = clock ?? new SystemClock();

    /// <summary>Closing-integration seam (RMM-04 hub remainder): when
    /// set, Redeem refuses a device id that already lives in the
    /// UNMANAGED asset register — one identity cannot be both a
    /// managed enrollment and an unmanaged asset. Null = not wired
    /// (unit use); CoreRuntime wires it to the hub register.</summary>
    public Func<string, bool>? IsUnmanagedAssetId { get; set; }

    /// <summary>U9: supplies THIS (the minting/responder) device's
    /// 32-byte public key so Redeem can compute the SAS binding both
    /// keys. CoreRuntime wires it to the host DeviceIdentity. When
    /// unset, redeem still succeeds (SAS never blocks pairing) and
    /// the record honestly carries an empty Sas + unconfirmed state.</summary>
    public Func<byte[]>? LocalPublicKeyProvider { get; set; }

    private readonly List<SasAuditEntry> _sasAudit = new();

    /// <summary>Raised when a SAS audit entry is appended, so the
    /// host can mirror it into the host audit log.</summary>
    public event Action<SasAuditEntry>? SasAuditAppended;

    private void AppendSasAudit(string deviceId, string action)
    {
        var entry = new SasAuditEntry(deviceId, action, _clock.UtcNow);
        _sasAudit.Add(entry);
        SasAuditAppended?.Invoke(entry);
    }

    /// <summary>The persisted SAS audit trail (redeem / confirm / mismatch).</summary>
    public IReadOnlyList<SasAuditEntry> ListSasAudit()
    {
        lock (_gate) return _sasAudit.ToList();
    }

    /// <summary>Expiry instant for a TTL, overflow-safe: an absurd
    /// TTL (e.g. TimeSpan.MaxValue) clamps to the end of time instead
    /// of throwing out of mint (D38 S1-WIN F10).</summary>
    private static DateTimeOffset SafeExpiry(DateTimeOffset now, TimeSpan ttl)
    {
        try { return now + ttl; }
        catch (ArgumentOutOfRangeException)
        {
            return ttl < TimeSpan.Zero ? DateTimeOffset.MinValue : DateTimeOffset.MaxValue;
        }
    }

    /// <summary>Raised after any durable mutation (redeem, revoke,
    /// receipt) so the host can persist the roster.</summary>
    public event Action? Changed;

    // ---- codes ----------------------------------------------------------

    /// <summary>Normalize a presented code for comparison: strip dashes
    /// and whitespace, uppercase. Null when it is not exactly 10
    /// alphabet characters.</summary>
    public static string? NormalizeCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var chars = code.Where(c => c != '-' && !char.IsWhiteSpace(c))
                        .Select(char.ToUpperInvariant).ToArray();
        if (chars.Length != CodeLength) return null;
        if (chars.Any(c => !CodeAlphabet.Contains(c))) return null;
        return new string(chars);
    }

    /// <summary>Format a normalized code for display: XXXXX-XXXXX.</summary>
    public static string FormatCode(string normalizedCode) =>
        normalizedCode.Length == CodeLength
            ? normalizedCode.Substring(0, 5) + "-" + normalizedCode.Substring(5)
            : normalizedCode;

    private static string GenerateCode()
    {
        var chars = new char[CodeLength];
        for (var i = 0; i < CodeLength; i++)
            chars[i] = CodeAlphabet[RandomNumberGenerator.GetInt32(CodeAlphabet.Length)];
        return new string(chars);
    }

    // ---- mint / redeem ----------------------------------------------------

    /// <summary>Mint an enrollment code (enrolling side only). Scope
    /// and device group are BOUND TO THE CODE here; redeem can only
    /// ever receive what was minted. Returns the display form
    /// (XXXXX-XXXXX). Default TTL is 10 minutes.</summary>
    public string CreateEnrollmentCode(string scope, string groupId, string groupName, TimeSpan? ttl = null,
        string transportMode = "inherit", IEnumerable<string>? allowedTransports = null,
        string? mintedByUserId = null, string? ownerUserId = null)
    {
        var normalizedScope = NormalizeScope(scope)
            ?? throw new ArgumentException($"Scope must be one of: {string.Join(", ", ValidScopes)}.", nameof(scope));
        if (string.IsNullOrWhiteSpace(groupId)) throw new ArgumentException("Group id is required.", nameof(groupId));
        if (string.IsNullOrWhiteSpace(groupName)) throw new ArgumentException("Group name is required.", nameof(groupName));
        var normalizedMode = NormalizeTransportMode(transportMode)
            ?? throw new ArgumentException($"Transport mode must be one of: {string.Join(", ", ValidTransportModes)}.", nameof(transportMode));
        var code = GenerateCode();
        lock (_gate)
        {
            // Expired-but-never-redeemed codes are purged at mint time
            // so dead entries cannot accumulate forever (F10).
            var now = _clock.UtcNow;
            foreach (var dead in _pending.Where(kv => now > kv.Value.ExpiresUtc).Select(kv => kv.Key).ToList())
                _pending.Remove(dead);
            _pending[code] = new PendingCode(code, SafeExpiry(now, ttl ?? DefaultCodeTtl),
                normalizedScope, groupId, groupName, normalizedMode, NormalizeTransports(allowedTransports),
                string.IsNullOrWhiteSpace(mintedByUserId) ? null : mintedByUserId.Trim(),
                string.IsNullOrWhiteSpace(ownerUserId) ? "" : ownerUserId.Trim());
        }
        return FormatCode(code);
    }

    /// <summary>Alias for <see cref="CreateEnrollmentCode"/>.</summary>
    public string MintCode(string scope, string groupId, string groupName, TimeSpan? ttl = null,
        string transportMode = "inherit", IEnumerable<string>? allowedTransports = null,
        string? mintedByUserId = null, string? ownerUserId = null) =>
        CreateEnrollmentCode(scope, groupId, groupName, ttl, transportMode, allowedTransports, mintedByUserId, ownerUserId);

    /// <summary>Kill every still-pending (unredeemed) code a user
    /// minted. Offboarding (D14) revokes the auth keys a user created —
    /// a pending code IS one: without this, a removed user leaves a
    /// live enrollment key behind that can still file a new device
    /// into a group. Returns the number of codes killed.</summary>
    public int RevokePendingCodesMintedBy(string? mintedByUserId)
    {
        if (string.IsNullOrWhiteSpace(mintedByUserId)) return 0;
        lock (_gate)
        {
            var doomed = _pending
                .Where(kv => string.Equals(kv.Value.MintedByUserId, mintedByUserId, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Key).ToList();
            foreach (var code in doomed) _pending.Remove(code);
            if (doomed.Count > 0) Changed?.Invoke();
            return doomed.Count;
        }
    }

    /// <summary>bd-shared-plat-1/F3: kill ONE still-pending code
    /// (by its display or normalized form). Directory-enrollment
    /// terminal transitions (decline, expiry, cancel) call this so
    /// the underlying Slice-1 code dies with the offer — removing
    /// only the engine's in-memory copy left the code redeemable
    /// directly, bypassing AcceptOffer's checks. True when a live
    /// code was killed.</summary>
    public bool RevokePendingCode(string? code)
    {
        var normalized = NormalizeCode(code);
        if (normalized is null) return false;
        lock (_gate)
        {
            if (!_pending.Remove(normalized)) return false;
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>bd-shared-plat-1/F3: kill a still-pending code by
    /// the SHA-256 hash of its normalized form (the directory
    /// engine's CodeHash shape) — the import path, which holds
    /// only hashes, uses this so an imported-expired offer's code
    /// cannot survive in a shared EnrollmentService.</summary>
    public int RevokePendingCodeByHash(string? codeHashHex)
    {
        if (string.IsNullOrWhiteSpace(codeHashHex)) return 0;
        lock (_gate)
        {
            var doomed = _pending.Keys.Where(k =>
                string.Equals(
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(k))).ToLowerInvariant(),
                    codeHashHex.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (var k in doomed) _pending.Remove(k);
            if (doomed.Count > 0) Changed?.Invoke();
            return doomed.Count;
        }
    }

    /// <summary>Normalize a transport mode; null when not a valid mode.
    /// Import paths use this non-throwing form so malformed stored
    /// values fall back to the "inherit" default, never fatal (D31).</summary>
    public static string? NormalizeTransportMode(string? mode)
    {
        if (string.IsNullOrWhiteSpace(mode)) return null;
        var m = mode.Trim().ToLowerInvariant();
        return ValidTransportModes.Contains(m) ? m : null;
    }

    private static IReadOnlySet<string> NormalizeTransports(IEnumerable<string>? transports) =>
        transports is null
            ? new HashSet<string>()
            : new HashSet<string>(transports.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()));

    /// <summary>Redeem a code for the enrolling device. The device
    /// must prove its claimed DeviceId is the fingerprint of its
    /// public key. Returns null (fail-closed) for unknown, expired,
    /// or already-consumed codes and for malformed/mismatched device
    /// claims. The code is consumed only on success — plus on expiry,
    /// where it is dead either way.</summary>
    public EnrolledDevice? Redeem(string? code, EnrollingDevice? device)
    {
        var normalized = NormalizeCode(code);
        if (normalized is null || device is null) return null;
        lock (_gate)
        {
            if (!_pending.TryGetValue(normalized, out var pending)) return null;
            if (_clock.UtcNow > pending.ExpiresUtc)
            {
                _pending.Remove(normalized); // expired: dead, drop it
                return null;
            }
            if (!ValidateDevice(device)) return null; // not consumed: caller may correct and retry
            // A REVOKED device cannot resurrect itself by redeeming a
            // fresh code (D38 S1-WIN F1): revocation is the owner's
            // act, and a silent re-enroll would reset Revoked to false
            // and rewrite the record's scope/group binding. The code
            // is not consumed — revocation stands until the owner
            // lifts it by an explicit, audited path (none exists in
            // the model yet, by design). Re-enrollment of a LIVE
            // (unrevoked) device keeps the recorded DG-FIND-10
            // behavior: mint-side possession of a fresh code is the
            // credential, and the spec is silent on it.
            if (_devices.TryGetValue(device.DeviceId, out var existing) && existing.Revoked)
                return null;
            // RMM-04 hub remainder: consult the unmanaged register
            // before enrolling — refuse (code not consumed) when the
            // id is an unmanaged asset.
            if (IsUnmanagedAssetId is { } isUnmanaged &&
                (isUnmanaged(device.DeviceId) || isUnmanaged(device.DeviceId.ToLowerInvariant())))
                return null;

            _pending.Remove(normalized); // single-use: consumed on successful redeem
            // U9: SAS binds BOTH keys + the transcript (the normalized
            // code both sides held). Initiator = redeeming device,
            // responder = this minting device. Computed here, at
            // redeem, because the code is consumed by this act.
            // Pairing completes regardless — an absent responder key
            // leaves Sas empty and the state honestly unconfirmed.
            var sasDisplay = "";
            try
            {
                var responderKey = LocalPublicKeyProvider?.Invoke();
                var initiatorKey = Convert.FromBase64String(device.PublicKeyBase64);
                if (PairingSas.Compute(initiatorKey, responderKey, normalized) is { } sas)
                    sasDisplay = sas.Display;
            }
            catch { sasDisplay = ""; /* SAS must never break pairing */ }
            var enrolled = new EnrolledDevice(
                DeviceId: device.DeviceId.ToLowerInvariant(),
                DisplayName: device.DisplayName.Trim(),
                PublicKeyBase64: device.PublicKeyBase64,
                Scope: pending.Scope,
                GroupId: pending.GroupId,
                GroupName: pending.GroupName,
                EnrolledUtc: _clock.UtcNow,
                Revoked: false,
                TransportMode: pending.TransportMode,
                AllowedTransports: pending.AllowedTransports,
                Sas: sasDisplay,
                SasConfirmed: false,
                // W14 P3-F2: owner likewise comes from the MINT only.
                OwnerUserId: pending.OwnerUserId);
            _devices[enrolled.DeviceId] = enrolled;
            AppendSasAudit(enrolled.DeviceId, PairingSas.StateUnconfirmed);
            Changed?.Invoke();
            return enrolled;
        }
    }

    /// <summary>Convenience overload of <see cref="Redeem(string, EnrollingDevice)"/>.</summary>
    public EnrolledDevice? Redeem(string? code, string deviceId, string publicKeyBase64, string displayName) =>
        Redeem(code, new EnrollingDevice(deviceId, publicKeyBase64, displayName));

    /// <summary>Alias for <see cref="Redeem(string, EnrollingDevice)"/>.</summary>
    public EnrolledDevice? RedeemCode(string? code, EnrollingDevice? device) => Redeem(code, device);

    // ---- U9 follow-up: enrollment response (enroller key reveal) ----

    /// <summary>Build the post-redeem <see cref="EnrollmentResponse"/>
    /// for an enrolled device (ENROLLER side). The response carries
    /// this device's public key — obtained from
    /// <see cref="LocalPublicKeyProvider"/> — so the enrollee can
    /// compute the identical SAS. When no local key is wired, the
    /// response is the LEGACY shape: no key, and the enrollee will
    /// honestly record an absent SAS.</summary>
    public EnrollmentResponse? BuildEnrollmentResponse(EnrolledDevice? enrolled, string enrollerName)
    {
        if (enrolled is null) return null;
        byte[]? key = null;
        try { key = LocalPublicKeyProvider?.Invoke(); } catch { key = null; }
        return key is { Length: 32 }
            ? new EnrollmentResponse(
                Ed25519.ComputeDeviceId(key), enrollerName ?? "",
                Convert.ToBase64String(key),
                enrolled.DeviceId, enrolled.Scope, enrolled.GroupId,
                enrolled.GroupName, enrolled.EnrolledUtc)
            : new EnrollmentResponse(
                "", enrollerName ?? "", null,
                enrolled.DeviceId, enrolled.Scope, enrolled.GroupId,
                enrolled.GroupName, enrolled.EnrolledUtc);
    }

    /// <summary>Redeem + build the enrollment response in one act
    /// (ENROLLER side). Null enrolled (and null response) when the
    /// redeem itself is refused.</summary>
    public (EnrolledDevice? Enrolled, EnrollmentResponse? Response) RedeemWithResponse(
        string? code, EnrollingDevice? device, string enrollerName)
    {
        var enrolled = Redeem(code, device);
        return (enrolled, enrolled is null ? null : BuildEnrollmentResponse(enrolled, enrollerName));
    }

    private static bool ValidateDevice(EnrollingDevice device)
    {
        if (string.IsNullOrWhiteSpace(device.DeviceId) ||
            string.IsNullOrWhiteSpace(device.DisplayName) ||
            string.IsNullOrWhiteSpace(device.PublicKeyBase64))
            return false;
        byte[] publicKey;
        try { publicKey = Convert.FromBase64String(device.PublicKeyBase64); }
        catch (FormatException) { return false; }
        if (publicKey.Length != 32) return false;
        // Small-order keys are forgeable (anyone can sign as them):
        // not enrollable identities (D38 S1-WIN F2).
        if (Ed25519.IsSmallOrderPublicKey(publicKey)) return false;
        // DisplayName is persisted and shown in the owner's UI: bound
        // its length and strip control / bidi-override characters
        // (D38 S1-WIN F12).
        var name = device.DisplayName.Trim();
        if (name.Length == 0 || name.Length > 64) return false;
        if (name.Any(c => char.IsControl(c) ||
                          (c >= '\u202A' && c <= '\u202E') ||
                          (c >= '\u2066' && c <= '\u2069')))
            return false;
        // The claimed DeviceId must BE the fingerprint of the key —
        // a device cannot enroll under someone else's identity.
        return string.Equals(Ed25519.ComputeDeviceId(publicKey), device.DeviceId,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeScope(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope)) return null;
        var s = scope.Trim().ToLowerInvariant();
        return ValidScopes.Contains(s) ? s : null;
    }

    // ---- roster -----------------------------------------------------------

    public IReadOnlyList<EnrolledDevice> List()
    {
        lock (_gate) return _devices.Values.ToList();
    }

    /// <summary>One enrolled device by id (case-insensitive), or
    /// null. The Android store's byId mirror.</summary>
    public EnrolledDevice? ById(string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return null;
        lock (_gate) return _devices.TryGetValue(deviceId, out var device) ? device : null;
    }

    /// <summary>W14 P3-F2 (W13-P3-F2 spec, Android
    /// HostSessionBinding mirror): the SESSION owner-binding check.
    /// Returns the refusal reason "owner_mismatch" when the
    /// handshake-proven peer device carries a non-empty
    /// <see cref="EnrolledDevice.OwnerUserId"/> and the SESSION
    /// verb's initiator is not that owner; null when the session
    /// may proceed (device unknown, owner unbound — every legacy
    /// record — or initiator IS the owner). An unbound owner
    /// imposes no check: absent field = current behaviour, and the
    /// session layer's own scope/member validation still applies.</summary>
    public string? SessionOwnerRefusal(string? peerDeviceId, string? initiatorUserId)
    {
        var boundOwner = (ById(peerDeviceId)?.OwnerUserId ?? "").Trim();
        if (boundOwner.Length == 0) return null;
        return string.Equals(boundOwner, (initiatorUserId ?? "").Trim(), StringComparison.Ordinal)
            ? null
            : "owner_mismatch";
    }

    public IReadOnlyList<EnrolledDevice> ListByGroup(string groupId)
    {
        lock (_gate)
            return _devices.Values
                .Where(d => string.Equals(d.GroupId, groupId, StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    /// <summary>Revoke a device: immediate effect — signature
    /// verification for it fails from the next call on.</summary>
    public bool Revoke(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var device)) return false;
            _devices[device.DeviceId] = device with { Revoked = true };
            Changed?.Invoke();
            return true;
        }
    }

    // ---- U9 SAS confirmation (endpoint-local human act) ----

    /// <summary>Recompute the SAS for an enrolled device from its
    /// stored key + the local key + a transcript id. Null when any
    /// input is unavailable. The operator side uses this at pairing
    /// time; the endpoint recomputes the identical string from the
    /// same inputs on its side.</summary>
    public SasString? ComputeSasFor(string deviceId, string transcriptId)
    {
        EnrolledDevice? device;
        lock (_gate) _devices.TryGetValue(deviceId ?? "", out device);
        if (device is null) return null;
        byte[] initiatorKey;
        try { initiatorKey = Convert.FromBase64String(device.PublicKeyBase64); }
        catch (FormatException) { return null; }
        byte[]? responderKey;
        try { responderKey = LocalPublicKeyProvider?.Invoke(); }
        catch { return null; }
        return PairingSas.Compute(initiatorKey, responderKey, transcriptId);
    }

    /// <summary>The endpoint-local human confirm: the person at THIS
    /// endpoint compared the SAS on both surfaces and they matched.
    /// This is the ONLY path that sets SasConfirmed — no remote or
    /// programmatic caller may fake it on the human's behalf (the
    /// host wires this to a local UI act only). False for unknown
    /// devices or devices with no computed SAS.</summary>
    public bool ConfirmSas(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var device)) return false;
            if (string.IsNullOrWhiteSpace(device.Sas)) return false;
            if (!device.SasConfirmed || device.SasQuarantined)
            {
                // bd-shared-plat-2/F11: the endpoint-local human
                // re-confirm is also the quarantine release — the
                // person at the device re-compared the strings.
                _devices[device.DeviceId] = device with { SasConfirmed = true, SasQuarantined = false };
                AppendSasAudit(device.DeviceId, PairingSas.StateConfirmed);
                Changed?.Invoke();
            }
            return true;
        }
    }

    /// <summary>The endpoint-local mismatch report: the compared
    /// strings did NOT match. The record stays honestly unconfirmed
    /// and the report is audit-trailed. Pairing is NOT torn down by
    /// this act (SAS never blocks the consent floor) — revocation
    /// remains the owner's separate, explicit act.</summary>
    public bool ReportSasMismatch(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var device)) return false;
            // bd-shared-plat-2/F11: a mismatch now QUARANTINES —
            // VerifyEnrolledSignature refuses this device's key
            // until ConfirmSas (endpoint-local human re-check) or
            // revocation/re-pairing. Enrollment is not torn down.
            _devices[device.DeviceId] = device with { SasConfirmed = false, SasQuarantined = true };
            AppendSasAudit(device.DeviceId, "sas_mismatch_reported");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Update an enrolled device's transport fields (D31/D32,
    /// Slice 2): the mode must be a valid mode; the caller (the roster)
    /// is responsible for the within-group-set pin check BEFORE calling
    /// — this method only applies an already-validated narrowing/pin.
    /// False for unknown devices or an invalid mode; fires Changed.</summary>
    public bool TryUpdateTransports(string deviceId, string transportMode, IEnumerable<string>? allowedTransports)
    {
        var mode = NormalizeTransportMode(transportMode);
        if (mode is null || string.IsNullOrWhiteSpace(deviceId)) return false;
        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var device)) return false;
            _devices[device.DeviceId] = device with
            {
                TransportMode = mode,
                AllowedTransports = NormalizeTransports(allowedTransports),
            };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Largest message VerifyEnrolledSignature will hash
    /// (D38 S1-WIN F11): verification is deliberately expensive
    /// BigInteger work, and DeviceIds are public — an unbounded
    /// message would let any caller who reaches this surface make
    /// the host hash arbitrary data on demand. Challenge/response
    /// messages are small; 1 MiB is generous headroom.</summary>
    public const int MaxVerifyMessageBytes = 1024 * 1024;

    /// <summary>Verify a signature from an enrolled device. False for
    /// unknown, revoked, or malformed anything — never throws.</summary>
    public bool VerifyEnrolledSignature(string? deviceId, byte[]? message, byte[]? signature)
    {
        if (string.IsNullOrWhiteSpace(deviceId) || message is null || signature is null) return false;
        if (message.Length > MaxVerifyMessageBytes) return false;
        EnrolledDevice? device;
        lock (_gate) _devices.TryGetValue(deviceId, out device);
        if (device is null || device.Revoked) return false;
        // bd-shared-plat-2/F11: SAS-quarantined devices' signatures
        // do not verify — mobile registration, approvals and every
        // other enrolled-signature path stop trusting the key.
        if (device.SasQuarantined) return false;
        byte[] publicKey;
        try { publicKey = Convert.FromBase64String(device.PublicKeyBase64); }
        catch (FormatException) { return false; }
        return Ed25519.Verify(publicKey, message, signature);
    }

    /// <summary>Base64-signature overload of VerifyEnrolledSignature.</summary>
    public bool VerifyEnrolledSignature(string? deviceId, byte[]? message, string? signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64)) return false;
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureBase64); }
        catch (FormatException) { return false; }
        return VerifyEnrolledSignature(deviceId, message, signature);
    }

    // ---- receipts -----------------------------------------------------------

    public void RecordReceipt(EnrollmentReceipt receipt)
    {
        if (receipt is null) throw new ArgumentNullException(nameof(receipt));
        // Changed fires INSIDE the gate, like every other mutator in
        // this class: a receipt write can then never race a redeem /
        // revoke write in the host's persistence handler, whose
        // snapshots would otherwise interleave (D38 S1-WIN F4).
        lock (_gate)
        {
            _receipts.Add(receipt);
            Changed?.Invoke();
        }
    }

    public EnrollmentReceipt RecordReceipt(string enrollerName, string enrollerDeviceId, string scope, string groupName, DateTimeOffset? enrolledUtc = null)
    {
        var receipt = new EnrollmentReceipt(enrollerName, enrollerDeviceId, scope, groupName,
            enrolledUtc ?? _clock.UtcNow);
        RecordReceipt(receipt);
        return receipt;
    }

    public IReadOnlyList<EnrollmentReceipt> ListReceipts()
    {
        lock (_gate) return _receipts.ToList();
    }

    /// <summary>Replay guard for
    /// <see cref="RecordReceiptFromResponse"/>: a receipt for the
    /// SAME enrollment (enroller, enrolled instant, scope, group,
    /// enroller name and SAS — the confirmation flag deliberately
    /// excluded) is already recorded. Caller must hold _gate.</summary>
    private EnrollmentReceipt? FindIdenticalReceipt(EnrollmentReceipt candidate) =>
        _receipts.FirstOrDefault(r =>
            r.EnrollerDeviceId == candidate.EnrollerDeviceId &&
            r.EnrolledUtc == candidate.EnrolledUtc &&
            r.Scope == candidate.Scope &&
            r.GroupName == candidate.GroupName &&
            r.EnrollerName == candidate.EnrollerName &&
            r.Sas == candidate.Sas);

    /// <summary>
    /// ENROLLEE side of the U9 follow-up: ingest an
    /// <see cref="EnrollmentResponse"/> and record this device's
    /// receipt, computing the SAS enrollee-side.
    ///
    /// Verification BEFORE use (the MITM leg): the transmitted
    /// enroller key is fingerprinted (SHA-256, the DeviceId
    /// derivation) and compared against
    /// <paramref name="expectedEnrollerDeviceId"/> — the commitment
    /// the enrollee already holds from the code/QR transcript — and
    /// against the response's own claimed enroller id when present.
    /// Any mismatch refuses the response: no receipt, no SAS, and a
    /// <see cref="PairingSas.AuditEnrollerKeyMismatch"/> audit entry.
    ///
    /// SAS derivation is the pinned U9 algorithm with the enrollee's
    /// OWN key as initiator, the verified enroller key as responder,
    /// and the enrollee's locally held code (normalized) as the
    /// transcript — never a transcript taken from the response, so a
    /// tampered response cannot steer the derivation. The resulting
    /// string is identical to the enroller-side record for the same
    /// enrollment.
    ///
    /// LEGACY: a response with no key stores the receipt with an
    /// empty SAS and a
    /// <see cref="PairingSas.AuditAbsentNoEnrollerKey"/> audit entry
    /// — the downgrade to the no-SAS state is VISIBLE, never silent,
    /// and the absent SAS is never faked.
    ///
    /// REPLAY: re-ingesting the identical response is idempotent —
    /// the already-recorded receipt is returned, no duplicate
    /// receipt or audit entry is stored, and a human-confirmed
    /// state is never shadowed by a fresh unconfirmed copy
    /// (recovery-verification fix, 2026-11-22).
    /// </summary>
    public EnrollmentResponseResult RecordReceiptFromResponse(
        EnrollmentResponse? response,
        string? expectedEnrollerDeviceId,
        string? ownPublicKeyBase64,
        string? transcriptCode)
    {
        if (response is null)
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "no enrollment response");
        var enrollerId = !string.IsNullOrWhiteSpace(response.EnrollerDeviceId)
            ? response.EnrollerDeviceId.Trim()
            : (expectedEnrollerDeviceId ?? "").Trim();
        if (string.IsNullOrWhiteSpace(enrollerId))
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "response carries no enroller identity and no committed fingerprint was held");
        if (NormalizeScope(response.Scope) is not { } scope)
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "response carries an unknown scope");

        // LEGACY leg: no key in the response — honest absent SAS.
        if (string.IsNullOrWhiteSpace(response.EnrollerPublicKeyBase64))
        {
            var legacyReceipt = new EnrollmentReceipt(
                response.EnrollerName ?? "", enrollerId, scope,
                response.GroupName ?? "", response.EnrolledUtc, "", false);
            lock (_gate)
            {
                // Replay guard: the identical receipt is already
                // recorded — a re-sent response stores no duplicate
                // and appends no second absent-SAS audit entry.
                if (FindIdenticalReceipt(legacyReceipt) is { } existingLegacy)
                    return new EnrollmentResponseResult(EnrollmentResponseOutcome.LegacyNoKey, existingLegacy,
                        "replayed response — receipt already recorded; no duplicate stored");
                _receipts.Add(legacyReceipt);
                AppendSasAudit(enrollerId, PairingSas.AuditAbsentNoEnrollerKey);
                Changed?.Invoke();
            }
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.LegacyNoKey, legacyReceipt,
                "legacy enroller sent no public key — SAS absent (audited), not faked");
        }

        // Decode + shape-check the revealed key BEFORE any use.
        byte[] enrollerKey;
        try { enrollerKey = Convert.FromBase64String(response.EnrollerPublicKeyBase64); }
        catch (FormatException)
        {
            lock (_gate) AppendSasAudit(enrollerId, PairingSas.AuditEnrollerKeyMalformed);
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "enroller public key is not valid base64 — refused");
        }
        if (enrollerKey.Length != 32 || Ed25519.IsSmallOrderPublicKey(enrollerKey))
        {
            lock (_gate) AppendSasAudit(enrollerId, PairingSas.AuditEnrollerKeyMalformed);
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "enroller public key is malformed (length or small-order) — refused");
        }

        // THE COMMITMENT CHECK: fingerprint(revealed key) must equal
        // the committed enroller DeviceId held from the code/QR, and
        // the response's own claimed id when it carries one.
        var fingerprint = Ed25519.ComputeDeviceId(enrollerKey);
        var committed = (expectedEnrollerDeviceId ?? "").Trim();
        if (string.IsNullOrWhiteSpace(committed) ||
            !string.Equals(fingerprint, committed, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrWhiteSpace(response.EnrollerDeviceId) &&
             !string.Equals(fingerprint, response.EnrollerDeviceId.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            lock (_gate) AppendSasAudit(enrollerId, PairingSas.AuditEnrollerKeyMismatch);
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedKeyMismatch, null,
                "enroller public key does not match the committed fingerprint — refused and audited");
        }

        // Derive the SAS enrollee-side: own key (initiator) + the
        // VERIFIED enroller key (responder) + the locally held code.
        var transcript = NormalizeCode(transcriptCode);
        byte[] ownKey;
        try { ownKey = Convert.FromBase64String(ownPublicKeyBase64 ?? ""); }
        catch (FormatException) { ownKey = Array.Empty<byte>(); }
        var sas = transcript is null ? null : PairingSas.Compute(ownKey, enrollerKey, transcript);
        if (sas is null)
            return new EnrollmentResponseResult(EnrollmentResponseOutcome.RefusedMalformed, null,
                "could not derive SAS enrollee-side (own key or transcript invalid) — no receipt recorded");

        var receipt = new EnrollmentReceipt(
            response.EnrollerName ?? "", enrollerId, scope,
            response.GroupName ?? "", response.EnrolledUtc, sas.Display, false);
        lock (_gate)
        {
            // Replay guard (see the legacy leg): no duplicate
            // receipt/audit, and a replay must never shadow a
            // human-confirmed receipt with a fresh unconfirmed copy.
            if (FindIdenticalReceipt(receipt) is { } existing)
                return new EnrollmentResponseResult(EnrollmentResponseOutcome.Applied, existing,
                    "replayed response — receipt already recorded; no duplicate stored, confirmation state untouched");
            _receipts.Add(receipt);
            AppendSasAudit(enrollerId, PairingSas.StateUnconfirmed);
            Changed?.Invoke();
        }
        return new EnrollmentResponseResult(EnrollmentResponseOutcome.Applied, receipt,
            "enroller key verified against the committed fingerprint; SAS computed enrollee-side, unconfirmed");
    }

    /// <summary>The endpoint-local human confirm for a RECEIPT
    /// (enrollee side, U9 follow-up): the person at THIS device
    /// compared the receipt's SAS against the string on the enroller
    /// and they matched. The ONLY path that confirms a receipt SAS.
    /// False when no receipt exists for the enroller or the receipt
    /// carries no SAS (legacy/absent is never confirmable).</summary>
    public bool ConfirmReceiptSas(string enrollerDeviceId)
    {
        if (string.IsNullOrWhiteSpace(enrollerDeviceId)) return false;
        lock (_gate)
        {
            var idx = _receipts.FindLastIndex(r =>
                string.Equals(r.EnrollerDeviceId, enrollerDeviceId, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            var receipt = _receipts[idx];
            if (string.IsNullOrWhiteSpace(receipt.Sas)) return false;
            if (!receipt.SasConfirmed)
            {
                _receipts[idx] = receipt with { SasConfirmed = true };
                AppendSasAudit(receipt.EnrollerDeviceId, PairingSas.StateConfirmed);
                Changed?.Invoke();
            }
            return true;
        }
    }

    /// <summary>The endpoint-local mismatch report for a RECEIPT
    /// (enrollee side, U9 follow-up): the compared strings did NOT
    /// match. The receipt stays honestly unconfirmed and the report
    /// is audit-trailed; pairing is NOT torn down.</summary>
    public bool ReportReceiptSasMismatch(string enrollerDeviceId)
    {
        if (string.IsNullOrWhiteSpace(enrollerDeviceId)) return false;
        lock (_gate)
        {
            var idx = _receipts.FindLastIndex(r =>
                string.Equals(r.EnrollerDeviceId, enrollerDeviceId, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return false;
            var receipt = _receipts[idx];
            if (receipt.SasConfirmed)
                _receipts[idx] = receipt with { SasConfirmed = false };
            AppendSasAudit(receipt.EnrollerDeviceId, "sas_mismatch_reported");
            Changed?.Invoke();
            return true;
        }
    }

    // ---- persistence ---------------------------------------------------------

    private sealed record DeviceDto(
        string DeviceId, string DisplayName, string PublicKeyBase64, string Scope,
        string GroupId, string GroupName, DateTimeOffset EnrolledUtc, bool Revoked,
        string? TransportMode, string[]? AllowedTransports,
        string? Sas = null, bool? SasConfirmed = null, bool? SasQuarantined = null,
        // W14 P3-F2 trailing field: absent in older exports —
        // parse-tolerant, loads as unbound ("").
        string? OwnerUserId = null);

    private sealed record StoreDto(DeviceDto[] Devices, EnrollmentReceipt[] Receipts,
        SasAuditEntry[]? SasAudit = null);

    /// <summary>Serialize the roster + receipts. Public keys only:
    /// no private seed and no pending (still-redeemable) code is ever
    /// in the export.</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _devices.Values.Select(d => new DeviceDto(d.DeviceId, d.DisplayName, d.PublicKeyBase64,
                    d.Scope, d.GroupId, d.GroupName, d.EnrolledUtc, d.Revoked,
                    d.TransportMode, d.AllowedTransports.ToArray(),
                    d.Sas, d.SasConfirmed, d.SasQuarantined, d.OwnerUserId)).ToArray(),
                _receipts.ToArray(),
                _sasAudit.ToArray());
            return JsonSerializer.Serialize(store);
        }
    }

    /// <summary>Restore a store previously produced by ExportJson.
    /// Malformed entries are skipped, never fatal — and malformed
    /// JSON as a whole restores nothing rather than throwing.
    /// Returns the number of device entries restored.</summary>
    public int ImportJson(string json)
    {
        StoreDto? store;
        try { store = JsonSerializer.Deserialize<StoreDto>(json); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in store.Devices ?? Array.Empty<DeviceDto>())
            {
                if (dto is null) continue;
                // Import restores into a fresh store; it never
                // overwrites a live record. Without this, a stale or
                // hand-edited file imported over a live store could
                // resurrect a revoked device or rewrite its scope /
                // group binding (destruction gate DG-S1-06).
                if (!string.IsNullOrWhiteSpace(dto.DeviceId) && _devices.ContainsKey(dto.DeviceId)) continue;
                var candidate = new EnrollingDevice(dto.DeviceId ?? "", dto.PublicKeyBase64 ?? "", dto.DisplayName ?? "");
                if (!ValidateDevice(candidate)) continue;
                if (NormalizeScope(dto.Scope) is not { } scope) continue;
                if (string.IsNullOrWhiteSpace(dto.GroupId)) continue;
                // D31: missing/malformed transport fields fall back
                // to the defaults ("inherit", empty set), never fatal.
                _devices[dto.DeviceId] = new EnrolledDevice(dto.DeviceId.ToLowerInvariant(), dto.DisplayName,
                    dto.PublicKeyBase64, scope, dto.GroupId, dto.GroupName ?? "", dto.EnrolledUtc, dto.Revoked,
                    NormalizeTransportMode(dto.TransportMode) ?? "inherit",
                    NormalizeTransports(dto.AllowedTransports),
                    // U9: SAS fields restore verbatim; a missing or
                    // over-long stored SAS degrades to empty +
                    // unconfirmed, never to a fake confirmation.
                    dto.Sas is { Length: <= 64 } sas ? sas : "",
                    !string.IsNullOrWhiteSpace(dto.Sas) && dto.Sas.Length <= 64 && dto.SasConfirmed == true,
                    // bd-shared-plat-2/F11: quarantine survives restart.
                    dto.SasQuarantined == true,
                    // W14 P3-F2 trailing field: absent = unbound.
                    string.IsNullOrWhiteSpace(dto.OwnerUserId) ? "" : dto.OwnerUserId.Trim());
                restored++;
            }
            foreach (var receipt in store.Receipts ?? Array.Empty<EnrollmentReceipt>())
            {
                if (receipt is null) continue;
                if (string.IsNullOrWhiteSpace(receipt.EnrollerDeviceId) ||
                    string.IsNullOrWhiteSpace(receipt.EnrollerName)) continue;
                if (_receipts.Contains(receipt)) continue; // re-import must not duplicate history
                // U9: a stored receipt confirmation with NO SAS
                // degrades to unconfirmed on import — never faked
                // (same discipline as device records above).
                _receipts.Add(string.IsNullOrWhiteSpace(receipt.Sas) && receipt.SasConfirmed
                    ? receipt with { SasConfirmed = false }
                    : receipt);
            }
            foreach (var entry in store.SasAudit ?? Array.Empty<SasAuditEntry>())
            {
                if (entry is null || string.IsNullOrWhiteSpace(entry.DeviceId)) continue;
                if (!_sasAudit.Contains(entry)) _sasAudit.Add(entry);
            }
        }
        return restored;
    }
}

using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Tailscale;

/// <summary>In-app Tailscale setup (D4) implementing the T2 audit's
/// binding conditions (REPORT §7) on DeskGuest's side of the boundary.
/// The ONE human moment is Tailscale's own IdP sign-in page inside
/// DeskGuest's frame: DeskGuest never sees, types, or stores that credential —
/// the setup flow crosses that boundary through a delegate that
/// reports only "the provider sign-in completed", and holds no
/// token from it. Everything after that moment DeskGuest drives via the
/// Tailscale API with scoped OAuth trust credentials only.
///
/// LIVE-ACCOUNT LEG: UNPROVEN. No real Tailscale account exists in
/// this programme (no external accounts may be created, nobody may
/// be signed in as). The flow is proven against the API surface
/// with a local mock; the leg past the sign-in boundary against
/// the real vendor API is owed a human's own sign-in.</summary>
public static class TailscalePins
{
    /// <summary>T2 §7.1 — the audited, pinned client.</summary>
    public const string PinnedClientVersion = "1.104.7";
    /// <summary>T2 §7.1 — the Tailworm floor (TS-2026-014…017).</summary>
    public const string MinClientVersion = HubPins.MinTailscaleClient; // 1.104.4
    public const string KillSwitchEnvVar = "TS_NO_LOGS_NO_SUPPORT";
    public const string SshForwardingOffEnvVar = "TS_SSH_DISABLE_FORWARDING";
}

/// <summary>Where setup is running. The platform decides whether
/// the logtail kill switch can be asserted at all (TS-03).</summary>
public enum MeshPlatform { DesktopWindows, DesktopLinux, DesktopMac, Android, Ios }

/// <summary>Who this device is in DeskGuest. Endpoints never sign in
/// (D3) and never offer the mesh rung; on mobile the rung is
/// operator-personal-device only (TS-03 carve-out).</summary>
public enum MeshRole { Operator, Endpoint }

public static class MeshHonesty
{
    /// <summary>D15/D16 honesty, shown IN the setup flow before the
    /// rung is enabled (T2 §7.8): the vendor processes connection
    /// metadata on this rung, and the free tier meters.</summary>
    public const string VendorLabel =
        "About this rung: session traffic is end-to-end encrypted between your devices, but on this rung " +
        "Tailscale Inc. processes connection metadata and the device inventory for the tailnet — DeskGuest's " +
        "'no vendor server holds your data' claim does not cover this rung. The free tier covers 6 users " +
        "and 50 tagged resources; beyond that a paid Tailscale plan is required.";

    /// <summary>TS-03 carve-out, shown on mobile before the flow
    /// proceeds: the mobile apps have no logtail opt-out (upstream
    /// issue #13174), so the vendor's operational-log collection
    /// cannot be switched off there.</summary>
    public const string MobileCarveOutLabel =
        "On Android and iOS the Tailscale app collects operational logs and there is no way to switch that " +
        "collection off (the desktop log switch does not exist in the mobile apps). This rung is therefore " +
        "offered only for your own personal device, never for a managed endpoint.";

    public const string SignInBoundaryLabel =
        "One step is yours alone: Tailscale's own sign-in page, shown here inside DeskGuest. DeskGuest never sees, " +
        "types, or stores that password — it only learns that sign-in completed.";
}

// ------------------------------------------------------------ credentials (TS-05)

public enum CredentialClass { ScopedOAuth, Federated, PersonalApiToken, Unknown }

public static class TailscaleCredentialGuard
{
    /// <summary>Classify a presented API credential. Personal API
    /// access tokens (`tskey-api-…`) are unscoped, full-admin,
    /// up-to-90-day bearer secrets (TS-05): DeskGuest refuses to hold
    /// one, at setup and everywhere else.</summary>
    public static CredentialClass Classify(string? credential)
    {
        if (string.IsNullOrWhiteSpace(credential)) return CredentialClass.Unknown;
        var c = credential.Trim();
        if (c.StartsWith("tskey-api-", StringComparison.Ordinal)) return CredentialClass.PersonalApiToken;
        if (c.StartsWith("tskey-client-", StringComparison.Ordinal)) return CredentialClass.ScopedOAuth;
        return CredentialClass.Unknown;
    }

    /// <summary>The minimum scope set per function (T2 §7.5):
    /// separate functions carry separate scopes; a credential
    /// presented for a function must hold that function's scope.</summary>
    public static readonly IReadOnlyDictionary<string, string> ScopeForFunction =
        new Dictionary<string, string>
        {
            ["policy"] = "policy_file",
            ["auth_keys"] = "auth_keys",
            ["devices_read"] = "devices:core:read",
        };

    public static (bool Ok, string Detail) AcceptForStorage(string? credential, IEnumerable<string> scopes)
    {
        var cls = Classify(credential);
        if (cls == CredentialClass.PersonalApiToken)
            return (false, "refused: that is a personal API access token — unscoped, full-admin, up to 90 days (TS-05). DeskGuest holds only scoped OAuth trust credentials; create one in the Tailscale admin console under Settings → OAuth clients and present that instead.");
        if (cls != CredentialClass.ScopedOAuth)
            return (false, "refused: unrecognized credential shape — DeskGuest holds only scoped OAuth trust credentials (tskey-client-…) or a federated identity with no stored secret.");
        var held = scopes.Select(s => s.Trim()).ToHashSet(StringComparer.Ordinal);
        if (held.Count == 0)
            return (false, "refused: an OAuth credential with no scopes can do nothing and proves nothing — scope it to the functions DeskGuest will drive.");
        return (true, "scoped OAuth trust credential accepted (exchanged for 1-hour tokens, secret stays in DeskGuest's vault)");
    }
}

/// <summary>OAuth token broker: holds the trust credential's
/// secret protector-wrapped (never plaintext at rest), exchanges
/// it for 1-hour access tokens through the API surface, and
/// refuses to ever hold a personal API token.</summary>
public sealed class OAuthTokenBroker
{
    private readonly ISecretProtector _protector;
    private readonly ITailscaleApi _api;
    private string? _protectedSecret;
    private string? _clientId;
    private string? _cachedToken;
    private DateTimeOffset _cachedUntil = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _exchangeGate = new(1, 1);

    public OAuthTokenBroker(ISecretProtector protector, ITailscaleApi api)
    { _protector = protector; _api = api; }

    public IReadOnlyList<string> Scopes { get; private set; } = Array.Empty<string>();

    public (bool Ok, string Detail) SetCredential(string clientId, string clientSecret, IEnumerable<string> scopes)
    {
        var verdict = TailscaleCredentialGuard.AcceptForStorage(clientSecret, scopes);
        if (!verdict.Ok) return verdict;
        if (string.IsNullOrWhiteSpace(clientId)) return (false, "refused: OAuth client id required");
        _clientId = clientId.Trim();
        _protectedSecret = _protector.Protect(clientSecret.Trim());
        Scopes = scopes.Select(s => s.Trim()).ToList();
        _cachedToken = null;
        return (true, verdict.Detail);
    }

    public bool HasFederatedIdentity { get; set; }

    /// <summary>A live 1-hour token, from cache or a fresh
    /// exchange. Federated identity exchanges a workload JWT with
    /// no stored secret at all (T2 improvement, adopted).</summary>
    public async Task<(bool Ok, string TokenOrDetail)> GetTokenAsync(DateTimeOffset now, CancellationToken ct = default)
    {
        // BD-SHARED-TRANSPORT F9: the cache lifetime comes from the
        // API's own expires_in (minus a 30 s safety skew), never a
        // fixed 55 minutes — a shorter-lived token cached for 55
        // minutes is a stale credential presented as live. The
        // exchange is serialised: concurrent callers share one
        // exchange instead of racing the cache fields.
        if (_cachedToken is not null && now < _cachedUntil) return (true, _cachedToken);
        await _exchangeGate.WaitAsync(ct);
        try
        {
            if (_cachedToken is not null && now < _cachedUntil) return (true, _cachedToken);
            ApiResult result;
            if (HasFederatedIdentity)
            {
                result = await _api.ExchangeFederatedAsync(Scopes, ct);
            }
            else
            {
                if (_protectedSecret is null || _clientId is null)
                    return (false, "no credential held — setup has not presented a scoped OAuth trust credential");
                var secret = _protector.Unprotect(_protectedSecret);
                result = await _api.ExchangeOAuthAsync(_clientId, secret, Scopes, ct);
            }
            if (!result.Ok) return (false, result.Detail);
            var lifetime = result.ExpiresInSeconds is { } secs and > 60
                ? TimeSpan.FromSeconds(secs) - TimeSpan.FromSeconds(30)
                : TimeSpan.FromMinutes(55); // legacy fakes that report no expiry keep the old bound, named here
            _cachedToken = result.Token; _cachedUntil = now + lifetime;
            return (true, result.Token!);
        }
        finally { _exchangeGate.Release(); }
    }
}

// ------------------------------------------------------------ daemon seam + kill switch (TS-01/02/10)

/// <summary>What DeskGuest can observe about the local Tailscale client.
/// Production implementations shell the pinned CLI / read the
/// service environment; tests use fakes. LogtailState is the
/// daemon's own report of its log pipeline: "disabled-no-logs" is
/// the only state DeskGuest accepts on desktop.</summary>
public sealed record TailscaleDaemonFacts(
    string? InstalledVersion, string LogtailState,
    bool SshEnabled, bool ServeEnabled, bool FunnelEnabled, bool Conn25Used,
    bool ProbeReliable = true);

public interface ITailscaleDaemonProbe
{
    TailscaleDaemonFacts Probe();
}

/// <summary>The daemon launch plan DeskGuest asserts FROM FIRST START
/// (T2 §7.2): the kill switch is in the environment and the flag
/// set before the daemon ever runs — a daemon started once
/// without it has already shipped its startup batch (TS-01).</summary>
public static class TailscaleDaemonLaunchPlan
{
    public static IReadOnlyDictionary<string, string> Environment() => new Dictionary<string, string>
    {
        [TailscalePins.KillSwitchEnvVar] = "true",
        [TailscalePins.SshForwardingOffEnvVar] = "1",
    };

    public static IReadOnlyList<string> DaemonArguments() => new[] { "--no-logs-no-support" };

    public static bool PlanAssertsKillSwitch(IReadOnlyDictionary<string, string> env, IReadOnlyList<string> args) =>
        env.TryGetValue(TailscalePins.KillSwitchEnvVar, out var v) && v == "true"
        && args.Contains("--no-logs-no-support");
}

public static class KillSwitchGuard
{
    public static bool CanAssert(MeshPlatform platform) =>
        platform is MeshPlatform.DesktopWindows or MeshPlatform.DesktopLinux or MeshPlatform.DesktopMac;

    /// <summary>Verify the kill switch on a desktop platform:
    /// the launch plan must assert it AND the daemon must report
    /// its log pipeline disabled. Anything else — including a
    /// daemon already running without the switch — refuses the
    /// rung: DeskGuest will not "fix it on the next restart", because
    /// the un-switched start already shipped its batch.</summary>
    public static (bool Ok, string Detail) VerifyDesktop(ITailscaleDaemonProbe probe)
    {
        if (!TailscaleDaemonLaunchPlan.PlanAssertsKillSwitch(
                TailscaleDaemonLaunchPlan.Environment(), TailscaleDaemonLaunchPlan.DaemonArguments()))
            return (false, "internal: DeskGuest's own launch plan does not assert the kill switch — rung refused");
        var facts = probe.Probe();
        if (facts.LogtailState != "disabled-no-logs")
            return (false, $"rung refused: the daemon's log pipeline reports '{facts.LogtailState}', not disabled. TS_NO_LOGS_NO_SUPPORT must be asserted from the daemon's first start and verified; a daemon that ever started without it has already uploaded its startup logs (TS-01/TS-02).");
        return (true, "logtail kill switch asserted from first start and verified (daemon reports logging disabled)");
    }
}

// ------------------------------------------------------------ D12 policy mapping + injection-safe builder (TS-07, T5 OP-01)

/// <summary>DeskGuest's roster shape for one tailnet policy build:
/// user groups become ACL groups, device groups become tags, and
/// the groups allowed to enroll a device group become its
/// tagOwners (D12). Grants are explicit (source group → tag,
/// ports) — nothing is implied.</summary>
public sealed record TailnetMapping(
    IReadOnlyDictionary<string, IReadOnlyList<string>> UserGroups,
    IReadOnlyList<string> DeviceGroups,
    IReadOnlyDictionary<string, IReadOnlyList<string>> EnrollRights,
    IReadOnlyList<TailnetGrant> Grants);

public sealed record TailnetGrant(string SourceGroup, string DestinationTag, IReadOnlyList<string> Ports);

public static class AclBuilder
{
    // T5 OP-01 applied to this API: the policy file is a config
    // surface, so every name/member/port is validated against a
    // strict shape before it can enter the document. Serialization
    // is structural (System.Text.Json over validated values) —
    // never string interpolation of unvalidated input.
    private static readonly Regex NameShape = new("^[a-z0-9][a-z0-9._-]{0,62}$", RegexOptions.Compiled);
    private static readonly Regex MemberShape = new("^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$", RegexOptions.Compiled);
    private static readonly Regex PortShape = new("^[0-9]{1,5}$", RegexOptions.Compiled);

    private static string Name(string raw, string what)
    {
        var n = (raw ?? "").Trim().ToLowerInvariant();
        if (!NameShape.IsMatch(n))
            throw new InvalidOperationException(
                $"policy build refused: {what} name '{raw}' is not a plain tailnet name (letters/digits/._- only) — nothing user-controlled reaches the policy file unvalidated");
        return n;
    }

    private static string Member(string raw)
    {
        var m = (raw ?? "").Trim();
        if (!MemberShape.IsMatch(m) || m.Any(char.IsControl))
            throw new InvalidOperationException(
                $"policy build refused: group member '{raw}' has an invalid shape — nothing user-controlled reaches the policy file unvalidated");
        return m;
    }

    private static string Port(string raw)
    {
        var p = (raw ?? "").Trim();
        if (!PortShape.IsMatch(p) || !int.TryParse(p, out var v) || v is < 1 or > 65535)
            throw new InvalidOperationException($"policy build refused: port '{raw}' is not a valid port");
        return p;
    }

    /// <summary>Build the whole policy document. Deny-by-default
    /// shape: no wildcard sources, no `*` destinations, and NO
    /// `ssh` section ever — DeskGuest does not enable Tailscale SSH on
    /// this rung (TS-10), so the builder cannot emit one.</summary>
    public static string Build(TailnetMapping mapping)
    {
        var groups = new Dictionary<string, IReadOnlyList<string>>();
        foreach (var (name, members) in mapping.UserGroups)
            groups["group:" + Name(name, "user group")] = members.Select(Member).ToList();

        var tagOwners = new Dictionary<string, IReadOnlyList<string>>();
        foreach (var dg in mapping.DeviceGroups)
        {
            var tag = "tag:" + Name(dg, "device group");
            var owners = mapping.EnrollRights.TryGetValue(dg, out var gs)
                ? gs.Select(g => "group:" + Name(g, "enroll-rights group")).ToList()
                : new List<string>();
            tagOwners[tag] = owners;
        }

        var acls = new List<object>();
        foreach (var grant in mapping.Grants)
        {
            var src = "group:" + Name(grant.SourceGroup, "grant source group");
            var dst = "tag:" + Name(grant.DestinationTag, "grant destination tag");
            var ports = grant.Ports.Select(Port).ToList();
            if (ports.Count == 0)
                throw new InvalidOperationException("policy build refused: a grant with no ports would be meaningless or over-broad — name the ports");
            acls.Add(new Dictionary<string, object>
            {
                ["action"] = "accept",
                ["src"] = new[] { src },
                ["dst"] = ports.Select(p => $"{dst}:{p}").ToArray(),
            });
        }

        var doc = new Dictionary<string, object>
        {
            ["groups"] = groups,
            ["tagOwners"] = tagOwners,
            ["acls"] = acls,
        };
        return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Structural diff for the preview step: lines added
    /// and removed between two policy documents.</summary>
    public static (IReadOnlyList<string> Added, IReadOnlyList<string> Removed) Diff(string oldPolicy, string newPolicy)
    {
        var oldLines = new HashSet<string>((oldPolicy ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0));
        var newLines = new HashSet<string>((newPolicy ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0));
        return (newLines.Except(oldLines).OrderBy(x => x).ToList(),
                oldLines.Except(newLines).OrderBy(x => x).ToList());
    }
}

// ------------------------------------------------------------ API surface + guarded writes (TS-07)

public sealed record ApiResult(bool Ok, string Detail, string? Token = null, string? Policy = null, string? AuthKey = null,
    int? ExpiresInSeconds = null);

public interface ITailscaleApi
{
    Task<ApiResult> ExchangeOAuthAsync(string clientId, string clientSecret, IReadOnlyList<string> scopes, CancellationToken ct = default);
    Task<ApiResult> ExchangeFederatedAsync(IReadOnlyList<string> scopes, CancellationToken ct = default);
    Task<ApiResult> GetPolicyAsync(string token, CancellationToken ct = default);
    Task<ApiResult> ValidatePolicyAsync(string token, string policy, CancellationToken ct = default);
    Task<ApiResult> ApplyPolicyAsync(string token, string policy, CancellationToken ct = default);
    Task<ApiResult> CreateAuthKeyAsync(string token, IReadOnlyList<string> tags, bool singleUse, TimeSpan expiry, CancellationToken ct = default);
}

/// <summary>Guarded policy writes (T2 §7.6): validate → preview
/// (diff against the live document) → apply, with the previous
/// document kept as the rollback copy; a failed apply triggers a
/// rollback attempt and says so. One DeskGuest operation, never a bare
/// POST.</summary>
public sealed class PolicyGuard
{
    private readonly ITailscaleApi _api;
    public string? LastKnownGoodPolicy { get; private set; }
    public (IReadOnlyList<string> Added, IReadOnlyList<string> Removed)? LastDiff { get; private set; }

    public PolicyGuard(ITailscaleApi api) => _api = api;

    public async Task<(bool Ok, string Detail)> ApplyAsync(string token, string newPolicy, CancellationToken ct = default)
    {
        var current = await _api.GetPolicyAsync(token, ct);
        if (!current.Ok) return (false, "policy write stopped: could not read the current policy — no write without a rollback copy. " + current.Detail);
        LastKnownGoodPolicy = current.Policy ?? "";
        var validation = await _api.ValidatePolicyAsync(token, newPolicy, ct);
        if (!validation.Ok) return (false, "policy write stopped at validation — nothing was applied. " + validation.Detail);
        LastDiff = AclBuilder.Diff(LastKnownGoodPolicy, newPolicy);
        var applied = await _api.ApplyPolicyAsync(token, newPolicy, ct);
        if (applied.Ok) return (true, $"policy applied (preview diff: +{LastDiff.Value.Added.Count}/-{LastDiff.Value.Removed.Count} lines; rollback copy kept)");
        var rollback = await _api.ApplyPolicyAsync(token, LastKnownGoodPolicy, ct);
        return (false, rollback.Ok
            ? "policy apply failed; the previous policy was restored from the rollback copy. " + applied.Detail
            : "policy apply failed AND the rollback failed — the tailnet policy needs manual attention now. " + applied.Detail);
    }
}

/// <summary>Endpoint auth keys (D3/D4, T2 §7.7): DeskGuest-minted,
/// single-use, tagged, ≤90 days with a much shorter default.
/// Reusable keys are refused outright.</summary>
public sealed class EndpointAuthKeyService
{
    public static readonly TimeSpan DefaultExpiry = TimeSpan.FromDays(7);
    public static readonly TimeSpan MaxExpiry = TimeSpan.FromDays(90);
    private readonly ITailscaleApi _api;
    public EndpointAuthKeyService(ITailscaleApi api) => _api = api;

    public async Task<ApiResult> MintAsync(string token, IReadOnlyList<string> tags, TimeSpan? expiry = null, bool reusable = false, CancellationToken ct = default)
    {
        if (reusable) return new ApiResult(false, "refused: DeskGuest mints single-use endpoint auth keys only (D3) — a reusable key is a standing credential on an endpoint");
        var exp = expiry ?? DefaultExpiry;
        if (exp <= TimeSpan.Zero || exp > MaxExpiry)
            return new ApiResult(false, $"refused: auth key expiry must be within (0, 90 days]; asked for {exp.TotalDays:0.#}d");
        if (tags.Count == 0) return new ApiResult(false, "refused: an endpoint auth key must be tagged (the tag is its whole reach)");
        var cleanTags = new List<string>();
        foreach (var t in tags)
        {
            var tag = (t ?? "").Trim().ToLowerInvariant();
            if (!Regex.IsMatch(tag, "^tag:[a-z0-9][a-z0-9._-]{0,62}$"))
                return new ApiResult(false, $"refused: tag '{t}' is not a valid tag name — keys are minted only for validated tags");
            cleanTags.Add(tag);
        }
        return await _api.CreateAuthKeyAsync(token, cleanTags, singleUse: true, exp, ct);
    }
}

// ------------------------------------------------------------ the setup flow (D4/D28)

public enum MeshSetupStage
{
    NotStarted, Refused, AwaitingSignIn, Ready,
}

public sealed record MeshSetupState(MeshSetupStage Stage, string Detail, bool MobileCarveOut = false);

/// <summary>The D4 setup flow, as a state machine on DeskGuest's side
/// of the boundary. Steps, in order: role/platform gate → client
/// floor → kill switch (desktop) or carve-out (mobile operator)
/// → no SSH/Serve/Funnel → scoped credential → THE sign-in
/// boundary (provider's page; DeskGuest receives only completion) →
/// post-sign-in automation (token exchange, D12 policy through
/// the guard). Any failed step stops the flow and says why.</summary>
public sealed class MeshSetupService
{
    private readonly ITailscaleDaemonProbe _probe;
    private readonly ClientVersionGate _floor = new();
    private readonly StringBuilder _trail = new();

    // BD-SHARED-TRANSPORT F9: the former two-argument constructor
    // silently built the broker over a base64 "protector" and its
    // comment claimed Core would swap it later — Broker is
    // get-only, so it never could. That constructor is GONE: the
    // protector is a required construction input, and a setup
    // service that cannot protect the OAuth secret cannot exist.
    public MeshSetupService(ITailscaleDaemonProbe probe, ITailscaleApi api, ISecretProtector protector)
    {
        _probe = probe;
        Broker = new OAuthTokenBroker(protector, api);
        Policy = new PolicyGuard(api);
        AuthKeys = new EndpointAuthKeyService(api);
    }

    /// <summary>BD-SHARED-TRANSPORT F9: readiness re-verification
    /// for the mesh rung's per-connect recheck. Re-probes the
    /// daemon and re-runs the setup-time gates (client floor, kill
    /// switch on desktop, SSH/Serve/Funnel/conn25 off); any drift
    /// drops the service OUT of Ready (to Refused, by name) so a
    /// later connect sees the refusal, not a stale Ready.</summary>
    public bool ReverifyReadiness()
    {
        if (State.Stage != MeshSetupStage.Ready) return false;
        var facts = _probe.Probe();
        string? drift = null;
        if (!facts.ProbeReliable) drift = "the local Tailscale client could not be probed reliably at re-verification";
        else if (!_floor.TryAdmitQuiet(facts.InstalledVersion)) drift = $"client '{facts.InstalledVersion ?? "(unknown)"}' no longer meets the floor at re-verification";
        else if (facts.SshEnabled) drift = "Tailscale SSH was turned ON after setup";
        else if (facts.ServeEnabled) drift = "Tailscale Serve was turned ON after setup";
        else if (facts.FunnelEnabled) drift = "Tailscale Funnel was turned ON after setup";
        else if (facts.Conn25Used) drift = "conn25 came into use after setup";
        else if (!State.MobileCarveOut && facts.LogtailState != "disabled-no-logs")
            drift = $"the daemon's log pipeline reports '{facts.LogtailState}' at re-verification — the kill switch no longer holds (daemon restarted without TS_NO_LOGS_NO_SUPPORT?)";
        if (drift is null) return true;
        Refuse("mesh readiness drift detected after setup: " + drift + " — the rung stays refused until setup re-runs clean");
        return false;
    }

    public OAuthTokenBroker Broker { get; }
    public PolicyGuard Policy { get; }
    public EndpointAuthKeyService AuthKeys { get; }
    public MeshSetupState State { get; private set; } = new(MeshSetupStage.NotStarted, "setup has not run");
    public string Trail => _trail.ToString();

    private MeshSetupState Refuse(string why)
    {
        State = new MeshSetupState(MeshSetupStage.Refused, why);
        _trail.AppendLine("REFUSED: " + why);
        return State;
    }

    private void Note(string step) => _trail.AppendLine("ok: " + step);

    /// <summary>Runs every pre-sign-in step and stops AT the
    /// boundary. Returns AwaitingSignIn when DeskGuest's side is fully
    /// ready for the one human moment.</summary>
    public MeshSetupState RunPreSignIn(MeshPlatform platform, MeshRole role, bool mobileCarveOutAcknowledged = false)
    {
        // Role gate (D3 + TS-03): endpoints never get this rung.
        if (role == MeshRole.Endpoint)
            return Refuse("endpoints never sign in and never offer the mesh rung (D3) — an endpoint joins with an DeskGuest-minted auth key, not an account");
        var mobile = platform is MeshPlatform.Android or MeshPlatform.Ios;
        if (mobile && !mobileCarveOutAcknowledged)
            return Refuse("mobile carve-out not acknowledged: " + MeshHonesty.MobileCarveOutLabel);
        if (mobile) Note("mobile carve-out acknowledged (operator-personal-device only)");

        // Client floor + pin (T2 §7.1).
        var facts = _probe.Probe();
        if (!facts.ProbeReliable)
            return Refuse("the local Tailscale client could not be probed reliably — setup refuses rather than guess at the state of the kill switch, SSH, Serve, or Funnel");
        if (!_floor.Admit(facts.InstalledVersion, DateTimeOffset.UtcNow))
            return Refuse($"Tailscale client '{facts.InstalledVersion ?? "(unknown)"}' is below the ≥{TailscalePins.MinClientVersion} floor (Tailworm fixes) — the rung refuses older clients at setup and at join");
        Note(facts.InstalledVersion == TailscalePins.PinnedClientVersion
            ? $"client is the pinned {TailscalePins.PinnedClientVersion}"
            : $"client {facts.InstalledVersion} meets the ≥{TailscalePins.MinClientVersion} floor (pinned is {TailscalePins.PinnedClientVersion}; a delta audit governs any pin change)");

        // Kill switch (T2 §7.2/§7.3).
        if (!mobile)
        {
            var ks = KillSwitchGuard.VerifyDesktop(_probe);
            if (!ks.Ok) return Refuse(ks.Detail);
            Note(ks.Detail);
        }

        // No SSH / Serve / Funnel / conn25, ever (T2 §7.4).
        if (facts.SshEnabled) return Refuse("Tailscale SSH is enabled on this device — DeskGuest never enables it and setup will not proceed with it on (TS-10)");
        if (facts.ServeEnabled) return Refuse("Tailscale Serve is enabled on this device — DeskGuest never enables it and setup will not proceed with it on (TS-10)");
        if (facts.FunnelEnabled) return Refuse("Tailscale Funnel is enabled on this device — DeskGuest never enables it and setup will not proceed with it on (TS-10)");
        if (facts.Conn25Used) return Refuse("the conn25 app-connector feature is in use on this device — DeskGuest asserts it unused on this rung (Tailworm F4)");
        Note("Tailscale SSH, Serve, Funnel all off; conn25 unused");

        State = new MeshSetupState(MeshSetupStage.AwaitingSignIn,
            "DeskGuest's side is ready. " + MeshHonesty.SignInBoundaryLabel + " " + MeshHonesty.VendorLabel,
            MobileCarveOut: mobile);
        return State;
    }

    /// <summary>Cross the sign-in boundary and run the post-sign-in
    /// automation. <paramref name="signInMoment"/> is the
    /// provider's own page hosted in DeskGuest's frame: it returns only
    /// whether the person completed it. DeskGuest passes it nothing and
    /// receives no credential from it.</summary>
    public async Task<MeshSetupState> CompleteAfterSignInAsync(
        Func<Task<bool>> signInMoment, TailnetMapping mapping, DateTimeOffset now, CancellationToken ct = default)
    {
        if (State.Stage != MeshSetupStage.AwaitingSignIn)
            return Refuse("post-sign-in automation attempted before the pre-sign-in steps passed — the flow's order is part of its safety");
        bool completed;
        try { completed = await signInMoment(); }
        catch { completed = false; }
        if (!completed)
            return Refuse("the provider sign-in was not completed — setup stops here; nothing was configured and no credential was captured");
        Note("provider sign-in completed (DeskGuest received only the completion, never a credential)");

        var token = await Broker.GetTokenAsync(now, ct);
        if (!token.Ok) return Refuse("token exchange failed — setup stops: " + token.TokenOrDetail);
        Note("scoped OAuth token exchanged (1-hour)");

        string policy;
        try { policy = AclBuilder.Build(mapping); }
        catch (InvalidOperationException ex) { return Refuse(ex.Message); }
        var applied = await Policy.ApplyAsync(token.TokenOrDetail, policy, ct);
        if (!applied.Ok) return Refuse(applied.Detail);
        Note("D12 policy written through the guard: " + applied.Detail);

        State = new MeshSetupState(MeshSetupStage.Ready,
            "mesh rung set up: client floored, kill switch state per platform, no SSH/Serve/Funnel, scoped credentials only, D12 policy applied with a rollback copy. " + MeshHonesty.VendorLabel,
            MobileCarveOut: State.MobileCarveOut);
        return State;
    }
}

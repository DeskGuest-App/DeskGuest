namespace DeskGuest.Shared.Policy;

// =====================================================================
// FR-143 (owner-raised IT requirement, 2026-11-25; GitHub issue
// #44) — "Require HTTPS for agent connections" as TOTAL POLICY
// CONTROL: a feature toggle in FeatureToggleRegistry
// ("connections.https_only.enabled", directive FR-143, default ON)
// plus the pure lane-transport decision the Core's LaneHostManager
// applies at bind time and at request time.
//
// The truth this setting is built on (Step-1 evidence, recorded in
// the FR-143 lane record):
//  * Agent (MCP) traffic is served per lane on one port by
//    LaneHostManager. The home-network (LAN) lane is ALREADY
//    HTTPS-only by construction — TLS with the device's own
//    certificate, and without a certificate the lane does not
//    start. This setting does not create that posture and turning
//    it off does not remove it.
//  * The mesh listener (the device's private-mesh / company-hub
//    address — Tailscale, headscale and NetBird all present
//    100.64.0.0/10 addresses, so one lane host serves them all)
//    historically served plain HTTP inside the mesh's encrypted
//    (WireGuard) tunnel. THIS is the surface the setting governs:
//    ON serves it over HTTPS with the same device certificate
//    (the pin an agent receives at pairing is checked on every
//    connection); OFF restores the historical plain-HTTP serve.
//  * Device-to-device connections are a different protocol
//    (LanProtocol v2: X25519 + Ed25519 + AES-256-GCM, sealed end
//    to end on every rung — mesh, hub, direct, sealed relay,
//    Tor). They never travel as readable HTTP and this setting
//    does NOT change them; the registry description says so
//    rather than pretending otherwise.
//  * Loopback (this same computer) is EXEMPT by name: it never
//    leaves the machine, and the setting's copy names the
//    exemption instead of hiding it.
//
// The key is not §7.10 consent floor (it names none of presence,
// STOP, audit or consent — ConsentFloorGuard admits it; a test
// pins that). The agent channel may never set it: there is no MCP
// tool, IPC kind or mesh route that writes policy (policy arrives
// only as signed management-policy documents, RMM-07).
// =====================================================================

/// <summary>The TOTAL POLICY CONTROL keys for FR-143.</summary>
public static class HttpsOnlyPolicyKeys
{
    /// <summary>Feature toggle registered in FeatureToggleRegistry
    /// (directive FR-143, default ON). OFF restores plain HTTP on
    /// the mesh listener for older agents; the LAN lane stays
    /// HTTPS-only by construction either way.</summary>
    public const string FeatureToggle = "connections.https_only.enabled";
}

/// <summary>How one lane is to be served.</summary>
public enum LaneTransport
{
    /// <summary>Serve plain HTTP (the historical mesh behaviour,
    /// and loopback always).</summary>
    Http,
    /// <summary>Serve HTTPS with the device's host certificate.</summary>
    Https,
    /// <summary>Do not start the lane at all: policy demands HTTPS
    /// and no certificate is available — fail closed, never fall
    /// back to cleartext.</summary>
    RefuseStart,
}

/// <summary>The pure FR-143 decision: which transport a lane is
/// served over, and whether a plain-HTTP request that still
/// arrives (a policy flip landing before the rebind) is refused.
/// LaneHostManager applies it; the tests pin it.</summary>
public static class HttpsOnlyDecision
{
    public static bool IsLoopbackLane(string? laneName) =>
        string.Equals((laneName ?? "").Trim(), "loopback", StringComparison.OrdinalIgnoreCase);

    public static bool IsLanLane(string? laneName) =>
        string.Equals((laneName ?? "").Trim(), "Lan", StringComparison.OrdinalIgnoreCase);

    /// <summary>The transport a lane binds with.
    /// LAN → HTTPS always (by construction, policy-independent;
    /// the caller separately refuses a LAN start with no
    /// certificate, as it always has). Loopback → HTTP always
    /// (the named exemption). Any other lane (the mesh listener
    /// today): HTTPS when the setting is on — RefuseStart when on
    /// but no certificate is available — and HTTP when off.</summary>
    public static LaneTransport TransportFor(string? laneName, bool httpsOnlyEnabled, bool certificateAvailable)
    {
        if (IsLanLane(laneName)) return LaneTransport.Https;
        if (IsLoopbackLane(laneName)) return LaneTransport.Http;
        if (!httpsOnlyEnabled) return LaneTransport.Http;
        return certificateAvailable ? LaneTransport.Https : LaneTransport.RefuseStart;
    }

    /// <summary>Whether a request arriving as plain HTTP on this
    /// lane is refused under the setting: enforcement on, request
    /// not HTTPS, lane not loopback. (A LAN-lane request can never
    /// arrive as plain HTTP — the endpoint is TLS — so in practice
    /// this fires on the mesh listener in the window between a
    /// policy flip and the rebind it triggers.)</summary>
    public static bool RefusePlainHttp(string? laneName, bool requestIsHttps, bool httpsOnlyEnabled) =>
        httpsOnlyEnabled && !requestIsHttps && !IsLoopbackLane(laneName);
}

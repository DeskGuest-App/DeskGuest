using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// BD-WIN-CORE-3/F1 (the BUILD half) — MeshIdentityResolver: the
// authenticated mesh identity, wired through the v2 channel's
// authenticated device identity.
//
// The mesh lanes (tailnet + loopback) are a network boundary, not
// an identity. The identity the mesh client already holds is its
// PAIRING: the /pair exchange (the v2 channel) issued a per-pairing
// bearer token, host-bound to an intended agent name at mint time
// (PairingService — the exchanging client could not choose its name
// or its scopes). This resolver authenticates a mesh request the
// same way McpHandler authenticates an MCP call:
//
//   Authorization: Bearer <pairing token>
//     → PairingService.Authenticate (revoked/expired fail closed)
//     → the pairing's host-bound AgentName
//     → the UNIQUE live roster user with that display name across
//        all scopes (the BlockGActors.ResolveAiUser discipline:
//        duplicate names resolve to NOBODY, a suspended user
//        resolves to nobody)
//     → that user's id, which is the identity StreamService checks
//        session participation and floor ownership against.
//
// Anything else — no header, unknown/revoked/expired token, a name
// matching zero or several roster users — resolves to null, and
// every mesh verb fails closed on null. The client presents the
// token it already carries for the MCP channel; no new credential
// is minted for the mesh.
// =====================================================================

/// <summary>Resolves the authenticated roster user id behind a
/// mesh request's pairing bearer token. Null = unauthenticated.</summary>
public sealed class MeshIdentityResolver
{
    private readonly PairingService _pairings;
    private readonly RosterService _roster;

    public MeshIdentityResolver(PairingService pairings, RosterService roster)
    {
        _pairings = pairings ?? throw new ArgumentNullException(nameof(pairings));
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
    }

    /// <summary>Authenticate an Authorization header value
    /// ("Bearer &lt;token&gt;") to a roster user id, or null.</summary>
    public string? ResolveUserId(string? authorizationHeader)
    {
        const string prefix = "Bearer ";
        if (string.IsNullOrWhiteSpace(authorizationHeader) ||
            !authorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return null;
        var pairing = _pairings.Authenticate(authorizationHeader[prefix.Length..].Trim());
        if (pairing is null) return null;
        string? match = null;
        foreach (var scope in _roster.ListScopes())
        {
            foreach (var user in _roster.ListUsers(scope.Id))
            {
                if (user.Suspended) continue;
                if (!string.Equals(user.DisplayName, pairing.AgentName, StringComparison.OrdinalIgnoreCase)) continue;
                if (match is not null) return null; // ambiguous name — resolves to nobody
                match = user.Id;
            }
        }
        return match;
    }

    public bool IsAuthenticated(string? authorizationHeader) => ResolveUserId(authorizationHeader) is not null;
}

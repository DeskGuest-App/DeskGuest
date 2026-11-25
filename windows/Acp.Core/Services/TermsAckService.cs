using Acp.Shared.Audit;
using Acp.Shared.Security;

namespace Acp.Core.Services;

/// <summary>The outcome of one Terms acknowledgment attempt,
/// shaped so each transport surface (the protocol method, the
/// tool) renders it in its own envelope without re-deciding
/// anything: the decision — and its audit record — is made here,
/// once.</summary>
public enum TermsAckOutcome
{
    Acknowledged,
    RefusedMismatch,
    RefusedPairingInvalid,
}

public sealed record TermsAckResult(TermsAckOutcome Outcome, DateTimeOffset? AckUtc, string? RefusalMessage);

/// <summary>FR-134 / BUILD-PROGRAMME item (16): the ONE
/// acknowledgment operation behind both ack surfaces — the
/// protocol method (deskguest/terms_acknowledge, for clients
/// that speak raw protocol) and the standard tool
/// (terms_acknowledge, item (16) amendment 2026-11-25, for the
/// tool-surface hosts that cannot emit custom methods).
///
/// The rule is identical on both surfaces: the returned version
/// AND hash must equal the currently served bundle exactly — an
/// ack of any other text (an old version, a corrupted copy, a
/// guess) is refused and the refusal is audited, so the record
/// never shows an acknowledgment that did not happen. A correct
/// ack is written into the pairing store and into the audit
/// chain under the agent's own name with the version, the hash,
/// and the time — the item (15)/(16) acceptance record.</summary>
public sealed class TermsAckService
{
    private readonly PairingService _pairings;
    private readonly IAuditLog _audit;
    private readonly CoreState _state;
    private readonly TermsBundle? _terms;

    public TermsAckService(PairingService pairings, IAuditLog audit, CoreState state, TermsBundle? terms)
    {
        _pairings = pairings;
        _audit = audit;
        _state = state;
        _terms = terms;
    }

    /// <summary>The bundle an ack is judged against — null only
    /// in bare unit embedders with no Terms machinery wired.</summary>
    public TermsBundle? Terms => _terms;

    public TermsAckResult Acknowledge(Pairing pairing, string? version, string? hash)
    {
        if (_terms is null)
            throw new InvalidOperationException("terms acknowledgment attempted with no Terms bundle wired");
        if (!string.Equals(version, _terms.Version, StringComparison.Ordinal) ||
            !string.Equals(hash, _terms.Sha256, StringComparison.Ordinal))
        {
            try
            {
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "system", pairing.Id, pairing.AgentName,
                    null, null, null,
                    $"terms_ack_refused:agent returned version '{version ?? "(none)"}' sha256 '{hash ?? "(none)"}'; " +
                    $"this host serves Terms v{_terms.Version} sha256 {_terms.Sha256}",
                    "Agent", null));
            }
            catch { _state.NoteAuditWriteFailure(); }
            return new TermsAckResult(TermsAckOutcome.RefusedMismatch, null,
                $"terms acknowledgment refused: this host serves Terms v{_terms.Version} with sha256 {_terms.Sha256}. " +
                $"Read the full current text at {TermsBundle.ResourceUri} (resources/read) and acknowledge its exact version and hash.");
        }
        var (ok, ackUtc) = _pairings.RecordTermsAck(pairing.Id, _terms.Version, _terms.Sha256);
        if (!ok || ackUtc is null)
            return new TermsAckResult(TermsAckOutcome.RefusedPairingInvalid, null,
                "terms acknowledgment refused: this pairing is no longer valid");
        try
        {
            _audit.Append(new AuditEntry(ackUtc.Value, "system", pairing.Id, pairing.AgentName,
                null, null, null,
                $"terms_acknowledged:version={_terms.Version};sha256={_terms.Sha256}",
                "Agent", null));
        }
        catch { _state.NoteAuditWriteFailure(); }
        return new TermsAckResult(TermsAckOutcome.Acknowledged, ackUtc, null);
    }
}

using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

/// <summary>
/// RMM-07 data surface in the Core: the management-policy engine,
/// live. Policy documents arrive ONLY as RMM-03 signed commands
/// (class policy_delivery) — the endpoint verifies the customer's
/// signature before a document is even parsed, so a compromised hub
/// cannot deliver policy either. Every application, change and
/// refusal is a hash-chained audit event in the enterprise ledger.
///
/// Effective Policy is exposed as service methods (ComputeEffective
/// / IsEnabled) — the queryable model other features and later
/// surfaces consume. No UI here: product design is last in this
/// programme; functional surfaces only.
/// </summary>
public sealed class ManagementPolicyService
{
    private readonly ChainedAuditLog _audit;
    private readonly SignedCommandGate? _gate;
    private readonly Func<DateTimeOffset> _now;
    private readonly string? _storePath;
    private readonly object _storeGate = new();

    /// <summary>The policy engine. NOTE (D38 F3): this is public
    /// because in-process Core services and resolvers consume the
    /// engine directly (same trust domain as Core itself — there is
    /// no hub-reachable path to it; the hub's only policy path is
    /// ApplySignedDocument). The dangerous capabilities the review
    /// flagged are closed IN THE ENGINE, so they are closed on
    /// every path: group definitions cannot be redefined or widen
    /// to match-everything, and document admission always runs the
    /// consent-floor + revision checks.</summary>
    public ManagementPolicyEngine Engine { get; }

    /// <summary>D38 F10: named durability state of the policy
    /// store — "not persisted (no store path)", "fresh: …",
    /// "loaded: N document(s), M group(s)…", or "BROKEN: …". A
    /// restart must never SILENTLY clear signed policy back to
    /// registry defaults; when a store path is wired the state is
    /// persisted and restored, and a store that fails to load is
    /// named here and in the audit log.</summary>
    public string PolicyStoreState { get; private set; } = "not loaded yet";

    /// <param name="gate">The RMM-03 verify-gate. When null (no
    /// customer command key configured on this endpoint), signed
    /// policy delivery refuses — named, never silent.</param>
    /// <param name="storePath">D38 F10: when set, admitted
    /// documents, revision floors and group definitions persist to
    /// this file (temp+replace) and are restored at construction —
    /// policy survives a Core restart, and the revision floor with
    /// it. Null = in-memory only (unit rigs); CoreRuntime wires a
    /// real path.</param>
    public ManagementPolicyService(ChainedAuditLog audit, SignedCommandGate? gate,
        ManagementPolicyEngine? engine = null, Func<DateTimeOffset>? now = null,
        string? storePath = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _gate = gate;
        Engine = engine ?? new ManagementPolicyEngine();
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _storePath = storePath;
        if (_storePath is null)
            PolicyStoreState = "not persisted (no store path wired) — policy is in-memory only for this host";
        else
            LoadStore();
    }

    // ---- D38 F10: policy durability --------------------------------

    private sealed record PolicyStoreFile(List<string> Documents, List<GroupDefinition> Groups);

    private void LoadStore()
    {
        if (!File.Exists(_storePath))
        {
            PolicyStoreState = "fresh: no policy store file yet (first boot)";
            return;
        }
        try
        {
            var file = System.Text.Json.JsonSerializer.Deserialize<PolicyStoreFile>(File.ReadAllText(_storePath!))
                ?? throw new InvalidOperationException("policy store parsed to null");
            var docs = 0;
            foreach (var json in file.Documents ?? new List<string>())
            {
                var doc = ManagementPolicyDocument.FromCanonicalJson(json);
                if (doc is null) throw new InvalidOperationException("policy store carries an unparsable document");
                var verdict = Engine.AddDocument(doc);
                if (!verdict.Allowed) throw new InvalidOperationException($"policy store document '{doc.Id}' refused on restore: {verdict.Reason}");
                docs++;
            }
            var groups = 0;
            foreach (var group in file.Groups ?? new List<GroupDefinition>())
            {
                var verdict = Engine.AddGroup(group);
                if (!verdict.Allowed) throw new InvalidOperationException($"policy store group '{group.Id}' refused on restore: {verdict.Reason}");
                groups++;
            }
            PolicyStoreState = $"loaded: {docs} document(s), {groups} group(s) restored from disk — revision floors restored with them";
        }
        catch (Exception ex)
        {
            // Fail-closed naming, not silent default-fallback: the
            // state and the audit log both say policy did NOT
            // restore, so an operator never mistakes registry
            // defaults for the customer's signed policy.
            PolicyStoreState = $"BROKEN: policy store at '{_storePath}' did not load ({ex.GetType().Name}: {ex.Message}) — the engine starts EMPTY and registry defaults apply; this is named, never silent (D38 F10)";
            _audit.Append("policy_store_broken", "management-policy", PolicyStoreState, _now());
        }
    }

    private void PersistStore()
    {
        if (_storePath is null) return;
        lock (_storeGate)
        {
            try
            {
                var file = new PolicyStoreFile(
                    Engine.Documents.Select(d => d.ToCanonicalJson()).ToList(),
                    Engine.Groups.ToList());
                var raw = System.Text.Json.JsonSerializer.Serialize(file);
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_storePath))!);
                var tmp = _storePath + ".tmp";
                File.WriteAllText(tmp, raw);
                File.Move(tmp, _storePath, overwrite: true);
            }
            catch (Exception ex)
            {
                PolicyStoreState = $"BROKEN: policy store flush failed ({ex.GetType().Name}) — admitted policy is in memory only until the next successful flush (D38 F10)";
                _audit.Append("policy_store_broken", "management-policy", PolicyStoreState, _now());
            }
        }
    }

    /// <summary>Apply one policy document delivered as a signed
    /// command envelope. Verification (RMM-03) precedes parsing;
    /// consent-floor and revision refusals come from the engine;
    /// all outcomes are chained-audit events.</summary>
    public PolicyVerdict ApplySignedDocument(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured on this endpoint — signed policy delivery refuses (RMM-03)";
            _audit.Append("policy_refusal", "management-policy", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        var json = Encoding.UTF8.GetString(verdict.Payload!);
        var doc = ManagementPolicyDocument.FromCanonicalJson(json);
        if (doc is null)
        {
            const string reason = "signed policy payload did not parse as a policy document — refused";
            _audit.Append("policy_refusal", "management-policy", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return Admit(doc, "signed delivery");
    }

    /// <summary>Admit a document that arrived over an already-trusted
    /// local path (the enterprise bundle bridge at load). The
    /// engine's own refusals (consent floor, revisions) still apply,
    /// and the admission is audited as a policy change.</summary>
    public PolicyVerdict AdmitLocalDocument(ManagementPolicyDocument doc, string via) => Admit(doc, via);

    private PolicyVerdict Admit(ManagementPolicyDocument doc, string via)
    {
        var now = _now();
        var verdict = Engine.AddDocument(doc);
        if (verdict.Allowed)
        {
            _audit.Append("policy_applied", "management-policy",
                $"doc={doc.Id} level={doc.Level} target={doc.TargetId} revision={doc.Revision} settings={doc.Settings.Count} via={via}", now);
            PersistStore(); // D38 F10: an admitted document is durable before the call returns
        }
        else
            _audit.Append("policy_refusal", "management-policy",
                $"doc={doc.Id} via={via} reason={verdict.Reason}", now);
        return verdict;
    }

    /// <summary>Define a targeting group. The engine's admission
    /// discipline applies (no in-place redefinition, no
    /// match-everything rules — D38 F3); BOTH outcomes are chained
    /// audit events, and an admitted group is persisted with the
    /// policy store (D38 F10).</summary>
    public PolicyVerdict AddGroup(GroupDefinition group)
    {
        var verdict = Engine.AddGroup(group);
        if (verdict.Allowed)
        {
            _audit.Append("policy_changed", "management-policy",
                $"group defined: {group.Id} ({group.Name}) rules={group.Rules.Count}", _now());
            PersistStore();
        }
        else
            _audit.Append("policy_refusal", "management-policy",
                $"group={group.Id} reason={verdict.Reason}", _now());
        return verdict;
    }

    /// <summary>The Effective Policy view: the computed settings +
    /// provenance for one device, from its facts.</summary>
    public EffectivePolicy ComputeEffective(IDeviceFacts facts) => Engine.ComputeEffective(facts);

    /// <summary>THE TOTAL POLICY CONTROL query: is this feature
    /// enabled for this device, per registry default + policy?</summary>
    public bool IsEnabled(IDeviceFacts facts, string featureKey) => Engine.IsEnabled(facts, featureKey);
}

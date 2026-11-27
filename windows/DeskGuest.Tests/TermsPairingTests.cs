using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;
using Xunit;

namespace DeskGuest.Tests;

/// <summary>FR-134 / BUILD-PROGRAMME item (16): the Terms-at-pairing
/// machinery. The Tested-AI battery's leg 0 failed on the shipped
/// build because none of this existed (POST /pair carried no Terms,
/// initialize had no instructions, resources/list was -32601, and
/// no ack surface existed anywhere). These pins hold the shipped
/// shape: the bundle in the exchange, the pointer at initialize,
/// the permanent resource, the exact-hash ack, the session lock,
/// the re-lock on a Terms update, and the audit record — each
/// behaviour the battery's leg 0 will exercise live.</summary>
public class TermsPairingTests
{
    private static string Sha256Hex(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private static string Rpc(string method, string? paramsJson = null) =>
        paramsJson is null
            ? $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\"}}"
            : $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":{paramsJson}}}";

    private static string CallBody(string name) =>
        Rpc("tools/call", $"{{\"name\":\"{name}\",\"arguments\":{{}}}}");

    private static string CallBodyArgs(string name, string argsJson) =>
        Rpc("tools/call", $"{{\"name\":\"{name}\",\"arguments\":{argsJson}}}");

    private static string ToolAckBody(string version, string hash) =>
        CallBodyArgs(TermsBundle.AckToolName, $"{{\"terms_version\":\"{version}\",\"terms_sha256\":\"{hash}\"}}");

    private static string AckBody(string version, string hash) =>
        Rpc(TermsBundle.AckMethod, $"{{\"terms_version\":\"{version}\",\"terms_sha256\":\"{hash}\"}}");

    private sealed record Rig(
        McpHandler Handler, PairingService Pairings, Pairing Pairing, string Token,
        FileAuditLog Audit, SessionManager Sessions);

    private static Rig MakeRig(TermsBundle? terms, PairingService? pairings = null, SessionManager? sessions = null,
        IReadOnlySet<string>? scopes = null)
    {
        Pairing pairing; string token;
        if (pairings is null)
        {
            (pairings, pairing, token) = TestUtil.MakePairing(scopes ?? Scopes.All);
        }
        else
        {
            var code = pairings.CreatePairingCode("test-agent", TimeSpan.FromMinutes(5), scopes ?? Scopes.All);
            var exchange = pairings.ExchangeCode(code, "test-agent");
            Assert.NotNull(exchange);
            pairing = pairings.List().Single(p => p.Id == exchange!.PairingId);
            token = exchange.BearerToken;
        }
        sessions ??= new SessionManager();
        var state = new CoreState();
        var registry = new ToolRegistry();
        registry.Register(new SessionStartModule(sessions, state));
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        if (terms is not null)
            registry.Register(new TermsAcknowledgeModule(new TermsAckService(pairings, audit, state, terms)));
        var handler = new McpHandler(pairings, new PolicyEngine(), registry, audit, state, sessions,
            TestUtil.TempDir(), terms: terms);
        return new Rig(handler, pairings, pairing, token, audit, sessions);
    }

    private static async Task<string> Call(Rig rig, string body)
    {
        var resp = await rig.Handler.HandleAsync(body, $"Bearer {rig.Token}", new HashSet<string>(), default);
        Assert.Equal(200, resp.HttpStatus);
        return resp.Json!;
    }

    private static bool AuditHas(FileAuditLog audit, string outcomePrefix) =>
        audit.ReadTail(200).Any(e => e.Outcome.StartsWith(outcomePrefix, StringComparison.Ordinal));

    // ---------- the bundle itself ----------

    [Fact]
    public void Bundle_IsTheCompleteTerms_WithHashOfTheExactText()
    {
        var bundle = TermsBundleProvider.Current;
        Assert.Equal(TermsBundleProvider.CurrentVersion, bundle.Version);
        // The complete legal text — including the sections whose
        // absence once truncated the draft (the FR-134 repair):
        // a bundle missing its tail is exactly the failure this
        // machinery exists to make impossible.
        Assert.Contains("## 1. Who is publishing DeskGuest", bundle.Text);
        Assert.Contains("## 13. Liability", bundle.Text);
        Assert.Contains("## 20.", bundle.Text);
        Assert.Contains("US $100", bundle.Text);
        Assert.DoesNotContain("[truncated", bundle.Text);
        // The hash covers the exact served text, recomputed here
        // from the text itself — no second copy to disagree.
        Assert.Equal(Sha256Hex(bundle.Text), bundle.Sha256);
        // The code's version constant and the document's own
        // header agree (the Terms header records the same version).
        Assert.Contains($"Terms version {bundle.Version}", bundle.Text);
    }

    [Fact]
    public void Bundle_Rulebook_CarriesTheItem16Points()
    {
        var rulebook = TermsBundle.AgentRulebook;
        Assert.Contains("observe", rulebook);                       // what the scopes mean
        Assert.Contains("STOP IS ABSOLUTE", rulebook);              // STOP is absolute
        Assert.Contains("PRESENCE IS NON-NEGOTIABLE", rulebook);    // presence is non-negotiable
        Assert.Contains("NEVER WIDEN YOUR OWN ACCESS", rulebook);   // never widen / never self-pair
        Assert.Contains("pair yourself", rulebook);
        Assert.Contains("RECORDED UNDER YOUR NAME", rulebook);      // audited under its own name
        Assert.Contains("THE HONEST LIMIT", rulebook);              // the stated honest limit
    }

    // ---------- (a) the exchange carries the bundle ----------

    [Fact]
    public void PairExchange_CarriesTermsBundle_AndAuditsDelivery()
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var handler = new PairingHandler(pairings, audit, null, null, () => TermsBundleProvider.Current);
        var code = pairings.CreatePairingCode("chatgpt-test", TimeSpan.FromMinutes(5), Scopes.All);
        var (status, json) = handler.Handle($"{{\"code\":\"{code}\",\"agent_name\":\"chatgpt-test\"}}", "test-source");
        Assert.Equal(200, status);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        // The pre-FR-134 shape is intact for existing clients.
        Assert.True(root.TryGetProperty("pairing_id", out _));
        Assert.True(root.TryGetProperty("bearer_token", out _));
        Assert.True(root.TryGetProperty("lan_tls_pin", out _));
        var terms = root.GetProperty("terms");
        var bundle = TermsBundleProvider.Current;
        Assert.Equal(bundle.Version, terms.GetProperty("version").GetString());
        Assert.Equal(bundle.Sha256, terms.GetProperty("sha256").GetString());
        Assert.Equal(bundle.Text, terms.GetProperty("text").GetString());
        Assert.Equal(TermsBundle.AgentRulebook, terms.GetProperty("rulebook").GetString());
        Assert.Equal(TermsBundle.ResourceUri, terms.GetProperty("resource_uri").GetString());
        Assert.Equal(TermsBundle.AckMethod, terms.GetProperty("ack_method").GetString());
        Assert.True(terms.GetProperty("ack_required_before_session").GetBoolean());
        // (d): the delivery is in the audit chain under the agent's name.
        Assert.Contains(audit.ReadTail(50), e =>
            e.Outcome.StartsWith("terms_delivered", StringComparison.Ordinal) &&
            e.Outcome.Contains(bundle.Sha256) && e.AgentName == "chatgpt-test");
    }

    // ---------- the initialize pointer + the push ----------

    [Fact]
    public async Task Initialize_PointsAtTerms_AndPushEntersAudit()
    {
        var rig = MakeRig(TermsBundleProvider.Current);
        var json = await Call(rig, Rpc("initialize", "{\"clientInfo\":{\"name\":\"probe\"}}"));
        using var doc = JsonDocument.Parse(json);
        var result = doc.RootElement.GetProperty("result");
        var instructions = result.GetProperty("instructions").GetString()!;
        Assert.Contains(TermsBundle.ResourceUri, instructions);
        Assert.Contains(TermsBundle.AckMethod, instructions);
        Assert.Contains(TermsBundleProvider.Current.Sha256, instructions);
        Assert.True(result.GetProperty("capabilities").TryGetProperty("resources", out _));
        // The push: a not-yet-acked pairing connecting is told, and
        // the telling is audit-chained under its name.
        Assert.Contains(rig.Audit.ReadTail(50), e =>
            e.Outcome.StartsWith("terms_pending_ack", StringComparison.Ordinal) && e.AgentName == "test-agent");
    }

    // ---------- (e) the permanent resource ----------

    [Fact]
    public async Task Resources_ListAndRead_ServeTheFullTerms()
    {
        var rig = MakeRig(TermsBundleProvider.Current);
        var listJson = await Call(rig, Rpc("resources/list"));
        using (var doc = JsonDocument.Parse(listJson))
        {
            var resources = doc.RootElement.GetProperty("result").GetProperty("resources");
            var only = Assert.Single(resources.EnumerateArray());
            Assert.Equal(TermsBundle.ResourceUri, only.GetProperty("uri").GetString());
        }
        var readJson = await Call(rig, Rpc("resources/read", $"{{\"uri\":\"{TermsBundle.ResourceUri}\"}}"));
        using (var doc = JsonDocument.Parse(readJson))
        {
            var contents = doc.RootElement.GetProperty("result").GetProperty("contents");
            var only = Assert.Single(contents.EnumerateArray());
            Assert.Equal(TermsBundleProvider.Current.Text, only.GetProperty("text").GetString());
        }
        var unknown = await Call(rig, Rpc("resources/read", "{\"uri\":\"deskguest://other\"}"));
        Assert.Contains("-32602", unknown);
    }

    // ---------- (b) the ack and the session lock ----------

    [Fact]
    public async Task SessionStart_LockedUntilAck_ThenUnlocks_AndAckIsAudited()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        var locked = await Call(rig, CallBody("session_start"));
        Assert.Contains("terms_ack_required", locked);
        Assert.Null(rig.Sessions.Current);

        var ackJson = await Call(rig, AckBody(bundle.Version, bundle.Sha256));
        using (var doc = JsonDocument.Parse(ackJson))
        {
            var result = doc.RootElement.GetProperty("result");
            Assert.True(result.GetProperty("acknowledged").GetBoolean());
            Assert.Equal(bundle.Version, result.GetProperty("terms_version").GetString());
            Assert.Equal(bundle.Sha256, result.GetProperty("terms_sha256").GetString());
            Assert.True(result.TryGetProperty("acknowledged_utc", out _));
        }
        // The acceptance record: version + hash + timestamp, under
        // the agent's own name (item 15/16).
        var current = rig.Pairings.CurrentPairing(rig.Pairing.Id)!;
        Assert.True(current.HasCurrentTermsAck(bundle.Sha256));
        Assert.Equal(bundle.Version, current.TermsAckVersion);
        Assert.NotNull(current.TermsAckUtc);
        Assert.Contains(rig.Audit.ReadTail(50), e =>
            e.Outcome == $"terms_acknowledged:version={bundle.Version};sha256={bundle.Sha256}" &&
            e.AgentName == "test-agent");

        var started = await Call(rig, CallBody("session_start"));
        Assert.DoesNotContain("terms_ack_required", started);
        Assert.NotNull(rig.Sessions.Current);
    }

    [Fact]
    public async Task Ack_WrongHash_Refused_AndStillLocked()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        var refused = await Call(rig, AckBody(bundle.Version, new string('0', 64)));
        Assert.Contains("-32602", refused);
        Assert.Contains("terms acknowledgment refused", refused);
        Assert.False(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
        Assert.True(AuditHas(rig.Audit, "terms_ack_refused"));
        Assert.False(AuditHas(rig.Audit, "terms_acknowledged"));
        var locked = await Call(rig, CallBody("session_start"));
        Assert.Contains("terms_ack_required", locked);
    }

    [Fact]
    public async Task Ack_WrongVersion_Refused()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        var refused = await Call(rig, AckBody("9.9", bundle.Sha256));
        Assert.Contains("-32602", refused);
        Assert.False(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
    }

    // ---------- (c) a Terms update re-locks until re-ack ----------

    [Fact]
    public async Task TermsUpdate_ReLocksPairing_UntilReAckOfTheNewHash()
    {
        var v1 = TermsBundleProvider.Current;
        // ONE pairing (one bearer) across both Cores: the update
        // scenario is the same agent meeting a Core that now
        // serves new Terms.
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var sessions = new SessionManager();
        McpHandler HandlerFor(TermsBundle t)
        {
            var state = new CoreState();
            var registry = new ToolRegistry();
            registry.Register(new SessionStartModule(sessions, state));
            return new McpHandler(pairings, new PolicyEngine(), registry,
                TestUtil.AuditLog(TestUtil.TempDir()), state, sessions, TestUtil.TempDir(), terms: t);
        }
        async Task<string> Call2(McpHandler h, string body)
        {
            var resp = await h.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            Assert.Equal(200, resp.HttpStatus);
            return resp.Json!;
        }

        var coreA = HandlerFor(v1);
        await Call2(coreA, AckBody(v1.Version, v1.Sha256));
        var started = await Call2(coreA, CallBody("session_start"));
        Assert.DoesNotContain("terms_", started);
        Assert.NotNull(sessions.Current);
        sessions.Stop();

        // The update lands: a Core serving new Terms (new version,
        // new hash, full new text — never a diff).
        var v2Text = v1.Text + "\n\nTEST-ONLY ADDENDUM: these are the updated Terms.\n";
        var v2 = new TermsBundle("1.1", Sha256Hex(v2Text), v2Text, TermsBundle.AgentRulebook);
        var coreB = HandlerFor(v2);

        var locked = await Call2(coreB, CallBody("session_start"));
        Assert.Contains("terms_update_pending", locked);
        // The resource on the updated Core serves the NEW full text.
        var readJson = await Call2(coreB, Rpc("resources/read", $"{{\"uri\":\"{TermsBundle.ResourceUri}\"}}"));
        Assert.Contains("TEST-ONLY ADDENDUM", readJson);
        // Re-acking the OLD hash does not unlock against new Terms.
        var staleAck = await Call2(coreB, AckBody(v1.Version, v1.Sha256));
        Assert.Contains("-32602", staleAck);
        // Re-acking the new hash unlocks.
        var ack2 = await Call2(coreB, AckBody(v2.Version, v2.Sha256));
        Assert.Contains("\"acknowledged\":true", ack2);
        var started2 = await Call2(coreB, CallBody("session_start"));
        Assert.DoesNotContain("terms_update_pending", started2);
        Assert.NotNull(sessions.Current);
    }

    // ---------- persistence: the ack survives the store ----------

    [Fact]
    public async Task AckState_SurvivesStoreRoundTrip_AndLegacyStoresRestoreUnacked()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        await Call(rig, AckBody(bundle.Version, bundle.Sha256));
        var exported = rig.Pairings.ExportJson();

        var restored = new PairingService(new DevOnlyPassThroughProtector());
        Assert.Equal(1, restored.ImportJson(exported));
        var pairing = restored.List().Single();
        Assert.True(pairing.HasCurrentTermsAck(bundle.Sha256));
        Assert.Equal(bundle.Version, pairing.TermsAckVersion);
        Assert.NotNull(pairing.TermsAckUtc);

        // A pre-FR-134 store carries no Terms fields at all: it
        // restores as never-acknowledged (the pairing re-acks on
        // its next connection — the item (16) update flow).
        var legacy = "[{\"Id\":\"legacy1\",\"AgentName\":\"old-agent\",\"Scopes\":[\"observe\"]," +
            "\"CreatedUtc\":\"2026-11-01T00:00:00+00:00\",\"ExpiresUtc\":null,\"SessionTimeBoxSeconds\":null," +
            "\"Revoked\":false,\"TokenHash\":\"" + new string('a', 64) + "\",\"ProtectedAgentName\":\"old-agent\"}]";
        var legacySvc = new PairingService(new DevOnlyPassThroughProtector());
        Assert.Equal(1, legacySvc.ImportJson(legacy));
        var legacyPairing = legacySvc.List().Single();
        Assert.Null(legacyPairing.TermsAckHash);
        Assert.False(legacyPairing.HasCurrentTermsAck(bundle.Sha256));
    }

    // ---------- the card's truth: snapshot pending state ----------

    [Fact]
    public void Snapshot_PairingTermsPending_JudgedAgainstCurrentTerms()
    {
        var terms = new HostStateSnapshot.TermsFact("1.0", "currenthash");
        Pairing Mk(string? ackVersion, string? ackHash) => new(
            Id: "p1", AgentName: "Muse", Scopes: new HashSet<string> { Scopes.Observe },
            CreatedUtc: DateTimeOffset.Parse("2026-11-16T10:00:00Z"), ExpiresUtc: null,
            SessionTimeBox: null, Revoked: false,
            TermsAckVersion: ackVersion, TermsAckHash: ackHash, TermsAckUtc: DateTimeOffset.UtcNow);

        string BuildWith(Pairing p) => HostStateSnapshot.Build(
            coreVersion: "1.2.3.4", machineName: "HOST", port: 8741,
            runningLanes: Array.Empty<string>(), agentConnected: false, desktopUnlocked: true,
            userStopInForce: false,
            session: new HostStateSnapshot.SessionFacts(false, null, 0, 0, null),
            pairings: new[] { p }, gatedClasses: Array.Empty<string>(),
            approvedGates: new HashSet<string>(), auditTail: Array.Empty<AuditEntry>(),
            terms: terms);

        using (var doc = JsonDocument.Parse(BuildWith(Mk("0.9", "oldhash"))))
        {
            var row = doc.RootElement.GetProperty("pairings")[0];
            Assert.True(row.GetProperty("termsPending").GetBoolean());
            Assert.Equal("0.9", row.GetProperty("termsAckVersion").GetString());
            Assert.Equal("1.0", row.GetProperty("termsCurrentVersion").GetString());
        }
        using (var doc = JsonDocument.Parse(BuildWith(Mk("1.0", "currenthash"))))
        {
            var row = doc.RootElement.GetProperty("pairings")[0];
            Assert.False(row.GetProperty("termsPending").GetBoolean());
        }
        using (var doc = JsonDocument.Parse(BuildWith(Mk(null, null))))
        {
            var row = doc.RootElement.GetProperty("pairings")[0];
            Assert.True(row.GetProperty("termsPending").GetBoolean());
        }
    }

    // ---------- bare embeds keep the pre-FR-134 posture ----------

    [Fact]
    public async Task NoTermsWiring_NoInstructions_EmptyResources_NoLock()
    {
        var rig = MakeRig(null);
        var init = await Call(rig, Rpc("initialize"));
        Assert.DoesNotContain("instructions", init);
        var list = await Call(rig, Rpc("resources/list"));
        Assert.Contains("\"resources\":[]", list);
        var started = await Call(rig, CallBody("session_start"));
        Assert.DoesNotContain("terms_", started);
        Assert.NotNull(rig.Sessions.Current);
    }

    // ---------- the tool form (item (16) amendment, issue #25) ----------
    // The battery's run 4: a tool-surface host read the Terms and
    // hashed the exact text, but could not emit the custom method.
    // These pins hold the tool form to the method's exact contract.

    private static async Task<string[]> ToolNames(Rig rig)
    {
        var json = await Call(rig, Rpc("tools/list"));
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("result").GetProperty("tools")
            .EnumerateArray().Select(t => t.GetProperty("name").GetString()!).ToArray();
    }

    private static (bool IsError, string Text) ToolOutcome(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var result = doc.RootElement.GetProperty("result");
        var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
        return (result.GetProperty("isError").GetBoolean(), text);
    }

    [Fact]
    public async Task ToolAck_InCatalog_PreAck_ForObserveAndFullPairings()
    {
        var bundle = TermsBundleProvider.Current;
        // Full pairing: the tool is listed before any ack exists.
        var full = MakeRig(bundle);
        Assert.Contains(TermsBundle.AckToolName, await ToolNames(full));
        Assert.False(full.Pairings.CurrentPairing(full.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
        // Observe-only pairing (the battery's own shape): the tool
        // is in its catalog too — Observe scope is the floor every
        // preset holds, so no pairing is catalog-blind to the ack.
        var observe = MakeRig(bundle, scopes: Scopes.Preset("look_only"));
        Assert.Contains(TermsBundle.AckToolName, await ToolNames(observe));
        Assert.False(observe.Pairings.CurrentPairing(observe.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
    }

    [Fact]
    public async Task ToolAck_UnlocksSession_AndWritesTheSameAcceptanceRecord()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        var locked = await Call(rig, CallBody("session_start"));
        Assert.Contains("terms_ack_required", locked);
        Assert.Null(rig.Sessions.Current);

        var (isError, text) = ToolOutcome(await Call(rig, ToolAckBody(bundle.Version, bundle.Sha256)));
        Assert.False(isError);
        using (var doc = JsonDocument.Parse(text))
        {
            Assert.True(doc.RootElement.GetProperty("acknowledged").GetBoolean());
            Assert.Equal(bundle.Version, doc.RootElement.GetProperty("terms_version").GetString());
            Assert.Equal(bundle.Sha256, doc.RootElement.GetProperty("terms_sha256").GetString());
            Assert.True(doc.RootElement.TryGetProperty("acknowledged_utc", out _));
        }
        // The acceptance record is the method's record, byte for
        // byte: same store fields, same audit outcome string,
        // under the agent's own name.
        var current = rig.Pairings.CurrentPairing(rig.Pairing.Id)!;
        Assert.True(current.HasCurrentTermsAck(bundle.Sha256));
        Assert.Equal(bundle.Version, current.TermsAckVersion);
        Assert.NotNull(current.TermsAckUtc);
        Assert.Contains(rig.Audit.ReadTail(50), e =>
            e.Outcome == $"terms_acknowledged:version={bundle.Version};sha256={bundle.Sha256}" &&
            e.AgentName == "test-agent");

        var started = await Call(rig, CallBody("session_start"));
        Assert.DoesNotContain("terms_ack_required", started);
        Assert.NotNull(rig.Sessions.Current);
    }

    [Fact]
    public async Task ToolAck_WrongHash_RefusedRecorded_StillLocked()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        var (isError, text) = ToolOutcome(await Call(rig, ToolAckBody(bundle.Version, new string('0', 64))));
        Assert.True(isError);
        Assert.Contains("terms acknowledgment refused", text);
        Assert.Contains(bundle.Sha256, text);
        Assert.False(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
        Assert.True(AuditHas(rig.Audit, "terms_ack_refused"));
        Assert.False(AuditHas(rig.Audit, "terms_acknowledged"));
        var locked = await Call(rig, CallBody("session_start"));
        Assert.Contains("terms_ack_required", locked);
    }

    [Fact]
    public async Task ToolAck_UnservedHash_Refused_EvenWhenWellFormed()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle);
        // A real SHA-256 — of some OTHER text. The rule is exact
        // match against the served bundle, not hash-shapedness:
        // there is no way to ack a text this host is not serving.
        var otherHash = Sha256Hex("some other terms text entirely");
        var (isError, _) = ToolOutcome(await Call(rig, ToolAckBody(bundle.Version, otherHash)));
        Assert.True(isError);
        Assert.False(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
        // And a fabricated version with the true hash refuses too.
        var (isError2, _) = ToolOutcome(await Call(rig, ToolAckBody("9.9", bundle.Sha256)));
        Assert.True(isError2);
        Assert.False(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
    }

    [Fact]
    public async Task ToolAck_ObservePairing_AcksAndUnlocks()
    {
        var bundle = TermsBundleProvider.Current;
        var rig = MakeRig(bundle, scopes: Scopes.Preset("look_only"));
        var locked = await Call(rig, CallBody("session_start"));
        Assert.Contains("terms_ack_required", locked);
        var (isError, _) = ToolOutcome(await Call(rig, ToolAckBody(bundle.Version, bundle.Sha256)));
        Assert.False(isError);
        Assert.True(rig.Pairings.CurrentPairing(rig.Pairing.Id)!.HasCurrentTermsAck(bundle.Sha256));
        var started = await Call(rig, CallBody("session_start"));
        Assert.DoesNotContain("terms_ack_required", started);
        Assert.NotNull(rig.Sessions.Current);
    }

    [Fact]
    public async Task TermsUpdate_ReLocksToolAckedPairing_ToolReAckUnlocks()
    {
        var v1 = TermsBundleProvider.Current;
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var sessions = new SessionManager();
        McpHandler HandlerFor(TermsBundle t)
        {
            var state = new CoreState();
            var registry = new ToolRegistry();
            registry.Register(new SessionStartModule(sessions, state));
            var audit = TestUtil.AuditLog(TestUtil.TempDir());
            registry.Register(new TermsAcknowledgeModule(new TermsAckService(pairings, audit, state, t)));
            return new McpHandler(pairings, new PolicyEngine(), registry,
                audit, state, sessions, TestUtil.TempDir(), terms: t);
        }
        async Task<string> Call2(McpHandler h, string body)
        {
            var resp = await h.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            Assert.Equal(200, resp.HttpStatus);
            return resp.Json!;
        }

        // Ack v1 THROUGH THE TOOL on the first Core; session opens.
        var coreA = HandlerFor(v1);
        var (errA, _) = ToolOutcome(await Call2(coreA, ToolAckBody(v1.Version, v1.Sha256)));
        Assert.False(errA);
        var started = await Call2(coreA, CallBody("session_start"));
        Assert.DoesNotContain("terms_", started);
        Assert.NotNull(sessions.Current);
        sessions.Stop();

        // The update lands. A tool-acked pairing re-locks exactly
        // like a method-acked one.
        var v2Text = v1.Text + "\n\nTEST-ONLY ADDENDUM: these are the updated Terms.\n";
        var v2 = new TermsBundle("1.1", Sha256Hex(v2Text), v2Text, TermsBundle.AgentRulebook);
        var coreB = HandlerFor(v2);
        var locked = await Call2(coreB, CallBody("session_start"));
        Assert.Contains("terms_update_pending", locked);
        // The tool cannot ack the OLD hash against the new Terms.
        var (errStale, _) = ToolOutcome(await Call2(coreB, ToolAckBody(v1.Version, v1.Sha256)));
        Assert.True(errStale);
        // The tool ack of the NEW hash unlocks.
        var (errB, _) = ToolOutcome(await Call2(coreB, ToolAckBody(v2.Version, v2.Sha256)));
        Assert.False(errB);
        var started2 = await Call2(coreB, CallBody("session_start"));
        Assert.DoesNotContain("terms_update_pending", started2);
        Assert.NotNull(sessions.Current);
    }
}

using Acp.Core;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Shared.Audit;
using Acp.Shared.Ipc;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>W97 / S09(b) — the AI connection-path control pins.
/// The policy is a security control: a pairing restricted to a
/// subset must NOT connect over an excluded rung (proven at the
/// real choke point, McpHandler, and at the pairing-exchange
/// door), a manual pin binds exactly, and a restriction NEVER
/// silently widens (FilterOrder only ever narrows; a subset with
/// no working path yields an empty order, not the full menu).
/// Changes AND refusals are audited at the Core; the setting is
/// bound at mint (C1) and changeable only through the store's
/// one write, from the laptop-UI consent channel.</summary>
public class W97ConnectionPathTests
{
    private static HashSet<string> Set(params string[] s) => new(s);

    private static ConnectionPathSetting Restricted(params string[] rungs) =>
        new(ConnectionMode.AutoRestricted, Set(rungs));

    private static ConnectionPathSetting Manual(string pin) =>
        new(ConnectionMode.Manual, null, pin);

    private sealed class PlainProtector : ISecretProtector
    {
        public string Name => "plain-test";
        public bool IsRealProtection => false;
        public string Protect(string plain) => plain;
        public string Unprotect(string protectedValue) => protectedValue;
    }

    private static PairingService NewService(out string token, ConnectionPathSetting? connection = null)
    {
        var svc = new PairingService(new PlainProtector());
        var code = svc.CreatePairingCode("w97-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"), connection);
        var ex = svc.ExchangeCode(code, "w97-agent")!;
        token = ex.BearerToken;
        return svc;
    }

    // ---- policy semantics ---------------------------------------

    [Fact]
    public void Allows_Auto_AnyRealRung_ButNeverAnEmptyClaim()
    {
        Assert.True(ConnectionPathPolicy.Allows(null, "mesh"));
        Assert.True(ConnectionPathPolicy.Allows(ConnectionPathSetting.DefaultAuto, "tor"));
        Assert.False(ConnectionPathPolicy.Allows(null, ""));
        Assert.False(ConnectionPathPolicy.Allows(null, null));
    }

    [Fact]
    public void Allows_Restricted_OnlyTheSubset()
    {
        var s = Restricted("mesh", "lan");
        Assert.True(ConnectionPathPolicy.Allows(s, "mesh"));
        Assert.True(ConnectionPathPolicy.Allows(s, "LAN")); // case-insensitive rung ids
        Assert.False(ConnectionPathPolicy.Allows(s, "tor"));
        Assert.False(ConnectionPathPolicy.Allows(s, "ownpath"));
        Assert.False(ConnectionPathPolicy.Allows(s, "loopback"));
    }

    [Fact]
    public void Allows_Manual_OnlyThePin()
    {
        var s = Manual("lan");
        Assert.True(ConnectionPathPolicy.Allows(s, "lan"));
        Assert.False(ConnectionPathPolicy.Allows(s, "mesh"));
        Assert.False(ConnectionPathPolicy.Allows(Manual(""), "mesh")); // a pin-less manual allows nothing
    }

    [Fact]
    public void FilterOrder_NarrowsPreservingOrder_NeverWidens()
    {
        var full = new[] { "mesh", "lan", "hub", "tor" };
        Assert.Equal(full, ConnectionPathPolicy.FilterOrder(full, null));
        Assert.Equal(new[] { "lan", "tor" }, ConnectionPathPolicy.FilterOrder(full, Restricted("tor", "lan")));
        Assert.Equal(new[] { "hub" }, ConnectionPathPolicy.FilterOrder(full, Manual("hub")));
        // A subset/pin with NO rung in the order stays empty — the
        // truthful "no working path in the allowed set", never the menu.
        Assert.Empty(ConnectionPathPolicy.FilterOrder(full, Restricted("ownpath")));
        Assert.Empty(ConnectionPathPolicy.FilterOrder(full, Manual("ipv6")));
        Assert.Empty(ConnectionPathPolicy.FilterOrder(full, Restricted()));
    }

    [Fact]
    public void Validate_RefusesEmptySubset_PinlessManual_UnknownRungs()
    {
        Assert.Null(ConnectionPathPolicy.Validate(ConnectionPathSetting.DefaultAuto));
        Assert.Null(ConnectionPathPolicy.Validate(Restricted("mesh")));
        Assert.Null(ConnectionPathPolicy.Validate(Manual("tor")));
        Assert.Contains("at least one", ConnectionPathPolicy.Validate(Restricted()));
        Assert.Contains("one pinned path", ConnectionPathPolicy.Validate(new ConnectionPathSetting(ConnectionMode.Manual)));
        Assert.Contains("unknown transport", ConnectionPathPolicy.Validate(Restricted("carrier-pigeon")));
        Assert.Contains("unknown transport", ConnectionPathPolicy.Validate(Manual("smoke-signal")));
        Assert.NotNull(ConnectionPathPolicy.Validate(null));
    }

    [Fact]
    public void RungForLane_MapsTheHostsRealLanes()
    {
        Assert.Equal("mesh", ConnectionPathPolicy.RungForLane("Tailscale"));
        Assert.Equal("lan", ConnectionPathPolicy.RungForLane("Lan"));
        Assert.Equal("loopback", ConnectionPathPolicy.RungForLane("loopback"));
    }

    [Fact]
    public void Parse_RoundTripsTheWireShape_AndRefusesUnknownModes()
    {
        var s = ConnectionPathPolicy.Parse("restricted", new[] { "Mesh", "lan" }, null)!;
        Assert.Equal(ConnectionMode.AutoRestricted, s.Mode);
        Assert.True(ConnectionPathPolicy.Allows(s, "mesh"));
        var m = ConnectionPathPolicy.Parse("manual", null, "TOR")!;
        Assert.Equal("tor", m.PinOrNull);
        Assert.Null(ConnectionPathPolicy.Parse("whatever", null, null));
    }

    // ---- the store: mint binding, one write, persistence --------

    [Fact]
    public void Mint_BindsTheSetting_TheExchangeCarriesIt()
    {
        var svc = NewService(out _, Restricted("lan"));
        var pairing = svc.List().Single();
        Assert.Equal(ConnectionMode.AutoRestricted, pairing.EffectiveConnection.Mode);
        Assert.False(ConnectionPathPolicy.Allows(pairing.EffectiveConnection, "mesh"));
    }

    [Fact]
    public void Mint_WithAnInvalidSetting_Throws_NoCodeIsBound()
    {
        var svc = new PairingService(new PlainProtector());
        Assert.Throws<ArgumentException>(() =>
            svc.CreatePairingCode("w97-agent", TimeSpan.FromMinutes(5), null, Restricted()));
    }

    [Fact]
    public void UpdateConnectionPath_Validates_AndNormalizes()
    {
        var svc = NewService(out _);
        var id = svc.List().Single().Id;
        var (ok, _, old) = svc.UpdateConnectionPath(id, Manual("LAN"));
        Assert.True(ok);
        Assert.Equal(ConnectionMode.Auto, old!.Mode);
        var now = svc.List().Single().EffectiveConnection;
        Assert.Equal(ConnectionMode.Manual, now.Mode);
        Assert.Equal("lan", now.PinOrNull);
        // refusals: empty subset, unknown pairing, revoked pairing
        Assert.False(svc.UpdateConnectionPath(id, Restricted()).Ok);
        Assert.False(svc.UpdateConnectionPath("nope", Manual("lan")).Ok);
        svc.Revoke(id);
        Assert.False(svc.UpdateConnectionPath(id, Manual("lan")).Ok);
        // and the refused proposals changed nothing
        Assert.Equal("lan", svc.List().Single().EffectiveConnection.PinOrNull);
    }

    [Fact]
    public void Setting_PersistsAcrossStoreRoundTrip()
    {
        var svc = NewService(out _);
        var id = svc.List().Single().Id;
        svc.UpdateConnectionPath(id, Restricted("mesh", "tor"));
        var json = svc.ExportJson();
        var svc2 = new PairingService(new PlainProtector());
        svc2.ImportJson(json);
        var restored = svc2.List().Single().EffectiveConnection;
        Assert.Equal(ConnectionMode.AutoRestricted, restored.Mode);
        Assert.True(ConnectionPathPolicy.Allows(restored, "tor"));
        Assert.False(ConnectionPathPolicy.Allows(restored, "lan"));
    }

    [Fact]
    public void PreW97Store_RestoresAsAuto()
    {
        // A store written before the policy existed: no connection
        // fields at all. It must restore as AUTO, not as a lockout.
        var svc = NewService(out _);
        var json = svc.ExportJson();
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var row = doc.RootElement[0];
        var legacy = System.Text.Json.JsonSerializer.Serialize(new[]
        {
            new
            {
                Id = row.GetProperty("Id").GetString(),
                AgentName = row.GetProperty("AgentName").GetString(),
                Scopes = row.GetProperty("Scopes").EnumerateArray().Select(e => e.GetString()).ToArray(),
                CreatedUtc = row.GetProperty("CreatedUtc").GetDateTimeOffset(),
                ExpiresUtc = (DateTimeOffset?)null,
                SessionTimeBoxSeconds = (double?)null,
                Revoked = false,
                TokenHash = row.GetProperty("TokenHash").GetString(),
                ProtectedAgentName = row.GetProperty("ProtectedAgentName").GetString(),
            },
        });
        var svc2 = new PairingService(new PlainProtector());
        svc2.ImportJson(legacy);
        Assert.Equal(ConnectionMode.Auto, svc2.List().Single().EffectiveConnection.Mode);
    }

    [Fact]
    public void LastConnection_OnlyMovesOnANotedArrival()
    {
        var svc = NewService(out _);
        var id = svc.List().Single().Id;
        Assert.Null(svc.LastConnection(id));
        svc.NoteConnection(id, "mesh");
        Assert.Equal("mesh", svc.LastConnection(id)!.Value.Rung);
        svc.NoteConnection(id, "");
        Assert.Equal("mesh", svc.LastConnection(id)!.Value.Rung);
    }

    // ---- the choke point: real enforcement at McpHandler --------

    private (McpHandler Handler, PairingService Svc, string Token, FileAuditLog Audit) ChokeSetup(ConnectionPathSetting setting)
    {
        var svc = new PairingService(new PlainProtector());
        var code = svc.CreatePairingCode("w97-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"), setting);
        var ex = svc.ExchangeCode(code, "w97-agent")!;
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var handler = new McpHandler(svc, new PolicyEngine(), new ToolRegistry(), audit,
            new CoreState(), new SessionManager(), TestUtil.TempDir());
        return (handler, svc, ex.BearerToken, audit);
    }

    private static string Ping(string token) =>
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

    [Fact]
    public async Task ChokePoint_RestrictedPairing_RefusedOnExcludedRung_AllowedOnIncluded()
    {
        var (handler, svc, token, audit) = ChokeSetup(Restricted("lan"));
        var id = svc.List().Single().Id;

        var refused = await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "mesh");
        Assert.Equal(401, refused.HttpStatus);
        Assert.Contains("may not connect over this path", refused.Json);
        // the refusal is audited, and the current-rung label did NOT move
        Assert.Contains(audit.ReadTail(50), e => e.Outcome.Contains("pairing_connection_refused"));
        Assert.Null(svc.LastConnection(id));

        var allowed = await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "lan");
        Assert.Equal(200, allowed.HttpStatus);
        Assert.Equal("lan", svc.LastConnection(id)!.Value.Rung);
    }

    [Fact]
    public async Task ChokePoint_ManualPin_BindsExactly()
    {
        var (handler, _, token, _) = ChokeSetup(Manual("mesh"));
        Assert.Equal(401, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "lan")).HttpStatus);
        Assert.Equal(200, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "mesh")).HttpStatus);
    }

    [Fact]
    public async Task ChokePoint_AutoPairing_ConnectsOnEveryLane()
    {
        var (handler, _, token, _) = ChokeSetup(ConnectionPathSetting.DefaultAuto);
        foreach (var rung in new[] { "mesh", "lan", "loopback" })
            Assert.Equal(200, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, rung)).HttpStatus);
    }

    [Fact]
    public async Task ChokePoint_RestrictionAppliedLater_BitesTheNextRequest()
    {
        // The owner tightens the setting on the card; the pairing's
        // EXISTING token stops working over the excluded rung at
        // once — no re-pairing, no token rotation.
        var (handler, svc, token, _) = ChokeSetup(ConnectionPathSetting.DefaultAuto);
        var id = svc.List().Single().Id;
        Assert.Equal(200, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "mesh")).HttpStatus);
        Assert.True(svc.UpdateConnectionPath(id, Restricted("lan")).Ok);
        Assert.Equal(401, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "mesh")).HttpStatus);
        Assert.Equal(200, (await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, "lan")).HttpStatus);
    }

    [Fact]
    public async Task EventStream_RefusedOnExcludedRung()
    {
        var (handler, _, token, _) = ChokeSetup(Restricted("lan"));
        handler.Events = new AgentEventBus(new EventSubscriptionStore());
        var refused = await handler.HandleEventStreamAsync($"Bearer {token}",
            (_, _) => Task.CompletedTask, new CancellationTokenSource(50).Token, 0, "mesh");
        Assert.False(refused);
    }

    // ---- the exchange door --------------------------------------

    [Fact]
    public void ExchangeDoor_CodePinnedAwayFromArrivalLane_RefusesWithoutConsuming()
    {
        var svc = new PairingService(new PlainProtector());
        var code = svc.CreatePairingCode("w97-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"), Manual("lan"));
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var door = new PairingHandler(svc, audit);
        var body = System.Text.Json.JsonSerializer.Serialize(new { code, agent_name = "w97-agent" });

        var (status, _) = door.Handle(body, "test-source", "mesh");
        Assert.Equal(403, status);
        Assert.Contains(audit.ReadTail(50), e => e.Outcome.Contains("pairing_exchange_refused_by_path"));
        Assert.Empty(svc.List()); // no pairing was born over the excluded path

        // the code is still alive for its allowed path
        var (okStatus, json) = door.Handle(body, "test-source", "lan");
        Assert.Equal(200, okStatus);
        Assert.Single(svc.List());
        Assert.Equal("lan", svc.LastConnection(svc.List().Single().Id)!.Value.Rung);
    }

    // ---- W107 (C5): corrupt restore fails CLOSED ----------------

    /// <summary>Rebuild a store JSON with the connection fields
    /// replaced — the hand-edited / corrupted store shape.</summary>
    private static (string Json, string Token) StoreJsonWithToken(string? mode, string[]? rungs, string? pin)
    {
        var svc = NewService(out var token);
        var json = svc.ExportJson();
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var row = doc.RootElement[0];
        var serialized = System.Text.Json.JsonSerializer.Serialize(new[]
        {
            new
            {
                Id = row.GetProperty("Id").GetString(),
                AgentName = row.GetProperty("AgentName").GetString(),
                Scopes = row.GetProperty("Scopes").EnumerateArray().Select(e => e.GetString()).ToArray(),
                CreatedUtc = row.GetProperty("CreatedUtc").GetDateTimeOffset(),
                ExpiresUtc = (DateTimeOffset?)null,
                SessionTimeBoxSeconds = (double?)null,
                Revoked = false,
                TokenHash = row.GetProperty("TokenHash").GetString(),
                ProtectedAgentName = row.GetProperty("ProtectedAgentName").GetString(),
                ConnectionMode = mode,
                ConnectionRungs = rungs,
                ConnectionPin = pin,
            },
        });
        return (serialized, token);
    }

    private static string StoreJsonWith(string? mode, string[]? rungs, string? pin) =>
        StoreJsonWithToken(mode, rungs, pin).Json;

    [Fact]
    public void CorruptRestricted_UnknownRung_RestoresFailClosed_NotAuto()
    {
        // W107 (W106-verified C5): a PRESENT restricted record with
        // one unknown rung is corruption, not a migration — it must
        // NOT restore as AUTO (the pre-W107 fail-open widening).
        var svc = new PairingService(new PlainProtector());
        svc.ImportJson(StoreJsonWith("restricted", new[] { "lan", "carrier-pigeon" }, null));
        var pairing = svc.List().Single();
        Assert.True(pairing.ConnectionNeedsAttention);
        Assert.Equal(ConnectionMode.CorruptRefused, pairing.EffectiveConnection.Mode);
        // refused on EVERY rung, including the ones it named
        foreach (var rung in new[] { "mesh", "lan", "hub", "ipv6", "ownpath", "tor", "loopback" })
            Assert.False(ConnectionPathPolicy.Allows(pairing.EffectiveConnection, rung), rung);
        Assert.Empty(ConnectionPathPolicy.FilterOrder(new[] { "mesh", "lan" }, pairing.EffectiveConnection));
        // the surface description says needs-attention, never AUTO
        var describe = ConnectionPathPolicy.Describe(pairing.EffectiveConnection);
        Assert.Contains("Needs attention", describe);
        Assert.DoesNotContain("Auto — any working path", describe);
    }

    [Fact]
    public void CorruptManual_MissingPin_AndBadMode_RestoreFailClosed()
    {
        var svc = new PairingService(new PlainProtector());
        svc.ImportJson(StoreJsonWith("manual", null, null)); // manual without its pin
        Assert.Equal(ConnectionMode.CorruptRefused, svc.List().Single().EffectiveConnection.Mode);

        var svc2 = new PairingService(new PlainProtector());
        svc2.ImportJson(StoreJsonWith("sideways", new[] { "lan" }, null)); // unparseable mode
        Assert.Equal(ConnectionMode.CorruptRefused, svc2.List().Single().EffectiveConnection.Mode);
    }

    [Fact]
    public void CorruptRecord_ExportPreservesOriginalFields_NeverOverwritesWithAuto()
    {
        // The permanence half of C5: an export (the next store
        // save) must write the corrupt fields back verbatim, not
        // launder them into a chosen-looking AUTO.
        var svc = new PairingService(new PlainProtector());
        svc.ImportJson(StoreJsonWith("restricted", new[] { "lan", "carrier-pigeon" }, null));
        var exported = svc.ExportJson();
        using var doc = System.Text.Json.JsonDocument.Parse(exported);
        var row = doc.RootElement[0];
        Assert.Equal("restricted", row.GetProperty("ConnectionMode").GetString());
        Assert.Contains("carrier-pigeon",
            row.GetProperty("ConnectionRungs").EnumerateArray().Select(e => e.GetString()).ToArray());
        // and a re-import of that export is STILL fail-closed
        var svc2 = new PairingService(new PlainProtector());
        svc2.ImportJson(exported);
        Assert.Equal(ConnectionMode.CorruptRefused, svc2.List().Single().EffectiveConnection.Mode);
    }

    [Fact]
    public void CorruptRecord_OwnerReset_RepairsAndClearsQuarantine()
    {
        var svc = new PairingService(new PlainProtector());
        svc.ImportJson(StoreJsonWith("restricted", new[] { "bogus-rung" }, null));
        var pairing = svc.List().Single();
        Assert.True(pairing.ConnectionNeedsAttention);
        var (ok, _, old) = svc.UpdateConnectionPath(pairing.Id, Restricted("lan"));
        Assert.True(ok);
        Assert.Equal(ConnectionMode.CorruptRefused, old!.Mode); // the audit trail sees what was repaired
        var repaired = svc.List().Single();
        Assert.False(repaired.ConnectionNeedsAttention);
        Assert.True(ConnectionPathPolicy.Allows(repaired.EffectiveConnection, "lan"));
        Assert.False(ConnectionPathPolicy.Allows(repaired.EffectiveConnection, "mesh"));
        // the repaired setting now exports as itself
        using var doc = System.Text.Json.JsonDocument.Parse(svc.ExportJson());
        Assert.Equal("AutoRestricted", doc.RootElement[0].GetProperty("ConnectionMode").GetString());
    }

    [Fact]
    public async Task CorruptPairing_ChokePoint_RefusesEveryRung_AndAudits()
    {
        var (json, token) = StoreJsonWithToken("restricted", new[] { "lan", "bogus-rung" }, null);
        var svc = new PairingService(new PlainProtector());
        svc.ImportJson(json);
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var handler = new McpHandler(svc, new PolicyEngine(), new ToolRegistry(), audit,
            new CoreState(), new SessionManager(), TestUtil.TempDir());
        // even the rung the corrupt record NAMED is refused
        foreach (var rung in new[] { "mesh", "lan", "loopback" })
        {
            var refused = await handler.HandleAsync(Ping(token), $"Bearer {token}", new HashSet<string>(), default, rung);
            Assert.Equal(401, refused.HttpStatus);
        }
        Assert.Contains(audit.ReadTail(50), e => e.Outcome.Contains("pairing_connection_refused"));
        Assert.Null(svc.LastConnection(svc.List().Single().Id)); // no arrival was ever noted
    }

    [Fact]
    public async Task EventStream_MidStreamRestriction_ClosesTheLiveStream()
    {
        // W107 (C5 mid-stream half): the stream attached under AUTO
        // on mesh; the owner restricts the pairing to LAN only —
        // the LIVE stream must close on the re-check cadence, not
        // keep delivering until reconnect.
        var (handler, svc, token, audit) = ChokeSetup(ConnectionPathSetting.DefaultAuto);
        handler.Events = new AgentEventBus(new EventSubscriptionStore());
        var id = svc.List().Single().Id;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var stream = handler.HandleEventStreamAsync($"Bearer {token}",
            (_, _) => Task.CompletedTask, cts.Token, 0, "mesh");
        await Task.Delay(300); // attach + first cycles under AUTO
        Assert.False(stream.IsCompleted);
        Assert.True(svc.UpdateConnectionPath(id, Restricted("lan")).Ok);
        var finished = await Task.WhenAny(stream, Task.Delay(TimeSpan.FromSeconds(20)));
        Assert.Same(stream, finished); // closed by the re-check, not by the 30 s token
        Assert.True(await stream);
        Assert.Contains(audit.ReadTail(50), e => e.Outcome.Contains("pairing_connection_refused"));
    }

    [Fact]
    public void CorruptRefused_IsNotAProposableSetting()
    {
        Assert.NotNull(ConnectionPathPolicy.Validate(ConnectionPathSetting.CorruptRefusedSetting));
        Assert.Null(ConnectionPathPolicy.Parse("corruptrefused", null, null));
        var svc = NewService(out _);
        var id = svc.List().Single().Id;
        Assert.False(svc.UpdateConnectionPath(id, ConnectionPathSetting.CorruptRefusedSetting).Ok);
    }

    // ---- wiring / surface source pins ----------------------------

    private static string SrcDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AcpWindows.slnx")))
            dir = dir.Parent;
        return dir!.FullName;
    }

    private static string ReadSrc(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { SrcDir() }.Concat(parts).ToArray()));

    [Fact]
    public void Ipc_PairingConnection_IsAConsentKind()
    {
        Assert.True(IpcConsent.IsConsentKind(IpcKinds.PairingConnection));
    }

    [Fact]
    public void Enforcement_LaneHostManager_HandsTheArrivalRungToBothHandlers()
    {
        var lanes = ReadSrc("Acp.Core", "Services", "LaneHostManager.cs");
        Assert.Contains("ConnectionPathPolicy.RungForLane", lanes);
        Assert.Contains("arrivalRung", lanes);
        var handler = ReadSrc("Acp.Core", "Mcp", "McpHandler.cs");
        Assert.Contains("PathAllowed", handler);
        Assert.Contains("pairing_connection_refused", handler);
        Assert.Contains("PeekCodeConnection", handler);
    }

    [Fact]
    public void Core_ApplyPairingConnection_AuditsChangeAndRefusal()
    {
        var core = ReadSrc("Acp.Core", "CoreRuntime.cs");
        Assert.Contains("pairing_connection_via_agent", core);
        Assert.Contains("pairing_connection_refused_via_agent", core);
        Assert.Contains("Pairings.UpdateConnectionPath", core);
        Assert.Contains("IpcKinds.PairingConnection", core);
    }

    [Fact]
    public void Surface_CardBesideTheSlider_CurrentRung_ThreeModes()
    {
        var page = ReadSrc("Acp.SessionAgent", "MainWindow.Access.cs");
        Assert.Contains("BuildConnectionCard", page);
        Assert.Contains("How this helper connects", page);
        Assert.Contains("Connected now over", page);           // the honest current-rung label
        Assert.Contains("IpcKinds.PairingConnection", page);   // the one write path
        Assert.Contains("ConnectionPathPolicy.Rungs", page);   // real transport names
        var main = ReadSrc("Acp.SessionAgent", "MainWindow.xaml.cs");
        Assert.Contains("How this helper may connect", main);  // the Pair card's mint-time choice
        Assert.Contains("MintConnectionJson", main);
        var snap = ReadSrc("Acp.Core", "Services", "HostStateSnapshot.cs");
        Assert.Contains("currentRung", snap);                  // the label reads live snapshot facts
        Assert.Contains("connectionMode", snap);
    }
}

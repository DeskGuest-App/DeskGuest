using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

public class PairingTests
{
    [Fact]
    public void Exchange_ValidCode_ReturnsToken_ThatAuthenticates()
    {
        // Rewritten after review flagged the original as
        // asserting nothing (L2): it now authenticates against the SAME
        // service that issued the token.
        var (svc, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var authed = svc.Authenticate(token);
        Assert.NotNull(authed);
        Assert.Equal(pairing.Id, authed!.Id);
        Assert.Equal("test-agent", authed.AgentName);
    }

    [Fact]
    public void Exchange_ScopesAreBoundAtMint_CallerCannotWiden()
    {
        // C1 regression: a code minted look-only can only ever produce
        // a look-only pairing — there is no exchange input that widens it.
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("guest", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
        var exchange = svc.ExchangeCode(code, "guest");
        Assert.NotNull(exchange);
        var pairing = svc.List().Single();
        Assert.Equal(new HashSet<string> { Scopes.Observe }, pairing.Scopes);
    }

    [Fact]
    public void Exchange_DefaultMint_IsLookOnly()
    {
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("guest", TimeSpan.FromMinutes(5));
        Assert.NotNull(svc.ExchangeCode(code, "guest"));
        Assert.Equal(new HashSet<string> { Scopes.Observe }, svc.List().Single().Scopes);
    }

    [Fact]
    public void Exchange_CodeIsSingleUse()
    {
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("a", TimeSpan.FromMinutes(5), Scopes.All);
        Assert.NotNull(svc.ExchangeCode(code, "a"));
        Assert.Null(svc.ExchangeCode(code, "a"));
    }

    [Fact]
    public void Exchange_ExpiredCode_Fails()
    {
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("a", TimeSpan.FromSeconds(-5), Scopes.All);
        Assert.Null(svc.ExchangeCode(code, "a"));
    }

    [Fact]
    public void Authenticate_WrongToken_ReturnsNull()
    {
        var (svc, _, _) = TestUtil.MakePairing(Scopes.All);
        Assert.Null(svc.Authenticate("not-the-token"));
        Assert.Null(svc.Authenticate(null));
    }

    [Fact]
    public void Revoke_TakesEffectImmediately()
    {
        var (svc, pairing, token) = TestUtil.MakePairing(Scopes.All);
        Assert.NotNull(svc.Authenticate(token));
        Assert.True(svc.Revoke(pairing.Id));
        Assert.Null(svc.Authenticate(token));
    }

    [Fact]
    public void Export_NeverContainsPlaintextToken()
    {
        var (svc, _, token) = TestUtil.MakePairing(Scopes.All);
        var json = svc.ExportJson();
        Assert.DoesNotContain(token, json);
    }
}

public class PairingPersistenceTests
{
    [Fact]
    public void ExportImport_RoundTrip_PreservesAuthentication()
    {
        var (svc, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var json = svc.ExportJson();
        var restored = new PairingService(new DevOnlyPassThroughProtector());
        Assert.Equal(1, restored.ImportJson(json));
        var authed = restored.Authenticate(token);
        Assert.NotNull(authed);
        Assert.Equal(pairing.Id, authed!.Id);
    }

    [Fact]
    public void ExportImport_PreservesRevocation()
    {
        var (svc, pairing, token) = TestUtil.MakePairing(Scopes.All);
        svc.Revoke(pairing.Id);
        var restored = new PairingService(new DevOnlyPassThroughProtector());
        restored.ImportJson(svc.ExportJson());
        Assert.Null(restored.Authenticate(token));
    }
}

public class PairingImportValidationTests
{
    [Fact]
    public void Import_CorruptHashEntry_Skipped_OthersStillAuthenticate()
    {
        // M8 regression: one malformed store line must not brick every pairing.
        var (svc, _, token) = TestUtil.MakePairing(Scopes.All);
        var good = svc.ExportJson();
        var corrupt = good.TrimEnd(']') + ",{\"Id\":\"bad\",\"AgentName\":\"x\",\"Scopes\":[\"observe\"],\"CreatedUtc\":\"2026-11-14T00:00:00Z\",\"ExpiresUtc\":null,\"SessionTimeBoxSeconds\":null,\"Revoked\":false,\"TokenHash\":\"not-hex-at-all\",\"ProtectedAgentName\":\"x\"}]";
        var restored = new PairingService(new DevOnlyPassThroughProtector());
        Assert.Equal(1, restored.ImportJson(corrupt));
        Assert.NotNull(restored.Authenticate(token));
    }
}

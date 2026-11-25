using Acp.Shared.Hub;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>Hub packaging (Block C part 2): every Headscale audit §8 condition
/// is verified here by test, none by intention. Destruction cases are named
/// HubDestruction_* and mirror DESTRUCTION-LEDGER.md entries.</summary>
public class HubTests
{
    private static HubOptions Opts(string home, bool devHttp = false) => new()
    {
        ComponentHome = home,
        ServerUrl = devHttp ? "http://127.0.0.1:8085" : "https://hub.example.test:8085",
        AllowLoopbackHttpDev = devHttp,
        TlsCertPath = "/acp/hub/tls.crt",
        TlsKeyPath = "/acp/hub/tls.key",
    };

    private static string Gen(string home) => HubConfig.Generate(Opts(home));

    // ------------------------------------------------ §8.1 pin
    [Fact]
    public void Pin_IsExactAuditedVersion()
    {
        Assert.Equal("0.29.7", HubPins.HeadscaleVersion);
        Assert.Equal("c9cf210b8bc84d13177e18b91f555788a44b47b6", HubPins.HeadscaleCommit);
        Assert.Equal("1.104.4", HubPins.MinTailscaleClient);
        Assert.Equal("1.27.4", HubPins.MinGoToolchain);
    }

    // ------------------------------------------------ §8.2 config conditions
    [Fact]
    public void GeneratedConfig_PassesEverySection8Check()
    {
        var o = Opts("/acp/hub");
        Assert.Empty(HubConfig.Validate(HubConfig.Generate(o), o));
    }

    [Fact]
    public void GeneratedConfig_NeverContainsExampleDerpUrl()
    {
        var text = Gen("/acp/hub");
        Assert.DoesNotContain("controlplane.tailscale.com", text);
        Assert.Contains("urls: []", text);
        Assert.Contains("verify_clients: true", text);
        Assert.Contains("disable_check_updates: true", text);
        Assert.Contains("grpc_allow_insecure: false", text);
    }

    [Fact]
    public void Validate_RejectsNonEmptyDerpUrls()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("urls: []",
            "urls: [\"https://controlplane.tailscale.com/derpmap/default\"]");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("derp.urls"));
    }

    [Fact]
    public void Validate_RejectsDerpUrlsBlockListForm()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("  urls: []",
            "  urls:\n    - https://controlplane.tailscale.com/derpmap/default");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("derp.urls"));
    }

    [Fact]
    public void Validate_RejectsVerifyClientsOff()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("verify_clients: true", "verify_clients: false");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("verify_clients"));
    }

    [Fact]
    public void Validate_RejectsUpdateCheckOn()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("disable_check_updates: true", "disable_check_updates: false");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("disable_check_updates"));
    }

    [Fact]
    public void Validate_RejectsLogtailNotAssertedFalse()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("  enabled: false\npolicy:", "  enabled: true\npolicy:");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("logtail"));
        var removed = Gen("/acp/hub").Replace("logtail:\n  enabled: false\n", "");
        Assert.Contains(HubConfig.Validate(removed, o), v => v.Condition.Contains("logtail"));
    }

    [Fact]
    public void Validate_RejectsMetricsExposedBeyondLoopback()
    {
        var o = Opts("/acp/hub") with { MetricsListenAddr = "0.0.0.0:9090" };
        // Even asking for it in options: the generated config is then refused.
        Assert.Contains(HubConfig.Validate(HubConfig.Generate(o), o), v => v.Condition.Contains("metrics"));
        var loopback = Opts("/acp/hub") with { MetricsListenAddr = "127.0.0.1:9090" };
        Assert.Empty(HubConfig.Validate(HubConfig.Generate(loopback), loopback));
    }

    [Fact]
    public void Validate_RejectsGrpcInsecureOrNonLoopback()
    {
        var o = Opts("/acp/hub");
        var t1 = Gen("/acp/hub").Replace("grpc_allow_insecure: false", "grpc_allow_insecure: true");
        Assert.Contains(HubConfig.Validate(t1, o), v => v.Condition.Contains("grpc_allow_insecure"));
        var t2 = Gen("/acp/hub").Replace("grpc_listen_addr: 127.0.0.1:50443", "grpc_listen_addr: 0.0.0.0:50443");
        Assert.Contains(HubConfig.Validate(t2, o), v => v.Condition.Contains("gRPC loopback"));
    }

    [Fact]
    public void Validate_RejectsPlainHttpServerUrl()
    {
        var o = Opts("/acp/hub");
        var tampered = Gen("/acp/hub").Replace("https://hub.example.test:8085", "http://hub.example.test:8085");
        Assert.Contains(HubConfig.Validate(tampered, o), v => v.Condition.Contains("HTTPS mandatory"));
    }

    [Fact]
    public void Validate_AllowsLoopbackHttpOnlyInDevMode()
    {
        var dev = Opts("/acp/hub", devHttp: true);
        Assert.Empty(HubConfig.Validate(HubConfig.Generate(dev), dev));
        var notDev = Opts("/acp/hub") with { ServerUrl = "http://127.0.0.1:8085" };
        Assert.Contains(HubConfig.Validate(HubConfig.Generate(notDev), notDev),
            v => v.Condition.Contains("HTTPS mandatory"));
    }

    [Fact]
    public void Validate_OidcRules()
    {
        var good = Opts("/acp/hub") with
        {
            Oidc = new HubOidcOptions
            {
                Issuer = "https://idp.example.test",
                ClientId = "acp",
                ClientSecretPath = "/acp/hub/oidc-secret",
                AllowedDomains = new[] { "example.test" },
            },
        };
        Assert.Empty(HubConfig.Validate(HubConfig.Generate(good), good));

        var httpIssuer = Opts("/acp/hub") with
        {
            Oidc = new HubOidcOptions
            {
                Issuer = "http://idp.example.test",
                ClientId = "acp",
                ClientSecretPath = "/acp/hub/oidc-secret",
                AllowedDomains = new[] { "example.test" },
            },
        };
        Assert.Contains(HubConfig.Validate(HubConfig.Generate(httpIssuer), httpIssuer),
            v => v.Condition.Contains("https issuer"));

        var plainPkce = HubConfig.Generate(good).Replace("method: S256", "method: plain");
        Assert.Contains(HubConfig.Validate(plainPkce, good), v => v.Condition.Contains("S256"));

        var noAllowlist = HubConfig.Generate(good).Replace(
            "  allowed_domains: [\"example.test\"]\n", "");
        Assert.Contains(HubConfig.Validate(noAllowlist, good),
            v => v.Condition.Contains("authorization always set"));
    }

    [Fact]
    public void GeneratedConfig_InHomePathsAreRelative()
    {
        // Regression (laptop proof, 2026-11-19): Headscale's resolver
        // misjudges absolute Windows paths as relative and joins them
        // onto the config dir — the hub refused to start. In-home paths
        // must be emitted relative to the config file's directory.
        var o = Opts(@"C:\ProgramData\ACP\data\hub");
        var text = HubConfig.Generate(o);
        Assert.Contains("private_key_path: data/noise_private.key", text);
        Assert.Contains("private_key_path: data/derp_server_private.key", text);
        Assert.Contains("path: data/db.sqlite", text);
        Assert.Contains("path: policy.json", text);
        Assert.DoesNotContain(@"C:\ProgramData\ACP\data\hub\data", text);
    }

    // ------------------------------------------------ §8.3 policy self-check (HS-01)
    [Fact]
    public void Policy_DenyByDefaultCompilesDenyAll()
    {
        var c = HubPolicy.Compile(HubPolicy.DenyByDefault);
        Assert.False(c.IsAllowAll);
        Assert.Equal(0, c.RuleCount);
    }

    [Fact]
    public void Policy_AbsentAclsAndGrants_IsAllowAll_AndSelfCheckRefuses()
    {
        var groupsOnly = "{ \"groups\": { \"group:admins\": [\"a@b\"] }, \"ssh\": [] }";
        Assert.True(HubPolicy.Compile(groupsOnly).IsAllowAll);
        var o = Opts("/acp/hub");
        Assert.Contains(HubStartupSelfCheck.Check(Gen("/acp/hub"), groupsOnly, o),
            v => v.Condition.Contains("HS-01"));
    }

    [Fact]
    public void Policy_EmptyOrMissing_IsAllowAll()
    {
        Assert.True(HubPolicy.Compile("").IsAllowAll);
        Assert.True(HubPolicy.Compile("  \n ").IsAllowAll);
        Assert.True(HubPolicy.Compile("{}").IsAllowAll);
    }

    [Fact]
    public void Policy_WildcardRule_IsEffectivelyAllowAll()
    {
        var wild = "{ \"acls\": [ { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] } ] }";
        Assert.True(HubPolicy.Compile(wild).IsAllowAll);
    }

    [Fact]
    public void Policy_NarrowRule_PassesSelfCheck()
    {
        var narrow = "{ \"groups\": {\"group:ops\": [\"a@b\"]}, \"acls\": [ { \"action\": \"accept\", \"src\": [\"group:ops\"], \"dst\": [\"tag:pc:8741\"] } ] }";
        Assert.False(HubPolicy.Compile(narrow).IsAllowAll);
        var o = Opts("/acp/hub");
        Assert.Empty(HubStartupSelfCheck.Check(Gen("/acp/hub"), narrow, o));
    }

    [Fact]
    public void Policy_AllowAllOptIn_IsExplicitOnly()
    {
        var o = Opts("/acp/hub") with { AllowAllPolicyOptIn = true };
        Assert.Empty(HubStartupSelfCheck.Check(Gen("/acp/hub"), "{}", o));
    }

    // BD-SHARED-TRANSPORT F2 test repair: hub keys are issued by
    // Headscale, never invented locally — the vault and join
    // service now refuse to mint without an IHeadscaleKeyAuthority.
    // These tests drive a fake authority that returns
    // deterministic Headscale-shaped keys, exactly as the real
    // CLI authority returns what `headscale preauthkeys/apikeys
    // create` issued. The vault/join behaviour under test
    // (caps, single-use, binding, export hygiene) is unchanged.
    private sealed class FakeHeadscaleAuthority : IHeadscaleKeyAuthority
    {
        private int _n;
        public string? CreatePreAuthKey(string hubUser, TimeSpan lifetime) =>
            $"hskey-auth-fake{++_n:0000}-preauthkeysecret{_n:0000}abcdef0123456789";
        public string? CreateApiKey(TimeSpan lifetime) =>
            $"hskey-api-fake{++_n:0000}-apikeysecret{_n:0000}abcdef0123456789";
    }

    // ------------------------------------------------ HS-02 API key vault
    [Fact]
    public void ApiKeyVault_Enforces90DayCap()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        Assert.Throws<InvalidOperationException>(() =>
            vault.Mint(TimeSpan.FromDays(91), DateTimeOffset.UtcNow));
        var ok = vault.Mint(TimeSpan.FromDays(90), DateTimeOffset.UtcNow);
        Assert.False(string.IsNullOrEmpty(ok.PlaintextOnce));
    }

    [Fact]
    public void ApiKeyVault_ExportNeverContainsPlaintext()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        var minted = vault.Mint(TimeSpan.FromDays(30), DateTimeOffset.UtcNow);
        var export = vault.ExportJson();
        // DevOnly protector is base64 — the RAW plaintext must not appear
        // verbatim; with DPAPI it cannot appear at all. The structural rule
        // tested here: export carries the wrapped field, keyed by prefix.
        Assert.Contains(minted.Record.Prefix, export);
        Assert.DoesNotContain("\"" + minted.PlaintextOnce + "\"", export);
    }

    [Fact]
    public void ApiKeyVault_ExpiredKeyIsUnusableAndUnrevealable()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        var t0 = new DateTimeOffset(2026, 11, 19, 0, 0, 0, TimeSpan.Zero);
        var minted = vault.Mint(TimeSpan.FromDays(10), t0);
        Assert.True(vault.IsUsable(minted.Record.Id, t0.AddDays(9)));
        Assert.False(vault.IsUsable(minted.Record.Id, t0.AddDays(10)));
        Assert.Throws<InvalidOperationException>(() => vault.RevealForUse(minted.Record.Id, t0.AddDays(11)));
    }

    [Fact]
    public void ApiKeyVault_RotateRevokesOld()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var first = vault.Mint(TimeSpan.FromDays(30), now);
        var second = vault.Rotate(first.Record.Id, TimeSpan.FromDays(30), now);
        Assert.False(vault.IsUsable(first.Record.Id, now));
        Assert.True(vault.IsUsable(second.Record.Id, now));
    }

    [Fact]
    public void ApiKeyVault_ImportExportRoundtrip()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var minted = vault.Mint(TimeSpan.FromDays(30), now);
        var restored = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeHeadscaleAuthority());
        restored.ImportJson(vault.ExportJson());
        Assert.True(restored.IsUsable(minted.Record.Id, now));
        Assert.Equal(minted.PlaintextOnce, restored.RevealForUse(minted.Record.Id, now));
    }

    // ------------------------------------------------ HS-03 client floor
    [Theory]
    [InlineData("1.104.4", true)]
    [InlineData("1.104.7", true)]
    [InlineData("1.106.0", true)]
    [InlineData("1.104.3", false)]
    [InlineData("1.90.1", false)]
    [InlineData("1.80.0", false)]
    [InlineData("", false)]
    [InlineData("garbage", false)]
    [InlineData(null, false)]
    public void ClientFloor_AdmitsOnlyPatchedClients(string? version, bool admitted)
    {
        var gate = new ClientVersionGate();
        Assert.Equal(admitted, gate.Admit(version, DateTimeOffset.UtcNow));
        if (!admitted) Assert.NotEmpty(gate.Refusals);
    }

    [Fact]
    public void ClientFloor_TailscaleSuffixFormsParse()
    {
        Assert.True(ClientVersionGate.TryParseClientVersion("1.104.7-t0e8f2c1", out var v));
        Assert.Equal(new Version(1, 104, 7), v);
    }

    // ------------------------------------------------ HS-06 / HS-07 registry
    [Fact]
    public void Registry_DecommissionDeletesNode_AndReconnectIsRefused()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var now = DateTimeOffset.UtcNow;
        var nodeId = reg.Join("device-1", "1.104.7", now);
        Assert.NotNull(nodeId);
        // BD-SHARED-TRANSPORT F2 test repair: Decommission now
        // names the node's real Headscale numeric id and refuses
        // while it is unknown (it previously emitted the ACP id,
        // which a real Headscale cannot resolve). The registry
        // learns the id from the hub's node list — recorded here
        // as production wiring records it.
        reg.RecordHeadscaleNodeId("device-1", "7");
        var cmd = reg.Decommission("device-1", now);
        Assert.Contains("nodes delete", cmd);
        Assert.Contains("--identifier 7", cmd);
        Assert.True(reg.Get("device-1")!.Deleted);
        // HS-07: a decommissioned node must NOT come back by re-registering.
        Assert.Null(reg.Join("device-1", "1.104.7", now));
    }

    [Fact]
    public void Registry_OldClientJoinRefusedAndRecorded()
    {
        var gate = new ClientVersionGate();
        var reg = new HubNodeRegistry(gate);
        Assert.Null(reg.Join("device-old", "1.90.0", DateTimeOffset.UtcNow));
        Assert.NotEmpty(gate.Refusals);
        Assert.Contains(reg.Events, e => e.Contains("join-refused"));
    }

    [Fact]
    public void LegacyPlaintextPakPurge_RemovesOnlyPlaintextEntries()
    {
        const string export = """
            [
              {"id": 1, "key": "hskey-auth-legacyplaintext", "prefix": "legacy1"},
              {"id": 2, "prefix": "bcrypt1", "key_hash": "$2a$10$abcdef"},
              {"id": 3, "key": "", "prefix": "empty"}
            ]
            """;
        var (cleaned, purged) = HubNodeRegistry.PurgeLegacyPlaintextPreAuthKeys(export);
        Assert.Single(purged);
        Assert.DoesNotContain("legacyplaintext", cleaned);
        Assert.Contains("bcrypt1", cleaned);
    }

    [Fact]
    public void Registry_ReconcileDeletions_DeletesNodesOfRemovedDevicesOnly()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var now = DateTimeOffset.UtcNow;
        reg.Join("dev-keep", "1.104.7", now);
        reg.Join("dev-gone", "1.104.7", now);
        // LANE W1 REPAIR (bd-shared-transport F2): the delete now
        // targets Headscale's REAL numeric node id, synced from
        // the hub — the pre-fix test encoded the invented-id
        // behaviour (the delete carried the ACP-local id). The
        // ids are recorded here exactly as the production id sync
        // does; the unknown-id path (pending, never fabricated)
        // is covered by BdSharedTransportFixTests.
        reg.RecordHeadscaleNodeId("dev-keep", "3");
        reg.RecordHeadscaleNodeId("dev-gone", "4");
        var cmds = reg.ReconcileDeletions(new HashSet<string> { "dev-keep" }, now);
        Assert.Single(cmds);
        Assert.Contains("nodes delete", cmds[0]);
        Assert.False(reg.Get("dev-keep")!.Deleted);
        Assert.True(reg.Get("dev-gone")!.Deleted);
        // Idempotent: a second reconcile deletes nothing twice.
        Assert.Empty(reg.ReconcileDeletions(new HashSet<string> { "dev-keep" }, now));
    }

    // ------------------------------------------------ D28 join service
    [Fact]
    public void JoinService_SingleUseShortLivedKey_FullAutomaticJoin()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg, new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var ticket = join.MintJoinTicket("dev-9", "group-ops", "https://hub.example.test:8085", now);
        Assert.Contains("--authkey", ticket.CommandLine);
        Assert.True(ticket.ExpiresUtc - now <= TimeSpan.FromHours(1));
        var key = ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];
        Assert.NotNull(join.ConsumeJoin(key, "dev-9", "1.104.7", now));
        // Single-use: replay is refused.
        Assert.Null(join.ConsumeJoin(key, "dev-9", "1.104.7", now));
    }

    [Fact]
    public void JoinService_ExpiredKeyRefused()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg, new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var ticket = join.MintJoinTicket("dev-10", "g", "https://hub.example.test:8085", now);
        var key = ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];
        Assert.Null(join.ConsumeJoin(key, "dev-10", "1.104.7", now.AddHours(2)));
    }

    [Fact]
    public void JoinService_KeyBoundToMintedDevice()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg, new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var ticket = join.MintJoinTicket("dev-A", "g", "https://hub.example.test:8085", now);
        var key = ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];
        Assert.Null(join.ConsumeJoin(key, "dev-B", "1.104.7", now));
    }

    [Fact]
    public void JoinService_OldClientBurnsKeyAndIsRefused()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg, new FakeHeadscaleAuthority());
        var now = DateTimeOffset.UtcNow;
        var ticket = join.MintJoinTicket("dev-old", "g", "https://hub.example.test:8085", now);
        var key = ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];
        Assert.Null(join.ConsumeJoin(key, "dev-old", "1.98.0", now));
    }

    // ------------------------------------------------ lifecycle + D16
    private sealed class FakeHubProcess : IHubProcess
    {
        public bool IsRunning { get; private set; }
        public int StartCount { get; private set; }
        public void Start(string binaryPath, string configPath, string workingDir)
        {
            IsRunning = true;
            StartCount++;
        }
        public void Stop() => IsRunning = false;
        public bool HealthOk(string healthUrl) => IsRunning;
    }

    private static string TempHome()
    {
        var dir = Path.Combine(Path.GetTempPath(), "acp-hub-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, OperatingSystem.IsWindows() ? "headscale.exe" : "headscale"), "fake-binary");
        return dir;
    }

    [Fact]
    public void Lifecycle_D16_NoRungNoRun()
    {
        var home = TempHome();
        var life = new HubLifecycle(Opts(home), new FakeHubProcess(), hubRungSelected: false);
        Assert.Throws<InvalidOperationException>(() => life.Start());
    }

    [Fact]
    public void Lifecycle_InstallStartStop()
    {
        var home = TempHome();
        var proc = new FakeHubProcess();
        var life = new HubLifecycle(Opts(home), proc, hubRungSelected: true);
        life.Install();
        Assert.True(File.Exists(Path.Combine(home, "config.yaml")));
        Assert.True(File.Exists(Path.Combine(home, "policy.json")));
        life.Start();
        Assert.Equal(HubState.Running, life.State);
        life.Stop();
        Assert.Equal(HubState.Stopped, life.State);
    }

    [Fact]
    public void Lifecycle_UpdateToUnpinnedVersionNeedsDeltaAudit()
    {
        var home = TempHome();
        var life = new HubLifecycle(Opts(home), new FakeHubProcess(), hubRungSelected: true);
        Assert.Throws<InvalidOperationException>(() => life.Update("0.30.0", null));
        life.Update("0.30.0", "delta-audit-2026-11-19"); // with stamp: allowed through the gate
        life.Update("0.29.7", null); // pinned version: no stamp needed
    }

    // ------------------------------------------------ DESTRUCTION PASS
    [Fact]
    public void HubDestruction_HandEditedPolicyToAllowAll_RefusedAndReasserted()
    {
        var home = TempHome();
        var proc = new FakeHubProcess();
        var life = new HubLifecycle(Opts(home), proc, hubRungSelected: true);
        life.Install();
        // Attacker/user hand-edits the policy to the HS-01 fail-open shape.
        File.WriteAllText(Path.Combine(home, "policy.json"), "{ \"groups\": {} }");
        Assert.Throws<HubRefusalException>(() => life.Start());
        Assert.Equal(0, proc.StartCount);
        // The tamper does not persist: ACP re-asserted deny-by-default.
        var restored = File.ReadAllText(Path.Combine(home, "policy.json"));
        Assert.False(HubPolicy.Compile(restored).IsAllowAll);
        // And the next start is clean.
        life.Start();
        Assert.Equal(HubState.Running, life.State);
    }

    [Fact]
    public void HubDestruction_HandEditedConfigToExampleDerp_RefusedAndReasserted()
    {
        var home = TempHome();
        var proc = new FakeHubProcess();
        var life = new HubLifecycle(Opts(home), proc, hubRungSelected: true);
        life.Install();
        var cfgPath = Path.Combine(home, "config.yaml");
        var cfg = File.ReadAllText(cfgPath).Replace("urls: []",
            "urls: [\"https://controlplane.tailscale.com/derpmap/default\"]");
        File.WriteAllText(cfgPath, cfg);
        Assert.Throws<HubRefusalException>(() => life.Start());
        Assert.Equal(0, proc.StartCount);
        Assert.DoesNotContain("controlplane.tailscale.com", File.ReadAllText(cfgPath));
    }

    [Fact]
    public void HubDestruction_HandEditedConfigMetricsExposed_Refused()
    {
        var home = TempHome();
        var proc = new FakeHubProcess();
        var life = new HubLifecycle(Opts(home), proc, hubRungSelected: true);
        life.Install();
        var cfgPath = Path.Combine(home, "config.yaml");
        File.WriteAllText(cfgPath, File.ReadAllText(cfgPath)
            .Replace("metrics_listen_addr: \"\"", "metrics_listen_addr: 0.0.0.0:9090"));
        Assert.Throws<HubRefusalException>(() => life.Start());
        Assert.Equal(0, proc.StartCount);
    }

    [Fact]
    public void HubDestruction_ApiKeyExtractionFromExport_YieldsNoPlaintext()
    {
        // With a REAL protector shape (encrypting test double), the export
        // must not contain the minted plaintext anywhere.
        var vault = new HubApiKeyVault(new XorTestProtector(), new FakeHeadscaleAuthority());
        var minted = vault.Mint(TimeSpan.FromDays(30), DateTimeOffset.UtcNow);
        var export = vault.ExportJson();
        Assert.DoesNotContain(minted.PlaintextOnce, export);
        var secretPart = minted.PlaintextOnce.Split('-')[^1];
        Assert.DoesNotContain(secretPart, export);
    }

    private sealed class XorTestProtector : ISecretProtector
    {
        public string Name => "xor-test";
        public bool IsRealProtection => true;
        public string Protect(string plaintext) =>
            Convert.ToBase64String(plaintext.Select(c => (byte)(c ^ 0x5A)).ToArray());
        public string Unprotect(string protectedText) =>
            new(Convert.FromBase64String(protectedText).Select(b => (char)(b ^ 0x5A)).ToArray());
    }
}

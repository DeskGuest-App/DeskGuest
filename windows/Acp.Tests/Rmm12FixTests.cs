using System.Net;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Sessions;
using Acp.Shared.Vulnerability;
using Acp.Shared.WorkItems;
using Xunit;

namespace Acp.Tests;

// RMM-12 D38 FIX (packet 33262b01) — regression battery for the
// cross-review findings F1–F10 as reconciled against the current
// tree. Every test here pins a CONFIRMED break (or the corrected
// behaviour for a refuted one); see
// ~/workspace/builds/rmm-r-logs/ledger-rmm12-fix.md.
public class Rmm12FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string OtherDev = "dev-2";
    private const string Scope = "co-1";
    private const string Secret = "bridge-secret-0123456789";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyService Policies;
        public RecordingWebhookTransport Transport = new();
        public Dictionary<string, Session> Sessions = new(StringComparer.OrdinalIgnoreCase);
        public WorkItemService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public StaticDeviceFacts OtherFacts = StaticDeviceFacts.Of(OtherDev, Scope);

        public Rig()
        {
            Policies = new ManagementPolicyService(Audit, null, now: () => Now);
            Service = new WorkItemService(Audit, Policies,
                id => id is not null && Sessions.TryGetValue(id, out var s) ? s : null,
                Transport, () => Now);
        }

        public void SetPolicy(string key, string value) =>
            Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                $"doc-{key}-{Guid.NewGuid():N}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, 1), "test");

        public Session AddSession(string id, string deviceId)
        {
            var s = new Session(id, Scope, deviceId, "tech-1", "remote", "active",
                Now, null, "webrtc", "none");
            Sessions[id] = s;
            return s;
        }

        public void EnableBridge()
        {
            SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
            Assert.True(Service.ConfigureBridge(Facts,
                "https://tickets.example.com/hooks/acp", Secret, "admin-1").Ok);
        }
    }

    private static HealthAlertEvent Alert(string alertId, string deviceId = Dev,
        string conditionId = "disk-low") =>
        new(alertId, deviceId, conditionId, "disk", "warning", HealthAlertStates.Raised,
            T0, T0, 1, "disk below threshold", null, null, null, null, "endpoint");

    private static ExposureWorkItem Exposure(string state = ExposureStates.Open, ClosureEvidence? closure = null) =>
        new("exp-abc", "CVE-2026-1 — Widget on dev-1", Dev, Scope, state,
            null, T0, T0, closure is not null ? T0.AddHours(2) : null,
            "CVE-2026-1", "Widget", new[] { "1.0" }, "1.1", null,
            7.5, "high", false, ExposureSources.Feed, "feed-1", "abc123",
            T0, T0, T0.AddDays(14), null, null, null, closure);

    private static WorkItem BareItem(string id = "wi-bare") =>
        new(id, "Bare", Dev, Scope, WorkItemStates.Open, null, T0, T0, null,
            WorkItemKinds.Manual, null, null, null, null, null, null,
            Array.Empty<WorkItemAttachment>(), null, Array.Empty<long>());

    // ---- F1: persistence lives in WorkItemStore and round-trips ----

    [Fact]
    public void F1_Persistence_ExportImport_RoundTrips_TamperRestoresNothing()
    {
        var rig = new Rig();
        var (manual, _) = rig.Service.Store.OpenManual(Dev, Scope, "Persist me", "tech-1", rig.Now);
        rig.Service.Store.OpenFromAlert(Alert("alert-p"), rig.Now);
        Assert.NotNull(manual);

        var exported = rig.Service.Store.ExportJson();
        var fresh = new WorkItemStore(new ChainedAuditLog());
        var restored = fresh.ImportJson(exported);
        Assert.Equal(2, restored);
        Assert.Equal(2, fresh.Items.Count);
        Assert.Contains(fresh.Items, i => i.Id == manual!.Id && i.Title == "Persist me");

        var tampered = exported.Replace("Persist me", "Forged title");
        var fresh2 = new WorkItemStore(new ChainedAuditLog());
        Assert.Equal(0, fresh2.ImportJson(tampered));
        Assert.Empty(fresh2.Items);
    }

    // ---- F2: re-adoption closure carries its outcome; kinds map honestly ----

    [Fact]
    public void F2_ReAdoptionClosure_VerifiesAgainstChain()
    {
        var rig = new Rig();
        var (item, _, _) = rig.Service.AdoptExposure(rig.Facts, Exposure());
        Assert.NotNull(item);
        var evidence = new ClosureEvidence("exp-abc", ClosureKinds.Patch, new string('a', 64),
            "patched", "tech-9", T0.AddHours(2));
        var (synced, _, _) = rig.Service.AdoptExposure(rig.Facts, Exposure(ExposureStates.Closed, evidence));
        Assert.True(synced!.IsClosed);
        Assert.Equal(WorkItemOutcomes.Resolved, synced.Closure!.Outcome);
        var (ok, reason) = rig.Service.Store.VerifyAgainstChain(synced.Id);
        Assert.True(ok, reason);
        var rebuilt = ReconstructedHistory.Reconstruct(rig.Audit.Entries, synced.Id);
        Assert.Equal(WorkItemOutcomes.Resolved, rebuilt.ClosureOutcome);
    }

    [Fact]
    public void F2_CompensatingControlClosure_IsMitigatedNotResolved_AndNotManualForgeable()
    {
        var rig = new Rig();
        var evidence = new ClosureEvidence("exp-abc", ClosureKinds.CompensatingControl,
            new string('c', 64), "control documented", "tech-9", T0.AddHours(2));
        var (item, _, _) = rig.Service.AdoptExposure(rig.Facts, Exposure(ExposureStates.Closed, evidence));
        Assert.True(item!.IsClosed);
        Assert.Equal(WorkItemOutcomes.MitigatedCompensatingControl, item.Closure!.Outcome);
        Assert.True(rig.Service.Store.VerifyAgainstChain(item.Id).Ok);
        // The mitigated outcome is reserved like the auto-close
        // outcome: no manual closure may claim it.
        var (other, _) = rig.Service.OpenManual(rig.Facts, "Forge mitigated", "tech-1");
        Assert.False(rig.Service.Store.Close(other!.Id,
            WorkItemOutcomes.MitigatedCompensatingControl, "tech-1", null, rig.Now).Ok);
    }

    // ---- F3: audit attribution is anchored to the leading item= token ----

    [Fact]
    public void F3_RequesterNameEmbeddingAnotherItemsId_DoesNotPoisonItsHistory()
    {
        var rig = new Rig();
        var (victim, _) = rig.Service.OpenManual(rig.Facts, "Victim", "tech-1");
        Assert.True(rig.Service.Close(rig.Facts, victim!.Id, WorkItemOutcomes.Resolved, null, "tech-1").Ok);

        // The requester's name carries a forged attribution token
        // naming the (closed) victim item.
        var req = new UserWorkRequest("req-evil", Dev, $"mallory item={victim.Id}", "help", null);
        var (evil, created, _) = rig.Service.IntakeRequest(rig.Facts, Dev, req);
        Assert.True(created);
        Assert.NotNull(evil);

        var (ok, reason) = rig.Service.Store.VerifyAgainstChain(victim.Id);
        Assert.True(ok, reason);
        var rebuilt = ReconstructedHistory.Reconstruct(rig.Audit.Entries, victim.Id);
        Assert.Equal(WorkItemStates.Closed, rebuilt.FinalState);
        Assert.Equal(WorkItemOutcomes.Resolved, rebuilt.ClosureOutcome);
    }

    // ---- F4: the gate checks the ITEM's device, and every action is gated ----

    [Fact]
    public void F4_CrossDeviceFacts_CannotAttachNoteOrClose()
    {
        var rig = new Rig();
        rig.AddSession("sess-1", Dev);
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Mine", "tech-1");
        Assert.False(rig.Service.AttachSession(rig.OtherFacts, item!.Id, "sess-1", "tech-1").Ok);
        Assert.False(rig.Service.AttachScript(rig.OtherFacts, item.Id, "script-x", "tech-1").Ok);
        Assert.False(rig.Service.AddNote(rig.OtherFacts, item.Id, "note-x", "poison", "tech-1").Ok);
        Assert.False(rig.Service.Close(rig.OtherFacts, item.Id, WorkItemOutcomes.Resolved, null, "tech-1").Ok);
        var stored = rig.Service.Store.Get(item.Id)!;
        Assert.Empty(stored.Attachments);
        Assert.False(stored.IsClosed);
    }

    [Fact]
    public void F4_PolicyOff_BlocksEveryServiceAction_IncludingAdoptAndConfigure()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Before off", "tech-1");
        rig.SetPolicy(WorkItemPolicyKeys.Enabled, "false");

        Assert.False(rig.Service.Assign(rig.Facts, item!.Id, "tech-2", "tech-1").Ok);
        Assert.False(rig.Service.AttachScript(rig.Facts, item.Id, "script-x", "tech-1").Ok);
        Assert.False(rig.Service.AddNote(rig.Facts, item.Id, "note-x", "text", "tech-1").Ok);
        Assert.False(rig.Service.Close(rig.Facts, item.Id, WorkItemOutcomes.Resolved, null, "tech-1").Ok);
        Assert.False(rig.Service.ConfigureBridge(rig.Facts,
            "https://tickets.example.com/hook", Secret, "admin-1").Ok);
        Assert.False(rig.Service.Bridge.IsConfigured);
        var (reqItem, _, _) = rig.Service.IntakeRequest(rig.Facts, Dev,
            new UserWorkRequest("req-off", Dev, "user", "slow", null));
        Assert.Null(reqItem);
        var (adopted, created, _) = rig.Service.AdoptExposure(rig.Facts, Exposure());
        Assert.Null(adopted);
        Assert.False(created);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_item_adopt_refused");
        Assert.Single(rig.Service.Store.Items); // only the pre-off item exists
    }

    [Fact]
    public void F4_Intake_FactsForAnotherDevice_RefusedNoItem()
    {
        var rig = new Rig();
        var request = new UserWorkRequest("req-1", Dev, "user", "slow", null);
        // Channel is dev-1's, but the policy facts presented are dev-2's.
        var (item, created, reason) = rig.Service.IntakeRequest(rig.OtherFacts, Dev, request);
        Assert.Null(item);
        Assert.False(created);
        Assert.Contains(OtherDev, reason);
        Assert.Empty(rig.Service.Store.Items);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_request_spoof_refused");
    }

    [Fact]
    public void F4_AdoptExposure_WrongDeviceFacts_Refused()
    {
        var rig = new Rig();
        var (item, created, reason) = rig.Service.AdoptExposure(rig.OtherFacts, Exposure());
        Assert.Null(item);
        Assert.False(created);
        Assert.Contains(Dev, reason);
        Assert.Empty(rig.Service.Store.Items);
    }

    // ---- F5: a throwing transport is a failed attempt, never an escape ----

    private sealed class ThrowOnceTransport : IWebhookTransport
    {
        public int Calls;
        public (bool Ok, string Detail) Post(Uri target, string payloadJson)
        {
            Calls++;
            if (Calls == 1) throw new InvalidOperationException("PSA socket exploded");
            return (true, "200 OK");
        }
    }

    private sealed class AlwaysThrowTransport : IWebhookTransport
    {
        public (bool Ok, string Detail) Post(Uri target, string payloadJson) =>
            throw new InvalidOperationException("PSA socket exploded");
    }

    private sealed class SlowTransport : IWebhookTransport
    {
        public int Sends;
        public (bool Ok, string Detail) Post(Uri target, string payloadJson)
        {
            Interlocked.Increment(ref Sends);
            Thread.Sleep(100);
            return (true, "200 OK");
        }
    }

    [Fact]
    public void F5_ThrowingTransport_FirstDeliveryFails_SecondStillDelivers()
    {
        var bridge = new WorkItemBridge();
        Assert.True(bridge.Configure("https://tickets.example.com/hook", Secret, "admin-1", T0).Ok);
        var item = BareItem();
        bridge.Enqueue(BridgeEventKinds.Opened, item, T0);
        bridge.Enqueue(BridgeEventKinds.Closed, item, T0);

        var transport = new ThrowOnceTransport();
        var changed = bridge.Pump(transport, T0); // must not throw
        Assert.Equal(2, changed.Count);
        Assert.Contains(changed, d => d.State == BridgeDeliveryStates.Failed &&
            d.Attempts == 1 && d.LastError!.Contains("transport threw"));
        Assert.Contains(changed, d => d.State == BridgeDeliveryStates.Delivered);
    }

    [Fact]
    public void F5_ServicePump_ThrowingTransport_ChainsFailure_NeverEscapes()
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null, now: () => T0);
        var service = new WorkItemService(audit, policies, _ => null,
            new AlwaysThrowTransport(), () => T0);
        policies.AdmitLocalDocument(new ManagementPolicyDocument(
            $"doc-{Guid.NewGuid():N}", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [WorkItemPolicyKeys.BridgeEnabled] = "true" }, 1), "test");
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        Assert.True(service.ConfigureBridge(facts, "https://tickets.example.com/hook", Secret, "admin-1").Ok);
        service.OpenManual(facts, "Will fail delivery", "tech-1");

        var changed = service.PumpBridge(); // must not throw
        var d = Assert.Single(changed);
        Assert.Equal(BridgeDeliveryStates.Failed, d.State);
        Assert.Equal(1, d.Attempts);
        Assert.Contains(audit.Entries, e => e.Kind == "work_bridge_delivery_failed");
    }

    [Fact]
    public void F5_ConcurrentPumps_SendEachDeliveryOnce()
    {
        var bridge = new WorkItemBridge();
        Assert.True(bridge.Configure("https://tickets.example.com/hook", Secret, "admin-1", T0).Ok);
        bridge.Enqueue(BridgeEventKinds.Opened, BareItem(), T0);
        var slow = new SlowTransport();
        Parallel.Invoke(
            () => bridge.Pump(slow, T0),
            () => bridge.Pump(slow, T0));
        Assert.Equal(1, slow.Sends);
        var d = Assert.Single(bridge.Deliveries);
        Assert.Equal(1, d.Attempts);
        Assert.Equal(BridgeDeliveryStates.Delivered, d.State);
    }

    // ---- F6: sink + re-adoption events reach the bridge or a chained skip ----

    [Fact]
    public void F6_SinkOpenAndAutoClose_ChainNamedBridgeSkips()
    {
        var rig = new Rig();
        IWorkItemSink sink = rig.Service;
        sink.OpenWorkItem(Alert("alert-sink"), rig.Now);
        var id = WorkItem.IdForAlert("alert-sink");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_skipped" &&
            e.Detail.Contains(id) && e.Detail.Contains(BridgeEventKinds.Opened));
        sink.CloseWorkItem(Alert("alert-sink"), "auto-reset: condition cleared", rig.Now);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_skipped" &&
            e.Detail.Contains(id) && e.Detail.Contains(BridgeEventKinds.AutoClosed));
    }

    [Fact]
    public void F6_BridgeOpened_ForwardsSinkItemWhenHubCallsWithFacts()
    {
        var rig = new Rig();
        rig.EnableBridge();
        IWorkItemSink sink = rig.Service;
        sink.OpenWorkItem(Alert("alert-fwd"), rig.Now);
        var item = rig.Service.Store.Get(WorkItem.IdForAlert("alert-fwd"))!;
        rig.Service.BridgeOpened(rig.Facts, item);
        var delivery = Assert.Single(rig.Service.Bridge.Deliveries);
        Assert.Equal(BridgeEventKinds.Opened, delivery.EventKind);
        Assert.Equal(item.Id, delivery.ItemId);
    }

    [Fact]
    public void F6_ReAdoptionClosure_ReachesBridgeAsClosedEvent()
    {
        var rig = new Rig();
        rig.EnableBridge();
        rig.Service.AdoptExposure(rig.Facts, Exposure());
        Assert.Single(rig.Service.Bridge.Deliveries); // the opened event
        var evidence = new ClosureEvidence("exp-abc", ClosureKinds.Patch, new string('a', 64),
            "patched", "tech-9", T0.AddHours(2));
        rig.Service.AdoptExposure(rig.Facts, Exposure(ExposureStates.Closed, evidence));
        Assert.Equal(2, rig.Service.Bridge.Deliveries.Count);
        Assert.Contains(rig.Service.Bridge.Deliveries, d => d.EventKind == BridgeEventKinds.Closed);
    }

    // ---- F7: the guard judges mapped / CGNAT / benchmark / *.localhost ----

    [Theory]
    // REPAIRED (Wave 2 Lane B, 2026-11-22) for bd-shared-rmm-3/F3:
    // two rows were removed — the IPv4-mapped PRIVATE literal and
    // the benchmarking-range literal. The drifted BridgeGuard refused
    // them; the ONE guard (WebhookTargetGuard) admits RFC1918-class
    // targets because a self-hosted PSA lives on the org's own LAN.
    // They are asserted ADMITTED in F7_LanClassTargets_AdmittedAtConfiguration
    // below. Mapped metadata, CGNAT and *.localhost stay refused.
    [InlineData("https://[::ffff:169.254.169.254]/latest")]    // IPv4-mapped metadata
    [InlineData("https://100.64.1.1/hook")]                    // CGNAT 100.64/10
    [InlineData("https://x.localhost/hook")]                   // localhost subdomain
    public void F7_NonPublicTargets_RefusedAtConfiguration(string url)
    {
        var rig = new Rig();
        var (ok, _) = rig.Service.ConfigureBridge(rig.Facts, url, Secret, "admin-1");
        Assert.False(ok);
        Assert.False(rig.Service.Bridge.IsConfigured);
    }

    [Theory]
    [InlineData("https://[::ffff:10.0.0.5]/hook")]              // IPv4-mapped private (org LAN)
    [InlineData("https://198.18.0.1/hook")]                    // benchmarking range — not a refused class in the one guard
    public void F7_LanClassTargets_AdmittedAtConfiguration(string url)
    {
        // bd-shared-rmm-3/F3: configuration admission follows the
        // hub's WebhookTargetGuard (LAN admitted); the public-only
        // rule now binds at the DNS-answer check, not here.
        var rig = new Rig();
        var (ok, _) = rig.Service.ConfigureBridge(rig.Facts, url, Secret, "admin-1");
        Assert.True(ok);
        Assert.True(rig.Service.Bridge.IsConfigured);
    }

    [Fact]
    public void F7_IsPublic_JudgesMappedAddressesByTheirIPv4()
    {
        Assert.False(BridgeGuard.IsPublic(IPAddress.Parse("::ffff:10.0.0.5")));
        Assert.False(BridgeGuard.IsPublic(IPAddress.Parse("::ffff:169.254.169.254")));
        Assert.True(BridgeGuard.IsPublic(IPAddress.Parse("::ffff:93.184.216.34")));
        Assert.False(BridgeGuard.IsPublic(IPAddress.Parse("100.64.0.1")));
        Assert.False(BridgeGuard.IsPublic(IPAddress.Parse("198.19.0.1")));
        Assert.True(BridgeGuard.IsPublic(IPAddress.Parse("100.63.0.1")));
        Assert.True(BridgeGuard.IsPublic(IPAddress.Parse("93.184.216.34")));
    }

    // ---- F8: queued deliveries keep their enqueue-time target ----

    [Fact]
    public void F8_Reconfigure_DoesNotRetargetQueuedDeliveries()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
        Assert.True(rig.Service.ConfigureBridge(rig.Facts,
            "https://psa-a.example.com/hook", Secret, "admin-1").Ok);
        rig.Service.OpenManual(rig.Facts, "Queued for A", "tech-1");
        // Reconfigure to a different PSA with a different secret.
        Assert.True(rig.Service.ConfigureBridge(rig.Facts,
            "https://psa-b.example.com/hook", "other-secret-0123456789", "admin-1").Ok);

        rig.Service.PumpBridge();
        var sent = Assert.Single(rig.Transport.Sent);
        Assert.Equal("psa-a.example.com", sent.Target.Host);
        // And the payload still verifies against the ORIGINAL secret.
        Assert.True(BridgeSigning.VerifyPayload(sent.PayloadJson, Secret));
    }

    [Fact]
    public void F8_StoredSecretFingerprint_IsNotThePlainSha256()
    {
        var rig = new Rig();
        Assert.True(rig.Service.ConfigureBridge(rig.Facts,
            "https://tickets.example.com/hook", Secret, "admin-1").Ok);
        var config = rig.Service.Bridge.Configuration!;
        Assert.NotEqual(BridgeSigning.SecretHash(Secret), config.SecretHash);
        Assert.DoesNotContain(Secret, config.SecretHash);
    }

    // ---- F9: every cap refusal counts; flood episodes re-chain; null device refuses ----

    [Fact]
    public void F9_ManualCapRefusal_IsCountedAndChained()
    {
        var rig = new Rig();
        for (var i = 0; i < WorkItemLimits.MaxOpenItemsPerDevice; i++)
            Assert.NotNull(rig.Service.Store.OpenManual(Dev, Scope, $"item-{i}", "tech-1", rig.Now).Item);
        var (item, reason) = rig.Service.Store.OpenManual(Dev, Scope, "one too many", "tech-1", rig.Now);
        Assert.Null(item);
        Assert.Contains("counted, not silent", reason);
        Assert.True(rig.Service.Store.FloodRefusals[Dev] >= 1);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_item_flood_capped" &&
            e.Detail.Contains("path=manual"));
    }

    [Fact]
    public void F9_SecondFloodAfterDrain_ChainsAgain()
    {
        var rig = new Rig();
        for (var round = 0; round < 2; round++)
        {
            for (var i = 0; i < WorkItemLimits.MaxOpenAlertItemsPerDevice; i++)
                rig.Service.Store.OpenFromAlert(Alert($"alert-r{round}-{i}"), rig.Now);
            var (item, _, _) = rig.Service.Store.OpenFromAlert(Alert($"alert-r{round}-overflow"), rig.Now);
            Assert.Null(item);
            // Drain: auto-close this round's items so the cap clears.
            for (var i = 0; i < WorkItemLimits.MaxOpenAlertItemsPerDevice; i++)
                rig.Service.Store.AutoCloseFromAlert(Alert($"alert-r{round}-{i}"), "reset", rig.Now);
        }
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "work_item_flood_capped"));
        Assert.True(rig.Service.Store.FloodRefusals[Dev] >= 2);
    }

    [Fact]
    public void F9_NullDeviceAlert_RefusesWithoutThrowing()
    {
        var rig = new Rig();
        var (item, created, reason) = rig.Service.Store.OpenFromAlert(Alert("alert-null", null!), rig.Now);
        Assert.Null(item);
        Assert.False(created);
        Assert.Contains("no device id", reason);
    }

    // ---- F10: growth is bounded where the lane controls it ----

    [Fact]
    public void F10_NoTransportPumpSkip_ChainedOnceNotPerPump()
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null, now: () => T0);
        var service = new WorkItemService(audit, policies, _ => null,
            transport: null, now: () => T0);
        service.PumpBridge();
        service.PumpBridge();
        service.PumpBridge();
        Assert.Single(audit.Entries, e => e.Kind == "work_bridge_pump_skipped");
    }

    [Fact]
    public void F10_SpoofLoop_CountsEveryRefusal_ChainsOnce()
    {
        var rig = new Rig();
        var spoof = new UserWorkRequest("req-spoof", OtherDev, "mallory", "slow",
            new DeviceHealthSummary("alerting", new[] { "cpu-high" }, "ok", rig.Now));
        for (var i = 0; i < 5; i++)
            rig.Service.Store.IntakeRequest(Dev, Scope, spoof, rig.Now);
        Assert.Equal(5, rig.Service.Store.SpoofRefusals[Dev]);
        Assert.Single(rig.Audit.Entries, e => e.Kind == "work_request_spoof_refused");
        Assert.Empty(rig.Service.Store.Items);
    }

    [Fact]
    public void F10_FiringConditionIds_AreCappedAtTheModelDoor()
    {
        var rig = new Rig();
        var ids = Enumerable.Range(0, 100).Select(i => $"cond-{i}").ToArray();
        var summary = new DeviceHealthSummary("alerting", ids, "ok", rig.Now);
        Assert.Equal(WorkItemLimits.MaxFiringConditionIds, summary.FiringConditionIds.Count);
        var request = new UserWorkRequest("req-many", Dev, "user", "slow", summary);
        var (item, created, _) = rig.Service.IntakeRequest(rig.Facts, Dev, request);
        Assert.True(created);
        Assert.Equal(WorkItemLimits.MaxFiringConditionIds, item!.HealthSummary!.FiringConditionIds.Count);
    }

    [Fact]
    public void F10_DeliveryRetention_EvictsOldestDelivered_NeverPending()
    {
        var bridge = new WorkItemBridge();
        Assert.True(bridge.Configure("https://tickets.example.com/hook", Secret, "admin-1", T0).Ok);
        var transport = new RecordingWebhookTransport();
        var item = BareItem();
        for (var i = 0; i < WorkItemLimits.MaxRetainedDeliveries + 5; i++)
            bridge.Enqueue(BridgeEventKinds.Opened, item, T0);
        bridge.Pump(transport, T0);
        Assert.All(bridge.Deliveries, d => Assert.Equal(BridgeDeliveryStates.Delivered, d.State));
        bridge.Enqueue(BridgeEventKinds.Closed, item, T0);
        Assert.Equal(WorkItemLimits.MaxRetainedDeliveries, bridge.Deliveries.Count);
        Assert.Contains(bridge.Deliveries, d => d.State == BridgeDeliveryStates.Pending);
    }
}

using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Vulnerability;
using DeskGuest.Shared.WorkItems;
using Xunit;

namespace DeskGuest.Tests;

// RMM-12 — Work items: the alert→work→session→audit trail
// (ticket-lite, deliberately not a PSA): alert auto-create /
// auto-close via the RMM-01 sink contract, manual items with
// sessions/scripts/notes attached and outcome closure, the
// end-user request channel with device context, RMM-05 exposure
// adoption, and the signed PSA bridge.
public class Rmm12Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyService Policies;
        public RecordingWebhookTransport Transport = new();
        public Dictionary<string, Session> Sessions = new(StringComparer.OrdinalIgnoreCase);
        public WorkItemService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

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
    }

    private static HealthAlertEvent Alert(string alertId, string deviceId = Dev,
        string conditionId = "disk-low", string kind = "disk", string severity = "warning") =>
        new(alertId, deviceId, conditionId, kind, severity, HealthAlertStates.Raised,
            T0, T0, 1, "disk below threshold", null, null, null, null, "endpoint");

    private static ExposureWorkItem Exposure(string state = ExposureStates.Open, ClosureEvidence? closure = null) =>
        new("exp-abc", "CVE-2026-1 — Widget on dev-1", Dev, Scope, state,
            null, T0, T0, closure is not null ? T0.AddHours(2) : null,
            "CVE-2026-1", "Widget", new[] { "1.0" }, "1.1", null,
            7.5, "high", false, ExposureSources.Feed, "feed-1", "abc123",
            T0, T0, T0.AddDays(14), null, null, null, closure);

    // ---- (a) alert-driven lifecycle -------------------------------------

    [Fact]
    public void AlertOpen_ViaSink_CreatesItemBoundToAlert()
    {
        var rig = new Rig();
        IWorkItemSink sink = rig.Service; // the service IS the RMM-01 sink
        sink.OpenWorkItem(Alert("alert-1"), rig.Now);
        var item = Assert.Single(rig.Service.Store.Items);
        Assert.Equal(WorkItemKinds.Alert, item.Kind);
        Assert.Equal(WorkItemStates.Open, item.State);
        Assert.Equal("alert-1", item.SourceAlertId);
        Assert.Equal("disk-low", item.SourceConditionId);
        Assert.Equal(Dev, item.DeviceId);
        Assert.Equal(WorkItem.IdForAlert("alert-1"), item.Id);
    }

    [Fact]
    public void AlertLifecycle_WithRealCentre_RaiseOpens_ResetAutoCloses()
    {
        var rig = new Rig();
        var centre = new HealthAlertCentre(rig.Audit, new AlertCenter());
        var outcome = centre.Raise(Dev, "disk-low", "disk", "warning", "disk below threshold",
            "endpoint", TimeSpan.FromMinutes(5), rig.Now);
        Assert.Equal(RaiseOutcome.New, outcome.Outcome);
        rig.Service.OpenWorkItem(outcome.Alert!, rig.Now);
        var item = Assert.Single(rig.Service.Store.OpenItems);

        var reset = centre.AutoResetCleared(Dev, new HashSet<string>(), rig.Now.AddMinutes(10));
        var resetAlert = Assert.Single(reset);
        rig.Service.CloseWorkItem(resetAlert, "auto-reset: condition cleared", rig.Now.AddMinutes(10));

        var closed = rig.Service.Store.Get(item.Id)!;
        Assert.True(closed.IsClosed);
        Assert.Equal(WorkItemOutcomes.AutoClosedConditionReset, closed.Closure!.Outcome);
        Assert.True(closed.Closure.AutoClosed);
        Assert.Equal(WorkItemStore.LifecycleActor, closed.Closure.ClosedBy);
    }

    [Fact]
    public void AlertOpen_IsIdempotentPerAlert()
    {
        var rig = new Rig();
        rig.Service.OpenWorkItem(Alert("alert-1"), rig.Now);
        var (again, created, _) = rig.Service.Store.OpenFromAlert(Alert("alert-1"), rig.Now);
        Assert.False(created);
        Assert.Single(rig.Service.Store.Items);
        Assert.Equal(WorkItem.IdForAlert("alert-1"), again!.Id);
    }

    // ---- (b) manual items -------------------------------------------------

    [Fact]
    public void ManualItem_FullLifecycle_AssignAttachCloseWithOutcome()
    {
        var rig = new Rig();
        rig.AddSession("sess-1", Dev);
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Investigate slowness", "tech-1");
        Assert.NotNull(item);
        Assert.Equal(WorkItemKinds.Manual, item!.Kind);

        var (assigned, _) = rig.Service.Assign(rig.Facts, item.Id, "tech-2", "tech-1");
        Assert.True(assigned);
        Assert.Equal(WorkItemStates.InProgress, rig.Service.Store.Get(item.Id)!.State);
        Assert.Equal("tech-2", rig.Service.Store.Get(item.Id)!.Owner);

        Assert.True(rig.Service.AttachSession(rig.Facts, item.Id, "sess-1", "tech-2").Ok);
        Assert.True(rig.Service.AttachScript(rig.Facts, item.Id, "script-disk-cleanup", "tech-2").Ok);
        Assert.True(rig.Service.AddNote(rig.Facts, item.Id, "note-1", "Cleared 40 GB of temp files.", "tech-2").Ok);
        Assert.Equal(3, rig.Service.Store.Get(item.Id)!.Attachments.Count);

        var (closed, _) = rig.Service.Close(rig.Facts, item.Id, WorkItemOutcomes.Resolved, "disk freed", "tech-2");
        Assert.True(closed);
        var done = rig.Service.Store.Get(item.Id)!;
        Assert.True(done.IsClosed);
        Assert.False(done.Closure!.AutoClosed);
        Assert.Equal("tech-2", done.Closure.ClosedBy);
    }

    [Fact]
    public void PolicyDisabled_BlocksManualActions()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.Enabled, "false");
        var (item, reason) = rig.Service.OpenManual(rig.Facts, "Nope", "tech-1");
        Assert.Null(item);
        Assert.Contains("disabled by policy", reason);
        Assert.Empty(rig.Service.Store.Items);
    }

    [Fact]
    public void ToggleSeededOn_InRegistry()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet("rmm.work_items.enabled", out var toggle));
        Assert.True(toggle!.DefaultEnabled);
        Assert.Equal("RMM-12", toggle.Directive);
    }

    // ---- (c) request channel ----------------------------------------------

    [Fact]
    public void RequestIntake_LandsWithDeviceContext()
    {
        var rig = new Rig();
        var summary = new DeviceHealthSummary("alerting", new[] { "cpu-high" }, "ok", rig.Now);
        var request = new UserWorkRequest("req-1", Dev, " front desk ", "My computer is slow", summary);
        var (item, created, _) = rig.Service.IntakeRequest(rig.Facts, Dev, request);
        Assert.True(created);
        Assert.NotNull(item);
        Assert.Equal(WorkItemKinds.Request, item!.Kind);
        Assert.Equal(Dev, item.DeviceId); // stamped from the channel
        Assert.Equal("req-1", item.RequestId);
        Assert.Equal("front desk", item.RequesterName);
        Assert.NotNull(item.HealthSummary);
        Assert.Equal("alerting", item.HealthSummary!.HealthState);
        Assert.Contains("cpu-high", item.HealthSummary.FiringConditionIds);
    }

    [Fact]
    public void RequestIntake_IdempotentPerRequestId()
    {
        var rig = new Rig();
        var request = new UserWorkRequest("req-1", Dev, "user", "slow", null);
        rig.Service.IntakeRequest(rig.Facts, Dev, request);
        var (_, created, _) = rig.Service.IntakeRequest(rig.Facts, Dev, request);
        Assert.False(created);
        Assert.Single(rig.Service.Store.Items);
    }

    [Fact]
    public void RequestChannel_DisabledByPolicy_Refuses()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.RequestChannelEnabled, "false");
        var request = new UserWorkRequest("req-1", Dev, "user", "slow", null);
        var (item, _, reason) = rig.Service.IntakeRequest(rig.Facts, Dev, request);
        Assert.Null(item);
        Assert.Contains("request channel is disabled", reason);
    }

    // ---- RMM-05 adoption ------------------------------------------------------

    [Fact]
    public void ExposureAdoption_ProjectsSpine_AndFollowsClosure()
    {
        var rig = new Rig();
        var open = Exposure();
        var (adopted, created, _) = rig.Service.AdoptExposure(rig.Facts, open);
        var item = adopted!;
        Assert.True(created);
        Assert.Equal(WorkItemKinds.Vulnerability, item.Kind);
        Assert.Equal("exp-abc", item.ExposureId);
        Assert.Equal(open.Title, item.Title);
        Assert.Equal(open.DeviceId, item.DeviceId);
        Assert.Equal(open.ScopeId, item.ScopeId);
        Assert.Equal(WorkItemStates.Open, item.State);

        var evidence = new ClosureEvidence("exp-abc", ClosureKinds.Patch, new string('a', 64),
            "patched", "tech-9", T0.AddHours(2));
        var closedExposure = Exposure(ExposureStates.Closed, evidence);
        var (synced, createdAgain, _) = rig.Service.AdoptExposure(rig.Facts, closedExposure);
        Assert.False(createdAgain);
        Assert.NotNull(synced);
        Assert.True(synced!.IsClosed);
        Assert.Equal("tech-9", synced.Closure!.ClosedBy);
        Assert.Contains("evidence", synced.Closure.Note!);
        // The exposure record itself was never mutated by adoption.
        Assert.Equal(ExposureStates.Open, open.State);
        Assert.Single(rig.Service.Store.Items);
    }

    [Fact]
    public void ExposureAdoptedClosed_VerifiesAgainstChain()
    {
        var rig = new Rig();
        var evidence = new ClosureEvidence("exp-abc", ClosureKinds.Patch, new string('b', 64),
            "patched", "tech-9", T0.AddHours(2));
        var (item, _, _) = rig.Service.AdoptExposure(rig.Facts, Exposure(ExposureStates.Closed, evidence));
        Assert.True(item!.IsClosed);
        var (ok, reason) = rig.Service.Store.VerifyAgainstChain(item.Id);
        Assert.True(ok, reason);
    }

    // ---- audit trail -----------------------------------------------------------

    [Fact]
    public void History_ReconstructsFromChain_AndVerifies()
    {
        var rig = new Rig();
        rig.AddSession("sess-1", Dev);
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Trail check", "tech-1");
        rig.Service.Assign(rig.Facts, item!.Id, "tech-1", "tech-1");
        rig.Service.AttachSession(rig.Facts, item.Id, "sess-1", "tech-1");
        rig.Service.Close(rig.Facts, item.Id, WorkItemOutcomes.Resolved, null, "tech-1");

        var stored = rig.Service.Store.Get(item.Id)!;
        Assert.Equal(4, stored.AuditSeqs.Count); // opened, assigned, attached, closed — references, not copies
        var (ok, reason) = rig.Service.Store.VerifyAgainstChain(item.Id);
        Assert.True(ok, reason);
        var rebuilt = ReconstructedHistory.Reconstruct(rig.Audit.Entries, item.Id);
        Assert.True(rebuilt.Found);
        Assert.Equal(WorkItemStates.Closed, rebuilt.FinalState);
        Assert.Equal(WorkItemOutcomes.Resolved, rebuilt.ClosureOutcome);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- (d) bridge --------------------------------------------------------------

    [Fact]
    public void Bridge_SignedDelivery_Verifies_AndAudits()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
        var (cfgOk, cfgReason) = rig.Service.ConfigureBridge(rig.Facts,
            "https://tickets.example.com/hooks/deskguest", "bridge-secret-0123456789", "admin-1");
        Assert.True(cfgOk, cfgReason);

        var (item, _) = rig.Service.OpenManual(rig.Facts, "Bridge me", "tech-1");
        Assert.NotNull(item);
        var delivery = Assert.Single(rig.Service.Bridge.Deliveries);
        Assert.Equal(BridgeDeliveryStates.Pending, delivery.State);
        Assert.True(BridgeSigning.VerifyPayload(delivery.PayloadJson, "bridge-secret-0123456789"));
        Assert.False(BridgeSigning.VerifyPayload(delivery.PayloadJson, "wrong-secret-0123456789"));

        var changed = rig.Service.PumpBridge();
        var done = Assert.Single(changed);
        Assert.Equal(BridgeDeliveryStates.Delivered, done.State);
        Assert.Equal(1, rig.Transport.Sent.Count);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_delivered");
        // The secret never reaches the audit chain.
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Detail.Contains("bridge-secret"));
    }

    [Fact]
    public void Bridge_DisabledByPolicy_SkipsVisibly_NeverSilently()
    {
        var rig = new Rig();
        rig.Service.ConfigureBridge(rig.Facts, "https://tickets.example.com/hooks/deskguest",
            "bridge-secret-0123456789", "admin-1");
        var (item, _) = rig.Service.OpenManual(rig.Facts, "No bridge", "tech-1");
        Assert.NotNull(item);
        Assert.Empty(rig.Service.Bridge.Deliveries);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_skipped" && e.Detail.Contains(item!.Id));
    }

    [Fact]
    public void Bridge_Unconfigured_EnqueueIsANamedSkip()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Nowhere to send", "tech-1");
        Assert.NotNull(item);
        Assert.Empty(rig.Service.Bridge.Deliveries);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_skipped" && e.Detail.Contains("not configured"));
    }

    [Fact]
    public void NoBillingSurface_OnWorkItemModel()
    {
        // RMM-12 scope law: billing/contracts/invoicing are OUT.
        // The model carries no money/contract/invoice member — if a
        // future edit adds one, this test is the tripwire.
        var props = typeof(WorkItem).GetProperties().Select(p => p.Name).ToList();
        Assert.DoesNotContain(props, n =>
            n.Contains("Bill", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Invoice", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Contract", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Price", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Cost", StringComparison.OrdinalIgnoreCase));
    }
}

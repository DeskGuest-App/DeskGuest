using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Sessions;
using Acp.Shared.WorkItems;
using Xunit;

namespace Acp.Tests;

// RMM-12 DESTRUCTION — hostile pass over the work-item layer:
// auto-close forgery, duplication floods, attachment poisoning,
// request-channel spoofing, bridge abuse (SSRF targets, unsigned
// payloads, retry storms), closure-without-outcome, and history
// rewriting. Every break found converts to a fix + this regression.
// Ledger: ~/workspace/builds/rmm-r-logs/ledger-rmm12.md
public class Rmm12DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string OtherDev = "dev-2";
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
        string conditionId = "disk-low") =>
        new(alertId, deviceId, conditionId, "disk", "warning", HealthAlertStates.Raised,
            T0, T0, 1, "disk below threshold", null, null, null, null, "endpoint");

    // ---- auto-close forgery ------------------------------------------------

    [Fact]
    public void ForgedAlert_DifferentAlertId_ClosesNothing()
    {
        var rig = new Rig();
        rig.Service.OpenWorkItem(Alert("alert-real"), rig.Now);
        // Same device, same condition — but NOT the alert that opened it.
        var (closed, _) = rig.Service.Store.AutoCloseFromAlert(Alert("alert-forged"), "auto-reset: condition cleared", rig.Now);
        Assert.False(closed);
        Assert.Single(rig.Service.Store.OpenItems);
    }

    [Fact]
    public void LaterEpisodeAlert_DoesNotCloseEarlierEpisodeItem()
    {
        var rig = new Rig();
        rig.Service.OpenWorkItem(Alert("alert-ep1"), rig.Now);
        // A NEW alert episode for the same condition fires and resets
        // while ep1's item is still being worked: its reset must not
        // reach back and close ep1's item.
        rig.Service.OpenWorkItem(Alert("alert-ep2"), rig.Now);
        var (closed, _) = rig.Service.Store.AutoCloseFromAlert(Alert("alert-ep2"), "auto-reset: condition cleared", rig.Now);
        Assert.True(closed); // ep2's own item closes
        var ep1 = rig.Service.Store.Get(WorkItem.IdForAlert("alert-ep1"))!;
        Assert.False(ep1.IsClosed);
        Assert.Single(rig.Service.Store.OpenItems);
    }

    [Fact]
    public void AutoClose_NeverOverwritesAHumanClosure()
    {
        var rig = new Rig();
        rig.Service.OpenWorkItem(Alert("alert-1"), rig.Now);
        var id = WorkItem.IdForAlert("alert-1");
        Assert.True(rig.Service.Store.Close(id, WorkItemOutcomes.Resolved, "tech-1", "fixed by hand", rig.Now).Ok);
        var (closed, reason) = rig.Service.Store.AutoCloseFromAlert(Alert("alert-1"), "auto-reset: condition cleared", rig.Now);
        Assert.False(closed);
        Assert.Contains("already closed", reason);
        var item = rig.Service.Store.Get(id)!;
        Assert.Equal(WorkItemOutcomes.Resolved, item.Closure!.Outcome);
        Assert.False(item.Closure.AutoClosed);
    }

    [Fact]
    public void ManualClose_CannotForgeTheAutoCloseOutcomeOrActor()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Forge attempt", "tech-1");
        Assert.False(rig.Service.Store.Close(item!.Id,
            WorkItemOutcomes.AutoClosedConditionReset, "tech-1", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Close(item.Id,
            WorkItemOutcomes.Resolved, WorkItemStore.LifecycleActor, null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Get(item.Id)!.IsClosed);
    }

    // ---- closure without outcome ----------------------------------------------

    [Fact]
    public void ClosureWithoutOutcome_RefusedInAllShapes()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Outcome games", "tech-1");
        Assert.False(rig.Service.Store.Close(item!.Id, null, "tech-1", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Close(item.Id, "", "tech-1", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Close(item.Id, "done-ish", "tech-1", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Close(item.Id, WorkItemOutcomes.Resolved, "", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Get(item.Id)!.IsClosed);
        // Double closure is refused too: closure is singular.
        Assert.True(rig.Service.Store.Close(item.Id, WorkItemOutcomes.Resolved, "tech-1", null, rig.Now).Ok);
        Assert.False(rig.Service.Store.Close(item.Id, WorkItemOutcomes.Resolved, "tech-1", null, rig.Now).Ok);
    }

    // ---- duplication floods -------------------------------------------------------

    [Fact]
    public void SameAlertOpenedFiftyTimes_MintsOneItem()
    {
        var rig = new Rig();
        for (var i = 0; i < 50; i++)
            rig.Service.OpenWorkItem(Alert("alert-flap"), rig.Now);
        Assert.Single(rig.Service.Store.Items);
    }

    [Fact]
    public void AlertFlood_CapRefusesAndCounts()
    {
        var rig = new Rig();
        for (var i = 0; i < WorkItemLimits.MaxOpenAlertItemsPerDevice; i++)
            rig.Service.OpenWorkItem(Alert($"alert-{i}"), rig.Now);
        Assert.Equal(WorkItemLimits.MaxOpenAlertItemsPerDevice, rig.Service.Store.OpenItems.Count);
        var (item, created, _) = rig.Service.Store.OpenFromAlert(Alert("alert-one-too-many"), rig.Now);
        Assert.Null(item);
        Assert.False(created);
        Assert.Equal(WorkItemLimits.MaxOpenAlertItemsPerDevice, rig.Service.Store.Items.Count);
        Assert.True(rig.Service.Store.FloodRefusals[Dev] >= 1);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_item_flood_capped");
    }

    // ---- attachment poisoning -------------------------------------------------------

    [Fact]
    public void SessionFromAnotherDevice_RefusedAndChained()
    {
        var rig = new Rig();
        rig.AddSession("sess-other", OtherDev);
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Poison target", "tech-1");
        var (ok, reason) = rig.Service.AttachSession(rig.Facts, item!.Id, "sess-other", "tech-1");
        Assert.False(ok);
        Assert.Contains(OtherDev, reason);
        Assert.Empty(rig.Service.Store.Get(item.Id)!.Attachments);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_item_attach_refused");
    }

    [Fact]
    public void UnknownSession_Refused_DuplicateAndClosedItemAttachmentsRefused()
    {
        var rig = new Rig();
        rig.AddSession("sess-1", Dev);
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Attach games", "tech-1");
        Assert.False(rig.Service.AttachSession(rig.Facts, item!.Id, "sess-ghost", "tech-1").Ok);
        Assert.True(rig.Service.AttachSession(rig.Facts, item.Id, "sess-1", "tech-1").Ok);
        Assert.False(rig.Service.AttachSession(rig.Facts, item.Id, "sess-1", "tech-1").Ok); // duplicate link
        Assert.True(rig.Service.Close(rig.Facts, item.Id, WorkItemOutcomes.Resolved, null, "tech-1").Ok);
        Assert.False(rig.Service.AttachScript(rig.Facts, item.Id, "script-x", "tech-1").Ok); // closed takes nothing
        Assert.False(rig.Service.Assign(rig.Facts, item.Id, "tech-2", "tech-1").Ok);
        Assert.Single(rig.Service.Store.Get(item.Id)!.Attachments);
    }

    [Fact]
    public void NoteAttachment_CannotSmuggleTextOntoSessionLink()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Smuggle", "tech-1");
        var bad = new WorkItemAttachment(AttachmentKinds.Session, "sess-1", "injected text", "tech-1", rig.Now);
        Assert.False(rig.Service.Store.Attach(item!.Id, bad, rig.Now).Ok);
        Assert.Empty(rig.Service.Store.Get(item.Id)!.Attachments);
    }

    // ---- request-channel spoofing ------------------------------------------------------

    [Fact]
    public void RequestClaimingAnotherDevice_RefusedNoItemSpoofChained()
    {
        var rig = new Rig();
        var spoof = new UserWorkRequest("req-spoof", OtherDev, "mallory", "my computer is slow",
            new DeviceHealthSummary("alerting", new[] { "cpu-high" }, "ok", rig.Now));
        // The request ARRIVES on dev-1's authenticated channel but
        // claims dev-2's identity + context.
        var (item, created, reason) = rig.Service.IntakeRequest(rig.Facts, Dev, spoof);
        Assert.Null(item);
        Assert.False(created);
        Assert.Contains("spoofed", reason);
        Assert.Empty(rig.Service.Store.Items);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_request_spoof_refused");
    }

    [Fact]
    public void RequestOnNoChannel_Refused()
    {
        var rig = new Rig();
        var request = new UserWorkRequest("req-1", Dev, "user", "slow", null);
        var (item, _, _) = rig.Service.Store.IntakeRequest(null, Scope, request, rig.Now);
        Assert.Null(item);
        Assert.Empty(rig.Service.Store.Items);
    }

    // ---- bridge abuse ---------------------------------------------------------------------

    [Theory]
    // REPAIRED (Wave 2 Lane B, 2026-11-22) for bd-shared-rmm-3/F3:
    // the two private-literal rows were removed — under the ONE
    // guard they are the org's own LAN, where a self-hosted PSA
    // legitimately lives; they are asserted ADMITTED in
    // LanPsaTargets_AdmittedAtConfiguration below. Every genuinely
    // SSRF-shaped row (cleartext, loopback, link-local/metadata,
    // localhost, userinfo, non-443, unparseable) stays refused.
    [InlineData("http://tickets.example.com/hook")]            // cleartext
    [InlineData("https://127.0.0.1/hook")]                     // loopback literal
    [InlineData("https://169.254.169.254/latest/meta-data")]   // link-local / metadata
    [InlineData("https://localhost/hook")]                     // localhost
    [InlineData("https://user:pass@tickets.example.com/hook")] // userinfo
    [InlineData("https://tickets.example.com:8443/hook")]      // non-443 port
    [InlineData("not a url")]
    public void SsrfShapedBridgeTargets_RefusedAtConfiguration(string url)
    {
        var rig = new Rig();
        var (ok, _) = rig.Service.ConfigureBridge(rig.Facts, url, "bridge-secret-0123456789", "admin-1");
        Assert.False(ok);
        Assert.False(rig.Service.Bridge.IsConfigured);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_refused");
    }

    [Theory]
    [InlineData("https://10.0.0.5/hook")]                      // private literal = org LAN PSA
    [InlineData("https://192.168.1.10/hook")]                  // private literal = org LAN PSA
    public void LanPsaTargets_AdmittedAtConfiguration(string url)
    {
        // bd-shared-rmm-3/F3: admitted at configuration under the
        // one guard; DNS-rebinding protection lives in the
        // send-time resolved-address check (asserted just below).
        var rig = new Rig();
        var (ok, _) = rig.Service.ConfigureBridge(rig.Facts, url, "bridge-secret-0123456789", "admin-1");
        Assert.True(ok);
        Assert.True(rig.Service.Bridge.IsConfigured);
    }

    [Fact]
    public void BridgeResolvedAddresses_PrivateAnswerRefused()
    {
        Assert.False(BridgeGuard.ValidateResolvedAddresses(new[]
            { System.Net.IPAddress.Parse("93.184.216.34"), System.Net.IPAddress.Parse("10.0.0.1") }));
        Assert.True(BridgeGuard.ValidateResolvedAddresses(new[]
            { System.Net.IPAddress.Parse("93.184.216.34") }));
        Assert.False(BridgeGuard.ValidateResolvedAddresses(Array.Empty<System.Net.IPAddress>()));
        Assert.False(BridgeGuard.ValidateResolvedAddresses(null));
    }

    [Fact]
    public void UnsignedBridge_Refused_NoSecretNoShortSecret()
    {
        var rig = new Rig();
        Assert.False(rig.Service.ConfigureBridge(rig.Facts,
            "https://tickets.example.com/hook", "", "admin-1").Ok);
        Assert.False(rig.Service.ConfigureBridge(rig.Facts,
            "https://tickets.example.com/hook", "short", "admin-1").Ok);
        Assert.False(rig.Service.Bridge.IsConfigured);
    }

    [Fact]
    public void TamperedPayload_FailsVerification()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
        rig.Service.ConfigureBridge(rig.Facts, "https://tickets.example.com/hook",
            "bridge-secret-0123456789", "admin-1");
        rig.Service.OpenManual(rig.Facts, "Tamper target", "tech-1");
        var delivery = Assert.Single(rig.Service.Bridge.Deliveries);
        var tampered = delivery.PayloadJson.Replace("Tamper target", "Forged title");
        Assert.False(BridgeSigning.VerifyPayload(tampered, "bridge-secret-0123456789"));
        Assert.True(BridgeSigning.VerifyPayload(delivery.PayloadJson, "bridge-secret-0123456789"));
    }

    [Fact]
    public void FailingBridge_BackoffThenDead_NeverStormedNeverDropped()
    {
        var rig = new Rig();
        rig.SetPolicy(WorkItemPolicyKeys.BridgeEnabled, "true");
        rig.Transport.Result = (false, "503 from PSA (recording double)");
        rig.Service.ConfigureBridge(rig.Facts, "https://tickets.example.com/hook",
            "bridge-secret-0123456789", "admin-1");
        rig.Service.OpenManual(rig.Facts, "Retry me", "tech-1");

        rig.Service.PumpBridge(); // attempt 1 at T0
        var d = Assert.Single(rig.Service.Bridge.Deliveries);
        Assert.Equal(BridgeDeliveryStates.Failed, d.State);
        Assert.Equal(1, d.Attempts);
        Assert.Equal(T0.AddMinutes(2), d.NextAttemptUtc);

        rig.Service.PumpBridge(); // not yet due — no storm
        Assert.Equal(1, rig.Transport.Sent.Count);

        rig.Now = T0.AddMinutes(2);
        rig.Service.PumpBridge(); // attempt 2
        d = Assert.Single(rig.Service.Bridge.Deliveries);
        Assert.Equal(2, d.Attempts);
        Assert.Equal(T0.AddMinutes(2 + 4), d.NextAttemptUtc);

        rig.Now = T0.AddMinutes(6);
        rig.Service.PumpBridge(); // attempt 3 → dead, visible
        d = Assert.Single(rig.Service.Bridge.Deliveries);
        Assert.Equal(BridgeDeliveryStates.Dead, d.State);
        Assert.Equal(3, d.Attempts);
        Assert.NotNull(d.LastError);
        Assert.Equal(3, rig.Transport.Sent.Count);

        rig.Now = T0.AddDays(1);
        rig.Service.PumpBridge(); // dead is terminal — no resurrection sends
        Assert.Equal(3, rig.Transport.Sent.Count);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "work_bridge_delivery_failed" && e.Detail.Contains("dead"));
    }

    // ---- history rewriting -----------------------------------------------------------------

    [Fact]
    public void TamperedChainExport_VerifyFails()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Chain target", "tech-1");
        rig.Service.Close(rig.Facts, item!.Id, WorkItemOutcomes.Resolved, null, "tech-1");
        var exported = rig.Audit.ExportEntriesJson();
        var tampered = exported.Replace("Chain target", "Forged title");
        var fresh = new ChainedAuditLog();
        var verdict = fresh.ImportEntriesJson(tampered);
        Assert.False(verdict.Ok); // the tamper imports as a BROKEN chain, never silently re-based
    }

    [Fact]
    public void Reconstruction_FromTruncatedChain_DisagreesWithStoredState()
    {
        var rig = new Rig();
        var (item, _) = rig.Service.OpenManual(rig.Facts, "Truncation", "tech-1");
        rig.Service.Close(rig.Facts, item!.Id, WorkItemOutcomes.Resolved, null, "tech-1");
        var stored = rig.Service.Store.Get(item.Id)!;
        Assert.True(stored.IsClosed);
        // Drop the closure event: reconstruction now concludes OPEN,
        // which DISAGREES with the stored closed state — exactly the
        // divergence VerifyAgainstChain names on the full chain.
        var truncated = rig.Audit.Entries.Where(e => e.Kind != "work_item_closed").ToList();
        var rebuilt = ReconstructedHistory.Reconstruct(truncated, item.Id);
        Assert.NotEqual(stored.State, rebuilt.FinalState);
        // And on the intact chain, verification passes.
        Assert.True(rig.Service.Store.VerifyAgainstChain(item.Id).Ok);
    }

    [Fact]
    public void ItemReferences_AreSeqsNotCopies_AndAllResolve()
    {
        var rig = new Rig();
        rig.Service.OpenWorkItem(Alert("alert-1"), rig.Now);
        var item = rig.Service.Store.Get(WorkItem.IdForAlert("alert-1"))!;
        Assert.NotEmpty(item.AuditSeqs);
        foreach (var seq in item.AuditSeqs)
            Assert.Contains(rig.Audit.Entries, e => e.Seq == seq && e.Detail.Contains($"item={item.Id}"));
        Assert.True(rig.Service.Store.VerifyAgainstChain(item.Id).Ok);
    }
}

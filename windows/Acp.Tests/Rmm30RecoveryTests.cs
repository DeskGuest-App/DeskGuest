using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.PeripheralControl;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-30 D38 FIX lane (RECOVERY dispatch #4) — pins for the
// sub-parts of F4/F6/F11 that Rmm30FixTests did not cover.
// The main per-finding regressions live in Rmm30FixTests.cs.
public class Rmm30RecoveryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string User = "user-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts1 = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-a" });
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope, groups: new[] { "grp-b" });
        public RecordingPeripheralControlApplier Applier = new();
        public RecordingPeripheralAlertSink Sink = new();
        public WorkItemStore WorkItems;
        public PeripheralControlService Svc;

        public Rig()
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Policy.AddGroup(new GroupDefinition("grp-b", "Group B", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            Svc = new PeripheralControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, () => Now);
            Svc.Exceptions.RegisterApproverPrincipal(Admin);
        }

        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, 1));
        public void SetEnforce() => SetPolicy(PeripheralKeys.Mode, PeripheralModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(PeripheralKeys.Rules, rules, "doc-rules");
    }

    private static DeviceIdentity Usb(string machine = Dev) =>
        new(machine, DeviceClasses.Storage, "0781", "5567", "SN-001", "USB Stick");

    private static string RuleEntry(string effect, string kind, string anchor, string id) =>
        $"{effect},{kind},org,{Scope},-,{id},{anchor}";

    // F4 (recovery pin) — self-approval refuses even when the
    // requester name IS a registered approver principal: registering
    // a principal grants decision power over OTHER people's
    // requests, never over one's own filing.
    [Fact]
    public void Rec_F4_RegisteredPrincipal_CannotApproveOwnRequest()
    {
        var rig = new Rig();
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-self", Admin, Usb(), "my own stick", Admin);
        var (_, rule, reason) = rig.Svc.ApproveExceptionRequest("req-self", Admin, T0.AddDays(7), Admin);
        Assert.Null(rule);
        Assert.Contains("never self-approve", reason);
        Assert.Equal(PeripheralRequestStates.Pending, rig.Svc.Exceptions.Get("req-self")!.State);
    }

    // F6 (recovery pin) — the service disconnect path is machine-
    // pinned exactly like connect/transfer: an identity naming
    // another machine refuses and closes nothing.
    [Fact]
    public void Rec_F6_Disconnect_WrongMachineIdentity_Refused_LiveWindowStays()
    {
        var rig = new Rig();
        rig.Svc.TraceMediaConnection(Dev, Usb(), "event", User);
        var (rec, reason) = rig.Svc.TraceMediaDisconnection(Dev, Usb(machine: Dev2), User);
        Assert.Null(rec);
        Assert.Contains("inside a media disconnection trace for", reason);
        // The real connection is still live: a transfer still traces.
        var (transfer, _) = rig.Svc.TraceTransfer(Dev, Usb(), "a.txt", 3, new string('a', 64), "event", User);
        Assert.NotNull(transfer);
    }

    // F11e (recovery pin) — an expired exception is NOT re-fed to
    // the resolver on every call: after expiry the device blocks
    // again and the resolution notes carry no expired-rule note
    // (the service feeds LiveExceptionRules only).
    [Fact]
    public void Rec_F11e_ExpiredException_NotRefed_DeviceBlocksAgain_NoExpiredNote()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "device", "0781:5567:SN-001", "r-devblock"));
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "site backups", User);
        var (_, rule, _) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddHours(1), Admin);
        Assert.NotNull(rule);
        var (during, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Allowed, during!.Disposition);

        rig.Now = T0.AddHours(2);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        Assert.DoesNotContain(policy!.Rules, r => r.Id == rule!.Id);
        Assert.DoesNotContain(policy.Notes, n => n.Contains("is expired"));
        var (after, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, after!.Disposition);
    }

    // F11f (recovery pin) — the rule cap is enforced DURING
    // accumulation: a policy string carrying more entries than the
    // cap resolves to exactly the cap, with the excess named.
    [Fact]
    public void Rec_F11f_RuleCap_EnforcedDuringAccumulation_ExcessNamed()
    {
        var rig = new Rig();
        var entries = Enumerable.Range(1, PeripheralLimits.MaxRulesPerPolicy + 5)
            .Select(i => RuleEntry("allow", "class", "storage", $"r{i}"));
        rig.SetRules(string.Join("|", entries));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        Assert.Equal(PeripheralLimits.MaxRulesPerPolicy, policy!.Rules.Count);
        Assert.Contains(policy.Notes, n => n.Contains("more rules than the cap") && n.Contains("5 excess"));
    }
}

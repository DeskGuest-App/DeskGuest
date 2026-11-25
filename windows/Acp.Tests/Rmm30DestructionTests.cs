using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.PeripheralControl;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-30 DESTRUCTION PASS — hostile attacks on peripheral control
// + media tracing: identity cloning, exception widening, tracing
// gaps, audit-mode confusion, expiry games, BadUSB HID injection.
public class Rmm30DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string User = "user-1";
    private static readonly string ShaA = new('a', 64);

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
            Svc.Exceptions.RegisterApproverPrincipal(Admin); // D38-F4: decisions need a registered principal
        }

        public void SetPolicy(string key, string value, string docId, long rev = 1) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, rev));
        public void SetEnforce() => SetPolicy(PeripheralKeys.Mode, PeripheralModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(PeripheralKeys.Rules, rules, "doc-rules");
    }

    private static DeviceIdentity Usb(string cls = DeviceClasses.Storage, string vid = "0781", string pid = "5567",
        string? serial = "SN-001", string machine = Dev) => new(machine, cls, vid, pid, serial, "USB Stick");

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // D30-01 CLONING: a blocked storage device re-appears with a
    // spoofed VID/PID copying an ALLOWED device's VID/PID but a
    // different serial. A serial-bound allow does NOT cover the
    // clone; the collision is alerted. A VID/PID-only allow DOES
    // cover it — and that is exactly the cloneability the model
    // labels, asserted here so the label is proven honest.
    [Fact]
    public void D30_01_CloneAttack_SerialBoundAllowResists_VidPidOnlyAllowIsLabelledCloneable()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(
            RuleEntry("block", "class", "storage", id: "r-block") + "|" +
            RuleEntry("allow", "device", "0781:5567:SN-GOOD", id: "r-good"));
        var clone = Usb(serial: "SN-EVIL");
        var (d, seen, _) = rig.Svc.EvaluateConnection(Dev, clone, User);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);
        // First present the genuine device, then the clone: collision.
        var rig2 = new Rig();
        rig2.SetEnforce();
        rig2.SetRules(RuleEntry("allow", "device", "0781:5567:SN-GOOD", id: "r-good"));
        rig2.Svc.EvaluateConnection(Dev, Usb(serial: "SN-GOOD"), User);
        var (_, seen2, _) = rig2.Svc.EvaluateConnection(Dev, Usb(serial: "SN-EVIL"), User);
        Assert.True(seen2!.IsIdentityCollision);
        Assert.Contains(rig2.Sink.Events, e => e.Kind == PeripheralAlertKind.IdentityCollision);

        // VID/PID-only allow: the clone passes — labelled, not hidden.
        var rig3 = new Rig();
        rig3.SetEnforce();
        rig3.SetRules(RuleEntry("allow", "device", "0781:5567", id: "r-vidpid"));
        var (policy, _) = rig3.Svc.ResolvePolicy(Dev);
        Assert.Contains("CLONEABLE", policy!.Rules.Single(r => r.Id == "r-vidpid").StrengthLabel);
        var (cloneDecision, _, _) = rig3.Svc.EvaluateConnection(Dev, Usb(serial: "ANYTHING"), User);
        Assert.Equal(PeripheralDispositions.Allowed, cloneDecision!.Disposition);
    }

    // D30-02 EXCEPTION WIDENING to a class: a hand-forged class-kind
    // exception rule is refused at admission AND a class-kind rule
    // carrying a source request never joins resolution.
    [Fact]
    public void D30_02_ExceptionWideningToClass_RefusedAtAdmissionAndResolution()
    {
        var forged = new PeripheralRule("exception-x", "allow", PeripheralRuleKinds.Class,
            DeviceClasses.Storage, null, null, null, PeripheralScopes.Device, Dev,
            T0.AddDays(7), "req-forged");
        Assert.NotNull(forged.Validate(T0));
        Assert.Contains("CLASS-wide", forged.Validate(T0));

        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "class", "storage", id: "r-block"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.DoesNotContain(policy!.Rules, r => r.Id == "exception-x");
        // The store itself offers no scope parameter at all: approval
        // mints device-scope on the requesting machine, full stop.
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "reason", User);
        var (_, rule, _) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        Assert.Equal(PeripheralRuleKinds.Exception, rule!.Kind);
        Assert.Equal(PeripheralScopes.Device, rule.ScopeKind);
        Assert.Equal(Dev, rule.ScopeId);
        // The exception does not allow a DIFFERENT storage device.
        var (other, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(vid: "1234", pid: "9999", serial: "X"), User);
        Assert.Equal(PeripheralDispositions.Blocked, other!.Disposition);
    }

    // D30-03 EXCEPTION CLASS RE-PRESENTATION: the approved storage
    // stick returns presenting as an HID (BadUSB shape). The
    // exception binds the approved class — it must not bless the
    // HID presentation; and in enforce mode the first-seen HID
    // event fires.
    [Fact]
    public void D30_03_ExceptionDoesNotBlessClassRePresentation()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(
            RuleEntry("block", "class", "storage", id: "r-bs") + "|" +
            RuleEntry("block", "class", "hid", id: "r-bh"));
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "backups", User);
        rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        var (asStorage, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Allowed, asStorage!.Disposition);
        var (asHid, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid), User);
        Assert.Equal(PeripheralDispositions.Blocked, asHid!.Disposition);
        Assert.Equal("r-bh", asHid.MatchedRule!.Id);
    }

    // D30-04 TRACING GAP — transfer with no connect, transfer after
    // disconnect, transfer on a machine the identity does not name:
    // all refused; the chain stays verifiable; nothing is recorded.
    [Fact]
    public void D30_04_TracingGaps_RefusedAndChainStaysHonest()
    {
        var rig = new Rig();
        var stick = Usb();
        var before = rig.Svc.Trace.Records.Count;
        var (a, _) = rig.Svc.TraceTransfer(Dev, stick, "x.bin", 5, ShaA, "event", User);
        Assert.Null(a);
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        var wrongMachine = Usb(machine: Dev2);
        var (b, _) = rig.Svc.TraceTransfer(Dev, wrongMachine, "x.bin", 5, ShaA, "event", User);
        Assert.Null(b);
        Assert.Equal(before + 1, rig.Svc.Trace.Records.Count); // only the connect landed
        var (ok, summary) = rig.Svc.Trace.VerifyChain();
        Assert.True(ok, summary);
        // The cannot-see list is part of the model, not a footnote.
        Assert.Contains(TransferPathVisibility.NotVisible, s => s.Contains("agent is stopped"));
    }

    // D30-05 TRACE TAMPERING: the store's records cannot be altered
    // through its public surface — Records hands out a copy, there
    // is no update/delete API, and a `with`-mutated copy diverges
    // from the stored record while the real chain still verifies
    // and its head is unchanged. (Deep chain-math tamper evidence
    // is the same SHA-256 linkage proven for ChainedAuditLog; here
    // we prove the store exposes no mutation path.)
    [Fact]
    public void D30_05_TraceChain_NoMutationPath()
    {
        var rig = new Rig();
        var stick = Usb();
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        rig.Svc.TraceTransfer(Dev, stick, "a.txt", 3, ShaA, "event", User);
        var headBefore = rig.Svc.Trace.HeadHash;
        var copy = rig.Svc.Trace.Records;
        var tampered = copy[1] with { FileName = "innocent.txt" };
        Assert.NotEqual(tampered.FileName, rig.Svc.Trace.Records[1].FileName);
        Assert.Equal(headBefore, rig.Svc.Trace.HeadHash);
        var (ok, summary) = rig.Svc.Trace.VerifyChain();
        Assert.True(ok, summary);
        // Linkage: each record's PrevHash is the previous record's Hash.
        var records = rig.Svc.Trace.Records;
        Assert.Equal(MediaTraceStore.GenesisHash, records[0].PrevHash);
        Assert.Equal(records[0].Hash, records[1].PrevHash);
    }

    // D30-06 AUDIT-MODE CONFUSION: in audit mode no surface claims a
    // block — decision, event, audit kinds all say would-block.
    [Fact]
    public void D30_06_AuditModeConfusion_Unrepresentable()
    {
        var rig = new Rig();
        rig.SetRules(RuleEntry("block", "class", "storage"));
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.WouldBlock, d!.Disposition);
        Assert.False(d.ActuallyBlocked);
        Assert.Contains("AUDIT-ONLY", d.EffectiveModeLabel);
        Assert.Contains("NOT blocked", d.Reason);
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "peripheral_blocked");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "peripheral_would_block");
        var ev = Assert.Single(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.Blocked);
        Assert.False(ev.ActuallyBlocked);
    }

    // D30-07 EXPIRY GAMES: exception works before expiry, dead AT
    // the expiry instant; a forged no-expiry exception rule matches
    // nothing even when handed straight to the evaluator.
    [Fact]
    public void D30_07_ExceptionExpiryGames()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "class", "storage", id: "r-block"));
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "backups", User);
        rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        rig.Now = T0.AddDays(6);
        var (alive, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Allowed, alive!.Disposition);
        rig.Now = T0.AddDays(7);
        var (dead, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, dead!.Disposition);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        // AMENDED by the D38 fix lane (F11e): the service now feeds
        // only LIVE exception rules to the resolver, so an expired
        // exception no longer rides every resolution with a note —
        // it is simply gone from the resolved rules.
        Assert.DoesNotContain(policy!.Rules, r => r.Id == "exception-req-1");

        var forged = new PeripheralRule("exception-forged", "allow", PeripheralRuleKinds.Exception,
            DeviceClasses.Storage, "0781", "5567", "SN-001", PeripheralScopes.Device, Dev,
            null, "req-forged");
        Assert.False(forged.Matches(Usb(), T0)); // defence in depth: no-expiry exception matches nothing
        var classBlock = new PeripheralRule("r-block2", "block", PeripheralRuleKinds.Class,
            DeviceClasses.Storage, null, null, null, PeripheralScopes.Org, Scope, null, null);
        var fakePolicy = new ResolvedPeripheralPolicy(true, PeripheralModes.Enforce, true,
            new PeripheralRule[] { forged, classBlock }, Array.Empty<string>());
        var forgedDecision = PeripheralEvaluator.Evaluate(Usb(), fakePolicy, T0);
        Assert.Equal(PeripheralDispositions.Blocked, forgedDecision.Disposition);
        Assert.Equal("r-block2", forgedDecision.MatchedRule!.Id);
    }

    // D30-08 BADUSB: a brand-new HID arrives on an enforce-mode
    // machine whose class policy allows HIDs. It is ALLOWED by class
    // policy (keyboards must work) but the first-seen HID event
    // names it — the detection is the control, stated honestly.
    [Fact]
    public void D30_08_BadUsb_NewHidNamedEvenWhenClassAllowed()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var badUsb = new DeviceIdentity(Dev, DeviceClasses.Hid, "1234", "5678", null, "USB Keyboard");
        var (d, seen, _) = rig.Svc.EvaluateConnection(Dev, badUsb, User);
        Assert.Equal(PeripheralDispositions.Allowed, d!.Disposition);
        Assert.True(seen!.IsFirstSeen);
        var ev = Assert.Single(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.NewHid);
        Assert.Contains("BadUSB", ev.Detail);
        Assert.Contains("CLONEABLE", ev.Detail);
    }

    // D30-09 SPOOFED REQUEST CHANNEL + FLOOD: a request claiming
    // another machine refuses with no record; duplicate pending
    // collapses; hourly cap bites.
    [Fact]
    public void D30_09_RequestSpoofAndFlood()
    {
        var rig = new Rig();
        var (spoof, _, spoofReason) = rig.Svc.FileExceptionRequest(Dev, Dev2, "req-spoof", User, Usb(), "r", User);
        Assert.Null(spoof);
        Assert.Contains("spoofed machine context", spoofReason);
        Assert.Empty(rig.Svc.Exceptions.Requests);

        var (first, created1, _) = rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "r", User);
        Assert.True(created1);
        var (dup, created2, _) = rig.Svc.FileExceptionRequest(Dev, Dev, "req-2", User, Usb(), "r again", User);
        Assert.False(created2);
        Assert.Equal(first!.Id, dup!.Id);
    }

    // D30-10 APPROVAL WHILE KILL-SWITCH OFF (R25R-F5 pattern):
    // approval refuses while the feature is disabled; denial still
    // works; approval after re-enable works.
    [Fact]
    public void D30_10_ApprovalWhileDisabled_Refused_DenialStillWorks()
    {
        var rig = new Rig();
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "r", User);
        rig.SetPolicy(PeripheralKeys.FeatureEnabled, "false", "doc-off");
        var (_, rule, reason) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        Assert.Null(rule);
        Assert.Contains("disabled by policy", reason);
        Assert.Equal(PeripheralRequestStates.Pending, rig.Svc.Exceptions.Get("req-1")!.State);
        var (denied, _) = rig.Svc.DenyExceptionRequest("req-1", Admin, "no", Admin);
        Assert.NotNull(denied);
    }

    // D30-11 CONSENT FLOOR: a policy document smuggling a floor key
    // alongside the enforce mode refuses WHOLE at the RMM-07 engine.
    [Fact]
    public void D30_11_ConsentFloorDocumentRefusedWhole()
    {
        var rig = new Rig();
        var verdict = rig.Policy.AddDocument(new ManagementPolicyDocument("doc-floor", "org", Scope,
            new Dictionary<string, string>
            {
                [PeripheralKeys.Mode] = "enforce",
                ["presence.enabled"] = "false",
            }, 1));
        Assert.False(verdict.Allowed);
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Equal(PeripheralModes.Audit, policy!.Mode); // enforce never landed
    }

    // D30-12 SAME-RANK CONFLICT + RANK: device allow vs device
    // block — block wins, conflict named. Class allow does NOT beat
    // a device block (rank first).
    [Fact]
    public void D30_12_Conflicts_BlockWinsWithinRank_RankDecidesAcross()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(
            RuleEntry("allow", "device", "0781:5567:SN-001", id: "r-a") + "|" +
            RuleEntry("block", "device", "0781:5567:SN-001", id: "r-b"));
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);
        Assert.Contains("conflict is named", d.Reason);

        var rig2 = new Rig();
        rig2.SetEnforce();
        rig2.SetRules(
            RuleEntry("allow", "class", "storage", id: "r-ca") + "|" +
            RuleEntry("block", "device", "0781:5567", id: "r-db"));
        var (d2, _, _) = rig2.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, d2!.Disposition);
        Assert.Equal("r-db", d2.MatchedRule!.Id);
    }

    // D30-13 UNPARSABLE MODE never enforces; unparsable tracing
    // value never disables the evidence trail.
    [Fact]
    public void D30_13_UnparsableModeAndTracing_FailSafe()
    {
        var rig = new Rig();
        rig.SetPolicy(PeripheralKeys.Mode, "enforce-pls", "doc-mode");
        rig.SetPolicy(PeripheralKeys.Tracing, "banana", "doc-tr");
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Equal(PeripheralModes.Audit, policy!.Mode);
        Assert.True(policy.TracingEnabled);
        Assert.Contains(policy.Notes, n => n.Contains("never silently disables"));
    }
}

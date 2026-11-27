using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.PeripheralControl;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Tests;

// RMM-30 — USB/peripheral control + removable-media tracing:
// class + device-identity rules (VID/PID + serial, strength
// labelled), audit (default) vs enforce, media connect + transfer
// tracing (name+size+hash, hash-chained), machine-pinned expiring
// exceptions via the approval workflow over RMM-12 work items.
public class Rmm30Tests
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

        public void SetPolicy(string key, string value, string docId, long rev = 1, string level = "org", string target = Scope) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, level, target,
                new Dictionary<string, string> { [key] = value }, rev));
        public void SetEnforce() => SetPolicy(PeripheralKeys.Mode, PeripheralModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(PeripheralKeys.Rules, rules, "doc-rules");
    }

    private static DeviceIdentity Usb(string cls = DeviceClasses.Storage, string vid = "0781", string pid = "5567",
        string? serial = "SN-001", string machine = Dev, string? display = "USB Stick") =>
        new(machine, cls, vid, pid, serial, display);

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    [Fact]
    public void Identity_SerialBound_IsLabelledStrong_VidPidOnly_IsLabelledCloneable()
    {
        Assert.Contains("strong", Usb().StrengthLabel);
        var cloneable = Usb(serial: null);
        Assert.Contains("CLONEABLE", cloneable.StrengthLabel);
        Assert.Contains("unauthenticated", cloneable.StrengthLabel);
    }

    [Fact]
    public void Identity_TooThinOrMalformed_Refused()
    {
        Assert.NotNull(new DeviceIdentity(Dev, DeviceClasses.Storage, null, null, null, "name only").Validate());
        Assert.NotNull(new DeviceIdentity(Dev, DeviceClasses.Storage, "zzzz", "5567", "S1", null).Validate());
        Assert.NotNull(new DeviceIdentity(Dev, DeviceClasses.Storage, "0781", null, "S1", null).Validate());
        Assert.NotNull(new DeviceIdentity(Dev, "hovercraft", "0781", "5567", "S1", null).Validate());
        Assert.Null(Usb().Validate());
        Assert.Null(new DeviceIdentity(Dev, DeviceClasses.Printer, null, null, "PRN-SERIAL-1", null).Validate());
    }

    [Fact]
    public void DefaultMode_IsAudit_AndNamedInNotes()
    {
        var rig = new Rig();
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.NotNull(policy);
        Assert.Equal(PeripheralModes.Audit, policy!.Mode);
        Assert.Contains("AUDIT-ONLY", policy.EffectiveModeLabel);
        Assert.Contains(policy.Notes, n => n.Contains("AUDIT-ONLY"));
        Assert.True(policy.TracingEnabled);
    }

    [Fact]
    public void ClassBlock_Enforce_BlocksStorage_Audit_WouldBlockOnly()
    {
        var auditRig = new Rig();
        auditRig.SetRules(RuleEntry("block", "class", "storage"));
        var (d1, _, _) = auditRig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.WouldBlock, d1!.Disposition);
        Assert.False(d1.ActuallyBlocked);
        Assert.Single(auditRig.Sink.Events, e => e.Kind == PeripheralAlertKind.Blocked && !e.ActuallyBlocked);

        var enforceRig = new Rig();
        enforceRig.SetEnforce();
        enforceRig.SetRules(RuleEntry("block", "class", "storage"));
        var (d2, _, _) = enforceRig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, d2!.Disposition);
        Assert.True(d2.ActuallyBlocked);
        Assert.Contains(enforceRig.Audit.Entries, e => e.Kind == "peripheral_blocked");
    }

    [Fact]
    public void DeviceRule_BeatsClassRule_SerialBoundMatchesExactly()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(
            RuleEntry("block", "class", "storage", id: "r-class") + "|" +
            RuleEntry("allow", "device", "0781:5567:SN-001", id: "r-dev"));
        var (allowed, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Allowed, allowed!.Disposition);
        Assert.Equal("r-dev", allowed.MatchedRule!.Id);
        // Same VID/PID, different serial: the serial-bound allow does
        // not cover it; the class block decides.
        var (blocked, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(serial: "SN-999"), User);
        Assert.Equal(PeripheralDispositions.Blocked, blocked!.Disposition);
        Assert.Equal("r-class", blocked.MatchedRule!.Id);
    }

    [Fact]
    public void NoMatchingRule_DefaultAllow_ExceptUnknownClassGuardInEnforce()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var (kb, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid), User);
        Assert.Equal(PeripheralDispositions.Allowed, kb!.Disposition);
        var (mystery, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Unknown), User);
        Assert.Equal(PeripheralDispositions.Blocked, mystery!.Disposition);
        Assert.Contains("unknown-class guard", mystery.Reason);
    }

    [Fact]
    public void FeatureDisabled_ByEitherSpelling_NotControlled()
    {
        var rig = new Rig();
        rig.SetPolicy(PeripheralKeys.FeatureEnabled, "false", "doc-off");
        var (d, _, reason) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Null(d);
        Assert.Contains("disabled by policy", reason);

        var rig2 = new Rig();
        rig2.SetPolicy(PeripheralKeys.FeatureEnabledSeeded, "false", "doc-off2");
        var (policy2, _) = rig2.Svc.ResolvePolicy(Dev);
        Assert.Null(policy2);
    }

    [Fact]
    public void MalformedRuleEntries_DroppedAndNamed_ValidRulesStillApply()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules("garbage-entry|" + RuleEntry("block", "class", "bluetooth", id: "r-bt"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("malformed rule entry"));
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Bluetooth), User);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);
    }

    [Fact]
    public void MediaConnection_AndTransfer_TracedWithChain_AndMetadataOnly()
    {
        var rig = new Rig();
        var stick = Usb();
        var (conn, _) = rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        Assert.NotNull(conn);
        var (transfer, reason) = rig.Svc.TraceTransfer(Dev, stick, "report.pdf", 12345, ShaA, "event", User);
        Assert.NotNull(transfer);
        Assert.Equal("report.pdf", transfer!.FileName);
        Assert.Equal(12345, transfer.FileSizeBytes);
        Assert.Equal(ShaA, transfer.FileSha256);
        var (ok, summary) = rig.Svc.Trace.VerifyChain();
        Assert.True(ok, summary);
        // Metadata only: the record type carries no content member.
        Assert.DoesNotContain(typeof(MediaTraceRecord).GetProperties(),
            p => p.Name.Contains("Content") || p.Name.Contains("Bytes") && p.Name != "FileSizeBytes");
    }

    [Fact]
    public void Transfer_WithoutConnection_Refused_PathNamesAndBadHashRefused()
    {
        var rig = new Rig();
        var stick = Usb();
        var (orphan, orphanReason) = rig.Svc.TraceTransfer(Dev, stick, "a.txt", 1, ShaA, "event", User);
        Assert.Null(orphan);
        Assert.Contains("no live media connection", orphanReason);
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        var (pathName, _) = rig.Svc.TraceTransfer(Dev, stick, @"C:\Users\user-1\secret.txt", 1, ShaA, "event", User);
        Assert.Null(pathName);
        var (badHash, _) = rig.Svc.TraceTransfer(Dev, stick, "a.txt", 1, "notahash", "event", User);
        Assert.Null(badHash);
        var (afterDisconnect, _) = rig.Svc.Trace.RecordDisconnection(stick, rig.Now);
        Assert.NotNull(afterDisconnect);
        var (late, lateReason) = rig.Svc.TraceTransfer(Dev, stick, "a.txt", 1, ShaA, "event", User);
        Assert.Null(late);
        Assert.Contains("no live media connection", lateReason);
    }

    [Fact]
    public void TracingDisabledByPolicy_RefusalIsNamedAndAudited_NeverSilent()
    {
        var rig = new Rig();
        rig.SetPolicy(PeripheralKeys.Tracing, "false", "doc-trace-off");
        var (rec, reason) = rig.Svc.TraceMediaConnection(Dev, Usb(), "event", User);
        Assert.Null(rec);
        Assert.Contains("NOT traced", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "media_trace_refused");
    }

    [Fact]
    public void TransferPathVisibility_NamesWhatItCannotSee()
    {
        Assert.Contains(TransferPathVisibility.NotVisible, s => s.Contains("raw disk"));
        Assert.Contains(TransferPathVisibility.NotVisible, s => s.Contains("encrypted containers"));
        Assert.Contains("NOT TRACED", TransferPathVisibility.CoverageStatement);
    }

    [Fact]
    public void IdentityCollision_TwoSerialsOneVidPid_RaisesAlertAndAudit()
    {
        var rig = new Rig();
        rig.Svc.EvaluateConnection(Dev, Usb(serial: "SN-001"), User);
        var (_, seen, _) = rig.Svc.EvaluateConnection(Dev, Usb(serial: "SN-002"), User);
        Assert.True(seen!.IsIdentityCollision);
        Assert.Contains(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.IdentityCollision);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "peripheral_identity_collision");
    }

    [Fact]
    public void NewHid_InEnforce_RaisesNamedEvent_EvenWhenAllowed()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var (d, seen, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid, serial: "KB-1"), User);
        Assert.Equal(PeripheralDispositions.Allowed, d!.Disposition);
        Assert.True(seen!.IsFirstSeen);
        var ev = Assert.Single(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.NewHid);
        Assert.Contains("BadUSB", ev.Detail);
        // Second connect of the same HID: no new-HID event again.
        rig.Sink.Events.Clear();
        rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid, serial: "KB-1"), User);
        Assert.DoesNotContain(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.NewHid);
    }

    // AMENDED by the D38 fix lane (F9): this test originally locked
    // in the defect — audit mode produced NO new-HID detection at
    // all. The event blocks nothing, so detection now fires in
    // every mode; ActuallyBlocked stays false in audit.
    [Fact]
    public void NewHid_InAuditMode_RaisesDetectionEvent_ButBlocksNothing()
    {
        var rig = new Rig();
        rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid, serial: "KB-1"), User);
        var ev = Assert.Single(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.NewHid);
        Assert.False(ev.ActuallyBlocked);
    }

    [Fact]
    public void ExceptionWorkflow_FileApprove_AllowsExactDeviceOnExactMachineOnly()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "class", "storage", id: "r-class"));
        var stick = Usb();
        var (req, created, _) = rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, stick, "need to copy site backups", User);
        Assert.True(created);
        Assert.NotNull(req);
        Assert.Contains(rig.WorkItems.Items, i => i.RequestId == "req-1");
        var (blockedBefore, _, _) = rig.Svc.EvaluateConnection(Dev, stick, User);
        Assert.Equal(PeripheralDispositions.Blocked, blockedBefore!.Disposition);

        var (approved, rule, _) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        Assert.NotNull(approved);
        Assert.NotNull(rule);
        Assert.Equal(PeripheralScopes.Device, rule!.ScopeKind);
        Assert.Equal(Dev, rule.ScopeId);

        var (allowed, _, _) = rig.Svc.EvaluateConnection(Dev, stick, User);
        Assert.Equal(PeripheralDispositions.Allowed, allowed!.Disposition);
        // Other machine: still blocked (exception is machine-pinned).
        var stickOnDev2 = Usb(machine: Dev2);
        rig.SetRules(RuleEntry("block", "class", "storage", id: "r-class")); // org rule already applies; resolution for dev2 must not see the exception
        var (dev2Decision, _, _) = rig.Svc.EvaluateConnection(Dev2, stickOnDev2, User);
        Assert.Equal(PeripheralDispositions.Blocked, dev2Decision!.Disposition);
        // Different serial on same machine: still blocked.
        var (other, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(serial: "SN-777"), User);
        Assert.Equal(PeripheralDispositions.Blocked, other!.Disposition);
    }

    [Fact]
    public void ExceptionApproval_NoExpiryOrOverLongOrSelfApproval_Refused()
    {
        var rig = new Rig();
        var stick = Usb();
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, stick, "reason", User);
        var (_, noExpiry, noExpiryReason) = rig.Svc.ApproveExceptionRequest("req-1", Admin, null, Admin);
        Assert.Null(noExpiry);
        Assert.Contains("MUST carry an expiry", noExpiryReason);
        var (_, overLong, _) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(200), Admin);
        Assert.Null(overLong);
        var (_, self, selfReason) = rig.Svc.ApproveExceptionRequest("req-1", User, T0.AddDays(7), User);
        Assert.Null(self);
        Assert.Contains("self-approve", selfReason);
        Assert.Equal(PeripheralRequestStates.Pending, rig.Svc.Exceptions.Get("req-1")!.State);
    }

    [Fact]
    public void ExceptionDenial_RecordedWithReason()
    {
        var rig = new Rig();
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "reason", User);
        var (denied, reason) = rig.Svc.DenyExceptionRequest("req-1", Admin, "use the hub transfer instead", Admin);
        Assert.NotNull(denied);
        Assert.Equal(PeripheralRequestStates.Denied, denied!.State);
        Assert.Contains("hub transfer", denied.DecisionReason);
        Assert.Contains("denied", reason);
    }

    [Fact]
    public void EvaluateAndApply_UnavailableApplier_ReportsNotAppliedHonestly()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var svc = new PeripheralControlService(audit, policy, new UnavailablePeripheralControlApplier(),
            new RecordingPeripheralAlertSink(), new WorkItemStore(audit),
            id => StaticDeviceFacts.Of(Dev, Scope), () => T0);
        var (result, reason) = svc.EvaluateAndApply(Dev, User);
        Assert.NotNull(result);
        Assert.False(result!.Applied);
        Assert.Contains("NOT applied", reason);
        Assert.Contains(audit.Entries, e => e.Kind == "peripheral_not_applied");
    }

    [Fact]
    public void BlockEvent_LandsInHealthAlertCentre_WithFullIdentity()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var svc = new PeripheralControlService(audit, policy, new RecordingPeripheralControlApplier(),
            new HealthAlertCentrePeripheralSink(centre), new WorkItemStore(audit),
            id => StaticDeviceFacts.Of(Dev, Scope), () => T0);
        policy.AddDocument(new ManagementPolicyDocument("doc-m", "org", Scope,
            new Dictionary<string, string> { [PeripheralKeys.Mode] = "enforce" }, 1));
        policy.AddDocument(new ManagementPolicyDocument("doc-r", "org", Scope,
            new Dictionary<string, string> { [PeripheralKeys.Rules] = RuleEntry("block", "class", "storage") }, 1));
        svc.EvaluateConnection(Dev, Usb(), User);
        var alert = Assert.Single(centre.Alerts);
        Assert.Equal(PeripheralAlertKind.Blocked, alert.Kind);
        Assert.Contains("SN-001", alert.Detail);
        Assert.Contains("0781", alert.Detail);
    }
}

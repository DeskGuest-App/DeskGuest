using System.Reflection;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.PeripheralControl;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-30 D38 FIX lane — regression tests for packet d1925bf2
// (12 findings, F1–F12). Each test pins the FIXED behaviour; the
// finding number is in the test name.
public class Rmm30FixTests
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

        public Rig(bool registerAdmin = true)
        {
            Policy.AddGroup(new GroupDefinition("grp-a", "Group A", Array.Empty<GroupRule>()));
            Policy.AddGroup(new GroupDefinition("grp-b", "Group B", Array.Empty<GroupRule>()));
            WorkItems = new WorkItemStore(Audit);
            Svc = new PeripheralControlService(Audit, Policy, Applier, Sink, WorkItems,
                id => id == Dev ? Facts1 : id == Dev2 ? Facts2 : null, () => Now);
            if (registerAdmin) Svc.Exceptions.RegisterApproverPrincipal(Admin);
        }

        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope,
                new Dictionary<string, string> { [key] = value }, 1));
        public void SetEnforce() => SetPolicy(PeripheralKeys.Mode, PeripheralModes.Enforce, "doc-mode");
        public void SetRules(string rules) => SetPolicy(PeripheralKeys.Rules, rules, "doc-rules");
    }

    private static DeviceIdentity Usb(string cls = DeviceClasses.Storage, string vid = "0781", string pid = "5567",
        string? serial = "SN-001", string machine = Dev, string? display = "USB Stick") =>
        new(machine, cls, vid, pid, serial, display);

    private static string RuleEntry(string effect, string kind, string anchor,
        string scopeKind = "org", string scopeId = Scope, string expires = "-", string id = "r1") =>
        $"{effect},{kind},{scopeKind},{scopeId},{expires},{id},{anchor}";

    // F1 — an identity that fails validation (unrecognised class
    // string; no VID/PID and no serial) gets a GUARD decision and a
    // block alert — never a silent null.
    [Fact]
    public void F1_UnidentifiableDevice_GetsGuardDecisionAndAlert()
    {
        var rig = new Rig();
        rig.SetEnforce();
        var mystery = new DeviceIdentity(Dev, "hovercraft", "0781", "5567", "S1", null);
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, mystery, User);
        Assert.NotNull(d);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);
        Assert.Contains("unidentifiable-device guard", d.Reason);
        var ev = Assert.Single(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.Blocked);
        Assert.True(ev.ActuallyBlocked);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "peripheral_blocked");

        var thin = new DeviceIdentity(Dev, DeviceClasses.Storage, null, null, null, "name only");
        var (d2, _, _) = rig.Svc.EvaluateConnection(Dev, thin, User);
        Assert.Equal(PeripheralDispositions.Blocked, d2!.Disposition);

        var auditRig = new Rig(); // audit is the default mode
        var (d3, _, _) = auditRig.Svc.EvaluateConnection(Dev, mystery, User);
        Assert.Equal(PeripheralDispositions.WouldBlock, d3!.Disposition);
        Assert.False(d3.ActuallyBlocked);
        Assert.Contains(auditRig.Sink.Events, e => e.Kind == PeripheralAlertKind.Blocked && !e.ActuallyBlocked);
    }

    // F2 — TraceMediaConnection refuses an identity naming another
    // machine than the one whose policy was resolved.
    [Fact]
    public void F2_TraceMediaConnection_WrongMachineIdentity_Refused()
    {
        var rig = new Rig();
        var (rec, reason) = rig.Svc.TraceMediaConnection(Dev, Usb(machine: Dev2), "event", User);
        Assert.Null(rec);
        Assert.Contains("inside a media connection trace for", reason);
        Assert.Empty(rig.Svc.Trace.Records);
        var (ok, _) = rig.Svc.TraceMediaConnection(Dev, Usb(), "event", User);
        Assert.NotNull(ok);
    }

    // F3 — a request ID taken on machine A discloses NOTHING to
    // machine B and does not block B from filing under a fresh ID.
    [Fact]
    public void F3_CrossMachineRequestIdCollision_RefusedWithoutDisclosure()
    {
        var rig = new Rig();
        var (a, created, _) = rig.Svc.FileExceptionRequest(Dev, Dev, "req-x", User, Usb(), "A-secret-reason", User);
        Assert.True(created);
        var (b, bCreated, bReason) = rig.Svc.FileExceptionRequest(Dev2, Dev2, "req-x", "mallory",
            Usb(machine: Dev2), "B reason", "mallory");
        Assert.Null(b);
        Assert.False(bCreated);
        Assert.Contains("already in use on another machine", bReason);
        Assert.DoesNotContain("A-secret-reason", bReason);
        Assert.DoesNotContain(User, bReason);
        Assert.Equal(Dev, rig.Svc.Exceptions.Get("req-x")!.MachineId);
        var (b2, b2Created, _) = rig.Svc.FileExceptionRequest(Dev2, Dev2, "req-y", "mallory",
            Usb(machine: Dev2), "B reason", "mallory");
        Assert.True(b2Created);
        Assert.NotNull(b2);
        // Same-machine idempotent filing still returns the standing request.
        var (again, againCreated, _) = rig.Svc.FileExceptionRequest(Dev, Dev, "req-x", User, Usb(), "A-secret-reason", User);
        Assert.False(againCreated);
        Assert.Equal(a!.Id, again!.Id);
    }

    // F4 — decisions require a REGISTERED approver principal;
    // a free-text invented approver is refused, and with no
    // principals registered at all the store fails closed.
    [Fact]
    public void F4_UnregisteredApprover_Refused_NoPrincipals_FailsClosed()
    {
        var rig = new Rig();
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "reason", User);
        var (_, rule, reason) = rig.Svc.ApproveExceptionRequest("req-1", "mallory-invented", T0.AddDays(7), "mallory-invented");
        Assert.Null(rule);
        Assert.Contains("not a registered approver principal", reason);
        Assert.Equal(PeripheralRequestStates.Pending, rig.Svc.Exceptions.Get("req-1")!.State);
        var (_, denyReason) = rig.Svc.DenyExceptionRequest("req-1", "mallory-invented", "no", "mallory-invented");
        Assert.Contains("not a registered approver principal", denyReason);

        var bare = new Rig(registerAdmin: false);
        bare.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "reason", User);
        var (_, rule2, reason2) = bare.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        Assert.Null(rule2);
        Assert.Contains("no approver principals are registered", reason2);
    }

    // F5a — policy text cannot author an exception; an exception
    // rule past the 90-day cap or with no class binding is refused
    // at Validate.
    [Fact]
    public void F5_PolicyAuthoredException_Dropped_CapAndClassBindingEnforcedAtValidate()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("allow", "exception", "0781:5567:SN-001", id: "r-exc") + "|" +
                     RuleEntry("block", "class", "storage", id: "r-block"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.DoesNotContain(policy!.Rules, r => r.Id == "r-exc");
        Assert.Contains(policy.Notes, n => n.Contains("kind=exception") && n.Contains("approval workflow only"));
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);

        var overLong = new PeripheralRule("exception-long", "allow", PeripheralRuleKinds.Exception,
            DeviceClasses.Storage, "0781", "5567", "SN-001", PeripheralScopes.Device, Dev,
            new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero), "req-1");
        Assert.Contains("maximum exception lifetime", overLong.Validate(T0));

        var classless = new PeripheralRule("exception-noclass", "allow", PeripheralRuleKinds.Exception,
            null, "0781", "5567", "SN-001", PeripheralScopes.Device, Dev, T0.AddDays(7), "req-1");
        Assert.Contains("binds NO class", classless.Validate(T0));
        Assert.False(classless.Matches(Usb(), T0));
    }

    // F5b — an approved exception outranks a DEVICE-level block on
    // the same identity (the approval is the human decision about
    // that exact device; at equal rank it previously changed
    // nothing while reporting 'minted').
    [Fact]
    public void F5_ApprovedException_BeatsDeviceLevelBlock()
    {
        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "device", "0781:5567:SN-001", id: "r-devblock"));
        var (before, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Blocked, before!.Disposition);
        rig.Svc.FileExceptionRequest(Dev, Dev, "req-1", User, Usb(), "site backups", User);
        var (_, rule, _) = rig.Svc.ApproveExceptionRequest("req-1", Admin, T0.AddDays(7), Admin);
        Assert.NotNull(rule);
        var (after, _, _) = rig.Svc.EvaluateConnection(Dev, Usb(), User);
        Assert.Equal(PeripheralDispositions.Allowed, after!.Disposition);
        Assert.Equal(rule!.Id, after.MatchedRule!.Id);
    }

    // F6 — the service can record a disconnect; after it, transfers
    // refuse; a refused transfer's size + SHA still land in the
    // chained audit; a disconnect with no live connection refuses.
    [Fact]
    public void F6_ServiceDisconnect_ClosesTheLiveWindow_RefusedTransferEvidenceAudited()
    {
        var rig = new Rig();
        var stick = Usb();
        var (orphanDisc, _) = rig.Svc.TraceMediaDisconnection(Dev, stick, User);
        Assert.Null(orphanDisc);
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        var (disc, _) = rig.Svc.TraceMediaDisconnection(Dev, stick, User);
        Assert.NotNull(disc);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "media_disconnected_traced");
        var (late, _) = rig.Svc.TraceTransfer(Dev, stick, "loot.zip", 777, ShaA, "event", User);
        Assert.Null(late);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "media_trace_refused"
            && e.Detail.Contains("loot.zip") && e.Detail.Contains("777") && e.Detail.Contains(ShaA));
        var (ok, summary) = rig.Svc.Trace.VerifyChain();
        Assert.True(ok, summary);
    }

    // F7 — VerifyChain CATCHES tampering with WatcherMode and with
    // DeviceStrengthLabel (both are hash-bound now), and watcher
    // mode is validated at record time.
    [Fact]
    public void F7_ChainTamper_WatcherModeOrLabel_VerifyChainFails()
    {
        var rig = new Rig();
        var stick = Usb();
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        rig.Svc.TraceTransfer(Dev, stick, "a.txt", 3, ShaA, "event", User);
        var (ok, _) = rig.Svc.Trace.VerifyChain();
        Assert.True(ok);

        var field = typeof(MediaTraceStore).GetField("_records", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var records = (List<MediaTraceRecord>)field.GetValue(rig.Svc.Trace)!;
        var original = records[1];
        records[1] = original with { WatcherMode = "poll" };
        var (okMode, _) = rig.Svc.Trace.VerifyChain();
        Assert.False(okMode);
        records[1] = original with { DeviceStrengthLabel = "strong (forged)" };
        var (okLabel, _) = rig.Svc.Trace.VerifyChain();
        Assert.False(okLabel);
        records[1] = original;
        var (okRestored, _) = rig.Svc.Trace.VerifyChain();
        Assert.True(okRestored);

        var (badMode, badReason) = rig.Svc.Trace.RecordConnection(Usb(serial: "SN-2"), "telepathy", T0);
        Assert.Null(badMode);
        Assert.Contains("not a known watcher mode", badReason);
    }

    // F8 — a serial-only identity is labelled WEAK with the missing
    // VID/PID named; it never claims a VID/PID binding.
    [Fact]
    public void F8_SerialOnlyIdentity_LabelledWeak_NeverStrong()
    {
        var serialOnly = new DeviceIdentity(Dev, DeviceClasses.Printer, null, null, "PRN-1", null);
        Assert.Contains("WEAK", serialOnly.StrengthLabel);
        Assert.Contains("NO VID/PID", serialOnly.StrengthLabel);
        Assert.DoesNotContain("strong", serialOnly.StrengthLabel);
        var rule = new PeripheralRule("r-ser", "allow", PeripheralRuleKinds.Device,
            null, null, null, "PRN-1", PeripheralScopes.Org, Scope, null, null);
        Assert.Contains("WEAK", rule.StrengthLabel);
        Assert.DoesNotContain("strong", rule.StrengthLabel);
    }

    // F9 — collision detection is class-independent: the same
    // VID/PID presenting a different serial in ANOTHER class still
    // raises the collision.
    [Fact]
    public void F9_CollisionDetection_CrossesClassBoundary()
    {
        var rig = new Rig();
        rig.Svc.EvaluateConnection(Dev, Usb(serial: "SN-001"), User);
        var (_, seen, _) = rig.Svc.EvaluateConnection(Dev, Usb(cls: DeviceClasses.Hid, serial: "SN-002"), User);
        Assert.True(seen!.IsIdentityCollision);
        Assert.Contains(rig.Sink.Events, e => e.Kind == PeripheralAlertKind.IdentityCollision);
    }

    // F10 — a malformed VID/PID in a rule refuses at admission
    // (named, never silently inert); a serial-only anchor CAN
    // target a serial-only device.
    [Fact]
    public void F10_MalformedVidPidRule_RefusedAtAdmission_SerialOnlyAnchorMatches()
    {
        var bad = new PeripheralRule("r-bad", "block", PeripheralRuleKinds.Device,
            null, "0781", "556X", "SN-1", PeripheralScopes.Org, Scope, null, null);
        Assert.Contains("malformed PID", bad.Validate(T0));

        var rig = new Rig();
        rig.SetEnforce();
        rig.SetRules(RuleEntry("block", "device", "0781:556X:SN-1", id: "r-typo") + "|" +
                     RuleEntry("block", "device", "::PRN-9", id: "r-serial"));
        var (policy, _) = rig.Svc.ResolvePolicy(Dev);
        Assert.Contains(policy!.Notes, n => n.Contains("malformed PID") && n.Contains("dropped"));
        Assert.DoesNotContain(policy.Rules, r => r.Id == "r-typo");
        var printer = new DeviceIdentity(Dev, DeviceClasses.Printer, null, null, "PRN-9", null);
        var (d, _, _) = rig.Svc.EvaluateConnection(Dev, printer, User);
        Assert.Equal(PeripheralDispositions.Blocked, d!.Disposition);
        Assert.Equal("r-serial", d.MatchedRule!.Id);
    }

    // F11c — a successful transfer's audit entry no longer embeds
    // the full coverage statement.
    [Fact]
    public void F11_TransferAudit_DoesNotEmbedCoverageStatement()
    {
        var rig = new Rig();
        var stick = Usb();
        rig.Svc.TraceMediaConnection(Dev, stick, "event", User);
        rig.Svc.TraceTransfer(Dev, stick, "a.txt", 3, ShaA, "event", User);
        var entry = Assert.Single(rig.Audit.Entries, e => e.Kind == "media_transfer_traced");
        Assert.DoesNotContain("raw disk", entry.Detail);
        Assert.DoesNotContain("NOT TRACED (named", entry.Detail);
    }

    // F12 — the dead ExceptionMatch duplicate is gone.
    [Fact]
    public void F12_ExceptionMatch_DeadDuplicateRemoved()
    {
        Assert.Null(typeof(PeripheralRule).Assembly.GetType("Acp.Shared.PeripheralControl.ExceptionMatch"));
    }
}

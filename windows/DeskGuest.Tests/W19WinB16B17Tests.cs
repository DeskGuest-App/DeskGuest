using System.Security.Cryptography;
using DeskGuest.Core;
using DeskGuest.Core.Platform;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 19 Lane A — round-3 closures.
/// B-16: (a) the pointer swap race — PointerAuditAnchor.Check
/// re-read the pointer instead of hashing the one ResolveTarget
/// actually used; now the anchor hashes the resolved read's bytes
/// (single read, SlotPointerRead.SelectedBytes). (b) Prefix
/// binding — the head comparison no longer skips on growth: the
/// chain entry at the marker's recorded count must hash-match the
/// marker's recorded head, AND the resolved pointer must match
/// the chain's last update_pointer_written record; the marker
/// refreshes only where both bind. (c) The irreducible remainder,
/// restated verbatim and pinned as a NAMED limit by a test named
/// for the limit: a growth forgery that preserves the genuine prefix and appends validly-linked records is indistinguishable under an unkeyed chain — full closure is the production signing key (R-05).
/// B-17: the DESKGUEST_DEV_ALLOW_NO_TOKEN posture split — the update
/// dev-ephemeral posture is decided by the ONE canonical path
/// DevEphemeralUpdateKeyOptIn (CoreOptions.AllowDevEphemeralUpdateKey
/// or DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY=1); DESKGUEST_DEV_ALLOW_NO_TOKEN
/// is IPC-only (IpcTrust); neither variable propagates to the
/// child Agent; the postures are labelled/audited separately.
/// The independence matrix specified in round-3 is pinned cell by
/// cell, including cell (a) — IPC-var-only ⇒ the update side
/// stays absent-key fail-closed — which failed before the split.</summary>
public class W19WinB16B17Tests
{
    // ---------- B-16 rig (W17 shape) ----------

    private sealed record Rig(string Root, string Install, string Updates, string SlotA, UpdateManager Manager, ChainedAuditLog Audit);

    private Rig PointerRig()
    {
        var audit = new ChainedAuditLog();
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, "DeskGuestCore.exe"), "base core");
        File.WriteAllText(Path.Combine(install, "DeskGuest.SessionAgent.exe"), "base agent");
        var updates = Path.Combine(root, "updates");
        var manager = new UpdateManager(updates, new RsaUpdateSignatureVerifier(), _ => Task.FromResult(true),
            pointerAudit: detail => audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", detail, DateTimeOffset.UtcNow));
        var slotA = SlotPointer.SlotDir(updates, SlotId.A); Directory.CreateDirectory(slotA);
        File.WriteAllText(Path.Combine(slotA, "DeskGuestCore.exe"), "slot core");
        File.WriteAllText(Path.Combine(slotA, "DeskGuest.SessionAgent.exe"), "slot agent");
        return new Rig(root, install, updates, slotA, manager, audit);
    }

    private string AuditPath(Rig rig) => Path.Combine(rig.Root, PointerAuditAnchor.AuditFileName);
    private void PersistAudit(Rig rig) => File.WriteAllText(AuditPath(rig), rig.Audit.ExportEntriesJson());
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private byte[] AttackerPointer(Rig rig)
    {
        var slotHash = SlotIntegrity.ContentHash(rig.SlotA);
        return System.Text.Encoding.UTF8.GetBytes(
            "{\"Active\":0,\"Version\":\"9.9.9\",\"StagedVersion\":null,\"LastOutcome\":\"attacker\",\"ActiveSlotHash\":\"" + slotHash + "\"}");
    }

    private static string PointerRecord(byte[] pointer) =>
        "pointer_sha256=" + Sha(pointer) + " active=A version=9.9.9 staged=- activeSlotHash=-";

    // ---------- B-16 (b): growth forgery, rewritten prefix ----------

    [Fact]
    public void B16_GrowthForgery_RewrittenPrefix_Refuses_PrefixBinding()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var markerBefore = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(1, markerBefore.ChainEntries);

        // round-3 sequence, hardened: grow the chain to
        // N+1 with a REWRITTEN first entry (validly linked — the
        // forged chain verifies internally) whose last pointer
        // record matches the rewritten pointer. W17 skipped the
        // head comparison on growth and vouched this.
        var attacker = AttackerPointer(rig);
        var forged = new ChainedAuditLog();
        forged.Append("session_open", "SYSTEM", "rewritten genesis entry", DateTimeOffset.UtcNow);
        forged.Append(PointerAuditAnchor.RecordKind, "SYSTEM", PointerRecord(attacker), DateTimeOffset.UtcNow);
        File.WriteAllText(AuditPath(rig), forged.ExportEntriesJson());
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), attacker);

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("genuine prefix was rewritten", note!);
        // The marker was NOT refreshed by the refused check: the
        // forged state never becomes the vouched state.
        var markerAfter = Assert.Single(PointerAnchorMarker.ReadAll(rig.Install));
        Assert.Equal(markerBefore.ChainEntries, markerAfter.ChainEntries);
        Assert.Equal(markerBefore.ChainHead, markerAfter.ChainHead);
        var target = LauncherCore_Resolve(rig);
        Assert.True(target);
    }

    private bool LauncherCore_Resolve(Rig rig) =>
        DeskGuest.Launcher.LauncherCore.ResolveTarget(rig.Install, rig.Updates).FellBack;

    // ---------- B-16 (c): growth forgery, genuine prefix — NAMED LIMIT ----------

    [Fact]
    public void B16_GrowthForgery_PreservingGenuinePrefix_PassesAnchor_LEGACY_UNKEYED_PostureOnly_NAMED_LIMIT()
    {
        // This test is named for the LIMIT, not as a success: a growth forgery that preserves the genuine prefix and appends validly-linked records is indistinguishable under an unkeyed chain — full closure is the production signing key (R-05).
        // The anchor passing here is the pinned, honest remainder —
        // no unkeyed scheme on the same writable media can separate
        // this chain from a genuine longer one.
        // W30 / D-DEC-7 REPURPOSE: this rig composes NO pointer-
        // signing custody, so it stands in the LEGACY-UNKEYED
        // posture (pre-keying installs) — the ONLY posture in which
        // this pass remains possible. On a keyed install the same
        // attack is REFUSED at the signature leg:
        // W30PointerSigningTests.GrowthForgery_DataDirOnly_
        // PrefixPreserving_RefusedAtSignatureLeg_MarkerNotRefreshed.
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);

        var attacker = AttackerPointer(rig);
        // Append a validly-linked pointer record to the GENUINE
        // chain (the genuine prefix is byte-preserved) and write
        // the matching pointer — exactly the R-05 remainder.
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM", PointerRecord(attacker), DateTimeOffset.UtcNow);
        PersistAudit(rig);
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), attacker);

        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note); // PINNED LIMIT (R-05), not a closure claim
    }

    // ---------- B-16 (a): pointer swap between resolve and check ----------

    [Fact]
    public void B16_PointerSwap_BetweenResolveAndCheck_Refuses_ResolvedBytesAreHashed()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        var genuinePointer = File.ReadAllBytes(SlotPointer.PointerPath(rig.Updates));

        // ResolveTarget's read consumes the ATTACKER pointer…
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), AttackerPointer(rig));
        var resolved = SlotPointer.ReadDetailed(rig.Updates);
        Assert.NotNull(resolved.SelectedBytes);
        // …then the on-disk pointer is swapped back to the genuine
        // bytes before the check. The pre-fix anchor re-read the
        // file, hashed the GENUINE pointer, and vouched the slot
        // the ATTACKER pointer named. The fixed anchor hashes the
        // resolved bytes and refuses.
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), genuinePointer);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install, resolved);
        Assert.False(ok);
        Assert.Contains("does NOT match", note!);

        // Control: the same overload over an unswapped read passes.
        var clean = SlotPointer.ReadDetailed(rig.Updates);
        var (ok2, note2) = PointerAuditAnchor.Check(rig.Updates, rig.Install, clean);
        Assert.True(ok2, note2);
    }

    [Fact]
    public void B16_SingleRead_SelectedBytesAreTheBytesParsed()
    {
        var rig = PointerRig();
        var read = SlotPointer.ReadDetailed(rig.Updates);
        Assert.Equal(SlotPointer.PointerPath(rig.Updates), read.SelectedPath);
        Assert.Equal(File.ReadAllBytes(SlotPointer.PointerPath(rig.Updates)), read.SelectedBytes);
        Assert.Equal(Sha(read.SelectedBytes!), Sha(File.ReadAllBytes(SlotPointer.PointerPath(rig.Updates))));
    }

    // ---------- B-16: rollback still refuses ----------

    [Fact]
    public void B16_Rollback_StillRefuses_AfterW19()
    {
        var rig = PointerRig();
        var initialPointer = File.ReadAllBytes(SlotPointer.PointerPath(rig.Updates));
        PersistAudit(rig);
        var initialAudit = File.ReadAllText(AuditPath(rig));
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        rig.Audit.Append(PointerAuditAnchor.RecordKind, "SYSTEM",
            "pointer_sha256=" + Sha(initialPointer) + " active=A version=0.1.0 staged=- activeSlotHash=-",
            DateTimeOffset.UtcNow);
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok); // marker now at 2
        File.WriteAllText(AuditPath(rig), initialAudit);
        File.WriteAllBytes(SlotPointer.PointerPath(rig.Updates), initialPointer);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.False(ok);
        Assert.Contains("FEWER than", note!);
        Assert.Contains("rolled back", note!);
    }

    [Fact]
    public void B16_LegitimateGrowth_GenuinePrefix_PointerRecordIntact_StillPasses_AndMarkerRefreshes()
    {
        var rig = PointerRig();
        PersistAudit(rig);
        Assert.True(PointerAuditAnchor.Check(rig.Updates, rig.Install).Ok);
        rig.Audit.Append("session_open", "SYSTEM", "later activity", DateTimeOffset.UtcNow);
        rig.Audit.Append("session_close", "SYSTEM", "more activity", DateTimeOffset.UtcNow);
        PersistAudit(rig);
        var (ok, note) = PointerAuditAnchor.Check(rig.Updates, rig.Install);
        Assert.True(ok, note);
        Assert.Equal(3, Assert.Single(PointerAnchorMarker.ReadAll(rig.Install)).ChainEntries);
    }

    // ---------- B-17: independence matrix ----------

    private sealed class EnvScope : IDisposable
    {
        private readonly string? _ipc, _upd;
        public EnvScope(string? ipc, string? upd)
        {
            _ipc = Environment.GetEnvironmentVariable(IpcTrust.DevOptInVariable);
            _upd = Environment.GetEnvironmentVariable(DevEphemeralUpdateKeyOptIn.Variable);
            Environment.SetEnvironmentVariable(IpcTrust.DevOptInVariable, ipc);
            Environment.SetEnvironmentVariable(DevEphemeralUpdateKeyOptIn.Variable, upd);
        }
        public void Dispose()
        {
            Environment.SetEnvironmentVariable(IpcTrust.DevOptInVariable, _ipc);
            Environment.SetEnvironmentVariable(DevEphemeralUpdateKeyOptIn.Variable, _upd);
        }
    }

    private CoreRuntime Runtime(int port, bool codeOptIn = false) => new(new CoreOptions
    {
        DataDir = TestUtil.TempDir(), Port = port,
        Protector = new DevOnlyPassThroughProtector(),
        Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
        AllowDevEphemeralUpdateKey = codeOptIn,
    });

    [Fact]
    public void B17_MatrixA_IpcVarOnly_UpdateStaysAbsentKeyFailClosed_IpcDevUnauthenticated()
    {
        // Round-3 cell (a) — FAILED before the split: the IPC var
        // alone un-pinned the update trust root.
        using var env = new EnvScope(ipc: "1", upd: null);
        var runtime = Runtime(18941);
        Assert.Equal("no-pinned-product-key", runtime.Updates.Status().SignatureKeyId);
        var staged = runtime.Updates.StagePackage(new byte[] { 1, 2, 3 }, new byte[] { 4 }, "9.9.9");
        Assert.False(staged.Ok);
        Assert.Contains("FAIL CLOSED", staged.Message);
        Assert.Contains("DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY", staged.Message);
        // …while the IPC posture, and only the IPC posture, opened:
        Assert.Equal(IpcTrustPosture.DevUnauthenticated, IpcTrust.Decide(null, "1"));
        // Separate audit labelling: the update posture is chained
        // under its own name and never claims the IPC variable.
        Assert.Contains(runtime.Enterprise.AuditLog.Entries,
            e => e.Kind == "update_signing_posture" && e.Detail.Contains("FAILS CLOSED"));
    }

    [Fact]
    public void B17_MatrixB_UpdateVarOnly_EphemeralVerifier_IpcRefusesNoToken()
    {
        using var env = new EnvScope(ipc: null, upd: "1");
        var runtime = Runtime(18942);
        Assert.Equal("dev-ephemeral", runtime.Updates.Status().SignatureKeyId);
        Assert.Contains(runtime.Enterprise.AuditLog.Entries,
            e => e.Kind == "update_signing_posture" && e.Detail.Contains("DEV-Ephemeral")
                 && e.Detail.Contains("DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY"));
        // IPC stays fail-closed: the update var is not an IPC opt-in.
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, null));
        Assert.Equal(IpcTrustPosture.RefuseNoToken,
            IpcTrust.Decide(null, Environment.GetEnvironmentVariable(IpcTrust.DevOptInVariable)));
    }

    [Fact]
    public void B17_MatrixC_Neither_FailClosedEverywhere()
    {
        using var env = new EnvScope(ipc: null, upd: null);
        var runtime = Runtime(18943);
        Assert.Equal("no-pinned-product-key", runtime.Updates.Status().SignatureKeyId);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, null));
    }

    [Fact]
    public void B17_MatrixC_Both_SumOfTheTwoPostures()
    {
        using var env = new EnvScope(ipc: "1", upd: "1");
        var runtime = Runtime(18944);
        Assert.Equal("dev-ephemeral", runtime.Updates.Status().SignatureKeyId);
        Assert.Equal(IpcTrustPosture.DevUnauthenticated, IpcTrust.Decide(null, "1"));
    }

    [Fact]
    public void B17_CodeOptInOnly_EphemeralUpdate_IpcUntouched()
    {
        using var env = new EnvScope(ipc: null, upd: null);
        var runtime = Runtime(18945, codeOptIn: true);
        Assert.Equal("dev-ephemeral", runtime.Updates.Status().SignatureKeyId);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, null));
    }

    [Fact]
    public void B17_CanonicalDecision_PureCells_AndDistinctVariables()
    {
        Assert.False(DevEphemeralUpdateKeyOptIn.IsInForce(false, null));
        Assert.False(DevEphemeralUpdateKeyOptIn.IsInForce(false, "true"));
        Assert.False(DevEphemeralUpdateKeyOptIn.IsInForce(false, "0"));
        Assert.True(DevEphemeralUpdateKeyOptIn.IsInForce(false, "1"));
        Assert.True(DevEphemeralUpdateKeyOptIn.IsInForce(false, " 1 "));
        Assert.True(DevEphemeralUpdateKeyOptIn.IsInForce(true, null));
        Assert.Equal("DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY", DevEphemeralUpdateKeyOptIn.Variable);
        Assert.NotEqual(IpcTrust.DevOptInVariable, DevEphemeralUpdateKeyOptIn.Variable);
    }

    [Fact]
    public void B17_NoPropagation_ChildAgentEnvironment_StripsBothDevVariables()
    {
        var source = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DESKGUEST_DEV_ALLOW_NO_TOKEN"] = "1",
            ["DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY"] = "1",
            ["DESKGUEST_IPC_TOKEN"] = "stale",
            ["FOO"] = "bar",
        };
        var child = WindowsAgentLauncher.BuildChildEnvironment(source, "fresh-token");
        Assert.False(child.ContainsKey("DESKGUEST_DEV_ALLOW_NO_TOKEN"));
        Assert.False(child.ContainsKey("DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY"));
        Assert.Equal("fresh-token", child["DESKGUEST_IPC_TOKEN"]);
        Assert.Equal("bar", child["FOO"]);
    }

    [Fact]
    public void B17_EndToEnd_AgentLaunchWithOnlyUpdateVar_StillRefusesNoTokenIpc()
    {
        // The launch-environment end of the matrix: a Core process
        // carrying ONLY the update var launches its Agent through
        // BuildChildEnvironment; the Agent's IpcTrust decision over
        // ITS OWN environment (no token handed over) refuses.
        var coreEnv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DESKGUEST_DEV_ALLOW_EPHEMERAL_UPDATE_KEY"] = "1",
        };
        var child = WindowsAgentLauncher.BuildChildEnvironment(coreEnv, ipcToken: null);
        child.TryGetValue(IpcTrust.DevOptInVariable, out var ipcOptIn);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, ipcOptIn));
        // And even a Core carrying BOTH vars does not propagate
        // the IPC opt-in: the child still refuses no-token IPC.
        coreEnv["DESKGUEST_DEV_ALLOW_NO_TOKEN"] = "1";
        var child2 = WindowsAgentLauncher.BuildChildEnvironment(coreEnv, ipcToken: null);
        child2.TryGetValue(IpcTrust.DevOptInVariable, out var ipcOptIn2);
        Assert.Equal(IpcTrustPosture.RefuseNoToken, IpcTrust.Decide(null, ipcOptIn2));
    }
}

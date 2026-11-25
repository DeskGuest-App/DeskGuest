using System.Diagnostics;
using Acp.Shared.Update;

namespace Acp.Launcher;

/// <summary>What the launcher resolved to run: the Core executable, the
/// Session Agent executable that belongs with it (same slot), whether
/// this is a fallback to the install-root base binaries, and why.</summary>
public sealed record LaunchTarget(string CoreExe, string AgentExe, bool FellBack, string Reason,
    // W13 / DS-P9-F18: when the target is a verified slot, the slot
    // directory + the hash it verified against ride along so the
    // exec path can re-verify and hold the verified files (below).
    string? VerifiedSlotDir = null, string? VerifiedSlotHash = null);

/// <summary>One child-process start request. Environment overrides are
/// applied on top of the launcher's inherited environment.</summary>
public sealed record LaunchRequest(string ExePath, string Arguments, IReadOnlyDictionary<string, string> EnvironmentOverrides,
    // W13 / DS-P9-F18: when set, the starter opens every file under
    // this directory with write-sharing DENIED before starting the
    // child and holds them until it exits — the verified bytes are
    // the executed bytes (see SlotIntegrity's doc for the limbs
    // this does NOT close, which stay named there).
    string? HoldDirectory = null,
    // W15 / DS-P9-F18 limb (a): the hash the slot verified against.
    // The starter acquires a whole-slot SlotHold against it and
    // re-checks the file set immediately before exec — a file
    // ADDED after verification refuses the start by name.
    string? ExpectedSlotHash = null);

/// <summary>
/// The launcher shim's decision logic (DESIGN §4.6): read the
/// active-slot pointer, exec the Core from the active slot, and set
/// ACP_AGENT_EXE to the SAME slot's agent so a flipped pointer swaps
/// Core and Agent together. If the active slot is missing its Core
/// (corrupt slot, half-copied update), fall back to the install-root
/// base binaries the installer laid down — the endpoint must come up
/// on SOMETHING known-good rather than not at all. A slot child that
/// fails to even START gets one retry on the base binaries; a child
/// that starts and exits owns its exit code (the SCM recovery policy
/// decides restarts, exactly as it did for the bare Core).
/// </summary>
public static class LauncherCore
{
    public const string CoreExeName = "AcpCore.exe";
    public const string AgentExeName = "Acp.SessionAgent.exe";

    public static LaunchTarget ResolveTarget(string installRoot, string updatesRoot)
    {
        // BD-SHARED-PLAT-3/F12: a pointer fallback is part of the
        // launch target's reason — a corrupt pointer after a bad
        // update is a diagnostic the operator can see, not a silent
        // start of a stale slot.
        var read = SlotPointer.ReadDetailed(updatesRoot);
        var pointer = read.Pointer;
        var fallbackNote = read.FellBack is null ? "" : $" [pointer fallback: {read.FellBack}]";
        var slotDir = SlotPointer.SlotDir(updatesRoot, pointer.Active);
        var slotCore = Path.Combine(slotDir, CoreExeName);
        var baseCore = Path.Combine(installRoot, CoreExeName);
        if (File.Exists(slotCore))
        {
            // BD-WIN-AGENT F6: existence is NOT enough to run a slot
            // binary as SYSTEM. The slot's contents must hash to the
            // anchor the Core recorded from the signature-verified
            // update package (SlotIntegrity). No anchor (install-time
            // or legacy pointer) or any mismatch => the slot is
            // UNVERIFIED and the base binaries run instead.
            if (pointer.ActiveSlotHash is null)
                return new LaunchTarget(baseCore, Path.Combine(installRoot, AgentExeName), true,
                    $"active slot {pointer.Active} ({pointer.Version}) has no integrity anchor in the pointer (not staged from a verified update); fell back to the install-root base binaries" + fallbackNote);
            if (!SlotIntegrity.Verify(slotDir, pointer.ActiveSlotHash))
                return new LaunchTarget(baseCore, Path.Combine(installRoot, AgentExeName), true,
                    $"active slot {pointer.Active} ({pointer.Version}) FAILED integrity verification against the pointer's recorded hash; fell back to the install-root base binaries" + fallbackNote);
            // W15 / DS-P9-F18 limb (b): cross-check the pointer
            // against the hash the Core recorded in the enterprise
            // audit chain when it wrote the pointer. A pointer
            // rewritten together with the slot refuses here, by
            // name. W30 / D-DEC-7: on a keyed install the anchor
            // ALSO verifies the pointer's signature leg against
            // the runtime pin in this install root (see
            // PointerAuditAnchor for the exact claim and the
            // named rollback limit).
            // W17 / DS-B-16: the install root carries the
            // launcher-side anchor marker (a different ACL domain
            // from the data dir) — absence/truncation/rollback of
            // the audit chain after first anchoring refuses here.
            // W19 / DS-B-16 (a): the anchor hashes the pointer
            // bytes THIS read resolved from (read above) — Check
            // does not re-read the pointer, so a swap between
            // resolve and check cannot validate a different
            // pointer than the one whose slot is about to run.
            var anchor = PointerAuditAnchor.Check(updatesRoot, markerDir: installRoot, resolvedRead: read);
            if (!anchor.Ok)
                return new LaunchTarget(baseCore, Path.Combine(installRoot, AgentExeName), true,
                    $"active slot {pointer.Active} ({pointer.Version}) refused: {anchor.Note}; fell back to the install-root base binaries" + fallbackNote);
            var anchorNote = anchor.Note is null ? "" : $" [{anchor.Note}]";
            var slotAgent = Path.Combine(slotDir, AgentExeName);
            // W17 / DS-B-15 (mixed case, pinned): Core and Agent
            // flip TOGETHER (DESIGN §4.6) — a verified slot core
            // is never paired with the install-root base agent.
            // A slot without its agent is not the package shape
            // the flip promises; both fall back, by name.
            if (!File.Exists(slotAgent))
                return new LaunchTarget(baseCore, Path.Combine(installRoot, AgentExeName), true,
                    $"active slot {pointer.Active} ({pointer.Version}) is integrity-verified but carries no {AgentExeName} — Core and Agent swap together, so the slot core is not paired with the base agent; fell back to the install-root base binaries" + fallbackNote + anchorNote);
            var agent = slotAgent;
            return new LaunchTarget(slotCore, agent, false,
                $"active slot {pointer.Active} ({pointer.Version}, integrity verified)" + fallbackNote + anchorNote,
                VerifiedSlotDir: slotDir, VerifiedSlotHash: pointer.ActiveSlotHash);
        }
        return new LaunchTarget(baseCore, Path.Combine(installRoot, AgentExeName), true,
            $"active slot {pointer.Active} has no {CoreExeName} at {slotDir}; fell back to the install-root base binaries" + fallbackNote);
    }

    public static async Task<int> RunAsync(
        string installRoot,
        string updatesRoot,
        string arguments,
        Func<LaunchRequest, Task<int>> startChild,
        TextWriter log)
    {
        var target = ResolveTarget(installRoot, updatesRoot);
        // W13 / DS-P9-F18: re-resolve IMMEDIATELY before exec — the
        // first resolution may be arbitrarily older than the start
        // (logging, SCM pauses), and the verify→exec window is the
        // finding. If the slot changed or stopped verifying between
        // the two reads, the second (honest, possibly fallback)
        // target is what runs.
        if (!target.FellBack)
        {
            var fresh = ResolveTarget(installRoot, updatesRoot);
            if (fresh.FellBack || fresh.CoreExe != target.CoreExe || fresh.VerifiedSlotHash != target.VerifiedSlotHash)
                log.WriteLine($"[acp-launcher] slot changed between resolve and exec; re-resolved: {fresh.Reason}");
            target = fresh;
        }
        log.WriteLine($"[acp-launcher] {target.Reason}");
        log.WriteLine($"[acp-launcher] core: {target.CoreExe}");
        log.WriteLine($"[acp-launcher] agent: {target.AgentExe}");
        try
        {
            return await startChild(new LaunchRequest(
                target.CoreExe, arguments,
                // W30 / D-DEC-7: the Core's runtime pointer-signing
                // custody lives in the install root; a slot Core's
                // own base directory is inside the data dir, so the
                // launcher names the install root explicitly.
                new Dictionary<string, string> { ["ACP_AGENT_EXE"] = target.AgentExe, ["ACP_INSTALL_ROOT"] = installRoot },
                HoldDirectory: target.FellBack ? null : target.VerifiedSlotDir,
                ExpectedSlotHash: target.FellBack ? null : target.VerifiedSlotHash));
        }
        catch (Exception ex) when (!target.FellBack)
        {
            // The slot child could not even start: one retry on the
            // base binaries before surrendering to SCM recovery.
            log.WriteLine($"[acp-launcher] slot child failed to start ({ex.GetType().Name}: {ex.Message}); retrying on base binaries");
            var baseTarget = new LaunchTarget(
                Path.Combine(installRoot, CoreExeName), Path.Combine(installRoot, AgentExeName), true, "retry after slot start failure");
            return await startChild(new LaunchRequest(
                baseTarget.CoreExe, arguments,
                new Dictionary<string, string> { ["ACP_AGENT_EXE"] = baseTarget.AgentExe }));
        }
    }

    /// <summary>The production child starter: a real process, output
    /// inherited (the Core is a service/host; its console is the
    /// service's), environment overrides applied, exit code returned.
    /// BD-WIN-AGENT F6: on Windows the child is assigned to a
    /// kill-on-close Job Object held for the child's lifetime, so
    /// stopping or killing the launcher can never orphan a running
    /// Core (the job handle closes with the launcher process, and
    /// the OS then terminates the child).</summary>
    public static async Task<int> StartChildProcessAsync(LaunchRequest request)
    {
        var psi = new ProcessStartInfo(request.ExePath)
        {
            Arguments = request.Arguments,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(request.ExePath) ?? Environment.CurrentDirectory
        };
        foreach (var (key, value) in request.EnvironmentOverrides)
            psi.Environment[key] = value;
        // W13 / DS-P9-F18 + W15 limb (a): hold the verified slot's
        // files open with write-sharing denied for the child's whole
        // lifetime, so a verified file cannot be replaced between
        // the integrity check and the exec — or while the child
        // runs. W15: the hold covers the WHOLE slot directory
        // (hash-verified, every file snapshotted + held), and the
        // intact check immediately before exec refuses the start
        // BY NAME when a file was ADDED after verification (neither
        // hashed nor held), removed, or changed. A file that cannot
        // be held refuses the start: unverifiable-at-exec is not
        // executed. W17 / DS-B-15: the hold also pins the slot
        // DIRECTORY (deny rename/delete on Windows) so the path
        // cannot be swapped to a different directory between the
        // intact check and the exec, and the intact check is
        // re-run after the start (child killed on drift).
        // A hold directory without an expected hash falls
        // back to the W13 file-set hold (no anchor to verify
        // against — embedder/test shape, named here).
        using var slotHold = request.HoldDirectory is not null && request.ExpectedSlotHash is not null
            ? SlotIntegrity.AcquireHold(request.HoldDirectory, request.ExpectedSlotHash) : null;
        using var holds = request.HoldDirectory is not null && request.ExpectedSlotHash is null
            ? SlotFileHolds.Acquire(request.HoldDirectory) : null;
        if (slotHold?.CheckIntact() is { } problem)
            throw new InvalidOperationException(problem);
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start {request.ExePath}");
        // W17 / DS-B-15: re-check AFTER the start as well. On
        // Windows the hold's directory handles make a swap
        // impossible while held, so this can only fire where
        // handle semantics are advisory — there, a slot swapped
        // in the check→start window is caught here and the child
        // is killed rather than left running unverified bytes.
        if (slotHold?.CheckIntact() is { } postProblem)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* the refusal below is the outcome either way */ }
            throw new InvalidOperationException(postProblem + " (post-start re-check — child killed, W17/DS-B-15)");
        }
        using var job = KillOnCloseJob.TryCreateFor(process);
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    /// <summary>W13 / DS-P9-F18: deny-write holds over every file in
    /// a verified slot directory. Acquire throws when any file
    /// cannot be opened deny-write — the caller treats that as a
    /// refused start rather than executing bytes it could not pin.
    /// On non-Windows platforms FileShare semantics are advisory;
    /// the production launcher is a Windows service, and the
    /// re-verify in RunAsync still narrows the window everywhere.</summary>
    private sealed class SlotFileHolds : IDisposable
    {
        private readonly List<FileStream> _streams = new();
        private SlotFileHolds() { }
        public static SlotFileHolds Acquire(string dir)
        {
            var holds = new SlotFileHolds();
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    holds._streams.Add(new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.Read));
                return holds;
            }
            catch { holds.Dispose(); throw; }
        }
        public void Dispose() { foreach (var s in _streams) s.Dispose(); _streams.Clear(); }
    }

    /// <summary>A Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    /// wrapping one child process. A null wrapper (non-Windows, or any
    /// API failure) degrades to the pre-fix behaviour and never blocks
    /// the launch.</summary>
    private sealed class KillOnCloseJob : IDisposable
    {
        private IntPtr _job;
        private KillOnCloseJob(IntPtr job) => _job = job;

        public static KillOnCloseJob? TryCreateFor(Process child)
        {
            if (!OperatingSystem.IsWindows()) return null;
            try
            {
                var job = Native.CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) return null;
                var info = new Native.JobObjectExtendedLimitInformation
                {
                    BasicLimitInformation = new Native.JobObjectBasicLimitInformation
                    {
                        LimitFlags = Native.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    },
                };
                var size = System.Runtime.InteropServices.Marshal.SizeOf<Native.JobObjectExtendedLimitInformation>();
                var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                try
                {
                    System.Runtime.InteropServices.Marshal.StructureToPtr(info, ptr, false);
                    if (!Native.SetInformationJobObject(job, Native.JobObjectExtendedLimitInformationClass, ptr, (uint)size))
                    { Native.CloseHandle(job); return null; }
                }
                finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr); }
                if (!Native.AssignProcessToJobObject(job, child.Handle))
                { Native.CloseHandle(job); return null; }
                return new KillOnCloseJob(job);
            }
            catch { return null; }
        }

        public void Dispose()
        {
            if (_job != IntPtr.Zero) { try { Native.CloseHandle(_job); } catch { } _job = IntPtr.Zero; }
        }

        private static class Native
        {
            public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
            public const int JobObjectExtendedLimitInformationClass = 9;

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public struct IoCounters
            {
                public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
                public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public struct JobObjectBasicLimitInformation
            {
                public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
                public uint LimitFlags;
                public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
                public uint ActiveProcessLimit;
                public UIntPtr Affinity;
                public uint PriorityClass, SchedulingClass;
            }

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public struct JobObjectExtendedLimitInformation
            {
                public JobObjectBasicLimitInformation BasicLimitInformation;
                public IoCounters IoInfo;
                public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
            }

            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
            public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);
            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);
            [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);
        }
    }
}

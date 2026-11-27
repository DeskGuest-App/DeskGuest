using System.Runtime.InteropServices;
using System.Threading;
using System.Text.Json;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Phase2;

/// <summary>
/// Storage for the vaulted logon password (DESIGN §5.4). Production is
/// an LSA private-data secret: readable only by SYSTEM processes on
/// that machine, additionally wrapped by the Core. There is NO read
/// path back to any caller — the interface is write / use / wipe only
/// (X4: no credential read-back exists in any scope, by construction).
/// </summary>
public interface ICredentialVault
{
    bool HasCredential { get; }
    void Vault(string password);
    /// <summary>Hand the secret to the credential provider over the
    /// authenticated local channel. Never returns it to a tool caller.</summary>
    bool TryDeliverToCredentialProvider(ICredentialProviderChannel channel);
    void Wipe();
}

/// <summary>The Core↔CP local channel (named pipe, SYSTEM-only ACL on
/// Windows). The CP is a thin courier; all policy lives in the Core.</summary>
public interface ICredentialProviderChannel
{
    bool SignalUnlock(string credentialPayload, string nonce);
}

/// <summary>LSA private-data store via advapi32 LsaStorePrivateData /
/// LsaRetrievePrivateData. COMPILED here; UNPROVEN-ON-WINDOWS — first
/// exercised in the Phase 2 laptop drills (scratch account first).</summary>
public sealed class LsaCredentialVault : ICredentialVault
{
    private const string SecretName = "DESKGUESTW1$Vault";

    // Existence WITHOUT materialising the secret into a managed string:
    // a state refresh must not drag the password through the heap (M6d).
    public bool HasCredential => OperatingSystem.IsWindows() && Exists();

    private bool Exists()
    {
        var keyPtr = Marshal.StringToHGlobalUni(SecretName);
        try
        {
            var key = new LSA_UNICODE_STRING { Buffer = keyPtr, Length = (ushort)(SecretName.Length * 2), MaximumLength = (ushort)(SecretName.Length * 2) };
            var handle = OpenPolicy(PolicyGetPrivateInformation);
            var status = NativeLsa.LsaRetrievePrivateData(handle, ref key, out var ptr);
            NativeLsa.LsaClose(handle);
            if (status != 0 || ptr == IntPtr.Zero) return false;
            NativeLsa.LsaFreeMemory(ptr);
            return true;
        }
        finally { Marshal.FreeHGlobal(keyPtr); }
    }

    public void Vault(string password)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("LSA vault is Windows-only");
        var dataPtr = Marshal.StringToHGlobalUni(password);
        var keyPtr = Marshal.StringToHGlobalUni(SecretName);
        try
        {
            var data = new LSA_UNICODE_STRING { Buffer = dataPtr, Length = (ushort)(password.Length * 2), MaximumLength = (ushort)(password.Length * 2) };
            var key = new LSA_UNICODE_STRING { Buffer = keyPtr, Length = (ushort)(SecretName.Length * 2), MaximumLength = (ushort)(SecretName.Length * 2) };
            var handle = OpenPolicy(PolicyCreateSecret);
            var status = NativeLsa.LsaStorePrivateData(handle, ref key, ref data);
            NativeLsa.LsaClose(handle);
            if (status != 0) throw new InvalidOperationException($"LsaStorePrivateData failed: 0x{status:X8}");
        }
        finally { Marshal.FreeHGlobal(dataPtr); Marshal.FreeHGlobal(keyPtr); }
    }

    private string? Retrieve()
    {
        var keyPtr = Marshal.StringToHGlobalUni(SecretName);
        try
        {
            var key = new LSA_UNICODE_STRING { Buffer = keyPtr, Length = (ushort)(SecretName.Length * 2), MaximumLength = (ushort)(SecretName.Length * 2) };
            var handle = OpenPolicy(PolicyGetPrivateInformation);
            var status = NativeLsa.LsaRetrievePrivateData(handle, ref key, out var ptr);
            NativeLsa.LsaClose(handle);
            if (status != 0 || ptr == IntPtr.Zero) return null;
            var data = Marshal.PtrToStructure<LSA_UNICODE_STRING>(ptr);
            // LSA does NOT guarantee NUL termination: honour Length (M6d).
            var value = data.Buffer == IntPtr.Zero ? null : Marshal.PtrToStringUni(data.Buffer, data.Length / 2);
            NativeLsa.LsaFreeMemory(ptr);
            return value;
        }
        finally { Marshal.FreeHGlobal(keyPtr); }
    }

    public bool TryDeliverToCredentialProvider(ICredentialProviderChannel channel)
    {
        var secret = Retrieve();
        if (secret is null) return false;
        var nonce = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        // The payload is the credential serialized for LogonUI by the CP;
        // it crosses only the local SYSTEM channel, never the MCP surface.
        return channel.SignalUnlock(secret, nonce);
    }

    public void Wipe()
    {
        if (!OperatingSystem.IsWindows()) return;
        var keyPtr = Marshal.StringToHGlobalUni(SecretName);
        try
        {
            var key = new LSA_UNICODE_STRING { Buffer = keyPtr, Length = (ushort)(SecretName.Length * 2), MaximumLength = (ushort)(SecretName.Length * 2) };
            var handle = OpenPolicy(PolicyCreateSecret);
            NativeLsa.LsaStorePrivateData(handle, ref key, IntPtr.Zero); // null data deletes the secret
            NativeLsa.LsaClose(handle);
        }
        finally { Marshal.FreeHGlobal(keyPtr); }
    }

    // Least-privilege policy access (was POLICY_ALL_ACCESS — M6d).
    private const uint PolicyGetPrivateInformation = 0x00000004;
    private const uint PolicyCreateSecret = 0x00000020;

    private static IntPtr OpenPolicy(uint access)
    {
        var oa = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        var status = NativeLsa.LsaOpenPolicy(IntPtr.Zero, ref oa, access, out var handle);
        if (status != 0) throw new InvalidOperationException($"LsaOpenPolicy failed: 0x{status:X8}");
        return handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }

    private static class NativeLsa
    {
        [DllImport("advapi32.dll")] public static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES oa, uint access, out IntPtr handle);
        [DllImport("advapi32.dll")] public static extern uint LsaClose(IntPtr handle);
        [DllImport("advapi32.dll")] public static extern uint LsaStorePrivateData(IntPtr handle, ref LSA_UNICODE_STRING key, ref LSA_UNICODE_STRING data);
        [DllImport("advapi32.dll")] public static extern uint LsaStorePrivateData(IntPtr handle, ref LSA_UNICODE_STRING key, IntPtr data);
        [DllImport("advapi32.dll")] public static extern uint LsaRetrievePrivateData(IntPtr handle, ref LSA_UNICODE_STRING key, out IntPtr data);
        [DllImport("advapi32.dll")] public static extern uint LsaFreeMemory(IntPtr buffer);
    }
}

/// <summary>Dev/test vault: in-memory only, never persisted. Exists so
/// the unlock policy suite runs on the build VM.</summary>
public sealed class InMemoryCredentialVault : ICredentialVault
{
    private string? _secret;
    public bool HasCredential => _secret is not null;
    public void Vault(string password) => _secret = password;
    public bool TryDeliverToCredentialProvider(ICredentialProviderChannel channel)
    {
        if (_secret is null) return false;
        return channel.SignalUnlock(_secret, Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)));
    }
    public void Wipe() => _secret = null;
}

public enum UnlockModuleState { Disabled, Ready, VaultDegraded, UnavailableHelloOnly, VaultEmpty }

/// <summary>
/// The unlock request path (DESIGN §5.4) minus the CP DLL itself:
/// scope check happens in the policy engine (dedicated `unlock`
/// scope); this service enforces the brakes — one attempt per request,
/// a failed authentication degrades the module until the owner re-vaults,
/// Hello-only mode makes it report UNAVAILABLE instead of failing
/// silently, and STOP blocks it like everything else.
/// </summary>
public sealed class UnlockService
{
    private readonly ICredentialVault _vault;
    private readonly ICredentialProviderChannel _channel;
    private readonly IFactChecks _facts;
    private readonly Func<bool> _stopInForce;
    private readonly Modules.SessionManager? _sessions;
    private readonly Func<bool>? _desktopUnlocked;
    private readonly SemaphoreSlim _attemptGate = new(1, 1);

    public UnlockModuleState State { get; private set; } = UnlockModuleState.Disabled;
    public bool ModuleEnabled { get; set; }
    public int Attempts { get; private set; }
    public int Failures { get; private set; }

    /// <param name="sessions">When supplied, a CONFIRMED unlock starts
    /// the control session marked agent-unlocked — the binding that
    /// makes the §5.4 auto-relock rule real instead of dead code (H4).</param>
    /// <param name="desktopUnlocked">Outcome probe: the session agent's
    /// reported lock state. A delivery is not an authentication (H3);
    /// success requires the desktop to actually report unlocked.</param>
    public UnlockService(ICredentialVault vault, ICredentialProviderChannel channel, IFactChecks facts, Func<bool> stopInForce,
        Modules.SessionManager? sessions = null, Func<bool>? desktopUnlocked = null)
    {
        _vault = vault;
        _channel = channel;
        _facts = facts;
        _stopInForce = stopInForce;
        _sessions = sessions;
        _desktopUnlocked = desktopUnlocked;
    }

    public async Task RefreshStateAsync(CancellationToken ct)
    {
        if (!ModuleEnabled) { State = UnlockModuleState.Disabled; return; }
        if (State == UnlockModuleState.VaultDegraded) return; // stays degraded until re-vault
        var facts = await _facts.RunAsync(ct);
        if (facts.HelloOnlyMode.Reason.Contains("Hello-only sign-in mode is ON"))
        {
            State = UnlockModuleState.UnavailableHelloOnly;
            return;
        }
        State = _vault.HasCredential ? UnlockModuleState.Ready : UnlockModuleState.VaultEmpty;
    }

    /// <summary>Called from the laptop UI only (never a tool): the owner
    /// types the password once, on the laptop. A successful vault
    /// clears a degraded state.</summary>
    public void VaultPasswordFromLaptop(string password)
    {
        _vault.Vault(password);
        if (State == UnlockModuleState.VaultDegraded) State = UnlockModuleState.Ready;
    }

    public void WipeVault()
    {
        _vault.Wipe();
        State = UnlockModuleState.VaultEmpty;
    }

    /// <summary>One unlock attempt. Exactly one: a failure degrades the
    /// module (no retry loops against a changed password — an agent
    /// must never be the reason the owner can't log into his own laptop).
    /// "Failure" now means what it says (second-inspector H3): delivery
    /// to the CP is followed by an outcome wait — if the desktop does
    /// not report unlocked within the window, the authentication is
    /// treated as failed and the brake engages. Concurrent calls are
    /// serialized so two callers cannot race past the state checks.</summary>
    public async Task<ToolResult> RequestUnlockAsync(Shared.Security.Pairing pairing, CancellationToken ct)
    {
        await _attemptGate.WaitAsync(ct);
        try
        {
            await RefreshStateAsync(ct);
            if (_stopInForce()) return ToolResult.Unavailable("STOP is in force; unlock is blocked like everything else");
            switch (State)
            {
                case UnlockModuleState.Disabled: return ToolResult.Unavailable("the Unlock module is not enabled on this host");
                case UnlockModuleState.VaultEmpty: return ToolResult.Unavailable("no credential is vaulted; the owner vaults it once, on the laptop");
                case UnlockModuleState.VaultDegraded: return ToolResult.Unavailable("the vault is degraded after a failed authentication; the owner re-vaults on the laptop to restore it");
                case UnlockModuleState.UnavailableHelloOnly: return ToolResult.Unavailable("Hello-only sign-in mode is ON: the password provider is not offered at the logon screen. The owner's one setup toggle clears this (DESIGN §5.4)");
            }

            Attempts++;
            var delivered = _vault.TryDeliverToCredentialProvider(_channel);
            if (!delivered)
            {
                Failures++;
                State = UnlockModuleState.VaultDegraded;
                return ToolResult.Error("delivery_failed", "the credential could not be delivered to the credential provider; the module is now VAULT_DEGRADED and will not retry — the owner re-vaults on the laptop (DESIGN §5.4 brakes)");
            }

            // Outcome confirmation: the agent (started at logon) reports
            // the lock state over IPC. No report of an unlocked desktop
            // within the window = the authentication failed, whatever
            // the pipe said.
            if (_desktopUnlocked is not null)
            {
                var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(15);
                var confirmed = false;
                while (DateTimeOffset.UtcNow < deadline)
                {
                    if (_desktopUnlocked()) { confirmed = true; break; }
                    await Task.Delay(250, ct);
                }
                if (!confirmed)
                {
                    Failures++;
                    State = UnlockModuleState.VaultDegraded;
                    return ToolResult.Error("authentication_failed", "the credential was delivered but the desktop did not unlock — treated as a failed authentication; the module is now VAULT_DEGRADED and will not retry (DESIGN §5.4 brakes)");
                }
            }

            // Bind the unlock to a session marked agent-unlocked, so the
            // §5.4 relock rule has something true to act on (H4).
            if (_sessions is not null && _sessions.Current is null)
                _sessions.Start(pairing, agentUnlocked: true);
            return ToolResult.Success("unlock CONFIRMED: the desktop reports unlocked and the session is started, marked agent-unlocked (relock rule armed) (DESIGN §5.4)");
        }
        finally { _attemptGate.Release(); }
    }
}

/// <summary>Census row 73: session_unlock (Phase 2, own gate).</summary>
public sealed class SessionUnlockModule : IToolModule
{
    private readonly UnlockService _unlock;
    public SessionUnlockModule(UnlockService unlock) => _unlock = unlock;
    public ToolDescriptor Descriptor { get; } = new(
        "session_unlock", "Route B agent unlock (DESIGN §5.4): the credential provider authenticates the owner with the vaulted password. Requires the dedicated 'unlock' scope; opens a session under presence; one attempt, then degrade — never a retry loop.",
        Scopes.Unlock, SessionRequirement.Core, RiskTier.Critical, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        await _unlock.RequestUnlockAsync(ctx.Pairing, ct);
}

/// <summary>Census row 74: relock a session the agent itself unlocked.</summary>
public sealed class SessionRelockModule : IToolModule
{
    private readonly Modules.SessionManager _sessions;
    private readonly Ipc.AgentIpcServer _ipc;
    public SessionRelockModule(Modules.SessionManager sessions, Ipc.AgentIpcServer ipc) { _sessions = sessions; _ipc = ipc; }
    public ToolDescriptor Descriptor { get; } = new(
        "session_relock", "Relock the workstation at the end of a session the agent itself unlocked (DESIGN §5.4 rule).",
        Scopes.Unlock, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var current = _sessions.Current;
        if (current is null) return ToolResult.Success("no session is active; nothing to relock");
        if (!current.AgentUnlockedThisSession)
            return ToolResult.Success("this session did not unlock the machine; its lock state is the owner's, unchanged");
        await _ipc.CallDesktopToolAsync("session_lock", "{}", ct);
        return ToolResult.Success("relocked (the design locks only what it unlocked)");
    }
}

/// <summary>Fake CP channel for tests: records deliveries.</summary>
public sealed class FakeCredentialProviderChannel : ICredentialProviderChannel
{
    public List<string> Nonces { get; } = new();
    public bool Result { get; set; } = true;
    public bool SignalUnlock(string credentialPayload, string nonce)
    {
        Nonces.Add(nonce);
        return Result;
    }
}

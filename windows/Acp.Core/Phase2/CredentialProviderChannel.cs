using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Acp.Shared.Ipc;

namespace Acp.Core.Phase2;

/// <summary>The real Core→CP channel: a one-shot write to the SYSTEM-only
/// named pipe the credential provider listens on inside LogonUI
/// (\\.\pipe\acp-cp-unlock). Wire protocol (UTF-8 lines): nonce,
/// username, domain, password. The username/domain are host config —
/// the vault delivers only the secret, and only into this channel.
///
/// Honest limit, named: SignalUnlock reports DELIVERY, not the logon
/// outcome. A wrong vaulted password fails inside LogonUI after
/// delivery; the CP's ReportResult has no callback pipe in this build,
/// so the one-attempt brake degrades on delivery failure, and outcome
/// feedback is a named remainder (BUILD-REPORT). No automatic retry
/// exists anywhere: RequestUnlockAsync runs once per explicit call.</summary>
public sealed class PipeCredentialProviderChannel : ICredentialProviderChannel
{
    private readonly string _username;
    private readonly string _domain;

    public PipeCredentialProviderChannel(string username, string domain)
    {
        _username = username;
        _domain = domain;
    }

    public bool SignalUnlock(string credentialPayload, string nonce)
    {
        if (!OperatingSystem.IsWindows()) return false;
        // W12 / DS-P6-F18: the wire protocol is newline-delimited with
        // no escaping. A field containing a newline would be parsed by
        // the CP as extra fields (truncated/misaligned credential), so
        // such a delivery REFUSES instead of writing a corrupt record.
        if (ContainsNewline(nonce) || ContainsNewline(_username) ||
            ContainsNewline(_domain) || ContainsNewline(credentialPayload))
            return false;
        try
        {
            using var pipe = new NamedPipeClientStream(".", "acp-cp-unlock", PipeDirection.Out);
            pipe.Connect(2000);
            // BD-WIN-AGENT F3 (Core-side limb): NEVER write the
            // password to an unverified pipe server. The server must
            // be LogonUI.exe (the only process that hosts credential
            // providers) running as SYSTEM; a squatter that grabbed
            // the pipe name first gets nothing. Any failure to prove
            // identity refuses the delivery (fail closed).
            if (!VerifyPipeServer(pipe)) return false;
            var bytes = Encoding.UTF8.GetBytes($"{nonce}\n{_username}\n{_domain}\n{credentialPayload}\n");
            pipe.Write(bytes, 0, bytes.Length);
            pipe.Flush();
            return true;
        }
        catch { return false; }
    }

    private static bool ContainsNewline(string? value) =>
        value is not null && (value.Contains('\n') || value.Contains('\r'));

    /// <summary>Prove the connected pipe server is LogonUI running
    /// as SYSTEM (BD-WIN-AGENT F3). Mirrors the CP-side client check
    /// (AcpCredentialProvider.ClientIsCoreSystem) in the opposite
    /// direction, so both ends authenticate the process across the
    /// pipe before any credential moves.</summary>
    private static bool VerifyPipeServer(NamedPipeClientStream pipe)
    {
        var handle = pipe.SafePipeHandle.DangerousGetHandle();
        if (handle == IntPtr.Zero) return false;
        if (!Native.GetNamedPipeServerProcessId(handle, out var pid) || pid == 0) return false;
        var proc = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (proc == IntPtr.Zero) return false;
        try
        {
            var sb = new StringBuilder(1024);
            var size = (uint)sb.Capacity;
            if (!Native.QueryFullProcessImageName(proc, 0, sb, ref size)) return false;
            if (!CpPipeTrust.IsCredentialHostImage(sb.ToString())) return false;
            if (!Native.OpenProcessToken(proc, Native.TOKEN_QUERY, out var token)) return false;
            try
            {
                Native.GetTokenInformation(token, 1 /* TokenUser */, IntPtr.Zero, 0, out var need);
                if (need == 0) return false;
                var buf = Marshal.AllocHGlobal((int)need);
                try
                {
                    if (!Native.GetTokenInformation(token, 1, buf, need, out _)) return false;
                    var sid = Marshal.ReadIntPtr(buf); // TOKEN_USER.User.Sid is the first field
                    if (!Native.ConvertSidToStringSid(sid, out var strPtr)) return false;
                    try { return Marshal.PtrToStringUni(strPtr) == "S-1-5-18"; } // SYSTEM
                    finally { Native.LocalFree(strPtr); }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { Native.CloseHandle(token); }
        }
        finally { Native.CloseHandle(proc); }
    }

    private static class Native
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageName(IntPtr proc, uint flags, StringBuilder name, ref uint size);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, uint len, out uint need);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr mem);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr h);
    }
}

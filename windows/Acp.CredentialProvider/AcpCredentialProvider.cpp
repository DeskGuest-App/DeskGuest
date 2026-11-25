// ACP-Windows Credential Provider (DESIGN §5.4, census Phase 2 unlock).
//
// A THIN COURIER, by design:
//  - It adds exactly ONE extra sign-in tile ("ACP Agent Unlock") and
//    NEVER filters, hides, or replaces the built-in providers: the owner's
//    standard password/PIN tiles are always present (verified as a
//    supervised step at first enable — THE OWNER'S MORNING LIST item (e)).
//  - It never auto-logs-on: GetCredentialCount always reports
//    pbAutoLogonWithDefault = FALSE. A logon happens only after the
//    Core (SYSTEM, policy-checked, STOP-aware) delivers a one-shot
//    credential over the SYSTEM-only named pipe, and LogonUI selects
//    this tile.
//  - The password exists in this process only between delivery and
//    serialization, and is SecureZeroMemory'd immediately after.
//  - All policy (scope, STOP, one-attempt brake, Hello-only check)
//    lives in the Core. This DLL decides nothing.
//
// COMPILED with mingw-w64 in the build sandbox. UNPROVEN-ON-WINDOWS:
// a credential provider can only be truly exercised inside LogonUI on
// the laptop, supervised, with a scratch account first (DESIGN §5.4).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <strsafe.h>
#include <sddl.h>
#include <string>
#include <vector>

#pragma comment(lib, "secur32.lib")

// {7D3A9C41-5E2B-4F8A-B1C6-9E4D2A8F6B50} — ACP Credential Provider.
static const CLSID CLSID_AcpCredentialProvider =
    { 0x7d3a9c41, 0x5e2b, 0x4f8a, { 0xb1, 0xc6, 0x9e, 0x4d, 0x2a, 0x8f, 0x6b, 0x50 } };
// BD-WIN-AGENT F1: the serialization's clsidCredentialProvider is
// THIS provider's own CLSID (CLSID_AcpCredentialProvider above) —
// the pre-fix code stamped the Kerberos provider's GUID
// (ac3ac249-…) there, misidentifying who produced the package.

static HINSTANCE g_hInst = nullptr;
static long g_cRefModule = 0;

namespace {

struct PendingCredential {
    std::wstring username;
    std::wstring domain;
    std::wstring password; // zeroized on consume/clear
    std::wstring nonce;
    ULONGLONG deliveredTick = 0;
    bool present = false;
};


CRITICAL_SECTION g_cs;
PendingCredential g_pending;
ICredentialProviderEvents* g_events = nullptr;
HANDLE g_pipeThread = nullptr;
bool g_stopPipe = false;
// BD-WIN-AGENT F2: the last accepted delivery nonce. A nonce is a
// ONE-SHOT capability: a second delivery carrying the same nonce is
// a replay and is rejected, so a captured delivery can never be
// re-presented. (The Core mints a fresh nonce per delivery.)
// W10 / V2-X3: the pre-fix code remembered only the SINGLE most
// recent nonce, so nonce A became acceptable again as soon as B
// landed. Spent nonces are now a bounded set (128 — far beyond any
// plausible delivery rate inside a lock-screen episode); the oldest
// is evicted only when the bound is hit.
static const size_t kMaxSpentNonces = 128;
std::vector<std::wstring> g_spentNonces;
bool NonceSpentLocked(const std::wstring& nonce) {
    for (auto& n : g_spentNonces) if (n == nonce) return true;
    return false;
}
void SpendNonceLocked(const std::wstring& nonce) {
    g_spentNonces.push_back(nonce);
    if (g_spentNonces.size() > kMaxSpentNonces)
        g_spentNonces.erase(g_spentNonces.begin());
}

void ClearPendingLocked() {
    if (!g_pending.password.empty())
        SecureZeroMemory(&g_pending.password[0], g_pending.password.size() * sizeof(wchar_t));
    g_pending = PendingCredential();
}
// A delivered credential is a ONE-SHOT, SHORT-LIVED capability
// (second-inspector H5): it must be consumed within 60 seconds of
// delivery or it evaporates. The nonce the Core minted for this
// delivery is recorded with it; a delivery that is never consumed
// never lingers in LogonUI memory waiting for a tile click.
static const ULONGLONG kPendingTtlMs = 60000;
bool PendingValidLocked() {
    if (!g_pending.present) return false;
    if (GetTickCount64() - g_pending.deliveredTick > kPendingTtlMs) {
        ClearPendingLocked();
        return false;
    }
    return true;
}

// BD-WIN-AGENT F2: the delivery's caller must BE the Core running
// as SYSTEM — the pipe DACL alone cannot prove that (any SYSTEM
// process could connect). Verify the client process image is
// AcpCore.exe and its token user is the SYSTEM SID. Any failure
// returns false and the delivery is dropped unread-as-credential.
// W10 / V2-C3: the image test is no longer a file-NAME compare —
// a SYSTEM process could drop a copy named AcpCore.exe anywhere.
// The expected image is the FULL PATH the installer registered as
// the AcpCore service's ImagePath (HKLM\SYSTEM\CurrentControlSet\
// Services\AcpCore): the one location the service manager itself
// launches. If that registration cannot be read, the check FAILS
// CLOSED — this provider is only ever enabled by the installer
// that registers the service, so a missing registration means the
// install is not the sanctioned one.
bool RegisteredCoreImagePath(std::wstring& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\AcpCore", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;
    wchar_t buf[MAX_PATH * 2];
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    bool ok = RegQueryValueExW(key, L"ImagePath", nullptr, &type, (BYTE*)buf, &cb) == ERROR_SUCCESS
        && (type == REG_SZ || type == REG_EXPAND_SZ);
    RegCloseKey(key);
    if (!ok) return false;
    std::wstring v(buf);
    if (!v.empty() && v.front() == L'"') {
        size_t end = v.find(L'"', 1);
        v = (end == std::wstring::npos) ? v.substr(1) : v.substr(1, end - 1);
    }
    wchar_t expanded[MAX_PATH * 2];
    if (ExpandEnvironmentStringsW(v.c_str(), expanded, (DWORD)(sizeof(expanded) / sizeof(expanded[0]))))
        v = expanded;
    out = v;
    return !out.empty();
}

bool ClientIsCoreSystem(HANDLE pipe) {
    DWORD pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return false;
    bool ok = false;
    wchar_t image[MAX_PATH * 2];
    DWORD imageLen = (DWORD)(sizeof(image) / sizeof(image[0]));
    std::wstring expectedCore;
    if (QueryFullProcessImageNameW(proc, 0, image, &imageLen)
        && RegisteredCoreImagePath(expectedCore)) {
        if (_wcsicmp(image, expectedCore.c_str()) == 0) {
            HANDLE token = nullptr;
            if (OpenProcessToken(proc, TOKEN_QUERY, &token)) {
                DWORD need = 0;
                GetTokenInformation(token, TokenUser, nullptr, 0, &need);
                if (need > 0) {
                    auto* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, need);
                    if (buf) {
                        if (GetTokenInformation(token, TokenUser, buf, need, &need)) {
                            auto* tu = (TOKEN_USER*)buf;
                            LPWSTR sidStr = nullptr;
                            if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
                                ok = wcscmp(sidStr, L"S-1-5-18") == 0; // SYSTEM
                                LocalFree(sidStr);
                            }
                        }
                        HeapFree(GetProcessHeap(), 0, buf);
                    }
                }
                CloseHandle(token);
            }
        }
    }
    CloseHandle(proc);
    return ok;
}

// Line protocol (UTF-8 on the wire, converted here):
//   nonce \n username \n domain \n password \n
// BD-WIN-AGENT F2: a delivery is accepted ONLY when it is exactly
// 4 non-empty lines, fits the byte cap, carries a fresh nonce of
// plausible shape, and comes from the verified Core process. The
// pre-fix loop accepted ANY connection — including StopPipeThread's
// own empty throwaway connection — as a valid pending credential.
DWORD WINAPI PipeThreadProc(LPVOID) {
    static const wchar_t* kPipeName = L"\\\\.\\pipe\\acp-cp-unlock";
    static const size_t kMaxDeliveryBytes = 8192;
    // SYSTEM-only DACL: SDDL "D:(A;;GA;;;SY)".
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)", SDDL_REVISION_1, &sd, nullptr))
        return 0;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    while (!g_stopPipe) {
        // FILE_FLAG_FIRST_PIPE_INSTANCE (F3): if another process
        // already owns this pipe name, creation FAILS instead of
        // silently queueing behind a squatter that would receive
        // the password the Core sends. The failure is surfaced on
        // the debug channel, never silent.
        HANDLE pipe = CreateNamedPipeW(kPipeName,
            PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 0, 64 * 1024, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            OutputDebugStringW(L"ACP CP: CreateNamedPipeW failed (pipe name already owned?); unlock delivery is DOWN\n");
            break;
        }
        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            // StopPipeThread's wake-up client (and process shutdown)
            // must never be parsed as a delivery (F2).
            if (!g_stopPipe && ClientIsCoreSystem(pipe)) {
                char buf[4096];
                DWORD read = 0;
                std::string all;
                bool oversize = false;
                while (ReadFile(pipe, buf, sizeof(buf), &read, nullptr) && read > 0) {
                    all.append(buf, read);
                    if (all.size() > kMaxDeliveryBytes) { oversize = true; break; }
                }
                DisconnectNamedPipe(pipe);
                // Split into lines; one trailing empty segment from
                // the final newline is the protocol's terminator,
                // not a fifth field.
                std::vector<std::string> parts;
                size_t pos = 0;
                while (true) {
                    size_t nl = all.find('\n', pos);
                    if (nl == std::string::npos) { parts.push_back(all.substr(pos)); break; }
                    parts.push_back(all.substr(pos, nl - pos));
                    pos = nl + 1;
                }
                if (!parts.empty() && parts.back().empty()) parts.pop_back();
                for (auto& p : parts)
                    if (!p.empty() && p.back() == '\r') p.pop_back();
                bool valid = !oversize && parts.size() == 4;
                if (valid)
                    for (auto& p : parts)
                        if (p.empty()) valid = false;
                if (valid && parts[0].size() < 16) valid = false; // nonce shape floor
                auto toWide = [](const std::string& s) {
                    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
                    std::wstring w(n, L'\0');
                    if (n) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
                    return w;
                };
                ICredentialProviderEvents* events = nullptr;
                if (valid) {
                    auto nonce = toWide(parts[0]);
                    EnterCriticalSection(&g_cs);
                    if (NonceSpentLocked(nonce)) {
                        valid = false; // replay of a spent nonce (F2 + W10 bounded set)
                    } else {
                        ClearPendingLocked();
                        SpendNonceLocked(nonce);
                        g_pending.nonce = nonce;
                        g_pending.username = toWide(parts[1]);
                        g_pending.domain = toWide(parts[2]);
                        g_pending.password = toWide(parts[3]);
                        g_pending.deliveredTick = GetTickCount64();
                        g_pending.present = true;
                        events = g_events;
                    }
                    LeaveCriticalSection(&g_cs);
                }
                // The parse copies are zeroized too (Block H find):
                // parts[3] is a second, unzeroized copy of the
                // password that otherwise lingers in freed heap
                // memory, against this file's own invariant that the
                // password exists only between delivery and
                // serialization.
                for (auto& part : parts)
                    if (!part.empty()) SecureZeroMemory(&part[0], part.size());
                if (!all.empty()) SecureZeroMemory(&all[0], all.size());
                if (events) events->CredentialsChanged(0);
            } else {
                DisconnectNamedPipe(pipe);
            }
        }
        CloseHandle(pipe);
    }
    LocalFree(sd);
    return 0;
}

void StartPipeThread() {
    if (g_pipeThread) return;
    g_stopPipe = false;
    g_pipeThread = CreateThread(nullptr, 0, PipeThreadProc, nullptr, 0, nullptr);
}
void StopPipeThread() {
    g_stopPipe = true;
    // Wake the blocking ConnectNamedPipe with a throwaway client.
    HANDLE h = CreateFileW(L"\\\\.\\pipe\\acp-cp-unlock", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (g_pipeThread) { WaitForSingleObject(g_pipeThread, 2000); CloseHandle(g_pipeThread); g_pipeThread = nullptr; }
}

enum FieldId { FID_LABEL = 0, FID_SUBMIT = 1, FID_COUNT = 2 };

class Credential : public ICredentialProviderCredential {
    long _ref = 1;
    ICredentialProviderCredentialEvents* _events = nullptr;
    // BD-WIN-AGENT F1: the usage scenario decides the serialization
    // shape (interactive logon vs workstation unlock). The Provider
    // stamps it in SetUsageScenario; the pre-fix GetSerialization
    // always built KerbInteractiveLogon, which Winlogon rejects for
    // CPUS_UNLOCK_WORKSTATION.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _scenario = CPUS_LOGON;
public:
    Credential() { InterlockedIncrement(&g_cRefModule); }
    void SetScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO s) { _scenario = s; }
    ~Credential() { InterlockedDecrement(&g_cRefModule); }

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) { *ppv = static_cast<ICredentialProviderCredential*>(this); AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&_ref); }
    ULONG STDMETHODCALLTYPE Release() override { long r = InterlockedDecrement(&_ref); if (!r) delete this; return r; }

    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents* e) override { _events = e; return S_OK; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { _events = nullptr; return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* pbAutoLogon) override {
        // Auto-submit ONLY when a credential is actually pending: the
        // Core asked for this logon, policy already approved it there.
        EnterCriticalSection(&g_cs);
        *pbAutoLogon = PendingValidLocked() ? TRUE : FALSE;
        LeaveCriticalSection(&g_cs);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetDeselected() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* pState, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pInteractive) override {
        if (id >= FID_COUNT || !pState) return E_INVALIDARG;
        *pState = CPFS_DISPLAY_IN_BOTH;
        if (pInteractive) *pInteractive = (id == FID_SUBMIT) ? CPFIS_FOCUSED : CPFIS_NONE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStringValue(DWORD id, LPWSTR* ppsz) override {
        if (id != FID_LABEL || !ppsz) return E_INVALIDARG;
        const wchar_t* text = L"ACP Agent Unlock";
        size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t);
        *ppsz = (LPWSTR)CoTaskMemAlloc(bytes);
        if (!*ppsz) return E_OUTOFMEMORY;
        StringCbCopyW(*ppsz, bytes, text);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD, HBITMAP*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD, BOOL*, LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD id, DWORD* pAdjacent) override {
        if (id != FID_SUBMIT || !pAdjacent) return E_INVALIDARG;
        *pAdjacent = FID_LABEL;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD, DWORD, LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD, LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override { return E_NOTIMPL; }

    HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pResponse,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pSerialization,
        LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override {
        EnterCriticalSection(&g_cs);
        if (!PendingValidLocked()) { LeaveCriticalSection(&g_cs); return E_FAIL; }
        PendingCredential cred = g_pending;
        ClearPendingLocked(); // one-shot: consumed whether or not logon succeeds
        LeaveCriticalSection(&g_cs);

        HRESULT hr = E_FAIL;
        // BD-WIN-AGENT F1 — the KerbInteractiveLogonPack pattern from
        // Microsoft's credential-provider sample:
        //  * The struct is PACKED for a process boundary: each
        //    UNICODE_STRING.Buffer holds the OFFSET of its bytes
        //    from the start of the serialization buffer, never an
        //    absolute in-process pointer (the pre-fix code wrote
        //    raw pointers, which are meaningless inside Winlogon).
        //  * CPUS_UNLOCK_WORKSTATION serializes a
        //    KERB_INTERACTIVE_UNLOCK_LOGON with MessageType
        //    KerbWorkstationUnlockLogon; a plain logon uses
        //    KERB_INTERACTIVE_LOGON / KerbInteractiveLogon.
        //  * The authentication package is Negotiate (the sample's
        //    package for Kerb interactive/unlock submissions).
        //  * clsidCredentialProvider is THIS provider's CLSID.
        // Named remainder: the unlock struct's LogonId is zeroed —
        // capturing the locked session's LogonId requires
        // SetSerialization, which this provider does not implement;
        // the unlock path stays UNPROVEN-ON-WINDOWS until the
        // supervised scratch-account LogonUI proof runs.
        const bool unlock = (_scenario == CPUS_UNLOCK_WORKSTATION);
        const ULONG structSize = unlock ? (ULONG)sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)
                                        : (ULONG)sizeof(KERB_INTERACTIVE_LOGON);
        auto bytesOf = [](const std::wstring& s) { return (ULONG)(s.size() * sizeof(wchar_t)); };
        ULONG total = structSize + bytesOf(cred.domain) + bytesOf(cred.username) + bytesOf(cred.password);
        BYTE* buffer = (BYTE*)CoTaskMemAlloc(total);
        if (buffer) {
            SecureZeroMemory(buffer, total);
            KERB_INTERACTIVE_LOGON* logon = unlock
                ? &((KERB_INTERACTIVE_UNLOCK_LOGON*)buffer)->Logon
                : (KERB_INTERACTIVE_LOGON*)buffer;
            BYTE* cursor = buffer + structSize;
            auto place = [&](UNICODE_STRING& field, const std::wstring& value) {
                field.Length = (USHORT)bytesOf(value);
                field.MaximumLength = (USHORT)bytesOf(value);
                // Offset from the start of the buffer, stored in the
                // Buffer field — the pack convention LSA unpacks.
                field.Buffer = (PWSTR)(ULONG_PTR)(cursor - buffer);
                if (!value.empty()) memcpy(cursor, value.data(), bytesOf(value));
                cursor += bytesOf(value);
            };
            logon->MessageType = unlock ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
            place(logon->LogonDomainName, cred.domain);
            place(logon->UserName, cred.username);
            place(logon->Password, cred.password);

            // Resolve the Negotiate authentication package id. If it
            // cannot be resolved, FAIL (M6b): returning success with
            // package 0 would hand Winlogon a nonsense serialization.
            HANDLE lsa = nullptr;
            ULONG pkg = 0;
            bool resolved = false;
            if (LsaConnectUntrusted(&lsa) == 0) {
                // NEGOSSP_NAME_A is the literal "Negotiate"; the
                // macro is not declared by mingw-w64's ntsecapi.h,
                // so name the package directly (same bytes MSVC's
                // macro expands to).
                static char kNegotiateName[] = "Negotiate";
                STRING name; name.Buffer = (PCHAR)kNegotiateName; name.Length = (USHORT)strlen(kNegotiateName); name.MaximumLength = (USHORT)(name.Length + 1);
                resolved = LsaLookupAuthenticationPackage(lsa, &name, &pkg) == 0;
                LsaDeregisterLogonProcess(lsa);
            }
            if (!resolved) {
                SecureZeroMemory(buffer, total);
                CoTaskMemFree(buffer);
                if (!cred.password.empty())
                    SecureZeroMemory(&cred.password[0], cred.password.size() * sizeof(wchar_t));
                // NOTE: the critical section was already released above
                // (the pending credential is consumed before this point).
                if (ppszOptionalStatusText) *ppszOptionalStatusText = nullptr;
                if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_ERROR;
                return E_FAIL;
            }
            pSerialization->ulAuthenticationPackage = pkg;
            pSerialization->rgbSerialization = buffer;
            pSerialization->cbSerialization = total;
            pSerialization->clsidCredentialProvider = CLSID_AcpCredentialProvider;
            *pResponse = CPGSR_RETURN_CREDENTIAL_FINISHED;
            hr = S_OK;
        }
        if (!cred.password.empty())
            SecureZeroMemory(&cred.password[0], cred.password.size() * sizeof(wchar_t));
        if (ppszOptionalStatusText) *ppszOptionalStatusText = nullptr;
        if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS, NTSTATUS, LPWSTR* ppsz, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsi) override {
        if (ppsz) *ppsz = nullptr;
        if (pcpsi) *pcpsi = CPSI_NONE;
        return S_OK;
    }
};

class Provider : public ICredentialProvider {
    long _ref = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _scenario = CPUS_INVALID;
    Credential* _credential = nullptr;
public:
    Provider() { InterlockedIncrement(&g_cRefModule); _credential = new Credential(); }
    ~Provider() { if (_credential) _credential->Release(); InterlockedDecrement(&g_cRefModule); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider) { *ppv = static_cast<ICredentialProvider*>(this); AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&_ref); }
    ULONG STDMETHODCALLTYPE Release() override { long r = InterlockedDecrement(&_ref); if (!r) delete this; return r; }

    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override {
        // BD-WIN-AGENT F3: CPUS_CREDUI is REFUSED. CredUI loads the
        // provider into ordinary user processes, where the pre-fix
        // code started the same single-instance pipe server and
        // SetSelected auto-submitted the pending lock-screen
        // credential into an arbitrary app's prompt. This provider
        // exists for the logon/unlock surfaces only.
        if (scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION) {
            _scenario = scenario;
            if (_credential) _credential->SetScenario(scenario);
            StartPipeThread();
            return S_OK;
        }
        return E_NOTIMPL; // CredUI, change-password and others: not our business
    }
    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* events, UINT_PTR context) override {
        EnterCriticalSection(&g_cs);
        g_events = events;
        if (g_events) g_events->AddRef();
        LeaveCriticalSection(&g_cs);
        (void)context;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UnAdvise() override {
        EnterCriticalSection(&g_cs);
        if (g_events) { g_events->Release(); g_events = nullptr; }
        ClearPendingLocked();
        LeaveCriticalSection(&g_cs);
        StopPipeThread();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* pCount) override { *pCount = FID_COUNT; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD id, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppDesc) override {
        if (id >= FID_COUNT || !ppDesc) return E_INVALIDARG;
        static const CREDENTIAL_PROVIDER_FIELD_TYPE types[FID_COUNT] = { CPFT_LARGE_TEXT, CPFT_SUBMIT_BUTTON };
        static const wchar_t* labels[FID_COUNT] = { L"ACP Agent Unlock", L"Unlock" };
        auto* desc = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
        if (!desc) return E_OUTOFMEMORY;
        desc->dwFieldID = id;
        desc->cpft = types[id];
        size_t bytes = (wcslen(labels[id]) + 1) * sizeof(wchar_t);
        desc->pszLabel = (LPWSTR)CoTaskMemAlloc(bytes);
        if (!desc->pszLabel) { CoTaskMemFree(desc); return E_OUTOFMEMORY; }
        StringCbCopyW(desc->pszLabel, bytes, labels[id]);
        desc->guidFieldType = GUID_NULL;
        *ppDesc = desc;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* pCount, DWORD* pDefault, BOOL* pbAutoLogonWithDefault) override {
        *pCount = 1;
        *pDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE; // NEVER auto-logon (see header)
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD id, ICredentialProviderCredential** ppCredential) override {
        if (id != 0 || !ppCredential) return E_INVALIDARG;
        *ppCredential = _credential;
        _credential->AddRef();
        return S_OK;
    }
};

class Factory : public IClassFactory {
    long _ref = 1;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&_ref); }
    ULONG STDMETHODCALLTYPE Release() override { long r = InterlockedDecrement(&_ref); if (!r) delete this; return r; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv) override {
        if (pOuter) return CLASS_E_NOAGGREGATION;
        auto* provider = new Provider();
        HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_cRefModule); else InterlockedDecrement(&g_cRefModule);
        return S_OK;
    }
};

} // namespace

extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid != CLSID_AcpCredentialProvider) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new Factory();
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}
extern "C" HRESULT __stdcall DllCanUnloadNow() { return g_cRefModule <= 0 ? S_OK : S_FALSE; }

static HRESULT SetRegSz(HKEY key, const wchar_t* name, const wchar_t* value) {
    return HRESULT_FROM_WIN32(RegSetValueExW(key, name, 0, REG_SZ, (const BYTE*)value,
        (DWORD)((wcslen(value) + 1) * sizeof(wchar_t))));
}

extern "C" HRESULT __stdcall DllRegisterServer() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(g_hInst, path, MAX_PATH);
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{7D3A9C41-5E2B-4F8A-B1C6-9E4D2A8F6B50}", 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return E_FAIL;
    SetRegSz(key, nullptr, L"ACP Agent Unlock");
    HKEY inproc = nullptr;
    RegCreateKeyExW(key, L"InProcServer32", 0, nullptr, 0, KEY_WRITE, nullptr, &inproc, nullptr);
    if (inproc) { SetRegSz(inproc, nullptr, path); SetRegSz(inproc, L"ThreadingModel", L"Apartment"); RegCloseKey(inproc); }
    RegCloseKey(key);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7D3A9C41-5E2B-4F8A-B1C6-9E4D2A8F6B50}", 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return E_FAIL;
    SetRegSz(key, nullptr, L"ACP Agent Unlock");
    RegCloseKey(key);
    return S_OK;
}

extern "C" HRESULT __stdcall DllUnregisterServer() {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{7D3A9C41-5E2B-4F8A-B1C6-9E4D2A8F6B50}");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{7D3A9C41-5E2B-4F8A-B1C6-9E4D2A8F6B50}");
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hInst;
        InitializeCriticalSection(&g_cs);
        DisableThreadLibraryCalls(hInst);
    } else if (reason == DLL_PROCESS_DETACH) {
        // NEVER wait, create handles, or tear down threads under the
        // loader lock (M6a — the classic LogonUI detach deadlock).
        // Just flag the stop; the pipe thread exits on its own or dies
        // with the process. The critical section is process-lifetime.
        g_stopPipe = true;
    }
    return TRUE;
}

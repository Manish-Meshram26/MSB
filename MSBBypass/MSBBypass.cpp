// MSBBypass.cpp
//
// ONE-CLICK MSB Bypass Tool — Security Testing Only
//
// How it works:
//   1. Extracts the embedded DLL from itself to %TEMP%
//   2. Watches for MSB, Task Manager, and WMI processes
//   3. Injects the DLL into each one automatically
//   4. DLL auto-configures: hides RemotePC, blocks SM_REMOTESESSION
//   5. No user input required — just run as admin
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <set>
#include "resource.h"

// ─────────────────────────────────────────────────────────────────────
// STEP 1: Extract embedded DLL to %TEMP%
// ─────────────────────────────────────────────────────────────────────
std::string ExtractDLL() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD_DLL), RT_RCDATA);
    if (!hRes) {
        std::cerr << "[ERROR] DLL resource not found in EXE!" << std::endl;
        return "";
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    DWORD size = SizeofResource(NULL, hRes);
    void* data = LockResource(hData);

    if (!data || size == 0) {
        std::cerr << "[ERROR] Failed to load DLL resource!" << std::endl;
        return "";
    }

    // Write to %TEMP% with a unique name each run
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    std::string dllPath = std::string(tempDir) + "svc_" + std::to_string(GetTickCount()) + ".dll";

    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] Cannot write DLL to " << dllPath << std::endl;
        return "";
    }

    DWORD written;
    WriteFile(hFile, data, size, &written, NULL);
    CloseHandle(hFile);

    return dllPath;
}

// ─────────────────────────────────────────────────────────────────────
// STEP 2: Find target processes
// ─────────────────────────────────────────────────────────────────────
struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};

std::vector<ProcessInfo> FindTargets() {
    std::vector<ProcessInfo> results;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe32)) { CloseHandle(hSnap); return results; }

    do {
        std::wstring name(pe32.szExeFile);
        std::wstring lower = name;
        for (auto& c : lower) c = towlower(c);

        bool target = false;
        if (lower.find(L"safeexam") != std::wstring::npos) target = true;
        if (lower.find(L"msb.exe") != std::wstring::npos) target = true;
        if (lower.find(L"mettl") != std::wstring::npos) target = true;
        if (lower.find(L"cefsharp") != std::wstring::npos) target = true;
        if (lower.find(L"wmiprvse") != std::wstring::npos) target = true;
        if (lower.find(L"taskmgr") != std::wstring::npos) target = true;

        if (target) {
            results.push_back({ pe32.th32ProcessID, name });
        }
    } while (Process32NextW(hSnap, &pe32));

    CloseHandle(hSnap);
    return results;
}

// ─────────────────────────────────────────────────────────────────────
// STEP 3: Inject DLL into a process
// ─────────────────────────────────────────────────────────────────────
bool Inject(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    LPVOID mem = VirtualAllocEx(hProc, nullptr, dllPath.size() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(hProc); return false; }

    WriteProcessMemory(hProc, mem, dllPath.c_str(), dllPath.size() + 1, nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        mem, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, 3000);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return exitCode != 0;
}

// ─────────────────────────────────────────────────────────────────────
// CLEANUP: Delete extracted DLL on exit
// ─────────────────────────────────────────────────────────────────────
std::string g_dllPath;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        if (!g_dllPath.empty()) {
            DeleteFileA(g_dllPath.c_str());
        }
        std::cout << "\n[*] Cleaned up. Hooks remain active until target processes exit." << std::endl;
        ExitProcess(0);
    }
    return TRUE;
}

// ─────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────
int main() {
    SetConsoleTitleA("MSB Security Test");

    // Check admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);

    if (!isAdmin) {
        std::cerr << "[!] This tool must be run as Administrator." << std::endl;
        std::cerr << "    Right-click -> Run as administrator" << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "  MSB Security Test Tool                " << std::endl;
    std::cout << "  For authorized security testing only  " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Step 1: Extract DLL
    std::cout << "[1/3] Extracting payload... ";
    g_dllPath = ExtractDLL();
    if (g_dllPath.empty()) {
        system("pause");
        return 1;
    }
    std::cout << "OK" << std::endl;

    // Register cleanup handler
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Step 2: Info
    std::cout << "[2/3] Hooks configured:" << std::endl;
    std::cout << "      - NtQuerySystemInformation (process hiding)" << std::endl;
    std::cout << "      - GetSystemMetrics (remote session spoofing)" << std::endl;
    std::cout << "      - Hiding: all *RemotePC* and *RPC* processes" << std::endl;
    std::cout << std::endl;

    // Step 3: Watch mode
    std::cout << "[3/3] Watching for target processes..." << std::endl;
    std::cout << std::endl;
    std::cout << "  Start Mettl Secure Browser now." << std::endl;
    std::cout << "  Press Ctrl+C when done testing." << std::endl;
    std::cout << std::endl;

    std::set<DWORD> injected;
    int totalHooked = 0;

    while (true) {
        auto targets = FindTargets();

        for (auto& t : targets) {
            if (injected.find(t.pid) != injected.end()) continue;

            bool ok = Inject(t.pid, g_dllPath);
            injected.insert(t.pid);

            if (ok) {
                std::wcout << "  [+] " << t.name << " (PID " << t.pid << ") - hooked" << std::endl;
                totalHooked++;
            }
            else {
                std::wcout << "  [-] " << t.name << " (PID " << t.pid << ") - failed" << std::endl;
            }
        }

        // Clean dead PIDs
        std::set<DWORD> alive;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do { alive.insert(pe.th32ProcessID); } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);

            std::vector<DWORD> dead;
            for (DWORD pid : injected) {
                if (alive.find(pid) == alive.end()) dead.push_back(pid);
            }
            for (DWORD pid : dead) injected.erase(pid);
        }

        Sleep(50);  // Check every 50ms — catch processes before they scan
    }

    return 0;
}

// UniversalInjector.cpp
// 
// WATCH MODE: Continuously monitors for new MSB processes and injects
// immediately. This solves the timing problem where SafeExamBrowser.Client.exe
// is spawned AFTER initial injection and runs its checks before we can hook it.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <set>

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};

// Track which PIDs we've already injected into
std::set<DWORD> injectedPids;

std::vector<ProcessInfo> FindTargetProcesses() {
    std::vector<ProcessInfo> results;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &pe32)) { CloseHandle(hSnapshot); return results; }

    do {
        std::wstring name(pe32.szExeFile);
        std::wstring nameLower = name;
        for (auto& c : nameLower) c = towlower(c);

        bool isTarget = false;
        if (nameLower.find(L"safeexam") != std::wstring::npos) isTarget = true;
        if (nameLower.find(L"msb") != std::wstring::npos) isTarget = true;
        if (nameLower.find(L"mettl") != std::wstring::npos) isTarget = true;
        if (nameLower.find(L"wmiprvse") != std::wstring::npos) isTarget = true;

        if (isTarget && injectedPids.find(pe32.th32ProcessID) == injectedPids.end()) {
            results.push_back({ pe32.th32ProcessID, name });
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return results;
}

bool InjectDLL(DWORD processId, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { CloseHandle(hProcess); return false; }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLibAddr, remoteMem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 3000);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return exitCode != 0;
}

int main() {
    std::cout << "================================================" << std::endl;
    std::cout << "  MSB Full Bypass - WATCH MODE                  " << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;
    std::cout << "This injector runs CONTINUOUSLY and watches for" << std::endl;
    std::cout << "new MSB processes. Run this BEFORE starting MSB." << std::endl;
    std::cout << std::endl;

    std::string dllPath;
    std::cout << "Enter FULL path to TaskManagerHack.dll:" << std::endl << "> ";
    std::getline(std::cin, dllPath);

    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[ERROR] File not found: " << dllPath << std::endl;
        system("pause"); return 1;
    }
    std::cout << "[OK] DLL found." << std::endl << std::endl;

    std::cout << "Choose mode:" << std::endl;
    std::cout << "  1. Task Manager (one-shot)" << std::endl;
    std::cout << "  2. MSB Full Bypass (WATCH MODE - run before starting MSB)" << std::endl;
    std::cout << "  3. Custom process (one-shot)" << std::endl << "> ";

    std::string choice;
    std::getline(std::cin, choice);
    std::cout << std::endl;

    if (choice == "1") {
        // One-shot Task Manager injection
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
        Process32FirstW(hSnapshot, &pe32);
        DWORD pid = 0;
        do {
            if (_wcsicmp(pe32.szExeFile, L"Taskmgr.exe") == 0) { pid = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
        CloseHandle(hSnapshot);
        if (!pid) { std::cerr << "[ERROR] Task Manager not running!" << std::endl; system("pause"); return 1; }
        std::cout << "Injecting into Taskmgr.exe (PID: " << pid << ")... ";
        std::cout << (InjectDLL(pid, dllPath) ? "OK" : "FAILED") << std::endl;
        system("pause"); return 0;
    }
    else if (choice == "3") {
        std::string procName;
        std::cout << "Enter process name: ";
        std::getline(std::cin, procName);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
        Process32FirstW(hSnapshot, &pe32);
        DWORD pid = 0;
        do {
            std::wstring target(procName.begin(), procName.end());
            if (_wcsicmp(pe32.szExeFile, target.c_str()) == 0) { pid = pe32.th32ProcessID; break; }
        } while (Process32NextW(hSnapshot, &pe32));
        CloseHandle(hSnapshot);
        if (!pid) { std::cerr << "[ERROR] Not found!" << std::endl; system("pause"); return 1; }
        std::cout << "Injecting... " << (InjectDLL(pid, dllPath) ? "OK" : "FAILED") << std::endl;
        system("pause"); return 0;
    }
    else if (choice != "2") {
        std::cerr << "Invalid choice." << std::endl;
        system("pause"); return 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  WATCH MODE — Continuously monitor for new MSB processes
    // ═══════════════════════════════════════════════════════════
    std::cout << "╔══════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     WATCH MODE ACTIVE - Waiting for MSB     ║" << std::endl;
    std::cout << "║                                              ║" << std::endl;
    std::cout << "║  1. Start Mettl Secure Browser NOW           ║" << std::endl;
    std::cout << "║  2. Every new MSB process will be hooked     ║" << std::endl;
    std::cout << "║     automatically within 200ms               ║" << std::endl;
    std::cout << "║  3. Press Ctrl+C to stop watching            ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    int totalInjected = 0;

    while (true) {
        auto newTargets = FindTargetProcesses();

        for (auto& t : newTargets) {
            std::wcout << "[NEW] Found: " << t.name << " (PID: " << t.pid << ") ... ";

            if (InjectDLL(t.pid, dllPath)) {
                std::cout << "HOOKED!" << std::endl;
                totalInjected++;
            }
            else {
                std::cout << "failed (may need higher privileges)" << std::endl;
            }

            // Mark as processed regardless (don't retry failures every loop)
            injectedPids.insert(t.pid);
        }

        // Also check if any injected PIDs have died (process restarted with new PID)
        std::set<DWORD> stillAlive;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnap, &pe32)) {
                do {
                    stillAlive.insert(pe32.th32ProcessID);
                } while (Process32NextW(hSnap, &pe32));
            }
            CloseHandle(hSnap);

            // Remove dead PIDs so if the process restarts, we'll reinject
            std::set<DWORD> toRemove;
            for (DWORD pid : injectedPids) {
                if (stillAlive.find(pid) == stillAlive.end()) {
                    toRemove.insert(pid);
                }
            }
            for (DWORD pid : toRemove) {
                injectedPids.erase(pid);
            }
        }

        // Check every 200ms — fast enough to catch the Client before it scans
        Sleep(200);
    }

    return 0;
}

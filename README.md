# MSB Security Vulnerability Assessment Tool

> **⚠️ INTERNAL USE ONLY — Authorized Security Testing**
>
> This tool demonstrates critical security vulnerabilities in Mettl Secure Browser (MSB) v43.x.
> It was developed by the Mettl security team to validate detection gaps before they are exploited in the wild.
> **Do not distribute outside the organization.**

## Summary of Findings

| # | Vulnerability | Severity | Tool Needed? |
|---|---|---|---|
| 1 | Process hiding via inline hooking bypasses all 3 detection layers | **Critical** | ✅ This tool |
| 2 | No integrity checks on ntdll.dll code section | **High** | — |
| 3 | No DLL injection detection | **High** | — |
| 4 | Process scanning runs client-side (hookable), not from the Service | **High** | — |
| 5 | Name-based blacklist trivially bypassed by renaming executables | **Medium** | ❌ None |

## What This Tool Does

A single EXE that:
1. Embeds a hook DLL inside itself
2. Watches for MSB processes and injects the DLL automatically
3. The DLL hooks `NtQuerySystemInformation` (inline) — hides RemotePC from process lists
4. The DLL hooks `GetSystemMetrics` (inline) — spoofs `SM_REMOTESESSION` flag
5. Also injects into `WmiPrvSE.exe` to filter WMI-based process queries
6. Auto-configures — hides all `*RemotePC*` and `*RPC*` processes at load time
7. Persists for the full exam duration

**Result:** RemotePC runs invisibly throughout the entire exam. MSB never detects it.

## Architecture

```
MSBBypass.exe (run as admin before MSB)
│
├─ Extracts embedded DLL to %TEMP%
├─ Watches for new processes every 50ms
│
├─ Injects into SafeExamBrowser.exe ──────┐
├─ Injects into SafeExamBrowser.Client.exe │  Each injected DLL:
├─ Injects into MSB.exe ─────────────────│  ├─ Hooks NtQuerySystemInformation
├─ Injects into CefSharp.*.exe ───────────│  ├─ Hooks GetSystemMetrics
├─ Injects into WmiPrvSE.exe ────────────┘  └─ Auto-hides RemotePC processes
│
└─ Keeps watching for new processes (MSB spawns Client mid-session)
```

## 3 Detection Layers Bypassed

| Layer | MSB's Detection Method | Our Bypass |
|---|---|---|
| 1 | `Process.GetProcesses()` → `NtQuerySystemInformation` | Inline hook on `NtQuerySystemInformation` in ntdll.dll |
| 2 | `RemoteSessionDetector` → `GetSystemMetrics(SM_REMOTESESSION)` | Inline hook on `GetSystemMetrics` in user32.dll |
| 3 | WMI `ManagementObjectSearcher` → `Win32_Process` | Inject into `WmiPrvSE.exe` (WMI provider host) |

## Prerequisites

- **Windows 10/11 x64**
- **RemotePC** installed (the software being hidden)
- **MSB** installed (the software being tested)

## Quick Start (No Build Required)

1. **Disable antivirus** (Windows Defender real-time protection OFF)
2. **Right-click** `dist/MSBBypass.exe` → **Run as administrator**
3. **Start MSB** (Mettl Secure Browser)
4. Enter the exam — MSB will not detect RemotePC

That's it. The tool auto-configures everything.

## Build from Source (Optional)

Only needed if you want to modify the tool. Requires **Visual Studio 2022** with "Desktop development with C++" workload.

### Step 1: Build the DLL

1. Open `TaskManagerHack.sln` in Visual Studio 2022
2. If prompted to retarget, click **Retarget All**
3. Set dropdowns: **Debug** | **x64**
4. `Ctrl+Shift+B` → confirm `Build: 1 succeeded`

### Step 2: Create the MSBBypass project

1. **File → New → Project → Console App** (C++, Windows, Console)
2. Name: `MSBBypass`, Location: this repo's root folder
3. **Delete** the auto-generated `.cpp` file from Solution Explorer
4. Right-click project → **Add → Existing Item** → select from the `MSBBypass/` folder:
   - `MSBBypass.cpp`
   - `resource.h`
5. Right-click project → **Add → Existing Item** → change filter to **All Files (*.*)** → select:
   - `Resource.rc`
6. Set dropdowns: **Debug** | **x64**

### Step 3: Copy the DLL payload

```powershell
Copy-Item "x64\Debug\TaskManagerHack.dll" "MSBBypass\payload.dll" -Force
```

### Step 4: Build MSBBypass

1. `Ctrl+Shift+B` → confirm `Build: 1 succeeded`
2. Output is in `x64\Debug\`

## Usage

### MSB Bypass Test

1. **Disable antivirus** (Windows Defender real-time + McAfee if present)
2. Make sure **RemotePC** is installed and running
3. Run `dist/MSBBypass.exe` **as Administrator** (right-click → Run as administrator)
4. **Start MSB** (Mettl Secure Browser)
5. Enter the exam — MSB should not detect RemotePC
6. When done: press `Ctrl+C` in the tool, close MSB, re-enable antivirus

Expected output:
```
========================================
  MSB Security Test Tool
  For authorized security testing only
========================================

[1/3] Extracting payload... OK
[2/3] Hooks configured:
      - NtQuerySystemInformation (process hiding)
      - GetSystemMetrics (remote session spoofing)
      - Hiding: all *RemotePC* and *RPC* processes

[3/3] Watching for target processes...

  Start Mettl Secure Browser now.
  Press Ctrl+C when done testing.

  [+] SafeExamBrowser.exe (PID 1234) - hooked
  [+] WmiPrvSE.exe (PID 5678) - hooked
  [+] SafeExamBrowser.Client.exe (PID 9012) - hooked
```


## Project Structure

```
├── dist/
│   └── MSBBypass.exe         # Pre-built tool — just run this as admin
│
├── TaskManagerHack/
│   ├── dllmain.cpp          # The hook DLL (inline hooks on NtQuerySystemInformation + GetSystemMetrics)
│   ├── framework.h          # Windows headers
│   ├── pch.h / pch.cpp      # Precompiled headers
│   ├── TaskManagerHack.vcxproj
│   └── UniversalInjector.cpp # Standalone injector (alternative to MSBBypass)
│
├── MSBBypass/
│   ├── MSBBypass.cpp         # One-click tool (embeds DLL, watch mode)
│   ├── resource.h            # Resource ID definitions
│   └── Resource.rc           # Resource script (embeds payload.dll)
│
├── TaskManagerHack.sln       # Visual Studio solution (DLL project)
├── build.bat                 # Command-line build script
├── .gitignore
└── README.md                 # This file
```

## Recommended Fixes for MSB

### P0 — Critical (Must Fix)

1. **Detect inline hooks**: Compare ntdll.dll's in-memory bytes against the on-disk copy. If they differ, the code section has been tampered with. This single check defeats the entire tool.

```csharp
// 10 lines that would defeat this entire tool:
var diskBytes = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
var memBytes = ReadFromProcessMemory(ntdllBase, codeSection.Size);
if (!diskBytes.SequenceEqual(memBytes))
    AbortExam("System integrity violation detected");
```

2. **Move process scanning to the Windows Service**: `SafeExamBrowser.Service.exe` runs as SYSTEM in a separate process. Scanning from there makes injection much harder.

### P1 — High

4. **Detect DLL injection**: Check for unexpected modules loaded in MSB processes.
5. **Use ETW for process monitoring**: Kernel-level notifications that can't be hooked from user mode.
6. **Use behavior-based detection**: Don't rely on process names (attacker-controlled). Detect remote access behavior: screen capture APIs, keyboard hooks, network tunneling.
7. **Check digital signatures**: Block all processes signed by known remote access vendors (IDrive Inc, TeamViewer, AnyDesk, etc.).

## Technical Details

### Inline Hooking Technique

We use a 14-byte absolute jump patch on x64:

```
FF 25 00 00 00 00    jmp qword ptr [rip+0]
XX XX XX XX XX XX XX XX    (8-byte absolute address of hook function)
```

This overwrites the first 14 bytes of the target function. When anyone calls the function (via IAT, GetProcAddress, or direct call), they hit our jump and get redirected to our hook.

### Why IAT Hooking Didn't Work

MSB is a .NET application. .NET resolves function addresses via `GetProcAddress` at runtime, bypassing the Import Address Table entirely. Inline hooking patches the function itself, so it works regardless of how the function is called.

### Thread Safety

The hook uses a `CRITICAL_SECTION` lock with an unhook-call-rehook pattern:
1. Lock
2. Restore original bytes
3. Call the real function
4. Re-patch with jump
5. Unlock

## Disclaimer

This tool is for authorized internal security testing only. Unauthorized use against exam proctoring systems violates terms of service and potentially applicable laws. This was developed to identify and fix security weaknesses in MSB.

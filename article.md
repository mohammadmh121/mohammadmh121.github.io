# Beyond Process Creation: Reverse Engineering and Detecting Windows Process Reflection

Tracing ntdll!RtlCreateProcessReflection from x64 disassembly to Sysmon telemetry and Sigma rules.

# 1 - Introduction

In most SOC environments, monitoring process creation relies heavily on telemetry like Sysmon Event ID 1, which means an executable file is mapped from disk and an initial thread starts running. The Windows NT kernel natively supports process forking, though. This mechanism allows a process to call the undocumented API `ntdll!RtlCreateProcessReflection` and clone the virtual address space of a target process in memory using Copy-on-Write (CoW) page tables. Microsoft originally built this for Windows Error Reporting (WER). Attackers now abuse it to dump memory or run code stealthily, leaving a blind spot in traditional telemetry.

For my research, I want to show how this two-level architecture works in assembly and the kernel, covering `ZwMapViewOfSection`, the injected helper thread `RtlpProcessReflectionStartup`, and the dual return mechanism in `RtlCloneUserProcess`. I will also show how Sysmon Event ID 1 is affected by implicit PPID distortion due to how `PspInsertThread` behaves. From there, I'll break down the telemetry artifacts across Event IDs 1, 8, and 10, and build a Splunk query and Sigma rule to catch the technique.

# 2 - Structure of Standard Process Creation vs. Cloning Process

The standard user-mode path for creating a process is `CreateProcessW -> CreateProcessInternalW -> NtCreateUserProcess`. Windows maps the executable file from disk (`SEC_IMAGE`) and starts the initial thread. SOC Tier 1 analysts track this via Sysmon Event ID 1 or Windows Security Event ID 4688. Process cloning skips disk mapping altogether and duplicates the memory of a running process directly in the kernel.

# 3 - Two-Stage Architecture in ntdll.dll

![[0.png]]

A common misconception is that `RtlCreateProcessReflection` directly calls a kernel syscall to clone an external process. It does not. The underlying cloning function, `ntdll!RtlCloneUserProcess`, can only clone its own caller process (`NtCurrentProcess() == -1`) and cannot target a remote process directly. To get around this, Windows uses a two-stage cross-process architecture:

3.1 - Shared memory section allocation (initiator context):
`RtlCreateProcessReflection` receives the target process handle in `RCX`. First, it calls `ZwCreateSection` to create a shared memory block. Next, it calls `ZwMapViewOfSection` twice, passing `SectionHandle` in `RCX` and the target process handle in `RDX`:

* First call inside the initiator process (`RDX = -1`, meaning `NtCurrentProcess`).
* Second call inside the target process (`RDX = TargetProcessHandle`).

After mapping both views, the initiator writes the control structure (flags, event handles, and the optional `StartRoutine` address) into that shared memory.

3.2 - Remote coordinator thread injection (`RtlCreateUserThread`):
The initiator process loads the address of an internal, unexported API named `ntdll!RtlpProcessReflectionStartup` using a `lea` instruction. It then calls `RtlCreateUserThread` (via `RtlpCreateUserThreadEx`) on the target process handle, passing the address of the shared memory mapped in the target process space as the context parameter.

3.3 - Cloning within the target process (`RtlCloneUserProcess`):
Execution now jumps into the target process. The injected helper thread starts running at `RtlpProcessReflectionStartup`, reads the shared parameters, and calls `ntdll!RtlCloneUserProcess`. Inside this function, Windows invokes the `NtCreateUserProcess` syscall with the `PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT` (`0x00000100`) flag so the new process inherits the parent's address space without a disk-backed image section (`SectionHandle = NULL`).

3.4 - Dual return mechanism (`STATUS_PROCESS_CLONED` and `STATUS_SUCCESS`):
Similar to `fork` in Unix systems, `NtCreateUserProcess` returns twice into two different address spaces. The chain `RtlCloneUserProcess -> RtlpProcessReflectionStartup` separates them by checking `EAX` with `cmp eax, 0x129`:

* The First Step: inside `RtlCloneUserProcess`
  Once the syscall returns, `cmp eax, 0x129` checks which process is running. In the child clone (`EAX == 0x129`), internal `ntdll` locks and the child's PEB are reinitialized before returning `STATUS_PROCESS_CLONED` (`0x129`) to `RtlpProcessReflectionStartup`. The parent gets `STATUS_SUCCESS` (`0x0`).
* The Second Step: inside `RtlpProcessReflectionStartup`
  This function checks the return value of `RtlCloneUserProcess`:
  * In the target parent process (`EAX == 0x0`): The newly created clone handles are copied into the initiator process via `ZwDuplicateObject`.
  * In the new cloned process (`EAX == 0x129`): Control flow moves to the child. If a custom `StartRoutine` is provided, it runs. Otherwise, the cloned thread waits on an internal synchronization event by calling `ZwWaitForSingleObject` (putting the thread into a `Waiting` / `WrUserRequest` state, not `Suspended`) and exits with `STATUS_SUCCESS` (`0x0`).

# 4 - Bitmask Access Logic for OpenProcess

`RtlCreateProcessReflection` needs to query process metadata, map a memory section, start a remote thread, and duplicate handles across processes. That requires four specific access permissions on the target handle:

* `PROCESS_CREATE_THREAD (0x0002)`: Required by `RtlCreateUserThread` to execute the thread in `RtlpProcessReflectionStartup`.
* `PROCESS_VM_OPERATION (0x0008)`: Required by `ZwMapViewOfSection` to map shared parameters into the target process space.
* `PROCESS_DUP_HANDLE (0x0040)`: Required by `ZwDuplicateObject` to copy the cloned handles into the initiator process.
* `PROCESS_QUERY_INFORMATION (0x0400)`: Required by `ZwQueryInformationProcess` to check the base status and architecture (WoW64) of the target process.

I didn't need `PROCESS_VM_WRITE = 0x0020` because data transfer happens through `ZwMapViewOfSection` instead of `ZwWriteVirtualMemory`:

`DesiredAccess = 0x0002 | 0x0008 | 0x0040 | 0x0400 = 0x044A`

Using `ZwQueryInformationProcess` with the lighter `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` flag changes the mask to `0x104A`. Also, per Microsoft's process access-right documentation, Windows automatically grants `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` whenever `PROCESS_QUERY_INFORMATION (0x0400)` is granted, which expands a `0x044A` request into `0x144A`.

# 5 - Open ntdll.dll

![[1.png]]

First, `RtlCreateProcessReflection` checks the target process state via `ZwQueryInformationProcess` (`ProcessInformationClass = 0x1B`). It then calls `ZwAllocateVirtualMemory` on `NtCurrentProcess` (`RCX = -1`) to allocate a local `0x58`-byte (88 bytes) staging buffer (`var_A0`) for the reflection control parameters.

![[1.5.png]]

Instead of using `PROCESS_VM_WRITE`, the initiator creates a shared memory section via `ZwCreateSection` (`SEC_COMMIT = 0x8000000`, `PAGE_READWRITE = 0x04`) and saves the handle in `var_68`.

![[2.png]]

Next, it calls `ZwMapViewOfSection` with the section handle in `RCX` and the target process handle (`R14`) in `RDX`, mapping the shared view directly into the remote target's virtual address space (`var_70`).

![[3.png]]

Inside the target process, the injected worker thread calls `RtlCloneUserProcess`. That function executes the `NtCreateUserProcess` syscall with `PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT (0x100)` and checks `cmp eax, 0x129` to split execution between the parent and the clone.

# 6 - Lab

# 6.1 - Test Environment and Sysmon Config

I ran all tests on the following machine setup:

* **OS Build:** Windows 11 x64 `26300.9974` (`26H2`)
* **ntdll.dll Version:** `10.0.26100.9974 (WinBuild.160101.0800)`
* **Offsets in ntdll.dll:** `RtlCreateProcessReflection` = `+0x99330`, `RtlpProcessReflectionStartup` = `+0x998D0`
* **Tools:** Sysmon v15.15 (schema `4.90`), MSVC `cl.exe` (VS 2022), IDA Pro, x64dbg, System Informer

Sysmon configuration used to capture Event IDs 1, 8, and 10:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="ReflectionLab" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">ReflectionTelemetrySim.exe</Image>
        <Image condition="end with">notepad.exe</Image>
        <ParentImage condition="contains">ReflectionTelemetrySim.exe</ParentImage>
        <ParentImage condition="end with">notepad.exe</ParentImage>
      </ProcessCreate>
      <CreateRemoteThread onmatch="include">
        <SourceImage condition="contains">ReflectionTelemetrySim.exe</SourceImage>
        <TargetImage condition="end with">notepad.exe</TargetImage>
      </CreateRemoteThread>
      <ProcessAccess onmatch="include">
        <SourceImage condition="contains">ReflectionTelemetrySim.exe</SourceImage>
        <TargetImage condition="end with">notepad.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

# 6.2 - Code

Here is the C++ code (`ReflectionTelemetrySim.cpp`) I wrote to test the reflection call and inspect the logs:

```cpp
#if !defined(_WIN64)
#error "This code must be compiled as a 64-bit (x64) binary."
#endif

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifndef RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES
#define RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES 0x02
#endif

#ifndef RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE
#define RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE  0x08
#endif

typedef struct _RTL_PROCESS_REFLECTION_REFLECTION_INFORMATION {
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
} RTL_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTL_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI* fnRtlCreateProcessReflection)(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    PRTL_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation
);

static void CloseIfValid(HANDLE& h) {
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        h = NULL;
    }
}

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    HANDLE hTarget = NULL;
    RTL_PROCESS_REFLECTION_REFLECTION_INFORMATION reflInfo = { 0 };
    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION; // 0x044A
    ULONG flags = RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES | RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE; // 0x0A
    NTSTATUS status = -1;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 1;

    fnRtlCreateProcessReflection pRtlCreateProcessReflection = (fnRtlCreateProcessReflection)GetProcAddress(
        hNtdll, "RtlCreateProcessReflection"
    );
    if (!pRtlCreateProcessReflection) return 1;

    printf("[*] Initiator PID: %lu\n", GetCurrentProcessId());
    printf("[*] RtlCreateProcessReflection address: 0x%p\n", (void*)pRtlCreateProcessReflection);

    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Spawned target notepad.exe -> PID: %lu\n", pi.dwProcessId);
    Sleep(1000);

    hTarget = OpenProcess(desiredAccess, FALSE, pi.dwProcessId);
    if (!hTarget) {
        printf("[-] OpenProcess(0x044A) failed: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Opened target handle: 0x%p (DesiredAccess = 0x%04X)\n", hTarget, desiredAccess);

    status = pRtlCreateProcessReflection(hTarget, flags, NULL, NULL, NULL, &reflInfo);

    if (status == 0) {
        printf("[+] Reflection succeeded!\n");
        printf("    Cloned PID: %llu | Cloned TID: %llu\n",
            (unsigned long long)reflInfo.ReflectionClientId.UniqueProcess,
            (unsigned long long)reflInfo.ReflectionClientId.UniqueThread);
        printf("[*] Press Enter to terminate processes and clean up...\n");
        (void)getchar();
    } else {
        printf("[-] RtlCreateProcessReflection failed with NTSTATUS: 0x%08X\n", (unsigned int)status);
    }

cleanup:
    if (reflInfo.ReflectionProcessHandle) {
        TerminateProcess(reflInfo.ReflectionProcessHandle, 0);
    }
    if (pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
    }

    CloseIfValid(reflInfo.ReflectionThreadHandle);
    CloseIfValid(reflInfo.ReflectionProcessHandle);
    CloseIfValid(hTarget);
    CloseIfValid(pi.hThread);
    CloseIfValid(pi.hProcess);
    return 0;
}
```

A few notes on the code:

* `#if !defined(_WIN64)` forces a 64-bit build. Trying to reflect a 64-bit process from a 32-bit WoW64 process fails immediately in the kernel (`STATUS_INVALID_PARAMETER`) due to PEB and thread context layout differences.
* `RtlCreateProcessReflection` is resolved at runtime via `GetModuleHandleA("ntdll.dll")` and `GetProcAddress`, keeping it out of the static Import Address Table (IAT).
* I passed `0x044A` to `OpenProcess` instead of `PROCESS_ALL_ACCESS (0x1FFFFF)`.
* Passing `NULL` for `StartRoutine` and `StartContext` with `Flags = 0x0A` (`RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES | RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE`) clones the target without running shellcode. The cloned thread enters `ZwWaitForSingleObject` and stays in a `Wait:UserRequest` state until I press Enter to clean up.

# 6.3 - Compile the code

![[4.png]]

Compiling in the x64 Native Tools Command Prompt:

```text
C:\Lab>cl.exe /W4 /O2 /Zi ReflectionTelemetrySim.cpp
Microsoft (R) C/C++ Optimizing Compiler Version 19.41.34120 for x64
Copyright (C) Microsoft Corporation.  All rights reserved.

ReflectionTelemetrySim.cpp
Microsoft (R) Incremental Linker Version 14.41.34120.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:ReflectionTelemetrySim.exe
/debug
ReflectionTelemetrySim.obj
```

What this command does:

* `cl.exe` -> Microsoft compiler
* `/W4` -> Warning level 4
* `/O2` -> Maximum speed optimization
* `/Zi` -> Output debug symbols (`.pdb`) for debugging

# 6.4 - Dynamic Analysis in x64dbg

I loaded `ReflectionTelemetrySim.exe` into x64dbg to watch the registers and handles live.

Step 1: Setting the breakpoint on `ntdll!RtlCreateProcessReflection` in the command bar:

![[5.png]]

Step 2: Checking the registers
Hitting `F9` lets `ReflectionTelemetrySim.exe` (`PID: 13664`) resolve `RtlCreateProcessReflection` at `0x00007FFF57BE9330`, spawn `notepad.exe` (`PID: 20132`), and call `OpenProcess(0x044A)`. It gets back handle `0x388`.

![[6.png]]

`OpenProcess` succeeds and I immediately hit the breakpoint at `0x00007FFF57BE9330` (`RIP`). Here are the incoming arguments:

* `RCX` (Arg 1 - `ProcessHandle`): `0x0000000000000388`
* `RDX` (Arg 2 - `Flags`): `0x000000000000000A`

The prologue saves `RCX` into `R14` (`mov r14, rcx`) and moves the flags from `EDX` (`0x0A`) into `ESI` (`mov esi, edx`).

![[7.png]]

Step 3: Stepping over the call and checking System Informer
I pressed `F9` to let the call finish. Checking System Informer shows how the process tree changes:

Before calling `RtlCreateProcessReflection`:

```text
└── cmd.exe (PID: 8420)
    └── ReflectionTelemetrySim.exe (PID: 13664)
        └── Notepad.exe (PID: 20132)
```

After calling `RtlCreateProcessReflection`:

```text
└── cmd.exe (PID: 8420)
    └── ReflectionTelemetrySim.exe (PID: 13664)
        └── Notepad.exe (PID: 20132)
            └── Notepad.exe (PID: 11564, Main Thread TID: 16824 - State: Wait:UserRequest)
```

Looking at thread `TID 16824` inside the cloned `Notepad.exe` (`PID 11564`) in System Informer confirms its state is **`Wait:UserRequest`** (not `Suspended`). Since `StartRoutine` was `NULL`, `RtlpProcessReflectionStartup` simply called `ZwWaitForSingleObject` on the reflection event handle.

# 6.5 - Sysmon Logs

When I first pulled the Sysmon logs during my x64dbg session, I saw a 23-second gap between Event ID 10 (`11:24:37.510`) and Event ID 8 (`11:25:00.629`). At first, this 23-second gap broke my 5-second correlation rule before I realized my own x64dbg breakpoint was the culprit. Running the binary normally without a debugger paused on the entry point shrinks the entire sequence, from `OpenProcess` to thread injection and process cloning, down to just **5 milliseconds**:

* **Event 0: Initiator Process Creation (Sysmon Event ID 1 at `11:24:36.480`)**

```text
EventID: 1
UtcTime: 2026-11-13 11:24:36.480
ProcessGuid: {4b9f2a10-6c14-6734-8901-000000001200}
ProcessId: 13664
Image: C:\Lab\ReflectionTelemetrySim.exe
CommandLine: "C:\Lab\ReflectionTelemetrySim.exe"
ParentProcessGuid: {4b9f2a10-68f0-6734-1200-000000001200}
ParentProcessId: 8420
ParentImage: C:\Windows\System32\cmd.exe
```

* **Event 1: Initial Target Process Creation (Sysmon Event ID 1 at `11:24:36.492`)**

Normal process creation from my `CreateProcessA` call. `ReflectionTelemetrySim.exe` (`13664`) spawns `Notepad.exe` (`20132`).

```text
EventID: 1
UtcTime: 2026-11-13 11:24:36.492
ProcessGuid: {4b9f2a10-6c14-6734-8a01-000000001200}
ProcessId: 20132
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
CommandLine: "C:\Windows\System32\notepad.exe"
ParentProcessGuid: {4b9f2a10-6c14-6734-8901-000000001200}
ParentProcessId: 13664
ParentImage: C:\Lab\ReflectionTelemetrySim.exe
```

* **Event 2: Default Handle Creation by `CreateProcessA` (Sysmon Event ID 10 at `11:24:36.493`)**

Logged 1ms later. `CreateProcessA` automatically grants the parent a full-access handle (`0x1FFFFF`) to its child in `pi.hProcess`, which is why I excluded `0x1FFFFF` in my detection rules.

```text
EventID: 10
UtcTime: 2026-11-13 11:24:36.493
SourceProcessGUID: {4b9f2a10-6c14-6734-8901-000000001200}
SourceProcessId: 13664
SourceImage: C:\Lab\ReflectionTelemetrySim.exe
TargetProcessGUID: {4b9f2a10-6c14-6734-8a01-000000001200}
TargetProcessId: 20132
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x1FFFFF
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+167df4|C:\WINDOWS\System32\KERNELBASE.dll+6e8f5|C:\WINDOWS\System32\KERNEL32.DLL+44ec4|C:\Lab\ReflectionTelemetrySim.exe+7418
```

* **Event 3: Reflection Handle Acquisition (Sysmon Event ID 10 at `11:24:37.510`)**

My explicit `OpenProcess(0x044A)` call after `Sleep(1000)`. Windows appends `0x1000`, so Sysmon logs `0x144A`.

```text
EventID: 10
UtcTime: 2026-11-13 11:24:37.510
SourceProcessGUID: {4b9f2a10-6c14-6734-8901-000000001200}
SourceProcessId: 13664
SourceImage: C:\Lab\ReflectionTelemetrySim.exe
TargetProcessGUID: {4b9f2a10-6c14-6734-8a01-000000001200}
TargetProcessId: 20132
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
GrantedAccess: 0x144A
CallTrace: C:\WINDOWS\SYSTEM32\ntdll.dll+1668a4|C:\WINDOWS\System32\KERNELBASE.dll+1bf36|C:\Lab\ReflectionTelemetrySim.exe+7468
```

* **Event 4: Coordinator Thread Injection (Sysmon Event ID 8 at `11:24:37.512`)**

```text
EventID: 8
UtcTime: 2026-11-13 11:24:37.512
SourceProcessGuid: {4b9f2a10-6c14-6734-8901-000000001200}
SourceProcessId: 13664
SourceImage: C:\Lab\ReflectionTelemetrySim.exe
TargetProcessGuid: {4b9f2a10-6c14-6734-8a01-000000001200}
TargetProcessId: 20132
TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
NewThreadId: 30656
StartAddress: 0x00007FFF57BE98D0
StartModule: C:\WINDOWS\SYSTEM32\ntdll.dll
StartFunction: -
```

2ms after `OpenProcess`, `RtlCreateProcessReflection` injects the worker thread into `Notepad.exe` (`PID 20132`). `StartAddress` (`0x00007FFF57BE98D0`) points to `ntdll!RtlpProcessReflectionStartup`, located `0x5A0` bytes after `RtlCreateProcessReflection`. Because `RtlpProcessReflectionStartup` is missing from the `ntdll.dll` Export Address Table (EAT), Sysmon logs `StartFunction` as `-`.

`StartFunction: -` in `ntdll.dll` is not unique to Process Reflection on its own. Sysmon infers `StartModule` and `StartFunction` from the export table, so any thread starting at an unexported internal `ntdll.dll` address (like `TppWorkerThread` or debugger threads) also produces `-`. That's why I treated this as a behavioral indicator and correlated it with Event ID 10 and the process context.

* **Event 5: Cloned Process Creation and Implicit PPID Distortion (Sysmon Event ID 1 at `11:24:37.515`)**

```text
EventID: 1
UtcTime: 2026-11-13 11:24:37.515
ProcessGuid: {4b9f2a10-6c2c-6734-8b01-000000001200}
ProcessId: 11564
Image: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
CommandLine: "C:\Windows\System32\notepad.exe"
ParentProcessGuid: {4b9f2a10-6c14-6734-8a01-000000001200}
ParentProcessId: 20132
ParentImage: C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

3ms after the remote thread starts in `PID 20132`, it calls `RtlCloneUserProcess -> NtCreateUserProcess`. When the kernel runs `PspInsertThread` to fire creation callbacks, the executing thread belongs to `Notepad.exe` (`PID 20132`), not `ReflectionTelemetrySim.exe` (`PID 13664`). Event ID 1 therefore logs `Notepad.exe` (`PID 20132`) spawning another `Notepad.exe` (`PID 11564`), leaving `ReflectionTelemetrySim.exe` completely out of Event ID 1.

This implicit PPID change is also different from the MITRE ATT&CK Parent PID Spoofing technique (`T1134.004`). In `T1134.004`, an attacker explicitly passes `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to fake the parent handle. Here, no attribute is spoofed. The parent PID changes simply because `NtCreateUserProcess` runs from inside the remote thread in `PID 20132`. For that reason, I mapped the detection below only to `T1055` (Process Injection) and not `T1134.004` or `T1003.001`.

# 7 - Detection (Splunk and Sigma)

To catch this without getting flooded by false positives, I correlated Event ID 10 (checking for the `0x004A` reflection bits + query bit `0x0400` or `0x1000`) with Event ID 8 (`StartModule` in `ntdll.dll` and empty/`-` `StartFunction`) between the same source and target processes within 5 seconds.

# 7.1 - Splunk SPL Query

Look closely at the raw logs in Section 6.5: Event ID 10 uses uppercase `SourceProcessGUID` / `TargetProcessGUID`, while Event ID 8 uses `SourceProcessGuid` / `TargetProcessGuid`. Depending on your Splunk add-on, the event ID field is also named either `EventID` or `EventCode`. The query below normalizes those fields first with `coalesce` and then runs a bitwise check (`bit_and`) on `GrantedAccess`:

```spl
index=win_sysmon (EventCode IN (8, 10) OR EventID IN (8, 10))
| eval NormEventID = coalesce(EventID, EventCode)
| eval NormSourceGuid = lower(coalesce(SourceProcessGuid, SourceProcessGUID))
| eval NormTargetGuid = lower(coalesce(TargetProcessGuid, TargetProcessGUID))
| eval AccessInt = tonumber(replace(GrantedAccess, "^0x", ""), 16)
| eval HasCoreReflectionBits = if(NormEventID=10 AND AccessInt!=2097151 AND bit_and(AccessInt, 74) == 74 AND (bit_and(AccessInt, 1024) == 1024 OR bit_and(AccessInt, 4096) == 4096), 1, 0)
| eval IsUnexportedNtdllThread = if(NormEventID=8 AND match(StartModule, "(?i)\\\\ntdll\.dll$") AND (isnull(StartFunction) OR StartFunction=="-" OR StartFunction==""), 1, 0)
| where HasCoreReflectionBits=1 OR IsUnexportedNtdllThread=1
| stats earliest(_time) as FirstSeen, latest(_time) as LastSeen,
        dc(NormEventID) as UniqueEvents,
        values(NormEventID) as EventIDs,
        values(GrantedAccess) as GrantedAccessMasks,
        values(StartAddress) as ThreadStartAddresses,
        values(SourceImage) as InitiatorImage,
        values(TargetImage) as ReflectedTargetImage
        by NormSourceGuid, NormTargetGuid, host
| eval TimeDelta = LastSeen - FirstSeen
| where UniqueEvents == 2 AND TimeDelta >= 0 AND TimeDelta <= 5
| search NOT InitiatorImage IN ("C:\\Windows\\System32\\WerFault.exe", "C:\\Windows\\SysWOW64\\WerFault.exe", "C:\\Windows\\System32\\WerFaultSecure.exe")
| table FirstSeen, host, InitiatorImage, ReflectedTargetImage, GrantedAccessMasks, ThreadStartAddresses, TimeDelta
```

# 7.2 - Sigma Rule (Known Access Mask Variants)

Standard Sigma has no bitwise AND operator for hex strings, so `GrantedAccess|endswith` only matches known access mask variants (and can miss cases if extra access bits like `PROCESS_TERMINATE 0x0001` are added). Here are the suffix variants included in the rule:

* `04A`, `44A` (`0x044A` / `0x104A` / `0x144A`)
* `45A` (`0x044A | PROCESS_VM_READ 0x0010 = 0x045A` / `0x145A`)
* `46A` (`0x044A | PROCESS_VM_WRITE 0x0020 = 0x046A` / `0x146A`)
* `47A` (`0x044A | 0x0010 | 0x0020 = 0x047A` / `0x147A`)
* `4CA` (`0x044A | PROCESS_CREATE_PROCESS 0x0080 = 0x04CA` / `0x14CA`)
* `54A` (`0x044A | PROCESS_SET_QUOTA 0x0100 = 0x054A` / `0x154A`)
* `C4A` (`0x044A | PROCESS_SUSPEND_RESUME 0x0800 = 0x0C4A` / `0x1C4A`)

I only excluded `WerFault.exe` and `WerFaultSecure.exe` in the filter. Leaving out `svchost.exe`, `taskmgr.exe`, and `procdump.exe` ensures analysts don't miss attackers injecting into `svchost.exe` or using `procdump.exe -r` to dump processes via reflection.

```yaml
title: Correlated Process Reflection Chain via RtlCreateProcessReflection
id: 1598fb01-41ad-46ca-9c57-7592c1cc9408
status: experimental
description: >
    Correlates known handle access mask variants for ntdll!RtlCreateProcessReflection
    (Sysmon Event ID 10) followed by an unexported ntdll.dll remote thread
    (Sysmon Event ID 8) between the same source and target processes.
author: Mohammad Haghighat
date: 2026-11-13
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
correlation:
    type: temporal_ordered
    rules:
        - reflection_handle_access
        - reflection_remote_thread
    group-by:
        - SourceProcessGuid
        - TargetProcessGuid
    timespan: 5s
falsepositives:
    - Windows Error Reporting (WerFault.exe / WerFaultSecure.exe)
    - Diagnostic tools calling PssCaptureSnapshot (Taskmgr.exe, SystemInformer.exe, ProcDump -r)
level: high
---
name: reflection_handle_access
id: 9f3c8d21-4a7b-4e19-8c2d-5e6f7a8b9c0d
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection_access:
        EventID: 10
        GrantedAccess|endswith:
            - '04A'
            - '44A'
            - '45A'
            - '46A'
            - '47A'
            - '4CA'
            - '54A'
            - 'C4A'
    filter_wer:
        SourceImage:
            - 'C:\Windows\System32\WerFault.exe'
            - 'C:\Windows\SysWOW64\WerFault.exe'
            - 'C:\Windows\System32\WerFaultSecure.exe'
    condition: selection_access and not filter_wer
---
name: reflection_remote_thread
id: 7a1d4e62-3b9c-4d81-a5e0-1c2b3d4e5f6a
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection_thread_module:
        EventID: 8
        StartModule|endswith: '\ntdll.dll'
    selection_thread_func:
        - StartFunction:
              - '-'
              - ''
              - 'RtlpProcessReflectionStartup'
        - StartFunction: null
    filter_wer:
        SourceImage:
            - 'C:\Windows\System32\WerFault.exe'
            - 'C:\Windows\SysWOW64\WerFault.exe'
            - 'C:\Windows\System32\WerFaultSecure.exe'
    condition: selection_thread_module and selection_thread_func and not filter_wer
```

Testing the rule with `sigma-cli`:

I tested the YAML file using `sigma-cli v1.1.0` (`pySigma v0.11.15`, `pySigma-backend-splunk v1.1.1`):

1. Running `sigma check` passes syntax and schema validation with zero issues:

```text
$ sigma check reflection_correlation.yml
Checking Sigma rules  [####################################]  100%
0 issue(s) found in 1 rule(s).
```

2. Converting to Splunk (`sigma convert -t splunk --without-pipeline reflection_correlation.yml`) generates a `join` subsearch across the two rules, but there are two practical limitations with the auto-generated output:
   * First, backend support for `temporal_ordered` in `pySigma` does not enforce strict millisecond ordering (`Event 10` before `Event 8`) in the generated Splunk `stats`/`join` query out of the box (currently, full `temporal_ordered` state-machine conversion is mainly supported in the `sqlite` backend).
   * Second, the auto-generated query groups directly by `SourceProcessGuid` and `TargetProcessGuid`, which fails to match raw Sysmon Event ID 10 logs where those fields are capitalized as `SourceProcessGUID` and `TargetProcessGUID`.

Output of `sigma convert` for the base rules:

```text
EventID=10 GrantedAccess IN ("*04A", "*44A", "*45A", "*46A", "*47A", "*4CA", "*54A", "*C4A") NOT SourceImage IN ("C:\\Windows\\System32\\WerFault.exe", "C:\\Windows\\SysWOW64\\WerFault.exe", "C:\\Windows\\System32\\WerFaultSecure.exe")
| join SourceProcessGuid, TargetProcessGuid [
    search EventID=8 StartModule="*\\ntdll.dll" (StartFunction IN ("-", "", "RtlpProcessReflectionStartup") OR NOT StartFunction="*") NOT SourceImage IN ("C:\\Windows\\System32\\WerFault.exe", "C:\\Windows\\SysWOW64\\WerFault.exe", "C:\\Windows\\System32\\WerFaultSecure.exe")
]
```

Because of those two backend limitations (`join` subsearch limits/ordering and `GUID` field casing), you should use the normalized `stats` + `bit_and` Splunk query in Section 7.1 for actual production hunting.
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
} RTL_PROCESS_REFLECTION_REFLECTION_INFORMATION, * PRTL_PROCESS_REFLECTION_REFLECTION_INFORMATION;
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
    }
    else {
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
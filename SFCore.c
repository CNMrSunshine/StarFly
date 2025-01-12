#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"

DWORD_PTR GetSystemTimeAddr = 0;
DWORD_PTR NtQuerySystemTimeAddr = 0;
DWORD_PTR NtQuerySystemInformationAddr = 0;
DWORD_PTR o_para1 = 0;
DWORD_PTR o_para2 = 0;
DWORD_PTR o_para3 = 0;
DWORD_PTR o_para4 = 0;
DWORD o_funchash = 0;
PVOID handler = NULL;

/*========================================
以下代码属于GitHub项目 SysWhisper3 的部分引用
https://github.com/klezVirus/SysWhispers3
========================================*/
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

    //此处获取GetSystemTime的断点地址的方式 以及断点设置的位置 需要进行修改

    NtQuerySystemTimeAddr = (DWORD_PTR)SW3_GetSyscallAddress(0x09A0F97AF);

    NtQuerySystemInformationAddr = (DWORD_PTR)SW3_GetSyscallAddress(0x09E349EA7);
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
            pExceptInfo->ContextRecord->Rcx = (ULONG_PTR)o_para1;
            pExceptInfo->ContextRecord->Rdx = (ULONG_PTR)o_para2;
            pExceptInfo->ContextRecord->R8 = (ULONG_PTR)o_para3;
            pExceptInfo->ContextRecord->R9 = (ULONG_PTR)o_para4;
            pExceptInfo->ContextRecord->R10 = (ULONG_PTR)o_para1;
            DWORD syscall_number = SW3_GetSyscallNumber(o_funchash);
            pExceptInfo->ContextRecord->Rax = syscall_number;
            DWORD_PTR syscall_addr = (DWORD_PTR)SW3_GetSyscallAddress(o_funchash);
            pExceptInfo->ContextRecord->Rip = syscall_addr;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void SetBreakPoint() {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = GetSystemTimeAddr;
        ctx.Dr1 = NtQuerySystemTimeAddr;
        ctx.Dr2 = NtQuerySystemInformationAddr;
        ctx.Dr7 = 0x0000000f;
        //ctx.Dr7 = 0x00000015;
        if (SetThreadContext(hThread, &ctx)) {
        }
        else {
            printf("[ERROR] Failed to set thread context.\n");
            return -1;
        }
    }
    else {
        printf("[ERROR] Failed to get thread context.\n");
        return -1;
    }
}

void StarFlyCoreStart() {
    GetBreakpointAddr();
    SetBreakPoint();
    handler = AddVectoredExceptionHandler(1, ExceptionHandler);
}

void StarFlyCoreExit() {
    RemoveVectoredExceptionHandler(handler);
}

NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass; // 通过全局变量传四个参数
    o_para2 = (ULONG_PTR)SystemInformation;
    o_para3 = (ULONG_PTR)SystemInformationLength;
    o_para4 = (ULONG_PTR)ReturnLength;
    o_funchash = 0x09E349EA7;
    /*
    SysWhisper3的FunctionHash计算函数没搞明白怎么用
    未来会换成用SysWhisperSeed + FunctionName动态计算FunctionHash
    */
    GetSystemTime(1);
    return 0;
}
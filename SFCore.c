#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"
#include <locale.h>

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
DWORD o_mode = 0;
PVOID handler = NULL;
DWORD o_lang = 0;
DWORD o_rip = 0;
NTSTATUS status = 0;
HANDLE hConsole = 0;
extern void LocalPrivilegeErrorHandler();
extern void OpenProcessErrorHandler();
extern void TILocalPrivilegeErrorHandler();
extern void OpenCMDErrorHandler();
extern void OpenCMD2ErrorHandler();

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
    // DebugBreakpointAddr = (DWORD_PTR)SW3_GetSyscallAddress(0x004027081); 调试用
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
    } else if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (o_mode == 1 || o_mode == 2) {
            LocalPrivilegeErrorHandler();
        }
        else if (o_mode == 3) {
            OpenProcessErrorHandler();
        }
        else if (o_mode == 4 || o_mode == 5) {
            TILocalPrivilegeErrorHandler();
        }
        else if (o_mode == 6) {
            exit(0);
        }
        else if (o_mode == 7 || o_mode == 8 || o_mode == 9) {
            OpenCMD2ErrorHandler();
        }
        else if (o_mode == 10) {
            OpenCMDErrorHandler();
        }
        else {
            SFPrintError("An Unexpected Fatal Error Occurred.", "发生了未预期的致命错误");
            SFPrintStatus("Rebooting...", "正在重启...");
            o_restart = 1;
            main();
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
        // ctx.Dr2 = DebugBreakpointAddr;
        ctx.Dr7 = 0x0000000f; //启用 Dr0 Dr1
        // ctx.Dr7 = 0x00000015; 调试用
        if (SetThreadContext(hThread, &ctx)) {
        }
        else {
            SFPrintError("Failed to set thread context.", "设置线程上下文失败");
            return;
        }
    }
    else {
        SFPrintError("Failed to get thread context.", "获取线程上下文失败");
        return;
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

void SFPrintStatus(const char* en, const char* cn) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[*] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (o_lang % 2 == 0) {
        printf("%s\n", en);
    }
    else {
        printf("%s\n", cn);
    }
}

void SFPrintSuccess(const char* en, const char* cn) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("[+] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (o_lang % 2 == 0) {
        printf("%s\n", en);
    }
    else {
        printf("%s\n", cn);
    }
}

void SFPrintError(const char* en, const char* cn) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("[-] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (o_lang % 2 == 0) {
        printf("%s\n", en);
    }
    else {
        printf("%s\n", cn);
    }
}

NTSTATUS SFNtAccessCheck(PSECURITY_DESCRIPTOR pSecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiaredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus) {
    o_para1 = (ULONG_PTR)pSecurityDescriptor;
    o_para2 = (ULONG_PTR)ClientToken;
    o_para3 = (ULONG_PTR)DesiaredAccess;
    o_para4 = (ULONG_PTR)GenericMapping;
    o_para5 = (ULONG_PTR)PrivilegeSet;
    o_para6 = (ULONG_PTR)PrivilegeSetLength;
    o_para7 = (ULONG_PTR)GrantedAccess;
    o_para8 = (ULONG_PTR)AccessStatus;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x0429E3D77;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWorkerFactoryWorkerReady(HANDLE WorkerFactoryHandle) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
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
    o_funchash = 0x093BB77D7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAcceptConnectPort(PHANDLE ServerPortHandle, ULONG AlternativeReceivePortHandle, PPORT_MESSAGE ConnectionReply, BOOLEAN AcceptConnection, PPORT_SECTION_WRITE ServerSharedMemory, PPORT_SECTION_READ ClientSharedMemory) {
    o_para1 = (ULONG_PTR)ServerPortHandle;
    o_para2 = (ULONG_PTR)AlternativeReceivePortHandle;
    o_para3 = (ULONG_PTR)ConnectionReply;
    o_para4 = (ULONG_PTR)AcceptConnection;
    o_para5 = (ULONG_PTR)ServerSharedMemory;
    o_para6 = (ULONG_PTR)ClientSharedMemory;
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
    o_para_num = 6;
    o_funchash = 0x024B23D18;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapUserPhysicalPagesScatter(PVOID VirtualAddresses, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)VirtualAddresses;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
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
    o_para_num = 3;
    o_funchash = 0x001C8772D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    o_para1 = (ULONG_PTR)ObjectHandle;
    o_para2 = (ULONG_PTR)Alertable;
    o_para3 = (ULONG_PTR)TimeOut;
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
    o_para_num = 3;
    o_funchash = 0x0E05EC0E2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCallbackReturn(PVOID OutputBuffer, ULONG OutputLength, NTSTATUS Status) {
    o_para1 = (ULONG_PTR)OutputBuffer;
    o_para2 = (ULONG_PTR)OutputLength;
    o_para3 = (ULONG_PTR)Status;
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
    o_para_num = 3;
    o_funchash = 0x0048EE991;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)ByteOffset;
    o_para9 = (ULONG_PTR)Key;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x02E7FE12F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)IoControlCode;
    o_para7 = (ULONG_PTR)InputBuffer;
    o_para8 = (ULONG_PTR)InputBufferLength;
    o_para9 = (ULONG_PTR)OutputBuffer;
    o_para10 = (ULONG_PTR)OutputBufferLength;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x0781942BE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)ByteOffset;
    o_para9 = (ULONG_PTR)Key;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0A4B2DEA5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRemoveIoCompletion(HANDLE IoCompletionHandle, PULONG KeyContext, PULONG ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)KeyContext;
    o_para3 = (ULONG_PTR)ApcContext;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_para5 = (ULONG_PTR)Timeout;
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
    o_para_num = 5;
    o_funchash = 0x0029A000B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)ReleaseCount;
    o_para3 = (ULONG_PTR)PreviousCount;
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
    o_para_num = 3;
    o_funchash = 0x075275B64;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyWaitReceivePort(HANDLE PortHandle, PVOID PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortContext;
    o_para3 = (ULONG_PTR)ReplyMessage;
    o_para4 = (ULONG_PTR)ReceiveMessage;
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
    o_funchash = 0x06CF0757C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ReplyMessage;
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
    o_funchash = 0x0D171E0DD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ThreadInformationClass;
    o_para3 = (ULONG_PTR)ThreadInformation;
    o_para4 = (ULONG_PTR)ThreadInformationLength;
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
    o_funchash = 0x0D48834D7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
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
    o_funchash = 0x036AD190E;
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

NTSTATUS SFNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)ObjectInformationClass;
    o_para3 = (ULONG_PTR)ObjectInformation;
    o_para4 = (ULONG_PTR)ObjectInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x00A553EF4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)FileInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)FileInformationClass;
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
    o_para_num = 5;
    o_funchash = 0x02218B021;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0BDB8EA66;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)Index;
    o_para3 = (ULONG_PTR)KeyValueInformationClass;
    o_para4 = (ULONG_PTR)KeyValueInformation;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ResultLength;
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
    o_para_num = 6;
    o_funchash = 0x0281F4D85;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFindAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
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
    o_para_num = 3;
    o_funchash = 0x038A00921;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDefaultLocale(BOOLEAN UserProfile, PLCID DefaultLocaleId) {
    o_para1 = (ULONG_PTR)UserProfile;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
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
    o_funchash = 0x0C32AF1FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)KeyInformationClass;
    o_para3 = (ULONG_PTR)KeyInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)ResultLength;
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
    o_para_num = 5;
    o_funchash = 0x09F0BB2AD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)ValueName;
    o_para3 = (ULONG_PTR)KeyValueInformationClass;
    o_para4 = (ULONG_PTR)KeyValueInformation;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ResultLength;
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
    o_para_num = 6;
    o_funchash = 0x0261BD761;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)ZeroBits;
    o_para4 = (ULONG_PTR)RegionSize;
    o_para5 = (ULONG_PTR)AllocationType;
    o_para6 = (ULONG_PTR)Protect;
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
    o_para_num = 6;
    o_funchash = 0x00114EF73;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)ProcessInformationClass;
    o_para3 = (ULONG_PTR)ProcessInformation;
    o_para4 = (ULONG_PTR)ProcessInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0DD27CE88;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForMultipleObjects32(ULONG ObjectCount, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)ObjectCount;
    o_para2 = (ULONG_PTR)Handles;
    o_para3 = (ULONG_PTR)WaitType;
    o_para4 = (ULONG_PTR)Alertable;
    o_para5 = (ULONG_PTR)Timeout;
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
    o_para_num = 5;
    o_funchash = 0x0B49D2D72;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWriteFileGather(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)SegmentArray;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)ByteOffset;
    o_para9 = (ULONG_PTR)Key;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0039C6F07;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TitleIndex;
    o_para5 = (ULONG_PTR)Class;
    o_para6 = (ULONG_PTR)CreateOptions;
    o_para7 = (ULONG_PTR)Disposition;
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
    o_para_num = 7;
    o_funchash = 0x01D1D3CA6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)FreeType;
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
    o_funchash = 0x00596110B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
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
    o_funchash = 0x0E0BED113;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseMutant(HANDLE MutantHandle, PULONG PreviousCount) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)PreviousCount;
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
    o_funchash = 0x038BE3338;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)TokenInformationClass;
    o_para3 = (ULONG_PTR)TokenInformation;
    o_para4 = (ULONG_PTR)TokenInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x004027081;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)RequestMessage;
    o_para3 = (ULONG_PTR)ReplyMessage;
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
    o_para_num = 3;
    o_funchash = 0x062BC6320;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)MemoryInformationClass;
    o_para4 = (ULONG_PTR)MemoryInformation;
    o_para5 = (ULONG_PTR)MemoryInformationLength;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x003910903;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)OpenAsSelf;
    o_para4 = (ULONG_PTR)TokenHandle;
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
    o_funchash = 0x001D87B3C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ThreadInformationClass;
    o_para3 = (ULONG_PTR)ThreadInformation;
    o_para4 = (ULONG_PTR)ThreadInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x022163CA7;
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

NTSTATUS SFNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)FileInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)FileInformationClass;
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
    o_para_num = 5;
    o_funchash = 0x015852515;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)ProcessHandle;
    o_para3 = (ULONG_PTR)BaseAddress;
    o_para4 = (ULONG_PTR)ZeroBits;
    o_para5 = (ULONG_PTR)CommitSize;
    o_para6 = (ULONG_PTR)SectionOffset;
    o_para7 = (ULONG_PTR)ViewSize;
    o_para8 = (ULONG_PTR)InheritDisposition;
    o_para9 = (ULONG_PTR)AllocationType;
    o_para10 = (ULONG_PTR)Win32Protect;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x0E0C7A011;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus, PBOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ObjectTypeName;
    o_para4 = (ULONG_PTR)ObjectName;
    o_para5 = (ULONG_PTR)SecurityDescriptor;
    o_para6 = (ULONG_PTR)DesiredAccess;
    o_para7 = (ULONG_PTR)GenericMapping;
    o_para8 = (ULONG_PTR)ObjectCreation;
    o_para9 = (ULONG_PTR)GrantedAccess;
    o_para10 = (ULONG_PTR)AccessStatus;
    o_para11 = (ULONG_PTR)GenerateOnClose;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0D2AC33F1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
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
    o_funchash = 0x0B6A3FC07;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyWaitReceivePortEx(HANDLE PortHandle, PULONG PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortContext;
    o_para3 = (ULONG_PTR)ReplyMessage;
    o_para4 = (ULONG_PTR)ReceiveMessage;
    o_para5 = (ULONG_PTR)Timeout;
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
    o_para_num = 5;
    o_funchash = 0x0138DCFC9;
    GetSystemTime(1);
    return 0;
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

NTSTATUS SFNtSetEventBoostPriority(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
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
    o_funchash = 0x054C35040;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadFileScatter(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)SegmentArray;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)ByteOffset;
    o_para9 = (ULONG_PTR)Key;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x025AE073F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)OpenAsSelf;
    o_para4 = (ULONG_PTR)HandleAttributes;
    o_para5 = (ULONG_PTR)TokenHandle;
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
    o_para_num = 5;
    o_funchash = 0x082E7B459;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)HandleAttributes;
    o_para4 = (ULONG_PTR)TokenHandle;
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
    o_funchash = 0x030937E54;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency) {
    o_para1 = (ULONG_PTR)PerformanceCounter;
    o_para2 = (ULONG_PTR)PerformanceFrequency;
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
    o_funchash = 0x037EA4CE7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)Index;
    o_para3 = (ULONG_PTR)KeyInformationClass;
    o_para4 = (ULONG_PTR)KeyInformation;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ResultLength;
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
    o_para_num = 6;
    o_funchash = 0x086BF8D20;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_para5 = (ULONG_PTR)ShareAccess;
    o_para6 = (ULONG_PTR)OpenOptions;
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
    o_para_num = 6;
    o_funchash = 0x0B265E2D2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    o_para1 = (ULONG_PTR)Alertable;
    o_para2 = (ULONG_PTR)DelayInterval;
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
    o_funchash = 0x0306872B5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)FileInformation;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)FileInformationClass;
    o_para9 = (ULONG_PTR)ReturnSingleEntry;
    o_para10 = (ULONG_PTR)FileName;
    o_para11 = (ULONG_PTR)RestartScan;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0B2198292;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass;
    o_para2 = (ULONG_PTR)SystemInformation;
    o_para3 = (ULONG_PTR)SystemInformationLength;
    o_para4 = (ULONG_PTR)ReturnLength;
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
    o_funchash = 0x09E349EA7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x009A5E9F3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)TimerInformationClass;
    o_para3 = (ULONG_PTR)TimerInformation;
    o_para4 = (ULONG_PTR)TimerInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0B11BE1B8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)FsControlCode;
    o_para7 = (ULONG_PTR)InputBuffer;
    o_para8 = (ULONG_PTR)InputBufferLength;
    o_para9 = (ULONG_PTR)OutputBuffer;
    o_para10 = (ULONG_PTR)OutputBufferLength;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x069D3A98B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)NumberOfBytesToWrite;
    o_para5 = (ULONG_PTR)NumberOfBytesWritten;
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
    o_para_num = 5;
    o_funchash = 0x007901F0F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)GenerateOnClose;
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
    o_para_num = 3;
    o_funchash = 0x036D53440;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    o_para1 = (ULONG_PTR)SourceProcessHandle;
    o_para2 = (ULONG_PTR)SourceHandle;
    o_para3 = (ULONG_PTR)TargetProcessHandle;
    o_para4 = (ULONG_PTR)TargetHandle;
    o_para5 = (ULONG_PTR)DesiredAccess;
    o_para6 = (ULONG_PTR)HandleAttributes;
    o_para7 = (ULONG_PTR)Options;
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
    o_para_num = 7;
    o_funchash = 0x0ECBFE423;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = (ULONG_PTR)FileInformation;
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
    o_funchash = 0x022B80BFE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearEvent(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
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
    o_funchash = 0x0E004F996;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)BufferSize;
    o_para5 = (ULONG_PTR)NumberOfBytesRead;
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
    o_para_num = 5;
    o_funchash = 0x01D950B1B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0588D2544;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)DisableAllPrivileges;
    o_para3 = (ULONG_PTR)NewState;
    o_para4 = (ULONG_PTR)BufferLength;
    o_para5 = (ULONG_PTR)PreviousState;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x09FAA8D2A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
    o_para1 = (ULONG_PTR)ExistingTokenHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)EffectiveOnly;
    o_para5 = (ULONG_PTR)TokenType;
    o_para6 = (ULONG_PTR)NewTokenHandle;
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
    o_para_num = 6;
    o_funchash = 0x073D14748;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert) {
    o_para1 = (ULONG_PTR)ContextRecord;
    o_para2 = (ULONG_PTR)TestAlert;
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
    o_funchash = 0x00880F3E0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDefaultUILanguage(PLANGID DefaultUILanguageId) {
    o_para1 = (ULONG_PTR)DefaultUILanguageId;
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
    o_funchash = 0x0C90B3652;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueueApcThread(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ApcRoutine;
    o_para3 = (ULONG_PTR)ApcArgument1;
    o_para4 = (ULONG_PTR)ApcArgument2;
    o_para5 = (ULONG_PTR)ApcArgument3;
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
    o_para_num = 5;
    o_funchash = 0x036932C35;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtYieldExecution() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x04AEC360F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
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
    o_para_num = 3;
    o_funchash = 0x0F260F7F2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)EventType;
    o_para5 = (ULONG_PTR)InitialState;
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
    o_para_num = 5;
    o_funchash = 0x0C08BC700;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)FsInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)FsInformationClass;
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
    o_para_num = 5;
    o_funchash = 0x0A6208368;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)MaximumSize;
    o_para5 = (ULONG_PTR)SectionPageProtection;
    o_para6 = (ULONG_PTR)AllocationAttributes;
    o_para7 = (ULONG_PTR)FileHandle;
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
    o_para_num = 7;
    o_funchash = 0x008A00A35;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
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
    o_funchash = 0x0A801A296;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtApphelpCacheControl(APPHELPCACHESERVICECLASS Service, PVOID ServiceData) {
    o_para1 = (ULONG_PTR)Service;
    o_para2 = (ULONG_PTR)ServiceData;
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
    o_funchash = 0x00B86631D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ParentProcess;
    o_para5 = (ULONG_PTR)Flags;
    o_para6 = (ULONG_PTR)SectionHandle;
    o_para7 = (ULONG_PTR)DebugPort;
    o_para8 = (ULONG_PTR)ExceptionPort;
    o_para9 = (ULONG_PTR)JobMemberLevel;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0D15FE1E7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PUSER_STACK InitialTeb, BOOLEAN CreateSuspended) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ProcessHandle;
    o_para5 = (ULONG_PTR)ClientId;
    o_para6 = (ULONG_PTR)ThreadContext;
    o_para7 = (ULONG_PTR)InitialTeb;
    o_para8 = (ULONG_PTR)CreateSuspended;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x0A20DFCBF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)JobHandle;
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
    o_funchash = 0x0AEC2984B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)NewProtect;
    o_para5 = (ULONG_PTR)OldProtect;
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
    o_para_num = 5;
    o_funchash = 0x097129F93;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, ULONG SectionInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)SectionInformationClass;
    o_para3 = (ULONG_PTR)SectionInformation;
    o_para4 = (ULONG_PTR)SectionInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x03AE2503F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
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
    o_funchash = 0x09CBFD611;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)ThreadHandle;
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
    o_funchash = 0x06D39A21D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG DataEntryIndex, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = (ULONG_PTR)DataEntryIndex;
    o_para4 = (ULONG_PTR)Buffer;
    o_para5 = (ULONG_PTR)BufferSize;
    o_para6 = (ULONG_PTR)NumberOfBytesRead;
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
    o_para_num = 6;
    o_funchash = 0x0381A24A0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_para5 = (ULONG_PTR)AllocationSize;
    o_para6 = (ULONG_PTR)FileAttributes;
    o_para7 = (ULONG_PTR)ShareAccess;
    o_para8 = (ULONG_PTR)CreateDisposition;
    o_para9 = (ULONG_PTR)CreateOptions;
    o_para10 = (ULONG_PTR)EaBuffer;
    o_para11 = (ULONG_PTR)EaLength;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0BDDB5F9C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)EventInformationClass;
    o_para3 = (ULONG_PTR)EventInformation;
    o_para4 = (ULONG_PTR)EventInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x086ABEF3E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWriteRequestData(HANDLE PortHandle, PPORT_MESSAGE Request, ULONG DataIndex, PVOID Buffer, ULONG Length, PULONG ResultLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Request;
    o_para3 = (ULONG_PTR)DataIndex;
    o_para4 = (ULONG_PTR)Buffer;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ResultLength;
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
    o_para_num = 6;
    o_funchash = 0x0A21ED092;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0AA95DA69;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckByTypeAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PBOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ObjectTypeName;
    o_para4 = (ULONG_PTR)ObjectName;
    o_para5 = (ULONG_PTR)SecurityDescriptor;
    o_para6 = (ULONG_PTR)PrincipalSelfSid;
    o_para7 = (ULONG_PTR)DesiredAccess;
    o_para8 = (ULONG_PTR)AuditType;
    o_para9 = (ULONG_PTR)Flags;
    o_para10 = (ULONG_PTR)ObjectTypeList;
    o_para11 = (ULONG_PTR)ObjectTypeListLength;
    o_para12 = (ULONG_PTR)GenericMapping;
    o_para13 = (ULONG_PTR)ObjectCreation;
    o_para14 = (ULONG_PTR)GrantedAccess;
    o_para15 = (ULONG_PTR)AccessStatus;
    o_para16 = (ULONG_PTR)GenerateOnClose;
    o_para17 = 0;
    o_para_num = 16;
    o_funchash = 0x00BABCCF9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForMultipleObjects(ULONG Count, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)Count;
    o_para2 = (ULONG_PTR)Handles;
    o_para3 = (ULONG_PTR)WaitType;
    o_para4 = (ULONG_PTR)Alertable;
    o_para5 = (ULONG_PTR)Timeout;
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
    o_para_num = 5;
    o_funchash = 0x035BA1D27;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)ObjectInformationClass;
    o_para3 = (ULONG_PTR)ObjectInformation;
    o_para4 = (ULONG_PTR)ObjectInformationLength;
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
    o_funchash = 0x00A960619;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
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
    o_funchash = 0x0B8EA89B0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields) {
    o_para1 = (ULONG_PTR)TraceHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)FieldSize;
    o_para4 = (ULONG_PTR)Fields;
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
    o_funchash = 0x032A92D02;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    o_para1 = (ULONG_PTR)InformationLevel;
    o_para2 = (ULONG_PTR)InputBuffer;
    o_para3 = (ULONG_PTR)InputBufferLength;
    o_para4 = (ULONG_PTR)OutputBuffer;
    o_para5 = (ULONG_PTR)OutputBufferLength;
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
    o_para_num = 5;
    o_funchash = 0x0149A2BD7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID SystemData, ULONG DataSize) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)ValueName;
    o_para3 = (ULONG_PTR)TitleIndex;
    o_para4 = (ULONG_PTR)Type;
    o_para5 = (ULONG_PTR)SystemData;
    o_para6 = (ULONG_PTR)DataSize;
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
    o_para_num = 6;
    o_funchash = 0x01580C8D3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)CurrentState;
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
    o_funchash = 0x0DB46D9D2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext, BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DueTime;
    o_para3 = (ULONG_PTR)TimerApcRoutine;
    o_para4 = (ULONG_PTR)TimerContext;
    o_para5 = (ULONG_PTR)ResumeTimer;
    o_para6 = (ULONG_PTR)Period;
    o_para7 = (ULONG_PTR)PreviousState;
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
    o_para_num = 7;
    o_funchash = 0x003960D0A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckByType(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ULONG DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus) {
    o_para1 = (ULONG_PTR)SecurityDescriptor;
    o_para2 = (ULONG_PTR)PrincipalSelfSid;
    o_para3 = (ULONG_PTR)ClientToken;
    o_para4 = (ULONG_PTR)DesiredAccess;
    o_para5 = (ULONG_PTR)ObjectTypeList;
    o_para6 = (ULONG_PTR)ObjectTypeListLength;
    o_para7 = (ULONG_PTR)GenericMapping;
    o_para8 = (ULONG_PTR)PrivilegeSet;
    o_para9 = (ULONG_PTR)PrivilegeSetLength;
    o_para10 = (ULONG_PTR)GrantedAccess;
    o_para11 = (ULONG_PTR)AccessStatus;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0840259B0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus) {
    o_para1 = (ULONG_PTR)SecurityDescriptor;
    o_para2 = (ULONG_PTR)PrincipalSelfSid;
    o_para3 = (ULONG_PTR)ClientToken;
    o_para4 = (ULONG_PTR)DesiredAccess;
    o_para5 = (ULONG_PTR)ObjectTypeList;
    o_para6 = (ULONG_PTR)ObjectTypeListLength;
    o_para7 = (ULONG_PTR)GenericMapping;
    o_para8 = (ULONG_PTR)PrivilegeSet;
    o_para9 = (ULONG_PTR)PrivilegeSetLength;
    o_para10 = (ULONG_PTR)GrantedAccess;
    o_para11 = (ULONG_PTR)AccessStatus;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0D2B43CEF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckByTypeResultListAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PULONG GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ObjectTypeName;
    o_para4 = (ULONG_PTR)ObjectName;
    o_para5 = (ULONG_PTR)SecurityDescriptor;
    o_para6 = (ULONG_PTR)PrincipalSelfSid;
    o_para7 = (ULONG_PTR)DesiredAccess;
    o_para8 = (ULONG_PTR)AuditType;
    o_para9 = (ULONG_PTR)Flags;
    o_para10 = (ULONG_PTR)ObjectTypeList;
    o_para11 = (ULONG_PTR)ObjectTypeListLength;
    o_para12 = (ULONG_PTR)GenericMapping;
    o_para13 = (ULONG_PTR)ObjectCreation;
    o_para14 = (ULONG_PTR)GrantedAccess;
    o_para15 = (ULONG_PTR)AccessStatus;
    o_para16 = (ULONG_PTR)GenerateOnClose;
    o_para17 = 0;
    o_para_num = 16;
    o_funchash = 0x0B6ABAE25;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAccessCheckByTypeResultListAndAuditAlarmByHandle(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PULONG GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ClientToken;
    o_para4 = (ULONG_PTR)ObjectTypeName;
    o_para5 = (ULONG_PTR)ObjectName;
    o_para6 = (ULONG_PTR)SecurityDescriptor;
    o_para7 = (ULONG_PTR)PrincipalSelfSid;
    o_para8 = (ULONG_PTR)DesiredAccess;
    o_para9 = (ULONG_PTR)AuditType;
    o_para10 = (ULONG_PTR)Flags;
    o_para11 = (ULONG_PTR)ObjectTypeList;
    o_para12 = (ULONG_PTR)ObjectTypeListLength;
    o_para13 = (ULONG_PTR)GenericMapping;
    o_para14 = (ULONG_PTR)ObjectCreation;
    o_para15 = (ULONG_PTR)GrantedAccess;
    o_para16 = (ULONG_PTR)AccessStatus;
    o_para17 = (ULONG_PTR)GenerateOnClose;
    o_para_num = 17;
    o_funchash = 0x07DD02D6C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAcquireProcessActivityReference() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x030A0790C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddAtomEx(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom, ULONG Flags) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
    o_para4 = (ULONG_PTR)Flags;
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
    o_funchash = 0x085937FE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddBootEntry(PBOOT_ENTRY BootEntry, PULONG Id) {
    o_para1 = (ULONG_PTR)BootEntry;
    o_para2 = (ULONG_PTR)Id;
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
    o_funchash = 0x019B40326;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddDriverEntry(PEFI_DRIVER_ENTRY DriverEntry, PULONG Id) {
    o_para1 = (ULONG_PTR)DriverEntry;
    o_para2 = (ULONG_PTR)Id;
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
    o_funchash = 0x0DFC826CB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAdjustGroupsToken(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)ResetToDefault;
    o_para3 = (ULONG_PTR)NewState;
    o_para4 = (ULONG_PTR)BufferLength;
    o_para5 = (ULONG_PTR)PreviousState;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x00F98F590;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAdjustTokenClaimsAndDeviceGroups(HANDLE TokenHandle, BOOLEAN UserResetToDefault, BOOLEAN DeviceResetToDefault, BOOLEAN DeviceGroupsResetToDefault, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState, PTOKEN_GROUPS NewDeviceGroupsState, ULONG UserBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState, ULONG DeviceBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState, ULONG DeviceGroupsBufferLength, PTOKEN_GROUPS PreviousDeviceGroups, PULONG UserReturnLength, PULONG DeviceReturnLength, PULONG DeviceGroupsReturnBufferLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)UserResetToDefault;
    o_para3 = (ULONG_PTR)DeviceResetToDefault;
    o_para4 = (ULONG_PTR)DeviceGroupsResetToDefault;
    o_para5 = (ULONG_PTR)NewUserState;
    o_para6 = (ULONG_PTR)NewDeviceState;
    o_para7 = (ULONG_PTR)NewDeviceGroupsState;
    o_para8 = (ULONG_PTR)UserBufferLength;
    o_para9 = (ULONG_PTR)PreviousUserState;
    o_para10 = (ULONG_PTR)DeviceBufferLength;
    o_para11 = (ULONG_PTR)PreviousDeviceState;
    o_para12 = (ULONG_PTR)DeviceGroupsBufferLength;
    o_para13 = (ULONG_PTR)PreviousDeviceGroups;
    o_para14 = (ULONG_PTR)UserReturnLength;
    o_para15 = (ULONG_PTR)DeviceReturnLength;
    o_para16 = (ULONG_PTR)DeviceGroupsReturnBufferLength;
    o_para17 = 0;
    o_para_num = 16;
    o_funchash = 0x005CD615F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
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
    o_funchash = 0x0A00EA697;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertThread(HANDLE ThreadHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
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
    o_funchash = 0x0CAEC4BC6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertThreadByThreadId(ULONG ThreadId) {
    o_para1 = (ULONG_PTR)ThreadId;
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
    o_funchash = 0x00F1271D1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateLocallyUniqueId(PLUID Luid) {
    o_para1 = (ULONG_PTR)Luid;
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
    o_funchash = 0x02795637C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateReserveObject(PHANDLE MemoryReserveHandle, POBJECT_ATTRIBUTES ObjectAttributes, MEMORY_RESERVE_TYPE Type) {
    o_para1 = (ULONG_PTR)MemoryReserveHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)Type;
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
    o_para_num = 3;
    o_funchash = 0x02E17AE0B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
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
    o_para_num = 3;
    o_funchash = 0x063C10C22;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateUuids(PLARGE_INTEGER Time, PULONG Range, PULONG Sequence, PUCHAR Seed) {
    o_para1 = (ULONG_PTR)Time;
    o_para2 = (ULONG_PTR)Range;
    o_para3 = (ULONG_PTR)Sequence;
    o_para4 = (ULONG_PTR)Seed;
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
    o_funchash = 0x0799F7707;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateVirtualMemoryEx(HANDLE ProcessHandle, PPVOID lpAddress, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG flAllocationType, PVOID DataBuffer, ULONG DataCount) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)lpAddress;
    o_para3 = (ULONG_PTR)ZeroBits;
    o_para4 = (ULONG_PTR)pSize;
    o_para5 = (ULONG_PTR)flAllocationType;
    o_para6 = (ULONG_PTR)DataBuffer;
    o_para7 = (ULONG_PTR)DataCount;
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
    o_para_num = 7;
    o_funchash = 0x0E4673932;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcAcceptConnectPort(PHANDLE PortHandle, HANDLE ConnectionPortHandle, ULONG Flags, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes, BOOLEAN AcceptConnection) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ConnectionPortHandle;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = (ULONG_PTR)ObjectAttributes;
    o_para5 = (ULONG_PTR)PortAttributes;
    o_para6 = (ULONG_PTR)PortContext;
    o_para7 = (ULONG_PTR)ConnectionRequest;
    o_para8 = (ULONG_PTR)ConnectionMessageAttributes;
    o_para9 = (ULONG_PTR)AcceptConnection;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x07EA1612A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCancelMessage(HANDLE PortHandle, ULONG Flags, PALPC_CONTEXT_ATTR MessageContext) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)MessageContext;
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
    o_para_num = 3;
    o_funchash = 0x01A1DDE44;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSID RequiredServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortName;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)PortAttributes;
    o_para5 = (ULONG_PTR)Flags;
    o_para6 = (ULONG_PTR)RequiredServerSid;
    o_para7 = (ULONG_PTR)ConnectionMessage;
    o_para8 = (ULONG_PTR)BufferLength;
    o_para9 = (ULONG_PTR)OutMessageAttributes;
    o_para10 = (ULONG_PTR)InMessageAttributes;
    o_para11 = (ULONG_PTR)Timeout;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x016813D1E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcConnectPortEx(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes, POBJECT_ATTRIBUTES ClientPortObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements, PPORT_MESSAGE ConnectionMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ConnectionPortObjectAttributes;
    o_para3 = (ULONG_PTR)ClientPortObjectAttributes;
    o_para4 = (ULONG_PTR)PortAttributes;
    o_para5 = (ULONG_PTR)Flags;
    o_para6 = (ULONG_PTR)ServerSecurityRequirements;
    o_para7 = (ULONG_PTR)ConnectionMessage;
    o_para8 = (ULONG_PTR)BufferLength;
    o_para9 = (ULONG_PTR)OutMessageAttributes;
    o_para10 = (ULONG_PTR)InMessageAttributes;
    o_para11 = (ULONG_PTR)Timeout;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0139FADA9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)PortAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0F0B07BAE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreatePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle, SIZE_T SectionSize, PHANDLE AlpcSectionHandle, PSIZE_T ActualSectionSize) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SectionHandle;
    o_para4 = (ULONG_PTR)SectionSize;
    o_para5 = (ULONG_PTR)AlpcSectionHandle;
    o_para6 = (ULONG_PTR)ActualSectionSize;
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
    o_para_num = 6;
    o_funchash = 0x074D61BCB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateResourceReserve(HANDLE PortHandle, ULONG Flags, SIZE_T MessageSize, PHANDLE ResourceId) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)MessageSize;
    o_para4 = (ULONG_PTR)ResourceId;
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
    o_funchash = 0x036BA2637;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateSectionView(HANDLE PortHandle, ULONG Flags, PALPC_DATA_VIEW_ATTR ViewAttributes) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ViewAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0F4ABF335;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateSecurityContext(HANDLE PortHandle, ULONG Flags, PALPC_SECURITY_ATTR SecurityAttribute) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SecurityAttribute;
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
    o_para_num = 3;
    o_funchash = 0x0164F1ACF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeletePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SectionHandle;
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
    o_para_num = 3;
    o_funchash = 0x070695EF5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteResourceReserve(HANDLE PortHandle, ULONG Flags, HANDLE ResourceId) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ResourceId;
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
    o_para_num = 3;
    o_funchash = 0x046ED6C61;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteSectionView(HANDLE PortHandle, ULONG Flags, PVOID ViewBase) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ViewBase;
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
    o_para_num = 3;
    o_funchash = 0x054ED7373;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ContextHandle;
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
    o_para_num = 3;
    o_funchash = 0x0FF3AEAB3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDisconnectPort(HANDLE PortHandle, ULONG Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
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
    o_funchash = 0x0A4F2419C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcImpersonateClientContainerOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x09EF672A5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, PVOID Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x0E4B5C16D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcOpenSenderProcess(PHANDLE ProcessHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)PortHandle;
    o_para3 = (ULONG_PTR)PortMessage;
    o_para4 = (ULONG_PTR)Flags;
    o_para5 = (ULONG_PTR)DesiredAccess;
    o_para6 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 6;
    o_funchash = 0x03D97320C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcOpenSenderThread(PHANDLE ThreadHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PortHandle;
    o_para3 = (ULONG_PTR)PortMessage;
    o_para4 = (ULONG_PTR)Flags;
    o_para5 = (ULONG_PTR)DesiredAccess;
    o_para6 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 6;
    o_funchash = 0x06EC8320B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcQueryInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortInformationClass;
    o_para3 = (ULONG_PTR)PortInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x08E5FC88B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcQueryInformationMessage(HANDLE PortHandle, PPORT_MESSAGE PortMessage, ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass, PVOID MessageInformation, ULONG Length, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortMessage;
    o_para3 = (ULONG_PTR)MessageInformationClass;
    o_para4 = (ULONG_PTR)MessageInformation;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x0AD9CA03A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcRevokeSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ContextHandle;
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
    o_para_num = 3;
    o_funchash = 0x0F56AE68D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage, PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes, PPORT_MESSAGE ReceiveMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SendMessage;
    o_para4 = (ULONG_PTR)SendMessageAttributes;
    o_para5 = (ULONG_PTR)ReceiveMessage;
    o_para6 = (ULONG_PTR)BufferLength;
    o_para7 = (ULONG_PTR)ReceiveMessageAttributes;
    o_para8 = (ULONG_PTR)Timeout;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x09F7DE6F1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcSetInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortInformationClass;
    o_para3 = (ULONG_PTR)PortInformation;
    o_para4 = (ULONG_PTR)Length;
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
    o_funchash = 0x01E7B649F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAreMappedFilesTheSame(PVOID File1MappedAsAnImage, PVOID File2MappedAsFile) {
    o_para1 = (ULONG_PTR)File1MappedAsAnImage;
    o_para2 = (ULONG_PTR)File2MappedAsFile;
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
    o_funchash = 0x0938DFC0F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)ProcessHandle;
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
    o_funchash = 0x03A84063B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAssociateWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, HANDLE IoCompletionHandle, HANDLE TargetObjectHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation, PBOOLEAN AlreadySignaled) {
    o_para1 = (ULONG_PTR)WaitCompletionPacketHandle;
    o_para2 = (ULONG_PTR)IoCompletionHandle;
    o_para3 = (ULONG_PTR)TargetObjectHandle;
    o_para4 = (ULONG_PTR)KeyContext;
    o_para5 = (ULONG_PTR)ApcContext;
    o_para6 = (ULONG_PTR)IoStatus;
    o_para7 = (ULONG_PTR)IoStatusInformation;
    o_para8 = (ULONG_PTR)AlreadySignaled;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x0393C33A2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCallEnclave(PENCLAVE_ROUTINE Routine, PVOID Parameter, BOOLEAN WaitForThread, PVOID ReturnValue) {
    o_para1 = (ULONG_PTR)Routine;
    o_para2 = (ULONG_PTR)Parameter;
    o_para3 = (ULONG_PTR)WaitForThread;
    o_para4 = (ULONG_PTR)ReturnValue;
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
    o_funchash = 0x09F309BDB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelIoFileEx(HANDLE FileHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoRequestToCancel;
    o_para3 = (ULONG_PTR)IoStatusBlock;
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
    o_para_num = 3;
    o_funchash = 0x0A95BFB86;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelSynchronousIoFile(HANDLE ThreadHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)IoRequestToCancel;
    o_para3 = (ULONG_PTR)IoStatusBlock;
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
    o_para_num = 3;
    o_funchash = 0x09604A6CE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelTimer2(HANDLE TimerHandle, PT2_CANCEL_PARAMETERS Parameters) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)Parameters;
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
    o_funchash = 0x0099DE933;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, BOOLEAN RemoveSignaledPacket) {
    o_para1 = (ULONG_PTR)WaitCompletionPacketHandle;
    o_para2 = (ULONG_PTR)RemoveSignaledPacket;
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
    o_funchash = 0x0AB9F4AE3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x040BC6C32;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x010B92F3A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)Wait;
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
    o_funchash = 0x002A821FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Wait;
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
    o_funchash = 0x03CA0DFB1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompactKeys(ULONG Count, HANDLE KeyArray) {
    o_para1 = (ULONG_PTR)Count;
    o_para2 = (ULONG_PTR)KeyArray;
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
    o_funchash = 0x07BE01004;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareObjects(HANDLE FirstObjectHandle, HANDLE SecondObjectHandle) {
    o_para1 = (ULONG_PTR)FirstObjectHandle;
    o_para2 = (ULONG_PTR)SecondObjectHandle;
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
    o_funchash = 0x0115AE533;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareSigningLevels(ULONG UnknownParameter1, ULONG UnknownParameter2) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
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
    o_funchash = 0x0B288438B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal) {
    o_para1 = (ULONG_PTR)FirstTokenHandle;
    o_para2 = (ULONG_PTR)SecondTokenHandle;
    o_para3 = (ULONG_PTR)Equal;
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
    o_para_num = 3;
    o_funchash = 0x0DDB1B6A5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompleteConnectPort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
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
    o_funchash = 0x0E6B2DF1C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompressKey(HANDLE Key) {
    o_para1 = (ULONG_PTR)Key;
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
    o_funchash = 0x0171238B4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_SECTION_WRITE ClientView, PPORT_SECTION_READ ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortName;
    o_para3 = (ULONG_PTR)SecurityQos;
    o_para4 = (ULONG_PTR)ClientView;
    o_para5 = (ULONG_PTR)ServerView;
    o_para6 = (ULONG_PTR)MaxMessageLength;
    o_para7 = (ULONG_PTR)ConnectionInformation;
    o_para8 = (ULONG_PTR)ConnectionInformationLength;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x062F27F5A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtConvertBetweenAuxiliaryCounterAndPerformanceCounter(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = (ULONG_PTR)UnknownParameter3;
    o_para4 = (ULONG_PTR)UnknownParameter4;
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
    o_funchash = 0x0199A3327;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
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
    o_funchash = 0x0A43CBE91;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x01C86744D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateDirectoryObjectEx(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ShadowDirectoryHandle, ULONG Flags) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ShadowDirectoryHandle;
    o_para5 = (ULONG_PTR)Flags;
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
    o_para_num = 5;
    o_funchash = 0x06ACB547C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateEnclave(HANDLE ProcessHandle, PVOID BaseAddress, ULONG_PTR ZeroBits, SIZE_T Size, SIZE_T InitialCommitment, ULONG EnclaveType, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)ZeroBits;
    o_para4 = (ULONG_PTR)Size;
    o_para5 = (ULONG_PTR)InitialCommitment;
    o_para6 = (ULONG_PTR)EnclaveType;
    o_para7 = (ULONG_PTR)EnclaveInformation;
    o_para8 = (ULONG_PTR)EnclaveInformationLength;
    o_para9 = (ULONG_PTR)EnclaveError;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x02254D5C4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, HANDLE TransactionHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, NOTIFICATION_MASK NotificationMask, PVOID EnlistmentKey) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ResourceManagerHandle;
    o_para4 = (ULONG_PTR)TransactionHandle;
    o_para5 = (ULONG_PTR)ObjectAttributes;
    o_para6 = (ULONG_PTR)CreateOptions;
    o_para7 = (ULONG_PTR)NotificationMask;
    o_para8 = (ULONG_PTR)EnlistmentKey;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x0FBA107CA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x09FB05DE7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateIRTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
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
    o_funchash = 0x0A5A638AD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Count) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Count;
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
    o_funchash = 0x0940D9265;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x03EA0141D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags) {
    o_para1 = (ULONG_PTR)NumJob;
    o_para2 = (ULONG_PTR)UserJobSet;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x0AE3EC723;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, HANDLE TransactionHandle, PULONG Disposition) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TitleIndex;
    o_para5 = (ULONG_PTR)Class;
    o_para6 = (ULONG_PTR)CreateOptions;
    o_para7 = (ULONG_PTR)TransactionHandle;
    o_para8 = (ULONG_PTR)Disposition;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x0C859D2E6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
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
    o_funchash = 0x0F915D941;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateLowBoxToken(PHANDLE TokenHandle, HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PSID PackageSid, ULONG CapabilityCount, PSID_AND_ATTRIBUTES Capabilities, ULONG HandleCount, HANDLE Handles) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)ExistingTokenHandle;
    o_para3 = (ULONG_PTR)DesiredAccess;
    o_para4 = (ULONG_PTR)ObjectAttributes;
    o_para5 = (ULONG_PTR)PackageSid;
    o_para6 = (ULONG_PTR)CapabilityCount;
    o_para7 = (ULONG_PTR)Capabilities;
    o_para8 = (ULONG_PTR)HandleCount;
    o_para9 = (ULONG_PTR)Handles;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x011A63F1A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateMailslotFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota, ULONG MaximumMessageSize, PLARGE_INTEGER ReadTimeout) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_para5 = (ULONG_PTR)CreateOptions;
    o_para6 = (ULONG_PTR)MailslotQuota;
    o_para7 = (ULONG_PTR)MaximumMessageSize;
    o_para8 = (ULONG_PTR)ReadTimeout;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x02AA0FA96;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)InitialOwner;
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
    o_funchash = 0x0CC4FE9D6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateNamedPipeFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, BOOLEAN NamedPipeType, BOOLEAN ReadMode, BOOLEAN CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_para5 = (ULONG_PTR)ShareAccess;
    o_para6 = (ULONG_PTR)CreateDisposition;
    o_para7 = (ULONG_PTR)CreateOptions;
    o_para8 = (ULONG_PTR)NamedPipeType;
    o_para9 = (ULONG_PTR)ReadMode;
    o_para10 = (ULONG_PTR)CompletionMode;
    o_para11 = (ULONG_PTR)MaximumInstances;
    o_para12 = (ULONG_PTR)InboundQuota;
    o_para13 = (ULONG_PTR)OutboundQuota;
    o_para14 = (ULONG_PTR)DefaultTimeout;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 14;
    o_funchash = 0x0A09B76A6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePagingFile(PUNICODE_STRING PageFileName, PULARGE_INTEGER MinimumSize, PULARGE_INTEGER MaximumSize, ULONG Priority) {
    o_para1 = (ULONG_PTR)PageFileName;
    o_para2 = (ULONG_PTR)MinimumSize;
    o_para3 = (ULONG_PTR)MaximumSize;
    o_para4 = (ULONG_PTR)Priority;
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
    o_funchash = 0x0E37AD32F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG PreferredNode) {
    o_para1 = (ULONG_PTR)PartitionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)PreferredNode;
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
    o_funchash = 0x0C775E424;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)MaxConnectionInfoLength;
    o_para4 = (ULONG_PTR)MaxMessageLength;
    o_para5 = (ULONG_PTR)MaxPoolUsage;
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
    o_para_num = 5;
    o_funchash = 0x062F37D70;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)BoundaryDescriptor;
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
    o_funchash = 0x00AADCFF5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ParentProcess;
    o_para5 = (ULONG_PTR)InheritObjectTable;
    o_para6 = (ULONG_PTR)SectionHandle;
    o_para7 = (ULONG_PTR)DebugPort;
    o_para8 = (ULONG_PTR)ExceptionPort;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x013BE36E6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateProfile(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, ULONG ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, ULONG Affinity) {
    o_para1 = (ULONG_PTR)ProfileHandle;
    o_para2 = (ULONG_PTR)Process;
    o_para3 = (ULONG_PTR)ProfileBase;
    o_para4 = (ULONG_PTR)ProfileSize;
    o_para5 = (ULONG_PTR)BucketSize;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)BufferSize;
    o_para8 = (ULONG_PTR)ProfileSource;
    o_para9 = (ULONG_PTR)Affinity;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x068BF2068;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateProfileEx(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, SIZE_T ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, USHORT GroupCount, PGROUP_AFFINITY GroupAffinity) {
    o_para1 = (ULONG_PTR)ProfileHandle;
    o_para2 = (ULONG_PTR)Process;
    o_para3 = (ULONG_PTR)ProfileBase;
    o_para4 = (ULONG_PTR)ProfileSize;
    o_para5 = (ULONG_PTR)BucketSize;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)BufferSize;
    o_para8 = (ULONG_PTR)ProfileSource;
    o_para9 = (ULONG_PTR)GroupCount;
    o_para10 = (ULONG_PTR)GroupAffinity;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x08CD67FAC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateRegistryTransaction(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, DWORD Flags) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
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
    o_funchash = 0x008E6364F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID RmGuid, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, PUNICODE_STRING Description) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)TmHandle;
    o_para4 = (ULONG_PTR)RmGuid;
    o_para5 = (ULONG_PTR)ObjectAttributes;
    o_para6 = (ULONG_PTR)CreateOptions;
    o_para7 = (ULONG_PTR)Description;
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
    o_para_num = 7;
    o_funchash = 0x0B837ECED;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)InitialCount;
    o_para5 = (ULONG_PTR)MaximumCount;
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
    o_para_num = 5;
    o_funchash = 0x0C99991A6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LinkTarget) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)LinkTarget;
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
    o_funchash = 0x0A437DCDB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ProcessHandle;
    o_para5 = (ULONG_PTR)StartRoutine;
    o_para6 = (ULONG_PTR)Argument;
    o_para7 = (ULONG_PTR)CreateFlags;
    o_para8 = (ULONG_PTR)ZeroBits;
    o_para9 = (ULONG_PTR)StackSize;
    o_para10 = (ULONG_PTR)MaximumStackSize;
    o_para11 = (ULONG_PTR)AttributeList;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x05CB293F5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TimerType;
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
    o_funchash = 0x0DB8FD712;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTimer2(PHANDLE TimerHandle, PVOID Reserved1, PVOID Reserved2, ULONG Attributes, ACCESS_MASK DesiredAccess) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)Reserved1;
    o_para3 = (ULONG_PTR)Reserved2;
    o_para4 = (ULONG_PTR)Attributes;
    o_para5 = (ULONG_PTR)DesiredAccess;
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
    o_para_num = 5;
    o_funchash = 0x0C9542EC1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TokenType;
    o_para5 = (ULONG_PTR)AuthenticationId;
    o_para6 = (ULONG_PTR)ExpirationTime;
    o_para7 = (ULONG_PTR)User;
    o_para8 = (ULONG_PTR)Groups;
    o_para9 = (ULONG_PTR)Privileges;
    o_para10 = (ULONG_PTR)Owner;
    o_para11 = (ULONG_PTR)PrimaryGroup;
    o_para12 = (ULONG_PTR)DefaultDacl;
    o_para13 = (ULONG_PTR)TokenSource;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 13;
    o_funchash = 0x0D590EBD8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTokenEx(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes, PTOKEN_GROUPS DeviceGroups, PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TokenType;
    o_para5 = (ULONG_PTR)AuthenticationId;
    o_para6 = (ULONG_PTR)ExpirationTime;
    o_para7 = (ULONG_PTR)User;
    o_para8 = (ULONG_PTR)Groups;
    o_para9 = (ULONG_PTR)Privileges;
    o_para10 = (ULONG_PTR)UserAttributes;
    o_para11 = (ULONG_PTR)DeviceAttributes;
    o_para12 = (ULONG_PTR)DeviceGroups;
    o_para13 = (ULONG_PTR)TokenMandatoryPolicy;
    o_para14 = (ULONG_PTR)Owner;
    o_para15 = (ULONG_PTR)PrimaryGroup;
    o_para16 = (ULONG_PTR)DefaultDacl;
    o_para17 = (ULONG_PTR)TokenSource;
    o_para_num = 17;
    o_funchash = 0x0AE4A7814;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle, ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags, PLARGE_INTEGER Timeout, PUNICODE_STRING Description) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Uow;
    o_para5 = (ULONG_PTR)TmHandle;
    o_para6 = (ULONG_PTR)CreateOptions;
    o_para7 = (ULONG_PTR)IsolationLevel;
    o_para8 = (ULONG_PTR)IsolationFlags;
    o_para9 = (ULONG_PTR)Timeout;
    o_para10 = (ULONG_PTR)Description;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x02C6B3CE9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, ULONG CreateOptions, ULONG CommitStrength) {
    o_para1 = (ULONG_PTR)TmHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)LogFileName;
    o_para5 = (ULONG_PTR)CreateOptions;
    o_para6 = (ULONG_PTR)CommitStrength;
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
    o_para_num = 6;
    o_funchash = 0x08FB0DF6F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)ThreadHandle;
    o_para3 = (ULONG_PTR)ProcessDesiredAccess;
    o_para4 = (ULONG_PTR)ThreadDesiredAccess;
    o_para5 = (ULONG_PTR)ProcessObjectAttributes;
    o_para6 = (ULONG_PTR)ThreadObjectAttributes;
    o_para7 = (ULONG_PTR)ProcessFlags;
    o_para8 = (ULONG_PTR)ThreadFlags;
    o_para9 = (ULONG_PTR)ProcessParameters;
    o_para10 = (ULONG_PTR)CreateInfo;
    o_para11 = (ULONG_PTR)AttributeList;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 11;
    o_funchash = 0x0821E8193;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateWaitCompletionPacket(PHANDLE WaitCompletionPacketHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)WaitCompletionPacketHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x039A0416C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateWaitablePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)MaxConnectionInfoLength;
    o_para4 = (ULONG_PTR)MaxMessageLength;
    o_para5 = (ULONG_PTR)MaxPoolUsage;
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
    o_para_num = 5;
    o_funchash = 0x0608C6716;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateWnfStateName(PCWNF_STATE_NAME StateName, WNF_STATE_NAME_LIFETIME NameLifetime, WNF_DATA_SCOPE DataScope, BOOLEAN PersistData, PCWNF_TYPE_ID TypeId, ULONG MaximumStateSize, PSECURITY_DESCRIPTOR SecurityDescriptor) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)NameLifetime;
    o_para3 = (ULONG_PTR)DataScope;
    o_para4 = (ULONG_PTR)PersistData;
    o_para5 = (ULONG_PTR)TypeId;
    o_para6 = (ULONG_PTR)MaximumStateSize;
    o_para7 = (ULONG_PTR)SecurityDescriptor;
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
    o_para_num = 7;
    o_funchash = 0x054CA7D4F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateWorkerFactory(PHANDLE WorkerFactoryHandleReturn, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE CompletionPortHandle, HANDLE WorkerProcessHandle, PVOID StartRoutine, PVOID StartParameter, ULONG MaxThreadCount, SIZE_T StackReserve, SIZE_T StackCommit) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandleReturn;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)CompletionPortHandle;
    o_para5 = (ULONG_PTR)WorkerProcessHandle;
    o_para6 = (ULONG_PTR)StartRoutine;
    o_para7 = (ULONG_PTR)StartParameter;
    o_para8 = (ULONG_PTR)MaxThreadCount;
    o_para9 = (ULONG_PTR)StackReserve;
    o_para10 = (ULONG_PTR)StackCommit;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x0CAAEFA17;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DebugObjectHandle;
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
    o_funchash = 0x086399F55;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDebugContinue(HANDLE DebugObjectHandle, PCLIENT_ID ClientId, NTSTATUS ContinueStatus) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)ClientId;
    o_para3 = (ULONG_PTR)ContinueStatus;
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
    o_para_num = 3;
    o_funchash = 0x048DCDBD0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteAtom(USHORT Atom) {
    o_para1 = (ULONG_PTR)Atom;
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
    o_funchash = 0x0DF4E3C17;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteBootEntry(ULONG Id) {
    o_para1 = (ULONG_PTR)Id;
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
    o_funchash = 0x0898AE966;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteDriverEntry(ULONG Id) {
    o_para1 = (ULONG_PTR)Id;
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
    o_funchash = 0x001987B7A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
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
    o_funchash = 0x0BBB92F81;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
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
    o_funchash = 0x0C793EA39;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)GenerateOnClose;
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
    o_para_num = 3;
    o_funchash = 0x034BA15EE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeletePrivateNamespace(HANDLE NamespaceHandle) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
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
    o_funchash = 0x035112A95;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)ValueName;
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
    o_funchash = 0x02F3B00ED;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteWnfStateData(PCWNF_STATE_NAME StateName, PVOID ExplicitScope) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)ExplicitScope;
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
    o_funchash = 0x064FB9AA6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteWnfStateName(PCWNF_STATE_NAME StateName) {
    o_para1 = (ULONG_PTR)StateName;
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
    o_funchash = 0x076118349;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDisableLastKnownGood() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x039A84F22;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDisplayString(PUNICODE_STRING String) {
    o_para1 = (ULONG_PTR)String;
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
    o_funchash = 0x00B063185;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDrawText(PUNICODE_STRING String) {
    o_para1 = (ULONG_PTR)String;
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
    o_funchash = 0x078DF6F5C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnableLastKnownGood() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0F8D2D658;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateBootEntries(PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)Buffer;
    o_para2 = (ULONG_PTR)BufferLength;
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
    o_funchash = 0x0CF93E00B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateDriverEntries(PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)Buffer;
    o_para2 = (ULONG_PTR)BufferLength;
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
    o_funchash = 0x00A49FF31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)InformationClass;
    o_para2 = (ULONG_PTR)Buffer;
    o_para3 = (ULONG_PTR)BufferLength;
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
    o_para_num = 3;
    o_funchash = 0x051AD1F7A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateTransactionObject(HANDLE RootObjectHandle, KTMOBJECT_TYPE QueryType, PKTMOBJECT_CURSOR ObjectCursor, ULONG ObjectCursorLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)RootObjectHandle;
    o_para2 = (ULONG_PTR)QueryType;
    o_para3 = (ULONG_PTR)ObjectCursor;
    o_para4 = (ULONG_PTR)ObjectCursorLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x09844F689;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)NewSectionSize;
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
    o_funchash = 0x075622BAF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFilterBootOption(FILTER_BOOT_OPTION_OPERATION FilterOperation, ULONG ObjectType, ULONG ElementType, PVOID SystemData, ULONG DataSize) {
    o_para1 = (ULONG_PTR)FilterOperation;
    o_para2 = (ULONG_PTR)ObjectType;
    o_para3 = (ULONG_PTR)ElementType;
    o_para4 = (ULONG_PTR)SystemData;
    o_para5 = (ULONG_PTR)DataSize;
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
    o_para_num = 5;
    o_funchash = 0x042CEA35D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, PHANDLE NewTokenHandle) {
    o_para1 = (ULONG_PTR)ExistingTokenHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SidsToDisable;
    o_para4 = (ULONG_PTR)PrivilegesToDelete;
    o_para5 = (ULONG_PTR)RestrictedSids;
    o_para6 = (ULONG_PTR)NewTokenHandle;
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
    o_para_num = 6;
    o_funchash = 0x04591C9B2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFilterTokenEx(HANDLE TokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, ULONG DisableUserClaimsCount, PUNICODE_STRING UserClaimsToDisable, ULONG DisableDeviceClaimsCount, PUNICODE_STRING DeviceClaimsToDisable, PTOKEN_GROUPS DeviceGroupsToDisable, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes, PTOKEN_GROUPS RestrictedDeviceGroups, PHANDLE NewTokenHandle) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SidsToDisable;
    o_para4 = (ULONG_PTR)PrivilegesToDelete;
    o_para5 = (ULONG_PTR)RestrictedSids;
    o_para6 = (ULONG_PTR)DisableUserClaimsCount;
    o_para7 = (ULONG_PTR)UserClaimsToDisable;
    o_para8 = (ULONG_PTR)DisableDeviceClaimsCount;
    o_para9 = (ULONG_PTR)DeviceClaimsToDisable;
    o_para10 = (ULONG_PTR)DeviceGroupsToDisable;
    o_para11 = (ULONG_PTR)RestrictedUserAttributes;
    o_para12 = (ULONG_PTR)RestrictedDeviceAttributes;
    o_para13 = (ULONG_PTR)RestrictedDeviceGroups;
    o_para14 = (ULONG_PTR)NewTokenHandle;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 14;
    o_funchash = 0x01620D09E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushBuffersFileEx(HANDLE FileHandle, ULONG Flags, PVOID Parameters, ULONG ParametersSize, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)Parameters;
    o_para4 = (ULONG_PTR)ParametersSize;
    o_para5 = (ULONG_PTR)IoStatusBlock;
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
    o_para_num = 5;
    o_funchash = 0x08C970FAF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushInstallUILanguage(LANGID InstallUILanguage, ULONG SetComittedFlag) {
    o_para1 = (ULONG_PTR)InstallUILanguage;
    o_para2 = (ULONG_PTR)SetComittedFlag;
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
    o_funchash = 0x0685F7DE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Length;
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
    o_para_num = 3;
    o_funchash = 0x08D2FF9B7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
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
    o_funchash = 0x024904975;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushProcessWriteBuffers() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0E0589C90;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)IoStatusBlock;
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
    o_funchash = 0x03191371F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushWriteBuffer() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0E75DD5E1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
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
    o_para_num = 3;
    o_funchash = 0x006BFFEB4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreezeRegistry(ULONG TimeOutInSeconds) {
    o_para1 = (ULONG_PTR)TimeOutInSeconds;
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
    o_funchash = 0x0CE54F6E5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreezeTransactions(PLARGE_INTEGER FreezeTimeout, PLARGE_INTEGER ThawTimeout) {
    o_para1 = (ULONG_PTR)FreezeTimeout;
    o_para2 = (ULONG_PTR)ThawTimeout;
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
    o_funchash = 0x0CF9B00C0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCachedSigningLevel(HANDLE File, PULONG Flags, PSE_SIGNING_LEVEL SigningLevel, PUCHAR Thumbprint, PULONG ThumbprintSize, PULONG ThumbprintAlgorithm) {
    o_para1 = (ULONG_PTR)File;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SigningLevel;
    o_para4 = (ULONG_PTR)Thumbprint;
    o_para5 = (ULONG_PTR)ThumbprintSize;
    o_para6 = (ULONG_PTR)ThumbprintAlgorithm;
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
    o_para_num = 6;
    o_funchash = 0x0B8FAFE48;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCompleteWnfStateSubscription(PCWNF_STATE_NAME OldDescriptorStateName, PLARGE_INTEGER OldSubscriptionId, ULONG OldDescriptorEventMask, ULONG OldDescriptorStatus, PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor, ULONG DescriptorSize) {
    o_para1 = (ULONG_PTR)OldDescriptorStateName;
    o_para2 = (ULONG_PTR)OldSubscriptionId;
    o_para3 = (ULONG_PTR)OldDescriptorEventMask;
    o_para4 = (ULONG_PTR)OldDescriptorStatus;
    o_para5 = (ULONG_PTR)NewDeliveryDescriptor;
    o_para6 = (ULONG_PTR)DescriptorSize;
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
    o_para_num = 6;
    o_funchash = 0x09C03BE97;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ThreadContext;
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
    o_funchash = 0x0F447FEF1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCurrentProcessorNumber() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x02ABB342A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCurrentProcessorNumberEx(PULONG ProcNumber) {
    o_para1 = (ULONG_PTR)ProcNumber;
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
    o_funchash = 0x09E90CC4A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetDevicePowerState(HANDLE Device, PDEVICE_POWER_STATE State) {
    o_para1 = (ULONG_PTR)Device;
    o_para2 = (ULONG_PTR)State;
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
    o_funchash = 0x0D887C339;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetMUIRegistryInfo(ULONG Flags, PULONG DataSize, PVOID SystemData) {
    o_para1 = (ULONG_PTR)Flags;
    o_para2 = (ULONG_PTR)DataSize;
    o_para3 = (ULONG_PTR)SystemData;
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
    o_para_num = 3;
    o_funchash = 0x004B8103D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)HandleAttributes;
    o_para4 = (ULONG_PTR)Flags;
    o_para5 = (ULONG_PTR)NewProcessHandle;
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
    o_para_num = 5;
    o_funchash = 0x0F2AC0AC0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)ThreadHandle;
    o_para3 = (ULONG_PTR)DesiredAccess;
    o_para4 = (ULONG_PTR)HandleAttributes;
    o_para5 = (ULONG_PTR)Flags;
    o_para6 = (ULONG_PTR)NewThreadHandle;
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
    o_para_num = 6;
    o_funchash = 0x0ECAEDFF1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetNlsSectionPtr(ULONG SectionType, ULONG SectionData, PVOID ContextData, PVOID SectionPointer, PULONG SectionSize) {
    o_para1 = (ULONG_PTR)SectionType;
    o_para2 = (ULONG_PTR)SectionData;
    o_para3 = (ULONG_PTR)ContextData;
    o_para4 = (ULONG_PTR)SectionPointer;
    o_para5 = (ULONG_PTR)SectionSize;
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
    o_para_num = 5;
    o_funchash = 0x03D8C2C2E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetNotificationResourceManager(HANDLE ResourceManagerHandle, PTRANSACTION_NOTIFICATION TransactionNotification, ULONG NotificationLength, PLARGE_INTEGER Timeout, PULONG ReturnLength, ULONG Asynchronous, ULONG AsynchronousContext) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)TransactionNotification;
    o_para3 = (ULONG_PTR)NotificationLength;
    o_para4 = (ULONG_PTR)Timeout;
    o_para5 = (ULONG_PTR)ReturnLength;
    o_para6 = (ULONG_PTR)Asynchronous;
    o_para7 = (ULONG_PTR)AsynchronousContext;
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
    o_para_num = 7;
    o_funchash = 0x02DB2331A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, ULONG RegionSize, PULONG UserAddressArray, PULONG EntriesInUserAddressArray, PULONG Granularity) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)BaseAddress;
    o_para4 = (ULONG_PTR)RegionSize;
    o_para5 = (ULONG_PTR)UserAddressArray;
    o_para6 = (ULONG_PTR)EntriesInUserAddressArray;
    o_para7 = (ULONG_PTR)Granularity;
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
    o_para_num = 7;
    o_funchash = 0x01C94D737;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateAnonymousToken(HANDLE ThreadHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
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
    o_funchash = 0x02B93FE30;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos) {
    o_para1 = (ULONG_PTR)ServerThreadHandle;
    o_para2 = (ULONG_PTR)ClientThreadHandle;
    o_para3 = (ULONG_PTR)SecurityQos;
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
    o_para_num = 3;
    o_funchash = 0x0A40FA2AD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitializeEnclave(HANDLE ProcessHandle, PVOID BaseAddress, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)EnclaveInformation;
    o_para4 = (ULONG_PTR)EnclaveInformationLength;
    o_para5 = (ULONG_PTR)EnclaveError;
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
    o_para_num = 5;
    o_funchash = 0x0D0970B2B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitializeNlsFiles(PVOID BaseAddress, PLCID DefaultLocaleId, PLARGE_INTEGER DefaultCasingTableSize) {
    o_para1 = (ULONG_PTR)BaseAddress;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
    o_para3 = (ULONG_PTR)DefaultCasingTableSize;
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
    o_para_num = 3;
    o_funchash = 0x0E6CF1A83;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitializeRegistry(USHORT BootCondition) {
    o_para1 = (ULONG_PTR)BootCondition;
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
    o_funchash = 0x0029D342D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous) {
    o_para1 = (ULONG_PTR)SystemAction;
    o_para2 = (ULONG_PTR)LightestSystemState;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = (ULONG_PTR)Asynchronous;
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
    o_funchash = 0x024B3A6A3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsSystemResumeAutomatic() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x03A9E353C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsUILanguageComitted() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0D3DD2BC1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtListenPort(HANDLE PortHandle, PPORT_MESSAGE ConnectionRequest) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ConnectionRequest;
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
    o_funchash = 0x0E53EDA8D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadDriver(PUNICODE_STRING DriverServiceName) {
    o_para1 = (ULONG_PTR)DriverServiceName;
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
    o_funchash = 0x088C36B99;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadEnclaveData(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, ULONG Protect, PVOID PageInformation, ULONG PageInformationLength, PSIZE_T NumberOfBytesWritten, PULONG EnclaveError) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)BufferSize;
    o_para5 = (ULONG_PTR)Protect;
    o_para6 = (ULONG_PTR)PageInformation;
    o_para7 = (ULONG_PTR)PageInformationLength;
    o_para8 = (ULONG_PTR)NumberOfBytesWritten;
    o_para9 = (ULONG_PTR)EnclaveError;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0C3A1ED2F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadHotPatch(PUNICODE_STRING HotPatchName, ULONG LoadFlag) {
    o_para1 = (ULONG_PTR)HotPatchName;
    o_para2 = (ULONG_PTR)LoadFlag;
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
    o_funchash = 0x0A8A3A206;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadKey(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)SourceFile;
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
    o_funchash = 0x02380465C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadKey2(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)SourceFile;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x07FA3B43A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadKeyEx(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags, HANDLE TrustClassKey, HANDLE Event, ACCESS_MASK DesiredAccess, PHANDLE RootHandle, PIO_STATUS_BLOCK IoStatus) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)SourceFile;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = (ULONG_PTR)TrustClassKey;
    o_para5 = (ULONG_PTR)Event;
    o_para6 = (ULONG_PTR)DesiredAccess;
    o_para7 = (ULONG_PTR)RootHandle;
    o_para8 = (ULONG_PTR)IoStatus;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x06BDC5F67;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER ByteOffset, PULARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)ByteOffset;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)Key;
    o_para9 = (ULONG_PTR)FailImmediately;
    o_para10 = (ULONG_PTR)ExclusiveLock;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x014C74670;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockProductActivationKeys(PULONG pPrivateVer, PULONG pSafeMode) {
    o_para1 = (ULONG_PTR)pPrivateVer;
    o_para2 = (ULONG_PTR)pSafeMode;
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
    o_funchash = 0x03BA72FCC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockRegistryKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
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
    o_funchash = 0x0C543E8E4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, ULONG MapType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)MapType;
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
    o_funchash = 0x003910913;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMakePermanentObject(HANDLE Handle) {
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
    o_funchash = 0x09AC70ACB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMakeTemporaryObject(HANDLE Handle) {
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
    o_funchash = 0x009966744;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtManagePartition(HANDLE TargetHandle, HANDLE SourceHandle, MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass, PVOID PartitionInformation, ULONG PartitionInformationLength) {
    o_para1 = (ULONG_PTR)TargetHandle;
    o_para2 = (ULONG_PTR)SourceHandle;
    o_para3 = (ULONG_PTR)PartitionInformationClass;
    o_para4 = (ULONG_PTR)PartitionInformation;
    o_para5 = (ULONG_PTR)PartitionInformationLength;
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
    o_para_num = 5;
    o_funchash = 0x000AA4005;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapCMFModule(ULONG What, ULONG Index, PULONG CacheIndexOut, PULONG CacheFlagsOut, PULONG ViewSizeOut, PVOID BaseAddress) {
    o_para1 = (ULONG_PTR)What;
    o_para2 = (ULONG_PTR)Index;
    o_para3 = (ULONG_PTR)CacheIndexOut;
    o_para4 = (ULONG_PTR)CacheFlagsOut;
    o_para5 = (ULONG_PTR)ViewSizeOut;
    o_para6 = (ULONG_PTR)BaseAddress;
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
    o_para_num = 6;
    o_funchash = 0x056D86A5E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapUserPhysicalPages(PVOID VirtualAddress, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)VirtualAddress;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
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
    o_para_num = 3;
    o_funchash = 0x07926824E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapViewOfSectionEx(HANDLE SectionHandle, HANDLE ProcessHandle, PLARGE_INTEGER SectionOffset, PPVOID BaseAddress, PSIZE_T ViewSize, ULONG AllocationType, ULONG Protect, PVOID DataBuffer, ULONG DataCount) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)ProcessHandle;
    o_para3 = (ULONG_PTR)SectionOffset;
    o_para4 = (ULONG_PTR)BaseAddress;
    o_para5 = (ULONG_PTR)ViewSize;
    o_para6 = (ULONG_PTR)AllocationType;
    o_para7 = (ULONG_PTR)Protect;
    o_para8 = (ULONG_PTR)DataBuffer;
    o_para9 = (ULONG_PTR)DataCount;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x084D606EC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtModifyBootEntry(PBOOT_ENTRY BootEntry) {
    o_para1 = (ULONG_PTR)BootEntry;
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
    o_funchash = 0x00D81090E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtModifyDriverEntry(PEFI_DRIVER_ENTRY DriverEntry) {
    o_para1 = (ULONG_PTR)DriverEntry;
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
    o_funchash = 0x00191312E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_NOTIFY_INFORMATION Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)CompletionFilter;
    o_para9 = (ULONG_PTR)WatchTree;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x06CFA7E4E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtNotifyChangeDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree, DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)Buffer;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)CompletionFilter;
    o_para9 = (ULONG_PTR)WatchTree;
    o_para10 = (ULONG_PTR)DirectoryNotifyInformationClass;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x006B5C0EB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)CompletionFilter;
    o_para7 = (ULONG_PTR)WatchTree;
    o_para8 = (ULONG_PTR)Buffer;
    o_para9 = (ULONG_PTR)BufferSize;
    o_para10 = (ULONG_PTR)Asynchronous;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x08505FAC0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtNotifyChangeMultipleKeys(HANDLE MasterKeyHandle, ULONG Count, POBJECT_ATTRIBUTES SubordinateObjects, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {
    o_para1 = (ULONG_PTR)MasterKeyHandle;
    o_para2 = (ULONG_PTR)Count;
    o_para3 = (ULONG_PTR)SubordinateObjects;
    o_para4 = (ULONG_PTR)Event;
    o_para5 = (ULONG_PTR)ApcRoutine;
    o_para6 = (ULONG_PTR)ApcContext;
    o_para7 = (ULONG_PTR)IoStatusBlock;
    o_para8 = (ULONG_PTR)CompletionFilter;
    o_para9 = (ULONG_PTR)WatchTree;
    o_para10 = (ULONG_PTR)Buffer;
    o_para11 = (ULONG_PTR)BufferSize;
    o_para12 = (ULONG_PTR)Asynchronous;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 12;
    o_funchash = 0x0EBB8F413;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtNotifyChangeSession(HANDLE SessionHandle, ULONG ChangeSequenceNumber, PLARGE_INTEGER ChangeTimeStamp, IO_SESSION_EVENT Event, IO_SESSION_STATE NewState, IO_SESSION_STATE PreviousState, PVOID Payload, ULONG PayloadSize) {
    o_para1 = (ULONG_PTR)SessionHandle;
    o_para2 = (ULONG_PTR)ChangeSequenceNumber;
    o_para3 = (ULONG_PTR)ChangeTimeStamp;
    o_para4 = (ULONG_PTR)Event;
    o_para5 = (ULONG_PTR)NewState;
    o_para6 = (ULONG_PTR)PreviousState;
    o_para7 = (ULONG_PTR)Payload;
    o_para8 = (ULONG_PTR)PayloadSize;
    o_para9 = 0;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 8;
    o_funchash = 0x07A991C09;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, LPGUID EnlistmentGuid, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ResourceManagerHandle;
    o_para4 = (ULONG_PTR)EnlistmentGuid;
    o_para5 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 5;
    o_funchash = 0x0583F45BD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x090B1C867;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0DC55FAC5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0E6B8EC27;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)OpenOptions;
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
    o_funchash = 0x049DD9885;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TransactionHandle;
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
    o_funchash = 0x0FEE0344E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyTransactedEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions, HANDLE TransactionHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)OpenOptions;
    o_para5 = (ULONG_PTR)TransactionHandle;
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
    o_para_num = 5;
    o_funchash = 0x03EAF3C15;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x010D5752C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x01CB5FEE3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ObjectTypeName;
    o_para4 = (ULONG_PTR)ObjectName;
    o_para5 = (ULONG_PTR)SecurityDescriptor;
    o_para6 = (ULONG_PTR)ClientToken;
    o_para7 = (ULONG_PTR)DesiredAccess;
    o_para8 = (ULONG_PTR)GrantedAccess;
    o_para9 = (ULONG_PTR)Privileges;
    o_para10 = (ULONG_PTR)ObjectCreation;
    o_para11 = (ULONG_PTR)AccessGranted;
    o_para12 = (ULONG_PTR)GenerateOnClose;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 12;
    o_funchash = 0x05C97540A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenPartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)PartitionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0CA9D28C1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenPrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)BoundaryDescriptor;
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
    o_funchash = 0x02E963531;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)TokenHandle;
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
    o_para_num = 3;
    o_funchash = 0x03DAF053E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenRegistryTransaction(PHANDLE RegistryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x01AB47865;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID ResourceManagerGuid, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)TmHandle;
    o_para4 = (ULONG_PTR)ResourceManagerGuid;
    o_para5 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 5;
    o_funchash = 0x067553C78;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x056885068;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSession(PHANDLE SessionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SessionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x0CA82CC16;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x006BCE0A1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    o_para1 = (ULONG_PTR)ThreadHandle;
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
    o_funchash = 0x0FCDFE27D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
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
    o_para_num = 3;
    o_funchash = 0x01DCE6746;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Uow;
    o_para5 = (ULONG_PTR)TmHandle;
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
    o_para_num = 5;
    o_funchash = 0x0DC4BFE9B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, LPGUID TmIdentity, ULONG OpenOptions) {
    o_para1 = (ULONG_PTR)TmHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)LogFileName;
    o_para5 = (ULONG_PTR)TmIdentity;
    o_para6 = (ULONG_PTR)OpenOptions;
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
    o_para_num = 6;
    o_funchash = 0x01D5D29DC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPlugPlayControl(PLUGPLAY_CONTROL_CLASS PnPControlClass, PVOID PnPControlData, ULONG PnPControlDataLength) {
    o_para1 = (ULONG_PTR)PnPControlClass;
    o_para2 = (ULONG_PTR)PnPControlData;
    o_para3 = (ULONG_PTR)PnPControlDataLength;
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
    o_para_num = 3;
    o_funchash = 0x013CFDD95;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrePrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x0BB39D42D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrePrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x059C69E8D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x0B93451B9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x018471DCD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrivilegeCheck(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result) {
    o_para1 = (ULONG_PTR)ClientToken;
    o_para2 = (ULONG_PTR)RequiredPrivileges;
    o_para3 = (ULONG_PTR)Result;
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
    o_para_num = 3;
    o_funchash = 0x034B6052D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrivilegeObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)ClientToken;
    o_para4 = (ULONG_PTR)DesiredAccess;
    o_para5 = (ULONG_PTR)Privileges;
    o_para6 = (ULONG_PTR)AccessGranted;
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
    o_para_num = 6;
    o_funchash = 0x032B5D2A2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrivilegedServiceAuditAlarm(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE ClientToken, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)ServiceName;
    o_para3 = (ULONG_PTR)ClientToken;
    o_para4 = (ULONG_PTR)Privileges;
    o_para5 = (ULONG_PTR)AccessGranted;
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
    o_para_num = 5;
    o_funchash = 0x05ADC5BB2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPropagationComplete(HANDLE ResourceManagerHandle, ULONG RequestCookie, ULONG BufferLength, PVOID Buffer) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)RequestCookie;
    o_para3 = (ULONG_PTR)BufferLength;
    o_para4 = (ULONG_PTR)Buffer;
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
    o_funchash = 0x03EBCA6BE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPropagationFailed(HANDLE ResourceManagerHandle, ULONG RequestCookie, NTSTATUS PropStatus) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)RequestCookie;
    o_para3 = (ULONG_PTR)PropStatus;
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
    o_para_num = 3;
    o_funchash = 0x03C5AC745;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPulseEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
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
    o_funchash = 0x0F8AADF31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryAuxiliaryCounterFrequency(PULONGLONG lpAuxiliaryCounterFrequency) {
    o_para1 = (ULONG_PTR)lpAuxiliaryCounterFrequency;
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
    o_funchash = 0x0B0562E46;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryBootEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
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
    o_funchash = 0x00F5219B7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength) {
    o_para1 = (ULONG_PTR)BootOptions;
    o_para2 = (ULONG_PTR)BootOptionsLength;
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
    o_funchash = 0x0C818F4B0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDebugFilterState(ULONG ComponentId, ULONG Level) {
    o_para1 = (ULONG_PTR)ComponentId;
    o_para2 = (ULONG_PTR)Level;
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
    o_funchash = 0x0D28DC222;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatusBlock;
    o_para6 = (ULONG_PTR)FileInformation;
    o_para7 = (ULONG_PTR)Length;
    o_para8 = (ULONG_PTR)FileInformationClass;
    o_para9 = (ULONG_PTR)QueryFlags;
    o_para10 = (ULONG_PTR)FileName;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 10;
    o_funchash = 0x0388A7E55;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)Buffer;
    o_para3 = (ULONG_PTR)Length;
    o_para4 = (ULONG_PTR)ReturnSingleEntry;
    o_para5 = (ULONG_PTR)RestartScan;
    o_para6 = (ULONG_PTR)Context;
    o_para7 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 7;
    o_funchash = 0x006AE3013;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDriverEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
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
    o_funchash = 0x09FB44CE8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PFILE_GET_EA_INFORMATION EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)ReturnSingleEntry;
    o_para6 = (ULONG_PTR)EaList;
    o_para7 = (ULONG_PTR)EaListLength;
    o_para8 = (ULONG_PTR)EaIndex;
    o_para9 = (ULONG_PTR)RestartScan;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0B6284E3A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = (ULONG_PTR)FileInformation;
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
    o_funchash = 0x0183B9E1A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationAtom(USHORT Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)Atom;
    o_para2 = (ULONG_PTR)AtomInformationClass;
    o_para3 = (ULONG_PTR)AtomInformation;
    o_para4 = (ULONG_PTR)AtomInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x052DEB58A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationByName(POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)FileInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)FileInformationClass;
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
    o_para_num = 5;
    o_funchash = 0x0129A5939;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)EnlistmentInformationClass;
    o_para3 = (ULONG_PTR)EnlistmentInformation;
    o_para4 = (ULONG_PTR)EnlistmentInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x05BC4BC9F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)JobObjectInformationClass;
    o_para3 = (ULONG_PTR)JobObjectInformation;
    o_para4 = (ULONG_PTR)JobObjectInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x031032781;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationPort(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortInformationClass;
    o_para3 = (ULONG_PTR)PortInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x026B2533C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)ResourceManagerInformationClass;
    o_para3 = (ULONG_PTR)ResourceManagerInformation;
    o_para4 = (ULONG_PTR)ResourceManagerInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0A762AFF8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationTransaction(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TransactionInformationClass;
    o_para3 = (ULONG_PTR)TransactionInformation;
    o_para4 = (ULONG_PTR)TransactionInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0CC87E2DF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationTransactionManager(HANDLE TransactionManagerHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, PVOID TransactionManagerInformation, ULONG TransactionManagerInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TransactionManagerHandle;
    o_para2 = (ULONG_PTR)TransactionManagerInformationClass;
    o_para3 = (ULONG_PTR)TransactionManagerInformation;
    o_para4 = (ULONG_PTR)TransactionManagerInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0082F297C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)WorkerFactoryInformationClass;
    o_para3 = (ULONG_PTR)WorkerFactoryInformation;
    o_para4 = (ULONG_PTR)WorkerFactoryInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0B412B09C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInstallUILanguage(PLANGID InstallUILanguageId) {
    o_para1 = (ULONG_PTR)InstallUILanguageId;
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
    o_funchash = 0x0E1B6EE13;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryIntervalProfile(KPROFILE_SOURCE ProfileSource, PULONG Interval) {
    o_para1 = (ULONG_PTR)ProfileSource;
    o_para2 = (ULONG_PTR)Interval;
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
    o_funchash = 0x00591FDD5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryIoCompletion(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)IoCompletionInformationClass;
    o_para3 = (ULONG_PTR)IoCompletionInformation;
    o_para4 = (ULONG_PTR)IoCompletionInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0CA83C86F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID SystemData, ULONG DataSize, PULONG ResultDataSize) {
    o_para1 = (ULONG_PTR)ValueName;
    o_para2 = (ULONG_PTR)Type;
    o_para3 = (ULONG_PTR)SystemData;
    o_para4 = (ULONG_PTR)DataSize;
    o_para5 = (ULONG_PTR)ResultDataSize;
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
    o_para_num = 5;
    o_funchash = 0x03A9E050C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryMultipleValueKey(HANDLE KeyHandle, PKEY_VALUE_ENTRY ValueEntries, ULONG EntryCount, PVOID ValueBuffer, PULONG BufferLength, PULONG RequiredBufferLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)ValueEntries;
    o_para3 = (ULONG_PTR)EntryCount;
    o_para4 = (ULONG_PTR)ValueBuffer;
    o_para5 = (ULONG_PTR)BufferLength;
    o_para6 = (ULONG_PTR)RequiredBufferLength;
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
    o_para_num = 6;
    o_funchash = 0x0BE288193;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)MutantInformationClass;
    o_para3 = (ULONG_PTR)MutantInformation;
    o_para4 = (ULONG_PTR)MutantInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0FC13FF84;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryOpenSubKeys(POBJECT_ATTRIBUTES TargetKey, PULONG HandleCount) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)HandleCount;
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
    o_funchash = 0x02183DEC8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryOpenSubKeysEx(POBJECT_ATTRIBUTES TargetKey, ULONG BufferLength, PVOID Buffer, PULONG RequiredSize) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)BufferLength;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)RequiredSize;
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
    o_funchash = 0x08B4B3D74;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryPortInformationProcess() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x03D9F3A0C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PFILE_QUOTA_LIST_INFORMATION SidList, ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)ReturnSingleEntry;
    o_para6 = (ULONG_PTR)SidList;
    o_para7 = (ULONG_PTR)SidListLength;
    o_para8 = (ULONG_PTR)StartSid;
    o_para9 = (ULONG_PTR)RestartScan;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x09D075527;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySecurityAttributesToken(HANDLE TokenHandle, PUNICODE_STRING Attributes, ULONG NumberOfAttributes, PVOID Buffer, ULONG Length, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)Attributes;
    o_para3 = (ULONG_PTR)NumberOfAttributes;
    o_para4 = (ULONG_PTR)Buffer;
    o_para5 = (ULONG_PTR)Length;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x039986334;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)SecurityInformation;
    o_para3 = (ULONG_PTR)SecurityDescriptor;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)LengthNeeded;
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
    o_para_num = 5;
    o_funchash = 0x084946FC8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySecurityPolicy(ULONG_PTR UnknownParameter1, ULONG_PTR UnknownParameter2, ULONG_PTR UnknownParameter3, ULONG_PTR UnknownParameter4, ULONG_PTR UnknownParameter5, ULONG_PTR UnknownParameter6) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = (ULONG_PTR)UnknownParameter3;
    o_para4 = (ULONG_PTR)UnknownParameter4;
    o_para5 = (ULONG_PTR)UnknownParameter5;
    o_para6 = (ULONG_PTR)UnknownParameter6;
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
    o_para_num = 6;
    o_funchash = 0x032A80517;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySemaphore(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)SemaphoreInformationClass;
    o_para3 = (ULONG_PTR)SemaphoreInformation;
    o_para4 = (ULONG_PTR)SemaphoreInformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0565A40E2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)LinkTarget;
    o_para3 = (ULONG_PTR)ReturnedLength;
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
    o_para_num = 3;
    o_funchash = 0x0369B0039;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PVOID VariableValue, ULONG ValueLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)VariableValue;
    o_para3 = (ULONG_PTR)ValueLength;
    o_para4 = (ULONG_PTR)ReturnLength;
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
    o_funchash = 0x0CE2CEFE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)VendorGuid;
    o_para3 = (ULONG_PTR)Value;
    o_para4 = (ULONG_PTR)ValueLength;
    o_para5 = (ULONG_PTR)Attributes;
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
    o_para_num = 5;
    o_funchash = 0x021CAEC8F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass;
    o_para2 = (ULONG_PTR)InputBuffer;
    o_para3 = (ULONG_PTR)InputBufferLength;
    o_para4 = (ULONG_PTR)SystemInformation;
    o_para5 = (ULONG_PTR)SystemInformationLength;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x08093DE55;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime) {
    o_para1 = (ULONG_PTR)MaximumTime;
    o_para2 = (ULONG_PTR)MinimumTime;
    o_para3 = (ULONG_PTR)CurrentTime;
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
    o_para_num = 3;
    o_funchash = 0x082181C15;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryWnfStateData(PCWNF_STATE_NAME StateName, PCWNF_TYPE_ID TypeId, PVOID ExplicitScope, PWNF_CHANGE_STAMP ChangeStamp, PVOID Buffer, PULONG BufferSize) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)TypeId;
    o_para3 = (ULONG_PTR)ExplicitScope;
    o_para4 = (ULONG_PTR)ChangeStamp;
    o_para5 = (ULONG_PTR)Buffer;
    o_para6 = (ULONG_PTR)BufferSize;
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
    o_para_num = 6;
    o_funchash = 0x0240B70C0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryWnfStateNameInformation(PCWNF_STATE_NAME StateName, PCWNF_TYPE_ID NameInfoClass, PVOID ExplicitScope, PVOID InfoBuffer, ULONG InfoBufferSize) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)NameInfoClass;
    o_para3 = (ULONG_PTR)ExplicitScope;
    o_para4 = (ULONG_PTR)InfoBuffer;
    o_para5 = (ULONG_PTR)InfoBufferSize;
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
    o_para_num = 5;
    o_funchash = 0x0128BF1DB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)UserApcReserveHandle;
    o_para3 = (ULONG_PTR)ApcRoutine;
    o_para4 = (ULONG_PTR)ApcArgument1;
    o_para5 = (ULONG_PTR)ApcArgument2;
    o_para6 = (ULONG_PTR)ApcArgument3;
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
    o_para_num = 6;
    o_funchash = 0x098A7C641;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOLEAN FirstChance) {
    o_para1 = (ULONG_PTR)ExceptionRecord;
    o_para2 = (ULONG_PTR)ContextRecord;
    o_para3 = (ULONG_PTR)FirstChance;
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
    o_para_num = 3;
    o_funchash = 0x017425269;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response) {
    o_para1 = (ULONG_PTR)ErrorStatus;
    o_para2 = (ULONG_PTR)NumberOfParameters;
    o_para3 = (ULONG_PTR)UnicodeStringParameterMask;
    o_para4 = (ULONG_PTR)Parameters;
    o_para5 = (ULONG_PTR)ValidResponseOptions;
    o_para6 = (ULONG_PTR)Response;
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
    o_para_num = 6;
    o_funchash = 0x0BFEF9F5D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadOnlyEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x00998120F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverEnlistment(HANDLE EnlistmentHandle, PVOID EnlistmentKey) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)EnlistmentKey;
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
    o_funchash = 0x00BE50A6F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverResourceManager(HANDLE ResourceManagerHandle) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
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
    o_funchash = 0x0F1E72CAF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverTransactionManager(HANDLE TransactionManagerHandle) {
    o_para1 = (ULONG_PTR)TransactionManagerHandle;
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
    o_funchash = 0x01A20822A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRegisterProtocolAddressInformation(HANDLE ResourceManager, LPGUID ProtocolId, ULONG ProtocolInformationSize, PVOID ProtocolInformation, ULONG CreateOptions) {
    o_para1 = (ULONG_PTR)ResourceManager;
    o_para2 = (ULONG_PTR)ProtocolId;
    o_para3 = (ULONG_PTR)ProtocolInformationSize;
    o_para4 = (ULONG_PTR)ProtocolInformation;
    o_para5 = (ULONG_PTR)CreateOptions;
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
    o_para_num = 5;
    o_funchash = 0x00E99C3CA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRegisterThreadTerminatePort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
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
    o_funchash = 0x02EB2C4EC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseKeyedEvent(HANDLE KeyedEventHandle, PVOID KeyValue, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)KeyValue;
    o_para3 = (ULONG_PTR)Alertable;
    o_para4 = (ULONG_PTR)Timeout;
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
    o_funchash = 0x0B8155B82;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseWorkerFactoryWorker(HANDLE WorkerFactoryHandle) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
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
    o_funchash = 0x0FC49D291;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRemoveIoCompletionEx(HANDLE IoCompletionHandle, PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation, ULONG Count, PULONG NumEntriesRemoved, PLARGE_INTEGER Timeout, BOOLEAN Alertable) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)IoCompletionInformation;
    o_para3 = (ULONG_PTR)Count;
    o_para4 = (ULONG_PTR)NumEntriesRemoved;
    o_para5 = (ULONG_PTR)Timeout;
    o_para6 = (ULONG_PTR)Alertable;
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
    o_para_num = 6;
    o_funchash = 0x0C290F02A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DebugObjectHandle;
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
    o_funchash = 0x000A6112E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)NewName;
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
    o_funchash = 0x08EEEA54C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRenameTransactionManager(PUNICODE_STRING LogFileName, LPGUID ExistingTransactionManagerGuid) {
    o_para1 = (ULONG_PTR)LogFileName;
    o_para2 = (ULONG_PTR)ExistingTransactionManagerGuid;
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
    o_funchash = 0x083B75B9D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplaceKey(POBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, POBJECT_ATTRIBUTES OldFile) {
    o_para1 = (ULONG_PTR)NewFile;
    o_para2 = (ULONG_PTR)TargetHandle;
    o_para3 = (ULONG_PTR)OldFile;
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
    o_para_num = 3;
    o_funchash = 0x066C48BA0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplacePartitionUnit(PUNICODE_STRING TargetInstancePath, PUNICODE_STRING SpareInstancePath, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetInstancePath;
    o_para2 = (ULONG_PTR)SpareInstancePath;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x0287B0CEC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ReplyMessage;
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
    o_funchash = 0x0A63493AA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)RequestMessage;
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
    o_funchash = 0x02CB6292C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResetEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
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
    o_funchash = 0x0C84ED1C0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
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
    o_para_num = 3;
    o_funchash = 0x0F5780E2A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRestoreKey(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x0C942F2F0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResumeProcess(HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
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
    o_funchash = 0x0F63BD7A7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRevertContainerImpersonation() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0DE49DEDF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x08921182D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x031B9F6EA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)Wait;
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
    o_funchash = 0x0C4D5E241;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Wait;
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
    o_funchash = 0x0C8920FC2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollforwardTransactionManager(HANDLE TransactionManagerHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)TransactionManagerHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x0CB93D238;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
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
    o_funchash = 0x0E720CC82;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
    o_para3 = (ULONG_PTR)Format;
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
    o_para_num = 3;
    o_funchash = 0x029A2D6C5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveMergedKeys(HANDLE HighPrecedenceKeyHandle, HANDLE LowPrecedenceKeyHandle, HANDLE FileHandle) {
    o_para1 = (ULONG_PTR)HighPrecedenceKeyHandle;
    o_para2 = (ULONG_PTR)LowPrecedenceKeyHandle;
    o_para3 = (ULONG_PTR)FileHandle;
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
    o_para_num = 3;
    o_funchash = 0x055B56E3E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSecureConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_SECTION_WRITE ClientView, PSID RequiredServerSid, PPORT_SECTION_READ ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortName;
    o_para3 = (ULONG_PTR)SecurityQos;
    o_para4 = (ULONG_PTR)ClientView;
    o_para5 = (ULONG_PTR)RequiredServerSid;
    o_para6 = (ULONG_PTR)ServerView;
    o_para7 = (ULONG_PTR)MaxMessageLength;
    o_para8 = (ULONG_PTR)ConnectionInformation;
    o_para9 = (ULONG_PTR)ConnectionInformationLength;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x018B11B3E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSerializeBoot() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x032E2583D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetBootEntryOrder(PULONG Ids, ULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
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
    o_funchash = 0x00B91070B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetBootOptions(PBOOT_OPTIONS BootOptions, ULONG FieldsToChange) {
    o_para1 = (ULONG_PTR)BootOptions;
    o_para2 = (ULONG_PTR)FieldsToChange;
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
    o_funchash = 0x0099D0F0D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetCachedSigningLevel(ULONG Flags, SE_SIGNING_LEVEL InputSigningLevel, PHANDLE SourceFiles, ULONG SourceFileCount, HANDLE TargetFile) {
    o_para1 = (ULONG_PTR)Flags;
    o_para2 = (ULONG_PTR)InputSigningLevel;
    o_para3 = (ULONG_PTR)SourceFiles;
    o_para4 = (ULONG_PTR)SourceFileCount;
    o_para5 = (ULONG_PTR)TargetFile;
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
    o_para_num = 5;
    o_funchash = 0x0A8FBFC44;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetCachedSigningLevel2(ULONG Flags, ULONG InputSigningLevel, PHANDLE SourceFiles, ULONG SourceFileCount, HANDLE TargetFile, PVOID LevelInformation) {
    o_para1 = (ULONG_PTR)Flags;
    o_para2 = (ULONG_PTR)InputSigningLevel;
    o_para3 = (ULONG_PTR)SourceFiles;
    o_para4 = (ULONG_PTR)SourceFileCount;
    o_para5 = (ULONG_PTR)TargetFile;
    o_para6 = (ULONG_PTR)LevelInformation;
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
    o_para_num = 6;
    o_funchash = 0x0EC537584;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)Context;
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
    o_funchash = 0x034ACCEBA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State) {
    o_para1 = (ULONG_PTR)ComponentId;
    o_para2 = (ULONG_PTR)Level;
    o_para3 = (ULONG_PTR)State;
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
    o_para_num = 3;
    o_funchash = 0x06AD45B8A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultHardErrorPort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
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
    o_funchash = 0x0DA8FCF2F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultLocale(BOOLEAN UserProfile, LCID DefaultLocaleId) {
    o_para1 = (ULONG_PTR)UserProfile;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
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
    o_funchash = 0x0E32A91FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultUILanguage(LANGID DefaultUILanguageId) {
    o_para1 = (ULONG_PTR)DefaultUILanguageId;
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
    o_funchash = 0x0538D6058;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDriverEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
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
    o_funchash = 0x01FAC3F1F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION EaBuffer, ULONG EaBufferSize) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)EaBuffer;
    o_para4 = (ULONG_PTR)EaBufferSize;
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
    o_funchash = 0x066FB8BB2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetHighEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
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
    o_funchash = 0x0B60EAE87;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetHighWaitLowEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
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
    o_funchash = 0x00049209F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIRTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DueTime;
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
    o_funchash = 0x0D98CD318;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationDebugObject(HANDLE DebugObject, DEBUGOBJECTINFOCLASS InformationClass, PVOID Information, ULONG InformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)DebugObject;
    o_para2 = (ULONG_PTR)InformationClass;
    o_para3 = (ULONG_PTR)Information;
    o_para4 = (ULONG_PTR)InformationLength;
    o_para5 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 5;
    o_funchash = 0x0FCDE0F92;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)EnlistmentInformationClass;
    o_para3 = (ULONG_PTR)EnlistmentInformation;
    o_para4 = (ULONG_PTR)EnlistmentInformationLength;
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
    o_funchash = 0x0B921BCB7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)JobObjectInformationClass;
    o_para3 = (ULONG_PTR)JobObjectInformation;
    o_para4 = (ULONG_PTR)JobObjectInformationLength;
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
    o_funchash = 0x082B9AA05;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeySetInformationClass, PVOID KeySetInformation, ULONG KeySetInformationLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)KeySetInformationClass;
    o_para3 = (ULONG_PTR)KeySetInformation;
    o_para4 = (ULONG_PTR)KeySetInformationLength;
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
    o_funchash = 0x00396223D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)ResourceManagerInformationClass;
    o_para3 = (ULONG_PTR)ResourceManagerInformation;
    o_para4 = (ULONG_PTR)ResourceManagerInformationLength;
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
    o_funchash = 0x0B3A6ED6D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationSymbolicLink(HANDLE Handle, ULONG Class, PVOID Buffer, ULONG BufferLength) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)Class;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)BufferLength;
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
    o_funchash = 0x060FB6C62;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)TokenInformationClass;
    o_para3 = (ULONG_PTR)TokenInformation;
    o_para4 = (ULONG_PTR)TokenInformationLength;
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
    o_funchash = 0x031AD0D02;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationTransaction(HANDLE TransactionHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TransactionInformationClass;
    o_para3 = (ULONG_PTR)TransactionInformation;
    o_para4 = (ULONG_PTR)TransactionInformationLength;
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
    o_funchash = 0x07EB97025;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationTransactionManager(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TransactionInformationClass;
    o_para3 = (ULONG_PTR)TransactionInformation;
    o_para4 = (ULONG_PTR)TransactionInformationLength;
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
    o_funchash = 0x083B29512;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationVirtualMemory(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, ULONG_PTR NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)VmInformationClass;
    o_para3 = (ULONG_PTR)NumberOfEntries;
    o_para4 = (ULONG_PTR)VirtualAddresses;
    o_para5 = (ULONG_PTR)VmInformation;
    o_para6 = (ULONG_PTR)VmInformationLength;
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
    o_para_num = 6;
    o_funchash = 0x0DD96C91B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)WorkerFactoryInformationClass;
    o_para3 = (ULONG_PTR)WorkerFactoryInformation;
    o_para4 = (ULONG_PTR)WorkerFactoryInformationLength;
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
    o_funchash = 0x081139A71;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source) {
    o_para1 = (ULONG_PTR)Interval;
    o_para2 = (ULONG_PTR)Source;
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
    o_funchash = 0x0429A5426;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIoCompletion(HANDLE IoCompletionHandle, ULONG CompletionKey, PIO_STATUS_BLOCK IoStatusBlock, NTSTATUS CompletionStatus, ULONG NumberOfBytesTransfered) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)CompletionKey;
    o_para3 = (ULONG_PTR)IoStatusBlock;
    o_para4 = (ULONG_PTR)CompletionStatus;
    o_para5 = (ULONG_PTR)NumberOfBytesTransfered;
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
    o_para_num = 5;
    o_funchash = 0x04C946FC5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIoCompletionEx(HANDLE IoCompletionHandle, HANDLE IoCompletionPacketHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)IoCompletionPacketHandle;
    o_para3 = (ULONG_PTR)KeyContext;
    o_para4 = (ULONG_PTR)ApcContext;
    o_para5 = (ULONG_PTR)IoStatus;
    o_para6 = (ULONG_PTR)IoStatusInformation;
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
    o_para_num = 6;
    o_funchash = 0x0A3517E35;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetLdtEntries(ULONG Selector0, ULONG Entry0Low, ULONG Entry0Hi, ULONG Selector1, ULONG Entry1Low, ULONG Entry1Hi) {
    o_para1 = (ULONG_PTR)Selector0;
    o_para2 = (ULONG_PTR)Entry0Low;
    o_para3 = (ULONG_PTR)Entry0Hi;
    o_para4 = (ULONG_PTR)Selector1;
    o_para5 = (ULONG_PTR)Entry1Low;
    o_para6 = (ULONG_PTR)Entry1Hi;
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
    o_para_num = 6;
    o_funchash = 0x006A2537D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetLowEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
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
    o_funchash = 0x082D28C42;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetLowWaitHighEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
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
    o_funchash = 0x010B43821;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG Length) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)Length;
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
    o_funchash = 0x0F0DB299A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSecurityObject(HANDLE ObjectHandle, SECURITY_INFORMATION SecurityInformationClass, PSECURITY_DESCRIPTOR DescriptorBuffer) {
    o_para1 = (ULONG_PTR)ObjectHandle;
    o_para2 = (ULONG_PTR)SecurityInformationClass;
    o_para3 = (ULONG_PTR)DescriptorBuffer;
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
    o_para_num = 3;
    o_funchash = 0x0FC61040D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemEnvironmentValue(PUNICODE_STRING VariableName, PUNICODE_STRING Value) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)Value;
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
    o_funchash = 0x03EAD211A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)VendorGuid;
    o_para3 = (ULONG_PTR)Value;
    o_para4 = (ULONG_PTR)ValueLength;
    o_para5 = (ULONG_PTR)Attributes;
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
    o_para_num = 5;
    o_funchash = 0x08FB6DB6A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass;
    o_para2 = (ULONG_PTR)SystemInformation;
    o_para3 = (ULONG_PTR)SystemInformationLength;
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
    o_para_num = 3;
    o_funchash = 0x034AA1FFF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemPowerState(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags) {
    o_para1 = (ULONG_PTR)SystemAction;
    o_para2 = (ULONG_PTR)MinSystemState;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x0E634067E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER PreviousTime) {
    o_para1 = (ULONG_PTR)SystemTime;
    o_para2 = (ULONG_PTR)PreviousTime;
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
    o_funchash = 0x0AA82A723;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetThreadExecutionState(EXECUTION_STATE ExecutionState, PEXECUTION_STATE PreviousExecutionState) {
    o_para1 = (ULONG_PTR)ExecutionState;
    o_para2 = (ULONG_PTR)PreviousExecutionState;
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
    o_funchash = 0x0523340BC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DueTime;
    o_para3 = (ULONG_PTR)Period;
    o_para4 = (ULONG_PTR)Parameters;
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
    o_funchash = 0x00995C99B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimerEx(HANDLE TimerHandle, TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, PVOID TimerSetInformation, ULONG TimerSetInformationLength) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)TimerSetInformationClass;
    o_para3 = (ULONG_PTR)TimerSetInformation;
    o_para4 = (ULONG_PTR)TimerSetInformationLength;
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
    o_funchash = 0x08E9BD439;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimerResolution(ULONG DesiredResolution, BOOLEAN SetResolution, PULONG CurrentResolution) {
    o_para1 = (ULONG_PTR)DesiredResolution;
    o_para2 = (ULONG_PTR)SetResolution;
    o_para3 = (ULONG_PTR)CurrentResolution;
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
    o_para_num = 3;
    o_funchash = 0x0DEB4DE27;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetUuidSeed(PUCHAR Seed) {
    o_para1 = (ULONG_PTR)Seed;
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
    o_funchash = 0x0A39DA930;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileSystemInformation, ULONG Length, FSINFOCLASS FileSystemInformationClass) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)FileSystemInformation;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)FileSystemInformationClass;
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
    o_para_num = 5;
    o_funchash = 0x0DFC49515;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetWnfProcessNotificationEvent(HANDLE NotificationEvent) {
    o_para1 = (ULONG_PTR)NotificationEvent;
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
    o_funchash = 0x018823522;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtShutdownSystem(SHUTDOWN_ACTION Action) {
    o_para1 = (ULONG_PTR)Action;
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
    o_funchash = 0x0A29FA903;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtShutdownWorkerFactory(HANDLE WorkerFactoryHandle, PLONG PendingWorkerCount) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)PendingWorkerCount;
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
    o_funchash = 0x04094742A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSignalAndWaitForSingleObject(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn, BOOLEAN bAlertable, PLARGE_INTEGER dwMilliseconds) {
    o_para1 = (ULONG_PTR)hObjectToSignal;
    o_para2 = (ULONG_PTR)hObjectToWaitOn;
    o_para3 = (ULONG_PTR)bAlertable;
    o_para4 = (ULONG_PTR)dwMilliseconds;
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
    o_funchash = 0x02E9D2600;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSinglePhaseReject(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x0644042DD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStartProfile(HANDLE ProfileHandle) {
    o_para1 = (ULONG_PTR)ProfileHandle;
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
    o_funchash = 0x00EBCD28A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStopProfile(HANDLE ProfileHandle) {
    o_para1 = (ULONG_PTR)ProfileHandle;
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
    o_funchash = 0x0871C595D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSubscribeWnfStateChange(PCWNF_STATE_NAME StateName, WNF_CHANGE_STAMP ChangeStamp, ULONG EventMask, PLARGE_INTEGER SubscriptionId) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)ChangeStamp;
    o_para3 = (ULONG_PTR)EventMask;
    o_para4 = (ULONG_PTR)SubscriptionId;
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
    o_funchash = 0x0229B1B46;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSuspendProcess(HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
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
    o_funchash = 0x05D847E28;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
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
    o_funchash = 0x0D3488D72;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSystemDebugControl(DEBUG_CONTROL_CODE Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)Command;
    o_para2 = (ULONG_PTR)InputBuffer;
    o_para3 = (ULONG_PTR)InputBufferLength;
    o_para4 = (ULONG_PTR)OutputBuffer;
    o_para5 = (ULONG_PTR)OutputBufferLength;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x007D40743;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateEnclave(PVOID BaseAddress, BOOLEAN WaitForThread) {
    o_para1 = (ULONG_PTR)BaseAddress;
    o_para2 = (ULONG_PTR)WaitForThread;
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
    o_funchash = 0x02D5A584A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)JobHandle;
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
    o_funchash = 0x0AA49E699;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTestAlert() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0049E0314;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtThawRegistry() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x01C8D263D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtThawTransactions() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x06428BE7E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTraceControl(ULONG FunctionCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)FunctionCode;
    o_para2 = (ULONG_PTR)InputBuffer;
    o_para3 = (ULONG_PTR)InputBufferLength;
    o_para4 = (ULONG_PTR)OutputBuffer;
    o_para5 = (ULONG_PTR)OutputBufferLength;
    o_para6 = (ULONG_PTR)ReturnLength;
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
    o_para_num = 6;
    o_funchash = 0x007906F13;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, PULONG OutputFilePathLength) {
    o_para1 = (ULONG_PTR)InputFilePath;
    o_para2 = (ULONG_PTR)OutputType;
    o_para3 = (ULONG_PTR)OutputFilePath;
    o_para4 = (ULONG_PTR)OutputFilePathLength;
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
    o_funchash = 0x088D06C9C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUmsThreadYield(PVOID SchedulerParam) {
    o_para1 = (ULONG_PTR)SchedulerParam;
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
    o_funchash = 0x0E1BE310A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadDriver(PUNICODE_STRING DriverServiceName) {
    o_para1 = (ULONG_PTR)DriverServiceName;
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
    o_funchash = 0x03499263A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    o_para1 = (ULONG_PTR)DestinationKeyName;
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
    o_funchash = 0x0D8FCAF00;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKey2(POBJECT_ATTRIBUTES TargetKey, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)Flags;
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
    o_funchash = 0x0D824240B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKeyEx(POBJECT_ATTRIBUTES TargetKey, HANDLE Event) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)Event;
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
    o_funchash = 0x0F7FDB938;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER ByteOffset, PULARGE_INTEGER Length, ULONG Key) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)ByteOffset;
    o_para4 = (ULONG_PTR)Length;
    o_para5 = (ULONG_PTR)Key;
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
    o_para_num = 5;
    o_funchash = 0x0BD60ABDD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToUnlock, ULONG LockType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)NumberOfBytesToUnlock;
    o_para4 = (ULONG_PTR)LockType;
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
    o_funchash = 0x0171E1391;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnmapViewOfSectionEx(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Flags;
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
    o_para_num = 3;
    o_funchash = 0x05EA5ADDF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnsubscribeWnfStateChange(PCWNF_STATE_NAME StateName) {
    o_para1 = (ULONG_PTR)StateName;
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
    o_funchash = 0x062BF2362;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUpdateWnfStateData(PCWNF_STATE_NAME StateName, PVOID Buffer, ULONG Length, PCWNF_TYPE_ID TypeId, PVOID ExplicitScope, WNF_CHANGE_STAMP MatchingChangeStamp, ULONG CheckStamp) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)Buffer;
    o_para3 = (ULONG_PTR)Length;
    o_para4 = (ULONG_PTR)TypeId;
    o_para5 = (ULONG_PTR)ExplicitScope;
    o_para6 = (ULONG_PTR)MatchingChangeStamp;
    o_para7 = (ULONG_PTR)CheckStamp;
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
    o_para_num = 7;
    o_funchash = 0x0DD82F34F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtVdmControl(VDMSERVICECLASS Service, PVOID ServiceData) {
    o_para1 = (ULONG_PTR)Service;
    o_para2 = (ULONG_PTR)ServiceData;
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
    o_funchash = 0x0379A2D3C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForAlertByThreadId(HANDLE Handle, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)Timeout;
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
    o_funchash = 0x048B7084A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PVOID WaitStateChange) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)Alertable;
    o_para3 = (ULONG_PTR)Timeout;
    o_para4 = (ULONG_PTR)WaitStateChange;
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
    o_funchash = 0x0F269CFC8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForKeyedEvent(HANDLE KeyedEventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)Key;
    o_para3 = (ULONG_PTR)Alertable;
    o_para4 = (ULONG_PTR)Timeout;
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
    o_funchash = 0x078481DD0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForWorkViaWorkerFactory(HANDLE WorkerFactoryHandle, PVOID MiniPacket) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)MiniPacket;
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
    o_funchash = 0x04ED96678;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitHighEventPair(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
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
    o_funchash = 0x010B0302D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitLowEventPair(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
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
    o_funchash = 0x023374A20;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAcquireCMFViewOwnership(BOOLEAN TimeStamp, BOOLEAN TokenTaken, BOOLEAN ReplaceExisting) {
    o_para1 = (ULONG_PTR)TimeStamp;
    o_para2 = (ULONG_PTR)TokenTaken;
    o_para3 = (ULONG_PTR)ReplaceExisting;
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
    o_para_num = 3;
    o_funchash = 0x062D6185C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelDeviceWakeupRequest(HANDLE DeviceHandle) {
    o_para1 = (ULONG_PTR)DeviceHandle;
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
    o_funchash = 0x093DD9250;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearAllSavepointsTransaction(HANDLE TransactionHandle) {
    o_para1 = (ULONG_PTR)TransactionHandle;
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
    o_funchash = 0x034AC3A31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)SavePointId;
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
    o_funchash = 0x097409BDA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)SavePointId;
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
    o_funchash = 0x00049DEF9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSavepointTransaction(HANDLE TransactionHandle, BOOLEAN Flag, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Flag;
    o_para3 = (ULONG_PTR)SavePointId;
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
    o_para_num = 3;
    o_funchash = 0x0DE48C2D9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSavepointComplete(HANDLE TransactionHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
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
    o_funchash = 0x094CB8240;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateSectionEx(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParametersCount) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)MaximumSize;
    o_para5 = (ULONG_PTR)SectionPageProtection;
    o_para6 = (ULONG_PTR)AllocationAttributes;
    o_para7 = (ULONG_PTR)FileHandle;
    o_para8 = (ULONG_PTR)ExtendedParameters;
    o_para9 = (ULONG_PTR)ExtendedParametersCount;
    o_para10 = 0;
    o_para11 = 0;
    o_para12 = 0;
    o_para13 = 0;
    o_para14 = 0;
    o_para15 = 0;
    o_para16 = 0;
    o_para17 = 0;
    o_para_num = 9;
    o_funchash = 0x0BE94C062;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateCrossVmEvent() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0F055351C;
    GetSystemTime(1);
    return 0;
}

/*NTSTATUS SFNtGetPlugPlayEvent(HANDLE EventHandle, PVOID Context, PPLUGPLAY_EVENT_BLOCK EventBlock, ULONG EventBufferSize) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)Context;
    o_para3 = (ULONG_PTR)EventBlock;
    o_para4 = (ULONG_PTR)EventBufferSize;
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
    o_funchash = 0x0D14BDCCA;
    GetSystemTime(1);
    return 0;
}*/

NTSTATUS SFNtListTransactions() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x00556C30D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMarshallTransaction() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x080CA479A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPullTransaction() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x09C0BBE9B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseCMFViewOwnership() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x04E952A7E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForWnfNotifications() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0078B2F11;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStartTm() {
    o_para1 = 0;
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
    o_para_num = 0;
    o_funchash = 0x0874BBDE4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationProcess(HANDLE DeviceHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG Length) {
    o_para1 = (ULONG_PTR)DeviceHandle;
    o_para2 = (ULONG_PTR)ProcessInformationClass;
    o_para3 = (ULONG_PTR)ProcessInformation;
    o_para4 = (ULONG_PTR)Length;
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
    o_funchash = 0x0639C7A30;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestDeviceWakeup(HANDLE DeviceHandle) {
    o_para1 = (ULONG_PTR)DeviceHandle;
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
    o_funchash = 0x005973536;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestWakeupLatency(ULONG LatencyTime) {
    o_para1 = (ULONG_PTR)LatencyTime;
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
    o_funchash = 0x08804A7A0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemTime(PLARGE_INTEGER SystemTime) {
    o_para1 = (ULONG_PTR)SystemTime;
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
    o_funchash = 0x09A0F97AF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtManageHotPatch(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = (ULONG_PTR)UnknownParameter3;
    o_para4 = (ULONG_PTR)UnknownParameter4;
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
    o_funchash = 0x0FC4230E6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtContinueEx(PCONTEXT ContextRecord, PKCONTINUE_ARGUMENT ContinueArgument) {
    o_para1 = (ULONG_PTR)ContextRecord;
    o_para2 = (ULONG_PTR)ContinueArgument;
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
    o_funchash = 0x0F360C6DD;
    GetSystemTime(1);
    return 0;
}
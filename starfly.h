#include <windows.h>

/*========================================
 以下是飞星的相关定义和声明
========================================*/
extern DWORD_PTR o_para1; // 向寄存器传递的四个参数
extern DWORD_PTR o_para2;
extern DWORD_PTR o_para3;
extern DWORD_PTR o_para4;
extern DWORD o_funchash; // 函数哈希




/*========================================
 以下是Windows的相关定义和声明
========================================*/
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef int KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

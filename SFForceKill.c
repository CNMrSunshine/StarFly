#include <stdio.h>
#include <Windows.h>
#include "nt.h"
#include <locale.h>
#include "starfly.h"
HANDLE hProcess;
LPVOID pDllAddr = NULL;
SIZE_T dwSize = 0;
DWORD tpid = 0;
char* DllPath;
UNICODE_STRING imageName; // 未知原因 UNICODE_STRING不放在全局变量 会被下一个UNICODE_STRING覆写
UNICODE_STRING dosPath;
extern BOOL CheckProcess(DWORD pid, DWORD mode);
void SFForceKill(DWORD pid) {
    setlocale(LC_ALL, "");
    SFPrintStatus("Querying Image NT Path.", "正在查询映像NT路径");
    ULONG returnLength;
    imageName.Buffer = NULL;
    status = SFNtQueryInformationProcess(GetCurrentProcess(), ProcessImageFileName, &imageName, 0, &returnLength);
    imageName.Buffer = (PWSTR)malloc(returnLength);
    imageName.MaximumLength = (USHORT)returnLength;
    imageName.Length = (USHORT)returnLength;
    status = SFNtQueryInformationProcess(GetCurrentProcess(), ProcessImageFileName, &imageName, returnLength, &returnLength);
    dosPath.Buffer = NULL;
    dosPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
    PWSTR filePart;
    status = RtlDosPathNameToNtPathName_U(imageName.Buffer, &dosPath, &filePart, NULL);
    SFPrintStatus("Calculating Image DOS Path.", "正在计算映像DOS路径");
    WCHAR volume[8];
    wcsncpy_s(volume, 8, dosPath.Buffer, 7);
    dosPath.Buffer = dosPath.Buffer + 30;
    size_t len1 = wcslen(volume);
    size_t len2 = wcslen(dosPath.Buffer);
    size_t total_len = len1 + len2;
    wchar_t* realPath = (wchar_t*)malloc((total_len + 1) * sizeof(wchar_t));
    wcscpy_s(realPath, total_len + 1, volume);
    wcscat_s(realPath, total_len + 1, dosPath.Buffer);
    realPath = realPath + 4;
    size_t realPathLen;
    wcstombs_s(&realPathLen, NULL, 0, realPath, _TRUNCATE);
    realPathLen += 1;
    DllPath = (char*)malloc(realPathLen);
    wcstombs_s(&realPathLen, DllPath, realPathLen, realPath, _TRUNCATE);
    size_t DllPathLen = strlen(DllPath);
    DllPath[DllPathLen - 3] = 'd';
    DllPath[DllPathLen - 2] = 'l';
    DllPath[DllPathLen - 1] = 'l';
    if (!CheckProcess(pid, 1)) {
        SFPrintError("Target Not Found.", "未找到目标");
        return;
    }
    tpid = pid;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread = 0;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    status = SFNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    dwSize = 1 + strlen(DllPath);
    o_mode = 10;
    status = SFNtAllocateVirtualMemory(hProcess, &pDllAddr, 0, &dwSize, MEM_COMMIT, PAGE_READWRITE);
}

void ForceKillErrorHandler() {
    if (o_mode == 10) {
        o_mode = 0;
        SIZE_T bytesWritten = 0;
        status = SFNtWriteVirtualMemory(hProcess, pDllAddr, (PVOID)DllPath, dwSize, &bytesWritten);
        if (bytesWritten != dwSize) {
            SFPrintError("Failed to Write Virtual Memory.", "写入虚拟内存失败");
            SFNtFreeVirtualMemory(hProcess, &pDllAddr, &dwSize, MEM_RELEASE);
            SFNtClose(hProcess);
            o_restart = 1;
            main();
        }
        LPVOID kernel32Base = NULL;
        UNICODE_STRING moduleName;
        RtlInitUnicodeString(&moduleName, L"kernel32.dll");
        status = LdrGetDllHandle(hProcess, NULL, &moduleName, &kernel32Base);
        PVOID pfnLoadLibraryA = NULL;
        ANSI_STRING functionName;
        RtlInitAnsiString(&functionName, "LoadLibraryA");
        status = LdrGetProcedureAddress(kernel32Base, &functionName, 0, &pfnLoadLibraryA);
        HANDLE hThread = NULL;
        o_mode = 11;
        status = SFNtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, pfnLoadLibraryA, pDllAddr, 0, 0, 0, 0, NULL);
    }
    else {
        if (CheckProcess(tpid, 0)) {
            SFPrintSuccess("Confirmed that the Targeted Process has Died.", "已确认目标进程死亡");
        }
        else {
            SFPrintError("Failed to Terminate the Targeted Process.", "终止目标进程失败");
        }
        o_restart = 1;
        main();
    }
}
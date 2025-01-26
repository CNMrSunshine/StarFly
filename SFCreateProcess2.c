/*#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "starfly.h"
HANDLE hProcess = NULL;
HANDLE hThread = NULL;
HANDLE hFile = NULL;
HANDLE hSection = NULL;
PVOID baseAddress = NULL;
void SFOpenCMD()
{
    HANDLE hParent = GetCurrentProcess();
    o_mode = 3;
    // 创建空进程
    status = SFNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent, 0, NULL, NULL, NULL, FALSE);
}
void OpenCMDErrorHandler() {
    if (o_mode == 3){
        // 打开cmd.exe
        hFile = CreateFileA("C:\\Windows\\System32\\cmd.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != NULL) {
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = 0;
    o_mode = 4;
    // 保存cmd.exe镜像
    status = SFNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    }
    CloseHandle(hThread);
    CloseHandle(hProcess);
} else if (o_mode == 4) {
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionOffset;
    sectionOffset.QuadPart = 0;
    o_mode = 5;
    // 加载cmd.exe到目标进程内存
    status = SFNtMapViewOfSection(
        hSection,
        hProcess,
        &baseAddress,
        0,
        0,
        &sectionOffset,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );
} else if (o_mode == 5) {
    // 解析PE头 找到入口点
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    // 读取DOS头
    NTSTATUS status = SFNtReadVirtualMemory(
        hProcess,
        baseAddress,
        &dosHeader,
        sizeof(dosHeader),
        &bytesRead
    );
    IMAGE_NT_HEADERS64 ntHeaders;
    LPVOID ntHeaderAddress = (LPVOID)((BYTE*)baseAddress + dosHeader.e_lfanew);
    // 读取NT头
    status = SFNtReadVirtualMemory(
        hProcess,
        ntHeaderAddress,
        &ntHeaders,
        sizeof(ntHeaders),
        &bytesRead
    );
    DWORD_PTR entryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
    DWORD_PTR entryPointVA = (DWORD_PTR)baseAddress + entryPointRVA;
    o_mode = 6;
    status = SFNtCreateThreadEx( //未知原因 启动线程失败
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)entryPointVA,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
} else if (o_mode == 6) {
    SFPrintSuccess("Success.", "Success.")
    o_restart = 1;
    main();
}
}*/
#include <windows.h>
#include <stdio.h>
#include "nt.h"
#include "starfly.h"

HANDLE hProcess;
HANDLE hThread;
HANDLE hFile = NULL;
HANDLE hSection = NULL;
PVOID baseAddress = NULL;
void SFOpenCMD2()
{
            // 打开cmd.exe
        hFile = CreateFileA("C:\\Windows\\System32\\cmd.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = 0;
    o_mode = 7;
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
void OpenCMD2ErrorHandler() {
    if (o_mode == 7){
          o_mode = 8;
    // 创建空进程
    status = SFNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

} else if (o_mode == 8) {
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionOffset;
    sectionOffset.QuadPart = 0;
    ULONG returnLength = 0;
    PROCESS_BASIC_INFORMATION pi = { 0 };
    status = SFNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    PEB peb_copy = { 0 };
    memset(&peb_copy, 0, sizeof(PEB));
    PPEB remote_peb_addr = pi.PebBaseAddress;
    status = SFNtReadVirtualMemory(hProcess, remote_peb_addr, &peb_copy, sizeof(PEB), NULL);
    ULONGLONG imageBase = (ULONGLONG) peb_copy.ImageBaseAddress;
    IMAGE_DOS_HEADER dosHeader = { 0 };
    status = SFNtReadVirtualMemory(hProcess, (PVOID)imageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
    IMAGE_NT_HEADERS64 ntHeaders = { 0 };
    status = SFNtReadVirtualMemory(hProcess, (PVOID)(imageBase + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);

    // 获取入口点地址
    ULONGLONG entryPoint = imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
    o_mode = 9;
    status = SFNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        entryPoint,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
} else if (o_mode == 9) {
    SFPrintSuccess("Success.", "Success.");
    o_restart = 1;
    main();
}
}
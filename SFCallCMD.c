#include <Windows.h>
#include "starfly.h"
#include "nt.h"
#include <wchar.h>
#include <stdio.h>
/*========================================
 以下代码改编于Capt-Meelo对底层函数研究的PoC
 https://github.com/capt-meelo/NtCreateUserProcess
========================================*/
IO_STATUS_BLOCK ioStatusBlock;
DWORD lastBytesRead = 0;
char buffer[16384];
DWORD bytesRead;
HANDLE hReadPipe;
void SFCallCMD(char* command) {
    const char *exePath = "C:\\Windows\\System32\\cmd.exe";
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;
    HANDLE hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    SFPrintStatus("Configuring IPC Pipe.", "正在配置进程间通信管道");
    CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    char cmdLine[256];
    snprintf(cmdLine, sizeof(cmdLine), "C:\\Windows\\System32\\cmd.exe /c %s", command);
    if (hDupPriToken != 0xcccccccccccccccc && hDupPriToken != 0) {
	        PROCESS_INFORMATION procinfo = { 0 };
            wchar_t wCmdLine[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, cmdLine, -1, wCmdLine, MAX_PATH);
            SFPrintStatus("Launching CMD.exe", "正在启动cmd.exe");
            CreateProcessWithTokenW(hDupPriToken, LOGON_WITH_PROFILE, NULL, wCmdLine, NULL, NULL, NULL, &si, &procinfo);
            CloseHandle(hWritePipe);
            o_mode = 4;
        status = SFNtReadFile(hReadPipe, NULL, NULL, NULL, &ioStatusBlock, buffer, sizeof(buffer) - 1, NULL, NULL);
    CloseHandle(hReadPipe);
    } else {
        SFPrintError("Please Obtain a Valid Primary Token First.", "请先获取主令牌");
    }
    return;
}

void CallCMDErrorHandler() {    
        bytesRead = (DWORD)ioStatusBlock.Information;
        if (bytesRead == lastBytesRead) {
            o_mode = 0;
            SFPrintSuccess("Output Successfully Received.", "成功获取到输出信息");
             CloseHandle(hReadPipe);
             o_restart = 1;
             main();
        }
        buffer[bytesRead] = '\0';
        printf("%s", buffer);
        lastBytesRead = bytesRead;
        status = SFNtReadFile(hReadPipe, NULL, NULL, NULL, &ioStatusBlock, buffer, sizeof(buffer) - 1, NULL, NULL);
        return;
}
#include "syscalls.h"
#include "starfly.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern void StarFlyCoreStart();
extern void StarFlyCoreExit();
extern void SFGetProcessInformation(char *procname);
extern void SFLocalPrivilege();
extern void SFCreateProcess(char *exePath);
extern void SFRespawn();
extern void SFGetToken(DWORD pid);
extern void SFOpenCMD2();
extern void SFCallCMD(char* command);
extern void SFStatus();
HANDLE hFakeProcess = 0;
DWORD TokenPrivilege = 0;
DWORD FakeProcess = 0;
DWORD o_restart = 0;
void StarFlyLoadEffect(const char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    while (*str) {
        putchar(*str);
        fflush(stdout);
        Sleep(50);
        str++;
    }
    for (int i = len - 1; i >= 0; i--) {
        Sleep(10);
        printf("\b \b");
        fflush(stdout);
    }
    printf("\n");
}

void SFGetSEDebugPrivilege() {
    HANDLE hToken;
    NTSTATUS status;
    status = SFNtOpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = 0x00000014;
    tp.Privileges[0].Luid.HighPart = 0x00000000;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    o_mode = 5;
    status = SFNtAdjustPrivilegesToken(hToken, FALSE, &tp, 0, NULL, NULL);
}

int main() {
    if (o_restart == 1) {
        o_restart = 0;
        goto restart;
    }
    hFakeProcess = GetCurrentProcess(); // 初始化
    StarFlyLoadEffect("StarFly Console is Starting...");
    StarFlyCoreStart();
    printf(" .d8888. d888888b  .d8b.  d8888b. d88888b db      db    db \n");
    printf(" 88'  YP `~~88~~' d8' `8b 88  `8D 88'     88      `8b  d8' \n");
    printf(" `8bo.      88    88ooo88 88oobY' 88ooo   88       `8bd8'  \n");
    printf("   `Y8b.    88    88~~~88 88`8b   88~~~   88         88    \n");
    printf(" db   8D    88    88   88 88 `88. 88      88booo.    88    \n");
    printf(" `8888Y'    YP    YP   YP 88   YD YP      Y88888P    YP    \n");
    printf(" StarFly, call kernel via multiple Hardware Breakpoint Hook\n");
    printf(" By CN-Mr.Sunshine https://github.com/CNMrSunshine/StarFly/\n");
    printf("\n");
    char input[100];
    SFGetSEDebugPrivilege();
    restart:
    while (1) {
        printf("StarFly> ");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            input[strcspn(input, "\n")] = '\0';

            if (strncmp(input, "ps", 2) == 0) {
                char *argument = strchr(input, ' ');
                if (argument != NULL) {
                    argument++;
                    SFGetProcessInformation(argument);
                } else {
                    SFGetProcessInformation(NULL);
                }
            } else if (strncmp(input, "kill", 4) == 0) {
                char *argument = strchr(input, ' ');
                if (argument != NULL) {
                    argument++;
                    DWORD pid = atoi(argument);
                    if (pid > 0) {
                        SFKillProcess(pid);
                    } else {
                        SFPrintError("Invalid PID", "无效的PID");
                    }
                } else {
                    SFPrintError("Usage: kill <PID>", "正确语法: kill <PID>");
                }
            } else if (strcmp(input, "getsystem") == 0) {
                SFLocalPrivilege();
            } else if (strncmp(input, "steal", 5) == 0) {
                char *argument = strchr(input, ' ');
                if (argument != NULL) {
                    argument++;
                    DWORD pid = atoi(argument);
                    if (pid > 0) {
                        SFGetToken(pid);
                    } else {
                        SFPrintError("Invalid PID", "无效的PID");
                    }
                } else {
                    SFPrintError("Usage: kill <PID>", "正确语法: kill <PID>");
                }
            } else if (strcmp(input, "respawn") == 0) {
                    SFRespawn();
            } else if (strncmp(input, "run", 3) == 0){
                char *argument = strchr(input, ' ');
                if (argument != NULL) {
                    argument++;
                    SFCreateProcess(argument);
                } else {
                    SFPrintError("Missed Argument: Executable Path", "参数缺失: 可执行程序绝对路径");
                }
            } else if (strcmp(input, "cmd2") == 0) {
                SFOpenCMD2();
            } else if (strncmp(input, "cmd", 3) == 0){
                char *argument = strchr(input, ' ');
                if (argument != NULL) {
                    argument++;
                    SFCallCMD(argument);
                } else {
                    SFPrintError("Missed Argument: CMD Command", "参数缺失: CMD命令");
                }
            } else if (strcmp(input, "lang") == 0) {
                o_lang++;
            } else if (strcmp(input, "") == 0) {
                printf("\n"); // 满足某些叶片闲的没事喜欢在控制台瞎按回车的需求
            } else if (strcmp(input, "exit") == 0) {
                break;
            } else {
                if (o_lang%2 == 0){
                    printf("Unknown Command: %s\n", input);
                } else {
                    printf("未知命令: %s\n", input);
                }
            }
        }
    }
    StarFlyCoreExit();
    return 0;
}
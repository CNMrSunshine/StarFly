#include "syscalls.h"
#include "starfly.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern void StarFlyCoreStart();
extern void StarFlyCoreExit();
extern void SFGetProcessInformation();

void StarFlyLoadEffect(const char *str) {
    int len = 0;

    // 计算字符串长度
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

int main(int argc, char *argv[]) {
    StarFlyLoadEffect("StarFly Console is Starting");
    StarFlyCoreStart();
    printf(" .d8888. d888888b  .d8b.  d8888b. d88888b db      db    db \n");
    printf(" 88'  YP `~~88~~' d8' `8b 88  `8D 88'     88      `8b  d8' \n");
    printf(" `8bo.      88    88ooo88 88oobY' 88ooo   88       `8bd8'  \n");
    printf("   `Y8b.    88    88~~~88 88`8b   88~~~   88         88    \n");
    printf(" db   8D    88    88   88 88 `88. 88      88booo.    88    \n");
    printf(" `8888Y'    YP    YP   YP 88   YD YP      Y88888P    YP    \n");
    printf(" StarFly, call kernel via multiple Hardware Breakpoint Hook\n");
    printf(" https://github.com/CNMrSunshine/StarFly/blob/master/main.c\n");
    printf("\n")

    if (argc > 1 && strcmp(argv[1], "-PoC") == 0) {
        printf("PoC Mode: Executing Module \"ListProcess\"\n");
        SFGetProcessInformation();
    }

    char input[100];
    while (1) {
        printf("StarFly> ");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            input[strcspn(input, "\n")] = '\0';
            if (strcmp(input, "ps") == 0) {
                printf("Executing Module \"ListProcess\"");
                SFGetProcessInformation();
            } else if (strcmp(input, "exit") == 0) {
                break;
            } else {
                printf("Unknown Command: %s\n", input);
            }
        }
    }
    StarFlyCoreExit();
    return 0;
}
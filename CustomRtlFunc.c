#include "VEHinj.h"

BOOL SFRtlEncodeRemotePointer(HANDLE hProcess, PVOID Pointer, PVOID* EncodedPtr)
{
    NTSTATUS status = 0;
    NTSTATUS retStatus = 0;
    ULONG processCookie = 0;
    status = NtQueryInformationProcess(hProcess, ProcessCookie, &processCookie, sizeof(processCookie), NULL);
    if (!processCookie) return FALSE;

    unsigned int rot = (unsigned int)(processCookie & 0x3F);
    unsigned long long cookie64 = (unsigned long long)(unsigned long)processCookie;
    unsigned long long ptr64 = (unsigned long long)(uintptr_t)Pointer;
    unsigned long long x = cookie64 ^ ptr64;
    unsigned long long encoded64;
    if ((rot & 0x3F) == 0) {
        encoded64 = x;
    }
    else {
        unsigned int r = rot & 0x3F;
        encoded64 = (x >> r) | (x << (64 - r));
    }
    *EncodedPtr = (PVOID)(uintptr_t)encoded64;
    return TRUE;
}
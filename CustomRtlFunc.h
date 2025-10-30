#pragma once
#include "vehinj.h"
BOOL SFRtlEncodeRemotePointer(HANDLE hProcess, PVOID Pointer, PVOID* EncodedPtr);
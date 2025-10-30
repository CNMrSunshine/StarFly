#pragma once
#include "vehinj.h"
size_t SFstrlen(const char* s);
size_t SFwcslen(const wchar_t* s);
wchar_t* SFwcsstr(const wchar_t* haystack, const wchar_t* needle);
int SFstrcmp(const char* a, const char* b);
size_t __imp_wcslen(const wchar_t* s);
size_t strlen(const char* s);
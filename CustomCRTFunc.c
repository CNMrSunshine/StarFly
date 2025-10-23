#include <stdio.h>
#include <stdint.h>
#include "syscalls.h"
#include <stdbool.h>
#include <wchar.h>
#include <wctype.h>
#include "VEHinj.h"
#include <stddef.h>

size_t SFstrlen(const char* s) {
    const char* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

size_t strlen(const char* s) {
    const char* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

size_t SFwcslen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

size_t __imp_wcslen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

wchar_t* SFwcsstr(const wchar_t* haystack, const wchar_t* needle) {
    if (!*needle) return (wchar_t*)haystack;

    size_t nlen = SFwcslen(needle);
    size_t hlen = SFwcslen(haystack);

    if (nlen > hlen) return NULL;
    unsigned int skip[256];
    size_t i;
    for (i = 0; i < 256; ++i) skip[i] = (unsigned int)nlen;
    for (i = 0; i < nlen - 1; ++i) {
        unsigned int idx = ((unsigned int)needle[i]) & 0xFFu;
        skip[idx] = (unsigned int)(nlen - i - 1);
    }

    const wchar_t* h = haystack;
    while (hlen >= nlen) {
        const wchar_t* hp = h + nlen - 1;
        const wchar_t* np = needle + nlen - 1;
        while (*hp == *np) {
            if (np == needle) return (wchar_t*)h;
            --hp; --np;
        }
        unsigned int idx = ((unsigned int)*hp) & 0xFFu;
        h += skip[idx];
        hlen -= skip[idx];
    }
    return NULL;
}

int SFstrcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (unsigned char)(*a) - (unsigned char)(*b);
}


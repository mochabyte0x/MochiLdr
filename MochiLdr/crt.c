#include "include/MochiLdr.h"


SIZE_T MStringLengthA(LPCSTR String)
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

SIZE_T MStringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T MCharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

//------------------------------- 
// memcpy
void* ldr_memcpy(void* dst, const void* src, unsigned long size)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (size--) *d++ = *s++;
    return dst;
}

#pragma function(memset)
void* __cdecl memset(void* dst, int c, size_t size) {
    unsigned char* d = dst;
    while (size--) *d++ = (unsigned char)c;
    return dst;
}

// memset
void* ldr_memset(void* dst, int c, unsigned long size)
{
    unsigned char* d = (unsigned char*)dst;
    while (size--) *d++ = (unsigned char)c;
    return dst;
}

// strlen
unsigned long ldr_strlen(const char* s)
{
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

// strcmp
int ldr_strcmp(const char* a, const char* b)
{
    while (*a && *b && *a == *b) {
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/*
void* ldr_alloc(PINSTANCE instance, unsigned long size)
{
    if (!instance || !instance->Win32.NtAllocateVirtualMemory) return NULL;

    SIZE_T s = size;
    PVOID  base = NULL;

    NTSTATUS st = instance->Win32.NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base,
        0,
        &s,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (st < 0) return NULL;
    return base;
}
*/
//------------------------------------------------------------- CHAR MANIP

// minimal wcslen
unsigned long ldr_wcslen(const wchar_t* s)
{
    unsigned long n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

// wide strcat: dst must have enough room
wchar_t* ldr_wcscat(wchar_t* dst, const wchar_t* src)
{
    unsigned long dlen = ldr_wcslen(dst);
    unsigned long i = 0;
    while (src[i]) {
        dst[dlen + i] = src[i];
        i++;
    }
    dst[dlen + i] = L'\0';
    return dst;
}

// ASCII/ANSI -> UTF16 into caller-provided buffer
// destCount = number of wchar_t entries in dest (including terminator)
unsigned long MCharToWide(const char* src, wchar_t* dest, unsigned long destCount)
{
    if (!src || !dest || destCount == 0)
        return 0;

    unsigned long len = ldr_strlen(src);

    if (len + 1 > destCount)
        return 0; // not enough room

    for (unsigned long i = 0; i < len; ++i) {
        dest[i] = (wchar_t)((unsigned char)src[i]);
    }
    dest[len] = L'\0';

    return len;
}
// convert one character to lowercase (ASCII only)
char ldr_tolower(char c)
{
    // 'A'..'Z'  →  'a'..'z'
    if (c >= 'A' && c <= 'Z')
        return (char)(c + ('a' - 'A'));

    return c;
}

// convert one character to uppercase (ASCII only)
char ldr_toupper(char c)
{
    // 'a'..'z'  →  'A'..'Z'
    if (c >= 'a' && c <= 'z')
        return (char)(c - ('a' - 'A'));

    return c;
}

#pragma once
#include "MochiLdr.h"

void* ldr_memcpy(void* dst, const void* src, unsigned long size);
void* ldr_memset(void* dst, int c, unsigned long size);
unsigned long ldr_strlen(const char* s);
int ldr_strcmp(const char* a, const char* b);
unsigned long ldr_wcslen(const wchar_t* s);
wchar_t* ldr_wcscat(wchar_t* dst, const wchar_t* src);
unsigned long MCharToWide(const char* src, wchar_t* dest, unsigned long destCount);
char ldr_tolower(char c);
char ldr_toupper(char c);

SIZE_T MStringLengthA(LPCSTR String);
SIZE_T MStringLengthW(LPCWSTR String);
SIZE_T MCharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);



#pragma once
#include <Windows.h>
#include "Structs.h"
#include "Crt.h"

// Simple helpers
#define DLLEXPORT   __declspec( dllexport ) 

// Global Macros
#define INITIAL_SEED 25
#define Hash_W(HASH)(JKOAAT_W((LPCWSTR) HASH))
#define Hash_A(HASH)(JKOAAT_A((PCHAR) HASH))
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

// Defining the WinAPI hashes
#define LdrLoadDll_HASH			0xE5231652
#define NtAllocMem_HASH			0x8D5082C5
#define NtProtectMem_HASH		0x554A340C
#define NtFlushInstruct_HASH	0xB658957E
#define AddFuncTable_HASH		0xE1AAB82C
#define Ntdll_HASH				0x129AB5AE
#define Kernel32_HASH			0xDC256F7A

// Struct to hold hashes for the WinAPIs and Modules
typedef struct {

    struct {

        NtAllocMem			AllocMem;
        NtProtectMem		ProtectMem;
        NtFlushInstruct	    FlushInstruct;
        LdrLoadDll			LoadDll;
        AddFuncTable		AddFuncTbl;

    } Api;

    struct {

        PVOID Ntdll;
        PVOID Kernel32;

    } Modules;


} FUNCS, * PFUNCS;

// GetModuleHandle + GetProcAddress replacements
PVOID GetPrcAddr(HMODULE hHandle, DWORD dwHashValue, WORD wOrdinal);
HMODULE GetModHandle(IN UINT32 uModuleHash);

// PE repairing
BOOL RepairIAT(PFUNCS Functions, PBYTE MochiImage, LPVOID IatDir);
BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress);

// Caller from ASM
extern LPVOID MochiCaller();